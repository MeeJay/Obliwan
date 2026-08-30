// ObliWAN client — how a time window becomes a query, and how a hole stays a
// hole (M3, study `docs/M3-series-temporelles.md` §2.1 and §4.6).

import { ROLLUP_BUCKET_SECONDS, rollupTiersFor, type RollupGranularity } from '@obliwan/shared';
import type { IfSeriesPoint, SeriesGranularity } from '@/types/telemetry';

// ── Windows ─────────────────────────────────────────────────────────────────

/** The values `components/common/PeriodSelector` emits, in seconds. */
export const PERIOD_SECONDS: Record<string, number> = {
  '1h': 3600,
  '24h': 86_400,
  '7d': 604_800,
  '30d': 2_592_000,
  '365d': 31_536_000,
};

export const DEFAULT_PERIOD = '24h';

export function periodSeconds(period: string): number {
  return PERIOD_SECONDS[period] ?? PERIOD_SECONDS[DEFAULT_PERIOD];
}

// ── Retention, straight out of study §2.1 ───────────────────────────────────
//
// These are not decoration. Asking for `raw` over 90 days does not return a
// heavy answer — it returns a MUTILATED one: the raw table keeps 48 h, so 88
// of the 90 days come back empty and the chart shows a flat nothing next to a
// two-day spike. Choosing the granularity is therefore a correctness
// requirement before it is a performance one.

export const RAW_RETENTION_SEC = 48 * 3600;

export const ROLLUP_RETENTION_SEC: Record<RollupGranularity, number> = {
  '1m': 8 * 86_400,
  '5m': 90 * 86_400,
  '1h': 730 * 86_400,
};

/**
 * How many points we are willing to put in one chart.
 *
 * 2 500 is chosen against the ladder, not against a feeling: it is the first
 * value that keeps 7 days at the 5-minute tier (2 016 points — a 7-day chart
 * at the hourly tier would flatten every burst) while refusing 24 h of raw
 * (2 880 points at a 30 s poll, for a strictly worse picture than the
 * 1-minute rollup's 1 440). A 1 200 px chart has ~1 200 device pixels of
 * width, so past ~2 500 points we transmit samples that cannot be drawn.
 */
export const MAX_CHART_POINTS = 2500;

interface Tier {
  key: SeriesGranularity;
  /** Nominal spacing between points, in seconds. */
  bucketSec: number;
  retentionSec: number;
}

/**
 * The ladder, finest first, restricted to what THIS interface actually has.
 *
 * `rollupTiersFor()` (shared, study §4.6) is the load-bearing call: above a
 * 60 s poll the 1-minute rollup is not written at all, so offering it would
 * make the chart query a table that is empty by design and render an outage
 * that never happened.
 */
function tiersFor(effectivePollSec: number): Tier[] {
  const pollSec = effectivePollSec > 0 ? effectivePollSec : 30;
  const rollups = rollupTiersFor(pollSec);
  return [
    { key: 'raw' as SeriesGranularity, bucketSec: pollSec, retentionSec: RAW_RETENTION_SEC },
    ...rollups.map((g) => ({
      key: g as SeriesGranularity,
      bucketSec: ROLLUP_BUCKET_SECONDS[g],
      retentionSec: ROLLUP_RETENTION_SEC[g],
    })),
  ];
}

/**
 * Pick the finest granularity that (a) still covers the window with real data
 * and (b) does not exceed `MAX_CHART_POINTS`.
 *
 * If nothing qualifies — a 365-day window, where even the hourly tier is
 * 8 760 points — we return the COARSEST available tier rather than nothing.
 * That is a deliberate overshoot: the alternative is refusing to draw a year,
 * and a year of hourly averages is exactly the question a capacity review
 * asks. `seriesPointBudget()` below lets the caller warn about it.
 */
export function chooseGranularity(windowSec: number, effectivePollSec: number): SeriesGranularity {
  const tiers = tiersFor(effectivePollSec);
  for (const tier of tiers) {
    if (tier.retentionSec < windowSec) continue;
    if (windowSec / tier.bucketSec <= MAX_CHART_POINTS) return tier.key;
  }
  return tiers[tiers.length - 1]!.key;
}

/** Nominal spacing of a granularity, for the same interface. */
export function granularityBucketSec(
  granularity: SeriesGranularity,
  effectivePollSec: number,
): number {
  if (granularity === 'raw') return effectivePollSec > 0 ? effectivePollSec : 30;
  return ROLLUP_BUCKET_SECONDS[granularity];
}

/** Estimated number of points for a window at a granularity. */
export function seriesPointBudget(
  windowSec: number,
  granularity: SeriesGranularity,
  effectivePollSec: number,
): number {
  return Math.ceil(windowSec / granularityBucketSec(granularity, effectivePollSec));
}

/** True when the chosen tier cannot hold the whole window — the chart will be
 *  truncated at the retention boundary and must say so. */
export function windowExceedsRetention(
  windowSec: number,
  granularity: SeriesGranularity,
): boolean {
  const retention = granularity === 'raw' ? RAW_RETENTION_SEC : ROLLUP_RETENTION_SEC[granularity];
  return windowSec > retention;
}

// ── Gaps ────────────────────────────────────────────────────────────────────

/** Chart-ready row: `null` metrics are holes, `0` metrics are measurements. */
export interface ChartPoint {
  /** Epoch ms — a numeric X axis, so the spacing on screen is the spacing in
   *  time. A category axis would draw a 3-day outage the same width as a
   *  30-second one. */
  t: number;
  inBps: number | null;
  outBps: number | null;
  inErrs: number | null;
  outErrs: number | null;
  inDiscards: number | null;
  outDiscards: number | null;
  /** Present on rollup tiers. Undefined on raw. */
  sampleCount?: number;
  expectedCount?: number;
  /** True for the synthetic rows this module inserts to break the line. */
  gap?: boolean;
}

/** Spacing beyond which two consecutive points are NOT considered contiguous. */
export const GAP_FACTOR = 1.5;

const NULL_METRICS = {
  inBps: null,
  outBps: null,
  inErrs: null,
  outErrs: null,
  inDiscards: null,
  outDiscards: null,
} as const;

/**
 * Turn an API series into chart rows, inserting an explicit null row wherever
 * the series is discontinuous.
 *
 * THIS IS THE FUNCTION THAT STOPS THE UI FROM LYING. Recharts, given two
 * points three days apart, draws a straight line between them — a clean
 * interpolation across a router reboot, a failed poll or a three-day server
 * outage, presenting invented traffic as measured traffic. With
 * `connectNulls={false}` a single null row between them breaks the line
 * instead.
 *
 * We insert ONE synthetic row per hole rather than densifying the whole
 * window: a 30-day gap at the 5-minute tier would otherwise cost 8 640 null
 * rows to draw one piece of white space.
 *
 * Two independent kinds of hole are handled:
 *  - a MISSING ROW (the server returned nothing for that stretch), detected
 *    here by comparing the spacing against `bucketSec * GAP_FACTOR`;
 *  - a PRESENT ROW WITH NULL VALUES (the rollup bucket existed but carried
 *    too few samples — `isRollupGap()` server-side). Those arrive as nulls and
 *    are passed straight through; they already break the line.
 */
export function toChartPoints(points: IfSeriesPoint[], bucketSec: number): ChartPoint[] {
  const spacingMs = Math.max(bucketSec, 1) * 1000;
  const gapMs = spacingMs * GAP_FACTOR;
  const out: ChartPoint[] = [];
  let prevT: number | null = null;

  for (const p of points) {
    const t = Date.parse(p.ts);
    if (!Number.isFinite(t)) continue;

    if (prevT !== null && t - prevT > gapMs) {
      // One null row placed just after the last real point. Anchoring it to
      // `prevT + spacing` rather than to the midpoint keeps the visible break
      // aligned with the moment data actually stopped.
      out.push({ t: Math.min(prevT + spacingMs, t - 1), ...NULL_METRICS, gap: true });
    }

    out.push({
      t,
      inBps: p.inBps,
      outBps: p.outBps,
      inErrs: p.inErrs,
      outErrs: p.outErrs,
      inDiscards: p.inDiscards,
      outDiscards: p.outDiscards,
      sampleCount: p.sampleCount,
      expectedCount: p.expectedCount,
    });
    prevT = t;
  }

  return out;
}

/** How many holes a series contains — shown next to the chart so an operator
 *  reading a sparse graph knows the sparseness is the data, not the renderer. */
export function countGaps(points: ChartPoint[]): number {
  let n = 0;
  for (const p of points) {
    if (p.gap) { n += 1; continue; }
    if (p.inBps === null && p.outBps === null) n += 1;
  }
  return n;
}

// ── Formatting ──────────────────────────────────────────────────────────────

const BPS_UNITS = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s'];

/** Network rates are decimal, not binary: a 100 Mbit/s port is 100 000 000
 *  bit/s, never 104 857 600. Using 1024 here would misreport every link. */
export function formatBps(value: number | null | undefined, digits = 2): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  if (value === 0) return `0 ${BPS_UNITS[0]}`;
  const abs = Math.abs(value);
  const exp = Math.min(Math.floor(Math.log10(abs) / 3), BPS_UNITS.length - 1);
  const scaled = value / 1000 ** exp;
  return `${scaled.toFixed(exp === 0 ? 0 : digits)} ${BPS_UNITS[exp]}`;
}

/** Compact form for an axis tick, where two decimals are noise. */
export function formatBpsShort(value: number): string {
  return formatBps(value, value >= 1000 ? 1 : 0);
}

export function formatPps(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return `${value.toLocaleString()} p/s`;
}

export function formatCount(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return value.toLocaleString();
}

/**
 * Utilisation as a percentage of line speed.
 *
 * `null` when the speed is unknown — NOT 0 and NOT 100. An interface whose
 * `ifHighSpeed` we never read is an interface whose saturation we cannot
 * state, and a fabricated 0 % would park it at the bottom of a saturation
 * sort, which is precisely where a broken link hides.
 */
export function utilPct(
  bps: number | null | undefined,
  speedBps: number | null | undefined,
): number | null {
  if (bps === null || bps === undefined) return null;
  if (!speedBps || speedBps <= 0) return null;
  return (bps / speedBps) * 100;
}

export function formatPct(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return `${value.toFixed(digits)} %`;
}

/** `for_seconds` / uptime style duration: 90 -> "1 m 30 s", 7200 -> "2 h". */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  if (seconds < 60) return `${Math.round(seconds)} s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return s ? `${m} m ${s} s` : `${m} m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  if (h < 24) return rm ? `${h} h ${rm} m` : `${h} h`;
  const d = Math.floor(h / 24);
  const rh = h % 24;
  return rh ? `${d} d ${rh} h` : `${d} d`;
}

/** X-axis tick formatter: a 1-hour window wants HH:MM, a year wants a date. */
export function tickFormatter(windowSec: number): (t: number) => string {
  if (windowSec <= 86_400) {
    return (t) => new Date(t).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }
  if (windowSec <= 7 * 86_400) {
    return (t) =>
      new Date(t).toLocaleString(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' });
  }
  return (t) => new Date(t).toLocaleDateString(undefined, { day: '2-digit', month: 'short' });
}
