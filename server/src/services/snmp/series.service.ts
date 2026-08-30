/**
 * The read side: what a graph asks for.
 *
 * ┌─ A HOLE MUST REACH THE PIXEL ─────────────────────────────────────────────┐
 * │ The whole "in case of doubt, discard" chain is worth nothing if the API   │
 * │ hands back a dense array. Recharts joins consecutive points with a        │
 * │ straight line, and A STRAIGHT LINE BETWEEN TWO POINTS THREE DAYS APART IS │
 * │ A LIE THAT LOOKS EXACTLY LIKE A MEASUREMENT.                              │
 * │                                                                          │
 * │ So this file emits an EXPLICIT `null` for every bucket that is missing or │
 * │ under-sampled, and the client must render with `connectNulls={false}`.    │
 * │ Dropping the point instead would leave the chart to interpolate across    │
 * │ the hole, which is the failure this design exists to prevent.             │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * GRANULARITY IS CHOSEN, NOT ASKED FOR. A client that requests "raw over 90
 * days" is asking for 259 200 points per interface, and would get a browser
 * freeze plus a 200 MB response. `chooseGranularity()` picks the finest tier
 * that BOTH still holds the requested window (retention) and keeps the point
 * count sane. An explicit `granularity` is honoured, but still clamped to what
 * retention can serve -- answering an empty array for a tier whose data was
 * dropped last week is indistinguishable, from the client, from an interface
 * that carried no traffic.
 */

import type { RollupGranularity } from '@obliwan/shared';
import { ROLLUP_BUCKET_SECONDS, isRollupGap } from '@obliwan/shared';
import { db } from '../../db';

/** Retention of each source, from `series_partition_policy` (study 2.1). */
const RETENTION_SEC: Record<SeriesResolution, number> = {
  raw: 48 * 3600,
  '1m': 8 * 86400,
  '5m': 90 * 86400,
  '1h': 730 * 86400,
};

export type SeriesResolution = 'raw' | RollupGranularity;

const BUCKET_SEC: Record<SeriesResolution, number> = {
  raw: 30,
  ...ROLLUP_BUCKET_SECONDS,
};

/** Above this, a line chart is drawing several points per pixel. */
const MAX_POINTS = 1000;

const ORDER: SeriesResolution[] = ['raw', '1m', '5m', '1h'];

/**
 * The finest resolution that covers the window and stays under `MAX_POINTS`.
 *
 * `raw` is only ever chosen for a window shorter than about eight hours: it is
 * the "zoom on the incident" case, which is exactly what the expensive
 * `(if_id, ts DESC)` B-tree on the raw table was paid for.
 */
export function chooseGranularity(
  from: Date,
  to: Date,
  requested?: SeriesResolution,
  /** The interface's REAL poll interval. `BUCKET_SEC.raw` is a 30 s default,
   *  and using it blindly under-counts the points a fast-polled interface
   *  would produce: at a 6 s poll a three-hour window is 1 800 raw points, not
   *  360, and the "raw is fine here" decision was made on the wrong number. */
  rawBucketSec = BUCKET_SEC.raw,
): SeriesResolution {
  const windowSec = Math.max(1, (to.getTime() - from.getTime()) / 1000);
  const ageSec = (Date.now() - from.getTime()) / 1000;
  const width = (r: SeriesResolution): number => (r === 'raw' ? rawBucketSec : BUCKET_SEC[r]);

  const usable = (r: SeriesResolution): boolean =>
    ageSec <= RETENTION_SEC[r] && windowSec / width(r) <= MAX_POINTS;

  if (requested) {
    if (ageSec <= RETENTION_SEC[requested]) return requested;
    // The requested tier no longer holds this window: fall UP to one that
    // does, rather than answering an honest-looking empty array.
    const fallback = ORDER.find((r) => ageSec <= RETENTION_SEC[r] && ORDER.indexOf(r) > ORDER.indexOf(requested));
    return fallback ?? '1h';
  }

  return ORDER.find(usable) ?? '1h';
}

// ============================================================================
// Interfaces
// ============================================================================

export interface InterfaceSummary {
  id: number;
  deviceId: number;
  ifName: string;
  ifIndex: number;
  ifAlias: string | null;
  ifDescr: string | null;
  ifType: number | null;
  speedBps: number;
  adminStatus: number;
  operStatus: number;
  state: string;
  monitored: boolean;
  counterBits: number;
  /** True when a rate for this interface would be a guess (study 3.2). The UI
   *  must refuse to draw a throughput chart and say why. */
  counterUnreliable: boolean;
  needsRediscovery: boolean;
  effectivePollSec: number;
  lastSeenAt: string | null;
  vanishedAt: string | null;
  /** Collection health, from `snmp_poll_state`. A series that is empty because
   *  every sample is being discarded looks exactly like a quiet link, and this
   *  is the only thing that tells them apart. */
  lastDiscard: string | null;
  consecutiveDiscards: number;
}

/** Tenant scoping goes through `devices`: `snmp_interfaces` has no tenant
 *  column of its own, and a WHERE on the interface id alone would answer for
 *  another customer's inventory. */
export async function listInterfaces(
  tenantId: number,
  deviceId: number,
  opts: { includeVanished?: boolean } = {},
): Promise<InterfaceSummary[]> {
  const q = db('snmp_interfaces')
    .join('devices', 'devices.id', 'snmp_interfaces.device_id')
    .leftJoin('snmp_poll_state', 'snmp_poll_state.if_id', 'snmp_interfaces.id')
    .where('devices.tenant_id', tenantId)
    .where('snmp_interfaces.device_id', deviceId)
    .select(
      'snmp_interfaces.*',
      'snmp_poll_state.last_discard as _last_discard',
      'snmp_poll_state.consecutive_discards as _consecutive_discards',
    )
    .orderBy('snmp_interfaces.if_index');
  if (!opts.includeVanished) q.where('snmp_interfaces.state', 'active');

  const rows = await q;
  return rows.map((r) => ({
    id: r.id,
    deviceId: r.device_id,
    ifName: r.if_name,
    ifIndex: r.if_index,
    ifAlias: r.if_alias,
    ifDescr: r.if_descr,
    ifType: r.if_type,
    speedBps: Number(r.speed_bps),
    adminStatus: Number(r.admin_status),
    operStatus: Number(r.oper_status),
    state: r.state,
    monitored: r.monitored,
    counterBits: Number(r.counter_bits),
    counterUnreliable: r.counter_unreliable,
    needsRediscovery: r.needs_rediscovery,
    effectivePollSec: Number(r.effective_poll_sec),
    lastSeenAt: r.last_seen_at ? new Date(r.last_seen_at).toISOString() : null,
    vanishedAt: r.vanished_at ? new Date(r.vanished_at).toISOString() : null,
    lastDiscard: r._last_discard ?? null,
    consecutiveDiscards: Number(r._consecutive_discards ?? 0),
  }));
}

/** One interface, tenant-checked. Returns null on both "does not exist" and
 *  "belongs to somebody else" -- an existence oracle on another customer's
 *  inventory is itself a leak. */
export async function getInterface(
  tenantId: number,
  ifId: number,
): Promise<(InterfaceSummary & { tenantId: number }) | null> {
  const row = await db('snmp_interfaces')
    .join('devices', 'devices.id', 'snmp_interfaces.device_id')
    .where('devices.tenant_id', tenantId)
    .where('snmp_interfaces.id', ifId)
    .first('snmp_interfaces.*', 'devices.tenant_id as _tenant_id');
  if (!row) return null;
  const [summary] = await listInterfaces(tenantId, row.device_id, { includeVanished: true }).then(
    (all) => all.filter((i) => i.id === ifId),
  );
  return summary ? { ...summary, tenantId: row._tenant_id } : null;
}

// ============================================================================
// Series
// ============================================================================

export interface SeriesPoint {
  ts: string;
  /** `null` IS the hole. See the file header. */
  inBps: number | null;
  outBps: number | null;
  inMaxBps: number | null;
  outMaxBps: number | null;
  inErrs: number | null;
  outErrs: number | null;
  inDiscards: number | null;
  outDiscards: number | null;
  operStatus: number | null;
}

export interface SeriesResponse {
  ifId: number;
  resolution: SeriesResolution;
  bucketSec: number;
  from: string;
  to: string;
  points: SeriesPoint[];
  /** Buckets emitted as null because they were absent or under-sampled. */
  gaps: number;
  /** True when a throughput chart must NOT be drawn at all (study 3.2). */
  counterUnreliable: boolean;
}

function emptyPoint(ts: Date): SeriesPoint {
  return {
    ts: ts.toISOString(),
    inBps: null,
    outBps: null,
    inMaxBps: null,
    outMaxBps: null,
    inErrs: null,
    outErrs: null,
    inDiscards: null,
    outDiscards: null,
    operStatus: null,
  };
}

/**
 * Walk the requested window bucket by bucket and place each row where it
 * belongs, emitting `null` everywhere else.
 *
 * This is where the hole becomes visible. A version that simply returned the
 * rows it found would be shorter, faster, and would draw a straight line
 * across a three-day outage.
 */
function densify(
  from: Date,
  to: Date,
  bucketSec: number,
  rows: Map<number, SeriesPoint>,
): { points: SeriesPoint[]; gaps: number } {
  const points: SeriesPoint[] = [];
  let gaps = 0;
  const step = bucketSec * 1000;
  const start = Math.floor(from.getTime() / step) * step;
  for (let t = start; t < to.getTime(); t += step) {
    const found = rows.get(t);
    if (found) points.push(found);
    else {
      points.push(emptyPoint(new Date(t)));
      gaps += 1;
    }
  }
  return { points, gaps };
}

export async function getInterfaceSeries(
  tenantId: number,
  ifId: number,
  from: Date,
  to: Date,
  requested?: SeriesResolution,
): Promise<SeriesResponse | null> {
  const iface = await getInterface(tenantId, ifId);
  if (!iface) return null;

  const resolution = chooseGranularity(from, to, requested, iface.effectivePollSec || BUCKET_SEC.raw);
  const bucketSec = resolution === 'raw' ? iface.effectivePollSec || BUCKET_SEC.raw : BUCKET_SEC[resolution];
  const byBucket = new Map<number, SeriesPoint>();

  if (resolution === 'raw') {
    const rows = await db('snmp_if_samples')
      .where('if_id', ifId)
      .where('ts', '>=', from)
      .where('ts', '<', to)
      .orderBy('ts')
      .select('*');
    for (const r of rows) {
      const ts = new Date(r.ts);
      const slot = Math.floor(ts.getTime() / (bucketSec * 1000)) * (bucketSec * 1000);
      byBucket.set(slot, {
        ts: ts.toISOString(),
        inBps: Number(r.in_bps),
        outBps: Number(r.out_bps),
        inMaxBps: Number(r.in_bps),
        outMaxBps: Number(r.out_bps),
        inErrs: Number(r.in_errs),
        outErrs: Number(r.out_errs),
        inDiscards: Number(r.in_discards),
        outDiscards: Number(r.out_discards),
        operStatus: Number(r.oper_status),
      });
    }
  } else {
    const table = `snmp_if_rollup_${resolution}`;
    const rows = await db(table)
      .where('if_id', ifId)
      .where('bucket', '>=', from)
      .where('bucket', '<', to)
      .orderBy('bucket')
      .select('*');
    for (const r of rows) {
      const bucket = new Date(r.bucket);
      const slot = bucket.getTime();
      // THE GAP RULE, and it is not optional: fewer than half the expected
      // samples is not a low value, it is an unknown one.
      if (isRollupGap(Number(r.sample_count), Number(r.expected_count))) {
        byBucket.set(slot, emptyPoint(bucket));
        continue;
      }
      byBucket.set(slot, {
        ts: bucket.toISOString(),
        inBps: Number(r.in_avg_bps),
        outBps: Number(r.out_avg_bps),
        inMaxBps: Number(r.in_max_bps),
        outMaxBps: Number(r.out_max_bps),
        inErrs: Number(r.in_errs),
        outErrs: Number(r.out_errs),
        inDiscards: Number(r.in_discards),
        outDiscards: Number(r.out_discards),
        operStatus: null,
      });
    }
  }

  const { points, gaps } = densify(from, to, bucketSec, byBucket);
  return {
    ifId,
    resolution,
    bucketSec,
    from: from.toISOString(),
    to: to.toISOString(),
    points,
    gaps,
    counterUnreliable: iface.counterUnreliable,
  };
}

// ============================================================================
// Device series
// ============================================================================

export interface DeviceSeriesPoint {
  ts: string;
  rttUs: number | null;
  cpuPct: number | null;
  memPct: number | null;
  tempDc: number | null;
  reachablePct: number | null;
}

export async function getDeviceSeries(
  tenantId: number,
  deviceId: number,
  from: Date,
  to: Date,
  requested?: SeriesResolution,
): Promise<{
  deviceId: number;
  resolution: SeriesResolution;
  bucketSec: number;
  points: DeviceSeriesPoint[];
} | null> {
  const device = await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id');
  if (!device) return null;

  const resolution = chooseGranularity(from, to, requested);
  const points: DeviceSeriesPoint[] = [];

  // `unsentinel` on the way out: -1 means "not exposed", and rendering it
  // straight puts "CPU: -1 %" on a dashboard.
  const un = (v: unknown, sentinel = -1): number | null => {
    const n = Number(v);
    return !Number.isFinite(n) || n === sentinel ? null : n;
  };

  if (resolution === 'raw') {
    const rows = await db('snmp_device_samples')
      .where('device_id', deviceId)
      .where('ts', '>=', from)
      .where('ts', '<', to)
      .orderBy('ts');
    for (const r of rows) {
      const used = un(r.mem_used_bytes);
      const total = un(r.mem_total_bytes);
      points.push({
        ts: new Date(r.ts).toISOString(),
        rttUs: un(r.rtt_us),
        cpuPct: un(r.cpu_pct),
        memPct: used !== null && total !== null && total > 0 ? (used * 100) / total : null,
        tempDc: un(r.temp_dc, -32768),
        reachablePct: r.reachable ? 100 : 0,
      });
    }
  } else {
    const rows = await db(`snmp_device_rollup_${resolution}`)
      .where('device_id', deviceId)
      .where('bucket', '>=', from)
      .where('bucket', '<', to)
      .orderBy('bucket');
    for (const r of rows) {
      const sampleCount = Number(r.sample_count);
      const gap = isRollupGap(sampleCount, Number(r.expected_count));
      const used = un(r.mem_used_avg_bytes);
      const total = un(r.mem_total_bytes);
      points.push({
        ts: new Date(r.bucket).toISOString(),
        rttUs: gap ? null : un(r.rtt_avg_us),
        cpuPct: gap ? null : un(r.cpu_avg_pct),
        memPct: gap || used === null || total === null || total <= 0 ? null : (used * 100) / total,
        tempDc: gap ? null : un(r.temp_avg_dc, -32768),
        // Availability is NOT a gap-sensitive metric in the same way: a device
        // that answered 0 times out of 10 was down, which is a fact worth
        // drawing. Only a bucket with no samples at all is unknown.
        reachablePct: sampleCount > 0 ? (Number(r.reachable_count) * 100) / sampleCount : null,
      });
    }
  }

  return { deviceId, resolution, bucketSec: BUCKET_SEC[resolution], points };
}

// ============================================================================
// Billing p95
// ============================================================================

/**
 * The 95th-percentile billing figure, computed ON DEMAND from the 5-minute
 * tier -- never pre-aggregated.
 *
 * A month is 8 928 rows (30 x 288) read through `PK(if_id, bucket)` across one
 * or two weekly partitions: milliseconds. THIS IS THE JUSTIFICATION FOR THE
 * 90-DAY RETENTION OF THE 5m TIER. Without it there is no billing p95 at all,
 * and a customer dispute cannot be arbitrated.
 *
 * `percentile_cont` interpolates and can therefore return a value that was
 * never measured. MRTG, Cacti and LibreNMS all interpolate, so this matches
 * what a customer would compute independently; `percentile_disc` is the
 * defensible alternative if a bill is ever contested.
 */
export async function billingP95(
  tenantId: number,
  ifId: number,
  from: Date,
  to: Date,
): Promise<{ inP95Bps: number; outP95Bps: number; buckets: number } | null> {
  const iface = await getInterface(tenantId, ifId);
  if (!iface) return null;
  const rows = await db.raw<{
    rows: Array<{ in_p95: string | null; out_p95: string | null; n: string }>;
  }>(
    `SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY in_avg_bps)  AS in_p95,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY out_avg_bps) AS out_p95,
            count(*) AS n
       FROM snmp_if_rollup_5m
      WHERE if_id = ? AND bucket >= ? AND bucket < ?`,
    [ifId, from, to],
  );
  const r = rows.rows?.[0];
  return {
    inP95Bps: Math.round(Number(r?.in_p95 ?? 0)),
    outP95Bps: Math.round(Number(r?.out_p95 ?? 0)),
    buckets: Number(r?.n ?? 0),
  };
}

/** A fleet-wide interface row: the per-device summary plus what the fleet view
 *  needs to be readable — which device and site it belongs to, and its latest
 *  measurement. */
export interface FleetInterfaceRow extends InterfaceSummary {
  deviceName: string;
  siteName: string | null;
  siteCode: string | null;
  lastSampleAt: string | null;
  inBps: number | null;
  outBps: number | null;
  inErrs: number | null;
  outErrs: number | null;
  /** in/out as a fraction of `speedBps`, whichever is higher. `null` when the
   *  link speed is unknown (0) — a saturation of "Infinity%" is worse than none. */
  utilisation: number | null;
}

/**
 * Every interface of the tenant, with its last measurement.
 *
 * Exists because `InterfacesPage` sorts the fleet by saturation, which is
 * impossible from the per-device endpoint without N round-trips.
 *
 * Tenant scoping goes through `devices`, like every other read here: the series
 * tables carry no tenant column at all (study §1.1b), so that join is the only
 * thing standing between one customer and another customer's traffic.
 *
 * The last sample is fetched with a LATERAL per interface rather than a window
 * over the whole table: raw retention is 48 h and BRIN is ordered on `ts`, so a
 * global sort would read every partition to keep 2 400 rows.
 */
export async function listFleetInterfaces(
  tenantId: number,
  opts: { includeVanished?: boolean; deviceId?: number } = {},
): Promise<FleetInterfaceRow[]> {
  const q = db('snmp_interfaces')
    .join('devices', 'devices.id', 'snmp_interfaces.device_id')
    .leftJoin('sites', 'sites.id', 'devices.site_id')
    .leftJoin('snmp_poll_state', 'snmp_poll_state.if_id', 'snmp_interfaces.id')
    .joinRaw(
      `LEFT JOIN LATERAL (
         SELECT s.ts, s.in_bps, s.out_bps, s.in_errs, s.out_errs
         FROM snmp_if_samples s
         WHERE s.if_id = snmp_interfaces.id
         ORDER BY s.ts DESC
         LIMIT 1
       ) last ON true`,
    )
    .where('devices.tenant_id', tenantId)
    .select(
      'snmp_interfaces.*',
      'devices.name as _device_name',
      'sites.name as _site_name',
      'sites.code as _site_code',
      'snmp_poll_state.last_discard as _last_discard',
      'snmp_poll_state.consecutive_discards as _consecutive_discards',
      db.raw('last.ts as _last_ts'),
      db.raw('last.in_bps as _in_bps'),
      db.raw('last.out_bps as _out_bps'),
      db.raw('last.in_errs as _in_errs'),
      db.raw('last.out_errs as _out_errs'),
    )
    .orderBy('devices.name')
    .orderBy('snmp_interfaces.if_index');

  if (!opts.includeVanished) q.where('snmp_interfaces.state', 'active');
  if (opts.deviceId !== undefined) q.where('snmp_interfaces.device_id', opts.deviceId);

  const rows = await q;
  return rows.map((r) => {
    const speed = Number(r.speed_bps);
    const inBps = r._in_bps === null || r._in_bps === undefined ? null : Number(r._in_bps);
    const outBps = r._out_bps === null || r._out_bps === undefined ? null : Number(r._out_bps);
    const peak = Math.max(inBps ?? 0, outBps ?? 0);
    return {
      id: r.id,
      deviceId: r.device_id,
      ifName: r.if_name,
      ifIndex: r.if_index,
      ifAlias: r.if_alias,
      ifDescr: r.if_descr,
      ifType: r.if_type,
      speedBps: speed,
      adminStatus: Number(r.admin_status),
      operStatus: Number(r.oper_status),
      state: r.state,
      monitored: r.monitored,
      counterBits: Number(r.counter_bits),
      counterUnreliable: r.counter_unreliable,
      needsRediscovery: r.needs_rediscovery,
      effectivePollSec: Number(r.effective_poll_sec),
      lastSeenAt: r.last_seen_at ? new Date(r.last_seen_at).toISOString() : null,
      vanishedAt: r.vanished_at ? new Date(r.vanished_at).toISOString() : null,
      lastDiscard: r._last_discard ?? null,
      consecutiveDiscards: Number(r._consecutive_discards ?? 0),
      deviceName: r._device_name,
      siteName: r._site_name ?? null,
      siteCode: r._site_code ?? null,
      lastSampleAt: r._last_ts ? new Date(r._last_ts).toISOString() : null,
      inBps,
      outBps,
      inErrs: r._in_errs === null || r._in_errs === undefined ? null : Number(r._in_errs),
      outErrs: r._out_errs === null || r._out_errs === undefined ? null : Number(r._out_errs),
      utilisation: speed > 0 && (inBps !== null || outBps !== null) ? peak / speed : null,
    };
  });
}
