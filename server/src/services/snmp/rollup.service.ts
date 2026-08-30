/**
 * The incremental rollups. Study section 4, implemented as written.
 *
 * INCREMENTAL MEANS INCREMENTAL. Each tier keeps a watermark in
 * `series_rollup_state`; a run aggregates the buckets between that watermark
 * and the last CLOSED bucket, and moves the watermark. Nothing recomputes
 * history. The three parameters below are not tuning knobs, each answers one
 * precise failure:
 *
 *   CLOSE LAG (90 s = one poll interval + 60 s)
 *     Never aggregate a bucket that is still open. Without it the last bucket
 *     is systematically partial, then frozen at half its real value -- and the
 *     graph shows a permanent dip at "now" that nobody can reproduce later.
 *
 *   OVERLAP (2 buckets backwards)
 *     A sample that arrived late (an SNMP retry, a slow device) lands in a
 *     bucket already written. Recomputing the last two buckets picks it up
 *     through `ON CONFLICT DO UPDATE`. Self-repairing, and it costs nothing.
 *
 *   CEILING (60 buckets per run)
 *     Stops a three-day catch-up from holding one transaction for minutes.
 *
 * THE `WHERE` ON THE `DO UPDATE` IS NOT COSMETIC. Without it the two overlap
 * buckets are rewritten identically every minute: 4 800 rows/min, 6.9 M dead
 * tuples a day, in the ONLY tables of the whole design where autovacuum has
 * real work to do. `IS DISTINCT FROM` makes the no-op case a no-op.
 *
 * WHY 1m AND 5m BOTH READ THE RAW TABLE, AND 1h DOES NOT
 * A PERCENTILE DOES NOT COMPOSE. The p95 of twelve p95s is not the p95 of the
 * whole, and the error is not even bounded. So 5m reads raw (48 h retention
 * against a rollup lag of minutes -- no constraint). 1h CANNOT read raw: when
 * it aggregates 06:00 the raw data may already be gone if the job fell behind.
 * It reads 5m, which makes the hourly p95 a "p95 of 5-minute averages" -- which
 * is precisely the 95th-percentile BILLING convention every carrier uses, and
 * which the UI must therefore label "p95 (5-min averages)".
 *
 * WEIGHTED AVERAGE AT THE 1h TIER, ALWAYS. `avg(avg)` is THE classic
 * rollup-cascade bug: on an hour where 11 buckets hold 10 samples and the 12th
 * holds 1 at ten times the rate, it overstates by ~7 %. Small, systematic, and
 * impossible to trace a year later.
 */

import type { SeriesTier } from '@obliwan/shared';
import { db } from '../../db';
import { leaderElection } from '../leaderElection';
import { logger } from '../../utils/logger';
import { snmpConfig } from './config';

/** Bucket origin. FROZEN FOREVER: changing it moves every historical bucket. */
const BUCKET_ORIGIN = "TIMESTAMPTZ '2000-01-01'";

const CLOSE_LAG_SEC = 90;
const OVERLAP_BUCKETS = 2;
const MAX_BUCKETS_PER_RUN = 60;

/**
 * How far behind the watermark may fall before the tier gives up on catching
 * up and JUMPS (study section 2.7).
 *
 * Twice the raw retention. Past that, the source rows have been dropped by the
 * retention job, so the buckets in between will never be computable: grinding
 * through 4 320 empty aggregations to produce nothing would just keep the job
 * busy while the live data falls further behind.
 */
const GIVE_UP_BEHIND_SEC = 96 * 3600;

interface TierSpec {
  tier: SeriesTier;
  interval: string;
  bucketSec: number;
  run: (lo: string, hi: string) => Promise<number>;
}

// ============================================================================
// Interface tiers
// ============================================================================

/**
 * 1m and 5m from the raw samples.
 *
 * `i.effective_poll_sec <= <bucket>` is the study section 4.6 filter, and it
 * is what stops a fleet moved to a 5-minute poll from filling
 * `snmp_if_rollup_1m` with 3.45 M rows a day of which 80 % are empty buckets --
 * MORE ROLLUP ROWS THAN RAW DATA.
 */
async function ifFromSamples(
  table: string,
  interval: string,
  bucketSec: number,
  lo: string,
  hi: string,
): Promise<number> {
  const result = await db.raw<{ rowCount: number }>(
    `
    WITH agg AS (
      SELECT date_bin(INTERVAL '${interval}', s.ts, ${BUCKET_ORIGIN}) AS bucket,
             s.if_id,
             avg(s.in_bps)::bigint  AS in_avg_bps,
             max(s.in_bps)          AS in_max_bps,
             percentile_cont(0.95) WITHIN GROUP (ORDER BY s.in_bps)::bigint  AS in_p95_bps,
             avg(s.out_bps)::bigint AS out_avg_bps,
             max(s.out_bps)         AS out_max_bps,
             percentile_cont(0.95) WITHIN GROUP (ORDER BY s.out_bps)::bigint AS out_p95_bps,
             sum(s.in_errs)::int     AS in_errs,
             sum(s.out_errs)::int    AS out_errs,
             sum(s.in_discards)::int AS in_discards,
             sum(s.out_discards)::int AS out_discards,
             count(*)::smallint      AS sample_count
        FROM snmp_if_samples s
       WHERE s.ts >= ?::timestamptz AND s.ts < ?::timestamptz
       GROUP BY 1, 2
    )
    INSERT INTO ${table} AS r
      (bucket, if_id, in_avg_bps, in_max_bps, in_p95_bps,
       out_avg_bps, out_max_bps, out_p95_bps,
       in_errs, out_errs, in_discards, out_discards, sample_count, expected_count)
    SELECT a.bucket, a.if_id, a.in_avg_bps, a.in_max_bps, a.in_p95_bps,
           a.out_avg_bps, a.out_max_bps, a.out_p95_bps,
           a.in_errs, a.out_errs, a.in_discards, a.out_discards, a.sample_count,
           GREATEST(1, ${bucketSec} / GREATEST(i.effective_poll_sec, 1))::smallint
      FROM agg a
      JOIN snmp_interfaces i ON i.id = a.if_id
     WHERE i.effective_poll_sec <= ${bucketSec}
    ON CONFLICT (if_id, bucket) DO UPDATE SET
      in_avg_bps   = EXCLUDED.in_avg_bps,
      in_max_bps   = EXCLUDED.in_max_bps,
      in_p95_bps   = EXCLUDED.in_p95_bps,
      out_avg_bps  = EXCLUDED.out_avg_bps,
      out_max_bps  = EXCLUDED.out_max_bps,
      out_p95_bps  = EXCLUDED.out_p95_bps,
      in_errs      = EXCLUDED.in_errs,
      out_errs     = EXCLUDED.out_errs,
      in_discards  = EXCLUDED.in_discards,
      out_discards = EXCLUDED.out_discards,
      sample_count = EXCLUDED.sample_count
    WHERE r.sample_count IS DISTINCT FROM EXCLUDED.sample_count
       OR r.in_avg_bps   IS DISTINCT FROM EXCLUDED.in_avg_bps
       OR r.out_avg_bps  IS DISTINCT FROM EXCLUDED.out_avg_bps
    `,
    [lo, hi],
  );
  return Number(result.rowCount ?? 0);
}

async function ifFromRollup5m(lo: string, hi: string): Promise<number> {
  const result = await db.raw<{ rowCount: number }>(
    `
    WITH agg AS (
      SELECT date_bin(INTERVAL '1 hour', b.bucket, ${BUCKET_ORIGIN}) AS bucket,
             b.if_id,
             -- WEIGHTED by the real sample count. avg(avg) would give a bucket
             -- of 1 sample the same weight as a bucket of 10.
             (sum(b.in_avg_bps::numeric * b.sample_count)
                / NULLIF(sum(b.sample_count), 0))::bigint AS in_avg_bps,
             max(b.in_max_bps) AS in_max_bps,
             percentile_cont(0.95) WITHIN GROUP (ORDER BY b.in_avg_bps)::bigint AS in_p95_bps,
             (sum(b.out_avg_bps::numeric * b.sample_count)
                / NULLIF(sum(b.sample_count), 0))::bigint AS out_avg_bps,
             max(b.out_max_bps) AS out_max_bps,
             percentile_cont(0.95) WITHIN GROUP (ORDER BY b.out_avg_bps)::bigint AS out_p95_bps,
             sum(b.in_errs)::int      AS in_errs,
             sum(b.out_errs)::int     AS out_errs,
             sum(b.in_discards)::int  AS in_discards,
             sum(b.out_discards)::int AS out_discards,
             LEAST(sum(b.sample_count), 32767)::smallint   AS sample_count,
             LEAST(sum(b.expected_count), 32767)::smallint AS expected_count
        FROM snmp_if_rollup_5m b
       WHERE b.bucket >= ?::timestamptz AND b.bucket < ?::timestamptz
       GROUP BY 1, 2
    )
    INSERT INTO snmp_if_rollup_1h AS r
      (bucket, if_id, in_avg_bps, in_max_bps, in_p95_bps,
       out_avg_bps, out_max_bps, out_p95_bps,
       in_errs, out_errs, in_discards, out_discards, sample_count, expected_count)
    SELECT bucket, if_id, coalesce(in_avg_bps, 0), in_max_bps, in_p95_bps,
           coalesce(out_avg_bps, 0), out_max_bps, out_p95_bps,
           in_errs, out_errs, in_discards, out_discards,
           sample_count, GREATEST(expected_count, 1)
      FROM agg
    ON CONFLICT (if_id, bucket) DO UPDATE SET
      in_avg_bps     = EXCLUDED.in_avg_bps,
      in_max_bps     = EXCLUDED.in_max_bps,
      in_p95_bps     = EXCLUDED.in_p95_bps,
      out_avg_bps    = EXCLUDED.out_avg_bps,
      out_max_bps    = EXCLUDED.out_max_bps,
      out_p95_bps    = EXCLUDED.out_p95_bps,
      in_errs        = EXCLUDED.in_errs,
      out_errs       = EXCLUDED.out_errs,
      in_discards    = EXCLUDED.in_discards,
      out_discards   = EXCLUDED.out_discards,
      sample_count   = EXCLUDED.sample_count,
      expected_count = EXCLUDED.expected_count
    WHERE r.sample_count IS DISTINCT FROM EXCLUDED.sample_count
       OR r.in_avg_bps   IS DISTINCT FROM EXCLUDED.in_avg_bps
       OR r.out_avg_bps  IS DISTINCT FROM EXCLUDED.out_avg_bps
    `,
    [lo, hi],
  );
  return Number(result.rowCount ?? 0);
}

// ============================================================================
// Device tiers
// ============================================================================

/**
 * THE SENTINELS ARE NOT VALUES AND MUST NOT BE AVERAGED.
 *
 * `cpu_pct = -1` means "not exposed". `avg()` over a mix of -1 and real
 * readings produces a number that is neither, and it is silently plausible.
 * Every aggregate here is `FILTER (WHERE col <> sentinel)` and falls back to
 * the sentinel when the whole bucket was unavailable, so "not measured" stays
 * "not measured" all the way to `unsentinel()` on the display side.
 */
async function devFromSamples(
  table: string,
  interval: string,
  bucketSec: number,
  lo: string,
  hi: string,
): Promise<number> {
  const result = await db.raw<{ rowCount: number }>(
    `
    WITH agg AS (
      SELECT date_bin(INTERVAL '${interval}', s.ts, ${BUCKET_ORIGIN}) AS bucket,
             s.device_id,
             coalesce(avg(s.mem_used_bytes) FILTER (WHERE s.mem_used_bytes <> -1), -1)::bigint
               AS mem_used_avg_bytes,
             coalesce(max(s.mem_used_bytes) FILTER (WHERE s.mem_used_bytes <> -1), -1)::bigint
               AS mem_used_max_bytes,
             coalesce(max(s.mem_total_bytes) FILTER (WHERE s.mem_total_bytes <> -1), -1)::bigint
               AS mem_total_bytes,
             max(s.uptime_ticks) AS uptime_ticks_max,
             coalesce(avg(s.rtt_us) FILTER (WHERE s.rtt_us <> -1), -1)::int AS rtt_avg_us,
             coalesce(max(s.rtt_us) FILTER (WHERE s.rtt_us <> -1), -1)::int AS rtt_max_us,
             coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY s.rtt_us)
                        FILTER (WHERE s.rtt_us <> -1), -1)::int AS rtt_p95_us,
             coalesce(avg(s.cpu_pct) FILTER (WHERE s.cpu_pct <> -1), -1)::smallint AS cpu_avg_pct,
             coalesce(max(s.cpu_pct) FILTER (WHERE s.cpu_pct <> -1), -1)::smallint AS cpu_max_pct,
             coalesce(avg(s.temp_dc) FILTER (WHERE s.temp_dc <> -32768), -32768)::smallint
               AS temp_avg_dc,
             coalesce(max(s.temp_dc) FILTER (WHERE s.temp_dc <> -32768), -32768)::smallint
               AS temp_max_dc,
             count(*) FILTER (WHERE s.reachable)::smallint AS reachable_count,
             count(*)::smallint AS sample_count
        FROM snmp_device_samples s
       WHERE s.ts >= ?::timestamptz AND s.ts < ?::timestamptz
       GROUP BY 1, 2
    )
    INSERT INTO ${table} AS r
      (bucket, mem_used_avg_bytes, mem_used_max_bytes, mem_total_bytes, uptime_ticks_max,
       device_id, rtt_avg_us, rtt_max_us, rtt_p95_us, cpu_avg_pct, cpu_max_pct,
       temp_avg_dc, temp_max_dc, reachable_count, sample_count, expected_count)
    SELECT a.bucket, a.mem_used_avg_bytes, a.mem_used_max_bytes, a.mem_total_bytes,
           a.uptime_ticks_max, a.device_id, a.rtt_avg_us, a.rtt_max_us, a.rtt_p95_us,
           a.cpu_avg_pct, a.cpu_max_pct, a.temp_avg_dc, a.temp_max_dc,
           a.reachable_count, a.sample_count,
           GREATEST(1, ${bucketSec} / GREATEST(coalesce(t.poll_interval_sec, ?), 1))::smallint
      FROM agg a
      LEFT JOIN snmp_targets t ON t.device_id = a.device_id
    ON CONFLICT (device_id, bucket) DO UPDATE SET
      mem_used_avg_bytes = EXCLUDED.mem_used_avg_bytes,
      mem_used_max_bytes = EXCLUDED.mem_used_max_bytes,
      mem_total_bytes    = EXCLUDED.mem_total_bytes,
      uptime_ticks_max   = EXCLUDED.uptime_ticks_max,
      rtt_avg_us         = EXCLUDED.rtt_avg_us,
      rtt_max_us         = EXCLUDED.rtt_max_us,
      rtt_p95_us         = EXCLUDED.rtt_p95_us,
      cpu_avg_pct        = EXCLUDED.cpu_avg_pct,
      cpu_max_pct        = EXCLUDED.cpu_max_pct,
      temp_avg_dc        = EXCLUDED.temp_avg_dc,
      temp_max_dc        = EXCLUDED.temp_max_dc,
      reachable_count    = EXCLUDED.reachable_count,
      sample_count       = EXCLUDED.sample_count
    WHERE r.sample_count    IS DISTINCT FROM EXCLUDED.sample_count
       OR r.reachable_count IS DISTINCT FROM EXCLUDED.reachable_count
       OR r.rtt_avg_us      IS DISTINCT FROM EXCLUDED.rtt_avg_us
    `,
    [lo, hi, snmpConfig.defaultPollIntervalSec],
  );
  return Number(result.rowCount ?? 0);
}

async function devFromRollup5m(lo: string, hi: string): Promise<number> {
  const result = await db.raw<{ rowCount: number }>(
    `
    WITH agg AS (
      SELECT date_bin(INTERVAL '1 hour', b.bucket, ${BUCKET_ORIGIN}) AS bucket,
             b.device_id,
             coalesce((sum(b.mem_used_avg_bytes::numeric * b.sample_count)
                         FILTER (WHERE b.mem_used_avg_bytes <> -1)
                       / NULLIF(sum(b.sample_count) FILTER (WHERE b.mem_used_avg_bytes <> -1), 0)),
                      -1)::bigint AS mem_used_avg_bytes,
             coalesce(max(b.mem_used_max_bytes) FILTER (WHERE b.mem_used_max_bytes <> -1), -1)::bigint
               AS mem_used_max_bytes,
             coalesce(max(b.mem_total_bytes) FILTER (WHERE b.mem_total_bytes <> -1), -1)::bigint
               AS mem_total_bytes,
             max(b.uptime_ticks_max) AS uptime_ticks_max,
             coalesce((sum(b.rtt_avg_us::numeric * b.sample_count) FILTER (WHERE b.rtt_avg_us <> -1)
                       / NULLIF(sum(b.sample_count) FILTER (WHERE b.rtt_avg_us <> -1), 0)),
                      -1)::int AS rtt_avg_us,
             coalesce(max(b.rtt_max_us) FILTER (WHERE b.rtt_max_us <> -1), -1)::int AS rtt_max_us,
             coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY b.rtt_avg_us)
                        FILTER (WHERE b.rtt_avg_us <> -1), -1)::int AS rtt_p95_us,
             coalesce((sum(b.cpu_avg_pct::numeric * b.sample_count) FILTER (WHERE b.cpu_avg_pct <> -1)
                       / NULLIF(sum(b.sample_count) FILTER (WHERE b.cpu_avg_pct <> -1), 0)),
                      -1)::smallint AS cpu_avg_pct,
             coalesce(max(b.cpu_max_pct) FILTER (WHERE b.cpu_max_pct <> -1), -1)::smallint AS cpu_max_pct,
             coalesce(avg(b.temp_avg_dc) FILTER (WHERE b.temp_avg_dc <> -32768), -32768)::smallint
               AS temp_avg_dc,
             coalesce(max(b.temp_max_dc) FILTER (WHERE b.temp_max_dc <> -32768), -32768)::smallint
               AS temp_max_dc,
             LEAST(sum(b.reachable_count), 32767)::smallint AS reachable_count,
             LEAST(sum(b.sample_count), 32767)::smallint    AS sample_count,
             LEAST(sum(b.expected_count), 32767)::smallint  AS expected_count
        FROM snmp_device_rollup_5m b
       WHERE b.bucket >= ?::timestamptz AND b.bucket < ?::timestamptz
       GROUP BY 1, 2
    )
    INSERT INTO snmp_device_rollup_1h AS r
      (bucket, mem_used_avg_bytes, mem_used_max_bytes, mem_total_bytes, uptime_ticks_max,
       device_id, rtt_avg_us, rtt_max_us, rtt_p95_us, cpu_avg_pct, cpu_max_pct,
       temp_avg_dc, temp_max_dc, reachable_count, sample_count, expected_count)
    SELECT bucket, mem_used_avg_bytes, mem_used_max_bytes, mem_total_bytes, uptime_ticks_max,
           device_id, rtt_avg_us, rtt_max_us, rtt_p95_us, cpu_avg_pct, cpu_max_pct,
           temp_avg_dc, temp_max_dc, reachable_count, sample_count, GREATEST(expected_count, 1)
      FROM agg
    ON CONFLICT (device_id, bucket) DO UPDATE SET
      mem_used_avg_bytes = EXCLUDED.mem_used_avg_bytes,
      mem_used_max_bytes = EXCLUDED.mem_used_max_bytes,
      mem_total_bytes    = EXCLUDED.mem_total_bytes,
      uptime_ticks_max   = EXCLUDED.uptime_ticks_max,
      rtt_avg_us         = EXCLUDED.rtt_avg_us,
      rtt_max_us         = EXCLUDED.rtt_max_us,
      rtt_p95_us         = EXCLUDED.rtt_p95_us,
      cpu_avg_pct        = EXCLUDED.cpu_avg_pct,
      cpu_max_pct        = EXCLUDED.cpu_max_pct,
      temp_avg_dc        = EXCLUDED.temp_avg_dc,
      temp_max_dc        = EXCLUDED.temp_max_dc,
      reachable_count    = EXCLUDED.reachable_count,
      sample_count       = EXCLUDED.sample_count,
      expected_count     = EXCLUDED.expected_count
    WHERE r.sample_count    IS DISTINCT FROM EXCLUDED.sample_count
       OR r.reachable_count IS DISTINCT FROM EXCLUDED.reachable_count
       OR r.rtt_avg_us      IS DISTINCT FROM EXCLUDED.rtt_avg_us
    `,
    [lo, hi],
  );
  return Number(result.rowCount ?? 0);
}

// ============================================================================
// The tier table
// ============================================================================

const TIERS: TierSpec[] = [
  {
    tier: 'if_1m',
    interval: '1 minute',
    bucketSec: 60,
    run: (lo, hi) => ifFromSamples('snmp_if_rollup_1m', '1 minute', 60, lo, hi),
  },
  {
    tier: 'if_5m',
    interval: '5 minutes',
    bucketSec: 300,
    run: (lo, hi) => ifFromSamples('snmp_if_rollup_5m', '5 minutes', 300, lo, hi),
  },
  { tier: 'if_1h', interval: '1 hour', bucketSec: 3600, run: ifFromRollup5m },
  {
    tier: 'dev_1m',
    interval: '1 minute',
    bucketSec: 60,
    run: (lo, hi) => devFromSamples('snmp_device_rollup_1m', '1 minute', 60, lo, hi),
  },
  {
    tier: 'dev_5m',
    interval: '5 minutes',
    bucketSec: 300,
    run: (lo, hi) => devFromSamples('snmp_device_rollup_5m', '5 minutes', 300, lo, hi),
  },
  { tier: 'dev_1h', interval: '1 hour', bucketSec: 3600, run: devFromRollup5m },
];

export interface TierRunResult {
  tier: SeriesTier;
  from: string;
  to: string;
  rows: number;
  durationMs: number;
  skipped: boolean;
  jumped: boolean;
}

// ============================================================================
// One tier, one run
// ============================================================================

export async function runTier(spec: TierSpec): Promise<TierRunResult> {
  const started = Date.now();

  const bounds = await db.raw<{
    rows: Array<{ lo: string; hi: string; watermark: string; behind_sec: string }>;
  }>(
    `
    SELECT
      (s.watermark - INTERVAL '${OVERLAP_BUCKETS * spec.bucketSec} seconds')     AS lo,
      LEAST(
        date_bin(INTERVAL '${spec.interval}',
                 now() - INTERVAL '${CLOSE_LAG_SEC} seconds', ${BUCKET_ORIGIN}),
        s.watermark + INTERVAL '${MAX_BUCKETS_PER_RUN * spec.bucketSec} seconds'
      )                                                                          AS hi,
      s.watermark                                                                AS watermark,
      EXTRACT(EPOCH FROM (now() - s.watermark))                                  AS behind_sec
      FROM series_rollup_state s
     WHERE s.tier = ?
    `,
    [spec.tier],
  );

  const row = bounds.rows?.[0];
  if (!row) {
    logger.error({ tier: spec.tier }, 'Rollup: no watermark row — 006_timeseries.ts seeds all six');
    return { tier: spec.tier, from: '', to: '', rows: 0, durationMs: 0, skipped: true, jumped: false };
  }

  // The give-up jump. The source rows for those buckets no longer exist, so
  // aggregating them can only produce nothing -- slowly.
  if (Number(row.behind_sec) > GIVE_UP_BEHIND_SEC) {
    const jumped = await db.raw<{ rows: Array<{ watermark: string }> }>(
      `UPDATE series_rollup_state
          SET watermark = date_bin(INTERVAL '${spec.interval}',
                                   now() - INTERVAL '${CLOSE_LAG_SEC} seconds', ${BUCKET_ORIGIN})
                          - INTERVAL '${OVERLAP_BUCKETS * spec.bucketSec} seconds',
              last_run_at = now()
        WHERE tier = ?
        RETURNING watermark`,
      [spec.tier],
    );
    logger.warn(
      { tier: spec.tier, behindSec: Number(row.behind_sec), newWatermark: jumped.rows?.[0]?.watermark },
      'Rollup watermark JUMPED: further behind than the raw retention, those buckets are ' +
        'unrecoverable — this is a series gap, not a silent success',
    );
    return {
      tier: spec.tier,
      from: row.watermark,
      to: String(jumped.rows?.[0]?.watermark ?? ''),
      rows: 0,
      durationMs: Date.now() - started,
      skipped: true,
      jumped: true,
    };
  }

  const lo = new Date(row.lo).toISOString();
  const hi = new Date(row.hi).toISOString();
  if (new Date(hi).getTime() <= new Date(row.watermark).getTime()) {
    // Nothing has closed since the last run. Normal on every tier whose bucket
    // is wider than the tick.
    return { tier: spec.tier, from: lo, to: hi, rows: 0, durationMs: Date.now() - started, skipped: true, jumped: false };
  }

  try {
    const rows = await spec.run(lo, hi);
    const durationMs = Date.now() - started;
    await db('series_rollup_state').where({ tier: spec.tier }).update({
      watermark: hi,
      last_run_at: db.fn.now(),
      last_duration_ms: durationMs,
      last_rows: rows,
      consecutive_errors: 0,
    });
    return { tier: spec.tier, from: lo, to: hi, rows, durationMs, skipped: false, jumped: false };
  } catch (err) {
    // The watermark is NOT moved on a failure: the next run retries the same
    // window. Moving it would turn a transient error into a permanent hole.
    await db('series_rollup_state')
      .where({ tier: spec.tier })
      .update({
        last_run_at: db.fn.now(),
        consecutive_errors: db.raw('LEAST(consecutive_errors + 1, 32767)'),
      });
    logger.error({ err, tier: spec.tier, lo, hi }, 'Rollup tier failed — watermark held');
    throw err;
  }
}

export async function runAllRollups(): Promise<TierRunResult[]> {
  const results: TierRunResult[] = [];
  for (const spec of TIERS) {
    try {
      results.push(await runTier(spec));
    } catch {
      results.push({
        tier: spec.tier,
        from: '',
        to: '',
        rows: 0,
        durationMs: 0,
        skipped: true,
        jumped: false,
      });
    }
  }
  return results;
}

// ============================================================================
// The timer
// ============================================================================

let timer: NodeJS.Timeout | null = null;
let unsubscribe: (() => void) | null = null;
let running = false;

/**
 * Rollups run on the LEADER ONLY (arbitrage A5).
 *
 * Two replicas running them concurrently would not corrupt the data -- the
 * `ON CONFLICT` makes each run idempotent -- but they would both advance the
 * same watermark, so half the windows would be skipped by whichever process
 * lost the race. Idempotent is not the same as concurrent-safe.
 */
export function startRollups(): void {
  if (unsubscribe) return;
  unsubscribe = leaderElection.onChange((isLeader) => {
    if (isLeader && !timer) {
      timer = setInterval(() => {
        if (running) return; // a run that overruns its tick must not stack
        running = true;
        void runAllRollups()
          .then((results) => {
            const worked = results.filter((r) => !r.skipped);
            if (worked.length > 0) {
              logger.debug(
                { tiers: worked.map((r) => `${r.tier}:${r.rows}r/${r.durationMs}ms`) },
                'Rollups done',
              );
            }
          })
          .catch((err) => logger.error({ err }, 'Rollup cycle failed'))
          .finally(() => {
            running = false;
          });
      }, snmpConfig.rollupTickMs);
      logger.info({ everyMs: snmpConfig.rollupTickMs }, 'Rollup job armed (leader)');
    } else if (!isLeader && timer) {
      clearInterval(timer);
      timer = null;
      logger.info('Rollup job disarmed (no longer leader)');
    }
  });
}

export function stopRollups(): void {
  unsubscribe?.();
  unsubscribe = null;
  if (timer) clearInterval(timer);
  timer = null;
}
