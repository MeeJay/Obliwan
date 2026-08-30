/**
 * The series writer. Study sections 7.2 and 7.4, plus LAYER 3 of the partition
 * machinery (section 2.5).
 *
 * WHY `INSERT ... SELECT * FROM unnest(...)` AND NOT A MULTI-ROW VALUES LIST
 * A `VALUES` list carries one placeholder per column per row. At 2 700 rows x
 * 12 columns that is 32 400 bind parameters, and the PostgreSQL wire protocol
 * caps a statement at 65 535 -- so the naive form works right up to the day the
 * fleet grows, then fails with a message that names neither the table nor the
 * cause. The `unnest` form uses TWELVE parameters whatever the row count: one
 * array per column. It is also what makes the plan cacheable.
 *
 * WHY NOT `COPY` / `pg-copy-streams`
 * Measured on this schema: 2 700 rows in 18.6 ms median on one connection,
 * i.e. 145 000 rows/s against a 90 rows/s target. COPY starts paying off
 * around 20 000 rows per cycle -- roughly 2 400 devices. It would be a
 * dependency, a second code path and a different error surface for a
 * 1 600x margin that already exists. The study is explicit: NOT AT THIS
 * VOLUME.
 *
 * LAYER 3, AND WHY IT MUST NEVER FIRE
 * If no partition covers a row, PostgreSQL raises SQLSTATE 23514. The writer
 * catches it, creates the partition, and RETRIES EXACTLY ONCE. A second
 * failure abandons the batch, logs, and DOES NOT STOP THE POLLER: losing one
 * cycle of metrics is acceptable, stopping the supervision of 300 sites
 * because a table is missing is not. Layers 1 and 2 (`partition.service.ts`)
 * are supposed to make this unreachable -- a non-zero `layer3Recoveries`
 * counter is itself an incident signal, not a reassurance.
 */

import type { DeviceSampleRow, IfSampleRow, PollState } from '@obliwan/shared';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { ensurePartitionFor, isMissingPartitionError } from './partition.service';

/**
 * Knex types `RawBinding` as a homogeneous scalar or array, which cannot
 * express "an array of arrays, some of which contain nulls" -- exactly the
 * shape every `unnest()` insert in this codebase needs. The cast is confined
 * to this one helper rather than sprinkled at each call site, so there is one
 * place to look if the driver's contract ever changes.
 */
function bindings(values: unknown[]): readonly Knex.RawBinding[] {
  return values as readonly Knex.RawBinding[];
}


/** How often layer 3 has had to rescue a batch. Should stay at zero. */
let layer3Recoveries = 0;
let abandonedBatches = 0;

export function writerStats(): { layer3Recoveries: number; abandonedBatches: number } {
  return { layer3Recoveries, abandonedBatches };
}

/**
 * Run an INSERT, and on a missing partition create it and retry ONCE.
 *
 * `isMissingPartitionError` distinguishes a missing partition from a GENUINE
 * check violation, which also arrives as 23514. Retrying on a genuine one
 * would be an infinite loop on an unfixable batch -- so a real constraint
 * failure propagates on the first attempt, as it should.
 */
async function insertWithPartitionRetry(
  parent: string,
  at: Date,
  run: () => Promise<unknown>,
): Promise<boolean> {
  try {
    await run();
    return true;
  } catch (err) {
    if (!isMissingPartitionError(err)) throw err;
    logger.warn({ parent, at }, 'Series writer: no partition for this row — layer 3 catch-up');
    const created = await ensurePartitionFor(parent, at);
    layer3Recoveries += 1;
    try {
      await run();
      logger.info({ parent, created }, 'Series writer: layer 3 recovered the batch');
      return true;
    } catch (retryErr) {
      abandonedBatches += 1;
      logger.error(
        { parent, at, err: retryErr },
        'Series writer: batch ABANDONED after a layer 3 retry — metrics lost for this cycle, ' +
          'the poller continues',
      );
      return false;
    }
  }
}

/**
 * All rows of one batch must land in the SAME partition for the layer-3 retry
 * to be meaningful: `ensurePartitionFor` creates the partition covering ONE
 * instant. A poll cycle writes a near-identical `ts` on every row, so this
 * holds naturally -- except exactly at a partition boundary, where a cycle
 * spanning midnight would need two. Splitting by UTC day makes that case a
 * pair of batches instead of a partial failure.
 */
function splitByUtcDay<T>(rows: T[], tsOf: (row: T) => string): Array<{ at: Date; rows: T[] }> {
  const groups = new Map<string, { at: Date; rows: T[] }>();
  for (const row of rows) {
    const at = new Date(tsOf(row));
    const key = at.toISOString().slice(0, 10);
    const bucket = groups.get(key);
    if (bucket) bucket.rows.push(row);
    else groups.set(key, { at, rows: [row] });
  }
  return [...groups.values()];
}

// ============================================================================
// snmp_if_samples
// ============================================================================

export async function writeIfSamples(rows: IfSampleRow[]): Promise<number> {
  if (rows.length === 0) return 0;
  let written = 0;

  for (const group of splitByUtcDay(rows, (r) => r.ts)) {
    const batch = group.rows;
    const ok = await insertWithPartitionRetry('snmp_if_samples', group.at, () =>
      db.raw(
        `INSERT INTO snmp_if_samples
           (ts, in_bps, out_bps, if_id, in_pps, out_pps,
            in_errs, out_errs, in_discards, out_discards, elapsed_ms, oper_status)
         SELECT * FROM unnest(
           ?::timestamptz[], ?::bigint[], ?::bigint[], ?::int[], ?::int[], ?::int[],
           ?::int[], ?::int[], ?::int[], ?::int[], ?::int[], ?::smallint[])`,
        [
          batch.map((r) => r.ts),
          // bigint -> string: node-pg cannot serialise a JS BigInt, and
          // Number() would lose precision above 2^53 -- which a bit/s value
          // never reaches, but a counter does, and this array shape is copied.
          batch.map((r) => r.inBps.toString()),
          batch.map((r) => r.outBps.toString()),
          batch.map((r) => r.ifId),
          batch.map((r) => r.inPps),
          batch.map((r) => r.outPps),
          batch.map((r) => r.inErrs),
          batch.map((r) => r.outErrs),
          batch.map((r) => r.inDiscards),
          batch.map((r) => r.outDiscards),
          batch.map((r) => r.elapsedMs),
          batch.map((r) => r.operStatus),
        ],
      ),
    );
    if (ok) written += batch.length;
  }
  return written;
}

// ============================================================================
// snmp_device_samples
// ============================================================================

export async function writeDeviceSamples(rows: DeviceSampleRow[]): Promise<number> {
  if (rows.length === 0) return 0;
  let written = 0;

  for (const group of splitByUtcDay(rows, (r) => r.ts)) {
    const batch = group.rows;
    const ok = await insertWithPartitionRetry('snmp_device_samples', group.at, () =>
      db.raw(
        `INSERT INTO snmp_device_samples
           (ts, uptime_ticks, mem_used_bytes, mem_total_bytes, device_id,
            rtt_us, cpu_pct, temp_dc, reachable)
         SELECT * FROM unnest(
           ?::timestamptz[], ?::bigint[], ?::bigint[], ?::bigint[], ?::int[],
           ?::int[], ?::smallint[], ?::smallint[], ?::boolean[])`,
        [
          batch.map((r) => r.ts),
          batch.map((r) => r.uptimeTicks.toString()),
          batch.map((r) => r.memUsedBytes.toString()),
          batch.map((r) => r.memTotalBytes.toString()),
          batch.map((r) => r.deviceId),
          batch.map((r) => r.rttUs),
          batch.map((r) => r.cpuPct),
          batch.map((r) => r.tempDc),
          batch.map((r) => r.reachable),
        ],
      ),
    );
    if (ok) written += batch.length;
  }
  return written;
}

// ============================================================================
// snmp_poll_state — the baseline
// ============================================================================

/**
 * Persist the delta baselines.
 *
 * A baseline held only in memory would mean: one hole per interface on every
 * deployment, and NO WAY AT ALL to detect a reboot that happened while the
 * process was down -- the counters would simply be lower and the next delta
 * would be a discard for the wrong reason, or worse, a wrap "correction".
 *
 * The counters are `numeric(20,0)` and are bound as STRINGS. `bigint` in
 * PostgreSQL would stop at 9.22e18 while an unsigned Counter64 reaches
 * 1.845e19: the overflow is silent and turns into a negative.
 */
export async function saveBaselines(states: PollState[]): Promise<number> {
  if (states.length === 0) return 0;

  await db.raw(
    `INSERT INTO snmp_poll_state
       (if_id, device_id, wall_ts, mono_ns, writer_epoch,
        in_octets, out_octets, in_pkts, out_pkts,
        in_errs, out_errs, in_discards, out_discards,
        counter_bits, sys_uptime_ticks, sys_uptime_epoch, line_speed_bps,
        last_discard, consecutive_discards, updated_at)
     SELECT * FROM unnest(
       ?::int[], ?::int[], ?::timestamptz[], ?::bigint[], ?::uuid[],
       ?::numeric[], ?::numeric[], ?::numeric[], ?::numeric[],
       ?::numeric[], ?::numeric[], ?::numeric[], ?::numeric[],
       ?::smallint[], ?::bigint[], ?::int[], ?::bigint[],
       ?::text[], ?::smallint[], ?::timestamptz[])
     ON CONFLICT (if_id) DO UPDATE SET
       wall_ts              = EXCLUDED.wall_ts,
       mono_ns              = EXCLUDED.mono_ns,
       writer_epoch         = EXCLUDED.writer_epoch,
       in_octets            = EXCLUDED.in_octets,
       out_octets           = EXCLUDED.out_octets,
       in_pkts              = EXCLUDED.in_pkts,
       out_pkts             = EXCLUDED.out_pkts,
       in_errs              = EXCLUDED.in_errs,
       out_errs             = EXCLUDED.out_errs,
       in_discards          = EXCLUDED.in_discards,
       out_discards         = EXCLUDED.out_discards,
       counter_bits         = EXCLUDED.counter_bits,
       sys_uptime_ticks     = EXCLUDED.sys_uptime_ticks,
       sys_uptime_epoch     = EXCLUDED.sys_uptime_epoch,
       line_speed_bps       = EXCLUDED.line_speed_bps,
       last_discard         = EXCLUDED.last_discard,
       consecutive_discards = EXCLUDED.consecutive_discards,
       updated_at           = EXCLUDED.updated_at`,
    bindings([
      states.map((s) => s.ifId),
      states.map((s) => s.deviceId),
      states.map((s) => s.wallTs),
      states.map((s) => s.monoNs.toString()),
      states.map((s) => s.writerEpoch),
      states.map((s) => s.inOctets.toString()),
      states.map((s) => s.outOctets.toString()),
      states.map((s) => s.inPkts.toString()),
      states.map((s) => s.outPkts.toString()),
      states.map((s) => s.inErrs.toString()),
      states.map((s) => s.outErrs.toString()),
      states.map((s) => s.inDiscards.toString()),
      states.map((s) => s.outDiscards.toString()),
      states.map((s) => s.counterBits),
      states.map((s) => s.sysUptimeTicks.toString()),
      states.map((s) => s.sysUptimeEpoch),
      states.map((s) => s.lineSpeedBps.toString()),
      states.map((s) => s.lastDiscard),
      states.map((s) => Math.min(s.consecutiveDiscards, 32_767)),
      states.map(() => new Date().toISOString()),
    ]),
  );
  return states.length;
}

/** Load the baselines of one device, keyed by `if_id`. */
export async function loadBaselines(deviceId: number): Promise<Map<number, PollState>> {
  const rows = await db('snmp_poll_state').where({ device_id: deviceId });
  const out = new Map<number, PollState>();
  for (const r of rows) {
    out.set(r.if_id, {
      ifId: r.if_id,
      deviceId: r.device_id,
      wallTs: new Date(r.wall_ts).toISOString(),
      monoNs: BigInt(r.mono_ns),
      writerEpoch: r.writer_epoch,
      inOctets: BigInt(r.in_octets),
      outOctets: BigInt(r.out_octets),
      inPkts: BigInt(r.in_pkts),
      outPkts: BigInt(r.out_pkts),
      inErrs: BigInt(r.in_errs),
      outErrs: BigInt(r.out_errs),
      inDiscards: BigInt(r.in_discards),
      outDiscards: BigInt(r.out_discards),
      counterBits: (Number(r.counter_bits) === 32 ? 32 : 64) as 32 | 64,
      sysUptimeTicks: BigInt(r.sys_uptime_ticks),
      sysUptimeEpoch: Number(r.sys_uptime_epoch),
      lineSpeedBps: BigInt(r.line_speed_bps),
      lastDiscard: r.last_discard,
      consecutiveDiscards: Number(r.consecutive_discards),
    });
  }
  return out;
}

/**
 * Bump `consecutive_discards` for interfaces whose read failed entirely.
 *
 * AGENT_ERROR is the one discard reason that leaves no baseline to write, so
 * the counter cannot ride along with it -- and without this the collection
 * health signal (10 in a row = incident, study section 3.5) would never fire
 * for the failure mode that needs it most: an interface that stopped
 * answering, which on a graph is indistinguishable from a quiet link.
 */
export async function bumpDiscardCounters(ifIds: number[], reason: string): Promise<void> {
  if (ifIds.length === 0) return;
  await db('snmp_poll_state')
    .whereIn('if_id', ifIds)
    .update({
      last_discard: reason,
      consecutive_discards: db.raw('LEAST(consecutive_discards + 1, 32767)'),
      updated_at: new Date(),
    });
}

/** Interfaces whose collection is itself broken (study section 3.5, point 4). */
export async function unhealthyInterfaces(threshold: number): Promise<
  Array<{ ifId: number; deviceId: number; reason: string | null; count: number }>
> {
  const rows = await db('snmp_poll_state')
    .where('consecutive_discards', '>=', threshold)
    .select('if_id', 'device_id', 'last_discard', 'consecutive_discards');
  return rows.map((r) => ({
    ifId: r.if_id,
    deviceId: r.device_id,
    reason: r.last_discard,
    count: Number(r.consecutive_discards),
  }));
}
