import type { PartitionGrain, SeriesPartitionPolicy } from '@obliwan/shared';
import { db } from '../../db';
import { leaderElection } from '../leaderElection';
import { logger } from '../../utils/logger';

/**
 * partition.service.ts — the TypeScript half of the partition machinery.
 *
 * Implements section 2 of `docs/M3-series-temporelles.md`. The SQL half —
 * `ensure_series_partition()` / `ensure_series_partitions()` and the
 * `series_partition_policy` table — lives in migration 006_timeseries.ts, on
 * purpose: those functions are called from three different contexts and must
 * stay runnable by hand during an incident.
 *
 * ┌─ THE THREE LAYERS, IN THIS ORDER (study §2.5) ────────────────────────────┐
 * │                                                                           │
 * │ LAYER 1 — at startup, SYNCHRONOUS, BEFORE the scheduler starts.           │
 * │   `ensureAllPartitions()` from the server bootstrap, before any poll task │
 * │   is registered. Idempotent, and it runs on EVERY node, leader or not: it │
 * │   is cheap (one catalogue query plus 0..N creations) and it removes every │
 * │   race between "I have been elected leader" and "the first poll fired".   │
 * │   THIS ORDER MUST BE COVERED BY A TEST, not just by a code review.        │
 * │                                                                           │
 * │ LAYER 2 — hourly job, LEADER ONLY.                                        │
 * │   At H+07 (offset so it does not land on the rollups):                    │
 * │     1. finalizePendingDetaches()                                          │
 * │     2. ensureAllPartitions()   — creates out to J+14                      │
 * │     3. dropExpiredPartitions() — ONE TRANSACTION PER PARTITION            │
 * │     4. analyzeCurrentPartitions()                                         │
 * │   Hourly and not daily: a daily job that fails has no second chance for   │
 * │   24 h. Hourly it has 24 attempts a day, and the alert only fires on 3    │
 * │   consecutive failures.                                                   │
 * │                                                                           │
 * │ LAYER 3 — catch-up in the INSERT path.                                    │
 * │   If no partition covers a row anyway, PostgreSQL raises SQLSTATE 23514.  │
 * │   The writer catches it (`isMissingPartitionError`), calls                │
 * │   `ensurePartitionFor()`, and RETRIES EXACTLY ONCE. If the second attempt │
 * │   fails the batch is abandoned, a counter is incremented and an error is  │
 * │   logged — BUT THE POLLER DOES NOT STOP. Losing one cycle of metrics is   │
 * │   acceptable; stopping the supervision of 300 sites because a table is    │
 * │   missing is not.                                                         │
 * │                                                                           │
 * │ The three layers are redundant ON PURPOSE. Layer 3 must never fire in     │
 * │ normal operation: a non-zero counter there is itself an incident signal.  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * WHY DROP AND NEVER DELETE — the numbers, so nobody re-opens the question.
 * On the 6.9 M rows of one day of `snmp_if_samples`:
 *
 *                              DELETE            DROP
 *   rows touched               6 912 000         0
 *   duration                   60-300 s          < 50 ms
 *   WAL generated              ~1.4 GB           a few KB
 *   dead tuples created        6.9 M             0
 *   space returned to the OS   ZERO              912 MB, immediately
 *
 * The decisive line is the last one. A DELETE leaves 636 MB of dead heap that
 * VACUUM will mark reusable FOR THIS TABLE — and reusing pages in the middle of
 * an append-only file DESTROYS the physical correlation the BRIN index depends
 * on. You lose the space AND the index.
 */

// ── Tunables ───────────────────────────────────────────────────────────────

/**
 * Minute of the hour at which the maintenance job runs. Offset from :00 so it
 * does not contend with the rollup jobs, which are aligned on the minute.
 */
const MAINTENANCE_MINUTE = 7;

/**
 * Lock timeout for the DETACH step. A partition DROP takes an ACCESS EXCLUSIVE
 * on the partition AND a lock on the parent, which waits for every in-flight
 * query on the partitioned table. A graph open in the UI scanning 48 h can hold
 * that off — and a waiting DROP then blocks every subsequent write, so the
 * poller freezes. Three seconds, then GIVE UP AND RETRY NEXT CYCLE: a failed
 * DROP justifies neither an immediate retry nor an escalation, the partition
 * will be dropped an hour from now.
 */
const DETACH_LOCK_TIMEOUT = '3s';

/**
 * One unit of look-BACK on top of the policy's look-ahead. Not decoration: it
 * covers the UTC midnight boundary, where a poll cycle that started at 23:59:59
 * carries a `ts` on the previous day, and it lets a late retry land after a
 * fresh install.
 */
const LOOKBACK_UNITS = 1;

/** SQLSTATE PostgreSQL raises for "no partition of relation found for row". It
 *  is the generic check-violation code — 23514 — which is why the message has
 *  to be inspected too. */
const CHECK_VIOLATION = '23514';

/**
 * Regexes that pull the range bounds back out of
 * `pg_get_expr(relpartbound)`, whose text is
 * `FOR VALUES FROM ('2026-08-28 00:00:00+00') TO ('2026-08-29 00:00:00+00')`.
 *
 * NOTE THE `[(]` / `[)]` INSTEAD OF `\(` / `\)`. These strings are embedded in
 * JavaScript template literals, where `\(` is an unrecognised escape that
 * silently collapses to `(` — so the regex that reaches PostgreSQL would open a
 * capture group instead of matching a parenthesis, match NOTHING, and every
 * bound would come back NULL. Nothing would throw: retention would simply stop
 * dropping anything, forever, and the first symptom would be a full disk.
 * (Observed for real while writing this file.) A bracket expression means the
 * same thing to POSIX ARE and contains no backslash to lose.
 */
const RE_LOWER_BOUND = "'FROM [(]''([^'']+)''[)]'";
const RE_UPPER_BOUND = "'TO [(]''([^'']+)''[)]'";

// ── Types ──────────────────────────────────────────────────────────────────

export interface EnsureResult {
  /** Partitions confirmed present (created or already there), per parent. */
  ensured: Record<string, number>;
  /** Parents whose ensure step threw. Logged, never thrown. */
  failures: Array<{ parent: string; error: string }>;
}

export interface DropResult {
  dropped: string[];
  /** Partitions that were due but could not be taken — almost always the
   *  3-second lock timeout. Not an error: next cycle will get them. */
  deferred: Array<{ partition: string; reason: string }>;
}

export interface MaintenanceResult extends EnsureResult, DropResult {
  finalized: string[];
  analyzed: string[];
  durationMs: number;
}

interface PolicyRow {
  parent: string;
  grain: PartitionGrain;
  part_column: string;
  retention: string;
  precreate_units: number;
  enabled: boolean;
}

/** A pg connection, narrowed to what we use. Taken straight from the Knex pool
 *  because `ALTER TABLE ... DETACH PARTITION ... CONCURRENTLY` CANNOT run
 *  inside a transaction block, so `db.transaction()` is not an option, and
 *  `SET lock_timeout` has to apply to the same backend as the DETACH. */
interface RawConnection {
  query(sql: string): Promise<unknown>;
}

// ── Policy ─────────────────────────────────────────────────────────────────

/**
 * Read the partition policy from the database.
 *
 * `retention` comes back as `retention::text` rather than as an interval,
 * because node-postgres parses intervals into an object and we never do
 * arithmetic on it here: every comparison against it happens server-side, where
 * `now() - pol.retention` is exact and time-zone-safe.
 */
export async function getPolicy(): Promise<SeriesPartitionPolicy[]> {
  const { rows } = await db.raw<{ rows: PolicyRow[] }>(
    `SELECT parent, grain, part_column, retention::text AS retention,
            precreate_units, enabled
       FROM series_partition_policy
      ORDER BY parent`,
  );
  return rows.map((r) => ({
    parent: r.parent,
    grain: r.grain,
    partColumn: r.part_column,
    retention: r.retention,
    precreateUnits: r.precreate_units,
    enabled: r.enabled,
  }));
}

// ── Layer 1 / Layer 2 step 2 — creation ────────────────────────────────────

/**
 * Make sure every enabled series table has its partitions, from one unit back
 * to `precreateUnits` ahead.
 *
 * THIS FUNCTION NEVER THROWS. It is on the boot path, and a partition that
 * cannot be created must not stop a server from serving HTTP, from answering
 * the API, or from showing the operator what is wrong. A per-parent failure is
 * logged at `error` and reported in the result; the caller decides.
 *
 * THE "SERVER WAS DOWN FOR THREE DAYS" CASE. There is nothing special to do,
 * and that is the whole point of pre-creating 14 days: the partitions for today
 * already exist, written a fortnight ago. The case that actually needs this
 * function is the harder one — down for MORE than 14 days, or restored from a
 * backup older than that — where nothing covers today. Then this call creates
 * today's partition (and the next 14) before the scheduler is allowed to start.
 * That is why layer 1 is synchronous and why it runs before poll registration.
 */
export async function ensureAllPartitions(): Promise<EnsureResult> {
  const result: EnsureResult = { ensured: {}, failures: [] };

  let policy: SeriesPartitionPolicy[];
  try {
    policy = await getPolicy();
  } catch (err) {
    // The policy table itself is unreadable: migrations have not run, or the
    // database is down. Both are the bootstrap's problem, not ours.
    logger.error({ err }, 'Partitions: cannot read series_partition_policy');
    return { ensured: {}, failures: [{ parent: '*', error: String(err) }] };
  }

  for (const p of policy) {
    if (!p.enabled) {
      logger.warn({ parent: p.parent }, 'Partitions: policy disabled, skipping');
      continue;
    }
    try {
      const { rows } = await db.raw<{ rows: Array<{ n: number }> }>(
        'SELECT ensure_series_partitions(?::regclass, ?, ?, ?) AS n',
        [p.parent, p.grain, LOOKBACK_UNITS, p.precreateUnits],
      );
      result.ensured[p.parent] = Number(rows[0]?.n ?? 0);
    } catch (err) {
      result.failures.push({ parent: p.parent, error: String(err) });
      logger.error({ err, parent: p.parent }, 'Partitions: ensure failed');
    }
  }

  if (result.failures.length > 0) {
    logger.error(
      { failures: result.failures.map((f) => f.parent) },
      'Partitions: some parents could not be provisioned — writes to them will ' +
        'fall back to the layer-3 catch-up path',
    );
  } else {
    logger.info({ ensured: result.ensured }, 'Partitions: all parents provisioned');
  }
  return result;
}

/**
 * Layer 3. Create the single partition that covers `at` for one parent.
 *
 * Called from the writer's error path after SQLSTATE 23514, and nowhere else in
 * normal operation. It looks the grain up in the policy so the caller only has
 * to know the table name.
 */
export async function ensurePartitionFor(parent: string, at: Date): Promise<string | null> {
  const { rows } = await db.raw<{ rows: Array<{ grain: PartitionGrain }> }>(
    'SELECT grain FROM series_partition_policy WHERE parent = ?',
    [parent],
  );
  const grain = rows[0]?.grain;
  if (!grain) {
    logger.error({ parent }, 'Partitions: no policy row — cannot create on demand');
    return null;
  }

  const { rows: created } = await db.raw<{ rows: Array<{ name: string }> }>(
    'SELECT ensure_series_partition(?::regclass, ?, ?::timestamptz) AS name',
    [parent, grain, at.toISOString()],
  );
  const name = created[0]?.name ?? null;
  // A layer-3 activation is an incident signal in itself: layers 1 and 2 should
  // have made it unnecessary. Logged at warn so it is visible without being
  // paged on.
  logger.warn(
    { parent, at: at.toISOString(), partition: name },
    'Partitions: LAYER 3 catch-up fired — layers 1/2 should have covered this',
  );
  return name;
}

/**
 * True when `err` is PostgreSQL telling us no partition covers the row.
 *
 * PostgreSQL reports it as a plain check violation (23514), the same code as
 * any CHECK constraint, so the code alone is not enough: `snmp_if_samples` also
 * carries `snmp_if_samples_sane_chk`, and retrying a batch that violates THAT
 * would loop forever. The message is what distinguishes them.
 */
export function isMissingPartitionError(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const e = err as { code?: string; message?: string };
  return e.code === CHECK_VIOLATION && /no partition of relation/i.test(e.message ?? '');
}

// ── Layer 2 step 1 — finalize interrupted detaches ─────────────────────────

/**
 * Recover — and RECLAIM — partitions left behind by an interrupted detach.
 *
 * `ALTER TABLE ... DETACH PARTITION ... CONCURRENTLY` runs in two internal
 * phases and cannot be wrapped in a transaction. If the process dies between
 * them — or, far more commonly, if the 3-second `lock_timeout` fires while a
 * long-running graph query holds the parent — the partition is left in DETACH
 * PENDING: still listed in `pg_inherits`, invisible to the planner, and
 * impossible to detach again. Nothing recovers from that on its own.
 *
 * ┌─ AND FINALIZE ALONE IS NOT ENOUGH ────────────────────────────────────────┐
 * │ Observed while testing this file: a DROP that times out under a reader     │
 * │ leaves `inhdetachpending = true`. `dropExpiredPartitions()` then SKIPS the │
 * │ partition forever (it must — it can no longer be detached), and FINALIZE   │
 * │ turns it into a standalone table that is no longer a partition of          │
 * │ anything, so the retention query never sees it again either. A full day of │
 * │ samples — 912 MB — would sit on disk permanently, and every subsequent     │
 * │ lock-timeout would add another. The reclaim step below is what closes that │
 * │ hole, and it is why this function drops as well as finalizes.              │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * The sweep only ever touches a table whose name matches `<policy parent>_` +
 * 8 digits AND which is not currently a partition of anything — that shape is
 * produced by `ensure_series_partition()` and by nothing else, so an orphan
 * with that name IS a failed drop. IF YOU EVER WANT TO KEEP A DETACHED
 * PARTITION (to archive a day of raw samples, say), RENAME IT FIRST.
 */
export async function finalizePendingDetaches(): Promise<string[]> {
  const { rows } = await db.raw<{ rows: Array<{ parent: string; child: string }> }>(
    `SELECT p.relname AS parent, c.relname AS child
       FROM pg_inherits i
       JOIN pg_class p ON p.oid = i.inhparent
       JOIN pg_class c ON c.oid = i.inhrelid
       JOIN series_partition_policy pol ON pol.parent = p.relname
      WHERE i.inhdetachpending`,
  );

  const finalized: string[] = [];
  for (const row of rows) {
    try {
      await db.raw(
        `ALTER TABLE ${qualify(row.parent)} DETACH PARTITION ${qualify(row.child)} FINALIZE`,
      );
      finalized.push(row.child);
      logger.warn(
        { parent: row.parent, partition: row.child },
        'Partitions: finalized an interrupted DETACH CONCURRENTLY',
      );
    } catch (err) {
      logger.error({ err, partition: row.child }, 'Partitions: FINALIZE failed');
    }
  }

  // Reclaim step. Runs unconditionally, not only after a FINALIZE above: an
  // orphan can also come from a run that finalized and then died before the
  // DROP, and it would otherwise never be looked at again.
  const { rows: orphans } = await db.raw<{ rows: Array<{ child: string; size: string }> }>(
    `SELECT c.relname AS child, pg_size_pretty(pg_total_relation_size(c.oid)) AS size
       FROM pg_class c
       JOIN series_partition_policy pol
         ON c.relname ~ ('^' || pol.parent || '_[0-9]{8}$')
      WHERE c.relkind = 'r'
        AND c.relnamespace = 'public'::regnamespace
        AND NOT c.relispartition`,
  );
  for (const orphan of orphans) {
    try {
      await db.raw(`DROP TABLE IF EXISTS ${qualify(orphan.child)}`);
      logger.warn(
        { partition: orphan.child, reclaimed: orphan.size },
        'Partitions: reclaimed a detached partition left over by an interrupted drop',
      );
    } catch (err) {
      logger.error({ err, partition: orphan.child }, 'Partitions: orphan reclaim failed');
    }
  }

  return finalized;
}

// ── Layer 2 step 3 — retention ─────────────────────────────────────────────

interface ExpiredRow {
  parent: string;
  child: string;
  hi: string;
}

/**
 * Partitions whose upper bound is already older than their table's retention.
 *
 * The bound is read back from `pg_get_expr(relpartbound)` rather than parsed
 * out of the partition NAME. The name is a convenience; the bound is the truth,
 * and a partition created by hand during an incident (which happens) may not
 * follow the naming convention at all.
 *
 * A DEFAULT partition — which this schema does not create, but which somebody
 * might add — yields no match and therefore a NULL bound, and a NULL never
 * satisfies `hi <= now() - retention`. It is silently, and correctly, never
 * dropped.
 */
async function findExpiredPartitions(): Promise<ExpiredRow[]> {
  const { rows } = await db.raw<{ rows: ExpiredRow[] }>(
    `SELECT p.relname AS parent, c.relname AS child, b.hi::text AS hi
       FROM series_partition_policy pol
       JOIN pg_class p ON p.relname = pol.parent
                      AND p.relnamespace = 'public'::regnamespace
       JOIN pg_inherits i ON i.inhparent = p.oid
       JOIN pg_class c ON c.oid = i.inhrelid
       CROSS JOIN LATERAL (
         SELECT (regexp_match(pg_get_expr(c.relpartbound, c.oid),
                              ${RE_UPPER_BOUND}))[1]::timestamptz AS hi
       ) b
      WHERE pol.enabled
        AND NOT i.inhdetachpending
        AND b.hi IS NOT NULL
        AND b.hi <= now() - pol.retention
      ORDER BY b.hi`,
  );
  return rows;
}

/**
 * Drop every expired partition, ONE PER TRANSACTION and DETACH-FIRST.
 *
 * The sequence is `DETACH ... CONCURRENTLY` then `DROP TABLE`, and not a plain
 * `DROP TABLE`, because DROP takes a lock on the PARENT that waits behind every
 * in-flight query on the partitioned table — and while it waits it blocks all
 * subsequent writes, i.e. the poller. DETACH CONCURRENTLY does not block
 * readers; once it has returned, the partition is an ordinary table that
 * nothing references and dropping it is free.
 *
 * Dropping three days of backlog inside one BEGIN would hold the parent lock
 * for the whole run, which is exactly what this avoids — hence one dedicated
 * connection per partition and no wrapping transaction.
 */
export async function dropExpiredPartitions(): Promise<DropResult> {
  const out: DropResult = { dropped: [], deferred: [] };

  let expired: ExpiredRow[];
  try {
    expired = await findExpiredPartitions();
  } catch (err) {
    logger.error({ err }, 'Partitions: could not list expired partitions');
    return out;
  }

  for (const row of expired) {
    try {
      await withDedicatedConnection(async (conn) => {
        // Session-scoped, on this backend only. Three seconds, then give up.
        await conn.query(`SET lock_timeout = '${DETACH_LOCK_TIMEOUT}'`);
        await conn.query(
          `ALTER TABLE ${qualify(row.parent)} DETACH PARTITION ${qualify(row.child)} CONCURRENTLY`,
        );
        // The partition is now an ordinary table. No lock_timeout needed: no
        // one can be referencing it any more.
        await conn.query(`SET lock_timeout = '0'`);
        await conn.query(`DROP TABLE IF EXISTS ${qualify(row.child)}`);
      });
      out.dropped.push(row.child);
      logger.info(
        { parent: row.parent, partition: row.child, upperBound: row.hi },
        'Partitions: dropped expired partition',
      );
    } catch (err) {
      // A lock timeout here is NORMAL and is not escalated: an open graph held
      // the parent, and the partition will be dropped at the next hourly run.
      out.deferred.push({ partition: row.child, reason: String(err) });
      logger.warn(
        { partition: row.child, err },
        'Partitions: drop deferred to the next cycle (lock contention is expected here)',
      );
    }
  }
  return out;
}

// ── Layer 2 step 4 — statistics ────────────────────────────────────────────

/**
 * ANALYZE the CURRENT partition of every raw table.
 *
 * `ensure_series_partition()` sets `autovacuum_enabled = false` on the sample
 * partitions — they are insert-only with a 72 h life span, so VACUUM has
 * nothing to do — but that switch also disables the automatic ANALYZE. Without
 * statistics the planner estimates zero rows and picks a catastrophic plan for
 * the rollup queries, which is a far more expensive problem than the vacuum we
 * saved. This is the compensation, and it is not optional.
 *
 * (Study §2.6 flags the alternative to watch for at the bench: if the planner
 * still drifts between two hourly ANALYZEs, go back to autovacuum_enabled=true
 * with autovacuum_vacuum_insert_threshold = 2000000 — automatic ANALYZE kept,
 * useless VACUUM still avoided.)
 */
export async function analyzeCurrentPartitions(): Promise<string[]> {
  const { rows } = await db.raw<{ rows: Array<{ child: string }> }>(
    `SELECT c.relname AS child
       FROM series_partition_policy pol
       JOIN pg_class p ON p.relname = pol.parent
                      AND p.relnamespace = 'public'::regnamespace
       JOIN pg_inherits i ON i.inhparent = p.oid
       JOIN pg_class c ON c.oid = i.inhrelid
       CROSS JOIN LATERAL (
         SELECT (regexp_match(pg_get_expr(c.relpartbound, c.oid),
                              ${RE_LOWER_BOUND}))[1]::timestamptz AS lo,
                (regexp_match(pg_get_expr(c.relpartbound, c.oid),
                              ${RE_UPPER_BOUND}))[1]::timestamptz AS hi
       ) b
      WHERE pol.parent LIKE '%\\_samples'
        AND NOT i.inhdetachpending
        AND b.lo <= now() AND b.hi > now()`,
  );

  const analyzed: string[] = [];
  for (const row of rows) {
    try {
      await db.raw(`ANALYZE ${qualify(row.child)}`);
      analyzed.push(row.child);
    } catch (err) {
      logger.warn({ err, partition: row.child }, 'Partitions: ANALYZE failed');
    }
  }
  return analyzed;
}

// ── Layer 2 — the job ──────────────────────────────────────────────────────

/**
 * The hourly maintenance run, in the order of study §2.5.
 *
 * The order is not arbitrary. FINALIZE first, because a partition stuck in
 * DETACH PENDING must not be seen as droppable by step 3. ENSURE before DROP,
 * so that a run which is going to fail has still created tomorrow's partitions.
 * ANALYZE last, on partitions that are certain to exist.
 */
export async function runPartitionMaintenance(): Promise<MaintenanceResult> {
  const startedAt = Date.now();
  const finalized = await finalizePendingDetaches();
  const ensure = await ensureAllPartitions();
  const drop = await dropExpiredPartitions();
  const analyzed = await analyzeCurrentPartitions();

  const result: MaintenanceResult = {
    ...ensure,
    ...drop,
    finalized,
    analyzed,
    durationMs: Date.now() - startedAt,
  };
  logger.info(
    {
      finalized: finalized.length,
      dropped: drop.dropped.length,
      deferred: drop.deferred.length,
      analyzed: analyzed.length,
      failures: result.failures.length,
      durationMs: result.durationMs,
    },
    'Partitions: maintenance run complete',
  );
  return result;
}

// ── Scheduling ─────────────────────────────────────────────────────────────

let timer: NodeJS.Timeout | null = null;
let unsubscribe: (() => void) | null = null;
let consecutiveFailures = 0;

/** Milliseconds until the next occurrence of MAINTENANCE_MINUTE past the hour. */
function msUntilNextRun(): number {
  const now = new Date();
  const next = new Date(now);
  next.setMinutes(MAINTENANCE_MINUTE, 0, 0);
  if (next <= now) next.setHours(next.getHours() + 1);
  return next.getTime() - now.getTime();
}

function scheduleNext(): void {
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => {
    void (async () => {
      try {
        const r = await runPartitionMaintenance();
        // Only a creation failure counts: a deferred DROP is the normal
        // outcome of lock contention and must never page anybody.
        if (r.failures.length > 0) {
          consecutiveFailures += 1;
        } else {
          consecutiveFailures = 0;
        }
      } catch (err) {
        consecutiveFailures += 1;
        logger.error({ err }, 'Partitions: maintenance run threw');
      }

      // Hourly rather than daily is what buys these 24 retries; the alert is
      // deliberately on the THIRD consecutive failure, not the first.
      if (consecutiveFailures >= 3) {
        logger.error(
          { consecutiveFailures },
          'Partitions: maintenance has failed 3 times in a row — series writes ' +
            'will start failing once the pre-created window runs out',
        );
      }
      if (timer) scheduleNext();
    })();
  }, msUntilNextRun());
  // Never hold the event loop open just to wait for the top of the hour.
  timer.unref();
}

/**
 * Wire the hourly job to leadership. Followers do nothing: retention must run
 * exactly once per cluster, and two nodes racing on DETACH CONCURRENTLY would
 * spend their three seconds waiting on each other.
 *
 * Note that LAYER 1 (`ensureAllPartitions`) is deliberately NOT gated on
 * leadership — see the header. Creation is idempotent and cheap; deletion is
 * neither.
 */
export function startPartitionMaintenance(): void {
  if (unsubscribe) return;
  unsubscribe = leaderElection.onChange((isLeader) => {
    if (isLeader) {
      logger.info('Partitions: this node is leader — hourly maintenance armed');
      scheduleNext();
    } else if (timer) {
      clearTimeout(timer);
      timer = null;
      logger.info('Partitions: leadership lost — hourly maintenance disarmed');
    }
  });
}

export function stopPartitionMaintenance(): void {
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
  if (unsubscribe) {
    unsubscribe();
    unsubscribe = null;
  }
}

// ── Plumbing ───────────────────────────────────────────────────────────────

/**
 * Quote an identifier that came out of the catalogue.
 *
 * These names are read from `pg_class`, not from user input, so this is belt
 * and braces — but a partition created by hand as `"snmp_if_samples 2026"` is
 * exactly the kind of thing that happens during an incident, and an unquoted
 * DROP would then hit the wrong relation or fail confusingly.
 */
function qualify(relname: string): string {
  return `public."${relname.replace(/"/g, '""')}"`;
}

/**
 * Run a callback against ONE pinned backend, outside any transaction.
 *
 * Both requirements are hard: `DETACH PARTITION ... CONCURRENTLY` refuses to
 * run inside a transaction block, and `SET lock_timeout` is session-scoped, so
 * issuing it through the pool would set it on whichever connection happened to
 * be free and the DETACH could then run on another one with no timeout at all —
 * which is precisely the "poller freezes behind an open graph" failure this
 * whole path exists to avoid.
 */
async function withDedicatedConnection<T>(fn: (conn: RawConnection) => Promise<T>): Promise<T> {
  const client = db.client as unknown as {
    acquireConnection(): Promise<RawConnection>;
    releaseConnection(c: RawConnection): Promise<void>;
  };
  const conn = await client.acquireConnection();
  try {
    return await fn(conn);
  } finally {
    // Never leave a lock_timeout behind on a pooled connection.
    try {
      await conn.query('RESET lock_timeout');
    } catch {
      /* connection already broken; releasing it is all we can do */
    }
    await client.releaseConnection(conn);
  }
}
