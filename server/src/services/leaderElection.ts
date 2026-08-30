import knex, { type Knex } from 'knex';
import knexConfig from '../../knexfile';
import { config } from '../config';
import { logger } from '../utils/logger';

/**
 * Leader election over a PostgreSQL session-level advisory lock — arbitrage A5.
 *
 * WHY A DEDICATED SINGLE-CONNECTION POOL
 * `pg_try_advisory_lock` is SESSION-scoped: the lock belongs to the backend
 * connection that took it and is released when that connection ends. Taking it
 * on the main application pool would be worse than useless — the pool would
 * hand the "locked" connection to unrelated queries and could reap it at any
 * moment, silently dropping our leadership. So the election owns its own Knex
 * instance with `pool: { min: 1, max: 1 }`: exactly one backend, kept alive by
 * `min: 1` (tarn never reaps below the minimum), used for nothing else.
 *
 * That is also what makes this safe. If the process crashes, is OOM-killed, or
 * its network drops, Postgres tears the backend down and releases the lock by
 * itself. There is no lease to expire, no clock to trust, no stale-lock
 * cleanup to write.
 *
 * M1 SCOPE
 * Nothing is wired to this yet — there is no poller, no job runner and no drift
 * scheduler before M2/M3. The election runs, logs plainly which process holds
 * leadership, and exposes `isLeader()` / `onChange()`. Building it now costs
 * half a day; retrofitting it once the pollers exist costs a rewrite of each.
 */

/**
 * Advisory lock key. Two 32-bit ints rather than one 64-bit so the pair is
 * readable in `pg_locks` (classid / objid). MUST stay stable forever: changing
 * it during a rolling restart would elect a SECOND leader alongside the first.
 * 0x4F57 = 'OW'. 1 = the background-duties lock.
 */
const LOCK_NAMESPACE = 0x4f57;
const LOCK_ID = 1;

/** How often a follower retries to take over after the leader disappears. */
const RETRY_INTERVAL_MS = 15_000;

type LeadershipListener = (isLeader: boolean) => void;

class LeaderElection {
  private leader = false;
  private started = false;
  private stopping = false;
  private lockDb: Knex | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private readonly listeners = new Set<LeadershipListener>();

  /** True when THIS process currently owns the background duties. */
  isLeader(): boolean {
    return this.leader;
  }

  /**
   * Subscribe to leadership transitions. The callback fires immediately with
   * the current state so a subscriber never misses an election that already
   * happened. Intended for M2+ pollers: `onChange(v => v ? start() : stop())`.
   * Returns an unsubscribe function.
   */
  onChange(listener: LeadershipListener): () => void {
    this.listeners.add(listener);
    listener(this.leader);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * Start campaigning. Returns as soon as the first attempt has been made — it
   * does NOT block until leadership is won, because a `web` replica must start
   * serving whether or not it is the leader.
   */
  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
    this.stopping = false;

    if (!config.runsBackground) {
      logger.info(
        { role: config.role },
        'Leader election: not campaigning (OBLIWAN_ROLE=web serves HTTP only)',
      );
      return;
    }

    this.lockDb = knex({
      ...knexConfig,
      pool: { min: 1, max: 1 },
    });

    await this.tryAcquire();
  }

  /** Resign and release the lock. Safe to call when not started or not leader. */
  async stop(): Promise<void> {
    this.stopping = true;
    this.stopRetrying();
    await this.release();
    this.started = false;
  }

  // -- internals -----------------------------------------------------------

  private async tryAcquire(): Promise<void> {
    if (this.stopping || this.leader || !this.lockDb) return;

    try {
      const result = await this.lockDb.raw<{ rows: Array<{ acquired: boolean }> }>(
        'SELECT pg_try_advisory_lock(?, ?) AS acquired',
        [LOCK_NAMESPACE, LOCK_ID],
      );
      const acquired = result.rows[0]?.acquired === true;

      if (acquired) {
        this.setLeader(true);
        logger.info(
          { role: config.role, lock: `${LOCK_NAMESPACE}/${LOCK_ID}` },
          'Leader election: THIS process is the leader — background duties are ours',
        );
        this.stopRetrying();
        return;
      }

      logger.info(
        { role: config.role, retryInMs: RETRY_INTERVAL_MS },
        'Leader election: another process holds the lock — standing by as follower',
      );
      this.startRetrying();
    } catch (err) {
      logger.error(err, 'Leader election: acquisition attempt failed — will retry');
      this.startRetrying();
    }
  }

  private startRetrying(): void {
    if (this.retryTimer || this.stopping) return;
    this.retryTimer = setInterval(() => {
      void this.tryAcquire();
    }, RETRY_INTERVAL_MS);
    // Never keep the event loop alive just to campaign.
    this.retryTimer.unref();
  }

  private stopRetrying(): void {
    if (this.retryTimer) {
      clearInterval(this.retryTimer);
      this.retryTimer = null;
    }
  }

  private async release(): Promise<void> {
    const lockDb = this.lockDb;
    this.lockDb = null;
    if (!lockDb) {
      this.setLeader(false);
      return;
    }

    if (this.leader) {
      try {
        await lockDb.raw('SELECT pg_advisory_unlock(?, ?)', [LOCK_NAMESPACE, LOCK_ID]);
      } catch (err) {
        // Losing the connection IS the release, so this is not worth escalating:
        // Postgres has already dropped the lock for us.
        logger.warn({ err }, 'Leader election: unlock failed (connection likely already closed)');
      }
      logger.info('Leader election: resigned leadership');
    }

    try {
      await lockDb.destroy();
    } catch { /* pool already gone */ }

    this.setLeader(false);
  }

  private setLeader(value: boolean): void {
    if (this.leader === value) return;
    this.leader = value;
    for (const listener of this.listeners) {
      try {
        listener(value);
      } catch (err) {
        logger.error(err, 'Leader election: listener threw');
      }
    }
  }
}

export const leaderElection = new LeaderElection();

/** Convenience re-export so callers need not know about the singleton. */
export function isLeader(): boolean {
  return leaderElection.isLeader();
}
