/**
 * The poll scheduler.
 *
 * ┌─ LEADER ONLY. THIS IS NOT AN OPTIMISATION. ───────────────────────────────┐
 * │ Two replicas polling the same device do not merely double the load: they  │
 * │ CORRUPT THE DELTAS. Both read the same counters, both write               │
 * │ `snmp_poll_state`, and each then computes its delta against the OTHER     │
 * │ one's baseline -- so every window is halved at random and every rate is   │
 * │ roughly doubled, with no error anywhere and no way to tell from the data. │
 * │ That is arbitrage A5, and it is why `start()` does nothing until          │
 * │ `leaderElection` says so.                                                 │
 * │                                                                          │
 * │ `claimDueTargets()` adds a second, independent guard (`FOR UPDATE SKIP    │
 * │ LOCKED` plus rescheduling in the claiming statement) so that even the     │
 * │ few seconds of overlap during a failover cannot double-poll a device.     │
 * │ Belt and braces, because the failure is silent.                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ADAPTIVE, IN TWO DIRECTIONS
 *  - per target: `snmp_targets.poll_interval_sec`, defaulting to 30 s;
 *  - on failure: `backoffSeconds()` doubles up to 10 intervals or 15 minutes.
 *    A dead site asked every 30 s costs 120 timeouts an hour, each holding a
 *    concurrency slot for `timeout x (retries + 1)` -- which is how a handful
 *    of dead sites starves the polling of the live ones.
 *
 * JITTER lives in `claimDueTargets()`, applied to `next_poll_at` as it is
 * pushed forward. Without it, 300 devices installed the same afternoon are
 * polled inside the same 100 ms every 30 s for ever: a burst on the tunnel, on
 * the concentrator and on the writer, all at the same instant.
 */

import pLimit from 'p-limit';
import { leaderElection } from '../leaderElection';
import { logger } from '../../utils/logger';
import { snmpConfig } from './config';
import { claimDueTargets, logTargetProblem } from './targets';
import { pollTarget, type PollOutcome } from './poller';
import { snmpSessions } from '../transport/snmp.transport';

let timer: NodeJS.Timeout | null = null;
let unsubscribe: (() => void) | null = null;
let ticking = false;
const inFlight = new Set<number>();

export interface SchedulerStats {
  running: boolean;
  inFlight: number;
  cycles: number;
  polls: number;
  failures: number;
  samples: number;
  lastTickAt: string | null;
}

const stats: SchedulerStats = {
  running: false,
  inFlight: 0,
  cycles: 0,
  polls: 0,
  failures: 0,
  samples: 0,
  lastTickAt: null,
};

export function schedulerStats(): SchedulerStats {
  return { ...stats, inFlight: inFlight.size };
}

/**
 * One tick: claim what is due, poll it with bounded concurrency.
 *
 * Exported so the bench can drive cycles deterministically instead of waiting
 * on a timer -- the alternative is a test that sleeps, which is a test that is
 * flaky on a loaded CI machine.
 */
export async function runSchedulerTick(limitRows = snmpConfig.pollBatchSize): Promise<PollOutcome[]> {
  const targets = await claimDueTargets(limitRows);
  if (targets.length === 0) return [];

  stats.cycles += 1;
  stats.lastTickAt = new Date().toISOString();

  const limit = pLimit(snmpConfig.pollConcurrency);
  const outcomes = await Promise.all(
    targets.map((resolved) =>
      limit(async () => {
        // A target already being polled (a poll that overran its interval)
        // must not be started twice in this process. The database claim
        // protects against another process; this protects against ourselves.
        if (inFlight.has(resolved.target.id)) return null;
        inFlight.add(resolved.target.id);
        try {
          const outcome = await pollTarget(resolved);
          stats.polls += 1;
          stats.samples += outcome.samples;
          if (!outcome.ok) stats.failures += 1;
          return outcome;
        } catch (err) {
          // pollTarget already swallows what it can; anything reaching here is
          // a bug in the poller itself and must not kill the tick for the
          // other 299 devices.
          stats.failures += 1;
          logTargetProblem(resolved, err);
          return null;
        } finally {
          inFlight.delete(resolved.target.id);
        }
      }),
    ),
  );

  return outcomes.filter((o): o is PollOutcome => o !== null);
}

/** Wire the scheduler to leadership. Idempotent. */
export function startScheduler(): void {
  if (unsubscribe) return;
  unsubscribe = leaderElection.onChange((isLeader) => {
    if (isLeader && !timer) {
      stats.running = true;
      timer = setInterval(() => {
        if (ticking) return; // a tick that overruns must never stack
        ticking = true;
        void runSchedulerTick()
          .then((outcomes) => {
            if (outcomes.length === 0) return;
            const failed = outcomes.filter((o) => !o.ok).length;
            const samples = outcomes.reduce((n, o) => n + o.samples, 0);
            logger.debug(
              { polled: outcomes.length, failed, samples },
              'SNMP poll cycle',
            );
          })
          .catch((err) => logger.error({ err }, 'SNMP scheduler tick failed'))
          .finally(() => {
            ticking = false;
          });
      }, snmpConfig.schedulerTickMs);
      logger.info(
        {
          tickMs: snmpConfig.schedulerTickMs,
          concurrency: snmpConfig.pollConcurrency,
          batch: snmpConfig.pollBatchSize,
        },
        'SNMP scheduler armed (leader)',
      );
    } else if (!isLeader && timer) {
      clearInterval(timer);
      timer = null;
      stats.running = false;
      // Losing leadership must release the UDP sockets too: an ex-leader
      // holding 300 open sessions is 300 file descriptors nobody will reclaim
      // until the process restarts.
      snmpSessions.closeAll();
      logger.info('SNMP scheduler disarmed (no longer leader)');
    }
  });
}

export function stopScheduler(): void {
  unsubscribe?.();
  unsubscribe = null;
  if (timer) clearInterval(timer);
  timer = null;
  stats.running = false;
  snmpSessions.closeAll();
}
