/**
 * ObliWAN F5 — Operator Weather runtime.
 *
 * Barrel plus the leadership gate, the same shape as `services/fleet/index.ts`
 * and for the same reason (arbitrage A5): the sweep WRITES — it opens and
 * closes incidents — and two replicas running it would race on every incident.
 * The database survives that race (`operator_incidents_live_uniq` makes a
 * duplicate incident unrepresentable, the ingestion is keyed on the session and
 * the counters are recomputed rather than incremented) but it would still
 * double every notification, and one outage announced twice is exactly the
 * credibility problem this feature is built to avoid.
 *
 * ┌─ WIRED, AND ON A TIMER ───────────────────────────────────────────────────┐
 * │ `server/src/index.ts` starts and stops this runtime, and                  │
 * │ `routes/index.ts` line 194 mounts the HTTP surface:                       │
 * │                                                                          │
 * │   startWeatherRuntime();          // next to startFleetRuntime()          │
 * │   await stopWeatherRuntime();     // in the graceful shutdown             │
 * │   tenantRouter.use('/weather', weatherRoutes);   // routes/index.ts       │
 * │                                                                          │
 * │ This block used to say "the sweep is not on a timer". It is — under the   │
 * │ leader election below, every WEATHER_SWEEP_INTERVAL_MS. Saying otherwise  │
 * │ invites the next reader to assume no incident can open without an HTTP    │
 * │ call and to reason about `POST /weather/scan` as the only entry point,    │
 * │ which is exactly wrong about who opens incidents in production. If the    │
 * │ arming ever changes, THIS BLOCK CHANGES IN THE SAME COMMIT.               │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { leaderElection } from '../leaderElection';
import { logger } from '../../utils/logger';
import { db } from '../../db';
import { runWeatherScan } from './correlator.service';

export * from './asn.service';
export * from './egressPath.service';
export * from './ingest.service';
export * from './correlator.service';

/**
 * How often the sweep runs.
 *
 * Deliberately SHORTER than the default ten-minute correlation window: a sweep
 * that ran exactly once per window would detect a quorum on average five
 * minutes after it formed, which is half the lead time this feature exists to
 * buy. Two minutes costs one cheap query per tenant and no device traffic at
 * all — the sweep dials nothing; it reads what the concentrator already wrote.
 */
export const WEATHER_SWEEP_INTERVAL_MS = 120_000;

let timer: NodeJS.Timeout | null = null;
let unsubscribe: (() => void) | null = null;
let running = false;

/** Every tenant that has at least one device — there is nothing to correlate
 *  for a tenant with no fleet, and scanning one costs three queries. */
async function activeTenants(): Promise<number[]> {
  const rows = await db('devices').distinct<Array<{ tenant_id: number }>>('tenant_id');
  return rows.map((r) => r.tenant_id);
}

async function sweep(): Promise<void> {
  // Re-entrancy guard: a slow sweep on a large fleet must not overlap itself
  // and have two evaluations of the same tenant race to open the same incident.
  if (running) return;
  running = true;
  try {
    for (const tenantId of await activeTenants()) {
      try {
        const outcome = await runWeatherScan(tenantId);
        if (outcome.opened.length || outcome.closed.length || outcome.clearing.length) {
          logger.info(
            {
              tenantId,
              opened: outcome.opened,
              clearing: outcome.clearing,
              closed: outcome.closed,
            },
            'Operator weather sweep changed incident state',
          );
        }
      } catch (err) {
        // One tenant's bad data must not stop the other tenants' sweep.
        logger.error({ err, tenantId }, 'Operator weather sweep failed for this tenant');
      }
    }
  } finally {
    running = false;
  }
}

/** Wire the sweep to leadership. Idempotent. */
export function startWeatherRuntime(): void {
  if (unsubscribe) return;
  unsubscribe = leaderElection.onChange((isLeader) => {
    if (isLeader) {
      if (timer) return;
      logger.info(
        { intervalMs: WEATHER_SWEEP_INTERVAL_MS },
        'Operator weather correlation started (leader)',
      );
      timer = setInterval(() => {
        void sweep();
      }, WEATHER_SWEEP_INTERVAL_MS);
      // Do not hold the event loop open for a correlation pass.
      timer.unref?.();
      void sweep();
    } else if (timer) {
      clearInterval(timer);
      timer = null;
      logger.info('Operator weather correlation stopped (leadership lost)');
    }
  });
}

export async function stopWeatherRuntime(): Promise<void> {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  if (unsubscribe) {
    unsubscribe();
    unsubscribe = null;
  }
}
