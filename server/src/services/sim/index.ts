/**
 * ObliWAN F9 — SIM fleet runtime.
 *
 * Barrel plus the leadership gate, the same shape as `services/weather/index.ts`
 * and for the same reason (arbitrage A5): the sweep WRITES — it opens low-data
 * episodes, raises alerts and creates top-up PROPOSALS — and two replicas
 * running it would race on every line.
 *
 * The database survives that race: `sim_balances` is upserted on its natural
 * key, samples are unique on `(sim_id, zone, observed_at)`, and a duplicate
 * proposal is refused by `sim_recharges_idem_uq`. But it would still double
 * every partner request, on an API with no published rate limit, for a feature
 * whose worst failure is being rate-limited into silence.
 *
 * ┌─ WIRED, AND ON A TIMER ───────────────────────────────────────────────────┐
 * │ `server/src/index.ts` starts and stops this runtime, and                  │
 * │ `routes/index.ts` mounts the HTTP surface:                                │
 * │                                                                          │
 * │   startSimRuntime();            // next to startWeatherRuntime()          │
 * │   await stopSimRuntime();       // in the graceful shutdown               │
 * │   tenantRouter.use('/sim', simRoutes);          // routes/index.ts        │
 * │                                                                          │
 * │ IF THE ARMING EVER CHANGES, THIS BLOCK CHANGES IN THE SAME COMMIT. A      │
 * │ header that claims "not on a timer" about a timed sweep invites the next  │
 * │ reader to reason about `POST /sim/accounts/:id/sync` as the only entry    │
 * │ point, which is exactly wrong about who spends a partner's rate limit.    │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import {
  HARDCODED_DEFAULTS,
  MASTER_TENANT_ID,
  SETTINGS_KEYS,
  clampSetting,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { leaderElection } from '../leaderElection';
import { pollableAccounts } from './account.service';
import { expireStale } from './recharge.service';
import { assertCatalogMatchesRegistry } from './registry';
import { syncAccount } from './sync.service';

export * from './types';
export * from './registry';
export * as simAccounts from './account.service';
export * as simLines from './line.service';
export * as simRecharges from './recharge.service';
export * as simReport from './report.service';
export * as simSync from './sync.service';

/**
 * How often the scheduler WAKES, not how often an account is polled.
 *
 * The poll interval is a setting in minutes (`SIM_SYNC_INTERVAL`, default four
 * hours) and is compared against each account's `last_sync_at`. Waking every
 * five minutes and deciding per account means a shortened interval takes effect
 * within five minutes instead of after one old-length cycle, and an account
 * that was added mid-cycle does not wait four hours for its first read.
 */
const TICK_MS = 5 * 60_000;

let timer: NodeJS.Timeout | null = null;
let unsubscribe: (() => void) | null = null;
let running = false;

/**
 * The poll interval, in minutes.
 *
 * Accounts are platform-level and have no tenant, but the setting is
 * tenant-scoped like every other. Resolved against the MASTER tenant — id 1,
 * positional by suite convention (`shared/src/tenants.ts`), the workspace that
 * owns the partner contracts. An installation with no override falls back to
 * the hardcoded default rather than to whichever tenant answered first, which
 * is what a `.first()` over an unscoped settings read would have done.
 */
async function pollIntervalMinutes(): Promise<number> {
  const key = SETTINGS_KEYS.SIM_SYNC_INTERVAL;
  try {
    const row = await db('settings')
      .where('tenant_id', MASTER_TENANT_ID)
      .where('scope', 'global')
      .whereNull('scope_id')
      .where('key', key)
      .first<{ value: unknown } | undefined>('value');
    const raw = typeof row?.value === 'number' ? row.value : Number(row?.value);
    return Number.isFinite(raw) ? clampSetting(key, raw) : HARDCODED_DEFAULTS[key];
  } catch {
    // A settings read that fails must not stop the sweep: the default interval
    // is a safe, conservative number and silence is the failure to avoid.
    return HARDCODED_DEFAULTS[key];
  }
}

async function tick(): Promise<void> {
  // Re-entrancy guard: a sweep of 400 lines at four concurrent requests takes
  // minutes, and two overlapping sweeps would double the partner's load for no
  // extra information.
  if (running) return;
  running = true;
  try {
    const intervalMs = (await pollIntervalMinutes()) * 60_000;
    const due = Date.now() - intervalMs;

    for (const account of await pollableAccounts()) {
      const last = account.last_sync_at ? new Date(account.last_sync_at).getTime() : 0;
      if (last > due) continue;
      try {
        const outcome = await syncAccount(account);
        if (outcome.outcome !== 'ok' || outcome.linesNew > 0 || outcome.proposalsCreated > 0) {
          logger.info({ ...outcome }, 'SIM sweep finished');
        }
      } catch (err) {
        // One account's failure must not stop the others. `syncAccount` already
        // records its own journal row; this catches what escapes it.
        logger.error({ accountId: account.id, err }, 'SIM sweep threw');
      }
    }

    // Housekeeping, on the same timer: a proposal nobody acted on for two weeks
    // is retired and its episode reopened, so a still-empty line is announced
    // again instead of being permanently silenced by its own stale proposal.
    await expireStale().catch((err: unknown) => {
      logger.warn({ err }, 'SIM proposal expiry failed');
    });
  } finally {
    running = false;
  }
}

/** Wire the sweep to leadership. Idempotent. */
export function startSimRuntime(): void {
  if (unsubscribe) return;

  // Fails loudly at boot when the shared catalogue and the code disagree —
  // a catalogue claiming a platform is readable when its connector refuses is a
  // product that says it is watching a fleet it is not watching, and both files
  // look correct on their own.
  const problems = assertCatalogMatchesRegistry();
  for (const p of problems) {
    logger.error({ problem: p }, 'SIM platform catalogue disagrees with the connector registry');
  }

  unsubscribe = leaderElection.onChange((isLeader) => {
    if (isLeader) {
      if (timer) return;
      logger.info({ tickMs: TICK_MS }, 'SIM balance sweep started (leader)');
      timer = setInterval(() => {
        void tick();
      }, TICK_MS);
      // Do not hold the event loop open for a sweep.
      timer.unref?.();
      void tick();
    } else if (timer) {
      clearInterval(timer);
      timer = null;
      logger.info('SIM balance sweep stopped (leadership lost)');
    }
  });
}

export async function stopSimRuntime(): Promise<void> {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  if (unsubscribe) {
    unsubscribe();
    unsubscribe = null;
  }
}
