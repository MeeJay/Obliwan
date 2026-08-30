/**
 * ObliWAN — the M8 runtime: the log pull, the attribution sweep, the
 * out-of-tunnel probe and log retention.
 *
 * ┌─ ALL FOUR DUTIES ARE LEADER-GATED (A5), AND EACH FOR ITS OWN REASON ─────┐
 * │ `/log` pull    CHOOSES to dial a device. Two of them double every dial on │
 * │                a fleet whose single socket per device is already scarce   │
 * │                (R5), and race each other on the cursor.                   │
 * │ external probe CHOOSES to dial a CUSTOMER'S PUBLIC ADDRESS. Two replicas  │
 * │                probing 300 sites is 600 unexplained connections a minute  │
 * │                arriving at somebody else's firewall.                      │
 * │ attribution    writes one row per drift run. Two sweeps racing on the     │
 * │                same run is harmless (the upsert is idempotent) but the    │
 * │                work is pure duplication.                                  │
 * │ retention      a DELETE. Two of them is a lock fight for no benefit.      │
 * │                                                                          │
 * │ Contrast with the RECEIVERS in `services/snmp/index.ts`, which are        │
 * │ deliberately NOT gated: a syslog datagram is PUSHED to whatever address   │
 * │ the device was configured with, and a follower that does not listen drops │
 * │ it with nothing to retry.                                                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * WIRING — not done here, because `server/src/index.ts` belongs to another
 * workstream. Exactly like `startSnmpRuntime()`:
 *
 *     startLogsRuntime();          // after leaderElection.start()
 *     ...
 *     await stopLogsRuntime();     // in the graceful shutdown
 *
 * Until those two lines exist, syslog ingestion and login extraction still work
 * (they ride the syslog receiver, which M3 already arms) but nothing pulls
 * `/log`, nothing probes out of band, and no drift run is ever attributed.
 */

import { leaderElection } from '../leaderElection';
import { logger } from '../../utils/logger';
import { probeDueDevices } from '../fleet/reachability.service';
import { attributePendingRuns } from '../drift/attribution.service';
import { pullDueLogs } from './routerosLog.service';
import { purgeOldLoginEvents } from './loginEvents.service';
import { logsConfig } from './config';

let unsubscribe: (() => void) | null = null;
let logTimer: NodeJS.Timeout | null = null;
let probeTimer: NodeJS.Timeout | null = null;
let attributionTimer: NodeJS.Timeout | null = null;
let retentionTimer: NodeJS.Timeout | null = null;

/**
 * Run `fn` on a timer, never twice at once.
 *
 * The overlap guard is not decoration: a `/log` cycle over a slow fleet can
 * outlast its own interval, and a second cycle starting on top of the first
 * would dial the same devices through the same single socket, with the pool's
 * anti-stampede budget already spent by the first.
 */
function everyMs(ms: number, label: string, fn: () => Promise<unknown>): NodeJS.Timeout {
  let running = false;
  const timer = setInterval(() => {
    if (running) {
      logger.debug({ label }, 'Logs runtime: previous cycle still running, skipping this tick');
      return;
    }
    running = true;
    void fn()
      .catch((err) => logger.error({ err, label }, 'Logs runtime cycle failed'))
      .finally(() => {
        running = false;
      });
  }, ms);
  timer.unref();
  return timer;
}

function startDuties(): void {
  if (logTimer || probeTimer || attributionTimer || retentionTimer) return;

  if (logsConfig.routerosLogEnabled) {
    // A fraction of the per-device interval: the tick decides WHO is due, the
    // interval decides how often a given device is read.
    const tickMs = Math.max(15_000, (logsConfig.routerosLogIntervalSec * 1000) / 4);
    logTimer = everyMs(tickMs, 'routeros-log', pullDueLogs);
  }
  if (logsConfig.externalProbeEnabled) {
    probeTimer = everyMs(logsConfig.externalProbeTickMs, 'external-probe', probeDueDevices);
  }
  // Attribution runs on a sweep and not inline with `runDrift()` on purpose:
  // the login line that explains a change often lands AFTER the run that needs
  // it (a five-minute `/log` cycle, or a datagram still in flight). Sweeping
  // gives the evidence time to arrive instead of freezing an `unattributed`
  // verdict seconds before its proof.
  attributionTimer = everyMs(60_000, 'attribution', () => attributePendingRuns());
  retentionTimer = everyMs(logsConfig.retentionSweepMs, 'login-retention', () =>
    purgeOldLoginEvents(logsConfig.loginEventRetentionDays),
  );

  logger.info(
    {
      routerosLog: logsConfig.routerosLogEnabled,
      externalProbe: logsConfig.externalProbeEnabled,
      loginRetentionDays: logsConfig.loginEventRetentionDays,
    },
    'Logs runtime armed (leader)',
  );
}

function stopDuties(): void {
  for (const t of [logTimer, probeTimer, attributionTimer, retentionTimer]) {
    if (t) clearInterval(t);
  }
  logTimer = null;
  probeTimer = null;
  attributionTimer = null;
  retentionTimer = null;
}

/** Idempotent. Safe on every role: a `web` replica never campaigns, so it never
 *  receives a `true` and never starts a duty. */
export function startLogsRuntime(): void {
  if (unsubscribe) return;
  unsubscribe = leaderElection.onChange((isLeader) => {
    if (isLeader) startDuties();
    else stopDuties();
  });
  logger.info('Logs runtime wired to leadership');
}

export async function stopLogsRuntime(): Promise<void> {
  unsubscribe?.();
  unsubscribe = null;
  stopDuties();
}

export * from './config';
export * from './contract';
export * from './parsers';
export * from './loginEvents.service';
export * from './routerosLog.service';
export * from './logs.service';
