/**
 * ObliWAN — the ACS runtime: one arm/disarm pair for the whole M10 subsystem.
 *
 * ┌─ THE LESSON OF M3, RESTATED ──────────────────────────────────────────────┐
 * │ The SNMP subsystem compiled, its tables existed, its routes answered —    │
 * │ and because nothing armed it in `index.ts` it never wrote a single        │
 * │ sample. The ACS has a worse version of that failure available to it: the  │
 * │ ports are ALREADY PUBLISHED by the compose files from M1, so an unarmed   │
 * │ ACS is a published port answering RST, and 300 CPEs logging "ACS          │
 * │ unreachable" at their own pace with nobody watching.                      │
 * │                                                                          │
 * │ Hence: `startAcsRuntime()` is called from `src/index.ts`, and this file   │
 * │ says out loud at boot whether the listener is up and whether anything is  │
 * │ enrolled.                                                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT IS LEADER-GATED AND WHAT IS NOT ────────────────────────────────────┐
 * │ THE LISTENER IS NOT GATED, and that is the same reasoning as the SNMP     │
 * │ trap and syslog receivers: a CPE PUSHES to whatever address it was        │
 * │ provisioned with, and a follower that does not listen simply loses the    │
 * │ Inform — nothing retries on our side, and the CPE waits a full interval.  │
 * │ So every replica listens, and the writes are made safe by the database    │
 * │ (`cwmp_sessions_fallback_uq`, `FOR UPDATE SKIP LOCKED` on the task queue) │
 * │ rather than by an election.                                               │
 * │                                                                          │
 * │ THE SWEEPERS ARE GATED. Expiring tasks, reaping sessions and recomputing  │
 * │ reachability are periodic writes over the whole fleet; running them on    │
 * │ three replicas would triple the work and interleave three passes over the │
 * │ same rows for no benefit.                                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { config } from '../config';
import { db } from '../db';
import { logger } from '../utils/logger';
import { isLeader } from '../services/leaderElection';
import { createCwmpApp } from './cwmpApp';
import { startCwmpListeners, stopCwmpListeners, type CwmpListeners } from './httpListener';
import { expireStaleTasks } from '../services/cwmp/task.service';
import { reapIdleSessions } from '../services/cwmp/session.service';
import { refreshReachability } from '../services/cwmp/device.service';
import { expireStaleTransfers } from '../services/cwmp/transfer.service';

/** One minute. Everything this sweeps is measured in minutes or hours, and a
 *  faster tick would only add load without changing any answer. */
const SWEEP_INTERVAL_MS = 60_000;

let listeners: CwmpListeners | null = null;
let sweeper: NodeJS.Timeout | null = null;
let armed = false;

export async function startAcsRuntime(): Promise<void> {
  if (armed) return;
  if (!config.cwmp.enabled) {
    logger.warn(
      'ACS: CWMP_ENABLED=false — port 7547 stays closed. Any CPE provisioned against this ' +
        'instance will log "ACS unreachable" until it is re-enabled.',
    );
    return;
  }
  armed = true;

  listeners = startCwmpListeners(createCwmpApp());

  // Say, at boot, whether this build can actually serve a CPE — and if it
  // cannot, which piece is missing. Both gaps fail closed on their own; what
  // they do not do on their own is tell anybody before the first Inform.
  for (const warning of await acsReadiness()) {
    logger.warn({ subsystem: 'acs' }, warning);
  }

  sweeper = setInterval(() => {
    void sweep();
  }, SWEEP_INTERVAL_MS);
  sweeper.unref();

  logger.info('ACS runtime armed');
}

async function sweep(): Promise<void> {
  if (!isLeader()) return;
  try {
    const [expiredTasks, reaped, reach, expiredTransfers] = await Promise.all([
      expireStaleTasks(),
      reapIdleSessions(config.cwmp.sessionIdleSeconds),
      refreshReachability(),
      expireStaleTransfers(),
    ]);
    if (expiredTasks || reaped || reach.changed || expiredTransfers) {
      logger.info(
        {
          expiredTasks,
          reapedSessions: reaped,
          reachabilityChanged: reach.changed,
          expiredTransfers,
        },
        'ACS: sweep',
      );
    }
  } catch (err) {
    // A failed sweep is a missed minute, not an incident: everything it does is
    // idempotent and the next tick redoes it.
    logger.warn({ err }, 'ACS: sweep failed (will retry next tick)');
  }
}

/**
 * What an operator needs to know before the first CPE calls in.
 *
 * Every line here corresponds to a state in which the ACS is running and
 * nothing works — the class of failure that otherwise surfaces as "the CPEs
 * never appeared" three days later.
 */
export async function acsReadiness(): Promise<string[]> {
  const warnings: string[] = [];

  const tenantsWithSlug = Number(
    ((await db('cwmp_acs_settings').count<{ count: string }[]>('* as count'))[0]?.count) ?? 0,
  );
  if (tenantsWithSlug === 0) {
    warnings.push(
      'No tenant has ACS settings yet, so every CPE POST will be answered 404. Create them ' +
        'from the ACS settings screen (or POST /api/acs/settings) before provisioning any CPE.',
    );
  }

  const enrolled = Number(
    ((await db('cwmp_devices').count<{ count: string }[]>('* as count'))[0]?.count) ?? 0,
  );
  const credentialled = Number(
    ((
      await db('cwmp_devices')
        .whereNotNull('acs_auth_ha1_enc')
        .count<{ count: string }[]>('* as count')
    )[0]?.count) ?? 0,
  );
  if (enrolled > 0 && credentialled < enrolled) {
    warnings.push(
      `${enrolled - credentialled} of ${enrolled} enrolled CPEs have no ACS credential. Their ` +
        'Informs are accepted read-only and NO task will ever be dispatched to them. Enrol them ' +
        'to obtain a username and password.',
    );
  }

  if (!config.cwmp.publicBaseUrl) {
    warnings.push(
      'CWMP_PUBLIC_BASE_URL is not set. Firmware download URLs will be built from an empty base ' +
        'and no CPE will be able to fetch a file. Set it to the address CPEs reach this ' +
        'instance on (e.g. http://acs.example.com:7547).',
    );
  }

  return warnings;
}

export async function stopAcsRuntime(): Promise<void> {
  armed = false;
  if (sweeper) {
    clearInterval(sweeper);
    sweeper = null;
  }
  if (listeners) {
    await stopCwmpListeners(listeners);
    listeners = null;
  }
  logger.info('ACS runtime stopped');
}

export { createCwmpApp } from './cwmpApp';
