/**
 * The M3 runtime: one arm/disarm pair for the whole SNMP subsystem, plus the
 * barrel the controllers import from.
 *
 * ┌─ THE ORDER OF startSnmpRuntime() IS THE SPEC, NOT A STYLE CHOICE ─────────┐
 * │ 1. `ensureAllPartitions()` -- SYNCHRONOUSLY, AND BEFORE ANY POLL TASK IS  │
 * │    REGISTERED. Study section 2.7 is explicit about this ordering, and     │
 * │    about the fact that it needs a TEST rather than a code review: on a    │
 * │    server that has been down longer than the look-ahead window, the very  │
 * │    first insert of the first poll hits a missing partition. Layer 3 would │
 * │    recover it, but layer 3 firing at all is an incident signal, and on a  │
 * │    fresh install it would fire 2 400 times in the first cycle.            │
 * │    It runs on EVERY node, leader or not: it is cheap and idempotent, and  │
 * │    it removes the race between "I was elected" and "the first poll".      │
 * │ 2. the leader-gated duties (maintenance, rollups, scheduler);             │
 * │ 3. the listeners, which are NOT leader-gated -- see below.                │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * WHY THE RECEIVERS ARE NOT LEADER-GATED, AND THE POLLER IS.
 * The poller CHOOSES to talk to a device: two of them double the load and
 * corrupt the deltas (A5). A trap or a syslog message is PUSHED to whatever
 * address the device was configured with; a follower that does not listen
 * simply drops it, and nothing retries. So every node listens, and the writes
 * are idempotent-by-append. The cost is that a two-node deployment behind a
 * load balancer may store a message twice; the alternative is losing every
 * message sent to the follower, which is worse and silent.
 *
 * WIRING (not done here -- `src/index.ts` belongs to another workstream):
 *
 *     await startSnmpRuntime();     // after leaderElection.start(), step 6b
 *     ...
 *     await stopSnmpRuntime();      // in the graceful shutdown
 */

import { logger } from '../../utils/logger';
import { ensureAllPartitions, startPartitionMaintenance, stopPartitionMaintenance } from './partition.service';
import { startScheduler, stopScheduler } from './scheduler';
import { startRollups, stopRollups } from './rollup.service';
import { startTrapReceiver, stopTrapReceiver } from './trapReceiver';
import { startSyslogReceiver, stopSyslogReceiver } from './syslogReceiver';
import { sweepStaleAlerts } from './threshold.service';
import { snmpSessions } from '../transport/snmp.transport';
import { snmpConfig } from './config';

let armed = false;

export async function startSnmpRuntime(): Promise<void> {
  if (armed) return;
  armed = true;

  // LAYER 1. Synchronous, before anything can write a sample.
  try {
    const result = await ensureAllPartitions();
    logger.info(
      { ensured: result.ensured, failures: result.failures.length },
      'SNMP runtime: partitions ensured (layer 1, before the scheduler)',
    );
  } catch (err) {
    // A failure here is serious but must not stop the process: the API still
    // has to serve, and layer 3 can still rescue individual batches.
    logger.error(err, 'SNMP runtime: ensureAllPartitions failed — layer 3 will have to catch up');
  }

  // Stale alert state from before the outage. Done before the first
  // evaluation so a pending timer that stopped being fed cannot complete on
  // the strength of a breach that started days ago.
  try {
    await sweepStaleAlerts(Math.max(snmpConfig.defaultPollIntervalSec * 10, 600));
  } catch (err) {
    logger.warn({ err }, 'SNMP runtime: alert state sweep failed');
  }

  startPartitionMaintenance();
  startRollups();
  startScheduler();

  startTrapReceiver();
  startSyslogReceiver();

  logger.info('SNMP runtime armed');
}

export async function stopSnmpRuntime(): Promise<void> {
  armed = false;
  stopScheduler();
  stopRollups();
  stopPartitionMaintenance();
  stopTrapReceiver();
  stopSyslogReceiver();
  snmpSessions.closeAll();
  logger.info('SNMP runtime stopped');
}

export * from './oids';
// The SNMP wire client is NOT re-exported here. It lives in
// `services/transport/snmp.transport.ts`, which is the single owner of session
// lifecycle; a second barrel entry is how a second import path — and then a
// second implementation — grows back.
export * from './rateCalculator';
export * from './discovery';
export * from './targets';
export * from './writer';
export * from './poller';
export * from './scheduler';
export * from './rollup.service';
export * from './threshold.service';
export * from './series.service';
export * from './credential.service';
export * from './trapReceiver';
export * from './syslogReceiver';
export { snmpConfig } from './config';
