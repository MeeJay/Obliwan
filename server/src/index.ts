import './env';
import http from 'http';
import { createApp } from './app';
import { createSocketServer } from './socket';
import { db } from './db';
import { config, validateConfig } from './config';
import { logger } from './utils/logger';
import { authService } from './services/auth.service';
import { groupService } from './services/group.service';
import { setLiveAlertIO } from './services/liveAlert.service';
import { leaderElection } from './services/leaderElection';
import { assertVaultUsable } from './services/secretVault.service';
import { startFleetRuntime, stopFleetRuntime } from './services/fleet';
import { startSnmpRuntime, stopSnmpRuntime } from './services/snmp';
import { startLogsRuntime, stopLogsRuntime } from './services/logs';
import { startChangeWorker, stopChangeWorker } from './services/change/jobQueue.service';
import { changeExecutorReadiness, runJob } from './services/change/apply.service';
import { startAcsRuntime, stopAcsRuntime } from './cwmp';
import { startEvidenceRuntime, stopEvidenceRuntime } from './services/attestation/runtime';
import { startWeatherRuntime, stopWeatherRuntime } from './services/weather';
import { sweepInterventionLinks } from './services/intervention';
import { sweepAftermath } from './services/change/aftermath.service';
import { leaderElection as leader } from './services/leaderElection';

async function main() {
  // 0. Configuration — refuse to start on a bad OBLIWAN_ROLE (arbitrage A5)
  //    before touching the database or opening a port.
  for (const warning of validateConfig()) {
    logger.warn(warning);
  }
  logger.info({ role: config.role }, 'ObliWAN starting');

  // 1. Run pending migrations
  logger.info('Running database migrations...');
  await db.migrate.latest();
  logger.info('Migrations complete');

  // 1b. CREDENTIAL VAULT GUARD (risk R8).
  //
  //     Placed exactly here — AFTER the migrations (it reads
  //     `device_transports`, a table migration 002 creates) and BEFORE anything
  //     that could dial a device. If the database already holds ciphertext and
  //     the configured key cannot decrypt it, this THROWS and `main().catch()`
  //     kills the process.
  //
  //     That is the whole point of the check: an instance carrying the wrong
  //     key boots, looks healthy, and then fails one device at a time — which
  //     an operator reads as "the fleet is down", not as "the key is wrong".
  //     Dying here says which of the two it is, once, at the only moment where
  //     the answer is cheap.
  //
  //     An EMPTY vault is a legitimate fresh install: the guard returns
  //     warnings instead of throwing, and they are logged through pino.
  for (const warning of await assertVaultUsable()) {
    logger.warn(warning);
  }

  // 2. Ensure the default admin exists (mirrors seeds/001_bootstrap.ts, so a
  //    plain `docker compose up` needs no manual seed step).
  await authService.ensureDefaultAdmin(
    config.defaultAdminUsername,
    config.defaultAdminPassword,
  );

  // 2b. Closure-table consistency check (AUDIT-CORR §2.2).
  //
  //     `group_closure` is the only source of truth for settings inheritance
  //     AND for group permissions, and a corrupt closure is INVISIBLE on
  //     screen: getTree renders from `parent_id`, so a group missing its
  //     self-row looks perfectly normal while inheriting nothing and being
  //     unreadable to every non-admin. It LOGS LOUDLY and never throws — a data
  //     inconsistency is a repair job, not a reason to refuse to serve a fleet.
  try {
    await groupService.checkClosureIntegrity();
  } catch (err) {
    logger.error(err, 'Closure integrity check failed to run (continuing startup)');
  }

  // 3. Leader election (arbitrage A5). Nothing is wired to it in M1: the
  //    pollers, the job queue and the drift scheduler arrive in M2/M3 and will
  //    subscribe through leaderElection.onChange().
  await leaderElection.start();

  // 4. Express app + HTTP server
  const app = createApp();
  const server = http.createServer(app);

  // 5. Socket.io — authenticated by the session cookie (see socket.ts, R14)
  const io = createSocketServer(server);
  app.set('io', io);
  setLiveAlertIO(io);

  // 6. Fleet runtime (M2).
  //
  //    Armed here, and no longer from `socket.ts`: arming a background duty is
  //    a startup act and belongs in the startup sequence. Its position is not
  //    free — it must come AFTER `createSocketServer()`, which is what hands
  //    `io` to `fleetEvents` (the channel presence emits through), and AFTER
  //    the vault guard above, so the RouterOS pool is never created against a
  //    vault whose secrets we cannot read.
  //
  //    Presence itself is gated on leadership inside `startFleetRuntime()`: a
  //    `web` replica never campaigns and therefore never opens a
  //    `/ppp/active/listen` on the concentrator (arbitrage A5).
  try {
    startFleetRuntime();
  } catch (err) {
    // A fleet that fails to arm must not stop the API from serving: the
    // operator needs the UI precisely when the fleet side is unhappy.
    logger.error(err, 'Fleet runtime failed to arm — presence will not run on this process');
  }

  // 6b. SNMP runtime (M3): poll scheduler, rollups, partition maintenance, trap
  //     and syslog listeners. Same contract as the fleet runtime above — polling
  //     is gated on leadership inside `startSnmpRuntime()`, so two `web`
  //     replicas never poll the same device twice (which would not just double
  //     the load: it would corrupt the counter deltas the rates are derived from).
  //
  //     Without these lines the whole M3 subsystem is dead code: it compiles,
  //     its tables exist, its routes answer — and nothing ever writes a sample.
  try {
    await startSnmpRuntime();
  } catch (err) {
    logger.error(err, 'SNMP runtime failed to arm — no polling, traps or syslog on this process');
  }

  // 6b-bis. LOGS RUNTIME (M8): the RouterOS `/log` pull, the out-of-tunnel
  //         probe that finally feeds K7's fourth signal, the K6 attribution
  //         sweep and login-event retention.
  //
  //         AFTER the SNMP runtime, because the syslog RECEIVER lives there and
  //         is what produces the login events this runtime attributes from.
  //         All four duties are leader-gated inside `startLogsRuntime()`: they
  //         all either dial an equipment, dial a customer's public address, or
  //         write. The receivers stay ungated, in the SNMP runtime, because a
  //         pushed datagram a follower does not listen for is simply lost.
  //
  //         Without these lines syslog still ingests and login events are still
  //         extracted, but no drift run is ever attributed.
  try {
    startLogsRuntime();
  } catch (err) {
    logger.error(err, 'Logs runtime failed to arm — no /log pull, probes or attribution');
  }

  // 6c. CHANGE QUEUE (M6 — decision D3).
  //
  //     Armed AFTER the SNMP runtime, and that order is not cosmetic: the SNMP
  //     runtime is what ensures the partitions and sweeps the stale alert
  //     state, and a change job that reboots a box while the poller is still
  //     initialising produces a counter discontinuity nobody can attribute.
  //
  //     THE LESSON OF M3 IS THE REASON THESE THREE LINES EXIST AT ALL: that
  //     subsystem compiled, its tables existed and its routes answered, and
  //     because nothing armed it in `index.ts` it never wrote a single sample.
  //     A change queue that is never armed is worse — the API accepts the job,
  //     the UI shows `queued`, and the change simply never happens.
  //
  //     `runJob` is injected rather than imported by the queue, which is what
  //     keeps `jobQueue` (the mechanics) and `apply.service` (the orchestration)
  //     acyclic. Leadership gating lives inside `startChangeWorker`: a `web`
  //     replica never arms, an `all` replica must win the election first, and a
  //     dedicated `worker` runs regardless — several of them side by side is
  //     precisely the deployment `FOR UPDATE SKIP LOCKED` exists for (A5).
  try {
    startChangeWorker(runJob);
    // Say out loud, at boot, whether this build can actually push — and if it
    // cannot, which piece is missing. Both gaps fail closed on their own; what
    // they do not do on their own is tell anybody before the first Apply click.
    for (const warning of (await changeExecutorReadiness()).warnings) {
      logger.warn({ subsystem: 'change' }, warning);
    }
  } catch (err) {
    // A queue that fails to arm must not stop the API: an operator needs the
    // UI most on the day the write path is unhappy. Jobs simply stay `queued`.
    logger.error(err, 'Change queue failed to arm — no change job will run on this process');
  }

  // 6d. ACS TR-069 (M10 — feature C10, arbitrage A1).
  //
  //     A SEPARATE Express app on a SEPARATE listener (7547), armed here for
  //     the same reason as everything above it: ports 7547 and 7548 have been
  //     PUBLISHED by the compose files since M1 with nothing behind them, and
  //     an unarmed ACS is a published port answering RST — 300 CPEs logging
  //     "ACS unreachable" at their own pace with nobody watching. That is a
  //     worse version of the M3 defect (a subsystem that compiled and never
  //     ran) because the failure is visible only from the customer's side.
  //
  //     AFTER the change queue on purpose: a CWMP write goes through
  //     `change_jobs` (D3), so the door has to be open before the corridor.
  //
  //     NOT leader-gated. A CPE PUSHES to whatever address it was provisioned
  //     with; a follower that does not listen loses the Inform outright and
  //     nothing on our side retries. Every replica listens, and the concurrent
  //     writes are made safe by the database — `cwmp_sessions_fallback_uq` and
  //     `FOR UPDATE SKIP LOCKED` on the task queue — rather than by an
  //     election. The periodic sweeps inside the runtime ARE leader-gated.
  try {
    await startAcsRuntime();
  } catch (err) {
    // A listener that fails to bind must not stop the API from serving: the
    // operator needs the UI precisely when the CPE side is unhappy.
    logger.error(err, 'ACS runtime failed to arm — no CPE can reach this instance on 7547');
  }

  // 6e. EVIDENCE RUNTIME (F1 — ARCHITECTURE §10).
  //
  //     One duty: the drift-exception expiry sweep. An exception is a
  //     JUSTIFIED, DATED suppression of a drift finding, and when its review
  //     date passes THE FINDING MUST COME BACK. The sweep is what writes that
  //     back into `drift_findings.ignored` — the column the drift screen, the
  //     fleet roll-up and `drift_runs.max_severity` already read, and which
  //     knows nothing about exceptions.
  //
  //     Without this line the rule is a dead guard: an exception that expired
  //     on Tuesday keeps hiding a critical until somebody happens to open the
  //     exceptions page, which turns F1 from "accepted drift gets revisited"
  //     into "accepted drift is hidden forever, with a date on it".
  //
  //     Leader-gated inside the runtime (A5). It only writes and never dials an
  //     equipment, so two replicas sweeping would be wasteful rather than
  //     dangerous — but the counters it logs are only readable as a rate if one
  //     process produces them.
  try {
    startEvidenceRuntime();
  } catch (err) {
    logger.error(
      err,
      'Evidence runtime failed to arm — expired drift exceptions will only be swept when the '
        + 'exceptions screen is read on this process',
    );
  }

  // 6f. Operator weather (F5, §10). Leadership is gated INSIDE
  //     `startWeatherRuntime`, like every other runtime here.
  try {
    startWeatherRuntime();
  } catch (err) {
    logger.error(err, 'Weather runtime failed to arm — no operator-incident correlation on this process');
  }

  // 6g. The two periodic sweeps that F3 and F4 shipped WITHOUT a caller.
  //
  //     They were delivered as plain exported functions, which is the sixth time
  //     on this project that a subsystem compiled, answered on its routes, and
  //     never ran because nothing armed it (M3's SNMP poller was the first).
  //     Both are leader-gated here rather than inside themselves, because
  //     neither owns a runtime module of its own.
  //
  //     `sweepInterventionLinks` attributes drift produced during a declared
  //     intervention and expires interventions nobody closed — an intervention
  //     left open forever is a permanent hole in attribution.
  //     `sweepAftermath` is the one that looks a week AFTER a change, which is
  //     the window K3's five-minute soak cannot see.
  const FEATURE_SWEEP_MS = 5 * 60_000;
  let featureSweepTimer: NodeJS.Timeout | null = null;
  //     Both sweeps are PER TENANT — they take a tenantId, they are not global.
  //     A tenant that fails must not stop the others: on a multi-customer
  //     platform, one broken tenant silently freezing everybody else's sweeps is
  //     the failure mode to avoid.
  const runFeatureSweeps = async (): Promise<void> => {
    if (!leader.isLeader()) return;
    let tenantIds: number[];
    try {
      tenantIds = await db('tenants').pluck<number[]>('id');
    } catch (err) {
      logger.warn({ err }, 'Feature sweeps: could not list tenants — skipping this tick');
      return;
    }
    for (const tenantId of tenantIds) {
      try { await sweepInterventionLinks(tenantId); } catch (err) {
        logger.warn({ err, tenantId }, 'Intervention link sweep failed — will retry next tick');
      }
      try { await sweepAftermath(tenantId); } catch (err) {
        logger.warn({ err, tenantId }, 'Change aftermath sweep failed — will retry next tick');
      }
    }
  };
  featureSweepTimer = setInterval(() => { void runFeatureSweeps(); }, FEATURE_SWEEP_MS);
  featureSweepTimer.unref?.();
  void runFeatureSweeps();

  // 7. Listen
  server.listen(config.port, () => {
    logger.info(`ObliWAN server listening on port ${config.port}`);
    logger.info(`Environment: ${config.nodeEnv} — role: ${config.role}`);
  });

  // 8. Graceful shutdown
  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return; // ignore a second signal mid-shutdown
    shuttingDown = true;
    logger.info(`Received ${signal}, shutting down...`);

    // Last resort: never let a stuck close()/destroy() block the exit forever.
    const hardExit = setTimeout(() => {
      logger.warn('shutdown: forced exit after 10s timeout');
      process.exit(0);
    }, 10_000);
    hardExit.unref();

    // Resign leadership first so a standby can take over immediately instead of
    // waiting out its retry interval.
    try { await leaderElection.stop(); } catch { /* already down */ }

    // Cancel the `/ppp/active/listen` on every concentrator and close the
    // pooled sockets. An abandoned listen stays registered on the CHR long
    // after the process that opened it is gone.
    // Stopped before the fleet: the SNMP poller reaches devices THROUGH the
    // transports the fleet runtime owns, so tearing the fleet down first would
    // leave in-flight polls talking to a closed pool.
    // Stop CLAIMING first, and wait for the jobs already in flight. A job
    // killed mid-apply is a half-configured router; a job that finishes its
    // phase and then finds the queue closed is a job that recorded what it did.
    // Anything that outlasts the grace period is left to its lease and to the
    // reaper, which never requeues past the write frontier.
    try { await stopChangeWorker(); } catch { /* already down */ }

    // Close the CWMP listener BEFORE the database pool: a CPE mid-session
    // would otherwise get a 500 and record a transfer failure it will report
    // for days. Closed early and idle connections dropped, so a CPE holding a
    // kept-alive socket cannot pin the process for the full 120 s keep-alive.
    try { await stopAcsRuntime(); } catch { /* already down */ }

    try { await stopLogsRuntime(); } catch { /* already down */ }
    try { await stopSnmpRuntime(); } catch { /* already down */ }
    try { stopEvidenceRuntime(); } catch { /* already down */ }
    try { await stopWeatherRuntime(); } catch { /* already down */ }
    if (featureSweepTimer) { clearInterval(featureSweepTimer); featureSweepTimer = null; }
    try { await stopFleetRuntime(); } catch { /* already down */ }

    // Stop accepting new work BEFORE tearing down the DB pool.
    try { io.close(); } catch { /* ignore */ }
    try { server.close(); } catch { /* ignore */ }

    // Destroy the pool last. Any in-flight query gets aborted here — that is
    // EXPECTED on shutdown; swallow the resulting rejection so it cannot escape
    // and crash the process before we exit cleanly.
    try {
      await db.destroy();
    } catch (err) {
      logger.warn({ err }, 'shutdown: db.destroy() aborted in-flight queries (expected)');
    }

    clearTimeout(hardExit);
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // Safety nets: a stray promise rejection or sync throw must NOT silently kill
  // the whole server.
  // - unhandledRejection: log and keep serving (usually one recoverable op).
  // - uncaughtException: log and exit so the orchestrator (Docker restart
  //   policy) restarts us cleanly rather than running on with corrupt state.
  process.on('unhandledRejection', (reason) => {
    logger.error({ reason }, 'Unhandled promise rejection (server kept running)');
  });
  process.on('uncaughtException', (err) => {
    logger.fatal(err, 'Uncaught exception — exiting for a clean restart');
    process.exit(1);
  });
}

main().catch((err) => {
  logger.fatal(err, 'Failed to start ObliWAN server');
  process.exit(1);
});
