/**
 * ObliWAN — K7, the reachability verdict.
 *
 * THE POINT OF THIS FILE, IN ONE SENTENCE: `UNREACHABLE` and `SITE_DOWN` are
 * not the same thing, and code that conflates them sends a technician driving
 * to a site because our own observation post went blind.
 *
 * The verdict crosses FOUR independent signals:
 *
 *   pppUp        the PPP session on the concentrator (D4 — the CHR is the
 *                source of truth for presence, not ping).
 *   snmpOk       SNMP answered THROUGH the tunnel. Note that this signal is
 *                not independent of `pppUp`: if the tunnel is down, SNMP
 *                cannot answer, so a false here adds nothing. It only counts
 *                as corroboration when the tunnel is up.
 *   externalOk   an out-of-tunnel probe reached the site's public address.
 *                Genuinely independent. Arrives at M8.
 *   cwmpRecent   a CWMP Inform landed recently. Genuinely independent.
 *                Arrives at M10.
 *
 * In M2 only the first two exist, so the last two are `null` — and `null` is a
 * THIRD value that means "not measured", never `false`. That is the whole
 * reason `SITE_DOWN` cannot be produced by an M2 deployment: asserting a site
 * is dead requires positive evidence from a signal that does not travel
 * through the very tunnel that is down. Without it the honest answer is
 * `UNREACHABLE`, and the truth table says so out loud.
 *
 * `CONCENTRATOR_DEGRADED` is the other half of R5: when the CHR itself is the
 * thing that is broken, its children produce NO verdicts at all. One alert, not
 * three hundred.
 *
 * ┌─ WHAT M8 ADDED, AND THE ONE BUG IT CLOSED ───────────────────────────────┐
 * │ Three things, all below the truth table, none of them touching it:        │
 * │                                                                          │
 * │ 1. `snmpOk` is now MEASURED, from `snmp_targets.last_ok_at`. Stale        │
 * │    reports `null`, not `false` — "the poller has been dead for an hour"   │
 * │    must never read as "the device stopped answering".                     │
 * │                                                                          │
 * │ 2. `externalOk` is now MEASURED, by an out-of-tunnel TCP probe. It is the │
 * │    first genuinely independent signal the product has ever had, and it is │
 * │    the only reason `SITE_DOWN` can now be produced at all. It reports     │
 * │    `false` ONLY once a baseline success exists — see `probeDevice()`.     │
 * │                                                                          │
 * │ 3. THE BUG: `assessDevice()` used to take `concentratorDegraded` from its │
 * │    CALLER. `pppPresence.assessChildren()` calls it without one, so a      │
 * │    re-assessment sweep during a concentrator outage wrote a verdict per   │
 * │    child — the 300 alerts R5 exists to prevent, produced by the code      │
 * │    meant to prevent them, through the one call site that forgot the       │
 * │    argument. The parent's state is now READ HERE and the caller can only  │
 * │    override it. Suppression is a property of the topology, not a          │
 * │    politeness the caller is expected to remember.                         │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

import net from 'net';
import type {
  ReachabilitySignals,
  ReachabilityVerdict,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { logsConfig } from '../logs/config';

/** Total number of signals in the table. Confidence is measured against this,
 *  so an M2 install can never report full confidence — which is correct. */
export const TOTAL_SIGNALS = 4;

export interface VerdictContext {
  /** The concentrator is itself unhealthy: everything under it is suppressed. */
  concentratorDegraded?: boolean;
  /** This device IS the concentrator. */
  isConcentrator?: boolean;
  /**
   * The session is up but the public address it came from is not the one we
   * recorded. That is a silent WAN failover — the thing nothing else reports.
   * `null` = not evaluated (no baseline yet).
   */
  publicPathChanged?: boolean | null;
}

export interface VerdictResult {
  verdict: ReachabilityVerdict;
  /** 0..1 — how many of the four signals actually backed this call. */
  confidence: number;
  /** Which row of the table fired. Debugging the verdict, not the device. */
  reason: string;
  /** True when no verdict row should be written or alerted at all: the parent
   *  concentrator is degraded and any child verdict would be noise. */
  suppressed: boolean;
}

const NO_SIGNALS: ReachabilitySignals = {
  pppUp: null,
  snmpOk: null,
  externalOk: null,
  cwmpRecent: null,
};

/** Signals that reach the site WITHOUT crossing the L2TP tunnel. These are the
 *  only ones that can distinguish "the tunnel died" from "the site died". */
function independentOfTunnel(s: ReachabilitySignals): Array<boolean | null> {
  return [s.externalOk, s.cwmpRecent];
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/**
 * The truth table. PURE: no clock, no I/O, no database — so it is testable
 * without a fleet, and so that a reviewer can read the whole decision in one
 * screen.
 */
export function evaluateReachability(
  signals: Partial<ReachabilitySignals>,
  context: VerdictContext = {},
): VerdictResult {
  const s: ReachabilitySignals = { ...NO_SIGNALS, ...signals };
  const independent = independentOfTunnel(s);
  const measured = [s.pppUp, s.snmpOk, ...independent].filter((v) => v !== null).length;

  // -- Row 0: the observer is broken --------------------------------------
  // Handled before anything else. A degraded concentrator invalidates `pppUp`
  // for every device behind it: the absence of a session says nothing about
  // the site when the thing holding the sessions is the thing that is down.
  if (context.concentratorDegraded && !context.isConcentrator) {
    return {
      verdict: 'CONCENTRATOR_DEGRADED',
      confidence: round2(1 / TOTAL_SIGNALS),
      reason: 'parent_concentrator_degraded',
      suppressed: true,
    };
  }
  if (context.isConcentrator && s.pppUp === null && s.snmpOk === false) {
    return {
      verdict: 'CONCENTRATOR_DEGRADED',
      confidence: round2(1 / TOTAL_SIGNALS),
      reason: 'concentrator_unreachable',
      suppressed: false,
    };
  }

  // -- Row 1: the tunnel is up --------------------------------------------
  if (s.pppUp === true) {
    // A session from an address that is not the nominal one: the site is
    // reachable, but not by the path we think. Nothing else in the stack
    // reports this, which is exactly why K7 exists.
    if (context.publicPathChanged === true) {
      const agree = 1 + (s.snmpOk === true ? 1 : 0);
      return {
        verdict: 'WAN_FAILOVER',
        confidence: round2(agree / TOTAL_SIGNALS),
        reason: 'ppp_up_from_new_public_path',
        suppressed: false,
      };
    }
    const agree =
      1 +
      (s.snmpOk === true ? 1 : 0) +
      independent.filter((v) => v === true).length;
    return {
      verdict: 'UP',
      confidence: round2(agree / TOTAL_SIGNALS),
      // Worth distinguishing: PPP up but SNMP silent is a real, common state
      // (SNMP not provisioned yet). It is still UP, just less corroborated.
      reason: s.snmpOk === true ? 'ppp_up_snmp_ok' : 'ppp_up_only',
      suppressed: false,
    };
  }

  // -- Row 2: the tunnel is down ------------------------------------------
  if (s.pppUp === false) {
    // Any independent signal that still reaches the site proves the site is
    // alive and the TUNNEL is the casualty. This is the verdict that stops an
    // operator from being dispatched for a routing problem.
    if (independent.some((v) => v === true)) {
      const agree = 1 + independent.filter((v) => v === true).length;
      return {
        verdict: 'TUNNEL_DOWN_SITE_UP',
        confidence: round2(agree / TOTAL_SIGNALS),
        reason: 'ppp_down_independent_signal_up',
        suppressed: false,
      };
    }
    // SITE_DOWN is POSITIVE knowledge and requires corroboration from a signal
    // that does not ride the tunnel. `snmpOk === false` does NOT count: SNMP
    // travels through the very tunnel that is down, so its silence is implied
    // by `pppUp === false` and adds no independent evidence.
    const negativeIndependent = independent.filter((v) => v === false).length;
    if (negativeIndependent >= 1) {
      return {
        verdict: 'SITE_DOWN',
        confidence: round2((1 + negativeIndependent) / TOTAL_SIGNALS),
        reason: 'ppp_down_and_independent_signals_down',
        suppressed: false,
      };
    }
    // The M2 case, and the one the milestone acceptance test checks.
    return {
      verdict: 'UNREACHABLE',
      confidence: round2(1 / TOTAL_SIGNALS),
      reason: 'ppp_down_no_independent_signal',
      suppressed: false,
    };
  }

  // -- Row 3: presence not measured ---------------------------------------
  if (s.snmpOk === true || independent.some((v) => v === true)) {
    const agree =
      (s.snmpOk === true ? 1 : 0) + independent.filter((v) => v === true).length;
    return {
      verdict: 'UP',
      confidence: round2(agree / TOTAL_SIGNALS),
      reason: 'no_ppp_signal_but_device_answered',
      suppressed: false,
    };
  }

  return {
    verdict: 'UNREACHABLE',
    confidence: round2(measured / TOTAL_SIGNALS),
    reason: measured === 0 ? 'no_signal_measured' : 'insufficient_evidence',
    suppressed: false,
  };
}

// ============================================================================
// Persistence
// ============================================================================

export interface RecordedVerdict extends VerdictResult {
  deviceId: number;
  ts: string;
  signals: ReachabilitySignals;
  /** False when the row was skipped (suppressed, or identical to the last
   *  one — the table is a change log, not a poll log). */
  written: boolean;
}

/** The latest verdict for a device, or null when it was never assessed. */
export async function latestVerdict(deviceId: number): Promise<{
  verdict: ReachabilityVerdict;
  confidence: number;
  reason: string | null;
  ts: string;
} | null> {
  const row = await db('reachability_verdicts')
    .where({ device_id: deviceId })
    .orderBy('ts', 'desc')
    .orderBy('id', 'desc')
    .first<
      | { verdict: string; confidence: string | number; reason: string | null; ts: Date }
      | undefined
    >();
  if (!row) return null;
  return {
    verdict: row.verdict as ReachabilityVerdict,
    confidence: Number(row.confidence),
    reason: row.reason,
    ts: row.ts.toISOString(),
  };
}

/**
 * Evaluate and persist. Writes only on CHANGE: `reachability_verdicts` is a
 * history of transitions, and appending an identical row every 60 s would turn
 * a 300-device fleet into 400 k rows a month for no information gain (R7).
 *
 * A suppressed verdict (parent concentrator degraded) writes nothing at all —
 * that is the whole point of the suppression.
 */
export async function recordVerdict(
  deviceId: number,
  signals: Partial<ReachabilitySignals>,
  context: VerdictContext = {},
): Promise<RecordedVerdict> {
  const result = evaluateReachability(signals, context);
  const full: ReachabilitySignals = { ...NO_SIGNALS, ...signals };
  const ts = new Date();

  if (result.suppressed) {
    return {
      ...result,
      deviceId,
      ts: ts.toISOString(),
      signals: full,
      written: false,
    };
  }

  const previous = await latestVerdict(deviceId);
  if (previous && previous.verdict === result.verdict && previous.reason === result.reason) {
    return { ...result, deviceId, ts: previous.ts, signals: full, written: false };
  }

  try {
    await db('reachability_verdicts').insert({
      device_id: deviceId,
      ts,
      ppp_up: full.pppUp,
      snmp_ok: full.snmpOk,
      external_ok: full.externalOk,
      cwmp_recent: full.cwmpRecent,
      verdict: result.verdict,
      confidence: result.confidence,
      reason: result.reason,
    });
  } catch (err) {
    // A verdict that cannot be stored must not take the presence path down
    // with it: history is valuable, presence is critical.
    logger.error({ err, deviceId, verdict: result.verdict }, 'Could not persist reachability verdict');
    return { ...result, deviceId, ts: ts.toISOString(), signals: full, written: false };
  }

  return { ...result, deviceId, ts: ts.toISOString(), signals: full, written: true };
}

/**
 * Is this device's parent concentrator currently degraded?
 *
 * READ HERE, not asked of the caller. Every path that assesses a device — the
 * presence listener, the reconciliation sweep, the API — is behind the same
 * suppression, and no future call site can forget the argument (see the header,
 * point 3).
 *
 * The verdict is only honoured while it is FRESH. A `CONCENTRATOR_DEGRADED` row
 * that nothing ever supersedes would silence a whole subtree for ever, which is
 * the mirror-image failure of the 300 alerts: total silence about 300 sites is
 * not better than 300 pages about one outage. After the TTL the children go
 * back to being assessed on their own signals — and with the tunnel still down
 * and no independent signal, the honest answer they produce is `UNREACHABLE`.
 */
async function parentConcentratorDegraded(concentratorId: number | null): Promise<boolean> {
  if (!concentratorId) return false;
  const latest = await latestVerdict(concentratorId);
  if (!latest || latest.verdict !== 'CONCENTRATOR_DEGRADED') return false;
  const ageSec = (Date.now() - new Date(latest.ts).getTime()) / 1000;
  return ageSec <= logsConfig.concentratorDegradedTtlSec;
}

/**
 * `snmpOk`, from the poller's own bookkeeping.
 *
 * THREE-VALUED, and the null cases are the point:
 *   - no enabled target      -> null. SNMP was never provisioned on this box.
 *   - never polled           -> null. We have not looked.
 *   - last poll is stale     -> null. The POLLER is the thing that stopped,
 *                               and its silence says nothing about the device.
 * Only a target that was polled recently and did not answer yields `false`.
 */
async function readSnmpOk(deviceId: number): Promise<boolean | null> {
  const target = await db('snmp_targets')
    .where({ device_id: deviceId, enabled: true })
    .first<
      | { last_poll_at: Date | null; last_ok_at: Date | null; poll_interval_sec: number | null }
      | undefined
    >('last_poll_at', 'last_ok_at', 'poll_interval_sec');
  if (!target || !target.last_poll_at) return null;

  const intervalMs = (target.poll_interval_sec ?? 30) * 1000 * logsConfig.snmpOkIntervals;
  const now = Date.now();
  if (now - target.last_poll_at.getTime() > intervalMs) return null; // the poller is stale
  if (!target.last_ok_at) return false;
  return now - target.last_ok_at.getTime() <= intervalMs;
}

/**
 * `externalOk`, from the out-of-tunnel probe.
 *
 * ┌─ THE BASELINE RULE, AND WHY IT IS NOT OPTIONAL ──────────────────────────┐
 * │ `false` here is one of the two signals that can produce `SITE_DOWN` — the │
 * │ verdict that puts a technician in a van. A probe that has NEVER succeeded │
 * │ is not measuring the site, it is measuring our own ignorance of it: most  │
 * │ customer sites answer nothing at all on their public address, by design.  │
 * │                                                                          │
 * │ So until `baseline_ok_at` is set, this returns `null` no matter how many  │
 * │ times the probe failed. And once it is set, it takes several consecutive  │
 * │ failures before `false`, because one lost SYN is not an outage.           │
 * │                                                                          │
 * │ A stale result also returns `null`: "the prober died an hour ago" must    │
 * │ never read as "the site has been up for an hour".                         │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
async function readExternalOk(deviceId: number): Promise<boolean | null> {
  const state = await db('external_probe_state')
    .where({ device_id: deviceId, enabled: true })
    .first<
      | {
          last_probe_at: Date | null;
          last_ok_at: Date | null;
          baseline_ok_at: Date | null;
          consecutive_failures: number;
        }
      | undefined
    >('last_probe_at', 'last_ok_at', 'baseline_ok_at', 'consecutive_failures');
  if (!state || !state.last_probe_at) return null;

  const ageSec = (Date.now() - state.last_probe_at.getTime()) / 1000;
  if (ageSec > logsConfig.externalProbeStaleSec) return null;

  if (state.consecutive_failures === 0) return true;
  if (!state.baseline_ok_at) return null; // never proven reachable: we do not know
  return state.consecutive_failures >= logsConfig.externalProbeFailuresForDown ? false : null;
}

/**
 * Assess one device from everything the database currently knows.
 *
 * `cwmpRecent` stays `null`: there is no ACS before M10, and writing `false`
 * because we did not look is exactly the bug this file exists to prevent.
 *
 * `overrides` and `context` still win over everything derived here — the
 * presence listener already holds a fresher `pppUp` than the database does, and
 * the self-test needs to drive the table directly.
 */
export async function assessDevice(
  deviceId: number,
  overrides: Partial<ReachabilitySignals> = {},
  context: VerdictContext = {},
): Promise<RecordedVerdict> {
  const device = await db('devices')
    .where({ id: deviceId })
    .first<
      | { id: number; role: string; ppp_username: string | null; concentrator_id: number | null }
      | undefined
    >('id', 'role', 'ppp_username', 'concentrator_id');
  if (!device) throw new Error(`Device ${deviceId} does not exist`);

  let pppUp: boolean | null = null;
  if (device.ppp_username && device.concentrator_id) {
    const open = await db('ppp_sessions')
      .where({ concentrator_id: device.concentrator_id, ppp_username: device.ppp_username })
      .whereNull('ended_at')
      .first('id');
    pppUp = !!open;
  }

  const isConcentrator = device.role === 'concentrator';
  const [snmpOk, externalOk, degraded] = await Promise.all([
    readSnmpOk(deviceId),
    readExternalOk(deviceId),
    // A concentrator is never suppressed by itself, and never has a parent in
    // the topology (§8.5: it is everyone's peer and nobody's child).
    isConcentrator ? Promise.resolve(false) : parentConcentratorDegraded(device.concentrator_id),
  ]);

  return recordVerdict(
    deviceId,
    { pppUp, snmpOk, externalOk, ...overrides },
    { isConcentrator, concentratorDegraded: degraded, ...context },
  );
}

// ============================================================================
// The out-of-tunnel probe — K7's fourth signal (M8)
// ============================================================================

export interface ProbeOutcome {
  deviceId: number;
  target: string | null;
  ok: boolean;
  /** Set when there was nothing to dial: no public address is known. */
  skipped: boolean;
  error: string | null;
  ms: number;
}

/**
 * A TCP connect to the site's PUBLIC address, over the internet, NOT through
 * the L2TP tunnel. That is the whole value of it: `pppUp` and `snmpOk` both
 * ride the tunnel, so when the tunnel dies they go quiet together and say
 * nothing about the site. This one keeps working.
 *
 * ┌─ A REFUSED CONNECTION IS A SUCCESS ──────────────────────────────────────┐
 * │ `ECONNREFUSED` means a TCP RST came back, which means the address is      │
 * │ reachable and something at the other end is alive enough to refuse us.    │
 * │ That is precisely the question being asked. Only silence (timeout) and    │
 * │ unreachability count as failure. Treating a refusal as a failure would    │
 * │ make the signal useless on every site with a closed firewall — that is to │
 * │ say, on every correctly configured site.                                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export function tcpProbe(
  host: string,
  port: number,
  timeoutMs: number,
): Promise<{ ok: boolean; error: string | null; ms: number }> {
  const started = Date.now();
  return new Promise((resolve) => {
    let settled = false;
    const done = (ok: boolean, error: string | null): void => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* already gone */
      }
      resolve({ ok, error, ms: Date.now() - started });
    };

    const socket = net.createConnection({ host, port, timeout: timeoutMs });
    socket.on('connect', () => done(true, null));
    socket.on('timeout', () => done(false, 'timeout'));
    socket.on('error', (err: NodeJS.ErrnoException) => {
      // See the box above: a reset proves reachability.
      if (err.code === 'ECONNREFUSED' || err.code === 'ECONNRESET') done(true, null);
      else done(false, err.code ?? err.message);
    });
  });
}

/**
 * Where to dial for a device, in order of trustworthiness:
 *   1. an operator-configured target;
 *   2. `devices.wan_public_ip`, the address inventory recorded;
 *   3. the `caller_ip` of the most recent PPP session — the address the
 *      concentrator SAW the site connect from, which is the freshest public
 *      address anyone has.
 *
 * NEVER `tunnel_ip`. A probe that rides the tunnel is `snmpOk` wearing a
 * different name, and feeding it into the truth table as an "independent"
 * signal would let a single tunnel outage produce `SITE_DOWN`.
 */
async function probeTargetFor(deviceId: number): Promise<{ host: string; port: number } | null> {
  const state = await db('external_probe_state')
    .where({ device_id: deviceId })
    .first<{ target_ip: string | null; target_port: number } | undefined>(
      'target_ip',
      'target_port',
    );
  const port = state?.target_port ?? 443;
  if (state?.target_ip) return { host: state.target_ip, port };

  const device = await db('devices')
    .where({ id: deviceId })
    .first<{ wan_public_ip: string | null; ppp_username: string | null } | undefined>(
      'wan_public_ip',
      'ppp_username',
    );
  if (device?.wan_public_ip) return { host: device.wan_public_ip, port };

  if (device?.ppp_username) {
    const session = await db('ppp_sessions')
      .where({ ppp_username: device.ppp_username })
      .whereNotNull('caller_ip')
      .orderBy('id', 'desc')
      .first<{ caller_ip: string | null } | undefined>('caller_ip');
    if (session?.caller_ip) return { host: session.caller_ip, port };
  }
  return null;
}

/** Probe one device and record the result. Does not compute a verdict — that
 *  is `assessDevice()`'s job, on its own schedule. */
export async function probeDevice(deviceId: number): Promise<ProbeOutcome> {
  const now = new Date();
  const target = await probeTargetFor(deviceId);

  if (!target) {
    // Nothing to dial. The row is NOT touched: leaving `last_probe_at` stale
    // makes `readExternalOk` return `null`, which is the truth. Writing a
    // failure here would manufacture the negative evidence the baseline rule
    // exists to withhold.
    return { deviceId, target: null, ok: false, skipped: true, error: 'no_public_address', ms: 0 };
  }

  const state = await db('external_probe_state')
    .where({ device_id: deviceId })
    .first<{ timeout_ms: number } | undefined>('timeout_ms');
  const result = await tcpProbe(target.host, target.port, state?.timeout_ms ?? 3000);

  const base = {
    device_id: deviceId,
    last_probe_at: now,
    last_error: result.ok ? null : result.error,
  };
  await db('external_probe_state')
    .insert({
      ...base,
      last_ok_at: result.ok ? now : null,
      baseline_ok_at: result.ok ? now : null,
      consecutive_failures: result.ok ? 0 : 1,
      updated_at: now,
    })
    .onConflict('device_id')
    .merge({
      ...base,
      last_ok_at: result.ok ? now : db.raw('external_probe_state.last_ok_at'),
      // Set once, never cleared: it is the record that this probe HAS worked at
      // least once, which is what licenses it to ever report `false`.
      baseline_ok_at: result.ok
        ? db.raw('coalesce(external_probe_state.baseline_ok_at, ?)', [now])
        : db.raw('external_probe_state.baseline_ok_at'),
      consecutive_failures: result.ok
        ? 0
        : db.raw('external_probe_state.consecutive_failures + 1'),
      updated_at: now,
    });

  return {
    deviceId,
    target: `${target.host}:${target.port}`,
    ok: result.ok,
    skipped: false,
    error: result.error,
    ms: result.ms,
  };
}

/** One prober tick: a bounded batch of the stalest enabled probes. */
export async function probeDueDevices(): Promise<{ probed: number; up: number; down: number }> {
  const rows = await db('external_probe_state')
    .where('enabled', true)
    .andWhere((qb) => {
      void qb
        .whereNull('last_probe_at')
        .orWhereRaw("last_probe_at < now() - (interval '1 second' * interval_sec)");
    })
    .orderByRaw('last_probe_at ASC NULLS FIRST')
    .limit(logsConfig.externalProbeBatch)
    .pluck<number[]>('device_id');
  if (rows.length === 0) return { probed: 0, up: 0, down: 0 };

  let up = 0;
  let down = 0;
  const queue = [...rows];
  const worker = async (): Promise<void> => {
    for (;;) {
      const deviceId = queue.shift();
      if (deviceId === undefined) return;
      try {
        const outcome = await probeDevice(deviceId);
        if (outcome.skipped) continue;
        if (outcome.ok) up += 1;
        else down += 1;
      } catch (err) {
        logger.warn({ err, deviceId }, 'External probe failed unexpectedly');
      }
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(logsConfig.externalProbeConcurrency, rows.length) }, worker),
  );
  return { probed: rows.length, up, down };
}

/**
 * Enrol a device in the out-of-tunnel probe. Idempotent.
 *
 * Not automatic on device creation: dialling a customer's public address is an
 * outbound connection to somebody else's network, and it is an operator's
 * decision to make, not a side effect of adding a row to the inventory.
 */
export async function enableExternalProbe(
  deviceId: number,
  options: { targetIp?: string | null; port?: number; intervalSec?: number } = {},
): Promise<void> {
  const now = new Date();
  const values = {
    device_id: deviceId,
    enabled: true,
    target_ip: options.targetIp ?? null,
    target_port: options.port ?? 443,
    interval_sec: options.intervalSec ?? 120,
    updated_at: now,
  };
  await db('external_probe_state')
    .insert(values)
    .onConflict('device_id')
    .merge({
      enabled: true,
      target_ip: values.target_ip,
      target_port: values.target_port,
      interval_sec: values.interval_sec,
      updated_at: now,
    });
}

/**
 * The R5 path: the concentrator went away. Raise ONE verdict on the
 * concentrator and mark every child as suppressed without writing a row.
 *
 * Returns how many children were suppressed, which is the number the operator
 * would otherwise have received as pages.
 */
export async function markConcentratorDegraded(
  concentratorId: number,
  lastError?: string,
): Promise<{ concentrator: RecordedVerdict; suppressedChildren: number }> {
  const concentrator = await recordVerdict(
    concentratorId,
    { pppUp: null, snmpOk: false },
    { isConcentrator: true },
  );

  const [{ count }] = await db('devices')
    .where({ concentrator_id: concentratorId })
    .count<{ count: string }[]>('id as count');

  const suppressedChildren = Number(count);
  if (suppressedChildren > 0) {
    logger.warn(
      { concentratorId, suppressedChildren, lastError },
      'Concentrator degraded: child reachability verdicts suppressed (R5)',
    );
  }
  return { concentrator, suppressedChildren };
}
