// ============================================================================
// ObliWAN — the health gate of a wave rollout (M7 / K3)
// ============================================================================
//
// The gate is the only thing that makes a wave rollout different from a `for`
// loop over `POST /changes/jobs`. It is measured BETWEEN two waves and it
// answers one question: did the wave that just landed break anything?
//
// ┌─ THE TRAP THIS FILE EXISTS TO AVOID ──────────────────────────────────────┐
// │ A gate that compares a device to its own POST-CHANGE state measures       │
// │ nothing. So the comparison point — the BASELINE — is captured before the  │
// │ wave is queued, and `rollout_targets_baseline_before_chk` (migration 010) │
// │ makes a row that was queued without one impossible to represent.          │
// │                                                                          │
// │ The other half of the same trap: an interface that was ALREADY down, or   │
// │ already dropping frames, before anybody touched anything MUST NOT fail a  │
// │ healthy wave. Accusing ourselves of a breakage we did not cause is how a  │
// │ good change gets rolled back and how a team stops trusting the gate. That │
// │ is why `InterfaceBaseline` carries `alreadyDown` and `alreadyErroring`,   │
// │ and why the word in `NEW_IF_IN_ERRORS` is NEW.                            │
// └───────────────────────────────────────────────────────────────────────────┘
//
// THE VERDICT IS THREE-VALUED, exactly like the Management-Path Guard's.
// `INDETERMINATE` is not `PASS`: the gate could not conclude, so the train
// stops and a human is asked. It is also not `FAIL`: rolling a fleet back
// because an SNMP target was never configured would undo good changes on
// ignorance alone, and a net that fires on ignorance is a net people disable.
//
// SHAPE: the judging half is PURE (`judgeDevice`, `foldWave`) and the reading
// half is a set of narrow queries. That split is what lets the acceptance test
// prove the gate's arithmetic without inventing telemetry, and lets the
// service prove the queries without re-implementing the arithmetic.
//
// SECRETS (§8.2 / R10): this file reads counters, statuses and timestamps.
// Nothing it touches can carry a device credential or a config body.

import type { Knex } from 'knex';
import {
  GATE_SETTLE_MS,
  RTT_BASELINE_DAYS,
  RTT_BASELINE_MIN_SAMPLES,
  RTT_REGRESSION_FACTOR,
  RTT_REGRESSION_FLOOR_US,
  healthGateVerdictFrom,
  type HealthBaseline,
  type HealthGateReason,
  type HealthGateReasonCode,
  type HealthGateResult,
  type HealthGateVerdict,
  type InterfaceBaseline,
  type WaveGateResult,
} from '@obliwan/shared/dist/rollout';
import { db } from '../../db';

/**
 * How far back the baseline looks for "was this interface already erroring".
 *
 * `snmp_if_samples.in_errs` is a DELTA over one poll window (migration 006),
 * not an absolute counter, so "already erroring" is a SUM over a window and
 * the window has to be long enough to catch an interface that drops a frame
 * every few minutes. Thirty minutes at a 30 s poll is sixty samples.
 */
export const BASELINE_ERROR_WINDOW_MS = 30 * 60 * 1000;

/** IF-MIB `ifOperStatus`. 1 = up; everything else is not up. */
const IF_OPER_UP = 1;

// ============================================================================
// Reading the baseline — BEFORE the wave, never after
// ============================================================================

interface DeviceRow {
  id: number;
  name: string;
  concentrator_id: number | null;
}

async function loadDevices(
  tenantId: number,
  deviceIds: readonly number[],
  q: Knex | Knex.Transaction,
): Promise<Map<number, DeviceRow>> {
  if (deviceIds.length === 0) return new Map();
  const rows = (await q('devices')
    .where('tenant_id', tenantId)
    .whereIn('id', deviceIds as number[])
    .select('id', 'name', 'concentrator_id')) as DeviceRow[];
  return new Map(rows.map((r) => [Number(r.id), r]));
}

/**
 * Is the PPP session up RIGHT NOW, as the concentrator sees it (D4)?
 *
 * `null` — not `false` — when the device has no concentrator: PPP presence
 * then says nothing about it, and folding "we cannot look" into "it is down"
 * is exactly how a SITE_DOWN gets invented (`telemetry.ts`, K7).
 */
async function readPppUp(
  device: DeviceRow,
  q: Knex | Knex.Transaction,
): Promise<boolean | null> {
  if (device.concentrator_id === null) return null;
  const open = await q('ppp_sessions')
    .where({ device_id: device.id })
    .whereNull('ended_at')
    .first('id');
  return Boolean(open);
}

/** Latest `sysUpTime` in TimeTicks, from the device series. */
async function readUptimeTicks(
  deviceId: number,
  q: Knex | Knex.Transaction,
  since?: Date,
): Promise<number | null> {
  const query = q('snmp_device_samples')
    .where({ device_id: deviceId })
    .orderBy('ts', 'desc')
    .first('uptime_ticks');
  if (since) query.where('ts', '>=', since);
  const row = (await query) as { uptime_ticks: string | number } | undefined;
  return row ? Number(row.uptime_ticks) : null;
}

/**
 * The 7-day RTT baseline (§5/M7: "RTT contre une baseline 7 jours").
 *
 * Read from the HOURLY rollup and not from the raw table: the raw retention is
 * 48 h (study §1.2), so a seven-day window over `snmp_if_samples`' sibling
 * would silently be a two-day window. `rtt_p95_us` is already a per-bucket
 * p95; the baseline is the p95 OF those, which is deliberately generous —
 * a gate meant to catch "the change made the link twice as slow" must not
 * fire on last Tuesday's worst hour.
 */
async function readRttBaseline(
  deviceId: number,
  q: Knex | Knex.Transaction,
  now: Date,
): Promise<{ p95Us: number | null; samples: number }> {
  const since = new Date(now.getTime() - RTT_BASELINE_DAYS * 24 * 3600 * 1000);
  const row = (await q('snmp_device_rollup_1h')
    .where({ device_id: deviceId })
    .where('bucket', '>=', since)
    .where('rtt_p95_us', '>=', 0)
    .select(
      q.raw('count(*)::int as n'),
      q.raw('percentile_cont(0.95) within group (order by rtt_p95_us) as p95'),
    )
    .first()) as { n: number; p95: string | number | null } | undefined;
  const samples = Number(row?.n ?? 0);
  const p95 = row?.p95 === null || row?.p95 === undefined ? null : Math.round(Number(row.p95));
  return { p95Us: samples > 0 ? p95 : null, samples };
}

/**
 * Every monitored interface as it was before the wave.
 *
 * `state = 'active'` and `monitored = true`: an interface the operator
 * deliberately excluded from polling has no samples, and gating on a series
 * nobody collects is how a gate answers INDETERMINATE forever.
 * `needs_rediscovery` interfaces are excluded too — R12 says nothing is
 * written for them until discovery confirms the new ifIndex, so their counters
 * are not comparable across the wave.
 */
async function readInterfaceBaselines(
  deviceId: number,
  q: Knex | Knex.Transaction,
  now: Date,
): Promise<InterfaceBaseline[]> {
  const ifaces = (await q('snmp_interfaces')
    .where({ device_id: deviceId, state: 'active', monitored: true, needs_rediscovery: false })
    .orderBy('if_name')
    .select('id', 'if_name', 'oper_status')) as Array<{
    id: number;
    if_name: string;
    oper_status: number;
  }>;
  if (ifaces.length === 0) return [];

  const since = new Date(now.getTime() - BASELINE_ERROR_WINDOW_MS);
  const errs = (await q('snmp_if_samples')
    .whereIn('if_id', ifaces.map((i) => Number(i.id)))
    .where('ts', '>=', since)
    .groupBy('if_id')
    .select(
      'if_id',
      q.raw('sum(in_errs)::bigint as in_errs'),
      q.raw('sum(out_errs)::bigint as out_errs'),
    )) as Array<{ if_id: number; in_errs: string; out_errs: string }>;
  const byIf = new Map(errs.map((e) => [Number(e.if_id), e]));

  return ifaces.map((i) => {
    const e = byIf.get(Number(i.id));
    const inErrors = Number(e?.in_errs ?? 0);
    const outErrors = Number(e?.out_errs ?? 0);
    const operStatus = Number(i.oper_status);
    return {
      ifId: Number(i.id),
      ifName: i.if_name,
      operStatus,
      inErrors,
      outErrors,
      // THE two flags trap 1 is about. An interface that was already down, or
      // already dropping frames, cannot be blamed on the wave.
      alreadyDown: operStatus !== IF_OPER_UP,
      alreadyErroring: inErrors > 0 || outErrors > 0,
    };
  });
}

/**
 * Capture the comparison point for a whole wave, in one pass.
 *
 * MUST be called before the wave's jobs are queued. The database enforces it
 * (`rollout_targets_baseline_before_chk`), which is why this function does not
 * bother to assert it: an assertion in TypeScript that the schema already
 * makes unrepresentable is a comment with a stack trace.
 */
export async function captureBaselines(
  tenantId: number,
  deviceIds: readonly number[],
  q: Knex | Knex.Transaction = db,
  now: Date = new Date(),
): Promise<Map<number, HealthBaseline>> {
  const devices = await loadDevices(tenantId, deviceIds, q);
  const out = new Map<number, HealthBaseline>();

  for (const deviceId of deviceIds) {
    const device = devices.get(deviceId);
    if (!device) continue;
    const [pppUp, uptimeTicks, rtt, interfaces] = await Promise.all([
      readPppUp(device, q),
      readUptimeTicks(deviceId, q),
      readRttBaseline(deviceId, q, now),
      readInterfaceBaselines(deviceId, q, now),
    ]);
    out.set(deviceId, {
      deviceId,
      capturedAt: now.toISOString(),
      pppUp,
      uptimeTicks,
      rttBaselineUs: rtt.p95Us,
      rttBaselineSamples: rtt.samples,
      interfaces,
    });
  }
  return out;
}

// ============================================================================
// Reading the AFTER — the same signals, measured in the settle window
// ============================================================================

/** What the gate observes once the wave's jobs are terminal. */
export interface PostWaveSignals {
  deviceId: number;
  /** `null` when the device has no concentrator (see `readPppUp`). */
  pppUp: boolean | null;
  /** Latest `sysUpTime`. `null` = no device sample since the baseline at all. */
  uptimeTicks: number | null;
  /** p95 RTT over the settle window, µs. `null` = not measured. */
  rttUs: number | null;
  /** How many device samples landed since the baseline. Zero is NO_TELEMETRY. */
  deviceSamples: number;
  /** Current `ifOperStatus` and NEW error deltas, per `snmp_interfaces.id`. */
  interfaces: Map<number, { operStatus: number; newInErrors: number; newOutErrors: number }>;
  /** The device's own change job, folded in so "this wave is unhealthy" has
   *  one answer rather than two that can disagree. */
  jobStatus: string | null;
  /**
   * Did a BRAND-NEW authenticated session succeed after the change?
   * `null` = the step never ran or was skipped, which is not evidence either way.
   */
  reconnectOk?: boolean | null;
}

export async function readPostWaveSignals(
  tenantId: number,
  deviceId: number,
  baseline: HealthBaseline,
  jobId: number | null,
  q: Knex | Knex.Transaction = db,
): Promise<PostWaveSignals> {
  const devices = await loadDevices(tenantId, [deviceId], q);
  const device = devices.get(deviceId);
  const since = new Date(baseline.capturedAt);

  const pppUp = device ? await readPppUp(device, q) : null;

  const deviceAgg = (await q('snmp_device_samples')
    .where({ device_id: deviceId })
    .where('ts', '>', since)
    .select(
      q.raw('count(*)::int as n'),
      q.raw('percentile_cont(0.95) within group (order by rtt_us) filter (where rtt_us >= 0) as rtt'),
    )
    .first()) as { n: number; rtt: string | number | null } | undefined;

  const uptimeTicks = await readUptimeTicks(deviceId, q, since);

  const interfaces = new Map<
    number,
    { operStatus: number; newInErrors: number; newOutErrors: number }
  >();
  const ifIds = baseline.interfaces.map((i) => i.ifId);
  if (ifIds.length > 0) {
    const live = (await q('snmp_interfaces')
      .whereIn('id', ifIds)
      .select('id', 'oper_status')) as Array<{ id: number; oper_status: number }>;
    const errs = (await q('snmp_if_samples')
      .whereIn('if_id', ifIds)
      .where('ts', '>', since)
      .groupBy('if_id')
      .select(
        'if_id',
        q.raw('sum(in_errs)::bigint as in_errs'),
        q.raw('sum(out_errs)::bigint as out_errs'),
      )) as Array<{ if_id: number; in_errs: string; out_errs: string }>;
    const byIf = new Map(errs.map((e) => [Number(e.if_id), e]));
    for (const l of live) {
      const e = byIf.get(Number(l.id));
      interfaces.set(Number(l.id), {
        operStatus: Number(l.oper_status),
        // `in_errs` is a per-window DELTA (migration 006), so the sum over the
        // window that starts at the baseline IS the count of new errors. No
        // subtraction of counters, therefore no counter-wrap arithmetic.
        newInErrors: Number(e?.in_errs ?? 0),
        newOutErrors: Number(e?.out_errs ?? 0),
      });
    }
  }

  let jobStatus: string | null = null;
  let reconnectOk: boolean | null = null;
  if (jobId !== null) {
    const job = (await q('change_jobs')
      .where({ id: jobId, tenant_id: tenantId })
      .first('status')) as { status: string } | undefined;
    jobStatus = job?.status ?? null;

    // The `reconnect` step is the ONLY place in the whole product that proves a
    // login still works after a change: `safeApply` opens six brand-new sockets
    // and re-asserts identity on them. It already runs; nothing read its
    // verdict. Latest attempt wins — an earlier attempt that failed and was
    // retried successfully is not a lockout.
    const step = (await q('change_job_steps')
      .where({ job_id: jobId, kind: 'reconnect' })
      .whereIn('status', ['succeeded', 'failed'])
      .orderBy('attempt', 'desc')
      .orderBy('seq', 'desc')
      .first('status')) as { status: string } | undefined;
    reconnectOk = step ? step.status === 'succeeded' : null;
  }

  return {
    deviceId,
    reconnectOk,
    pppUp,
    uptimeTicks,
    rttUs:
      deviceAgg?.rtt === null || deviceAgg?.rtt === undefined
        ? null
        : Math.round(Number(deviceAgg.rtt)),
    deviceSamples: Number(deviceAgg?.n ?? 0),
    interfaces,
    jobStatus,
  };
}

// ============================================================================
// Judging — PURE. Every rule of the gate lives here and nowhere else.
// ============================================================================

function reason(
  code: HealthGateReasonCode,
  message: string,
  extra: Partial<HealthGateReason> = {},
): HealthGateReason {
  return { code, message, ...extra };
}

/**
 * The five signals of §5/M7, plus the job's own outcome.
 *
 * Every FAIL below is a comparison against the baseline. There is not one
 * absolute threshold in this function, and that is deliberate: an absolute
 * threshold is a statement about a fleet we have never measured (§5.0.3 —
 * nothing has ever talked to a real equipment), while a comparison against the
 * device's own state fifteen minutes ago is a statement about the change.
 */
export function judgeDevice(
  deviceName: string,
  baseline: HealthBaseline | null,
  post: PostWaveSignals,
): HealthGateResult {
  const reasons: HealthGateReason[] = [];

  if (!baseline) {
    return {
      deviceId: post.deviceId,
      deviceName,
      verdict: 'INDETERMINATE',
      reasons: [
        reason(
          'NO_BASELINE',
          'No pre-wave baseline was captured for this device, so there is nothing to compare ' +
            'the current state against. A gate without a baseline is not a gate.',
        ),
      ],
      measured: { ppp: false, interfaces: 0, rtt: false, uptime: false, job: false },
    };
  }

  // ── 0. The job's own verdict ──────────────────────────────────────────────
  // A device whose push did not reach `succeeded` has already failed; the
  // signals below would only describe the wreckage.
  if (post.jobStatus !== null && post.jobStatus !== 'succeeded') {
    reasons.push(
      reason(
        'JOB_NOT_SUCCEEDED',
        `The change job for this device ended in '${post.jobStatus}', not 'succeeded'. ` +
          "A 'rolled_back' here means the on-box dead-man already did its work.",
      ),
    );
  }

  // ── 0b. Can we still LOG IN? ──────────────────────────────────────────────
  // Every other signal below is L3 presence. A router that lost its last usable
  // account forwards perfectly: `pppUp` true, `sysUpTime` climbing, RTT normal,
  // every `ifOperStatus` up. The gate would pass the wave and move to the next
  // one, and on a brand with no on-device dead-man that is one truck per device
  // in the wave. This is the only signal here that tests ACCESS.
  if (post.reconnectOk === false) {
    reasons.push(
      reason(
        'MGMT_SESSION_LOST',
        'A brand-new authenticated session to this device failed after the change, on a box we ' +
          'could open one to before it. The packets still arrive; nobody can log in to use them.',
      ),
    );
  }

  // ── 1. PPP session (D4) ───────────────────────────────────────────────────
  if (baseline.pppUp === null) {
    reasons.push(
      reason(
        'NO_PPP_SOURCE',
        'This device is attached to no concentrator, so PPP presence carries no information ' +
          'about it. The most direct signal that we cut our own tunnel is unavailable here.',
      ),
    );
  } else if (baseline.pppUp === true && post.pppUp === false) {
    reasons.push(
      reason(
        'PPP_SESSION_DOWN',
        'The PPP session was UP before this wave and is DOWN after it. This is the most direct ' +
          'statement available that the change cut the tunnel we administer the site through.',
      ),
    );
  }
  // baseline.pppUp === false: the tunnel was already down before we touched
  // anything. Trap 1 — that is not our breakage and must not fail the wave.

  // ── 2. ifOperStatus ───────────────────────────────────────────────────────
  if (baseline.interfaces.length === 0) {
    reasons.push(
      reason(
        'NO_SNMP_COVERAGE',
        'No monitored SNMP interface exists for this device, so ifOperStatus and ifInErrors ' +
          'were never readable. Two of the five gate signals are simply absent.',
      ),
    );
  }
  for (const b of baseline.interfaces) {
    const now = post.interfaces.get(b.ifId);
    if (!now) continue;
    if (!b.alreadyDown && now.operStatus !== IF_OPER_UP) {
      reasons.push(
        reason(
          'IF_OPER_DOWN',
          `Interface ${b.ifName} was up (ifOperStatus 1) before this wave and is now ` +
            `ifOperStatus ${now.operStatus}.`,
          { ifName: b.ifName, before: b.operStatus, after: now.operStatus },
        ),
      );
    }
    // ── 3. NEW input errors. The word NEW is the whole rule (trap 1) ───────
    if (!b.alreadyErroring && now.newInErrors > 0) {
      reasons.push(
        reason(
          'NEW_IF_IN_ERRORS',
          `Interface ${b.ifName} was clean before this wave and has taken ${now.newInErrors} ` +
            'input error(s) since. An interface that was ALREADY erroring is excluded from this ' +
            'check on purpose — blaming a pre-existing fault on our change is how a good ' +
            'rollout gets rolled back.',
          { ifName: b.ifName, before: 0, after: now.newInErrors },
        ),
      );
    }
  }

  // ── 4. RTT against the 7-day baseline ─────────────────────────────────────
  const rttMeasured = post.rttUs !== null;
  if (baseline.rttBaselineSamples < RTT_BASELINE_MIN_SAMPLES) {
    reasons.push(
      reason(
        'RTT_BASELINE_INSUFFICIENT',
        `Only ${baseline.rttBaselineSamples} hourly bucket(s) of RTT exist over the last ` +
          `${RTT_BASELINE_DAYS} days (minimum ${RTT_BASELINE_MIN_SAMPLES}). Twelve hours of ` +
          'data is not a week, and comparing against it turns a quiet Sunday into a regression.',
      ),
    );
  } else if (rttMeasured && baseline.rttBaselineUs !== null) {
    const ceiling = Math.max(
      RTT_REGRESSION_FLOOR_US,
      Math.round(baseline.rttBaselineUs * RTT_REGRESSION_FACTOR),
    );
    if ((post.rttUs as number) > ceiling) {
      reasons.push(
        reason(
          'RTT_REGRESSION',
          `RTT p95 is ${post.rttUs} µs against a ${RTT_BASELINE_DAYS}-day baseline of ` +
            `${baseline.rttBaselineUs} µs (tolerance ×${RTT_REGRESSION_FACTOR}, floor ` +
            `${RTT_REGRESSION_FLOOR_US} µs).`,
          { before: baseline.rttBaselineUs, after: post.rttUs },
        ),
      );
    }
  }

  // ── 5. An unexpected reboot ───────────────────────────────────────────────
  const uptimeMeasured = post.uptimeTicks !== null && baseline.uptimeTicks !== null;
  if (uptimeMeasured && (post.uptimeTicks as number) < (baseline.uptimeTicks as number)) {
    reasons.push(
      reason(
        'UNEXPECTED_BOOT',
        `sysUpTime went backwards (${baseline.uptimeTicks} → ${post.uptimeTicks} ticks): the ` +
          'device restarted during or just after this wave. Either it crashed, or an on-box ' +
          'dead-man fired.',
        { before: baseline.uptimeTicks, after: post.uptimeTicks },
      ),
    );
  }

  // ── 6. Silence is not health ──────────────────────────────────────────────
  if (post.deviceSamples === 0 && baseline.interfaces.length > 0) {
    reasons.push(
      reason(
        'NO_TELEMETRY',
        'Not one telemetry sample landed for this device since the baseline was taken. Silence ' +
          'from a box we just wrote to is not a pass — it is the absence of an answer.',
      ),
    );
  }

  return {
    deviceId: post.deviceId,
    deviceName,
    // The verdict is DERIVED from the reasons through the shared map. Deciding
    // twice — once by collecting reasons and once by setting a verdict — is how
    // a FAIL ends up shown next to a green tick.
    verdict: healthGateVerdictFrom(reasons.map((r) => r.code)),
    reasons,
    measured: {
      ppp: baseline.pppUp !== null,
      interfaces: post.interfaces.size,
      rtt: rttMeasured && baseline.rttBaselineSamples >= RTT_BASELINE_MIN_SAMPLES,
      uptime: uptimeMeasured,
      job: post.jobStatus !== null,
    },
  };
}

/**
 * The wave-level fold. Severity, never majority — one FAIL fails the wave.
 *
 * A wave with no device in it returns INDETERMINATE and not PASS: migration
 * 010 forbids such a wave (`rollout_waves_size_chk`), and if one ever appears
 * anyway it must not be the thing that green-lights the next 200 routers.
 */
export function foldWave(waveIndex: number, devices: HealthGateResult[]): WaveGateResult {
  const failedDeviceIds = devices.filter((d) => d.verdict === 'FAIL').map((d) => d.deviceId);
  const indeterminateDeviceIds = devices
    .filter((d) => d.verdict === 'INDETERMINATE')
    .map((d) => d.deviceId);

  let verdict: HealthGateVerdict = 'PASS';
  if (devices.length === 0) verdict = 'INDETERMINATE';
  else if (failedDeviceIds.length > 0) verdict = 'FAIL';
  else if (indeterminateDeviceIds.length > 0) verdict = 'INDETERMINATE';

  return { waveIndex, verdict, devices, failedDeviceIds, indeterminateDeviceIds };
}

// ============================================================================
// The one call the rollout driver makes
// ============================================================================

export interface GateTarget {
  deviceId: number;
  deviceName: string;
  jobId: number | null;
  baseline: HealthBaseline | null;
}

/**
 * Measure a whole wave: read the AFTER for every device, judge each against
 * its own baseline, fold.
 *
 * Sequential, like `planner.compileForDevices`, and for the same reason: the
 * correct concurrency is a measurement nobody in this project has made yet,
 * and a wave is at most a quarter of a fleet.
 */
export async function evaluateWave(
  tenantId: number,
  waveIndex: number,
  targets: readonly GateTarget[],
  q: Knex | Knex.Transaction = db,
): Promise<WaveGateResult> {
  const results: HealthGateResult[] = [];
  for (const t of targets) {
    if (!t.baseline) {
      results.push(
        judgeDevice(t.deviceName, null, {
          deviceId: t.deviceId,
          pppUp: null,
          uptimeTicks: null,
          rttUs: null,
          deviceSamples: 0,
          interfaces: new Map(),
          jobStatus: null,
        }),
      );
      continue;
    }
    const post = await readPostWaveSignals(tenantId, t.deviceId, t.baseline, t.jobId, q);
    results.push(judgeDevice(t.deviceName, t.baseline, post));
  }
  return foldWave(waveIndex, results);
}

export const healthGate = {
  captureBaselines,
  readPostWaveSignals,
  judgeDevice,
  foldWave,
  evaluateWave,
  GATE_SETTLE_MS,
};
