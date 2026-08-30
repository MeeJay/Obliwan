// ============================================================================
// @obliwan/shared — the vocabulary of a WAVE ROLLOUT (M7, killer K3)
// ============================================================================
//
// LEAD: this file is NOT re-exported yet. Add `export * from './rollout';` to
// `shared/src/index.ts` next to the `./change` line — that is the only edit
// this milestone needs in a file it is not allowed to touch. Until then the
// server imports it as `@obliwan/shared/dist/rollout`, which keeps working
// unchanged once the barrel line exists.
//
// ┌─ WHAT A ROLLOUT IS ───────────────────────────────────────────────────────┐
// │ One template revision, N devices, pushed in WAVES with a HEALTH GATE       │
// │ measured BETWEEN them. Every wave is a bet that the previous wave already  │
// │ paid off, and the gate is what collects.                                  │
// │                                                                          │
// │ A rollout is NOT a loop over `POST /changes/jobs`. Three things make it   │
// │ a different object, and all three are safety properties:                  │
// │                                                                          │
// │  1. THE BASELINE IS TAKEN BEFORE THE WAVE. A gate that compares the       │
// │     device to its own post-change state measures nothing, and an          │
// │     interface that was ALREADY erroring before we touched anything must   │
// │     not fail a healthy wave — accusing ourselves of a breakage we did not │
// │     cause is how a good rollout gets rolled back.                         │
// │                                                                          │
// │  2. THE ORDER FOLLOWS THE SAFETY NET (§8.3). `degraded` devices go LAST.  │
// │     Sending a device with no remote recovery in as the canary is choosing │
// │     the worst possible guinea pig: the one failure we cannot undo.        │
// │                                                                          │
// │  3. THE SUBTREE INTERLOCK (§8.5). A concentrator and its children are     │
// │     never in the same active rollout. If the concentrator falls while its │
// │     children soak with their dead-men armed, we can disarm NONE of them,  │
// │     and N devices revert good changes on their own. One incident becomes  │
// │     N+1. The composition is REFUSED; it is never repaired mid-flight.     │
// └───────────────────────────────────────────────────────────────────────────┘
//
// SECRETS (§8.2 / R10): nothing here carries a device value. The gate reads
// counters and statuses; the baseline stores integers and interface names.

import type { SafetyLevel } from './device';

// ============================================================================
// Statuses
// ============================================================================

/**
 * The life of a rollout.
 *
 *  draft        composed: the N plans are compiled, the waves are laid out,
 *               the blast radius is known. NOTHING has been queued. This is
 *               the state the impact screen reads (§8.3: the level is shown
 *               BEFORE the launch, never after).
 *  running      a wave is executing or its gate is being measured.
 *  paused       stopped between waves, by an operator or by a gate that could
 *               not CONCLUDE. Resumable. No device is mid-apply.
 *  rolling_back the gate failed: the previous waves are being restored.
 *  succeeded    every wave passed its gate.
 *  failed       a wave failed and its rollback could not complete. The one
 *               state that means somebody has to look.
 *  rolled_back  a wave failed and every previously changed device is back on
 *               its pre-change config. THIS IS A SUCCESSFUL OUTCOME of the
 *               safety machinery, exactly as `rolled_back` is on a job.
 *  aborted      stopped by an operator. Devices already changed were either
 *               left (explicit choice) or rolled back — `rollouts.abort_reason`
 *               says which.
 */
export const ROLLOUT_STATUSES = [
  'draft',
  'running',
  'paused',
  'rolling_back',
  'succeeded',
  'failed',
  'rolled_back',
  'aborted',
] as const;
export type RolloutStatus = (typeof ROLLOUT_STATUSES)[number];

/** Rollout states in which the rollout still holds its devices. Mirrors
 *  `ACTIVE_CHANGE_JOB_STATUSES`: it is the predicate of a partial unique
 *  index, not a convention. */
export const ACTIVE_ROLLOUT_STATUSES = ['draft', 'running', 'paused', 'rolling_back'] as const;
export const TERMINAL_ROLLOUT_STATUSES = [
  'succeeded', 'failed', 'rolled_back', 'aborted',
] as const;

export function isActiveRolloutStatus(s: RolloutStatus): boolean {
  return (ACTIVE_ROLLOUT_STATUSES as readonly string[]).includes(s);
}
export function isTerminalRolloutStatus(s: RolloutStatus): boolean {
  return (TERMINAL_ROLLOUT_STATUSES as readonly string[]).includes(s);
}

/**
 * The only transitions that exist.
 *
 * `paused -> running` is the single backward edge and it exists for one
 * reason: a gate that answered INDETERMINATE stopped the train without
 * accusing the change, and a human must be able to restart it after looking.
 * There is no edge from `rolled_back` or `succeeded` back into `running`: a
 * finished rollout is evidence, and evidence that can be reopened is not.
 */
export const ROLLOUT_TRANSITIONS: Readonly<Record<RolloutStatus, readonly RolloutStatus[]>> =
  Object.freeze({
    draft:        ['running', 'aborted'],
    running:      ['paused', 'rolling_back', 'succeeded', 'failed', 'aborted'],
    paused:       ['running', 'rolling_back', 'aborted', 'failed'],
    rolling_back: ['rolled_back', 'failed'],
    succeeded:    [],
    failed:       [],
    rolled_back:  [],
    aborted:      [],
  } as Record<RolloutStatus, readonly RolloutStatus[]>);

export function canRolloutTransition(from: RolloutStatus, to: RolloutStatus): boolean {
  return ROLLOUT_TRANSITIONS[from].includes(to);
}

/**
 * The life of one wave.
 *
 * `gating` is a state of its own and not a flag on `running`: while a wave is
 * gating, every job in it is already terminal and the devices are being
 * WATCHED. Collapsing the two would make "the wave is applying" and "the wave
 * is being judged" indistinguishable on the screen somebody stares at while
 * deciding whether to press abort.
 */
export const ROLLOUT_WAVE_STATUSES = [
  'pending', 'running', 'gating', 'passed', 'failed', 'rolled_back', 'skipped',
] as const;
export type RolloutWaveStatus = (typeof ROLLOUT_WAVE_STATUSES)[number];

/**
 * The life of one device inside a rollout.
 *
 * `cancelled` is distinct from `skipped`: `skipped` is "this wave never ran",
 * `cancelled` is "the rollout was abandoned and this device was released".
 * Both are terminal, and both release the device from the one-active-rollout
 * unique index — which is exactly why they must exist rather than leaving a
 * dead draft holding a fleet hostage.
 */
export const ROLLOUT_TARGET_STATUSES = [
  'pending', 'queued', 'running', 'succeeded', 'failed', 'rolled_back', 'skipped', 'cancelled',
] as const;
export type RolloutTargetStatus = (typeof ROLLOUT_TARGET_STATUSES)[number];

/** Target states in which the device is still committed to this rollout. The
 *  predicate of `rollout_targets_one_active_uq`. */
export const ACTIVE_ROLLOUT_TARGET_STATUSES = ['pending', 'queued', 'running'] as const;

export function isActiveTargetStatus(s: RolloutTargetStatus): boolean {
  return (ACTIVE_ROLLOUT_TARGET_STATUSES as readonly string[]).includes(s);
}

// ============================================================================
// The wave plan — 1 → 5% → 25% → the rest
// ============================================================================

/**
 * The four canary checkpoints, as CUMULATIVE COVERAGE of the fleet.
 *
 * "1, then 5%, then 25%, then the rest" is read the way canary deployments are
 * always read: after wave 2 five percent of the fleet carries the change, not
 * five percent plus one. The alternative reading (each wave is 5% of the
 * fleet) makes the second wave smaller than the first on any fleet under
 * twenty devices, which is not a ramp.
 *
 * `count: 1` on the first checkpoint rather than a percentage: the canary is
 * ONE device whatever the fleet size. A percentage-based canary on 300 devices
 * is fifteen simultaneous first contacts.
 */
export const ROLLOUT_WAVE_PLAN: ReadonlyArray<{
  readonly label: string;
  /** Absolute cumulative count, when the checkpoint is a fixed number. */
  readonly count?: number;
  /** Cumulative fraction of the fleet, when it is a proportion. */
  readonly fraction?: number;
}> = Object.freeze([
  { label: 'canary', count: 1 },
  { label: '5%', fraction: 0.05 },
  { label: '25%', fraction: 0.25 },
  { label: 'rest', fraction: 1 },
]);

export interface PlannedWave {
  index: number;
  label: string;
  size: number;
  /** How many devices carry the change once this wave has passed. */
  cumulative: number;
}

/**
 * Turn a device count into waves.
 *
 * Empty checkpoints are DROPPED rather than kept at size zero: on a fleet of
 * twenty, `5%` is one device and the canary already covered it, so a `5%` wave
 * would be a wave with nothing in it — a gate measured on no device, which
 * passes for free and teaches nothing. A wave that cannot be evidence must not
 * exist.
 *
 * `n = 0` returns no waves at all; a rollout with no targets is refused at
 * composition, and this function does not pretend otherwise by inventing one.
 */
export function planWaves(n: number): PlannedWave[] {
  if (!Number.isFinite(n) || n <= 0) return [];
  const waves: PlannedWave[] = [];
  let covered = 0;
  for (const step of ROLLOUT_WAVE_PLAN) {
    const target = Math.min(
      n,
      step.count !== undefined ? step.count : Math.ceil((step.fraction ?? 1) * n),
    );
    const size = target - covered;
    if (size <= 0) continue;
    covered = target;
    waves.push({ index: waves.length, label: step.label, size, cumulative: covered });
  }
  // The plan above always ends on `fraction: 1`, so `covered === n` here. The
  // assertion is kept as an explicit remainder wave rather than a comment: a
  // future edit to ROLLOUT_WAVE_PLAN that drops the 100% checkpoint would
  // otherwise silently leave devices out of every wave.
  if (covered < n) {
    waves.push({ index: waves.length, label: 'rest', size: n - covered, cumulative: n });
  }
  return waves;
}

// ============================================================================
// The subtree interlock — §8.5
// ============================================================================

/** The minimum a device must expose for the interlock to be decidable. */
export interface SubtreeNode {
  deviceId: number;
  deviceName?: string;
  /** `'concentrator'` or `'cpe'`. Never the string `'chr'` — that named a
   *  MikroTik PRODUCT, not a function (§8.5, correction 1). */
  role: string;
  /** `devices.concentrator_id`. NULL on a concentrator, and on an orphan CPE. */
  concentratorId: number | null;
}

export interface SubtreeConflict {
  concentratorId: number;
  concentratorName: string | null;
  childDeviceIds: number[];
}

/**
 * Find every (concentrator, child) pair inside one candidate rollout.
 *
 * PURE, and deliberately so: the same rule is enforced a second time by a
 * trigger in migration `010`, because §8.5 requires the interlock to be "aussi
 * structurel" as the one-job-per-device index. This function exists so the
 * REFUSAL can be explained on the composition screen — "you cannot roll out
 * chr-paris together with its 12 children" — instead of surfacing as a
 * constraint violation nobody can read.
 *
 * The answer is a LIST, not a boolean: an operator who has to remove devices
 * from a rollout needs to know which ones.
 */
export function findSubtreeConflicts(nodes: readonly SubtreeNode[]): SubtreeConflict[] {
  const concentrators = new Map<number, SubtreeNode>();
  for (const n of nodes) {
    if (n.role === 'concentrator') concentrators.set(n.deviceId, n);
  }
  if (concentrators.size === 0) return [];

  const byConcentrator = new Map<number, number[]>();
  for (const n of nodes) {
    if (n.concentratorId === null) continue;
    if (!concentrators.has(n.concentratorId)) continue;
    // A concentrator that points at another concentrator is a child too: the
    // interlock is about "who carries whose tunnel", not about the role name.
    if (n.deviceId === n.concentratorId) continue;
    const list = byConcentrator.get(n.concentratorId) ?? [];
    list.push(n.deviceId);
    byConcentrator.set(n.concentratorId, list);
  }

  return [...byConcentrator.entries()]
    .map(([concentratorId, childDeviceIds]) => ({
      concentratorId,
      concentratorName: concentrators.get(concentratorId)?.deviceName ?? null,
      childDeviceIds: [...childDeviceIds].sort((a, b) => a - b),
    }))
    .sort((a, b) => a.concentratorId - b.concentratorId);
}

/** The sentence shown when a composition is refused. Written once so the API,
 *  the UI and the logs cannot paraphrase §8.5 into something softer. */
export function describeSubtreeConflict(c: SubtreeConflict): string {
  const name = c.concentratorName ? `${c.concentratorName} (#${c.concentratorId})` : `#${c.concentratorId}`;
  return (
    `The concentrator ${name} and ${c.childDeviceIds.length} of its children ` +
    `(${c.childDeviceIds.join(', ')}) cannot be in the same rollout. If an apply makes the ` +
    'concentrator unreachable while its children are soaking with their dead-men armed, NONE of ' +
    'them can be disarmed and every one of them reverts a good change on its own — one incident ' +
    'becomes N+1 (ARCHITECTURE.md §8.5). Split them into two rollouts, concentrator first.'
  );
}

// ============================================================================
// The health gate — the thing measured BETWEEN two waves
// ============================================================================

/**
 * Three-valued, and for the same reason `GuardVerdict` is (see `change.ts`):
 * `INDETERMINATE` IS NOT `PASS`.
 *
 *  PASS           every signal that could be measured says the wave is healthy.
 *  FAIL           at least one signal PROVES the wave hurt something.
 *  INDETERMINATE  not enough evidence to conclude. The train stops and a human
 *                 is asked — it does NOT roll back. Rolling back on absent
 *                 telemetry would undo good changes every time an SNMP target
 *                 is missing, and a safety net that fires on ignorance is a
 *                 safety net people disable.
 *
 * Any narrowing of this union to `!== 'FAIL'` breaks the milestone.
 */
export const HEALTH_GATE_VERDICTS = ['PASS', 'FAIL', 'INDETERMINATE'] as const;
export type HealthGateVerdict = (typeof HEALTH_GATE_VERDICTS)[number];

export function gateAllowsNextWave(v: HealthGateVerdict): boolean {
  return v === 'PASS';
}
/** True when the gate PROVED harm — the only verdict that rolls a wave back. */
export function gateDemandsRollback(v: HealthGateVerdict): boolean {
  return v === 'FAIL';
}

/**
 * The gate proved harm. Every one of these is a comparison against a baseline
 * taken BEFORE the wave, never against a fixed threshold.
 */
export const HEALTH_GATE_FAIL_REASONS = [
  /** D4: the PPP session that was up before the change is not up after it.
   *  The most direct statement that we cut the tunnel we administer through. */
  'PPP_SESSION_DOWN',
  /** An interface that was `up` (ifOperStatus = 1) at baseline is no longer.
   *  Interfaces already down at baseline are EXCLUDED — trap 1. */
  'IF_OPER_DOWN',
  /** `ifInErrors` grew on an interface that was NOT already erroring. "New"
   *  is the whole word: a link that was dropping frames before we arrived is
   *  not our breakage, and failing a wave for it is accusing ourselves. */
  'NEW_IF_IN_ERRORS',
  /** RTT is worse than the 7-day baseline by more than the tolerated factor. */
  'RTT_REGRESSION',
  /** `sysUpTime` went backwards without us asking for a reboot. The box
   *  restarted — either it crashed, or a dead-man fired. */
  'UNEXPECTED_BOOT',
  /** The device's own change job did not end in `succeeded`. Folded into the
   *  gate so that "the wave is unhealthy" has ONE answer and not two. */
  'JOB_NOT_SUCCEEDED',
  /** A brand-new authenticated session to the device FAILED after the change,
   *  on a box we could reach before it. Every other gate signal is L3 presence:
   *  `pppUp`, `sysUpTime`, RTT, `ifOperStatus`. All four stay perfectly green on
   *  a router that forwards and that nobody can log into any more — which is
   *  exactly what removing the last usable account produces. This is the only
   *  signal in the gate that tests ACCESS rather than PRESENCE. K2 has the same
   *  blind spot at plan time and now checks for it; this is its counterpart
   *  after the fact. */
  'MGMT_SESSION_LOST',
] as const;
export type HealthGateFailReason = (typeof HEALTH_GATE_FAIL_REASONS)[number];

/** The gate could not conclude. Never a `PASS`. */
export const HEALTH_GATE_INDETERMINATE_REASONS = [
  /** No baseline row was captured before the wave. Without it there is
   *  nothing to compare to, and comparing to a constant is not a gate. */
  'NO_BASELINE',
  /** No post-wave telemetry at all: the poller never wrote a sample in the
   *  settle window. Silence is not health. */
  'NO_TELEMETRY',
  /** Fewer than `RTT_BASELINE_MIN_SAMPLES` hourly buckets in the 7-day
   *  window: the RTT baseline is not a baseline yet. */
  'RTT_BASELINE_INSUFFICIENT',
  /** The device has no SNMP target, so `ifOperStatus` and `ifInErrors` were
   *  never readable. Honest about A2: the three non-MikroTik brands land here
   *  most often, and pretending they passed would be the §8.3 lie. */
  'NO_SNMP_COVERAGE',
  /** The device is not attached to a concentrator, so PPP presence carries no
   *  information about it. */
  'NO_PPP_SOURCE',
] as const;
export type HealthGateIndeterminateReason = (typeof HEALTH_GATE_INDETERMINATE_REASONS)[number];

export type HealthGateReasonCode = HealthGateFailReason | HealthGateIndeterminateReason;

/** Which verdict a reason implies. THE source of truth — a gate that collects
 *  reasons derives its verdict from this map instead of deciding twice. */
export const HEALTH_GATE_REASON_VERDICT: Readonly<
  Record<HealthGateReasonCode, Exclude<HealthGateVerdict, 'PASS'>>
> = Object.freeze({
  PPP_SESSION_DOWN: 'FAIL',
  IF_OPER_DOWN: 'FAIL',
  NEW_IF_IN_ERRORS: 'FAIL',
  RTT_REGRESSION: 'FAIL',
  UNEXPECTED_BOOT: 'FAIL',
  JOB_NOT_SUCCEEDED: 'FAIL',
  MGMT_SESSION_LOST: 'FAIL',
  NO_BASELINE: 'INDETERMINATE',
  NO_TELEMETRY: 'INDETERMINATE',
  RTT_BASELINE_INSUFFICIENT: 'INDETERMINATE',
  NO_SNMP_COVERAGE: 'INDETERMINATE',
  NO_PPP_SOURCE: 'INDETERMINATE',
} as Record<HealthGateReasonCode, Exclude<HealthGateVerdict, 'PASS'>>);

/** Fold reasons into one verdict. Empty = PASS; one FAIL beats any number of
 *  INDETERMINATEs. Severity, never majority — same rule as `guardVerdictFrom`. */
export function healthGateVerdictFrom(
  reasons: readonly HealthGateReasonCode[],
): HealthGateVerdict {
  let verdict: HealthGateVerdict = 'PASS';
  for (const r of reasons) {
    const v = HEALTH_GATE_REASON_VERDICT[r];
    if (v === 'FAIL') return 'FAIL';
    verdict = v;
  }
  return verdict;
}

/** One reason, with the numbers that produced it. The operator sees the
 *  comparison, not the conclusion: "we stopped" is useless, "ether3 went from
 *  0 to 412 input errors while up" is actionable. */
export interface HealthGateReason {
  code: HealthGateReasonCode;
  message: string;
  /** Interface name when the reason is per-interface. */
  ifName?: string | null;
  before?: number | null;
  after?: number | null;
}

// ============================================================================
// The baseline — captured BEFORE the wave, and this is trap 1
// ============================================================================

/** One interface as it was BEFORE the wave touched anything. */
export interface InterfaceBaseline {
  ifId: number;
  ifName: string;
  /** IF-MIB ifOperStatus, 1..7. 1 = up. */
  operStatus: number;
  /** Input errors accumulated over the baseline window. */
  inErrors: number;
  outErrors: number;
  /** True when the interface was ALREADY down before the change. Such an
   *  interface can never produce `IF_OPER_DOWN`: it is not our breakage. */
  alreadyDown: boolean;
  /** True when the interface was ALREADY dropping frames. It can never
   *  produce `NEW_IF_IN_ERRORS` — the word "NEW" is the whole rule. */
  alreadyErroring: boolean;
}

/**
 * Everything the gate will compare against, frozen at the instant before the
 * wave is queued.
 *
 * Stored as one jsonb column per target row rather than in a table of its own:
 * it is read exactly once, by the gate for that wave, and it is evidence — a
 * shape that is written once and read once does not earn five columns.
 */
export interface HealthBaseline {
  deviceId: number;
  capturedAt: string;
  /** D4's signal. `null` = the device has no concentrator, so PPP presence
   *  says nothing about it (→ NO_PPP_SOURCE, an INDETERMINATE, not a pass). */
  pppUp: boolean | null;
  /** `sysUpTime` in TimeTicks at baseline. A post-wave value BELOW this one is
   *  a reboot we did not ask for. */
  uptimeTicks: number | null;
  /** p95 RTT over the last `RTT_BASELINE_DAYS`, in microseconds. */
  rttBaselineUs: number | null;
  /** How many hourly buckets backed that baseline. Below
   *  `RTT_BASELINE_MIN_SAMPLES` the gate says so instead of comparing. */
  rttBaselineSamples: number;
  /** Empty when the device has no SNMP interfaces (→ NO_SNMP_COVERAGE). */
  interfaces: InterfaceBaseline[];
}

/** The full answer for one device. */
export interface HealthGateResult {
  deviceId: number;
  deviceName: string;
  verdict: HealthGateVerdict;
  reasons: HealthGateReason[];
  /** Which signals were actually measurable. A gate that PASSED on one signal
   *  out of five is a gate that must say so. */
  measured: {
    ppp: boolean;
    interfaces: number;
    rtt: boolean;
    uptime: boolean;
    job: boolean;
  };
}

/** The wave-level fold. One FAIL fails the wave; one INDETERMINATE with no
 *  FAIL pauses it. Same severity rule, one level up. */
export interface WaveGateResult {
  waveIndex: number;
  verdict: HealthGateVerdict;
  devices: HealthGateResult[];
  failedDeviceIds: number[];
  indeterminateDeviceIds: number[];
}

// ============================================================================
// Gate tuning — the four numbers, named once
// ============================================================================

/** §5/M7: "RTT contre une baseline 7 jours". */
export const RTT_BASELINE_DAYS = 7;
/** Below this many hourly buckets the 7-day window is not a baseline. Twelve
 *  hours of data is not a week, and pretending otherwise turns a quiet Sunday
 *  into a regression. */
export const RTT_BASELINE_MIN_SAMPLES = 12;
/**
 * How much worse than baseline p95 the post-wave RTT may be before the gate
 * calls it a regression. 2.0 and not 1.2: RTT over an L2TP tunnel across the
 * public internet is noisy, and a gate that fires on jitter is a gate whose
 * rollbacks nobody believes.
 */
export const RTT_REGRESSION_FACTOR = 2.0;
/** Below this absolute RTT, the factor is not applied at all: 200 µs → 500 µs
 *  is a 2.5x "regression" and means nothing on a LAN. */
export const RTT_REGRESSION_FLOOR_US = 5_000;

/**
 * How long the gate waits, after the last job of a wave went terminal, before
 * it measures. The change has already survived its per-job soak (K1, 5 min by
 * default); this is the extra window during which the poller must produce at
 * least one fresh sample to compare against.
 */
export const GATE_SETTLE_MS = 90_000;

/** Ceiling on how long a wave may sit in `gating` before the gate gives up and
 *  answers INDETERMINATE (which pauses, and does not roll back). */
export const GATE_TIMEOUT_MS = 15 * 60 * 1000;

// ============================================================================
// API / socket shapes
// ============================================================================

/** One device on the impact screen, BEFORE anything is queued. */
export interface RolloutTargetSummary {
  id: number;
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  siteName: string | null;
  brand: string;
  waveIndex: number;
  orderRank: number;
  safetyLevel: SafetyLevel;
  status: RolloutTargetStatus;
  planOpsCount: number;
  riskLevel: string;
  jobId: number | null;
  rollbackJobId: number | null;
  healthVerdict: HealthGateVerdict | null;
  healthReasons: HealthGateReason[];
}

export interface RolloutWaveSummary {
  id: number;
  waveIndex: number;
  label: string;
  status: RolloutWaveStatus;
  targetCount: number;
  succeededCount: number;
  failedCount: number;
  gateVerdict: HealthGateVerdict | null;
  gateReasons: HealthGateReason[];
  startedAt: string | null;
  gateStartedAt: string | null;
  finishedAt: string | null;
}

export interface RolloutSummary {
  id: number;
  uuid: string;
  tenantId: number;
  name: string;
  status: RolloutStatus;
  templateRevisionId: number;
  deviceCount: number;
  siteCount: number;
  waveCount: number;
  currentWaveIndex: number | null;
  succeededCount: number;
  failedCount: number;
  rolledBackCount: number;
  revisionQuarantinedAt: string | null;
  failedWaveIndex: number | null;
  pauseReason: string | null;
  abortReason: string | null;
  startedBy: number | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
}

/** `wan:rollout:progress` — emitted on every state change, keyed by
 *  `rolloutId` so a client watching one rollout can ignore the rest. */
export interface RolloutProgressEvent {
  rolloutId: number;
  tenantId: number;
  status: RolloutStatus;
  currentWaveIndex: number | null;
  waveCount: number;
  deviceCount: number;
  succeededCount: number;
  failedCount: number;
  rolledBackCount: number;
  /** Free-form operator sentence: "wave 2/3 gating", "rolling back 5 devices". */
  message: string;
}

/** `wan:rollout:wave` — a wave changed state, gate verdict included. */
export interface RolloutWaveEvent {
  rolloutId: number;
  tenantId: number;
  waveIndex: number;
  label: string;
  status: RolloutWaveStatus;
  targetCount: number;
  gateVerdict: HealthGateVerdict | null;
  gateReasons: HealthGateReason[];
}

/** `wan:rollout:finished` — terminal, once. */
export interface RolloutFinishedEvent {
  rolloutId: number;
  tenantId: number;
  status: RolloutStatus;
  deviceCount: number;
  succeededCount: number;
  rolledBackCount: number;
  failedWaveIndex: number | null;
  revisionQuarantined: boolean;
  message: string;
}
