// ObliWAN client — M6 change/apply DTOs.
//
// Same rule as `types/config.ts`: the VOCABULARIES come from `@obliwan/shared`
// and are never redeclared here. `ChangeJobStatus`, `ChangeStepKind`,
// `GuardVerdict`, `SafetyLevel`, `ApplyPlan`, `PlanOp`, `RiskLevel` are the
// frozen M6 contract. What lives here is the ENVELOPE the HTTP routes and the
// `wan:job:*` socket frames wrap them in.
//
// ── §8.2 IS LOAD-BEARING IN EVERY SHAPE BELOW ───────────────────────────────
// Nothing in this file may carry a secret. `outputRedacted` / `errorRedacted`
// are masked AT THE SOURCE by the driver — the client is the last reader, not
// the redactor. It still runs `utils/secretScan` over anything it paints,
// because "the server guarantees it" is a claim the UI is in a position to
// check and therefore should.
//
// ── ON THE TWO GUARD VOCABULARIES ───────────────────────────────────────────
// `GuardVerdict` is uppercase three-valued (ACCEPT | REJECT | INDETERMINATE);
// `MgmtPathVerdict` on the plan envelope is lowercase and calls a proven
// refusal a `veto`. The client NEVER hand-maps between them: it calls
// `guardVerdictOfMgmtPath()` from `@obliwan/shared`. One synonym invented at a
// call site is how "we refused" becomes "we pushed".

import type {
  ApplyPlan,
  BlastRadius,
  ChangeJobKind,
  ChangeJobStatus,
  ChangeStepKind,
  ChangeStepStatus,
  GuardVerdict,
  MgmtPathVerdict,
  PlanOp,
  PlanOpKind,
  RiskLevel,
  SafetyLevel,
} from '@obliwan/shared';

// ── The safety net (§8.3) ───────────────────────────────────────────────────
//
// The server's `blastRadius.service.ts` spells these UPPERCASE
// (`ARMED | ARMED_BY_PEER | DEGRADED`) while `devices.safety_level` in the
// database is lowercase (`armed | armed_by_peer | degraded`). Both reach this
// client on different routes. `normalizeSafetyNet()` in `change.api.ts` is the
// ONLY place that folds them, and it folds towards the WORST reading of an
// unknown value — an unrecognised level is DEGRADED, never ARMED. Painting a
// box as self-healing when we do not know is the one mistake this screen
// cannot make.

export const SAFETY_NET_LEVELS = ['ARMED', 'ARMED_BY_PEER', 'DEGRADED'] as const;
export type SafetyNetLevel = (typeof SAFETY_NET_LEVELS)[number];

export const SAFETY_NET_RANK: Readonly<Record<SafetyNetLevel, number>> = {
  ARMED: 0,
  ARMED_BY_PEER: 1,
  DEGRADED: 2,
};

/** §8.3: DEGRADED is detection WITHOUT recovery. An explicit, costly, recorded
 *  confirmation is required before any write job may be created. */
export function netRequiresConfirmation(level: SafetyNetLevel): boolean {
  return level === 'DEGRADED';
}

/** Whether the net survives the death of the ObliWAN server. THE property of
 *  §8.3, and the reason ARMED and ARMED_BY_PEER are two values and not one. */
export function netSurvivesServerLoss(level: SafetyNetLevel): boolean {
  return level !== 'DEGRADED';
}

// ── The guard result, as the plan/preflight routes carry it ─────────────────

/** Mirrors `MgmtGuardReason` in `server/src/services/plan/mgmtPathGuard.ts`.
 *  `effect` splits proofs of a cut from admissions of blindness — the UI shows
 *  both as refusals and labels which kind each one is. */
export interface GuardReasonView {
  code: string;
  effect: 'reject' | 'indeterminate';
  probe: string | null;
  /** Operator-facing sentence, produced server-side. Shown verbatim. */
  message: string;
  culprit: {
    resource: string;
    semKey: string;
    index: number | null;
    chain: string | null;
    /** Brand-neutral one-liner: `chain=input action=drop src-address=...`. */
    describe: string;
    opSeq: number | null;
    opKind: PlanOpKind | null;
  } | null;
}

/** Mirrors `ProbeReport`. `before` is how the box behaves TODAY; a probe whose
 *  packet is already dropped today carries no information about the plan. */
export interface GuardProbeView {
  id: string;
  description: string;
  before: 'accept' | 'drop' | 'unknown';
  after: 'accept' | 'drop' | 'unknown';
}

export interface GuardRouteView {
  state: 'ok' | 'broken' | 'none' | 'unknown';
  via: string | null;
  /** The interface the reply actually leaves through. `state: 'ok'` with a
   *  changed egress is the silent-default-route motif — the UI shows egress
   *  next to state for exactly that reason. */
  egress: string | null;
  detail: string;
}

/** What the engine says it reasoned about. Displayed BESIDE the verdict so
 *  nobody has to guess which address and which interface it analysed. */
export interface GuardAnalysedView {
  peerAddress: string | null;
  managementAddress: string | null;
  tunnelInterface: string | null;
  tunnelInterfaceCertain: boolean;
  ports: number[];
}

export interface GuardResultView {
  verdict: GuardVerdict;
  planVerdict: MgmtPathVerdict;
  reasons: GuardReasonView[];
  probes: GuardProbeView[];
  routing: { before: GuardRouteView; after: GuardRouteView } | null;
  culpritOpSeqs: number[];
  summary: string;
  analysed: GuardAnalysedView | null;
  /** False when the payload carried no guard block at all: the guard was NOT
   *  RUN. That is not an ACCEPT and the UI must not render it as one. */
  ran: boolean;
}

// ── Blast radius, per device and per plan ───────────────────────────────────

export interface DeviceImpact {
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  siteName: string | null;
  brand: string;
  safetyNet: SafetyNetLevel;
  /** `armed_by_peer` is a claim about a SPECIFIC other box; without the peer
   *  named, the claim is empty and the UI says so. */
  safetyPeerDeviceId: number | null;
  safetyPeerDeviceName: string | null;
  guard: GuardResultView;
  riskLevel: RiskLevel;
  changeOpCount: number;
  blockedOpCount: number;
  disruptiveOpCount: number;
  byOpKind: Partial<Record<PlanOpKind, number>>;
  affectedInterfaces: string[];
  affectedSubnets: string[];
  touchesManagementPath: boolean;
  requiresExplicitConfirmation: boolean;
}

// ── The compiled plan as `POST /plan/devices/:id` returns it ────────────────

export interface PlanDiffSummary {
  findingCount: number;
  inertMoveCount: number;
  outOfScopeCount: number;
}

export interface PlanDetail {
  deviceName: string | null;
  renderId: number | null;
  revisionId: number | null;
  revision: number | null;
  templateId: number | null;
  observedSnapshotId: string | null;
  observedCapturedAt: string | null;
  deletionsBlocked: number;
  warnings: string[];
  diff: PlanDiffSummary;
}

/** §8.3's empirical memory, surfaced IN the plan and BEFORE the apply. Below
 *  `significant`, the UI shows raw counts and NO percentage: three rollbacks
 *  out of three is not a 100 % failure rate, it is three rollbacks. */
export interface OutcomeHistoryView {
  opKind: ChangeJobKind;
  brand: string;
  model: string | null;
  osVersion: string | null;
  succeeded: number;
  rolledBack: number;
  lostContact: number;
  total: number;
  significant: boolean;
}

export interface CompiledPlan {
  plan: ApplyPlan;
  detail: PlanDetail;
  /** Present once K2 is wired into the planner. `ran: false` until then. */
  guard: GuardResultView;
  impact: DeviceImpact | null;
  outcomeHistory: OutcomeHistoryView[];
  /** Server-side sentence restating what this payload does NOT claim. */
  notice: string | null;
}

/** `GET /plan/config` — the gate the whole milestone turns on. */
export interface PlanConfig {
  planTtlMs: number;
  /** M5 answered `false`. Until the server answers `true`, every apply control
   *  in this client is inert and says which milestone it waits for. */
  canApply: boolean;
  applyMilestone: string | null;
  mgmtPathGuard: string | null;
  /** Soak window in ms, so the countdown is the server's and not a constant
   *  duplicated in the client. */
  soakMs: number | null;
}

// ── Jobs ────────────────────────────────────────────────────────────────────

export interface ChangeJobView {
  id: number;
  uuid: string;
  deviceId: number;
  deviceName: string | null;
  siteId: number | null;
  siteName: string | null;
  planId: number | null;
  kind: ChangeJobKind;
  status: ChangeJobStatus;
  attempt: number;

  /** The level the job was CREATED with. `armedLevel` below is the level
   *  actually obtained on the box, which may be worse. */
  safetyLevel: SafetyLevel;
  safetyPeerDeviceId: number | null;
  safetyPeerDeviceName: string | null;
  guardVerdict: GuardVerdict | null;
  guardReasons: string[];
  overrideReason: string | null;
  overriddenBy: number | null;
  overriddenByName: string | null;
  overriddenAt: string | null;
  degradedConfirmedBy: number | null;
  degradedConfirmedByName: string | null;
  degradedConfirmedAt: string | null;

  riskLevel: RiskLevel | null;
  baseStateHash: string | null;
  preflightBackupId: number | null;

  // ── the dead-man, which is the whole point of the live screen ──
  deadmanArmedAt: string | null;
  deadmanDisarmedAt: string | null;
  /** The `SafetyLevel` actually obtained when the net was installed. */
  armedLevel: SafetyLevel | null;
  soakUntil: string | null;

  scheduledFor: string | null;
  windowStart: string | null;
  windowEnd: string | null;

  requestedBy: number | null;
  requestedByName: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  createdAt: string;
}

export interface ChangeJobStepView {
  id: number;
  jobId: number;
  seq: number;
  attempt: number;
  kind: ChangeStepKind;
  status: ChangeStepStatus;
  planOpSeq: number | null;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  /** Redacted at the source. Painted through `secretScan` all the same. */
  outputRedacted: string | null;
  errorRedacted: string | null;
}

export interface ChangeJobDetail extends ChangeJobView {
  steps: ChangeJobStepView[];
  plan: ApplyPlan | null;
  planOps: PlanOp[];
  blastRadius: BlastRadius | null;
  guard: GuardResultView | null;
}

// ── Kill switch ─────────────────────────────────────────────────────────────

/**
 * FAIL-CLOSED, in the client too. `blocked` defaults to `true` whenever the
 * state could not be read: a kill switch whose state is unknown is a kill
 * switch that is on. The apply controls are the thing being gated, and the
 * failure mode of guessing wrong is a write we should not have made.
 */
export interface KillSwitchView {
  blocked: boolean;
  /** Which switch blocks: the global one wins and is reported first. */
  by: 'global' | 'tenant' | null;
  reason: string | null;
  engagedAt: string | null;
  engagedByName: string | null;
  /** False when the endpoint is not served by this build — the UI says
   *  "unknown", never "clear". */
  known: boolean;
}

// ── The launch request ──────────────────────────────────────────────────────

/**
 * What `POST /changes/jobs` is given. Every safety field is EXPLICIT and
 * absent-by-default: there is no `force: true` shortcut, and no field here has
 * a value that means "skip the check". `overrideReason` empty is refused
 * client-side AND is a CHECK constraint server-side (migration 009).
 */
export interface CreateJobRequest {
  deviceId: number;
  kind: ChangeJobKind;
  planUuid: string;
  /** The frozen plan, sent whole so the server re-validates the envelope it is
   *  about to freeze rather than trusting a uuid. */
  plan: ApplyPlan;
  /** Required whenever the guard verdict is not ACCEPT. Non-blank. */
  overrideReason?: string;
  /** Required whenever the computed safety net is DEGRADED. */
  degradedConfirmed?: boolean;
  scheduledFor?: string | null;
  windowStart?: string | null;
  windowEnd?: string | null;
}
