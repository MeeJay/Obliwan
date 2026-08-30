// ObliWAN client — M7 rollout DTOs (killer K3).
//
// Same rule as `types/change.ts`: the VOCABULARIES that already exist in
// `@obliwan/shared` are never redeclared here. `SafetyLevel`, `RiskLevel`,
// `ChangeJobKind`, `ChangeJobStatus` are the frozen M6 contract, and a rollout
// is nothing but an ordered set of the jobs that contract describes.
//
// What IS declared here is the M7 envelope — waves, health gates, quarantine —
// because `shared/src` has no rollout module yet and this client must not
// invent one there (`shared/src/index.ts` belongs to the lead).
//
// ── THE ONE RULE OF THIS FILE (§8.3) ────────────────────────────────────────
// A wave carries the SAFETY NET of every device in it, and an unknown net is
// `DEGRADED`. §8.3: "Un rollout par vagues (K3) qui mélange des devices ARMÉ et
// DÉGRADÉ traite les DÉGRADÉ en dernier." That ordering is a property of the
// composition, so the composition is a first-class object here —
// `WaveComposition` — and not a devices-per-wave number computed inside a
// render function where nobody can see it.

import type {
  ChangeJobKind,
  ChangeJobStatus,
  RiskLevel,
} from '@obliwan/shared';
import type { DeviceImpact, SafetyNetLevel } from '@/types/change';

// ── Status vocabularies ─────────────────────────────────────────────────────
//
// Mirrors what the `rollouts` / `rollout_waves` tables will hold. Every
// normaliser in `rollout.api.ts` folds an unrecognised value to the PESSIMISTIC
// member of these lists, never to a reassuring one.

export const ROLLOUT_STATUSES = [
  'draft',
  'running',
  'paused',
  'halted',      // a health gate refused; waves already applied stay applied
  'aborted',     // a human stopped it
  'rolled_back', // the applied waves were reverted
  'succeeded',
  'failed',
] as const;
export type RolloutStatus = (typeof ROLLOUT_STATUSES)[number];

export const ACTIVE_ROLLOUT_STATUSES: readonly RolloutStatus[] = [
  'draft', 'running', 'paused',
];

export const WAVE_STATUSES = [
  'pending',
  'running',
  'gating',      // applied, waiting for the health gates to conclude
  'passed',
  'failed',
  'rolled_back',
  'skipped',
] as const;
export type WaveStatus = (typeof WAVE_STATUSES)[number];

/**
 * The five health gates of §5/M7, plus the one §8.4 adds.
 *
 * They are named rather than numbered because the operator must be able to
 * read WHICH signal refused a wave. "Gate 3 failed" is a support ticket; "no
 * new ifInErrors: FAILED on 2 of 5 devices" is a diagnosis.
 */
export const HEALTH_GATE_KINDS = [
  'ppp_session',    // the PPP session came back up on the concentrator
  'oper_status',    // ifOperStatus up on the interfaces that were up before
  'if_errors',      // no NEW ifInErrors since the apply
  'rtt_baseline',   // RTT within tolerance of the 7-day baseline
  'no_boot',        // no unexpected BOOT (sysUpTime went backwards)
  'netwatch',       // §8.4 — the CLIENT's service is still answering
] as const;
export type HealthGateKind = (typeof HEALTH_GATE_KINDS)[number];

export const GATE_STATES = ['pending', 'pass', 'fail', 'unknown', 'skipped'] as const;
export type GateState = (typeof GATE_STATES)[number];

// ── Views ───────────────────────────────────────────────────────────────────

export interface HealthGateView {
  kind: HealthGateKind;
  /** `unknown` is NOT a pass. A gate whose signal never arrived proved nothing,
   *  and the wave screen paints it on the refusing side. */
  state: GateState;
  /** Devices that failed this gate, by id — the drill-down target. */
  failedDeviceIds: number[];
  observedAt: string | null;
  /** Server sentence, shown verbatim. */
  detail: string | null;
}

export interface RolloutTargetView {
  deviceId: number;
  deviceName: string | null;
  siteId: number | null;
  siteName: string | null;
  brand: string;
  waveIndex: number;
  /** §8.3 — the net this device gets. Unknown folds to DEGRADED. */
  safetyNet: SafetyNetLevel;
  safetyPeerDeviceName: string | null;
  /** The job this target became, once its wave started. */
  jobId: number | null;
  jobStatus: ChangeJobStatus | null;
  /** Terminal outcome as the rollout records it, independent of the job row. */
  outcome: 'pending' | 'applied' | 'rolled_back' | 'failed' | 'skipped';
  errorMessage: string | null;
}

export interface RolloutWaveView {
  id: number | null;
  rolloutId: number;
  /** 0-based. Wave 0 is the canary by convention, and the UI says so. */
  index: number;
  label: string | null;
  status: WaveStatus;
  deviceIds: number[];
  gates: HealthGateView[];
  startedAt: string | null;
  finishedAt: string | null;
  succeeded: number;
  rolledBack: number;
  failed: number;
}

export interface RolloutView {
  id: number;
  uuid: string;
  name: string;
  status: RolloutStatus;
  kind: ChangeJobKind;
  /** The template revision being rolled out, when there is one. */
  revisionId: number | null;
  revision: number | null;
  templateName: string | null;
  deviceCount: number;
  waveCount: number;
  /** Index of the wave currently running, or the last one that ran. */
  currentWave: number | null;
  riskLevel: RiskLevel | null;
  /** Set when a gate refused and the revision was quarantined (§5/M7). */
  quarantinedRevisionId: number | null;
  quarantineReason: string | null;
  pausedReason: string | null;
  requestedByName: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
  /** Roll-up counters, so the list does not need every target row. */
  applied: number;
  rolledBack: number;
  failed: number;
  pending: number;
}

export interface RolloutDetail extends RolloutView {
  waves: RolloutWaveView[];
  targets: RolloutTargetView[];
}

// ── The pre-launch impact radius ────────────────────────────────────────────

/**
 * One device on the impact-radius screen.
 *
 * `impact` is the M6 preview (`POST /changes/preview`) — the REAL safety net
 * and the REAL Management-Path Guard verdict for this box. `planCompiled` is
 * the N-plans-before-launch of §5/M7 (`POST /plan/compile`). Either may be
 * missing, and when either is missing the row SAYS so instead of showing a
 * blank cell: a device whose plan would not compile is a device that must not
 * quietly end up in wave 0.
 */
export interface ImpactRow {
  deviceId: number;
  deviceName: string;
  siteName: string | null;
  brand: string;
  role: string;
  concentratorId: number | null;
  /** Devices this one carries, when it IS a concentrator (§8.5). */
  subtreeSize: number;
  impact: DeviceImpact | null;
  /** Why no impact could be computed. Shown; never swallowed. */
  impactError: string | null;
  planCompiled: boolean;
  planError: string | null;
  changeOpCount: number;
  riskLevel: RiskLevel | null;
  touchesManagementPath: boolean;
  /** Folded from `impact`; DEGRADED when there is no impact at all. */
  safetyNet: SafetyNetLevel;
}

/** One wave, as the client composes it BEFORE anything is sent. */
export interface WaveComposition {
  index: number;
  label: string;
  rows: ImpactRow[];
}

/**
 * The whole pre-launch screen in one object.
 *
 * `blockers` is a LIST of sentences and not a boolean because an operator who
 * cannot launch is entitled to know every reason at once rather than one per
 * attempt.
 */
export interface ImpactRadius {
  rows: ImpactRow[];
  waves: WaveComposition[];
  degradedCount: number;
  guardRefusedCount: number;
  concentratorCount: number;
  /** Sites that lose management if a concentrator in the set goes down
   *  (§8.5: "son rayon d'impact est le sous-arbre entier"). */
  subtreeSiteCount: number;
  blockers: string[];
  warnings: string[];
}

// ── The launch request ──────────────────────────────────────────────────────

export interface RolloutLaunchRequest {
  name: string;
  kind: ChangeJobKind;
  /** Wave composition, sent EXPLICITLY as the operator saw it. The server does
   *  not recompute it: a screen that shows one grouping and posts another is
   *  the exact failure this screen exists to prevent. */
  waves: Array<{ index: number; label: string; deviceIds: number[] }>;
  revisionId?: number | null;
  /** §8.3 — required when any device in the set is DEGRADED. */
  degradedConfirmed?: boolean;
  /** Required when the guard did not ACCEPT on at least one device. */
  overrideReason?: string;
  /** Halt the whole rollout on the first wave whose gates do not pass. */
  haltOnGateFailure: boolean;
  /** Quarantine the faulty revision when a gate refuses (§5/M7). */
  quarantineOnFailure: boolean;
}

// ── Safety-net ordering, the §8.3 rule made executable ──────────────────────

const NET_ORDER: Record<SafetyNetLevel, number> = {
  ARMED: 0,
  ARMED_BY_PEER: 1,
  DEGRADED: 2,
};

/**
 * §8.3, literally: DEGRADED devices are treated LAST.
 *
 * The comparison is (net, concentrator-last, name). Concentrators sort after
 * their peers WITHIN the same net because §8.5 makes their blast radius the
 * whole subtree — a canary wave must never open on one.
 */
export function compareForWaveOrder(a: ImpactRow, b: ImpactRow): number {
  const net = NET_ORDER[a.safetyNet] - NET_ORDER[b.safetyNet];
  if (net !== 0) return net;
  const conc = Number(a.role === 'concentrator') - Number(b.role === 'concentrator');
  if (conc !== 0) return conc;
  return a.deviceName.localeCompare(b.deviceName);
}
