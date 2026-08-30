// ============================================================================
// ObliWAN — wave rollouts (M7, killer K3)
// ============================================================================
//
// One template revision, N devices, pushed in canary waves with a HEALTH GATE
// measured BETWEEN them. A failed gate rolls the previous waves back and
// quarantines the revision that caused it.
//
// ┌─ WHAT THIS SERVICE IS ALLOWED TO DO, AND WHAT IT MUST DELEGATE ───────────┐
// │ It NEVER opens a socket to an equipment. Decision D3 says nothing writes  │
// │ outside `change_jobs`, and a rollout is not an exception to D3 — it is a  │
// │ CUSTOMER of it. Every device this file touches is touched by enqueuing a  │
// │ job and watching its status. `jobQueue`, `apply`, `safeApply`, `backup`,  │
// │ `rollback` and `killSwitch` are called, never re-implemented, and the     │
// │ blast radius comes from `plan/blastRadius.service` for the same reason:   │
// │ the numbers on the impact screen must be produced by the code the queue   │
// │ will act on, not by a second implementation that agrees with it today.    │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THE THREE RULES THAT DECIDE THIS MILESTONE ──────────────────────────────┐
// │ 1. THE BASELINE COMES BEFORE THE WAVE. `startWave` captures it and only   │
// │    then queues a single job. `rollout_targets_baseline_before_chk`        │
// │    (migration 010) makes the reverse order unrepresentable, so this is    │
// │    not a convention that a refactor can quietly invert.                   │
// │ 2. `degraded` GOES LAST (§8.3). The order comes from `orderForWaves` in   │
// │    blastRadius.service, and `rollout_targets_safety_order` refuses any    │
// │    row that would break it.                                               │
// │ 3. A CONCENTRATOR AND ITS CHILDREN NEVER SHARE A ROLLOUT (§8.5). The      │
// │    composition is REFUSED — `findSubtreeConflicts` explains it in a       │
// │    sentence, and two triggers in migration 010 make it impossible even if │
// │    somebody writes the rows by hand.                                      │
// └───────────────────────────────────────────────────────────────────────────┘
//
// LEAD, TWO LINES ARE NEEDED IN FILES THIS MILESTONE MAY NOT TOUCH:
//   • `server/src/index.ts`, next to `startChangeWorker(runJob)`:
//         startRolloutRuntime();      // and `await stopRolloutRuntime()` in shutdown
//     Without it this whole subsystem is the M3 lesson repeated: it compiles,
//     its tables exist, its routes answer — and no wave ever advances.
//   • `shared/src/index.ts`: `export * from './rollout';`
//
// SECRETS (§8.2 / R10): the plan envelopes stored on `rollout_targets` are the
// REDACTED ones the planner produced. The complete rendered config exists in
// memory only, on the vault -> equipment path, inside `safeApply`.

import type { Knex } from 'knex';
import { SOCKET_EVENTS, type GuardVerdict, type SafetyLevel } from '@obliwan/shared';
import {
  GATE_SETTLE_MS,
  GATE_TIMEOUT_MS,
  describeSubtreeConflict,
  findSubtreeConflicts,
  isTerminalRolloutStatus,
  planWaves,
  type HealthBaseline,
  type HealthGateReason,
  type PlannedWave,
  type RolloutStatus,
  type RolloutSummary,
  type RolloutTargetStatus,
  type SubtreeConflict,
  type WaveGateResult,
} from '@obliwan/shared/dist/rollout';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { leaderElection } from '../leaderElection';
import { emitToTenant } from '../fleet/fleetEvents';
import {
  enqueueChangeJob,
  evaluateGuardForPlan,
  guardVerdictWorsened,
  resolveSafetyNet,
  type GuardOutcome,
  type SafetyNetPlan,
} from './apply.service';
import { readKillSwitch, KillSwitchEngagedError } from './killSwitch.service';
import { abortJob } from './jobQueue.service';
import { compilePlan, PlanCompilationError } from '../plan/planner.service';
import {
  aggregateBlastRadius,
  orderForWaves,
  describeBlastRadius,
  type BlastDeviceInput,
  type FleetBlastRadius,
  type SafetyNetLevel,
} from '../plan/blastRadius.service';
import { captureBaselines, evaluateWave, type GateTarget } from './healthGate';

// ============================================================================
// Errors
// ============================================================================

/**
 * Every refusal this service can produce, with a machine-readable `kind` the
 * controller maps to a status code. §8.5's interlock arrives as
 * `subtree_interlock` and must never be flattened into a 500: an operator has
 * to be told WHICH devices to remove, not that something went wrong.
 */
export class RolloutRefusedError extends Error {
  constructor(
    readonly kind: string,
    message: string,
    readonly detail: unknown = null,
  ) {
    super(message);
    this.name = 'RolloutRefusedError';
  }
}

// ============================================================================
// Row shapes
// ============================================================================

export interface RolloutRow {
  id: number;
  uuid: string;
  tenant_id: number;
  name: string;
  description: string | null;
  template_revision_id: number;
  status: RolloutStatus;
  wave_count: number;
  device_count: number;
  site_count: number;
  current_wave_index: number | null;
  succeeded_count: number;
  failed_count: number;
  rolled_back_count: number;
  failed_wave_index: number | null;
  revision_quarantined_at: Date | null;
  pause_reason: string | null;
  abort_reason: string | null;
  gate_settle_ms: number;
  override_reason: string | null;
  overridden_by: number | null;
  degraded_confirmed_by: number | null;
  created_by: number | null;
  started_by: number | null;
  started_at: Date | null;
  finished_at: Date | null;
  created_at: Date;
}

export interface WaveRow {
  id: number;
  rollout_id: number;
  tenant_id: number;
  wave_index: number;
  label: string;
  target_count: number;
  status: string;
  succeeded_count: number;
  failed_count: number;
  gate_verdict: string | null;
  gate_reasons: unknown;
  started_at: Date | null;
  gate_started_at: Date | null;
  finished_at: Date | null;
}

export interface TargetRow {
  id: number;
  rollout_id: number;
  wave_id: number;
  tenant_id: number;
  device_id: number;
  wave_index: number;
  order_rank: number;
  status: RolloutTargetStatus;
  safety_level: SafetyLevel;
  safety_peer_device_id: number | null;
  plan_envelope: unknown;
  plan_ops_count: number;
  risk_level: string;
  guard_verdict: string | null;
  job_id: number | null;
  queued_at: Date | null;
  health_baseline: unknown;
  health_baseline_at: Date | null;
  health_verdict: string | null;
  health_reasons: unknown;
  rollback_job_id: number | null;
  rollback_backup_id: number | null;
  note: string | null;
  device_name?: string;
}

/** The device columns `evaluateGuardForPlan` / `resolveSafetyNet` read. Kept
 *  in lockstep with `apply.service.DeviceRecord`; selected explicitly so a
 *  column added there does not silently arrive here as `undefined`. */
const DEVICE_COLUMNS = [
  'id', 'uuid', 'tenant_id', 'site_id', 'name', 'brand', 'family', 'model',
  'os_version', 'tunnel_ip', 'source_ip_hint', 'concentrator_id', 'status', 'is_managed',
] as const;

interface DeviceRow {
  id: number;
  uuid: string;
  tenant_id: number;
  site_id: number | null;
  name: string;
  brand: string;
  family: string;
  model: string | null;
  os_version: string | null;
  tunnel_ip: string | null;
  source_ip_hint: string | null;
  concentrator_id: number | null;
  status: string;
  is_managed: boolean;
  role?: string;
  site_name?: string | null;
}

function iso(d: Date | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

function asArray<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : [];
}

/** `SafetyLevel` (lowercase, the database's spelling) -> `SafetyNetLevel`
 *  (uppercase, blastRadius' spelling). ONE bridge, exactly as
 *  `mgmtPathVerdictOf` is the one bridge between the guard's two vocabularies.
 *  Hand-mapping this at a call site is how a `degraded` device ends up sorted
 *  as if it were armed. */
export function safetyNetLevelOf(level: SafetyLevel): SafetyNetLevel {
  switch (level) {
    case 'armed': return 'ARMED';
    case 'armed_by_peer': return 'ARMED_BY_PEER';
    default: return 'DEGRADED';
  }
}

// ============================================================================
// Composition — the impact screen, and the moment §8.5 refuses
// ============================================================================

export interface ComposeInput {
  tenantId: number;
  name: string;
  description?: string | null;
  deviceIds: readonly number[];
  templateRevisionId: number;
  createdBy: number | null;
  gateSettleMs?: number;
  /** Signed once, in front of the impact screen, for every device whose guard
   *  verdict is not ACCEPT. Copied onto each job at enqueue time, where
   *  migration 009's CHECK makes it non-optional. */
  override?: { reason: string; userId: number | null } | null;
  /** §8.3's explicit confirmation, for every `degraded` device in the set. */
  confirmDegraded?: { userId: number | null } | null;
}

/** One device on the impact screen, before anything is queued. */
export interface ComposedTarget {
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  siteName: string | null;
  brand: string;
  waveIndex: number;
  orderRank: number;
  safetyLevel: SafetyLevel;
  safetyPeerDeviceId: number | null;
  safetyRationale: string;
  guardVerdict: string;
  guardSummary: string;
  planOpsCount: number;
  riskLevel: string;
  /** The REDACTED `ApplyPlan` envelope compiled BEFORE the launch. */
  planEnvelope: unknown;
}

export interface RolloutComposition {
  /** `null` in preview mode: nothing was written. */
  rolloutId: number | null;
  name: string;
  templateRevisionId: number;
  waves: PlannedWave[];
  targets: ComposedTarget[];
  /** Devices whose plan did not compile. They are NOT silently dropped: a
   *  rollout that quietly excludes four devices is a rollout whose operator
   *  believes he covered the fleet. */
  failures: { deviceId: number; deviceName: string | null; reason: string; message: string }[];
  blastRadius: FleetBlastRadius;
  summaryLine: string;
  /** §8.3, counted so the confirmation dialog can state the number. */
  degradedCount: number;
  guardNotClearedCount: number;
  requiresOverride: boolean;
  requiresDegradedConfirmation: boolean;
  killSwitch: { blocked: boolean; reason: string | null };
}

async function loadDevicesForRollout(
  tenantId: number,
  deviceIds: readonly number[],
  q: Knex | Knex.Transaction,
): Promise<DeviceRow[]> {
  const rows = (await q('devices as d')
    .leftJoin('sites as s', 's.id', 'd.site_id')
    .where('d.tenant_id', tenantId)
    .whereIn('d.id', deviceIds as number[])
    .select(
      ...DEVICE_COLUMNS.map((c) => `d.${c}`),
      'd.role as role',
      's.name as site_name',
    )) as DeviceRow[];
  return rows;
}

/**
 * Compile the whole rollout without writing anything to a device.
 *
 * This is §5/M7's "écran de rayon d'impact (compilation des N plans AVANT
 * lancement)" and §8.3's "le niveau est calculé par device et affiché sur
 * l'écran de rayon d'impact AVANT le lancement, jamais après". The three
 * expensive things — the render, the semantic diff and the Management-Path
 * Guard's forwarding simulation — all happen HERE, once, so that the operator
 * decides with the same numbers the queue will act on.
 *
 * `persist = false` is the preview; `persist = true` writes the rollout in
 * `draft`. The two share every line of arithmetic on purpose.
 */
async function build(input: ComposeInput, persist: boolean): Promise<RolloutComposition> {
  const deviceIds = [...new Set(input.deviceIds.map(Number))].filter((n) => Number.isInteger(n) && n > 0);
  if (deviceIds.length === 0) {
    throw new RolloutRefusedError('empty', 'A rollout with no device is not a rollout.');
  }

  const devices = await loadDevicesForRollout(input.tenantId, deviceIds, db);
  const missing = deviceIds.filter((id) => !devices.some((d) => Number(d.id) === id));
  if (missing.length > 0) {
    throw new RolloutRefusedError(
      'device_not_found',
      `Device(s) ${missing.join(', ')} do not exist in this tenant.`,
      { missing },
    );
  }

  // ── §8.5 — THE INTERLOCK, AT COMPOSITION AND NOWHERE LATER ───────────────
  //
  // Refused here, before a single plan is compiled, because the refusal is the
  // point: "Refuse la composition du rollout, ne la répare pas en cours de
  // route." Repairing it mid-flight would mean silently pulling devices out of
  // a set an operator already approved.
  const conflicts: SubtreeConflict[] = findSubtreeConflicts(
    devices.map((d) => ({
      deviceId: Number(d.id),
      deviceName: d.name,
      role: String(d.role ?? 'cpe'),
      concentratorId: d.concentrator_id === null ? null : Number(d.concentrator_id),
    })),
  );
  if (conflicts.length > 0) {
    throw new RolloutRefusedError(
      'subtree_interlock',
      conflicts.map(describeSubtreeConflict).join(' '),
      { conflicts },
    );
  }

  const notWritable = devices.filter(
    (d) => d.status === 'disabled' || d.status === 'quarantined' || !d.is_managed,
  );
  if (notWritable.length > 0) {
    throw new RolloutRefusedError(
      'device_not_writable',
      `${notWritable.length} device(s) in this set cannot be written to: ` +
        notWritable.map((d) => `${d.name} (${d.is_managed ? d.status : 'not managed'})`).join(', ') +
        '. A device can be readable without being writable, and that distinction is the whole ' +
        'reason `is_managed` is a separate column.',
      { deviceIds: notWritable.map((d) => Number(d.id)) },
    );
  }

  // The revision is PINNED here and used for every wave's recompilation. A
  // revision published between wave 1 and wave 4 must not change what wave 4
  // pushes: the operator approved a body, not a moving target.
  const revision = (await db('template_revisions as r')
    .join('templates as t', 't.id', 'r.template_id')
    .where('r.id', input.templateRevisionId)
    .where((b) => b.where('t.tenant_id', input.tenantId).orWhereNull('t.tenant_id'))
    .first('r.id', 'r.status', 'r.revision', 'r.template_id')) as
    | { id: number; status: string; revision: number; template_id: number }
    | undefined;
  if (!revision) {
    throw new RolloutRefusedError(
      'revision_not_found',
      `Template revision ${input.templateRevisionId} does not exist in this tenant.`,
    );
  }
  if (revision.status !== 'published') {
    throw new RolloutRefusedError(
      'revision_not_published',
      `Template revision ${input.templateRevisionId} is '${revision.status}'. Only a published ` +
        'revision may be rolled out — a quarantined one is quarantined for a reason somebody wrote down.',
    );
  }

  // ── The N plans, compiled BEFORE the launch ──────────────────────────────
  const failures: RolloutComposition['failures'] = [];
  const compiled: Array<{
    device: DeviceRow;
    plan: { ops: unknown[]; riskLevel: string; [k: string]: unknown };
    signals: Record<number, unknown>;
    guard: GuardOutcome;
    net: SafetyNetPlan;
  }> = [];

  for (const device of devices) {
    try {
      const compilation = await compilePlan(input.tenantId, Number(device.id), {
        revisionId: input.templateRevisionId,
        // A preview must not litter `config_renders` with rows for a rollout
        // nobody launched; a composed rollout keeps its provenance.
        persistRender: persist,
        createdBy: input.createdBy,
        source: 'template',
      });
      const guard = await evaluateGuardForPlan(device as never, compilation.plan.ops);
      const net = await resolveSafetyNet(device as never);
      compiled.push({
        device,
        plan: compilation.plan as never,
        signals: compilation.detail.signals as never,
        guard,
        net,
      });
    } catch (err) {
      failures.push({
        deviceId: Number(device.id),
        deviceName: device.name,
        reason: err instanceof PlanCompilationError ? err.reason : (err as Error).name,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  if (compiled.length === 0) {
    throw new RolloutRefusedError(
      'nothing_compiles',
      `Not one of the ${devices.length} device(s) produced a plan. ` +
        (failures[0]?.message ?? ''),
      { failures },
    );
  }

  // ── The blast radius, from the ONE implementation (blastRadius.service) ──
  const blastInputs: BlastDeviceInput[] = compiled.map((c) => ({
    deviceId: Number(c.device.id),
    deviceName: c.device.name,
    siteId: c.device.site_id === null ? null : Number(c.device.site_id),
    siteName: c.device.site_name ?? null,
    brand: c.device.brand,
    family: c.device.family as never,
    ops: c.plan.ops as never,
    riskLevel: c.plan.riskLevel as never,
    signals: c.signals as never,
    guardVerdict: c.guard.verdict as never,
    // The REAL, resolved level, not `classifySafetyNet`'s inventory guess: we
    // just asked `apply.service` the same question the enqueue will ask.
    safetyNet: safetyNetLevelOf(c.net.level),
  }));
  const blastRadius = aggregateBlastRadius(blastInputs);

  // ── §8.3's ORDER: armed first, degraded LAST ─────────────────────────────
  const ordered = orderForWaves(
    compiled.map((c) => ({
      safetyNet: safetyNetLevelOf(c.net.level),
      deviceId: Number(c.device.id),
      c,
    })),
  );
  const waves = planWaves(ordered.length);

  const targets: ComposedTarget[] = [];
  let cursor = 0;
  for (const wave of waves) {
    for (let rank = 0; rank < wave.size; rank++) {
      const { c } = ordered[cursor++];
      targets.push({
        deviceId: Number(c.device.id),
        deviceName: c.device.name,
        siteId: c.device.site_id === null ? null : Number(c.device.site_id),
        siteName: c.device.site_name ?? null,
        brand: c.device.brand,
        waveIndex: wave.index,
        orderRank: rank,
        safetyLevel: c.net.level,
        safetyPeerDeviceId: c.net.peerDeviceId,
        safetyRationale: c.net.rationale,
        guardVerdict: c.guard.verdict,
        guardSummary: c.guard.summary,
        planOpsCount: (c.plan.ops as unknown[]).length,
        riskLevel: String(c.plan.riskLevel),
        planEnvelope: c.plan,
      });
    }
  }

  const degradedCount = targets.filter((t) => t.safetyLevel === 'degraded').length;
  const guardNotClearedCount = targets.filter((t) => t.guardVerdict !== 'ACCEPT').length;
  const killSwitch = await readKillSwitch(input.tenantId);

  const composition: RolloutComposition = {
    rolloutId: null,
    name: input.name,
    templateRevisionId: input.templateRevisionId,
    waves,
    targets,
    failures,
    blastRadius,
    summaryLine: describeBlastRadius(blastRadius),
    degradedCount,
    guardNotClearedCount,
    requiresOverride: guardNotClearedCount > 0,
    requiresDegradedConfirmation: degradedCount > 0,
    killSwitch: { blocked: killSwitch.blocked, reason: killSwitch.reason },
  };

  if (!persist) return composition;

  // ── The two signatures, demanded ONCE in front of the numbers above ──────
  if (composition.requiresOverride && !input.override) {
    throw new RolloutRefusedError(
      'guard_refused',
      `${guardNotClearedCount} of ${targets.length} device(s) were not cleared by the ` +
        'Management-Path Guard — INDETERMINATE included, which is a refusal and not a pass. ' +
        'Composing this rollout requires an explicit override with a written reason ' +
        '(capability CHANGE_APPROVE), recorded against your name. It covers THESE devices and ' +
        'only these: a device cleared today and refused by the guard when its wave runs is ' +
        'failed, not pushed.',
      { deviceIds: blastRadius.guardNotClearedDeviceIds },
    );
  }
  if (composition.requiresDegradedConfirmation && !input.confirmDegraded) {
    throw new RolloutRefusedError(
      'degraded_unconfirmed',
      `${degradedCount} of ${targets.length} device(s) have NO remote recovery (§8.3 safety net ` +
        'DEGRADED: detection without repair — a failure there means a visit). They are ordered ' +
        'LAST in the waves, and the rollout still needs an explicit confirmation before it can ' +
        'be composed.',
      { degradedCount },
    );
  }

  const rolloutId = await persistComposition(input, composition);
  composition.rolloutId = rolloutId;
  return composition;
}

async function persistComposition(
  input: ComposeInput,
  composition: RolloutComposition,
): Promise<number> {
  const now = new Date();
  return db.transaction(async (trx) => {
    const [rollout] = (await trx('rollouts')
      .insert({
        tenant_id: input.tenantId,
        name: input.name.trim(),
        description: input.description ?? null,
        template_revision_id: input.templateRevisionId,
        status: 'draft',
        wave_count: composition.waves.length,
        device_count: composition.targets.length,
        site_count: composition.blastRadius.siteCount,
        blast_radius: JSON.stringify(composition.blastRadius),
        gate_settle_ms: input.gateSettleMs ?? GATE_SETTLE_MS,
        override_reason: input.override?.reason ?? null,
        overridden_by: input.override ? input.override.userId : null,
        overridden_at: input.override ? now : null,
        degraded_confirmed_by: input.confirmDegraded ? input.confirmDegraded.userId : null,
        degraded_confirmed_at: input.confirmDegraded ? now : null,
        created_by: input.createdBy,
      })
      .returning('id')) as Array<{ id: string | number }>;
    const rolloutId = Number(rollout.id);

    const waveIdByIndex = new Map<number, number>();
    for (const wave of composition.waves) {
      const [row] = (await trx('rollout_waves')
        .insert({
          rollout_id: rolloutId,
          wave_index: wave.index,
          label: wave.label,
          target_count: wave.size,
          status: 'pending',
        })
        .returning('id')) as Array<{ id: string | number }>;
      waveIdByIndex.set(wave.index, Number(row.id));
    }

    for (const t of composition.targets) {
      await trx('rollout_targets').insert({
        rollout_id: rolloutId,
        wave_id: waveIdByIndex.get(t.waveIndex),
        device_id: t.deviceId,
        wave_index: t.waveIndex,
        order_rank: t.orderRank,
        status: 'pending',
        safety_level: t.safetyLevel,
        safety_peer_device_id: t.safetyPeerDeviceId,
        plan_envelope: JSON.stringify(t.planEnvelope),
        plan_ops_count: t.planOpsCount,
        risk_level: t.riskLevel,
        guard_verdict: t.guardVerdict,
      });
    }
    return rolloutId;
  });
}

export function previewRollout(input: ComposeInput): Promise<RolloutComposition> {
  return build(input, false);
}
export function composeRollout(input: ComposeInput): Promise<RolloutComposition> {
  return build(input, true);
}

// ============================================================================
// Reading
// ============================================================================

export async function getRollout(
  tenantId: number,
  rolloutId: number,
  q: Knex | Knex.Transaction = db,
): Promise<RolloutRow | null> {
  const row = (await q('rollouts')
    .where({ id: rolloutId, tenant_id: tenantId })
    .first('*')) as RolloutRow | undefined;
  return row ?? null;
}

export async function listRollouts(
  tenantId: number,
  opts: { status?: string[]; limit?: number; offset?: number } = {},
): Promise<RolloutSummary[]> {
  const query = db('rollouts').where({ tenant_id: tenantId });
  if (opts.status?.length) query.whereIn('status', opts.status);
  const rows = (await query
    .orderBy('created_at', 'desc')
    .limit(Math.min(opts.limit ?? 50, 200))
    .offset(opts.offset ?? 0)
    .select('*')) as RolloutRow[];
  return rows.map(toRolloutSummary);
}

export function toRolloutSummary(r: RolloutRow): RolloutSummary {
  return {
    id: Number(r.id),
    uuid: r.uuid,
    tenantId: Number(r.tenant_id),
    name: r.name,
    status: r.status,
    templateRevisionId: Number(r.template_revision_id),
    deviceCount: Number(r.device_count),
    siteCount: Number(r.site_count),
    waveCount: Number(r.wave_count),
    currentWaveIndex: r.current_wave_index === null ? null : Number(r.current_wave_index),
    succeededCount: Number(r.succeeded_count),
    failedCount: Number(r.failed_count),
    rolledBackCount: Number(r.rolled_back_count),
    revisionQuarantinedAt: iso(r.revision_quarantined_at),
    failedWaveIndex: r.failed_wave_index === null ? null : Number(r.failed_wave_index),
    pauseReason: r.pause_reason,
    abortReason: r.abort_reason,
    startedBy: r.started_by === null ? null : Number(r.started_by),
    startedAt: iso(r.started_at),
    finishedAt: iso(r.finished_at),
    createdAt: new Date(r.created_at).toISOString(),
  };
}

export async function listWaves(
  rolloutId: number,
  q: Knex | Knex.Transaction = db,
): Promise<WaveRow[]> {
  return (await q('rollout_waves')
    .where({ rollout_id: rolloutId })
    .orderBy('wave_index')
    .select('*')) as WaveRow[];
}

export async function listTargets(
  rolloutId: number,
  waveIndex: number | null = null,
  q: Knex | Knex.Transaction = db,
): Promise<TargetRow[]> {
  const query = q('rollout_targets as t')
    .join('devices as d', 'd.id', 't.device_id')
    .where('t.rollout_id', rolloutId);
  if (waveIndex !== null) query.where('t.wave_index', waveIndex);
  return (await query
    .orderBy(['t.wave_index', 't.order_rank'])
    .select('t.*', 'd.name as device_name')) as TargetRow[];
}

// ============================================================================
// The state machine
// ============================================================================

async function setStatus(
  rollout: RolloutRow,
  status: RolloutStatus,
  patch: Record<string, unknown> = {},
  q: Knex | Knex.Transaction = db,
): Promise<RolloutRow> {
  const update: Record<string, unknown> = { status, updated_at: q.fn.now(), ...patch };
  if (isTerminalRolloutStatus(status) && patch.finished_at === undefined) {
    update.finished_at = new Date();
  }
  await q('rollouts').where({ id: rollout.id }).update(update);
  const fresh = (await q('rollouts').where({ id: rollout.id }).first('*')) as RolloutRow;
  return fresh;
}

// ============================================================================
// Launch — and the ORDER of the two things it does is the milestone
// ============================================================================

export async function launchRollout(
  tenantId: number,
  rolloutId: number,
  userId: number | null,
): Promise<RolloutRow> {
  const rollout = await getRollout(tenantId, rolloutId);
  if (!rollout) throw new RolloutRefusedError('not_found', `Rollout ${rolloutId} not found`);
  if (rollout.status !== 'draft') {
    throw new RolloutRefusedError(
      'not_draft',
      `Rollout ${rolloutId} is '${rollout.status}'. Only a draft can be launched.`,
    );
  }
  const killSwitch = await readKillSwitch(tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);

  const running = await setStatus(rollout, 'running', {
    started_by: userId,
    started_at: new Date(),
    current_wave_index: 0,
    pause_reason: null,
  });

  logger.warn(
    { rolloutId, tenantId, devices: rollout.device_count, waves: rollout.wave_count, userId },
    'ROLLOUT LAUNCHED — a wave rollout is about to write to a fleet',
  );

  await startWave(running, 0);
  emitProgress(running, `wave 1/${running.wave_count} starting`);
  return (await getRollout(tenantId, rolloutId)) as RolloutRow;
}

/**
 * Start one wave. THE ORDER OF THE TWO HALVES IS THE POINT.
 *
 *   1. capture the health baseline for every device in the wave;
 *   2. only then queue a single job.
 *
 * Reversed, the gate would compare each device to its own post-change state
 * and measure nothing at all. `rollout_targets_baseline_before_chk` refuses
 * the row that would result, so this order cannot be inverted by accident —
 * but it is written this way round so nobody has to learn that from a
 * constraint violation at three in the morning.
 */
async function startWave(rollout: RolloutRow, waveIndex: number): Promise<void> {
  const targets = await listTargets(Number(rollout.id), waveIndex);
  if (targets.length === 0) return;

  // ── 1. THE BASELINE, BEFORE ANYTHING IS QUEUED ───────────────────────────
  const baselineAt = new Date();
  const baselines = await captureBaselines(
    Number(rollout.tenant_id),
    targets.map((t) => Number(t.device_id)),
    db,
    baselineAt,
  );
  for (const t of targets) {
    const b = baselines.get(Number(t.device_id));
    // `captureBaselines` returns nothing for a device `loadDevices` no longer
    // hands back — disabled since composition, moved out of the tenant. That
    // device is NOT skipped quietly: `queueTarget` refuses it below, on this
    // very field, and it never reaches a router.
    if (!b) continue;
    await db('rollout_targets').where({ id: t.id }).update({
      health_baseline: JSON.stringify(b),
      health_baseline_at: baselineAt,
      updated_at: db.fn.now(),
    });
    // The in-memory row is what `queueTarget` reads; leaving it stale would
    // make every target look baseline-less.
    t.health_baseline = b;
    t.health_baseline_at = baselineAt;
  }

  await db('rollout_waves')
    .where({ rollout_id: rollout.id, wave_index: waveIndex })
    .update({ status: 'running', started_at: new Date(), updated_at: db.fn.now() });

  // ── 2. Only now, the jobs ────────────────────────────────────────────────
  for (const t of targets) {
    await queueTarget(rollout, t);
  }

  const wave = (await db('rollout_waves')
    .where({ rollout_id: rollout.id, wave_index: waveIndex })
    .first('*')) as WaveRow;
  emitWave(rollout, wave);
}

/**
 * Queue ONE device's push.
 *
 * The plan is RECOMPILED against the pinned revision rather than replayed from
 * the envelope stored at composition. A plan is perishable (`PLAN_TTL_MS` is
 * 30 minutes) and wave 4 can run an hour after wave 1; replaying a stale
 * envelope would hand `enqueueChangeJob` a `base_state_hash` that no longer
 * describes the box, and `assertPlanFresh` would refuse it — correctly, and
 * unhelpfully. Recompiling against the SAME revision keeps the content pinned
 * while letting the base state be today's.
 *
 * A device that refuses to be queued is recorded as `failed` WITH the reason,
 * never dropped: a rollout that quietly skips four devices is a rollout whose
 * operator believes he covered the fleet.
 *
 * ┌─ THE SIGNED OVERRIDE IS NOT A BLANKET, AND IT DOES NOT AGE WELL ──────────┐
 * │ The operator signed in front of a screen that said "3 of 300 device(s)    │
 * │ were not cleared". He signed for THOSE THREE, and for the verdicts they   │
 * │ had at that moment. Replaying that signature verbatim onto every device   │
 * │ of every wave turned it into a standing authorisation: a device that was  │
 * │ ACCEPT at composition, and that an engineer has since fitted with a       │
 * │ `chain=input action=drop`, would be pushed to on a fresh REJECT — the     │
 * │ guard having PROVED the plan cuts the management path — under a reason    │
 * │ that talks about three CPEs in Nantes.                                    │
 * │                                                                          │
 * │ So the override is replayed only onto the devices whose COMPOSITION       │
 * │ verdict was already not ACCEPT (`rollout_targets.guard_verdict`, frozen   │
 * │ by `persistComposition` — the same set the operator was shown as          │
 * │ `blastRadius.guardNotClearedDeviceIds`), and a device whose verdict has   │
 * │ WORSENED since is refused outright, whatever was signed.                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ ONE TRANSACTION, OR AN ORPHAN JOB WRITES TO A ROUTER NOBODY IS WATCHING ─┐
 * │ Creating the job and recording it on the target used to be three          │
 * │ statements in three implicit transactions. The last one can fail —        │
 * │ `rollout_targets_baseline_before_chk` fires on a target whose baseline    │
 * │ was never captured — and the `catch` then marked the TARGET failed while  │
 * │ the JOB stayed queued and went on to push. `failAndRollBack` restores     │
 * │ targets in `succeeded`, so that device was never rolled back: it kept the │
 * │ configuration the gate had just judged harmful.                          │
 * │                                                                          │
 * │ Now: the bookkeeping is one transaction, and if anything after the insert │
 * │ fails the job is ABORTED before the target is written off. A job that     │
 * │ cannot be aborted is one a worker has already claimed — that is a fact an │
 * │ operator has to be told, not a line in a log.                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
async function queueTarget(rollout: RolloutRow, target: TargetRow): Promise<void> {
  const tenantId = Number(rollout.tenant_id);
  let jobId: number | null = null;

  try {
    // ── The baseline, checked BEFORE a job can exist ───────────────────────
    // `startWave` captures it, and skips silently for a device `loadDevices`
    // no longer returns. Without it `rollout_targets_baseline_before_chk`
    // rejects the row that records the job — after the job exists. Refusing
    // here means the device is never written to at all, which is the only
    // acceptable answer for a device whose post-change health CANNOT be
    // measured: an ungated push is not what the operator asked for.
    if (target.health_baseline_at === null) {
      throw new RolloutRefusedError(
        'no_baseline',
        'No health baseline could be captured for this device, so its health gate could ' +
          'never conclude. It has NOT been queued — an unmeasurable push is not a push this ' +
          'rollout is allowed to make. Check that the device is still enabled and in this tenant.',
      );
    }

    const compilation = await compilePlan(tenantId, Number(target.device_id), {
      revisionId: Number(rollout.template_revision_id),
      persistRender: true,
      createdBy: rollout.started_by,
      source: 'template',
    });

    // The verdict this device carried on the composition screen. `null` only
    // for a row written before that column existed; treated as ACCEPT would be
    // the unsafe reading, so it is treated as "not cleared" — the override
    // covers it and the worsening check below still applies.
    const composedVerdict = (target.guard_verdict ?? 'INDETERMINATE') as GuardVerdict;
    const overrideCoversThisDevice = composedVerdict !== 'ACCEPT';

    const result = await enqueueChangeJob({
      tenantId,
      deviceId: Number(target.device_id),
      kind: 'push',
      plan: compilation.plan,
      requestedBy: rollout.started_by,
      override:
        rollout.override_reason && overrideCoversThisDevice
          ? { reason: rollout.override_reason, userId: rollout.overridden_by }
          : null,
      confirmDegraded: rollout.degraded_confirmed_by !== null
        ? { userId: rollout.degraded_confirmed_by }
        : null,
    });
    jobId = result.jobId;

    // The world may have moved between the signature and this wave. Nothing
    // signed at composition authorises a verdict that is worse than the one
    // signed for.
    if (guardVerdictWorsened(composedVerdict, result.guard.verdict)) {
      throw new RolloutRefusedError(
        'guard_worsened',
        `The Management-Path Guard now says ${result.guard.verdict} for this device; it was ` +
          `${composedVerdict} when this rollout was composed and signed. ${result.guard.summary} ` +
          'Nothing signed then covers this, so the device has been left untouched.',
      );
    }

    // Migration 009 forward-declared these three columns for exactly this
    // moment; `change_jobs_rollout_chk` ties the first two together and
    // `change_jobs_canary_rank_chk` (010) ties the third to them.
    //
    // ONE transaction with the target row: either this device is a queued
    // target of this rollout, or it has no job at all.
    await db.transaction(async (trx) => {
      await trx('change_jobs').where({ id: result.jobId }).update({
        rollout_id: rollout.id,
        wave_index: target.wave_index,
        canary_rank: target.order_rank,
        updated_at: trx.fn.now(),
      });

      await trx('rollout_targets').where({ id: target.id }).update({
        job_id: result.jobId,
        queued_at: new Date(),
        status: 'queued',
        guard_verdict: result.guard.verdict,
        safety_level: result.safetyNet.level,
        safety_peer_device_id: result.safetyNet.peerDeviceId,
        plan_ops_count: compilation.plan.ops.length,
        risk_level: compilation.plan.riskLevel,
        updated_at: trx.fn.now(),
      });
    });
    // No device-room emit here: `enqueueChangeJob` already sends JOB_QUEUED to
    // `device:{id}`, and a second payload under the ROLLOUT_PROGRESS name
    // would give one event name two shapes — which is how a client ends up
    // reading `status` off a message that has none.
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      { rolloutId: Number(rollout.id), deviceId: Number(target.device_id), jobId, err },
      'rollout: a device could not be queued',
    );

    // ── The job must not outlive its own bookkeeping ───────────────────────
    let note = message;
    if (jobId !== null) {
      try {
        await abortJob(
          tenantId,
          jobId,
          rollout.started_by,
          'the rollout could not record this job against its target',
        );
      } catch (abortErr) {
        // `abortJob` refuses anything past `queued`: a worker has claimed it
        // and this device IS going to be written to, outside the rollout's
        // accounting. `rollout_targets_job_chk` + `..._baseline_before_chk`
        // forbid naming the job on a target we could not queue, so the only
        // honest place left is the note — and it must scream.
        logger.error(
          { rolloutId: Number(rollout.id), deviceId: Number(target.device_id), jobId, abortErr },
          'ROLLOUT ORPHAN JOB — a change job could not be attached to its rollout target and ' +
            'could not be aborted either. It will write to the device without this rollout ' +
            'watching it, and a wave rollback will NOT restore that device.',
        );
        note =
          `${message}\n\nWARNING: change job #${jobId} was already claimed and could not be ` +
          'aborted. It will write to this device OUTSIDE this rollout, and a wave rollback ' +
          'will not restore it. This device needs a human.';
      }
    }

    await db('rollout_targets').where({ id: target.id }).update({
      status: 'failed',
      note: note.slice(0, 2000),
      updated_at: db.fn.now(),
    });
    await db('rollout_waves')
      .where({ rollout_id: rollout.id, wave_index: target.wave_index })
      .increment('failed_count', 1);
    await db('rollouts').where({ id: rollout.id }).increment('failed_count', 1);
    // Swallowed on purpose, whatever the shape: one device that cannot be
    // queued must not abort the wave loop for the other nineteen. The reason
    // is on the target row, where an operator reads it, and in the log above.
  }
}

// ============================================================================
// Advancing — one tick over one rollout
// ============================================================================

/** What a tick did, so the caller (and the test) can assert on it. */
export interface AdvanceReport {
  rolloutId: number;
  status: RolloutStatus;
  waveIndex: number | null;
  action:
    | 'waiting_jobs'
    | 'settling'
    | 'gate_passed'
    | 'gate_failed'
    | 'gate_indeterminate'
    | 'wave_started'
    | 'finished'
    | 'rollback_pending'
    | 'rolled_back'
    | 'idle';
  gate: WaveGateResult | null;
  message: string;
}

const JOB_TERMINAL = ['succeeded', 'rolled_back', 'failed', 'aborted'];

/**
 * Advance one rollout by at most one step.
 *
 * Deliberately NOT a loop: every step of a rollout is a decision an operator
 * may want to interrupt, and a function that runs a whole rollout to
 * completion in one call is a function that cannot be paused.
 */
export async function advanceRollout(
  tenantId: number,
  rolloutId: number,
): Promise<AdvanceReport> {
  const rollout = await getRollout(tenantId, rolloutId);
  if (!rollout) throw new RolloutRefusedError('not_found', `Rollout ${rolloutId} not found`);

  if (rollout.status === 'rolling_back') return advanceRollback(rollout);
  if (rollout.status !== 'running') {
    return {
      rolloutId,
      status: rollout.status,
      waveIndex: rollout.current_wave_index,
      action: 'idle',
      gate: null,
      message: `Rollout is '${rollout.status}'; nothing to advance.`,
    };
  }

  const waveIndex = rollout.current_wave_index ?? 0;
  const targets = await listTargets(rolloutId, waveIndex);
  const wave = (await db('rollout_waves')
    .where({ rollout_id: rolloutId, wave_index: waveIndex })
    .first('*')) as WaveRow | undefined;
  if (!wave) {
    throw new RolloutRefusedError('no_wave', `Rollout ${rolloutId} has no wave ${waveIndex}`);
  }

  // ── 1. Reconcile every target with its job ───────────────────────────────
  const jobIds = targets.map((t) => t.job_id).filter((v): v is number => v !== null);
  const jobs = jobIds.length
    ? ((await db('change_jobs')
        .whereIn('id', jobIds)
        .select('id', 'status', 'outcome')) as Array<{
        id: number;
        status: string;
        outcome: string | null;
      }>)
    : [];
  const jobById = new Map(jobs.map((j) => [Number(j.id), j]));

  let stillRunning = 0;
  for (const t of targets) {
    if (t.status === 'failed' || t.status === 'succeeded' || t.status === 'rolled_back') continue;
    if (t.job_id === null) continue;
    const job = jobById.get(Number(t.job_id));
    if (!job) continue;
    if (!JOB_TERMINAL.includes(job.status)) {
      stillRunning++;
      if (t.status !== 'running') {
        await db('rollout_targets').where({ id: t.id }).update({
          status: 'running',
          updated_at: db.fn.now(),
        });
      }
      continue;
    }
    const next: RolloutTargetStatus =
      job.status === 'succeeded' ? 'succeeded'
        : job.status === 'rolled_back' ? 'rolled_back'
          : 'failed';
    await db('rollout_targets').where({ id: t.id }).update({
      status: next,
      updated_at: db.fn.now(),
    });
    t.status = next;
  }

  if (stillRunning > 0) {
    return {
      rolloutId,
      status: rollout.status,
      waveIndex,
      action: 'waiting_jobs',
      gate: null,
      message: `${stillRunning} job(s) still in flight in wave ${waveIndex + 1}.`,
    };
  }

  // ── 2. Every job is terminal: open the settle window ─────────────────────
  const succeeded = targets.filter((t) => t.status === 'succeeded').length;
  const failed = targets.filter((t) => t.status === 'failed' || t.status === 'rolled_back').length;
  await db('rollout_waves').where({ id: wave.id }).update({
    succeeded_count: succeeded,
    failed_count: failed,
    updated_at: db.fn.now(),
  });

  let gateStartedAt = wave.gate_started_at;
  if (!gateStartedAt) {
    gateStartedAt = new Date();
    await db('rollout_waves').where({ id: wave.id }).update({
      status: 'gating',
      gate_started_at: gateStartedAt,
      updated_at: db.fn.now(),
    });
    wave.status = 'gating';
    wave.gate_started_at = gateStartedAt;
    emitWave(rollout, wave);
  }

  const settled = Date.now() - new Date(gateStartedAt).getTime();
  if (settled < Number(rollout.gate_settle_ms) && settled < GATE_TIMEOUT_MS) {
    return {
      rolloutId,
      status: rollout.status,
      waveIndex,
      action: 'settling',
      gate: null,
      message:
        `Wave ${waveIndex + 1} is settling: ${Math.round(settled / 1000)}s of ` +
        `${Math.round(Number(rollout.gate_settle_ms) / 1000)}s. The gate measures AFTER the ` +
        'poller has had a chance to write a fresh sample — measuring immediately would compare ' +
        'the device to nothing.',
    };
  }

  // ── 3. THE GATE ──────────────────────────────────────────────────────────
  const gateTargets: GateTarget[] = targets.map((t) => ({
    deviceId: Number(t.device_id),
    deviceName: t.device_name ?? `#${t.device_id}`,
    jobId: t.job_id === null ? null : Number(t.job_id),
    baseline: (t.health_baseline as HealthBaseline | null) ?? null,
  }));
  const gate = await evaluateWave(tenantId, waveIndex, gateTargets);

  const now = new Date();
  for (const d of gate.devices) {
    await db('rollout_targets')
      .where({ rollout_id: rolloutId, device_id: d.deviceId })
      .update({
        health_verdict: d.verdict,
        health_reasons: JSON.stringify(d.reasons),
        health_checked_at: now,
        updated_at: db.fn.now(),
      });
  }
  const waveReasons: HealthGateReason[] = gate.devices.flatMap((d) =>
    d.verdict === 'PASS' ? [] : d.reasons.map((r) => ({ ...r, message: `${d.deviceName}: ${r.message}` })),
  );
  await db('rollout_waves').where({ id: wave.id }).update({
    gate_verdict: gate.verdict,
    gate_reasons: JSON.stringify(waveReasons),
    updated_at: db.fn.now(),
  });
  wave.gate_verdict = gate.verdict;
  wave.gate_reasons = waveReasons;

  if (gate.verdict === 'FAIL') {
    await db('rollout_waves').where({ id: wave.id }).update({
      status: 'failed',
      finished_at: now,
      updated_at: db.fn.now(),
    });
    wave.status = 'failed';
    emitWave(rollout, wave);
    const report = await failAndRollBack(rollout, waveIndex, gate);
    return report;
  }

  if (gate.verdict === 'INDETERMINATE') {
    // The train stops; nothing is undone. A rollback triggered by ignorance
    // would annul good changes every time an SNMP target is missing, and a net
    // that fires on ignorance is a net people switch off.
    const paused = await setStatus(rollout, 'paused', {
      pause_reason:
        `Wave ${waveIndex + 1}'s health gate could not conclude on ` +
        `${gate.indeterminateDeviceIds.length} device(s). Nothing has been rolled back: an ` +
        'INDETERMINATE gate has not proved harm, it has proved it cannot see. Look, then resume ' +
        'or abort.',
    });
    emitProgress(paused, `wave ${waveIndex + 1} gate INDETERMINATE — paused`);
    emitWave(paused, wave);
    return {
      rolloutId,
      status: 'paused',
      waveIndex,
      action: 'gate_indeterminate',
      gate,
      message: paused.pause_reason ?? '',
    };
  }

  // ── 4. PASS: next wave, or the end ───────────────────────────────────────
  await db('rollout_waves').where({ id: wave.id }).update({
    status: 'passed',
    finished_at: now,
    updated_at: db.fn.now(),
  });
  wave.status = 'passed';
  emitWave(rollout, wave);

  await db('rollouts').where({ id: rolloutId }).update({
    succeeded_count: await countTargets(rolloutId, ['succeeded']),
    failed_count: await countTargets(rolloutId, ['failed']),
    updated_at: db.fn.now(),
  });

  const nextIndex = waveIndex + 1;
  if (nextIndex < Number(rollout.wave_count)) {
    const advanced = await setStatus(rollout, 'running', { current_wave_index: nextIndex });
    await startWave(advanced, nextIndex);
    emitProgress(advanced, `wave ${nextIndex + 1}/${advanced.wave_count} starting`);
    return {
      rolloutId,
      status: 'running',
      waveIndex: nextIndex,
      action: 'wave_started',
      gate,
      message: `Wave ${waveIndex + 1} passed its health gate; wave ${nextIndex + 1} started.`,
    };
  }

  const done = await setStatus(rollout, 'succeeded', { current_wave_index: null });
  emitProgress(done, 'every wave passed its health gate');
  emitFinished(done, false);
  return {
    rolloutId,
    status: 'succeeded',
    waveIndex,
    action: 'finished',
    gate,
    message: `All ${done.wave_count} wave(s) passed. ${done.succeeded_count} device(s) changed.`,
  };
}

async function countTargets(rolloutId: number, statuses: string[]): Promise<number> {
  const row = (await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .whereIn('status', statuses)
    .count<{ c: string }>({ c: '*' })
    .first()) as { c: string } | undefined;
  return Number(row?.c ?? 0);
}

// ============================================================================
// The failure path — quarantine, then undo the waves that already landed
// ============================================================================

/**
 * A gate said FAIL.
 *
 * Three things happen, in this order, and the order matters:
 *
 *  1. THE REVISION IS QUARANTINED FIRST. Between the decision and the last
 *     restore job there is a window of minutes; a revision left `published`
 *     during it can be assigned to a new device or picked up by another
 *     rollout. `template_revisions.status` already accepts `quarantined` and
 *     its freeze trigger (migration 008) already allows exactly this flip.
 *  2. Waves that never ran are marked `skipped` and their devices released.
 *  3. Every device that ACTUALLY took the change — this wave included — gets a
 *     `restore` job, queued through `change_jobs` like everything else (D3).
 *     A device that already rolled itself back (its on-box dead-man fired) is
 *     NOT restored again: it is already on its pre-change config, and pushing
 *     a backup onto it would be a second write nobody asked for.
 */
async function failAndRollBack(
  rollout: RolloutRow,
  failedWaveIndex: number,
  gate: WaveGateResult,
): Promise<AdvanceReport> {
  const rolloutId = Number(rollout.id);
  const tenantId = Number(rollout.tenant_id);

  logger.error(
    {
      rolloutId,
      waveIndex: failedWaveIndex,
      failedDeviceIds: gate.failedDeviceIds,
      revisionId: Number(rollout.template_revision_id),
    },
    'ROLLOUT GATE FAILED — quarantining the revision and rolling the previous waves back',
  );

  // ── 1. Quarantine ────────────────────────────────────────────────────────
  const quarantinedAt = new Date();
  const flipped = await db('template_revisions')
    .where({ id: rollout.template_revision_id, status: 'published' })
    .update({ status: 'quarantined', updated_at: db.fn.now() });

  // The status moves to `rolling_back` IN THE SAME UPDATE as
  // `failed_wave_index`: `rollouts_failed_wave_chk` refuses a rollout that
  // names a failed wave while still claiming to be running, which is exactly
  // the half-written state a two-statement version would pass through.
  const rolling = await setStatus(rollout, 'rolling_back', {
    failed_wave_index: failedWaveIndex,
    revision_quarantined_at: flipped > 0 ? quarantinedAt : rollout.revision_quarantined_at,
    current_wave_index: failedWaveIndex,
  });

  // ── 2. Waves that never ran ──────────────────────────────────────────────
  await db('rollout_waves')
    .where({ rollout_id: rolloutId })
    .where('wave_index', '>', failedWaveIndex)
    .update({ status: 'skipped', finished_at: quarantinedAt, updated_at: db.fn.now() });
  await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .where('wave_index', '>', failedWaveIndex)
    .whereIn('status', ['pending', 'queued'])
    .update({
      status: 'skipped',
      note: `Never ran: wave ${failedWaveIndex + 1} failed its health gate.`,
      updated_at: db.fn.now(),
    });

  // ── 3. The undo ──────────────────────────────────────────────────────────
  const landed = (await db('rollout_targets as t')
    .join('devices as d', 'd.id', 't.device_id')
    .where('t.rollout_id', rolloutId)
    .where('t.wave_index', '<=', failedWaveIndex)
    .where('t.status', 'succeeded')
    .orderBy(['t.wave_index', 't.order_rank'])
    .select('t.*', 'd.name as device_name')) as TargetRow[];

  let queued = 0;
  for (const t of landed) {
    const backup = (await db('device_backups')
      .where({ taken_before_job_id: t.job_id, kind: 'binary' })
      .first('id')) as { id: string | number } | undefined;

    try {
      const result = await enqueueChangeJob({
        tenantId,
        deviceId: Number(t.device_id),
        kind: 'restore',
        // The rollback is attributed to the operator who LAUNCHED the rollout.
        // Migration 009 makes a non-ACCEPT verdict impossible without a named
        // human, and a machine-decided rollback still has to name one: he
        // signed for the machinery, including the half that undoes his change.
        requestedBy: rollout.started_by,
        override: {
          reason:
            `Automatic rollback of rollout #${rolloutId} (${rollout.name}): the health gate of ` +
            `wave ${failedWaveIndex + 1} returned FAIL on device(s) ` +
            `${gate.failedDeviceIds.join(', ')}. Restoring the pre-change configuration taken ` +
            `before job #${t.job_id}.`,
          userId: rollout.started_by,
        },
        confirmDegraded:
          t.safety_level === 'degraded' ? { userId: rollout.degraded_confirmed_by } : null,
      });

      await db('change_jobs').where({ id: result.jobId }).update({
        rollout_id: rolloutId,
        wave_index: t.wave_index,
        canary_rank: t.order_rank,
        updated_at: db.fn.now(),
      });
      await db('rollout_targets').where({ id: t.id }).update({
        rollback_job_id: result.jobId,
        rollback_backup_id: backup ? Number(backup.id) : null,
        note: backup
          ? null
          : 'No binary preflight backup was found for this device: the restore job was queued ' +
            'but has nothing recorded to load. Inspect before letting it run.',
        updated_at: db.fn.now(),
      });
      queued++;
    } catch (err) {
      logger.error(
        { rolloutId, deviceId: Number(t.device_id), err },
        'rollout: could not queue the rollback job for a device that took the change',
      );
      await db('rollout_targets').where({ id: t.id }).update({
        note: `Rollback could not be queued: ${
          err instanceof Error ? err.message : String(err)
        }`.slice(0, 2000),
        updated_at: db.fn.now(),
      });
    }
  }

  emitProgress(
    rolling,
    `wave ${failedWaveIndex + 1} FAILED its health gate — rolling ${queued} device(s) back`,
  );

  return {
    rolloutId,
    status: 'rolling_back',
    waveIndex: failedWaveIndex,
    action: 'gate_failed',
    gate,
    message:
      `Wave ${failedWaveIndex + 1} failed its health gate on ${gate.failedDeviceIds.length} ` +
      `device(s). Revision #${rollout.template_revision_id} ${
        flipped > 0 ? 'has been quarantined' : 'was already not published'
      }; ${queued} restore job(s) queued for the devices that had taken the change.`,
  };
}

/** Watch the restore jobs to their end. */
async function advanceRollback(rollout: RolloutRow): Promise<AdvanceReport> {
  const rolloutId = Number(rollout.id);
  const targets = (await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .whereNotNull('rollback_job_id')
    .select('*')) as TargetRow[];

  const jobIds = targets.map((t) => Number(t.rollback_job_id));
  const jobs = jobIds.length
    ? ((await db('change_jobs').whereIn('id', jobIds).select('id', 'status')) as Array<{
        id: number;
        status: string;
      }>)
    : [];
  const jobById = new Map(jobs.map((j) => [Number(j.id), j.status]));

  let pending = 0;
  let restored = 0;
  let stuck = 0;
  for (const t of targets) {
    const status = jobById.get(Number(t.rollback_job_id));
    if (!status || !JOB_TERMINAL.includes(status)) {
      pending++;
      continue;
    }
    if (status === 'succeeded' || status === 'rolled_back') {
      restored++;
      if (t.status !== 'rolled_back') {
        await db('rollout_targets').where({ id: t.id }).update({
          status: 'rolled_back',
          updated_at: db.fn.now(),
        });
      }
    } else {
      stuck++;
      if (t.status !== 'failed') {
        await db('rollout_targets').where({ id: t.id }).update({
          status: 'failed',
          note: `The rollback job ended '${status}'. This device is NOT back on its pre-change ` +
            'configuration and needs a human.',
          updated_at: db.fn.now(),
        });
      }
    }
  }

  if (pending > 0) {
    return {
      rolloutId,
      status: 'rolling_back',
      waveIndex: rollout.current_wave_index,
      action: 'rollback_pending',
      gate: null,
      message: `${pending} restore job(s) still in flight.`,
    };
  }

  await db('rollout_waves')
    .where({ rollout_id: rolloutId })
    .whereIn('status', ['passed', 'failed'])
    .update({ status: 'rolled_back', updated_at: db.fn.now() });

  const finalStatus: RolloutStatus = stuck > 0 ? 'failed' : 'rolled_back';
  const done = await setStatus(rollout, finalStatus, {
    rolled_back_count: restored,
    failed_count: await countTargets(rolloutId, ['failed']),
    succeeded_count: await countTargets(rolloutId, ['succeeded']),
    current_wave_index: null,
  });
  emitProgress(
    done,
    stuck > 0
      ? `${stuck} device(s) could NOT be restored — this rollout needs a human`
      : `${restored} device(s) restored to their pre-change configuration`,
  );
  emitFinished(done, done.revision_quarantined_at !== null);

  return {
    rolloutId,
    status: finalStatus,
    waveIndex: null,
    action: 'rolled_back',
    gate: null,
    message:
      stuck > 0
        ? `${restored} device(s) restored, ${stuck} could NOT be. A rolled-back rollout with a ` +
          'device left changed is not a rolled-back rollout, so this one is marked failed.'
        : `${restored} device(s) restored to their pre-change configuration.`,
  };
}

// ============================================================================
// Operator gestures
// ============================================================================

export async function pauseRollout(
  tenantId: number,
  rolloutId: number,
  reason: string | null,
): Promise<RolloutRow> {
  const rollout = await getRollout(tenantId, rolloutId);
  if (!rollout) throw new RolloutRefusedError('not_found', `Rollout ${rolloutId} not found`);
  if (rollout.status !== 'running') {
    throw new RolloutRefusedError(
      'not_running',
      `Rollout ${rolloutId} is '${rollout.status}'; only a running rollout can be paused.`,
    );
  }
  const paused = await setStatus(rollout, 'paused', {
    pause_reason: reason ?? 'Paused by an operator.',
  });
  logger.warn({ rolloutId, tenantId }, 'rollout PAUSED');
  emitProgress(paused, 'paused by an operator');
  return paused;
}

/**
 * Resume a paused rollout.
 *
 * A pause never stops a job that is already in flight — the queue owns those,
 * and a button that claimed to stop a change already going onto a router would
 * lie at the exact moment somebody is desperate enough to press it twice
 * (`changes.controller`, `abort`).
 *
 * ┌─ TWO PAUSES, TWO RESUMES, AND CONFLATING THEM SKIPS A HEALTH GATE ────────┐
 * │ GATE PAUSE    `advanceRollout` measured the wave, the gate came back      │
 * │               INDETERMINATE, and the rollout stopped ON that verdict. The │
 * │               wave row is `gating` with `gate_verdict='INDETERMINATE'`.   │
 * │               Resuming is a human ACCEPTING a verdict that was never a    │
 * │               PASS: the wave is marked passed and the NEXT wave starts.   │
 * │                                                                          │
 * │ MANUAL PAUSE  an operator pressed pause, possibly while the wave's jobs   │
 * │               were still on the wire. The wave has NOT been measured.     │
 * │               Resuming means "carry on where you were": `running`, SAME   │
 * │               `current_wave_index`, and `advanceRollout` picks the wave   │
 * │               up at reconciliation and takes it through its gate.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Before this distinction existed, both resumes incremented
 * `current_wave_index`. Pause + resume during wave 1 therefore left wave 1
 * un-gated and pointed the rollout at a wave whose jobs had never been queued;
 * every target of it was `pending` with `job_id IS NULL`, the reconciliation
 * loop skipped them all, `stillRunning` was 0, and the settle window opened on
 * a wave that had done nothing. Repeating it walked the rollout to
 * `succeeded` with one device of forty touched. `1 -> 5% -> 25% -> rest, with a
 * MEASURED gate between each step` is M7's whole promise; two legitimate HTTP
 * calls must not be able to step over it.
 */
export async function resumeRollout(
  tenantId: number,
  rolloutId: number,
  userId: number | null,
): Promise<RolloutRow> {
  const rollout = await getRollout(tenantId, rolloutId);
  if (!rollout) throw new RolloutRefusedError('not_found', `Rollout ${rolloutId} not found`);
  if (rollout.status !== 'paused') {
    throw new RolloutRefusedError(
      'not_paused',
      `Rollout ${rolloutId} is '${rollout.status}'; only a paused rollout can be resumed.`,
    );
  }
  const killSwitch = await readKillSwitch(tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);

  const waveIndex = rollout.current_wave_index ?? 0;
  const wave = (await db('rollout_waves')
    .where({ rollout_id: rolloutId, wave_index: waveIndex })
    .first('*')) as WaveRow | undefined;

  // ── MANUAL PAUSE ─────────────────────────────────────────────────────────
  // The current wave has not produced a verdict, so there is nothing to accept
  // and nothing to step over. Put the rollout back to `running` on the SAME
  // wave and let the tick loop do its job.
  if (!wave || wave.status !== 'gating' || wave.gate_verdict !== 'INDETERMINATE') {
    const resumed = await setStatus(rollout, 'running', {
      pause_reason: null,
      started_by: rollout.started_by ?? userId,
    });
    logger.warn(
      { rolloutId, tenantId, userId, waveIndex, waveStatus: wave?.status ?? null },
      'rollout RESUMED on the same wave — the wave has not been gated yet',
    );
    emitProgress(
      resumed,
      `resumed — wave ${waveIndex + 1}/${resumed.wave_count} continues, its health gate ` +
        'has not run yet',
    );
    return resumed;
  }

  // ── GATE PAUSE ───────────────────────────────────────────────────────────
  // A rollout paused on an INDETERMINATE gate is resumed by a human who has
  // LOOKED. Recording the gate verdict as accepted is what makes the resume an
  // act rather than a retry: the wave moves on with a verdict that was never
  // a PASS, and the trace must say so.
  await db('rollout_waves')
    .where({ rollout_id: rolloutId, wave_index: waveIndex, status: 'gating' })
    .update({ status: 'passed', finished_at: new Date(), updated_at: db.fn.now() });

  const nextIndex = waveIndex + 1;
  if (nextIndex >= Number(rollout.wave_count)) {
    const done = await setStatus(rollout, 'succeeded', {
      current_wave_index: null,
      pause_reason: null,
      succeeded_count: await countTargets(rolloutId, ['succeeded']),
    });
    emitProgress(done, 'resumed on the last wave — finished');
    emitFinished(done, false);
    return done;
  }

  const resumed = await setStatus(rollout, 'running', {
    current_wave_index: nextIndex,
    pause_reason: null,
    started_by: rollout.started_by ?? userId,
  });
  logger.warn(
    { rolloutId, tenantId, userId, waveIndex: nextIndex },
    'rollout RESUMED past a gate that did not PASS — a human accepted an INDETERMINATE verdict',
  );
  await startWave(resumed, nextIndex);
  emitProgress(resumed, `resumed — wave ${nextIndex + 1}/${resumed.wave_count} starting`);
  return resumed;
}

export async function abortRollout(
  tenantId: number,
  rolloutId: number,
  userId: number | null,
  reason: string | null,
): Promise<RolloutRow> {
  const rollout = await getRollout(tenantId, rolloutId);
  if (!rollout) throw new RolloutRefusedError('not_found', `Rollout ${rolloutId} not found`);
  if (isTerminalRolloutStatus(rollout.status)) {
    throw new RolloutRefusedError(
      'already_finished',
      `Rollout ${rolloutId} is already '${rollout.status}'.`,
    );
  }

  // Jobs that have not been claimed yet CAN be cancelled; anything past
  // `applying` cannot, and `abortJob` refuses it. We ask, and we record what
  // it answered — we never pretend a running apply was stopped.
  const targets = await listTargets(rolloutId);
  let cancelledJobs = 0;
  for (const t of targets) {
    if (t.job_id === null) continue;
    try {
      await abortJob(tenantId, Number(t.job_id), userId, reason ?? 'rollout aborted');
      cancelledJobs++;
    } catch {
      // Past the write frontier. The dead-man owns it now, not this button.
    }
  }
  await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .whereIn('status', ['pending', 'queued', 'running'])
    .update({ status: 'cancelled', updated_at: db.fn.now() });
  await db('rollout_waves')
    .where({ rollout_id: rolloutId })
    .whereIn('status', ['pending', 'running', 'gating'])
    .update({ status: 'skipped', finished_at: new Date(), updated_at: db.fn.now() });

  const aborted = await setStatus(rollout, 'aborted', {
    abort_reason:
      (reason ?? 'Aborted by an operator.') +
      ` ${cancelledJobs} queued job(s) were cancelled. Devices already changed were NOT rolled ` +
      'back by this gesture — use the per-device restore, or the kill switch to stop the fleet.',
    current_wave_index: null,
  });
  logger.warn({ rolloutId, tenantId, userId, cancelledJobs }, 'rollout ABORTED');
  emitProgress(aborted, 'aborted by an operator');
  emitFinished(aborted, aborted.revision_quarantined_at !== null);
  return aborted;
}

// ============================================================================
// Socket progress — keyed by rolloutId
// ============================================================================
//
// Emitted to the TENANT room, with `rolloutId` in every payload.
// `socketRooms.rollout(id)` exists in the shared contract and
// `CLIENT_EVENTS.ROLLOUT_SUBSCRIBE` is declared, but nothing joins that room
// yet: the handler lives in `socket.ts`, which this milestone may not touch.
// Emitting into an empty room instead of the tenant room would have looked
// tidier and delivered nothing to anybody.
//
// LEAD: three lines in `socket.ts` (mirror the DEVICE_SUBSCRIBE block, check
// the rollout's tenant, then `socket.join(socketRooms.rollout(id))`) plus an
// `emitToRollout` in `fleet/fleetEvents.ts` complete this.

function emitProgress(r: RolloutRow, message: string): void {
  emitToTenant(Number(r.tenant_id), SOCKET_EVENTS.ROLLOUT_PROGRESS, {
    rolloutId: Number(r.id),
    tenantId: Number(r.tenant_id),
    status: r.status,
    currentWaveIndex: r.current_wave_index === null ? null : Number(r.current_wave_index),
    waveCount: Number(r.wave_count),
    deviceCount: Number(r.device_count),
    succeededCount: Number(r.succeeded_count),
    failedCount: Number(r.failed_count),
    rolledBackCount: Number(r.rolled_back_count),
    message,
  });
}

function emitWave(r: RolloutRow, w: WaveRow): void {
  emitToTenant(Number(r.tenant_id), SOCKET_EVENTS.ROLLOUT_WAVE_CHANGED, {
    rolloutId: Number(r.id),
    tenantId: Number(r.tenant_id),
    waveIndex: Number(w.wave_index),
    label: w.label,
    status: w.status,
    targetCount: Number(w.target_count),
    gateVerdict: w.gate_verdict,
    gateReasons: asArray<HealthGateReason>(w.gate_reasons),
  });
}

function emitFinished(r: RolloutRow, revisionQuarantined: boolean): void {
  emitToTenant(Number(r.tenant_id), SOCKET_EVENTS.ROLLOUT_FINISHED, {
    rolloutId: Number(r.id),
    tenantId: Number(r.tenant_id),
    status: r.status,
    deviceCount: Number(r.device_count),
    succeededCount: Number(r.succeeded_count),
    rolledBackCount: Number(r.rolled_back_count),
    failedWaveIndex: r.failed_wave_index === null ? null : Number(r.failed_wave_index),
    revisionQuarantined,
    message: r.abort_reason ?? r.pause_reason ?? `Rollout ${r.status}.`,
  });
}

// ============================================================================
// The runtime — leader-gated, exactly like every other poller (A5)
// ============================================================================

/** How often the driver looks at the rollouts that still have work to do. */
export const ROLLOUT_TICK_MS = Number(process.env.OBLIWAN_ROLLOUT_TICK_MS) || 10_000;

let timer: NodeJS.Timeout | null = null;
let ticking = false;

/**
 * One pass over every rollout of every tenant that is not finished.
 *
 * `leaderElection.isLeader()` gates it (arbitrage A5): two replicas advancing
 * the same rollout would start the same wave twice, and the second start would
 * queue a second job against a device the first one already holds — which
 * `change_jobs_one_in_flight_uq` would refuse, loudly, on a fleet, at night.
 * Exported without the gate as well (`advanceRollout`) so a controller and a
 * test can step one rollout deliberately.
 */
export async function tickRollouts(): Promise<AdvanceReport[]> {
  if (!leaderElection.isLeader()) return [];
  const active = (await db('rollouts')
    .whereIn('status', ['running', 'rolling_back'])
    .select('id', 'tenant_id')) as Array<{ id: number; tenant_id: number }>;

  const reports: AdvanceReport[] = [];
  for (const r of active) {
    try {
      reports.push(await advanceRollout(Number(r.tenant_id), Number(r.id)));
    } catch (err) {
      logger.error({ err, rolloutId: Number(r.id) }, 'rollout tick failed');
    }
  }
  return reports;
}

/**
 * Arm the driver. LEAD: call this from `index.ts` next to
 * `startChangeWorker(runJob)` — without it every rollout stops after its first
 * wave's jobs finish, which is the M3 lesson (a subsystem that compiles, whose
 * tables exist, whose routes answer, and that nothing ever runs).
 */
export function startRolloutRuntime(): void {
  if (timer) return;
  timer = setInterval(() => {
    if (ticking) return;
    ticking = true;
    tickRollouts()
      .catch((err) => logger.error({ err }, 'rollout runtime tick failed'))
      .finally(() => {
        ticking = false;
      });
  }, ROLLOUT_TICK_MS);
  timer.unref();
  logger.info({ intervalMs: ROLLOUT_TICK_MS }, 'rollout runtime armed (leader-gated)');
}

export async function stopRolloutRuntime(): Promise<void> {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  // Let an in-flight tick finish: it may be halfway through queueing a wave,
  // and a wave half queued is a set of devices nobody is watching.
  for (let i = 0; ticking && i < 100; i++) {
    await new Promise((r) => setTimeout(r, 50));
  }
}

export const rolloutService = {
  previewRollout,
  composeRollout,
  listRollouts,
  getRollout,
  listWaves,
  listTargets,
  launchRollout,
  advanceRollout,
  pauseRollout,
  resumeRollout,
  abortRollout,
  tickRollouts,
  startRolloutRuntime,
  stopRolloutRuntime,
  toRolloutSummary,
  safetyNetLevelOf,
};
