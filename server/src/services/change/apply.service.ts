// ============================================================================
// ObliWAN — the safe write, orchestrated (M6, decision D3 / R1 / R4 / §8.2-8.3)
// ============================================================================
//
// This file is the ONLY thing in the product that decides a device may be
// written to. It does not itself send a single byte: the transport work belongs
// to `safeApply` / `backup` (K1, another workstream) and is reached through the
// `ChangeExecutor` contract at the bottom of this file. What lives here is the
// sequence of refusals that must all be passed first, and the trace they leave.
//
// ┌─ THE ORDER IS THE SPECIFICATION ──────────────────────────────────────────┐
// │  0. kill switch                 — read, fail-closed                       │
// │  1. bind_assert (R4)            — a NEW socket, identity re-proved         │
// │  2. plan freshness (M5)         — `base_state_hash` still matches         │
// │  3. Management-Path Guard (K2)  — re-run, on the state as it is NOW       │
// │  4. safety net (§8.3)           — ARMED / ARMED_BY_PEER / DEGRADED        │
// │  5. preflight backup (R1)       — a CHECK constraint, not a habit         │
// │  6. arm the dead-man            — the router repairs itself without us    │
// │  7. KILL SWITCH AGAIN           — the last statement before the write     │
// │  8. apply                       — the only line that changes a router     │
// │  9. reconnect + verify          — on a NEW socket, never the one that      │
// │                                   carried the change                      │
// │ 10. soak                        — live, watched, dead-man still armed     │
// │ 11. disarm                      — a job is not `succeeded` while a router │
// │                                   still carries a scheduler that reverts  │
// │ 12. apply_outcomes (§8.3)       — success AND failure. The corpus.        │
// └───────────────────────────────────────────────────────────────────────────┘
//
// STEPS 3 AND 7 ARE RE-DONE ON PURPOSE. The guard ran at enqueue time, possibly
// hours ago and certainly before an approval; the kill switch was read when the
// job was created, which is precisely NOT when somebody engages it. A check
// performed once, early, is a check that answers a question nobody is asking
// any more.
//
// WHY A NON-ACCEPT VERDICT NEEDS A SIGNATURE AND NOT A FLAG: `INDETERMINATE` is
// not `ACCEPT`. Both non-accept verdicts demand `override_reason` +
// `overridden_by` + `overridden_at`, and that demand is a CHECK constraint in
// migration 009 — so the destructive acceptance test of M6 CAN force a
// `chain=input drop` past the guard, but not without naming a human in the
// database. That row is the line somebody reads after the incident.
//
// SECRETS (§8.2): nothing in this file ever sees a complete rendered config.
// `change_plans.ops` is the redacted plan; the full version exists in memory
// only, inside the executor, on the vault -> equipment path. Every string that
// reaches `change_job_steps` or `command_audit` from here is already masked.

import crypto from 'crypto';
import type { Knex } from 'knex';
import {
  ApplyPlan,
  SOCKET_EVENTS,
  guardAllowsApply,
  isWriteJobKind,
  mgmtPathVerdictOf,
  type ChangeJobKind,
  type GuardVerdict,
  type SafetyLevel,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { emitToDevice, emitToTenant } from '../fleet/fleetEvents';
import { assertTargetBinding, BindingAssertionError } from '../fleet/deviceBinding.service';
import { latestDocument } from '../config/snapshot.service';
import {
  assertPlanFresh,
  checkPlanFreshness,
  PlanExpiredError,
  StalePlanError,
} from '../plan/planner.service';
import { buildMgmtPathFacts } from '../plan/riskScoring';
import { guardPlan, type MgmtGuardResult } from '../plan/mgmtPathGuard';
import { assertWritable, KillSwitchEngagedError, readKillSwitch } from './killSwitch.service';
import {
  DeviceBusyError,
  LeaseLostError,
  WORKER_ID,
  assertLease,
  finishStep,
  getJobRow,
  skipStep,
  startStep,
  transitionJob,
  type ChangeJobRow,
  type StepHandle,
} from './jobQueue.service';
import { auditedCommand, recordCommandIntent } from '../audit.service';

// ============================================================================
// Constants
// ============================================================================

/**
 * How long a change is watched, live, before the dead-man is removed.
 *
 * The dead-man is ARMED throughout the soak. That is the whole value of it: if
 * the change is going to cut the tunnel, it cuts it now, and the router puts
 * itself back without anybody dialling in.
 */
export const SOAK_MS = Number(process.env.OBLIWAN_SOAK_MS ?? 5 * 60 * 1000);

/**
 * RECONNECTING AFTER A WRITE IS NOT A SINGLE ATTEMPT, AND THE FIRST FAILURE IS
 * NOT AN ANSWER.
 *
 * The write that just landed is, very often, precisely the write that makes the
 * box stop answering for a moment: touching `/ip/service` or an `input` chain
 * rule makes RouterOS close and re-open its API listener, typically for one to
 * three seconds, longer on a loaded router. Dialling immediately and failing
 * the job on the first `ECONNREFUSED` produced the worst outcome this milestone
 * has: a change that WORKED recorded as `failed`, the dead-man left armed
 * because `failJob` concluded, and the router quietly undoing a good change ten
 * minutes later — with nobody having decided that.
 *
 * These mirror `SAFE_APPLY_DEFAULTS.reconnect*` in `safeApply.service.ts`,
 * which `changeExecutor.verify()` already honours at the `postcheck` step.
 * They are duplicated rather than imported because K1's module is resolved
 * DYNAMICALLY (see `resolveExecutor`) and a static import here would make the
 * whole server fail to compile over a file this layer deliberately does not
 * depend on. The numbers are timings, not a rule: if they drift apart, the
 * worst case is one step waiting longer than the other, and
 * `assertTimingsCoherent` still holds the dead-man window against the sum.
 */
export const RECONNECT_DELAY_MS = Number(process.env.OBLIWAN_RECONNECT_DELAY_MS ?? 5_000);
export const RECONNECT_ATTEMPTS = Math.max(
  1,
  Number(process.env.OBLIWAN_RECONNECT_ATTEMPTS ?? 6),
);
export const RECONNECT_INTERVAL_MS = Number(process.env.OBLIWAN_RECONNECT_INTERVAL_MS ?? 10_000);

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, Math.max(0, ms)));
}

/** `change_jobs.base_state_hash` is NOT NULL with a hex-64 CHECK, and a backup
 *  job has no plan to take a hash from. A device with no snapshot at all gets
 *  this sentinel, which is a legal hash and matches nothing. */
const NO_BASE_STATE = '0'.repeat(64);

/** Verdict severity, for "did the world get worse since the human signed?". */
const VERDICT_RANK: Record<GuardVerdict, number> = { ACCEPT: 0, INDETERMINATE: 1, REJECT: 2 };

/**
 * The same question, for callers that hold a verdict signed somewhere else and
 * a verdict measured now — `rollout.service` asks it about the verdict frozen
 * on `rollout_targets` at composition versus the one the enqueue just produced.
 *
 * Exported rather than duplicated: two rank tables that agree today are two
 * rank tables, and the one nobody edits is the one that decides whether a
 * REJECT gets pushed.
 */
export function guardVerdictWorsened(signed: GuardVerdict, fresh: GuardVerdict): boolean {
  return VERDICT_RANK[fresh] > VERDICT_RANK[signed];
}

// ============================================================================
// Errors
// ============================================================================

export class ChangeRefusedError extends Error {
  constructor(readonly kind: string, message: string) {
    super(message);
    this.name = 'ChangeRefusedError';
  }
}

// ============================================================================
// The executor contract — K1's module, reached by name and never by guesswork
// ============================================================================

export interface ExecContext {
  job: ChangeJobRow;
  device: DeviceRecord;
  /** The frozen plan's ops, REDACTED (§8.2). Empty for non-push kinds. */
  ops: unknown[];
  /** `change_plans.id` the job is applying, when there is one. */
  planId: number | null;
  /** Ties every command of this job together in `command_audit`. */
  correlationId: string;
  /** The safety net the operator was shown and confirmed. */
  safetyLevel: SafetyLevel;
  safetyPeerDeviceId: number | null;
  /** `device_backups.id` taken before the change. Null before step 5. */
  preflightBackupId: number | null;
  /** The on-box handle of the dead-man, once armed. */
  deadmanHandle: string | null;
}

/**
 * What `safeApply` / `backup` must provide.
 *
 * IT IS RESOLVED AT RUNTIME, and its absence is a REFUSAL, not a degradation:
 * a queue whose executor is missing fails its jobs at `backing_up`, before any
 * socket is opened. That is deliberate — the alternative (a stub that "does
 * nothing successfully") is a queue that reports green while a fleet drifts.
 */
export interface ChangeExecutor {
  /** R1. Both `binary` and `rsc` where the driver can; returns the row that
   *  `change_jobs.preflight_backup_id` will point at. */
  takePreflightBackup(ctx: ExecContext): Promise<{ backupId: number }>;
  /** §8.3. Installs the on-box dead-man (`/system/scheduler start-time=startup`
   *  + the restore script), or the peer-carried one. MUST return the level it
   *  ACTUALLY obtained, which may be worse than the one planned. */
  armDeadman(
    ctx: ExecContext,
  ): Promise<{ handle: string; level: SafetyLevel; confirmDeadline: Date; peerDeviceId?: number | null }>;
  /** THE WRITE. `:do{}on-error={rollback}`, never `/import` (arbitrated
   *  rejection: `/import` stops at the first error and leaves the router half
   *  configured with no handler). */
  applyChange(ctx: ExecContext): Promise<{ appliedOps: number; outputRedacted?: string | null }>;
  /** Reconnect on a NEW socket, re-assert the binding, check post-conditions. */
  verify(
    ctx: ExecContext,
  ): Promise<{ ok: boolean; detail?: Record<string, unknown>; errorRedacted?: string | null }>;
  /** Remove the dead-man, with retry. */
  disarmDeadman(ctx: ExecContext): Promise<void>;
  /** Did the device restore itself? Used to distinguish `rolled_back` from
   *  `lost_contact` in the empirical corpus, which are NOT the same night. */
  observeRollback?(ctx: ExecContext): Promise<boolean>;
  /** `export` / `backup` — the read-only kinds, in the queue so that "one
   *  operation at a time per device" is true rather than mostly true. */
  runReadOnly?(
    ctx: ExecContext,
  ): Promise<{ outputRedacted?: string | null; detail?: Record<string, unknown> }>;
}

let injectedExecutor: ChangeExecutor | null = null;
let resolvedExecutor: ChangeExecutor | null | undefined;

/**
 * Wire the executor explicitly.
 *
 *  - an object   : use it (a fake, in a test).
 *  - `null`      : forget the injection and go back to resolving `safeApply`.
 *  - `'none'`    : PIN the answer to "no executor installed". A test seam, and
 *                  the only way to exercise the refusal path once K1's module
 *                  actually exists on the build — which is the situation the
 *                  refusal is hardest to prove in and most important to keep.
 */
export function setChangeExecutor(executor: ChangeExecutor | null | 'none'): void {
  if (executor === 'none') {
    injectedExecutor = null;
    resolvedExecutor = null;
    return;
  }
  injectedExecutor = executor;
  resolvedExecutor = undefined;
}

/** What the queue would use right now. Exported for the integration check that
 *  asserts K1's module really satisfies the contract at runtime. */
export async function currentExecutor(): Promise<ChangeExecutor | null> {
  return resolveExecutor();
}

/**
 * Can this process actually push, and if not, WHY — answered at startup rather
 * than discovered by the first operator who presses Apply.
 *
 * Both gaps it reports fail closed on their own (a missing executor is a
 * `ChangeRefusedError`; a missing renderer makes `applyChange` throw before it
 * opens a session). Saying so out loud at boot is the difference between "the
 * job failed, is the router alright?" and "we knew, and here is the line".
 */
export async function changeExecutorReadiness(): Promise<{ ready: boolean; warnings: string[] }> {
  const warnings: string[] = [];
  const executor = await resolveExecutor();
  if (!executor) {
    warnings.push(
      'No change executor is installed (services/change/safeApply.service). The queue will ' +
        'accept jobs and refuse every one of them before opening a session. NOTHING can be ' +
        'written to any equipment on this build.',
    );
    return { ready: false, warnings };
  }
  if (typeof (executor as { runReadOnly?: unknown }).runReadOnly !== 'function') {
    warnings.push(
      "The installed executor has no runReadOnly(): change jobs of kind 'export' and 'backup' " +
        'will be refused rather than silently faked.',
    );
  }
  try {
    const specifier = './safeApply.service';
    const mod = (await import(specifier)) as { isChangeRendererRegistered?: () => boolean };
    if (typeof mod.isChangeRendererRegistered === 'function' && !mod.isChangeRendererRegistered()) {
      warnings.push(
        'No change RENDERER is registered (registerChangeRenderer). The queue hands the executor ' +
          'the REDACTED plan (§8.2) — the complete config with its secrets exists only on the ' +
          "vault -> equipment path — so `push` jobs will refuse at the apply step rather than " +
          'write literal `***` into a customer firewall. Register it from the composition root ' +
          'before enabling pushes.',
      );
    }
  } catch {
    /* the module was resolvable a moment ago; a probe failure is not fatal */
  }
  return { ready: warnings.length === 0, warnings };
}

/**
 * Find K1's module without importing it statically.
 *
 * `safeApply.service.ts` belongs to another workstream and may not exist on
 * this checkout. A static import would make the whole server fail to compile
 * over a file this milestone does not own; a dynamic one lets the queue exist,
 * refuse honestly, and start working the day the module lands — with no edit
 * here.
 */
async function resolveExecutor(): Promise<ChangeExecutor | null> {
  if (injectedExecutor) return injectedExecutor;
  if (resolvedExecutor !== undefined) return resolvedExecutor;

  const specifier = './safeApply.service';
  try {
    const mod = (await import(specifier)) as Record<string, unknown>;
    const candidate = (mod.changeExecutor ?? mod.safeApply ?? mod.default ?? mod) as
      Partial<ChangeExecutor>;
    const required: Array<keyof ChangeExecutor> = [
      'takePreflightBackup',
      'armDeadman',
      'applyChange',
      'verify',
      'disarmDeadman',
    ];
    const missing = required.filter((k) => typeof candidate[k] !== 'function');
    if (missing.length > 0) {
      logger.error(
        { missing },
        'change executor: safeApply.service was found but does not implement the ChangeExecutor ' +
          'contract. No write will be attempted.',
      );
      resolvedExecutor = null;
      return null;
    }
    logger.info('change executor: safeApply.service resolved — writes are possible');
    resolvedExecutor = candidate as ChangeExecutor;
    return resolvedExecutor;
  } catch {
    logger.warn(
      'change executor: no safeApply.service module on this build. The queue will accept and ' +
        'refuse jobs, and NOTHING will be written to any equipment.',
    );
    resolvedExecutor = null;
    return null;
  }
}

// ============================================================================
// Device record
// ============================================================================

export interface DeviceRecord {
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
}

async function loadDeviceRecord(
  tenantId: number,
  deviceId: number,
  q: Knex | Knex.Transaction = db,
): Promise<DeviceRecord> {
  const row = (await q('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first(
      'id', 'uuid', 'tenant_id', 'site_id', 'name', 'brand', 'family', 'model',
      'os_version', 'tunnel_ip', 'source_ip_hint', 'concentrator_id', 'status', 'is_managed',
    )) as DeviceRecord | undefined;
  if (!row) throw new ChangeRefusedError('device_not_found', `Device ${deviceId} not found`);
  return row;
}

/**
 * The address the management session comes FROM — the concentrator.
 *
 * Approximate by construction, and the guard is told so: the CHR's `tunnel_ip`
 * is its address on the tunnel network, which is what a CPE sees as the source
 * of an inbound API session in the normal topology. When it cannot be
 * determined the guard receives `null` and answers INDETERMINATE with
 * NO_MGMT_PATH_KNOWN — which is the correct answer, not a fallback.
 */
async function resolvePeerAddress(device: DeviceRecord): Promise<string | null> {
  if (device.concentrator_id) {
    const chr = (await db('devices')
      .where({ id: device.concentrator_id })
      .first('tunnel_ip', 'wan_public_ip')) as
      | { tunnel_ip: string | null; wan_public_ip: string | null }
      | undefined;
    const addr = chr?.tunnel_ip ?? chr?.wan_public_ip ?? null;
    if (addr) return String(addr).split('/')[0];
  }
  return device.source_ip_hint ? String(device.source_ip_hint).split('/')[0] : null;
}

// ============================================================================
// Step 3 — the Management-Path Guard
// ============================================================================

export interface GuardOutcome {
  verdict: GuardVerdict;
  /** The guard's own richer reasons (message, culprit record, plan line). */
  reasons: unknown[];
  summary: string;
  /** True when the guard could not even be run (no snapshot, no coordinates). */
  unavailable: boolean;
}

/**
 * Run K2 against the device as it is NOW.
 *
 * The observed document comes from the LATEST snapshot, not from the one the
 * plan was compiled against: the question the guard answers is "does this plan
 * cut the path we use today", and yesterday's document cannot answer it. The
 * freshness check (step 2) is what guarantees the two are the same document
 * when a job actually runs.
 *
 * A missing snapshot, a missing tunnel address or an unresolvable peer make the
 * verdict INDETERMINATE. Never ACCEPT. `guardAllowsApply()` is the only
 * predicate any caller may use — nothing in this file writes `!== 'REJECT'`.
 */
export async function evaluateGuardForPlan(
  device: DeviceRecord,
  ops: readonly unknown[],
): Promise<GuardOutcome> {
  const latest = await latestDocument(device.id);
  if (!latest) {
    return {
      verdict: 'INDETERMINATE',
      reasons: [
        {
          code: 'COVERAGE_INCOMPLETE',
          effect: 'indeterminate',
          message:
            'This device has no configuration snapshot, so the Management-Path Guard has ' +
            'nothing to reason over. Collect the configuration before applying anything.',
        },
      ],
      summary: 'Management-Path Guard: INDETERMINATE — no configuration snapshot for this device.',
      unavailable: true,
    };
  }

  const facts = buildMgmtPathFacts(latest.doc, {
    deviceId: device.id,
    tunnelIp: device.tunnel_ip ? String(device.tunnel_ip).split('/')[0] : null,
  });
  const peerAddress = await resolvePeerAddress(device);

  let result: MgmtGuardResult;
  try {
    result = guardPlan({
      observed: latest.doc,
      // The guard reads `PlanOp[]`; the ops come straight from the frozen plan,
      // which was validated by the shared `ApplyPlan` schema on the way in.
      ops: ops as never,
      facts,
      peerAddress,
      family: device.family as never,
    });
  } catch (err) {
    // A guard that THREW has not accepted anything. Refuse to conclude rather
    // than let an exception read as silence.
    logger.error({ err, deviceId: device.id }, 'Management-Path Guard threw');
    return {
      verdict: 'INDETERMINATE',
      reasons: [
        {
          code: 'NO_FORWARDING_MODEL',
          effect: 'indeterminate',
          message: `The Management-Path Guard failed to run: ${
            err instanceof Error ? err.message : String(err)
          }`,
        },
      ],
      summary: 'Management-Path Guard: INDETERMINATE — the guard could not run.',
      unavailable: true,
    };
  }

  return {
    verdict: result.verdict,
    reasons: result.reasons as unknown[],
    summary: result.summary,
    unavailable: false,
  };
}

/**
 * A write kind with no plan — `reboot`, `firmware`, `restore`.
 *
 * The guard models a FORWARDING change. It has nothing to say about a reboot
 * (whose hazard is an unsaved running config coming back different) or about a
 * firmware upgrade (whose hazard is everything). Pretending it accepted them
 * would be a lie with a green tick on it, so these are INDETERMINATE by
 * construction and need a signed override like any other refusal.
 */
function guardForPlanlessWrite(kind: ChangeJobKind): GuardOutcome {
  return {
    verdict: 'INDETERMINATE',
    reasons: [
      {
        code: 'NO_FORWARDING_MODEL',
        effect: 'indeterminate',
        message:
          `A '${kind}' job carries no plan, so the Management-Path Guard has no operations to ` +
          'simulate. It cannot prove the management path survives, and it does not pretend to.',
      },
    ],
    summary: `Management-Path Guard: INDETERMINATE — '${kind}' is outside the forwarding model.`,
    unavailable: false,
  };
}

// ============================================================================
// Step 4 — the safety net (§8.3)
// ============================================================================

export interface SafetyNetPlan {
  level: SafetyLevel;
  peerDeviceId: number | null;
  peerDeviceName: string | null;
  /** Shown on the impact screen BEFORE launch, verbatim. */
  rationale: string;
  /** True when the level is a CLAIM we have not verified on hardware. */
  unverified: boolean;
  requiresConfirmation: boolean;
}

/**
 * Which of the three nets this device gets.
 *
 * ┌─ WHAT THIS FUNCTION KNOWS, AND WHAT IT DOES NOT ──────────────────────────┐
 * │ It is INVENTORY ARITHMETIC. It reads a brand and looks for a co-located   │
 * │ MikroTik. It does NOT probe whether `/system/scheduler` can be written,   │
 * │ whether the peer is reachable, or — the harder half of §8.3 — whether the │
 * │ tunnel to that peer is one THIS change does not touch.                    │
 * │                                                                          │
 * │ So `armed_by_peer` is returned with `unverified: true`, which becomes a   │
 * │ PEER_UNVERIFIED guard reason, which makes the verdict INDETERMINATE,      │
 * │ which demands a signed override. That is not pessimism for its own sake:  │
 * │ A2 says the four brands write from v1 and that there is no laboratory, so │
 * │ the net IS the laboratory, and a net we have not verified must not be     │
 * │ presented as one we have.                                                 │
 * │                                                                          │
 * │ The level the operator finally lives with is the one `armDeadman()`       │
 * │ REPORTS at step 6. If that is worse than this one, the job stops.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function resolveSafetyNet(device: DeviceRecord): Promise<SafetyNetPlan> {
  if (device.brand === 'mikrotik') {
    return {
      level: 'armed',
      peerDeviceId: null,
      peerDeviceName: null,
      rationale:
        'ARMED — the dead-man is installed on this device itself ' +
        '(/system/scheduler start-time=startup + a restore script). The router repairs itself ' +
        'even if the ObliWAN server is dead.',
      unverified: false,
      requiresConfirmation: false,
    };
  }

  const peer =
    device.site_id === null
      ? undefined
      : ((await db('devices')
          .where({ tenant_id: device.tenant_id, site_id: device.site_id, brand: 'mikrotik' })
          .whereNot('id', device.id)
          .whereIn('status', ['active'])
          .orderBy('id')
          .first('id', 'name')) as { id: number; name: string } | undefined);

  if (peer) {
    return {
      level: 'armed_by_peer',
      peerDeviceId: peer.id,
      peerDeviceName: peer.name,
      rationale:
        `ARMED_BY_PEER — the dead-man would be carried by ${peer.name} (#${peer.id}), a MikroTik ` +
        'on the same site. NOT VERIFIED: nothing has yet checked that this peer is reachable, ' +
        'nor that the tunnel used to reach it is one this change does not touch. Treat the net ' +
        'as a claim until the arming step confirms it.',
      unverified: true,
      // §8.3 demands the explicit confirmation for DEGRADED. An unverified peer
      // is not DEGRADED — but it is not a proof either, which is why it is
      // routed through the guard's PEER_UNVERIFIED reason instead.
      requiresConfirmation: false,
    };
  }

  return {
    level: 'degraded',
    peerDeviceId: null,
    peerDeviceName: null,
    rationale:
      `DEGRADED — ${device.brand} with no co-located MikroTik. Detection WITHOUT recovery: if ` +
      'this change cuts the management path we will know, and we will not be able to repair it ' +
      'remotely. Repair means a visit. §8.3 requires an explicit, recorded confirmation.',
    unverified: false,
    requiresConfirmation: true,
  };
}

// ============================================================================
// Enqueue — where a plan becomes a job
// ============================================================================

export interface EnqueueInput {
  tenantId: number;
  deviceId: number;
  kind: ChangeJobKind;
  /** The compiled plan, as `/api/plan/devices/:id` returned it. Required for
   *  `push`, forbidden otherwise. */
  plan?: unknown;
  requestedBy: number | null;
  /** A signed override of a non-ACCEPT guard verdict. `CHANGE_APPROVE` at the
   *  route, `override_reason` + `overridden_by` + `overridden_at` in the row. */
  override?: { reason: string; userId: number | null } | null;
  /** §8.3 — the explicit confirmation a DEGRADED write demands. */
  confirmDegraded?: { userId: number | null } | null;
  scheduledFor?: Date | null;
  windowStart?: Date | null;
  windowEnd?: Date | null;
  maxAttempts?: number;
}

export interface EnqueueResult {
  jobId: number;
  planId: number | null;
  guard: GuardOutcome;
  safetyNet: SafetyNetPlan;
}

/**
 * PREVIEW — everything `enqueue` would decide, decided, with nothing written.
 *
 * This is what the impact screen calls: §8.3 says the three levels are
 * "calculés PAR DEVICE et AFFICHÉS AVANT le lancement", and a level computed
 * only inside the enqueue transaction is a level nobody was shown.
 */
export async function previewChange(input: {
  tenantId: number;
  deviceId: number;
  kind: ChangeJobKind;
  plan?: unknown;
}): Promise<{
  device: { id: number; name: string; brand: string; family: string };
  guard: GuardOutcome;
  safetyNet: SafetyNetPlan;
  killSwitch: Awaited<ReturnType<typeof readKillSwitch>>;
  freshness: { fresh: boolean; reason: string | null } | null;
  requiresOverride: boolean;
  requiresDegradedConfirmation: boolean;
}> {
  const device = await loadDeviceRecord(input.tenantId, input.deviceId);
  const safetyNet = await resolveSafetyNet(device);

  let guard: GuardOutcome;
  let freshness: { fresh: boolean; reason: string | null } | null = null;

  if (input.kind === 'push') {
    const plan = ApplyPlan.parse(input.plan);
    const verdict = await checkPlanFreshness(input.tenantId, plan);
    freshness = { fresh: verdict.fresh, reason: verdict.reason };
    guard = await evaluateGuardForPlan(device, plan.ops);
  } else if (isWriteJobKind(input.kind)) {
    guard = guardForPlanlessWrite(input.kind);
  } else {
    guard = {
      verdict: 'ACCEPT',
      reasons: [],
      summary: 'Read-only operation: nothing is written, so there is nothing to guard.',
      unavailable: false,
    };
  }

  guard = withPeerReason(guard, safetyNet, input.kind);

  return {
    device: { id: device.id, name: device.name, brand: device.brand, family: device.family },
    guard,
    safetyNet,
    killSwitch: await readKillSwitch(input.tenantId),
    freshness,
    requiresOverride: isWriteJobKind(input.kind) && !guardAllowsApply(guard.verdict),
    requiresDegradedConfirmation: isWriteJobKind(input.kind) && safetyNet.requiresConfirmation,
  };
}

/** An unverified peer net is a blind spot, and a blind spot is INDETERMINATE. */
function withPeerReason(
  guard: GuardOutcome,
  net: SafetyNetPlan,
  kind: ChangeJobKind,
): GuardOutcome {
  if (!net.unverified || !isWriteJobKind(kind)) return guard;
  const reasons = [
    ...guard.reasons,
    {
      code: 'PEER_UNVERIFIED',
      effect: 'indeterminate',
      message: net.rationale,
    },
  ];
  return {
    verdict: guard.verdict === 'REJECT' ? 'REJECT' : 'INDETERMINATE',
    reasons,
    summary:
      guard.verdict === 'REJECT'
        ? guard.summary
        : 'Management-Path Guard: INDETERMINATE — the safety net for this device is a claim ' +
          'about a peer nothing has verified.',
    unavailable: guard.unavailable,
  };
}

/**
 * Create the job. THE only door into `change_jobs`.
 *
 * The plan is FROZEN into `change_plans` first (D3, "plan figé"): a trigger
 * leaves only `invalidated_at` / `invalidated_reason` mutable afterwards, so
 * the ops an approver read are the ops that run. The job then points at it.
 *
 * The one-job-per-device rule is NOT checked here. It is
 * `change_jobs_one_in_flight_uq`, and the 23505 it raises is translated into a
 * `DeviceBusyError`. A SELECT-then-INSERT would have a gap in the middle, and
 * two API calls fit in that gap.
 */
export async function enqueueChangeJob(input: EnqueueInput): Promise<EnqueueResult> {
  // FIRST, before anything else is even looked up. Not the guarantee — the
  // switch is read again immediately before the write, because that is when
  // somebody actually engages it — but when the world is stopped, "the world is
  // stopped" is the answer an operator needs, not "device 1 not found".
  const killSwitch = await readKillSwitch(input.tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);

  const device = await loadDeviceRecord(input.tenantId, input.deviceId);

  if (device.status === 'disabled' || device.status === 'quarantined') {
    throw new ChangeRefusedError(
      'device_not_writable',
      `Device ${device.name} is '${device.status}'. No job may be queued against it.`,
    );
  }
  if (isWriteJobKind(input.kind) && !device.is_managed) {
    throw new ChangeRefusedError(
      'device_not_managed',
      `Device ${device.name} is not managed. A device can be readable without being writable, ` +
        'and that distinction is the whole reason `is_managed` is a separate column.',
    );
  }

  const safetyNet = await resolveSafetyNet(device);

  let planId: number | null = null;
  let baseStateHash = NO_BASE_STATE;
  let guard: GuardOutcome;

  if (input.kind === 'push') {
    const plan = ApplyPlan.parse(input.plan);
    if (plan.deviceId !== device.id) {
      throw new ChangeRefusedError(
        'plan_device_mismatch',
        `This plan targets device ${plan.deviceId}, not ${device.id}.`,
      );
    }
    // Guarantee 2 (M5), at the door. It is checked AGAIN inside the job, on a
    // snapshot taken immediately before the write — same function, two call
    // sites, one guarantee.
    await assertPlanFresh(input.tenantId, plan);

    guard = withPeerReason(await evaluateGuardForPlan(device, plan.ops), safetyNet, input.kind);
    baseStateHash = plan.baseStateHash;
    planId = await freezePlan(input.tenantId, device, plan, guard, safetyNet, input.requestedBy);
  } else if (isWriteJobKind(input.kind)) {
    guard = withPeerReason(guardForPlanlessWrite(input.kind), safetyNet, input.kind);
    baseStateHash = (await currentStateHash(device.id)) ?? NO_BASE_STATE;
  } else {
    guard = {
      verdict: 'ACCEPT',
      reasons: [],
      summary: 'Read-only operation: nothing is written, so there is nothing to guard.',
      unavailable: false,
    };
    baseStateHash = (await currentStateHash(device.id)) ?? NO_BASE_STATE;
  }

  const isWrite = isWriteJobKind(input.kind);

  // ── The two refusals a human can lift, and only by signing ────────────────
  if (isWrite && !guardAllowsApply(guard.verdict) && !input.override) {
    throw new ChangeRefusedError(
      'guard_refused',
      `${guard.summary} Applying anyway requires an explicit override with a written reason ` +
        '(capability CHANGE_APPROVE) — which is recorded against your name.',
    );
  }
  if (isWrite && safetyNet.requiresConfirmation && !input.confirmDegraded) {
    throw new ChangeRefusedError(
      'degraded_unconfirmed',
      `${safetyNet.rationale} This job needs an explicit confirmation before it can be queued.`,
    );
  }

  const now = new Date();
  const row: Record<string, unknown> = {
    tenant_id: input.tenantId,
    device_id: device.id,
    plan_id: planId,
    kind: input.kind,
    status: 'queued',
    attempt: 0,
    // A WRITE IS NOT RETRIED SILENTLY. Almost nothing here is safe to try twice.
    max_attempts: Math.max(1, Math.min(input.maxAttempts ?? 1, 3)),
    base_state_hash: baseStateHash,
    safety_level: safetyNet.level,
    safety_peer_device_id: safetyNet.peerDeviceId,
    guard_verdict: isWrite ? guard.verdict : null,
    guard_reasons: JSON.stringify(guard.reasons),
    scheduled_for: input.scheduledFor ?? null,
    window_start: input.windowStart ?? null,
    window_end: input.windowEnd ?? null,
    requested_by: input.requestedBy,
  };

  if (isWrite && !guardAllowsApply(guard.verdict)) {
    row.override_reason = input.override?.reason ?? null;
    row.overridden_by = input.override?.userId ?? null;
    row.overridden_at = now;
  }
  if (isWrite && safetyNet.requiresConfirmation) {
    row.degraded_confirmed_by = input.confirmDegraded?.userId ?? null;
    row.degraded_confirmed_at = now;
  }

  let jobId: number;
  try {
    const inserted = (await db('change_jobs').insert(row).returning('id')) as Array<{
      id: string | number;
    }>;
    jobId = Number(inserted[0].id);
  } catch (err) {
    // 23505 on `change_jobs_one_in_flight_uq` is the per-device lock speaking.
    const pg = err as { code?: string; constraint?: string };
    if (pg.code === '23505' && pg.constraint === 'change_jobs_one_in_flight_uq') {
      throw new DeviceBusyError(device.id);
    }
    throw err;
  }

  logger.warn(
    {
      jobId,
      deviceId: device.id,
      kind: input.kind,
      guard: guard.verdict,
      safetyNet: safetyNet.level,
      override: Boolean(row.override_reason),
      requestedBy: input.requestedBy,
    },
    'change job QUEUED — a write to a customer equipment has been authorised',
  );

  const summary = { jobId, deviceId: device.id, kind: input.kind, status: 'queued' };
  emitToTenant(input.tenantId, SOCKET_EVENTS.JOB_QUEUED, summary);
  emitToDevice(device.id, SOCKET_EVENTS.JOB_QUEUED, summary);

  return { jobId, planId, guard, safetyNet };
}

async function currentStateHash(deviceId: number): Promise<string | null> {
  const row = (await db('config_snapshots')
    .where({ device_id: deviceId })
    .orderBy('captured_at', 'desc')
    .first('ncm_hash')) as { ncm_hash: string | null } | undefined;
  return row?.ncm_hash ?? null;
}

/** D3's "plan figé". Frozen by trigger the instant it exists. */
async function freezePlan(
  tenantId: number,
  device: DeviceRecord,
  plan: ApplyPlan,
  guard: GuardOutcome,
  net: SafetyNetPlan,
  createdBy: number | null,
): Promise<number> {
  const rows = (await db('change_plans')
    .insert({
      tenant_id: tenantId,
      device_id: device.id,
      source: plan.source,
      base_state_hash: plan.baseStateHash,
      ncm_version: plan.ncmVersion,
      sem_key_generation: plan.semKeyGeneration,
      // §8.2 — `PlanOp` values are redacted by construction; a secret never
      // transits through one. This column is the one an operator reads.
      ops: JSON.stringify(plan.ops),
      ops_count: plan.ops.length,
      risk_level: plan.riskLevel,
      // K2's uppercase verdict, bridged through the ONE authorised function.
      mgmt_path_verdict: mgmtPathVerdictOf(guard.verdict),
      guard_reasons: JSON.stringify(guard.reasons),
      safety_level: net.level,
      safety_peer_device_id: net.peerDeviceId,
      blast_radius: JSON.stringify(plan.blastRadius),
      order_converges: plan.orderConverges,
      expires_at: plan.expiresAt,
      created_by: createdBy,
    })
    .returning('id')) as Array<{ id: string | number }>;
  return Number(rows[0].id);
}

// ============================================================================
// Override, recorded after the fact
// ============================================================================

/**
 * Sign an override on a job that is still `queued`.
 *
 * Separate from enqueue because the two are separate GESTURES with separate
 * capabilities: `CHANGE_APPLY` asks for the change, `CHANGE_APPROVE` overrules
 * the guard. Four eyes is the point, and it is defeated if one call can do both
 * — which is exactly why the route for this is a different route.
 */
export async function recordOverride(
  tenantId: number,
  jobId: number,
  userId: number | null,
  reason: string,
): Promise<void> {
  const trimmed = reason.trim();
  if (trimmed.length < 8) {
    throw new ChangeRefusedError(
      'override_reason_too_short',
      'An override reason is read after an incident. "ok" is not one. Write what you checked.',
    );
  }
  const job = await getJobRow(tenantId, jobId);
  if (!job) throw new ChangeRefusedError('not_found', `Change job ${jobId} not found`);
  if (job.status !== 'queued') {
    throw new ChangeRefusedError(
      'not_queued',
      `Job ${jobId} is '${job.status}'. An override can only be signed before the job is claimed.`,
    );
  }
  if (job.guard_verdict === 'ACCEPT') {
    throw new ChangeRefusedError(
      'nothing_to_override',
      'The guard accepted this plan. There is nothing to override, and recording one anyway ' +
        'would put a signature on a decision nobody made.',
    );
  }

  await db('change_jobs').where({ id: jobId }).update({
    override_reason: trimmed,
    overridden_by: userId,
    overridden_at: db.fn.now(),
    approved_by: userId,
    updated_at: db.fn.now(),
  });

  logger.warn(
    { jobId, deviceId: job.device_id, userId, verdict: job.guard_verdict, reason: trimmed },
    'MANAGEMENT-PATH GUARD OVERRIDDEN — a non-ACCEPT verdict was forced by a named operator',
  );
}

// ============================================================================
// runJob — the orchestration
// ============================================================================

interface RunState {
  seq: number;
  job: ChangeJobRow;
  device: DeviceRecord;
  ctx: ExecContext;
  /** True once bytes may have reached the router. Decides whether the corpus
   *  gets a row, and whether a failure is a hardware observation at all. */
  wroteToDevice: boolean;
  /** True once the post-conditions were MEASURED and held. The only state in
   *  which taking the dead-man down on a failing job is defensible. */
  postcheckPassed: boolean;
  /** The worker that holds the lease. Renewals are made AS this identity, so a
   *  process that did not claim the job cannot keep it alive. */
  workerId: string;
  rollbackObserved: boolean;
  startedAt: number;
}

/**
 * Run one claimed job to a terminal state.
 *
 * NEVER THROWS. Every exit is a status in the database, because a throw that
 * escapes here is a device left in a state nobody recorded.
 */
export async function runJob(claimed: ChangeJobRow, workerId: string = WORKER_ID): Promise<void> {
  const jobId = Number(claimed.id);
  let state: RunState | null = null;

  try {
    const device = await loadDeviceRecord(claimed.tenant_id, claimed.device_id);
    const planOps = await loadPlanOps(claimed);

    state = {
      seq: 0,
      job: claimed,
      device,
      startedAt: Date.now(),
      workerId,
      wroteToDevice: false,
      postcheckPassed: false,
      rollbackObserved: false,
      ctx: {
        job: claimed,
        device,
        ops: planOps,
        planId: claimed.plan_id === null ? null : Number(claimed.plan_id),
        correlationId: crypto.randomUUID(),
        safetyLevel: claimed.safety_level,
        safetyPeerDeviceId: claimed.safety_peer_device_id,
        preflightBackupId: null,
        deadmanHandle: null,
      },
    };

    await runPhases(state);
  } catch (err) {
    if (err instanceof LeaseLostError) {
      // Somebody else owns this job now. Touch NOTHING — not the row, not the
      // device. Two workers writing the same status is how a job gets disarmed
      // twice and applied twice.
      logger.error({ jobId }, 'change job: lease lost mid-run — this worker stands down');
      return;
    }
    await failJob(state, claimed, err);
  }
}

async function runPhases(s: RunState): Promise<void> {
  const { job } = s;
  const write = isWriteJobKind(job.kind);

  // ── 0. Kill switch ───────────────────────────────────────────────────────
  await assertWritable(job.tenant_id);

  // ── 1. R4 — the ONLY authorised way to reach a device ────────────────────
  await step(s, 'bind_assert', async () => {
    const assertion = await assertTargetBinding(s.device.id, { throwOnFailure: true });
    return {
      output: `identity confirmed on a fresh socket (${assertion.matched} attribute(s) matched)`,
      detail: { dialled: assertion.dialled, matched: assertion.matched },
    };
  });

  // ── 2 + 3. Freshness, then the guard, on the state as it is NOW ──────────
  await step(s, 'guard', async () => {
    if (job.plan_id !== null) {
      await assertPlanFresh(job.tenant_id, {
        deviceId: s.device.id,
        baseStateHash: job.base_state_hash,
        // The plan's own expiry was checked at enqueue; a job that waited for
        // its maintenance window must not be failed for having waited, so the
        // expiry is re-anchored here and the HASH carries the load. That is the
        // braces, and the braces are what matters (planner.service, PLAN_TTL).
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });
    }

    if (!write) return { output: 'read-only operation: nothing to guard' };

    const fresh = job.plan_id !== null
      ? await evaluateGuardForPlan(s.device, s.ctx.ops)
      : guardForPlanlessWrite(job.kind);

    const signed = (job.guard_verdict ?? 'INDETERMINATE') as GuardVerdict;
    const hasOverride = Boolean(job.override_reason && job.overridden_by !== null);

    // The verdict must still be one a human accepted. A plan signed off as
    // INDETERMINATE that has become REJECT since is a different decision.
    if (guardVerdictWorsened(signed, fresh.verdict)) {
      throw new ChangeRefusedError(
        'guard_worsened',
        `The Management-Path Guard now says ${fresh.verdict}; this job was authorised against ` +
          `${signed}. ${fresh.summary} Recompile and have it reviewed again.`,
      );
    }
    if (!guardAllowsApply(fresh.verdict) && !hasOverride) {
      throw new ChangeRefusedError('guard_refused', fresh.summary);
    }

    await db('change_jobs').where({ id: job.id }).update({
      guard_reasons: JSON.stringify(fresh.reasons),
      updated_at: db.fn.now(),
    });

    return {
      output: hasOverride
        ? `${fresh.summary} OVERRIDDEN by user ${job.overridden_by}: ${job.override_reason}`
        : fresh.summary,
      detail: { verdict: fresh.verdict, overridden: hasOverride, reasonCount: fresh.reasons.length },
    };
  });

  const executor = await resolveExecutor();
  if (!executor) {
    throw new ChangeRefusedError(
      'executor_unavailable',
      'No change executor is installed on this build (safeApply.service). The queue accepted ' +
        'this job and is refusing it BEFORE opening any session. Nothing was written.',
    );
  }

  // ── Read-only kinds leave here ───────────────────────────────────────────
  //
  // They walk the SAME state machine, because there is only one and inventing a
  // shortcut would mean two definitions of "what state is this job in". What
  // makes the difference legible is not a different path, it is two SKIPPED
  // steps that say, in the trace, exactly why no backup was taken and why no
  // dead-man was armed. §3.5's `skipped` status exists for this: "we did not
  // arm a net" must be a recorded fact and never an absent row.
  if (!write) {
    s.job = await transitionJob(s.job, 'backing_up');
    await skipStep(
      s.job,
      s.seq++,
      'preflight_backup',
      `'${job.kind}' does not modify the device, so R1's pre-change backup does not apply.`,
    );
    s.job = await transitionJob(s.job, 'arming');
    await skipStep(
      s.job,
      s.seq++,
      'arm_deadman',
      `'${job.kind}' writes nothing, so there is nothing for a dead-man to undo. No net armed.`,
    );
    s.job = await transitionJob(s.job, 'applying');
    await step(s, 'apply', async () => {
      if (!executor.runReadOnly) {
        throw new ChangeRefusedError(
          'executor_unavailable',
          `The installed executor cannot perform a '${job.kind}'.`,
        );
      }
      const out = await executor.runReadOnly(s.ctx);
      return { output: out.outputRedacted ?? 'done', detail: out.detail };
    });
    s.job = await transitionJob(s.job, 'verifying');
    s.job = await transitionJob(s.job, 'soaking');
    s.job = await transitionJob(s.job, 'disarming');
    s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
    return;
  }

  // ── 5. R1 — the pre-change backup. A CHECK constraint, not a habit ───────
  await assertLease(Number(job.id), s.workerId);
  s.job = await transitionJob(s.job, 'backing_up');
  await step(s, 'preflight_backup', async () => {
    const { backupId } = await executor.takePreflightBackup(s.ctx);
    s.ctx.preflightBackupId = backupId;
    // Written to the row BEFORE the transition to `arming`, because
    // `change_jobs_preflight_backup_chk` makes that transition impossible
    // without it. The constraint is the reason this is not a comment.
    await db('change_jobs').where({ id: job.id }).update({
      preflight_backup_id: backupId,
      updated_at: db.fn.now(),
    });
    return { output: `pre-change backup #${backupId} stored`, detail: { backupId } };
  });

  // ── 6. The net (§8.3) ────────────────────────────────────────────────────
  await assertLease(Number(job.id), s.workerId);
  s.job = await transitionJob(s.job, 'arming');
  await step(s, 'arm_deadman', async () => {
    const armed = await executor.armDeadman(s.ctx);
    s.ctx.deadmanHandle = armed.handle;

    // THE NET YOU WERE SHOWN MUST BE THE NET YOU GOT. A device promised as
    // ARMED that could only be armed by a peer — or not at all — is a device
    // whose operator confirmed a different risk. Downgrading silently here is
    // exactly the lie §8.3 forbids, so the job stops instead.
    if (armed.level !== s.job.safety_level) {
      throw new ChangeRefusedError(
        'safety_net_downgraded',
        `The safety net actually obtained is '${armed.level}', but this job was authorised ` +
          `against '${s.job.safety_level}'. Nothing has been applied. Re-queue it with the ` +
          'real level so the confirmation matches the risk.',
      );
    }

    await db('change_jobs').where({ id: job.id }).update({
      deadman_handle: armed.handle,
      deadman_armed_at: db.fn.now(),
      confirm_deadline: armed.confirmDeadline,
      updated_at: db.fn.now(),
    });
    return {
      output: `dead-man armed (${armed.level}); the device restores itself at ${
        armed.confirmDeadline.toISOString()
      } unless disarmed`,
      detail: { handle: armed.handle, level: armed.level },
    };
  });

  // ── 7. THE LAST STATEMENT BEFORE THE WRITE ───────────────────────────────
  //
  // Not a repetition: this is the check the kill switch exists FOR. Between it
  // and `applyChange` there is one status update and no I/O.
  await assertWritable(job.tenant_id);
  await assertLease(Number(job.id), s.workerId);

  // ── 8. The write ─────────────────────────────────────────────────────────
  s.job = await transitionJob(s.job, 'applying');
  s.wroteToDevice = true;
  await step(s, 'apply', async () => {
    const out = await executor.applyChange(s.ctx);
    return {
      output: out.outputRedacted ?? `${out.appliedOps} operation(s) applied`,
      detail: { appliedOps: out.appliedOps },
    };
  });

  // ── 9. Verify, on a NEW socket ───────────────────────────────────────────
  await assertLease(Number(job.id), s.workerId);
  s.job = await transitionJob(s.job, 'verifying');
  await step(s, 'reconnect', async () => {
    // Let the listener come back before deciding it is gone.
    await sleep(RECONNECT_DELAY_MS);
    let lastError: unknown = null;
    for (let attempt = 1; attempt <= RECONNECT_ATTEMPTS; attempt++) {
      try {
        const assertion = await assertTargetBinding(s.device.id, { throwOnFailure: true });
        return {
          output:
            `reconnected and re-asserted identity at attempt ${attempt}/${RECONNECT_ATTEMPTS} ` +
            `(${assertion.dialled})`,
          detail: { attempt, dialled: assertion.dialled, matched: assertion.matched },
        };
      } catch (err) {
        // A MISMATCH IS AN ANSWER, AND IT IS FINAL. The box replied and it is
        // not the device on the row (R4): retrying cannot change that, and
        // `assertTargetBinding` has already quarantined it — looping would
        // simply re-quarantine it five more times. Only SILENCE is retried.
        if (err instanceof BindingAssertionError && err.assertion.mismatched > 0) throw err;
        lastError = err;
        if (attempt < RECONNECT_ATTEMPTS) await sleep(RECONNECT_INTERVAL_MS);
      }
    }
    throw lastError instanceof Error
      ? lastError
      : new ChangeRefusedError(
          'reconnect_failed',
          `The device did not answer in ${RECONNECT_ATTEMPTS} attempts after the write.`,
        );
  });
  await step(s, 'postcheck', async () => {
    const verdict = await executor.verify(s.ctx);
    if (!verdict.ok) {
      throw new ChangeRefusedError(
        'postcheck_failed',
        verdict.errorRedacted ?? 'Post-conditions did not hold after the change.',
      );
    }
    return { output: 'post-conditions hold', detail: verdict.detail };
  });
  // From here on, the change has been WRITTEN and PROVED to hold. A failure
  // after this point is a failure of our own bookkeeping, not of the change —
  // which is the one case where `failJob` may try to take the net down.
  s.postcheckPassed = true;

  // ── 10. Soak — live, watched, dead-man STILL armed ───────────────────────
  const soakUntil = new Date(Date.now() + SOAK_MS);
  s.job = await transitionJob(s.job, 'soaking', { soakUntil });
  await step(s, 'soak', async () => {
    await soak(Number(job.id), soakUntil, s.workerId);
    return { output: `soaked for ${Math.round(SOAK_MS / 1000)}s with the dead-man armed` };
  });

  // ── 11. Disarm. A job is not `succeeded` while a scheduler still reverts ─
  await assertLease(Number(job.id), s.workerId);
  s.job = await transitionJob(s.job, 'disarming');
  await step(s, 'disarm', async () => {
    await executor.disarmDeadman(s.ctx);
    await db('change_jobs').where({ id: job.id }).update({
      deadman_disarmed_at: db.fn.now(),
      updated_at: db.fn.now(),
    });
    return { output: 'dead-man removed and confirmed gone' };
  });

  s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
  await recordOutcome(s, 'succeeded', null);
  logger.info({ jobId: Number(job.id), deviceId: s.device.id }, 'change job SUCCEEDED');
}

/**
 * Wait out the soak window, renewing the lease as we go.
 *
 * The renewal is the point: five minutes of silence is longer than a lease, and
 * a job whose lease expired mid-soak would be picked up by the reaper as
 * "worker died after the write" — a false alarm on the one signal that must
 * never cry wolf.
 */
async function soak(jobId: number, until: Date, workerId: string): Promise<void> {
  while (Date.now() < until.getTime()) {
    const remaining = until.getTime() - Date.now();
    await new Promise((r) => setTimeout(r, Math.min(remaining, 15_000)));
    await assertLease(jobId, workerId);
  }
}

// ============================================================================
// Steps
// ============================================================================

interface StepOutcome {
  output?: string | null;
  detail?: Record<string, unknown>;
}

/**
 * Run one step, recorded whatever happens.
 *
 * A step whose row is missing is a step nobody can prove was attempted, which
 * is why the `finishStep` on the failure path is not conditional and is not
 * inside the try.
 */
async function step(
  s: RunState,
  kind: Parameters<typeof startStep>[2],
  body: () => Promise<StepOutcome>,
): Promise<void> {
  const handle: StepHandle = await startStep(s.job, s.seq++, kind);
  try {
    const out = await body();
    await finishStep(s.job, handle, 'succeeded', {
      output: out.output ?? null,
      detail: out.detail,
    });
  } catch (err) {
    await finishStep(s.job, handle, 'failed', {
      // Already redacted at the source; this layer does not remove secrets, it
      // only refuses to add any (§8.2).
      error: err instanceof Error ? err.message : String(err),
    });
    throw err;
  }
}

// ============================================================================
// Failure
// ============================================================================

async function failJob(s: RunState | null, claimed: ChangeJobRow, err: unknown): Promise<void> {
  const jobId = Number(claimed.id);
  const message = err instanceof Error ? err.message : String(err);
  const kind = classifyFailure(err);

  logger.error(
    { jobId, deviceId: claimed.device_id, errorKind: kind, err },
    'change job FAILED',
  );

  try {
    const current = (await db('change_jobs').where({ id: jobId }).first('*')) as
      | ChangeJobRow
      | undefined;
    if (!current) return;

    // A dead-man may still be on the box. Say so on the row: an operator who
    // reads "failed" and nothing else will not go looking for a scheduler that
    // reverts his colleague's change at the next power cut.
    let armedNotDisarmed =
      current.deadman_armed_at !== null && current.deadman_disarmed_at === null;

    // ── THE NET COMES DOWN ONLY FOR A CHANGE WE PROVED GOOD ─────────────────
    //
    // Leaving a dead-man armed is the SAFE default and stays the default here:
    // an apply that threw, a box that never answered again, a postcheck that
    // did not hold — in every one of those the router reverting itself is the
    // correct ending, and disarming would be us cancelling the only net the
    // customer has, from a code path that has just admitted it does not know
    // what state the box is in.
    //
    // There is exactly one case where the opposite is true: the write landed,
    // the box answered, the post-conditions were MEASURED and held, and the job
    // then failed on something of ours — a lost lease, an interrupted soak, a
    // disarm that did not take. That job's change is good. Concluding `failed`
    // with the scheduler still counting hands the customer a revert nobody
    // decided on, ten minutes later, of a change that worked.
    //
    // So: `postcheckPassed` and nothing weaker. A disarm that fails changes
    // nothing — the row keeps saying STILL ARMED, which is the truth.
    let disarmNote = '';
    if (s && s.postcheckPassed && armedNotDisarmed) {
      try {
        const executor = await resolveExecutor();
        if (executor) {
          await executor.disarmDeadman(s.ctx);
          await db('change_jobs').where({ id: jobId }).update({
            deadman_disarmed_at: db.fn.now(),
            updated_at: db.fn.now(),
          });
          armedNotDisarmed = false;
          disarmNote =
            ' The post-conditions had already been verified, so the dead-man was disarmed ' +
            'before this job was closed: the change stands, only the job failed.';
          logger.warn(
            { jobId, deviceId: claimed.device_id },
            'change job failed AFTER a verified change — dead-man disarmed so a good change ' +
              'is not reverted by the router',
          );
        }
      } catch (disarmErr) {
        logger.error(
          { err: disarmErr, jobId, deviceId: claimed.device_id },
          'change job: the dead-man could not be disarmed on the failure path; the device WILL ' +
            'restore itself',
        );
      }
    }

    const operatorMessage =
      message +
      disarmNote +
      (armedNotDisarmed
        ? ` A dead-man is STILL ARMED on this device (handle ${current.deadman_handle ?? '?'}). ` +
          'It will restore the pre-change configuration at its deadline or at the next boot.'
        : '');

    if (current.status === 'failed' || current.status === 'rolled_back' ||
        current.status === 'succeeded' || current.status === 'aborted') {
      return; // already terminal — a second hand on the row is a second truth
    }

    await transitionJob(current, 'failed', {
      errorKind: kind,
      errorMessage: operatorMessage,
      outcome: null,
    });

    if (s) await recordOutcome(s, 'failed', kind);
  } catch (inner) {
    logger.error({ err: inner, jobId }, 'change job: could not even record the failure');
  }
}

function classifyFailure(err: unknown): string {
  if (err instanceof KillSwitchEngagedError) return 'kill_switch';
  if (err instanceof BindingAssertionError) return 'binding_mismatch';
  if (err instanceof StalePlanError) return 'plan_stale';
  if (err instanceof PlanExpiredError) return 'plan_expired';
  if (err instanceof ChangeRefusedError) return err.kind;
  if (err instanceof Error && err.name) return err.name.slice(0, 48);
  return 'unknown';
}

// ============================================================================
// Step 12 — apply_outcomes (§8.3, "the laboratory we do not have")
// ============================================================================

/**
 * Append one row to the empirical corpus.
 *
 * ┌─ WHEN A ROW IS WRITTEN, AND WHY NOT ALWAYS ───────────────────────────────┐
 * │ Only once the device has been touched with intent to change it — from     │
 * │ `arming` onward, because installing a dead-man IS a write. A job the      │
 * │ guard refused, or one that died on a stale plan, tells you nothing about  │
 * │ how a 2927 running 4.4.3 behaves under a firewall push, and putting it in │
 * │ the corpus would make the corpus lie in the reassuring direction.         │
 * │                                                                          │
 * │ THE MAPPING IS PESSIMISTIC AND SAYS SO. `APPLY_OUTCOMES` has three        │
 * │ values. A post-write failure is `rolled_back` ONLY if a rollback was      │
 * │ OBSERVED; everything else lands in `lost_contact` with the real           │
 * │ `failure_kind` beside it. That over-reports the worst outcome, which is   │
 * │ the safe direction for a memory whose whole job is to warn — and it is    │
 * │ recorded here so nobody later reads a `lost_contact` count as a van       │
 * │ count without checking `failure_kind`.                                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
async function recordOutcome(
  s: RunState,
  result: 'succeeded' | 'failed',
  failureKind: string | null,
): Promise<void> {
  const { job, device } = s;
  if (!isWriteJobKind(job.kind)) return;

  const armed = s.ctx.deadmanHandle !== null || s.wroteToDevice;
  if (!armed) {
    await skipStep(
      s.job,
      s.seq++,
      'record_outcome',
      'No row written to apply_outcomes: this job never touched the device, so it is not an ' +
        'observation about this hardware. (§8.3 — the corpus must not be padded with our own ' +
        'refusals.)',
    );
    return;
  }

  const outcome =
    result === 'succeeded' ? 'succeeded' : s.rollbackObserved ? 'rolled_back' : 'lost_contact';

  await step(s, 'record_outcome', async () => {
    await db('apply_outcomes').insert({
      tenant_id: job.tenant_id,
      device_id: device.id,
      job_id: job.id,
      op_kind: job.kind,
      resource: null,
      brand: device.brand,
      model: device.model,
      os_version: device.os_version,
      outcome,
      safety_level: job.safety_level,
      guard_verdict: job.guard_verdict,
      was_override: Boolean(job.override_reason),
      ops_count: s.ctx.ops.length,
      duration_ms: Date.now() - s.startedAt,
      failure_kind: failureKind,
      detail_redacted: JSON.stringify({
        rollbackObserved: s.rollbackObserved,
        wroteToDevice: s.wroteToDevice,
        overridden: Boolean(job.override_reason),
      }),
    });
    return {
      output: `apply_outcomes: ${outcome} (${device.brand} ${device.model ?? '?'} ${
        device.os_version ?? '?'
      })`,
    };
  });
}

// ============================================================================
// Plan ops
// ============================================================================

async function loadPlanOps(job: ChangeJobRow): Promise<unknown[]> {
  if (job.plan_id === null) return [];
  const row = (await db('change_plans')
    .where({ id: job.plan_id, tenant_id: job.tenant_id })
    .first('ops', 'invalidated_at')) as
    | { ops: unknown; invalidated_at: Date | null }
    | undefined;
  if (!row) {
    throw new ChangeRefusedError('plan_missing', `The frozen plan of job ${job.id} is gone.`);
  }
  if (row.invalidated_at) {
    throw new ChangeRefusedError(
      'plan_invalidated',
      'This plan was invalidated (the device moved under us). Recompile it.',
    );
  }
  const ops = typeof row.ops === 'string' ? (JSON.parse(row.ops) as unknown) : row.ops;
  return Array.isArray(ops) ? ops : [];
}

// ============================================================================
// Barrel
// ============================================================================

export const applyService = {
  enqueueChangeJob,
  previewChange,
  recordOverride,
  runJob,
  currentExecutor,
  evaluateGuardForPlan,
  resolveSafetyNet,
  setChangeExecutor,
};

// `auditedCommand` / `recordCommandIntent` are re-exported here so the executor
// module (K1) has one import for "the audited way to talk to a device" and
// cannot accidentally reach the transport without leaving a trace first.
//
// THE RULE IS NOT ENFORCED BY THIS RE-EXPORT AND NEVER WAS. It is enforced one
// layer down, in `backup.service.DeviceSession.run()`, which is the single
// place in this tree where a sentence leaves for an equipment and which now
// goes through `auditedCommand()` itself: the intent row is INSERTed before
// `conn.query`, with no try/catch, so an audit that cannot be written stops the
// command instead of following it. Nothing in `services/change/` opens a socket
// except through that class.
export { auditedCommand, recordCommandIntent };
