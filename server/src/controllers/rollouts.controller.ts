// ============================================================================
// ObliWAN — wave rollouts: the HTTP layer (M7, killer K3)
// ============================================================================
//
// `changes.controller` can end in a packet reaching ONE router. This one can
// end in a packet reaching two hundred, in an order this server chose, over an
// hour during which nobody is watching. Everything below is shaped by that.
//
// ┌─ THE CAPABILITY MAP, AND EVERY LINE OF IT IS A DECISION ──────────────────┐
// │ PLAN_CREATE     read a rollout, its waves, its devices — and PREVIEW one. │
// │                 The impact screen writes nothing to an equipment: seeing   │
// │                 that a change would touch 40 sites and that 12 of them     │
// │                 have NO remote recovery is exactly the information         │
// │                 somebody needs in order to decide NOT to ask for it.       │
// │ ROLLOUT_MANAGE  compose, launch, pause, resume, abort. The grant exists    │
// │                 in the capability list since M1 and says "Start, pause and │
// │                 abort wave rollouts" — this is the file that finally uses  │
// │                 it.                                                        │
// │ CHANGE_APPROVE  checked A SECOND TIME, in the handler, when the body       │
// │                 carries an override. A rollout that forces N devices past  │
// │                 a Management-Path Guard refusal is N times the act that    │
// │                 `POST /changes/jobs` asks for CHANGE_APPROVE to perform    │
// │                 once, and it must not ride in on ROLLOUT_MANAGE.           │
// └───────────────────────────────────────────────────────────────────────────┘
//
// WHAT IS DELIBERATELY ABSENT: no route that changes a wave's membership after
// composition, and no route that reorders the waves. §8.3's order (`degraded`
// last) and §8.5's subtree interlock are decided ONCE, at composition, in
// front of the operator — and migration 010 refuses the rows that would break
// either. An endpoint that let somebody move a device into an earlier wave
// would be an endpoint whose only purpose is to defeat both.
//
// EVERY read is tenant-scoped through `req.tenantId`, which comes from the
// SESSION and never from the body.

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { CAPABILITIES, type Capability } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';
import { KillSwitchEngagedError } from '../services/change/killSwitch.service';
import { ChangeRefusedError } from '../services/change/apply.service';
import { StalePlanError, PlanExpiredError } from '../services/plan/planner.service';
import { DeviceBusyError } from '../services/change/jobQueue.service';
import {
  RolloutRefusedError,
  abortRollout,
  advanceRollout,
  composeRollout,
  getRollout,
  launchRollout,
  listRollouts,
  listTargets,
  listWaves,
  pauseRollout,
  previewRollout,
  resumeRollout,
  toRolloutSummary,
} from '../services/change/rollout.service';

// ============================================================================
// Parsing and error mapping
// ============================================================================

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    const flat = result.error.flatten();
    const fields = Object.entries(flat.fieldErrors)
      .map(([f, m]) => `${f}: ${((m as string[] | undefined) ?? []).join(', ')}`)
      .concat(flat.formErrors)
      .filter((s) => s.length > 0)
      .join('; ');
    throw new AppError(400, fields ? `Validation failed — ${fields}` : 'Validation failed');
  }
  return result.data;
}

/**
 * A refusal must arrive as a refusal, with its own status and its own words.
 *
 * 409 for "the world says no" (the kill switch, a device already in another
 * rollout, a rollout in the wrong state), 422 for "you have not given me what
 * the safety machinery requires" (an unsigned override, an unconfirmed
 * DEGRADED set) and — the one that matters — 409 with the LIST of offending
 * devices for §8.5's subtree interlock. An operator told "conflict" learns to
 * retry; an operator told "chr-paris and its 12 children" fixes his rollout.
 */
function mapError(err: unknown): unknown {
  if (err instanceof AppError) return err;
  if (err instanceof KillSwitchEngagedError) return new AppError(409, err.message);
  if (err instanceof DeviceBusyError) return new AppError(409, err.message);
  if (err instanceof StalePlanError) return new AppError(409, err.message);
  if (err instanceof PlanExpiredError) return new AppError(409, err.message);
  if (err instanceof RolloutRefusedError) {
    switch (err.kind) {
      case 'not_found':
      case 'device_not_found':
      case 'revision_not_found':
        return new AppError(404, err.message);
      case 'guard_refused':
      case 'degraded_unconfirmed':
        return new AppError(422, err.message);
      default:
        return new AppError(409, err.message);
    }
  }
  if (err instanceof ChangeRefusedError) {
    switch (err.kind) {
      case 'device_not_found':
      case 'not_found':
        return new AppError(404, err.message);
      case 'guard_refused':
      case 'degraded_unconfirmed':
        return new AppError(422, err.message);
      case 'executor_unavailable':
        return new AppError(503, err.message);
      default:
        return new AppError(409, err.message);
    }
  }
  return err;
}

/** The conditional half of the RBAC split — the body raises the bar. */
async function requireExtraCapability(req: Request, capability: Capability): Promise<void> {
  if (req.session?.role === 'admin') return;
  const tenantId = req.tenantId ?? req.session?.currentTenantId;
  if (!req.session?.userId || !tenantId) {
    throw new AppError(403, 'No tenant granted for this account');
  }
  const caps = await permissionService.getUserCapabilities(req.session.userId, false, tenantId);
  if (!caps.includes(capability)) {
    throw new AppError(
      403,
      `This action additionally requires '${capability}'. Forcing a rollout past a ` +
        'Management-Path Guard refusal is a separate capability from launching one, on purpose: ' +
        'a rollout override signs for every device in the set at once.',
    );
  }
}

// ============================================================================
// Schemas
// ============================================================================

const composeSchema = z
  .object({
    name: z.string().min(1).max(200),
    description: z.string().max(4000).nullable().optional(),
    /** 500 is the fleet ceiling ObliWAN is dimensioned for (decision D6). */
    deviceIds: z.array(z.number().int().positive()).min(1).max(500),
    templateRevisionId: z.number().int().positive(),
    gateSettleMs: z.number().int().min(0).max(3600_000).optional(),
    /** Non-empty means "force every non-ACCEPT guard verdict in this set".
     *  Requires CHANGE_APPROVE on top of ROLLOUT_MANAGE. */
    overrideReason: z.string().min(8).max(2000).optional(),
    /** §8.3's explicit confirmation, for every DEGRADED device in the set. */
    confirmDegraded: z.boolean().optional(),
  })
  .strict();

const previewSchema = z
  .object({
    name: z.string().min(1).max(200).optional(),
    deviceIds: z.array(z.number().int().positive()).min(1).max(500),
    templateRevisionId: z.number().int().positive(),
  })
  .strict();

const reasonSchema = z.object({ reason: z.string().max(2000).optional() }).strict();

const listQuerySchema = z.object({
  status: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

// ============================================================================
// Controller
// ============================================================================

export const rolloutsController = {
  /**
   * THE IMPACT SCREEN — §5/M7's "compilation des N plans AVANT lancement".
   *
   * It compiles every plan, runs the Management-Path Guard on every device and
   * resolves every safety net, and it writes NOTHING: no rollout row, no
   * `config_renders` row, no job. §8.3 says the level is shown before the
   * launch and never after; a level computed only inside the composition
   * transaction is a level nobody was shown.
   *
   * It is also where §8.5's refusal surfaces first, which is the cheap moment.
   */
  async preview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(previewSchema, req.body ?? {});
      const data = await previewRollout({
        tenantId: req.tenantId,
        name: input.name ?? 'preview',
        deviceIds: input.deviceIds,
        templateRevisionId: input.templateRevisionId,
        createdBy: req.session.userId ?? null,
      });
      res.json({ success: true, data });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * Compose a rollout: same arithmetic as the preview, persisted in `draft`.
   *
   * Nothing is queued here. A composed rollout holds its devices (migration
   * 010's `rollout_targets_one_active_uq`) and waits for an explicit launch,
   * so the operator can read the impact screen, walk away, and come back.
   */
  async compose(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(composeSchema, req.body ?? {});
      if (input.overrideReason) {
        await requireExtraCapability(req, CAPABILITIES.CHANGE_APPROVE);
      }
      const data = await composeRollout({
        tenantId: req.tenantId,
        name: input.name,
        description: input.description ?? null,
        deviceIds: input.deviceIds,
        templateRevisionId: input.templateRevisionId,
        createdBy: req.session.userId ?? null,
        gateSettleMs: input.gateSettleMs,
        override: input.overrideReason
          ? { reason: input.overrideReason, userId: req.session.userId ?? null }
          : null,
        confirmDegraded: input.confirmDegraded ? { userId: req.session.userId ?? null } : null,
      });
      res.status(201).json({ success: true, data });
    } catch (err) {
      next(mapError(err));
    }
  },

  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(listQuerySchema, req.query);
      const data = await listRollouts(req.tenantId, {
        status: q.status ? q.status.split(',').map((s) => s.trim()).filter(Boolean) : undefined,
        limit: q.limit,
        offset: q.offset,
      });
      res.json({ success: true, data });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** The rollout, its waves and every device with its gate verdict. */
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'rollout id');
      const rollout = await getRollout(req.tenantId, id);
      if (!rollout) throw new AppError(404, `Rollout ${id} not found`);
      const [waves, targets] = await Promise.all([listWaves(id), listTargets(id)]);
      res.json({
        success: true,
        data: {
          rollout: toRolloutSummary(rollout),
          overrideReason: rollout.override_reason,
          overriddenBy: rollout.overridden_by,
          degradedConfirmedBy: rollout.degraded_confirmed_by,
          gateSettleMs: Number(rollout.gate_settle_ms),
          waves: waves.map((w) => ({
            id: Number(w.id),
            waveIndex: Number(w.wave_index),
            label: w.label,
            status: w.status,
            targetCount: Number(w.target_count),
            succeededCount: Number(w.succeeded_count),
            failedCount: Number(w.failed_count),
            gateVerdict: w.gate_verdict,
            gateReasons: Array.isArray(w.gate_reasons) ? w.gate_reasons : [],
            startedAt: w.started_at ? new Date(w.started_at).toISOString() : null,
            gateStartedAt: w.gate_started_at ? new Date(w.gate_started_at).toISOString() : null,
            finishedAt: w.finished_at ? new Date(w.finished_at).toISOString() : null,
          })),
          targets: targets.map((t) => ({
            id: Number(t.id),
            deviceId: Number(t.device_id),
            deviceName: t.device_name ?? null,
            waveIndex: Number(t.wave_index),
            orderRank: Number(t.order_rank),
            status: t.status,
            safetyLevel: t.safety_level,
            safetyPeerDeviceId: t.safety_peer_device_id,
            guardVerdict: t.guard_verdict,
            planOpsCount: Number(t.plan_ops_count),
            riskLevel: t.risk_level,
            jobId: t.job_id === null ? null : Number(t.job_id),
            rollbackJobId: t.rollback_job_id === null ? null : Number(t.rollback_job_id),
            rollbackBackupId:
              t.rollback_backup_id === null ? null : Number(t.rollback_backup_id),
            // The baseline itself is NOT returned: it is evidence for the gate,
            // it is large, and a screen that shows it invites somebody to read
            // a counter as a current value.
            healthBaselineAt: t.health_baseline_at
              ? new Date(t.health_baseline_at).toISOString()
              : null,
            healthVerdict: t.health_verdict,
            healthReasons: Array.isArray(t.health_reasons) ? t.health_reasons : [],
            note: t.note,
          })),
        },
      });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** GO. The first wave's baseline is captured and its jobs are queued. */
  async launch(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'rollout id');
      const row = await launchRollout(req.tenantId, id, req.session.userId ?? null);
      res.json({ success: true, data: toRolloutSummary(row) });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * Step the rollout by one decision.
   *
   * The leader-gated runtime does this on a timer; the endpoint exists because
   * "advance it now" is what an operator wants at the end of a settle window,
   * and because a subsystem whose only driver is a background timer is a
   * subsystem nobody can test from the outside.
   */
  async advance(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'rollout id');
      const report = await advanceRollout(req.tenantId, id);
      res.json({ success: true, data: report });
    } catch (err) {
      next(mapError(err));
    }
  },

  async pause(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'rollout id');
      const input = parse(reasonSchema, req.body ?? {});
      const row = await pauseRollout(req.tenantId, id, input.reason ?? null);
      res.json({ success: true, data: toRolloutSummary(row) });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * Resume a rollout paused on a gate that did not PASS.
   *
   * ROLLOUT_MANAGE and not CHANGE_APPROVE: an INDETERMINATE gate has not
   * proved harm, it has proved it could not see — which is a different act
   * from overruling a guard that PROVED the change cuts the tunnel. The trace
   * records that the wave moved on with a verdict that was never a PASS.
   */
  async resume(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'rollout id');
      const row = await resumeRollout(req.tenantId, id, req.session.userId ?? null);
      res.json({ success: true, data: toRolloutSummary(row) });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * Stop the rollout. It does NOT undo what already landed.
   *
   * Saying so in the response rather than pretending otherwise: a button that
   * claimed to reverse a fleet would be a button that lies at the exact moment
   * somebody is desperate enough to press it twice. Jobs not yet claimed are
   * cancelled; anything past `applying` belongs to the on-box dead-man.
   */
  async abort(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'rollout id');
      const input = parse(reasonSchema, req.body ?? {});
      const row = await abortRollout(
        req.tenantId,
        id,
        req.session.userId ?? null,
        input.reason ?? null,
      );
      res.json({ success: true, data: toRolloutSummary(row) });
    } catch (err) {
      next(mapError(err));
    }
  },
};
