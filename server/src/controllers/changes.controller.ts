// ============================================================================
// ObliWAN — change jobs: the HTTP layer (M6, decision D3)
// ============================================================================
//
// This controller is the first one in the product whose endpoints can end in a
// packet reaching somebody's router. Everything it does is therefore shaped by
// one question: what does a person who reads this route six months from now,
// after an incident, need to be able to prove?
//
// ┌─ TWO CAPABILITIES, AND THEY ARE NOT THE SAME CAPABILITY ──────────────────┐
// │ CHANGE_APPLY    ask for a change. Enqueue a job, abort one, engage the    │
// │                 kill switch.                                             │
// │ CHANGE_APPROVE  OVERRULE THE MANAGEMENT-PATH GUARD. Sign that a REJECT or │
// │                 an INDETERMINATE may proceed anyway.                     │
// │                                                                          │
// │ Splitting them is the four-eyes rule expressed in the permission system   │
// │ rather than in a workflow: the person who wants the change and the person │
// │ who accepts the risk of pushing it past a refusal are, deliberately, two  │
// │ different grants. `POST /jobs` with an `override` in the body therefore   │
// │ demands BOTH — checked in the handler, because the requirement is         │
// │ conditional on the body and a middleware cannot see the body's meaning.   │
// │                                                                          │
// │ Releasing the kill switch is SETTINGS_MANAGE, engaging it is CHANGE_APPLY.│
// │ Asymmetric on purpose: stopping the world must be the fastest gesture in  │
// │ the product, restarting it must not be. Both capabilities are resolved in │
// │ the CALLER'S tenant, so both of them stop at that tenant's fleet: the     │
// │ GLOBAL kill switch — one row, every customer — additionally demands the   │
// │ platform admin role, in both directions. See `resolveKillSwitchScope`.    │
// └───────────────────────────────────────────────────────────────────────────┘
//
// EVERY read is tenant-scoped through `req.tenantId`, which comes from the
// SESSION and never from the body. `command_audit` and `apply_outcomes` carry
// no foreign key to `tenants` (migration 009, decision 5), so that WHERE clause
// is the only thing between one customer and another customer's command
// history.

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { CAPABILITIES, type Capability, type ChangeJobKind } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';
import {
  ChangeRefusedError,
  enqueueChangeJob,
  previewChange,
  recordOverride,
  SOAK_MS,
} from '../services/change/apply.service';
import {
  DeviceBusyError,
  InvalidTransitionError,
  LEASE_TTL_MS,
  MAX_CONCURRENT_JOBS,
  abortJob,
  getJobRow,
  guardReasonsOf,
  listJobSteps,
  listJobs,
  shouldProcessJobs,
  toJobSummary,
} from '../services/change/jobQueue.service';
import {
  KillSwitchEngagedError,
  engageKillSwitch,
  getKillSwitchView,
  releaseKillSwitch,
} from '../services/change/killSwitch.service';
import { listCommandAudit } from '../services/audit.service';
import { StalePlanError, PlanExpiredError } from '../services/plan/planner.service';

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
 * A refusal must arrive as a refusal, with its own status.
 *
 * 409 for "the world says no" (busy device, stale plan, kill switch), 422 for
 * "you have not given me what the safety machinery requires" (an unsigned
 * override, an unconfirmed DEGRADED). A blanket 500 on any of these is how an
 * operator learns to retry instead of to read.
 */
function mapError(err: unknown): unknown {
  if (err instanceof AppError) return err;
  // The `ApplyPlan` envelope is parsed inside the SERVICE, not here, because a
  // plan compiled by one server version must not be reinterpreted by another —
  // and that check belongs next to the code that acts on it. The cost is that
  // its rejection surfaces as a ZodError at this layer, and a malformed plan is
  // a 400, not a 500: the caller's request is wrong, the server is fine.
  if (err instanceof z.ZodError) {
    const first = err.issues[0];
    return new AppError(
      400,
      `The plan envelope is not a valid ApplyPlan${
        first ? ` — ${first.path.join('.')}: ${first.message}` : ''
      }. Recompile it with POST /api/plan/devices/:id.`,
    );
  }
  if (err instanceof DeviceBusyError) return new AppError(409, err.message);
  if (err instanceof KillSwitchEngagedError) return new AppError(409, err.message);
  if (err instanceof StalePlanError) return new AppError(409, err.message);
  if (err instanceof PlanExpiredError) return new AppError(409, err.message);
  if (err instanceof InvalidTransitionError) return new AppError(409, err.message);
  if (err instanceof ChangeRefusedError) {
    switch (err.kind) {
      case 'device_not_found':
      case 'not_found':
        return new AppError(404, err.message);
      case 'guard_refused':
      case 'degraded_unconfirmed':
      case 'override_reason_too_short':
      case 'nothing_to_override':
        return new AppError(422, err.message);
      case 'executor_unavailable':
        return new AppError(503, err.message);
      default:
        return new AppError(409, err.message);
    }
  }
  return err;
}

/**
 * The conditional half of the RBAC split.
 *
 * `requireCapability` covers the unconditional one at the route. This covers
 * the case where the BODY raises the bar — an override is a different act from
 * an apply and must not ride in on the apply's grant.
 */
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
      `This action additionally requires '${capability}'. Overriding the Management-Path Guard ` +
        'is a separate capability from applying a change, on purpose: the person who wants the ' +
        'change and the person who accepts the risk of forcing it are two people.',
    );
  }
}

// ============================================================================
// Schemas
// ============================================================================

const JOB_KINDS = ['push', 'export', 'backup', 'restore', 'reboot', 'firmware'] as const;

const enqueueSchema = z
  .object({
    deviceId: z.number().int().positive(),
    kind: z.enum(JOB_KINDS),
    /** The full `ApplyPlan` envelope, validated by the shared schema inside the
     *  service. Required for `push`, meaningless otherwise. */
    plan: z.unknown().optional(),
    scheduledFor: z.string().datetime().nullable().optional(),
    windowStart: z.string().datetime().nullable().optional(),
    windowEnd: z.string().datetime().nullable().optional(),
    /** Non-empty means "force a non-ACCEPT guard verdict". Requires
     *  CHANGE_APPROVE on top of CHANGE_APPLY. */
    overrideReason: z.string().min(8).max(2000).optional(),
    /** §8.3 — the explicit confirmation a DEGRADED write demands. */
    confirmDegraded: z.boolean().optional(),
    maxAttempts: z.number().int().min(1).max(3).optional(),
  })
  .strict()
  .superRefine((v, ctx) => {
    if (v.kind === 'push' && v.plan === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['plan'],
        message: 'a push needs the compiled plan it is applying',
      });
    }
    if ((v.windowStart === undefined) !== (v.windowEnd === undefined)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['windowEnd'],
        message: 'a maintenance window is a pair or it is nothing',
      });
    }
  });

const previewSchema = z
  .object({
    deviceId: z.number().int().positive(),
    kind: z.enum(JOB_KINDS),
    plan: z.unknown().optional(),
  })
  .strict();

/** Batch form of `previewSchema`. Bounded at 500: this is the screen that
 *  precedes a fleet-wide rollout, and an unbounded list would let one request
 *  open a RouterOS session per device of the whole estate. */
const preflightSchema = z
  .object({
    deviceIds: z.array(z.number().int().positive()).min(1).max(500),
    /** Optional, and 'push' by default: the blast-radius screen this serves is
     *  always about a push, and demanding the field would make the common call
     *  the verbose one. */
    kind: z.enum(JOB_KINDS).optional(),
    plan: z.unknown().optional(),
  })
  .strict();

const overrideSchema = z.object({ reason: z.string().min(8).max(2000) }).strict();
const abortSchema = z.object({ reason: z.string().max(500).optional() }).strict();

const killSwitchSchema = z
  .object({
    scope: z.enum(['global', 'tenant']).default('tenant'),
    reason: z.string().max(1000).nullable().optional(),
  })
  .strict();

/**
 * THE GLOBAL SCOPE IS NOT A TENANT GESTURE.
 *
 * These routes are mounted under the tenant-scoped router, so every capability
 * on them (`CHANGE_APPLY` to engage, `SETTINGS_MANAGE` to release) is resolved
 * inside the CALLER'S OWN tenant. `user_tenants.role = 'admin'` on one single
 * customer grants both. `scope` arrives in the BODY, and `kill_switch` has
 * exactly one global row whose meaning is "no write may be attempted on any
 * equipment of any tenant".
 *
 * Left as it was, an administrator of customer B could freeze every customer's
 * fleet — and, far worse, RELEASE the freeze an incident on customer A had just
 * put in place, sending queued jobs back onto routers mid-incident.
 *
 * The platform role is the only thing in this request that is not scoped to the
 * caller's tenant, so it is what the global scope is gated on. `requireAuth`
 * re-reads `users.role` from the database on every request, so a demoted admin
 * does not keep this. The `tenant` scope is untouched: freezing your own fleet
 * stays the fast gesture it is meant to be.
 */
function resolveKillSwitchScope(
  req: Request,
  input: { scope?: 'global' | 'tenant' },
  gesture: 'engage' | 'release',
): { scope: 'global' | 'tenant'; tenantId: number | null } {
  const scope = input.scope ?? 'tenant';
  if (scope !== 'global') return { scope: 'tenant', tenantId: req.tenantId };
  if (req.session.role !== 'admin') {
    throw new AppError(
      403,
      `Only a platform administrator may ${gesture} the GLOBAL kill switch — it ` +
        'covers every tenant. Use {"scope":"tenant"} to act on your own fleet.',
    );
  }
  return { scope: 'global', tenantId: null };
}

const auditQuerySchema = z.object({
  deviceId: z.coerce.number().int().positive().optional(),
  jobId: z.coerce.number().int().positive().optional(),
  correlationId: z.string().uuid().optional(),
  writesOnly: z.enum(['true', 'false']).optional(),
  limit: z.coerce.number().int().min(1).max(500).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

const jobQuerySchema = z.object({
  deviceId: z.coerce.number().int().positive().optional(),
  status: z.string().optional(),
  activeOnly: z.enum(['true', 'false']).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

function date(raw: string | null | undefined): Date | null {
  return raw ? new Date(raw) : null;
}

// ============================================================================
// Controller
// ============================================================================

export const changesController = {
  /**
   * What this deployment can actually do — read by the client before it renders
   * a single Apply button.
   *
   * `canApply` is TRUE from M6 on, and the fields beside it are what make that
   * true statement honest: whether a worker is running on this process, whether
   * the kill switch is engaged, and how long a soak lasts.
   */
  async config(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const view = await getKillSwitchView(req.tenantId);
      res.json({
        success: true,
        data: {
          canApply: true,
          applyMilestone: 'M6',
          mgmtPathGuard: 'enforced',
          /** False on a `web` replica: HTTP accepts the job, a worker runs it. */
          workerOnThisProcess: shouldProcessJobs(),
          soakMs: SOAK_MS,
          leaseTtlMs: LEASE_TTL_MS,
          maxConcurrentJobs: MAX_CONCURRENT_JOBS,
          killSwitch: view,
          /** Restated on every response because it is the sentence a client
           *  must not paraphrase away. */
          notice:
            'A non-ACCEPT Management-Path Guard verdict — INDETERMINATE INCLUDED — blocks the ' +
            'apply until a named operator signs an override. A DEGRADED safety net (§8.3: ' +
            'detection without recovery) requires an explicit confirmation before the job can ' +
            'even be queued.',
        },
      });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * Everything the enqueue would decide, decided, with nothing written.
   *
   * §8.3 requires the three safety levels to be shown PER DEVICE and BEFORE the
   * launch. A level computed only inside the enqueue is a level nobody saw.
   */
  async preview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(previewSchema, req.body ?? {});
      const data = await previewChange({
        tenantId: req.tenantId,
        deviceId: input.deviceId,
        kind: input.kind as ChangeJobKind,
        plan: input.plan,
      });
      res.json({ success: true, data });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * The same preview, for MANY devices at once.
   *
   * Exists because the blast-radius screen shows the §8.3 safety level of every
   * device BEFORE the launch, and the per-device route makes that N round-trips
   * — on a 300-site rollout the screen would render progressively and an
   * operator would decide on a half-filled table.
   *
   * A device that fails its own preview does NOT fail the batch: it comes back
   * with `ok: false` and its reason, because a preview whose whole point is to
   * warn must not go silent on the one device that has a problem. The caller
   * still gets every other verdict.
   */
  async preflight(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(preflightSchema, req.body ?? {});
      const results = await Promise.all(
        input.deviceIds.map(async (deviceId) => {
          try {
            const data = await previewChange({
              tenantId: req.tenantId,
              deviceId,
              kind: (input.kind ?? 'push') as ChangeJobKind,
              plan: input.plan,
            });
            return { deviceId, ok: true as const, ...data };
          } catch (err) {
            return {
              deviceId,
              ok: false as const,
              error: err instanceof Error ? err.message : 'preview failed',
            };
          }
        }),
      );
      res.json({ success: true, data: results });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** Queue a change. THE endpoint that can end in a write to a customer's box. */
  async enqueue(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(enqueueSchema, req.body ?? {});

      // The override is a SECOND capability, checked before anything is written.
      if (input.overrideReason) {
        await requireExtraCapability(req, CAPABILITIES.CHANGE_APPROVE);
      }

      const result = await enqueueChangeJob({
        tenantId: req.tenantId,
        deviceId: input.deviceId,
        kind: input.kind as ChangeJobKind,
        plan: input.plan,
        requestedBy: req.session.userId ?? null,
        override: input.overrideReason
          ? { reason: input.overrideReason, userId: req.session.userId ?? null }
          : null,
        confirmDegraded: input.confirmDegraded
          ? { userId: req.session.userId ?? null }
          : null,
        scheduledFor: date(input.scheduledFor),
        windowStart: date(input.windowStart),
        windowEnd: date(input.windowEnd),
        maxAttempts: input.maxAttempts,
      });

      res.status(201).json({ success: true, data: result });
    } catch (err) {
      next(mapError(err));
    }
  },

  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(jobQuerySchema, req.query);
      const statuses = q.status
        ? (q.status.split(',').map((s) => s.trim()).filter(Boolean) as never[])
        : undefined;
      const data = await listJobs(req.tenantId, {
        deviceId: q.deviceId,
        status: statuses,
        activeOnly: q.activeOnly === 'true',
        limit: q.limit,
        offset: q.offset,
      });
      res.json({ success: true, data });
    } catch (err) {
      next(mapError(err));
    }
  },

  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'job id');
      const row = await getJobRow(req.tenantId, id);
      if (!row) throw new AppError(404, `Change job ${id} not found`);
      res.json({
        success: true,
        data: {
          ...toJobSummary(row, row.device_name ?? ''),
          guardReasons: guardReasonsOf(row),
          overriddenBy: row.overridden_by,
          overriddenAt: row.overridden_at ? new Date(row.overridden_at).toISOString() : null,
          degradedConfirmedBy: row.degraded_confirmed_by,
          deadmanHandle: row.deadman_handle,
          confirmDeadline: row.confirm_deadline
            ? new Date(row.confirm_deadline).toISOString()
            : null,
          outcome: row.outcome,
          claimedBy: row.claimed_by,
          leaseExpiresAt: row.lease_expires_at
            ? new Date(row.lease_expires_at).toISOString()
            : null,
        },
      });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** The live job screen reads this, in order, over and over. */
  async steps(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'job id');
      const job = await getJobRow(req.tenantId, id);
      if (!job) throw new AppError(404, `Change job ${id} not found`);
      res.json({ success: true, data: await listJobSteps(req.tenantId, id) });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * Cancel a job that has NOT started writing.
   *
   * 409 once the job is `applying` or beyond, and that is not a limitation to
   * be worked around: a button that claims to stop a change already going onto
   * a router would be a button that lies at the exact moment somebody is
   * desperate enough to press it twice. The kill switch stops the NEXT write;
   * the dead-man undoes this one.
   */
  async abort(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'job id');
      const input = parse(abortSchema, req.body ?? {});
      const job = await getJobRow(req.tenantId, id);
      if (!job) throw new AppError(404, `Change job ${id} not found`);
      const row = await abortJob(req.tenantId, id, req.session.userId ?? null, input.reason ?? null);
      res.json({ success: true, data: toJobSummary(row, job.device_name ?? '') });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * Sign an override on a queued job. CHANGE_APPROVE, and only that.
   *
   * The reason is stored verbatim and is undeletable in practice — this is the
   * line somebody reads after an incident, and "forced" with no sentence beside
   * it is the same as no record at all.
   */
  async override(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'job id');
      const input = parse(overrideSchema, req.body ?? {});
      await recordOverride(req.tenantId, id, req.session.userId ?? null, input.reason);
      const row = await getJobRow(req.tenantId, id);
      res.json({
        success: true,
        data: row ? toJobSummary(row, row.device_name ?? '') : null,
      });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** `command_audit`, folded (attempt + result) into one line per command. */
  async audit(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(auditQuerySchema, req.query);
      const data = await listCommandAudit(req.tenantId, {
        deviceId: q.deviceId,
        jobId: q.jobId,
        correlationId: q.correlationId,
        writesOnly: q.writesOnly === 'true',
        limit: q.limit,
        offset: q.offset,
      });
      res.json({ success: true, data });
    } catch (err) {
      next(mapError(err));
    }
  },

  async killSwitch(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await getKillSwitchView(req.tenantId) });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * STOP. Broad by design WITHIN A TENANT: anybody who could start a push on
   * this fleet can stop every push on this fleet. `scope: 'global'` is a
   * different gesture — it covers every customer — and takes the platform
   * admin role (`resolveKillSwitchScope`).
   */
  async engage(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(killSwitchSchema, req.body ?? {});
      const { scope, tenantId } = resolveKillSwitchScope(req, input, 'engage');
      const state = await engageKillSwitch({
        scope,
        tenantId,
        reason: input.reason ?? null,
        userId: req.session.userId ?? null,
      });
      res.json({ success: true, data: state });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * Let the fleet be written to again. The stricter gesture (SETTINGS_MANAGE),
   * and stricter again for `scope: 'global'`, which needs the platform admin
   * role: releasing a global freeze puts EVERY customer back in the line of
   * fire, including the one whose incident caused it.
   */
  async release(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(killSwitchSchema, req.body ?? {});
      const { scope, tenantId } = resolveKillSwitchScope(req, input, 'release');
      const state = await releaseKillSwitch({
        scope,
        tenantId,
        reason: input.reason ?? null,
        userId: req.session.userId ?? null,
      });
      res.json({ success: true, data: state });
    } catch (err) {
      next(mapError(err));
    }
  },
};
