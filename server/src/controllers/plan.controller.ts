// ============================================================================
// ObliWAN — plan compilation : HTTP layer
// ============================================================================
//
// NOTHING UNDER THIS CONTROLLER TOUCHES AN EQUIPMENT. Compiling a plan reads
// two documents and writes at most one `config_renders` row. Applying is M6 and
// has no route here at all — the endpoint does not exist, so it cannot be
// mis-permissioned, which is the same argument that keeps `SECRET_READ` off the
// devices controller.
//
// RBAC: `PLAN_CREATE`. It is deliberately NOT `TEMPLATE_WRITE`: compiling a
// plan executes a STORED revision, whose body got into the database under
// `TEMPLATE_WRITE` and is frozen. An operator who may not author a template may
// still ask "what would ObliWAN change on this box", and the capability matrix
// grants exactly that pair (`TEMPLATE_READ` + `PLAN_CREATE`) to the operator
// role.
//
// ┌─ THE ONE THING THIS FILE MUST NOT LET THROUGH ───────────────────────────┐
// │ A plan carries `baseStateHash`: the `ncm_hash` of the snapshot it was     │
// │ computed against. `POST /plan/validate` is what an approval screen calls  │
// │ before showing the Approve button, and what M6 will call on a FRESH       │
// │ snapshot immediately before writing. A plan whose base state no longer    │
// │ matches is REFUSED — 409, not a warning — because a stale plan applied to │
// │ a box somebody edited in Winbox is how an operator deletes a rule they    │
// │ never saw.                                                                │
// └──────────────────────────────────────────────────────────────────────────┘

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { ApplyPlan } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import { db } from '../db';
import {
  compilePlan, compileForDevices, checkPlanFreshness, summarize,
  PlanCompilationError, StalePlanError, PlanExpiredError, PLAN_TTL_MS,
  type PlanCompilation,
} from '../services/plan/planner.service';
import {
  RenderRefusedError, RenderTargetError, NoParserError,
} from '../services/template/render.service';
import { VariableResolutionError } from '../services/template/variableResolver.service';

// ============================================================================
// Parsing
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

function mapError(err: unknown): unknown {
  if (err instanceof AppError) return err;
  if (err instanceof StalePlanError) return new AppError(409, err.message);
  if (err instanceof PlanExpiredError) return new AppError(409, err.message);
  if (err instanceof RenderTargetError) return new AppError(404, err.message);
  if (err instanceof RenderRefusedError) return new AppError(409, err.message);
  if (err instanceof NoParserError) return new AppError(503, err.message);
  if (err instanceof VariableResolutionError) {
    const e = new AppError(422, err.message) as AppError & { details?: unknown };
    e.details = { missing: err.missing, typeErrors: err.typeErrors, chain: err.chain };
    return e;
  }
  if (err instanceof PlanCompilationError) {
    // `no_snapshot` is a precondition the operator can fix (collect first);
    // everything else is a conflict between the template and the device.
    return new AppError(err.reason === 'no_snapshot' ? 409 : 422, err.message);
  }
  return err;
}

const compileOneSchema = z.object({
  /** Compile a specific revision instead of the assigned one — the "what would
   *  revision 7 do to this box" question an approver asks before promoting it. */
  revisionId: z.number().int().positive().nullable().optional(),
  /** Compare against a specific snapshot instead of the latest. */
  snapshotId: z.string().regex(/^[0-9]{1,19}$/).nullable().optional(),
  /** Preview mode: do not write a `config_renders` row. */
  persistRender: z.boolean().optional(),
});

const compileFleetSchema = z
  .object({
    deviceIds: z.array(z.number().int().positive()).min(1).max(500).optional(),
    groupId: z.number().int().positive().optional(),
    revisionId: z.number().int().positive().nullable().optional(),
    persistRender: z.boolean().optional(),
  })
  .superRefine((v, ctx) => {
    if (!v.deviceIds && v.groupId === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['deviceIds'],
        message: 'provide deviceIds or groupId',
      });
    }
  });

/**
 * The freshness request.
 *
 * The FULL plan is accepted and parsed with the shared `ApplyPlan` schema, so
 * that a plan compiled by one server version cannot be handed to another and
 * silently reinterpreted — which is exactly what the schema exists for. Only
 * three fields are read, but validating the whole envelope is what makes
 * "this is a plan I produced" checkable at all.
 */
const validatePlanSchema = z.object({ plan: ApplyPlan });

// ============================================================================
// Shaping
// ============================================================================

/**
 * `before` / `after` on a `PlanOp` are whole NCM resources. On a fifty-op plan
 * that is a large payload, and the fleet screen only needs the shape. `full`
 * is opt-in per request rather than a second endpoint, so there is one code
 * path producing the plan and one deciding how much of it to ship.
 */
function planDto(c: PlanCompilation, full: boolean) {
  const ops = full
    ? c.plan.ops
    : c.plan.ops.map((op) => ({ ...op, before: null, after: null }));
  return {
    plan: { ...c.plan, ops },
    summary: summarize(c),
    detail: {
      deviceName: c.detail.deviceName,
      renderId: c.detail.renderId,
      revisionId: c.detail.revisionId,
      revision: c.detail.revision,
      templateId: c.detail.templateId,
      observedSnapshotId: c.detail.observedSnapshotId,
      observedCapturedAt: c.detail.observedCapturedAt,
      claimedKinds: c.detail.claimedKinds,
      signals: c.detail.signals,
      deletionsBlocked: c.detail.deletionsBlocked,
      warnings: c.detail.warnings,
      diff: {
        findingCount: c.detail.diff.findings.length,
        inertMoveCount: c.detail.diff.inertMoveCount,
        outOfScopeCount: c.detail.diff.outOfScopeCount,
        suppressed: c.detail.diff.suppressed,
        scope: c.detail.diff.scope,
      },
    },
    /**
     * Restated on every response because it is the one thing a reader of this
     * payload must not assume: M5 has no forwarding engine, so no plan it
     * compiles may claim the management path survives.
     */
    notice:
      'This plan has NOT been applied and M5 cannot apply it. `mgmtPathVerdict` is ' +
      '`indeterminate` by construction: the Management-Path Guard (K2) is milestone M6, ' +
      'and until it exists no plan may claim the management path survives.',
  };
}

// ============================================================================
// Controller
// ============================================================================

export const planController = {
  /** Compile a plan for one device. */
  async compileDevice(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const input = parse(compileOneSchema, req.body ?? {});
      const compilation = await compilePlan(req.tenantId, deviceId, {
        revisionId: input.revisionId ?? null,
        snapshotId: input.snapshotId ?? null,
        persistRender: input.persistRender !== false,
        createdBy: req.session.userId ?? null,
      });
      res.json({ success: true, data: planDto(compilation, true) });
    } catch (err) { next(mapError(err)); }
  },

  /**
   * Compile for a set of devices — the milestone's recipe (a) and the input to
   * the blast-radius screen of M7.
   *
   * Failures are RETURNED, not thrown: one device with no snapshot must not
   * hide the twenty-nine plans that compiled correctly, and an operator needs
   * to see which nine boxes are missing a variable.
   */
  async compileFleet(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(compileFleetSchema, req.body);
      const deviceIds = input.deviceIds ?? (await devicesOfGroup(req.tenantId, input.groupId as number));
      if (deviceIds.length === 0) {
        res.json({ success: true, data: { plans: [], failures: [], summary: emptyFleetSummary() } });
        return;
      }
      const result = await compileForDevices(req.tenantId, deviceIds, {
        revisionId: input.revisionId ?? null,
        persistRender: input.persistRender !== false,
        createdBy: req.session.userId ?? null,
      });
      res.json({
        success: true,
        data: {
          // Ops omitted on the fleet view; `POST /plan/devices/:id` serves one
          // plan in full when the operator opens it.
          plans: result.plans.map((c) => planDto(c, false)),
          failures: result.failures,
          summary: {
            devices: deviceIds.length,
            compiled: result.plans.length,
            failed: result.failures.length,
            high: result.plans.filter((c) => c.plan.riskLevel === 'high').length,
            touchingManagementPath:
              result.plans.filter((c) => c.plan.blastRadius.touchesManagementPath).length,
            withBlockedOps:
              result.plans.filter((c) => c.plan.ops.some((o) => o.kind === 'blocked')).length,
            notConverging: result.plans.filter((c) => !c.plan.orderConverges).length,
          },
        },
      });
    } catch (err) { next(mapError(err)); }
  },

  /**
   * Is this plan still applicable?
   *
   * 200 with `fresh: true` when the device is still exactly as the plan
   * described it. 409 when it is not — a stale plan is not a warning, it is a
   * refusal, and answering 200 with a flag invites a client to ignore it.
   */
  async validate(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { plan } = parse(validatePlanSchema, req.body);
      const verdict = await checkPlanFreshness(req.tenantId, plan);
      if (!verdict.fresh) {
        const err = new AppError(
          409,
          verdict.currentStateHash === null
            ? `The device has no configuration snapshot any more; recompile the plan.`
            : verdict.currentStateHash !== plan.baseStateHash
              ? `This plan is STALE. It was computed against device state ` +
                `${plan.baseStateHash.slice(0, 12)}… and device #${plan.deviceId} is now at ` +
                `${verdict.currentStateHash.slice(0, 12)}…. Somebody changed the configuration ` +
                'since the plan was compiled — recompile it and review the new operations.'
              : `This plan expired at ${plan.expiresAt}. Recompile it.`,
        ) as AppError & { details?: unknown };
        err.details = verdict;
        next(err);
        return;
      }
      res.json({ success: true, data: verdict });
    } catch (err) { next(mapError(err)); }
  },

  /** How long a compiled plan stays valid, so the client can show a countdown
   *  instead of discovering the expiry on the Approve click. */
  async config(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // These three were hardcoded to "M5 cannot apply" and stayed that way after
      // M6 shipped the write path — the client reads `canApply` to decide whether
      // to offer the Apply button at all, so a stale `false` here silently hides a
      // feature that works. Now reported from what is actually mounted.
      res.json({
        success: true,
        data: {
          planTtlMs: PLAN_TTL_MS,
          // Applying goes through change_jobs (D3), never from this controller.
          canApply: true,
          // Kept, and null on purpose: the client types it as `string | null` and
          // shows it as "waiting for milestone X" under a disabled control. Now
          // that applying works, no milestone gates it — removing the field would
          // have broken the client's parser, and leaving 'M6' would have put a
          // reassuring sentence under a control that is in fact enabled.
          applyMilestone: null,
          applyRoute: '/api/changes/jobs',
          mgmtPathGuard: 'enforced',
          // The client must not present a rejected or indeterminate verdict as a
          // warning: overriding either one demands CHANGE_APPROVE and a written,
          // signed reason, which the database refuses to store empty.
          overrideCapability: 'change.approve',
        },
      });
    } catch (err) { next(err); }
  },
};

// ============================================================================
// Helpers
// ============================================================================

/**
 * Every device under a group, INCLUDING its descendants, scoped by tenant on
 * both the closure and the device.
 *
 * The tenant filter appears twice on purpose (AUDIT-SEC #9): `group_closure`
 * carries no composite foreign key, so a forged edge naming another tenant's
 * group is insertable, and a walk that trusted the closure alone would compile
 * plans for another customer's fleet.
 */
async function devicesOfGroup(tenantId: number, groupId: number): Promise<number[]> {
  const group = await db('device_groups').where({ id: groupId, tenant_id: tenantId }).first('id');
  if (!group) throw new AppError(404, `Group ${groupId} not found`);
  const rows = (await db('devices as d')
    .join('group_closure as gc', 'gc.descendant_id', 'd.group_id')
    .join('device_groups as g', 'g.id', 'gc.descendant_id')
    .where('gc.ancestor_id', groupId)
    .where('g.tenant_id', tenantId)
    .where('d.tenant_id', tenantId)
    .distinct('d.id as id')
    .orderBy('d.id')) as { id: number }[];
  return rows.map((r) => r.id);
}

function emptyFleetSummary() {
  return {
    devices: 0, compiled: 0, failed: 0, high: 0,
    touchingManagementPath: 0, withBlockedOps: 0, notConverging: 0,
  };
}
