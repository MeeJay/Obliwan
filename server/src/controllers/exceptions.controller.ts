/**
 * Drift exceptions (F1) — HTTP layer.
 *
 * ┌─ WHAT REPLACED WHAT ──────────────────────────────────────────────────────┐
 * │ `PATCH /api/drift/findings/:id/ignore {ignored:true}` is no longer a way  │
 * │ to accept a drift, and closing it took three files:                       │
 * │                                                                           │
 * │  019  `drift_findings_ignore_justified` refuses `ignored = true` unless   │
 * │       the row names a normalization rule or an exception. That killed the │
 * │       bare `{ignored:true}` — and nothing else, because the CHECK asks    │
 * │       for a NAME and not for a justification: `{"ignored":true,           │
 * │       "ruleId":1}` still bought a permanent, unaudited suppression, and   │
 * │       the seeded library rules guaranteed a small integer always worked.  │
 * │  022  the STORAGE half: the named rule must belong to the finding's own   │
 * │       tenant, or be a shipped library rule.                               │
 * │  now  the ROUTE half, in `drift.service.setFindingIgnored`: `ignored =    │
 * │       true` is accepted only when the layer-4 rule set genuinely produces │
 * │       the suppression — the rule must be enabled, in scope for the        │
 * │       device, a `suppress_finding`, and match the finding under the very  │
 * │       predicate a run uses. Anything else answers 409 naming this         │
 * │       controller, and BOTH outcomes append to `audit_log`.                │
 * │       `sweep()` also grew the clause that hands a finding back when the   │
 * │       rule hiding it stops applying — until then, `ignored_by_rule` was a │
 * │       one-way door.                                                       │
 * │                                                                           │
 * │ `POST /api/exceptions` is the replacement, and it costs the caller two    │
 * │ fields it did not have to supply before: WHY, and UNTIL WHEN. That is the │
 * │ whole feature.                                                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Every read and every write is scoped on `drift_exceptions.tenant_id`, and an
 * id belonging to another customer is a 404 — never a 403. "That exception
 * exists but is not yours" is itself a disclosure about another customer.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import {
  MAX_JUSTIFICATION_LENGTH,
  MIN_JUSTIFICATION_LENGTH,
  justificationProblemStrict,
  reviewDateProblem,
} from '../services/attestation/contract';
import { AppError } from '../middleware/errorHandler';
import * as exceptions from '../services/drift/exception.service';

function parseBigId(raw: string, what = 'id'): string {
  if (!/^[0-9]{1,19}$/.test(raw)) throw new AppError(400, `Invalid ${what}`);
  return raw;
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
 * The actor. `req.session.username` is a snapshot stored on the exception so
 * that "who accepted this" still has an answer after the account is deleted.
 */
function actorOf(req: Request): exceptions.Actor {
  const userId = req.session?.userId ?? null;
  const username = req.session?.username ?? 'unknown';
  return { userId, username };
}

/**
 * The justification and the review date are validated HERE only to produce a
 * sentence instead of a 23514. The database refuses them regardless — see
 * `drift_exceptions_justified_chk` and `drift_exceptions_horizon_chk`. If these
 * two ever disagree, the database wins and the API is the thing that is wrong.
 *
 * `justificationProblemStrict` and not `justificationProblem`: the shared
 * mirror measures `String.prototype.trim()`, which leaves U+200B ZERO WIDTH
 * SPACE standing, and the old CHECK measured `btrim`, which leaves every
 * no-break space standing. Thirty invisible characters passed both walls and
 * rendered as an empty justification on a suppression good for 300 days. The
 * strict form is the mirror of migration 023's replacement CHECK.
 *
 * `.min()` still counts raw characters, which is the cheap test; the refine is
 * the one that counts characters that exist.
 */
const justification = z
  .string()
  .min(MIN_JUSTIFICATION_LENGTH)
  .max(MAX_JUSTIFICATION_LENGTH)
  .superRefine((v, ctx) => {
    const problem = justificationProblemStrict(v);
    if (problem) ctx.addIssue({ code: z.ZodIssueCode.custom, message: problem });
  });

const reviewDueAt = z.string().superRefine((v, ctx) => {
  const problem = reviewDateProblem(v);
  if (problem) ctx.addIssue({ code: z.ZodIssueCode.custom, message: problem });
});

const createBody = z
  .object({
    findingId: z.string().regex(/^[0-9]{1,19}$/).optional(),
    deviceId: z.number().int().positive().optional(),
    semKey: z.string().min(1).max(180).optional(),
    resource: z.string().min(1).max(24).optional(),
    path: z.string().min(1).max(2000).nullable().optional(),
    justification,
    reviewDueAt,
  })
  .refine(
    (b) => b.findingId !== undefined || (b.deviceId !== undefined && b.semKey !== undefined
      && b.resource !== undefined),
    { message: 'Either findingId, or deviceId + semKey + resource, is required' },
  );

const renewBody = z.object({ justification, reviewDueAt });

/** A revocation is a decision and carries a reason, at the same length as a
 *  grant. "Because I said so" is not an audit trail. */
const revokeBody = z.object({ reason: justification });

const listQuery = z.object({
  deviceId: z.coerce.number().int().positive().optional(),
  state: z.enum(['active', 'expiring', 'expired', 'revoked']).optional(),
  dueWithinDays: z.coerce.number().int().min(0).max(3650).optional(),
  semKey: z.string().max(180).optional(),
  limit: z.coerce.number().int().min(1).max(1000).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

function mapError(err: unknown): unknown {
  if (err instanceof exceptions.ExceptionError) return new AppError(err.status, err.message);
  return err;
}

export const exceptionsController = {
  /** GET /api/exceptions */
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(listQuery, req.query);
      res.json({ success: true, data: await exceptions.listExceptions(req.tenantId, q) });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * GET /api/exceptions/review-queue — the screen F1 is actually for.
   *
   * Everything already expired plus everything due within the horizon, oldest
   * date first. An expired exception is at the TOP because its drift is already
   * visible again and somebody is about to ask why.
   */
  async reviewQueue(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const days = parse(z.object({ days: z.coerce.number().int().min(1).max(365).optional() }),
        req.query).days ?? 30;
      const rows = await exceptions.listExceptions(req.tenantId, { dueWithinDays: days });
      res.json({
        success: true,
        data: {
          horizonDays: days,
          expired: rows.filter((e) => e.state === 'expired'),
          dueSoon: rows.filter((e) => e.state !== 'expired' && e.state !== 'revoked'),
        },
      });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** GET /api/exceptions/:id — with its full review history. */
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await exceptions.getException(
        req.tenantId,
        parseBigId(req.params.id, 'exception id'),
      );
      if (!row) throw new AppError(404, 'Exception not found');
      res.json({ success: true, data: row });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** POST /api/exceptions — grant one. DRIFT_MANAGE. */
  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(createBody, req.body ?? {});
      const row = await exceptions.createException(req.tenantId, actorOf(req), body);
      res.status(201).json({ success: true, data: row });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** POST /api/exceptions/:id/renew — reconduction, with a NEW justification. */
  async renew(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(renewBody, req.body ?? {});
      const row = await exceptions.renewException(
        req.tenantId,
        parseBigId(req.params.id, 'exception id'),
        actorOf(req),
        body,
      );
      res.json({ success: true, data: row });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** POST /api/exceptions/:id/revoke — withdraw. The drift comes back at once. */
  async revoke(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(revokeBody, req.body ?? {});
      const row = await exceptions.revokeException(
        req.tenantId,
        parseBigId(req.params.id, 'exception id'),
        actorOf(req),
        body.reason,
      );
      res.json({ success: true, data: row });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * POST /api/exceptions/sweep — run the expiry pass now.
   *
   * Not a debug endpoint: an operator who has just revoked a batch wants the
   * fleet screen correct before the next tick, and an installation whose leader
   * has been down needs a way to catch up without a restart. It only ever moves
   * `drift_findings.ignored` to the value the exceptions already imply, so
   * running it twice does nothing the first run did not.
   *
   * SCOPED TO THE CALLER'S TENANT. This handler used to call `sweep()` with no
   * argument, and none of that function's statements carried a tenant
   * predicate: a DRIFT_MANAGE user of one customer triggered an on-demand
   * write across the `drift_findings` and `drift_runs` of every customer in the
   * installation. Nothing leaked — the pass only settles booleans — but this
   * route is mounted on the tenant router and must not be the one place that
   * ignores it. The fleet-wide form belongs to the leader's timer.
   */
  async sweep(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await exceptions.sweep({ tenantId: req.tenantId }) });
    } catch (err) {
      next(mapError(err));
    }
  },
};
