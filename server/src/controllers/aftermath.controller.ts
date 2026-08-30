/**
 * F4 — change → telemetry correlation (ARCHITECTURE.md §10/F4), HTTP layer.
 *
 * ┌─ THE WORD THIS SURFACE IS BUILT AROUND IS "SINCE" ────────────────────────┐
 * │ Every payload returned here is a correlation over a long window. The      │
 * │ `disclaimer` field is served with EVERY report, not as decoration but     │
 * │ because the client renders what the server sends: a screen that shows     │
 * │ `DEGRADED` next to a change id, with no sentence saying what that does    │
 * │ and does not mean, is a screen that reads as an accusation. §10/F4 is     │
 * │ explicit — "un produit qui accuse à tort un changement sain apprend à ses │
 * │ utilisateurs à ignorer ses alertes".                                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Tenant scoping: `change_aftermath` deliberately carries NO foreign key
 * (migration 020, decision 6 — it is part of the §8.3 corpus like
 * `apply_outcomes`), so `req.tenantId` reaching the service is the ONLY
 * isolation this table has. Every handler passes it.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import {
  AFTERMATH_CORRELATION_PHRASE,
  AFTERMATH_METRICS,
  AFTERMATH_SIGNAL_OUTCOMES,
  AFTERMATH_TUNING,
  AFTERMATH_VERDICTS,
} from '@obliwan/shared/dist/intervention';
import { AppError } from '../middleware/errorHandler';
import * as aftermath from '../services/change/aftermath.service';

/**
 * Served with every report. One sentence, and it is the product decision of
 * §10/F4 made visible rather than left in a comment.
 */
const DISCLAIMER =
  'These numbers describe what the telemetry has done SINCE this change, over the horizon ' +
  'window. They do not establish that the change caused it: a correlation on one device over ' +
  'one window is a reason to look, never a verdict on the change. Subjects that were already ' +
  'unhealthy BEFORE the change are excluded from the comparison and counted separately.';

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

const evaluateBody = z
  .object({
    jobId: z.string().regex(/^[0-9]{1,19}$/).optional(),
    interventionId: z.string().regex(/^[0-9]{1,19}$/).optional(),
    horizonDays: z
      .number()
      .int()
      .min(AFTERMATH_TUNING.horizonDaysMin)
      .max(AFTERMATH_TUNING.horizonDaysMax)
      .optional(),
    /** Compute without storing. Useful to look at a shorter horizon without
     *  polluting the §8.3 corpus with a second row for the same change. */
    preview: z.boolean().optional(),
  })
  .strict()
  .refine((b) => (b.jobId === undefined) !== (b.interventionId === undefined), {
    message: 'exactly one of jobId or interventionId is required',
  });

const listQuery = z
  .object({
    deviceId: z.coerce.number().int().positive().optional(),
    verdict: z.enum(AFTERMATH_VERDICTS).optional(),
    jobId: z.string().regex(/^[0-9]{1,19}$/).optional(),
    interventionId: z.string().regex(/^[0-9]{1,19}$/).optional(),
    degradedOnly: z.enum(['true', 'false']).optional(),
    limit: z.coerce.number().int().min(1).max(200).optional(),
    offset: z.coerce.number().int().min(0).optional(),
  })
  .strict();

const sweepBody = z
  .object({
    horizonDays: z
      .number()
      .int()
      .min(AFTERMATH_TUNING.horizonDaysMin)
      .max(AFTERMATH_TUNING.horizonDaysMax)
      .optional(),
    limit: z.number().int().min(1).max(500).optional(),
  })
  .strict();

export const aftermathController = {
  /** GET /api/aftermath/params */
  params(_req: Request, res: Response): void {
    res.json({
      success: true,
      data: {
        metrics: AFTERMATH_METRICS,
        outcomes: AFTERMATH_SIGNAL_OUTCOMES,
        verdicts: AFTERMATH_VERDICTS,
        tuning: AFTERMATH_TUNING,
        phrase: AFTERMATH_CORRELATION_PHRASE,
        disclaimer: DISCLAIMER,
        rules: {
          baseline:
            'The baseline is the same horizon BEFORE the change, from the same hourly ' +
            'rollups. The hour bucket containing the change belongs to neither side.',
          preexisting:
            'An interface already erroring, a link already saturated, a device already ' +
            'flapping or already restarting is EXCLUDED from the comparison and reported as ' +
            'context. Blaming a pre-existing fault on a change is the failure this feature ' +
            'is built to avoid.',
          insufficient:
            'INSUFFICIENT_DATA is never folded into STABLE. A device nobody polls has not ' +
            'been proven healthy; it has not been looked at.',
        },
      },
    });
  },

  /** POST /api/aftermath/evaluate */
  async evaluate(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(evaluateBody, req.body ?? {});
      const report = await aftermath.evaluateAftermath(
        req.tenantId,
        { jobId: body.jobId, interventionId: body.interventionId },
        { horizonDays: body.horizonDays, persist: body.preview !== true },
      );
      res.json({ success: true, data: { report, disclaimer: DISCLAIMER } });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/aftermath */
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(listQuery, req.query);
      const rows = await aftermath.listAftermath(req.tenantId, {
        deviceId: q.deviceId,
        verdict: q.verdict,
        jobId: q.jobId,
        interventionId: q.interventionId,
        degradedOnly: q.degradedOnly === 'true',
        limit: q.limit,
        offset: q.offset,
      });
      res.json({ success: true, data: { reports: rows, disclaimer: DISCLAIMER } });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/aftermath/:id */
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await aftermath.getAftermath(
        req.tenantId,
        parseBigId(req.params.id, 'aftermath id'),
      );
      if (!row) throw new AppError(404, 'Aftermath report not found');
      res.json({ success: true, data: { report: row, disclaimer: DISCLAIMER } });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/aftermath/sweep — the J+7 engine.
   *
   * Evaluates every change job of this tenant whose observation window is now
   * complete and that nobody has looked at. Synchronous and bounded by `limit`
   * for the same reason M12's mining run is: the work is a handful of indexed
   * aggregate queries per job, and moving it to pg-boss is a change of caller,
   * not of shape.
   */
  async sweep(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(sweepBody, req.body ?? {});
      const outcome = await aftermath.sweepAftermath(req.tenantId, {
        horizonDays: body.horizonDays,
        limit: body.limit,
      });
      res.json({ success: true, data: { ...outcome, disclaimer: DISCLAIMER } });
    } catch (err) {
      next(err);
    }
  },
};
