/**
 * Drift runs and findings — HTTP layer.
 *
 * Tenant scoping goes finding -> run -> device -> tenant on every single read,
 * because neither `drift_runs` nor `drift_findings` carries a tenant column.
 * A cross-tenant id is a 404.
 *
 * ┌─ IGNORING IS AN ACT, NOT A DELETE ────────────────────────────────────────┐
 * │ `PATCH /findings/:id/ignore` flips a boolean and records WHICH RULE       │
 * │ silenced the finding. The row stays. Six months later "we saw it and      │
 * │ chose to ignore it" and "we never saw it" are still distinguishable, and  │
 * │ `drift_runs.max_severity` is recomputed so an ignored critical stops      │
 * │ keeping the device red — and un-ignoring turns it red again without a     │
 * │ fresh run.                                                                │
 * │                                                                           │
 * │ WHICH RULE, and only a rule that really applies. This route no longer     │
 * │ accepts a human's decision to hide a finding: that is `POST              │
 * │ /api/exceptions`, which asks WHY and UNTIL WHEN. Every call — accepted or │
 * │ refused — appends to `audit_log`.                                         │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { DIFF_KINDS, DIFF_SEVERITIES, NCM_RESOURCE_KINDS } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import * as drift from '../services/drift/drift.service';

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

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

const runsQuery = z.object({
  deviceId: z.coerce.number().int().positive().optional(),
  status: z.enum(drift.DRIFT_STATUSES).optional(),
  cause: z.enum(drift.DRIFT_CAUSES).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

const findingsQuery = z.object({
  deviceId: z.coerce.number().int().positive().optional(),
  severity: z.enum(DIFF_SEVERITIES).optional(),
  kind: z.enum(DIFF_KINDS).optional(),
  resource: z.enum(NCM_RESOURCE_KINDS).optional(),
  includeIgnored: z.enum(['true', 'false']).optional(),
  limit: z.coerce.number().int().min(1).max(1000).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

const runBody = z.object({
  // `renormalization` and `model_upgrade` are NOT accepted from a client: §6.5
  // makes them a conclusion the engine draws from the two documents, and a
  // cause a caller can assert is a cause a caller can use to dodge attribution.
  cause: z.enum(['scheduled', 'manual', 'post_change', 'takeover']).optional(),
  scope: z.enum(['managed_only', 'full']).optional(),
  baselineSnapshotId: z.string().regex(/^[0-9]{1,19}$/).optional(),
  snapshotId: z.string().regex(/^[0-9]{1,19}$/).optional(),
  collect: z.boolean().optional(),
  fuzzy: z.boolean().optional(),
});

const ignoreBody = z.object({
  ignored: z.boolean(),
  /**
   * The `normalization_rules` row that ALREADY suppresses this finding.
   *
   * Not "the reason the caller would like to give": the service resolves it
   * under the finding's own tenant and re-runs the layer-4 predicate against
   * the finding before accepting it. A request with no `ruleId`, or with one
   * that does not actually match, is a human accepting a drift and is answered
   * 409 pointing at `POST /api/exceptions`.
   */
  ruleId: z.number().int().positive().nullable().optional(),
});

export const driftController = {
  /** GET /api/drift/runs */
  async listRuns(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(runsQuery, req.query);
      res.json({ success: true, data: await drift.listRuns(req.tenantId, q) });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/drift/runs/:id */
  async getRun(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await drift.getRun(req.tenantId, parseBigId(req.params.id, 'run id'));
      if (!row) throw new AppError(404, 'Drift run not found');
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/drift/runs/:id/findings */
  async listRunFindings(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const runId = parseBigId(req.params.id, 'run id');
      const run = await drift.getRun(req.tenantId, runId);
      if (!run) throw new AppError(404, 'Drift run not found');
      const q = parse(findingsQuery, req.query);
      const rows = await drift.listFindings(req.tenantId, {
        ...q,
        runId,
        includeIgnored: q.includeIgnored === 'true',
      });
      res.json({ success: true, data: { run, findings: rows } });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/drift/findings */
  async listFindings(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(findingsQuery, req.query);
      const rows = await drift.listFindings(req.tenantId, {
        ...q,
        includeIgnored: q.includeIgnored === 'true',
      });
      res.json({ success: true, data: rows });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/drift/findings/:id */
  async getFinding(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await drift.getFinding(req.tenantId, parseBigId(req.params.id, 'finding id'));
      if (!row) throw new AppError(404, 'Finding not found');
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  /**
   * PATCH /api/drift/findings/:id/ignore — DRIFT_MANAGE.
   *
   * Records that the NORMALIZATION ENGINE silences this finding. It is not the
   * way to accept a drift: see the box on `drift.service.setFindingIgnored`.
   * A refusal is a 409 naming `POST /api/exceptions`, and it leaves an
   * `audit_log` row of its own.
   */
  async setIgnored(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(ignoreBody, req.body);
      const row = await drift.setFindingIgnored(
        req.tenantId,
        parseBigId(req.params.id, 'finding id'),
        { ignored: body.ignored, ruleId: body.ruleId ?? null },
        // The username is a snapshot in the ledger: "who hid this" must still
        // have an answer after the account is gone.
        { userId: req.session?.userId ?? null, username: req.session?.username ?? 'unknown' },
      );
      if (!row) throw new AppError(404, 'Finding not found');
      res.json({ success: true, data: row });
    } catch (err) {
      if (err instanceof drift.IgnoreRefused) {
        next(new AppError(err.status, err.message));
        return;
      }
      if (typeof err === 'object' && err !== null && (err as { code?: string }).code === '23503') {
        next(new AppError(400, 'ruleId does not reference an existing normalization rule'));
        return;
      }
      next(err);
    }
  },

  /** POST /api/drift/devices/:deviceId/run — evaluate one device now. */
  async run(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(runBody, req.body ?? {});
      const summary = await drift.runDrift(
        req.tenantId,
        parseId(req.params.deviceId, 'device id'),
        body,
      );
      if (!summary) throw new AppError(404, 'Device not found');
      res.json({ success: true, data: summary });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/drift/status — the fleet roll-up, and the R3 instrument. */
  async status(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await drift.fleetStatus(req.tenantId) });
    } catch (err) {
      next(err);
    }
  },
};
