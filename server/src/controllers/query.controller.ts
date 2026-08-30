/**
 * Fleet Query (K5) — HTTP layer.
 *
 * Everything here is tenant-scoped through `req.tenantId`, which is the ONLY
 * argument the service accepts before a DSL string: `config_snapshots` and
 * `policy_results` carry no tenant column, so the join to `devices` inside the
 * compiled statement is the whole isolation. A saved-query id from another
 * customer is a 404, never a 403 — a 403 confirms the row exists.
 *
 * ┌─ WHY A PARSE ERROR IS A 400 AND NOT A 500 ────────────────────────────────┐
 * │ The DSL is a language the user writes. `QueryParseError` carries the       │
 * │ message AND the offset, both of which go back in the response body so the │
 * │ editor can underline the token. Swallowing it into "invalid query" would  │
 * │ make an unfamiliar language unusable, and the language is the feature.    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE CAPABILITY SPLIT, AND ITS ONE ACKNOWLEDGED HOLE ─────────────────────┐
 * │ `QUERY_RUN` runs and SAVES (that is its catalogue description verbatim).  │
 * │ `DRIFT_MANAGE` promotes a saved query to a POLICY and triggers an         │
 * │ evaluation, because a policy changes what the fleet screen says — the     │
 * │ same reason acknowledging a drift finding is not `DRIFT_READ`.            │
 * │                                                                          │
 * │ The hole: a holder of `QUERY_RUN` can edit the DSL of an existing policy  │
 * │ without holding `DRIFT_MANAGE`. Closing it needs a `QUERY_MANAGE`         │
 * │ capability, which is not in `CAPABILITY_CATALOG` and is not this          │
 * │ milestone's to add. Stated here rather than left to be discovered.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { DIFF_SEVERITIES, NCM_RESOURCE_KINDS } from '@obliwan/shared';
import {
  QUERY_EXAMPLES, QUERY_EXPORT_FORMATS, QUERY_LIMITS, QUERY_SCOPES,
  QUERY_UNSUPPORTED_FIELDS, SavedQueryInput, SavedQueryPatch,
  fieldsOf, isQueryScope, operatorsFor,
} from '@obliwan/shared/dist/query';
import { AppError } from '../middleware/errorHandler';
import { QueryParseError } from '../services/query/dsl';
import * as query from '../services/query/savedQuery.service';

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

/** A parse error is the user's, and it must arrive with its position intact. */
function asHttp(err: unknown): unknown {
  if (err instanceof QueryParseError) {
    const e = new AppError(400, err.message);
    (e as AppError & { offset?: number | null }).offset = err.offset;
    return e;
  }
  return err;
}

const runBody = z.object({
  dsl: z.string().min(1).max(QUERY_LIMITS.maxQueryLength),
  limit: z.number().int().min(1).max(QUERY_LIMITS.maxRows).optional(),
  offset: z.number().int().min(0).optional(),
  deviceId: z.number().int().positive().optional(),
}).strict();

const exportBody = z.object({
  dsl: z.string().min(1).max(QUERY_LIMITS.maxQueryLength),
  format: z.enum(QUERY_EXPORT_FORMATS).optional(),
  limit: z.number().int().min(1).max(QUERY_LIMITS.maxExportRows).optional(),
}).strict();

const explainBody = z.object({
  dsl: z.string().min(1).max(QUERY_LIMITS.maxQueryLength),
}).strict();

const promoteBody = z.object({
  severity: z.enum(DIFF_SEVERITIES),
}).strict();

const evaluateBody = z.object({
  deviceId: z.number().int().positive().optional(),
}).strict();

const violationsQuery = z.object({
  queryId: z.coerce.number().int().positive().optional(),
  deviceId: z.coerce.number().int().positive().optional(),
  limit: z.coerce.number().int().min(1).max(QUERY_LIMITS.maxRows).optional(),
});

const listQuery = z.object({
  policiesOnly: z.enum(['true', 'false']).optional(),
});

/** `Content-Disposition` with a filename built from a UUID and a timestamp and
 *  NOTHING the user supplied — a query name reaches this header otherwise, and
 *  a header is one of the few places a newline is still an injection. */
function attachmentName(kind: string, format: string): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `obliwan-${kind}-${stamp}.${format}`;
}

export const queryController = {
  /**
   * GET /api/query/fields
   *
   * The whitelist itself, for the editor's autocompletion. Derived from the zod
   * schemas of `shared/src/ncm/` at module load, which is why this endpoint can
   * never disagree with what the parser will accept.
   */
  async fields(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const scopes = QUERY_SCOPES.map((scope) => ({
        scope,
        fields: fieldsOf(scope).map((f) => ({
          path: f.path,
          type: f.type,
          cardinality: f.cardinality,
          nullable: f.nullable,
          values: f.values,
          operators: operatorsFor(f),
        })),
        unsupported: QUERY_UNSUPPORTED_FIELDS[scope] ?? [],
      }));
      res.json({
        success: true,
        data: {
          scopes,
          resourceKinds: NCM_RESOURCE_KINDS,
          limits: QUERY_LIMITS,
          examples: QUERY_EXAMPLES,
        },
      });
    } catch (err) { next(err); }
  },

  /** GET /api/query/fields/:scope */
  async fieldsOfScope(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const scope = req.params.scope;
      if (!isQueryScope(scope)) throw new AppError(404, `Unknown query scope '${scope}'`);
      res.json({
        success: true,
        data: {
          scope,
          fields: fieldsOf(scope).map((f) => ({ ...f, operators: operatorsFor(f) })),
          unsupported: QUERY_UNSUPPORTED_FIELDS[scope] ?? [],
        },
      });
    } catch (err) { next(err); }
  },

  /** POST /api/query/run */
  async run(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(runBody, req.body);
      const result = await query.runDsl(req.tenantId, body.dsl, {
        limit: body.limit,
        offset: body.offset,
        deviceId: body.deviceId,
      });
      res.json({ success: true, data: result });
    } catch (err) { next(asHttp(err)); }
  },

  /**
   * POST /api/query/explain
   *
   * `EXPLAIN (ANALYZE)` of the compiled statement. Shipped as a route, not left
   * as a psql recipe, because "the GIN index is used" is an acceptance
   * criterion of this milestone and a criterion nobody can check is a criterion
   * that stops being true.
   */
  async explain(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(explainBody, req.body);
      const plan = await query.explainDsl(req.tenantId, body.dsl);
      res.json({
        success: true,
        data: {
          plan,
          usesGin: plan.some((l) => l.includes('config_snapshots_ncm_gin')),
        },
      });
    } catch (err) { next(asHttp(err)); }
  },

  /** POST /api/query/export */
  async exportAdHoc(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(exportBody, req.body);
      const format = body.format ?? 'csv';
      const result = await query.runDsl(req.tenantId, body.dsl, {
        limit: Math.min(body.limit ?? QUERY_LIMITS.maxExportRows, QUERY_LIMITS.maxExportRows),
      });
      const payload = query.serialiseExport(result, format);
      res.setHeader('Content-Type', format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${attachmentName('query', format)}"`);
      res.send(payload);
    } catch (err) { next(asHttp(err)); }
  },

  // ── saved queries ─────────────────────────────────────────────────────────

  /** GET /api/query/saved */
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(listQuery, req.query);
      const rows = await query.listSavedQueries(req.tenantId, {
        policiesOnly: q.policiesOnly === 'true',
      });
      res.json({ success: true, data: rows });
    } catch (err) { next(err); }
  },

  /** GET /api/query/saved/:id */
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await query.getSavedQuery(req.tenantId, parseId(req.params.id, 'query id'));
      res.json({ success: true, data: row });
    } catch (err) { next(err); }
  },

  /**
   * POST /api/query/saved
   *
   * `isPolicy` is refused here and only here: promotion is a `DRIFT_MANAGE`
   * act, and letting it ride in on a create body would route around the
   * middleware that says so.
   */
  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(SavedQueryInput, req.body);
      if (body.isPolicy) {
        throw new AppError(
          400,
          'Save the query first, then promote it with POST /query/saved/:id/promote — '
            + 'promotion needs the drift.manage capability.',
        );
      }
      const row = await query.createSavedQuery(
        req.tenantId,
        req.session?.userId ?? null,
        body,
      );
      res.status(201).json({ success: true, data: row });
    } catch (err) { next(asHttp(err)); }
  },

  /** PATCH /api/query/saved/:id */
  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(SavedQueryPatch, req.body);
      if (body.isPolicy !== undefined) {
        throw new AppError(400, 'Use /promote and /demote to change a policy flag.');
      }
      const row = await query.updateSavedQuery(
        req.tenantId,
        parseId(req.params.id, 'query id'),
        body,
      );
      res.json({ success: true, data: row });
    } catch (err) { next(asHttp(err)); }
  },

  /** DELETE /api/query/saved/:id */
  async remove(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      await query.deleteSavedQuery(req.tenantId, parseId(req.params.id, 'query id'));
      res.json({ success: true });
    } catch (err) { next(err); }
  },

  /** POST /api/query/saved/:id/run */
  async runSaved(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(
        z.object({
          limit: z.number().int().min(1).max(QUERY_LIMITS.maxRows).optional(),
          offset: z.number().int().min(0).optional(),
        }).strict(),
        req.body ?? {},
      );
      const out = await query.runSavedQuery(
        req.tenantId,
        parseId(req.params.id, 'query id'),
        q,
      );
      res.json({ success: true, data: out });
    } catch (err) { next(asHttp(err)); }
  },

  /** GET /api/query/saved/:id/export?format=csv|json */
  async exportSaved(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const format = req.query.format === 'json' ? 'json' : 'csv';
      const out = await query.runSavedQuery(
        req.tenantId,
        parseId(req.params.id, 'query id'),
        { limit: QUERY_LIMITS.maxExportRows },
      );
      const payload = query.serialiseExport(out.result, format);
      res.setHeader('Content-Type', format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${attachmentName('query', format)}"`);
      res.send(payload);
    } catch (err) { next(asHttp(err)); }
  },

  // ── policies ──────────────────────────────────────────────────────────────

  /** POST /api/query/saved/:id/promote */
  async promote(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(promoteBody, req.body);
      const row = await query.updateSavedQuery(
        req.tenantId,
        parseId(req.params.id, 'query id'),
        { isPolicy: true, severity: body.severity },
      );
      res.json({ success: true, data: row });
    } catch (err) { next(asHttp(err)); }
  },

  /** POST /api/query/saved/:id/demote */
  async demote(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await query.updateSavedQuery(
        req.tenantId,
        parseId(req.params.id, 'query id'),
        { isPolicy: false, severity: null },
      );
      res.json({ success: true, data: row });
    } catch (err) { next(asHttp(err)); }
  },

  /**
   * POST /api/query/policies/evaluate
   *
   * Evaluates every enabled policy of the tenant — over the whole fleet, or
   * over one device with `{ deviceId }`. The second shape is the one the
   * snapshot indexer will call once M9's perimeter is stitched into M4's
   * collection path.
   */
  async evaluate(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(evaluateBody, req.body ?? {});
      const out = await query.evaluatePolicies(req.tenantId, { deviceId: body.deviceId });
      res.json({ success: true, data: out });
    } catch (err) { next(asHttp(err)); }
  },

  /** GET /api/query/policies/violations */
  async violations(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(violationsQuery, req.query);
      const rows = await query.listViolations(req.tenantId, q);
      res.json({ success: true, data: rows });
    } catch (err) { next(err); }
  },
};
