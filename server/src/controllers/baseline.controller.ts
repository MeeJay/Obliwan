/**
 * Fleet take-over / Golden Site (M12 — K8) — HTTP layer.
 *
 * Everything here is tenant-scoped through `req.tenantId`. The `baseline_*`
 * tables all carry `tenant_id NOT NULL` (migration 017, decision 1) and every
 * service call takes it as its first argument — there is no "current tenant"
 * read from a session inside the service layer, and no query in this milestone
 * that could return a row without one.
 *
 * ┌─ A ROW BELONGING TO ANOTHER CUSTOMER IS A 404 ────────────────────────────┐
 * │ Never a 403. A 403 confirms that the id exists, which on a table keyed by │
 * │ bigserial is an enumeration oracle over other customers' fleets.          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE MINING RUN IS SYNCHRONOUS, AND THAT IS A CHOICE WITH A CEILING ──────┐
 * │ `POST /baseline/runs` does the work inside the request. At the fifty       │
 * │ sites of the acceptance test it is a few hundred milliseconds; the        │
 * │ clustering itself is off the event loop in a worker (`cluster.ts`), the   │
 * │ extraction and the inserts are not. At the 500-site design point of §6.3  │
 * │ this becomes a request measured in seconds and it should move to pg-boss  │
 * │ like every other long job in the product — `baseline_runs` already        │
 * │ carries `status`, `started_at`, `finished_at` and `error` for exactly     │
 * │ that, and the row is written BEFORE the work starts so nothing about the  │
 * │ move changes the read model. Said here rather than left to be discovered  │
 * │ at the first customer with a large fleet.                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import {
  BASELINE_DEFAULT_PARAMS, BASELINE_DEVIATION_CLASSES, BASELINE_DEVIATION_KINDS,
  BASELINE_DRAFT_STATUSES, BASELINE_EXCEPTION_SCOPES, BASELINE_LINKAGES,
  BASELINE_MODEL_VERSION, BASELINE_RUN_STATUSES, BASELINE_SLOT_ROLES,
  BASELINE_VALUE_CLASSES, BaselineParams,
} from '@obliwan/shared/dist/baseline';
import { AppError } from '../middleware/errorHandler';
import * as baseline from '../services/baseline/miner.service';

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

const classifyBody = z.object({
  classification: z.enum(BASELINE_DEVIATION_CLASSES),
  note: z.string().max(2000).nullable().optional(),
  scope: z.enum(BASELINE_EXCEPTION_SCOPES).optional(),
  // Not `.min(1)` alone: a reason of three spaces satisfies a length check and
  // fails the database CHECK, and the operator deserves the better message.
  reason: z.string().max(2000).optional(),
}).strict();

const promoteBody = z.object({
  name: z.string().min(1).max(120),
  description: z.string().max(2000).nullable().optional(),
}).strict();

const deviationQuery = z.object({
  clusterId: z.coerce.number().int().positive().optional(),
  deviceId: z.coerce.number().int().positive().optional(),
  classification: z.enum(BASELINE_DEVIATION_CLASSES).optional(),
  kind: z.enum(BASELINE_DEVIATION_KINDS).optional(),
  // Optional rather than `.default()`: the shared `parse<T>` helper is typed on
  // `z.ZodType<T>`, which collapses input and output, so a schema-level default
  // would come back out as `number | undefined` and the page size would be
  // silently `NaN`. The defaults live at the one call site instead.
  limit: z.coerce.number().int().min(1).max(500).optional(),
  offset: z.coerce.number().int().min(0).optional(),
}).strict();

export const baselineController = {
  /**
   * The parameter surface, with its defaults and its acceptance criterion.
   * Behind CONFIG_READ like everything else: the field list names the knobs, not
   * the fleet, but it is the entry point of a screen that shows configurations.
   */
  params(_req: Request, res: Response): void {
    res.json({
      modelVersion: BASELINE_MODEL_VERSION,
      defaults: BASELINE_DEFAULT_PARAMS,
      // The whole vocabulary, in one place. A client that renders a baseline
      // has to label a run status, a slot role, a draft status and a value
      // class; shipping the lists here is what stops four copies of them from
      // being retyped on the other side and drifting from the CHECK
      // constraints of migration 017.
      linkages: BASELINE_LINKAGES,
      runStatuses: BASELINE_RUN_STATUSES,
      slotRoles: BASELINE_SLOT_ROLES,
      draftStatuses: BASELINE_DRAFT_STATUSES,
      valueClasses: BASELINE_VALUE_CLASSES,
      deviationKinds: BASELINE_DEVIATION_KINDS,
      deviationClasses: BASELINE_DEVIATION_CLASSES,
      exceptionScopes: BASELINE_EXCEPTION_SCOPES,
      stoppingRule:
        'The smallest k in 1..maxClusters such that every member of every cluster has at ' +
        'least minCoverage of its own facts explained by its cluster template. Purity is a ' +
        'hard gate; k grows only to buy it.',
    });
  },

  async run(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const params = parse(BaselineParams, req.body ?? {});
      const outcome = await baseline.runBaseline(
        req.tenantId,
        params,
        req.session?.userId ?? null,
      );
      res.status(201).json(outcome);
    } catch (err) {
      next(err);
    }
  },

  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const limit = req.query.limit ? Number(req.query.limit) : 25;
      res.json(await baseline.listRuns(req.tenantId, limit));
    } catch (err) {
      next(err);
    }
  },

  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await baseline.getRun(req.tenantId, parseId(req.params.id, 'run id')));
    } catch (err) {
      next(err);
    }
  },

  async cluster(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await baseline.getCluster(req.tenantId, parseId(req.params.id, 'cluster id')));
    } catch (err) {
      next(err);
    }
  },

  async draft(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await baseline.getDraft(req.tenantId, parseId(req.params.id, 'draft id')));
    } catch (err) {
      next(err);
    }
  },

  async deviations(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(deviationQuery, req.query);
      res.json(await baseline.listDeviations(req.tenantId, {
        runId: parseId(req.params.id, 'run id'),
        clusterId: q.clusterId,
        deviceId: q.deviceId,
        classification: q.classification,
        kind: q.kind,
        limit: q.limit ?? 100,
        offset: q.offset ?? 0,
      }));
    } catch (err) {
      next(err);
    }
  },

  async conformance(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await baseline.getConformance(req.tenantId, parseId(req.params.id, 'run id')));
    } catch (err) {
      next(err);
    }
  },

  /**
   * Classifying a deviation. `client_specific` needs a reason and produces a
   * documented exception — the service refuses a blank one, and the database
   * refuses it again.
   */
  async classify(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(classifyBody, req.body ?? {});
      res.json(await baseline.classifyDeviation(
        req.tenantId,
        parseId(req.params.id, 'deviation id'),
        body,
        req.session?.userId ?? null,
      ));
    } catch (err) {
      next(err);
    }
  },

  async exceptions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await baseline.listExceptions(req.tenantId));
    } catch (err) {
      next(err);
    }
  },

  async removeException(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      await baseline.deleteException(req.tenantId, parseId(req.params.id, 'exception id'));
      res.status(204).end();
    } catch (err) {
      next(err);
    }
  },

  /**
   * Promotion. Writes a `templates` row and a `template_revisions` row with
   * `status = 'draft'` — never a published one. TEMPLATE_WRITE is required for
   * the same reason it is required to author a template body by hand (R6): this
   * is the act that puts a body into the store the render engine reads from.
   */
  async promote(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(promoteBody, req.body ?? {});
      const out = await baseline.promoteDraft(
        req.tenantId,
        parseId(req.params.id, 'draft id'),
        body.name,
        body.description ?? null,
        req.session?.userId ?? null,
      );
      res.status(201).json(out);
    } catch (err) {
      next(err);
    }
  },
};
