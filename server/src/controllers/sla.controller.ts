/**
 * ObliWAN F7 — the calculated SLA, HTTP layer.
 *
 * Everything is scoped through `req.tenantId`. `sla_objectives`, `sla_reports`
 * and `sla_report_intervals` all carry `tenant_id NOT NULL` (migration 026) and
 * every service call takes it as its first argument: there is no "current
 * tenant" read from a session inside the service layer, and no query in this
 * milestone can return a row without one. `ppp_sessions` and
 * `reachability_verdicts` have no tenant column at all and are scoped by an
 * INNER JOIN on `devices` — see `availability.service.ts`.
 *
 * A ROW BELONGING TO ANOTHER CUSTOMER IS A 404, NEVER A 403. A 403 confirms the
 * id exists, which on a serial is an enumeration oracle over another MSP
 * customer's estate.
 *
 * ┌─ WHAT THIS SURFACE ACCEPTS, AND WHAT IT REFUSES TO ACCEPT ────────────────┐
 * │ ACCEPTED, and this is the COMPLETE list:                                  │
 * │   from, to        the period. Bounded server-side by                      │
 * │                   `normalizePeriod` to [60 s, 366 days] — the bound lives  │
 * │                   in the service so every entry point hits it, not only   │
 * │                   this one.                                               │
 * │   siteId          which site. A FILTER, never an authorisation: the       │
 * │                   tenant filter is applied first and the id narrows what  │
 * │                   is already the caller's.                                │
 * │   kind            which interval kinds to list from a stored trail.       │
 * │   limit           page size, capped server-side.                          │
 * │                                                                          │
 * │ REFUSED, AND THE REFUSAL IS THE POINT:                                    │
 * │   an objective override. The objective comes from `sla_objectives`,       │
 * │   written only through `settings.manage`, copied onto the report and      │
 * │   folded into `params_hash`.                                              │
 * │   a verdict-validity argument. It decides how long one K7 sample speaks   │
 * │   for and therefore moves availability figures; it is a stored setting.   │
 * │   any "assume up", "tolerance" or "treat gaps as service" flag. The F2    │
 * │   audit found precisely such a parameter turning 365 days without a       │
 * │   single observation into a signed "continuous" attestation. The fix is   │
 * │   not to bound it. The fix is not to have it.                             │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING HERE TOUCHES AN EQUIPMENT (D3) ──────────────────────────────────┐
 * │ Every route reads `sites`, `devices`, `ppp_sessions`,                     │
 * │ `reachability_verdicts` and `sla_*`. The only writes are `sla_objectives`,│
 * │ `sla_reports`, `sla_report_intervals` and one `audit_log` row per issued  │
 * │ report. No socket is opened to a router; no `change_job` is enqueued.     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2): nothing on this surface can return one. The widest object it
 * serves is a count of seconds, a site code and a reason drawn from a closed
 * vocabulary. `ppp_sessions.ppp_username` is never selected by F7, and no
 * response below carries a device credential, a configuration body or a jsonb
 * a driver wrote into.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import {
  SLA_ALGORITHM_VERSION, SLA_COVERAGE_STATUSES, SLA_EXCLUDED_KINDS,
  SLA_INTERVAL_KINDS, SLA_METHOD,
  SLA_MAX_PERIOD_DAYS, SLA_OBJECTIVE_VERDICTS,
  MAX_VERDICT_VALIDITY_SECONDS, MIN_VERDICT_VALIDITY_SECONDS,
} from '@obliwan/shared/dist/sla';
import { AppError } from '../middleware/errorHandler';
import {
  OBJECTIVE_BOUNDS,
  computeAvailability, computeSiteAvailability,
  deleteObjective, deleteReport, getReport, getReportIntervals,
  issueReport, listObjectives, listReports, setObjective,
  type ComputedSiteSla,
} from '../services/sla';

// ============================================================================
// Parsing
// ============================================================================

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

/** Generic over the SCHEMA, not over its output: `isoInstant` transforms a
 *  string into a Date, so input and output types differ and a `ZodType<T>`
 *  parameter (which fixes both to `T`) would not accept it. */
function parse<S extends z.ZodTypeAny>(schema: S, value: unknown): z.infer<S> {
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

/** An ISO-8601 instant. `z.coerce.date()` accepts "0" and "true"; this does
 *  not — an unparseable period must be a 400 with a reason, not a silent
 *  1970-01-01 that produces a 56-year report. */
const isoInstant = z
  .string()
  .min(4)
  .max(64)
  .refine((s) => Number.isFinite(Date.parse(s)), 'expected an ISO-8601 date-time')
  .transform((s) => new Date(Date.parse(s)));

const periodQuery = z
  .object({
    from: isoInstant,
    to: isoInstant,
    siteId: z.coerce.number().int().positive().optional(),
  })
  .strict();

const issueBody = z
  .object({
    siteId: z.number().int().positive(),
    from: isoInstant,
    to: isoInstant,
  })
  .strict();

const objectiveBody = z
  .object({
    objectivePercent: z.number(),
    /** Bounded here AND clamped in `clampVerdictValiditySeconds` AND checked by
     *  migration 026. It is a stored SETTING behind `settings.manage`, never a
     *  parameter of a calculation. */
    verdictValiditySeconds: z.number().int()
      .min(MIN_VERDICT_VALIDITY_SECONDS).max(MAX_VERDICT_VALIDITY_SECONDS)
      .optional(),
    note: z.string().max(2000).nullable().optional(),
  })
  .strict();

const intervalQuery = z
  .object({
    kind: z.union([z.enum(SLA_INTERVAL_KINDS), z.array(z.enum(SLA_INTERVAL_KINDS))]).optional(),
  })
  .strict();

const listQuery = z
  .object({
    siteId: z.coerce.number().int().positive().optional(),
    limit: z.coerce.number().int().min(1).max(500).optional(),
  })
  .strict();

/** The audit trail is what makes the number defensible, so the API never
 *  serves the number without a way to reach it. `segments` can be tens of
 *  thousands of rows, so the computed endpoints return the SUMMARY and the
 *  count, and the stored ones expose the rows under `/intervals`. */
function toWire(r: ComputedSiteSla): Record<string, unknown> {
  return {
    siteId: r.siteId,
    siteCode: r.siteCode,
    siteName: r.siteName,
    siteTimezone: r.siteTimezone,
    deviceCount: r.deviceCount,
    period: r.period,
    availabilityPercent: r.outcome.availabilityPercent,
    worstCasePercent: r.outcome.worstCasePercent,
    bestCasePercent: r.outcome.bestCasePercent,
    coveragePercent: r.outcome.coveragePercent,
    coverageStatus: r.outcome.status,
    objectivePercent: r.outcome.objectivePercent,
    objectiveScope: r.objectiveScope,
    objectiveVerdict: r.outcome.objectiveVerdict,
    verdictReason: r.outcome.verdictReason,
    totals: r.outcome.totals,
    exclusions: r.exclusions,
    maintenanceError: r.maintenanceError,
    unreachableSamplesIgnored: r.unreachableSamplesIgnored,
    algorithmVersion: r.algorithmVersion,
    verdictValiditySeconds: r.verdictValiditySeconds,
    paramsHash: r.paramsHash,
    intervalCount: r.segments.length,
  };
}

// ============================================================================
// Controller
// ============================================================================

export const slaController = {
  /** The published method. Behind the same capability as the numbers: it names
   *  the tables the evidence is drawn from, which is a map of the schema. */
  async method(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({
        algorithmVersion: SLA_ALGORITHM_VERSION,
        method: SLA_METHOD,
        vocabularies: {
          intervalKinds: SLA_INTERVAL_KINDS,
          /** WHICH KINDS LEAVE THE CALCULATION. Served as DATA rather than
           *  described in prose, so that a customer auditing a report checks
           *  the same list the arithmetic used. */
          excludedKinds: SLA_EXCLUDED_KINDS,
          coverageStatuses: SLA_COVERAGE_STATUSES,
          objectiveVerdicts: SLA_OBJECTIVE_VERDICTS,
        },
        bounds: {
          maxPeriodDays: SLA_MAX_PERIOD_DAYS,
          minObjectivePercent: OBJECTIVE_BOUNDS.minPercent,
          maxObjectivePercent: OBJECTIVE_BOUNDS.maxPercent,
          minVerdictValiditySeconds: MIN_VERDICT_VALIDITY_SECONDS,
          maxVerdictValiditySeconds: MAX_VERDICT_VALIDITY_SECONDS,
        },
      });
    } catch (err) { next(err); }
  },

  // -- Objectives -----------------------------------------------------------

  async objectives(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ objectives: await listObjectives(req.tenantId) });
    } catch (err) { next(err); }
  },

  async setTenantObjective(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(objectiveBody, req.body);
      const objective = await setObjective(
        req.tenantId, null, body, req.session?.userId ?? null,
      );
      res.json({ objective });
    } catch (err) { next(err); }
  },

  async setSiteObjective(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const siteId = parseId(req.params.siteId, 'site id');
      const body = parse(objectiveBody, req.body);
      const objective = await setObjective(
        req.tenantId, siteId, body, req.session?.userId ?? null,
      );
      res.json({ objective });
    } catch (err) { next(err); }
  },

  async clearTenantObjective(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const removed = await deleteObjective(req.tenantId, null);
      if (!removed) throw new AppError(404, 'No tenant objective configured');
      res.json({ deleted: true });
    } catch (err) { next(err); }
  },

  async clearSiteObjective(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const siteId = parseId(req.params.siteId, 'site id');
      const removed = await deleteObjective(req.tenantId, siteId);
      if (!removed) throw new AppError(404, 'No objective configured for that site');
      res.json({ deleted: true });
    } catch (err) { next(err); }
  },

  // -- Computed (nothing stored) --------------------------------------------

  /** Availability for every site of the tenant, or one of them via `?siteId=`. */
  async availability(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(periodQuery, req.query);
      const sites = await computeAvailability({
        tenantId: req.tenantId,
        from: q.from,
        to: q.to,
        siteIds: q.siteId === undefined ? undefined : [q.siteId],
      });
      res.json({
        period: { from: q.from.toISOString(), to: q.to.toISOString() },
        algorithmVersion: SLA_ALGORITHM_VERSION,
        sites: sites.map(toWire),
      });
    } catch (err) { next(err); }
  },

  /** One site, with the full classification. `segments` is bounded by the
   *  period cap, and it is served because "prove it" is the request this
   *  feature exists to answer. */
  async siteAvailability(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const siteId = parseId(req.params.siteId, 'site id');
      const q = parse(periodQuery.omit({ siteId: true }), req.query);
      const report = await computeSiteAvailability(req.tenantId, siteId, q.from, q.to);
      res.json({
        ...toWire(report),
        intervals: report.segments.map((s) => ({
          startedAt: new Date(s.start).toISOString(),
          endedAt: new Date(s.end).toISOString(),
          seconds: Math.round((s.end - s.start) / 1000),
          kind: s.kind,
          reason: s.reason,
        })),
      });
    } catch (err) { next(err); }
  },

  // -- Stored reports -------------------------------------------------------

  async issue(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(issueBody, req.body);
      const { report } = await issueReport({
        tenantId: req.tenantId,
        siteId: body.siteId,
        from: body.from,
        to: body.to,
        actorUserId: req.session?.userId ?? null,
        actorName: req.session?.username ?? null,
      });
      res.status(201).json({ report });
    } catch (err) { next(err); }
  },

  async reports(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(listQuery, req.query);
      res.json({ reports: await listReports(req.tenantId, q) });
    } catch (err) { next(err); }
  },

  async report(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'report id');
      const report = await getReport(req.tenantId, id);
      if (!report) throw new AppError(404, 'Report not found');
      res.json({ report });
    } catch (err) { next(err); }
  },

  /** The audit trail. `?kind=excluded_management` answers "what exactly did you
   *  take off my invoice, and why". */
  async reportIntervals(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'report id');
      const q = parse(intervalQuery, req.query);
      const report = await getReport(req.tenantId, id);
      if (!report) throw new AppError(404, 'Report not found');
      const kinds = q.kind === undefined
        ? undefined
        : (Array.isArray(q.kind) ? q.kind : [q.kind]);
      res.json({
        reportId: report.id,
        intervals: await getReportIntervals(req.tenantId, id, kinds),
      });
    } catch (err) { next(err); }
  },

  async removeReport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'report id');
      const removed = await deleteReport(req.tenantId, id);
      if (!removed) throw new AppError(404, 'Report not found');
      res.json({ deleted: true });
    } catch (err) { next(err); }
  },
};
