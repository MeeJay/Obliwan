/**
 * F3 — the intervention mode (ARCHITECTURE.md §10/F3), HTTP layer.
 *
 * Everything is tenant-scoped through `req.tenantId`. `interventions` carries
 * `tenant_id NOT NULL` and every service call takes it as its first argument;
 * there is no "current tenant" read from a session inside the service layer.
 *
 * ┌─ A ROW BELONGING TO ANOTHER CUSTOMER IS A 404 ────────────────────────────┐
 * │ Never a 403. A 403 confirms the id exists, which on a bigserial key is an │
 * │ enumeration oracle over other customers' fleets. Same rule as M12.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE OPERATOR IS DECLARED, NOT INFERRED ──────────────────────────────────┐
 * │ `operator` comes from the BODY and `openedBy` from the session, and they  │
 * │ are two different people often enough that conflating them would be a     │
 * │ lie: the person opening Winbox is regularly a subcontractor or the        │
 * │ customer's own admin, with no account here. What is NEVER used to         │
 * │ identify anybody is the source address — arbitrage A6, and the audit that │
 * │ found a vault secret handed to a stranger through exactly that path.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import {
  INTERVENTION_CHANNELS,
  INTERVENTION_DEFAULT_WINDOW_MINUTES,
  INTERVENTION_DISPOSITIONS,
  INTERVENTION_EVENTS,
  INTERVENTION_HARD_CAP_MINUTES,
  INTERVENTION_MAX_ATTRIBUTION_WINDOW_MINUTES,
  INTERVENTION_MIN_OVERLAP_RATIO,
  INTERVENTION_LINK_DISPOSITIONS,
  INTERVENTION_MAX_WINDOW_MINUTES,
  INTERVENTION_MIN_WINDOW_MINUTES,
  INTERVENTION_STATUSES,
} from '@obliwan/shared/dist/intervention';
import { AppError } from '../middleware/errorHandler';
// Through the barrel: the feature is two modules plus the window arithmetic
// they share, and which of the three a handler happens to need is not the
// controller's business.
import * as intervention from '../services/intervention';
import { listLinks, sweepInterventionLinks } from '../services/intervention';

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

const openBody = z
  .object({
    deviceId: z.number().int().positive(),
    // `.trim().min(1)` and not `.min(1)`: three spaces satisfy a length check
    // and then fail the database CHECK, and the operator deserves the better
    // message on this side of the wire.
    operator: z.string().trim().min(1).max(96),
    reason: z.string().trim().min(1).max(4000),
    channel: z.enum(INTERVENTION_CHANNELS).optional(),
    windowMinutes: z
      .number()
      .int()
      .min(INTERVENTION_MIN_WINDOW_MINUTES)
      .max(INTERVENTION_MAX_WINDOW_MINUTES)
      .optional(),
    collect: z.boolean().optional(),
  })
  .strict();

const closeBody = z
  .object({
    collect: z.boolean().optional(),
    notes: z.string().max(4000).nullable().optional(),
  })
  .strict();

const dispositionBody = z
  .object({
    disposition: z.enum(INTERVENTION_DISPOSITIONS),
    notes: z.string().max(4000).nullable().optional(),
  })
  .strict();

const listQuery = z
  .object({
    deviceId: z.coerce.number().int().positive().optional(),
    status: z.enum(INTERVENTION_STATUSES).optional(),
    expiredOnly: z.enum(['true', 'false']).optional(),
    unreviewedOnly: z.enum(['true', 'false']).optional(),
    limit: z.coerce.number().int().min(1).max(200).optional(),
    offset: z.coerce.number().int().min(0).optional(),
  })
  .strict();

const sweepBody = z
  .object({
    deviceId: z.number().int().positive().optional(),
    limit: z.number().int().min(1).max(1000).optional(),
  })
  .strict();

async function loadOr404(
  tenantId: number,
  id: string,
): Promise<Awaited<ReturnType<typeof intervention.getIntervention>>> {
  const row = await intervention.getIntervention(tenantId, id);
  if (!row) throw new AppError(404, 'Intervention not found');
  return row;
}

export const interventionsController = {
  /**
   * GET /api/interventions/params — the vocabulary and the ceilings.
   *
   * Shipped as DATA so the client does not retype four enums that are CHECK
   * constraints in migration 020 and would drift from them silently.
   */
  params(_req: Request, res: Response): void {
    res.json({
      success: true,
      data: {
        statuses: INTERVENTION_STATUSES,
        channels: INTERVENTION_CHANNELS,
        dispositions: INTERVENTION_DISPOSITIONS,
        // What a link between a window and a drift run can say. Shipped because
        // `GET /:id/drift` returns those values and a client that renders
        // `already_explained` as "attributed" would undo the whole precedence
        // rule on the screen.
        linkDispositions: INTERVENTION_LINK_DISPOSITIONS,
        events: INTERVENTION_EVENTS,
        window: {
          defaultMinutes: INTERVENTION_DEFAULT_WINDOW_MINUTES,
          minMinutes: INTERVENTION_MIN_WINDOW_MINUTES,
          maxMinutes: INTERVENTION_MAX_WINDOW_MINUTES,
          hardCapMinutes: INTERVENTION_HARD_CAP_MINUTES,
          maxAttributionWindowMinutes: INTERVENTION_MAX_ATTRIBUTION_WINDOW_MINUTES,
          // The second, and stricter, attribution rule. Shipped as data for the
          // same reason as the ceiling above: the screen renders
          // `window_too_wide` and has to be able to say WHY.
          minOverlapRatio: INTERVENTION_MIN_OVERLAP_RATIO,
        },
        rules: {
          notAnAuthorisation:
            'An open intervention declares that a human is working. It does not authorise ' +
            'this server to write anything: D3 stands — nothing reaches an equipment outside ' +
            'change_jobs.',
          expiry:
            'A window that is never closed expires on its own at its declared deadline, and ' +
            'says so in the intervention log. From that instant drift on the device is ' +
            'attributable again.',
          attribution:
            'A declared window claims only the drift K6 left unexplained (unattributed, ' +
            'ambiguous). A run already explained by a change job or by a named login session ' +
            'keeps its verdict and is merely linked.',
          coverage:
            'A window explains a change only when it covers at least ' +
            Math.round(INTERVENTION_MIN_OVERLAP_RATIO * 100) +
            ' % of the interval that change provably happened in. A five-minute window ' +
            'overlapping a week of uncertainty by one minute is a coincidence: it is ' +
            'recorded as window_too_wide, shown next to the change, and the platform keeps ' +
            'saying that nobody owns it.',
        },
      },
    });
  },

  /** GET /api/interventions */
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(listQuery, req.query);
      const rows = await intervention.listInterventions(req.tenantId, {
        deviceId: q.deviceId,
        status: q.status,
        expiredOnly: q.expiredOnly === 'true',
        unreviewedOnly: q.unreviewedOnly === 'true',
        limit: q.limit,
        offset: q.offset,
      });
      res.json({ success: true, data: rows });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/interventions/overview */
  async overview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await intervention.overview(req.tenantId) });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/interventions/devices/:deviceId/live */
  async live(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = Number.parseInt(req.params.deviceId, 10);
      if (!Number.isInteger(deviceId) || deviceId <= 0) {
        throw new AppError(400, 'Invalid device id');
      }
      const row = await intervention.liveInterventionFor(req.tenantId, deviceId);
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  /** POST /api/interventions */
  async open(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(openBody, req.body ?? {});
      const outcome = await intervention.openIntervention(req.tenantId, {
        ...body,
        openedBy: req.session.userId ?? null,
      });
      res.status(201).json({ success: true, data: outcome });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/interventions/:id */
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await loadOr404(req.tenantId, parseBigId(req.params.id, 'intervention id'));
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/interventions/:id/events — the lifecycle log, including expiry. */
  async events(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'intervention id');
      await loadOr404(req.tenantId, id);
      res.json({ success: true, data: await intervention.listEvents(req.tenantId, id) });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/interventions/:id/drift — what this window absorbed. */
  async links(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'intervention id');
      await loadOr404(req.tenantId, id);
      res.json({ success: true, data: await listLinks(req.tenantId, id) });
    } catch (err) {
      next(err);
    }
  },

  /** POST /api/interventions/:id/close */
  async close(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'intervention id');
      const body = parse(closeBody, req.body ?? {});
      const outcome = await intervention.closeIntervention(req.tenantId, id, {
        collect: body.collect,
        notes: body.notes ?? null,
        closedBy: req.session.userId ?? null,
      });
      res.json({ success: true, data: outcome });
    } catch (err) {
      next(err);
    }
  },

  /** POST /api/interventions/:id/cancel */
  async cancel(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'intervention id');
      const row = await intervention.cancelIntervention(
        req.tenantId,
        id,
        req.session.userId ?? null,
      );
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  /** PATCH /api/interventions/:id/disposition */
  async disposition(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'intervention id');
      const body = parse(dispositionBody, req.body ?? {});
      const row = await intervention.setDisposition(
        req.tenantId,
        id,
        body.disposition,
        body.notes ?? null,
        req.session.userId ?? null,
      );
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/interventions/sweep
   *
   * Expire what ran out, then attribute the drift the declared windows cover.
   *
   * NOT the scheduler's entry point, and the distinction matters: `index.ts`
   * arms `sweepInterventionLinks` directly on its feature-sweep timer, and
   * that function expires overdue windows itself. This endpoint exists so an
   * operator can force the pass on demand, and it calls `expireOverdue`
   * explicitly only so the response can REPORT how many windows ran out —
   * running it twice costs one indexed UPDATE that matches nothing.
   */
  async sweep(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(sweepBody, req.body ?? {});
      const expired = await intervention.expireOverdue(req.tenantId);
      const linked = await sweepInterventionLinks(req.tenantId, {
        deviceId: body.deviceId,
        limit: body.limit,
      });
      res.json({ success: true, data: { expired, linked } });
    } catch (err) {
      next(err);
    }
  },
};
