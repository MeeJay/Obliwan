/**
 * ObliWAN F6 — identity watch, HTTP layer.
 *
 * ┌─ EVERY READ IS SCOPED BY `req.tenantId`, AND NOTHING ELSE ────────────────┐
 * │ `device_identity_observations`, `device_identity_reference` and           │
 * │ `device_identity_events` all carry `tenant_id NOT NULL` tied to the       │
 * │ device's by a composite foreign key (migration 025), and every service    │
 * │ call below takes it as its FIRST argument. There is no "current tenant"   │
 * │ read inside the service layer and no query in this feature can return a   │
 * │ row without one. `config_snapshots` is the one table involved that has no │
 * │ tenant column (migration 007); `baselineTrust()` reaches it by joining    │
 * │ `devices` and filtering on `d.tenant_id`.                                 │
 * │                                                                          │
 * │ A ROW BELONGING TO ANOTHER CUSTOMER IS A 404, NEVER A 403. A 403 confirms │
 * │ the id exists, which on a serial `devices.id` is an enumeration oracle    │
 * │ over another MSP customer's fleet.                                        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT THIS SURFACE ACCEPTS FROM A CALLER, AND WHAT IT CANNOT ─────────────┐
 * │ ACCEPTS: `deviceId`, `kind`, `severity`, `pending`, `invalidating`,       │
 * │ `sinceHours`, `limit`, `historyLimit` (all NARROWING read filters, all    │
 * │ clamped server-side) and the acknowledgement note.                        │
 * │                                                                          │
 * │ CANNOT ACCEPT — AND THIS IS THE POINT: AN IDENTITY.                       │
 * │ There is no route on this router that takes a serial, a system identity,  │
 * │ a model or a firmware version in its body. The only way an observation    │
 * │ enters the system is `POST /devices/:deviceId/observe`, which DIALS THE   │
 * │ BOX and records what the box said. A caller who could post a snapshot     │
 * │ could manufacture a `hardware_replacement` against a competitor's site,   │
 * │ or — far worse — post the OLD serial to make a real replacement look      │
 * │ like "no change" and bury it. `source` is likewise a server-side literal  │
 * │ at the call site (`probe` for the button, `sweep` for the pass), never a  │
 * │ field: a caller able to choose it could dress a hand-made observation as  │
 * │ a background fact.                                                        │
 * │                                                                          │
 * │ NO PARAMETER ON THIS SURFACE CHANGES A VERDICT. `limit` and `sinceHours`  │
 * │ change how much of the answer you see; `classifyIdentityChange()` reads   │
 * │ exactly two things, and both come from inside: the stored reference and   │
 * │ the socket.                                                               │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2 / R10): nothing on this surface can return one. The widest
 * object it serves is a device's serial number, hostname, model designation
 * and firmware version, plus the sentence an operator typed when
 * acknowledging an event. `baselineTrust()` returns a snapshot's `id` and
 * `captured_at` and NEVER its content — which is why that one route sits
 * behind CONFIG_READ; see `routes/identity.routes.ts`.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { IDENTITY_EVENT_KINDS, IDENTITY_EVENT_SEVERITIES } from '@obliwan/shared/dist/identity';
import { AppError } from '../middleware/errorHandler';
import {
  IdentityWatchError,
  MAX_EVENT_PAGE,
  MAX_SWEEP_DEVICES,
  acknowledgeIdentityEvent,
  baselineTrust,
  getDeviceIdentity,
  getIdentityEvent,
  listIdentityEvents,
  observeDeviceIdentity,
  sweepTenantIdentities,
} from '../services/fleet/identityWatch.service';

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

/** Generic over the SCHEMA, not over its output: `z.ZodType<T>` pins input and
 *  output to the same type, which a schema carrying a `.transform()` (the
 *  `flag` below turns `"true"` into `true`) can never satisfy. */
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

/**
 * The service speaks in HTTP statuses because "this device is not in your
 * tenant" is a 404 and "this event was already acknowledged" is a 409, and
 * neither is a 500. Translated here, once, rather than in seven handlers.
 *
 * It RETURNS the error rather than throwing it: every handler below is
 * `async`, and Express 4 does not catch a rejected promise — a translator that
 * threw inside a `catch` would turn a clean 404 into a hung request.
 */
function httpError(err: unknown): unknown {
  if (err instanceof IdentityWatchError) return new AppError(err.status, err.message);
  return err;
}

// -- Query shapes. `.strict()` everywhere: an unknown filter is a 400, not a
//    silently ignored word that the caller believes narrowed their result. ----

const flag = z
  .enum(['true', 'false'])
  .transform((v) => v === 'true')
  .optional();

const eventQuery = z
  .object({
    deviceId: z.coerce.number().int().positive().optional(),
    kind: z.enum(IDENTITY_EVENT_KINDS).optional(),
    severity: z.enum(IDENTITY_EVENT_SEVERITIES).optional(),
    // NOT `z.coerce.boolean()`: that is `Boolean(value)`, and `Boolean("false")`
    // is `true` — so `?pending=false` would have meant `pending`. A query flag
    // is the two words and nothing else.
    pending: flag,
    invalidating: flag,
    sinceHours: z.coerce.number().int().min(1).max(8760).optional(),
    limit: z.coerce.number().int().min(1).max(MAX_EVENT_PAGE).optional(),
  })
  .strict();

const deviceQuery = z
  .object({
    historyLimit: z.coerce.number().int().min(1).max(MAX_EVENT_PAGE).optional(),
  })
  .strict();

const sweepBody = z
  .object({
    // Narrows the pass; it cannot widen it. `sweepTenantIdentities()` clamps
    // to MAX_SWEEP_DEVICES again on its own side, because a service must not
    // depend on its caller having validated anything.
    limit: z.number().int().min(1).max(MAX_SWEEP_DEVICES).optional(),
  })
  .strict();

const ackBody = z
  .object({
    // The only free text this feature accepts. It is stored verbatim and
    // displayed; migration 025 refuses one made of invisible characters.
    note: z.string().min(1).max(4000),
  })
  .strict();

export const identityController = {
  /**
   * GET /api/identity/events — the tenant's identity change feed.
   *
   * The default view an operator wants is "what changed and has nobody looked
   * at it yet", which is `?pending=true&invalidating=true`.
   */
  async events(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(eventQuery, req.query ?? {});
      const data = await listIdentityEvents(req.tenantId, {
        deviceId: q.deviceId,
        kind: q.kind,
        severity: q.severity,
        pendingOnly: q.pending === true,
        invalidatingOnly: q.invalidating === true,
        sinceHours: q.sinceHours,
        limit: q.limit,
      });
      res.json({ success: true, data });
    } catch (err) {
      next(httpError(err));
    }
  },

  /** GET /api/identity/events/:id — one event, or a 404. */
  async event(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'event id');
      const found = await getIdentityEvent(req.tenantId, id);
      if (!found) throw new AppError(404, `Identity event ${id} does not exist`);
      res.json({ success: true, data: found });
    } catch (err) {
      next(httpError(err));
    }
  },

  /**
   * POST /api/identity/events/:id/acknowledge — a human looked at this.
   *
   * NOTHING IS REPAIRED HERE. No snapshot is deleted, no baseline retired, no
   * drift finding closed, no `devices` row written. Three columns are written
   * once on an append-only row (migration 025's trigger enforces the "once"),
   * and the effect is that `baselineTrust()` stops listing this event as a
   * reason to distrust the reference config. The judgement is the operator's;
   * the record of it is the product's.
   */
  async acknowledge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'event id');
      const body = parse(ackBody, req.body ?? {});
      const userId = req.session?.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const data = await acknowledgeIdentityEvent(req.tenantId, id, userId, body.note);
      res.json({ success: true, data });
    } catch (err) {
      next(httpError(err));
    }
  },

  /** GET /api/identity/devices/:deviceId — everything F6 knows about one box:
   *  the registry values, the sticky reference, the compressed history and the
   *  events. The registry and the reference are shown SIDE BY SIDE on purpose;
   *  F6 never writes to `devices`, so a divergence between the two is a fact
   *  an operator should see rather than something to reconcile silently. */
  async device(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const q = parse(deviceQuery, req.query ?? {});
      const data = await getDeviceIdentity(req.tenantId, deviceId, {
        historyLimit: q.historyLimit,
      });
      res.json({ success: true, data });
    } catch (err) {
      next(httpError(err));
    }
  },

  /**
   * GET /api/identity/devices/:deviceId/baseline-trust — THE SECOND TRAP,
   * answered as a sentence.
   *
   * "Is the last config snapshot of this device still a reference?" A replaced
   * chassis means it is not, and that the drift computed against it is not
   * drift. This route SAYS so, and does nothing else: it is a SELECT, it
   * returns a snapshot id and a capture time (never a snapshot's CONTENT), and
   * the only thing that changes the answer is a human acknowledging the event.
   */
  async baselineTrust(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const data = await baselineTrust(req.tenantId, deviceId);
      res.json({ success: true, data });
    } catch (err) {
      next(httpError(err));
    }
  },

  /**
   * POST /api/identity/devices/:deviceId/observe — ask the box who it is.
   *
   * READ-ONLY ON THE EQUIPMENT (D3): `/system/identity/print`,
   * `/system/routerboard/print`, `/system/resource/print`. Nothing outside
   * `change_jobs` writes to a device, and this writes to no device at all.
   *
   * The BODY IS IGNORED. There is deliberately no way to hand this endpoint an
   * identity: see the header of this file.
   */
  async observe(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const data = await observeDeviceIdentity(req.tenantId, deviceId, { source: 'probe' });
      res.json({ success: true, data });
    } catch (err) {
      next(httpError(err));
    }
  },

  /**
   * POST /api/identity/sweep — observe every MikroTik in this tenant that has
   * a usable RouterOS channel, sequentially, up to a server-side ceiling.
   *
   * Sequential and capped because it DIALS REAL ROUTERS: an unbounded parallel
   * sweep is a self-inflicted denial of service on a customer's management
   * plane (risk R5). A device that cannot be reached is reported in
   * `failures[]`; the sweep finishes.
   */
  async sweep(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(sweepBody, req.body ?? {});
      const data = await sweepTenantIdentities(req.tenantId, { limit: body.limit });
      res.json({ success: true, data });
    } catch (err) {
      next(httpError(err));
    }
  },
};
