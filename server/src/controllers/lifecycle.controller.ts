/**
 * ObliWAN F8 — End-of-Life Inventory, HTTP layer.
 *
 * ┌─ WHAT THIS SURFACE MUST NEVER ACCEPT ─────────────────────────────────────┐
 * │ `asOf`. IT IS NOT IN A SINGLE SCHEMA BELOW AND IT MUST NOT BE ADDED.      │
 * │                                                                          │
 * │ Every pure function in `shared/src/lifecycle.ts` takes the date to reason │
 * │ at, because a rule that reads a clock cannot be tested. The temptation to │
 * │ expose that parameter ("let the UI ask what the fleet looks like at the   │
 * │ end of the contract") is exactly the mistake this project has already     │
 * │ shipped once: a caller-driven parameter that flipped a verdict — 365 days │
 * │ with no observation turned into a signed `continuous` attestation.        │
 * │                                                                          │
 * │ Here the same hole reads `?asOf=2000-01-01` and reports an entire fleet   │
 * │ `supported`. The controllers call `serverToday()` themselves and pass it  │
 * │ down. `getInventory`, `getLifecycleSummary`, `getDeviceLifecycle` and     │
 * │ `getCatalogGaps` all DEFAULT the parameter, so even a future caller that  │
 * │ forgets gets the server's clock rather than `undefined`.                  │
 * │                                                                          │
 * │ What IS accepted is `horizonDays` — a WINDOW OVER ALREADY-COMPUTED DATES. │
 * │ It selects rows out of a finished list; no device's status, priority or   │
 * │ citation changes by one character when it moves. It is capped server-side │
 * │ at ten years so it cannot be used to ask for a sort of the whole fleet.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ TENANT SCOPE ────────────────────────────────────────────────────────────┐
 * │ Everything that reads customer data goes through `assessFleet`, whose one │
 * │ query filters `devices.tenant_id = req.tenantId` and joins `sites` on id  │
 * │ AND tenant. `getDeviceLifecycle` finds the device INSIDE that already     │
 * │ scoped list, so a device id from another customer is simply absent, and   │
 * │ the answer is 404 — NEVER 403. A 403 confirms the id exists, which on a   │
 * │ serial primary key is an enumeration oracle over another MSP customer's   │
 * │ inventory.                                                                │
 * │                                                                          │
 * │ The catalogue endpoints read `lifecycle_models` / `lifecycle_firmware`,   │
 * │ which have no tenant column by design (migration 027, decision 2): they   │
 * │ hold published vendor product facts. WRITING them is a platform act and   │
 * │ is guarded by `requireRole('admin')` on the route, upstream of every      │
 * │ branch in these handlers.                                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2): nothing on this surface can return one. The widest object it
 * serves is a device's name, site, brand, family, model string and firmware
 * version, plus a vendor citation. `devices.serial`, `devices.ppp_username`,
 * every `device_transports` column and every jsonb in the schema are outside
 * the projection — see `inventory.service.ts`.
 *
 * D3: read-only, and not even read-only ON A DEVICE. F8 never opens a session.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import {
  FIRMWARE_STATUSES,
  LIFECYCLE_IMPORT_KINDS,
  LIFECYCLE_STATUSES,
  LifecycleCatalogError,
  RENEWAL_PRIORITIES,
  RENEWAL_WATCH_DAYS,
} from '@obliwan/shared/dist/lifecycle';
import { DEVICE_BRANDS, DEVICE_FAMILIES } from '@obliwan/shared/dist/device';
import { AppError } from '../middleware/errorHandler';
import {
  deleteCatalogEntry,
  getCatalogGaps,
  getDeviceLifecycle,
  getInventory,
  getLifecycleCatalog,
  getLifecycleSummary,
  importFirmwareEntries,
  importModelEntries,
  listCatalogImports,
  serverToday,
  LIFECYCLE_VOCABULARY,
} from '../services/lifecycle';

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

/** `z.infer<S>` and not a bare `z.ZodType<T>`: the query schemas below use
 *  `.transform().pipe()`, whose INPUT type (a raw query string) differs from
 *  its OUTPUT type (a validated enum array). Inferring from the schema keeps
 *  the parsed value correctly typed instead of collapsing to the input. */
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

/** A catalogue entry the service refuses is a 400 with the reason spelled out —
 *  never a 500, and never a silently dropped row. Everything else passes
 *  through untouched so a real fault still reaches the error handler. */
function asHttpError(err: unknown): unknown {
  return err instanceof LifecycleCatalogError ? new AppError(400, err.message) : err;
}

/** `?status=end_of_life&status=end_of_support` and `?status=a,b` both work. */
const csvEnum = <T extends readonly [string, ...string[]]>(values: T) =>
  z
    .union([z.string(), z.array(z.string())])
    .transform((v) => (Array.isArray(v) ? v : v.split(',')))
    .transform((parts) => parts.map((p) => p.trim()).filter((p) => p.length > 0))
    .pipe(z.array(z.enum(values)).max(values.length));

/**
 * THE COMPLETE LIST OF WHAT THIS ENDPOINT ACCEPTS. `.strict()` — an unknown key
 * is a 400 rather than a silently ignored filter, so a typo in `?priority=` can
 * never be read as "no filter, everything is fine".
 *
 * NOT ONE OF THESE CHANGES A VERDICT. `status`, `firmwareStatus`, `priority`,
 * `brand`, `family` and `siteId` select rows; `horizonDays` windows dates that
 * are already computed; `limit`/`offset` paginate. The statuses themselves were
 * decided before any of this ran, against `serverToday()`.
 */
const inventoryQuery = z
  .object({
    status: csvEnum(LIFECYCLE_STATUSES).optional(),
    firmwareStatus: csvEnum(FIRMWARE_STATUSES).optional(),
    priority: csvEnum(RENEWAL_PRIORITIES).optional(),
    brand: z.enum(DEVICE_BRANDS).optional(),
    family: z.enum(DEVICE_FAMILIES).optional(),
    siteId: z.coerce.number().int().positive().optional(),
    // Ten years. An uncapped horizon is a request to return the whole fleet
    // under a name that sounds like a filter.
    horizonDays: z.coerce.number().int().min(1).max(3650).optional(),
    limit: z.coerce.number().int().min(1).max(1000).optional(),
    offset: z.coerce.number().int().min(0).max(1_000_000).optional(),
  })
  .strict();

const catalogQuery = z
  .object({
    brand: z.enum(DEVICE_BRANDS).optional(),
  })
  .strict();

const importsQuery = z
  .object({
    limit: z.coerce.number().int().min(1).max(200).optional(),
  })
  .strict();

/**
 * THE ROUTES THAT TAKE NO QUERY AT ALL STILL PARSE ONE.
 *
 * An empty `.strict()` object turns any query string into a 400. Without it,
 * `GET /summary?asOf=2000-01-01` is accepted with a 200 and the parameter is
 * silently dropped — which is the CORRECT behaviour today and the wrong
 * PROPERTY to have. The failure mode is a later edit that adds a field to the
 * service call and reads it from `req.query` on a route that never refused
 * anything: nothing in the diff looks like it opened a hole, because the hole
 * was always there and only the exploit was missing.
 *
 * Making "an unrecognised query parameter is a 400" true of the WHOLE surface
 * rather than of the three routes that happened to need a schema is what makes
 * the F8 harness able to assert it by enumerating the router, instead of by a
 * list somebody has to remember to extend.
 */
const noQuery = z.object({}).strict();

/**
 * An import body. `entries` is validated element by element INSIDE the service
 * so one bad row in three hundred is one rejection with its index, not a 400
 * for the whole dataset — an operator loading a vendor's list should not have
 * to bisect it.
 *
 * `sourceKind` is deliberately absent: the service stamps `import` on every row
 * it writes. A caller that could stamp `builtin` would make its own rows look
 * like the seeded, reviewed set, which changes how a human weighs the claim.
 */
const importBody = z
  .object({
    label: z.string().trim().min(1).max(255),
    entries: z.array(z.unknown()).min(1).max(5000),
  })
  .strict();

export const lifecycleController = {
  /**
   * GET /api/lifecycle/inventory — THE RENEWAL LIST.
   *
   * Worst first. Every row carries its citation, so the person reading it can
   * say where the claim comes from without leaving the screen.
   */
  async inventory(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(inventoryQuery, req.query ?? {});
      // The clock is read HERE, on the server, and passed down. Not accepted.
      const page = await getInventory(req.tenantId, q, serverToday());
      res.json({
        success: true,
        data: { ...page, watchDays: RENEWAL_WATCH_DAYS, vocabulary: LIFECYCLE_VOCABULARY },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/lifecycle/summary — the counts, plus the coverage gauge.
   *
   * `coverage` is the honesty number and it is not optional: a renewal list
   * built from a catalogue that cites 4% of the fleet has a 96% blind spot, and
   * without this figure an empty catalogue and a healthy fleet render the same
   * green page.
   */
  async summary(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      parse(noQuery, req.query ?? {});
      const summary = await getLifecycleSummary(req.tenantId, serverToday());
      res.json({ success: true, data: { ...summary, watchDays: RENEWAL_WATCH_DAYS } });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/lifecycle/devices/:deviceId — one device, both axes, cited. */
  async device(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // Before the id, so an unrecognised query parameter is refused even for a
      // device id that does not exist. Otherwise "Device not found" masks the
      // fact that the parameter was accepted.
      parse(noQuery, req.query ?? {});
      const deviceId = parseId(req.params.deviceId, 'device id');
      const found = await getDeviceLifecycle(req.tenantId, deviceId, serverToday());
      // Another customer's device is indistinguishable from a device that does
      // not exist. 404, never 403.
      if (!found) throw new AppError(404, 'Device not found');
      res.json({ success: true, data: found });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/lifecycle/gaps — the research list.
   *
   * "These eleven model strings account for 340 of your devices, and the
   * catalogue has never heard of any of them." This is what makes `unknown`
   * actionable instead of merely honest.
   */
  async gaps(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      parse(noQuery, req.query ?? {});
      res.json({ success: true, data: await getCatalogGaps(req.tenantId, serverToday()) });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/lifecycle/catalog — the vendor facts, with their sources.
   *
   * Unscoped by tenant BY DESIGN (migration 027, decision 2): published product
   * information about SonicWall is not a fact about a customer. Behind
   * DEVICE_READ all the same, because "which models does this MSP's tooling
   * know about" is still operational detail.
   */
  async catalog(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(catalogQuery, req.query ?? {});
      const catalog = await getLifecycleCatalog();
      const models = q.brand ? catalog.models.filter((m) => m.brand === q.brand) : catalog.models;
      const firmware = q.brand
        ? catalog.firmware.filter((f) => f.brand === q.brand)
        : catalog.firmware;
      res.json({ success: true, data: { models, firmware, asOf: serverToday() } });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/lifecycle/catalog/imports — who changed the catalogue, and when. */
  async imports(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(importsQuery, req.query ?? {});
      res.json({ success: true, data: await listCatalogImports(q.limit ?? 50) });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/lifecycle/catalog/models — PLATFORM ADMIN ONLY.
   *
   * The guard is `requireRole('admin')` on the ROUTE, i.e. upstream of every
   * branch in this handler. There is no path into `importModelEntries` that
   * skips it, and the handler itself has no conditional that could reach the
   * write on one branch and not another.
   */
  async importModels(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(importBody, req.body ?? {});
      const result = await importModelEntries(
        body.entries,
        body.label,
        req.session?.userId ?? null,
      );
      res.json({ success: true, data: result });
    } catch (err) {
      next(asHttpError(err));
    }
  },

  /** POST /api/lifecycle/catalog/firmware — PLATFORM ADMIN ONLY. Same guard. */
  async importFirmware(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(importBody, req.body ?? {});
      const result = await importFirmwareEntries(
        body.entries,
        body.label,
        req.session?.userId ?? null,
      );
      res.json({ success: true, data: result });
    } catch (err) {
      next(asHttpError(err));
    }
  },

  /**
   * DELETE /api/lifecycle/catalog/:kind/:id — PLATFORM ADMIN ONLY.
   *
   * A wrong row here is a false claim being made to paying customers on every
   * page load, so removing one must not require an import round-trip. `:kind`
   * is validated against the vocabulary BEFORE it is used to pick a table —
   * the service takes a `LifecycleImportKind`, never a caller-supplied table
   * name.
   */
  async deleteEntry(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const kind = z.enum(LIFECYCLE_IMPORT_KINDS).safeParse(req.params.kind);
      if (!kind.success) throw new AppError(400, "kind must be 'model' or 'firmware'");
      const id = parseId(req.params.id, 'entry id');
      const removed = await deleteCatalogEntry(kind.data, id);
      if (!removed) throw new AppError(404, 'Catalogue entry not found');
      res.json({ success: true, data: { deleted: true, kind: kind.data, id } });
    } catch (err) {
      next(err);
    }
  },
};
