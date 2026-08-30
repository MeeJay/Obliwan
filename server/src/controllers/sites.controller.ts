import type { Request, Response, NextFunction } from 'express';
import { AppError } from '../middleware/errorHandler';
import * as siteService from '../services/fleet/site.service';
import * as deviceService from '../services/fleet/device.service';
import { toDeviceDto, toSiteDto } from '../services/fleet/dto';
import type { CreateSiteInput, UpdateSiteInput } from '../validators/site.schema';

/**
 * Sites — HTTP layer.
 *
 * The tenant is ALWAYS `req.tenantId` (from the session, via `requireTenant`)
 * and never anything the client sent. A 404 rather than a 403 on a
 * cross-tenant id is deliberate: telling an operator "that site exists but is
 * not yours" is itself a leak of another customer's inventory.
 *
 * Every response body goes through a mapper from `services/fleet/dto.ts`. The
 * database columns are `snake_case` and the API contract is `camelCase`;
 * handing a Knex row to `res.json()` publishes the schema and silently breaks
 * every consumer, which is exactly what had happened here.
 */

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

/** Postgres unique-violation, turned into something an operator can act on. */
function isUniqueViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505';
}

export const sitesController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const search = typeof req.query.search === 'string' ? req.query.search : undefined;
      const sites = await siteService.listSites(req.tenantId, { search });
      res.json({ success: true, data: sites.map(toSiteDto) });
    } catch (err) {
      next(err);
    }
  },

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const site = await siteService.getSite(req.tenantId, parseId(req.params.id));
      if (!site) throw new AppError(404, 'Site not found');
      res.json({ success: true, data: toSiteDto(site) });
    } catch (err) {
      next(err);
    }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const site = await siteService.createSite(req.tenantId, req.body as CreateSiteInput);
      res.status(201).json({ success: true, data: toSiteDto(site) });
    } catch (err) {
      if (isUniqueViolation(err)) {
        next(new AppError(409, 'A site with this code already exists in this tenant'));
        return;
      }
      next(err);
    }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const site = await siteService.updateSite(
        req.tenantId,
        parseId(req.params.id),
        req.body as UpdateSiteInput,
      );
      if (!site) throw new AppError(404, 'Site not found');
      res.json({ success: true, data: toSiteDto(site) });
    } catch (err) {
      if (isUniqueViolation(err)) {
        next(new AppError(409, 'A site with this code already exists in this tenant'));
        return;
      }
      next(err);
    }
  },

  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const ok = await siteService.deleteSite(req.tenantId, parseId(req.params.id));
      if (!ok) throw new AppError(404, 'Site not found');
      res.json({ success: true, message: 'Site deleted' });
    } catch (err) {
      next(err);
    }
  },

  /** Live presence of every device on the site, with its latest K7 verdict. */
  async presence(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const site = await siteService.getSite(req.tenantId, id);
      if (!site) throw new AppError(404, 'Site not found');
      res.json({ success: true, data: await siteService.sitePresence(req.tenantId, id) });
    } catch (err) {
      next(err);
    }
  },

  /**
   * The devices filed under this site.
   *
   * The site detail page used to fetch the WHOLE fleet and filter it in the
   * browser. That is wrong twice over: it is O(fleet) to render one site, and
   * a truncated device list (the collection endpoint is paginated) silently
   * renders a site as emptier than it is. The server owns the filter.
   *
   * The 404 comes first, and it is the same 404 a site of another tenant
   * gets — otherwise this route becomes an existence oracle for ids the caller
   * is not allowed to name.
   */
  async devices(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const site = await siteService.getSite(req.tenantId, id);
      if (!site) throw new AppError(404, 'Site not found');
      const result = await deviceService.listDevices(req.tenantId, { siteId: id });
      res.json({
        success: true,
        data: result.items.map(toDeviceDto),
        meta: { total: result.total },
      });
    } catch (err) {
      next(err);
    }
  },

  /** PPP chronology for the site (spec §4.2). */
  async pppSessions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const site = await siteService.getSite(req.tenantId, id);
      if (!site) throw new AppError(404, 'Site not found');
      const limitRaw = Number(req.query.limit);
      const limit = Number.isInteger(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 500) : 100;
      res.json({
        success: true,
        data: await siteService.sitePppSessions(req.tenantId, id, limit),
      });
    } catch (err) {
      next(err);
    }
  },
};
