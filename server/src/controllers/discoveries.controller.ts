import type { Request, Response, NextFunction } from 'express';
import type { DeviceFamily } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import {
  bindDiscovery,
  getDiscovery,
  listDiscoveries,
  runChrDiscovery,
  setDiscoveryState,
} from '../services/fleet/concentratorDiscovery.service';
import * as deviceService from '../services/fleet/device.service';
import { toDeviceDetailDto, toDiscoveryDto } from '../services/fleet/dto';
import type { BindDiscoveryInput } from '../validators/device.schema';

/**
 * Discoveries — the quarantine review screen.
 *
 * `discoveries` has NO `tenant_id` (migration 002): a PPP username seen on the
 * wire belongs to nobody until a human says so. Scoping therefore goes through
 * the CONCENTRATOR: a caller sees the discoveries of the concentrators in their
 * tenant, and nothing else. That is why every handler starts by resolving the
 * tenant's concentrator ids instead of filtering on a column.
 *
 * Binding is the only path from `pending` to `bound`, it requires
 * `DEVICE_DISCOVER`, and it stamps `reviewed_by`. There is no auto-bind, no
 * "bind all", and no heuristic on tunnel IP — that is risk R4, and the whole
 * reason this screen exists.
 */

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

/** Load a discovery and prove the caller's tenant owns its concentrator. */
async function requireVisibleDiscovery(req: Request, id: number) {
  const discovery = await getDiscovery(id);
  if (!discovery) throw new AppError(404, 'Discovery not found');
  const visible = await deviceService.concentratorIdsForTenant(req.tenantId);
  if (!visible.includes(discovery.concentrator_id)) {
    // 404, not 403: the existence of another tenant's quarantine row is itself
    // information about another customer's fleet.
    throw new AppError(404, 'Discovery not found');
  }
  return discovery;
}

export const discoveriesController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = req.query as Record<string, unknown>;
      let concentratorIds = await deviceService.concentratorIdsForTenant(req.tenantId);
      if (q.concentratorId !== undefined) {
        const wanted = Number(q.concentratorId);
        concentratorIds = concentratorIds.filter((id) => id === wanted);
      }
      const result = await listDiscoveries({
        concentratorIds,
        state: q.state as string | undefined,
        search: q.search as string | undefined,
        limit: q.limit as number | undefined,
        offset: q.offset as number | undefined,
      });
      res.json({
        success: true,
        data: result.items.map(toDiscoveryDto),
        meta: { total: result.total },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * Run a discovery pass against a concentrator, now.
   *
   * Synchronous on purpose at this scale: the operator pressed a button and
   * wants the count back. It reads `/ppp/secret` and `/ppp/active` through the
   * single pooled socket, so two operators pressing it at once still produce
   * one round trip's worth of load on the CHR.
   */
  async scan(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { concentratorId } = req.body as { concentratorId: number };
      const chr = await deviceService.getDevice(req.tenantId, concentratorId);
      if (!chr) throw new AppError(404, 'Concentrator not found');
      if (chr.role !== 'concentrator') throw new AppError(400, 'This device is not a concentrator');

      const result = await runChrDiscovery(concentratorId);
      res.json({ success: true, data: result });
    } catch (err) {
      if (err instanceof Error && err.message.includes('no usable RouterOS API transport')) {
        return next(new AppError(400, err.message));
      }
      next(err);
    }
  },

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const discovery = await requireVisibleDiscovery(req, parseId(req.params.id));
      res.json({ success: true, data: toDiscoveryDto(discovery) });
    } catch (err) {
      next(err);
    }
  },

  /**
   * The human gesture: attach a quarantined PPP username to a device.
   *
   * Either an existing device, or one created on the spot from the operator's
   * own description of it. Note what the created device does NOT inherit from
   * the discovery: nothing about identity beyond the username. Model, serial
   * and system identity are learned from the box itself by
   * `assertTargetBinding()`, never from what the CHR happened to report.
   */
  async bind(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const discovery = await requireVisibleDiscovery(req, parseId(req.params.id));
      const body = req.body as BindDiscoveryInput;
      const userId = req.session.userId;
      if (!userId) throw new AppError(401, 'Authentication required');

      let deviceId: number;
      if (body.deviceId !== undefined) {
        const device = await deviceService.getDevice(req.tenantId, body.deviceId);
        if (!device) throw new AppError(404, 'Target device not found in this tenant');
        deviceId = device.id;
      } else if (body.device) {
        const created = await deviceService.createDevice(req.tenantId, {
          ...(body.device as unknown as deviceService.CreateDeviceData),
          family: body.device.family as DeviceFamily,
          // Bound but unproven: `active` is a statement about a box that has
          // answered an identity assertion, and nothing has yet.
          status: 'pending',
        });
        deviceId = created.id;
      } else {
        throw new AppError(400, 'Provide either deviceId or device');
      }

      const bound = await bindDiscovery(discovery.id, deviceId, userId);
      const detail = await deviceService.getDeviceDetail(req.tenantId, deviceId);
      res.json({
        success: true,
        data: {
          discovery: toDiscoveryDto(bound),
          device: detail ? toDeviceDetailDto(detail) : null,
        },
      });
    } catch (err) {
      if (typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505') {
        return next(new AppError(409, 'This PPP username is already bound to another device'));
      }
      if (err instanceof Error && /already bound|already bound to PPP user|does not exist/.test(err.message)) {
        return next(new AppError(409, err.message));
      }
      next(err);
    }
  },

  /** Ignore (not ours) or push back to pending. Never used to unbind. */
  async setState(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const discovery = await requireVisibleDiscovery(req, parseId(req.params.id));
      const { state } = req.body as { state: 'pending' | 'ignored' };
      const userId = req.session.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const row = await setDiscoveryState(discovery.id, state, userId);
      res.json({ success: true, data: toDiscoveryDto(row) });
    } catch (err) {
      if (err instanceof Error && err.message.includes('is bound to device')) {
        return next(new AppError(409, err.message));
      }
      next(err);
    }
  },
};
