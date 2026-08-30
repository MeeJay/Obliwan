import type { Request, Response, NextFunction } from 'express';
import { notificationService } from '../services/notification.service';
import { getPluginMetas } from '../notifications/registry';
import { AppError } from '../middleware/errorHandler';
import { assertScopeInTenant } from '../utils/tenantScope';
import type {
  CreateChannelInput,
  UpdateChannelInput,
  AddBindingInput,
  RemoveBindingInput,
} from '../validators/notification.schema';

export const notificationsController = {
  // GET /api/notifications/plugins — list available plugin types
  async plugins(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const metas = getPluginMetas();
      res.json({ success: true, data: metas });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/notifications/channels
  async listChannels(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const channels = await notificationService.getAllChannels(req.tenantId);
      res.json({ success: true, data: channels });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/notifications/channels/:id
  async getChannel(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const channel = await notificationService.getChannelById(id, req.tenantId);
      if (!channel) throw new AppError(404, 'Channel not found');
      res.json({ success: true, data: channel });
    } catch (err) {
      next(err);
    }
  },

  // POST /api/notifications/channels
  async createChannel(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = req.body as CreateChannelInput;
      const channel = await notificationService.createChannel({
        ...data,
        createdBy: req.session.userId!,
      }, req.tenantId);
      res.status(201).json({ success: true, data: channel });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('Unknown notification')) {
        next(new AppError(400, err.message));
      } else {
        next(err);
      }
    }
  },

  // PUT /api/notifications/channels/:id
  async updateChannel(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const data = req.body as UpdateChannelInput;
      const channel = await notificationService.updateChannel(id, data, req.tenantId);
      if (!channel) throw new AppError(404, 'Channel not found');
      res.json({ success: true, data: channel });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('Unknown notification')) {
        next(new AppError(400, err.message));
      } else {
        next(err);
      }
    }
  },

  // DELETE /api/notifications/channels/:id
  async deleteChannel(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const deleted = await notificationService.deleteChannel(id, req.tenantId);
      if (!deleted) throw new AppError(404, 'Channel not found');
      res.json({ success: true, message: 'Channel deleted' });
    } catch (err) {
      next(err);
    }
  },

  // POST /api/notifications/channels/:id/test
  async testChannel(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      await notificationService.testChannel(id, req.tenantId);
      res.json({ success: true, message: 'Test notification sent' });
    } catch (err: unknown) {
      if (err instanceof Error) {
        next(new AppError(400, `Test failed: ${err.message}`));
      } else {
        next(err);
      }
    }
  },

  // GET /api/notifications/channels/:id/tenants — list tenant IDs the channel is shared to
  async getChannelTenants(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const tenantIds = await notificationService.getChannelTenants(id, req.tenantId);
      if (tenantIds === null) throw new AppError(404, 'Channel not found');
      res.json({ success: true, data: tenantIds });
    } catch (err) {
      next(err);
    }
  },

  // PUT /api/notifications/channels/:id/tenants — replace sharing list
  async setChannelTenants(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const tenantIds: number[] = req.body.tenantIds ?? [];
      if (!Array.isArray(tenantIds)) {
        throw new AppError(400, 'tenantIds must be an array');
      }
      const ok = await notificationService.setChannelTenants(id, tenantIds, req.tenantId);
      if (!ok) throw new AppError(404, 'Channel not found');
      res.json({ success: true, message: 'Channel tenants updated' });
    } catch (err) {
      next(err);
    }
  },

  // ── Bindings ──

  // GET /api/notifications/bindings?scope=...&scopeId=...
  async listBindings(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const scope = req.query.scope as string;
      const rawScopeId = req.query.scopeId as string | undefined;
      const scopeId = rawScopeId && rawScopeId !== 'null' ? parseInt(rawScopeId, 10) : null;
      const bindings = await notificationService.getBindings(req.tenantId, scope, scopeId);
      res.json({ success: true, data: bindings });
    } catch (err) {
      next(err);
    }
  },

  // POST /api/notifications/bindings
  async addBinding(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = req.body as AddBindingInput;
      // AUDIT-CORR §1.2 — the binding now carries a tenant_id, so binding
      // ANOTHER tenant's channel would recreate the leak from the other side:
      // tenant 2 posting on tenant 1's Discord. Only a channel this tenant owns
      // or has been shared can be bound.
      const target = await notificationService.getChannelById(data.channelId, req.tenantId);
      if (!target) throw new AppError(404, 'Channel not found');

      // VERIF-SECFIX-AUTRES #14 — the channel was checked and the scopeId was
      // not: a binding on another tenant's group id was accepted, producing an
      // orphan row that no screen shows, that the export carries, and that a
      // later import re-materialises somewhere else.
      //
      // VERDICT-CONSOLIDATION §3.3.1 — this used to be an INLINE
      // `db('device_groups').where({id, tenant_id})`, i.e. a third private copy
      // of the rule that covered `group` and silently waved `device` through —
      // the exact shape of R5, one scope kind ahead of the copy that had been
      // fixed. It now calls the single shared implementation, which is
      // allow-list driven and covers every scope kind at once.
      await assertScopeInTenant(data.scope, data.scopeId, req.tenantId);

      const binding = await notificationService.addBinding(
        req.tenantId,
        data.channelId,
        data.scope,
        data.scopeId,
        data.overrideMode,
      );
      res.status(201).json({ success: true, data: binding });
    } catch (err) {
      next(err);
    }
  },

  // DELETE /api/notifications/bindings
  async removeBinding(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = req.body as RemoveBindingInput;
      const removed = await notificationService.removeBinding(req.tenantId, data.channelId, data.scope, data.scopeId);
      res.json({ success: true, message: removed ? 'Binding removed' : 'Binding not found' });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/notifications/bindings/resolved?scope=group|device&scopeId=N
  async resolvedBindings(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const scope = req.query.scope as 'group' | 'device';
      const scopeId = parseInt(req.query.scopeId as string, 10);

      if ((scope !== 'group' && scope !== 'device') || isNaN(scopeId)) {
        throw new AppError(400, 'scope must be group or device, and scopeId a number');
      }

      // groupId is only meaningful for a device scope (it anchors the ancestor
      // walk). Devices arrive in M2; until then a device-scoped resolution
      // simply inherits the global bindings, which is the correct answer for a
      // device that belongs to no group.
      const groupId = req.query.groupId ? parseInt(req.query.groupId as string, 10) : null;

      // Same shared guard as addBinding: resolving against a foreign scope id
      // returned the caller's own global bindings under someone else's anchor,
      // which reads as "this group inherits nothing" instead of "no such group".
      await assertScopeInTenant(scope, scopeId, req.tenantId);
      if (groupId !== null && !Number.isNaN(groupId)) {
        await assertScopeInTenant('group', groupId, req.tenantId);
      }

      const resolved = await notificationService.resolveBindingsWithSources(
        req.tenantId,
        scope,
        scopeId,
        Number.isNaN(groupId as number) ? null : groupId,
      );
      res.json({ success: true, data: resolved });
    } catch (err) {
      next(err);
    }
  },
};
