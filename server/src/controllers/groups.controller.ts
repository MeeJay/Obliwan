import type { Request, Response, NextFunction } from 'express';
import { groupService, CrossTenantParentError } from '../services/group.service';
import { permissionService } from '../services/permission.service';
import type { TenantScope } from '../services/permission.service';
import { teamService } from '../services/team.service';
import { groupNotificationService } from '../services/groupNotification.service';
import { AppError } from '../middleware/errorHandler';
import type { CreateGroupInput, UpdateGroupInput, MoveGroupInput } from '../validators/group.schema';

/**
 * The tenant scope of the current request.
 *
 * `masterView` comes from `requireTenant`, which set it only after a real
 * `user_tenants` lookup — never from `isMasterTenant(session.currentTenantId)`,
 * which the `?? 1` fallback used to satisfy for any user with no tenant at all
 * (AUDIT-SEC #2).
 */
function scopeOf(req: Request): TenantScope {
  return { tenantId: req.tenantId, masterView: req.masterView === true };
}

/**
 * The Socket.io room a group mutation may be announced in.
 *
 * VERIF-SECFIX R1 / VERIF-SECFIX-AUTRES #7 — the five emits below used to
 * target `role:admin`, a GLOBAL room carrying no tenant. It was demonstrated
 * end to end on a running server: an account to which EVERY tenant route
 * answered 403 received `group:created {"id":7,"name":"GlobexPrivateSite",
 * "slug":"globexprivatesite", ...}` in real time. `requireGroupWrite` had been
 * hardened so an admin on tenant B could no longer write tenant A's tree; the
 * websocket handed him its contents to read instead.
 *
 * Room convention, platform-wide: `tenant:{id}` for every member of a tenant,
 * `tenant:{id}:admin` for the admins POSITIONED ON it, `user:{id}` for one
 * account. Nothing broadcasts outside a tenant any more.
 *
 * Note this is the tenant the WRITE happened in (`req.tenantId`), which under
 * `requireGroupWrite` is also the tenant of the group — a platform admin in
 * master view reads across tenants but still writes into his current one.
 */
function adminRoom(req: Request): string {
  return `tenant:${req.tenantId}:admin`;
}

export const groupsController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const isAdmin = req.session.role === 'admin';
      const scope = scopeOf(req);
      const allGroups = await groupService.getAll(scope.tenantId, { crossTenant: scope.masterView });

      if (isAdmin) {
        res.json({ success: true, data: allGroups });
        return;
      }

      const visibleIds = await permissionService.getVisibleGroupIds(req.session.userId!, false, scope);
      if (visibleIds === 'all') {
        res.json({ success: true, data: allGroups });
        return;
      }

      const visibleSet = new Set(visibleIds);
      const filtered = allGroups.filter((g) => visibleSet.has(g.id));
      res.json({ success: true, data: filtered });
    } catch (err) {
      next(err);
    }
  },

  async tree(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const isAdmin = req.session.role === 'admin';
      const scope = scopeOf(req);
      const tree = await groupService.getTree(scope.tenantId, { crossTenant: scope.masterView });

      if (isAdmin) {
        res.json({ success: true, data: tree });
        return;
      }

      const visibleIds = await permissionService.getVisibleGroupIds(req.session.userId!, false, scope);
      if (visibleIds === 'all') {
        res.json({ success: true, data: tree });
        return;
      }

      // Filter tree to only include visible groups
      const visibleSet = new Set(visibleIds);
      function filterTree(nodes: typeof tree): typeof tree {
        return nodes
          .filter((n) => visibleSet.has(n.id))
          .map((n) => ({ ...n, children: filterTree(n.children) }));
      }
      res.json({ success: true, data: filterTree(tree) });
    } catch (err) {
      next(err);
    }
  },

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      if (isNaN(id)) throw new AppError(400, 'Invalid group ID');
      const scope = scopeOf(req);
      const isAdmin = req.session.role === 'admin';

      // AUDIT-SEC #3 — the permission check comes FIRST and carries the tenant.
      // The previous order (load the group by bare id, then check) returned
      // 404-vs-403 differently for a group of another tenant, which by itself
      // confirmed the group existed. Both cases are now a plain 404.
      const perm = await permissionService.getGroupPermission(
        req.session.userId!,
        id,
        isAdmin,
        scope,
      );
      if (perm === null) throw new AppError(404, 'Group not found');

      const group = await groupService.getById(id, scope.masterView ? undefined : scope.tenantId);
      if (!group) throw new AppError(404, 'Group not found');

      res.json({ success: true, data: group });
    } catch (err) {
      next(err);
    }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = req.body as CreateGroupInput;
      const scope = scopeOf(req);

      // AUDIT-CORR §3.1 — the creator's RW grants are handed to the service so
      // they are written in the SAME transaction as the group and its closure
      // rows. A failure here used to leave a group nobody could see.
      let grantRwToTeamIds: number[] = [];
      if (req.session.role !== 'admin') {
        const userTeams = await teamService.getUserTeams(req.session.userId!, scope.tenantId);
        grantRwToTeamIds = userTeams.filter((t) => t.canCreate).map((t) => t.id);
      }

      // The parent is validated inside the transaction, against the tenant
      // (AUDIT-SEC #9): checking it here first would be a TOCTOU window and,
      // worse, `groupService.getById(parentId)` carried no tenant filter at all.
      const group = await groupService.create(data, scope.tenantId, { grantRwToTeamIds });

      // Broadcast via Socket.io
      const io = req.app.get('io');
      if (io) {
        io.to(adminRoom(req)).emit('group:created', { tenantId: req.tenantId, group });
      }

      res.status(201).json({ success: true, data: group });
    } catch (err) {
      if (err instanceof CrossTenantParentError) {
        next(new AppError(400, 'Parent group not found'));
        return;
      }
      next(err);
    }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const data = req.body as UpdateGroupInput;
      const group = await groupService.update(id, data, req.tenantId);

      if (!group) throw new AppError(404, 'Group not found');

      if (data.groupNotifications !== undefined) {
        groupNotificationService.removeGroup(id);
      }

      const io = req.app.get('io');
      if (io) {
        io.to(adminRoom(req)).emit('group:updated', { tenantId: req.tenantId, group });
      }

      res.json({ success: true, data: group });
    } catch (err) {
      next(err);
    }
  },

  async move(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const { newParentId } = req.body as MoveGroupInput;
      const scope = scopeOf(req);

      // Write permission on the target parent, in this tenant.
      const isAdmin = req.session.role === 'admin';
      if (!isAdmin && newParentId !== null) {
        const canWriteTarget = await permissionService.canWriteGroup(
          req.session.userId!,
          newParentId,
          false,
          scope,
        );
        if (!canWriteTarget) throw new AppError(403, 'No write permission on target group');
      }

      const group = await groupService.move(id, newParentId, scope.tenantId);
      if (!group) throw new AppError(404, 'Group not found');

      const io = req.app.get('io');
      if (io) {
        io.to(adminRoom(req)).emit('group:moved', { tenantId: req.tenantId, group });
      }

      res.json({ success: true, data: group });
    } catch (err: unknown) {
      if (err instanceof CrossTenantParentError) {
        next(new AppError(400, 'Parent group not found'));
      } else if (err instanceof Error && err.message.includes('circular')) {
        next(new AppError(400, err.message));
      } else {
        next(err);
      }
    }
  },

  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);

      groupNotificationService.removeGroup(id);

      // AUDIT-CORR §1.4 — the count of groups actually destroyed by the cascade
      // is reported instead of a bare `success: true` that said "1 deleted"
      // whether it removed one group or fifteen.
      const deletedCount = await groupService.delete(id, req.tenantId);
      if (deletedCount === 0) throw new AppError(404, 'Group not found');

      const io = req.app.get('io');
      if (io) {
        io.to(adminRoom(req)).emit('group:deleted', { tenantId: req.tenantId, groupId: id });
      }

      res.json({
        success: true,
        message: `Group deleted (${deletedCount} group(s) removed)`,
        data: { deletedCount },
      });
    } catch (err) {
      next(err);
    }
  },

  async reorder(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const items = req.body.items as { id: number; sortOrder: number }[];
      if (!Array.isArray(items) || items.length === 0) {
        throw new AppError(400, 'items array is required');
      }
      // Scoped to the tenant: the route is admin-only, but an admin positioned
      // on tenant B had no business renumbering tenant A's tree.
      await groupService.reorder(items, req.tenantId);

      const io = req.app.get('io');
      if (io) {
        io.to(adminRoom(req)).emit('group:reordered', { tenantId: req.tenantId, items });
      }

      res.json({ success: true, message: 'Groups reordered' });
    } catch (err) {
      next(err);
    }
  },
};
