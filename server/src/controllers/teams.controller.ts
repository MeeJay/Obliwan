import type { Request, Response, NextFunction } from 'express';
import { teamService } from '../services/team.service';
import { AppError } from '../middleware/errorHandler';
import type {
  CreateTeamInput,
  UpdateTeamInput,
  SetTeamMembersInput,
  SetTeamPermissionsInput,
} from '../validators/team.schema';

export const teamsController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // Platform admins can request all teams across tenants via ?scope=all
      // Otherwise scope to the current tenant from session
      const isPlatformAdmin = req.session.role === 'admin';
      const scopeAll = isPlatformAdmin && req.query.scope === 'all';
      const teams = await teamService.getAll(scopeAll ? null : req.tenantId);
      res.json({ success: true, data: teams });
    } catch (err) {
      next(err);
    }
  },

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      // VERIF-SECFIX-AUTRES #13 — scoped to the current tenant, like the list
      // this detail view is opened from. A team of another customer used to
      // return 200 here with its members and its grants.
      const team = await teamService.getById(id, req.tenantId);
      if (!team) throw new AppError(404, 'Team not found');

      const [members, permissions] = await Promise.all([
        teamService.getMembers(id, req.tenantId),
        teamService.getPermissions(id, req.tenantId),
      ]);

      res.json({ success: true, data: { ...team, memberIds: members ?? [], permissions: permissions ?? [] } });
    } catch (err) {
      next(err);
    }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = req.body as CreateTeamInput & { tenantId?: number };
      // Platform admins can specify the target tenant in the body; others use the session tenant
      const isPlatformAdmin = req.session.role === 'admin';
      const targetTenantId = (isPlatformAdmin && data.tenantId) ? data.tenantId : req.tenantId;
      const team = await teamService.create(data, targetTenantId);
      res.status(201).json({ success: true, data: team });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('unique')) {
        next(new AppError(409, 'Team name already exists'));
      } else {
        next(err);
      }
    }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const data = req.body as UpdateTeamInput;
      const team = await teamService.update(id, data, req.tenantId);
      if (!team) throw new AppError(404, 'Team not found');
      res.json({ success: true, data: team });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('unique')) {
        next(new AppError(409, 'Team name already exists'));
      } else {
        next(err);
      }
    }
  },

  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const deleted = await teamService.delete(id, req.tenantId);
      if (!deleted) throw new AppError(404, 'Team not found');
      res.json({ success: true, message: 'Team deleted' });
    } catch (err) {
      next(err);
    }
  },

  // ── Members ──

  async getMembers(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const members = await teamService.getMembers(id, req.tenantId);
      if (members === null) throw new AppError(404, 'Team not found');
      res.json({ success: true, data: members });
    } catch (err) {
      next(err);
    }
  },

  async setMembers(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const { userIds } = req.body as SetTeamMembersInput;
      // VERIF-SECFIX-AUTRES #9 — the tenant of the CURRENT request decides both
      // which team may be edited and which users are eligible for it. A team of
      // another tenant now 404s here, exactly as `GET /api/teams` already
      // refused to list it.
      await teamService.setMembers(id, userIds, req.tenantId);
      res.json({ success: true, data: userIds });
    } catch (err) {
      next(err);
    }
  },

  // ── Permissions ──

  async getPermissions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const permissions = await teamService.getPermissions(id, req.tenantId);
      if (permissions === null) throw new AppError(404, 'Team not found');
      res.json({ success: true, data: permissions });
    } catch (err) {
      next(err);
    }
  },

  async setPermissions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const { permissions } = req.body as SetTeamPermissionsInput;
      const result = await teamService.setPermissions(id, permissions, req.tenantId);
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },

  async removePermission(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const permId = parseInt(req.params.permId, 10);
      // The team id in the path was never read: scanning permId erased the
      // grants of every tenant, 200 each time (VERIF-SECFIX-AUTRES #13).
      const deleted = await teamService.removePermission(id, permId, req.tenantId);
      if (!deleted) throw new AppError(404, 'Permission not found');
      res.json({ success: true, message: 'Permission removed' });
    } catch (err) {
      next(err);
    }
  },
};
