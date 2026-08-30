import type { Request, Response, NextFunction } from 'express';
import { db } from '../db';
import { userService } from '../services/user.service';
import { teamService } from '../services/team.service';
import { AppError } from '../middleware/errorHandler';
import type {
  CreateUserInput,
  UpdateUserInput,
  ChangePasswordInput,
} from '../validators/user.schema';

export const usersController = {
  /**
   * GET /api/users  —  the accounts of the CURRENT tenant.
   * GET /api/users?scope=all  —  every account, platform admins only.
   *
   * VERIF-SECFIX-AUTRES #9 — this route is mounted under `tenantRouter` and
   * returned every account of every customer: usernames, display names and
   * e-mail addresses of one client handed to an admin positioned on another,
   * and — worse — the dropdown of the team-editing screen was fed from that
   * cross-tenant inventory with no mention of which tenant each account came
   * from. `teamService.setMembers` now refuses a foreign user, but the UI must
   * stop OFFERING him in the first place: a control that only fires at save
   * time trains operators to consider the list trustworthy.
   *
   * `?scope=all` is the same explicit opt-in `teamsController.list` already
   * uses, and it is what an admin needs to see an account that belongs to no
   * tenant yet (a freshly created one, whose `user_tenants` rows are written by
   * `PUT /api/users/:id/tenants`).
   */
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const isPlatformAdmin = req.session.role === 'admin';
      const users = await userService.getAll();

      if (isPlatformAdmin && req.query.scope === 'all') {
        res.json({ success: true, data: users });
        return;
      }

      // Filtered here rather than in userService.getAll(), whose signature is
      // shared with paths that legitimately need the whole table (last-admin
      // checks below, and the SSO sync).
      const memberIds = await db('user_tenants')
        .where({ tenant_id: req.tenantId })
        .pluck<number[]>('user_id');
      const allowed = new Set(memberIds);
      res.json({ success: true, data: users.filter((u) => allowed.has(u.id)) });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/users/:id
  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const user = await userService.getById(id);
      if (!user) throw new AppError(404, 'User not found');

      // Same scoping as list() right above — without it, GET /api/users/1 from
      // tenant 2 returned tenant 1's admin. 404 rather than 403: a 403 would
      // confirm the id exists and turn this into an enumeration oracle.
      const isPlatformAdmin = req.session.role === 'admin';
      if (!isPlatformAdmin) {
        const member = await db('user_tenants')
          .where({ tenant_id: req.tenantId, user_id: id })
          .first();
        if (!member) throw new AppError(404, 'User not found');
      }

      res.json({ success: true, data: user });
    } catch (err) {
      next(err);
    }
  },

  // POST /api/users
  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = req.body as CreateUserInput;
      const user = await userService.create(data);
      res.status(201).json({ success: true, data: user });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('unique')) {
        next(new AppError(409, 'Username already exists'));
      } else {
        next(err);
      }
    }
  },

  // PUT /api/users/:id
  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const data = req.body as UpdateUserInput;

      // Block role/isActive changes for SSO users — manage from Obligate
      const targetUser = await userService.getById(id);
      if (targetUser?.foreignSource === 'obligate') {
        if (data.role !== undefined || data.isActive !== undefined) {
          throw new AppError(400, 'Cannot modify SSO user — manage from Obligate');
        }
      }

      // Block username change for SSO users
      if (data.username !== undefined) {
        const currentUser = targetUser ?? await userService.getById(id);
        if (currentUser?.foreignSource) {
          throw new AppError(400, 'Cannot change username of an SSO user');
        }
      }

      // Prevent demoting the last admin
      if (data.role === 'user' || data.isActive === false) {
        const currentUser = await userService.getById(id);
        if (currentUser?.role === 'admin') {
          const allUsers = await userService.getAll();
          const activeAdmins = allUsers.filter((u) => u.role === 'admin' && u.isActive && u.id !== id);
          if (activeAdmins.length === 0) {
            throw new AppError(400, 'Cannot remove the last active admin');
          }
        }
      }

      const user = await userService.update(id, data);
      if (!user) throw new AppError(404, 'User not found');
      res.json({ success: true, data: user });
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('unique')) {
        next(new AppError(409, 'Username already exists'));
      } else {
        next(err);
      }
    }
  },

  // PUT /api/users/:id/password
  async changePassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);

      // Block password change for SSO users
      const currentUser = await userService.getById(id);
      if (currentUser?.foreignSource) {
        throw new AppError(400, 'Cannot change password of an SSO user');
      }

      const data = req.body as ChangePasswordInput;
      const success = await userService.changePassword(id, data.password);
      if (!success) throw new AppError(404, 'User not found');
      res.json({ success: true, message: 'Password changed' });
    } catch (err) {
      next(err);
    }
  },

  // DELETE /api/users/:id
  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);

      if (id === req.session.userId) {
        throw new AppError(400, 'Cannot delete your own account');
      }

      const user = await userService.getById(id);

      // Block deletion of SSO users — manage from Obligate
      if (user?.foreignSource === 'obligate') {
        throw new AppError(400, 'Cannot delete SSO user — manage from Obligate');
      }

      if (user?.role === 'admin') {
        const allUsers = await userService.getAll();
        const activeAdmins = allUsers.filter((u) => u.role === 'admin' && u.isActive && u.id !== id);
        if (activeAdmins.length === 0) {
          throw new AppError(400, 'Cannot delete the last admin');
        }
      }

      const deleted = await userService.delete(id);
      if (!deleted) throw new AppError(404, 'User not found');
      res.json({ success: true, message: 'User deleted' });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/users/:id/teams
  async getTeams(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      // Scoped to the tenant the admin is currently on, like every other list
      // served under tenantRouter. Passing `undefined` here would list the
      // user's teams across every customer.
      const teams = await teamService.getUserTeams(id, req.masterView ? undefined : req.tenantId);
      res.json({ success: true, data: teams });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/users/:id/tenants
  async getTenants(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      if (Number.isNaN(id)) throw new AppError(400, 'Invalid user id');

      // `getUserTenantAssignments` is a LEFT JOIN from `tenants`, so an id that
      // matches nobody returns the full tenant list with `isMember: false` —
      // indistinguishable, from the screen, from a real user who belongs to
      // nothing. Say 404 instead of answering about an account that isn't there.
      const user = await userService.getById(id);
      if (!user) throw new AppError(404, 'User not found');

      const assignments = await userService.getUserTenantAssignments(id);
      res.json({ success: true, data: assignments });
    } catch (err) {
      next(err);
    }
  },

  // PUT /api/users/:id/tenants
  // Body: { assignments: [{ tenantId: number, role: 'admin' | 'member' }] }
  async setTenants(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      if (Number.isNaN(id)) throw new AppError(400, 'Invalid user id');

      const targetUser = await userService.getById(id);

      // VERDICT-CONSOLIDATION §3.2 — this used to fall straight through to
      // `setUserTenantAssignments`, whose INSERT then broke the `user_tenants ->
      // users` foreign key, and the raw 23503 came back as
      // `500 Internal server error`. `PUT /api/users/99999/tenants` is a typo,
      // not an incident. `errorHandler` now maps 23503 as a net; this is the
      // answer to the question actually asked.
      //
      // It also removes a real side effect: with an unknown id, the DELETE half
      // of the transaction ran and `destroyUserSessions(99999)` was called
      // before the INSERT failed.
      if (!targetUser) throw new AppError(404, 'User not found');

      if (targetUser.foreignSource === 'obligate') {
        throw new AppError(400, 'Cannot modify SSO user tenant access — manage from Obligate');
      }
      const { assignments } = req.body as {
        assignments: { tenantId: number; role: 'admin' | 'member' }[];
      };
      if (!Array.isArray(assignments)) {
        throw new AppError(400, 'assignments must be an array');
      }
      for (const a of assignments) {
        if (!a || typeof a.tenantId !== 'number' || !Number.isInteger(a.tenantId)) {
          throw new AppError(400, 'Each assignment needs an integer tenantId');
        }
        if (a.role !== 'admin' && a.role !== 'member') {
          throw new AppError(400, "Each assignment needs a role of 'admin' or 'member'");
        }
      }
      await userService.setUserTenantAssignments(id, assignments);
      res.json({ success: true, message: 'Tenant assignments updated' });
    } catch (err) {
      next(err);
    }
  },
};
