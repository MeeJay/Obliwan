import type { Request, Response, NextFunction } from 'express';
import type { UserRole, Capability } from '@obliwan/shared';
import { AppError } from './errorHandler';
import { permissionService } from '../services/permission.service';

/**
 * Require a feature capability (see CAPABILITIES in @obliwan/shared).
 *
 * Platform admins (`users.role = 'admin'`, re-read from the database by
 * `requireAuth`) pass. Everyone else must hold the capability for the tenant
 * they are currently operating on: derived from `user_tenants.role` through the
 * matrix in permission.service, or granted by name (pinned team grant /
 * Obligate assertion).
 *
 * A caller with no current tenant now gets 403 instead of silently resolving
 * capabilities against "any tenant" — `getUserCapabilities` returns [] without
 * a tenant, but failing here gives a clear answer instead of an empty one.
 */
export function requireCapability(capability: Capability) {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.userId) {
        next(new AppError(401, 'Authentication required'));
        return;
      }
      if (req.session.role === 'admin') { next(); return; }

      const tenantId = req.tenantId ?? req.session.currentTenantId;
      if (!tenantId) {
        next(new AppError(403, 'No tenant granted for this account'));
        return;
      }

      const caps = await permissionService.getUserCapabilities(
        req.session.userId,
        false,
        tenantId,
      );
      if (!caps.includes(capability)) {
        next(new AppError(403, 'Insufficient permissions'));
        return;
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

export function requireRole(...roles: UserRole[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.session?.userId) {
      next(new AppError(401, 'Authentication required'));
      return;
    }

    if (!roles.includes(req.session.role as UserRole)) {
      next(new AppError(403, 'Insufficient permissions'));
      return;
    }

    next();
  };
}

/**
 * Require write permission on a group (id from req.params.id).
 *
 * AUDIT-SEC #3 — the tenant scope is now mandatory. This middleware only ever
 * runs under `tenantRouter`, so `req.tenantId` is always populated; the guard
 * below exists so a future mount outside it fails closed instead of silently
 * authorising against an undefined tenant.
 */
export function requireGroupWrite() {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const groupId = parseInt(req.params.id, 10);
      if (isNaN(groupId)) return next(new AppError(400, 'Invalid group ID'));
      if (!req.tenantId) return next(new AppError(403, 'No tenant granted for this account'));

      const canWrite = await permissionService.canWriteGroup(
        req.session.userId!,
        groupId,
        req.session.role === 'admin',
        { tenantId: req.tenantId, masterView: req.masterView },
      );
      if (!canWrite) return next(new AppError(403, 'Insufficient permissions'));
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Require canCreate permission (for creating new groups), within the tenant.
 */
export function requireCanCreate() {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (req.session.role === 'admin') return next();
      if (!req.tenantId) return next(new AppError(403, 'No tenant granted for this account'));
      const canCreate = await permissionService.canCreate(req.session.userId!, false, req.tenantId);
      if (!canCreate) return next(new AppError(403, 'Insufficient permissions'));
      next();
    } catch (err) {
      next(err);
    }
  };
}
