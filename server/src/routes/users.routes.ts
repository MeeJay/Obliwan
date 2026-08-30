import type { Request, Response, NextFunction } from 'express';
import { Router } from 'express';
import { usersController } from '../controllers/users.controller';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { AppError } from '../middleware/errorHandler';
import { validate } from '../middleware/validate';
import {
  createUserSchema,
  updateUserSchema,
  changePasswordSchema,
} from '../validators/user.schema';

const router = Router();

router.use(requireAuth);
router.use(requireRole('admin'));

/**
 * VERIF-SECFIX R8 — this router is mounted under `tenantRouter`, but
 * `requireTenant` lets a PLATFORM ADMIN through with no tenant at all here (it
 * is the only way to repair an account that has no `user_tenants` row; see
 * `middleware/tenant.ts`). Everything below is tenant-agnostic except
 * `GET /:id/teams`, which reads `req.tenantId` — and passing `undefined` there
 * lists that user's teams across EVERY customer. Fail closed instead.
 */
function requireResolvedTenant(req: Request, _res: Response, next: NextFunction): void {
  if (!req.tenantId) {
    next(new AppError(403, 'No tenant selected — switch to a tenant first'));
    return;
  }
  next();
}

/**
 * `GET /api/users` filters on `req.tenantId`; `GET /api/users?scope=all` is the
 * platform admin's explicit cross-tenant opt-in and needs no tenant at all.
 * A tenantless platform admin (see above) must therefore be told to use the
 * opt-in rather than get a knex "undefined binding" 500 from the scoped branch.
 */
function requireResolvedTenantUnlessScopeAll(req: Request, res: Response, next: NextFunction): void {
  if (req.session.role === 'admin' && req.query.scope === 'all') {
    next();
    return;
  }
  requireResolvedTenant(req, res, next);
}

router.get('/', requireResolvedTenantUnlessScopeAll, usersController.list);
router.get('/:id', usersController.getById);
router.post('/', validate(createUserSchema), usersController.create);
router.put('/:id', validate(updateUserSchema), usersController.update);
router.put('/:id/password', validate(changePasswordSchema), usersController.changePassword);
router.delete('/:id', usersController.delete);

// Team membership listing
router.get('/:id/teams', requireResolvedTenant, usersController.getTeams);

// Tenant assignment management
router.get('/:id/tenants', usersController.getTenants);
router.put('/:id/tenants', usersController.setTenants);

export default router;
