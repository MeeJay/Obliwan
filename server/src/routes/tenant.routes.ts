import { Router } from 'express';
import { requireAuth, regenerateSession } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { tenantService } from '../services/tenant.service';
import { AppError } from '../middleware/errorHandler';
import { logger } from '../utils/logger';

const router = Router();

// All tenant routes require auth
router.use(requireAuth);

// ── Tenant switch ──────────────────────────────────────────────────────────
// POST /api/tenant/switch  { tenantId: number }
router.post('/switch', async (req, res, next) => {
  try {
    const { tenantId } = req.body as { tenantId: number };
    if (!tenantId || typeof tenantId !== 'number' || !Number.isInteger(tenantId) || tenantId <= 0) {
      throw new AppError(400, 'tenantId is required');
    }

    const userId = req.session.userId!;
    const isPlatformAdmin = req.session.role === 'admin';

    // Platform admins can switch to any tenant; others only to their own.
    // The membership check runs FIRST for non-admins so this route is not an
    // existence oracle: a stranger gets the same 403 whether the tenant exists
    // or not.
    if (!isPlatformAdmin) {
      const hasAccess = await tenantService.userHasAccess(userId, tenantId);
      if (!hasAccess) throw new AppError(403, 'Access denied to this tenant');
    }

    // VERIF-SECFIX R7 — the tenant must EXIST. `POST /api/tenant/switch
    // {"tenantId": 99999}` used to answer 200 for a platform admin and leave
    // the session pointing at nothing: every subsequent list came back empty,
    // with no way for the UI to tell "no data" from "no such tenant".
    const tenant = await tenantService.getById(tenantId);
    if (!tenant) throw new AppError(404, 'Tenant not found');

    // AUDIT-SEC #5 — a tenant switch changes the authorisation scope of the
    // session (`requireTenant` derives `req.tenantId` and `req.masterView` from
    // it, and switching to the master tenant as a platform admin turns the god
    // view ON). Rotate the session id here as on the other two elevation
    // paths, so a fixed id can never be riding along when the scope widens.
    // `regenerate()` empties the session; the authenticated identity is copied
    // back by name and nothing pre-auth survives.
    const username = req.session.username;
    const role = req.session.role;
    await regenerateSession(req);
    req.session.userId = userId;
    req.session.username = username;
    req.session.role = role;
    req.session.currentTenantId = tenantId;

    // Persist before answering: the client's very next request carries the new
    // cookie, and it must find the new row already written.
    await new Promise<void>((resolve, reject) => {
      req.session.save((err) => (err ? reject(new AppError(500, 'Failed to persist session')) : resolve()));
    });

    logger.info({ userId, tenantId }, 'Tenant switch: session id rotated');
    res.json({ success: true, data: { currentTenantId: tenantId } });
  } catch (err) {
    next(err);
  }
});

// ── List tenants ───────────────────────────────────────────────────────────
// GET /api/tenants  (admin: all, user: their tenants with role)
router.get('/', async (req, res, next) => {
  try {
    const userId = req.session.userId!;
    const isAdmin = req.session.role === 'admin';

    if (isAdmin) {
      const tenants = await tenantService.getAll();
      res.json({ success: true, data: tenants });
    } else {
      const tenants = await tenantService.getTenantsForUser(userId);
      res.json({ success: true, data: tenants });
    }
  } catch (err) {
    next(err);
  }
});

// ── Create tenant (platform admin only) ───────────────────────────────────
router.post('/', requireRole('admin'), async (req, res, next) => {
  try {
    const { name, slug } = req.body as { name: string; slug: string };
    if (!name || !slug) throw new AppError(400, 'name and slug are required');
    const tenant = await tenantService.create({ name, slug });
    res.status(201).json({ success: true, data: tenant });
  } catch (err) {
    next(err);
  }
});

// ── Get one tenant ─────────────────────────────────────────────────────────
router.get('/:id', async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const tenant = await tenantService.getById(id);
    if (!tenant) throw new AppError(404, 'Tenant not found');

    // Non-admins can only see their own tenants
    if (req.session.role !== 'admin') {
      const hasAccess = await tenantService.userHasAccess(req.session.userId!, id);
      if (!hasAccess) throw new AppError(403, 'Access denied');
    }

    res.json({ success: true, data: tenant });
  } catch (err) {
    next(err);
  }
});

// ── Update tenant (platform admin only) ───────────────────────────────────
router.put('/:id', requireRole('admin'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const { name, slug } = req.body as { name?: string; slug?: string };
    const tenant = await tenantService.update(id, { name, slug });
    if (!tenant) throw new AppError(404, 'Tenant not found');
    res.json({ success: true, data: tenant });
  } catch (err) {
    next(err);
  }
});

// ── Delete tenant (platform admin only, cannot delete tenant 1) ───────────
router.delete('/:id', requireRole('admin'), async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    if (id === 1) throw new AppError(400, 'Cannot delete the default tenant');
    await tenantService.delete(id);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// ── Tenant members ─────────────────────────────────────────────────────────
// GET /api/tenants/:id/members
router.get('/:id/members', requireRole('admin'), async (req, res, next) => {
  try {
    const tenantId = parseInt(req.params.id);
    const members = await tenantService.getMembers(tenantId);
    res.json({ success: true, data: members });
  } catch (err) {
    next(err);
  }
});

// POST /api/tenants/:id/members  { userId, role }
router.post('/:id/members', requireRole('admin'), async (req, res, next) => {
  try {
    const tenantId = parseInt(req.params.id);
    const { userId, role } = req.body as { userId: number; role?: 'admin' | 'member' };
    if (!userId) throw new AppError(400, 'userId is required');
    await tenantService.addUser(tenantId, userId, role ?? 'member');
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// PUT /api/tenants/:id/members/:uid  { role }
router.put('/:id/members/:uid', requireRole('admin'), async (req, res, next) => {
  try {
    const tenantId = parseInt(req.params.id);
    const userId = parseInt(req.params.uid);
    const { role } = req.body as { role: 'admin' | 'member' };
    if (!role) throw new AppError(400, 'role is required');
    await tenantService.updateUserRole(tenantId, userId, role);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/tenants/:id/members/:uid
router.delete('/:id/members/:uid', requireRole('admin'), async (req, res, next) => {
  try {
    const tenantId = parseInt(req.params.id);
    const userId = parseInt(req.params.uid);
    await tenantService.removeUser(tenantId, userId);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

export default router;
