import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { permissionSetService } from '../services/permissionSet.service';
import { logger } from '../utils/logger';

const router = Router();

/**
 * VERIF-SECFIX R9-c — the two read routes below were `requireAuth` alone, while
 * the three write routes were already `requireRole('admin')`.
 *
 * What leaked is not data belonging to a customer, so this is cartography rather
 * than a breach: `GET /` returns every permission set with its full capability
 * list, and `GET /capabilities` returns the complete catalogue of capability
 * names the build knows about. Any authenticated account — including one with no
 * `user_tenants` row at all, which 403s on every other route in the product —
 * could read the exact vocabulary of the authorisation system and the exact
 * shape of each role, which is the map you want before looking for a gap in it.
 *
 * Restricting them costs nothing: the ONLY consumer of either route is
 * `client/src/components/PermissionSetsTab.tsx` (both are fetched together in
 * one `Promise.all`, line 48-49), which is a tab of `AdminUsersPage` — a screen
 * whose other calls already go to `/api/users`, i.e. behind `requireRole('admin')`
 * already. Nothing else in the client or the server references them.
 */

/**
 * GET /api/permission-sets
 * Returns all permission sets. Platform admins only (see above).
 */
router.get('/', requireAuth, requireRole('admin'), async (_req, res) => {
  try {
    const sets = await permissionSetService.getAll();
    res.json({ success: true, data: sets });
  } catch (err) {
    logger.error(err, 'Failed to list permission sets');
    res.status(500).json({ success: false, error: 'Failed to list permission sets' });
  }
});

/**
 * GET /api/permission-sets/capabilities
 * Returns available capabilities for this app. Platform admins only (see above).
 */
router.get('/capabilities', requireAuth, requireRole('admin'), async (_req, res) => {
  try {
    const capabilities = permissionSetService.getAvailableCapabilities();
    res.json({ success: true, data: capabilities });
  } catch (err) {
    logger.error(err, 'Failed to list capabilities');
    res.status(500).json({ success: false, error: 'Failed to list capabilities' });
  }
});

/**
 * POST /api/permission-sets
 * Creates a new permission set. Admin only.
 */
router.post('/', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { name, slug, capabilities } = req.body as { name: string; slug: string; capabilities: string[] };
    if (!name || !slug || !Array.isArray(capabilities)) {
      res.status(400).json({ success: false, error: 'name, slug, and capabilities[] are required' });
      return;
    }
    const set = await permissionSetService.create({ name, slug, capabilities });
    res.status(201).json({ success: true, data: set });
  } catch (err: any) {
    logger.error(err, 'Failed to create permission set');
    const status = err.message?.includes('unique') || err.code === '23505' ? 409 : 500;
    res.status(status).json({ success: false, error: err.message || 'Failed to create permission set' });
  }
});

/**
 * PUT /api/permission-sets/:id
 * Updates a permission set. Admin only.
 */
router.put('/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) { res.status(400).json({ success: false, error: 'Invalid ID' }); return; }
    const { name, slug, capabilities } = req.body as { name?: string; slug?: string; capabilities?: string[] };
    const set = await permissionSetService.update(id, { name, slug, capabilities });
    res.json({ success: true, data: set });
  } catch (err: any) {
    logger.error(err, 'Failed to update permission set');
    const status = err.message === 'Permission set not found' ? 404 : 500;
    res.status(status).json({ success: false, error: err.message || 'Failed to update permission set' });
  }
});

/**
 * DELETE /api/permission-sets/:id
 * Deletes a non-default permission set. Admin only.
 */
router.delete('/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) { res.status(400).json({ success: false, error: 'Invalid ID' }); return; }
    await permissionSetService.delete(id);
    res.json({ success: true });
  } catch (err: any) {
    logger.error(err, 'Failed to delete permission set');
    const status = err.message === 'Permission set not found' ? 404
      : err.message?.includes('default') ? 400
      : 500;
    res.status(status).json({ success: false, error: err.message || 'Failed to delete permission set' });
  }
});

export default router;
