import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireTenant } from '../middleware/tenant';
import { requireRole } from '../middleware/rbac';
import { importExportController } from '../controllers/importExport.controller';

const router = Router();

// All import/export routes are admin-only
router.use(requireAuth);
router.use(requireRole('admin'));

/**
 * AUDIT-SEC #2 / AUDIT-CORR §4.1 (CRITIQUE) — this router is mounted under
 * `/admin` in the "global (no tenant required)" section of routes/index.ts, so
 * it never went through `requireTenant`, and both handlers fell back to
 * `req.session.currentTenantId ?? 1`. An admin whose session had no current
 * tenant (fresh session, tenant just deleted, direct link to
 * /admin/import-export before any switch) uploaded a customer bundle straight
 * into the MASTER tenant: 40 groups, 6 teams and their settings created in
 * "Default", with the source uuids now owned by tenant 1 — after which a
 * re-import into the right tenant sees them as foreign and regenerates fresh
 * uuids, losing the correspondence with the source instance for good.
 *
 * `requireTenant` is applied HERE rather than by moving the mount under
 * `tenantRouter`, because routes/index.ts belongs to the M2 agent. The effect
 * is the same and the two `?? 1` in the controller are gone.
 */
router.use(requireTenant);

router.get('/export', importExportController.exportData);
router.post('/import', importExportController.importData);

export default router;
