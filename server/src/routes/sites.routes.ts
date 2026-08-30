import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { sitesController } from '../controllers/sites.controller';
import { requireCapability } from '../middleware/rbac';
import { validate } from '../middleware/validate';
import { createSiteSchema, updateSiteSchema } from '../validators/site.schema';

/**
 * Sites. Mounted under the tenant-scoped router, so `requireAuth` and
 * `requireTenant` have already run.
 *
 * Reading the fleet is `DEVICE_READ`; changing it is `DEVICE_WRITE`. Config
 * reading is a DIFFERENT capability (`CONFIG_READ`, risk R10) and appears
 * nowhere in this file — an operator who may see the inventory does not thereby
 * get to see the configurations.
 */
const router = Router();

router.get('/', requireCapability(CAPABILITIES.DEVICE_READ), sitesController.list);
router.get('/:id', requireCapability(CAPABILITIES.DEVICE_READ), sitesController.getById);
router.get('/:id/presence', requireCapability(CAPABILITIES.DEVICE_READ), sitesController.presence);
/** The site's own inventory, filtered server-side. */
router.get('/:id/devices', requireCapability(CAPABILITIES.DEVICE_READ), sitesController.devices);
/** The PPP chronology of that inventory (spec §4.2). */
router.get(
  '/:id/ppp-sessions',
  requireCapability(CAPABILITIES.DEVICE_READ),
  sitesController.pppSessions,
);

router.post(
  '/',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  validate(createSiteSchema),
  sitesController.create,
);
router.patch(
  '/:id',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  validate(updateSiteSchema),
  sitesController.update,
);
router.delete('/:id', requireCapability(CAPABILITIES.DEVICE_WRITE), sitesController.delete);

export default router;
