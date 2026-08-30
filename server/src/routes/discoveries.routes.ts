import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { discoveriesController } from '../controllers/discoveries.controller';
import { requireCapability } from '../middleware/rbac';
import { validate } from '../middleware/validate';
import {
  bindDiscoverySchema,
  listDiscoveriesQuerySchema,
  scanDiscoveriesSchema,
  setDiscoveryStateSchema,
} from '../validators/device.schema';

/**
 * The PPP quarantine.
 *
 * Everything here is `DEVICE_DISCOVER`, including reading: the list is a
 * pre-tenant view of PPP usernames seen on a concentrator, and it is a
 * different, narrower audience than "can see the fleet". Binding additionally
 * writes a device, so it also demands `DEVICE_WRITE`.
 */
const router = Router();

router.get(
  '/',
  requireCapability(CAPABILITIES.DEVICE_DISCOVER),
  validate(listDiscoveriesQuerySchema, 'query'),
  discoveriesController.list,
);
router.post(
  '/scan',
  requireCapability(CAPABILITIES.DEVICE_DISCOVER),
  validate(scanDiscoveriesSchema),
  discoveriesController.scan,
);
router.get('/:id', requireCapability(CAPABILITIES.DEVICE_DISCOVER), discoveriesController.getById);
router.post(
  '/:id/bind',
  requireCapability(CAPABILITIES.DEVICE_DISCOVER),
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  validate(bindDiscoverySchema),
  discoveriesController.bind,
);
router.post(
  '/:id/state',
  requireCapability(CAPABILITIES.DEVICE_DISCOVER),
  validate(setDiscoveryStateSchema),
  discoveriesController.setState,
);

export default router;
