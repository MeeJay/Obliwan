import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { configController } from '../controllers/config.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Config snapshots and the NCM. Mounted under the tenant-scoped router, so
 * `requireAuth` and `requireTenant` have already run.
 *
 * ┌─ WHY CONFIG_READ AND NOT DEVICE_READ ─────────────────────────────────────┐
 * │ Risk R10. Seeing that a device exists in the inventory is a different     │
 * │ question from seeing what it carries: a snapshot describes a firewall, an │
 * │ IPsec topology, a management-service exposure and a local user list. The  │
 * │ two capabilities are separate in `shared/src/capabilities.ts` for exactly  │
 * │ this surface.                                                             │
 * │                                                                          │
 * │ And why the raw export is still `CONFIG_READ` and not `SECRET_READ`: it   │
 * │ is the REDACTED export. `show-sensitive=no` is hard-wired in              │
 * │ `collect.service.ts`, and a non-empty secret prop aborts the collection   │
 * │ before anything is stored. If that ever stops being true, this route is   │
 * │ the one that has to move, and the comment is here so the reviewer knows.  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY COLLECT IS CONFIG_WRITE ─────────────────────────────────────────────┐
 * │ It writes nothing to the equipment — M4 is read-only drift and the write  │
 * │ paths arrive at M6. But it makes the platform DIAL a customer's router on │
 * │ demand, and an operator entitled to read stored configuration is not      │
 * │ thereby entitled to generate traffic towards the fleet.                   │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

// -- Per device --------------------------------------------------------------
router.get(
  '/devices/:deviceId/snapshots',
  requireCapability(CAPABILITIES.CONFIG_READ),
  configController.listSnapshots,
);
/** N against N-1 by default; `?from=&to=` pins either side explicitly. */
router.get(
  '/devices/:deviceId/compare',
  requireCapability(CAPABILITIES.CONFIG_READ),
  configController.compare,
);
router.post(
  '/devices/:deviceId/collect',
  requireCapability(CAPABILITIES.CONFIG_WRITE),
  configController.collect,
);

// -- Per snapshot ------------------------------------------------------------
/** Fleet-wide snapshot list. `deviceId` narrows it; without it the caller gets
 *  every snapshot of the tenant, which is what the Configurations screen shows.
 *  Declared before '/snapshots/:id' so the literal path wins over the pattern. */
router.get(
  '/snapshots',
  requireCapability(CAPABILITIES.CONFIG_READ),
  configController.listSnapshots,
);

router.get(
  '/snapshots/:id',
  requireCapability(CAPABILITIES.CONFIG_READ),
  configController.getSnapshot,
);
router.get(
  '/snapshots/:id/ncm',
  requireCapability(CAPABILITIES.CONFIG_READ),
  configController.getNcmTree,
);
router.get(
  // Aliased as `/raw` too: the client calls it that, and "raw" describes what
  // comes back (the stored export, decompressed and redacted) better than
  // "export", which in this product also means an import/export bundle (§8.1).
  ['/snapshots/:id/export', '/snapshots/:id/raw'],
  requireCapability(CAPABILITIES.CONFIG_READ),
  configController.exportSnapshot,
);
/** The `ncm_*` tables are a rebuildable cache (§8.3); this is the one door that
 *  rebuilds one snapshot's rows without a migration. */
router.post(
  '/snapshots/:id/reindex',
  requireCapability(CAPABILITIES.CONFIG_WRITE),
  configController.reindex,
);

export default router;
