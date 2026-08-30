import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { driftController } from '../controllers/drift.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Drift. Mounted under the tenant-scoped router.
 *
 * ┌─ TWO CAPABILITIES, AND THE SPLIT IS THE POINT ────────────────────────────┐
 * │ DRIFT_READ    see runs, findings and (later) their attribution.           │
 * │ DRIFT_MANAGE  acknowledge / ignore a finding, and trigger a run.          │
 * │                                                                          │
 * │ Ignoring is behind the second one because it CHANGES WHAT THE FLEET       │
 * │ SCREEN SAYS: a suppressed critical stops keeping a device red. That is a  │
 * │ decision, not a view preference, and it must be attributable to someone   │
 * │ who was entitled to make it.                                              │
 * │                                                                          │
 * │ Triggering a run is DRIFT_MANAGE and not DRIFT_READ for the same reason a │
 * │ collection is CONFIG_WRITE: with `collect: true` it makes the platform    │
 * │ dial the equipment.                                                       │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

/** Fleet roll-up. Declared before `/runs/:id` so no literal path is swallowed
 *  by a parameterised one. */
router.get('/status', requireCapability(CAPABILITIES.DRIFT_READ), driftController.status);

router.get('/runs', requireCapability(CAPABILITIES.DRIFT_READ), driftController.listRuns);
/** The runs of one device. Same handler: `listRuns` already filters on an
 *  optional deviceId, it simply had no path that supplied one. */
router.get(
  '/devices/:deviceId/runs',
  requireCapability(CAPABILITIES.DRIFT_READ),
  driftController.listRuns,
);
router.get('/runs/:id', requireCapability(CAPABILITIES.DRIFT_READ), driftController.getRun);
router.get(
  '/runs/:id/findings',
  requireCapability(CAPABILITIES.DRIFT_READ),
  driftController.listRunFindings,
);

/** Fleet-wide findings, filterable by device / severity / kind / resource.
 *  Ignored findings are excluded unless `?includeIgnored=true` — they are kept,
 *  not hidden. */
router.get('/findings', requireCapability(CAPABILITIES.DRIFT_READ), driftController.listFindings);
router.get(
  '/findings/:id',
  requireCapability(CAPABILITIES.DRIFT_READ),
  driftController.getFinding,
);
/** The client PATCHes the finding itself with `{ ignored }`. The explicit
 *  `/ignore` sub-path below is kept — it is the clearer of the two and may
 *  already be bookmarked — and both reach the same handler. */
router.patch(
  '/findings/:id',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  driftController.setIgnored,
);
router.patch(
  '/findings/:id/ignore',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  driftController.setIgnored,
);

router.post(
  '/devices/:deviceId/run',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  driftController.run,
);

export default router;
