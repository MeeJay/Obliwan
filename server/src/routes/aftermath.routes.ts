import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { aftermathController } from '../controllers/aftermath.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * F4 — "depuis ce changement" (ARCHITECTURE.md §10/F4). MOUNTED and live over
 * HTTP: `routes/index.ts` line 188, `tenantRouter.use('/aftermath', ...)`, next
 * to the interventions router it shares a milestone with.
 *
 * ┌─ CAPABILITIES ────────────────────────────────────────────────────────────┐
 * │ DRIFT_READ    read the reports. They contain interface names, counters    │
 * │               and timestamps — never a configuration, never a secret —    │
 * │               and they answer the same question as the drift screens one  │
 * │               week later.                                                 │
 * │ DRIFT_MANAGE  run an evaluation or a sweep. It WRITES a row into          │
 * │               `change_aftermath`, which is part of the §8.3 corpus the    │
 * │               planner reads, so it is not a read-only act even though it  │
 * │               touches no equipment.                                       │
 * │                                                                          │
 * │ NOT behind CHANGE_APPLY: nothing here can enqueue, approve or modify a    │
 * │ change job. Reading the aftermath of a push must not require the right to │
 * │ make one — the operator who investigates a regression is very often not   │
 * │ the one allowed to fix it.                                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

router.get('/params', requireCapability(CAPABILITIES.DRIFT_READ), aftermathController.params);
router.post(
  '/evaluate',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  aftermathController.evaluate,
);
router.post('/sweep', requireCapability(CAPABILITIES.DRIFT_MANAGE), aftermathController.sweep);

router.get('/', requireCapability(CAPABILITIES.DRIFT_READ), aftermathController.list);
router.get('/:id', requireCapability(CAPABILITIES.DRIFT_READ), aftermathController.get);

export default router;
