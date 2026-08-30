import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { planController } from '../controllers/plan.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Plan compilation — `diff(ncm_desired, ncm_observed)` -> `PlanOp[]`.
 *
 * NOTHING UNDER THIS PREFIX TOUCHES AN EQUIPMENT, and nothing under it can be
 * made to. Compiling reads two documents and writes at most one
 * `config_renders` row. Applying is milestone M6 and has no route here at all
 * — not disabled, not behind a flag: absent. An endpoint that does not exist
 * cannot be mis-permissioned, which is the same argument that keeps
 * `SECRET_READ` off the devices controller.
 *
 * RBAC: `PLAN_CREATE` throughout. Deliberately NOT `TEMPLATE_WRITE`: compiling
 * a plan executes a STORED revision whose body got into the database under
 * `TEMPLATE_WRITE` and is frozen on publication. An operator who may not
 * author a template may still ask "what would ObliWAN change on this box", and
 * the capability matrix grants exactly that pair (`TEMPLATE_READ` +
 * `PLAN_CREATE`) to the operator role.
 *
 * `POST /validate` is the freshness check, and it is the reason a plan is safe
 * to review asynchronously: a plan carries the `ncm_hash` of the state it was
 * computed against, and this endpoint answers 409 the moment the device stops
 * matching it. An approval screen calls it before showing the Approve button;
 * M6's executor will call `assertPlanFresh` on a snapshot taken immediately
 * before the write. Same function, two call sites, one guarantee.
 *
 * NOT MOUNTED HERE — `routes/index.ts` is the M4 workstream's file. The lead
 * mounts this router under `tenantRouter` at `/plan`.
 */
const router = Router();

router.get('/config', requireCapability(CAPABILITIES.PLAN_CREATE), planController.config);

router.post(
  '/validate',
  requireCapability(CAPABILITIES.PLAN_CREATE),
  planController.validate,
);

router.post(
  '/compile',
  requireCapability(CAPABILITIES.PLAN_CREATE),
  planController.compileFleet,
);

router.post(
  '/devices/:deviceId',
  requireCapability(CAPABILITIES.PLAN_CREATE),
  planController.compileDevice,
);

export default router;
