import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { baselineController } from '../controllers/baseline.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Fleet take-over / Golden Site (M12 — K8). Mounted under the tenant-scoped
 * router.
 *
 * ┌─ NOT MOUNTED YET, AND ON PURPOSE ─────────────────────────────────────────┐
 * │ `routes/index.ts` belongs to another workstream in this cycle and is not  │
 * │ this milestone's to edit. One line under the M9 block wires it up:        │
 * │                                                                          │
 * │   tenantRouter.use('/baseline', baselineRoutes);                          │
 * │                                                                          │
 * │ Until that line exists, this surface is unreachable over HTTP and the     │
 * │ milestone is exercised through its service layer and its verification     │
 * │ harness. Stated here rather than left to be discovered by somebody        │
 * │ wondering why a 404 comes back from a route they can read.                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THREE CAPABILITIES, AND THE SPLIT IS THE POINT ──────────────────────────┐
 * │ CONFIG_READ     mine a baseline and read everything it produced. A mined  │
 * │                 draft IS the fleet's configuration, reorganised: whoever  │
 * │                 may read a snapshot may read a draft, and whoever may     │
 * │                 not, may not. This is R10's separation of CONFIG_READ     │
 * │                 from DEVICE_READ applied to the one screen that would     │
 * │                 otherwise hand out thirty routers' firewalls under a      │
 * │                 different name. Mining writes only `baseline_*` rows —    │
 * │                 no equipment, no template, no plan.                       │
 * │ DRIFT_MANAGE    classify a deviation and manage the exceptions. Deciding  │
 * │                 "this customer is legitimately different" changes what    │
 * │                 the conformance screen says, which is the same class of   │
 * │                 act as acknowledging a drift finding — and it is behind   │
 * │                 the same capability for the same reason.                  │
 * │ TEMPLATE_WRITE  promote a draft into `templates` + `template_revisions`.  │
 * │                 That is authoring a template body, and R6 says authoring  │
 * │                 a body is the privilege that lets a caller make this      │
 * │                 server evaluate template code.                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING HERE TOUCHES AN EQUIPMENT, AND NOTHING HERE PUBLISHES ───────────┐
 * │ Every route reads `devices`, `config_snapshots` and the `baseline_*`      │
 * │ tables. The only writes outside `baseline_*` are the promotion's          │
 * │ `templates` row and a `template_revisions` row with `status = 'draft'` —  │
 * │ which cannot be assigned, rendered into a plan or applied. D3 is intact:  │
 * │ nothing writes to an equipment outside `change_jobs`.                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

// ── the miner ────────────────────────────────────────────────────────────────
router.get('/params', requireCapability(CAPABILITIES.CONFIG_READ), baselineController.params);
router.post('/runs', requireCapability(CAPABILITIES.CONFIG_READ), baselineController.run);
router.get('/runs', requireCapability(CAPABILITIES.CONFIG_READ), baselineController.list);

// ── exceptions ───────────────────────────────────────────────────────────────
// Declared BEFORE `/runs/:id` could ever swallow them and on a distinct prefix,
// so no literal path is shadowed by a parameterised one.
router.get(
  '/exceptions',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  baselineController.exceptions,
);
router.delete(
  '/exceptions/:id',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  baselineController.removeException,
);

// ── one run ──────────────────────────────────────────────────────────────────
router.get('/runs/:id', requireCapability(CAPABILITIES.CONFIG_READ), baselineController.get);
router.get(
  '/runs/:id/deviations',
  requireCapability(CAPABILITIES.CONFIG_READ),
  baselineController.deviations,
);
router.get(
  '/runs/:id/conformance',
  requireCapability(CAPABILITIES.CONFIG_READ),
  baselineController.conformance,
);

// ── clusters and drafts ──────────────────────────────────────────────────────
router.get(
  '/clusters/:id',
  requireCapability(CAPABILITIES.CONFIG_READ),
  baselineController.cluster,
);
router.get('/drafts/:id', requireCapability(CAPABILITIES.CONFIG_READ), baselineController.draft);
router.post(
  '/drafts/:id/promote',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  baselineController.promote,
);

// ── triage ───────────────────────────────────────────────────────────────────
router.patch(
  '/deviations/:id',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  baselineController.classify,
);

export default router;
