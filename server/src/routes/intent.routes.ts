import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { intentController } from '../controllers/intent.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * The Intent Compiler (M11 — K4). Tenant-scoped.
 *
 * ┌─ NOT YET MOUNTED, AND THAT IS NOT AN OVERSIGHT ───────────────────────────┐
 * │ `routes/index.ts` is owned by another workstream and this milestone may   │
 * │ not edit it. One line mounts this router:                                 │
 * │                                                                          │
 * │     import intentRoutes from './intent.routes';                          │
 * │     tenantRouter.use('/intent', intentRoutes);                           │
 * │                                                                          │
 * │ Placed next to `/templates` and `/plan`: like them, everything here       │
 * │ COMPILES and nothing applies. Until that line exists these endpoints are  │
 * │ unreachable, which is the honest state to leave the tree in — a route     │
 * │ half-wired somewhere else would be worse than a route not wired at all.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THREE CAPABILITIES, AND THE SPLIT IS THE POINT ──────────────────────────┐
 * │ TEMPLATE_READ   read intents and the brand-coverage matrix. An intent is  │
 * │                 a site design: the same class of object as a template,    │
 * │                 behind the same capability.                               │
 * │ TEMPLATE_WRITE  author one. Writing a site design is authoring, and       │
 * │                 authoring is the boundary the product already draws.      │
 * │ PLAN_CREATE     COMPILE. Its catalogue description reads "Compute a       │
 * │                 change plan without touching any equipment", which is     │
 * │                 exactly what a compilation is: it produces the desired    │
 * │                 NCM the planner will diff, and it dials nothing.          │
 * │ CONFIG_READ     read a stored artefact and its desired NCM. Distinct from │
 * │                 DEVICE_READ for the reason risk R10 gives: a rendered     │
 * │                 configuration is more sensitive than an inventory row,    │
 * │                 even redacted — it is a map of the customer's network.    │
 * │                                                                          │
 * │ No capability here can write to an equipment, because no route here can.  │
 * │ Applying a compiled artefact is `/changes` and nothing else (D3).         │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

// ── the vendor knowledge itself ──────────────────────────────────────────────
// Declared BEFORE anything parameterised, so no literal path can be swallowed
// by `/:id`.
router.get(
  '/capabilities',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  intentController.capabilities,
);

// The refusal, before the network and before the intent is even saved. Behind
// PLAN_CREATE rather than TEMPLATE_READ: it answers "what would this compile
// to", which is a compilation question.
router.post('/check', requireCapability(CAPABILITIES.PLAN_CREATE), intentController.check);

// ── the intents ──────────────────────────────────────────────────────────────
router.get('/', requireCapability(CAPABILITIES.TEMPLATE_READ), intentController.list);
router.post('/', requireCapability(CAPABILITIES.TEMPLATE_WRITE), intentController.create);
router.get('/:id', requireCapability(CAPABILITIES.TEMPLATE_READ), intentController.get);
router.patch('/:id', requireCapability(CAPABILITIES.TEMPLATE_WRITE), intentController.update);
router.delete('/:id', requireCapability(CAPABILITIES.TEMPLATE_WRITE), intentController.remove);

// ── compilation ──────────────────────────────────────────────────────────────
router.post('/:id/compile', requireCapability(CAPABILITIES.PLAN_CREATE), intentController.compile);
router.get(
  '/:id/compilations',
  requireCapability(CAPABILITIES.CONFIG_READ),
  intentController.compilations,
);
router.get(
  '/:id/compilations/:compilationId',
  requireCapability(CAPABILITIES.CONFIG_READ),
  intentController.compilation,
);

// Why a site cannot be built on a given brand. Behind TEMPLATE_READ, not
// CONFIG_READ: a gap names a capability and a brand, never a configuration.
router.get('/:id/gaps', requireCapability(CAPABILITIES.TEMPLATE_READ), intentController.gaps);

export default router;
