import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { rolloutsController } from '../controllers/rollouts.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Wave rollouts — K3. Mounted under the tenant-scoped router.
 *
 * LEAD: `tenantRouter.use('/rollouts', rolloutsRoutes);` in `routes/index.ts`,
 * next to `/changes`. It belongs on the same side of the line that file draws
 * at M6: everything above `/changes` reads, compiles or proposes; `/changes`
 * and `/rollouts` are the only two prefixes from which this server can modify
 * somebody else's hardware. The difference between them is scale — `/changes`
 * writes to one box, `/rollouts` writes to a fleet in an order it chose.
 *
 * ┌─ THE CAPABILITY MAP ──────────────────────────────────────────────────────┐
 * │ PLAN_CREATE     read a rollout and PREVIEW one. The impact screen writes  │
 * │                 nothing: the same grant that lets you ask "what would     │
 * │                 ObliWAN change on these 40 boxes" lets you watch what it  │
 * │                 did.                                                      │
 * │ ROLLOUT_MANAGE  compose, launch, advance, pause, resume, abort. The grant │
 * │                 has existed since M1 ("Start, pause and abort wave        │
 * │                 rollouts", sensitive: true) and this is what uses it.     │
 * │ CHANGE_APPROVE  checked a SECOND time inside `compose`, when the body     │
 * │                 carries an override. Forcing N devices past a             │
 * │                 Management-Path Guard refusal in one gesture must not     │
 * │                 ride in on the grant that merely starts rollouts.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * WHAT IS DELIBERATELY ABSENT: nothing here edits a composed rollout's
 * membership or wave order. §8.3's "degraded last" and §8.5's subtree
 * interlock are decided once, at composition, in front of the operator — and
 * migration 010 refuses the rows that would break either. A `PATCH /waves/:i`
 * would exist for no other purpose than to defeat both.
 *
 * There is also no `POST /rollouts/:id/rollback`. The rollback of the previous
 * waves is what a FAILED HEALTH GATE does, automatically, with the launcher's
 * signature; a manual button beside it would be a second, unsigned path to the
 * same fleet-wide write.
 */
const router = Router();

// ── Reads, and the impact screen ─────────────────────────────────────────────
router.get('/', requireCapability(CAPABILITIES.PLAN_CREATE), rolloutsController.list);
// Literal path before the parameterised one, so `/preview` can never be
// swallowed as a rollout id.
router.post('/preview', requireCapability(CAPABILITIES.PLAN_CREATE), rolloutsController.preview);
router.get('/:id', requireCapability(CAPABILITIES.PLAN_CREATE), rolloutsController.get);

// ── Composition ──────────────────────────────────────────────────────────────
router.post('/', requireCapability(CAPABILITIES.ROLLOUT_MANAGE), rolloutsController.compose);

// ── The gestures that move a fleet ───────────────────────────────────────────
router.post(
  '/:id/launch',
  requireCapability(CAPABILITIES.ROLLOUT_MANAGE),
  rolloutsController.launch,
);
router.post(
  '/:id/advance',
  requireCapability(CAPABILITIES.ROLLOUT_MANAGE),
  rolloutsController.advance,
);
router.post(
  '/:id/pause',
  requireCapability(CAPABILITIES.ROLLOUT_MANAGE),
  rolloutsController.pause,
);
router.post(
  '/:id/resume',
  requireCapability(CAPABILITIES.ROLLOUT_MANAGE),
  rolloutsController.resume,
);
router.post(
  '/:id/abort',
  requireCapability(CAPABILITIES.ROLLOUT_MANAGE),
  rolloutsController.abort,
);

export default router;
