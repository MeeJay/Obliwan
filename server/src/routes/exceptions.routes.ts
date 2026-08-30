import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { exceptionsController } from '../controllers/exceptions.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Drift exceptions (F1). Mounted under the tenant-scoped router.
 *
 * ┌─ THE SAME TWO CAPABILITIES AS THE DRIFT SCREEN, AND THE SAME SPLIT ───────┐
 * │ DRIFT_READ    see which drift is being forgiven, by whom, until when.     │
 * │ DRIFT_MANAGE  grant, renew or revoke an exception.                        │
 * │                                                                           │
 * │ Granting is behind DRIFT_MANAGE for the reason `drift.routes.ts` already  │
 * │ states about ignoring: it CHANGES WHAT THE FLEET SCREEN SAYS. A           │
 * │ suppressed critical stops keeping a device red. That is a decision, not a │
 * │ view preference, and it must be attributable to somebody entitled to make │
 * │ it — which is now literal: the username is stored on the row and in the   │
 * │ ledger.                                                                   │
 * │                                                                           │
 * │ REVOKING is also DRIFT_MANAGE and not DRIFT_READ, even though it only     │
 * │ ever makes MORE drift visible. Un-forgiving a rule turns a green device   │
 * │ red at 2am for whoever is on call, and "it only makes things stricter" is │
 * │ not a reason to let anyone do it unattributed.                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING HERE TOUCHES AN EQUIPMENT ───────────────────────────────────────┐
 * │ Every route reads or writes `drift_exceptions`,                           │
 * │ `drift_exception_reviews`, `drift_findings.ignored` and `audit_log`. No   │
 * │ route compiles a plan, enqueues a change job or opens a connection to a   │
 * │ router (decision D3).                                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

/** Literal paths first, so no parameterised route swallows them. */
router.get(
  '/review-queue',
  requireCapability(CAPABILITIES.DRIFT_READ),
  exceptionsController.reviewQueue,
);
router.post('/sweep', requireCapability(CAPABILITIES.DRIFT_MANAGE), exceptionsController.sweep);

router.get('/', requireCapability(CAPABILITIES.DRIFT_READ), exceptionsController.list);
router.post('/', requireCapability(CAPABILITIES.DRIFT_MANAGE), exceptionsController.create);

router.get('/:id', requireCapability(CAPABILITIES.DRIFT_READ), exceptionsController.get);
router.post(
  '/:id/renew',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  exceptionsController.renew,
);
/**
 * POST and not DELETE. A revocation is an ACT that is recorded with its reason
 * and its author, and the exception row survives it — `DELETE` would promise
 * the opposite of what happens and invite a client to treat the row as gone.
 */
router.post(
  '/:id/revoke',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  exceptionsController.revoke,
);

export default router;
