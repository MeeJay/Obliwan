import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { interventionsController } from '../controllers/interventions.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * F3 — the intervention mode (ARCHITECTURE.md §10/F3). Mounted under the
 * tenant-scoped router.
 *
 * ┌─ MOUNTED. THIS SURFACE IS LIVE OVER HTTP ─────────────────────────────────┐
 * │ `routes/index.ts` lines 187-188 wire the pair under the tenant router:    │
 * │                                                                          │
 * │   tenantRouter.use('/interventions', interventionsRoutes);                │
 * │   tenantRouter.use('/aftermath', aftermathRoutes);                        │
 * │                                                                          │
 * │ This block used to say the opposite — "not mounted yet", "until they      │
 * │ exist this surface is unreachable over HTTP" — long after both lines had  │
 * │ been written. A header that misstates the mounting is not a stale         │
 * │ comment, it is an instruction to skip the HTTP surface: a reviewer who    │
 * │ believes it tests the service layer and never sends the request, and      │
 * │ everything reachable only through `POST /api/interventions` goes          │
 * │ unexercised. This project has already lost routers to that exact reading. │
 * │ If the mounting ever changes, THIS BLOCK CHANGES IN THE SAME COMMIT.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ TWO CAPABILITIES, BOTH ALREADY IN THE CATALOGUE ─────────────────────────┐
 * │ DRIFT_READ    read windows, their lifecycle log and what they absorbed.   │
 * │               An intervention record names an operator and a reason; it   │
 * │               carries no configuration and no secret, so it sits with the │
 * │               drift screens rather than behind CONFIG_READ.               │
 * │ DRIFT_MANAGE  declare, close, cancel, decide a disposition, sweep.        │
 * │               Declaring a window CHANGES WHAT THE DRIFT SCREEN SAYS —     │
 * │               findings on that device stop reading as anomalies nobody    │
 * │               owns — which is precisely the act DRIFT_MANAGE already      │
 * │               covers ("acknowledge / ignore a drift finding"). No new     │
 * │               capability is invented: `shared/src/capabilities.ts` is     │
 * │               outside this feature's perimeter, and a feature that needs  │
 * │               a new privilege to be safe would be a design smell here —   │
 * │               nothing on this router writes to an equipment.              │
 * │                                                                          │
 * │ `DRIFT_MANAGE` already implies `DRIFT_READ` through CAPABILITY_IMPLIES.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ D3 IS UNTOUCHED ─────────────────────────────────────────────────────────┐
 * │ No route here enqueues a change job, renders a plan or opens a write      │
 * │ session. `POST /` and `POST /:id/close` may take a configuration READ     │
 * │ (`collect: true`), the same read `POST /drift/devices/:id/run` already    │
 * │ offers, and nothing else reaches the equipment. An open intervention is a │
 * │ declaration, never an authorisation.                                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

// ── literal paths first, so no parameterised route can shadow them ──────────
router.get('/params', requireCapability(CAPABILITIES.DRIFT_READ), interventionsController.params);
router.get(
  '/overview',
  requireCapability(CAPABILITIES.DRIFT_READ),
  interventionsController.overview,
);
router.get(
  '/devices/:deviceId/live',
  requireCapability(CAPABILITIES.DRIFT_READ),
  interventionsController.live,
);
router.post(
  '/sweep',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  interventionsController.sweep,
);

// ── the window itself ───────────────────────────────────────────────────────
router.get('/', requireCapability(CAPABILITIES.DRIFT_READ), interventionsController.list);
router.post('/', requireCapability(CAPABILITIES.DRIFT_MANAGE), interventionsController.open);

router.get('/:id', requireCapability(CAPABILITIES.DRIFT_READ), interventionsController.get);
router.get(
  '/:id/events',
  requireCapability(CAPABILITIES.DRIFT_READ),
  interventionsController.events,
);
router.get('/:id/drift', requireCapability(CAPABILITIES.DRIFT_READ), interventionsController.links);

router.post(
  '/:id/close',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  interventionsController.close,
);
router.post(
  '/:id/cancel',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  interventionsController.cancel,
);
router.patch(
  '/:id/disposition',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  interventionsController.disposition,
);

export default router;
