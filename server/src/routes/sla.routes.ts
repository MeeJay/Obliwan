import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { slaController } from '../controllers/sla.controller';
import { requireAuth } from '../middleware/auth';
import { requireTenant } from '../middleware/tenant';
import { requireCapability } from '../middleware/rbac';

/**
 * Calculated SLA (F7, §10).
 *
 * ┌─ THIS ROUTER GUARDS ITSELF, AND THAT IS DELIBERATE ───────────────────────┐
 * │ `requireAuth` and `requireTenant` are applied HERE, at the top of the     │
 * │ router, BEFORE any path is declared and therefore UPSTREAM OF EVERY       │
 * │ BRANCH. Not on each route, not in one of them, not on some of them.       │
 * │                                                                          │
 * │ Every other feature router in this codebase inherits those two from       │
 * │ `tenantRouter` in `routes/index.ts` and adds only a capability. That      │
 * │ works exactly as long as the mount point does not move. The audits that   │
 * │ preceded this milestone found "an authenticated guard applied to one      │
 * │ protocol branch out of four" and three routers that were never mounted at │
 * │ all, and both failures share one shape: a guard whose effect depends on   │
 * │ something written somewhere else. So this router carries its own. The     │
 * │ cost is two redundant middleware calls per request under the tenant       │
 * │ mount — `requireAuth` re-reads a cached identity, `requireTenant` a       │
 * │ cached membership. The benefit is that these paths cannot become          │
 * │ unauthenticated by an edit to a file this milestone is not allowed to     │
 * │ touch.                                                                    │
 * │                                                                          │
 * │ MOUNTING, STATED HONESTLY: `routes/index.ts` is outside this milestone's  │
 * │ perimeter, so as of this commit NOTHING mounts this router and none of    │
 * │ the paths below answer over HTTP. Every path is listed against its        │
 * │ intended prefix under "THE SURFACE" so the mounting line can be written   │
 * │ in one gesture:                                                          │
 * │                                                                          │
 * │     tenantRouter.use('/sla', slaRoutes);                                  │
 * │                                                                          │
 * │ WHEN THAT LINE IS WRITTEN, THIS BLOCK CHANGES IN THE SAME COMMIT. A       │
 * │ header that says "not mounted" about a live router tells a reviewer to    │
 * │ skip the request, and it works just as well in reverse.                   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE SURFACE (prefix `/api/sla`) ─────────────────────────────────────────┐
 * │ GET    /api/sla/method                        DEVICE_READ                 │
 * │ GET    /api/sla/objectives                    DEVICE_READ                 │
 * │ PUT    /api/sla/objectives                    SETTINGS_MANAGE             │
 * │ DELETE /api/sla/objectives                    SETTINGS_MANAGE             │
 * │ PUT    /api/sla/objectives/sites/:siteId      SETTINGS_MANAGE             │
 * │ DELETE /api/sla/objectives/sites/:siteId      SETTINGS_MANAGE             │
 * │ GET    /api/sla/availability                  DEVICE_READ                 │
 * │ GET    /api/sla/sites/:siteId/availability    DEVICE_READ                 │
 * │ POST   /api/sla/reports                       DEVICE_READ + EXPORT_RUN    │
 * │ GET    /api/sla/reports                       DEVICE_READ                 │
 * │ GET    /api/sla/reports/:id                   DEVICE_READ                 │
 * │ GET    /api/sla/reports/:id/intervals         DEVICE_READ                 │
 * │ DELETE /api/sla/reports/:id                   SETTINGS_MANAGE             │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THREE CAPABILITIES, AND THE SPLIT IS THE POINT ──────────────────────────┐
 * │ DEVICE_READ      reading availability, the exclusions, the audit trail    │
 * │                  and the published method. This is fleet observation      │
 * │                  derived from presence history; it carries no             │
 * │                  configuration and no secret, so R10's separation of      │
 * │                  CONFIG_READ from DEVICE_READ is not engaged. Same class  │
 * │                  as the F5 weather map.                                   │
 * │                                                                          │
 * │ SETTINGS_MANAGE  THE OBJECTIVE AND THE VERDICT-VALIDITY KNOB. What the    │
 * │                  MSP sells, and how long one K7 sample is allowed to      │
 * │                  speak for. Both move the number a customer is shown and  │
 * │                  neither is an operator preference — but both ARE         │
 * │                  tenant-local decisions, and `TENANT_ROLE_CAPABILITIES`   │
 * │                  gives SETTINGS_MANAGE to a tenant's own admin, which is  │
 * │                  exactly the right blast radius. Deleting a stored        │
 * │                  report sits here too: a report is frozen against UPDATE  │
 * │                  by trigger, so DELETE is the only way to make one        │
 * │                  disappear, and that is a records-management act.         │
 * │                                                                          │
 * │ EXPORT_RUN       ISSUING a report, ON TOP OF DEVICE_READ. Issuing writes  │
 * │                  a frozen row, up to five thousand interval rows and one  │
 * │                  permanent `audit_log` entry, and produces the portable   │
 * │                  artefact an MSP hands to a customer — the same reasoning │
 * │                  and the same capability `attestation.routes.ts` uses for │
 * │                  `POST /issue`. `requireCapability` calls `next()` on     │
 * │                  success, so the two guards compose and the caller must   │
 * │                  hold both. Reading availability deliberately does NOT    │
 * │                  need it: looking at what would be issued has to be       │
 * │                  cheaper than issuing it, or nobody looks first.          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING HERE TOUCHES AN EQUIPMENT (D3) ──────────────────────────────────┐
 * │ F7 reads `sites`, `devices`, `ppp_sessions`, `reachability_verdicts` and  │
 * │ its own `sla_*` tables. It opens no session to a router, dials nothing,   │
 * │ and enqueues no `change_job`. Every route below is arithmetic over rows   │
 * │ M2 already wrote.                                                        │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

// ── THE GUARD, UPSTREAM OF EVERY BRANCH ──────────────────────────────────────
// Declared before the first path so that no route added later can be reached
// without them, whatever order it is written in and wherever this router ends
// up mounted.
router.use(requireAuth);
router.use(requireTenant);

// ── the published method ─────────────────────────────────────────────────────
router.get('/method', requireCapability(CAPABILITIES.DEVICE_READ), slaController.method);

// ── objectives ───────────────────────────────────────────────────────────────
// Literal paths before any parameterised sibling could shadow them.
router.get(
  '/objectives',
  requireCapability(CAPABILITIES.DEVICE_READ),
  slaController.objectives,
);
router.put(
  '/objectives',
  requireCapability(CAPABILITIES.SETTINGS_MANAGE),
  slaController.setTenantObjective,
);
router.delete(
  '/objectives',
  requireCapability(CAPABILITIES.SETTINGS_MANAGE),
  slaController.clearTenantObjective,
);
router.put(
  '/objectives/sites/:siteId',
  requireCapability(CAPABILITIES.SETTINGS_MANAGE),
  slaController.setSiteObjective,
);
router.delete(
  '/objectives/sites/:siteId',
  requireCapability(CAPABILITIES.SETTINGS_MANAGE),
  slaController.clearSiteObjective,
);

// ── computed, nothing stored ────────────────────────────────────────────────
router.get(
  '/availability',
  requireCapability(CAPABILITIES.DEVICE_READ),
  slaController.availability,
);
router.get(
  '/sites/:siteId/availability',
  requireCapability(CAPABILITIES.DEVICE_READ),
  slaController.siteAvailability,
);

// ── stored reports ───────────────────────────────────────────────────────────
// BOTH capabilities on the issue path. See the block above.
router.post(
  '/reports',
  requireCapability(CAPABILITIES.DEVICE_READ),
  requireCapability(CAPABILITIES.EXPORT_RUN),
  slaController.issue,
);
router.get('/reports', requireCapability(CAPABILITIES.DEVICE_READ), slaController.reports);
router.get('/reports/:id', requireCapability(CAPABILITIES.DEVICE_READ), slaController.report);
router.get(
  '/reports/:id/intervals',
  requireCapability(CAPABILITIES.DEVICE_READ),
  slaController.reportIntervals,
);
router.delete(
  '/reports/:id',
  requireCapability(CAPABILITIES.SETTINGS_MANAGE),
  slaController.removeReport,
);

export default router;
