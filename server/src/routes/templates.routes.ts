import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { templatesController } from '../controllers/templates.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Templates, revisions, partials and assignments.
 *
 * ┌─ RBAC, BY GESTURE ───────────────────────────────────────────────────────┐
 * │ TEMPLATE_READ   list and read templates, revisions, partials,           │
 * │                 assignments; diff two revisions; RENDER A STORED        │
 * │                 REVISION on a witness device.                            │
 * │ TEMPLATE_WRITE  author, publish, quarantine, assign — and RENDER AN      │
 * │                 ARBITRARY BODY.                                          │
 * │                                                                          │
 * │ `TEMPLATE_WRITE` is the mitigation R6 names, and it is a security        │
 * │ boundary rather than a CRUD permission: it is the capability that lets   │
 * │ a caller make this server EXECUTE TEMPLATE CODE OF THEIR CHOOSING, on    │
 * │ the machine that holds the administration credentials of every device    │
 * │ of every customer. The sandbox (`worker_threads`, `resourceLimits`, a    │
 * │ 5 s ceiling, a pure-JSON context and an empty `vm` realm) is what makes  │
 * │ that survivable; this capability is what makes it authorised. Grant it   │
 * │ the way you would grant shell access, because that is what it is.        │
 * │                                                                          │
 * │ The line falls on WHO CHOSE THE CODE, not on who pressed the button:     │
 * │   POST /preview                 body in the request  -> TEMPLATE_WRITE  │
 * │   POST /revisions/:id/preview   body in the database  -> TEMPLATE_READ   │
 * │ A stored body got there under TEMPLATE_WRITE and is frozen once          │
 * │ published; `loadRevisionBundle` reads nothing else.                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Route ORDER is load-bearing: every literal prefix (`/partials`,
 * `/revisions`, `/assignments`, `/devices`, `/preview`) is declared BEFORE
 * `/:id`, or the parameter swallows it and `GET /templates/partials` starts
 * looking up a template whose id is the string "partials".
 *
 * NOT MOUNTED BY THIS FILE. `routes/index.ts` belongs to the M4 workstream;
 * the lead mounts this router under `tenantRouter` at `/templates`, which is
 * where `requireAuth` + `requireTenant` are applied. Nothing here reads
 * `req.tenantId` without them having run.
 */
const router = Router();

// ── Partials ────────────────────────────────────────────────────────────────
router.get(
  '/partials',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  templatesController.listPartials,
);
router.post(
  '/partials',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.createPartial,
);
// Declared before `/partials/:id/...` so the literal is not eaten by the param.
router.post(
  '/partials/revisions/:revId/publish',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.publishPartialRevision,
);
router.post(
  '/partials/:id/revisions',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.createPartialRevision,
);

// ── Revisions ───────────────────────────────────────────────────────────────
router.get(
  '/revisions/:fromId/diff/:toId',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  templatesController.diffRevisions,
);
router.post(
  '/revisions/:revId/publish',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.publishRevision,
);
router.post(
  '/revisions/:revId/status',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.setRevisionStatus,
);
// Rendering a STORED revision. See the banner: TEMPLATE_READ on purpose.
router.post(
  '/revisions/:revId/preview',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  templatesController.previewRevision,
);
router.get(
  '/revisions/:revId',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  templatesController.getRevision,
);
router.patch(
  '/revisions/:revId',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.updateRevision,
);

// ── Preview of an arbitrary body — THE R6 BOUNDARY ──────────────────────────
router.post(
  '/preview',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.previewScratch,
);

// ── Assignments ─────────────────────────────────────────────────────────────
router.get(
  '/assignments',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  templatesController.listAssignments,
);
router.post(
  '/assignments',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.createAssignment,
);
router.patch(
  '/assignments/:id',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.updateAssignment,
);
router.delete(
  '/assignments/:id',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.removeAssignment,
);

// ── Per-device views ────────────────────────────────────────────────────────
router.get(
  '/devices/:deviceId/resolution',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  templatesController.deviceResolution,
);
router.get(
  '/devices/:deviceId/render',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  templatesController.deviceRender,
);

// ── Templates ───────────────────────────────────────────────────────────────
router.get('/', requireCapability(CAPABILITIES.TEMPLATE_READ), templatesController.list);
router.post('/', requireCapability(CAPABILITIES.TEMPLATE_WRITE), templatesController.create);
router.get('/:id', requireCapability(CAPABILITIES.TEMPLATE_READ), templatesController.get);
router.patch('/:id', requireCapability(CAPABILITIES.TEMPLATE_WRITE), templatesController.update);
router.get(
  '/:id/revisions',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  templatesController.listRevisions,
);
router.post(
  '/:id/revisions',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.createRevision,
);

// There is deliberately NO `DELETE /:id`. A template whose revisions produced
// renders that produced plans is provenance: `config_renders.revision_id` is
// ON DELETE RESTRICT for exactly that reason. Archiving is `PATCH /:id` with
// `status: 'archived'`, which the assignment resolver already honours.

export default router;
