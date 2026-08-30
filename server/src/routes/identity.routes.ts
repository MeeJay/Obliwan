import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { identityController } from '../controllers/identity.controller';
import { requireAuth } from '../middleware/auth';
import { requireTenant } from '../middleware/tenant';
import { requireCapability } from '../middleware/rbac';

/**
 * ObliWAN F6 — identity watch (detection of a replaced device).
 *
 * ┌─ THE GUARD IS ON THE ROUTER, NOT ON THE ROUTES ───────────────────────────┐
 * │ `router.use(requireAuth)` and `router.use(requireTenant)` are declared    │
 * │ BEFORE the first `router.get(...)` below, so they run ahead of the        │
 * │ branching and there is no path through this file — present or future,     │
 * │ GET or POST, parameterised or not — that reaches a handler without them.  │
 * │                                                                          │
 * │ THIS IS DELIBERATE BELT-AND-BRACES, NOT A MISREADING OF THE MOUNT.        │
 * │ `routes/index.ts` puts `requireAuth` + `requireTenant` on `tenantRouter`  │
 * │ and every sibling router relies on that alone. Relying on it means this   │
 * │ file's safety is a property of a LINE IN ANOTHER FILE, and the day        │
 * │ somebody mounts this router on the outer `router` (as `/auth`,            │
 * │ `/live-alerts` and `/permission-sets` legitimately are) every route here  │
 * │ becomes anonymous, including the two that DIAL A CUSTOMER'S ROUTER WITH A │
 * │ VAULT CREDENTIAL. Express runs middleware once per matching layer, so     │
 * │ under the intended mount these two lines cost one cached membership       │
 * │ lookup and change no behaviour. Under any other mount they are the        │
 * │ difference between a locked feature and an open one.                      │
 * │                                                                          │
 * │ MOUNTED: `routes/index.ts` must add, in the tenant-scoped block:          │
 * │     tenantRouter.use('/identity', identityRoutes);                        │
 * │ giving the exact paths listed at the bottom of this block. If the         │
 * │ mounting ever changes, THIS COMMENT CHANGES IN THE SAME COMMIT — a header │
 * │ that lies about where a router lives is how three unmounted routers went  │
 * │ unnoticed on this project.                                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THREE CAPABILITIES, AND THE SPLIT IS THE POINT ──────────────────────────┐
 * │                                                                           │
 * │ DEVICE_READ   the event feed, one event, and everything F6 knows about a  │
 * │               device: serial, system identity, model, firmware, and when  │
 * │               each was last confirmed. This is fleet METADATA — the same  │
 * │               class as the inventory screen, which already shows          │
 * │               `devices.serial` behind this exact capability. It carries   │
 * │               no configuration and no secret, so R10's separation of      │
 * │               CONFIG_READ from DEVICE_READ is not engaged.                │
 * │                                                                           │
 * │ DEVICE_WRITE  `POST /devices/:deviceId/observe` and `POST /sweep`. Both   │
 * │               make this server DIAL a customer's router with a vault      │
 * │               credential. That is not a read of our own database and it   │
 * │               does not belong behind a read capability — same line        │
 * │               `weather.routes.ts` draws for its probe and its scan.       │
 * │               Both remain strictly READ-ONLY ON THE EQUIPMENT             │
 * │               (`/system/identity/print`, `/system/routerboard/print`,     │
 * │               `/system/resource/print`), so D3 holds: nothing outside     │
 * │               `change_jobs` writes to a device.                           │
 * │                                                                           │
 * │ CONFIG_READ   `GET /devices/:deviceId/baseline-trust`, AND NOTHING ELSE   │
 * │               ON THIS ROUTER. R10 is explicit that seeing the fleet must  │
 * │               not imply seeing its configuration, and this route speaks   │
 * │               about a `config_snapshots` row: it returns that row's id    │
 * │               and capture time and answers whether it is still a          │
 * │               reference. It returns NO snapshot content — but "device 42  │
 * │               has a snapshot from Tuesday" is a statement about the       │
 * │               config estate, and the capability that governs the config   │
 * │               estate is the one that should gate it. The cost of being    │
 * │               wrong here is one extra grant on a permission set; the cost │
 * │               of the other choice is a fleet-read role learning the shape │
 * │               of a customer's configuration history.                      │
 * │                                                                           │
 * │ DRIFT_MANAGE  `POST /events/:id/acknowledge`. Acknowledging "this chassis │
 * │               was replaced, and I have decided what that means for the    │
 * │               reference config" is the same act, on the same evidence,    │
 * │               as acknowledging a drift finding — which is the sentence    │
 * │               DRIFT_MANAGE was written for. It is deliberately NOT        │
 * │               DEVICE_WRITE: editing an inventory row and closing an       │
 * │               investigation are different powers, and the acknowledgement │
 * │               is the only thing on this router that changes a stored      │
 * │               verdict (it stops `baselineTrust()` reporting the event).   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING HERE WRITES TO AN EQUIPMENT, AND NOTHING HERE REPAIRS ANYTHING ──┐
 * │ The two POSTs that touch a router issue three `print` commands with no    │
 * │ argument and no interpolated value (D3, and nothing to escape per         │
 * │ dialect). The third POST writes three columns on one append-only row of   │
 * │ `device_identity_events`. No route on this router deletes a config        │
 * │ snapshot, retires a baseline, closes a drift finding, or writes to        │
 * │ `devices` — a replaced chassis DOES invalidate what rested on the old     │
 * │ box, and F6 says so instead of acting on it.                              │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * EXACT PATHS, under the mount above:
 *   GET  /api/identity/events
 *   GET  /api/identity/events/:id
 *   POST /api/identity/events/:id/acknowledge
 *   GET  /api/identity/devices/:deviceId
 *   GET  /api/identity/devices/:deviceId/baseline-trust
 *   POST /api/identity/devices/:deviceId/observe
 *   POST /api/identity/sweep
 */
const router = Router();

// ── The guard, upstream of every branch in this file. See the block above. ───
router.use(requireAuth);
router.use(requireTenant);

// ── The feed ────────────────────────────────────────────────────────────────
// Declared before any parameterised sibling could shadow them.
router.get('/events', requireCapability(CAPABILITIES.DEVICE_READ), identityController.events);
router.get('/events/:id', requireCapability(CAPABILITIES.DEVICE_READ), identityController.event);

// ── The one stored verdict this router can change ───────────────────────────
router.post(
  '/events/:id/acknowledge',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  identityController.acknowledge,
);

// ── What F6 knows about one device ──────────────────────────────────────────
// `/devices/:deviceId/baseline-trust` is declared BEFORE `/devices/:deviceId`
// would be reached for it — Express matches in declaration order and
// `/devices/:deviceId` does not match a two-segment tail, but the order is
// kept explicit so that adding `/devices/:deviceId/*` later stays safe.
router.get(
  '/devices/:deviceId/baseline-trust',
  requireCapability(CAPABILITIES.CONFIG_READ),
  identityController.baselineTrust,
);
router.get(
  '/devices/:deviceId',
  requireCapability(CAPABILITIES.DEVICE_READ),
  identityController.device,
);

// ── Asking a box who it is. Read-only on the equipment (D3). ────────────────
router.post(
  '/devices/:deviceId/observe',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  identityController.observe,
);
router.post('/sweep', requireCapability(CAPABILITIES.DEVICE_WRITE), identityController.sweep);

export default router;
