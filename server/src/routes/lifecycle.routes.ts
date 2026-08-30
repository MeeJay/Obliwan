import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { lifecycleController } from '../controllers/lifecycle.controller';
import { requireCapability, requireRole } from '../middleware/rbac';

/**
 * End-of-Life Inventory (F8). Intended to be mounted under the tenant-scoped
 * router as `/lifecycle`.
 *
 * ┌─ NOT MOUNTED. NOTHING HERE IS REACHABLE OVER HTTP YET ────────────────────┐
 * │ `server/src/routes/index.ts` is OUTSIDE this milestone's perimeter, so    │
 * │ this router is written, guarded and complete — and NOT WIRED. One line    │
 * │ next to the F5 block finishes it:                                         │
 * │                                                                          │
 * │   import lifecycleRoutes from './lifecycle.routes';                       │
 * │   tenantRouter.use('/lifecycle', lifecycleRoutes);                        │
 * │                                                                          │
 * │ THIS BLOCK CHANGES IN THE SAME COMMIT AS THAT LINE. A header that claims  │
 * │ "unreachable over HTTP" about a mounted router tells a reviewer to test   │
 * │ the service layer and skip the request — which is how three unmounted     │
 * │ routers went unnoticed on this project — and it works exactly as well in  │
 * │ reverse. The paths below are written as they will be once mounted.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ TWO GUARDS, AND THE SPLIT IS THE ENTIRE SECURITY DESIGN ─────────────────┐
 * │                                                                          │
 * │ DEVICE_READ           EVERY READ. The renewal list, the summary, the      │
 * │                       per-device verdict, the research list, the          │
 * │                       catalogue and its journal.                          │
 * │                                                                          │
 * │                       Not CONFIG_READ: nothing here comes from a config   │
 * │                       snapshot. The projection is a device's name, site,  │
 * │                       brand, family, `model` and `os_version` — fleet     │
 * │                       metadata, the same class M2 already serves under    │
 * │                       DEVICE_READ — plus published vendor dates. R10's    │
 * │                       separation of CONFIG_READ from DEVICE_READ is not   │
 * │                       engaged because there is no snapshot, no secret and │
 * │                       no configuration anywhere in the payload.           │
 * │                                                                          │
 * │ requireRole('admin')  EVERY WRITE TO THE CATALOGUE. Platform role, read   │
 * │                       from `users.role` — NOT a capability.               │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY THE CATALOGUE WRITE IS NOT BEHIND SETTINGS_MANAGE ───────────────────┐
 * │ `lifecycle_models` and `lifecycle_firmware` have NO `tenant_id`           │
 * │ (migration 027, decision 2). They hold published vendor product facts —   │
 * │ "the SonicWall TZ215 is retired" is a statement about SonicWall, not      │
 * │ about a customer — and per-tenant copies would be the same rows a hundred │
 * │ times, drifting apart.                                                    │
 * │                                                                          │
 * │ The consequence is that ONE ROW WRITTEN HERE CHANGES WHAT EVERY TENANT IS │
 * │ TOLD, so the write cannot sit behind a tenant-scoped capability.          │
 * │ SETTINGS_MANAGE IS TENANT-SCOPED: `TENANT_ROLE_CAPABILITIES.admin`        │
 * │ contains it, so `requireCapability` grants it to the admin of ANY tenant  │
 * │ through `user_tenants.role`. F5 shipped precisely that on                 │
 * │ `ip_asn_ranges` and one customer's admin could rewrite every other        │
 * │ customer's carrier attribution.                                           │
 * │                                                                          │
 * │ The same shape here is worse in both directions. Loud: customer B's admin │
 * │ declares customer A's whole fleet end-of-life, and A's screen tells A's   │
 * │ engineers to rip out working hardware. Quiet, and far more likely to      │
 * │ succeed: B inserts one benign `exact` row for a model that a real         │
 * │ `end_of_support` `prefix` row already covers — `matchModelEntry` prefers  │
 * │ the exact match (decision 7 of `shared/src/lifecycle.ts`), so a genuine   │
 * │ end-of-support verdict silently becomes `unknown` across every tenant,    │
 * │ with a plausible source string attached and nothing on any screen to say  │
 * │ why. A catalogue that can be poisoned is a catalogue nobody can quote.    │
 * │                                                                          │
 * │ `requireRole('admin')` is the platform role read from the session —       │
 * │ the same guard `/api/tenants` uses, and the same reasoning that keeps     │
 * │ `tenants.manage` and `credential.manage` out of                           │
 * │ `TENANT_ROLE_CAPABILITIES` via `NEVER_ROLE_DERIVED`. It is checked from   │
 * │ the session alone, so it holds whether this router ends up mounted under  │
 * │ the tenant router or anywhere else. READING the catalogue stays on        │
 * │ DEVICE_READ: it is published vendor data plus an import journal.          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ EVERY GUARD IS UPSTREAM OF EVERY BRANCH ─────────────────────────────────┐
 * │ There is no route below whose handler branches BEFORE its guard, and no   │
 * │ handler that decides internally which of two protection levels applies.   │
 * │ In particular `DELETE /catalog/:kind/:id` takes `:kind` as a path         │
 * │ parameter and switches on it INSIDE the controller — that switch is       │
 * │ downstream of `requireRole('admin')`, which is declared on the route      │
 * │ itself, so both branches are equally guarded. The F5 audit found a guard  │
 * │ applied to one protocol branch out of four; the way that does not recur   │
 * │ is that a branch never sits between the request and its check.            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * D3: not one route here writes to an equipment, and F8 never contacts one at
 * all. There is no driver, no transport pool and no command in this feature —
 * it reads `devices.model`, `devices.os_version` and `devices.family`, which
 * M2 already collected, out of our own Postgres.
 */
const router = Router();

// ── the renewal list ─────────────────────────────────────────────────────────
router.get(
  '/inventory',
  requireCapability(CAPABILITIES.DEVICE_READ),
  lifecycleController.inventory,
);
router.get('/summary', requireCapability(CAPABILITIES.DEVICE_READ), lifecycleController.summary);

// ── the honesty half: what the catalogue does NOT cover ──────────────────────
router.get('/gaps', requireCapability(CAPABILITIES.DEVICE_READ), lifecycleController.gaps);

// ── the catalogue. Declared before `/:kind/:id` could shadow them. ───────────
router.get('/catalog', requireCapability(CAPABILITIES.DEVICE_READ), lifecycleController.catalog);
router.get(
  '/catalog/imports',
  requireCapability(CAPABILITIES.DEVICE_READ),
  lifecycleController.imports,
);

// WRITING THE CATALOGUE IS A PLATFORM ACT, AND `requireRole('admin')` IS THE
// ONLY GUARD THAT SAYS SO. See the block above.
router.post('/catalog/models', requireRole('admin'), lifecycleController.importModels);
router.post('/catalog/firmware', requireRole('admin'), lifecycleController.importFirmware);
router.delete('/catalog/:kind/:id', requireRole('admin'), lifecycleController.deleteEntry);

// ── one device ───────────────────────────────────────────────────────────────
// Last: `/devices/:deviceId` cannot shadow any literal above it, but keeping
// the parameterised routes at the bottom is the habit that stops the next
// addition from doing so.
router.get(
  '/devices/:deviceId',
  requireCapability(CAPABILITIES.DEVICE_READ),
  lifecycleController.device,
);

export default router;
