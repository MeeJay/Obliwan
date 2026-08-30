import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { acsController } from '../controllers/acs.controller';
import { requireAuth } from '../middleware/auth';
import { requireTenant } from '../middleware/tenant';
import { requireCapability } from '../middleware/rbac';

/**
 * The ACS admin API (M10). Mounted at `/api/acs`.
 *
 * ┌─ WHY THIS ROUTER CARRIES ITS OWN `requireAuth` + `requireTenant` ─────────┐
 * │ `routes/index.ts` is off limits to this milestone, so the mount lives in  │
 * │ `app.ts` — next to the Obligate SSO callback, which is mounted the same   │
 * │ way and for the same practical reason. A router mounted outside           │
 * │ `tenantRouter` gets neither middleware for free, so it declares both      │
 * │ here. Moving the mount into `routes/index.ts` later means DELETING these  │
 * │ two lines; leaving them in by accident is harmless (both are idempotent). │
 * │                                                                          │
 * │ Without them every handler would read `req.tenantId` as `undefined`, and  │
 * │ `assertDeviceInTenant()` would compare `tenant_id = undefined` — which    │
 * │ knex renders as a query that matches nothing. That fails CLOSED, but it   │
 * │ fails as "device not found" on every request, which is the worst kind of  │
 * │ correct.                                                                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ ONE CAPABILITY, AND WHY IT IS NOT SPLIT ─────────────────────────────────┐
 * │ Everything here is `ACS_ADMIN` — including the reads. That is a           │
 * │ deliberate departure from the two-capability shape of `/drift` and        │
 * │ `/query`, and the reason is what the ACS reads ARE: a CPE's parameter     │
 * │ tree is the customer's complete LAN topology, Wi-Fi configuration, DHCP   │
 * │ ranges and connected-host counts. There is no "safe" half of it to give   │
 * │ to a wider audience, and the catalogue entry for `ACS_ADMIN` is already   │
 * │ marked `sensitive: true`.                                                 │
 * │                                                                          │
 * │ The one thing an operator may want without ACS rights — "does the ACS     │
 * │ cover MikroTik?" — is answered by the shared constant                     │
 * │ `ACS_BRAND_COVERAGE`, which the client can render without calling         │
 * │ anything.                                                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING HERE WRITES TO AN EQUIPMENT ON ITS OWN (D3) ─────────────────────┐
 * │ The four mutating routes below all pass through `enqueueTask`, which      │
 * │ refuses without a `change_jobs` row. They are POSTs that create a QUEUED  │
 * │ INTENT, and they answer 202 with the sentence saying when it will run.    │
 * │ The single exception is `/refresh`, whose whitelist and justification are │
 * │ in `task.service.ts` next to the whitelist itself.                        │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

router.use(requireAuth);
router.use(requireTenant);

const acsAdmin = requireCapability(CAPABILITIES.ACS_ADMIN);

// ── The honest answer to "which brands does the ACS cover" (risk R2) ────────
// Declared before any parameterised path so no literal is ever swallowed.
router.get('/coverage', acsAdmin, acsController.coverage);
router.get('/status', acsAdmin, acsController.status);

// ── Settings ────────────────────────────────────────────────────────────────
router.get('/settings', acsAdmin, acsController.getSettings);
router.patch('/settings', acsAdmin, acsController.updateSettings);

// ── The parameter map (shipped library + learned proposals) ────────────────
router.get('/param-map', acsAdmin, acsController.listMappings);
router.post('/param-map', acsAdmin, acsController.upsertMapping);
router.delete('/param-map/:id', acsAdmin, acsController.deleteMapping);

// ── Files available for Download ────────────────────────────────────────────
router.get('/files', acsAdmin, acsController.listFiles);

// ── Devices ─────────────────────────────────────────────────────────────────
router.get('/devices', acsAdmin, acsController.listDevices);
router.get('/devices/:deviceId', acsAdmin, acsController.getDevice);
router.post('/devices/:deviceId/enrol', acsAdmin, acsController.enrol);

router.get('/devices/:deviceId/parameters', acsAdmin, acsController.listParameters);
// For these two families the parameter tree IS the configuration (D1): a Vigor
// `.cfg` is an opaque vendor blob and a Zyxel CPE exports nothing at all.
router.get('/devices/:deviceId/config', acsAdmin, acsController.configDocument);
router.get('/devices/:deviceId/tasks', acsAdmin, acsController.listTasks);
router.delete('/devices/:deviceId/tasks/:taskId', acsAdmin, acsController.cancelTask);
router.get('/devices/:deviceId/transfers', acsAdmin, acsController.listTransfers);

// Reads: no change job (a CWMP read is the equivalent of `/config/collect`).
router.post('/devices/:deviceId/read', acsAdmin, acsController.queueRead);
router.post('/devices/:deviceId/discover', acsAdmin, acsController.queueDiscovery);

// Writes: refused without a change job (D3). The 409 names the door.
router.post('/devices/:deviceId/write', acsAdmin, acsController.queueWrite);
router.post('/devices/:deviceId/download', acsAdmin, acsController.queueDownload);
router.post('/devices/:deviceId/reboot', acsAdmin, acsController.queueReboot);

// NOT a Connection Request. Answers `CwmpRefreshOutcome { supported: false }`.
router.post('/devices/:deviceId/refresh', acsAdmin, acsController.refresh);

// ── The envelope log (risk R7: off by default, on twice to turn on) ─────────
router.get('/devices/:deviceId/rpc-log', acsAdmin, acsController.rpcLog);
router.put('/devices/:deviceId/rpc-log', acsAdmin, acsController.setRpcLog);

export default router;
