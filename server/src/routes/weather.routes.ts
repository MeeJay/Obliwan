import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { weatherController } from '../controllers/weather.controller';
import { requireCapability, requireRole } from '../middleware/rbac';

/**
 * Operator Weather (F5). Mounted under the tenant-scoped router.
 *
 * ┌─ MOUNTED. THIS SURFACE IS LIVE OVER HTTP ─────────────────────────────────┐
 * │ `routes/index.ts` line 194, under the M9 block:                           │
 * │                                                                          │
 * │   tenantRouter.use('/weather', weatherRoutes);                            │
 * │                                                                          │
 * │ This block used to claim the opposite. A header that says "unreachable    │
 * │ over HTTP" about a mounted router tells a reviewer to test the service    │
 * │ layer and skip the request — which is how three unmounted routers went    │
 * │ unnoticed on this project, and it works just as well in reverse. If the   │
 * │ mounting ever changes, THIS BLOCK CHANGES IN THE SAME COMMIT.             │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THREE CAPABILITIES, AND THE SPLIT IS THE POINT ──────────────────────────┐
 * │ DEVICE_READ      the weather map, the incidents, the path history and the │
 * │                  per-device egress state. This is fleet observation —     │
 * │                  which site is on LTE, which carrier is having a bad      │
 * │                  afternoon. It carries no configuration and no secret, so │
 * │                  R10's separation of CONFIG_READ from DEVICE_READ is not  │
 * │                  engaged: there is nothing here a snapshot would leak.    │
 * │                                                                          │
 * │ DEVICE_WRITE     `POST /devices/:id/probe` and `POST /scan`. The probe    │
 * │                  makes this server DIAL a customer's router with a vault  │
 * │                  credential to read its active default route; the scan    │
 * │                  OPENS AND CLOSES incidents. Neither is a read of our own │
 * │                  database and neither belongs behind a read capability.   │
 * │                  Both are still strictly read-only ON THE EQUIPMENT —     │
 * │                  `/ip/route/print`, `/interface/lte/print`,               │
 * │                  `/ip/address/print` — so D3 holds: nothing outside       │
 * │                  `change_jobs` writes to a device.                        │
 * │                                                                          │
 * │ SETTINGS_MANAGE  the quorum policy, and NOTHING ELSE. The policy is what  │
 * │                  decides whether an MSP telephones a carrier, and getting │
 * │                  it wrong twice ends the feature — it is not an operator  │
 * │                  preference. It IS, however, a tenant-local decision:     │
 * │                  a customer's quorum belongs to that customer's admin.    │
 * │                                                                          │
 * │ requireRole('admin')  WRITING THE ASN TABLE. Platform role, not           │
 * │                  capability.                                              │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY THE ASN IMPORT IS NOT BEHIND SETTINGS_MANAGE ────────────────────────┐
 * │ This header used to claim the ASN table "cannot sit behind a tenant-      │
 * │ scoped fleet capability" and then put it behind one. SETTINGS_MANAGE IS   │
 * │ TENANT-SCOPED: `TENANT_ROLE_CAPABILITIES.admin` contains it, so           │
 * │ `requireCapability` grants it to the admin of ANY tenant through          │
 * │ `user_tenants.role`.                                                      │
 * │                                                                          │
 * │ `ip_asn_ranges` has no `tenant_id` (migration 021, decision 3). One       │
 * │ customer's admin POSTing a dataset therefore rewrote every other          │
 * │ customer's attribution: `ON CONFLICT (prefix) DO UPDATE` plus             │
 * │ `clearAsnCache()` makes it immediate and global, and longest-prefix match │
 * │ means a /32 beats a reference /16 without overwriting anything at all.    │
 * │ Reproduced with two tenants: twelve /32 rows imported by the admin of     │
 * │ customer B turned customer A's live twelve-site outage into twelve        │
 * │ single-site ASNs and `below_absolute_quorum:1/5` — no incident, and       │
 * │ nothing on A's screen to say why. The symmetric abuse is worse: merging   │
 * │ unrelated prefixes under one ASN MANUFACTURES a quorum.                   │
 * │                                                                          │
 * │ `requireRole('admin')` is the platform role read from `users.role` — the  │
 * │ same guard every `/api/tenants` route uses, and the same reasoning that   │
 * │ keeps `tenants.manage` and `credential.manage` out of                     │
 * │ `TENANT_ROLE_CAPABILITIES` via `NEVER_ROLE_DERIVED`. It is checked from   │
 * │ the session alone, so it holds whether this router is mounted under the   │
 * │ tenant router or anywhere else. READING the table stays on DEVICE_READ:   │
 * │ it is public routing data and an import journal.                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

// ── the map ──────────────────────────────────────────────────────────────────
router.get('/', requireCapability(CAPABILITIES.DEVICE_READ), weatherController.report);

// ── incidents ────────────────────────────────────────────────────────────────
// Declared before any parameterised sibling could shadow them.
router.get('/incidents', requireCapability(CAPABILITIES.DEVICE_READ), weatherController.incidents);
router.get(
  '/incidents/:id',
  requireCapability(CAPABILITIES.DEVICE_READ),
  weatherController.incident,
);

// ── the evidence ─────────────────────────────────────────────────────────────
router.get('/events', requireCapability(CAPABILITIES.DEVICE_READ), weatherController.events);
router.get('/paths', requireCapability(CAPABILITIES.DEVICE_READ), weatherController.paths);
router.get(
  '/devices/:deviceId/path',
  requireCapability(CAPABILITIES.DEVICE_READ),
  weatherController.devicePath,
);

// ── acts on the fleet ────────────────────────────────────────────────────────
router.post(
  '/devices/:deviceId/probe',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  weatherController.probe,
);
router.post('/scan', requireCapability(CAPABILITIES.DEVICE_WRITE), weatherController.scan);

// ── the quorum ───────────────────────────────────────────────────────────────
router.get('/policy', requireCapability(CAPABILITIES.DEVICE_READ), weatherController.policy);
router.put(
  '/policy',
  requireCapability(CAPABILITIES.SETTINGS_MANAGE),
  weatherController.setPolicy,
);

// ── the offline enrichment table ─────────────────────────────────────────────
router.get(
  '/asn-table',
  requireCapability(CAPABILITIES.DEVICE_READ),
  weatherController.asnTable,
);
// WRITING IT IS A PLATFORM ACT, AND `requireRole('admin')` IS THE ONLY GUARD
// THAT SAYS SO. See the block above.
router.post(
  '/asn-table',
  requireRole('admin'),
  weatherController.importAsnTable,
);
// "Why is this site unattributed" — the debugging answer that is otherwise a
// shrug. Read-only, offline, and it touches no device.
router.get('/classify', requireCapability(CAPABILITIES.DEVICE_READ), weatherController.classify);

export default router;
