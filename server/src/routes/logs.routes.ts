import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { logsController } from '../controllers/logs.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Logs, attribution (K6) and the reachability verdict (K7).
 *
 * MOUNT: under the tenant-scoped router, at `/logs` — `requireAuth` and
 * `requireTenant` have already run by then.
 *
 * ┌─ FOUR CAPABILITIES, AND EACH SPLIT IS DELIBERATE ────────────────────────┐
 * │ SNMP_READ     the journal itself and its ingestion health. The same       │
 * │               capability as the series, because syslog and traps are the  │
 * │               same telemetry domain — pushed by the same devices, stored  │
 * │               in the same partitioned tables, read on the same incident   │
 * │               screen. Deliberately NOT `DEVICE_READ`: seeing that a       │
 * │               device exists is a different question from reading what it  │
 * │               logs (the same reasoning as CONFIG_READ, risk R10).         │
 * │                                                                          │
 * │ DRIFT_READ    login events and attributions. The capability catalogue     │
 * │               already says "drift runs, findings AND THEIR ATTRIBUTION" — │
 * │               K6 is the sentence that was written for.                    │
 * │                                                                          │
 * │ DRIFT_MANAGE  recomputing an attribution. It can change a verdict that    │
 * │               has already been read: an `unattributed` becoming an        │
 * │               `attributed` puts a colleague's name on a change after the  │
 * │               fact. That is a decision, not a refresh.                    │
 * │                                                                          │
 * │ AUDIT_READ    the unattributed feed. It is the ONE route here that cannot │
 * │               be tenant-scoped — a sender we cannot tie to a device       │
 * │               cannot be tied to a tenant either — so it is gated on a     │
 * │               capability NO built-in permission set grants. Effectively   │
 * │               platform admins only, which is the correct blast radius for │
 * │               a cross-customer view.                                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * DEVICE_WRITE guards exactly one route, and not for symmetry: enabling the
 * out-of-tunnel probe makes this server open scheduled TCP connections to a
 * customer's public address. That is an outbound action against somebody
 * else's network.
 */
const router = Router();

// -- The unified journal ------------------------------------------------------
// Literal paths before parameterised ones, so `/logs/health` is never swallowed.
router.get('/health', requireCapability(CAPABILITIES.SNMP_READ), logsController.health);
router.get('/unattributed', requireCapability(CAPABILITIES.AUDIT_READ), logsController.unattributed);
router.get('/logins', requireCapability(CAPABILITIES.DRIFT_READ), logsController.logins);

// -- K6, attribution ----------------------------------------------------------
router.get(
  '/attributions',
  requireCapability(CAPABILITIES.DRIFT_READ),
  logsController.attributions,
);
router.get(
  '/attributions/runs/:runId',
  requireCapability(CAPABILITIES.DRIFT_READ),
  logsController.attributionForRun,
);
router.post(
  '/attributions/runs/:runId',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  logsController.reattribute,
);

// -- K7, the reachability verdict --------------------------------------------
router.get(
  '/reachability/devices/:deviceId',
  requireCapability(CAPABILITIES.DEVICE_READ),
  logsController.verdict,
);
router.post(
  '/reachability/devices/:deviceId/assess',
  requireCapability(CAPABILITIES.DEVICE_READ),
  logsController.assess,
);
router.put(
  '/reachability/devices/:deviceId/external-probe',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  logsController.setExternalProbe,
);

// -- Pull `/log` off one box now ---------------------------------------------
// SNMP_READ and not DRIFT_READ: like a collection, this DIALS THE EQUIPMENT.
// It reads and never writes, which is why it is not CHANGE_APPLY, but it is
// still an action on someone's hardware and not a query against our database.
router.post(
  '/devices/:deviceId/pull',
  requireCapability(CAPABILITIES.SNMP_READ),
  logsController.pull,
);

// The list is LAST: `/logs/` with no sub-path.
router.get('/', requireCapability(CAPABILITIES.SNMP_READ), logsController.list);

export default router;
