import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { snmpController } from '../controllers/snmp.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * SNMP / telemetry. Mounted under the tenant-scoped router, so `requireAuth`
 * and `requireTenant` have already run.
 *
 * ┌─ THREE CAPABILITIES, AND THE SPLIT IS THE POINT ──────────────────────────┐
 * │ SNMP_READ          see interfaces, series, thresholds and alert state.    │
 * │ SNMP_ADMIN         change what is polled and what alerts (targets,        │
 * │                    thresholds).                                          │
 * │ CREDENTIAL_MANAGE  touch `snmp_credentials` AT ALL -- including the       │
 * │                    listing.                                               │
 * │                                                                          │
 * │ Why the credential LIST is behind CREDENTIAL_MANAGE and not SNMP_READ,    │
 * │ even though it returns no secret: the list is a map of which sites share  │
 * │ which credential and which are still on v2c. That is reconnaissance, and  │
 * │ an operator who may look at bandwidth graphs has no reason to hold it.    │
 * │                                                                          │
 * │ And why the graph routes are SNMP_READ and not DEVICE_READ: seeing that a │
 * │ device exists in the inventory is a different question from seeing what   │
 * │ it carries. The same reasoning as CONFIG_READ against DEVICE_READ in      │
 * │ `devices.routes.ts` (risk R10).                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

// -- Credentials: CREDENTIAL_MANAGE throughout, listing included -------------
router.get(
  '/credentials',
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  snmpController.listCredentials,
);
router.get(
  '/credentials/:id',
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  snmpController.getCredential,
);
router.post(
  '/credentials',
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  snmpController.createCredential,
);
router.put(
  '/credentials/:id',
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  snmpController.updateCredential,
);
router.delete(
  '/credentials/:id',
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  snmpController.deleteCredential,
);

// -- Targets: reading is SNMP_READ, changing what we poll is SNMP_ADMIN ------
router.get(
  '/devices/:deviceId/target',
  requireCapability(CAPABILITIES.SNMP_READ),
  snmpController.getTarget,
);
router.put(
  '/devices/:deviceId/target',
  requireCapability(CAPABILITIES.SNMP_ADMIN),
  snmpController.putTarget,
);
router.delete(
  '/devices/:deviceId/target',
  requireCapability(CAPABILITIES.SNMP_ADMIN),
  snmpController.deleteTarget,
);

// -- Interfaces and series --------------------------------------------------
router.get(
  '/devices/:deviceId/interfaces',
  requireCapability(CAPABILITIES.SNMP_READ),
  snmpController.listInterfaces,
);
router.get(
  '/devices/:deviceId/series',
  requireCapability(CAPABILITIES.SNMP_READ),
  snmpController.deviceSeries,
);
/** Fleet-wide interface list: every interface of the tenant with its last
 *  measurement, device and site. Declared BEFORE `/interfaces/:ifId/...` so the
 *  literal path is not swallowed by the parameterised one. */
router.get(
  '/interfaces',
  requireCapability(CAPABILITIES.SNMP_READ),
  snmpController.listFleetInterfaces,
);

/** The graph. `granularity` is optional and is CLAMPED to what retention can
 *  actually serve -- see `series.service.chooseGranularity`. */
router.get(
  '/interfaces/:ifId/series',
  requireCapability(CAPABILITIES.SNMP_READ),
  snmpController.interfaceSeries,
);
/** 95th percentile of 5-minute averages: the carrier billing convention. */
router.get(
  '/interfaces/:ifId/billing-p95',
  requireCapability(CAPABILITIES.SNMP_READ),
  snmpController.billingP95,
);

// -- Thresholds -------------------------------------------------------------
router.get('/thresholds', requireCapability(CAPABILITIES.SNMP_READ), snmpController.listThresholds);
router.get(
  '/thresholds/:id',
  requireCapability(CAPABILITIES.SNMP_READ),
  snmpController.getThreshold,
);
router.post(
  '/thresholds',
  requireCapability(CAPABILITIES.SNMP_ADMIN),
  snmpController.createThreshold,
);
router.put(
  '/thresholds/:id',
  requireCapability(CAPABILITIES.SNMP_ADMIN),
  snmpController.updateThreshold,
);
router.delete(
  '/thresholds/:id',
  requireCapability(CAPABILITIES.SNMP_ADMIN),
  snmpController.deleteThreshold,
);

/** Current alert state (ok / pending / firing) across the tenant. */
router.get('/alerts', requireCapability(CAPABILITIES.SNMP_READ), snmpController.listAlerts);

/** Collection health. A missing series and a broken collector look identical
 *  on a chart; this is what tells them apart. */
router.get('/status', requireCapability(CAPABILITIES.SNMP_READ), snmpController.status);

export default router;
