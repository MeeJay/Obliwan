import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { devicesController } from '../controllers/devices.controller';
import { requireCapability } from '../middleware/rbac';
import { validate } from '../middleware/validate';
import {
  createConcentratorSchema,
  enrollDeviceSchema,
  createDeviceSchema,
  listDevicesQuerySchema,
  updateDeviceSchema,
  upsertTransportSchema,
} from '../validators/device.schema';

/**
 * Devices, transports and presence.
 *
 * RBAC, by gesture rather than by URL shape:
 *   DEVICE_READ        see the inventory, presence and verdicts
 *   DEVICE_WRITE       create / edit / delete a device, declare the CHR,
 *                      test a channel, re-assert an identity
 *   CREDENTIAL_MANAGE  write or delete a transport row, because a transport row
 *                      carries a credential. Rotating a password is an operator
 *                      act; READING one is `SECRET_READ`, which has no route
 *                      here at all — the endpoint does not exist, so it cannot
 *                      be mis-permissioned (section 8.2).
 */
const router = Router();

router.get(
  '/',
  requireCapability(CAPABILITIES.DEVICE_READ),
  validate(listDevicesQuerySchema, 'query'),
  devicesController.list,
);
router.get(
  '/presence/status',
  requireCapability(CAPABILITIES.DEVICE_READ),
  devicesController.presenceStatus,
);

// Declared before `/:id` so the literal path is not swallowed by the parameter.
router.post(
  // M15 — single-device enrolment FROM THE UI. Unlike '/enroll' above, a
  // credential IS transmitted and goes to the vault, so this one demands
  // CREDENTIAL_MANAGE. That capability is the entire difference between the
  // two paths, which is why they are two routes and not one with a flag.
  '/enroll-probe',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  validate(enrollDeviceSchema),
  devicesController.enrollFromUi,
);

router.post(
  // M15 — bench enrolment. DEVICE_WRITE only: it creates a quarantined row and
  // nothing else. It deliberately does NOT ask for CREDENTIAL_MANAGE, because
  // it carries no credential — the factory password never leaves the bench.
  '/enroll',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  devicesController.enroll,
);

router.post(
  '/concentrator',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  validate(createConcentratorSchema),
  devicesController.createConcentrator,
);

router.get('/:id', requireCapability(CAPABILITIES.DEVICE_READ), devicesController.getById);
router.get('/:id/sessions', requireCapability(CAPABILITIES.DEVICE_READ), devicesController.sessions);
router.get(
  '/:id/reachability',
  requireCapability(CAPABILITIES.DEVICE_READ),
  devicesController.reachability,
);
router.get(
  '/:id/transports',
  requireCapability(CAPABILITIES.DEVICE_READ),
  devicesController.listTransports,
);

router.post(
  '/',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  validate(createDeviceSchema),
  devicesController.create,
);
router.patch(
  '/:id',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  validate(updateDeviceSchema),
  devicesController.update,
);
router.delete('/:id', requireCapability(CAPABILITIES.DEVICE_WRITE), devicesController.delete);

router.put(
  '/:id/transports/:transport',
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  validate(upsertTransportSchema),
  devicesController.upsertTransport,
);
router.delete(
  '/:id/transports/:transport',
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  devicesController.deleteTransport,
);
router.post(
  '/:id/transports/:transport/test',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  devicesController.testTransport,
);
/** Device-level variant: every enabled channel at once. Same capability —
 *  opening a channel is an operator act whichever way it is asked for. */
router.post(
  '/:id/test-connection',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  devicesController.testConnection,
);

/** Fresh-connection identity proof (D5 / R4). Available now so the door is
 *  exercised before M6 puts writes behind it. */
router.post(
  '/:id/assert-binding',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  devicesController.assertBinding,
);

/** Force the 60 s sweep now, on a concentrator. */
router.post(
  '/:id/reconcile',
  requireCapability(CAPABILITIES.DEVICE_DISCOVER),
  devicesController.reconcile,
);

export default router;
