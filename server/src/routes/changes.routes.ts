import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { changesController } from '../controllers/changes.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Change jobs — the ONLY route surface from which a write can reach an
 * equipment (decision D3). Mounted under the tenant-scoped router.
 *
 * ┌─ THE CAPABILITY MAP, AND EVERY LINE OF IT IS A DECISION ──────────────────┐
 * │ PLAN_CREATE      read the queue, a job, its steps, the kill-switch state. │
 * │                  The same grant that lets you ask "what would ObliWAN     │
 * │                  change on this box" lets you watch what it did.          │
 * │ CHANGE_APPLY     enqueue, abort, ENGAGE the kill switch.                  │
 * │ CHANGE_APPROVE   override the Management-Path Guard. NOT the same as       │
 * │                  CHANGE_APPLY, and deliberately harder to hold: it is the │
 * │                  capability that lets somebody push a plan the guard has  │
 * │                  PROVED cuts the tunnel. `POST /jobs` checks it a second  │
 * │                  time, in the handler, when the body carries an override. │
 * │ SETTINGS_MANAGE  RELEASE the kill switch. The capability list already     │
 * │                  names the kill switch under settings, and the asymmetry  │
 * │                  is the point: engaging is a panic gesture and must be    │
 * │                  fast; releasing puts a fleet back in the line of fire.   │
 * │ AUDIT_READ       `command_audit`. Reading every command sent to every     │
 * │                  customer box is its own grant and always was.            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * WHAT IS DELIBERATELY ABSENT: there is no route that writes to a device
 * directly, no "run this command" endpoint, and no way to skip the queue. D3
 * says nothing writes outside `change_jobs`, and an endpoint that does not
 * exist cannot be mis-permissioned.
 *
 * There is also no `resume` and no `retry` on a job past `applying`. A worker
 * that died after the write is a job for a human and for the on-box dead-man,
 * not for a button — and the reaper refuses that transition anyway.
 */
const router = Router();

// ── Reads ────────────────────────────────────────────────────────────────────
router.get('/config', requireCapability(CAPABILITIES.PLAN_CREATE), changesController.config);
router.get(
  '/kill-switch',
  requireCapability(CAPABILITIES.PLAN_CREATE),
  changesController.killSwitch,
);
router.get('/audit', requireCapability(CAPABILITIES.AUDIT_READ), changesController.audit);

// Literal paths before the parameterised one, so `/jobs/audit` can never be
// swallowed as a job id.
router.get('/jobs', requireCapability(CAPABILITIES.PLAN_CREATE), changesController.list);
router.get('/jobs/:id', requireCapability(CAPABILITIES.PLAN_CREATE), changesController.get);
router.get(
  '/jobs/:id/steps',
  requireCapability(CAPABILITIES.PLAN_CREATE),
  changesController.steps,
);

// ── The impact screen (§8.3), which writes nothing ───────────────────────────
// PLAN_CREATE and not CHANGE_APPLY: seeing what a change WOULD do, and which of
// the three safety nets this device gets, is exactly the information somebody
// needs in order to decide NOT to ask for it.
router.post('/preview', requireCapability(CAPABILITIES.PLAN_CREATE), changesController.preview);
// Same verdict, many devices — what the blast-radius screen needs before a
// rollout. Same capability: a batch of reads is still a read.
router.post(
  '/preflight',
  requireCapability(CAPABILITIES.PLAN_CREATE),
  changesController.preflight,
);

// ── Writes ───────────────────────────────────────────────────────────────────
router.post('/jobs', requireCapability(CAPABILITIES.CHANGE_APPLY), changesController.enqueue);
router.post(
  '/jobs/:id/abort',
  requireCapability(CAPABILITIES.CHANGE_APPLY),
  changesController.abort,
);
router.post(
  '/jobs/:id/override',
  requireCapability(CAPABILITIES.CHANGE_APPROVE),
  changesController.override,
);

// ── The kill switch ──────────────────────────────────────────────────────────
router.post(
  '/kill-switch/engage',
  requireCapability(CAPABILITIES.CHANGE_APPLY),
  changesController.engage,
);
router.post(
  '/kill-switch/release',
  requireCapability(CAPABILITIES.SETTINGS_MANAGE),
  changesController.release,
);

export default router;
