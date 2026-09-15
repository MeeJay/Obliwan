import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { simController } from '../controllers/sim.controller';
import { requireCapability, requireRole } from '../middleware/rbac';

/**
 * Mobile data lines (F9). Mounted under the tenant-scoped router as `/sim`
 * (`server/src/routes/index.ts`).
 *
 * ┌─ THREE GUARDS, AND THE SPLIT IS THE ENTIRE SECURITY DESIGN ───────────────┐
 * │                                                                          │
 * │ requireRole('admin')  EVERY `/accounts` ROUTE, read included. Platform    │
 * │                       role, read from `users.role` — NOT a capability.    │
 * │                       `sim_accounts` has no `tenant_id` (migration 032,   │
 * │                       decision 2) and holds a partner CREDENTIAL, so one  │
 * │                       write changes what every tenant is shown.           │
 * │                       SETTINGS_MANAGE is tenant-scoped —                  │
 * │                       `TENANT_ROLE_CAPABILITIES.admin` grants it to the   │
 * │                       admin of ANY tenant — which is precisely the defect │
 * │                       F5 shipped on `ip_asn_ranges`. The READ is guarded  │
 * │                       too, and that is not excess: the row carries the    │
 * │                       partner host, the partner id and whether a          │
 * │                       credential exists, which is reconnaissance for the  │
 * │                       account somebody would want to repoint.             │
 * │                                                                          │
 * │ SIM_READ              Every tenant-scoped read: the fleet, one line, its  │
 * │                       history, the top-up list, the re-invoicing report.  │
 * │                       Not DEVICE_READ: a SIM is commercial inventory      │
 * │                       carrying an MSISDN and a cost, and a role that may  │
 * │                       see routers need not see what the lines cost.       │
 * │                                                                          │
 * │ SIM_MANAGE            Assignment and per-line policy — which customer a   │
 * │                       line belongs to, its threshold, whether it may      │
 * │                       produce a top-up proposal at all. Changes WHAT gets │
 * │                       proposed. Buys nothing.                             │
 * │                                                                          │
 * │ SIM_RECHARGE          Approve, reject, record, execute. THE ONLY ROUTES   │
 * │                       IN THIS PRODUCT THAT COMMIT A PURCHASE. Deliberately│
 * │                       not implied by SIM_MANAGE (`CAPABILITY_IMPLIES`):   │
 * │                       deciding a line should be watched is an inventory   │
 * │                       act, deciding money leaves the company is not —     │
 * │                       the same split as CHANGE_APPLY against              │
 * │                       CHANGE_APPROVE.                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Proposing a top-up manually sits under SIM_MANAGE, not SIM_RECHARGE: a
 * proposal costs nothing and its only effect is to put a decision in front of
 * somebody who does hold SIM_RECHARGE. Requiring the spending capability to ask
 * for a spend would mean the only people who can raise the question are the
 * people who can already answer it, which defeats the four-eyes split.
 */
const router = Router();

// ── Platform coverage matrix ────────────────────────────────────────────────
// Read as DATA by the UI so a screen cannot imply ObliWAN is watching a partner
// it cannot read. SIM_READ rather than admin: it is a capability statement about
// the product, and it contains no account, host or customer datum.
router.get('/platforms', requireCapability(CAPABILITIES.SIM_READ), simController.listPlatforms);

// ── Partner accounts — PLATFORM ONLY ────────────────────────────────────────
router.get('/accounts', requireRole('admin'), simController.listAccounts);
router.post('/accounts', requireRole('admin'), simController.createAccount);
router.patch('/accounts/:id', requireRole('admin'), simController.updateAccount);
router.delete('/accounts/:id', requireRole('admin'), simController.deleteAccount);
router.put('/accounts/:id/credential', requireRole('admin'), simController.setCredential);
// The interactive one-time-code flow. A sweep has no human and cannot answer a
// code challenge; this is how an operator leaves a long-lived token behind.
router.post('/accounts/:id/otp', requireRole('admin'), simController.authenticateWithCode);
router.post('/accounts/:id/test', requireRole('admin'), simController.testAccount);
// Spends a partner's rate limit on an API that publishes none.
router.post('/accounts/:id/sync', requireRole('admin'), simController.syncAccount);
router.get('/accounts/:id/runs', requireRole('admin'), simController.listRuns);
router.get('/accounts/:id/caps', requireRole('admin'), simController.accountCaps);

// ── The fleet — TENANT SCOPED ───────────────────────────────────────────────
router.get('/summary', requireCapability(CAPABILITIES.SIM_READ), simController.summary);
router.get('/lines', requireCapability(CAPABILITIES.SIM_READ), simController.listLines);
router.get('/lines/:id', requireCapability(CAPABILITIES.SIM_READ), simController.getLine);
router.get(
  '/lines/:id/history',
  requireCapability(CAPABILITIES.SIM_READ),
  simController.getLineHistory,
);
router.patch('/lines/:id', requireCapability(CAPABILITIES.SIM_MANAGE), simController.updateLine);

// ── Top-ups ─────────────────────────────────────────────────────────────────
router.get('/recharges', requireCapability(CAPABILITIES.SIM_READ), simController.listRecharges);
router.get(
  '/recharges/:id',
  requireCapability(CAPABILITIES.SIM_READ),
  simController.getRechargeById,
);
router.post(
  '/recharges',
  requireCapability(CAPABILITIES.SIM_MANAGE),
  simController.proposeRecharge,
);
router.post(
  '/recharges/:id/approve',
  requireCapability(CAPABILITIES.SIM_RECHARGE),
  simController.approveRecharge,
);
router.post(
  '/recharges/:id/reject',
  requireCapability(CAPABILITIES.SIM_RECHARGE),
  simController.rejectRecharge,
);
router.post(
  '/recharges/:id/record',
  requireCapability(CAPABILITIES.SIM_RECHARGE),
  simController.recordRecharge,
);
// Filling in the invoice after the fact. SIM_RECHARGE like the other money
// routes: it changes what a customer is billed, even though it moves no state.
router.post(
  '/recharges/:id/price',
  requireCapability(CAPABILITIES.SIM_RECHARGE),
  simController.priceRecharge,
);
// Answers 501 for every platform today: `SIM_RECHARGE_ADAPTERS` is empty on
// purpose. The route exists so the refusal is a documented answer with a reason
// rather than a 404 a future client discovers by accident.
router.post(
  '/recharges/:id/execute',
  requireCapability(CAPABILITIES.SIM_RECHARGE),
  simController.executeRecharge,
);

// ── Re-invoicing report ─────────────────────────────────────────────────────
router.get('/report', requireCapability(CAPABILITIES.SIM_READ), simController.report);
router.get('/report.csv', requireCapability(CAPABILITIES.SIM_READ), simController.reportCsv);

export default router;
