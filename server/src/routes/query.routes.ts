import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { queryController } from '../controllers/query.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Fleet Query (K5). Mounted under the tenant-scoped router.
 *
 * ┌─ TWO CAPABILITIES, AND THE SPLIT IS THE POINT ────────────────────────────┐
 * │ QUERY_RUN     write, run, save and export a query. Its catalogue entry    │
 * │               reads "Execute and save Fleet Query DSL queries", and this  │
 * │               is that sentence as a route table.                          │
 * │ DRIFT_MANAGE  PROMOTE a saved query to a policy, demote it, and trigger   │
 * │               an evaluation.                                              │
 * │                                                                          │
 * │ Promotion is not a view preference: a policy is evaluated at every        │
 * │ snapshot, it writes `policy_results`, and its violations sit next to the  │
 * │ drift findings on the fleet screen with a severity of their own. Deciding │
 * │ that "SNMP v1 is critical for this customer" is the same class of act as  │
 * │ silencing a drift finding, and it is behind the same capability for the   │
 * │ same reason.                                                              │
 * │                                                                          │
 * │ Reading violations is DRIFT_READ, not QUERY_RUN: by then they are         │
 * │ findings, and whoever may see the drift screen may see them.              │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING HERE TOUCHES AN EQUIPMENT ───────────────────────────────────────┐
 * │ Every route below reads `devices`, `config_snapshots` and                 │
 * │ `saved_queries`, and the only writes are to `saved_queries` and           │
 * │ `policy_results`. No route compiles a plan, enqueues a change job or      │
 * │ dials a router — M9 is an interrogation of what M4 already collected.     │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

// ── the language itself ──────────────────────────────────────────────────────
// The whitelist, its operators and the worked examples. Behind QUERY_RUN rather
// than open: the field catalogue names every resource kind and every attribute
// ObliWAN models, which is reconnaissance for anyone who should not be here.
router.get('/fields', requireCapability(CAPABILITIES.QUERY_RUN), queryController.fields);
router.get(
  '/fields/:scope',
  requireCapability(CAPABILITIES.QUERY_RUN),
  queryController.fieldsOfScope,
);

// ── ad-hoc execution ─────────────────────────────────────────────────────────
router.post('/run', requireCapability(CAPABILITIES.QUERY_RUN), queryController.run);
router.post('/explain', requireCapability(CAPABILITIES.QUERY_RUN), queryController.explain);
router.post('/export', requireCapability(CAPABILITIES.QUERY_RUN), queryController.exportAdHoc);

// ── policies ─────────────────────────────────────────────────────────────────
// Declared BEFORE `/saved/:id` would be reachable, and on a distinct prefix, so
// no literal path can ever be swallowed by a parameterised one.
router.post(
  '/policies/evaluate',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  queryController.evaluate,
);
router.get(
  '/policies/violations',
  requireCapability(CAPABILITIES.DRIFT_READ),
  queryController.violations,
);

// ── saved queries ────────────────────────────────────────────────────────────
router.get('/saved', requireCapability(CAPABILITIES.QUERY_RUN), queryController.list);
router.post('/saved', requireCapability(CAPABILITIES.QUERY_RUN), queryController.create);
router.get('/saved/:id', requireCapability(CAPABILITIES.QUERY_RUN), queryController.get);
router.patch('/saved/:id', requireCapability(CAPABILITIES.QUERY_RUN), queryController.update);
router.delete('/saved/:id', requireCapability(CAPABILITIES.QUERY_RUN), queryController.remove);
router.post('/saved/:id/run', requireCapability(CAPABILITIES.QUERY_RUN), queryController.runSaved);
router.get(
  '/saved/:id/export',
  requireCapability(CAPABILITIES.QUERY_RUN),
  queryController.exportSaved,
);

router.post(
  '/saved/:id/promote',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  queryController.promote,
);
router.post(
  '/saved/:id/demote',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  queryController.demote,
);

export default router;
