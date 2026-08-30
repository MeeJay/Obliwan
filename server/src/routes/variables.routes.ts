import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { variablesController } from '../controllers/variables.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Template variables — `config_variables`.
 *
 * RBAC:
 *   TEMPLATE_READ    resolve variables for a device / group / tenant, and list
 *                    what is set at one level.
 *   TEMPLATE_WRITE   set or remove one.
 *
 * Writing a variable is `TEMPLATE_WRITE` and not a lesser capability, because a
 * variable is an INPUT to a rendered template: whoever can set one can change
 * what the server would push to a router. That is the same class of act as
 * authoring the template, and it gets the same capability.
 *
 * Reading a SECRET variable's value has no route at all — not here, not under
 * a flag, not for a platform admin. A secret comes back as
 * `__OBLIWAN_SECRET_<KEY>__` with a keyed fingerprint at every level of this
 * API; the plaintext exists in memory only, on the vault -> equipment path
 * (§8.2), and M5 has no such path. The endpoint does not exist, so it cannot
 * be mis-permissioned.
 *
 * ┌─ WHY THE PATHS LOOK LIKE THIS ───────────────────────────────────────────┐
 * │ `scope` is one of global | tenant | group | device. `global` and         │
 * │ `tenant` carry NO scope id (their identity is the tenant, exactly as in  │
 * │ `settings`); `group` and `device` require one. Two route arities express │
 * │ that, so a `device` write with a missing scope id cannot even be routed  │
 * │ — it 404s at the router instead of landing in the UNSCOPED partial       │
 * │ unique index and behaving, silently, like a global variable for the      │
 * │ whole fleet.                                                             │
 * │                                                                          │
 * │ The variable KEY travels in the query string on DELETE rather than as a  │
 * │ path segment: `/variables/at/global/vlan` and `/variables/at/group/12`   │
 * │ have the same arity, and telling them apart by whether the last segment  │
 * │ looks numeric is one rename away from deleting the wrong row.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * NOT MOUNTED HERE — `routes/index.ts` is the M4 workstream's file. The lead
 * mounts this router under `tenantRouter` at `/variables`.
 */
const router = Router();

// ── Resolved views — every value with its ORIGIN (the InheritanceBadge) ─────
router.get(
  '/devices/:deviceId',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  variablesController.forDevice,
);
router.get(
  '/groups/:groupId',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  variablesController.forGroup,
);
router.get(
  '/tenant',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  variablesController.forTenant,
);

// ── Bulk write. Declared before `/at/...` so the literal is not shadowed. ───
router.put(
  '/bulk/:scope',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.setBulkAtScope,
);
router.put(
  '/bulk/:scope/:scopeId',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.setBulkAtScope,
);

// ── One level, no inheritance: the editing view ─────────────────────────────
router.get(
  '/at/:scope',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  variablesController.listAtScope,
);
router.get(
  '/at/:scope/:scopeId',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  variablesController.listAtScope,
);
router.put(
  '/at/:scope',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.setAtScope,
);
router.put(
  '/at/:scope/:scopeId',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.setAtScope,
);
router.delete(
  '/at/:scope',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.removeAtScope,
);
router.delete(
  '/at/:scope/:scopeId',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.removeAtScope,
);

export default router;
