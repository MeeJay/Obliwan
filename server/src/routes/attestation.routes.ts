import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { attestationController } from '../controllers/attestation.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Compliance attestations and the append-only ledger (F2 / C11). Mounted under
 * the tenant-scoped router.
 *
 * ┌─ ONE CAPABILITY, AND WHY IT IS AUDIT_READ ────────────────────────────────┐
 * │ The catalogue entry for AUDIT_READ is "read the append-only audit log and │
 * │ the command audit". An attestation is an ASSEMBLY of exactly that         │
 * │ material plus snapshot hashes, so it belongs to whoever may read the      │
 * │ audit.                                                                    │
 * │                                                                           │
 * │ It is deliberately NOT behind CONFIG_READ. Risk R10 makes CONFIG_READ     │
 * │ distinct from DEVICE_READ because a snapshot may carry residual sensitive │
 * │ material; an attestation carries the HASH of a configuration and never    │
 * │ its content, so it discloses nothing CONFIG_READ exists to protect.       │
 * │                                                                           │
 * │ ISSUING NEEDS A SECOND ONE: EXPORT_RUN.                                   │
 * │                                                                           │
 * │ `POST /issue` is the only route here that WRITES — a frozen `attestations`│
 * │ row and one `audit_log` entry, both of which are permanent and neither of │
 * │ which can be deleted inside the immutable window. Putting a durable write │
 * │ behind a capability whose name is `audit.read` would be exactly the kind  │
 * │ of quiet mismatch a permission audit is supposed to find, and "the write  │
 * │ is harmless" is not the standard: an account able to read the audit could │
 * │ otherwise mint unbounded, undeletable rows.                               │
 * │                                                                           │
 * │ EXPORT_RUN is the right second half rather than a new capability nobody   │
 * │ has been granted: its catalogue entry is "export a tenant to a portable   │
 * │ bundle", and an attestation is precisely a portable, durable artefact     │
 * │ about a tenant, meant to leave the building.                              │
 * │                                                                           │
 * │ `/preview` deliberately does NOT need it. Looking at what would be        │
 * │ attested has to be cheaper than issuing it, or nobody looks first.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING HERE TOUCHES AN EQUIPMENT ───────────────────────────────────────┐
 * │ Every route reads `config_snapshots`, `drift_runs`, `change_jobs`,        │
 * │ `apply_outcomes`, `command_audit`, `drift_exceptions` and `audit_log`.    │
 * │ The only writes are one `attestations` row and one `audit_log` row.       │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

/** The verification procedure, standalone. Behind the capability like the rest:
 *  it names every table and column the evidence is drawn from, which is a map
 *  of the schema for anyone who should not be here. */
router.get('/method', requireCapability(CAPABILITIES.AUDIT_READ), attestationController.method);

/** The tenant's chain. Declared before `/:uuid` so the literal path wins. */
router.get('/ledger', requireCapability(CAPABILITIES.AUDIT_READ), attestationController.ledger);

router.post(
  '/preview',
  requireCapability(CAPABILITIES.AUDIT_READ),
  attestationController.preview,
);
/** BOTH capabilities. `requireCapability` calls `next()` on success, so the two
 *  guards compose and the caller must hold each of them. */
router.post(
  '/issue',
  requireCapability(CAPABILITIES.AUDIT_READ),
  requireCapability(CAPABILITIES.EXPORT_RUN),
  attestationController.issue,
);

router.get('/', requireCapability(CAPABILITIES.AUDIT_READ), attestationController.list);
router.get('/:uuid', requireCapability(CAPABILITIES.AUDIT_READ), attestationController.get);
router.post(
  '/:uuid/verify',
  requireCapability(CAPABILITIES.AUDIT_READ),
  attestationController.verify,
);
router.post(
  '/:uuid/compare',
  requireCapability(CAPABILITIES.AUDIT_READ),
  attestationController.compare,
);

export default router;
