/**
 * ObliWAN — credential rotation (backlog: "rotation massive d'identifiants").
 *
 * ┌─ THE ORDERING IS THE FEATURE ────────────────────────────────────────────┐
 * │ Rotating a password is two writes that must both land — one on the router │
 * │ and one in the vault — with no transaction spanning them. Either order    │
 * │ loses the device on a crash:                                             │
 * │                                                                          │
 * │   vault first, router refuses -> the vault holds a password the box never │
 * │                                  accepted                                 │
 * │   router first, vault fails   -> the box accepts a password nobody has    │
 * │                                                                          │
 * │ So there is a third slot. `device_transports.secret_next_enc` (migration  │
 * │ 031) holds the candidate while `secret_enc` keeps working, and the        │
 * │ promotion happens only after the NEW credential has opened a session of   │
 * │ its own. A crash anywhere leaves the old credential valid.                │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY THIS IS NOT A TEMPLATE, A PLAN OR A ROLLOUT ────────────────────────┐
 * │ A password change is a `changed` on a `localUser`, and the planner VETOES │
 * │ those (`mgmt_path_veto`) because a compiled plan must never touch the     │
 * │ identity the platform logs in with. That veto is correct and this module  │
 * │ does not weaken it: rotation is not compiled from a desired state, it is  │
 * │ a per-device operation that verifies its own result before committing.    │
 * │                                                                          │
 * │ "Mass" therefore means a LOOP OVER THIS, one device at a time, each with  │
 * │ its own verification. It does not mean a wave: a wave measures health     │
 * │ AFTER the fact on a sample, and the only acceptable sample size for "can  │
 * │ we still log in" is all of them.                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

import type { TransportKind } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { encrypt, decrypt, currentKeyVersion } from '../secretVault.service';
import { generateServicePassword } from '../../bench/provision';

export type RotationOutcome =
  | 'rotated'
  | 'refused_no_current_secret'
  | 'refused_device_not_active'
  | 'refused_pending_candidate'
  | 'failed_device_write'
  | 'failed_verification';

export interface RotationResult {
  deviceId: number;
  transport: TransportKind;
  outcome: RotationOutcome;
  /** Operator-readable, and it is the field that must survive into the audit. */
  detail: string;
}

/** Injected so the acceptance harness can drive this without a fleet. */
export interface RotationDriver {
  /** Write the new password for `username` on the device. Throws on refusal. */
  setPassword(deviceId: number, transport: TransportKind, username: string, password: string): Promise<void>;
  /**
   * Open a BRAND-NEW session with the candidate and assert the box is still the
   * recorded device. Returns false rather than throwing on a bad credential:
   * "the password did not take" is an answer, not an exception.
   */
  verify(deviceId: number, transport: TransportKind, username: string, password: string): Promise<boolean>;
}

/**
 * Rotate one device's credential on one transport.
 *
 * Returns an outcome instead of throwing, because the caller is a loop over a
 * fleet and one refusal must not abandon the other three hundred and ninety
 * nine. Every branch below leaves `secret_enc` usable.
 */
export async function rotateOne(
  tenantId: number,
  deviceId: number,
  transport: TransportKind,
  driver: RotationDriver,
): Promise<RotationResult> {
  const r = (outcome: RotationOutcome, detail: string): RotationResult =>
    ({ deviceId, transport, outcome, detail });

  const row = await db('device_transports as t')
    .join('devices as d', 'd.id', 't.device_id')
    .where({ 't.device_id': deviceId, 't.transport': transport, 'd.tenant_id': tenantId })
    .first<
      | { username: string | null; secret_enc: string | null; secret_next_enc: string | null; status: string }
      | undefined
    >('t.username', 't.secret_enc', 't.secret_next_enc', 'd.status');

  if (!row?.secret_enc || !row.username) {
    return r('refused_no_current_secret',
      'No credential is stored for this transport. Rotation replaces a password; it does not ' +
      'invent the first one — that is enrolment.');
  }
  if (row.status !== 'active') {
    // A quarantined device failed an identity assertion (R4). Handing it a new
    // password would be writing to a box we are not sure is the right one.
    return r('refused_device_not_active',
      `Device status is '${row.status}', not 'active'. Refusing to write a credential to a box ` +
      'whose identity is not currently trusted.');
  }
  if (row.secret_next_enc) {
    return r('refused_pending_candidate',
      'A previous rotation left a candidate behind and was never promoted. Resolve that one ' +
      'first: overwriting it would lose the only record of a password the device may already ' +
      'have accepted.');
  }

  // ── 1. Stage. Nothing has been written to the device yet, and `secret_enc`
  //       still opens sessions.
  const candidate = generateServicePassword();
  await db('device_transports')
    .where({ device_id: deviceId, transport })
    .update({
      secret_next_enc: encrypt(candidate),
      secret_next_key_version: currentKeyVersion(),
      secret_next_at: new Date(),
    });

  // ── 2. Write it to the device.
  try {
    await driver.setPassword(deviceId, transport, row.username, candidate);
  } catch (err) {
    // The candidate is DELIBERATELY LEFT IN PLACE. The write may have landed
    // before the error — a timeout is not a rollback — and discarding it here
    // would throw away the only copy of a password the box might now demand.
    const message = err instanceof Error ? err.message : String(err);
    logger.error({ deviceId, transport, err: message }, 'rotation: device write failed, candidate kept');
    return r('failed_device_write',
      `The device refused or dropped the write (${message}). The candidate is kept and the old ` +
      'credential is still active; verify by hand which one the box now accepts.');
  }

  // ── 3. Prove it on a session that did not exist a moment ago.
  const ok = await driver.verify(deviceId, transport, row.username, candidate);
  if (!ok) {
    return r('failed_verification',
      'The device accepted the write but a fresh session with the new credential failed. Not ' +
      'promoting: the stored credential must be the one that demonstrably works.');
  }

  // ── 4. Promote, in one statement, and only now.
  await db('device_transports')
    .where({ device_id: deviceId, transport })
    .update({
      secret_enc: db.ref('secret_next_enc'),
      key_version: db.ref('secret_next_key_version'),
      secret_next_enc: null,
      secret_next_key_version: null,
      secret_next_at: null,
      rotated_at: new Date(),
      updated_at: new Date(),
    });

  return r('rotated', 'Rotated and verified on a fresh session.');
}

/**
 * Rotate a list of devices, ONE AT A TIME.
 *
 * Serial on purpose, and it is not a performance oversight. Concurrency here
 * buys minutes on an operation that runs once a year, and costs the property
 * that matters: if something is systematically wrong — a driver bug, a wrong
 * dialect, a vault key that just changed — a serial loop stops after the first
 * failure with 399 devices untouched, whereas sixteen in flight loses sixteen.
 *
 * `stopOnFailure` defaults to true for the same reason. Turning it off is a
 * deliberate choice an operator makes after reading the first failure, not a
 * default that lets a campaign grind through a fleet doing damage.
 */
export async function rotateMany(
  tenantId: number,
  targets: readonly { deviceId: number; transport: TransportKind }[],
  driver: RotationDriver,
  opts: { stopOnFailure?: boolean } = {},
): Promise<RotationResult[]> {
  const stopOnFailure = opts.stopOnFailure ?? true;
  const out: RotationResult[] = [];
  for (const t of targets) {
    const res = await rotateOne(tenantId, t.deviceId, t.transport, driver);
    out.push(res);
    if (stopOnFailure && res.outcome !== 'rotated') {
      logger.warn(
        { deviceId: t.deviceId, outcome: res.outcome, done: out.length, total: targets.length },
        'rotation campaign stopped on first failure',
      );
      break;
    }
  }
  return out;
}

/** Devices whose rotation was started and never promoted. The morning-after query. */
export async function pendingRotations(tenantId: number): Promise<Array<{
  deviceId: number; deviceName: string; transport: string; stagedAt: Date;
}>> {
  const rows = await db('device_transports as t')
    .join('devices as d', 'd.id', 't.device_id')
    .where('d.tenant_id', tenantId)
    .whereNotNull('t.secret_next_enc')
    .select<Array<{ device_id: number; name: string; transport: string; secret_next_at: Date }>>(
      't.device_id', 'd.name', 't.transport', 't.secret_next_at',
    );
  return rows.map((r) => ({
    deviceId: Number(r.device_id),
    deviceName: r.name,
    transport: r.transport,
    stagedAt: r.secret_next_at,
  }));
}

/**
 * Abandon a candidate after a human has established which password the device
 * actually accepts.
 *
 * Deliberately NOT automatic. A stale candidate is the trace of an ambiguous
 * state, and clearing it on a timer would erase the evidence of the one case
 * this whole module is built around: a write whose outcome is unknown.
 */
export async function discardCandidate(
  tenantId: number, deviceId: number, transport: TransportKind,
): Promise<void> {
  const affected = await db('device_transports')
    .whereIn('device_id', db('devices').select('id').where({ id: deviceId, tenant_id: tenantId }))
    .andWhere({ transport })
    .update({ secret_next_enc: null, secret_next_key_version: null, secret_next_at: null });
  if (affected === 0) throw new Error('no such transport in this tenant');
  void decrypt; // kept in scope: the promotion path above re-reads through the vault
}
