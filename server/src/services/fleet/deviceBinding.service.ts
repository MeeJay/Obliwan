/**
 * ObliWAN — `assertTargetBinding()` (D5 / risk R4).
 *
 * THE PROBLEM, STATED PLAINLY
 * The platform reaches a router at a tunnel address handed out by a PPP pool.
 * Pools reassign. If we push configuration to "10.66.0.11 because that is where
 * device 42 was yesterday", then one lease rotation is all it takes to write
 * customer A's firewall onto customer B's router. Nothing else in the stack
 * catches that: the connection succeeds, the credentials work, the commands
 * apply. It is a silent, total, cross-tenant failure.
 *
 * THE ANSWER
 * Identity is `ppp_username` + `system_identity` + `serial` — never an address.
 * Before any operation that targets a specific box, we open a FRESH connection
 * (not a pooled one that was established minutes or hours ago, possibly before
 * the lease moved) and ask the box who it is. If the answer does not match the
 * record, the operation is refused and the device is quarantined.
 *
 * THREE RULES THAT MAKE THIS WORTH HAVING
 *  1. FAIL CLOSED. If nothing could be verified — no identity channel, a
 *     brand with no probe path yet — the assertion FAILS. "We could not check"
 *     never means "go ahead".
 *  2. A FRESH SOCKET. Reusing the pool would prove the identity of whatever
 *     answered when the pool dialled, which is the very thing in question.
 *  3. ONE MISMATCH IS FATAL. Two matching attributes do not outvote one
 *     contradicting attribute: a box that agrees on `system_identity` (an
 *     operator-typed string, easily duplicated across a template fleet) and
 *     disagrees on `serial` is a different box.
 *
 * In M2 nothing writes to a device. This function exists now anyway, tested and
 * exported, so that when M6 adds the write paths there is exactly one door and
 * it is already locked.
 */

import { FAMILY_BRAND, type DeviceFamily } from '@obliwan/shared';
import {
  createRouterOsConnection,
  RouterOsTrapError,
  type RouterOsConnection,
} from '../transport/routeros';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { decrypt } from '../secretVault.service';

// ============================================================================
// Result shapes
// ============================================================================

export type IdentityAttribute = 'ppp_username' | 'system_identity' | 'serial';

export interface AttributeCheck {
  attribute: IdentityAttribute;
  expected: string | null;
  observed: string | null;
  /** `match` the two agree · `mismatch` they contradict · `unknown` the box
   *  could not tell us · `unrecorded` we had nothing to compare against. */
  outcome: 'match' | 'mismatch' | 'unknown' | 'unrecorded';
}

export interface BindingAssertion {
  deviceId: number;
  ok: boolean;
  checks: AttributeCheck[];
  /** How many attributes actually corroborated the identity. */
  matched: number;
  mismatched: number;
  /** Address the fresh connection actually dialled. Reported for the audit
   *  trail; deliberately NOT part of the identity. */
  dialled: string;
  reason: string;
  at: string;
}

export class BindingAssertionError extends Error {
  readonly assertion: BindingAssertion;
  constructor(assertion: BindingAssertion) {
    super(`Identity assertion failed for device ${assertion.deviceId}: ${assertion.reason}`);
    this.name = 'BindingAssertionError';
    this.assertion = assertion;
  }
}

/** What a fresh connection managed to read off the box. */
export interface ObservedIdentity {
  systemIdentity: string | null;
  serial: string | null;
  pppUsername: string | null;
}

// ============================================================================
// Comparison — pure, therefore testable without a router
// ============================================================================

function normalise(value: string | null | undefined): string | null {
  const v = value?.trim();
  return v ? v.toLowerCase() : null;
}

/**
 * Compare recorded identity against observed identity.
 *
 * Exported separately from the network path so the DECISION can be tested
 * exhaustively (it is the part that must never be wrong) without a device.
 */
export function compareIdentity(
  expected: Partial<Record<IdentityAttribute, string | null>>,
  observed: ObservedIdentity,
): { checks: AttributeCheck[]; ok: boolean; matched: number; mismatched: number; reason: string } {
  const pairs: Array<[IdentityAttribute, string | null | undefined, string | null]> = [
    ['ppp_username', expected.ppp_username, observed.pppUsername],
    ['system_identity', expected.system_identity, observed.systemIdentity],
    ['serial', expected.serial, observed.serial],
  ];

  const checks: AttributeCheck[] = pairs.map(([attribute, exp, obs]) => {
    const e = normalise(exp);
    const o = normalise(obs);
    let outcome: AttributeCheck['outcome'];
    if (e === null) outcome = 'unrecorded';
    else if (o === null) outcome = 'unknown';
    else outcome = e === o ? 'match' : 'mismatch';
    return {
      attribute,
      expected: exp ?? null,
      observed: obs,
      outcome,
    };
  });

  const matched = checks.filter((c) => c.outcome === 'match').length;
  const mismatched = checks.filter((c) => c.outcome === 'mismatch').length;

  if (mismatched > 0) {
    const names = checks.filter((c) => c.outcome === 'mismatch').map((c) => c.attribute);
    return {
      checks,
      ok: false,
      matched,
      mismatched,
      reason: `identity mismatch on ${names.join(', ')} — this is NOT the recorded device`,
    };
  }
  if (matched === 0) {
    // Fail closed. Either we recorded no identity at all (a device that has
    // never been probed) or the box answered nothing. Both mean "unproven",
    // and unproven must not authorise a write.
    return {
      checks,
      ok: false,
      matched,
      mismatched,
      reason:
        'no identity attribute could be corroborated — the device is unproven, ' +
        'not confirmed (fail closed)',
    };
  }
  return { checks, ok: true, matched, mismatched, reason: `identity confirmed on ${matched} attribute(s)` };
}

// ============================================================================
// Reading identity off a live RouterOS box
// ============================================================================

/** `!trap` = "this menu does not exist here" (a CHR has no RouterBOARD). It is
 *  an answer, not a failure: null, and carry on. */
async function optionalRow(
  conn: RouterOsConnection,
  path: string,
): Promise<Record<string, string> | null> {
  try {
    return await conn.queryFirst([path]);
  } catch (err) {
    if (err instanceof RouterOsTrapError) return null;
    throw err;
  }
}

export async function readRouterOsIdentity(conn: RouterOsConnection): Promise<ObservedIdentity> {
  const identity = await optionalRow(conn, '/system/identity/print');
  const routerboard = await optionalRow(conn, '/system/routerboard/print');
  // The device's own view of its PPP account. On a CPE the tunnel is an
  // l2tp-client; the CHR itself has none, which is correct — a concentrator is
  // asserted on identity + serial.
  const l2tp = await optionalRow(conn, '/interface/l2tp-client/print');

  return {
    systemIdentity: identity?.name ?? null,
    serial: routerboard?.['serial-number'] ?? null,
    pppUsername: l2tp?.user ?? null,
  };
}

// ============================================================================
// The assertion
// ============================================================================

interface TargetRow {
  id: number;
  tenant_id: number;
  name: string;
  family: string;
  status: string;
  ppp_username: string | null;
  system_identity: string | null;
  serial: string | null;
  tunnel_ip: string | null;
  host: string | null;
  port: number | null;
  username: string | null;
  secret_enc: string | null;
  use_tls: boolean | null;
  tls_fingerprint_sha256: string | null;
  enabled: boolean | null;
}

async function loadTarget(deviceId: number): Promise<TargetRow> {
  const row = await db('devices as d')
    .leftJoin('device_transports as t', function joinRouterOs(this: any) {
      this.on('t.device_id', '=', 'd.id').andOn('t.transport', '=', db.raw('?', ['routeros_api']));
    })
    .where('d.id', deviceId)
    .first<TargetRow | undefined>(
      'd.id',
      'd.tenant_id',
      'd.name',
      'd.family',
      'd.status',
      'd.ppp_username',
      'd.system_identity',
      'd.serial',
      'd.tunnel_ip',
      't.host',
      't.port',
      't.username',
      't.secret_enc',
      't.use_tls',
      't.tls_fingerprint_sha256',
      't.enabled',
    );
  if (!row) throw new Error(`Device ${deviceId} does not exist`);
  return row;
}

export interface AssertOptions {
  /** Quarantine the device on mismatch. Default true — a box that answered
   *  with the wrong identity must not stay targetable. */
  quarantineOnMismatch?: boolean;
  /** Throw instead of returning a failed assertion. Default true: callers on
   *  the write path must not be able to ignore a returned `ok: false`. */
  throwOnFailure?: boolean;
  connectTimeoutMs?: number;
}

/**
 * Prove that the box currently at the device's address IS the device.
 *
 * ALWAYS opens a new socket, and always closes it. Nothing is cached: a cached
 * assertion is a stale assertion, and a stale assertion is the bug.
 */
export async function assertTargetBinding(
  deviceId: number,
  options: AssertOptions = {},
): Promise<BindingAssertion> {
  const quarantineOnMismatch = options.quarantineOnMismatch ?? true;
  const throwOnFailure = options.throwOnFailure ?? true;
  const at = new Date().toISOString();
  const target = await loadTarget(deviceId);

  const fail = async (reason: string, checks: AttributeCheck[] = [], dialled = '-'): Promise<BindingAssertion> => {
    const assertion: BindingAssertion = {
      deviceId,
      ok: false,
      checks,
      matched: checks.filter((c) => c.outcome === 'match').length,
      mismatched: checks.filter((c) => c.outcome === 'mismatch').length,
      dialled,
      reason,
      at,
    };
    if (assertion.mismatched > 0 && quarantineOnMismatch) {
      await db('devices')
        .where({ id: deviceId })
        .update({ status: 'quarantined', is_managed: false, updated_at: db.fn.now() });
      logger.error(
        { deviceId, reason, checks },
        'Device quarantined: the box at its address is not the recorded device (R4)',
      );
    }
    if (throwOnFailure) throw new BindingAssertionError(assertion);
    return assertion;
  };

  if (target.status === 'disabled') {
    return fail("device status is 'disabled'; no transport may be opened");
  }

  const brand = FAMILY_BRAND[target.family as DeviceFamily];
  if (brand !== 'mikrotik') {
    // Honest refusal rather than a silent pass. DrayTek / Zyxel / SonicWall
    // identity probes ride SSH and REST, and those write paths arrive at M6:
    // returning `ok: true` here would hand M6 an unlocked door.
    return fail(
      `no fresh-connection identity path for family '${target.family}' yet (milestone M6) — ` +
        'refusing rather than assuming',
    );
  }

  if (!target.enabled) return fail('routeros_api transport is absent or disabled');
  const host = target.host ?? target.tunnel_ip;
  if (!host) return fail('no address to dial');
  if (!target.username || !target.secret_enc) return fail('no credential in the vault');

  let conn: RouterOsConnection | null = null;
  let observed: ObservedIdentity;
  try {
    conn = await createRouterOsConnection({
      host,
      port: target.port ?? undefined,
      tls: target.use_tls === true,
      username: target.username,
      password: decrypt(target.secret_enc),
      expectedFingerprint: target.tls_fingerprint_sha256,
      connectTimeoutMs: options.connectTimeoutMs ?? 10_000,
      label: `assert:${target.name}`,
    });
    observed = await readRouterOsIdentity(conn);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return fail(`fresh connection to ${host} failed: ${message}`, [], host);
  } finally {
    // The socket exists for this assertion and dies with it. It is deliberately
    // NOT handed to the pool: a connection opened to prove identity must not
    // become the connection used to act on it minutes later.
    conn?.close();
  }

  const comparison = compareIdentity(
    {
      ppp_username: target.ppp_username,
      system_identity: target.system_identity,
      serial: target.serial,
    },
    observed,
  );

  if (!comparison.ok) {
    return fail(comparison.reason, comparison.checks, host);
  }

  // Opportunistic learning: fill in what was blank, never overwrite what was
  // recorded (that would let a wrong box rewrite the identity it failed).
  const learn: Record<string, unknown> = {};
  if (!target.system_identity && observed.systemIdentity) {
    learn.system_identity = observed.systemIdentity;
  }
  if (!target.serial && observed.serial) learn.serial = observed.serial;
  if (Object.keys(learn).length > 0) {
    await db('devices').where({ id: deviceId }).update({ ...learn, updated_at: db.fn.now() });
  }

  const assertion: BindingAssertion = {
    deviceId,
    ok: true,
    checks: comparison.checks,
    matched: comparison.matched,
    mismatched: 0,
    dialled: host,
    reason: comparison.reason,
    at,
  };
  logger.info(
    { deviceId, dialled: host, matched: comparison.matched },
    'Target binding asserted on a fresh connection',
  );
  return assertion;
}

/**
 * The ONLY sanctioned way to act on a device.
 *
 * `assertTargetBinding()` first, work second. Exported as one call so that no
 * future caller can accidentally do the work and forget the proof — the shape
 * of the API makes the safe order the only order.
 */
export async function withAssertedDevice<T>(
  deviceId: number,
  work: (assertion: BindingAssertion) => Promise<T>,
  options: AssertOptions = {},
): Promise<T> {
  const assertion = await assertTargetBinding(deviceId, { ...options, throwOnFailure: true });
  return work(assertion);
}
