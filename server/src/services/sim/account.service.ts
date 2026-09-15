/**
 * ObliWAN F9 — partner accounts and their credentials.
 *
 * ┌─ THIS TABLE HAS NO `tenant_id`, AND THAT IS THE WHOLE SECURITY STORY ─────┐
 * │ "We hold a partner contract with Phenix" is a fact about the company      │
 * │ running ObliWAN, not about a customer, so migration 032 stores it once    │
 * │ (decision 2). The consequence is the half that matters: ONE WRITE HERE    │
 * │ CHANGES WHAT EVERY TENANT IS SHOWN, and the row holds a CREDENTIAL, so    │
 * │ the write cannot sit behind a tenant-scoped capability.                   │
 * │                                                                          │
 * │ F5 shipped exactly that bug on `ip_asn_ranges`: the import was guarded by │
 * │ SETTINGS_MANAGE, which `TENANT_ROLE_CAPABILITIES.admin` grants to the     │
 * │ admin of ANY tenant, so one customer's admin rewrote every other          │
 * │ customer's attribution. Here the same shape would be worse: a tenant      │
 * │ admin could point the partner account at a host they control and harvest  │
 * │ the credential on the next sweep.                                         │
 * │                                                                          │
 * │ Every mutating export in this file is therefore reached only through      │
 * │ `requireRole('admin')` — the PLATFORM role read from `users.role` — and   │
 * │ that guard is on the ROUTE, upstream of every branch in the handler.      │
 * │ See `routes/sim.routes.ts`.                                               │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ SECRETS (§8.2) — WHAT LEAVES THIS MODULE ────────────────────────────────┐
 * │ `credential_blob` is AES-256-GCM under `OBLIWAN_ENCRYPTION_KEY`. It is    │
 * │ decrypted by exactly one exported function, `loadCredential`, which is    │
 * │ called by the sweep and by nothing that answers an HTTP request.          │
 * │                                                                          │
 * │ `toAccount()` maps a row to the API shape and CANNOT carry the blob: the  │
 * │ projection is explicit, the column is not in it, and what the API returns │
 * │ instead is `hasCredential: boolean`. There is deliberately no "reveal"    │
 * │ endpoint for a partner credential — SECRET_READ exists for device         │
 * │ credentials an engineer must sometimes type into a console, and a partner │
 * │ API token has no such use.                                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import {
  isSimPlatform,
  simPlatformInfo,
  type SimAccount,
  type SimAccountInput,
  type SimAuthMode,
  type SimCredentialInput,
  type SimPlatform,
} from '@obliwan/shared';
import { db } from '../../db';
import { decrypt, encrypt } from '../secretVault.service';
import { logger } from '../../utils/logger';
import { getConnector, isPollable } from './registry';
import { SimConnectorError, type SimCredential } from './types';

// ============================================================================
// Row shape and mapping
// ============================================================================

export interface SimAccountRow {
  id: number;
  platform: SimPlatform;
  name: string;
  base_url: string | null;
  partner_ref: string | null;
  auth_mode: SimAuthMode;
  credential_blob: string | null;
  token_expires_at: Date | string | null;
  status: 'active' | 'disabled' | 'auth_failed';
  skip_operators: unknown;
  monthly_recharge_cap: number | null;
  monthly_cost_cap_cents: string | number | null;
  last_sync_at: Date | string | null;
  last_sync_error: string | null;
  last_sync_line_count: number | null;
  created_at: Date | string;
  updated_at: Date | string;
}

function iso(v: Date | string | null): string | null {
  if (v === null) return null;
  return v instanceof Date ? v.toISOString() : new Date(v).toISOString();
}

/** jsonb comes back as whatever was stored. A non-array is dropped, not cast:
 *  iterating a string would skip every one-character operator name. */
function readSkipOperators(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((v): v is string => typeof v === 'string' && v.trim() !== '');
}

/**
 * Row → API object. The projection is explicit and `credential_blob` is not in
 * it. Do not replace this with a spread.
 */
export function toAccount(row: SimAccountRow): SimAccount {
  return {
    id: row.id,
    platform: row.platform,
    name: row.name,
    baseUrl: row.base_url,
    partnerRef: row.partner_ref,
    authMode: row.auth_mode,
    hasCredential: row.credential_blob !== null && row.credential_blob !== '',
    tokenExpiresAt: iso(row.token_expires_at),
    status: row.status,
    skipOperators: readSkipOperators(row.skip_operators),
    monthlyRechargeCap: row.monthly_recharge_cap,
    monthlyCostCapCents:
      row.monthly_cost_cap_cents === null ? null : Number(row.monthly_cost_cap_cents),
    lastSyncAt: iso(row.last_sync_at),
    lastSyncError: row.last_sync_error,
    lastSyncLineCount: row.last_sync_line_count,
    createdAt: iso(row.created_at)!,
    updatedAt: iso(row.updated_at)!,
  };
}

export class SimAccountError extends Error {
  readonly status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.name = 'SimAccountError';
    this.status = status;
  }
}

// ============================================================================
// Reads
// ============================================================================

export async function listAccounts(): Promise<SimAccount[]> {
  const rows = await db<SimAccountRow>('sim_accounts').orderBy(['platform', 'name']);
  return rows.map(toAccount);
}

export async function getAccount(id: number): Promise<SimAccount | null> {
  const row = await db<SimAccountRow>('sim_accounts').where({ id }).first();
  return row ? toAccount(row) : null;
}

/** Every account the sweep should dial: active, credentialed, and pollable. */
export async function pollableAccounts(): Promise<SimAccountRow[]> {
  const rows = await db<SimAccountRow>('sim_accounts').where({ status: 'active' });
  return rows.filter(
    // `isPollable`, not `ingestion.includes('pull')` spelled out again. This
    // line held the second copy of the rule, and when `ingestion` was corrected
    // for CFAST the two copies would have disagreed about whether a connector
    // that refuses every read belongs on a four-hourly timer.
    (r) => r.credential_blob !== null && isPollable(r.platform),
  );
}

// ============================================================================
// Writes — every caller is behind requireRole('admin')
// ============================================================================

export async function createAccount(input: SimAccountInput): Promise<SimAccount> {
  assertPlatformUsable(input.platform, input.authMode);
  const [row] = await db<SimAccountRow>('sim_accounts')
    .insert({
      platform: input.platform,
      name: input.name,
      base_url: input.baseUrl ?? null,
      partner_ref: input.partnerRef ?? null,
      auth_mode: input.authMode,
      skip_operators: JSON.stringify(input.skipOperators ?? []),
      monthly_recharge_cap: input.monthlyRechargeCap ?? null,
      monthly_cost_cap_cents: input.monthlyCostCapCents ?? null,
    } as Partial<SimAccountRow>)
    .returning('*');
  return toAccount(row);
}

export async function updateAccount(
  id: number,
  input: Partial<SimAccountInput>,
): Promise<SimAccount> {
  const existing = await db<SimAccountRow>('sim_accounts').where({ id }).first();
  if (!existing) throw new SimAccountError('Account not found', 404);

  const patch: Record<string, unknown> = { updated_at: db.fn.now() };
  if (input.name !== undefined) patch.name = input.name;
  if (input.baseUrl !== undefined) patch.base_url = input.baseUrl;
  if (input.partnerRef !== undefined) patch.partner_ref = input.partnerRef;
  if (input.skipOperators !== undefined) {
    patch.skip_operators = JSON.stringify(input.skipOperators);
  }
  if (input.monthlyRechargeCap !== undefined) patch.monthly_recharge_cap = input.monthlyRechargeCap;
  if (input.monthlyCostCapCents !== undefined) {
    patch.monthly_cost_cap_cents = input.monthlyCostCapCents;
  }
  // The platform is NOT editable. Changing it would leave a stored credential
  // minted for one partner pointed at another partner's connector, and every
  // line already collected under the old platform attributed to the new one.
  // Delete the account and make a new one; the lines go with it.
  if (input.authMode !== undefined && input.authMode !== existing.auth_mode) {
    assertPlatformUsable(existing.platform, input.authMode);
    patch.auth_mode = input.authMode;
    // The stored credential belongs to the old mode. Keeping it would mean a
    // token replayed as a password, so it is cleared and the account is
    // unusable until a new one is supplied — visible, rather than broken.
    patch.credential_blob = null;
    patch.token_expires_at = null;
    patch.status = 'disabled';
  }

  const [row] = await db<SimAccountRow>('sim_accounts').where({ id }).update(patch).returning('*');
  return toAccount(row);
}

export async function deleteAccount(id: number): Promise<void> {
  // `sim_lines` cascade; `sim_recharges.account_id` is ON DELETE SET NULL, so
  // the billing history survives with its denormalised identity intact
  // (migration 032, decision 7).
  const deleted = await db('sim_accounts').where({ id }).del();
  if (!deleted) throw new SimAccountError('Account not found', 404);
}

/**
 * Stores a credential, and re-derives what the credential itself says.
 *
 * A token carries the partner id and the expiry in its own claims, and those
 * beat whatever was typed into the form: a token minted for partner A cannot
 * list partner B's lines, and querying with a mismatched id returns an empty
 * page that reads on screen as "this partner has no SIMs".
 */
export async function setCredential(
  id: number,
  cred: SimCredentialInput,
  derived?: { partnerRef?: string | null; expiresAt?: string | null },
): Promise<SimAccount> {
  const existing = await db<SimAccountRow>('sim_accounts').where({ id }).first();
  if (!existing) throw new SimAccountError('Account not found', 404);
  if (cred.authMode !== existing.auth_mode) {
    throw new SimAccountError(
      `This account is in ${existing.auth_mode} mode; the credential supplied is a ` +
        `${cred.authMode} credential. Change the mode first.`,
    );
  }

  const patch: Record<string, unknown> = {
    credential_blob: encrypt(JSON.stringify(cred)),
    status: 'active',
    // A new credential invalidates the previous failure. Leaving `auth_failed`
    // set would keep the account out of `pollableAccounts` forever, which
    // presents as "I fixed the token and nothing happened".
    last_sync_error: null,
    updated_at: db.fn.now(),
  };

  if (cred.authMode === 'token') {
    patch.token_expires_at = derived?.expiresAt ?? null;
    if (derived?.partnerRef) patch.partner_ref = derived.partnerRef;
  } else {
    patch.token_expires_at = null;
  }

  const [row] = await db<SimAccountRow>('sim_accounts').where({ id }).update(patch).returning('*');
  return toAccount(row);
}

/**
 * Decrypts an account's credential. THE ONLY DECRYPTION SITE (§8.2).
 *
 * Never call this from an HTTP handler. Its callers are the sweep and the
 * connection test, both of which use the result and discard it.
 */
export function loadCredential(row: SimAccountRow): SimCredential {
  if (!row.credential_blob) {
    throw new SimAccountError(`Account ${row.id} has no stored credential`, 409);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(decrypt(row.credential_blob));
  } catch {
    // The message deliberately says nothing about the blob's content.
    throw new SimAccountError(
      `Account ${row.id}: the stored credential could not be decrypted. If ` +
        `OBLIWAN_ENCRYPTION_KEY was rotated without re-encryption, supply the ` +
        `credential again.`,
      409,
    );
  }
  const c = parsed as Partial<SimCredential> & { authMode?: string };
  if (c?.authMode === 'token' && typeof (c as { token?: unknown }).token === 'string') {
    return { authMode: 'token', token: (c as { token: string }).token };
  }
  if (
    c?.authMode === 'password' &&
    typeof (c as { username?: unknown }).username === 'string' &&
    typeof (c as { password?: unknown }).password === 'string'
  ) {
    return {
      authMode: 'password',
      username: (c as { username: string }).username,
      password: (c as { password: string }).password,
    };
  }
  throw new SimAccountError(`Account ${row.id}: the stored credential is malformed`, 409);
}

/**
 * Marks an account as unable to authenticate.
 *
 * Separated from a generic sync error because it takes the account OUT of
 * `pollableAccounts`: a dead token would otherwise produce one failed sweep
 * every interval, forever, and bury the real reason under identical noise.
 */
export async function markAuthFailed(id: number, reason: string): Promise<void> {
  await db('sim_accounts')
    .where({ id })
    .update({ status: 'auth_failed', last_sync_error: reason, updated_at: db.fn.now() });
}

// ============================================================================
// Guards
// ============================================================================

/**
 * Refuses an account whose platform cannot be read at all.
 *
 * A CFAST account today is a container for lines loaded from a file — that is
 * legitimate and is allowed. What is refused is `password` mode on a platform
 * whose connector has no authentication to perform, because storing a password
 * that nothing will ever use is storing a secret for no reason (§8.2).
 */
function assertPlatformUsable(platform: SimPlatform, authMode: SimAuthMode): void {
  if (!isSimPlatform(platform)) {
    throw new SimAccountError(`Unknown platform: ${platform}`);
  }
  const info = simPlatformInfo(platform);
  if (!info.readImplemented && authMode === 'password') {
    throw new SimAccountError(
      `${info.label} cannot be polled yet, so a password would be stored and never ` +
        `used. ${info.note}`,
    );
  }
}

/**
 * THE GUARD THAT CLOSES MIGRATION 032's DECISION-4 RESIDUAL HOLE.
 *
 * The composite foreign keys `(device_id, tenant_id)` and `(site_id, tenant_id)`
 * make a cross-tenant reference unrepresentable FOR AN ASSIGNED LINE. They do
 * nothing for a POOLED line, because MATCH SIMPLE skips the check when any
 * column of the key is NULL — and the invariant cannot be compiled as
 * `CHECK (device_id IS NULL OR tenant_id IS NOT NULL)`, because CHECK
 * constraints are not deferrable in Postgres and a tenant deletion fires the
 * two cascades in an unspecified order, which would abort the deletion at
 * random.
 *
 * So it is enforced here, on the only path that writes those columns, and the
 * comment in the migration points at this function by name.
 */
export function assertAssignable(next: {
  tenantId: number | null;
  siteId: number | null;
  deviceId: number | null;
}): void {
  if (next.tenantId === null && (next.siteId !== null || next.deviceId !== null)) {
    throw new SimAccountError(
      'A line with no tenant cannot be attached to a site or a router. Assign the line ' +
        'to a customer first.',
    );
  }
}

// ============================================================================
// Connection test — an interactive act, never part of the sweep
// ============================================================================

export interface SimConnectionTest {
  ok: boolean;
  partnerRef: string | null;
  tokenExpiresAt: string | null;
  lineCount: number | null;
  error: string | null;
  errorCode: string | null;
}

/**
 * Opens a session and lists lines, without storing anything.
 *
 * Lists rather than merely authenticating, because a token can authenticate and
 * still be unable to see a single line — wrong partner id, missing role — and
 * "connection OK" followed by an empty fleet is the most expensive kind of
 * green tick.
 */
export async function testConnection(id: number): Promise<SimConnectionTest> {
  const row = await db<SimAccountRow>('sim_accounts').where({ id }).first();
  if (!row) throw new SimAccountError('Account not found', 404);

  const connector = getConnector(row.platform);
  let session: Awaited<ReturnType<typeof connector.open>> | null = null;
  try {
    const credential = loadCredential(row);
    session = await connector.open({
      accountId: row.id,
      baseUrl: row.base_url,
      partnerRef: row.partner_ref,
      authMode: row.auth_mode,
      credential,
    });
    const listing = await session.listLines();

    // A successful test is also the cheapest moment to learn what the token
    // really is. Persisted so the sweep does not rediscover it every run and so
    // the expiry warning has something to count down from.
    await db('sim_accounts')
      .where({ id })
      .update({
        partner_ref: session.partnerRef ?? row.partner_ref,
        token_expires_at: session.tokenExpiresAt ?? row.token_expires_at,
        status: 'active',
        last_sync_error: null,
        updated_at: db.fn.now(),
      });

    return {
      ok: true,
      partnerRef: session.partnerRef,
      tokenExpiresAt: session.tokenExpiresAt,
      lineCount: listing.lines.length,
      // A test that says "connected, 200 lines" while the partner says it has
      // 900 is the green tick this feature can least afford.
      error:
        listing.declaredTotal !== null && listing.declaredTotal > listing.lines.length
          ? `The partner reports ${listing.declaredTotal} lines and returned ` +
            `${listing.lines.length}: this listing is one page and the remainder is not tracked.`
          : null,
      errorCode: null,
    };
  } catch (err) {
    const code = err instanceof SimConnectorError ? err.code : null;
    // Already scrubbed by `SimConnectorError` (§8.2); scrubbed again is free.
    const message = err instanceof Error ? err.message : String(err);
    if (code === 'AUTH_FAILED') await markAuthFailed(id, message);
    logger.warn({ accountId: id, code }, 'SIM partner connection test failed');
    return {
      ok: false,
      partnerRef: null,
      tokenExpiresAt: null,
      lineCount: null,
      error: message,
      errorCode: code,
    };
  } finally {
    await session?.close().catch(() => undefined);
  }
}
