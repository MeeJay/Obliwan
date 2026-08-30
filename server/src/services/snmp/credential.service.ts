/**
 * SNMP credentials and SNMP targets -- the configuration side.
 *
 * ┌─ THE SECRET NEVER COMES BACK OUT. ────────────────────────────────────────┐
 * │ There is no "masked" community field, no `community: "pub***"`, no        │
 * │ `communityLength`. The API answers `hasCommunity: true`. A masked         │
 * │ plaintext is still a plaintext on the path that produced it, and it is    │
 * │ how a community string reaches a log, a HAR file attached to a support    │
 * │ ticket, or a browser extension.                                          │
 * │                                                                          │
 * │ The write path follows from that: a client that GETs then PUTs cannot     │
 * │ send the secret back, so an ABSENT secret field means UNCHANGED, never    │
 * │ "clear it". Same rule as the notification channels (AUDIT-SEC #10).       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The vault blob format is enforced by the DATABASE (`snmp_credentials_vault_
 * fmt_chk`, `^v[0-9]+:[0-9]+:`), so an attempt to store something the legacy
 * `utils/crypto.ts` produced is refused by PostgreSQL itself rather than
 * discovered on the day it fails to decrypt.
 */

import type {
  SnmpAuthProtocol,
  SnmpCredentialSummary,
  SnmpPrivProtocol,
  SnmpSecurityLevel,
  SnmpVersion,
} from '@obliwan/shared';
import { db } from '../../db';
import { currentKeyVersion, encrypt } from '../secretVault.service';
import type { SnmpCredentialRow, SnmpTargetRow } from './targets';

// ============================================================================
// Credentials
// ============================================================================

export interface CredentialInput {
  name: string;
  version: SnmpVersion;
  /** v1/v2c only. Absent on update = unchanged. */
  community?: string;
  username?: string | null;
  securityLevel?: SnmpSecurityLevel | null;
  authProtocol?: SnmpAuthProtocol | null;
  /** Absent on update = unchanged. */
  authKey?: string;
  privProtocol?: SnmpPrivProtocol | null;
  /** Absent on update = unchanged. */
  privKey?: string;
  context?: string | null;
}

/** The ONLY shape that leaves the server. */
export function toSummary(row: SnmpCredentialRow): SnmpCredentialSummary {
  return {
    id: row.id,
    uuid: row.uuid,
    tenantId: row.tenant_id,
    name: row.name,
    version: row.version,
    username: row.username,
    securityLevel: row.security_level,
    authProtocol: row.auth_proto,
    privProtocol: row.priv_proto,
    context: row.context,
    hasCommunity: row.community_enc !== null,
    hasAuthKey: row.auth_key_enc !== null,
    hasPrivKey: row.priv_key_enc !== null,
  };
}

export async function listCredentials(tenantId: number): Promise<SnmpCredentialSummary[]> {
  const rows = await db<SnmpCredentialRow>('snmp_credentials')
    .where({ tenant_id: tenantId })
    .orderBy('name');
  return rows.map(toSummary);
}

export async function getCredential(
  tenantId: number,
  id: number,
): Promise<SnmpCredentialSummary | null> {
  const row = await db<SnmpCredentialRow>('snmp_credentials')
    .where({ id, tenant_id: tenantId })
    .first();
  return row ? toSummary(row) : null;
}

/**
 * The v1/v2c vs v3 shape is ALSO enforced by a database CHECK
 * (`snmp_credentials_shape_chk`). It is re-stated here so the caller gets a
 * 400 with a sentence instead of a 23514 with a constraint name -- not because
 * the check is redundant. Validation in the application is a courtesy;
 * validation in the schema is the guarantee.
 */
function shapeColumns(input: CredentialInput): Record<string, unknown> {
  if (input.version === 'v3') {
    return {
      version: 'v3',
      community_enc: null,
      username: input.username ?? null,
      security_level: input.securityLevel ?? null,
      auth_proto: input.authProtocol ?? null,
      priv_proto: input.privProtocol ?? null,
      context: input.context ?? null,
    };
  }
  return {
    version: input.version,
    username: null,
    security_level: null,
    auth_proto: null,
    priv_proto: null,
    context: input.context ?? null,
  };
}

export async function createCredential(
  tenantId: number,
  input: CredentialInput,
): Promise<SnmpCredentialSummary> {
  const columns: Record<string, unknown> = {
    tenant_id: tenantId,
    name: input.name,
    key_version: currentKeyVersion(),
    ...shapeColumns(input),
  };

  if (input.version === 'v3') {
    columns.auth_key_enc = input.authKey ? encrypt(input.authKey) : null;
    columns.priv_key_enc = input.privKey ? encrypt(input.privKey) : null;
  } else {
    columns.community_enc = input.community ? encrypt(input.community) : null;
  }

  const [row] = await db<SnmpCredentialRow>('snmp_credentials').insert(columns).returning('*');
  return toSummary(row);
}

/**
 * Update. An OMITTED secret is UNCHANGED.
 *
 * That is not a convenience: since the GET never returns the secret, the
 * client cannot echo it back, so reading "absent" as "clear" would wipe the
 * community string of every credential the first time somebody renamed one.
 */
export async function updateCredential(
  tenantId: number,
  id: number,
  input: CredentialInput,
): Promise<SnmpCredentialSummary | null> {
  const current = await db<SnmpCredentialRow>('snmp_credentials')
    .where({ id, tenant_id: tenantId })
    .first();
  if (!current) return null;

  const columns: Record<string, unknown> = {
    name: input.name,
    ...shapeColumns(input),
    updated_at: new Date(),
  };

  if (input.version === 'v3') {
    if (input.authKey !== undefined) {
      columns.auth_key_enc = input.authKey ? encrypt(input.authKey) : null;
      columns.key_version = currentKeyVersion();
    } else {
      columns.auth_key_enc = current.auth_key_enc;
    }
    if (input.privKey !== undefined) {
      columns.priv_key_enc = input.privKey ? encrypt(input.privKey) : null;
      columns.key_version = currentKeyVersion();
    } else {
      columns.priv_key_enc = current.priv_key_enc;
    }
    columns.community_enc = null;
  } else {
    if (input.community !== undefined) {
      columns.community_enc = input.community ? encrypt(input.community) : null;
      columns.key_version = currentKeyVersion();
    } else {
      columns.community_enc = current.community_enc;
    }
    columns.auth_key_enc = null;
    columns.priv_key_enc = null;
  }

  const [row] = await db<SnmpCredentialRow>('snmp_credentials')
    .where({ id, tenant_id: tenantId })
    .update(columns)
    .returning('*');
  return row ? toSummary(row) : null;
}

/**
 * Delete. The FK from `snmp_targets` is ON DELETE RESTRICT, so a credential
 * still in use raises 23503 and the controller turns that into a 409. Deleting
 * it silently and leaving the targets un-pollable would be a fleet-wide outage
 * caused by a tidy-up.
 */
export async function deleteCredential(tenantId: number, id: number): Promise<boolean> {
  const count = await db('snmp_credentials').where({ id, tenant_id: tenantId }).del();
  return count > 0;
}

/** How many targets use this credential -- so the UI can say so BEFORE the
 *  operator clicks delete. */
export async function credentialUsage(tenantId: number, id: number): Promise<number> {
  const row = await db('snmp_targets')
    .join('snmp_credentials', 'snmp_credentials.id', 'snmp_targets.credential_id')
    .where('snmp_credentials.tenant_id', tenantId)
    .where('snmp_targets.credential_id', id)
    .count<{ count: string }[]>('* as count');
  return Number(row[0]?.count ?? 0);
}

// ============================================================================
// Targets
// ============================================================================

export interface TargetInput {
  credentialId?: number | null;
  host?: string | null;
  port?: number;
  enabled?: boolean;
  pollIntervalSec?: number | null;
  timeoutMs?: number;
  retries?: number;
  maxRepetitions?: number;
  supportsHcCounters?: boolean;
}

export interface TargetSummary {
  id: number;
  uuid: string;
  deviceId: number;
  credentialId: number | null;
  host: string | null;
  port: number;
  enabled: boolean;
  pollIntervalSec: number | null;
  timeoutMs: number;
  retries: number;
  maxRepetitions: number;
  supportsHcCounters: boolean;
  nextPollAt: string;
  lastPollAt: string | null;
  lastOkAt: string | null;
  consecutiveFailures: number;
  lastError: string | null;
  lastDiscoveryAt: string | null;
}

function toTargetSummary(row: SnmpTargetRow): TargetSummary {
  return {
    id: row.id,
    uuid: row.uuid,
    deviceId: row.device_id,
    credentialId: row.credential_id,
    host: row.host,
    port: row.port,
    enabled: row.enabled,
    pollIntervalSec: row.poll_interval_sec,
    timeoutMs: row.timeout_ms,
    retries: row.retries,
    maxRepetitions: row.max_repetitions,
    supportsHcCounters: row.supports_hc_counters,
    nextPollAt: new Date(row.next_poll_at).toISOString(),
    lastPollAt: row.last_poll_at ? new Date(row.last_poll_at).toISOString() : null,
    lastOkAt: row.last_ok_at ? new Date(row.last_ok_at).toISOString() : null,
    consecutiveFailures: row.consecutive_failures,
    lastError: row.last_error,
    lastDiscoveryAt: row.last_discovery_at ? new Date(row.last_discovery_at).toISOString() : null,
  };
}

/** Tenant check on BOTH the device and the credential: a target is the one
 *  place where a device id and a credential id meet, and accepting a
 *  cross-tenant credential id there would hand another customer's community
 *  string to this customer's router. */
export async function upsertTarget(
  tenantId: number,
  deviceId: number,
  input: TargetInput,
): Promise<TargetSummary | null> {
  const device = await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id');
  if (!device) return null;

  if (input.credentialId != null) {
    const cred = await db('snmp_credentials')
      .where({ id: input.credentialId, tenant_id: tenantId })
      .first('id');
    if (!cred) return null;
  }

  const columns: Record<string, unknown> = { device_id: deviceId, updated_at: new Date() };
  if (input.credentialId !== undefined) columns.credential_id = input.credentialId;
  if (input.host !== undefined) columns.host = input.host;
  if (input.port !== undefined) columns.port = input.port;
  if (input.enabled !== undefined) columns.enabled = input.enabled;
  if (input.pollIntervalSec !== undefined) columns.poll_interval_sec = input.pollIntervalSec;
  if (input.timeoutMs !== undefined) columns.timeout_ms = input.timeoutMs;
  if (input.retries !== undefined) columns.retries = input.retries;
  if (input.maxRepetitions !== undefined) columns.max_repetitions = input.maxRepetitions;
  if (input.supportsHcCounters !== undefined) {
    columns.supports_hc_counters = input.supportsHcCounters;
  }

  const existing = await db<SnmpTargetRow>('snmp_targets').where({ device_id: deviceId }).first();
  if (existing) {
    const [row] = await db<SnmpTargetRow>('snmp_targets')
      .where({ id: existing.id })
      .update(columns)
      .returning('*');
    // Changing the interval changes what "expected" means for the rate window
    // and for `expected_count` in every rollup. The denormalised copy on
    // `snmp_interfaces` has to follow, or the window bounds of study 3.4e are
    // measured against a value nobody uses any more.
    if (input.pollIntervalSec !== undefined) {
      await db('snmp_interfaces')
        .where({ device_id: deviceId })
        .update({ effective_poll_sec: input.pollIntervalSec ?? 30, updated_at: new Date() });
    }
    return toTargetSummary(row);
  }

  const [row] = await db('snmp_targets')
    .insert({ ...columns, created_at: new Date() })
    .returning('*');
  return toTargetSummary(row as SnmpTargetRow);
}

export async function getTargetSummary(
  tenantId: number,
  deviceId: number,
): Promise<TargetSummary | null> {
  const row = await db<SnmpTargetRow>('snmp_targets')
    .join('devices', 'devices.id', 'snmp_targets.device_id')
    .where('devices.tenant_id', tenantId)
    .where('snmp_targets.device_id', deviceId)
    .first('snmp_targets.*');
  return row ? toTargetSummary(row) : null;
}

export async function deleteTarget(tenantId: number, deviceId: number): Promise<boolean> {
  const device = await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id');
  if (!device) return false;
  const count = await db('snmp_targets').where({ device_id: deviceId }).del();
  return count > 0;
}
