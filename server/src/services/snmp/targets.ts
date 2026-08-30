/**
 * The data layer between `snmp_targets` / `snmp_credentials` /
 * `snmp_interfaces` and everything else in this folder.
 *
 * One rule governs the whole file: A DECRYPTED SECRET EXISTS IN MEMORY, ON THE
 * PATH TO THE AGENT, AND NOWHERE ELSE (ARCHITECTURE section 8.2). It is never
 * logged, never cached on disk, never attached to an error, and it never
 * appears in any type that a controller can reach -- which is why
 * `resolveTarget()` returns an `SnmpTarget` (a transport input) and never a
 * "credential DTO".
 */

import type { Knex } from 'knex';
import type {
  SnmpVersion,
  SnmpSecurityLevel,
  SnmpAuthProtocol,
  SnmpPrivProtocol,
  InterfaceState,
} from '@obliwan/shared';
import { db } from '../../db';
import { decrypt } from '../secretVault.service';
import { logger } from '../../utils/logger';
import type { SnmpTarget } from '../transport/snmp.transport';
import { snmpConfig } from './config';

// ============================================================================
// Row shapes
// ============================================================================

export interface SnmpCredentialRow {
  id: number;
  uuid: string;
  tenant_id: number;
  name: string;
  version: SnmpVersion;
  community_enc: string | null;
  username: string | null;
  security_level: SnmpSecurityLevel | null;
  auth_proto: SnmpAuthProtocol | null;
  auth_key_enc: string | null;
  priv_proto: SnmpPrivProtocol | null;
  priv_key_enc: string | null;
  context: string | null;
  engine_id: string | null;
  key_version: number;
  created_at: Date;
  updated_at: Date;
}

export interface SnmpTargetRow {
  id: number;
  uuid: string;
  device_id: number;
  credential_id: number | null;
  host: string | null;
  port: number;
  enabled: boolean;
  poll_interval_sec: number | null;
  timeout_ms: number;
  retries: number;
  max_repetitions: number;
  supports_hc_counters: boolean;
  next_poll_at: Date;
  last_poll_at: Date | null;
  last_ok_at: Date | null;
  consecutive_failures: number;
  last_error: string | null;
  last_discovery_at: Date | null;
  next_discovery_at: Date | null;
}

export interface SnmpInterfaceRow {
  id: number;
  device_id: number;
  if_name: string;
  if_index: number;
  if_alias: string | null;
  if_descr: string | null;
  phys_address: string | null;
  if_type: number | null;
  speed_bps: string | number;
  admin_status: number;
  oper_status: number;
  state: InterfaceState;
  monitored: boolean;
  effective_poll_sec: number;
  counter_bits: number;
  counter_unreliable: boolean;
  needs_rediscovery: boolean;
  first_seen_at: Date;
  last_seen_at: Date | null;
  vanished_at: Date | null;
}

/** A target joined to its credential and to the device's address. */
export interface ResolvedTarget {
  target: SnmpTargetRow;
  credential: SnmpCredentialRow | null;
  deviceId: number;
  tenantId: number;
  deviceName: string;
  groupId: number | null;
  /** `snmp_targets.host`, else the device's tunnel address. */
  address: string | null;
  pollIntervalSec: number;
}

// ============================================================================
// Loading
// ============================================================================

/**
 * Where to dial.
 *
 * `snmp_targets.host` is a plain string column because it may legitimately
 * hold a DNS name, so it is used verbatim -- never cast to `inet`, which
 * would throw on exactly the rows an operator typed by hand. The device's
 * tunnel address is the fallback, and `null` (no host, no tunnel) is a
 * TargetNotUsableError rather than a silent skip: a device nobody can dial
 * must say so, not quietly stop producing data.
 */
function addressOf(row: { host: string | null; _tunnel_ip: string | null }): string | null {
  const explicit = row.host?.trim();
  if (explicit) return explicit;
  return row._tunnel_ip ?? null;
}

interface TargetJoinRow extends SnmpTargetRow {
  _tenant_id: number;
  _device_name: string;
  _group_id: number | null;
  _tunnel_ip: string | null;
}

function toResolved(row: TargetJoinRow, credential: SnmpCredentialRow | null): ResolvedTarget {
  return {
    target: row,
    credential,
    deviceId: row.device_id,
    tenantId: row._tenant_id,
    deviceName: row._device_name,
    groupId: row._group_id,
    address: addressOf(row),
    pollIntervalSec: row.poll_interval_sec ?? snmpConfig.defaultPollIntervalSec,
  };
}

function targetQuery(exec: Knex | Knex.Transaction = db) {
  return exec<TargetJoinRow>('snmp_targets')
    .join('devices', 'devices.id', 'snmp_targets.device_id')
    .select(
      'snmp_targets.*',
      'devices.tenant_id as _tenant_id',
      'devices.name as _device_name',
      'devices.group_id as _group_id',
      exec.raw('host(devices.tunnel_ip) as _tunnel_ip'),
    );
}

async function attachCredentials(rows: TargetJoinRow[]): Promise<ResolvedTarget[]> {
  const ids = [...new Set(rows.map((r) => r.credential_id).filter((v): v is number => v !== null))];
  const creds = ids.length
    ? await db<SnmpCredentialRow>('snmp_credentials').whereIn('id', ids)
    : [];
  const byId = new Map(creds.map((c) => [c.id, c]));
  return rows.map((r) => toResolved(r, r.credential_id ? (byId.get(r.credential_id) ?? null) : null));
}

export async function getTarget(targetId: number): Promise<ResolvedTarget | null> {
  const row = await targetQuery().where('snmp_targets.id', targetId).first();
  if (!row) return null;
  const [resolved] = await attachCredentials([row]);
  return resolved;
}

export async function getTargetForDevice(deviceId: number): Promise<ResolvedTarget | null> {
  const row = await targetQuery().where('snmp_targets.device_id', deviceId).first();
  if (!row) return null;
  const [resolved] = await attachCredentials([row]);
  return resolved;
}

/**
 * Claim the targets that are due, and push their `next_poll_at` forward IN THE
 * SAME STATEMENT.
 *
 * The `UPDATE ... RETURNING` over a `SELECT ... FOR UPDATE SKIP LOCKED`
 * sub-select is the whole concurrency story:
 *
 *  - claiming and rescheduling in one statement means a device whose poll
 *    takes 40 s at a 30 s interval is NOT picked again by the next tick,
 *    which would double the load on the slowest device in the fleet and
 *    corrupt its deltas by halving every window;
 *  - `SKIP LOCKED` means a second process that reached here despite the
 *    leader election (a mid-failover overlap) claims DIFFERENT rows rather
 *    than the same ones;
 *  - the ORDER BY drives `snmp_targets_sched (enabled, next_poll_at)`.
 *
 * The jitter is applied here, on the way out: without it 300 devices are
 * polled inside the same 100 ms every 30 s, which is a burst on the tunnel,
 * on the CHR and on the writer all at once.
 */
export async function claimDueTargets(limit: number): Promise<ResolvedTarget[]> {
  const jitterPct = snmpConfig.pollJitterPct;
  const defaultInterval = snmpConfig.defaultPollIntervalSec;

  const result = await db.raw<{ rows: TargetJoinRow[] }>(
    `
    WITH due AS (
      SELECT id
      FROM snmp_targets
      WHERE enabled AND next_poll_at <= now()
      ORDER BY next_poll_at
      LIMIT ?
      FOR UPDATE SKIP LOCKED
    )
    UPDATE snmp_targets t
       SET next_poll_at = now()
         + (coalesce(t.poll_interval_sec, ?) * interval '1 second')
         + (coalesce(t.poll_interval_sec, ?) * (random() - 0.5) * ? / 100.0) * interval '1 second'
      FROM due, devices d
     WHERE t.id = due.id AND d.id = t.device_id
    RETURNING t.*,
              d.tenant_id AS "_tenant_id",
              d.name      AS "_device_name",
              d.group_id  AS "_group_id",
              host(d.tunnel_ip) AS "_tunnel_ip"
    `,
    [limit, defaultInterval, defaultInterval, jitterPct],
  );

  const rows = result.rows ?? [];
  if (rows.length === 0) return [];
  return attachCredentials(rows);
}

export async function listInterfaceRows(
  deviceId: number,
  opts: { includeVanished?: boolean; monitoredOnly?: boolean } = {},
): Promise<SnmpInterfaceRow[]> {
  const q = db<SnmpInterfaceRow>('snmp_interfaces').where({ device_id: deviceId });
  if (!opts.includeVanished) q.where('state', 'active');
  if (opts.monitoredOnly) q.where('monitored', true);
  return q.orderBy('if_index');
}

// ============================================================================
// Dialable target resolution
// ============================================================================

export class TargetNotUsableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TargetNotUsableError';
  }
}

/**
 * Turn a target row plus its credential into something dialable.
 *
 * A decryption failure is NOT swallowed. It means the vault key does not match
 * the stored ciphertext, and a poller that quietly skipped such a device would
 * report "no data" for a credential problem -- the exact confusion the R8
 * startup guard exists to prevent.
 */
export function resolveTarget(resolved: ResolvedTarget): SnmpTarget {
  const { target, credential, address } = resolved;
  if (!address) {
    throw new TargetNotUsableError(
      `SNMP target ${target.id}: no host on the target and no tunnel_ip on device ${target.device_id}`,
    );
  }
  if (!credential) {
    throw new TargetNotUsableError(`SNMP target ${target.id}: no credential attached`);
  }

  const base = {
    host: address,
    port: target.port,
    version: credential.version,
    timeoutMs: target.timeout_ms,
    retries: target.retries,
    maxRepetitions: target.max_repetitions,
  };

  if (credential.version === 'v3') {
    return {
      ...base,
      credentials: {
        username: credential.username,
        securityLevel: credential.security_level,
        authProtocol: credential.auth_proto,
        authKey: credential.auth_key_enc ? decrypt(credential.auth_key_enc) : null,
        privProtocol: credential.priv_proto,
        privKey: credential.priv_key_enc ? decrypt(credential.priv_key_enc) : null,
        context: credential.context,
      },
    };
  }

  return {
    ...base,
    credentials: {
      community: credential.community_enc ? decrypt(credential.community_enc) : null,
      context: credential.context,
    },
  };
}

// ============================================================================
// Target bookkeeping
// ============================================================================

/**
 * Record the outcome of a poll.
 *
 * `consecutive_failures` drives the adaptive back-off in `scheduler.ts`. It is
 * reset by a SUCCESS and not by a partial one: a device that answers sysUpTime
 * and nothing else is not healthy.
 *
 * `last_error` is truncated. An agent can return a multi-kilobyte message and
 * this column is read on a list screen.
 */
export async function recordPollOutcome(
  targetId: number,
  outcome: { ok: boolean; error?: string | null; backoffSec?: number },
): Promise<void> {
  const patch: Record<string, unknown> = {
    last_poll_at: db.fn.now(),
    updated_at: db.fn.now(),
  };
  if (outcome.ok) {
    patch.last_ok_at = db.fn.now();
    patch.consecutive_failures = 0;
    patch.last_error = null;
  } else {
    patch.consecutive_failures = db.raw('consecutive_failures + 1');
    patch.last_error = (outcome.error ?? 'unknown error').slice(0, 500);
    if (outcome.backoffSec && outcome.backoffSec > 0) {
      patch.next_poll_at = db.raw("now() + (? * interval '1 second')", [outcome.backoffSec]);
    }
  }
  await db('snmp_targets').where({ id: targetId }).update(patch);
}

/**
 * Adaptive back-off after consecutive failures.
 *
 * A device that has been dead for an hour does not become reachable by being
 * asked every 30 s -- it just costs 120 timeouts an hour, each holding a
 * concurrency slot for `timeout x (retries + 1)`, which is how a handful of
 * dead sites starves the polling of the live ones. Doubling, capped at 10
 * intervals or 15 minutes, keeps recovery detection under a quarter of an hour
 * while dividing the wasted budget by ten.
 */
export function backoffSeconds(intervalSec: number, consecutiveFailures: number): number {
  const factor = Math.min(2 ** Math.min(consecutiveFailures, 4), 10);
  return Math.min(intervalSec * factor, 900);
}

export async function markDiscovered(targetId: number, intervalSec: number): Promise<void> {
  await db('snmp_targets')
    .where({ id: targetId })
    .update({
      last_discovery_at: db.fn.now(),
      next_discovery_at: db.raw("now() + (? * interval '1 second')", [intervalSec]),
      updated_at: db.fn.now(),
    });
}

/** True when this target is due for a full IF-MIB rediscovery. */
export function discoveryDue(target: SnmpTargetRow, hasInterfaces: boolean): boolean {
  if (!hasInterfaces) return true;
  if (target.next_discovery_at === null) return true;
  return target.next_discovery_at.getTime() <= Date.now();
}

/** Log a decrypted-credential failure WITHOUT the credential. */
export function logTargetProblem(resolved: ResolvedTarget, err: unknown): void {
  logger.warn(
    {
      targetId: resolved.target.id,
      deviceId: resolved.deviceId,
      err: err instanceof Error ? err.message : String(err),
    },
    'SNMP target unusable',
  );
}
