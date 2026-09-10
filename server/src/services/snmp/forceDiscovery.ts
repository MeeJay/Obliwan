/**
 * ObliWAN — "discover this device's interfaces NOW", and what happened before.
 *
 * ┌─ WHY A BUTTON, WHEN DISCOVERY IS AUTOMATIC ──────────────────────────────┐
 * │ The poller rediscovers on its own schedule — hours apart, because a full  │
 * │ ifTable walk is expensive and interfaces do not usually move. That is the │
 * │ right default and the wrong behaviour in the one moment it matters: an    │
 * │ operator who has JUST plugged in an SFP, JUST renamed a bridge, or just   │
 * │ finished enabling SNMP on the box is standing in front of the equipment   │
 * │ and cannot wait an hour to learn whether it worked.                       │
 * │                                                                          │
 * │ Without this, the only way to find out was to wait, and waiting is        │
 * │ indistinguishable from "it silently does not work". That ambiguity is     │
 * │ what the button removes — not the walk, which happened anyway.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── THE HISTORY IS DERIVED, NOT LOGGED ──────────────────────────────────────
 * There is no `snmp_discoveries` table and there should not be one. Migration
 * 005 already records the whole story on `snmp_interfaces` itself, because an
 * interface is NEVER deleted: `first_seen_at` says when it appeared,
 * `vanished_at` when it stopped being reported, and `state` which of the two it
 * is now. A separate event log would be a second account of the same facts,
 * free to disagree with the first — and the one that disagrees is always the
 * one somebody reads.
 *
 * So "what did discovery ever find" is answered by asking the interfaces, which
 * cannot drift from themselves.
 */

import { db } from '../../db';
import { logger } from '../../utils/logger';
import { openSnmpConnection } from '../transport/snmp.transport';
import { discoverDevice } from './discovery';
import { getTargetForDevice, markDiscovered, resolveTarget, type SnmpInterfaceRow } from './targets';
import { snmpConfig } from './config';

export class DiscoveryUnavailableError extends Error {
  readonly reason: 'no_target' | 'disabled' | 'no_address' | 'no_credential';
  constructor(reason: DiscoveryUnavailableError['reason'], message: string) {
    super(message);
    this.name = 'DiscoveryUnavailableError';
    this.reason = reason;
  }
}

export interface ForcedDiscovery {
  deviceId: number;
  /** ifTable rows the agent reported. */
  discovered: number;
  created: number;
  updated: number;
  /** Interfaces whose `ifIndex` moved — R12, the reason the check exists. */
  remapped: number;
  vanished: number;
  durationMs: number;
}

/**
 * Walk the ifTable now and reconcile.
 *
 * Runs the SAME `discoverDevice` the poller runs, deliberately: a "force"
 * button that took a different code path would be testing something the fleet
 * never does, and would drift from it. The only difference is who decided it
 * was time.
 */
export async function forceDiscovery(
  tenantId: number,
  deviceId: number,
): Promise<ForcedDiscovery> {
  const device = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{ id: number } | undefined>('id');
  if (!device) throw new DiscoveryUnavailableError('no_target', 'Device not found');

  const resolved = await getTargetForDevice(deviceId);
  if (!resolved) {
    throw new DiscoveryUnavailableError(
      'no_target',
      'This device has no SNMP target. Name an SNMP credential in Settings and confirmed devices '
        + 'are given one automatically — or create one for this device alone.',
    );
  }
  if (!resolved.target.enabled) {
    throw new DiscoveryUnavailableError('disabled', 'This device\'s SNMP target is disabled.');
  }

  let dialable;
  try {
    dialable = resolveTarget(resolved);
  } catch (err) {
    // `resolveTarget` refuses on a missing address or an unusable credential,
    // and its message already names which. Forwarded rather than flattened:
    // "no address" and "no community" have different fixes.
    const message = err instanceof Error ? err.message : String(err);
    throw new DiscoveryUnavailableError(
      /address|host/i.test(message) ? 'no_address' : 'no_credential',
      message,
    );
  }

  const started = Date.now();
  const connection = openSnmpConnection(dialable);
  try {
    const result = await discoverDevice(deviceId, connection, resolved.pollIntervalSec);
    // The clock is pushed forward exactly as the poller would, so a forced run
    // does not leave the scheduled one due one second later.
    await markDiscovered(resolved.target.id, snmpConfig.discoveryIntervalSec);
    const out: ForcedDiscovery = {
      deviceId,
      discovered: result.discovered,
      created: result.created,
      updated: result.updated,
      remapped: result.remapped,
      vanished: result.vanished,
      durationMs: Date.now() - started,
    };
    logger.info(out, 'SNMP discovery forced by an operator');
    return out;
  } finally {
    connection.close?.();
  }
}

// ============================================================================
// History, read off the interfaces themselves
// ============================================================================

export interface DiscoveryHistoryEntry {
  ifName: string;
  ifDescr: string | null;
  ifIndex: number;
  state: string;
  firstSeenAt: string;
  lastSeenAt: string | null;
  vanishedAt: string | null;
  /** True while the ifIndex/name pair is under suspicion (R12). */
  needsRediscovery: boolean;
}

export interface DiscoveryHistory {
  lastDiscoveryAt: string | null;
  nextDiscoveryAt: string | null;
  activeCount: number;
  vanishedCount: number;
  entries: DiscoveryHistoryEntry[];
}

/**
 * Every interface this device has EVER reported, newest arrival first.
 *
 * Vanished rows are included and are the point: an interface that disappeared
 * is the trace of a change on the box — an SFP pulled, a bridge deleted, a
 * reboot that renumbered everything (R12). Hiding them would leave the operator
 * with a list that quietly shrank and no record of when or what.
 */
export async function discoveryHistory(
  tenantId: number,
  deviceId: number,
): Promise<DiscoveryHistory | null> {
  const target = await db('snmp_targets as t')
    .join('devices as d', 'd.id', 't.device_id')
    .where({ 't.device_id': deviceId, 'd.tenant_id': tenantId })
    .first<{ last_discovery_at: Date | null; next_discovery_at: Date | null } | undefined>(
      't.last_discovery_at', 't.next_discovery_at',
    );

  const device = await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id');
  if (!device) return null;

  const rows = await db<SnmpInterfaceRow>('snmp_interfaces')
    .where({ device_id: deviceId })
    .orderBy([{ column: 'first_seen_at', order: 'desc' }, { column: 'if_index', order: 'asc' }])
    .limit(500);

  const iso = (v: Date | string | null | undefined): string | null =>
    v == null ? null : v instanceof Date ? v.toISOString() : new Date(v).toISOString();

  return {
    lastDiscoveryAt: iso(target?.last_discovery_at),
    nextDiscoveryAt: iso(target?.next_discovery_at),
    activeCount: rows.filter((r) => r.state === 'active').length,
    vanishedCount: rows.filter((r) => r.state === 'vanished').length,
    entries: rows.map((r) => ({
      ifName: r.if_name,
      ifDescr: r.if_descr,
      ifIndex: r.if_index,
      state: r.state,
      firstSeenAt: iso(r.first_seen_at) ?? new Date(0).toISOString(),
      lastSeenAt: iso(r.last_seen_at),
      vanishedAt: iso(r.vanished_at),
      needsRediscovery: Boolean(r.needs_rediscovery),
    })),
  };
}
