/**
 * IF-MIB discovery.
 *
 * ┌─ THE IDENTITY RULE, WHICH IS THE WHOLE POINT OF THIS FILE ────────────────┐
 * │ An interface is identified by `(device_id, if_name)`. NEVER by ifIndex.   │
 * │                                                                          │
 * │ ifIndex is an INDEX, not a name. A reboot, a card swap, an "ip service"   │
 * │ toggle or a firmware upgrade renumbers it, and RFC 2863 explicitly allows │
 * │ that. Keying the series on it means that after one reboot the WAN         │
 * │ counters are written into the LAN's series -- silently, forever, with     │
 * │ nothing in the data ever looking wrong. That is risk R12 and it is the    │
 * │ most expensive mistake available in this subsystem.                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The consequence lives in `poller.ts`, not here: EVERY poll re-reads the name
 * at the ifIndex it is about to use and compares. Discovery is what makes that
 * comparison possible; the check itself is per-poll and must never be
 * "optimised away" (study section 3.1).
 *
 * WHICH COLUMN IS THE COHERENCE VARBIND -- derived, not stored.
 * `if_descr` is written only when the agent actually answers `ifDescr`. So:
 *
 *     if_descr IS NOT NULL  ->  poll re-reads ifDescr.<ifIndex>, expects if_descr
 *     if_descr IS NULL      ->  poll re-reads ifName.<ifIndex>,  expects if_name
 *
 * One varbind either way, no extra column, and an agent that exposes only the
 * ifXTable (some ONTs, some virtual switches) does not end up in a permanent
 * IFINDEX_REMAP loop -- which is exactly what a hard-coded `ifDescr` would
 * have produced, and it would have looked like a fleet-wide remap storm.
 *
 * A VANISHED INTERFACE IS NEVER DELETED. It becomes `state = 'vanished'`.
 * Deleting it would orphan (and, with a cascade, destroy) millions of series
 * rows -- exactly what R7 forbids -- and it would erase the history of the one
 * link somebody is asking about BECAUSE it disappeared.
 */

import type { InterfaceState } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { IF_TABLE, IFX_TABLE, indexOf, instance } from './oids';
import {
  asCounter,
  asInt,
  asText,
  type SnmpConnection,
  type SnmpVarbind,
} from '../transport/snmp.transport';
import { counterUnreliable } from './rateCalculator';
import type { SnmpInterfaceRow } from './targets';

// ============================================================================
// What the agent said
// ============================================================================

export interface DiscoveredInterface {
  ifIndex: number;
  /** The stable identity half: ifName when the agent has an ifXTable, else
   *  ifDescr, else a synthesised `if-<index>` (which is a last resort and is
   *  logged as such -- it is stable only as long as ifIndex is). */
  name: string;
  /** Only set when the agent really answered `ifDescr`. Null drives the
   *  coherence-varbind choice described in the file header. */
  descr: string | null;
  alias: string | null;
  ifType: number | null;
  /** bit/s. ifHighSpeed (Mbit/s) x 1e6 when available, else ifSpeed. */
  speedBps: bigint;
  adminStatus: number;
  operStatus: number;
  physAddress: string | null;
  /** 64 when the agent answered ifHCInOctets for THIS index. Per-interface,
   *  not per-device: an agent may advertise HC counters and still return
   *  noSuchObject on one port, and believing the device-level flag there
   *  turns every poll of that port into an AGENT_ERROR. */
  counterBits: 32 | 64;
}

export interface DiscoveryResult {
  deviceId: number;
  discovered: number;
  created: number;
  updated: number;
  remapped: number;
  vanished: number;
  interfaces: SnmpInterfaceRow[];
}

// ============================================================================
// Reading the tables
// ============================================================================

/** A walk turned into `ifIndex -> varbind`. Rows whose OID is not a direct
 *  child of the column base are dropped: an agent that overruns its own table
 *  must not inject another column's values. */
function byIndex(base: string, varbinds: SnmpVarbind[]): Map<number, SnmpVarbind> {
  const out = new Map<number, SnmpVarbind>();
  for (const vb of varbinds) {
    const idx = indexOf(base, vb.oid);
    if (idx !== null) out.set(idx, vb);
  }
  return out;
}

/** A walk that fails on an OPTIONAL column is not a failure of the discovery:
 *  the ifXTable is absent on a large share of the fleet. */
async function optionalWalk(connection: SnmpConnection, base: string): Promise<SnmpVarbind[]> {
  try {
    return await connection.walk(base);
  } catch {
    return [];
  }
}

/**
 * Read the IF-MIB. Nine walks, of which four are optional.
 *
 * `ifDescr` and `ifOperStatus` are REQUIRED: without a name there is no
 * identity, and without an operational status there is no row to write. The
 * ifXTable columns are all optional.
 */
export async function readInterfaceTable(connection: SnmpConnection): Promise<DiscoveredInterface[]> {
  const [descr, type, speed, phys, admin, oper] = await Promise.all([
    connection.walk(IF_TABLE.ifDescr),
    optionalWalk(connection, IF_TABLE.ifType),
    optionalWalk(connection, IF_TABLE.ifSpeed),
    optionalWalk(connection, IF_TABLE.ifPhysAddress),
    optionalWalk(connection, IF_TABLE.ifAdminStatus),
    connection.walk(IF_TABLE.ifOperStatus),
  ]);
  const [name, alias, highSpeed, hcIn] = await Promise.all([
    optionalWalk(connection, IFX_TABLE.ifName),
    optionalWalk(connection, IFX_TABLE.ifAlias),
    optionalWalk(connection, IFX_TABLE.ifHighSpeed),
    optionalWalk(connection, IFX_TABLE.ifHCInOctets),
  ]);

  const mDescr = byIndex(IF_TABLE.ifDescr, descr);
  const mType = byIndex(IF_TABLE.ifType, type);
  const mSpeed = byIndex(IF_TABLE.ifSpeed, speed);
  const mPhys = byIndex(IF_TABLE.ifPhysAddress, phys);
  const mAdmin = byIndex(IF_TABLE.ifAdminStatus, admin);
  const mOper = byIndex(IF_TABLE.ifOperStatus, oper);
  const mName = byIndex(IFX_TABLE.ifName, name);
  const mAlias = byIndex(IFX_TABLE.ifAlias, alias);
  const mHigh = byIndex(IFX_TABLE.ifHighSpeed, highSpeed);
  const mHcIn = byIndex(IFX_TABLE.ifHCInOctets, hcIn);

  // The union of the two index sets: an agent can expose an ifXTable row for
  // an index its ifTable no longer lists, and vice versa.
  const indices = [...new Set([...mDescr.keys(), ...mOper.keys(), ...mName.keys()])].sort(
    (a, b) => a - b,
  );

  const out: DiscoveredInterface[] = [];
  for (const ifIndex of indices) {
    const descrText = asText(mDescr.get(ifIndex));
    const nameText = asText(mName.get(ifIndex));
    const identity = nameText ?? descrText ?? `if-${ifIndex}`;

    // ifHighSpeed is in MEGABITS per second. Forgetting the 1e6 is a
    // 1 000 000x clamp error: every rate would be rejected as OVER_LINE_SPEED
    // and the interface would go permanently dark.
    const highBps = (() => {
      const mbit = asInt(mHigh.get(ifIndex));
      return mbit !== null && mbit > 0 ? BigInt(mbit) * 1_000_000n : null;
    })();
    // ifSpeed is a Gauge32 in bit/s and SATURATES at 4 294 967 295 -- a 10 G
    // port reports 4.29 G. It is a fallback, never a correction of ifHighSpeed.
    const lowBps = (() => {
      const bps = asCounter(mSpeed.get(ifIndex));
      return bps !== null && bps > 0n ? bps : null;
    })();

    out.push({
      ifIndex,
      name: identity,
      descr: descrText,
      alias: asText(mAlias.get(ifIndex)),
      ifType: asInt(mType.get(ifIndex)),
      speedBps: highBps ?? lowBps ?? 0n,
      adminStatus: asInt(mAdmin.get(ifIndex)) ?? 0,
      operStatus: asInt(mOper.get(ifIndex)) ?? 0,
      physAddress: (() => {
        const vb = mPhys.get(ifIndex);
        if (!vb || vb.missing || !vb.bytes || vb.bytes.length === 0) return null;
        return Array.from(vb.bytes)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(':');
      })(),
      counterBits: mHcIn.has(ifIndex) && !mHcIn.get(ifIndex)!.missing ? 64 : 32,
    });
  }
  return out;
}

// ============================================================================
// Reconciliation
// ============================================================================

/**
 * ifTypes that are monitored=false the day they are first seen.
 *
 * 24 = softwareLoopback, 1 = other, 53 = propVirtual. This is a DEFAULT on
 * INSERT ONLY: an operator who turns monitoring on for a loopback keeps it,
 * because the update path never touches `monitored`. Losing an operator's
 * explicit choice on the next discovery would be the worst kind of bug -- it
 * repairs itself before anybody can reproduce it.
 */
const UNMONITORED_BY_DEFAULT = new Set([24]);

/**
 * Write what was discovered.
 *
 * Three things happen here that are easy to get wrong:
 *
 *  1. AN ifIndex THAT MOVED DROPS THE BASELINE. The interface identity is
 *     unchanged (same name), but the counters now live at a different index,
 *     and the reason an index moves is almost always a reboot -- which zeroed
 *     them. Keeping the baseline would compute one delta against a
 *     pre-reboot value: a single, enormous, perfectly plausible spike. One
 *     lost sample is the correct price.
 *  2. A VANISHED INTERFACE IS FLAGGED, NEVER DELETED (see the file header),
 *     and its baseline goes with it: if it comes back, its counters restarted.
 *  3. `needs_rediscovery` IS CLEARED HERE AND NOWHERE ELSE. It is set by the
 *     poller on an IFINDEX_REMAP and it is what makes the remap self-healing:
 *     poll notices, discovery repairs, polling resumes at the next cycle.
 */
export async function reconcileInterfaces(
  deviceId: number,
  discovered: DiscoveredInterface[],
  effectivePollSec: number,
): Promise<DiscoveryResult> {
  const now = new Date();
  const existing = await db<SnmpInterfaceRow>('snmp_interfaces').where({ device_id: deviceId });
  const byName = new Map(existing.map((r) => [r.if_name, r]));

  let created = 0;
  let updated = 0;
  let remapped = 0;
  const baselinesToDrop: number[] = [];

  const seen = new Set(discovered.map((d) => d.name));
  const gone = existing.filter((r) => r.state === 'active' && !seen.has(r.if_name));

  await db.transaction(async (trx) => {
    for (const d of discovered) {
      const unreliable = counterUnreliable(d.counterBits, effectivePollSec, d.speedBps);
      const previous = byName.get(d.name);

      const common = {
        if_index: d.ifIndex,
        if_alias: d.alias,
        if_descr: d.descr,
        phys_address: d.physAddress,
        if_type: d.ifType,
        speed_bps: d.speedBps.toString(),
        admin_status: d.adminStatus,
        oper_status: d.operStatus,
        state: 'active' as InterfaceState,
        vanished_at: null,
        effective_poll_sec: effectivePollSec,
        counter_bits: d.counterBits,
        counter_unreliable: unreliable,
        needs_rediscovery: false,
        last_seen_at: now,
        updated_at: now,
      };

      if (!previous) {
        await trx('snmp_interfaces').insert({
          device_id: deviceId,
          if_name: d.name,
          monitored: !UNMONITORED_BY_DEFAULT.has(d.ifType ?? -1),
          first_seen_at: now,
          created_at: now,
          ...common,
        });
        created += 1;
        continue;
      }

      if (previous.if_index !== d.ifIndex) {
        remapped += 1;
        baselinesToDrop.push(previous.id);
        logger.warn(
          { deviceId, ifName: d.name, from: previous.if_index, to: d.ifIndex },
          'SNMP discovery: ifIndex moved (R12) — baseline dropped, one sample will be lost',
        );
      }
      // `monitored` is deliberately absent: it is the operator's column.
      await trx('snmp_interfaces').where({ id: previous.id }).update(common);
      updated += 1;
    }

    for (const row of gone) {
      await trx('snmp_interfaces').where({ id: row.id }).update({
        state: 'vanished',
        vanished_at: now,
        updated_at: now,
      });
      baselinesToDrop.push(row.id);
    }

    if (baselinesToDrop.length > 0) {
      await trx('snmp_poll_state').whereIn('if_id', baselinesToDrop).del();
    }
  });

  const interfaces = await db<SnmpInterfaceRow>('snmp_interfaces')
    .where({ device_id: deviceId, state: 'active' })
    .orderBy('if_index');

  return {
    deviceId,
    discovered: discovered.length,
    created,
    updated,
    remapped,
    vanished: gone.length,
    interfaces,
  };
}

/** Walk the agent and write the result. */
export async function discoverDevice(
  deviceId: number,
  connection: SnmpConnection,
  effectivePollSec: number,
): Promise<DiscoveryResult> {
  const discovered = await readInterfaceTable(connection);
  if (discovered.length === 0) {
    // An agent that answers but exposes no ifTable row is not the same thing
    // as an unreachable agent, and it must NOT mass-vanish the interfaces we
    // already know: a transient empty walk would flag the whole device
    // vanished and drop every baseline.
    logger.warn({ deviceId }, 'SNMP discovery returned no interface — keeping the existing set');
    const interfaces = await db<SnmpInterfaceRow>('snmp_interfaces')
      .where({ device_id: deviceId, state: 'active' })
      .orderBy('if_index');
    return { deviceId, discovered: 0, created: 0, updated: 0, remapped: 0, vanished: 0, interfaces };
  }
  return reconcileInterfaces(deviceId, discovered, effectivePollSec);
}

// ============================================================================
// The per-poll coherence varbind (R12)
// ============================================================================

/**
 * Which OID re-reads this interface's name, and what the answer must be.
 *
 * See the file header for why this is derived from `if_descr IS NULL` rather
 * than hard-coded. ONE varbind per interface per poll: 2 400 varbinds per
 * cycle at fleet size, 9 % of the poll's varbind budget, and the only thing
 * standing between a renumbered ifIndex and a permanently, invisibly wrong
 * graph.
 */
export function coherenceProbe(row: SnmpInterfaceRow): { oid: string; expected: string } {
  return row.if_descr !== null
    ? { oid: instance(IF_TABLE.ifDescr, row.if_index), expected: row.if_descr }
    : { oid: instance(IFX_TABLE.ifName, row.if_index), expected: row.if_name };
}

/** Flag interfaces whose ifIndex no longer matches, so the next cycle
 *  rediscovers before it writes anything. */
export async function flagForRediscovery(ifIds: number[]): Promise<void> {
  if (ifIds.length === 0) return;
  await db('snmp_interfaces').whereIn('id', ifIds).update({
    needs_rediscovery: true,
    updated_at: new Date(),
  });
}
