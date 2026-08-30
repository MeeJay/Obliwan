/**
 * The OIDs M3 reads, and nothing else.
 *
 * Kept in ONE file because the poller, the discovery and the fake agent used in
 * the bench must agree byte for byte: a typo in a column OID does not fail, it
 * returns `noSuchObject`, which the poller reads as AGENT_ERROR and which then
 * looks exactly like an unreachable device.
 *
 * Two tables matter and they are NOT interchangeable:
 *
 *   ifTable   (1.3.6.1.2.1.2.2.1)      — RFC 1213, Counter32, `ifSpeed` in bit/s
 *                                        saturating at 4.29 Gbit/s.
 *   ifXTable  (1.3.6.1.2.1.31.1.1.1)   — RFC 2233, the HC (Counter64) columns,
 *                                        `ifName`, `ifAlias` and `ifHighSpeed`
 *                                        in Mbit/s.
 *
 * An agent that answers `noSuchObject` on the ifXTable is a Counter32-only
 * agent, and study §3.2 says exactly what that costs: a Counter32 wraps in
 * 34.4 s on a saturated 1 Gbit/s link, which is LESS than one 30 s poll
 * interval. Such an interface is marked `counter_unreliable` and its rate is
 * never written — see `rateCalculator.ts`.
 */

/** MIB-II system group. Only sysUpTime is on the hot path. */
export const SYS_OID = {
  sysDescr: '1.3.6.1.2.1.1.1.0',
  sysObjectID: '1.3.6.1.2.1.1.2.0',
  /** TimeTicks, 1/100 s, wraps every 497.1 days. THE reboot signal. */
  sysUpTime: '1.3.6.1.2.1.1.3.0',
  sysName: '1.3.6.1.2.1.1.5.0',
} as const;

/** ifTable columns (the base OID, WITHOUT the trailing ifIndex). */
export const IF_TABLE = {
  ifIndex: '1.3.6.1.2.1.2.2.1.1',
  ifDescr: '1.3.6.1.2.1.2.2.1.2',
  ifType: '1.3.6.1.2.1.2.2.1.3',
  ifMtu: '1.3.6.1.2.1.2.2.1.4',
  /** bit/s, Gauge32 — saturates at 4 294 967 295. Fallback only. */
  ifSpeed: '1.3.6.1.2.1.2.2.1.5',
  ifPhysAddress: '1.3.6.1.2.1.2.2.1.6',
  ifAdminStatus: '1.3.6.1.2.1.2.2.1.7',
  ifOperStatus: '1.3.6.1.2.1.2.2.1.8',
  /** Counter32 octet counters. Used only when the HC ones are absent. */
  ifInOctets: '1.3.6.1.2.1.2.2.1.10',
  ifInUcastPkts: '1.3.6.1.2.1.2.2.1.11',
  ifInDiscards: '1.3.6.1.2.1.2.2.1.13',
  ifInErrors: '1.3.6.1.2.1.2.2.1.14',
  ifOutOctets: '1.3.6.1.2.1.2.2.1.16',
  ifOutUcastPkts: '1.3.6.1.2.1.2.2.1.17',
  ifOutDiscards: '1.3.6.1.2.1.2.2.1.19',
  ifOutErrors: '1.3.6.1.2.1.2.2.1.20',
} as const;

/** ifXTable columns (the base OID, WITHOUT the trailing ifIndex). */
export const IFX_TABLE = {
  ifName: '1.3.6.1.2.1.31.1.1.1.1',
  ifHCInOctets: '1.3.6.1.2.1.31.1.1.1.6',
  ifHCInUcastPkts: '1.3.6.1.2.1.31.1.1.1.7',
  ifHCOutOctets: '1.3.6.1.2.1.31.1.1.1.10',
  ifHCOutUcastPkts: '1.3.6.1.2.1.31.1.1.1.11',
  /** Mbit/s. Multiply by 1e6 — forgetting that is a 1 000 000x clamp bug. */
  ifHighSpeed: '1.3.6.1.2.1.31.1.1.1.15',
  ifAlias: '1.3.6.1.2.1.31.1.1.1.18',
} as const;

/** SNMPv2 notification wrapper OIDs, used by the trap receiver. */
export const TRAP_OID = {
  /** The sysUpTime varbind every v2c trap carries first. */
  sysUpTime: '1.3.6.1.2.1.1.3.0',
  /** The second varbind: WHICH trap this is. */
  snmpTrapOID: '1.3.6.1.6.3.1.1.4.1.0',
  /** Present on a v1-to-v2c proxied trap. Carries the ORIGINAL agent address,
   *  which is exactly as untrustworthy as the UDP source address (A6). */
  snmpTrapAddress: '1.3.6.1.6.3.18.1.3.0',
  snmpTrapEnterprise: '1.3.6.1.6.3.1.1.4.3.0',
} as const;

/** `<base>.<index>` — the only way an instance OID should ever be built. */
export function instance(base: string, index: number): string {
  return `${base}.${index}`;
}

/** `1.3.6.1.2.1.2.2.1.2.7` under base `1.3.6.1.2.1.2.2.1.2` -> 7. Returns null
 *  when `oid` is not a direct child of `base` (a walk that overran its table). */
export function indexOf(base: string, oid: string): number | null {
  if (!oid.startsWith(`${base}.`)) return null;
  const tail = oid.slice(base.length + 1);
  if (!/^\d+$/.test(tail)) return null;
  const n = Number.parseInt(tail, 10);
  return Number.isSafeInteger(n) ? n : null;
}
