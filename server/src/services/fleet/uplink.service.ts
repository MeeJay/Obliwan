/**
 * ObliWAN — "which uplink is this site ACTUALLY running on right now?"
 *
 * ┌─ THE CONFIG CANNOT ANSWER THIS, AND THAT IS THE WHOLE POINT ─────────────┐
 * │ A router can have a perfect default route through ether1 / PPPoE and be   │
 * │ passing every byte over LTE, because the PPPoE session dropped and a       │
 * │ higher-distance route took over exactly as it was designed to. The         │
 * │ failover WORKED. Nothing is broken. And nobody knows — which is the        │
 * │ expensive part, because the customer is on a metered SIM at backup speed   │
 * │ and the ticket arrives at the end of the month.                            │
 * │                                                                          │
 * │ So this reports TWO answers and never merges them:                        │
 * │                                                                          │
 * │   CONFIGURED  the default route the snapshot says should win — intent.    │
 * │   OBSERVED    the interface that is actually moving bytes — fact.         │
 * │                                                                          │
 * │ When they agree there is nothing to say. When they DISAGREE, that is the  │
 * │ finding: the site is on its backup uplink and the configuration still     │
 * │ believes otherwise. Collapsing the two into one "status" would destroy    │
 * │ precisely the signal worth having.                                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── WHY BYTES AND NOT `ifOperStatus` ────────────────────────────────────────
 * An LTE interface is usually UP all the time: the modem is registered, the
 * interface is up, and it carries nothing until the day it carries everything.
 * `operStatus` would report both uplinks up and answer nothing. Traffic is the
 * only signal that distinguishes a standby link from a working one — which is
 * also why this needs two samples and says so rather than showing a zero.
 */

import { db } from '../../db';
import { latestDocument } from '../config/snapshot.service';
import { deviceEgress, type AsnInfo } from './asn.service';

/** Below this, a link is keeping itself alive, not carrying a site. Chosen an
 *  order of magnitude above keepalives/ARP/LLDP chatter and far below any real
 *  user traffic, so the classification does not hinge on a tuned threshold. */
const IDLE_BPS = 16_000;

/** How far back to look. Long enough to survive one missed poll, short enough
 *  that "right now" means right now. */
const WINDOW_MINUTES = 15;

export type UplinkKind = 'pppoe' | 'lte' | 'wireguard' | 'ethernet' | 'other';

export interface UplinkCandidate {
  ifId: number;
  ifName: string;
  alias: string | null;
  kind: UplinkKind;
  /** IF-MIB ifOperStatus. 1 = up. */
  operStatus: number;
  /** Mean over the window. `null` = not enough samples to derive a rate. */
  inBps: number | null;
  outBps: number | null;
  samples: number;
  /** `null` when no rate could be derived — NOT `false`. */
  carrying: boolean | null;
}

export interface UplinkVerdict {
  deviceId: number;
  /** What the routing configuration says should carry traffic. */
  configured: string | null;
  /** What the counters say IS carrying traffic. */
  observed: string | null;
  /**
   * True when the site is demonstrably running on a backup link while the
   * configuration still names another. `null` = not enough evidence.
   */
  onBackup: boolean | null;
  /** One sentence an operator can act on, or ignore. */
  reason: string;
  candidates: UplinkCandidate[];
  windowMinutes: number;
  /** The public address the CONCENTRATOR saw this site dial in from, and who
   *  announces it — the outside view, see `asn.service`. Both null when the
   *  device has no tunnel or the lookup is disabled. */
  publicIp: string | null;
  /** ppp_caller = seen by the concentrator when the site dialled in (strong).
   *  dial_address = the address WE reach it on (weaker: a port forward can
   *  publish a box on an address its own traffic does not leave by). */
  publicIpSource: 'ppp_caller' | 'dial_address' | null;
  asn: AsnInfo | null;
  asnLookupEnabled: boolean;
}

/**
 * Classify by NAME and TYPE, never by position.
 *
 * "ether1 is the WAN" is true on most of this fleet and false on the one site
 * where it matters. The RouterOS interface type is the reliable half; the name
 * only breaks ties, and only for prefixes the platform itself imposes.
 */
function classify(ifName: string, ifType: number | null): UplinkKind {
  const n = ifName.toLowerCase();
  if (n.startsWith('pppoe-') || n.includes('pppoe')) return 'pppoe';
  if (n.startsWith('lte') || n.includes('lte')) return 'lte';
  if (n.startsWith('wireguard') || n.startsWith('wg')) return 'wireguard';
  // ifType 6 = ethernetCsmacd, 23 = ppp, 243 = wwanPP2 (cellular on RouterOS).
  if (ifType === 23) return 'pppoe';
  if (ifType === 243) return 'lte';
  if (ifType === 6) return 'ethernet';
  return 'other';
}

/** Only links that can plausibly be an uplink. A bridge or a LAN port moving
 *  traffic is not an answer to "which WAN are we on". */
function isUplinkCandidate(kind: UplinkKind, ifName: string): boolean {
  if (kind === 'pppoe' || kind === 'lte') return true;
  // An ethernet port is a candidate only when it is named like a WAN: on this
  // fleet that is ether1, and the alias usually says so.
  return /(^|[^a-z])(ether1|wan|ont|orange|sfp)/i.test(ifName);
}

/**
 * The configured default route's outgoing interface, from the latest snapshot.
 *
 * Lowest `distance` wins, as RouterOS decides it. A disabled route is not a
 * candidate. This is INTENT and is reported as such — it is exactly the value
 * that can be wrong while everything else is right.
 */
async function configuredUplink(deviceId: number): Promise<string | null> {
  const row = await latestDocument(deviceId).catch(() => null);
  if (!row) return null;

  const defaults = row.doc.resources.routes
    .filter((r) => r.dst === '0.0.0.0/0' && !r.disabled)
    .sort((a, b) => (a.distance ?? 1) - (b.distance ?? 1));

  // `gateway` is a selector atom: `iface:ether1-ONTOrange` names an interface
  // directly, `ip:…` names a next hop that could be reached through any of
  // them. Only the first form answers "which interface", and claiming an
  // answer from the second would be a guess dressed as a fact.
  for (const route of defaults) {
    const gw = route.gateway;
    if (typeof gw === 'string' && gw.startsWith('iface:')) return gw.slice('iface:'.length);
  }
  return null;
}

/**
 * Which uplink is carrying traffic, and what the routing says should be.
 *
 * Returns `observed: null` rather than guessing when no candidate has two
 * samples: a rate is a derivative, and the first point of a series cannot
 * produce one. Saying "no traffic" on a link nobody has measured twice yet is
 * how a healthy site is reported as down on the day it is enrolled.
 */
export async function assessUplink(
  tenantId: number,
  deviceId: number,
): Promise<UplinkVerdict | null> {
  const device = await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id');
  if (!device) return null;

  const interfaces = await db('snmp_interfaces')
    .where({ device_id: deviceId, state: 'active' })
    .select<Array<{
      id: number; if_name: string; if_alias: string | null;
      if_type: number | null; oper_status: number;
    }>>('id', 'if_name', 'if_alias', 'if_type', 'oper_status');

  const candidates: UplinkCandidate[] = [];
  for (const i of interfaces) {
    const kind = classify(i.if_name, i.if_type);
    if (!isUplinkCandidate(kind, i.if_name)) continue;

    const agg = (await db('snmp_if_samples')
      .where({ if_id: i.id })
      .where('ts', '>', db.raw(`now() - interval '${WINDOW_MINUTES} minutes'`))
      .select(
        db.raw('count(*)::int as n'),
        db.raw('avg(in_bps)::bigint as avg_in'),
        db.raw('avg(out_bps)::bigint as avg_out'),
      )
      .first()) as { n: number; avg_in: string | null; avg_out: string | null } | undefined;

    const n = agg?.n ?? 0;
    // One sample is a counter, not a rate. `null`, never 0.
    const inBps = n > 0 && agg?.avg_in != null ? Number(agg.avg_in) : null;
    const outBps = n > 0 && agg?.avg_out != null ? Number(agg.avg_out) : null;

    candidates.push({
      ifId: i.id,
      ifName: i.if_name,
      alias: i.if_alias,
      kind,
      operStatus: i.oper_status,
      inBps,
      outBps,
      samples: n,
      carrying: inBps === null || outBps === null
        ? null
        : Math.max(inBps, outBps) >= IDLE_BPS,
    });
  }

  const configured = await configuredUplink(deviceId);
  const measured = candidates.filter((c) => c.carrying !== null);
  const carrying = measured.filter((c) => c.carrying);
  // Busiest wins when several move traffic: a backup that has taken over still
  // leaves keepalives on the primary's physical port.
  carrying.sort((a, b) => Math.max(b.inBps!, b.outBps!) - Math.max(a.inBps!, a.outBps!));
  const observed = carrying[0]?.ifName ?? null;

  let onBackup: boolean | null = null;
  let reason: string;

  if (measured.length === 0) {
    reason = candidates.length === 0
      ? 'No uplink interface was recognised on this device yet. Run an SNMP discovery first.'
      : 'No uplink has two samples yet, so no rate can be derived. A throughput is a derivative: '
        + 'the first poll gives a counter, the second gives a number.';
  } else if (!observed) {
    reason = 'Every uplink is idle — under the noise floor. The site is up and passing nothing, '
      + 'which is normal out of hours and worth a look during them.';
  } else {
    const active = carrying[0];
    if (active.kind === 'lte') {
      onBackup = true;
      reason = configured && configured !== active.ifName
        ? `Traffic is on ${active.ifName} (LTE) while the default route still names `
          + `${configured}. The site has failed over to its SIM and the configuration does not `
          + 'say so — bandwidth is metered and degraded until the primary comes back.'
        : `Traffic is on ${active.ifName} (LTE). This site is running on its cellular backup.`;
    } else {
      onBackup = false;
      reason = configured && configured !== active.ifName
        ? `Traffic is on ${active.ifName}, but the default route names ${configured}. Both are `
          + 'primary-class links, so this is a routing question rather than a failover.'
        : `Traffic is on ${active.ifName}, which is what the routing says it should be.`;
    }
  }

  // The egress half is decoration: it asks a third party, and the verdict is
  // complete without it. It may never take the answer down with it.
  const egress = await deviceEgress(tenantId, deviceId).catch(() => ({
    publicIp: null, source: null as null, asn: null, lookupEnabled: false,
  }));

  return {
    deviceId,
    configured,
    observed,
    publicIp: egress.publicIp,
    publicIpSource: egress.source,
    asn: egress.asn,
    asnLookupEnabled: egress.lookupEnabled,
    onBackup,
    reason,
    candidates: candidates.sort((a, b) => a.ifName.localeCompare(b.ifName)),
    windowMinutes: WINDOW_MINUTES,
  };
}
