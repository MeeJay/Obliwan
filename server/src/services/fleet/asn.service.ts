/**
 * ObliWAN — who is carrying this site's traffic, according to the internet.
 *
 * ┌─ THE THIRD SIGNAL, AND THE ONLY ONE THAT IS NOT SELF-REPORTED ───────────┐
 * │ Interface counters say which port moves bytes. The routing table says     │
 * │ which port should. Both are the ROUTER's account of itself, and both can  │
 * │ be right while the site still exits through somebody else — a modem that  │
 * │ failed over internally, a PPPoE that reconnected on a different carrier,  │
 * │ an upstream that is re-routing.                                          │
 * │                                                                          │
 * │ The ASN of the public address is the outside view. If a site normally     │
 * │ leaves through AS3215 (Orange) and today leaves through a mobile ASN,     │
 * │ it is on its SIM — and that conclusion needed no counter, no snapshot and │
 * │ no agent on anybody's PC.                                                │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── WHERE THE ADDRESS COMES FROM, AND WHY THERE IS NO AGENT ─────────────────
 * `devices.wan_public_ip` is already filled from the PPP session's caller
 * address, seen BY THE CONCENTRATOR (`concentratorDiscovery`). The site tells
 * us its public address simply by dialling in, for every device behind the CHR,
 * with nothing installed anywhere. When a site fails over to LTE the tunnel
 * re-establishes from the SIM carrier's address and that column changes on its
 * own. ObliWAN is agentless (§0) and this does not change that.
 *
 * ── WHY IT IS OFF BY DEFAULT ────────────────────────────────────────────────
 * Resolving an ASN means asking somebody else. Team Cymru's DNS service is the
 * lightest way to do it — no key, no account, a TXT lookup — but it is still a
 * third party learning which public addresses this installation cares about,
 * one query per distinct customer WAN address. That is a disclosure, small but
 * real, and it is not ours to make silently on a fleet of 400 customer sites.
 * `ASN_LOOKUP_ENABLED` defaults to false and the UI says what turning it on
 * sends where.
 */

import { Resolver } from 'node:dns/promises';
import { db } from '../../db';
import { logger } from '../../utils/logger';

export interface AsnInfo {
  asn: number;
  /** Registry name, e.g. "ORANGE, FR". Never invented when the lookup is thin. */
  name: string | null;
  /** The announcing prefix, which is what actually changes on a failover. */
  prefix: string | null;
  countryCode: string | null;
}

const enabled = (process.env.ASN_LOOKUP_ENABLED ?? 'false').toLowerCase() === 'true';

/**
 * In-process cache. An ASN for a given address changes on the order of months;
 * re-asking a third party every time a page is opened would be both wasteful
 * and a louder disclosure than the one already accepted.
 */
const cache = new Map<string, { value: AsnInfo | null; at: number }>();
const TTL_MS = 6 * 60 * 60 * 1000;

/**
 * ┌─ A THIRD PARTY MAY NOT HOLD A REQUEST OPEN ──────────────────────────────┐
 * │ `dns.resolveTxt` has NO timeout by default. This lookup sits on the path  │
 * │ of a page load, so an unreachable or slow resolver does not degrade the   │
 * │ answer — it hangs the request until the reverse proxy gives up and the    │
 * │ operator sees a 502 on a screen that has nothing to do with DNS.          │
 * │                                                                          │
 * │ The ASN is DECORATION. The uplink verdict is built from counters and      │
 * │ snapshots and is complete without it. So the lookup is bounded twice —    │
 * │ the resolver's own timeout AND a hard race — and a miss returns `null`,   │
 * │ which the card already renders as "not known".                            │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
const LOOKUP_TIMEOUT_MS = 1500;

/** A dedicated resolver so the timeout is ours and not the process's. */
const resolver = new Resolver({ timeout: LOOKUP_TIMEOUT_MS, tries: 1 });

/** Belt and braces: `tries`/`timeout` bound each query, this bounds the pair. */
async function withDeadline<T>(p: Promise<T>, ms: number): Promise<T | null> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      p,
      new Promise<null>((resolve) => { timer = setTimeout(() => resolve(null), ms); }),
    ]);
  } catch {
    return null;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function reverseV4(ip: string): string | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  if (!parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return null;
  return parts.reverse().join('.');
}

/**
 * RFC 1918 and friends never have an ASN, and asking about one would leak an
 * internal address for an answer that is knowably "none".
 */
function isPublicV4(ip: string): boolean {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n))) return false;
  if (o[0] === 10 || o[0] === 127 || o[0] === 0) return false;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;
  if (o[0] === 192 && o[1] === 168) return false;
  if (o[0] === 169 && o[1] === 254) return false;
  // CGNAT: an LTE SIM very often lands here, and it HAS an ASN — the carrier's.
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true;
  return true;
}

/**
 * Look an address up, or say plainly that we did not.
 *
 * Returns `null` for "no answer", never a fabricated one. A wrong ASN on this
 * screen would claim a site had failed over when it had not.
 */
export async function lookupAsn(ip: string | null): Promise<AsnInfo | null> {
  if (!enabled || !ip) return null;
  const addr = ip.trim();
  if (!isPublicV4(addr)) return null;

  const hit = cache.get(addr);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.value;

  const rev = reverseV4(addr);
  if (!rev) return null;

  try {
    // "13335 | 1.1.1.0/24 | US | arin | 2010-07-14"
    const origin = await withDeadline(resolver.resolveTxt(`${rev}.origin.asn.cymru.com`), LOOKUP_TIMEOUT_MS);
    if (!origin) {
      // Timed out or refused. Cached as a miss so a broken resolver costs one
      // slow request per address per TTL, not one per page load.
      cache.set(addr, { value: null, at: Date.now() });
      return null;
    }
    const first = origin[0]?.join('') ?? '';
    const [asnRaw, prefix, cc] = first.split('|').map((s) => s.trim());
    const asn = Number(asnRaw.split(' ')[0]);
    if (!Number.isInteger(asn) || asn <= 0) {
      cache.set(addr, { value: null, at: Date.now() });
      return null;
    }

    let name: string | null = null;
    try {
      const desc = await withDeadline(resolver.resolveTxt(`AS${asn}.asn.cymru.com`), LOOKUP_TIMEOUT_MS);
      const parts = (desc?.[0]?.join('') ?? '').split('|').map((s) => s.trim());
      name = parts[4] || null;
    } catch {
      // A missing description is not a missing ASN. The number alone already
      // answers "did the carrier change", which is the question.
      name = null;
    }

    const value: AsnInfo = { asn, name, prefix: prefix || null, countryCode: cc || null };
    cache.set(addr, { value, at: Date.now() });
    return value;
  } catch (err) {
    logger.debug({ err, ip: addr }, 'ASN lookup failed');
    cache.set(addr, { value: null, at: Date.now() });
    return null;
  }
}

export function asnLookupEnabled(): boolean {
  return enabled;
}

/**
 * This device's public address and who announces it.
 *
 * The address is read, never probed: it is what the concentrator recorded when
 * the site dialled in. A device with no tunnel has none here, and that is
 * reported as unknown rather than filled from somewhere else — an address
 * obtained by a different route would answer a different question.
 */
export async function deviceEgress(
  tenantId: number,
  deviceId: number,
): Promise<{
  publicIp: string | null;
  /** How we know it — the UI says which, because they are not equally strong. */
  source: 'ppp_caller' | 'dial_address' | null;
  asn: AsnInfo | null;
  lookupEnabled: boolean;
}> {
  const row = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{ wan_public_ip: string | null } | undefined>(
      db.raw('host(wan_public_ip) as wan_public_ip'),
    );

  // 1. The concentrator's account of where this site dialled in from. The
  //    strongest source: it is observed from outside the site, on every
  //    reconnection, and it changes by itself the moment a failover happens.
  const fromPpp = row?.wan_public_ip ?? null;
  if (fromPpp && isPublicV4(fromPpp)) {
    return { publicIp: fromPpp, source: 'ppp_caller', asn: await lookupAsn(fromPpp), lookupEnabled: enabled };
  }

  // 2. A standalone device has no tunnel and therefore no caller address — but
  //    we reach it over the internet, so THE ADDRESS WE DIAL IS ITS PUBLIC
  //    ADDRESS, by construction. No fetch on the router, no `fetch` policy on
  //    the service account, and nothing on the customer's network talking to a
  //    third party on our behalf.
  //
  //    It is weaker than the caller address and is labelled as such: a port
  //    forward can publish a box on an address that is not the one its own
  //    traffic leaves by, so this answers "where the world reaches it" rather
  //    than "where it goes out". For a site whose uplink is the thing in
  //    question, that distinction is worth showing, not hiding.
  const dialled = await db('device_transports')
    .where({ device_id: deviceId })
    .whereNotNull('host')
    .orderBy('priority')
    .first<{ host: string } | undefined>('host');

  const host = dialled?.host?.trim() ?? null;
  if (host && isPublicV4(host)) {
    return { publicIp: host, source: 'dial_address', asn: await lookupAsn(host), lookupEnabled: enabled };
  }

  return { publicIp: null, source: null, asn: null, lookupEnabled: enabled };
}
