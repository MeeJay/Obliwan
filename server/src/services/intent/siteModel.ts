// ============================================================================
// ObliWAN — the resolved site model (M11 — K4)
// ============================================================================
//
// One step, and only one: take a brand-neutral `SiteIntent` and a `BrandProfile`
// and produce the same site with the BRAND'S OWN NAMES on it. `ether1` /
// `WAN1` / `ge1` / `X1`, `bridge-lan` / `LAN1` / `ge2` / `X0`, zones where the
// family has them and `null` where it does not.
//
// Everything downstream — the NCM builder and the four dialect renderers —
// reads this structure. Neither of them is allowed to call `naming.*` again or
// to re-derive a port name: two functions that both compute "the WAN interface
// name" WILL disagree eventually, and the disagreement surfaces as a device
// whose firewall rules reference an interface its addresses are not on.

import type { LanSegment, SiteIntentDocument, WanUplink } from '@obliwan/shared/dist/intent';
import { canonicalizeCidr, formatIp, parseCidr } from '@obliwan/shared';
import type { BrandProfile, NamingContext } from './brandProfiles';

export interface ResolvedWan {
  intent: WanUplink;
  /** The physical uplink port. */
  physicalName: string;
  /** Where the address actually sits: the tagged sub-interface when the
   *  operator hands off a VLAN, the physical port otherwise. */
  l3Name: string;
  /** True when `l3Name` is a tagged sub-interface of `physicalName`. */
  tagged: boolean;
  zone: string | null;
  /** Canonical `a.b.c.d/nn` with the host bits KEPT — a static uplink address
   *  says both "this subnet" and "we are this host in it". */
  address: string | null;
  gateway: string | null;
}

export interface ResolvedSegment {
  intent: LanSegment;
  index: number;
  /** The L3 interface carrying the segment. */
  ifName: string;
  zone: string | null;
  /** The box's own address in the segment, without a prefix. */
  gatewayIp: string;
  /** The segment's subnet, host bits zeroed. */
  subnet: string;
  /** Prefix length, kept so a renderer can emit a netmask without re-parsing. */
  prefix: number;
  /** Brand port names for the untagged member ports. */
  accessPorts: string[];
}

export interface ResolvedSite {
  intent: SiteIntentDocument;
  profile: BrandProfile;
  ctx: NamingContext;
  wans: ResolvedWan[];
  /** The primary uplink — `SiteIntentDocument` guarantees there is exactly one. */
  primaryWan: ResolvedWan;
  segments: ResolvedSegment[];
  /** The L2 domain the segments hang off. */
  trunkName: string;
  /**
   * True when no segment already occupies the trunk name, so the trunk is a
   * configuration object in its own right (a MikroTik `bridge` with every
   * segment tagged on top of it). False when the untagged segment IS the trunk,
   * which is the common case on all four brands.
   */
  trunkIsSeparate: boolean;
}

// ============================================================================
// The `obliwan:` marker
// ============================================================================
//
// The strongest identity mechanism in the product (see `ncm/keys.ts`): a record
// carrying `obliwan:<slug>` stays paired with its desired counterpart through a
// change of action, of selectors and of comment, so drift on what WE wrote is
// always a `changed` and never a `missing` + an `extra`.
//
// The marker is built HERE, once, and both the NCM builder and the four dialect
// renderers call it. Two functions computing "the comment of this rule"
// independently would eventually differ by a character, and a marker that
// differs by a character is a marker that does not pair.

/** `sem_key`'s `managedSlug` is `varchar(48)` and matches `[a-z0-9._-]{1,48}`.
 *  The site slug is capped so that `<site>.<record>` always fits without a
 *  truncation that could make two records share one marker. */
const MARKER_SITE_MAX = 24;
const MARKER_RECORD_MAX = 23;

/** The `managedSlug` of one compiled record: `<site>.<record>`. */
export function markerSlug(intent: SiteIntentDocument, recordId: string): string {
  const site = intent.slug.slice(0, MARKER_SITE_MAX);
  const record = recordId.slice(0, MARKER_RECORD_MAX);
  return `${site}.${record}`;
}

/** The device-side comment: `obliwan:<site>.<record>`. Identical in the NCM and
 *  in every rendered artefact, by construction. */
export function markerComment(intent: SiteIntentDocument, recordId: string): string {
  return `obliwan:${markerSlug(intent, recordId)}`;
}

/** `10.20.0.1/24` -> `{ ip: '10.20.0.1', subnet: '10.20.0.0/24', prefix: 24 }`. */
function splitHostCidr(value: string): { ip: string; subnet: string; prefix: number } {
  const parsed = parseCidr(value);
  if (!parsed) {
    // Unreachable through the API: `SiteIntentDocument` refuses anything the
    // shared parser cannot read. Kept as a throw rather than a fallback because
    // a silently invented address is how a plan targets the wrong subnet.
    throw new Error(`intent carries an unparsable address "${value}"`);
  }
  const subnet = canonicalizeCidr(value, false);
  if (!subnet) throw new Error(`intent carries an unparsable address "${value}"`);
  return {
    ip: formatIp({ version: parsed.version, bytes: parsed.bytes }),
    subnet,
    prefix: parsed.prefix,
  };
}

/** Resolve one intent against one brand. Pure; no I/O, no device, no database. */
export function resolveSite(intent: SiteIntentDocument, profile: BrandProfile): ResolvedSite {
  const ctx: NamingContext = { wanCount: intent.wan.length };
  const naming = profile.naming;

  const wans: ResolvedWan[] = intent.wan.map((w) => {
    const physicalName = naming.wan(w.uplinkIndex, ctx);
    const tagged = w.vlanId !== null;
    return {
      intent: w,
      physicalName,
      l3Name: tagged ? naming.wanVlan(w.uplinkIndex, w.vlanId as number, ctx) : physicalName,
      tagged,
      zone: naming.wanZone(),
      address: w.address ? canonicalizeCidr(w.address, true) : null,
      gateway: w.gateway,
    };
  });

  const primaryWan = wans.find((w) => w.intent.role === 'primary');
  if (!primaryWan) {
    // `SiteIntentDocument.superRefine` already rejects this; the throw exists so
    // that a hand-built object in a test cannot reach the renderers without one.
    throw new Error('intent has no primary uplink');
  }

  const segments: ResolvedSegment[] = intent.lans.map((l, index) => {
    const { ip, subnet, prefix } = splitHostCidr(l.gatewayCidr);
    return {
      intent: l,
      index,
      ifName: naming.segment(l, index, ctx),
      zone: naming.segmentZone(l, index),
      gatewayIp: ip,
      subnet,
      prefix,
      accessPorts: l.accessPorts.map((p) => naming.accessPort(p, ctx)),
    };
  });

  const trunkName = naming.lanTrunk(ctx);

  return {
    intent,
    profile,
    ctx,
    wans,
    primaryWan,
    segments,
    trunkName,
    trunkIsSeparate: !segments.some((s) => s.ifName === trunkName),
  };
}

/** The segment a publication or a zone rule points at. Throws on an unknown id,
 *  which `SiteIntentDocument` has already made unreachable through the API. */
export function segmentById(site: ResolvedSite, id: string): ResolvedSegment {
  const found = site.segments.find((s) => s.intent.id === id);
  if (!found) throw new Error(`intent references unknown segment "${id}"`);
  return found;
}

/** The uplink a publication listens on. */
export function wanById(site: ResolvedSite, id: string): ResolvedWan {
  const found = site.wans.find((w) => w.intent.id === id);
  if (!found) throw new Error(`intent references unknown uplink "${id}"`);
  return found;
}

/**
 * The zone name for one side of a zone rule. `wan` and `any` are the two
 * reserved words of the intent vocabulary; everything else is a segment id.
 * Returns `null` on a family with no zone model — which cannot happen through
 * the compiler, because `policy.zoneModel` refuses those families first.
 */
export function zoneOf(site: ResolvedSite, id: string): string | null {
  if (id === 'wan') return site.profile.naming.wanZone();
  if (id === 'any') return null;
  return segmentById(site, id).zone;
}
