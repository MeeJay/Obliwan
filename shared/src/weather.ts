// ============================================================================
// @obliwan/shared — F5, Operator Weather
// ============================================================================
//
// ONE SENTENCE: a site that falls back to LTE is a flap; twelve sites that
// leave the SAME operator inside ten minutes is that operator's outage, and
// this file is the arithmetic that separates the two.
//
// ┌─ THE DECISION THIS FILE EXISTS TO MAKE UNTAKEABLE ────────────────────────┐
// │ "OPERATOR INCIDENT" IS NEVER A CONCLUSION ABOUT ONE SITE.                 │
// │                                                                          │
// │ Everything below is built around a quorum. Not a threshold on a severity, │
// │ not a debounce on an event: a COUNT OF DISTINCT SITES that all left the   │
// │ same autonomous system inside one window, crossed with the share of that  │
// │ operator's footprint in this tenant that the count represents. One site   │
// │ can never satisfy it, whatever it does and however often it does it.      │
// │                                                                          │
// │ The cost of being wrong is asymmetric and that is the whole design brief. │
// │ A missed incident costs ten minutes of lead time on a phone call that was │
// │ going to happen anyway. A false one sends an MSP to argue with a carrier  │
// │ about an outage the carrier does not have — and the SECOND one ends the   │
// │ feature, because nobody believes the third.                              │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ SIX DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ────────────────────┐
// │                                                                           │
// │ 1. THE INCIDENT IS KEYED ON THE ASN THE SITES *LEFT*, NEVER THE ONE THEY  │
// │    ARRIVED ON. A site failing over to LTE arrives on a MOBILE operator's  │
// │    ASN; keying on arrival would file every fixed-line outage in France    │
// │    under three mobile carriers and never name the one that broke. The     │
// │    failing operator is the one whose address the site stopped using.      │
// │                                                                           │
// │ 2. SITES ARE THE UNIT, NOT DEVICES. Two routers at one site behind one    │
// │    subscription fail together and prove one thing once. Counting devices  │
// │    would let a single site with a redundant pair contribute two votes to  │
// │    a quorum of five, and a site with a stack of six reach it alone.       │
// │    `affectedSiteKeys` is a SET everywhere in this file, and its elements  │
// │    come from `lineKeyOf`: the site id when there is one, and OTHERWISE    │
// │    THE PUBLIC ADDRESS THE DEVICE EGRESSED FROM. `site_id` is nullable and │
// │    nothing populates it, so "one device, one vote" was the real behaviour │
// │    for unsited fleets — five routers behind one DSL line reached a quorum │
// │    of five on their own. Two devices leaving the same public address are  │
// │    behind the same line and share one vote.                               │
// │                                                                           │
// │ 3. TWO QUORUMS, AND BOTH MUST HOLD. An absolute one (`minSites`) because  │
// │    three sites are three sites whatever the denominator; and a relative   │
// │    one (`minFraction`) because five sites out of the four hundred a large │
// │    carrier terminates for this tenant is background noise, and paging on  │
// │    it teaches the operator to ignore the screen.                          │
// │                                                                           │
// │ 4. THE FLEET-WIDE GUARD: WHEN EVERYONE BREAKS AT ONCE, IT IS US.          │
// │    Failovers spread across many unrelated ASNs at the same instant are    │
// │    not a carrier outage — they are our concentrator, our transit, or our  │
// │    own observation post. `evaluateOperatorWeather` refuses to open ANY    │
// │    operator incident in that shape and says so out loud, because the      │
// │    worst possible output of this feature is three carriers being called   │
// │    about a fault that is in our rack.                                     │
// │                                                                           │
// │ 5. OPENING AND CLOSING ARE DELIBERATELY ASYMMETRIC, AND THE ASYMMETRY IS  │
// │    A VALIDATED INVARIANT, NOT A CONVENTION. An incident opens on the      │
// │    first evaluation whose window satisfies the quorum. It closes only     │
// │    after recovery has HELD for `holdDownMinutes`, which `validatePolicy`  │
// │    refuses to let fall below `MIN_HOLD_DOWN_RATIO x windowMinutes`. A     │
// │    carrier outage that heals in bursts would otherwise flap the incident  │
// │    open and closed six times, and six notifications about one outage is   │
// │    the same credibility loss as a false positive, spread over an hour.    │
// │                                                                           │
// │ 6. EVERY FUNCTION HERE IS PURE. No clock (`now` is an argument), no I/O,  │
// │    no database. The rule that decides whether an MSP calls a carrier has  │
// │    to be readable in one screen and testable without a fleet — and it is  │
// │    exercised offline, with no Postgres, by the F5 verification harness.   │
// └───────────────────────────────────────────────────────────────────────────┘

import { z } from 'zod';
import { parseIp } from './ncm/primitives';

// ============================================================================
// 1. Vocabularies
//
// Text + CHECK in the database, exactly like every other vocabulary in this
// schema since migration 002. Column widths are set from the LONGEST value
// below and then rounded up — a CHECK wider than its column is a constraint
// that can only ever be discovered as "value too long for type" at 2 a.m.
// ============================================================================

/**
 * How a router is getting to the internet right now.
 *
 * `other` is not a synonym for `unknown`: it means we DID resolve the active
 * egress and it is neither the designated WAN port nor a cellular interface
 * (a second fibre, a backup VDSL, a wireless bridge). `unknown` means we did
 * not resolve it, and nothing may be concluded from it.
 */
export const WAN_PATH_KINDS = ['wan_port', 'lte', 'other', 'unknown'] as const;
export type WanPathKind = (typeof WAN_PATH_KINDS)[number];

/**
 * Which way a path transition went, relative to the address the site used to
 * come from.
 *
 *   away     the site left the public address (and usually the ASN) it was on.
 *            This is the only direction that can ever contribute to a quorum.
 *   back     the site returned to the ASN it had left. This is what retires a
 *            membership and starts the hold-down.
 *   lateral  it moved to a different address WITHIN the same ASN — a DHCP
 *            renumber on the same carrier. Recorded, never counted: treating
 *            it as a failover would turn a carrier's nightly lease rotation
 *            into a nightly outage.
 */
export const WAN_EVENT_DIRECTIONS = ['away', 'back', 'lateral'] as const;
export type WanEventDirection = (typeof WAN_EVENT_DIRECTIONS)[number];

/**
 * Where a piece of weather evidence came from, most trustworthy first.
 *
 * The order is documentation here, NOT a mechanism: the precedence that
 * actually decides which public address is used is
 * `device_wan_path.effective_public_ip`, a GENERATED column reading
 * `COALESCE(observed_public_ip, reported_public_ip)`. A second ranking table in
 * TypeScript would be a rule that only applies where somebody remembered to
 * consult it, next to one the database applies unconditionally.
 *
 *   ppp_caller_id    the `caller-id` of the PPP session, as seen BY THE
 *                    CONCENTRATOR. An observation made from outside the site,
 *                    so it survives a NAT and cannot be forged by the router.
 *                    This is the primary source and it always wins.
 *   routeros_route   the active default route, read from the box through the
 *                    capability matrix (never a hard-coded menu path — R11).
 *   routeros_lte     `/interface/lte`, ditto.
 *   snmp_if_type     an IANAifType that identifies a cellular interface. The
 *                    brand-agnostic fallback: it works on a Vigor and a Zyxel,
 *                    which have no `/interface/lte` to read.
 *   device_reported  the router resolved its own public address by reaching
 *                    out. LAST RESORT, and never allowed to overwrite the
 *                    concentrator's observation — it is a DECLARATION by the
 *                    box, not an observation of it.
 */
export const WEATHER_SOURCES = [
  'ppp_caller_id',
  'routeros_route',
  'routeros_lte',
  'snmp_if_type',
  'device_reported',
] as const;
export type WeatherSource = (typeof WEATHER_SOURCES)[number];

/** Lifecycle of an operator incident. `open` -> `clearing` -> `closed`, and
 *  `clearing` -> `open` when the outage comes back before the hold-down ends. */
export const OPERATOR_INCIDENT_STATUSES = ['open', 'clearing', 'closed'] as const;
export type OperatorIncidentStatus = (typeof OPERATOR_INCIDENT_STATUSES)[number];

/** Provenance of a row in the offline ASN table. */
export const ASN_RANGE_SOURCES = ['builtin', 'import', 'manual'] as const;
export type AsnRangeSource = (typeof ASN_RANGE_SOURCES)[number];

/**
 * Socket events. F5 does not own `shared/src/socketEvents.ts` and does not
 * edit it: these names live here, next to their payload types, and are emitted
 * through the same `emitToTenant` fan-out as every other fleet event. Wire
 * format — never rename, add.
 */
export const WEATHER_SOCKET_EVENTS = {
  /** An operator incident was opened. Fires ONCE per incident, not once per
   *  affected site — that is the entire point of the feature. */
  OPERATOR_INCIDENT_OPENED: 'wan:weather:incidentOpened',
  /** More sites joined an already-open incident. */
  OPERATOR_INCIDENT_GREW: 'wan:weather:incidentGrew',
  /** Recovery observed; the hold-down has started. Not "it is over". */
  OPERATOR_INCIDENT_CLEARING: 'wan:weather:incidentClearing',
  /** The hold-down elapsed with recovery holding. Now it is over. */
  OPERATOR_INCIDENT_CLOSED: 'wan:weather:incidentClosed',
} as const;

// ============================================================================
// 2. Address scope — the offline half of the enrichment
// ============================================================================

/**
 * What kind of address this is, decided arithmetically and with no network
 * access whatsoever.
 *
 * WHY THIS IS NOT COSMETIC: a `caller-id` of `10.8.0.14` means the session
 * arrived over a private transit and carries NO information about which
 * carrier the site is using. Attributing it to an ASN would file every site of
 * an MPLS customer under one bogus operator and produce a permanent, confident,
 * completely fictional incident. `private`, `cgnat`, `loopback`, `linklocal`,
 * `multicast` and `invalid` are all refused attribution, by
 * `isAttributableAddress`, which the enrichment calls before it looks anything
 * up.
 *
 * CGNAT (100.64.0.0/10) is called out separately from `private` because it is
 * the shape a mobile fallback usually has, and an operator reading the screen
 * needs to see "your site is behind carrier-grade NAT" rather than "private".
 */
export const IP_SCOPES = [
  'public',
  'private',
  'cgnat',
  'loopback',
  'linklocal',
  'multicast',
  'invalid',
] as const;
export type IpScope = (typeof IP_SCOPES)[number];

function v4(ip: Uint8Array): number {
  return ((ip[0] << 24) >>> 0) + (ip[1] << 16) + (ip[2] << 8) + ip[3];
}

function inV4Net(addr: number, net: string, bits: number): boolean {
  const parts = net.split('.').map(Number);
  const base = ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((addr & mask) >>> 0) === ((base & mask) >>> 0);
}

/** Pure, offline, allocation-free-ish classification of a bare IP literal. */
export function classifyIpScope(raw: string | null | undefined): IpScope {
  if (!raw) return 'invalid';
  // A `caller-id` occasionally arrives with a port or a CIDR suffix attached.
  const bare = raw.trim().split('/')[0].split('%')[0];
  const parsed = parseIp(bare);
  if (!parsed) return 'invalid';

  if (parsed.version === 4) {
    const a = v4(parsed.bytes);
    if (inV4Net(a, '127.0.0.0', 8)) return 'loopback';
    if (inV4Net(a, '169.254.0.0', 16)) return 'linklocal';
    if (inV4Net(a, '100.64.0.0', 10)) return 'cgnat';
    if (
      inV4Net(a, '10.0.0.0', 8) ||
      inV4Net(a, '172.16.0.0', 12) ||
      inV4Net(a, '192.168.0.0', 16)
    ) {
      return 'private';
    }
    // 0.0.0.0/8 is "this network"; 240/4 is reserved. Neither is routable and
    // neither may be attributed to a carrier.
    if (inV4Net(a, '0.0.0.0', 8) || inV4Net(a, '240.0.0.0', 4)) return 'invalid';
    if (inV4Net(a, '224.0.0.0', 4)) return 'multicast';
    // Documentation ranges: a device that reports one of these is misconfigured
    // or lying, and either way it is not a carrier address.
    if (
      inV4Net(a, '192.0.2.0', 24) ||
      inV4Net(a, '198.51.100.0', 24) ||
      inV4Net(a, '203.0.113.0', 24)
    ) {
      return 'invalid';
    }
    return 'public';
  }

  const b = parsed.bytes;
  const allZeroButLast = b.slice(0, 15).every((x) => x === 0);
  if (allZeroButLast && b[15] === 1) return 'loopback';
  if (allZeroButLast && b[15] === 0) return 'invalid';
  if (b[0] === 0xff) return 'multicast';
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return 'linklocal';
  // fc00::/7 — unique local, the v6 spelling of RFC1918.
  if ((b[0] & 0xfe) === 0xfc) return 'private';
  // 2001:db8::/32 — documentation.
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return 'invalid';
  return 'public';
}

/**
 * May this address be attributed to a carrier at all?
 *
 * THE ONLY GATE IN FRONT OF THE ENRICHMENT. Called by `asn.service.lookupAsn`
 * before any range is consulted, so a private `caller-id` produces `null` and
 * a null ASN produces no quorum candidate anywhere downstream.
 */
export function isAttributableAddress(raw: string | null | undefined): boolean {
  return classifyIpScope(raw) === 'public';
}

// ============================================================================
// 3. Cellular identification, the brand-agnostic half
// ============================================================================

/**
 * IANAifType values that identify a cellular interface.
 *
 *   243 wwanPP   — WWAN over GSM/UMTS/LTE. What a MikroTik LTE interface,
 *                  a Vigor LTE model and a Zyxel dongle all report.
 *   244 wwanPP2  — WWAN over CDMA. Rare in Europe, free to accept.
 *
 * This is the COMPLEMENT to the RouterOS path, not a replacement: it is what
 * answers on a brand that has no `/interface/lte` to read. It is deliberately
 * a SHORT list — adding `23 (ppp)` here would classify every L2TP tunnel in
 * the fleet as a cellular uplink and manufacture a fleet-wide incident on the
 * first evaluation.
 */
export const CELLULAR_IF_TYPES: readonly number[] = [243, 244];

const CELLULAR_IF_TYPE_SET = new Set<number>(CELLULAR_IF_TYPES);

export function isCellularIfType(ifType: number | null | undefined): boolean {
  return typeof ifType === 'number' && CELLULAR_IF_TYPE_SET.has(ifType);
}

/**
 * Interface-name shapes that mean "cellular" across the four brands we drive.
 *
 * A HINT, NEVER A VERDICT ON ITS OWN. `resolveEgressPath` uses it only to
 * disambiguate an interface whose `if_type` the agent did not report (0 or
 * NULL); it never overrides a `if_type` that says otherwise, because a
 * customer is entitled to name an ethernet port `lte-backup`.
 */
const CELLULAR_NAME_RE = /^(lte|wwan|ppp-out-lte|usb-?modem|cellular|wan-lte)/i;

export function looksCellularByName(ifName: string | null | undefined): boolean {
  return typeof ifName === 'string' && CELLULAR_NAME_RE.test(ifName.trim());
}

// ============================================================================
// 4. The policy
// ============================================================================

export const weatherPolicySchema = z
  .object({
    /**
     * The correlation window. Events older than this do not contribute to a
     * quorum. Ten minutes is the direction given in §10/F5 and it is a real
     * trade-off: shorter misses a carrier whose sites drop over a quarter of
     * an hour, longer starts merging two unrelated afternoons together.
     */
    windowMinutes: z.number().int().min(1).max(240),
    /** ABSOLUTE quorum: distinct sites that must have left the same ASN. */
    minSites: z.number().int().min(2).max(1000),
    /**
     * RELATIVE quorum: the share of the sites this tenant has behind that ASN
     * which must be affected. Both quorums must hold.
     */
    minFraction: z.number().min(0).max(1),
    /**
     * Below this many still-affected sites, an open incident starts clearing.
     * Expressed as a ratio of `minSites` so the two cannot drift apart when an
     * operator tunes the quorum.
     */
    clearRatio: z.number().min(0).max(1),
    /**
     * How long recovery must HOLD before the incident closes. The asymmetry of
     * decision 5 — validated, not merely documented.
     */
    holdDownMinutes: z.number().int().min(1).max(1440),
    /**
     * Fleet-wide guard, first half: how many distinct ASNs must be flapping at
     * once before we suspect ourselves rather than the carriers.
     */
    fleetWideAsnCount: z.number().int().min(2).max(100),
    /**
     * Fleet-wide guard, second half: what share of the tenant's whole attributed
     * footprint must be moving at once for the same suspicion.
     */
    fleetWideFraction: z.number().min(0).max(1),
  })
  .strict();

export type WeatherPolicy = z.infer<typeof weatherPolicySchema>;

/**
 * `holdDownMinutes` must be at least this many times `windowMinutes`.
 *
 * THIS CONSTANT IS THE ASYMMETRY. Two is the floor, not the target: the
 * default policy sits at three. A configuration that closes an incident as
 * fast as it opens one is refused by `validateWeatherPolicy`, which the
 * settings writer and the correlator both call — a policy row that violates it
 * cannot be stored and cannot be used even if it somehow got stored.
 */
export const MIN_HOLD_DOWN_RATIO = 2;

export const DEFAULT_WEATHER_POLICY: WeatherPolicy = {
  windowMinutes: 10,
  minSites: 5,
  minFraction: 0.25,
  clearRatio: 0.5,
  // 30 minutes: three windows. Opening takes one evaluation, closing takes
  // half an hour of sustained calm.
  holdDownMinutes: 30,
  fleetWideAsnCount: 4,
  fleetWideFraction: 0.3,
};

export interface PolicyProblem {
  field: string;
  message: string;
}

/**
 * Structural validation the Zod schema cannot express, because it is about the
 * RELATIONSHIP between two fields.
 *
 * Called by `normalizeWeatherPolicy`, which is the ONLY way a policy enters
 * either the correlator or the settings table — there is no second path that
 * skips it.
 *
 * ┌─ THERE IS EXACTLY ONE RULE HERE, AND IT IS REACHABLE ─────────────────────┐
 * │ A second one used to sit below it: `clearThreshold(policy) >              │
 * │ policy.minSites` → "clearRatio must not exceed 1". It could not fire.     │
 * │ `clearThreshold` is `max(1, ceil(minSites x clearRatio))`, Zod bounds     │
 * │ `clearRatio` to [0,1] and `minSites` to >= 2, so the threshold is always  │
 * │ <= minSites and the branch was unreachable from every caller — a stated   │
 * │ invariant that no input could ever exercise, which is the shape of guard  │
 * │ this project has now paid for seven times.                                │
 * │                                                                          │
 * │ It was DELETED rather than tightened to `>=`. Tightening would outlaw     │
 * │ `clearRatio = 1`, and `clearRatio = 1` is a legitimate, handled setting:  │
 * │ it means "start the recovery clock the moment anything comes back", the   │
 * │ hold-down still governs the close, and `resumeThreshold` carries an       │
 * │ explicit `clearThreshold + 1` floor written FOR that case. Refusing it    │
 * │ here would have killed that floor — one dead branch traded for another.   │
 * │ The [0,1] bound on `clearRatio` is Zod's, it is real, and it is enough.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export function validateWeatherPolicy(policy: WeatherPolicy): PolicyProblem[] {
  const problems: PolicyProblem[] = [];
  if (policy.holdDownMinutes < policy.windowMinutes * MIN_HOLD_DOWN_RATIO) {
    problems.push({
      field: 'holdDownMinutes',
      message:
        `holdDownMinutes (${policy.holdDownMinutes}) must be at least ` +
        `${MIN_HOLD_DOWN_RATIO} x windowMinutes (${policy.windowMinutes * MIN_HOLD_DOWN_RATIO}). ` +
        'An incident must always take longer to end than it took to start: a carrier ' +
        'outage that heals in bursts would otherwise flap the alert and burn its credibility.',
    });
  }
  return problems;
}

export class WeatherPolicyError extends Error {
  readonly problems: PolicyProblem[];
  constructor(problems: PolicyProblem[]) {
    super(problems.map((p) => `${p.field}: ${p.message}`).join(' | '));
    this.name = 'WeatherPolicyError';
    this.problems = problems;
  }
}

/**
 * Parse + structurally validate an arbitrary value into a usable policy.
 *
 * `undefined` and `null` yield the default. Anything else that does not
 * validate THROWS — it is never silently coerced back to the default, because
 * "your tuned quorum was ignored and we used ours" is exactly the failure an
 * operator would not notice until the alert did not fire.
 */
export function normalizeWeatherPolicy(value: unknown): WeatherPolicy {
  if (value === undefined || value === null) return { ...DEFAULT_WEATHER_POLICY };
  const parsed = weatherPolicySchema.safeParse(value);
  if (!parsed.success) {
    throw new WeatherPolicyError(
      parsed.error.issues.map((i) => ({
        field: i.path.join('.') || '(root)',
        message: i.message,
      })),
    );
  }
  const problems = validateWeatherPolicy(parsed.data);
  if (problems.length > 0) throw new WeatherPolicyError(problems);
  return parsed.data;
}

/** How many still-affected sites keep an incident out of `clearing`. */
export function clearThreshold(policy: WeatherPolicy): number {
  return Math.max(1, Math.ceil(policy.minSites * policy.clearRatio));
}

/**
 * How many still-affected sites it takes to pull a `clearing` incident back
 * OPEN. Strictly more than `clearThreshold` — this is the hysteresis, and it
 * is the whole point of the function existing separately.
 *
 * ┌─ WHY TWO THRESHOLDS AND NOT ONE ──────────────────────────────────────────┐
 * │ A single threshold governing both directions is a Schmitt trigger with no │
 * │ gap: `remaining` is recomputed from live state every sweep, so ONE noisy  │
 * │ site sitting on the boundary drives the incident open → clearing → open   │
 * │ → clearing for as long as it keeps flapping, and every crossing is        │
 * │ another `wan:weather:incidentClearing` and another line in the operator's │
 * │ notification feed. Decision 5 of the contract says six notifications      │
 * │ about one outage costs exactly what a false positive costs; the hold-down │
 * │ CHECK only ever protected the closing edge, and nothing protected this    │
 * │ one.                                                                      │
 * │                                                                          │
 * │ The upper edge is the OPENING QUORUM: an incident is pulled back out of   │
 * │ recovery only when the evidence would have been enough to open it in the  │
 * │ first place. `clearThreshold + 1` is the floor for the degenerate         │
 * │ clearRatio = 1, where `clearThreshold` already equals `minSites` and the  │
 * │ two edges would otherwise coincide again.                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export function resumeThreshold(policy: WeatherPolicy): number {
  return Math.max(clearThreshold(policy) + 1, policy.minSites);
}

// ============================================================================
// 5. The correlation core
// ============================================================================

/**
 * A site's identity for quorum purposes.
 *
 * Decision 2: a device with no `site_id` is its own site. The negative key
 * keeps it distinct from every real site id AND from every other orphan
 * device, so it is worth one vote and merges with nothing.
 */
export function siteKeyOf(siteId: number | null, deviceId: number): number {
  return siteId ?? -deviceId;
}

/**
 * THE QUORUM'S UNIT OF ACCOUNT: one site, or failing that, one LINE.
 *
 * ┌─ WHY `siteKeyOf` IS NOT THIS FUNCTION ────────────────────────────────────┐
 * │ `devices.site_id` is nullable and nothing fills it in — not device        │
 * │ creation, not binding a discovery behind a concentrator. `siteKeyOf`      │
 * │ answers "-device_id" for those, which reads as a reasonable fallback and  │
 * │ is, for the quorum, a hole: five routers at ONE customer site, behind ONE │
 * │ line, are five distinct keys. When that single line bounces, the five     │
 * │ sessions come back on one new address and the arithmetic sees five sites  │
 * │ leaving a carrier at once — 5/5 absolute, 1.00 relative, both quorums     │
 * │ satisfied, `untakeable` taken by one flapping DSL modem.                  │
 * │                                                                          │
 * │ So: the site if we have one, otherwise the PUBLIC ADDRESS THE DEVICE      │
 * │ EGRESSED FROM. Two devices that left the same public address were behind  │
 * │ the same line and are worth one vote between them, site id or no site id. │
 * │ Only a device with neither falls back to its own identity.                │
 * │                                                                          │
 * │ The key is a STRING, and deliberately: hashing three different namespaces │
 * │ into one integer space to keep the old `number` type would have traded a  │
 * │ real collision risk for a cosmetic compatibility, and a key that reads as │
 * │ `line:185.10.1.1` in a log is a key somebody can argue with. Nothing      │
 * │ outside the correlation ever sees it — the per-event `siteKey` on the API │
 * │ is still `siteKeyOf`, which answers a different question ("which site is  │
 * │ this event about") and is unchanged.                                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * The longest value is `line:` + a full IPv6 literal — 50 characters. Any
 * column that stores one must be wider than that.
 */
export function lineKeyOf(
  siteId: number | null,
  deviceId: number,
  fromIp: string | null,
): string {
  if (siteId !== null && siteId !== undefined) return `site:${siteId}`;
  const ip = typeof fromIp === 'string' ? fromIp.trim() : '';
  if (ip.length > 0) return `line:${ip.split('/')[0].toLowerCase()}`;
  return `dev:${deviceId}`;
}

export interface AsnCandidate {
  asn: number;
  asOrg: string | null;
  /**
   * Distinct line keys (see `lineKeyOf`) that produced an `away` event inside
   * the window. Callers may pass duplicates; `evaluateOperatorWeather`
   * de-duplicates and never trusts the caller to have done it.
   */
  affectedSiteKeys: string[];
  /** Distinct sites this tenant has behind that ASN — the denominator. */
  fleetSiteCount: number;
  /** How many of the affected sites are now on a cellular path. Reporting
   *  only; it never enters the quorum. */
  onLteCount?: number;
}

export interface OpenIncidentState {
  incidentId: number;
  asn: number;
  status: Exclude<OperatorIncidentStatus, 'closed'>;
  /** ISO. Null unless `status === 'clearing'`. */
  clearingSince: string | null;
  /** Line keys (see `lineKeyOf`) still off the incident's ASN right now. */
  stillAffectedSiteKeys: string[];
  peakSiteCount: number;
}

export interface WeatherInput {
  /** ISO. Injected, never read from a clock in here. */
  now: string;
  policy: WeatherPolicy;
  /**
   * Distinct sites in this tenant for which we currently hold an attributable
   * public address. The denominator of the fleet-wide guard; a tenant we know
   * nothing about must not be able to trip it with two sites.
   */
  attributedSiteCount: number;
  candidates: AsnCandidate[];
  openIncidents: OpenIncidentState[];
}

export type WeatherAction =
  | { kind: 'open'; asn: number; asOrg: string | null; siteKeys: string[]; fleetSiteCount: number; reason: string }
  | { kind: 'grow'; incidentId: number; asn: number; siteKeys: string[]; reason: string }
  | { kind: 'start_clearing'; incidentId: number; asn: number; remaining: number; reason: string }
  | { kind: 'resume'; incidentId: number; asn: number; remaining: number; reason: string }
  /** Recovery stopped holding without reaching the re-opening quorum: restart
   *  the hold-down clock, change no status, notify nobody. */
  | { kind: 'extend_hold_down'; incidentId: number; asn: number; remaining: number; reason: string }
  | { kind: 'close'; incidentId: number; asn: number; reason: string };

export interface AsnWeather {
  asn: number;
  asOrg: string | null;
  affectedSites: number;
  fleetSiteCount: number;
  fraction: number;
  /** How many of the affected sites are currently on a cellular path. Reported,
   *  never counted: the quorum is about LEAVING a carrier, and a site that left
   *  it for a second fibre proves the same thing as one that left it for LTE. */
  onLte: number;
  quorumMet: boolean;
  /** Machine-readable, and it is what the API returns so an operator can see
   *  WHY a near-miss did not page anybody. */
  reason: string;
}

export interface WeatherEvaluation {
  /** True when the shape says the fault is ours, not a carrier's. */
  fleetWide: boolean;
  fleetWideReason: string | null;
  actions: WeatherAction[];
  asns: AsnWeather[];
}

function uniq(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function minutesBetween(fromIso: string, toIso: string): number {
  return (Date.parse(toIso) - Date.parse(fromIso)) / 60_000;
}

/**
 * Does this candidate reach quorum? BOTH gates, always, in this order.
 *
 * Returns the reason whether or not it passed: the near-miss is the number an
 * operator most wants to see, and hiding it is how a quorum gets tuned by
 * guesswork.
 */
export function quorumFor(
  candidate: AsnCandidate,
  policy: WeatherPolicy,
): { met: boolean; reason: string; affected: number; fraction: number } {
  const affected = uniq(candidate.affectedSiteKeys).length;
  const denominator = Math.max(candidate.fleetSiteCount, affected);
  const fraction = denominator > 0 ? affected / denominator : 0;

  if (affected < policy.minSites) {
    return {
      met: false,
      reason: `below_absolute_quorum:${affected}/${policy.minSites}`,
      affected,
      fraction,
    };
  }
  if (fraction < policy.minFraction) {
    return {
      met: false,
      reason: `below_relative_quorum:${fraction.toFixed(2)}/${policy.minFraction}`,
      affected,
      fraction,
    };
  }
  return {
    met: true,
    reason: `quorum:${affected}/${policy.minSites}_sites,${fraction.toFixed(2)}/${policy.minFraction}_of_asn`,
    affected,
    fraction,
  };
}

/**
 * THE function. Pure, total, and the only place an operator incident is ever
 * decided to exist.
 *
 * Order of business, and it matters:
 *   1. the fleet-wide guard runs FIRST and can veto every opening;
 *   2. existing incidents are aged (clear / resume / close) whatever the guard
 *      said, because an incident that already exists must still be able to end
 *      even during a fleet-wide event;
 *   3. new incidents open last, and only for ASNs with no live incident — the
 *      "one alert, not twelve" property, which the database enforces a second
 *      time with a partial unique index on (tenant_id, asn) WHERE status <>
 *      'closed'.
 */
export function evaluateOperatorWeather(input: WeatherInput): WeatherEvaluation {
  const { policy, now } = input;
  const actions: WeatherAction[] = [];

  // -- 1. the fleet-wide guard --------------------------------------------
  const movingAsns = input.candidates.filter((c) => uniq(c.affectedSiteKeys).length > 0);
  const movingSites = uniq(movingAsns.flatMap((c) => c.affectedSiteKeys)).length;
  const movingShare =
    input.attributedSiteCount > 0 ? movingSites / input.attributedSiteCount : 0;
  const fleetWide =
    movingAsns.length >= policy.fleetWideAsnCount &&
    movingShare >= policy.fleetWideFraction;
  const fleetWideReason = fleetWide
    ? `fleet_wide:${movingAsns.length}_asns,${movingSites}/${input.attributedSiteCount}_sites — ` +
      'failovers spread across unrelated operators at once are ours, not theirs'
    : null;

  // -- 2. age the incidents that already exist -----------------------------
  //
  // TWO EDGES, NOT ONE. `threshold` takes an incident DOWN into `clearing`;
  // `resume` takes it back UP, and it is strictly higher. With a single edge,
  // `remaining` — recomputed from live state every two minutes — put one noisy
  // site in charge of the incident's status: four round trips of ONE router
  // produced four `resume`s and four more `start_clearing`s, i.e. five
  // `wan:weather:incidentClearing` notifications for one outage, unbounded.
  // See `resumeThreshold`.
  const threshold = clearThreshold(policy);
  const resumeAt = resumeThreshold(policy);
  const live = new Set<number>();
  for (const incident of input.openIncidents) {
    live.add(incident.asn);
    const remaining = uniq(incident.stillAffectedSiteKeys).length;

    if (incident.status === 'open') {
      if (remaining >= threshold) {
        // Still going. Grow it if the window brought new sites in.
        const candidate = input.candidates.find((c) => c.asn === incident.asn);
        const fresh = candidate ? uniq(candidate.affectedSiteKeys) : [];
        if (fresh.length > incident.peakSiteCount) {
          actions.push({
            kind: 'grow',
            incidentId: incident.incidentId,
            asn: incident.asn,
            siteKeys: fresh,
            reason: `grew:${fresh.length}_sites`,
          });
        }
      } else {
        actions.push({
          kind: 'start_clearing',
          incidentId: incident.incidentId,
          asn: incident.asn,
          remaining,
          reason: `recovering:${remaining}<${threshold}_hold_down_${policy.holdDownMinutes}m`,
        });
      }
      continue;
    }

    // status === 'clearing'
    if (remaining >= resumeAt) {
      actions.push({
        kind: 'resume',
        incidentId: incident.incidentId,
        asn: incident.asn,
        remaining,
        reason: `relapsed:${remaining}>=${resumeAt}`,
      });
      continue;
    }
    // BETWEEN THE TWO EDGES. Not a relapse — it does not reach the quorum that
    // would open an incident — but not recovery holding either. The incident
    // stays `clearing` and says nothing, and the hold-down clock RESTARTS:
    // closing is a statement that recovery held for `holdDownMinutes`, and it
    // did not. Silent by construction — this is the action that exists so that
    // "restart the clock" does not have to borrow `start_clearing` and page
    // somebody a second time about an incident that never left `clearing`.
    if (remaining >= threshold) {
      actions.push({
        kind: 'extend_hold_down',
        incidentId: incident.incidentId,
        asn: incident.asn,
        remaining,
        reason: `recovery_not_holding:${threshold}<=${remaining}<${resumeAt}`,
      });
      continue;
    }
    // A `clearing` incident with no `clearingSince` is a corrupted row, not a
    // reason to close: refuse to close and let it re-enter clearing next pass.
    if (!incident.clearingSince) continue;
    const held = minutesBetween(incident.clearingSince, now);
    if (held >= policy.holdDownMinutes) {
      actions.push({
        kind: 'close',
        incidentId: incident.incidentId,
        asn: incident.asn,
        reason: `held_${Math.round(held)}m>=${policy.holdDownMinutes}m`,
      });
    }
  }

  // -- 3. open what deserves opening ---------------------------------------
  const asns: AsnWeather[] = [];
  for (const candidate of input.candidates) {
    const q = quorumFor(candidate, policy);
    let reason = q.reason;

    if (q.met && live.has(candidate.asn)) {
      reason = 'already_open';
    } else if (q.met && fleetWide) {
      reason = fleetWideReason ?? 'fleet_wide';
    } else if (q.met) {
      actions.push({
        kind: 'open',
        asn: candidate.asn,
        asOrg: candidate.asOrg,
        siteKeys: uniq(candidate.affectedSiteKeys),
        fleetSiteCount: candidate.fleetSiteCount,
        reason: q.reason,
      });
    }

    asns.push({
      asn: candidate.asn,
      asOrg: candidate.asOrg,
      affectedSites: q.affected,
      fleetSiteCount: candidate.fleetSiteCount,
      fraction: Math.round(q.fraction * 100) / 100,
      onLte: candidate.onLteCount ?? 0,
      quorumMet: q.met && !fleetWide && !live.has(candidate.asn),
      reason,
    });
  }

  asns.sort((a, b) => b.affectedSites - a.affectedSites || a.asn - b.asn);
  return { fleetWide, fleetWideReason, actions, asns };
}

// ============================================================================
// 6. Read models
// ============================================================================

export interface DeviceWanPath {
  deviceId: number;
  siteId: number | null;
  deviceName: string;
  pathKind: WanPathKind;
  egressInterface: string | null;
  /** COALESCE(concentrator observation, router self-report) — a generated
   *  column, so the precedence is a property of the schema. */
  publicIp: string | null;
  /** True when `publicIp` came from the concentrator rather than the router. */
  publicIpObserved: boolean;
  ipScope: IpScope;
  asn: number | null;
  asOrg: string | null;
  country: string | null;
  region: string | null;
  source: WeatherSource;
  observedAt: string;
}

export interface OperatorIncidentSummary {
  id: number;
  asn: number;
  asOrg: string | null;
  status: OperatorIncidentStatus;
  openedAt: string;
  clearingSince: string | null;
  closedAt: string | null;
  currentSiteCount: number;
  peakSiteCount: number;
  fleetSiteCount: number;
  openReason: string | null;
  closeReason: string | null;
}

export interface OperatorIncidentMemberView {
  deviceId: number;
  siteId: number | null;
  deviceName: string;
  siteName: string | null;
  joinedAt: string;
  recoveredAt: string | null;
  fromPathKind: WanPathKind;
  toPathKind: WanPathKind;
}

export interface OperatorIncidentDetail extends OperatorIncidentSummary {
  policy: WeatherPolicy;
  members: OperatorIncidentMemberView[];
}

export interface WeatherReport {
  generatedAt: string;
  policy: WeatherPolicy;
  fleetWide: boolean;
  fleetWideReason: string | null;
  attributedSiteCount: number;
  /**
   * ┌─ THE COVERAGE BLOCK: HOW MUCH OF THE QUORUM RESTS ON A FALLBACK ────────┐
   * │ `devices.site_id` is nullable and NOTHING fills it in — not device      │
   * │ creation, not `bindDiscovery()` when a router is adopted behind a       │
   * │ concentrator. So the quorum unit is `lineKeyOf()`: the site when there  │
   * │ is one, ELSE the public address the device egresses from, ELSE the      │
   * │ device itself. Those three cases are not equally trustworthy, and a     │
   * │ single "devices with no site" number could not tell them apart.         │
   * │                                                                         │
   * │ It also had no denominator. "Nine routers have no site" means one thing │
   * │ in a fleet of ten and another in a fleet of nine hundred, and the       │
   * │ number an operator has to act on is the ratio.                          │
   * │                                                                         │
   * │ THE INVARIANT, which the harness asserts:                               │
   * │   unsitedDeviceCount = unsitedGroupedByLineCount                        │
   * │                      + unsitedUngroupedDeviceCount                      │
   * │ and every count excludes concentrators, which are infrastructure and    │
   * │ never vote.                                                             │
   * └─────────────────────────────────────────────────────────────────────────┘
   */
  /** Non-concentrator devices in this tenant. THE DENOMINATOR of everything
   *  below; without it the other counts are unreadable. */
  deviceCount: number;
  /**
   * Non-concentrator devices with NO `site_id`. A COVERAGE WARNING, not a
   * statistic: none of them is counted as a site. See the two counts below,
   * which split this one into the case that is safe and the case that is not.
   */
  unsitedDeviceCount: number;
  /**
   * Of those, the ones grouped by the public address they egress from — the
   * fallback WORKING. Five routers behind one line are one line and one vote,
   * which is the whole point of `lineKeyOf`. Still a fallback, and it has two
   * known edges: two genuinely distinct sites behind one carrier NAT are
   * merged into one vote, and two routers at one site on two different lines
   * stay two votes.
   */
  unsitedGroupedByLineCount: number;
  /**
   * Of those, the ones with NO attributable egress address either — no
   * `effective_public_ip` on `device_wan_path`. These fall to `dev:<id>` and
   * are worth ONE VOTE EACH, which is exactly the collapse migration 022
   * exists to prevent. THIS is the number that can manufacture a quorum, and
   * it is the one a non-zero value must be acted on.
   */
  unsitedUngroupedDeviceCount: number;
  /**
   * Of the unsited devices, those bound to a concentrator.
   *
   * The ACTIONABLE subset, and the reason it is reported rather than enforced.
   * Requiring a `site_id` on every device behind a concentrator was considered
   * as a database CHECK and REFUSED: the only writer that binds one is
   * `fleet/concentratorDiscovery.bindDiscovery()`, and a PPPoE discovery
   * learns a username, a tunnel address and a caller-id — never a site. The
   * constraint would turn every adoption into a failed UPDATE with no code
   * path anywhere able to supply the missing value, and `tsc` would have
   * nothing to say about it. So the invariant is reported here, on the screen
   * that depends on it, instead of being enforced where it cannot be met.
   */
  unsitedBehindConcentratorCount: number;
  asns: AsnWeather[];
  incidents: OperatorIncidentSummary[];
}
