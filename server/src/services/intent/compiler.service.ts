// ============================================================================
// ObliWAN — the Intent Compiler (M11 — K4)
// ============================================================================
//
// ┌─ THE OUTPUT OF THIS FILE IS AN NCM DOCUMENT, NOT TEXT ────────────────────┐
// │ The dialect artefact is a BY-PRODUCT. What makes an intent worth having   │
// │ is that its output is comparable to what was OBSERVED on the box and      │
// │ applicable through the M6 path that already exists: the planner diffs NCM │
// │ against NCM, never text against text. A compiler that emitted RouterOS    │
// │ script and DrayTek CLI and stopped there would have produced four         │
// │ generators and zero of the product.                                       │
// │                                                                           │
// │ So: intent -> capability gate -> resolved site -> NcmDocument -> artefact.│
// │ The artefact is rendered from the resolved site, and then CROSS-CHECKED   │
// │ against the document (`crossCheckArtifact`), because two renderings of    │
// │ one site that disagree about an interface name is exactly the class of    │
// │ bug that only shows up on a customer's router.                            │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ EVERY SELECTOR THE COMPILER EMITS IS SINGLE-ATOM ────────────────────────┐
// │ A rule whose `srcAddress` holds three CIDRs is one NCM record and three   │
// │ device rules on brands with no address-object model, and one rule with an │
// │ address group on the others. Rather than let each renderer invent its own │
// │ expansion — and produce artefacts that no longer correspond record for    │
// │ record to the document — the COMPILER expands: one source, one rule.      │
// │ The document then maps one-to-one onto the artefact, which is what makes  │
// │ the cross-check above possible at all.                                    │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ COVERAGE, AND THE PLAN THAT DELETES A CUSTOMER'S FIREWALL ───────────────┐
// │ `coverage[kind].state === 'complete'` on the DESIRED side authorises the  │
// │ diff engine to emit `extra`, which the planner turns into a deletion. An  │
// │ intent describes what a site MUST have, not everything a box may also     │
// │ legitimately have, so the default here is `'partial'` and the claim of    │
// │ completeness is opt-in, per resource kind, through `intent.authoritative`.│
// │ This is the same lesson `render.service` learned at M5, applied before it │
// │ could be re-learned the expensive way.                                    │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ §8.2 ────────────────────────────────────────────────────────────────────┐
// │ No secret can reach this code: the intent has no field to put one in. The │
// │ NCM carries `UNAVAILABLE_SECRET` fingerprints, the artefact carries       │
// │ `<<secret:label>>` placeholders, and `assertArtefactRedacted` refuses to  │
// │ return an artefact where a credential-shaped assignment holds anything    │
// │ else. The vault -> device substitution belongs to M6 and happens in       │
// │ memory, on the push path, never here and never in a stored column.        │
// └───────────────────────────────────────────────────────────────────────────┘

import type {
  CoverageState,
  DeviceFamily,
  NcmCoverageMap,
  NcmDhcpReservation,
  NcmDhcpScope,
  NcmDocument,
  NcmFirewallRule,
  NcmInterface,
  NcmIpsecPeer,
  NcmLocalUser,
  NcmMatch,
  NcmNatRule,
  NcmQosRule,
  NcmResourceKind,
  NcmRoute,
  NcmService,
  NcmServiceName,
  NcmVlan,
  ObservedCapabilityOverrides,
  Selector,
  TransportKind,
} from '@obliwan/shared';
import {
  ANY_SELECTOR,
  EMPTY_MATCH,
  NCM_RESOURCE_KINDS,
  NCM_VERSION,
  NcmDocumentAuthored,
  SEM_KEY_GENERATION,
  UNAVAILABLE_SECRET,
  addressAtom,
  canonicalizeCidr,
  computeMatchHash,
  dhcpReservationKey,
  dhcpScopeKey,
  interfaceKey,
  ipsecPeerKey,
  localUserKey,
  ncmHash,
  normalizePortSet,
  normalizeSelector,
  orderedRuleKey,
  qosRuleKey,
  routeKey,
  serviceKey,
  sha256Hex,
  sha256Short,
  vlanKey,
} from '@obliwan/shared';
import type {
  ArtifactFormat,
  CapabilityVerdict,
  ManagedService,
  SiteIntentDocument,
} from '@obliwan/shared/dist/intent';
import { INTENT_COMPILER_VERSION, INTENT_SCHEMA_VERSION } from '@obliwan/shared/dist/intent';
import { getCapabilities } from '../drivers';
import { brandProfile } from './brandProfiles';
import { assertCapable } from './capabilityCheck';
import { renderArtifact } from './renderers';
import {
  markerComment,
  markerSlug,
  resolveSite,
  segmentById,
  wanById,
  zoneOf,
  type ResolvedSegment,
  type ResolvedSite,
} from './siteModel';

// ============================================================================
// Public shapes
// ============================================================================

export interface CompileTarget {
  deviceId: number;
  tenantId: number;
  family: DeviceFamily;
  model?: string | null;
  serial?: string | null;
  systemIdentity?: string | null;
  pppUsername?: string | null;
  osVersion?: string | null;
  /** Per-unit probe deltas from `device_capabilities.observed_overrides`. */
  observedOverrides?: ObservedCapabilityOverrides | null;
  /**
   * Test seam. `capturedAt` is excluded from `ncmHash` by design, so pinning it
   * changes nothing about identity — it exists so a golden file can be compared
   * byte for byte instead of "byte for byte except this one line".
   */
  capturedAt?: string;
}

export interface CompiledArtifact {
  format: ArtifactFormat;
  /** Redacted by construction. Safe to store, to show and to export. */
  body: string;
  sha256: string;
}

export interface IntentCompilation {
  family: DeviceFamily;
  brand: string;
  compilerVersion: number;
  schemaVersion: number;
  verdict: CapabilityVerdict;
  document: NcmDocument;
  ncmHash: string;
  artifact: CompiledArtifact;
  /** Things the operator should read but that do not block the compilation. */
  warnings: string[];
}

/** A compilation that failed for a reason that is NOT a capability gap. */
export class IntentCompilerError extends Error {
  readonly family: DeviceFamily;
  constructor(family: DeviceFamily, message: string) {
    super(`intent compilation for ${family}: ${message}`);
    this.name = 'IntentCompilerError';
    this.family = family;
  }
}

// ============================================================================
// Small vocabulary shared by the builder and the renderers
// ============================================================================

/** Default listening port of each manageable service. A brand that listens
 *  elsewhere overrides it in the intent, per service. */
export const SERVICE_DEFAULT_PORT: Readonly<Record<ManagedService, number>> = {
  ssh: 22,
  https: 443,
  winbox: 8291,
  'api-ssl': 8729,
  snmp: 161,
};

/** SNMP is the only UDP one, and getting that wrong makes a management rule
 *  that never matches — a silent lockout of the poller. */
export const SERVICE_PROTOCOL: Readonly<Record<ManagedService, 'tcp' | 'udp'>> = {
  ssh: 'tcp',
  https: 'tcp',
  winbox: 'tcp',
  'api-ssl': 'tcp',
  snmp: 'udp',
};

const ANY: Selector = ANY_SELECTOR;

function ifaceSel(name: string): Selector {
  return normalizeSelector([`iface:${name}`]);
}

function addrSel(value: string): Selector {
  return normalizeSelector([addressAtom(value)]);
}

function port(p: number): NcmMatch['dstPort'] {
  return normalizePortSet([[p, p]]);
}

function match(partial: Partial<NcmMatch>): NcmMatch {
  return { ...EMPTY_MATCH, ...partial };
}

// ============================================================================
// The builder
// ============================================================================

interface BuildState {
  site: ResolvedSite;
  via: TransportKind;
  warnings: string[];
  interfaces: NcmInterface[];
  vlans: NcmVlan[];
  routes: NcmRoute[];
  firewallRules: NcmFirewallRule[];
  natRules: NcmNatRule[];
  dhcpScopes: NcmDhcpScope[];
  ipsecPeers: NcmIpsecPeer[];
  localUsers: NcmLocalUser[];
  services: NcmService[];
  qosRules: NcmQosRule[];
  /** Per-chain ordinal counters — `ordinal` is the discriminator of §3.4 and
   *  must be dense within a chain, not global. */
  ordinals: Map<string, number>;
}

function nextOrdinal(state: BuildState, chain: string): number {
  const n = state.ordinals.get(chain) ?? 0;
  state.ordinals.set(chain, n + 1);
  return n;
}

/** The three fields every compiled record shares: it is ours, it says so, and
 *  it says so in a form `parseComment` will read back identically. */
function owned(
  state: BuildState,
  recordId: string,
  text: string | null,
): Pick<NcmInterface, 'managedBy' | 'managedSlug' | 'comment' | 'disabled' | 'via' | 'keyQuality'> {
  return {
    managedBy: 'obliwan',
    managedSlug: markerSlug(state.site.intent, recordId),
    comment: text,
    disabled: false,
    via: state.via,
    keyQuality: 'strong',
  };
}

// ── interfaces, vlans, routes ───────────────────────────────────────────────

function buildInterfaces(state: BuildState): void {
  const { site } = state;
  const seen = new Set<string>();

  // The semKey is computed HERE, from the name, rather than by a later pass:
  // a record that reaches the array without its key would only fail at the
  // final `NcmDocumentAuthored.parse`, several hundred lines away from the
  // builder that forgot it.
  //
  // The name is also the deduplication key, and it has to be: on every brand
  // except MikroTik the untagged segment IS a physical port, so the segment
  // interface and the access port resolve to one name. The FIRST record wins,
  // and the ordering below puts the richer one first on purpose.
  const push = (record: Omit<NcmInterface, 'semKey'>): void => {
    if (seen.has(record.name)) return;
    seen.add(record.name);
    state.interfaces.push({ ...record, semKey: interfaceKey(record.name) });
  };

  site.wans.forEach((w, i) => {
    const addresses =
      w.intent.mode === 'static' && w.address
        ? [{ cidr: w.address, originUnknown: false }]
        : // A DHCP or PPPoE address is STATE, not configuration. Writing one
          // into the desired document would make every reconnection a drift.
          [];

    if (w.tagged) {
      push({
        ...owned(state, `wan-w${i}-phy`, `${w.intent.id} physical uplink`),
        kind: 'interface',
        name: w.physicalName,
        type: 'ethernet',
        alias: null,
        parent: null,
        mtu: w.intent.mtu,
        addresses: [],
        lists: ['WAN'],
        zone: w.zone,
      });
      push({
        ...owned(state, `wan-w${i}`, `${w.intent.id} uplink`),
        kind: 'interface',
        name: w.l3Name,
        type: w.intent.mode === 'pppoe' ? 'pppoe' : 'vlan',
        alias: null,
        parent: w.physicalName,
        mtu: w.intent.mtu,
        addresses,
        lists: ['WAN'],
        zone: w.zone,
      });
      return;
    }

    push({
      ...owned(state, `wan-w${i}`, `${w.intent.id} uplink`),
      kind: 'interface',
      name: w.l3Name,
      type: w.intent.mode === 'pppoe' ? 'pppoe' : 'ethernet',
      alias: null,
      parent: null,
      mtu: w.intent.mtu,
      addresses,
      lists: ['WAN'],
      zone: w.zone,
    });
  });

  if (site.trunkIsSeparate) {
    push({
      ...owned(state, 'lan-trunk', 'LAN trunk'),
      kind: 'interface',
      name: site.trunkName,
      type: site.profile.trunkType,
      alias: null,
      parent: null,
      mtu: null,
      addresses: [],
      lists: ['LAN'],
      zone: null,
    });
  }

  site.segments.forEach((s, i) => {
    const isTrunk = s.ifName === site.trunkName;
    push({
      ...owned(state, `lan-s${i}`, s.intent.name),
      kind: 'interface',
      name: s.ifName,
      type: s.intent.vlanId !== null ? 'vlan' : site.profile.trunkType,
      alias: s.intent.name,
      parent: isTrunk ? null : site.trunkName,
      mtu: null,
      addresses: [{ cidr: `${s.gatewayIp}/${s.prefix}`, originUnknown: false }],
      lists: s.intent.isolated ? ['LAN', 'GUEST'] : ['LAN'],
      zone: s.zone,
    });
  });

  // Physical member ports come last so a port name that collides with a segment
  // interface (a brand where the untagged segment IS the port) keeps the richer
  // record.
  site.segments.forEach((s, i) => {
    s.accessPorts.forEach((portName, j) => {
      push({
        ...owned(state, `lan-s${i}-p${j}`, `${s.intent.name} access port`),
        kind: 'interface',
        name: portName,
        type: 'ethernet',
        alias: null,
        parent: site.trunkName,
        mtu: null,
        addresses: [],
        lists: ['LAN'],
        zone: s.zone,
      });
    });
  });

}

function buildVlans(state: BuildState): void {
  state.site.segments.forEach((s, i) => {
    if (s.intent.vlanId === null) return;
    state.vlans.push({
      ...owned(state, `vlan-s${i}`, s.intent.name),
      kind: 'vlan',
      semKey: vlanKey(state.site.trunkName, s.intent.vlanId),
      vlanId: s.intent.vlanId,
      name: s.intent.name,
      parent: state.site.trunkName,
      taggedPorts: [],
      untaggedPorts: s.accessPorts.slice().sort(),
    });
  });
}

function buildRoutes(state: BuildState): void {
  const multi = state.site.wans.length > 1;
  state.site.wans.forEach((w, i) => {
    if (w.intent.mode !== 'static' || !w.gateway) return;
    const gateway = addressAtom(w.gateway);
    state.routes.push({
      ...owned(state, `route-w${i}`, `default route via ${w.intent.id}`),
      kind: 'route',
      semKey: routeKey('main', '0.0.0.0/0', gateway),
      dst: '0.0.0.0/0',
      gateway,
      distance: w.intent.role === 'primary' ? 1 : 10,
      scope: null,
      targetScope: null,
      table: 'main',
      // Two default routes with no liveness check is a failover that never
      // fails over, which is worse than no failover at all: nobody notices.
      checkGateway: multi ? 'ping' : null,
      vrf: null,
    });
  });
}

// ── firewall ────────────────────────────────────────────────────────────────

function fw(
  state: BuildState,
  chain: NcmFirewallRule['chain'],
  recordId: string,
  text: string,
  m: NcmMatch,
  payload: Pick<NcmFirewallRule, 'action'> & Partial<Pick<NcmFirewallRule, 'log' | 'logPrefix' | 'rejectWith'>>,
): void {
  const ordinal = nextOrdinal(state, `fw:${chain}`);
  const matchHash = computeMatchHash(chain, null, m);
  const base = owned(state, recordId, text);
  state.firewallRules.push({
    ...base,
    kind: 'firewallRule',
    semKey: orderedRuleKey('firewallRule', chain, null, matchHash, ordinal, base.managedSlug),
    chain,
    chainName: null,
    match: m,
    action: payload.action,
    jumpTarget: null,
    rejectWith: payload.rejectWith ?? null,
    log: payload.log ?? false,
    logPrefix: payload.logPrefix ?? null,
    addToList: null,
    addToListTimeout: null,
    ordinal,
    matchHash,
  });
}

function buildFirewall(state: BuildState): void {
  const { site } = state;
  const policy = site.intent.policy;
  const defaultAction = policy.defaultInbound === 'reject' ? 'reject' : 'drop';

  // ── chain input ───────────────────────────────────────────────────────────
  fw(state, 'input', 'in-estab', 'established and related', match({ connectionState: ['established', 'related'] }), { action: 'accept' });
  fw(state, 'input', 'in-invalid', 'invalid connections', match({ connectionState: ['invalid'] }), { action: 'drop' });

  if (policy.allowPingFromWan) {
    site.wans.forEach((w, i) => {
      fw(state, 'input', `in-icmp-w${i}`, `ICMP from ${w.intent.id}`, match({ protocol: 'icmp', inInterface: ifaceSel(w.l3Name) }), { action: 'accept' });
    });
  }

  // Management services. One rule per allowed source, so every selector stays
  // single-atom and the artefact maps record for record onto the document.
  site.intent.management.services.forEach((svc, i) => {
    if (!svc.enabled) return;
    const p = svc.port ?? SERVICE_DEFAULT_PORT[svc.service];
    const proto = SERVICE_PROTOCOL[svc.service];
    if (svc.allowedFrom.length === 0) {
      state.warnings.push(
        `management service "${svc.service}" is reachable from ANY address — this is the first thing a Fleet Query audit will flag`,
      );
      fw(state, 'input', `in-svc${i}`, `${svc.service} from anywhere`, match({ protocol: proto, dstPort: port(p), srcAddress: ANY }), { action: 'accept' });
      return;
    }
    svc.allowedFrom.forEach((source, j) => {
      fw(state, 'input', `in-svc${i}-${j}`, `${svc.service} from ${source}`, match({ protocol: proto, dstPort: port(p), srcAddress: addrSel(source) }), { action: 'accept' });
    });
  });

  // DNS and DHCP to the box itself, from each segment that has a scope. Without
  // these two the site builds cleanly and no client can resolve anything.
  site.segments.forEach((s, i) => {
    if (!s.intent.dhcp) return;
    fw(state, 'input', `in-dns-s${i}`, `DNS/DHCP from ${s.intent.name}`, match({ protocol: 'udp', dstPort: normalizePortSet([[53, 53], [67, 67]]), inInterface: ifaceSel(s.ifName) }), { action: 'accept' });
  });

  fw(state, 'input', 'in-default', 'default inbound policy', match({}), {
    action: defaultAction,
    log: true,
    logPrefix: 'obliwan-in',
  });

  // ── chain forward ─────────────────────────────────────────────────────────
  fw(state, 'forward', 'fwd-estab', 'established and related', match({ connectionState: ['established', 'related'] }), { action: 'accept' });
  fw(state, 'forward', 'fwd-invalid', 'invalid connections', match({ connectionState: ['invalid'] }), { action: 'drop' });

  // Explicit zone policy first: it is the only part of the firewall the
  // operator wrote by hand, and everything below it is a default.
  policy.zones.forEach((rule, i) => {
    const srcZone = zoneOf(site, rule.from);
    const dstZone = zoneOf(site, rule.to);
    const ports = rule.ports.length > 0 ? normalizePortSet(rule.ports.map((p) => [p, p] as [number, number])) : null;
    fw(
      state,
      'forward',
      `fwd-z${i}`,
      rule.comment ?? `${rule.from} -> ${rule.to}`,
      match({ srcZone, dstZone, protocol: rule.protocol, dstPort: ports }),
      { action: rule.action === 'allow' ? 'accept' : 'drop' },
    );
  });

  // Publications: the forward-side accept that makes the destination NAT
  // actually reach the host.
  policy.publish.forEach((p, i) => {
    const target = segmentById(site, p.toSegment);
    const common = {
      protocol: p.protocol,
      dstAddress: addrSel(p.toAddress),
      dstPort: port(p.toPort),
      outInterface: ifaceSel(target.ifName),
      connectionNat: ['dstnat'],
      dstZone: target.zone,
    };
    if (p.fromSources.length === 0) {
      state.warnings.push(
        `publication "${p.id}" exposes ${p.toAddress}:${p.toPort} to the whole internet (no fromSources)`,
      );
      fw(state, 'forward', `fwd-p${i}`, p.comment ?? `publish ${p.id}`, match(common), { action: 'accept' });
      return;
    }
    p.fromSources.forEach((source, j) => {
      fw(state, 'forward', `fwd-p${i}-${j}`, p.comment ?? `publish ${p.id} from ${source}`, match({ ...common, srcAddress: addrSel(source) }), { action: 'accept' });
    });
  });

  // Segment-to-segment. `interSegment: 'deny'` covers every pair, so a segment
  // marked `isolated` under a deny policy adds nothing — emitting both would
  // produce two rules that select identical packets, which is the definition of
  // dead configuration and a source of pure drift noise.
  const pairs: Array<[ResolvedSegment, number, ResolvedSegment, number]> = [];
  site.segments.forEach((a, i) => {
    site.segments.forEach((b, j) => {
      if (i === j) return;
      pairs.push([a, i, b, j]);
    });
  });
  if (policy.interSegment === 'deny' && site.segments.length > 1) {
    for (const [a, i, b, j] of pairs) {
      fw(state, 'forward', `fwd-x-s${i}-s${j}`, `${a.intent.name} -> ${b.intent.name} denied`, match({ inInterface: ifaceSel(a.ifName), outInterface: ifaceSel(b.ifName), srcZone: a.zone, dstZone: b.zone }), { action: 'drop' });
    }
  } else {
    for (const [a, i, b, j] of pairs) {
      if (!a.intent.isolated && !b.intent.isolated) continue;
      fw(state, 'forward', `fwd-i-s${i}-s${j}`, `${a.intent.name} isolated from ${b.intent.name}`, match({ inInterface: ifaceSel(a.ifName), outInterface: ifaceSel(b.ifName), srcZone: a.zone, dstZone: b.zone }), { action: 'drop' });
    }
  }

  // Outbound internet, one rule per (segment, uplink) pair.
  site.segments.forEach((s, i) => {
    if (!s.intent.internetAccess) return;
    site.wans.forEach((w, j) => {
      fw(state, 'forward', `fwd-n-s${i}-w${j}`, `${s.intent.name} to ${w.intent.id}`, match({ inInterface: ifaceSel(s.ifName), outInterface: ifaceSel(w.l3Name), srcZone: s.zone, dstZone: w.zone }), { action: 'accept' });
    });
  });

  fw(state, 'forward', 'fwd-default', 'default forward policy', match({}), {
    action: defaultAction,
    log: true,
    logPrefix: 'obliwan-fwd',
  });
}

// ── nat ─────────────────────────────────────────────────────────────────────

function nat(
  state: BuildState,
  chain: NcmNatRule['chain'],
  recordId: string,
  text: string,
  m: NcmMatch,
  payload: Pick<NcmNatRule, 'action'> & Partial<Pick<NcmNatRule, 'toAddresses' | 'toPorts'>>,
): void {
  const ordinal = nextOrdinal(state, `nat:${chain}`);
  const matchHash = computeMatchHash(chain, null, m);
  const base = owned(state, recordId, text);
  state.natRules.push({
    ...base,
    kind: 'natRule',
    semKey: orderedRuleKey('natRule', chain, null, matchHash, ordinal, base.managedSlug),
    chain,
    chainName: null,
    match: m,
    action: payload.action,
    toAddresses: payload.toAddresses ?? null,
    toPorts: payload.toPorts ?? null,
    ordinal,
    matchHash,
  });
}

function buildNat(state: BuildState): void {
  const { site } = state;

  // Destination NAT first: it runs in prerouting and it is the only reason an
  // inbound packet ever reaches a LAN host.
  site.intent.policy.publish.forEach((p, i) => {
    const uplink = wanById(site, p.wan);
    const common = {
      protocol: p.protocol,
      dstPort: port(p.externalPort),
      inInterface: ifaceSel(uplink.l3Name),
      srcZone: uplink.zone,
    };
    const payload = {
      action: 'dstnat' as const,
      toAddresses: normalizeSelector([addressAtom(p.toAddress)]),
      toPorts: port(p.toPort),
    };
    if (p.fromSources.length === 0) {
      nat(state, 'prerouting', `nat-p${i}`, p.comment ?? `publish ${p.id}`, match(common), payload);
      return;
    }
    p.fromSources.forEach((source, j) => {
      nat(state, 'prerouting', `nat-p${i}-${j}`, p.comment ?? `publish ${p.id} from ${source}`, match({ ...common, srcAddress: addrSel(source) }), payload);
    });
  });

  site.segments.forEach((s, i) => {
    if (!s.intent.internetAccess) return;
    site.wans.forEach((w, j) => {
      nat(state, 'postrouting', `nat-m-s${i}-w${j}`, `${s.intent.name} out ${w.intent.id}`, match({ srcAddress: addrSel(s.subnet), outInterface: ifaceSel(w.l3Name), dstZone: w.zone }), { action: 'masquerade' });
    });
  });
}

// ── dhcp, ipsec, users, services, qos ───────────────────────────────────────

function buildDhcp(state: BuildState): void {
  state.site.segments.forEach((s, i) => {
    const dhcp = s.intent.dhcp;
    if (!dhcp) return;
    const name = `dhcp-${s.intent.id}`;
    const reservations: NcmDhcpReservation[] = dhcp.reservations
      .map((r) => ({
        semKey: dhcpReservationKey(name, r.mac),
        mac: r.mac.toLowerCase(),
        address: r.address,
        hostname: r.hostname,
        comment: markerComment(state.site.intent, `dhcp-s${i}-${r.mac.replace(/:/g, '').slice(-4)}`),
      }))
      .sort((a, b) => (a.semKey < b.semKey ? -1 : a.semKey > b.semKey ? 1 : 0));

    state.dhcpScopes.push({
      ...owned(state, `dhcp-s${i}`, `${s.intent.name} scope`),
      kind: 'dhcpScope',
      semKey: dhcpScopeKey(name),
      name,
      onInterface: `iface:${s.ifName}`,
      subnet: s.subnet,
      poolFrom: dhcp.poolFrom,
      poolTo: dhcp.poolTo,
      gateway: s.gatewayIp,
      dnsServers: dhcp.dnsServers.slice(),
      ntpServers: [],
      domain: dhcp.domain,
      leaseSeconds: dhcp.leaseSeconds,
      reservations,
      options: [],
    });
  });
}

function buildIpsec(state: BuildState): void {
  state.site.intent.vpn.forEach((v, i) => {
    const remote = v.remote.trim().toLowerCase();
    state.ipsecPeers.push({
      ...owned(state, `ipsec-v${i}`, `tunnel ${v.id}`),
      kind: 'ipsecPeer',
      semKey: ipsecPeerKey(remote, null),
      name: v.id,
      remote,
      localId: null,
      remoteId: null,
      exchangeMode: v.exchangeMode,
      authMethod: 'psk',
      // The PSK is in the vault and NEVER in the NCM. `unavailable: true` is
      // the honest encoding: the document does not carry it, and the diff must
      // not read that as "the peer has an empty key".
      pskFingerprint: UNAVAILABLE_SECRET,
      proposal: {
        encryption: v.encryption.slice().sort(),
        integrity: v.integrity.slice().sort(),
        dhGroup: v.dhGroup.slice().sort(),
        lifetimeSeconds: null,
        pfsGroup: null,
      },
      localSubnets: v.localSubnets.map((c) => canonicalizeCidr(c, false) ?? c).sort(),
      remoteSubnets: v.remoteSubnets.map((c) => canonicalizeCidr(c, false) ?? c).sort(),
      dpdSeconds: v.dpdSeconds,
      natTraversal: null,
    });
  });
}

function buildLocalUsers(state: BuildState): void {
  state.site.intent.management.localUsers.forEach((u, i) => {
    state.localUsers.push({
      ...owned(state, `user-u${i}`, `account ${u.username}`),
      kind: 'localUser',
      semKey: localUserKey(u.username),
      username: u.username,
      group: u.group,
      permissions: [],
      allowedFrom:
        u.allowedFrom.length > 0 ? normalizeSelector(u.allowedFrom.map(addressAtom)) : ANY,
      passwordFingerprint: UNAVAILABLE_SECRET,
      isVendorDefault: false,
      sshKeyFingerprints: [],
      twoFactor: null,
    });
  });
}

function buildServices(state: BuildState): void {
  const mgmt = state.site.intent.management;
  const snmpDeclared = mgmt.snmp !== null;

  mgmt.services.forEach((svc, i) => {
    // The dedicated `management.snmp` block is richer (version, community) and
    // owns `svc.v1:snmp`. Emitting both would produce two records with one
    // semKey, which the indexer would reject as a parser bug.
    if (svc.service === 'snmp' && snmpDeclared) return;
    const name = svc.service as NcmServiceName;
    state.services.push({
      ...owned(state, `svc-${i}`, svc.service),
      kind: 'service',
      semKey: serviceKey(name, null),
      service: name,
      rawName: null,
      enabled: svc.enabled,
      port: svc.port ?? SERVICE_DEFAULT_PORT[svc.service],
      allowedFrom:
        svc.allowedFrom.length > 0 ? normalizeSelector(svc.allowedFrom.map(addressAtom)) : ANY,
      tlsRequired: svc.service === 'https' || svc.service === 'api-ssl' ? true : null,
      certificate: null,
      version: null,
      communityFingerprint: null,
      communityIsWellKnown: null,
    });
  });

  if (mgmt.snmp) {
    state.services.push({
      ...owned(state, 'svc-snmp', `SNMP ${mgmt.snmp.version}`),
      kind: 'service',
      semKey: serviceKey('snmp', null),
      service: 'snmp',
      rawName: null,
      enabled: true,
      port: SERVICE_DEFAULT_PORT.snmp,
      allowedFrom:
        mgmt.snmp.allowedFrom.length > 0
          ? normalizeSelector(mgmt.snmp.allowedFrom.map(addressAtom))
          : ANY,
      tlsRequired: null,
      certificate: null,
      version: mgmt.snmp.version,
      communityFingerprint: UNAVAILABLE_SECRET,
      // We know it is NOT a well-known community precisely because we generated
      // it into the vault. The field exists for what a COLLECTOR finds on a box
      // nobody managed; on the desired side the honest answer is `false`.
      communityIsWellKnown: false,
    });
  }
}

function buildQos(state: BuildState): void {
  const qos = state.site.intent.qos;
  if (!qos) return;
  const uplink = wanById(state.site, qos.wan);

  const rootId = `qos-w-${qos.wan}`;
  const rootBase = owned(state, 'qos-wan', `${qos.wan} shaper`);
  const rootOrdinal = nextOrdinal(state, 'qos:shaper');
  state.qosRules.push({
    ...rootBase,
    kind: 'qosRule',
    semKey: qosRuleKey('shaper', rootId, null, rootOrdinal, rootBase.managedSlug),
    queueClass: 'shaper',
    name: rootId,
    target: ifaceSel(uplink.l3Name),
    match: null,
    parent: null,
    priority: null,
    maxLimitUpBps: qos.upBps,
    maxLimitDownBps: qos.downBps,
    limitAtUpBps: null,
    limitAtDownBps: null,
    queueType: null,
    ordinal: rootOrdinal,
    matchHash: null,
  });

  qos.segments.forEach((limit, i) => {
    const segment = segmentById(state.site, limit.segment);
    const name = `qos-${limit.segment}`;
    const base = owned(state, `qos-s${i}`, `${segment.intent.name} queue`);
    const ordinal = nextOrdinal(state, 'qos:simple');
    state.qosRules.push({
      ...base,
      kind: 'qosRule',
      semKey: qosRuleKey('simple', name, null, ordinal, base.managedSlug),
      queueClass: 'simple',
      name,
      target: addrSel(segment.subnet),
      match: null,
      parent: rootId,
      priority: limit.priority,
      maxLimitUpBps: limit.maxUpBps,
      maxLimitDownBps: limit.maxDownBps,
      limitAtUpBps: null,
      limitAtDownBps: null,
      queueType: null,
      ordinal,
      matchHash: null,
    });
  });
}

// ── coverage ────────────────────────────────────────────────────────────────

function buildCoverage(intent: SiteIntentDocument, counts: Record<NcmResourceKind, number>): NcmCoverageMap {
  const authoritative = new Set<NcmResourceKind>(intent.authoritative);
  const out = {} as NcmCoverageMap;
  for (const kind of NCM_RESOURCE_KINDS) {
    const recordCount = counts[kind];
    let state: CoverageState;
    let reason: string | null;
    if (authoritative.has(kind)) {
      state = 'complete';
      reason = null;
    } else if (recordCount > 0) {
      state = 'partial';
      reason = 'the intent describes the records it owns, not every record the device may hold';
    } else {
      state = 'unsupported';
      reason = 'the intent says nothing about this resource kind';
    }
    out[kind] = { state, via: null, reason, recordCount };
  }
  return out;
}

// ============================================================================
// Redaction and cross-check
// ============================================================================

/**
 * §8.2, as an assertion rather than a convention.
 *
 * Any credential-shaped assignment in a rendered artefact must hold a
 * `<<secret:…>>` placeholder and nothing else. The artefact is stored, shown in
 * the plan, exported in a bundle and written to the audit trail — it is exactly
 * the kind of column the last audit found a fleet's L2TP passwords in.
 */
const CREDENTIAL_ASSIGNMENT =
  /\b(password|passwd|passphrase|psk|pre-?shared-?key|secret|community|auth-?key|priv-?key|api-?key)\b\s*[=:]\s*"?([^\s",;}]+)/gi;

export function assertArtefactRedacted(format: ArtifactFormat, body: string): void {
  // Placeholders are collapsed FIRST. `<<secret:lyon-psk>>` is itself shaped
  // like `secret:<value>`, so scanning the raw text would make every correctly
  // redacted artefact look like a leak — a guard that cries wolf is a guard
  // somebody eventually deletes.
  const scrubbed = body.replace(/<<secret:[A-Za-z0-9._-]{1,72}>>/g, '<<SECRET>>');
  CREDENTIAL_ASSIGNMENT.lastIndex = 0;
  for (;;) {
    const m = CREDENTIAL_ASSIGNMENT.exec(scrubbed);
    if (!m) break;
    const value = m[2];
    if (value === '<<SECRET>>' || value === 'null' || value === '""') continue;
    throw new Error(
      `intent compiler produced a ${format} artefact with a plaintext ${m[1]} — refusing to return it (§8.2)`,
    );
  }
}

/**
 * The artefact and the document are two renderings of one site, checked in
 * BOTH directions.
 *
 * Outwards: every interface name, every DHCP scope name and every marker in
 * the document must appear in the artefact; if one does not, the two
 * renderings have diverged and the plan an operator approves is not the
 * change the device receives.
 *
 * Inwards: the artefact may hold no line the renderer did not emit. That is
 * the direction this function was missing, and the direction a free-text
 * field of the intent attacks — see the block at the top of the body.
 */
export function crossCheckArtifact(
  document: NcmDocument,
  body: string,
  emittedLines?: number | null,
): void {
  // ── lines in EXCESS, which the inclusion checks below cannot see ────────
  //
  // The checks that follow ask "is every record present?". They were blind
  // to the opposite question — "is anything present that no record put
  // there?" — and that is the whole of the injection an operator with
  // TEMPLATE_WRITE could perform through any free-text field: a segment
  // named `x"\n/user add name=bd group=full\n#` left every record in place
  // and added sixteen `/user add` lines the NCM never described.
  //
  // `emittedLines` is the renderer's own count of `add()` calls. If the body
  // splits into more lines than the renderer emitted, a value carried a line
  // break into the middle of a line, and the artefact says something the
  // document does not.
  if (emittedLines !== undefined && emittedLines !== null) {
    const actual = body.split('\n').length;
    if (actual !== emittedLines) {
      throw new Error(
        `the rendered artefact holds ${actual} line(s) where the renderer emitted ${emittedLines} — ` +
          'text from an intent field carried a line break into the artefact (§8.2 injection guard)',
      );
    }
  }
  // A carriage return never comes from a renderer, and on a CLI it is a line
  // terminator of its own: it would split a line the count above just agreed
  // on. Same for any other C0 control.
  const control = body.match(/[\u0000-\u0009\u000b-\u001f\u007f]/);
  if (control) {
    throw new Error(
      `the rendered artefact carries a control character (U+${control[0]
        .charCodeAt(0)
        .toString(16)
        .padStart(4, '0')
        .toUpperCase()}) — refusing to return it (§8.2 injection guard)`,
    );
  }

  const missing: string[] = [];
  for (const iface of document.resources.interfaces) {
    if (!body.includes(iface.name)) missing.push(`interface ${iface.name}`);
  }
  for (const scope of document.resources.dhcpScopes) {
    if (!body.includes(scope.name)) missing.push(`dhcp scope ${scope.name}`);
  }
  for (const rule of document.resources.firewallRules) {
    if (rule.managedSlug && !body.includes(rule.managedSlug)) {
      missing.push(`firewall marker ${rule.managedSlug}`);
    }
  }
  if (missing.length > 0) {
    throw new Error(
      `the rendered artefact does not mention ${missing.length} record(s) present in the NCM ` +
        `(${missing.slice(0, 5).join(', ')}${missing.length > 5 ? ', …' : ''}) — ` +
        'the document and the artefact have diverged',
    );
  }
}

// ============================================================================
// compileIntent
// ============================================================================

/**
 * Intent + one device family -> an NCM document and one dialect artefact.
 *
 * Order matters and is the whole design: the capability gate runs FIRST, on
 * declarative data, so a refusal costs no session, no credential and no packet.
 */
export function compileIntent(
  intent: SiteIntentDocument,
  target: CompileTarget,
): IntentCompilation {
  const verdict = assertCapable(intent, target.family, target.observedOverrides);
  const profile = brandProfile(target.family);
  if (profile.artifactFormat === null) {
    // Unreachable while the profile's support matrix stays NO_INTENT_SUPPORT —
    // `assertCapable` refuses first. It is the guard that catches the day
    // somebody turns a feature on without writing the renderer.
    throw new IntentCompilerError(
      target.family,
      'the brand profile declares no artefact format: no renderer exists for this family',
    );
  }

  const site = resolveSite(intent, profile);
  const capabilities = getCapabilities(target.family);
  const state: BuildState = {
    site,
    via: capabilities.transportPriority[0] ?? 'ssh',
    warnings: [],
    interfaces: [],
    vlans: [],
    routes: [],
    firewallRules: [],
    natRules: [],
    dhcpScopes: [],
    ipsecPeers: [],
    localUsers: [],
    services: [],
    qosRules: [],
    ordinals: new Map(),
  };

  buildInterfaces(state);
  buildVlans(state);
  buildRoutes(state);
  buildFirewall(state);
  buildNat(state);
  buildDhcp(state);
  buildIpsec(state);
  buildLocalUsers(state);
  buildServices(state);
  buildQos(state);

  const counts: Record<NcmResourceKind, number> = {
    interface: state.interfaces.length,
    vlan: state.vlans.length,
    route: state.routes.length,
    firewallRule: state.firewallRules.length,
    natRule: state.natRules.length,
    dhcpScope: state.dhcpScopes.length,
    ipsecPeer: state.ipsecPeers.length,
    localUser: state.localUsers.length,
    service: state.services.length,
    qosRule: state.qosRules.length,
  };

  const document: NcmDocument = NcmDocumentAuthored.parse({
    ncmVersion: NCM_VERSION,
    semKeyGeneration: SEM_KEY_GENERATION,
    // Not a normalization rule set: this document was AUTHORED, not collected.
    // Stamping the compiler version here means a compiler change really is a
    // different desired state, which is exactly what `normalizationEpoch`
    // encodes on the collected side.
    normalizationEpoch: sha256Short(`intent-compiler/v${INTENT_COMPILER_VERSION}`),
    capturedAt: target.capturedAt ?? new Date().toISOString(),
    device: {
      deviceId: target.deviceId,
      brand: profile.brand,
      family: target.family,
      model: target.model ?? null,
      serial: target.serial ?? null,
      systemIdentity: target.systemIdentity ?? null,
      pppUsername: target.pppUsername ?? null,
      osVersion: target.osVersion ?? null,
    },
    coverage: buildCoverage(intent, counts),
    // The compiler AUTHORED the order of every ordered chain, so the order
    // analysis is complete by construction — there is no truncation to declare.
    orderAnalysis: 'full',
    resources: {
      interfaces: state.interfaces,
      vlans: state.vlans,
      routes: state.routes,
      firewallRules: state.firewallRules,
      natRules: state.natRules,
      dhcpScopes: state.dhcpScopes,
      ipsecPeers: state.ipsecPeers,
      localUsers: state.localUsers,
      services: state.services,
      qosRules: state.qosRules,
    },
    unmodeled: [],
    extensions: {},
  });

  const rendered = renderArtifact(site, document);
  assertArtefactRedacted(rendered.format, rendered.body);
  crossCheckArtifact(document, rendered.body, rendered.emittedLines);

  return {
    family: target.family,
    brand: profile.brand,
    compilerVersion: INTENT_COMPILER_VERSION,
    schemaVersion: INTENT_SCHEMA_VERSION,
    verdict,
    document,
    ncmHash: ncmHash(document),
    artifact: {
      format: rendered.format,
      body: rendered.body,
      sha256: sha256Hex(rendered.body),
    },
    warnings: state.warnings,
  };
}

