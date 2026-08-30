// ============================================================================
// M12 / K8 — step 1: cutting a configuration into atomic facts
// ============================================================================
//
// A fact is `(slot, value)`. The slot is WHERE, expressed so that the same
// place at two different sites produces the same string; the value is WHAT,
// verbatim. Decision 2 of `shared/src/baseline.ts` rests entirely on that
// split: alignment happens on the slot, and a slot whose value differs between
// two sites at the same place IS a variable. Nothing downstream has to guess.
//
// ┌─ FIVE RULES THIS FILE ENFORCES ───────────────────────────────────────────┐
// │                                                                           │
// │ 1. NO FACT FROM A SECTION WE DID NOT FULLY READ. A `coverage` of          │
// │    'failed' or 'unsupported' means we do not know what is there, and a    │
// │    baseline mined from a failed firewall collection says "this site has   │
// │    no firewall" — which becomes a template that proposes to create one    │
// │    from scratch at 30 sites. This is N3 of the NCM contract               │
// │    (`mayEmitMissing`) applied to mining instead of to diffing, and it is  │
// │    the same accident it exists to prevent.                                │
// │                                                                           │
// │ 2. ABSENCE IS EXPRESSED BY THE ABSENCE OF THE FACT. A null attribute      │
// │    emits nothing at all rather than a `null` token. It is what makes      │
// │    `missing` and `extra` mean something later, and it stops "unset" and   │
// │    "set to empty" from hashing the same.                                  │
// │                                                                           │
// │ 3. THE SECRET REFUSAL IS CALLED ON EVERY ATTRIBUTE, NOT ON A LIST OF      │
// │    ATTRIBUTES SOMEBODY REMEMBERED. `emit()` is the ONLY way a fact is     │
// │    created in this file, and it calls `isForbiddenBaselineAttribute`      │
// │    every time. Adding an eleventh resource kind therefore cannot          │
// │    accidentally leak `pskFingerprint` — the guard is on the funnel, not   │
// │    on the callers.                                                        │
// │                                                                           │
// │ 4. A COMMENT IS NOT A FACT. `comment`, `alias` and `managedSlug` are free │
// │    text an operator typed on a Tuesday. Mining them produces a variable   │
// │    per site for every single resource and drowns the real signal — R3     │
// │    ("drift bruyant tue l'outil") in the shape of a template.              │
// │                                                                           │
// │ 5. RULE ORDER IS NOT MINED. Two sites with one extra rule near the top    │
// │    would report every subsequent ordinal as a deviation, which is a       │
// │    hundred findings for one difference. Order is the drift engine's       │
// │    business (§4.3 of the NCM contract, `buildOrderSignature`); what this  │
// │    file mines from a chain is its POPULATION and its rules' shapes. Said  │
// │    plainly rather than left to be discovered: a baseline template does    │
// │    not pin firewall rule order, and it must not be read as if it did.     │
// └───────────────────────────────────────────────────────────────────────────┘

import {
  canonicalJson, coverageOf, sha256Short,
  type NcmDocument, type NcmMatch, type NcmResourceKind,
} from '@obliwan/shared';
import {
  classifyBaselineValue, generalizeBaselineValue, isForbiddenBaselineAttribute,
  type BaselineFact,
} from '@obliwan/shared/dist/baseline';

/** What the miner needs to know about one device to align it with the others. */
export interface DeviceFacts {
  deviceId: number;
  snapshotId: number;
  facts: BaselineFact[];
  /** Distinct slots — the clustering input. */
  slots: Set<string>;
  /** Resource kinds skipped because coverage was 'failed' or 'unsupported'.
   *  Surfaced on the run so a thin baseline is explainable rather than
   *  mysterious. */
  skippedSections: NcmResourceKind[];
  /** Attributes the secret refusal rejected. Should always be empty — a
   *  non-empty value means a parser started emitting credential material and
   *  the miner caught it. Counted, never printed with its value. */
  refusedAttributes: number;
}

// ============================================================================
// The funnel
// ============================================================================

class FactSink {
  readonly facts: BaselineFact[] = [];
  refused = 0;

  /**
   * Rule 2 and rule 3 live here, and this is the only constructor of a fact.
   * `value` of `null`/`undefined`/`''` after serialisation emits nothing.
   */
  emit(
    section: NcmResourceKind,
    discriminator: string,
    attribute: string,
    value: string | number | boolean | null | undefined,
  ): void {
    if (isForbiddenBaselineAttribute(attribute)) { this.refused++; return; }
    if (value === null || value === undefined) return;
    const text = typeof value === 'string' ? value : String(value);
    if (text === '') return;

    const slot = `${section}/${discriminator}/${attribute}`;
    // A duplicate slot inside ONE document is what makes a slot 'divergent'
    // downstream. It is kept, not deduplicated, precisely so the alignment can
    // see it and refuse to template it.
    this.facts.push({
      slot,
      section,
      value: text,
      klass: classifyBaselineValue(text),
    });
  }

  emitList(
    section: NcmResourceKind,
    discriminator: string,
    attribute: string,
    values: readonly string[] | null | undefined,
  ): void {
    if (!values || values.length === 0) return;
    this.emit(section, discriminator, attribute, [...values].sort().join(' '));
  }

  emitPorts(
    section: NcmResourceKind,
    discriminator: string,
    attribute: string,
    ports: readonly (readonly [number, number])[] | null | undefined,
  ): void {
    if (!ports || ports.length === 0) return;
    this.emit(
      section,
      discriminator,
      attribute,
      ports.map(([a, b]) => (a === b ? String(a) : `${a}-${b}`)).join(' '),
    );
  }
}

// ============================================================================
// Discriminators
// ============================================================================

/**
 * Decision 3 of `shared/src/baseline.ts`: the STRUCTURE is kept verbatim, the
 * ADDRESSES are folded. `ether1` stays `ether1` across the fleet (same port,
 * same role); `vlan30` and `vlan40` stay distinct, because two sites that
 * number their voice VLAN differently really are two profiles, and merging them
 * produces the template nobody can apply.
 */
function structuralName(name: string | null | undefined, fallback: string): string {
  const n = (name ?? '').trim().toLowerCase();
  if (n === '') return fallback;
  // Slashes would break the `section/disc/attribute` grammar of a slot.
  return n.replace(/[/\s]+/g, '_').slice(0, 96);
}

/**
 * The identity of an anonymous rule, folded to its SHAPE: same protocol, same
 * ports, same interfaces, same zones, same connection state — but "a private
 * /24" instead of "10.20.0.0/24". That fold is what lets the same rule at
 * thirty sites align on one slot so that its addresses can be recognised as a
 * variable.
 *
 * `unmodeledMatch` is included: two rules that differ only by something the
 * parser could not read are not provably the same rule, and pretending they are
 * would let a template silently generalise over an unread predicate.
 */
function matchShape(match: NcmMatch): string {
  const shape = {
    protocol: match.protocol,
    src: match.srcAddress.map(generalizeBaselineValue).sort(),
    dst: match.dstAddress.map(generalizeBaselineValue).sort(),
    srcPort: match.srcPort,
    dstPort: match.dstPort,
    inIf: match.inInterface.map(generalizeBaselineValue).sort(),
    outIf: match.outInterface.map(generalizeBaselineValue).sort(),
    srcZone: match.srcZone,
    dstZone: match.dstZone,
    cs: [...match.connectionState].sort(),
    cn: [...match.connectionNat].sort(),
    flags: [...match.tcpFlags].sort(),
    icmp: match.icmpType,
    ipsec: match.ipsecPolicy,
    unmodeled: [...match.unmodeledMatch].sort(),
  };
  return sha256Short(canonicalJson(shape)).slice(0, 12);
}

/**
 * Within ONE document, two resources may legitimately produce the same
 * discriminator base (two static routes to two different private /24s, two
 * accept rules with the same shape). They are separated by their rank inside
 * the group, in the document's own order.
 *
 * Deterministic, and deliberately NOT global: the rank is local to the
 * discriminator base, so inserting a rule of a DIFFERENT shape does not shift
 * anybody's suffix. That is the same reasoning as `ordinal` in the NCM contract
 * (§3.4) — a collision class that renumbers on every unrelated edit produces a
 * cascade of false differences.
 */
function withRank(base: string, counters: Map<string, number>): string {
  const n = counters.get(base) ?? 0;
  counters.set(base, n + 1);
  return n === 0 ? base : `${base}~${n}`;
}

// ============================================================================
// Match attributes, shared by firewall / nat / qos
// ============================================================================

function emitMatch(
  sink: FactSink,
  section: NcmResourceKind,
  disc: string,
  match: NcmMatch,
): void {
  sink.emit(section, disc, 'protocol', match.protocol);
  sink.emitList(section, disc, 'srcAddress', match.srcAddress);
  sink.emitList(section, disc, 'dstAddress', match.dstAddress);
  sink.emitPorts(section, disc, 'srcPort', match.srcPort as [number, number][] | null);
  sink.emitPorts(section, disc, 'dstPort', match.dstPort as [number, number][] | null);
  sink.emitList(section, disc, 'inInterface', match.inInterface);
  sink.emitList(section, disc, 'outInterface', match.outInterface);
  sink.emit(section, disc, 'srcZone', match.srcZone);
  sink.emit(section, disc, 'dstZone', match.dstZone);
  sink.emitList(section, disc, 'connectionState', match.connectionState);
  sink.emitList(section, disc, 'connectionNat', match.connectionNat);
  sink.emitList(section, disc, 'tcpFlags', match.tcpFlags);
  sink.emit(section, disc, 'icmpType', match.icmpType);
  sink.emit(section, disc, 'ipsecPolicy', match.ipsecPolicy);
  sink.emitList(section, disc, 'unmodeledMatch', match.unmodeledMatch);
}

// ============================================================================
// The extractor
// ============================================================================

/** Rule 1: only a section we listed COMPLETELY or PARTIALLY may be mined. */
function readable(doc: NcmDocument, kind: NcmResourceKind): boolean {
  const state = coverageOf(doc.coverage, kind).state;
  return state === 'complete' || state === 'partial';
}

export function extractFacts(
  doc: NcmDocument,
  deviceId: number,
  snapshotId: number,
): DeviceFacts {
  const sink = new FactSink();
  const skipped: NcmResourceKind[] = [];
  const rank = new Map<string, number>();
  const r = doc.resources;

  // ── interface ─────────────────────────────────────────────────────────────
  if (readable(doc, 'interface')) {
    for (const i of r.interfaces) {
      const disc = withRank(structuralName(i.name, 'unnamed'), rank);
      sink.emit('interface', disc, 'type', i.type);
      sink.emit('interface', disc, 'parent', i.parent);
      sink.emit('interface', disc, 'mtu', i.mtu);
      sink.emit('interface', disc, 'zone', i.zone);
      sink.emit('interface', disc, 'disabled', i.disabled);
      sink.emitList('interface', disc, 'lists', i.lists);
      sink.emitList('interface', disc, 'addresses', i.addresses.map((a) => a.cidr));
    }
  } else skipped.push('interface');

  // ── vlan ──────────────────────────────────────────────────────────────────
  if (readable(doc, 'vlan')) {
    for (const v of r.vlans) {
      const disc = withRank(
        `${structuralName(v.parent, 'global')}#${v.vlanId}`,
        rank,
      );
      sink.emit('vlan', disc, 'name', v.name);
      sink.emit('vlan', disc, 'disabled', v.disabled);
      sink.emitList('vlan', disc, 'taggedPorts', v.taggedPorts);
      sink.emitList('vlan', disc, 'untaggedPorts', v.untaggedPorts);
    }
  } else skipped.push('vlan');

  // ── route ─────────────────────────────────────────────────────────────────
  // The discriminator folds the destination ("a private /24"), the FACT keeps
  // it verbatim. That single asymmetry is how "the LAN prefix" becomes a
  // variable instead of thirty unrelated routes.
  if (readable(doc, 'route')) {
    for (const rt of r.routes) {
      const disc = withRank(
        `${structuralName(rt.table, 'main')}#${generalizeBaselineValue(rt.dst)}`,
        rank,
      );
      sink.emit('route', disc, 'dst', rt.dst);
      sink.emit('route', disc, 'gateway', rt.gateway);
      sink.emit('route', disc, 'distance', rt.distance);
      sink.emit('route', disc, 'scope', rt.scope);
      sink.emit('route', disc, 'targetScope', rt.targetScope);
      sink.emit('route', disc, 'checkGateway', rt.checkGateway);
      sink.emit('route', disc, 'vrf', rt.vrf);
      sink.emit('route', disc, 'disabled', rt.disabled);
    }
  } else skipped.push('route');

  // ── firewall ──────────────────────────────────────────────────────────────
  if (readable(doc, 'firewallRule')) {
    const perChain = new Map<string, number>();
    for (const f of r.firewallRules) {
      const chain = f.chain === 'custom' ? `custom:${structuralName(f.chainName, 'x')}` : f.chain;
      perChain.set(chain, (perChain.get(chain) ?? 0) + 1);
      const disc = withRank(`${chain}#${matchShape(f.match)}`, rank);
      emitMatch(sink, 'firewallRule', disc, f.match);
      sink.emit('firewallRule', disc, 'action', f.action);
      sink.emit('firewallRule', disc, 'jumpTarget', f.jumpTarget);
      sink.emit('firewallRule', disc, 'rejectWith', f.rejectWith);
      sink.emit('firewallRule', disc, 'log', f.log);
      sink.emit('firewallRule', disc, 'addToList', f.addToList);
      sink.emit('firewallRule', disc, 'disabled', f.disabled);
    }
    // Rule 5's replacement for order: how POPULATED each chain is. One fact per
    // chain, it aligns across the fleet, and a site with a chain twice the size
    // of its cluster's shows up as one deviation instead of forty.
    for (const [chain, count] of [...perChain].sort()) {
      sink.emit('firewallRule', `${chain}#chain`, 'ruleCount', count);
    }
  } else skipped.push('firewallRule');

  // ── nat ───────────────────────────────────────────────────────────────────
  if (readable(doc, 'natRule')) {
    for (const n of r.natRules) {
      const chain = n.chain === 'custom' ? `custom:${structuralName(n.chainName, 'x')}` : n.chain;
      const disc = withRank(`${chain}#${matchShape(n.match)}`, rank);
      emitMatch(sink, 'natRule', disc, n.match);
      sink.emit('natRule', disc, 'action', n.action);
      sink.emitList('natRule', disc, 'toAddresses', n.toAddresses ?? undefined);
      sink.emitPorts('natRule', disc, 'toPorts', n.toPorts as [number, number][] | null);
      sink.emit('natRule', disc, 'disabled', n.disabled);
    }
  } else skipped.push('natRule');

  // ── dhcp ──────────────────────────────────────────────────────────────────
  if (readable(doc, 'dhcpScope')) {
    for (const d of r.dhcpScopes) {
      const disc = withRank(structuralName(d.name, 'dhcp'), rank);
      sink.emit('dhcpScope', disc, 'onInterface', d.onInterface);
      sink.emit('dhcpScope', disc, 'subnet', d.subnet);
      sink.emit('dhcpScope', disc, 'poolFrom', d.poolFrom);
      sink.emit('dhcpScope', disc, 'poolTo', d.poolTo);
      sink.emit('dhcpScope', disc, 'gateway', d.gateway);
      sink.emit('dhcpScope', disc, 'domain', d.domain);
      sink.emit('dhcpScope', disc, 'leaseSeconds', d.leaseSeconds);
      sink.emit('dhcpScope', disc, 'disabled', d.disabled);
      sink.emitList('dhcpScope', disc, 'dnsServers', d.dnsServers);
      sink.emitList('dhcpScope', disc, 'ntpServers', d.ntpServers);
      // The reservations themselves are per-site inventory, not a template
      // line: mining thirty MAC addresses per site produces thirty variables
      // nobody will ever fill. The COUNT aligns and is worth one fact.
      sink.emit('dhcpScope', disc, 'reservationCount', d.reservations.length);
      sink.emitList(
        'dhcpScope', disc, 'options',
        d.options.map((o) => `${o.code}=${o.value}`),
      );
    }
  } else skipped.push('dhcpScope');

  // ── ipsec ─────────────────────────────────────────────────────────────────
  // `pskFingerprint` is NOT listed below, and if it ever were, `emit()` would
  // refuse it and count the refusal (rule 3).
  if (readable(doc, 'ipsecPeer')) {
    for (const p of r.ipsecPeers) {
      const disc = withRank(
        p.name
          ? structuralName(p.name, 'peer')
          : `remote#${generalizeBaselineValue(p.remote)}`,
        rank,
      );
      sink.emit('ipsecPeer', disc, 'remote', p.remote);
      sink.emit('ipsecPeer', disc, 'localId', p.localId);
      sink.emit('ipsecPeer', disc, 'remoteId', p.remoteId);
      sink.emit('ipsecPeer', disc, 'exchangeMode', p.exchangeMode);
      sink.emit('ipsecPeer', disc, 'authMethod', p.authMethod);
      sink.emit('ipsecPeer', disc, 'dpdSeconds', p.dpdSeconds);
      sink.emit('ipsecPeer', disc, 'natTraversal', p.natTraversal);
      sink.emit('ipsecPeer', disc, 'disabled', p.disabled);
      sink.emitList('ipsecPeer', disc, 'localSubnets', p.localSubnets);
      sink.emitList('ipsecPeer', disc, 'remoteSubnets', p.remoteSubnets);
      sink.emitList('ipsecPeer', disc, 'encryption', p.proposal.encryption);
      sink.emitList('ipsecPeer', disc, 'integrity', p.proposal.integrity);
      sink.emitList('ipsecPeer', disc, 'dhGroup', p.proposal.dhGroup);
      sink.emit('ipsecPeer', disc, 'pfsGroup', p.proposal.pfsGroup);
      sink.emit('ipsecPeer', disc, 'lifetimeSeconds', p.proposal.lifetimeSeconds);
    }
  } else skipped.push('ipsecPeer');

  // ── local users ───────────────────────────────────────────────────────────
  // `passwordFingerprint` and `sshKeyFingerprints` are absent by design, and
  // refused by `emit()` if a later hand adds them.
  if (readable(doc, 'localUser')) {
    for (const u of r.localUsers) {
      const disc = withRank(structuralName(u.username, 'user'), rank);
      sink.emit('localUser', disc, 'group', u.group);
      sink.emit('localUser', disc, 'isVendorDefault', u.isVendorDefault);
      sink.emit('localUser', disc, 'twoFactor', u.twoFactor);
      sink.emit('localUser', disc, 'disabled', u.disabled);
      sink.emitList('localUser', disc, 'permissions', u.permissions);
      sink.emitList('localUser', disc, 'allowedFrom', u.allowedFrom);
    }
  } else skipped.push('localUser');

  // ── management services ───────────────────────────────────────────────────
  if (readable(doc, 'service')) {
    for (const s of r.services) {
      const disc = withRank(
        s.service === 'other' ? `other:${structuralName(s.rawName, 'x')}` : s.service,
        rank,
      );
      sink.emit('service', disc, 'enabled', s.enabled);
      sink.emit('service', disc, 'port', s.port);
      sink.emit('service', disc, 'tlsRequired', s.tlsRequired);
      sink.emit('service', disc, 'certificate', s.certificate);
      sink.emit('service', disc, 'version', s.version);
      // Kept on purpose: §7.2 of the NCM contract carves this one boolean out
      // as the audit signal worth having. It is a statement ABOUT a community,
      // never the community — `communityFingerprint` is refused by `emit()`.
      sink.emit('service', disc, 'communityIsWellKnown', s.communityIsWellKnown);
      sink.emitList('service', disc, 'allowedFrom', s.allowedFrom);
    }
  } else skipped.push('service');

  // ── qos ───────────────────────────────────────────────────────────────────
  if (readable(doc, 'qosRule')) {
    for (const q of r.qosRules) {
      const disc = withRank(
        `${q.queueClass}#${q.name ? structuralName(q.name, 'q') : (q.match ? matchShape(q.match) : 'plain')}`,
        rank,
      );
      sink.emit('qosRule', disc, 'parent', q.parent);
      sink.emit('qosRule', disc, 'priority', q.priority);
      sink.emit('qosRule', disc, 'maxLimitUpBps', q.maxLimitUpBps);
      sink.emit('qosRule', disc, 'maxLimitDownBps', q.maxLimitDownBps);
      sink.emit('qosRule', disc, 'limitAtUpBps', q.limitAtUpBps);
      sink.emit('qosRule', disc, 'limitAtDownBps', q.limitAtDownBps);
      sink.emit('qosRule', disc, 'queueType', q.queueType);
      sink.emit('qosRule', disc, 'disabled', q.disabled);
      sink.emitList('qosRule', disc, 'target', q.target);
      if (q.match) emitMatch(sink, 'qosRule', disc, q.match);
    }
  } else skipped.push('qosRule');

  return {
    deviceId,
    snapshotId,
    facts: sink.facts,
    slots: new Set(sink.facts.map((f) => f.slot)),
    skippedSections: skipped,
    refusedAttributes: sink.refused,
  };
}
