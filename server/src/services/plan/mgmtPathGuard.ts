// ============================================================================
// ObliWAN — K2, the Management-Path Guard
// ============================================================================
//
// PURE. No database, no socket, no clock, no randomness. Everything it needs
// arrives as two NCM documents and a handful of facts. That is deliberate and
// it is the whole point of the module: this is the ONLY part of M6 that can be
// proved to the last branch without a router on a bench, so it is proved.
//
// ┌─ WHAT THIS FILE DECIDES ─────────────────────────────────────────────────┐
// │ "If we apply this plan, can the platform still reach this device?"        │
// │                                                                          │
// │ It answers by building a mini forwarding engine over the TARGET NCM —     │
// │ the state the device would be in AFTER the plan — and running a           │
// │ synthetic packet `CHR -> management IP` through it. The same packet is    │
// │ run through the OBSERVED NCM to get a baseline. A verdict that flips      │
// │ from ACCEPT to DROP, or a return route that disappears, is a REJECT.      │
// │                                                                          │
// │ It does NOT decide whether the change is a good idea, whether the         │
// │ dead-man is armed, or whether the operator may override. Those are K1     │
// │ and the job queue. This file produces a verdict and the evidence for it.  │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ── THE ONE RULE THAT MATTERS MOST ──────────────────────────────────────────
//
// `INDETERMINATE` IS NOT `ACCEPT`.
//
// §6.4 of the NCM contract is not advisory. If `coverage` is not `complete`, if
// a `forwardingRelevant` section sits in `unmodeled[]`, if a rule on the walked
// path carries a non-empty `unmodeledMatch`, or if the order analysis is not
// `full`, this guard MAY NOT return ACCEPT. It returns INDETERMINATE, which the
// caller treats as a refusal that only an explicit, recorded override can lift.
//
// Reasoning about a firewall we can only half read, and concluding "it is
// fine", is precisely the failure mode that takes a customer site off the air
// and puts an engineer in a van. Every ambiguity below therefore resolves
// towards "I cannot conclude", never towards "probably fine".
//
// The one asymmetry, stated so it can be argued with: a PROOF OF DROP BEATS
// BLINDNESS. If the engine definitely matched a denying rule on the management
// path, the verdict is REJECT even when other parts of the document are
// unreadable. Being blind elsewhere does not un-prove a proof, and downgrading
// a proven cut to "indeterminate" would let it be waved through with the same
// click as an ordinary blind spot.
//
// ── SCOPE, HONESTLY ─────────────────────────────────────────────────────────
//
// The engine models what the NCM models: ordered filter chains with the
// selectors of `NcmMatch`, static routes, interface state, management services
// and prerouting DNAT. It does NOT model connection tracking beyond a state
// label, policy routing / mangle marks, OSPF or BGP, RouterOS `fasttrack`
// semantics, per-brand zone defaults, or the dynamic peer route an L2TP client
// installs. Each of those gaps has a named, testable consequence below rather
// than a silent assumption — a modelled gap that announces itself is safe, a
// modelled gap that stays quiet is the thing §6.4 was written against.

import type {
  DeviceFamily, NcmDocument, NcmFirewallRule, NcmInterface, NcmMatch, NcmNatRule,
  NcmResource, NcmResourceKind, NcmRoute, NcmService, PlanOp, MgmtPathVerdict,
  PortSet, Selector,
} from '@obliwan/shared';
import {
  MGMT_PATH_VERDICTS, RESOURCE_KIND_TO_COLLECTION, coverageOf, parseCidr, parseIp,
} from '@obliwan/shared';
import {
  MANAGEMENT_SERVICES, MANAGEMENT_PORTS, cidrContains,
  type MgmtPathFacts,
} from './riskScoring';

// ============================================================================
// Vocabulary
// ============================================================================

/** The three verdicts of §6.4, in the guard's own spelling. `REJECT` maps to
 *  the plan-level `veto`; the shape is uppercase here because the milestone
 *  brief, the UI copy and the operator's vocabulary all say ACCEPT / REJECT /
 *  INDETERMINATE. `toPlanVerdict()` is the only translation point. */
export const MGMT_GUARD_VERDICTS = ['ACCEPT', 'REJECT', 'INDETERMINATE'] as const;
export type MgmtGuardVerdict = (typeof MGMT_GUARD_VERDICTS)[number];

/**
 * Why the guard concluded what it concluded.
 *
 * An operator who reads "refused" without the line of the plan that triggered
 * it will switch the guard off within a week. Every reason therefore carries a
 * code from this closed list, a sentence, and — whenever the conclusion came
 * from a record — the record itself and the plan op that produced it.
 *
 * The list is split in two by `REASON_EFFECT` below: proofs of a cut, and
 * admissions of blindness. Nothing is decorative; every code is reachable.
 */
export const MGMT_GUARD_REASON_CODES = [
  // ── proofs: the guard matched something and it denies the path ──────────
  'INPUT_DROP',            // a filter rule in input (or a chain jumped into) denies the probe
  'OUTPUT_DROP',           // the reply leg is denied in output
  'CHAIN_POLICY_DROP',     // no rule decided and the chain policy is a deny
  'NO_ROUTE',              // the return route to the CHR is gone, blackholed or dead
  'TUNNEL_CRITICAL',       // the tunnel interface is removed or disabled by the plan
  'MGMT_ADDRESS_LOST',     // the management address is no longer configured anywhere
  'MGMT_SERVICE_LOST',     // every management service is disabled, or shut to the CHR
  'MGMT_IDENTITY_LOST',    // no local account is left that could log in and act
  'NAT_HIJACK',            // a prerouting DNAT captures the management session
  // ── blindness: the guard may not conclude ACCEPT ────────────────────────
  'COVERAGE_INCOMPLETE',
  'UNMODELED_FORWARDING_SECTION',
  'UNMODELED_MATCH',
  'ORDER_ANALYSIS_PARTIAL',
  'AMBIGUOUS_RULE',
  'UNKNOWN_ACTION',
  'CHAIN_POLICY_UNKNOWN',
  'TUNNEL_UNKNOWN',
  'MGMT_ADDRESS_UNKNOWN',
  'MGMT_IDENTITY_UNKNOWN',
  'PEER_ADDRESS_UNKNOWN',
  'ROUTE_MODEL_BLIND',
  'JUMP_DEPTH_EXCEEDED',
  'JUMP_LOOP',
  'BASELINE_CONTRADICTION',
  'PROJECTION_INCOMPLETE',
] as const;
export type MgmtGuardReasonCode = (typeof MGMT_GUARD_REASON_CODES)[number];

export type ReasonEffect = 'reject' | 'indeterminate';

/** Which half of the verdict each code belongs to. A single table so a new code
 *  cannot be added without deciding, explicitly, whether it refuses or blinds. */
export const REASON_EFFECT: Readonly<Record<MgmtGuardReasonCode, ReasonEffect>> = {
  INPUT_DROP: 'reject',
  OUTPUT_DROP: 'reject',
  CHAIN_POLICY_DROP: 'reject',
  NO_ROUTE: 'reject',
  TUNNEL_CRITICAL: 'reject',
  MGMT_ADDRESS_LOST: 'reject',
  MGMT_SERVICE_LOST: 'reject',
  MGMT_IDENTITY_LOST: 'reject',
  NAT_HIJACK: 'reject',
  COVERAGE_INCOMPLETE: 'indeterminate',
  UNMODELED_FORWARDING_SECTION: 'indeterminate',
  UNMODELED_MATCH: 'indeterminate',
  ORDER_ANALYSIS_PARTIAL: 'indeterminate',
  AMBIGUOUS_RULE: 'indeterminate',
  UNKNOWN_ACTION: 'indeterminate',
  CHAIN_POLICY_UNKNOWN: 'indeterminate',
  TUNNEL_UNKNOWN: 'indeterminate',
  MGMT_ADDRESS_UNKNOWN: 'indeterminate',
  MGMT_IDENTITY_UNKNOWN: 'indeterminate',
  PEER_ADDRESS_UNKNOWN: 'indeterminate',
  ROUTE_MODEL_BLIND: 'indeterminate',
  JUMP_DEPTH_EXCEEDED: 'indeterminate',
  JUMP_LOOP: 'indeterminate',
  BASELINE_CONTRADICTION: 'indeterminate',
  PROJECTION_INCOMPLETE: 'indeterminate',
};

/** Kleene truth for "does this selector / rule match this packet". `unknown` is
 *  a first-class answer and is never silently folded into `no`. */
export type Tri = 'yes' | 'no' | 'unknown';

/** What happens to a packet at the end of a chain walk. */
export type PacketOutcome = 'accept' | 'drop' | 'unknown';

/**
 * The record the guard blames, plus the plan line that put it there.
 *
 * `opSeq` is what makes the refusal actionable: "REJECT" alone is an argument,
 * "REJECT because op #7 of your plan inserts `chain=input action=drop` above
 * your management accept" is a fix.
 */
export interface MgmtGuardCulprit {
  resource: NcmResourceKind;
  semKey: string;
  /** Position in the document's collection, when the kind is ordered. */
  index: number | null;
  /** Chain the record lives in, for the ordered kinds. */
  chain: string | null;
  /** One line, brand-neutral, safe to log: the NCM carries no secrets (§8.2). */
  describe: string;
  /** `seq` of the plan op that creates / changes / moves this record. */
  opSeq: number | null;
  /** `kind` of that op, so the UI can say "the DELETE at step 7". */
  opKind: PlanOp['kind'] | null;
}

export interface MgmtGuardReason {
  code: MgmtGuardReasonCode;
  effect: ReasonEffect;
  /** Probe id when the reason came from a packet walk, else null. */
  probe: string | null;
  /** Operator-facing sentence. Shown verbatim; never a stack trace. */
  message: string;
  culprit: MgmtGuardCulprit | null;
}

export interface ProbeReport {
  id: string;
  description: string;
  /** Verdict on the OBSERVED document — how the box behaves today. */
  before: PacketOutcome;
  /** Verdict on the TARGET document — how it would behave after the plan. */
  after: PacketOutcome;
}

export type RouteState = 'ok' | 'broken' | 'none' | 'unknown';

export interface RouteResolution {
  state: RouteState;
  /** `route:<semKey>` or `connected:<interface>`, for the UI. */
  via: string | null;
  /**
   * The interface the reply actually leaves through.
   *
   * This is the field that catches the nastiest of the routing motifs: delete
   * the specific route to the concentrator and the reply does not vanish, it
   * silently follows the default route out of the WAN, where an RFC1918
   * next hop dies at the first ISP router. `state` stays `ok` — there IS a
   * route — and only the egress betrays it.
   */
  egress: string | null;
  detail: string;
  culprit: MgmtGuardCulprit | null;
}

export interface MgmtGuardResult {
  verdict: MgmtGuardVerdict;
  /** The same decision in the vocabulary `change_plans.mgmt_path_verdict` uses. */
  planVerdict: MgmtPathVerdict;
  /** Sorted: proofs first, then blindness. The first one is the headline. */
  reasons: MgmtGuardReason[];
  probes: ProbeReport[];
  routing: { before: RouteResolution; after: RouteResolution };
  /** Plan ops implicated by at least one reason, ascending. */
  culpritOpSeqs: number[];
  /** One sentence for the plan header / the refusal toast. */
  summary: string;
  /** What the engine actually analysed — shown next to the verdict so nobody
   *  has to guess which address and which interface it reasoned about. */
  analysed: {
    peerAddress: string | null;
    managementAddress: string | null;
    tunnelInterface: string | null;
    tunnelInterfaceCertain: boolean;
    ports: number[];
    chainPolicy: ChainPolicy;
  };
}

// ============================================================================
// Chain policy — what happens when no rule decides
// ============================================================================

/**
 * A chain that reaches its end without a terminal decision falls back on its
 * policy. netfilter (and therefore RouterOS) ships `ACCEPT` on the three
 * built-in filter chains, and RouterOS exposes no way to change it — a
 * RouterOS box that denies management does so with an explicit rule, which is
 * exactly what the walk above is for.
 *
 * For DrayTek / Zyxel / SonicWall the default is deliberately `unknown`. Those
 * are zone firewalls whose implicit inter-zone behaviour we have NOT modelled,
 * and no hardware exists to check a guess against (A2 / §8.3). Declaring
 * `accept` there would manufacture ACCEPT verdicts out of an assumption; the
 * whole file exists to not do that. The consequence is stated plainly: on
 * those three brands the guard can PROVE a cut, but it cannot certify safety
 * unless an explicit rule accepts the probe before the end of the chain.
 */
export interface ChainPolicy {
  input: PacketOutcome;
  output: PacketOutcome;
  forward: PacketOutcome;
}

export const ROUTEROS_CHAIN_POLICY: ChainPolicy = {
  input: 'accept', output: 'accept', forward: 'accept',
};
export const UNKNOWN_CHAIN_POLICY: ChainPolicy = {
  input: 'unknown', output: 'unknown', forward: 'unknown',
};

export function defaultChainPolicy(family: DeviceFamily | null | undefined): ChainPolicy {
  if (family === 'mikrotik_routeros6' || family === 'mikrotik_routeros7') return ROUTEROS_CHAIN_POLICY;
  return UNKNOWN_CHAIN_POLICY;
}

// ============================================================================
// Bounds
// ============================================================================

/** A DESIRED document is not a router: nothing stops a template from writing a
 *  jump cycle. The walk is depth-bounded AND cycle-detected, and both produce
 *  an INDETERMINATE rather than a stack overflow. */
export const MAX_JUMP_DEPTH = 16;

/** Probing every management port of a box with twenty services would produce
 *  sixty probes for no extra information: the ports differ, the path does not. */
export const MAX_PROBE_PORTS = 4;

/** Recursive next-hop resolution. Three levels is more than any real static
 *  routing table on a CPE, and the fourth is a loop we refuse to chase. */
const MAX_ROUTE_RECURSION = 3;

/** Ephemeral source port of the synthetic session. Any value works; a constant
 *  keeps the probe ids stable across runs, which matters because they end up
 *  in `command_audit` and in screenshots attached to change tickets. */
const EPHEMERAL_PORT = 41234;

/**
 * Resource kinds whose collection must be `complete` before ACCEPT is even
 * arguable. `vlan` is conditional (added only when a tunnel interface actually
 * rides one) and `qosRule` / `dhcpScope` / `localUser` / `ipsecPeer` are out:
 * none of them can, on their own, change the fate of a packet already inside
 * the tunnel, and demanding `complete` on kinds most families declare
 * `unsupported` would turn every verdict into INDETERMINATE — which is Q8, the
 * failure mode where the confirmation click becomes reflex.
 */
const FORWARDING_KINDS: readonly NcmResourceKind[] = [
  'interface', 'route', 'firewallRule', 'natRule', 'service',
];

// ============================================================================
// Input
// ============================================================================

export interface MgmtGuardInput {
  /** The device as it is TODAY. The baseline the verdict is a delta against. */
  observed: NcmDocument;
  /**
   * The device as it WOULD BE after the plan. Callers that hold a plan should
   * obtain this from `projectPlan(observed, ops)` rather than from the rendered
   * template: outside a claimed section the template says nothing, and a target
   * built from it alone would silently drop every rule the plan leaves alone.
   */
  target: NcmDocument;
  /** From `buildMgmtPathFacts(observed, …)`. Never built from the target: the
   *  question is how we reach the box today. */
  facts: MgmtPathFacts;
  /** Source address of the management session — the CHR / concentrator. Null
   *  makes the verdict INDETERMINATE and says so. */
  peerAddress: string | null;
  /** The plan, used ONLY to attribute a reason to a line. Never to decide. */
  ops?: readonly PlanOp[];
  /** Overrides the family-derived policy. */
  chainPolicy?: ChainPolicy;
  family?: DeviceFamily | null;
  /** Set by `projectPlan` when it could not fully simulate the plan. */
  projectionComplete?: boolean;
  /** Extra ports to probe on top of the ones derived from the services. */
  extraPorts?: readonly number[];
}

// ============================================================================
// The synthetic packet
// ============================================================================

interface TcpFlags { syn: boolean; ack: boolean; fin: boolean; rst: boolean; psh: boolean; urg: boolean; }

interface SyntheticPacket {
  id: string;
  description: string;
  chain: 'input' | 'output';
  /** Interface the packet enters (input) or leaves (output) through. */
  interfaceName: string;
  protocol: string;
  srcAddress: string;
  dstAddress: string;
  srcPort: number;
  dstPort: number;
  connectionState: string;
  tcp: TcpFlags;
}

const SYN: TcpFlags = { syn: true, ack: false, fin: false, rst: false, psh: false, urg: false };
const ACK: TcpFlags = { syn: false, ack: true, fin: false, rst: false, psh: false, urg: false };

// ============================================================================
// Document context — chains, interface index, coverage
// ============================================================================

interface IndexedRule<T> { rule: T; index: number; }

interface DocContext {
  doc: NcmDocument;
  label: 'observed' | 'target';
  /** Filter rules grouped by chain key, ARRAY ORDER PRESERVED. That order is
   *  the forwarding order, and preserving it is what makes a reordering plan
   *  detectable at all. */
  chains: Map<string, IndexedRule<NcmFirewallRule>[]>;
  natChains: Map<string, IndexedRule<NcmNatRule>[]>;
  interfaces: Map<string, NcmInterface>;
  /** True when `coverage.interface` is `complete`, i.e. "this interface is not
   *  in the document" may be read as "this interface does not exist". */
  interfacesComplete: boolean;
  policy: ChainPolicy;
  ops: Map<string, PlanOp>;
}

function chainKeyOf(rule: { chain: string; chainName: string | null }): string {
  return rule.chain === 'custom' ? (rule.chainName ?? '?') : rule.chain;
}

function buildContext(
  doc: NcmDocument,
  label: DocContext['label'],
  policy: ChainPolicy,
  ops: Map<string, PlanOp>,
): DocContext {
  const chains = new Map<string, IndexedRule<NcmFirewallRule>[]>();
  doc.resources.firewallRules.forEach((rule, index) => {
    const key = chainKeyOf(rule);
    const list = chains.get(key);
    if (list) list.push({ rule, index });
    else chains.set(key, [{ rule, index }]);
  });

  const natChains = new Map<string, IndexedRule<NcmNatRule>[]>();
  doc.resources.natRules.forEach((rule, index) => {
    const key = chainKeyOf(rule);
    const list = natChains.get(key);
    if (list) list.push({ rule, index });
    else natChains.set(key, [{ rule, index }]);
  });

  const interfaces = new Map<string, NcmInterface>();
  for (const iface of doc.resources.interfaces) interfaces.set(iface.name, iface);

  return {
    doc,
    label,
    chains,
    natChains,
    interfaces,
    interfacesComplete: coverageOf(doc.coverage, 'interface').state === 'complete',
    policy,
    ops,
  };
}

// ============================================================================
// Three-valued selector evaluation
// ============================================================================

/** Kleene AND over a list of dimension verdicts. One `no` is decisive; a single
 *  `unknown` with no `no` poisons the whole match, which is the point. */
function andTri(values: readonly Tri[]): Tri {
  let unknown = false;
  for (const v of values) {
    if (v === 'no') return 'no';
    if (v === 'unknown') unknown = true;
  }
  return unknown ? 'unknown' : 'yes';
}

/** Kleene OR over the atoms of one selector: a selector matches when ANY of its
 *  atoms does. `yes` dominates — a definite hit is a hit even if a sibling atom
 *  is unreadable. */
function orTri(values: readonly Tri[]): Tri {
  let unknown = false;
  for (const v of values) {
    if (v === 'yes') return 'yes';
    if (v === 'unknown') unknown = true;
  }
  return unknown ? 'unknown' : 'no';
}

/**
 * Does this address selector cover `ip`?
 *
 * `ref:` (an address list or named object we refuse to expand silently, §3.3
 * rule 8), `fqdn:` and `mac:` all answer `unknown`. That is the honest answer:
 * an address list is a runtime set this document does not contain, and the day
 * we pretend otherwise is the day a plan gets approved because the guard
 * assumed `ref:MGMT-ALLOWED` still had our address in it.
 */
export function addressSelectorMatches(sel: Selector, ip: string): Tri {
  const parsed = parseIp(ip);
  if (!parsed) return 'unknown';
  const per: Tri[] = [];
  for (const atom of sel) {
    if (atom === 'any') return 'yes';
    const colon = atom.indexOf(':');
    const tag = colon < 0 ? '' : atom.slice(0, colon);
    const value = atom.slice(colon + 1);
    switch (tag) {
      case 'ip': per.push(value === ip ? 'yes' : 'no'); break;
      case 'cidr': per.push(cidrContains(value, ip) ? 'yes' : 'no'); break;
      case 'range': per.push(rangeContains(value, ip)); break;
      default: per.push('unknown'); break;      // ref / fqdn / mac / unknown tag
    }
  }
  return orTri(per);
}

function rangeContains(value: string, ip: string): Tri {
  const dash = value.indexOf('-');
  if (dash < 0) return 'unknown';
  const lo = parseIp(value.slice(0, dash));
  const hi = parseIp(value.slice(dash + 1));
  const target = parseIp(ip);
  if (!lo || !hi || !target) return 'unknown';
  if (lo.version !== target.version || hi.version !== target.version) return 'no';
  const cmp = (a: Uint8Array, b: Uint8Array): number => {
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
  };
  const [low, high] = cmp(lo.bytes, hi.bytes) <= 0 ? [lo, hi] : [hi, lo];
  return cmp(low.bytes, target.bytes) <= 0 && cmp(target.bytes, high.bytes) <= 0 ? 'yes' : 'no';
}

/**
 * Does this interface selector name the interface the probe rides?
 *
 * `ifaceList:` IS resolved here, unlike in `mayIntersect` — and the difference
 * is not an inconsistency. `mayIntersect` compares two rules and must not let
 * a list membership change make every rule of the box "move"; the guard
 * evaluates ONE packet against ONE document that contains the membership, so
 * refusing to read it would throw away the only fact that decides. It stays
 * honest by answering `unknown` whenever the membership cannot be read: the
 * interface is absent, or `coverage.interface` is not `complete` and therefore
 * "not listed" does not mean "not a member".
 */
export function interfaceSelectorMatches(ctx: DocContext, sel: Selector, ifaceName: string): Tri {
  const per: Tri[] = [];
  for (const atom of sel) {
    if (atom === 'any') return 'yes';
    const colon = atom.indexOf(':');
    const tag = colon < 0 ? '' : atom.slice(0, colon);
    const value = atom.slice(colon + 1);
    if (tag === 'iface') { per.push(value === ifaceName ? 'yes' : 'no'); continue; }
    if (tag === 'ifaceList') {
      const iface = ctx.interfaces.get(ifaceName);
      if (!iface) { per.push('unknown'); continue; }
      if (iface.lists.includes(value)) { per.push('yes'); continue; }
      per.push(ctx.interfacesComplete ? 'no' : 'unknown');
      continue;
    }
    per.push('unknown');
  }
  return orTri(per);
}

function portMatches(set: PortSet, port: number): Tri {
  if (set === null) return 'yes';
  for (const [lo, hi] of set) if (port >= lo && port <= hi) return 'yes';
  return 'no';
}

/**
 * TCP flag tokens (`syn`, `!ack`, …) against the flags of the synthetic packet.
 * Anything outside the six modelled flags answers `unknown` rather than being
 * ignored — a rule keyed on a flag we do not carry is a rule we cannot resolve.
 */
function tcpFlagsMatch(tokens: readonly string[], flags: TcpFlags): Tri {
  if (tokens.length === 0) return 'yes';
  const per: Tri[] = [];
  for (const raw of tokens) {
    const negated = raw.startsWith('!');
    const name = (negated ? raw.slice(1) : raw).trim().toLowerCase();
    const value =
      name === 'syn' ? flags.syn :
      name === 'ack' ? flags.ack :
      name === 'fin' ? flags.fin :
      name === 'rst' ? flags.rst :
      name === 'psh' ? flags.psh :
      name === 'urg' ? flags.urg : null;
    if (value === null) { per.push('unknown'); continue; }
    per.push((negated ? !value : value) ? 'yes' : 'no');
  }
  // RouterOS `tcp-flags` is a conjunction: every listed token must hold.
  return andTri(per);
}

function zoneOf(ctx: DocContext, ifaceName: string): string | null | undefined {
  const iface = ctx.interfaces.get(ifaceName);
  if (!iface) return undefined;         // unreadable
  return iface.zone;                    // may legitimately be null (no zone model)
}

/**
 * The whole match, dimension by dimension.
 *
 * Dimensions are ordered cheapest-and-most-selective first so a rule that
 * obviously does not apply costs three comparisons, not a CIDR walk.
 */
function matchPacket(ctx: DocContext, match: NcmMatch, pkt: SyntheticPacket): Tri {
  const dims: Tri[] = [];

  // 1. protocol
  dims.push(match.protocol === null ? 'yes' : match.protocol === pkt.protocol ? 'yes' : 'no');

  // 2. connection state. Our probes carry exactly one state label; a rule that
  //    lists states matches when ours is among them. This is the dimension that
  //    catches the single most common self-inflicted lockout: deleting the
  //    `connection-state=established,related accept` rule.
  dims.push(
    match.connectionState.length === 0
      ? 'yes'
      : match.connectionState.includes(pkt.connectionState) ? 'yes' : 'no',
  );

  // 3. interfaces. A packet in the `input` chain has no out-interface and a
  //    locally generated packet in `output` has no in-interface — netfilter
  //    semantics, and a definite `no` rather than an `unknown`.
  if (pkt.chain === 'input') {
    dims.push(interfaceSelectorMatches(ctx, match.inInterface, pkt.interfaceName));
    dims.push(match.outInterface.includes('any') ? 'yes' : 'no');
  } else {
    dims.push(match.inInterface.includes('any') ? 'yes' : 'no');
    dims.push(interfaceSelectorMatches(ctx, match.outInterface, pkt.interfaceName));
  }

  // 4. ports
  dims.push(portMatches(match.srcPort, pkt.srcPort));
  dims.push(portMatches(match.dstPort, pkt.dstPort));

  // 5. addresses
  dims.push(addressSelectorMatches(match.srcAddress, pkt.srcAddress));
  dims.push(addressSelectorMatches(match.dstAddress, pkt.dstAddress));

  // 6. zones. Resolvable only through the interface the probe rides; a zone we
  //    cannot resolve is `unknown`, never "matches".
  if (match.srcZone !== null) {
    const z = pkt.chain === 'input' ? zoneOf(ctx, pkt.interfaceName) : undefined;
    dims.push(z === undefined || z === null ? 'unknown' : z === match.srcZone ? 'yes' : 'no');
  }
  if (match.dstZone !== null) {
    const z = pkt.chain === 'output' ? zoneOf(ctx, pkt.interfaceName) : undefined;
    dims.push(z === undefined || z === null ? 'unknown' : z === match.dstZone ? 'yes' : 'no');
  }

  // 7. tcp flags
  dims.push(tcpFlagsMatch(match.tcpFlags, pkt.tcp));

  // 8. dimensions the synthetic packet genuinely does not carry. Each one is an
  //    `unknown`, which poisons the rule and — if that rule sits on the path —
  //    the verdict. That is the fail-closed direction and it is intended.
  if (match.connectionNat.length > 0) dims.push('unknown');
  if (match.ipsecPolicy !== null) dims.push('unknown');
  if (match.icmpType !== null) {
    // An icmp-options rule on a TCP probe: only a definite protocol mismatch
    // makes it a clean `no`, and dimension 1 has already produced that.
    dims.push(match.protocol === 'icmp' || match.protocol === 'icmpv6' ? 'no' : 'unknown');
  }

  // 9. THE HONEST BOUNDARY. A selector the parser saw and did not model cannot
  //    be evaluated, so the rule cannot be resolved. §6.4 turns this into
  //    INDETERMINATE at the verdict level; here it simply refuses to be `yes`.
  if (match.unmodeledMatch.length > 0) dims.push('unknown');

  return andTri(dims);
}

// ============================================================================
// The chain walk
// ============================================================================

interface WalkAcc {
  dropCulprits: MgmtGuardCulprit[];
  acceptCulprits: MgmtGuardCulprit[];
  ambiguous: MgmtGuardCulprit[];
  unmodeled: MgmtGuardCulprit[];
  unknownAction: MgmtGuardCulprit[];
  depthExceeded: boolean;
  loop: boolean;
}

function freshAcc(): WalkAcc {
  return {
    dropCulprits: [], acceptCulprits: [], ambiguous: [], unmodeled: [],
    unknownAction: [], depthExceeded: false, loop: false,
  };
}

/**
 * Walk ONE chain and report the SET of outcomes the packet can meet.
 *
 * The set, not a single value, is what makes three-valued matching usable: a
 * rule that MIGHT match contributes its outcome as a possibility and the walk
 * carries on as if it had not matched, exploring the other branch. Two
 * different possible fates means the guard does not know, and does not know is
 * `INDETERMINATE`.
 *
 * Cost is O(rules) per chain and the recursion is depth- and cycle-bounded, so
 * a hostile DESIRED document cannot make this spin.
 */
function walkChain(
  ctx: DocContext,
  chainKey: string,
  pkt: SyntheticPacket,
  acc: WalkAcc,
  stack: readonly string[],
): { possible: Set<PacketOutcome>; falls: boolean } {
  const possible = new Set<PacketOutcome>();

  if (stack.includes(chainKey)) {
    acc.loop = true;
    possible.add('unknown');
    return { possible, falls: false };
  }
  if (stack.length >= MAX_JUMP_DEPTH) {
    acc.depthExceeded = true;
    possible.add('unknown');
    return { possible, falls: false };
  }

  const rules = ctx.chains.get(chainKey);
  // A jump to a chain that carries no rule: on RouterOS the chain is simply
  // empty and control returns to the caller. Not a decision, not an error.
  if (!rules) return { possible, falls: true };

  for (const { rule, index } of rules) {
    if (rule.disabled) continue;
    const m = matchPacket(ctx, rule.match, pkt);
    if (m === 'no') continue;

    const culprit = culpritOfRule(ctx, rule, index, chainKey);
    if (rule.match.unmodeledMatch.length > 0) acc.unmodeled.push(culprit);

    switch (rule.action) {
      case 'accept':
        possible.add('accept');
        acc.acceptCulprits.push(culprit);
        if (m === 'yes') return { possible, falls: false };
        acc.ambiguous.push(culprit);
        break;

      case 'drop':
      case 'reject':
      case 'tarpit':
        possible.add('drop');
        acc.dropCulprits.push(culprit);
        if (m === 'yes') return { possible, falls: false };
        acc.ambiguous.push(culprit);
        break;

      case 'jump': {
        if (!rule.jumpTarget) {
          possible.add('unknown');
          acc.unknownAction.push(culprit);
          break;
        }
        const sub = walkChain(ctx, rule.jumpTarget, pkt, acc, [...stack, chainKey]);
        for (const o of sub.possible) possible.add(o);
        // A definite jump into a chain that definitely decides ends the walk.
        if (m === 'yes' && !sub.falls) return { possible, falls: false };
        if (m === 'unknown') acc.ambiguous.push(culprit);
        break;
      }

      case 'return':
        // Control leaves this chain for its caller (or for the policy, at the
        // top level).
        if (m === 'yes') return { possible, falls: true };
        acc.ambiguous.push(culprit);
        break;

      case 'log':
      case 'passthrough':
      case 'addToList':
        // Non-deciding by construction: the packet carries on down the chain.
        break;

      case 'fasttrack':
        // DELIBERATE DIVERGENCE from `TERMINAL_ACTIONS` in the shared package.
        // `action=fasttrack-connection` does NOT terminate rule evaluation on
        // RouterOS — the packet keeps walking, which is why every real config
        // pairs it with an `accept` immediately after. Treating it as terminal
        // here would make the guard miss a drop that sits below it. The cost of
        // the choice is a possible false REJECT on a chain that relies on
        // fasttrack alone; the cost of the other choice is a missed lockout.
        break;

      case 'other':
      default:
        // An action the model did not recognise. We cannot know what it does to
        // the packet, so the walk can no longer conclude.
        possible.add('unknown');
        acc.unknownAction.push(culprit);
        break;
    }
  }

  return { possible, falls: true };
}

interface ChainVerdict {
  outcome: PacketOutcome;
  acc: WalkAcc;
  /** True when the outcome came from the chain policy rather than a rule. */
  byPolicy: boolean;
}

function evaluateChain(ctx: DocContext, pkt: SyntheticPacket): ChainVerdict {
  const acc = freshAcc();
  const { possible, falls } = walkChain(ctx, pkt.chain, pkt, acc, []);
  const policy = ctx.policy[pkt.chain];
  let byPolicy = false;
  if (falls || possible.size === 0) { possible.add(policy); byPolicy = true; }
  const outcome: PacketOutcome = possible.size === 1 ? [...possible][0] : 'unknown';
  return { outcome, acc, byPolicy: byPolicy && possible.size === 1 };
}

// ============================================================================
// Culprits
// ============================================================================

function opFor(ctx: DocContext, semKey: string): PlanOp | undefined {
  return ctx.ops.get(semKey);
}

function culpritOfRule(
  ctx: DocContext,
  rule: NcmFirewallRule,
  index: number,
  chainKey: string,
): MgmtGuardCulprit {
  const op = opFor(ctx, rule.semKey);
  return {
    resource: 'firewallRule',
    semKey: rule.semKey,
    index,
    chain: chainKey,
    describe: describeFirewallRule(rule, chainKey),
    opSeq: op ? op.seq : null,
    opKind: op ? op.kind : null,
  };
}

function culpritOfResource(
  ctx: DocContext,
  resource: NcmResource,
  index: number | null,
  describe: string,
): MgmtGuardCulprit {
  const op = opFor(ctx, resource.semKey);
  return {
    resource: resource.kind,
    semKey: resource.semKey,
    index,
    chain: null,
    describe,
    opSeq: op ? op.seq : null,
    opKind: op ? op.kind : null,
  };
}

/** A brand-neutral one-liner. The NCM carries fingerprints, never secrets
 *  (§8.2 / R10), so this string is safe in `command_audit` and in a log. */
export function describeFirewallRule(rule: NcmFirewallRule, chainKey?: string): string {
  const parts: string[] = [`chain=${chainKey ?? chainKeyOf(rule)}`, `action=${rule.action}`];
  if (rule.jumpTarget) parts.push(`jump-target=${rule.jumpTarget}`);
  const m = rule.match;
  if (m.protocol) parts.push(`protocol=${m.protocol}`);
  if (!m.srcAddress.includes('any')) parts.push(`src-address=${m.srcAddress.join(',')}`);
  if (!m.dstAddress.includes('any')) parts.push(`dst-address=${m.dstAddress.join(',')}`);
  if (m.dstPort) parts.push(`dst-port=${m.dstPort.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`)).join(',')}`);
  if (!m.inInterface.includes('any')) parts.push(`in-interface=${m.inInterface.join(',')}`);
  if (!m.outInterface.includes('any')) parts.push(`out-interface=${m.outInterface.join(',')}`);
  if (m.connectionState.length > 0) parts.push(`connection-state=${m.connectionState.join(',')}`);
  if (m.unmodeledMatch.length > 0) parts.push(`unmodelled:${m.unmodeledMatch.join(',')}`);
  if (rule.disabled) parts.push('disabled=yes');
  return parts.join(' ');
}

// ============================================================================
// Routing — does the reply still have a way home?
// ============================================================================

/**
 * Resolve the return path from the device to `ip`.
 *
 * MODELLING LIMIT, STATED: an L2TP client installs its peer route dynamically
 * and dynamic routes are STATE, so they are not in the NCM (§7.1). The engine
 * therefore reports `none` on a perfectly healthy box whose only path to the
 * CHR is that dynamic route. `none` is NOT a refusal — a refusal is `broken`,
 * or `ok` degrading to anything else. What `none -> none` does trigger, and
 * only when the plan actually edits routing, is `ROUTE_MODEL_BLIND`: we are
 * being asked to bless a routing change we cannot evaluate.
 */
function resolveReturnPath(
  ctx: DocContext,
  ip: string,
  depth = 0,
  used: ReadonlySet<string> = new Set(),
): RouteResolution {
  // 1. Connected: an enabled interface whose subnet contains the address.
  for (const iface of ctx.doc.resources.interfaces) {
    if (iface.disabled) continue;
    for (const addr of iface.addresses) {
      const net = parseCidr(addr.cidr);
      if (!net) continue;
      const width = net.version === 4 ? 32 : 128;
      if (net.prefix >= width) continue;      // a host address reaches nobody
      if (cidrContains(addr.cidr, ip)) {
        return {
          state: 'ok',
          via: `connected:${iface.name}`,
          egress: iface.name,
          detail: `${ip} is inside ${addr.cidr} on ${iface.name}`,
          culprit: null,
        };
      }
    }
  }

  // 2. Static routes covering the address, longest prefix then lowest distance.
  const candidates: { route: NcmRoute; index: number; prefix: number }[] = [];
  ctx.doc.resources.routes.forEach((route, index) => {
    if (route.disabled) return;
    if (used.has(route.semKey)) return;
    const net = parseCidr(route.dst);
    if (!net) return;
    if (!cidrContains(route.dst, ip)) return;
    candidates.push({ route, index, prefix: net.prefix });
  });
  candidates.sort((a, b) =>
    b.prefix - a.prefix || (a.route.distance ?? 1) - (b.route.distance ?? 1));

  for (const { route, index } of candidates) {
    const culprit = culpritOfResource(ctx, route, index, describeRoute(route));
    if (route.gateway === null) {
      return {
        state: 'broken',
        via: `route:${route.semKey}`,
        egress: null,
        detail: `${route.dst} is a blackhole route — the reply to ${ip} is discarded`,
        culprit,
      };
    }
    if (route.gateway.startsWith('iface:')) {
      const name = route.gateway.slice('iface:'.length);
      const iface = ctx.interfaces.get(name);
      if (iface && !iface.disabled) {
        return {
          state: 'ok',
          via: `route:${route.semKey}`,
          egress: name,
          detail: `${route.dst} via interface ${name}`,
          culprit: null,
        };
      }
      if (iface && iface.disabled) {
        return {
          state: 'broken',
          via: `route:${route.semKey}`,
          egress: name,
          detail: `${route.dst} goes out ${name}, which is disabled`,
          culprit,
        };
      }
      if (ctx.interfacesComplete) {
        return {
          state: 'broken',
          via: `route:${route.semKey}`,
          egress: null,
          detail: `${route.dst} goes out ${name}, which does not exist`,
          culprit,
        };
      }
      return {
        state: 'unknown',
        via: `route:${route.semKey}`,
        egress: name,
        detail: `${route.dst} goes out ${name}, absent from an incomplete interface collection`,
        culprit,
      };
    }
    if (route.gateway.startsWith('ip:')) {
      if (depth >= MAX_ROUTE_RECURSION) {
        return {
          state: 'unknown',
          via: `route:${route.semKey}`,
          egress: null,
          detail: `next-hop resolution for ${route.dst} exceeded ${MAX_ROUTE_RECURSION} levels`,
          culprit,
        };
      }
      const nextUsed = new Set(used);
      nextUsed.add(route.semKey);
      const hop = resolveReturnPath(ctx, route.gateway.slice('ip:'.length), depth + 1, nextUsed);
      if (hop.state === 'ok') {
        return {
          state: 'ok',
          via: `route:${route.semKey}`,
          egress: hop.egress,
          detail: `${route.dst} via ${route.gateway} (${hop.detail})`,
          culprit: null,
        };
      }
      if (hop.state === 'broken') return { ...hop, culprit: hop.culprit ?? culprit };
      // The next hop is presumably reachable through a route we do not model.
      return {
        state: 'unknown',
        via: `route:${route.semKey}`,
        egress: hop.egress,
        detail: `${route.dst} via ${route.gateway}, whose own path is not in the model`,
        culprit: null,
      };
    }
    return {
      state: 'unknown',
      via: `route:${route.semKey}`,
      egress: null,
      detail: `${route.dst} via an unresolved gateway ${route.gateway}`,
      culprit,
    };
  }

  return {
    state: 'none',
    via: null,
    egress: null,
    detail: `no modelled connected subnet or static route covers ${ip}`,
    culprit: null,
  };
}

function describeRoute(route: NcmRoute): string {
  const parts = [`dst-address=${route.dst}`];
  if (route.gateway) parts.push(`gateway=${route.gateway}`);
  else parts.push('gateway=<blackhole>');
  if (route.distance !== null) parts.push(`distance=${route.distance}`);
  if (route.table !== 'main') parts.push(`routing-table=${route.table}`);
  if (route.disabled) parts.push('disabled=yes');
  return parts.join(' ');
}

// ============================================================================
// NAT — a DNAT that captures the session is a lockout with extra steps
// ============================================================================

type NatState = 'clean' | 'hijack' | 'unknown';

interface NatVerdict { state: NatState; culprit: MgmtGuardCulprit | null; }

/**
 * Walk `prerouting` for the inbound probe. A `dstnat` / `redirect` / `netmap`
 * that definitely matches sends our management session to some other host or
 * port, which is indistinguishable from a drop as far as staying in control of
 * the box is concerned.
 */
function evaluateNat(ctx: DocContext, pkt: SyntheticPacket): NatVerdict {
  const rules = ctx.natChains.get('prerouting');
  if (!rules) return { state: 'clean', culprit: null };
  let sawUnknown: MgmtGuardCulprit | null = null;

  for (const { rule, index } of rules) {
    if (rule.disabled) continue;
    const m = matchPacket(ctx, rule.match, pkt);
    if (m === 'no') continue;
    const op = opFor(ctx, rule.semKey);
    const culprit: MgmtGuardCulprit = {
      resource: 'natRule',
      semKey: rule.semKey,
      index,
      chain: 'prerouting',
      describe: describeNatRule(rule),
      opSeq: op ? op.seq : null,
      opKind: op ? op.kind : null,
    };
    if (rule.action === 'dstnat' || rule.action === 'redirect' || rule.action === 'netmap') {
      if (m === 'yes') return { state: 'hijack', culprit };
      sawUnknown = sawUnknown ?? culprit;
      continue;
    }
    if (rule.action === 'accept' && m === 'yes') return { state: 'clean', culprit: null };
    if (rule.action === 'other') sawUnknown = sawUnknown ?? culprit;
  }
  return sawUnknown ? { state: 'unknown', culprit: sawUnknown } : { state: 'clean', culprit: null };
}

function describeNatRule(rule: NcmNatRule): string {
  const parts = [`chain=${chainKeyOf(rule)}`, `action=${rule.action}`];
  if (rule.toAddresses) parts.push(`to-addresses=${rule.toAddresses.join(',')}`);
  if (rule.toPorts) parts.push(`to-ports=${rule.toPorts.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`)).join(',')}`);
  const m = rule.match;
  if (!m.dstAddress.includes('any')) parts.push(`dst-address=${m.dstAddress.join(',')}`);
  if (m.dstPort) parts.push(`dst-port=${m.dstPort.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`)).join(',')}`);
  if (!m.inInterface.includes('any')) parts.push(`in-interface=${m.inInterface.join(',')}`);
  return parts.join(' ');
}

// ============================================================================
// Management services — the `/ip/service address=` lockout
// ============================================================================

interface ServiceState {
  /** At least one management service is enabled AND provably open to the peer. */
  definitelyOpen: boolean;
  /** At least one might be — `allowedFrom` carries a `ref:` we cannot expand. */
  maybeOpen: boolean;
  /** Something was modelled at all. Without this, "no service is open" would be
   *  indistinguishable from "the family does not model services". */
  anyManagementService: boolean;
  openNames: string[];
  culprit: MgmtGuardCulprit | null;
}

function managementServiceState(ctx: DocContext, peer: string): ServiceState {
  let definitelyOpen = false;
  let maybeOpen = false;
  let anyManagementService = false;
  const openNames: string[] = [];
  let culprit: MgmtGuardCulprit | null = null;

  ctx.doc.resources.services.forEach((svc, index) => {
    if (!MANAGEMENT_SERVICES.has(svc.service)) return;
    anyManagementService = true;
    if (svc.disabled || !svc.enabled) {
      culprit = culprit ?? culpritOfResource(ctx, svc, index, describeService(svc));
      return;
    }
    const reach = addressSelectorMatches(svc.allowedFrom, peer);
    if (reach === 'yes') { definitelyOpen = true; maybeOpen = true; openNames.push(svc.service); return; }
    if (reach === 'unknown') { maybeOpen = true; openNames.push(`${svc.service}?`); return; }
    culprit = culprit ?? culpritOfResource(ctx, svc, index, describeService(svc));
  });

  return { definitelyOpen, maybeOpen, anyManagementService, openNames, culprit };
}

function describeService(svc: NcmService): string {
  const parts = [`service=${svc.service}`, `enabled=${svc.enabled && !svc.disabled ? 'yes' : 'no'}`];
  if (svc.port !== null) parts.push(`port=${svc.port}`);
  if (!svc.allowedFrom.includes('any')) parts.push(`address=${svc.allowedFrom.join(',')}`);
  return parts.join(' ');
}

// ============================================================================
// Probes
// ============================================================================

/**
 * Which interface does the management session ride?
 *
 * `certain` is true only when exactly one candidate carries the management
 * address. When it is false the guard still probes — using the first candidate
 * in a stable order — because a probe that PROVES a drop is worth having even
 * on a guess, but it also records `TUNNEL_UNKNOWN`, which makes ACCEPT
 * unreachable. Prove a refusal on a guess: yes. Certify safety on a guess: no.
 */
function resolveTunnelInterface(
  observed: NcmDocument,
  facts: MgmtPathFacts,
): { name: string | null; certain: boolean } {
  const names = [...facts.tunnelInterfaces].sort();
  if (names.length === 0) return { name: null, certain: false };
  if (facts.tunnelIp) {
    const bearing = observed.resources.interfaces
      .filter((i) => names.includes(i.name))
      .filter((i) => i.addresses.some((a) => cidrContains(a.cidr, facts.tunnelIp as string)))
      .map((i) => i.name)
      .sort();
    if (bearing.length === 1) return { name: bearing[0], certain: true };
    if (bearing.length > 1) return { name: bearing[0], certain: false };
  }
  return { name: names[0], certain: names.length === 1 };
}

/**
 * The ports worth probing: the ones a management service listens on TODAY.
 *
 * Derived from the observed document, because the question is whether the
 * session we currently hold survives. Falls back to the well-known set when the
 * family models no service — a fallback that is only ever reached alongside a
 * `COVERAGE_INCOMPLETE`, so it can never be the sole basis of an ACCEPT.
 */
function probePorts(observed: NcmDocument, extra: readonly number[]): number[] {
  const ports = new Set<number>();
  for (const svc of observed.resources.services) {
    if (!MANAGEMENT_SERVICES.has(svc.service)) continue;
    if (svc.disabled || !svc.enabled) continue;
    ports.add(svc.port ?? MANAGEMENT_PORTS[svc.service] ?? 22);
  }
  if (ports.size === 0) for (const p of Object.values(MANAGEMENT_PORTS)) ports.add(p);
  for (const p of extra) if (Number.isInteger(p) && p > 0 && p < 65536) ports.add(p);
  return [...ports].sort((a, b) => a - b).slice(0, MAX_PROBE_PORTS);
}

function buildProbes(opts: {
  peer: string;
  mgmt: string;
  iface: string;
  ports: readonly number[];
}): SyntheticPacket[] {
  const out: SyntheticPacket[] = [];
  for (const port of opts.ports) {
    out.push({
      id: `in:new:tcp/${port}`,
      description: `new TCP session ${opts.peer} -> ${opts.mgmt}:${port} arriving on ${opts.iface}`,
      chain: 'input',
      interfaceName: opts.iface,
      protocol: 'tcp',
      srcAddress: opts.peer,
      dstAddress: opts.mgmt,
      srcPort: EPHEMERAL_PORT,
      dstPort: port,
      connectionState: 'new',
      tcp: SYN,
    });
    out.push({
      id: `in:established:tcp/${port}`,
      description: `established TCP ${opts.peer} -> ${opts.mgmt}:${port} arriving on ${opts.iface}`,
      chain: 'input',
      interfaceName: opts.iface,
      protocol: 'tcp',
      srcAddress: opts.peer,
      dstAddress: opts.mgmt,
      srcPort: EPHEMERAL_PORT,
      dstPort: port,
      connectionState: 'established',
      tcp: ACK,
    });
    out.push({
      id: `out:established:tcp/${port}`,
      description: `reply ${opts.mgmt}:${port} -> ${opts.peer} leaving through ${opts.iface}`,
      chain: 'output',
      interfaceName: opts.iface,
      protocol: 'tcp',
      srcAddress: opts.mgmt,
      dstAddress: opts.peer,
      srcPort: port,
      dstPort: EPHEMERAL_PORT,
      connectionState: 'established',
      tcp: ACK,
    });
  }
  return out;
}

// ============================================================================
// Plan projection — building the TARGET document
// ============================================================================

export interface ProjectionResult {
  doc: NcmDocument;
  /** FALSE the moment one op could not be simulated faithfully. A target the
   *  guard is not sure it built correctly may not produce an ACCEPT. */
  complete: boolean;
  warnings: string[];
}

/**
 * Apply a plan to the observed document, in memory, to obtain the state the
 * device would be in afterwards.
 *
 * Why here and not in the planner: the guard is the only consumer that needs
 * the FULL post-state, including everything the plan does not touch. A target
 * built from the rendered template alone would be missing every rule outside
 * the claimed sections — and on a taken-over fleet that is most of the
 * firewall, which would make the guard reason about a device that does not
 * exist.
 *
 * Ops are applied in `seq` order, exactly as the executor will apply them,
 * because `move` targets an index in the SIMULATED list (§4.5) and any other
 * order produces a different final chain.
 */
export function projectPlan(observed: NcmDocument, ops: readonly PlanOp[]): ProjectionResult {
  const doc = JSON.parse(JSON.stringify(observed)) as NcmDocument;
  const warnings: string[] = [];
  let complete = true;

  const sorted = [...ops].sort((a, b) => a.seq - b.seq);
  for (const op of sorted) {
    if (op.kind === 'verify') continue;
    if (op.kind === 'blocked') {
      // A blocked op changes nothing on the device, so the projection stays
      // faithful. It is still worth a warning: the plan the operator reads is
      // not the plan they may think they read.
      warnings.push(`op #${op.seq}: blocked (${op.blockedReason ?? 'no reason recorded'}), nothing simulated`);
      continue;
    }

    const key = RESOURCE_KIND_TO_COLLECTION[op.resource] as keyof NcmDocument['resources'];
    const list = doc.resources[key] as unknown as NcmResource[];
    if (!Array.isArray(list)) {
      complete = false;
      warnings.push(`op #${op.seq}: resource kind ${op.resource} has no collection in the document`);
      continue;
    }
    const at = list.findIndex((r) => r.semKey === op.semKey);

    switch (op.kind) {
      case 'create': {
        const after = asResource(op.after);
        if (!after) { complete = false; warnings.push(`op #${op.seq}: create with no usable payload`); break; }
        if (at >= 0) list[at] = after; else list.push(after);
        break;
      }
      case 'update': {
        const after = asResource(op.after);
        if (!after) { complete = false; warnings.push(`op #${op.seq}: update with no usable payload`); break; }
        if (at < 0) { complete = false; warnings.push(`op #${op.seq}: update targets ${op.semKey}, absent from the observed document`); list.push(after); break; }
        list[at] = after;
        break;
      }
      case 'delete': {
        if (at < 0) { complete = false; warnings.push(`op #${op.seq}: delete targets ${op.semKey}, absent from the observed document`); break; }
        list.splice(at, 1);
        break;
      }
      case 'enable':
      case 'disable': {
        if (at < 0) { complete = false; warnings.push(`op #${op.seq}: ${op.kind} targets ${op.semKey}, absent from the observed document`); break; }
        (list[at] as { disabled: boolean }).disabled = op.kind === 'disable';
        break;
      }
      case 'move': {
        if (at < 0 || op.targetIndex === null) {
          complete = false;
          warnings.push(`op #${op.seq}: move of ${op.semKey} could not be simulated`);
          break;
        }
        if (!moveWithinChain(list, at, op.targetIndex, op.chain)) {
          complete = false;
          warnings.push(`op #${op.seq}: move of ${op.semKey} to index ${op.targetIndex} is out of range for chain ${op.chain ?? '?'}`);
        }
        break;
      }
      default:
        complete = false;
        warnings.push(`op #${op.seq}: unknown op kind ${String(op.kind)}`);
        break;
    }
  }

  return { doc, complete, warnings };
}

function asResource(v: unknown): NcmResource | null {
  if (!v || typeof v !== 'object') return null;
  const r = v as { kind?: unknown; semKey?: unknown };
  if (typeof r.kind !== 'string' || typeof r.semKey !== 'string') return null;
  return v as NcmResource;
}

/**
 * Reposition a rule inside its own chain while leaving every other chain's
 * relative order untouched. The document interleaves chains in one array;
 * `targetIndex` is an index in the CHAIN, per `PlanOp.targetIndex`.
 */
function moveWithinChain(
  list: NcmResource[],
  from: number,
  targetIndex: number,
  chain: string | null,
): boolean {
  const chainOf = (r: NcmResource): string | null => {
    if (r.kind !== 'firewallRule' && r.kind !== 'natRule' && r.kind !== 'qosRule') return null;
    if (r.kind === 'qosRule') return null;
    return chainKeyOf(r);
  };
  const wanted = chain ?? chainOf(list[from]);
  const slots: number[] = [];
  list.forEach((r, i) => { if (chainOf(r) === wanted) slots.push(i); });
  const posInChain = slots.indexOf(from);
  if (posInChain < 0) return false;
  if (targetIndex < 0 || targetIndex >= slots.length) return false;

  const sub = slots.map((i) => list[i]);
  const [moved] = sub.splice(posInChain, 1);
  sub.splice(targetIndex, 0, moved);
  slots.forEach((slot, i) => { list[slot] = sub[i]; });
  return true;
}

// ============================================================================
// THE GUARD
// ============================================================================

export function evaluateMgmtPath(input: MgmtGuardInput): MgmtGuardResult {
  const reasons: MgmtGuardReason[] = [];
  const push = (
    code: MgmtGuardReasonCode,
    message: string,
    culprit: MgmtGuardCulprit | null = null,
    probe: string | null = null,
  ): void => {
    reasons.push({ code, effect: REASON_EFFECT[code], probe, message, culprit });
  };

  const policy = input.chainPolicy ?? defaultChainPolicy(input.family);
  const opIndex = new Map<string, PlanOp>();
  // FIRST op wins, not last. When a plan creates a rule and then moves it, the
  // op an operator needs to look at is the one that introduced the record; the
  // move is a consequence. A `Map.set` per op would name the last one and send
  // them to the wrong line.
  for (const op of input.ops ?? []) {
    if (op.kind === 'verify') continue;
    if (!opIndex.has(op.semKey)) opIndex.set(op.semKey, op);
  }

  const before = buildContext(input.observed, 'observed', policy, opIndex);
  const after = buildContext(input.target, 'target', policy, opIndex);

  // ── 0. Blindness that is a property of the DOCUMENTS ─────────────────────
  //
  // Checked first and unconditionally, so that no later branch can return
  // early and skip them. §6.4, literally.
  checkDocumentBlindness(input.observed, 'observed', input.facts, push);
  checkDocumentBlindness(input.target, 'target', input.facts, push);
  if (input.projectionComplete === false) {
    push('PROJECTION_INCOMPLETE',
      'The guard could not simulate every operation of this plan, so the state it analysed is ' +
      'not certainly the state the device would reach. No ACCEPT can be based on it.');
  }

  // ── 1. The facts the probe is made of ────────────────────────────────────
  const tunnel = resolveTunnelInterface(input.observed, input.facts);
  if (!tunnel.certain) {
    push('TUNNEL_UNKNOWN',
      tunnel.name === null
        ? 'No interface of this device could be identified as the one carrying the management ' +
          'session. The guard has nothing to trace a packet through.'
        : `Several interfaces could carry the management session; the guard traced the packet ` +
          `through "${tunnel.name}" only. A refusal below is still a refusal, but no ACCEPT can ` +
          'be granted on a guessed path.');
  }
  const mgmt = input.facts.tunnelIp;
  if (mgmt === null) {
    push('MGMT_ADDRESS_UNKNOWN',
      'This device has no recorded management address, so the guard cannot address a packet to ' +
      'it. Dial the device once before applying a change to it.');
  }
  const peer = input.peerAddress;
  if (peer === null) {
    push('PEER_ADDRESS_UNKNOWN',
      'The address of the concentrator the management session comes from is not known to the ' +
      'guard, so it cannot build the packet it is supposed to trace.');
  }

  const ports = probePorts(input.observed, input.extraPorts ?? []);
  const probes: ProbeReport[] = [];
  let routing: { before: RouteResolution; after: RouteResolution } = {
    before: { state: 'unknown', via: null, egress: null, detail: 'not evaluated', culprit: null },
    after: { state: 'unknown', via: null, egress: null, detail: 'not evaluated', culprit: null },
  };

  // ── 2. Everything below needs the three coordinates above ────────────────
  if (peer !== null && mgmt !== null && tunnel.name !== null) {
    const iface = tunnel.name;

    // 2a. Interface fate. Checked before the walk: a chain that accepts a
    //     packet on an interface that no longer exists accepts nothing.
    checkTunnelInterface(before, after, input.facts, push);

    // 2b. The management address itself.
    checkManagementAddress(before, after, mgmt, push);
    checkManagementIdentity(before, after, peer, push);

    // 2c. Management services and their address restriction.
    checkManagementServices(before, after, peer, push);

    // 2d. The walks.
    //
    // A probe only carries information when the SAME packet is accepted today.
    // A management port that is firewalled off right now (ssh restricted to the
    // LAN while we administer over the API, say) is a port we do not use, and
    // reporting its fate as a regression would flood the operator with refusals
    // about sessions nobody has.
    const inboundBaseline: PacketOutcome[] = [];
    let baselineDropCulprit: MgmtGuardCulprit | null = null;

    for (const pkt of buildProbes({ peer, mgmt, iface, ports })) {
      const b = evaluateChain(before, pkt);
      const a = evaluateChain(after, pkt);
      probes.push({ id: pkt.id, description: pkt.description, before: b.outcome, after: a.outcome });
      if (pkt.chain === 'input') {
        inboundBaseline.push(b.outcome);
        baselineDropCulprit = baselineDropCulprit ?? b.acc.dropCulprits[0] ?? null;
      }

      const dropCode: MgmtGuardReasonCode = pkt.chain === 'input' ? 'INPUT_DROP' : 'OUTPUT_DROP';

      // This packet does not get through TODAY. Whatever the plan does to it is
      // not a regression, and blaming the plan for it would be a false refusal
      // — the fastest way to get a guard switched off is to make it cry wolf.
      // The aggregate case (nothing at all gets through today) is handled once,
      // after the loop, as a contradiction in the MODEL rather than a fault in
      // the plan.
      if (b.outcome === 'drop') continue;

      if (a.outcome === 'drop') {
        if (a.byPolicy && a.acc.dropCulprits.length === 0) {
          push('CHAIN_POLICY_DROP',
            `No rule decides the fate of the ${pkt.description}, and the default policy of the ` +
            `"${pkt.chain}" chain on this platform denies it. Applying this plan ends the ` +
            'management session.',
            null, pkt.id);
        } else {
          const culprit = a.acc.dropCulprits[0] ?? null;
          push(dropCode,
            `After this plan, the ${pkt.description} is DENIED` +
            (culprit ? ` by ${culprit.describe}` : '') +
            (culprit && culprit.opSeq !== null
              ? ` — operation #${culprit.opSeq} (${culprit.opKind}) of this plan.`
              : '.') +
            (b.outcome === 'accept'
              ? ' The same packet is accepted by the configuration currently on the device.'
              : ''),
            culprit, pkt.id);
        }
      } else if (a.outcome === 'unknown') {
        const culprit = a.acc.ambiguous[0] ?? a.acc.unknownAction[0] ?? null;
        if (a.acc.unknownAction.length > 0) {
          push('UNKNOWN_ACTION',
            `The ${pkt.description} meets ${a.acc.unknownAction[0].describe}, whose action this ` +
            'model does not understand. The guard cannot say what happens to the session.',
            a.acc.unknownAction[0], pkt.id);
        }
        if (a.acc.unmodeled.length > 0) {
          push('UNMODELED_MATCH',
            `The ${pkt.description} passes ${a.acc.unmodeled[0].describe}, which carries a ` +
            'selector this model does not read. §6.4 forbids concluding on that path.',
            a.acc.unmodeled[0], pkt.id);
        }
        if (a.acc.unknownAction.length === 0 && a.acc.unmodeled.length === 0) {
          push('AMBIGUOUS_RULE',
            `The fate of the ${pkt.description} cannot be decided: ` +
            (culprit ? `${culprit.describe} may or may not match it.` : 'the chain admits more than one outcome.') +
            ' The guard does not conclude on a maybe.',
            culprit, pkt.id);
        }
        if (a.byPolicy && policy[pkt.chain] === 'unknown') {
          push('CHAIN_POLICY_UNKNOWN',
            `No rule decides the fate of the ${pkt.description} and the default policy of this ` +
            'platform\'s firewall has not been modelled for this brand (§8.3). The guard will ' +
            'not invent one.',
            null, pkt.id);
        }
      } else if (a.outcome === 'accept' && a.acc.unmodeled.length > 0) {
        // Accepted, but only because a rule we cannot fully read did not stop
        // it. §6.4 again: a path with an unread selector on it is not proved.
        push('UNMODELED_MATCH',
          `The ${pkt.description} is accepted, but it passes ${a.acc.unmodeled[0].describe}, ` +
          'which carries a selector this model does not read. The path is not proved.',
          a.acc.unmodeled[0], pkt.id);
      }

      // 2e. NAT hijack, on the inbound leg only.
      if (pkt.chain === 'input') {
        const natB = evaluateNat(before, pkt);
        const natA = evaluateNat(after, pkt);
        if (natA.state === 'hijack' && natB.state !== 'hijack') {
          push('NAT_HIJACK',
            `After this plan, ${natA.culprit?.describe ?? 'a prerouting NAT rule'} captures the ` +
            `${pkt.description} and sends it elsewhere. The session would not reach the router.`,
            natA.culprit, pkt.id);
        } else if (natA.state === 'unknown' && natB.state === 'clean') {
          push('AMBIGUOUS_RULE',
            `A prerouting NAT rule (${natA.culprit?.describe ?? 'unnamed'}) may or may not ` +
            `capture the ${pkt.description}. The guard does not conclude on a maybe.`,
            natA.culprit, pkt.id);
        }
      }
    }

    // 2e-bis. THE MODEL CONTRADICTS REALITY.
    //
    // Not "one port is closed" — EVERY inbound management probe is definitively
    // denied by the configuration that is on the box right now, while we are
    // demonstrably talking to it: we are holding one of its snapshots. Something
    // in the model, the collection or the recorded addresses is wrong.
    //
    // The honest move is neither to blame the plan (it did not cause this) nor
    // to bless it (the engine provably does not describe this box). It is to say
    // so and refuse to conclude — INDETERMINATE, which still blocks the apply.
    if (inboundBaseline.length > 0 && inboundBaseline.every((o) => o === 'drop')) {
      push('BASELINE_CONTRADICTION',
        `The configuration currently on the device denies every management probe the guard ` +
        `built (${ports.join(', ')} from ${peer} to ${mgmt} over ${iface})` +
        (baselineDropCulprit ? `, e.g. ${baselineDropCulprit.describe}` : '') +
        ', yet the platform is talking to this device. The forwarding model therefore does not ' +
        'describe this box correctly, and no verdict computed from it can be trusted.',
        baselineDropCulprit);
    }

    // 2f. The way home.
    routing = {
      before: resolveReturnPath(before, peer),
      after: resolveReturnPath(after, peer),
    };
    checkRouting(routing.before, routing.after, input.ops ?? [], peer, mgmt, input.facts, push);
  }

  // ── 3. Fold ──────────────────────────────────────────────────────────────
  const deduped = dedupeReasons(reasons);
  const hasReject = deduped.some((r) => r.effect === 'reject');
  const hasBlind = deduped.some((r) => r.effect === 'indeterminate');
  // PROOF BEATS BLINDNESS. See the header.
  const verdict: MgmtGuardVerdict = hasReject ? 'REJECT' : hasBlind ? 'INDETERMINATE' : 'ACCEPT';

  const culpritOpSeqs = [...new Set(
    deduped.map((r) => r.culprit?.opSeq).filter((s): s is number => typeof s === 'number'),
  )].sort((a, b) => a - b);

  return {
    verdict,
    planVerdict: toPlanVerdict(verdict),
    reasons: deduped,
    probes,
    routing,
    culpritOpSeqs,
    summary: summarize(verdict, deduped, probes),
    analysed: {
      peerAddress: peer,
      managementAddress: mgmt,
      tunnelInterface: tunnel.name,
      tunnelInterfaceCertain: tunnel.certain,
      ports,
      chainPolicy: policy,
    },
  };
}

/** The guard's verdict in the vocabulary the plan envelope stores. */
export function toPlanVerdict(v: MgmtGuardVerdict): MgmtPathVerdict {
  const out: MgmtPathVerdict = v === 'ACCEPT' ? 'accept' : v === 'REJECT' ? 'veto' : 'indeterminate';
  // Belt and braces: the two vocabularies are declared in different packages.
  return MGMT_PATH_VERDICTS.includes(out) ? out : 'indeterminate';
}

/** Anything that is not ACCEPT stops a plan unless a human overrides it on the
 *  record. There is exactly one definition of that, and it is here. */
export function blocksApply(v: MgmtGuardVerdict): boolean {
  return v !== 'ACCEPT';
}

// ============================================================================
// The individual checks
// ============================================================================

type Push = (
  code: MgmtGuardReasonCode,
  message: string,
  culprit?: MgmtGuardCulprit | null,
  probe?: string | null,
) => void;

function checkDocumentBlindness(
  doc: NcmDocument,
  label: 'observed' | 'target',
  facts: MgmtPathFacts,
  push: Push,
): void {
  const kinds = [...FORWARDING_KINDS];
  // A tunnel interface that rides a VLAN makes the VLAN table forwarding-
  // relevant for THIS device. Adding `vlan` unconditionally would demand
  // `complete` on a kind most families declare `unsupported`, and turn every
  // verdict into INDETERMINATE for nothing (open arbitration Q8).
  const ridesVlan = doc.resources.interfaces.some(
    (i) => facts.tunnelInterfaces.has(i.name) && i.parent !== null &&
      doc.resources.interfaces.some((p) => p.name === i.parent && p.type === 'vlan'),
  );
  if (ridesVlan) kinds.push('vlan');

  for (const kind of kinds) {
    const cov = coverageOf(doc.coverage, kind);
    if (cov.state === 'complete') continue;
    push('COVERAGE_INCOMPLETE',
      `The ${label} configuration does not claim a complete collection of ${kind} ` +
      `(coverage: ${cov.state}${cov.reason ? ` — ${cov.reason}` : ''}). The guard cannot prove ` +
      'anything about a firewall it has only partly read.');
  }

  for (const section of doc.unmodeled) {
    if (!section.forwardingRelevant) continue;
    push('UNMODELED_FORWARDING_SECTION',
      `The ${label} configuration contains "${section.section}" (${section.lineCount} lines), a ` +
      'section that can influence forwarding and that this model does not read. §6.4 forbids an ' +
      'ACCEPT while it is there.');
  }

  if (doc.orderAnalysis !== 'full') {
    push('ORDER_ANALYSIS_PARTIAL',
      `The rule-order analysis of the ${label} configuration is "${doc.orderAnalysis}", not ` +
      '"full". The guard cannot rely on the chain order it was given.');
  }
}

function checkTunnelInterface(
  before: DocContext,
  after: DocContext,
  facts: MgmtPathFacts,
  push: Push,
): void {
  for (const name of [...facts.tunnelInterfaces].sort()) {
    const wasThere = before.interfaces.get(name);
    if (!wasThere || wasThere.disabled) continue;      // nothing to lose
    const now = after.interfaces.get(name);
    if (!now) {
      const idx = before.doc.resources.interfaces.findIndex((i) => i.name === name);
      push('TUNNEL_CRITICAL',
        `This plan removes "${name}", the interface the management session rides. The device ` +
        'would be unreachable the moment the change lands.',
        culpritOfResource(before, wasThere, idx < 0 ? null : idx, `interface ${name} (${wasThere.type})`));
      continue;
    }
    if (now.disabled) {
      const idx = after.doc.resources.interfaces.findIndex((i) => i.name === name);
      push('TUNNEL_CRITICAL',
        `This plan disables "${name}", the interface the management session rides. The device ` +
        'would be unreachable the moment the change lands.',
        culpritOfResource(after, now, idx < 0 ? null : idx, `interface ${name} (${now.type}) disabled=yes`));
    }
  }
}

function checkManagementAddress(
  before: DocContext,
  after: DocContext,
  mgmt: string,
  push: Push,
): void {
  const bearer = (ctx: DocContext): NcmInterface | null => {
    for (const iface of ctx.doc.resources.interfaces) {
      if (iface.disabled) continue;
      if (iface.addresses.some((a) => cidrContains(a.cidr, mgmt))) return iface;
    }
    return null;
  };
  const was = bearer(before);
  // Nothing statically carried the address before (an L2TP client learns it
  // from the concentrator). There is no regression to measure.
  if (!was) return;
  const now = bearer(after);
  if (now) return;
  const idx = before.doc.resources.interfaces.findIndex((i) => i.name === was.name);
  push('MGMT_ADDRESS_LOST',
    `The management address ${mgmt} is configured on "${was.name}" today and on no enabled ` +
    'interface after this plan. The platform would have nothing left to talk to.',
    culpritOfResource(before, was, idx < 0 ? null : idx, `interface ${was.name} carries ${mgmt}`));
}

function checkManagementServices(
  before: DocContext,
  after: DocContext,
  peer: string,
  push: Push,
): void {
  const b = managementServiceState(before, peer);
  const a = managementServiceState(after, peer);
  if (!b.anyManagementService) return;      // the family models no service; nothing to compare
  if (!b.definitelyOpen && !b.maybeOpen) return;   // already closed before the plan

  if (!a.maybeOpen) {
    push('MGMT_SERVICE_LOST',
      `After this plan no management service (${[...MANAGEMENT_SERVICES].join(', ')}) is left ` +
      `enabled and reachable from ${peer}. Today ${b.openNames.join(', ') || 'at least one'} ` +
      'accepts the platform.',
      a.culprit);
    return;
  }
  if (b.definitelyOpen && !a.definitelyOpen) {
    push('AMBIGUOUS_RULE',
      `After this plan, whether any management service still accepts ${peer} depends on an ` +
      'address object this model does not expand. The guard will not assume it still contains us.',
      a.culprit);
  }
}

/**
 * Groups that can ACT, not merely look. A read-only account keeps the session
 * alive and cannot repair anything, which for this guard's purpose is the same
 * as no account at all: the plan that locked us out cannot be undone.
 *
 * Brand roles outside this set are `unknown`, never `no` — a Vigor
 * administrator role we have not catalogued is not evidence of a demotion.
 */
const WRITE_CAPABLE_GROUPS = new Set(['full', 'write', 'admin', 'administrator']);
const READ_ONLY_GROUPS = new Set(['read', 'readonly', 'read-only', 'guest', 'monitor']);

interface IdentityState {
  /** The family models local users at all. False = nothing to compare. */
  modelled: boolean;
  /** Enabled, write-capable, and `allowedFrom` provably accepts the peer. */
  definitelyUsable: string[];
  /** Not excluded, but one of the two facts is `unknown`. */
  maybeUsable: string[];
}

function managementIdentityState(ctx: DocContext, peer: string): IdentityState {
  const users = ctx.doc.resources.localUsers;
  const state: IdentityState = { modelled: users.length > 0, definitelyUsable: [], maybeUsable: [] };

  for (const u of users) {
    if (u.disabled) continue;

    const group = (u.group ?? '').trim().toLowerCase();
    const groupOk: Tri = READ_ONLY_GROUPS.has(group)
      ? 'no'
      : WRITE_CAPABLE_GROUPS.has(group)
        ? 'yes'
        : 'unknown';
    if (groupOk === 'no') continue;

    const fromOk = addressSelectorMatches(u.allowedFrom, peer);
    if (fromOk === 'no') continue;

    if (groupOk === 'yes' && fromOk === 'yes') state.definitelyUsable.push(u.username);
    else state.maybeUsable.push(u.username);
  }
  return state;
}

/**
 * K2's fourth coordinate — THE ONE THE FILE WAS MISSING.
 *
 * ┌───────────────────────────────────────────────────────────────────────────┐
 * │ The other three checks prove the PACKET arrives: the tunnel is up, the    │
 * │ address is held, a service listens and accepts the peer. None of them     │
 * │ asks whether an IDENTITY survives to use it. A plan that removes the last │
 * │ account ObliWAN logs in with leaves every one of them green — and leaves  │
 * │ a router that forwards perfectly and that nobody can enter.               │
 * │                                                                          │
 * │ `localUser` is deliberately still OUT of `FORWARDING_KINDS`: demanding    │
 * │ `complete` coverage on a kind most families declare `unsupported` would   │
 * │ turn every verdict INDETERMINATE, which is Q8 — the failure mode where    │
 * │ the confirmation click becomes reflex. So this check is SILENT when the   │
 * │ family models no accounts, and speaks only when it can compare.           │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
function checkManagementIdentity(
  before: DocContext,
  after: DocContext,
  peer: string,
  push: Push,
): void {
  const b = managementIdentityState(before, peer);
  const a = managementIdentityState(after, peer);

  if (!b.modelled) return;                                   // nothing to compare
  if (b.definitelyUsable.length === 0 && b.maybeUsable.length === 0) return;  // none before either

  if (a.definitelyUsable.length === 0 && a.maybeUsable.length === 0) {
    push('MGMT_IDENTITY_LOST',
      `After this plan no enabled local account is left that could log in from ${peer} and act. ` +
      `Today ${[...b.definitelyUsable, ...b.maybeUsable].join(', ')} could. The packet would ` +
      'still arrive and nobody would be able to use it — the box routes and cannot be entered.',
      null);
    return;
  }
  if (b.definitelyUsable.length > 0 && a.definitelyUsable.length === 0) {
    push('MGMT_IDENTITY_UNKNOWN',
      `After this plan, whether any account can still act from ${peer} depends on a group name ` +
      'or an address object this model does not resolve. Candidates left: ' +
      `${a.maybeUsable.join(', ')}. The guard will not assume one of them still works.`,
      null);
  }
}

function checkRouting(
  before: RouteResolution,
  after: RouteResolution,
  ops: readonly PlanOp[],
  peer: string,
  mgmt: string,
  facts: MgmtPathFacts,
  push: Push,
): void {
  // THE SILENT ONE, checked first because `state` alone never reveals it.
  // Deleting the specific route to the concentrator does not remove a route:
  // the reply falls onto the default route and leaves through the WAN, where a
  // private next hop dies at the first ISP hop. Both resolutions say `ok`; only
  // the egress interface changed, and it changed off the tunnel.
  if (
    before.state === 'ok' && after.state === 'ok' &&
    before.egress !== null && after.egress !== null &&
    before.egress !== after.egress &&
    facts.tunnelInterfaces.has(before.egress) && !facts.tunnelInterfaces.has(after.egress)
  ) {
    push('NO_ROUTE',
      `Today the reply to ${peer} leaves through the tunnel interface "${before.egress}" ` +
      `(${before.detail}). After this plan it would leave through "${after.egress}" instead ` +
      `(${after.detail}) — the management session would not come back down the tunnel.`,
      after.culprit ?? before.culprit);
    return;
  }

  if (before.state === 'ok' && (after.state === 'broken' || after.state === 'none')) {
    push('NO_ROUTE',
      `Today the reply to ${peer} leaves through ${before.via ?? 'a modelled path'} ` +
      `(${before.detail}). After this plan, ${after.detail}. The device would answer nothing.`,
      after.culprit ?? before.culprit);
    return;
  }
  if (before.state !== 'broken' && after.state === 'broken') {
    push('NO_ROUTE',
      `After this plan the return path to ${peer} is dead: ${after.detail}.`,
      after.culprit);
    return;
  }
  if (before.state === 'ok' && after.state === 'unknown') {
    push('ROUTE_MODEL_BLIND',
      `Today the reply to ${peer} has a modelled path; after this plan the guard can no longer ` +
      `resolve it (${after.detail}). It will not call that safe.`,
      after.culprit);
    return;
  }
  if (before.state === 'none' && after.state === 'none') {
    // The normal, healthy MikroTik case: the peer route is dynamic and is not
    // in the NCM. Silent — UNLESS the plan is editing routing, in which case we
    // are being asked to bless a change to something we cannot see.
    const culprit = routingOp(ops, peer, mgmt);
    if (culprit) {
      push('ROUTE_MODEL_BLIND',
        `The return path to ${peer} is not represented in this device's model (it is a dynamic ` +
        `route), and this plan edits routing — ${culprit.describe}. The guard cannot tell ` +
        'whether the way home survives.',
        culprit);
    }
  }
}

/**
 * A plan op that edits routing in a way the guard would need to understand.
 *
 * Deliberately narrow: adding a static route to a LAN subnet is not a reason to
 * blind the verdict, deleting one or touching the default route is.
 */
function routingOp(ops: readonly PlanOp[], peer: string, mgmt: string): MgmtGuardCulprit | null {
  for (const op of ops) {
    if (op.resource !== 'route') continue;
    if (op.kind === 'verify' || op.kind === 'blocked') continue;
    const r = asResource(op.after) ?? asResource(op.before);
    const dst = r && r.kind === 'route' ? r.dst : null;
    const dangerous =
      op.kind === 'delete' || op.kind === 'disable' || op.kind === 'move' ||
      (dst !== null && (dst === '0.0.0.0/0' || dst === '::/0' ||
        cidrContains(dst, peer) || cidrContains(dst, mgmt)));
    if (!dangerous) continue;
    return {
      resource: 'route',
      semKey: op.semKey,
      index: null,
      chain: null,
      describe: r && r.kind === 'route'
        ? `${op.kind} ${describeRoute(r)}`
        : `${op.kind} route ${op.semKey}`,
      opSeq: op.seq,
      opKind: op.kind,
    };
  }
  return null;
}

// ============================================================================
// Presentation
// ============================================================================

function dedupeReasons(reasons: readonly MgmtGuardReason[]): MgmtGuardReason[] {
  const seen = new Set<string>();
  const out: MgmtGuardReason[] = [];
  for (const r of reasons) {
    const key = `${r.code}|${r.culprit?.semKey ?? ''}|${r.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  // Proofs first: the operator must read WHY it is refused before reading what
  // else the guard could not see.
  return out.sort((a, b) => {
    if (a.effect !== b.effect) return a.effect === 'reject' ? -1 : 1;
    return a.code.localeCompare(b.code);
  });
}

function summarize(
  verdict: MgmtGuardVerdict,
  reasons: readonly MgmtGuardReason[],
  probes: readonly ProbeReport[],
): string {
  if (verdict === 'ACCEPT') {
    return `Management-Path Guard: ACCEPT — ${probes.length} synthetic probe(s) still reach the ` +
      'device after this plan, and the return path survives.';
  }
  const head = reasons[0];
  const others = reasons.length - 1;
  const tail = others > 0 ? ` (+${others} further finding${others > 1 ? 's' : ''})` : '';
  if (verdict === 'REJECT') {
    return `Management-Path Guard: REJECT — ${head?.message ?? 'the management path does not survive this plan.'}${tail}`;
  }
  return `Management-Path Guard: INDETERMINATE — ${head?.message ?? 'the guard could not prove the management path survives.'}` +
    `${tail} INDETERMINATE is not ACCEPT: applying anyway requires an explicit, recorded override.`;
}

// ============================================================================
// Convenience: plan -> verdict, in one call
// ============================================================================

export interface GuardPlanInput {
  observed: NcmDocument;
  ops: readonly PlanOp[];
  facts: MgmtPathFacts;
  peerAddress: string | null;
  family?: DeviceFamily | null;
  chainPolicy?: ChainPolicy;
  extraPorts?: readonly number[];
}

/**
 * Project the plan onto the observed document and run the guard over the
 * result. This is the entry point a caller should use: it is the only one that
 * cannot forget to mark an incompletely simulated projection.
 */
export function guardPlan(input: GuardPlanInput): MgmtGuardResult & { projection: ProjectionResult } {
  const projection = projectPlan(input.observed, input.ops);
  const result = evaluateMgmtPath({
    observed: input.observed,
    target: projection.doc,
    facts: input.facts,
    peerAddress: input.peerAddress,
    ops: input.ops,
    family: input.family,
    chainPolicy: input.chainPolicy,
    projectionComplete: projection.complete,
    extraPorts: input.extraPorts,
  });
  return { ...result, projection };
}

export const mgmtPathGuard = {
  evaluateMgmtPath,
  guardPlan,
  projectPlan,
  toPlanVerdict,
  blocksApply,
  defaultChainPolicy,
};
