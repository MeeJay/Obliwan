// ============================================================================
// ObliWAN — risk scoring for a PlanOp, and the `tunnelCritical` vocabulary
// ============================================================================
//
// PURE. No database, no I/O, no clock. Everything this file needs arrives in
// `MgmtPathFacts`, which the planner builds once per device from the OBSERVED
// document plus `devices.tunnel_ip`. That is the only reason the classification
// below can be unit-tested against fixtures instead of against a router.
//
// ┌─ WHAT THIS FILE IS FOR, AND WHAT IT IS NOT ──────────────────────────────┐
// │ It answers "how dangerous is this operation" and "does it touch the      │
// │ path we administer this box through".                                    │
// │                                                                          │
// │ It does NOT answer "will the management path survive". That is the       │
// │ Management-Path Guard (K2, `mgmtPathGuard.ts`), which needs a forwarding  │
// │ engine over the TARGET NCM. `tunnelCritical` is the SET OF CANDIDATES     │
// │ K2 proves something about; a `false` here means "K2 has nothing to look   │
// │ at", never "this change is safe".                                        │
// │                                                                          │
// │ Consequence, and it is deliberate: nothing in THIS file may ever produce  │
// │ `mgmtPathVerdict: 'accept'`. Only `mgmtPathGuard.evaluateMgmtPath` can,   │
// │ and only when it has proved it; every other path is the fail-closed       │
// │ `'indeterminate'` of §6.4.                                               │
// └──────────────────────────────────────────────────────────────────────────┘
//
// THE DEFINITION OF `tunnelCritical`, stated once so nobody re-derives it:
// a resource is tunnel-critical when a change to it can plausibly alter
// whether the platform can still reach this device. Four families, and they
// are the four the milestone brief names:
//
//   1. the `input` chain (and `output`, the reply half of the same session);
//   2. the tunnel interface — the L2TP/PPPoE/WireGuard/GRE/IPsec interface the
//      management session rides on, or any interface bearing `tunnel_ip`;
//   3. default routing — a `0.0.0.0/0` / `::/0` route, or any route whose
//      destination covers `tunnel_ip`;
//   4. management access — `ssh` / `winbox` / `api` / `api-ssl` services, and
//      the local users that can use them.
//
// M6 ADDS TWO MORE, and they are additions to the same list rather than a new
// idea: both are ways of losing the box that the four above do not name.
//
//   5. the management ADDRESS itself — the interface that carries `tunnel_ip`,
//      and any rule that names that address explicitly in any chain. Losing the
//      address is not "the link may flap", it is "there is nothing left to
//      dial", and K2 checks the two separately;
//   6. a prerouting DNAT/redirect that can swallow a management PORT aimed at
//      that address. The session reaches the box and is handed to somebody
//      else — the same outcome as a drop, with none of the visibility.
//
// EVERY PREDICATE BELOW IS CONSERVATIVE IN THE SAME DIRECTION: when a selector
// cannot be PROVED not to cover the management address, it is treated as
// covering it. A false positive costs one op marked `high` that an operator
// confirms; a false negative costs a truck roll. `mayIntersect` in the shared
// package makes exactly the same trade for exactly the same reason.

import type {
  NcmDocument, NcmDiffFinding, NcmResource, NcmResourceKind, NcmChain,
  NcmServiceName, InterfaceType, Selector, PortSet, DiffSeverity, RiskLevel, PlanOpKind,
} from '@obliwan/shared';
import { parseCidr, parseIp } from '@obliwan/shared';

// ============================================================================
// Vocabulary
// ============================================================================

/**
 * Why an op scored the way it did. Persisted on the op's `reason` sentence and
 * returned to the client so the PlanPage can colour a row AND explain it —
 * a risk level with no reason is a number nobody trusts twice.
 *
 * `tunnelCritical` is the one K2 (M6) consumes; the others exist so that the
 * reason string is composed from a fixed vocabulary instead of being written
 * freehand at each call site.
 */
export const RISK_SIGNALS = [
  'tunnelCritical',
  'inputChain',
  'tunnelInterface',
  'defaultRoute',
  'managementService',
  'managementUser',
  'managementAddress',
  'natHijack',
  'terminalDrop',
  'wideSelector',
  'unmodeledMatch',
  'deletion',
  'orderChange',
  'disableToggle',
  'coverageDegraded',
  'weakKey',
  'cosmetic',
] as const;
export type RiskSignal = (typeof RISK_SIGNALS)[number];

/**
 * Interface types that can carry a management session on this product's
 * topology (§1, L2TP to a CHR). `ethernet` is deliberately ABSENT as a type:
 * an ethernet interface becomes tunnel-critical by bearing `tunnel_ip`, not by
 * being ethernet — otherwise every port on every box would be critical and the
 * flag would mean nothing.
 */
export const TUNNEL_INTERFACE_TYPES: ReadonlySet<InterfaceType> = new Set<InterfaceType>([
  'l2tp', 'pppoe', 'wireguard', 'gre', 'ipsec', 'lte',
]);

/** Services whose loss is a loss of administrative access. `snmp` is NOT here:
 *  losing SNMP costs telemetry, not control. */
export const MANAGEMENT_SERVICES: ReadonlySet<NcmServiceName> = new Set<NcmServiceName>([
  'ssh', 'winbox', 'api', 'api-ssl',
]);

/**
 * Default listening port of each management service, used when the document
 * does not carry one (an `/export` omits a port left at its default) and by K2
 * to decide which ports its synthetic packet should be addressed to.
 *
 * These are DEFAULTS, not truths: `service.port` always wins when present. A
 * box with ssh moved to 2222 and no `port` in its NCM is a collection bug, and
 * it surfaces as a probe on the wrong port rather than as a silent wrong
 * answer — `coverage.service` is what tells the guard to distrust the list.
 */
export const MANAGEMENT_PORTS: Readonly<Partial<Record<NcmServiceName, number>>> = {
  ssh: 22,
  winbox: 8291,
  api: 8728,
  'api-ssl': 8729,
};

/** Chains on the box's own control plane. `forward` is not one of them: a
 *  forward rule cannot drop a packet addressed to the router itself. */
export const MANAGEMENT_CHAINS: ReadonlySet<NcmChain> = new Set<NcmChain>(['input', 'output']);

/** Actions that end the walk for a packet. Kept local rather than imported from
 *  `TERMINAL_ACTIONS`, because what matters here is narrower: an action that
 *  can DENY. `accept` is terminal and harmless on the management path. */
const DENYING_ACTIONS = new Set(['drop', 'reject', 'tarpit']);

// ============================================================================
// Management-path facts
// ============================================================================

/**
 * Everything the scorer needs to know about how we reach this box. Built ONCE
 * per device by the planner and handed to every op — recomputing it per op
 * would be O(ops x interfaces) and, worse, would let two ops disagree about
 * which interface is the tunnel.
 */
export interface MgmtPathFacts {
  deviceId: number;
  /** `devices.tunnel_ip`. NULL on a box we have never dialled — which makes
   *  every address predicate below fall back to "cannot prove disjoint". */
  tunnelIp: string | null;
  /** Interface NAMES (not semKeys) that carry, or may carry, the management
   *  session. */
  tunnelInterfaces: ReadonlySet<string>;
  /** Interface-list names those interfaces belong to. A firewall rule written
   *  against `ifaceList:WAN` is on the management path exactly as much as one
   *  written against the interface itself, and templates are usually written
   *  against the list. */
  tunnelInterfaceLists: ReadonlySet<string>;
  /**
   * Custom chains reachable from `input` / `output` by a chain of `jump`s.
   *
   * Without this, the single most common firewall idiom in the product's own
   * templates would be invisible to the guard: `chain=input action=jump
   * jump-target=mgmt` followed by every real rule sitting in `chain=mgmt`. The
   * jumping rule would be flagged and the rules that actually decide the fate
   * of the management session would not.
   */
  managementChainNames: ReadonlySet<string>;
  /** True when we could not establish which interface is the tunnel. Every
   *  interface-based predicate then answers "maybe", which is the fail-closed
   *  direction. */
  tunnelUnknown: boolean;
}

function isTunnelBearing(iface: { type: InterfaceType; addresses: { cidr: string }[] }, tunnelIp: string | null): boolean {
  if (TUNNEL_INTERFACE_TYPES.has(iface.type)) return true;
  if (!tunnelIp) return false;
  return iface.addresses.some((a) => cidrContains(a.cidr, tunnelIp));
}

/**
 * Derive the management-path facts from the OBSERVED document.
 *
 * The observed side, never the desired one: the question is "how do we reach
 * the box TODAY", and the desired document is precisely the thing that might
 * be about to break it.
 */
export function buildMgmtPathFacts(
  observed: NcmDocument,
  opts: { deviceId: number; tunnelIp: string | null },
): MgmtPathFacts {
  const tunnelInterfaces = new Set<string>();
  const tunnelInterfaceLists = new Set<string>();

  for (const iface of observed.resources.interfaces) {
    if (!isTunnelBearing(iface, opts.tunnelIp)) continue;
    tunnelInterfaces.add(iface.name);
    for (const list of iface.lists) tunnelInterfaceLists.add(list);
  }

  // An interface whose PARENT is a tunnel interface rides the same path: a
  // VLAN over the L2TP link dies with the link.
  for (const iface of observed.resources.interfaces) {
    if (iface.parent && tunnelInterfaces.has(iface.parent) && !tunnelInterfaces.has(iface.name)) {
      tunnelInterfaces.add(iface.name);
      for (const list of iface.lists) tunnelInterfaceLists.add(list);
    }
  }

  return {
    deviceId: opts.deviceId,
    tunnelIp: opts.tunnelIp,
    tunnelInterfaces,
    tunnelInterfaceLists,
    managementChainNames: reachableChains(observed),
    // `coverage.interface` is 'partial' on RouterOS BY CONSTRUCTION (an
    // /export omits a factory-default interface), so "we found no tunnel
    // interface" genuinely means "we do not know", not "there is none".
    tunnelUnknown: tunnelInterfaces.size === 0,
  };
}

/**
 * Transitive closure of `jump` targets starting from `input` and `output`.
 *
 * Bounded by the number of rules, and cycle-safe by construction (a chain is
 * added to the frontier only once). RouterOS itself refuses a jump loop, but a
 * DESIRED document is not a router and must not be able to make this walk spin.
 */
function reachableChains(doc: NcmDocument): ReadonlySet<string> {
  const jumpsFrom = new Map<string, Set<string>>();
  for (const rule of doc.resources.firewallRules) {
    if (rule.action !== 'jump' || !rule.jumpTarget) continue;
    const from = rule.chain === 'custom' ? (rule.chainName ?? '') : rule.chain;
    const set = jumpsFrom.get(from);
    if (set) set.add(rule.jumpTarget);
    else jumpsFrom.set(from, new Set([rule.jumpTarget]));
  }

  const reached = new Set<string>();
  const frontier: string[] = ['input', 'output'];
  while (frontier.length > 0) {
    const chain = frontier.pop() as string;
    for (const target of jumpsFrom.get(chain) ?? []) {
      if (reached.has(target)) continue;
      reached.add(target);
      frontier.push(target);
    }
  }
  return reached;
}

// ============================================================================
// Address / selector predicates — conservative, in one direction only
// ============================================================================

/**
 * True when `cidr` provably contains `ip`. False on anything unparsable.
 *
 * EXPORTED for K2 (`mgmtPathGuard`): the guard needs exactly this predicate,
 * with exactly this fail-to-false behaviour, and a second implementation living
 * three files away is how two modules end up disagreeing about whether the
 * management address is inside a subnet.
 */
export function cidrContains(cidr: string, ip: string): boolean {
  const net = parseCidr(cidr);
  const addr = parseIp(ip);
  if (!net || !addr || net.version !== addr.version) return false;
  const bits = net.prefix;
  for (let i = 0; i < net.bytes.length; i++) {
    const before = i * 8;
    if (bits <= before) break;
    const keep = Math.min(8, bits - before);
    const mask = (0xff << (8 - keep)) & 0xff;
    if ((net.bytes[i] & mask) !== (addr.bytes[i] & mask)) return false;
  }
  return true;
}

/**
 * "Can this selector cover the management address?"
 *
 * Returns TRUE when it cannot be proved otherwise. `any` is true. An
 * unresolved `ref:` object is true — §3.3 rule 8 refuses to expand a named
 * object silently, and a firewall guard may not assume an object it cannot
 * read is harmless. `fqdn:` is true for the same reason.
 */
export function selectorMayCover(sel: Selector, ip: string | null): boolean {
  if (sel.length === 0) return true;
  for (const atom of sel) {
    if (atom === 'any') return true;
    const colon = atom.indexOf(':');
    const tag = atom.slice(0, colon);
    const value = atom.slice(colon + 1);
    switch (tag) {
      case 'ref':
      case 'fqdn':
      case 'mac':
        // Unresolvable here. Fail open towards "critical".
        return true;
      case 'range':
        // `range:a-b`. Not expanded; treated as unknown coverage.
        return true;
      case 'ip':
        if (ip === null || value === ip) return true;
        break;
      case 'cidr':
        if (ip === null || cidrContains(value, ip)) return true;
        break;
      default:
        return true;
    }
  }
  return false;
}

/**
 * The strict counterpart of `selectorMayCover`: TRUE only when an atom PROVES
 * that the selector contains `ip`.
 *
 * `any` is deliberately excluded. `mayCover` exists to answer "could this rule
 * touch us" and must say yes to `any`; this one exists to answer "is this
 * record ABOUT the management address", and a rule that selects everything is
 * not about the management address in particular. Marking every `any` rule as
 * `managementAddress` would make the signal mean nothing — the same argument
 * `selectorTouchesTunnel` makes for interfaces, for the same reason.
 */
function selectorDefinitelyCovers(sel: Selector, ip: string | null): boolean {
  if (ip === null) return false;
  for (const atom of sel) {
    if (atom === 'any') continue;
    const colon = atom.indexOf(':');
    const tag = atom.slice(0, colon);
    const value = atom.slice(colon + 1);
    if (tag === 'ip' && value === ip) return true;
    if (tag === 'cidr' && cidrContains(value, ip)) return true;
  }
  return false;
}

/** Does this port set include a port an administrator logs in on? `null` is
 *  "any port", which includes all of them. */
function portSetHitsManagement(ports: PortSet): boolean {
  if (ports === null) return true;
  for (const p of Object.values(MANAGEMENT_PORTS)) {
    for (const [lo, hi] of ports) if (p >= lo && p <= hi) return true;
  }
  return false;
}

/**
 * "Does this interface selector NAME the tunnel path?"
 *
 * `any` deliberately does NOT count, and that is the one place this file is not
 * maximally conservative. The reasoning, and its cost, stated so it can be
 * argued with:
 *
 *   `any` is the DEFAULT value of every interface selector — `EMPTY_MATCH` in
 *   the NCM contract sets `inInterface: ['any']`, and a `/export` omits the
 *   prop entirely on the overwhelming majority of rules. Treating `any` as
 *   "touches the tunnel" would mark essentially every firewall and NAT rule on
 *   every device as `tunnelCritical`, and a flag that is always true is a flag
 *   K2 cannot use to prioritise anything.
 *
 *   What is NOT lost: a rule that can actually decide the fate of the
 *   management session with an `any` interface is caught by a DIFFERENT
 *   predicate — `chain=input`/`output` (or a custom chain reachable from them),
 *   or an address selector that can cover `tunnel_ip`. Those are checked
 *   independently in `classifyResource`.
 *
 *   What IS lost: a `forward`-chain rule with `any` on both interfaces that
 *   happens to sit on the transit path of a routed management flow. K2's
 *   forwarding engine (M6) is what will decide that; a heuristic here cannot,
 *   and pretending otherwise would be the false confidence §6.4 forbids.
 *
 * When we could not identify the tunnel interface at all, everything is
 * "maybe" — that is the fail-closed branch and it is checked first.
 */
function selectorTouchesTunnel(sel: Selector, facts: MgmtPathFacts): boolean {
  if (facts.tunnelUnknown) return true;
  for (const atom of sel) {
    const colon = atom.indexOf(':');
    const tag = atom.slice(0, colon);
    const value = atom.slice(colon + 1);
    if (tag === 'iface' && facts.tunnelInterfaces.has(value)) return true;
    if (tag === 'ifaceList' && facts.tunnelInterfaceLists.has(value)) return true;
    if (tag === 'ref') return true;
  }
  return false;
}

// ============================================================================
// tunnelCritical
// ============================================================================

export interface CriticalityVerdict {
  tunnelCritical: boolean;
  signals: RiskSignal[];
}

/**
 * The classification the Management-Path Guard (K2, M6) consumes.
 *
 * Called on BOTH sides of an op — the observed resource and the desired one —
 * and the results are unioned by `scoreOp`. A rule that used to be on the
 * management path and no longer is, is exactly as interesting as the converse.
 */
export function classifyResource(
  resource: NcmResource | null,
  facts: MgmtPathFacts,
): CriticalityVerdict {
  const signals = new Set<RiskSignal>();
  if (!resource) return { tunnelCritical: false, signals: [] };

  switch (resource.kind) {
    case 'firewallRule': {
      if (MANAGEMENT_CHAINS.has(resource.chain)) signals.add('inputChain');
      // A custom chain the input chain jumps into is the input chain, as far as
      // the management session is concerned.
      if (
        resource.chain === 'custom' &&
        resource.chainName !== null &&
        facts.managementChainNames.has(resource.chainName)
      ) {
        signals.add('inputChain');
      }
      if (
        selectorTouchesTunnel(resource.match.inInterface, facts) ||
        selectorTouchesTunnel(resource.match.outInterface, facts)
      ) {
        signals.add('tunnelInterface');
      }
      // A rule in `forward` that can select the management address is on the
      // path when the box routes for the tunnel (a CPE behind a CHR does).
      if (
        selectorMayCover(resource.match.srcAddress, facts.tunnelIp) &&
        selectorMayCover(resource.match.dstAddress, facts.tunnelIp) &&
        (signals.has('inputChain') || signals.has('tunnelInterface'))
      ) {
        signals.add('wideSelector');
      }
      // A rule that NAMES the management address is about the management
      // address, whatever chain it sits in. This is what catches a `forward`
      // rule aimed at the CPE from the LAN, which no chain predicate sees.
      if (
        selectorDefinitelyCovers(resource.match.dstAddress, facts.tunnelIp) ||
        selectorDefinitelyCovers(resource.match.srcAddress, facts.tunnelIp)
      ) {
        signals.add('managementAddress');
      }
      if (DENYING_ACTIONS.has(resource.action)) signals.add('terminalDrop');
      if (resource.match.unmodeledMatch.length > 0) signals.add('unmodeledMatch');
      break;
    }

    case 'natRule': {
      if (selectorTouchesTunnel(resource.match.inInterface, facts)) signals.add('tunnelInterface');
      if (selectorTouchesTunnel(resource.match.outInterface, facts)) signals.add('tunnelInterface');
      // A dst-nat that captures the management address redirects our own
      // session somewhere else — same outcome as dropping it.
      if (
        resource.chain === 'prerouting' &&
        facts.tunnelIp !== null &&
        selectorMayCover(resource.match.dstAddress, facts.tunnelIp) &&
        resource.action !== 'accept'
      ) {
        signals.add('wideSelector');
      }
      // …and when that dst-nat can actually swallow a management PORT, it is
      // not merely a wide selector, it is a lockout with extra steps: the
      // session reaches the box and is sent somewhere else. K2 proves or
      // refutes it; the flag is what puts it in front of the guard at all.
      //
      // The port test is what keeps this from firing on every `prerouting`
      // rule: the DNS-redirect idiom (`dst-port=53 action=redirect`) is
      // unremarkable and stays unflagged, while `dst-nat` with no port
      // restriction — the shape that actually steals winbox — does not.
      if (
        resource.chain === 'prerouting' &&
        (resource.action === 'dstnat' || resource.action === 'redirect' || resource.action === 'netmap') &&
        selectorMayCover(resource.match.dstAddress, facts.tunnelIp) &&
        portSetHitsManagement(resource.match.dstPort)
      ) {
        signals.add('natHijack');
      }
      if (resource.match.unmodeledMatch.length > 0) signals.add('unmodeledMatch');
      break;
    }

    case 'route': {
      if (resource.dst === '0.0.0.0/0' || resource.dst === '::/0') signals.add('defaultRoute');
      if (facts.tunnelIp && cidrContains(resource.dst, facts.tunnelIp)) signals.add('defaultRoute');
      if (
        resource.gateway &&
        resource.gateway.startsWith('iface:') &&
        facts.tunnelInterfaces.has(resource.gateway.slice('iface:'.length))
      ) {
        signals.add('tunnelInterface');
      }
      break;
    }

    case 'interface': {
      if (facts.tunnelInterfaces.has(resource.name)) signals.add('tunnelInterface');
      if (TUNNEL_INTERFACE_TYPES.has(resource.type)) signals.add('tunnelInterface');
      if (facts.tunnelIp && resource.addresses.some((a) => cidrContains(a.cidr, facts.tunnelIp as string))) {
        signals.add('tunnelInterface');
        // Distinct from `tunnelInterface`: this interface does not merely ride
        // the path, it CARRIES the address we dial. Editing its addresses is
        // the difference between "the link may flap" and "there is nothing left
        // to connect to", and K2 checks the two separately.
        signals.add('managementAddress');
      }
      break;
    }

    case 'service': {
      if (MANAGEMENT_SERVICES.has(resource.service)) signals.add('managementService');
      break;
    }

    case 'localUser': {
      // Every local user is a potential management identity: RouterOS does not
      // separate "can log in over winbox" from "exists".
      signals.add('managementUser');
      break;
    }

    case 'ipsecPeer': {
      // The tunnel to the CHR may itself be the IPsec transport of the L2TP
      // link (R9 requires L2TP/IPsec). Losing the peer loses the path.
      signals.add('tunnelInterface');
      break;
    }

    case 'qosRule': {
      // A queue is not a firewall, but `max-limit=0` on the tunnel interface
      // has exactly the effect of a drop rule and none of the visibility. The
      // predicate is narrow on purpose: only a queue whose TARGET is the
      // management path counts, so ordinary per-LAN shaping stays `low`.
      if (
        selectorTouchesTunnel(resource.target, facts) ||
        selectorDefinitelyCovers(resource.target, facts.tunnelIp)
      ) {
        signals.add('tunnelInterface');
      }
      if (resource.match && resource.match.unmodeledMatch.length > 0) signals.add('unmodeledMatch');
      break;
    }

    // vlan / dhcpScope carry no management-path meaning on their own.
    default:
      break;
  }

  const tunnelCritical =
    signals.has('inputChain') ||
    signals.has('tunnelInterface') ||
    signals.has('defaultRoute') ||
    signals.has('managementService') ||
    signals.has('managementUser') ||
    signals.has('managementAddress') ||
    signals.has('natHijack');

  if (tunnelCritical) signals.add('tunnelCritical');
  return { tunnelCritical, signals: [...signals].sort() };
}

// ============================================================================
// Scoring one op
// ============================================================================

export interface RiskAssessment {
  risk: RiskLevel;
  /** True when K2 (M6) must analyse this op before it may be applied. */
  tunnelCritical: boolean;
  /** True when applying this op may drop the session it is applied through —
   *  what the dead-man arming decision of M6 reads. */
  disruptive: boolean;
  signals: RiskSignal[];
  /** Operator-facing sentence. Shown verbatim, never a stack trace. */
  reason: string;
}

/** Diff severity -> the risk floor it implies. The diff engine's severity table
 *  is a security judgement that was reviewed; re-deriving a second, different
 *  one here would mean the product has two opinions about the same edit. */
const SEVERITY_FLOOR: Readonly<Record<DiffSeverity, RiskLevel>> = {
  info: 'low',
  low: 'low',
  medium: 'medium',
  high: 'high',
  critical: 'high',
};

const RANK: Readonly<Record<RiskLevel, number>> = { low: 0, medium: 1, high: 2 };
function worst(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RANK[b] > RANK[a] ? b : a;
}

export interface ScoreInput {
  kind: PlanOpKind;
  resource: NcmResourceKind;
  /** The observed resource, `null` on a `create`. */
  before: NcmResource | null;
  /** The desired resource, `null` on a `delete`. */
  after: NcmResource | null;
  /** Field paths the op changes, from `NcmFieldDiff.field`. */
  fields: readonly string[];
  /** The finding this op came from, when there is one. `severity`, `crossed`
   *  and `matchMethod` all feed the score. */
  finding: NcmDiffFinding | null;
  facts: MgmtPathFacts;
  /** Set when the observed side could not claim `coverage: 'complete'` for
   *  this kind. Never lets an op score BELOW medium: acting on a partial
   *  picture is itself a risk, and hiding that behind `low` is how a truncated
   *  export becomes a confident plan. */
  coverageDegraded: boolean;
}

/** Field heads whose change cannot alter forwarding. Same list as the diff
 *  engine's `COSMETIC_FIELDS`, restated because this module is pure and must
 *  not import a server service. Divergence between the two would show up as an
 *  op scored `high` for a comment edit. */
const COSMETIC_FIELDS = new Set(['comment', 'log', 'logPrefix', 'alias', 'hostname']);

export function scoreOp(input: ScoreInput): RiskAssessment {
  const beforeVerdict = classifyResource(input.before, input.facts);
  const afterVerdict = classifyResource(input.after, input.facts);
  const signals = new Set<RiskSignal>([...beforeVerdict.signals, ...afterVerdict.signals]);
  const tunnelCritical = beforeVerdict.tunnelCritical || afterVerdict.tunnelCritical;

  const materialFields = input.fields.filter((f) => !COSMETIC_FIELDS.has(f.split('.')[0]));
  const cosmeticOnly =
    (input.kind === 'update' || input.kind === 'move') &&
    input.fields.length > 0 &&
    materialFields.length === 0;
  if (cosmeticOnly) signals.add('cosmetic');

  let risk: RiskLevel = 'low';

  // 1. The floor the diff engine already established.
  if (input.finding) risk = worst(risk, SEVERITY_FLOOR[input.finding.severity]);

  // 2. What the op KIND costs, independently of the finding.
  switch (input.kind) {
    case 'delete':
      // Deleting is the only irreversible half of a plan on a box we do not
      // hold a backup of yet (backups are M6). It is never `low`.
      signals.add('deletion');
      risk = worst(risk, 'medium');
      break;
    case 'create':
      risk = worst(risk, 'low');
      break;
    case 'move':
      signals.add('orderChange');
      // A move that crosses a decisive rule changed the forwarding of the
      // chain; §4.4 puts it at `high` and requires K2 to re-run.
      if (input.finding && input.finding.crossed.length > 0) risk = worst(risk, 'medium');
      break;
    case 'enable':
    case 'disable':
      signals.add('disableToggle');
      risk = worst(risk, 'medium');
      break;
    default:
      break;
  }

  // 3. The management path. A tunnel-critical op is never below `medium`, and
  //    a tunnel-critical op that DENIES, DELETES or REORDERS is `high`.
  if (tunnelCritical && !cosmeticOnly) {
    risk = worst(risk, 'medium');
    const touchesFate =
      input.kind === 'delete' ||
      input.kind === 'disable' ||
      input.kind === 'move' ||
      signals.has('terminalDrop') ||
      materialFields.some((f) => f === 'action' || f === 'enabled' || f === 'disabled' || f.startsWith('match') || f === 'allowedFrom');
    if (touchesFate) risk = 'high';
  }

  // 4. Blind spots. An op computed against a degraded picture cannot be `low`.
  if (input.coverageDegraded) {
    signals.add('coverageDegraded');
    risk = worst(risk, 'medium');
  }
  if (input.finding && input.finding.matchMethod === 'fuzzy') {
    // The pairing itself is a guess. Acting on a guess is at least `medium`.
    risk = worst(risk, 'medium');
  }
  if ((input.before?.keyQuality ?? input.after?.keyQuality) === 'weak') {
    signals.add('weakKey');
    risk = worst(risk, 'medium');
  }

  // 5. A `blocked` op applies nothing, so it carries no risk of its own. Its
  //    level is informational and must not inflate `planRisk`.
  if (input.kind === 'blocked') risk = 'low';

  return {
    risk,
    tunnelCritical,
    disruptive: tunnelCritical && !cosmeticOnly && input.kind !== 'blocked' && input.kind !== 'verify',
    signals: [...signals].sort(),
    reason: composeReason(input, signals, tunnelCritical, risk),
  };
}

// ============================================================================
// The sentence an operator reads
// ============================================================================

const KIND_VERB: Readonly<Record<PlanOpKind, string>> = {
  create: 'Create',
  update: 'Update',
  delete: 'Delete',
  move: 'Reorder',
  enable: 'Enable',
  disable: 'Disable',
  verify: 'Verify',
  blocked: 'Blocked',
};

const SIGNAL_PHRASE: Readonly<Record<RiskSignal, string>> = {
  tunnelCritical: 'on the management path',
  inputChain: 'in the router’s own input/output chain',
  tunnelInterface: 'on the tunnel interface',
  defaultRoute: 'on the default route',
  managementService: 'on a management service',
  managementUser: 'on a local login account',
  managementAddress: 'on the address the platform dials this device on',
  natHijack: 'redirecting traffic aimed at the management address',
  terminalDrop: 'with a denying action',
  wideSelector: 'with a selector that can cover the management address',
  unmodeledMatch: 'carrying a match this model does not understand',
  deletion: 'removing configuration from the device',
  orderChange: 'changing rule order',
  disableToggle: 'toggling an enable/disable flag',
  coverageDegraded: 'computed against an incomplete collection',
  weakKey: 'on a record with a weak identity',
  cosmetic: 'touching only comments or logging',
};

function composeReason(
  input: ScoreInput,
  signals: ReadonlySet<RiskSignal>,
  tunnelCritical: boolean,
  risk: RiskLevel,
): string {
  const head = `${KIND_VERB[input.kind]} ${input.resource}`;
  const parts: string[] = [];
  // Order matters: the management-path phrases come first because that is what
  // an operator scans for.
  for (const s of ['tunnelCritical', 'inputChain', 'tunnelInterface', 'managementAddress',
    'defaultRoute', 'managementService', 'managementUser', 'natHijack', 'terminalDrop',
    'deletion', 'orderChange', 'coverageDegraded', 'weakKey', 'cosmetic'] as RiskSignal[]) {
    if (signals.has(s) && s !== 'tunnelCritical') parts.push(SIGNAL_PHRASE[s]);
  }
  const fieldText =
    input.fields.length > 0 && input.fields.length <= 6
      ? ` (${input.fields.join(', ')})`
      : input.fields.length > 6
        ? ` (${input.fields.length} fields)`
        : '';
  const tail = parts.length > 0 ? ` — ${parts.join(', ')}` : '';
  const guard = tunnelCritical
    ? ' The Management-Path Guard must clear this operation before it is applied.'
    : '';
  return `${head}${fieldText}${tail}. Risk ${risk}.${guard}`.slice(0, 400);
}

// Plan-level risk deliberately has NO wrapper here. It is `planRisk` in
// `@obliwan/shared` — the maximum of the ops' levels, never an average, because
// one high-risk op in fifty makes the whole plan high-risk and four-eyes apply.
// A convenience re-export would be a second import path to the same decision,
// and the day the two drift apart is the day a plan is approved at the wrong
// level. `planner.service` imports it from the contract.
