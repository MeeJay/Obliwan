// ============================================================================
// @obliwan/shared — may-intersect and order signatures
// ============================================================================
//
// Implements §4 of `docs/M4-NCM-contrat.md`.
//
// THE PRINCIPLE (N2): absolute position is not semantics. What matters is the
// relative order of two rules that can select the SAME packet. Two rules whose
// packet sets are disjoint can be swapped without a single packet in the world
// changing fate, and the diff must emit ZERO findings for that. Inserting one
// rule at the head of a 40-rule chain must produce ONE finding, not forty.
//
// Pure and dependency-free: the client uses these to explain a `moved` finding
// ("this rule now sits above these three") without a round trip.

import type { NcmMatch, NcmOrderedRule, FirewallAction } from './resources';
import { TERMINAL_ACTIONS } from './resources';
import { parseIp, parseCidr } from './primitives';

// ── address atoms as numeric intervals ──────────────────────────────────────

interface AddrRange {
  version: 4 | 6;
  lo: Uint8Array;
  hi: Uint8Array;
}

function cmpBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

/**
 * `null` means "this atom constrains nothing we can reason about" — either it
 * literally matches everything (`any`) or it is an unresolved named object
 * (`ref:HTTP-ALT`, `ifaceList:WAN`) that we refuse to expand silently (§3.3
 * rule 8). Both cases force the conservative answer.
 */
function atomToRange(atom: string): AddrRange | null {
  if (atom === 'any') return null;
  const colon = atom.indexOf(':');
  if (colon < 0) return null;
  const tag = atom.slice(0, colon);
  const value = atom.slice(colon + 1);

  if (tag === 'ip') {
    const ip = parseIp(value);
    if (!ip) return null;
    return { version: ip.version, lo: ip.bytes, hi: ip.bytes };
  }
  if (tag === 'cidr') {
    const c = parseCidr(value);
    if (!c) return null;
    const lo = new Uint8Array(c.bytes.length);
    const hi = new Uint8Array(c.bytes.length);
    for (let i = 0; i < c.bytes.length; i++) {
      const bitsBefore = i * 8;
      let mask: number;
      if (c.prefix >= bitsBefore + 8) mask = 0xff;
      else if (c.prefix <= bitsBefore) mask = 0x00;
      else mask = (0xff << (8 - (c.prefix - bitsBefore))) & 0xff;
      lo[i] = c.bytes[i] & mask;
      hi[i] = (c.bytes[i] & mask) | (~mask & 0xff);
    }
    return { version: c.version, lo, hi };
  }
  if (tag === 'range') {
    const dash = value.indexOf('-');
    if (dash < 0) return null;
    const a = parseIp(value.slice(0, dash));
    const b = parseIp(value.slice(dash + 1));
    if (!a || !b || a.version !== b.version) return null;
    return cmpBytes(a.bytes, b.bytes) <= 0
      ? { version: a.version, lo: a.bytes, hi: b.bytes }
      : { version: a.version, lo: b.bytes, hi: a.bytes };
  }
  // iface / ifaceList / mac / fqdn / ref — not an address dimension.
  return null;
}

/**
 * Address selectors. Returns true ONLY when the two selectors are PROVABLY
 * disjoint: every atom on both sides resolves to an interval, and no pair of
 * intervals overlaps.
 *
 * Two selectors of DIFFERENT IP versions are disjoint on that dimension in the
 * strict sense, but a rule may legitimately carry both families, so the test is
 * per-pair rather than per-selector.
 */
function addressSelectorsDisjoint(a: readonly string[], b: readonly string[]): boolean {
  const ra: AddrRange[] = [];
  for (const atom of a) {
    const r = atomToRange(atom);
    if (!r) return false;      // 'any' or unresolvable -> cannot prove disjoint
    ra.push(r);
  }
  const rb: AddrRange[] = [];
  for (const atom of b) {
    const r = atomToRange(atom);
    if (!r) return false;
    rb.push(r);
  }
  for (const x of ra) {
    for (const y of rb) {
      if (x.version !== y.version) continue;   // provably disjoint pair
      if (cmpBytes(x.lo, y.hi) <= 0 && cmpBytes(y.lo, x.hi) <= 0) return false;
    }
  }
  return true;
}

/**
 * Interface selectors. Only bare `iface:` names can be compared: an
 * `ifaceList:WAN` is a named object whose membership changes when a port is
 * added, and expanding it here would make every rule of the device "move" the
 * day someone adds ether5 to the WAN list (§3.3 rule 7).
 */
function interfaceSelectorsDisjoint(a: readonly string[], b: readonly string[]): boolean {
  const names = (sel: readonly string[]): Set<string> | null => {
    const out = new Set<string>();
    for (const atom of sel) {
      if (atom === 'any') return null;
      if (!atom.startsWith('iface:')) return null;   // ifaceList / ref -> unknown
      out.add(atom.slice(6));
    }
    return out.size > 0 ? out : null;
  };
  const na = names(a);
  const nb = names(b);
  if (!na || !nb) return false;
  for (const n of na) if (nb.has(n)) return false;
  return true;
}

function portSetsDisjoint(
  a: readonly (readonly [number, number])[] | null,
  b: readonly (readonly [number, number])[] | null,
): boolean {
  if (a === null || b === null) return false;   // null = any port
  for (const [a0, a1] of a) {
    for (const [b0, b1] of b) {
      if (a0 <= b1 && b0 <= a1) return false;
    }
  }
  return true;
}

function tokenSetsDisjoint(a: readonly string[], b: readonly string[]): boolean {
  if (a.length === 0 || b.length === 0) return false;   // empty = any
  const sa = new Set(a);
  for (const t of b) if (sa.has(t)) return false;
  return true;
}

/**
 * Conservative may-intersect (§4.3). Returns FALSE only when the two rules are
 * PROVABLY disjoint on at least one dimension. Anything unknown — an unresolved
 * `ref:` object, an interface list, a brand construct we do not understand —
 * returns TRUE.
 *
 * The asymmetry is deliberate and is the whole safety argument: a false
 * positive costs one noisy `moved` finding; a false negative costs a lockout
 * that K2 failed to predict.
 *
 * Note on `unmodeledMatch`: it deliberately does NOT force TRUE on its own. An
 * unread selector cannot make two provably disjoint protocols overlap, and
 * every dimension below is evaluated independently, so an unmodelled token
 * simply contributes no evidence. What it DOES do is bar K2 from concluding
 * (§6.4) — that guard lives on the verdict, not here.
 *
 * Dimensions are ordered cheapest first: protocol, zones, connection state,
 * interfaces, ports, addresses.
 */
export function mayIntersect(a: NcmMatch, b: NcmMatch): boolean {
  // 1. protocol — null means "any"
  if (a.protocol !== null && b.protocol !== null && a.protocol !== b.protocol) return false;

  // 2. zones
  if (a.srcZone !== null && b.srcZone !== null && a.srcZone !== b.srcZone) return false;
  if (a.dstZone !== null && b.dstZone !== null && a.dstZone !== b.dstZone) return false;

  // 3. connection tracking state
  if (tokenSetsDisjoint(a.connectionState, b.connectionState)) return false;
  if (tokenSetsDisjoint(a.connectionNat, b.connectionNat)) return false;

  // 4. interfaces
  if (interfaceSelectorsDisjoint(a.inInterface, b.inInterface)) return false;
  if (interfaceSelectorsDisjoint(a.outInterface, b.outInterface)) return false;

  // 5. ports — only meaningful once the protocols are compatible, which step 1
  //    has already established.
  if (portSetsDisjoint(a.srcPort, b.srcPort)) return false;
  if (portSetsDisjoint(a.dstPort, b.dstPort)) return false;

  // 6. addresses — the expensive one, deliberately last
  if (addressSelectorsDisjoint(a.srcAddress, b.srcAddress)) return false;
  if (addressSelectorsDisjoint(a.dstAddress, b.dstAddress)) return false;

  return true;
}

// ============================================================================
// Order signatures (§4.2)
// ============================================================================

/** Beyond this many rules in one chain the O(n^2) comparison is restricted to a
 *  window and the document must declare `orderAnalysis: 'partial'` (§4.3,
 *  risk N-R8). */
export const ORDER_ANALYSIS_MAX_RULES = 500;
export const ORDER_ANALYSIS_WINDOW = 25;

/**
 * What a rule DOES to a packet, for the purpose of deciding whether crossing it
 * matters. Two rules with the same effect can be reordered freely even when
 * they overlap: the packet meets the same fate either way.
 */
function effectKey(rule: NcmOrderedRule): string {
  if (rule.kind === 'firewallRule') {
    return `${rule.action}|${rule.jumpTarget ?? ''}|${rule.rejectWith ?? ''}`;
  }
  if (rule.kind === 'natRule') {
    return `${rule.action}|${(rule.toAddresses ?? []).join(',')}|${JSON.stringify(rule.toPorts)}`;
  }
  return `qos|${rule.maxLimitUpBps ?? ''}|${rule.maxLimitDownBps ?? ''}|${rule.priority ?? ''}`;
}

function isTerminal(rule: NcmOrderedRule): boolean {
  if (rule.kind === 'firewallRule') return TERMINAL_ACTIONS.has(rule.action as FirewallAction);
  // Every NAT action rewrites the packet, and a queue that matches first wins:
  // for these two kinds, "reached first" always decides.
  return true;
}

/**
 * A pair is DECISIVE when swapping it can change where a packet ends up:
 * the two rules can select the same packet, at least one is terminal, and their
 * effects differ. Two `log` / `passthrough` rules crossing each other change
 * no forwarding at all, and emitting a finding for that is pure noise (R3).
 *
 * A disabled rule decides nothing, so it is never part of a decisive pair.
 */
export function isDecisivePair(a: NcmOrderedRule, b: NcmOrderedRule): boolean {
  if (a.disabled || b.disabled) return false;
  if (!isTerminal(a) && !isTerminal(b)) return false;
  if (effectKey(a) === effectKey(b)) return false;
  const ma = a.kind === 'qosRule' ? a.match : a.match;
  const mb = b.kind === 'qosRule' ? b.match : b.match;
  if (ma === null || mb === null) return true;   // a plain interface queue: unknown
  return mayIntersect(ma, mb);
}

export interface OrderSignature {
  /** `${earlierSemKey}>${laterSemKey}` for every decisive ordered pair. */
  pairs: Set<string>;
  /** 'partial' when the window guard of §4.3 kicked in — K2 must then refuse
   *  to return ACCEPT, and the UI must show the order analysis as degraded. */
  analysis: 'full' | 'partial';
}

/**
 * Builds the precedence signature of ONE chain. The caller groups by
 * (device, resourceKind, chain) — a rule in `input` can never precede a rule in
 * `forward` in any meaningful sense.
 */
export function buildOrderSignature(chain: readonly NcmOrderedRule[]): OrderSignature {
  const pairs = new Set<string>();
  const n = chain.length;
  const windowed = n > ORDER_ANALYSIS_MAX_RULES;
  for (let i = 0; i < n; i++) {
    const jMax = windowed ? Math.min(n, i + 1 + ORDER_ANALYSIS_WINDOW) : n;
    for (let j = i + 1; j < jMax; j++) {
      if (isDecisivePair(chain[i], chain[j])) {
        pairs.add(`${chain[i].semKey}>${chain[j].semKey}`);
      }
    }
  }
  return { pairs, analysis: windowed ? 'partial' : 'full' };
}

/**
 * The symmetric difference of §4.2 step 4, folded into AT MOST ONE `moved`
 * entry per rule — never one per pair. A rule inserted at the head of a chain
 * of 40 only changes the pairs that INVOLVE it, so the 39 others are untouched
 * and produce nothing.
 *
 * A rule whose `crossed` list comes back empty had an inert move: it is counted
 * in `NcmDiffReport.inertMoveCount` and shown as a single aggregated line, not
 * as a finding (§4.4).
 */
export function crossedByRule(
  intent: OrderSignature,
  actual: OrderSignature,
): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const add = (key: string, other: string): void => {
    const cur = out.get(key);
    if (cur) { if (!cur.includes(other)) cur.push(other); }
    else out.set(key, [other]);
  };
  const walk = (from: Set<string>, to: Set<string>): void => {
    for (const p of from) {
      if (to.has(p)) continue;
      const gt = p.indexOf('>');
      const a = p.slice(0, gt);
      const b = p.slice(gt + 1);
      // The pair flipped rather than disappeared: attribute it to both ends,
      // because either one may be the rule the operator actually moved and the
      // engine picks the attribution using the pairing it already has.
      add(a, b);
      add(b, a);
    }
  };
  walk(intent.pairs, actual.pairs);
  walk(actual.pairs, intent.pairs);
  for (const [k, v] of out) out.set(k, v.sort());
  return out;
}
