// ============================================================================
// ObliWAN — the semantic diff engine
// ============================================================================
//
// Implements §3.5 (pairing), §4 (order) and §5 (diff) of
// `docs/M4-NCM-contrat.md`. PURE: no database, no I/O, no clock. Everything it
// needs is in the two documents it is handed, which is the only reason the
// eight anti-noise levers of §5.4 can be tested individually.
//
// ┌─ THE MEASURE OF THIS FILE IS NOISE, NOT COMPLETENESS ─────────────────────┐
// │ R3: a taken-over fleet that produces 200 findings on the first run is a   │
// │ product nobody opens twice. The acceptance criterion of this milestone is │
// │ FEWER THAN 3 NOISE FINDINGS PER DEVICE, and every design decision below   │
// │ is subordinate to it. Where completeness and quiet conflict, quiet wins   │
// │ and the gap is COUNTED (`outOfScopeCount`, `inertMoveCount`,             │
// │ `suppressed[]`) so the blind spot stays visible instead of becoming       │
// │ silent.                                                                   │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THE FIVE GUARDS, IN THE ORDER THEY FIRE ─────────────────────────────────┐
// │ N3   no `missing` unless `actual.coverage[kind].state === 'complete'`.   │
// │      A partial collection must not be able to claim a firewall was       │
// │      emptied. Symmetrically, no `extra` unless the INTENT side is        │
// │      complete: an incomplete desired state would call everything extra.  │
// │ N2   position is never a field. Order is modelled as the set of DECISIVE │
// │      precedence pairs, and only between rules that MAY intersect.        │
// │ §4.4 an inert `moved` is not emitted. It is counted and shown as one     │
// │      aggregated line.                                                    │
// │ §5.3 `managed_only` is the default scope: outside a claimed section an   │
// │      observed object is inventoried, not reported.                       │
// │ §3.4 findings on a `weak` key are capped at `info`.                      │
// └───────────────────────────────────────────────────────────────────────────┘

import type {
  NcmDocument, NcmDiffFinding, NcmDiffReport, NcmFieldDiff, NcmMatch,
  NcmOrderedRule, NcmResource, NcmResourceKind, DiffKind, DiffScope, DiffSeverity,
  MatchMethod, SuppressionReason,
} from '@obliwan/shared';
import {
  RESOURCE_KIND_TO_COLLECTION, ORDERED_RESOURCE_KINDS, TERMINAL_ACTIONS,
  SEVERITY_RANK, FUZZY_MATCH, findingPath, mayEmitMissing, mayIntersect,
  buildOrderSignature, ncmHash,
} from '@obliwan/shared';

// ============================================================================
// Options
// ============================================================================

export interface SemanticDiffOptions {
  /**
   * §5.3 / open arbitration Q2. `managed_only` is the DEFAULT and the reason a
   * taken-over fleet is quiet on day one: an observed object that ObliWAN did
   * not write and that no claimed section covers is inventoried and queryable
   * (K5) but is NOT a finding.
   */
  scope?: DiffScope;
  /**
   * Resource kinds the applied template revision CLAIMS. Under `managed_only`
   * an `extra` is emitted inside a claimed kind even when the observed record
   * carries no `obliwan:` marker — that is what "the template owns this
   * section" means.
   *
   * M5 fills this from `template_revisions.section_severity`. Until that table
   * exists the caller passes null and the only claimed objects are the ones
   * carrying our own marker, which is the correct fail-quiet default.
   */
  claimedKinds?: ReadonlySet<NcmResourceKind> | null;
  /** Phase 3 of §3.5. On by default; a caller that wants a strictly provable
   *  pairing (K2) turns it off and accepts missing+extra instead. */
  fuzzy?: boolean;
}

// ============================================================================
// Severity
// ============================================================================

const KIND_SEVERITY: Readonly<Record<NcmResourceKind, DiffSeverity>> = {
  interface: 'medium',
  dhcpClient: 'medium',
  vlan: 'medium',
  route: 'high',
  firewallRule: 'high',
  natRule: 'high',
  dhcpScope: 'medium',
  ipsecPeer: 'high',
  localUser: 'high',
  service: 'high',
  qosRule: 'low',
};

/** Fields whose change cannot alter behaviour. A comment edit that produced a
 *  `medium` would, on a fleet where scripts rewrite comments, be most of the
 *  drift screen. */
const COSMETIC_FIELDS = new Set(['comment', 'log', 'logPrefix', 'alias', 'name', 'hostname']);

/**
 * Severity of ONE field change. The table is explicit rather than derived
 * because "which edits are dangerous" is a security judgement, and a security
 * judgement written as a heuristic is a security judgement nobody reviewed.
 */
function severityForField(kind: NcmResourceKind, field: string): DiffSeverity {
  const head = field.split('.')[0];
  if (COSMETIC_FIELDS.has(head)) return 'info';
  if (head === 'disabled') return 'high';
  if (head === 'match') return 'high';

  switch (kind) {
    case 'firewallRule':
      // The single most dangerous edit available in the product. N1 exists so
      // that it arrives as ONE `changed` and not as a missing+extra pair that
      // a fuzzy matcher has to reunite.
      if (head === 'action') return 'critical';
      if (head === 'jumpTarget' || head === 'rejectWith') return 'high';
      return 'medium';
    case 'natRule':
      if (head === 'action' || head === 'toAddresses' || head === 'toPorts') return 'high';
      return 'medium';
    case 'service':
      if (head === 'allowedFrom' || head === 'communityIsWellKnown') return 'critical';
      if (head === 'enabled' || head === 'tlsRequired') return 'high';
      return 'medium';
    case 'localUser':
      if (head === 'passwordFingerprint' || head === 'group' || head === 'permissions') return 'critical';
      if (head === 'isVendorDefault') return 'critical';
      if (head === 'allowedFrom' || head === 'sshKeyFingerprints') return 'high';
      return 'medium';
    case 'ipsecPeer':
      if (head === 'pskFingerprint') return 'critical';
      return 'high';
    case 'route':
      if (head === 'distance' || head === 'checkGateway' || head === 'vrf') return 'high';
      return 'medium';
    case 'interface':
      if (head === 'addresses' || head === 'lists' || head === 'zone') return 'high';
      return 'medium';
    case 'vlan':
      if (head === 'taggedPorts' || head === 'untaggedPorts') return 'high';
      return 'medium';
    case 'dhcpScope':
      if (head === 'subnet' || head === 'gateway' || head === 'dnsServers') return 'high';
      return 'medium';
    case 'qosRule':
      return 'low';
    default:
      return 'medium';
  }
}

function maxSev(a: DiffSeverity, b: DiffSeverity): DiffSeverity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

// ============================================================================
// Field diffing
// ============================================================================

/**
 * Never diffed as values, and each exclusion is load-bearing:
 *   semKey / matchHash  derived from fields already compared
 *   managedBy / managedSlug  derived from `comment`, which IS compared
 *   keyQuality / via    metadata about the COLLECTION, not the config —
 *                       switching a device from SSH to the API must not make
 *                       every record look changed
 *   ordinal             a position discriminator; N2 says position is never a
 *                       field, and a `moved` is not a `changed`
 *   kind                the discriminator itself
 */
const NOT_A_FIELD = new Set([
  'semKey', 'matchHash', 'managedBy', 'managedSlug', 'keyQuality', 'via', 'ordinal', 'kind',
]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Dotted-path diff of two resources.
 *
 * ARRAYS ARE COMPARED WHOLE, never element by element. An index in a field path
 * would make the path unstable — `drift_findings.path` is what user ignore
 * rules match on, and §5.1 requires it to be index-free. Inserting one port in
 * a list must not invalidate every ignore rule written against that rule.
 */
function diffFields(
  intent: Record<string, unknown>,
  actual: Record<string, unknown>,
  prefix = '',
): NcmFieldDiff[] {
  const out: NcmFieldDiff[] = [];
  const keys = new Set([...Object.keys(intent), ...Object.keys(actual)]);
  for (const key of [...keys].sort()) {
    if (prefix === '' && NOT_A_FIELD.has(key)) continue;
    const a = intent[key];
    const b = actual[key];
    const field = prefix ? `${prefix}.${key}` : key;
    if (isPlainObject(a) && isPlainObject(b)) {
      out.push(...diffFields(a, b, field));
      continue;
    }
    if (JSON.stringify(a ?? null) === JSON.stringify(b ?? null)) continue;
    out.push({ field, intent: a ?? null, actual: b ?? null });
  }
  return out;
}

// ============================================================================
// Pairing (§3.5)
// ============================================================================

interface Rec {
  /** Index inside the ORDER GROUP, as collected. Used by phase 3's positional
   *  term and by the order analysis; never emitted as a field. */
  index: number;
  res: NcmResource;
}

interface Pair {
  intent: Rec;
  actual: Rec;
  method: MatchMethod;
  confidence: number;
  predicateChanged: boolean;
}

function anyRecord(r: NcmResource): Record<string, unknown> {
  return r as unknown as Record<string, unknown>;
}

function matchOf(r: NcmResource): NcmMatch | null {
  if (r.kind === 'firewallRule' || r.kind === 'natRule') return r.match;
  if (r.kind === 'qosRule') return r.match;
  return null;
}

function actionOf(r: NcmResource): string | null {
  if (r.kind === 'firewallRule' || r.kind === 'natRule') return r.action;
  return null;
}

/** The atoms of every selector dimension, as one set. Phase 3's Jaccard term
 *  runs on this: two rules that select nearly the same packets score high even
 *  when nothing else about them matches. */
function selectorAtoms(m: NcmMatch | null): Set<string> {
  const out = new Set<string>();
  if (!m) return out;
  if (m.protocol) out.add(`proto:${m.protocol}`);
  for (const a of m.srcAddress) out.add(`sa:${a}`);
  for (const a of m.dstAddress) out.add(`da:${a}`);
  for (const a of m.inInterface) out.add(`ii:${a}`);
  for (const a of m.outInterface) out.add(`oi:${a}`);
  if (m.srcZone) out.add(`sz:${m.srcZone}`);
  if (m.dstZone) out.add(`dz:${m.dstZone}`);
  for (const p of m.srcPort ?? []) out.add(`sp:${p[0]}-${p[1]}`);
  for (const p of m.dstPort ?? []) out.add(`dp:${p[0]}-${p[1]}`);
  for (const t of m.connectionState) out.add(`cs:${t}`);
  for (const t of m.connectionNat) out.add(`cn:${t}`);
  for (const t of m.tcpFlags) out.add(`tf:${t}`);
  if (m.icmpType) out.add(`it:${m.icmpType}`);
  if (m.ipsecPolicy) out.add(`ip:${m.ipsecPolicy}`);
  for (const t of m.unmodeledMatch) out.add(`um:${t}`);
  return out;
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 1;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  const union = a.size + b.size - inter;
  return union === 0 ? 0 : inter / union;
}

/** §3.5 phase 3, verbatim on the study's weights. Greedy and not Hungarian:
 *  at n <= a few hundred the optimality gain does not pay for the complexity,
 *  and a sub-optimal pairing produces noise, never a security error. */
function fuzzyScore(a: Rec, b: Rec, chainSize: number): number {
  const sel = jaccard(selectorAtoms(matchOf(a.res)), selectorAtoms(matchOf(b.res)));
  const actA = actionOf(a.res);
  const actB = actionOf(b.res);
  const sameAction = actA !== null && actA === actB ? 1 : 0;
  const ca = a.res.comment;
  const cb = b.res.comment;
  const sameComment = ca && cb && ca === cb ? 1 : 0;
  const posTerm = chainSize <= 1 ? 1 : 1 - Math.abs(a.index - b.index) / chainSize;
  return (
    FUZZY_MATCH.weightSelectorJaccard * sel +
    FUZZY_MATCH.weightSameAction * sameAction +
    FUZZY_MATCH.weightSameComment * sameComment +
    FUZZY_MATCH.weightPosition * Math.max(0, posTerm)
  );
}

function exactMethod(kind: NcmResourceKind, r: NcmResource): MatchMethod {
  if (ORDERED_RESOURCE_KINDS.has(kind)) {
    if (r.kind === 'qosRule' && r.name) return 'natural';
    return 'matchHash';
  }
  return 'natural';
}

interface PairingResult {
  pairs: Pair[];
  unpairedIntent: Rec[];
  unpairedActual: Rec[];
}

/**
 * The three phases of §3.5, on ONE (kind, orderGroup) bucket.
 *
 * Phase 1 is why drift is silent on everything ObliWAN owns: a marker-anchored
 * record stays paired through a simultaneous change of action, selectors AND
 * comment, so it yields ONE `changed` instead of a missing+extra pair that a
 * matcher has to reunite.
 */
function pairBucket(
  kind: NcmResourceKind,
  intent: Rec[],
  actual: Rec[],
  useFuzzy: boolean,
): PairingResult {
  const pairs: Pair[] = [];
  const takenIntent = new Set<number>();
  const takenActual = new Set<number>();

  // ── Phase 1 — markers. Never ambiguous. ──────────────────────────────────
  const bySlug = new Map<string, Rec[]>();
  for (const r of actual) {
    if (r.res.managedBy !== 'obliwan' || !r.res.managedSlug) continue;
    const list = bySlug.get(r.res.managedSlug);
    if (list) list.push(r);
    else bySlug.set(r.res.managedSlug, [r]);
  }
  for (const i of intent) {
    if (i.res.managedBy !== 'obliwan' || !i.res.managedSlug) continue;
    const candidates = bySlug.get(i.res.managedSlug);
    // Two records carrying the same slug on one device is a marker collision:
    // pairing either of them would be a coin flip, so neither is paired and
    // they fall through to the later phases on their own merits.
    if (!candidates || candidates.length !== 1) continue;
    const a = candidates[0];
    if (takenActual.has(a.index)) continue;
    takenIntent.add(i.index);
    takenActual.add(a.index);
    pairs.push({
      intent: i,
      actual: a,
      method: 'marker',
      confidence: 1,
      predicateChanged:
        matchOf(i.res) !== null &&
        JSON.stringify(matchOf(i.res)) !== JSON.stringify(matchOf(a.res)),
    });
  }

  // ── Phase 2 — exact semKey. ──────────────────────────────────────────────
  const byKey = new Map<string, Rec>();
  for (const a of actual) {
    if (takenActual.has(a.index)) continue;
    // A duplicate semKey inside one snapshot is a parser bug the indexer
    // refuses outright; here we simply keep the first and let the second fall
    // through rather than pairing arbitrarily.
    if (!byKey.has(a.res.semKey)) byKey.set(a.res.semKey, a);
  }
  for (const i of intent) {
    if (takenIntent.has(i.index)) continue;
    const a = byKey.get(i.res.semKey);
    if (!a || takenActual.has(a.index)) continue;
    takenIntent.add(i.index);
    takenActual.add(a.index);
    pairs.push({
      intent: i,
      actual: a,
      method: exactMethod(kind, i.res),
      confidence: 1,
      predicateChanged: false,
    });
  }

  const restIntent = intent.filter((r) => !takenIntent.has(r.index));
  const restActual = actual.filter((r) => !takenActual.has(r.index));

  // ── Phase 3 — fuzzy, on the residue, ORDERED KINDS ONLY. ─────────────────
  //
  // Deliberately not run on natural-key resources. An interface's name IS its
  // identity; pairing `ether1` with `ether5` because their addresses look
  // alike would produce a confidently wrong finding, and §3.5's scoring
  // function is written entirely in terms of a rule's selectors, action and
  // comment. A route whose gateway changed is a missing+extra BY DESIGN,
  // because the gateway is part of the route's identity.
  if (useFuzzy && ORDERED_RESOURCE_KINDS.has(kind) && restIntent.length > 0 && restActual.length > 0) {
    const chainSize = Math.max(intent.length, actual.length, 1);
    const scored: { i: Rec; a: Rec; s: number }[] = [];
    for (const i of restIntent) {
      for (const a of restActual) {
        const s = fuzzyScore(i, a, chainSize);
        if (s >= FUZZY_MATCH.threshold) scored.push({ i, a, s });
      }
    }
    scored.sort((x, y) => y.s - x.s || x.i.index - y.i.index || x.a.index - y.a.index);
    for (const cand of scored) {
      if (takenIntent.has(cand.i.index) || takenActual.has(cand.a.index)) continue;
      takenIntent.add(cand.i.index);
      takenActual.add(cand.a.index);
      pairs.push({
        intent: cand.i,
        actual: cand.a,
        method: 'fuzzy',
        confidence: Math.min(1, Number(cand.s.toFixed(3))),
        // By construction: phase 3 only ever pairs records the exact-key phase
        // refused, which for an ordered rule means the predicate moved.
        predicateChanged: true,
      });
    }
  }

  return {
    pairs,
    unpairedIntent: intent.filter((r) => !takenIntent.has(r.index)),
    unpairedActual: actual.filter((r) => !takenActual.has(r.index)),
  };
}

// ============================================================================
// Order (§4)
// ============================================================================

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
  if (rule.kind === 'firewallRule') {
    return TERMINAL_ACTIONS.has(rule.action as Parameters<typeof TERMINAL_ACTIONS.has>[0]);
  }
  return true;
}

/**
 * §4.4 row 2 — "crosses only non-terminal rules → severity low, the routing is
 * identical, the logging changes".
 *
 * That row is unreachable through `buildOrderSignature`, because §4.2 step 2
 * drops a pair unless at least one side is terminal. Both statements are in the
 * study and they contradict each other, so this is the reconciliation: the
 * forwarding-relevant signature stays exactly as §4.2 defines it (that is the
 * anti-noise lever), and a SECOND, clearly separate signature carries the
 * non-terminal crossings so they can be reported at `low` instead of being
 * silently folded into `inertMoveCount`.
 */
function isLoggingPair(a: NcmOrderedRule, b: NcmOrderedRule): boolean {
  if (a.disabled || b.disabled) return false;
  if (isTerminal(a) || isTerminal(b)) return false;
  if (effectKey(a) === effectKey(b)) return false;
  const ma = matchOf(a);
  const mb = matchOf(b);
  if (ma === null || mb === null) return true;
  return mayIntersect(ma, mb);
}

function loggingSignature(chain: readonly NcmOrderedRule[]): Set<string> {
  const pairs = new Set<string>();
  for (let i = 0; i < chain.length; i++) {
    for (let j = i + 1; j < chain.length; j++) {
      if (isLoggingPair(chain[i], chain[j])) pairs.add(`${chain[i].semKey}>${chain[j].semKey}`);
    }
  }
  return pairs;
}

/**
 * Fold a symmetric difference of precedence pairs into AT MOST ONE entry per
 * rule, attributing each flipped pair to ONE end.
 *
 * `crossedByRule` in the shared package attributes to BOTH ends on purpose: it
 * has no pairing and cannot know which rule the operator moved. The engine
 * does, so it decides here — the rule with the larger displacement is the one
 * that moved, ties broken deterministically by key. Without this, a single swap
 * of two rules produces TWO `moved` findings for ONE operator action, which is
 * precisely the kind of double counting R3 is about.
 */
function foldCrossings(
  intentPairs: ReadonlySet<string>,
  actualPairs: ReadonlySet<string>,
  displacement: ReadonlyMap<string, number>,
): Map<string, string[]> {
  const flipped = new Set<string>();
  const collect = (from: ReadonlySet<string>, to: ReadonlySet<string>): void => {
    for (const p of from) {
      if (to.has(p)) continue;
      const gt = p.indexOf('>');
      const a = p.slice(0, gt);
      const b = p.slice(gt + 1);
      flipped.add(a < b ? `${a}\u0000${b}` : `${b}\u0000${a}`);
    }
  };
  collect(intentPairs, actualPairs);
  collect(actualPairs, intentPairs);

  const out = new Map<string, string[]>();
  for (const key of flipped) {
    const [a, b] = key.split('\u0000');
    const da = displacement.get(a) ?? 0;
    const db = displacement.get(b) ?? 0;
    const owner = da > db ? a : db > da ? b : a < b ? a : b;
    const other = owner === a ? b : a;
    const cur = out.get(owner);
    if (cur) { if (!cur.includes(other)) cur.push(other); }
    else out.set(owner, [other]);
  }
  for (const [k, v] of out) out.set(k, v.sort());
  return out;
}

// ============================================================================
// The engine
// ============================================================================

function bucketsOf(doc: NcmDocument, kind: NcmResourceKind): Map<string, Rec[]> {
  const key = RESOURCE_KIND_TO_COLLECTION[kind] as keyof NcmDocument['resources'];
  const list = (doc.resources[key] ?? []) as unknown as NcmResource[];
  const out = new Map<string, Rec[]>();
  for (const res of list) {
    let group = '';
    if (res.kind === 'firewallRule' || res.kind === 'natRule') {
      group = res.chainName ? `${res.chain}:${res.chainName}` : res.chain;
    } else if (res.kind === 'qosRule') {
      group = res.queueClass;
    }
    const bucket = out.get(group);
    const rec: Rec = { index: bucket ? bucket.length : 0, res };
    if (bucket) bucket.push(rec);
    else out.set(group, [rec]);
  }
  return out;
}

function capForKeyQuality(
  severity: DiffSeverity,
  keyQuality: string,
  material: boolean,
): DiffSeverity {
  // §3.4 case 3. "We prefer to keep quiet about a real change than to drown the
  // drift screen — R3 wins." Stated in the study exactly that starkly.
  if (keyQuality === 'weak' && !material) return 'info';
  return severity;
}

export function semanticDiff(
  intent: NcmDocument,
  actual: NcmDocument,
  options: SemanticDiffOptions = {},
): NcmDiffReport {
  const scope: DiffScope = options.scope ?? 'managed_only';
  const useFuzzy = options.fuzzy ?? true;
  const claimed = options.claimedKinds ?? null;

  const findings: NcmDiffFinding[] = [];
  const suppressed: { resource: NcmResourceKind; reason: SuppressionReason }[] = [];
  let inertMoveCount = 0;
  let outOfScopeCount = 0;

  const suppress = (resource: NcmResourceKind, reason: SuppressionReason): void => {
    if (suppressed.some((s) => s.resource === resource && s.reason === reason)) return;
    suppressed.push({ resource, reason });
  };

  // ── Version skew (§8.2) ──────────────────────────────────────────────────
  // Two documents of different `ncmVersion` are NEVER diffed. Callers are
  // expected to run both sides through `upgradeNcm` first; if they did not, the
  // engine declines rather than comparing a v1 resource to a v2 one.
  if (
    intent.ncmVersion !== actual.ncmVersion ||
    intent.semKeyGeneration !== actual.semKeyGeneration
  ) {
    for (const kind of Object.keys(RESOURCE_KIND_TO_COLLECTION) as NcmResourceKind[]) {
      suppress(kind, 'version_skew');
    }
    return {
      ncmVersion: actual.ncmVersion,
      baseStateHash: ncmHash(actual),
      findings: [],
      inertMoveCount: 0,
      suppressed,
      scope,
      outOfScopeCount: 0,
    };
  }

  const orderDegraded = intent.orderAnalysis !== 'full' || actual.orderAnalysis !== 'full';
  const orderSkipped = intent.orderAnalysis === 'skipped' || actual.orderAnalysis === 'skipped';

  for (const kind of Object.keys(RESOURCE_KIND_TO_COLLECTION) as NcmResourceKind[]) {
    const actualCoverage = actual.coverage[kind];
    const intentCoverage = intent.coverage[kind];

    // A kind the collector could not read at all is not evaluated. Comparing
    // against "nothing was collected" is how a diff engine invents a firewall
    // that vanished.
    if (!actualCoverage || actualCoverage.state === 'unsupported' || actualCoverage.state === 'failed') {
      suppress(kind, 'coverage_incomplete');
      continue;
    }

    // N3, the guard. `missing` requires a COMPLETE observed side; `extra`
    // requires a complete desired side, by exactly the same argument.
    const allowMissing = mayEmitMissing(actual.coverage, kind);
    const allowExtra = mayEmitMissing(intent.coverage, kind);
    if (!allowMissing || !allowExtra) suppress(kind, 'coverage_incomplete');
    if (!intentCoverage || intentCoverage.state === 'unsupported' || intentCoverage.state === 'failed') {
      // Nothing was claimed on the desired side: every observed record would be
      // `extra`, which is exactly the 200-finding first run of R3.
      suppress(kind, 'coverage_incomplete');
      continue;
    }

    const intentBuckets = bucketsOf(intent, kind);
    const actualBuckets = bucketsOf(actual, kind);
    const groups = new Set([...intentBuckets.keys(), ...actualBuckets.keys()]);

    // §3.4 case 3, at the level of a whole kind: when every record on both
    // sides carries a `weak` key, positional pairing is a coin flip and an
    // unpaired record says nothing. The engine declines missing/extra for the
    // kind and says so, rather than guessing.
    const allRecs = [
      ...[...intentBuckets.values()].flat(),
      ...[...actualBuckets.values()].flat(),
    ];
    const weakOnly =
      allRecs.length > 1 && allRecs.every((r) => r.res.keyQuality === 'weak');
    if (weakOnly) suppress(kind, 'weak_keys');

    const ordered = ORDERED_RESOURCE_KINDS.has(kind);
    if (ordered && orderDegraded) suppress(kind, 'order_partial');

    for (const group of [...groups].sort()) {
      const i = intentBuckets.get(group) ?? [];
      const a = actualBuckets.get(group) ?? [];
      const { pairs, unpairedIntent, unpairedActual } = pairBucket(kind, i, a, useFuzzy);

      // ── changed ────────────────────────────────────────────────────────
      for (const pair of pairs) {
        const fieldDiffs = diffFields(anyRecord(pair.intent.res), anyRecord(pair.actual.res));
        if (fieldDiffs.length === 0) continue;
        const material = fieldDiffs.some((f) => !COSMETIC_FIELDS.has(f.field.split('.')[0]));
        let severity: DiffSeverity = 'info';
        for (const f of fieldDiffs) severity = maxSev(severity, severityForField(kind, f.field));
        severity = capForKeyQuality(severity, pair.actual.res.keyQuality, material);
        findings.push({
          kind: 'changed',
          resource: kind,
          semKey: pair.actual.res.semKey,
          path: findingPath('changed', pair.actual.res.semKey),
          severity,
          matchMethod: pair.method,
          matchConfidence: pair.confidence,
          // ONE finding, N fieldDiffs. §5.4 puts this at "divides the count by
          // 3 to 5 on wide resources", and it is the cheapest of the levers.
          fieldDiffs,
          crossed: [],
          intentValue: pair.intent.res as unknown,
          actualValue: pair.actual.res as unknown,
          predicateChanged: pair.predicateChanged,
        });
      }

      // ── missing (N3) ───────────────────────────────────────────────────
      if (allowMissing && !weakOnly) {
        for (const rec of unpairedIntent) {
          findings.push(
            unpairedFinding('missing', kind, rec, rec.res as unknown, null),
          );
        }
      }

      // ── extra (scope, §5.3) ────────────────────────────────────────────
      for (const rec of unpairedActual) {
        if (!allowExtra || weakOnly) break;
        const inScope =
          scope === 'full' ||
          rec.res.managedBy === 'obliwan' ||
          (claimed !== null && claimed.has(kind));
        if (!inScope) {
          // Inventoried and queryable (K5), but not a finding. Counted so the
          // Q2 compromise stays visible instead of becoming silent.
          outOfScopeCount++;
          continue;
        }
        findings.push(unpairedFinding('extra', kind, rec, null, rec.res as unknown));
      }

      // ── moved (§4) ─────────────────────────────────────────────────────
      if (!ordered || orderSkipped || pairs.length < 2) continue;

      // Signatures are built over PAIRED rules only, and the canonical id of a
      // pair replaces both semKeys so the two sides are comparable at all.
      //
      // Restricting to paired rules is what keeps an insertion cheap: adding a
      // rule at the head of a 40-rule chain leaves the mutual order of the 40
      // untouched, so it costs exactly ONE `extra` and ZERO `moved`. Including
      // the unpaired rule would instead flip 40 pairs and attribute a crossing
      // to every rule in the chain.
      const canonical = new Map<Rec, string>();
      pairs.forEach((p, n) => {
        const id = `p${n}:${p.intent.res.semKey}`;
        canonical.set(p.intent, id);
        canonical.set(p.actual, id);
      });

      const intentChain = pairs
        .slice()
        .sort((x, y) => x.intent.index - y.intent.index)
        .map((p) => ({ ...(p.intent.res as NcmOrderedRule), semKey: canonical.get(p.intent) as string }));
      const actualChain = pairs
        .slice()
        .sort((x, y) => x.actual.index - y.actual.index)
        .map((p) => ({ ...(p.actual.res as NcmOrderedRule), semKey: canonical.get(p.actual) as string }));

      const posIntent = new Map(intentChain.map((r, n) => [r.semKey, n]));
      const posActual = new Map(actualChain.map((r, n) => [r.semKey, n]));
      const displacement = new Map<string, number>();
      for (const [id, pi] of posIntent) {
        displacement.set(id, Math.abs((posActual.get(id) ?? pi) - pi));
      }

      const sigIntent = buildOrderSignature(intentChain);
      const sigActual = buildOrderSignature(actualChain);
      if (sigIntent.analysis === 'partial' || sigActual.analysis === 'partial') {
        suppress(kind, 'order_partial');
      }
      const decisive = foldCrossings(sigIntent.pairs, sigActual.pairs, displacement);
      const logging = foldCrossings(
        loggingSignature(intentChain),
        loggingSignature(actualChain),
        displacement,
      );

      const actualById = new Map(pairs.map((p) => [canonical.get(p.actual) as string, p]));
      const reported = new Set<string>();

      for (const [id, crossedIds] of decisive) {
        const pair = actualById.get(id);
        if (!pair) continue;
        const finding = movedFinding(kind, pair, crossedIds, actualById, 'high');
        if (!finding) continue;
        reported.add(id);
        findings.push(finding);
      }
      for (const [id, crossedIds] of logging) {
        if (reported.has(id)) continue;      // one finding per rule, maximum
        const pair = actualById.get(id);
        if (!pair) continue;
        const finding = movedFinding(kind, pair, crossedIds, actualById, 'low');
        if (!finding) continue;
        reported.add(id);
        findings.push(finding);
      }

      // §4.4 row 1: a reordering with no effect on forwarding produces NO
      // finding. The new position IS written to `ncm_*.position` — auditable,
      // never noisy — and the count is shown as one aggregated line.
      for (const [id, pi] of posIntent) {
        if (reported.has(id)) continue;
        if ((posActual.get(id) ?? pi) !== pi) inertMoveCount++;
      }
    }
  }

  return {
    ncmVersion: actual.ncmVersion,
    baseStateHash: ncmHash(actual),
    findings,
    inertMoveCount,
    suppressed,
    scope,
    outOfScopeCount,
  };
}

function unpairedFinding(
  kind: DiffKind & ('missing' | 'extra'),
  resource: NcmResourceKind,
  rec: Rec,
  intentValue: unknown,
  actualValue: unknown,
): NcmDiffFinding {
  const severity = capForKeyQuality(KIND_SEVERITY[resource], rec.res.keyQuality, true);
  return {
    kind,
    resource,
    semKey: rec.res.semKey,
    path: findingPath(kind, rec.res.semKey),
    severity,
    // The database CHECK `drift_findings_pairing_coherent` enforces this pair
    // of invariants; stating it here means the engine cannot produce a row the
    // database will reject at the end of a long run.
    matchMethod: 'none',
    matchConfidence: 1,
    fieldDiffs: [],
    crossed: [],
    intentValue: intentValue ?? null,
    actualValue: actualValue ?? null,
    predicateChanged: false,
  };
}

function movedFinding(
  resource: NcmResourceKind,
  pair: Pair,
  crossedIds: readonly string[],
  byId: ReadonlyMap<string, Pair>,
  severity: DiffSeverity,
): NcmDiffFinding | null {
  const crossed = crossedIds
    .map((id) => byId.get(id)?.actual.res.semKey)
    .filter((k): k is string => typeof k === 'string');
  // Belt and braces for §4.4: if every counterpart fell out of the map the move
  // is inert as far as anything we can NAME is concerned, and a `moved` we
  // cannot explain is worse than no finding at all.
  if (crossed.length === 0) return null;
  return {
    kind: 'moved',
    resource,
    semKey: pair.actual.res.semKey,
    path: findingPath('moved', pair.actual.res.semKey),
    severity: capForKeyQuality(severity, pair.actual.res.keyQuality, true),
    matchMethod: pair.method,
    matchConfidence: pair.confidence,
    fieldDiffs: [],
    // NEVER empty: an empty `crossed` is an inert move, §4.4 forbids emitting
    // it, and migration 007 refuses the row outright.
    crossed,
    intentValue: pair.intent.res as unknown,
    actualValue: pair.actual.res as unknown,
    predicateChanged: pair.predicateChanged,
  };
}
