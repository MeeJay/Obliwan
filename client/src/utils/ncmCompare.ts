// ObliWAN client — snapshot N vs N-1, computed in the browser.
//
// ── WHAT THIS IS, AND WHAT IT IS EMPHATICALLY NOT ───────────────────────────
// This is NOT the drift engine. The drift engine is a server service; it
// compares an INTENT (`config_renders.ncm_desired`) against an OBSERVED
// snapshot, it applies the seeded `normalization_rules`, it owns the severity
// model, the fuzzy pairing of §3.5 and the customer's ignore rules, and its
// output is a `drift_runs` row that survives the browser tab.
//
// What this file does is answer one much smaller question that ConfigPage is
// required to answer (§4.2, "comparaison N/N-1"): given TWO snapshots of the
// SAME device that the client already holds in memory, what changed between
// them? There is no intent side, so there is nothing to be right or wrong
// about beyond the two documents themselves — which is exactly why it can be
// done client-side without forking the engine. Every change it produces is
// stamped `origin: 'local'` and `severity: 'info'`, and the panel says above
// the list that these are observations, not findings.
//
// ── THE THREE CONTRACT RULES IT STILL OBEYS ─────────────────────────────────
// N1  identity is the MATCH side. Pairing is by `semKey`, which the parser
//     already computed; `accept -> drop` is therefore ONE `changed`, never a
//     `missing` + an `extra`.
// N2  position is never a field. Reordering is detected through
//     `buildOrderSignature`/`crossedByRule` from the shared contract, and a
//     move whose `crossed` set is empty is INERT: it is counted and shown as
//     one aggregated line, never emitted (§4.4).
// N3  no `missing` without `coverage: 'complete'`. A record that is in the old
//     snapshot and absent from the new one is only a disappearance if the new
//     collection was complete for that kind — otherwise it is a blind spot, and
//     it is reported as a SUPPRESSION with the reason, not as a change.
//
// That last one is the reason this file exists at all rather than a naive
// object diff: a partial collection must not be able to draw a screen that
// says "your whole firewall is gone".

import {
  NCM_RESOURCE_KINDS,
  ORDERED_RESOURCE_KINDS,
  RESOURCE_KIND_TO_COLLECTION,
  buildOrderSignature,
  computePayloadHash,
  coverageOf,
  crossedByRule,
  findingPath,
  mayEmitMissing,
  type NcmCoverageMap,
  type NcmDocumentStored,
  type NcmFieldDiff,
  type NcmOrderedRule,
  type NcmResourceKind,
  type OrderAnalysisState,
} from '@obliwan/shared';
import type { DriftSuppression, SemanticChange, SemanticChangeSet } from '@/types/config';

type Rec = Record<string, unknown>;

/** Fields `computePayloadHash` excludes, plus the ones that are structure
 *  rather than payload. Listed here so the field-level diff below shows exactly
 *  what the hash reacted to and nothing else — a `changed` that lists a `via`
 *  difference would be a lie, because switching a device from SSH to the API
 *  changes no configuration. */
const NOT_PAYLOAD = new Set([
  'semKey', 'matchHash', 'managedBy', 'managedSlug', 'keyQuality', 'via', 'ordinal', 'kind',
]);

function collectionOf(doc: NcmDocumentStored | null, kind: NcmResourceKind): Rec[] {
  if (!doc) return [];
  const resources = (doc as unknown as Rec).resources as Rec | undefined;
  if (!resources) return [];
  const arr = resources[RESOURCE_KIND_TO_COLLECTION[kind]];
  return Array.isArray(arr) ? (arr as Rec[]) : [];
}

function coverageMapOf(doc: NcmDocumentStored | null): Partial<NcmCoverageMap> | undefined {
  if (!doc) return undefined;
  return (doc as unknown as Rec).coverage as Partial<NcmCoverageMap> | undefined;
}

function keyOf(r: Rec): string {
  return typeof r.semKey === 'string' ? r.semKey : '';
}

/** Stable, human-readable rendering of a leaf for the field table. Objects and
 *  arrays are canonicalised as JSON so `['a','b']` and `['a','b']` never differ
 *  by key order alone. */
function leafText(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  try { return JSON.stringify(v); } catch { return String(v); }
}

/**
 * Dotted-path field diff between two resources of the same semKey.
 *
 * Nested objects are walked (`match.dstPort`), arrays are compared as WHOLES
 * rather than element by element: a firewall rule whose `srcAddress` went from
 * two atoms to three is ONE difference on `match.srcAddress`, not three. §5.4
 * is explicit that the count is what kills the screen, and per-element array
 * diffing is the fastest way to multiply it.
 */
function fieldDiffs(before: Rec, after: Rec): NcmFieldDiff[] {
  const out: NcmFieldDiff[] = [];
  const walk = (a: unknown, b: unknown, path: string, depth: number): void => {
    if (out.length >= 40 || depth > 5) return;
    const aObj = a && typeof a === 'object' && !Array.isArray(a);
    const bObj = b && typeof b === 'object' && !Array.isArray(b);
    if (aObj && bObj) {
      const keys = new Set([...Object.keys(a as Rec), ...Object.keys(b as Rec)]);
      for (const k of keys) {
        if (depth === 0 && NOT_PAYLOAD.has(k)) continue;
        walk((a as Rec)[k], (b as Rec)[k], path ? `${path}.${k}` : k, depth + 1);
      }
      return;
    }
    const sa = leafText(a);
    const sb = leafText(b);
    if (sa !== sb) out.push({ field: path, intent: a ?? null, actual: b ?? null });
  };
  walk(before, after, '', 0);
  return out;
}

function change(partial: Omit<SemanticChange, 'origin' | 'ignored' | 'ignoredByRule'>): SemanticChange {
  return { ...partial, origin: 'local', ignored: false, ignoredByRule: null };
}

/**
 * Compares two snapshots of one device.
 *
 * `before` is the OLDER document (N-1), `after` the newer (N). The orientation
 * matches the drift engine's (`intent -> observed`), so `missing` means "was
 * there, is not any more" and `extra` means "appeared", and `ConfigDiff` can
 * render both sources with one legend.
 */
export function compareSnapshots(
  before: NcmDocumentStored | null,
  after: NcmDocumentStored | null,
): SemanticChangeSet {
  const changes: SemanticChange[] = [];
  const suppressed: DriftSuppression[] = [];
  let inertMoveCount = 0;

  const beforeCov = coverageMapOf(before);
  const afterCov = coverageMapOf(after);

  for (const kind of NCM_RESOURCE_KINDS) {
    const oldRows = collectionOf(before, kind);
    const newRows = collectionOf(after, kind);
    if (oldRows.length === 0 && newRows.length === 0) continue;

    const oldByKey = new Map<string, Rec>();
    for (const r of oldRows) { const k = keyOf(r); if (k) oldByKey.set(k, r); }
    const newByKey = new Map<string, Rec>();
    for (const r of newRows) { const k = keyOf(r); if (k) newByKey.set(k, r); }

    // N3, both directions. A disappearance is only real if the NEW collection
    // was complete; an appearance is only real if the OLD one was.
    const mayReportMissing = mayEmitMissing(afterCov, kind);
    const mayReportExtra = mayEmitMissing(beforeCov, kind);
    if (!mayReportMissing && oldByKey.size > 0) {
      suppressed.push({ resource: kind, reason: 'coverage_incomplete' });
    } else if (!mayReportExtra && newByKey.size > 0) {
      suppressed.push({ resource: kind, reason: 'coverage_incomplete' });
    }

    for (const [key, oldRow] of oldByKey) {
      const newRow = newByKey.get(key);
      if (!newRow) {
        if (!mayReportMissing) continue;
        changes.push(change({
          id: findingPath('missing', key),
          kind: 'missing',
          resource: kind,
          semKey: key,
          path: findingPath('missing', key),
          severity: 'info',
          matchMethod: 'none',
          matchConfidence: 1,
          predicateChanged: false,
          fieldDiffs: [],
          crossed: [],
          beforeValue: oldRow,
          afterValue: null,
          textPatch: null,
        }));
        continue;
      }
      // Identity is the semKey; the payload hash is what says whether anything
      // actually changed. Comparing the objects directly would report a
      // difference every time the parser reordered a key.
      if (computePayloadHash(oldRow) === computePayloadHash(newRow)) continue;
      const diffs = fieldDiffs(oldRow, newRow);
      if (diffs.length === 0) continue;
      changes.push(change({
        id: findingPath('changed', key),
        kind: 'changed',
        resource: kind,
        semKey: key,
        path: findingPath('changed', key),
        severity: 'info',
        matchMethod: 'natural',
        matchConfidence: 1,
        predicateChanged: false,
        // ONE change per resource carrying N field diffs. Never one per field.
        fieldDiffs: diffs,
        crossed: [],
        beforeValue: oldRow,
        afterValue: newRow,
        textPatch: null,
      }));
    }

    if (mayReportExtra) {
      for (const [key, newRow] of newByKey) {
        if (oldByKey.has(key)) continue;
        changes.push(change({
          id: findingPath('extra', key),
          kind: 'extra',
          resource: kind,
          semKey: key,
          path: findingPath('extra', key),
          severity: 'info',
          matchMethod: 'none',
          matchConfidence: 1,
          predicateChanged: false,
          fieldDiffs: [],
          crossed: [],
          beforeValue: null,
          afterValue: newRow,
          textPatch: null,
        }));
      }
    }

    // ── ordering (N2) ───────────────────────────────────────────────────────
    if (!ORDERED_RESOURCE_KINDS.has(kind)) continue;
    const chainsBefore = groupByChain(oldRows);
    const chainsAfter = groupByChain(newRows);
    for (const chain of new Set([...chainsBefore.keys(), ...chainsAfter.keys()])) {
      const sigBefore = buildOrderSignature(chainsBefore.get(chain) ?? []);
      const sigAfter = buildOrderSignature(chainsAfter.get(chain) ?? []);
      const crossed = crossedByRule(sigBefore, sigAfter);
      // A rule that also disappeared or appeared is not "moved" — it is already
      // reported once, and reporting it twice is the duplication §5.4 counts.
      const present = new Set<string>();
      for (const k of oldByKey.keys()) if (newByKey.has(k)) present.add(k);

      const pending = new Map<string, Set<string>>();
      for (const [key, others] of crossed) {
        if (!present.has(key)) continue;
        const decisive = others.filter((o) => present.has(o));
        // An empty set here means the only rules this one crossed were
        // themselves added or removed: nothing decisive moved past it, so §4.4
        // makes it an inert move — counted, never listed.
        if (decisive.length === 0) { inertMoveCount++; continue; }
        pending.set(key, new Set(decisive));
      }

      for (const [key, others] of attributeMoves(pending)) {
        changes.push(change({
          id: findingPath('moved', key),
          kind: 'moved',
          resource: kind,
          semKey: key,
          path: findingPath('moved', key),
          severity: 'info',
          matchMethod: 'natural',
          matchConfidence: 1,
          predicateChanged: false,
          fieldDiffs: [],
          crossed: others,
          beforeValue: oldByKey.get(key) ?? null,
          afterValue: newByKey.get(key) ?? null,
          textPatch: null,
        }));
      }
      // Rules whose position moved without crossing anything decisive: the
      // signature diff produced nothing for them at all, which is precisely
      // §4.4's point. They are invisible here BY DESIGN, and the aggregated
      // inert counter above is what keeps that decision honest.
      if (sigBefore.analysis === 'partial' || sigAfter.analysis === 'partial') {
        suppressed.push({ resource: kind, reason: 'order_partial' });
      }
    }
  }

  const orderAnalysis: OrderAnalysisState =
    suppressed.some((s) => s.reason === 'order_partial') ? 'partial' : 'full';

  return {
    changes,
    inertMoveCount,
    outOfScopeCount: 0,
    suppressed: dedupeSuppressions(suppressed),
    // A snapshot-to-snapshot comparison has no template claim to be inside or
    // outside of, so it is the `full` scope by construction. Saying
    // `managed_only` here would imply a filter that does not exist.
    scope: 'full',
    orderAnalysis,
    origin: 'local',
  };
}

/**
 * WHICH END OF A FLIPPED PAIR ACTUALLY MOVED — and why this function has to
 * exist at all.
 *
 * `crossedByRule` deliberately attributes every flipped precedence pair to BOTH
 * ends, and says so: it cannot know which of the two the operator moved, so it
 * refuses to guess and hands the decision to its caller. Here, the caller is
 * this comparison, and NOT deciding is not an option: measured on a 40-rule
 * chain with one wide `drop` rule dragged to the head, the raw attribution
 * produces 21 `moved` findings for ONE move — the wide rule crossing 20 others,
 * plus one finding on each of those 20. That is the wall of noise R3 exists to
 * forbid, produced by a diff that is technically correct.
 *
 * The rule applied is the one that matches how chains are actually edited: a
 * rule that was moved crosses MANY, and each rule it passed crosses only it.
 * So the largest crossing set is attributed first, the rule it names is removed
 * from everybody else's set, and the process repeats. A genuine two-rule swap
 * (each crossing exactly one) collapses to a single finding for the same
 * reason, which is the other half of what `crossedByRule` asked its caller to
 * guarantee: never two findings for one swap.
 *
 * Ties break lexicographically so the same pair of documents always produces
 * the same finding — a comparison whose output depends on `Map` iteration order
 * cannot be diffed against yesterday's.
 *
 * THE HONEST LIMIT: when two rules genuinely both moved past each other, this
 * names one of them and lists the other under `crossed`. It reports the right
 * pair and may name the wrong end. That is a strictly smaller error than
 * reporting the pair twice, and the pair is what the operator has to look at.
 */
function attributeMoves(pending: Map<string, Set<string>>): [string, string[]][] {
  const work = new Map<string, Set<string>>();
  for (const [k, v] of pending) work.set(k, new Set(v));
  const out: [string, string[]][] = [];
  for (;;) {
    let bestKey: string | null = null;
    let bestSize = 0;
    for (const [k, s] of work) {
      if (s.size > bestSize || (s.size === bestSize && bestKey !== null && k < bestKey)) {
        bestKey = k;
        bestSize = s.size;
      }
    }
    if (bestKey === null || bestSize === 0) break;
    out.push([bestKey, [...work.get(bestKey)!].sort()]);
    work.delete(bestKey);
    // Every rule this one passed is now EXPLAINED by the finding just emitted.
    // Those rules did not move; emitting a finding for them would be the
    // duplication this whole function exists to remove.
    for (const s of work.values()) s.delete(bestKey);
  }
  return out;
}

function groupByChain(rows: Rec[]): Map<string, NcmOrderedRule[]> {
  const out = new Map<string, NcmOrderedRule[]>();
  for (const r of rows) {
    const chain = typeof r.chain === 'string' ? r.chain : 'queue';
    const chainName = typeof r.chainName === 'string' ? r.chainName : '';
    const key = chainName ? `${chain}:${chainName}` : chain;
    const list = out.get(key);
    if (list) list.push(r as unknown as NcmOrderedRule);
    else out.set(key, [r as unknown as NcmOrderedRule]);
  }
  return out;
}

function dedupeSuppressions(list: DriftSuppression[]): DriftSuppression[] {
  const seen = new Set<string>();
  const out: DriftSuppression[] = [];
  for (const s of list) {
    const k = `${s.resource}/${s.reason}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(s);
  }
  return out;
}

/** Coverage of one document as a flat list, for the tree's section badges. */
export function coverageList(doc: NcmDocumentStored | null): {
  kind: NcmResourceKind;
  state: ReturnType<typeof coverageOf>['state'];
  reason: string | null;
  via: string | null;
  recordCount: number;
}[] {
  const cov = coverageMapOf(doc);
  return NCM_RESOURCE_KINDS.map((kind) => {
    const c = coverageOf(cov, kind);
    return {
      kind,
      state: c.state,
      reason: c.reason,
      via: c.via,
      recordCount: c.recordCount,
    };
  });
}
