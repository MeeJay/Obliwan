// ============================================================================
// @obliwan/shared — normalization contract
// ============================================================================
//
// Implements §5.5 of `docs/M4-normalisation-routeros.md`. The ENGINE is a
// server service; what lives here is the vocabulary the engine, the database
// (migration 007) and the rule editor in the UI must all agree on.
//
// DOCTRINE, from §0 of that study: a normalization rule is allowed to exist
// only if someone wrote down what it can HIDE. `rationale` and `falseNegative`
// are NOT NULL in the database for that reason, and they are required here.
// A rule whose false negative is undocumented is an undebuggable rule, and the
// first bad normalization in production costs a day of investigation and the
// operator's trust in the product.

import type { DeviceBrand, DeviceFamily } from '../device';
import type { DiffSeverity } from './diff';
import { canonicalJson, sha256Short } from './hash';

/**
 * The four layers of D3. The layer is what makes the doctrine executable: the
 * engine cannot apply an L3 rule to raw text, and the UI can refuse an L1 rule
 * without review.
 *   1 — raw text (line / section removal). EXCEPTIONAL USE.
 *   2 — lexical canonicalisation (unquoting, prop ordering, line unwrapping).
 *   3 — semantic (NCM level): ignore, default fill, sorting, path aliasing.
 *   4 — finding level: severity override, suppression.
 */
export type NormalizationLayer = 1 | 2 | 3 | 4;

export const NORMALIZATION_KINDS = [
  'strip_line', 'strip_section', 'canonicalize', 'ignore_prop', 'ignore_entry',
  'default_fill', 'sort_set', 'map_path', 'rewrite_value', 'mask_secret',
  'severity_override', 'suppress_finding',
] as const;
export type NormalizationKind = (typeof NORMALIZATION_KINDS)[number];

/** Which layer each kind belongs to. Single source of truth, mirrored by the
 *  CHECK constraint in migration 007. */
export const NORMALIZATION_KIND_LAYER: Readonly<Record<NormalizationKind, NormalizationLayer>> = {
  strip_line: 1,
  strip_section: 1,
  canonicalize: 2,
  ignore_prop: 3,
  ignore_entry: 3,
  default_fill: 3,
  sort_set: 3,
  map_path: 3,
  rewrite_value: 3,
  mask_secret: 3,
  severity_override: 4,
  suppress_finding: 4,
};

export const NORMALIZATION_SCOPES = ['global', 'brand', 'group', 'device'] as const;
export type NormalizationScope = (typeof NORMALIZATION_SCOPES)[number];

/** Specificity order: the MOST specific rule applies LAST, so it can correct
 *  the more general one. Mirrors the ORDER BY frozen in §5.1 of the study. */
export const NORMALIZATION_SCOPE_RANK: Readonly<Record<NormalizationScope, number>> = {
  global: 0, brand: 1, group: 2, device: 3,
};

export interface EntryPredicate {
  prop: string;
  eq?: string | number | boolean;
  /** Anchored regex — the lint of §6.4 rejects an unanchored one. */
  matches?: string;
  notEmpty?: boolean;
}

export interface NormalizationRule {
  id: number;
  uuid: string;
  /** Stable identifier of a seeded rule ('ros.header.strip'). Reconciled by key
   *  at every migration WITHOUT overwriting the user's `enabled` / `severity`. */
  builtinKey: string | null;
  scope: NormalizationScope;
  scopeId: number | null;
  brand: DeviceBrand | null;
  family: DeviceFamily | null;
  osMin: string | null;   // semver range
  osMax: string | null;
  name: string;
  description: string;
  /** WHY this is not a real change. */
  rationale: string;
  /** WHAT IT CAN HIDE. Never empty — this is the contract. */
  falseNegative: string;
  layer: NormalizationLayer;
  kind: NormalizationKind;
  sectionPath: string | null;
  /** Default TRUE, deliberately: sorting a firewall chain destroys its
   *  semantics (ARCHITECTURE.md §3.4). */
  sectionOrdered: boolean;
  prop: string | null;
  pattern: string | null;
  replacement: string | null;
  predicate: EntryPredicate | null;
  value: unknown;
  targetPath: string | null;
  severity: DiffSeverity | null;
  applyOrder: number;
  enabled: boolean;
}

/** One row of `ncm_section_catalog` — the doctrine, not free-form data. An
 *  operator must not be able to declare `/ip/firewall/filter` unordered by
 *  accident, which is why this is a separate, capability-gated table. */
export interface NcmSectionSpec {
  sectionPath: string;
  family: DeviceFamily | null;
  ordered: boolean;
  /** Position is relative to this prop's value ('chain'), not to the file. */
  orderGroupProp: string | null;
  semKeyProps: string[];
  semKeyFallback: string[] | null;
  semKeyVersion: number;
  secretProps: string[];
  stateProps: string[];
  counterProps: string[];
  /** Hard bound on `default_fill`: these props are never filled in. */
  noDefaultFillProps: string[];
  defaultSeverity: DiffSeverity;
  ros6Path: string | null;
  ros7Path: string | null;
}

/** A parsed entry, before the typed NCM. */
export interface RawEntry {
  sectionPath: string;      // '/ip/firewall/filter'
  verb: 'add' | 'set' | 'remove';
  props: Record<string, string>;
  /** Index in the raw text — indispensable to debugging a rule. */
  sourceLine: number;
}

/** An entry after normalisation, before it becomes a typed NCM resource. */
export interface NcmEntry {
  sectionPath: string;
  semKey: string;
  semKeyVersion: number;
  position: number | null;       // null when the section is unordered
  orderGroup: string | null;     // 'input' for chain=input
  isDynamic: boolean;
  isManaged: boolean;            // comment ~ '^obliwan:'
  props: Record<string, unknown>;
}

/**
 * Application trace. NOT a convenience.
 *
 * This is what answers, on the Drift screen, "why is this router in_sync when I
 * just changed it?" by naming the rule responsible. Without it, the first false
 * normalization in production costs a day of investigation and the trust in the
 * tool. Always produced, stored with the run.
 */
export interface NormalizationTrace {
  ruleId: number;
  builtinKey: string | null;
  sectionPath: string | null;
  semKey: string | null;
  prop: string | null;
  before: unknown;
  after: unknown;
  sourceLine: number | null;
}

export interface NormalizeResult {
  /** Typed as unknown here to keep this module free of a cycle with model.ts;
   *  the service narrows it with `NcmDocument.parse`. */
  ncm: unknown;
  ncmHash: string;
  osVersion: string | null;
  model: string | null;
  serial: string | null;
  traces: NormalizationTrace[];
  /** N05: props we saw and do not know. Feeds the model's own backlog. */
  unknownProps: Array<{ sectionPath: string; prop: string }>;
  warnings: string[];
}

export interface NormalizeContext {
  family: DeviceFamily;
  osVersion: string | null;
  /** Already sorted by the order resolver — the engine must not re-sort. */
  rules: NormalizationRule[];
  sectionCatalog: Map<string, NcmSectionSpec>;
  /** Key `'<sectionPath>|<prop>'`, sourced from `routeros_defaults`. */
  defaults: Map<string, unknown>;
}

/**
 * The frozen application order of §5.1. Duplicating it in SQL and in the engine
 * is how the two silently diverge, so both call this.
 *
 *   layer ASC, scope specificity ASC, applyOrder ASC, id ASC
 *
 * The most specific rule applies LAST (it may therefore correct the more
 * general one), and no two rules can ever be ambiguously ordered thanks to the
 * `id` tie-break.
 */
export function compareNormalizationRules(a: NormalizationRule, b: NormalizationRule): number {
  return (
    a.layer - b.layer ||
    NORMALIZATION_SCOPE_RANK[a.scope] - NORMALIZATION_SCOPE_RANK[b.scope] ||
    a.applyOrder - b.applyOrder ||
    a.id - b.id
  );
}

/**
 * `NcmDocument.normalizationEpoch` — a 16-hex-char fingerprint of the EFFECTIVE
 * rule set applied to a document.
 *
 * It is inside `ncmHash` on purpose: editing a normalization rule really does
 * change the NCM, so it really is a new snapshot. What it buys is attribution —
 * the resulting drift run is labelled `renormalization` and is never blamed on
 * a human (§6.5). Inventing a culprit for a change caused by our own deployment
 * is precisely the failure mode `unattributed` exists to avoid.
 *
 * Only the fields that can change the OUTPUT are hashed. `name`,
 * `description`, `rationale`, `falseNegative` and the observability counters are
 * excluded: fixing a typo in a rationale must not re-snapshot the entire fleet.
 */
export function computeNormalizationEpoch(rules: readonly NormalizationRule[]): string {
  const effective = rules
    .filter((r) => r.enabled)
    .slice()
    .sort(compareNormalizationRules)
    .map((r) => ({
      k: r.builtinKey ?? `#${r.id}`,
      s: r.scope, si: r.scopeId,
      b: r.brand, f: r.family, mn: r.osMin, mx: r.osMax,
      l: r.layer, kd: r.kind,
      sp: r.sectionPath, so: r.sectionOrdered,
      p: r.prop, pt: r.pattern, rp: r.replacement,
      pr: r.predicate ?? null, v: r.value ?? null, tp: r.targetPath,
      sv: r.severity, ao: r.applyOrder,
    }));
  return sha256Short(canonicalJson(effective));
}

/** The epoch of "no rules at all" — what a parser uses in a unit test, and what
 *  a fresh install carries before the builtin rules are seeded. */
export const EMPTY_NORMALIZATION_EPOCH: string = computeNormalizationEpoch([]);
