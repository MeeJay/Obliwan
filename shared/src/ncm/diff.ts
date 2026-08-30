// ============================================================================
// @obliwan/shared — semantic diff types
// ============================================================================
//
// Implements §5 of `docs/M4-NCM-contrat.md`. TYPES ONLY: the engine is a server
// service, but the client renders findings and must agree on their shape, and
// the shape is what the anti-noise budget of §5.4 is actually made of.
//
// The diff is oriented DESIRED -> OBSERVED: `intent` is
// `config_renders.ncm_desired`, `actual` is `config_snapshots.ncm`.

import { z } from 'zod';
import { NCM_RESOURCE_KINDS } from './resources';

export const DIFF_KINDS = ['missing', 'extra', 'changed', 'moved'] as const;
export type DiffKind = (typeof DIFF_KINDS)[number];

export const DIFF_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type DiffSeverity = (typeof DIFF_SEVERITIES)[number];

/** Ordering for `drift_runs.max_severity`. */
export const SEVERITY_RANK: Readonly<Record<DiffSeverity, number>> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

/**
 * How the two sides were paired (§3.5). PERSISTED on the finding, and not for
 * decoration: K6 must not attribute a fuzzy pairing with the confidence of an
 * anchor, and K2 must not prove anything from a fuzzy pair (risk N-R6).
 *
 *  'marker'    phase 1 — anchored on `obliwan:<slug>`. Never ambiguous.
 *  'natural'   phase 2 — a name the device itself carries.
 *  'matchHash' phase 2 — same predicate, same ordinal.
 *  'fuzzy'     phase 3 — greedy bipartite scoring on the residue.
 *  'none'      unpaired: this finding is a `missing` or an `extra`.
 */
export const MATCH_METHODS = ['marker', 'natural', 'matchHash', 'fuzzy', 'none'] as const;
export type MatchMethod = (typeof MATCH_METHODS)[number];

/** Phase-3 scoring weights and threshold (§3.5). Open arbitration Q6: these
 *  CANNOT be chosen a priori and must be calibrated on the two-week corpus with
 *  false pairings counted by hand. They live here so the calibration is one
 *  edit in one place, and so the diff engine cannot quietly grow its own. */
export const FUZZY_MATCH = {
  weightSelectorJaccard: 0.55,
  weightSameAction: 0.20,
  weightSameComment: 0.15,
  weightPosition: 0.10,
  threshold: 0.60,
} as const;

export const NcmFieldDiff = z.object({
  /** Dotted field path inside the resource: 'action', 'match.dstPort'. */
  field: z.string().max(120),
  intent: z.unknown(),
  actual: z.unknown(),
}).strict();
export type NcmFieldDiff = z.infer<typeof NcmFieldDiff>;

export const NcmDiffFinding = z.object({
  kind: z.enum(DIFF_KINDS),
  resource: z.enum(NCM_RESOURCE_KINDS),
  semKey: z.string().max(180),
  /** Stable, INDEX-FREE path written to `drift_findings.path` and matched by
   *  user ignore rules: '<kind>/<semKey>' or '<kind>/<semKey>/<field>'. An
   *  array index in this path would invalidate every ignore rule a customer
   *  wrote the next time a rule is inserted above. */
  path: z.string().max(240),
  severity: z.enum(DIFF_SEVERITIES),
  matchMethod: z.enum(MATCH_METHODS),
  matchConfidence: z.number().min(0).max(1),
  /** ONE finding per resource, carrying N field diffs. NEVER one per field —
   *  that alone divides the count by 3 to 5 on wide resources (§5.4). */
  fieldDiffs: z.array(NcmFieldDiff),
  /** `moved` only: the DECISIVE rules this one crossed. Empty => the move is
   *  inert and the finding is not emitted at all (§4.4). */
  crossed: z.array(z.string().max(180)),
  intentValue: z.unknown().nullable(),
  actualValue: z.unknown().nullable(),
  /** true when the pairing came from phase 3 and the match side itself moved. */
  predicateChanged: z.boolean(),
}).strict();
export type NcmDiffFinding = z.infer<typeof NcmDiffFinding>;

/** Why the engine declined to evaluate a whole resource kind. Each value is a
 *  fail-closed decision, not an error. */
export const SUPPRESSION_REASONS = [
  'coverage_incomplete', 'version_skew', 'order_partial', 'weak_keys',
] as const;
export type SuppressionReason = (typeof SUPPRESSION_REASONS)[number];

export const DIFF_SCOPES = ['managed_only', 'full'] as const;
export type DiffScope = (typeof DIFF_SCOPES)[number];

export const NcmDiffReport = z.object({
  ncmVersion: z.number().int(),
  baseStateHash: z.string().length(64),   // ncm_hash of the OBSERVED side
  findings: z.array(NcmDiffFinding),
  /** Reorderings with no effect on forwarding. Counted, shown as ONE aggregated
   *  line, never emitted as findings (§4.4). */
  inertMoveCount: z.number().int().min(0),
  suppressed: z.array(z.object({
    resource: z.enum(NCM_RESOURCE_KINDS),
    reason: z.enum(SUPPRESSION_REASONS),
  }).strict()),
  /**
   * `managed_only` is the DEFAULT (open arbitration Q2). On a taken-over fleet
   * a device carries 200 rules ObliWAN did not write; a naive diff emits 200
   * `extra` on the first run, which is exactly scenario R3. Outside a claimed
   * template section, an observed object is inventoried and queryable (K5) but
   * is NOT a finding. `full` exists for compliance audit and K8 and must be
   * asked for explicitly.
   */
  scope: z.enum(DIFF_SCOPES),
  /** The permanent counter that keeps the `managed_only` blind spot VISIBLE.
   *  Without it, Q2's compromise becomes a silent one. */
  outOfScopeCount: z.number().int().min(0),
}).strict();
export type NcmDiffReport = z.infer<typeof NcmDiffReport>;

/** Builds the ignore-rule-stable path of §5.1. The single place that knows the
 *  format, so a change is one edit and not a fleet-wide invalidation. */
export function findingPath(kind: DiffKind, semKey: string, field?: string): string {
  return field ? `${kind}/${semKey}/${field}` : `${kind}/${semKey}`;
}

/** `drift_runs.max_severity` from a finding list. Ignored findings are excluded
 *  by the caller BEFORE this is called — an ignored critical must not keep a
 *  device red, which is the point of keeping ignored findings at all. */
export function maxSeverity(findings: readonly NcmDiffFinding[]): DiffSeverity | null {
  let best: DiffSeverity | null = null;
  for (const f of findings) {
    if (best === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]) best = f.severity;
  }
  return best;
}
