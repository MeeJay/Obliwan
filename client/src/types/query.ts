// ObliWAN client — M9 Fleet Query DTOs (killer K5).
//
// The DSL itself is parsed SERVER-SIDE by Chevrotain and lowered to
// JSONPath/SQL against the flattened `ncm_*` tables, behind a strict whitelist
// of paths derived from the NCM schema (§5/M9). This file describes the
// envelope the HTTP routes carry, and nothing else: the client does not
// evaluate the DSL, it only helps write it and renders what came back.
//
// ── WHY THE CLIENT KNOWS THE SCHEMA ANYWAY ──────────────────────────────────
// Autocompletion has to come from somewhere, and there are exactly two
// choices: a hand-maintained list in the client, or the NCM contract itself.
// The first drifts silently the day a resource gains a field — and a query
// language whose autocompletion is subtly wrong is worse than one with none,
// because the operator trusts it. So `components/query/ncmSchema.ts` walks the
// Zod schemas in `@obliwan/shared/ncm` at runtime. The whitelist that actually
// GATES the query stays on the server, where a whitelist belongs; the client
// list is an ergonomics aid derived from the same source of truth.

// ── Results ─────────────────────────────────────────────────────────────────

export interface QueryColumn {
  key: string;
  /** Path as written in the DSL, so a column header is a thing the operator
   *  can paste back into the editor. */
  path: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
}

/**
 * One matched device.
 *
 * `matches` is the DRILL-DOWN payload: the individual resources that satisfied
 * the predicate, already redacted server-side. A result that says "device X
 * matched" without saying WHICH rule matched is an audit nobody can action —
 * §5/M9's "résultats drill-down" is that requirement.
 */
export interface QueryRow {
  deviceId: number;
  deviceName: string | null;
  siteId: number | null;
  siteName: string | null;
  brand: string;
  model: string | null;
  osVersion: string | null;
  /** Flat cells for the table, keyed by `QueryColumn.key`. */
  cells: Record<string, unknown>;
  /** Resources that matched, for the expanded row. */
  matches: QueryMatch[];
  /** Snapshot the answer was computed from. A fleet query answers about a
   *  SNAPSHOT, never about a live box, and the age of that snapshot is part of
   *  the answer. */
  snapshotId: string | null;
  snapshotAt: string | null;
}

export interface QueryMatch {
  resource: string;
  semKey: string;
  /** Redacted resource body as the server shipped it. Painted through
   *  `secretScan` all the same — §8.2, and this one carries brand extensions. */
  value: unknown;
}

export interface QueryResult {
  columns: QueryColumn[];
  rows: QueryRow[];
  /** Devices EXAMINED, not matched. "12 of 300" is the sentence that makes a
   *  fleet answer meaningful; "12" on its own is a number. */
  devicesExamined: number;
  elapsedMs: number;
  /** True when the server capped the result set. A truncated answer must never
   *  be presented as a complete one — an audit that silently drops rows is an
   *  audit that certifies boxes nobody looked at. */
  truncated: boolean;
  /** Devices skipped because they have no snapshot at all. Reported, never
   *  folded into "no match": never-collected and clean are different facts. */
  devicesWithoutSnapshot: number;
  /** Server sentence about what this answer does NOT claim. */
  notice: string | null;
}

// ── Parse / validation feedback ─────────────────────────────────────────────

export interface QueryError {
  message: string;
  /** 0-based offset into the DSL text, when the parser gives one. */
  offset: number | null;
  length: number | null;
  /** `path_not_allowed` is NOT a syntax error and is labelled separately: it
   *  means the whitelist refused a path, which is a security answer and not a
   *  typo. */
  kind: 'syntax' | 'path_not_allowed' | 'unsupported' | 'server';
}

// ── Saved queries and policies ──────────────────────────────────────────────

export const POLICY_SEVERITIES = ['info', 'warning', 'critical'] as const;
export type PolicySeverity = (typeof POLICY_SEVERITIES)[number];

/**
 * A saved query, and — when `isPolicy` — one that is re-evaluated at every
 * snapshot (§5/M9).
 *
 * The promotion is a distinct flag rather than a separate object because the
 * text must stay identical: a policy that drifted from the query it was
 * promoted from is a policy nobody reviewed.
 */
export interface SavedQuery {
  id: number;
  name: string;
  dsl: string;
  description: string | null;
  isPolicy: boolean;
  severity: PolicySeverity;
  createdByName: string | null;
  createdAt: string;
  /** Last evaluation of the POLICY. Null on a query that was never promoted. */
  lastRunAt: string | null;
  lastMatchCount: number | null;
}

export interface SaveQueryRequest {
  name: string;
  dsl: string;
  description?: string | null;
  isPolicy?: boolean;
  severity?: PolicySeverity;
}
