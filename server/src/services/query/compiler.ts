// ============================================================================
// ObliWAN — Fleet Query (K5): AST -> SQL
// ============================================================================
//
// ┌─ THE ONE INVARIANT THIS FILE EXISTS TO HOLD ──────────────────────────────┐
// │                                                                           │
// │   THE GENERATED SQL CONTAINS NO SINGLE QUOTE. NOT ONE.                    │
// │                                                                           │
// │ Every value — a user's `"input"`, a path segment out of the whitelist, and │
// │ the compiler's OWN constants `[]`, `array`, `number` — is appended to the  │
// │ binding array and referenced as `?`. Nothing else is ever concatenated     │
// │ into the statement except fixed keywords and column names written out in   │
// │ this file. `assertNoLiterals()` checks it on every compile and throws a    │
// │ 500 rather than emit a statement it cannot vouch for.                     │
// │                                                                           │
// │ That check is worth more than a review: it is decidable in one line, it    │
// │ cannot be argued with, and it catches the future edit that "just" inlines  │
// │ a value because it looked safe. The whitelist of paths is a CORRECTNESS    │
// │ guard and is explicitly NOT what makes this safe.                          │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ TENANT SCOPING IS THE OTHER HALF ────────────────────────────────────────┐
// │ `config_snapshots` has no tenant column. The join to `devices` and the     │
// │ `d.tenant_id = ?` that follows it are the ONLY thing between one MSP       │
// │ customer's firewall and another's. It is emitted unconditionally, from a   │
// │ constant, with the tenant id as binding #1, and `assertTenantScoped()`     │
// │ refuses to hand back a statement that lost it.                             │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ TWO STRATEGIES, AND WHY THE FAST ONE IS THE DEFAULT ─────────────────────┐
// │ A conjunction of equalities inside one bracket is EXACTLY jsonb            │
// │ containment: `{"resources":{"firewallRules":[{"chain":"input",…}]}}`       │
// │ merges every constraint into one array element, which is the "same rule"   │
// │ semantics the bracket promises, and `config_snapshots_ncm_gin`             │
// │ (jsonb_path_ops) accelerates exactly that operator and no other.           │
// │                                                                           │
// │ `not`, `!=` on an open domain, `<`/`>` and `count()` cannot be expressed   │
// │ that way. They fall back to expanding the collection with                  │
// │ `jsonb_array_elements` — correct, bounded by the document, and NOT index-  │
// │ accelerated. `ginEligible` is reported to the caller so a slow query is    │
// │ legible as a slow QUERY and not as a slow database.                        │
// └───────────────────────────────────────────────────────────────────────────┘

import { RESOURCE_KIND_TO_COLLECTION, type NcmResourceKind } from '@obliwan/shared';
import {
  QUERY_LIMITS, lookupField,
  type DeviceFieldName, type QueryExpr, type QueryFieldNode,
  type QueryFieldSpec, type QueryLiteral, type QueryScope, type ResourceExpr,
  type SnapshotFieldName,
} from '@obliwan/shared/dist/query';
import { QueryParseError } from './dsl';

export interface CompiledQuery {
  /** `?`-placeholder SQL, for `knex.raw`. */
  sql: string;
  bindings: unknown[];
  /** True when no resource predicate needed element expansion. */
  ginEligible: boolean;
}

// ============================================================================
// Column maps — the only place a scope name becomes a column
// ============================================================================
//
// `Record<DeviceFieldName, …>` is exhaustive by construction: adding a name to
// the catalog in `shared/src/query.ts` without giving it an expression here is
// a TYPE ERROR, not a runtime "unknown field" six weeks later.

const DEVICE_SQL: Readonly<Record<DeviceFieldName, string>> = {
  name: 'd.name',
  brand: 'd.brand',
  family: 'd.family',
  model: 'd.model',
  serial: 'd.serial',
  os_version: 'd.os_version',
  role: 'd.role',
  status: 'd.status',
  is_managed: 'd.is_managed',
  site: 'st.name',
  site_code: 'st.code',
  group: 'g.name',
  ppp_username: 'd.ppp_username',
  system_identity: 'd.system_identity',
  last_seen_days: 'COALESCE(EXTRACT(EPOCH FROM (now() - d.last_seen_at)) / 86400.0, 1e9)',
};

const SNAPSHOT_SQL: Readonly<Record<SnapshotFieldName, string>> = {
  // A device that was never collected has NO row here, and `now() - NULL` is
  // NULL, which would quietly drop it out of `age_days > 30` — i.e. out of the
  // exact report it belongs at the top of. 1e9 days is "infinitely stale".
  age_days: 'COALESCE(EXTRACT(EPOCH FROM (now() - s.last_seen_at)) / 86400.0, 1e9)',
  captured_age_days: 'COALESCE(EXTRACT(EPOCH FROM (now() - s.captured_at)) / 86400.0, 1e9)',
  missing: '(s.id IS NULL)',
  source: 's.source',
  os_version: 's.os_version',
  model: 's.model',
  order_analysis: 's.order_analysis',
  ncm_version: 's.ncm_version',
  unmodeled_forwarding: 's.unmodeled_forwarding_count',
  seen_count: 's.seen_count',
};

// ============================================================================
// The binder
// ============================================================================

class Binder {
  readonly values: unknown[] = [];

  /** Appends a value and returns its placeholder. The ONLY way a value enters
   *  the statement. */
  bind(value: unknown): string {
    this.values.push(value);
    return '?';
  }
}

/** `%`, `_` and `\` are LIKE metacharacters. They are escaped inside the BOUND
 *  VALUE — the pattern is never assembled in the SQL text — and the escape
 *  character is declared with `ESCAPE ?` for the same reason. No regex is
 *  involved at any point: `~` would put an attacker-authored automaton on the
 *  API's event loop. */
function likeEscape(raw: string): string {
  return raw.replace(/[\\%_]/g, (c) => `\\${c}`);
}

// ============================================================================
// Containment fragments — the fast path
// ============================================================================

type Fragment = Record<string, unknown>;

/** Builds the element-level fragment for one leaf: `match.srcAddress has "any"`
 *  -> `{"match":{"srcAddress":["any"]}}`. An `array: true` segment wraps the
 *  remainder in a one-element array, which is precisely what `@>` reads as
 *  "there exists an element containing this". */
function fragmentFor(field: QueryFieldSpec, value: QueryLiteral): Fragment {
  let node: unknown = value;
  for (let i = field.segments.length - 1; i >= 0; i -= 1) {
    const seg = field.segments[i];
    if (i === field.segments.length - 1 && seg.array) {
      node = [value];
    } else if (seg.array) {
      node = [node];
    }
    node = { [seg.key]: node };
  }
  return node as Fragment;
}

/** Deep merge of two fragments. Returns null when they CONTRADICT — `chain =
 *  "input" and chain = "forward"` describes no rule at all, and silently
 *  keeping one of the two would answer a different question than the one asked. */
function mergeFragments(a: unknown, b: unknown): unknown | null {
  if (Array.isArray(a) && Array.isArray(b)) {
    // Two set constraints on the same path: `@>` on an array means "contains
    // all of these", so the union is the conjunction. Two constraints on an
    // array of OBJECTS, however, must land in the SAME element to keep the
    // bracket's promise, so they are merged element-wise when both are 1-long.
    if (a.length === 1 && b.length === 1
        && typeof a[0] === 'object' && a[0] !== null && !Array.isArray(a[0])
        && typeof b[0] === 'object' && b[0] !== null && !Array.isArray(b[0])) {
      const merged = mergeFragments(a[0], b[0]);
      return merged === null ? null : [merged];
    }
    const out = [...a];
    for (const v of b) if (!out.some((x) => JSON.stringify(x) === JSON.stringify(v))) out.push(v);
    return out;
  }
  if (Array.isArray(a) || Array.isArray(b)) return null;
  if (typeof a === 'object' && a !== null && typeof b === 'object' && b !== null) {
    const out: Record<string, unknown> = { ...(a as Record<string, unknown>) };
    for (const [k, v] of Object.entries(b as Record<string, unknown>)) {
      if (!(k in out)) { out[k] = v; continue; }
      const m = mergeFragments(out[k], v);
      if (m === null) return null;
      out[k] = m;
    }
    return out;
  }
  return a === b ? a : null;
}

/**
 * Tries to express a whole resource expression as a set of containment
 * fragments OR-ed together.
 *
 * Returns `null` when it cannot (a `not`, a range, a text match) — the caller
 * then expands the collection. Returns `[]` when the expression is
 * CONTRADICTORY, which is a different answer: `[]` means "matches nothing" and
 * compiles to `false`, and conflating it with `null` would send an
 * unsatisfiable query down the slow path to discover the same thing.
 */
function tryFragments(expr: ResourceExpr, kind: NcmResourceKind): Fragment[] | null {
  switch (expr.t) {
    case 'and': {
      let acc: Fragment[] = [{}];
      for (const child of expr.nodes) {
        const next = tryFragments(child, kind);
        if (next === null) return null;
        const combined: Fragment[] = [];
        for (const a of acc) {
          for (const b of next) {
            const m = mergeFragments(a, b);
            if (m !== null) combined.push(m as Fragment);
            if (combined.length > QUERY_LIMITS.maxContainmentFragments) return null;
          }
        }
        acc = combined;
        if (acc.length === 0) return [];
      }
      return acc;
    }
    case 'or': {
      const out: Fragment[] = [];
      for (const child of expr.nodes) {
        const next = tryFragments(child, kind);
        if (next === null) return null;
        out.push(...next);
        if (out.length > QUERY_LIMITS.maxContainmentFragments) return null;
      }
      return out;
    }
    case 'not':
      return null;
    default: {
      const field = lookupField(kind, expr.field);
      if (!field) return null;
      if (expr.op === 'eq' || expr.op === 'has') return [fragmentFor(field, expr.values[0])];
      if (expr.op === 'in') return expr.values.map((v) => fragmentFor(field, v));
      // ┌─ `!=` IS NOT REWRITTEN AS THE COMPLEMENT, AND THAT IS MEASURED ─────┐
      // │ Over a closed domain, `service != "snmp"` IS expressible as an OR   │
      // │ of the fifteen other equalities, so it CAN stay on the containment  │
      // │ path. It was, briefly. Timed on 300 devices / 10 045 snapshots:     │
      // │                                                                    │
      // │   complement, 15 fragments, GIN   490 ms                            │
      // │   element expansion               67 ms                             │
      // │                                                                    │
      // │ Which is not a surprise once stated: a `!=` is by nature            │
      // │ UNSELECTIVE — it matches nearly everything — so the index returns   │
      // │ nearly the whole history, fifteen times over, and detoasts it. The  │
      // │ expansion reads one document per device and is O(fleet) whatever    │
      // │ the retention. The complement was a clever rewrite that made the    │
      // │ query seven times slower, so it is gone.                            │
      // └────────────────────────────────────────────────────────────────────┘
      return null;
    }
  }
}

// ============================================================================
// Element expansion — the general path
// ============================================================================

/** The `text[]` path from the snapshot document root to a collection. */
function collectionPath(kind: NcmResourceKind): string[] {
  return ['resources', RESOURCE_KIND_TO_COLLECTION[kind]];
}

/** Path of a field RELATIVE to one element. Only meaningful when no segment is
 *  an array — set fields never take this route. */
function elementPath(field: QueryFieldSpec): string[] {
  return field.segments.map((s) => s.key);
}

function compileElementLeaf(node: QueryFieldNode, kind: NcmResourceKind, b: Binder): string {
  const field = lookupField(kind, node.field);
  if (!field) throw new QueryParseError(`'${node.field}' is not a field of '${kind}'.`);

  switch (node.op) {
    case 'eq':
    case 'has':
      return `(el @> ${b.bind(JSON.stringify(fragmentFor(field, node.values[0])))}::jsonb)`;
    case 'in': {
      const parts = node.values.map(
        (v) => `el @> ${b.bind(JSON.stringify(fragmentFor(field, v)))}::jsonb`,
      );
      return `(${parts.join(' OR ')})`;
    }
    case 'neq':
      // Inside ONE element, so this is "this record's field is not v" and not
      // "some other record differs" — which is the whole reason `not` lives on
      // the slow path instead of being distributed over containment.
      return `(NOT (el @> ${b.bind(JSON.stringify(fragmentFor(field, node.values[0])))}::jsonb))`;
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      const op = { gt: '>', gte: '>=', lt: '<', lte: '<=' }[node.op];
      const p = b.bind(elementPath(field));
      return `(jsonb_typeof(el #> ${p}::text[]) = ${b.bind('number')} `
        + `AND (el #>> ${b.bind(elementPath(field))}::text[])::numeric `
        + `${op} ${b.bind(node.values[0])})`;
    }
    case 'contains':
    case 'startsWith':
    case 'endsWith': {
      const raw = likeEscape(String(node.values[0]));
      const pattern = node.op === 'contains' ? `%${raw}%`
        : node.op === 'startsWith' ? `${raw}%` : `%${raw}`;
      return `((el #>> ${b.bind(elementPath(field))}::text[]) ILIKE ${b.bind(pattern)} `
        + `ESCAPE ${b.bind('\\')})`;
    }
    case 'isNull':
    case 'isNotNull': {
      const expr = nullTestSql(field, b);
      return node.op === 'isNull' ? expr : `(NOT ${expr})`;
    }
    default:
      throw new QueryParseError(`Operator '${node.op}' is not supported here.`);
  }
}

/**
 * "This field carries no value."
 *
 * For a SET field that means the list is absent or empty — "this interface has
 * no address" is a real question and `#>` through an array index would answer a
 * different one. For a scalar it means absent, or JSON `null`.
 */
function nullTestSql(field: QueryFieldSpec, b: Binder): string {
  const firstArray = field.segments.findIndex((s) => s.array);
  if (firstArray !== -1) {
    const upTo = field.segments.slice(0, firstArray + 1).map((s) => s.key);
    return `((el #> ${b.bind(upTo)}::text[]) IS NULL `
      + `OR jsonb_array_length(COALESCE(el #> ${b.bind(upTo)}::text[], `
      + `${b.bind('[]')}::jsonb)) = 0)`;
  }
  const p = elementPath(field);
  return `((el #> ${b.bind(p)}::text[]) IS NULL `
    + `OR jsonb_typeof(el #> ${b.bind(p)}::text[]) = ${b.bind('null')})`;
}

function compileElementExpr(expr: ResourceExpr, kind: NcmResourceKind, b: Binder): string {
  switch (expr.t) {
    case 'and':
      return `(${expr.nodes.map((n) => compileElementExpr(n, kind, b)).join(' AND ')})`;
    case 'or':
      return `(${expr.nodes.map((n) => compileElementExpr(n, kind, b)).join(' OR ')})`;
    case 'not':
      return `(NOT ${compileElementExpr(expr.node, kind, b)})`;
    default:
      return compileElementLeaf(expr, kind, b);
  }
}

/** `jsonb_array_elements` raises on a non-array. A snapshot written by a
 *  future parser, or rolled back from one, is not a reason to 500 a query. */
function collectionSql(kind: NcmResourceKind, b: Binder): string {
  // Bound in the order the placeholders appear in the string below — see
  // `assertBindingCount`. The path is bound TWICE because it appears twice.
  const p = b.bind(collectionPath(kind));
  const arrayTag = b.bind('array');
  const p2 = b.bind(collectionPath(kind));
  const empty = b.bind('[]');
  return `jsonb_array_elements(CASE WHEN jsonb_typeof(s.ncm #> ${p}::text[]) = ${arrayTag} `
    + `THEN s.ncm #> ${p2}::text[] ELSE ${empty}::jsonb END)`;
}

// ============================================================================
// Top level
// ============================================================================

interface Ctx {
  b: Binder;
  /** Flipped as soon as one predicate had to leave the containment path. */
  ginEligible: boolean;
}

function compileScalarLeaf(node: QueryFieldNode, ctx: Ctx): string {
  const { b } = ctx;
  const field = lookupField(node.scope, node.field);
  if (!field) throw new QueryParseError(`'${node.field}' is not a field of '${node.scope}'.`);

  const col = node.scope === 'device'
    ? DEVICE_SQL[node.field as DeviceFieldName]
    : SNAPSHOT_SQL[node.field as SnapshotFieldName];
  if (!col) throw new QueryParseError(`'${node.scope}.${node.field}' has no column mapping.`);

  switch (node.op) {
    case 'eq':
      return `(${col} = ${b.bind(node.values[0])})`;
    case 'neq':
      // IS DISTINCT FROM, not `<>`: `device.model != "RB5009"` must return the
      // devices whose model we do not know. `<>` returns NULL for them and they
      // vanish from an inventory gap report — which is the report they matter
      // most in.
      return `(${col} IS DISTINCT FROM ${b.bind(node.values[0])})`;
    case 'in':
      return `(${col} IN (${node.values.map((v) => b.bind(v)).join(', ')}))`;
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      const op = { gt: '>', gte: '>=', lt: '<', lte: '<=' }[node.op];
      return `(${col} ${op} ${b.bind(node.values[0])})`;
    }
    case 'contains':
    case 'startsWith':
    case 'endsWith': {
      const raw = likeEscape(String(node.values[0]));
      const pattern = node.op === 'contains' ? `%${raw}%`
        : node.op === 'startsWith' ? `${raw}%` : `%${raw}`;
      return `(${col} ILIKE ${b.bind(pattern)} ESCAPE ${b.bind('\\')})`;
    }
    case 'isNull':
      return `(${col} IS NULL)`;
    case 'isNotNull':
      return `(${col} IS NOT NULL)`;
    default:
      throw new QueryParseError(`Operator '${node.op}' is not supported on ${node.scope}.`);
  }
}

function compileResource(kind: NcmResourceKind, expr: ResourceExpr | null, ctx: Ctx): string {
  const { b } = ctx;
  if (expr !== null) {
    const frags = tryFragments(expr, kind);
    if (frags !== null) {
      if (frags.length === 0) return 'FALSE';
      const parts = frags.map((f) => {
        const doc = { resources: { [RESOURCE_KIND_TO_COLLECTION[kind]]: [f] } };
        // ┌─ WHY THIS IS NOT WRAPPED IN COALESCE(…, FALSE) ──────────────────┐
        // │ It was, for one commit, so that a device with no snapshot        │
        // │ (`s.ncm IS NULL`, hence `NULL @> x` = NULL) read as a definite    │
        // │ FALSE. It cost the index. `COALESCE` is NOT STRICT, so the        │
        // │ planner could no longer prove the LEFT JOIN behaves as an inner   │
        // │ one, could not reduce it, and therefore could not push the        │
        // │ containment down to `config_snapshots_ncm_gin`. The plan degraded │
        // │ to a Filter applied AFTER joining every snapshot of the fleet.    │
        // │                                                                  │
        // │ It is also unnecessary: `WHERE` already treats NULL as not-true.  │
        // │ Three-valued and two-valued logic differ only under negation, and │
        // │ `compileExpr`'s `not` branch is where the COALESCE actually       │
        // │ lives — the one place the distinction is observable, and the one  │
        // │ place no index could have helped anyway.                          │
        // └──────────────────────────────────────────────────────────────────┘
        return `s.ncm @> ${b.bind(JSON.stringify(doc))}::jsonb`;
      });
      return `(${parts.join(' OR ')})`;
    }
  }
  ctx.ginEligible = false;
  // ORDER MATTERS, AND IT IS NOT COSMETIC. `?` bindings are positional: the
  // array must be built in the order the placeholders APPEAR IN THE TEXT. The
  // collection's own placeholders come first in the string, so they must be
  // bound first — building `where` before `collectionSql` shifts every
  // parameter by four and hands Postgres a JSON object where it wants a
  // `text[]`. It fails loudly here; in a query that happened to type-check on
  // both sides it would fail silently, with wrong answers.
  const from = collectionSql(kind, b);
  const where = expr === null ? 'TRUE' : compileElementExpr(expr, kind, b);
  return `EXISTS (SELECT 1 FROM ${from} AS el WHERE ${where})`;
}

function compileCount(
  kind: NcmResourceKind,
  expr: ResourceExpr | null,
  op: string,
  value: number,
  ctx: Ctx,
): string {
  ctx.ginEligible = false;
  const { b } = ctx;
  // Bind in TEXTUAL order — see the note in `compileResource`.
  const from = collectionSql(kind, b);
  const where = expr === null ? 'TRUE' : compileElementExpr(expr, kind, b);
  const sqlOp = { eq: '=', neq: '<>', gt: '>', gte: '>=', lt: '<', lte: '<=' }[op] ?? '=';
  return `((SELECT count(*) FROM ${from} AS el WHERE ${where}) `
    + `${sqlOp} ${b.bind(value)})`;
}

function compileExpr(node: QueryExpr, ctx: Ctx): string {
  switch (node.t) {
    case 'and':
      return `(${node.nodes.map((n) => compileExpr(n, ctx)).join(' AND ')})`;
    case 'or':
      return `(${node.nodes.map((n) => compileExpr(n, ctx)).join(' OR ')})`;
    case 'not':
      return `(NOT COALESCE(${compileExpr(node.node, ctx)}, FALSE))`;
    case 'resource':
      return compileResource(node.kind, node.expr, ctx);
    case 'count':
      return compileCount(node.kind, node.expr, node.op, node.value, ctx);
    default:
      return compileScalarLeaf(node, ctx);
  }
}

// ============================================================================
// The statement
// ============================================================================

/**
 * The current snapshot of each device.
 *
 * NOT a `LATERAL … LIMIT 1`: that form forces one index descent per device and
 * hides the containment behind an ordered subquery, where the planner can no
 * longer push it down to `config_snapshots_ncm_gin`. As a plain LEFT JOIN with
 * an anti-join predicate, a strict qual in the outer WHERE lets the planner
 * reduce the outer join to an inner one and drive the whole query from the GIN
 * bitmap scan — which is the difference between reading 300 documents and
 * reading the four that match.
 *
 * `last_seen_at`, not `captured_at`: `UNIQUE(device_id, ncm_hash)` means a
 * router that goes A -> B -> A resurrects the OLD row and bumps its
 * `last_seen_at`. Ordering on `captured_at` would report B as current forever.
 *
 * ┌─ MEASURED, SO THE TRADE-OFF IS ON THE RECORD ─────────────────────────────┐
 * │ This shape leaves the planner BOTH plans, and it picks by cost:            │
 * │                                                                           │
 * │  · 300 devices / 895 snapshots — Seq Scan on `config_snapshots` (28        │
 * │    pages; the GIN is 3.6 MB against a 224 kB heap, so the index genuinely  │
 * │    loses). 20–40 ms for the four flagship queries.                         │
 * │  · 300 devices / 10 045 snapshots — Bitmap Index Scan on                   │
 * │    `config_snapshots_ncm_gin`, then the anti-join on                       │
 * │    `config_snapshots_device_current_idx`. 90–221 ms.                       │
 * │                                                                           │
 * │ The GIN path is SLOWER on that second measurement than the anti-join-first │
 * │ plan would be, and the reason is worth writing down: containment           │
 * │ selectivity on jsonb is estimated at a flat 0.1 %, and the bitmap scan     │
 * │ actually returned 25 % of the table — every HISTORICAL snapshot that ever  │
 * │ carried the pattern, all detoasted, before the anti-join throws all but    │
 * │ the current one away. The fixture is adversarial on purpose (thirty        │
 * │ near-identical documents per device); real history is deduplicated by      │
 * │ `UNIQUE(device_id, ncm_hash)` and does not repeat like that.               │
 * │                                                                           │
 * │ Not "fixed" by pinning the plan (a `LATERAL … LIMIT 1` would force 300     │
 * │ detoasts always and make the GIN unreachable) because the cost model is    │
 * │ right in the shape and wrong only in one estimate — and a query that is    │
 * │ index-driven when the predicate is rare is the behaviour K5 wants at the   │
 * │ scale where it matters. `statement_timeout` bounds the bad case.           │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const CURRENT_SNAPSHOT_JOIN = `
LEFT JOIN config_snapshots s
       ON s.device_id = d.id
      AND NOT EXISTS (
            SELECT 1 FROM config_snapshots s2
             WHERE s2.device_id = s.device_id
               AND (s2.last_seen_at, s2.id) > (s.last_seen_at, s.id))`;

const SELECT_COLUMNS = `
  d.id            AS device_id,
  d.uuid          AS device_uuid,
  d.name          AS name,
  d.brand         AS brand,
  d.family        AS family,
  d.model         AS model,
  d.role          AS role,
  d.status        AS status,
  st.name         AS site,
  s.id            AS snapshot_id,
  s.uuid          AS snapshot_uuid,
  s.captured_at   AS captured_at,
  s.last_seen_at  AS last_seen_at,
  s.ncm_hash      AS ncm_hash`;

const FROM_CLAUSE = `
FROM devices d
LEFT JOIN sites st ON st.id = d.site_id
LEFT JOIN device_groups g ON g.id = d.group_id${CURRENT_SNAPSHOT_JOIN}`;

/** Emitted from a constant, always, with the tenant as binding #1. */
const TENANT_PREDICATE = 'd.tenant_id = ?';

/**
 * THE guard of the header. Called on every compile.
 *
 * A single quote in the output means some value was concatenated instead of
 * bound — the compiler's own constants (`[]`, `array`, `number`, `null`, the
 * LIKE escape) all go through the binder precisely so that this test has no
 * exceptions to carve out and cannot be weakened by one.
 */
function assertNoLiterals(sql: string): void {
  if (sql.includes("'")) {
    throw new Error('Fleet Query compiler: generated SQL contains a literal quote');
  }
  if (sql.includes(';')) {
    throw new Error('Fleet Query compiler: generated SQL contains a statement separator');
  }
  if (sql.includes('--') || sql.includes('/*')) {
    throw new Error('Fleet Query compiler: generated SQL contains a comment introducer');
  }
}

function assertTenantScoped(sql: string): void {
  if (!sql.includes(TENANT_PREDICATE)) {
    throw new Error('Fleet Query compiler: generated SQL lost its tenant predicate');
  }
}

/**
 * `?` bindings are POSITIONAL: the array must be built in the order the
 * placeholders appear in the text, which means every helper has to call
 * `bind()` in the order it concatenates. Getting that wrong once already
 * produced a statement that handed Postgres a JSON object where it wanted a
 * `text[]`. This counts them; it cannot prove the ORDER, so the helpers that
 * assemble more than one placeholder carry a comment saying why the sequence
 * of their statements is load-bearing.
 */
function assertBindingCount(sql: string, bindings: readonly unknown[]): void {
  const placeholders = (sql.match(/\?/g) ?? []).length;
  if (placeholders !== bindings.length) {
    throw new Error(
      `Fleet Query compiler: ${placeholders} placeholders for ${bindings.length} bindings`,
    );
  }
}

function seal(sql: string, bindings: unknown[], ginEligible: boolean): CompiledQuery {
  assertNoLiterals(sql);
  assertTenantScoped(sql);
  assertBindingCount(sql, bindings);
  return { sql, bindings, ginEligible };
}

export interface CompileOptions {
  tenantId: number;
  limit?: number;
  offset?: number;
  /** Restrict to one device — used by the per-snapshot policy evaluation. */
  deviceId?: number;
}

/**
 * AST -> statement. Pure: no database handle, no clock, no session. The same
 * AST compiles to the same SQL, which is what makes `compiled_sql_hash` a
 * meaningful thing to store on a saved query.
 */
export function compile(ast: QueryExpr, opts: CompileOptions): CompiledQuery {
  const ctx: Ctx = { b: new Binder(), ginEligible: true };

  // Binding #1, before anything a user wrote can claim the slot.
  const tenantBinding = ctx.b.bind(opts.tenantId);
  const scoping = [`d.tenant_id = ${tenantBinding}`];
  if (opts.deviceId !== undefined) scoping.push(`d.id = ${ctx.b.bind(opts.deviceId)}`);

  const predicate = compileExpr(ast, ctx);

  const limit = Math.min(Math.max(1, opts.limit ?? 200), QUERY_LIMITS.maxExportRows);
  const offset = Math.max(0, opts.offset ?? 0);

  const sql = `SELECT${SELECT_COLUMNS},
  count(*) OVER () AS total_count${FROM_CLAUSE}
WHERE ${scoping.join(' AND ')}
  AND (${predicate})
ORDER BY d.name ASC, d.id ASC
LIMIT ${ctx.b.bind(limit)} OFFSET ${ctx.b.bind(offset)}`;

  return seal(sql, ctx.b.values, ctx.ginEligible);
}

/**
 * The matching DEVICE IDS only, for policy evaluation: the evaluator needs the
 * violating set and the evaluated set, not fifteen columns of each.
 */
export function compileIdsOnly(ast: QueryExpr, opts: CompileOptions): CompiledQuery {
  const ctx: Ctx = { b: new Binder(), ginEligible: true };
  const scoping = [`d.tenant_id = ${ctx.b.bind(opts.tenantId)}`];
  if (opts.deviceId !== undefined) scoping.push(`d.id = ${ctx.b.bind(opts.deviceId)}`);
  const predicate = compileExpr(ast, ctx);

  const sql = `SELECT d.id AS device_id, s.id AS snapshot_id${FROM_CLAUSE}
WHERE ${scoping.join(' AND ')}
  AND (${predicate})`;

  return seal(sql, ctx.b.values, ctx.ginEligible);
}

/** Every device of the tenant with its current snapshot — the DENOMINATOR of a
 *  policy evaluation. Without it a policy that matches nothing is
 *  indistinguishable from a policy that was never evaluated. */
export function compilePopulation(opts: CompileOptions): CompiledQuery {
  const b = new Binder();
  const scoping = [`d.tenant_id = ${b.bind(opts.tenantId)}`];
  if (opts.deviceId !== undefined) scoping.push(`d.id = ${b.bind(opts.deviceId)}`);
  const sql = `SELECT d.id AS device_id, s.id AS snapshot_id${FROM_CLAUSE}
WHERE ${scoping.join(' AND ')}`;
  return seal(sql, b.values, true);
}

/** Exported for the scope badges the UI shows and for the executor's decision
 *  to skip the snapshot join entirely on a pure `device.*` query. */
export function touchesSnapshot(scopes: readonly QueryScope[]): boolean {
  return scopes.some((s) => s !== 'device');
}
