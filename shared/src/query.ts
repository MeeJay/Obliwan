// ============================================================================
// @obliwan/shared — Fleet Query (K5), the contract
// ============================================================================
//
// Implements M9 of ARCHITECTURE.md §5 and the `saved_queries` / `policy_results`
// half of §3.7. The parser lives on the server (`services/query/dsl.ts`,
// Chevrotain, §6.1); the compiler lives next to it. THIS file owns three things
// and nothing else:
//
//   1. the AST shape, so the client can lint and render a query it did not
//      compile itself;
//   2. THE PATH WHITELIST, **derived from the zod schemas of `./ncm`** at module
//      load — never typed out by hand;
//   3. the hard limits (§ "ReDoS"), so client and server refuse the same inputs.
//
// ┌─ WHY THE WHITELIST IS GENERATED AND NOT WRITTEN ──────────────────────────┐
// │ A hand-maintained list of queryable paths diverges from the model at the  │
// │ first resource added — and it diverges SILENTLY, in the direction that    │
// │ hurts: the new field is simply not queryable, nobody gets an error, and   │
// │ the answer to "who has X" is quietly "nobody". Walking                    │
// │ `NcmFirewallRule` & co. means a field exists in the DSL the same commit   │
// │ it exists in the NCM, and a field REMOVED from the NCM makes every stored │
// │ query that used it fail loudly at validation instead of matching zero     │
// │ devices forever.                                                          │
// │                                                                          │
// │ It is a CORRECTNESS guard. It is NOT the SQL-injection guard — that one  │
// │ is "no fragment of user input ever reaches the statement except as a      │
// │ bound parameter", and it is enforced in the compiler, independently.      │
// └───────────────────────────────────────────────────────────────────────────┘

import { z } from 'zod';
import {
  DEVICE_BRANDS, DEVICE_FAMILIES, DEVICE_ROLES, DEVICE_STATUSES,
} from './device';
import { DIFF_SEVERITIES } from './ncm/diff';
import {
  NCM_RESOURCE_KINDS, RESOURCE_KIND_TO_COLLECTION,
  NcmInterface, NcmVlan, NcmRoute, NcmFirewallRule, NcmNatRule,
  NcmDhcpScope, NcmIpsecPeer, NcmLocalUser, NcmService, NcmQosRule,
} from './ncm/resources';
import type { NcmResourceKind } from './ncm/resources';
import { ORDER_ANALYSIS_STATES } from './ncm/model';

// ============================================================================
// Hard limits — risk "ReDoS on the API thread"
// ============================================================================
//
// The DSL takes text from an authenticated user and turns it into a parse tree
// on the SAME event loop that answers every other request of every other
// tenant. There is no user-supplied regex anywhere in this feature (that is a
// design decision, not an omission: `matches`/`~` do not exist in the grammar,
// and `contains` compiles to a LIKE with escaped metacharacters). What remains
// to bound is the SIZE of the input and the SIZE of what it can expand to.

export const QUERY_LIMITS = {
  /** Bytes of DSL text accepted. A real query is under 400. */
  maxQueryLength: 4096,
  /** Tokens the lexer may emit before the request is refused. */
  maxTokens: 512,
  /** AST nodes. Guards `((((…))))` and long OR chains alike. */
  maxAstNodes: 256,
  /** Nesting depth of parentheses / boolean structure. */
  maxDepth: 16,
  /** Wall clock allowed for lex+parse+validate, milliseconds. Chevrotain is
   *  linear on this grammar; this is the belt to the braces above. */
  maxParseMs: 250,
  /** Longest string literal. Wider than any `varchar` in the NCM. */
  maxLiteralLength: 512,
  /** Values inside one `in (…)` list. */
  maxInListValues: 64,
  /** Containment fragments one query may expand to before the compiler stops
   *  distributing ORs and falls back to element expansion. */
  maxContainmentFragments: 32,
  /** Rows an execution may return, and the ceiling of `?limit`. */
  maxRows: 5000,
  /** Rows an export may stream. */
  maxExportRows: 50000,
  /** `statement_timeout` set on the query connection, milliseconds. */
  statementTimeoutMs: 5000,
} as const;

// ============================================================================
// Operators
// ============================================================================

export const QUERY_OPERATORS = [
  'eq', 'neq', 'gt', 'gte', 'lt', 'lte',
  'has', 'in',
  'contains', 'startsWith', 'endsWith',
  'isNull', 'isNotNull',
] as const;
export type QueryOperator = (typeof QUERY_OPERATORS)[number];

/** Operators whose right-hand side is a single literal. */
export const UNARY_VALUE_OPERATORS: ReadonlySet<QueryOperator> = new Set<QueryOperator>([
  'eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'has', 'contains', 'startsWith', 'endsWith',
]);
/** Operators that take no value at all. */
export const NO_VALUE_OPERATORS: ReadonlySet<QueryOperator> = new Set<QueryOperator>([
  'isNull', 'isNotNull',
]);
/** Operators that ORDER values, and therefore need a number or a timestamp. */
export const ORDERING_OPERATORS: ReadonlySet<QueryOperator> = new Set<QueryOperator>([
  'gt', 'gte', 'lt', 'lte',
]);
/** Operators that match a SUBSTRING. They compile to `LIKE` with `%`, `_` and
 *  `\` escaped in the bound parameter — never to a regular expression, and
 *  never to a pattern assembled by string concatenation into the statement. */
export const TEXT_MATCH_OPERATORS: ReadonlySet<QueryOperator> = new Set<QueryOperator>([
  'contains', 'startsWith', 'endsWith',
]);

/** Surface spelling -> internal operator. Kept here so the client's editor and
 *  the server's parser cannot disagree about what `!=` means. */
export const OPERATOR_SPELLINGS: Readonly<Record<string, QueryOperator>> = {
  '=': 'eq', '==': 'eq', '!=': 'neq', '<>': 'neq',
  '>': 'gt', '>=': 'gte', '<': 'lt', '<=': 'lte',
  has: 'has', in: 'in',
  contains: 'contains', startswith: 'startsWith', endswith: 'endsWith',
};

// ============================================================================
// Field descriptors
// ============================================================================

export const QUERY_FIELD_TYPES = ['string', 'number', 'boolean', 'timestamp'] as const;
export type QueryFieldType = (typeof QUERY_FIELD_TYPES)[number];

/**
 * One step of a whitelisted path.
 *
 * `array: true` means the JSON value under `key` is an ARRAY. When it is the
 * last segment the field is a set of scalars (`match.srcAddress`); when it is
 * not, the remaining segments address a field of the array's ELEMENTS
 * (`addresses.cidr`, `reservations.mac`). Both cases are existential and both
 * compile to a containment fragment — which is the entire reason §2.1 of the
 * NCM contract made every selector a tagged STRING instead of a nested object.
 */
export interface QuerySegment {
  key: string;
  array: boolean;
}

export interface QueryFieldSpec {
  /** Dotted path, relative to the resource element (`match.srcAddress`) or to
   *  the scope (`device.brand` is stored as `brand` under scope `device`). */
  path: string;
  segments: readonly QuerySegment[];
  type: QueryFieldType;
  /** 'set' as soon as ANY segment is an array: membership, not equality. */
  cardinality: 'scalar' | 'set';
  nullable: boolean;
  /** Closed value domain (zod enum / literal / boolean), else null. A closed
   *  domain is what lets the compiler turn `!=` into an OR over the complement
   *  and keep the fast containment path; it is also what catches a typo'd
   *  `chain = "imput"` at validation instead of returning zero devices. */
  values: readonly string[] | null;
  /** `.max()` of the zod string, when there is one. */
  maxLength: number | null;
}

/** A scope is the thing a predicate is ABOUT: the device row, its current
 *  snapshot's metadata, or one element of one NCM resource collection. */
export const QUERY_SCOPES = ['device', 'snapshot', ...NCM_RESOURCE_KINDS] as const;
export type QueryScope = (typeof QUERY_SCOPES)[number];

// ============================================================================
// The generator — zod introspection
// ============================================================================

/**
 * Leaf names that are NEVER queryable, whatever the schema says.
 *
 * `fp` is the keyed HMAC of a PSK / password / SNMP community. It is not a
 * secret in the sense of §8.2 — it cannot be reversed — but it IS a stable
 * per-tenant identifier of a secret, and a DSL that can test it for equality is
 * an oracle: `ipsecPeer[pskFingerprint.fp = "…"]` turns "do these two sites
 * share a PSK" into a fleet-wide query, and the CSV export then carries the
 * fingerprints out of the platform. `unavailable` stays queryable, because
 * "we could not read the secret at all" is exactly what an audit needs.
 */
const DENIED_LEAF_KEYS: ReadonlySet<string> = new Set(['fp', 'algo']);

/** Element-relative depth. `match.srcAddress` is 2, `proposal.encryption` is 2,
 *  and nothing in the NCM legitimately needs 4. */
const MAX_PATH_DEPTH = 3;

type AnyZod = z.ZodTypeAny;

interface Unwrapped {
  schema: AnyZod;
  nullable: boolean;
}

/** Peels ZodNullable / ZodOptional / ZodDefault / ZodEffects, remembering
 *  whether the value may be absent. */
function unwrap(schema: AnyZod): Unwrapped {
  let cur: AnyZod = schema;
  let nullable = false;
  // Bounded: zod wrappers nest a handful deep at most, and an unbounded `while`
  // over user-unreachable data is still an unbounded `while`.
  for (let i = 0; i < 8; i += 1) {
    if (cur instanceof z.ZodNullable) { nullable = true; cur = cur.unwrap(); continue; }
    if (cur instanceof z.ZodOptional) { nullable = true; cur = cur.unwrap(); continue; }
    if (cur instanceof z.ZodDefault) { cur = cur._def.innerType as AnyZod; continue; }
    if (cur instanceof z.ZodEffects) { cur = cur.innerType() as AnyZod; continue; }
    if (cur instanceof z.ZodBranded) { cur = cur.unwrap() as AnyZod; continue; }
    break;
  }
  return { schema: cur, nullable };
}

/** The closed domain of a schema, or null when the domain is open. */
function domainOf(schema: AnyZod): readonly string[] | null {
  if (schema instanceof z.ZodEnum) return schema.options as readonly string[];
  if (schema instanceof z.ZodLiteral) {
    const v = schema.value;
    return typeof v === 'string' ? [v] : null;
  }
  if (schema instanceof z.ZodBoolean) return ['true', 'false'];
  if (schema instanceof z.ZodUnion) {
    // `z.union([z.literal('a'), z.literal('b')])` — accepted, anything else is
    // an open domain rather than a wrong one.
    const opts = schema.options as AnyZod[];
    const out: string[] = [];
    for (const o of opts) {
      const inner = unwrap(o).schema;
      if (!(inner instanceof z.ZodLiteral) || typeof inner.value !== 'string') return null;
      out.push(inner.value);
    }
    return out;
  }
  return null;
}

function scalarTypeOf(schema: AnyZod): QueryFieldType | null {
  if (schema instanceof z.ZodString) return 'string';
  if (schema instanceof z.ZodNumber) return 'number';
  if (schema instanceof z.ZodBoolean) return 'boolean';
  if (schema instanceof z.ZodEnum) return 'string';
  if (schema instanceof z.ZodLiteral) {
    const t = typeof schema.value;
    if (t === 'string') return 'string';
    if (t === 'number') return 'number';
    if (t === 'boolean') return 'boolean';
    return null;
  }
  if (schema instanceof z.ZodUnion) return domainOf(schema) ? 'string' : null;
  return null;
}

function maxLengthOf(schema: AnyZod): number | null {
  if (schema instanceof z.ZodString) return schema.maxLength;
  if (schema instanceof z.ZodEnum) {
    const opts = schema.options as readonly string[];
    return opts.reduce((m, o) => Math.max(m, o.length), 0);
  }
  if (schema instanceof z.ZodLiteral && typeof schema.value === 'string') {
    return schema.value.length;
  }
  return null;
}

/**
 * Walks a zod object and emits every queryable leaf.
 *
 * DELIBERATELY SILENT SKIPS, each of them a shape containment cannot address:
 *  - `PortSet` (array of `[number, number]` tuples): a port RANGE is not a
 *    value you can test with `@>`. Querying ports needs its own operator and
 *    its own index; shipping a half-working `dstPort = 22` that misses
 *    `[20, 25]` would be worse than not shipping it. It lands in
 *    `QUERY_UNSUPPORTED_FIELDS` so the UI can say why.
 *  - `extensions` (`z.record`): unversioned by construction (§ NcmDocument),
 *    and a query over it would be a second, undeclared model.
 */
function walkObject(
  schema: z.ZodObject<z.ZodRawShape>,
  prefix: readonly QuerySegment[],
  out: QueryFieldSpec[],
  skipped: string[],
): void {
  if (prefix.length >= MAX_PATH_DEPTH) return;
  const shape = schema.shape;
  for (const key of Object.keys(shape).sort()) {
    if (DENIED_LEAF_KEYS.has(key)) continue;
    const { schema: inner, nullable } = unwrap(shape[key] as AnyZod);
    const dotted = [...prefix.map((s) => s.key), key].join('.');

    // ── array ──────────────────────────────────────────────────────────────
    if (inner instanceof z.ZodArray) {
      const el = unwrap(inner.element as AnyZod);
      const elScalar = scalarTypeOf(el.schema);
      const seg: QuerySegment = { key, array: true };
      if (elScalar !== null) {
        out.push({
          path: dotted,
          segments: [...prefix, seg],
          type: elScalar,
          cardinality: 'set',
          nullable,
          values: domainOf(el.schema),
          maxLength: maxLengthOf(el.schema),
        });
        continue;
      }
      if (el.schema instanceof z.ZodObject) {
        walkObject(el.schema as z.ZodObject<z.ZodRawShape>, [...prefix, seg], out, skipped);
        continue;
      }
      skipped.push(dotted);
      continue;
    }

    // ── nested object ──────────────────────────────────────────────────────
    if (inner instanceof z.ZodObject) {
      walkObject(inner as z.ZodObject<z.ZodRawShape>, [...prefix, { key, array: false }], out, skipped);
      continue;
    }

    // ── scalar ─────────────────────────────────────────────────────────────
    const t = scalarTypeOf(inner);
    if (t === null) { skipped.push(dotted); continue; }
    out.push({
      path: dotted,
      segments: [...prefix, { key, array: false }],
      type: t,
      cardinality: prefix.some((s) => s.array) ? 'set' : 'scalar',
      nullable,
      values: domainOf(inner),
      maxLength: maxLengthOf(inner),
    });
  }
}

const RESOURCE_SCHEMAS: Readonly<Record<NcmResourceKind, z.ZodObject<z.ZodRawShape>>> = {
  interface: NcmInterface as unknown as z.ZodObject<z.ZodRawShape>,
  vlan: NcmVlan as unknown as z.ZodObject<z.ZodRawShape>,
  route: NcmRoute as unknown as z.ZodObject<z.ZodRawShape>,
  firewallRule: NcmFirewallRule as unknown as z.ZodObject<z.ZodRawShape>,
  natRule: NcmNatRule as unknown as z.ZodObject<z.ZodRawShape>,
  dhcpScope: NcmDhcpScope as unknown as z.ZodObject<z.ZodRawShape>,
  ipsecPeer: NcmIpsecPeer as unknown as z.ZodObject<z.ZodRawShape>,
  localUser: NcmLocalUser as unknown as z.ZodObject<z.ZodRawShape>,
  service: NcmService as unknown as z.ZodObject<z.ZodRawShape>,
  qosRule: NcmQosRule as unknown as z.ZodObject<z.ZodRawShape>,
};

const unsupported: Record<string, string[]> = {};

function buildResourceFields(kind: NcmResourceKind): ReadonlyMap<string, QueryFieldSpec> {
  const out: QueryFieldSpec[] = [];
  const skipped: string[] = [];
  walkObject(RESOURCE_SCHEMAS[kind], [], out, skipped);
  unsupported[kind] = skipped;
  return new Map(out.map((f) => [f.path, f]));
}

// ============================================================================
// device / snapshot scopes — declared, not derived
// ============================================================================
//
// These two are NOT walked out of a zod schema, and that asymmetry is
// deliberate: they are not the NCM. They are columns of `devices` and
// `config_snapshots`, and their SQL expressions live in the server's compiler
// as a `Record` keyed by THIS list, so adding a name here without giving it an
// expression is a compile error rather than a runtime one.

function scalar<P extends string>(
  path: P,
  type: QueryFieldType,
  opts: { nullable?: boolean; values?: readonly string[]; maxLength?: number } = {},
): QueryFieldSpec & { path: P } {
  return {
    path,
    segments: [{ key: path, array: false }],
    type,
    cardinality: 'scalar',
    nullable: opts.nullable ?? false,
    values: opts.values ?? null,
    maxLength: opts.maxLength ?? null,
  };
}

const DEVICE_FIELD_LIST = [
  scalar('name', 'string', { maxLength: 255 }),
  scalar('brand', 'string', { values: DEVICE_BRANDS }),
  scalar('family', 'string', { values: DEVICE_FAMILIES }),
  scalar('model', 'string', { nullable: true, maxLength: 128 }),
  scalar('serial', 'string', { nullable: true, maxLength: 128 }),
  scalar('os_version', 'string', { nullable: true, maxLength: 64 }),
  scalar('role', 'string', { values: DEVICE_ROLES }),
  scalar('status', 'string', { values: DEVICE_STATUSES }),
  scalar('is_managed', 'boolean'),
  scalar('site', 'string', { nullable: true, maxLength: 255 }),
  scalar('site_code', 'string', { nullable: true, maxLength: 64 }),
  scalar('group', 'string', { nullable: true, maxLength: 255 }),
  scalar('ppp_username', 'string', { nullable: true, maxLength: 128 }),
  scalar('system_identity', 'string', { nullable: true, maxLength: 128 }),
  scalar('last_seen_days', 'number'),
] as const;

const SNAPSHOT_SOURCES = [
  'routeros_api', 'ssh', 'rest', 'cwmp', 'pre_change', 'import',
] as const;

const SNAPSHOT_FIELD_LIST = [
  /**
   * Age of the CURRENT snapshot, in days.
   *
   * A device that has never been collected at all has NO snapshot row, and the
   * honest answer to "who has not been backed up for 30 days" must include it —
   * a NULL that silently drops out of `> 30` would return the reassuring half
   * of the fleet. The compiler therefore coalesces a missing snapshot to
   * 1e9 days, i.e. "infinitely stale", and `snapshot.missing` exists so the two
   * populations stay distinguishable when you want them to be.
   */
  scalar('age_days', 'number'),
  scalar('captured_age_days', 'number'),
  scalar('missing', 'boolean'),
  scalar('source', 'string', { values: SNAPSHOT_SOURCES }),
  scalar('os_version', 'string', { nullable: true, maxLength: 32 }),
  scalar('model', 'string', { nullable: true, maxLength: 64 }),
  scalar('order_analysis', 'string', { values: ORDER_ANALYSIS_STATES }),
  scalar('ncm_version', 'number'),
  scalar('unmodeled_forwarding', 'number'),
  scalar('seen_count', 'number'),
] as const;

export type DeviceFieldName = (typeof DEVICE_FIELD_LIST)[number]['path'];
export type SnapshotFieldName = (typeof SNAPSHOT_FIELD_LIST)[number]['path'];

// ============================================================================
// THE CATALOG
// ============================================================================

export interface QueryScopeSpec {
  scope: QueryScope;
  /** `resources.<collection>` for a resource scope, null for device/snapshot. */
  collection: string | null;
  fields: ReadonlyMap<string, QueryFieldSpec>;
}

function scopeSpec(
  scope: QueryScope,
  collection: string | null,
  fields: readonly QueryFieldSpec[] | ReadonlyMap<string, QueryFieldSpec>,
): QueryScopeSpec {
  return {
    scope,
    collection,
    fields: fields instanceof Map
      ? fields
      : new Map((fields as readonly QueryFieldSpec[]).map((f) => [f.path, f])),
  };
}

const catalog = new Map<QueryScope, QueryScopeSpec>();
catalog.set('device', scopeSpec('device', null, DEVICE_FIELD_LIST));
catalog.set('snapshot', scopeSpec('snapshot', null, SNAPSHOT_FIELD_LIST));
for (const kind of NCM_RESOURCE_KINDS) {
  catalog.set(
    kind,
    scopeSpec(kind, `resources.${RESOURCE_KIND_TO_COLLECTION[kind]}`, buildResourceFields(kind)),
  );
}

/** The whitelist. Frozen, built once, at module load, out of the zod schemas. */
export const QUERY_CATALOG: ReadonlyMap<QueryScope, QueryScopeSpec> = catalog;

/** Fields present in the NCM that the DSL deliberately cannot address, by
 *  scope. Surfaced so the UI can explain a gap instead of pretending. */
export const QUERY_UNSUPPORTED_FIELDS: Readonly<Record<string, readonly string[]>> = unsupported;

export function isQueryScope(value: string): value is QueryScope {
  return catalog.has(value as QueryScope);
}

/** The single lookup every caller must go through. Returns null for anything
 *  not on the whitelist — the caller turns that into a 400 naming the field. */
export function lookupField(scope: QueryScope, path: string): QueryFieldSpec | null {
  return catalog.get(scope)?.fields.get(path) ?? null;
}

/** Autocompletion source for the client. Sorted, stable. */
export function fieldsOf(scope: QueryScope): readonly QueryFieldSpec[] {
  const spec = catalog.get(scope);
  if (!spec) return [];
  return [...spec.fields.values()].sort((a, b) => a.path.localeCompare(b.path));
}

/**
 * Operators the grammar will accept for a given field.
 *
 * THE SERVER'S VALIDATOR CALLS THIS — it is not a hint for the editor that the
 * back end then re-derives from a second, drifting copy. The client greys out
 * what is not in the list, the server refuses what is not in the list, and
 * there is exactly one list.
 */
export function operatorsFor(field: QueryFieldSpec): readonly QueryOperator[] {
  const out: QueryOperator[] = [];
  if (field.cardinality === 'set') {
    out.push('has', 'in');
    // `= ` on a set would read as "the whole array equals", which is not what
    // anybody means and not what containment does. `has` is the honest name.
  } else {
    out.push('eq', 'neq', 'in');
    if (field.type === 'number' || field.type === 'timestamp') out.push('gt', 'gte', 'lt', 'lte');
    if (field.type === 'string') out.push('contains', 'startsWith', 'endsWith');
  }
  // `is null` is offered on EVERY field, nullable or not. A non-nullable field
  // of `ncmVersion` 1 is simply ABSENT from a document written by an older
  // parser, and "which devices predate this field" is a legitimate — and, when
  // a resource is being backfilled, an important — question. Restricting the
  // operator to `nullable` fields would answer it with a syntax error.
  out.push('isNull', 'isNotNull');
  return out;
}

// ============================================================================
// The AST
// ============================================================================

export type QueryLiteral = string | number | boolean | null;

/** A predicate on ONE field of the enclosing scope. */
export interface QueryFieldNode {
  t: 'field';
  scope: QueryScope;
  field: string;
  op: QueryOperator;
  values: QueryLiteral[];
}

/** Boolean structure INSIDE a resource bracket. Every leaf is a field of the
 *  same resource element, which is what makes `firewallRule[a and b]` mean
 *  "one rule with both" and not "a rule with a, and some rule with b". */
export type ResourceExpr =
  | { t: 'and'; nodes: ResourceExpr[] }
  | { t: 'or'; nodes: ResourceExpr[] }
  | { t: 'not'; node: ResourceExpr }
  | QueryFieldNode;

export type QueryExpr =
  | { t: 'and'; nodes: QueryExpr[] }
  | { t: 'or'; nodes: QueryExpr[] }
  | { t: 'not'; node: QueryExpr }
  | { t: 'resource'; kind: NcmResourceKind; expr: ResourceExpr | null }
  | { t: 'count'; kind: NcmResourceKind; expr: ResourceExpr | null; op: QueryOperator; value: number }
  | QueryFieldNode;

export interface ParsedQuery {
  ast: QueryExpr;
  /** Scopes the query touched — the UI badges them, and the executor uses them
   *  to decide whether the snapshot join is needed at all. */
  scopes: QueryScope[];
  nodeCount: number;
  parseMs: number;
}

// ============================================================================
// Saved queries and policies — the wire contract of §3.7
// ============================================================================

/**
 * A POLICY QUERY MATCHES THE VIOLATORS.
 *
 * `service[service = "snmp" and version = "v1"]` promoted to a policy means
 * "SNMP v1 is forbidden", and every device the query returns FAILS it. The
 * inverse convention (write the desired state, fail on non-match) reads better
 * in a sentence and is a trap in practice: a device whose snapshot is missing
 * matches nothing, and would be reported as failing every policy it was never
 * evaluated against. Matching-is-violating means "no data" is "no violation",
 * which is the fail-QUIET direction — and `snapshot.missing` is itself
 * queryable, so "no data" is a policy you write explicitly when you want it.
 */
export const POLICY_MATCH_MEANING = 'match_is_violation' as const;

export const SavedQueryInput = z.object({
  name: z.string().min(1).max(120),
  description: z.string().max(1000).nullable().optional(),
  dsl: z.string().min(1).max(QUERY_LIMITS.maxQueryLength),
  isPolicy: z.boolean().optional(),
  severity: z.enum(DIFF_SEVERITIES).optional(),
  enabled: z.boolean().optional(),
}).strict().superRefine((v, ctx) => {
  // A policy with no severity cannot be ranked against the drift findings it
  // will sit next to on the fleet screen, and `severity` on a non-policy query
  // is a field nothing reads — both are quiet ways to end up with a policy that
  // never surfaces.
  if (v.isPolicy === true && v.severity === undefined) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['severity'],
      message: 'a policy requires a severity',
    });
  }
});
export type SavedQueryInput = z.infer<typeof SavedQueryInput>;

export const SavedQueryPatch = z.object({
  name: z.string().min(1).max(120).optional(),
  description: z.string().max(1000).nullable().optional(),
  dsl: z.string().min(1).max(QUERY_LIMITS.maxQueryLength).optional(),
  isPolicy: z.boolean().optional(),
  severity: z.enum(DIFF_SEVERITIES).nullable().optional(),
  enabled: z.boolean().optional(),
}).strict();
export type SavedQueryPatch = z.infer<typeof SavedQueryPatch>;

export interface SavedQuery {
  id: number;
  uuid: string;
  name: string;
  description: string | null;
  dsl: string;
  compiledSqlHash: string;
  isPolicy: boolean;
  severity: (typeof DIFF_SEVERITIES)[number] | null;
  enabled: boolean;
  createdBy: number | null;
  lastRunAt: string | null;
  lastRunMs: number | null;
  lastMatchCount: number | null;
  createdAt: string;
  updatedAt: string;
}

export interface QueryResultRow {
  deviceId: number;
  deviceUuid: string;
  name: string;
  brand: string;
  family: string;
  model: string | null;
  role: string;
  status: string;
  site: string | null;
  snapshotId: string | null;
  snapshotUuid: string | null;
  capturedAt: string | null;
  lastSeenAt: string | null;
  ncmHash: string | null;
}

export interface QueryResult {
  rows: QueryResultRow[];
  total: number;
  /** Milliseconds spent inside Postgres. Reported because M9's acceptance
   *  criterion is a number, not an adjective. */
  elapsedMs: number;
  parseMs: number;
  truncated: boolean;
  scopes: QueryScope[];
  /** True when every resource predicate compiled to a `@>` containment, i.e.
   *  when the GIN index on `config_snapshots.ncm` could be used. False means
   *  the query fell back to per-element expansion; the UI says so rather than
   *  letting a slow query look like a slow database. */
  ginEligible: boolean;
}

export interface PolicyEvaluation {
  queryId: number;
  queryName: string;
  severity: (typeof DIFF_SEVERITIES)[number] | null;
  evaluatedAt: string;
  devicesEvaluated: number;
  violations: number;
  elapsedMs: number;
}

export const QUERY_EXPORT_FORMATS = ['csv', 'json'] as const;
export type QueryExportFormat = (typeof QUERY_EXPORT_FORMATS)[number];

/**
 * The queries M9 exists to answer, shipped as data so the UI can offer them on
 * an empty Queries page and so the acceptance test and the product pitch cannot
 * drift apart.
 */
export const QUERY_EXAMPLES: readonly { name: string; dsl: string; severity: string }[] = [
  {
    name: 'Inbound any/any accepted from the WAN',
    dsl: 'firewallRule[chain = "input" and action = "accept" and disabled = false '
      + 'and match.srcAddress has "any" and match.dstAddress has "any"]',
    severity: 'critical',
  },
  {
    name: 'SNMP v1, or a well-known community',
    dsl: 'service[service = "snmp" and enabled = true and version = "v1"] '
      + 'or service[service = "snmp" and enabled = true and communityIsWellKnown = true]',
    severity: 'high',
  },
  {
    name: 'Vendor default administrative account',
    dsl: 'localUser[isVendorDefault = true and disabled = false]',
    severity: 'critical',
  },
  {
    name: 'No configuration backup for 30 days',
    dsl: 'snapshot.age_days > 30',
    severity: 'medium',
  },
];
