import {
  NCM_RESOURCE_KINDS,
  NcmDhcpScope,
  NcmFirewallRule,
  NcmInterface,
  NcmIpsecPeer,
  NcmLocalUser,
  NcmNatRule,
  NcmQosRule,
  NcmRoute,
  NcmService,
  NcmVlan,
  RESOURCE_KIND_TO_COLLECTION,
  type NcmResourceKind,
} from '@obliwan/shared';

/**
 * The Fleet Query field list, DERIVED FROM THE NCM SCHEMA (M9, killer K5).
 *
 * ┌─ WHY THIS WALKS ZOD INSTEAD OF LISTING FIELDS BY HAND ───────────────────┐
 * │ §5/M9 says the whitelist comes "du schéma NCM". A hand-written copy in   │
 * │ the client drifts the day a resource gains a field — silently, because   │
 * │ nothing fails: autocompletion simply stops offering the new field, or    │
 * │ keeps offering one that was removed. An operator then writes a query     │
 * │ against a path that does not exist and reads the empty result as "no     │
 * │ device is affected". That is the worst possible failure for an audit     │
 * │ tool, so the list is computed from `@obliwan/shared/ncm` at load time.   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── THIS IS NOT THE SECURITY BOUNDARY ───────────────────────────────────────
 * The whitelist that GATES a query lives on the server, next to the SQL it
 * lowers to. This list is an ergonomics aid: it helps write a correct query, it
 * does not decide whether one may run. A client-side path list is a convenience;
 * a server-side one is the guarantee. Confusing the two is how a DSL becomes an
 * arbitrary-JSONPath endpoint.
 *
 * ── INTROSPECTION IS BEST-EFFORT AND SAYS SO ────────────────────────────────
 * Zod's internals are not a public contract. Every step is defensive and the
 * whole walk is wrapped: if a future zod changes `_def`, `SCHEMA_INTROSPECTED`
 * goes false, the editor keeps working with no completions and the page says
 * "autocompletion unavailable" instead of silently offering an empty list that
 * reads as "this resource has no fields".
 */

export type FieldType = 'string' | 'number' | 'boolean' | 'enum' | 'array' | 'object' | 'unknown';

export interface SchemaField {
  /** What the operator types: `services.version`, `firewallRules.match.srcPort`. */
  path: string;
  collection: string;
  kind: NcmResourceKind;
  type: FieldType;
  /** Populated for `enum`; drives value completion after an operator. */
  enumValues: string[];
  nullable: boolean;
}

// ── zod walking ─────────────────────────────────────────────────────────────

interface ZodLike {
  _def?: {
    typeName?: string;
    values?: unknown;
    innerType?: ZodLike;
    type?: ZodLike;
    schema?: ZodLike;
  };
  shape?: Record<string, ZodLike>;
}

/** Peel `optional` / `nullable` / `default` / `effects` down to the real node. */
function unwrap(node: ZodLike, depth = 0): { node: ZodLike; nullable: boolean } {
  if (depth > 8) return { node, nullable: false };
  const name = node?._def?.typeName;
  if (name === 'ZodOptional' || name === 'ZodNullable' || name === 'ZodDefault') {
    const inner = node._def?.innerType;
    if (!inner) return { node, nullable: true };
    const next = unwrap(inner, depth + 1);
    return { node: next.node, nullable: true };
  }
  if (name === 'ZodEffects') {
    const inner = node._def?.schema;
    if (inner) return unwrap(inner, depth + 1);
  }
  return { node, nullable: false };
}

function typeOf(node: ZodLike): FieldType {
  switch (node?._def?.typeName) {
    case 'ZodString': return 'string';
    case 'ZodNumber': return 'number';
    case 'ZodBoolean': return 'boolean';
    case 'ZodEnum':
    case 'ZodNativeEnum':
    case 'ZodLiteral': return 'enum';
    case 'ZodArray': return 'array';
    case 'ZodObject': return 'object';
    default: return 'unknown';
  }
}

function enumValuesOf(node: ZodLike): string[] {
  const def = node?._def;
  if (!def) return [];
  if (def.typeName === 'ZodEnum' && Array.isArray(def.values)) {
    return (def.values as unknown[]).map((v) => String(v));
  }
  if (def.typeName === 'ZodLiteral') {
    const literal = (def as { value?: unknown }).value;
    return literal === undefined ? [] : [String(literal)];
  }
  return [];
}

function shapeOf(node: ZodLike): Record<string, ZodLike> | null {
  if (node?._def?.typeName !== 'ZodObject') return null;
  const shape = (node as { shape?: unknown }).shape;
  if (typeof shape === 'function') {
    try { return (shape as () => Record<string, ZodLike>)(); } catch { return null; }
  }
  if (shape && typeof shape === 'object') return shape as Record<string, ZodLike>;
  const lazy = (node._def as { shape?: unknown }).shape;
  if (typeof lazy === 'function') {
    try { return (lazy as () => Record<string, ZodLike>)(); } catch { return null; }
  }
  return null;
}

/**
 * Fields that exist in the model but are never worth completing.
 *
 * `matchHash` and `ordinal` are IDENTITY plumbing: querying them is querying an
 * implementation detail, and offering them teaches the wrong mental model of
 * the DSL. `kind` is redundant with the collection the path already names.
 */
const HIDDEN_FIELDS = new Set(['kind', 'matchHash', 'ordinal', 'semKey']);

function walk(
  node: ZodLike,
  prefix: string,
  collection: string,
  kind: NcmResourceKind,
  out: SchemaField[],
  depth: number,
): void {
  // Depth 2 covers `firewallRules.match.srcAddress`, which is the deepest path
  // any of the ten resources needs. Deeper would only surface array element
  // internals, which the DSL addresses with `contains`, not with a path.
  if (depth > 2) return;
  const shape = shapeOf(node);
  if (!shape) return;

  for (const [key, raw] of Object.entries(shape)) {
    if (HIDDEN_FIELDS.has(key)) continue;
    const { node: inner, nullable } = unwrap(raw);
    const type = typeOf(inner);
    const path = prefix ? `${prefix}.${key}` : key;

    if (type === 'object') {
      // The object itself is not a queryable leaf, but its children are.
      walk(inner, path, collection, kind, out, depth + 1);
      continue;
    }

    out.push({
      path: `${collection}.${path}`,
      collection,
      kind,
      type,
      enumValues: enumValuesOf(inner),
      nullable,
    });
  }
}

const RESOURCE_SCHEMAS: Partial<Record<NcmResourceKind, unknown>> = {
  interface: NcmInterface,
  vlan: NcmVlan,
  route: NcmRoute,
  firewallRule: NcmFirewallRule,
  natRule: NcmNatRule,
  dhcpScope: NcmDhcpScope,
  ipsecPeer: NcmIpsecPeer,
  localUser: NcmLocalUser,
  service: NcmService,
  qosRule: NcmQosRule,
};

/**
 * Device-level fields the DSL exposes alongside the NCM collections.
 *
 * These are NOT part of the NCM document — they come from `devices` — so they
 * are declared here rather than walked. The list is deliberately short and
 * contains no address: risk R4 says the tunnel IP is not an identity, and a
 * fleet query that can filter on it invites exactly that mistake.
 */
const DEVICE_FIELDS: SchemaField[] = [
  { path: 'device.name', collection: 'device', kind: 'interface', type: 'string', enumValues: [], nullable: false },
  { path: 'device.brand', collection: 'device', kind: 'interface', type: 'string', enumValues: [], nullable: false },
  { path: 'device.model', collection: 'device', kind: 'interface', type: 'string', enumValues: [], nullable: true },
  { path: 'device.osVersion', collection: 'device', kind: 'interface', type: 'string', enumValues: [], nullable: true },
  { path: 'device.role', collection: 'device', kind: 'interface', type: 'enum', enumValues: ['cpe', 'concentrator'], nullable: false },
  { path: 'device.siteName', collection: 'device', kind: 'interface', type: 'string', enumValues: [], nullable: true },
];

function build(): { fields: SchemaField[]; ok: boolean } {
  const out: SchemaField[] = [];
  let introspected = 0;
  for (const kind of NCM_RESOURCE_KINDS) {
    const schema = RESOURCE_SCHEMAS[kind];
    const collection = RESOURCE_KIND_TO_COLLECTION[kind];
    if (!schema || !collection) continue;
    const before = out.length;
    try {
      walk(schema as ZodLike, '', collection, kind, out, 0);
    } catch {
      // One resource failing must not cost the other nine.
      continue;
    }
    if (out.length > before) introspected += 1;
  }
  out.push(...DEVICE_FIELDS);
  out.sort((a, b) => a.path.localeCompare(b.path));
  // Nine of ten is still a usable list; zero or one means zod moved under us.
  return { fields: out, ok: introspected >= NCM_RESOURCE_KINDS.length - 1 };
}

const built = build();

/** Every completable path, sorted. */
export const NCM_SCHEMA_FIELDS: readonly SchemaField[] = built.fields;

/** False when the zod walk did not produce a usable list. The page SAYS so
 *  rather than showing an empty completion list that reads as "no fields". */
export const SCHEMA_INTROSPECTED: boolean = built.ok;

// ── DSL vocabulary ──────────────────────────────────────────────────────────
//
// Mirrors the token set the Chevrotain grammar will accept. Kept next to the
// field list because a completion popup that offers a keyword the parser does
// not know is worse than one that offers none.

export const QUERY_KEYWORDS = ['and', 'or', 'not', 'any', 'all', 'exists', 'count'] as const;

export const QUERY_OPERATORS = [
  '=', '!=', '~', '!~', '>', '>=', '<', '<=', 'in', 'contains',
] as const;

export interface Completion {
  value: string;
  label: string;
  detail: string;
  category: 'field' | 'operator' | 'keyword' | 'value';
}

/**
 * Completions for the token under the caret.
 *
 * Context is decided by the LAST token before the caret, which is enough for a
 * flat predicate language and is honest about being a heuristic: it offers,
 * it never rewrites. The parser on the server is the authority on whether the
 * result is valid, and the editor never blocks a keystroke because it did not
 * recognise it.
 */
export function completionsFor(text: string, caret: number): { items: Completion[]; from: number } {
  const before = text.slice(0, caret);
  const tokenMatch = /[A-Za-z0-9_.$-]*$/.exec(before);
  const token = tokenMatch ? tokenMatch[0] : '';
  const from = caret - token.length;
  const preceding = before.slice(0, from).trimEnd();
  const lastToken = /[^\s]+$/.exec(preceding)?.[0] ?? '';

  const lower = token.toLowerCase();
  const items: Completion[] = [];

  // After a field path, offer operators. After an operator, offer that field's
  // enum values when it has any.
  const fieldByPath = new Map(NCM_SCHEMA_FIELDS.map((f) => [f.path, f]));
  if (fieldByPath.has(lastToken)) {
    for (const op of QUERY_OPERATORS) {
      if (!lower || op.startsWith(lower)) {
        items.push({ value: op, label: op, detail: 'operator', category: 'operator' });
      }
    }
    return { items, from };
  }

  const opIndex = (QUERY_OPERATORS as readonly string[]).indexOf(lastToken);
  if (opIndex !== -1) {
    const pathToken = /[A-Za-z0-9_.]+$/.exec(preceding.slice(0, preceding.length - lastToken.length).trimEnd())?.[0];
    const field = pathToken ? fieldByPath.get(pathToken) : undefined;
    if (field) {
      if (field.type === 'boolean') {
        for (const v of ['true', 'false']) {
          if (!lower || v.startsWith(lower)) {
            items.push({ value: v, label: v, detail: 'boolean', category: 'value' });
          }
        }
        return { items, from };
      }
      for (const v of field.enumValues) {
        const quoted = `"${v}"`;
        if (!lower || v.toLowerCase().startsWith(lower.replace(/^"/, ''))) {
          items.push({ value: quoted, label: quoted, detail: field.path, category: 'value' });
        }
      }
      if (items.length > 0) return { items, from };
    }
  }

  // Default: fields, then keywords.
  for (const field of NCM_SCHEMA_FIELDS) {
    if (!lower || field.path.toLowerCase().includes(lower)) {
      items.push({
        value: field.path,
        label: field.path,
        detail: field.enumValues.length > 0
          ? `${field.type} · ${field.enumValues.slice(0, 4).join(' | ')}${field.enumValues.length > 4 ? ' …' : ''}`
          : field.type + (field.nullable ? ' · nullable' : ''),
        category: 'field',
      });
    }
    if (items.length >= 40) break;
  }
  for (const kw of QUERY_KEYWORDS) {
    if (!lower || kw.startsWith(lower)) {
      items.push({ value: kw, label: kw, detail: 'keyword', category: 'keyword' });
    }
  }
  return { items, from };
}

/**
 * The three queries §5/M9 uses as its acceptance test, written in the DSL.
 *
 * They are shipped as buttons because the first thing anybody does with a query
 * language is fail to guess its syntax, and because these three are the ones
 * the milestone is measured on.
 */
export const EXAMPLE_QUERIES: ReadonlyArray<{ key: string; dsl: string }> = [
  {
    key: 'anyAnyWan',
    dsl: 'firewallRules.chain = "input" and firewallRules.action = "accept" '
      + 'and firewallRules.match.srcAddress contains "any" '
      + 'and firewallRules.match.inInterface contains "any"',
  },
  {
    key: 'snmpV1',
    dsl: 'services.service = "snmp" and services.enabled = true and services.version = "v1"',
  },
  {
    key: 'defaultAdmin',
    dsl: 'localUsers.isVendorDefault = true',
  },
];
