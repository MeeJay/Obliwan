// ============================================================================
// variableResolver.service.ts — hierarchical TEMPLATE VARIABLES (M5 / C6)
// ============================================================================
//
// This is the PORT of `services/settings.service.ts` to template variables.
// Three properties of that file were audited, corrected and hardened on this
// project; they are reproduced here verbatim in intent, because relearning them
// on the config-push path would cost a customer network:
//
//   1. `tenantId` is the FIRST parameter of every function and has NO default.
//      A caller that forgets it must fail to COMPILE, not fall back silently on
//      the master tenant (AUDIT-CORR §1.2).
//   2. The ancestor walk joins `device_groups` and filters on `tenant_id`.
//      A cross-tenant closure edge (AUDIT-SEC #9) must not make one customer's
//      routers inherit another customer's variables.
//   3. The chain is resolved in ONE query ordered by decreasing depth, never in
//      N+1 round-trips (AUDIT-CORR §2.3). Here it is literally one query: the
//      four levels are UNION-ed and ranked in SQL.
//
// WHAT DIFFERS FROM `settings`, and why this file is not a copy-paste:
//
//   - a variable is TYPED. A `var_schema` (JSON Schema) carried by the template
//     revision declares each variable, its type, its default and whether it is
//     required. Validation is `ajv` + `ajv-formats` (ARCHITECTURE.md §6.1).
//   - a variable can be REQUIRED WITHOUT A DEFAULT. A device for which it does
//     not resolve must NOT produce a render with a hole in it: it produces a
//     `VariableResolutionError` naming the variable, the device, and the level
//     at which it should have been defined. A silently incomplete config that
//     reaches a router is precisely what this product exists to prevent.
//   - a variable can be SECRET. Its value lives in the vault; §8.2 says it
//     exists IN MEMORY ONLY on the path vault -> equipment. It must never
//     appear in a stored render, a diff, a plan, the UI, an export or a LOG.
//     Everything that is not that one path gets the REDACTED form.
//   - every value carries its ORIGIN (Default / Global / Tenant / Group X /
//     Device) — the shape `{ value, source, sourceId, sourceName }` is what the
//     existing `client/src/components/settings/InheritanceBadge.tsx` reads.
//
// RISK R6 — this file feeds the Nunjucks worker. `buildRenderContext()` is the
// ONLY producer of a template context, and what it returns has been proved to
// be PURE JSON: no live object, no function, no inherited prototype, no
// `__proto__` / `constructor` / `prototype` key. Nothing that could carry
// `{{ x.constructor.constructor('...')() }}` across the worker boundary comes
// from here. The worker itself, its `resourceLimits` and its 5 s timeout are
// the other half of the mitigation and live in `renderWorker.ts`.
//
// ---------------------------------------------------------------------------
// TABLE THIS SERVICE READS — `config_variables`, migration 008 (another agent).
// Its decision 6 splits the storage in two columns and makes it a CHECK:
//
//     is_secret = false  ->  value IS NOT NULL, secret_enc IS NULL
//     is_secret = true   ->  value IS NULL,     secret_enc IS NOT NULL
//
// That is a better boundary than a marker object inside `value`, because "a
// secret ended up in a jsonb column that gets rendered, diffed and exported"
// stops being a code review question and becomes an impossible row. This file
// reads and writes exactly that shape, and treats any row that contradicts it
// as REJECTED rather than as data.
//
// `settings`-style uniqueness applies (AUDIT-CORR §1.1): two PARTIAL unique
// indexes, `(tenant_id, scope, key) WHERE scope_id IS NULL` and
// `(tenant_id, scope, scope_id, key) WHERE scope_id IS NOT NULL`, because a
// naive `UNIQUE(scope,scope_id,key)` constrains NOTHING at the two levels that
// apply to a whole fleet (PostgreSQL 16 is still NULLS DISTINCT). The upserts
// below target them through their conflict EXPRESSION, WHERE clause included —
// PostgreSQL cannot infer a partial index from a bare column list, and the
// expression form does not couple this file to 008's index names.
// ============================================================================

import crypto from 'crypto';
import type { Knex } from 'knex';
import Ajv, { type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import { LRUCache } from 'lru-cache';
import type { SecretFingerprint } from '@obliwan/shared';
import { db } from '../../db';
import { config } from '../../config';
import { decrypt, encrypt } from '../secretVault.service';
import { VARIABLE_KEY_RE, VARIABLE_SCOPES } from '../../validators/template.schema';

// The naming rule and the scope list live at the API boundary
// (`validators/template.schema.ts`) so that a form field can be validated
// without importing a module that opens a database connection. They are
// re-exported here because this service is where the rest of M5 looks for them,
// and because there must be exactly one regex.
export { VARIABLE_KEY_RE, VARIABLE_SCOPES };

// ============================================================================
// Types
// ============================================================================

/** The four levels of the inheritance chain, narrowest last. */
export type VariableScope = (typeof VARIABLE_SCOPES)[number];

/** Where a resolved value came from. `'default'` = the `var_schema` default. */
export type VariableSource = VariableScope | 'default';

/** JSON, and nothing but JSON. `undefined` is deliberately absent from this
 *  union: it does not survive `JSON.stringify`, and it is the single most
 *  common way a hole reaches a router. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [k: string]: JsonValue };

/**
 * One resolved variable, in its REDACTED form — safe for `config_renders`, the
 * diff, the plan, the UI, an export and a log line.
 *
 * The `{ value, source, sourceId, sourceName }` quartet is deliberately the
 * same shape as `SettingValue` in `@obliwan/shared`, so `InheritanceBadge`
 * renders it unchanged. (That component has no branch for `source: 'tenant'`
 * yet — a client change, and the client is outside this agent's perimeter; it
 * is listed in the hand-off.)
 */
export interface ResolvedVariable {
  key: string;
  /** Redacted when `isSecret`: never the plaintext. */
  value: JsonValue;
  source: VariableSource;
  sourceId: number | null;
  sourceName: string;
  /** Closure depth of the winning group (0 = the device's own group), else null. */
  sourceDepth: number | null;
  isSecret: boolean;
  /** true when `value` is the placeholder rather than the real value. */
  redacted: boolean;
  /**
   * Keyed fingerprint of the plaintext, per tenant, so "the secret changed" is
   * detectable without the platform ever writing the secret to a diffable
   * store. Same construction as `SecretFingerprint` in the NCM contract.
   * `null` for a non-secret variable.
   */
  fingerprint: SecretFingerprint | null;
}

export type ResolvedVariables = Record<string, ResolvedVariable>;

/** One step of the chain that was actually searched, for error messages. */
export interface ChainStep {
  scope: VariableScope;
  scopeId: number | null;
  label: string;
  depth: number | null;
}

export interface MissingVariable {
  key: string;
  /** Level the template author declared with `x-obliwan-level`, else 'device'. */
  expectedScope: VariableScope;
  reason: 'required-and-unresolved' | 'secret-declared-but-absent';
}

export interface VariableTypeError {
  key: string;
  /** ajv's message, or ours. NEVER contains the offending value: a secret must
   *  not reach a log through a validation error. */
  message: string;
  source: VariableSource;
  sourceName: string;
}

/** A row the API could not have written — a key that does not match
 *  `VARIABLE_KEY_RE`, or a broken secret envelope. Skipped, never rendered,
 *  always reported. */
export interface RejectedVariable {
  key: string;
  scope: VariableScope;
  scopeId: number | null;
  reason: string;
}

/** The full picture for one target. Non-throwing: this is the INSPECTION view
 *  (variables UI, template preview). `buildRenderContext()` is the throwing one. */
export interface VariableReport {
  tenantId: number;
  deviceId: number | null;
  deviceName: string | null;
  groupId: number | null;
  chain: ChainStep[];
  variables: ResolvedVariables;
  missing: MissingVariable[];
  typeErrors: VariableTypeError[];
  rejected: RejectedVariable[];
  /** true when a render may proceed. */
  ok: boolean;
}

/** What `buildRenderContext()` hands to the render worker. */
export interface RenderContext {
  /** PURE JSON. In `'redacted'` mode secrets are placeholders; in `'secrets'`
   *  mode they are plaintext and this object is IN-MEMORY ONLY (§8.2). */
  context: Record<string, JsonValue>;
  mode: 'redacted' | 'secrets';
  /** Redacted view — this is the one that goes into `variables_snapshot`. */
  variables: ResolvedVariables;
  /** Keys whose value is a secret, in either mode. */
  secretKeys: string[];
  report: VariableReport;
}

// ============================================================================
// Errors
// ============================================================================

/**
 * Raised instead of rendering a hole. Carries the machine-readable lists so a
 * controller can turn it into a 422 with a per-variable form error, and a
 * message an operator can act on without opening a log aggregator.
 */
export class VariableResolutionError extends Error {
  constructor(
    message: string,
    readonly tenantId: number,
    readonly deviceId: number | null,
    readonly missing: MissingVariable[],
    readonly typeErrors: VariableTypeError[],
    readonly chain: ChainStep[],
  ) {
    super(message);
    this.name = 'VariableResolutionError';
  }
}

/** The `var_schema` of the revision is not a usable JSON Schema. */
export class VarSchemaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VarSchemaError';
  }
}

/** A value crossing into the render worker was not pure JSON. */
export class ImpureContextError extends Error {
  constructor(
    message: string,
    readonly path: string,
  ) {
    super(message);
    this.name = 'ImpureContextError';
  }
}

// ============================================================================
// Key naming — the first line of defence against prototype pollution
// ============================================================================

// `VARIABLE_KEY_RE` is imported from the validator above and mirrors migration
// 008's `config_variables_key_chk` exactly. Its leading-lowercase-letter rule
// makes `__proto__` unrepresentable — but NOT `constructor` and NOT
// `prototype`, which match it. 008's header claims otherwise; that claim is
// wrong and is reported to the lead. The set below is what actually stops
// those two, and it is applied at write time (`assertWritable`), at read time
// (`fold` — a row inserted by psql behind the API's back is rejected, not
// rendered) and again on the whole context before it crosses into the worker
// (`assertJsonPure`). Three checks for one rule, because the cost of the rule
// failing is a Nunjucks context whose prototype an attacker controls.
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// ============================================================================
// Redaction (§8.2)
// ============================================================================

/**
 * The masked form of a secret. It names the VARIABLE, not the value: the key is
 * already public (it is declared in `var_schema`, which the operator wrote),
 * and a reviewer reading a masked plan needs to know WHICH secret lands where.
 *
 * A constant per key also makes the masked body byte-stable across a secret
 * ROTATION — deliberately: the masked artefact must not be a rotation oracle.
 * "The secret changed" is carried by `ResolvedVariable.fingerprint`, which is
 * keyed per tenant and irreversible.
 */
export function redactedPlaceholder(key: string): string {
  return `__OBLIWAN_SECRET_${key.toUpperCase()}__`;
}

/** Matches any placeholder produced above. `render.service` uses it to assert
 *  that no placeholder survived into the artefact actually pushed. */
export const SECRET_PLACEHOLDER_RE = /__OBLIWAN_SECRET_[A-Z0-9_]+__/g;

/**
 * Last-chance guard before persisting or logging anything derived from a
 * render: refuse a string that contains a secret plaintext.
 *
 * Cheap, and the only check that catches a template author writing `{{ psk }}`
 * into a section that ends up in the STORED body. The error names the variable
 * and never echoes the value.
 */
export function assertNoPlaintextSecret(
  subject: string,
  secrets: readonly { key: string; plaintext: string }[],
  what = 'value',
): void {
  for (const s of secrets) {
    if (s.plaintext.length > 0 && subject.includes(s.plaintext)) {
      throw new Error(
        `Refusing to persist ${what}: it contains the plaintext of the secret ` +
          `variable "${s.key}" (ARCHITECTURE.md §8.2 — a secret exists in memory ` +
          'only, on the path vault -> device).',
      );
    }
  }
}

// ============================================================================
// Vault blob shape
// ============================================================================

/**
 * `secretVault`'s storage format: `v1:<key_version>:<iv>:<tag>:<ciphertext>`.
 * Used only to notice a blob that has been pasted into the CLEAR `value`
 * column — a row that migration 008's CHECK permits (it is a legal non-secret
 * string) but that means somebody stored a credential on the rendered path.
 */
const VAULT_BLOB_RE = /^v1:\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]*$/;

// ============================================================================
// Secret fingerprint — same construction as the NCM `SecretFingerprint`
// ============================================================================

const FP_UNAVAILABLE: SecretFingerprint = {
  algo: 'hmac-sha256/v1',
  fp: null,
  unavailable: true,
};

/**
 * Per-tenant key derived from OBLIWAN_ENCRYPTION_KEY, so two tenants using the
 * same weak PSK are not linkable through a stored fingerprint. Derivation only
 * — the key never leaves this module and is never persisted.
 */
function tenantFingerprintKey(tenantId: number): Buffer | null {
  if (!config.encryptionKey || !config.encryptionKeyValid) return null;
  return crypto
    .createHmac('sha256', Buffer.from(config.encryptionKey.trim(), 'hex'))
    .update(`obliwan:varfp:v1:${tenantId}`)
    .digest();
}

function fingerprintSecret(tenantId: number, key: string, plaintext: string): SecretFingerprint {
  const k = tenantFingerprintKey(tenantId);
  if (!k) return FP_UNAVAILABLE;
  const mac = crypto.createHmac('sha256', k).update(`configVar|${key}|${plaintext}`).digest();
  return {
    algo: 'hmac-sha256/v1',
    fp: mac.toString('base64url').slice(0, 22),
    unavailable: false,
  };
}

// ============================================================================
// JSON purity — the R6 boundary
// ============================================================================

const MAX_CONTEXT_DEPTH = 32;

/**
 * Prove a value is pure JSON, or throw naming the exact path.
 *
 * What this rejects, and why each one matters at the worker boundary:
 *   undefined / function / symbol / bigint — not JSON; a function is a
 *       reachable callable inside the sandbox.
 *   NaN / Infinity — `JSON.stringify` turns them into `null`, i.e. a silent
 *       hole in a router configuration.
 *   a non-plain object (Date, Buffer, Map, a class instance) — carries a
 *       prototype, and a prototype carries `constructor`, which is step one of
 *       `{{ x.constructor.constructor('...')() }}`.
 *   `__proto__` / `constructor` / `prototype` as a KEY — prototype pollution.
 *   an accessor property — a getter is a function call in disguise.
 *   a cycle, or depth > 32 — a hostile or accidental structure that would hang
 *       the serializer.
 */
export function assertJsonPure(
  value: unknown,
  path = '$',
  seen: Set<unknown> = new Set<unknown>(),
  depth = 0,
): void {
  if (depth > MAX_CONTEXT_DEPTH) {
    throw new ImpureContextError(
      `Context is deeper than ${MAX_CONTEXT_DEPTH} levels at ${path}.`,
      path,
    );
  }
  if (value === null) return;

  const t = typeof value;
  if (t === 'string' || t === 'boolean') return;
  if (t === 'number') {
    if (!Number.isFinite(value as number)) {
      throw new ImpureContextError(
        `Non-finite number at ${path} — JSON.stringify would turn it into null, ` +
          'i.e. a hole in a device configuration.',
        path,
      );
    }
    return;
  }
  if (t === 'undefined' || t === 'function' || t === 'symbol' || t === 'bigint') {
    throw new ImpureContextError(`Value of type "${t}" at ${path} is not JSON.`, path);
  }

  if (seen.has(value)) {
    throw new ImpureContextError(`Circular reference at ${path}.`, path);
  }
  seen.add(value);

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw new ImpureContextError(`Array at ${path} has a tampered prototype.`, path);
    }
    value.forEach((v, i) => assertJsonPure(v, `${path}[${i}]`, seen, depth + 1));
    seen.delete(value);
    return;
  }

  const proto = Object.getPrototypeOf(value) as object | null;
  if (proto !== Object.prototype && proto !== null) {
    throw new ImpureContextError(
      `Object at ${path} is a live instance (prototype "${
        (proto as { constructor?: { name?: string } })?.constructor?.name ?? 'unknown'
      }"), not a plain JSON object. Nothing carrying a prototype crosses into ` +
        'the render worker.',
      path,
    );
  }
  for (const k of Object.getOwnPropertyNames(value)) {
    if (FORBIDDEN_KEYS.has(k)) {
      throw new ImpureContextError(`Forbidden key "${k}" at ${path} (prototype pollution).`, path);
    }
    const d = Object.getOwnPropertyDescriptor(value, k);
    if (d && (typeof d.get === 'function' || typeof d.set === 'function')) {
      throw new ImpureContextError(`Accessor property "${k}" at ${path} is not JSON.`, path);
    }
    assertJsonPure((value as Record<string, unknown>)[k], `${path}.${k}`, seen, depth + 1);
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new ImpureContextError(`Symbol-keyed property at ${path} is not JSON.`, path);
  }
  seen.delete(value);
}

/**
 * Re-materialise a value through JSON so that whatever object identity it had
 * on this side of the boundary is gone. `assertJsonPure` has already run, so
 * this cannot lose information; the reviver exists only so a `__proto__` key
 * smuggled in as raw jsonb text cannot be revived as a real prototype.
 */
export function jsonClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value), (k: string, v: unknown) =>
    FORBIDDEN_KEYS.has(k) ? undefined : v,
  ) as T;
}

// ============================================================================
// var_schema — JSON Schema plus the ObliWAN extension keywords
// ============================================================================

/**
 * `x-obliwan-secret` — the property's value comes from the vault. Declared in
 *   the schema so the TEMPLATE states which of its inputs are secret; the row's
 *   `is_secret` column states how the value is STORED. If the two disagree we
 *   fail closed (see `applySchema`).
 * `x-obliwan-level` — the level at which the author expects the variable to be
 *   defined. Used verbatim in the "required but unresolved" error, which is the
 *   whole point of the keyword: an operator must be told WHERE to go and fix it.
 */
export interface VarSchema {
  type?: 'object';
  properties?: Record<string, Record<string, unknown>>;
  required?: string[];
  additionalProperties?: boolean;
  [k: string]: unknown;
}

function newAjv(): Ajv {
  const instance = new Ajv({
    allErrors: true,
    // `verbose` stays OFF: it copies the offending DATA into every error
    // object, and error objects end up in logs. A secret must not reach a log
    // through a validation failure (§8.2). Secrets are not handed to ajv at all
    // (see `stripSecrets`), and this is the second lock on that door.
    verbose: false,
    useDefaults: false, // defaults are applied by us, WITH their origin
    strict: false,
    coerceTypes: false, // the string "835" is not an integer VLAN id
  });
  addFormats(instance);
  instance.addKeyword({ keyword: 'x-obliwan-secret', schemaType: 'boolean' });
  instance.addKeyword({ keyword: 'x-obliwan-level', schemaType: 'string' });
  instance.addKeyword({ keyword: 'x-obliwan-label', schemaType: 'string' });
  return instance;
}

const ajv = newAjv();

/** Compiling a schema costs about a millisecond; a rollout resolves it once per
 *  device. Cache on the schema's own hash so two revisions sharing a schema
 *  share the validator, and a schema edit invalidates itself. */
const validatorCache = new LRUCache<string, ValidateFunction>({ max: 200 });

function schemaKey(schema: VarSchema): string {
  return crypto.createHash('sha256').update(JSON.stringify(schema)).digest('hex');
}

/** Compile (and cache) a `var_schema`. Throws `VarSchemaError` on a bad one — a
 *  template revision must not be publishable with a schema nobody can run. */
export function compileVarSchema(schema: VarSchema): ValidateFunction {
  const k = schemaKey(schema);
  const hit = validatorCache.get(k);
  if (hit) return hit;
  let fn: ValidateFunction;
  try {
    fn = ajv.compile(schema as object);
  } catch (e) {
    throw new VarSchemaError(`var_schema is not a valid JSON Schema: ${(e as Error).message}`);
  }
  validatorCache.set(k, fn);
  return fn;
}

/** OWN properties only. `schema.properties` is parsed from jsonb and therefore
 *  carries `Object.prototype`; `properties['constructor']` on such an object
 *  returns the Object constructor, and every keyword lookup below would then be
 *  reading a function's fields. */
function propOf(schema: VarSchema, key: string): Record<string, unknown> | undefined {
  const props = schema.properties;
  if (!props || !Object.prototype.hasOwnProperty.call(props, key)) return undefined;
  return props[key];
}

function declaredSecret(schema: VarSchema, key: string): boolean {
  return propOf(schema, key)?.['x-obliwan-secret'] === true;
}

function expectedLevel(schema: VarSchema, key: string): VariableScope {
  const lvl = propOf(schema, key)?.['x-obliwan-level'];
  return typeof lvl === 'string' && (VARIABLE_SCOPES as readonly string[]).includes(lvl)
    ? (lvl as VariableScope)
    : 'device';
}

// ============================================================================
// The chain query — ONE round-trip, all four levels
// ============================================================================

interface ChainRow {
  scope: VariableScope;
  rank: number;
  depth: number | null;
  src_id: number | null;
  src_name: string | null;
  key: string;
  /** NULL exactly when `is_secret` (migration 008, decision 6). */
  value: unknown;
  is_secret: boolean;
  /** The vault blob. NOT NULL exactly when `is_secret`. */
  secret_enc: string | null;
}

/**
 * Load every override that applies to a target, ordered so that a plain
 * left-to-right fold produces the right precedence:
 *
 *   global  <  tenant  <  group(root)  < ... <  group(leaf)  <  device
 *
 * `ORDER BY rank, depth DESC` IS the precedence rule. `depth` is the closure
 * distance from the device's own group, so the FARTHEST ancestor comes first
 * and the device's own group comes last — the same ordering
 * `settings.service._ancestorOverrides` uses, for the same reason.
 *
 * The two tenant guards that must never be removed:
 *   - `dg.tenant_id = :tenantId` — a cross-tenant closure edge (AUDIT-SEC #9)
 *     must not let another customer's group inject a variable here.
 *   - `d.tenant_id = :tenantId` on the device branch — the same argument one
 *     level down: a device id belonging to another tenant resolves to zero
 *     rows, not to that tenant's overrides.
 */
async function chainRows(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  groupId: number | null,
  deviceId: number | null,
): Promise<ChainRow[]> {
  const sql = `
    select 'global'::text as scope, 0 as rank, null::int as depth,
           null::int as src_id, null::text as src_name,
           cv.key, cv.value, cv.is_secret, cv.secret_enc
      from config_variables cv
     where cv.tenant_id = :tenantId and cv.scope = 'global' and cv.scope_id is null
    union all
    select 'tenant'::text, 1, null::int, t.id, t.name,
           cv.key, cv.value, cv.is_secret, cv.secret_enc
      from config_variables cv
      join tenants t on t.id = cv.tenant_id
     where cv.tenant_id = :tenantId and cv.scope = 'tenant' and cv.scope_id is null
    union all
    select 'group'::text, 2, gc.depth, dg.id, dg.name,
           cv.key, cv.value, cv.is_secret, cv.secret_enc
      from group_closure gc
      join device_groups dg on dg.id = gc.ancestor_id
      join config_variables cv
        on cv.scope_id = gc.ancestor_id and cv.scope = 'group' and cv.tenant_id = :tenantId
     where gc.descendant_id = :groupId
       and dg.tenant_id = :tenantId
    union all
    select 'device'::text, 3, null::int, d.id, d.name,
           cv.key, cv.value, cv.is_secret, cv.secret_enc
      from config_variables cv
      join devices d on d.id = cv.scope_id and d.tenant_id = :tenantId
     where cv.tenant_id = :tenantId and cv.scope = 'device' and cv.scope_id = :deviceId
     order by 2 asc, 3 desc nulls last
  `;
  const res = (await executor.raw(sql, {
    tenantId,
    // A device with no group, or a group-level preview with no device: the
    // corresponding branch matches nothing. Still one query.
    groupId: groupId ?? -1,
    deviceId: deviceId ?? -1,
  })) as { rows?: ChainRow[] };
  return res.rows ?? [];
}

/** The chain that was actually searched, for the "where do I go and fix this"
 *  half of the error message. Only run when something is wrong. */
async function describeChain(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  groupId: number | null,
  deviceId: number | null,
  deviceName: string | null,
): Promise<ChainStep[]> {
  const steps: ChainStep[] = [
    { scope: 'global', scopeId: null, label: 'Global', depth: null },
    { scope: 'tenant', scopeId: tenantId, label: `Tenant #${tenantId}`, depth: null },
  ];
  if (groupId !== null) {
    const groups = (await executor('group_closure')
      .join('device_groups', 'device_groups.id', 'group_closure.ancestor_id')
      .where('group_closure.descendant_id', groupId)
      .where('device_groups.tenant_id', tenantId)
      .orderBy('group_closure.depth', 'desc')
      .select(
        'device_groups.id as id',
        'device_groups.name as name',
        'group_closure.depth as depth',
      )) as { id: number; name: string; depth: number }[];
    for (const g of groups) {
      steps.push({ scope: 'group', scopeId: g.id, label: `Group "${g.name}"`, depth: g.depth });
    }
  }
  if (deviceId !== null) {
    steps.push({
      scope: 'device',
      scopeId: deviceId,
      label: deviceName ? `Device "${deviceName}"` : `Device #${deviceId}`,
      depth: null,
    });
  }
  return steps;
}

// ============================================================================
// Fold: rows -> resolved variables
// ============================================================================

function sourceNameOf(row: ChainRow, tenantId: number): string {
  switch (row.scope) {
    case 'global':
      return 'Global';
    case 'tenant':
      return row.src_name ?? `Tenant #${tenantId}`;
    case 'group':
      return row.src_name ?? `Group #${row.src_id}`;
    case 'device':
      return row.src_name ?? `Device #${row.src_id}`;
  }
}

interface FoldResult {
  variables: ResolvedVariables;
  /** key -> plaintext, IN MEMORY ONLY. Never returned to a caller that did not
   *  explicitly ask for secrets. */
  plaintexts: Map<string, string>;
  rejected: RejectedVariable[];
}

function fold(tenantId: number, rows: ChainRow[]): FoldResult {
  // NULL-PROTOTYPE, and this is not a micro-optimisation.
  //
  // `constructor`, `prototype`, `toString`, `valueOf` and `hasOwnProperty` all
  // match `VARIABLE_KEY_RE` and are all legal `config_variables.key` values as
  // far as migration 008's CHECK is concerned. On a `{}` map,
  // `variables['toString']` returns a FUNCTION inherited from
  // `Object.prototype`, so `if (variables[key] !== undefined)` reads "already
  // resolved" for a variable nobody ever set, `applySchema` skips its default,
  // and a caller reading `report.variables[key].value` gets a live function
  // instead of a value. The verification run caught exactly this.
  const variables: ResolvedVariables = Object.create(null) as ResolvedVariables;
  const plaintexts = new Map<string, string>();
  const rejected: RejectedVariable[] = [];

  for (const row of rows) {
    // A row whose key the API could not have written did not come through the
    // API. Skip it — and say so, loudly — rather than let it near a context.
    if (!VARIABLE_KEY_RE.test(row.key) || FORBIDDEN_KEYS.has(row.key)) {
      rejected.push({
        key: row.key,
        scope: row.scope,
        scopeId: row.src_id,
        reason: 'key does not match VARIABLE_KEY_RE — refused, never rendered',
      });
      continue;
    }

    const base = {
      key: row.key,
      source: row.scope,
      sourceId: row.scope === 'global' ? null : row.src_id,
      sourceName: sourceNameOf(row, tenantId),
      sourceDepth: row.depth,
    };

    if (row.is_secret) {
      if (typeof row.secret_enc !== 'string' || row.secret_enc.length === 0) {
        rejected.push({
          key: row.key,
          scope: row.scope,
          scopeId: row.src_id,
          reason: 'is_secret row carries no secret_enc blob',
        });
        // Fail CLOSED: drop the lower-precedence value too. A half-resolved
        // secret is worse than a missing one — the render must stop.
        delete variables[row.key];
        plaintexts.delete(row.key);
        continue;
      }
      let plain: string;
      try {
        plain = decrypt(row.secret_enc);
      } catch (e) {
        rejected.push({
          key: row.key,
          scope: row.scope,
          scopeId: row.src_id,
          // VaultError names the key_version and nothing else — safe to keep.
          reason: `vault: ${(e as Error).message}`,
        });
        delete variables[row.key];
        plaintexts.delete(row.key);
        continue;
      }
      plaintexts.set(row.key, plain);
      variables[row.key] = {
        ...base,
        value: redactedPlaceholder(row.key),
        isSecret: true,
        redacted: true,
        fingerprint: fingerprintSecret(tenantId, row.key, plain),
      };
      continue;
    }

    if (row.value === null || row.value === undefined) {
      // 008's CHECK makes this unreachable through SQL; reaching it means the
      // constraint was dropped. A NULL `value` on a clear row would render as
      // an empty string, which is the hole this service exists to prevent.
      rejected.push({
        key: row.key,
        scope: row.scope,
        scopeId: row.src_id,
        reason: 'non-secret row has a NULL value',
      });
      delete variables[row.key];
      continue;
    }

    if (typeof row.value === 'string' && VAULT_BLOB_RE.test(row.value)) {
      // A vault blob pasted into the CLEAR column. It would be pushed to the
      // router verbatim — a broken config AND a credential on the stored path.
      rejected.push({
        key: row.key,
        scope: row.scope,
        scopeId: row.src_id,
        reason: 'a vault blob is stored in the clear `value` column',
      });
      continue;
    }

    // A non-secret at a narrower scope legitimately overrides a secret set
    // wider: drop the stale plaintext with it.
    plaintexts.delete(row.key);
    variables[row.key] = {
      ...base,
      value: row.value as JsonValue,
      isSecret: false,
      redacted: false,
      fingerprint: null,
    };
  }

  return { variables, plaintexts, rejected };
}

// ============================================================================
// Schema pass: defaults, required, types
// ============================================================================

function applySchema(
  schema: VarSchema | null,
  variables: ResolvedVariables,
  plaintexts: Map<string, string>,
): { missing: MissingVariable[]; typeErrors: VariableTypeError[] } {
  const missing: MissingVariable[] = [];
  const typeErrors: VariableTypeError[] = [];
  if (!schema) return { missing, typeErrors };

  const props = schema.properties ?? {};
  const required = new Set(schema.required ?? []);

  // 1. Defaults — applied by us, not by ajv's `useDefaults`, because a default
  //    that arrives through mutation loses the one thing the UI needs: where
  //    the value came from.
  for (const [key, prop] of Object.entries(props)) {
    if (!VARIABLE_KEY_RE.test(key) || FORBIDDEN_KEYS.has(key)) {
      typeErrors.push({
        key,
        message: `is declared by var_schema but is not a legal variable name (${VARIABLE_KEY_RE})`,
        source: 'default',
        sourceName: 'var_schema',
      });
      continue;
    }
    if (variables[key] !== undefined) continue;
    if (!('default' in prop)) continue;
    if (declaredSecret(schema, key)) {
      // A default for a SECRET would be a plaintext credential sitting in the
      // revision body, which is exactly what the vault exists to avoid.
      typeErrors.push({
        key,
        message: 'is declared secret and given a default — a secret has no default (§8.2)',
        source: 'default',
        sourceName: 'var_schema',
      });
      continue;
    }
    variables[key] = {
      key,
      value: prop.default as JsonValue,
      source: 'default',
      sourceId: null,
      sourceName: 'Default',
      sourceDepth: null,
      isSecret: false,
      redacted: false,
      fingerprint: null,
    };
  }

  // 2. Secret / non-secret agreement, both directions. Fail closed.
  for (const key of Object.getOwnPropertyNames(props)) {
    const v = variables[key];
    if (!v) continue;
    if (declaredSecret(schema, key) && !v.isSecret) {
      typeErrors.push({
        key,
        message: `is declared secret by the template but is stored in clear at ${v.sourceName}`,
        source: v.source,
        sourceName: v.sourceName,
      });
    }
    if (!declaredSecret(schema, key) && v.isSecret) {
      typeErrors.push({
        key,
        message:
          'is stored as a secret but the template does not declare "x-obliwan-secret": ' +
          'the rendered value would be a placeholder',
        source: v.source,
        sourceName: v.sourceName,
      });
    }
  }

  // 3. Required and unresolved -> a NAMED error, never a hole.
  for (const key of required) {
    const v = variables[key];
    const resolved = v !== undefined && (!v.isSecret || plaintexts.has(key));
    if (!resolved) {
      missing.push({
        key,
        expectedScope: expectedLevel(schema, key),
        reason: declaredSecret(schema, key)
          ? 'secret-declared-but-absent'
          : 'required-and-unresolved',
      });
    }
  }

  // 4. Types. Secrets are EXCLUDED from ajv on purpose: ajv builds error
  //    strings, error strings reach logs, and a secret must not (§8.2). What
  //    can still be checked about a secret without looking at it — that it
  //    exists, and that it decrypted — has been checked above.
  const validate = compileVarSchema(stripSecrets(schema));
  const subject: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [key, v] of Object.entries(variables)) {
    if (v.isSecret || declaredSecret(schema, key)) continue;
    subject[key] = v.value;
  }
  if (!validate(subject)) {
    for (const err of validate.errors ?? []) {
      // `required` is reported by us, with a level to go and fix it. Do not
      // duplicate it as an opaque type error.
      if (err.keyword === 'required') continue;
      const key = err.instancePath.startsWith('/')
        ? err.instancePath.slice(1).split('/')[0]
        : ((err.params as { additionalProperty?: string })?.additionalProperty ?? '(document)');
      const v = variables[key];
      const sub = err.instancePath.slice(Math.min(key.length + 1, err.instancePath.length));
      typeErrors.push({
        key,
        message: `${sub ? sub + ' ' : ''}${err.message ?? 'is invalid'}`,
        source: v?.source ?? 'default',
        sourceName: v?.sourceName ?? 'var_schema',
      });
    }
  }

  return { missing, typeErrors };
}

/** A copy of the schema with the secret properties removed, so ajv never sees a
 *  secret value AND never reports `required` on one (that path is ours). */
function stripSecrets(schema: VarSchema): VarSchema {
  const props = schema.properties ?? {};
  const secretKeys = Object.keys(props).filter((k) => props[k]?.['x-obliwan-secret'] === true);
  const out: VarSchema = { ...schema };
  if (secretKeys.length > 0) {
    const p: Record<string, Record<string, unknown>> = {};
    for (const [k, v] of Object.entries(props)) if (!secretKeys.includes(k)) p[k] = v;
    out.properties = p;
  }
  // `required` is enforced by us, with a device name and a level. ajv's version
  // of the same message has neither.
  delete out.required;
  return out;
}

// ============================================================================
// Public API
// ============================================================================

/** Audit columns migration 008 puts on `config_variables`. */
export interface VariableMeta {
  description?: string | null;
  updatedBy?: number | null;
}

/** Look up a device, scoped by tenant. A device id belonging to another tenant
 *  does not exist as far as this service is concerned. */
async function loadDevice(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  deviceId: number,
): Promise<{ id: number; name: string; group_id: number | null }> {
  const row = (await executor('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first('id', 'name', 'group_id')) as
    | { id: number; name: string; group_id: number | null }
    | undefined;
  if (!row) throw new Error(`Device #${deviceId} does not exist in tenant #${tenantId}.`);
  return row;
}

export const variableResolver = {
  // ── Inspection (never throws on a missing variable) ──────────────────────

  /**
   * Resolve every variable that applies to a device, in REDACTED form.
   *
   * `tenantId` first and mandatory (AUDIT-CORR §1.2). `groupId` may be passed
   * by a caller that already has it (`render.service` walking a rollout) to
   * save the device lookup; when omitted it is read from `devices`, scoped by
   * tenant.
   *
   * Cost: one query for the whole chain, one for the device row, and one for
   * the chain DESCRIPTION only when something is wrong.
   */
  async resolveForDevice(
    tenantId: number,
    deviceId: number,
    varSchema: VarSchema | null = null,
    opts: { groupId?: number | null; executor?: Knex | Knex.Transaction } = {},
  ): Promise<VariableReport> {
    const executor = opts.executor ?? db;
    let deviceName: string | null;
    let groupId: number | null;
    if (opts.groupId !== undefined) {
      groupId = opts.groupId;
      const row = (await executor('devices')
        .where({ id: deviceId, tenant_id: tenantId })
        .first('name')) as { name: string } | undefined;
      deviceName = row?.name ?? null;
    } else {
      const dev = await loadDevice(executor, tenantId, deviceId);
      groupId = dev.group_id;
      deviceName = dev.name;
    }

    const rows = await chainRows(executor, tenantId, groupId, deviceId);
    const { variables, plaintexts, rejected } = fold(tenantId, rows);
    const { missing, typeErrors } = applySchema(varSchema, variables, plaintexts);

    const bad = missing.length > 0 || typeErrors.length > 0 || rejected.length > 0;
    const chain = bad
      ? await describeChain(executor, tenantId, groupId, deviceId, deviceName)
      : [];

    return {
      tenantId,
      deviceId,
      deviceName,
      groupId,
      chain,
      variables,
      missing,
      typeErrors,
      rejected,
      ok: !bad,
    };
  },

  /**
   * The group-level view the variables UI needs: what a group INHERITS
   * (global -> tenant -> ancestors, self excluded) and what it OVERRIDES.
   * Mirrors `settingsService.resolveForGroup`.
   */
  async resolveForGroup(
    tenantId: number,
    groupId: number,
    varSchema: VarSchema | null = null,
  ): Promise<{ inherited: ResolvedVariables; overrides: ResolvedVariables }> {
    const rows = await chainRows(db, tenantId, groupId, null);
    // depth 0 is the group itself; the inherited view stops at its parent.
    const inheritedRows = rows.filter((r) => r.scope !== 'group' || (r.depth ?? 0) > 0);
    const ownRows = rows.filter((r) => r.scope === 'group' && (r.depth ?? -1) === 0);
    const inherited = fold(tenantId, inheritedRows);
    applySchema(varSchema, inherited.variables, inherited.plaintexts);
    return {
      inherited: inherited.variables,
      overrides: fold(tenantId, ownRows).variables,
    };
  },

  /** Global + tenant only — the two levels that apply to a whole customer. */
  async resolveForTenant(
    tenantId: number,
    varSchema: VarSchema | null = null,
  ): Promise<ResolvedVariables> {
    const rows = await chainRows(db, tenantId, null, null);
    const { variables, plaintexts } = fold(tenantId, rows);
    applySchema(varSchema, variables, plaintexts);
    return variables;
  },

  // ── The render path (THROWS rather than render a hole) ───────────────────

  /**
   * Build the context handed to the Nunjucks worker.
   *
   * This is the ONLY function that produces a render context, and it THROWS —
   * `VariableResolutionError` — when a required variable did not resolve, when
   * a value does not match its declared type, or when a row was rejected. A
   * template that renders `interface=` with nothing after it is a config that
   * either fails on the router or, worse, succeeds and means something else.
   *
   * `mode`:
   *   'redacted' (default) — secrets are placeholders. This context produces
   *       the body stored in `config_renders.body`, the `ncm_desired`, the diff
   *       and the plan: everything that is persisted or displayed.
   *   'secrets' — secrets are plaintext. IN MEMORY ONLY, on the path
   *       vault -> equipment (§8.2). The caller must not store, log, cache or
   *       put into a `PlanOp` anything derived from it, and must run
   *       `assertNoPlaintextSecret()` on anything it is tempted to keep.
   *
   * What comes back is proven pure JSON (`assertJsonPure` + `jsonClone`): no
   * live object, no function, no prototype, no `__proto__` key. That is this
   * file's half of risk R6.
   */
  async buildRenderContext(
    tenantId: number,
    deviceId: number,
    varSchema: VarSchema | null,
    opts: {
      groupId?: number | null;
      mode?: 'redacted' | 'secrets';
      /** Extra device facts (name, model, os version...). Validated for JSON
       *  purity exactly like the variables — a live knex row must not cross. */
      extra?: Record<string, unknown>;
      executor?: Knex | Knex.Transaction;
    } = {},
  ): Promise<RenderContext> {
    const mode = opts.mode ?? 'redacted';
    const executor = opts.executor ?? db;

    const report = await this.resolveForDevice(tenantId, deviceId, varSchema, {
      groupId: opts.groupId,
      executor,
    });

    if (!report.ok) {
      throw new VariableResolutionError(
        formatResolutionError(report),
        tenantId,
        deviceId,
        report.missing,
        report.typeErrors,
        report.chain,
      );
    }

    // The plaintexts are re-read here rather than carried out of
    // `resolveForDevice`: a plaintext is never a field of a report that a
    // caller might log or persist.
    let plaintexts = new Map<string, string>();
    if (mode === 'secrets') {
      const rows = await chainRows(executor, tenantId, report.groupId, deviceId);
      plaintexts = fold(tenantId, rows).plaintexts;
    }

    // Null-prototype for the same reason `fold` uses one: a variable legitimately
    // named `toString` must not read as "already present" through the prototype.
    // `jsonClone` at the end hands the worker an ordinary object, built from
    // own properties only.
    const context: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    const secretKeys: string[] = [];
    for (const [key, v] of Object.entries(report.variables)) {
      if (v.isSecret) {
        secretKeys.push(key);
        if (mode === 'secrets') {
          const p = plaintexts.get(key);
          if (p === undefined) {
            throw new VariableResolutionError(
              `Secret variable "${key}" could not be read from the vault for device #${deviceId}.`,
              tenantId,
              deviceId,
              [{ key, expectedScope: 'device', reason: 'secret-declared-but-absent' }],
              [],
              report.chain,
            );
          }
          context[key] = p;
          continue;
        }
      }
      context[key] = v.value;
    }

    if (opts.extra) {
      for (const [k, v] of Object.entries(opts.extra)) {
        if (!VARIABLE_KEY_RE.test(k) || FORBIDDEN_KEYS.has(k)) {
          throw new ImpureContextError(`Illegal context key "${k}" in \`extra\`.`, `$.${k}`);
        }
        if (k in context) {
          throw new Error(
            `\`extra\` key "${k}" collides with a resolved variable — refusing to let ` +
              'device facts silently shadow an operator-set variable.',
          );
        }
        context[k] = v as JsonValue;
      }
    }

    // The R6 boundary. Prove, then re-materialise through JSON so no object
    // identity from this realm survives into the worker.
    assertJsonPure(context);
    const pure = jsonClone(context);

    return { context: pure, mode, variables: report.variables, secretKeys, report };
  },

  /**
   * The plaintext secrets for a device, IN MEMORY ONLY. Kept out of the context
   * so a caller has to ask for them explicitly, and so `assertNoPlaintextSecret`
   * has something to scan against before anything is persisted.
   */
  async loadSecrets(
    tenantId: number,
    deviceId: number,
    opts: { groupId?: number | null; executor?: Knex | Knex.Transaction } = {},
  ): Promise<{ key: string; plaintext: string }[]> {
    const executor = opts.executor ?? db;
    const groupId =
      opts.groupId !== undefined
        ? opts.groupId
        : (await loadDevice(executor, tenantId, deviceId)).group_id;
    const rows = await chainRows(executor, tenantId, groupId, deviceId);
    return [...fold(tenantId, rows).plaintexts].map(([key, plaintext]) => ({ key, plaintext }));
  },

  // ── Raw CRUD ─────────────────────────────────────────────────────────────

  /** Every variable set AT a level (no inheritance), redacted. */
  async getByScope(
    tenantId: number,
    scope: VariableScope,
    scopeId: number | null,
  ): Promise<ResolvedVariables> {
    const rows = (await db('config_variables')
      .where({ tenant_id: tenantId, scope, scope_id: scopeId })
      .select('key', 'value', 'is_secret', 'secret_enc')) as {
      key: string;
      value: unknown;
      is_secret: boolean;
      secret_enc: string | null;
    }[];
    return fold(
      tenantId,
      rows.map((r) => ({
        scope,
        rank: 0,
        depth: null,
        src_id: scopeId,
        src_name: null,
        key: r.key,
        value: r.value,
        is_secret: r.is_secret,
        secret_enc: r.secret_enc,
      })),
    ).variables;
  },

  /**
   * Write one variable. A secret is encrypted here and NEVER stored in clear;
   * the plaintext is not returned, not logged and not echoed in an error.
   */
  async set(
    tenantId: number,
    scope: VariableScope,
    scopeId: number | null,
    key: string,
    value: JsonValue,
    isSecret = false,
    meta: VariableMeta = {},
  ): Promise<void> {
    await db.transaction((trx) =>
      this._write(trx, tenantId, scope, scopeId, key, value, isSecret, meta),
    );
  },

  /**
   * AUDIT-CORR §2.4 — validate EVERYTHING first, then write the lot in ONE
   * transaction. A half-applied variables form leaves an operator with no way
   * to tell which half took.
   */
  async setBulk(
    tenantId: number,
    scope: VariableScope,
    scopeId: number | null,
    entries: { key: string; value: JsonValue; isSecret?: boolean; meta?: VariableMeta }[],
  ): Promise<void> {
    for (const e of entries) assertWritable(scope, scopeId, e.key, e.value, e.isSecret ?? false);
    await db.transaction(async (trx) => {
      for (const e of entries) {
        await this._write(
          trx,
          tenantId,
          scope,
          scopeId,
          e.key,
          e.value,
          e.isSecret ?? false,
          e.meta ?? {},
        );
      }
    });
  },

  /**
   * The two-column write of migration 008's decision 6: a secret goes to
   * `secret_enc` with a NULL `value`, a clear value goes to `value` with a NULL
   * `secret_enc`. `merge()` sets BOTH columns every time, because flipping a
   * variable from clear to secret (or back) must not leave the other column
   * populated — the CHECK would reject it, which is the correct outcome, but
   * only if the update actually names both columns.
   */
  async _write(
    executor: Knex | Knex.Transaction,
    tenantId: number,
    scope: VariableScope,
    scopeId: number | null,
    key: string,
    value: JsonValue,
    isSecret: boolean,
    meta: VariableMeta = {},
  ): Promise<void> {
    assertWritable(scope, scopeId, key, value, isSecret);
    const columns = {
      value: isSecret ? null : JSON.stringify(value),
      secret_enc: isSecret ? encrypt(value as string) : null,
      is_secret: isSecret,
      description: meta.description ?? null,
      updated_by: meta.updatedBy ?? null,
      updated_at: new Date(),
    };
    await executor('config_variables')
      .insert({ tenant_id: tenantId, scope, scope_id: scopeId, key, ...columns })
      .onConflict(
        scopeId === null
          ? db.raw('(tenant_id, scope, key) WHERE scope_id IS NULL')
          : db.raw('(tenant_id, scope, scope_id, key) WHERE scope_id IS NOT NULL'),
      )
      .merge(columns);
  },

  async remove(
    tenantId: number,
    scope: VariableScope,
    scopeId: number | null,
    key: string,
  ): Promise<boolean> {
    const n = await db('config_variables')
      .where({ tenant_id: tenantId, scope, scope_id: scopeId, key })
      .del();
    return n > 0;
  },
};

// ============================================================================
// Write-side invariants
// ============================================================================

function assertWritable(
  scope: VariableScope,
  scopeId: number | null,
  key: string,
  value: JsonValue,
  isSecret: boolean,
): void {
  if (!VARIABLE_KEY_RE.test(key) || FORBIDDEN_KEYS.has(key)) {
    throw new Error(
      `Illegal variable name "${key}": expected ${VARIABLE_KEY_RE}, and not one ` +
        'of __proto__ / constructor / prototype. The regex is what stops ' +
        '`__proto__`; the explicit list is what stops the other two, which the ' +
        'regex and the database CHECK both accept.',
    );
  }
  // 'global' and 'tenant' carry their identity in tenant_id, exactly like
  // `settings` — a scope_id at those levels would sit outside both partial
  // unique indexes and silently allow duplicate rows.
  if ((scope === 'global' || scope === 'tenant') && scopeId !== null) {
    throw new Error(`Scope "${scope}" must have a null scope_id.`);
  }
  if ((scope === 'group' || scope === 'device') && scopeId === null) {
    throw new Error(`Scope "${scope}" requires a scope_id.`);
  }
  if (isSecret && typeof value !== 'string') {
    throw new Error('A secret variable must be a string — the vault encrypts strings.');
  }
  if (!isSecret) {
    // A non-secret is stored in clear jsonb; prove now that it is renderable.
    assertJsonPure(value, `$.${key}`);
  }
}

// ============================================================================
// Error formatting — say WHAT, on WHICH device, and WHERE to go and fix it
// ============================================================================

function formatResolutionError(report: VariableReport): string {
  const who = report.deviceName
    ? `device #${report.deviceId} ("${report.deviceName}")`
    : `device #${report.deviceId}`;
  const chain = report.chain.map((s) => s.label).join(' -> ');
  const parts: string[] = [];

  for (const m of report.missing) {
    parts.push(
      `variable "${m.key}" is required by the template but resolves to nothing for ${who}; ` +
        `it should be defined at the ${m.expectedScope} level` +
        (m.reason === 'secret-declared-but-absent'
          ? ' (it is a SECRET: set it in the vault, not in the template)'
          : ''),
    );
  }
  for (const t of report.typeErrors) {
    parts.push(`variable "${t.key}" (from ${t.sourceName}) ${t.message}`);
  }
  for (const r of report.rejected) {
    parts.push(`row "${r.key}" at ${r.scope}#${r.scopeId ?? '-'} was refused: ${r.reason}`);
  }

  return (
    `Refusing to render for ${who}: ${parts.join('; ')}. ` +
    `Chain searched: ${chain || '(none)'}. ` +
    'A render with an unresolved variable is not produced — an incomplete ' +
    'configuration reaching a router is what this check exists to prevent.'
  );
}
