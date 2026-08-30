// ============================================================================
// ObliWAN — L0/L1 acquisition: getting a config off a box, safely.
// ============================================================================
//
// Implements §1 ("Le pipeline cible") and the frozen acquisition command of
// `docs/M4-normalisation-routeros.md`, under decisions R4 (identity before any
// operation) and R10 (no secret may enter a snapshot).
//
// ┌─ FOUR THINGS THIS FILE REFUSES TO MAKE CONFIGURABLE ──────────────────────┐
// │                                                                           │
// │ 1. `show-sensitive=no` IS A CONSTANT. Not a parameter, not an option, not │
// │    a column. R10 says a secret must never enter a snapshot, a diff, the   │
// │    UI or a log; a flag someone can flip is a flag someone will flip. The  │
// │    second line of defence is a RouterOS service account stripped of the   │
// │    `sensitive` policy, which is an operator act this code cannot perform  │
// │    — so the code does the half it can, in a way nobody can undo from a    │
// │    settings screen.                                                       │
// │                                                                           │
// │ 2. NO PTY. `ssh2.exec()` without `pty: true`. RouterOS wraps long lines   │
// │    with `\` continuations as a function of terminal width when it thinks  │
// │    it is talking to a human; the export then depends on the width of a    │
// │    terminal that does not exist. `terse` plus no pty is what makes the    │
// │    text reproducible (N13).                                               │
// │                                                                           │
// │ 3. IDENTITY FIRST, ALWAYS. Every path into this file goes through         │
// │    `withAssertedDevice()`. Reading is not writing, but a snapshot         │
// │    attributed to the wrong device is a lie stored forever, and the drift  │
// │    engine will later compare customer A's firewall to customer B's        │
// │    template. A PPP pool rotation is all it takes (R4/D5).                 │
// │                                                                           │
// │ 4. THE PARSER IS BOUND LATE, NOT IMPORTED. `normalize.service.ts` is a    │
// │    separate workstream and a separate file; a static import would make    │
// │    the whole collection path, the snapshot store and the drift engine     │
// │    fail to compile whenever it is mid-edit. The binding is a registry     │
// │    with a `require`-based fallback and a FAIL-CLOSED default: with no     │
// │    parser the collector REFUSES rather than storing an empty document.    │
// │    A collector that silently produced an empty NCM would hand the diff    │
// │    engine a device whose firewall "disappeared".                          │
// └───────────────────────────────────────────────────────────────────────────┘

import type { DeviceFamily, NcmDocument, TransportKind } from '@obliwan/shared';
import {
  FAMILY_BRAND,
  type NormalizationRule,
  type NormalizationTrace,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { decrypt } from '../secretVault.service';
import { DriverError } from '../drivers/types';
import { withSsh, type SshTransport } from '../transport/ssh.transport';
import {
  createRouterOsConnection,
  RouterOsTrapError,
  type RouterOsConnection,
} from '../transport/routeros';
import { withAssertedDevice, type BindingAssertion } from '../fleet/deviceBinding.service';
import { storeSnapshot, latestDocument, type StoreSnapshotResult } from './snapshot.service';

// ============================================================================
// The frozen L0 command
// ============================================================================

/**
 * §1 of the normalisation study, verbatim and non-negotiable.
 *
 * `terse` — one entry per line, no width-dependent continuations.
 * `show-sensitive=no` — R10.
 *
 * Exported so a test can assert on the literal rather than on a re-typed copy
 * of it, which is how these things drift apart.
 */
export const ROUTEROS_EXPORT_COMMAND = '/export terse show-sensitive=no' as const;

/**
 * Props whose presence with a NON-EMPTY value in a supposedly redacted export
 * means the redaction did not happen — a `sensitive`-capable account, an
 * unexpected firmware behaviour, or somebody who found a way to pass
 * `show-sensitive=yes`.
 *
 * When one of these fires the collection is ABORTED and nothing is stored. Not
 * "stored with a warning": the whole point of R10 is that the secret never
 * reaches the store, and a snapshot we then have to scrub is a snapshot that
 * already existed.
 *
 * The check is on the PROP NAME plus "the value is not the redaction marker".
 * RouterOS emits `password=""` or omits the prop entirely when redacting.
 */
const SENSITIVE_PROPS: readonly string[] = [
  'password', 'secret', 'passphrase', 'private-key', 'pre-shared-key', 'psk',
  'wpa-pre-shared-key', 'wpa2-pre-shared-key', 'authentication-key',
  'encryption-key', 'auth-password', 'enc-password', 'shared-secret',
];

const SENSITIVE_RE = new RegExp(
  `(?:^|[\\s;])(${SENSITIVE_PROPS.join('|')})=(?!""|''|\\s|$)(\\S)`,
  'i',
);

export class SensitiveMaterialError extends Error {
  readonly prop: string;
  constructor(prop: string, deviceId: number) {
    super(
      `Export for device ${deviceId} carries a non-empty '${prop}=' — the redaction did not ` +
        'happen. The snapshot was discarded (R10). Check that the service account is stripped ' +
        "of the RouterOS 'sensitive' policy.",
    );
    this.name = 'SensitiveMaterialError';
    this.prop = prop;
  }
}

/**
 * R10's last gate before the store. Reports the PROP NAME and never the value —
 * an error message is a log line, and a log line is exactly what R10 forbids
 * a secret from reaching.
 */
export function assertNoSensitiveMaterial(raw: string, deviceId: number): void {
  const m = SENSITIVE_RE.exec(raw);
  if (m) throw new SensitiveMaterialError(m[1].toLowerCase(), deviceId);
}

// ============================================================================
// The normaliser registry (fail closed)
// ============================================================================

/**
 * The context frozen by §5.5 of the normalisation study, restated structurally
 * rather than imported from `normalize.service.ts`.
 *
 * The shape is the parser's, field for field, so the late binding below can
 * hand it straight through. Restating it is what keeps the dependency one-way
 * and OPTIONAL — and what keeps the absence of a parser a loud failure instead
 * of an empty document.
 */
export interface NormalizeContextInput {
  /** The device the document will be attributed to. The parser needs it to
   *  fill `NcmDocument.device`, which carries the D5 identity triple. */
  deviceId: number;
  tenantId: number;
  family: DeviceFamily;
  osVersion: string | null;
  /** Already ordered by the frozen §5.1 comparison. The engine must not
   *  re-sort: two sorts is two orders waiting to disagree. */
  rules: NormalizationRule[];
  /** `'<sectionPath>|<prop>' -> value`, from `routeros_defaults`. */
  defaults: Map<string, string>;
  via: TransportKind;
  capturedAt?: string;
  /** §3.4 case 2 — the pairing reference for ordinal assignment. */
  previous?: NcmDocument | null;
}

/** Structurally what §5.5 of the normalisation study froze. Declared as a local
 *  shape rather than imported so this module carries no compile-time dependency
 *  on the parser (see below). */
export interface NormalizeOutput {
  ncm: NcmDocument;
  osVersion: string | null;
  model: string | null;
  serial: string | null;
  traces: NormalizationTrace[];
  unknownProps: Array<{ sectionPath: string; prop: string }>;
  warnings: string[];
}

export type NormalizeFn = (raw: string, ctx: NormalizeContextInput) => NormalizeOutput;

let normalizeImpl: NormalizeFn | null = null;
let autoBindAttempted = false;

/** Called at boot, or by a test that wants a double. The last registration
 *  wins, and an explicit registration always beats the auto-binding below. */
export function registerNormalizer(fn: NormalizeFn): void {
  normalizeImpl = fn;
  autoBindAttempted = true;
}

/** For tests that registered a double and must not leak it into the next one. */
export function clearNormalizer(): void {
  normalizeImpl = null;
  autoBindAttempted = false;
}

/**
 * Late binding to `normalize.service.ts`, ON PURPOSE, through `require` rather
 * than an `import`.
 *
 * The parser is a separate workstream and a separate file. A static import
 * would make this module — and therefore the whole collection path, the
 * snapshot store and the drift engine — fail to compile whenever the parser is
 * mid-edit. A late binding keeps the dependency one-way and OPTIONAL, and the
 * fail-closed default below keeps its absence loud instead of turning it into
 * an empty document.
 */
function autoBind(): NormalizeFn | null {
  if (autoBindAttempted) return normalizeImpl;
  autoBindAttempted = true;
  try {

    const mod = require('./normalize.service') as Record<string, unknown>;
    const fn = mod.normalizeRouterOsExport ?? mod.normalize;
    if (typeof fn === 'function') normalizeImpl = fn as NormalizeFn;
  } catch {
    normalizeImpl = null;
  }
  return normalizeImpl;
}

export function hasNormalizer(): boolean {
  return autoBind() !== null;
}

export class NoNormalizerError extends Error {
  constructor() {
    super(
      'No NCM normaliser is registered. Refusing to build a document: an empty NCM would ' +
        'read, to the diff engine, as a device whose entire configuration vanished.',
    );
    this.name = 'NoNormalizerError';
  }
}

function requireNormalizer(): NormalizeFn {
  const fn = autoBind();
  if (!fn) throw new NoNormalizerError();
  return fn;
}

// ============================================================================
// Loading the normalisation ruleset for one device
// ============================================================================

interface RuleRow {
  id: number;
  uuid: string;
  builtin_key: string | null;
  scope: string;
  scope_id: number | null;
  brand: string | null;
  family: string | null;
  os_min: string | null;
  os_max: string | null;
  name: string;
  description: string;
  rationale: string;
  false_negative: string;
  layer: number;
  kind: string;
  section_path: string | null;
  section_ordered: boolean;
  prop: string | null;
  pattern: string | null;
  replacement: string | null;
  predicate: unknown;
  value: unknown;
  target_path: string | null;
  severity: string | null;
  apply_order: number;
  enabled: boolean;
}

function toRule(r: RuleRow): NormalizationRule {
  return {
    id: Number(r.id),
    uuid: r.uuid,
    builtinKey: r.builtin_key,
    scope: r.scope as NormalizationRule['scope'],
    scopeId: r.scope_id === null ? null : Number(r.scope_id),
    brand: r.brand as NormalizationRule['brand'],
    family: r.family as NormalizationRule['family'],
    osMin: r.os_min,
    osMax: r.os_max,
    name: r.name,
    description: r.description,
    rationale: r.rationale,
    falseNegative: r.false_negative,
    layer: r.layer as NormalizationRule['layer'],
    kind: r.kind as NormalizationRule['kind'],
    sectionPath: r.section_path,
    sectionOrdered: r.section_ordered,
    prop: r.prop,
    pattern: r.pattern,
    replacement: r.replacement,
    predicate: (r.predicate ?? null) as NormalizationRule['predicate'],
    value: r.value ?? null,
    targetPath: r.target_path,
    severity: r.severity as NormalizationRule['severity'],
    applyOrder: Number(r.apply_order),
    enabled: r.enabled,
  };
}

/**
 * The EFFECTIVE rule set for one device, already ordered.
 *
 * The ORDER BY duplicates `compareNormalizationRules()` from the shared
 * package on purpose — the study froze it in SQL and in TypeScript, and the
 * ordering must be identical whichever side sorts. `normalizationEpoch` is
 * computed from this exact list, so a difference between the two would produce
 * an epoch that does not describe what was applied.
 *
 * Scope resolution: `global` always, `brand` on a brand match, `device` on this
 * device, `group` on any group the device belongs to.
 */
export async function loadNormalizationRules(
  deviceId: number,
  tenantId: number,
  family: DeviceFamily | null,
): Promise<NormalizationRule[]> {
  const brand = family ? FAMILY_BRAND[family] : null;

  const rows = await db<RuleRow>('normalization_rules as nr')
    // THE TENANT'S OWN RULES **PLUS THE SHARED LIBRARY**.
    //
    // `tenant_id IS NULL` is the shipped doctrine (N01..N16 and the ~150
    // generated state/sort/default rules), seeded tenant-less by
    // `db/seeds/002_ncm_doctrine.ts` since migration
    // `013_normalization_shared.ts`. The same convention 008 froze for
    // `templates` / `template_partials`.
    //
    // This predicate used to be a bare `.where(tenant_id, tenantId)` against
    // a doctrine seeded to tenant #1, which meant EVERY OTHER TENANT
    // NORMALISED WITH AN EMPTY RULE SET (audit M4/M5, F1). Not a degraded
    // mode: an unnormalised export changes its `ncm_hash` on every
    // collection, so `config_snapshots` gained a row per collect and every
    // drift run reported that churn as findings.
    //
    // NOTE FOR ANY FUTURE EDIT: this must stay a GROUPED `OR`. Written flat
    // it would bind against the `andWhere` chain below and let a rule of
    // ANOTHER tenant through on the `IS NULL` alternative.
    .where((qb) => {
      void qb.where('nr.tenant_id', tenantId).orWhereNull('nr.tenant_id');
    })
    .andWhere('nr.enabled', true)
    .andWhere((qb) => {
      // No orWhere when there is no brand to match: the whereNull above already
      // covers "rule applies to every brand", and a NUL sentinel cannot travel
      // to a PostgreSQL text column (the driver rejects the parameter).
      void qb.whereNull('nr.brand');
      if (brand !== null) void qb.orWhere('nr.brand', brand);
    })
    .andWhere((qb) => {
      void qb.whereNull('nr.family');
      if (family !== null) void qb.orWhere('nr.family', family);
    })
    .andWhere((qb) => {
      void qb
        .where('nr.scope', 'global')
        .orWhere((b) => {
          void b.where('nr.scope', 'brand').whereNotNull('nr.brand');
        })
        .orWhere((b) => {
          void b.where('nr.scope', 'device').andWhere('nr.scope_id', deviceId);
        })
        .orWhere((b) => {
          // `devices.group_id` is a single nullable column (migration 002), not
          // a membership table. Only the DIRECT group matches: inheriting down
          // the `device_groups` tree would silently apply a parent's rule to a
          // device nobody scoped it to, and a normalisation rule is allowed to
          // HIDE a change. Widening this is a deliberate act, not a default.
          void b.where('nr.scope', 'group').whereIn(
            'nr.scope_id',
            db('devices').select('group_id').where('id', deviceId).whereNotNull('group_id'),
          );
        });
    })
    // layer, then scope specificity, then apply_order, then id — §5.1, frozen.
    .orderByRaw(
      "nr.layer ASC, CASE nr.scope WHEN 'global' THEN 0 WHEN 'brand' THEN 1 " +
        "WHEN 'group' THEN 2 ELSE 3 END ASC, nr.apply_order ASC, nr.id ASC",
    )
    .select('nr.*');

  return rows.map(toRule);
}

/**
 * The learned default-value oracle of N09, keyed `'<sectionPath>|<prop>'`.
 *
 * NEVER EXTRAPOLATED ACROSS VERSIONS. The dictionary is indexed by EXACT
 * `os_version` because RouterOS changes which defaults it emits between minor
 * releases (N15); filling a prop with a 7.14 default on a 7.15 box is a
 * fleet-wide false negative — the diff would stop seeing a real change on
 * every device at once. With no `osVersion` the map is empty and
 * `default_fill` simply does not run, which is the safe direction.
 *
 * `conflicting = true` rows are excluded: a default two devices disagree about
 * is not a default, it is a configuration.
 */
export async function loadDefaults(
  family: DeviceFamily | null,
  osVersion: string | null,
): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  if (!family || !osVersion) return out;
  const rows = await db('routeros_defaults')
    .where({ family, os_version: osVersion, conflicting: false })
    .select('section_path', 'prop', 'default_value');
  for (const r of rows as { section_path: string; prop: string; default_value: unknown }[]) {
    const v = r.default_value;
    out.set(
      `${r.section_path}|${r.prop}`,
      typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : JSON.stringify(v),
    );
  }
  return out;
}

// ============================================================================
// The raw read
// ============================================================================

export interface CollectedRaw {
  /** The export EXACTLY as the box produced it, header included. Never
   *  normalised on disk — `config_snapshots.raw_gz` is the recoverable proof
   *  the day a normalisation rule turns out to be wrong (§1). */
  raw: string;
  via: 'ssh' | 'routeros_api';
  /** Facts the API gave us that the redacted export does not state reliably.
   *  This is the whole of "API en complément": it never SUBSTITUTES for the
   *  export, because the API returns counters, `.id`s and computed flags that
   *  are noise source number one (N03-N06). */
  osVersion: string | null;
  model: string | null;
  serial: string | null;
  warnings: string[];
  durationMs: number;
}

interface TransportRow {
  transport: string;
  host: string | null;
  port: number | null;
  username: string | null;
  secret_enc: string | null;
  use_tls: boolean | null;
  tls_fingerprint_sha256: string | null;
  enabled: boolean;
  priority: number;
  params: Record<string, unknown> | null;
}

interface DeviceRow {
  id: number;
  tenant_id: number;
  name: string;
  family: string | null;
  tunnel_ip: string | null;
}

async function loadDevice(deviceId: number, tenantId: number): Promise<DeviceRow> {
  const row = await db<DeviceRow>('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first('id', 'tenant_id', 'name', 'family', 'tunnel_ip');
  // Not "device not found in this tenant": the two answers must be the same
  // string, or the message itself is a cross-tenant existence oracle.
  if (!row) throw new DriverError(`Device ${deviceId} not found`, 'UNKNOWN', { retryable: false });
  return row;
}

async function loadTransports(deviceId: number): Promise<TransportRow[]> {
  return db<TransportRow>('device_transports')
    .where('device_id', deviceId)
    .andWhere('enabled', true)
    .orderBy('priority', 'asc')
    .select(
      'transport', 'host', 'port', 'username', 'secret_enc', 'use_tls',
      'tls_fingerprint_sha256', 'enabled', 'priority', 'params',
    );
}

/**
 * Run the frozen export command over an already-open SSH channel.
 *
 * Split out from the connection so the command, the pty decision, the exit-code
 * handling and the continuation check can all be tested against a double
 * without a router — which is the only way any of this is testable at all,
 * since there is no MikroTik in this environment.
 */
export async function runExport(
  ssh: Pick<SshTransport, 'exec'>,
  opts: { timeoutMs?: number } = {},
): Promise<{ raw: string; warnings: string[] }> {
  const result = await ssh.exec(ROUTEROS_EXPORT_COMMAND, {
    // NEVER a pty. See the header of this file, and N13.
    pty: false,
    timeoutMs: opts.timeoutMs ?? 60_000,
    maxOutputBytes: 16 * 1024 * 1024,
  });

  if (result.code !== null && result.code !== 0) {
    throw new DriverError(
      `'${ROUTEROS_EXPORT_COMMAND}' exited with code ${result.code}`,
      'PROTOCOL_ERROR',
      { transport: 'ssh', retryable: false },
    );
  }

  const raw = result.stdout;
  if (raw.trim().length === 0) {
    // An empty export is NOT an empty router. Treating it as one would hand the
    // diff engine a device whose entire configuration disappeared, and — but
    // for N3 — a plan to recreate it.
    throw new DriverError(
      'export returned no output; refusing to treat that as an empty configuration',
      'PARSE_ERROR',
      { transport: 'ssh', retryable: true },
    );
  }

  const warnings: string[] = [];
  // N13: a `\` at end of line means the box wrapped the output, which means a
  // pty was allocated somewhere. The text is then terminal-width dependent and
  // will produce phantom drift the day the width changes.
  if (/\\\r?\n/.test(raw)) {
    warnings.push(
      'export contains line continuations (\\): a pty was allocated on the export channel — ' +
        'the text is terminal-width dependent (N13)',
    );
  }
  if (result.stderr.trim().length > 0) {
    warnings.push(`export channel wrote to stderr: ${result.stderr.trim().slice(0, 200)}`);
  }
  return { raw, warnings };
}

/** `!trap` = "this menu does not exist here". An answer, not a failure. */
async function optionalRow(
  conn: RouterOsConnection,
  path: string,
): Promise<Record<string, string> | null> {
  try {
    return await conn.queryFirst([path]);
  } catch (err) {
    if (err instanceof RouterOsTrapError) return null;
    return null;
  }
}

/**
 * The API COMPLEMENT — and nothing more.
 *
 * Three facts the redacted export header states inconsistently across RouterOS
 * 6 and 7 (N01), and which we need OUTSIDE the hash: `os_version` and `model`
 * are `config_snapshots` columns precisely because a firmware upgrade must be
 * visible without creating a snapshot (§8.5), and `serial` is one leg of the D5
 * identity triple carried inside the document.
 *
 * Deliberately NOT used to enrich the resources themselves. The API returns
 * counters, `.id`s and computed flags — noise source number one the moment it
 * touches configuration (§1).
 */
async function readApiComplement(
  device: DeviceRow,
  transports: TransportRow[],
): Promise<{ osVersion: string | null; model: string | null; serial: string | null; warning: string | null }> {
  const api = transports.find((t) => t.transport === 'routeros_api');
  const host = api?.host ?? device.tunnel_ip;
  if (!api || !host || !api.username || !api.secret_enc) {
    return { osVersion: null, model: null, serial: null, warning: null };
  }
  let conn: RouterOsConnection | null = null;
  try {
    conn = await createRouterOsConnection({
      host,
      port: api.port ?? undefined,
      tls: api.use_tls === true,
      username: api.username,
      password: decrypt(api.secret_enc),
      expectedFingerprint: api.tls_fingerprint_sha256,
      connectTimeoutMs: 10_000,
      label: `collect:${device.name}`,
    });
    const resource = await optionalRow(conn, '/system/resource/print');
    const board = await optionalRow(conn, '/system/routerboard/print');
    return {
      osVersion: resource?.version ?? null,
      model: resource?.['board-name'] ?? board?.model ?? null,
      serial: board?.['serial-number'] ?? null,
      warning: null,
    };
  } catch (err) {
    // A missing complement is a degraded collection, never a failed one: the
    // export is the source of truth and it already succeeded.
    return {
      osVersion: null,
      model: null,
      serial: null,
      warning: `API complement unavailable: ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    conn?.close();
  }
}

export interface CollectOptions {
  timeoutMs?: number;
  /** Skip the API complement (used by tests and by a device with no API
   *  transport). The export alone is a valid collection. */
  skipApiComplement?: boolean;
}

/**
 * Read the configuration off one device.
 *
 * IDENTITY IS ASSERTED FIRST, on a fresh connection, through the one sanctioned
 * door (`withAssertedDevice`). A snapshot filed against the wrong device is not
 * a cosmetic error: the drift engine will compare it to a template it was never
 * meant to obey, and every finding after that is nonsense with the confidence
 * of a machine behind it.
 */
export async function collectRaw(
  deviceId: number,
  tenantId: number,
  options: CollectOptions = {},
): Promise<CollectedRaw & { assertion: BindingAssertion }> {
  const device = await loadDevice(deviceId, tenantId);
  const transports = await loadTransports(deviceId);

  const ssh = transports.find((t) => t.transport === 'ssh');
  if (!ssh || !ssh.host || !ssh.username) {
    // Honest refusal. The API cannot substitute for `/export`: §1 is explicit
    // that it returns much more than the export (counters, `.id`s, computed
    // flags) and that using it as the source is noise source number one.
    throw new DriverError(
      `device ${deviceId} has no enabled SSH transport; '/export' is the only sanctioned ` +
        'acquisition path and the API is a complement, never a substitute',
      'NO_TRANSPORT',
      { transport: 'ssh', retryable: false },
    );
  }

  return withAssertedDevice(deviceId, async (assertion) => {
    const startedAt = Date.now();
    const warnings: string[] = [];

    const params = (ssh.params ?? {}) as { legacyAlgorithms?: boolean };
    const { raw, warnings: exportWarnings } = await withSsh(
      {
        host: ssh.host as string,
        port: ssh.port ?? 22,
        username: ssh.username as string,
        password: ssh.secret_enc ? decrypt(ssh.secret_enc) : null,
        timeoutMs: options.timeoutMs ?? 30_000,
        legacyAlgorithms: params.legacyAlgorithms === true,
      },
      (channel) => runExport(channel, { timeoutMs: options.timeoutMs }),
    );
    warnings.push(...exportWarnings);

    // R10, before anything is written anywhere.
    assertNoSensitiveMaterial(raw, deviceId);

    let osVersion: string | null = null;
    let model: string | null = null;
    let serial: string | null = null;
    if (!options.skipApiComplement) {
      const complement = await readApiComplement(device, transports);
      osVersion = complement.osVersion;
      model = complement.model;
      serial = complement.serial;
      if (complement.warning) warnings.push(complement.warning);
    }

    return {
      raw,
      via: 'ssh' as const,
      osVersion,
      model,
      serial,
      warnings,
      durationMs: Date.now() - startedAt,
      assertion,
    };
  });
}

// ============================================================================
// The whole L0 -> L3 path
// ============================================================================

export interface CollectAndStoreResult {
  snapshot: StoreSnapshotResult;
  warnings: string[];
  /** N05 of the normalisation study: props the parser saw and does not know.
   *  Surfaced, not swallowed — it is the model's own backlog. */
  unknownProps: Array<{ sectionPath: string; prop: string }>;
  durationMs: number;
}

/**
 * Collect -> normalise -> store, in one call, for one device.
 *
 * The three stages are separate functions so each is testable on its own, and
 * they are joined here so no caller can do the store without the R10 gate or
 * the normalisation without the identity assertion.
 */
export async function collectAndStore(
  deviceId: number,
  tenantId: number,
  options: CollectOptions & { source?: string } = {},
): Promise<CollectAndStoreResult> {
  const normalize = requireNormalizer();
  const collected = await collectRaw(deviceId, tenantId, options);

  const device = await loadDevice(deviceId, tenantId);
  const family = (device.family ?? null) as DeviceFamily | null;
  if (!family) {
    throw new DriverError(
      `device ${deviceId} has no family; the normalisation ruleset cannot be resolved`,
      'UNKNOWN',
      { retryable: false },
    );
  }

  const [rules, defaults, previous] = await Promise.all([
    loadNormalizationRules(deviceId, tenantId, family),
    loadDefaults(family, collected.osVersion),
    // §3.4 case 2: the parser assigns ordinals by pairing with the PREVIOUS
    // document. `storeSnapshot` re-runs the same reconciliation at the store
    // boundary — idempotent, and the guarantee does not then depend on which
    // parser produced the document.
    latestDocument(deviceId),
  ]);

  const result = normalize(collected.raw, {
    deviceId,
    tenantId,
    family,
    osVersion: collected.osVersion,
    rules,
    defaults,
    via: 'ssh',
    previous: previous?.doc ?? null,
  });

  const snapshot = await storeSnapshot({
    deviceId,
    tenantId,
    source: (options.source as StoreSnapshotResult['source']) ?? 'ssh',
    raw: collected.raw,
    doc: result.ncm as NcmDocument,
    osVersion: collected.osVersion ?? result.osVersion,
    model: collected.model ?? result.model,
    normalizationTraces: result.traces,
  });

  if (collected.warnings.length > 0 || result.warnings.length > 0) {
    logger.warn(
      { deviceId, warnings: [...collected.warnings, ...result.warnings] },
      'Configuration collected with warnings',
    );
  }

  return {
    snapshot,
    warnings: [...collected.warnings, ...result.warnings],
    unknownProps: result.unknownProps,
    durationMs: collected.durationMs,
  };
}
