// ============================================================================
// ObliWAN — site intents in the database (M11 — K4)
// ============================================================================
//
// The persistence half of the Intent Compiler: CRUD on `site_intents`, and the
// two tables that record what the compiler produced and what it refused.
//
// ┌─ TENANT SCOPING ──────────────────────────────────────────────────────────┐
// │ `intent_compilations` and `intent_capability_gaps` carry NO tenant column │
// │ (migration 016, decision 2). Every read here therefore joins              │
// │ `site_intents` and filters on `tenant_id`, and every write goes through   │
// │ an intent this tenant owns. The database trigger closes the write path;   │
// │ these joins close the read path; neither replaces the other.              │
// │                                                                          │
// │ An id belonging to another customer is a 404, never a 403 — a 403         │
// │ confirms the row exists.                                                  │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ NOTHING HERE TOUCHES AN EQUIPMENT ───────────────────────────────────────┐
// │ Compiling reads `devices` and `device_capabilities` for the family and    │
// │ the probed overrides, and it writes two tables. It opens no transport,    │
// │ decrypts no credential and dials nothing. Applying a compiled artefact is │
// │ M6's job and happens inside a `change_jobs` row (D3).                     │
// └───────────────────────────────────────────────────────────────────────────┘

import type { Knex } from 'knex';
import type { DeviceFamily, ObservedCapabilityOverrides } from '@obliwan/shared';
import type { CapabilityGap, SiteIntentDocument } from '@obliwan/shared/dist/intent';
import {
  INTENT_SCHEMA_VERSION,
  SiteIntentDocument as SiteIntentSchema,
} from '@obliwan/shared/dist/intent';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { capabilityCheck } from './capabilityCheck';
import { compileIntent, type IntentCompilation } from './compiler.service';

// ============================================================================
// Rows
// ============================================================================

export interface SiteIntentRow {
  id: number;
  uuid: string;
  tenantId: number;
  siteId: number | null;
  slug: string;
  name: string;
  description: string | null;
  schemaVersion: number;
  revision: number;
  isPublished: boolean;
  createdBy: number | null;
  createdAt: string;
  updatedAt: string;
  body: SiteIntentDocument;
}

interface RawIntent {
  id: number;
  uuid: string;
  tenant_id: number;
  site_id: number | null;
  slug: string;
  name: string;
  description: string | null;
  schema_version: number;
  revision: number;
  is_published: boolean;
  created_by: number | null;
  created_at: Date | string;
  updated_at: Date | string;
  body: unknown;
}

function toRow(raw: RawIntent): SiteIntentRow {
  const parsed = SiteIntentSchema.safeParse(raw.body);
  if (!parsed.success) {
    // A stored document that no longer validates is not something to paper
    // over: compiling it would produce an artefact from a shape nothing
    // checked. It is surfaced as a 500 because it means the schema moved
    // without a migration of the rows.
    throw new Error(
      `site_intents.id=${raw.id} does not satisfy the intent schema — ` +
        `it was written under schema v${raw.schema_version} and the server reads v${INTENT_SCHEMA_VERSION}`,
    );
  }
  return {
    id: raw.id,
    uuid: raw.uuid,
    tenantId: raw.tenant_id,
    siteId: raw.site_id,
    slug: raw.slug,
    name: raw.name,
    description: raw.description,
    schemaVersion: raw.schema_version,
    revision: raw.revision,
    isPublished: raw.is_published,
    createdBy: raw.created_by,
    createdAt: new Date(raw.created_at).toISOString(),
    updatedAt: new Date(raw.updated_at).toISOString(),
    body: parsed.data,
  };
}

// ============================================================================
// CRUD
// ============================================================================

export async function listIntents(tenantId: number): Promise<SiteIntentRow[]> {
  const rows = await db<RawIntent>('site_intents')
    .where({ tenant_id: tenantId })
    .orderBy('name', 'asc');
  return rows.map(toRow);
}

export async function getIntent(tenantId: number, id: number): Promise<SiteIntentRow> {
  const raw = await db<RawIntent>('site_intents').where({ id, tenant_id: tenantId }).first();
  if (!raw) throw new AppError(404, 'Intent not found');
  return toRow(raw);
}

export interface IntentInput {
  siteId?: number | null;
  body: SiteIntentDocument;
}

/**
 * The update input, and the one field whose THREE states matter.
 *
 * `siteId` is `number | null | undefined` and each value means a different
 * thing, which is exactly what the previous version threw away:
 *
 *   number     -> file this intent under that site (checked for ownership)
 *   null       -> UNFILE it, said out loud by whoever sent the request
 *   undefined  -> the field was not in the PATCH; leave `site_id` alone
 *
 * It used to collapse to `input.siteId ?? null`, so a `PATCH` that only fixed a
 * typo in a comment silently detached the intent from its site: the partial
 * index `site_intents_tenant_site_idx` stopped seeing it and the "intents of
 * this site" screen lost it, with no error and no signal but the `siteId` of
 * the response. The line immediately below it already did the right thing for
 * `is_published` (`input.isPublished ?? existing.isPublished`) — the asymmetry
 * between the two was the whole defect.
 *
 * A separate type rather than `IntentInput & …`: on CREATE there is no previous
 * value, so "absent" and "null" really are the same thing there and the
 * distinction should not be offered.
 */
export interface IntentUpdateInput {
  siteId?: number | null;
  body: SiteIntentDocument;
  isPublished?: boolean;
}

export async function createIntent(
  tenantId: number,
  userId: number | null,
  input: IntentInput,
): Promise<SiteIntentRow> {
  await assertSiteBelongsToTenant(tenantId, input.siteId ?? null);
  const [raw] = await db<RawIntent>('site_intents')
    .insert({
      tenant_id: tenantId,
      site_id: input.siteId ?? null,
      slug: input.body.slug,
      name: input.body.name,
      description: input.body.description,
      schema_version: input.body.schemaVersion,
      body: JSON.stringify(input.body) as unknown as RawIntent['body'],
      revision: 1,
      created_by: userId,
    })
    .returning('*');
  return toRow(raw);
}

/**
 * Every edit bumps `revision`. The number travels onto each compilation, so an
 * artefact can always be traced back to the exact text it came from — including
 * after the intent has been edited three times since.
 */
export async function updateIntent(
  tenantId: number,
  id: number,
  input: IntentUpdateInput,
): Promise<SiteIntentRow> {
  const existing = await getIntent(tenantId, id);
  // Only when the caller actually named a site. Re-validating the site the row
  // already carries would turn "the site was deleted last month" into a 404 on
  // an edit that never mentioned a site.
  if (input.siteId !== undefined) await assertSiteBelongsToTenant(tenantId, input.siteId);
  const [raw] = await db<RawIntent>('site_intents')
    .where({ id: existing.id, tenant_id: tenantId })
    .update({
      site_id: input.siteId === undefined ? existing.siteId : input.siteId,
      slug: input.body.slug,
      name: input.body.name,
      description: input.body.description,
      schema_version: input.body.schemaVersion,
      body: JSON.stringify(input.body) as unknown as RawIntent['body'],
      revision: existing.revision + 1,
      is_published: input.isPublished ?? existing.isPublished,
      updated_at: new Date(),
    })
    .returning('*');
  return toRow(raw);
}

export async function deleteIntent(tenantId: number, id: number): Promise<void> {
  const deleted = await db('site_intents').where({ id, tenant_id: tenantId }).delete();
  if (deleted === 0) throw new AppError(404, 'Intent not found');
}

async function assertSiteBelongsToTenant(tenantId: number, siteId: number | null): Promise<void> {
  if (siteId === null) return;
  const site = await db('sites').where({ id: siteId, tenant_id: tenantId }).first('id');
  if (!site) throw new AppError(404, 'Site not found');
}

// ============================================================================
// Targets
// ============================================================================

export interface CompileRequest {
  /** Devices of this tenant to compile for. */
  deviceIds?: number[];
  /** Families to compile for with no device in hand — the "which of my brands
   *  could take this site" screen. */
  families?: DeviceFamily[];
}

interface DeviceTarget {
  deviceId: number;
  family: DeviceFamily;
  model: string | null;
  serial: string | null;
  systemIdentity: string | null;
  pppUsername: string | null;
  osVersion: string | null;
  observedOverrides: ObservedCapabilityOverrides | null;
}

async function loadDeviceTargets(tenantId: number, ids: number[]): Promise<DeviceTarget[]> {
  if (ids.length === 0) return [];
  const rows = await db('devices as d')
    .leftJoin('device_capabilities as dc', 'dc.device_id', 'd.id')
    .where('d.tenant_id', tenantId)
    .whereIn('d.id', ids)
    .select(
      'd.id',
      'd.family',
      'd.model',
      'd.serial',
      'd.os_version',
      'd.system_identity',
      'd.ppp_username',
      'dc.observed_overrides',
    );
  const found = new Set(rows.map((r) => Number(r.id)));
  const missing = ids.filter((id) => !found.has(id));
  if (missing.length > 0) {
    // 404 rather than a silent partial result: a screen that quietly dropped
    // one of the five devices the operator selected would show four green rows
    // and no reason to look for the fifth.
    throw new AppError(404, `Device not found: ${missing.join(', ')}`);
  }
  return rows.map((r) => ({
    deviceId: Number(r.id),
    family: r.family as DeviceFamily,
    model: r.model ?? null,
    serial: r.serial ?? null,
    systemIdentity: r.system_identity ?? null,
    pppUsername: r.ppp_username ?? null,
    osVersion: r.os_version ?? null,
    observedOverrides: (r.observed_overrides as ObservedCapabilityOverrides | null) ?? null,
  }));
}

// ============================================================================
// Compile and store
// ============================================================================

export interface CompiledTargetResult {
  family: DeviceFamily;
  deviceId: number | null;
  ok: boolean;
  ncmHash: string | null;
  artifactFormat: string | null;
  artifactSha256: string | null;
  features: string[];
  warnings: string[];
  gaps: CapabilityGap[];
  /** Present only when the failure was NOT a capability gap. */
  error: string | null;
}

/**
 * Compile one intent for every requested target, and record both outcomes.
 *
 * A capability refusal is a RESULT, not an exception: a request for four
 * brands where three cannot do the job must answer with four rows, not with a
 * 500 that hides the one brand that can.
 */
export async function compileAndStore(
  tenantId: number,
  userId: number | null,
  intentId: number,
  request: CompileRequest,
): Promise<{ intent: SiteIntentRow; results: CompiledTargetResult[] }> {
  const intent = await getIntent(tenantId, intentId);
  const deviceTargets = await loadDeviceTargets(tenantId, request.deviceIds ?? []);
  const familyTargets = request.families ?? [];

  if (deviceTargets.length === 0 && familyTargets.length === 0) {
    throw new AppError(400, 'Give at least one deviceId or one family to compile for');
  }

  const results: CompiledTargetResult[] = [];

  await db.transaction(async (trx) => {
    for (const target of deviceTargets) {
      results.push(
        await compileOne(trx, intent, userId, target.family, target.deviceId, {
          deviceId: target.deviceId,
          tenantId,
          family: target.family,
          model: target.model,
          serial: target.serial,
          systemIdentity: target.systemIdentity,
          pppUsername: target.pppUsername,
          osVersion: target.osVersion,
          observedOverrides: target.observedOverrides,
        }),
      );
    }
    for (const family of familyTargets) {
      results.push(
        await compileOne(trx, intent, userId, family, null, {
          // A family-only compilation still needs a device reference inside the
          // NCM envelope (`NcmDeviceRef.deviceId` is a positive integer). The
          // intent's own id is used, and the row is stored with
          // `device_id = NULL` so nothing can mistake it for a real device.
          deviceId: intent.id,
          tenantId,
          family,
        }),
      );
    }
  });

  return { intent, results };
}

async function compileOne(
  trx: Knex.Transaction,
  intent: SiteIntentRow,
  userId: number | null,
  family: DeviceFamily,
  deviceId: number | null,
  target: Parameters<typeof compileIntent>[1],
): Promise<CompiledTargetResult> {
  // The gap set is the CURRENT answer, not a history: a feature that stopped
  // failing because the intent was edited or a brand profile corrected must
  // disappear from the screen, not linger as a row nobody dares delete.
  await clearGaps(trx, intent.id, deviceId, family);

  let compilation: IntentCompilation | null = null;
  let error: string | null = null;
  const verdict = capabilityCheck(intent.body, family, target.observedOverrides);

  if (verdict.ok) {
    try {
      compilation = compileIntent(intent.body, target);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }
  } else {
    await recordGaps(trx, intent.id, deviceId, verdict.gaps);
  }

  if (compilation) {
    await storeCompilation(trx, intent, userId, deviceId, compilation);
  }

  return {
    family,
    deviceId,
    ok: compilation !== null,
    ncmHash: compilation?.ncmHash ?? null,
    artifactFormat: compilation?.artifact.format ?? null,
    artifactSha256: compilation?.artifact.sha256 ?? null,
    features: verdict.required.map((u) => u.feature),
    warnings: compilation?.warnings ?? [],
    gaps: verdict.gaps,
    error,
  };
}

async function clearGaps(
  trx: Knex.Transaction,
  intentId: number,
  deviceId: number | null,
  family: DeviceFamily,
): Promise<void> {
  const q = trx('intent_capability_gaps').where({ intent_id: intentId });
  if (deviceId === null) await q.whereNull('device_id').andWhere({ family }).delete();
  else await q.where({ device_id: deviceId }).delete();
}

async function recordGaps(
  trx: Knex.Transaction,
  intentId: number,
  deviceId: number | null,
  gaps: CapabilityGap[],
): Promise<void> {
  if (gaps.length === 0) return;
  // ONE row per (target, feature) — that is what the unique indexes of
  // migration 016 enforce, and it is the right shape: a screen listing the same
  // capability twice for one brand, once because the family cannot and once
  // because a flag is false, tells the reader nothing extra and makes the
  // "which capability blocks the most sites" count wrong.
  //
  // `capabilityCheck` may legitimately produce two entries for one feature the
  // day a feature requires two `DeviceCapabilities` flags. The FIRST is kept:
  // `capabilityCheck` emits the family verdict before any driver verdict, so
  // the surviving row is always the most fundamental reason.
  const seen = new Set<string>();
  const unique = gaps.filter((gap) => {
    if (seen.has(gap.feature)) return false;
    seen.add(gap.feature);
    return true;
  });
  await trx('intent_capability_gaps').insert(
    unique.map((gap) => ({
      intent_id: intentId,
      device_id: deviceId,
      family: gap.family,
      brand: gap.brand,
      feature: gap.feature,
      reason: gap.reason,
      capability_flag: gap.capabilityFlag,
      intent_path: gap.intentPath.slice(0, 120),
      note: gap.note,
    })),
  );
}

/**
 * Idempotent per (target, ncm_hash). Recompiling an unchanged intent bumps
 * `compiled_at` instead of growing the table — the same shape, and the same
 * reason, as `policy_results`' upsert in M9. Two DIFFERENT hashes are two rows
 * on purpose: that is the history of what this site was asked to be.
 *
 * Written as raw SQL because the uniqueness is carried by two PARTIAL indexes,
 * and inferring a partial index in `ON CONFLICT` requires repeating its
 * predicate — which the query builder cannot express.
 */
async function storeCompilation(
  trx: Knex.Transaction,
  intent: SiteIntentRow,
  userId: number | null,
  deviceId: number | null,
  compilation: IntentCompilation,
): Promise<void> {
  const values = [
    intent.id,
    deviceId,
    compilation.family,
    compilation.brand,
    intent.revision,
    compilation.compilerVersion,
    JSON.stringify(compilation.document),
    compilation.ncmHash,
    compilation.artifact.format,
    compilation.artifact.sha256,
    compilation.artifact.body,
    JSON.stringify(compilation.verdict.required.map((u) => u.feature)),
    JSON.stringify(compilation.warnings),
    userId,
  ];
  const conflict =
    deviceId === null
      ? '(intent_id, family, ncm_hash) WHERE device_id IS NULL'
      : '(intent_id, device_id, ncm_hash) WHERE device_id IS NOT NULL';

  await trx.raw(
    `INSERT INTO intent_compilations
       (intent_id, device_id, family, brand, intent_revision, compiler_version,
        ncm, ncm_hash, artifact_format, artifact_sha256, artifact, features, warnings, compiled_by)
     VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?)
     ON CONFLICT ${conflict}
     DO UPDATE SET
       intent_revision = EXCLUDED.intent_revision,
       compiler_version = EXCLUDED.compiler_version,
       artifact = EXCLUDED.artifact,
       artifact_sha256 = EXCLUDED.artifact_sha256,
       features = EXCLUDED.features,
       warnings = EXCLUDED.warnings,
       compiled_by = EXCLUDED.compiled_by,
       compiled_at = now()`,
    values,
  );
}

// ============================================================================
// Reads
// ============================================================================

export interface CompilationRow {
  id: string;
  intentId: number;
  deviceId: number | null;
  family: string;
  brand: string;
  intentRevision: number;
  compilerVersion: number;
  ncmHash: string;
  artifactFormat: string;
  artifactSha256: string;
  features: string[];
  warnings: string[];
  compiledAt: string;
  /** Only on the single-compilation read: these two are the large columns. */
  artifact?: string;
  ncm?: unknown;
}

/** Every compilation of one intent. The artefact and the NCM are NOT returned
 *  here: a list screen does not need two large documents per row, and shipping
 *  them by default is how a list endpoint becomes a timeout. */
export async function listCompilations(
  tenantId: number,
  intentId: number,
): Promise<CompilationRow[]> {
  await getIntent(tenantId, intentId); // 404s on another tenant's id
  const rows = await db('intent_compilations as c')
    .join('site_intents as i', 'i.id', 'c.intent_id')
    .where('i.tenant_id', tenantId)
    .andWhere('c.intent_id', intentId)
    .orderBy('c.compiled_at', 'desc')
    .select(
      'c.id', 'c.intent_id', 'c.device_id', 'c.family', 'c.brand', 'c.intent_revision',
      'c.compiler_version', 'c.ncm_hash', 'c.artifact_format', 'c.artifact_sha256',
      'c.features', 'c.warnings', 'c.compiled_at',
    );
  return rows.map(mapCompilation);
}

/** One compilation, with its artefact and its desired NCM. */
export async function getCompilation(
  tenantId: number,
  intentId: number,
  compilationId: string,
): Promise<CompilationRow> {
  const row = await db('intent_compilations as c')
    .join('site_intents as i', 'i.id', 'c.intent_id')
    .where('i.tenant_id', tenantId)
    .andWhere('c.intent_id', intentId)
    .andWhere('c.id', compilationId)
    .first(
      'c.id', 'c.intent_id', 'c.device_id', 'c.family', 'c.brand', 'c.intent_revision',
      'c.compiler_version', 'c.ncm_hash', 'c.artifact_format', 'c.artifact_sha256',
      'c.features', 'c.warnings', 'c.compiled_at', 'c.artifact', 'c.ncm',
    );
  if (!row) throw new AppError(404, 'Compilation not found');
  return { ...mapCompilation(row), artifact: row.artifact as string, ncm: row.ncm };
}

function mapCompilation(row: Record<string, unknown>): CompilationRow {
  return {
    id: String(row.id),
    intentId: Number(row.intent_id),
    deviceId: row.device_id === null ? null : Number(row.device_id),
    family: String(row.family),
    brand: String(row.brand),
    intentRevision: Number(row.intent_revision),
    compilerVersion: Number(row.compiler_version),
    ncmHash: String(row.ncm_hash),
    artifactFormat: String(row.artifact_format),
    artifactSha256: String(row.artifact_sha256),
    features: (row.features as string[] | null) ?? [],
    warnings: (row.warnings as string[] | null) ?? [],
    compiledAt: new Date(row.compiled_at as string).toISOString(),
  };
}

export interface GapRow {
  id: string;
  deviceId: number | null;
  family: string;
  brand: string;
  feature: string;
  reason: string;
  capabilityFlag: string | null;
  intentPath: string;
  note: string | null;
  detectedAt: string;
}

/** Why this site cannot be built on those boxes. The answer the milestone
 *  exists to give, which is why it is a table and not a log line. */
export async function listGaps(tenantId: number, intentId: number): Promise<GapRow[]> {
  await getIntent(tenantId, intentId);
  const rows = await db('intent_capability_gaps as g')
    .join('site_intents as i', 'i.id', 'g.intent_id')
    .where('i.tenant_id', tenantId)
    .andWhere('g.intent_id', intentId)
    .orderBy(['g.family', 'g.feature'])
    .select(
      'g.id', 'g.device_id', 'g.family', 'g.brand', 'g.feature', 'g.reason',
      'g.capability_flag', 'g.intent_path', 'g.note', 'g.detected_at',
    );
  return rows.map((row) => ({
    id: String(row.id),
    deviceId: row.device_id === null ? null : Number(row.device_id),
    family: String(row.family),
    brand: String(row.brand),
    feature: String(row.feature),
    reason: String(row.reason),
    capabilityFlag: row.capability_flag ?? null,
    intentPath: String(row.intent_path),
    note: row.note ?? null,
    detectedAt: new Date(row.detected_at as string).toISOString(),
  }));
}
