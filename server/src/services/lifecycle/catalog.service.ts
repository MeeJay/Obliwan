/**
 * ObliWAN F8 — the end-of-life catalogue: read, import, delete.
 *
 * ┌─ THIS TABLE HAS NO `tenant_id`, AND THAT IS THE WHOLE SECURITY STORY ─────┐
 * │ "The SonicWall TZ215 is retired" is a fact about SonicWall, not about a   │
 * │ customer, so migration 027 stores it once (decision 2). The consequence   │
 * │ is that ONE WRITE HERE CHANGES WHAT EVERY TENANT IS TOLD, and therefore   │
 * │ the write cannot sit behind a tenant-scoped capability.                   │
 * │                                                                          │
 * │ F5 shipped exactly that bug on `ip_asn_ranges`: the import was guarded by │
 * │ SETTINGS_MANAGE, which `TENANT_ROLE_CAPABILITIES.admin` grants to the     │
 * │ admin of ANY tenant, so one customer's admin rewrote every other          │
 * │ customer's attribution. The same shape here would let customer B's admin  │
 * │ declare customer A's whole fleet end-of-life, or — worse and quieter —    │
 * │ insert a benign row that MASKS a real end-of-support (a more specific     │
 * │ `exact` entry beats a `prefix` one, so a single row can flip a fleet from │
 * │ `end_of_support` to `unknown`).                                           │
 * │                                                                          │
 * │ Every mutating export in this file is therefore reached only through      │
 * │ `requireRole('admin')` — the PLATFORM role read from `users.role` — and   │
 * │ that guard is on the ROUTE, upstream of every branch in the handler.      │
 * │ See `routes/lifecycle.routes.ts`.                                         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2): there is no credential within reach of this module. It reads
 * and writes vendor product names, calendar dates and citation URLs.
 *
 * D3: nothing here touches an equipment. F8 does not open a session, does not
 * use the transport pool and sends no command — it reads `devices.model`,
 * `devices.os_version` and `devices.family`, which M2 already collected, out of
 * our own Postgres.
 */

import type { Knex } from 'knex';
import {
  LifecycleCatalogError,
  firmwareCatalogEntrySchema,
  modelCatalogEntrySchema,
  normalizeModelKey,
  toIsoDate,
  validateFirmwareEntry,
  validateModelEntry,
  type FirmwareCatalogEntry,
  type FirmwareCatalogEntryInput,
  type LifecycleCatalog,
  type LifecycleImportKind,
  type LifecycleSourceKind,
  type ModelCatalogEntry,
  type ModelCatalogEntryInput,
} from '@obliwan/shared/dist/lifecycle';
import type { DeviceBrand, DeviceFamily } from '@obliwan/shared/dist/device';
import { db } from '../../db';

// ============================================================================
// Row shapes and mapping
// ============================================================================

interface ModelRow {
  id: string | number;
  brand: DeviceBrand;
  model_pattern: string;
  match_mode: 'exact' | 'prefix';
  model_label: string;
  end_of_sale: Date | string | null;
  end_of_software_support: Date | string | null;
  end_of_support: Date | string | null;
  declared_status: 'end_of_sale' | 'end_of_support' | 'end_of_life' | null;
  replacement: string | null;
  source_kind: LifecycleSourceKind;
  source: string;
  source_url: string | null;
  verified_at: Date | string;
  note: string | null;
}

interface FirmwareRow {
  id: string | number;
  brand: DeviceBrand;
  family: DeviceFamily | null;
  branch: string;
  branch_label: string;
  min_supported_version: string | null;
  end_of_support: Date | string | null;
  declared_status: 'end_of_sale' | 'end_of_support' | 'end_of_life' | null;
  source_kind: LifecycleSourceKind;
  source: string;
  source_url: string | null;
  verified_at: Date | string;
  note: string | null;
}

/**
 * `date` columns come back from `pg` as a JS `Date` at local midnight, or as a
 * string depending on the parser configuration. Both are funnelled through
 * `toIsoDate` — the SHARED converter, so the day a boundary is read as and the
 * day `serverToday()` compares it against can never be produced by two
 * different rules.
 */
function toDateString(value: Date | string | null): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value.slice(0, 10);
  return toIsoDate(value);
}

function toModelEntry(r: ModelRow): ModelCatalogEntry {
  return {
    id: Number(r.id),
    brand: r.brand,
    modelPattern: r.model_pattern,
    matchMode: r.match_mode,
    modelLabel: r.model_label,
    endOfSale: toDateString(r.end_of_sale),
    endOfSoftwareSupport: toDateString(r.end_of_software_support),
    endOfSupport: toDateString(r.end_of_support),
    declaredStatus: r.declared_status,
    replacement: r.replacement,
    sourceKind: r.source_kind,
    source: r.source,
    sourceUrl: r.source_url,
    verifiedAt: toDateString(r.verified_at) as string,
    note: r.note,
  };
}

function toFirmwareEntry(r: FirmwareRow): FirmwareCatalogEntry {
  return {
    id: Number(r.id),
    brand: r.brand,
    family: r.family,
    branch: r.branch,
    branchLabel: r.branch_label,
    minSupportedVersion: r.min_supported_version,
    endOfSupport: toDateString(r.end_of_support),
    declaredStatus: r.declared_status,
    sourceKind: r.source_kind,
    source: r.source,
    sourceUrl: r.source_url,
    verifiedAt: toDateString(r.verified_at) as string,
    note: r.note,
  };
}

const MODEL_COLUMNS = [
  'id', 'brand', 'model_pattern', 'match_mode', 'model_label', 'end_of_sale',
  'end_of_software_support', 'end_of_support', 'declared_status', 'replacement',
  'source_kind', 'source', 'source_url', 'verified_at', 'note',
];
const FIRMWARE_COLUMNS = [
  'id', 'brand', 'family', 'branch', 'branch_label', 'min_supported_version',
  'end_of_support', 'declared_status', 'source_kind', 'source', 'source_url',
  'verified_at', 'note',
];

// ============================================================================
// The cache
//
// The catalogue is small (hundreds of rows), read on EVERY inventory request,
// and changes only when a platform admin imports. Re-reading both tables per
// request is two round trips per page load for data that is identical between
// them. The TTL is short and every mutation clears it, so an import is visible
// on the next request rather than up to a minute later.
//
// It is a GLOBAL cache and that is correct here precisely because the tables
// are global — there is no tenant datum in it. A cache keyed by nothing would
// be a cross-tenant leak in any of the other services in this codebase; here
// it is the same rows for everyone by construction (migration 027, decision 2).
// ============================================================================

const CATALOG_TTL_MS = 30_000;
let cached: { at: number; catalog: LifecycleCatalog } | null = null;

/** Drop the memoised catalogue. Called by every mutation in this file so an
 *  import is effective immediately. */
export function clearLifecycleCatalogCache(): void {
  cached = null;
}

/**
 * Both halves of the catalogue. Global by design — see the header.
 *
 * No transaction parameter and no cache-bypass parameter: nothing calls this
 * with either, and an option that exists for a caller who does not exist is a
 * branch nobody tests. `clearLifecycleCatalogCache()` is the whole story, and
 * every mutation in this file calls it.
 */
export async function getLifecycleCatalog(): Promise<LifecycleCatalog> {
  if (cached && Date.now() - cached.at < CATALOG_TTL_MS) return cached.catalog;

  const [modelRows, firmwareRows] = await Promise.all([
    db('lifecycle_models').select<ModelRow[]>(MODEL_COLUMNS).orderBy('id', 'asc'),
    db('lifecycle_firmware').select<FirmwareRow[]>(FIRMWARE_COLUMNS).orderBy('id', 'asc'),
  ]);
  const catalog: LifecycleCatalog = {
    models: modelRows.map(toModelEntry),
    firmware: firmwareRows.map(toFirmwareEntry),
  };
  cached = { at: Date.now(), catalog };
  return catalog;
}

// ============================================================================
// Import
// ============================================================================

export interface CatalogImportResult {
  importId: number;
  kind: LifecycleImportKind;
  label: string;
  rowsLoaded: number;
  rowsRejected: number;
  /** One line per refused row, with its index, so a 300-row dataset does not
   *  fail as a single opaque "invalid". */
  rejections: Array<{ index: number; reason: string }>;
}

/**
 * Validate a batch WITHOUT touching the database.
 *
 * Split out from the write on purpose: the rejection list is the useful half of
 * an import, and it must be identical whether the caller is importing for real
 * or asking "what would this do". Both callers below go through it, so there is
 * no second, drifting copy of the rules.
 */
function validateBatch<I, E>(
  raw: unknown[],
  parse: (value: unknown) => I,
  check: (input: I) => void,
  build: (input: I) => E,
): { accepted: Array<{ index: number; row: E }>; rejections: Array<{ index: number; reason: string }> } {
  const accepted: Array<{ index: number; row: E }> = [];
  const rejections: Array<{ index: number; reason: string }> = [];
  raw.forEach((value, index) => {
    try {
      const input = parse(value);
      check(input);
      // The index of the row IN THE CALLER'S ARRAY travels with it, so a
      // rejection raised later by Postgres names the same row the caller sent
      // rather than a position in some filtered intermediate list.
      accepted.push({ index, row: build(input) });
    } catch (err) {
      rejections.push({
        index,
        reason: err instanceof Error ? err.message : 'invalid entry',
      });
    }
  });
  return { accepted, rejections };
}

function parseModel(value: unknown): ModelCatalogEntryInput {
  const r = modelCatalogEntrySchema.safeParse(value);
  if (!r.success) {
    throw new LifecycleCatalogError(
      r.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; '),
    );
  }
  return r.data;
}

function parseFirmware(value: unknown): FirmwareCatalogEntryInput {
  const r = firmwareCatalogEntrySchema.safeParse(value);
  if (!r.success) {
    throw new LifecycleCatalogError(
      r.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; '),
    );
  }
  return r.data;
}

/**
 * Load model entries.
 *
 * PLATFORM ADMIN ONLY (`requireRole('admin')` on the route) — see the header.
 *
 * `sourceKind` is forced to `import`: a caller does not get to stamp its rows
 * `builtin` and make them look like the seeded, reviewed set. That is a
 * caller-driven parameter that would change how a human weighs a claim, which
 * is the same class of mistake as a caller-driven verdict input.
 *
 * Upsert on the natural key (brand, model_pattern, match_mode), which is a
 * real unique index (migration 027) with no nullable column in it. Re-importing
 * a corrected dataset therefore CORRECTS rows instead of duplicating them, and
 * the duplicate that would make `matchModelEntry` non-deterministic is
 * unrepresentable.
 */
export async function importModelEntries(
  entries: unknown[],
  label: string,
  userId: number | null,
): Promise<CatalogImportResult> {
  const { accepted, rejections } = validateBatch(
    entries,
    parseModel,
    validateModelEntry,
    (input) => ({
      brand: input.brand,
      // Normalised HERE, once, with the same function that normalises
      // `devices.model` at read time. Migration 027's CHECK refuses anything
      // that skipped this step.
      model_pattern: normalizeModelKey(input.model) as string,
      match_mode: input.matchMode ?? 'exact',
      model_label: input.modelLabel,
      end_of_sale: input.endOfSale ?? null,
      end_of_software_support: input.endOfSoftwareSupport ?? null,
      end_of_support: input.endOfSupport ?? null,
      declared_status: input.declaredStatus ?? null,
      replacement: input.replacement ?? null,
      source_kind: 'import' as const,
      source: input.source,
      source_url: input.sourceUrl ?? null,
      verified_at: input.verifiedAt,
      note: input.note ?? null,
      updated_at: db.fn.now(),
    }),
  );

  return writeBatch('model', 'lifecycle_models', ['brand', 'model_pattern', 'match_mode'],
    accepted, rejections, label, userId);
}

/**
 * Load firmware-branch entries. PLATFORM ADMIN ONLY.
 *
 * The conflict target here is NOT a plain unique constraint: `family` is
 * nullable, so migration 027 has TWO partial unique indexes. Postgres resolves
 * `ON CONFLICT (brand, family, branch)` against the partial index only if the
 * statement carries a matching `WHERE` clause, so the two shapes are written as
 * two separate statements — see `writeBatch`.
 */
export async function importFirmwareEntries(
  entries: unknown[],
  label: string,
  userId: number | null,
): Promise<CatalogImportResult> {
  const { accepted, rejections } = validateBatch(
    entries,
    parseFirmware,
    validateFirmwareEntry,
    (input) => ({
      brand: input.brand,
      family: input.family ?? null,
      branch: input.branch,
      branch_label: input.branchLabel,
      min_supported_version: input.minSupportedVersion ?? null,
      end_of_support: input.endOfSupport ?? null,
      declared_status: input.declaredStatus ?? null,
      source_kind: 'import' as const,
      source: input.source,
      source_url: input.sourceUrl ?? null,
      verified_at: input.verifiedAt,
      note: input.note ?? null,
      updated_at: db.fn.now(),
    }),
  );

  return writeBatch('firmware', 'lifecycle_firmware', ['brand', 'family', 'branch'],
    accepted, rejections, label, userId);
}

/**
 * One transaction: the rows, then the journal entry.
 *
 * The journal is written INSIDE the same transaction as the rows. An import
 * that changed the catalogue without leaving a record of who changed it is
 * exactly the state that makes "why does this screen say the customer's
 * firewall is dead?" unanswerable a month later.
 */
async function writeBatch(
  kind: LifecycleImportKind,
  table: 'lifecycle_models' | 'lifecycle_firmware',
  conflictKey: string[],
  accepted: Array<{ index: number; row: Record<string, unknown> }>,
  rejections: Array<{ index: number; reason: string }>,
  label: string,
  userId: number | null,
): Promise<CatalogImportResult> {
  let loaded = 0;
  const extraRejections: Array<{ index: number; reason: string }> = [];
  let importId = 0;

  await db.transaction(async (trx) => {
    for (const { index, row } of accepted) {
      try {
        if (table === 'lifecycle_firmware' && row.family === null) {
          // Partial index `... WHERE family IS NULL`. The predicate has to be
          // repeated for Postgres to select that index as the arbiter.
          await trx.raw(
            `INSERT INTO lifecycle_firmware (brand, family, branch, branch_label,
               min_supported_version, end_of_support, declared_status, source_kind,
               source, source_url, verified_at, note)
             VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (brand, branch) WHERE family IS NULL DO UPDATE SET
               branch_label = EXCLUDED.branch_label,
               min_supported_version = EXCLUDED.min_supported_version,
               end_of_support = EXCLUDED.end_of_support,
               declared_status = EXCLUDED.declared_status,
               source_kind = EXCLUDED.source_kind,
               source = EXCLUDED.source,
               source_url = EXCLUDED.source_url,
               verified_at = EXCLUDED.verified_at,
               note = EXCLUDED.note,
               updated_at = now()`,
            [
              row.brand, row.branch, row.branch_label, row.min_supported_version,
              row.end_of_support, row.declared_status, row.source_kind, row.source,
              row.source_url, row.verified_at, row.note,
            ] as Knex.RawBinding[],
          );
        } else if (table === 'lifecycle_firmware') {
          await trx.raw(
            `INSERT INTO lifecycle_firmware (brand, family, branch, branch_label,
               min_supported_version, end_of_support, declared_status, source_kind,
               source, source_url, verified_at, note)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (brand, family, branch) WHERE family IS NOT NULL DO UPDATE SET
               branch_label = EXCLUDED.branch_label,
               min_supported_version = EXCLUDED.min_supported_version,
               end_of_support = EXCLUDED.end_of_support,
               declared_status = EXCLUDED.declared_status,
               source_kind = EXCLUDED.source_kind,
               source = EXCLUDED.source,
               source_url = EXCLUDED.source_url,
               verified_at = EXCLUDED.verified_at,
               note = EXCLUDED.note,
               updated_at = now()`,
            [
              row.brand, row.family, row.branch, row.branch_label,
              row.min_supported_version, row.end_of_support, row.declared_status,
              row.source_kind, row.source, row.source_url, row.verified_at, row.note,
            ] as Knex.RawBinding[],
          );
        } else {
          await trx(table).insert(row).onConflict(conflictKey).merge();
        }
        loaded += 1;
      } catch (err) {
        // A row the database refuses (a CHECK the service layer did not
        // reproduce) is ONE rejected row with its reason, not a failed import.
        // Migration 027's constraints are the wall behind the Zod schema, and
        // hitting the wall has to be legible.
        extraRejections.push({
          index,
          reason: err instanceof Error ? err.message : 'database refused the row',
        });
      }
    }

    const [journal] = await trx('lifecycle_imports')
      .insert({
        kind,
        source_kind: 'import',
        label,
        rows_loaded: loaded,
        rows_rejected: rejections.length + extraRejections.length,
        imported_by: userId,
      })
      .returning<Array<{ id: string | number }>>('id');
    importId = Number(journal.id);
  });

  clearLifecycleCatalogCache();

  return {
    importId,
    kind,
    label,
    rowsLoaded: loaded,
    rowsRejected: rejections.length + extraRejections.length,
    rejections: [...rejections, ...extraRejections],
  };
}

/**
 * Delete one catalogue row. PLATFORM ADMIN ONLY.
 *
 * A wrong entry has to be removable, and quickly: a bad row here is a claim
 * being made to customers. Returns false when nothing matched so the caller can
 * answer 404 rather than pretending.
 */
export async function deleteCatalogEntry(
  kind: LifecycleImportKind,
  id: number,
): Promise<boolean> {
  const table = kind === 'model' ? 'lifecycle_models' : 'lifecycle_firmware';
  const n = await db(table).where('id', id).delete();
  if (n > 0) clearLifecycleCatalogCache();
  return n > 0;
}

// ============================================================================
// The journal
// ============================================================================

export interface CatalogImportRecord {
  id: number;
  kind: LifecycleImportKind;
  sourceKind: LifecycleSourceKind;
  label: string;
  rowsLoaded: number;
  rowsRejected: number;
  importedBy: number | null;
  importedByUsername: string | null;
  importedAt: string;
}

/** Who changed the catalogue, when, and by how much. Read-only; the answer to
 *  "where did this claim come from" a month after the fact. */
export async function listCatalogImports(limit = 50): Promise<CatalogImportRecord[]> {
  const rows = await db('lifecycle_imports as i')
    .leftJoin('users as u', 'u.id', 'i.imported_by')
    .orderBy('i.imported_at', 'desc')
    .limit(Math.min(Math.max(limit, 1), 200))
    .select<Array<{
      id: string | number; kind: LifecycleImportKind; source_kind: LifecycleSourceKind;
      label: string; rows_loaded: number; rows_rejected: number;
      imported_by: number | null; username: string | null; imported_at: Date;
    }>>(
      'i.id', 'i.kind', 'i.source_kind', 'i.label', 'i.rows_loaded', 'i.rows_rejected',
      'i.imported_by', 'u.username', 'i.imported_at',
    );

  return rows.map((r) => ({
    id: Number(r.id),
    kind: r.kind,
    sourceKind: r.source_kind,
    label: r.label,
    rowsLoaded: r.rows_loaded,
    rowsRejected: r.rows_rejected,
    importedBy: r.imported_by,
    importedByUsername: r.username,
    importedAt: new Date(r.imported_at).toISOString(),
  }));
}

/** Today, as the SERVER sees it. THE ONE PLACE F8 READS A CLOCK.
 *
 *  Decision 5 of `shared/src/lifecycle.ts`: `asOf` is a parameter of every pure
 *  function and of NO HTTP route. `asOf=2000-01-01` would report an entire
 *  fleet `supported`; `asOf=2099-01-01` would report it all `end_of_life`.
 *  Nothing on the HTTP surface reaches this value — the controller calls this
 *  function and passes the result down.
 *
 *  Goes through the SAME `toIsoDate` as `toDateString`: the day a boundary is
 *  read as and the day it is compared against are produced by one rule, so
 *  there is no timezone seam for a verdict to flicker across at midnight. */
export function serverToday(): string {
  return toIsoDate(new Date());
}
