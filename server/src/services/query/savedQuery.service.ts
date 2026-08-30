// ============================================================================
// ObliWAN — Fleet Query (K5): execution, saved queries, policies, export
// ============================================================================
//
// The half of M9 that touches Postgres. `dsl.ts` turns text into an AST,
// `compiler.ts` turns an AST into a parameterised statement, and this file is
// the only place either of them meets a connection or a tenant id.
//
// ┌─ EVERY EXECUTION RUNS IN A READ-ONLY TRANSACTION ─────────────────────────┐
// │ `SET TRANSACTION READ ONLY` costs nothing and means that even a compiler  │
// │ defect that let a fragment through could not write, drop or escalate —    │
// │ Postgres refuses the statement before it runs. `SET LOCAL                 │
// │ statement_timeout` bounds it in time for the same reason the parser is    │
// │ bounded in size: this runs on the event loop that serves every other      │
// │ tenant, and "the query engine is slow today" must never become "the API   │
// │ is down today".                                                           │
// │                                                                          │
// │ The policy evaluator writes, so it opens its OWN transaction and does not │
// │ reuse this one. That asymmetry is the point of naming the function        │
// │ `runReadOnly`.                                                            │
// └───────────────────────────────────────────────────────────────────────────┘

import { createHash } from 'crypto';
import type { Knex } from 'knex';
import type { DiffSeverity } from '@obliwan/shared';
import {
  QUERY_LIMITS,
  type PolicyEvaluation, type QueryExportFormat, type QueryResult, type QueryResultRow,
  type SavedQuery, type SavedQueryInput, type SavedQueryPatch,
} from '@obliwan/shared/dist/query';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { AppError } from '../../middleware/errorHandler';
import { parseQuery, QueryParseError } from './dsl';
import { compile, compileIdsOnly, compilePopulation } from './compiler';

const STATEMENT_TIMEOUT_MS = Math.trunc(QUERY_LIMITS.statementTimeoutMs);

interface RawRow {
  device_id: number;
  device_uuid: string;
  name: string;
  brand: string;
  family: string;
  model: string | null;
  role: string;
  status: string;
  site: string | null;
  snapshot_id: string | null;
  snapshot_uuid: string | null;
  captured_at: Date | null;
  last_seen_at: Date | null;
  ncm_hash: string | null;
  total_count: string;
}

function toRow(r: RawRow): QueryResultRow {
  return {
    deviceId: r.device_id,
    deviceUuid: r.device_uuid,
    name: r.name,
    brand: r.brand,
    family: r.family,
    model: r.model,
    role: r.role,
    status: r.status,
    site: r.site,
    snapshotId: r.snapshot_id === null ? null : String(r.snapshot_id),
    snapshotUuid: r.snapshot_uuid,
    capturedAt: r.captured_at ? r.captured_at.toISOString() : null,
    lastSeenAt: r.last_seen_at ? r.last_seen_at.toISOString() : null,
    ncmHash: r.ncm_hash,
  };
}

/**
 * The single door to the database for anything compiled from user text.
 *
 * READ ONLY + `statement_timeout` + an explicit transaction. `SET LOCAL` only
 * exists inside a transaction, which is why this is not a bare `db.raw`.
 */
async function runReadOnly<T>(
  fn: (trx: Knex.Transaction) => Promise<T>,
): Promise<{ value: T; elapsedMs: number }> {
  const started = process.hrtime.bigint();
  const value = await db.transaction(async (trx) => {
    await trx.raw('SET TRANSACTION READ ONLY');
    // The interpolated value is a compile-time integer from QUERY_LIMITS, never
    // a request field: `SET` does not accept a bind parameter.
    await trx.raw(`SET LOCAL statement_timeout = ${STATEMENT_TIMEOUT_MS}`);
    return fn(trx);
  });
  return { value, elapsedMs: Number(process.hrtime.bigint() - started) / 1e6 };
}

function mapPgError(err: unknown): never {
  const code = (err as { code?: string } | null)?.code;
  // 57014 = query_canceled, i.e. our own statement_timeout fired.
  if (code === '57014') {
    throw new AppError(
      408,
      `Query exceeded ${STATEMENT_TIMEOUT_MS} ms and was cancelled. `
        + 'Narrow it — a predicate on device.* or snapshot.* filters before the '
        + 'configuration documents are opened.',
    );
  }
  throw err;
}

// ============================================================================
// Ad-hoc execution
// ============================================================================

export interface RunOptions {
  limit?: number;
  offset?: number;
  deviceId?: number;
}

/**
 * Parse, compile, execute. The three failure modes are kept distinct on
 * purpose: a `QueryParseError` is the user's (400), a timeout is the query's
 * (408), and anything else is ours (500).
 */
export async function runDsl(
  tenantId: number,
  dsl: string,
  opts: RunOptions = {},
): Promise<QueryResult> {
  const parsed = parseQuery(dsl);
  const limit = Math.min(opts.limit ?? 200, QUERY_LIMITS.maxRows);
  const compiled = compile(parsed.ast, {
    tenantId,
    limit,
    offset: opts.offset,
    deviceId: opts.deviceId,
  });

  let elapsedMs = 0;
  let rows: RawRow[] = [];
  try {
    const out = await runReadOnly(async (trx) => {
      const res = await trx.raw(compiled.sql, compiled.bindings as Knex.RawBinding[]);
      return res.rows as RawRow[];
    });
    rows = out.value;
    elapsedMs = out.elapsedMs;
  } catch (err) {
    mapPgError(err);
  }

  const total = rows.length > 0 ? Number(rows[0].total_count) : 0;
  return {
    rows: rows.map(toRow),
    total,
    elapsedMs: Math.round(elapsedMs * 100) / 100,
    parseMs: parsed.parseMs,
    truncated: total > rows.length,
    scopes: parsed.scopes,
    ginEligible: compiled.ginEligible,
  };
}

/**
 * `EXPLAIN (ANALYZE, BUFFERS)` for one DSL query.
 *
 * This exists because M9's acceptance criterion is "verify by EXPLAIN that the
 * GIN is really used", and a criterion you can only check by hand in psql is a
 * criterion that stops being checked. It runs the same compiled statement,
 * through the same read-only path, and returns the plan as text.
 */
export async function explainDsl(tenantId: number, dsl: string): Promise<string[]> {
  const parsed = parseQuery(dsl);
  const compiled = compile(parsed.ast, { tenantId, limit: QUERY_LIMITS.maxRows });
  const out = await runReadOnly(async (trx) => {
    const res = await trx.raw(
      `EXPLAIN (ANALYZE, BUFFERS, TIMING OFF) ${compiled.sql}`,
      compiled.bindings as Knex.RawBinding[],
    );
    return (res.rows as { 'QUERY PLAN': string }[]).map((r) => r['QUERY PLAN']);
  });
  return out.value;
}

// ============================================================================
// Export
// ============================================================================

const CSV_COLUMNS: readonly (keyof QueryResultRow)[] = [
  'deviceId', 'name', 'brand', 'family', 'model', 'role', 'status', 'site',
  'snapshotId', 'capturedAt', 'lastSeenAt', 'ncmHash',
];

/**
 * RFC 4180 quoting.
 *
 * The leading-`=`/`+`/`-`/`@` neutralisation is not paranoia about our data: a
 * device NAME is attacker-controllable in a takeover scenario (it comes off the
 * router), the export is opened in Excel by an operator, and `=cmd|…` in a cell
 * is a well-known way to turn a report into code execution on their laptop.
 */
function csvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  let s = String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  if (/[",\n\r]/.test(s)) s = `"${s.replace(/"/g, '""')}"`;
  return s;
}

export function toCsv(rows: readonly QueryResultRow[]): string {
  const header = CSV_COLUMNS.join(',');
  const body = rows.map((r) => CSV_COLUMNS.map((c) => csvCell(r[c])).join(','));
  return [header, ...body].join('\r\n');
}

export function serialiseExport(result: QueryResult, format: QueryExportFormat): string {
  return format === 'csv' ? toCsv(result.rows) : JSON.stringify(result, null, 2);
}

// ============================================================================
// Saved queries
// ============================================================================

interface SavedQueryRow {
  id: number;
  uuid: string;
  tenant_id: number;
  name: string;
  description: string | null;
  dsl: string;
  compiled_sql_hash: string;
  is_policy: boolean;
  severity: DiffSeverity | null;
  enabled: boolean;
  created_by: number | null;
  last_run_at: Date | null;
  last_run_ms: number | null;
  last_match_count: number | null;
  created_at: Date;
  updated_at: Date;
}

function toSaved(r: SavedQueryRow): SavedQuery {
  return {
    id: r.id,
    uuid: r.uuid,
    name: r.name,
    description: r.description,
    dsl: r.dsl,
    compiledSqlHash: r.compiled_sql_hash,
    isPolicy: r.is_policy,
    severity: r.severity,
    enabled: r.enabled,
    createdBy: r.created_by,
    lastRunAt: r.last_run_at ? r.last_run_at.toISOString() : null,
    lastRunMs: r.last_run_ms,
    lastMatchCount: r.last_match_count,
    createdAt: r.created_at.toISOString(),
    updatedAt: r.updated_at.toISOString(),
  };
}

/**
 * The fingerprint of what a DSL string means TO THIS COMPILER.
 *
 * Compiled with tenant 0 so that the same query saved by two tenants hashes the
 * same: the hash is about the semantics of the language, not about who ran it.
 */
export function compiledSqlHash(dsl: string): string {
  const parsed = parseQuery(dsl);
  const compiled = compile(parsed.ast, { tenantId: 0, limit: QUERY_LIMITS.maxRows });
  return createHash('sha256').update(compiled.sql).digest('hex');
}

export async function listSavedQueries(
  tenantId: number,
  opts: { policiesOnly?: boolean } = {},
): Promise<SavedQuery[]> {
  const q = db<SavedQueryRow>('saved_queries').where('tenant_id', tenantId);
  if (opts.policiesOnly) q.andWhere('is_policy', true);
  const rows = await q.orderBy('name', 'asc');
  return rows.map(toSaved);
}

/** Tenant scoping is a WHERE, not a check after the fact: a query id belonging
 *  to another customer is a 404, never a 403 that confirms it exists. */
export async function getSavedQuery(tenantId: number, id: number): Promise<SavedQuery> {
  const row = await db<SavedQueryRow>('saved_queries')
    .where({ id, tenant_id: tenantId })
    .first();
  if (!row) throw new AppError(404, 'Saved query not found');
  return toSaved(row);
}

export async function createSavedQuery(
  tenantId: number,
  userId: number | null,
  input: SavedQueryInput,
): Promise<SavedQuery> {
  // Compiling BEFORE the insert is what makes "every stored query is a query
  // that parses" an invariant rather than an aspiration. A policy that only
  // fails at evaluation time fails at 03:00, in a worker, silently.
  const hash = compiledSqlHash(input.dsl);
  const isPolicy = input.isPolicy === true;
  try {
    const [row] = await db<SavedQueryRow>('saved_queries')
      .insert({
        tenant_id: tenantId,
        name: input.name,
        description: input.description ?? null,
        dsl: input.dsl,
        compiled_sql_hash: hash,
        is_policy: isPolicy,
        severity: isPolicy ? (input.severity as DiffSeverity) : null,
        enabled: input.enabled ?? true,
        created_by: userId,
      } as Partial<SavedQueryRow>)
      .returning('*');
    return toSaved(row);
  } catch (err) {
    if ((err as { code?: string }).code === '23505') {
      throw new AppError(409, `A saved query named '${input.name}' already exists`);
    }
    throw err;
  }
}

export async function updateSavedQuery(
  tenantId: number,
  id: number,
  patch: SavedQueryPatch,
): Promise<SavedQuery> {
  const existing = await getSavedQuery(tenantId, id);
  const update: Partial<SavedQueryRow> & { updated_at: Date } = { updated_at: new Date() };

  if (patch.dsl !== undefined) {
    update.dsl = patch.dsl;
    update.compiled_sql_hash = compiledSqlHash(patch.dsl);
  }
  if (patch.name !== undefined) update.name = patch.name;
  if (patch.description !== undefined) update.description = patch.description;
  if (patch.enabled !== undefined) update.enabled = patch.enabled;

  // `is_policy` and `severity` move together — the CHECK constraint enforces
  // it, and letting the API discover that through a 500 would be a worse
  // message than the one we can write here.
  const willBePolicy = patch.isPolicy ?? existing.isPolicy;
  if (patch.isPolicy !== undefined) update.is_policy = willBePolicy;
  if (willBePolicy) {
    const severity = patch.severity ?? existing.severity;
    if (!severity) throw new AppError(400, 'A policy requires a severity');
    update.severity = severity;
  } else {
    update.severity = null;
  }

  try {
    const [row] = await db<SavedQueryRow>('saved_queries')
      .where({ id, tenant_id: tenantId })
      .update(update)
      .returning('*');
    return toSaved(row);
  } catch (err) {
    if ((err as { code?: string }).code === '23505') {
      throw new AppError(409, `A saved query named '${patch.name}' already exists`);
    }
    throw err;
  }
}

export async function deleteSavedQuery(tenantId: number, id: number): Promise<void> {
  const deleted = await db('saved_queries').where({ id, tenant_id: tenantId }).del();
  if (deleted === 0) throw new AppError(404, 'Saved query not found');
}

/**
 * Runs a stored query and records what it cost.
 *
 * The stored `compiled_sql_hash` is recomputed here rather than trusted. When a
 * compiler change alters the statement a stored DSL produces, the row is
 * updated and the change is LOGGED — because "this policy started reporting
 * differently in March" deserves an answer, and a hash that is written once and
 * never compared is a column that documents nothing.
 */
export async function runSavedQuery(
  tenantId: number,
  id: number,
  opts: RunOptions = {},
): Promise<{ query: SavedQuery; result: QueryResult }> {
  const query = await getSavedQuery(tenantId, id);
  const result = await runDsl(tenantId, query.dsl, opts);

  const hash = compiledSqlHash(query.dsl);
  if (hash !== query.compiledSqlHash) {
    logger.warn(
      { queryId: id, tenantId, was: query.compiledSqlHash, now: hash },
      'Fleet Query: the compiler now produces a different statement for a stored query',
    );
  }

  await db('saved_queries').where({ id, tenant_id: tenantId }).update({
    last_run_at: new Date(),
    last_run_ms: Math.round(result.elapsedMs),
    last_match_count: result.total,
    compiled_sql_hash: hash,
    compiled_at: new Date(),
  });

  return { query: { ...query, compiledSqlHash: hash }, result };
}

// ============================================================================
// Policies
// ============================================================================

interface IdRow { device_id: number; snapshot_id: string | null }

/**
 * Evaluates one policy over a tenant's fleet — or over a single device, which
 * is the shape the per-snapshot hook needs.
 *
 * TWO statements, not one: the VIOLATORS and the POPULATION. A policy that
 * matched nothing and a policy that was never evaluated look identical in a
 * table that only stores matches, and "no violations" is a claim that requires
 * knowing the denominator.
 */
export async function evaluatePolicy(
  tenantId: number,
  query: SavedQuery,
  opts: { deviceId?: number } = {},
): Promise<PolicyEvaluation> {
  const started = process.hrtime.bigint();
  const parsed = parseQuery(query.dsl);
  const violating = compileIdsOnly(parsed.ast, { tenantId, deviceId: opts.deviceId });
  const population = compilePopulation({ tenantId, deviceId: opts.deviceId });

  const { value } = await runReadOnly(async (trx) => {
    const v = await trx.raw(violating.sql, violating.bindings as Knex.RawBinding[]);
    const p = await trx.raw(population.sql, population.bindings as Knex.RawBinding[]);
    return { violators: v.rows as IdRow[], population: p.rows as IdRow[] };
  }).catch(mapPgError);

  const violatorKeys = new Set(value.violators.map((r) => `${r.device_id}:${r.snapshot_id ?? ''}`));
  const now = new Date();

  const rows = value.population.map((r) => ({
    query_id: query.id,
    device_id: r.device_id,
    snapshot_id: r.snapshot_id,
    passed: !violatorKeys.has(`${r.device_id}:${r.snapshot_id ?? ''}`),
    severity: query.severity,
    first_failed: now,
  }));

  await db.transaction(async (trx) => {
    await upsertResults(trx, rows.filter((r) => r.snapshot_id !== null), true);
    await upsertResults(trx, rows.filter((r) => r.snapshot_id === null), false);
  });

  return {
    queryId: query.id,
    queryName: query.name,
    severity: query.severity,
    evaluatedAt: now.toISOString(),
    devicesEvaluated: rows.length,
    violations: rows.filter((r) => !r.passed).length,
    elapsedMs: Math.round(Number(process.hrtime.bigint() - started) / 1e4) / 100,
  };
}

interface ResultRowInput {
  query_id: number;
  device_id: number;
  snapshot_id: string | null;
  passed: boolean;
  severity: DiffSeverity | null;
  first_failed: Date;
}

/**
 * Upsert against ONE of the two partial unique indexes of migration 012.
 *
 * They have to be addressed separately: `ON CONFLICT (query_id, device_id,
 * snapshot_id)` cannot match a partial index whose predicate it does not
 * repeat, and the NULL-snapshot rows are not covered by that index at all
 * (NULLS DISTINCT). One `ON CONFLICT` clause here would silently duplicate
 * every never-collected device on every evaluation.
 */
async function upsertResults(
  trx: Knex.Transaction,
  rows: readonly ResultRowInput[],
  withSnapshot: boolean,
): Promise<void> {
  if (rows.length === 0) return;
  const target = withSnapshot
    ? '(query_id, device_id, snapshot_id) WHERE snapshot_id IS NOT NULL'
    : '(query_id, device_id) WHERE snapshot_id IS NULL';

  for (let i = 0; i < rows.length; i += 500) {
    const chunk = rows.slice(i, i + 500);
    const tuples = chunk.map(() => '(?, ?, ?, ?, ?, now(), ?)').join(', ');
    const bindings: Knex.RawBinding[] = [];
    for (const r of chunk) {
      bindings.push(
        r.query_id, r.device_id, r.snapshot_id, r.passed, r.severity,
        r.passed ? null : r.first_failed,
      );
    }
    // eslint-disable-next-line no-await-in-loop
    await trx.raw(
      'INSERT INTO policy_results '
        + '(query_id, device_id, snapshot_id, passed, severity, evaluated_at, first_failed_at) '
        + `VALUES ${tuples} `
        + `ON CONFLICT ${target} DO UPDATE SET `
        + 'passed = EXCLUDED.passed, '
        + 'severity = EXCLUDED.severity, '
        + 'evaluated_at = now(), '
        // A violation that is still a violation keeps its ORIGINAL date: "open
        // since 6 March" is the number an MSP reports, and recomputing it every
        // evaluation would reset it to "open since this morning", forever.
        + 'first_failed_at = CASE WHEN EXCLUDED.passed THEN NULL '
        + 'ELSE COALESCE(policy_results.first_failed_at, EXCLUDED.first_failed_at) END',
      bindings,
    );
  }
}

/**
 * Every enabled policy of a tenant, evaluated.
 *
 * THIS IS THE CALLER the per-snapshot hook will share. M9's perimeter stops at
 * the query service, so the hook itself (one call from the snapshot indexer, on
 * the device that was just collected) is not wired here — but the function it
 * needs takes a `deviceId` and is exercised by `POST /query/policies/evaluate`
 * today, so it is a live path and not a dead guard waiting for a caller.
 */
export async function evaluatePolicies(
  tenantId: number,
  opts: { deviceId?: number } = {},
): Promise<PolicyEvaluation[]> {
  const policies = await listSavedQueries(tenantId, { policiesOnly: true });
  const out: PolicyEvaluation[] = [];
  for (const p of policies) {
    if (!p.enabled) continue;
    try {
      // Sequential on purpose: this can run on the snapshot path, and a fleet
      // of policies fanning out in parallel would turn one collection into a
      // burst of concurrent full-table reads.
      // eslint-disable-next-line no-await-in-loop
      out.push(await evaluatePolicy(tenantId, p, opts));
    } catch (err) {
      // One broken policy must not stop the other nine. It is logged with its
      // id and skipped; the UI shows a stale `evaluated_at` for it.
      logger.error(
        { err, queryId: p.id, tenantId },
        'Fleet Query: policy evaluation failed',
      );
      if (err instanceof QueryParseError) continue;
      if (err instanceof AppError) continue;
      throw err;
    }
  }
  return out;
}

export interface PolicyViolation {
  queryId: number;
  queryName: string;
  severity: DiffSeverity | null;
  deviceId: number;
  deviceName: string;
  site: string | null;
  snapshotId: string | null;
  evaluatedAt: string;
  firstFailedAt: string | null;
}

/**
 * The violations of a tenant.
 *
 * `policy_results` carries no tenant column (migration 012, decision 1): the
 * join to `devices` and the `tenant_id` filter below ARE the isolation. The
 * join to `saved_queries` is filtered too — not redundantly, but because a
 * policy and a device could in principle have been paired before the trigger
 * existed, and a read that only checks one side would surface it.
 */
export async function listViolations(
  tenantId: number,
  opts: { queryId?: number; deviceId?: number; limit?: number } = {},
): Promise<PolicyViolation[]> {
  const q = db('policy_results as pr')
    .join('devices as d', 'd.id', 'pr.device_id')
    .join('saved_queries as sq', 'sq.id', 'pr.query_id')
    .leftJoin('sites as st', 'st.id', 'd.site_id')
    .where('d.tenant_id', tenantId)
    .andWhere('sq.tenant_id', tenantId)
    .andWhere('pr.passed', false)
    .select(
      'pr.query_id', 'sq.name as query_name', 'pr.severity', 'pr.device_id',
      'd.name as device_name', 'st.name as site', 'pr.snapshot_id',
      'pr.evaluated_at', 'pr.first_failed_at',
    )
    .orderBy([{ column: 'pr.evaluated_at', order: 'desc' }, { column: 'pr.device_id' }])
    .limit(Math.min(opts.limit ?? 500, QUERY_LIMITS.maxRows));

  if (opts.queryId !== undefined) q.andWhere('pr.query_id', opts.queryId);
  if (opts.deviceId !== undefined) q.andWhere('pr.device_id', opts.deviceId);

  const rows = await q;
  return rows.map((r: Record<string, unknown>) => ({
    queryId: r.query_id as number,
    queryName: r.query_name as string,
    severity: r.severity as DiffSeverity | null,
    deviceId: r.device_id as number,
    deviceName: r.device_name as string,
    site: (r.site as string | null) ?? null,
    snapshotId: r.snapshot_id === null ? null : String(r.snapshot_id),
    evaluatedAt: (r.evaluated_at as Date).toISOString(),
    firstFailedAt: r.first_failed_at ? (r.first_failed_at as Date).toISOString() : null,
  }));
}
