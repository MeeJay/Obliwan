// ============================================================================
// ObliWAN — drift runs and findings
// ============================================================================
//
// The persistence and orchestration half of the drift engine. The comparison
// itself is `semanticDiff.ts`, which is pure; this file is what turns a report
// into rows and what the API reads back.
//
// ┌─ M4 IS READ-ONLY, AND THAT IS A SCOPE DECISION, NOT AN OVERSIGHT ─────────┐
// │ Nothing here proposes a remediation, compiles a plan or writes to an      │
// │ equipment. `config_renders` (the DESIRED side) arrives with the template  │
// │ milestone; until then the desired side of a comparison is the PREVIOUS    │
// │ SNAPSHOT, which answers "what changed on this box since we last looked"   │
// │ — the question a read-only drift can actually answer honestly.            │
// │ `drift_runs.render_id` is therefore left NULL by every path in this file. │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ AN IGNORED FINDING IS KEPT ──────────────────────────────────────────────┐
// │ Never deleted, never skipped at write time. "We saw it and chose to       │
// │ ignore it" and "we never saw it" must stay distinguishable months later,  │
// │ and the rule that silenced it must be nameable. That is why               │
// │ `drift_findings.ignored` is a boolean and `ignored_by_rule` is a foreign  │
// │ key rather than a delete.                                                 │
// │                                                                           │
// │ NAMEABLE IS NOT THE SAME AS JUSTIFIED. `ignored_by_rule` says which       │
// │ POLICY suppressed it, and a policy is only an answer when the policy      │
// │ really ran. `setFindingIgnored` below therefore accepts `ignored = true`  │
// │ only when the layer-4 rule set genuinely produces the suppression, and    │
// │ sends every human decision to `POST /api/exceptions`, which asks for a    │
// │ justification and a review date. Both outcomes reach `audit_log`.         │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ ATTRIBUTION MUST NOT INVENT A CULPRIT (§6.5) ────────────────────────────┐
// │ A run whose two sides differ only because we changed the normalization    │
// │ ruleset or bumped `ncmVersion` is labelled `renormalization` /            │
// │ `model_upgrade` and is EXCLUDED from attribution by construction. The     │
// │ cause is decided here, from the documents, and never inferred afterwards  │
// │ from a timestamp.                                                         │
// └───────────────────────────────────────────────────────────────────────────┘

import type {
  NcmDiffFinding, NcmDiffReport, DiffScope, DiffSeverity,
} from '@obliwan/shared';
import { SEVERITY_RANK, NcmVersionAheadError, NCM_VERSION_AHEAD_REASON } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import {
  compareSnapshots, getSnapshot, getSnapshotDocument, latestDocument, listSnapshots,
} from '../config/snapshot.service';
import { collectAndStore, hasNormalizer } from '../config/collect.service';
// `PATCH /findings/:id/ignore` writes to the F1 ledger. The import points at
// the milestone that owns the chain rather than re-implementing an append here:
// there is exactly one writer of `audit_log`, and it is the one the database
// trigger was built for.
import { appendAudit } from '../attestation/auditLog.service';

export const DRIFT_CAUSES = [
  'scheduled', 'manual', 'post_change', 'renormalization', 'model_upgrade', 'takeover',
] as const;
export type DriftCause = (typeof DRIFT_CAUSES)[number];

export const DRIFT_STATUSES = ['in_sync', 'drifted', 'error', 'unreachable'] as const;
export type DriftStatus = (typeof DRIFT_STATUSES)[number];

/** Causes §6.5 excludes from attribution. Exported because K6 must read the
 *  same list and not keep a copy of its own. */
export const UNATTRIBUTABLE_CAUSES: ReadonlySet<DriftCause> = new Set<DriftCause>([
  'renormalization',
  'model_upgrade',
]);

// ============================================================================
// Layer-4 normalization rules — suppression and severity override
// ============================================================================

interface L4Rule {
  id: number;
  builtin_key: string | null;
  kind: string;
  pattern: string | null;
  prop: string | null;
  section_path: string | null;
  severity: string | null;
}

/**
 * The two layer-4 kinds of the normalisation study: `suppress_finding` and
 * `severity_override`. They act on a FINDING, after the diff, which is why they
 * live here and not in the normaliser.
 *
 * The match is on `drift_findings.path` — the index-free
 * `<kind>/<semKey>[/<field>]` string of §5.1 — because that is precisely the
 * value a customer's ignore rule is written against, and it is the one that
 * survives a rule being inserted above.
 *
 * A suppressed finding is STORED with `ignored = true` and `ignored_by_rule`
 * pointing at the rule. It is never dropped.
 */
async function loadLayer4Rules(deviceId: number, tenantId: number): Promise<L4Rule[]> {
  return db<L4Rule>('normalization_rules as nr')
    // Tenant rules **and the shared library** (`tenant_id IS NULL`), same
    // predicate as `collect.service.loadNormalizationRules` — the two must
    // not disagree about which rules exist, or layer 4 would suppress on a
    // different set from the one layers 1..3 normalised with.
    //
    // Layer 4 is where the strict filter hurt most (audit M4/M5, F1): for
    // every tenant but #1, `ros.comment.severity` never demoted a
    // comment-only diff (the device went red on cosmetics),
    // `ros.obliwan.owned` never removed OUR OWN M6 writes from the diff (we
    // reported ourselves as customer drift), and `ros.version.rebaseline`
    // gave no tolerance after an OS upgrade.
    //
    // Grouped `OR`, deliberately: flattened, it would bind against the
    // `andWhere` chain and leak another tenant's layer-4 rules.
    .where((qb) => {
      void qb.where('nr.tenant_id', tenantId).orWhereNull('nr.tenant_id');
    })
    .andWhere('nr.enabled', true)
    .andWhere('nr.layer', 4)
    .andWhere((qb) => {
      void qb
        .where('nr.scope', 'global')
        .orWhere('nr.scope', 'brand')
        .orWhere((b) => {
          void b.where('nr.scope', 'device').andWhere('nr.scope_id', deviceId);
        })
        .orWhere((b) => {
          void b.where('nr.scope', 'group').whereIn(
            'nr.scope_id',
            db('devices').select('group_id').where('id', deviceId).whereNotNull('group_id'),
          );
        });
    })
    .orderByRaw('nr.apply_order ASC, nr.id ASC')
    .select('nr.id', 'nr.builtin_key', 'nr.kind', 'nr.pattern', 'nr.prop', 'nr.section_path', 'nr.severity');
}

interface DecoratedFinding {
  finding: NcmDiffFinding;
  ignored: boolean;
  ignoredByRule: number | null;
}

function ruleMatches(rule: L4Rule, f: NcmDiffFinding): boolean {
  if (rule.pattern) {
    let re: RegExp;
    try {
      re = new RegExp(rule.pattern);
    } catch {
      // A rule whose regex does not compile matches NOTHING. Failing open here
      // would let a typo silence a whole fleet's findings.
      return false;
    }
    if (!re.test(f.path)) return false;
  }
  if (rule.prop) {
    // EVERY field diff must be under that prop, not merely one of them.
    //
    // This is the difference between "a comment-only change is noise" and "any
    // finding that happens to mention a comment is noise". With `some()`, a
    // rule written to silence comment churn would also silence a rule whose
    // ACTION changed in the same edit — a false negative on the single most
    // dangerous change in the product, produced by a rule whose author
    // believed they were suppressing cosmetics.
    if (f.fieldDiffs.length === 0) return false;
    if (!f.fieldDiffs.every((d) => d.field === rule.prop || d.field.startsWith(`${rule.prop}.`))) {
      return false;
    }
  }
  if (!rule.pattern && !rule.prop) return false;   // a rule matching everything is a bug
  return true;
}

export function applyLayer4(
  findings: readonly NcmDiffFinding[],
  rules: readonly L4Rule[],
): DecoratedFinding[] {
  return findings.map((original) => {
    let finding = original;
    let ignored = false;
    let ignoredByRule: number | null = null;
    for (const rule of rules) {
      if (!ruleMatches(rule, finding)) continue;
      if (rule.kind === 'suppress_finding') {
        ignored = true;
        ignoredByRule = Number(rule.id);
      } else if (rule.kind === 'severity_override' && rule.severity) {
        finding = { ...finding, severity: rule.severity as DiffSeverity };
      }
    }
    return { finding, ignored, ignoredByRule };
  });
}

// ============================================================================
// Running
// ============================================================================

export interface RunDriftOptions {
  cause?: DriftCause;
  scope?: DiffScope;
  /** The DESIRED side. Defaults to the snapshot before the observed one. */
  baselineSnapshotId?: string;
  /** The OBSERVED side. Defaults to the device's latest snapshot. */
  snapshotId?: string;
  /**
   * Collect a fresh snapshot before comparing. A read of the device, never a
   * write — but it opens a connection, so it is opt-in and the HTTP surface
   * gates it behind a capability of its own.
   */
  collect?: boolean;
  fuzzy?: boolean;
}

export interface DriftRunSummary {
  id: string;
  uuid: string;
  deviceId: number;
  deviceName: string;
  snapshotId: string | null;
  baselineSnapshotId: string | null;
  status: DriftStatus;
  errorReason: string | null;
  cause: DriftCause;
  attributable: boolean;
  scope: string;
  findingsCount: number;
  ignoredCount: number;
  inertMoveCount: number;
  outOfScopeCount: number;
  maxSeverity: DiffSeverity | null;
  ncmVersion: number;
  normalizationEpoch: string | null;
  orderAnalysis: string;
  suppressed: Array<{ resource: string; reason: string }>;
  startedAt: string;
  finishedAt: string | null;
}

interface RunRow {
  id: string;
  uuid: string;
  device_id: number;
  device_name: string;
  snapshot_id: string | null;
  render_id: string | null;
  status: string;
  error_reason: string | null;
  cause: string;
  scope: string;
  findings_count: number;
  ignored_count: number;
  inert_move_count: number;
  out_of_scope_count: number;
  max_severity: string | null;
  ncm_version: number;
  normalization_epoch: string | null;
  order_analysis: string;
  suppressed: unknown;
  started_at: Date;
  finished_at: Date | null;
}

/**
 * `drift_runs` has no `baseline_snapshot_id` column — the desired side is
 * `render_id` once templates exist. Until then the baseline is carried in the
 * run's own `suppressed` sibling? No: it is returned to the caller and NOT
 * invented as a column. Adding a column belongs to the templates migration,
 * which owns `config_renders`; forging one here would put half of that schema
 * in the wrong file.
 */
function toRunSummary(r: RunRow, baselineSnapshotId: string | null = null): DriftRunSummary {
  const cause = r.cause as DriftCause;
  return {
    id: String(r.id),
    uuid: r.uuid,
    deviceId: r.device_id,
    deviceName: r.device_name,
    snapshotId: r.snapshot_id === null ? null : String(r.snapshot_id),
    baselineSnapshotId,
    status: r.status as DriftStatus,
    errorReason: r.error_reason,
    cause,
    attributable: !UNATTRIBUTABLE_CAUSES.has(cause),
    scope: r.scope,
    findingsCount: Number(r.findings_count),
    ignoredCount: Number(r.ignored_count),
    inertMoveCount: Number(r.inert_move_count),
    outOfScopeCount: Number(r.out_of_scope_count),
    maxSeverity: (r.max_severity as DiffSeverity | null) ?? null,
    ncmVersion: Number(r.ncm_version),
    normalizationEpoch: r.normalization_epoch,
    orderAnalysis: r.order_analysis,
    suppressed: (r.suppressed as Array<{ resource: string; reason: string }>) ?? [],
    startedAt: new Date(r.started_at).toISOString(),
    finishedAt: r.finished_at ? new Date(r.finished_at).toISOString() : null,
  };
}

const RUN_COLUMNS = [
  'dr.id', 'dr.uuid', 'dr.device_id', 'dr.snapshot_id', 'dr.render_id', 'dr.status',
  'dr.error_reason', 'dr.cause', 'dr.scope', 'dr.findings_count', 'dr.ignored_count',
  'dr.inert_move_count', 'dr.out_of_scope_count', 'dr.max_severity', 'dr.ncm_version',
  'dr.normalization_epoch', 'dr.order_analysis', 'dr.suppressed', 'dr.started_at',
  'dr.finished_at', 'd.name as device_name',
];

function scopedRuns(tenantId: number) {
  // `drift_runs` carries no tenant column: the scoping goes through `devices`,
  // exactly as the SNMP series tables do. Removing this join is a cross-tenant
  // disclosure, not a refactor.
  return db('drift_runs as dr')
    .join('devices as d', 'd.id', 'dr.device_id')
    .where('d.tenant_id', tenantId);
}

function maxSeverityOf(findings: readonly NcmDiffFinding[]): DiffSeverity | null {
  let best: DiffSeverity | null = null;
  for (const f of findings) {
    if (best === null || SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]) best = f.severity;
  }
  return best;
}

async function persistRun(input: {
  deviceId: number;
  snapshotId: string | null;
  status: DriftStatus;
  errorReason: string | null;
  cause: DriftCause;
  scope: DiffScope;
  report: NcmDiffReport | null;
  decorated: DecoratedFinding[];
  ncmVersion: number;
  normalizationEpoch: string | null;
  orderAnalysis: string;
  startedAt: Date;
}): Promise<string> {
  const visible = input.decorated.filter((d) => !d.ignored).map((d) => d.finding);
  return db.transaction(async (trx) => {
    const [run] = await trx('drift_runs')
      .insert({
        device_id: input.deviceId,
        snapshot_id: input.snapshotId,
        status: input.status,
        error_reason: input.errorReason,
        cause: input.cause,
        scope: input.scope,
        findings_count: input.decorated.length,
        ignored_count: input.decorated.filter((d) => d.ignored).length,
        inert_move_count: input.report?.inertMoveCount ?? 0,
        out_of_scope_count: input.report?.outOfScopeCount ?? 0,
        // An IGNORED critical must not keep a device red. That is the whole
        // point of keeping ignored findings at all.
        max_severity: maxSeverityOf(visible),
        ncm_version: input.ncmVersion,
        normalization_epoch: input.normalizationEpoch,
        order_analysis: input.orderAnalysis,
        suppressed: JSON.stringify(input.report?.suppressed ?? []),
        started_at: input.startedAt,
        finished_at: new Date(),
      })
      .returning<{ id: string }[]>('id');

    if (input.decorated.length > 0) {
      const rows = input.decorated.map((d) => ({
        run_id: run.id,
        path: d.finding.path,
        sem_key: d.finding.semKey,
        resource: d.finding.resource,
        kind: d.finding.kind,
        severity: d.finding.severity,
        match_method: d.finding.matchMethod,
        match_confidence: d.finding.matchConfidence,
        predicate_changed: d.finding.predicateChanged,
        field_diffs: JSON.stringify(d.finding.fieldDiffs),
        crossed: JSON.stringify(d.finding.crossed),
        intent_value: d.finding.intentValue === null ? null : JSON.stringify(d.finding.intentValue),
        actual_value: d.finding.actualValue === null ? null : JSON.stringify(d.finding.actualValue),
        ignored: d.ignored,
        ignored_by_rule: d.ignoredByRule,
      }));
      for (let i = 0; i < rows.length; i += 200) {
        await trx('drift_findings').insert(rows.slice(i, i + 200));
      }
    }
    return String(run.id);
  });
}

/**
 * Run one drift evaluation for one device.
 *
 * Never throws on a device-side problem: an unreachable box is a FACT to
 * record (`status: 'unreachable'`), not an exception to propagate — one dead
 * CPE must not abort a fleet sweep. A bug in our own code is `status: 'error'`,
 * and the two are kept distinct because collapsing them hides our failures
 * behind the customer's WAN.
 */
export async function runDrift(
  tenantId: number,
  deviceId: number,
  options: RunDriftOptions = {},
): Promise<DriftRunSummary | null> {
  const startedAt = new Date();
  const scope: DiffScope = options.scope ?? 'managed_only';

  const device = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{ id: number } | undefined>('id');
  if (!device) return null;

  const fail = async (
    status: DriftStatus,
    reason: string,
    snapshotId: string | null,
  ): Promise<DriftRunSummary> => {
    const id = await persistRun({
      deviceId,
      snapshotId,
      status,
      errorReason: reason.slice(0, 2000),
      cause: options.cause ?? 'manual',
      scope,
      report: null,
      decorated: [],
      ncmVersion: 1,
      normalizationEpoch: null,
      orderAnalysis: 'skipped',
      startedAt,
    });
    return (await getRun(tenantId, id)) as DriftRunSummary;
  };

  try {
    if (options.collect) {
      if (!hasNormalizer()) {
        return fail('error', 'no NCM normaliser is registered on this build', null);
      }
      await collectAndStore(deviceId, tenantId, { source: 'ssh' });
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // A box we could not reach is an infrastructure event; a run that blew up
    // is our bug. `/UNREACHABLE|TIMEOUT|NO_TRANSPORT/` is the taxonomy the
    // transport layer already produces.
    const code = (err as { code?: string }).code ?? '';
    const unreachable = ['UNREACHABLE', 'TIMEOUT', 'NO_TRANSPORT', 'CIRCUIT_OPEN'].includes(code);
    return fail(unreachable ? 'unreachable' : 'error', message, null);
  }

  // ── EXPLICIT SNAPSHOT IDS ARE RESOLVED AND VALIDATED BEFORE ANYTHING ────
  //
  // Both ids arrive straight from the HTTP body (`drift.controller.ts`
  // `runBody`, route `POST /api/drift/devices/:deviceId/run`). An id that
  // does not resolve — nonexistent, purged by retention, belonging to another
  // tenant, or belonging to ANOTHER DEVICE OF THIS TENANT — made
  // `compareSnapshots()` return `null`, which fell through into the
  // `takeover` branch below and persisted a run with `status: in_sync`,
  // `findings_count: 0`. Audit M4/M5 F2.
  //
  // A GREEN RUN THAT COMPARED NOTHING IS WORSE THAN AN ERROR: `fleetStatus`
  // reads the LAST run per device, so the fleet screen showed a device that
  // had really drifted as `in_sync` until the next successful run. The
  // planner already fails closed on the same input
  // (`planner.service.ts` -> `PlanCompilationError('no_snapshot')` -> 409);
  // drift was the outlier.
  //
  // `getSnapshot()` is tenant-scoped through the `devices` join, so the
  // cross-tenant case is already `null` here; the `deviceId` comparison is
  // what catches the same-tenant wrong-device case. Both are one `error` run.
  for (const [label, explicitId] of [
    ['snapshotId', options.snapshotId],
    ['baselineSnapshotId', options.baselineSnapshotId],
  ] as const) {
    if (explicitId === undefined || explicitId === null) continue;
    const summary = await getSnapshot(tenantId, explicitId);
    if (!summary || summary.deviceId !== deviceId) {
      return fail(
        'error',
        `${label} ${explicitId} is not a snapshot of this device`,
        null,
      );
    }
  }

  let observedId = options.snapshotId ?? null;
  if (!observedId) {
    const latest = await latestDocument(deviceId);
    if (!latest) return fail('error', 'device has no config snapshot to evaluate', null);
    observedId = latest.id;
  }

  try {
    const comparison = await compareSnapshots(tenantId, deviceId, {
      fromId: options.baselineSnapshotId,
      toId: observedId,
      scope,
      fuzzy: options.fuzzy,
    });

    if (!comparison) {
      // THE CONDITION FOR `takeover` IS POSITIVE: **this device has fewer
      // than two snapshots**. It is never "the comparison returned nothing".
      //
      // `compareSnapshots()` returns `null` for four distinct reasons
      // (`snapshot.service.ts`): fewer than two snapshots; a `fromId` or
      // `toId` that does not resolve for this tenant; and either side
      // belonging to another device. The explicit-id loop above already
      // rejected the last three for ids the CALLER supplied, so what can
      // still land here is a race — a retention purge or a delete between
      // that check and this one. Recording an unexplained `null` as
      // `in_sync` is exactly the false negative this subsystem exists to
      // prevent, so it is an `error` run and the operator sees red.
      const known = await listSnapshots(tenantId, deviceId, { limit: 2 });
      if (known.length >= 2) {
        return fail(
          'error',
          'the two snapshots could not be compared',
          observedId,
        );
      }

      // Exactly one snapshot exists: there is no previous state to compare
      // against and inventing one would report the entire device as `extra`.
      // That is the taken-over-fleet first run, and it is recorded as such.
      const observed = await getSnapshotDocument(tenantId, observedId);
      if (!observed) return fail('error', 'observed snapshot not found', null);
      const id = await persistRun({
        deviceId,
        snapshotId: observedId,
        status: 'in_sync',
        errorReason: null,
        cause: 'takeover',
        scope,
        report: null,
        decorated: [],
        ncmVersion: observed.doc.ncmVersion,
        normalizationEpoch: observed.doc.normalizationEpoch,
        orderAnalysis: observed.doc.orderAnalysis,
        startedAt,
      });
      return (await getRun(tenantId, id)) as DriftRunSummary;
    }

    // §6.5. The cause is decided from the DOCUMENTS, never guessed afterwards.
    const cause: DriftCause =
      comparison.cause === 'model_upgrade'
        ? 'model_upgrade'
        : comparison.cause === 'renormalization'
          ? 'renormalization'
          : (options.cause ?? 'manual');

    const l4 = await loadLayer4Rules(deviceId, tenantId);
    const decorated = applyLayer4(comparison.report.findings, l4);
    const visible = decorated.filter((d) => !d.ignored);

    const id = await persistRun({
      deviceId,
      snapshotId: observedId,
      status: visible.length > 0 ? 'drifted' : 'in_sync',
      errorReason: null,
      cause,
      scope,
      report: comparison.report,
      decorated,
      ncmVersion: comparison.report.ncmVersion,
      normalizationEpoch: comparison.to.normalizationEpoch,
      orderAnalysis: comparison.to.orderAnalysis,
      startedAt,
    });

    if (UNATTRIBUTABLE_CAUSES.has(cause)) {
      logger.info(
        { deviceId, runId: id, cause },
        'Drift run excluded from attribution: caused by our own deployment (§6.5)',
      );
    }
    const summary = (await getRun(tenantId, id)) as DriftRunSummary;
    return { ...summary, baselineSnapshotId: comparison.from.id };
  } catch (err) {
    if (err instanceof NcmVersionAheadError) {
      return fail('error', NCM_VERSION_AHEAD_REASON, observedId);
    }
    return fail('error', err instanceof Error ? err.message : String(err), observedId);
  }
}

// ============================================================================
// Reading
// ============================================================================

export interface ListRunsFilter {
  deviceId?: number;
  status?: DriftStatus;
  cause?: DriftCause;
  limit?: number;
  offset?: number;
}

export async function listRuns(
  tenantId: number,
  filter: ListRunsFilter = {},
): Promise<DriftRunSummary[]> {
  const q = scopedRuns(tenantId);
  if (filter.deviceId !== undefined) void q.andWhere('dr.device_id', filter.deviceId);
  if (filter.status) void q.andWhere('dr.status', filter.status);
  if (filter.cause) void q.andWhere('dr.cause', filter.cause);
  const rows = await q
    .orderBy('dr.started_at', 'desc')
    .orderBy('dr.id', 'desc')
    .limit(Math.min(filter.limit ?? 50, 200))
    .offset(filter.offset ?? 0)
    .select<RunRow[]>(RUN_COLUMNS);
  return rows.map((r) => toRunSummary(r));
}

export async function getRun(tenantId: number, runId: string): Promise<DriftRunSummary | null> {
  const row = await scopedRuns(tenantId)
    .andWhere('dr.id', runId)
    .first<RunRow | undefined>(RUN_COLUMNS);
  return row ? toRunSummary(row) : null;
}

export interface DriftFinding {
  id: string;
  runId: string;
  path: string;
  semKey: string;
  legacySemKey: string | null;
  resource: string;
  kind: string;
  severity: string;
  matchMethod: string;
  matchConfidence: number;
  predicateChanged: boolean;
  fieldDiffs: unknown;
  crossed: string[];
  intentValue: unknown;
  actualValue: unknown;
  ignored: boolean;
  ignoredByRule: number | null;
  createdAt: string;
}

interface FindingRow {
  id: string;
  run_id: string;
  path: string;
  sem_key: string;
  legacy_sem_key: string | null;
  resource: string;
  kind: string;
  severity: string;
  match_method: string;
  match_confidence: string;
  predicate_changed: boolean;
  field_diffs: unknown;
  crossed: unknown;
  intent_value: unknown;
  actual_value: unknown;
  ignored: boolean;
  ignored_by_rule: string | null;
  created_at: Date;
}

function toFinding(r: FindingRow): DriftFinding {
  return {
    id: String(r.id),
    runId: String(r.run_id),
    path: r.path,
    semKey: r.sem_key,
    legacySemKey: r.legacy_sem_key,
    resource: r.resource,
    kind: r.kind,
    severity: r.severity,
    matchMethod: r.match_method,
    matchConfidence: Number(r.match_confidence),
    predicateChanged: r.predicate_changed,
    fieldDiffs: r.field_diffs ?? [],
    crossed: (r.crossed as string[]) ?? [],
    intentValue: r.intent_value ?? null,
    actualValue: r.actual_value ?? null,
    ignored: r.ignored,
    ignoredByRule: r.ignored_by_rule === null ? null : Number(r.ignored_by_rule),
    createdAt: new Date(r.created_at).toISOString(),
  };
}

/** Scoping goes run -> device -> tenant. A finding id from another customer is
 *  a 404 and never a 403: "that finding exists but is not yours" is itself a
 *  disclosure about another customer's inventory. */
function scopedFindings(tenantId: number) {
  return db('drift_findings as df')
    .join('drift_runs as dr', 'dr.id', 'df.run_id')
    .join('devices as d', 'd.id', 'dr.device_id')
    .where('d.tenant_id', tenantId);
}

const FINDING_COLUMNS = [
  'df.id', 'df.run_id', 'df.path', 'df.sem_key', 'df.legacy_sem_key', 'df.resource',
  'df.kind', 'df.severity', 'df.match_method', 'df.match_confidence',
  'df.predicate_changed', 'df.field_diffs', 'df.crossed', 'df.intent_value',
  'df.actual_value', 'df.ignored', 'df.ignored_by_rule', 'df.created_at',
];

export interface ListFindingsFilter {
  runId?: string;
  deviceId?: number;
  severity?: string;
  kind?: string;
  resource?: string;
  /** Ignored findings are EXCLUDED by default and included on request — they
   *  are kept, not hidden. */
  includeIgnored?: boolean;
  limit?: number;
  offset?: number;
}

export async function listFindings(
  tenantId: number,
  filter: ListFindingsFilter = {},
): Promise<DriftFinding[]> {
  const q = scopedFindings(tenantId);
  if (filter.runId) void q.andWhere('df.run_id', filter.runId);
  if (filter.deviceId !== undefined) void q.andWhere('dr.device_id', filter.deviceId);
  if (filter.severity) void q.andWhere('df.severity', filter.severity);
  if (filter.kind) void q.andWhere('df.kind', filter.kind);
  if (filter.resource) void q.andWhere('df.resource', filter.resource);
  if (!filter.includeIgnored) void q.andWhere('df.ignored', false);
  const rows = await q
    .orderByRaw(
      "CASE df.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 " +
        "WHEN 'low' THEN 1 ELSE 0 END DESC, df.id ASC",
    )
    .limit(Math.min(filter.limit ?? 200, 1000))
    .offset(filter.offset ?? 0)
    .select<FindingRow[]>(FINDING_COLUMNS);
  return rows.map(toFinding);
}

export async function getFinding(
  tenantId: number,
  findingId: string,
): Promise<DriftFinding | null> {
  const row = await scopedFindings(tenantId)
    .andWhere('df.id', findingId)
    .first<FindingRow | undefined>(FINDING_COLUMNS);
  return row ? toFinding(row) : null;
}

/** Raised by `setFindingIgnored` when the request is understood and refused.
 *  Carries the status the HTTP layer must answer with. */
export class IgnoreRefused extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'IgnoreRefused';
  }
}

/** Who is asking. Written into the ledger, never into `drift_findings`. */
export interface IgnoreActor {
  userId: number | null;
  username: string;
}

/** The columns `ruleMatches` needs, plus what the ledger entry has to name. */
interface IgnoreTargetRow {
  id: string;
  run_id: string;
  device_id: number;
  device_name: string;
  tenant_id: number;
  path: string;
  sem_key: string;
  resource: string;
  kind: string;
  severity: string;
  field_diffs: unknown;
  ignored: boolean;
  ignored_by_rule: string | null;
  ignored_by_exception: string | null;
}

/**
 * Mark a finding as ignored, or un-ignore it.
 *
 * The row is NEVER deleted, and `drift_runs.max_severity` is recomputed over
 * the remaining visible findings — an ignored critical must not keep a device
 * red, and un-ignoring one must turn it red again without a fresh run.
 *
 * ┌─ THIS ROUTE IS NOT A WAY TO ACCEPT DRIFT, AND IT USED TO BE ──────────────┐
 * │ Migration 019 added `drift_findings_ignore_justified` and both it and the │
 * │ exceptions controller announced that the unjustified manual ignore was    │
 * │ dead. It was dead only WITHOUT a `ruleId`. The CHECK asks the row to name │
 * │ a rule or an exception — a NAME, not a justification — so                 │
 * │ `{"ignored":true,"ruleId":1}` still bought a permanent suppression with   │
 * │ no reason, no review date, no expiry, no ledger row, and (until migration │
 * │ 022) a rule belonging to a DIFFERENT CUSTOMER. The library rules seeded   │
 * │ by `002_ncm_doctrine` guaranteed that a small integer always worked.      │
 * │                                                                           │
 * │ `ignored = true` is now accepted here ONLY when the normalization engine  │
 * │ genuinely produces that suppression: the named rule must be one this      │
 * │ tenant is entitled to, must be a live layer-4 `suppress_finding` in scope │
 * │ for this device, and must MATCH this finding under the very predicate the │
 * │ run uses (`ruleMatches`). Anything else is a human accepting a drift, and │
 * │ a human accepting a drift owes a justification and a review date:         │
 * │ 409, naming `POST /api/exceptions`.                                       │
 * │                                                                           │
 * │ Every outcome — the write and the refusal — appends to `audit_log`.       │
 * │ Inside the transaction, so a suppression whose ledger entry failed does   │
 * │ not exist. An ATTEMPT to hide a critical without justification is exactly │
 * │ the thing an audit is for, which is why the refusal is recorded too.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function setFindingIgnored(
  tenantId: number,
  findingId: string,
  input: { ignored: boolean; ruleId?: number | null },
  actor: IgnoreActor,
): Promise<DriftFinding | null> {
  const owned = await scopedFindings(tenantId)
    .andWhere('df.id', findingId)
    .first<IgnoreTargetRow | undefined>(
      'df.id', 'df.run_id', 'dr.device_id', 'd.name as device_name', 'd.tenant_id',
      'df.path', 'df.sem_key', 'df.resource', 'df.kind', 'df.severity', 'df.field_diffs',
      'df.ignored', 'df.ignored_by_rule', 'df.ignored_by_exception',
    );
  if (!owned) return null;

  const audit = {
    tenantId,
    actorType: (actor.userId === null ? 'system' : 'user') as 'system' | 'user',
    actorId: actor.userId,
    actorName: actor.username,
    entityType: 'drift_finding',
    entityId: findingId,
  };
  const subject = {
    deviceId: owned.device_id,
    deviceName: owned.device_name,
    semKey: owned.sem_key,
    resource: owned.resource,
    path: owned.path,
    severity: owned.severity,
  };

  /** One refusal: a ledger row, then the error. Its own transaction, because
   *  the act being refused has none to be part of. */
  const refuse = async (status: number, action: string, message: string): Promise<never> => {
    await db.transaction(async (trx) => {
      await appendAudit(
        {
          ...audit,
          action,
          after: { ...subject, requestedRuleId: input.ruleId ?? null, refusal: message },
        },
        trx,
      );
    });
    throw new IgnoreRefused(status, message);
  };

  let ruleId: number | null = null;

  if (input.ignored) {
    // ── 1. A manual ignore is not a decision this route may record ─────────
    if (input.ruleId === null || input.ruleId === undefined) {
      return refuse(
        409,
        'drift_finding.ignore_refused',
        'A finding is not silenced by marking it ignored. Accepting a drift needs a written '
          + 'justification, a review date and an author: POST /api/exceptions.',
      );
    }

    // ── 2. The rule must be one this customer is entitled to ───────────────
    //
    // Tenant of the FINDING, resolved finding -> run -> device, never a tenant
    // the caller supplies. `tenant_id IS NULL` is the shipped library, which
    // belongs to everybody and is the one legal cross-tenant value. Migration
    // 022 enforces the same thing in a trigger; this is what turns it into a
    // sentence instead of a 23514.
    const rule = await db('normalization_rules')
      .where('id', input.ruleId)
      .andWhere((qb) => {
        void qb.where('tenant_id', owned.tenant_id).orWhereNull('tenant_id');
      })
      .first<{ id: string } | undefined>('id');
    if (!rule) {
      return refuse(
        404,
        'drift_finding.ignore_refused',
        'Normalization rule not found. A rule belonging to another customer is not a reason '
          + 'to hide this finding.',
      );
    }

    // ── 3. The engine must REALLY produce this suppression ─────────────────
    //
    // Same loader and same predicate as a drift run: enabled, layer 4, in
    // scope for this device, `suppress_finding`, and matching this finding's
    // path and field diffs. If the rule does not suppress it, then nothing but
    // a human is asking for it to disappear — and a human owes an exception.
    const rules = await loadLayer4Rules(owned.device_id, owned.tenant_id);
    const candidate = rules.find((r) => Number(r.id) === input.ruleId);
    const applies = candidate !== undefined
      && candidate.kind === 'suppress_finding'
      && ruleMatches(candidate, {
        path: owned.path,
        fieldDiffs: Array.isArray(owned.field_diffs) ? owned.field_diffs : [],
      } as NcmDiffFinding);
    if (!applies) {
      return refuse(
        409,
        'drift_finding.ignore_refused',
        `Normalization rule ${input.ruleId} does not suppress this finding — it is not an `
          + 'enabled layer-4 suppression in scope for this device, or it does not match. '
          + 'Recording it as the reason would be naming a policy that never ran. To accept '
          + 'this drift deliberately: POST /api/exceptions.',
      );
    }
    ruleId = Number(input.ruleId);
  } else if (owned.ignored_by_exception !== null) {
    // ── Un-ignoring what an exception is holding down ──────────────────────
    //
    // Clearing `ignored` while `ignored_by_exception` still points somewhere
    // leaves a row no clause of `sweep()` will look at again: REVIVE keys on
    // the exception's expiry and APPLY refuses rows whose exception column is
    // set. The finding would be visible until the next run and the exception
    // would still be counted as suppressing it. Revoking is the act that
    // matches the intent, and it is recorded with a reason.
    return refuse(
      409,
      'drift_finding.unignore_refused',
      'This finding is hidden by an accepted-drift exception, not by a rule. Withdraw the '
        + 'exception instead — POST /api/exceptions/:id/revoke — so the reason it stops '
        + 'being hidden is recorded.',
    );
  }

  // A repeated PATCH asking for the state the row is already in is not an act.
  // Writing a ledger row for it would fill the audit screen with entries that
  // record nothing having happened, which is how a ledger stops being read.
  // A repeated REFUSAL above is recorded, deliberately: a second attempt to
  // hide a critical without a justification is a fact, not a no-op.
  const currentRule = owned.ignored_by_rule === null ? null : Number(owned.ignored_by_rule);
  if (owned.ignored === input.ignored && currentRule === (input.ignored ? ruleId : null)) {
    return getFinding(tenantId, findingId);
  }

  await db.transaction(async (trx) => {
    await trx('drift_findings')
      .where({ id: findingId })
      .update({
        ignored: input.ignored,
        // The rule that silenced it must be nameable months later — and, since
        // this route now refuses anything else, it is always a rule the engine
        // itself would have written.
        ignored_by_rule: input.ignored ? ruleId : null,
      });

    const stats = await trx('drift_findings')
      .where({ run_id: owned.run_id })
      .select<{ severity: string; ignored: boolean }[]>('severity', 'ignored');
    const visible = stats.filter((s) => !s.ignored);
    let best: string | null = null;
    for (const s of visible) {
      if (best === null || SEVERITY_RANK[s.severity as DiffSeverity] > SEVERITY_RANK[best as DiffSeverity]) {
        best = s.severity;
      }
    }
    await trx('drift_runs')
      .where({ id: owned.run_id })
      .update({
        ignored_count: stats.filter((s) => s.ignored).length,
        max_severity: best,
        status: visible.length > 0 ? 'drifted' : 'in_sync',
      });

    // In the transaction: if the ledger refuses the entry, the suppression does
    // not happen. Same rule `audit.service.ts` states for `command_audit` and
    // `exception.service.ts` for a grant — an untraceable act is not an
    // acceptable degradation.
    await appendAudit(
      {
        ...audit,
        action: input.ignored ? 'drift_finding.ignored' : 'drift_finding.unignored',
        before: {
          ignored: owned.ignored,
          ignoredByRule: owned.ignored_by_rule === null ? null : Number(owned.ignored_by_rule),
        },
        after: { ...subject, ignored: input.ignored, ignoredByRule: ruleId },
      },
      trx,
    );
  });

  return getFinding(tenantId, findingId);
}

// ============================================================================
// Fleet view
// ============================================================================

export interface DriftFleetStatus {
  devices: number;
  inSync: number;
  drifted: number;
  error: number;
  unreachable: number;
  neverRun: number;
  /** The R3 instrument. If this climbs above 3 the product is on the path to
   *  "nobody looks at the drift screen any more", and the per-lever counters
   *  on each run are what say which lever to fix. */
  averageVisibleFindingsPerDevice: number;
}

export async function fleetStatus(tenantId: number): Promise<DriftFleetStatus> {
  const devices = await db('devices').where({ tenant_id: tenantId }).count<{ count: string }[]>('id as count');
  const total = Number(devices[0]?.count ?? 0);

  // The LAST run of each device, and nothing older: a device that drifted last
  // week and is in sync today is in sync.
  const rows = await db
    .with('last_run', (qb) => {
      void qb
        .from('drift_runs as dr')
        .join('devices as d', 'd.id', 'dr.device_id')
        .where('d.tenant_id', tenantId)
        .select(
          'dr.device_id',
          'dr.status',
          'dr.findings_count',
          'dr.ignored_count',
          db.raw('row_number() over (partition by dr.device_id order by dr.started_at desc, dr.id desc) as rn'),
        );
    })
    .from('last_run')
    .where('rn', 1)
    .select<{ device_id: number; status: string; findings_count: number; ignored_count: number }[]>(
      'device_id', 'status', 'findings_count', 'ignored_count',
    );

  const counts = { in_sync: 0, drifted: 0, error: 0, unreachable: 0 } as Record<string, number>;
  let visible = 0;
  for (const r of rows) {
    counts[r.status] = (counts[r.status] ?? 0) + 1;
    visible += Math.max(0, Number(r.findings_count) - Number(r.ignored_count));
  }

  return {
    devices: total,
    inSync: counts.in_sync ?? 0,
    drifted: counts.drifted ?? 0,
    error: counts.error ?? 0,
    unreachable: counts.unreachable ?? 0,
    neverRun: Math.max(0, total - rows.length),
    averageVisibleFindingsPerDevice: rows.length === 0 ? 0 : visible / rows.length,
  };
}
