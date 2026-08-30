// ============================================================================
// ObliWAN F7 — the stored SLA report and its audit trail
// ============================================================================
//
// ┌─ WHAT MAKES A STORED REPORT DIFFERENT FROM A COMPUTED ONE ────────────────┐
// │ `availability.service.ts` answers a question. THIS file issues a          │
// │ DOCUMENT: a row that is frozen against UPDATE by a trigger, that carries  │
// │ the parameter set it was computed with and the hash of that set, and that │
// │ is accompanied by EVERY interval of the period with its classification    │
// │ and its reason.                                                          │
// │                                                                          │
// │ The audit trail is the feature, not the decoration. The brief is blunt    │
// │ about it: an SLA whose exclusions cannot be audited is worth no more than │
// │ the spreadsheet it replaced. So a report that cannot carry its complete   │
// │ trail is REFUSED rather than stored with a truncated one — a trail with   │
// │ holes is worse than no trail, because it looks complete.                  │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ NOTHING CALLER-DRIVEN REACHES THE ARITHMETIC ────────────────────────────┐
// │ The caller chooses the PERIOD and the SITE. That is the whole list.       │
// │                                                                          │
// │ The objective and `verdictValiditySeconds` come from `sla_objectives`,    │
// │ which is written only through `settings.manage`. Both are copied onto the │
// │ report and folded into `params_hash`. There is no override parameter, no  │
// │ "assume up" flag, no tolerance argument — the F2 audit found exactly such │
// │ a parameter turning 365 unobserved days into a signed "continuous", and   │
// │ the fix is not to bound it, it is not to have it.                         │
// └───────────────────────────────────────────────────────────────────────────┘
//
// Every read and every write below is scoped by `tenant_id`, and a row
// belonging to another customer is a 404, never a 403.
//
// D3: nothing here writes to an equipment.

import {
  SLA_MAX_STORED_INTERVALS,
  type SlaCoverageStatus, type SlaObjectiveScope, type SlaObjectiveVerdict,
} from '@obliwan/shared/dist/sla';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { appendAudit } from '../attestation/auditLog.service';
import { computeSiteAvailability, type ComputedSiteSla } from './availability.service';

export interface StoredSlaReport {
  id: string;
  uuid: string;
  tenantId: number;
  siteId: number;
  siteCode: string | null;
  siteName: string | null;
  periodStart: string;
  periodEnd: string;
  generatedAt: string;
  actorId: string | null;
  actorName: string | null;
  objectivePercent: number | null;
  objectiveScope: SlaObjectiveScope | null;
  verdictValiditySeconds: number;
  algorithmVersion: string;
  paramsHash: string;
  periodSeconds: number;
  upSeconds: number;
  downSeconds: number;
  excludedManagementSeconds: number;
  excludedMaintenanceSeconds: number;
  unmeasuredSeconds: number;
  availabilityPercent: number | null;
  worstCasePercent: number | null;
  bestCasePercent: number | null;
  coveragePercent: number | null;
  coverageStatus: SlaCoverageStatus;
  objectiveVerdict: SlaObjectiveVerdict;
  verdictReason: string;
  maintenanceError: string | null;
  deviceCount: number;
  intervalCount: number;
}

interface ReportRow {
  id: string;
  uuid: string;
  tenant_id: number;
  site_id: number;
  site_code?: string | null;
  site_name?: string | null;
  period_start: Date;
  period_end: Date;
  generated_at: Date;
  actor_id: string | null;
  actor_name: string | null;
  objective_percent: string | null;
  objective_scope: string | null;
  verdict_validity_seconds: number;
  algorithm_version: string;
  params_hash: string;
  period_seconds: string;
  up_seconds: string;
  down_seconds: string;
  excluded_management_seconds: string;
  excluded_maintenance_seconds: string;
  unmeasured_seconds: string;
  availability_percent: string | null;
  worst_case_percent: string | null;
  best_case_percent: string | null;
  coverage_percent: string | null;
  coverage_status: string;
  objective_verdict: string;
  verdict_reason: string;
  maintenance_error: string | null;
  device_count: number;
  interval_count: number;
}

/** `numeric` and `bigint` both come back from `pg` as STRINGS. Every read goes
 *  through here so that no caller has to remember it — a silent
 *  `'99.5000' > 99.4` string comparison is exactly the kind of bug that would
 *  flip a verdict without failing a type check. */
function num(value: string | null): number | null {
  return value === null ? null : Number(value);
}

function toReport(row: ReportRow): StoredSlaReport {
  return {
    id: String(row.id),
    uuid: row.uuid,
    tenantId: row.tenant_id,
    siteId: row.site_id,
    siteCode: row.site_code ?? null,
    siteName: row.site_name ?? null,
    periodStart: new Date(row.period_start).toISOString(),
    periodEnd: new Date(row.period_end).toISOString(),
    generatedAt: new Date(row.generated_at).toISOString(),
    actorId: row.actor_id,
    actorName: row.actor_name,
    objectivePercent: num(row.objective_percent),
    objectiveScope: (row.objective_scope as SlaObjectiveScope | null) ?? null,
    verdictValiditySeconds: row.verdict_validity_seconds,
    algorithmVersion: row.algorithm_version,
    paramsHash: row.params_hash,
    periodSeconds: Number(row.period_seconds),
    upSeconds: Number(row.up_seconds),
    downSeconds: Number(row.down_seconds),
    excludedManagementSeconds: Number(row.excluded_management_seconds),
    excludedMaintenanceSeconds: Number(row.excluded_maintenance_seconds),
    unmeasuredSeconds: Number(row.unmeasured_seconds),
    availabilityPercent: num(row.availability_percent),
    worstCasePercent: num(row.worst_case_percent),
    bestCasePercent: num(row.best_case_percent),
    coveragePercent: num(row.coverage_percent),
    coverageStatus: row.coverage_status as SlaCoverageStatus,
    objectiveVerdict: row.objective_verdict as SlaObjectiveVerdict,
    verdictReason: row.verdict_reason,
    maintenanceError: row.maintenance_error,
    deviceCount: row.device_count,
    intervalCount: row.interval_count,
  };
}

export interface IssueReportInput {
  tenantId: number;
  siteId: number;
  from: Date;
  to: Date;
  actorUserId: number | null;
  actorName: string | null;
}

/**
 * Compute one site's availability and FREEZE it.
 *
 * The report, its intervals and its `audit_log` entry are written in ONE
 * transaction, and the ledger write is inside it on purpose — the same rule
 * migration 019 applies to attestations: if the ledger write fails, the act
 * does not happen, rather than happening unrecorded.
 */
export async function issueReport(input: IssueReportInput): Promise<{
  report: StoredSlaReport;
  computed: ComputedSiteSla;
}> {
  const computed = await computeSiteAvailability(
    input.tenantId, input.siteId, input.from, input.to,
  );

  const intervals = computed.segments
    .map((s) => ({
      started_at: new Date(s.start),
      ended_at: new Date(s.end),
      seconds: Math.round((s.end - s.start) / 1000),
      kind: s.kind,
      reason: s.reason,
    }))
    // Sub-second segments cannot exist: `snapSecond` floors every boundary
    // before the timeline is built. The filter is the second wall, and it is
    // here rather than nowhere because migration 026 refuses `seconds = 0` and
    // a 23514 in the middle of issuing a report is a worse answer than this.
    .filter((r) => r.seconds > 0);

  if (intervals.length > SLA_MAX_STORED_INTERVALS) {
    throw new AppError(
      400,
      `That period classifies into ${intervals.length} intervals, more than the `
      + `${SLA_MAX_STORED_INTERVALS} a single report may carry. Issue it over a shorter `
      + 'period: a report stored without its complete audit trail would look complete and '
      + 'would not be.',
    );
  }

  const o = computed.outcome;
  const t = o.totals;

  return db.transaction(async (trx) => {
    const [row]: ReportRow[] = await trx('sla_reports')
      .insert({
        tenant_id: input.tenantId,
        site_id: computed.siteId,
        period_start: new Date(computed.period.from),
        period_end: new Date(computed.period.to),
        actor_id: input.actorUserId === null ? null : String(input.actorUserId),
        actor_name: input.actorName,
        objective_percent: o.objectivePercent,
        objective_scope: computed.objectiveScope,
        verdict_validity_seconds: computed.verdictValiditySeconds,
        algorithm_version: computed.algorithmVersion,
        params_hash: computed.paramsHash,
        period_seconds: t.periodSeconds,
        up_seconds: t.upSeconds,
        down_seconds: t.downSeconds,
        excluded_management_seconds: t.excludedManagementSeconds,
        excluded_maintenance_seconds: t.excludedMaintenanceSeconds,
        unmeasured_seconds: t.unmeasuredSeconds,
        availability_percent: o.availabilityPercent,
        worst_case_percent: o.worstCasePercent,
        best_case_percent: o.bestCasePercent,
        coverage_percent: o.coveragePercent,
        coverage_status: o.status,
        objective_verdict: o.objectiveVerdict,
        verdict_reason: o.verdictReason,
        maintenance_error: computed.maintenanceError,
        device_count: computed.deviceCount,
        interval_count: intervals.length,
      })
      .returning('*');

    if (intervals.length > 0) {
      await trx('sla_report_intervals').insert(
        intervals.map((i) => ({ ...i, report_id: row.id, tenant_id: input.tenantId })),
      );
    }

    // The ledger. `after` carries seconds, percentages and a hash — no
    // credential, no configuration body, no command line (§8.2).
    await appendAudit({
      tenantId: input.tenantId,
      actorType: input.actorUserId === null ? 'system' : 'user',
      actorId: input.actorUserId,
      actorName: input.actorName,
      action: 'sla_report.issued',
      entityType: 'sla_report',
      entityId: row.id,
      after: {
        siteId: computed.siteId,
        periodStart: computed.period.from,
        periodEnd: computed.period.to,
        availabilityPercent: o.availabilityPercent,
        coverageStatus: o.status,
        objectivePercent: o.objectivePercent,
        objectiveVerdict: o.objectiveVerdict,
        excludedManagementSeconds: t.excludedManagementSeconds,
        excludedMaintenanceSeconds: t.excludedMaintenanceSeconds,
        unmeasuredSeconds: t.unmeasuredSeconds,
        algorithmVersion: computed.algorithmVersion,
        paramsHash: computed.paramsHash,
      },
    }, trx);

    return { report: toReport(row), computed };
  });
}

export interface ListReportsFilter {
  siteId?: number;
  limit?: number;
}

/** Tenant-scoped. The site name is joined in for the list screen; the join is
 *  on `(site_id, tenant_id)` so it cannot reach across customers even if the
 *  report row were somehow wrong. */
export async function listReports(
  tenantId: number,
  filter: ListReportsFilter = {},
): Promise<StoredSlaReport[]> {
  const q = db('sla_reports as r')
    .leftJoin('sites as s', function join() {
      this.on('s.id', 'r.site_id').andOn('s.tenant_id', 'r.tenant_id');
    })
    .where('r.tenant_id', tenantId)
    .orderBy('r.generated_at', 'desc')
    .limit(Math.min(Math.max(filter.limit ?? 50, 1), 500))
    .select('r.*', 's.code as site_code', 's.name as site_name');
  if (filter.siteId !== undefined) q.andWhere('r.site_id', filter.siteId);
  const rows: ReportRow[] = await q;
  return rows.map(toReport);
}

export async function getReport(
  tenantId: number,
  id: number,
): Promise<StoredSlaReport | null> {
  const row: ReportRow | undefined = await db('sla_reports as r')
    .leftJoin('sites as s', function join() {
      this.on('s.id', 'r.site_id').andOn('s.tenant_id', 'r.tenant_id');
    })
    .where('r.tenant_id', tenantId)
    .andWhere('r.id', id)
    .first('r.*', 's.code as site_code', 's.name as site_name');
  return row ? toReport(row) : null;
}

export interface StoredInterval {
  startedAt: string;
  endedAt: string;
  seconds: number;
  kind: string;
  reason: string;
}

/**
 * The audit trail of one report.
 *
 * Scoped by `tenant_id` ON THE INTERVAL TABLE ITSELF, not only through the
 * report: `sla_report_intervals` carries its own `tenant_id` precisely so that
 * this read does not depend on a join being written correctly every time.
 */
export async function getReportIntervals(
  tenantId: number,
  reportId: number,
  kinds?: string[],
): Promise<StoredInterval[]> {
  const q = db('sla_report_intervals')
    .where({ tenant_id: tenantId, report_id: reportId })
    .orderBy('started_at')
    .limit(SLA_MAX_STORED_INTERVALS)
    .select('started_at', 'ended_at', 'seconds', 'kind', 'reason');
  if (kinds && kinds.length > 0) q.whereIn('kind', kinds);
  const rows: Array<{
    started_at: Date; ended_at: Date; seconds: number; kind: string; reason: string;
  }> = await q;
  return rows.map((r) => ({
    startedAt: new Date(r.started_at).toISOString(),
    endedAt: new Date(r.ended_at).toISOString(),
    seconds: r.seconds,
    kind: r.kind,
    reason: r.reason,
  }));
}

/** Tenant-scoped delete. Reports are computed artefacts under a retention
 *  policy, not a ledger, so DELETE is allowed where UPDATE is not — the trigger
 *  `sla_reports_freeze_trg` refuses the second. The intervals cascade: they are
 *  meaningless without their header. */
export async function deleteReport(tenantId: number, id: number): Promise<boolean> {
  const deleted = await db('sla_reports')
    .where({ tenant_id: tenantId, id })
    .delete();
  return deleted > 0;
}
