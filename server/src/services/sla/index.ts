// ============================================================================
// ObliWAN F7 — SLA. Service barrel.
// ============================================================================
//
// F7 turns the rows M2 already writes — `ppp_sessions`, `reachability_verdicts`
// and `sites.maintenance_window` — into the number an MSP puts in a contract,
// with every excluded second named and counted.
//
// THE THREE THINGS THAT MAKE IT WORTH MORE THAN THE SPREADSHEET IT REPLACES:
//
//   1. An outage of OUR management plane is not the customer's outage.
//      `CONCENTRATOR_DEGRADED` and `TUNNEL_DOWN_SITE_UP` leave the calculation
//      and are reported separately, with their seconds and their reason.
//   2. An unobserved period is never 100 %. It is "no measurement", and
//      migration 026 makes the alternative unstorable.
//   3. The objective is decided on the bracket [worst case, best case], so a
//      month of gaps can buy neither a "met" nor a "missed".
//
// NOTHING IN F7 WRITES TO AN EQUIPMENT (D3). It opens no session, dials no
// router and enqueues no `change_job`. Its only writes are `sla_objectives`,
// `sla_reports`, `sla_report_intervals` and one `audit_log` row per issued
// report.

export {
  listObjectives, resolveForSite, setObjective, deleteObjective, OBJECTIVE_BOUNDS,
  type SlaObjective, type ResolvedObjective, type SetObjectiveInput,
} from './objective.service';

export {
  computeAvailability, computeSiteAvailability, hashParams, normalizePeriod, snapSecond,
  type ComputedSiteSla, type ComputeOptions, type SlaPeriodInput,
} from './availability.service';

export {
  issueReport, listReports, getReport, getReportIntervals, deleteReport,
  type StoredSlaReport, type StoredInterval, type IssueReportInput, type ListReportsFilter,
} from './report.service';
