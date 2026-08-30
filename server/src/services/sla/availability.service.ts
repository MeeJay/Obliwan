// ============================================================================
// ObliWAN F7 — availability, computed from the rows M2 and M3 already wrote
// ============================================================================
//
// ┌─ WHAT THIS SERVICE READS, AND HOW EVERY READ IS SCOPED ───────────────────┐
// │ sites                  `tenant_id` column, filtered directly.             │
// │ devices                `tenant_id` column, filtered directly.             │
// │ ppp_sessions           NO tenant column (migration 002). Scoped by an     │
// │                        INNER JOIN on `devices` with `d.tenant_id = ?`, on │
// │                        EVERY read, exactly as the M3 series tables and    │
// │                        the M4 ncm tables are. That join is the only thing │
// │                        standing between one customer's uptime figure and  │
// │                        another customer's presence history.               │
// │ reachability_verdicts  NO tenant column. Same join, same reason.          │
// │ sla_objectives         `tenant_id` column, filtered directly.             │
// │                                                                          │
// │ It writes NOTHING. `report.service.ts` is the only thing in F7 that       │
// │ inserts a row, and what it inserts is our own report.                     │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THE OBSERVATION MASK, AND WHY IT IS THE HONEST PART ─────────────────────┐
// │ "No PPP session" does not mean "the site was down". It means one of two   │
// │ things, and telling them apart is the difference between an SLA report    │
// │ and a fabrication:                                                       │
// │                                                                          │
// │   - the router was disconnected — a real outage; or                       │
// │   - ObliWAN was not watching (not installed yet, migrated, restored from  │
// │     a backup, or simply down) — no outage at all, and no measurement.     │
// │                                                                          │
// │ The mask is the evidence that decides: the intervals during which the     │
// │ concentrator terminating this device's tunnel held a session FOR ANYBODY. │
// │ If the CHR was writing sessions for other subscribers while this device   │
// │ had none, the device was disconnected. If the CHR held nothing either, we │
// │ were blind, and the seconds are `unmeasured`.                             │
// │                                                                          │
// │ Consequence, stated so nobody "fixes" it later: a fresh install does NOT  │
// │ bill its customer for the 362 days that preceded it, and a site that has  │
// │ never connected at all reports "no measurement" rather than 0 %.          │
// │                                                                          │
// │ The mask is fetched with a hard cap. Hitting it is a REFUSAL, not a       │
// │ truncation: a partial mask reclassifies real outages as unmeasured and    │
// │ therefore IMPROVES the customer's figure, which is the one direction an   │
// │ error in this file must never take.                                       │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHICH DEVICES COUNT ─────────────────────────────────────────────────────┐
// │ `role = 'cpe' AND status = 'active'`.                                     │
// │                                                                          │
// │ Concentrators are OURS. A CHR sitting in our rack is the instrument, not  │
// │ the measurement, and counting its downtime against the customer would     │
// │ invert the whole point of F7.                                             │
// │                                                                          │
// │ `status <> 'active'` is excluded and the exclusion is load-bearing: a     │
// │ `disabled` or `quarantined` router has no sessions by design, so leaving  │
// │ it in would contribute a permanent `down` to the site's timeline and take │
// │ precedence over its healthy neighbour's `unmeasured`.                     │
// └───────────────────────────────────────────────────────────────────────────┘
//
// D3: NOTHING HERE WRITES TO AN EQUIPMENT. F7 opens no session, dials no
// router, enqueues no `change_job`. It is arithmetic over stored rows.
//
// SECRETS (§8.2): the widest object this file builds is a count of seconds and
// a site name. `ppp_sessions.ppp_username` is deliberately NOT selected — the
// service has no use for it, and a column that is never read cannot be leaked.

import { createHash } from 'crypto';
import {
  SLA_ALGORITHM_VERSION, SLA_MAX_DEVICES_PER_SITE, SLA_MAX_OBSERVATION_ROWS,
  SLA_MAX_PERIOD_DAYS, SLA_MAX_ROWS_PER_DEVICE, SLA_MAX_SITES_PER_REQUEST,
  SLA_MIN_PERIOD_SECONDS,
  applyMaintenance, buildDeviceTimeline, combineSiteTimeline, evaluateSla,
  expandMaintenanceWindow, normalizeIntervals, summariseExclusions, totalsFor,
  type SlaInterval, type SlaSegment, type SlaSiteReport, type SlaVerdictSample,
} from '@obliwan/shared/dist/sla';
import type { ReachabilityVerdict } from '@obliwan/shared/dist/telemetry';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { listObjectives, resolveForSite, type SlaObjective } from './objective.service';

// ============================================================================
// 1. The period
// ============================================================================

export interface SlaPeriodInput {
  from: Date;
  to: Date;
}

/**
 * Whole seconds, always.
 *
 * Every boundary in F7 — the period, a session edge, a verdict sample — is
 * snapped down to a whole second before anything is computed. Migration 026
 * refuses an audit-trail row with `seconds = 0`, and a `timestamptz` carries
 * microseconds, so without this a millisecond of overlap between two sessions
 * would produce an interval the database will not store and a report whose
 * trail is quietly shorter than its header.
 */
export function snapSecond(ms: number): number {
  return Math.floor(ms / 1000) * 1000;
}

/** Server-side caps. THE CALLER CHOOSES THE PERIOD; IT DOES NOT CHOOSE HOW
 *  LONG A PERIOD MAY BE, and the bound is here rather than in the controller so
 *  that every entry point — HTTP, the harness, a future job — hits it. */
export function normalizePeriod(input: SlaPeriodInput): { from: number; to: number } {
  const from = snapSecond(input.from.getTime());
  const to = snapSecond(input.to.getTime());
  if (!Number.isFinite(from) || !Number.isFinite(to)) {
    throw new AppError(400, 'Invalid period');
  }
  if (to - from < SLA_MIN_PERIOD_SECONDS * 1000) {
    throw new AppError(400, `The period must be at least ${SLA_MIN_PERIOD_SECONDS} seconds long`);
  }
  const maxMs = SLA_MAX_PERIOD_DAYS * 86_400_000;
  if (to - from > maxMs) {
    throw new AppError(400, `The period may not exceed ${SLA_MAX_PERIOD_DAYS} days`);
  }
  return { from, to };
}

// ============================================================================
// 2. Loading
// ============================================================================

interface SiteRow {
  id: number;
  code: string;
  name: string;
  timezone: string;
  maintenance_window: unknown;
}

interface DeviceRow {
  id: number;
  site_id: number;
  concentrator_id: number | null;
}

interface SessionRow {
  device_id: number;
  concentrator_id: number;
  started_at: Date;
  ended_at: Date | null;
}

interface VerdictRow {
  device_id: number;
  ts: Date;
  verdict: string;
}

/**
 * `sites` for this tenant, optionally narrowed. TENANT FIRST in the WHERE, and
 * the narrowing list is applied on top of it rather than instead of it: a site
 * id supplied by a caller is a filter, never an authorisation.
 */
async function loadSites(tenantId: number, siteIds?: number[]): Promise<SiteRow[]> {
  const q = db('sites')
    .where({ tenant_id: tenantId })
    .orderBy('id')
    .limit(SLA_MAX_SITES_PER_REQUEST + 1)
    .select('id', 'code', 'name', 'timezone', 'maintenance_window');
  if (siteIds && siteIds.length > 0) q.whereIn('id', siteIds);
  const rows: SiteRow[] = await q;
  if (rows.length > SLA_MAX_SITES_PER_REQUEST) {
    throw new AppError(
      400,
      `This tenant has more than ${SLA_MAX_SITES_PER_REQUEST} sites; ask for them by id `
      + '(?siteId=) rather than all at once.',
    );
  }
  return rows;
}

async function loadDevices(tenantId: number, siteIds: number[]): Promise<DeviceRow[]> {
  if (siteIds.length === 0) return [];
  const rows: DeviceRow[] = await db('devices')
    .where({ tenant_id: tenantId, role: 'cpe', status: 'active' })
    .whereIn('site_id', siteIds)
    .orderBy('id')
    .limit(SLA_MAX_DEVICES_PER_SITE * siteIds.length + 1)
    .select('id', 'site_id', 'concentrator_id');
  if (rows.length > SLA_MAX_DEVICES_PER_SITE * siteIds.length) {
    throw new AppError(400, 'Too many devices for one SLA request; narrow the site list.');
  }
  return rows;
}

/**
 * The sessions of the devices under report.
 *
 * `ppp_sessions` HAS NO `tenant_id` (migration 002). The INNER JOIN on
 * `devices` with `d.tenant_id = ?` is the scope, and it is applied even though
 * `deviceIds` was itself produced by a tenant-scoped query: the day somebody
 * passes this function a list from somewhere else, the join is what is still
 * standing.
 */
async function loadSessions(
  tenantId: number,
  deviceIds: number[],
  from: number,
  to: number,
): Promise<SessionRow[]> {
  if (deviceIds.length === 0) return [];
  const rows: SessionRow[] = await db('ppp_sessions as s')
    .join('devices as d', 'd.id', 's.device_id')
    .where('d.tenant_id', tenantId)
    .whereIn('s.device_id', deviceIds)
    .where('s.started_at', '<', new Date(to))
    .andWhere((b) => b.whereNull('s.ended_at').orWhere('s.ended_at', '>', new Date(from)))
    .orderBy('s.started_at')
    .limit(SLA_MAX_ROWS_PER_DEVICE * deviceIds.length + 1)
    .select('s.device_id', 's.concentrator_id', 's.started_at', 's.ended_at');
  if (rows.length > SLA_MAX_ROWS_PER_DEVICE * deviceIds.length) {
    throw new AppError(400, 'Too many PPP sessions in that period; narrow it.');
  }
  return rows;
}

/**
 * The observation mask. See the header block.
 *
 * Scoped through `devices` on `concentrator_id` — the concentrator is itself a
 * row in `devices` and carries the tenant. A concentrator shared between two
 * tenants cannot exist (one row, one `tenant_id`), so this join both scopes the
 * read and bounds it.
 */
async function loadObservationMask(
  tenantId: number,
  concentratorIds: number[],
  from: number,
  to: number,
): Promise<Map<number, SlaInterval[]>> {
  const mask = new Map<number, SlaInterval[]>();
  if (concentratorIds.length === 0) return mask;

  const rows: Array<{ concentrator_id: number; started_at: Date; ended_at: Date | null }> =
    await db('ppp_sessions as s')
      .join('devices as c', 'c.id', 's.concentrator_id')
      .where('c.tenant_id', tenantId)
      .whereIn('s.concentrator_id', concentratorIds)
      .where('s.started_at', '<', new Date(to))
      .andWhere((b) => b.whereNull('s.ended_at').orWhere('s.ended_at', '>', new Date(from)))
      .limit(SLA_MAX_OBSERVATION_ROWS + 1)
      .select('s.concentrator_id', 's.started_at', 's.ended_at');

  if (rows.length > SLA_MAX_OBSERVATION_ROWS) {
    // REFUSAL, NOT TRUNCATION. A partial mask turns proven outages into
    // "unmeasured" and hands the customer a better number than the truth.
    throw new AppError(
      400,
      `More than ${SLA_MAX_OBSERVATION_ROWS} PPP sessions are needed to establish what was `
      + 'observed during that period. Narrowing the period is the only correct answer: a '
      + 'partial observation record would understate downtime.',
    );
  }

  for (const r of rows) {
    const list = mask.get(r.concentrator_id) ?? [];
    list.push({
      start: snapSecond(r.started_at.getTime()),
      end: snapSecond((r.ended_at ?? new Date(to)).getTime()),
    });
    mask.set(r.concentrator_id, list);
  }
  for (const [id, list] of mask) mask.set(id, normalizeIntervals(list));
  return mask;
}

/**
 * K7 verdicts. `UNREACHABLE` is filtered OUT IN SQL and counted separately.
 *
 * `shared/src/telemetry.ts` is explicit that `UNREACHABLE` means "we cannot
 * tell". It is neither uptime nor downtime, it must never override the presence
 * history, and the count is surfaced on the report so that a low coverage
 * figure has a visible cause instead of being a mystery.
 */
async function loadVerdicts(
  tenantId: number,
  deviceIds: number[],
  from: number,
  to: number,
  lookbackMs: number,
): Promise<{ byDevice: Map<number, SlaVerdictSample[]>; unreachableIgnored: number }> {
  const byDevice = new Map<number, SlaVerdictSample[]>();
  if (deviceIds.length === 0) return { byDevice, unreachableIgnored: 0 };

  const windowStart = new Date(from - lookbackMs);
  const rows: VerdictRow[] = await db('reachability_verdicts as v')
    .join('devices as d', 'd.id', 'v.device_id')
    .where('d.tenant_id', tenantId)
    .whereIn('v.device_id', deviceIds)
    .where('v.ts', '>=', windowStart)
    .andWhere('v.ts', '<', new Date(to))
    .andWhere('v.verdict', '<>', 'UNREACHABLE')
    .orderBy('v.ts')
    .limit(SLA_MAX_ROWS_PER_DEVICE * deviceIds.length + 1)
    .select('v.device_id', 'v.ts', 'v.verdict');
  if (rows.length > SLA_MAX_ROWS_PER_DEVICE * deviceIds.length) {
    throw new AppError(400, 'Too many reachability verdicts in that period; narrow it.');
  }

  for (const r of rows) {
    const list = byDevice.get(r.device_id) ?? [];
    list.push({ ts: snapSecond(r.ts.getTime()), verdict: r.verdict as ReachabilityVerdict });
    byDevice.set(r.device_id, list);
  }

  const [{ count }] = await db('reachability_verdicts as v')
    .join('devices as d', 'd.id', 'v.device_id')
    .where('d.tenant_id', tenantId)
    .whereIn('v.device_id', deviceIds)
    .where('v.ts', '>=', windowStart)
    .andWhere('v.ts', '<', new Date(to))
    .andWhere('v.verdict', '=', 'UNREACHABLE')
    .count<{ count: string }[]>('* as count');

  return { byDevice, unreachableIgnored: Number(count) };
}

// ============================================================================
// 3. The computation
// ============================================================================

export interface ComputedSiteSla extends SlaSiteReport {
  /** The full classification. This IS the audit trail; `report.service.ts`
   *  stores it verbatim. */
  segments: SlaSegment[];
  /** sha256 over the parameter set that produced the numbers. */
  paramsHash: string;
  /** K7 samples that said "we cannot tell" and were therefore ignored. */
  unreachableSamplesIgnored: number;
}

export interface ComputeOptions {
  tenantId: number;
  from: Date;
  to: Date;
  /** Optional narrowing. Never an authorisation — see `loadSites`. */
  siteIds?: number[];
}

/**
 * The parameter set, hashed.
 *
 * EVERYTHING THAT COULD MOVE A NUMBER IS IN HERE. Two reports carrying the same
 * hash were computed the same way; two carrying different hashes are two
 * different documents, and noticing that is the whole reason the column exists.
 */
export function hashParams(params: {
  from: number;
  to: number;
  siteId: number;
  objectivePercent: number | null;
  objectiveScope: string | null;
  verdictValiditySeconds: number;
}): string {
  const canonical = JSON.stringify({
    algorithmVersion: SLA_ALGORITHM_VERSION,
    from: new Date(params.from).toISOString(),
    to: new Date(params.to).toISOString(),
    siteId: params.siteId,
    objectivePercent: params.objectivePercent,
    objectiveScope: params.objectiveScope,
    verdictValiditySeconds: params.verdictValiditySeconds,
  });
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Availability per site over one period, with every exclusion traced.
 *
 * Five queries in total whatever the number of sites, then pure arithmetic from
 * `@obliwan/shared/dist/sla`. Nothing in the loop below decides anything: the
 * rules live in the shared module so that the harness can exercise them with no
 * database at all, and so that there is exactly one place where "this second
 * counted against the SLA" is decided.
 */
export async function computeAvailability(opts: ComputeOptions): Promise<ComputedSiteSla[]> {
  const { from, to } = normalizePeriod({ from: opts.from, to: opts.to });
  const tenantId = opts.tenantId;

  const sites = await loadSites(tenantId, opts.siteIds);
  if (sites.length === 0) return [];

  const objectives: SlaObjective[] = await listObjectives(tenantId);
  const siteIds = sites.map((s) => s.id);
  const devices = await loadDevices(tenantId, siteIds);
  const deviceIds = devices.map((d) => d.id);

  const sessions = await loadSessions(tenantId, deviceIds, from, to);

  // The concentrators to build the mask from: the one each device points at
  // today, PLUS every concentrator its sessions actually landed on inside the
  // period. A device that was re-homed mid-period would otherwise be measured
  // against a CHR that was not carrying it.
  const concentratorIds = new Set<number>();
  for (const d of devices) if (d.concentrator_id !== null) concentratorIds.add(d.concentrator_id);
  for (const s of sessions) concentratorIds.add(s.concentrator_id);

  const mask = await loadObservationMask(tenantId, [...concentratorIds], from, to);

  // The widest validity across the tenant decides how far back verdicts are
  // fetched: a sample taken just before the period still speaks for its first
  // minutes.
  const widestValidity = Math.max(
    ...sites.map((s) => resolveForSite(objectives, s.id).verdictValiditySeconds),
  );
  const { byDevice: verdictsByDevice, unreachableIgnored } =
    await loadVerdicts(tenantId, deviceIds, from, to, widestValidity * 1000);

  // -- Index the rows -------------------------------------------------------
  const sessionsByDevice = new Map<number, SlaInterval[]>();
  const concentratorsByDevice = new Map<number, Set<number>>();
  for (const s of sessions) {
    const list = sessionsByDevice.get(s.device_id) ?? [];
    list.push({
      start: snapSecond(s.started_at.getTime()),
      // An open session (`ended_at IS NULL`) runs to the end of the period. It
      // is NOT extended past it: the period is the document's subject.
      end: snapSecond((s.ended_at ?? new Date(to)).getTime()),
    });
    sessionsByDevice.set(s.device_id, list);

    const cset = concentratorsByDevice.get(s.device_id) ?? new Set<number>();
    cset.add(s.concentrator_id);
    concentratorsByDevice.set(s.device_id, cset);
  }

  const devicesBySite = new Map<number, DeviceRow[]>();
  for (const d of devices) {
    const list = devicesBySite.get(d.site_id) ?? [];
    list.push(d);
    devicesBySite.set(d.site_id, list);
  }

  // -- Per site -------------------------------------------------------------
  const out: ComputedSiteSla[] = [];
  for (const site of sites) {
    const resolved = resolveForSite(objectives, site.id);
    const siteDevices = devicesBySite.get(site.id) ?? [];

    const deviceTimelines: SlaSegment[][] = siteDevices.map((device) => {
      const own = normalizeIntervals(sessionsByDevice.get(device.id) ?? []);

      const relevant = new Set<number>(concentratorsByDevice.get(device.id) ?? []);
      if (device.concentrator_id !== null) relevant.add(device.concentrator_id);
      const observation: SlaInterval[] = [];
      for (const cid of relevant) observation.push(...(mask.get(cid) ?? []));

      return buildDeviceTimeline({
        from,
        to,
        sessions: own,
        observation: normalizeIntervals(observation),
        verdicts: verdictsByDevice.get(device.id) ?? [],
        verdictValiditySeconds: resolved.verdictValiditySeconds,
      });
    });

    const combined = combineSiteTimeline(deviceTimelines, from, to);
    const maintenance = expandMaintenanceWindow(
      site.maintenance_window,
      site.timezone,
      from,
      to,
    );
    const segments = applyMaintenance(combined, maintenance.intervals);
    const totals = totalsFor(segments, from, to);
    const outcome = evaluateSla(totals, resolved.objectivePercent);

    out.push({
      siteId: site.id,
      siteCode: site.code,
      siteName: site.name,
      siteTimezone: site.timezone,
      deviceCount: siteDevices.length,
      period: { from: new Date(from).toISOString(), to: new Date(to).toISOString() },
      outcome,
      exclusions: summariseExclusions(segments),
      maintenanceError: maintenance.error,
      objectiveScope: resolved.scope,
      algorithmVersion: SLA_ALGORITHM_VERSION,
      verdictValiditySeconds: resolved.verdictValiditySeconds,
      segments,
      paramsHash: hashParams({
        from,
        to,
        siteId: site.id,
        objectivePercent: resolved.objectivePercent,
        objectiveScope: resolved.scope,
        verdictValiditySeconds: resolved.verdictValiditySeconds,
      }),
      unreachableSamplesIgnored: unreachableIgnored,
    });
  }
  return out;
}

/** One site, or a 404. A site belonging to another customer is a 404 and never
 *  a 403: on a serial id a 403 is an enumeration oracle over another MSP
 *  customer's estate. */
export async function computeSiteAvailability(
  tenantId: number,
  siteId: number,
  from: Date,
  to: Date,
): Promise<ComputedSiteSla> {
  const [report] = await computeAvailability({ tenantId, from, to, siteIds: [siteId] });
  if (!report) throw new AppError(404, 'Site not found');
  return report;
}
