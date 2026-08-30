/**
 * ObliWAN F8 — the renewal list.
 *
 * ┌─ EVERY READ IN THIS FILE IS SCOPED BY TENANT, AND THE SCOPE LEADS ────────┐
 * │ There is exactly ONE query in this module that touches customer data —    │
 * │ `loadFleet` — and its first predicate is `devices.tenant_id = ?`. The join │
 * │ to `sites` is on BOTH id AND tenant (`s.id = d.site_id AND                │
 * │ s.tenant_id = d.tenant_id`), so a site name can never be borrowed from    │
 * │ another customer even if a `site_id` were somehow crossed. That is the    │
 * │ same discipline as `loadPaths` in the weather controller, and it is not   │
 * │ decoration: `devices.site_id` is nullable with ON DELETE SET NULL, so the │
 * │ pair really can go stale.                                                 │
 * │                                                                          │
 * │ The catalogue tables have NO tenant column and are read unscoped ON       │
 * │ PURPOSE (migration 027, decision 2): they hold published vendor product   │
 * │ facts and no customer datum of any kind. Nothing joins them to `devices`  │
 * │ in SQL — the match happens in `shared/src/lifecycle.ts`, on rows the      │
 * │ tenant-scoped query already returned.                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY THE MATCH IS IN TYPESCRIPT AND NOT IN SQL ───────────────────────────┐
 * │ The rule — normalise the model string, exact beats prefix, longest prefix │
 * │ wins, the branch with the most components wins, `supported` needs a date  │
 * │ in the future — is the rule that decides what an MSP tells a paying       │
 * │ customer. It has to be readable in one screen and testable with no        │
 * │ database, which is why every line of it lives in a pure module with no    │
 * │ clock and no I/O. Expressed as a LATERAL join with a LIKE and a           │
 * │ length(pattern) DESC it would be untestable, dialect-bound, and it would  │
 * │ put an operator-supplied string on the left of a LIKE.                    │
 * │                                                                          │
 * │ The cost is one full fleet read per report. The catalogue is hundreds of  │
 * │ rows and cached; the fleet is thousands at the outside, and the whole     │
 * │ cross-product is a few milliseconds of pure computation. The summary and  │
 * │ the gap list both need the WHOLE fleet anyway — a paginated summary is a  │
 * │ wrong summary — so the read could not have been narrowed regardless.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2): the widest object this file serves is a device's name, site,
 * brand, family, model string and firmware version. No transport row, no
 * `secret_enc`, no `ppp_username`, no jsonb. `devices.serial` is deliberately
 * NOT selected: it is not needed to decide whether a model is retired, and the
 * narrowest projection that answers the question is the one that ships.
 *
 * D3: this module reads. It sends nothing to any equipment, ever.
 */

import {
  assessDevice,
  catalogGaps,
  compareAssessments,
  summarizeLifecycle,
  FIRMWARE_STATUSES,
  LIFECYCLE_STATUSES,
  RENEWAL_PRIORITIES,
  type CatalogGap,
  type FirmwareStatus,
  type LifecycleAssessment,
  type LifecycleStatus,
  type LifecycleSummary,
  type LifecycleDeviceInput,
  type RenewalPriority,
} from '@obliwan/shared/dist/lifecycle';
import type { DeviceBrand, DeviceFamily } from '@obliwan/shared/dist/device';
import { db } from '../../db';
import { getLifecycleCatalog, serverToday } from './catalog.service';

interface FleetRow {
  id: number;
  name: string;
  site_id: number | null;
  site_name: string | null;
  brand: DeviceBrand;
  family: DeviceFamily;
  model: string | null;
  os_version: string | null;
}

/**
 * THE ONLY QUERY IN F8 THAT READS CUSTOMER DATA.
 *
 * `where('d.tenant_id', tenantId)` is not optional and is not conditional:
 * there is no code path through this module that reaches Postgres without it.
 * Callers pass `req.tenantId`, which `requireTenant` resolved from a real
 * `user_tenants` membership.
 */
async function loadFleet(tenantId: number): Promise<LifecycleDeviceInput[]> {
  const rows = await db('devices as d')
    .leftJoin('sites as s', function joinSite(this: any) {
      // Both halves. `d.site_id` is nullable with ON DELETE SET NULL, so the
      // pair is proven by the query rather than trusted from the row.
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where('d.tenant_id', tenantId)
    .orderBy('d.id', 'asc')
    .select<FleetRow[]>(
      'd.id', 'd.name', 'd.site_id', 's.name as site_name',
      'd.brand', 'd.family', 'd.model', 'd.os_version',
    );

  return rows.map((r) => ({
    deviceId: r.id,
    name: r.name,
    siteId: r.site_id,
    siteName: r.site_name,
    brand: r.brand,
    family: r.family,
    model: r.model,
    osVersion: r.os_version,
  }));
}

/**
 * Assess this tenant's whole fleet, once.
 *
 * `asOf` defaults to `serverToday()` and the HTTP layer NEVER passes anything
 * else. It is a parameter here only so the verification harness can prove that
 * a boundary in the past and the same boundary in the future produce different
 * verdicts — which is untestable against a clock. See decision 5 of
 * `shared/src/lifecycle.ts` and the note on `serverToday`.
 */
export async function assessFleet(
  tenantId: number,
  asOf: string = serverToday(),
): Promise<{ asOf: string; assessments: LifecycleAssessment[] }> {
  const [fleet, catalog] = await Promise.all([loadFleet(tenantId), getLifecycleCatalog()]);
  const assessments = fleet
    .map((device) => assessDevice(device, catalog, asOf))
    .sort(compareAssessments);
  return { asOf, assessments };
}

// ============================================================================
// The filters
//
// EVERY OPTION BELOW SELECTS ROWS OUT OF AN ALREADY-COMPUTED LIST. Not one of
// them is an input to a verdict: `assessFleet` has already run, against the
// server's own clock, before any of this is applied. That separation is the
// point — a filter that could change a status would be a caller-driven verdict,
// which is the shape of bug this codebase has already shipped once.
// ============================================================================

export interface InventoryFilter {
  /** Keep only these hardware statuses. */
  status?: LifecycleStatus[];
  /** Keep only these firmware statuses. */
  firmwareStatus?: FirmwareStatus[];
  /** Keep only these renewal priorities. */
  priority?: RenewalPriority[];
  brand?: DeviceBrand;
  family?: DeviceFamily;
  siteId?: number;
  /**
   * Keep only devices whose next cited boundary falls within N days.
   *
   * The pipeline query: "what expires this quarter". It is a WINDOW ON DATES
   * THAT ARE ALREADY COMPUTED — a device that is `supported` stays `supported`
   * whatever this is set to, and a device with no cited boundary is simply
   * absent from the result rather than being reclassified. Capped by the
   * controller at ten years, because an uncapped one is a request to sort the
   * entire fleet for nothing.
   */
  horizonDays?: number;
  limit?: number;
  offset?: number;
}

function inSet<T>(allowed: T[] | undefined, value: T): boolean {
  return allowed === undefined || allowed.length === 0 || allowed.includes(value);
}

/** The next cited boundary on either axis, in days, or null. */
function nextBoundaryDays(a: LifecycleAssessment): number | null {
  const days = [a.hardware.daysUntilNextBoundary, a.firmware.daysUntilEndOfSupport]
    .filter((d): d is number => d !== null);
  return days.length > 0 ? Math.min(...days) : null;
}

export interface InventoryPage {
  asOf: string;
  /** Devices in this tenant's fleet, before any filter. */
  total: number;
  /** Devices that survived the filter, before pagination. */
  matched: number;
  items: LifecycleAssessment[];
  /** The summary is ALWAYS over the WHOLE fleet, never over the filtered page.
   *  A count that moved when the operator ticked a filter box would be read as
   *  "the fleet changed", and the coverage figure would become meaningless. */
  summary: LifecycleSummary;
}

export async function getInventory(
  tenantId: number,
  filter: InventoryFilter = {},
  asOf: string = serverToday(),
): Promise<InventoryPage> {
  const { assessments } = await assessFleet(tenantId, asOf);

  const matched = assessments.filter((a) => {
    if (!inSet(filter.status, a.hardware.status)) return false;
    if (!inSet(filter.firmwareStatus, a.firmware.status)) return false;
    if (!inSet(filter.priority, a.priority)) return false;
    if (filter.brand !== undefined && a.device.brand !== filter.brand) return false;
    if (filter.family !== undefined && a.device.family !== filter.family) return false;
    if (filter.siteId !== undefined && a.device.siteId !== filter.siteId) return false;
    if (filter.horizonDays !== undefined) {
      const days = nextBoundaryDays(a);
      if (days === null || days > filter.horizonDays) return false;
    }
    return true;
  });

  const offset = filter.offset ?? 0;
  const limit = filter.limit ?? 200;

  return {
    asOf,
    total: assessments.length,
    matched: matched.length,
    items: matched.slice(offset, offset + limit),
    summary: summarizeLifecycle(assessments, asOf),
  };
}

/** The counts on their own, for a dashboard tile. Same whole-fleet basis. */
export async function getLifecycleSummary(
  tenantId: number,
  asOf: string = serverToday(),
): Promise<LifecycleSummary> {
  const { assessments } = await assessFleet(tenantId, asOf);
  return summarizeLifecycle(assessments, asOf);
}

/** One device. Returns null when the id is not in THIS tenant's fleet — the
 *  caller answers 404, never 403: a 403 confirms the id exists, which on a
 *  serial primary key is an enumeration oracle over another MSP customer's
 *  inventory. */
export async function getDeviceLifecycle(
  tenantId: number,
  deviceId: number,
  asOf: string = serverToday(),
): Promise<LifecycleAssessment | null> {
  const { assessments } = await assessFleet(tenantId, asOf);
  return assessments.find((a) => a.device.deviceId === deviceId) ?? null;
}

/**
 * The research list: model strings in THIS tenant's fleet that no catalogue row
 * cites, biggest first.
 *
 * This is the other half of "unknown is an honest answer". Telling a
 * salesperson "unknown" is correct but not actionable; telling them "these
 * eleven strings cover 340 of your devices, look them up in this order" is what
 * turns the unknown pile into a catalogue and, eventually, into quotes.
 */
export async function getCatalogGaps(
  tenantId: number,
  asOf: string = serverToday(),
): Promise<{ asOf: string; gaps: CatalogGap[] }> {
  const { assessments } = await assessFleet(tenantId, asOf);
  return { asOf, gaps: catalogGaps(assessments) };
}

/** The vocabularies, so a client can build its filter chips without hard-coding
 *  them and drifting from the server. */
export const LIFECYCLE_VOCABULARY = Object.freeze({
  statuses: LIFECYCLE_STATUSES,
  firmwareStatuses: FIRMWARE_STATUSES,
  priorities: RENEWAL_PRIORITIES,
});
