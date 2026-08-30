/**
 * ObliWAN — sites.
 *
 * A site is the customer premises. It carries the maintenance window that gates
 * every push from M6 onwards, so it exists as a first-class entity from M2 even
 * though nothing pushes yet.
 *
 * EVERY query in this file is tenant-scoped, and the tenant comes from the
 * SESSION (`req.tenantId`), never from the request body. `sites.code` is unique
 * per tenant, not globally: two MSP customers are both entitled to a site
 * called "SIEGE".
 */

import { SOCKET_EVENTS } from '@obliwan/shared';
import { db } from '../../db';
import { emitToTenant } from './fleetEvents';
import { toSiteDto } from './dto';

export interface SiteRow {
  id: number;
  uuid: string;
  tenant_id: number;
  code: string;
  name: string;
  address: string | null;
  contact: string | null;
  timezone: string;
  maintenance_window: unknown;
  created_at: Date;
  updated_at: Date;
}

export interface SiteWithCounts extends SiteRow {
  device_count: number;
  online_count: number;
}

export interface CreateSiteData {
  code: string;
  name: string;
  address?: string | null;
  contact?: string | null;
  timezone?: string;
  maintenanceWindow?: unknown;
}

export type UpdateSiteData = Partial<CreateSiteData>;

function toColumns(data: UpdateSiteData): Record<string, unknown> {
  const row: Record<string, unknown> = {};
  if (data.code !== undefined) row.code = data.code;
  if (data.name !== undefined) row.name = data.name;
  if (data.address !== undefined) row.address = data.address;
  if (data.contact !== undefined) row.contact = data.contact;
  if (data.timezone !== undefined) row.timezone = data.timezone;
  if (data.maintenanceWindow !== undefined) {
    row.maintenance_window =
      data.maintenanceWindow === null ? null : JSON.stringify(data.maintenanceWindow);
  }
  return row;
}

/**
 * List with the two numbers the fleet tree actually needs: how many devices,
 * and how many of them have an open PPP session right now.
 *
 * "Online" is defined as an open row in `ppp_sessions` — the concentrator's
 * view (D4) — and not as a ping, not as `last_seen_at` being recent.
 */
export async function listSites(
  tenantId: number,
  options: { search?: string } = {},
): Promise<SiteWithCounts[]> {
  const query = db('sites as s')
    .where('s.tenant_id', tenantId)
    .leftJoin('devices as d', 'd.site_id', 's.id')
    .leftJoin('ppp_sessions as p', function joinOpenSession(this: any) {
      this.on('p.device_id', '=', 'd.id').andOnNull('p.ended_at');
    })
    .groupBy('s.id')
    .select<SiteWithCounts[]>(
      's.*',
      db.raw('COUNT(DISTINCT d.id)::int as device_count'),
      db.raw('COUNT(DISTINCT p.device_id)::int as online_count'),
    )
    .orderBy('s.name');

  if (options.search) {
    const like = `%${options.search}%`;
    query.andWhere((q) => {
      q.whereILike('s.name', like).orWhereILike('s.code', like);
    });
  }

  return query;
}

export async function getSite(tenantId: number, id: number): Promise<SiteRow | undefined> {
  return db('sites').where({ id, tenant_id: tenantId }).first<SiteRow | undefined>();
}

export async function createSite(tenantId: number, data: CreateSiteData): Promise<SiteRow> {
  const [row] = await db('sites')
    .insert({ ...toColumns(data), tenant_id: tenantId })
    .returning<SiteRow[]>('*');
  emitToTenant(tenantId, SOCKET_EVENTS.SITE_CREATED, { site: toSiteDto(row) });
  return row;
}

export async function updateSite(
  tenantId: number,
  id: number,
  data: UpdateSiteData,
): Promise<SiteRow | undefined> {
  const columns = toColumns(data);
  if (Object.keys(columns).length === 0) return getSite(tenantId, id);

  const [row] = await db('sites')
    .where({ id, tenant_id: tenantId })
    .update({ ...columns, updated_at: db.fn.now() })
    .returning<SiteRow[]>('*');
  if (row) emitToTenant(tenantId, SOCKET_EVENTS.SITE_UPDATED, { site: toSiteDto(row) });
  return row;
}

/**
 * Delete a site. `devices.site_id` is ON DELETE SET NULL, so the routers
 * survive and land back in the unfiled pool — deleting an administrative
 * grouping must never delete the fleet that was in it.
 */
export async function deleteSite(tenantId: number, id: number): Promise<boolean> {
  const deleted = await db('sites').where({ id, tenant_id: tenantId }).delete();
  if (deleted > 0) emitToTenant(tenantId, SOCKET_EVENTS.SITE_DELETED, { siteId: id });
  return deleted > 0;
}

export interface SitePresenceRow {
  deviceId: number;
  name: string;
  pppUsername: string | null;
  up: boolean;
  since: string | null;
  tunnelIp: string | null;
  verdict: string | null;
  verdictAt: string | null;
}

/**
 * Presence of every device on a site, with its latest K7 verdict.
 *
 * The verdict is joined in rather than recomputed: `reachability_verdicts` is a
 * change log, so the latest row IS the current verdict, and re-deriving it here
 * would be a second implementation of the truth table waiting to disagree with
 * the first.
 */
export async function sitePresence(tenantId: number, siteId: number): Promise<SitePresenceRow[]> {
  const rows = await db('devices as d')
    .where({ 'd.tenant_id': tenantId, 'd.site_id': siteId })
    .leftJoin('ppp_sessions as p', function joinOpen(this: any) {
      this.on('p.device_id', '=', 'd.id').andOnNull('p.ended_at');
    })
    .leftJoin(
      db('reachability_verdicts')
        .distinctOn('device_id')
        .select('device_id', 'verdict', 'ts')
        .orderBy('device_id')
        .orderBy('ts', 'desc')
        .as('v'),
      'v.device_id',
      'd.id',
    )
    .select<
      Array<{
        id: number;
        name: string;
        ppp_username: string | null;
        started_at: Date | null;
        tunnel_ip: string | null;
        verdict: string | null;
        ts: Date | null;
      }>
    >('d.id', 'd.name', 'd.ppp_username', 'p.started_at', 'p.tunnel_ip', 'v.verdict', 'v.ts')
    .orderBy('d.name');

  return rows.map((r) => ({
    deviceId: r.id,
    name: r.name,
    pppUsername: r.ppp_username,
    up: r.started_at !== null,
    since: r.started_at ? r.started_at.toISOString() : null,
    tunnelIp: r.tunnel_ip,
    verdict: r.verdict,
    verdictAt: r.ts ? r.ts.toISOString() : null,
  }));
}

// ============================================================================
// PPP timeline
// ============================================================================

export interface SitePppSessionDto {
  id: string;
  concentratorId: number;
  deviceId: number | null;
  deviceName: string | null;
  pppUsername: string;
  tunnelIp: string | null;
  callerIp: string | null;
  startedAt: string;
  /** null = the session is still open. */
  endedAt: string | null;
  durationSeconds: number | null;
  disconnectReason: string | null;
}

/**
 * The site's PPP chronology (spec §4.2): every session, open or closed, of
 * every device currently filed under this site.
 *
 * Scoping goes through `devices`, which carries the tenant — `ppp_sessions`
 * does not, because a session is observed on the concentrator before anybody
 * has decided whose it is. The JOIN is therefore the access check, not a
 * convenience: no device row in this tenant, no session row out.
 *
 * A site with no session yet returns `[]`, and that is a real answer meaning
 * "nothing has ever dialled". The client distinguishes it from `null` ("the
 * endpoint does not exist"), which is why this route exists at all rather than
 * leaving the page to guess.
 */
export async function sitePppSessions(
  tenantId: number,
  siteId: number,
  limit = 100,
): Promise<SitePppSessionDto[]> {
  const rows = await db('ppp_sessions as p')
    .join('devices as d', 'd.id', 'p.device_id')
    .where({ 'd.tenant_id': tenantId, 'd.site_id': siteId })
    .orderBy('p.started_at', 'desc')
    .limit(limit)
    .select<
      Array<{
        id: string;
        concentrator_id: number;
        device_id: number | null;
        device_name: string;
        ppp_username: string;
        tunnel_ip: string | null;
        caller_ip: string | null;
        started_at: Date;
        ended_at: Date | null;
        duration_seconds: number | null;
        disconnect_reason: string | null;
      }>
    >(
      'p.id',
      'p.concentrator_id',
      'p.device_id',
      'd.name as device_name',
      'p.ppp_username',
      'p.tunnel_ip',
      'p.caller_ip',
      'p.started_at',
      'p.ended_at',
      'p.duration_seconds',
      'p.disconnect_reason',
    );

  return rows.map((r) => ({
    id: String(r.id),
    concentratorId: r.concentrator_id,
    deviceId: r.device_id,
    deviceName: r.device_name,
    pppUsername: r.ppp_username,
    tunnelIp: r.tunnel_ip,
    callerIp: r.caller_ip,
    startedAt: r.started_at.toISOString(),
    endedAt: r.ended_at ? r.ended_at.toISOString() : null,
    durationSeconds: r.duration_seconds,
    disconnectReason: r.disconnect_reason,
  }));
}
