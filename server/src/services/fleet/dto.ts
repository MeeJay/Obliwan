/**
 * ObliWAN — the fleet's wire shapes.
 *
 * THE RULE THIS FILE EXISTS TO HOLD: the database speaks `snake_case`, the API
 * speaks `camelCase`, and the translation happens HERE, at the edge, once.
 *
 * It was previously not happening at all: `sites`, `devices` and `discoveries`
 * handed their raw Knex rows to `res.json()`, so the client received
 * `ppp_username` / `site_id` / `is_managed` while every client-side type,
 * store and page was written against `pppUsername` / `siteId` / `isManaged`.
 * Nothing crashed — `undefined` renders as blank — which is precisely why it
 * survived: a device page silently missing its PPP identity looks like a
 * device that has none.
 *
 * SECOND RULE, non-negotiable (section 8.2): `secret_enc` and
 * `private_key_enc` do not appear in this file, in either direction. A
 * transport is serialised by `toPublicTransport()` in `device.service.ts`,
 * which emits `hasSecret` / `hasPrivateKey` booleans and nothing derived from
 * the ciphertext — not its length, not a mask, not the encrypted blob "because
 * it is encrypted anyway". Ciphertext plus a key that leaks later is still a
 * credential; the API never carries it.
 *
 * A note on what these mappers do NOT do: they never invent a field. A join
 * that was not performed yields `null` or an absent key, so the UI can say "not
 * known" instead of rendering a confident wrong answer.
 */

import type { DeviceRow, DeviceListItem, PublicTransport } from './device.service';
import type { SiteRow, SiteWithCounts } from './site.service';
import type { DiscoveryRow } from './concentratorDiscovery.service';

// ============================================================================
// Small helpers
// ============================================================================

/** Postgres timestamps arrive as `Date`; the wire carries ISO-8601 strings. */
function iso(value: Date | string | null | undefined): string | null {
  if (value == null) return null;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function isoRequired(value: Date | string): string {
  return iso(value) ?? new Date(0).toISOString();
}

/** `jsonb` comes back parsed from `pg`, but a column written as a string by an
 *  older path can still arrive as text. Never throw on a display field. */
function json<T>(value: unknown, fallback: T): T {
  if (value == null) return fallback;
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  return value as T;
}

// ============================================================================
// Sites
// ============================================================================

export interface SiteDto {
  id: number;
  uuid: string;
  tenantId: number;
  code: string;
  name: string;
  address: string | null;
  contact: string | null;
  timezone: string;
  maintenanceWindow: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
  /** Present only on the list endpoint, which computes them in SQL. */
  deviceCount?: number;
  onlineCount?: number;
}

export function toSiteDto(row: SiteRow | SiteWithCounts): SiteDto {
  const counts = row as Partial<SiteWithCounts>;
  const dto: SiteDto = {
    id: row.id,
    uuid: row.uuid,
    tenantId: row.tenant_id,
    code: row.code,
    name: row.name,
    address: row.address,
    contact: row.contact,
    timezone: row.timezone,
    maintenanceWindow: json<Record<string, unknown> | null>(row.maintenance_window, null),
    createdAt: isoRequired(row.created_at),
    updatedAt: isoRequired(row.updated_at),
  };
  if (counts.device_count !== undefined) dto.deviceCount = Number(counts.device_count);
  if (counts.online_count !== undefined) dto.onlineCount = Number(counts.online_count);
  return dto;
}

// ============================================================================
// Devices
// ============================================================================

/**
 * The client's third presence value.
 *
 * `up: null` means "nothing has been observed yet" and is NOT `false`. Folding
 * the two together is how a healthy fleet turns red on a page load, so the
 * distinction is carried on the wire rather than reconstructed in the UI.
 */
export interface DevicePresenceDto {
  up: boolean | null;
  verdict: string | null;
  at: string | null;
}

export interface DeviceDto {
  id: number;
  uuid: string;
  tenantId: number;
  siteId: number | null;
  siteName: string | null;
  siteCode: string | null;
  groupId: number | null;
  name: string;
  brand: string;
  family: string;
  model: string | null;
  serial: string | null;
  osVersion: string | null;
  role: string;
  concentratorId: number | null;
  pppUsername: string | null;
  systemIdentity: string | null;
  tunnelIp: string | null;
  wanPublicIp: string | null;
  sourceIpHint: string | null;
  status: string;
  isManaged: boolean;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
  presence?: DevicePresenceDto | null;
}

export function toDeviceDto(row: DeviceRow | DeviceListItem): DeviceDto {
  const listed = row as Partial<DeviceListItem>;
  const dto: DeviceDto = {
    id: row.id,
    uuid: row.uuid,
    tenantId: row.tenant_id,
    siteId: row.site_id,
    siteName: listed.site_name ?? null,
    siteCode: listed.site_code ?? null,
    groupId: row.group_id,
    name: row.name,
    brand: row.brand,
    family: row.family,
    model: row.model,
    serial: row.serial,
    osVersion: row.os_version,
    role: row.role,
    concentratorId: row.concentrator_id,
    pppUsername: row.ppp_username,
    systemIdentity: row.system_identity,
    tunnelIp: row.tunnel_ip,
    wanPublicIp: row.wan_public_ip,
    sourceIpHint: row.source_ip_hint,
    status: row.status,
    isManaged: row.is_managed,
    firstSeenAt: iso(row.first_seen_at),
    lastSeenAt: iso(row.last_seen_at),
    notes: row.notes,
    createdAt: isoRequired(row.created_at),
    updatedAt: isoRequired(row.updated_at),
  };

  // Only the list query joins presence. A row that did not carry the join gets
  // no `presence` key at all rather than a fabricated "down".
  if (listed.ppp_up !== undefined) {
    dto.presence = {
      up: listed.ppp_up,
      verdict: listed.verdict ?? null,
      at: listed.ppp_since ?? null,
    };
  }
  return dto;
}

export interface DeviceHealthDto {
  transport: string;
  connState: string;
  circuitState: string;
  consecutiveFailures: number;
  nextRetryAt: string | null;
  lastError: string | null;
}

export interface DeviceDetailDto extends DeviceDto {
  transports: PublicTransport[];
  health: DeviceHealthDto[];
}

/**
 * `getDeviceDetail()` already returns camelCase for its joined blocks
 * (`transports`, `health`, `pppUp`, `verdict`); only the device row itself was
 * raw. This folds the two halves into one shape.
 */
export function toDeviceDetailDto(detail: {
  transports: PublicTransport[];
  health: DeviceHealthDto[];
  pppUp: boolean;
  verdict: string | null;
} & DeviceRow): DeviceDetailDto {
  const { transports, health, pppUp, verdict, ...row } = detail;
  return {
    ...toDeviceDto(row as DeviceRow),
    transports,
    health,
    presence: { up: pppUp, verdict, at: iso(row.last_seen_at) },
  };
}

// ============================================================================
// Discoveries
// ============================================================================

export interface DiscoveryDto {
  id: number;
  uuid: string;
  concentratorId: number;
  concentratorName: string | null;
  pppUsername: string;
  remoteAddress: string | null;
  callerIp: string | null;
  profile: string | null;
  pppComment: string | null;
  raw: Record<string, unknown>;
  state: string;
  boundDeviceId: number | null;
  reviewedBy: number | null;
  reviewedAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
}

export function toDiscoveryDto(
  row: DiscoveryRow & { concentrator_name?: string | null },
): DiscoveryDto {
  return {
    id: row.id,
    uuid: row.uuid,
    concentratorId: row.concentrator_id,
    concentratorName: row.concentrator_name ?? null,
    pppUsername: row.ppp_username,
    remoteAddress: row.remote_address,
    callerIp: row.caller_ip,
    profile: row.profile,
    pppComment: row.ppp_comment,
    raw: json<Record<string, unknown>>(row.raw, {}),
    state: row.state,
    boundDeviceId: row.bound_device_id,
    reviewedBy: row.reviewed_by,
    reviewedAt: iso(row.reviewed_at),
    firstSeenAt: isoRequired(row.first_seen_at),
    lastSeenAt: isoRequired(row.last_seen_at),
  };
}
