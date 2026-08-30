/**
 * ObliWAN — RouterOS capability matrix (risk R11).
 *
 * RouterOS 6 and RouterOS 7 are not the same product wearing two version
 * numbers. `/system/health` returns ONE record on v6 and a row per sensor on
 * v7; wireless lives under `/interface/wireless` on v6 and `/interface/wifi`
 * (or `/interface/wifiwave2` on early 7.x) on v7; `/system/routerboard` traps
 * outright on a CHR because there is no routerboard.
 *
 * The rule this file exists to enforce: a collector NEVER hard-codes a menu
 * path. It asks the matrix. The matrix is probed once per session, cached, and
 * invalidated when the connection dies or the box is upgraded.
 *
 * Probing is deliberately defensive: every optional probe is wrapped so that a
 * `!trap` means "this box cannot do that", not "the whole probe failed". Only
 * `/system/resource/print` is mandatory — a device that cannot answer it is
 * not a RouterOS device we can drive.
 */

import { LRUCache } from 'lru-cache';
import type { DeviceCapabilities, DeviceFamily } from '@obliwan/shared';
import { NO_CAPABILITIES } from '@obliwan/shared';
import { logger } from '../../../utils/logger';
import { RouterOsConnection } from './connection';
import { RouterOsTrapError } from './protocol';

// ============================================================================
// Shape of the matrix
// ============================================================================

/** How `/system/health/print` answers on this firmware. */
export type HealthShape = 'record' | 'rows' | 'unsupported';

/** Menu paths, resolved per firmware. Collectors read these, never literals. */
export interface RouterOsPaths {
  identity: string;
  resource: string;
  routerboard: string | null;
  /** `null` when the box has no health sensors at all (CHR, x86). */
  health: string | null;
  interfaces: string;
  interfaceMonitorTraffic: string;
  ipAddress: string;
  ipRoute: string;
  firewallFilter: string;
  firewallNat: string;
  firewallAddressList: string;
  dhcpServerLease: string;
  /** `/interface/wifi` (7.x), `/interface/wifiwave2` (early 7.x),
   *  `/interface/wireless` (6.x), or `null` when no wireless package. */
  wireless: string | null;
  pppActive: string;
  pppActiveListen: string;
  pppSecret: string;
  log: string;
  logListen: string;
  export: string;
}

export interface RouterOsCapabilityMatrix {
  probedAt: Date;
  /** Raw `=version=` as reported, e.g. `7.14.3 (stable)`. */
  version: string;
  major: number;
  minor: number;
  patch: number;
  /** Release channel word in parentheses, when present. */
  channel: string | null;
  family: Extract<DeviceFamily, 'mikrotik_routeros6' | 'mikrotik_routeros7'>;
  identity: string | null;
  boardName: string | null;
  platform: string | null;
  architecture: string | null;
  /** From `/system/routerboard`. `null` on CHR / x86 (D5 falls back to
   *  `ppp_username` + `system_identity` there). */
  serialNumber: string | null;
  healthShape: HealthShape;
  hasRouterboard: boolean;
  hasWireless: boolean;
  /** The box answered `/ppp/active/print`: it is a PPP concentrator (D4). */
  hasPppServer: boolean;
  paths: RouterOsPaths;
  /** Honest, user-visible gaps discovered while probing. */
  notes: string[];
}

// ============================================================================
// Version parsing
// ============================================================================

const VERSION_RE = /^\s*(\d+)\.(\d+)(?:\.(\d+))?\s*(?:\(([^)]*)\))?/;

export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  channel: string | null;
}

/** Parse `7.14.3 (stable)` / `6.49.10 (long-term)` / `7.16`. */
export function parseRouterOsVersion(raw: string): ParsedVersion {
  const m = VERSION_RE.exec(raw ?? '');
  if (!m) return { major: 0, minor: 0, patch: 0, channel: null };
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: m[3] ? Number(m[3]) : 0,
    channel: m[4] ?? null,
  };
}

/** RouterOS 6 and 7 are separate `DeviceFamily` values on purpose (R11). */
export function familyForVersion(major: number): RouterOsCapabilityMatrix['family'] {
  return major >= 7 ? 'mikrotik_routeros7' : 'mikrotik_routeros6';
}

// ============================================================================
// Probing
// ============================================================================

const PROBE_TIMEOUT_MS = 8_000;

/**
 * Run an optional probe. A `!trap` (typically "no such command") means the
 * feature is absent on this firmware, which is information, not a failure.
 * Anything else (timeout, dead socket) propagates: those are real problems.
 */
async function optionalQuery(
  conn: RouterOsConnection,
  words: string[],
): Promise<Record<string, string>[] | null> {
  try {
    return await conn.query(words, { timeoutMs: PROBE_TIMEOUT_MS });
  } catch (err) {
    if (err instanceof RouterOsTrapError) return null;
    throw err;
  }
}

function basePaths(major: number): RouterOsPaths {
  const v7 = major >= 7;
  return {
    identity: '/system/identity/print',
    resource: '/system/resource/print',
    routerboard: '/system/routerboard/print',
    health: '/system/health/print',
    interfaces: '/interface/print',
    interfaceMonitorTraffic: '/interface/monitor-traffic',
    ipAddress: '/ip/address/print',
    // RouterOS 7 splits the routing stack; `/ip/route/print` still works on
    // both, and is the only path that does.
    ipRoute: '/ip/route/print',
    firewallFilter: '/ip/firewall/filter/print',
    firewallNat: '/ip/firewall/nat/print',
    firewallAddressList: '/ip/firewall/address-list/print',
    dhcpServerLease: '/ip/dhcp-server/lease/print',
    wireless: v7 ? '/interface/wifi/print' : '/interface/wireless/print',
    pppActive: '/ppp/active/print',
    pppActiveListen: '/ppp/active/listen',
    pppSecret: '/ppp/secret/print',
    log: '/log/print',
    logListen: '/log/listen',
    // R10: `show-sensitive` is pinned off. Never make this configurable.
    export: '/export',
  };
}

/**
 * Interrogate a live session and build its capability matrix.
 * Cheap enough (4 to 6 short commands) to run on every fresh connection.
 */
export async function probeCapabilities(
  conn: RouterOsConnection,
): Promise<RouterOsCapabilityMatrix> {
  const notes: string[] = [];

  // --- mandatory ----------------------------------------------------------
  const resource = await conn.queryFirst(['/system/resource/print'], {
    timeoutMs: PROBE_TIMEOUT_MS,
  });
  if (!resource) {
    throw new Error(`${conn.target} answered /system/resource/print with no row; not a usable RouterOS device`);
  }
  const version = resource.version ?? '';
  const { major, minor, patch, channel } = parseRouterOsVersion(version);
  if (major === 0) {
    notes.push(`Unrecognised RouterOS version string "${version}"; assuming the v6 dialect.`);
  }
  const paths = basePaths(major);

  // --- identity -----------------------------------------------------------
  const identityRow = await optionalQuery(conn, ['/system/identity/print']);
  const identity = identityRow?.[0]?.name ?? null;

  // --- routerboard (absent on CHR / x86) ----------------------------------
  const rb = await optionalQuery(conn, ['/system/routerboard/print']);
  const rbRow = rb?.[0] ?? null;
  const hasRouterboard = rbRow ? rbRow.routerboard === 'true' || rbRow['routerboard'] === 'yes' : false;
  const serialNumber = rbRow?.['serial-number'] ?? null;
  if (!rbRow) {
    paths.routerboard = null;
    notes.push('No /system/routerboard: virtual or x86 install, so there is no hardware serial to key identity on (D5 falls back to ppp_username + identity).');
  }

  // --- health: THE R11 divergence -----------------------------------------
  let healthShape: HealthShape = 'unsupported';
  const health = await optionalQuery(conn, ['/system/health/print']);
  if (health === null || health.length === 0) {
    paths.health = null;
    notes.push('No /system/health readings on this box (typical of CHR and x86): temperature and voltage will stay empty.');
  } else if (health.length >= 1 && health[0].name !== undefined && health[0].value !== undefined) {
    // RouterOS 7: one row per sensor, `=name=temperature =value=41`.
    healthShape = 'rows';
  } else {
    // RouterOS 6: a single record, `=temperature=41 =voltage=24.1`.
    healthShape = 'record';
  }

  // --- wireless: /interface/wifi vs /interface/wireless -------------------
  let wirelessPath: string | null = null;
  const candidates =
    major >= 7
      ? ['/interface/wifi/print', '/interface/wifiwave2/print', '/interface/wireless/print']
      : ['/interface/wireless/print'];
  for (const candidate of candidates) {
    const res = await optionalQuery(conn, [candidate, '=.proplist=.id']);
    if (res !== null) {
      wirelessPath = candidate;
      break;
    }
  }
  paths.wireless = wirelessPath;
  if (!wirelessPath) {
    notes.push('No wireless package installed; wireless collection is skipped for this device.');
  }

  // --- PPP server (is this the concentrator?) -----------------------------
  const ppp = await optionalQuery(conn, ['/ppp/active/print', '=.proplist=.id']);
  const hasPppServer = ppp !== null;

  const matrix: RouterOsCapabilityMatrix = {
    probedAt: new Date(),
    version,
    major,
    minor,
    patch,
    channel,
    family: familyForVersion(major),
    identity,
    boardName: resource['board-name'] ?? null,
    platform: resource.platform ?? null,
    architecture: resource['architecture-name'] ?? null,
    serialNumber,
    healthShape,
    hasRouterboard,
    hasWireless: wirelessPath !== null,
    hasPppServer,
    paths,
    notes,
  };

  logger.debug(
    {
      target: conn.target,
      version: matrix.version,
      family: matrix.family,
      healthShape: matrix.healthShape,
      wireless: matrix.paths.wireless,
      hasPppServer: matrix.hasPppServer,
    },
    'RouterOS capability matrix probed',
  );
  return matrix;
}

// ============================================================================
// Projection onto the shared DeviceCapabilities contract
// ============================================================================

/**
 * Translate the RouterOS matrix into the brand-agnostic contract the rest of
 * ObliWAN reads. Write flags stay `false`: the write paths land in M6, and the
 * safe default of `NO_CAPABILITIES` is "we do not know how", which surfaces as
 * a refusal instead of a half-applied change.
 */
export function toDeviceCapabilities(matrix: RouterOsCapabilityMatrix): DeviceCapabilities {
  return {
    ...NO_CAPABILITIES,
    supportsRouterosApi: true,
    supportsSsh: true,
    supportsSnmp: true,
    transportPriority: ['routeros_api', 'ssh', 'snmp'],

    canExportConfig: true,
    canReadInterfaces: true,
    canReadRoutes: true,
    canReadVlans: true,
    canReadFirewall: true,
    canReadDhcpLeases: true,
    canReadTunnels: true,
    canReadLogs: true,
    canReadPppSessions: matrix.hasPppServer,
    canStreamPppEvents: matrix.hasPppServer,

    configFormat: 'text_cli',
    applyGranularity: 'line',
    supportsStructuredDiff: true,

    // One socket per device, multiplexed by `.tag=`. The concentrator is the
    // hard case (risk R5) and the pool enforces the same rule there.
    maxConcurrentSessions: 1,
    minPollIntervalMs: 15_000,
    notes: matrix.notes,
  };
}

// ============================================================================
// Cache
// ============================================================================

const DEFAULT_TTL_MS = 15 * 60_000;

const cache = new LRUCache<string, RouterOsCapabilityMatrix>({
  max: 2_000,
  ttl: DEFAULT_TTL_MS,
});

/**
 * Probe once per cache key (use the `devices.id`), then reuse.
 * `force` re-probes: call it after a firmware upgrade or a package change.
 */
export async function getCapabilities(
  conn: RouterOsConnection,
  cacheKey: string,
  opts: { force?: boolean } = {},
): Promise<RouterOsCapabilityMatrix> {
  if (!opts.force) {
    const hit = cache.get(cacheKey);
    if (hit) return hit;
  }
  const matrix = await probeCapabilities(conn);
  cache.set(cacheKey, matrix);
  return matrix;
}

/** Read the cache without touching the device. */
export function peekCapabilities(cacheKey: string): RouterOsCapabilityMatrix | undefined {
  return cache.get(cacheKey);
}

/** Drop one entry — call this when a device connection dies or is upgraded. */
export function invalidateCapabilities(cacheKey: string): void {
  cache.delete(cacheKey);
}

/** Drop everything (tests, and the leader handover path). */
export function clearCapabilityCache(): void {
  cache.clear();
}
