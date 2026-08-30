/**
 * ObliWAN F5 — the ACTIVE EGRESS PATH: is this router going out over its
 * designated WAN port, or over LTE?
 *
 * ┌─ RISK R11: THE MENU PATH IS NEVER A LITERAL ──────────────────────────────┐
 * │ `services/transport/routeros/capabilities.ts` probes a capability matrix  │
 * │ once per session and caches it. Collectors read `matrix.paths.*`; nobody  │
 * │ writes `/ip/route/print` in a collector, because RouterOS 6 and 7 are two │
 * │ products wearing one brand name.                                          │
 * │                                                                          │
 * │ The default route comes straight from that matrix — `paths.ipRoute`.      │
 * │                                                                          │
 * │ The CELLULAR menus are not in `RouterOsPaths` yet, and that file is not   │
 * │ F5's to rewrite. So this file EXTENDS the matrix rather than bypassing    │
 * │ it: `resolveCellularPaths()` PROBES a candidate list with the same        │
 * │ trap-tolerant discipline (`!trap` means "this firmware cannot do that",   │
 * │ anything else propagates), caches per device, and is invalidated with the │
 * │ matrix. It is a matrix extension, not a hard-coded path — no branch of    │
 * │ this file can reach a menu the box has not answered.                      │
 * │                                                                          │
 * │ PROBE-SELECTED, NOT VERSION-SELECTED, AND THE DIFFERENCE WAS A LIE.       │
 * │ This block used to say "version-selected", and `cellularCandidates()`     │
 * │ took a `major` and branched on it — into two IDENTICAL arrays. A rule     │
 * │ stated in a header and applied nowhere is the failure mode this project   │
 * │ keeps paying for, so the claim is gone and so is the parameter. The real  │
 * │ discriminator is the box: `/interface/lte` and `/interface/ppp-client`    │
 * │ exist on both 6 and 7, and which of them ANSWERS is the only fact worth   │
 * │ having. Nothing here pretends to know a menu it has not been told about.  │
 * │                                                                          │
 * │ WHAT THAT COSTS, STATED RATHER THAN HIDDEN: a firmware whose cellular     │
 * │ menu is neither of the two — the v7 `esim` builds — resolves to "no       │
 * │ cellular menu", records that as a note, and falls through to the SNMP     │
 * │ IANAifType net below, which is brand-agnostic and catches it. The site    │
 * │ reads `lte` from SNMP or `unknown` from neither; it never reads a         │
 * │ confident `wan_port` it has not earned. Adding `/interface/lte/esim` to   │
 * │ the list WITHOUT a box to verify against would be worse than the gap: it  │
 * │ lists eSIM PROFILES, not interfaces, and a profile row parsed as an       │
 * │ interface is a fabricated egress rather than a missing one.               │
 * │                                                                          │
 * │ WHEN `RouterOsPaths` NEXT CHANGES, `lte` / `lteMonitor` belong in it —    │
 * │ and that is where a genuinely version-keyed menu goes, next to every      │
 * │ other one, instead of a second version table living here.                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE GENERIC HALF, AND WHY IT IS NOT OPTIONAL ────────────────────────────┐
 * │ A Vigor and a Zyxel have no `/interface/lte` and never will. The          │
 * │ brand-agnostic identification is `snmp_interfaces.if_type` — IANAifType   │
 * │ 243/244 is a cellular interface on every agent that implements IF-MIB.    │
 * │ `resolveEgressFromSnmp` is that path, and it reads a table that already   │
 * │ exists (M3). It is a COMPLEMENT, consulted when the RouterOS answer is    │
 * │ absent or inconclusive, never a second opinion that overrides a live one. │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE PUBLIC ADDRESS, AND THE ONE INVERSION THAT MUST NEVER HAPPEN ────────┐
 * │ `devices.wan_public_ip` is written by `applySessionUp` from the PPP       │
 * │ `caller-id`: the address AS SEEN BY THE CONCENTRATOR. It is an            │
 * │ OBSERVATION FROM OUTSIDE, so it is correct behind a NAT and cannot be     │
 * │ forged by the router. It is the primary source and this file never writes │
 * │ to it.                                                                    │
 * │                                                                          │
 * │ The fallback, used ONLY when the observation is missing, is the address   │
 * │ CONFIGURED ON THE ACTIVE EGRESS INTERFACE, read from the box. Note what   │
 * │ it is not: it is not an outbound fetch to a "what is my IP" service.      │
 * │ That would publish the customer's topology to a third party, make the     │
 * │ router perform a network action on our behalf, and fail precisely during  │
 * │ the outage this feature exists to detect. A configured address is a pure  │
 * │ read of state the box already holds.                                      │
 * │                                                                          │
 * │ The precedence is not enforced here. It is enforced by                    │
 * │ `device_wan_path.effective_public_ip`, a GENERATED column                 │
 * │ (COALESCE(observed, reported)) that no statement can invert.              │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * D3: nothing in this file writes to an equipment. `/ip/route/print`,
 * `/interface/lte/print`, `/interface/lte/monitor once` and `/ip/address/print`
 * are reads. The only rows written are `device_wan_path`.
 */

import {
  isCellularIfType, looksCellularByName,
  type WanPathKind, type WeatherSource,
} from '@obliwan/shared/dist/weather';
import type { RouterOsCapabilityMatrix } from '../transport/routeros';
import { getCapabilities } from '../transport/routeros';
import {
  getRouterOsPool, resolveRouterOsTarget, NoRouterOsTransportError,
} from '../fleet/routerosPool';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { attributeAddress } from './asn.service';

// ============================================================================
// 1. The matrix extension (R11)
// ============================================================================

/** The minimum of a RouterOS session this module needs. Injectable, so the
 *  whole resolution is exercised offline against a scripted box. */
export interface RouterOsQueryable {
  query(words: string[], opts?: { timeoutMs?: number }): Promise<Record<string, string>[]>;
}

export interface CellularPaths {
  /** `/interface/lte/print` or null when the firmware has no cellular menu. */
  lte: string | null;
  /** `/interface/lte/monitor` or null. */
  lteMonitor: string | null;
  notes: string[];
}

/**
 * The menus a cellular interface can live under, in the order they are tried.
 *
 * ONE list, and no version branch. Both entries exist on RouterOS 6 and 7
 * alike, so a `major >= 7 ? A : B` over them selects nothing — which is what
 * the previous version of this function did, with two byte-identical arrays
 * behind a ternary and a header claiming the selection was real.
 *
 * The box decides instead: each candidate is probed and a `!trap` ("no such
 * command") moves on to the next. If a future firmware genuinely keys a menu
 * to its major version, that belongs in `RouterOsPaths` with every other
 * version-keyed path, not in a second version table here.
 */
const CELLULAR_MENU_CANDIDATES: ReadonlyArray<{ lte: string; monitor: string }> = [
  { lte: '/interface/lte/print', monitor: '/interface/lte/monitor' },
  { lte: '/interface/ppp-client/print', monitor: '/interface/ppp-client/monitor' },
];

const cellularCache = new Map<string, CellularPaths>();

/** Drop a device's cached cellular menus. Called on a firmware change, and by
 *  the self-test between scripted boxes. */
export function invalidateCellularPaths(cacheKey: string): void {
  cellularCache.delete(cacheKey);
}

/**
 * Probe which cellular menu this firmware answers.
 *
 * The matrix is NOT a parameter: the two candidate menus below exist on both
 * major versions, so nothing here can be selected by one. It used to take a
 * `major` and branch on it into two identical lists. The cache key is still
 * per device and still invalidated on a dead session, which is what actually
 * covers a box upgraded across the 6/7 boundary.
 *
 * Trap-tolerant exactly like `capabilities.ts`: a `!trap` is the box saying
 * "no such command", which is information. Anything else (dead socket,
 * timeout) propagates, because those are real problems and swallowing them
 * would report "no LTE on this site" for a router that is simply unreachable —
 * and "no LTE" is a fact this feature would act on.
 */
export async function resolveCellularPaths(
  conn: RouterOsQueryable,
  cacheKey: string,
): Promise<CellularPaths> {
  const hit = cellularCache.get(cacheKey);
  if (hit) return hit;

  const notes: string[] = [];
  let resolved: CellularPaths = { lte: null, lteMonitor: null, notes };

  for (const candidate of CELLULAR_MENU_CANDIDATES) {
    let rows: Record<string, string>[] | null;
    try {
      rows = await conn.query([candidate.lte, '=.proplist=.id'], { timeoutMs: 8_000 });
    } catch (err) {
      if (isTrap(err)) {
        rows = null;
      } else {
        throw err;
      }
    }
    if (rows !== null) {
      resolved = { lte: candidate.lte, lteMonitor: candidate.monitor, notes };
      break;
    }
  }

  if (!resolved.lte) {
    notes.push(
      'No cellular menu on this firmware: LTE presence falls back to the generic ' +
        'IANAifType signal from SNMP (snmp_interfaces.if_type).',
    );
  }
  cellularCache.set(cacheKey, resolved);
  return resolved;
}

/** A RouterOS `!trap` — "no such command" — rather than a transport failure.
 *  Matched by name so this module does not import the protocol internals. */
function isTrap(err: unknown): boolean {
  return err instanceof Error && err.name === 'RouterOsTrapError';
}

/**
 * The width of `device_wan_path.egress_interface`, and of the column the value
 * is read from (`snmp_interfaces.if_name`, migration 005), and of IF-MIB's
 * `ifName` itself. Migration 023 widened this column from 64 to here: an
 * eighty-four character `ifName` — ordinary on an agent that derives it from
 * `ifDescr` — aborted the INSERT with `value too long` and took
 * `POST /weather/devices/:deviceId/probe` down with it, invisibly to `tsc`.
 */
const EGRESS_INTERFACE_WIDTH = 255;

/**
 * The last resort under the widened column.
 *
 * The schema is the fix; this is the floor. The RouterOS half of the same
 * field is a name read off a live box (`immediate-gw`'s `%iface` suffix, or
 * `gateway-interface`) and no CHECK anywhere bounds what a router may call an
 * interface. A box inventing a four-hundred character name must degrade to a
 * shortened name, not to a 500 on the probe.
 */
function clampInterfaceName(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  return trimmed.length > EGRESS_INTERFACE_WIDTH
    ? trimmed.slice(0, EGRESS_INTERFACE_WIDTH)
    : trimmed;
}

// ============================================================================
// 2. Reading the box
// ============================================================================

export interface EgressObservation {
  pathKind: WanPathKind;
  egressInterface: string | null;
  gateway: string | null;
  distance: number | null;
  ltePresent: boolean;
  lteRegistered: boolean | null;
  /** The address configured on the egress interface, when it is a public one.
   *  FALLBACK ONLY — see the header. */
  reportedPublicIp: string | null;
  source: WeatherSource;
  notes: string[];
}

function truthy(value: string | undefined): boolean {
  return value === 'true' || value === 'yes';
}

/**
 * THE ACTIVE default route — the flagged one, not the first one printed.
 *
 * A router with a failover setup has TWO 0.0.0.0/0 routes at all times, one of
 * which is inactive; reading the first row would report the primary WAN as the
 * egress during the entire outage, which is the exact opposite of this
 * feature's job. RouterOS marks the live one `active=true`, and among several
 * the lowest `distance` wins.
 */
export function pickActiveDefaultRoute(
  rows: readonly Record<string, string>[],
): { gateway: string | null; iface: string | null; distance: number | null } | null {
  const defaults = rows.filter((r) => {
    const dst = r['dst-address'] ?? '';
    return dst === '0.0.0.0/0' || dst === '::/0';
  });
  const active = defaults.filter((r) => truthy(r.active) && !truthy(r.disabled));
  // The flagged routes and nothing else. This used to read
  // `active.length > 0 ? active : []` — a ternary whose two branches are the
  // same value, which reads like a fallback to the unflagged defaults and is
  // not one. Falling back would be WRONG here, not merely dead: a failover
  // router always has two default routes and picking the inactive one reports
  // the dead primary as the egress for the whole outage.
  const pool = active;
  if (pool.length === 0) return null;

  pool.sort((a, b) => Number(a.distance ?? '255') - Number(b.distance ?? '255'));
  const best = pool[0];
  // `immediate-gw` is `<ip>%<iface>` on v7 and is the only field that names the
  // interface a route actually leaves by; `gateway` alone is just an address.
  const immediate = best['immediate-gw'] ?? '';
  const viaIface = immediate.includes('%') ? immediate.split('%')[1] : null;
  return {
    gateway: (best.gateway ?? '').split('%')[0] || null,
    iface: viaIface ?? best['gateway-interface'] ?? null,
    distance: Number.isFinite(Number(best.distance)) ? Number(best.distance) : null,
  };
}

/**
 * Resolve the egress path from a live RouterOS session.
 *
 * `conn` is injected rather than dialled here so the whole decision is testable
 * against a scripted box, which is the only kind of box this project has.
 */
export async function resolveEgressFromRouter(
  conn: RouterOsQueryable,
  matrix: RouterOsCapabilityMatrix,
  cacheKey: string,
): Promise<EgressObservation> {
  const notes: string[] = [];

  // --- the active default route, through the matrix (never a literal) ------
  const routeRows = await conn.query([matrix.paths.ipRoute], { timeoutMs: 8_000 });
  const active = pickActiveDefaultRoute(routeRows);
  if (!active) {
    notes.push(
      'No ACTIVE default route on this router: it currently has no path to the ' +
        'internet at all, which is a stronger statement than "not on LTE".',
    );
  }

  // --- cellular menus, probed --------------------------------------------
  const cellular = await resolveCellularPaths(conn, cacheKey);
  notes.push(...cellular.notes);

  let ltePresent = false;
  let lteRegistered: boolean | null = null;
  const lteNames = new Set<string>();
  if (cellular.lte) {
    const lteRows = await conn.query([cellular.lte], { timeoutMs: 8_000 });
    ltePresent = lteRows.length > 0;
    for (const row of lteRows) {
      const name = row.name ?? row['default-name'] ?? null;
      if (name) lteNames.add(name);
      if (row.running !== undefined) {
        lteRegistered = (lteRegistered ?? false) || truthy(row.running);
      }
    }
  }

  // --- the verdict --------------------------------------------------------
  let pathKind: WanPathKind = 'unknown';
  let source: WeatherSource = 'routeros_route';
  const iface = active?.iface ?? null;
  if (active && iface) {
    if (lteNames.has(iface) || looksCellularByName(iface)) {
      pathKind = 'lte';
      source = 'routeros_lte';
    } else {
      // A resolved, non-cellular egress. `wan_port` means "the designated WAN
      // port", and the designation is the device's own: a route that leaves by
      // a named ethernet/PPPoE interface IS that port.
      pathKind = 'wan_port';
    }
  } else if (active && !iface) {
    notes.push(
      'The active default route names no egress interface on this firmware; ' +
        'the path is resolved but its kind is not.',
    );
  }

  // --- the fallback address, and only the fallback -------------------------
  let reportedPublicIp: string | null = null;
  if (iface) {
    const addrRows = await conn.query([matrix.paths.ipAddress], { timeoutMs: 8_000 });
    for (const row of addrRows) {
      if (row.interface !== iface || truthy(row.disabled)) continue;
      const bare = (row.address ?? '').split('/')[0];
      if (!bare) continue;
      const attribution = await attributeAddress(bare);
      // Only a PUBLIC address is worth recording as a self-reported WAN
      // address: a private one behind a carrier NAT tells us nothing and would
      // pollute the fallback with an address no correlation can use.
      if (attribution.scope === 'public') {
        reportedPublicIp = bare;
        break;
      }
    }
    if (!reportedPublicIp) {
      notes.push(
        'The egress interface carries no public address of its own (carrier NAT). ' +
          "The concentrator's caller-id observation is the only usable public address here.",
      );
    }
  }

  return {
    pathKind,
    egressInterface: iface,
    gateway: active?.gateway ?? null,
    distance: active?.distance ?? null,
    ltePresent,
    lteRegistered,
    reportedPublicIp,
    source,
    notes,
  };
}

// ============================================================================
// 3. The generic, brand-agnostic half
// ============================================================================

/**
 * Cellular identification from SNMP, for the brands that have no LTE menu.
 *
 * TENANT SCOPING: `snmp_interfaces` carries no tenant column (M3, and
 * deliberately), so the read joins `devices` and filters on `tenant_id`. That
 * join is the only thing between one customer and another customer's
 * interfaces, and this function is not exempt from it because it is "just a
 * fallback".
 */
export async function resolveEgressFromSnmp(
  tenantId: number,
  deviceId: number,
): Promise<Pick<EgressObservation, 'pathKind' | 'egressInterface' | 'ltePresent' | 'source' | 'notes'>> {
  const rows = await db('snmp_interfaces as si')
    .join('devices as d', 'd.id', 'si.device_id')
    .where('d.tenant_id', tenantId)
    .andWhere('si.device_id', deviceId)
    .andWhere('si.state', 'active')
    .select<Array<{ if_name: string; if_type: number | null; oper_status: number }>>(
      'si.if_name',
      'si.if_type',
      'si.oper_status',
    );

  if (rows.length === 0) {
    return {
      pathKind: 'unknown',
      egressInterface: null,
      ltePresent: false,
      source: 'snmp_if_type',
      notes: ['SNMP has never discovered an interface on this device; no generic egress signal.'],
    };
  }

  const cellular = rows.filter(
    (r) => isCellularIfType(r.if_type) || (!r.if_type && looksCellularByName(r.if_name)),
  );
  // ifOperStatus 1 = up. Only an UP cellular interface says anything about the
  // path actually in use; a present-but-down modem is a spare, not a failover.
  const up = cellular.find((r) => r.oper_status === 1);

  return {
    pathKind: up ? 'lte' : 'unknown',
    egressInterface: up?.if_name ?? null,
    ltePresent: cellular.length > 0,
    source: 'snmp_if_type',
    notes: up
      ? []
      : cellular.length > 0
        ? ['A cellular interface exists but is not up: this site is not on LTE right now.']
        : ['No cellular interface in the SNMP inventory for this device.'],
  };
}

// ============================================================================
// 4. Orchestration + persistence
// ============================================================================

interface DeviceRow {
  id: number;
  tenant_id: number;
  site_id: number | null;
  name: string;
  wan_public_ip: string | null;
}

export interface ObserveOptions {
  /** Inject a scripted session instead of dialling. The self-test uses this;
   *  nothing in production passes it. */
  connection?: RouterOsQueryable;
  matrix?: RouterOsCapabilityMatrix;
  /** Skip the RouterOS dial entirely and use only the generic SNMP signal. */
  offlineOnly?: boolean;
}

/**
 * Observe one device's egress path and persist it.
 *
 * ORDER, AND IT IS THE POINT:
 *   1. the RouterOS answer when we can get one — it is the only source that
 *      knows which route is ACTIVE;
 *   2. the generic SNMP signal otherwise, or to fill in `ltePresent` when the
 *      firmware has no cellular menu;
 *   3. the concentrator's `caller-id` for the public address, ALWAYS, and the
 *      router's self-report only into `reported_public_ip`, where the generated
 *      column decides it loses.
 */
export async function observeEgressPath(
  tenantId: number,
  deviceId: number,
  opts: ObserveOptions = {},
): Promise<{ deviceId: number; pathKind: WanPathKind; asn: number | null; notes: string[] }> {
  const device = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<DeviceRow | undefined>('id', 'tenant_id', 'site_id', 'name', 'wan_public_ip');
  if (!device) {
    // A device of another tenant is indistinguishable from a device that does
    // not exist. Never a different error: the id space is a bigserial and the
    // difference would be an enumeration oracle over other customers' fleets.
    throw new Error(`Device ${deviceId} not found`);
  }

  const notes: string[] = [];
  let router: EgressObservation | null = null;
  let matrixFamily: string | null = null;

  if (!opts.offlineOnly) {
    try {
      if (opts.connection && opts.matrix) {
        matrixFamily = opts.matrix.family;
        router = await resolveEgressFromRouter(opts.connection, opts.matrix, `device:${deviceId}`);
      } else {
        const target = await resolveRouterOsTarget(deviceId);
        router = await getRouterOsPool().withConnection(target, async (conn) => {
          const matrix = await getCapabilities(conn, `device:${deviceId}`);
          matrixFamily = matrix.family;
          return resolveEgressFromRouter(conn, matrix, `device:${deviceId}`);
        });
      }
    } catch (err) {
      if (err instanceof NoRouterOsTransportError) {
        notes.push('No RouterOS transport on this device; using the generic SNMP signal only.');
      } else {
        // The session died. Drop the cached cellular menus with it, exactly as
        // `capabilities.ts` invalidates its matrix on a dead connection: the
        // next successful dial may be a box that has been upgraded across the
        // 6/7 boundary, and answering it out of a stale cache is the
        // hard-coded-path failure R11 exists to prevent, one indirection later.
        invalidateCellularPaths(`device:${deviceId}`);
        // A dial failure is NOT "this site is not on LTE". It is "we do not
        // know", and the row must say so rather than record a confident
        // `wan_port` that a correlation would then trust.
        notes.push(
          `RouterOS egress probe failed (${err instanceof Error ? err.message.slice(0, 120) : 'unknown'}); ` +
            'path kind falls back to the generic signal.',
        );
        logger.debug({ err, deviceId }, 'F5 egress probe failed; falling back to SNMP');
      }
    }
  }

  const snmp = await resolveEgressFromSnmp(tenantId, deviceId);
  notes.push(...(router?.notes ?? []), ...snmp.notes);

  const pathKind: WanPathKind =
    router && router.pathKind !== 'unknown' ? router.pathKind : snmp.pathKind;
  const source: WeatherSource =
    router && router.pathKind !== 'unknown' ? router.source : snmp.source;

  const observed = device.wan_public_ip;
  const reported = router?.reportedPublicIp ?? null;
  const attribution = await attributeAddress(observed ?? reported);

  await db('device_wan_path')
    .insert({
      device_id: device.id,
      tenant_id: device.tenant_id,
      path_kind: pathKind,
      egress_interface: clampInterfaceName(
        router?.egressInterface ?? snmp.egressInterface ?? null,
      ),
      default_route_gateway: router?.gateway ?? null,
      default_route_distance: router?.distance ?? null,
      lte_present: (router?.ltePresent ?? false) || snmp.ltePresent,
      lte_registered: router?.lteRegistered ?? null,
      observed_public_ip: observed,
      reported_public_ip: reported,
      asn: attribution.asn?.asn ?? null,
      as_org: attribution.asn?.asOrg ?? null,
      country: attribution.asn?.country ?? null,
      region: attribution.asn?.region ?? null,
      ip_scope: attribution.scope,
      source,
      matrix_family: matrixFamily,
      note: notes.length > 0 ? notes.join(' ') : null,
      observed_at: db.fn.now(),
      updated_at: db.fn.now(),
    })
    .onConflict('device_id')
    .merge([
      'path_kind', 'egress_interface', 'default_route_gateway', 'default_route_distance',
      'lte_present', 'lte_registered', 'observed_public_ip', 'reported_public_ip',
      'asn', 'as_org', 'country', 'region', 'ip_scope', 'source', 'matrix_family',
      'note', 'observed_at', 'updated_at',
    ]);

  return { deviceId: device.id, pathKind, asn: attribution.asn?.asn ?? null, notes };
}

/**
 * Refresh the CONCENTRATOR-SIDE half for every device of a tenant, with no
 * dialling at all.
 *
 * This is what runs on every sweep: `devices.wan_public_ip` is already the
 * observation we trust, and turning it into an attributed row costs one query
 * plus a cached lookup per device. The RouterOS probe is reserved for devices
 * that actually moved, and for the on-demand route — dialling three hundred
 * routers every ten minutes to learn what the concentrator already told us
 * would be the most expensive way possible to be no better informed.
 *
 * `path_kind` and the LTE columns are deliberately NOT in the merge list: they
 * are the probe's to own, and a sweep must not overwrite a resolved `lte` with
 * `unknown` just because it did not dial.
 */
export async function refreshObservedPaths(tenantId: number): Promise<number> {
  const devices = await db('devices')
    .where({ tenant_id: tenantId })
    .whereNotNull('wan_public_ip')
    .select<Array<{ id: number; tenant_id: number; wan_public_ip: string }>>(
      'id', 'tenant_id', 'wan_public_ip',
    );

  let written = 0;
  for (const device of devices) {
    const attribution = await attributeAddress(device.wan_public_ip);
    await db('device_wan_path')
      .insert({
        device_id: device.id,
        tenant_id: device.tenant_id,
        observed_public_ip: device.wan_public_ip,
        asn: attribution.asn?.asn ?? null,
        as_org: attribution.asn?.asOrg ?? null,
        country: attribution.asn?.country ?? null,
        region: attribution.asn?.region ?? null,
        ip_scope: attribution.scope,
        source: 'ppp_caller_id',
        observed_at: db.fn.now(),
        updated_at: db.fn.now(),
      })
      .onConflict('device_id')
      // `source` is set on INSERT and never merged: it describes where
      // `path_kind` came from, and a sweep that did not dial must not relabel a
      // probe's `routeros_lte` verdict as a caller-id observation.
      .merge([
        'observed_public_ip', 'asn', 'as_org', 'country', 'region', 'ip_scope',
        'observed_at', 'updated_at',
      ]);
    written++;
  }
  return written;
}
