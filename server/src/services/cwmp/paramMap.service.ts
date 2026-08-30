/**
 * ObliWAN — `cwmp_param_map`: one canonical name, two data models, N vendors.
 *
 * ┌─ THE PROBLEM THIS TABLE EXISTS FOR ───────────────────────────────────────┐
 * │ "The WAN address of this CPE" is:                                         │
 * │   TR-098  InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.        │
 * │           WANPPPConnection.1.ExternalIPAddress                            │
 * │   TR-181  Device.IP.Interface.2.IPv4Address.1.IPAddress                   │
 * │ …and on a Zyxel EX it is interface 3, and on a Vigor with two WANs there  │
 * │ are two of them. Hardcoding either path anywhere outside this table means │
 * │ the NCM builder, the drift engine and the fleet query each grow their own │
 * │ vendor branch — which is exactly the failure decision D1 exists to avoid. │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ LEARN MODE, AND WHY IT DOES NOT USE GetParameterNames ───────────────────┐
 * │ Arbitrage A1 limits the ACS to four RPCs, and `GetParameterNames` is not  │
 * │ one of them. It does not need to be: in CWMP a name ending in `.` is a    │
 * │ PARTIAL PATH, and `GetParameterValues` on the root returns the entire     │
 * │ tree with its values. One RPC does the work of two, and the values it     │
 * │ brings back are the ones learn mode needs to decide which of three        │
 * │ candidate paths is actually populated on this box.                        │
 * │                                                                          │
 * │ A learned mapping is NEVER silently promoted to doctrine. It is written   │
 * │ with `learned = true` and `learned_from_device_id`, it is scoped to the   │
 * │ tenant it was learned in, and an operator reviews it. The shipped library │
 * │ (`tenant_id IS NULL`) is only ever edited by a human.                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { db } from '../../db';
import { logger } from '../../utils/logger';
import {
  CWMP_CANONICAL_KEYS,
  comparePathsByInstance,
  expandInstanceTemplate,
  type CanonicalKey,
  type CwmpDataModel,
  type CwmpParamMapping,
} from './contract';

/**
 * The ON CONFLICT target for a TENANT mapping.
 *
 * THE `WHERE` IS MANDATORY AND IT IS THE WHOLE REASON THIS CONSTANT EXISTS.
 * `cwmp_param_map_tenant_uq` is a PARTIAL unique index (migration 015 —
 * `tenant_id` is nullable and NULLS DISTINCT would make every library row
 * unique by vacuity). PostgreSQL will not match a partial index to an
 * ON CONFLICT specification unless the conflict target repeats the index
 * predicate verbatim; without it the statement fails with "there is no unique
 * or exclusion constraint matching the ON CONFLICT specification" — at run
 * time, on the first CPE that ever completes a subtree read.
 */
const TENANT_CONFLICT_TARGET =
  "(tenant_id, canonical_key, data_model, coalesce(brand,''), " +
  "coalesce(model_pattern,''), coalesce(firmware_pattern,'')) " +
  'WHERE tenant_id IS NOT NULL';

interface MapRow {
  id: number;
  tenant_id: number | null;
  canonical_key: CanonicalKey;
  data_model: CwmpDataModel;
  brand: string | null;
  model_pattern: string | null;
  firmware_pattern: string | null;
  param_path: string;
  priority: number;
  learned: boolean;
  learned_from_device_id: number | null;
}

function toMapping(row: MapRow): CwmpParamMapping {
  return {
    id: row.id,
    canonicalKey: row.canonical_key,
    dataModel: row.data_model,
    brand: row.brand,
    modelPattern: row.model_pattern,
    firmwarePattern: row.firmware_pattern,
    paramPath: row.param_path,
    priority: row.priority,
    learned: row.learned,
  };
}

export interface MappingContext {
  tenantId: number;
  dataModel: CwmpDataModel;
  brand: string;
  model: string | null;
  firmware: string | null;
}

/**
 * Every mapping that could apply, most specific first.
 *
 * Specificity is `priority` ASC, then "narrower wins" as a tie-break: a row
 * naming a firmware beats one naming a model beats one naming a brand beats the
 * catch-all. Expressed as a computed rank rather than as SQL `ORDER BY CASE`
 * so the rule is readable and testable in one place.
 */
export async function mappingsFor(ctx: MappingContext): Promise<CwmpParamMapping[]> {
  const rows = (await db('cwmp_param_map')
    .where((q) => q.whereNull('tenant_id').orWhere('tenant_id', ctx.tenantId))
    .andWhere('data_model', ctx.dataModel)
    .andWhere((q) => q.whereNull('brand').orWhere('brand', ctx.brand))
    .orderBy('priority')) as MapRow[];

  const applicable = rows.filter(
    (r) =>
      matches(r.model_pattern, ctx.model) && matches(r.firmware_pattern, ctx.firmware),
  );

  applicable.sort((a, b) => a.priority - b.priority || specificity(b) - specificity(a));
  return applicable.map(toMapping);
}

function specificity(row: MapRow): number {
  return (
    (row.brand ? 1 : 0) + (row.model_pattern ? 2 : 0) + (row.firmware_pattern ? 4 : 0)
  );
}

/**
 * A pattern matches when it is absent (applies to everything) or when it is a
 * prefix/glob of the value.
 *
 * `*` is the only wildcard, and it is deliberate: `model_pattern` is typed by
 * operators into a form, and a full regex there is an injection surface and a
 * support burden ("why does `Vigor2927+` match nothing"). An INVALID pattern
 * matches NOTHING rather than everything — failing closed on a mapping means a
 * missing canonical value, failing open means the wrong path pushed to a router.
 */
function matches(pattern: string | null, value: string | null): boolean {
  if (!pattern) return true;
  if (!value) return false;
  const rx = new RegExp(
    '^' + pattern.split('*').map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$',
    'i',
  );
  return rx.test(value);
}

/**
 * Resolve canonical keys to the concrete paths of ONE device.
 *
 * Returns a map from canonical key to the paths that actually exist on the box:
 * empty for a key this CPE does not expose, which is a legitimate answer and
 * must not be turned into an empty string by the caller.
 */
export async function resolvePaths(
  ctx: MappingContext,
  knownPaths: readonly string[],
): Promise<Map<CanonicalKey, string[]>> {
  const mappings = await mappingsFor(ctx);
  const out = new Map<CanonicalKey, string[]>();

  for (const mapping of mappings) {
    if (out.has(mapping.canonicalKey)) continue; // most specific already won
    const expanded = expandInstanceTemplate(mapping.paramPath, knownPaths);
    if (expanded.length > 0) out.set(mapping.canonicalKey, expanded);
  }
  return out;
}

/**
 * Canonical values for a device, ready for the UI and for the NCM builders.
 *
 * Secrets come back as `null` because `valuesFor` reads a column that is NULL
 * by construction for them (§8.2). That is why the value type here is
 * `string | null` and not `string`: "we have it but will not show it" and "the
 * CPE does not have it" are different, and the UI renders them differently.
 */
export async function canonicalValues(
  ctx: MappingContext,
  knownPaths: readonly string[],
  values: ReadonlyMap<string, string | null>,
): Promise<Partial<Record<CanonicalKey, string | null>>> {
  const paths = await resolvePaths(ctx, knownPaths);
  const out: Partial<Record<CanonicalKey, string | null>> = {};
  for (const [key, candidates] of paths) {
    const first = [...candidates].sort(comparePathsByInstance)[0];
    if (first !== undefined) out[key] = values.get(first) ?? null;
  }
  return out;
}

// ============================================================================
// Learn mode
// ============================================================================

/**
 * Heuristics that turn a discovered tree into candidate mappings.
 *
 * DELIBERATELY CONSERVATIVE — a wrong mapping is worse than a missing one,
 * because a missing one shows up as a blank field and a wrong one shows up as
 * the LAN address labelled "WAN address". Each rule matches on a leaf name that
 * is unambiguous in both data models, and anything that would need to guess
 * between two populated candidates learns NOTHING and leaves it to the operator.
 */
const LEARN_RULES: ReadonlyArray<{
  key: CanonicalKey;
  /** Matched against the full path, case-insensitively. */
  test: RegExp;
  /** A populated value is required — an empty leaf proves nothing. */
  requireValue?: boolean;
}> = [
  { key: 'device.manufacturer', test: /\.DeviceInfo\.Manufacturer$/i },
  { key: 'device.model', test: /\.DeviceInfo\.(ProductClass|ModelName)$/i },
  { key: 'device.serial', test: /\.DeviceInfo\.SerialNumber$/i },
  { key: 'device.hardware_version', test: /\.DeviceInfo\.HardwareVersion$/i },
  { key: 'device.software_version', test: /\.DeviceInfo\.SoftwareVersion$/i },
  { key: 'device.uptime_seconds', test: /\.DeviceInfo\.UpTime$/i },
  { key: 'mgmt.periodic_inform_enable', test: /\.ManagementServer\.PeriodicInformEnable$/i },
  { key: 'mgmt.periodic_inform_interval', test: /\.ManagementServer\.PeriodicInformInterval$/i },
  { key: 'mgmt.connection_request_url', test: /\.ManagementServer\.ConnectionRequestURL$/i },
  { key: 'mgmt.parameter_key', test: /\.ManagementServer\.ParameterKey$/i },
  {
    key: 'wan.external_ip',
    test: /(WANPPPConnection\.\d+\.ExternalIPAddress|WANIPConnection\.\d+\.ExternalIPAddress)$/i,
    requireValue: true,
  },
  {
    key: 'wan.connection_status',
    test: /(WAN(PPP|IP)Connection\.\d+\.ConnectionStatus|PPP\.Interface\.\d+\.ConnectionStatus)$/i,
  },
  { key: 'wifi.ssid', test: /(WLANConfiguration\.\d+\.SSID|WiFi\.SSID\.\d+\.SSID)$/i },
  { key: 'wifi.channel', test: /(WLANConfiguration\.\d+\.Channel|WiFi\.Radio\.\d+\.Channel)$/i },
  { key: 'hosts.total', test: /Hosts\.HostNumberOfEntries$/i },
];

export interface LearnResult {
  proposed: number;
  skippedAmbiguous: CanonicalKey[];
}

/**
 * Derive mappings from what a CPE actually reported, and store them for review.
 *
 * `{i}` generalisation is applied on the way in: a path learned as
 * `…WLANConfiguration.1.SSID` is stored as `…WLANConfiguration.{i}.SSID`, so
 * the mapping covers the second radio of the next box instead of being wrong
 * about it.
 */
export async function learnFromTree(
  ctx: MappingContext,
  deviceId: number,
  paths: readonly string[],
  values: ReadonlyMap<string, string | null>,
): Promise<LearnResult> {
  const existing = await mappingsFor(ctx);
  const alreadyMapped = new Set(existing.map((m) => m.canonicalKey));

  const proposals: Array<Record<string, unknown>> = [];
  const skippedAmbiguous: CanonicalKey[] = [];

  for (const rule of LEARN_RULES) {
    if (alreadyMapped.has(rule.key)) continue;

    let candidates = paths.filter((p) => rule.test.test(p));
    if (rule.requireValue) {
      candidates = candidates.filter((p) => {
        const v = values.get(p);
        return typeof v === 'string' && v.trim().length > 0;
      });
    }
    if (candidates.length === 0) continue;

    const templates = new Set(candidates.map(generalise));
    if (templates.size > 1) {
      // Two structurally DIFFERENT paths both populated. Guessing here is how a
      // LAN address gets labelled "WAN address"; leave it to a human.
      skippedAmbiguous.push(rule.key);
      continue;
    }

    proposals.push({
      tenant_id: ctx.tenantId,
      canonical_key: rule.key,
      data_model: ctx.dataModel,
      brand: ctx.brand,
      model_pattern: ctx.model,
      firmware_pattern: null,
      param_path: [...templates][0],
      // Learned rows sit BEHIND the shipped library on purpose: doctrine wins
      // over a guess, and 200 > the library's default 100.
      priority: 200,
      learned: true,
      learned_from_device_id: deviceId,
    });
  }

  if (proposals.length > 0) {
    await db('cwmp_param_map')
      .insert(proposals)
      .onConflict(db.raw(TENANT_CONFLICT_TARGET) as never)
      .ignore();
    logger.info(
      { deviceId, tenantId: ctx.tenantId, learned: proposals.length, skipped: skippedAmbiguous },
      'ACS: learn mode proposed parameter mappings for review',
    );
  }

  return { proposed: proposals.length, skippedAmbiguous };
}

/** `…WLANConfiguration.1.SSID` -> `…WLANConfiguration.{i}.SSID`. */
export function generalise(path: string): string {
  return path
    .split('.')
    .map((segment) => (/^\d+$/.test(segment) ? '{i}' : segment))
    .join('.');
}

// ============================================================================
// CRUD for the review screen
// ============================================================================

export async function listMappings(
  tenantId: number,
  opts: { learnedOnly?: boolean } = {},
): Promise<CwmpParamMapping[]> {
  const q = db('cwmp_param_map').where((b) =>
    b.whereNull('tenant_id').orWhere('tenant_id', tenantId),
  );
  if (opts.learnedOnly) q.andWhere('learned', true);
  const rows = (await q.orderBy(['canonical_key', 'priority'])) as MapRow[];
  return rows.map(toMapping);
}

export async function upsertMapping(
  tenantId: number,
  input: {
    canonicalKey: CanonicalKey;
    dataModel: CwmpDataModel;
    brand?: string | null;
    modelPattern?: string | null;
    firmwarePattern?: string | null;
    paramPath: string;
    priority?: number;
  },
): Promise<CwmpParamMapping> {
  const [row] = (await db('cwmp_param_map')
    .insert({
      tenant_id: tenantId,
      canonical_key: input.canonicalKey,
      data_model: input.dataModel,
      brand: input.brand ?? null,
      model_pattern: input.modelPattern ?? null,
      firmware_pattern: input.firmwarePattern ?? null,
      param_path: input.paramPath,
      priority: input.priority ?? 100,
      // An operator editing a mapping ADOPTS it: it stops being a guess.
      learned: false,
      learned_from_device_id: null,
    })
    .onConflict(db.raw(TENANT_CONFLICT_TARGET) as never)
    .merge(['param_path', 'priority', 'learned', 'learned_from_device_id', 'updated_at'])
    .returning('*')) as MapRow[];
  return toMapping(row);
}

export async function deleteMapping(tenantId: number, id: number): Promise<boolean> {
  // A tenant may only delete its OWN mappings. The shipped library
  // (`tenant_id IS NULL`) is not deletable through the API: it is content that
  // ships with the product, and a tenant deleting it would remove it for
  // everybody.
  const affected = await db('cwmp_param_map').where({ id, tenant_id: tenantId }).del();
  return affected > 0;
}

/** The keys with no mapping at all for this context — the review screen's TODO. */
export async function unmappedKeys(ctx: MappingContext): Promise<CanonicalKey[]> {
  const have = new Set((await mappingsFor(ctx)).map((m) => m.canonicalKey));
  return CWMP_CANONICAL_KEYS.filter((k) => !have.has(k));
}
