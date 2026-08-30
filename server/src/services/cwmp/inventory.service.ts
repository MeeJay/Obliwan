/**
 * ObliWAN — the bridge from the CWMP parameter tree to the `DeviceDriver`
 * contract.
 *
 * ┌─ WHY THIS LIVES HERE AND NOT IN THE TWO DRIVERS ──────────────────────────┐
 * │ A Vigor's TR-098 tree and a VMG's TR-181 tree describe the same box in    │
 * │ two different vocabularies, and `cwmp_param_map` is what reconciles them  │
 * │ (decision D1). If each driver read the tree itself, each would grow its   │
 * │ own copy of the reconciliation and the map would stop being the single    │
 * │ place a vendor path is written down — which is exactly the failure the    │
 * │ canonical layer exists to prevent.                                        │
 * │                                                                          │
 * │ So the drivers ask ONE question — "what does the ACS know about this      │
 * │ device" — and get back canonical facts. Adding a third CWMP brand is a    │
 * │ row in `cwmp_param_map`, not a third parser.                              │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ AND WHY A CPE'S INVENTORY IS A READ OF OUR OWN DATABASE ─────────────────┐
 * │ Every other driver in this product DIALS the device. This one cannot: a   │
 * │ CPE behind carrier NAT is unreachable by definition, which is the entire  │
 * │ reason TR-069 is inverted. The freshest truth ObliWAN can have about a    │
 * │ Vigor is what that Vigor said the last time it called in — so             │
 * │ `cwmpInventory()` reads `cwmp_parameters`, and `observedAt` is carried    │
 * │ alongside so a caller can tell three-minute-old data from three-day-old   │
 * │ data instead of assuming freshness the way it can with SSH.               │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { db } from '../../db';
import { canonicalValues } from './paramMap.service';
import { knownPaths, valuesFor } from './parameter.service';
import { classifyReachability, type CanonicalKey, type CwmpDataModel, type CwmpReachability } from './contract';

export interface CwmpInventoryFacts {
  manufacturer: string | null;
  model: string | null;
  serial: string | null;
  hardwareVersion: string | null;
  osVersion: string | null;
  uptimeSeconds: number | null;
  wanAddress: string | null;
  lanAddress: string | null;
  connectionStatus: string | null;
  /** When the CPE last told us any of this. Null = it never has. */
  observedAt: string | null;
  reachability: CwmpReachability;
  dataModel: CwmpDataModel;
  /** Every canonical key we could resolve, for the UI's detail panel. */
  canonical: Partial<Record<CanonicalKey, string | null>>;
}

/**
 * What the ACS knows about a device.
 *
 * Returns null when the device is not enrolled — NOT an empty record. An empty
 * record is indistinguishable from "a CPE that reported nothing", and the
 * driver layer's rule 2 (`drivers/types.ts`) is explicit that a method which
 * cannot answer must say so rather than return a plausible blank.
 */
export async function cwmpInventory(deviceId: number): Promise<CwmpInventoryFacts | null> {
  const row = (await db('cwmp_devices as c')
    .join('devices as d', 'd.id', 'c.device_id')
    .where('c.device_id', deviceId)
    .first(
      'c.data_model',
      'c.manufacturer',
      'c.product_class',
      'c.serial_number',
      'c.hardware_version',
      'c.software_version',
      'c.last_inform_at',
      'c.periodic_inform_interval',
      'd.tenant_id',
      'd.brand',
      'd.model',
    )) as
    | {
        data_model: CwmpDataModel;
        manufacturer: string | null;
        product_class: string | null;
        serial_number: string | null;
        hardware_version: string | null;
        software_version: string | null;
        last_inform_at: Date | null;
        periodic_inform_interval: number;
        tenant_id: number;
        brand: string;
        model: string | null;
      }
    | undefined;

  if (!row) return null;

  const paths = await knownPaths(deviceId);
  const values = await valuesFor(deviceId, paths);
  const canonical = await canonicalValues(
    {
      tenantId: row.tenant_id,
      dataModel: row.data_model,
      brand: row.brand,
      model: row.model,
      firmware: row.software_version,
    },
    paths,
    values,
  );

  return {
    // The `cwmp_devices` columns win over the canonical map for identity: they
    // come straight out of the Inform's `DeviceId`, which every CPE fills in,
    // while `DeviceInfo.*` is a parameter a stripped-down firmware may omit.
    manufacturer: row.manufacturer ?? canonical['device.manufacturer'] ?? null,
    model: row.product_class ?? canonical['device.model'] ?? null,
    serial: row.serial_number ?? canonical['device.serial'] ?? null,
    hardwareVersion: row.hardware_version ?? canonical['device.hardware_version'] ?? null,
    osVersion: row.software_version ?? canonical['device.software_version'] ?? null,
    uptimeSeconds: toInt(canonical['device.uptime_seconds']),
    wanAddress: canonical['wan.external_ip'] ?? null,
    lanAddress: canonical['lan.ip_address'] ?? null,
    connectionStatus: canonical['wan.connection_status'] ?? null,
    observedAt: row.last_inform_at ? new Date(row.last_inform_at).toISOString() : null,
    reachability: classifyReachability(row.last_inform_at, row.periodic_inform_interval),
    dataModel: row.data_model,
    canonical,
  };
}

/**
 * The flattened tree, for the config snapshot a CPE cannot give us as text.
 *
 * A DrayTek `.cfg` is a vendor-encrypted binary and a Zyxel CPE has no config
 * export at all, so the "configuration" of these boxes IS the parameter tree
 * (§1.1 C5 / decision D1). It is emitted as a stable, sorted `path = value`
 * document so that two collections of an unchanged CPE hash identically —
 * `config_snapshots` deduplicates on `ncm_hash`, and an unstable ordering would
 * make every collection a new row (the "row generator" migration 007 forbids).
 *
 * Credential paths appear with an explicit `(secret, not stored)` marker rather
 * than being dropped: a diff must be able to show that the parameter EXISTS,
 * and dropping it would make a CPE that gained a Wi-Fi password look identical
 * to one that never had one.
 */
export async function cwmpConfigDocument(deviceId: number): Promise<string | null> {
  const rows = (await db('cwmp_parameters')
    .where({ device_id: deviceId })
    .orderBy('path')
    .select('path', 'value', 'is_secret')) as Array<{
    path: string;
    value: string | null;
    is_secret: boolean;
  }>;
  if (rows.length === 0) return null;

  return rows
    .map((r) => `${r.path} = ${r.is_secret ? '(secret, not stored)' : (r.value ?? '')}`)
    .join('\n');
}

function toInt(raw: string | null | undefined): number | null {
  if (raw === null || raw === undefined) return null;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : null;
}
