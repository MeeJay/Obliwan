/**
 * ObliWAN — the CWMP branch shared by the two ACS-managed drivers.
 *
 * ┌─ WHY A SHARED FILE AND NOT TWO COPIES ────────────────────────────────────┐
 * │ `draytek_vigor` (TR-098) and `zyxel_cpe` (TR-181) reach ObliWAN through   │
 * │ the SAME channel and are reconciled by the SAME table (`cwmp_param_map`,  │
 * │ decision D1). The only thing that differs between them is the data model, │
 * │ and the data model is already handled inside the canonical layer. Two     │
 * │ copies of this function would be two places for the reconciliation to     │
 * │ drift.                                                                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ "REACHABLE" MEANS SOMETHING ELSE ON THIS TRANSPORT ──────────────────────┐
 * │ Every other driver in this product dials the box and measures a latency.  │
 * │ A CPE behind carrier NAT cannot be dialled — that inversion is the whole  │
 * │ reason TR-069 exists — so the only evidence of life is that it CALLED IN. │
 * │                                                                          │
 * │ `cwmpProbe()` therefore succeeds when the CPE has informed recently and   │
 * │ throws `UNREACHABLE` when it has not, which is what makes the attempt      │
 * │ appear in `device_capabilities.failed_transports` and feeds K7's fourth   │
 * │ signal (`cwmp_recent`). The latency it reports is the AGE of the last     │
 * │ Inform, not a round trip, and the caller is told so rather than left to   │
 * │ compare it against an SSH number it does not resemble.                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import type { DeviceBrand, DeviceFamily } from '@obliwan/shared';
import { cwmpInventory } from '../cwmp/inventory.service';
import { DriverError, emptyInventory, type DeviceInventory } from './types';

/**
 * Identify a CPE from what the ACS last heard it say.
 *
 * Returns null when the device is not enrolled at all, so the caller can fall
 * through to SSH or SNMP instead of reporting a box with eleven nulls in it.
 */
export async function cwmpDeviceInventory(
  deviceId: number,
  brand: DeviceBrand,
  family: DeviceFamily,
): Promise<DeviceInventory | null> {
  const facts = await cwmpInventory(deviceId);
  if (!facts || facts.observedAt === null) return null;

  return {
    ...emptyInventory('cwmp'),
    brand,
    family,
    model: facts.model,
    serial: facts.serial,
    osVersion: facts.osVersion,
    // A CPE has no `/system/identity`. Its operator-visible label is the SSID
    // far more often than a hostname, and claiming otherwise would put a
    // fabricated name in the inventory.
    systemIdentity: facts.canonical['wifi.ssid'] ?? null,
    boardName: facts.model,
    uptimeSeconds: facts.uptimeSeconds,
    // The address the CPE reported for its own WAN. Diagnostics only — it is
    // not dialable and it is emphatically not an identity (D5).
    managementAddress: facts.wanAddress,
    collectedVia: 'cwmp',
    // NOT `now()`. The freshest truth about a CPE is the moment it last called
    // in, and a caller that saw `now()` here would treat three-day-old data as
    // current.
    collectedAt: facts.observedAt,
  };
}

/**
 * The probe branch. Throws rather than returning null — see the header.
 */
export async function cwmpProbe(
  deviceId: number,
  brand: DeviceBrand,
  family: DeviceFamily,
): Promise<DeviceInventory> {
  const facts = await cwmpInventory(deviceId);
  if (!facts) {
    throw new DriverError(
      `device ${deviceId} is not enrolled in the ACS`,
      'NO_TRANSPORT',
      { transport: 'cwmp', retryable: false },
    );
  }
  if (facts.reachability === 'never_seen') {
    throw new DriverError(
      'the CPE has never contacted the ACS — check the ACS URL and credentials provisioned on it',
      'UNREACHABLE',
      { transport: 'cwmp' },
    );
  }
  if (facts.reachability === 'lost') {
    throw new DriverError(
      `the CPE has not informed since ${facts.observedAt}`,
      'UNREACHABLE',
      { transport: 'cwmp' },
    );
  }

  const inventory = await cwmpDeviceInventory(deviceId, brand, family);
  if (!inventory) {
    throw new DriverError(
      'the CPE is enrolled but has reported no parameters yet',
      'UNREACHABLE',
      { transport: 'cwmp' },
    );
  }
  return inventory;
}
