/**
 * ObliWAN — the `unknown` driver.
 *
 * Returned by the registry for any family it does not know: a row written by a
 * future migration, a device whose family was never determined, a typo in an
 * import bundle.
 *
 * IT DOES NOTHING, AND THAT IS THE FEATURE. The alternative — throwing from
 * `getDriver()` — means one unidentified box aborts a fleet scan, and the
 * operator sees "scan failed" instead of "one device could not be identified".
 * An unknown device must appear in the inventory, greyed out, with an honest
 * reason.
 *
 * It also declares NOTHING (`NO_CAPABILITIES` verbatim), which means the
 * arbiter refuses every intent for it before a single packet is sent. It does
 * not attempt an SNMP identification either: picking a driver requires knowing
 * the dialect, and identification-before-family is the discovery path's job
 * (the CHR discovery and the operator's manual binding), not a driver's.
 */

import type { DeviceBrand, DeviceCapabilities, DeviceFamily } from '@obliwan/shared';
import { NO_CAPABILITIES } from '@obliwan/shared';
import { BaseDriver } from './base';
import { emptyInventory, type DeviceInventory, type DriverContext, type ProbeOutcome } from './types';

export class UnknownDriver extends BaseDriver {
  readonly id = 'unknown';
  readonly brand: DeviceBrand | null = null;
  readonly family: DeviceFamily | null = null;
  readonly capabilities: DeviceCapabilities = {
    ...NO_CAPABILITIES,
    notes: [
      'No driver matches this device family. The device is listed but nothing can be read from it or pushed to it.',
      'Set devices.family to a supported value, or bind the discovery record to the right family, to give it a driver.',
    ],
  };

  /** Never dials. Reports "unknown", which is not the same as "down" (K7). */
  async probe(_ctx: DriverContext): Promise<ProbeOutcome> {
    return {
      reachable: false,
      attempts: [],
      workingTransports: [],
      failedTransports: [],
      latencyMs: null,
      observedOverrides: {},
      inventory: null,
      probedAt: new Date().toISOString(),
    };
  }

  async getInventory(_ctx: DriverContext): Promise<DeviceInventory> {
    return { ...emptyInventory(null), brand: null, family: null };
  }
}
