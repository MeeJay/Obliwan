/**
 * ObliWAN — driver registry.
 *
 * The ONLY place in the server that knows brands exist. Everything downstream
 * (the probe scheduler, the discovery binder, the M3 poller, the M5 collector,
 * the controllers, the socket handlers) resolves a driver here and then talks
 * to the `DeviceDriver` interface.
 *
 * Adding a brand = one folder under `drivers/` and one line in `FACTORIES`.
 *
 * `getDriver()` NEVER throws. An unrecognised family gets the inert
 * `UnknownDriver`, so an unidentified box shows up in the inventory with an
 * honest "no driver" instead of taking down the scan that found it.
 */

import type { DeviceBrand, DeviceCapabilities, DeviceFamily } from '@obliwan/shared';
import { DEVICE_FAMILIES, FAMILY_BRAND } from '@obliwan/shared';
import { DraytekVigorDriver } from './draytek/draytek.driver';
import { MikrotikRouterOsDriver } from './mikrotik/mikrotik.driver';
import { SonicWallDriver } from './sonicwall/sonicwall.driver';
import type { DeviceDriver } from './types';
import { UnknownDriver } from './unknown.driver';
import { ZyxelNebulaDriver } from './zyxel/zyxelNebula.driver';
import { ZyxelCpeDriver, ZyxelStandaloneDriver } from './zyxel/zyxelStandalone.driver';

/**
 * Exhaustive over `DeviceFamily`: adding a family to the shared union without
 * adding a driver here is a compile error, not a runtime surprise on the day
 * someone provisions one.
 */
const FACTORIES: Readonly<Record<DeviceFamily, () => DeviceDriver>> = {
  mikrotik_routeros6: () => new MikrotikRouterOsDriver('mikrotik_routeros6'),
  mikrotik_routeros7: () => new MikrotikRouterOsDriver('mikrotik_routeros7'),
  draytek_vigor: () => new DraytekVigorDriver(),
  zyxel_nebula: () => new ZyxelNebulaDriver(),
  zyxel_standalone: () => new ZyxelStandaloneDriver(),
  zyxel_cpe: () => new ZyxelCpeDriver(),
  sonicwall_sonicos: () => new SonicWallDriver(),
};

/** Drivers are stateless: every per-device value travels in `DriverContext`,
 *  so one instance per family is shared by the whole process. */
const instances = new Map<string, DeviceDriver>();

export const unknownDriver: DeviceDriver = new UnknownDriver();

function isKnownFamily(family: string): family is DeviceFamily {
  return (DEVICE_FAMILIES as readonly string[]).includes(family);
}

/** Resolve a driver. Never throws; unknown families get the inert driver. */
export function getDriver(family: string | null | undefined): DeviceDriver {
  if (!family || !isKnownFamily(family)) return unknownDriver;
  const cached = instances.get(family);
  if (cached) return cached;
  const driver = FACTORIES[family]();
  instances.set(family, driver);
  return driver;
}

export function getCapabilities(family: string | null | undefined): DeviceCapabilities {
  return getDriver(family).capabilities;
}

/** Every driver, for the UI capability matrix and the "brand coverage" panel
 *  the spec requires (risk R2: the TR-069 perimeter must be visible, not
 *  implied). */
export function allDrivers(): DeviceDriver[] {
  return DEVICE_FAMILIES.map((family) => getDriver(family));
}

export function familiesForBrand(brand: DeviceBrand): DeviceFamily[] {
  return DEVICE_FAMILIES.filter((family) => FAMILY_BRAND[family] === brand);
}

/**
 * Pick a family for a device whose brand is known but whose family is not.
 *
 * Zyxel genuinely needs this: the same hardware behaves as three different
 * products depending on whether it was adopted into Nebula. MikroTik needs it
 * because the DIALECT depends on the running version (R11). DrayTek and
 * SonicWall map one-to-one.
 *
 * Returns `null` when the hints are not enough. A null family gets the unknown
 * driver, which is recoverable by an operator; a WRONG family sends v6 menu
 * paths to a v7 router and produces confident nonsense.
 */
export function guessFamily(
  brand: DeviceBrand,
  hints: {
    /** RouterOS version string, e.g. `7.14.3`. */
    osVersion?: string | null;
    model?: string | null;
    /** Whether the unit answers as adopted in the Nebula cloud. */
    nebulaManaged?: boolean | null;
  } = {},
): DeviceFamily | null {
  switch (brand) {
    case 'mikrotik': {
      const major = Number((hints.osVersion ?? '').trim().split('.')[0]);
      if (major === 6) return 'mikrotik_routeros6';
      if (major === 7) return 'mikrotik_routeros7';
      return null;
    }
    case 'draytek':
      return 'draytek_vigor';
    case 'sonicwall':
      // 6.5 and 7.x share the family on purpose — the difference is a probed
      // capability, not a dialect. See shared/device.ts.
      return 'sonicwall_sonicos';
    case 'zyxel': {
      if (hints.nebulaManaged === true) return 'zyxel_nebula';
      if (hints.nebulaManaged === false) {
        return isCpeModel(hints.model) ? 'zyxel_cpe' : 'zyxel_standalone';
      }
      // Adoption status unknown: a CPE model name is decisive on its own, a
      // security-appliance model name is not (a USG FLEX can be either).
      return isCpeModel(hints.model) ? 'zyxel_cpe' : null;
    }
  }
}

function isCpeModel(model: string | null | undefined): boolean {
  return typeof model === 'string' && /^(VMG|DX|EX|AX)\d/i.test(model.trim());
}
