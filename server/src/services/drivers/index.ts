/**
 * ObliWAN — driver layer barrel.
 *
 * Import from here, not from a brand folder. A call site that imports
 * `MikrotikRouterOsDriver` directly has branched on brand, which is exactly
 * what decision D2 forbids: resolve with `getDriver(device.family)` and read
 * `driver.capabilities`.
 */

export * from './types';
export { BaseDriver } from './base';
export {
  getDriver,
  getCapabilities,
  allDrivers,
  familiesForBrand,
  guessFamily,
  unknownDriver,
} from './registry';

// The RouterOS API pool lives in `services/transport/routeros/**` and is owned
// by another workstream; this is the seam the composition root wires at boot.
export {
  registerRouterOsChannelFactory,
  routerOsChannelFactoryFromPool,
  clearRouterOsChannelFactory,
  isRouterOsChannelAvailable,
  type RouterOsChannel,
  type RouterOsChannelFactory,
  type RouterOsRow,
  type RouterOsQueryOptions,
} from './mikrotik/routerosChannel';
