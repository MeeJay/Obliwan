/**
 * ObliWAN — MikroTik RouterOS driver (families `mikrotik_routeros6` and
 * `mikrotik_routeros7`).
 *
 * Primary channel is the RouterOS API (8728, or 8729 with TLS and a pinned
 * fingerprint — risk R9), reached through the seam in `routerosChannel.ts`.
 * SNMP is a fallback that identifies a box whose API credentials are wrong or
 * whose API service is disabled; it is never the primary, because the API
 * returns strictly more (spec section 1.4, "SNMP as primary for MikroTik" is a
 * rejected option).
 *
 * WHY TWO FAMILIES (risk R11): RouterOS 6 and 7 are one brand and two command
 * dialects. `/system/health` returns a single record on v6 and rows on v7,
 * wireless moved from `/interface/wireless` to `/interface/wifi`, and menu
 * paths diverge. One family with a version `if` inside every collector is
 * exactly the hard-coded-path failure R11 exists to prevent. The M2 identity
 * menus below happen to be identical on both — which is why this file is one
 * class with a family parameter, and why the M3+ collectors will not be.
 *
 * The version reported by the box is authoritative over the family recorded in
 * `devices.family`: an operator who upgrades a hEX from 6.49 to 7.x changes the
 * dialect, and the inventory has to say so rather than keep speaking v6.
 */

import type { DeviceCapabilities, DeviceFamily, TransportKind } from '@obliwan/shared';
import { NO_CAPABILITIES } from '@obliwan/shared';
import { BaseDriver } from '../base';
import {
  DriverError,
  emptyInventory,
  requireTransport,
  type DeviceInventory,
  type DriverContext,
  type ProbeOutcome,
  type ResolvedTransport,
} from '../types';
import { withRouterOsChannel, type RouterOsRow } from './routerosChannel';

/** Capabilities shared by both RouterOS families. */
function routerosCapabilities(family: DeviceFamily): DeviceCapabilities {
  return {
    ...NO_CAPABILITIES,
    supportsRouterosApi: true,
    supportsSsh: true,
    supportsSnmp: true,
    transportPriority: ['routeros_api', 'ssh', 'snmp'] as TransportKind[],

    // Only what M2 actually implements is true here. Everything else stays
    // false until the code exists — the flag is a promise to the planner.
    canReadInterfaces: false,
    // STILL FALSE, AND DELIBERATELY SO. `./driver.ts` now implements the M4
    // collection path (`collectRouterOsExport`, hard-wired to
    // `/export terse show-sensitive=no` with no pty — R10 and N13), and
    // `services/config/normalize.service.ts` turns its output into an
    // `NcmDocument`. But `DeviceDriver.exportConfig` is declared
    // `Promise<never>` in `drivers/types.ts`, a file this workstream does not
    // own, so the driver METHOD still throws its dated `NotImplementedError`
    // and the snapshot service calls the function directly. Flipping this flag
    // while the interface method still refuses would promise the planner
    // something it cannot get. It becomes true when the M5 signature change
    // lands, in the same commit.
    canExportConfig: false,

    // The concentrator role is what makes MikroTik special in this product
    // (D4): /ppp/active + /ppp/active/listen are the source of truth for
    // presence. The CHR is a RouterOS 7 box; a v6 unit can serve the same
    // menus, so the flag is on for both and the ROLE decides who is asked.
    canReadPppSessions: true,
    canStreamPppEvents: true,

    configFormat: 'text_cli',
    applyGranularity: 'line',
    supportsStructuredDiff: true,
    requiresExplicitCommit: false,
    requiresRebootToApply: false,

    // The CHR terminates the whole fleet's tunnels; it is a SPOF and a
    // bottleneck (R5). One socket, multiplexed by tag — not four sessions.
    maxConcurrentSessions: 1,
    minPollIntervalMs: 30_000,
    notes: [
      family === 'mikrotik_routeros6'
        ? 'RouterOS 6: menu paths differ from v7 (/interface/wireless, /system/health as a single record). Collectors are family-specific by design (R11).'
        : 'RouterOS 7: /interface/wifi replaces /interface/wireless and /system/health returns rows (R11).',
      'Config export runs with show-sensitive=no and a service account without the "sensitive" policy (R10).',
      'Identity is ppp_username + system_identity + serial, never the tunnel IP (D5).',
    ],
  };
}

export class MikrotikRouterOsDriver extends BaseDriver {
  readonly id: string;
  readonly brand = 'mikrotik' as const;
  readonly family: DeviceFamily;
  readonly capabilities: DeviceCapabilities;

  constructor(family: DeviceFamily = 'mikrotik_routeros7') {
    super();
    this.family = family;
    this.id = family;
    this.capabilities = routerosCapabilities(family);
  }

  async probe(ctx: DriverContext): Promise<ProbeOutcome> {
    return this.runProbe(ctx, [
      {
        transport: 'routeros_api',
        run: (channel) => this.inventoryOverApi(ctx, channel),
      },
      {
        transport: 'snmp',
        run: async (channel) => {
          const { inventory, identity } = await this.identifyOverSnmp(ctx, channel);
          // "RouterOS 7.14.3 (stable) ..." — the only version signal SNMP has.
          return { ...inventory, osVersion: versionFromSysDescr(identity.sysDescr) };
        },
      },
    ]);
  }

  async getInventory(ctx: DriverContext): Promise<DeviceInventory> {
    const api = ctx.transports.find((t) => t.transport === 'routeros_api' && t.enabled);
    if (api) return this.inventoryOverApi(ctx, api);

    const snmp = requireTransport(ctx, 'snmp');
    const { inventory, identity } = await this.identifyOverSnmp(ctx, snmp);
    return { ...inventory, osVersion: versionFromSysDescr(identity.sysDescr) };
  }

  /**
   * Three menus, one channel. `/system/routerboard` is the only source of a
   * serial — and a CHR (a virtual machine) legitimately has none, which is why
   * D5 makes identity a triple and not a serial alone.
   */
  private async inventoryOverApi(
    ctx: DriverContext,
    channel: ResolvedTransport,
  ): Promise<DeviceInventory> {
    const timeoutMs = ctx.timeoutMs ?? 15_000;

    return withRouterOsChannel(
      channel,
      async (ros) => {
        const resource = firstRow(await ros.query('/system/resource/print', { timeoutMs }));
        const identity = firstRow(await ros.query('/system/identity/print', { timeoutMs }));

        // A CHR has no RouterBOARD menu at all; a trap there is expected, not
        // a failure of the whole inventory.
        let routerboard: RouterOsRow = {};
        try {
          routerboard = firstRow(await ros.query('/system/routerboard/print', { timeoutMs }));
        } catch {
          routerboard = {};
        }

        const version = resource['version'] ?? null;
        const observedFamily = familyFromVersion(version);

        return {
          ...emptyInventory('routeros_api'),
          brand: this.brand,
          // What the box says it runs wins over what the database remembers.
          family: observedFamily ?? this.family,
          model:
            routerboard['model'] ??
            routerboard['board-name'] ??
            resource['board-name'] ??
            resource['platform'] ??
            null,
          serial: routerboard['serial-number'] ?? null,
          osVersion: cleanVersion(version),
          systemIdentity: identity['name'] ?? null,
          boardName: resource['board-name'] ?? null,
          uptimeSeconds: this.parseUptimeSeconds(resource['uptime']),
          managementAddress: channel.host,
        };
      },
      { timeoutMs, deviceId: ctx.deviceId },
    );
  }
}

function firstRow(rows: RouterOsRow[]): RouterOsRow {
  if (!rows || rows.length === 0) {
    throw new DriverError('RouterOS returned no row for a /print of a singleton menu', 'PROTOCOL_ERROR', {
      transport: 'routeros_api',
    });
  }
  return rows[0];
}

/** `7.14.3 (stable)` -> `7.14.3`. */
function cleanVersion(raw: string | null): string | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  const match = /^([0-9][0-9a-zA-Z.\-_]*)/.exec(trimmed);
  return match ? match[1] : trimmed || null;
}

/** Major version -> family. Anything but 6 or 7 returns null: guessing a
 *  dialect for RouterOS 8 would be inventing one. */
export function familyFromVersion(raw: string | null): DeviceFamily | null {
  const version = cleanVersion(raw);
  if (!version) return null;
  const major = Number(version.split('.')[0]);
  if (major === 6) return 'mikrotik_routeros6';
  if (major === 7) return 'mikrotik_routeros7';
  return null;
}

export function versionFromSysDescr(sysDescr: string | null): string | null {
  if (!sysDescr) return null;
  const match = /RouterOS\s+v?([0-9][0-9a-zA-Z.\-_]*)/i.exec(sysDescr);
  return match ? match[1] : null;
}
