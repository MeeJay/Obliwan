/**
 * ObliWAN — Zyxel Nebula driver (family `zyxel_nebula`).
 *
 * The only CLOUD-managed device in the fleet, which changes every assumption
 * the other three brands are built on:
 *
 *  - We do not dial the device. We dial Zyxel, over the Internet, and ask about
 *    a device. The tunnel is irrelevant here — a Nebula device can be perfectly
 *    manageable while its L2TP tunnel is down, and unmanageable while the site
 *    is perfectly healthy. The K7 verdict must never read a Nebula REST failure
 *    as a site outage.
 *  - The quota is per ORGANIZATION and is shared with the customer's own
 *    integrations. The token bucket in `rest.transport.ts` is keyed on the org
 *    for that reason, and 429 is normal operation, not an incident.
 *  - Writes are eventually consistent: the cloud ACKs, the device applies at
 *    its next check-in. A read-after-write returning stale data is NOT a failed
 *    push, and M6 must not treat it as one.
 *
 * HONEST LIMITATION, STATED IN CODE RATHER THAN DISCOVERED LATER: the exact
 * Nebula endpoint layout and its response envelope are region- and
 * version-dependent, and no Nebula organisation was available to verify them.
 * So the endpoint is configuration (`device_transports.params.devicePath`) with
 * a documented default, and the response is read by SEARCHING FOR FIELD NAMES
 * at any depth rather than by walking a guessed path. A wrong envelope
 * therefore yields nulls in the inventory — never a crash, never a wrong serial.
 */

import type { DeviceCapabilities, TransportKind } from '@obliwan/shared';
import { NO_CAPABILITIES } from '@obliwan/shared';
import { NebulaClient } from '../../transport/rest.transport';
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

const DEFAULT_BASE_URL = 'https://api.nebula.zyxel.com';
/** `{orgId}` / `{siteId}` / `{serial}` are substituted from the transport row. */
const DEFAULT_DEVICE_PATH = '/nebula/v1.0/organizations/{orgId}/sites/{siteId}/devices';

export class ZyxelNebulaDriver extends BaseDriver {
  readonly id = 'zyxel_nebula';
  readonly brand = 'zyxel' as const;
  readonly family = 'zyxel_nebula' as const;

  readonly capabilities: DeviceCapabilities = {
    ...NO_CAPABILITIES,
    supportsRest: true,
    // The hardware still has an SSH CLI when adopted, but it is read-mostly and
    // the cloud owns the configuration. Pushing over SSH to a Nebula-managed
    // unit is a change the cloud will silently revert at the next check-in.
    supportsSsh: false,
    supportsSnmp: true,
    transportPriority: ['rest', 'snmp'] as TransportKind[],

    configFormat: 'json',
    applyGranularity: 'section',
    supportsStructuredDiff: true,

    // Shared org quota — not a per-device limit.
    maxConcurrentSessions: 2,
    minPollIntervalMs: 300_000,
    notes: [
      'Cloud-managed: reachability of the Nebula API says nothing about the site, and a site outage says nothing about the API. The two signals must stay separate in the K7 verdict.',
      'The API quota is per organization and shared with the customer’s own integrations; 429 is expected traffic, not an incident.',
      'Writes are eventually consistent — the cloud ACKs and the device applies at its next check-in, so a stale read-after-write is not a failed push.',
      'Endpoint layout is region- and version-dependent and was NOT verified against a live organization: it is configured per transport (params.devicePath).',
    ],
  };

  async probe(ctx: DriverContext): Promise<ProbeOutcome> {
    return this.runProbe(ctx, [
      { transport: 'rest', run: (channel) => this.inventoryOverRest(ctx, channel) },
      {
        transport: 'snmp',
        run: async (channel) => {
          const { inventory } = await this.identifyOverSnmp(ctx, channel);
          return inventory;
        },
      },
    ]);
  }

  async getInventory(ctx: DriverContext): Promise<DeviceInventory> {
    const rest = ctx.transports.find((t) => t.transport === 'rest' && t.enabled);
    if (rest) return this.inventoryOverRest(ctx, rest);

    const snmp = requireTransport(ctx, 'snmp');
    const { inventory } = await this.identifyOverSnmp(ctx, snmp);
    return inventory;
  }

  private async inventoryOverRest(
    ctx: DriverContext,
    channel: ResolvedTransport,
  ): Promise<DeviceInventory> {
    const apiKey = channel.credentials.apiKey;
    if (!apiKey) {
      throw new DriverError('Nebula transport row has no API key in the vault', 'AUTH_FAILED', {
        transport: 'rest',
        retryable: false,
      });
    }

    const orgId = stringParam(channel.params, 'orgId');
    const siteId = stringParam(channel.params, 'siteId');
    const serial = stringParam(channel.params, 'serial');
    const path = (stringParam(channel.params, 'devicePath') ?? DEFAULT_DEVICE_PATH)
      .replace('{orgId}', orgId ?? '')
      .replace('{siteId}', siteId ?? '')
      .replace('{serial}', serial ?? '');

    const client = new NebulaClient({
      baseUrl: channel.host ? `https://${channel.host}` : (stringParam(channel.params, 'baseUrl') ?? DEFAULT_BASE_URL),
      apiKey,
      orgId,
      siteId,
      timeoutMs: ctx.timeoutMs,
    });

    try {
      const payload = await client.get<unknown>(path);
      // When the endpoint returns the whole site, narrow to our unit BEFORE
      // reading fields — otherwise the serial of the first device in the list
      // would be recorded as this device's serial (risk R4, by another road).
      const scoped = serial ? narrowToSerial(payload, serial) ?? payload : payload;

      return {
        ...emptyInventory('rest'),
        brand: this.brand,
        family: this.family,
        model: this.pickDeep(scoped, ['model', 'modelName', 'deviceModel', 'productModel']),
        serial: this.pickDeep(scoped, ['serial', 'serialNumber', 'sn']),
        osVersion: this.pickDeep(scoped, ['firmwareVersion', 'firmware', 'currentFirmware', 'version']),
        systemIdentity: this.pickDeep(scoped, ['name', 'deviceName', 'hostname']),
        boardName: this.pickDeep(scoped, ['model', 'modelName']),
        uptimeSeconds: null,
        managementAddress: this.pickDeep(scoped, ['lanIp', 'ip', 'ipAddress', 'wanIp']),
      };
    } finally {
      await client.close().catch(() => undefined);
    }
  }
}

function stringParam(params: Record<string, unknown>, key: string): string | null {
  const value = params[key];
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

/** Find the array element whose serial matches, at shallow depth. */
function narrowToSerial(payload: unknown, serial: string): unknown | null {
  const wanted = serial.trim().toLowerCase();
  const visit = (node: unknown, depth: number): unknown | null => {
    if (depth > 4 || node === null || typeof node !== 'object') return null;
    if (Array.isArray(node)) {
      for (const item of node) {
        if (item && typeof item === 'object') {
          for (const [key, value] of Object.entries(item as Record<string, unknown>)) {
            if (/^(serial|serialnumber|sn)$/i.test(key.replace(/[_-]/g, '')) && String(value).toLowerCase() === wanted) {
              return item;
            }
          }
        }
        const found = visit(item, depth + 1);
        if (found) return found;
      }
      return null;
    }
    for (const value of Object.values(node as Record<string, unknown>)) {
      const found = visit(value, depth + 1);
      if (found) return found;
    }
    return null;
  };
  return visit(payload, 0);
}
