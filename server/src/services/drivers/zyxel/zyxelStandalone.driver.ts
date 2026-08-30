/**
 * ObliWAN — Zyxel STANDALONE driver (`zyxel_standalone`) and Zyxel CPE driver
 * (`zyxel_cpe`).
 *
 * Zyxel is one brand and three products, which is why the shared contract makes
 * it three families rather than one driver with a mode switch:
 *
 *  - `zyxel_standalone` — USG FLEX / ATP / VPN on ZLD firmware. A Cisco-ish
 *    SSH CLI with a real `show running-config`. After MikroTik, this is the
 *    best diff target in the fleet.
 *  - `zyxel_nebula` — the SAME hardware, adopted into the Nebula cloud. The
 *    CLI is then read-mostly and the cloud owns the configuration; see
 *    `zyxelNebula.driver.ts`.
 *  - `zyxel_cpe` — VMG / DX / EX xDSL and GPON gateways. Carrier-provisioned,
 *    local UI usually locked by the ISP, SSH frequently absent, SNMP usually
 *    disabled. In practice: TR-069 only.
 *
 * ZLD's write semantics are the mirror image of SonicWall's and matter for M6,
 * not for M2: CLI lines apply IMMEDIATELY (no pending buffer) but are lost on
 * reboot until `write`. A failed push therefore leaves a LIVE half-applied
 * config. That is recorded here as a capability note now, so the M6 author does
 * not discover it against a customer's firewall.
 */

import type { DeviceCapabilities, TransportKind } from '@obliwan/shared';
import { NO_CAPABILITIES } from '@obliwan/shared';
import { withSsh, type SshTarget } from '../../transport/ssh.transport';
import { BaseDriver } from '../base';
import { cwmpDeviceInventory, cwmpProbe } from '../cwmpInventory';
import {
  DriverError,
  emptyInventory,
  requireTransport,
  type DeviceInventory,
  type DriverContext,
  type ProbeOutcome,
  type ResolvedTransport,
} from '../types';

export class ZyxelStandaloneDriver extends BaseDriver {
  readonly id = 'zyxel_standalone';
  readonly brand = 'zyxel' as const;
  readonly family = 'zyxel_standalone' as const;

  readonly capabilities: DeviceCapabilities = {
    ...NO_CAPABILITIES,
    supportsSsh: true,
    supportsSnmp: true,
    // Classic ZLD has no documented REST API; only the newer uOS "H" line does,
    // and guessing which one we are talking to is how a driver starts POSTing
    // to a 404. That line gets its own family when it appears in the fleet.
    supportsRest: false,
    transportPriority: ['ssh', 'snmp'] as TransportKind[],

    configFormat: 'text_cli',
    applyGranularity: 'line',
    supportsStructuredDiff: true,
    requiresExplicitCommit: false,
    requiresRebootToApply: false,

    maxConcurrentSessions: 2,
    minPollIntervalMs: 60_000,
    notes: [
      'ZLD applies CLI lines immediately with no pending buffer: a failed push leaves a live, half-applied config. A generated rollback script is mandatory at M6.',
      '`write` is what persists the running config to flash; without it the change is lost at the next reboot.',
      'REST is treated as absent for classic ZLD. The uOS "H" line will get its own family rather than a runtime guess.',
    ],
  };

  async probe(ctx: DriverContext): Promise<ProbeOutcome> {
    return this.runProbe(ctx, [
      { transport: 'ssh', run: (channel) => this.inventoryOverSsh(ctx, channel) },
      {
        transport: 'snmp',
        run: async (channel) => {
          const { inventory, identity } = await this.identifyOverSnmp(ctx, channel);
          return { ...inventory, ...parseSysDescr(identity.sysDescr) };
        },
      },
    ]);
  }

  async getInventory(ctx: DriverContext): Promise<DeviceInventory> {
    const ssh = ctx.transports.find((t) => t.transport === 'ssh' && t.enabled);
    if (ssh) return this.inventoryOverSsh(ctx, ssh);

    const snmp = requireTransport(ctx, 'snmp');
    const { inventory, identity } = await this.identifyOverSnmp(ctx, snmp);
    return { ...inventory, ...parseSysDescr(identity.sysDescr) };
  }

  /**
   * `show version` on ZLD prints a key/value block (model, firmware version,
   * build date, serial). It is one of the few ZLD commands whose shape has not
   * moved across firmware trains, which is why identification uses it rather
   * than the richer but more volatile `show system information`.
   */
  private async inventoryOverSsh(
    ctx: DriverContext,
    channel: ResolvedTransport,
  ): Promise<DeviceInventory> {
    const target = zyxelSshTarget(channel, ctx);

    return withSsh(target, async (ssh) => {
      const result = await ssh.exec('show version', { timeoutMs: ctx.timeoutMs ?? 20_000 });
      if (result.code !== null && result.code !== 0 && result.stdout.trim().length === 0) {
        throw new DriverError(
          `"show version" exited ${result.code}: ${result.stderr.slice(0, 200)}`,
          'PROTOCOL_ERROR',
          { transport: 'ssh' },
        );
      }
      const fields = this.parseKeyValueBlock(result.stdout);
      const model = this.firstOf(fields, ['model', 'product-model', 'device-model']);

      return {
        ...emptyInventory('ssh'),
        brand: this.brand,
        family: this.family,
        model,
        serial: this.firstOf(fields, ['serial-number', 'serial', 'mac-serial']),
        osVersion: this.firstOf(fields, ['firmware-version', 'zld-version', 'version']),
        systemIdentity: this.firstOf(fields, ['system-name', 'hostname', 'host-name']),
        boardName: model,
        uptimeSeconds: this.parseUptimeSeconds(this.firstOf(fields, ['system-uptime', 'uptime'])),
        managementAddress: channel.host,
      };
    });
  }
}

/**
 * Zyxel xDSL/GPON CPE. TR-069 only in practice, and live since M10.
 *
 * THE PROBE OF A BOX THAT CANNOT BE DIALLED. A carrier-provisioned CPE sits
 * behind NAT with its local UI locked and SSH absent. It cannot be probed in
 * the sense every other driver means: ObliWAN never opens a connection to it.
 * What the CWMP branch does instead is read what the ACS last heard the box
 * say, and report UNREACHABLE when it has stopped calling in. That is a
 * property of the brand, not a limitation of the driver, and it is what feeds
 * K7's fourth signal.
 */
export class ZyxelCpeDriver extends BaseDriver {
  readonly id = 'zyxel_cpe';
  readonly brand = 'zyxel' as const;
  readonly family = 'zyxel_cpe' as const;

  readonly capabilities: DeviceCapabilities = {
    ...NO_CAPABILITIES,
    // The family's real channel, live since M10.
    supportsCwmp: true,
    supportsSnmp: true,
    transportPriority: ['cwmp', 'snmp'] as TransportKind[],
    configFormat: 'cwmp_params',
    applyGranularity: 'parameter',
    maxConcurrentSessions: 1,
    minPollIntervalMs: 300_000,
    notes: [
      'Carrier-provisioned CPE: the local web UI is usually locked by the ISP, SSH is frequently absent and SNMP usually disabled.',
      'The data model root differs across the range — InternetGatewayDevice (TR-098) on older VMG, Device:2 (TR-181) on DX/EX. It is discovered from the Inform, never assumed.',
      'On TR-181 the WAN and LAN addresses are structurally identical paths differing only by instance number, so the WAN mapping is confirmed by an operator rather than guessed (cwmp_param_map).',
      'No Connection Request: a queued task runs at the next inform, never on demand.',
    ],
  };

  /** The ACS first, then SNMP if the ISP happened to leave it on. */
  async probe(ctx: DriverContext): Promise<ProbeOutcome> {
    return this.runProbe(ctx, [
      { transport: 'cwmp', run: () => cwmpProbe(ctx.deviceId, this.brand, this.family) },
      {
        transport: 'snmp',
        run: async (channel) => {
          const { inventory, identity } = await this.identifyOverSnmp(ctx, channel);
          return { ...inventory, ...parseSysDescr(identity.sysDescr) };
        },
      },
    ]);
  }

  async getInventory(ctx: DriverContext): Promise<DeviceInventory> {
    const viaCwmp = await cwmpDeviceInventory(ctx.deviceId, this.brand, this.family);
    if (viaCwmp) return viaCwmp;

    const snmp = ctx.transports.find((t) => t.transport === 'snmp' && t.enabled);
    if (!snmp) {
      // No longer a NotImplementedError: the path EXISTS, the box has simply
      // never used it. Naming a milestone here would send the operator looking
      // for missing code instead of at the ACS URL provisioned on the CPE,
      // which is where the problem actually is.
      throw new DriverError(
        'device ' + ctx.deviceId + ' has never contacted the ACS and has no SNMP transport: ' +
          'enrol it in the ACS and provision the ACS URL and credentials on the CPE',
        'NO_TRANSPORT',
        { transport: 'cwmp', retryable: false },
      );
    }
    const { inventory, identity } = await this.identifyOverSnmp(ctx, snmp);
    return { ...inventory, ...parseSysDescr(identity.sysDescr) };
  }
}

export function zyxelSshTarget(channel: ResolvedTransport, ctx: DriverContext): SshTarget {
  if (!channel.host) {
    throw new DriverError('Zyxel SSH transport row has no host', 'NO_TRANSPORT', {
      transport: 'ssh',
      retryable: false,
    });
  }
  if (!channel.credentials.username) {
    throw new DriverError('Zyxel SSH transport row has no username', 'AUTH_FAILED', {
      transport: 'ssh',
      retryable: false,
    });
  }
  return {
    host: channel.host,
    port: channel.port ?? 22,
    username: channel.credentials.username,
    password: channel.credentials.password ?? null,
    privateKey: channel.credentials.privateKey ?? null,
    passphrase: channel.credentials.passphrase ?? null,
    timeoutMs: ctx.timeoutMs ?? 20_000,
    legacyAlgorithms: channel.params.legacyAlgorithms === true,
  };
}

/** Model and firmware out of a Zyxel `sysDescr`, best effort. */
function parseSysDescr(sysDescr: string | null): Pick<DeviceInventory, 'model' | 'osVersion'> {
  if (!sysDescr) return { model: null, osVersion: null };
  const model = /\b(USG\s?FLEX\s?\d+H?|ATP\d+|VPN\d+|ZyWALL\s?\d+|VMG\d+[\w-]*|DX\d+[\w-]*|EX\d+[\w-]*)/i.exec(
    sysDescr,
  );
  const version = /\bV?(\d+\.\d+[\w.()-]*)/.exec(sysDescr);
  return {
    model: model ? model[1].replace(/\s+/g, ' ').trim() : null,
    osVersion: version ? version[1] : null,
  };
}
