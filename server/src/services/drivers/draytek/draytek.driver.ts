/**
 * ObliWAN — DrayTek Vigor driver (family `draytek_vigor`).
 *
 * WHAT THIS BRAND ACTUALLY OFFERS, and why the code looks like it does:
 *
 *  - CLI over SSH (or telnet, which we refuse — risk R9). It is a MENU CLI:
 *    there is no `show running-config`, no exec channel worth the name, and
 *    output is human-formatted tables whose layout changes between firmware
 *    trains. So: an INTERACTIVE SHELL driven by a prompt regex, and a parser
 *    that is deliberately tolerant. A strict parser here turns a firmware
 *    upgrade into a fleet-wide inventory outage.
 *  - SNMP v2c/v3, standard MIB-II. Cheap, reliable, and the only channel that
 *    works when the single CLI session is already taken — hence the fallback.
 *  - TR-069, which is genuinely DrayTek's best channel and is where the config
 *    model will come from at M10. Nothing here uses it yet, and the capability
 *    flag stays false until it does.
 *  - The `.cfg` backup is a vendor-encrypted binary keyed to the model. Backup
 *    and restore will work at M6; a textual diff never will, which is why
 *    `supportsStructuredDiff` is false for this family and drift will be
 *    computed from the CWMP parameter tree instead (D1).
 *
 * The single-CLI-session limit is the operational fact that shapes this file:
 * every session is opened inside `withSsh`, so it is closed in a `finally`. A
 * leaked session locks the operator out of their own router until it times out.
 */

import type { DeviceCapabilities, TransportKind } from '@obliwan/shared';
import { NO_CAPABILITIES } from '@obliwan/shared';
import { SshTransport, withSsh, type SshTarget } from '../../transport/ssh.transport';
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

/** The Vigor menu prompt: `DrayTek> `, or bare `> ` on older trains. */
const DEFAULT_PROMPT = /(?:^|\n)[^\n]{0,32}>\s*$/;

export class DraytekVigorDriver extends BaseDriver {
  readonly id = 'draytek_vigor';
  readonly brand = 'draytek' as const;
  readonly family = 'draytek_vigor' as const;

  readonly capabilities: DeviceCapabilities = {
    ...NO_CAPABILITIES,
    supportsSsh: true,
    supportsSnmp: true,
    // Live since M10. FIRST in the priority list, and that ordering is the
    // point: the CWMP tree is structured, it is the only channel that survives
    // the single-CLI-session limit below, and it costs nothing to read because
    // the CPE already pushed it to us. It is also INVERTED — the Vigor dials
    // the ACS on 7547 and we never dial it, so this branch reads what the ACS
    // last heard instead of opening a connection (see ../cwmpInventory.ts).
    supportsCwmp: true,
    transportPriority: ['cwmp', 'ssh', 'snmp'] as TransportKind[],

    configFormat: 'binary_opaque',
    applyGranularity: 'full_replace',
    supportsStructuredDiff: false,
    requiresRebootToApply: true,

    // One CLI session at a time. This number is read by the arbiter and by the
    // rate limiter; raising it does not give the router a second session, it
    // just makes the second caller fail.
    maxConcurrentSessions: 1,
    minPollIntervalMs: 120_000,
    notes: [
      'Menu CLI: no `show running-config`. Interactive shell only, and output layout varies by firmware.',
      'The .cfg backup is a vendor-encrypted binary keyed to the model — restoring a 2927 backup onto a 2962 fails.',
      'Structured configuration comes from the TR-069 parameter tree (M10), not from the .cfg.',
      'TR-069 is inverted: the Vigor dials the ACS on 7547. ObliWAN implements no Connection Request, so a queued task runs at the next inform and never on demand.',
      'Telnet is intentionally unsupported: it would carry fleet credentials in clear over transit networks (R9).',
    ],
  };

  async probe(ctx: DriverContext): Promise<ProbeOutcome> {
    return this.runProbe(ctx, [
      // No dial: this branch reads the last Inform. It appears in
      // workingTransports when the CPE is calling in, which is precisely the
      // signal K7 consumes as cwmp_recent.
      { transport: 'cwmp', run: () => cwmpProbe(ctx.deviceId, this.brand, this.family) },
      { transport: 'ssh', run: (channel) => this.inventoryOverSsh(ctx, channel) },
      {
        transport: 'snmp',
        run: async (channel) => {
          const { inventory, identity } = await this.identifyOverSnmp(ctx, channel);
          return {
            ...inventory,
            model: modelFromSysDescr(identity.sysDescr),
            osVersion: versionFromSysDescr(identity.sysDescr),
          };
        },
      },
    ]);
  }

  async getInventory(ctx: DriverContext): Promise<DeviceInventory> {
    // The ACS first. A Vigor's single CLI session is frequently taken by the
    // customer's own installer, and the parameter tree is both richer and
    // already here. A null means "not enrolled, or never informed" and falls
    // through — it never means "a Vigor with no model and no serial".
    const viaCwmp = await cwmpDeviceInventory(ctx.deviceId, this.brand, this.family);
    if (viaCwmp) return viaCwmp;

    const ssh = ctx.transports.find((t) => t.transport === 'ssh' && t.enabled);
    if (ssh) return this.inventoryOverSsh(ctx, ssh);

    const snmp = requireTransport(ctx, 'snmp');
    const { inventory, identity } = await this.identifyOverSnmp(ctx, snmp);
    return {
      ...inventory,
      model: modelFromSysDescr(identity.sysDescr),
      osVersion: versionFromSysDescr(identity.sysDescr),
    };
  }

  /**
   * `sys ver` is the one command whose output has been stable across every
   * Vigor train we know of. `sys info` is asked for as well because some
   * firmware puts the serial there and not in `sys ver`; a failure of the
   * second command does not invalidate the first.
   */
  private async inventoryOverSsh(
    ctx: DriverContext,
    channel: ResolvedTransport,
  ): Promise<DeviceInventory> {
    const target = draytekSshTarget(channel, ctx);
    const prompt = promptFrom(channel.params) ?? DEFAULT_PROMPT;

    return withSsh(target, async (ssh: SshTransport) => {
      const shell = await ssh.shell({ prompt, timeoutMs: ctx.timeoutMs ?? 20_000 });
      try {
        await shell.waitForPrompt();
        const version = await shell.send('sys ver');
        let info = '';
        try {
          info = await shell.send('sys info');
        } catch {
          // Older trains do not have `sys info`. `sys ver` alone is enough to
          // identify the unit; refusing the whole inventory over a missing
          // optional command would be worse than a missing serial.
          info = '';
        }

        const fields = { ...this.parseKeyValueBlock(info), ...this.parseKeyValueBlock(version) };
        const model =
          this.firstOf(fields, ['router-model', 'model', 'model-name', 'product']) ??
          modelFromBanner(version);

        return {
          ...emptyInventory('ssh'),
          brand: this.brand,
          family: this.family,
          model,
          serial: this.firstOf(fields, ['serial-number', 'serial', 'serialnumber']),
          osVersion: this.firstOf(fields, ['version', 'firmware-version', 'fw-version']),
          systemIdentity: this.firstOf(fields, ['router-name', 'system-name', 'hostname']),
          boardName: model,
          uptimeSeconds: this.parseUptimeSeconds(this.firstOf(fields, ['system-uptime', 'uptime'])),
          managementAddress: channel.host,
        };
      } finally {
        shell.close();
      }
    });
  }
}

export function draytekSshTarget(channel: ResolvedTransport, ctx: DriverContext): SshTarget {
  if (!channel.host) {
    throw new DriverError('DrayTek SSH transport row has no host', 'NO_TRANSPORT', {
      transport: 'ssh',
      retryable: false,
    });
  }
  if (!channel.credentials.username) {
    throw new DriverError('DrayTek SSH transport row has no username', 'AUTH_FAILED', {
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
    // Old Vigor firmware negotiates only pre-2015 KEX. Opt-in per device so the
    // rest of the fleet is not downgraded along with it.
    legacyAlgorithms: channel.params.legacyAlgorithms === true,
  };
}

function promptFrom(params: Record<string, unknown>): RegExp | null {
  const raw = params.cliPrompt;
  if (typeof raw !== 'string' || raw.length === 0) return null;
  try {
    return new RegExp(raw);
  } catch {
    // A bad regex in a device row must not take the device out of the
    // inventory: fall back to the default and let the probe report reality.
    return null;
  }
}

/** `Vigor2927 Series` on the first line of `sys ver`. */
function modelFromBanner(text: string): string | null {
  const match = /\b(Vigor\s?\d{3,4}[A-Za-z-]*)/i.exec(text);
  return match ? match[1].replace(/\s+/g, '') : null;
}

export function modelFromSysDescr(sysDescr: string | null): string | null {
  if (!sysDescr) return null;
  return modelFromBanner(sysDescr);
}

export function versionFromSysDescr(sysDescr: string | null): string | null {
  if (!sysDescr) return null;
  const match = /(?:version|ver\.?)\s*[: ]\s*v?([0-9][0-9a-zA-Z._-]*)/i.exec(sysDescr);
  return match ? match[1] : null;
}
