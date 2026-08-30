/**
 * ObliWAN — SonicWall driver (family `sonicwall_sonicos`, TZ / NSa / NSv).
 *
 * ONE family for SonicOS 6.5 and 7.x on purpose (see `shared/device.ts`): the
 * difference between them is "is the REST API present and enabled", which is an
 * OBSERVED CAPABILITY probed at connection time, not a different command
 * dialect. `devices.os_version` carries the detail; a firmware upgrade must not
 * require re-typing the family of a device.
 *
 * THE OPERATIONAL FACT THAT SHAPES THIS FILE: a SonicWall allows a very small
 * number of concurrent administrative sessions and leaks them on timeout. Every
 * unit of work therefore goes through `withSonicOsSession`, which logs out in a
 * `finally`, unconditionally. `override: true` on login steals the config lock
 * from a stale web-UI session — without it a forgotten browser tab blocks
 * ObliWAN indefinitely; with it, ObliWAN is the one who can block the customer,
 * which is why the session is held for the shortest possible time and never
 * across two operations.
 *
 * Consequence for M2, stated plainly: probing a SonicWall is NOT free. Unlike
 * an SNMP GET it consumes an admin session slot. The arbiter's minimum poll
 * interval for this family is set accordingly, and SNMP is preferred whenever
 * it can answer the question.
 */

import type { DeviceCapabilities, TransportKind } from '@obliwan/shared';
import { NO_CAPABILITIES } from '@obliwan/shared';
import { withSonicOsSession, type RestTarget } from '../../transport/rest.transport';
import {
  applyStagedOps,
  type ApplyStagedOptions,
  type SonicOsApplyReport,
  type SonicOsStagedOp,
} from './sonicosSession';
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

/**
 * Identification endpoints, tried in order until one answers. SonicOS moved
 * these between 6.5 and 7.x, so the driver asks rather than assumes; a 404 on
 * the first is expected traffic, not a failure.
 */
const IDENTITY_PATHS = ['/version', '/reporting/status/system', '/system/status'] as const;

export class SonicWallDriver extends BaseDriver {
  readonly id = 'sonicwall_sonicos';
  readonly brand = 'sonicwall' as const;
  readonly family = 'sonicwall_sonicos' as const;

  readonly capabilities: DeviceCapabilities = {
    ...NO_CAPABILITIES,
    supportsRest: true,
    supportsSsh: true,
    supportsSnmp: true,
    // SNMP first for anything SNMP can answer: it burns no admin session.
    transportPriority: ['rest', 'snmp', 'ssh'] as TransportKind[],

    configFormat: 'text_cli',
    applyGranularity: 'line',
    supportsStructuredDiff: true,
    // The pending-config model: writes stage, then commit or discard. This is
    // what makes SonicWall the safest brand to push to despite the ceremony —
    // a rejected commit leaves the appliance completely untouched.
    requiresExplicitCommit: true,

    maxConcurrentSessions: 1,
    minPollIntervalMs: 300_000,
    notes: [
      'Administrative sessions are scarce and leak on timeout: every operation logs out in a finally. A probe is not free — it consumes a session slot.',
      'login sends override:true to steal the config lock from a stale web-UI session; otherwise a forgotten browser tab blocks ObliWAN indefinitely.',
      'Writes stage in a pending config and are committed all-or-nothing; a rejected commit leaves the appliance untouched (M6).',
      'SonicOS 6.5 vs 7.x is an observed capability (REST present or not), not a separate family — os_version carries the detail.',
    ],
  };

  async probe(ctx: DriverContext): Promise<ProbeOutcome> {
    return this.runProbe(ctx, [
      // SNMP first: it identifies the box without taking the admin session that
      // the customer's own administrator may need at that exact moment.
      {
        transport: 'snmp',
        run: async (channel) => {
          const { inventory, identity } = await this.identifyOverSnmp(ctx, channel);
          return { ...inventory, ...parseSysDescr(identity.sysDescr) };
        },
      },
      { transport: 'rest', run: (channel) => this.inventoryOverRest(ctx, channel) },
    ]);
  }

  async getInventory(ctx: DriverContext): Promise<DeviceInventory> {
    const rest = ctx.transports.find((t) => t.transport === 'rest' && t.enabled);
    if (rest) return this.inventoryOverRest(ctx, rest);

    const snmp = requireTransport(ctx, 'snmp');
    const { inventory, identity } = await this.identifyOverSnmp(ctx, snmp);
    return { ...inventory, ...parseSysDescr(identity.sysDescr) };
  }

  private async inventoryOverRest(
    ctx: DriverContext,
    channel: ResolvedTransport,
  ): Promise<DeviceInventory> {
    const { username, password } = channel.credentials;
    if (!username || !password) {
      throw new DriverError('SonicOS transport row has no username/password in the vault', 'AUTH_FAILED', {
        transport: 'rest',
        retryable: false,
      });
    }
    const target = sonicOsTarget(channel, ctx);

    return withSonicOsSession(target, { username, password }, async (session) => {
      const documents: unknown[] = [];
      for (const path of IDENTITY_PATHS) {
        try {
          documents.push(await session.get<unknown>(path));
        } catch (err) {
          // A missing endpoint on this firmware is information, not a failure.
          // An auth or permission error is neither, and must surface.
          const code = err instanceof DriverError ? err.code : 'UNKNOWN';
          if (code === 'AUTH_FAILED' || code === 'PERMISSION_DENIED') throw err;
        }
      }

      if (documents.length === 0) {
        throw new DriverError(
          `SonicOS answered none of ${IDENTITY_PATHS.join(', ')} — the REST API may be disabled on this firmware`,
          'PROTOCOL_ERROR',
          { transport: 'rest' },
        );
      }

      return {
        ...emptyInventory('rest'),
        brand: this.brand,
        family: this.family,
        model: this.pickDeep(documents, ['model', 'modelName', 'productName', 'product']),
        serial: this.pickDeep(documents, ['serialNumber', 'serial']),
        osVersion: this.pickDeep(documents, ['firmwareVersion', 'firmware', 'version', 'romVersion']),
        systemIdentity: this.pickDeep(documents, ['friendlyName', 'name', 'hostname', 'systemName']),
        boardName: this.pickDeep(documents, ['model', 'modelName']),
        uptimeSeconds: this.parseUptimeSeconds(this.pickDeep(documents, ['upTime', 'uptime', 'systemUptime'])),
        managementAddress: channel.host,
      };
    });
  }

  /**
   * THE WRITE PATH (M11). Stage every operation of a compiled artefact in the
   * pending configuration, then commit it once, atomically.
   *
   * ┌─ D3, AND IT IS NOT NEGOTIABLE ─────────────────────────────────────────┐
   * │ This method is NOT part of the `DeviceDriver` interface and no          │
   * │ controller can reach it. Its only production caller will be the M6      │
   * │ apply path, which runs inside a `change_jobs` row that already holds    │
   * │ the device lock, a frozen plan, a Management-Path Guard verdict and a   │
   * │ pre-change backup. Today its callers are the M11 self-test and the fake │
   * │ appliance it runs against.                                             │
   * │                                                                        │
   * │ `capabilities.canPushConfig` therefore stays FALSE: the interface       │
   * │ method `applyConfig` still refuses (it is typed `Promise<never>` in a   │
   * │ file this milestone does not own), and a flag that promised the planner │
   * │ something the interface cannot deliver would be a lie the scheduler     │
   * │ acts on. Same reasoning, same shape, as MikroTik's `canExportConfig`.   │
   * └────────────────────────────────────────────────────────────────────────┘
   *
   * Failure semantics are the appliance's own and they are the reason this
   * brand is the safest to push to: nothing is applied unless everything is.
   *
   * `options.discardForeignPending` is the one decision this method does not
   * take by itself: a pending batch ObliWAN did not stage stops the job with
   * `DEVICE_BUSY`, and destroying it is a replay an operator asks for after
   * reading what was in it. The parameter is threaded from here rather than
   * left on `applyStagedOps` alone, because a choice reachable only from a
   * function the product does not call is not a choice.
   */
  async applyPendingConfig(
    ctx: DriverContext,
    ops: readonly SonicOsStagedOp[],
    options: ApplyStagedOptions = {},
  ): Promise<SonicOsApplyReport> {
    const channel = requireTransport(ctx, 'rest');
    const { username, password } = channel.credentials;
    if (!username || !password) {
      throw new DriverError(
        'SonicOS transport row has no username/password in the vault',
        'AUTH_FAILED',
        { transport: 'rest', retryable: false },
      );
    }
    return applyStagedOps(sonicOsTarget(channel, ctx), { username, password }, ops, options);
  }
}

export function sonicOsTarget(channel: ResolvedTransport, ctx: DriverContext): RestTarget {
  if (!channel.host) {
    throw new DriverError('SonicOS transport row has no host', 'NO_TRANSPORT', {
      transport: 'rest',
      retryable: false,
    });
  }
  const scheme = channel.useTls === false ? 'http' : 'https';
  const port = channel.port ?? 443;
  return {
    baseUrl: `${scheme}://${channel.host}:${port}`,
    timeoutMs: ctx.timeoutMs ?? 30_000,
    tls: {
      // Appliance certificates are self-signed. The honest configuration is
      // "verify nothing, but pin exactly this certificate" (R9); the transport
      // refuses the combination without a pin.
      rejectUnauthorized: typeof channel.params.rejectUnauthorized === 'boolean'
        ? (channel.params.rejectUnauthorized as boolean)
        : channel.tlsFingerprintSha256 === null,
      fingerprintSha256: channel.tlsFingerprintSha256,
    },
    secrets: [channel.credentials.password, channel.credentials.apiKey],
  };
}

/** `SonicWALL NSA 2700 (SonicOS Enhanced 7.0.1-5030)` and friends. */
function parseSysDescr(sysDescr: string | null): Pick<DeviceInventory, 'model' | 'osVersion'> {
  if (!sysDescr) return { model: null, osVersion: null };
  const model = /\b(TZ\s?\d+\w*|NSa\s?\d+\w*|NSA\s?\d+\w*|NSv\s?\d+\w*|SOHO\w*)/i.exec(sysDescr);
  const version = /SonicOS[^0-9]*([0-9][\w.\-]*)/i.exec(sysDescr);
  return {
    model: model ? model[1].replace(/\s+/g, ' ').trim() : null,
    osVersion: version ? version[1] : null,
  };
}
