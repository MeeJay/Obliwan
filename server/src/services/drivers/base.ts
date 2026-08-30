/**
 * ObliWAN — BaseDriver.
 *
 * Implements every `DeviceDriver` member as an explicit, milestone-tagged
 * throw, plus the plumbing all four brands share (probe orchestration, SNMP
 * identification, string parsing helpers).
 *
 * The throw is the design, not a placeholder. A `getInterfaces()` that returned
 * `[]` would be indistinguishable from a switch with no ports: the M3 poller
 * would write an empty series, the drift engine would report every interface as
 * "extra", and nothing would ever surface the fact that nobody wrote the code.
 * `NotImplementedError('milestone M3')` is loud, and it names the date.
 */

import type {
  DeviceBrand,
  DeviceCapabilities,
  DeviceFamily,
  ObservedCapabilityOverrides,
  TransportKind,
} from '@obliwan/shared';
import { snmpIdentify, type SnmpIdentity, type SnmpTarget } from '../transport/snmp.transport';
import {
  DriverError,
  NotImplementedError,
  asDriverError,
  emptyInventory,
  pickTransport,
  type DeviceDriver,
  type DeviceInventory,
  type DriverContext,
  type ProbeOutcome,
  type ResolvedTransport,
  type TransportAttempt,
} from './types';

export abstract class BaseDriver implements DeviceDriver {
  abstract readonly id: string;
  abstract readonly brand: DeviceBrand | null;
  abstract readonly family: DeviceFamily | null;
  abstract readonly capabilities: DeviceCapabilities;

  // ── M2 ────────────────────────────────────────────────────────────────────

  abstract probe(ctx: DriverContext): Promise<ProbeOutcome>;
  abstract getInventory(ctx: DriverContext): Promise<DeviceInventory>;

  // ── Declared, dated, and refusing until then ──────────────────────────────

  getInterfaces(_ctx: DriverContext): Promise<never> {
    return Promise.reject(new NotImplementedError(`${this.id}.getInterfaces`, 'milestone M3'));
  }

  exportConfig(_ctx: DriverContext): Promise<never> {
    return Promise.reject(new NotImplementedError(`${this.id}.exportConfig`, 'milestone M5'));
  }

  applyConfig(_ctx: DriverContext, _rendered: string): Promise<never> {
    return Promise.reject(new NotImplementedError(`${this.id}.applyConfig`, 'milestone M6'));
  }

  backup(_ctx: DriverContext): Promise<never> {
    return Promise.reject(new NotImplementedError(`${this.id}.backup`, 'milestone M6'));
  }

  reboot(_ctx: DriverContext): Promise<never> {
    return Promise.reject(new NotImplementedError(`${this.id}.reboot`, 'milestone M6'));
  }

  // ── Shared probe plumbing ────────────────────────────────────────────────

  /**
   * Try each candidate channel in order and record what answered.
   *
   * NEVER rejects. A probe that throws on the first dead device aborts the
   * fleet scan, and "the scan crashed" is not a reachability verdict — it is a
   * missing one. Failures become `attempts[]` entries; the caller turns those
   * into `device_capabilities` and, with the other three signals, into a K7
   * verdict.
   */
  protected async runProbe(
    ctx: DriverContext,
    candidates: Array<{
      transport: TransportKind;
      run: (channel: ResolvedTransport) => Promise<DeviceInventory | null>;
    }>,
  ): Promise<ProbeOutcome> {
    const attempts: TransportAttempt[] = [];
    const observedOverrides: ObservedCapabilityOverrides = {};
    let inventory: DeviceInventory | null = null;
    let bestLatency: number | null = null;

    for (const candidate of candidates) {
      const channel = pickTransport(ctx, candidate.transport);
      if (!channel) continue;

      const startedAt = Date.now();
      try {
        const result = await candidate.run(channel);
        const latencyMs = Date.now() - startedAt;
        attempts.push({ transport: candidate.transport, ok: true, latencyMs });
        observedOverrides[transportFlag(candidate.transport)] = true;
        if (bestLatency === null || latencyMs < bestLatency) bestLatency = latencyMs;
        if (!inventory && result) inventory = result;
      } catch (err) {
        const driverError = asDriverError(err, 'UNKNOWN', candidate.transport);
        attempts.push({
          transport: candidate.transport,
          ok: false,
          latencyMs: Date.now() - startedAt,
          error: driverError.message,
          errorCode: driverError.code,
        });
        // A channel that answered "wrong password" IS reachable, and the box
        // does support the transport — the credential is what is broken. Only
        // a transport-level failure demotes the capability.
        if (driverError.code !== 'AUTH_FAILED' && driverError.code !== 'PERMISSION_DENIED') {
          observedOverrides[transportFlag(candidate.transport)] = false;
        }
      }
    }

    const working = attempts.filter((a) => a.ok).map((a) => a.transport);
    const failed = attempts.filter((a) => !a.ok).map((a) => a.transport);

    return {
      reachable: working.length > 0,
      attempts,
      workingTransports: working,
      failedTransports: failed,
      latencyMs: bestLatency,
      observedOverrides,
      inventory,
      probedAt: new Date().toISOString(),
    };
  }

  /** Build an SNMP target from a `device_transports` row. */
  protected snmpTargetFrom(channel: ResolvedTransport, ctx: DriverContext): SnmpTarget {
    if (!channel.host) {
      throw new DriverError('SNMP transport row has no host', 'NO_TRANSPORT', {
        transport: 'snmp',
        retryable: false,
      });
    }
    const version = String(channel.params.version ?? (channel.credentials.snmp?.username ? '3' : '2c'));
    return {
      host: channel.host,
      port: channel.port ?? 161,
      version: version === '3' ? '3' : '2c',
      credentials: channel.credentials.snmp ?? {},
      timeoutMs: ctx.timeoutMs ?? 5_000,
      retries: typeof channel.params.retries === 'number' ? channel.params.retries : 1,
    };
  }

  /**
   * The identification every brand shares. MIB-II only — the private MIBs of
   * these four vendors add nothing at identification time, and depending on
   * them would make this layer brand-aware, which is the one thing it exists to
   * avoid.
   */
  protected async identifyOverSnmp(
    ctx: DriverContext,
    channel: ResolvedTransport,
  ): Promise<{ inventory: DeviceInventory; identity: SnmpIdentity }> {
    const identity = await snmpIdentify(this.snmpTargetFrom(channel, ctx));
    const inventory: DeviceInventory = {
      ...emptyInventory('snmp'),
      brand: this.brand,
      family: this.family,
      systemIdentity: identity.sysName,
      osVersion: null,
      uptimeSeconds: identity.uptimeSeconds,
      managementAddress: channel.host,
    };
    return { inventory, identity };
  }

  // ── Parsing helpers ──────────────────────────────────────────────────────

  /**
   * Parse a `key: value` / `key = value` CLI block into a map.
   *
   * Tolerant on purpose: these tables change layout between firmware trains,
   * and a parser that throws on an unexpected line turns a firmware upgrade
   * into a fleet-wide outage of the inventory.
   */
  protected parseKeyValueBlock(text: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) continue;
      const match = /^([A-Za-z][\w \-/.]*?)\s*[:=]\s*(.*)$/.exec(line);
      if (!match) continue;
      const key = match[1].trim().toLowerCase().replace(/\s+/g, '-');
      const value = match[2].trim().replace(/^"(.*)"$/, '$1');
      if (key && !(key in out)) out[key] = value;
    }
    return out;
  }

  /** First non-empty value among several possible key spellings. */
  protected firstOf(map: Record<string, string>, keys: string[]): string | null {
    for (const key of keys) {
      const value = map[key];
      if (typeof value === 'string' && value.trim().length > 0) return value.trim();
    }
    return null;
  }

  /**
   * Find the first value for any of `keys`, at any depth of a JSON document.
   *
   * The two REST APIs in the fleet (SonicOS, Nebula) wrap the same field in a
   * different envelope on nearly every firmware and API version — `serial`,
   * `serial_number`, `serialNumber`, sometimes nested two objects deep. Pinning
   * an exact path means the inventory breaks on an upgrade the operator did not
   * tell us about; searching by key name degrades to "field missing" instead,
   * which is a null in the inventory rather than a failed collection.
   *
   * Keys are matched case-insensitively with `_`/`-` stripped.
   */
  protected pickDeep(input: unknown, keys: string[], maxDepth = 6): string | null {
    const wanted = new Set(keys.map(normaliseKey));
    const visit = (node: unknown, depth: number): string | null => {
      if (depth > maxDepth || node === null || typeof node !== 'object') return null;
      if (Array.isArray(node)) {
        for (const item of node) {
          const found = visit(item, depth + 1);
          if (found !== null) return found;
        }
        return null;
      }
      for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
        if (wanted.has(normaliseKey(key))) {
          if (typeof value === 'string' && value.trim().length > 0) return value.trim();
          if (typeof value === 'number' && Number.isFinite(value)) return String(value);
        }
      }
      for (const value of Object.values(node as Record<string, unknown>)) {
        const found = visit(value, depth + 1);
        if (found !== null) return found;
      }
      return null;
    };
    return visit(input, 0);
  }

  /**
   * `1w2d03:04:05` (RouterOS), `12:34:56`, `5 days 03:04:05` -> seconds.
   * Returns null rather than 0 when nothing parses: 0 means "just rebooted",
   * which would make a reboot detector fire on every unparsed string.
   */
  protected parseUptimeSeconds(raw: string | null | undefined): number | null {
    if (!raw) return null;
    const text = raw.trim().toLowerCase();
    let total = 0;
    let matched = false;

    // No `\b` after the unit on purpose: RouterOS writes `1w2d03:04:05`, where
    // the `w` is immediately followed by a digit and a word boundary never
    // occurs. Long spellings come first so `days` is not consumed as `d`.
    for (const [, amount, unit] of text.matchAll(
      /(\d+)\s*(weeks?|days?|hours?|min(?:ute)?s?|sec(?:ond)?s?|w|d|h|m|s)/g,
    )) {
      const n = Number(amount);
      const factor = unit.startsWith('w')
        ? 604_800
        : unit.startsWith('d')
          ? 86_400
          : unit.startsWith('h')
            ? 3_600
            : unit.startsWith('m')
              ? 60
              : 1;
      total += n * factor;
      matched = true;
    }

    const clock = /(\d+):(\d{2}):(\d{2})/.exec(text);
    if (clock) {
      total += Number(clock[1]) * 3_600 + Number(clock[2]) * 60 + Number(clock[3]);
      matched = true;
    }
    return matched ? total : null;
  }
}

function normaliseKey(key: string): string {
  return key.toLowerCase().replace(/[_\-\s]/g, '');
}

function transportFlag(kind: TransportKind): keyof ObservedCapabilityOverrides {
  switch (kind) {
    case 'routeros_api':
      return 'supportsRouterosApi';
    case 'ssh':
      return 'supportsSsh';
    case 'rest':
      return 'supportsRest';
    case 'cwmp':
      return 'supportsCwmp';
    case 'snmp':
      return 'supportsSnmp';
  }
}
