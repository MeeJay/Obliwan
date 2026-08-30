/**
 * ObliWAN — the `DeviceDriver` contract (decision D2).
 *
 * This module is the vocabulary shared by the driver layer AND by the
 * transports underneath it (`services/transport/*`). It deliberately imports
 * nothing from `../transport`, so the dependency graph is one-way:
 *
 *     transport/*  ->  drivers/types.ts  <-  drivers/*.driver.ts
 *
 * Two rules the rest of the server depends on:
 *
 *  1. Nothing outside `services/drivers/` branches on `brand`. Callers read
 *     `driver.capabilities` (declarative, from `NO_CAPABILITIES`) and call the
 *     normalised method.
 *
 *  2. A method a driver cannot perform THROWS. It never returns an empty array
 *     or a null-filled record — a silent empty result reads as "the device has
 *     no interfaces", which is how a drift engine invents 400 findings or a
 *     planner decides a firewall is empty. In M2 every read path beyond
 *     `probe()` / `getInventory()` throws `NotImplementedError`.
 *
 * Section 8.2 (secrets): `ResolvedTransport.credentials` holds DECRYPTED
 * material. It exists in memory only, on the vault -> device path. It must
 * never be logged, serialised into an error message, stored in a snapshot, or
 * put in a `PlanOp`. Use `redact()` below on anything that goes to a log.
 */

import type {
  DeviceBrand,
  DeviceCapabilities,
  DeviceFamily,
  ObservedCapabilityOverrides,
  TransportKind,
} from '@obliwan/shared';
import type { CapabilityProbeResult } from '@obliwan/shared';

// ============================================================================
// Errors
// ============================================================================

/**
 * Why an operation failed, in terms the arbiter and the circuit breaker can
 * act on. `retryable` is the only thing the breaker reads: an auth failure
 * repeated 50 times is not a network problem and must not open a circuit that
 * a credential fix would close.
 */
export const DRIVER_ERROR_CODES = [
  'NOT_IMPLEMENTED',    // ObliWAN has not written this path yet (milestone Mx)
  'UNSUPPORTED',        // the family genuinely cannot do this
  'NO_TRANSPORT',       // no enabled channel of the required kind is configured
  'UNREACHABLE',        // tunnel down, TCP timeout, DNS failure
  'TIMEOUT',
  'AUTH_FAILED',        // bad credentials / expired token
  'PERMISSION_DENIED',  // authenticated, but the account lacks the right
  'TLS_PINNING_FAILED', // certificate fingerprint does not match the pin (R9)
  'PROTOCOL_ERROR',     // the device answered something we cannot map
  'PARSE_ERROR',
  'DEVICE_BUSY',        // another session holds the config lock
  'RATE_LIMITED',       // cloud quota (Nebula)
  'CIRCUIT_OPEN',       // the breaker refused to dial
  'UNKNOWN',
] as const;
export type DriverErrorCode = (typeof DRIVER_ERROR_CODES)[number];

/** Codes for which a retry can plausibly succeed without human action. */
const RETRYABLE: ReadonlySet<DriverErrorCode> = new Set<DriverErrorCode>([
  'UNREACHABLE',
  'TIMEOUT',
  'DEVICE_BUSY',
  'RATE_LIMITED',
  'CIRCUIT_OPEN',
]);

export class DriverError extends Error {
  readonly code: DriverErrorCode;
  readonly retryable: boolean;
  readonly transport: TransportKind | null;
  readonly detail: unknown;

  constructor(
    message: string,
    code: DriverErrorCode = 'UNKNOWN',
    opts: { retryable?: boolean; transport?: TransportKind | null; cause?: unknown } = {},
  ) {
    super(message);
    this.name = 'DriverError';
    this.code = code;
    this.retryable = opts.retryable ?? RETRYABLE.has(code);
    this.transport = opts.transport ?? null;
    this.detail = opts.cause;
  }
}

/**
 * "Written down, not written yet." Carries the milestone so the UI and the
 * logs can say *when* rather than just *no*. Never caught and turned into an
 * empty result.
 */
export class NotImplementedError extends DriverError {
  readonly milestone: string;
  constructor(operation: string, milestone: string) {
    super(`${operation} is not implemented yet (${milestone})`, 'NOT_IMPLEMENTED', {
      retryable: false,
    });
    this.name = 'NotImplementedError';
    this.milestone = milestone;
  }
}

/** The family cannot do it at all — no milestone will change that. */
export const unsupported = (operation: string, family: string): DriverError =>
  new DriverError(`${operation} is not supported on ${family}`, 'UNSUPPORTED', {
    retryable: false,
  });

/** Normalise anything thrown into a DriverError without losing the message. */
export function asDriverError(
  err: unknown,
  fallbackCode: DriverErrorCode = 'UNKNOWN',
  transport: TransportKind | null = null,
): DriverError {
  if (err instanceof DriverError) return err;
  const message = err instanceof Error ? err.message : String(err);
  return new DriverError(message, fallbackCode, { transport, cause: err });
}

// ============================================================================
// Redaction — section 8.2
// ============================================================================

/** What a redacted secret looks like everywhere in the product. */
export const REDACTED = '***REDACTED***';

/**
 * Remove known secret literals from a string before it reaches a log, an
 * error message or a persisted column.
 *
 * This is a LAST line of defence, not the strategy: the strategy is to never
 * put a secret into a string in the first place. It exists because device CLIs
 * happily echo the password you just typed back at you, and that echo would
 * otherwise land verbatim in `device_health.last_error`.
 *
 * Short secrets (< 4 chars) are skipped on purpose: replacing every "a" in a
 * transcript produces a useless log AND leaks the secret's length.
 */
export function redact(text: string, secrets: ReadonlyArray<string | null | undefined>): string {
  let out = text;
  for (const secret of secrets) {
    if (!secret || secret.length < 4) continue;
    out = out.split(secret).join(REDACTED);
  }
  return out;
}

/** Every secret literal carried by a transport, for `redact()`. */
export function secretsOf(t: Pick<ResolvedTransport, 'credentials'>): string[] {
  const c = t.credentials;
  return [c.password, c.privateKey, c.passphrase, c.apiKey, c.snmp?.community, c.snmp?.authKey, c.snmp?.privKey]
    .filter((v): v is string => typeof v === 'string' && v.length > 0);
}

// ============================================================================
// Connection descriptors
// ============================================================================

/** SNMP v3 USM material. v2c uses `community` only. */
export interface SnmpCredentialMaterial {
  /** v2c community. Never logged. */
  community?: string | null;
  /** v3 USM user name (not a secret, but kept together with the rest). */
  username?: string | null;
  authProtocol?: 'md5' | 'sha' | 'sha224' | 'sha256' | 'sha384' | 'sha512' | null;
  authKey?: string | null;
  privProtocol?: 'des' | 'aes' | 'aes128' | 'aes192' | 'aes256' | null;
  privKey?: string | null;
  context?: string | null;
}

/**
 * Decrypted credential material for ONE channel. Produced by the caller from
 * `device_transports` + `secretVault.decrypt()`. Drivers never touch the DB
 * and never touch the vault.
 */
export interface TransportCredentials {
  username?: string | null;
  password?: string | null;
  /** OpenSSH private key, PEM text. Preferred over `password` (risk R9). */
  privateKey?: string | null;
  passphrase?: string | null;
  /** Bearer / API key for cloud REST (Nebula). */
  apiKey?: string | null;
  snmp?: SnmpCredentialMaterial;
}

/** One row of `device_transports`, with its secrets already decrypted. */
export interface ResolvedTransport {
  transport: TransportKind;
  enabled: boolean;
  /** Lower wins. Mirrors `device_transports.priority`. */
  priority: number;
  /** Null for `cwmp`: the CPE dials us, there is nothing to dial. */
  host: string | null;
  port: number | null;
  useTls: boolean;
  /** Pinned on the first successful handshake; a mismatch is fatal (R9). */
  tlsFingerprintSha256: string | null;
  /** Transport-specific knobs. NEVER a secret. */
  params: Record<string, unknown>;
  credentials: TransportCredentials;
}

/**
 * Everything a driver needs for one device, for the duration of one operation.
 *
 * `host` is deliberately absent at this level: the address lives on each
 * transport row, because the SNMP host (tunnel IP) and the REST host (cloud
 * endpoint) are not the same machine. And per D5, the tunnel IP is never an
 * identity — it is only "where to dial today".
 */
export interface DriverContext {
  deviceId: number;
  tenantId: number;
  /** Declared family from `devices.family`; may disagree with reality until a
   *  probe says otherwise — that disagreement is exactly what probe reports. */
  family: DeviceFamily | null;
  transports: ResolvedTransport[];
  /** Default per-operation budget. Individual calls may shorten it. */
  timeoutMs?: number;
  /** Correlation id for the audit trail. */
  correlationId?: string;
}

/** First enabled transport of a given kind, honouring `priority`. */
export function pickTransport(
  ctx: DriverContext,
  kind: TransportKind,
): ResolvedTransport | null {
  return (
    ctx.transports
      .filter((t) => t.transport === kind && t.enabled)
      .sort((a, b) => a.priority - b.priority)[0] ?? null
  );
}

/** Same, but throws the error the arbiter expects instead of returning null. */
export function requireTransport(ctx: DriverContext, kind: TransportKind): ResolvedTransport {
  const t = pickTransport(ctx, kind);
  if (!t) {
    throw new DriverError(
      `device ${ctx.deviceId} has no enabled "${kind}" transport configured`,
      'NO_TRANSPORT',
      { transport: kind, retryable: false },
    );
  }
  return t;
}

// ============================================================================
// Operation results
// ============================================================================

/**
 * What identification learned. Every field is nullable because a half-answer
 * is normal: SNMP gives sysName and a model string but no serial, RouterOS
 * gives a serial only on a RouterBOARD (a CHR has none).
 */
export interface DeviceInventory {
  brand: DeviceBrand | null;
  family: DeviceFamily | null;
  model: string | null;
  serial: string | null;
  osVersion: string | null;
  /** `/system/identity`, `sysName`, `hostname` — the operator-set label. */
  systemIdentity: string | null;
  boardName: string | null;
  uptimeSeconds: number | null;
  /** The address that actually answered. Diagnostics only, never identity. */
  managementAddress: string | null;
  /** Which channel produced this record. `null` when nothing answered. */
  collectedVia: TransportKind | null;
  collectedAt: string;
}

/** Empty inventory, so a driver never has to hand-write eleven nulls. */
export function emptyInventory(via: TransportKind | null = null): DeviceInventory {
  return {
    brand: null,
    family: null,
    model: null,
    serial: null,
    osVersion: null,
    systemIdentity: null,
    boardName: null,
    uptimeSeconds: null,
    managementAddress: null,
    collectedVia: via,
    collectedAt: new Date().toISOString(),
  };
}

export interface TransportAttempt {
  transport: TransportKind;
  ok: boolean;
  latencyMs: number | null;
  /** Redacted message. Present only when `ok` is false. */
  error?: string;
  errorCode?: DriverErrorCode;
}

/**
 * Result of a probe. A probe NEVER mutates the device and never rejects: an
 * unreachable device is a fact to record (`reachable: false`), not an
 * exception to propagate — one dead CPE must not abort a fleet scan.
 */
export interface ProbeOutcome {
  reachable: boolean;
  attempts: TransportAttempt[];
  workingTransports: TransportKind[];
  failedTransports: TransportKind[];
  latencyMs: number | null;
  /** Per-unit deltas over the family defaults, for
   *  `device_capabilities.observed_overrides`. */
  observedOverrides: ObservedCapabilityOverrides;
  /** Whatever identification the probe got for free. */
  inventory: DeviceInventory | null;
  probedAt: string;
}

/** Adapter to the shared shape persisted in `device_capabilities`. */
export function toCapabilityProbeResult(
  deviceId: number,
  family: DeviceFamily,
  outcome: ProbeOutcome,
): CapabilityProbeResult {
  return {
    deviceId,
    family,
    workingTransports: outcome.workingTransports.slice(),
    failedTransports: outcome.failedTransports.slice(),
    probedAt: outcome.probedAt,
  };
}

// ============================================================================
// The driver
// ============================================================================

/**
 * One driver per family. M2 implements `probe()` and `getInventory()` only —
 * every other member is declared so the interface is stable, and throws
 * `NotImplementedError` with its milestone until that milestone lands.
 */
export interface DeviceDriver {
  /** Stable driver id. Equals the family, or `'unknown'`. */
  readonly id: string;
  readonly brand: DeviceBrand | null;
  readonly family: DeviceFamily | null;
  readonly capabilities: DeviceCapabilities;

  /** M2. Cheap reachability + transport discovery. Never mutates, never rejects. */
  probe(ctx: DriverContext): Promise<ProbeOutcome>;

  /** M2. Identification: brand, model, serial, OS version, system identity. */
  getInventory(ctx: DriverContext): Promise<DeviceInventory>;

  /** M3 — SNMP poller and interface series. */
  getInterfaces(ctx: DriverContext): Promise<never>;

  /** M5 — NCM collection. */
  exportConfig(ctx: DriverContext): Promise<never>;

  /** M6 — the write path (arbitrage A2: all four brands, but not before M6). */
  applyConfig(ctx: DriverContext, rendered: string): Promise<never>;

  /** M6 — pre-change backup artefact. */
  backup(ctx: DriverContext): Promise<never>;

  /** M6 — reboot, gated by the change queue (D3). */
  reboot(ctx: DriverContext): Promise<never>;
}
