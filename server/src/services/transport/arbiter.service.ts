/**
 * ObliWAN — Transport Arbiter (feature C3).
 *
 * Answers one question: "the caller wants to do X on device D — which channel,
 * if any, should it use right now?"
 *
 * Four inputs, in this order of authority:
 *
 *  1. The DRIVER'S CAPABILITIES. A flag left at `false` means "we do not know
 *     how to do this", and the arbiter refuses. This is a permanent refusal:
 *     waiting does not teach a driver a new trick.
 *  2. The INTENT'S allowed channels. Reading a PPP table over SNMP is not a
 *     thing; asking for it is a bug, not a retry.
 *  3. The CONFIGURED TRANSPORTS (`device_transports`), enabled ones only, in
 *     `priority` order — lower wins.
 *  4. The PERSISTED CIRCUIT BREAKER (`device_health`). Persisted, because an
 *     in-memory breaker resets on every deploy and a restart would then
 *     stampede 300 unreachable devices at once (risk R5).
 *
 * When every channel is temporarily unusable the arbiter DEFERS: it returns a
 * retry time and parks the intent, instead of failing the caller. A transient
 * tunnel outage must not turn into 300 error toasts and 300 lost pieces of
 * work.
 *
 * Decision D3: nothing writes to a device outside the `change_jobs` queue. A
 * write intent presented without `viaChangeQueue` is refused here, at the
 * choke point, rather than trusted to every future call site.
 */

import type {
  DeviceCapabilities,
  DeviceCapabilityFlag,
  TransportKind,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { DriverError, type ResolvedTransport } from '../drivers/types';

// ============================================================================
// Intents
// ============================================================================

export const TRANSPORT_INTENTS = [
  'probe',           // is it there, and what answers
  'inventory',       // brand / model / serial / os version / identity
  'read_interfaces', // M3
  'read_config',     // M5
  'ppp_presence',    // concentrator only — /ppp/active (+ listen)
  'ppp_secrets',     // concentrator only — /ppp/secret
  'write_config',    // M6
  'backup',          // M6
  'reboot',          // M6
] as const;
export type TransportIntent = (typeof TRANSPORT_INTENTS)[number];

interface IntentSpec {
  /** All of these capability flags must be true on the driver. */
  requires: DeviceCapabilityFlag[];
  /** Channels that can serve this intent at all, best first. */
  channels: TransportKind[];
  /** Mutates the device — gated by the change queue (D3). */
  write: boolean;
}

const INTENTS: Readonly<Record<TransportIntent, IntentSpec>> = {
  probe: { requires: [], channels: ['routeros_api', 'ssh', 'rest', 'snmp'], write: false },
  inventory: { requires: [], channels: ['routeros_api', 'ssh', 'rest', 'snmp'], write: false },
  read_interfaces: {
    requires: ['canReadInterfaces'],
    channels: ['routeros_api', 'snmp', 'ssh', 'rest'],
    write: false,
  },
  read_config: {
    requires: ['canExportConfig'],
    // Never SNMP: MIB-II carries no configuration.
    channels: ['routeros_api', 'ssh', 'rest', 'cwmp'],
    write: false,
  },
  ppp_presence: { requires: ['canReadPppSessions'], channels: ['routeros_api'], write: false },
  ppp_secrets: { requires: ['canReadPppSessions'], channels: ['routeros_api'], write: false },
  write_config: {
    requires: ['canPushConfig'],
    channels: ['routeros_api', 'ssh', 'rest', 'cwmp'],
    write: true,
  },
  backup: { requires: ['canBackup'], channels: ['routeros_api', 'ssh', 'rest', 'cwmp'], write: true },
  reboot: { requires: ['canReboot'], channels: ['routeros_api', 'ssh', 'rest', 'cwmp'], write: true },
};

/** Which capability flag says "the driver can open this kind of channel". */
const TRANSPORT_FLAG: Readonly<Record<TransportKind, DeviceCapabilityFlag>> = {
  routeros_api: 'supportsRouterosApi',
  ssh: 'supportsSsh',
  rest: 'supportsRest',
  cwmp: 'supportsCwmp',
  snmp: 'supportsSnmp',
};

// ============================================================================
// Health / circuit breaker
// ============================================================================

export type CircuitState = 'closed' | 'open' | 'half_open';

/** One row of `device_health`, as the arbiter reads it. */
export interface TransportHealth {
  deviceId: number;
  transport: TransportKind;
  enabled: boolean;
  circuitState: CircuitState;
  consecutiveFailures: number;
  backoffMs: number;
  nextRetryAt: Date | null;
}

export function defaultHealth(deviceId: number, transport: TransportKind): TransportHealth {
  return {
    deviceId,
    transport,
    enabled: true,
    circuitState: 'closed',
    consecutiveFailures: 0,
    backoffMs: 0,
    nextRetryAt: null,
  };
}

export interface BreakerPolicy {
  /** Consecutive retryable failures before the circuit opens. */
  failureThreshold: number;
  baseBackoffMs: number;
  maxBackoffMs: number;
  /**
   * Backoff applied to a failure that a retry cannot fix (bad credentials,
   * refused algorithm). Deliberately long: hammering a management interface
   * with a wrong password is how a fleet account gets locked out, and the fix
   * is a human editing a credential, not another attempt in five seconds.
   */
  nonRetryableBackoffMs: number;
}

export const DEFAULT_BREAKER: BreakerPolicy = {
  failureThreshold: 4,
  baseBackoffMs: 5_000,
  maxBackoffMs: 15 * 60_000,
  nonRetryableBackoffMs: 15 * 60_000,
};

/**
 * Exponential, capped, with ±20 % jitter.
 *
 * The jitter is not cosmetic: when the CHR comes back, 300 devices whose
 * breakers all opened at the same second would otherwise retry at the same
 * second (risk R5). `consecutiveFailures` is 1-based.
 */
export function computeBackoffMs(
  consecutiveFailures: number,
  policy: BreakerPolicy = DEFAULT_BREAKER,
  random: () => number = Math.random,
): number {
  const n = Math.max(1, consecutiveFailures);
  const raw = policy.baseBackoffMs * 2 ** (n - 1);
  const capped = Math.min(raw, policy.maxBackoffMs);
  const jitter = 0.8 + random() * 0.4;
  return Math.round(capped * jitter);
}

export interface BreakerTransition {
  circuitState: CircuitState;
  consecutiveFailures: number;
  backoffMs: number;
  nextRetryAt: Date | null;
}

/** Pure state machine — the DB write is a separate concern. */
export function onFailure(
  current: TransportHealth,
  opts: { retryable: boolean; now?: Date; policy?: BreakerPolicy; random?: () => number },
): BreakerTransition {
  const policy = opts.policy ?? DEFAULT_BREAKER;
  const now = opts.now ?? new Date();
  const failures = current.consecutiveFailures + 1;

  if (!opts.retryable) {
    return {
      circuitState: 'open',
      consecutiveFailures: failures,
      backoffMs: policy.nonRetryableBackoffMs,
      nextRetryAt: new Date(now.getTime() + policy.nonRetryableBackoffMs),
    };
  }

  // A half-open trial that fails goes straight back to open: the point of the
  // trial was to answer "is it back?", and the answer was no.
  const shouldOpen = current.circuitState === 'half_open' || failures >= policy.failureThreshold;
  if (!shouldOpen) {
    return {
      circuitState: 'closed',
      consecutiveFailures: failures,
      backoffMs: 0,
      nextRetryAt: null,
    };
  }

  const backoffMs = computeBackoffMs(failures, policy, opts.random);
  return {
    circuitState: 'open',
    consecutiveFailures: failures,
    backoffMs,
    nextRetryAt: new Date(now.getTime() + backoffMs),
  };
}

export function onSuccess(): BreakerTransition {
  return { circuitState: 'closed', consecutiveFailures: 0, backoffMs: 0, nextRetryAt: null };
}

// ============================================================================
// Decision
// ============================================================================

export interface ChannelCandidateRejection {
  transport: TransportKind;
  reason: string;
  /** true when time alone can fix it (open circuit), false when it cannot
   *  (capability missing, transport not configured). */
  transient: boolean;
  retryAt: Date | null;
}

export type ArbiterDecision =
  | {
      outcome: 'selected';
      transport: TransportKind;
      channel: ResolvedTransport;
      /** The circuit was open and its backoff elapsed: this call is the probe
       *  that decides whether the channel is back. One trial at a time. */
      halfOpenTrial: boolean;
      rejected: ChannelCandidateRejection[];
    }
  | {
      outcome: 'deferred';
      /** Earliest moment any channel could work again. */
      retryAt: Date;
      reason: string;
      rejected: ChannelCandidateRejection[];
    }
  | {
      outcome: 'refused';
      code: 'UNSUPPORTED' | 'NO_TRANSPORT' | 'WRITE_NOT_QUEUED';
      reason: string;
      rejected: ChannelCandidateRejection[];
    };

export interface ChooseChannelInput {
  intent: TransportIntent;
  capabilities: DeviceCapabilities;
  transports: ResolvedTransport[];
  health: TransportHealth[];
  now?: Date;
  /** Set by the change-job runner only. Without it, write intents are refused
   *  at this choke point (D3). */
  viaChangeQueue?: boolean;
  /** Force one specific channel (operator "test this transport" button).
   *  Still subject to capabilities and to the breaker. */
  requireTransport?: TransportKind;
}

/**
 * Pure selection. No I/O, no clock of its own, no database — which is what
 * makes it testable without a device, and what makes its behaviour under a
 * flapping tunnel reproducible.
 */
export function chooseChannel(input: ChooseChannelInput): ArbiterDecision {
  const now = input.now ?? new Date();
  const spec = INTENTS[input.intent];
  const rejected: ChannelCandidateRejection[] = [];

  if (spec.write && !input.viaChangeQueue) {
    return {
      outcome: 'refused',
      code: 'WRITE_NOT_QUEUED',
      reason:
        `intent "${input.intent}" writes to the device and was not presented by the change queue. ` +
        `Decision D3: every write goes through change_jobs, with a device lock, a frozen plan and a dead-man.`,
      rejected,
    };
  }

  const missingCapability = spec.requires.filter((flag) => !input.capabilities[flag]);
  if (missingCapability.length > 0) {
    return {
      outcome: 'refused',
      code: 'UNSUPPORTED',
      reason: `driver does not declare ${missingCapability.join(', ')} for intent "${input.intent}"`,
      rejected,
    };
  }

  const healthByTransport = new Map<TransportKind, TransportHealth>(
    input.health.map((h) => [h.transport, h]),
  );

  // Order: the intent's own preference first, then the driver's declared
  // `transportPriority`, then the operator's `device_transports.priority`.
  // Rationale: the intent knows what the data lives in, the driver knows what
  // it speaks best, and the operator breaks the tie for a specific unit.
  const ranked = [...input.transports]
    .filter((t) => {
      if (!spec.channels.includes(t.transport)) {
        rejected.push({
          transport: t.transport,
          reason: `"${t.transport}" cannot serve intent "${input.intent}"`,
          transient: false,
          retryAt: null,
        });
        return false;
      }
      if (input.requireTransport && t.transport !== input.requireTransport) return false;
      if (!t.enabled) {
        rejected.push({
          transport: t.transport,
          reason: 'transport row is disabled',
          transient: false,
          retryAt: null,
        });
        return false;
      }
      if (!input.capabilities[TRANSPORT_FLAG[t.transport]]) {
        rejected.push({
          transport: t.transport,
          reason: `driver does not declare ${TRANSPORT_FLAG[t.transport]}`,
          transient: false,
          retryAt: null,
        });
        return false;
      }
      // cwmp has no host on purpose (the CPE dials us); everything else needs one.
      if (t.transport !== 'cwmp' && !t.host) {
        rejected.push({
          transport: t.transport,
          reason: 'transport row has no host',
          transient: false,
          retryAt: null,
        });
        return false;
      }
      return true;
    })
    .sort((a, b) => {
      const intentRank = spec.channels.indexOf(a.transport) - spec.channels.indexOf(b.transport);
      if (intentRank !== 0) return intentRank;
      const driverRank =
        rankIn(input.capabilities.transportPriority, a.transport) -
        rankIn(input.capabilities.transportPriority, b.transport);
      if (driverRank !== 0) return driverRank;
      return a.priority - b.priority;
    });

  if (ranked.length === 0) {
    return {
      outcome: 'refused',
      code: 'NO_TRANSPORT',
      reason: `no enabled transport can serve intent "${input.intent}"`,
      rejected,
    };
  }

  let earliestRetry: Date | null = null;

  for (const candidate of ranked) {
    const health = healthByTransport.get(candidate.transport) ?? defaultHealth(-1, candidate.transport);

    if (!health.enabled) {
      rejected.push({
        transport: candidate.transport,
        reason: 'channel disabled by the operator kill-switch',
        transient: false,
        retryAt: null,
      });
      continue;
    }

    if (health.circuitState === 'open') {
      const due = health.nextRetryAt;
      if (due && due.getTime() > now.getTime()) {
        rejected.push({
          transport: candidate.transport,
          reason: `circuit open until ${due.toISOString()}`,
          transient: true,
          retryAt: due,
        });
        if (!earliestRetry || due.getTime() < earliestRetry.getTime()) earliestRetry = due;
        continue;
      }
      // Backoff elapsed (or was never set): this call is the trial.
      return {
        outcome: 'selected',
        transport: candidate.transport,
        channel: candidate,
        halfOpenTrial: true,
        rejected,
      };
    }

    if (health.circuitState === 'half_open') {
      // A trial is already in flight elsewhere. Letting a second one through
      // is how a half-open breaker becomes a thundering herd.
      const due = health.nextRetryAt ?? new Date(now.getTime() + DEFAULT_BREAKER.baseBackoffMs);
      rejected.push({
        transport: candidate.transport,
        reason: 'a half-open trial is already in flight',
        transient: true,
        retryAt: due,
      });
      if (!earliestRetry || due.getTime() < earliestRetry.getTime()) earliestRetry = due;
      continue;
    }

    return {
      outcome: 'selected',
      transport: candidate.transport,
      channel: candidate,
      halfOpenTrial: false,
      rejected,
    };
  }

  return {
    outcome: 'deferred',
    retryAt: earliestRetry ?? new Date(now.getTime() + DEFAULT_BREAKER.baseBackoffMs),
    reason: `every channel for intent "${input.intent}" is in backoff`,
    rejected,
  };
}

function rankIn(order: readonly TransportKind[], kind: TransportKind): number {
  const i = order.indexOf(kind);
  return i === -1 ? order.length : i;
}

// ============================================================================
// Deferred intents
// ============================================================================

export interface DeferredIntent {
  deviceId: number;
  intent: TransportIntent;
  retryAt: Date;
  reason: string;
  queuedAt: Date;
}

/**
 * In-memory parking lot for intents no channel can serve yet.
 *
 * SCOPE, STATED PLAINLY: this queue does NOT survive a restart. That is
 * deliberate for M2, where every intent is a read (probe, inventory, presence
 * reconciliation) and the periodic scheduler will simply ask again. The
 * durable queue is `change_jobs` (M6) — writes never live here, they are
 * refused above until the change queue exists.
 *
 * Deduplicated on `(deviceId, intent)`: a scheduler that re-asks every 60 s
 * for a device that has been down for a week must not accumulate 10 000
 * identical entries.
 */
export class DeferredIntentQueue {
  private readonly entries = new Map<string, DeferredIntent>();
  private droppedForCapacity = 0;

  constructor(private readonly maxEntries = 5_000) {}

  private static key(deviceId: number, intent: TransportIntent): string {
    return `${deviceId}:${intent}`;
  }

  /** Keeps the EARLIEST retry time when the same intent is parked twice. */
  push(entry: Omit<DeferredIntent, 'queuedAt'>): void {
    const key = DeferredIntentQueue.key(entry.deviceId, entry.intent);
    const existing = this.entries.get(key);
    if (existing) {
      if (entry.retryAt.getTime() < existing.retryAt.getTime()) {
        existing.retryAt = entry.retryAt;
        existing.reason = entry.reason;
      }
      return;
    }
    if (this.entries.size >= this.maxEntries) {
      this.droppedForCapacity += 1;
      return;
    }
    this.entries.set(key, { ...entry, queuedAt: new Date() });
  }

  /** Entries whose retry time has come. Removed from the queue as they are
   *  handed out — the caller owns them from that point. */
  take(now: Date = new Date()): DeferredIntent[] {
    const due: DeferredIntent[] = [];
    for (const [key, entry] of this.entries) {
      if (entry.retryAt.getTime() <= now.getTime()) {
        due.push(entry);
        this.entries.delete(key);
      }
    }
    return due.sort((a, b) => a.retryAt.getTime() - b.retryAt.getTime());
  }

  cancel(deviceId: number, intent: TransportIntent): boolean {
    return this.entries.delete(DeferredIntentQueue.key(deviceId, intent));
  }

  get size(): number {
    return this.entries.size;
  }

  get dropped(): number {
    return this.droppedForCapacity;
  }

  clear(): void {
    this.entries.clear();
    this.droppedForCapacity = 0;
  }
}

// ============================================================================
// Health store
// ============================================================================

export interface HealthStore {
  load(deviceId: number): Promise<TransportHealth[]>;
  recordSuccess(deviceId: number, transport: TransportKind, rttMs: number | null): Promise<void>;
  recordFailure(
    deviceId: number,
    transport: TransportKind,
    err: { message: string; retryable: boolean },
  ): Promise<void>;
  markHalfOpen(deviceId: number, transport: TransportKind): Promise<void>;
}

interface HealthRow {
  device_id: number;
  transport: string;
  enabled: boolean;
  circuit_state: string;
  consecutive_failures: number;
  backoff_ms: number;
  next_retry_at: Date | string | null;
}

function toHealth(row: HealthRow): TransportHealth {
  return {
    deviceId: row.device_id,
    transport: row.transport as TransportKind,
    enabled: row.enabled,
    circuitState: row.circuit_state as CircuitState,
    consecutiveFailures: row.consecutive_failures,
    backoffMs: row.backoff_ms,
    nextRetryAt: row.next_retry_at ? new Date(row.next_retry_at) : null,
  };
}

/**
 * The transports whose `device_health` row this store MUST NOT write.
 *
 * ── ARBITRATION: ONE WRITER PER (device_id, transport) ROW ─────────────────
 *
 * `routeros_api` had two writers with two independent failure counters: the
 * `RouterOsPool` hooks in `services/fleet/routerosPool.ts`, and this store.
 * That is not a cosmetic duplication. The pool's breaker is the one that
 * actually GATES a dial — `RouterOsPool.acquire()` throws `CircuitOpenError`
 * off its in-memory state — while this store's counter only ever existed on
 * paper. With both writing, the row the arbiter reads at decision time is the
 * last one of the two to have written, which is a coin toss: the arbiter
 * selects a channel the pool will refuse to open (a circuit that never
 * reopens), or reports `closed` over a pool that is still open (a circuit that
 * never trips). Either way the breaker stops meaning anything.
 *
 * THE POOL WINS, for `routeros_api`. It is the component that holds the
 * socket, observes the failure, and enforces the refusal; a breaker owned
 * anywhere else is a description of events rather than a control over them.
 * So this store DELEGATES: it still READS the row (`load`/`current`, which is
 * exactly what makes the arbiter's decision agree with the pool's), and it
 * refuses to write it.
 *
 * Every other channel — `ssh`, `rest`, `snmp`, `cwmp` — has no pool and no
 * other writer, so this store owns those rows outright. The rule is one
 * writer per row, not one writer per table.
 */
const POOL_OWNED_TRANSPORTS: ReadonlySet<TransportKind> = new Set<TransportKind>(['routeros_api']);

/** `device_health`-backed store. The breaker survives a deploy (risk R5). */
export class DbHealthStore implements HealthStore {
  constructor(private readonly policy: BreakerPolicy = DEFAULT_BREAKER) {}

  async load(deviceId: number): Promise<TransportHealth[]> {
    const rows = await db<HealthRow>('device_health').where({ device_id: deviceId });
    return rows.map(toHealth);
  }

  private async current(deviceId: number, transport: TransportKind): Promise<TransportHealth> {
    const row = await db<HealthRow>('device_health')
      .where({ device_id: deviceId, transport })
      .first();
    return row ? toHealth(row) : defaultHealth(deviceId, transport);
  }

  private async upsert(
    deviceId: number,
    transport: TransportKind,
    patch: Record<string, unknown>,
  ): Promise<void> {
    // See POOL_OWNED_TRANSPORTS above: for a channel the pool owns, the pool
    // has already recorded this very outcome from the socket that observed it.
    // Writing here would be a second, competing counter on the same row.
    if (POOL_OWNED_TRANSPORTS.has(transport)) return;
    await db('device_health')
      .insert({ device_id: deviceId, transport, ...patch })
      .onConflict(['device_id', 'transport'])
      .merge();
  }

  async recordSuccess(deviceId: number, transport: TransportKind, rttMs: number | null): Promise<void> {
    const t = onSuccess();
    await this.upsert(deviceId, transport, {
      conn_state: 'ok',
      circuit_state: t.circuitState,
      consecutive_failures: t.consecutiveFailures,
      backoff_ms: t.backoffMs,
      next_retry_at: t.nextRetryAt,
      last_rtt_ms: rttMs,
      last_ok_at: new Date(),
      last_error: null,
      updated_at: new Date(),
    });
  }

  /**
   * `err.message` is written to `device_health.last_error`, which is read by
   * the UI. It MUST already be redacted — every transport in this folder
   * scrubs its own secrets before the message escapes (section 8.2).
   */
  async recordFailure(
    deviceId: number,
    transport: TransportKind,
    err: { message: string; retryable: boolean },
  ): Promise<void> {
    const current = await this.current(deviceId, transport);
    const t = onFailure(current, { retryable: err.retryable, policy: this.policy });
    await this.upsert(deviceId, transport, {
      conn_state: t.circuitState === 'open' ? 'down' : 'degraded',
      circuit_state: t.circuitState,
      consecutive_failures: t.consecutiveFailures,
      backoff_ms: t.backoffMs,
      next_retry_at: t.nextRetryAt,
      last_failure_at: new Date(),
      last_error: err.message.slice(0, 2_000),
      updated_at: new Date(),
    });
  }

  /** Claim the single half-open trial slot. */
  async markHalfOpen(deviceId: number, transport: TransportKind): Promise<void> {
    await this.upsert(deviceId, transport, {
      circuit_state: 'half_open',
      next_retry_at: new Date(Date.now() + this.policy.baseBackoffMs),
      updated_at: new Date(),
    });
  }
}

// ============================================================================
// Service
// ============================================================================

export interface AcquireInput {
  deviceId: number;
  intent: TransportIntent;
  capabilities: DeviceCapabilities;
  transports: ResolvedTransport[];
  viaChangeQueue?: boolean;
  requireTransport?: TransportKind;
  now?: Date;
}

/**
 * The arbiter as the rest of the server sees it: decide, park what cannot run,
 * and record the outcome so the breaker learns.
 *
 * Typical use:
 *
 *   const decision = await arbiter.acquire({ deviceId, intent: 'inventory', ... });
 *   if (decision.outcome !== 'selected') return;               // parked or refused
 *   try   { const r = await driver.getInventory(ctx);
 *           await arbiter.reportSuccess(deviceId, decision.transport, rtt); }
 *   catch (e) { await arbiter.reportFailure(deviceId, decision.transport, e); throw e; }
 */
export class TransportArbiter {
  readonly deferred = new DeferredIntentQueue();

  constructor(private readonly health: HealthStore = new DbHealthStore()) {}

  async acquire(input: AcquireInput): Promise<ArbiterDecision> {
    const health = await this.health.load(input.deviceId);
    const decision = chooseChannel({
      intent: input.intent,
      capabilities: input.capabilities,
      transports: input.transports,
      health,
      now: input.now,
      viaChangeQueue: input.viaChangeQueue,
      requireTransport: input.requireTransport,
    });

    if (decision.outcome === 'deferred') {
      this.deferred.push({
        deviceId: input.deviceId,
        intent: input.intent,
        retryAt: decision.retryAt,
        reason: decision.reason,
      });
      logger.debug(
        { deviceId: input.deviceId, intent: input.intent, retryAt: decision.retryAt },
        'transport arbiter: intent deferred, every channel in backoff',
      );
      return decision;
    }

    if (decision.outcome === 'selected' && decision.halfOpenTrial) {
      await this.health.markHalfOpen(input.deviceId, decision.transport);
    }

    return decision;
  }

  async reportSuccess(deviceId: number, transport: TransportKind, rttMs: number | null): Promise<void> {
    await this.health.recordSuccess(deviceId, transport, rttMs);
    // The channel is back: anything parked for this device can be tried again.
    for (const intent of TRANSPORT_INTENTS) this.deferred.cancel(deviceId, intent);
  }

  async reportFailure(deviceId: number, transport: TransportKind, err: unknown): Promise<void> {
    const driverError = err instanceof DriverError ? err : null;
    await this.health.recordFailure(deviceId, transport, {
      message: err instanceof Error ? err.message : String(err),
      retryable: driverError ? driverError.retryable : true,
    });
  }
}

/** Process-wide instance. */
export const transportArbiter = new TransportArbiter();
