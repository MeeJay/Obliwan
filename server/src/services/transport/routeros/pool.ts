/**
 * ObliWAN — persistent RouterOS connection pool.
 *
 * Invariants this pool exists to hold:
 *
 *  - ONE socket per device, reused for the life of the process. Multiplexing
 *    by `.tag=` (see `connection.ts`) is what makes that possible; without it
 *    a pool would be pointless.
 *  - ONE socket to the CHR, no exception (risk R5). The concentrator is a
 *    single point of failure and a bottleneck; opening a second session on it
 *    per collector would be the fastest way to melt it.
 *  - Reconnection is RATE LIMITED GLOBALLY, not per device (risk R5 again).
 *    When the CHR comes back, ~300 CPE become reachable in the same second.
 *    A shared token bucket plus per-attempt jitter spreads that stampede.
 *  - The circuit breaker state is OWNED by this pool but PERSISTED by someone
 *    else. `device_health` belongs to another agent; the pool never touches
 *    the database. It calls the hooks it was handed and moves on.
 *
 * Nothing here logs a secret: credentials arrive already decrypted from the
 * vault, are passed straight to the connection, and never enter a log line.
 */

import crypto from 'crypto';
import type { CircuitState } from '@obliwan/shared';
import { logger } from '../../../utils/logger';
import {
  RouterOsAuthError,
  RouterOsConnection,
  RouterOsFingerprintError,
  createRouterOsConnection,
} from './connection';
import { invalidateCapabilities } from './capabilities';

// ============================================================================
// Public shapes
// ============================================================================

/** Everything needed to dial one device. Built by the arbiter from
 *  `device_transports` + the secret vault; the pool never reads the DB. */
export interface RouterOsTarget {
  /** `devices.id`. The pool key, and the key of the capability cache. */
  deviceId: string;
  host: string;
  port?: number;
  tls?: boolean;
  username: string;
  /** Plaintext, decrypted by the caller from `device_transports.secret_enc`. */
  password: string;
  /** `device_transports.tls_fingerprint_sha256`, or null for first use. */
  expectedFingerprint?: string | null;
  sourceAddress?: string;
  /** The concentrator. Logged and rate-limited more conservatively. */
  isConcentrator?: boolean;
  /** Human label for logs (site code, identity). Never a secret. */
  label?: string;
}

/** Circuit-breaker state as the pool sees it. The persistence layer maps this
 *  onto `device_health` columns; the shapes are intentionally 1:1. */
export interface DeviceHealthSnapshot {
  deviceId: string;
  circuit: CircuitState;
  consecutiveFailures: number;
  lastOkAt: Date | null;
  lastError: string | null;
  nextRetryAt: Date | null;
  openedAt: Date | null;
}

/**
 * Callbacks into the rest of the system. All optional, all best-effort:
 * a hook that throws is logged and swallowed, it never breaks a session.
 */
export interface RouterOsPoolHooks {
  /** Restore a persisted breaker state on the first acquire of a device. */
  loadHealth?: (deviceId: string) => Promise<Partial<DeviceHealthSnapshot> | null>;
  /** Persist a breaker transition (writes `device_health`). */
  saveHealth?: (snapshot: DeviceHealthSnapshot) => Promise<void>;
  /** First successful TLS handshake with no pin yet: store the fingerprint
   *  in `device_transports.tls_fingerprint_sha256`. */
  onFingerprint?: (deviceId: string, fingerprintSha256: string) => void;
  /** Session came up / went down. Feeds reachability, not alerting. */
  onSessionChange?: (deviceId: string, up: boolean, error?: Error) => void;
}

export interface RouterOsPoolOptions {
  /** Consecutive failures before the breaker opens. */
  failureThreshold?: number;
  backoffBaseMs?: number;
  backoffMaxMs?: number;
  /** Backoff after a credential or fingerprint refusal: retrying fast there
   *  achieves nothing and can lock the account out. */
  authBackoffMs?: number;
  /** Global dial budget (risk R5). Defaults to 4 burst, 2 per second. */
  dialBurst?: number;
  dialsPerSecond?: number;
  /** Liveness probe interval on idle sessions. 0 disables. */
  keepaliveMs?: number;
  connectTimeoutMs?: number;
  requestTimeoutMs?: number;
}

/** The breaker is open: the device is known-bad and must not be dialled. */
export class CircuitOpenError extends Error {
  readonly kind = 'circuit_open';
  readonly deviceId: string;
  readonly retryAt: Date | null;
  readonly lastError: string | null;
  constructor(deviceId: string, retryAt: Date | null, lastError: string | null) {
    super(
      `RouterOS circuit is open for device ${deviceId}` +
        (retryAt ? ` until ${retryAt.toISOString()}` : '') +
        (lastError ? ` (last error: ${lastError})` : ''),
    );
    this.name = 'CircuitOpenError';
    this.deviceId = deviceId;
    this.retryAt = retryAt;
    this.lastError = lastError;
  }
}

// ============================================================================
// Backoff — pure, therefore testable
// ============================================================================

/**
 * Exponential backoff with FULL jitter (random in `[base, delay]`), which is
 * the variant that actually de-correlates a fleet-wide stampede; classic
 * "delay +/- 20 %" leaves 300 devices retrying inside the same window.
 */
export function computeBackoffMs(
  consecutiveFailures: number,
  opts: { baseMs: number; maxMs: number; random?: () => number },
): number {
  const n = Math.max(1, consecutiveFailures);
  const exp = Math.min(opts.maxMs, opts.baseMs * 2 ** (n - 1));
  const rnd = (opts.random ?? Math.random)();
  return Math.round(opts.baseMs + rnd * Math.max(0, exp - opts.baseMs));
}

// ============================================================================
// Token bucket — the anti-stampede valve
// ============================================================================

export class TokenBucket {
  private tokens: number;
  private lastRefill = Date.now();
  constructor(
    private readonly capacity: number,
    private readonly refillPerSecond: number,
  ) {
    this.tokens = capacity;
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    if (elapsed <= 0) return;
    this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refillPerSecond);
    this.lastRefill = now;
  }

  /** Blocks until a token is available. */
  async take(): Promise<void> {
    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const deficit = 1 - this.tokens;
      const waitMs = Math.max(10, Math.ceil((deficit / this.refillPerSecond) * 1000));
      // NOT unref-ed on purpose: a caller is awaiting this delay, so it must
      // hold the event loop open until it fires.
      await new Promise<void>((res) => {
        setTimeout(res, waitMs);
      });
    }
  }

  /** Diagnostics only. */
  get available(): number {
    this.refill();
    return this.tokens;
  }
}

// ============================================================================
// Pool
// ============================================================================

/**
 * WHY A POOLED SESSION CARRIES A TARGET FINGERPRINT (audit M2/M3, finding 3)
 *
 * The pool is keyed on `deviceId` — it has to be, because "one socket per
 * device" is the invariant at the top of this file and the capability cache is
 * keyed the same way. But a device id is not a target: `device_transports`
 * carries the host, the port, the TLS flag, the account and the secret, and
 * every one of them can change under a live session.
 *
 * Before this, `acquire()` returned `e.conn` on the sole ground that it was
 * ready, so a session opened at boot survived a management-IP change, a
 * password rotation, an account revocation and the first pinning of a TLS
 * fingerprint — for the whole life of the process, because the 45 s keepalive
 * never lets it die. `resolveRouterOsTarget()` re-read the database faithfully
 * on every call and the pool then ignored the answer. The visible symptom was a
 * "test transport" button reporting success against a box that had not been
 * contacted; the one that matters is M6, where `assertTargetBinding()` proves
 * the identity of the NEW host on a fresh socket and then writes through the
 * pooled socket to the OLD one.
 *
 * So the entry remembers what it dialled, and `acquire()` compares. The
 * password is hashed, never stored in clear here: this structure is reachable
 * from `stats()` and from every heap dump.
 */
function targetFingerprint(target: RouterOsTarget): string {
  return [
    target.host,
    String(target.port ?? 8728),
    String(!!target.tls),
    target.username,
    crypto.createHash('sha256').update(target.password ?? '').digest('hex'),
    target.expectedFingerprint ?? '',
    target.sourceAddress ?? '',
  ].join('|');
}

interface PoolEntry {
  deviceId: string;
  conn: RouterOsConnection | null;
  connecting: Promise<RouterOsConnection> | null;
  /** Fingerprint of the target the current (or in-flight) session was dialled
   *  with. `null` when nothing has ever been dialled for this device. */
  targetFp: string | null;
  health: DeviceHealthSnapshot;
  healthLoaded: boolean;
}

const DEFAULTS: Required<RouterOsPoolOptions> = {
  failureThreshold: 4,
  backoffBaseMs: 2_000,
  backoffMaxMs: 300_000,
  authBackoffMs: 900_000,
  dialBurst: 4,
  dialsPerSecond: 2,
  keepaliveMs: 30_000,
  connectTimeoutMs: 10_000,
  requestTimeoutMs: 20_000,
};

export class RouterOsPool {
  private readonly entries = new Map<string, PoolEntry>();
  private readonly opts: Required<RouterOsPoolOptions>;
  private readonly hooks: RouterOsPoolHooks;
  private readonly bucket: TokenBucket;
  private keepaliveTimer: NodeJS.Timeout | null = null;
  private shuttingDown = false;

  constructor(hooks: RouterOsPoolHooks = {}, options: RouterOsPoolOptions = {}) {
    this.hooks = hooks;
    this.opts = { ...DEFAULTS, ...options };
    this.bucket = new TokenBucket(this.opts.dialBurst, this.opts.dialsPerSecond);
    if (this.opts.keepaliveMs > 0) {
      this.keepaliveTimer = setInterval(() => void this.runKeepalive(), this.opts.keepaliveMs);
      this.keepaliveTimer.unref?.();
    }
  }

  // -- entries --------------------------------------------------------------

  private entry(deviceId: string): PoolEntry {
    let e = this.entries.get(deviceId);
    if (!e) {
      e = {
        deviceId,
        conn: null,
        connecting: null,
        targetFp: null,
        healthLoaded: false,
        health: {
          deviceId,
          circuit: 'closed',
          consecutiveFailures: 0,
          lastOkAt: null,
          lastError: null,
          nextRetryAt: null,
          openedAt: null,
        },
      };
      this.entries.set(deviceId, e);
    }
    return e;
  }

  private async ensureHealthLoaded(e: PoolEntry): Promise<void> {
    if (e.healthLoaded) return;
    e.healthLoaded = true;
    if (!this.hooks.loadHealth) return;
    try {
      const stored = await this.hooks.loadHealth(e.deviceId);
      if (stored) e.health = { ...e.health, ...stored, deviceId: e.deviceId };
    } catch (err) {
      logger.warn(
        { deviceId: e.deviceId, err: (err as Error).message },
        'Could not restore persisted RouterOS circuit state; starting closed',
      );
    }
  }

  private persist(e: PoolEntry): void {
    if (!this.hooks.saveHealth) return;
    const snapshot = { ...e.health };
    void Promise.resolve(this.hooks.saveHealth(snapshot)).catch((err: Error) => {
      logger.warn(
        { deviceId: e.deviceId, err: err.message },
        'Could not persist RouterOS circuit state',
      );
    });
  }

  // -- breaker --------------------------------------------------------------

  /** Current breaker view of a device. Never dials. */
  health(deviceId: string): DeviceHealthSnapshot {
    return { ...this.entry(deviceId).health };
  }

  private markSuccess(e: PoolEntry): void {
    const wasOpen = e.health.circuit !== 'closed' || e.health.consecutiveFailures > 0;
    e.health.circuit = 'closed';
    e.health.consecutiveFailures = 0;
    e.health.lastOkAt = new Date();
    e.health.lastError = null;
    e.health.nextRetryAt = null;
    e.health.openedAt = null;
    if (wasOpen) {
      logger.info({ deviceId: e.deviceId }, 'RouterOS circuit closed');
    }
    this.persist(e);
  }

  private markFailure(e: PoolEntry, err: Error): void {
    e.health.consecutiveFailures += 1;
    e.health.lastError = err.message;

    const isRefusal = err instanceof RouterOsAuthError || err instanceof RouterOsFingerprintError;
    const backoff = isRefusal
      ? this.opts.authBackoffMs
      : computeBackoffMs(e.health.consecutiveFailures, {
          baseMs: this.opts.backoffBaseMs,
          maxMs: this.opts.backoffMaxMs,
        });

    // A rejected credential or a changed certificate is not a flaky link:
    // open immediately rather than burning three more attempts on it.
    const shouldOpen = isRefusal || e.health.consecutiveFailures >= this.opts.failureThreshold;
    if (shouldOpen && e.health.circuit !== 'open') {
      e.health.circuit = 'open';
      e.health.openedAt = new Date();
      logger.warn(
        {
          deviceId: e.deviceId,
          failures: e.health.consecutiveFailures,
          backoffMs: backoff,
          reason: err.name,
        },
        'RouterOS circuit opened',
      );
    }
    e.health.nextRetryAt = new Date(Date.now() + backoff);
    this.persist(e);
  }

  /** Report a request-level failure that means the transport is suspect
   *  (used by callers that hold a connection handle directly). */
  reportFailure(deviceId: string, err: Error): void {
    this.markFailure(this.entry(deviceId), err);
  }

  /** Report that a request went through, closing the breaker. */
  reportSuccess(deviceId: string): void {
    this.markSuccess(this.entry(deviceId));
  }

  // -- acquisition ----------------------------------------------------------

  /**
   * Get the device's session, opening it if needed.
   *
   * Concurrent callers share ONE dial: the in-flight promise is memoised, so
   * ten collectors waking at the same second still produce a single socket.
   */
  async acquire(target: RouterOsTarget): Promise<RouterOsConnection> {
    if (this.shuttingDown) throw new Error('RouterOS pool is shutting down');
    const e = this.entry(target.deviceId);
    await this.ensureHealthLoaded(e);
    const fp = targetFingerprint(target);

    // A dial is already in flight. AWAIT it instead of returning it blindly:
    // it may be a dial towards the PREVIOUS target, and the caller that is
    // holding the new one must not be handed the old socket. Once it settles,
    // the comparison below decides whether it is usable.
    if (e.connecting) {
      try {
        await e.connecting;
      } catch {
        // The dialer already recorded the failure on the breaker and rejected
        // its own caller; this caller re-evaluates from a clean state.
      }
    }

    // Host, port, TLS, account, secret or expected certificate changed since
    // the last dial. Note the condition does NOT require a live session: the
    // interesting case is precisely the one where there is none, because the
    // previous target's credential was refused and the breaker is open.
    if (e.targetFp !== null && e.targetFp !== fp) {
      logger.info(
        { deviceId: e.deviceId, concentrator: !!target.isConcentrator, hadSession: !!e.conn },
        'RouterOS transport target changed: dropping any pooled session and re-dialling',
      );
      // An open session towards the previous target is not an answer to a
      // request for this one. Close it rather than hand it back.
      if (e.conn) this.dropSession(e);
      e.targetFp = null;
      // The breaker described the OLD target. Keeping it would mean the four
      // auth failures caused by an expired password lock out the corrected one
      // for `authBackoffMs` — the operator fixes the credential and the product
      // keeps refusing to dial for fifteen minutes. A new target is entitled to
      // a new verdict; a target that has NOT changed keeps its backoff, which
      // is what the breaker is for.
      this.resetBreakerForNewTarget(e);
    }

    if (e.conn && e.conn.isReady) return e.conn;
    if (e.connecting) return e.connecting;

    // Breaker gate.
    const now = Date.now();
    if (e.health.circuit === 'open') {
      const retryAt = e.health.nextRetryAt;
      if (retryAt && retryAt.getTime() > now) {
        throw new CircuitOpenError(e.deviceId, retryAt, e.health.lastError);
      }
      e.health.circuit = 'half_open';
      logger.info({ deviceId: e.deviceId }, 'RouterOS circuit half-open: allowing one probe');
      this.persist(e);
    }

    // Recorded BEFORE the dial so a concurrent `acquire()` compares against
    // what is actually being opened, not against what was open before.
    e.targetFp = fp;
    const dial = this.dial(e, target);
    e.connecting = dial;
    try {
      return await dial;
    } finally {
      if (e.connecting === dial) e.connecting = null;
    }
  }

  private async dial(e: PoolEntry, target: RouterOsTarget): Promise<RouterOsConnection> {
    // Global valve. When the CHR returns, 300 devices arrive here at once;
    // they leave at `dialsPerSecond`, in a random order, jittered.
    await this.bucket.take();
    // Per-attempt jitter on top of the bucket: the bucket paces the fleet,
    // the jitter breaks the lockstep inside a single release burst.
    await new Promise<void>((res) => {
      setTimeout(res, Math.floor(Math.random() * 250));
    });

    const label = target.label ?? target.deviceId;
    try {
      const conn = await createRouterOsConnection({
        host: target.host,
        port: target.port,
        tls: target.tls,
        username: target.username,
        password: target.password,
        expectedFingerprint: target.expectedFingerprint ?? null,
        sourceAddress: target.sourceAddress,
        connectTimeoutMs: this.opts.connectTimeoutMs,
        requestTimeoutMs: this.opts.requestTimeoutMs,
        label,
        onFingerprint: (fp) => {
          try {
            this.hooks.onFingerprint?.(target.deviceId, fp);
          } catch (err) {
            logger.warn(
              { deviceId: target.deviceId, err: (err as Error).message },
              'onFingerprint hook threw',
            );
          }
        },
      });

      conn.on('close', (err?: Error) => this.onSessionClosed(e, conn, err));
      e.conn = conn;
      this.markSuccess(e);
      this.notifySession(target.deviceId, true);
      logger.info(
        { deviceId: target.deviceId, target: conn.target, concentrator: !!target.isConcentrator },
        'RouterOS session opened',
      );
      return conn;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      e.conn = null;
      this.markFailure(e, error);
      this.notifySession(target.deviceId, false, error);
      throw error;
    }
  }

  /** Close the pooled session without touching the breaker. The `close` event
   *  it triggers is a no-op in `onSessionClosed` because `e.conn` is already
   *  cleared — the "a newer session replaced it" guard covers this case too. */
  private dropSession(e: PoolEntry): void {
    const conn = e.conn;
    if (!conn) return;
    e.conn = null;
    e.targetFp = null;
    conn.close();
    invalidateCapabilities(e.deviceId);
  }

  /** The target changed, so the accumulated verdict no longer describes
   *  anything. `lastOkAt` is kept: it is a fact about the past, not a claim
   *  about the new target. */
  private resetBreakerForNewTarget(e: PoolEntry): void {
    if (e.health.circuit === 'closed' && e.health.consecutiveFailures === 0) return;
    e.health.circuit = 'closed';
    e.health.consecutiveFailures = 0;
    e.health.lastError = null;
    e.health.nextRetryAt = null;
    e.health.openedAt = null;
    logger.info({ deviceId: e.deviceId }, 'RouterOS circuit reset: the transport target changed');
    this.persist(e);
  }

  private onSessionClosed(e: PoolEntry, conn: RouterOsConnection, err?: Error): void {
    if (e.conn !== conn) return; // a newer session already replaced it
    e.conn = null;
    e.targetFp = null;
    // Capabilities are per-firmware AND per-session: a box that reconnected
    // may have been upgraded in between.
    invalidateCapabilities(e.deviceId);
    if (err) this.markFailure(e, err);
    this.notifySession(e.deviceId, false, err);
    logger.warn(
      { deviceId: e.deviceId, err: err?.message },
      'RouterOS session closed',
    );
  }

  private notifySession(deviceId: string, up: boolean, err?: Error): void {
    try {
      this.hooks.onSessionChange?.(deviceId, up, err);
    } catch (hookErr) {
      logger.warn(
        { deviceId, err: (hookErr as Error).message },
        'onSessionChange hook threw',
      );
    }
  }

  /**
   * Acquire, run, and account for the outcome in one call. This is the
   * ergonomic entry point for collectors; the breaker is fed automatically.
   */
  async withConnection<T>(
    target: RouterOsTarget,
    fn: (conn: RouterOsConnection) => Promise<T>,
  ): Promise<T> {
    const conn = await this.acquire(target);
    try {
      const result = await fn(conn);
      this.reportSuccess(target.deviceId);
      return result;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      // A trap is the ROUTER answering, not a broken transport: it must not
      // count against the breaker or one bad command would blacklist a device.
      if ((error as { kind?: string }).kind !== 'trap') {
        this.reportFailure(target.deviceId, error);
      }
      throw error;
    }
  }

  // -- maintenance ----------------------------------------------------------

  private async runKeepalive(): Promise<void> {
    if (this.shuttingDown) return;
    const live = Array.from(this.entries.values()).filter((e) => e.conn?.isReady);
    for (const e of live) {
      const conn = e.conn;
      if (!conn) continue;
      // A session that answered something recently needs no probe.
      if (Date.now() - conn.lastActivityAt < this.opts.keepaliveMs) continue;
      try {
        await conn.ping();
      } catch (err) {
        logger.warn(
          { deviceId: e.deviceId, err: (err as Error).message },
          'RouterOS keepalive failed; dropping the session',
        );
        conn.destroy(err instanceof Error ? err : new Error(String(err)));
      }
    }
  }

  /** Close one device's session (leaves the breaker state untouched). */
  close(deviceId: string): void {
    const e = this.entries.get(deviceId);
    if (!e?.conn) return;
    this.dropSession(e);
  }

  /** Sessions currently established. */
  get openSessions(): number {
    let n = 0;
    for (const e of this.entries.values()) if (e.conn?.isReady) n++;
    return n;
  }

  /** Snapshot for the UI / health endpoint. Contains no credentials. */
  stats(): Array<{ deviceId: string; connected: boolean; inFlight: number; circuit: CircuitState; failures: number }> {
    return Array.from(this.entries.values()).map((e) => ({
      deviceId: e.deviceId,
      connected: !!e.conn?.isReady,
      inFlight: e.conn?.inFlight ?? 0,
      circuit: e.health.circuit,
      failures: e.health.consecutiveFailures,
    }));
  }

  /** Close everything. Safe to call twice. */
  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    if (this.keepaliveTimer) {
      clearInterval(this.keepaliveTimer);
      this.keepaliveTimer = null;
    }
    for (const e of this.entries.values()) {
      const conn = e.conn;
      e.conn = null;
      e.targetFp = null;
      conn?.close();
    }
    this.entries.clear();
  }
}
