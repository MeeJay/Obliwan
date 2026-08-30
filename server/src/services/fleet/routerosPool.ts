/**
 * ObliWAN — the process-wide RouterOS API pool, and the only place that turns
 * a `devices` row into dial-able coordinates.
 *
 * WHY THIS FILE EXISTS
 * `services/transport/routeros/pool.ts` is deliberately database-free: it knows
 * sockets, tags and breakers, and nothing else. It exposes hooks instead. Two
 * workstreams left the same note behind — "somebody must instantiate this once
 * and wire the hooks to `device_health`" — because the pool owns the SINGLE
 * socket to the CHR that the whole fleet shares (risk R5), and a second
 * instance would silently double every `listen`, every dial budget and every
 * breaker. So there is exactly one, here, memoised.
 *
 * The hooks below are the missing half:
 *   loadHealth / saveHealth  -> `device_health` (device_id, 'routeros_api').
 *                               The breaker therefore survives a deploy; an
 *                               in-memory one would stampede 300 unreachable
 *                               devices on every restart.
 *   onFingerprint            -> `device_transports.tls_fingerprint_sha256`.
 *                               Without this write, TOFU restarts from scratch
 *                               at every boot and the pinning of R9 protects
 *                               nothing at all.
 *   onSessionChange          -> forwarded to subscribers (presence, logs).
 *
 * SECRETS (section 8.2): the plaintext password exists here for the duration of
 * building a `RouterOsTarget` and nowhere else. It is never logged, never
 * returned by the API, never written back.
 */

import {
  RouterOsPool,
  type DeviceHealthSnapshot,
  type RouterOsTarget,
} from '../transport/routeros';
import {
  registerRouterOsChannelFactory,
  routerOsChannelFactoryFromPool,
} from '../drivers';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { decrypt } from '../secretVault.service';

const ROUTEROS = 'routeros_api';

// ============================================================================
// Session-change fan-out
// ============================================================================

type SessionListener = (deviceId: number, up: boolean, error?: Error) => void;

const sessionListeners = new Set<SessionListener>();

/** Subscribe to "the RouterOS session to this device came up / went down".
 *  Used by presence to notice the CHR itself dropping. Returns unsubscribe. */
export function onRouterOsSessionChange(listener: SessionListener): () => void {
  sessionListeners.add(listener);
  return () => {
    sessionListeners.delete(listener);
  };
}

// ============================================================================
// device_health persistence
// ============================================================================

/**
 * Map the pool's breaker snapshot onto `device_health`. `conn_state` is the
 * cheap label the UI reads; `circuit_state` is the real machine.
 *
 * ── THIS IS THE ONLY WRITER OF (device_id, 'routeros_api') ─────────────────
 *
 * `services/transport/arbiter.service.ts` used to write the same row from its
 * own `DbHealthStore`, with its own independent failure counter. That was
 * arbitrated in favour of THIS function, and `DbHealthStore.upsert()` now
 * returns early for `routeros_api` (see `POOL_OWNED_TRANSPORTS` there).
 *
 * The reason is that the pool's breaker is the one with teeth: `RouterOsPool`
 * refuses the dial itself, throwing `CircuitOpenError` off the in-memory state
 * this function persists. The arbiter's counter never gated anything. Two
 * counters on one row do not average out — whichever wrote last is what the
 * arbiter reads at decision time, so it either picks a channel the pool will
 * refuse to open (a circuit that never recloses) or reports `closed` over a
 * pool that is still open (a circuit that never trips).
 *
 * The arbiter still READS this row, through `DbHealthStore.load()`. That is
 * the point of the arbitration: what the arbiter sees when it chooses a
 * channel is exactly what the pool wrote when it failed to open one.
 *
 * The other four channels (`ssh`, `rest`, `snmp`, `cwmp`) have no pool, so
 * `DbHealthStore` remains their sole writer. One writer per row.
 */
async function saveHealth(snapshot: DeviceHealthSnapshot): Promise<void> {
  const deviceId = Number(snapshot.deviceId);
  if (!Number.isFinite(deviceId)) return;

  const connState =
    snapshot.circuit === 'open' ? 'down' : snapshot.consecutiveFailures > 0 ? 'degraded' : 'ok';

  await db('device_health')
    .insert({
      device_id: deviceId,
      transport: ROUTEROS,
      conn_state: connState,
      circuit_state: snapshot.circuit,
      consecutive_failures: snapshot.consecutiveFailures,
      backoff_ms: snapshot.nextRetryAt
        ? Math.max(0, snapshot.nextRetryAt.getTime() - Date.now())
        : 0,
      next_retry_at: snapshot.nextRetryAt,
      last_ok_at: snapshot.lastOkAt,
      last_failure_at: snapshot.lastError ? new Date() : null,
      // Truncated, and it is already a redacted message: the transport never
      // puts a credential in an Error string (proven by its own self-test).
      last_error: snapshot.lastError ? snapshot.lastError.slice(0, 500) : null,
      updated_at: db.fn.now(),
    })
    .onConflict(['device_id', 'transport'])
    .merge([
      'conn_state',
      'circuit_state',
      'consecutive_failures',
      'backoff_ms',
      'next_retry_at',
      'last_ok_at',
      'last_failure_at',
      'last_error',
      'updated_at',
    ]);
}

async function loadHealth(deviceId: string): Promise<Partial<DeviceHealthSnapshot> | null> {
  const id = Number(deviceId);
  if (!Number.isFinite(id)) return null;
  const row = await db('device_health')
    .where({ device_id: id, transport: ROUTEROS })
    .first<
      | {
          circuit_state: string;
          consecutive_failures: number;
          next_retry_at: Date | null;
          last_ok_at: Date | null;
          last_error: string | null;
        }
      | undefined
    >();
  if (!row) return null;
  return {
    deviceId,
    circuit: row.circuit_state as DeviceHealthSnapshot['circuit'],
    consecutiveFailures: row.consecutive_failures,
    nextRetryAt: row.next_retry_at,
    lastOkAt: row.last_ok_at,
    lastError: row.last_error,
  };
}

// ============================================================================
// The singleton
// ============================================================================

let pool: RouterOsPool | null = null;

/** The one and only RouterOS pool. Created on first use, wired to the DB. */
export function getRouterOsPool(): RouterOsPool {
  if (pool) return pool;

  pool = new RouterOsPool(
    {
      loadHealth: (deviceId) =>
        loadHealth(deviceId).catch((err) => {
          logger.warn({ err, deviceId }, 'device_health load failed; breaker starts cold');
          return null;
        }),
      saveHealth: (snapshot) =>
        saveHealth(snapshot).catch((err) => {
          logger.warn({ err, deviceId: snapshot.deviceId }, 'device_health persist failed');
        }),
      onFingerprint: (deviceId, fingerprint) => {
        // Trust-on-first-use only becomes pinning once this row is written.
        void db('device_transports')
          .where({ device_id: Number(deviceId), transport: ROUTEROS })
          .whereNull('tls_fingerprint_sha256')
          .update({ tls_fingerprint_sha256: fingerprint, updated_at: db.fn.now() })
          .then((n: number) => {
            if (n > 0) {
              logger.info({ deviceId, fingerprint }, 'Pinned RouterOS TLS fingerprint (first use)');
            }
          })
          .catch((err: unknown) =>
            logger.warn({ err, deviceId }, 'Could not persist TLS fingerprint'),
          );
      },
      onSessionChange: (deviceId, up, error) => {
        const id = Number(deviceId);
        for (const l of sessionListeners) {
          try {
            l(id, up, error);
          } catch (err) {
            logger.error({ err }, 'RouterOS session listener threw');
          }
        }
      },
    },
    {
      // Conservative on purpose: the CHR is a SPOF and its recovery must not
      // become a self-inflicted denial of service (R5).
      dialBurst: 4,
      dialsPerSecond: 2,
      keepaliveMs: 45_000,
    },
  );

  // Closes the gap both other workstreams reported: until this line runs, every
  // MikroTik driver call fails with NO_TRANSPORT.
  registerRouterOsChannelFactory(routerOsChannelFactoryFromPool(pool));

  logger.info('RouterOS pool created and registered as the MikroTik channel factory');
  return pool;
}

/** Test/shutdown seam. Safe to call when nothing was ever created. */
export async function shutdownRouterOsPool(): Promise<void> {
  const p = pool;
  pool = null;
  sessionListeners.clear();
  if (p) await p.shutdown();
}

// ============================================================================
// devices row -> RouterOsTarget
// ============================================================================

export class NoRouterOsTransportError extends Error {
  readonly deviceId: number;
  constructor(deviceId: number, reason: string) {
    super(`Device ${deviceId} has no usable RouterOS API transport: ${reason}`);
    this.name = 'NoRouterOsTransportError';
    this.deviceId = deviceId;
  }
}

/**
 * Build the dial coordinates for a device's RouterOS API channel.
 *
 * `devices.tunnel_ip` is used ONLY when the transport row carries no explicit
 * host — and even then it is "where to dial today", never an identity (D5).
 * That is why `assertTargetBinding()` exists and why nothing writes to a device
 * on the strength of this function alone.
 */
export async function resolveRouterOsTarget(deviceId: number): Promise<RouterOsTarget> {
  const row = await db('devices as d')
    .leftJoin('device_transports as t', function joinRouterOs(this: any) {
      this.on('t.device_id', '=', 'd.id').andOn('t.transport', '=', db.raw('?', [ROUTEROS]));
    })
    .where('d.id', deviceId)
    .first<
      | {
          id: number;
          name: string;
          role: string;
          status: string;
          tunnel_ip: string | null;
          t_id: number | null;
          host: string | null;
          port: number | null;
          username: string | null;
          secret_enc: string | null;
          use_tls: boolean | null;
          tls_fingerprint_sha256: string | null;
          enabled: boolean | null;
        }
      | undefined
    >(
      'd.id',
      'd.name',
      'd.role',
      'd.status',
      'd.tunnel_ip',
      't.id as t_id',
      't.host',
      't.port',
      't.username',
      't.secret_enc',
      't.use_tls',
      't.tls_fingerprint_sha256',
      't.enabled',
    );

  if (!row) throw new NoRouterOsTransportError(deviceId, 'device does not exist');
  if (row.t_id === null) throw new NoRouterOsTransportError(deviceId, 'no routeros_api row');
  if (row.enabled === false) throw new NoRouterOsTransportError(deviceId, 'transport disabled');
  if (row.status === 'disabled') {
    throw new NoRouterOsTransportError(deviceId, "device status is 'disabled'");
  }

  const host = row.host ?? row.tunnel_ip;
  if (!host) throw new NoRouterOsTransportError(deviceId, 'neither transport host nor tunnel_ip');
  if (!row.username) throw new NoRouterOsTransportError(deviceId, 'no username');
  if (!row.secret_enc) throw new NoRouterOsTransportError(deviceId, 'no credential in the vault');

  return {
    deviceId: String(deviceId),
    host,
    port: row.port ?? undefined,
    tls: row.use_tls === true,
    username: row.username,
    // Plaintext lives from here to the socket and nowhere else.
    password: decrypt(row.secret_enc),
    expectedFingerprint: row.tls_fingerprint_sha256,
    isConcentrator: row.role === 'concentrator',
    label: row.name,
  };
}
