/**
 * ObliWAN — the seam between the MikroTik driver and the RouterOS API pool.
 *
 * `services/transport/routeros/**` (tagged sentences, `.tag=` multiplexing,
 * `/cancel`, streaming `listen`, TLS fingerprint pinning) is owned by another
 * workstream. This module declares the ONLY shape the driver needs from it and
 * lets the composition root plug the real implementation in.
 *
 * Why a registration seam rather than the driver constructing a pool itself:
 * the pool owns ONE socket per device, including the single socket to the CHR
 * that the whole fleet shares (risk R5), and it carries the hooks that persist
 * `device_health`. There must be exactly one instance in the process, created
 * by the composition root. Wiring is two lines in the server bootstrap:
 *
 *     const pool = new RouterOsPool(hooks, options);
 *     registerRouterOsChannelFactory(routerOsChannelFactoryFromPool(pool));
 *
 * Until those lines exist, every RouterOS call fails with an explicit
 * `NO_TRANSPORT` naming the missing wiring — not with a mystery `undefined is
 * not a function`, and never with a silent empty result.
 *
 * The adapter below is the only place in the driver layer that knows the pool's
 * API. `RouterOsChannel` is what the driver actually programs against, so a
 * change in the transport's shape is a change to one function here.
 */

import { rowsOf, type RouterOsPool, type RouterOsTarget } from '../../transport/routeros';
import { DriverError, type ResolvedTransport } from '../types';

/**
 * One RouterOS sentence result. RouterOS returns `!re` records whose fields are
 * all strings — `.id`, `uptime`, `version`, `free-memory`. The driver converts;
 * the transport does not, because a numeric coercion in the transport would
 * silently turn a MAC address or a serial with leading zeros into a number.
 */
export type RouterOsRow = Record<string, string>;

export interface RouterOsQueryOptions {
  /** Per-request budget. The pool must attach `.tag=` and be able to `/cancel`
   *  this specific request when the budget expires, without tearing down the
   *  shared socket. */
  timeoutMs?: number;
  /** `?`-style query words, e.g. `['?disabled=false']`. */
  queries?: string[];
  /** `.proplist` — ask for fewer fields on a big menu. */
  properties?: string[];
}

/**
 * The narrow contract the driver relies on. `!trap` responses must arrive as a
 * rejected promise carrying a `DriverError`, never as an empty row set: a trap
 * that reads as "no rows" is how a permission error becomes "this router has no
 * firewall rules".
 */
export interface RouterOsChannel {
  /** e.g. `query('/system/resource/print')`. */
  query(path: string, options?: RouterOsQueryOptions): Promise<RouterOsRow[]>;
  /** Release the channel back to the pool (or close it). */
  release(): Promise<void>;
}

export type RouterOsChannelFactory = (
  channel: ResolvedTransport,
  opts?: { timeoutMs?: number; deviceId?: number },
) => Promise<RouterOsChannel>;

let factory: RouterOsChannelFactory | null = null;

/** Called once at boot by the composition root. */
export function registerRouterOsChannelFactory(next: RouterOsChannelFactory): void {
  factory = next;
}

/** Test seam / shutdown. */
export function clearRouterOsChannelFactory(): void {
  factory = null;
}

export function isRouterOsChannelAvailable(): boolean {
  return factory !== null;
}

export async function openRouterOsChannel(
  channel: ResolvedTransport,
  opts?: { timeoutMs?: number; deviceId?: number },
): Promise<RouterOsChannel> {
  if (!factory) {
    throw new DriverError(
      'RouterOS API pool is not wired: call registerRouterOsChannelFactory() from the server bootstrap ' +
        'with the factory exported by services/transport/routeros.',
      'NO_TRANSPORT',
      { transport: 'routeros_api', retryable: false },
    );
  }
  return factory(channel, opts);
}

// ============================================================================
// Adapter over the RouterOS pool
// ============================================================================

/**
 * Build the factory from an existing `RouterOsPool`.
 *
 * The POOL ITSELF is not created here on purpose. It owns the single socket per
 * device — including the one socket to the CHR that the whole fleet shares
 * (risk R5) — and it carries the hooks that persist `device_health`. Two pools
 * in one process means two sockets to the concentrator and two breakers
 * disagreeing about the same device. The composition root creates exactly one
 * and hands it here:
 *
 *     const pool = new RouterOsPool(hooks, options);
 *     registerRouterOsChannelFactory(routerOsChannelFactoryFromPool(pool));
 *
 * `release()` is a no-op by design: the pool keeps one persistent authenticated
 * session per device and multiplexes requests over it by `.tag=`. Closing it
 * after each query would re-authenticate on every inventory refresh, which on
 * 300 devices is a login storm rather than a poll.
 */
export function routerOsChannelFactoryFromPool(pool: RouterOsPool): RouterOsChannelFactory {
  return async (channel, opts) => {
    const { username, password } = channel.credentials;
    if (!channel.host) {
      throw new DriverError('RouterOS transport row has no host', 'NO_TRANSPORT', {
        transport: 'routeros_api',
        retryable: false,
      });
    }
    if (!username || !password) {
      throw new DriverError(
        'RouterOS transport row has no username/password in the vault',
        'AUTH_FAILED',
        { transport: 'routeros_api', retryable: false },
      );
    }

    const target: RouterOsTarget = {
      deviceId: String(opts?.deviceId ?? channel.host),
      host: channel.host,
      port: channel.port ?? undefined,
      tls: channel.useTls,
      username,
      password,
      expectedFingerprint: channel.tlsFingerprintSha256,
    };

    return {
      async query(path, options) {
        const words = [
          path,
          ...(options?.properties?.length ? [`=.proplist=${options.properties.join(',')}`] : []),
          ...(options?.queries ?? []),
        ];
        try {
          const sentences = await pool.withConnection(target, (conn) =>
            conn.talk(words, { timeoutMs: options?.timeoutMs ?? opts?.timeoutMs }),
          );
          return rowsOf(sentences);
        } catch (err) {
          throw translateRouterOsError(err, path);
        }
      },
      async release() {
        // Intentionally empty: the pool owns the session lifecycle.
      },
    };
  };
}

/**
 * Map the RouterOS transport's error vocabulary onto the driver taxonomy the
 * arbiter's breaker reads.
 *
 * The distinction that matters: a `!trap` is the ROUTER answering — a bad
 * command, a missing menu, a permission refusal. It is not a broken transport,
 * and counting it as one would blacklist a healthy device because a collector
 * asked for a menu that does not exist on that firmware (R11).
 */
function translateRouterOsError(err: unknown, path: string): DriverError {
  if (err instanceof DriverError) return err;
  const error = err instanceof Error ? err : new Error(String(err));
  const kind = (error as { kind?: string }).kind;

  const code =
    kind === 'trap'
      ? /not enough permissions|no permission/i.test(error.message)
        ? 'PERMISSION_DENIED'
        : 'PROTOCOL_ERROR'
      : kind === 'auth'
        ? 'AUTH_FAILED'
        : kind === 'fingerprint'
          ? 'TLS_PINNING_FAILED'
          : kind === 'timeout'
            ? 'TIMEOUT'
            : kind === 'circuit_open'
              ? 'CIRCUIT_OPEN'
              : 'UNREACHABLE';

  return new DriverError(`RouterOS ${path}: ${error.message}`, code, {
    transport: 'routeros_api',
    cause: error,
  });
}

/** Open, use, release — the release in a `finally`. A leaked RouterOS channel
 *  holds a tag slot on the single socket the fleet shares with the CHR (R5). */
export async function withRouterOsChannel<T>(
  channel: ResolvedTransport,
  fn: (ros: RouterOsChannel) => Promise<T>,
  opts?: { timeoutMs?: number; deviceId?: number },
): Promise<T> {
  const ros = await openRouterOsChannel(channel, opts);
  try {
    return await fn(ros);
  } finally {
    await ros.release().catch(() => undefined);
  }
}
