/**
 * ObliWAN — REST transport, on `undici`.
 *
 * Serves the two HTTP-shaped brands, which have opposite failure models:
 *
 *  - SonicOS (on-box, per-device): the appliance allows a very small number of
 *    concurrent admin sessions and LEAKS them on timeout. Every unit of work
 *    logs in, does its thing, and logs out in a `finally`. Skipping the logout
 *    makes the firewall unmanageable — including for the customer's own
 *    administrator — within a day. `override: true` on login steals the config
 *    lock from a forgotten browser tab; without it one stale web session blocks
 *    ObliWAN indefinitely.
 *
 *  - Nebula (cloud, per-organization): the quota is shared by every device in
 *    the org AND by the customer's own integrations. 429 is normal operation,
 *    not an incident. The token bucket is therefore keyed on the org, never on
 *    the device, and `Retry-After` is honoured rather than fought.
 *
 * TLS (risk R9): `tlsFingerprintSha256` pins the certificate. On-box appliance
 * certificates are self-signed, so the realistic choice is between "trust
 * anything" and "trust exactly this certificate". We pin. A mismatch is a hard
 * failure (`TLS_PINNING_FAILED`), never a warning — a changed fingerprint on a
 * management channel is either a firmware upgrade the operator must confirm or
 * someone in the middle of the transit network.
 *
 * Section 8.2: no header, no body and no URL query is ever logged from here.
 * The `Authorization` header and the session cookie are the credentials.
 */

import { Agent, request } from 'undici';
import type { Dispatcher } from 'undici';
import type { PeerCertificate } from 'tls';
import { DriverError, asDriverError, redact } from '../drivers/types';

// ============================================================================
// Target
// ============================================================================

export interface RestTlsOptions {
  /** `false` only makes sense with a pin; see `assertTlsConfig`. */
  rejectUnauthorized?: boolean;
  /** Lowercase hex, no separators. Compared against the peer's SHA-256. */
  fingerprintSha256?: string | null;
}

export interface RestTarget {
  /** Scheme + host + optional port + optional base path. */
  baseUrl: string;
  timeoutMs?: number;
  /** Attempts AFTER the first one. 0 = never retry. */
  retries?: number;
  headers?: Record<string, string>;
  tls?: RestTlsOptions;
  /** Literals scrubbed from every error message this client produces. */
  secrets?: ReadonlyArray<string | null | undefined>;
}

export interface RestRequestOptions {
  body?: unknown;
  headers?: Record<string, string>;
  timeoutMs?: number;
  retries?: number;
  /**
   * Whether replaying the request is safe. GET/HEAD are assumed safe; anything
   * else must say so explicitly. Retrying a non-idempotent POST against a
   * firewall is how one commit becomes two.
   */
  idempotent?: boolean;
  /** `json` parses, `text` returns the body verbatim, `buffer` for backups. */
  expect?: 'json' | 'text' | 'buffer' | 'none';
}

export interface RestResponse<T = unknown> {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: T;
  durationMs: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RETRIES = 2;
const MAX_BACKOFF_MS = 20_000;

// ============================================================================
// TLS pinning
// ============================================================================

function normaliseFingerprint(fp: string): string {
  return fp.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
}

/**
 * Refuse a configuration that disables verification without pinning anything.
 * That combination is not "lenient", it is "unauthenticated": the credentials
 * of an entire fleet would be offered to whatever answers on port 443.
 */
export function assertTlsConfig(tls: RestTlsOptions | undefined, host: string): void {
  if (!tls) return;
  if (tls.rejectUnauthorized === false && !tls.fingerprintSha256) {
    throw new DriverError(
      `REST ${host}: TLS verification is disabled and no certificate fingerprint is pinned. ` +
        `Pin device_transports.tls_fingerprint_sha256 or leave verification on.`,
      'TLS_PINNING_FAILED',
      { transport: 'rest', retryable: false },
    );
  }
}

// ============================================================================
// Client
// ============================================================================

export class RestTransport {
  private readonly agent: Agent;
  private readonly base: URL;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly secrets: string[];
  private closed = false;

  /**
   * Set on the first successful handshake when nothing was pinned yet. The
   * caller persists it into `device_transports.tls_fingerprint_sha256` — this
   * class never touches the database.
   */
  public observedFingerprintSha256: string | null = null;

  constructor(private readonly target: RestTarget) {
    this.base = new URL(target.baseUrl);
    this.timeoutMs = target.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.retries = target.retries ?? DEFAULT_RETRIES;
    this.secrets = (target.secrets ?? []).filter(
      (s): s is string => typeof s === 'string' && s.length > 0,
    );
    assertTlsConfig(target.tls, this.base.host);

    const pin = target.tls?.fingerprintSha256
      ? normaliseFingerprint(target.tls.fingerprintSha256)
      : null;

    this.agent = new Agent({
      headersTimeout: this.timeoutMs,
      bodyTimeout: this.timeoutMs,
      connections: 4,
      connect: {
        timeout: this.timeoutMs,
        rejectUnauthorized: target.tls?.rejectUnauthorized ?? true,
        checkServerIdentity: (host: string, cert: PeerCertificate): Error | undefined => {
          const seen = normaliseFingerprint(cert.fingerprint256 ?? '');
          this.observedFingerprintSha256 = seen || null;
          if (!pin) return undefined;
          if (seen === pin) return undefined;
          return new Error(
            `certificate fingerprint mismatch for ${host}: pinned ${pin}, presented ${seen || '(none)'}`,
          );
        },
      },
    });
  }

  private clean(text: string): string {
    return redact(text, this.secrets);
  }

  get dispatcher(): Dispatcher {
    return this.agent;
  }

  private url(path: string): string {
    // `new URL(path, base)` would drop the base path on a leading slash; the
    // SonicOS and Nebula base URLs both carry one.
    const basePath = this.base.pathname.replace(/\/+$/, '');
    const suffix = path.startsWith('/') ? path : `/${path}`;
    return `${this.base.origin}${basePath}${suffix}`;
  }

  async request<T = unknown>(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD',
    path: string,
    opts: RestRequestOptions = {},
  ): Promise<RestResponse<T>> {
    if (this.closed) {
      throw new DriverError('REST client is closed', 'PROTOCOL_ERROR', { transport: 'rest' });
    }
    const idempotent = opts.idempotent ?? (method === 'GET' || method === 'HEAD');
    const maxAttempts = 1 + (idempotent ? (opts.retries ?? this.retries) : 0);
    const budget = opts.timeoutMs ?? this.timeoutMs;
    const url = this.url(path);

    let lastError: DriverError | null = null;

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const startedAt = Date.now();
      try {
        const res = await request(url, {
          dispatcher: this.agent,
          method,
          headers: {
            Accept: 'application/json',
            ...this.target.headers,
            ...opts.headers,
            ...(opts.body !== undefined && !(opts.headers?.['Content-Type'] ?? opts.headers?.['content-type'])
              ? { 'Content-Type': 'application/json' }
              : {}),
          },
          body: encodeBody(opts.body),
          headersTimeout: budget,
          bodyTimeout: budget,
          signal: AbortSignal.timeout(budget),
        });

        // 429 and 5xx are retried; everything else is handed to the caller,
        // which decides whether a 404 is an error for that endpoint.
        if (res.statusCode === 429 || (res.statusCode >= 500 && res.statusCode <= 599)) {
          const detail = await res.body.text().catch(() => '');
          lastError = httpError(res.statusCode, this.clean(detail), path);
          if (attempt + 1 < maxAttempts) {
            await sleep(retryDelayMs(attempt, res.headers['retry-after']));
            continue;
          }
          throw lastError;
        }

        const body = await readBody<T>(res, opts.expect ?? 'json');
        return {
          statusCode: res.statusCode,
          headers: res.headers as Record<string, string | string[] | undefined>,
          body,
          durationMs: Date.now() - startedAt,
        };
      } catch (err) {
        if (err instanceof DriverError && err.code !== 'UNREACHABLE' && err.code !== 'TIMEOUT') {
          throw err;
        }
        const wrapped = this.wrapNetworkError(err, url);
        lastError = wrapped;
        if (attempt + 1 < maxAttempts && wrapped.retryable) {
          await sleep(retryDelayMs(attempt, undefined));
          continue;
        }
        throw wrapped;
      }
    }

    throw lastError ?? new DriverError(`REST ${path} failed`, 'UNKNOWN', { transport: 'rest' });
  }

  private wrapNetworkError(err: unknown, url: string): DriverError {
    if (err instanceof DriverError) return err;
    const message = err instanceof Error ? err.message : String(err);
    const code = (err as { code?: string }).code ?? '';
    const host = safeHost(url);

    if (/fingerprint mismatch/i.test(message) || code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
      return new DriverError(this.clean(`REST ${host}: ${message}`), 'TLS_PINNING_FAILED', {
        transport: 'rest',
        retryable: false,
        cause: err,
      });
    }
    if (/self.signed|unable to verify|CERT_|SSL/i.test(message) || code.startsWith('ERR_TLS')) {
      return new DriverError(
        this.clean(
          `REST ${host}: TLS handshake refused (${message}). Appliance certificates are self-signed: ` +
            `pin the fingerprint on the transport instead of disabling verification.`,
        ),
        'TLS_PINNING_FAILED',
        { transport: 'rest', retryable: false, cause: err },
      );
    }
    if (message.includes('aborted') || /timeout|TimeoutError/i.test(message) || code === 'UND_ERR_HEADERS_TIMEOUT') {
      return new DriverError(this.clean(`REST ${host}: timed out`), 'TIMEOUT', {
        transport: 'rest',
        cause: err,
      });
    }
    return asDriverError(new Error(this.clean(`REST ${host}: ${message}`)), 'UNREACHABLE', 'rest');
  }

  /** Release the connection pool. Idempotent. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.agent.close().catch(() => undefined);
  }
}

function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return 'unknown-host';
  }
}

function encodeBody(body: unknown): string | Buffer | undefined {
  if (body === undefined || body === null) return undefined;
  if (typeof body === 'string' || Buffer.isBuffer(body)) return body;
  return JSON.stringify(body);
}

async function readBody<T>(
  res: { body: Dispatcher.ResponseData['body'] },
  expect: NonNullable<RestRequestOptions['expect']>,
): Promise<T> {
  switch (expect) {
    case 'none':
      await res.body.dump();
      return undefined as T;
    case 'text':
      return (await res.body.text()) as unknown as T;
    case 'buffer':
      return Buffer.from(await res.body.arrayBuffer()) as unknown as T;
    case 'json':
    default: {
      const text = await res.body.text();
      if (text.trim().length === 0) return undefined as T;
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new DriverError(
          `expected JSON, got ${text.slice(0, 120)}`,
          'PARSE_ERROR',
          { transport: 'rest', retryable: false },
        );
      }
    }
  }
}

export function httpError(statusCode: number, detail: string, path: string): DriverError {
  const code =
    statusCode === 401
      ? 'AUTH_FAILED'
      : statusCode === 403
        ? 'PERMISSION_DENIED'
        : statusCode === 409
          ? 'DEVICE_BUSY'
          : statusCode === 429
            ? 'RATE_LIMITED'
            : statusCode >= 500
              ? 'UNREACHABLE'
              : 'PROTOCOL_ERROR';
  return new DriverError(`${path} -> HTTP ${statusCode}${detail ? `: ${detail.slice(0, 400)}` : ''}`, code, {
    transport: 'rest',
  });
}

/** Exponential backoff with full jitter, `Retry-After` taking precedence. */
export function retryDelayMs(attempt: number, retryAfter: string | string[] | undefined): number {
  const header = Array.isArray(retryAfter) ? retryAfter[0] : retryAfter;
  if (header) {
    const seconds = Number(header);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, MAX_BACKOFF_MS);
    const date = Date.parse(header);
    if (!Number.isNaN(date)) return Math.min(Math.max(date - Date.now(), 0), MAX_BACKOFF_MS);
  }
  const ceiling = Math.min(2 ** attempt * 500, MAX_BACKOFF_MS);
  return Math.floor(ceiling / 2 + Math.random() * (ceiling / 2));
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms).unref?.();
  });
}

// ============================================================================
// SonicOS session
// ============================================================================

export interface SonicOsCredentials {
  username: string;
  password: string;
}

/**
 * A SonicOS admin session. Always used through `withSonicOsSession` so the
 * logout cannot be forgotten.
 */
export class SonicOsSession {
  private cookie: string | null = null;

  constructor(
    private readonly rest: RestTransport,
    private readonly creds: SonicOsCredentials,
  ) {}

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      Accept: 'application/json',
      ...(this.cookie ? { Cookie: this.cookie } : {}),
      ...extra,
    };
  }

  async login(): Promise<void> {
    const basic = Buffer.from(`${this.creds.username}:${this.creds.password}`).toString('base64');
    const res = await this.rest.request<unknown>('POST', '/api/sonicos/auth', {
      headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/json' },
      // Steal the config lock from a stale web-UI login.
      body: { override: true },
      expect: 'none',
      idempotent: false,
    });
    if (res.statusCode === 401 || res.statusCode === 403) {
      throw httpError(res.statusCode, '', 'sonicos/auth');
    }
    if (res.statusCode >= 400) {
      throw httpError(res.statusCode, '', 'sonicos/auth');
    }
    const setCookie = res.headers['set-cookie'];
    this.cookie = Array.isArray(setCookie) ? setCookie.join('; ') : (setCookie ?? null);
  }

  async logout(): Promise<void> {
    if (!this.cookie) return;
    try {
      await this.rest.request('DELETE', '/api/sonicos/auth', {
        headers: this.headers(),
        expect: 'none',
        idempotent: true,
      });
    } finally {
      this.cookie = null;
    }
  }

  async get<T = unknown>(path: string): Promise<T> {
    const res = await this.rest.request<T>('GET', `/api/sonicos${path}`, {
      headers: this.headers(),
    });
    if (res.statusCode >= 400) throw httpError(res.statusCode, '', `sonicos${path}`);
    return res.body;
  }

  async getText(path: string): Promise<string> {
    const res = await this.rest.request<string>('GET', `/api/sonicos${path}`, {
      headers: this.headers({ Accept: 'text/plain' }),
      expect: 'text',
    });
    if (res.statusCode >= 400) throw httpError(res.statusCode, '', `sonicos${path}`);
    return res.body;
  }
}

/**
 * Log in, run the work, log out — the logout in a `finally`, unconditionally.
 * This is the only supported way to talk to a SonicWall.
 */
export async function withSonicOsSession<T>(
  target: RestTarget,
  creds: SonicOsCredentials,
  fn: (session: SonicOsSession, rest: RestTransport) => Promise<T>,
): Promise<T> {
  const rest = new RestTransport({
    ...target,
    secrets: [...(target.secrets ?? []), creds.password],
  });
  const session = new SonicOsSession(rest, creds);
  try {
    await session.login();
    return await fn(session, rest);
  } finally {
    // Both cleanups run even if the first throws: leaking an admin session is
    // worse than losing the original error's stack.
    await session.logout().catch(() => undefined);
    await rest.close().catch(() => undefined);
  }
}

// ============================================================================
// Nebula cloud client
// ============================================================================

const NEBULA_BUCKET_CAPACITY = 10;
const NEBULA_REFILL_PER_SEC = 2;

interface Bucket {
  tokens: number;
  refilledAt: number;
}

/** Keyed on the ORGANIZATION, because that is what Zyxel meters. */
const nebulaBuckets = new Map<string, Bucket>();

export async function takeNebulaToken(orgId: string, now: () => number = Date.now): Promise<void> {
  for (;;) {
    const t = now();
    const bucket = nebulaBuckets.get(orgId) ?? { tokens: NEBULA_BUCKET_CAPACITY, refilledAt: t };
    const elapsedSec = Math.max(0, (t - bucket.refilledAt) / 1000);
    bucket.tokens = Math.min(NEBULA_BUCKET_CAPACITY, bucket.tokens + elapsedSec * NEBULA_REFILL_PER_SEC);
    bucket.refilledAt = t;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      nebulaBuckets.set(orgId, bucket);
      return;
    }
    nebulaBuckets.set(orgId, bucket);
    await sleep(((1 - bucket.tokens) / NEBULA_REFILL_PER_SEC) * 1000);
  }
}

/** Test seam: drops every org bucket. */
export function resetNebulaBuckets(): void {
  nebulaBuckets.clear();
}

export interface NebulaConfig {
  /** Region-specific host. Configured per device, not hardcoded. */
  baseUrl: string;
  apiKey: string;
  orgId?: string | null;
  siteId?: string | null;
  timeoutMs?: number;
}

export class NebulaClient {
  private readonly rest: RestTransport;

  constructor(private readonly cfg: NebulaConfig) {
    if (!cfg.apiKey) {
      throw new DriverError('Nebula API key missing', 'AUTH_FAILED', {
        transport: 'rest',
        retryable: false,
      });
    }
    this.rest = new RestTransport({
      baseUrl: cfg.baseUrl,
      timeoutMs: cfg.timeoutMs,
      headers: { Authorization: `Bearer ${cfg.apiKey}`, Accept: 'application/json' },
      secrets: [cfg.apiKey],
    });
  }

  async get<T = unknown>(path: string): Promise<T> {
    await takeNebulaToken(this.cfg.orgId ?? 'unscoped');
    const res = await this.rest.request<T>('GET', path);
    if (res.statusCode >= 400) throw httpError(res.statusCode, '', path);
    return res.body;
  }

  async close(): Promise<void> {
    await this.rest.close();
  }
}
