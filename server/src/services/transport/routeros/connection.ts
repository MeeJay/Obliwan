/**
 * ObliWAN — a single multiplexed RouterOS API session.
 *
 * One instance == one TCP/TLS socket == one authenticated RouterOS session.
 * Everything the fleet does to a MikroTik goes through here.
 *
 * What this connection does that the inherited Obliguard client did not:
 *
 *  1. `.tag=` on EVERY command. Replies are routed back to the promise that
 *     asked for them, so N commands share one socket. Without this the pool
 *     is decorative: one request would mean one connection.
 *  2. Streaming. `/ppp/active/listen` never completes; it pushes `!re` for
 *     every PPP event. `stream()` hands each row to a callback (or an async
 *     iterator) instead of awaiting an array that never arrives.
 *  3. `/cancel`. A `listen` left running is a leaked command on the router.
 *     Cancelling by tag is the only clean way out.
 *  4. Per-request timeouts. A slow `/export` must not poison an unrelated
 *     `/system/identity/print` on the same socket. On expiry the promise
 *     rejects AND the tag is cancelled on the router.
 *  5. `!trap` -> `RouterOsTrapError`. Failures are never swallowed.
 *     `!fatal` closes the session and rejects everything in flight.
 *  6. TLS fingerprint pinning on 8729 (risk R9: the L2TP carrier is often
 *     unencrypted, so the certificate pin is the only real protection).
 */

import net from 'net';
import tls from 'tls';
import crypto from 'crypto';
import { EventEmitter } from 'events';
import { logger } from '../../../utils/logger';
import {
  Sentence,
  SentenceReader,
  commandOf,
  encodeSentence,
  parseSentence,
  redactWords,
  RouterOsFatalError,
  RouterOsProtocolError,
  RouterOsTrapError,
} from './protocol';

export const ROUTEROS_PLAIN_PORT = 8728;
export const ROUTEROS_TLS_PORT = 8729;

// ============================================================================
// Errors
// ============================================================================

/** A request exceeded its own budget. The tag has been `/cancel`-ed. */
export class RouterOsTimeoutError extends Error {
  readonly kind = 'timeout';
  readonly command: string;
  readonly timeoutMs: number;
  constructor(command: string, timeoutMs: number) {
    super(`RouterOS command ${command} timed out after ${timeoutMs} ms`);
    this.name = 'RouterOsTimeoutError';
    this.command = command;
    this.timeoutMs = timeoutMs;
  }
}

/** The socket went away (peer reset, tunnel down, /fatal, deliberate close). */
export class RouterOsConnectionClosedError extends Error {
  readonly kind = 'closed';
  constructor(reason: string) {
    super(`RouterOS connection closed: ${reason}`);
    this.name = 'RouterOsConnectionClosedError';
  }
}

/** Credentials rejected. Distinct from a transport failure on purpose: the
 *  pool must NOT retry this in a tight loop, it will lock the account out. */
export class RouterOsAuthError extends Error {
  readonly kind = 'auth';
  constructor(message: string) {
    super(`RouterOS login failed: ${message}`);
    this.name = 'RouterOsAuthError';
  }
}

/**
 * The certificate presented on 8729 is not the pinned one. This is a hard
 * stop: on a tunnel that may not carry IPsec, a changed fingerprint is
 * indistinguishable from an interception.
 */
export class RouterOsFingerprintError extends Error {
  readonly kind = 'fingerprint';
  readonly expected: string;
  readonly actual: string;
  constructor(host: string, expected: string, actual: string) {
    super(
      `TLS fingerprint mismatch for ${host}: pinned ${expected}, presented ${actual}. ` +
        'Refusing the session. Clear the pin explicitly if the device certificate was legitimately replaced.',
    );
    this.name = 'RouterOsFingerprintError';
    this.expected = expected;
    this.actual = actual;
  }
}

// ============================================================================
// Options
// ============================================================================

export interface RouterOsConnectionOptions {
  host: string;
  /** Defaults to 8729 when `tls`, 8728 otherwise. */
  port?: number;
  tls?: boolean;
  username: string;
  /** Plaintext, straight from the vault. Never logged, never persisted here. */
  password: string;
  /**
   * Pinned peer-certificate SHA-256 (hex, colons optional, case-insensitive).
   * `null`/absent means trust-on-first-use: the fingerprint observed on the
   * first successful handshake is reported through `onFingerprint` so the
   * caller can persist it in `device_transports.tls_fingerprint_sha256`.
   */
  expectedFingerprint?: string | null;
  onFingerprint?: (fingerprintSha256: string) => void;
  /** Bind the outgoing socket (maps to `device_transports` source hints). */
  sourceAddress?: string;
  connectTimeoutMs?: number;
  loginTimeoutMs?: number;
  /** Default per-request budget; overridable per call. */
  requestTimeoutMs?: number;
  /** RouterOS < 6.43 MD5 challenge fallback. Cheap, so on by default. */
  allowLegacyLogin?: boolean;
  /** Free-form identity used in logs only (device id / hostname). */
  label?: string;
}

interface ResolvedOptions extends Required<Omit<RouterOsConnectionOptions,
  'expectedFingerprint' | 'onFingerprint' | 'sourceAddress' | 'label'>> {
  expectedFingerprint: string | null;
  onFingerprint?: (fingerprintSha256: string) => void;
  sourceAddress?: string;
  label: string;
}

const DEFAULTS = {
  connectTimeoutMs: 10_000,
  loginTimeoutMs: 10_000,
  requestTimeoutMs: 20_000,
  allowLegacyLogin: true,
};

function normaliseFingerprint(fp: string): string {
  return fp.replace(/[:\s]/g, '').toLowerCase();
}

// ============================================================================
// Pending request bookkeeping
// ============================================================================

type PendingMode = 'call' | 'stream';

interface Pending {
  tag: string;
  command: string;
  mode: PendingMode;
  rows: Sentence[];
  onRow?: (row: Sentence) => void;
  resolve: (rows: Sentence[]) => void;
  reject: (err: Error) => void;
  settled: boolean;
  /** A `/cancel` was issued: the incoming `!trap interrupted` is expected. */
  cancelling: boolean;
  timer?: NodeJS.Timeout;
  /** Reaper for a tag the router never terminated after we gave up on it. */
  reaper?: NodeJS.Timeout;
}

export interface TalkOptions {
  /** Per-request budget in ms. Falls back to the connection default. */
  timeoutMs?: number;
  /** Called for each `!re` as it arrives, even in `talk()` mode. */
  onRow?: (row: Sentence) => void;
}

export interface StreamOptions {
  /** Invoked for every `!re` pushed by the router. */
  onRow: (row: Sentence) => void;
  /** Invoked once if the router terminates the stream by itself. */
  onDone?: () => void;
  /** Invoked on `!trap` / `!fatal` / socket death. */
  onError?: (err: Error) => void;
}

/** Handle on a running `listen`. Always `cancel()` it, or the tag leaks. */
export interface RouterOsStream {
  readonly tag: string;
  /** Sends `/cancel` for this tag and resolves once the router acknowledges
   *  (or immediately, if the connection is already gone). Idempotent. */
  cancel(): Promise<void>;
  /** Resolves when the stream is over, whatever the reason. Never rejects. */
  readonly closed: Promise<void>;
  readonly isClosed: boolean;
}

// ============================================================================
// Connection
// ============================================================================

export type ConnectionState = 'new' | 'connecting' | 'authenticating' | 'ready' | 'closed';

export declare interface RouterOsConnection {
  on(event: 'close', listener: (err?: Error) => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

export class RouterOsConnection extends EventEmitter {
  private readonly opts: ResolvedOptions;
  private socket: net.Socket | tls.TLSSocket | null = null;
  private readonly reader = new SentenceReader();
  private readonly pending = new Map<string, Pending>();
  private tagCounter = 0;
  private _state: ConnectionState = 'new';
  private closeReason: Error | null = null;
  private _fingerprint: string | null = null;
  private _lastActivityAt = Date.now();

  constructor(options: RouterOsConnectionOptions) {
    super();
    const useTls = options.tls ?? false;
    this.opts = {
      host: options.host,
      port: options.port ?? (useTls ? ROUTEROS_TLS_PORT : ROUTEROS_PLAIN_PORT),
      tls: useTls,
      username: options.username,
      password: options.password,
      expectedFingerprint: options.expectedFingerprint
        ? normaliseFingerprint(options.expectedFingerprint)
        : null,
      onFingerprint: options.onFingerprint,
      sourceAddress: options.sourceAddress,
      connectTimeoutMs: options.connectTimeoutMs ?? DEFAULTS.connectTimeoutMs,
      loginTimeoutMs: options.loginTimeoutMs ?? DEFAULTS.loginTimeoutMs,
      requestTimeoutMs: options.requestTimeoutMs ?? DEFAULTS.requestTimeoutMs,
      allowLegacyLogin: options.allowLegacyLogin ?? DEFAULTS.allowLegacyLogin,
      label: options.label ?? `${options.host}:${options.port ?? (useTls ? ROUTEROS_TLS_PORT : ROUTEROS_PLAIN_PORT)}`,
    };
  }

  get state(): ConnectionState {
    return this._state;
  }

  get isReady(): boolean {
    return this._state === 'ready';
  }

  /** Peer certificate SHA-256 observed on this session (TLS only). */
  get fingerprint(): string | null {
    return this._fingerprint;
  }

  /** Epoch ms of the last byte received. Used by the pool's idle reaper. */
  get lastActivityAt(): number {
    return this._lastActivityAt;
  }

  /** Number of commands currently awaiting a `!done` (streams included). */
  get inFlight(): number {
    return this.pending.size;
  }

  get target(): string {
    return `${this.opts.host}:${this.opts.port}`;
  }

  // -- lifecycle ------------------------------------------------------------

  /** Open the socket and authenticate. Resolves only once the session is
   *  usable; rejects with a typed error otherwise. */
  async connect(): Promise<void> {
    if (this._state !== 'new') {
      throw new Error(`connect() called on a ${this._state} RouterOS connection`);
    }
    this._state = 'connecting';
    await this.openSocket();
    this._state = 'authenticating';
    try {
      await this.login();
    } catch (err) {
      this.destroy(err instanceof Error ? err : new Error(String(err)));
      throw err;
    }
    this._state = 'ready';
    logger.debug(
      { target: this.target, tls: this.opts.tls, label: this.opts.label },
      'RouterOS session ready',
    );
  }

  private openSocket(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const finish = (err?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) {
          this.destroy(err);
          reject(err);
        } else {
          resolve();
        }
      };

      const timer = setTimeout(() => {
        finish(new Error(`Connection to ${this.target} timed out after ${this.opts.connectTimeoutMs} ms`));
      }, this.opts.connectTimeoutMs);
      timer.unref?.();

      if (this.opts.tls) {
        // RouterOS ships a self-signed certificate; chain validation is
        // meaningless here — the PIN is the trust anchor.
        // `tls.connect()` has no `localAddress`, so when the transport pins a
        // source address we build the TCP socket ourselves and wrap it.
        let raw: net.Socket | undefined;
        if (this.opts.sourceAddress) {
          raw = net.createConnection({
            host: this.opts.host,
            port: this.opts.port,
            localAddress: this.opts.sourceAddress,
          });
          raw.once('error', (err) => finish(err));
        }
        const socket = raw
          ? tls.connect({ socket: raw, rejectUnauthorized: false })
          : tls.connect({ host: this.opts.host, port: this.opts.port, rejectUnauthorized: false });
        this.socket = socket;
        socket.once('secureConnect', () => {
          try {
            this.verifyFingerprint(socket);
          } catch (err) {
            finish(err as Error);
            return;
          }
          this.attachSocketHandlers();
          finish();
        });
        socket.once('error', (err) => finish(err));
      } else {
        logger.warn(
          { target: this.target, label: this.opts.label },
          'RouterOS API in cleartext on 8728 (risk R9): credentials cross the transit network unprotected. Prefer 8729 with a pinned fingerprint.',
        );
        const socket = net.createConnection({
          host: this.opts.host,
          port: this.opts.port,
          localAddress: this.opts.sourceAddress,
        });
        this.socket = socket;
        socket.once('connect', () => {
          this.attachSocketHandlers();
          finish();
        });
        socket.once('error', (err) => finish(err));
      }
    });
  }

  private verifyFingerprint(socket: tls.TLSSocket): void {
    const cert = socket.getPeerCertificate(false);
    const raw = cert && (cert as { raw?: Buffer }).raw;
    if (!raw || raw.length === 0) {
      throw new RouterOsProtocolError(`${this.target} completed a TLS handshake without presenting a certificate`);
    }
    const fp = crypto.createHash('sha256').update(raw).digest('hex');
    this._fingerprint = fp;

    if (this.opts.expectedFingerprint) {
      if (this.opts.expectedFingerprint !== fp) {
        throw new RouterOsFingerprintError(this.target, this.opts.expectedFingerprint, fp);
      }
      return;
    }

    // Trust on first use. The caller persists it; from the next session on,
    // any change is a hard refusal.
    logger.info(
      { target: this.target, label: this.opts.label, fingerprint: fp },
      'Pinning RouterOS TLS certificate on first successful handshake',
    );
    this.opts.onFingerprint?.(fp);
  }

  private attachSocketHandlers(): void {
    const socket = this.socket;
    if (!socket) return;
    socket.setNoDelay(true);
    socket.on('data', (chunk: Buffer) => this.onData(chunk));
    socket.on('error', (err: Error) => {
      // A post-handshake error is a session death, not a connect failure.
      if (this._state !== 'closed') this.destroy(err);
    });
    socket.on('close', () => {
      if (this._state !== 'closed') {
        this.destroy(new RouterOsConnectionClosedError('peer closed the socket'));
      }
    });
  }

  private onData(chunk: Buffer): void {
    this._lastActivityAt = Date.now();
    let sentences: string[][];
    try {
      sentences = this.reader.push(chunk);
    } catch (err) {
      // Frame desync: nothing on this socket can be trusted any more.
      this.destroy(err instanceof Error ? err : new Error(String(err)));
      return;
    }
    for (const words of sentences) {
      try {
        this.dispatch(parseSentence(words));
      } catch (err) {
        logger.error(
          { target: this.target, err: (err as Error).message },
          'RouterOS sentence dispatch failed',
        );
      }
    }
  }

  private dispatch(sentence: Sentence): void {
    if (sentence.type === '!fatal') {
      const message = sentence.attrs.message || sentence.words.slice(1).join(' ') || 'session terminated by device';
      this.destroy(new RouterOsFatalError(message));
      return;
    }

    const tag = sentence.tag;
    if (tag === undefined) {
      // Untagged, non-fatal. Should not happen since we tag everything; keep
      // it visible rather than silently dropping router output.
      logger.warn(
        { target: this.target, type: sentence.type, words: redactWords(sentence.words) },
        'Untagged RouterOS sentence ignored',
      );
      return;
    }

    const p = this.pending.get(tag);
    if (!p) {
      // Late reply for a tag we already gave up on (timeout) or cancelled.
      logger.debug({ target: this.target, tag, type: sentence.type }, 'Reply for an unknown RouterOS tag');
      return;
    }

    switch (sentence.type) {
      case '!re':
        if (p.onRow) {
          try {
            p.onRow(sentence);
          } catch (err) {
            logger.error(
              { target: this.target, tag, err: (err as Error).message },
              'RouterOS row handler threw; the stream keeps running',
            );
          }
        }
        if (p.mode === 'call') p.rows.push(sentence);
        break;

      case '!done':
        if (p.mode === 'call') p.rows.push(sentence);
        this.settle(p, null);
        break;

      case '!trap': {
        const message = sentence.attrs.message || 'command failed';
        if (p.cancelling) {
          // `/cancel` makes the router trap the victim tag with "interrupted".
          // That is the acknowledgement, not a failure.
          logger.debug({ target: this.target, tag, message }, 'RouterOS tag cancelled');
          break;
        }
        this.settle(p, new RouterOsTrapError(message, p.command, sentence.attrs));
        break;
      }

      default:
        logger.warn(
          { target: this.target, tag, words: redactWords(sentence.words) },
          'Unknown RouterOS sentence type',
        );
    }
  }

  private settle(p: Pending, err: Error | null): void {
    this.pending.delete(p.tag);
    if (p.timer) clearTimeout(p.timer);
    if (p.reaper) clearTimeout(p.reaper);
    if (p.settled) return; // already rejected by a timeout; just absorbed the tail
    p.settled = true;
    if (err) p.reject(err);
    else p.resolve(p.rows);
  }

  /** Tear the session down and fail everything in flight. Idempotent. */
  destroy(reason?: Error): void {
    if (this._state === 'closed') return;
    this._state = 'closed';
    const err: Error = reason ?? new RouterOsConnectionClosedError('closed locally');
    this.closeReason = err;

    for (const p of Array.from(this.pending.values())) {
      this.pending.delete(p.tag);
      if (p.timer) clearTimeout(p.timer);
      if (p.reaper) clearTimeout(p.reaper);
      if (!p.settled) {
        p.settled = true;
        p.reject(err);
      }
    }

    this.reader.reset();
    const socket = this.socket;
    this.socket = null;
    if (socket) {
      socket.removeAllListeners('data');
      socket.removeAllListeners('close');
      socket.removeAllListeners('error');
      socket.on('error', () => undefined); // swallow the post-destroy ECONNRESET
      socket.destroy();
    }

    // `emit('error')` on an EventEmitter with no listener THROWS. A session
    // dying must never blow up the caller that merely subscribed to 'close'.
    if (reason && this.listenerCount('error') > 0) this.emit('error', reason);
    this.emit('close', reason);
  }

  /** Polite shutdown: best-effort `/quit`, then destroy. */
  close(): void {
    if (this._state === 'ready' && this.socket) {
      try {
        this.socket.write(encodeSentence(['/quit']));
      } catch {
        /* the socket is going away anyway */
      }
    }
    this.destroy();
  }

  // -- authentication -------------------------------------------------------

  private async login(): Promise<void> {
    const timeoutMs = this.opts.loginTimeoutMs;
    let reply: Sentence[];
    try {
      reply = await this.talk(
        ['/login', `=name=${this.opts.username}`, `=password=${this.opts.password}`],
        { timeoutMs },
      );
    } catch (err) {
      if (err instanceof RouterOsTrapError) throw new RouterOsAuthError(err.message);
      throw err;
    }

    // RouterOS >= 6.43 answers `!done` with nothing. RouterOS < 6.43 ignores
    // the credentials and answers `!done =ret=<hex challenge>`, which is the
    // legacy MD5 handshake asking for a second round-trip.
    const done = reply.find((s) => s.type === '!done');
    const challenge = done?.attrs.ret;
    if (!challenge) return;

    if (!this.opts.allowLegacyLogin) {
      throw new RouterOsAuthError(
        'device requires the pre-6.43 MD5 challenge login, which is disabled for this transport',
      );
    }
    await this.loginLegacy(challenge, timeoutMs);
  }

  private async loginLegacy(challengeHex: string, timeoutMs: number): Promise<void> {
    // md5(0x00 || password || challenge), prefixed with "00".
    const md5 = crypto.createHash('md5');
    md5.update(Buffer.from([0]));
    md5.update(Buffer.from(this.opts.password, 'utf8'));
    md5.update(Buffer.from(challengeHex, 'hex'));
    const response = `00${md5.digest('hex')}`;

    try {
      await this.talk(
        ['/login', `=name=${this.opts.username}`, `=response=${response}`],
        { timeoutMs },
      );
    } catch (err) {
      if (err instanceof RouterOsTrapError) throw new RouterOsAuthError(err.message);
      throw err;
    }
    logger.debug({ target: this.target }, 'Authenticated with the legacy RouterOS MD5 challenge');
  }

  // -- requests -------------------------------------------------------------

  private nextTag(): string {
    this.tagCounter = (this.tagCounter + 1) % 0x7fffffff;
    return String(this.tagCounter);
  }

  private write(words: string[]): void {
    const socket = this.socket;
    if (!socket || this._state === 'closed') {
      throw this.closeReason ?? new RouterOsConnectionClosedError('not connected');
    }
    socket.write(encodeSentence(words));
  }

  /**
   * Run one command and collect its reply.
   *
   * Resolves with every sentence received for the tag (`!re` rows, then the
   * closing `!done`). Rejects with `RouterOsTrapError` on `!trap`,
   * `RouterOsTimeoutError` on expiry (after `/cancel`), or
   * `RouterOsConnectionClosedError` / `RouterOsFatalError` on session death.
   */
  talk(words: string[], options: TalkOptions = {}): Promise<Sentence[]> {
    if (this._state === 'closed') {
      return Promise.reject(this.closeReason ?? new RouterOsConnectionClosedError('not connected'));
    }
    if (this._state === 'new' || this._state === 'connecting') {
      return Promise.reject(new RouterOsConnectionClosedError('session not established yet'));
    }

    const tag = this.nextTag();
    const command = commandOf(words);
    const timeoutMs = options.timeoutMs ?? this.opts.requestTimeoutMs;

    return new Promise<Sentence[]>((resolve, reject) => {
      const p: Pending = {
        tag,
        command,
        mode: 'call',
        rows: [],
        onRow: options.onRow,
        resolve,
        reject,
        settled: false,
        cancelling: false,
      };
      this.pending.set(tag, p);

      if (timeoutMs > 0) {
        p.timer = setTimeout(() => this.expire(p, timeoutMs), timeoutMs);
        p.timer.unref?.();
      }

      try {
        this.write([...words, `.tag=${tag}`]);
      } catch (err) {
        this.pending.delete(tag);
        if (p.timer) clearTimeout(p.timer);
        reject(err as Error);
        return;
      }
      logger.trace?.(
        { target: this.target, tag, words: redactWords(words) },
        'RouterOS command sent',
      );
    });
  }

  /** Timeout path: reject the caller now, cancel the tag on the router, and
   *  keep absorbing the tail so a late `!done` is not logged as an orphan. */
  private expire(p: Pending, timeoutMs: number): void {
    if (p.settled) return;
    p.settled = true;
    p.cancelling = true;
    p.reject(new RouterOsTimeoutError(p.command, timeoutMs));
    this.sendCancel(p.tag);
    p.reaper = setTimeout(() => {
      this.pending.delete(p.tag);
    }, 5_000);
    p.reaper.unref?.();
  }

  /** Fire-and-forget `/cancel` for a tag. Errors are logged, never thrown:
   *  the caller has already been told what happened. */
  private sendCancel(tag: string): void {
    if (this._state !== 'ready') return;
    const cancelTag = this.nextTag();
    const p: Pending = {
      tag: cancelTag,
      command: '/cancel',
      mode: 'call',
      rows: [],
      resolve: () => undefined,
      reject: () => undefined,
      settled: false,
      cancelling: false,
    };
    this.pending.set(cancelTag, p);
    p.timer = setTimeout(() => {
      this.pending.delete(cancelTag);
    }, 5_000);
    p.timer.unref?.();
    try {
      this.write(['/cancel', `=tag=${tag}`, `.tag=${cancelTag}`]);
    } catch (err) {
      this.pending.delete(cancelTag);
      clearTimeout(p.timer);
      logger.debug({ target: this.target, tag, err: (err as Error).message }, 'Could not send /cancel');
    }
  }

  /** `talk()` reduced to the `!re` rows as plain attribute maps. */
  async query(words: string[], options: TalkOptions = {}): Promise<Record<string, string>[]> {
    const sentences = await this.talk(words, options);
    return sentences.filter((s) => s.type === '!re').map((s) => s.attrs);
  }

  /** First `!re` row, or `null`. Handy for `/system/resource/print`. */
  async queryFirst(words: string[], options: TalkOptions = {}): Promise<Record<string, string> | null> {
    const rows = await this.query(words, options);
    return rows[0] ?? null;
  }

  /**
   * Start a never-ending command (`/ppp/active/listen`, `/log/listen`).
   *
   * The returned handle MUST be cancelled when the subscriber goes away:
   * an abandoned `listen` stays registered on the router forever.
   */
  stream(words: string[], options: StreamOptions): RouterOsStream {
    const tag = this.nextTag();
    const command = commandOf(words);

    let closeResolve!: () => void;
    const closed = new Promise<void>((res) => {
      closeResolve = res;
    });
    let isClosed = false;
    const finish = (err: Error | null) => {
      if (isClosed) return;
      isClosed = true;
      if (err) options.onError?.(err);
      else options.onDone?.();
      closeResolve();
    };

    const p: Pending = {
      tag,
      command,
      mode: 'stream',
      rows: [],
      onRow: options.onRow,
      resolve: () => finish(null),
      reject: (err) => finish(err),
      settled: false,
      cancelling: false,
    };

    let cancelPromise: Promise<void> | null = null;
    const handle: RouterOsStream = {
      tag,
      get isClosed() {
        return isClosed;
      },
      closed,
      cancel: () => {
        if (cancelPromise) return cancelPromise;
        const live = this.pending.get(tag);
        if (live) {
          live.cancelling = true;
          this.sendCancel(tag);
          // The router answers `!trap interrupted` (swallowed above) then
          // `!done`, which settles the pending and resolves `closed`.
          cancelPromise = Promise.race([
            closed,
            new Promise<void>((res) => {
              const t = setTimeout(() => {
                // The router never acknowledged; stop waiting but drop the tag
                // so nothing leaks on our side.
                this.pending.delete(tag);
                finish(null);
                res();
              }, 5_000);
              t.unref?.();
            }),
          ]);
        } else {
          finish(null);
          cancelPromise = Promise.resolve();
        }
        return cancelPromise;
      },
    };

    if (this._state !== 'ready') {
      finish(this.closeReason ?? new RouterOsConnectionClosedError('session not established yet'));
      return handle;
    }

    this.pending.set(tag, p);
    try {
      this.write([...words, `.tag=${tag}`]);
    } catch (err) {
      this.pending.delete(tag);
      finish(err as Error);
    }
    return handle;
  }

  /**
   * Same as `stream()`, as an async iterator. Rows are buffered between
   * `next()` calls; `bufferLimit` bounds that queue so a slow consumer on a
   * chatty CHR cannot grow the heap without bound (oldest rows are dropped).
   */
  async *streamIterator(
    words: string[],
    opts: { bufferLimit?: number } = {},
  ): AsyncGenerator<Sentence, void, void> {
    const limit = opts.bufferLimit ?? 1000;
    const queue: Sentence[] = [];
    let wake: (() => void) | null = null;
    // Held in an object: values mutated only from callbacks defeat TypeScript's
    // control-flow narrowing when read back in the loop below.
    const box: { error: Error | null; done: boolean; dropped: number } = {
      error: null,
      done: false,
      dropped: 0,
    };

    const notify = () => {
      const w = wake;
      wake = null;
      w?.();
    };

    const handle = this.stream(words, {
      onRow: (row) => {
        if (queue.length >= limit) {
          queue.shift();
          box.dropped++;
        }
        queue.push(row);
        notify();
      },
      onDone: () => {
        box.done = true;
        notify();
      },
      onError: (err) => {
        box.error = err;
        box.done = true;
        notify();
      },
    });

    try {
      for (;;) {
        while (queue.length > 0) {
          yield queue.shift() as Sentence;
        }
        if (box.done) break;
        await new Promise<void>((res) => {
          wake = res;
        });
      }
      if (box.error) throw box.error;
    } finally {
      if (box.dropped > 0) {
        logger.warn(
          { target: this.target, tag: handle.tag, dropped: box.dropped },
          'RouterOS stream consumer fell behind; oldest rows were dropped',
        );
      }
      await handle.cancel();
    }
  }

  /** Cheap liveness probe used by the pool's keepalive. */
  async ping(timeoutMs = 5_000): Promise<void> {
    await this.talk(['/system/identity/print'], { timeoutMs });
  }
}

/** Open + authenticate in one call. */
export async function createRouterOsConnection(
  options: RouterOsConnectionOptions,
): Promise<RouterOsConnection> {
  const conn = new RouterOsConnection(options);
  await conn.connect();
  return conn;
}
