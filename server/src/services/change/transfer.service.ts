/**
 * ObliWAN — M6 / K1. Moving a file OFF an equipment, and leaving nothing behind.
 *
 * WHY THIS FILE EXISTS AT ALL
 * A backup that stays on the router is a copy of the customer's configuration
 * sitting on the customer's router, readable by anybody who ever gets a shell
 * on it — including the next owner of a box that gets RMA'd or resold. The
 * backup is only useful on OUR storage, and it is only safe once it is no
 * longer on THEIRS. So the contract of this module is three-part and
 * indivisible:
 *
 *   1. pull the file off,
 *   2. prove what we received is what was there (bytes AND digest),
 *   3. delete it on the device and PROVE it is gone.
 *
 * Step 3 is not best-effort. `removeDeviceFile()` re-reads the file table after
 * the delete and reports `verified: false` if the row is still there; the caller
 * (backup.service) treats that as a failure of the backup, not as a warning.
 *
 * THE TOKEN
 * `/tool/fetch upload=yes` makes the ROUTER dial US. That inverts the trust
 * direction: for the duration of the transfer there is an HTTP listener that
 * accepts a body from whatever can reach it. So the URL carries a single-use,
 * short-lived, 256-bit token, the receiver compares it in constant time, and
 * the token is burned on first use — a replay lands on a 404, not on a second
 * write into the same file. One token authorises exactly one file, of a bounded
 * size, for a bounded time.
 *
 * SFTP is implemented too (`sftpPullFile`) because a large binary backup over
 * HTTP is not always the right idea, and because some sites will not let the
 * router dial back. It is UNTESTED — see the honesty note on the function.
 *
 * §8.2 / R10: nothing here logs a body, a token, or a backup password. The
 * audit line for a fetch carries the src-path and the URL WITHOUT its token,
 * because a token in `command_audit` is a token on the audit screen.
 */

import crypto from 'crypto';
import fs from 'fs';
import fsp from 'fs/promises';
import http from 'http';
import os from 'os';
import path from 'path';
import { RouterOsTrapError, type RouterOsConnection } from '../transport/routeros';
import { logger } from '../../utils/logger';

// ============================================================================
// Errors
// ============================================================================

export type TransferErrorCode =
  | 'TOKEN_INVALID'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_CONSUMED'
  | 'TOO_LARGE'
  | 'TRANSFER_TIMEOUT'
  | 'TRANSFER_FAILED'
  | 'DIGEST_MISMATCH'
  | 'SIZE_MISMATCH'
  | 'FILE_ABSENT'
  | 'DELETE_UNVERIFIED'
  | 'NOT_SUPPORTED';

export class TransferError extends Error {
  readonly code: TransferErrorCode;
  readonly detail: Record<string, unknown>;
  constructor(code: TransferErrorCode, message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.name = 'TransferError';
    this.code = code;
    this.detail = detail;
  }
}

// ============================================================================
// One-time tokens
// ============================================================================

export interface TokenGrant {
  /** The bearer value. Goes in the URL handed to the router, nowhere else. */
  readonly token: string;
  readonly purpose: string;
  readonly maxBytes: number;
  readonly expiresAt: number;
}

interface TokenRecord {
  hash: Buffer;
  purpose: string;
  maxBytes: number;
  expiresAt: number;
  consumedAt: number | null;
}

/** Default life of a transfer token. Long enough for a 20 MB backup over a bad
 *  ADSL, short enough that a token found in a proxy log tomorrow is dead. */
export const TRANSFER_TOKEN_TTL_MS = 5 * 60_000;

/**
 * Tokens are stored HASHED. The value only ever exists in the URL we hand the
 * router and in the request line the router sends back; a heap dump or a stray
 * dump of this store yields digests, not credentials.
 */
export class OneTimeTokenStore {
  private readonly records = new Map<string, TokenRecord>();

  mint(purpose: string, maxBytes: number, ttlMs = TRANSFER_TOKEN_TTL_MS): TokenGrant {
    const token = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(token).digest();
    const expiresAt = Date.now() + ttlMs;
    this.records.set(hash.toString('hex'), {
      hash,
      purpose,
      maxBytes,
      expiresAt,
      consumedAt: null,
    });
    return { token, purpose, maxBytes, expiresAt };
  }

  /**
   * Burn a token. The map is keyed by the DIGEST, so a wrong token cannot be
   * distinguished by timing on the lookup, and the final `timingSafeEqual`
   * covers the (theoretical) collision path.
   */
  consume(
    token: string,
  ): { ok: true; record: TokenRecord } | { ok: false; code: TransferErrorCode } {
    if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) {
      return { ok: false, code: 'TOKEN_INVALID' };
    }
    const hash = crypto.createHash('sha256').update(token).digest();
    const record = this.records.get(hash.toString('hex'));
    if (!record) return { ok: false, code: 'TOKEN_INVALID' };
    if (!crypto.timingSafeEqual(record.hash, hash)) return { ok: false, code: 'TOKEN_INVALID' };
    if (record.consumedAt !== null) return { ok: false, code: 'TOKEN_CONSUMED' };
    if (Date.now() > record.expiresAt) return { ok: false, code: 'TOKEN_EXPIRED' };
    record.consumedAt = Date.now();
    return { ok: true, record };
  }

  /** Drop a grant that was never used (the fetch failed, the job aborted). */
  revoke(token: string): void {
    if (!/^[0-9a-f]{64}$/.test(token ?? '')) return;
    this.records.delete(crypto.createHash('sha256').update(token).digest('hex'));
  }

  /** Housekeeping. A consumed token is kept until expiry so that a replay is
   *  reported as TOKEN_CONSUMED (a signal) rather than TOKEN_INVALID (noise). */
  sweep(now = Date.now()): number {
    let n = 0;
    for (const [key, rec] of this.records) {
      if (now > rec.expiresAt) {
        this.records.delete(key);
        n++;
      }
    }
    return n;
  }

  get size(): number {
    return this.records.size;
  }
}

// ============================================================================
// The receiver — the half-minute during which a router may write to us
// ============================================================================

export interface ReceivedFile {
  /** Absolute path of the spooled file. The caller owns it and must move it or
   *  delete it. */
  path: string;
  bytes: number;
  sha256: string;
  durationMs: number;
  remoteAddress: string | null;
}

export interface TransferReceiverOptions {
  /** Interface to bind. Defaults to every interface, because the router dials
   *  us over the tunnel and we do not always know which local address that is.
   *  Set it in production to the tunnel-facing address. */
  host?: string;
  /** 0 = an ephemeral port, which is what tests want. */
  port?: number;
  /** Where uploads land before the caller moves them. */
  spoolDir?: string;
  /** Advertised base URL, for when ObliWAN sits behind a NAT or a proxy and the
   *  router cannot reach `host:port` directly. */
  publicBaseUrl?: string;
}

export interface ExpectedUpload {
  grant: TokenGrant;
  /** The exact URL to hand `/tool/fetch`. Contains the token. NEVER audit it
   *  raw — use `redactTransferUrl()`. */
  url: string;
  /** Resolves when the body has been fully received and hashed. */
  received: Promise<ReceivedFile>;
  /** Give up waiting and refuse any later arrival. */
  cancel(reason: string): void;
}

const TRANSFER_PATH_PREFIX = '/_obliwan/transfer/';

/**
 * Matches a transfer token WHEREVER it appears, not only in a bare URL.
 *
 * This regex exists because the first run of the M6 recipe caught the leak it
 * closes: `/tool/fetch =url=http://…/_obliwan/transfer/<64 hex>` was being
 * written verbatim into `command_audit`, because `url` is not a secret
 * attribute and nobody had told the audit redactor that this particular URL
 * carries a bearer credential in its path. A single-use token is still a
 * credential for the seconds it is alive, and the audit screen is exactly the
 * place a credential must not be.
 */
export const TRANSFER_TOKEN_IN_TEXT = /\/_obliwan\/transfer\/[0-9a-f]+/gi;

/** Strip the token out of a fetch URL so it can be written to `command_audit`. */
export function redactTransferUrl(url: string): string {
  return url.replace(TRANSFER_TOKEN_IN_TEXT, `${TRANSFER_PATH_PREFIX}***`);
}

export class TransferReceiver {
  private readonly opts: Required<Omit<TransferReceiverOptions, 'publicBaseUrl'>> & {
    publicBaseUrl?: string;
  };
  private readonly tokens = new OneTimeTokenStore();
  private readonly pending = new Map<
    string,
    {
      resolve: (f: ReceivedFile) => void;
      reject: (e: Error) => void;
      settled: boolean;
      spoolPath: string;
      startedAt: number;
    }
  >();
  private server: http.Server | null = null;
  private boundPort = 0;

  constructor(options: TransferReceiverOptions = {}) {
    this.opts = {
      host: options.host ?? '0.0.0.0',
      port: options.port ?? 0,
      spoolDir: options.spoolDir ?? path.join(os.tmpdir(), 'obliwan-transfer'),
      publicBaseUrl: options.publicBaseUrl,
    };
  }

  async start(): Promise<number> {
    if (this.server) return this.boundPort;
    await fsp.mkdir(this.opts.spoolDir, { recursive: true });
    const server = http.createServer((req, res) => {
      void this.onRequest(req, res);
    });
    // A router that opens a socket and says nothing must not hold us open.
    server.headersTimeout = 30_000;
    server.requestTimeout = 15 * 60_000;
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.opts.port, this.opts.host, () => resolve());
    });
    const addr = server.address();
    this.boundPort = typeof addr === 'object' && addr ? addr.port : this.opts.port;
    this.server = server;
    return this.boundPort;
  }

  async stop(): Promise<void> {
    for (const [, p] of this.pending) {
      if (!p.settled) {
        p.settled = true;
        p.reject(new TransferError('TRANSFER_FAILED', 'transfer receiver stopped'));
      }
    }
    this.pending.clear();
    const server = this.server;
    this.server = null;
    if (!server) return;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  get port(): number {
    return this.boundPort;
  }

  /** The address the ROUTER should dial. Callers pass the tunnel-side address
   *  of this server. */
  baseUrl(host?: string): string {
    if (this.opts.publicBaseUrl) return this.opts.publicBaseUrl.replace(/\/+$/, '');
    const h = host ?? (this.opts.host === '0.0.0.0' ? '127.0.0.1' : this.opts.host);
    return `http://${h.includes(':') ? `[${h}]` : h}:${this.boundPort}`;
  }

  /**
   * Authorise exactly one upload.
   *
   * `timeoutMs` is a hard ceiling: the promise rejects and the token is revoked,
   * so a router that dies mid-transfer cannot leave a listener half-open with a
   * live credential attached to it.
   */
  expect(options: {
    purpose: string;
    maxBytes: number;
    timeoutMs?: number;
    /** Host to build the URL with — the address the router can reach us on. */
    callbackHost?: string;
  }): ExpectedUpload {
    if (!this.server) throw new TransferError('TRANSFER_FAILED', 'receiver is not started');
    const grant = this.tokens.mint(
      options.purpose,
      options.maxBytes,
      options.timeoutMs ?? TRANSFER_TOKEN_TTL_MS,
    );
    const spoolPath = path.join(
      this.opts.spoolDir,
      `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.part`,
    );
    let resolveFn!: (f: ReceivedFile) => void;
    let rejectFn!: (e: Error) => void;
    const received = new Promise<ReceivedFile>((resolve, reject) => {
      resolveFn = resolve;
      rejectFn = reject;
    });
    const entry = {
      resolve: resolveFn,
      reject: rejectFn,
      settled: false,
      spoolPath,
      startedAt: Date.now(),
    };
    this.pending.set(grant.token, entry);

    const timer = setTimeout(() => {
      if (entry.settled) return;
      entry.settled = true;
      this.tokens.revoke(grant.token);
      this.pending.delete(grant.token);
      rejectFn(
        new TransferError('TRANSFER_TIMEOUT', 'the device never delivered the file', {
          purpose: options.purpose,
          waitedMs: Date.now() - entry.startedAt,
        }),
      );
    }, options.timeoutMs ?? TRANSFER_TOKEN_TTL_MS);
    timer.unref?.();
    void received.catch(() => undefined).finally(() => clearTimeout(timer));

    return {
      grant,
      url: `${this.baseUrl(options.callbackHost)}${TRANSFER_PATH_PREFIX}${grant.token}`,
      received,
      cancel: (reason: string) => {
        if (entry.settled) return;
        entry.settled = true;
        clearTimeout(timer);
        this.tokens.revoke(grant.token);
        this.pending.delete(grant.token);
        rejectFn(new TransferError('TRANSFER_FAILED', reason));
      },
    };
  }

  private async onRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = req.url ?? '';
    if (!url.startsWith(TRANSFER_PATH_PREFIX)) {
      res.writeHead(404).end();
      return;
    }
    if (req.method !== 'POST' && req.method !== 'PUT') {
      // RouterOS `/tool/fetch upload=yes` posts. Some firmwares PUT. Anything
      // else is not a transfer and gets nothing, not even a hint.
      res.writeHead(405).end();
      return;
    }
    const token = url.slice(TRANSFER_PATH_PREFIX.length).split(/[?#]/)[0];
    const verdict = this.tokens.consume(token);
    if (!verdict.ok) {
      // Deliberately indistinguishable to the caller: an expired token and a
      // forged one both get 404. The DIFFERENCE goes to our log, not to them.
      logger.warn({ code: verdict.code }, 'transfer: upload refused');
      res.writeHead(404).end();
      return;
    }
    const entry = this.pending.get(token);
    if (!entry || entry.settled) {
      res.writeHead(409).end();
      return;
    }
    this.pending.delete(token);

    const hash = crypto.createHash('sha256');
    let bytes = 0;
    let aborted: TransferError | null = null;
    const sink = fs.createWriteStream(entry.spoolPath);

    await new Promise<void>((resolve) => {
      req.on('data', (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > verdict.record.maxBytes) {
          aborted = new TransferError('TOO_LARGE', 'upload exceeded the authorised size', {
            maxBytes: verdict.record.maxBytes,
            bytes,
          });
          req.destroy();
          sink.destroy();
          resolve();
          return;
        }
        hash.update(chunk);
        sink.write(chunk);
      });
      req.on('error', (err) => {
        aborted = new TransferError('TRANSFER_FAILED', `upload aborted: ${err.message}`);
        sink.destroy();
        resolve();
      });
      req.on('end', () => {
        sink.end(() => resolve());
      });
    });

    const abortedErr: TransferError | null = aborted;
    if (abortedErr) {
      await fsp.rm(entry.spoolPath, { force: true }).catch(() => undefined);
      entry.settled = true;
      entry.reject(abortedErr);
      res.writeHead(413).end();
      return;
    }

    entry.settled = true;
    entry.resolve({
      path: entry.spoolPath,
      bytes,
      sha256: hash.digest('hex'),
      durationMs: Date.now() - entry.startedAt,
      remoteAddress: req.socket.remoteAddress ?? null,
    });
    res.writeHead(204).end();
  }
}

// ============================================================================
// Device-side file operations (RouterOS)
// ============================================================================

export interface DeviceFile {
  name: string;
  sizeBytes: number;
  type: string | null;
  id: string | null;
}

function parseSize(raw: string | undefined): number {
  if (!raw) return 0;
  // v6 prints `12.3KiB`, v7 prints the byte count. Accept both; a human-readable
  // size is a WEAK size and the caller must not treat it as a proof.
  const plain = Number(raw);
  if (Number.isFinite(plain) && raw.trim() !== '') return plain;
  const m = /^([\d.]+)\s*([KMG])i?B$/i.exec(raw.trim());
  if (!m) return 0;
  const mult = { k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[m[2].toLowerCase()] ?? 1;
  return Math.round(Number(m[1]) * mult);
}

/** Read one file row, or null. A `!trap` on `/file/print` means the menu is not
 *  there — treated as "no file", never as an error. */
export async function deviceFileInfo(
  conn: RouterOsConnection,
  name: string,
): Promise<DeviceFile | null> {
  let rows: Record<string, string>[];
  try {
    rows = await conn.query(['/file/print', `?name=${name}`]);
  } catch (err) {
    if (err instanceof RouterOsTrapError) return null;
    throw err;
  }
  const row = rows.find((r) => r.name === name) ?? null;
  if (!row) return null;
  return {
    name: row.name,
    sizeBytes: parseSize(row.size),
    type: row.type ?? null,
    id: row['.id'] ?? null,
  };
}

/**
 * Wait for a file the device is writing asynchronously.
 *
 * `/system/backup/save` answers `!done` before the file is necessarily on the
 * disk, and `/export file=` certainly does. Polling `/file/print` until the size
 * STOPS GROWING is the only honest way to know it finished: a size still
 * increasing means we would pull a truncated backup and then verify it against
 * its own truncated digest, which proves nothing.
 */
export async function waitForDeviceFile(
  conn: RouterOsConnection,
  name: string,
  options: { timeoutMs?: number; pollMs?: number; stableChecks?: number } = {},
): Promise<DeviceFile> {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const pollMs = options.pollMs ?? 250;
  const stableChecks = options.stableChecks ?? 2;
  const deadline = Date.now() + timeoutMs;
  let lastSize = -1;
  let stable = 0;
  let seen: DeviceFile | null = null;

  while (Date.now() < deadline) {
    const info = await deviceFileInfo(conn, name);
    if (info) {
      seen = info;
      if (info.sizeBytes > 0 && info.sizeBytes === lastSize) {
        stable++;
        if (stable >= stableChecks) return info;
      } else {
        stable = 0;
      }
      lastSize = info.sizeBytes;
    }
    await new Promise<void>((r) => setTimeout(r, pollMs));
  }
  throw new TransferError(
    'FILE_ABSENT',
    `the device never produced a stable '${name}' within ${timeoutMs} ms`,
    { name, lastSeenSize: seen?.sizeBytes ?? null },
  );
}

export interface RemovalResult {
  removed: boolean;
  /** True only when a re-read of the file table confirmed the absence. A
   *  `removed: true, verified: false` is a FAILURE for the caller: it means we
   *  asked, nothing complained, and the customer's config may still be there. */
  verified: boolean;
  attempts: number;
  lastError: string | null;
}

/**
 * Delete a file and PROVE it is gone.
 *
 * The proof is the point. `/file/remove` on a name that does not exist traps;
 * `/file/remove` on a name that does exist returns `!done` and, on a busy
 * router, occasionally leaves the row. So: remove, re-read, and only report
 * success when the re-read comes back empty.
 */
export async function removeDeviceFile(
  conn: RouterOsConnection,
  name: string,
  options: { attempts?: number; backoffMs?: number } = {},
): Promise<RemovalResult> {
  const attempts = options.attempts ?? 3;
  const backoffMs = options.backoffMs ?? 300;
  let lastError: string | null = null;

  for (let i = 1; i <= attempts; i++) {
    try {
      const existing = await deviceFileInfo(conn, name);
      if (!existing) return { removed: true, verified: true, attempts: i, lastError };
      const selector = existing.id ?? name;
      await conn.talk(['/file/remove', `=numbers=${selector}`]);
      const after = await deviceFileInfo(conn, name);
      if (!after) return { removed: true, verified: true, attempts: i, lastError: null };
      lastError = 'the file is still listed after /file/remove';
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }
    if (i < attempts) await new Promise<void>((r) => setTimeout(r, backoffMs * i));
  }
  return { removed: false, verified: false, attempts, lastError };
}

export interface FetchOutcome {
  ok: boolean;
  /** RouterOS' own view: `finished`, `failed`, `connecting`... */
  deviceStatus: string | null;
  durationMs: number;
  error: string | null;
}

/**
 * Make the device upload a file to us.
 *
 * Issued with a generous per-request budget because a 30 MB backup over a
 * saturated ADSL is slow, and the receiver has its OWN independent deadline —
 * two clocks, so a router that answers `!done` while having sent nothing still
 * fails on the receiver's side rather than passing on ours.
 */
export async function uploadFileFromDevice(
  conn: RouterOsConnection,
  options: { srcPath: string; url: string; timeoutMs?: number },
): Promise<FetchOutcome> {
  const started = Date.now();
  try {
    const rows = await conn.query(
      ['/tool/fetch', '=upload=yes', `=src-path=${options.srcPath}`, `=url=${options.url}`],
      { timeoutMs: options.timeoutMs ?? 10 * 60_000 },
    );
    const status = rows.length > 0 ? (rows[rows.length - 1].status ?? null) : null;
    return {
      ok: status === null || status === 'finished',
      deviceStatus: status,
      durationMs: Date.now() - started,
      error: null,
    };
  } catch (err) {
    return {
      ok: false,
      deviceStatus: null,
      durationMs: Date.now() - started,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

// ============================================================================
// SFTP — the other road, for sites that will not let the router dial back
// ============================================================================

export interface SftpPullOptions {
  host: string;
  port?: number;
  username: string;
  password?: string;
  privateKey?: string;
  passphrase?: string;
  remotePath: string;
  localPath: string;
  maxBytes: number;
  timeoutMs?: number;
  /** Pinned host key SHA-256 (base64). Absent = trust on first use, and the
   *  observed key is reported so the caller can persist it. */
  expectedHostKeySha256?: string | null;
  onHostKey?: (sha256Base64: string) => void;
}

/**
 * HONESTY NOTE, LOAD-BEARING: this path has never been run against anything.
 * There is no SSH server in this repository's test scaffolding and no lab
 * router on this machine, so `sftpPullFile` is written, type-checked and
 * UNPROVEN. `/tool/fetch` is the tested road. Anyone enabling SFTP in
 * production is running it for the first time; treat the first pull as a test.
 */
export async function sftpPullFile(
  options: SftpPullOptions,
): Promise<{ bytes: number; sha256: string }> {
  // Imported lazily so a deployment that never uses SFTP does not pay for
  // ssh2's native bindings at boot.
  const { Client } = await import('ssh2');
  return new Promise((resolve, reject) => {
    const client = new Client();
    const timer = setTimeout(() => {
      client.end();
      reject(new TransferError('TRANSFER_TIMEOUT', 'SFTP pull timed out'));
    }, options.timeoutMs ?? 10 * 60_000);

    const fail = (err: Error) => {
      clearTimeout(timer);
      client.end();
      reject(err);
    };

    client
      .on('ready', () => {
        client.sftp((err, sftp) => {
          if (err) return fail(err);
          const hash = crypto.createHash('sha256');
          let bytes = 0;
          const read = sftp.createReadStream(options.remotePath);
          const write = fs.createWriteStream(options.localPath);
          read.on('data', (chunk: Buffer | string) => {
            const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            bytes += buf.length;
            if (bytes > options.maxBytes) {
              read.destroy();
              write.destroy();
              fail(new TransferError('TOO_LARGE', 'SFTP body exceeded the authorised size'));
              return;
            }
            hash.update(buf);
          });
          read.on('error', (e: Error) => fail(e));
          write.on('error', (e: Error) => fail(e));
          write.on('close', () => {
            clearTimeout(timer);
            client.end();
            resolve({ bytes, sha256: hash.digest('hex') });
          });
          read.pipe(write);
        });
      })
      .on('error', fail)
      .connect({
        host: options.host,
        port: options.port ?? 22,
        username: options.username,
        password: options.password,
        privateKey: options.privateKey,
        passphrase: options.passphrase,
        readyTimeout: options.timeoutMs ?? 30_000,
        hostVerifier: ((key: Buffer) => {
          const digest = crypto.createHash('sha256').update(key).digest('base64');
          options.onHostKey?.(digest);
          if (!options.expectedHostKeySha256) return true;
          const expected = options.expectedHostKeySha256.replace(/=+$/, '');
          return digest.replace(/=+$/, '') === expected;
        }) as never,
      });
  });
}

// ============================================================================
// Verification
// ============================================================================

export interface VerifiedArtefact {
  path: string;
  bytes: number;
  sha256: string;
}

/**
 * Prove that what landed on our disk is what came off the router.
 *
 * Three separate claims, because they fail separately:
 *   - the stream digest matches a RE-READ of the file from disk (catches a
 *     truncated write, a full filesystem, a spool the OS never flushed);
 *   - the byte count matches what the device said the file was;
 *   - the file is at least `minBytes` — a zero-length or 40-byte "backup" is
 *     the classic silent failure, and a job must not proceed on one.
 */
export async function verifyArtefact(
  received: ReceivedFile,
  options: { minBytes: number; deviceReportedBytes?: number | null },
): Promise<VerifiedArtefact> {
  const stat = await fsp.stat(received.path);
  if (stat.size !== received.bytes) {
    throw new TransferError('SIZE_MISMATCH', 'the spooled file is not the size we received', {
      onDisk: stat.size,
      received: received.bytes,
    });
  }
  if (received.bytes < options.minBytes) {
    throw new TransferError(
      'SIZE_MISMATCH',
      `the artefact is ${received.bytes} bytes, below the ${options.minBytes}-byte floor — ` +
        'a backup this small is a failure that answered !done',
      { bytes: received.bytes, minBytes: options.minBytes },
    );
  }
  const rehash = crypto.createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    const s = fs.createReadStream(received.path);
    s.on('data', (c: Buffer | string) => rehash.update(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    s.on('error', reject);
    s.on('end', () => resolve());
  });
  const onDisk = rehash.digest('hex');
  if (onDisk !== received.sha256) {
    throw new TransferError('DIGEST_MISMATCH', 'the stored file does not hash to what we received', {
      streamed: received.sha256,
      onDisk,
    });
  }
  const reported = options.deviceReportedBytes ?? null;
  if (reported !== null && reported > 0) {
    // RouterOS 6 rounds the size it prints. 2% or 1 KiB, whichever is larger.
    const tolerance = Math.max(1024, Math.ceil(reported * 0.02));
    if (Math.abs(reported - received.bytes) > tolerance) {
      throw new TransferError(
        'SIZE_MISMATCH',
        'the device reported a different size than we received',
        { deviceReported: reported, received: received.bytes, tolerance },
      );
    }
  }
  return { path: received.path, bytes: received.bytes, sha256: onDisk };
}

/** sha256 of a local file. Used to re-verify a stored backup months later. */
export async function hashFile(filePath: string): Promise<{ sha256: string; bytes: number }> {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  await new Promise<void>((resolve, reject) => {
    const s = fs.createReadStream(filePath);
    s.on('data', (c: Buffer | string) => {
      const b = Buffer.isBuffer(c) ? c : Buffer.from(c);
      bytes += b.length;
      hash.update(b);
    });
    s.on('error', reject);
    s.on('end', () => resolve());
  });
  return { sha256: hash.digest('hex'), bytes };
}
