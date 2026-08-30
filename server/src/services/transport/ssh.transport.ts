/**
 * ObliWAN — SSH transport, on `ssh2`.
 *
 * Two modes, because the four brands disagree about what an SSH server is:
 *
 *  - `exec()`  one command per channel, separate stdout/stderr, real exit code.
 *              MikroTik, Zyxel ZLD and SonicOS behave properly here.
 *  - `shell()` a persistent interactive channel driven by a prompt regex.
 *              REQUIRED for DrayTek (a menu CLI with no exec channel) and for
 *              any sequence where line N depends on the mode entered by line
 *              N-1 (`configure terminal` ... `write`).
 *
 * Secrets (section 8.2): the password / private key / passphrase enter this
 * module and never leave it. Nothing here logs. Every message that can reach a
 * caller — and therefore a log or `device_health.last_error` — goes through
 * `redact()` with the literals this connection holds, because a CLI will echo
 * back the password you just typed at an interactive login prompt.
 *
 * Risk R9: password auth is supported (some Vigor firmware has no other way)
 * but `privateKey` is preferred and used first when both are present.
 */

import { Client, type ClientChannel, type ConnectConfig } from 'ssh2';
import { DriverError, asDriverError, redact } from '../drivers/types';

// ============================================================================
// Target
// ============================================================================

export interface SshTarget {
  host: string;
  port?: number;
  username: string;
  password?: string | null;
  /** PEM text. Preferred over `password`. */
  privateKey?: string | null;
  passphrase?: string | null;
  /** Budget for the handshake AND the default budget for each command. */
  timeoutMs?: number;
  /**
   * Old DrayTek / Zyxel firmware negotiates only pre-2015 KEX and ciphers.
   * OFF by default: widening the algorithm set for every device to accommodate
   * two families would silently downgrade the MikroTik fleet too. The driver
   * opts in per device via `device_transports.params.legacyAlgorithms`.
   */
  legacyAlgorithms?: boolean;
  /** Keepalive so a half-open tunnel is detected instead of hanging. */
  keepaliveIntervalMs?: number;
}

export interface SshExecResult {
  stdout: string;
  stderr: string;
  /** null when the channel closed on a signal instead of an exit code. */
  code: number | null;
  signal: string | null;
  durationMs: number;
}

export interface SshExecOptions {
  timeoutMs?: number;
  /** Some CLIs need a pty even for exec (SonicOS refuses without one). */
  pty?: boolean;
  /** Cap on captured output. A `show tech-support` can be megabytes and a
   *  runaway pager can be infinite; truncate rather than exhaust the heap. */
  maxOutputBytes?: number;
}

const DEFAULT_TIMEOUT_MS = 20_000;
const DEFAULT_MAX_OUTPUT = 8 * 1024 * 1024;

/** Algorithm set for firmware that never learned modern crypto. */
const LEGACY_ALGORITHMS = {
  kex: [
    'curve25519-sha256',
    'ecdh-sha2-nistp256',
    'diffie-hellman-group14-sha256',
    'diffie-hellman-group14-sha1',
    'diffie-hellman-group1-sha1',
  ],
  cipher: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', 'aes256-cbc', '3des-cbc'],
  serverHostKey: ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'],
};

/** Map an ssh2 error onto the taxonomy the arbiter's breaker understands. */
function classify(err: Error & { level?: string; code?: string }): DriverError['code'] {
  if (err.level === 'client-authentication') return 'AUTH_FAILED';
  if (err.code === 'ENOTFOUND' || err.code === 'EHOSTUNREACH' || err.code === 'ENETUNREACH') {
    return 'UNREACHABLE';
  }
  if (err.code === 'ECONNREFUSED' || err.code === 'ECONNRESET') return 'UNREACHABLE';
  if (err.code === 'ETIMEDOUT' || /timed? ?out/i.test(err.message)) return 'TIMEOUT';
  if (err.level === 'protocol' || /handshake|kex|no matching/i.test(err.message)) {
    return 'PROTOCOL_ERROR';
  }
  return 'UNREACHABLE';
}

// ============================================================================
// Connection
// ============================================================================

export class SshTransport {
  private client: Client | null = null;
  private readonly secrets: string[];
  private readonly timeoutMs: number;

  private constructor(private readonly target: SshTarget) {
    this.timeoutMs = target.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.secrets = [target.password, target.privateKey, target.passphrase].filter(
      (s): s is string => typeof s === 'string' && s.length > 0,
    );
  }

  /** Dial and authenticate. The only place a handshake happens. */
  static async open(target: SshTarget): Promise<SshTransport> {
    const t = new SshTransport(target);
    await t.connect();
    return t;
  }

  /** Scrub anything this connection could echo back before it escapes. */
  private clean(text: string): string {
    return redact(text, this.secrets);
  }

  private fail(message: string, code: DriverError['code'], cause?: unknown): DriverError {
    return new DriverError(this.clean(message), code, { transport: 'ssh', cause });
  }

  private connect(): Promise<Client> {
    if (this.client) return Promise.resolve(this.client);

    const { target } = this;
    if (!target.host) {
      return Promise.reject(this.fail('SSH target has no host', 'NO_TRANSPORT'));
    }
    if (!target.password && !target.privateKey) {
      return Promise.reject(
        this.fail(`SSH ${target.host}: neither a private key nor a password is set`, 'AUTH_FAILED'),
      );
    }

    return new Promise<Client>((resolve, reject) => {
      const client = new Client();
      let settled = false;

      const cfg: ConnectConfig = {
        host: target.host,
        port: target.port ?? 22,
        username: target.username,
        readyTimeout: this.timeoutMs,
        keepaliveInterval: target.keepaliveIntervalMs ?? 15_000,
        // Key first (R9). ssh2 falls back to the password on its own if the
        // server rejects publickey and a password is also supplied.
        ...(target.privateKey ? { privateKey: target.privateKey } : {}),
        ...(target.passphrase ? { passphrase: target.passphrase } : {}),
        ...(target.password ? { password: target.password } : {}),
        ...(target.legacyAlgorithms
          ? { algorithms: LEGACY_ALGORITHMS as unknown as ConnectConfig['algorithms'] }
          : {}),
      };

      client.once('ready', () => {
        if (settled) return;
        settled = true;
        this.client = client;
        resolve(client);
      });

      client.on('error', (err: Error & { level?: string; code?: string }) => {
        if (settled) return;
        settled = true;
        client.end();
        reject(this.fail(`SSH ${target.host}: ${err.message}`, classify(err), err));
      });

      client.once('close', () => {
        this.client = null;
        if (settled) return;
        settled = true;
        reject(this.fail(`SSH ${target.host}: connection closed during handshake`, 'UNREACHABLE'));
      });

      try {
        client.connect(cfg);
      } catch (err) {
        if (settled) return;
        settled = true;
        reject(asDriverError(err, 'UNREACHABLE', 'ssh'));
      }
    });
  }

  /**
   * One command on its own channel. stdout and stderr are kept SEPARATE: a
   * parser that reads a CLI banner off stderr as if it were table data is the
   * classic way to invent an interface that does not exist.
   */
  async exec(command: string, opts: SshExecOptions = {}): Promise<SshExecResult> {
    const client = await this.connect();
    const budget = opts.timeoutMs ?? this.timeoutMs;
    const maxBytes = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT;
    const startedAt = Date.now();

    return new Promise<SshExecResult>((resolve, reject) => {
      let settled = false;
      const finish = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        fn();
      };

      const timer = setTimeout(() => {
        finish(() =>
          reject(this.fail(`SSH exec timed out after ${budget} ms: ${command}`, 'TIMEOUT')),
        );
      }, budget);

      client.exec(command, { pty: opts.pty ?? false }, (err, stream: ClientChannel) => {
        if (err) {
          finish(() => reject(this.fail(`SSH exec failed: ${err.message}`, 'PROTOCOL_ERROR', err)));
          return;
        }

        let stdout = '';
        let stderr = '';
        let bytes = 0;
        let code: number | null = null;
        let signal: string | null = null;

        const cap = (chunk: Buffer): boolean => {
          bytes += chunk.length;
          if (bytes > maxBytes) {
            finish(() =>
              reject(
                this.fail(
                  `SSH exec output exceeded ${maxBytes} bytes: ${command}`,
                  'PROTOCOL_ERROR',
                ),
              ),
            );
            stream.close();
            return false;
          }
          return true;
        };

        stream.on('data', (d: Buffer) => {
          if (cap(d)) stdout += d.toString('utf8');
        });
        stream.stderr.on('data', (d: Buffer) => {
          if (cap(d)) stderr += d.toString('utf8');
        });
        stream.on('exit', (c: number | null, sig?: string) => {
          code = c;
          signal = sig ?? null;
        });
        stream.on('close', () => {
          finish(() =>
            resolve({
              stdout: this.clean(stdout),
              stderr: this.clean(stderr),
              code,
              signal,
              durationMs: Date.now() - startedAt,
            }),
          );
        });
        stream.on('error', (streamErr: Error) => {
          finish(() =>
            reject(this.fail(`SSH exec stream error: ${streamErr.message}`, 'PROTOCOL_ERROR', streamErr)),
          );
        });
      });
    });
  }

  /**
   * Open an interactive shell. For CLIs that have no exec channel at all
   * (DrayTek) or that are modal (Zyxel `configure terminal`).
   *
   * `prompt` must match ONLY the idle prompt. A regex that also matches a line
   * of output makes the reader return half a table, and the next command's
   * output then arrives as a prefix of the one after it — the failure looks
   * like a flaky device and is really a bad regex.
   */
  async shell(opts: { prompt: RegExp; timeoutMs?: number; cols?: number; rows?: number }): Promise<SshShell> {
    const client = await this.connect();
    const stream = await new Promise<ClientChannel>((resolve, reject) => {
      client.shell(
        { term: 'vt100', cols: opts.cols ?? 200, rows: opts.rows ?? 5000 },
        (err, s) => (err ? reject(this.fail(`SSH shell failed: ${err.message}`, 'PROTOCOL_ERROR', err)) : resolve(s)),
      );
    });
    return new SshShell(stream, opts.prompt, opts.timeoutMs ?? this.timeoutMs, (t) => this.clean(t));
  }

  async close(): Promise<void> {
    const client = this.client;
    this.client = null;
    if (!client) return;
    await new Promise<void>((resolve) => {
      client.once('close', () => resolve());
      client.end();
      // A device that never answers FIN must not hold the pool forever.
      setTimeout(resolve, 2_000).unref?.();
    });
  }
}

// ============================================================================
// Interactive shell
// ============================================================================

/** Pagers the four brands use. Answered with a space instead of hanging. */
const PAGER = /--More--|--\s*more\s*--|Press any key to continue|\(q\)uit/i;

export class SshShell {
  private buffer = '';
  private closed = false;

  constructor(
    private readonly stream: ClientChannel,
    private readonly prompt: RegExp,
    private readonly timeoutMs: number,
    private readonly clean: (text: string) => string,
  ) {
    this.stream.on('close', () => {
      this.closed = true;
    });
  }

  /** Consume whatever the device printed on connect (banner, MOTD, prompt). */
  async waitForPrompt(timeoutMs?: number): Promise<string> {
    return this.read(timeoutMs ?? this.timeoutMs);
  }

  /**
   * Write one line and read until the prompt comes back.
   *
   * The echo of the command itself is stripped: every one of these CLIs echoes
   * what you typed, and leaving it in means an interactive login sequence puts
   * the password in the returned transcript.
   */
  async send(line: string, opts: { timeoutMs?: number; secret?: boolean } = {}): Promise<string> {
    if (this.closed) {
      throw new DriverError('SSH shell is closed', 'UNREACHABLE', { transport: 'ssh' });
    }
    this.buffer = '';
    this.stream.write(`${line}\n`);
    const raw = await this.read(opts.timeoutMs ?? this.timeoutMs, opts.secret ? line : null);
    return stripEcho(raw, opts.secret ? null : line);
  }

  private read(timeoutMs: number, extraSecret: string | null = null): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      let settled = false;

      const done = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.stream.off('data', onData);
        this.stream.off('close', onClose);
        fn();
      };

      const timer = setTimeout(() => {
        const tail = this.sanitize(this.buffer, extraSecret).slice(-400);
        done(() =>
          reject(
            new DriverError(
              `SSH shell timed out after ${timeoutMs} ms waiting for the prompt. Last output: ${tail}`,
              'TIMEOUT',
              { transport: 'ssh' },
            ),
          ),
        );
      }, timeoutMs);

      const onData = (d: Buffer) => {
        this.buffer += d.toString('utf8');
        // Feed the pager rather than waiting for a prompt that never comes.
        if (PAGER.test(this.buffer)) {
          this.buffer = this.buffer.replace(PAGER, '');
          this.stream.write(' ');
          return;
        }
        if (this.prompt.test(this.buffer)) {
          const out = this.buffer;
          this.buffer = '';
          done(() => resolve(this.sanitize(out, extraSecret)));
        }
      };

      const onClose = () => {
        this.closed = true;
        const out = this.sanitize(this.buffer, extraSecret);
        this.buffer = '';
        done(() => resolve(out));
      };

      this.stream.on('data', onData);
      this.stream.once('close', onClose);
    });
  }

  private sanitize(text: string, extraSecret: string | null): string {
    const base = this.clean(text);
    return extraSecret ? redactLiteral(base, extraSecret) : base;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.stream.end();
  }
}

/** Drop the leading echoed command line, and only that line. */
function stripEcho(output: string, command: string | null): string {
  if (!command) return output;
  const lines = output.split(/\r?\n/);
  if (lines.length > 0 && lines[0].trim() === command.trim()) lines.shift();
  return lines.join('\n');
}

function redactLiteral(text: string, secret: string): string {
  return redact(text, [secret]);
}

/**
 * Convenience for the common "connect, run a few commands, disconnect" shape.
 * The `finally` is the point: a leaked SSH session on a DrayTek (single CLI
 * session) makes the device unmanageable until it times out on its own.
 */
export async function withSsh<T>(
  target: SshTarget,
  fn: (ssh: SshTransport) => Promise<T>,
): Promise<T> {
  const ssh = await SshTransport.open(target);
  try {
    return await fn(ssh);
  } finally {
    await ssh.close().catch(() => undefined);
  }
}
