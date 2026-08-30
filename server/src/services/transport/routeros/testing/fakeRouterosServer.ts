/**
 * ObliWAN — a fake RouterOS API device.
 *
 * There is no lab router on this machine, and the two things most likely to be
 * silently wrong in an API client — the 1..5 byte length encoding and the
 * `.tag=` multiplexing — cannot be proven by reading the code. So we speak the
 * protocol back at ourselves.
 *
 * This server implements the wire format independently of `protocol.ts` where
 * it matters (it writes its own length prefixes), so a bug in the encoder is
 * not mirrored by the same bug in the decoder.
 *
 * It is test scaffolding, not production code: it is never imported by the
 * server at runtime. It lives in `src/` only so that `tsc` type-checks it.
 */

import net from 'net';
import tls from 'tls';
import { SentenceReader } from '../protocol';

export interface FakeRouterOsOptions {
  username?: string;
  password?: string;
  /** Emulate RouterOS < 6.43: answer /login with `=ret=<challenge>` first. */
  legacyLogin?: boolean;
  /** `7.14.3 (stable)` by default. Drives the capability probe. */
  version?: string;
  boardName?: string;
  identity?: string;
  /** `/system/health/print` shape. `rows` = v7, `record` = v6. */
  healthShape?: 'rows' | 'record' | 'unsupported';
  /** Menus that answer `!trap no such command`. */
  unsupportedPaths?: string[];
  /** Split every reply into two TCP segments at this byte offset. */
  splitRepliesAt?: number | null;
  /** Log every sentence the client sends (debugging). */
  trace?: boolean;
  /** Serve TLS (port 8729 behaviour) with this self-signed identity. */
  tls?: { cert: string; key: string };
}

interface Session {
  socket: net.Socket;
  reader: SentenceReader;
  authenticated: boolean;
  challenge: string | null;
  /** Tags of running `listen` commands. */
  listeners: Set<string>;
  /** Serialises writes when replies are being split into TCP segments. */
  writeChain: Promise<void>;
}

// -- independent encoder (deliberately not shared with protocol.ts) ----------

function fakeEncodeLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x4000) {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(len | 0x8000);
    return b;
  }
  if (len < 0x200000) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(len | 0xc00000);
    return b.subarray(1);
  }
  if (len < 0x10000000) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE((len | 0xe0000000) >>> 0);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = 0xf0;
  b.writeUInt32BE(len, 1);
  return b;
}

function fakeEncodeSentence(words: string[]): Buffer {
  const parts: Buffer[] = [];
  for (const w of words) {
    const data = Buffer.from(w, 'utf8');
    parts.push(fakeEncodeLength(data.length), data);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

// -- server -----------------------------------------------------------------

export class FakeRouterOs {
  private readonly server: net.Server;
  private readonly opts: Required<Omit<FakeRouterOsOptions, 'splitRepliesAt' | 'tls'>> & {
    splitRepliesAt: number | null;
    tls?: { cert: string; key: string };
  };
  private readonly sessions = new Set<Session>();

  /** Every sentence received, redaction-free, for assertions. */
  readonly received: string[][] = [];

  constructor(options: FakeRouterOsOptions = {}) {
    this.opts = {
      username: options.username ?? 'obliwan',
      password: options.password ?? 's3cr3t',
      legacyLogin: options.legacyLogin ?? false,
      version: options.version ?? '7.14.3 (stable)',
      boardName: options.boardName ?? 'CHR',
      identity: options.identity ?? 'chr-lab',
      healthShape: options.healthShape ?? 'rows',
      unsupportedPaths: options.unsupportedPaths ?? [],
      trace: options.trace ?? false,
      splitRepliesAt: options.splitRepliesAt ?? null,
      tls: options.tls,
    };
    this.server = options.tls
      ? tls.createServer({ cert: options.tls.cert, key: options.tls.key }, (socket) =>
          this.onConnection(socket),
        )
      : net.createServer((socket) => this.onConnection(socket));
  }

  listen(port = 0): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(port, '127.0.0.1', () => {
        const addr = this.server.address();
        resolve(typeof addr === 'object' && addr ? addr.port : port);
      });
    });
  }

  async close(): Promise<void> {
    for (const s of this.sessions) s.socket.destroy();
    this.sessions.clear();
    await new Promise<void>((res) => this.server.close(() => res()));
  }

  /** Number of live client sockets — proves the pool reuses one connection. */
  get connectionCount(): number {
    return this.sessions.size;
  }

  /** Push a `!re` to every running `/ppp/active/listen`. */
  pushPppEvent(attrs: Record<string, string>): number {
    let n = 0;
    for (const s of this.sessions) {
      for (const tag of s.listeners) {
        this.send(s, ['!re', ...Object.entries(attrs).map(([k, v]) => `=${k}=${v}`), `.tag=${tag}`]);
        n++;
      }
    }
    return n;
  }

  /** Kill every session the way a router does when it gives up on us. */
  sendFatal(message = 'session terminated'): void {
    for (const s of this.sessions) {
      this.send(s, ['!fatal', message]);
      setTimeout(() => s.socket.destroy(), 10);
    }
  }

  // -- plumbing -------------------------------------------------------------

  private onConnection(socket: net.Socket): void {
    const session: Session = {
      socket,
      reader: new SentenceReader(),
      authenticated: false,
      challenge: null,
      listeners: new Set(),
      writeChain: Promise.resolve(),
    };
    this.sessions.add(session);
    socket.on('data', (chunk) => {
      let sentences: string[][];
      try {
        sentences = session.reader.push(chunk);
      } catch {
        socket.destroy();
        return;
      }
      for (const words of sentences) {
        this.received.push(words);
        if (this.opts.trace) console.log('  [fake] <-', words.join(' '));
        this.handle(session, words);
      }
    });
    socket.on('error', () => undefined);
    socket.on('close', () => this.sessions.delete(session));
  }

  private send(session: Session, words: string[]): void {
    const buf = fakeEncodeSentence(words);
    const at = this.opts.splitRepliesAt;
    if (at === null) {
      session.socket.write(buf);
      return;
    }
    // Prove the client's reader is an automaton: cut every sentence, possibly
    // mid-word, and deliver the halves in two TCP segments. The writes are
    // chained so that a multi-sentence reply keeps its byte order.
    session.writeChain = session.writeChain.then(async () => {
      if (session.socket.destroyed) return;
      if (at > 0 && at < buf.length) {
        session.socket.write(buf.subarray(0, at));
        await new Promise<void>((res) => setTimeout(res, 15));
        if (!session.socket.destroyed) session.socket.write(buf.subarray(at));
      } else {
        session.socket.write(buf);
      }
    });
  }

  private tagWords(tag: string | undefined): string[] {
    return tag === undefined ? [] : [`.tag=${tag}`];
  }

  private done(session: Session, tag: string | undefined, attrs: string[] = []): void {
    this.send(session, ['!done', ...attrs, ...this.tagWords(tag)]);
  }

  private trap(session: Session, tag: string | undefined, message: string, category = 2): void {
    this.send(session, [
      '!trap',
      `=category=${category}`,
      `=message=${message}`,
      ...this.tagWords(tag),
    ]);
    this.done(session, tag);
  }

  private row(session: Session, tag: string | undefined, attrs: Record<string, string>): void {
    this.send(session, [
      '!re',
      ...Object.entries(attrs).map(([k, v]) => `=${k}=${v}`),
      ...this.tagWords(tag),
    ]);
  }

  private handle(session: Session, words: string[]): void {
    const command = words[0] ?? '';
    const attrs: Record<string, string> = {};
    let tag: string | undefined;
    for (const w of words.slice(1)) {
      if (w.startsWith('=')) {
        const rest = w.slice(1);
        const i = rest.indexOf('=');
        attrs[i === -1 ? rest : rest.slice(0, i)] = i === -1 ? '' : rest.slice(i + 1);
      } else if (w.startsWith('.tag=')) {
        tag = w.slice(5);
      }
    }

    if (command === '/login') {
      this.handleLogin(session, tag, attrs);
      return;
    }
    if (command === '/quit') {
      this.done(session, tag);
      setTimeout(() => session.socket.destroy(), 5);
      return;
    }
    if (!session.authenticated) {
      this.trap(session, tag, 'not logged in', 4);
      return;
    }
    if (command === '/cancel') {
      const victim = attrs.tag;
      if (victim !== undefined) {
        session.listeners.delete(victim);
        // Exactly what a real router does: trap the victim tag as
        // "interrupted", then close it with !done.
        this.send(session, ['!trap', '=category=2', '=message=interrupted', `.tag=${victim}`]);
        this.send(session, ['!done', `.tag=${victim}`]);
      }
      this.done(session, tag);
      return;
    }
    if (this.opts.unsupportedPaths.includes(command)) {
      this.trap(session, tag, 'no such command prefix', 0);
      return;
    }

    switch (command) {
      case '/system/identity/print':
        this.row(session, tag, { name: this.opts.identity });
        this.done(session, tag);
        return;

      case '/system/resource/print':
        this.row(session, tag, {
          uptime: '1w2d3h',
          version: this.opts.version,
          'board-name': this.opts.boardName,
          platform: 'MikroTik',
          'architecture-name': 'x86_64',
          'cpu-count': '2',
          'total-memory': '1073741824',
        });
        this.done(session, tag);
        return;

      case '/system/routerboard/print':
        if (this.opts.boardName === 'CHR') {
          this.trap(session, tag, 'no such command prefix', 0);
          return;
        }
        this.row(session, tag, { routerboard: 'true', model: this.opts.boardName, 'serial-number': 'HXX0LAB0001' });
        this.done(session, tag);
        return;

      case '/system/health/print':
        if (this.opts.healthShape === 'unsupported') {
          this.trap(session, tag, 'no such command prefix', 0);
        } else if (this.opts.healthShape === 'rows') {
          this.row(session, tag, { '.id': '*1', name: 'temperature', value: '41', type: 'C' });
          this.row(session, tag, { '.id': '*2', name: 'voltage', value: '24.1', type: 'V' });
          this.done(session, tag);
        } else {
          this.row(session, tag, { temperature: '41', voltage: '24.1' });
          this.done(session, tag);
        }
        return;

      case '/interface/wifi/print':
      case '/interface/wireless/print':
        this.row(session, tag, { '.id': '*1' });
        this.done(session, tag);
        return;

      case '/ppp/active/print':
        this.row(session, tag, { '.id': '*1', name: 'site-001', address: '10.66.0.11', service: 'l2tp' });
        this.done(session, tag);
        return;

      case '/ppp/active/listen':
        if (tag === undefined) {
          this.trap(session, tag, 'listen without a tag is unusable');
          return;
        }
        // A `listen` never sends !done on its own. It stays open until /cancel.
        session.listeners.add(tag);
        return;

      // --- test-only helpers ------------------------------------------------
      case '/test/delay': {
        const ms = Number(attrs.ms ?? '0');
        setTimeout(() => {
          this.row(session, tag, { echo: attrs.echo ?? '', ms: String(ms) });
          this.done(session, tag);
        }, ms);
        return;
      }
      case '/test/big': {
        const size = Number(attrs.size ?? '300');
        this.row(session, tag, { data: 'x'.repeat(size) });
        this.done(session, tag);
        return;
      }
      case '/test/never':
        // Deliberate black hole: exercises the per-request timeout + /cancel.
        return;
      case '/test/trap':
        this.trap(session, tag, attrs.message ?? 'input does not match any value of interface', 1);
        return;

      default:
        this.trap(session, tag, 'no such command prefix', 0);
    }
  }

  private handleLogin(session: Session, tag: string | undefined, attrs: Record<string, string>): void {
    if (this.opts.legacyLogin) {
      if (attrs.response === undefined) {
        session.challenge = '0123456789abcdef0123456789abcdef';
        this.done(session, tag, [`=ret=${session.challenge}`]);
        return;
      }
      // The self-test only checks that the client answers the second round
      // trip; the MD5 itself is verified separately.
      if (!/^00[0-9a-f]{32}$/.test(attrs.response)) {
        this.trap(session, tag, 'invalid user name or password (6)', 4);
        return;
      }
      session.authenticated = true;
      this.done(session, tag);
      return;
    }

    if (attrs.name === this.opts.username && attrs.password === this.opts.password) {
      session.authenticated = true;
      this.done(session, tag);
      return;
    }
    this.trap(session, tag, 'invalid user name or password (6)', 4);
  }
}
