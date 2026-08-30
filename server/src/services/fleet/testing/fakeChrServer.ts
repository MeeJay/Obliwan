/**
 * ObliWAN — a fake MikroTik concentrator.
 *
 * There is no CHR on this machine and no L2TP tunnel, so the M2 acceptance test
 * ("three lab sites appear as pending, presence flips in under two seconds when
 * the tunnel drops") cannot be run against hardware. It CAN be run end to end
 * against a server that speaks the real binary protocol, and that is what this
 * is: a TCP server implementing `/login`, `/ppp/secret`, `/ppp/active` and
 * `/ppp/active/listen` with `.tag=` multiplexing and `/cancel`.
 *
 * WHY NOT REUSE `transport/routeros/testing/fakeRouterosServer.ts`
 * That one exists, is good, and proves the wire format — but its `/ppp/active`
 * is a single hard-coded row and it has no `/ppp/secret`, no way to add or drop
 * a session at runtime, and no `.dead` teardown event. Presence needs exactly
 * those. Its file belongs to another workstream and is not edited here.
 *
 * Like that server, this one writes its OWN length prefixes rather than calling
 * `encodeSentence()` from `protocol.ts`, so an encoding bug in the client is not
 * mirrored by the identical bug in the fixture and hidden.
 *
 * Test scaffolding. Never imported by the running server.
 */

import net from 'net';
import { SentenceReader } from '../../transport/routeros/protocol';

export interface FakeSecret {
  name: string;
  service?: string;
  profile?: string;
  remoteAddress?: string;
  comment?: string;
  disabled?: boolean;
}

export interface FakeSession {
  name: string;
  address: string;
  callerId?: string;
  service?: string;
}

export interface FakeChrOptions {
  username?: string;
  password?: string;
  identity?: string;
  version?: string;
  /** A CHR is virtual: `/system/routerboard` traps, so there is no serial. */
  hasRouterboard?: boolean;
  serial?: string;
  secrets?: FakeSecret[];
  sessions?: FakeSession[];
  trace?: boolean;
}

interface Session {
  socket: net.Socket;
  reader: SentenceReader;
  authenticated: boolean;
  listeners: Set<string>;
}

// -- independent length encoder ---------------------------------------------

function encLen(len: number): Buffer {
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

function encSentence(words: string[]): Buffer {
  const parts: Buffer[] = [];
  for (const w of words) {
    const data = Buffer.from(w, 'utf8');
    parts.push(encLen(data.length), data);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

export class FakeChr {
  private readonly server: net.Server;
  private readonly sessions = new Set<Session>();
  private readonly opts: Required<Omit<FakeChrOptions, 'secrets' | 'sessions' | 'serial'>> & {
    serial: string | null;
  };

  /** Declared PPP accounts (`/ppp/secret`). */
  readonly secrets = new Map<string, FakeSecret>();
  /** Live sessions (`/ppp/active`), keyed by username. */
  readonly active = new Map<string, FakeSession & { routerId: string }>();
  /** Every sentence received, for assertions. */
  readonly received: string[][] = [];

  private nextRouterId = 1;

  constructor(options: FakeChrOptions = {}) {
    this.opts = {
      username: options.username ?? 'obliwan',
      password: options.password ?? 'chr-s3cret',
      identity: options.identity ?? 'CHR-CENTRAL',
      version: options.version ?? '7.14.3 (stable)',
      hasRouterboard: options.hasRouterboard ?? false,
      trace: options.trace ?? false,
      serial: options.serial ?? null,
    };
    for (const s of options.secrets ?? []) this.secrets.set(s.name, s);
    for (const s of options.sessions ?? []) this.addSession(s);

    this.server = net.createServer((socket) => this.onConnection(socket));
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

  get connectionCount(): number {
    return this.sessions.size;
  }

  /** How many `/ppp/active/listen` commands are registered right now. Proves
   *  the platform opens ONE, and cancels it on shutdown. */
  get listenerCount(): number {
    let n = 0;
    for (const s of this.sessions) n += s.listeners.size;
    return n;
  }

  // -- fleet manipulation, as a real CHR would experience it -----------------

  /** A site dials in. Pushes the add event to every live `listen`. */
  addSession(session: FakeSession): void {
    const routerId = `*${(this.nextRouterId++).toString(16).toUpperCase()}`;
    const entry = { ...session, routerId };
    this.active.set(session.name, entry);
    this.broadcast({
      '.id': routerId,
      name: session.name,
      service: session.service ?? 'l2tp',
      address: session.address,
      'caller-id': session.callerId ?? '',
      uptime: '00:00:01',
    });
  }

  /**
   * The tunnel drops.
   *
   * The teardown event carries `.id` and `.dead=true` and NOTHING ELSE — which
   * is what a real RouterOS `listen` sends, and the reason the presence monitor
   * has to keep a `.id -> username` map. Sending the name here would make the
   * test easier and the code untested.
   */
  dropSession(name: string, reason?: string): boolean {
    const entry = this.active.get(name);
    if (!entry) return false;
    this.active.delete(name);
    const attrs: Record<string, string> = { '.id': entry.routerId, '.dead': 'true' };
    if (reason) attrs['disconnect-reason'] = reason;
    this.broadcast(attrs);
    return true;
  }

  /** Drop a session WITHOUT telling anyone — the event a `listen` can miss.
   *  Only the 60 s reconciliation can catch this. */
  dropSessionSilently(name: string): boolean {
    return this.active.delete(name);
  }

  /** Add a session without announcing it either. */
  addSessionSilently(session: FakeSession): void {
    const routerId = `*${(this.nextRouterId++).toString(16).toUpperCase()}`;
    this.active.set(session.name, { ...session, routerId });
  }

  private broadcast(attrs: Record<string, string>): number {
    let n = 0;
    for (const s of this.sessions) {
      for (const tag of s.listeners) {
        this.send(s, [
          '!re',
          ...Object.entries(attrs).map(([k, v]) => `=${k}=${v}`),
          `.tag=${tag}`,
        ]);
        n++;
      }
    }
    return n;
  }

  // -- protocol -------------------------------------------------------------

  private onConnection(socket: net.Socket): void {
    const session: Session = {
      socket,
      reader: new SentenceReader(),
      authenticated: false,
      listeners: new Set(),
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
        if (this.opts.trace) console.log('  [chr] <-', words.join(' '));
        this.handle(session, words);
      }
    });
    socket.on('error', () => undefined);
    socket.on('close', () => this.sessions.delete(session));
  }

  private send(session: Session, words: string[]): void {
    if (session.socket.destroyed) return;
    session.socket.write(encSentence(words));
  }

  private tagWords(tag: string | undefined): string[] {
    return tag === undefined ? [] : [`.tag=${tag}`];
  }

  private done(session: Session, tag: string | undefined, attrs: string[] = []): void {
    this.send(session, ['!done', ...attrs, ...this.tagWords(tag)]);
  }

  private trap(session: Session, tag: string | undefined, message: string, category = 2): void {
    this.send(session, ['!trap', `=category=${category}`, `=message=${message}`, ...this.tagWords(tag)]);
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
      if (attrs.name === this.opts.username && attrs.password === this.opts.password) {
        session.authenticated = true;
        this.done(session, tag);
      } else {
        this.trap(session, tag, 'invalid user name or password (6)', 4);
      }
      return;
    }
    if (!session.authenticated) {
      this.trap(session, tag, 'not logged in', 4);
      return;
    }
    if (command === '/quit') {
      this.done(session, tag);
      setTimeout(() => session.socket.destroy(), 5);
      return;
    }
    if (command === '/cancel') {
      const victim = attrs.tag;
      if (victim !== undefined) {
        session.listeners.delete(victim);
        this.send(session, ['!trap', '=category=2', '=message=interrupted', `.tag=${victim}`]);
        this.send(session, ['!done', `.tag=${victim}`]);
      }
      this.done(session, tag);
      return;
    }

    switch (command) {
      case '/system/identity/print':
        this.row(session, tag, { name: this.opts.identity });
        this.done(session, tag);
        return;

      case '/system/resource/print':
        this.row(session, tag, {
          uptime: '3w1d02:03:04',
          version: this.opts.version,
          'board-name': this.opts.hasRouterboard ? 'RB4011' : 'CHR',
          platform: 'MikroTik',
        });
        this.done(session, tag);
        return;

      case '/system/routerboard/print':
        if (!this.opts.hasRouterboard) {
          // A virtual CHR has no RouterBOARD menu. This trap is the normal case
          // and must not read as a failure anywhere upstream (D5: no serial).
          this.trap(session, tag, 'no such command prefix', 0);
          return;
        }
        this.row(session, tag, {
          routerboard: 'true',
          model: 'RB4011',
          'serial-number': this.opts.serial ?? 'LAB0000001',
        });
        this.done(session, tag);
        return;

      case '/interface/l2tp-client/print':
        // The concentrator terminates tunnels, it does not dial one.
        this.done(session, tag);
        return;

      case '/ppp/secret/print':
        for (const s of this.secrets.values()) {
          this.row(session, tag, {
            '.id': `*S${s.name}`,
            name: s.name,
            service: s.service ?? 'l2tp',
            profile: s.profile ?? 'default',
            'remote-address': s.remoteAddress ?? '',
            comment: s.comment ?? '',
            disabled: s.disabled ? 'true' : 'false',
          });
        }
        this.done(session, tag);
        return;

      case '/ppp/active/print':
        for (const s of this.active.values()) {
          this.row(session, tag, {
            '.id': s.routerId,
            name: s.name,
            service: s.service ?? 'l2tp',
            address: s.address,
            'caller-id': s.callerId ?? '',
            uptime: '01:02:03',
          });
        }
        this.done(session, tag);
        return;

      case '/ppp/active/listen':
        if (tag === undefined) {
          this.trap(session, tag, 'listen without a tag is unusable');
          return;
        }
        // A listen never terminates on its own.
        session.listeners.add(tag);
        return;

      default:
        this.trap(session, tag, 'no such command prefix', 0);
    }
  }
}
