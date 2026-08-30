/**
 * ObliWAN — a fake RouterOS that can LOCK YOU OUT AND THEN REPAIR ITSELF.
 *
 * WHY THIS EXISTS ALONGSIDE `transport/routeros/testing/fakeRouterosServer.ts`
 * That one proves the WIRE: length prefixes, `.tag=` multiplexing, `/cancel`,
 * TLS. This one proves the MILESTONE, and the milestone is a behaviour no wire
 * test can express:
 *
 *   apply a rule that blocks new connections
 *     -> EXISTING sockets keep answering (this is the trap §5/M6 warns about)
 *     -> NEW sockets are refused (this is the actual lockout)
 *     -> the on-box scheduler fires anyway, because it is ON THE BOX
 *     -> /system/backup/load restores the snapshot and reboots
 *     -> the router comes back, pre-change, with nobody having intervened.
 *
 * The last step is the one that matters and the one that cannot be faked in a
 * unit test: the timer that repairs the device runs INSIDE this object, and it
 * keeps running while every attempt to reach the object is being refused. That
 * is the property of a dead-man, and this is the only way to observe it without
 * a MikroTik on the desk.
 *
 * IT IS A MODEL, AND THE MODEL'S EDGES ARE DECLARED:
 *  - it does NOT interpret RouterOS scripting. `obliwan-rollback-*` is executed
 *    as a MODELLED EFFECT (restore + reboot). The real script's `:global`
 *    counter, its `:if`, and the exact semantics of `/system/backup/load` are
 *    NOT verified here and are listed as untested.
 *  - the `:do={} on-error={}` wrapper of the APPLY script IS interpreted, line
 *    by line, because that wrapper is the thing under test.
 *  - `/system/backup/save` snapshots configuration + scripts + schedulers. A
 *    real binary backup contains more (users, certificates); nothing here
 *    depends on that difference.
 *
 * It is test scaffolding. It lives in `src/` only so `tsc` type-checks it, and
 * it is never imported by the server at runtime.
 */

import net from 'net';
import http from 'http';
import { SentenceReader } from '../../transport/routeros/protocol';

// ---------------------------------------------------------------------------
// Independent encoder — deliberately not shared with protocol.ts
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------

interface Session {
  socket: net.Socket;
  reader: SentenceReader;
  authenticated: boolean;
}

interface DeviceFileEntry {
  name: string;
  contents: string;
  type: string;
  /** For a `.backup`: the state to restore. */
  snapshot?: Snapshot;
  password?: string;
}

interface ScriptEntry {
  id: string;
  name: string;
  source: string;
  policy: string;
  runCount: number;
}

interface SchedulerEntry {
  id: string;
  name: string;
  startTime: string;
  interval: string;
  intervalSeconds: number;
  onEvent: string;
  disabled: boolean;
  runCount: number;
  timer: NodeJS.Timeout | null;
}

interface Snapshot {
  config: string[];
  scripts: Array<Omit<ScriptEntry, 'id'>>;
  schedulers: Array<Omit<SchedulerEntry, 'id' | 'timer'>>;
  cut: boolean;
  identity: string;
}

export interface FakeDeadmanRouterOptions {
  username?: string;
  password?: string;
  identity?: string;
  serial?: string;
  pppUsername?: string;
  version?: string;
  boardName?: string;
  /** How long the box is unreachable while "rebooting". */
  rebootMs?: number;
  /**
   * `new_connections_only` (default) reproduces `chain=input action=drop` with
   * an established-connection accept above it: the socket we are already on
   * keeps working, new ones are refused. That is the trap the milestone exists
   * to catch. `kill_all` reproduces a rule with no such exception.
   */
  cutMode?: 'new_connections_only' | 'kill_all';
  /** Make `/system/scheduler/remove` fail this many times before working.
   *  Proves the disarm retry. `Infinity` proves the incident path. */
  failSchedulerRemoves?: number;
  /** Make `/tool/fetch` upload a truncated body, to prove the digest check. */
  corruptTransfer?: boolean;
  trace?: boolean;
}

export class FakeDeadmanRouter {
  private readonly server: net.Server;
  private readonly sessions = new Set<Session>();
  private readonly opts: Required<Omit<FakeDeadmanRouterOptions, 'failSchedulerRemoves'>> & {
    failSchedulerRemoves: number;
  };

  private files = new Map<string, DeviceFileEntry>();
  private scripts = new Map<string, ScriptEntry>();
  private schedulers = new Map<string, SchedulerEntry>();
  private globals = new Map<string, string>();
  private config: string[] = [];
  private identity: string;
  private cut = false;
  private rebooting = false;
  private bootedAt = Date.now() - 3600_000;
  private idSeq = 1;
  private schedulerRemoveFailures = 0;

  /** Ordered, timestamped record of everything the box did. This is what lets a
   *  test assert that the dead-man was ARMED BEFORE the apply ran, rather than
   *  merely that both happened. */
  readonly events: Array<{ at: number; what: string }> = [];
  /** Every sentence received, for assertions about what we sent. */
  readonly received: string[][] = [];
  readonly logLines: string[] = [];

  constructor(options: FakeDeadmanRouterOptions = {}) {
    this.opts = {
      username: options.username ?? 'obliwan',
      password: options.password ?? 's3cr3t',
      identity: options.identity ?? 'cpe-lab-01',
      serial: options.serial ?? 'HXX0LAB0001',
      pppUsername: options.pppUsername ?? 'site-001',
      version: options.version ?? '7.14.3 (stable)',
      boardName: options.boardName ?? 'hEX',
      rebootMs: options.rebootMs ?? 1500,
      cutMode: options.cutMode ?? 'new_connections_only',
      corruptTransfer: options.corruptTransfer ?? false,
      trace: options.trace ?? false,
      failSchedulerRemoves: options.failSchedulerRemoves ?? 0,
    };
    this.identity = this.opts.identity;
    // A plausible starting configuration, so an /export is not empty and the
    // canonical comparison has something to compare.
    this.config = [
      '/interface l2tp-client add name=l2tp-mgmt connect-to=203.0.113.9 user=site-001',
      '/ip address add address=10.66.0.11/32 interface=l2tp-mgmt',
      '/ip firewall filter add chain=input action=accept connection-state=established,related',
      '/ip firewall filter add chain=input action=accept src-address=10.255.0.1',
      '/ip firewall filter add chain=forward action=accept',
    ];
    this.server = net.createServer((socket) => this.onConnection(socket));
  }

  // -- lifecycle ------------------------------------------------------------

  listen(port = 0): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(port, '127.0.0.1', () => {
        const addr = this.server.address();
        this.event('listening');
        resolve(typeof addr === 'object' && addr ? addr.port : port);
      });
    });
  }

  async close(): Promise<void> {
    for (const s of this.schedulers.values()) if (s.timer) clearInterval(s.timer);
    this.schedulers.clear();
    for (const s of this.sessions) s.socket.destroy();
    this.sessions.clear();
    await new Promise<void>((res) => this.server.close(() => res()));
  }

  // -- observation surface for tests ---------------------------------------

  get isCut(): boolean {
    return this.cut;
  }
  get isRebooting(): boolean {
    return this.rebooting;
  }
  get connectionCount(): number {
    return this.sessions.size;
  }
  get uptimeSeconds(): number {
    return Math.floor((Date.now() - this.bootedAt) / 1000);
  }
  fileNames(): string[] {
    return [...this.files.keys()].sort();
  }
  scriptNames(): string[] {
    return [...this.scripts.keys()].sort();
  }
  schedulerNames(): string[] {
    return [...this.schedulers.keys()].sort();
  }
  configLines(): string[] {
    return [...this.config];
  }
  eventIndex(predicate: (what: string) => boolean): number {
    return this.events.findIndex((e) => predicate(e.what));
  }
  private event(what: string): void {
    this.events.push({ at: Date.now(), what });
    if (this.opts.trace) console.log(`  [router] ${what}`);
  }

  // -- the box's own behaviour ---------------------------------------------

  private snapshot(): Snapshot {
    return {
      config: [...this.config],
      scripts: [...this.scripts.values()].map((s) => ({
        name: s.name,
        source: s.source,
        policy: s.policy,
        runCount: s.runCount,
      })),
      schedulers: [...this.schedulers.values()].map((s) => ({
        name: s.name,
        startTime: s.startTime,
        interval: s.interval,
        intervalSeconds: s.intervalSeconds,
        onEvent: s.onEvent,
        disabled: s.disabled,
        runCount: s.runCount,
      })),
      cut: this.cut,
      identity: this.identity,
    };
  }

  private restore(snapshot: Snapshot): void {
    this.config = [...snapshot.config];
    for (const s of this.schedulers.values()) if (s.timer) clearInterval(s.timer);
    this.scripts = new Map(
      snapshot.scripts.map((s) => [s.name, { id: `*${this.idSeq++}`, ...s }]),
    );
    this.schedulers = new Map(
      snapshot.schedulers.map((s) => [s.name, { id: `*${this.idSeq++}`, ...s, timer: null }]),
    );
    for (const s of this.schedulers.values()) this.startSchedulerTimer(s);
    this.cut = snapshot.cut;
    this.identity = snapshot.identity;
    this.globals.clear(); // globals do not survive a reboot
  }

  /** Restore + reboot. This is what `/system/backup/load` does, and it is the
   *  reason a fired dead-man erases its own evidence. */
  private loadBackupAndReboot(fileName: string): void {
    const file = this.files.get(fileName);
    if (!file?.snapshot) {
      this.event(`backup-load-FAILED-no-such-file:${fileName}`);
      return;
    }
    this.event(`backup-load:${fileName}`);
    this.restore(file.snapshot);
    this.reboot();
  }

  private reboot(): void {
    this.event('reboot-start');
    this.rebooting = true;
    for (const s of this.sessions) s.socket.destroy();
    this.sessions.clear();
    setTimeout(() => {
      this.bootedAt = Date.now();
      this.rebooting = false;
      this.event('reboot-done');
      // `start-time=startup`: every scheduler with it fires once at boot.
      for (const s of this.schedulers.values()) {
        if (!s.disabled && s.startTime === 'startup') {
          this.event(`scheduler-startup-fire:${s.name}`);
          this.runOnEvent(s);
        }
      }
    }, this.opts.rebootMs).unref?.();
  }

  private startSchedulerTimer(entry: SchedulerEntry): void {
    if (entry.timer) clearInterval(entry.timer);
    if (entry.disabled || entry.intervalSeconds <= 0) return;
    entry.timer = setInterval(() => {
      this.event(`scheduler-interval-fire:${entry.name}`);
      entry.runCount++;
      this.runOnEvent(entry);
    }, entry.intervalSeconds * 1000);
    entry.timer.unref?.();
  }

  private runOnEvent(entry: SchedulerEntry): void {
    const m = /\/system\/script\/run\s+(?:\[[^\]]*name="?([\w.-]+)"?[^\]]*\]|([\w.-]+))/.exec(
      entry.onEvent,
    );
    const name = m?.[1] ?? m?.[2] ?? null;
    if (!name) {
      this.event(`scheduler-onevent-unparsed:${entry.onEvent}`);
      return;
    }
    this.runScript(name);
  }

  /**
   * Execute a script.
   *
   * `obliwan-rollback-*` is a MODELLED EFFECT: this fake does not interpret
   * RouterOS scripting, it performs what that script is designed to perform.
   * Everything else is interpreted line by line, including the `:do={}
   * on-error={}` wrapper, because that wrapper is under test.
   */
  runScript(name: string): void {
    const script = this.scripts.get(name);
    if (!script) {
      this.event(`script-run-MISSING:${name}`);
      return;
    }
    script.runCount++;
    this.event(`script-run:${name}`);

    if (/^obliwan-rollback-/.test(name)) {
      const m = /\/system\/backup\/load\s+name="([^"]+)"/.exec(script.source);
      const file = m?.[1] ?? null;
      // The real script removes its own scheduler on the give-up branch; the
      // restore removes it on the success branch. Modelled as the latter.
      if (file) this.loadBackupAndReboot(file);
      else this.event('rollback-script-had-no-backup-name');
      return;
    }

    this.execBlockStructure(script.source);
  }

  private execBlockStructure(source: string): void {
    const lines = source.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
    const doIndex = lines.findIndex((l) => l.startsWith(':do={'));
    if (doIndex === -1) {
      for (const l of lines) this.execLine(l);
      return;
    }
    const onErrorIndex = lines.findIndex((l) => l.startsWith('} on-error={'));
    const endIndex = lines.length - 1;
    const body = lines.slice(doIndex + 1, onErrorIndex === -1 ? endIndex : onErrorIndex);
    const handler = onErrorIndex === -1 ? [] : lines.slice(onErrorIndex + 1, endIndex);
    for (const l of lines.slice(0, doIndex)) this.execLine(l);
    try {
      for (const l of body) this.execLine(l);
    } catch (err) {
      this.event(`apply-on-error-branch:${err instanceof Error ? err.message : String(err)}`);
      for (const l of handler) this.execLine(l);
    }
  }

  private execLine(raw: string): void {
    const line = raw.replace(/;+$/, '').trim();
    if (line.length === 0) return;

    if (line.startsWith(':log')) {
      this.logLines.push(line);
      return;
    }
    const set = /^:set\s+(\w+)\s+"([^"]*)"$/.exec(line);
    if (set) {
      this.globals.set(set[1], set[2]);
      return;
    }
    const glob = /^:global\s+(\w+)(?:\s+"([^"]*)")?$/.exec(line);
    if (glob) {
      this.globals.set(glob[1], glob[2] ?? '');
      return;
    }
    const runOther = /^\/system\/script\/run\s+(?:\[[^\]]*name="([\w.-]+)"[^\]]*\]|([\w.-]+))$/.exec(
      line,
    );
    if (runOther) {
      this.runScript(runOther[1] ?? runOther[2]);
      return;
    }
    if (/^\/system\/backup\/load/.test(line)) {
      const m = /name="?([^"\s]+)"?/.exec(line);
      if (m) this.loadBackupAndReboot(m[1]);
      return;
    }
    // The poison pill the tests use to make a line fail on the router.
    if (line.includes('/obliwan/test/fail')) {
      throw new Error('the device refused this line');
    }
    if (/^\/system\/identity\/set/.test(line)) {
      const m = /name=([^\s]+)/.exec(line);
      if (m) this.identity = m[1];
      this.config.push(line);
      return;
    }
    if (/^\/ip[\s/]/.test(line) || /^\/interface[\s/]/.test(line)) {
      this.config.push(line);
      // THE CUT. `chain=input action=drop` with nothing letting our source
      // through is what takes the site off the air.
      if (/chain=input/.test(line) && /action=drop/.test(line)) {
        this.cut = true;
        this.event('CUT: chain=input action=drop is now in force');
      }
      return;
    }
    this.config.push(line);
  }

  /** Deterministic textual view of the configuration, as `/export` renders it. */
  private exportText(): string {
    const parts: string[] = [
      `# ${new Date().toISOString()} by RouterOS ${this.opts.version}`,
      `/system identity set name=${this.identity}`,
      ...this.config,
      ...[...this.scripts.values()]
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((s) => `/system script add name=${s.name} source="<${s.source.length} chars>"`),
      ...[...this.schedulers.values()]
        .sort((a, b) => a.name.localeCompare(b.name))
        .map(
          (s) =>
            `/system scheduler add name=${s.name} start-time=${s.startTime} interval=${s.interval}`,
        ),
    ];
    return `${parts.join('\n')}\n`;
  }

  // -- wire -----------------------------------------------------------------

  private onConnection(socket: net.Socket): void {
    // THE LOCKOUT. A `chain=input action=drop` that sits below an
    // established/related accept lets the socket we are already on carry on and
    // refuses every new one. That asymmetry is the whole reason §5/M6 demands a
    // reconnection on a NEW socket.
    if (this.rebooting || this.cut) {
      this.event(`refused-new-connection (${this.rebooting ? 'rebooting' : 'cut'})`);
      socket.destroy();
      return;
    }
    const session: Session = { socket, reader: new SentenceReader(), authenticated: false };
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
        this.handle(session, words);
      }
    });
    socket.on('error', () => undefined);
    socket.on('close', () => this.sessions.delete(session));
  }

  private send(s: Session, words: string[]): void {
    if (!s.socket.destroyed) s.socket.write(encSentence(words));
  }
  private tagOf(tag: string | undefined): string[] {
    return tag === undefined ? [] : [`.tag=${tag}`];
  }
  private done(s: Session, tag: string | undefined, attrs: string[] = []): void {
    this.send(s, ['!done', ...attrs, ...this.tagOf(tag)]);
  }
  private trap(s: Session, tag: string | undefined, message: string, category = 2): void {
    this.send(s, ['!trap', `=category=${category}`, `=message=${message}`, ...this.tagOf(tag)]);
    this.done(s, tag);
  }
  private row(s: Session, tag: string | undefined, attrs: Record<string, string>): void {
    this.send(s, [
      '!re',
      ...Object.entries(attrs).map(([k, v]) => `=${k}=${v}`),
      ...this.tagOf(tag),
    ]);
  }

  private handle(session: Session, words: string[]): void {
    const command = words[0] ?? '';
    const attrs: Record<string, string> = {};
    const queries: Record<string, string> = {};
    let tag: string | undefined;
    for (const w of words.slice(1)) {
      if (w.startsWith('=')) {
        const rest = w.slice(1);
        const i = rest.indexOf('=');
        attrs[i === -1 ? rest : rest.slice(0, i)] = i === -1 ? '' : rest.slice(i + 1);
      } else if (w.startsWith('?')) {
        const rest = w.slice(1);
        const i = rest.indexOf('=');
        queries[i === -1 ? rest : rest.slice(0, i)] = i === -1 ? '' : rest.slice(i + 1);
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
      this.done(session, tag);
      return;
    }

    switch (command) {
      case '/system/identity/print':
        this.row(session, tag, { name: this.identity });
        return this.done(session, tag);

      case '/system/resource/print':
        this.row(session, tag, {
          uptime: `${this.uptimeSeconds}s`,
          version: this.opts.version,
          'board-name': this.opts.boardName,
          platform: 'MikroTik',
        });
        return this.done(session, tag);

      case '/system/routerboard/print':
        this.row(session, tag, {
          routerboard: 'true',
          model: this.opts.boardName,
          'serial-number': this.opts.serial,
        });
        return this.done(session, tag);

      case '/interface/l2tp-client/print':
        this.row(session, tag, { name: 'l2tp-mgmt', user: this.opts.pppUsername });
        return this.done(session, tag);

      case '/file/print': {
        for (const f of this.files.values()) {
          if (queries.name !== undefined && f.name !== queries.name) continue;
          this.row(session, tag, {
            '.id': `*f${f.name.length}`,
            name: f.name,
            size: String(Buffer.byteLength(f.contents, 'utf8')),
            type: f.type,
          });
        }
        return this.done(session, tag);
      }

      case '/file/remove': {
        const key = attrs.numbers ?? '';
        const byName = this.files.has(key)
          ? key
          : [...this.files.values()].find((f) => `*f${f.name.length}` === key)?.name;
        if (!byName) return this.trap(session, tag, 'no such item', 1);
        this.files.delete(byName);
        this.event(`file-remove:${byName}`);
        return this.done(session, tag);
      }

      case '/system/backup/save': {
        const name = `${attrs.name}.backup`;
        // A binary backup is opaque; the fake stores an opaque-looking body of
        // realistic size PLUS the snapshot it can restore.
        this.files.set(name, {
          name,
          type: 'backup',
          contents: `OBLIWAN-FAKE-BACKUP:${name}:${'x'.repeat(4096)}`,
          snapshot: this.snapshot(),
          password: attrs.password,
        });
        this.event(`backup-save:${name}`);
        return this.done(session, tag);
      }

      case '/system/backup/load': {
        this.done(session, tag);
        setTimeout(() => this.loadBackupAndReboot(`${attrs.name}`), 10).unref?.();
        return;
      }

      case '/export': {
        if (attrs['show-sensitive'] !== 'no') {
          // R10: refuse anything else, loudly, so a regression is a test
          // failure and not a silent disclosure.
          return this.trap(session, tag, 'obliwan-fake: refusing an export without show-sensitive=no');
        }
        const name = `${attrs.file}.rsc`;
        this.files.set(name, { name, type: 'script', contents: this.exportText() });
        this.event(`export:${name}`);
        return this.done(session, tag);
      }

      case '/tool/fetch': {
        const src = attrs['src-path'] ?? '';
        const file = this.files.get(src);
        if (!file) return this.trap(session, tag, 'no such file');
        const body = this.opts.corruptTransfer
          ? file.contents.slice(0, Math.floor(file.contents.length / 2))
          : file.contents;
        this.uploadTo(attrs.url ?? '', body)
          .then(() => {
            this.row(session, tag, { status: 'finished', downloaded: String(body.length) });
            this.done(session, tag);
          })
          .catch((err) => {
            this.trap(session, tag, `fetch failed: ${err.message}`);
          });
        return;
      }

      case '/system/script/print': {
        for (const s of this.scripts.values()) {
          if (queries.name !== undefined && s.name !== queries.name) continue;
          this.row(session, tag, {
            '.id': s.id,
            name: s.name,
            policy: s.policy,
            source: s.source,
            'run-count': String(s.runCount),
          });
        }
        return this.done(session, tag);
      }

      case '/system/script/add': {
        if (this.scripts.has(attrs.name)) {
          return this.trap(session, tag, 'failure: already have script with such name');
        }
        this.scripts.set(attrs.name, {
          id: `*${this.idSeq++}`,
          name: attrs.name,
          source: attrs.source ?? '',
          policy: attrs.policy ?? '',
          runCount: 0,
        });
        this.event(`script-add:${attrs.name}`);
        return this.done(session, tag);
      }

      case '/system/script/remove': {
        const key = attrs.numbers ?? '';
        const name = this.scripts.has(key)
          ? key
          : [...this.scripts.values()].find((s) => s.id === key)?.name;
        if (!name) return this.trap(session, tag, 'no such item', 1);
        this.scripts.delete(name);
        this.event(`script-remove:${name}`);
        return this.done(session, tag);
      }

      case '/system/script/run': {
        const key = attrs.number ?? attrs.numbers ?? '';
        const name = this.scripts.has(key)
          ? key
          : [...this.scripts.values()].find((s) => s.id === key)?.name;
        if (!name) return this.trap(session, tag, 'no such item', 1);
        // Answer FIRST, then run. A real router does the same when the script
        // reboots it: the !done is already on the wire.
        this.done(session, tag);
        setTimeout(() => this.runScript(name), 5).unref?.();
        return;
      }

      case '/system/script/environment/print': {
        for (const [name, value] of this.globals) {
          if (queries.name !== undefined && name !== queries.name) continue;
          this.row(session, tag, { name, value });
        }
        return this.done(session, tag);
      }

      case '/system/scheduler/print': {
        for (const s of this.schedulers.values()) {
          if (queries.name !== undefined && s.name !== queries.name) continue;
          this.row(session, tag, {
            '.id': s.id,
            name: s.name,
            'start-time': s.startTime,
            interval: s.interval,
            'on-event': s.onEvent,
            disabled: String(s.disabled),
            'run-count': String(s.runCount),
          });
        }
        return this.done(session, tag);
      }

      case '/system/scheduler/add': {
        if (this.schedulers.has(attrs.name)) {
          return this.trap(session, tag, 'failure: already have scheduler with such name');
        }
        const seconds = parseClock(attrs.interval ?? '');
        const entry: SchedulerEntry = {
          id: `*${this.idSeq++}`,
          name: attrs.name,
          startTime: attrs['start-time'] ?? '',
          interval: attrs.interval ?? '',
          intervalSeconds: seconds,
          onEvent: attrs['on-event'] ?? '',
          disabled: attrs.disabled === 'yes' || attrs.disabled === 'true',
          runCount: 0,
          timer: null,
        };
        this.schedulers.set(entry.name, entry);
        this.startSchedulerTimer(entry);
        this.event(`scheduler-add:${entry.name} start-time=${entry.startTime} interval=${entry.interval}`);
        return this.done(session, tag);
      }

      case '/system/scheduler/set': {
        const key = attrs.numbers ?? '';
        const entry =
          this.schedulers.get(key) ?? [...this.schedulers.values()].find((s) => s.id === key);
        if (!entry) return this.trap(session, tag, 'no such item', 1);
        if (attrs.disabled !== undefined) entry.disabled = attrs.disabled === 'yes';
        if (attrs.interval !== undefined) {
          entry.interval = attrs.interval;
          entry.intervalSeconds = parseClock(attrs.interval);
        }
        this.startSchedulerTimer(entry);
        return this.done(session, tag);
      }

      case '/system/scheduler/remove': {
        if (this.schedulerRemoveFailures < this.opts.failSchedulerRemoves) {
          this.schedulerRemoveFailures++;
          this.event(`scheduler-remove-REFUSED (#${this.schedulerRemoveFailures})`);
          return this.trap(session, tag, 'obliwan-fake: scheduler removal refused');
        }
        const key = attrs.numbers ?? '';
        const name = this.schedulers.has(key)
          ? key
          : [...this.schedulers.values()].find((s) => s.id === key)?.name;
        if (!name) return this.trap(session, tag, 'no such item', 1);
        const entry = this.schedulers.get(name);
        if (entry?.timer) clearInterval(entry.timer);
        this.schedulers.delete(name);
        this.event(`scheduler-remove:${name}`);
        return this.done(session, tag);
      }

      default:
        return this.trap(session, tag, 'no such command prefix', 0);
    }
  }

  /** The router dialling US — `/tool/fetch upload=yes`. A real HTTP POST. */
  private uploadTo(url: string, body: string): Promise<void> {
    return new Promise((resolve, reject) => {
      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch (err) {
        return reject(err as Error);
      }
      const req = http.request(
        {
          hostname: parsed.hostname,
          port: parsed.port,
          path: `${parsed.pathname}${parsed.search}`,
          method: 'POST',
          headers: { 'content-length': Buffer.byteLength(body, 'utf8') },
        },
        (res) => {
          res.resume();
          res.on('end', () =>
            res.statusCode && res.statusCode < 300
              ? resolve()
              : reject(new Error(`HTTP ${res.statusCode}`)),
          );
        },
      );
      req.on('error', reject);
      req.end(Buffer.from(body, 'utf8'));
    });
  }
}

function parseClock(raw: string): number {
  const m = /^(\d+):(\d{1,2}):(\d{1,2})$/.exec(raw.trim());
  if (m) return Number(m[1]) * 3600 + Number(m[2]) * 60 + Number(m[3]);
  const n = Number(raw);
  return Number.isFinite(n) ? n : 0;
}
