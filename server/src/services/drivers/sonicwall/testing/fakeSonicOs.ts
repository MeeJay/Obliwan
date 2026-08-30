// ============================================================================
// ObliWAN — a fake SonicOS REST appliance
// ============================================================================
//
// NO SONICWALL EXISTS. Not in a lab, not on a shelf, not on a customer site we
// may experiment on (§8.3). Every claim this milestone makes about the SonicOS
// write path is a claim about THIS server, which was written from the vendor's
// REST documentation by the same person who wrote the driver — so it can only
// prove that the driver does what its author believed the appliance does. It
// cannot prove the belief.
//
// What it CAN prove, and what the M11 self-test uses it for, is the whole set
// of properties that are about the DRIVER and not about SonicOS:
//
//   - exactly one administrative session is ever open, and it is closed even
//     when the work throws — the leak that makes a firewall unmanageable;
//   - `override: true` really is sent, so a stale web-UI lock is stolen rather
//     than waited on;
//   - a staging failure discards the ENTIRE batch: the appliance ends the
//     operation byte-identical to how it started — and when the appliance
//     REFUSES the discard, the driver says so instead of claiming it;
//   - a rejected commit does the same;
//   - a logout the appliance refuses reaches the report instead of being
//     swallowed by a `.catch(() => false)` nobody read;
//   - a pending configuration left behind by somebody else is never committed
//     as ours, and never destroyed without a trace either;
//   - no password reaches an error message.
//
// The quirk switches exist because those are the behaviours that break drivers:
// a firmware that omits the cookie, one that answers 404 on an empty pending
// config, one that rejects the commit after accepting every write — and, since
// the M11 audit, one that REFUSES A DISCARD and one that REFUSES A LOGOUT.
// Those two had no switch, so the two claims above that matter most — "the
// batch is discarded", "the session is closed" — were only ever exercised on
// the path where the appliance cooperates, and the driver asserted them to the
// change job on the path where it does not.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';

export interface FakeSonicOsOptions {
  username?: string;
  password?: string;
  /** Refuse the login unless `override: true` is present — a stale web session
   *  holds the configuration lock. */
  lockHeldByWebUi?: boolean;
  /** Answer the login without a `Set-Cookie` header (a real firmware quirk). */
  omitCookie?: boolean;
  /** Reject the commit after accepting every staged write. */
  rejectCommit?: boolean;
  /** Reject the staged write whose path ends with this suffix. */
  failStagingPath?: string;
  /** Seed a pending configuration, as a crashed session would leave behind. */
  seedPending?: number;
  /** Answer 404 to `GET config/pending` when nothing is pending. */
  pendingNotFoundWhenEmpty?: boolean;
  /**
   * Answer every `DELETE config/pending` with a 500 and KEEP the batch
   * staged. The state of a loaded appliance, and the one the driver used to
   * describe to the change job as "the appliance is unchanged" — it is not:
   * our half-batch is still on it, waiting for whoever commits next.
   */
  failDiscard?: boolean;
  /**
   * Answer every `DELETE /auth` with a 503 and KEEP the session open. A real
   * firmware does this while it is busy applying a commit. Since this family
   * allows ONE administrative session, a driver that does not notice has
   * locked the customer out of their own firewall.
   */
  failLogout?: boolean;
}

export interface StagedRecord {
  method: string;
  path: string;
  body: unknown;
}

export class FakeSonicOs {
  private server: Server | null = null;
  private cookie: string | null = null;

  /** Every write that has been staged and not yet committed or discarded. */
  pending: StagedRecord[] = [];
  /** Every write that survived a commit. This is "the appliance's config". */
  applied: StagedRecord[] = [];

  logins = 0;
  logouts = 0;
  overrideRequests = 0;
  loginsWithoutOverride = 0;
  commits = 0;
  /** Discards the appliance ACCEPTED. */
  discards = 0;
  /** `DELETE config/pending` calls received, accepted or not. */
  discardAttempts = 0;
  /** `DELETE /auth` calls received, accepted or not. */
  logoutAttempts = 0;
  /** Requests that arrived with no valid session cookie. */
  unauthenticated = 0;

  constructor(private readonly opts: FakeSonicOsOptions = {}) {
    if (opts.seedPending) {
      for (let i = 0; i < opts.seedPending; i += 1) {
        this.pending.push({ method: 'POST', path: '/leftover', body: { from: 'a crashed session' } });
      }
    }
  }

  get sessionOpen(): boolean {
    return this.cookie !== null;
  }

  async listen(): Promise<string> {
    this.server = createServer((req, res) => {
      void this.handle(req, res);
    });
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    const address = this.server!.address() as AddressInfo;
    return `http://127.0.0.1:${address.port}`;
  }

  async close(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = null;
  }

  private send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
    const payload = JSON.stringify(body);
    res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
    res.end(payload);
  }

  private info(message: string): unknown {
    return { status: { success: true, info: [{ level: 'info', code: 'E_OK', message }] } };
  }

  private error(message: string): unknown {
    return { status: { success: false, info: [{ level: 'error', code: 'E_FAIL', message }] } };
  }

  private authenticated(req: IncomingMessage): boolean {
    if (!this.cookie) return false;
    const header = req.headers.cookie ?? '';
    return header.includes(this.cookie);
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = req.url ?? '';
    const path = url.startsWith('/api/sonicos') ? url.slice('/api/sonicos'.length) : url;
    const raw = await readBody(req);
    const body = raw.length > 0 ? safeJson(raw) : null;

    if (path === '/auth') {
      if (req.method === 'POST') return this.handleLogin(req, res, body);
      if (req.method === 'DELETE') {
        this.logoutAttempts += 1;
        if (this.opts.failLogout) {
          return this.send(res, 503, this.error('busy applying a configuration'));
        }
        this.logouts += 1;
        this.cookie = null;
        return this.send(res, 200, this.info('logged out'));
      }
      return this.send(res, 405, this.error('method not allowed'));
    }

    if (!this.authenticated(req)) {
      this.unauthenticated += 1;
      return this.send(res, 401, this.error('no valid administrative session'));
    }

    if (path === '/config/pending') {
      switch (req.method) {
        case 'GET':
          if (this.pending.length === 0 && this.opts.pendingNotFoundWhenEmpty) {
            return this.send(res, 404, this.error('no pending configuration'));
          }
          return this.send(res, 200, { pending: this.pending });
        case 'POST': {
          this.commits += 1;
          if (this.opts.rejectCommit) {
            return this.send(res, 400, this.error('commit rejected: dependency check failed'));
          }
          this.applied.push(...this.pending);
          this.pending = [];
          return this.send(res, 200, this.info('configuration committed'));
        }
        case 'DELETE':
          this.discardAttempts += 1;
          if (this.opts.failDiscard) {
            return this.send(res, 500, this.error('the pending configuration is locked'));
          }
          this.discards += 1;
          this.pending = [];
          return this.send(res, 200, this.info('pending configuration discarded'));
        default:
          return this.send(res, 405, this.error('method not allowed'));
      }
    }

    if (req.method === 'GET') {
      if (path === '/version') {
        return this.send(res, 200, {
          firmware_version: 'SonicOS Enhanced 7.0.1-5030',
          model: 'NSa 2700',
          serial_number: 'FAKE0001SONIC',
          friendly_name: 'fake-sonicwall',
        });
      }
      return this.send(res, 404, this.error(`no such endpoint ${path}`));
    }

    // Any other verb is a configuration write: it STAGES.
    if (this.opts.failStagingPath && path.endsWith(this.opts.failStagingPath)) {
      return this.send(res, 400, this.error(`invalid object for ${path}`));
    }
    this.pending.push({ method: req.method ?? 'POST', path, body });
    return this.send(res, 200, this.info('staged in the pending configuration'));
  }

  private handleLogin(req: IncomingMessage, res: ServerResponse, body: unknown): void {
    const auth = req.headers.authorization ?? '';
    const expectedUser = this.opts.username ?? 'obliwan';
    const expectedPass = this.opts.password ?? 'correct-horse-battery';
    const expected = `Basic ${Buffer.from(`${expectedUser}:${expectedPass}`).toString('base64')}`;
    if (auth !== expected) {
      return this.send(res, 401, this.error('invalid credentials'));
    }

    const override = !!(body && typeof body === 'object' && (body as Record<string, unknown>).override === true);
    if (override) this.overrideRequests += 1;
    else this.loginsWithoutOverride += 1;

    if (this.opts.lockHeldByWebUi && !override) {
      return this.send(res, 403, this.error('the configuration lock is held by another administrator'));
    }

    this.logins += 1;
    this.cookie = `swap=fake-${this.logins}`;
    if (this.opts.omitCookie) {
      return this.send(res, 200, this.info('authenticated'));
    }
    return this.send(
      res,
      200,
      { ...(this.info('authenticated') as Record<string, unknown>), csrfToken: `csrf-${this.logins}` },
      { 'Set-Cookie': `${this.cookie}; Path=/; HttpOnly` },
    );
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(''));
  });
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { raw: text };
  }
}
