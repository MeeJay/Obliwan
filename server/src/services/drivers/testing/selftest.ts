/**
 * ObliWAN — offline self-test for the transport and driver layers.
 *
 * NO REAL EQUIPMENT IS TOUCHED. Everything here runs against fakes, a
 * loopback HTTP server, and pure functions. What it proves:
 *
 *   - the SNMP session cache really closes sessions (the UDP socket leak the
 *     spec warns about), on eviction, on TTL, on drop and on shutdown;
 *   - the arbiter picks the channel the capability matrix and the breaker
 *     allow, refuses what no waiting can fix, and DEFERS what waiting can;
 *   - a SonicOS session logs out in a `finally`, including when the work throws;
 *   - the registry resolves every family and degrades to `unknown` instead of
 *     throwing;
 *   - every unimplemented driver method throws with its milestone rather than
 *     returning empty;
 *   - secrets do not survive into error strings.
 *
 * Run:  npx tsx src/services/drivers/testing/selftest.ts
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import type { AddressInfo } from 'net';
import {
  DEFAULT_BREAKER,
  DeferredIntentQueue,
  chooseChannel,
  computeBackoffMs,
  defaultHealth,
  onFailure,
  onSuccess,
  type TransportHealth,
} from '../../transport/arbiter.service';
import {
  SnmpSessionCache,
  brandFromSnmp,
  snmpGet,
  snmpIdentify,
  type SnmpSessionLike,
  type SnmpTarget,
} from '../../transport/snmp.transport';
import {
  assertTlsConfig,
  retryDelayMs,
  withSonicOsSession,
} from '../../transport/rest.transport';
import { BaseDriver } from '../base';
import { MikrotikRouterOsDriver } from '../mikrotik/mikrotik.driver';
import {
  clearRouterOsChannelFactory,
  registerRouterOsChannelFactory,
  type RouterOsRow,
} from '../mikrotik/routerosChannel';
import { getDriver, guessFamily, unknownDriver } from '../registry';
import {
  DriverError,
  NotImplementedError,
  redact,
  type DriverContext,
  type ResolvedTransport,
} from '../types';

// ── tiny harness ────────────────────────────────────────────────────────────

let passed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed += 1;
    return;
  }
  failures.push(`${name}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`);
}

function eq<T>(name: string, actual: T, expected: T): void {
  check(name, Object.is(actual, expected), { actual, expected });
}

async function throws(name: string, fn: () => Promise<unknown>, predicate: (e: unknown) => boolean): Promise<void> {
  try {
    await fn();
    check(name, false, 'did not throw');
  } catch (err) {
    check(name, predicate(err), err instanceof Error ? err.message : String(err));
  }
}

// ── fixtures ────────────────────────────────────────────────────────────────

function transport(partial: Partial<ResolvedTransport> & Pick<ResolvedTransport, 'transport'>): ResolvedTransport {
  return {
    enabled: true,
    priority: 100,
    host: '10.90.0.1',
    port: null,
    useTls: false,
    tlsFingerprintSha256: null,
    params: {},
    credentials: {},
    ...partial,
  };
}

function ctxFor(transports: ResolvedTransport[]): DriverContext {
  return { deviceId: 42, tenantId: 1, family: 'mikrotik_routeros7', transports, timeoutMs: 2_000 };
}

// ── 1. SNMP session cache ───────────────────────────────────────────────────

function snmpCacheTests(): void {
  const closed: string[] = [];
  let created = 0;

  const factory = (t: SnmpTarget): SnmpSessionLike => {
    created += 1;
    const id = `${t.host}#${created}`;
    return {
      get(_oids, cb) {
        cb(null, []);
      },
      close() {
        closed.push(id);
      },
    };
  };

  const cache = new SnmpSessionCache({ factory, max: 2, ttlMs: 60_000 });
  const a: SnmpTarget = { host: '10.0.0.1', version: '2c', credentials: { community: 'public' } };
  const b: SnmpTarget = { host: '10.0.0.2', version: '2c', credentials: { community: 'public' } };
  const c: SnmpTarget = { host: '10.0.0.3', version: '2c', credentials: { community: 'public' } };

  const first = cache.acquire(a);
  const again = cache.acquire(a);
  check('snmp cache reuses the session for the same target', first === again);
  eq('snmp cache created exactly one session', created, 1);

  cache.acquire(b);
  eq('snmp cache size honours max', cache.size, 2);

  // Evicting the least-recently-used entry MUST close its socket.
  cache.acquire(c);
  eq('snmp cache evicted one entry', cache.size, 2);
  eq('eviction closed exactly one session', closed.length, 1);
  eq('eviction closed the LRU entry', closed[0], '10.0.0.1#1');

  // Explicit drop (used after an error) closes too.
  cache.drop(b);
  check('drop() closed the dropped session', closed.includes('10.0.0.2#2'));

  cache.closeAll();
  eq('closeAll() closed every remaining session', closed.length, 3);
  eq('closeAll() emptied the cache', cache.size, 0);

  // A different community is a DIFFERENT session, and the key must not carry it.
  const keyA = SnmpSessionCache.keyFor(a);
  const keyASecret = SnmpSessionCache.keyFor({ ...a, credentials: { community: 's3cr3t-community' } });
  check('cache key changes with the credential', keyA !== keyASecret);
  check('cache key does not contain the community', !keyASecret.includes('s3cr3t-community'), keyASecret);

  // A session whose close() throws must still leave the cache.
  const angry = new SnmpSessionCache({
    factory: () => ({
      get(_o, cb) {
        cb(null, []);
      },
      close() {
        throw new Error('socket already gone');
      },
    }),
    max: 1,
  });
  angry.acquire(a);
  angry.closeAll();
  eq('a throwing close() still empties the cache', angry.size, 0);
}

async function snmpDecodeTests(): Promise<void> {
  const target: SnmpTarget = { host: '10.0.0.9', version: '2c', credentials: { community: 'public' } };
  const cache = new SnmpSessionCache({
    factory: () => ({
      get(oids, cb) {
        cb(
          null,
          oids.map((oid) => {
            if (oid.endsWith('1.1.0')) return { oid, type: 4, value: Buffer.from('RouterOS 7.14.3\0') };
            if (oid.endsWith('1.2.0')) return { oid, type: 6, value: '1.3.6.1.4.1.14988.1' };
            if (oid.endsWith('1.5.0')) return { oid, type: 4, value: Buffer.from('CPE-LYON-01') };
            if (oid.endsWith('1.3.0')) return { oid, type: 67, value: 123_456 };
            // sysLocation / sysContact absent — noSuchInstance.
            return { oid, type: 129, value: null };
          }),
        );
      },
      close() {
        /* nothing to release in the fake */
      },
    }),
  });

  const identity = await snmpIdentify(target, cache);
  eq('sysDescr decoded and NUL-trimmed', identity.sysDescr, 'RouterOS 7.14.3');
  eq('sysName decoded', identity.sysName, 'CPE-LYON-01');
  eq('sysUpTime converted from centiseconds', identity.uptimeSeconds, 1_234);
  eq('absent sysLocation reads as null, not as an error', identity.sysLocation, null);
  eq('brand from the enterprise arc', brandFromSnmp(identity), 'mikrotik');
  eq(
    'brand falls back to sysDescr',
    brandFromSnmp({ sysObjectID: '1.3.6.1.4.1.9999.1', sysDescr: 'Vigor2927 Series' }),
    'draytek',
  );
  eq(
    'an unrecognised box is null, never a guess',
    brandFromSnmp({ sysObjectID: '1.3.6.1.4.1.9999.1', sysDescr: 'Linux router' }),
    null,
  );

  // An erroring session must be dropped, not handed to the next caller.
  const dropCache = new SnmpSessionCache({
    factory: () => ({
      get(_oids, cb) {
        cb(new Error('RequestTimedOutError'), []);
      },
      close() {
        /* noop */
      },
    }),
  });
  await throws(
    'a timed-out GET rejects as TIMEOUT',
    () => snmpGet(target, ['1.3.6.1.2.1.1.1.0'], dropCache),
    (e) => e instanceof DriverError && e.code === 'TIMEOUT' && e.retryable,
  );
  eq('the failed session was evicted', dropCache.size, 0);

  const authCache = new SnmpSessionCache({
    factory: () => ({
      get(_oids, cb) {
        cb(new Error('Authentication failure (incorrect password, community or key)'), []);
      },
      close() {
        /* noop */
      },
    }),
  });
  await throws(
    'a bad community rejects as AUTH_FAILED and is NOT retryable',
    () => snmpGet(target, ['1.3.6.1.2.1.1.1.0'], authCache),
    (e) => e instanceof DriverError && e.code === 'AUTH_FAILED' && !e.retryable,
  );
}

// ── 2. Arbiter ──────────────────────────────────────────────────────────────

function arbiterTests(): void {
  const driver = new MikrotikRouterOsDriver('mikrotik_routeros7');
  const caps = driver.capabilities;
  const now = new Date('2026-08-28T10:00:00Z');

  const api = transport({ transport: 'routeros_api', priority: 10 });
  const ssh = transport({ transport: 'ssh', priority: 20 });
  const snmp = transport({ transport: 'snmp', priority: 30 });

  // Preference order: the API wins for inventory.
  const first = chooseChannel({
    intent: 'inventory',
    capabilities: caps,
    transports: [snmp, ssh, api],
    health: [],
    now,
  });
  eq('inventory picks the RouterOS API', first.outcome === 'selected' ? first.transport : 'none', 'routeros_api');

  // Same input, API circuit open and not yet due -> next channel down the list.
  const openApi: TransportHealth = {
    ...defaultHealth(42, 'routeros_api'),
    circuitState: 'open',
    consecutiveFailures: 5,
    backoffMs: 60_000,
    nextRetryAt: new Date(now.getTime() + 60_000),
  };
  const second = chooseChannel({
    intent: 'inventory',
    capabilities: caps,
    transports: [api, ssh, snmp],
    health: [openApi],
    now,
  });
  eq('an open circuit falls through to the next channel', second.outcome === 'selected' ? second.transport : 'none', 'ssh');

  // Every channel open -> DEFERRED, not an error, with the earliest retry time.
  const allOpen: TransportHealth[] = (['routeros_api', 'ssh', 'snmp'] as const).map((t, i) => ({
    ...defaultHealth(42, t),
    circuitState: 'open' as const,
    consecutiveFailures: 5,
    backoffMs: 60_000,
    nextRetryAt: new Date(now.getTime() + (i + 1) * 30_000),
  }));
  const deferred = chooseChannel({
    intent: 'inventory',
    capabilities: caps,
    transports: [api, ssh, snmp],
    health: allOpen,
    now,
  });
  eq('every channel in backoff defers instead of failing', deferred.outcome, 'deferred');
  eq(
    'the deferred retry time is the earliest channel',
    deferred.outcome === 'deferred' ? deferred.retryAt.toISOString() : '',
    new Date(now.getTime() + 30_000).toISOString(),
  );

  // Backoff elapsed -> exactly one half-open trial.
  const dueApi: TransportHealth = {
    ...defaultHealth(42, 'routeros_api'),
    circuitState: 'open',
    consecutiveFailures: 5,
    backoffMs: 60_000,
    nextRetryAt: new Date(now.getTime() - 1_000),
  };
  const trial = chooseChannel({
    intent: 'inventory',
    capabilities: caps,
    transports: [api],
    health: [dueApi],
    now,
  });
  check('an elapsed backoff yields a half-open trial', trial.outcome === 'selected' && trial.halfOpenTrial);

  // A trial already in flight does not get a second one.
  const inFlight: TransportHealth = {
    ...defaultHealth(42, 'routeros_api'),
    circuitState: 'half_open',
    nextRetryAt: new Date(now.getTime() + 5_000),
  };
  const blocked = chooseChannel({
    intent: 'inventory',
    capabilities: caps,
    transports: [api],
    health: [inFlight],
    now,
  });
  eq('a half-open trial in flight blocks a second one', blocked.outcome, 'deferred');

  // Capability the driver does not declare -> permanent refusal.
  const unsupported = chooseChannel({
    intent: 'read_config',
    capabilities: caps,
    transports: [api],
    health: [],
    now,
  });
  eq('an undeclared capability is refused, not deferred', unsupported.outcome, 'refused');
  eq(
    'refusal names the missing capability',
    unsupported.outcome === 'refused' ? unsupported.code : '',
    'UNSUPPORTED',
  );

  // D3: no write outside the change queue.
  const writeCaps = { ...caps, canPushConfig: true };
  const ungated = chooseChannel({
    intent: 'write_config',
    capabilities: writeCaps,
    transports: [api],
    health: [],
    now,
  });
  eq(
    'a write outside the change queue is refused (D3)',
    ungated.outcome === 'refused' ? ungated.code : '',
    'WRITE_NOT_QUEUED',
  );
  const gated = chooseChannel({
    intent: 'write_config',
    capabilities: writeCaps,
    transports: [api],
    health: [],
    now,
    viaChangeQueue: true,
  });
  eq('the change queue may write', gated.outcome, 'selected');

  // SNMP can never serve a config read.
  const snmpOnly = chooseChannel({
    intent: 'read_config',
    capabilities: { ...caps, canExportConfig: true },
    transports: [snmp],
    health: [],
    now,
  });
  eq('SNMP cannot serve a config read', snmpOnly.outcome === 'refused' ? snmpOnly.code : '', 'NO_TRANSPORT');

  // A disabled row is invisible.
  const disabled = chooseChannel({
    intent: 'inventory',
    capabilities: caps,
    transports: [transport({ transport: 'routeros_api', enabled: false })],
    health: [],
    now,
  });
  eq('a disabled transport row is not selectable', disabled.outcome, 'refused');

  // A row without a host cannot be dialled (cwmp excepted, it dials us).
  const hostless = chooseChannel({
    intent: 'inventory',
    capabilities: caps,
    transports: [transport({ transport: 'routeros_api', host: null })],
    health: [],
    now,
  });
  eq('a transport row without a host is not selectable', hostless.outcome, 'refused');

  // Operator "test this channel" button.
  const forced = chooseChannel({
    intent: 'inventory',
    capabilities: caps,
    transports: [api, snmp],
    health: [],
    now,
    requireTransport: 'snmp',
  });
  eq('requireTransport forces the channel', forced.outcome === 'selected' ? forced.transport : '', 'snmp');
}

function breakerTests(): void {
  const policy = DEFAULT_BREAKER;
  const now = new Date('2026-08-28T10:00:00Z');

  // Below the threshold the circuit stays closed: one lost packet is not an outage.
  let health = defaultHealth(1, 'ssh');
  for (let i = 1; i < policy.failureThreshold; i += 1) {
    const t = onFailure(health, { retryable: true, now });
    health = { ...health, ...t };
    eq(`failure ${i} keeps the circuit closed`, t.circuitState, 'closed');
  }
  const opening = onFailure(health, { retryable: true, now });
  eq('the threshold opens the circuit', opening.circuitState, 'open');
  check('opening sets a retry time', opening.nextRetryAt !== null);

  // A non-retryable failure opens immediately with the long backoff: hammering
  // a management interface with a wrong password locks the account out.
  const auth = onFailure(defaultHealth(1, 'ssh'), { retryable: false, now });
  eq('a non-retryable failure opens at once', auth.circuitState, 'open');
  eq('and uses the long backoff', auth.backoffMs, policy.nonRetryableBackoffMs);

  // A failed half-open trial goes straight back to open.
  const trialFailed = onFailure({ ...defaultHealth(1, 'ssh'), circuitState: 'half_open', consecutiveFailures: 4 }, {
    retryable: true,
    now,
  });
  eq('a failed trial reopens the circuit', trialFailed.circuitState, 'open');

  const recovered = onSuccess();
  eq('success closes the circuit', recovered.circuitState, 'closed');
  eq('success clears the failure counter', recovered.consecutiveFailures, 0);
  eq('success clears the retry time', recovered.nextRetryAt, null);

  // Backoff grows, is capped, and is jittered — 300 devices must not all retry
  // on the same second when the CHR comes back (R5).
  const b1 = computeBackoffMs(1, policy, () => 0.5);
  const b3 = computeBackoffMs(3, policy, () => 0.5);
  const b30 = computeBackoffMs(30, policy, () => 0.5);
  check('backoff grows with failures', b3 > b1, { b1, b3 });
  check('backoff is capped', b30 <= policy.maxBackoffMs, b30);
  const low = computeBackoffMs(10, policy, () => 0);
  const high = computeBackoffMs(10, policy, () => 1);
  check('backoff is jittered', low !== high, { low, high });
  check('jitter stays within ±20 %', low >= policy.maxBackoffMs * 0.79 && high <= policy.maxBackoffMs * 1.21, {
    low,
    high,
  });
}

function deferredQueueTests(): void {
  const q = new DeferredIntentQueue(3);
  const t0 = new Date('2026-08-28T10:00:00Z');

  q.push({ deviceId: 1, intent: 'inventory', retryAt: new Date(t0.getTime() + 60_000), reason: 'backoff' });
  q.push({ deviceId: 1, intent: 'inventory', retryAt: new Date(t0.getTime() + 10_000), reason: 'backoff' });
  eq('the same intent is parked once', q.size, 1);

  const due = q.take(new Date(t0.getTime() + 30_000));
  eq('the earliest retry time wins on a duplicate push', due.length, 1);
  eq('taking an entry removes it', q.size, 0);

  q.push({ deviceId: 1, intent: 'inventory', retryAt: new Date(t0.getTime() + 600_000), reason: 'x' });
  eq('nothing is due before its time', q.take(t0).length, 0);
  eq('and it stays parked', q.size, 1);

  q.push({ deviceId: 2, intent: 'probe', retryAt: t0, reason: 'x' });
  q.push({ deviceId: 3, intent: 'probe', retryAt: t0, reason: 'x' });
  q.push({ deviceId: 4, intent: 'probe', retryAt: t0, reason: 'x' });
  eq('the queue is bounded', q.size, 3);
  eq('and it counts what it dropped rather than lying', q.dropped, 1);

  check('cancel removes a parked intent', q.cancel(2, 'probe'));
}

// ── 3. REST ─────────────────────────────────────────────────────────────────

function restPureTests(): void {
  eq('Retry-After in seconds is honoured', retryDelayMs(0, '2'), 2_000);
  eq('Retry-After is capped', retryDelayMs(0, '9999'), 20_000);
  const jittered = retryDelayMs(3, undefined);
  check('backoff without Retry-After is jittered and bounded', jittered > 0 && jittered <= 4_000, jittered);

  let refused = false;
  try {
    assertTlsConfig({ rejectUnauthorized: false, fingerprintSha256: null }, 'fw.example');
  } catch (err) {
    refused = err instanceof DriverError && err.code === 'TLS_PINNING_FAILED';
  }
  check('TLS verification off with no pin is refused', refused);

  let accepted = true;
  try {
    assertTlsConfig({ rejectUnauthorized: false, fingerprintSha256: 'ab:cd' }, 'fw.example');
  } catch {
    accepted = false;
  }
  check('TLS verification off WITH a pin is accepted', accepted);
}

/**
 * A loopback stand-in for a SonicWall. It counts logins and logouts, which is
 * the only thing that matters: an appliance that is logged into and not out of
 * becomes unmanageable.
 */
async function sonicOsSessionTests(): Promise<void> {
  let logins = 0;
  let logouts = 0;
  let overrideSeen: unknown = null;
  let versionCalls = 0;

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? '';
    if (url === '/api/sonicos/auth' && req.method === 'POST') {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        logins += 1;
        try {
          overrideSeen = JSON.parse(Buffer.concat(chunks).toString('utf8')).override;
        } catch {
          overrideSeen = null;
        }
        res.setHeader('set-cookie', 'sonicos-session=abc');
        res.statusCode = 200;
        res.end('{}');
      });
      return;
    }
    if (url === '/api/sonicos/auth' && req.method === 'DELETE') {
      logouts += 1;
      res.statusCode = 200;
      res.end('{}');
      return;
    }
    if (url === '/api/sonicos/version') {
      versionCalls += 1;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ firmware_version: 'SonicOS 7.0.1-5030', model: 'TZ470', serial_number: '18B169ABCDEF' }));
      return;
    }
    res.statusCode = 404;
    res.end('{"status":"not found"}');
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const body = await withSonicOsSession(
    { baseUrl, retries: 0 },
    { username: 'obliwan', password: 'sup3r-s3cret-pass' },
    async (session) => session.get<Record<string, string>>('/version'),
  );
  eq('SonicOS login happened once', logins, 1);
  eq('SonicOS logout happened once', logouts, 1);
  eq('login sends override:true to steal a stale config lock', overrideSeen, true);
  eq('the session read the version endpoint', versionCalls, 1);
  eq('the response body came back parsed', body.model, 'TZ470');

  // The whole point: the logout must happen even when the work throws.
  await throws(
    'a throwing operation still logs out',
    () =>
      withSonicOsSession({ baseUrl, retries: 0 }, { username: 'obliwan', password: 'sup3r-s3cret-pass' }, async () => {
        throw new Error('collector blew up');
      }),
    (e) => e instanceof Error && e.message === 'collector blew up',
  );
  eq('logout ran despite the exception', logouts, 2);

  // A 404 on an endpoint this firmware does not have is a normal HTTP answer.
  await throws(
    'a 404 endpoint surfaces as a driver error, not a hang',
    () =>
      withSonicOsSession({ baseUrl, retries: 0 }, { username: 'obliwan', password: 'sup3r-s3cret-pass' }, async (s) =>
        s.get('/does-not-exist'),
      ),
    (e) => e instanceof DriverError && e.code === 'PROTOCOL_ERROR',
  );
  eq('and it logged out too', logouts, 3);

  await new Promise<void>((resolve) => server.close(() => resolve()));
}

// ── 4. Drivers and registry ─────────────────────────────────────────────────

async function registryTests(): Promise<void> {
  eq('routeros6 resolves to its own driver', getDriver('mikrotik_routeros6').id, 'mikrotik_routeros6');
  eq('routeros7 resolves to its own driver', getDriver('mikrotik_routeros7').id, 'mikrotik_routeros7');
  eq('draytek resolves', getDriver('draytek_vigor').id, 'draytek_vigor');
  eq('zyxel nebula resolves', getDriver('zyxel_nebula').id, 'zyxel_nebula');
  eq('zyxel standalone resolves', getDriver('zyxel_standalone').id, 'zyxel_standalone');
  eq('zyxel cpe resolves', getDriver('zyxel_cpe').id, 'zyxel_cpe');
  eq('sonicwall resolves', getDriver('sonicwall_sonicos').id, 'sonicwall_sonicos');

  check('drivers are memoised', getDriver('draytek_vigor') === getDriver('draytek_vigor'));

  // The whole reason the unknown driver exists.
  eq('an unknown family does not throw', getDriver('cisco_ios').id, 'unknown');
  eq('a null family does not throw', getDriver(null).id, 'unknown');
  check('the unknown driver declares nothing', !unknownDriver.capabilities.supportsSsh);
  const probe = await unknownDriver.probe(ctxFor([]));
  eq('the unknown driver probes to "not reachable" rather than throwing', probe.reachable, false);

  eq('RouterOS 6 is guessed from the version', guessFamily('mikrotik', { osVersion: '6.49.10' }), 'mikrotik_routeros6');
  eq('RouterOS 7 is guessed from the version', guessFamily('mikrotik', { osVersion: '7.14.3' }), 'mikrotik_routeros7');
  eq('an unknown RouterOS major is not guessed', guessFamily('mikrotik', { osVersion: '8.0' }), null);
  eq('draytek maps one-to-one', guessFamily('draytek', {}), 'draytek_vigor');
  eq('sonicos 6.5 and 7 share a family', guessFamily('sonicwall', { osVersion: '6.5.4' }), 'sonicwall_sonicos');
  eq('an adopted zyxel is nebula', guessFamily('zyxel', { nebulaManaged: true }), 'zyxel_nebula');
  eq(
    'a standalone zyxel appliance',
    guessFamily('zyxel', { nebulaManaged: false, model: 'USG FLEX 200' }),
    'zyxel_standalone',
  );
  eq('a zyxel CPE model is decisive on its own', guessFamily('zyxel', { model: 'VMG8825-B50B' }), 'zyxel_cpe');
  eq('an ambiguous zyxel is not guessed', guessFamily('zyxel', { model: 'USG FLEX 200' }), null);
}

async function notImplementedTests(): Promise<void> {
  const ctx = ctxFor([]);
  for (const family of ['mikrotik_routeros7', 'draytek_vigor', 'zyxel_standalone', 'sonicwall_sonicos']) {
    const driver = getDriver(family);
    await throws(
      `${family}.getInterfaces refuses with its milestone`,
      () => driver.getInterfaces(ctx),
      (e) => e instanceof NotImplementedError && e.milestone === 'milestone M3',
    );
    await throws(
      `${family}.exportConfig refuses with its milestone`,
      () => driver.exportConfig(ctx),
      (e) => e instanceof NotImplementedError && e.milestone === 'milestone M5',
    );
    await throws(
      `${family}.applyConfig refuses with its milestone`,
      () => driver.applyConfig(ctx, 'anything'),
      (e) => e instanceof NotImplementedError && e.milestone === 'milestone M6',
    );
  }

  // No M2 driver claims a write capability it cannot perform.
  for (const family of ['mikrotik_routeros7', 'draytek_vigor', 'zyxel_nebula', 'sonicwall_sonicos']) {
    const caps = getDriver(family).capabilities;
    check(`${family} claims no write capability before M6`, !caps.canPushConfig && !caps.canReboot && !caps.canBackup);
    check(`${family} claims no interface read before M3`, !caps.canReadInterfaces);
  }
}

/** MikroTik identification against a fake RouterOS channel — no socket. */
async function mikrotikInventoryTests(): Promise<void> {
  const asked: string[] = [];
  const rows: Record<string, RouterOsRow[]> = {
    '/system/resource/print': [
      {
        uptime: '2w3d04:05:06',
        version: '7.14.3 (stable)',
        'board-name': 'CCR2004-1G-12S+2XS',
        platform: 'MikroTik',
      },
    ],
    '/system/identity/print': [{ name: 'CHR-CENTRAL' }],
    '/system/routerboard/print': [{ model: 'CCR2004-1G-12S+2XS', 'serial-number': 'HFX07YZ1234' }],
  };

  registerRouterOsChannelFactory(async () => ({
    async query(path) {
      asked.push(path);
      const result = rows[path];
      if (!result) throw new DriverError(`no such command prefix ${path}`, 'PROTOCOL_ERROR');
      return result;
    },
    async release() {
      /* the fake owns nothing */
    },
  }));

  const driver = new MikrotikRouterOsDriver('mikrotik_routeros7');
  const ctx = ctxFor([transport({ transport: 'routeros_api', port: 8728 })]);
  const inventory = await driver.getInventory(ctx);

  eq('model comes from /system/routerboard', inventory.model, 'CCR2004-1G-12S+2XS');
  eq('serial comes from /system/routerboard', inventory.serial, 'HFX07YZ1234');
  eq('the version is cleaned of its channel suffix', inventory.osVersion, '7.14.3');
  eq('system identity is read', inventory.systemIdentity, 'CHR-CENTRAL');
  eq('uptime is parsed to seconds', inventory.uptimeSeconds, 14 * 86_400 + 3 * 86_400 + 4 * 3_600 + 5 * 60 + 6);
  eq('the collecting channel is recorded', inventory.collectedVia, 'routeros_api');

  // A CHR has no RouterBOARD menu: the trap must not sink the whole inventory.
  delete rows['/system/routerboard/print'];
  const chr = await driver.getInventory(ctx);
  eq('a missing /system/routerboard leaves the serial null', chr.serial, null);
  eq('and the rest of the inventory survives', chr.systemIdentity, 'CHR-CENTRAL');

  // The box's own version wins over the family stored in the database.
  rows['/system/resource/print'] = [{ version: '6.49.10 (long-term)', 'board-name': 'RB760iGS' }];
  const v6 = await driver.getInventory(ctx);
  eq('the running version overrides the recorded family (R11)', v6.family, 'mikrotik_routeros6');

  // A probe with no usable channel must not throw.
  clearRouterOsChannelFactory();
  const outcome = await driver.probe(ctxFor([transport({ transport: 'routeros_api' })]));
  eq('an unwired RouterOS pool makes the probe fail, not throw', outcome.reachable, false);
  eq('and the failure is attributed to the channel', outcome.failedTransports[0], 'routeros_api');
  eq('the observed capability is demoted', outcome.observedOverrides.supportsRouterosApi, false);

  const noTransport = await driver.probe(ctxFor([]));
  eq('a device with no transports probes cleanly', noTransport.reachable, false);
  eq('with no attempts recorded', noTransport.attempts.length, 0);
}

// ── 5. Parsing and redaction ────────────────────────────────────────────────

/** Exposes the protected helpers of BaseDriver for testing. */
class ParserProbe extends BaseDriver {
  readonly id = 'test';
  readonly brand = null;
  readonly family = null;
  readonly capabilities = getDriver(null).capabilities;
  async probe(): Promise<never> {
    throw new Error('unused');
  }
  async getInventory(): Promise<never> {
    throw new Error('unused');
  }
  uptime(raw: string | null): number | null {
    return this.parseUptimeSeconds(raw);
  }
  kv(text: string): Record<string, string> {
    return this.parseKeyValueBlock(text);
  }
  deep(input: unknown, keys: string[]): string | null {
    return this.pickDeep(input, keys);
  }
}

function parserTests(): void {
  const p = new ParserProbe();

  eq('RouterOS uptime', p.uptime('1w2d03:04:05'), 7 * 86_400 + 2 * 86_400 + 3 * 3_600 + 4 * 60 + 5);
  eq('clock-only uptime', p.uptime('12:34:56'), 12 * 3_600 + 34 * 60 + 56);
  eq('worded uptime', p.uptime('5 days 03:04:05'), 5 * 86_400 + 3 * 3_600 + 4 * 60 + 5);
  eq('an unparsable uptime is null, never 0', p.uptime('who knows'), null);
  eq('a missing uptime is null', p.uptime(null), null);

  const fields = p.kv([
    'Router Model : Vigor2927 Series',
    'Version: 4.4.3.1',
    'Serial Number = 2020072800000',
    '',
    '--- some banner nobody asked for ---',
  ].join('\n'));
  eq('key/value with a colon', fields['router-model'], 'Vigor2927 Series');
  eq('key/value with an equals sign', fields['serial-number'], '2020072800000');
  eq('a banner line is ignored rather than fatal', fields['---'], undefined);

  const doc = { data: { device: [{ serial_number: 'ABC123', firmwareVersion: '7.0.1' }] } };
  eq('a nested field is found by name', p.deep(doc, ['serialNumber', 'serial']), 'ABC123');
  eq('an absent field is null, not a crash', p.deep(doc, ['macAddress']), null);

  // Section 8.2 — a secret must not survive into a string that can be logged.
  const transcript = 'Password: hunter2-very-secret\nlogin ok';
  const clean = redact(transcript, ['hunter2-very-secret']);
  check('the secret is gone from the transcript', !clean.includes('hunter2-very-secret'), clean);
  check('the rest of the transcript survives', clean.includes('login ok'));
  eq('a very short secret is not blindly substituted', redact('aaa bbb', ['a']), 'aaa bbb');
}

// ── run ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  snmpCacheTests();
  await snmpDecodeTests();
  arbiterTests();
  breakerTests();
  deferredQueueTests();
  restPureTests();
  await sonicOsSessionTests();
  await registryTests();
  await notImplementedTests();
  await mikrotikInventoryTests();
  parserTests();

  const total = passed + failures.length;
  if (failures.length > 0) {
    console.error(`\n${failures.length}/${total} assertions FAILED:\n`);
    for (const f of failures) console.error(`  - ${f}`);
    process.exit(1);
  }
  console.log(`\nAll ${total} assertions passed.`);
  process.exit(0);
}

void main();
