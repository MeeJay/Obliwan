/**
 * ObliWAN — offline self-test for the SNMP session lifecycle.
 *
 * NO REAL EQUIPMENT IS TOUCHED, AND NO UDP SOCKET IS EVER OPENED. Every session
 * here is a hand-written double; the one test that goes through the real
 * factory does so on a path that throws BEFORE `snmp.createSession()`.
 *
 * What it proves, and why each of these was worth a test:
 *
 *  - THERE IS ONE CACHE. M2 and M3 each had one, so there were two places for a
 *    UDP socket to leak. The last test in this file re-reads the source tree and
 *    fails if a second module ever opens a session again.
 *  - `dispose()` REALLY CLOSES, on all four exits: LRU eviction, TTL expiry
 *    (`ttlAutopurge`), explicit drop, and shutdown. The TTL path had no test
 *    anywhere before this file: on a quiet fleet it is the ONLY thing that ever
 *    returns an idle socket.
 *  - A REQUEST THAT NEVER ANSWERS EVICTS ITS SESSION. The hard timer is not
 *    redundant with net-snmp's own timeout, and the eviction happens in exactly
 *    one place for GET and WALK alike.
 *  - THE TYPE-AWARE DECODE SURVIVED THE MERGE. A Counter64 is 8 big-endian
 *    bytes; read as text it yields mojibake, `asCounter` returns null, and every
 *    HC interface silently becomes AGENT_ERROR for ever.
 *  - A WALK THE SESSION CANNOT DO IS AN ERROR, NEVER AN EMPTY TABLE. An empty
 *    walk is how discovery mass-vanishes a device.
 *
 * Run:  npx tsx src/services/snmp/testing/selftest.ts
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import type * as snmp from 'net-snmp';
import { DriverError } from '../../drivers/types';
import {
  ASN1,
  MAX_VARBINDS_PER_PDU,
  SnmpSessionCache,
  asCounter,
  asInt,
  asText,
  classifySnmpError,
  decodeVarbind,
  dialTarget,
  getMany,
  openSnmpConnection,
  securityLevelOf,
  snmpGet,
  snmpSessions,
  snmpWalk,
  type SnmpSessionLike,
  type SnmpTarget,
  type SnmpVersionInput,
} from '../../transport/snmp.transport';

// ── tiny harness ────────────────────────────────────────────────────────────

let passed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed += 1;
    return;
  }
  failures.push(`${name}${detail === undefined ? '' : ` — ${JSON.stringify(detail, replacer)}`}`);
}

function replacer(_k: string, v: unknown): unknown {
  return typeof v === 'bigint' ? `${v}n` : v;
}

function eq<T>(name: string, actual: T, expected: T): void {
  check(name, Object.is(actual, expected), { actual, expected });
}

async function throws(
  name: string,
  fn: () => Promise<unknown>,
  predicate: (e: unknown) => boolean,
): Promise<void> {
  try {
    await fn();
    check(name, false, 'did not throw');
  } catch (err) {
    check(name, predicate(err), err instanceof Error ? err.message : String(err));
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// ── fixtures ────────────────────────────────────────────────────────────────

function v2c(host: string, community = 'public', extra: Partial<SnmpTarget> = {}): SnmpTarget {
  return { host, version: '2c', credentials: { community }, ...extra };
}

interface Recorder {
  created: string[];
  closed: string[];
  disposed: Array<{ key: string; reason: string }>;
}

/** A session double that answers `get` with whatever `answer` returns, and
 *  `subtree` with whatever `rows` returns. Both are optional: a double with no
 *  `subtree` is exactly the M2-era fake, and the walk path must refuse it. */
function fakeFactory(
  rec: Recorder,
  opts: {
    answer?: (oids: string[]) => { error?: Error; varbinds?: snmp.Varbind[] } | 'never';
    rows?: (base: string) => { error?: Error; varbinds?: snmp.Varbind[] };
    closeThrows?: boolean;
  } = {},
): (t: SnmpTarget) => SnmpSessionLike {
  return (t: SnmpTarget) => {
    const id = `${t.host}:${t.port ?? 161}#${rec.created.length + 1}`;
    rec.created.push(id);
    const session: SnmpSessionLike = {
      get(oids, cb) {
        const a = opts.answer ? opts.answer(oids) : { varbinds: [] };
        if (a === 'never') return; // a socket that never errors and never receives
        setImmediate(() => cb(a.error ?? null, a.varbinds ?? []));
      },
      close() {
        rec.closed.push(id);
        if (opts.closeThrows) throw new Error('socket already gone');
      },
    };
    if (opts.rows) {
      const rows = opts.rows;
      session.subtree = (base, _maxRep, feed, done) => {
        const r = rows(base);
        setImmediate(() => {
          if (r.varbinds && r.varbinds.length > 0) feed(r.varbinds);
          done(r.error ?? null);
        });
      };
    }
    return session;
  };
}

function recorder(): Recorder {
  return { created: [], closed: [], disposed: [] };
}

function cacheWith(
  rec: Recorder,
  factory: (t: SnmpTarget) => SnmpSessionLike,
  opts: { max?: number; ttlMs?: number } = {},
): SnmpSessionCache {
  return new SnmpSessionCache({
    factory,
    max: opts.max ?? 8,
    ttlMs: opts.ttlMs ?? 60_000,
    onDispose: (key, reason) => rec.disposed.push({ key, reason }),
  });
}

const vb = (oid: string, type: number, value: snmp.Varbind['value']): snmp.Varbind => ({
  oid,
  type,
  value,
});

// ── 1. one cache, one identity ──────────────────────────────────────────────

function identityTests(): void {
  const rec = recorder();
  const cache = cacheWith(rec, fakeFactory(rec));

  const a = v2c('10.0.0.1');
  cache.acquire(a);
  cache.acquire(a);
  eq('the same target reuses the one session', rec.created.length, 1);

  // Two connection handles are two views on ONE cached session — this is the
  // whole point of the merge: the poller and the discovery cannot end up on
  // two different sockets to the same agent.
  const c1 = openSnmpConnection(a, cache);
  const c2 = openSnmpConnection(a, cache);
  check('two connection handles are distinct objects', c1 !== c2);
  eq('...but they open no extra session', rec.created.length, 1);

  // The M2 spelling and the shared/DB spelling are the SAME target. Before the
  // merge they were two types in two modules and could not even be compared.
  eq(
    'version "2c" and version "v2c" are one cache entry',
    SnmpSessionCache.keyFor(v2c('10.0.0.1')),
    SnmpSessionCache.keyFor({ host: '10.0.0.1', version: 'v2c', credentials: { community: 'public' } }),
  );
  eq('the normalised version is the shared spelling', dialTarget(v2c('10.0.0.1')).version, 'v2c');
  eq('the default port is 161', dialTarget(v2c('10.0.0.1')).port, 161);

  check(
    'a different port is a different session',
    SnmpSessionCache.keyFor(v2c('10.0.0.1')) !==
      SnmpSessionCache.keyFor(v2c('10.0.0.1', 'public', { port: 1161 })),
  );

  // Section 8.2: the key travels into metrics and debug logs.
  const secret = SnmpSessionCache.keyFor(v2c('10.0.0.1', 's3cr3t-community'));
  check('the key changes with the credential', secret !== SnmpSessionCache.keyFor(v2c('10.0.0.1')));
  check('the key does not contain the community', !secret.includes('s3cr3t-community'), secret);

  const usm: SnmpTarget = {
    host: '10.0.0.5',
    version: 'v3',
    credentials: {
      username: 'obliwan-ro',
      securityLevel: 'authPriv',
      authProtocol: 'sha256',
      authKey: 'auth-key-plaintext',
      privProtocol: 'aes256',
      privKey: 'priv-key-plaintext',
    },
  };
  const usmKey = SnmpSessionCache.keyFor(usm);
  check('the key does not contain the USM auth key', !usmKey.includes('auth-key-plaintext'), usmKey);
  check('the key does not contain the USM priv key', !usmKey.includes('priv-key-plaintext'), usmKey);
  check(
    'the security level is part of the session identity',
    usmKey !==
      SnmpSessionCache.keyFor({
        ...usm,
        credentials: { ...usm.credentials, securityLevel: 'authNoPriv' },
      }),
  );

  // The stored level wins over the derivation; without a stored level the M2
  // behaviour (derive from the keys that are set) still applies.
  eq(
    'an explicit authNoPriv beats a lingering privKey',
    securityLevelOf({ ...usm.credentials, securityLevel: 'authNoPriv' }),
    securityLevelOf({ username: 'x', authKey: 'a' }),
  );
  eq(
    'with no stored level, auth + priv keys derive authPriv',
    securityLevelOf({ authKey: 'a', privKey: 'p' }),
    securityLevelOf({ securityLevel: 'authPriv' }),
  );

  cache.closeAll();
}

// ── 2. dispose() really closes, on every exit ───────────────────────────────

async function disposeTests(): Promise<void> {
  // -- LRU eviction --------------------------------------------------------
  {
    const rec = recorder();
    const cache = cacheWith(rec, fakeFactory(rec), { max: 2 });
    cache.acquire(v2c('10.0.0.1'));
    cache.acquire(v2c('10.0.0.2'));
    eq('the cache honours max', cache.size, 2);
    cache.acquire(v2c('10.0.0.3'));
    eq('...and evicts one', cache.size, 2);
    eq('eviction closed exactly one session', rec.closed.length, 1);
    eq('eviction closed the LRU entry', rec.closed[0], '10.0.0.1:161#1');
    eq('the eviction reason is "evict"', rec.disposed[0]?.reason, 'evict');
    cache.closeAll();
  }

  // -- TTL expiry (ttlAutopurge). Untested anywhere before this file. -------
  {
    const rec = recorder();
    const cache = cacheWith(rec, fakeFactory(rec), { ttlMs: 40 });
    cache.acquire(v2c('10.0.0.1'));
    eq('the session is live before the TTL', cache.size, 1);
    await sleep(250);
    eq('an idle session is CLOSED when its TTL expires', rec.closed.length, 1);
    eq('the TTL reason is "expire"', rec.disposed[0]?.reason, 'expire');
    eq('...and it left the cache', cache.size, 0);
    cache.closeAll();
  }

  // -- explicit drop and shutdown ------------------------------------------
  {
    const rec = recorder();
    const cache = cacheWith(rec, fakeFactory(rec));
    const t = v2c('10.0.0.1');
    cache.acquire(t);
    cache.drop(t);
    eq('drop() closed the session', rec.closed.length, 1);
    eq('the drop reason is "delete"', rec.disposed[0]?.reason, 'delete');

    cache.acquire(v2c('10.0.0.7'));
    cache.acquire(v2c('10.0.0.8'));
    cache.closeAll();
    eq('closeAll() closed every remaining session', rec.closed.length, 3);
    eq('closeAll() emptied the cache', cache.size, 0);
  }

  // -- a close() that throws must not keep the entry -----------------------
  {
    const rec = recorder();
    const cache = cacheWith(rec, fakeFactory(rec, { closeThrows: true }));
    cache.acquire(v2c('10.0.0.1'));
    cache.closeAll();
    eq('a throwing close() still empties the cache', cache.size, 0);
    eq('...and the close was attempted', rec.closed.length, 1);
  }

  // -- the connection handle evicts through the same one cache -------------
  {
    const rec = recorder();
    const cache = cacheWith(rec, fakeFactory(rec));
    const conn = openSnmpConnection(v2c('10.0.0.1'), cache);
    eq('opening a connection opens NO session by itself', rec.created.length, 0);
    await conn.get(['1.3.6.1.2.1.1.1.0']);
    eq('the first request acquires one session', rec.created.length, 1);
    conn.close();
    eq('connection.close() closed the cached session', rec.closed.length, 1);
    eq('...and emptied the cache', cache.size, 0);
  }
}

// ── 3. one timeout budget, one eviction point ───────────────────────────────

async function requestPolicyTests(): Promise<void> {
  // A socket that never errors and never receives. Without the hard timer the
  // promise stays pending for ever and the scheduler slot is never freed.
  {
    const rec = recorder();
    const cache = cacheWith(rec, fakeFactory(rec, { answer: () => 'never' }));
    const t = v2c('10.0.0.1', 'public', { timeoutMs: 5, retries: 0 });
    const started = Date.now();
    await throws(
      'a GET that never answers rejects as TIMEOUT',
      () => snmpGet(t, ['1.3.6.1.2.1.1.1.0'], cache),
      (e) => e instanceof DriverError && e.code === 'TIMEOUT' && e.retryable,
    );
    check('...within its budget', Date.now() - started < 5_000, Date.now() - started);
    eq('the hung session was EVICTED', cache.size, 0);
    eq('...and closed', rec.closed.length, 1);
  }

  // The same rule on the walk path, applied by the same one helper.
  {
    const rec = recorder();
    const walkCache = cacheWith(
      rec,
      fakeFactory(rec, { rows: () => ({ error: new Error('RequestTimedOutError') }) }),
    );
    const t = v2c('10.0.0.2', 'public', { timeoutMs: 5, retries: 0 });
    await throws(
      'a walk that times out rejects as TIMEOUT',
      () => snmpWalk(t, '1.3.6.1.2.1.2.2.1.2', walkCache),
      (e) => e instanceof DriverError && e.code === 'TIMEOUT',
    );
    eq('the failed walk evicted its session', walkCache.size, 0);
    eq('...and closed it', rec.closed.length, 1);
  }

  // Classification is shared: a bad community is a human problem, not a
  // network one, and must not open the breaker.
  {
    const rec = recorder();
    const cache = cacheWith(
      rec,
      fakeFactory(rec, {
        answer: () => ({
          error: new Error('Authentication failure (incorrect password, community or key)'),
        }),
      }),
    );
    await throws(
      'a bad community rejects as AUTH_FAILED and is NOT retryable',
      () => snmpGet(v2c('10.0.0.3'), ['1.3.6.1.2.1.1.1.0'], cache),
      (e) => e instanceof DriverError && e.code === 'AUTH_FAILED' && !e.retryable,
    );
    eq('the failed session was evicted', cache.size, 0);
  }

  eq(
    'an unreachable host classifies as UNREACHABLE',
    classifySnmpError(new Error('connect EHOSTUNREACH'), '10.0.0.4').code,
    'UNREACHABLE',
  );
  eq(
    'anything else is a protocol error, never a silent success',
    classifySnmpError(new Error('garbage on the wire'), '10.0.0.4').code,
    'PROTOCOL_ERROR',
  );
  check(
    'a DriverError raised by the factory travels untouched',
    classifySnmpError(new DriverError('no community', 'AUTH_FAILED'), 'x').code === 'AUTH_FAILED',
  );

  // Through the REAL factory: a v2c target with no community must fail fast at
  // acquire time rather than opening a socket to nowhere.
  await throws(
    'a v2c target with no community fails before any socket is opened',
    () => snmpGet({ host: '203.0.113.1', version: '2c', credentials: {} }, ['1.3.6.1.2.1.1.1.0']),
    (e) => e instanceof DriverError && e.code === 'AUTH_FAILED' && !e.retryable,
  );
  eq('...and nothing was cached', snmpSessions.size, 0);

  eq('an empty GET is a no-op, not a PDU', (await snmpGet(v2c('10.0.0.9'), [])).length, 0);

  // A promise-returning function that sometimes throws SYNCHRONOUSLY is how a
  // poll escapes its own try/catch and takes a whole scheduler tick with it.
  {
    const rec = recorder();
    const cache = cacheWith(rec, fakeFactory(rec));
    const malformed: SnmpTarget = {
      host: '10.0.0.6',
      version: 'v9' as SnmpVersionInput,
      credentials: { community: 'public' },
    };
    let sync: unknown = null;
    let pending: Promise<unknown> | null = null;
    try {
      pending = snmpGet(malformed, ['1.3.6.1.2.1.1.1.0'], cache);
    } catch (err) {
      sync = err;
    }
    check('a malformed target does NOT throw synchronously', sync === null, String(sync));
    await throws(
      '...it rejects as PROTOCOL_ERROR like every other SNMP failure',
      () => pending ?? Promise.reject(new Error('no promise was returned')),
      (e) => e instanceof DriverError && e.code === 'PROTOCOL_ERROR',
    );
    eq('...and no session was created for it', rec.created.length, 0);
  }
}

// ── 4. the type-aware decode (the part of M3 that had to survive) ───────────

function decodeTests(): void {
  const hc = Buffer.from([0x00, 0x00, 0x00, 0x02, 0x54, 0x0b, 0xe4, 0x00]);
  const counter = decodeVarbind(vb('1.3.6.1.2.1.31.1.1.1.6.1', ASN1.Counter64, hc));
  eq('a Counter64 decodes to a bigint, not to mojibake', counter.value, 10_000_000_000n);
  eq('...and asCounter reads it', asCounter(counter), 10_000_000_000n);
  check('...and the raw octets are kept', counter.bytes?.equals(hc) === true);

  // net-snmp hands a Counter32 back as a SIGNED JS number.
  eq(
    'a Counter32 past 2^31 folds back into the unsigned range',
    asCounter(decodeVarbind(vb('1.3.6.1.2.1.2.2.1.10.1', ASN1.Counter32, -1))),
    4_294_967_295n,
  );

  const missing = decodeVarbind(vb('1.3.6.1.2.1.31.1.1.1.6.9', ASN1.NoSuchInstance, null));
  check('noSuchInstance is "missing", not an error', missing.missing);
  eq('a missing counter is null, NEVER zero', asCounter(missing), null);
  eq('a missing integer is null', asInt(missing), null);
  eq('a missing string is null', asText(missing), null);

  eq(
    'an IpAddress decodes to dotted quad',
    decodeVarbind(vb('1.3.6.1.2.1.4.20.1.1.1', ASN1.IpAddress, Buffer.from([10, 0, 0, 1]))).value,
    '10.0.0.1',
  );
  eq(
    'an OctetString is UTF-8 with its NUL padding trimmed',
    decodeVarbind(vb('1.3.6.1.2.1.1.1.0', ASN1.OctetString, Buffer.from('RouterOS 7.14.3\u0000')))
      .value,
    'RouterOS 7.14.3',
  );
  eq(
    'asText strips the control bytes a vendor ifAlias can carry',
    asText(decodeVarbind(vb('1.3.6.1.2.1.31.1.1.1.18.1', ASN1.OctetString, Buffer.from('uplink\r')))),
    'uplink',
  );
  eq(
    'an empty ifAlias reads as "no alias", not as ""',
    asText(decodeVarbind(vb('1.3.6.1.2.1.31.1.1.1.18.2', ASN1.OctetString, Buffer.from('')))),
    null,
  );
}

// ── 5. walk ─────────────────────────────────────────────────────────────────

async function walkTests(): Promise<void> {
  const base = '1.3.6.1.2.1.2.2.1.2';
  const rec = recorder();
  const cache = cacheWith(
    rec,
    fakeFactory(rec, {
      rows: (b) => ({
        varbinds: [
          vb(`${b}.1`, ASN1.OctetString, Buffer.from('ether1')),
          vb(`${b}.2`, ASN1.OctetString, Buffer.from('ether2')),
          // An agent that overruns its own table. Keeping this row would put
          // another column's values into the ifDescr map.
          vb('1.3.6.1.2.1.2.2.1.3.1', ASN1.Integer, 6),
        ],
      }),
    }),
  );

  const rows = await snmpWalk(v2c('10.0.0.1'), base, cache);
  eq('the walk returns the rows of its own subtree', rows.length, 2);
  eq('...decoded', asText(rows[0]), 'ether1');
  check('...and drops anything outside it', !rows.some((r) => r.oid.startsWith('1.3.6.1.2.1.2.2.1.3')));
  cache.closeAll();

  // A session that cannot walk must SAY SO. Returning [] here reads as "this
  // device has no interfaces", and discovery vanishes every one of them.
  const rec2 = recorder();
  const noWalk = cacheWith(rec2, fakeFactory(rec2)); // no `subtree` on the double
  await throws(
    'a walk on a session with no subtree() is an error, never an empty table',
    () => snmpWalk(v2c('10.0.0.2'), base, noWalk),
    (e) => e instanceof DriverError && e.code === 'PROTOCOL_ERROR' && !e.retryable,
  );
  noWalk.closeAll();
}

// ── 6. chunked GET ──────────────────────────────────────────────────────────

async function getManyTests(): Promise<void> {
  const rec = recorder();
  const pdus: string[][] = [];
  const cache = cacheWith(
    rec,
    fakeFactory(rec, {
      answer: (oids) => {
        pdus.push(oids);
        return {
          // The agent echoes a NORMALISED oid (leading dot). Trusting its
          // spelling as the map key silently loses every varbind. The value is
          // the ifIndex, so a varbind landing under the wrong key is visible.
          varbinds: oids.map((o) => vb(`.${o}`, ASN1.Counter32, Number(o.split('.').pop()))),
        };
      },
    }),
  );

  const oids = Array.from({ length: 30 }, (_, i) => `1.3.6.1.2.1.2.2.1.10.${i + 1}`);
  const answers = await getMany(openSnmpConnection(v2c('10.0.0.1'), cache), oids);
  eq('a 30-varbind read is split into 2 PDUs', pdus.length, 2);
  eq('...the first at the PDU ceiling', pdus[0].length, MAX_VARBINDS_PER_PDU);
  eq('every requested OID is present', answers.size, 30);
  eq('...keyed by the OID WE ASKED FOR, not by the one echoed back', asInt(answers.get(oids[29])), 30);
  eq('...including across the chunk boundary', asInt(answers.get(oids[24])), 25);

  // A failing chunk fails the whole read: half an interface is the AGENT_ERROR
  // case, not a sample.
  const rec2 = recorder();
  let seen = 0;
  const flaky = cacheWith(
    rec2,
    fakeFactory(rec2, {
      answer: (o) => {
        seen += 1;
        return seen === 1 ? { varbinds: o.map((x) => vb(x, ASN1.Counter32, 1)) } : { error: new Error('boom') };
      },
    }),
  );
  await throws(
    'a failing chunk fails the whole read',
    () => getMany(openSnmpConnection(v2c('10.0.0.2'), flaky), oids),
    (e) => e instanceof DriverError,
  );
  cache.closeAll();
  flaky.closeAll();
}

// ── 7. the structural guard: there must stay exactly ONE owner ──────────────

function singleOwnerTest(): void {
  const root = join(__dirname, '..', '..');
  const owner = join('transport', 'snmp.transport.ts');
  const offenders: string[] = [];

  const walkDir = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walkDir(full);
        continue;
      }
      if (!entry.endsWith('.ts') || entry.endsWith('.d.ts')) continue;
      if (full.endsWith(owner)) continue;
      // Comments are stripped first: this very file NAMES `createSession` in
      // its header, and a guard that trips on prose is a guard nobody keeps.
      const src = readFileSync(full, 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/^[ \t]*\/\/.*$/gm, '');
      if (/\bcreateV?3?Session\s*\(/.test(src)) offenders.push(full);
    }
  };
  walkDir(root);

  check(
    'no module outside snmp.transport.ts creates an SNMP session',
    offenders.length === 0,
    offenders,
  );

  // And the duplicate really is gone — not renamed, not re-exported.
  let dead = false;
  try {
    statSync(join(root, 'snmp', 'snmpClient.ts'));
    dead = true;
  } catch {
    dead = false;
  }
  check('services/snmp/snmpClient.ts is deleted, not shimmed', !dead);
}

// ── run ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  identityTests();
  await disposeTests();
  await requestPolicyTests();
  decodeTests();
  await walkTests();
  await getManyTests();
  singleOwnerTest();

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
