/**
 * ObliWAN — RouterOS transport self-test.
 *
 * Run:  cd server && npx tsx src/services/transport/routeros/testing/selftest.ts
 *
 * Every assertion runs against `FakeRouterOs`, a real TCP server speaking the
 * real binary protocol on loopback. No mocks, no stubs: the bytes go through a
 * socket. That is the only way to prove the length encoding and the `.tag=`
 * multiplexing, which are the two things a code review cannot check.
 *
 * Exits non-zero on the first failure count > 0.
 */

import {
  SentenceReader,
  encodeLength,
  encodeSentence,
  parseSentence,
  redactWords,
  RouterOsTrapError,
} from '../protocol';
import {
  RouterOsAuthError,
  RouterOsConnection,
  RouterOsTimeoutError,
  createRouterOsConnection,
} from '../connection';
import { getCapabilities, probeCapabilities, clearCapabilityCache } from '../capabilities';
import { RouterOsPool, TokenBucket, computeBackoffMs, CircuitOpenError } from '../pool';
import { FakeRouterOs, FakeRouterOsOptions } from './fakeRouterosServer';
import { TEST_CERT_A, TEST_KEY_A, TEST_CERT_B, TEST_KEY_B } from './testCertificates';
import { RouterOsFingerprintError } from '../connection';
import crypto from 'crypto';

let passed = 0;
let failed = 0;

function ok(condition: boolean, label: string, detail?: unknown): void {
  if (condition) {
    passed++;
    console.log(`  PASS  ${label}`);
  } else {
    failed++;
    console.log(`  FAIL  ${label}${detail === undefined ? '' : ` -- ${JSON.stringify(detail)}`}`);
  }
}

function eq(actual: unknown, expected: unknown, label: string): void {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  ok(a === b, label, a === b ? undefined : { actual, expected });
}

function section(title: string): void {
  console.log(`\n== ${title}`);
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function withServer<T>(
  opts: FakeRouterOsOptions,
  fn: (server: FakeRouterOs, port: number) => Promise<T>,
): Promise<T> {
  const server = new FakeRouterOs(opts);
  const port = await server.listen(0);
  try {
    return await fn(server, port);
  } finally {
    await server.close();
  }
}

async function connectTo(port: number, over: Partial<FakeRouterOsOptions> = {}): Promise<RouterOsConnection> {
  return createRouterOsConnection({
    host: '127.0.0.1',
    port,
    tls: false,
    username: over.username ?? 'obliwan',
    password: over.password ?? 's3cr3t',
    requestTimeoutMs: 5_000,
    label: 'selftest',
  });
}

// ===========================================================================

async function testLengthEncoding(): Promise<void> {
  section('1. Word length encoding (1..5 bytes)');

  eq([...encodeLength(0)], [0x00], 'len 0 -> 1 byte');
  eq([...encodeLength(0x7f)], [0x7f], 'len 0x7F -> 1 byte (upper bound)');
  eq([...encodeLength(0x80)], [0x80, 0x80], 'len 0x80 -> 2 bytes (first that needs them)');
  eq([...encodeLength(300)], [0x81, 0x2c], 'len 300 -> 2 bytes 0x81 0x2C');
  eq([...encodeLength(0x3fff)], [0xbf, 0xff], 'len 0x3FFF -> 2 bytes (upper bound)');
  eq([...encodeLength(0x4000)], [0xc0, 0x40, 0x00], 'len 0x4000 -> 3 bytes');
  eq([...encodeLength(0x1fffff)], [0xdf, 0xff, 0xff], 'len 0x1FFFFF -> 3 bytes (upper bound)');
  eq([...encodeLength(0x200000)], [0xe0, 0x20, 0x00, 0x00], 'len 0x200000 -> 4 bytes');
  eq([...encodeLength(0xfffffff)], [0xef, 0xff, 0xff, 0xff], 'len 0x0FFFFFFF -> 4 bytes (upper bound)');
  eq([...encodeLength(0x10000000)], [0xf0, 0x10, 0x00, 0x00, 0x00], 'len 0x10000000 -> 5 bytes');

  // Round-trip every boundary through the reader, one byte at a time, which
  // is the worst case a TCP stack can hand us.
  const sizes = [0, 1, 127, 128, 300, 16383, 16384, 200000];
  for (const size of sizes) {
    const word = 'a'.repeat(size);
    const buf = encodeSentence(['!re', `=data=${word}`]);
    const reader = new SentenceReader();
    let out: string[][] = [];
    for (let i = 0; i < buf.length; i++) {
      out = out.concat(reader.push(buf.subarray(i, i + 1)));
    }
    ok(
      out.length === 1 && out[0][1] === `=data=${word}`,
      `round-trip of a ${size}-byte word delivered 1 byte at a time`,
      { sentences: out.length },
    );
  }

  // Several sentences arriving inside a single chunk.
  const glued = Buffer.concat([
    encodeSentence(['!re', '=a=1']),
    encodeSentence(['!re', '=a=2']),
    encodeSentence(['!done', '.tag=7']),
  ]);
  const reader = new SentenceReader();
  const got = reader.push(glued);
  eq(got.length, 3, 'three sentences glued in one TCP chunk are split back out');
  eq(reader.pendingBytes, 0, 'nothing left buffered after a clean boundary');

  // Attribute values containing '=' must not be truncated.
  const s = parseSentence(['!re', '=comment=a=b=c', '.tag=12']);
  eq(s.attrs.comment, 'a=b=c', 'attribute value keeps its embedded "="');
  eq(s.tag, '12', '.tag is parsed out of the words');

  // Redaction (section 8.2).
  const red = redactWords(['/login', '=name=obliwan', '=password=hunter2', '=address=10.0.0.1']);
  ok(!red.join(' ').includes('hunter2'), 'redactWords() removes a password before logging');
  ok(red.includes('=name=obliwan'), 'redactWords() keeps non-secret attributes readable');
}

async function testLoginAndSimpleCommand(): Promise<void> {
  section('2. Login and a simple command');

  await withServer({}, async (server, port) => {
    const conn = await connectTo(port);
    ok(conn.isReady, 'modern (>= 6.43) plaintext login succeeded');
    const identity = await conn.queryFirst(['/system/identity/print']);
    eq(identity?.name, 'chr-lab', '/system/identity/print returned the identity');
    // The login sentence must have carried a tag like everything else.
    const loginSent = server.received.find((w) => w[0] === '/login');
    ok(!!loginSent?.some((w) => w.startsWith('.tag=')), '/login itself is tagged');
    conn.close();
  });

  await withServer({}, async (_server, port) => {
    let err: unknown;
    try {
      await connectTo(port, { password: 'wrong' });
    } catch (e) {
      err = e;
    }
    ok(err instanceof RouterOsAuthError, 'a bad password rejects with RouterOsAuthError', String(err));
  });

  await withServer({ legacyLogin: true }, async (server, port) => {
    const conn = await connectTo(port);
    ok(conn.isReady, 'legacy (< 6.43) MD5 challenge login succeeded');
    const rounds = server.received.filter((w) => w[0] === '/login').length;
    eq(rounds, 2, 'the legacy login took exactly two round trips');
    conn.close();
  });
}

async function testMultiplexing(): Promise<void> {
  section('3. Three concurrent commands on ONE socket');

  await withServer({}, async (server, port) => {
    const conn = await connectTo(port);
    // Replies come back in the REVERSE order of the requests. If tags were not
    // routed, the fast answer would resolve the slow promise.
    const t0 = Date.now();
    const [a, b, c] = await Promise.all([
      conn.queryFirst(['/test/delay', '=ms=300', '=echo=slow']),
      conn.queryFirst(['/test/delay', '=ms=150', '=echo=medium']),
      conn.queryFirst(['/test/delay', '=ms=10', '=echo=fast']),
    ]);
    const elapsed = Date.now() - t0;
    eq(a?.echo, 'slow', 'the 300 ms command resolved with ITS OWN reply');
    eq(b?.echo, 'medium', 'the 150 ms command resolved with ITS OWN reply');
    eq(c?.echo, 'fast', 'the 10 ms command resolved with ITS OWN reply');
    ok(elapsed < 600, `the three ran concurrently, not serially (${elapsed} ms < 600)`, elapsed);
    eq(server.connectionCount, 1, 'all three shared a single TCP connection');
    eq(conn.inFlight, 0, 'no pending tag leaked after completion');
    conn.close();
  });
}

async function testStreamAndCancel(): Promise<void> {
  section('4. listen: two events, then /cancel');

  await withServer({}, async (server, port) => {
    const conn = await connectTo(port);
    const events: Record<string, string>[] = [];
    const stream = conn.stream(['/ppp/active/listen'], {
      onRow: (row) => events.push(row.attrs),
    });
    await sleep(50);

    server.pushPppEvent({ '.id': '*1', name: 'site-001', address: '10.66.0.11' });
    server.pushPppEvent({ '.id': '*2', name: 'site-002', address: '10.66.0.12', '.dead': 'true' });
    await sleep(80);

    eq(events.length, 2, 'the stream received both pushed events');
    eq(events[0]?.name, 'site-001', 'first event carries its attributes');
    eq(events[1]?.['.dead'], 'true', 'a session teardown event is delivered too');
    ok(!stream.isClosed, 'a listen does not terminate by itself');

    await stream.cancel();
    ok(stream.isClosed, '/cancel closed the stream');
    const cancels = server.received.filter((w) => w[0] === '/cancel');
    eq(cancels.length, 1, 'exactly one /cancel was sent to the router');
    ok(cancels[0].includes(`=tag=${stream.tag}`), '/cancel targeted the listen tag');
    eq(conn.inFlight, 0, 'the cancelled tag was released client-side');

    // The connection stays usable after a cancel.
    const id = await conn.queryFirst(['/system/identity/print']);
    eq(id?.name, 'chr-lab', 'the session still works after /cancel');
    conn.close();
  });

  section('4b. listen as an async iterator');
  await withServer({}, async (server, port) => {
    const conn = await connectTo(port);
    const seen: string[] = [];
    const iterator = conn.streamIterator(['/ppp/active/listen']);
    const consumer = (async () => {
      for await (const row of iterator) {
        seen.push(row.attrs.name ?? '');
        if (seen.length === 2) break; // `break` must cancel the tag
      }
    })();
    await sleep(50);
    server.pushPppEvent({ name: 'site-A' });
    server.pushPppEvent({ name: 'site-B' });
    await consumer;
    eq(seen, ['site-A', 'site-B'], 'the async iterator yielded both events');
    await sleep(50);
    ok(
      server.received.some((w) => w[0] === '/cancel'),
      'breaking out of the for-await loop sent /cancel',
    );
    conn.close();
  });
}

async function testTrapAndFatal(): Promise<void> {
  section('5. !trap rejects, !fatal kills the session');

  await withServer({}, async (_server, port) => {
    const conn = await connectTo(port);
    let err: unknown;
    try {
      await conn.talk(['/test/trap', '=message=input does not match any value of interface']);
    } catch (e) {
      err = e;
    }
    ok(err instanceof RouterOsTrapError, 'a !trap rejects the promise (never swallowed)');
    eq((err as RouterOsTrapError).message, 'input does not match any value of interface', 'the router message survives verbatim');
    eq((err as RouterOsTrapError).category, 1, 'the trap category is decoded');

    // A trap must not poison the socket.
    const id = await conn.queryFirst(['/system/identity/print']);
    eq(id?.name, 'chr-lab', 'the session is still usable after a trap');

    // "no such item" is recognisable so callers can treat it as empty.
    let notFound: unknown;
    try {
      await conn.talk(['/nope/print']);
    } catch (e) {
      notFound = e;
    }
    ok(
      notFound instanceof RouterOsTrapError && notFound.isNoSuchItem,
      'category 0 is surfaced as isNoSuchItem',
    );
    conn.close();
  });

  await withServer({}, async (server, port) => {
    const conn = await connectTo(port);
    const pending = conn.talk(['/test/never'], { timeoutMs: 5_000 });
    let closed = false;
    conn.on('close', () => {
      closed = true;
    });
    await sleep(30);
    server.sendFatal('not logged in');
    let err: unknown;
    try {
      await pending;
    } catch (e) {
      err = e;
    }
    ok(!!err, '!fatal rejected the in-flight command');
    ok(closed, '!fatal closed the connection');
    eq(conn.state, 'closed', 'the connection state is "closed" after !fatal');
  });
}

async function testTimeout(): Promise<void> {
  section('6. Per-request timeout + /cancel');

  await withServer({}, async (server, port) => {
    const conn = await connectTo(port);
    const t0 = Date.now();
    // A short-budget command and a normal one on the SAME socket: only the
    // first must die.
    const doomed = conn.talk(['/test/never'], { timeoutMs: 250 });
    const healthy = conn.queryFirst(['/test/delay', '=ms=400', '=echo=survivor']);

    let err: unknown;
    try {
      await doomed;
    } catch (e) {
      err = e;
    }
    const elapsed = Date.now() - t0;
    ok(err instanceof RouterOsTimeoutError, 'the request timed out with RouterOsTimeoutError', String(err));
    ok(elapsed >= 240 && elapsed < 1_000, `it rejected on ITS OWN budget (${elapsed} ms)`, elapsed);

    const survivor = await healthy;
    eq(survivor?.echo, 'survivor', 'the unrelated slower command on the same socket completed');
    await sleep(50);
    ok(
      server.received.some((w) => w[0] === '/cancel'),
      'the timed-out tag was /cancel-ed on the router (no leaked command)',
    );
    conn.close();
  });
}

async function testBigWordAndSplitSegments(): Promise<void> {
  section('7. A 300-byte word (2-byte length prefix)');

  await withServer({}, async (_server, port) => {
    const conn = await connectTo(port);
    const row = await conn.queryFirst(['/test/big', '=size=300']);
    eq(row?.data.length, 300, 'a 300-byte attribute value arrived intact');
    const big = await conn.queryFirst(['/test/big', '=size=20000']);
    eq(big?.data.length, 20000, 'a 20 000-byte value (still 2-byte prefix) arrived intact');
    conn.close();
  });

  section('8. A sentence cut across two TCP segments');
  // The server writes every reply in two pieces, 9 bytes then the rest, with
  // 15 ms in between. Byte 9 lands in the middle of a word for these replies.
  await withServer({ splitRepliesAt: 9 }, async (_server, port) => {
    const conn = await connectTo(port);
    ok(conn.isReady, 'login completed although every reply was split in two segments');
    const row = await conn.queryFirst(['/test/big', '=size=300']);
    eq(row?.data.length, 300, 'a split 300-byte reply was reassembled correctly');
    const id = await conn.queryFirst(['/system/identity/print']);
    eq(id?.name, 'chr-lab', 'a split short reply was reassembled correctly');
    conn.close();
  });
}

async function testCapabilities(): Promise<void> {
  section('9. Capability matrix (risk R11)');

  clearCapabilityCache();
  await withServer({ version: '7.14.3 (stable)', boardName: 'CHR', healthShape: 'rows' }, async (_s, port) => {
    const conn = await connectTo(port);
    const m = await probeCapabilities(conn);
    eq(m.family, 'mikrotik_routeros7', 'RouterOS 7 is detected as its own family');
    eq(m.major, 7, 'major version parsed');
    eq(m.channel, 'stable', 'release channel parsed');
    eq(m.healthShape, 'rows', 'v7 /system/health is detected as ROWS');
    eq(m.paths.wireless, '/interface/wifi/print', 'v7 wireless path is /interface/wifi');
    eq(m.hasRouterboard, false, 'a CHR reports no routerboard');
    eq(m.serialNumber, null, 'a CHR has no hardware serial (D5 falls back to ppp_username)');
    ok(m.hasPppServer, 'the CHR is detected as a PPP concentrator');
    conn.close();
  });

  await withServer(
    {
      version: '6.49.10 (long-term)',
      boardName: 'RB4011',
      healthShape: 'record',
      unsupportedPaths: ['/interface/wifi/print', '/interface/wifiwave2/print', '/ppp/active/print'],
    },
    async (_s, port) => {
      const conn = await connectTo(port);
      const m = await probeCapabilities(conn);
      eq(m.family, 'mikrotik_routeros6', 'RouterOS 6 is detected as its own family');
      eq(m.healthShape, 'record', 'v6 /system/health is detected as a RECORD');
      eq(m.paths.wireless, '/interface/wireless/print', 'v6 wireless path is /interface/wireless');
      eq(m.serialNumber, 'HXX0LAB0001', 'a routerboard serial is captured');
      eq(m.hasPppServer, false, 'a CPE without /ppp/active is not a concentrator');
      conn.close();
    },
  );

  // A v7 box whose wifi package is missing must fall back, not explode.
  await withServer(
    { version: '7.11 (stable)', unsupportedPaths: ['/interface/wifi/print', '/interface/wifiwave2/print', '/interface/wireless/print'] },
    async (_s, port) => {
      const conn = await connectTo(port);
      const m = await probeCapabilities(conn);
      eq(m.paths.wireless, null, 'no wireless package -> wireless path is null, not a crash');
      ok(m.notes.length > 0, 'the gap is recorded as a user-visible note');
      conn.close();
    },
  );

  // Caching: probe twice, the device is only asked once.
  clearCapabilityCache();
  await withServer({}, async (server, port) => {
    const conn = await connectTo(port);
    await getCapabilities(conn, 'device-1');
    const afterFirst = server.received.length;
    await getCapabilities(conn, 'device-1');
    eq(server.received.length, afterFirst, 'the second getCapabilities() hit the cache, not the router');
    await getCapabilities(conn, 'device-1', { force: true });
    ok(server.received.length > afterFirst, 'force:true re-probes the device');
    conn.close();
  });
}

async function testPool(): Promise<void> {
  section('10. Pool: one socket per device, breaker, anti-stampede');

  await withServer({}, async (server, port) => {
    const fingerprints: string[] = [];
    const saved: string[] = [];
    const pool = new RouterOsPool(
      {
        onFingerprint: (_id, fp) => fingerprints.push(fp),
        saveHealth: async (s) => {
          saved.push(`${s.deviceId}:${s.circuit}:${s.consecutiveFailures}`);
        },
      },
      { keepaliveMs: 0, failureThreshold: 2, backoffBaseMs: 50, backoffMaxMs: 200 },
    );
    const target = {
      deviceId: 'dev-1',
      host: '127.0.0.1',
      port,
      tls: false,
      username: 'obliwan',
      password: 's3cr3t',
    };

    // Ten simultaneous acquires must produce ONE socket.
    const conns = await Promise.all(Array.from({ length: 10 }, () => pool.acquire(target)));
    eq(server.connectionCount, 1, 'ten concurrent acquires opened exactly ONE TCP session');
    ok(
      conns.every((c) => c === conns[0]),
      'every caller got the same connection object',
    );

    const rows = await pool.withConnection(target, (c) => c.query(['/ppp/active/print']));
    eq(rows.length, 1, 'withConnection() ran a command through the pooled session');
    eq(pool.health('dev-1').circuit, 'closed', 'the breaker is closed after success');

    // A !trap is the router answering: it must NOT count against the breaker.
    try {
      await pool.withConnection(target, (c) => c.talk(['/test/trap']));
    } catch {
      /* expected */
    }
    eq(pool.health('dev-1').consecutiveFailures, 0, 'a !trap does not open the breaker');

    await pool.shutdown();
    ok(saved.length > 0, 'breaker transitions were handed to the persistence hook');
    ok(fingerprints.length === 0, 'no TLS fingerprint is captured on a plaintext session');
  });

  // Breaker: a dead host opens the circuit and then refuses to dial.
  const pool = new RouterOsPool({}, {
    keepaliveMs: 0,
    failureThreshold: 2,
    backoffBaseMs: 5_000,
    backoffMaxMs: 10_000,
    connectTimeoutMs: 300,
  });
  const dead = {
    deviceId: 'dev-dead',
    host: '127.0.0.1',
    port: 9, // discard port: refuses or hangs, never speaks RouterOS
    tls: false,
    username: 'x',
    password: 'y',
  };
  for (let i = 0; i < 2; i++) {
    try {
      await pool.acquire(dead);
    } catch {
      /* expected */
    }
  }
  eq(pool.health('dev-dead').circuit, 'open', 'two failures opened the breaker');
  let circuitErr: unknown;
  try {
    await pool.acquire(dead);
  } catch (e) {
    circuitErr = e;
  }
  ok(circuitErr instanceof CircuitOpenError, 'an open breaker refuses to dial at all', String(circuitErr));
  ok(
    (circuitErr as CircuitOpenError).retryAt instanceof Date,
    'the refusal carries the retry deadline the scheduler needs',
  );
  await pool.shutdown();

  // Backoff shape.
  section('11. Backoff and token bucket (risk R5)');
  const opts = { baseMs: 1_000, maxMs: 60_000, random: () => 1 };
  eq(computeBackoffMs(1, opts), 1_000, 'first retry waits the base delay');
  eq(computeBackoffMs(2, opts), 2_000, 'second retry doubles');
  eq(computeBackoffMs(3, opts), 4_000, 'third retry doubles again');
  eq(computeBackoffMs(20, opts), 60_000, 'the delay is capped at maxMs');
  const lo = computeBackoffMs(10, { ...opts, random: () => 0 });
  ok(lo === 1_000, 'full jitter can bring a long backoff back down to the base delay');
  const spread = new Set(
    Array.from({ length: 50 }, () => computeBackoffMs(8, { baseMs: 1_000, maxMs: 60_000 })),
  );
  ok(spread.size > 40, `jitter de-correlates the fleet (${spread.size}/50 distinct delays)`);

  const bucket = new TokenBucket(2, 5); // 2 burst, 5 per second
  const t0 = Date.now();
  await bucket.take();
  await bucket.take();
  await bucket.take(); // must wait ~200 ms for a refill
  const waited = Date.now() - t0;
  ok(waited >= 150, `the token bucket throttled the third dial (${waited} ms)`, waited);
}

function derFingerprint(pem: string): string {
  const der = Buffer.from(
    pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, ''),
    'base64',
  );
  return crypto.createHash('sha256').update(der).digest('hex');
}

async function testTlsPinning(): Promise<void> {
  section('12. TLS fingerprint pinning on 8729 (risk R9)');

  const fpA = derFingerprint(TEST_CERT_A);
  const fpB = derFingerprint(TEST_CERT_B);
  ok(fpA !== fpB, 'the two test certificates really are different identities');

  // Trust on first use: no pin yet, the fingerprint is captured and reported.
  await withServer({ tls: { cert: TEST_CERT_A, key: TEST_KEY_A } }, async (_s, port) => {
    let captured: string | null = null;
    const conn = await createRouterOsConnection({
      host: '127.0.0.1',
      port,
      tls: true,
      username: 'obliwan',
      password: 's3cr3t',
      expectedFingerprint: null,
      onFingerprint: (fp) => {
        captured = fp;
      },
      label: 'tls-tofu',
    });
    ok(conn.isReady, 'the TLS session came up against a self-signed certificate');
    eq(captured, fpA, 'the fingerprint observed on first use matches the served certificate');
    eq(conn.fingerprint, fpA, 'the connection exposes the fingerprint for persistence');
    conn.close();
  });

  // Same certificate, correct pin: accepted.
  await withServer({ tls: { cert: TEST_CERT_A, key: TEST_KEY_A } }, async (_s, port) => {
    const conn = await createRouterOsConnection({
      host: '127.0.0.1',
      port,
      tls: true,
      username: 'obliwan',
      password: 's3cr3t',
      // Colons and upper case are what an operator pastes from Winbox.
      expectedFingerprint: (fpA.match(/../g) ?? []).join(':').toUpperCase(),
      label: 'tls-pinned',
    });
    ok(conn.isReady, 'a matching pin is accepted (and normalised from AA:BB:.. form)');
    conn.close();
  });

  // Different certificate on the same host: refused, hard.
  await withServer({ tls: { cert: TEST_CERT_B, key: TEST_KEY_B } }, async (_s, port) => {
    let err: unknown;
    try {
      await createRouterOsConnection({
        host: '127.0.0.1',
        port,
        tls: true,
        username: 'obliwan',
        password: 's3cr3t',
        expectedFingerprint: fpA,
        label: 'tls-mitm',
      });
    } catch (e) {
      err = e;
    }
    ok(err instanceof RouterOsFingerprintError, 'a CHANGED certificate is refused', String(err));
    ok(
      (err as RouterOsFingerprintError).actual === fpB,
      'the refusal reports the fingerprint actually presented',
    );
    ok(
      !String((err as Error).message).includes('s3cr3t'),
      'the refusal message carries no credential',
    );
  });

  // The pool turns a fingerprint refusal into an immediately open breaker.
  await withServer({ tls: { cert: TEST_CERT_B, key: TEST_KEY_B } }, async (_s, port) => {
    const pool = new RouterOsPool({}, { keepaliveMs: 0, failureThreshold: 10, authBackoffMs: 60_000 });
    try {
      await pool.acquire({
        deviceId: 'dev-tls',
        host: '127.0.0.1',
        port,
        tls: true,
        username: 'obliwan',
        password: 's3cr3t',
        expectedFingerprint: fpA,
      });
    } catch {
      /* expected */
    }
    eq(
      pool.health('dev-tls').circuit,
      'open',
      'ONE fingerprint refusal opens the breaker (no retry storm on a suspected MITM)',
    );
    await pool.shutdown();
  });
}

// ===========================================================================

async function main(): Promise<void> {
  console.log('RouterOS transport self-test (fake device on loopback)');
  await testLengthEncoding();
  await testLoginAndSimpleCommand();
  await testMultiplexing();
  await testStreamAndCancel();
  await testTrapAndFatal();
  await testTimeout();
  await testBigWordAndSplitSegments();
  await testCapabilities();
  await testPool();
  await testTlsPinning();

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

if (require.main === module) {
  main().catch((err) => {
    console.error('SELF-TEST CRASHED:', err);
    process.exit(2);
  });
}
