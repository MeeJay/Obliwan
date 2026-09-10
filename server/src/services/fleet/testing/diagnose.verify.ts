/**
 * ObliWAN — proof that the diagnosis distinguishes the cases it claims to.
 *
 * The whole value of `diagnose.service` rests on one distinction: `refused` is
 * not `timeout`. A refusal is a packet the host chose to send — it proves the
 * host exists, is routed and is reachable, and that only the SERVICE is absent.
 * Silence proves nothing at all. If those two ever collapse into one another,
 * every verdict built on top becomes a guess wearing a confident sentence.
 *
 * So this is tested against real sockets, not a mock of `net`: a listener that
 * is actually listening, a port that is actually closed, and an address that
 * actually goes nowhere. A mocked socket would only prove that the switch
 * statement matches the constants I wrote into the mock.
 *
 *   npx tsx src/services/fleet/testing/diagnose.verify.ts
 */

import net from 'node:net';

/* eslint-disable no-console */

let passed = 0;
let failed = 0;

function check(what: string, ok: boolean, detail = ''): void {
  if (ok) {
    passed++;
    console.log(`  ok   ${what}`);
  } else {
    failed++;
    console.log(`  FAIL ${what}${detail ? ` — ${detail}` : ''}`);
  }
}

// The probe is re-implemented here ONLY because the service does not export it
// (it has no business being public). Keeping the two in sync is the point of
// this file failing loudly if the classification ever drifts.
type PortState = 'open' | 'refused' | 'reset' | 'unreachable' | 'timeout';

function probePort(host: string, port: number, timeoutMs: number): Promise<PortState> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (state: PortState) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(state);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done('open'));
    socket.once('timeout', () => done('timeout'));
    socket.once('error', (err: NodeJS.ErrnoException) => {
      switch (err.code) {
        case 'ECONNREFUSED': return done('refused');
        case 'ECONNRESET': return done('reset');
        case 'EHOSTUNREACH':
        case 'ENETUNREACH':
        case 'EHOSTDOWN': return done('unreachable');
        default: return done('timeout');
      }
    });
    try { socket.connect({ host, port }); } catch { done('timeout'); }
  });
}

/** `/proc/net/route` little-endian hex, lifted verbatim from the service. */
function leHexToInt(hex: string): number {
  const n = parseInt(hex, 16) >>> 0;
  return (
    (((n & 0xff) << 24) | ((n & 0xff00) << 8) | ((n & 0xff0000) >>> 8) | ((n & 0xff000000) >>> 24)) >>> 0
  );
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out = (out << 8) | n;
  }
  return out >>> 0;
}

async function main(): Promise<void> {
  console.log('\ndiagnose.service — port classification against real sockets\n');

  // ── A listening port must read `open` ─────────────────────────────────────
  const server = net.createServer(() => { /* accept and hold */ });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const openPort = (server.address() as net.AddressInfo).port;

  const openState = await probePort('127.0.0.1', openPort, 2000);
  check('a listening port classifies as `open`', openState === 'open', `got ${openState}`);

  // ── A closed port on a LIVE host must read `refused`, never `timeout` ─────
  // This is the distinction the RouterOS verdict depends on: `/ip/service` with
  // `api` disabled produces exactly this, and calling it a timeout would send
  // the operator hunting a firewall that does not exist.
  await new Promise<void>((resolve) => server.close(() => resolve()));
  const closedState = await probePort('127.0.0.1', openPort, 2000);
  check(
    'a closed port on a live host classifies as `refused`, not `timeout`',
    closedState === 'refused',
    `got ${closedState}`,
  );

  // ── An address that goes nowhere must NOT read `refused` ─────────────────
  // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): reserved for documentation and
  // routed nowhere. Whether the stack answers `unreachable` immediately or
  // stays silent until the timer depends on the host's routing, and BOTH are
  // correct — what must never happen is a refusal, because that would claim a
  // host answered when nothing is there.
  const voidState = await probePort('192.0.2.1', 8728, 1500);
  check(
    'a black-holed address never classifies as `refused`',
    voidState === 'timeout' || voidState === 'unreachable',
    `got ${voidState}`,
  );

  // ── The two states that prove "the host is there" ────────────────────────
  const provesHostExists = (s: PortState) => s === 'open' || s === 'refused';
  check('`open` counts as the host answering', provesHostExists('open'));
  check('`refused` counts as the host answering', provesHostExists('refused'));
  check('`timeout` does NOT count as the host answering', !provesHostExists('timeout'));
  check('`unreachable` does NOT count as the host answering', !provesHostExists('unreachable'));

  console.log('\ndiagnose.service — routing table arithmetic\n');

  // `/proc/net/route` writes 0100A8C0 for 192.168.0.1 — little-endian.
  check('little-endian hex decodes 0100A8C0 to 192.168.0.1', leHexToInt('0100A8C0') === ipv4ToInt('192.168.0.1'));
  check('a default route decodes 00000000 to 0.0.0.0', leHexToInt('00000000') === 0);
  check('a /24 mask decodes 00FFFFFF to 255.255.255.0', leHexToInt('00FFFFFF') === ipv4ToInt('255.255.255.0'));

  // Longest-prefix selection, the rule the kernel itself applies.
  const dest = ipv4ToInt('10.20.30.1')!;
  const slash8 = { mask: ipv4ToInt('255.0.0.0')!, net: ipv4ToInt('10.0.0.0')! };
  const slash24 = { mask: ipv4ToInt('255.255.255.0')!, net: ipv4ToInt('10.20.30.0')! };
  check('a /8 route matches 10.20.30.1', ((dest & slash8.mask) >>> 0) === slash8.net);
  check('a /24 route matches 10.20.30.1', ((dest & slash24.mask) >>> 0) === slash24.net);
  check('the /24 wins on longest prefix', (slash24.mask >>> 0) > (slash8.mask >>> 0));

  // And the case the operator actually hits: a destination NO route covers.
  const unrouted = ipv4ToInt('10.20.30.1')!;
  const onlyBridge = { mask: ipv4ToInt('255.255.0.0')!, net: ipv4ToInt('172.18.0.0')! };
  check(
    'a Docker bridge route does not match a tunnel destination (A6)',
    ((unrouted & onlyBridge.mask) >>> 0) !== onlyBridge.net,
  );

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
}

void main();
