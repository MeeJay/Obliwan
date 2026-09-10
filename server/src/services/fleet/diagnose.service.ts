/**
 * ObliWAN — "the channel failed; WHY?"
 *
 * A connection test answers a yes/no question and, when the answer is no, hands
 * the operator one line: `Connection to 10.20.30.1:8728 timed out after 10000
 * ms`. That sentence is true and nearly useless. A TCP timeout is the most
 * silent failure there is — it is equally consistent with "no route", "a
 * firewall drops us", "the service is not running", "the box is off" and "the
 * address belongs to somebody else now". Those five have five different fixes.
 *
 * ┌─ THE PROBE THAT ACTUALLY ANSWERS IT IS NOT PING ─────────────────────────┐
 * │ ICMP is the reflex and it is the weakest signal here: it is filtered on   │
 * │ half the paths this product crosses, and a box that answers ping happily  │
 * │ while its API port is closed looks HEALTHY to it. D4 already refuses ping │
 * │ as a presence signal for exactly that reason (a diagnostic ping is a      │
 * │ different question from presence, so running one here contradicts         │
 * │ nothing — it is just not the interesting one).                            │
 * │                                                                          │
 * │ The decisive test is a TCP sweep of the SIBLING ports. If 22 or 8291      │
 * │ answers while 8728 times out, the box is alive, routed and reachable, and │
 * │ the problem is one service — on RouterOS, almost always `/ip/service` with │
 * │ `api` disabled, which is its DEFAULT state. Ping cannot distinguish that  │
 * │ from a dead site. One extra TCP connect can.                              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── WHAT KEEPS THIS FROM BEING A PORT SCANNER ────────────────────────────────
 * The target host is read from the DEVICE'S OWN transport row (or its
 * `tunnel_ip`), never from the request. The port list is a fixed constant per
 * brand. There is no shape of this API that lets a caller say "connect to this
 * address for me": that would be a server-side request forgery wearing a
 * diagnostic's clothes, reachable with the same capability that opens a
 * channel. Everything here is about one device that already exists.
 *
 * ── AND WHAT KEEPS IT HONEST ────────────────────────────────────────────────
 * Every step reports `unknown` rather than `fail` when the tool itself was
 * missing or refused. "traceroute is not installed" and "traceroute found
 * nothing" are different facts, and a diagnostic that blurs them sends an
 * operator to look at the network when they should be looking at the image.
 */

import net from 'node:net';
import dns from 'node:dns/promises';
import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { db } from '../../db';
import { logger } from '../../utils/logger';

// ============================================================================
// Shapes
// ============================================================================

export type StepOutcome = 'ok' | 'fail' | 'unknown' | 'skipped';

export interface DiagnosticStep {
  /** Stable key — the UI decides its own wording and icon from this. */
  step: 'dns' | 'route' | 'tcp' | 'icmp' | 'traceroute';
  /** What was attempted, in the operator's terms. */
  label: string;
  outcome: StepOutcome;
  /** One sentence. Never a stack trace, never a credential. */
  detail: string;
  ms: number | null;
}

export type PortState = 'open' | 'refused' | 'reset' | 'unreachable' | 'timeout';

export interface PortProbe {
  port: number;
  /** What this port MEANS on this brand, so the operator does not have to know. */
  service: string;
  state: PortState;
  ms: number;
}

export interface Diagnosis {
  deviceId: number;
  target: { host: string; port: number | null; transport: string };
  ports: PortProbe[];
  steps: DiagnosticStep[];
  /** The synthesised answer. This is the line the operator reads first. */
  verdict: string;
  /** True when something on this host answered TCP. Drives the UI's tone. */
  hostAnswered: boolean;
}

// ============================================================================
// The port vocabulary — small, fixed, and brand-aware
// ============================================================================

/**
 * Deliberately short. This is not reconnaissance: each entry earns its place by
 * changing the DIAGNOSIS when it answers, and the sweep runs against a device
 * the operator already owns and already asked us to dial.
 */
const BRAND_PORTS: Readonly<Record<string, ReadonlyArray<{ port: number; service: string }>>> = {
  mikrotik: [
    { port: 8728, service: 'RouterOS API' },
    { port: 8729, service: 'RouterOS API over TLS' },
    { port: 8291, service: 'Winbox' },
    { port: 22, service: 'SSH' },
    { port: 443, service: 'HTTPS / WebFig' },
    { port: 80, service: 'HTTP / WebFig' },
  ],
  draytek: [
    { port: 22, service: 'SSH' },
    { port: 443, service: 'HTTPS admin' },
    { port: 80, service: 'HTTP admin' },
  ],
  zyxel: [
    { port: 22, service: 'SSH' },
    { port: 443, service: 'HTTPS admin' },
    { port: 80, service: 'HTTP admin' },
  ],
  sonicwall: [
    { port: 443, service: 'SonicOS HTTPS / REST' },
    { port: 22, service: 'SSH' },
  ],
};

const FALLBACK_PORTS: ReadonlyArray<{ port: number; service: string }> = [
  { port: 22, service: 'SSH' },
  { port: 443, service: 'HTTPS' },
];

/** Short on purpose: six ports at 10 s each would out-wait the operator. */
const SWEEP_TIMEOUT_MS = 2500;
const PING_TIMEOUT_MS = 6000;
const TRACEROUTE_TIMEOUT_MS = 15_000;

// ============================================================================
// TCP: the one probe that needs no privilege and answers the real question
// ============================================================================

/**
 * Connect, and classify the REFUSAL as carefully as the success.
 *
 * `refused` versus `timeout` is the single most informative bit in this whole
 * file. A refusal is a packet — it proves the host exists, is routed, and chose
 * to say no; the service is simply not listening. A timeout is silence, and
 * silence has no author: it could be the router, a firewall, or the absence of
 * a route on the Docker host (arbitration A6).
 */
function probePort(host: string, port: number, timeoutMs = SWEEP_TIMEOUT_MS): Promise<{ state: PortState; ms: number }> {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = new net.Socket();
    let settled = false;

    const done = (state: PortState) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ state, ms: Date.now() - started });
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

    try {
      socket.connect({ host, port });
    } catch {
      done('timeout');
    }
  });
}

// ============================================================================
// Route: the local half, and the one A6 warns about
// ============================================================================

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

function intToIpv4(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** `/proc/net/route` stores addresses as little-endian hex. */
function leHexToInt(hex: string): number {
  const n = parseInt(hex, 16) >>> 0;
  return (
    (((n & 0xff) << 24) | ((n & 0xff00) << 8) | ((n & 0xff0000) >>> 8) | ((n & 0xff000000) >>> 24)) >>> 0
  );
}

/**
 * Which route this container would use for `host` — read straight from the
 * kernel, no binary involved.
 *
 * This is here because of arbitration A6: ObliWAN reaches the fleet through a
 * route that lives on the DOCKER HOST, and a container that has no matching
 * route produces exactly the symptom being diagnosed — a timeout with no
 * further evidence. When that is the cause, nothing on the router is wrong and
 * every minute spent looking at the router is wasted.
 */
async function findRoute(host: string): Promise<DiagnosticStep> {
  const started = Date.now();
  const dest = ipv4ToInt(host);
  if (dest === null) {
    return {
      step: 'route', label: `Local route to ${host}`, outcome: 'skipped',
      detail: 'Only IPv4 destinations are checked against the routing table.',
      ms: null,
    };
  }

  let table: string;
  try {
    table = await readFile('/proc/net/route', 'utf8');
  } catch {
    return {
      step: 'route', label: `Local route to ${host}`, outcome: 'unknown',
      detail: 'The kernel routing table is not readable here (this check runs on Linux only).',
      ms: Date.now() - started,
    };
  }

  let best: { iface: string; gateway: number; mask: number } | null = null;
  for (const line of table.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 8) continue;
    const destination = leHexToInt(f[1]);
    const gateway = leHexToInt(f[2]);
    const mask = leHexToInt(f[7]);
    if ((dest & mask) >>> 0 !== destination) continue;
    // Longest prefix wins, exactly as the kernel would choose.
    if (!best || mask >>> 0 > best.mask >>> 0) best = { iface: f[0], gateway, mask };
  }

  if (!best) {
    return {
      step: 'route', label: `Local route to ${host}`, outcome: 'fail',
      detail:
        `This container has NO route to ${host} — packets to it are dropped before they reach the `
        + 'network. ObliWAN reaches the fleet through a route that lives on the Docker HOST '
        + '(arbitration A6): check that the host has a route to this subnet via the L2TP tunnel, '
        + 'and that docker-compose.yml is not isolating this container from it.',
      ms: Date.now() - started,
    };
  }

  const via = best.gateway === 0 ? 'directly attached' : `via ${intToIpv4(best.gateway)}`;
  return {
    step: 'route', label: `Local route to ${host}`, outcome: 'ok',
    detail: `Routed ${via} on interface ${best.iface}. A route existing does not prove the path works end to end.`,
    ms: Date.now() - started,
  };
}

// ============================================================================
// The optional, privileged, weaker signals
// ============================================================================

function run(cmd: string, args: string[], timeoutMs: number): Promise<{ ok: boolean; out: string; missing: boolean }> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 256 * 1024 }, (err, stdout, stderr) => {
      const out = `${stdout ?? ''}${stderr ?? ''}`.trim();
      if (err && (err as NodeJS.ErrnoException).code === 'ENOENT') {
        resolve({ ok: false, out: '', missing: true });
        return;
      }
      resolve({ ok: !err, out, missing: false });
    });
  });
}

/**
 * ICMP, reported for what it is worth and no more.
 *
 * Kept because an operator asks for it and because a successful ping DOES
 * narrow things (the host is up and routed), but its failure proves almost
 * nothing: ICMP is filtered on most of the paths this product crosses. The
 * wording below never turns "no ICMP reply" into "the device is down".
 */
async function pingHost(host: string): Promise<DiagnosticStep> {
  const started = Date.now();
  const r = await run('ping', ['-c', '3', '-W', '1', '-n', host], PING_TIMEOUT_MS);
  const ms = Date.now() - started;

  if (r.missing) {
    return {
      step: 'icmp', label: `ICMP echo to ${host}`, outcome: 'unknown',
      detail: 'No ping binary in this image, so ICMP was not attempted.', ms,
    };
  }
  if (r.ok) {
    const rtt = /min\/avg\/max[^=]*=\s*([\d.]+)\/([\d.]+)/.exec(r.out);
    return {
      step: 'icmp', label: `ICMP echo to ${host}`, outcome: 'ok',
      detail: rtt
        ? `The host replies to ping (avg ${rtt[2]} ms). It is up and routed; this says nothing about the port.`
        : 'The host replies to ping. It is up and routed; this says nothing about the port.',
      ms,
    };
  }
  return {
    step: 'icmp', label: `ICMP echo to ${host}`, outcome: 'fail',
    detail:
      'No ICMP reply. This is WEAK evidence: ICMP is filtered on many paths, and a router that '
      + 'ignores ping can still serve its API perfectly. Read the TCP results below instead.',
    ms,
  };
}

/**
 * Traceroute, and why it is last and conditional.
 *
 * It is slow (a wall of timeouts costs the full budget), it is noisy through a
 * tunnel where every hop is NATed, and it answers a question the TCP sweep has
 * usually already settled. It runs only when everything else came back silent —
 * the one case where "how far do packets get" is genuinely the next question.
 */
async function traceHost(host: string): Promise<DiagnosticStep> {
  const started = Date.now();
  const r = await run('traceroute', ['-n', '-w', '1', '-q', '1', '-m', '8', host], TRACEROUTE_TIMEOUT_MS);
  const ms = Date.now() - started;

  if (r.missing) {
    return {
      step: 'traceroute', label: `Path to ${host}`, outcome: 'unknown',
      detail: 'No traceroute binary in this image, so the path was not traced.', ms,
    };
  }

  const hops = r.out.split('\n').map((l) => l.trim()).filter((l) => /^\d+\s/.test(l));
  if (hops.length === 0) {
    return {
      step: 'traceroute', label: `Path to ${host}`, outcome: 'unknown',
      detail: 'traceroute produced no readable hops.', ms,
    };
  }
  const lastAnswering = [...hops].reverse().find((h) => !/\*\s*$/.test(h));
  return {
    step: 'traceroute', label: `Path to ${host}`, outcome: lastAnswering ? 'ok' : 'fail',
    detail: lastAnswering
      ? `Packets reach at least: ${lastAnswering.replace(/\s+/g, ' ')}. Hops beyond it are silent — `
        + 'which is normal for a filtered path and not proof of a break.'
      : 'No hop on the path answered at all.',
    ms,
  };
}

// ============================================================================
// Synthesis — the sentence the operator reads first
// ============================================================================

function synthesise(
  target: { host: string; port: number | null },
  ports: PortProbe[],
  route: DiagnosticStep,
  icmp: DiagnosticStep | null,
): { verdict: string; hostAnswered: boolean } {
  const targetProbe = target.port === null ? null : ports.find((p) => p.port === target.port) ?? null;
  const others = ports.filter((p) => p.port !== target.port);
  const answering = ports.filter((p) => p.state === 'open' || p.state === 'refused');
  const hostAnswered = answering.length > 0;

  if (targetProbe?.state === 'open') {
    return {
      hostAnswered: true,
      verdict:
        `Port ${target.port} accepts connections. The network is not the problem — the channel `
        + 'failed after the socket opened, so look at the credential, the TLS setting or the '
        + "service's own access list (on RouterOS, `/ip/service` carries an allowed-address list "
        + 'that refuses a good password from the wrong source).',
    };
  }

  if (targetProbe?.state === 'refused') {
    return {
      hostAnswered: true,
      verdict:
        `The host answered and actively REFUSED port ${target.port}. It is up, routed and reachable; `
        + 'the service is simply not listening. On RouterOS the API service is DISABLED by default '
        + '— enable it with `/ip/service enable api` (or `api-ssl` for 8729) and confirm the port.',
    };
  }

  const openSiblings = others.filter((p) => p.state === 'open' || p.state === 'refused');
  if (targetProbe && targetProbe.state === 'timeout' && openSiblings.length > 0) {
    const list = openSiblings.map((p) => `${p.port} (${p.service}, ${p.state})`).join(', ');
    return {
      hostAnswered: true,
      verdict:
        `The host is alive and reachable — ${list} answered — but port ${target.port} is SILENTLY `
        + 'DROPPED. Silence rather than a refusal means a filter is eating the packets: a firewall '
        + 'rule on the router or on the path. If the service were merely off, this port would have '
        + 'been refused like the others.',
    };
  }

  if (route.outcome === 'fail') {
    return {
      hostAnswered: false,
      verdict:
        `Nothing answered, and this container has no route to ${target.host} at all. Fix the route `
        + 'before looking at the router: nothing you change on the equipment can help while packets '
        + 'never leave (arbitration A6 — the host route to the tunnel subnet).',
    };
  }

  if (!hostAnswered && icmp?.outcome === 'ok') {
    return {
      hostAnswered: false,
      verdict:
        'The host replies to ping but refuses to answer any TCP port we tried. Something between us '
        + 'and it is filtering TCP while letting ICMP through — a firewall on the path, or an '
        + 'address that now belongs to a different box than the one you think (D5: the tunnel IP is '
        + 'never an identity).',
    };
  }

  return {
    hostAnswered: false,
    verdict:
      `Nothing at ${target.host} answered — no port, no refusal, no ICMP. Either the site is down, `
      + 'the tunnel is not up, or this address no longer belongs to this device. Check the PPP '
      + 'session before anything else: a device whose tunnel is down is never dialled (D4).',
  };
}

// ============================================================================
// Entry point
// ============================================================================

/**
 * Diagnose one device's channel.
 *
 * Order matters and is not cosmetic: the cheap local checks run first (a
 * missing route makes every network result meaningless), the TCP sweep second
 * (it decides the verdict), and the two privileged, slow, weak probes last —
 * traceroute only when the sweep found silence, because that is the only case
 * where it adds anything.
 */
export async function diagnoseDevice(tenantId: number, deviceId: number): Promise<Diagnosis> {
  const device = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{ id: number; brand: string; tunnel_ip: string | null } | undefined>(
      'id', 'brand', 'tunnel_ip',
    );
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);

  // The target comes from the device's own rows. See the header: there is no
  // way for a caller to name an address here.
  const transport = await db('device_transports')
    .where({ device_id: deviceId })
    .orderBy('priority')
    .first<{ transport: string; host: string | null; port: number | null } | undefined>(
      'transport', 'host', 'port',
    );

  const host = transport?.host ?? device.tunnel_ip;
  if (!host) {
    throw new Error(
      'This device has no address to diagnose: no transport host and no tunnel IP are recorded.',
    );
  }

  const steps: DiagnosticStep[] = [];

  // ── 1. Name resolution, when there is a name at all ───────────────────────
  let resolved = host;
  if (!net.isIP(host)) {
    const started = Date.now();
    try {
      const addrs = await dns.lookup(host, { all: true });
      resolved = addrs[0]?.address ?? host;
      steps.push({
        step: 'dns', label: `Resolve ${host}`, outcome: 'ok',
        detail: `Resolves to ${addrs.map((a) => a.address).join(', ')}.`,
        ms: Date.now() - started,
      });
    } catch {
      steps.push({
        step: 'dns', label: `Resolve ${host}`, outcome: 'fail',
        detail:
          `${host} does not resolve from this container. Nothing else can succeed until it does — `
          + 'and an address is more robust than a name for equipment this product must reach when '
          + 'the network is already unwell.',
        ms: Date.now() - started,
      });
      return {
        deviceId, target: { host, port: transport?.port ?? null, transport: transport?.transport ?? 'none' },
        ports: [], steps,
        verdict: `The hostname ${host} cannot be resolved from the server, so no connection was attempted.`,
        hostAnswered: false,
      };
    }
  }

  // ── 2. Do we even have a route? (A6) ──────────────────────────────────────
  const route = await findRoute(resolved);
  steps.push(route);

  // ── 3. The sweep that decides the verdict ─────────────────────────────────
  const catalogue = BRAND_PORTS[device.brand] ?? FALLBACK_PORTS;
  const wanted = new Map<number, string>();
  if (transport?.port) wanted.set(transport.port, `${transport.transport} (this channel)`);
  for (const p of catalogue) if (!wanted.has(p.port)) wanted.set(p.port, p.service);

  const sweepStarted = Date.now();
  const ports: PortProbe[] = await Promise.all(
    [...wanted.entries()].map(async ([port, service]) => {
      const r = await probePort(resolved, port);
      return { port, service, state: r.state, ms: r.ms };
    }),
  );
  ports.sort((a, b) => a.port - b.port);
  const answering = ports.filter((p) => p.state === 'open' || p.state === 'refused');
  steps.push({
    step: 'tcp',
    label: `TCP probe of ${ports.length} ports on ${resolved}`,
    outcome: answering.length > 0 ? 'ok' : 'fail',
    detail: answering.length > 0
      ? `${answering.length} of ${ports.length} ports answered. An answer — even a refusal — proves `
        + 'the host exists and is routed.'
      : `None of the ${ports.length} ports answered. Silence has no author: it is equally consistent `
        + 'with a filter, a down site, and an address that moved.',
    ms: Date.now() - sweepStarted,
  });

  // ── 4. ICMP, for what it is worth ─────────────────────────────────────────
  const icmp = await pingHost(resolved);
  steps.push(icmp);

  // ── 5. Traceroute ONLY into silence ───────────────────────────────────────
  if (answering.length === 0 && route.outcome !== 'fail') {
    steps.push(await traceHost(resolved));
  } else {
    steps.push({
      step: 'traceroute', label: `Path to ${resolved}`, outcome: 'skipped',
      detail: answering.length > 0
        ? 'Skipped: the host already answered on TCP, so where packets die is not the question.'
        : 'Skipped: there is no route to trace along.',
      ms: null,
    });
  }

  const { verdict, hostAnswered } = synthesise(
    { host: resolved, port: transport?.port ?? null },
    ports, route, icmp,
  );

  logger.info(
    { deviceId, host: resolved, hostAnswered, ports: ports.map((p) => `${p.port}:${p.state}`).join(',') },
    'Channel diagnosis complete',
  );

  return {
    deviceId,
    target: { host: resolved, port: transport?.port ?? null, transport: transport?.transport ?? 'none' },
    ports,
    steps,
    verdict,
    hostAnswered,
  };
}
