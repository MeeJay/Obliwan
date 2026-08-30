/**
 * The SNMP trap listener (UDP/162).
 *
 * ┌─ ARBITRAGE A6: NEVER IDENTIFY A DEVICE BY THE SOURCE IP OF A TRAP. ───────┐
 * │ The Docker bridge NATs inbound traffic, so the source address on the      │
 * │ socket is a gateway address, not the router's. Even without Docker it     │
 * │ would be wrong: a CPE behind CGNAT, a site that failed over to its backup │
 * │ WAN, or two customers on overlapping RFC1918 space all break the mapping. │
 * │                                                                          │
 * │ AND IT FAILS IN THE WORST DIRECTION: a source-IP match does not fail to   │
 * │ identify, it identifies the WRONG device -- so an alert appears against a │
 * │ router that is perfectly healthy, and the one that is burning stays       │
 * │ silent.                                                                   │
 * │                                                                          │
 * │ `source_ip` IS stored, for forensics. It is never a join key. Attribution │
 * │ uses IDENTITY carried INSIDE the PDU: a sysName varbind matched against   │
 * │ `devices.system_identity` / `devices.name`. When nothing matches,         │
 * │ `device_id` stays NULL -- and an unattributed trap is exactly the one     │
 * │ worth keeping, which is why the column is nullable.                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The socket is the only unauthenticated input surface of the server. Three
 * consequences, all implemented below: a token-bucket rate limit BEFORE any
 * parsing, a bounded queue that DROPS rather than grows, and a decoder
 * (`ber.ts`) that bounds-checks every field.
 *
 * The community string in a v1/v2c trap is NOT authentication -- it travels in
 * clear and anyone can guess "public". It is decoded and deliberately NOT
 * stored: keeping it would put a credential-shaped string in a table that is
 * read on an incident screen, for no security benefit whatsoever.
 */

import dgram from 'dgram';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { snmpConfig } from './config';
import { decodeTrap, type DecodedVarbind } from './ber';
import { ensurePartitionFor, isMissingPartitionError } from './partition.service';

const SYS_NAME_OID = '1.3.6.1.2.1.1.5.0';

interface PendingTrap {
  ts: Date;
  sourceIp: string;
  version: number;
  trapOid: string;
  enterpriseOid: string | null;
  genericTrap: number | null;
  specificTrap: number | null;
  uptimeTicks: bigint | null;
  varbinds: DecodedVarbind[];
}

const stats = {
  received: 0,
  decoded: 0,
  malformed: 0,
  rateLimited: 0,
  v3Refused: 0,
  attributed: 0,
  stored: 0,
  dropped: 0,
};

export function trapStats(): typeof stats {
  return { ...stats };
}

// ============================================================================
// Rate limiting
// ============================================================================

/**
 * A token bucket, refilled continuously, checked BEFORE decoding.
 *
 * Checking after the parse would mean a flood still costs a full BER decode
 * per datagram -- which is the CPU sink the limit exists to prevent. The
 * bucket is global rather than per source precisely because the source
 * address is untrustworthy (A6): a per-source bucket is trivially defeated by
 * spoofing it.
 */
class TokenBucket {
  private tokens: number;
  private last = Date.now();

  constructor(private readonly ratePerSec: number) {
    this.tokens = ratePerSec;
  }

  take(): boolean {
    const now = Date.now();
    this.tokens = Math.min(this.ratePerSec, this.tokens + ((now - this.last) / 1000) * this.ratePerSec);
    this.last = now;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
}

// ============================================================================
// Attribution
// ============================================================================

/**
 * Resolve a device from what the trap SAYS it is, never from where it came.
 *
 * `system_identity` (RouterOS) and `name` are compared case-insensitively; a
 * value matching more than one device resolves to NONE, because a wrong
 * attribution is worse than no attribution.
 */
export async function attributeTrap(varbinds: DecodedVarbind[]): Promise<number | null> {
  const sysName = varbinds.find((v) => v.oid === SYS_NAME_OID && typeof v.value === 'string');
  const identity = typeof sysName?.value === 'string' ? sysName.value.trim() : '';
  if (identity.length === 0) return null;

  const matches = await db('devices')
    .whereRaw('lower(system_identity) = lower(?)', [identity])
    .orWhereRaw('lower(name) = lower(?)', [identity])
    .limit(2)
    .select('id');
  return matches.length === 1 ? matches[0].id : null;
}

// ============================================================================
// Persistence
// ============================================================================

async function persist(batch: PendingTrap[]): Promise<number> {
  if (batch.length === 0) return 0;
  const rows = await Promise.all(
    batch.map(async (t) => ({
      ts: t.ts.toISOString(),
      uptime_ticks: t.uptimeTicks === null ? null : t.uptimeTicks.toString(),
      device_id: await attributeTrap(t.varbinds),
      specific_trap: t.specificTrap,
      generic_trap: t.genericTrap,
      version: t.version,
      source_ip: t.sourceIp,
      trap_oid: t.trapOid,
      enterprise_oid: t.enterpriseOid,
      varbinds: JSON.stringify(
        t.varbinds.map((v) => ({
          oid: v.oid,
          type: v.type,
          value: typeof v.value === 'bigint' ? v.value.toString() : v.value,
        })),
      ),
      parsed: JSON.stringify({}),
    })),
  );
  stats.attributed += rows.filter((r) => r.device_id !== null).length;

  const insert = (): Promise<unknown> => db('snmp_traps').insert(rows);
  try {
    await insert();
  } catch (err) {
    if (!isMissingPartitionError(err)) throw err;
    await ensurePartitionFor('snmp_traps', batch[0].ts);
    await insert();
  }
  stats.stored += rows.length;
  return rows.length;
}

// ============================================================================
// The listener
// ============================================================================

let socket: dgram.Socket | null = null;
let bucket: TokenBucket | null = null;
let queue: PendingTrap[] = [];
let flushTimer: NodeJS.Timeout | null = null;

/**
 * Traps are batched for one second before insertion.
 *
 * A trap storm is the norm, not the exception: one flapping BGP session emits
 * hundreds in a minute. One INSERT per datagram would give the database a
 * transaction per trap at the exact moment it is also absorbing a poll cycle.
 */
function scheduleFlush(): void {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    const batch = queue;
    queue = [];
    if (batch.length === 0) return;
    void persist(batch).catch((err) => {
      stats.dropped += batch.length;
      logger.error({ err, count: batch.length }, 'Trap batch failed — traps lost');
    });
  }, 1_000);
  flushTimer.unref();
}

export function startTrapReceiver(): void {
  if (socket || !snmpConfig.trapEnabled) return;
  bucket = new TokenBucket(snmpConfig.trapRateLimit);

  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  socket = sock;

  sock.on('message', (msg, rinfo) => {
    stats.received += 1;
    if (!bucket!.take()) {
      stats.rateLimited += 1;
      return;
    }
    // The bound is on the QUEUE, not on the socket: shedding here is a
    // counted, deliberate loss. An unbounded queue in front of a slow
    // database turns a trap storm into an OOM kill, and losing the whole
    // supervision is worse than losing traps.
    if (queue.length >= snmpConfig.syslogQueueMax) {
      stats.dropped += 1;
      return;
    }

    const decoded = decodeTrap(msg);
    if (!decoded) {
      stats.malformed += 1;
      return;
    }
    if (decoded.version === 3) {
      // USM authentication is not implemented. Storing a v3 trap without
      // verifying it would display it as authenticated, which is strictly
      // worse than refusing it.
      stats.v3Refused += 1;
      return;
    }
    stats.decoded += 1;

    queue.push({
      ts: new Date(),
      sourceIp: rinfo.address,
      version: decoded.version,
      trapOid: decoded.trapOid ?? '0.0',
      enterpriseOid: decoded.enterprise,
      genericTrap: decoded.genericTrap,
      specificTrap: decoded.specificTrap,
      uptimeTicks: decoded.uptimeTicks,
      varbinds: decoded.varbinds,
    });
    scheduleFlush();
  });

  sock.on('error', (err) => {
    // EACCES on 162 is the common one: a container without NET_BIND_SERVICE
    // cannot bind a privileged port. It must be a loud, specific message, not
    // a silent absence of traps that gets diagnosed six months later.
    logger.error({ err, port: snmpConfig.trapPort }, 'Trap receiver socket error');
    try {
      sock.close();
    } catch {
      /* already closing */
    }
    socket = null;
  });

  sock.bind(snmpConfig.trapPort, snmpConfig.trapBind, () => {
    logger.info(
      { port: snmpConfig.trapPort, bind: snmpConfig.trapBind, rateLimit: snmpConfig.trapRateLimit },
      'SNMP trap receiver listening (source IP is NEVER used to identify a device — A6)',
    );
  });
}

export function stopTrapReceiver(): void {
  if (flushTimer) clearTimeout(flushTimer);
  flushTimer = null;
  queue = [];
  if (socket) {
    try {
      socket.close();
    } catch {
      /* already closed */
    }
  }
  socket = null;
}

/** Exposed for the bench: decode + enqueue without a socket. */
export async function ingestTrapDatagram(msg: Buffer, sourceIp: string): Promise<boolean> {
  const decoded = decodeTrap(msg);
  if (!decoded || decoded.version === 3) return false;
  await persist([
    {
      ts: new Date(),
      sourceIp,
      version: decoded.version,
      trapOid: decoded.trapOid ?? '0.0',
      enterpriseOid: decoded.enterprise,
      genericTrap: decoded.genericTrap,
      specificTrap: decoded.specificTrap,
      uptimeTicks: decoded.uptimeTicks,
      varbinds: decoded.varbinds,
    },
  ]);
  return true;
}
