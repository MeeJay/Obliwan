/**
 * ObliWAN — M8 syslog throughput bench.
 *
 * The study calls the syslog "the real bottleneck of M3" (§5.5) and the
 * receiver carries four defences against it. This measures them instead of
 * asserting them, against a REAL Postgres and a REAL UDP socket.
 *
 * Two phases, because they answer two different questions and mixing them
 * produces a number that means nothing:
 *
 *   A. THE SOCKET. How many of N blasted datagrams the process even sees. The
 *      answer on loopback is "not all of them", and that is the honest headline
 *      of the whole milestone: UDP syslog loses messages under load, which is
 *      exactly why M8 added a TCP listener and a `/log` pull for the one
 *      message class attribution cannot do without.
 *
 *   B. THE PIPELINE. Admission + parse + severity floor + batched INSERT, with
 *      the socket taken out of the picture, which is the number that tells you
 *      whether the database can keep up with a fleet.
 *
 * Run:
 *   DATABASE_URL=postgres://... SYSLOG_RATE_LIMIT_PER_SOURCE=100000 \
 *   SYSLOG_DAILY_QUOTA=100000000 npx tsx src/services/logs/testing/bench.ts [n]
 *
 * (The two env vars lift the per-source limiter out of the way so the bench
 * measures the pipeline rather than the limiter. Their defaults — 50/s and
 * 50 000/day — are what a real deployment runs, and the limiter working is
 * verified separately in phase C.)
 */

import dgram from 'dgram';
import { db } from '../../../db';
import { snmpConfig } from '../../snmp/config';
import {
  flushSyslog,
  ingestSyslogBatch,
  startSyslogReceiver,
  stopSyslogReceiver,
  syslogStats,
} from '../../snmp/syslogReceiver';

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function frame(severity: number, host: string, tag: string, msg: string): string {
  return `<${16 * 8 + severity}>Aug 29 10:22:11 ${host} ${tag}: ${msg}`;
}

const ABOVE = frame(3, 'BENCH-1', 'system,error', 'interface ether1 link down');
const BELOW = frame(7, 'BENCH-1', 'dhcp,debug', 'offering lease 10.1.1.55 to 00:0c:29:1a:2b:3c');

function delta(after: Record<string, number>, before: Record<string, number>, k: string): number {
  return (after[k] ?? 0) - (before[k] ?? 0);
}

async function main(): Promise<void> {
  const total = Number(process.argv[2] ?? 20_000);

  // ── A. the socket ────────────────────────────────────────────────────────
  await db.raw('DELETE FROM syslog_messages');
  const beforeA = syslogStats() as unknown as Record<string, number>;
  startSyslogReceiver();
  await sleep(200);

  const sock = dgram.createSocket('udp4');
  const payload = Buffer.from(ABOVE);
  const startedA = Date.now();
  for (let i = 0; i < total; i += 1) {
    sock.send(payload, snmpConfig.syslogPort, '127.0.0.1');
    if (i % 200 === 0) await sleep(0);
  }
  await sleep(1500);
  await flushSyslog();
  const elapsedA = Date.now() - startedA;
  const afterA = syslogStats() as unknown as Record<string, number>;
  const receivedA = delta(afterA, beforeA, 'received');
  sock.close();
  stopSyslogReceiver();

  console.log('\n== A. UDP socket ==');
  console.log(`  sent                 ${total}`);
  console.log(`  received             ${receivedA}`);
  console.log(
    `  lost in the kernel   ${total - receivedA} (${(((total - receivedA) / total) * 100).toFixed(1)} %)`,
  );
  console.log(`  wall clock           ${elapsedA} ms`);
  console.log(
    '  -> UDP syslog is lossy under load. A dropped counter line is a gap in a graph;',
  );
  console.log(
    '     a dropped LOGIN line is a change attributed to nobody. Hence TCP/514 and /log.',
  );

  // ── B. the pipeline ──────────────────────────────────────────────────────
  await db.raw('DELETE FROM syslog_messages');
  const beforeB = syslogStats() as unknown as Record<string, number>;
  const lines: string[] = [];
  for (let i = 0; i < total; i += 1) lines.push(i % 2 === 0 ? ABOVE : BELOW);

  const startedB = Date.now();
  const admitted = await ingestSyslogBatch(lines, '172.17.0.1');
  const elapsedB = Date.now() - startedB;
  const afterB = syslogStats() as unknown as Record<string, number>;
  const storedRows = await db('syslog_messages').count<{ count: string }[]>('* as count');

  console.log('\n== B. admission + parse + floor + batched INSERT ==');
  console.log(`  offered              ${total}`);
  console.log(`  admitted             ${admitted}`);
  console.log(`  below floor, dropped ${delta(afterB, beforeB, 'belowFloor')}`);
  console.log(`  kept as account      ${delta(afterB, beforeB, 'belowFloorKeptAccount')}`);
  console.log(`  written to Postgres  ${storedRows[0].count}`);
  console.log(`  wall clock           ${elapsedB} ms`);
  console.log(
    `  sustained            ${Math.round((total / elapsedB) * 1000)} msg/s offered, ` +
      `${Math.round((admitted / elapsedB) * 1000)} msg/s written`,
  );

  // ── C. the limiter bites ────────────────────────────────────────────────
  // Offered from a source that has never spoken, at twice its configured
  // per-second budget, in well under a second. Whatever the limiter is set to,
  // roughly that many messages get through and the rest are counted as shed —
  // a bench that only ever ran with the guards lifted would prove they compile.
  const beforeC = syslogStats() as unknown as Record<string, number>;
  const burst = snmpConfig.syslogRateLimitPerSource * 2 + 100;
  await ingestSyslogBatch(Array.from({ length: burst }, () => ABOVE), '198.51.100.7');
  const afterC = syslogStats() as unknown as Record<string, number>;
  console.log('\n== C. per-source limiter, from a fresh source ==');
  console.log(`  offered              ${burst} (2x the configured budget, in one burst)`);
  console.log(`  accepted             ${delta(afterC, beforeC, 'accepted')}`);
  console.log(`  rate limited         ${delta(afterC, beforeC, 'rateLimited')}`);
  console.log(`  quota suppressed     ${delta(afterC, beforeC, 'quotaSuppressed')}`);
  console.log(`  queue dropped        ${delta(afterC, beforeC, 'queueDropped')}`);
  console.log(
    `  config               floor=${snmpConfig.syslogSeverityFloor} ` +
      `perSourceRate=${snmpConfig.syslogRateLimitPerSource}/s ` +
      `dailyQuota=${snmpConfig.syslogDailyQuota} ` +
      `queueMax=${snmpConfig.syslogQueueMax} batch=${snmpConfig.syslogFlushBatch}`,
  );

  await db.raw('DELETE FROM syslog_messages');
  await db.destroy();
}

main().catch(async (err) => {
  console.error(err);
  await db.destroy().catch(() => undefined);
  process.exit(1);
});
