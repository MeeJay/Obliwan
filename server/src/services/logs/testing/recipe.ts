/**
 * ObliWAN — the M8 acceptance test, end to end.
 *
 * The milestone recipe, verbatim from the assignment:
 *
 *   "modification manuelle simulée -> drift attribué au bon compte et à la
 *    bonne IP ; une modification sans trace -> `unattributed` explicite ;
 *    coupure du concentrateur -> 1 alerte et pas N ; un signal manquant ->
 *    `UNREACHABLE` et surtout PAS `SITE_DOWN`."
 *
 * Run against a REAL PostgreSQL with all migrations applied. The syslog goes
 * through the REAL receiver — a real UDP-less admission path for the push case
 * and a REAL TCP socket on a real port for the RFC 6587 case — so the severity
 * floor, the token bucket and the framing are exercised rather than described.
 *
 * WHAT IS NOT REAL, STATED PLAINLY: there is no MikroTik, DrayTek, Zyxel or
 * SonicWall on this machine and none in the project. The `/log` PULL path is
 * therefore covered by its pure half only (`selftest.ts`), and the syslog lines
 * below are the wordings those firmwares emit, typed by hand. What this proves
 * is that our side of the contract is correct; it does not prove that a Vigor
 * says what we think it says.
 *
 * Run:
 *   DATABASE_URL=postgres://... npx tsx src/services/logs/testing/recipe.ts
 *
 * It DELETES the contents of the tables it uses and refuses to run against a
 * database whose URL is not obviously a throwaway.
 */

import net from 'net';
import { createHash } from 'crypto';
import { db } from '../../../db';
import {
  flushSyslog,
  ingestSyslogLine,
  startSyslogReceiver,
  stopSyslogReceiver,
  syslogStats,
} from '../../snmp/syslogReceiver';
import { snmpConfig } from '../../snmp/config';
import { logsConfig } from '../config';
import { listLoginEvents, purgeOldLoginEvents } from '../loginEvents.service';
import { listLogs, unattributedSources, ingestHealth } from '../logs.service';
import { attributeRun, attributePendingRuns, getAttributionForRun } from '../../drift/attribution.service';
import {
  assessDevice,
  markConcentratorDegraded,
  probeDevice,
  enableExternalProbe,
} from '../../fleet/reachability.service';

let passed = 0;
const failures: string[] = [];
const notes: string[] = [];

function check(label: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed += 1;
    console.log(`  ok    ${label}`);
    return;
  }
  const line = `${label}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`;
  failures.push(line);
  console.log(`  FAIL  ${line}`);
}

function eq(label: string, actual: unknown, expected: unknown): void {
  check(label, Object.is(actual, expected), { actual, expected });
}

function note(text: string): void {
  notes.push(text);
  console.log(`  note  ${text}`);
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const iso = (d: Date): string => d.toISOString();

/** A syslog frame. Facility local0 (16), severity as given. */
function frame(severity: number, host: string, tag: string, msg: string, when: Date): string {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const pad = (n: number): string => String(n).padStart(2, '0');
  const stamp =
    `${months[when.getUTCMonth()]} ${String(when.getUTCDate()).padStart(2, ' ')} ` +
    `${pad(when.getUTCHours())}:${pad(when.getUTCMinutes())}:${pad(when.getUTCSeconds())}`;
  return `<${16 * 8 + severity}>${stamp} ${host} ${tag}: ${msg}`;
}

const TENANT = 1;
const OTHER_TENANT_SLUG = 'm8-other-msp';

function hash(seed: string): string {
  return createHash('sha256').update(seed).digest('hex');
}

async function main(): Promise<void> {
  const url = process.env.DATABASE_URL ?? '';
  if (!/localhost|127\.0\.0\.1|10\.0\.0\.152/.test(url)) {
    throw new Error('Refusing to run: DATABASE_URL does not look like a throwaway database.');
  }

  console.log('\n== 0. clean slate ==');
  await db('drift_attributions').del();
  await db('drift_findings').del();
  await db('drift_runs').del();
  await db('device_login_events').del();
  await db('routeros_log_cursors').del();
  await db('external_probe_state').del();
  await db('config_snapshots').del();
  await db('reachability_verdicts').del();
  await db('ppp_sessions').del();
  await db('discoveries').del();
  await db('device_health').del();
  await db('device_transports').del();
  await db.raw('DELETE FROM syslog_messages');
  await db.raw('DELETE FROM snmp_traps');
  await db('devices').update({ concentrator_id: null });
  await db('devices').del();
  await db('sites').del();
  console.log('  tables emptied');

  let tenant = await db('tenants').where({ id: TENANT }).first<{ id: number } | undefined>('id');
  if (!tenant) {
    const [created] = await db('tenants')
      .insert({ name: 'M8 MSP', slug: 'm8-msp' })
      .returning<Array<{ id: number }>>('id');
    tenant = created;
  }
  const tenantId = tenant.id;

  const [site] = await db('sites')
    .insert({ tenant_id: tenantId, name: 'Lyon Nord', code: 'LYN' })
    .returning<Array<{ id: number }>>('id');

  const [chr] = await db('devices')
    .insert({
      tenant_id: tenantId,
      site_id: site.id,
      name: 'CHR-CENTRAL',
      brand: 'mikrotik',
      family: 'mikrotik_routeros7',
      role: 'concentrator',
      status: 'active',
      system_identity: 'CHR-CENTRAL',
    })
    .returning<Array<{ id: number }>>('id');

  // Three CPEs behind the concentrator, plus 297 more further down so the
  // "1 alert, not N" claim is measured against a number worth measuring.
  const cpeRows = Array.from({ length: 300 }, (_, i) => ({
    tenant_id: tenantId,
    site_id: site.id,
    name: `site-${String(i + 1).padStart(3, '0')}`,
    brand: 'mikrotik',
    family: 'mikrotik_routeros7',
    role: 'cpe',
    status: 'active',
    concentrator_id: chr.id,
    ppp_username: `site-${String(i + 1).padStart(3, '0')}`,
    system_identity: `RTR-${String(i + 1).padStart(3, '0')}`,
  }));
  const cpes = await db('devices').insert(cpeRows).returning<Array<{ id: number }>>('id');
  const rtr1 = cpes[0].id;
  const rtr2 = cpes[1].id;
  console.log(`  1 concentrator + ${cpes.length} CPEs seeded`);

  // ==========================================================================
  console.log('\n== 1. syslog ingestion: floor, exception, attribution, TCP ==');
  // ==========================================================================

  const t0 = new Date();
  const before = syslogStats();

  // A debug line, far below the floor and NOT account activity: must never be
  // written. This is the 1.04 GB/day the whole design exists to avoid.
  await ingestSyslogLine(
    frame(7, 'RTR-001', 'dhcp,debug', 'dhcp-server offering lease 10.1.1.55', t0),
    '172.17.0.1',
  );

  // A RouterOS login at severity `info` (6) — BELOW the default floor of 5.
  // Without the account exception this line is dropped and K6 never sees a
  // single MikroTik login on the push path.
  const loginAt = new Date(t0.getTime() + 1000);
  await ingestSyslogLine(
    frame(6, 'RTR-001', 'system,info,account',
      'user noc-alice logged in from 10.20.30.40 via winbox', loginAt),
    '172.17.0.1',
  );
  await flushSyslog();

  const after = syslogStats();
  eq('the debug line was filtered AT INGESTION', after.belowFloor - before.belowFloor, 1);
  eq(
    'the info-level account line was kept by the one exception',
    after.belowFloorKeptAccount - before.belowFloorKeptAccount,
    1,
  );
  eq('one login event was extracted', after.loginEvents - before.loginEvents, 1);

  const stored = await db('syslog_messages').count<{ count: string }[]>('* as count');
  eq('exactly one syslog row was written', stored[0].count, '1');

  const logins = await listLoginEvents(tenantId, { deviceId: rtr1 });
  eq('the login was attributed to the device by HOSTNAME, not by source IP', logins.length, 1);
  eq('...to the right account', logins[0].account, 'noc-alice');
  eq('...with the OPERATOR address, not the docker gateway', logins[0].sourceIp, '10.20.30.40');
  check(
    '...and the datagram source (172.17.0.1, the bridge) is nowhere in the event',
    logins[0].sourceIp !== '172.17.0.1',
  );
  eq('...through the right door', logins[0].method, 'winbox');
  eq('...and it is not a shared account', logins[0].sharedAccount, false);

  // -- the same event again, through the pull path's key ---------------------
  await ingestSyslogLine(
    frame(6, 'RTR-001', 'system,info,account',
      'user noc-alice logged in from 10.20.30.40 via winbox', loginAt),
    '172.17.0.1',
  );
  await flushSyslog();
  const afterDup = await listLoginEvents(tenantId, { deviceId: rtr1 });
  eq('the same login seen twice is stored once', afterDup.length, 1);

  // -- an unknown sender ----------------------------------------------------
  await ingestSyslogLine(
    frame(4, 'RTR-UNKNOWN-999', 'system,error', 'something is wrong', new Date()),
    '172.17.0.1',
  );
  await flushSyslog();
  const orphan = await db('syslog_messages').whereNull('device_id').count<{ count: string }[]>('* as count');
  eq('an unmatched hostname leaves device_id NULL rather than guessing', orphan[0].count, '1');
  const sources = await unattributedSources(24);
  eq('the unattributed feed shows the sender', sources.length, 1);
  eq('...by the name it claims', sources[0].hostname, 'RTR-UNKNOWN-999');
  check(
    '...and carries no message body (it belongs to no tenant)',
    !Object.prototype.hasOwnProperty.call(sources[0], 'message'),
  );

  // -- TCP/514, both RFC 6587 framings, on a real socket --------------------
  {
    // `logsConfig` is read at module load, so the port cannot be changed from
    // here — the test dials the port the receiver actually bound. Set
    // SYSLOG_TCP_PORT in the environment to move it off 514 on a host where
    // binding a privileged port is not allowed.
    const testPort = logsConfig.syslogTcpPort;
    startSyslogReceiver();
    await sleep(250);

    const lfLine = frame(4, 'RTR-002', 'system,error', 'tcp-lf-framing', new Date());
    const countedLine = frame(4, 'RTR-002', 'system,error', 'tcp-octet-counting', new Date());
    const payload = `${lfLine}\n${Buffer.byteLength(countedLine)} ${countedLine}`;

    await new Promise<void>((resolve, reject) => {
      const sock = net.createConnection({ host: '127.0.0.1', port: testPort }, () => {
        sock.write(payload, () => {
          sock.end();
          resolve();
        });
      });
      sock.on('error', reject);
      setTimeout(() => reject(new Error('tcp connect timed out')), 3000);
    }).catch((err) => {
      note(`TCP framing case skipped: ${err instanceof Error ? err.message : String(err)}`);
    });

    await sleep(300);
    await flushSyslog();
    const tcpRows = await db('syslog_messages')
      .where('msg', 'like', 'tcp-%')
      .orderBy('msg')
      .select<{ msg: string; device_id: number | null }[]>('msg', 'device_id');
    eq('TCP: both RFC 6587 framings were assembled', tcpRows.length, 2);
    // Ordered by msg: 'tcp-lf-framing' sorts before 'tcp-octet-counting'.
    eq('TCP: LF-delimited frame', tcpRows[0]?.msg, 'tcp-lf-framing');
    eq('TCP: octet-counted frame', tcpRows[1]?.msg, 'tcp-octet-counting');
    eq('TCP: attributed through the same hostname path', tcpRows[0]?.device_id, rtr2);
    stopSyslogReceiver();
  }

  const health = ingestHealth();
  check('ingest health exposes the queue bound, not just a counter', health.queueMax > 0);
  eq('...and the floor it is enforcing', health.severityFloor, snmpConfig.syslogSeverityFloor);

  // ==========================================================================
  console.log('\n== 2. a manual modification is attributed to the right account and IP ==');
  // ==========================================================================

  // The story: we confirmed the config unchanged at T-20min; someone logged in
  // at T-15min through Winbox; we captured a different config at T-10min.
  const now = Date.now();
  const confirmedAt = new Date(now - 20 * 60_000);
  const capturedAt = new Date(now - 10 * 60_000);

  const [snapA] = await db('config_snapshots')
    .insert({
      device_id: rtr1, source: 'ssh', ncm: JSON.stringify({ v: 1 }), ncm_hash: hash('A'),
      ncm_version: 1, normalization_epoch: 'a'.repeat(16),
      captured_at: new Date(now - 60 * 60_000), last_seen_at: confirmedAt,
    })
    .returning<Array<{ id: string }>>('id');
  const [snapB] = await db('config_snapshots')
    .insert({
      device_id: rtr1, source: 'ssh', ncm: JSON.stringify({ v: 2 }), ncm_hash: hash('B'),
      ncm_version: 1, normalization_epoch: 'a'.repeat(16),
      captured_at: capturedAt, last_seen_at: capturedAt,
    })
    .returning<Array<{ id: string }>>('id');
  void snapA;

  // The login that explains it: five minutes after the last confirmation.
  const manualAt = new Date(now - 15 * 60_000);
  await ingestSyslogLine(
    frame(6, 'RTR-001', 'system,info,account',
      'user noc-bob logged in from 10.20.30.41 via winbox', manualAt),
    '172.17.0.1',
  );
  await flushSyslog();
  // `ingestSyslogLine` stamps OUR clock, which is now — move the event to when
  // it actually happened, exactly as a live deployment would have recorded it.
  await db('device_login_events')
    .where({ device_id: rtr1, account: 'noc-bob' })
    .update({ ts: manualAt });

  const [run1] = await db('drift_runs')
    .insert({
      device_id: rtr1, snapshot_id: snapB.id, status: 'drifted', cause: 'scheduled',
      findings_count: 3, started_at: capturedAt, finished_at: capturedAt,
    })
    .returning<Array<{ id: string }>>('id');

  const attr1 = await attributeRun(String(run1.id));
  eq('drift attributed', attr1?.verdict, 'attributed');
  eq('...to the right account', attr1?.account, 'noc-bob');
  eq('...and the right IP', attr1?.sourceIp, '10.20.30.41');
  eq('...through the right door', attr1?.method, 'winbox');
  check('...with a usable score', (attr1?.score ?? 0) >= 0.55, { score: attr1?.score });
  check(
    '...and a window that starts at the last CONFIRMATION, not 24 h ago',
    Math.abs(new Date(attr1!.window.from).getTime() - confirmedAt.getTime()) < 1000,
    { from: attr1?.window.from, confirmedAt: iso(confirmedAt) },
  );
  eq('...spanning exactly the interval the change could have happened in',
    attr1?.window.spanSeconds, 600);
  note(`window span = ${attr1?.window.spanSeconds}s, candidates = ${attr1?.candidates.length}`);

  // The earlier noc-alice login is outside the window and must not compete.
  eq('a login from before the last confirmation is not a candidate', attr1?.candidates.length, 1);

  // ==========================================================================
  console.log('\n== 3. a change with no trace is `unattributed`, explicitly ==');
  // ==========================================================================

  const [snapC] = await db('config_snapshots')
    .insert({
      device_id: rtr2, source: 'ssh', ncm: JSON.stringify({ v: 1 }), ncm_hash: hash('C'),
      ncm_version: 1, normalization_epoch: 'a'.repeat(16),
      captured_at: new Date(now - 60 * 60_000), last_seen_at: confirmedAt,
    })
    .returning<Array<{ id: string }>>('id');
  void snapC;
  const [snapD] = await db('config_snapshots')
    .insert({
      device_id: rtr2, source: 'ssh', ncm: JSON.stringify({ v: 2 }), ncm_hash: hash('D'),
      ncm_version: 1, normalization_epoch: 'a'.repeat(16),
      captured_at: capturedAt, last_seen_at: capturedAt,
    })
    .returning<Array<{ id: string }>>('id');

  const [run2] = await db('drift_runs')
    .insert({
      device_id: rtr2, snapshot_id: snapD.id, status: 'drifted', cause: 'scheduled',
      findings_count: 1, started_at: capturedAt, finished_at: capturedAt,
    })
    .returning<Array<{ id: string }>>('id');

  const attr2 = await attributeRun(String(run2.id));
  eq('a change nobody logged in for is unattributed', attr2?.verdict, 'unattributed');
  eq('...and the row EXISTS: "we looked and found nobody" is a result', attr2 !== null, true);
  eq('...naming the reason', attr2?.reason, 'no_login_event_in_window');
  eq('...and naming NOBODY', attr2?.account, null);
  eq('...with no login event attached either', attr2?.loginEventId, null);

  // -- and the two failure modes it must not slide into ---------------------
  {
    // Two operators in the same window: `ambiguous`, not a coin toss.
    const amb = new Date(now - 14 * 60_000);
    for (const [account, ip] of [['noc-carol', '10.20.30.42'], ['noc-dave', '10.20.30.43']]) {
      await ingestSyslogLine(
        frame(6, 'RTR-002', 'system,info,account',
          `user ${account} logged in from ${ip} via ssh`, amb),
        '172.17.0.1',
      );
    }
    await flushSyslog();
    await db('device_login_events').where({ device_id: rtr2 }).update({ ts: amb });

    const amb2 = await attributeRun(String(run2.id), { force: true });
    eq('two operators in the window -> ambiguous', amb2?.verdict, 'ambiguous');
    eq('...naming nobody', amb2?.account, null);
    eq('...but showing both candidates', amb2?.candidates.length, 2);
  }

  {
    // A change made by one of OUR OWN jobs is `platform`, never a human.
    const [job] = await db('change_jobs')
      .insert({
        tenant_id: tenantId, device_id: rtr2, kind: 'export', status: 'succeeded',
        base_state_hash: 'f'.repeat(64), safety_level: 'armed',
        // `change_jobs_started_chk`: a job cannot have started without a lease.
        claimed_by: 'recipe:0:0', claimed_at: new Date(now - 13 * 60_000),
        started_at: new Date(now - 13 * 60_000), finished_at: new Date(now - 12 * 60_000),
      })
      .returning<Array<{ id: string }>>('id');
    const plat = await attributeRun(String(run2.id), { force: true });
    eq('our own change job wins over any human candidate', plat?.verdict, 'platform');
    eq('...and points at the job', plat?.changeJobId, String(job.id));
    eq('...naming no human', plat?.account, null);
    await db('change_jobs').where({ id: job.id }).del();
  }

  {
    // A run caused by OUR re-normalisation is excluded by construction (§6.5).
    await db('drift_runs').where({ id: run2.id }).update({ cause: 'renormalization' });
    const excl = await attributeRun(String(run2.id), { force: true });
    eq('a renormalization run is excluded from attribution', excl?.verdict, 'excluded');
    eq('...and says so', excl?.reason, 'cause_renormalization');
    await db('drift_runs').where({ id: run2.id }).update({ cause: 'scheduled' });
  }

  {
    // The database itself refuses a named `unattributed` row.
    let refused = false;
    try {
      await db('drift_attributions')
        .where({ run_id: run2.id })
        .update({ verdict: 'unattributed', account: 'somebody' });
    } catch {
      refused = true;
    }
    check('the CHECK constraint refuses to let a non-attributed row name an account', refused);
  }

  // The sweep picks up whatever has no attribution yet.
  await db('drift_attributions').del();
  const swept = await attributePendingRuns(100);
  eq('the sweep attributed both drifted runs', swept.processed, 2);
  const back = await getAttributionForRun(tenantId, String(run1.id));
  eq('and the tenant-scoped read finds it', back?.account, 'noc-bob');

  // ==========================================================================
  console.log('\n== 4. concentrator outage: ONE alert, not N ==');
  // ==========================================================================

  await db('reachability_verdicts').del();
  const degraded = await markConcentratorDegraded(chr.id, 'simulated concentrator outage');
  eq('the concentrator itself is marked', degraded.concentrator.verdict, 'CONCENTRATOR_DEGRADED');
  check('...and that verdict IS written: it is the one alert', degraded.concentrator.written);
  eq('...covering every child', degraded.suppressedChildren, cpes.length);

  // THE REGRESSION: a re-assessment sweep over the children while the parent is
  // degraded. Before M8 this call site passed no context and wrote one verdict
  // per child — 300 pages from one outage.
  let written = 0;
  for (const cpe of cpes) {
    const r = await assessDevice(cpe.id);
    if (r.written) written += 1;
    if (r.verdict !== 'CONCENTRATOR_DEGRADED') {
      check(`child ${cpe.id} suppressed`, false, r.verdict);
      break;
    }
  }
  eq('a full re-assessment of 300 children writes ZERO extra verdicts', written, 0);

  const rows = await db('reachability_verdicts').count<{ count: string }[]>('* as count');
  eq('total verdict rows for the whole outage: 1', rows[0].count, '1');
  note(`1 alert instead of ${cpes.length} — suppression ratio ${cpes.length}:1`);

  // ==========================================================================
  console.log('\n== 5. a missing signal is UNREACHABLE, never SITE_DOWN ==');
  // ==========================================================================

  await db('reachability_verdicts').del();
  // The concentrator recovers: its degraded verdict is superseded.
  await db('reachability_verdicts').insert({
    device_id: chr.id, ts: new Date(), ppp_up: true, verdict: 'UP', confidence: 0.25,
    reason: 'ppp_up_only',
  });

  // rtr1 has a PPP username but no open session -> pppUp = false. No SNMP
  // target, no external probe: two signals unmeasured.
  const v1 = await assessDevice(rtr1);
  eq('tunnel down, nothing else measured -> UNREACHABLE', v1.verdict, 'UNREACHABLE');
  check('and above all NOT SITE_DOWN', v1.verdict !== 'SITE_DOWN');
  eq('the unmeasured signals are null, not false', v1.signals.externalOk, null);
  eq('...both of them', v1.signals.snmpOk, null);

  // Now give it an external probe that has NEVER succeeded and has failed hard.
  await enableExternalProbe(rtr1, { targetIp: '203.0.113.201', port: 9, intervalSec: 60 });
  await db('external_probe_state')
    .where({ device_id: rtr1 })
    .update({ last_probe_at: new Date(), consecutive_failures: 10, baseline_ok_at: null });
  const v2 = await assessDevice(rtr1);
  eq(
    'a probe that has NEVER worked reports null, not false — still UNREACHABLE',
    v2.verdict,
    'UNREACHABLE',
  );
  check('a firewall that always dropped us cannot manufacture SITE_DOWN', v2.verdict !== 'SITE_DOWN');
  eq('...because the signal itself refuses to be false without a baseline', v2.signals.externalOk, null);

  // Give it a baseline: it HAS worked before. Now a sustained failure is real.
  await db('external_probe_state')
    .where({ device_id: rtr1 })
    .update({ baseline_ok_at: new Date(Date.now() - 3_600_000) });
  const v3 = await assessDevice(rtr1);
  eq('with a baseline, a sustained out-of-tunnel failure yields SITE_DOWN', v3.verdict, 'SITE_DOWN');
  eq('...and the signal is finally false', v3.signals.externalOk, false);
  note('SITE_DOWN requires a baseline success; before that the same failures read as UNREACHABLE');

  // One failure is not an outage.
  await db('external_probe_state').where({ device_id: rtr1 }).update({ consecutive_failures: 1 });
  const v4 = await assessDevice(rtr1);
  eq('a single lost SYN is not an outage', v4.verdict, 'UNREACHABLE');

  // A stale probe reports null: "the prober died" is not "the site is up".
  await db('external_probe_state')
    .where({ device_id: rtr1 })
    .update({ consecutive_failures: 0, last_probe_at: new Date(Date.now() - 86_400_000) });
  const v5 = await assessDevice(rtr1);
  eq('a stale probe result is null, not a stale `true`', v5.signals.externalOk, null);

  // The probe itself, against a port nothing listens on locally: a refusal is
  // a SUCCESS (the address answered).
  {
    await enableExternalProbe(rtr2, { targetIp: '127.0.0.1', port: 9, intervalSec: 60 });
    const outcome = await probeDevice(rtr2);
    check('a TCP refusal counts as reachable (a RST proves the host is alive)', outcome.ok, outcome);
    const state = await db('external_probe_state')
      .where({ device_id: rtr2 })
      .first<{ baseline_ok_at: Date | null }>('baseline_ok_at');
    check('...and it establishes the baseline', state.baseline_ok_at !== null);
  }

  // ==========================================================================
  console.log('\n== 6. the unified journal, and tenant isolation ==');
  // ==========================================================================

  const feed = await listLogs(tenantId, { limit: 100 });
  check('the journal returns the syslog lines', feed.some((e) => e.source === 'syslog'), feed.length);
  check(
    'and never an unattributed one (it belongs to no tenant)',
    feed.every((e) => e.deviceId !== null),
  );

  // A trap and a `/log`-derived login, to prove all three sources union.
  await db.raw(
    `INSERT INTO snmp_traps (ts, device_id, version, source_ip, trap_oid, varbinds, parsed)
     VALUES (now(), ?, 2, '172.17.0.1', '1.3.6.1.6.3.1.1.5.3', '{}'::jsonb, '{}'::jsonb)`,
    [rtr1] as never[],
  );
  await db('device_login_events').insert({
    device_id: rtr1, ts: new Date(), event: 'login', account: 'admin', shared_account: true,
    method: 'ssh', source_ip: '10.20.30.44', origin: 'routeros_log',
    message: 'user admin logged in from 10.20.30.44 via ssh', dedupe_key: hash('pulled'),
  });
  const all = await listLogs(tenantId, { limit: 200 });
  const bySource = new Set(all.map((e) => e.source));
  check('the journal unions syslog + trap + /log', bySource.size === 3, [...bySource]);

  const other = await db('tenants')
    .insert({ name: 'Other MSP', slug: OTHER_TENANT_SLUG })
    .onConflict('slug').merge()
    .returning<Array<{ id: number }>>('id');
  const otherFeed = await listLogs(other[0].id, { limit: 100 });
  eq('another tenant sees none of it', otherFeed.length, 0);
  const otherLogins = await listLoginEvents(other[0].id, {});
  eq('...nor the login events', otherLogins.length, 0);
  const otherAttr = await getAttributionForRun(other[0].id, String(run1.id));
  eq('...nor the attribution', otherAttr, null);
  await db('tenants').where({ slug: OTHER_TENANT_SLUG }).del();

  // Retention is a real DELETE and it works.
  await db('device_login_events')
    .where({ device_id: rtr1, account: 'admin' })
    .update({ ts: new Date(Date.now() - 200 * 86_400_000) });
  const purged = await purgeOldLoginEvents(90);
  eq('retention removes login events past the horizon', purged, 1);

  // ==========================================================================
  console.log(`\n== summary ==`);
  console.log(`  ${passed} passed, ${failures.length} failed`);
  for (const f of failures) console.log(`  FAIL  ${f}`);
  for (const n of notes) console.log(`  note  ${n}`);
}

main()
  .then(async () => {
    await db.destroy();
    process.exit(failures.length === 0 ? 0 : 1);
  })
  .catch(async (err) => {
    console.error(err);
    await db.destroy().catch(() => undefined);
    process.exit(1);
  });
