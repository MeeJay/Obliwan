/**
 * ObliWAN — the M6 / K1 acceptance test, end to end, and it is DESTRUCTIVE BY
 * DESIGN.
 *
 * The milestone recipe, verbatim from ARCHITECTURE.md §5/M6:
 *
 *   "pousser volontairement une règle `chain=input drop` qui coupe le tunnel ->
 *    le guard la REFUSE ; forcer l'override -> le device se restaure SEUL et le
 *    job passe `rolled_back` SANS INTERVENTION."
 *
 * The first half belongs to K2 (`mgmtPathGuard`, another agent's file and
 * already proven there). THIS FILE PROVES THE SECOND HALF, which is the half
 * that involves an equipment: the override is forced, the rule goes on, the box
 * stops answering NEW connections, nobody intervenes, and the router repairs
 * itself from its own scheduler while the server merely watches.
 *
 * Everything here is real except the router:
 *   - a real PostgreSQL with all 9 migrations;
 *   - real `change_jobs` / `change_job_steps` / `device_backups` /
 *     `command_audit` / `apply_outcomes` rows, under their real CHECK
 *     constraints;
 *   - a real TCP socket speaking the real RouterOS binary protocol;
 *   - a real HTTP upload from the "router" to a real `TransferReceiver` with a
 *     real single-use token;
 *   - a real `assertTargetBinding()` on a real fresh connection.
 *
 * Run:
 *   DATABASE_URL=postgres://... OBLIWAN_ENCRYPTION_KEY=<64 hex> \
 *   npx tsx src/services/change/testing/recipe.ts
 *
 * It DELETES the change tables it uses and refuses to run against a database
 * whose URL is not obviously a throwaway.
 */

import crypto from 'crypto';
import fsp from 'fs/promises';
import os from 'os';
import path from 'path';
import { db } from '../../../db';
import { encrypt } from '../../secretVault.service';
import { FakeDeadmanRouter } from './fakeDeadmanRouter';
import {
  OneTimeTokenStore,
  TransferReceiver,
  hashFile,
} from '../transfer.service';
import {
  ChangeError,
  backupRoot,
  canonicalRscHash,
  getBackup,
  loadDeviceTarget,
  openDeviceSession,
  purgeExpiredBackups,
  redactForAudit,
  takeDeviceBackup,
  verifyStoredBackup,
} from '../backup.service';
import {
  armDeadman,
  buildApplyScriptSource,
  buildRollbackScriptSource,
  deadmanNames,
  disarmWithRetry,
  formatRouterOsInterval,
  judgeArming,
  judgeDeadmanEvidence,
  parseRouterOsInterval,
  readDeadmanState,
} from '../rollback.service';
import {
  assertTimingsCoherent,
  checkKillSwitch,
  resolveSafetyNet,
  changeExecutor,
  registerChangeRenderer,
  runSafeApply,
  sleep,
  type RenderedChange,
} from '../safeApply.service';

// ============================================================================
// Harness
// ============================================================================

let passed = 0;
const failures: string[] = [];
const numbers: string[] = [];

function check(label: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed++;
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
function num(text: string): void {
  numbers.push(text);
  console.log(`  #     ${text}`);
}

const TENANT = 1;
let USER = 0;

// ============================================================================
// Fixtures
// ============================================================================

interface Fixture {
  router: FakeDeadmanRouter;
  deviceId: number;
  port: number;
}

async function makeDevice(options: {
  name: string;
  family?: string;
  brand?: string;
  serial: string;
  pppUsername: string;
  siteId?: number | null;
  router?: FakeDeadmanRouter | null;
}): Promise<Fixture> {
  const router =
    options.router === null
      ? null
      : (options.router ??
        new FakeDeadmanRouter({
          identity: options.name,
          serial: options.serial,
          pppUsername: options.pppUsername,
          rebootMs: 1200,
        }));
  const port = router ? await router.listen(0) : 0;
  const [row] = await db('devices')
    .insert({
      tenant_id: TENANT,
      site_id: options.siteId ?? null,
      name: options.name,
      brand: options.brand ?? 'mikrotik',
      family: options.family ?? 'mikrotik_routeros7',
      model: 'hEX',
      os_version: '7.14.3',
      serial: options.serial,
      ppp_username: options.pppUsername,
      system_identity: options.name,
      tunnel_ip: '10.66.0.11',
      status: 'active',
      is_managed: true,
      role: 'cpe',
    })
    .returning('id');
  const deviceId = Number((row as any).id ?? row);
  if (router) {
    await db('device_transports').insert({
      device_id: deviceId,
      transport: 'routeros_api',
      enabled: true,
      host: '127.0.0.1',
      port,
      username: 'obliwan',
      secret_enc: encrypt('s3cr3t'),
      use_tls: false,
    });
  }
  return { router: router as FakeDeadmanRouter, deviceId, port };
}

async function makePlan(deviceId: number): Promise<number> {
  const [row] = await db('change_plans')
    .insert({
      tenant_id: TENANT,
      device_id: deviceId,
      source: 'template',
      base_state_hash: 'a'.repeat(64),
      ops: JSON.stringify([]),
      ops_count: 1,
      risk_level: 'high',
      mgmt_path_verdict: 'veto',
      guard_reasons: JSON.stringify(['ACCEPT_BECOMES_DROP']),
      safety_level: 'armed',
      order_converges: true,
      expires_at: new Date(Date.now() + 3600_000),
    })
    .returning('id');
  return Number((row as any).id ?? row);
}

interface JobSpec {
  deviceId: number;
  planId: number;
  guardVerdict: 'ACCEPT' | 'REJECT' | 'INDETERMINATE';
  override?: boolean;
  safetyLevel?: 'armed' | 'armed_by_peer' | 'degraded';
  degradedConfirmed?: boolean;
}

async function makeClaimedJob(spec: JobSpec): Promise<number> {
  const now = new Date();
  const [row] = await db('change_jobs')
    .insert({
      tenant_id: TENANT,
      device_id: spec.deviceId,
      plan_id: spec.planId,
      kind: 'push',
      status: 'claimed',
      attempt: 1,
      max_attempts: 1,
      base_state_hash: 'a'.repeat(64),
      safety_level: spec.safetyLevel ?? 'armed',
      guard_verdict: spec.guardVerdict,
      guard_reasons: JSON.stringify(
        spec.guardVerdict === 'ACCEPT' ? [] : ['ACCEPT_BECOMES_DROP'],
      ),
      override_reason:
        spec.guardVerdict === 'ACCEPT'
          ? null
          : spec.override
            ? 'M6 destructive acceptance test: forcing a known-lethal rule on purpose'
            : null,
      overridden_by: spec.guardVerdict === 'ACCEPT' ? null : spec.override ? USER : null,
      overridden_at: spec.guardVerdict === 'ACCEPT' ? null : spec.override ? now : null,
      degraded_confirmed_by: spec.degradedConfirmed ? USER : null,
      degraded_confirmed_at: spec.degradedConfirmed ? now : null,
      claimed_by: 'recipe:worker:1',
      claimed_at: now,
      lease_expires_at: new Date(Date.now() + 900_000),
      requested_by: USER,
    })
    .returning('id');
  return Number((row as any).id ?? row);
}

/** Timings small enough for a test, coherent enough to pass the guard on the
 *  timings themselves. The RATIOS are what production uses; only the scale is
 *  compressed, and every number is printed so nobody can mistake one for the
 *  other. */
const FAST = {
  deadmanSeconds: 6,
  soakMs: 800,
  reconnectDelayMs: 200,
  reconnectAttempts: 3,
  reconnectIntervalMs: 300,
  soakProbeIntervalMs: 300,
  disarmAttempts: 4,
  disarmBackoffMs: 150,
  recoveryGraceMs: 12_000,
  recoveryProbeIntervalMs: 700,
  connectTimeoutMs: 2_000,
};

function rendered(commands: string[], secrets: string[] = []): RenderedChange {
  return {
    commands,
    redacted: commands.map((c) =>
      secrets.reduce((acc, s) => acc.split(s).join('***'), c),
    ),
    secretValues: secrets,
  };
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  const url = process.env.DATABASE_URL ?? '';
  if (!/localhost|127\.0\.0\.1|10\.0\.0\.152/.test(url)) {
    throw new Error('Refusing to run: DATABASE_URL is not obviously a throwaway database.');
  }
  if (!/^[0-9a-fA-F]{64}$/.test(process.env.OBLIWAN_ENCRYPTION_KEY ?? '')) {
    throw new Error('OBLIWAN_ENCRYPTION_KEY must be 64 hex characters');
  }
  process.env.OBLIWAN_BACKUP_ROOT =
    process.env.OBLIWAN_BACKUP_ROOT ?? path.join(os.tmpdir(), `obliwan-backups-${process.pid}`);

  const routers: FakeDeadmanRouter[] = [];
  const receivers: TransferReceiver[] = [];

  console.log('\n== 0. clean slate ==');
  await db('apply_outcomes').del();
  await db('command_audit').whereRaw("executed_at < now() + interval '1 day'").del().catch(async () => {
    // command_audit refuses DELETE of rows younger than 400 days (by design).
    // Truncate is not blocked by a row trigger, and this is a throwaway DB.
    await db.raw('TRUNCATE command_audit');
  });
  await db.raw('TRUNCATE command_audit');
  await db('change_job_steps').del();
  await db('change_jobs').del();
  await db('device_backups').del();
  await db.raw('DELETE FROM change_plans');
  await db('ppp_sessions').del().catch(() => undefined);
  await db('device_transports').del();
  await db('devices').update({ concentrator_id: null });
  await db('devices').del();
  await db('sites').del();
  await db('kill_switch').where({ scope: 'global' }).update({ engaged: false, reason: null });

  const existing = await db('users').where({ username: 'recipe-operator' }).first('id');
  if (existing) USER = existing.id;
  else {
    const [u] = await db('users')
      .insert({ username: 'recipe-operator', display_name: 'M6 recipe', role: 'admin' })
      .returning('id');
    USER = Number((u as any).id ?? u);
  }
  check('fixture user exists', USER > 0, { USER });

  try {
    // ======================================================================
    console.log('\n== 1. pure units: tokens, intervals, script builders ==');
    // ======================================================================
    const store = new OneTimeTokenStore();
    const grant = store.mint('test', 1024, 50);
    eq('a fresh token is accepted', store.consume(grant.token).ok, true);
    const replay = store.consume(grant.token);
    check('a replayed token is refused as CONSUMED', !replay.ok && replay.code === 'TOKEN_CONSUMED', replay);
    const forged = store.consume('f'.repeat(64));
    check('a forged token is refused', !forged.ok && forged.code === 'TOKEN_INVALID', forged);
    check('a malformed token is refused', !store.consume('nope').ok);
    const g2 = store.mint('expiring', 10, 20);
    await sleep(40);
    const expired = store.consume(g2.token);
    check('an expired token is refused as EXPIRED', !expired.ok && expired.code === 'TOKEN_EXPIRED', expired);

    eq('formatRouterOsInterval(600)', formatRouterOsInterval(600), '00:10:00');
    eq('parse 00:10:00', parseRouterOsInterval('00:10:00'), 600);
    eq('parse 10m', parseRouterOsInterval('10m'), 600);
    eq('parse 1w2d3h4m5s', parseRouterOsInterval('1w2d3h4m5s'), 788645);
    eq('parse garbage is null, never zero', parseRouterOsInterval('later'), null);

    const rbSource = buildRollbackScriptSource({
      jobId: 42,
      backupFileName: 'obliwan-deadman-42.backup',
      backupPassword: 'PW-SECRET-VALUE',
      schedulerName: 'obliwan-deadman-42',
    });
    check('the rollback script loads the backup', rbSource.includes('/system/backup/load'));
    check('the rollback script gives up rather than reboot-looping', rbSource.includes('gave up'));
    const applySource = buildApplyScriptSource({
      jobId: 42,
      commands: ['/ip firewall filter add chain=input action=drop'],
      rollbackScriptName: 'obliwan-rollback-42',
      markerGlobal: 'obliwanApply42',
    });
    check('the apply script uses :do{} on-error={}', /:do=\{[\s\S]*\} on-error=\{/.test(applySource));
    check('the apply script does NOT use /import', !applySource.includes('/import'));
    check(
      'the on-error branch runs the rollback script',
      applySource.includes('/system/script/run [/system/script find name="obliwan-rollback-42"]'),
    );

    // §8.2 — the redactor
    const auditLine = redactForAudit(
      ['/system/script/add', '=name=x', '=source=/ppp secret set password=hunter2'],
      ['hunter2'],
    );
    check('=source= is collapsed to a byte count', /=source=<\d+ bytes, redacted>/.test(auditLine), auditLine);
    check('the secret literal is gone from the audit line', !auditLine.includes('hunter2'), auditLine);
    const pwLine = redactForAudit(['/system/backup/save', '=name=x', '=password=hunter2'], []);
    check('=password= is masked by the transport redactor', pwLine.includes('=password=***'), pwLine);

    check(
      'incoherent timings are REFUSED, not clamped',
      (() => {
        try {
          assertTimingsCoherent({ ...FAST, deadmanSeconds: 1 });
          return false;
        } catch (e) {
          return e instanceof ChangeError;
        }
      })(),
    );

    // judgeArming, on hand-built states
    const armedState = {
      scriptPresent: true, scriptId: '*1', scriptRunCount: 0,
      schedulerPresent: true, schedulerId: '*2', schedulerDisabled: false,
      schedulerStartTime: 'startup', schedulerIntervalSeconds: 600,
      schedulerOnEvent: '/system/script/run obliwan-rollback-1', schedulerRunCount: 0,
      backupPresent: true, backupBytes: 4096,
    };
    const expect = { schedulerName: 'obliwan-deadman-1', scriptName: 'obliwan-rollback-1', intervalSeconds: 600 };
    eq('a complete arming is judged armed', judgeArming(armedState, expect).armed, true);
    eq('a DISABLED scheduler is not armed', judgeArming({ ...armedState, schedulerDisabled: true }, expect).armed, false);
    eq('start-time != startup is not armed', judgeArming({ ...armedState, schedulerStartTime: '00:00:00' }, expect).armed, false);
    eq('a wrong interval is not armed', judgeArming({ ...armedState, schedulerIntervalSeconds: 60 }, expect).armed, false);
    eq('an unreadable interval is not armed', judgeArming({ ...armedState, schedulerIntervalSeconds: null }, expect).armed, false);
    eq('an on-event pointing elsewhere is not armed', judgeArming({ ...armedState, schedulerOnEvent: '/system/script/run something-else' }, expect).armed, false);
    eq('a MISSING BACKUP BLOB is not armed', judgeArming({ ...armedState, backupPresent: false }, expect).armed, false);
    check(
      'the missing-blob problem says the dead-man would restore nothing',
      judgeArming({ ...armedState, backupPresent: false }, expect).problems.join(' ').includes('restore nothing'),
    );

    // judgeDeadmanEvidence, on hand-built states
    const armedAt = new Date(Date.now() - 600_000);
    const gone = { ...armedState, scriptPresent: false, schedulerPresent: false };
    eq(
      'entries gone + rebooted = fired_restored (inferred)',
      judgeDeadmanEvidence({ state: gone, uptimeSeconds: 30, armedAt }).verdict,
      'fired_restored',
    );
    eq(
      'entries gone + a matching config = fired_restored (PROVED)',
      judgeDeadmanEvidence({ state: gone, uptimeSeconds: 30, armedAt, configMatchesPreflight: true }).confidence,
      'proved',
    );
    eq(
      'entries gone, no reboot, no disarm = unknown, NOT disarmed',
      judgeDeadmanEvidence({ state: gone, uptimeSeconds: 99_999, armedAt }).verdict,
      'unknown',
    );
    eq(
      'entries gone because WE removed them = disarmed',
      judgeDeadmanEvidence({ state: gone, uptimeSeconds: 99_999, armedAt, disarmRequested: true }).verdict,
      'disarmed',
    );
    eq(
      'scheduler still there = still_armed',
      judgeDeadmanEvidence({ state: armedState, uptimeSeconds: 99_999, armedAt }).verdict,
      'still_armed',
    );

    // ======================================================================
    console.log('\n== 2. backup: taken, verified, and ERASED from the equipment ==');
    // ======================================================================
    const fx = await makeDevice({ name: 'cpe-backup', serial: 'SER-BK-1', ppp_username: 'site-bk' } as any);
    routers.push(fx.router);
    const receiver = new TransferReceiver({ host: '127.0.0.1' });
    receivers.push(receiver);
    await receiver.start();

    const t0 = Date.now();
    const set = await takeDeviceBackup({
      deviceId: fx.deviceId,
      trigger: 'manual',
      kinds: ['binary', 'rsc'],
      receiver,
      callbackHost: '127.0.0.1',
      createdBy: USER,
    });
    num(`backup of both kinds took ${Date.now() - t0} ms (binary ${set.binary?.sizeBytes} B, rsc ${set.rsc?.sizeBytes} B)`);
    check('a binary backup row exists', set.binary !== null);
    check('an rsc backup row exists', set.rsc !== null);
    eq('the binary backup is proven erased from the device', set.binary?.onDeviceRemoved, true);
    eq('the rsc backup is proven erased from the device', set.rsc?.onDeviceRemoved, true);
    eq('NOTHING obliwan-shaped is left on the router', fx.router.fileNames().length, 0);
    check('sha256 is a real digest', /^[0-9a-f]{64}$/.test(set.binary?.sha256 ?? ''));
    const onDisk = await hashFile(set.binary!.absolutePath);
    eq('the stored blob hashes to the recorded value', onDisk.sha256, set.binary!.sha256);
    const verify = await verifyStoredBackup(set.binary!.id);
    eq('verifyStoredBackup agrees', verify.ok, true);
    const rows = await db('device_backups').where({ device_id: fx.deviceId }).select('kind', 'trigger_kind');
    eq('two device_backups rows', rows.length, 2);

    // R10 is enforced on the device side too: the fake refuses an export
    // without show-sensitive=no, so a regression here is a hard failure.
    const exported = fx.router.events.filter((e) => e.what.startsWith('export:'));
    check('the export happened with show-sensitive=no (the fake refuses anything else)', exported.length === 1);

    // the password is stored ENCRYPTED and is not the plaintext
    const stored = await getBackup(set.binary!.id);
    check('the backup password is stored as a vault blob', (stored?.encryptionPasswordEnc ?? '').startsWith('v1:'));

    // command_audit must not carry the backup password
    const audit = await db('command_audit').where({ device_id: fx.deviceId }).select('command');
    const auditText = audit.map((a: any) => a.command).join('\n');
    check('command_audit has rows', audit.length > 0, { rows: audit.length });
    check('command_audit masks =password=', auditText.includes('=password=***'), auditText.slice(0, 200));
    check('command_audit never contains a raw transfer token', !/_obliwan\/transfer\/[0-9a-f]{64}/.test(auditText));

    // a corrupted transfer must be caught by the digest/size check
    const bad = await makeDevice({ name: 'cpe-corrupt', serial: 'SER-BK-2', ppp_username: 'site-bkc' } as any);
    routers.push(bad.router);
    // rebuild the fixture's router with corruption enabled
    await bad.router.close();
    const corruptRouter = new FakeDeadmanRouter({
      identity: 'cpe-corrupt', serial: 'SER-BK-2', pppUsername: 'site-bkc', corruptTransfer: true,
    });
    routers.push(corruptRouter);
    const corruptPort = await corruptRouter.listen(0);
    await db('device_transports').where({ device_id: bad.deviceId }).update({ port: corruptPort });
    let corruptCaught = '';
    try {
      await takeDeviceBackup({
        deviceId: bad.deviceId, trigger: 'manual', kinds: ['binary'],
        receiver, callbackHost: '127.0.0.1',
      });
    } catch (err) {
      corruptCaught = err instanceof ChangeError ? err.kind : String(err);
    }
    eq('a truncated transfer is refused', corruptCaught, 'BACKUP_UNVERIFIED');
    eq('and the truncated file is erased from the device anyway', corruptRouter.fileNames().length, 0);

    // retention
    await db('device_backups').where({ id: set.rsc!.id }).update({ expires_at: new Date(Date.now() - 1000) });
    const purge = await purgeExpiredBackups();
    eq('the expired backup is purged', purge.purged, 1);
    const purgedRow = await getBackup(set.rsc!.id);
    eq('and its row is marked purged, never deleted', purgedRow?.status, 'purged');

    // ======================================================================
    console.log('\n== 3. R4 — a box with the wrong identity is refused ==');
    // ======================================================================
    await db('devices').where({ id: bad.deviceId }).update({ serial: 'SER-SOMEONE-ELSE' });
    let identityRefusal = '';
    try {
      const s = await openDeviceSession(bad.deviceId, { purpose: 'r4-test' });
      s.close();
    } catch (err) {
      identityRefusal = err instanceof ChangeError ? err.kind : String(err);
    }
    eq('a mismatched serial refuses the session', identityRefusal, 'IDENTITY_MISMATCH');
    await db('devices').where({ id: bad.deviceId }).update({ serial: 'SER-BK-2' });

    // ======================================================================
    console.log('\n== 4. §8.3 — the level of net, per device ==');
    // ======================================================================
    const netMik = await resolveSafetyNet(fx.deviceId);
    eq('a reachable MikroTik is ARMED', netMik.level, 'armed');
    eq('and its net survives the death of this server', netMik.survivesServerLoss, true);
    eq('and it needs no confirmation', netMik.requiresConfirmation, false);

    const [siteRow] = await db('sites')
      .insert({ tenant_id: TENANT, code: 'SITE-A', name: 'Site A' })
      .returning('id');
    const siteId = Number((siteRow as any).id ?? siteRow);
    await db('devices').where({ id: fx.deviceId }).update({ site_id: siteId });
    const dray = await makeDevice({
      name: 'vigor-2927', family: 'draytek_vigor', brand: 'draytek',
      serial: 'DT-1', ppp_username: 'site-dt', siteId, router: null,
    } as any);
    const netDray = await resolveSafetyNet(dray.deviceId);
    eq('a DrayTek next to a MikroTik is still DEGRADED (no peer adapter exists)', netDray.level, 'degraded');
    eq('and it demands an explicit confirmation', netDray.requiresConfirmation, true);
    check(
      'and it says out loud that the peer could detect but not repair',
      netDray.checks.join(' ').includes('NO peer-recovery adapter'),
      netDray.checks,
    );
    check('a co-located MikroTik was actually found', netDray.checks.join(' ').includes('co-located MikroTik candidate'));

    // a MikroTik we cannot dial is DEGRADED, never ARMED
    const dead = await makeDevice({ name: 'cpe-dead', serial: 'SER-DEAD', ppp_username: 'site-dead' } as any);
    await dead.router.close();
    const netDead = await resolveSafetyNet(dead.deviceId, { connectTimeoutMs: 600 });
    eq('an unreachable MikroTik is DEGRADED, not ARMED', netDead.level, 'degraded');

    // ======================================================================
    console.log('\n== 5. the gates: kill switch, guard, degraded confirmation ==');
    // ======================================================================
    const gateFx = await makeDevice({ name: 'cpe-gates', serial: 'SER-GATE', ppp_username: 'site-gate' } as any);
    routers.push(gateFx.router);
    const gatePlan = await makePlan(gateFx.deviceId);

    await db('kill_switch')
      .where({ scope: 'global' })
      .update({ engaged: true, reason: 'recipe test', engaged_by: USER, engaged_at: new Date() });
    eq('checkKillSwitch reports blocked', (await checkKillSwitch(TENANT)).blocked, true);
    const killJob = await makeClaimedJob({ deviceId: gateFx.deviceId, planId: gatePlan, guardVerdict: 'ACCEPT' });
    const killResult = await runSafeApply({
      jobId: killJob, rendered: rendered(['/system identity set name=x']), timings: FAST,
    });
    eq('the kill switch stops the job', killResult.errorKind, 'KILL_SWITCH');
    eq('and nothing was sent to the device', gateFx.router.received.length, 0);
    await db('kill_switch').where({ scope: 'global' }).update({ engaged: false, reason: null });
    await db('change_jobs').where({ id: killJob }).update({ status: 'aborted' });

    const indetJob = await makeClaimedJob({
      deviceId: gateFx.deviceId, planId: gatePlan, guardVerdict: 'INDETERMINATE', override: false,
    }).catch((e) => e as Error);
    check(
      'the DATABASE refuses an INDETERMINATE job with no override (23514)',
      indetJob instanceof Error && /change_jobs_override_chk/.test(String(indetJob)),
      String(indetJob).slice(0, 160),
    );

    // ======================================================================
    console.log('\n== 6. a GOOD change: armed before the apply, then disarmed ==');
    // ======================================================================
    const okFx = await makeDevice({ name: 'cpe-good', serial: 'SER-GOOD', ppp_username: 'site-good' } as any);
    routers.push(okFx.router);
    const okPlan = await makePlan(okFx.deviceId);
    const okJob = await makeClaimedJob({ deviceId: okFx.deviceId, planId: okPlan, guardVerdict: 'ACCEPT' });

    const okStart = Date.now();
    const okResult = await runSafeApply({
      jobId: okJob,
      rendered: rendered(
        ['/ip firewall filter add chain=forward action=accept comment=obliwan-benign'],
        [],
      ),
      timings: FAST,
      callbackHost: '127.0.0.1',
    });
    num(`a clean apply (arm -> apply -> reconnect -> ${FAST.soakMs} ms soak -> disarm) took ${Date.now() - okStart} ms`);
    eq('the job SUCCEEDED', okResult.status, 'succeeded');
    eq('the outcome is succeeded', okResult.outcome, 'succeeded');

    // THE ORDER: armed strictly before the apply ran.
    const armIdx = okFx.router.eventIndex((w) => w.startsWith('scheduler-add:obliwan-deadman-'));
    const applyIdx = okFx.router.eventIndex((w) => w.startsWith('script-run:obliwan-apply-'));
    check('the dead-man scheduler was added', armIdx >= 0, { armIdx });
    check('the apply script ran', applyIdx >= 0, { applyIdx });
    check('THE DEAD-MAN WAS ARMED BEFORE THE APPLY RAN', armIdx >= 0 && applyIdx > armIdx, { armIdx, applyIdx });
    num(`arming event #${armIdx}, apply event #${applyIdx} (${okFx.router.events[applyIdx].at - okFx.router.events[armIdx].at} ms apart)`);

    eq('the scheduler is gone after the disarm', okFx.router.schedulerNames().length, 0);
    eq('the rollback script is gone after the disarm', okFx.router.scriptNames().filter((n) => n.startsWith('obliwan-rollback')).length, 0);
    eq('THE BACKUP BLOB IS GONE FROM THE EQUIPMENT', okFx.router.fileNames().filter((n) => n.endsWith('.backup')).length, 0);
    check('deadman_disarmed_at is set', okResult.deadmanDisarmedAt !== null);

    const okSteps = await db('change_job_steps').where({ job_id: okJob }).orderBy('seq').select('kind', 'status');
    const kinds = okSteps.map((s: any) => s.kind);
    check('the step trace is the sequence', JSON.stringify(kinds).includes('"bind_assert","preflight_backup","arm_deadman","apply","reconnect","postcheck","soak","disarm"'), kinds);
    eq('every step succeeded', okSteps.every((s: any) => s.status === 'succeeded'), true);
    const outcomeRow = await db('apply_outcomes').where({ job_id: okJob }).first('outcome', 'safety_level');
    eq('apply_outcomes recorded the success', outcomeRow?.outcome, 'succeeded');
    eq('with the safety level it ran under', outcomeRow?.safety_level, 'armed');

    // ======================================================================
    console.log('\n== 7. THE DESTRUCTIVE RECIPE — chain=input drop, override forced ==');
    // ======================================================================
    const cutFx = await makeDevice({ name: 'cpe-cut', serial: 'SER-CUT', ppp_username: 'site-cut' } as any);
    routers.push(cutFx.router);
    const cutPlan = await makePlan(cutFx.deviceId);
    // The guard said REJECT. A human signed an override. That is the ONLY way
    // this row can exist — migration 009 refuses it otherwise, and §5 above
    // proved that refusal.
    const cutJob = await makeClaimedJob({
      deviceId: cutFx.deviceId, planId: cutPlan, guardVerdict: 'REJECT', override: true,
    });
    const jobRow = await db('change_jobs').where({ id: cutJob }).first('override_reason', 'overridden_by');
    check('the override is signed by a named human', jobRow?.overridden_by === USER && (jobRow?.override_reason ?? '').length > 10);

    const cutStart = Date.now();
    const cutResult = await runSafeApply({
      jobId: cutJob,
      rendered: rendered([
        '/ip firewall filter add chain=input action=drop comment=obliwan-lethal place-before=0',
      ]),
      timings: FAST,
      callbackHost: '127.0.0.1',
    });
    const cutElapsed = Date.now() - cutStart;

    num(`from apply to a terminal verdict: ${cutElapsed} ms (dead-man window ${FAST.deadmanSeconds}s, reboot ${1200} ms)`);
    eq('THE JOB IS rolled_back', cutResult.status, 'rolled_back');
    eq('the outcome is rolled_back', cutResult.outcome, 'rolled_back');
    check('the evidence names the dead-man', cutResult.evidence?.verdict === 'fired_restored', cutResult.evidence?.verdict);
    eq('and the restoration was PROVED, not merely inferred', cutResult.evidence?.confidence, 'proved');
    num(`evidence: ${cutResult.evidence?.observations.join(' | ')}`);

    // The router's own event tape is the proof that nobody intervened.
    const tape = cutFx.router.events.map((e) => e.what);
    check('the router recorded the CUT', tape.some((w) => w.startsWith('CUT:')), tape.slice(-14));
    check('the router refused new connections while cut', tape.some((w) => w.startsWith('refused-new-connection')), tape.slice(-14));
    check(
      'ITS OWN SCHEDULER FIRED — not us',
      tape.some((w) => w === 'scheduler-interval-fire:obliwan-deadman-' + cutJob),
      tape.filter((w) => w.includes('scheduler')),
    );
    check('it loaded the backup by itself', tape.some((w) => w.startsWith('backup-load:')));
    check('and it rebooted', tape.includes('reboot-start') && tape.includes('reboot-done'));
    eq('the lethal rule is no longer in the configuration', cutFx.router.configLines().filter((l) => /action=drop/.test(l)).length, 0);
    eq('the device is reachable again', cutFx.router.isCut, false);
    eq('the dead-man scheduler is gone (the restore removed it)', cutFx.router.schedulerNames().length, 0);
    eq('the dead-man blob was cleaned up afterwards', cutFx.router.fileNames().filter((n) => n.endsWith('.backup')).length, 0);

    const cutSteps = await db('change_job_steps').where({ job_id: cutJob }).orderBy('seq').select('kind', 'status', 'output_redacted');
    check('there is a rollback step in the trace', cutSteps.some((s: any) => s.kind === 'rollback'));
    const finalStatus = await db('change_jobs').where({ id: cutJob }).first('status', 'outcome', 'error_kind');
    eq('the database agrees the job is rolled_back', finalStatus?.status, 'rolled_back');
    eq('and records DEADMAN_FIRED', finalStatus?.error_kind, 'DEADMAN_FIRED');
    const cutOutcome = await db('apply_outcomes').where({ job_id: cutJob }).first('outcome', 'was_override');
    eq('apply_outcomes recorded rolled_back', cutOutcome?.outcome, 'rolled_back');
    eq('and remembers it was an override', cutOutcome?.was_override, true);

    // ======================================================================
    console.log('\n== 8. an apply that FAILS on the box runs the on-error branch ==');
    // ======================================================================
    const errFx = await makeDevice({ name: 'cpe-onerror', serial: 'SER-ERR', ppp_username: 'site-err' } as any);
    routers.push(errFx.router);
    const errPlan = await makePlan(errFx.deviceId);
    const errJob = await makeClaimedJob({ deviceId: errFx.deviceId, planId: errPlan, guardVerdict: 'ACCEPT' });
    const errResult = await runSafeApply({
      jobId: errJob,
      rendered: rendered([
        '/ip firewall filter add chain=forward action=accept comment=obliwan-first',
        '/obliwan/test/fail this line is refused by the device',
        '/ip firewall filter add chain=forward action=accept comment=obliwan-never',
      ]),
      timings: FAST,
      callbackHost: '127.0.0.1',
    });
    const errTape = errFx.router.events.map((e) => e.what);
    check('the on-error branch ran on the router', errTape.some((w) => w.startsWith('apply-on-error-branch:')), errTape.slice(-10));
    check('the rollback script was run by the ROUTER, from its own handler', errTape.some((w) => w.startsWith('script-run:obliwan-rollback-')));
    eq('the job is rolled_back', errResult.status, 'rolled_back');
    eq('the line after the failure never ran', errFx.router.configLines().some((l) => l.includes('obliwan-never')), false);

    // ======================================================================
    console.log('\n== 9. disarm: retry, then incident ==');
    // ======================================================================
    // (a) two refusals then success
    const retryRouter = new FakeDeadmanRouter({
      identity: 'cpe-retry', serial: 'SER-RETRY', pppUsername: 'site-retry', failSchedulerRemoves: 2,
    });
    routers.push(retryRouter);
    const retryPort = await retryRouter.listen(0);
    const [retryDev] = await db('devices').insert({
      tenant_id: TENANT, name: 'cpe-retry', brand: 'mikrotik', family: 'mikrotik_routeros7',
      serial: 'SER-RETRY', ppp_username: 'site-retry', system_identity: 'cpe-retry',
      status: 'active', is_managed: true, role: 'cpe',
    }).returning('id');
    const retryId = Number((retryDev as any).id ?? retryDev);
    await db('device_transports').insert({
      device_id: retryId, transport: 'routeros_api', enabled: true, host: '127.0.0.1',
      port: retryPort, username: 'obliwan', secret_enc: encrypt('s3cr3t'), use_tls: false,
    });
    const retryPlan = await makePlan(retryId);
    const retryJob = await makeClaimedJob({ deviceId: retryId, planId: retryPlan, guardVerdict: 'ACCEPT' });
    const retryResult = await runSafeApply({
      jobId: retryJob,
      rendered: rendered(['/ip firewall filter add chain=forward action=accept comment=obliwan-retry']),
      timings: FAST,
      callbackHost: '127.0.0.1',
    });
    const retryRefusals = retryRouter.events.filter((e) => e.what.startsWith('scheduler-remove-REFUSED')).length;
    num(`disarm was refused ${retryRefusals} time(s) and then succeeded`);
    eq('two refusals then success still SUCCEEDS', retryResult.status, 'succeeded');
    eq('the refusals were real', retryRefusals, 2);
    eq('and the scheduler really is gone', retryRouter.schedulerNames().length, 0);

    // (b) permanent refusal -> incident
    const incRouter = new FakeDeadmanRouter({
      identity: 'cpe-incident', serial: 'SER-INC', pppUsername: 'site-inc',
      failSchedulerRemoves: Number.MAX_SAFE_INTEGER,
    });
    routers.push(incRouter);
    const incPort = await incRouter.listen(0);
    const [incDev] = await db('devices').insert({
      tenant_id: TENANT, name: 'cpe-incident', brand: 'mikrotik', family: 'mikrotik_routeros7',
      serial: 'SER-INC', ppp_username: 'site-inc', system_identity: 'cpe-incident',
      status: 'active', is_managed: true, role: 'cpe',
    }).returning('id');
    const incId = Number((incDev as any).id ?? incDev);
    await db('device_transports').insert({
      device_id: incId, transport: 'routeros_api', enabled: true, host: '127.0.0.1',
      port: incPort, username: 'obliwan', secret_enc: encrypt('s3cr3t'), use_tls: false,
    });
    const incPlan = await makePlan(incId);
    const incJob = await makeClaimedJob({ deviceId: incId, planId: incPlan, guardVerdict: 'ACCEPT' });
    const incidents: unknown[] = [];
    const incResult = await runSafeApply({
      jobId: incJob,
      rendered: rendered(['/ip firewall filter add chain=forward action=accept comment=obliwan-inc']),
      timings: FAST,
      callbackHost: '127.0.0.1',
      emit: (event, payload) => {
        if (event === 'incident') incidents.push(payload);
      },
    });
    eq('a permanently failing disarm FAILS the job', incResult.status, 'failed');
    eq('with error_kind DEADMAN_STILL_ARMED', incResult.errorKind, 'DEADMAN_STILL_ARMED');
    eq('an incident was raised, not a warning', incidents.length, 1);
    check('the incident names when the box will revert itself', JSON.stringify(incidents[0]).includes('revertsAt'), incidents[0]);
    const incAttempts = incRouter.events.filter((e) => e.what.startsWith('scheduler-remove-REFUSED')).length;
    num(`the disarm retried ${incAttempts} times before declaring the incident (configured max ${FAST.disarmAttempts})`);
    eq('it retried the configured number of times', incAttempts, FAST.disarmAttempts);
    check('and the scheduler is deliberately still there', incRouter.schedulerNames().length === 1, incRouter.schedulerNames());
    // Let the box do exactly what the incident said it would.
    const beforeFire = incRouter.events.length;
    await sleep(FAST.deadmanSeconds * 1000 + 2500);
    const fired = incRouter.events.slice(beforeFire).some((e) => e.what.startsWith('backup-load:'));
    check('AND THE BOX REVERTED THE GOOD CHANGE BY ITSELF, exactly as the incident warned', fired);

    // ======================================================================
    console.log('\n== 10. §8.2 — no secret anywhere in the persisted trace ==');
    // ======================================================================
    const secretFx = await makeDevice({ name: 'cpe-secret', serial: 'SER-SEC', ppp_username: 'site-sec' } as any);
    routers.push(secretFx.router);
    const secretPlan = await makePlan(secretFx.deviceId);
    const secretJob = await makeClaimedJob({ deviceId: secretFx.deviceId, planId: secretPlan, guardVerdict: 'ACCEPT' });
    const PSK = 'S3cr3t-PSK-Never-Persist-9f2a';
    await runSafeApply({
      jobId: secretJob,
      rendered: rendered(
        [`/ip ipsec identity add peer=hub secret="${PSK}"`],
        [PSK],
      ),
      timings: FAST,
      callbackHost: '127.0.0.1',
    });
    const allAudit = await db('command_audit').where({ device_id: secretFx.deviceId }).select('command', 'error_redacted');
    const allSteps = await db('change_job_steps').where({ job_id: secretJob }).select('output_redacted', 'error_redacted');
    const persisted = JSON.stringify([allAudit, allSteps]);
    check('THE PSK IS NOWHERE IN command_audit OR change_job_steps', !persisted.includes(PSK));
    check('the router did receive the real secret (the vault -> device path works)',
      secretFx.router.configLines().some((l) => l.includes(PSK)));
    check('and the audit shows a byte count instead of the script body',
      allAudit.some((a: any) => /=source=<\d+ bytes, redacted>/.test(a.command)));

    // FLEET-WIDE, over every command this whole run sent to every fake router.
    const everyCommand = (await db('command_audit').select('command', 'error_redacted'))
      .map((r: any) => `${r.command} ${r.error_redacted ?? ''}`)
      .join('\n');
    num(`command_audit holds ${(await db('command_audit').count('* as n'))[0].n} rows for this run`);
    check(
      'NO single-use transfer token survives anywhere in command_audit',
      !/_obliwan\/transfer\/[0-9a-f]{8}/.test(everyCommand),
      everyCommand.match(/_obliwan\/transfer\/\S{0,20}/g)?.slice(0, 3),
    );
    check('no raw =password= value anywhere in command_audit', !/=password=(?!\*\*\*)\S/.test(everyCommand));
    check('no raw =source= body anywhere in command_audit', !/=source=(?!<)\S/.test(everyCommand));

    // ======================================================================
    console.log('\n== 11. a dead-man that did not take is REFUSED before the apply ==');
    // ======================================================================
    const sabFx = await makeDevice({ name: 'cpe-sabotage', serial: 'SER-SAB', ppp_username: 'site-sab' } as any);
    routers.push(sabFx.router);
    // Arm by hand, then break the arming exactly as a router with a full disk
    // or a policy restriction would: the scheduler is there but disabled.
    const sabSession = await openDeviceSession(sabFx.deviceId, { purpose: 'sabotage' });
    const sabNames = deadmanNames(9999);
    await sabSession.run(['/system/backup/save', '=name=' + sabNames.backupFileBase, '=password=pw'], { isWrite: true });
    await armDeadman(sabSession, {
      jobId: 9999, backupFileName: sabNames.backupFileName, backupPassword: 'pw', intervalSeconds: 6,
    });
    const goodState = await readDeadmanState(sabSession, sabNames);
    eq('the hand-armed dead-man reads back as armed', judgeArming(goodState, {
      schedulerName: sabNames.schedulerName, scriptName: sabNames.scriptName, intervalSeconds: 6,
    }).armed, true);
    await sabSession.run(['/system/scheduler/set', `=numbers=${sabNames.schedulerName}`, '=disabled=yes'], { isWrite: true });
    const brokenState = await readDeadmanState(sabSession, sabNames);
    const brokenVerdict = judgeArming(brokenState, {
      schedulerName: sabNames.schedulerName, scriptName: sabNames.scriptName, intervalSeconds: 6,
    });
    eq('a disabled scheduler is NOT armed', brokenVerdict.armed, false);
    check('and the problem is named', brokenVerdict.problems.join(' ').includes('DISABLED'), brokenVerdict.problems);
    // and the disarm path cleans up after us
    const cleanup = await disarmWithRetry({
      openSession: () => openDeviceSession(sabFx.deviceId, { purpose: 'sabotage-cleanup' }),
      names: sabNames, attempts: 3, backoffMs: 100,
    });
    eq('disarm removes both entries and the blob', cleanup.disarmed && cleanup.backupRemoved, true);
    sabSession.close();

    // ======================================================================
    console.log('\n== 12. WHY step (e) demands a NEW socket ==');
    // ======================================================================
    // The trap, demonstrated rather than asserted from theory: a
    // `chain=input action=drop` sitting under an established/related accept
    // leaves the socket we are already on perfectly healthy. A verification
    // done on that socket reports a green light from inside a box nobody else
    // can reach.
    const trapFx = await makeDevice({ name: 'cpe-trap', serial: 'SER-TRAP', ppp_username: 'site-trap' } as any);
    routers.push(trapFx.router);
    const held = await openDeviceSession(trapFx.deviceId, { purpose: 'trap-held-socket' });
    await held.run(['/system/script/add', '=name=cut', '=source=/ip firewall filter add chain=input action=drop'], { isWrite: true });
    await held.run(['/system/script/run', '=number=cut'], { isWrite: true });
    await sleep(150);
    eq('the router is now cut', trapFx.router.isCut, true);
    const heldStillWorks = await held
      .run(['/system/identity/print'], { isWrite: false, skipAudit: true })
      .then(() => true, () => false);
    check('THE ALREADY-OPEN SOCKET STILL ANSWERS — this is the trap', heldStillWorks);
    const freshFails = await openDeviceSession(trapFx.deviceId, { purpose: 'trap-fresh-socket', connectTimeoutMs: 800 })
      .then((s) => { s.close(); return false; }, () => true);
    check('a BRAND-NEW socket is refused — this is the truth', freshFails);
    held.close();

    // ======================================================================
    console.log('\n== 13. the ChangeExecutor seam the queue half looks for ==');
    // ======================================================================
    // `apply.service.ts` (the other K1 workstream) resolves `./safeApply.service`
    // dynamically and requires these five methods. Asserting the SHAPE here
    // means the two halves cannot drift apart silently.
    for (const m of ['takePreflightBackup', 'armDeadman', 'applyChange', 'verify', 'disarmDeadman']) {
      check(`changeExecutor.${m} is a function`, typeof (changeExecutor as any)[m] === 'function');
    }
    const seamFx = await makeDevice({ name: 'cpe-seam', serial: 'SER-SEAM', ppp_username: 'site-seam' } as any);
    routers.push(seamFx.router);
    const seamPlan = await makePlan(seamFx.deviceId);
    const seamJob = await makeClaimedJob({ deviceId: seamFx.deviceId, planId: seamPlan, guardVerdict: 'ACCEPT' });
    const seamCtx: any = {
      job: { id: seamJob, device_id: seamFx.deviceId, tenant_id: TENANT },
      correlationId: 'seam-test',
      planId: seamPlan,
      preflightBackupId: null,
      deadmanHandle: null,
    };

    registerChangeRenderer(null);
    let seamRefusal = '';
    try {
      await changeExecutor.applyChange(seamCtx);
    } catch (err) {
      seamRefusal = err instanceof ChangeError ? err.kind : String(err);
    }
    eq('applyChange REFUSES without a vault -> equipment renderer', seamRefusal, 'SECRET_LEAK_REFUSED');

    registerChangeRenderer(async () =>
      rendered(['/ip firewall filter add chain=forward action=accept comment=obliwan-seam']),
    );
    const seamBackup = await changeExecutor.takePreflightBackup(seamCtx);
    seamCtx.preflightBackupId = seamBackup.backupId;
    check('the seam took a preflight backup', seamBackup.backupId > 0);
    const seamArm = await changeExecutor.armDeadman(seamCtx);
    seamCtx.deadmanHandle = seamArm.handle;
    eq('the seam reports the level it ACTUALLY obtained', seamArm.level, 'armed');
    check('and a deadline the UI can count down to', seamArm.confirmDeadline instanceof Date);
    const seamApply = await changeExecutor.applyChange(seamCtx);
    eq('the seam applied one op', seamApply.appliedOps, 1);
    const seamVerify = await changeExecutor.verify(seamCtx);
    eq('the seam verified on a fresh socket', seamVerify.ok, true);
    await changeExecutor.disarmDeadman(seamCtx);
    eq('the seam left no scheduler behind', seamFx.router.schedulerNames().length, 0);
    eq('and no backup blob on the equipment', seamFx.router.fileNames().length, 0);
    registerChangeRenderer(null);
    await db('change_jobs').where({ id: seamJob }).update({ status: 'aborted', finished_at: new Date() });

    // ======================================================================
    console.log('\n== 14. canonical .rsc comparison is not fooled by the header ==');
    // ======================================================================
    const a = '# 2026-08-29 10:00:00 by RouterOS 7.14.3\n/ip address add address=1.2.3.4\n';
    const b = '# 2026-08-29 23:59:59 by RouterOS 7.14.3\n/ip address add address=1.2.3.4\n';
    eq('two exports of the same config hash the same', canonicalRscHash(a), canonicalRscHash(b));
    const c = '# x\n/ip address add address=1.2.3.5\n';
    check('a real difference still differs', canonicalRscHash(a) !== canonicalRscHash(c));
  } finally {
    for (const r of routers) await r.close().catch(() => undefined);
    for (const r of receivers) await r.stop().catch(() => undefined);
    await fsp.rm(backupRoot(), { recursive: true, force: true }).catch(() => undefined);
  }

  console.log('\n===========================================================');
  console.log(`  ${passed} passed, ${failures.length} failed`);
  if (numbers.length) {
    console.log('\n  observed numbers:');
    for (const n of numbers) console.log(`    ${n}`);
  }
  if (failures.length) {
    console.log('\n  failures:');
    for (const f of failures) console.log(`    - ${f}`);
  }
  console.log('===========================================================\n');
  await db.destroy();
  process.exit(failures.length === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error('\nFATAL', err);
  await db.destroy().catch(() => undefined);
  process.exit(2);
});
