/**
 * ObliWAN M6 — the change queue, verified against a real PostgreSQL.
 *
 * WHAT THIS FILE PROVES, AND WHAT IT CANNOT
 *
 * It proves the REFUSALS. Every safety property of the queue is a refusal —
 * the device is busy, the plan is stale, the guard says no, the switch is
 * engaged, the audit could not be written — and every one of them is either a
 * database constraint or a line in this service layer, so every one of them is
 * testable without hardware.
 *
 * It does NOT prove that a router does anything. There is no equipment on this
 * machine, real or emulated, beyond a fake RouterOS API socket that answers
 * `/system/identity/print`. The dead-man, the rollback script and the restore
 * are `safeApply`'s (K1) and are injected here as a FAKE executor whose only
 * job is to record that it was — or was not — called. "applyChange was never
 * called" is a strong statement about this queue and says nothing whatsoever
 * about MikroTik.
 *
 *   DATABASE_URL=… npx tsx src/services/change/testing/m6-queue.verify.ts
 */

import { spawn } from 'child_process';
import path from 'path';
import { ncmHash, type NcmDocument, type ApplyPlan as ApplyPlanType } from '@obliwan/shared';
import { db } from '../../../db';
import { encrypt } from '../../secretVault.service';
import { FakeRouterOs } from '../../transport/routeros/testing/fakeRouterosServer';
import {
  auditedCommand,
  listCommandAudit,
  recordCommandIntent,
  redactArgs,
  redactCommand,
} from '../../audit.service';
import {
  claimNextJob,
  isWithinMaintenanceWindow,
  reapExpiredLeases,
  transitionJob,
  getJobRow,
  listJobSteps,
  LEASE_TTL_MS,
  type ChangeJobRow,
} from '../jobQueue.service';
import {
  engageKillSwitch,
  killSwitchBlocks,
  readKillSwitch,
  releaseKillSwitch,
} from '../killSwitch.service';
import {
  ChangeRefusedError,
  enqueueChangeJob,
  recordOverride,
  runJob,
  setChangeExecutor,
  currentExecutor,
  previewChange,
  type ChangeExecutor,
} from '../apply.service';
import { DeviceBusyError } from '../jobQueue.service';
import { StalePlanError } from '../../plan/planner.service';
import {
  baseDoc, harmlessOp, lockoutOps, rule as fixtureRule, MGMT_ADDRESS, CHR_ADDRESS,
} from './fixtures';

// ============================================================================
// Harness
// ============================================================================

let passed = 0;
let failed = 0;
const failures: string[] = [];

function ok(label: string, cond: boolean, extra = ''): void {
  if (cond) {
    passed++;
    console.log(`  PASS  ${label}${extra ? ' — ' + extra : ''}`);
  } else {
    failed++;
    failures.push(label);
    console.log(`  FAIL  ${label}${extra ? ' — ' + extra : ''}`);
  }
}
function eq(label: string, a: unknown, b: unknown): void {
  ok(label, JSON.stringify(a) === JSON.stringify(b), `got ${JSON.stringify(a)} want ${JSON.stringify(b)}`);
}
function section(t: string): void {
  console.log(`\n=== ${t} ===`);
}
async function throws(
  label: string,
  fn: () => Promise<unknown>,
  test: (err: unknown) => boolean,
  describe: (err: unknown) => string = (e) => String(e),
): Promise<void> {
  try {
    await fn();
    ok(label, false, 'it did NOT throw');
  } catch (err) {
    ok(label, test(err), describe(err));
  }
}

// ============================================================================
// World
// ============================================================================

const TENANT = 1;
let siteId = 0;
let chrId = 0;
let deviceId = 0;
let deviceB = 0;
let draytekId = 0;
let fakeRouter: FakeRouterOs | null = null;
let fakePort = 0;
let requesterId = 0;
let approverId = 0;

const DEVICE_IDENTITY = 'cpe-m6';
const DEVICE_SERIAL = 'HXX0LAB0001'; // what fakeRouterosServer answers

async function reset(): Promise<void> {
  await db.raw('TRUNCATE change_job_steps, change_jobs, change_plans, device_backups, ' +
    'apply_outcomes, command_audit RESTART IDENTITY CASCADE');
  await db('config_snapshots').del();
  await db('device_transports').del();
  await db('devices').del();
  await db('sites').del();
  await db('kill_switch').where('scope', 'tenant').del();
  await db('kill_switch').where('scope', 'global').update({
    engaged: false, reason: null, engaged_at: null, engaged_by: null,
  });
}

async function storeDoc(id: number, doc: NcmDocument): Promise<string> {
  const hash = ncmHash(doc);
  await db('config_snapshots').insert({
    device_id: id,
    source: 'routeros_api',
    ncm: JSON.stringify(doc),
    ncm_hash: hash,
    ncm_version: doc.ncmVersion,
    sem_key_generation: doc.semKeyGeneration,
    normalization_epoch: doc.normalizationEpoch,
    order_analysis: doc.orderAnalysis,
    os_version: doc.device.osVersion,
    model: doc.device.model,
    captured_at: new Date(),
  });
  return hash;
}

/**
 * Two real users, because "the override names a human" is only a proof if the
 * foreign key to `users` actually holds. A test that passes `7` and gets away
 * with it is a test that would still pass if the column were free text.
 */
async function seedUsers(): Promise<void> {
  const upsert = async (username: string): Promise<number> => {
    const existing = (await db('users').where({ username }).first('id')) as
      | { id: number }
      | undefined;
    if (existing) return existing.id;
    const [row] = (await db('users')
      .insert({ username, display_name: username, role: 'user' })
      .returning('id')) as Array<{ id: number }>;
    return row.id;
  };
  requesterId = await upsert('m6-requester');
  approverId = await upsert('m6-approver');
}

async function seed(): Promise<void> {
  await reset();
  await seedUsers();

  [siteId] = await db('sites')
    .insert({ tenant_id: TENANT, code: 'M6', name: 'M6 site', timezone: 'Europe/Paris' })
    .returning('id')
    .then((r: Array<{ id: number }>) => [r[0].id]);

  [chrId] = await db('devices')
    .insert({
      tenant_id: TENANT, name: 'chr-m6', brand: 'mikrotik', family: 'mikrotik_routeros7',
      role: 'concentrator', status: 'active', is_managed: true, tunnel_ip: CHR_ADDRESS,
    })
    .returning('id')
    .then((r: Array<{ id: number }>) => [r[0].id]);

  [deviceId] = await db('devices')
    .insert({
      tenant_id: TENANT, site_id: siteId, name: 'cpe-m6', brand: 'mikrotik',
      family: 'mikrotik_routeros7', role: 'cpe', status: 'active', is_managed: true,
      tunnel_ip: MGMT_ADDRESS, concentrator_id: chrId,
      ppp_username: DEVICE_IDENTITY, system_identity: DEVICE_IDENTITY, serial: DEVICE_SERIAL,
    })
    .returning('id')
    .then((r: Array<{ id: number }>) => [r[0].id]);

  [deviceB] = await db('devices')
    .insert({
      tenant_id: TENANT, site_id: siteId, name: 'cpe-m6-b', brand: 'mikrotik',
      family: 'mikrotik_routeros7', role: 'cpe', status: 'active', is_managed: true,
      tunnel_ip: '10.255.1.6', concentrator_id: chrId,
      ppp_username: 'cpe-m6-b', system_identity: 'cpe-m6-b', serial: 'HXX0LAB0002',
    })
    .returning('id')
    .then((r: Array<{ id: number }>) => [r[0].id]);

  // A DrayTek at another site, with NO co-located MikroTik: §8.3 DEGRADED.
  const [otherSite] = (await db('sites')
    .insert({ tenant_id: TENANT, code: 'M6B', name: 'M6 site B', timezone: 'Europe/Paris' })
    .returning('id')) as Array<{ id: number }>;
  [draytekId] = await db('devices')
    .insert({
      tenant_id: TENANT, site_id: otherSite.id, name: 'vigor-m6', brand: 'draytek',
      family: 'draytek_vigor', role: 'cpe', status: 'active', is_managed: true,
      tunnel_ip: '10.255.1.9', concentrator_id: chrId,
    })
    .returning('id')
    .then((r: Array<{ id: number }>) => [r[0].id]);

  // The routeros_api transport for the CPE, pointed at the fake router.
  await db('device_transports').insert({
    device_id: deviceId,
    transport: 'routeros_api',
    enabled: true,
    host: '127.0.0.1',
    port: fakePort,
    username: 'obliwan',
    secret_enc: encrypt('s3cr3t'),
    use_tls: false,
  });

  await storeDoc(deviceId, baseDoc(deviceId, DEVICE_IDENTITY, DEVICE_SERIAL));
  await storeDoc(deviceB, baseDoc(deviceB, 'cpe-m6-b', 'HXX0LAB0002'));
}

/** A compiled plan envelope, as `/api/plan/devices/:id` would have returned. */
function planFor(id: number, hash: string, ops: ApplyPlanType['ops']): ApplyPlanType {
  return {
    planUuid: crypto.randomUUID(),
    deviceId: id,
    source: 'template',
    ncmVersion: 1,
    semKeyGeneration: 1,
    baseStateHash: hash,
    ops,
    riskLevel: 'high',
    mgmtPathVerdict: 'indeterminate',
    blastRadius: {
      deviceCount: 1,
      siteCount: 1,
      affectedInterfaces: [],
      affectedSubnets: [],
      touchesManagementPath: true,
    },
    expiresAt: new Date(Date.now() + 20 * 60 * 1000).toISOString(),
    orderConverges: true,
  };
}

// ============================================================================
// The fake executor — it records, it never dials
// ============================================================================

interface ExecutorLog {
  calls: string[];
  backupId: number | null;
  /** Run just before `applyChange` would have been reached. */
  beforeApply?: () => Promise<void>;
  failVerify?: boolean;
  armLevel?: 'armed' | 'armed_by_peer' | 'degraded';
}

function fakeExecutor(log: ExecutorLog): ChangeExecutor {
  return {
    async takePreflightBackup(ctx) {
      log.calls.push('takePreflightBackup');
      const rows = (await db('device_backups')
        .insert({
          tenant_id: ctx.job.tenant_id,
          device_id: ctx.device.id,
          kind: 'binary',
          trigger_kind: 'preflight',
          storage_path: `m6/${ctx.job.id}.backup`,
          size_bytes: 1024,
          sha256: 'a'.repeat(64),
          taken_before_job_id: ctx.job.id,
        })
        .returning('id')) as Array<{ id: string | number }>;
      log.backupId = Number(rows[0].id);
      return { backupId: log.backupId };
    },
    async armDeadman(ctx) {
      log.calls.push('armDeadman');
      if (log.beforeApply) await log.beforeApply();
      return {
        handle: `obliwan-rollback-${ctx.job.id}`,
        level: log.armLevel ?? ctx.job.safety_level,
        confirmDeadline: new Date(Date.now() + 10 * 60 * 1000),
      };
    },
    async applyChange() {
      log.calls.push('applyChange');
      return { appliedOps: 1, outputRedacted: 'fake: 1 op applied' };
    },
    async verify() {
      log.calls.push('verify');
      return log.failVerify
        ? { ok: false, errorRedacted: 'fake: post-conditions did not hold' }
        : { ok: true, detail: { probed: true } };
    },
    async disarmDeadman() {
      log.calls.push('disarmDeadman');
    },
    async runReadOnly() {
      log.calls.push('runReadOnly');
      return { outputRedacted: 'fake: export taken' };
    },
  };
}

// ============================================================================
// 1. Redaction (§8.2 / R10)
// ============================================================================

function testRedaction(): void {
  section('1. §8.2 — redaction is applied BEFORE the row is written');

  ok(
    'password= is masked in a RouterOS command',
    redactCommand('/ppp/secret/set name=site-001 password=hunter2') ===
      '/ppp/secret/set name=site-001 password=***',
    redactCommand('/ppp/secret/set name=site-001 password=hunter2'),
  );
  ok(
    'a quoted secret is masked, quotes and all',
    !redactCommand('/ip/ipsec/peer/set secret="Tr0ub4dor&3"').includes('Tr0ub4dor'),
    redactCommand('/ip/ipsec/peer/set secret="Tr0ub4dor&3"'),
  );
  ok(
    'a space-separated CLI secret is masked (DrayTek / SonicWall shape)',
    redactCommand('snmp-server community pr1vateC0mmunity ro') ===
      'snmp-server community *** ro',
    redactCommand('snmp-server community pr1vateC0mmunity ro'),
  );
  ok(
    'a non-secret assignment is left readable',
    redactCommand('/ip/address/add address=10.0.0.1/24 interface=ether1') ===
      '/ip/address/add address=10.0.0.1/24 interface=ether1',
  );
  ok(
    'a known vault literal is masked even with no attribute name in front of it',
    redactCommand('some rsc body containing Tr0ub4dor&3 inline', ['Tr0ub4dor&3']) ===
      'some rsc body containing *** inline',
  );
  eq(
    'a nested secret-named key is masked whatever its value type',
    redactArgs({ user: 'admin', credentials: { password: 'x', apiKey: 'y' }, port: 8728 }),
    { user: 'admin', credentials: '***', port: 8728 },
  );
  eq(
    'an array of assignments is redacted element by element',
    redactArgs(['name=a', 'psk=verysecret']),
    ['name=a', 'psk=***'],
  );
}

// ============================================================================
// 2. Maintenance windows
// ============================================================================

function testWindows(): void {
  section('2. Maintenance windows — a job outside its window WAITS');

  const wed0300 = new Date('2026-09-02T01:00:00.000Z'); // 03:00 Paris, a Wednesday
  const wed1400 = new Date('2026-09-02T12:00:00.000Z'); // 14:00 Paris

  ok('no window at all is always open', isWithinMaintenanceWindow(null, 'Europe/Paris', wed1400).open);
  ok(
    'inside a 22:00-06:00 overnight window',
    isWithinMaintenanceWindow(
      { days: ['mon', 'tue', 'wed'], start: '22:00', end: '06:00' },
      'Europe/Paris',
      wed0300,
    ).open,
  );
  ok(
    'outside the same overnight window at 14:00',
    !isWithinMaintenanceWindow(
      { days: ['mon', 'tue', 'wed'], start: '22:00', end: '06:00' },
      'Europe/Paris',
      wed1400,
    ).open,
  );
  ok(
    'a day the window does not include is closed',
    !isWithinMaintenanceWindow({ days: ['sun'], start: '00:00', end: '23:59' }, 'Europe/Paris', wed0300)
      .open,
  );
  ok(
    'numeric days (0 = Sunday) are understood too',
    isWithinMaintenanceWindow({ days: [3], start: '00:00', end: '23:00' }, 'Europe/Paris', wed0300).open,
  );
  ok(
    'THE SITE timezone decides, not the server: 03:00 Paris is 05:00 in Réunion',
    !isWithinMaintenanceWindow(
      { days: ['wed'], start: '02:00', end: '04:00' },
      'Indian/Reunion',
      wed0300,
    ).open,
  );
  const bad = isWithinMaintenanceWindow({ days: ['mon'], start: 'quarter past', end: '06:00' }, 'UTC', wed0300);
  ok('a MALFORMED window fails CLOSED (the job waits, it is not pushed)', !bad.open, bad.reason ?? '');
  const badTz = isWithinMaintenanceWindow({ start: '00:00', end: '23:00' }, 'Mars/Olympus', wed0300);
  ok('an INVALID timezone fails CLOSED', !badTz.open, badTz.reason ?? '');
  ok(
    'an explicitly disabled window is open',
    isWithinMaintenanceWindow({ enabled: false, days: ['sun'], start: '01:00', end: '02:00' }, 'UTC', wed1400)
      .open,
  );
}

// ============================================================================
// 3. Kill switch
// ============================================================================

async function testKillSwitch(): Promise<void> {
  section('3. The kill switch — fail-closed, and read again before the write');

  eq('disengaged: not blocked', (await readKillSwitch(TENANT)).blocked, false);
  eq('kill_switch_blocks(1) agrees', await killSwitchBlocks(TENANT), false);

  await engageKillSwitch({ scope: 'global', tenantId: null, reason: 'M6 test', userId: null });
  const engaged = await readKillSwitch(TENANT);
  eq('global engaged: blocked', engaged.blocked, true);
  eq('…and it says WHICH switch', engaged.by, 'global');
  eq('…and carries the operator sentence', engaged.reason, 'M6 test');
  eq('kill_switch_blocks(1) agrees', await killSwitchBlocks(TENANT), true);
  eq('a different tenant is blocked too', await killSwitchBlocks(999), true);

  await releaseKillSwitch({ scope: 'global', tenantId: null, userId: null });
  eq('released: not blocked', (await readKillSwitch(TENANT)).blocked, false);

  await engageKillSwitch({ scope: 'tenant', tenantId: TENANT, reason: 'one client', userId: null });
  eq('tenant switch blocks its own tenant', (await readKillSwitch(TENANT)).blocked, true);
  eq('…and NOT another tenant', await killSwitchBlocks(999), false);
  await releaseKillSwitch({ scope: 'tenant', tenantId: TENANT, userId: null });

  // FAIL-CLOSED, proved by removing the row inside a transaction.
  await db
    .transaction(async (trx) => {
      await trx.raw('ALTER TABLE kill_switch DISABLE TRIGGER kill_switch_protect_global');
      await trx('kill_switch').where('scope', 'global').del();
      const decision = await readKillSwitch(TENANT, trx);
      eq('a MISSING global row blocks every write (fail-closed)', decision.blocked, true);
      eq('kill_switch_blocks() agrees', await killSwitchBlocks(TENANT, trx), true);
      throw new Error('rollback');
    })
    .catch(() => undefined);
  eq('…and the row is back after the rollback', (await readKillSwitch(TENANT)).blocked, false);

  // A database that cannot be read is a database that cannot authorise a write.
  const brokenQ = (() => {
    throw new Error('connection terminated');
  }) as never;
  eq(
    'a kill-switch read that THROWS is treated as ENGAGED',
    (await readKillSwitch(TENANT, brokenQ)).blocked,
    true,
  );
}

// ============================================================================
// 4. The audit — no trace, no write
// ============================================================================

async function testAudit(): Promise<void> {
  section('4. `command_audit` — if the audit write fails, the device write does not happen');

  const intent = {
    tenantId: TENANT,
    deviceId,
    deviceName: 'cpe-m6',
    transport: 'routeros_api' as const,
    command: '/ppp/secret/set name=site-001 password=hunter2',
    isWrite: true,
    args: { password: 'hunter2', name: 'site-001' },
    secrets: ['hunter2'],
  };

  let sent = false;
  await auditedCommand(intent, async () => {
    sent = true;
    return 'ok';
  });
  ok('the happy path sends', sent);

  const listed = await listCommandAudit(TENANT, { deviceId });
  eq('one folded line per command (attempt + result merged)', listed.rows.length, 1);
  eq('the outcome is recorded', listed.rows[0].success, true);
  ok(
    'THE SECRET IS NOT IN THE DATABASE',
    !listed.rows[0].command.includes('hunter2') &&
      !JSON.stringify(listed.rows[0].args).includes('hunter2'),
    listed.rows[0].command,
  );
  const rawRows = (await db('command_audit').select('command', 'args_redacted')) as Array<{
    command: string;
    args_redacted: unknown;
  }>;
  ok(
    '…not in ANY raw row either',
    !JSON.stringify(rawRows).includes('hunter2'),
  );

  // Append-only: the trigger refuses an UPDATE, which is why the result is a
  // second row rather than a patch of the first.
  await throws(
    'command_audit refuses UPDATE (append-only)',
    () => db('command_audit').where({ id: 1 }).update({ success: false }),
    (err) => String(err).includes('append-only'),
    (err) => String(err).slice(0, 90),
  );

  // THE PROPERTY. A real database-level failure of the audit insert, and the
  // send function must never run.
  let sentUnderFailure = false;
  await db
    .transaction(async (trx) => {
      await trx.raw('ALTER TABLE command_audit ADD CONSTRAINT m6_break CHECK (false)');
      try {
        await auditedCommand(
          { ...intent, command: '/system/reboot' },
          async () => {
            sentUnderFailure = true;
            return 'ok';
          },
          trx,
        );
        ok('an audit write failure ABORTS the operation', false, 'auditedCommand did not throw');
      } catch (err) {
        ok(
          'an audit write failure ABORTS the operation',
          !sentUnderFailure,
          `threw ${String(err).slice(0, 60)}… and the send function was ${
            sentUnderFailure ? 'CALLED' : 'never called'
          }`,
        );
      }
      throw new Error('rollback');
    })
    .catch(() => undefined);
  ok('…and nothing reached the device', !sentUnderFailure);

  await throws(
    'recordCommandIntent propagates its failure rather than swallowing it',
    async () =>
      db.transaction(async (trx) => {
        await trx.raw('ALTER TABLE command_audit ADD CONSTRAINT m6_break2 CHECK (false)');
        await recordCommandIntent({ ...intent, command: '/x' }, trx);
      }),
    (err) => err instanceof Error,
  );
}

// ============================================================================
// 5. The guard at the door: REJECT blocks, a signed override unblocks
// ============================================================================

async function testGuardGate(): Promise<{ rejectJobId: number }> {
  section('5. The Management-Path Guard at enqueue — REJECT blocks, an override is SIGNED');

  const hash = ncmHash(baseDoc(deviceId, DEVICE_IDENTITY, DEVICE_SERIAL));
  const lockout = planFor(deviceId, hash, [...lockoutOps()]);

  const preview = await previewChange({ tenantId: TENANT, deviceId, kind: 'push', plan: lockout });
  eq('preview: the guard REJECTS `chain=input action=drop`', preview.guard.verdict, 'REJECT');
  eq('preview: the impact screen says an override is required', preview.requiresOverride, true);
  eq('preview: the safety net is shown BEFORE launch', preview.safetyNet.level, 'armed');
  ok('preview writes nothing', (await db('change_jobs').count({ c: '*' }))[0].c === '0');

  await throws(
    'a REJECT plan CANNOT be queued without an override',
    () =>
      enqueueChangeJob({
        tenantId: TENANT, deviceId, kind: 'push', plan: lockout, requestedBy: requesterId,
      }),
    (err) => err instanceof ChangeRefusedError && err.kind === 'guard_refused',
    (err) => String((err as Error).message).slice(0, 110),
  );
  eq('…and no job row exists', (await db('change_jobs').count({ c: '*' }))[0].c, '0');

  const forced = await enqueueChangeJob({
    tenantId: TENANT, deviceId, kind: 'push', plan: lockout, requestedBy: requesterId,
    override: { reason: 'M6 destructive recipe: forcing a proven lockout on purpose.', userId: requesterId },
  });
  eq('an OVERRIDDEN REJECT plan is queued', typeof forced.jobId, 'number');
  eq('…with the verdict preserved as REJECT', forced.guard.verdict, 'REJECT');

  const row = (await db('change_jobs').where({ id: forced.jobId }).first()) as ChangeJobRow;
  ok('…the override names a human', row.overridden_by === requesterId, `overridden_by=${row.overridden_by}`);
  ok('…and carries their sentence verbatim', String(row.override_reason).startsWith('M6 destructive'));
  ok('…and is timestamped', row.overridden_at !== null);
  eq('…the plan is frozen into change_plans', typeof forced.planId, 'number');

  // The database refuses the same thing independently of the service.
  await throws(
    'THE DATABASE refuses a REJECT verdict with no override (independent of the service)',
    () =>
      db('change_jobs').insert({
        tenant_id: TENANT, device_id: deviceB, kind: 'push', status: 'queued',
        base_state_hash: hash, safety_level: 'armed', guard_verdict: 'REJECT',
        plan_id: forced.planId,
      }),
    (err) => String(err).includes('change_jobs_override_chk'),
    (err) => String(err).slice(0, 80),
  );
  await throws(
    'THE DATABASE refuses INDETERMINATE with no override — indeterminate is NOT accept',
    () =>
      db('change_jobs').insert({
        tenant_id: TENANT, device_id: deviceB, kind: 'push', status: 'queued',
        base_state_hash: hash, safety_level: 'armed', guard_verdict: 'INDETERMINATE',
        plan_id: forced.planId,
      }),
    (err) => String(err).includes('change_jobs_override_chk'),
  );

  // The frozen plan is frozen.
  await throws(
    'the frozen plan cannot be edited after approval (D3, "plan figé")',
    () => db('change_plans').where({ id: forced.planId }).update({ ops: JSON.stringify([]) }),
    (err) => String(err).includes('frozen'),
    (err) => String(err).slice(0, 70),
  );

  return { rejectJobId: forced.jobId };
}

// ============================================================================
// 6. One job in flight per device — BY THE DATABASE
// ============================================================================

async function testOnePerDevice(): Promise<void> {
  section('6. One job in flight per device — enforced by a unique index, not by a check');

  const hash = ncmHash(baseDoc(deviceId, DEVICE_IDENTITY, DEVICE_SERIAL));
  const plan = planFor(deviceId, hash, [...lockoutOps()]);

  await throws(
    'a SECOND job on the same device is refused',
    () =>
      enqueueChangeJob({
        tenantId: TENANT, deviceId, kind: 'push', plan, requestedBy: requesterId,
        override: { reason: 'second attempt, should be refused by the index', userId: requesterId },
      }),
    (err) => err instanceof DeviceBusyError,
    (err) => String((err as Error).message).slice(0, 90),
  );

  await throws(
    'and a raw INSERT is refused too — 23505 on change_jobs_one_in_flight_uq',
    () =>
      db('change_jobs').insert({
        tenant_id: TENANT, device_id: deviceId, kind: 'backup', status: 'queued',
        base_state_hash: hash, safety_level: 'armed',
      }),
    (err) =>
      (err as { code?: string }).code === '23505' &&
      String((err as { constraint?: string }).constraint) === 'change_jobs_one_in_flight_uq',
  );

  const other = await enqueueChangeJob({
    tenantId: TENANT, deviceId: deviceB, kind: 'backup', requestedBy: requesterId,
  });
  ok('a job on a DIFFERENT device is allowed', other.jobId > 0);
  await db('change_jobs').where({ id: other.jobId }).update({
    status: 'aborted', finished_at: db.fn.now(),
  });

  const counts = (await db('change_jobs')
    .whereIn('status', ['queued', 'claimed', 'backing_up', 'arming', 'applying', 'verifying', 'soaking', 'disarming'])
    .groupBy('device_id')
    .select('device_id')
    .count({ c: '*' })) as Array<{ device_id: number; c: string }>;
  ok(
    'no device holds more than one active job',
    counts.every((r) => Number(r.c) === 1),
    JSON.stringify(counts),
  );
}

// ============================================================================
// 7. Staleness
// ============================================================================

async function testStalePlan(): Promise<void> {
  section('7. A stale plan is REFUSED (the device moved under us)');

  const doc = baseDoc(deviceB, 'cpe-m6-b', 'HXX0LAB0002');
  const hash = ncmHash(doc);
  const plan = planFor(deviceB, hash, [harmlessOp(doc)]);

  // Somebody edits the box in Winbox: a new snapshot, a new hash.
  const moved = baseDoc(deviceB, 'cpe-m6-b', 'HXX0LAB0002');
  moved.resources.firewallRules.push(
    fixtureRule({ slug: 'someone-elses-rule', chain: 'forward', action: 'accept' }),
  );
  await storeDoc(deviceB, moved);
  ok('the device now has a different state hash', ncmHash(moved) !== hash);

  await throws(
    'a plan compiled against the old state cannot be queued',
    () =>
      enqueueChangeJob({
        tenantId: TENANT, deviceId: deviceB, kind: 'push', plan, requestedBy: requesterId,
        override: { reason: 'even an override must not get a stale plan through', userId: requesterId },
      }),
    (err) => err instanceof StalePlanError,
    (err) => String((err as Error).message).slice(0, 110),
  );
  eq(
    'no job was created for the stale plan',
    (await db('change_jobs').where({ device_id: deviceB }).whereIn('status', ['queued']).count({ c: '*' }))[0].c,
    '0',
  );
}



// ============================================================================
// 8. Two PROCESSES claiming at once
// ============================================================================

async function testConcurrentClaims(): Promise<void> {
  section('8. Two worker PROCESSES racing on FOR UPDATE SKIP LOCKED');

  await reset();
  // 24 devices, one queued job each. `change_jobs_one_in_flight_uq` means one
  // job per device, so the only way to have 24 claimable jobs is 24 devices —
  // which is also the realistic shape of a wave.
  const hash = 'b'.repeat(64);
  const ids: number[] = [];
  for (let i = 0; i < 24; i++) {
    const [d] = (await db('devices')
      .insert({
        tenant_id: TENANT, name: `race-${i}`, brand: 'mikrotik', family: 'mikrotik_routeros7',
        role: 'cpe', status: 'active', is_managed: true, tunnel_ip: `10.66.9.${i + 1}`,
      })
      .returning('id')) as Array<{ id: number }>;
    const [j] = (await db('change_jobs')
      .insert({
        tenant_id: TENANT, device_id: d.id, kind: 'backup', status: 'queued',
        base_state_hash: hash, safety_level: 'armed', max_attempts: 1,
      })
      .returning('id')) as Array<{ id: string | number }>;
    ids.push(Number(j.id));
  }

  const child = path.join(__dirname, 'claimer.child.ts');
  const results = await Promise.all([runChild(child), runChild(child), runChild(child)]);

  const all = results.flatMap((r) => r.claimed);
  const unique = new Set(all);
  eq('every queued job was claimed exactly once', all.length, 24);
  eq('…and NO job was claimed twice', unique.size, all.length);
  ok(
    'the work was actually shared between the processes',
    results.filter((r) => r.claimed.length > 0).length >= 2,
    results.map((r) => `${r.worker.slice(-8)}:${r.claimed.length}`).join(' '),
  );
  const workers = (await db('change_jobs').distinct('claimed_by').pluck('claimed_by')) as string[];
  ok('…and each row names the worker that took it', workers.every((w) => Boolean(w)), workers.join(' '));
}

function runChild(script: string): Promise<{ worker: string; claimed: number[] }> {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [require.resolve('tsx/cli'), script], {
      env: process.env,
      cwd: path.resolve(__dirname, '../../../..'),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    proc.stdout.on('data', (d) => (out += String(d)));
    proc.stderr.on('data', (d) => (err += String(d)));
    proc.on('close', (code) => {
      const line = out.trim().split('\n').filter((l) => l.startsWith('{')).pop();
      if (!line) return reject(new Error(`child exited ${code}: ${err.slice(-500)}`));
      resolve(JSON.parse(line) as { worker: string; claimed: number[] });
    });
  });
}

// ============================================================================
// 9. Crash recovery
// ============================================================================

async function testCrashRecovery(): Promise<void> {
  section('9. A job held by a DEAD worker — the lease, not a flag');

  await reset();
  const hash = 'c'.repeat(64);
  const [d1] = (await db('devices')
    .insert({ tenant_id: TENANT, name: 'dead-1', brand: 'mikrotik', family: 'mikrotik_routeros7', status: 'active', is_managed: true })
    .returning('id')) as Array<{ id: number }>;
  const [d2] = (await db('devices')
    .insert({ tenant_id: TENANT, name: 'dead-2', brand: 'mikrotik', family: 'mikrotik_routeros7', status: 'active', is_managed: true })
    .returning('id')) as Array<{ id: number }>;
  const [d3] = (await db('devices')
    .insert({ tenant_id: TENANT, name: 'dead-3', brand: 'mikrotik', family: 'mikrotik_routeros7', status: 'active', is_managed: true })
    .returning('id')) as Array<{ id: number }>;

  const past = new Date(Date.now() - 60_000);
  const mk = async (deviceIdX: number, status: string, kind = 'backup') => {
    const [j] = (await db('change_jobs')
      .insert({
        tenant_id: TENANT, device_id: deviceIdX, kind, status,
        base_state_hash: hash, safety_level: 'armed', attempt: 1, max_attempts: 1,
        claimed_by: 'ghost:9999:deadbeef', claimed_at: past, lease_expires_at: past,
        started_at: past,
      })
      .returning('id')) as Array<{ id: string | number }>;
    return Number(j.id);
  };

  const claimedJob = await mk(d1.id, 'claimed');
  const backingUp = await mk(d2.id, 'backing_up');
  const applying = await mk(d3.id, 'applying');

  const report = await reapExpiredLeases();
  eq('one CLAIMED job was requeued', report.requeued, 1);
  eq('one BACKING_UP job was failed (nothing was pushed, but not resumable)', report.failed, 1);
  eq('the APPLYING job was flagged for a human', report.needingInspection, [applying]);

  const after1 = (await db('change_jobs').where({ id: claimedJob }).first()) as ChangeJobRow;
  eq('…the requeued job is queued again', after1.status, 'queued');
  eq('…it holds nothing', [after1.claimed_by, after1.claimed_at, after1.lease_expires_at], [null, null, null]);
  eq(
    '…and its attempt was GIVEN BACK, so max_attempts=1 does not brick it',
    after1.attempt,
    0,
  );

  const reclaimed = await claimNextJob('resurrected:1:aaaa');
  ok('…so a live worker CAN claim it again', reclaimed !== null && Number(reclaimed.id) === claimedJob);
  eq('…and the new worker owns it', reclaimed?.claimed_by, 'resurrected:1:aaaa');

  const after2 = (await db('change_jobs').where({ id: backingUp }).first()) as ChangeJobRow;
  eq('…the backing_up job is failed, not requeued', after2.status, 'failed');
  eq('…with an error kind', after2.error_kind, 'worker_lost');

  const after3 = (await db('change_jobs').where({ id: applying }).first()) as ChangeJobRow;
  eq('THE APPLYING JOB WAS NOT TOUCHED — status', after3.status, 'applying');
  eq('…still names the dead worker (nothing was rewritten)', after3.claimed_by, 'ghost:9999:deadbeef');
  eq('…and was NOT requeued', after3.finished_at, null);

  // Second pass: the reaper must be idempotent and must still not touch it.
  const again = await reapExpiredLeases();
  eq('a second reap requeues nothing new', again.requeued, 0);
  eq('…and still refuses to requeue the write-committed job', again.needingInspection, [applying]);
}

// ============================================================================
// 10. runJob — the kill switch DURING a job, and the full happy path
// ============================================================================

async function testRunJob(): Promise<void> {
  section('10. runJob — the kill switch engaged WHILE a job runs stops the write');

  await seed();
  const hash = ncmHash(baseDoc(deviceId, DEVICE_IDENTITY, DEVICE_SERIAL));
  const plan = planFor(deviceId, hash, [...lockoutOps()]);

  const log: ExecutorLog = { calls: [], backupId: null };
  setChangeExecutor(fakeExecutor(log));

  // The switch is engaged from inside `armDeadman`, i.e. AFTER the job started
  // and BEFORE the write. That is precisely the moment the gesture is made.
  log.beforeApply = async () => {
    await engageKillSwitch({
      scope: 'global', tenantId: null, reason: 'operator pulled the cord mid-job', userId: approverId,
    });
  };

  const enq = await enqueueChangeJob({
    tenantId: TENANT, deviceId, kind: 'push', plan, requestedBy: requesterId,
    override: { reason: 'M6 destructive recipe: forcing a proven lockout on purpose.', userId: requesterId },
  });
  const claimed = await claimNextJob('m6-verify:1:aaaa');
  ok('the job was claimed', claimed !== null && Number(claimed.id) === enq.jobId);
  await runJob(claimed as ChangeJobRow, 'm6-verify:1:aaaa');

  const finished = (await db('change_jobs').where({ id: enq.jobId }).first()) as ChangeJobRow;
  eq('the job FAILED', finished.status, 'failed');
  eq('…because of the kill switch', finished.error_kind, 'kill_switch');
  ok(
    'THE WRITE NEVER HAPPENED — applyChange was not called',
    !log.calls.includes('applyChange'),
    `executor calls: ${log.calls.join(' -> ')}`,
  );
  ok('…but the backup and the dead-man had already run', log.calls.includes('armDeadman'));
  ok(
    '…and the operator is told a dead-man is still armed',
    String(finished.error_message).includes('STILL ARMED'),
    String(finished.error_message).slice(0, 120),
  );
  const steps = await listJobSteps(TENANT, enq.jobId);
  eq(
    'the trace shows every step that was attempted, in order',
    steps.map((s) => s.kind),
    ['bind_assert', 'guard', 'preflight_backup', 'arm_deadman', 'record_outcome'],
  );
  eq(
    'apply_outcomes recorded the failure (the device HAD been touched)',
    (await db('apply_outcomes').count({ c: '*' }))[0].c,
    '1',
  );
  const outcome = (await db('apply_outcomes').first()) as Record<string, unknown>;
  eq('…as lost_contact, pessimistically', outcome.outcome, 'lost_contact');
  eq('…flagged as an override', outcome.was_override, true);

  await releaseKillSwitch({ scope: 'global', tenantId: null, userId: approverId });

  // ── The happy path, on a plan the guard ACCEPTS ─────────────────────────
  section('10b. runJob — a plan the guard ACCEPTS runs to `succeeded`');

  await db.raw('TRUNCATE change_job_steps, change_jobs, change_plans, device_backups, apply_outcomes RESTART IDENTITY CASCADE');
  const log2: ExecutorLog = { calls: [], backupId: null };
  setChangeExecutor(fakeExecutor(log2));

  const good = planFor(deviceId, hash, [harmlessOp(baseDoc(deviceId, DEVICE_IDENTITY, DEVICE_SERIAL))]);
  const enq2 = await enqueueChangeJob({
    tenantId: TENANT, deviceId, kind: 'push', plan: good, requestedBy: requesterId,
  });
  eq('a harmless plan needs NO override', enq2.guard.verdict, 'ACCEPT');
  const claimed2 = await claimNextJob('m6-verify:1:bbbb');
  await runJob(claimed2 as ChangeJobRow, 'm6-verify:1:bbbb');

  const done = (await db('change_jobs').where({ id: enq2.jobId }).first()) as ChangeJobRow;
  eq('the job succeeded', done.status, 'succeeded');
  eq(
    'the executor was driven in the mandated order',
    log2.calls,
    ['takePreflightBackup', 'armDeadman', 'applyChange', 'verify', 'disarmDeadman'],
  );
  ok('R1: a pre-change backup is linked to the job', done.preflight_backup_id !== null);
  ok('the dead-man was armed…', done.deadman_armed_at !== null);
  ok('…and disarmed before `succeeded`', done.deadman_disarmed_at !== null);
  const steps2 = await listJobSteps(TENANT, enq2.jobId);
  eq(
    'the full trace',
    steps2.map((s) => s.kind),
    ['bind_assert', 'guard', 'preflight_backup', 'arm_deadman', 'apply', 'reconnect', 'postcheck',
      'soak', 'disarm', 'record_outcome'],
  );
  const outcome2 = (await db('apply_outcomes').first()) as Record<string, unknown>;
  eq('apply_outcomes: succeeded', outcome2.outcome, 'succeeded');
  eq('…with the brand for the corpus', outcome2.brand, 'mikrotik');

  // ── R1 proved structurally: the row cannot even exist without a backup ──
  await throws(
    'R1: a WRITE job at `arming` with no preflight backup CANNOT EXIST',
    () =>
      db('change_jobs').insert({
        tenant_id: TENANT, device_id: deviceB, kind: 'restore', status: 'arming',
        base_state_hash: hash, safety_level: 'armed', guard_verdict: 'ACCEPT',
        claimed_by: 'x', claimed_at: db.fn.now(),
      }),
    (err) => String(err).includes('change_jobs_preflight_backup_chk'),
    (err) => String(err).slice(0, 80),
  );

  setChangeExecutor(null);
}

// ============================================================================
// 11. §8.3 — DEGRADED demands a confirmation
// ============================================================================

async function testDegraded(): Promise<void> {
  section('11. §8.3 — a DEGRADED device demands an explicit confirmation');

  const preview = await previewChange({ tenantId: TENANT, deviceId: draytekId, kind: 'reboot' });
  eq('a DrayTek with no co-located MikroTik is DEGRADED', preview.safetyNet.level, 'degraded');
  eq('…and the impact screen says a confirmation is required', preview.requiresDegradedConfirmation, true);
  ok(
    '…and says plainly what DEGRADED costs',
    preview.safetyNet.rationale.includes('visit'),
    preview.safetyNet.rationale.slice(0, 100),
  );
  eq(
    'a reboot is INDETERMINATE, never ACCEPT — the guard does not model it',
    preview.guard.verdict,
    'INDETERMINATE',
  );

  await throws(
    'a DEGRADED write cannot be queued without the confirmation',
    () =>
      enqueueChangeJob({
        tenantId: TENANT, deviceId: draytekId, kind: 'reboot', requestedBy: requesterId,
        override: { reason: 'an override is not a degraded confirmation', userId: requesterId },
      }),
    (err) => err instanceof ChangeRefusedError && err.kind === 'degraded_unconfirmed',
    (err) => String((err as Error).message).slice(0, 110),
  );

  const done = await enqueueChangeJob({
    tenantId: TENANT, deviceId: draytekId, kind: 'reboot', requestedBy: requesterId,
    override: { reason: 'planned reboot, customer informed, on site', userId: requesterId },
    confirmDegraded: { userId: requesterId },
  });
  const row = (await db('change_jobs').where({ id: done.jobId }).first()) as ChangeJobRow;
  eq('…and with it, the job exists', row.safety_level, 'degraded');
  ok('…naming who confirmed', row.degraded_confirmed_by === requesterId);

  await db('change_jobs').where({ id: done.jobId }).update({
    status: 'aborted', finished_at: db.fn.now(),
  });

  // A read-only job on a degraded box needs no confirmation: reading cannot
  // lock anybody out.
  const ro = await enqueueChangeJob({
    tenantId: TENANT, deviceId: draytekId, kind: 'export', requestedBy: requesterId,
  });
  ok('a READ-ONLY job on the same box needs no confirmation', ro.jobId > 0);
  await db('change_jobs').where({ id: ro.jobId }).update({
    status: 'aborted', finished_at: db.fn.now(),
  });
}

// ============================================================================
// 12. The override, signed after the fact
// ============================================================================

async function testOverrideEndpointPath(): Promise<void> {
  section('12. Signing an override on a queued job (CHANGE_APPROVE)');

  await db.raw('TRUNCATE change_job_steps, change_jobs, change_plans, device_backups, apply_outcomes RESTART IDENTITY CASCADE');
  const hash = ncmHash(baseDoc(deviceId, DEVICE_IDENTITY, DEVICE_SERIAL));
  const good = planFor(deviceId, hash, [harmlessOp(baseDoc(deviceId, DEVICE_IDENTITY, DEVICE_SERIAL))]);
  const enq = await enqueueChangeJob({
    tenantId: TENANT, deviceId, kind: 'push', plan: good, requestedBy: requesterId,
  });

  await throws(
    'you cannot "override" a verdict the guard ACCEPTED',
    () => recordOverride(TENANT, enq.jobId, approverId, 'signing something nobody refused'),
    (err) => err instanceof ChangeRefusedError && err.kind === 'nothing_to_override',
  );
  await throws(
    'a two-character reason is refused — this line is read after an incident',
    () => recordOverride(TENANT, enq.jobId, approverId, 'ok'),
    (err) => err instanceof ChangeRefusedError && err.kind === 'override_reason_too_short',
  );

  // Now a job that genuinely needs one.
  await db('change_jobs').where({ id: enq.jobId }).update({ status: 'aborted', finished_at: db.fn.now() });
  const lock = planFor(deviceId, hash, [...lockoutOps()]);
  const forced = await enqueueChangeJob({
    tenantId: TENANT, deviceId, kind: 'push', plan: lock, requestedBy: requesterId,
    override: { reason: 'initial signature at enqueue time', userId: requesterId },
  });
  await recordOverride(TENANT, forced.jobId, approverId, 'second reviewer: checked the console access on site');
  const row = (await getJobRow(TENANT, forced.jobId)) as ChangeJobRow;
  eq('the override reason is replaced by the approver’s', row.override_reason, 'second reviewer: checked the console access on site');
  eq('…and the approver is recorded separately', row.approved_by, approverId);

  await throws(
    'an override cannot be signed once the job left the queue',
    async () => {
      await db('change_jobs').where({ id: forced.jobId }).update({
        status: 'claimed', claimed_by: 'x', claimed_at: db.fn.now(),
        lease_expires_at: new Date(Date.now() + LEASE_TTL_MS),
      });
      await recordOverride(TENANT, forced.jobId, approverId, 'too late, the worker has it');
    },
    (err) => err instanceof ChangeRefusedError && err.kind === 'not_queued',
  );
}

// ============================================================================
// 13. Transitions
// ============================================================================

async function testTransitions(): Promise<void> {
  section('13. The state machine — the edges that do not exist');

  await db.raw('TRUNCATE change_job_steps, change_jobs, change_plans, device_backups, apply_outcomes RESTART IDENTITY CASCADE');
  const [j] = (await db('change_jobs')
    .insert({
      tenant_id: TENANT, device_id: deviceB, kind: 'push', status: 'applying',
      base_state_hash: 'd'.repeat(64), safety_level: 'armed', guard_verdict: 'ACCEPT',
      claimed_by: 'x', claimed_at: db.fn.now(), attempt: 1,
      preflight_backup_id: null,
    })
    .returning('*')
    .catch(() => [null])) as Array<ChangeJobRow | null>;
  ok(
    'a push at `applying` with no backup could not even be inserted (R1)',
    j === null || j === undefined,
  );

  const [k] = (await db('change_jobs')
    .insert({
      tenant_id: TENANT, device_id: deviceB, kind: 'export', status: 'applying',
      base_state_hash: 'd'.repeat(64), safety_level: 'armed',
      claimed_by: 'x', claimed_at: db.fn.now(), attempt: 1,
    })
    .returning('*')) as ChangeJobRow[];
  await throws(
    'a job that is APPLYING cannot be aborted — a change already going onto a router',
    () => transitionJob(k, 'aborted'),
    (err) => String(err).includes('applying -> aborted'),
    (err) => String(err).slice(0, 70),
  );
  await throws(
    'and it cannot go back to `queued` either',
    () => transitionJob(k, 'queued'),
    (err) => String(err).includes('applying -> queued'),
  );
  await db('change_jobs').where({ id: k.id }).update({ status: 'failed', finished_at: db.fn.now() });
}

// ============================================================================
// 14. The maintenance window gates the CLAIM, not the outcome
// ============================================================================

async function testWindowGatesClaim(): Promise<void> {
  section('14. A job outside its site maintenance window WAITS — it is not failed');

  await reset();
  const [site] = (await db('sites')
    .insert({
      tenant_id: TENANT, code: 'NIGHT', name: 'night only', timezone: 'Europe/Paris',
      // A window that is closed for all but one hour a week, on a day chosen so
      // this test never accidentally runs inside it.
      maintenance_window: JSON.stringify({ days: ['sun'], start: '03:00', end: '04:00' }),
    })
    .returning('id')) as Array<{ id: number }>;
  const [d] = (await db('devices')
    .insert({
      tenant_id: TENANT, site_id: site.id, name: 'night-cpe', brand: 'mikrotik',
      family: 'mikrotik_routeros7', status: 'active', is_managed: true,
    })
    .returning('id')) as Array<{ id: number }>;
  const [j] = (await db('change_jobs')
    .insert({
      tenant_id: TENANT, device_id: d.id, kind: 'backup', status: 'queued',
      base_state_hash: 'e'.repeat(64), safety_level: 'armed',
    })
    .returning('id')) as Array<{ id: string | number }>;

  const now = new Date();
  const inWindow =
    isWithinMaintenanceWindow(
      { days: ['sun'], start: '03:00', end: '04:00' },
      'Europe/Paris',
      now,
    ).open;

  const claimed = await claimNextJob('window-test:1:aaaa');
  if (inWindow) {
    ok('(we happen to be inside the window right now — claim expected)', claimed !== null);
  } else {
    ok('a job outside its window is NOT claimed', claimed === null);
    const row = (await db('change_jobs').where({ id: j.id }).first()) as ChangeJobRow;
    eq('…and it is still QUEUED, not failed', row.status, 'queued');
    eq('…and it burned no attempt', row.attempt, 0);
    eq('…and holds nothing', row.claimed_by, null);
  }

  // Open the window and the same job becomes claimable, with no other change.
  await db('sites').where({ id: site.id }).update({
    maintenance_window: JSON.stringify({ days: [0, 1, 2, 3, 4, 5, 6], start: '00:00', end: '23:59' }),
  });
  const claimed2 = await claimNextJob('window-test:1:bbbb');
  ok('…and the SAME job is claimed once the window opens', claimed2 !== null && Number(claimed2.id) === Number(j.id));

  // A window nobody can parse must not become a licence to push.
  await db('change_jobs').where({ id: j.id }).update({
    status: 'queued', claimed_by: null, claimed_at: null, lease_expires_at: null,
    started_at: null, attempt: 0,
  });
  await db('sites').where({ id: site.id }).update({
    maintenance_window: JSON.stringify({ days: ['fnord'], start: '00:00', end: '23:59' }),
  });
  eq('an UNPARSEABLE window keeps the job waiting (fail-closed)', await claimNextJob('w:1:c'), null);
}

// ============================================================================
// 15. No executor installed — the queue refuses BEFORE opening a session
// ============================================================================

async function testNoExecutor(): Promise<void> {
  section('15. The executor contract — resolved at runtime, and refused when absent');

  // ── 15a. THE INTEGRATION CHECK ─────────────────────────────────────────
  // K1's `safeApply.service` is reached through a dynamic import and is
  // therefore `any` to the compiler: nothing in `tsc` can tell us the two
  // modules still agree. This is the assertion that can.
  setChangeExecutor(null);
  const real = (await currentExecutor()) as unknown as Record<string, unknown> | null;
  ok(
    'K1 `safeApply.service` resolves as a ChangeExecutor',
    real !== null,
    real === null ? 'NOT PRESENT on this build' : 'present',
  );
  if (real) {
    for (const method of [
      'takePreflightBackup', 'armDeadman', 'applyChange', 'verify', 'disarmDeadman',
    ]) {
      ok(`…and implements ${method}()`, typeof real[method] === 'function');
    }
    ok(
      '…observeRollback() is present, so rolled_back and lost_contact stay distinguishable',
      typeof real.observeRollback === 'function',
    );
    ok(
      'NOTE: runReadOnly() is ABSENT — `export` / `backup` jobs will be refused, not silently faked',
      typeof real.runReadOnly !== 'function',
    );
  }

  // ── 15b. THE REFUSAL, still provable now that the module exists ────────
  await seed();
  setChangeExecutor('none');

  const hash = ncmHash(baseDoc(deviceId, DEVICE_IDENTITY, DEVICE_SERIAL));
  const good = planFor(deviceId, hash, [harmlessOp(baseDoc(deviceId, DEVICE_IDENTITY, DEVICE_SERIAL))]);
  const enq = await enqueueChangeJob({
    tenantId: TENANT, deviceId, kind: 'push', plan: good, requestedBy: requesterId,
  });
  const claimed = await claimNextJob('m6-verify:1:cccc');
  await runJob(claimed as ChangeJobRow, 'm6-verify:1:cccc');

  const row = (await db('change_jobs').where({ id: enq.jobId }).first()) as ChangeJobRow;
  eq('the job failed rather than silently reporting success', row.status, 'failed');
  eq('…with an honest error kind', row.error_kind, 'executor_unavailable');
  eq('…and no backup was taken (nothing was attempted on the box)', row.preflight_backup_id, null);
  eq('…and no dead-man was armed', row.deadman_armed_at, null);
  eq(
    '…and NO row was added to the empirical corpus: this is our refusal, not the hardware',
    (await db('apply_outcomes').count({ c: '*' }))[0].c,
    '0',
  );
  const steps = await listJobSteps(TENANT, enq.jobId);
  ok(
    '…and the trace records the refusal explicitly',
    steps.some((s) => s.kind === 'record_outcome' && s.status === 'skipped'),
    JSON.stringify(steps.map((s) => `${String(s.kind)}:${String(s.status)}`)),
  );
}

// ============================================================================
// 16. The guard is re-run at apply time
// ============================================================================

async function testGuardReRunAtApply(): Promise<void> {
  section('16. The guard runs AGAIN before the write — a verdict that got worse stops the job');

  await seed();
  const log: ExecutorLog = { calls: [], backupId: null };
  setChangeExecutor(fakeExecutor(log));

  const doc = baseDoc(deviceId, DEVICE_IDENTITY, DEVICE_SERIAL);
  const hash = ncmHash(doc);
  const good = planFor(deviceId, hash, [harmlessOp(doc)]);
  const enq = await enqueueChangeJob({
    tenantId: TENANT, deviceId, kind: 'push', plan: good, requestedBy: requesterId,
  });
  eq('queued on an ACCEPT verdict', enq.guard.verdict, 'ACCEPT');

  const rows = (await db('change_plans').where({ id: enq.planId }).first('ops')) as { ops: unknown };
  const ops = (typeof rows.ops === 'string' ? JSON.parse(rows.ops) : rows.ops) as unknown[];
  ok('the frozen plan still holds its ops', Array.isArray(ops) && ops.length === 1);

  // Simulate the dangerous case the re-run exists for: the job carries a
  // guard_verdict a human accepted (ACCEPT, so no override was ever needed) but
  // the plan it now points at REJECTS. The frozen plan cannot be edited — that
  // is the whole point of D3 — so the job is pointed at a different one, which
  // is exactly the shape any future bug in the rollout code would take.
  const [replacement] = (await db('change_plans')
    .insert({
      tenant_id: TENANT, device_id: deviceId, source: 'template',
      base_state_hash: hash, ncm_version: 1, sem_key_generation: 1,
      ops: JSON.stringify(lockoutOps()), ops_count: 2, risk_level: 'high',
      mgmt_path_verdict: 'accept', guard_reasons: '[]', safety_level: 'armed',
      blast_radius: '{}', order_converges: true,
      expires_at: new Date(Date.now() + 3_600_000),
    })
    .returning('id')) as Array<{ id: string | number }>;
  await db('change_jobs').where({ id: enq.jobId }).update({ plan_id: replacement.id });

  const claimed = await claimNextJob('m6-verify:1:dddd');
  await runJob(claimed as ChangeJobRow, 'm6-verify:1:dddd');

  const row = (await db('change_jobs').where({ id: enq.jobId }).first()) as ChangeJobRow;
  eq('the job failed at the guard step', row.status, 'failed');
  eq('…because the verdict got worse than the one that was signed', row.error_kind, 'guard_worsened');
  ok(
    'THE WRITE NEVER HAPPENED',
    !log.calls.includes('applyChange'),
    `executor calls: ${log.calls.join(' -> ') || '(none)'}`,
  );
  ok(
    '…and not even the backup was taken: the guard sits before R1',
    log.calls.length === 0,
  );
  setChangeExecutor(null);
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  console.log('ObliWAN M6 — change queue verification\n');

  fakeRouter = new FakeRouterOs({
    username: 'obliwan',
    password: 's3cr3t',
    identity: DEVICE_IDENTITY,
    boardName: 'hEX-S', // not 'CHR', so /system/routerboard/print answers a serial
  });
  fakePort = await fakeRouter.listen(0);
  console.log(`fake RouterOS API on 127.0.0.1:${fakePort}\n`);

  await db.migrate.latest();
  await seed();

  testRedaction();
  testWindows();
  await testKillSwitch();
  await testAudit();
  await testGuardGate();
  await testOnePerDevice();
  await testStalePlan();
  await testConcurrentClaims();
  await testCrashRecovery();
  await testRunJob();
  await testDegraded();
  await testOverrideEndpointPath();
  await testTransitions();
  await testWindowGatesClaim();
  await testNoExecutor();
  await testGuardReRunAtApply();

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failures.length) {
    console.log('\nFAILURES:');
    for (const f of failures) console.log(`  - ${f}`);
  }

  await fakeRouter.close();
  await db.destroy();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  try {
    await fakeRouter?.close();
    await db.destroy();
  } catch {
    /* going down */
  }
  process.exit(1);
});
