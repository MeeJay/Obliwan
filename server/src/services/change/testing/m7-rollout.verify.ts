/**
 * ObliWAN M7 — wave rollouts, verified against a real PostgreSQL.
 *
 * WHAT THIS FILE PROVES, AND WHAT IT CANNOT
 *
 * It proves the ROLLOUT LAYER: the wave arithmetic, the order of the waves
 * (§8.3), the baseline-before-the-wave rule, the health gate's three-valued
 * verdict, the automatic rollback of the previous waves, the quarantine of the
 * faulty revision, and both halves of §8.5's subtree interlock — the
 * composition refusal and the queue-level one.
 *
 * It does NOT prove that a router does anything. There is no equipment on this
 * machine. The change jobs are created by the REAL `enqueueChangeJob` (guard,
 * safety net, frozen plan, signatures, constraints — all real), and their
 * EXECUTION is simulated by writing the terminal states the queue would have
 * written, exactly as M6's own harness declared for its fake executor. "The
 * rollout stopped at wave 2 and rolled the previous wave back" is a strong
 * statement about this service and says nothing whatsoever about MikroTik.
 *
 *   DATABASE_URL=… npx tsx src/services/change/testing/m7-rollout.verify.ts
 */

import {
  findSubtreeConflicts,
  healthGateVerdictFrom,
  planWaves,
  type HealthBaseline,
} from '@obliwan/shared/dist/rollout';
import { ncmHash, type NcmDocument } from '@obliwan/shared';
import { db } from '../../../db';
import { orderForWaves } from '../../plan/blastRadius.service';
import { judgeDevice, foldWave, type PostWaveSignals } from '../healthGate';
import {
  RolloutRefusedError,
  advanceRollout,
  composeRollout,
  getRollout,
  launchRollout,
  listTargets,
  listWaves,
  previewRollout,
  safetyNetLevelOf,
} from '../rollout.service';
import { enqueueChangeJob, ChangeRefusedError } from '../apply.service';
import { baseDoc, CHR_ADDRESS } from './fixtures';

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
  ok(
    label,
    JSON.stringify(a) === JSON.stringify(b),
    `got ${JSON.stringify(a)} want ${JSON.stringify(b)}`,
  );
}
function section(t: string): void {
  console.log(`\n=== ${t} ===`);
}
async function throws(
  label: string,
  fn: () => Promise<unknown>,
  test: (err: unknown) => boolean,
  describe: (err: unknown) => string = (e) => String(e).slice(0, 200),
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
const FLEET_SIZE = 20;

let operatorId = 0;
let chrId = 0;
let siteId = 0;
let revisionId = 0;
let templateId = 0;
const cpeIds: number[] = [];
const ifIdByDevice = new Map<number, { ether1: number; ether2: number }>();

/** A body the RouterOS normaliser can parse, claiming exactly one section. */
const TEMPLATE_BODY = [
  '/ip firewall filter',
  'add action=accept chain=input comment="obliwan:m7-allow-icmp" protocol=icmp',
  '',
].join('\n');

async function reset(): Promise<void> {
  await db.raw(
    'TRUNCATE rollout_targets, rollout_waves, rollouts, change_job_steps, change_jobs, ' +
      'change_plans, device_backups, apply_outcomes, command_audit RESTART IDENTITY CASCADE',
  );
  await db('config_renders').del();
  await db('config_snapshots').del();
  await db('snmp_if_samples').del();
  await db('snmp_device_samples').del();
  await db('snmp_device_rollup_1h').del();
  await db('snmp_interfaces').del();
  await db('ppp_sessions').del();
  await db('template_revisions').del();
  await db('templates').del();
  await db('device_transports').del();
  await db('devices').del();
  await db('sites').del();
  await db('kill_switch').where('scope', 'tenant').del();
  await db('kill_switch').where('scope', 'global').update({
    engaged: false, reason: null, engaged_at: null, engaged_by: null,
  });
  cpeIds.length = 0;
  ifIdByDevice.clear();
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

async function ensurePartitions(): Promise<void> {
  for (const parent of ['snmp_if_samples', 'snmp_device_samples']) {
    await db.raw("SELECT ensure_series_partitions(?::regclass, 'day', 10, 2)", [parent]);
  }
  await db.raw("SELECT ensure_series_partitions('snmp_device_rollup_1h'::regclass, 'month', 2, 1)");
}

async function seedUser(username: string): Promise<number> {
  const existing = (await db('users').where({ username }).first('id')) as { id: number } | undefined;
  if (existing) return Number(existing.id);
  const [row] = (await db('users')
    .insert({ username, display_name: username, role: 'user' })
    .returning('id')) as Array<{ id: number }>;
  return Number(row.id);
}

/**
 * 20 MikroTik CPE behind one concentrator, all `active` and `is_managed`, each
 * with a snapshot, an SNMP profile and seven days of RTT history.
 *
 * All twenty are MikroTik on purpose: `resolveSafetyNet` returns `armed` for
 * every one of them, so the acceptance rollout below measures the WAVE
 * machinery on a uniform fleet. §8.3's ordering is proved separately, on a
 * mixed set, by the pure function and by the database trigger — both of which
 * are the things that would actually break.
 */
async function seedWorld(): Promise<void> {
  await reset();
  await ensurePartitions();
  operatorId = await seedUser('m7-operator');

  const [site] = (await db('sites')
    .insert({ tenant_id: TENANT, code: 'M7', name: 'M7 site', timezone: 'Europe/Paris' })
    .returning('id')) as Array<{ id: number }>;
  siteId = Number(site.id);

  const [chr] = (await db('devices')
    .insert({
      tenant_id: TENANT, name: 'chr-m7', brand: 'mikrotik', family: 'mikrotik_routeros7',
      role: 'concentrator', status: 'active', is_managed: true, tunnel_ip: CHR_ADDRESS,
      ppp_username: 'chr-m7', system_identity: 'chr-m7', serial: 'CHRM70000000',
    })
    .returning('id')) as Array<{ id: number }>;
  chrId = Number(chr.id);

  const now = Date.now();
  for (let i = 0; i < FLEET_SIZE; i++) {
    const name = `cpe-m7-${String(i).padStart(2, '0')}`;
    const [row] = (await db('devices')
      .insert({
        tenant_id: TENANT, site_id: siteId, name, brand: 'mikrotik',
        family: 'mikrotik_routeros7', role: 'cpe', status: 'active', is_managed: true,
        tunnel_ip: `10.255.1.${10 + i}`, concentrator_id: chrId,
        ppp_username: name, system_identity: name,
        serial: `HXX0M7${String(i).padStart(4, '0')}`,
        os_version: '7.14.3', model: 'RB5009',
      })
      .returning('id')) as Array<{ id: number }>;
    const id = Number(row.id);
    cpeIds.push(id);

    await storeDoc(id, baseDoc(id, name, `HXX0M7${String(i).padStart(4, '0')}`));

    // ── D4: an OPEN PPP session, so the baseline can record `pppUp: true` ──
    await db('ppp_sessions').insert({
      concentrator_id: chrId,
      device_id: id,
      ppp_username: name,
      tunnel_ip: `10.255.1.${10 + i}`,
      started_at: new Date(now - 86_400_000),
    });

    // ── Two interfaces. `ether2` on the FIRST device is deliberately dirty
    //    before anybody touches anything: trap 1's second half.
    const [e1] = (await db('snmp_interfaces')
      .insert({
        device_id: id, if_name: 'ether1', if_index: 1, oper_status: 1, admin_status: 1,
        state: 'active', monitored: true, speed_bps: 1_000_000_000, effective_poll_sec: 30,
      })
      .returning('id')) as Array<{ id: number }>;
    const [e2] = (await db('snmp_interfaces')
      .insert({
        device_id: id, if_name: 'ether2', if_index: 2, oper_status: 1, admin_status: 1,
        state: 'active', monitored: true, speed_bps: 1_000_000_000, effective_poll_sec: 30,
      })
      .returning('id')) as Array<{ id: number }>;
    ifIdByDevice.set(id, { ether1: Number(e1.id), ether2: Number(e2.id) });

    // 7 days of hourly RTT history (only 24 buckets: the gate needs 12).
    const rows = [];
    for (let h = 24; h >= 1; h--) {
      rows.push({
        bucket: new Date(now - h * 3600_000),
        device_id: id,
        mem_used_avg_bytes: 1, mem_used_max_bytes: 1, mem_total_bytes: 2,
        uptime_ticks_max: 100_000,
        rtt_avg_us: 20_000, rtt_max_us: 24_000, rtt_p95_us: 22_000,
        cpu_avg_pct: 5, cpu_max_pct: 9, temp_avg_dc: 400, temp_max_dc: 420,
        reachable_count: 120, sample_count: 120, expected_count: 120,
      });
    }
    await db('snmp_device_rollup_1h').insert(rows);

    // One pre-baseline device sample: this is what `uptimeTicks` reads.
    await db('snmp_device_samples').insert({
      ts: new Date(now - 60_000),
      device_id: id,
      uptime_ticks: 100_000,
      mem_used_bytes: 1, mem_total_bytes: 2,
      rtt_us: 21_000, cpu_pct: 5, temp_dc: 400, reachable: true,
    });
  }

  // The one already-dirty interface (trap 1): `ether2` of the first CPE has
  // been dropping frames since long before this rollout existed.
  const dirty = ifIdByDevice.get(cpeIds[0])!;
  await db('snmp_if_samples').insert({
    ts: new Date(now - 600_000),
    if_id: dirty.ether2,
    in_bps: 1000, out_bps: 1000, in_pps: 1, out_pps: 1,
    in_errs: 17, out_errs: 0, in_discards: 0, out_discards: 0,
    elapsed_ms: 30_000, oper_status: 1,
  });

  const [tpl] = (await db('templates')
    .insert({
      tenant_id: TENANT, name: 'm7-baseline-firewall', brand: 'mikrotik', status: 'active',
    })
    .returning('id')) as Array<{ id: number }>;
  templateId = Number(tpl.id);

  const [rev] = (await db('template_revisions')
    .insert({
      template_id: templateId,
      tenant_id: TENANT,
      revision: 1,
      body: TEMPLATE_BODY,
      body_sha256: 'b'.repeat(64),
      status: 'published',
      published_at: new Date(),
      published_by: operatorId,
      deps_pinned: true,
      deps_count: 0,
    })
    .returning('id')) as Array<{ id: number }>;
  revisionId = Number(rev.id);
}

// ============================================================================
// Job execution, simulated exactly as the queue would have written it
// ============================================================================

/**
 * Drive a change job to a terminal state without touching an equipment.
 *
 * Every column the queue would have set is set here, including the R1
 * pre-change backup — `change_jobs_preflight_backup_chk` makes `succeeded`
 * unrepresentable without one, so this helper cannot cheat past the schema.
 */
async function finishJob(jobId: number, status: 'succeeded' | 'failed' | 'rolled_back'): Promise<void> {
  const job = (await db('change_jobs').where({ id: jobId }).first('*')) as {
    id: number; tenant_id: number; device_id: number; kind: string;
  };
  const [backup] = (await db('device_backups')
    .insert({
      tenant_id: job.tenant_id,
      device_id: job.device_id,
      kind: 'binary',
      trigger_kind: 'preflight',
      storage_path: `m7/${jobId}.backup`,
      size_bytes: 2048,
      sha256: 'c'.repeat(64),
      taken_before_job_id: jobId,
    })
    .returning('id')) as Array<{ id: string | number }>;

  await db('change_jobs').where({ id: jobId }).update({
    claimed_by: 'm7-verify:0:0000',
    claimed_at: new Date(),
    started_at: new Date(),
    preflight_backup_id: Number(backup.id),
    deadman_armed_at: new Date(),
    deadman_disarmed_at: status === 'succeeded' ? new Date() : null,
    status,
    outcome: status === 'failed' ? null : status === 'succeeded' ? 'succeeded' : 'rolled_back',
    finished_at: new Date(),
    updated_at: db.fn.now(),
  });
}

async function jobIdsOfWave(rolloutId: number, waveIndex: number): Promise<number[]> {
  const targets = await listTargets(rolloutId, waveIndex);
  return targets.map((t) => Number(t.job_id)).filter((n) => Number.isFinite(n));
}

// ============================================================================
// 1. The wave plan and the order — pure, no database
// ============================================================================

function testPureWavePlan(): void {
  section('1. planWaves — 1 → 5% → 25% → the rest (cumulative coverage)');

  eq('a fleet of 0 has no wave', planWaves(0), []);
  eq(
    'a fleet of 1 is one canary wave',
    planWaves(1).map((w) => [w.label, w.size]),
    [['canary', 1]],
  );
  eq(
    'a fleet of 20 → 1, 4, 15 (the 5% checkpoint is already covered by the canary)',
    planWaves(20).map((w) => [w.label, w.size]),
    [['canary', 1], ['25%', 4], ['rest', 15]],
  );
  eq(
    'a fleet of 300 → 1, 14, 60, 225',
    planWaves(300).map((w) => [w.label, w.size]),
    [['canary', 1], ['5%', 14], ['25%', 60], ['rest', 225]],
  );
  ok(
    'every wave has at least one device — a gate on nobody passes for free',
    planWaves(3).every((w) => w.size > 0) && planWaves(7).every((w) => w.size > 0),
  );
  for (const n of [1, 2, 3, 5, 20, 37, 300]) {
    const total = planWaves(n).reduce((a, w) => a + w.size, 0);
    ok(`every device lands in exactly one wave (n=${n})`, total === n, `${total}`);
  }

  section('2. §8.3 — the weakest safety net goes LAST');
  const mixed = [
    { deviceId: 5, safetyNet: 'DEGRADED' as const },
    { deviceId: 2, safetyNet: 'ARMED' as const },
    { deviceId: 9, safetyNet: 'ARMED_BY_PEER' as const },
    { deviceId: 1, safetyNet: 'ARMED' as const },
    { deviceId: 7, safetyNet: 'DEGRADED' as const },
  ];
  eq(
    'ordered armed → armed_by_peer → degraded, stable by device id inside a level',
    orderForWaves(mixed).map((d) => d.deviceId),
    [1, 2, 9, 5, 7],
  );
  eq('safetyNetLevelOf bridges the two vocabularies', [
    safetyNetLevelOf('armed'), safetyNetLevelOf('armed_by_peer'), safetyNetLevelOf('degraded'),
  ], ['ARMED', 'ARMED_BY_PEER', 'DEGRADED']);
  ok(
    'the canary of a mixed fleet is never a DEGRADED device',
    orderForWaves(mixed)[0].safetyNet === 'ARMED',
  );
}

// ============================================================================
// 3. §8.5 — the subtree interlock, as a pure function
// ============================================================================

function testPureInterlock(): void {
  section('3. §8.5 — findSubtreeConflicts');

  const chr = { deviceId: 1, deviceName: 'chr-paris', role: 'concentrator', concentratorId: null };
  const childA = { deviceId: 2, deviceName: 'cpe-a', role: 'cpe', concentratorId: 1 };
  const childB = { deviceId: 3, deviceName: 'cpe-b', role: 'cpe', concentratorId: 1 };
  const stranger = { deviceId: 4, deviceName: 'cpe-c', role: 'cpe', concentratorId: 99 };

  eq('children alone are fine', findSubtreeConflicts([childA, childB, stranger]), []);
  eq('a concentrator alone is fine', findSubtreeConflicts([chr]), []);
  eq(
    'a concentrator with a child of another concentrator is fine',
    findSubtreeConflicts([chr, stranger]),
    [],
  );
  const conflict = findSubtreeConflicts([childA, chr, childB]);
  eq('the conflict names the concentrator AND every child', conflict, [
    { concentratorId: 1, concentratorName: 'chr-paris', childDeviceIds: [2, 3] },
  ]);
  ok(
    'the order of the inputs does not change the answer',
    JSON.stringify(findSubtreeConflicts([chr, childA, childB])) === JSON.stringify(conflict),
  );
}

// ============================================================================
// 4. The health gate — trap 1, judged purely
// ============================================================================

function baselineOf(over: Partial<HealthBaseline> = {}): HealthBaseline {
  return {
    deviceId: 1,
    capturedAt: new Date().toISOString(),
    pppUp: true,
    uptimeTicks: 100_000,
    rttBaselineUs: 20_000,
    rttBaselineSamples: 24,
    interfaces: [
      {
        ifId: 11, ifName: 'ether1', operStatus: 1, inErrors: 0, outErrors: 0,
        alreadyDown: false, alreadyErroring: false,
      },
      {
        ifId: 12, ifName: 'ether2', operStatus: 1, inErrors: 17, outErrors: 0,
        alreadyDown: false, alreadyErroring: true,
      },
      {
        ifId: 13, ifName: 'ether3', operStatus: 2, inErrors: 0, outErrors: 0,
        alreadyDown: true, alreadyErroring: false,
      },
    ],
    ...over,
  };
}

function postOf(over: Partial<PostWaveSignals> = {}): PostWaveSignals {
  return {
    deviceId: 1,
    pppUp: true,
    uptimeTicks: 130_000,
    rttUs: 21_000,
    deviceSamples: 4,
    interfaces: new Map([
      [11, { operStatus: 1, newInErrors: 0, newOutErrors: 0 }],
      [12, { operStatus: 1, newInErrors: 0, newOutErrors: 0 }],
      [13, { operStatus: 2, newInErrors: 0, newOutErrors: 0 }],
    ]),
    jobStatus: 'succeeded',
    ...over,
  };
}

function codes(r: { reasons: { code: string }[] }): string[] {
  return r.reasons.map((x) => x.code).sort();
}

function testHealthGate(): void {
  section('4. The health gate — trap 1: the baseline is the comparison point');

  eq('a healthy device passes', judgeDevice('d', baselineOf(), postOf()).verdict, 'PASS');

  // ── The two halves of trap 1 ────────────────────────────────────────────
  const stillDown = judgeDevice('d', baselineOf(), postOf());
  ok(
    'an interface ALREADY down before the wave does not fail it',
    stillDown.verdict === 'PASS' && !codes(stillDown).includes('IF_OPER_DOWN'),
    codes(stillDown).join(','),
  );
  const stillErroring = judgeDevice(
    'd',
    baselineOf(),
    postOf({
      interfaces: new Map([
        [11, { operStatus: 1, newInErrors: 0, newOutErrors: 0 }],
        // ether2 keeps dropping frames, exactly as it did before the change.
        [12, { operStatus: 1, newInErrors: 41, newOutErrors: 0 }],
        [13, { operStatus: 2, newInErrors: 0, newOutErrors: 0 }],
      ]),
    }),
  );
  ok(
    'an interface ALREADY erroring before the wave does not fail it',
    stillErroring.verdict === 'PASS' && !codes(stillErroring).includes('NEW_IF_IN_ERRORS'),
    codes(stillErroring).join(','),
  );

  // ── The five signals, one at a time ─────────────────────────────────────
  const pppDown = judgeDevice('d', baselineOf(), postOf({ pppUp: false }));
  eq('PPP up → down fails', [pppDown.verdict, codes(pppDown)], ['FAIL', ['PPP_SESSION_DOWN']]);
  ok(
    'PPP already down before the wave does NOT fail',
    judgeDevice('d', baselineOf({ pppUp: false }), postOf({ pppUp: false })).verdict === 'PASS',
  );

  const ifDown = judgeDevice(
    'd',
    baselineOf(),
    postOf({
      interfaces: new Map([
        [11, { operStatus: 2, newInErrors: 0, newOutErrors: 0 }],
        [12, { operStatus: 1, newInErrors: 0, newOutErrors: 0 }],
        [13, { operStatus: 2, newInErrors: 0, newOutErrors: 0 }],
      ]),
    }),
  );
  eq('an interface that WAS up going down fails', [ifDown.verdict, codes(ifDown)], ['FAIL', ['IF_OPER_DOWN']]);

  const newErrs = judgeDevice(
    'd',
    baselineOf(),
    postOf({
      interfaces: new Map([
        [11, { operStatus: 1, newInErrors: 412, newOutErrors: 0 }],
        [12, { operStatus: 1, newInErrors: 0, newOutErrors: 0 }],
        [13, { operStatus: 2, newInErrors: 0, newOutErrors: 0 }],
      ]),
    }),
  );
  eq('NEW input errors on a clean interface fail', [newErrs.verdict, codes(newErrs)], ['FAIL', ['NEW_IF_IN_ERRORS']]);

  const rtt = judgeDevice('d', baselineOf(), postOf({ rttUs: 90_000 }));
  eq('RTT past ×2 of the 7-day baseline fails', [rtt.verdict, codes(rtt)], ['FAIL', ['RTT_REGRESSION']]);
  ok(
    'RTT within tolerance passes',
    judgeDevice('d', baselineOf(), postOf({ rttUs: 39_000 })).verdict === 'PASS',
  );
  ok(
    'a LAN-speed RTT never trips the factor (the 5 ms floor)',
    judgeDevice(
      'd',
      baselineOf({ rttBaselineUs: 200 }),
      postOf({ rttUs: 900 }),
    ).verdict === 'PASS',
  );

  const boot = judgeDevice('d', baselineOf(), postOf({ uptimeTicks: 400 }));
  eq('sysUpTime going backwards fails', [boot.verdict, codes(boot)], ['FAIL', ['UNEXPECTED_BOOT']]);

  const badJob = judgeDevice('d', baselineOf(), postOf({ jobStatus: 'rolled_back' }));
  eq('a job that did not succeed fails the device', [badJob.verdict, codes(badJob)], ['FAIL', ['JOB_NOT_SUCCEEDED']]);

  // ── INDETERMINATE is not PASS, and it is not FAIL either ────────────────
  const noBaseline = judgeDevice('d', null, postOf());
  eq('no baseline → INDETERMINATE', [noBaseline.verdict, codes(noBaseline)], ['INDETERMINATE', ['NO_BASELINE']]);
  const silent = judgeDevice('d', baselineOf(), postOf({ deviceSamples: 0 }));
  ok('silence is INDETERMINATE, never PASS', silent.verdict === 'INDETERMINATE', codes(silent).join(','));
  const thinRtt = judgeDevice('d', baselineOf({ rttBaselineSamples: 3 }), postOf());
  ok(
    'a 3-bucket RTT history is not a 7-day baseline → INDETERMINATE',
    thinRtt.verdict === 'INDETERMINATE',
    codes(thinRtt).join(','),
  );
  const noSnmp = judgeDevice('d', baselineOf({ interfaces: [] }), postOf({ interfaces: new Map() }));
  ok('no SNMP coverage → INDETERMINATE', noSnmp.verdict === 'INDETERMINATE', codes(noSnmp).join(','));
  const noPpp = judgeDevice('d', baselineOf({ pppUp: null }), postOf({ pppUp: null }));
  ok('no concentrator → INDETERMINATE on the PPP signal', noPpp.verdict === 'INDETERMINATE');

  eq('severity, never majority: one FAIL beats any number of INDETERMINATEs',
    healthGateVerdictFrom(['NO_BASELINE', 'NO_TELEMETRY', 'PPP_SESSION_DOWN', 'NO_SNMP_COVERAGE']),
    'FAIL');

  section('4b. The wave-level fold');
  const pass = judgeDevice('a', baselineOf(), postOf());
  const fail = judgeDevice('b', baselineOf(), postOf({ pppUp: false }));
  const ind = judgeDevice('c', baselineOf(), postOf({ deviceSamples: 0 }));
  eq('one FAIL fails the wave', foldWave(0, [pass, pass, fail, ind]).verdict, 'FAIL');
  eq('one INDETERMINATE with no FAIL pauses the wave', foldWave(0, [pass, ind]).verdict, 'INDETERMINATE');
  eq('all PASS passes', foldWave(0, [pass, pass]).verdict, 'PASS');
  eq('an EMPTY wave is INDETERMINATE, not PASS', foldWave(0, []).verdict, 'INDETERMINATE');
}

// ============================================================================
// 5. Migration 010 — the constraints, against a real PostgreSQL
// ============================================================================

async function testSchema(): Promise<void> {
  section('5. Migration 010 — what the database refuses to represent');

  const [r] = (await db('rollouts')
    .insert({
      tenant_id: TENANT, name: 'schema probe', template_revision_id: revisionId,
      status: 'draft', wave_count: 2, device_count: 2, site_count: 1,
    })
    .returning('id')) as Array<{ id: string | number }>;
  const rid = Number(r.id);
  const [w0] = (await db('rollout_waves')
    .insert({ rollout_id: rid, wave_index: 0, label: 'canary', target_count: 1 })
    .returning('id')) as Array<{ id: string | number }>;
  const [w1] = (await db('rollout_waves')
    .insert({ rollout_id: rid, wave_index: 1, label: 'rest', target_count: 1 })
    .returning('id')) as Array<{ id: string | number }>;

  const tenantOfWave = (await db('rollout_waves').where({ id: Number(w0.id) }).first('tenant_id')) as
    | { tenant_id: number } | undefined;
  eq('the tenant is synced onto a wave from its parent', Number(tenantOfWave?.tenant_id), TENANT);

  await throws(
    'a wave with no device cannot exist (a gate on nobody passes for free)',
    () => db('rollout_waves').insert({ rollout_id: rid, wave_index: 2, label: 'rest', target_count: 0 }),
    (e) => String(e).includes('rollout_waves_size_chk'),
  );

  // ── Trap 1 as a CHECK constraint ────────────────────────────────────────
  await throws(
    'TRAP 1: a target cannot be queued without a baseline',
    () =>
      db('rollout_targets').insert({
        rollout_id: rid, wave_id: Number(w0.id), device_id: cpeIds[0], wave_index: 0,
        safety_level: 'armed', job_id: 1, queued_at: new Date(),
      }),
    (e) => String(e).includes('rollout_targets_baseline_before_chk'),
  );
  await throws(
    'TRAP 1: a baseline captured AFTER the job was queued is refused',
    () =>
      db('rollout_targets').insert({
        rollout_id: rid, wave_id: Number(w0.id), device_id: cpeIds[0], wave_index: 0,
        safety_level: 'armed', job_id: 1,
        queued_at: new Date(Date.now() - 60_000),
        health_baseline: JSON.stringify({ deviceId: cpeIds[0] }),
        health_baseline_at: new Date(),
      }),
    (e) => String(e).includes('rollout_targets_baseline_before_chk'),
  );

  // ── Trap 2 as a trigger ─────────────────────────────────────────────────
  await db('rollout_targets').insert({
    rollout_id: rid, wave_id: Number(w1.id), device_id: cpeIds[1], wave_index: 1,
    safety_level: 'degraded',
  });
  ok('a DEGRADED device in the LAST wave is accepted', true);
  await throws(
    'TRAP 2: an ARMED device cannot be scheduled AFTER a DEGRADED one',
    () =>
      db('rollout_targets').insert({
        rollout_id: rid, wave_id: Number(w0.id), device_id: cpeIds[2], wave_index: 0,
        safety_level: 'armed',
      }).then(() =>
        db('rollout_targets').insert({
          rollout_id: rid, wave_id: Number(w1.id), device_id: cpeIds[3], wave_index: 1,
          safety_level: 'armed',
        })).then(() =>
        // now try to put a DEGRADED device in the EARLIER wave
        db('rollout_targets').insert({
          rollout_id: rid, wave_id: Number(w0.id), device_id: cpeIds[4], wave_index: 0,
          safety_level: 'degraded',
        })),
    (e) => String(e).includes('wave order'),
  );

  // ── One active rollout per device ───────────────────────────────────────
  await throws(
    'a device cannot be in two active rollouts at once',
    async () => {
      const [r2] = (await db('rollouts')
        .insert({
          tenant_id: TENANT, name: 'second', template_revision_id: revisionId,
          status: 'draft', wave_count: 1, device_count: 1, site_count: 1,
        })
        .returning('id')) as Array<{ id: string | number }>;
      const [w] = (await db('rollout_waves')
        .insert({ rollout_id: Number(r2.id), wave_index: 0, label: 'canary', target_count: 1 })
        .returning('id')) as Array<{ id: string | number }>;
      return db('rollout_targets').insert({
        rollout_id: Number(r2.id), wave_id: Number(w.id), device_id: cpeIds[2], wave_index: 0,
        safety_level: 'armed',
      });
    },
    (e) => String(e).includes('rollout_targets_one_active_uq'),
  );

  // ── §8.5, at composition, in the DATABASE ───────────────────────────────
  await throws(
    '§8.5: a concentrator cannot join a rollout that already holds one of its children',
    () =>
      db('rollout_targets').insert({
        rollout_id: rid, wave_id: Number(w1.id), device_id: chrId, wave_index: 1,
        safety_level: 'armed',
      }),
    (e) => String(e).includes('subtree interlock'),
  );

  await db('rollouts').where({ id: rid }).update({ status: 'aborted', finished_at: new Date() });
  await db('rollout_targets').where({ rollout_id: rid }).update({ status: 'cancelled' });
  await db.raw('TRUNCATE rollout_targets, rollout_waves, rollouts RESTART IDENTITY CASCADE');
}

// ============================================================================
// 6. §8.5 on the QUEUE — a concentrator job and a child job never coexist
// ============================================================================

async function testQueueInterlock(): Promise<void> {
  section('6. §8.5 — the interlock on `change_jobs`, fleet-wide');

  const child = cpeIds[0];
  const [parentJob] = (await db('change_jobs')
    .insert({
      tenant_id: TENANT, device_id: chrId, kind: 'backup', status: 'queued',
      base_state_hash: '0'.repeat(64), safety_level: 'armed',
    })
    .returning('id')) as Array<{ id: string | number }>;
  ok('a job on the concentrator is accepted while its children are idle', true);

  await throws(
    'a child job is REFUSED while a job is in flight on its concentrator',
    () =>
      db('change_jobs').insert({
        tenant_id: TENANT, device_id: child, kind: 'backup', status: 'queued',
        base_state_hash: '0'.repeat(64), safety_level: 'armed',
      }),
    (e) => String(e).includes('subtree interlock'),
  );

  await db('change_jobs').where({ id: Number(parentJob.id) }).update({
    status: 'aborted', finished_at: new Date(),
  });

  const [childJob] = (await db('change_jobs')
    .insert({
      tenant_id: TENANT, device_id: child, kind: 'backup', status: 'queued',
      base_state_hash: '0'.repeat(64), safety_level: 'armed',
    })
    .returning('id')) as Array<{ id: string | number }>;
  await throws(
    'and the reverse: a concentrator job is REFUSED while a child job is in flight',
    () =>
      db('change_jobs').insert({
        tenant_id: TENANT, device_id: chrId, kind: 'backup', status: 'queued',
        base_state_hash: '0'.repeat(64), safety_level: 'armed',
      }),
    (e) => String(e).includes('subtree interlock'),
  );
  await db('change_jobs').where({ id: Number(childJob.id) }).update({
    status: 'aborted', finished_at: new Date(),
  });

  const [sibling] = (await db('change_jobs')
    .insert({
      tenant_id: TENANT, device_id: cpeIds[1], kind: 'backup', status: 'queued',
      base_state_hash: '0'.repeat(64), safety_level: 'armed',
    })
    .returning('id')) as Array<{ id: string | number }>;
  const [sibling2] = (await db('change_jobs')
    .insert({
      tenant_id: TENANT, device_id: cpeIds[2], kind: 'backup', status: 'queued',
      base_state_hash: '0'.repeat(64), safety_level: 'armed',
    })
    .returning('id')) as Array<{ id: string | number }>;
  ok('two SIBLING jobs are fine — the interlock is about the parent, not the fleet', true);
  await db('change_jobs')
    .whereIn('id', [Number(sibling.id), Number(sibling2.id)])
    .update({ status: 'aborted', finished_at: new Date() });
  await db.raw('TRUNCATE change_job_steps, change_jobs, device_backups RESTART IDENTITY CASCADE');
}

// ============================================================================
// 7. Composition — the impact screen, and §8.5's refusal
// ============================================================================

let rolloutId = 0;

async function testComposition(): Promise<void> {
  section('7. Composition — N plans compiled BEFORE the launch');

  const preview = await previewRollout({
    tenantId: TENANT,
    name: 'preview',
    deviceIds: cpeIds,
    templateRevisionId: revisionId,
    createdBy: operatorId,
  });
  eq('the preview compiled a plan for every device', preview.targets.length, FLEET_SIZE);
  eq('and produced no failure', preview.failures.map((f) => f.message), []);
  eq(
    'the waves are 1 / 4 / 15 for a fleet of 20',
    preview.waves.map((w) => [w.label, w.size]),
    [['canary', 1], ['25%', 4], ['rest', 15]],
  );
  eq('the blast radius counts SITES first', preview.blastRadius.siteCount, 1);
  ok('the preview wrote no rollout', preview.rolloutId === null);
  eq(
    'the preview persisted no render row',
    Number(((await db('config_renders').count<{ c: string }>({ c: '*' }).first()) as { c: string }).c),
    0,
  );
  ok(
    'every device was given a §8.3 safety level before the launch',
    preview.targets.every((t) => t.safetyLevel === 'armed'),
  );
  ok(
    'and a Management-Path Guard verdict before the launch',
    preview.targets.every((t) => ['ACCEPT', 'REJECT', 'INDETERMINATE'].includes(t.guardVerdict)),
    preview.targets[0]?.guardVerdict,
  );
  console.log(`        impact line: ${preview.summaryLine}`);

  // ── §8.5, from the service, with a readable sentence ────────────────────
  await throws(
    '§8.5: composing a concentrator together with one of its children is REFUSED',
    () =>
      previewRollout({
        tenantId: TENANT,
        name: 'illegal',
        deviceIds: [chrId, cpeIds[0], cpeIds[1]],
        templateRevisionId: revisionId,
        createdBy: operatorId,
      }),
    (e) => e instanceof RolloutRefusedError && e.kind === 'subtree_interlock',
    (e) => String((e as Error).message).slice(0, 160),
  );

  // ── The signatures §8.3 demands ─────────────────────────────────────────
  const needsOverride = preview.requiresOverride;
  if (needsOverride) {
    await throws(
      'a set the guard did not clear cannot be composed without a signed override',
      () =>
        composeRollout({
          tenantId: TENANT, name: 'unsigned', deviceIds: cpeIds,
          templateRevisionId: revisionId, createdBy: operatorId,
        }),
      (e) => e instanceof RolloutRefusedError && e.kind === 'guard_refused',
    );
  } else {
    ok('the guard cleared every device, so no override is demanded', true);
  }

  const composition = await composeRollout({
    tenantId: TENANT,
    name: 'M7 acceptance',
    deviceIds: cpeIds,
    templateRevisionId: revisionId,
    createdBy: operatorId,
    gateSettleMs: 0,
    override: needsOverride
      ? {
          reason: 'M7 acceptance run: guard verdicts reviewed device by device on the impact screen.',
          userId: operatorId,
        }
      : null,
    confirmDegraded: preview.requiresDegradedConfirmation ? { userId: operatorId } : null,
  });
  rolloutId = composition.rolloutId as number;
  ok('the rollout was composed', rolloutId > 0, `#${rolloutId}`);

  const waves = await listWaves(rolloutId);
  eq('three waves were persisted', waves.map((w) => Number(w.target_count)), [1, 4, 15]);
  const targets = await listTargets(rolloutId);
  eq('twenty targets, all pending', [targets.length, new Set(targets.map((t) => t.status)).size], [20, 1]);
  eq(
    'the wave order is the §8.3 order (armed first, then by device id)',
    targets.map((t) => Number(t.device_id)),
    [...cpeIds].sort((a, b) => a - b),
  );
  eq(
    'no job exists yet — a composed rollout writes nothing',
    Number(((await db('change_jobs').count<{ c: string }>({ c: '*' }).first()) as { c: string }).c),
    0,
  );

  await throws(
    'a second rollout cannot hold the same devices',
    () =>
      composeRollout({
        tenantId: TENANT, name: 'clash', deviceIds: [cpeIds[0]],
        templateRevisionId: revisionId, createdBy: operatorId,
        override: needsOverride
          ? { reason: 'clash probe, should never be reached', userId: operatorId }
          : null,
      }),
    (e) => String(e).includes('rollout_targets_one_active_uq'),
  );
}

// ============================================================================
// 8. THE ACCEPTANCE RUN — 20 devices, 2 saboteurs, stop at wave 2
// ============================================================================

async function testAcceptance(): Promise<void> {
  section('8. Acceptance — 20 devices, 2 saboteurs in wave 2');

  await launchRollout(TENANT, rolloutId, operatorId);
  let rollout = (await getRollout(TENANT, rolloutId))!;
  eq('the rollout is running on wave 1', [rollout.status, rollout.current_wave_index], ['running', 0]);

  // ── Wave 1: the canary ─────────────────────────────────────────────────
  const wave0Targets = await listTargets(rolloutId, 0);
  eq('wave 1 queued exactly one job', wave0Targets.filter((t) => t.job_id !== null).length, 1);
  ok(
    'TRAP 1: the baseline was captured BEFORE the job was queued',
    wave0Targets.every(
      (t) =>
        t.health_baseline_at !== null &&
        t.queued_at !== null &&
        new Date(t.health_baseline_at).getTime() <= new Date(t.queued_at).getTime(),
    ),
  );
  const canaryJob = (await db('change_jobs').where({ id: wave0Targets[0].job_id }).first('*')) as {
    rollout_id: string | number; wave_index: number; canary_rank: number; kind: string;
    guard_verdict: string; override_reason: string | null;
  };
  eq('the job carries its rollout, wave and canary rank (migration 009 columns)', [
    Number(canaryJob.rollout_id), Number(canaryJob.wave_index), Number(canaryJob.canary_rank),
    canaryJob.kind,
  ], [rolloutId, 0, 0, 'push']);

  let report = await advanceRollout(TENANT, rolloutId);
  eq('nothing advances while the wave job is in flight', report.action, 'waiting_jobs');

  await finishJob(Number(wave0Targets[0].job_id), 'succeeded');
  // A fresh post-baseline sample, as the poller would have written it.
  await pollAll([Number(wave0Targets[0].device_id)], { healthy: true });

  report = await advanceRollout(TENANT, rolloutId);
  eq('the canary passed its gate and wave 2 started', [report.action, report.gate?.verdict], [
    'wave_started', 'PASS',
  ]);

  // ── Wave 2: four devices, two of which are saboteurs ────────────────────
  const wave1Targets = await listTargets(rolloutId, 1);
  eq('wave 2 queued four jobs', wave1Targets.filter((t) => t.job_id !== null).length, 4);
  ok(
    'TRAP 1: wave 2 got its OWN baseline, captured after wave 1 landed and before wave 2 was queued',
    wave1Targets.every(
      (t) =>
        t.health_baseline_at !== null &&
        new Date(t.health_baseline_at).getTime() >
          new Date(wave0Targets[0].health_baseline_at as Date).getTime() &&
        new Date(t.health_baseline_at).getTime() <= new Date(t.queued_at as Date).getTime(),
    ),
  );

  const saboteurs = wave1Targets.slice(0, 2).map((t) => Number(t.device_id));
  const innocents = wave1Targets.slice(2).map((t) => Number(t.device_id));
  console.log(`        saboteurs: ${saboteurs.join(', ')}; innocent: ${innocents.join(', ')}`);

  for (const t of wave1Targets) await finishJob(Number(t.job_id), 'succeeded');
  await pollAll(innocents, { healthy: true });
  await pollAll(saboteurs, { healthy: false });

  report = await advanceRollout(TENANT, rolloutId);
  eq('wave 2 FAILED its health gate', [report.action, report.gate?.verdict], ['gate_failed', 'FAIL']);
  eq('and it named exactly the two saboteurs', report.gate?.failedDeviceIds.sort(), saboteurs.sort());

  const sabTarget = (await listTargets(rolloutId, 1)).find(
    (t) => Number(t.device_id) === saboteurs[0],
  )!;
  const sabCodes = (sabTarget.health_reasons as { code: string }[]).map((r) => r.code).sort();
  console.log(`        saboteur reasons: ${sabCodes.join(', ')}`);
  ok(
    'the saboteur failed on the PPP session, the interface, NEW errors and the reboot',
    ['PPP_SESSION_DOWN', 'IF_OPER_DOWN', 'NEW_IF_IN_ERRORS', 'UNEXPECTED_BOOT'].every((c) =>
      sabCodes.includes(c),
    ),
    sabCodes.join(','),
  );
  const dirtyDevice = cpeIds[0];
  const dirtyTarget = (await listTargets(rolloutId)).find(
    (t) => Number(t.device_id) === dirtyDevice,
  )!;
  if (dirtyTarget.health_verdict !== null) {
    ok(
      'TRAP 1 end to end: the device whose ether2 was ALREADY erroring still PASSED',
      dirtyTarget.health_verdict === 'PASS',
      String(dirtyTarget.health_verdict),
    );
  }

  // ── The consequences ───────────────────────────────────────────────────
  rollout = (await getRollout(TENANT, rolloutId))!;
  eq('the rollout is rolling back', rollout.status, 'rolling_back');
  eq('and it recorded which wave failed', Number(rollout.failed_wave_index), 1);

  const revision = (await db('template_revisions').where({ id: revisionId }).first('status')) as {
    status: string;
  };
  eq('THE FAULTY REVISION IS QUARANTINED', revision.status, 'quarantined');
  ok('and the rollout says when', rollout.revision_quarantined_at !== null);

  const restoreJobs = (await db('change_jobs')
    .where({ rollout_id: rolloutId, kind: 'restore' })
    .select('id', 'device_id', 'override_reason', 'overridden_by')) as Array<{
    id: number; device_id: number; override_reason: string | null; overridden_by: number | null;
  }>;
  eq('five restore jobs were queued — wave 1 (1) plus wave 2 (4)', restoreJobs.length, 5);
  ok(
    'every rollback is signed by the operator who launched the rollout',
    restoreJobs.every((j) => j.overridden_by === operatorId && (j.override_reason ?? '').length > 40),
  );
  const restoredDevices = restoreJobs.map((j) => Number(j.device_id)).sort((a, b) => a - b);
  const changedDevices = [Number(wave0Targets[0].device_id), ...wave1Targets.map((t) => Number(t.device_id))]
    .sort((a, b) => a - b);
  eq('and they cover exactly the devices that took the change', restoredDevices, changedDevices);

  const withBackup = (await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .whereNotNull('rollback_backup_id')
    .count<{ c: string }>({ c: '*' })
    .first()) as { c: string };
  eq('each rollback names the pre-change backup it must load', Number(withBackup.c), 5);

  const skipped = (await db('rollout_targets')
    .where({ rollout_id: rolloutId, status: 'skipped' })
    .count<{ c: string }>({ c: '*' })
    .first()) as { c: string };
  eq('the fifteen devices of wave 3 were never touched', Number(skipped.c), 15);
  eq(
    'no job was ever created for them',
    Number(
      ((await db('change_jobs')
        .where({ rollout_id: rolloutId, wave_index: 2 })
        .count<{ c: string }>({ c: '*' })
        .first()) as { c: string }).c,
    ),
    0,
  );

  // ── Finish the rollback ────────────────────────────────────────────────
  report = await advanceRollout(TENANT, rolloutId);
  eq('the rollout waits for its restore jobs', report.action, 'rollback_pending');
  for (const j of restoreJobs) await finishJob(Number(j.id), 'succeeded');

  report = await advanceRollout(TENANT, rolloutId);
  eq('the rollout ends ROLLED BACK', [report.action, report.status], ['rolled_back', 'rolled_back']);
  rollout = (await getRollout(TENANT, rolloutId))!;
  eq('five devices were restored', Number(rollout.rolled_back_count), 5);
  ok('and the rollout is finished', rollout.finished_at !== null);

  const stillActive = (await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .whereIn('status', ['pending', 'queued', 'running'])
    .count<{ c: string }>({ c: '*' })
    .first()) as { c: string };
  eq('no device is left held by a finished rollout', Number(stillActive.c), 0);
}

/**
 * Write the telemetry the poller would have written after a wave landed.
 *
 * `healthy: false` is the saboteur: its tunnel drops, its `ether1` goes down,
 * it takes new input errors and its `sysUpTime` goes backwards. Four of the
 * five gate signals at once, which is what a change that cuts a site looks like.
 */
async function pollAll(deviceIds: number[], opts: { healthy: boolean }): Promise<void> {
  const now = Date.now();
  for (const id of deviceIds) {
    const ifs = ifIdByDevice.get(id)!;
    if (!opts.healthy) {
      await db('ppp_sessions')
        .where({ device_id: id })
        .whereNull('ended_at')
        .update({ ended_at: new Date(), disconnect_reason: 'peer-disconnect' });
      await db('snmp_interfaces').where({ id: ifs.ether1 }).update({ oper_status: 2 });
    }
    for (let k = 0; k < 3; k++) {
      await db('snmp_device_samples').insert({
        ts: new Date(now + k * 1000),
        device_id: id,
        // The saboteur rebooted: sysUpTime is BELOW the baseline's 100 000.
        uptime_ticks: opts.healthy ? 130_000 + k : 500,
        mem_used_bytes: 1, mem_total_bytes: 2,
        rtt_us: opts.healthy ? 21_000 : 24_000,
        cpu_pct: 5, temp_dc: 400, reachable: true,
      });
      await db('snmp_if_samples').insert({
        ts: new Date(now + k * 1000),
        if_id: ifs.ether1,
        in_bps: 1000, out_bps: 1000, in_pps: 1, out_pps: 1,
        in_errs: opts.healthy ? 0 : 137,
        out_errs: 0, in_discards: 0, out_discards: 0,
        elapsed_ms: 30_000,
        oper_status: opts.healthy ? 1 : 2,
      });
      // The already-dirty ether2 of the first CPE keeps erroring throughout.
      await db('snmp_if_samples').insert({
        ts: new Date(now + k * 1000),
        if_id: ifs.ether2,
        in_bps: 1000, out_bps: 1000, in_pps: 1, out_pps: 1,
        in_errs: id === cpeIds[0] ? 23 : 0,
        out_errs: 0, in_discards: 0, out_discards: 0,
        elapsed_ms: 30_000, oper_status: 1,
      });
    }
  }
}

// ============================================================================
// 9. The refusals a rollout must still honour
// ============================================================================

async function testRefusals(): Promise<void> {
  section('9. Refusals');

  await throws(
    'a finished rollout cannot be launched again',
    () => launchRollout(TENANT, rolloutId, operatorId),
    (e) => e instanceof RolloutRefusedError && e.kind === 'not_draft',
  );
  await throws(
    'a quarantined revision cannot be rolled out',
    () =>
      previewRollout({
        tenantId: TENANT, name: 'after quarantine', deviceIds: [cpeIds[5]],
        templateRevisionId: revisionId, createdBy: operatorId,
      }),
    (e) => e instanceof RolloutRefusedError && e.kind === 'revision_not_published',
  );
  await throws(
    'a rollout with no device is refused',
    () =>
      previewRollout({
        tenantId: TENANT, name: 'empty', deviceIds: [],
        templateRevisionId: revisionId, createdBy: operatorId,
      }),
    (e) => e instanceof RolloutRefusedError && e.kind === 'empty',
  );
  await throws(
    "another tenant's device is not visible",
    () =>
      previewRollout({
        tenantId: TENANT + 999, name: 'other tenant', deviceIds: [cpeIds[0]],
        templateRevisionId: revisionId, createdBy: operatorId,
      }),
    (e) => e instanceof RolloutRefusedError,
  );

  // The rollback job the rollout signs is a REAL job on the real queue: it
  // still obeys `change_jobs_one_in_flight_uq`.
  await db('template_revisions').where({ id: revisionId }).update({ status: 'published' });
  const [held] = (await db('change_jobs')
    .insert({
      tenant_id: TENANT, device_id: cpeIds[7], kind: 'backup', status: 'queued',
      base_state_hash: '0'.repeat(64), safety_level: 'armed',
    })
    .returning('id')) as Array<{ id: string | number }>;
  await throws(
    'a device already holding a job cannot be given a second one',
    () =>
      enqueueChangeJob({
        tenantId: TENANT, deviceId: cpeIds[7], kind: 'backup', requestedBy: operatorId,
      }),
    (e) => String(e).includes('busy') || String(e).includes('in flight') || e instanceof ChangeRefusedError,
  );
  await db('change_jobs').where({ id: Number(held.id) }).update({
    status: 'aborted', finished_at: new Date(),
  });
}

// ============================================================================
// main
// ============================================================================

async function main(): Promise<void> {
  console.log('ObliWAN M7 — wave rollouts, against a real PostgreSQL\n');

  testPureWavePlan();
  testPureInterlock();
  testHealthGate();

  await seedWorld();
  await testSchema();
  await testQueueInterlock();
  await testComposition();
  await testAcceptance();
  await testRefusals();

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failures.length) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  - ${f}`);
  }
  await db.destroy();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  try { await db.destroy(); } catch { /* ignore */ }
  process.exit(1);
});
