/**
 * ObliWAN F3 + F4 — verified against a real PostgreSQL.
 *
 * WHAT THIS FILE PROVES, AND WHAT IT CANNOT
 *
 * It proves the two features of ARCHITECTURE.md §10/F3-F4 against the REAL
 * schema of migration 020: the CHECK constraints, the partial unique indexes
 * and the composite foreign keys are all live, and several assertions below
 * exist only to make the database refuse something.
 *
 * It proves NOTHING about MikroTik. There is no router on this machine and
 * there never was one on this project. The two configurations compared in the
 * F3 tests come from `services/baseline/testing/fixtures.ts` — documents
 * written by hand in the NCM shape the M4 collector produces — and every SNMP
 * rollup bucket in the F4 tests was INSERTed by this file. "The errors on
 * ether1 went from 0 to 50 per hour" is a statement about this arithmetic, not
 * about any interface that has ever existed.
 *
 * The four acceptance criteria, checked verbatim:
 *   1. an OPEN intervention  -> the drift observed is attributed to it;
 *   2. an intervention never closed -> it expires by itself and says so;
 *   3. a device whose errors rise AFTER a change -> reported;
 *   4. a device already erroring BEFORE the change -> NOT reported.
 *
 *   DATABASE_URL=… npx tsx src/services/intervention/testing/f3f4.verify.ts
 */

import { ncmHash, type NcmDocument } from '@obliwan/shared';
import {
  AFTERMATH_TUNING,
  aftermathVerdictFrom,
  assertCorrelationalWording,
  INTERVENTION_HARD_CAP_MINUTES,
  INTERVENTION_MAX_ATTRIBUTION_WINDOW_MINUTES,
  INTERVENTION_MIN_OVERLAP_RATIO,
  interventionCoversChangeWindow,
} from '@obliwan/shared/dist/intervention';
import { db } from '../../../db';
import { runDrift } from '../../drift/drift.service';
import { attributeRun } from '../../drift/attribution.service';
import {
  cancelIntervention,
  closeIntervention,
  expireOverdue,
  getIntervention,
  listEvents,
  listInterventions,
  liveInterventionFor,
  openIntervention,
  overview,
  setDisposition,
} from '../intervention.service';
import { linkRunToIntervention, listLinks, sweepInterventionLinks } from '../driftLink';
import {
  evaluateAftermath,
  judgeAftermath,
  listAftermath,
  measure,
  sweepAftermath,
  windowsFor,
  windowsForInterval,
  type AftermathMeasurements,
} from '../../change/aftermath.service';
import { effectiveEnd } from '../window';
import { siteDoc, type SiteSpec } from '../../baseline/testing/fixtures';

const TENANT = 1;
const OTHER_TENANT = 2;

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
    failures.push(label + (extra ? ` — ${extra}` : ''));
    console.log(`  FAIL  ${label}${extra ? ' — ' + extra : ''}`);
  }
}

async function refuses(label: string, fn: () => Promise<unknown>, needle: string): Promise<void> {
  try {
    await fn();
    ok(label, false, 'it was accepted');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    ok(label, message.toLowerCase().includes(needle.toLowerCase()), message.slice(0, 200));
  }
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

// ============================================================================
// Seeding
// ============================================================================

interface Seeded {
  d1: number; // F3 — the attributed drift
  d2: number; // F3 — expiry
  d3: number; // F3 — a change job already explains the drift
  d4: number; // F4 — errors rise AFTER
  d5: number; // F4 — already erroring BEFORE
  d6: number; // isolation — belongs to OTHER_TENANT
  d7: number; // audit — a five-minute window swallowing a seven-day drift
  d8: number; // audit — the expired window whose sweep ran three days late
  d9: number; // audit — the window nobody closed and no HTTP path ever read
  d10: number; // audit — a week of outage with one reachable hour
  d11: number; // audit — the intervention that disturbed its own baseline
  d12: number; // audit — the premature evaluation that poisoned the J+7 sweep
  d13: number; // audit — the link that changed hands and kept the wrong window
  userId: number;
}

async function reset(): Promise<void> {
  await db.raw(
    'TRUNCATE change_aftermath, intervention_drift_links, intervention_events, ' +
      'interventions RESTART IDENTITY CASCADE',
  );
  await db('drift_attributions').del();
  await db('drift_findings').del();
  await db('drift_runs').del();
  await db('change_jobs').del();
  await db('change_plans').del();
  await db('device_backups').del();
  await db.raw('TRUNCATE snmp_if_rollup_1h, snmp_device_rollup_1h');
  await db('snmp_interfaces').del();
  await db('config_snapshots').del();
  await db('devices').del();
  await db('sites').del();
}

async function seed(): Promise<Seeded> {
  for (const [id, slug] of [
    [TENANT, 'default'],
    [OTHER_TENANT, 'other'],
  ] as const) {
    await db('tenants')
      .insert({ id, name: slug, slug })
      .onConflict('id')
      .ignore();
  }

  const existing = await db('users').where({ username: 'f3f4-operator' }).first<{ id: number }>('id');
  let userId: number;
  if (existing) userId = Number(existing.id);
  else {
    const [row] = await db('users')
      .insert({ username: 'f3f4-operator', display_name: 'f3f4-operator', role: 'user' })
      .returning<{ id: number }[]>('id');
    userId = Number(row.id);
  }

  const mk = async (name: string, tenantId: number): Promise<number> => {
    const [site] = await db('sites')
      .insert({ tenant_id: tenantId, code: name.toUpperCase(), name, timezone: 'Europe/Paris' })
      .returning<{ id: number }[]>('id');
    const [dev] = await db('devices')
      .insert({
        tenant_id: tenantId,
        site_id: Number(site.id),
        name,
        brand: 'mikrotik',
        family: 'mikrotik_routeros7',
        model: 'RB5009',
        serial: `SN-${name}`,
        os_version: '7.14.3',
        role: 'cpe',
        status: 'active',
        is_managed: true,
        system_identity: name,
      })
      .returning<{ id: number }[]>('id');
    return Number(dev.id);
  };

  return {
    d1: await mk('f3-attributed', TENANT),
    d2: await mk('f3-expiry', TENANT),
    d3: await mk('f3-platform', TENANT),
    d4: await mk('f4-degraded', TENANT),
    d5: await mk('f4-preexisting', TENANT),
    d6: await mk('other-tenant', OTHER_TENANT),
    d7: await mk('audit-overlap', TENANT),
    d8: await mk('audit-late-sweep', TENANT),
    d9: await mk('audit-dead-guard', TENANT),
    d10: await mk('audit-outage-baseline', TENANT),
    d11: await mk('audit-two-pivots', TENANT),
    d12: await mk('audit-premature', TENANT),
    d13: await mk('audit-relinked', TENANT),
    userId,
  };
}

// ── configuration snapshots, from the M12 fixtures ──────────────────────────

function spec(index: number, sshPort?: number): SiteSpec {
  return {
    index,
    name: `f3-site-${index}`,
    profile: 'A',
    octet: 30 + index,
    quirks: sshPort ? { sshPort } : {},
  };
}

async function storeDoc(
  deviceId: number,
  doc: NcmDocument,
  capturedAt: Date,
  lastSeenAt: Date,
): Promise<string> {
  const [row] = await db('config_snapshots')
    .insert({
      device_id: deviceId,
      source: 'routeros_api',
      ncm: JSON.stringify(doc),
      ncm_hash: ncmHash(doc),
      ncm_version: doc.ncmVersion,
      sem_key_generation: doc.semKeyGeneration,
      normalization_epoch: doc.normalizationEpoch,
      order_analysis: doc.orderAnalysis,
      os_version: doc.device.osVersion,
      model: doc.device.model,
      captured_at: capturedAt,
      last_seen_at: lastSeenAt,
    })
    .returning<{ id: string }[]>('id');
  return String(row.id);
}

/**
 * A push that reached the device and succeeded.
 *
 * The plan and the preflight backup are NOT decoration:
 * `change_jobs_push_needs_plan_chk` and `change_jobs_preflight_backup_chk`
 * (migration 009, decision 2) make a write job without either of them
 * unrepresentable, so a test that skipped them would be exercising a row the
 * product can never produce.
 */
async function succeededPush(
  deviceId: number,
  startedAt: Date,
  finishedAt: Date,
): Promise<string> {
  const [plan] = await db('change_plans')
    .insert({
      tenant_id: TENANT,
      device_id: deviceId,
      source: 'template',
      base_state_hash: 'a'.repeat(64),
      risk_level: 'low',
      mgmt_path_verdict: 'accept',
      safety_level: 'armed',
      expires_at: new Date(startedAt.getTime() + 24 * HOUR),
    })
    .returning<{ id: string }[]>('id');
  const [backup] = await db('device_backups')
    .insert({
      tenant_id: TENANT,
      device_id: deviceId,
      kind: 'binary',
      trigger_kind: 'preflight',
      storage_path: `/var/obliwan/backups/${deviceId}-${startedAt.getTime()}.backup`,
      size_bytes: 1024,
      sha256: 'd'.repeat(64),
      status: 'available',
      taken_at: startedAt,
    })
    .returning<{ id: string }[]>('id');
  const [job] = await db('change_jobs')
    .insert({
      tenant_id: TENANT,
      device_id: deviceId,
      kind: 'push',
      status: 'succeeded',
      base_state_hash: 'a'.repeat(64),
      safety_level: 'armed',
      guard_verdict: 'ACCEPT',
      plan_id: plan.id,
      preflight_backup_id: backup.id,
      // `change_jobs_started_chk`: a job that started was claimed by a worker
      // first. The lease is part of what makes the row believable.
      claimed_by: 'verify:0:f3f4',
      claimed_at: startedAt,
      attempt: 1,
      started_at: startedAt,
      finished_at: finishedAt,
      outcome: 'succeeded',
    })
    .returning<{ id: string }[]>('id');
  return String(job.id);
}

// ── SNMP rollups ────────────────────────────────────────────────────────────

async function seedInterface(deviceId: number, ifName: string, speedBps: number): Promise<number> {
  const [row] = await db('snmp_interfaces')
    .insert({
      device_id: deviceId,
      if_name: ifName,
      if_index: 1,
      speed_bps: speedBps,
      admin_status: 1,
      oper_status: 1,
      state: 'active',
      monitored: true,
      needs_rediscovery: false,
      effective_poll_sec: 30,
    })
    .returning<{ id: number }[]>('id');
  return Number(row.id);
}

interface HourSpec {
  rttUs: number;
  reachable: number;
  samples: number;
  uptimeTicks: number;
}

async function seedDeviceHours(
  deviceId: number,
  from: Date,
  hours: number,
  h: HourSpec,
): Promise<void> {
  const rows = [];
  for (let i = 0; i < hours; i += 1) {
    rows.push({
      bucket: new Date(from.getTime() + i * HOUR),
      device_id: deviceId,
      mem_used_avg_bytes: 1,
      mem_used_max_bytes: 1,
      mem_total_bytes: 2,
      uptime_ticks_max: h.uptimeTicks + i * 360_000,
      rtt_avg_us: h.rttUs,
      rtt_max_us: h.rttUs,
      rtt_p95_us: h.rttUs,
      cpu_avg_pct: 5,
      cpu_max_pct: 9,
      temp_avg_dc: 400,
      temp_max_dc: 420,
      reachable_count: h.reachable,
      sample_count: h.samples,
      expected_count: h.samples,
    });
  }
  for (let i = 0; i < rows.length; i += 200) {
    await db('snmp_device_rollup_1h').insert(rows.slice(i, i + 200));
  }
}

async function seedIfHours(
  ifId: number,
  from: Date,
  hours: number,
  errorsPerHour: number,
  bps: number,
): Promise<void> {
  const rows = [];
  for (let i = 0; i < hours; i += 1) {
    rows.push({
      bucket: new Date(from.getTime() + i * HOUR),
      if_id: ifId,
      in_avg_bps: bps,
      in_max_bps: bps,
      in_p95_bps: bps,
      out_avg_bps: 0,
      out_max_bps: 0,
      out_p95_bps: 0,
      in_errs: errorsPerHour,
      out_errs: 0,
      in_discards: 0,
      out_discards: 0,
      sample_count: 120,
      expected_count: 120,
    });
  }
  for (let i = 0; i < rows.length; i += 200) {
    await db('snmp_if_rollup_1h').insert(rows.slice(i, i + 200));
  }
}

// ============================================================================
// 1. Pure tests — no database
// ============================================================================

function measurements(over: Partial<AftermathMeasurements> = {}): AftermathMeasurements {
  return {
    device: {
      bucketsBefore: 168,
      bucketsAfter: 168,
      // A healthy week: every rollup bucket carries an RTT and a poll.
      rttBucketsBefore: 168,
      rttBucketsAfter: 168,
      availBucketsBefore: 168,
      availBucketsAfter: 168,
      rttBeforeUs: 8000,
      rttAfterUs: 8200,
      reachableBefore: 20160,
      samplesBefore: 20160,
      reachableAfter: 20160,
      samplesAfter: 20160,
      rebootsBefore: 0,
      rebootsAfter: 0,
    },
    interfaces: [],
    ...over,
  };
}

function testPure(): void {
  console.log('\n── F4 arithmetic and the wording guard (pure) ──');

  // THE headline case of §10/F4: clean before, erroring since.
  const rising = judgeAftermath(
    measurements({
      interfaces: [
        {
          ifName: 'ether1',
          speedBps: 1_000_000_000,
          bucketsBefore: 168,
          bucketsAfter: 168,
          errorsBefore: 0,
          errorsAfter: 168 * 40,
          peakBpsBefore: 10_000_000,
          peakBpsAfter: 10_000_000,
        },
      ],
    }),
  );
  ok('a clean interface that starts erroring is DEGRADED', rising.verdict === 'DEGRADED',
    `${rising.verdict}, ${rising.degradedCount} degraded`);

  // TRAP 1. The same ×40 rise, on a link that was ALREADY erroring.
  const preexisting = judgeAftermath(
    measurements({
      interfaces: [
        {
          ifName: 'ether1',
          speedBps: 1_000_000_000,
          bucketsBefore: 168,
          bucketsAfter: 168,
          errorsBefore: 168 * 10,
          errorsAfter: 168 * 400,
          peakBpsBefore: 10_000_000,
          peakBpsAfter: 10_000_000,
        },
      ],
    }),
  );
  ok(
    'an interface ALREADY erroring is excluded, not accused',
    preexisting.verdict !== 'DEGRADED' && preexisting.preexistingCount === 1,
    `${preexisting.verdict}, ${preexisting.preexistingCount} pre-existing`,
  );

  // A device that was already flapping does not get blamed either.
  const flapping = judgeAftermath(
    measurements({
      device: {
        ...measurements().device,
        reachableBefore: 18000,
        samplesBefore: 20160,
        reachableAfter: 14000,
        samplesAfter: 20160,
      },
    }),
  );
  ok(
    'a device already missing polls is excluded, not accused',
    flapping.verdict !== 'DEGRADED',
    flapping.verdict,
  );

  // …but a healthy device that starts missing polls IS reported.
  const dropping = judgeAftermath(
    measurements({
      device: {
        ...measurements().device,
        reachableBefore: 20160,
        samplesBefore: 20160,
        reachableAfter: 16000,
        samplesAfter: 20160,
      },
    }),
  );
  ok('a healthy device that starts missing polls is DEGRADED', dropping.verdict === 'DEGRADED');

  // A device that was already restarting is excluded; one that starts is not.
  const wasRebooting = judgeAftermath(
    measurements({ device: { ...measurements().device, rebootsBefore: 3, rebootsAfter: 4 } }),
  );
  ok('a device already restarting is excluded', wasRebooting.verdict !== 'DEGRADED');
  const startedRebooting = judgeAftermath(
    measurements({ device: { ...measurements().device, rebootsBefore: 0, rebootsAfter: 2 } }),
  );
  ok('a device that starts restarting is DEGRADED', startedRebooting.verdict === 'DEGRADED');

  // Silence is not health.
  const silent = judgeAftermath(
    measurements({
      device: {
        bucketsBefore: 0, bucketsAfter: 0,
        rttBucketsBefore: 0, rttBucketsAfter: 0,
        availBucketsBefore: 0, availBucketsAfter: 0,
        rttBeforeUs: null, rttAfterUs: null,
        reachableBefore: 0, samplesBefore: 0, reachableAfter: 0, samplesAfter: 0,
        rebootsBefore: 0, rebootsAfter: 0,
      },
    }),
  );
  ok(
    'a device nobody polls is INSUFFICIENT_DATA and never STABLE',
    silent.verdict === 'INSUFFICIENT_DATA' && silent.measuredCount === 0,
    silent.verdict,
  );

  // Saturation needs the CROSSING, not just the rise.
  const grew = judgeAftermath(
    measurements({
      interfaces: [
        {
          ifName: 'ether1', speedBps: 1_000_000_000,
          bucketsBefore: 168, bucketsAfter: 168, errorsBefore: 0, errorsAfter: 0,
          peakBpsBefore: 50_000_000, peakBpsAfter: 250_000_000,
        },
      ],
    }),
  );
  ok('traffic growth well under the line rate is not a degradation', grew.verdict !== 'DEGRADED');
  const saturated = judgeAftermath(
    measurements({
      interfaces: [
        {
          ifName: 'ether1', speedBps: 1_000_000_000,
          bucketsBefore: 168, bucketsAfter: 168, errorsBefore: 0, errorsAfter: 0,
          peakBpsBefore: 500_000_000, peakBpsAfter: 900_000_000,
        },
      ],
    }),
  );
  ok('crossing the saturation ceiling IS a degradation', saturated.verdict === 'DEGRADED');

  // The fold: severity, never majority.
  ok('one degraded beats any number of stables',
    aftermathVerdictFrom(['stable', 'stable', 'degraded', 'improved']) === 'DEGRADED');
  ok('only excluded subjects means INSUFFICIENT_DATA',
    aftermathVerdictFrom(['preexisting', 'no_baseline', 'not_measured']) === 'INSUFFICIENT_DATA');
  ok('improvement is reported when nothing degraded',
    aftermathVerdictFrom(['stable', 'improved']) === 'IMPROVED');

  // TRAP 2, enforced at runtime.
  let refused = false;
  try {
    assertCorrelationalWording('ether1 is erroring because of this change');
  } catch {
    refused = true;
  }
  ok('a causal claim is refused by the wording guard', refused);
  let refusedFr = false;
  try {
    assertCorrelationalWording('les erreurs ont augmenté à cause de ce changement');
  } catch {
    refusedFr = true;
  }
  ok('the French causal claim is refused too', refusedFr);
  let accepted = true;
  try {
    assertCorrelationalWording('ether1 has taken 40 errors/h since this change');
  } catch {
    accepted = false;
  }
  ok('the correlational sentence is accepted', accepted);

  // Every message the judge produced went through the guard already; assert it
  // out loud so a future refactor that bypasses `say()` is caught here.
  const allMessages = [...rising.signals, ...preexisting.signals].map((s) => s.message);
  ok(
    'no message the judge produced claims causation',
    allMessages.every((m) => {
      try {
        assertCorrelationalWording(m);
        return true;
      } catch {
        return false;
      }
    }),
    `${allMessages.length} messages`,
  );

  // The bucket containing the change belongs to neither side.
  const w = windowsFor(new Date('2026-08-20T13:37:00.000Z'), 7);
  ok(
    'the hour containing the change is in neither window',
    w.baselineTo.toISOString() === '2026-08-20T13:00:00.000Z' &&
      w.afterFrom.toISOString() === '2026-08-20T14:00:00.000Z',
    `${w.baselineTo.toISOString()} .. ${w.afterFrom.toISOString()}`,
  );
  ok(
    'the baseline is a full horizon BEFORE the change',
    w.baselineFrom.getTime() === w.baselineTo.getTime() - 7 * DAY,
  );
}

// ============================================================================
// 2. F3 — an OPEN intervention absorbs the drift observed on its device
// ============================================================================

async function testAttribution(s: Seeded): Promise<void> {
  console.log('\n── F3: drift during a declared window is attributed to it ──');

  const now = new Date();
  const openedAt = new Date(now.getTime() - 40 * MINUTE);

  // The BEFORE state exists first — an intervention opened on a device we have
  // never collected has no before-state to diff against, and `openIntervention`
  // records that honestly by leaving `snapshot_before_id` NULL. Here the
  // configuration was last confirmed still true five minutes into the window.
  const before = await storeDoc(
    s.d1,
    siteDoc(spec(1), s.d1),
    new Date(openedAt.getTime() - HOUR),
    new Date(openedAt.getTime() + 5 * MINUTE),
  );

  const result = await openIntervention(
    TENANT,
    {
      deviceId: s.d1,
      operator: 'Jean (sous-traitant)',
      reason: 'Ajout de la règle NAT pour le nouvel ERP du client',
      channel: 'winbox',
      windowMinutes: 120,
      openedBy: s.userId,
    },
    openedAt,
  );
  const iv = result.intervention;
  ok('the window opens', iv.status === 'open' && iv.deviceId === s.d1, `#${iv.id}`);
  ok('it carries the declared operator and reason', iv.operator.startsWith('Jean') && iv.reason.length > 10);
  ok('it pins the before-state without touching the device',
    iv.snapshotBeforeId === before && result.collectError === null);

  // The new state, captured half an hour into the window. The interval between
  // the two — K6's own window — sits inside the declared one.
  const after = await storeDoc(
    s.d1,
    siteDoc(spec(1, 2222), s.d1),
    new Date(openedAt.getTime() + 30 * MINUTE),
    new Date(openedAt.getTime() + 30 * MINUTE),
  );

  const run = await runDrift(TENANT, s.d1, {
    cause: 'manual',
    baselineSnapshotId: before,
    snapshotId: after,
    scope: 'full',
  });
  ok('the two configurations differ', run !== null && run.status === 'drifted',
    `${run?.status}, ${run?.findingsCount} findings`);

  // What K6 says on its own, with no login event anywhere: nobody owns it.
  const bare = await attributeRun(run!.id, { force: true });
  ok(
    'without the intervention, K6 calls it unattributed — an anomaly nobody owns',
    bare?.verdict === 'unattributed',
    bare?.verdict,
  );

  const swept = await sweepInterventionLinks(TENANT, { deviceId: s.d1 });
  ok('the sweep considered the run', swept.considered === 1 && swept.attributed === 1,
    JSON.stringify(swept));

  const claimed = await attributeRun(run!.id);
  ok(
    'the drift is now attributed to the declared intervention',
    String(claimed?.verdict) === 'intervention' && claimed?.reason === 'declared_intervention',
    `${claimed?.verdict} / ${claimed?.reason}`,
  );
  ok('and it names nobody — the CHECK forbids it under this verdict', claimed?.account === null);

  const links = await listLinks(TENANT, iv.id);
  ok('the link records what K6 would have said', links.length === 1 &&
    links[0].disposition === 'attributed' && links[0].priorVerdict === 'unattributed',
    JSON.stringify(links[0]));
  ok('the link carries the overlap arithmetic',
    links[0].overlapSeconds > 0 && links[0].overlapSeconds <= links[0].windowSpanSeconds,
    `${links[0].overlapSeconds}/${links[0].windowSpanSeconds}s`);

  const events = await listEvents(TENANT, iv.id);
  ok('the lifecycle log carries the link', events.some((e) => e.event === 'drift_linked'));

  // It is no longer on the "changes nobody owns" screen.
  const open = await db('drift_attributions')
    .whereIn('verdict', ['unattributed', 'ambiguous'])
    .andWhere('run_id', run!.id)
    .first();
  ok('it has left the anomaly screen', open === undefined);

  // Idempotence: sweeping twice claims nothing twice.
  const again = await sweepInterventionLinks(TENANT, { deviceId: s.d1 });
  ok('a second sweep is a no-op', again.considered === 0, JSON.stringify(again));

  // Closing produces the diff offered for promotion.
  const closed = await closeIntervention(TENANT, iv.id, { closedBy: s.userId, notes: null });
  ok('closing produces a semantic diff for review',
    closed.driftRunId !== null && closed.findingsCount > 0,
    `run ${closed.driftRunId}, ${closed.findingsCount} findings`);
  ok('a closed window is unreviewed until somebody decides',
    closed.intervention.disposition === 'unreviewed');

  const decided = await setDisposition(TENANT, iv.id, 'template', 'promu en template NAT-ERP', s.userId);
  ok('the decision is recorded', decided.disposition === 'template');

  // …and the closing run is claimed too, so the review never shows up as an
  // anonymous anomaly either.
  const closingAttribution = await attributeRun(closed.driftRunId as string);
  ok('the closing diff is attributed to the window as well',
    String(closingAttribution?.verdict) === 'intervention', closingAttribution?.verdict);
}

// ============================================================================
// 3. F3 — the window nobody closed expires by itself, and says so
// ============================================================================

async function testExpiry(s: Seeded): Promise<void> {
  console.log('\n── F3: an intervention nobody closes expires and says so ──');

  const now = new Date();
  const openedAt = new Date(now.getTime() - 3 * HOUR);
  const { intervention: iv } = await openIntervention(
    TENANT,
    {
      deviceId: s.d2,
      operator: 'Camille',
      reason: 'Diagnostic OSPF sur site',
      windowMinutes: 60,
      openedBy: s.userId,
    },
    openedAt,
  );
  ok('the window is open and already past its deadline', iv.status === 'open' &&
    new Date(iv.expiresAt).getTime() < now.getTime());

  const outcome = await expireOverdue(TENANT, now);
  ok('the sweep expired it', outcome.expired === 1 && outcome.ids.includes(iv.id),
    JSON.stringify(outcome));

  const after = await getIntervention(TENANT, iv.id);
  ok('its status is expired, not closed', after?.status === 'expired', after?.status);
  ok('expired and closed stay distinguishable', after?.closedAt === null && after?.expiredAt !== null);

  const events = await listEvents(TENANT, iv.id);
  const expiredEvent = events.find((e) => e.event === 'expired');
  ok('it SAYS SO: an expiry event is written', expiredEvent !== undefined);
  ok('and it says how long it went unattended',
    Number(expiredEvent?.detail.unattendedSeconds ?? 0) > 3000,
    String(expiredEvent?.detail.unattendedSeconds));

  const counters = await overview(TENANT);
  ok('the overview counts it as a window nobody closed', counters.expiredUnclosed >= 1,
    JSON.stringify(counters));

  // THE load-bearing consequence: a new window can be declared on that device.
  const second = await openIntervention(
    TENANT,
    { deviceId: s.d2, operator: 'Camille', reason: 'Reprise du diagnostic', openedBy: s.userId },
    now,
  );
  ok('a new window can be declared on the same device once the old one expired',
    second.intervention.status === 'open' && second.intervention.id !== iv.id);

  // Two live windows on one device remain impossible.
  await refuses(
    'a second live window on the same device is refused',
    () =>
      openIntervention(TENANT, {
        deviceId: s.d2,
        operator: 'Someone else',
        reason: 'Concurrent work',
        openedBy: s.userId,
      }),
    'already has an open intervention',
  );

  // Drift whose change window falls AFTER the expiry is attributable again.
  const beforeSnap = await storeDoc(
    s.d2,
    siteDoc(spec(2), s.d2),
    new Date(now.getTime() - 10 * MINUTE),
    new Date(now.getTime() - 9 * MINUTE),
  );
  const afterSnap = await storeDoc(
    s.d2,
    siteDoc(spec(2, 2223), s.d2),
    new Date(now.getTime() - 8 * MINUTE),
    new Date(now.getTime() - 8 * MINUTE),
  );
  const run = await runDrift(TENANT, s.d2, {
    baselineSnapshotId: beforeSnap,
    snapshotId: afterSnap,
    scope: 'full',
  });
  const links = await db('intervention_drift_links')
    .where({ tenant_id: TENANT, drift_run_id: run!.id })
    .first<{ intervention_id: string } | undefined>('intervention_id');
  // The change happened AFTER the first window expired, so the expired window
  // cannot absorb it. The SECOND window (opened at `now`) legitimately can —
  // which is the correct answer, and the assertion is that the EXPIRED one
  // does not claim it.
  await sweepInterventionLinks(TENANT, { deviceId: s.d2 });
  const linked = await db('intervention_drift_links')
    .where({ tenant_id: TENANT, drift_run_id: run!.id })
    .first<{ intervention_id: string } | undefined>('intervention_id');
  ok(
    'an expired window does not absorb a change made after it ran out',
    links === undefined && (linked === undefined || String(linked.intervention_id) !== iv.id),
    `linked to ${linked?.intervention_id ?? 'nothing'} (expired window was ${iv.id})`,
  );

  await cancelIntervention(TENANT, second.intervention.id, s.userId);
  const cancelled = await getIntervention(TENANT, second.intervention.id);
  ok('a window can be called off before it runs', cancelled?.status === 'cancelled');
}

// ============================================================================
// 4. F3 — the intervention resolves the UNKNOWN, never the KNOWN
// ============================================================================

async function testPrecedence(s: Seeded): Promise<void> {
  console.log('\n── F3: a change job already explains it — the window does not steal it ──');

  const now = new Date();
  const openedAt = new Date(now.getTime() - 30 * MINUTE);
  const { intervention: iv } = await openIntervention(
    TENANT,
    { deviceId: s.d3, operator: 'Alex', reason: 'Vérification post-push', windowMinutes: 120, openedBy: s.userId },
    openedAt,
  );

  const before = await storeDoc(
    s.d3,
    siteDoc(spec(3), s.d3),
    new Date(openedAt.getTime() - HOUR),
    new Date(openedAt.getTime() + 2 * MINUTE),
  );
  const after = await storeDoc(
    s.d3,
    siteDoc(spec(3, 2224), s.d3),
    new Date(openedAt.getTime() + 20 * MINUTE),
    new Date(openedAt.getTime() + 20 * MINUTE),
  );

  // OUR OWN write, inside the same window.
  await succeededPush(
    s.d3,
    new Date(openedAt.getTime() + 8 * MINUTE),
    new Date(openedAt.getTime() + 10 * MINUTE),
  );

  const run = await runDrift(TENANT, s.d3, {
    baselineSnapshotId: before,
    snapshotId: after,
    scope: 'full',
  });
  await sweepInterventionLinks(TENANT, { deviceId: s.d3 });

  const attribution = await attributeRun(run!.id);
  ok(
    'a run explained by one of our change jobs keeps the `platform` verdict',
    attribution?.verdict === 'platform',
    attribution?.verdict,
  );
  const links = await listLinks(TENANT, iv.id);
  ok(
    'the window links it anyway, marked already_explained',
    links.length === 1 && links[0].disposition === 'already_explained' &&
      links[0].priorVerdict === 'platform',
    JSON.stringify(links[0]),
  );
}

// ============================================================================
// 5. F4 — errors that rise AFTER a change, and errors that were there BEFORE
// ============================================================================

async function testAftermath(s: Seeded): Promise<void> {
  console.log('\n── F4: what the telemetry has done since the change ──');

  const now = new Date();
  // The change landed eight days ago, so a full seven-day observation window
  // exists on both sides — the horizon §10/F4 asks for.
  const changeAt = new Date(Math.floor((now.getTime() - 8 * DAY) / HOUR) * HOUR + 37 * MINUTE);
  const w = windowsFor(changeAt, 7);

  const mkJob = (deviceId: number): Promise<string> =>
    succeededPush(deviceId, new Date(changeAt.getTime() - MINUTE), changeAt);

  // ── the device whose errors RISE after the change ────────────────────────
  const job4 = await mkJob(s.d4);
  const if4 = await seedInterface(s.d4, 'ether1', 1_000_000_000);
  await seedDeviceHours(s.d4, w.baselineFrom, 168, {
    rttUs: 9000, reachable: 120, samples: 120, uptimeTicks: 1_000_000,
  });
  await seedDeviceHours(s.d4, w.afterFrom, 168, {
    rttUs: 9100, reachable: 120, samples: 120, uptimeTicks: 9_000_000,
  });
  await seedIfHours(if4, w.baselineFrom, 168, 0, 10_000_000);
  await seedIfHours(if4, w.afterFrom, 168, 40, 10_000_000);

  const rising = await evaluateAftermath(TENANT, { jobId: job4 }, { horizonDays: 7, now });
  ok(
    'a device whose errors rise AFTER the change is reported',
    rising.verdict === 'DEGRADED' && rising.degradedCount >= 1,
    `${rising.verdict}, ${rising.degradedCount} degraded`,
  );
  const errSignal = rising.signals.find((x) => x.metric === 'if_errors');
  ok('the report carries the two numbers, not just the verdict',
    errSignal?.before === 0 && Number(errSignal?.after) === 40, JSON.stringify(errSignal));
  // Trap 2, on the wire this time. Every signal that CLAIMS something must
  // name the window it measured over; `signal()` throws otherwise, so this
  // assertion is the guard's observable half.
  const claiming = rising.signals.filter(
    (x) => x.outcome === 'degraded' || x.outcome === 'improved',
  );
  ok(
    'every claiming sentence says SINCE and never BECAUSE',
    claiming.length > 0 &&
      claiming.every(
        (x) => /since this change/i.test(x.message) && !/because|caused/i.test(x.message),
      ),
    errSignal?.message,
  );

  // ── the device that was ALREADY erroring before ──────────────────────────
  const job5 = await mkJob(s.d5);
  const if5 = await seedInterface(s.d5, 'ether1', 1_000_000_000);
  await seedDeviceHours(s.d5, w.baselineFrom, 168, {
    rttUs: 9000, reachable: 120, samples: 120, uptimeTicks: 1_000_000,
  });
  await seedDeviceHours(s.d5, w.afterFrom, 168, {
    rttUs: 9050, reachable: 120, samples: 120, uptimeTicks: 9_000_000,
  });
  // Already dropping ten frames an hour BEFORE anybody touched it, and forty
  // after — the exact same rise as the device above.
  await seedIfHours(if5, w.baselineFrom, 168, 10, 10_000_000);
  await seedIfHours(if5, w.afterFrom, 168, 40, 10_000_000);

  const already = await evaluateAftermath(TENANT, { jobId: job5 }, { horizonDays: 7, now });
  ok(
    'a device ALREADY erroring before the change is NOT reported',
    already.verdict !== 'DEGRADED' && already.degradedCount === 0,
    `${already.verdict}, ${already.preexistingCount} excluded`,
  );
  ok('and the exclusion is counted, not hidden', already.preexistingCount >= 1);
  const excluded = already.signals.find((x) => x.metric === 'if_errors');
  ok('the excluded subject is still shown with its numbers',
    excluded?.outcome === 'preexisting' && excluded?.before === 10 && excluded?.after === 40,
    JSON.stringify(excluded));

  // ── persistence, idempotence and the corpus ──────────────────────────────
  ok('the report is stored next to apply_outcomes', rising.id !== null);
  const twice = await evaluateAftermath(TENANT, { jobId: job4 }, { horizonDays: 7, now });
  ok('re-evaluating updates in place instead of duplicating', twice.id === rising.id);
  const stored = await db('change_aftermath').where('tenant_id', TENANT).count<{ count: string }[]>('* as count').first();
  ok('exactly two rows exist', Number(stored?.count) === 2, String(stored?.count));

  const listed = await listAftermath(TENANT, { degradedOnly: true });
  ok('the degraded screen returns only the degraded one',
    listed.length === 1 && listed[0].jobId === job4, `${listed.length} rows`);

  // A shorter horizon is a DIFFERENT row, not an overwrite.
  const short = await evaluateAftermath(TENANT, { jobId: job4 }, { horizonDays: 3, now });
  ok('a different horizon is a different evaluation', short.id !== rising.id);

  // ── the J+7 engine ───────────────────────────────────────────────────────
  await db('change_aftermath').where({ tenant_id: TENANT, horizon_days: 7 }).del();
  const swept = await sweepAftermath(TENANT, { horizonDays: 7, now });
  ok('the sweep finds the changes old enough to be judged',
    swept.considered >= 2 && swept.evaluated >= 2, JSON.stringify(swept));
  ok('and it reports the degraded one', swept.degraded === 1, JSON.stringify(swept));

  // A change made an hour ago is NOT swept: its window is not complete.
  const fresh = await succeededPush(
    s.d4,
    new Date(now.getTime() - 2 * HOUR),
    new Date(now.getTime() - HOUR),
  );
  const swept2 = await sweepAftermath(TENANT, { horizonDays: 7, now });
  ok('a change younger than the horizon is not judged yet',
    !swept2.considered || swept2.considered === 0, JSON.stringify(swept2));
  void fresh;

  // ── an intervention can be the anchor too ────────────────────────────────
  const openedAt = new Date(changeAt.getTime() - HOUR);
  const { intervention: iv } = await openIntervention(
    TENANT,
    { deviceId: s.d4, operator: 'Nadia', reason: 'Remplacement du SFP WAN', windowMinutes: 120, openedBy: s.userId },
    openedAt,
  );
  await db('interventions').where('id', iv.id).update({
    status: 'closed', closed_at: changeAt, closed_by: s.userId,
  });
  const ivReport = await evaluateAftermath(TENANT, { interventionId: iv.id }, { horizonDays: 7, now });
  ok('a human intervention can be measured a week later too',
    ivReport.interventionId === iv.id && ivReport.jobId === null &&
      ivReport.verdict === 'DEGRADED',
    ivReport.verdict);
}

// ============================================================================
// 6. The six findings of the F3/F4 audit, replayed
// ============================================================================
//
// Every test below FAILED before its fix and passes after it. They are written
// as scenarios rather than as unit tests on purpose: each one is the shortest
// sequence of ordinary product calls that produced the wrong answer.

async function testAuditFindings(s: Seeded): Promise<void> {
  console.log('\n── the six findings of the audit, replayed ──');
  const now = new Date();

  // ── 1. A five-minute window declared after the fact swallowed a seven-day
  //      drift, on 0.0099 % of overlap. ─────────────────────────────────────
  ok('the coverage rule is stated once, in shared',
    interventionCoversChangeWindow(60, 100) &&
      !interventionCoversChangeWindow(49, 100) &&
      interventionCoversChangeWindow(0, 0) &&
      INTERVENTION_MIN_OVERLAP_RATIO === 0.5);

  // The router was last CONFIRMED unchanged seven days ago; the fresh
  // collection happens now. K6's change window is therefore a week wide.
  const b7 = await storeDoc(
    s.d7,
    siteDoc(spec(7), s.d7),
    new Date(now.getTime() - 8 * DAY),
    new Date(now.getTime() - 7 * DAY),
  );
  const a7 = await storeDoc(s.d7, siteDoc(spec(7, 2227), s.d7), now, now);
  const run7 = await runDrift(TENANT, s.d7, {
    baselineSnapshotId: b7,
    snapshotId: a7,
    scope: 'full',
  });
  ok('a week-wide change window exists on the device', run7?.status === 'drifted');

  // …and only NOW does somebody declare a five-minute intervention, with the
  // capability that already lets him dismiss a drift.
  const { intervention: iv7 } = await openIntervention(
    TENANT,
    {
      deviceId: s.d7,
      operator: 'quelqu-un',
      reason: 'Declaree apres coup, cinq minutes',
      windowMinutes: 5,
      openedBy: s.userId,
    },
    new Date(now.getTime() - 3 * MINUTE),
  );
  await sweepInterventionLinks(TENANT, { deviceId: s.d7, now });

  const links7 = await listLinks(TENANT, iv7.id);
  ok('the sweep still LINKS the coincidence — the operator sees it',
    links7.length === 1, String(links7.length) + ' links');
  ok(
    'but a 0.03 % overlap does not attribute a week of drift to a five-minute window',
    links7[0]?.disposition === 'window_too_wide',
    String(links7[0]?.disposition) + ' ' +
      String(links7[0]?.overlapSeconds) + '/' + String(links7[0]?.windowSpanSeconds) + 's',
  );
  ok('the two numbers that justify the claim are now the CRITERION',
    links7[0] !== undefined &&
      links7[0].windowSpanSeconds > (6 * DAY) / 1000 &&
      links7[0].overlapSeconds * 2 < links7[0].windowSpanSeconds);
  const att7 = await attributeRun(String(run7?.id));
  ok('K6 keeps its verdict: the change is still one nobody owns',
    att7?.verdict === 'unattributed', att7?.verdict);
  const still7 = await db('drift_attributions')
    .whereIn('verdict', ['unattributed', 'ambiguous'])
    .andWhere('run_id', run7!.id)
    .first();
  ok('and it is still on the "changes nobody owns" screen', still7 !== undefined);

  // ── 2. An expired window ends at its DECLARED deadline, not at the instant
  //      a late sweep noticed. ──────────────────────────────────────────────
  const declared = new Date('2026-08-27T03:53:00.000Z');
  const noticed = new Date('2026-08-30T01:53:00.000Z');
  ok(
    'effectiveEnd of an expired window is expires_at, not expired_at',
    effectiveEnd({
      status: 'expired',
      expires_at: declared,
      closed_at: null,
      expired_at: noticed,
      cancelled_at: null,
    }).getTime() === declared.getTime(),
  );
  ok(
    'a window closed AFTER its deadline is clamped to the deadline too',
    effectiveEnd({
      status: 'closed',
      expires_at: declared,
      closed_at: noticed,
      expired_at: null,
      cancelled_at: null,
    }).getTime() === declared.getTime(),
  );

  // The whole scenario: a two-hour window declared three days ago, never
  // closed, and swept for the first time now.
  const opened8 = new Date(now.getTime() - 72 * HOUR);
  const { intervention: iv8 } = await openIntervention(
    TENANT,
    {
      deviceId: s.d8,
      operator: 'Camille',
      reason: 'Fenetre de deux heures jamais fermee',
      windowMinutes: 120,
      openedBy: s.userId,
    },
    opened8,
  );
  await expireOverdue(TENANT, now, s.d8);
  const row8 = await db('interventions').where('id', iv8.id)
    .first<{ status: string; expires_at: Date; expired_at: Date }>(
      'status', 'expires_at', 'expired_at',
    );
  ok('the sweep ran three days late and says so in expired_at',
    row8.status === 'expired' &&
      row8.expired_at.getTime() - row8.expires_at.getTime() > 60 * HOUR,
    String(Math.round((row8.expired_at.getTime() - row8.expires_at.getTime()) / HOUR)) + ' h late');

  const b8 = await storeDoc(
    s.d8,
    siteDoc(spec(8), s.d8),
    new Date(now.getTime() - 72 * HOUR),
    new Date(now.getTime() - 71 * HOUR),
  );
  const a8 = await storeDoc(s.d8, siteDoc(spec(8, 2228), s.d8), now, now);
  const run8 = await runDrift(TENANT, s.d8, {
    baselineSnapshotId: b8,
    snapshotId: a8,
    scope: 'full',
  });
  await sweepInterventionLinks(TENANT, { deviceId: s.d8, now });
  const links8 = await listLinks(TENANT, iv8.id);
  ok(
    'a two-hour window records a two-hour overlap of a 71-hour change window',
    links8.length === 1 &&
      Math.abs(links8[0].overlapSeconds - 3600) < 180 &&
      links8[0].windowSpanSeconds > 250_000,
    String(links8[0]?.overlapSeconds) + '/' + String(links8[0]?.windowSpanSeconds) + 's',
  );
  ok('so it does not claim the change either',
    links8[0]?.disposition === 'window_too_wide', links8[0]?.disposition);
  void run8;

  // ── 3. GARDE MORTE — the periodic sweep never expired anything. ──────────
  const opened9 = new Date(now.getTime() - 5 * DAY);
  const { intervention: iv9 } = await openIntervention(
    TENANT,
    {
      deviceId: s.d9,
      operator: 'personne',
      reason: 'Cinq minutes declarees il y a cinq jours',
      windowMinutes: 5,
      openedBy: s.userId,
    },
    opened9,
  );
  const before9 = await db('interventions').where('id', iv9.id)
    .first<{ status: string }>('status');
  ok('the window is open and five days past its deadline', before9.status === 'open');

  // THE assertion: the only function a scheduler arms, and nothing else.
  await sweepInterventionLinks(TENANT, { deviceId: s.d9, now });

  const after9 = await db('interventions').where('id', iv9.id)
    .first<{ status: string; expired_at: Date | null }>('status', 'expired_at');
  ok(
    'the periodic sweep — with no human reading any screen — expires it',
    after9.status === 'expired' && after9.expired_at !== null,
    after9.status,
  );
  const ev9 = await listEvents(TENANT, iv9.id);
  const expired9 = ev9.find((e) => e.event === 'expired');
  ok('and it says so, with how long it went unattended',
    expired9 !== undefined &&
      Number(expired9.detail.unattendedSeconds) > (4 * DAY) / 1000,
    String(expired9?.detail.unattendedSeconds));

  // ── 4. 167 unreachable hours out of 168 are not a baseline. ──────────────
  const outage = judgeAftermath(
    measurements({
      device: {
        ...measurements().device,
        // A week of rollup rows exists; exactly one of them carries an RTT.
        rttBucketsBefore: 1,
        rttBeforeUs: 1000,
        rttAfterUs: 40_000,
      },
    }),
  );
  const outageRtt = outage.signals.find((x) => x.metric === 'rtt');
  ok(
    'one reachable hour in a week is no baseline, not a x40 regression',
    outageRtt?.outcome === 'no_baseline',
    String(outageRtt?.outcome) + ' / ' + outage.verdict,
  );
  const thinAvail = judgeAftermath(
    measurements({
      device: {
        ...measurements().device,
        availBucketsBefore: 1,
        reachableBefore: 1,
        samplesBefore: 1,
        reachableAfter: 16_000,
        samplesAfter: 20_160,
      },
    }),
  );
  ok(
    'a single successful poll is not an availability baseline either',
    thinAvail.signals.find((x) => x.metric === 'availability')?.outcome === 'no_baseline',
  );

  // …and the same thing end to end, on rollup rows this database really holds.
  const changeAt10 = new Date(Math.floor((now.getTime() - 8 * DAY) / HOUR) * HOUR + 37 * MINUTE);
  const w10 = windowsFor(changeAt10, 7);
  const job10 = await succeededPush(s.d10, new Date(changeAt10.getTime() - MINUTE), changeAt10);
  // One hour of contact at 1 ms, then 167 hours of a WAN flat on its back:
  // `rtt_p95_us = -1` is exactly what `rollup.service.ts` writes for an hour
  // with no reachable sample.
  await seedDeviceHours(s.d10, w10.baselineFrom, 1, {
    rttUs: 1000, reachable: 120, samples: 120, uptimeTicks: 1_000_000,
  });
  await seedDeviceHours(s.d10, new Date(w10.baselineFrom.getTime() + HOUR), 167, {
    rttUs: -1, reachable: 0, samples: 120, uptimeTicks: 1_360_000,
  });
  // The link comes back on LTE: 40 ms, a perfectly ordinary LTE round trip.
  await seedDeviceHours(s.d10, w10.afterFrom, 168, {
    rttUs: 40_000, reachable: 120, samples: 120, uptimeTicks: 80_000_000,
  });
  const outageReport = await evaluateAftermath(TENANT, { jobId: job10 }, {
    horizonDays: 7,
    now,
  });
  const outageSignal = outageReport.signals.find((x) => x.metric === 'rtt');
  ok(
    'measured on real rollups: the outage week yields no_baseline, not DEGRADED',
    outageSignal?.outcome === 'no_baseline' && outageReport.verdict !== 'DEGRADED',
    String(outageSignal?.outcome) + ' / ' + outageReport.verdict,
  );

  // ── 5. The intervention window is no longer inside its own baseline. ─────
  const closed11 = new Date(Math.floor((now.getTime() - 8 * DAY) / HOUR) * HOUR);
  const opened11 = new Date(closed11.getTime() - 10 * HOUR);
  const wNew = windowsForInterval(opened11, closed11, 7);
  const wOld = windowsFor(closed11, 7);

  const { intervention: iv11 } = await openIntervention(
    TENANT,
    {
      deviceId: s.d11,
      operator: 'Nadia',
      reason: 'Dix heures de travail manuel, redemarrage a mi-parcours',
      windowMinutes: 600,
      openedBy: s.userId,
    },
    opened11,
  );
  await db('interventions').where('id', iv11.id)
    .update({ status: 'closed', closed_at: closed11, closed_by: s.userId });

  // A quiet week before the technician arrived.
  await seedDeviceHours(s.d11, wNew.baselineFrom, 168, {
    rttUs: 9000, reachable: 120, samples: 120, uptimeTicks: 1_000_000,
  });
  // The eleven hour-buckets of the window itself: he reboots the router at
  // hour five, DURING his own window.
  await seedDeviceHours(s.d11, wNew.baselineTo, 5, {
    rttUs: 9000, reachable: 120, samples: 120, uptimeTicks: 61_480_000,
  });
  await seedDeviceHours(s.d11, new Date(wNew.baselineTo.getTime() + 5 * HOUR), 6, {
    rttUs: 9000, reachable: 120, samples: 120, uptimeTicks: 100_000,
  });
  // Then the router restarts four times on its own during the week after. The
  // first chunk carries on from where the window left off — a drop is only
  // detectable against a PREVIOUS bucket, so the first hour of the observation
  // window can never be a restart.
  await seedDeviceHours(s.d11, wNew.afterFrom, 28, {
    rttUs: 9000, reachable: 120, samples: 120, uptimeTicks: 200_000_000,
  });
  for (let k = 0; k < 4; k += 1) {
    await seedDeviceHours(
      s.d11,
      new Date(wNew.afterFrom.getTime() + (28 + k * 35) * HOUR),
      35,
      { rttUs: 9000, reachable: 120, samples: 120, uptimeTicks: 200_000 + k * 100_000 },
    );
  }

  const twoPivots = await evaluateAftermath(TENANT, { interventionId: iv11.id }, {
    horizonDays: 7,
    now,
  });
  ok(
    'the baseline now STOPS where the human started, not where he stopped',
    new Date(twoPivots.windows.baselineTo).getTime() <= new Date(iv11.openedAt).getTime(),
    twoPivots.windows.baselineTo + ' vs opened ' + iv11.openedAt,
  );
  const reboots = twoPivots.signals.find((x) => x.metric === 'unexpected_reboots');
  ok(
    'the reboot the technician caused no longer counts as a PRE-EXISTING fault',
    reboots?.outcome === 'degraded' && reboots.before === 0 && reboots.after === 4,
    JSON.stringify(reboots),
  );
  ok('so the four restarts that followed are reported',
    twoPivots.verdict === 'DEGRADED', twoPivots.verdict);

  // The counterfactual, on the same rows and through the same pure judge: the
  // ONE-pivot window is what used to make this STABLE.
  const oldShape = judgeAftermath(await measure(TENANT, s.d11, wOld));
  const oldReboots = oldShape.signals.find((x) => x.metric === 'unexpected_reboots');
  ok(
    'and the one-pivot window it replaces would have called it preexisting',
    oldReboots?.outcome === 'preexisting' && oldShape.verdict !== 'DEGRADED',
    String(oldReboots?.outcome) + ' / ' + oldShape.verdict,
  );

  // ── 6. A premature evaluation neither persists nor excludes the change. ──
  const fresh12 = await succeededPush(
    s.d12,
    new Date(now.getTime() - 2 * HOUR),
    new Date(now.getTime() - HOUR),
  );
  const early = await evaluateAftermath(TENANT, { jobId: fresh12 }, { horizonDays: 7, now });
  ok('looking an hour after the change still ANSWERS', early.verdict.length > 0, early.verdict);
  ok('but the answer is not stored: its observation window is not over',
    early.id === null, String(early.id));
  const stored12 = await db('change_aftermath')
    .where({ tenant_id: TENANT, job_id: fresh12 })
    .first();
  ok('nothing was written to the §8.3 corpus', stored12 === undefined);

  // The second lock: a row written too early by an older build — or by anything
  // that is not `evaluateAftermath` — must be RECOMPUTED, not treated as an
  // answer that excludes the job from the sweep for ever.
  const changeAt12 = new Date(Math.floor((now.getTime() - 8 * DAY) / HOUR) * HOUR + 11 * MINUTE);
  const w12 = windowsFor(changeAt12, 7);
  const job12 = await succeededPush(s.d12, new Date(changeAt12.getTime() - MINUTE), changeAt12);
  await seedDeviceHours(s.d12, w12.baselineFrom, 168, {
    rttUs: 9000, reachable: 120, samples: 120, uptimeTicks: 1_000_000,
  });
  await seedDeviceHours(s.d12, w12.afterFrom, 168, {
    rttUs: 9100, reachable: 120, samples: 120, uptimeTicks: 90_000_000,
  });
  await db('change_aftermath').insert({
    tenant_id: TENANT,
    device_id: s.d12,
    job_id: job12,
    change_at: changeAt12,
    horizon_days: 7,
    baseline_from: w12.baselineFrom,
    baseline_to: w12.baselineTo,
    after_from: w12.afterFrom,
    after_to: w12.afterTo,
    verdict: 'INSUFFICIENT_DATA',
    measured_count: 0,
    // Written one hour after the change — seven days before its own window
    // closed. This is the shape the old `evaluateAftermath` produced and that
    // the anti-join then honoured for ever.
    evaluated_at: new Date(changeAt12.getTime() + HOUR),
  });

  const swept12 = await sweepAftermath(TENANT, { horizonDays: 7, now });
  const row12 = await db('change_aftermath')
    .where({ tenant_id: TENANT, job_id: job12, horizon_days: 7 })
    .first<{ verdict: string; measured_count: number; evaluated_at: Date; after_to: Date }>(
      'verdict', 'measured_count', 'evaluated_at', 'after_to',
    );
  ok(
    'a verdict written before its window closed is RECOMPUTED by the J+7 sweep',
    row12.verdict === 'STABLE' && Number(row12.measured_count) > 0,
    row12.verdict + ', ' + String(row12.measured_count) + ' measured, considered ' +
      String(swept12.considered),
  );
  ok('and the recomputation happened after the window it measures',
    row12.evaluated_at.getTime() >= row12.after_to.getTime());

  // …while a row that WAS written after its window closed still keeps the job
  // out of the sweep: the anti-join is fixed, not removed.
  const swept12b = await sweepAftermath(TENANT, { horizonDays: 7, now });
  ok('a complete evaluation is not redone on every tick',
    swept12b.considered === 0, JSON.stringify(swept12b));

  // ── 7. The link that changed hands and kept the wrong window. ────────────
  //
  // `intervention_drift_links` was upserted with `intervention_id` OUT of the
  // merge list while `overlap_seconds`, `window_span_seconds` and
  // `disposition` were IN it. Re-electing a different window therefore left
  // the row pointing at the OLD intervention while carrying the NEW one's two
  // numbers — the pair migration 020 calls "the two numbers that justify the
  // claim" — so `GET /interventions/:id/drift` showed, under one window, the
  // arithmetic measured against another.
  //
  // The election really does move: `effectiveEnd()` reads the row's status, a
  // window closed EARLY ends before its deadline, and the incumbent's overlap
  // therefore shrinks under a rival's between two passes.
  const b13 = await storeDoc(
    s.d13,
    siteDoc(spec(13), s.d13),
    new Date(now.getTime() - 4 * HOUR),
    new Date(now.getTime() - 3 * HOUR),
  );
  const a13 = await storeDoc(
    s.d13,
    siteDoc(spec(13, 2233), s.d13),
    new Date(now.getTime() - HOUR),
    new Date(now.getTime() - HOUR),
  );
  // K6's change window is [now-3h, now-1h]: 7200 seconds wide.

  // RIVAL: declared for the whole window, closed twenty minutes early.
  // Overlap 4800 s of 7200 — two thirds, comfortably over the coverage ratio.
  const { intervention: rival } = await openIntervention(
    TENANT,
    {
      deviceId: s.d13,
      operator: 'equipe-nuit',
      reason: 'Intervention de nuit, fermee vingt minutes en avance',
      windowMinutes: 120,
      openedBy: s.userId,
    },
    new Date(now.getTime() - 3 * HOUR),
  );
  await closeIntervention(
    TENANT,
    rival.id,
    { closedBy: s.userId, collect: false },
    new Date(now.getTime() - 100 * MINUTE),
  );

  // INCUMBENT: declared five minutes later and still open, so its effective
  // end is its deadline — two hours from now. Overlap 6900 s of 7200.
  const { intervention: incumbent } = await openIntervention(
    TENANT,
    {
      deviceId: s.d13,
      operator: 'equipe-jour',
      reason: 'Fenetre large encore ouverte au moment du premier balayage',
      windowMinutes: 295,
      openedBy: s.userId,
    },
    new Date(now.getTime() - 175 * MINUTE),
  );

  const run13 = await runDrift(TENANT, s.d13, {
    baselineSnapshotId: b13,
    snapshotId: a13,
    scope: 'full',
  });
  ok('a two-hour change window exists on the device', run13?.status === 'drifted');

  const first13 = await linkRunToIntervention(TENANT, String(run13?.id), now);
  ok(
    'the first pass elects the window that covers the change best',
    first13?.interventionId === incumbent.id && first13?.disposition === 'attributed',
    String(first13?.interventionId) + ' ' + String(first13?.overlapSeconds) + '/' +
      String(first13?.windowSpanSeconds) + 's',
  );

  // The incumbent is now closed EARLY: its effective end moves back to five
  // minutes after it opened, and its overlap collapses under the rival's.
  await closeIntervention(
    TENANT,
    incumbent.id,
    { closedBy: s.userId, collect: false },
    new Date(now.getTime() - 170 * MINUTE),
  );
  const second13 = await linkRunToIntervention(TENANT, String(run13?.id), now);

  ok(
    'the second pass re-elects the rival window',
    second13?.interventionId === rival.id,
    String(second13?.interventionId) + ' (was ' + String(incumbent.id) + ')',
  );
  const row13 = await db('intervention_drift_links')
    .where({ tenant_id: TENANT, drift_run_id: String(run13?.id) })
    .first<{
      intervention_id: string; overlap_seconds: number;
      window_span_seconds: number; prior_verdict: string | null;
    }>('intervention_id', 'overlap_seconds', 'window_span_seconds', 'prior_verdict');
  ok(
    'the STORED row moved with it — the pointer and its two numbers travel together',
    String(row13.intervention_id) === rival.id &&
      Number(row13.overlap_seconds) === second13?.overlapSeconds,
    String(row13.intervention_id) + ' ' + String(row13.overlap_seconds) + '/' +
      String(row13.window_span_seconds) + 's',
  );
  ok(
    '…and the numbers belong to the RIVAL window, not to the one it replaced',
    Number(row13.overlap_seconds) === 4800 && Number(row13.window_span_seconds) === 7200,
    String(row13.overlap_seconds) + '/' + String(row13.window_span_seconds) + 's',
  );
  const dead13 = await listLinks(TENANT, incumbent.id);
  ok('the window it left keeps no orphan link', dead13.length === 0, String(dead13.length));
  ok(
    'and the K6 verdict recorded the FIRST time is not re-read as its own effect',
    row13.prior_verdict === 'unattributed',
    String(row13.prior_verdict),
  );
}

// ============================================================================
// 7. What the database refuses, and what one tenant cannot see
// ============================================================================

async function testRefusals(s: Seeded): Promise<void> {
  console.log('\n── the constraints, and the tenant boundary ──');

  await refuses(
    'a window longer than the service ceiling is refused',
    () =>
      openIntervention(TENANT, {
        deviceId: s.d1,
        operator: 'X',
        reason: 'trop long',
        windowMinutes: 60 * 24 * 5,
        openedBy: s.userId,
      }),
    'must be between',
  );

  await refuses(
    'the DATABASE refuses a window beyond the hard cap, service or no service',
    () =>
      db('interventions').insert({
        tenant_id: TENANT,
        device_id: s.d1,
        status: 'open',
        channel: 'ssh',
        operator: 'raw insert',
        reason: 'bypassing the service layer',
        opened_at: new Date(),
        expires_at: new Date(Date.now() + (INTERVENTION_HARD_CAP_MINUTES + 60) * MINUTE),
      }),
    'interventions_window_chk',
  );

  await refuses(
    'a blank reason is refused',
    () =>
      db('interventions').insert({
        tenant_id: TENANT,
        device_id: s.d1,
        status: 'open',
        channel: 'ssh',
        operator: 'nobody',
        reason: '   ',
        opened_at: new Date(),
        expires_at: new Date(Date.now() + HOUR),
      }),
    'interventions_reason_chk',
  );

  await refuses(
    'a closed window with no closed_at is unrepresentable',
    () =>
      db('interventions').insert({
        tenant_id: TENANT,
        device_id: s.d1,
        status: 'closed',
        channel: 'ssh',
        operator: 'nobody',
        reason: 'inconsistent',
        opened_at: new Date(),
        expires_at: new Date(Date.now() + HOUR),
      }),
    'interventions_terminal_chk',
  );

  await refuses(
    'an intervention on another tenant\'s device is refused by the composite FK',
    () =>
      db('interventions').insert({
        tenant_id: TENANT,
        device_id: s.d6, // belongs to OTHER_TENANT
        status: 'open',
        channel: 'ssh',
        operator: 'crosser',
        reason: 'cross-tenant',
        opened_at: new Date(),
        expires_at: new Date(Date.now() + HOUR),
      }),
    'interventions_device_tenant_fk',
  );

  const anyIv = await db('interventions').where('tenant_id', TENANT).first<{ id: string }>('id');
  await refuses(
    'a credential-shaped key in the lifecycle log is refused by the database',
    () =>
      db('intervention_events').insert({
        tenant_id: TENANT,
        intervention_id: anyIv.id,
        event: 'opened',
        detail: JSON.stringify({ apiToken: 'hunter2' }),
      }),
    'intervention_events_detail_chk',
  );
  // …while ordinary prose that merely mentions the word is fine: the CHECK
  // tests KEYS, not values.
  let prosePassed = true;
  try {
    await db('intervention_events').insert({
      tenant_id: TENANT,
      intervention_id: anyIv.id,
      event: 'opened',
      detail: JSON.stringify({ note: 'the customer forgot his password' }),
    });
  } catch {
    prosePassed = false;
  }
  ok('a value mentioning a secret word is still allowed', prosePassed);

  await refuses(
    'an aftermath row whose observation precedes the change is unrepresentable',
    () =>
      db('change_aftermath').insert({
        tenant_id: TENANT,
        device_id: s.d4,
        job_id: null,
        intervention_id: null,
        change_at: new Date(),
        horizon_days: 7,
        baseline_from: new Date(Date.now() - DAY),
        baseline_to: new Date(),
        after_from: new Date(Date.now() - 2 * DAY),
        after_to: new Date(),
        verdict: 'STABLE',
      }),
    'change_aftermath',
  );

  await refuses(
    'an aftermath row with no anchor at all is unrepresentable',
    () =>
      db('change_aftermath').insert({
        tenant_id: TENANT,
        device_id: s.d4,
        change_at: new Date(),
        horizon_days: 7,
        baseline_from: new Date(Date.now() - 8 * DAY),
        baseline_to: new Date(Date.now() - DAY),
        after_from: new Date(),
        after_to: new Date(Date.now() + DAY),
        verdict: 'STABLE',
      }),
    'change_aftermath_anchor_chk',
  );

  // ── the tenant boundary ──────────────────────────────────────────────────
  const otherSees = await listInterventions(OTHER_TENANT, {});
  ok('the other tenant sees none of these windows', otherSees.length === 0,
    `${otherSees.length} rows`);
  const otherAftermath = await listAftermath(OTHER_TENANT, {});
  ok('nor any of these aftermath reports', otherAftermath.length === 0);
  const stolen = await getIntervention(OTHER_TENANT, anyIv.id);
  ok('a cross-tenant id reads as absent', stolen === null);
  const live = await liveInterventionFor(OTHER_TENANT, s.d1);
  ok('and no live window leaks across the boundary', live === null);

  ok(
    'the attribution ceiling is three times the hard cap, as documented',
    INTERVENTION_MAX_ATTRIBUTION_WINDOW_MINUTES === 3 * INTERVENTION_HARD_CAP_MINUTES,
  );
  ok('the default horizon is the week §10/F4 asks for', AFTERMATH_TUNING.horizonDaysDefault === 7);
}

// ============================================================================
// Main
// ============================================================================

async function main(): Promise<void> {
  console.log('ObliWAN — F3 (intervention mode) + F4 (change → telemetry, J+7)');
  console.log('No equipment was contacted. Every document and every counter below was written');
  console.log('by this file; what is proven is the arithmetic and the schema, nothing else.\n');

  testPure();

  await reset();
  const s = await seed();
  await testAttribution(s);
  await testExpiry(s);
  await testPrecedence(s);
  await testAftermath(s);
  await testAuditFindings(s);
  await testRefusals(s);

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  - ${f}`);
  }
  await db.destroy();
  process.exit(failed === 0 ? 0 : 1);
}

void main().catch(async (err) => {
  console.error(err);
  await db.destroy();
  process.exit(1);
});
