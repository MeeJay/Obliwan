/* eslint-disable no-console */
// ============================================================================
// F1 + F2 acceptance — run against a REAL Postgres, never a mock
// ============================================================================
//
//   DATABASE_URL=postgres://obliwan:t@host:port/obliwan \
//     npx tsx src/services/attestation/testing/f1f2-evidence.verify.ts
//
// ┌─ WHAT IS BEING ASSERTED, AND WHY EACH ONE IS HERE ────────────────────────┐
// │ F1-a  An exception with no justification is REFUSED BY THE DATABASE.      │
// │       Asserted against raw INSERTs that bypass every Zod schema, because  │
// │       the claim is about the constraint and not about the API.            │
// │ F1-b  A finding cannot be ignored with no reason at all — the old         │
// │       unjustified manual ignore is dead at the storage layer.             │
// │ F1-c  An EXPIRED exception makes its finding VISIBLE AGAIN, and the run's │
// │       `max_severity` comes back with it.                                  │
// │ F1-d  Renewal re-hides it; revocation gives it back; the history keeps    │
// │       every decision and its author.                                      │
// │ F2-a  An attestation over a device with 3 snapshots and 2 changes is      │
// │       assembled, and its chain is re-verified by a SCRIPT THAT SHARES NO  │
// │       CODE WITH THE PRODUCER (`independent-verifier.cjs`).                │
// │ F2-b  Tampering with one byte of the document is CAUGHT by that script.   │
// │ F2-c  The dedup trap: a device that goes A -> B -> A must NOT be attested │
// │       as continuously A. This is the assertion the whole design of        │
// │       `evidence.ts` exists for.                                           │
// └───────────────────────────────────────────────────────────────────────────┘

import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { db } from '../../../db';
import * as exc from '../../drift/exception.service';
import * as att from '../attestation.service';
import { appendAudit } from '../auditLog.service';
import { evidenceField } from '../contract';

let passed = 0;
let failed = 0;

function ok(label: string, cond: boolean, detail?: unknown): void {
  if (cond) {
    passed += 1;
    console.log(`  PASS  ${label}`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${label}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`);
  }
}

function eq(label: string, actual: unknown, expected: unknown): void {
  ok(label, JSON.stringify(actual) === JSON.stringify(expected), { actual, expected });
}

async function refused(label: string, fn: () => Promise<unknown>, code?: string): Promise<void> {
  try {
    await fn();
    ok(label, false, 'the statement was ACCEPTED');
  } catch (err) {
    const e = err as { code?: string; constraint?: string };
    ok(
      `${label} [${e.code}${e.constraint ? ` ${e.constraint}` : ''}]`,
      code === undefined || e.code === code,
      { code: e.code, constraint: e.constraint },
    );
  }
}

const HEX = (n: number): string => n.toString(16).padStart(2, '0').repeat(32);
const DAY = 86_400_000;

async function main(): Promise<void> {
  const t0 = Date.now();

  // ── fixture ────────────────────────────────────────────────────────────
  //
  // Its OWN tenants, never tenant 1. Two reasons, and neither is tidiness:
  //  - the teardown is then a single `DELETE FROM tenants`, which exercises
  //    every ON DELETE CASCADE this migration added — including the escape
  //    hatches in the append-only triggers, which is where a broken one would
  //    show up as "a customer can no longer be offboarded";
  //  - a leftover fixture from a crashed run cannot collide with the next one.
  await db('tenants').whereLike('slug', 'evidence-%').del();
  await db('users').whereLike('username', 'evidence-tester-%').del();

  const stamp = Date.now();
  const [tenant] = await db('tenants')
    .insert({ name: `Evidence ${stamp}`, slug: `evidence-${stamp}` })
    .returning<{ id: number }[]>('id');
  const tenantId = tenant.id;

  const username = `evidence-tester-${stamp}`;
  const [user] = await db('users')
    .insert({ username, role: 'admin' })
    .returning<{ id: number }[]>('id');
  const actor: exc.Actor = { userId: user.id, username };

  const [device] = await db('devices')
    .insert({
      tenant_id: tenantId,
      name: 'CPE-EVIDENCE-01',
      brand: 'mikrotik',
      family: 'mikrotik_routeros7',
      model: 'RB2011',
      serial: 'SN-EVID-01',
      role: 'cpe',
      status: 'active',
      is_managed: true,
    })
    .returning<{ id: number; uuid: string }[]>(['id', 'uuid']);

  // Another tenant + device, to prove the scoping is not decorative.
  const [otherTenant] = await db('tenants')
    .insert({ name: 'Other', slug: `evidence-other-${stamp}` })
    .returning<{ id: number }[]>('id');
  const [otherDevice] = await db('devices')
    .insert({
      tenant_id: otherTenant.id, name: 'FOREIGN-01', brand: 'mikrotik', family: 'mikrotik_routeros7',
    })
    .returning<{ id: number }[]>('id');

  const now = Date.now();
  const epoch = '0123456789abcdef';

  // Three snapshots, and the third is a RETURN to the first configuration —
  // the A -> B -> A shape that makes `captured_at .. last_seen_at` a lie.
  const hashA = HEX(0xaa);
  const hashB = HEX(0xbb);
  const [snapA] = await db('config_snapshots').insert({
    device_id: device.id, source: 'ssh', ncm: JSON.stringify({ v: 'A' }),
    ncm_hash: hashA, ncm_version: 1, normalization_epoch: epoch,
    raw_sha256: HEX(0x11), raw_bytes: 4096,
    captured_at: new Date(now - 90 * DAY), last_seen_at: new Date(now - 20 * DAY), seen_count: 40,
  }).returning<{ id: string }[]>('id');
  const [snapB] = await db('config_snapshots').insert({
    device_id: device.id, source: 'ssh', ncm: JSON.stringify({ v: 'B' }),
    ncm_hash: hashB, ncm_version: 1, normalization_epoch: epoch,
    raw_sha256: HEX(0x22), raw_bytes: 4100,
    captured_at: new Date(now - 60 * DAY), last_seen_at: new Date(now - 55 * DAY), seen_count: 5,
  }).returning<{ id: string }[]>('id');
  const hashC = HEX(0xcc);
  const [snapC] = await db('config_snapshots').insert({
    device_id: device.id, source: 'ssh', ncm: JSON.stringify({ v: 'C' }),
    ncm_hash: hashC, ncm_version: 1, normalization_epoch: epoch,
    raw_sha256: HEX(0x33), raw_bytes: 4200,
    captured_at: new Date(now - 10 * DAY), last_seen_at: new Date(now - 1 * DAY), seen_count: 9,
  }).returning<{ id: string }[]>('id');

  // Drift runs: independent dated observations of which snapshot was live.
  const [runOld] = await db('drift_runs').insert({
    device_id: device.id, snapshot_id: snapA.id, status: 'in_sync', cause: 'scheduled',
    started_at: new Date(now - 80 * DAY), finished_at: new Date(now - 80 * DAY),
  }).returning<{ id: string }[]>('id');
  await db('drift_runs').insert({
    device_id: device.id, snapshot_id: snapB.id, status: 'drifted', cause: 'scheduled',
    started_at: new Date(now - 58 * DAY), finished_at: new Date(now - 58 * DAY),
  });
  const [runNow] = await db('drift_runs').insert({
    device_id: device.id, snapshot_id: snapC.id, status: 'drifted', cause: 'scheduled',
    started_at: new Date(now - 2 * DAY), finished_at: new Date(now - 2 * DAY),
  }).returning<{ id: string }[]>('id');
  void runOld;

  // Two changes, one clean and one overridden. A `push` that reached
  // `succeeded` is a heavily constrained row in migration 009 — it needs its
  // frozen plan, its pre-flight backup and its lease — and building it properly
  // rather than reaching for a `kind` with fewer constraints is the point: the
  // attestation is supposed to describe REAL changes.
  const plan = async (hash: string, at: Date): Promise<string> => {
    const [p] = await db('change_plans').insert({
      tenant_id: tenantId, device_id: device.id, source: 'template',
      base_state_hash: hash, safety_level: 'armed', risk_level: 'low',
      mgmt_path_verdict: 'accept', order_converges: true,
      expires_at: new Date(at.getTime() + DAY), created_by: user.id,
      created_at: at, updated_at: at,
    }).returning<{ id: string }[]>('id');
    return p.id;
  };
  const backup = async (at: Date, seed: number): Promise<string> => {
    const [b] = await db('device_backups').insert({
      tenant_id: tenantId, device_id: device.id, kind: 'rsc', trigger_kind: 'preflight',
      storage_path: `/backups/${seed}.rsc`, sha256: HEX(seed), size_bytes: 2048,
      created_at: at,
    }).returning<{ id: string }[]>('id');
    return b.id;
  };

  const at1 = new Date(now - 61 * DAY);
  const at2 = new Date(now - 11 * DAY);
  const [job1] = await db('change_jobs').insert({
    tenant_id: tenantId, device_id: device.id, kind: 'push', status: 'succeeded',
    plan_id: await plan(hashA, at1), preflight_backup_id: await backup(at1, 0x41),
    base_state_hash: hashA, safety_level: 'armed', guard_verdict: 'ACCEPT',
    outcome: 'succeeded', requested_by: user.id, approved_by: user.id,
    claimed_by: 'test:0:0', claimed_at: at1,
    started_at: at1, finished_at: at1, created_at: at1, updated_at: at1,
  }).returning<{ id: string }[]>('id');
  const [job2] = await db('change_jobs').insert({
    tenant_id: tenantId, device_id: device.id, kind: 'push', status: 'succeeded',
    plan_id: await plan(hashB, at2), preflight_backup_id: await backup(at2, 0x42),
    base_state_hash: hashB, safety_level: 'armed', guard_verdict: 'REJECT',
    override_reason: 'ERP cutover window agreed with the customer',
    overridden_by: user.id, overridden_at: at2,
    outcome: 'succeeded', requested_by: user.id, approved_by: user.id,
    claimed_by: 'test:0:0', claimed_at: at2,
    started_at: at2, finished_at: at2, created_at: at2, updated_at: at2,
  }).returning<{ id: string }[]>('id');

  await db('apply_outcomes').insert([
    {
      tenant_id: tenantId, device_id: device.id, job_id: job1.id, op_kind: 'push',
      brand: 'mikrotik', outcome: 'succeeded', safety_level: 'armed', ops_count: 3,
      observed_at: new Date(now - 61 * DAY),
    },
    {
      tenant_id: tenantId, device_id: device.id, job_id: job2.id, op_kind: 'push',
      brand: 'mikrotik', outcome: 'succeeded', safety_level: 'armed', ops_count: 1,
      observed_at: new Date(now - 11 * DAY),
    },
  ]);

  await db('command_audit').insert([
    {
      tenant_id: tenantId, device_id: device.id, job_id: job1.id, transport: 'ssh',
      command: '/ip/firewall/nat/add comment=obliwan', is_write: true, success: true,
      executed_at: new Date(now - 61 * DAY),
    },
    {
      tenant_id: tenantId, device_id: device.id, transport: 'ssh',
      command: '/export show-sensitive=no', is_write: false, success: true,
      executed_at: new Date(now - 10 * DAY),
    },
  ]);

  // The finding F1 will forgive.
  const [finding] = await db('drift_findings').insert({
    run_id: runNow.id,
    path: 'natRule/nat:srcnat:erp-legacy/dstPort',
    sem_key: 'nat:srcnat:erp-legacy',
    resource: 'natRule',
    kind: 'changed',
    severity: 'critical',
    match_method: 'marker',
    match_confidence: 1,
    field_diffs: JSON.stringify([{ field: 'dstPort', from: '80', to: '8080' }]),
  }).returning<{ id: string }[]>('id');

  console.log('\n── F1-a  an exception with no justification cannot exist ──────────────');

  const validDue = new Date(now + 30 * DAY);
  const base = {
    tenant_id: tenantId, device_id: device.id, sem_key: 'nat:srcnat:erp-legacy',
    resource: 'natRule', review_due_at: validDue, created_by_username: 'raw',
  };
  await refused(
    'INSERT with an empty justification',
    () => db('drift_exceptions').insert({ ...base, justification: '' }),
    '23514',
  );
  await refused(
    'INSERT with a short justification ("known")',
    () => db('drift_exceptions').insert({ ...base, justification: 'known' }),
    '23514',
  );
  await refused(
    'INSERT with 200 spaces (btrim is why length() alone is not enough)',
    () => db('drift_exceptions').insert({ ...base, justification: ' '.repeat(200) }),
    '23514',
  );
  await refused(
    'INSERT with a review date in the past',
    () => db('drift_exceptions').insert({
      ...base,
      justification: 'NAT rule kept for the legacy ERP at site 12.',
      review_due_at: new Date(now - DAY),
    }),
    '23514',
  );
  await refused(
    'INSERT with a review date ten years out',
    () => db('drift_exceptions').insert({
      ...base,
      justification: 'NAT rule kept for the legacy ERP at site 12.',
      review_due_at: new Date(now + 3650 * DAY),
    }),
    '23514',
  );
  await refused(
    'INSERT naming a device that belongs to another tenant',
    () => db('drift_exceptions').insert({
      ...base,
      device_id: otherDevice.id,
      justification: 'NAT rule kept for the legacy ERP at site 12.',
    }),
  );

  console.log('\n── F1-b  a finding cannot be ignored with no reason ───────────────────');

  await refused(
    'the old unjustified manual ignore (ignored=true, no rule, no exception)',
    () => db('drift_findings').where({ id: finding.id }).update({ ignored: true }),
    '23514',
  );

  console.log('\n── F1-c  an expired exception makes the drift VISIBLE AGAIN ───────────');

  const created = await exc.createException(tenantId, actor, {
    findingId: finding.id,
    justification: 'This NAT rule exists for the customer legacy ERP; agreed with them on '
      + 'ticket OW-4821 and reviewed at the next contract renewal.',
    reviewDueAt: validDue.toISOString(),
  });
  eq('the exception is active', created.state, 'active');
  eq('it names its author', created.createdByUsername, username);
  eq('it is keyed on the semantic key', created.semKey, 'nat:srcnat:erp-legacy');
  eq('it pinned the FIELD, not the whole resource', created.path,
    'natRule/nat:srcnat:erp-legacy/dstPort');
  eq('it recorded the severity that was accepted', created.severityAtCreation, 'critical');
  eq('one finding is suppressed', created.suppressedFindings, 1);

  let f = await db('drift_findings').where({ id: finding.id }).first<{
    ignored: boolean; ignored_by_exception: string | null;
  }>();
  eq('the finding is now ignored', f.ignored, true);
  eq('and it names the exception that hides it', String(f.ignored_by_exception), created.id);
  let run = await db('drift_runs').where({ id: runNow.id })
    .first<{ max_severity: string | null; status: string; ignored_count: number }>();
  eq('the run no longer keeps the device red', run.max_severity, null);
  eq('and reports itself in sync', run.status, 'in_sync');

  // A NEW drift run, as tomorrow's sweep would produce: the exception must
  // survive it. This is decision 4 of migration 019, asserted.
  const [runTomorrow] = await db('drift_runs').insert({
    device_id: device.id, snapshot_id: snapC.id, status: 'drifted', cause: 'scheduled',
    started_at: new Date(now + 60_000), finished_at: new Date(now + 60_000),
  }).returning<{ id: string }[]>('id');
  const [freshFinding] = await db('drift_findings').insert({
    run_id: runTomorrow.id,
    path: 'natRule/nat:srcnat:erp-legacy/dstPort',
    sem_key: 'nat:srcnat:erp-legacy',
    resource: 'natRule', kind: 'changed', severity: 'critical',
    match_method: 'marker', match_confidence: 1,
  }).returning<{ id: string }[]>('id');
  await exc.sweep();
  f = await db('drift_findings').where({ id: freshFinding.id }).first();
  eq('a finding created by a LATER run is suppressed too', f.ignored, true);

  // Simulate the passage of two months. BOTH dates move, because
  // `drift_exceptions_horizon_chk` refuses `review_due_at <= created_at` — an
  // exception cannot be born expired, and it cannot be pushed into expiry by
  // dragging its review date behind its own creation either. Ageing the whole
  // row is the only legal way to reach the state, and that is the constraint
  // doing its job on the test itself.
  await db('drift_exceptions').where({ id: created.id }).update({
    created_at: new Date(now - 60 * DAY),
    review_due_at: new Date(now - DAY),
  });
  const swept = await exc.sweep();
  ok('the sweep gave findings back', swept.revived >= 2, swept);

  f = await db('drift_findings').where({ id: finding.id }).first();
  eq('THE EXPIRED EXCEPTION NO LONGER HIDES THE FINDING', f.ignored, false);
  eq('and the link is cleared', f.ignored_by_exception, null);
  run = await db('drift_runs').where({ id: runNow.id }).first();
  eq('the run is red again', run.max_severity, 'critical');
  eq('and drifted again', run.status, 'drifted');

  const expired = await exc.getException(tenantId, created.id);
  eq('the exception reports itself expired', expired!.state, 'expired');
  eq('and says so as a boolean the UI can use', expired!.visibleAgain, true);
  eq('nothing is suppressed by it any more', expired!.suppressedFindings, 0);

  console.log('\n── F1-d  reconduction and revocation ─────────────────────────────────');

  const renewed = await exc.renewException(tenantId, created.id, actor, {
    justification: 'Still required: the ERP migration slipped to Q3, confirmed by the customer '
      + 'on ticket OW-5102.',
    reviewDueAt: new Date(now + 120 * DAY).toISOString(),
  });
  eq('the renewal reactivates it', renewed.state, 'active');
  eq('and counts', renewed.renewalCount, 1);
  eq('and it hides the findings again', renewed.suppressedFindings, 2);
  f = await db('drift_findings').where({ id: finding.id }).first();
  eq('the finding is hidden once more', f.ignored, true);

  await refused(
    'a renewal that does not move the date forward',
    () => exc.renewException(tenantId, created.id, actor, {
      justification: 'Still required: the ERP migration slipped to Q3, confirmed by the '
        + 'customer.',
      reviewDueAt: new Date(now + 10 * DAY).toISOString(),
    }),
  );
  await refused(
    'a renewal with a two-word justification',
    () => exc.renewException(tenantId, created.id, actor, {
      justification: 'still needed',
      reviewDueAt: new Date(now + 200 * DAY).toISOString(),
    }),
  );

  const revoked = await exc.revokeException(
    tenantId, created.id, actor,
    'The ERP was migrated on 2026-08-15 and the rule was removed from the template.',
  );
  eq('revocation is a state, not a delete', revoked.state, 'revoked');
  f = await db('drift_findings').where({ id: finding.id }).first();
  eq('and the drift is visible again immediately', f.ignored, false);

  const withHistory = await exc.getException(tenantId, created.id);
  eq('the history kept every decision',
    withHistory!.reviews!.map((r) => r.decision), ['created', 'renewed', 'revoked']);
  ok('every decision names its author',
    withHistory!.reviews!.every((r) => r.reviewedByUsername === username));

  await refused(
    'a review row cannot be rewritten',
    () => db('drift_exception_reviews')
      .where({ exception_id: created.id })
      .update({ justification: 'a completely different reason, forged later' }),
  );
  await refused(
    'a review row cannot be deleted',
    () => db('drift_exception_reviews').where({ exception_id: created.id }).del(),
  );

  const foreign = await exc.getException(otherTenant.id, created.id);
  eq('another tenant cannot read this exception', foreign, null);

  // ==========================================================================
  // F1-e / F1-f / F1-g run on their OWN device, so that the F2 sections keep
  // attesting the three-snapshot, two-change device they were written for.
  // ==========================================================================
  const [dev2] = await db('devices')
    .insert({
      tenant_id: tenantId, name: 'CPE-EVIDENCE-02', brand: 'mikrotik',
      family: 'mikrotik_routeros7', role: 'cpe', status: 'active', is_managed: true,
    })
    .returning<{ id: number }[]>(['id']);
  const [snapD] = await db('config_snapshots').insert({
    device_id: dev2.id, source: 'ssh', ncm: JSON.stringify({ v: 'D' }),
    ncm_hash: HEX(0xdd), ncm_version: 1, normalization_epoch: epoch,
    captured_at: new Date(now - 5 * DAY), last_seen_at: new Date(now - 5 * DAY), seen_count: 1,
  }).returning<{ id: string }[]>('id');

  const mkRun = async (at: Date, sev: string | null): Promise<string> => {
    const [r] = await db('drift_runs').insert({
      device_id: dev2.id, snapshot_id: snapD.id, status: 'drifted', cause: 'scheduled',
      max_severity: sev, started_at: at, finished_at: at,
    }).returning<{ id: string }[]>('id');
    return r.id;
  };
  const mkFinding = async (
    runId: string,
    f: { semKey: string; kind: string; severity: string; resource: string; path?: string },
  ): Promise<string> => {
    const [x] = await db('drift_findings').insert({
      run_id: runId,
      path: f.path ?? `${f.kind}/${f.semKey}`,
      sem_key: f.semKey,
      resource: f.resource,
      kind: f.kind,
      severity: f.severity,
      match_method: f.kind === 'missing' || f.kind === 'extra' ? 'none' : 'marker',
      match_confidence: 1,
    }).returning<{ id: string }[]>('id');
    return x.id;
  };

  console.log('\n── F1-e  an exception forgives a SEVERITY, not a name ─────────────────');

  // ┌─ THE SCENARIO ────────────────────────────────────────────────────────┐
  // │ `orderedRuleKey` is built from a rule's MATCH criteria, not from its   │
  // │ action, so ONE sem_key survives the rule changing what it does. A NAT  │
  // │ rule drifts on a cosmetic detail (`low`); the operator forgives it for │
  // │ 300 days. The next day the same rule — same sem_key — starts           │
  // │ redirecting traffic to a third-party host and the engine emits a       │
  // │ `critical`. `severity_at_creation` says `low`. If nothing compares the │
  // │ two, the critical inherits the pardon and the box stays green for the  │
  // │ rest of the horizon.                                                   │
  // └───────────────────────────────────────────────────────────────────────┘
  const natKey = 'nat:srcnat:erp-cosmetic';
  const runLow = await mkRun(new Date(now - 5 * DAY), 'low');
  const lowFinding = await mkFinding(runLow, {
    semKey: natKey, kind: 'changed', severity: 'low', resource: 'natRule',
  });

  const lenient = await exc.createException(tenantId, actor, {
    findingId: lowFinding,
    justification: 'Cosmetic comment drift on the legacy ERP NAT rule, agreed with the '
      + 'customer on ticket OW-6001.',
    reviewDueAt: new Date(now + 300 * DAY).toISOString(),
  });
  eq('the exception records the severity it accepted', lenient.severityAtCreation, 'low');
  let x = await db('drift_findings').where({ id: lowFinding }).first<{
    ignored: boolean; ignored_by_rule: number | null; ignored_by_exception: string | null;
  }>();
  eq('the low finding it was granted for is suppressed', x.ignored, true);
  let r2 = await db('drift_runs').where({ id: runLow })
    .first<{ max_severity: string | null; status: string }>();
  eq('and that run stops keeping the device red', r2.max_severity, null);

  // Tomorrow: SAME device, SAME sem_key, severity `critical`.
  const runCrit = await mkRun(new Date(now - 4 * DAY), 'critical');
  const critFinding = await mkFinding(runCrit, {
    semKey: natKey, kind: 'changed', severity: 'critical', resource: 'natRule',
  });
  await exc.sweep();
  x = await db('drift_findings').where({ id: critFinding }).first();
  eq('A `critical` UNDER THE SAME KEY IS NOT HIDDEN BY A `low` EXCEPTION', x.ignored, false);
  r2 = await db('drift_runs').where({ id: runCrit }).first();
  eq('the run stays red', r2.max_severity, 'critical');
  eq('and reports drift', r2.status, 'drifted');

  // …and the decision still covers everything MILDER than what it accepted.
  const runInfo = await mkRun(new Date(now - 3 * DAY), 'info');
  const infoFinding = await mkFinding(runInfo, {
    semKey: natKey, kind: 'changed', severity: 'info', resource: 'natRule',
  });
  await exc.sweep();
  x = await db('drift_findings').where({ id: infoFinding }).first();
  eq('a MILDER finding under the same key is still forgiven', x.ignored, true);

  // A finding that grows graver WHILE ALREADY HIDDEN must be handed back: the
  // guard has to live in the revive half too, or it would only ever apply to
  // rows the sweep had not touched yet.
  await db('drift_findings').where({ id: lowFinding }).update({ severity: 'high' });
  await exc.sweep();
  x = await db('drift_findings').where({ id: lowFinding }).first();
  eq('a finding that got worse WHILE HIDDEN comes back', x.ignored, false);
  r2 = await db('drift_runs').where({ id: runLow }).first();
  eq('and its run is red again', r2.max_severity, 'high');

  console.log('\n── F1-f  the scope is the RESOURCE; a sem_key may contain a slash ─────');

  // `routeKey` produces `route.v1:main:0.0.0.0/0:10.255.0.1` (keys.ts), so the
  // finding path `changed/route.v1:main:0.0.0.0/0:10.255.0.1` has FOUR
  // segments. The old test — `path.split('/').length > 2` — read that as "this
  // exception is scoped to one field" and pinned it, and the pin included the
  // DIFF KIND: the day the same route came back as `missing`, the exception
  // stopped matching and the operator re-justified it again.
  const routeKey = 'route.v1:main:0.0.0.0/0:10.255.0.1';
  ok('the finding path really does contain extra slashes',
    `changed/${routeKey}`.split('/').length > 2);

  const runRoute = await mkRun(new Date(now - 3 * DAY), 'high');
  const routeChanged = await mkFinding(runRoute, {
    semKey: routeKey, kind: 'changed', severity: 'high', resource: 'route',
  });
  const routeExc = await exc.createException(tenantId, actor, {
    findingId: routeChanged,
    justification: 'Default route points at the backup uplink for the duration of the MPLS '
      + 'migration, ticket OW-6102.',
    reviewDueAt: new Date(now + 60 * DAY).toISOString(),
  });
  eq('A SLASH INSIDE THE SEM KEY IS NOT A FIELD SCOPE', routeExc.path, null);
  x = await db('drift_findings').where({ id: routeChanged }).first();
  eq('the route finding is suppressed', x.ignored, true);

  // The same route, next run, as a DIFFERENT diff kind.
  const runRoute2 = await mkRun(new Date(now - 2 * DAY), 'high');
  const routeMissing = await mkFinding(runRoute2, {
    semKey: routeKey, kind: 'missing', severity: 'high', resource: 'route',
  });
  await exc.sweep();
  x = await db('drift_findings').where({ id: routeMissing }).first();
  eq('the same route reappearing as `missing` is STILL forgiven — no re-justification',
    x.ignored, true);

  // A genuinely field-scoped path is still pinned, and F1-c already asserted
  // that on `natRule/nat:srcnat:erp-legacy/dstPort`. Re-asserted here against
  // the canonical form the engine would emit if it ever passed a third
  // argument to `findingPath`.
  const runField = await mkRun(new Date(now - 2 * DAY), 'medium');
  const fieldFinding = await mkFinding(runField, {
    semKey: 'dhcp:v1:lan-scope', kind: 'changed', severity: 'medium', resource: 'dhcpScope',
    path: 'changed/dhcp:v1:lan-scope/leaseTime',
  });
  const fieldExc = await exc.createException(tenantId, actor, {
    findingId: fieldFinding,
    justification: 'Lease time widened for the seasonal site, reviewed at the end of the '
      + 'season, ticket OW-6210.',
    reviewDueAt: new Date(now + 60 * DAY).toISOString(),
  });
  eq('a REAL field path is still pinned to that field',
    fieldExc.path, 'changed/dhcp:v1:lan-scope/leaseTime');

  console.log('\n── F1-g  ignored_by_rule: one tenant\'s rule, and a deletable one ─────');

  const mkRule = async (tid: number | null, order: number): Promise<number> => {
    const [rule] = await db('normalization_rules').insert({
      tenant_id: tid, scope: 'global', name: `evidence-rule-${order}`,
      description: 'Test rule for the F1 storage guard.',
      rationale: 'Uptime is not configuration.',
      false_negative: 'A genuine uptime-shaped property would be hidden.',
      layer: 2, kind: 'ignore_prop', prop: 'uptime',
      apply_order: order, enabled: true, requires_test: false,
    }).returning<{ id: number }[]>('id');
    return rule.id;
  };

  const ownRule = await mkRule(tenantId, 9101);
  const libraryRule = await mkRule(null, 9102);
  const foreignRule = await mkRule(otherTenant.id, 9103);

  const runRule = await mkRun(new Date(now - DAY), 'critical');
  const ruleFinding = await mkFinding(runRule, {
    semKey: 'nat:srcnat:rule-silenced', kind: 'changed', severity: 'critical',
    resource: 'natRule',
  });

  // THE EXPLOIT: a critical of THIS tenant, silenced by ANOTHER tenant's rule.
  await refused(
    'silencing a finding with ANOTHER TENANT\'S normalization rule',
    () => db('drift_findings').where({ id: ruleFinding })
      .update({ ignored: true, ignored_by_rule: foreignRule }),
  );
  x = await db('drift_findings').where({ id: ruleFinding }).first();
  eq('and the critical is still visible', x.ignored, false);

  // The two legal values: the tenant's own rule, and a shipped library rule.
  await db('drift_findings').where({ id: ruleFinding })
    .update({ ignored: true, ignored_by_rule: libraryRule });
  x = await db('drift_findings').where({ id: ruleFinding }).first();
  eq('a SHIPPED LIBRARY rule (tenant_id IS NULL) may silence it', x.ignored, true);
  await db('drift_findings').where({ id: ruleFinding })
    .update({ ignored: true, ignored_by_rule: ownRule });
  x = await db('drift_findings').where({ id: ruleFinding }).first();
  eq('and so may the tenant\'s own rule', x.ignored, true);

  // ── Deleting the rule must WORK, and must un-hide the finding ───────────
  let ruleDeleted = true;
  let ruleErr: unknown = null;
  try {
    await db('normalization_rules').where({ id: ownRule }).del();
  } catch (err) {
    ruleDeleted = false;
    ruleErr = err;
  }
  ok('DELETING A NORMALIZATION RULE SUCCEEDS', ruleDeleted, ruleErr);
  x = await db('drift_findings').where({ id: ruleFinding }).first();
  eq('and the finding it was silencing comes back', x.ignored, false);
  eq('with no dangling reason', x.ignored_by_rule, null);

  // The same shape when the exception is the OTHER reason: losing the rule
  // must not un-hide a finding an exception still forgives.
  const runBoth = await mkRun(new Date(now - DAY), 'high');
  const bothFinding = await mkFinding(runBoth, {
    semKey: routeKey, kind: 'changed', severity: 'high', resource: 'route',
  });
  await exc.sweep();
  await db('drift_findings').where({ id: bothFinding }).update({ ignored_by_rule: libraryRule });
  await db('normalization_rules').where({ id: libraryRule }).del();
  x = await db('drift_findings').where({ id: bothFinding }).first();
  eq('losing the rule leaves the EXCEPTION\'s suppression standing', x.ignored, true);

  // And the unjustified manual ignore is STILL refused loudly — the
  // compensation branch must not have turned a 23514 into a silent no-op.
  await refused(
    'the unjustified manual ignore is still refused, not silently corrected',
    () => db('drift_findings').where({ id: critFinding }).update({ ignored: true }),
    '23514',
  );
  await db('normalization_rules').where({ id: foreignRule }).del();

  console.log('\n── audit_log: the chain Postgres computed ────────────────────────────');

  const ledger = await db('audit_log').where({ tenant_id: tenantId }).orderBy('seq', 'asc')
    .select<{ seq: string; action: string; prev_hash: string | null; hash: string }[]>('*');
  ok('the exception acts were recorded', ledger.length >= 3, ledger.map((r) => r.action));
  eq('the chain starts with no predecessor', ledger[0].prev_hash, null);
  ok('every link points at the previous hash',
    ledger.every((r, i) => i === 0 || r.prev_hash === ledger[i - 1].hash));
  ok('the sequence is contiguous',
    ledger.every((r, i) => Number(r.seq) === i + 1));

  await refused(
    'a ledger row cannot be modified',
    () => db('audit_log').where({ seq: 1, tenant_id: tenantId })
      .update({ action: 'something.else' }),
  );
  await refused(
    'a recent ledger row cannot be deleted',
    () => db('audit_log').where({ seq: 1, tenant_id: tenantId }).del(),
  );

  // Two tenants, two independent chains, both starting at 1.
  await appendAudit({
    tenantId: otherTenant.id, actorType: 'system', action: 'test.seeded',
  });
  const otherLedger = await db('audit_log').where({ tenant_id: otherTenant.id })
    .orderBy('seq', 'asc').select<{ seq: string; prev_hash: string | null }[]>('*');
  eq('the other tenant has its own chain, starting at 1', otherLedger[0].seq, '1');
  eq('and its own genesis', otherLedger[0].prev_hash, null);

  console.log('\n── F2-c  the deduplication trap ──────────────────────────────────────');

  // Snapshot A was captured 90 days ago and last confirmed 20 days ago, but
  // snapshot B was observed in between. Reading A's interval off its own row
  // would attest 70 days of continuity that did not happen.
  const trapDoc = await att.build(tenantId, {
    deviceId: device.id,
    from: new Date(now - 85 * DAY),
    to: new Date(now - 15 * DAY),
    issuedByUsername: username,
    issuedByUserId: user.id,
  });
  ok('the A -> B -> A window is NOT reported as continuous',
    trapDoc.claim.verdict === 'changed', trapDoc.claim);
  ok('and it reports more than one period', trapDoc.periods.length > 1,
    trapDoc.periods.map((p) => [p.ncmHash.slice(0, 4), p.from, p.to]));
  eq('a changed verdict names no single configuration', trapDoc.claim.ncmHash, null);

  // A window inside which only snapshot C was ever observed.
  const narrow = await att.build(tenantId, {
    deviceId: device.id,
    from: new Date(now - 9 * DAY),
    to: new Date(now - 2 * DAY),
    maxGapDays: 30,
    issuedByUsername: username,
    issuedByUserId: user.id,
  });
  ok('a single-configuration window is attested as continuous',
    narrow.claim.verdict === 'continuous', narrow.claim);
  eq('and it names the configuration', narrow.claim.ncmHash, hashC);
  eq('and carries the raw export digest a customer can check themselves',
    narrow.periods[0].rawSha256, HEX(0x33));

  // The same window with a one-hour tolerance: the gaps must appear.
  const gappy = await att.build(tenantId, {
    deviceId: device.id,
    from: new Date(now - 9 * DAY),
    to: new Date(now - 2 * DAY),
    maxGapDays: 0,
    issuedByUsername: username,
    issuedByUserId: user.id,
  });
  eq('with zero tolerance the same window is downgraded, not silently upgraded',
    gappy.claim.verdict, 'continuous_with_gaps');
  ok('and the holes are printed', gappy.periods[0].gaps.length > 0, gappy.periods[0].gaps);

  const empty = await att.build(tenantId, {
    deviceId: device.id,
    from: new Date(now + 200 * DAY),
    to: new Date(now + 260 * DAY),
    issuedByUsername: username,
    issuedByUserId: user.id,
  });
  eq('a window with no evidence refuses to attest', empty.claim.verdict, 'insufficient_evidence');

  console.log('\n── F2-a  issue, and re-verify with an INDEPENDENT script ─────────────');

  // The window runs to a few seconds from NOW so that the ledger rows the F1
  // section just wrote fall inside it — the point of this attestation is that
  // it carries a slice of a chain it did not compute.
  const issued = await att.issue(tenantId, {
    deviceId: device.id,
    from: new Date(now - 100 * DAY),
    to: new Date(Date.now() + 5_000),
    issuedByUsername: username,
    issuedByUserId: user.id,
  });
  const doc = issued.document;
  eq('the document carries its own uuid', doc.attestationUuid, issued.uuid);
  ok('it covers three snapshots',
    doc.evidence.filter((e) => e.kind === 'snapshot').length === 3,
    doc.evidence.filter((e) => e.kind === 'snapshot').length);
  ok('and the two changes',
    doc.changes.length === 2, doc.changes.map((c) => c.jobId));
  ok('it carries a ledger slice', doc.auditChain.length > 0, doc.auditChain.length);
  eq('it publishes its own verification method', doc.verification.spec,
    'obliwan.attestation/v1');

  // The evidence rows are self-describing `[name, value]` pairs, so a reader
  // needs no schema. `evidenceField` is the accessor a UI uses; asserting
  // through it is how the shape stays honest.
  const firstSnap = doc.evidence.find((e) => e.kind === 'snapshot')!;
  eq('an evidence row is readable by field name, with no schema',
    evidenceField(firstSnap, 'rawSha256'), HEX(0x11));
  eq('and a genuinely absent value is null, not missing',
    evidenceField(firstSnap, 'osVersion'), null);

  // NO SECRET, NO CONFIGURATION BODY, NO COMMAND LINE (§8.2 / R10).
  const asText = JSON.stringify(doc);
  ok('the document contains no command line',
    !asText.includes('/ip/firewall/nat/add') && !asText.includes('show-sensitive'));
  ok('the document contains no configuration body',
    !asText.includes('"ncm":{') && !asText.includes('{"v":"A"}'));
  eq('commands are counters only', doc.commandSummary.writes, 1);

  // The document is stored as `jsonb`, which does NOT preserve key order — and
  // that is exactly why the digest is defined over a CANONICAL serialisation
  // rather than over the bytes. Comparing `JSON.stringify` of the two would be
  // testing Postgres's key ordering; comparing the digests tests the property
  // the reader depends on.
  const stored = await att.getAttestation(tenantId, issued.uuid);
  eq('what comes back out of the database has the same digest',
    stored!.document.documentDigest, doc.documentDigest);
  eq('and the same evidence root', stored!.document.evidenceRoot, doc.evidenceRoot);

  await refused(
    'an issued attestation cannot be rewritten',
    () => db('attestations').where({ uuid: issued.uuid }).update({ verdict: 'continuous' }),
  );
  await refused(
    'an issued attestation cannot be deleted',
    () => db('attestations').where({ uuid: issued.uuid }).del(),
  );

  const report = await att.verifyStored(tenantId, issued.uuid);
  eq('our own verifier finds the document intact', report!.documentIntact, true);
  eq('and the ledger agrees with it', report!.ledgerHashMatches, true);

  // ── The independent check ────────────────────────────────────────────────
  const dir = mkdtempSync(path.join(tmpdir(), 'obliwan-attest-'));
  const file = path.join(dir, 'attestation.json');
  writeFileSync(file, JSON.stringify(doc, null, 2), 'utf8');

  const verifier = path.join(__dirname, 'independent-verifier.cjs');
  const runVerifier = (target: string): { code: number; out: string } => {
    try {
      return { code: 0, out: execFileSync(process.execPath, [verifier, target], {
        encoding: 'utf8',
      }) };
    } catch (err) {
      const e = err as { status?: number; stdout?: string; stderr?: string };
      return { code: e.status ?? 1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
    }
  };

  const clean = runVerifier(file);
  console.log(clean.out.split('\n').map((l) => `        ${l}`).join('\n'));
  eq('THE INDEPENDENT VERIFIER ACCEPTS THE DOCUMENT', clean.code, 0);

  // And again on the copy that went through Postgres and came back, with its
  // keys reordered by `jsonb`. If the canonical serialisation were not doing
  // its job, THIS is the run that would fail.
  const roundTripFile = path.join(dir, 'round-tripped.json');
  writeFileSync(roundTripFile, JSON.stringify(stored!.document, null, 2), 'utf8');
  eq('and accepts the copy that round-tripped through jsonb',
    runVerifier(roundTripFile).code, 0);

  console.log('\n── F2-b  tamper with it, and the independent verifier must object ────');

  const forged = JSON.parse(JSON.stringify(doc)) as typeof doc;
  const snapEntry = forged.evidence.find((e) => e.kind === 'snapshot')!;
  const capturedAt = snapEntry.fields.find(([n]) => n === 'capturedAt')!;
  capturedAt[1] = new Date(now - 200 * DAY).toISOString();
  const forgedFile = path.join(dir, 'forged.json');
  writeFileSync(forgedFile, JSON.stringify(forged, null, 2), 'utf8');
  const tampered = runVerifier(forgedFile);
  ok('a back-dated snapshot is caught', tampered.code !== 0, tampered.out.slice(0, 400));
  ok('and the verifier says which row', tampered.out.includes('rowHash'), tampered.out.slice(0, 400));

  const dropped = JSON.parse(JSON.stringify(doc)) as typeof doc;
  dropped.evidence.splice(2, 1);
  const droppedFile = path.join(dir, 'dropped.json');
  writeFileSync(droppedFile, JSON.stringify(dropped, null, 2), 'utf8');
  const droppedRun = runVerifier(droppedFile);
  ok('a REMOVED evidence row is caught', droppedRun.code !== 0, droppedRun.out.slice(0, 300));

  const ledgerForged = JSON.parse(JSON.stringify(doc)) as typeof doc;
  if (ledgerForged.auditChain.length > 0) {
    ledgerForged.auditChain[0].action = 'drift_exception.revoked';
    const lf = path.join(dir, 'ledger-forged.json');
    writeFileSync(lf, JSON.stringify(ledgerForged, null, 2), 'utf8');
    const lr = runVerifier(lf);
    ok('a rewritten LEDGER row is caught — and that hash came from Postgres',
      lr.code !== 0 && lr.out.includes('auditChain'), lr.out.slice(0, 400));
  }

  console.log('\n── re-issue determinism ──────────────────────────────────────────────');

  const cmp = await att.compareToLive(tenantId, issued.uuid, username);
  eq('rebuilding the same window reproduces the same evidence root', cmp!.identical, true);

  console.log('\n── F2-d  the tolerance is hashed, and one row is one witness ─────────');

  // ┌─ THE SCENARIO, VERBATIM ──────────────────────────────────────────────┐
  // │ One device. ONE `config_snapshots` row: captured 2024-12-20, last     │
  // │ confirmed 2026-01-05, seen_count 2. Window 2025-01-01 → 2025-12-31 —  │
  // │ 364 days during which NOTHING looked at the equipment.                │
  // │                                                                       │
  // │ Before this fix, `build()` with `maxGapDays: 365` emptied the gap     │
  // │ list, printed "continuously … confirmed by 2 independent dated        │
  // │ observations", and produced an evidenceRoot IDENTICAL to the honest   │
  // │ 7-day document's — because neither the tolerance nor the verdict was  │
  // │ in the chain. The string "maxGapDays" appeared nowhere in the JSON,   │
  // │ verifyStored said intact, compareToLive said identical, and the       │
  // │ independent verifier said VERIFIED. Both "independent" observations   │
  // │ were `captured_at` and `last_seen_at` OF THE SAME ROW.                │
  // └───────────────────────────────────────────────────────────────────────┘
  const [dev3] = await db('devices')
    .insert({
      tenant_id: tenantId, name: 'CPE-EVIDENCE-03', brand: 'mikrotik',
      family: 'mikrotik_routeros7', role: 'cpe', status: 'active', is_managed: true,
    })
    .returning<{ id: number }[]>(['id']);
  await db('config_snapshots').insert({
    device_id: dev3.id, source: 'ssh', ncm: JSON.stringify({ v: 'E' }),
    ncm_hash: HEX(0xee), ncm_version: 1, normalization_epoch: epoch,
    raw_sha256: HEX(0x55), raw_bytes: 2048,
    captured_at: new Date('2024-12-20T00:00:00.000Z'),
    last_seen_at: new Date('2026-01-05T00:00:00.000Z'),
    seen_count: 2,
  });
  const wFrom = new Date('2025-01-01T00:00:00.000Z');
  const wTo = new Date('2025-12-31T00:00:00.000Z');
  const asker = { issuedByUsername: username, issuedByUserId: user.id };

  const strict = await att.build(tenantId, {
    deviceId: dev3.id, from: wFrom, to: wTo, ...asker,
  });
  eq('at the default tolerance a year of silence is a gap',
    strict.claim.verdict, 'continuous_with_gaps');

  const bought = await att.build(tenantId, {
    deviceId: dev3.id, from: wFrom, to: wTo, maxGapDays: 365, ...asker,
  });
  eq('A 365-DAY TOLERANCE NO LONGER BUYS THE WORD `continuous`',
    bought.claim.verdict, 'continuous_with_gaps');
  eq('the two dates are still counted as two observations',
    bought.periods[0].confirmations, 2);
  eq('BUT THEY ARE ONE WITNESS, BECAUSE THEY ARE ONE ROW',
    bought.periods[0].independentSources, 1);
  ok('and the document says so in the sentence an insurer reads',
    bought.claim.statement.includes('CONTINUITY IS NOT ESTABLISHED'), bought.claim.statement);
  ok('the tolerance is printed in the claim',
    bought.claim.statement.includes('365 day(s)'), bought.claim.statement);

  ok('THE TWO TOLERANCES NO LONGER SHARE AN EVIDENCE ROOT',
    strict.evidenceRoot !== bought.evidenceRoot,
    { strict: strict.evidenceRoot, bought: bought.evidenceRoot });
  eq('the tolerance is inside the HASHED header', strict.chainHeader.maxGapDays, 7);
  eq('and the caller-chosen one is too', bought.chainHeader.maxGapDays, 365);
  ok('the rulebook version is hashed with it',
    typeof bought.chainHeader.judgeVersion === 'string'
      && bought.chainHeader.judgeVersion.length > 0, bought.chainHeader.judgeVersion);
  ok('and "maxGapDays" now appears in the emitted JSON',
    JSON.stringify(bought).includes('maxGapDays'));

  // A device with genuinely independent witnesses is NOT downgraded: the
  // guard must cost nothing to an honest claim. `narrow` (above) is that
  // device, and it was asserted `continuous` — re-read its sources here so
  // the two assertions are visibly about the same property.
  ok('a period with real independent sources is still `continuous`',
    narrow.claim.verdict === 'continuous' && narrow.periods[0].independentSources >= 2,
    { verdict: narrow.claim.verdict, sources: narrow.periods[0].independentSources });

  // ── /issue caps the tolerance; /preview does not ────────────────────────
  await refused(
    'ISSUING a permanent document at a 365-day tolerance',
    () => att.issue(tenantId, {
      deviceId: dev3.id, from: wFrom, to: wTo, maxGapDays: 365, ...asker,
    }),
  );
  const honest = await att.issue(tenantId, {
    deviceId: dev3.id, from: wFrom, to: wTo, ...asker,
  });
  eq('an issued document declares the tolerance it was drawn under',
    honest.document.chainHeader.maxGapDays, 7);
  eq('and carries the weak verdict', honest.document.claim.verdict, 'continuous_with_gaps');
  const honestReport = await att.verifyStored(tenantId, honest.uuid);
  eq('it verifies against the ledger', honestReport!.ledgerHashMatches, true);
  const honestCmp = await att.compareToLive(tenantId, honest.uuid, username);
  eq('and rebuilds to the same root — the comparison uses the STORED tolerance',
    honestCmp!.identical, true);

  // ── The independent verifier must refuse a document that hides its knob ──
  const gapDir = mkdtempSync(path.join(tmpdir(), 'obliwan-gap-'));
  const honestFile = path.join(gapDir, 'honest.json');
  writeFileSync(honestFile, JSON.stringify(honest.document, null, 2), 'utf8');
  const honestRun = runVerifier(honestFile);
  console.log(honestRun.out.split('\n').map((l) => `        ${l}`).join('\n'));
  eq('the independent verifier accepts the honest document', honestRun.code, 0);
  ok('and PRINTS the tolerance next to the verdict',
    honestRun.out.includes('tolerance'), honestRun.out.slice(0, 300));

  // Retro-fit the old shape: a header with no tolerance in it at all.
  const legacy = JSON.parse(JSON.stringify(honest.document)) as typeof honest.document;
  delete (legacy.chainHeader as Partial<typeof legacy.chainHeader>).maxGapDays;
  const legacyFile = path.join(gapDir, 'no-tolerance.json');
  writeFileSync(legacyFile, JSON.stringify(legacy, null, 2), 'utf8');
  const legacyRun = runVerifier(legacyFile);
  ok('a document whose header hides its tolerance is REFUSED',
    legacyRun.code !== 0 && legacyRun.out.includes('maxGapDays'),
    legacyRun.out.slice(0, 400));

  // And widening the tolerance after the fact breaks the chain, because the
  // header seeds it.
  const widened = JSON.parse(JSON.stringify(honest.document)) as typeof honest.document;
  widened.chainHeader.maxGapDays = 365;
  const widenedFile = path.join(gapDir, 'widened.json');
  writeFileSync(widenedFile, JSON.stringify(widened, null, 2), 'utf8');
  const widenedRun = runVerifier(widenedFile);
  ok('WIDENING THE TOLERANCE AFTER ISSUANCE BREAKS THE CHAIN',
    widenedRun.code !== 0 && widenedRun.out.includes('chainHash'),
    widenedRun.out.slice(0, 400));

  console.log('\n── offboarding: every append-only trigger must let a tenant go ───────');

  // The one test nothing else in the suite covers, and the one whose failure
  // mode is "a customer can no longer be deleted". Every table this migration
  // added is append-only or frozen; each of them needs its cascade escape, and
  // an escape that is wrong shows up ONLY here.
  let offboarded = true;
  let offboardErr: unknown = null;
  try {
    await db('tenants').whereIn('id', [tenantId, otherTenant.id]).del();
  } catch (err) {
    offboarded = false;
    offboardErr = err;
  }
  ok('deleting the tenant cascades through audit_log, attestations and the '
    + 'exception history', offboarded, offboardErr);
  if (offboarded) {
    const left = await db('audit_log').where({ tenant_id: tenantId }).count<{ count: string }[]>('*');
    eq('and leaves no ledger row behind', Number(left[0].count), 0);
  }
  await db('users').where({ id: user.id }).del();

  console.log(`\n${passed} passed, ${failed} failed  (${Date.now() - t0} ms)\n`);
  await db.destroy();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  await db.destroy();
  process.exit(1);
});
