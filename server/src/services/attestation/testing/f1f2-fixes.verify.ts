/* eslint-disable no-console */
// ============================================================================
// F1 + F2 — the corrections, against a REAL Postgres, never a mock
// ============================================================================
//
//   DATABASE_URL=postgres://obliwan:t@host:port/obliwan \
//     npx tsx src/services/attestation/testing/f1f2-fixes.verify.ts
//
// The sibling `f1f2-evidence.verify.ts` asserts what the feature DOES. This one
// asserts what an adversarial audit found it still allowed, and each block
// reproduces the audited scenario rather than testing the fix's own code path:
//
//   CRITIQUE 2   `PATCH /findings/:id/ignore {ignored:true, ruleId:N}` was a
//                complete bypass of the exception mechanism — no justification,
//                no review date, no expiry, no ledger row, and it accepted a
//                rule belonging to ANOTHER CUSTOMER. Migration 022 closed the
//                storage half; the route half is asserted here.
//   CRITIQUE 2b  a finding hidden by `ignored_by_rule` had no path back to the
//                screen at all: both clauses of `sweep()` keyed on
//                `ignored_by_exception`.
//   MINEUR 6     24 no-break spaces satisfied `length(btrim(...)) >= 24`, and
//                30 zero-width spaces satisfied `String.trim()` as well.
//   MINEUR 7     a renewal accepted the previous justification byte for byte.
//   MINEUR 8     `acceptedDrift[].state` described the moment of ISSUANCE and
//                not the attested window.
//   MINEUR 9     the published method described a time-filtered ledger slice;
//                the code produces a contiguous one by `seq`.
//   MINEUR 10    `POST /api/exceptions/sweep` is a tenant route that wrote
//                across every tenant in the installation.
//   MINEUR 11    the chain's advisory lock only holds in READ COMMITTED.
//
// Its own tenants, deleted at the end — which also exercises the offboarding
// cascade through `audit_log`.

import { db } from '../../../db';
import * as drift from '../../drift/drift.service';
import * as exc from '../../drift/exception.service';
import * as att from '../attestation.service';
import { justificationProblemStrict, PUBLISHED_METHOD } from '../contract';
import { appendAudit } from '../auditLog.service';

let passed = 0;
let failed = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  if (cond) { passed += 1; console.log(`  PASS  ${label}`); } else {
    failed += 1;
    console.log(`  FAIL  ${label}${detail === undefined ? '' : ` -- ${JSON.stringify(detail)}`}`);
  }
}
async function throws(label: string, fn: () => Promise<unknown>, want: RegExp): Promise<void> {
  try { await fn(); ok(label, false, 'ACCEPTED'); } catch (e) {
    const m = (e as Error).message;
    ok(label, want.test(m), m);
  }
}
const DAY = 86_400_000;
const ACTOR = { userId: null, username: 'verify' };

async function main(): Promise<void> {
  const stamp = Date.now();
  await db('tenants').whereLike('slug', 'fixv-%').del();

  const [tA] = await db('tenants').insert({ name: 'FIXA', slug: `fixv-a-${stamp}` }).returning<{ id: number }[]>('id');
  const [tB] = await db('tenants').insert({ name: 'FIXB', slug: `fixv-b-${stamp}` }).returning<{ id: number }[]>('id');

  const mkDevice = async (tenant: number, name: string): Promise<number> => {
    const [d] = await db('devices').insert({
      tenant_id: tenant, name, brand: 'mikrotik', family: 'mikrotik_routeros7',
      role: 'cpe', status: 'active', is_managed: true,
    }).returning<{ id: number }[]>('id');
    return d.id;
  };
  const devA = await mkDevice(tA.id, `FIXV-A-${stamp}`);
  const devB = await mkDevice(tB.id, `FIXV-B-${stamp}`);

  const mkRun = async (deviceId: number): Promise<string> => {
    const [r] = await db('drift_runs').insert({
      device_id: deviceId, status: 'drifted', cause: 'manual', scope: 'managed_only',
      findings_count: 1, ignored_count: 0, max_severity: 'critical', ncm_version: 1,
    }).returning<{ id: string }[]>('id');
    return String(r.id);
  };
  const mkFinding = async (runId: string, semKey: string): Promise<string> => {
    const [f] = await db('drift_findings').insert({
      run_id: runId, path: `changed/${semKey}`, sem_key: semKey, resource: 'firewallRule',
      kind: 'changed', severity: 'critical', match_method: 'natural', match_confidence: 1,
      predicate_changed: false,
      field_diffs: JSON.stringify([{ field: 'action', before: 'accept', after: 'dst-nat' }]),
      crossed: JSON.stringify([]), ignored: false,
    }).returning<{ id: string }[]>('id');
    return String(f.id);
  };

  const runA = await mkRun(devA);
  const findingA = await mkFinding(runA, 'nat.v1:srcnat:10.0.0.0/8');

  const mkRule = async (
    tenantId: number | null, name: string, extra: Record<string, unknown>,
  ): Promise<string> => {
    const [r] = await db('normalization_rules').insert({
      tenant_id: tenantId, scope: 'global', name, description: 'x', rationale: 'x',
      false_negative: 'x', layer: 4, kind: 'suppress_finding', enabled: true,
      apply_order: Math.floor(Math.random() * 100000), requires_test: false, ...extra,
    }).returning<{ id: string }[]>('id');
    return String(r.id);
  };
  const ruleB = await mkRule(tB.id, `B suppress ${stamp}`, { pattern: '^changed/' });
  const ruleLib = await mkRule(null, `lib comments ${stamp}`, { prop: 'comment' });
  const ruleMatching = await mkRule(tA.id, `A suppress nat ${stamp}`, { pattern: '^changed/nat\\.v1:' });

  console.log('\n-- CRITIQUE 2: the route half of the unjustified ignore --------------');

  await throws(
    'a manual ignore with no ruleId is refused and names POST /api/exceptions',
    () => drift.setFindingIgnored(tA.id, findingA, { ignored: true, ruleId: null }, ACTOR),
    /POST \/api\/exceptions/,
  );
  await throws(
    "another tenant's rule cannot silence this finding",
    () => drift.setFindingIgnored(tA.id, findingA, { ignored: true, ruleId: Number(ruleB) }, ACTOR),
    /not found/i,
  );
  await throws(
    'a real, in-scope rule that does not MATCH is refused too',
    () => drift.setFindingIgnored(tA.id, findingA, { ignored: true, ruleId: Number(ruleLib) }, ACTOR),
    /does not suppress this finding/,
  );

  const still = await db('drift_findings').where({ id: findingA })
    .first<{ ignored: boolean }>('ignored');
  ok('after three refusals the critical is still visible', still.ignored === false, still);

  const refusals = await db('audit_log')
    .where({ tenant_id: tA.id, action: 'drift_finding.ignore_refused' })
    .count<{ count: string }[]>('id as count');
  ok('every refusal left an audit_log row', Number(refusals[0].count) === 3, refusals[0]);

  const accepted = await drift.setFindingIgnored(
    tA.id, findingA, { ignored: true, ruleId: Number(ruleMatching) }, ACTOR,
  );
  ok('a rule the engine really applies IS accepted', accepted?.ignored === true, accepted?.ignored);
  const acceptAudit = await db('audit_log')
    .where({ tenant_id: tA.id, action: 'drift_finding.ignored' }).first<{ id: string } | undefined>('id');
  ok('and the acceptance is in the ledger too', acceptAudit !== undefined);
  const runAfter = await db('drift_runs').where({ id: runA })
    .first<{ max_severity: string | null; status: string }>('max_severity', 'status');
  ok('the run rolled up', runAfter.max_severity === null && runAfter.status === 'in_sync', runAfter);

  console.log('\n-- CRITIQUE 2b: REVIVE must cover ignored_by_rule --------------------');

  await db('normalization_rules').where({ id: ruleMatching }).update({ enabled: false });
  const sweptA = await exc.sweep({ tenantId: tA.id });
  const revivedRow = await db('drift_findings').where({ id: findingA })
    .first<{ ignored: boolean; ignored_by_rule: string | null }>('ignored', 'ignored_by_rule');
  ok(
    'disabling the rule hands the finding back',
    revivedRow.ignored === false && revivedRow.ignored_by_rule === null,
    { revivedRow, sweptA },
  );
  const runRevived = await db('drift_runs').where({ id: runA })
    .first<{ max_severity: string | null }>('max_severity');
  ok('and the device is red again', runRevived.max_severity === 'critical', runRevived);

  console.log('\n-- MINEUR 10: the sweep must not write across the installation -------');

  const runB = await mkRun(devB);
  const findingB = await mkFinding(runB, 'nat.v1:srcnat:172.16.0.0/12');
  await db('drift_findings').where({ id: findingB })
    .update({ ignored: true, ignored_by_rule: ruleB });
  await db('normalization_rules').where({ id: ruleB }).update({ enabled: false });

  await exc.sweep({ tenantId: tA.id });
  const bAfterA = await db('drift_findings').where({ id: findingB }).first<{ ignored: boolean }>('ignored');
  ok("tenant A's sweep left tenant B's finding alone", bAfterA.ignored === true, bAfterA);
  await exc.sweep({ tenantId: tB.id });
  const bAfterB = await db('drift_findings').where({ id: findingB }).first<{ ignored: boolean }>('ignored');
  ok("tenant B's own sweep hands it back", bAfterB.ignored === false, bAfterB);

  console.log('\n-- MINEUR 6: invisible characters are not a justification ------------');

  const ZWSP = '​'.repeat(30);
  const NBSP = ' '.repeat(30);
  ok('the application guard refuses 30 zero-width spaces', justificationProblemStrict(ZWSP) !== null);
  ok('and 30 no-break spaces', justificationProblemStrict(NBSP) !== null);
  ok('and 30 dots', justificationProblemStrict('.'.repeat(30)) !== null);
  ok(
    'but accepts real prose',
    justificationProblemStrict('Kept until the Q3 VPN migration lands, tracked in OPS-4412.') === null,
  );

  await throws(
    'the DATABASE refuses them on the createException path',
    () => exc.createException(tA.id, ACTOR, {
      deviceId: devA, semKey: 'nat.v1:zwsp', resource: 'firewallRule',
      justification: ZWSP, reviewDueAt: new Date(Date.now() + 30 * DAY).toISOString(),
    }),
    /justified_chk|at least 24 characters/,
  );
  await throws(
    'and a raw INSERT bypassing every Zod schema is refused as well',
    () => db('drift_exceptions').insert({
      tenant_id: tA.id, device_id: devA, sem_key: 'nat.v1:nbsp', resource: 'firewallRule',
      justification: NBSP, status: 'active', review_due_at: new Date(Date.now() + 30 * DAY),
      created_by_username: 'raw',
    }),
    /drift_exceptions_justified_chk/,
  );

  console.log('\n-- MINEUR 7: a renewal repeating the previous text -------------------');

  const J1 = 'The lab NAT rule stays until the Q3 migration is signed off.';
  const created = await exc.createException(tA.id, ACTOR, {
    deviceId: devA, semKey: 'nat.v1:srcnat:10.0.0.0/8', resource: 'firewallRule',
    justification: J1, reviewDueAt: new Date(Date.now() + 30 * DAY).toISOString(),
  });
  ok('an exception can still be granted', created.id !== undefined);
  const fetched = await exc.getException(tA.id, created.id);
  await throws(
    'reposting the justification GET returned is refused',
    () => exc.renewException(tA.id, created.id, ACTOR, {
      justification: fetched!.justification,
      reviewDueAt: new Date(Date.now() + 90 * DAY).toISOString(),
    }),
    /new decision/,
  );
  await throws(
    'padding it with invisible characters does not buy one either',
    () => exc.renewException(tA.id, created.id, ACTOR, {
      justification: ` ${fetched!.justification}​`,
      reviewDueAt: new Date(Date.now() + 90 * DAY).toISOString(),
    }),
    /new decision/,
  );
  const renewed = await exc.renewException(tA.id, created.id, ACTOR, {
    justification: 'Re-checked in June: the migration slipped, the rule is still needed.',
    reviewDueAt: new Date(Date.now() + 90 * DAY).toISOString(),
  });
  ok('a genuinely new assertion renews it', renewed.renewalCount === 1, renewed.renewalCount);

  console.log('\n-- MINEUR 8: acceptedDrift[].state must describe the WINDOW ----------');

  const Y = new Date().getUTCFullYear() - 1;
  const jan = new Date(Date.UTC(Y, 0, 10));
  const feb = new Date(Date.UTC(Y, 1, 10));
  const jun = new Date(Date.UTC(Y, 5, 10));
  const dec = new Date(Date.UTC(Y, 11, 10));
  const J_JAN = 'Accepted in January while the replacement circuit was on order.';
  const J_JUN = 'Re-examined in June: the circuit slipped to the next quarter.';
  const [gap] = await db('drift_exceptions').insert({
    tenant_id: tA.id, device_id: devA, sem_key: 'nat.v1:gap-demo', resource: 'firewallRule',
    justification: J_JUN, status: 'active', review_due_at: dec, created_by_username: 'op',
    created_at: jan, renewal_count: 1, last_renewed_at: jun, severity_at_creation: 'low',
  }).returning<{ id: string }[]>('id');
  await db('drift_exception_reviews').insert([
    {
      exception_id: gap.id, tenant_id: tA.id, decision: 'created', justification: J_JAN,
      reviewed_by_username: 'op', reviewed_at: jan, previous_review_due_at: null,
      new_review_due_at: feb,
    },
    {
      exception_id: gap.id, tenant_id: tA.id, decision: 'renewed', justification: J_JUN,
      reviewed_by_username: 'op', reviewed_at: jun, previous_review_due_at: feb,
      new_review_due_at: dec,
    },
  ]);

  const march = await exc.exceptionsInForce(
    tA.id, devA, new Date(Date.UTC(Y, 2, 1)), new Date(Date.UTC(Y, 3, 1)),
  );
  ok(
    'a window inside the lapse does NOT report it in force',
    march.every((e) => e.semKey !== 'nat.v1:gap-demo'),
    march.map((e) => e.semKey),
  );
  const janWin = await exc.exceptionsInForce(
    tA.id, devA, new Date(Date.UTC(Y, 0, 15)), new Date(Date.UTC(Y, 0, 25)),
  );
  const inJan = janWin.find((e) => e.semKey === 'nat.v1:gap-demo');
  ok('a January window reports it, active', inJan?.state === 'active', inJan?.state);
  ok('with the review date in force THEN', inJan?.reviewDueAt === feb.toISOString(), inJan?.reviewDueAt);
  ok('no renewal counted yet', inJan?.renewalCount === 0, inJan?.renewalCount);
  ok('and the wording in force then', inJan?.justification === J_JAN, inJan?.justification);
  const julWin = await exc.exceptionsInForce(
    tA.id, devA, new Date(Date.UTC(Y, 6, 1)), new Date(Date.UTC(Y, 6, 10)),
  );
  const inJul = julWin.find((e) => e.semKey === 'nat.v1:gap-demo');
  ok(
    'a July window sees the renewed wording and count',
    inJul?.renewalCount === 1 && inJul.justification === J_JUN,
    { n: inJul?.renewalCount, j: inJul?.justification },
  );

  console.log('\n-- MINEUR 9: the published method must describe the real slice -------');

  await appendAudit({ tenantId: tA.id, actorType: 'system', action: 'verify.marker' });
  const doc = await att.build(tA.id, {
    deviceId: devA,
    from: new Date(Date.now() - 30 * DAY),
    to: new Date(),
    issuedByUsername: 'verify',
    issuedByUserId: null,
  });
  ok(
    'the document no longer claims a time-filtered slice',
    !doc.verification.auditLog.startsWith('The `auditChain` section carries the tenant-scoped'),
    doc.verification.auditLog.slice(0, 80),
  );
  ok(
    'it says CONTIGUOUS and names the seq range',
    doc.verification.auditLog.includes('CONTIGUOUS')
      && doc.verification.auditLog.includes('[fromSeq..toSeq]'),
  );
  ok('the emitted method is the corrected one', doc.verification.auditLog === PUBLISHED_METHOD.auditLog);
  ok(
    'and the rest of the method is untouched',
    doc.verification.rowHash.startsWith('rowHash = SHA256') && doc.verification.spec === 'obliwan.attestation/v1',
  );

  console.log('\n-- MINEUR 11: the chain refuses an isolation level it cannot hold ----');

  await throws(
    'an audit append under REPEATABLE READ is refused with the real reason',
    () => db.transaction(
      async (trx) => appendAudit({ tenantId: tA.id, actorType: 'system', action: 'verify.iso' }, trx),
      { isolationLevel: 'repeatable read' },
    ),
    /READ COMMITTED/,
  );

  const chain = await db('audit_log').where({ tenant_id: tA.id }).orderBy('seq', 'asc')
    .select<{ seq: string; prev_hash: string | null; hash: string; occurred_at: Date }[]>(
      'seq', 'prev_hash', 'hash', 'occurred_at',
    );
  let contiguous = chain.length > 0;
  for (let i = 0; i < chain.length; i += 1) {
    if (Number(chain[i].seq) !== i + 1) contiguous = false;
    if (i > 0 && chain[i].prev_hash !== chain[i - 1].hash) contiguous = false;
  }
  ok(`the chain is intact and contiguous (${chain.length} rows)`, contiguous);
  let monotone = true;
  for (let i = 1; i < chain.length; i += 1) {
    if (new Date(chain[i].occurred_at).getTime() < new Date(chain[i - 1].occurred_at).getTime()) {
      monotone = false;
    }
  }
  ok('occurred_at is monotone with seq', monotone);

  console.log('\n-- offboarding still works -------------------------------------------');
  await db('tenants').whereIn('id', [tA.id, tB.id]).del();
  const leftovers = await db('audit_log').whereIn('tenant_id', [tA.id, tB.id]).count<{ count: string }[]>('id as count');
  ok('deleting both tenants cascades cleanly', Number(leftovers[0].count) === 0);

  console.log(`\n${passed} passed, ${failed} failed`);
  await db.destroy();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (e) => {
  console.error(e);
  await db.destroy();
  process.exit(1);
});
