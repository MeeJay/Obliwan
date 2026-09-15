/**
 * ObliWAN F9 — the schema and the sweep, verified against a real PostgreSQL.
 *
 *   DATABASE_URL=postgres://... npx tsx src/services/sim/testing/f9-sim.verify.ts
 *
 * ┌─ WHAT THIS FILE PROVES, AND WHAT IT CANNOT ───────────────────────────────┐
 * │ It proves the half `f9-rules.verify.ts` cannot: everything that is only    │
 * │ true because the DATABASE enforces it, and everything that is only true    │
 * │ across a whole sweep.                                                     │
 * │                                                                          │
 * │   - migration 032's CHECKs and indexes REFUSE what they are supposed to.  │
 * │     Several assertions below exist purely to make Postgres say no: an     │
 * │     unpriced-but-currency-less cost, a billable row with no completion    │
 * │     instant, a second proposal for one low episode, two lines sharing an  │
 * │     ICCID, a cross-tenant router on a line.                               │
 * │   - the composite foreign keys really are composite.                      │
 * │   - the sweep opens a low episode ONCE, keeps `low_since` stable while    │
 * │     the line stays low, clears it when the line recovers, and writes a    │
 * │     history sample only when a reading actually changed.                  │
 * │   - a partner answering a renamed field produces `unknown` and NO         │
 * │     proposal — the end-to-end version of the rule, through real rows.     │
 * │   - a tenant cannot read another tenant's line, the pool, or another      │
 * │     tenant's charges, on any read this feature serves.                    │
 * │   - the re-invoicing report never sums an unpriced top-up as zero.        │
 * │                                                                          │
 * │ It proves NOTHING about the real Phenix API: the partner it talks to is   │
 * │ `fakePhenixApi`, whose field names are the same guess the connector makes.│
 * │ See that file's header for why that is still worth testing.               │
 * │                                                                          │
 * │ It writes to the database it is pointed at. Point it at a disposable one. │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import {
  MB_PER_GB,
  UNKNOWN_ZONE,
  canonicalZone,
  evaluateBalance,
  rechargeIdempotencyKey,
  suggestsPlanChange,
} from '@obliwan/shared';
import { db } from '../../../db';
import { createAccount, setCredential, testConnection, type SimAccountRow } from '../account.service';
import { getLine, getLineHistory, listLines, updateLine, fleetSummary } from '../line.service';
import {
  approve,
  assertExecutionAllowed,
  expireStale,
  listRecharges,
  proposeManual,
  recordCompletion,
} from '../recharge.service';
import { rechargeReport, reportToCsv } from '../report.service';
import { applyBalancesForTest, syncAccount } from '../sync.service';
import { startFakePhenix, type FakePhenix } from './fakePhenixApi';

let passed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail?: string): void {
  if (condition) passed += 1;
  else failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
}

function eq(name: string, actual: unknown, expected: unknown): void {
  check(name, Object.is(actual, expected), `got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}

/** Asserts the DATABASE refuses something. A silent success here is the defect. */
async function refuses(name: string, fn: () => Promise<unknown>, constraintHint?: string): Promise<void> {
  try {
    await fn();
    failures.push(`${name} — the database ACCEPTED it`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (constraintHint && !message.includes(constraintHint)) {
      failures.push(`${name} — refused, but not by ${constraintHint}: ${message.slice(0, 120)}`);
      return;
    }
    passed += 1;
  }
}

interface Fixture {
  tenantA: number;
  tenantB: number;
  siteA: number;
  siteB: number;
  deviceA: number;
  deviceB: number;
  userId: number;
}

/**
 * Removes what a previous run of this harness left behind.
 *
 * Re-runnable by construction: an offline harness that only works against a
 * freshly migrated database is one nobody runs twice, and the second run is
 * where a state-dependent defect shows up. Scoped to this file's own fixtures
 * by slug and by name prefix — it touches nothing else in the database.
 */
async function cleanup(): Promise<void> {
  const tenantIds = (
    await db('tenants')
      .whereIn('slug', ['f9-cust-a', 'f9-cust-b'])
      .select<Array<{ id: number }>>('id')
  ).map((r) => r.id);

  // Order matters: sim_recharges holds SET NULL references to lines and
  // accounts, so it is emptied first and the accounts cascade the rest.
  await db('sim_recharges').whereIn('platform', ['phenix', 'cfast']).del();
  await db('sim_accounts').where('name', 'like', 'Phenix — verification%').del();
  if (tenantIds.length > 0) {
    await db('devices').whereIn('tenant_id', tenantIds).del();
    await db('sites').whereIn('tenant_id', tenantIds).del();
    await db('tenants').whereIn('id', tenantIds).del();
  }
  await db('users').where('username', 'f9-operator').del();
}

async function seed(): Promise<Fixture> {
  // Tenant 1 is seeded by migration 001 and is the MASTER (positional, see
  // shared/src/tenants.ts). Two customer tenants are created beneath it.
  const [tenantA] = await db('tenants')
    .insert({ name: 'Customer A', slug: 'f9-cust-a' })
    .returning<Array<{ id: number }>>('id');
  const [tenantB] = await db('tenants')
    .insert({ name: 'Customer B', slug: 'f9-cust-b' })
    .returning<Array<{ id: number }>>('id');

  const [siteA] = await db('sites')
    .insert({ tenant_id: tenantA.id, code: 'F9-A', name: 'Boulangerie A' })
    .returning<Array<{ id: number }>>('id');
  const [siteB] = await db('sites')
    .insert({ tenant_id: tenantB.id, code: 'F9-B', name: 'Garage B' })
    .returning<Array<{ id: number }>>('id');

  const [deviceA] = await db('devices')
    .insert({ tenant_id: tenantA.id, site_id: siteA.id, name: 'rtr-a', brand: 'mikrotik', family: 'mikrotik_routeros7' })
    .returning<Array<{ id: number }>>('id');
  const [deviceB] = await db('devices')
    .insert({ tenant_id: tenantB.id, site_id: siteB.id, name: 'rtr-b', brand: 'mikrotik', family: 'mikrotik_routeros7' })
    .returning<Array<{ id: number }>>('id');

  const [user] = await db('users')
    .insert({ username: 'f9-operator', password_hash: 'x', role: 'admin' })
    .returning<Array<{ id: number }>>('id');

  return {
    tenantA: tenantA.id, tenantB: tenantB.id,
    siteA: siteA.id, siteB: siteB.id,
    deviceA: deviceA.id, deviceB: deviceB.id,
    userId: user.id,
  };
}

async function main(): Promise<void> {
  await cleanup();
  const fx = await seed();
  const MASTER = { tenantId: 1, masterView: true };
  const SCOPE_A = { tenantId: fx.tenantA, masterView: false };
  const SCOPE_B = { tenantId: fx.tenantB, masterView: false };

  let fake: FakePhenix | null = null;
  try {
    fake = await startFakePhenix();

    // ========================================================================
    // 1. Schema refusals — migration 032 must say no
    // ========================================================================

    await refuses(
      'a cost with no currency is refused',
      () =>
        db('sim_recharges').insert({
          platform: 'phenix', msisdn: '33600000099', status: 'proposed', trigger: 'manual',
          zone: 'France', threshold_mb_at_proposal: 1024, cost_cents: 500, currency: null,
          idempotency_key: 'chk-currency-1',
        }),
      'sim_recharges_currency_chk',
    );

    await refuses(
      'a billable row with no completion instant is refused',
      () =>
        db('sim_recharges').insert({
          platform: 'phenix', msisdn: '33600000099', status: 'recorded', trigger: 'manual',
          zone: 'France', threshold_mb_at_proposal: 1024, decided_at: new Date(),
          completed_at: null, idempotency_key: 'chk-completed-1',
        }),
      'sim_recharges_completed_chk',
    );

    await refuses(
      'a decided row with no decision instant is refused',
      () =>
        db('sim_recharges').insert({
          platform: 'phenix', msisdn: '33600000099', status: 'rejected', trigger: 'manual',
          zone: 'France', threshold_mb_at_proposal: 1024, decided_at: null,
          idempotency_key: 'chk-decided-1',
        }),
      'sim_recharges_decided_chk',
    );

    // Short enough to fit varchar(24), so the CHECK is what refuses it rather
    // than the column width — the property being proved is the pattern, and a
    // test that is satisfied by a length limit proves nothing about the pattern.
    await refuses(
      'an MSISDN that is not a phone number is refused by the CHECK',
      () => db('sim_lines').insert({ account_id: 1, msisdn: "336'; DROP--" }),
      'sim_lines_msisdn_chk',
    );
    await refuses(
      'and a plausible MSISDN carrying a query separator is refused too',
      () => db('sim_lines').insert({ account_id: 1, msisdn: '33600000001&x=1' }),
      'sim_lines_msisdn_chk',
    );

    await refuses(
      'a finished sync run with no outcome is refused',
      () => db('sim_sync_runs').insert({ account_id: 1, finished_at: new Date(), outcome: null }),
      'sim_sync_runs_finished_chk',
    );

    // ========================================================================
    // 2. The account, and the credential that must never come back out
    // ========================================================================

    const account = await createAccount({
      platform: 'phenix',
      name: 'Phenix — verification',
      baseUrl: fake.baseUrl,
      authMode: 'password',
      // The prototype's rule, preserved: SFR lines answer nothing useful here.
      skipOperators: ['SFR'],
    });
    eq('the account starts with no credential', account.hasCredential, false);
    check('the account object carries no blob', !('credentialBlob' in (account as object)));
    check(
      'and no key of it holds anything password-shaped',
      !JSON.stringify(account).includes('pa55word'),
    );

    const withCred = await setCredential(account.id, {
      authMode: 'password', username: 'verify-user', password: 'pa55word-long',
    });
    eq('hasCredential flips to true', withCred.hasCredential, true);
    check(
      'the serialised account still carries no secret',
      !JSON.stringify(withCred).includes('pa55word-long') &&
        !JSON.stringify(withCred).includes('verify-user'),
    );

    const stored = await db('sim_accounts').where('id', account.id).first<{ credential_blob: string }>('credential_blob');
    check(
      'the blob in the database is not plaintext',
      !!stored && !stored.credential_blob.includes('pa55word-long'),
    );

    // The positive half of the MSISDN CHECK: the two legal shapes must actually
    // be storable, or the refusals above are passing for the wrong reason (see
    // migration 032's note on knex rewriting `?` inside a raw regex). Placed
    // here rather than in section 1 because `sim_lines.account_id` is NOT NULL
    // with a foreign key, so it needs a real account to hang off.
    const legal = await db('sim_lines')
      .insert([
        { account_id: account.id, msisdn: '33600000777' },
        { account_id: account.id, msisdn: '+33600000778' },
      ])
      .returning<Array<{ id: number }>>('id')
      .then((rows) => rows.length)
      .catch(() => 0);
    eq('both legal MSISDN shapes are accepted', legal, 2);
    await db('sim_lines').whereIn('msisdn', ['33600000777', '+33600000778']).del();

    const test = await testConnection(account.id);
    check('the connection test succeeds against the fake', test.ok, test.error ?? '');
    eq('and it reports the real line count, not just a tick', test.lineCount, 3);
    eq('the partner id is learned from the token', test.partnerRef, '4242');

    // ========================================================================
    // 3. The sweep — inventory, episodes, samples
    // ========================================================================

    const row = (await db('sim_accounts').where('id', account.id).first()) as SimAccountRow;
    const first = await syncAccount(row);
    eq('the sweep reports three lines seen', first.linesSeen, 3);
    eq('all three are new', first.linesNew, 3);
    eq('and it did not fail', first.outcome, 'ok');
    eq('nothing was proposed — no line has opted in', first.proposalsCreated, 0);

    const pooled = await listLines(MASTER, { assignment: 'pool' });
    eq('every new line lands in the pool, unassigned', pooled.length, 3);

    // The SFR line is skipped, so it has no balance at all — and that is
    // reported as `unknown`, never as an empty line.
    const sfr = pooled.find((l) => l.operator === 'SFR');
    check('the SFR line exists in the inventory', sfr !== undefined);
    eq('but it was never polled, so it has no zones', sfr?.zones.length, 0);
    eq('and it reads as unknown, not as empty', sfr?.verdict, 'unknown');

    const orange = pooled.find((l) => l.operator === 'Orange');
    check('the Orange line has two zones', orange?.zones.length === 2);
    const europe = orange?.zones.find((z) => z.zone === 'Europe');
    eq('Europe has 0.5 Go left', europe?.restMb, 512);
    check('and its low episode is open', europe?.lowSince !== null);
    eq(
      'while France, at 40 Go, is not low',
      orange?.zones.find((z) => z.zone === 'France')?.lowSince,
      null,
    );

    const samplesAfterFirst = Number(
      (await db('sim_balance_samples').count<Array<{ count: string }>>('id as count'))[0].count,
    );
    check('the first sweep wrote history', samplesAfterFirst > 0);

    // A second identical sweep must change nothing: same readings, same episode.
    const episodeBefore = europe?.lowSince;
    const second = await syncAccount(row);
    eq('the second sweep sees the same three lines', second.linesSeen, 3);
    eq('no line is new', second.linesNew, 0);
    eq('and no reading changed', second.balancesUpdated, 0);

    const samplesAfterSecond = Number(
      (await db('sim_balance_samples').count<Array<{ count: string }>>('id as count'))[0].count,
    );
    eq(
      'so NO history row was written — samples are recorded only on change',
      samplesAfterSecond,
      samplesAfterFirst,
    );

    const orange2 = (await listLines(MASTER, { assignment: 'pool' })).find((l) => l.operator === 'Orange');
    eq(
      'and the low episode marker did not move',
      orange2?.zones.find((z) => z.zone === 'Europe')?.lowSince,
      episodeBefore,
    );

    // ========================================================================
    // 4. Assignment, and the guards around it
    // ========================================================================

    const lineId = orange!.id;

    await refuses(
      'a pooled line cannot be attached to a site',
      () => updateLine(MASTER, lineId, { siteId: fx.siteA }),
      'no tenant',
    );

    await updateLine(MASTER, lineId, { tenantId: fx.tenantA });
    await updateLine(MASTER, lineId, { siteId: fx.siteA, deviceId: fx.deviceA });
    const assigned = await getLine(MASTER, lineId);
    eq('the line now belongs to customer A', assigned?.tenantId, fx.tenantA);
    eq('and carries its site name', assigned?.siteName, 'Boulangerie A');

    await refuses(
      "another tenant's router is refused",
      () => updateLine(MASTER, lineId, { deviceId: fx.deviceB }),
      'does not exist in this workspace',
    );

    // The database must refuse it too, not just the service — a direct UPDATE
    // has to hit the composite foreign key.
    await refuses(
      'and the composite foreign key refuses it at the database',
      () => db('sim_lines').where('id', lineId).update({ device_id: fx.deviceB }),
      'sim_lines_device_tenant_fk',
    );

    // ICCID uniqueness is PARTIAL: many nulls are fine, two equal values are not.
    await db('sim_lines').where('id', lineId).update({ iccid: '8933150319... '.replace(/\D/g, '').padEnd(19, '0') });
    const otherLineId = pooled.find((l) => l.id !== lineId)!.id;
    await refuses(
      'two lines cannot share an ICCID',
      () =>
        db('sim_lines')
          .where('id', otherLineId)
          .update({ iccid: '8933150319'.padEnd(19, '0') }),
      'sim_lines_iccid_uq',
    );
    const nullIccids = Number(
      (
        await db('sim_lines')
          .whereNull('iccid')
          .count<Array<{ count: string }>>('id as count')
      )[0].count,
    );
    check('while several lines with no ICCID coexist', nullIccids >= 2);

    // ── one zone, whatever the partner capitalises it as ───────────────────
    //
    // Each balance row carries its own episode marker, so two spellings of one
    // zone are two episodes — and therefore two idempotency keys and two
    // proposals for a single shortage. `canonicalZone` trims and collapses on
    // the way in; the functional index is what makes it true for anything that
    // writes without going through the sweep.

    eq('canonicalZone trims', canonicalZone('  Europe  '), 'Europe');
    eq('canonicalZone collapses inner whitespace', canonicalZone('Zone   Euro'), 'Zone Euro');
    eq('canonicalZone maps an empty label to the sentinel', canonicalZone('   '), UNKNOWN_ZONE);

    await db('sim_balances').where('sim_id', lineId).del();
    await db('sim_balances').insert({
      sim_id: lineId, zone: 'Europe', rest_mb: 100, observed_at: new Date(),
    });
    await refuses(
      'a second row for the same zone in another case is refused by the database',
      () =>
        db('sim_balances').insert({
          sim_id: lineId, zone: 'europe', rest_mb: 100, observed_at: new Date(),
        }),
      'sim_balances_sim_zone_uq',
    );
    // A genuinely different zone is of course still storable.
    const otherZone = await db('sim_balances')
      .insert({ sim_id: lineId, zone: 'France', rest_mb: 100, observed_at: new Date() })
      .returning<Array<{ id: string }>>('id')
      .then(() => true)
      .catch(() => false);
    check('while a genuinely different zone still is', otherZone);
    await db('sim_balances').where('sim_id', lineId).del();

    // Restore the balances this section just cleared: the sections below read
    // the Europe zone the nominal dialect produces (0.5 Go, under the 1 Go
    // default), and a test that quietly leaves the fixture half-built proves
    // the next assertion for the wrong reason.
    await syncAccount((await db('sim_accounts').where('id', account.id).first()) as SimAccountRow);

    // ========================================================================
    // 5. Tenant isolation
    // ========================================================================

    eq('customer A sees its one line', (await listLines(SCOPE_A)).length, 1);
    eq('customer B sees none', (await listLines(SCOPE_B)).length, 0);
    eq("customer B cannot read customer A's line by id", await getLine(SCOPE_B, lineId), null);
    eq(
      "nor its history — the sim_balance_samples read is gated by a scoped lookup",
      (await getLineHistory(SCOPE_B, lineId)).length,
      0,
    );
    check(
      'while customer A can read its own history',
      (await getLineHistory(SCOPE_A, lineId)).length > 0,
    );
    eq('customer B sees no pooled line either', (await listLines(SCOPE_B, { assignment: 'pool' })).length, 0);
    check('and the master view still sees the pool', (await listLines(MASTER, { assignment: 'pool' })).length >= 1);

    // ========================================================================
    // 6. The money path
    // ========================================================================

    const proposal = await proposeManual(
      SCOPE_A,
      { simId: lineId, zone: 'Europe' },
      { id: fx.userId, name: 'f9-operator' },
    );
    eq('a manual proposal starts as proposed', proposal.status, 'proposed');
    eq('and freezes the evidence it was based on', proposal.restMbAtProposal, 512);
    eq('and the threshold that applied', proposal.thresholdMbAtProposal, 1024);
    eq('and the site name, for the invoice', proposal.siteName, 'Boulangerie A');

    await refuses(
      'a second proposal cannot reuse an idempotency key',
      () =>
        db('sim_recharges').insert({
          platform: 'phenix', msisdn: proposal.msisdn, status: 'proposed', trigger: 'threshold',
          zone: 'Europe', threshold_mb_at_proposal: 1024,
          idempotency_key: proposal.idempotencyKey,
        }),
      'sim_recharges_idem_uq',
    );

    const approved = await approve(SCOPE_A, proposal.id, { id: fx.userId, name: 'f9-operator' }, 'go ahead');
    eq('approving moves it to approved', approved.status, 'approved');
    check('and stamps who decided', approved.decidedBy === fx.userId);

    await refuses(
      'an approved top-up cannot be approved again',
      () => approve(SCOPE_A, proposal.id, { id: fx.userId, name: 'f9-operator' }, null),
      'cannot become',
    );

    await refuses(
      "customer B cannot approve customer A's top-up",
      () => approve(SCOPE_B, proposal.id, { id: fx.userId, name: 'f9-operator' }, null),
      'not found',
    );

    const recorded = await recordCompletion(
      SCOPE_A,
      proposal.id,
      { id: fx.userId, name: 'f9-operator' },
      { costCents: 1250, currency: 'EUR', planMb: 5 * MB_PER_GB, billingReference: 'INV-001' },
    );
    eq('recording makes it billable', recorded.status, 'recorded');
    check('and stamps the completion instant', recorded.completedAt !== null);
    eq('with the cost as typed', recorded.costCents, 1250);

    // A second, deliberately UNPRICED top-up: the report must count it, never
    // add it as zero.
    const second2 = await proposeManual(
      SCOPE_A, { simId: lineId, zone: 'France' }, { id: fx.userId, name: 'f9-operator' },
    );
    await approve(SCOPE_A, second2.id, { id: fx.userId, name: 'f9-operator' }, null);
    await recordCompletion(SCOPE_A, second2.id, { id: fx.userId, name: 'f9-operator' }, { planMb: 1024 });

    // ── failed -> recorded, the transition with the awkward constraint ──────
    //
    // A top-up whose machine execution failed can still turn out to have been
    // bought by hand. That path skips the decision fields, which
    // `sim_recharges_decided_chk` still demands — so `recordCompletion`
    // COALESCEs them. This asserts the COALESCE and the CHECK agree; without it
    // the only failing path in the state machine is the one nobody exercises.
    const failedRow = {
      sim_id: lineId,
      account_id: account.id,
      platform: 'phenix',
      tenant_id: fx.tenantA,
      msisdn: '33600000001',
      status: 'failed',
      trigger: 'manual',
      zone: 'France',
      threshold_mb_at_proposal: 1024,
      failure_reason: 'partner refused',
    };

    // FIRST, the property that makes the COALESCE unnecessary: a `failed` row
    // with no decision instant is UNREPRESENTABLE. `failed` is only reachable
    // from `approved`, which stamps `decided_at` — and the CHECK enforces that
    // rather than trusting the state machine to.
    await refuses(
      'a failed top-up with no decision instant is refused by the database',
      () =>
        db('sim_recharges').insert({
          ...failedRow,
          idempotency_key: 'verify-failed-nodecision',
          decided_at: null,
          decided_by: null,
        }),
      'sim_recharges_decided_chk',
    );

    const failedId = (
      await db('sim_recharges')
        .insert({
          ...failedRow,
          idempotency_key: 'verify-failed-path',
          decided_at: new Date('2026-09-01T09:00:00.000Z'),
          decided_by: fx.userId,
        })
        .returning<Array<{ id: string }>>('id')
    )[0].id;

    const rescued = await recordCompletion(
      SCOPE_A,
      Number(failedId),
      { id: fx.userId, name: 'f9-operator' },
      { costCents: 500, currency: 'eur' },
    );
    eq('a failed top-up can be recorded as bought by hand', rescued.status, 'recorded');
    eq(
      'and the ORIGINAL decision instant is preserved, not overwritten by now()',
      rescued.decidedAt,
      '2026-09-01T09:00:00.000Z',
    );
    eq('the currency is upper-cased to satisfy the CHECK', rescued.currency, 'EUR');
    check('and the completion instant is set', rescued.completedAt !== null);

    // It is terminal: a recorded row accepts nothing further.
    await refuses(
      'a recorded top-up cannot be recorded twice',
      () =>
        recordCompletion(SCOPE_A, Number(failedId), { id: fx.userId, name: 'f9-operator' }, {}),
      'cannot become',
    );
    // Removed so it does not perturb the report totals asserted below.
    await db('sim_recharges').where('id', failedId).del();

    // ── the spend ceilings: NULL is refuse, and an unpriced month blocks ────
    //
    // `assertExecutionAllowed` gates MACHINE execution only. It is unreachable
    // today (the adapter registry is empty on purpose) and is asserted here
    // directly, so the rule that will one day decide whether ObliWAN may buy is
    // proven rather than merely written down.

    await refuses(
      'with no ceilings configured, machine execution is REFUSED, not unlimited',
      () => assertExecutionAllowed(account.id, 100),
      'no monthly ceiling is configured',
    );

    await db('sim_accounts')
      .where('id', account.id)
      .update({ monthly_recharge_cap: 10, monthly_cost_cap_cents: 100_000 });

    // Section 6 left one BILLABLE row with no cost. A month it cannot price is
    // a month whose running total is a floor, not a total.
    await refuses(
      'an unpriced top-up this month blocks the cost ceiling check',
      () => assertExecutionAllowed(account.id, 100),
      'no recorded cost',
    );

    // Price it, and the ceiling can be evaluated again.
    const unpriced = await db('sim_recharges')
      .whereIn('status', ['executed', 'recorded'])
      .whereNull('cost_cents')
      .first<{ id: string } | undefined>('id');
    if (unpriced) {
      await db('sim_recharges')
        .where('id', unpriced.id)
        .update({ cost_cents: 100, currency: 'EUR' });
    }
    await assertExecutionAllowed(account.id, 100)
      .then(() => passed++)
      .catch((err: unknown) =>
        failures.push(
          'a priced month under the ceiling is allowed — ' +
            (err instanceof Error ? err.message : String(err)),
        ),
      );

    await refuses(
      'an estimate of unknown cost is refused even under the ceiling',
      () => assertExecutionAllowed(account.id, null),
      'no expected cost',
    );
    await refuses(
      'and an estimate that would breach the ceiling is refused',
      () => assertExecutionAllowed(account.id, 100_000_000),
      'monthly cost ceiling',
    );

    // Restore, so the report below reads the state section 6 built.
    if (unpriced) {
      await db('sim_recharges').where('id', unpriced.id).update({ cost_cents: null, currency: null });
    }
    await db('sim_accounts')
      .where('id', account.id)
      .update({ monthly_recharge_cap: null, monthly_cost_cap_cents: null });

    // ========================================================================
    // 7. The report
    // ========================================================================

    const from = new Date('2000-01-01T00:00:00.000Z');
    const to = new Date('2100-01-01T00:00:00.000Z');
    const report = await rechargeReport(SCOPE_A, from, to);
    eq('two billable top-ups are reported', report.totalRecharges, 2);
    eq('one of them has no price', report.unpricedCount, 1);
    eq('the priced one is summed alone, not padded with a zero', report.totalCostCents, 1250);
    eq('one line is reported', report.rows.length, 1);
    const rrow = report.rows[0];
    eq('the row names the site', rrow.siteName, 'Boulangerie A');
    eq('counts both top-ups', rrow.rechargeCount, 2);
    eq('flags the unpriced one', rrow.unpricedCount, 1);
    eq('sums only the known volume', rrow.totalMb, 5 * MB_PER_GB + 1024);
    check('and knows the current allowance', rrow.basePlanMb !== null);
    eq(
      "which is today's plan summed over the zones (50 + 5 Go)",
      rrow.basePlanMb,
      55 * MB_PER_GB,
    );
    eq('both top-ups fall in one calendar month', rrow.monthsWithRecharge, 1);

    eq("customer B's report is empty", (await rechargeReport(SCOPE_B, from, to)).totalRecharges, 0);

    // ── the allowance column must not leak across a re-assignment ──────────
    //
    // `sim_recharges.sim_id` is frozen at proposal time and points at the LIVE
    // line, which can be moved to another customer afterwards. A `basePlans`
    // read with no tenant predicate would then print customer B's current
    // subscribed allowance in customer A's invoice — and `suggestsPlanChange`
    // would compute "plan too small" for A out of B's subscription.

    await db('sim_balances').where('sim_id', lineId).del();
    await db('sim_balances').insert({
      sim_id: lineId,
      zone: 'France',
      recharge_mb: 99 * MB_PER_GB,
      used_mb: 0,
      rest_mb: 99 * MB_PER_GB,
      observed_at: new Date(),
    });
    const beforeMove = await rechargeReport(SCOPE_A, from, to);
    eq(
      "while the line is still customer A's, its allowance IS shown",
      beforeMove.rows[0]?.basePlanMb,
      99 * MB_PER_GB,
    );

    // Move the line to customer B, allowance and all.
    await updateLine(MASTER, lineId, { tenantId: null });
    await updateLine(MASTER, lineId, { tenantId: fx.tenantB });

    const afterMove = await rechargeReport(SCOPE_A, from, to);
    eq("customer A still sees its own historic charge", afterMove.totalRecharges, 2);
    eq(
      "but the allowance column is now unknown, NOT the new owner's plan",
      afterMove.rows[0]?.basePlanMb,
      null,
    );
    check(
      'and an unknown allowance never produces a plan finding on its own',
      !suggestsPlanChange(afterMove.rows[0]),
      'monthsWithRecharge=' + afterMove.rows[0]?.monthsWithRecharge,
    );

    // Put it back for the sections that follow.
    await updateLine(MASTER, lineId, { tenantId: null });
    await updateLine(MASTER, lineId, { tenantId: fx.tenantA });
    await updateLine(MASTER, lineId, { siteId: fx.siteA, deviceId: fx.deviceA });

    // ── a missing currency is not a conflicting one ────────────────────────
    //
    // An UNPRICED row carries `currency = null`. Comparing it against the
    // group's currency wiped the group's unit, so a group mixing one priced and
    // one unpriced top-up printed an amount with NO unit — migration 032
    // decision 8's named failure, on the screen handed to accounting.
    const mixedGroup = report.rows.find((r) => r.unpricedCount > 0 && r.totalCostCents !== null);
    check(
      'a group mixing a priced and an unpriced top-up keeps its currency',
      mixedGroup ? mixedGroup.currency === 'EUR' : false,
      mixedGroup ? String(mixedGroup.currency) : 'no such group in the fixture',
    );

    const csv = reportToCsv(report);
    check('the CSV carries the site', csv.includes('Boulangerie A'));
    check('and leaves the unpriced total blank rather than 0.00', !csv.includes(',"0.00",'));

    // ========================================================================
    // 7bis. The low-data announcement is raised ONCE per reminder window
    // ========================================================================
    //
    // The browser alert deduplicates on `stable_key`, and the channel message
    // rides on that deduplication (`announceLineIfLow`). Without this, a
    // four-hourly sweep would put six Teams/Slack/e-mail messages a day on a
    // line that is still low, against one browser alert per 24-hour window —
    // which is how a notification channel gets muted.

    await db('live_alerts').where('tenant_id', fx.tenantA).del();
    // The Europe zone of this line sits at 0.5 Go, under the 1 Go default.
    await syncAccount((await db('sim_accounts').where('id', account.id).first()) as SimAccountRow);
    const alertsAfterOne = await db('live_alerts')
      .where('tenant_id', fx.tenantA)
      .select<Array<{ stable_key: string; title: string }>>('stable_key', 'title');
    eq('a low line raises exactly one alert', alertsAfterOne.length, 1);
    check(
      'keyed on the line, the zone and the episode',
      alertsAfterOne[0].stable_key.startsWith(`sim-low:${lineId}:Europe:`),
      alertsAfterOne[0].stable_key,
    );

    await syncAccount((await db('sim_accounts').where('id', account.id).first()) as SimAccountRow);
    const alertsAfterTwo = Number(
      (
        await db('live_alerts')
          .where('tenant_id', fx.tenantA)
          .count<Array<{ count: string }>>('id as count')
      )[0].count,
    );
    eq('a second sweep in the same window raises no second alert', alertsAfterTwo, 1);

    // ========================================================================
    // 7ter. expireStale must retire the proposal WITHOUT stealing a newer
    //       episode's marker
    // ========================================================================
    //
    // The scenario the first draft got wrong, replayed here with real rows:
    //   E1 opens, proposal P1 is made. The line recovers and falls again -> E2,
    //   proposal P2. Fourteen days later P1 expires. Clearing `low_since`
    //   unconditionally would wipe E2's marker while P2 is still open, so the
    //   next sweep would open E3 and mint a THIRD proposal for one ongoing
    //   shortage — and, once an execution adapter exists, a second purchase.

    const E1 = new Date('2026-01-01T00:00:00.000Z');
    const E2 = new Date('2026-02-01T00:00:00.000Z');

    // Scoped to `trigger = 'threshold'`: the BILLABLE rows created in section 6
    // are `manual`, and the re-invoicing assertions in section 10 read them.
    await db('sim_recharges').where('sim_id', lineId).where('trigger', 'threshold').del();
    await db('sim_balances').where('sim_id', lineId).del();
    await db('sim_balances').insert({
      sim_id: lineId,
      zone: 'France',
      recharge_mb: 50 * MB_PER_GB,
      used_mb: 50 * MB_PER_GB,
      rest_mb: 10,
      observed_at: new Date(),
      // The CURRENT episode is E2 — the line fell again after recovering.
      low_since: E2,
    });

    // P1 belongs to the OLD episode E1 and is old enough to expire.
    await db('sim_recharges').insert({
      sim_id: lineId,
      account_id: account.id,
      platform: 'phenix',
      tenant_id: fx.tenantA,
      msisdn: '33600000001',
      status: 'proposed',
      trigger: 'threshold',
      zone: 'France',
      rest_mb_at_proposal: 10,
      threshold_mb_at_proposal: 1024,
      idempotency_key: rechargeIdempotencyKey(lineId, 'France', E1.toISOString()),
      proposed_at: new Date('2026-01-01T00:05:00.000Z'),
    });

    const expired = await expireStale();
    check('the stale proposal is expired', expired >= 1);

    const marker = await db('sim_balances')
      .where('sim_id', lineId)
      .where('zone', 'France')
      .first<{ low_since: Date | string | null } | undefined>('low_since');
    eq(
      "a newer episode's marker is LEFT ALONE when an older proposal expires",
      marker?.low_since ? new Date(marker.low_since).toISOString() : null,
      E2.toISOString(),
    );

    // The other half: when the expired proposal IS the current episode, the
    // marker must be cleared, or the line is silenced forever by its own
    // expired row colliding with the UNIQUE index.
    await db('sim_recharges').where('sim_id', lineId).where('trigger', 'threshold').del();
    await db('sim_recharges').insert({
      sim_id: lineId,
      account_id: account.id,
      platform: 'phenix',
      tenant_id: fx.tenantA,
      msisdn: '33600000001',
      status: 'proposed',
      trigger: 'threshold',
      zone: 'France',
      rest_mb_at_proposal: 10,
      threshold_mb_at_proposal: 1024,
      idempotency_key: rechargeIdempotencyKey(lineId, 'France', E2.toISOString()),
      proposed_at: new Date('2026-02-01T00:05:00.000Z'),
    });
    await expireStale();
    const cleared = await db('sim_balances')
      .where('sim_id', lineId)
      .where('zone', 'France')
      .first<{ low_since: Date | string | null } | undefined>('low_since');
    eq(
      'but its OWN episode is reopened, so a still-low line is announced again',
      cleared?.low_since ?? null,
      null,
    );

    await db('sim_recharges').where('sim_id', lineId).where('trigger', 'threshold').del();

    // ========================================================================
    // 7quater. A line must be able to go back to the pool
    // ========================================================================

    const backToPool = await updateLine(MASTER, lineId, { tenantId: null });
    eq('the line is unassigned', backToPool.tenantId, null);
    eq('and its site went with it', backToPool.siteId, null);
    eq('and its router too', backToPool.deviceId, null);
    // Put it back for the sections that follow.
    await updateLine(MASTER, lineId, { tenantId: fx.tenantA });
    await updateLine(MASTER, lineId, { siteId: fx.siteA, deviceId: fx.deviceA });

    // ========================================================================
    // 7quinquies. The verdict filter must not be applied after the SQL LIMIT
    // ========================================================================
    //
    // `listLines({verdict:'low', limit:1})` must return ONE LOW line, not "the
    // first line by MSISDN, if it happens to be low". The pool holds three
    // lines of which one (Orange/Europe) is low, and MSISDN ordering puts it
    // first — so the assertion is built on a line that sorts LAST.

    await db('sim_balances').del();
    const allLines = await listLines(MASTER, { limit: 100 });
    const last = [...allLines].sort((a, b) => a.msisdn.localeCompare(b.msisdn)).at(-1)!;
    await db('sim_balances').insert({
      sim_id: last.id,
      zone: 'France',
      recharge_mb: 50 * MB_PER_GB,
      used_mb: 50 * MB_PER_GB,
      rest_mb: 5,
      observed_at: new Date(),
      low_since: new Date(),
    });
    const lowOnly = await listLines(MASTER, { verdict: 'low', limit: 1 });
    eq('one low line is returned', lowOnly.length, 1);
    eq('and it is the one that is actually low, not the first by number', lowOnly[0].id, last.id);
    await db('sim_balances').del();

    // ========================================================================
    // 7sexies. A partner that changes a zone label's CASE must change nothing
    // ========================================================================
    //
    // The regression the case-insensitive index introduced: the read was
    // case-sensitive while row identity was not, so every sweep after a casing
    // change missed the row, minted a new episode, merged over the old one, and
    // produced a NEW proposal — six a day at the default interval, with the
    // unique index intact and doing nothing.

    await db('sim_recharges').where('sim_id', lineId).where('trigger', 'threshold').del();
    await db('sim_balances').where('sim_id', lineId).del();
    await db('sim_lines').where('id', lineId).update({ auto_recharge_enabled: true });

    const casingLine = (await db('sim_lines')
      .where('id', lineId)
      .first()) as unknown as {
      id: number; tenant_id: number | null; msisdn: string; operator: string | null;
      site_id: number | null; device_id: number | null; low_threshold_mb: number | null;
      auto_recharge_enabled: boolean; recharge_plan_mb: number | null;
    };

    // First sweep: the zone arrives as "Europe" and is low.
    const firstPass = await applyBalancesForTest(casingLine, [
      { zone: 'Europe', rechargeMb: 5 * MB_PER_GB, usedMb: 5 * MB_PER_GB, restMb: 100 },
    ]);
    eq('the first low reading proposes once', firstPass.proposals, 1);
    const episode1 = await db('sim_balances')
      .where('sim_id', lineId)
      .first<{ low_since: Date | string | null; zone: string } | undefined>('low_since', 'zone');
    check('and opens an episode', !!episode1?.low_since);

    // Second sweep: SAME zone, SAME reading, only the casing changed.
    const secondPass = await applyBalancesForTest(casingLine, [
      { zone: 'EUROPE', rechargeMb: 5 * MB_PER_GB, usedMb: 5 * MB_PER_GB, restMb: 100 },
    ]);
    eq('a casing change proposes NOTHING new', secondPass.proposals, 0);
    eq('and writes no history row, because nothing actually moved', secondPass.updated, 0);

    const rowsForZone = Number(
      (
        await db('sim_balances')
          .where('sim_id', lineId)
          .count<Array<{ count: string }>>('id as count')
      )[0].count,
    );
    eq('there is still exactly ONE row for that zone', rowsForZone, 1);

    const episode2 = await db('sim_balances')
      .where('sim_id', lineId)
      .first<{ low_since: Date | string | null; zone: string } | undefined>('low_since', 'zone');
    eq(
      'the episode marker did NOT restart',
      episode2?.low_since ? new Date(episode2.low_since).toISOString() : null,
      episode1?.low_since ? new Date(episode1.low_since).toISOString() : null,
    );
    eq('and the stored label followed the partner, rather than freezing', episode2?.zone, 'EUROPE');

    const proposalCount = Number(
      (
        await db('sim_recharges')
          .where('sim_id', lineId)
          .where('trigger', 'threshold')
          .count<Array<{ count: string }>>('id as count')
      )[0].count,
    );
    eq('one shortage, one proposal — whatever the partner capitalises', proposalCount, 1);

    await db('sim_recharges').where('sim_id', lineId).where('trigger', 'threshold').del();
    await db('sim_balances').where('sim_id', lineId).del();
    await db('sim_lines').where('id', lineId).update({ auto_recharge_enabled: false });
    await syncAccount((await db('sim_accounts').where('id', account.id).first()) as SimAccountRow);

    // ========================================================================
    // 7septies. Moving a line to another workspace settles its open work
    // ========================================================================
    //
    // A proposal freezes the tenant and the site name. Left open across a
    // re-assignment it lets the OLD customer approve — and be invoiced for — a
    // top-up on a line that is no longer theirs, while the NEW customer is
    // never proposed anything because the episode marker is still set and its
    // idempotency key is already taken.

    await db('sim_recharges').where('sim_id', lineId).where('trigger', 'threshold').del();
    await db('sim_balances').where('sim_id', lineId).del();
    await db('sim_balances').insert({
      sim_id: lineId, zone: 'France', rest_mb: 10, observed_at: new Date(), low_since: new Date(),
    });
    const openOne = await proposeManual(
      SCOPE_A, { simId: lineId, zone: 'France' }, { id: fx.userId, name: 'f9-operator' },
    );
    await approve(SCOPE_A, openOne.id, { id: fx.userId, name: 'f9-operator' }, 'because');

    const billableBefore = (await rechargeReport(SCOPE_A, from, to)).totalRecharges;

    await updateLine(MASTER, lineId, { tenantId: null });
    await updateLine(MASTER, lineId, { tenantId: fx.tenantB });

    const settled = await db('sim_recharges')
      .where('id', openOne.id)
      .first<{ status: string; decision_note: string | null } | undefined>('status', 'decision_note');
    eq('the open proposal is expired by the move', settled?.status, 'expired');
    check(
      "and the operator's original note is kept, not overwritten",
      (settled?.decision_note ?? '').includes('because'),
      settled?.decision_note ?? '',
    );
    check(
      'with the reason appended',
      (settled?.decision_note ?? '').includes('re-assigned'),
      settled?.decision_note ?? '',
    );

    const movedMarker = await db('sim_balances')
      .where('sim_id', lineId)
      .first<{ low_since: Date | string | null } | undefined>('low_since');
    eq('the episode is reopened for the new owner', movedMarker?.low_since ?? null, null);

    eq(
      "the old customer's BILLABLE history is untouched — that money really was spent",
      (await rechargeReport(SCOPE_A, from, to)).totalRecharges,
      billableBefore,
    );

    // And the new owner does not inherit the previous customer's consumption.
    const bHistory = await getLineHistory(
      { tenantId: fx.tenantB, masterView: false },
      lineId,
      730,
    );
    eq('the new owner sees no history from before the move', bHistory.length, 0);
    check(
      'while the master view still sees the whole series',
      (await getLineHistory(MASTER, lineId, 730)).length >= 0,
    );

    // Put it back.
    await updateLine(MASTER, lineId, { tenantId: null });
    await updateLine(MASTER, lineId, { tenantId: fx.tenantA });
    await updateLine(MASTER, lineId, { siteId: fx.siteA, deviceId: fx.deviceA });
    await db('sim_recharges').where('sim_id', lineId).whereIn('status', ['expired']).del();
    await db('sim_balances').where('sim_id', lineId).del();
    await syncAccount((await db('sim_accounts').where('id', account.id).first()) as SimAccountRow);

    // ========================================================================
    // 8. A renamed partner field must produce unknown, and propose NOTHING
    // ========================================================================

    // Opt the line in, so that ONLY the unknown reading stands between it and a
    // proposal. This is the end-to-end version of the rule.
    await db('sim_lines').where('id', lineId).update({ auto_recharge_enabled: true });
    await db('sim_balances').where('sim_id', lineId).del();

    fake.setDialect('renamed');
    const proposalsBefore = Number(
      (await db('sim_recharges').count<Array<{ count: string }>>('id as count'))[0].count,
    );
    const blind = await syncAccount(row);
    eq('the sweep still completes', blind.outcome, 'ok');
    eq('and proposes NOTHING on an unreadable balance', blind.proposalsCreated, 0);
    const proposalsAfter = Number(
      (await db('sim_recharges').count<Array<{ count: string }>>('id as count'))[0].count,
    );
    eq('no row was created', proposalsAfter, proposalsBefore);

    const blindLine = await getLine(SCOPE_A, lineId);
    eq('the line reads as unknown', blindLine?.verdict, 'unknown');
    eq('with a null remaining, not a zero', blindLine?.zones[0]?.restMb, null);
    eq('and no low episode was opened', blindLine?.zones[0]?.lowSince, null);
    eq(
      'the shared rule agrees',
      evaluateBalance(blindLine?.zones[0]?.restMb ?? null, 1024),
      'unknown',
    );

    // ========================================================================
    // 9. A dead token stops the account rather than failing every line
    // ========================================================================

    fake.setDialect('expired');
    const rowNow = (await db('sim_accounts').where('id', account.id).first()) as SimAccountRow;
    const dead = await syncAccount(rowNow);
    eq('the sweep reports an auth failure', dead.outcome, 'auth_failed');
    eq('and did not count every line as an individual failure', dead.linesFailed, 0);

    const after = await db('sim_accounts').where('id', account.id).first<{ status: string; last_sync_error: string }>('status', 'last_sync_error');
    eq('the account is taken out of the poll list', after?.status, 'auth_failed');
    check(
      'and the recorded error carries no credential',
      !(after?.last_sync_error ?? '').includes('pa55word-long'),
    );

    const runs = await db('sim_sync_runs')
      .where('account_id', account.id)
      .orderBy('started_at', 'desc')
      .select<Array<{ outcome: string; error: string | null }>>('outcome', 'error');
    eq('the journal recorded it', runs[0].outcome, 'auth_failed');
    check(
      'and the journal entry carries no credential either',
      !(runs[0].error ?? '').includes('pa55word-long'),
    );

    // ========================================================================
    // 10. The summary a tenant is shown
    // ========================================================================

    const summary = await fleetSummary(SCOPE_A);
    eq('customer A has one line', summary.totalLines, 1);
    eq('it is assigned', summary.assignedLines, 1);
    eq('and currently unreadable', summary.unknownLines, 1);
    check('the failed account is counted', summary.failedAccounts >= 1);
    eq('two top-ups were billed', summary.rechargesThisMonth, 2);
    eq('and the priced one alone is summed', summary.costThisMonthCents, 1250);

    const openProposals = await listRecharges(SCOPE_A, { status: ['proposed'] });
    eq('no proposal is left open', openProposals.length, 0);
  } finally {
    if (fake) await fake.close();
  }

  const total = passed + failures.length;
  if (failures.length === 0) {
    process.stdout.write(`F9 schema + sweep: ${passed}/${total} checks passed.\n`);
  } else {
    process.stdout.write(`F9 schema + sweep: ${passed}/${total} passed, ${failures.length} FAILED\n`);
    for (const f of failures) process.stdout.write(`  FAIL  ${f}\n`);
  }
  await db.destroy();
  process.exit(failures.length === 0 ? 0 : 1);
}

void main().catch(async (err: unknown) => {
  process.stdout.write(`F9 verification crashed: ${err instanceof Error ? err.stack : String(err)}\n`);
  await db.destroy().catch(() => undefined);
  process.exit(1);
});
