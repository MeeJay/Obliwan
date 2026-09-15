/**
 * ObliWAN F9 — the rules and the wire, verified WITHOUT a database.
 *
 *   npx tsx src/services/sim/testing/f9-rules.verify.ts
 *
 * ┌─ WHAT THIS FILE PROVES, AND WHAT IT CANNOT ───────────────────────────────┐
 * │ It proves the two things that decide whether this feature is safe:        │
 * │                                                                          │
 * │   1. THE RULE. `evaluateBalance`, `worstZone`, `lineVerdict`, the unit    │
 * │      conversions, the recharge state machine, the idempotency key and     │
 * │      the plan-sizing heuristic are pure functions, and every boundary     │
 * │      that decides whether money can be spent is asserted here.            │
 * │                                                                          │
 * │   2. THE WIRE. The Phenix connector is run against a protocol-level fake  │
 * │      speaking eight dialects, including one where every balance field has │
 * │      been renamed and one that answers an unrecognisable envelope. The    │
 * │      connector must produce `null` and an ERROR respectively — never a    │
 * │      zero and never an empty fleet.                                       │
 * │                                                                          │
 * │ It proves NOTHING about the real Phenix API. Every field name in the fake │
 * │ is the same guess the connector makes, read off the same Angular bundle.  │
 * │ What it does prove is that being WRONG about those names degrades to      │
 * │ "unknown" instead of to "empty" — which is the property that matters when │
 * │ the guess turns out to be wrong.                                          │
 * │                                                                          │
 * │ It also proves nothing about tenant scoping, the schema CHECKs, or the    │
 * │ sweep's persistence: those need PostgreSQL and live in                    │
 * │ `f9-sim.verify.ts`.                                                       │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import {
  MB_PER_GB,
  SIM_PLATFORMS,
  SIM_PLATFORM_CATALOG,
  SIM_RECHARGE_STATUSES,
  canRechargeTransition,
  effectiveThresholdMb,
  evaluateBalance,
  formatData,
  gbToMb,
  isRechargeBillable,
  isReadingStale,
  isRechargeTerminal,
  lineVerdict,
  stalenessHorizonMs,
  rechargeIdempotencyKey,
  simPlatformInfo,
  suggestsPlanChange,
  worstZone,
  type SimRechargeReportRow,
  type SimRechargeStatus,
  type SimZoneBalance,
} from '@obliwan/shared';
import { expiryFromJwt, partnerRefFromJwt, stripQuery } from '../phenix.connector';
import { cfastConnector } from '../cfast.connector';
import { assertCatalogMatchesRegistry, canExecuteRecharge, getConnector, isPollable } from '../registry';
import { SIM_RECHARGE_ADAPTERS, SimConnectorError, scrub } from '../types';
import { startFakePhenix } from './fakePhenixApi';

let passed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail?: string): void {
  if (condition) {
    passed += 1;
    return;
  }
  failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
}

function eq(name: string, actual: unknown, expected: unknown): void {
  check(name, Object.is(actual, expected), `got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}

function zone(z: Partial<SimZoneBalance> & { zone: string }): SimZoneBalance {
  return {
    rechargeMb: null,
    usedMb: null,
    restMb: null,
    observedAt: '2026-01-01T00:00:00.000Z',
    lowSince: null,
    ...z,
  };
}

async function main(): Promise<void> {
  // ==========================================================================
  // 1. Units — the conversion that must never invent a number
  // ==========================================================================

  eq('gbToMb(1) = 1024', gbToMb(1), MB_PER_GB);
  eq('gbToMb("0,5") handles a decimal comma', gbToMb('0,5'), 512);
  eq('gbToMb(null) is null', gbToMb(null), null);
  eq('gbToMb(undefined) is null', gbToMb(undefined), null);
  eq('gbToMb("") is null, NOT 0', gbToMb(''), null);
  // `Number(' ')` is 0, not NaN. A padded or blanked partner field must not
  // become "0 Go remaining" — the fleet-wide false emergency of decision 2.
  eq('gbToMb(" ") is null, NOT 0', gbToMb(' '), null);
  eq('gbToMb("   ") is null, NOT 0', gbToMb('   '), null);
  eq('gbToMb(a tab) is null, NOT 0', gbToMb(String.fromCharCode(9)), null);
  eq('gbToMb(a newline) is null, NOT 0', gbToMb(String.fromCharCode(10)), null);
  eq('gbToMb(a non-breaking space) is null, NOT 0', gbToMb(String.fromCharCode(160)), null);
  eq('gbToMb(" 12,5 ") parses through the padding', gbToMb(' 12,5 '), Math.round(12.5 * MB_PER_GB));
  eq('gbToMb(NaN) is null', gbToMb(Number.NaN), null);
  eq('gbToMb(Infinity) is null', gbToMb(Number.POSITIVE_INFINITY), null);
  eq('gbToMb("abc") is null, NOT 0', gbToMb('abc'), null);
  eq('gbToMb(-1) is null, NOT 0', gbToMb(-1), null);
  // 0 IS a legitimate reading: a line the partner says is empty really is empty.
  // It must survive as 0 and not be flattened into "unknown".
  eq('gbToMb(0) is 0 — a real, readable empty line', gbToMb(0), 0);
  eq('formatData(null) renders an em dash', formatData(null), '—');
  eq('formatData(0) renders 0 Mo, not a dash', formatData(0), '0 Mo');

  // ==========================================================================
  // 2. The verdict — where "unknown" must never become "low"
  // ==========================================================================

  eq('null remaining is unknown', evaluateBalance(null, 1024), 'unknown');
  eq('NaN remaining is unknown', evaluateBalance(Number.NaN, 1024), 'unknown');
  eq('0 remaining is low', evaluateBalance(0, 1024), 'low');
  eq('exactly at the threshold is low', evaluateBalance(1024, 1024), 'low');
  eq('one MB above the threshold is ok', evaluateBalance(1025, 1024), 'ok');
  // A zero threshold means "only warn when the line is actually empty" and must
  // stay expressible: it is the setting an operator picks for a line they never
  // want to top up.
  eq('threshold 0: an empty line is still low', evaluateBalance(0, 0), 'low');
  eq('threshold 0: any remaining data is ok', evaluateBalance(1, 0), 'ok');

  // ==========================================================================
  // 3. worstZone — an unreadable zone must not drag a line down
  // ==========================================================================

  eq('worstZone of no zones is null', worstZone([]), null);
  eq(
    'worstZone of only-unreadable zones is null',
    worstZone([zone({ zone: 'A' }), zone({ zone: 'B' })]),
    null,
  );
  check(
    'worstZone ignores unreadable zones and picks the smallest readable one',
    worstZone([
      zone({ zone: 'unreadable' }),
      zone({ zone: 'big', restMb: 40_000 }),
      zone({ zone: 'small', restMb: 100 }),
    ])?.zone === 'small',
  );
  // The defect this guards: an unreadable zone treated as 0 would win every
  // comparison and report the whole fleet as empty.
  eq(
    'a line with one unreadable zone and one healthy zone is ok',
    lineVerdict([zone({ zone: 'x' }), zone({ zone: 'y', restMb: 40_000 })], 1024).verdict,
    'ok',
  );
  eq(
    'a line whose every zone is unreadable is unknown',
    lineVerdict([zone({ zone: 'x' }), zone({ zone: 'y' })], 1024).verdict,
    'unknown',
  );

  eq('no override falls back to the global default', effectiveThresholdMb(null, 1024), 1024);
  eq('undefined override falls back too', effectiveThresholdMb(undefined, 1024), 1024);
  // 0 is a real override and must NOT be swallowed by a `||` fallback.
  eq('an override of 0 is honoured, not treated as absent', effectiveThresholdMb(0, 1024), 0);

  // ==========================================================================
  // 3bis. A reading has an age, and an old reading is not an answer
  // ==========================================================================
  //
  // Decision 2 used to be enforced only when the connector PARSED a field. Once
  // a value reached the table it was immortal: a dead token, a zone the partner
  // stopped returning and a skipped operator all kept their last good reading
  // forever, so a fleet nobody had read for six weeks rendered `ok`.

  const NOW = Date.parse('2026-06-01T12:00:00.000Z');
  const HORIZON = stalenessHorizonMs(240); // the default four-hour sweep
  eq('the horizon is three missed sweeps', HORIZON, 240 * 60_000 * 3);

  const fresh = { now: NOW, maxAgeMs: HORIZON };
  const recent = new Date(NOW - 60_000).toISOString();
  const ancient = new Date(NOW - HORIZON - 60_000).toISOString();

  check('a recent reading is not stale', !isReadingStale(recent, fresh));
  check('a reading past the horizon is', isReadingStale(ancient, fresh));
  check('and an unparseable instant is not evidence of freshness', isReadingStale('nonsense', fresh));

  eq(
    'a healthy but ANCIENT reading is unknown, not ok',
    lineVerdict([zone({ zone: 'France', restMb: 40_000, observedAt: ancient })], 1024, fresh)
      .verdict,
    'unknown',
  );
  check(
    'and it says WHY — stale, not never-read',
    lineVerdict([zone({ zone: 'France', restMb: 40_000, observedAt: ancient })], 1024, fresh).stale,
  );
  eq(
    'a LOW but ancient reading also stops being an answer, so it cannot propose',
    lineVerdict([zone({ zone: 'France', restMb: 10, observedAt: ancient })], 1024, fresh).verdict,
    'unknown',
  );
  eq(
    'while a fresh reading is judged normally',
    lineVerdict([zone({ zone: 'France', restMb: 40_000, observedAt: recent })], 1024, fresh)
      .verdict,
    'ok',
  );
  eq(
    'one fresh zone rescues a line whose other zone went stale',
    lineVerdict(
      [
        zone({ zone: 'old', restMb: 10, observedAt: ancient }),
        zone({ zone: 'new', restMb: 40_000, observedAt: recent }),
      ],
      1024,
      fresh,
    ).verdict,
    'ok',
  );
  eq(
    'a line that was NEVER read is unknown and NOT flagged stale',
    lineVerdict([zone({ zone: 'France', observedAt: recent })], 1024, fresh).stale,
    false,
  );
  // Omitting the argument keeps the age-blind behaviour, for callers that have
  // already filtered — asserted so the default cannot change by accident.
  eq(
    'without a freshness argument, age is ignored',
    lineVerdict([zone({ zone: 'France', restMb: 40_000, observedAt: ancient })], 1024).verdict,
    'ok',
  );

  // ==========================================================================
  // 4. The recharge state machine
  // ==========================================================================

  check('proposed -> approved is legal', canRechargeTransition('proposed', 'approved'));
  check('proposed -> rejected is legal', canRechargeTransition('proposed', 'rejected'));
  check('approved -> recorded is legal', canRechargeTransition('approved', 'recorded'));
  check('failed -> recorded is legal', canRechargeTransition('failed', 'recorded'));
  check('proposed -> recorded is REFUSED', !canRechargeTransition('proposed', 'recorded'));
  check('proposed -> executed is REFUSED', !canRechargeTransition('proposed', 'executed'));
  check('recorded -> anything is REFUSED', !canRechargeTransition('recorded', 'approved'));
  check('rejected -> approved is REFUSED', !canRechargeTransition('rejected', 'approved'));

  for (const s of SIM_RECHARGE_STATUSES) {
    const terminal = isRechargeTerminal(s);
    const expected = s === 'proposed' || s === 'approved' || s === 'failed' ? false : true;
    eq(`terminality of ${s}`, terminal, expected);
  }

  const billable: SimRechargeStatus[] = ['executed', 'recorded'];
  for (const s of SIM_RECHARGE_STATUSES) {
    eq(`billable(${s})`, isRechargeBillable(s), billable.includes(s));
  }

  // ==========================================================================
  // 5. Idempotency — one proposal per low episode
  // ==========================================================================

  const k1 = rechargeIdempotencyKey(7, 'France', '2026-03-01T00:00:00.000Z');
  const k2 = rechargeIdempotencyKey(7, ' france ', '2026-03-01T00:00:00.000Z');
  eq('zone case and whitespace do not mint a second key', k1, k2);
  check(
    'a new episode mints a different key',
    k1 !== rechargeIdempotencyKey(7, 'France', '2026-04-01T00:00:00.000Z'),
  );
  check(
    'a different line mints a different key',
    k1 !== rechargeIdempotencyKey(8, 'France', '2026-03-01T00:00:00.000Z'),
  );
  check(
    'an empty zone label still produces a usable key',
    rechargeIdempotencyKey(7, '   ', '2026-03-01T00:00:00.000Z').includes('unknown'),
  );

  // ==========================================================================
  // 6. Plan sizing — the heuristic must not fire on an unknown allowance
  // ==========================================================================

  const row = (over: Partial<SimRechargeReportRow>): SimRechargeReportRow => ({
    siteId: 1, siteName: 'Site', tenantId: 1, tenantName: 'T', simId: 1,
    msisdn: '33600000001', platform: 'phenix', operator: 'Orange',
    rechargeCount: 1, totalMb: null, totalCostCents: null, currency: null,
    firstRechargeAt: '2026-01-01T00:00:00.000Z', lastRechargeAt: '2026-01-01T00:00:00.000Z',
    unpricedCount: 0, unknownVolumeCount: 0, basePlanMb: null, monthsWithRecharge: 1, ...over,
  });

  check('one month is not a pattern', !suggestsPlanChange(row({ monthsWithRecharge: 1 })));
  check('two months is not a pattern', !suggestsPlanChange(row({ monthsWithRecharge: 2 })));
  check('three months is a pattern', suggestsPlanChange(row({ monthsWithRecharge: 3 })));
  check(
    'an unknown allowance never flags on volume alone',
    !suggestsPlanChange(row({ basePlanMb: null, totalMb: 999_999, monthsWithRecharge: 1 })),
  );
  check(
    'topped-up volume reaching the allowance in one month flags',
    suggestsPlanChange(row({ basePlanMb: 10_000, totalMb: 10_000, monthsWithRecharge: 1 })),
  );
  // WINDOW-INDEPENDENCE: the same two months of top-ups must give the same
  // verdict whichever window the operator selected. A cumulative comparison
  // against a single-month allowance would make the finding count track the
  // dropdown instead of the fleet.
  check(
    'two months totalling one month of allowance does NOT flag',
    !suggestsPlanChange(row({ basePlanMb: 10_000, totalMb: 10_000, monthsWithRecharge: 2 })),
  );
  check(
    'two months each reaching the allowance DOES flag',
    suggestsPlanChange(row({ basePlanMb: 10_000, totalMb: 20_000, monthsWithRecharge: 2 })),
  );
  check(
    'a zero-month row never divides by zero',
    !suggestsPlanChange(row({ basePlanMb: 10_000, totalMb: 50_000, monthsWithRecharge: 0 })),
  );
  check(
    'a zero allowance does not divide the fleet into findings',
    !suggestsPlanChange(row({ basePlanMb: 0, totalMb: 5_000, monthsWithRecharge: 1 })),
  );

  // ==========================================================================
  // 7. The registry and the coverage matrix must agree
  // ==========================================================================

  const problems = assertCatalogMatchesRegistry();
  check('catalogue and registry agree', problems.length === 0, problems.join('; '));
  check('phenix is pollable', isPollable('phenix'));

  // CFAST now declares `pull`, corrected against the vendor's public
  // documentation. The whole point of the second condition in `isPollable` is
  // that this correction changed a DESCRIPTION and must not have changed
  // BEHAVIOUR: a connector whose every read throws must never reach the sweep,
  // or it raises a four-hourly error nobody can clear and paints a permanent
  // partner-unhealthy banner on every dashboard.
  eq('cfast declares pull, like the partner really works', getConnector('cfast').ingestion.join(','), 'pull');
  check('yet cfast is NOT pollable, because its read is not implemented', !isPollable('cfast'));
  check(
    'and the reason is the catalogue flag, not the ingestion kind',
    simPlatformInfo('cfast').readImplemented === false,
  );
  // The rule stated the other way round, so a future connector cannot be armed
  // by editing the catalogue alone either.
  check(
    'every pollable platform has an implemented read',
    SIM_PLATFORMS.every((p) => !isPollable(p) || simPlatformInfo(p).readImplemented),
  );
  check(
    'no platform can execute a recharge today',
    Object.keys(SIM_RECHARGE_ADAPTERS).length === 0 &&
      !canExecuteRecharge('phenix') &&
      !canExecuteRecharge('cfast'),
  );
  for (const info of SIM_PLATFORM_CATALOG) {
    check(
      `${info.platform} declares rechargeImplemented=false while the adapter registry is empty`,
      info.rechargeImplemented === false,
    );
    check(`${info.platform} carries a non-empty note`, info.note.trim().length > 0);
  }
  eq('simPlatformInfo resolves phenix', simPlatformInfo('phenix').label, 'Phenix Partner');

  // CFAST refuses, loudly, with a code the sweep understands.
  let cfastRefused = false;
  try {
    await cfastConnector.open({
      accountId: 1, baseUrl: null, partnerRef: null, authMode: 'token',
      credential: { authMode: 'token', token: 'x'.repeat(30) },
    });
  } catch (err) {
    cfastRefused = err instanceof SimConnectorError && err.code === 'NOT_IMPLEMENTED';
  }
  check('cfast refuses with NOT_IMPLEMENTED', cfastRefused);

  // ==========================================================================
  // 8. Secret scrubbing
  // ==========================================================================

  eq(
    'scrub removes a credential literal',
    scrub('login failed for hunter2secret', ['hunter2secret']),
    'login failed for ***',
  );
  check(
    'a SimConnectorError scrubs in its constructor',
    !new SimConnectorError('token=abcdef123456 rejected', 'AUTH_FAILED', 'phenix', {
      secrets: ['abcdef123456'],
    }).message.includes('abcdef123456'),
  );
  // A two-character secret is not replaced: doing so would mangle every message
  // into unreadability, and a two-character password has a larger problem.
  eq('scrub leaves very short literals alone', scrub('abcdef', ['ab']), 'abcdef');

  // ==========================================================================
  // 8bis. The MSISDN must not leave the connector inside a URL
  // ==========================================================================
  //
  // `RestTransport.httpError` embeds the request PATH in its message, and this
  // connector's paths carry `?partenaireId=..&msisdn=..`. That message reaches
  // `logger.warn` and `sim_sync_runs.error`, which the account screen renders.

  eq(
    'a query string is replaced, the path kept',
    stripQuery('/GsmApi/GetSdtrConso?partenaireId=4242&msisdn=33600000001 -> HTTP 429'),
    '/GsmApi/GetSdtrConso?… -> HTTP 429',
  );
  check(
    'so no subscriber number survives',
    !stripQuery('/GsmApi/GetSdtrConso?msisdn=33600000001 -> HTTP 500').includes('33600000001'),
  );
  eq(
    'a message with no path is left alone',
    stripQuery('REST phenix-mb-api.netcom-group.fr: timed out'),
    'REST phenix-mb-api.netcom-group.fr: timed out',
  );

  // ==========================================================================
  // 9. The wire — the connector against the fake, dialect by dialect
  // ==========================================================================

  const fake = await startFakePhenix();
  try {
    const ctx = {
      accountId: 1,
      baseUrl: fake.baseUrl,
      partnerRef: null,
      authMode: 'password' as const,
      credential: { authMode: 'password' as const, username: 'user', password: 'pa55word-long' },
    };

    // ── nominal ──────────────────────────────────────────────────────────────
    let session = await getConnector('phenix').open(ctx);
    eq('partner id is decoded from the token, not from the form', session.partnerRef, '4242');
    check('token expiry is read from the exp claim', session.tokenExpiresAt !== null);

    const listing = await session.listLines();
    const lines = listing.lines;
    eq('three lines are listed', lines.length, 3);
    eq('and the partner declared no total on the nominal dialect', listing.declaredTotal, null);
    eq('operator is read', lines[0].operator, 'Orange');
    eq('client code is read', lines[0].clientCode, 'CLI-001');
    eq('ICCID is null — this endpoint does not carry one', lines[0].iccid, null);
    eq('an "Actif" line reads as active', lines[0].status, 'active');
    eq('a "Suspendu" line reads as suspended', lines[2].status, 'suspended');

    let balances = await session.fetchBalances('33600000001');
    eq('two zones on the nominal dialect', balances.length, 2);
    eq('France remaining is 40 Go in MB', balances[0].restMb, 40 * MB_PER_GB);
    eq('Europe remaining is 0.5 Go in MB', balances[1].restMb, 512);
    eq(
      'the Europe zone is low against a 1 Go threshold',
      evaluateBalance(balances[1].restMb, 1024),
      'low',
    );
    await session.close();

    // ── renamed — THE defect this feature exists to survive ──────────────────
    fake.setDialect('renamed');
    session = await getConnector('phenix').open(ctx);
    balances = await session.fetchBalances('33600000001');
    eq('the zone label is still readable', balances[0].zone, 'France');
    eq('a renamed remaining field yields null, NOT 0', balances[0].restMb, null);
    eq('a renamed used field yields null, NOT 0', balances[0].usedMb, null);
    eq('a renamed plan field yields null, NOT 0', balances[0].rechargeMb, null);
    eq(
      'and the line is therefore unknown, which never proposes a top-up',
      lineVerdict(balances.map((b) => zone({ ...b, lowSince: null })), 1024).verdict,
      'unknown',
    );
    await session.close();

    // ── partial ─────────────────────────────────────────────────────────────
    fake.setDialect('partial');
    session = await getConnector('phenix').open(ctx);
    balances = await session.fetchBalances('33600000001');
    eq('the readable zone is read', balances[0].restMb, 30 * MB_PER_GB);
    eq('the zone missing its remaining field is null', balances[1].restMb, null);
    eq(
      'the line is judged on its readable zone alone',
      lineVerdict(balances.map((b) => zone({ ...b, lowSince: null })), 1024).verdict,
      'ok',
    );
    await session.close();

    // ── stringy ─────────────────────────────────────────────────────────────
    fake.setDialect('stringy');
    session = await getConnector('phenix').open(ctx);
    balances = await session.fetchBalances('33600000001');
    eq('a numeric string with a decimal comma parses', balances[0].restMb, 512);
    await session.close();

    // ── envelope ────────────────────────────────────────────────────────────
    fake.setDialect('envelope');
    session = await getConnector('phenix').open(ctx);
    eq('rows wrapped in {items:[]} are found', (await session.listLines()).lines.length, 3);
    eq('so are wrapped balances', (await session.fetchBalances('33600000001')).length, 1);
    await session.close();

    // ── garbage — must be an ERROR, never an empty fleet ─────────────────────
    fake.setDialect('garbage');
    session = await getConnector('phenix').open(ctx);
    let unreadable = false;
    try {
      await session.listLines();
    } catch (err) {
      unreadable = err instanceof SimConnectorError && err.code === 'UNREADABLE';
    }
    check('an unrecognisable envelope is UNREADABLE, not an empty fleet', unreadable);
    await session.close();

    // ── expired ─────────────────────────────────────────────────────────────
    fake.setDialect('expired');
    session = await getConnector('phenix').open(ctx);
    let authFailed = false;
    try {
      await session.listLines();
    } catch (err) {
      authFailed = err instanceof SimConnectorError && err.code === 'AUTH_FAILED';
    }
    check('a 401 on a read is AUTH_FAILED, which stops the whole account', authFailed);
    await session.close();

    // ── otp — password mode cannot complete the challenge ────────────────────
    fake.setDialect('otp');
    let otpRefused: SimConnectorError | null = null;
    try {
      await getConnector('phenix').open(ctx);
    } catch (err) {
      otpRefused = err instanceof SimConnectorError ? err : null;
    }
    check('password mode fails on an OTP account', otpRefused?.code === 'AUTH_FAILED');
    check(
      'and the message names the one-time code as the likely cause',
      (otpRefused?.message ?? '').toLowerCase().includes('one-time code'),
    );
    check(
      'the password never appears in the error message',
      !(otpRefused?.message ?? '').includes('pa55word-long'),
    );

    // ── the token never leaks into an error ──────────────────────────────────
    fake.setDialect('expired');
    const tokenCtx = {
      ...ctx,
      authMode: 'token' as const,
      credential: { authMode: 'token' as const, token: 'supersecrettoken-abcdefghij' },
    };
    session = await getConnector('phenix').open(tokenCtx);
    let leaked = false;
    try {
      await session.listLines();
    } catch (err) {
      leaked = err instanceof Error && err.message.includes('supersecrettoken-abcdefghij');
    }
    check('a stored token never appears in a connector error', !leaked);
    await session.close();

    // ── a truncated page must be REPORTED, never read as a smaller fleet ────
    //
    // `GetLigneGsmByFilterPaged` is paged and the connector reads page one.
    // Above the partner's page size the remainder is invisible — never
    // inserted, never balance-read, never invoiced — and the sweep would report
    // `ok` over a fleet that had silently shrunk.
    fake.setDialect('truncated');
    session = await getConnector('phenix').open(ctx);
    const truncated = await session.listLines();
    eq('page one came back', truncated.lines.length, 1);
    eq('and the partner declared the real total', truncated.declaredTotal, 3);
    check(
      'so the truncation is detectable',
      truncated.declaredTotal !== null && truncated.declaredTotal > truncated.lines.length,
    );
    await session.close();

    // ── a 429 must not carry the subscriber's number out with it ────────────
    //
    // `RestTransport` throws on 429 and 5xx instead of returning, so the
    // connector's `res.statusCode >= 400` branch — the only place `stripQuery`
    // was applied to a read — was never reached for them. The raw error escaped
    // with the full request path into `logger.warn` and `sim_sync_runs.error`:
    // one customer MSISDN per rate-limited line, per sweep.
    fake.setDialect('ratelimited');
    session = await getConnector('phenix').open(ctx);
    let rateLimitMessage = '';
    try {
      await session.fetchBalances('33612345678');
    } catch (err) {
      rateLimitMessage = err instanceof Error ? err.message : String(err);
    }
    check('a 429 on a balance read raises an error', rateLimitMessage !== '');
    check(
      'and the MSISDN is NOT in it',
      !rateLimitMessage.includes('33612345678'),
      rateLimitMessage,
    );
    check(
      'nor is the partner id, which travels in the same query string',
      !rateLimitMessage.includes('partenaireId=4242'),
      rateLimitMessage,
    );
    check(
      'while the call that failed is still identifiable',
      rateLimitMessage.includes('GetSdtrConso'),
      rateLimitMessage,
    );
    // The same for the line listing, which has no MSISDN but does carry the
    // partner id — and which takes the identical throwing path.
    let listMessage = '';
    try {
      await session.listLines();
    } catch (err) {
      listMessage = err instanceof Error ? err.message : String(err);
    }
    check('the line listing is wrapped the same way', !listMessage.includes('partenaireId=4242'));
    await session.close();

    // ── the JWT helpers ─────────────────────────────────────────────────────
    const issued = fake.tokensSeen[0];
    check('the fake saw a bearer token', typeof issued === 'string' && issued.length > 20);
    eq('partnerRefFromJwt reads the claim', partnerRefFromJwt(issued), '4242');
    check('expiryFromJwt returns an ISO instant', (expiryFromJwt(issued) ?? '').endsWith('Z'));
    eq('partnerRefFromJwt on nonsense is null', partnerRefFromJwt('not-a-jwt'), null);
    eq('expiryFromJwt on nonsense is null', expiryFromJwt('not-a-jwt'), null);
  } finally {
    await fake.close();
  }

  // ==========================================================================
  // Verdict
  // ==========================================================================

  const total = passed + failures.length;
  if (failures.length === 0) {
    process.stdout.write(`F9 rules + wire: ${passed}/${total} checks passed.\n`);
  } else {
    process.stdout.write(`F9 rules + wire: ${passed}/${total} passed, ${failures.length} FAILED\n`);
    for (const f of failures) process.stdout.write(`  FAIL  ${f}\n`);
  }
  // ┌─ `process.exitCode`, NOT `process.exit()` ──────────────────────────────┐
  // │ Exiting while the fake HTTP server and the undici agents are still      │
  // │ tearing down aborts the process on Windows with                         │
  // │ `Assertion failed: !(handle->flags & UV_HANDLE_CLOSING)` — AFTER the    │
  // │ verdict has been printed. A human then reads "104/104 passed" and CI    │
  // │ reads a crash, which is the worst possible pair. Letting the loop drain │
  // │ gives the real exit code.                                                │
  // └────────────────────────────────────────────────────────────────────────┘
  process.exitCode = failures.length === 0 ? 0 : 1;
  // Safety net for a handle that never closes. `unref`'d, so it cannot by
  // itself keep the process alive — it only fires if something else did.
  setTimeout(() => process.exit(process.exitCode ?? 0), 5000).unref();
}

void main().catch((err: unknown) => {
  process.stdout.write(`F9 verification crashed: ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exitCode = 1;
  setTimeout(() => process.exit(1), 5000).unref();
});
