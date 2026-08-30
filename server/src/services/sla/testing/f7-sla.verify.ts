/**
 * ObliWAN F7 — the calculated SLA, verified against a real PostgreSQL.
 *
 * WHAT THIS FILE PROVES, AND WHAT IT CANNOT
 *
 * It proves the ARITHMETIC and the REFUSALS: the classification of a second,
 * the exclusion of our own management plane, the exclusion and separate
 * accounting of declared maintenance, the difference between "0 %" and "no
 * measurement", the objective bracket, the tenant isolation, and the
 * schema-level catches that make a fabricated 100 % impossible to store. It
 * runs the REAL services against the REAL schema of migration 026 — the partial
 * unique indexes, the CHECK constraints and the freeze trigger are all live,
 * and several assertions below exist only to make the database refuse
 * something.
 *
 * It proves NOTHING about MikroTik. There is no router on this machine and
 * there never was one on this project. The `ppp_sessions` rows are hand-written
 * in the shape `applySessionUp` writes them, and the `reachability_verdicts`
 * rows in the shape `evaluateReachability` produces. "A concentrator outage is
 * excluded" is a strong statement about this arithmetic and says nothing about
 * whether a real CHR gets classified `CONCENTRATOR_DEGRADED` in the field —
 * that is K7's claim, made and tested at M2.
 *
 * THE FOUR ACCEPTANCE SCENARIOS OF THE BRIEF ARE CHECKED VERBATIM:
 *   a site with real outages       -> the availability figure is exact
 *   a concentrator outage          -> EXCLUDED, and traced with its reason
 *   a declared maintenance window  -> excluded and counted SEPARATELY
 *   an empty period                -> "no measurement", and NEVER 100 %
 *
 *   DATABASE_URL=… npx tsx src/services/sla/testing/f7-sla.verify.ts
 */

import {
  DEFAULT_VERDICT_VALIDITY_SECONDS, SLA_ALGORITHM_VERSION, SLA_EXCLUDED_KINDS,
  SLA_MAX_PERIOD_DAYS, SLA_MIN_OBJECTIVE_PERCENT,
  applyMaintenance, buildDeviceTimeline, clampVerdictValiditySeconds,
  combineSiteTimeline, evaluateSla, expandMaintenanceWindow, normalizeIntervals,
  reasonForVerdict, stateForVerdict, summariseExclusions, totalsFor,
  validateObjectivePercent,
  type SlaSegment,
} from '@obliwan/shared/dist/sla';
import { REACHABILITY_VERDICTS } from '@obliwan/shared/dist/telemetry';
import { CAPABILITIES } from '@obliwan/shared';
import { db } from '../../../db';
import { AppError } from '../../../middleware/errorHandler';
import slaRoutes from '../../../routes/sla.routes';
import {
  computeAvailability, computeSiteAvailability, deleteObjective, getReport,
  getReportIntervals, issueReport, listObjectives, listReports, setObjective,
} from '../index';

const TENANT = 1;
const OTHER_TENANT = 2;

const HOUR = 3_600_000;
const DAY = 86_400_000;

// A fixed, boring week. Nothing here reads the clock: a harness whose result
// depends on the day it runs is a harness that fails once and is then ignored.
const T0 = Date.parse('2026-03-02T00:00:00.000Z'); // a Monday
const T_END = T0 + 7 * DAY;

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

function eq(label: string, actual: unknown, expected: unknown): void {
  ok(label, Object.is(actual, expected), `got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
}

async function refuses(label: string, fn: () => Promise<unknown>, needle: string): Promise<void> {
  try {
    await fn();
    ok(label, false, 'it was accepted');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    ok(label, message.toLowerCase().includes(needle.toLowerCase()), message.slice(0, 160));
  }
}

function section(title: string): void {
  console.log(`\n${title}\n${'-'.repeat(title.length)}`);
}

// ============================================================================
// Seeding
// ============================================================================

interface Fleet {
  concentratorId: number;
  siteId: number;
  deviceId: number;
  username: string;
}

async function reset(): Promise<void> {
  await db.raw('TRUNCATE sla_report_intervals, sla_reports, sla_objectives RESTART IDENTITY CASCADE');
  await db.raw('TRUNCATE ppp_sessions, reachability_verdicts RESTART IDENTITY CASCADE');
  // `audit_log` is NOT truncated. Migration 019 makes a row younger than 400
  // days undeletable BY ANYBODY, and that refusal is the ledger working as
  // designed — a harness is not a reason to weaken it. The assertion below
  // reads the newest matching row instead of assuming an empty table.
  await db('devices').update({ concentrator_id: null });
  await db('devices').del();
  await db('sites').del();
}

async function seedTenants(): Promise<void> {
  await db('tenants')
    .insert([
      { id: TENANT, name: 'Default', slug: 'default' },
      { id: OTHER_TENANT, name: 'Other MSP customer', slug: 'other' },
    ])
    .onConflict('id')
    .ignore();
}

async function seedSite(
  tenantId: number,
  code: string,
  concentratorId: number,
  opts: { timezone?: string; maintenanceWindow?: unknown } = {},
): Promise<Fleet> {
  const [site] = await db('sites')
    .insert({
      tenant_id: tenantId,
      code,
      name: `Site ${code}`,
      timezone: opts.timezone ?? 'Europe/Paris',
      maintenance_window: opts.maintenanceWindow === undefined
        ? null
        : JSON.stringify(opts.maintenanceWindow),
    })
    .returning<Array<{ id: number }>>('id');

  const username = `${code}-ppp`;
  const [device] = await db('devices')
    .insert({
      tenant_id: tenantId,
      site_id: site.id,
      name: `${code}-router`,
      brand: 'mikrotik',
      family: 'mikrotik_routeros7',
      role: 'cpe',
      status: 'active',
      concentrator_id: concentratorId,
      ppp_username: username,
    })
    .returning<Array<{ id: number }>>('id');

  return { concentratorId, siteId: site.id, deviceId: device.id, username };
}

async function seedConcentrator(tenantId: number, name: string): Promise<number> {
  const [chr] = await db('devices')
    .insert({
      tenant_id: tenantId,
      name,
      brand: 'mikrotik',
      family: 'mikrotik_routeros7',
      role: 'concentrator',
      status: 'active',
    })
    .returning<Array<{ id: number }>>('id');
  return chr.id;
}

/** One `ppp_sessions` row, in the shape `applySessionUp` writes them. */
async function session(
  fleet: Pick<Fleet, 'concentratorId' | 'deviceId' | 'username'>,
  start: number,
  end: number | null,
  reason = 'test',
): Promise<void> {
  await db('ppp_sessions').insert({
    concentrator_id: fleet.concentratorId,
    device_id: fleet.deviceId,
    ppp_username: fleet.username,
    started_at: new Date(start),
    ended_at: end === null ? null : new Date(end),
    duration_seconds: end === null ? null : Math.round((end - start) / 1000),
    disconnect_reason: end === null ? null : reason,
  });
}

/** One `reachability_verdicts` row, in the shape `evaluateReachability` makes. */
async function verdict(deviceId: number, ts: number, v: string): Promise<void> {
  await db('reachability_verdicts').insert({
    device_id: deviceId,
    ts: new Date(ts),
    verdict: v,
    confidence: 0.5,
    reason: 'f7-fixture',
  });
}

// ============================================================================
// 1. Offline arithmetic — no database at all
// ============================================================================

function offlineSuite(): void {
  section('1. The classification of a second (pure, offline)');

  // -- The verdict map -----------------------------------------------------
  eq('UP is uptime', stateForVerdict('UP'), 'up');
  eq('WAN_FAILOVER is uptime (reachable, different path)', stateForVerdict('WAN_FAILOVER'), 'up');
  eq('SITE_DOWN is downtime', stateForVerdict('SITE_DOWN'), 'down');
  eq('CONCENTRATOR_DEGRADED is OUR fault, excluded',
    stateForVerdict('CONCENTRATOR_DEGRADED'), 'excluded_management');
  eq('TUNNEL_DOWN_SITE_UP is OUR fault, excluded',
    stateForVerdict('TUNNEL_DOWN_SITE_UP'), 'excluded_management');
  eq('UNREACHABLE carries NO opinion — neither up nor down',
    stateForVerdict('UNREACHABLE'), null);
  ok('every K7 verdict is decided explicitly (no silent default)',
    REACHABILITY_VERDICTS.every((v) => v === 'UNREACHABLE' || stateForVerdict(v) !== null));
  eq('the reason names the verdict that decided',
    reasonForVerdict('CONCENTRATOR_DEGRADED'), 'verdict_concentrator_degraded');
  eq('exactly two kinds leave the calculation, and they are published as data',
    SLA_EXCLUDED_KINDS.join(','), 'excluded_management,excluded_maintenance');

  // -- The device timeline --------------------------------------------------
  const from = T0;
  const to = T0 + 10 * HOUR;

  // Observed all ten hours (the CHR held sessions for other subscribers the
  // whole time); this device was connected for the first two and the last six.
  const timeline = buildDeviceTimeline({
    from,
    to,
    sessions: [{ start: from, end: from + 2 * HOUR }, { start: from + 4 * HOUR, end: to }],
    observation: [{ start: from, end: to }],
    verdicts: [],
    verdictValiditySeconds: DEFAULT_VERDICT_VALIDITY_SECONDS,
  });
  const t1 = totalsFor(timeline, from, to);
  eq('a gap while the concentrator WAS observing is downtime', t1.downSeconds, 2 * 3600);
  eq('  ... and the rest is uptime', t1.upSeconds, 8 * 3600);
  eq('  ... and nothing is unmeasured', t1.unmeasuredSeconds, 0);

  // The same gap, with NO proof we were watching.
  const blind = buildDeviceTimeline({
    from,
    to,
    sessions: [{ start: from, end: from + 2 * HOUR }, { start: from + 4 * HOUR, end: to }],
    observation: [],
    verdicts: [],
    verdictValiditySeconds: DEFAULT_VERDICT_VALIDITY_SECONDS,
  });
  const t2 = totalsFor(blind, from, to);
  eq('the SAME gap with no observation mask is UNMEASURED, not downtime',
    t2.downSeconds, 0);
  eq('  ... and lands in unmeasured', t2.unmeasuredSeconds, 2 * 3600);

  // CONCENTRATOR_DEGRADED samples covering the FIRST HOUR of the two-hour gap,
  // one every 15 minutes with a 15-minute validity. The second hour has no
  // sample at all and therefore stays downtime: an exclusion is only ever as
  // wide as the observations that justify it.
  const excluded = buildDeviceTimeline({
    from,
    to,
    sessions: [{ start: from, end: from + 2 * HOUR }, { start: from + 4 * HOUR, end: to }],
    observation: [{ start: from, end: to }],
    verdicts: [0, 900_000, 1_800_000, 2_700_000].map((d) => ({
      ts: from + 2 * HOUR + d, verdict: 'CONCENTRATOR_DEGRADED' as const,
    })),
    verdictValiditySeconds: 900,
  });
  const t3 = totalsFor(excluded, from, to);
  eq('a CONCENTRATOR_DEGRADED sample removes its seconds from BOTH sides',
    t3.excludedManagementSeconds, 3600);
  eq('  ... and the unsampled half of the gap is still downtime', t3.downSeconds, 3600);

  // A stale sample must not outlive the moment the tunnel came back.
  const stale = buildDeviceTimeline({
    from,
    to,
    sessions: [{ start: from, end: from + HOUR }, { start: from + 2 * HOUR, end: to }],
    observation: [{ start: from, end: to }],
    verdicts: [{ ts: from + 2 * HOUR - 600_000, verdict: 'CONCENTRATOR_DEGRADED' }],
    verdictValiditySeconds: 3600,
  });
  const tStale = totalsFor(stale, from, to);
  eq('a verdict is truncated by the next PPP session transition',
    tStale.excludedManagementSeconds, 600);
  eq('  ... so the exclusion never eats observed uptime',
    tStale.upSeconds, 3600 + 8 * 3600);

  // UNREACHABLE must not override the presence history.
  const unreachable = buildDeviceTimeline({
    from,
    to,
    sessions: [{ start: from, end: to }],
    observation: [{ start: from, end: to }],
    verdicts: [{ ts: from + HOUR, verdict: 'UNREACHABLE' }],
    verdictValiditySeconds: 3600,
  });
  const t4 = totalsFor(unreachable, from, to);
  eq('an UNREACHABLE sample does NOT erase an open session', t4.upSeconds, 10 * 3600);

  // A verdict is a POINT observation and expires.
  const expiring = buildDeviceTimeline({
    from,
    to,
    sessions: [],
    observation: [],
    verdicts: [{ ts: from, verdict: 'UP' }],
    verdictValiditySeconds: 900,
  });
  const t5 = totalsFor(expiring, from, to);
  eq('one UP sample buys 15 minutes, not ten hours', t5.upSeconds, 900);
  eq('  ... and the rest stays unmeasured', t5.unmeasuredSeconds, 10 * 3600 - 900);

  // -- Site precedence ------------------------------------------------------
  section('2. Combining devices into a site');
  const deviceA: SlaSegment[] = [
    { start: from, end: to, kind: 'down', reason: 'ppp_absent_while_concentrator_observing' },
  ];
  const deviceB: SlaSegment[] = [
    { start: from, end: from + HOUR, kind: 'up', reason: 'ppp_session_open' },
    { start: from + HOUR, end: to, kind: 'unmeasured', reason: 'no_observation' },
  ];
  const site = combineSiteTimeline([deviceA, deviceB], from, to);
  const t6 = totalsFor(site, from, to);
  eq('one router carrying traffic makes the SITE up', t6.upSeconds, 3600);
  eq('  ... and the rest is the other router being down', t6.downSeconds, 9 * 3600);

  const deviceC: SlaSegment[] = [
    { start: from, end: to, kind: 'excluded_management', reason: 'verdict_concentrator_degraded' },
  ];
  const t7 = totalsFor(combineSiteTimeline([deviceA, deviceC], from, to), from, to);
  eq('if ANY device proves the fault is ours, the site is not billed for it',
    t7.excludedManagementSeconds, 10 * 3600);
  eq('  ... and nothing is counted as downtime', t7.downSeconds, 0);

  eq('a site with no active device is unmeasured, NOT 100 %',
    totalsFor(combineSiteTimeline([], from, to), from, to).unmeasuredSeconds, 10 * 3600);

  // -- Totals balance -------------------------------------------------------
  const balanced = totalsFor(site, from, to);
  eq('the buckets add up to the period exactly',
    balanced.upSeconds + balanced.downSeconds + balanced.excludedManagementSeconds
      + balanced.excludedMaintenanceSeconds + balanced.unmeasuredSeconds,
    balanced.periodSeconds);

  // -- The verdict bracket --------------------------------------------------
  section('3. The objective is decided on the bracket');
  const nothing = evaluateSla(totalsFor([], from, to), 99.5);
  eq('a period with NO data has NO availability figure',
    nothing.availabilityPercent, null);
  eq('  ... its status says so', nothing.status, 'no_data');
  eq('  ... and the objective is INDETERMINATE, never met', nothing.objectiveVerdict, 'indeterminate');
  eq('  ... with the reason spelled out', nothing.verdictReason, 'no_measurement');

  const perfect = evaluateSla(
    totalsFor([{ start: from, end: to, kind: 'up', reason: 'ppp_session_open' }], from, to),
    99.5,
  );
  eq('a fully observed, fully up period is 100 %', perfect.availabilityPercent, 100);
  eq('  ... and the objective is met', perfect.objectiveVerdict, 'met');
  eq('  ... because even the worst case holds', perfect.worstCasePercent, 100);

  const halfBlind = evaluateSla(
    totalsFor([
      { start: from, end: from + 5 * HOUR, kind: 'up', reason: 'ppp_session_open' },
      { start: from + 5 * HOUR, end: to, kind: 'unmeasured', reason: 'no_observation' },
    ], from, to),
    99.5,
  );
  eq('half a period of gaps cannot buy a "met"', halfBlind.objectiveVerdict, 'indeterminate');
  eq('  ... the point estimate is still 100 %', halfBlind.availabilityPercent, 100);
  eq('  ... but the worst case is 50 %', halfBlind.worstCasePercent, 50);
  eq('  ... and the reason names the coverage', halfBlind.verdictReason, 'coverage_insufficient_to_decide');

  const clearlyMissed = evaluateSla(
    totalsFor([
      { start: from, end: from + 5 * HOUR, kind: 'up', reason: 'ppp_session_open' },
      { start: from + 5 * HOUR, end: to, kind: 'down', reason: 'verdict_site_down' },
    ], from, to),
    99.5,
  );
  eq('observed downtime alone can settle a MISS', clearlyMissed.objectiveVerdict, 'missed');
  eq('  ... even though the rest is unobserved', clearlyMissed.verdictReason,
    'observed_downtime_alone_breaches_objective');

  const noObjective = evaluateSla(
    totalsFor([{ start: from, end: to, kind: 'up', reason: 'ppp_session_open' }], from, to),
    null,
  );
  eq('no objective configured is not a default of 99.5', noObjective.objectiveVerdict, 'indeterminate');
  eq('  ... and says why', noObjective.verdictReason, 'no_objective_configured');

  // -- Maintenance expansion ------------------------------------------------
  section('4. Maintenance windows, expanded in the site timezone');
  const week = expandMaintenanceWindow(
    { days: [0], start: '02:00', end: '04:00' }, 'Europe/Paris', T0, T_END,
  );
  eq('a weekly 2-hour Sunday window covers 2 h of one week', totalMsOf(week.intervals) / HOUR, 2);
  eq('  ... and it parses cleanly', week.error, null);

  const wrapped = expandMaintenanceWindow(
    { days: [0], start: '22:00', end: '06:00' }, 'Europe/Paris', T0, T_END,
  );
  eq('a wrapping window is read the same way as the change scheduler reads it '
    + '(the day test applies to the instant)', totalMsOf(wrapped.intervals) / HOUR, 8);

  const broken = expandMaintenanceWindow(
    { days: ['fnord'], start: '02:00', end: '04:00' }, 'Europe/Paris', T0, T_END,
  );
  eq('an UNREADABLE window excludes NOTHING', broken.intervals.length, 0);
  ok('  ... and the report carries the parse error', (broken.error ?? '').includes('fnord'));

  const badTz = expandMaintenanceWindow(
    { days: [0], start: '02:00', end: '04:00', tz: 'Mars/Olympus' }, 'Europe/Paris', T0, T_END,
  );
  eq('an invalid timezone excludes NOTHING', badTz.intervals.length, 0);
  ok('  ... and says so', (badTz.error ?? '').includes('Mars/Olympus'));

  eq('no window at all excludes nothing',
    expandMaintenanceWindow(null, 'Europe/Paris', T0, T_END).intervals.length, 0);
  eq('a disabled window excludes nothing',
    expandMaintenanceWindow({ enabled: false, days: [0], start: '02:00', end: '04:00' },
      'Europe/Paris', T0, T_END).intervals.length, 0);

  // Maintenance beats everything and is counted apart.
  const overlaid = applyMaintenance(
    [{ start: from, end: to, kind: 'down', reason: 'ppp_absent_while_concentrator_observing' }],
    [{ start: from + HOUR, end: from + 3 * HOUR }],
  );
  const t8 = totalsFor(overlaid, from, to);
  eq('maintenance overrides downtime', t8.excludedMaintenanceSeconds, 2 * 3600);
  eq('  ... and is NOT merged into the management exclusion', t8.excludedManagementSeconds, 0);
  eq('  ... leaving the rest as downtime', t8.downSeconds, 8 * 3600);
  const lines = summariseExclusions(overlaid);
  eq('the exclusion summary names the reason', lines[0]?.reason, 'maintenance_window');

  // -- Caps -----------------------------------------------------------------
  section('5. Server-side caps on everything that could move a number');
  eq('the verdict-validity knob is clamped low', clampVerdictValiditySeconds(1), 60);
  eq('  ... and high', clampVerdictValiditySeconds(999_999_999), 21_600);
  eq('  ... and defaults when absent', clampVerdictValiditySeconds(undefined),
    DEFAULT_VERDICT_VALIDITY_SECONDS);
  try {
    validateObjectivePercent(0);
    ok('an objective of 0 is refused (it would make a blind period "met")', false);
  } catch (err) {
    ok('an objective of 0 is refused (it would make a blind period "met")',
      err instanceof Error && err.message.includes(String(SLA_MIN_OBJECTIVE_PERCENT)));
  }
  eq('99.5 survives validation', validateObjectivePercent(99.5), 99.5);
}

function totalMsOf(intervals: readonly { start: number; end: number }[]): number {
  return intervals.reduce((s, i) => s + (i.end - i.start), 0);
}

// ============================================================================
// 6..10 — against the real schema
// ============================================================================

async function main(): Promise<void> {
  offlineSuite();

  section('6. Real schema: a site with real outages');
  await seedTenants();
  await reset();

  const chr = await seedConcentrator(TENANT, 'chr-1');
  // A neighbour that stays connected for the whole week. It is what proves we
  // were watching — the observation mask.
  const witness = await seedSite(TENANT, 'WITNESS', chr);
  await session(witness, T0 - DAY, null);

  const alpha = await seedSite(TENANT, 'ALPHA', chr);
  // Connected all week except two outages: 3 h on Tuesday, 1 h on Friday.
  const out1 = T0 + DAY + 9 * HOUR;
  const out2 = T0 + 4 * DAY + 14 * HOUR;
  await session(alpha, T0 - DAY, out1, 'peer-timeout');
  await session(alpha, out1 + 3 * HOUR, out2, 'peer-timeout');
  await session(alpha, out2 + HOUR, null);

  await setObjective(TENANT, null, { objectivePercent: 99.5 }, null);

  const [report] = await computeAvailability({
    tenantId: TENANT, from: new Date(T0), to: new Date(T_END), siteIds: [alpha.siteId],
  });
  eq('downtime is exactly the two outages', report.outcome.totals.downSeconds, 4 * 3600);
  eq('uptime is the rest of the week',
    report.outcome.totals.upSeconds, 7 * 24 * 3600 - 4 * 3600);
  eq('nothing is unmeasured (the witness proves we were watching)',
    report.outcome.totals.unmeasuredSeconds, 0);
  eq('coverage is complete', report.outcome.status, 'complete');
  eq('availability is 4 h out of a week',
    report.outcome.availabilityPercent,
    Math.round(((7 * 24 - 4) / (7 * 24)) * 100 * 10_000) / 10_000);
  eq('99.5 % was NOT held', report.outcome.objectiveVerdict, 'missed');
  eq('the objective came from the tenant default', report.objectiveScope, 'tenant');
  eq('the algorithm version is stamped', report.algorithmVersion, SLA_ALGORITHM_VERSION);

  // -- A site override wins over the tenant default -------------------------
  await setObjective(TENANT, alpha.siteId, { objectivePercent: 95 }, null);
  const [relaxed] = await computeAvailability({
    tenantId: TENANT, from: new Date(T0), to: new Date(T_END), siteIds: [alpha.siteId],
  });
  eq('a per-site objective overrides the tenant default', relaxed.objectiveScope, 'site');
  eq('  ... and 95 % WAS held', relaxed.outcome.objectiveVerdict, 'met');
  eq('the two objectives are two rows, not seventeen', (await listObjectives(TENANT)).length, 2);
  await deleteObjective(TENANT, alpha.siteId);

  section('7. A concentrator outage is EXCLUDED and traced');
  const beta = await seedSite(TENANT, 'BETA', chr);
  // Connected all week, except a 6 h stretch during which K7 said the fault was
  // ours. The neighbour keeps the observation mask alive.
  const chrOut = T0 + 2 * DAY;
  await session(beta, T0 - DAY, chrOut, 'concentrator-restart');
  await session(beta, chrOut + 6 * HOUR, null);
  for (let t = chrOut; t < chrOut + 6 * HOUR; t += 600_000) {
    await verdict(beta.deviceId, t, 'CONCENTRATOR_DEGRADED');
  }

  const [betaReport] = await computeAvailability({
    tenantId: TENANT, from: new Date(T0), to: new Date(T_END), siteIds: [beta.siteId],
  });
  eq('the six hours are excluded, not billed',
    betaReport.outcome.totals.excludedManagementSeconds, 6 * 3600);
  eq('  ... and NOT counted as downtime', betaReport.outcome.totals.downSeconds, 0);
  eq('  ... so the site is at 100 %', betaReport.outcome.availabilityPercent, 100);
  eq('  ... and the objective is met', betaReport.outcome.objectiveVerdict, 'met');
  const mgmt = betaReport.exclusions.find((e) => e.kind === 'excluded_management');
  eq('the exclusion is REPORTED with its seconds', mgmt?.seconds, 6 * 3600);
  eq('  ... and with the K7 verdict that justified it',
    mgmt?.reason, 'verdict_concentrator_degraded');
  eq('the accountable period shrank by exactly the exclusion',
    betaReport.outcome.totals.accountableSeconds, 7 * 24 * 3600 - 6 * 3600);

  // TUNNEL_DOWN_SITE_UP is the same class of exclusion.
  const gamma = await seedSite(TENANT, 'GAMMA', chr);
  const tunnelOut = T0 + 3 * DAY;
  await session(gamma, T0 - DAY, tunnelOut, 'tunnel');
  await session(gamma, tunnelOut + 2 * HOUR, null);
  for (let t = tunnelOut; t < tunnelOut + 2 * HOUR; t += 600_000) {
    await verdict(gamma.deviceId, t, 'TUNNEL_DOWN_SITE_UP');
  }
  const [gammaReport] = await computeAvailability({
    tenantId: TENANT, from: new Date(T0), to: new Date(T_END), siteIds: [gamma.siteId],
  });
  eq('"our tunnel died while the site was up" is excluded too',
    gammaReport.outcome.totals.excludedManagementSeconds, 2 * 3600);
  eq('  ... and never counted against the customer',
    gammaReport.outcome.totals.downSeconds, 0);

  section('8. A declared maintenance window is excluded AND counted apart');
  const delta = await seedSite(TENANT, 'DELTA', chr, {
    timezone: 'Europe/Paris',
    // Sunday 02:00-04:00 Paris. 2026-03-08 is a Sunday inside the window.
    maintenanceWindow: { days: [0], start: '02:00', end: '04:00' },
  });
  // Down for the whole of that Sunday window and for one extra hour after it.
  const sundayStart = Date.parse('2026-03-08T01:00:00.000Z'); // 02:00 Paris (UTC+1)
  await session(delta, T0 - DAY, sundayStart, 'planned');
  await session(delta, sundayStart + 3 * HOUR, null);

  const [deltaReport] = await computeAvailability({
    tenantId: TENANT, from: new Date(T0), to: new Date(T_END), siteIds: [delta.siteId],
  });
  eq('the declared window is excluded',
    deltaReport.outcome.totals.excludedMaintenanceSeconds, 2 * 3600);
  eq('  ... the hour that overran it is NOT',
    deltaReport.outcome.totals.downSeconds, 3600);
  eq('  ... and maintenance is a SEPARATE line from the management exclusion',
    deltaReport.outcome.totals.excludedManagementSeconds, 0);
  const maint = deltaReport.exclusions.find((e) => e.kind === 'excluded_maintenance');
  eq('the maintenance exclusion is reported with its reason',
    maint?.reason, 'maintenance_window');
  eq('nothing failed to parse', deltaReport.maintenanceError, null);

  const epsilon = await seedSite(TENANT, 'EPSILON', chr, {
    maintenanceWindow: { days: ['fnord'], start: '02:00', end: '04:00' },
  });
  await session(epsilon, T0 - DAY, null);
  const [epsReport] = await computeAvailability({
    tenantId: TENANT, from: new Date(T0), to: new Date(T_END), siteIds: [epsilon.siteId],
  });
  eq('an unreadable window excludes NOTHING',
    epsReport.outcome.totals.excludedMaintenanceSeconds, 0);
  ok('  ... and the report carries the reason',
    (epsReport.maintenanceError ?? '').includes('fnord'));

  section('9. An empty period is "no measurement", NEVER 100 %');
  const zeta = await seedSite(TENANT, 'ZETA', chr);
  // No sessions at all for this device — but the concentrator IS observing
  // (the witness holds a session all week), so this is a real, proven outage.
  const [zetaReport] = await computeAvailability({
    tenantId: TENANT, from: new Date(T0), to: new Date(T_END), siteIds: [zeta.siteId],
  });
  eq('a device that never connected while we WERE watching is 0 %, not 100 %',
    zetaReport.outcome.availabilityPercent, 0);
  eq('  ... and that is a measurement', zetaReport.outcome.status, 'complete');

  // A period BEFORE anything was ever observed: nothing to measure.
  const [beforeTime] = await computeAvailability({
    tenantId: TENANT,
    from: new Date(T0 - 100 * DAY),
    to: new Date(T0 - 90 * DAY),
    siteIds: [zeta.siteId],
  });
  eq('a period before ObliWAN was watching has NO availability figure',
    beforeTime.outcome.availabilityPercent, null);
  eq('  ... it is "no_data"', beforeTime.outcome.status, 'no_data');
  eq('  ... it is NOT 100 %', beforeTime.outcome.availabilityPercent === 100, false);
  eq('  ... the objective cannot be met on it', beforeTime.outcome.objectiveVerdict, 'indeterminate');
  eq('  ... and every second of it is unmeasured',
    beforeTime.outcome.totals.unmeasuredSeconds, 10 * DAY / 1000);

  const eta = await seedSite(TENANT, 'ETA', chr);
  await db('devices').where({ id: eta.deviceId }).update({ concentrator_id: null });
  const [etaReport] = await computeAvailability({
    tenantId: TENANT, from: new Date(T0), to: new Date(T_END), siteIds: [eta.siteId],
  });
  eq('a device with no concentrator and no session is unmeasured, not down',
    etaReport.outcome.status, 'no_data');

  section('10. Tenant isolation');
  const otherChr = await seedConcentrator(OTHER_TENANT, 'other-chr');
  const other = await seedSite(OTHER_TENANT, 'OTHER', otherChr);
  await session(other, T0 - DAY, null);

  const mine = await computeAvailability({
    tenantId: TENANT, from: new Date(T0), to: new Date(T_END),
  });
  ok('the tenant-wide report never contains another customer\'s site',
    mine.every((r) => r.siteCode !== 'OTHER'), `${mine.length} sites`);
  await refuses(
    'asking for another customer\'s site by id is a 404, not a 403',
    () => computeSiteAvailability(TENANT, other.siteId, new Date(T0), new Date(T_END)),
    'not found',
  );
  await refuses(
    'setting an objective on another customer\'s site is a 404',
    () => setObjective(TENANT, other.siteId, { objectivePercent: 99 }, null),
    'not found',
  );

  section('11. Server-side caps refuse, they do not silently narrow');
  await refuses(
    `a period longer than ${SLA_MAX_PERIOD_DAYS} days is refused`,
    () => computeAvailability({
      tenantId: TENANT,
      from: new Date(T0 - 400 * DAY),
      to: new Date(T_END),
      siteIds: [alpha.siteId],
    }),
    'may not exceed',
  );
  await refuses(
    'a zero-length period is refused',
    () => computeAvailability({
      tenantId: TENANT, from: new Date(T0), to: new Date(T0), siteIds: [alpha.siteId],
    }),
    'at least',
  );

  section('12. Storing a report: the document and its audit trail');
  const issued = await issueReport({
    tenantId: TENANT,
    siteId: beta.siteId,
    from: new Date(T0),
    to: new Date(T_END),
    actorUserId: null,
    actorName: 'f7-harness',
  });
  eq('the stored report carries the excluded seconds',
    issued.report.excludedManagementSeconds, 6 * 3600);
  eq('  ... the objective it was judged against', issued.report.objectivePercent, 99.5);
  eq('  ... the knob that produced it',
    issued.report.verdictValiditySeconds, DEFAULT_VERDICT_VALIDITY_SECONDS);
  eq('  ... and the hash of the whole parameter set', issued.report.paramsHash.length, 64);

  const trail = await getReportIntervals(TENANT, Number(issued.report.id));
  eq('the audit trail is stored in full',
    trail.length, issued.report.intervalCount);
  const excludedRows = trail.filter((r) => r.kind === 'excluded_management');
  eq('the excluded stretch is in the trail with its reason',
    excludedRows.reduce((s, r) => s + r.seconds, 0), 6 * 3600);
  ok('  ... and names the K7 verdict',
    excludedRows.every((r) => r.reason === 'verdict_concentrator_degraded'));

  const filtered = await getReportIntervals(TENANT, Number(issued.report.id), ['excluded_management']);
  eq('the trail can be filtered to "what exactly did you take off my invoice"',
    filtered.length, excludedRows.length);

  const ledger = await db('audit_log')
    .where({ tenant_id: TENANT, action: 'sla_report.issued', entity_id: issued.report.id })
    .orderBy('seq', 'desc')
    .first('entity_id', 'hash');
  eq('issuing a report writes one hash-chained audit row', ledger?.entity_id, issued.report.id);
  ok('  ... and Postgres computed the digest', (ledger?.hash ?? '').length === 64);

  ok('the report is listed for its tenant',
    (await listReports(TENANT)).some((r) => r.id === issued.report.id));
  eq('another tenant cannot read it', await getReport(OTHER_TENANT, Number(issued.report.id)), null);

  section('13. The database refuses what the service refuses');
  await refuses(
    'a stored report cannot be edited (frozen by trigger)',
    () => db('sla_reports').where({ id: issued.report.id }).update({ availability_percent: 100 }),
    'append-only',
  );
  await refuses(
    'a "no_data" report with an availability figure is refused',
    () => db('sla_reports').insert({
      tenant_id: TENANT, site_id: beta.siteId,
      period_start: new Date(T0), period_end: new Date(T_END),
      verdict_validity_seconds: 900, algorithm_version: 'x', params_hash: 'f'.repeat(64),
      period_seconds: 604800, up_seconds: 0, down_seconds: 0,
      excluded_management_seconds: 0, excluded_maintenance_seconds: 0,
      unmeasured_seconds: 604800,
      availability_percent: 100,          // <- the F2 defect, attempted directly
      coverage_status: 'no_data', objective_verdict: 'indeterminate',
      verdict_reason: 'no_measurement', device_count: 1, interval_count: 0,
    }),
    'sla_reports_no_data_has_no_figure',
  );
  await refuses(
    'an unmeasured period cannot be stored as "met"',
    () => db('sla_reports').insert({
      tenant_id: TENANT, site_id: beta.siteId,
      period_start: new Date(T0), period_end: new Date(T_END),
      verdict_validity_seconds: 900, algorithm_version: 'x', params_hash: 'f'.repeat(64),
      period_seconds: 604800, up_seconds: 0, down_seconds: 0,
      excluded_management_seconds: 0, excluded_maintenance_seconds: 0,
      unmeasured_seconds: 604800,
      availability_percent: null,
      coverage_status: 'no_data', objective_verdict: 'met',
      verdict_reason: 'x', device_count: 1, interval_count: 0,
    }),
    'sla_reports_verdict_needs_measurement',
  );
  await refuses(
    'a report whose seconds do not add up to its period is refused',
    () => db('sla_reports').insert({
      tenant_id: TENANT, site_id: beta.siteId,
      period_start: new Date(T0), period_end: new Date(T_END),
      verdict_validity_seconds: 900, algorithm_version: 'x', params_hash: 'f'.repeat(64),
      period_seconds: 604800, up_seconds: 1, down_seconds: 0,
      excluded_management_seconds: 0, excluded_maintenance_seconds: 0,
      unmeasured_seconds: 0,
      availability_percent: 100,
      coverage_status: 'complete', objective_verdict: 'indeterminate',
      verdict_reason: 'x', device_count: 1, interval_count: 0,
    }),
    'sla_reports_seconds_balance_chk',
  );
  await refuses(
    'an objective of 10 % is refused by the database as well as by the service',
    () => db('sla_objectives').insert({
      tenant_id: TENANT, site_id: null, scope: 'tenant', objective_percent: 10,
    }),
    'sla_objectives_percent_chk',
  );
  await refuses(
    'a second tenant DEFAULT is refused by the PARTIAL unique index',
    () => db('sla_objectives').insert({
      tenant_id: TENANT, site_id: null, scope: 'tenant', objective_percent: 98,
    }),
    'sla_objectives_tenant_default_uq',
  );
  await refuses(
    'a verdict-validity of one year is refused by the database',
    () => db('sla_objectives').insert({
      tenant_id: OTHER_TENANT, site_id: null, scope: 'tenant', objective_percent: 99,
      verdict_validity_seconds: 31_536_000,
    }),
    'sla_objectives_validity_chk',
  );
  await refuses(
    'an objective pointing at another tenant\'s site is unrepresentable',
    () => db('sla_objectives').insert({
      tenant_id: TENANT, site_id: other.siteId, scope: 'site', objective_percent: 99,
    }),
    'sla_objectives_site_tenant_fk',
  );

  section('14. The HTTP surface');
  const layer = (slaRoutes as unknown as { stack: Array<{
    route?: { path: string; methods: Record<string, boolean>; stack: Array<{ name: string }> };
    name: string;
  }> }).stack;
  const guards = layer.filter((l) => !l.route).map((l) => l.name);
  ok('requireAuth is applied to the whole router, upstream of every branch',
    guards.some((n) => n.toLowerCase().includes('auth')), guards.join(', '));
  ok('requireTenant is applied to the whole router too',
    guards.some((n) => n.toLowerCase().includes('tenant')), guards.join(', '));
  const routed = layer.filter((l) => l.route);
  ok('every declared route carries at least one capability guard',
    routed.every((l) => (l.route?.stack.length ?? 0) >= 2),
    `${routed.length} routes`);
  ok('the issue route carries TWO capability guards',
    (routed.find((l) => l.route?.path === '/reports' && l.route.methods.post)
      ?.route?.stack.length ?? 0) >= 3);
  ok('EXPORT_RUN and DEVICE_READ are both real capabilities',
    typeof CAPABILITIES.EXPORT_RUN === 'string' && typeof CAPABILITIES.DEVICE_READ === 'string');
  ok('AppError is what the services throw', new AppError(404, 'x') instanceof Error);

  section('15. No secret can leave through this surface');
  const wide = await computeSiteAvailability(TENANT, alpha.siteId, new Date(T0), new Date(T_END));
  const serialised = JSON.stringify(wide);
  ok('no ppp_username in any F7 response object',
    !serialised.includes(alpha.username), alpha.username);
  ok('no "password"/"secret"/"credential" key anywhere in the payload',
    !/password|secret|credential|token/i.test(serialised));
  const storedJson = JSON.stringify(await getReport(TENANT, Number(issued.report.id)));
  ok('nor in a stored report', !/password|secret|credential|token/i.test(storedJson));

  // ==========================================================================
  console.log(`\n${'='.repeat(72)}`);
  console.log(`F7 SLA — ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  - ${f}`);
  }
  console.log('='.repeat(72));
  await db.destroy();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  await db.destroy();
  process.exit(1);
});
