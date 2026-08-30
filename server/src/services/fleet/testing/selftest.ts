/**
 * ObliWAN — fleet self-test, OFFLINE half.
 *
 * Everything in here is pure: no database, no socket, no clock beyond
 * `Date.now()`. It covers the two decisions that must never be wrong and that
 * a network test would not exercise exhaustively:
 *
 *   - the K7 truth table (`UNREACHABLE` is not `SITE_DOWN`);
 *   - `compareIdentity()` (fail closed — "we could not check" never means
 *     "go ahead").
 *
 * Run: npx tsx src/services/fleet/testing/selftest.ts
 *
 * The end-to-end acceptance test (real Postgres + a fake CHR speaking the
 * binary protocol) is `recipe.ts` next door; it needs a database, this does not.
 */

import {
  evaluateReachability,
  TOTAL_SIGNALS,
} from '../reachability.service';
import { compareIdentity } from '../deviceBinding.service';
import { asInetOrNull, mergeCandidates, parseActiveRow, parseSecretRow } from '../concentratorDiscovery.service';

let passed = 0;
const failures: string[] = [];

function check(label: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed++;
    return;
  }
  failures.push(`${label}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`);
}

function eq(label: string, actual: unknown, expected: unknown): void {
  check(label, Object.is(actual, expected), { actual, expected });
}

// ============================================================================
// K7 — the truth table
// ============================================================================

function verdictOf(signals: Parameters<typeof evaluateReachability>[0], ctx?: Parameters<typeof evaluateReachability>[1]) {
  return evaluateReachability(signals, ctx);
}

// -- the M2 acceptance criterion, stated as a test ---------------------------
{
  // Tunnel cut, and NOTHING else is measurable (no SNMP poller before M3, no
  // external probe before M8, no CWMP before M10). The honest answer is "we do
  // not know", and it must not be SITE_DOWN.
  const r = verdictOf({ pppUp: false });
  eq('M2: ppp down + no other signal -> UNREACHABLE', r.verdict, 'UNREACHABLE');
  check('M2: UNREACHABLE is not SITE_DOWN', r.verdict !== 'SITE_DOWN');
  eq('M2: reason names the missing evidence', r.reason, 'ppp_down_no_independent_signal');
  eq('M2: confidence is one signal out of four', r.confidence, 0.25);
}

{
  // The same tunnel-down state, but an out-of-tunnel probe also failed. NOW we
  // have positive, independent evidence and may say the site is dead.
  const r = verdictOf({ pppUp: false, externalOk: false });
  eq('ppp down + external probe down -> SITE_DOWN', r.verdict, 'SITE_DOWN');
  eq('SITE_DOWN confidence rises with corroboration', r.confidence, 0.5);
}

{
  // SNMP silence must NOT promote UNREACHABLE to SITE_DOWN: SNMP rides the
  // very tunnel that is down, so its failure is implied, not independent.
  const r = verdictOf({ pppUp: false, snmpOk: false });
  eq('ppp down + snmp down (same path) is still UNREACHABLE', r.verdict, 'UNREACHABLE');
}

{
  const r = verdictOf({ pppUp: false, snmpOk: false, cwmpRecent: true });
  eq('ppp down but CPE still informing -> TUNNEL_DOWN_SITE_UP', r.verdict, 'TUNNEL_DOWN_SITE_UP');
}
{
  const r = verdictOf({ pppUp: false, externalOk: true });
  eq('ppp down but external probe up -> TUNNEL_DOWN_SITE_UP', r.verdict, 'TUNNEL_DOWN_SITE_UP');
}

{
  const r = verdictOf({ pppUp: true });
  eq('ppp up -> UP', r.verdict, 'UP');
  eq('UP on one signal only is honestly low-confidence', r.confidence, 0.25);
  eq('reason distinguishes uncorroborated UP', r.reason, 'ppp_up_only');
}
{
  const r = verdictOf({ pppUp: true, snmpOk: true });
  eq('ppp up + snmp ok -> UP', r.verdict, 'UP');
  eq('two agreeing signals -> 0.5', r.confidence, 0.5);
  eq('reason records the corroboration', r.reason, 'ppp_up_snmp_ok');
}
{
  const r = verdictOf({ pppUp: true, snmpOk: true, externalOk: true, cwmpRecent: true });
  eq('all four signals agree -> confidence 1', r.confidence, 1);
}
{
  const r = verdictOf({ pppUp: true, snmpOk: false });
  eq('ppp up, snmp silent, still UP', r.verdict, 'UP');
}

{
  const r = verdictOf({ pppUp: true }, { publicPathChanged: true });
  eq('session from a new public address -> WAN_FAILOVER', r.verdict, 'WAN_FAILOVER');
}
{
  const r = verdictOf({ pppUp: true }, { publicPathChanged: false });
  eq('same public address -> plain UP', r.verdict, 'UP');
}
{
  const r = verdictOf({ pppUp: true }, { publicPathChanged: null });
  eq('no baseline for the public address -> plain UP', r.verdict, 'UP');
}

// -- R5: the concentrator is the thing that broke ---------------------------
{
  const r = verdictOf({ pppUp: false }, { concentratorDegraded: true });
  eq('child of a degraded CHR -> CONCENTRATOR_DEGRADED', r.verdict, 'CONCENTRATOR_DEGRADED');
  check('child verdicts are SUPPRESSED, not raised (one alert, not 300)', r.suppressed === true);
}
{
  const r = verdictOf({ pppUp: null, snmpOk: false }, { isConcentrator: true });
  eq('the CHR itself -> CONCENTRATOR_DEGRADED', r.verdict, 'CONCENTRATOR_DEGRADED');
  check('the concentrator alert itself is NOT suppressed', r.suppressed === false);
}
{
  const r = verdictOf({ pppUp: false }, { concentratorDegraded: true, isConcentrator: true });
  check('a degraded CHR does not suppress its own verdict', r.suppressed === false);
}

// -- nothing measured at all -------------------------------------------------
{
  const r = verdictOf({});
  eq('no signal at all -> UNREACHABLE', r.verdict, 'UNREACHABLE');
  eq('and confidence zero', r.confidence, 0);
  eq('and a reason that says so', r.reason, 'no_signal_measured');
}
{
  const r = verdictOf({ snmpOk: true });
  eq('no ppp signal but the box answered SNMP -> UP', r.verdict, 'UP');
}
{
  const r = verdictOf({ snmpOk: false });
  eq('no ppp signal and snmp failed -> UNREACHABLE (never SITE_DOWN)', r.verdict, 'UNREACHABLE');
}

// -- structural --------------------------------------------------------------
eq('confidence is measured against four signals', TOTAL_SIGNALS, 4);
{
  // Exhaustive sweep of the 3^4 signal combinations: no input may ever produce
  // SITE_DOWN without at least one independent signal measured false.
  const values: Array<boolean | null> = [true, false, null];
  let sitedowns = 0;
  let bad = 0;
  for (const pppUp of values)
    for (const snmpOk of values)
      for (const externalOk of values)
        for (const cwmpRecent of values) {
          const r = verdictOf({ pppUp, snmpOk, externalOk, cwmpRecent });
          if (r.verdict === 'SITE_DOWN') {
            sitedowns++;
            if (pppUp !== false || (externalOk !== false && cwmpRecent !== false)) bad++;
          }
          if (r.confidence < 0 || r.confidence > 1) bad++;
        }
  check('81 signal combinations: SITE_DOWN never without independent evidence', bad === 0, { bad });
  check('SITE_DOWN is reachable at all (the table is not vacuous)', sitedowns > 0, { sitedowns });
}

// ============================================================================
// D5 / R4 — identity comparison
// ============================================================================

{
  const r = compareIdentity(
    { ppp_username: 'site-001', system_identity: 'RTR-LYON', serial: 'HXX01' },
    { pppUsername: 'site-001', systemIdentity: 'RTR-LYON', serial: 'HXX01' },
  );
  check('three matching attributes -> ok', r.ok);
  eq('and all three counted', r.matched, 3);
}
{
  const r = compareIdentity(
    { ppp_username: 'site-001', system_identity: 'RTR-LYON', serial: 'HXX01' },
    { pppUsername: 'site-001', systemIdentity: 'RTR-LYON', serial: 'DIFFERENT' },
  );
  check('one contradicting attribute is fatal even with two matches', !r.ok);
  eq('the mismatch is counted', r.mismatched, 1);
  check('and named in the reason', r.reason.includes('serial'), r.reason);
}
{
  // A CHR has no RouterBOARD, so no serial, and no l2tp-client, so no ppp
  // username. It is still assertable on its system identity.
  const r = compareIdentity(
    { system_identity: 'CHR-CENTRAL', serial: null, ppp_username: null },
    { pppUsername: null, systemIdentity: 'CHR-CENTRAL', serial: null },
  );
  check('a CHR asserts on identity alone', r.ok);
  eq('unrecorded attributes are not failures', r.checks.filter((c) => c.outcome === 'unrecorded').length, 2);
}
{
  const r = compareIdentity({ serial: 'HXX01' }, { pppUsername: null, systemIdentity: null, serial: null });
  check('FAIL CLOSED: recorded serial, box said nothing -> not ok', !r.ok);
  eq('the attribute is marked unknown, not mismatched', r.checks.find((c) => c.attribute === 'serial')?.outcome, 'unknown');
}
{
  const r = compareIdentity({}, { pppUsername: 'x', systemIdentity: 'y', serial: 'z' });
  check('FAIL CLOSED: nothing recorded to compare against -> not ok', !r.ok);
  check('and the reason says "unproven", not "confirmed"', r.reason.includes('unproven'), r.reason);
}
{
  const r = compareIdentity(
    { system_identity: 'rtr-lyon' },
    { pppUsername: null, systemIdentity: 'RTR-LYON', serial: null },
  );
  check('comparison is case-insensitive and trimmed', r.ok);
}
{
  const r = compareIdentity(
    { system_identity: '  RTR-LYON  ' },
    { pppUsername: null, systemIdentity: 'RTR-LYON', serial: null },
  );
  check('whitespace does not create a false mismatch', r.ok);
}
{
  const r = compareIdentity(
    { ppp_username: 'site-001', serial: 'HXX01' },
    { pppUsername: 'site-002', systemIdentity: null, serial: 'HXX01' },
  );
  check('the classic R4 case: right serial, wrong tunnel account -> refused', !r.ok);
}

// ============================================================================
// Discovery parsing and the /ppp/secret + /ppp/active merge
// ============================================================================

eq('inet guard accepts IPv4', asInetOrNull('10.66.0.11'), '10.66.0.11');
eq('inet guard rejects an out-of-range octet', asInetOrNull('10.66.0.999'), null);
eq('inet guard rejects a MAC (RouterOS puts one in caller-id for PPPoE)', asInetOrNull('00:0C:29:AA:BB:CC'), null);
eq('inet guard rejects a hostname', asInetOrNull('vpn.example.com'), null);
eq('inet guard rejects the empty string', asInetOrNull(''), null);
eq('inet guard passes IPv6 through for Postgres to validate', asInetOrNull('2001:db8::1'), '2001:db8::1');
eq('inet guard strips a zone index', asInetOrNull('10.0.0.1%eth0'), '10.0.0.1');

{
  const parsed = parseActiveRow({
    '.id': '*1',
    name: 'site-001',
    address: '10.66.0.11',
    'caller-id': '203.0.113.7',
    service: 'l2tp',
  });
  eq('active row keeps the router id for listen correlation', parsed?.routerId, '*1');
  eq('active row username', parsed?.name, 'site-001');
  eq('active row tunnel address', parsed?.address, '10.66.0.11');
  eq('active row caller ip', parsed?.callerId, '203.0.113.7');
}
eq('a row with no name is unusable and dropped', parseActiveRow({ '.id': '*9' }), null);
{
  const s = parseSecretRow({ name: 'site-004', profile: 'l2tp-sites', comment: 'Lyon Nord', disabled: 'true' });
  eq('secret comment survives (that is where the site name is written)', s?.comment, 'Lyon Nord');
  eq('RouterOS "true" is decoded as a boolean', s?.disabled, true);
}

{
  const merged = mergeCandidates(
    [
      { routerId: '*S1', name: 'site-001', service: 'l2tp', profile: 'sites', remoteAddress: '10.66.0.11', comment: 'Lyon', disabled: false, raw: {} },
      { routerId: '*S2', name: 'site-002', service: 'l2tp', profile: 'sites', remoteAddress: '10.66.0.12', comment: 'Paris', disabled: false, raw: {} },
      { routerId: '*S3', name: 'site-003', service: 'l2tp', profile: 'sites', remoteAddress: null, comment: 'Never dialled', disabled: false, raw: {} },
    ],
    [
      { routerId: '*1', name: 'site-001', service: 'l2tp', address: '10.66.0.11', callerId: '203.0.113.7', uptime: '1h', raw: {} },
      { routerId: '*2', name: 'site-009', service: 'l2tp', address: '10.66.0.99', callerId: '203.0.113.9', uptime: '2m', raw: {} },
    ],
  );
  eq('merge produces one candidate per username', merged.length, 4);
  const s1 = merged.find((c) => c.username === 'site-001');
  check('a declared + connected account is online', s1?.online === true);
  eq('the live session supplies the caller ip', s1?.callerIp, '203.0.113.7');
  eq('the secret supplies the comment', s1?.comment, 'Lyon');
  const s3 = merged.find((c) => c.username === 'site-003');
  check('a declared account that never dialled is still discovered', s3 !== undefined);
  check('...and is marked offline', s3?.online === false);
  const s9 = merged.find((c) => c.username === 'site-009');
  check('a session with no /ppp/secret is still discovered (RADIUS, deleted secret)', s9 !== undefined);
  check('...and is marked online', s9?.online === true);
}

// ============================================================================
// Report
// ============================================================================

console.log(`\nfleet offline self-test: ${passed} passed, ${failures.length} failed`);
for (const f of failures) console.log(`  FAIL  ${f}`);
process.exit(failures.length === 0 ? 0 : 1);
