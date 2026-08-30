/**
 * ObliWAN — M8 self-test, OFFLINE half.
 *
 * Everything here is pure: no database, no socket, no equipment. It covers the
 * decisions that must never be wrong and that an end-to-end test would exercise
 * only by luck:
 *
 *   - the per-brand login parsers, including the lines they must REFUSE;
 *   - `isSharedAccount` — `admin` designates nobody, decorated or not;
 *   - the K6 scoring: `unattributed`, `ambiguous`, and the rule that a named
 *     account never outranks a shared one on identity alone;
 *   - the RouterOS `/log` timestamp reconstruction and cursor arithmetic;
 *   - the K7 truth table under the NEW signals, and the two failures it must
 *     not produce: `SITE_DOWN` from a missing signal, and N alerts from one
 *     concentrator outage.
 *
 * Run: npx tsx src/services/logs/testing/selftest.ts
 *
 * The end-to-end acceptance test (real Postgres, real syslog sockets, real
 * migrations) is `recipe.ts` next door; it needs a database, this does not.
 */

import {
  parseLoginLine,
  parseMikrotikLogin,
  parseZyxelLogin,
  parseDraytekLogin,
  parseSonicwallLogin,
  parseGenericLogin,
  addressFrom,
  methodFrom,
} from '../parsers';
import { isSharedAccount, ATTRIBUTION_TUNING } from '../contract';
import { loginDedupeKey } from '../loginEvents.service';
import {
  loginEventsFromLogRows,
  parseRouterOsLogTime,
  rowsAfterCursor,
  rowHash,
} from '../routerosLog.service';
import {
  buildSessions,
  methodFit,
  scoreSessions,
  temporalFit,
  type Session,
} from '../../drift/attribution.service';
import { evaluateReachability } from '../../fleet/reachability.service';

let passed = 0;
const failures: string[] = [];

function check(label: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed += 1;
    return;
  }
  failures.push(`${label}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`);
}

function eq(label: string, actual: unknown, expected: unknown): void {
  check(label, Object.is(actual, expected), { actual, expected });
}

// ============================================================================
// 1. Parsers
// ============================================================================

{
  const login = parseMikrotikLogin('user alice logged in from 10.0.0.5 via winbox', 'system,info,account');
  eq('routeros: event', login?.event, 'login');
  eq('routeros: account', login?.account, 'alice');
  eq('routeros: method', login?.method, 'winbox');
  eq('routeros: the OPERATOR address, not the datagram source', login?.sourceIp, '10.0.0.5');

  const out = parseMikrotikLogin('user alice logged out from 10.0.0.5 via winbox', null);
  eq('routeros: logout', out?.event, 'logout');

  const failed = parseMikrotikLogin('login failure for user admin from 10.0.0.5 via ssh', null);
  eq('routeros: failure is its own event', failed?.event, 'login_failed');
  eq('routeros: failure keeps the account', failed?.account, 'admin');

  const local = parseMikrotikLogin('user admin logged in via local', null);
  eq('routeros: a console login has no address', local?.sourceIp, null);
  eq('routeros: `local` maps to console', local?.method, 'console');

  // The refusals matter more than the matches.
  check(
    'routeros: an interface flap is not a login',
    parseMikrotikLogin('ether1 link down', 'interface,info') === null,
  );
  check(
    'routeros: a PPP session is not an admin login',
    parseMikrotikLogin('site-001 logged in, 10.66.0.11', 'l2tp,ppp,info') === null,
  );
}

{
  const z = parseZyxelLogin(
    'Administrator alice from 192.168.1.33 has logged in Web Configurator',
    null,
  );
  eq('zyxel: account', z?.account, 'alice');
  eq('zyxel: web configurator maps to web', z?.method, 'web');
  eq('zyxel: address', z?.sourceIp, '192.168.1.33');
  check(
    'zyxel: a failed attempt with no username produces NOTHING rather than a placeholder',
    parseZyxelLogin('Failed login attempt to Device from ssh (incorrect password)', null) === null,
  );
}

{
  const d = parseDraytekLogin('[WEB]Login success from 192.168.1.10, Account: alice', null);
  eq('draytek: account', d?.account, 'alice');
  eq('draytek: channel from the bracket tag', d?.method, 'web');
  eq('draytek: address', d?.sourceIp, '192.168.1.10');
  check(
    'draytek: a line with no account is refused',
    parseDraytekLogin('[WEB]Login success from 192.168.1.10', null) === null,
  );
}

{
  const s = parseSonicwallLogin(
    'id=firewall sn=0017C5 pri=5 c=1024 m=238 msg="User login successful" src=192.168.168.20:1044:X0 usr="alice"',
    null,
  );
  eq('sonicwall: account from usr=', s?.account, 'alice');
  eq('sonicwall: src= strips the port and the interface', s?.sourceIp, '192.168.168.20');
  const f = parseSonicwallLogin(
    'id=firewall m=236 msg="User login denied - incorrect password" src=192.168.168.20:1044:X0 usr="alice"',
    null,
  );
  eq('sonicwall: a denial is login_failed, not login', f?.event, 'login_failed');
}

{
  const a = parseGenericLogin('Accepted password for alice from 10.0.0.5 port 51234 ssh2', 'sshd');
  eq('sshd: account', a?.account, 'alice');
  eq('sshd: method', a?.method, 'ssh');
  check(
    'sshd patterns are not applied to an arbitrary tag',
    parseGenericLogin('Accepted password for alice from 10.0.0.5', 'firewall') === null,
  );
}

{
  // Brand unknown: every parser is tried and only an UNAMBIGUOUS hit counts.
  const one = parseLoginLine('user alice logged in from 10.0.0.5 via winbox', null, null);
  eq('unknown brand: a line only one parser claims is accepted', one?.account, 'alice');
}

{
  eq('address: bare v4', addressFrom('10.0.0.5'), '10.0.0.5');
  eq('address: v4 with port', addressFrom('10.0.0.5:1044'), '10.0.0.5');
  eq('address: sonicwall port + interface', addressFrom('10.0.0.5:1044:X0'), '10.0.0.5');
  eq('address: trailing punctuation', addressFrom('10.0.0.5,'), '10.0.0.5');
  eq('address: a MAC is not an address', addressFrom('00:0c:29:1a:2b:3c'), null);
  eq('method: an unknown door stays unknown, it is not guessed', methodFrom('quantum'), 'unknown');
}

// ============================================================================
// 2. Shared accounts — `admin` designates nobody
// ============================================================================

{
  check('admin is a shared account', isSharedAccount('admin'));
  check('ADMIN is too (case)', isSharedAccount('ADMIN'));
  check('admin@site keeps being shared (decoration stripped)', isSharedAccount('admin@site'));
  check('admin+cte keeps being shared', isSharedAccount('admin+cte'));
  check('admin(1) keeps being shared', isSharedAccount('admin(1)'));
  check('alice is not', !isSharedAccount('alice'));
  check('an empty account is not a shared account, it is nothing', !isSharedAccount(''));
}

// ============================================================================
// 3. Dedup between the push and the pull path
// ============================================================================

{
  const base = { event: 'login', account: 'alice', method: 'winbox', sourceIp: '10.0.0.5' };
  const a = loginDedupeKey({ ...base, ts: new Date('2026-08-29T10:22:11.000Z') });
  const b = loginDedupeKey({ ...base, ts: new Date('2026-08-29T10:22:11.850Z') });
  eq('the same login seen by syslog and by /log hashes identically', a, b);
  const c = loginDedupeKey({ ...base, ts: new Date('2026-08-29T10:22:12.000Z') });
  check('a different second is a different event', a !== c);
  const d = loginDedupeKey({ ...base, account: 'ALICE', ts: new Date('2026-08-29T10:22:11Z') });
  eq('the account is case-folded', a, d);
}

// ============================================================================
// 4. RouterOS /log
// ============================================================================

{
  const now = new Date('2026-08-29T12:00:00Z');
  eq(
    'log time: dated form',
    parseRouterOsLogTime('aug/29 10:22:11', now)?.toISOString(),
    '2026-08-29T10:22:11.000Z',
  );
  eq(
    'log time: full date',
    parseRouterOsLogTime('aug/29/2025 10:22:11', now)?.toISOString(),
    '2025-08-29T10:22:11.000Z',
  );
  eq(
    'log time: iso form',
    parseRouterOsLogTime('2026-08-29 10:22:11', now)?.toISOString(),
    '2026-08-29T10:22:11.000Z',
  );
  eq(
    'log time: time-only means today',
    parseRouterOsLogTime('10:22:11', now)?.toISOString(),
    '2026-08-29T10:22:11.000Z',
  );
  // 23:50 read at 00:05 is yesterday, not eighteen hours in the future.
  eq(
    'log time: time-only rolls back over midnight',
    parseRouterOsLogTime('23:50:00', new Date('2026-08-29T00:05:00Z'))?.toISOString(),
    '2026-08-28T23:50:00.000Z',
  );
  eq('log time: unparseable stays null', parseRouterOsLogTime('yesterday-ish', now), null);
}

{
  const rows = [
    { time: '10:00:00', topics: 'system,info,account', message: 'user a logged in via local' },
    { time: '10:01:00', topics: 'system,info,account', message: 'user b logged in via local' },
    { time: '10:02:00', topics: 'system,info,account', message: 'user c logged in via local' },
  ];
  const after = rowsAfterCursor(rows, rowHash(rows[0]), 100);
  eq('cursor: only rows after the known one', after.length, 2);
  eq('cursor: and in order', after[0].message, 'user b logged in via local');

  const wrapped = rowsAfterCursor(rows, 'a-hash-that-no-longer-exists', 2);
  eq('cursor: a lost cursor falls back to the TAIL, not the head', wrapped.length, 2);
  eq('cursor: which is the recent end', wrapped[1].message, 'user c logged in via local');

  const events = loginEventsFromLogRows(7, rows, new Date('2026-08-29T12:00:00Z'));
  eq('/log yields one event per account line', events.length, 3);
  eq('/log events are tagged as pulled, not pushed', events[0].origin, 'routeros_log');
}

{
  // A box with no NTP: the device timestamp is absurd, so `ts` must fall back
  // to our clock or the event lands outside every window for ever.
  const now = new Date('2026-08-29T12:00:00Z');
  const events = loginEventsFromLogRows(
    7,
    [{ time: 'jan/01/1970 02:00:00', topics: 'account', message: 'user a logged in via local' }],
    now,
  );
  eq('a 1970 clock does not banish the event from every window', events[0].ts.getTime(), now.getTime());
  eq('but the device clock is kept verbatim', events[0].deviceTs?.getUTCFullYear(), 1970);
}

// ============================================================================
// 5. K6 — the scoring
// ============================================================================

const W = { from: new Date('2026-08-29T10:00:00Z'), to: new Date('2026-08-29T11:00:00Z') };

function session(over: Partial<Session> = {}): Session {
  return {
    loginEventId: '1',
    account: 'alice',
    sharedAccount: false,
    method: 'winbox',
    sourceIp: '10.0.0.5',
    loginAt: new Date('2026-08-29T10:30:00Z'),
    logoutAt: null,
    ...over,
  };
}

{
  eq('temporal: a login inside the window scores 1', temporalFit(session(), W), 1);
  eq(
    'temporal: a session that ended before the window cannot explain anything',
    temporalFit(
      session({
        loginAt: new Date('2026-08-29T08:00:00Z'),
        logoutAt: new Date('2026-08-29T09:00:00Z'),
      }),
      W,
    ),
    0,
  );
  const old = temporalFit(
    session({ loginAt: new Date('2026-08-29T08:00:00Z') }),
    W,
  );
  eq('temporal: an old still-open session floors at minTemporalFit', old, ATTRIBUTION_TUNING.minTemporalFit);
  const recent = temporalFit(session({ loginAt: new Date('2026-08-29T09:30:00Z') }), W);
  check('temporal: half an hour before the window decays but stays high', recent > 0.6 && recent < 1);

  eq('method: winbox can write', methodFit('winbox'), 1);
  eq('method: a VPN user cannot reconfigure the box', methodFit('vpn'), 0);
  eq('method: unknown is half, not zero and not one', methodFit('unknown'), 0.5);
}

{
  const r = scoreSessions([], W);
  eq('no session in the window -> unattributed', r.verdict, 'unattributed');
  eq('...and it says why', r.reason, 'no_login_event_in_window');
  eq('...and it names nobody', r.winner, null);
}

{
  const r = scoreSessions([session()], W);
  eq('one clean session -> attributed', r.verdict, 'attributed');
  eq('...to the right account', r.winner?.account, 'alice');
  eq('...and the right address', r.winner?.sourceIp, '10.0.0.5');
  eq('...with full evidence', r.winner?.evidence, 1);
}

{
  const r = scoreSessions([session({ account: 'admin', sharedAccount: true })], W);
  eq('one session on a shared account is still attributed', r.verdict, 'attributed');
  check('...but flagged as naming a role, not a person', r.winner?.sharedAccount === true);
  check(
    '...and its confidence is reduced, not its rank',
    r.winner!.score < r.winner!.evidence,
    { score: r.winner?.score, evidence: r.winner?.evidence },
  );
}

{
  const r = scoreSessions(
    [
      session({ loginEventId: '1', account: 'alice' }),
      session({ loginEventId: '2', account: 'bob', loginAt: new Date('2026-08-29T10:40:00Z') }),
    ],
    W,
  );
  eq('two equally placed sessions -> ambiguous, never a pick', r.verdict, 'ambiguous');
  eq('...and it says why', r.reason, 'candidates_within_ambiguity_margin');
  eq('...naming nobody', r.winner, null);
  eq('...while still showing both candidates', r.candidates.length, 2);
}

{
  // THE REGRESSION THIS EXISTS TO PREVENT: a named account must not beat a
  // shared one on identity alone. Both are equally placed in time, so the only
  // honest answer is `ambiguous`.
  const r = scoreSessions(
    [
      session({ loginEventId: '1', account: 'alice', sharedAccount: false }),
      session({
        loginEventId: '2',
        account: 'admin',
        sharedAccount: true,
        loginAt: new Date('2026-08-29T10:31:00Z'),
      }),
    ],
    W,
  );
  eq('alice and admin logged in together -> ambiguous, NOT alice', r.verdict, 'ambiguous');
}

{
  // Evidence, on the other hand, is allowed to break a tie: a VPN user cannot
  // have reconfigured the router, so the winbox session stands alone.
  const r = scoreSessions(
    [
      session({ loginEventId: '1', account: 'alice', method: 'winbox' }),
      session({ loginEventId: '2', account: 'bob', method: 'vpn' }),
    ],
    W,
  );
  eq('a VPN session does not compete with a winbox session', r.verdict, 'attributed');
  eq('...and the winbox one wins', r.winner?.account, 'alice');
}

{
  const r = scoreSessions(
    [session({ loginAt: new Date('2026-08-29T06:00:00Z'), account: 'admin', sharedAccount: true })],
    W,
  );
  eq('a weak, old, shared session is refused rather than named', r.verdict, 'unattributed');
  eq('...and it says the threshold is why', r.reason, 'best_candidate_below_threshold');
}

{
  const sessions = buildSessions([
    { id: '1', event: 'login', account: 'alice', shared_account: false, method: 'ssh', source_ip: '10.0.0.5', ts: new Date('2026-08-29T10:00:00Z') },
    { id: '2', event: 'logout', account: 'alice', shared_account: false, method: 'ssh', source_ip: null, ts: new Date('2026-08-29T10:30:00Z') },
    { id: '3', event: 'login_failed', account: 'mallory', shared_account: false, method: 'ssh', source_ip: '10.0.0.9', ts: new Date('2026-08-29T10:40:00Z') },
  ]);
  eq('sessions: one login/logout pair', sessions.length, 1);
  eq('sessions: the logout closed it', sessions[0].logoutAt?.toISOString(), '2026-08-29T10:30:00.000Z');
  check(
    'sessions: a FAILED login never becomes a candidate — it changed nothing',
    sessions.every((s) => s.account !== 'mallory'),
  );

  const orphanLogout = buildSessions([
    { id: '9', event: 'logout', account: 'carol', shared_account: false, method: 'ssh', source_ip: null, ts: new Date('2026-08-29T10:10:00Z') },
  ]);
  eq('sessions: a logout with no login is not back-filled into an invented session', orphanLogout.length, 0);

  const relogin = buildSessions([
    { id: '1', event: 'login', account: 'alice', shared_account: false, method: 'ssh', source_ip: null, ts: new Date('2026-08-29T10:00:00Z') },
    { id: '2', event: 'login', account: 'alice', shared_account: false, method: 'ssh', source_ip: null, ts: new Date('2026-08-29T10:20:00Z') },
  ]);
  eq('sessions: a missed logout is closed by the next login, not left open for ever',
    relogin[0].logoutAt?.toISOString(), '2026-08-29T10:20:00.000Z');
}

// ============================================================================
// 6. K7 — the truth table under the new signals
// ============================================================================

{
  // THE MILESTONE CRITERION. A signal we did not measure is `null`, and `null`
  // can never add up to SITE_DOWN.
  const r = evaluateReachability({ pppUp: false, snmpOk: false, externalOk: null, cwmpRecent: null });
  eq('missing independent signal -> UNREACHABLE', r.verdict, 'UNREACHABLE');
  check('and above all NOT SITE_DOWN', r.verdict !== 'SITE_DOWN');
  eq('and it names the missing evidence', r.reason, 'ppp_down_no_independent_signal');
}

{
  // The probe has a baseline and has failed repeatedly: NOW the site is down.
  const r = evaluateReachability({ pppUp: false, snmpOk: false, externalOk: false, cwmpRecent: null });
  eq('tunnel down + a proven out-of-tunnel path also down -> SITE_DOWN', r.verdict, 'SITE_DOWN');
}

{
  const r = evaluateReachability({ pppUp: false, snmpOk: false, externalOk: true, cwmpRecent: null });
  eq('tunnel down but the site answers from outside -> TUNNEL_DOWN_SITE_UP', r.verdict, 'TUNNEL_DOWN_SITE_UP');
  check('nobody is dispatched for a routing problem', r.verdict !== 'SITE_DOWN');
}

{
  const child = evaluateReachability({ pppUp: false, snmpOk: null }, { concentratorDegraded: true });
  eq('a child of a degraded concentrator -> CONCENTRATOR_DEGRADED', child.verdict, 'CONCENTRATOR_DEGRADED');
  check('...and writes NO row: that is what "one alert, not 300" means', child.suppressed);
}

{
  const chr = evaluateReachability({ pppUp: null, snmpOk: false }, { isConcentrator: true });
  eq('the concentrator itself -> CONCENTRATOR_DEGRADED', chr.verdict, 'CONCENTRATOR_DEGRADED');
  check('...and it IS raised: it is the one alert', !chr.suppressed);
}

// ============================================================================

console.log(`\nM8 offline self-test: ${passed} passed, ${failures.length} failed`);
for (const f of failures) console.log(`  FAIL  ${f}`);
process.exit(failures.length === 0 ? 0 : 1);
