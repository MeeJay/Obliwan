/**
 * ObliWAN — the M2 acceptance test, end to end.
 *
 * The milestone recipe, verbatim from ARCHITECTURE.md §5:
 *
 *   "the CHR is declared, 3 lab sites appear as `pending`, manual binding,
 *    presence flips in under 2 s when the tunnel is cut, `UNREACHABLE` verdict
 *    distinct from `DOWN`."
 *
 * This runs it against a REAL PostgreSQL (migrations 001 + 002) and a fake CHR
 * that speaks the actual RouterOS binary protocol over a real TCP socket. There
 * is no mock of the transport, no stub of the database, and no in-memory
 * shortcut of the presence path: the only thing that is not real is the router
 * on the far end of the socket, because there is no lab CHR on this machine.
 *
 * Run:
 *   DATABASE_URL=postgres://... OBLIWAN_ENCRYPTION_KEY=<64 hex> \
 *   npx tsx src/services/fleet/testing/recipe.ts
 *
 * It DELETES the contents of the fleet tables it uses. It refuses to run
 * against a database whose URL is not obviously a throwaway (see `guard`).
 */

import { db } from '../../../db';
import { FakeChr } from './fakeChrServer';
import * as deviceService from '../device.service';
import * as siteService from '../site.service';
import {
  bindDiscovery,
  listDiscoveries,
  runChrDiscovery,
  setDiscoveryState,
} from '../concentratorDiscovery.service';
import { pppPresence, reconcile, RECONCILE_INTERVAL_MS } from '../pppPresence.service';
import { assertTargetBinding } from '../deviceBinding.service';
import { assessDevice, latestVerdict, markConcentratorDegraded } from '../reachability.service';
import { setFleetIO } from '../fleetEvents';
import { shutdownRouterOsPool } from '../routerosPool';

// ============================================================================
// Harness
// ============================================================================

let passed = 0;
const failures: string[] = [];
const notes: string[] = [];

function check(label: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed++;
    console.log(`  ok    ${label}`);
    return;
  }
  failures.push(`${label}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`);
  console.log(`  FAIL  ${label}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`);
}

function eq(label: string, actual: unknown, expected: unknown): void {
  check(label, Object.is(actual, expected), { actual, expected });
}

function note(text: string): void {
  notes.push(text);
  console.log(`  note  ${text}`);
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Captured `wan:*` emissions, with the wall-clock time they arrived. */
interface Emission {
  room: string;
  event: string;
  payload: any;
  at: number;
}
const emissions: Emission[] = [];

/** A Socket.io stand-in that records instead of transmitting. It is a duck of
 *  the two methods `fleetEvents` uses, which is the whole surface. */
function installFakeIo(): void {
  const io = {
    to(room: string) {
      return {
        emit(event: string, payload: unknown) {
          emissions.push({ room, event, payload, at: Date.now() });
        },
      };
    },
  };
  setFleetIO(io as never);
}

/** Wait for an emission matching `pred`, or give up. Returns the elapsed ms. */
async function waitForEmission(
  pred: (e: Emission) => boolean,
  budgetMs: number,
): Promise<{ found: Emission | null; elapsedMs: number }> {
  const started = Date.now();
  const from = emissions.length;
  while (Date.now() - started < budgetMs) {
    for (let i = from; i < emissions.length; i++) {
      if (pred(emissions[i])) {
        return { found: emissions[i], elapsedMs: emissions[i].at - started };
      }
    }
    await sleep(10);
  }
  return { found: null, elapsedMs: Date.now() - started };
}

// ============================================================================
// Main
// ============================================================================

const TENANT = 1;

async function main(): Promise<void> {
  const url = process.env.DATABASE_URL ?? '';
  if (!/localhost|127\.0\.0\.1|10\.0\.0\.152/.test(url)) {
    throw new Error(
      'Refusing to run: DATABASE_URL does not look like a throwaway database. ' +
        'This test truncates the fleet tables.',
    );
  }
  if (!/^[0-9a-fA-F]{64}$/.test(process.env.OBLIWAN_ENCRYPTION_KEY ?? '')) {
    throw new Error('OBLIWAN_ENCRYPTION_KEY must be 64 hex characters for this test');
  }

  installFakeIo();

  console.log('\n== 0. clean slate ==');
  // Order matters: reachability and sessions reference devices, and devices
  // self-reference through concentrator_id (ON DELETE RESTRICT).
  await db('reachability_verdicts').del();
  await db('ppp_sessions').del();
  await db('discoveries').del();
  await db('device_health').del();
  await db('device_transports').del();
  await db('devices').update({ concentrator_id: null });
  await db('devices').del();
  await db('sites').del();
  console.log('  fleet tables emptied');

  // `discoveries.reviewed_by` is a real FK: quarantine review is an audited
  // human act, so there has to be a human. Reuse the bootstrap admin if the
  // migration seeded one, otherwise make a reviewer.
  let reviewer = await db('users').first<{ id: number } | undefined>('id');
  if (!reviewer) {
    const [created] = await db('users')
      .insert({ username: 'recipe-operator', email: 'recipe@example.invalid', role: 'admin' })
      .returning<Array<{ id: number }>>('id');
    reviewer = created;
  }
  const REVIEWER = reviewer.id;
  console.log(`  reviewer user id = ${REVIEWER}`);

  // ---------------------------------------------------------------------
  console.log('\n== 1. declare the CHR ==');
  const chr = new FakeChr({
    identity: 'CHR-CENTRAL',
    username: 'obliwan',
    password: 'chr-s3cret',
    secrets: [
      { name: 'site-001', profile: 'l2tp-sites', remoteAddress: '10.66.0.11', comment: 'Lyon Nord' },
      { name: 'site-002', profile: 'l2tp-sites', remoteAddress: '10.66.0.12', comment: 'Paris Sud' },
      { name: 'site-003', profile: 'l2tp-sites', remoteAddress: '10.66.0.13', comment: 'Marseille' },
    ],
    sessions: [
      { name: 'site-001', address: '10.66.0.11', callerId: '203.0.113.11' },
      { name: 'site-002', address: '10.66.0.12', callerId: '203.0.113.12' },
      { name: 'site-003', address: '10.66.0.13', callerId: '203.0.113.13' },
    ],
  });
  const chrPort = await chr.listen(0);
  console.log(`  fake CHR listening on 127.0.0.1:${chrPort}`);

  const chrDevice = await deviceService.createDevice(TENANT, {
    name: 'CHR-CENTRAL',
    family: 'mikrotik_routeros7',
    role: 'concentrator',
    status: 'active',
  });
  const transport = await deviceService.upsertTransport(TENANT, chrDevice.id, 'routeros_api', {
    enabled: true,
    priority: 10,
    host: '127.0.0.1',
    port: chrPort,
    username: 'obliwan',
    secret: 'chr-s3cret',
  });

  check('the transport response carries no secret field at all', !('secret' in (transport as object)));
  check('...and no ciphertext either', !('secret_enc' in (transport as object)));
  eq('...it reports only that a secret exists', transport.hasSecret, true);
  eq('...stamped with the current key version', transport.keyVersion, 1);

  const stored = await db('device_transports')
    .where({ device_id: chrDevice.id, transport: 'routeros_api' })
    .first<{ secret_enc: string; key_version: number }>('secret_enc', 'key_version');
  check('the credential is stored as vault ciphertext', stored.secret_enc.startsWith('v1:1:'));
  check('...and the plaintext is nowhere in it', !stored.secret_enc.includes('chr-s3cret'));

  const test = await deviceService.testTransport(TENANT, chrDevice.id, 'routeros_api');
  check('the declared CHR answers on a real socket', test.ok, test.error);
  eq('...and identifies itself', test.identity?.systemIdentity, 'CHR-CENTRAL');
  eq('...with no serial, because a CHR is virtual (D5)', test.identity?.serial, null);

  // ---------------------------------------------------------------------
  console.log('\n== 2. discovery: 3 lab sites land in quarantine ==');
  const scan = await runChrDiscovery(chrDevice.id);
  eq('the CHR declared 3 PPP secrets', scan.secrets, 3);
  eq('3 sessions were up', scan.active, 3);
  eq('3 quarantine rows were created', scan.created, 3);
  eq('none was already known', scan.known, 0);

  const quarantine = await listDiscoveries({ concentratorIds: [chrDevice.id] });
  eq('the quarantine holds 3 rows', quarantine.total, 3);
  check(
    'ALL of them are pending — nothing was auto-bound (R4)',
    quarantine.items.every((d) => d.state === 'pending'),
    quarantine.items.map((d) => d.state),
  );
  check(
    'no device was silently created for them',
    (await db('devices').count<{ count: string }[]>('id as count'))[0].count === '1',
  );
  check(
    'the operator sees the CHR comment, which is where the site name lives',
    quarantine.items.some((d) => d.ppp_comment === 'Lyon Nord'),
  );

  const rescan = await runChrDiscovery(chrDevice.id);
  eq('a re-scan creates nothing new (idempotent UPSERT)', rescan.created, 0);
  eq('...it refreshes the 3 existing rows', rescan.refreshed, 3);

  // ---------------------------------------------------------------------
  console.log('\n== 3. manual binding ==');
  const site = await siteService.createSite(TENANT, { code: 'LYON-N', name: 'Lyon Nord' });
  const cpe = await deviceService.createDevice(TENANT, {
    name: 'RTR-LYON-NORD',
    family: 'mikrotik_routeros7',
    role: 'cpe',
    siteId: site.id,
    concentratorId: chrDevice.id,
  });
  const target = quarantine.items.find((d) => d.ppp_username === 'site-001')!;
  const bound = await bindDiscovery(target.id, cpe.id, REVIEWER);
  eq('the discovery is now bound', bound.state, 'bound');
  eq('...to the device the operator chose', bound.bound_device_id, cpe.id);
  eq("...and records WHO bound it", bound.reviewed_by, REVIEWER);

  const cpeRow = await deviceService.getDevice(TENANT, cpe.id);
  eq('the device inherited the PPP username', cpeRow?.ppp_username, 'site-001');
  eq('...and the tunnel address as "where to dial today"', cpeRow?.tunnel_ip, '10.66.0.11');

  const afterBind = await runChrDiscovery(chrDevice.id);
  eq('a bound username is no longer a discovery', afterBind.known, 1);
  eq('...and no new quarantine row appears for it', afterBind.created, 0);

  // A second device must not be able to claim the same PPP account.
  const rival = await deviceService.createDevice(TENANT, {
    name: 'RTR-RIVAL',
    family: 'mikrotik_routeros7',
    role: 'cpe',
    concentratorId: chrDevice.id,
  });
  let duplicateRefused = false;
  try {
    await db('devices').where({ id: rival.id }).update({ ppp_username: 'site-001' });
  } catch {
    duplicateRefused = true;
  }
  check('two devices cannot share one PPP username (presence would be ambiguous)', duplicateRefused);
  await db('devices').where({ id: rival.id }).del();

  const ignored = quarantine.items.find((d) => d.ppp_username === 'site-003')!;
  const ignoredRow = await setDiscoveryState(ignored.id, "ignored", REVIEWER);
  eq('a discovery can be marked "not ours"', ignoredRow.state, 'ignored');
  const afterIgnore = await runChrDiscovery(chrDevice.id);
  eq('...and a re-scan does NOT drag it back to pending', afterIgnore.created, 0);
  const stillIgnored = await db('discoveries').where({ id: ignored.id }).first<{ state: string }>('state');
  eq('...it is still ignored', stillIgnored.state, 'ignored');

  // ---------------------------------------------------------------------
  console.log('\n== 4. presence: listen + reconciliation ==');
  await pppPresence.watch(chrDevice.id);
  await sleep(200);
  check('exactly ONE /ppp/active/listen is registered on the CHR', chr.listenerCount === 1, chr.listenerCount);
  check('...over exactly ONE TCP session (R5)', chr.connectionCount === 1, chr.connectionCount);

  const openNow = await db('ppp_sessions').whereNull('ended_at').select('ppp_username');
  eq('the first sweep opened a session row per live tunnel', openNow.length, 3);
  const boundSession = await db('ppp_sessions')
    .where({ ppp_username: 'site-001' })
    .whereNull('ended_at')
    .first<{ device_id: number | null; tunnel_ip: string }>('device_id', 'tunnel_ip');
  eq('the bound device is attached to its session', boundSession.device_id, cpe.id);
  eq('...with the tunnel address the CHR handed out', boundSession.tunnel_ip, '10.66.0.11');

  const upVerdict = await latestVerdict(cpe.id);
  eq('a live tunnel reads as UP', upVerdict?.verdict, 'UP');

  // -- THE ACCEPTANCE MEASUREMENT ---------------------------------------
  console.log('\n== 5. cut the tunnel — presence must flip in under 2 s ==');
  emissions.length = 0;
  const cutAt = Date.now();
  chr.dropSession('site-001', 'peer-disconnect');
  const { found, elapsedMs } = await waitForEmission(
    (e) => e.event === 'wan:site:presence' && e.payload?.pppUsername === 'site-001' && e.payload?.up === false,
    5_000,
  );
  check('wan:site:presence was emitted for the cut tunnel', found !== null);
  const flipMs = found ? found.at - cutAt : -1;
  check(`...in ${flipMs} ms, under the 2000 ms the milestone requires`, flipMs >= 0 && flipMs < 2000, {
    flipMs,
    elapsedMs,
  });
  note(`observed presence flip latency: ${flipMs} ms (budget 2000 ms)`);

  eq('the event names the device', found?.payload?.deviceId, cpe.id);
  eq('...and the site', found?.payload?.siteId, site.id);

  // -- THE OTHER ACCEPTANCE CRITERION -----------------------------------
  eq(
    'the verdict in the event is UNREACHABLE, NOT SITE_DOWN',
    found?.payload?.verdict,
    'UNREACHABLE',
  );
  const downVerdict = await latestVerdict(cpe.id);
  eq('the persisted verdict agrees', downVerdict?.verdict, 'UNREACHABLE');
  check('...and it is not SITE_DOWN', downVerdict?.verdict !== 'SITE_DOWN');
  eq('...with the honest low confidence of a single signal', downVerdict?.confidence, 0.25);
  eq('...and a reason naming the missing evidence', downVerdict?.reason, 'ppp_down_no_independent_signal');

  const closed = await db('ppp_sessions')
    .where({ ppp_username: 'site-001' })
    .orderBy('id', 'desc')
    .first<{ ended_at: Date | null; duration_seconds: number | null; disconnect_reason: string | null }>(
      'ended_at',
      'duration_seconds',
      'disconnect_reason',
    );
  check('the session row was closed', closed.ended_at !== null);
  check('...with a duration', closed.duration_seconds !== null, closed.duration_seconds);
  eq('...and the reason the CHR gave', closed.disconnect_reason, 'peer-disconnect');

  // -- and back up -------------------------------------------------------
  console.log('\n== 6. the tunnel comes back ==');
  emissions.length = 0;
  const upAt = Date.now();
  chr.addSession({ name: 'site-001', address: '10.66.0.11', callerId: '203.0.113.11' });
  const back = await waitForEmission(
    (e) => e.event === 'wan:site:presence' && e.payload?.pppUsername === 'site-001' && e.payload?.up === true,
    5_000,
  );
  check('the recovery is reported too', back.found !== null);
  const upMs = back.found ? back.found.at - upAt : -1;
  check(`...in ${upMs} ms`, upMs >= 0 && upMs < 2000, { upMs });
  note(`observed recovery latency: ${upMs} ms`);
  eq('and the verdict is UP again', back.found?.payload?.verdict, 'UP');

  const sessionCount = await db('ppp_sessions').where({ ppp_username: 'site-001' }).count<{ count: string }[]>('id as count');
  eq('two session rows now exist — the flap is history, not a mutation', sessionCount[0].count, '2');

  // -- the event a listen can miss ---------------------------------------
  console.log('\n== 7. the missed event: reconciliation is not a fallback ==');
  chr.dropSessionSilently('site-002');
  await sleep(300);
  const stillOpen = await db('ppp_sessions')
    .where({ ppp_username: 'site-002' })
    .whereNull('ended_at')
    .first('id');
  check('a silently-dropped tunnel is NOT noticed by the listen (as expected)', !!stillOpen);

  const rec = await reconcile(chrDevice.id);
  eq('the 60 s sweep closes it', rec.closed, 1);
  const nowClosed = await db('ppp_sessions')
    .where({ ppp_username: 'site-002' })
    .whereNull('ended_at')
    .first('id');
  check('...and the database now agrees with the CHR', !nowClosed);
  const reason = await db('ppp_sessions')
    .where({ ppp_username: 'site-002' })
    .orderBy('id', 'desc')
    .first<{ disconnect_reason: string }>('disconnect_reason');
  eq('...marked as a reconciliation, not as a reported disconnect', reason.disconnect_reason, 'reconciled-missing');

  chr.addSessionSilently({ name: 'site-002', address: '10.66.0.12', callerId: '203.0.113.12' });
  const rec2 = await reconcile(chrDevice.id);
  eq('a silently-added tunnel is opened by the sweep too', rec2.opened, 1);

  // -- the timer itself, not just the function it calls -------------------
  // Off by default because it costs 70 s of wall clock. Run it with
  // RECIPE_SLOW=1 to prove that the 60 s sweep is actually SCHEDULED and not
  // merely callable — the difference between "reconciliation exists" and
  // "reconciliation happens" is a week of a device shown online while it is
  // not, and it is exactly the kind of thing a fast test suite never catches.
  if (process.env.RECIPE_SLOW === '1') {
    console.log('\n== 7b. the 60 s timer actually fires (RECIPE_SLOW) ==');
    chr.dropSessionSilently('site-003');
    const deadline = Date.now() + 75_000;
    let swept = false;
    while (Date.now() < deadline) {
      const row = await db('ppp_sessions')
        .where({ ppp_username: 'site-003' })
        .whereNull('ended_at')
        .first('id');
      if (!row) {
        swept = true;
        break;
      }
      await sleep(1_000);
    }
    check('the scheduled sweep closed a silently-dropped tunnel within 75 s', swept);
    note(`scheduled reconciliation interval is ${RECONCILE_INTERVAL_MS} ms`);
  } else {
    note('7b (the 60 s timer firing on its own) was SKIPPED — set RECIPE_SLOW=1 to run it');
  }

  // ---------------------------------------------------------------------
  console.log('\n== 8. identity: assertTargetBinding on a fresh connection (D5 / R4) ==');
  // Before anything is recorded, the assertion must REFUSE. The box answers
  // perfectly; we simply have nothing to compare its answer against, and
  // "reachable" is not "identified".
  const unrecorded = await assertTargetBinding(chrDevice.id, { throwOnFailure: false });
  check('a reachable box with NO recorded identity is refused, not accepted', !unrecorded.ok);
  check('...and the device is NOT quarantined for it (nothing contradicted)',
    (await db('devices').where({ id: chrDevice.id }).first<{ status: string }>('status')).status === 'active');

  await db('devices').where({ id: chrDevice.id }).update({ system_identity: 'CHR-CENTRAL' });

  const before = chr.connectionCount;
  const ok = await assertTargetBinding(chrDevice.id, { throwOnFailure: false });
  check('the CHR proves its identity', ok.ok, ok.reason);
  eq('...on system_identity', ok.checks.find((c) => c.attribute === 'system_identity')?.outcome, 'match');
  check('...over a connection opened for the purpose, not the pooled one', chr.connectionCount >= before);
  await sleep(150);
  check('...which is closed again afterwards', chr.connectionCount === before, {
    before,
    after: chr.connectionCount,
  });

  // Now move the identity under it: this is the pool-reassignment scenario,
  // and it is the whole reason the function exists.
  await db('devices').where({ id: chrDevice.id }).update({ system_identity: 'CHR-SOMEONE-ELSE' });
  const bad = await assertTargetBinding(chrDevice.id, { throwOnFailure: false, quarantineOnMismatch: true });
  check('a box answering a DIFFERENT identity is refused', !bad.ok);
  check('...and the reason says "NOT the recorded device"', bad.reason.includes('NOT the recorded device'), bad.reason);
  const quarantined = await db('devices').where({ id: chrDevice.id }).first<{ status: string; is_managed: boolean }>('status', 'is_managed');
  eq('...and the device is quarantined', quarantined.status, 'quarantined');
  eq('...and no longer managed', quarantined.is_managed, false);
  await db('devices').where({ id: chrDevice.id }).update({ system_identity: 'CHR-CENTRAL', status: 'active' });

  // A CPE that has never been probed has nothing to compare against: fail closed.
  const unproven = await assertTargetBinding(cpe.id, { throwOnFailure: false });
  check('a device with no reachable transport is REFUSED, not assumed', !unproven.ok);
  note(`fail-closed reason for an unconfigured device: ${unproven.reason}`);

  // ---------------------------------------------------------------------
  console.log('\n== 9. R5: a degraded concentrator suppresses its children ==');
  const degraded = await markConcentratorDegraded(chrDevice.id, 'simulated CHR outage');
  eq('one verdict is raised, on the concentrator', degraded.concentrator.verdict, 'CONCENTRATOR_DEGRADED');
  check('...and it IS written', degraded.concentrator.written);
  check('...while the children are suppressed', degraded.suppressedChildren >= 1, degraded.suppressedChildren);
  const childVerdictsBefore = (
    await db('reachability_verdicts').where({ device_id: cpe.id }).count<{ count: string }[]>('id as count')
  )[0].count;
  const suppressed = await assessDevice(cpe.id, {}, { concentratorDegraded: true });
  eq('a child assessed under a degraded CHR yields CONCENTRATOR_DEGRADED', suppressed.verdict, 'CONCENTRATOR_DEGRADED');
  check('...and writes NO row (one alert, not 300)', suppressed.written === false);
  const childVerdictsAfter = (
    await db('reachability_verdicts').where({ device_id: cpe.id }).count<{ count: string }[]>('id as count')
  )[0].count;
  eq('...the child verdict history is untouched', childVerdictsAfter, childVerdictsBefore);

  // ---------------------------------------------------------------------
  console.log('\n== 10. tenant scoping and secret leakage ==');
  const otherTenant = await db('tenants')
    .insert({ name: 'Other MSP', slug: 'other-msp' })
    .onConflict('slug')
    .merge({ name: 'Other MSP' })
    .returning<{ id: number }[]>('id');
  const otherId = otherTenant[0].id;
  const unseen = await deviceService.getDevice(otherId, cpe.id);
  check('another tenant cannot read this device', unseen === undefined);
  const otherList = await deviceService.listDevices(otherId);
  eq('...nor see it in a list', otherList.total, 0);
  const otherSites = await siteService.listSites(otherId);
  eq('...nor its sites', otherSites.length, 0);

  const detail = await deviceService.getDeviceDetail(TENANT, chrDevice.id);
  const serialised = JSON.stringify(detail);
  check('the full device payload contains no plaintext credential', !serialised.includes('chr-s3cret'));
  check('...and no ciphertext blob either', !serialised.includes('v1:1:'));
  check('...it does say a secret is present', serialised.includes('"hasSecret":true'));

  const health = await db('device_health').where({ device_id: chrDevice.id }).first<{ circuit_state: string; conn_state: string } | undefined>();
  check('the pool persisted its breaker state to device_health', health !== undefined, health);
  if (health) eq('...closed, because the CHR answered', health.circuit_state, 'closed');

  // ---------------------------------------------------------------------
  console.log('\n== 11. shutdown leaves nothing behind on the router ==');
  await pppPresence.unwatch(chrDevice.id);
  await sleep(200);
  eq('the /ppp/active/listen was cancelled on the CHR', chr.listenerCount, 0);

  await shutdownRouterOsPool();
  await chr.close();
}

main()
  .then(async () => {
    console.log(`\nM2 acceptance: ${passed} passed, ${failures.length} failed`);
    for (const n of notes) console.log(`  note  ${n}`);
    for (const f of failures) console.log(`  FAIL  ${f}`);
    await db.destroy();
    process.exit(failures.length === 0 ? 0 : 1);
  })
  .catch(async (err) => {
    console.error('\nrecipe aborted:', err);
    await db.destroy().catch(() => undefined);
    process.exit(2);
  });
