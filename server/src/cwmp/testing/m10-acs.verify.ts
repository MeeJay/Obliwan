/**
 * ObliWAN M10 — the ACS, verified against a real PostgreSQL and a real socket.
 *
 * ┌─ WHAT THIS PROVES, AND WHAT IT CANNOT ────────────────────────────────────┐
 * │ It proves the PROTOCOL LAYER, end to end, over TCP: the digest handshake, │
 * │ the cookie and its fallback, the session machine, the empty-POST signal,  │
 * │ the parser's `isArray` behaviour, the serialiser's well-formedness, the   │
 * │ task queue, the CommandKey correlation across two sessions, the HTTP file │
 * │ fetch, learn mode, and — the one that matters most — that not a single    │
 * │ credential from the parameter tree reaches a stored column.               │
 * │                                                                          │
 * │ IT PROVES NOTHING ABOUT A VIGOR OR A VMG. There is no DrayTek and no      │
 * │ Zyxel on this machine; §8.3 says so and §5/M10 says the milestone is not  │
 * │ closed until one of each has been through it in a lab. The client on the  │
 * │ other end of this socket is `fakeCpe.ts`, written by the same author as   │
 * │ the ACS from the same specification, and its agreement with the server is │
 * │ evidence about the specification, not about the hardware.                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 *   DATABASE_URL=… OBLIWAN_ENCRYPTION_KEY=… npx tsx \
 *     src/cwmp/testing/m10-acs.verify.ts
 */

import crypto from 'crypto';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import { db } from '../../db';
import { config } from '../../config';
import { createCwmpApp } from '../cwmpApp';
import { redactEnvelope } from '../../services/cwmp/rpcLog.service';
import { encrypt } from '../../services/secretVault.service';
import * as acs from '../../services/cwmp';
import { getDriver } from '../../services/drivers';
import { FakeCpe, parseChallenge, type SessionResult } from './fakeCpe';

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
  ok(label, JSON.stringify(a) === JSON.stringify(b), `got ${JSON.stringify(a)} want ${JSON.stringify(b)}`);
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

// ============================================================================
// Fixtures
// ============================================================================

const SLUG = `m10test${crypto.randomBytes(3).toString('hex')}`;
const PORT = 17547;
const HOST = '127.0.0.1';

interface Fixture {
  tenantId: number;
  vigorId: number;
  vmgId: number;
  mikrotikId: number;
  vigorCreds: { username: string; password: string };
  vmgCreds: { username: string; password: string };
  fileId: number;
  fileDir: string;
}

async function setup(): Promise<Fixture> {
  const tag = crypto.randomBytes(3).toString('hex');

  const [tenant] = (await db('tenants')
    .insert({ name: `M10 ${tag}`, slug: `m10-${tag}` })
    .returning('id')) as Array<{ id: number }>;
  const tenantId = tenant.id;

  const mkDevice = async (name: string, brand: string, family: string, model: string, serial: string) => {
    const [row] = (await db('devices')
      .insert({
        tenant_id: tenantId,
        name: `${name}-${tag}`,
        brand,
        family,
        model,
        serial,
        role: 'cpe',
        status: 'active',
      })
      .returning('id')) as Array<{ id: number }>;
    return row.id;
  };

  const vigorId = await mkDevice('vigor', 'draytek', 'draytek_vigor', 'Vigor2927', `VG${tag}`);
  const vmgId = await mkDevice('vmg', 'zyxel', 'zyxel_cpe', 'DX5401-B0', `ZY${tag}`);
  const mikrotikId = await mkDevice('chr', 'mikrotik', 'mikrotik_routeros7', 'CHR', `MT${tag}`);

  // ACS settings, with the slug the CPEs will POST to.
  await db('cwmp_acs_settings').insert({
    tenant_id: tenantId,
    tenant_slug: SLUG,
    digest_realm: 'obliwan-acs',
    allow_auto_enroll: false,
    rpc_log_enabled: false,
    default_periodic_inform_interval: 300,
  });
  acs.invalidateAcsSettings();

  const base = `http://${HOST}:${PORT}`;
  const vigorCreds = await acs.enrolDevice(vigorId, tenantId, 'obliwan-acs', base, SLUG);
  const vmgCreds = await acs.enrolDevice(vmgId, tenantId, 'obliwan-acs', base, SLUG);

  // A firmware image on disk, and its row.
  const fileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obliwan-cwmp-'));
  const payload = crypto.randomBytes(64 * 1024);
  fs.writeFileSync(path.join(fileDir, 'vigor.all'), payload);
  const [file] = (await db('cwmp_files')
    .insert({
      tenant_id: tenantId,
      name: `vigor-4.4.5.1-${tag}.all`,
      file_type: '1 Firmware Upgrade Image',
      storage_path: 'vigor.all',
      sha256: crypto.createHash('sha256').update(payload).digest('hex'),
      size_bytes: payload.length,
      brand: 'draytek',
      model_pattern: 'Vigor29*',
      version: '4.4.5.1',
    })
    .returning('id')) as Array<{ id: number }>;

  return {
    tenantId,
    vigorId,
    vmgId,
    mikrotikId,
    vigorCreds: { username: vigorCreds.username, password: vigorCreds.password },
    vmgCreds: { username: vmgCreds.username, password: vmgCreds.password },
    fileId: file.id,
    fileDir,
  };
}

async function teardown(fx: Fixture): Promise<void> {
  await db('tenants').where({ id: fx.tenantId }).del();
  try {
    fs.rmSync(fx.fileDir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}

// ============================================================================
// Small HTTP helpers for the tests that are not a CWMP session
// ============================================================================

function rawRequest(
  options: http.RequestOptions,
  body?: string | null,
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: HOST, port: PORT, ...options }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () =>
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }),
      );
    });
    req.on('error', reject);
    req.end(body ?? undefined);
  });
}

function cpeFor(
  fx: Fixture,
  which: 'vigor' | 'vmg',
  quirks: Record<string, boolean> = {},
): FakeCpe {
  return which === 'vigor'
    ? new FakeCpe({
        host: HOST,
        port: PORT,
        path: `/${SLUG}`,
        oui: '00507F',
        productClass: 'Vigor2927',
        serialNumber: fixtureSerial(fx, 'vigor'),
        manufacturer: 'DrayTek',
        dataModel: 'tr098',
        username: fx.vigorCreds.username,
        password: fx.vigorCreds.password,
        quirks,
      })
    : new FakeCpe({
        host: HOST,
        port: PORT,
        path: `/${SLUG}`,
        oui: '5C6A80',
        productClass: 'DX5401-B0',
        serialNumber: fixtureSerial(fx, 'vmg'),
        manufacturer: 'Zyxel',
        dataModel: 'tr181',
        username: fx.vmgCreds.username,
        password: fx.vmgCreds.password,
        quirks,
      });
}

const serials = new Map<string, string>();
function fixtureSerial(fx: Fixture, which: string): string {
  const key = `${fx.tenantId}:${which}`;
  if (!serials.has(key)) serials.set(key, `${which.toUpperCase()}-${fx.tenantId}-0001`);
  return serials.get(key)!;
}

/**
 * Bind an informing CPE to a device by rewriting the provisional cwmp_id.
 *
 * ┌─ THIS HELPER ONCE HID A BUG, AND THE NOTE STAYS ─────────────────────────┐
 * │ Production could not do this at all: `enrolDevice` wrote                 │
 * │ `PENDING-<id>-<serial>` and nothing ever replaced it, so an enrolled     │
 * │ device was challenged for ever — while every section below sailed past   │
 * │ because the harness did the step by hand in SQL.                          │
 * │                                                                          │
 * │ The step now exists (`findProvisionalCpe` + `bindProvisionalCwmpId`) and  │
 * │ section 13 walks from `enrolDevice()` to an InformResponse WITHOUT one    │
 * │ SQL fixture. This helper survives only because these fixtures give the    │
 * │ inventory a different serial from the one the box reports — the case the  │
 * │ enrolment comment describes and which no automatic path can resolve.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
async function bindCwmpId(deviceId: number, cwmpId: string): Promise<void> {
  await db('cwmp_devices').where({ device_id: deviceId }).update({ cwmp_id: cwmpId });
}

function allXmlValid(result: SessionResult): boolean {
  return result.exchanges.every((e) => e.xmlValid !== false);
}

// ============================================================================
// The run
// ============================================================================

async function main(): Promise<void> {
  console.log('ObliWAN M10 — ACS verification against a live PostgreSQL and a live socket\n');

  // The file server reads from here; the download URL is built from this base.
  const fx = await setup();
  (config.cwmp as { fileStorageDir: string }).fileStorageDir = fx.fileDir;
  (config.cwmp as { publicBaseUrl: string }).publicBaseUrl = `http://${HOST}:${PORT}`;

  const server = http.createServer(createCwmpApp());
  await new Promise<void>((resolve) => server.listen(PORT, HOST, resolve));
  console.log(`  CWMP listener up on ${HOST}:${PORT}, tenant slug "${SLUG}"\n`);

  try {
    await runAll(fx);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await teardown(fx);
    await db.destroy();
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.log('FAILURES:');
    for (const f of failures) console.log(`  - ${f}`);
    process.exitCode = 1;
  }
}

async function runAll(fx: Fixture): Promise<void> {
  // ══════════════════════════════════════════════════════════════════════════
  section('1. The listener answers the protocol, not HTTP conventions');
  // ══════════════════════════════════════════════════════════════════════════

  {
    // An EMPTY POST with no session. This is the single most important
    // negative: a body parser that rejects a zero-length body makes the whole
    // ACS silently dead, and the symptom appears nowhere near the cause.
    const res = await rawRequest(
      { method: 'POST', path: `/${SLUG}`, headers: { 'Content-Length': '0' } },
      '',
    );
    ok('empty POST is a protocol signal, not a 400', res.status === 204, `status ${res.status}`);
  }

  {
    const res = await rawRequest({ method: 'POST', path: '/nope-not-a-tenant' }, '');
    ok('unknown tenant slug is 404, never a default tenant', res.status === 404);
  }

  {
    const res = await rawRequest(
      { method: 'POST', path: `/${SLUG}`, headers: { 'Content-Type': 'text/xml' } },
      '<this is not xml',
    );
    ok('malformed envelope earns a CWMP fault, not a bare 400', res.status === 400);
    ok(
      '…and the fault body names the CWMP fault code 9003',
      res.body.toString().includes('9003'),
    );
  }

  {
    const res = await rawRequest({ method: 'GET', path: '/' });
    ok('GET on the ACS port explains itself', res.status === 404 && res.body.includes('CPEs POST'));
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('2. Digest — the handshake, and the refusal');
  // ══════════════════════════════════════════════════════════════════════════

  {
    const cpe = cpeFor(fx, 'vigor');
    await bindCwmpId(fx.vigorId, cpe.cwmpId);

    // Unauthenticated Inform first: the ACS must challenge.
    const bare = await rawRequest(
      { method: 'POST', path: `/${SLUG}`, headers: { 'Content-Type': 'text/xml' } },
      informOnly(cpe),
    );
    ok('an unauthenticated Inform is challenged', bare.status === 401, `status ${bare.status}`);
    const challenge = parseChallenge(bare.headers['www-authenticate']);
    ok('the challenge is Digest with a qop and a nonce', !!challenge && challenge.scheme === 'Digest' && !!challenge.nonce && !!challenge.qop);
  }

  {
    const wrong = cpeFor(fx, 'vigor');
    (wrong.opts as { password?: string }).password = 'definitely-not-the-password';
    const result = await wrong.session(['2 PERIODIC']);
    ok('a wrong password never gets past the challenge', result.error !== undefined && result.exchanges.some((e) => e.status === 401));
    eq('…and no session is opened for it', await openSessionsFor(fx.vigorId), 0);
  }

  {
    const basic = cpeFor(fx, 'vigor', { basicAuthOnly: true });
    const result = await basic.session(['2 PERIODIC']);
    ok('a CPE that only speaks Basic is refused, not looped', result.error !== undefined);
    const quirks = await quirksOf(fx.vigorId);
    ok('…and the refusal is recorded as the quirk `basicAuthOnly`', quirks.basicAuthOnly === true);
  }

  // ── THE REPLAY BOUND `digest.ts` USED TO ONLY PROMISE ────────────────────
  //
  // Its header said "replay within the window is bounded by the `nc` counter
  // recorded on the session row". There was no such column and no comparison,
  // and this listener is plain HTTP by design (§6.2), so anything on the path
  // could copy one `Authorization: Digest …` header and re-POST it for the
  // next five minutes to open a session with `authenticated = true`.
  //
  // Reproduced the way the observer does it: the SAME bytes, twice. Nothing
  // here recomputes a digest — `authFor` returns the header the honest CPE
  // produced — so what is asserted is the ACS's behaviour, not the test's md5.
  {
    const honest = cpeFor(fx, 'vigor');
    const observer = cpeFor(fx, 'vigor');   // same identity, no cookie of its own
    const inform = honest.buildInform(['2 PERIODIC']);

    const challenged = await honest.postRaw(inform, null);
    ok('the Inform is challenged before anything is captured', challenged.status === 401,
      `status ${challenged.status}`);
    const challenge = parseChallenge(challenged.headers['www-authenticate']);
    const header = honest.authFor(challenge!);

    const accepted = await honest.postRaw(inform, header);
    ok('the honest CPE authenticates with it once',
      accepted.status === 200 && /InformResponse/.test(accepted.responseBody),
      `status ${accepted.status}`);
    const sessionsAfterHonest = await openSessionsFor(fx.vigorId);

    const replayed = await observer.postRaw(inform, header);
    ok('the SAME captured header a second time is refused', replayed.status === 401,
      `status ${replayed.status}`);
    ok('…with stale=true, so an honest box retries instead of prompting',
      String(replayed.headers['www-authenticate'] ?? '').includes('stale=true'),
      String(replayed.headers['www-authenticate'] ?? '').slice(0, 80));
    eq('…and the replay opened no session', await openSessionsFor(fx.vigorId), sessionsAfterHonest);

    // The bound must not become a denial of service for the fleet it protects:
    // a fresh challenge, a fresh nonce, and the same box authenticates again.
    const again = await cpeFor(fx, 'vigor').session(['2 PERIODIC']);
    ok('a CPE that answers a FRESH challenge is still let in',
      again.error === undefined && again.authChallenges === 1,
      again.error ?? `${again.authChallenges} challenge(s)`);
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('3. TR-098 (DrayTek shape) — a full session');
  // ══════════════════════════════════════════════════════════════════════════

  let vigorSession: SessionResult;
  {
    const cpe = cpeFor(fx, 'vigor');
    vigorSession = await cpe.session(['1 BOOT', '0 BOOTSTRAP']);

    ok('the session completed without error', vigorSession.error === undefined, vigorSession.error ?? '');
    ok('every ACS response was well-formed XML', allXmlValid(vigorSession));
    ok('the ACS offered an ACSsession cookie', vigorSession.cookieOffered);
    ok('exactly one Digest challenge was needed', vigorSession.authChallenges === 1, `${vigorSession.authChallenges}`);
    ok(
      'a BOOTSTRAP triggered a full-tree read on the root partial path',
      vigorSession.rpcsReceived.includes('GetParameterValues'),
      vigorSession.rpcsReceived.join(', '),
    );

    const cwmp = await cpeRow(fx.vigorId);
    eq('the data model was derived from the tree, not assumed', cwmp.data_model, 'tr098');
    eq('…and the root prefix follows it', cwmp.root_prefix, 'InternetGatewayDevice.');
    ok('reachability is `online` after an Inform', cwmp.reachability === 'online');
    ok('the bootstrap timestamp was recorded', cwmp.last_bootstrap_at !== null);
    eq('the software version came off the wire', cwmp.software_version, '4.4.5.1');

    const params = await db('cwmp_parameters').where({ device_id: fx.vigorId }).count<{ count: string }[]>('* as count');
    const stored = Number(params[0].count);
    ok('the whole TR-098 tree was stored', stored >= 25, `${stored} parameters`);
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('4. §8.2 — NOT ONE CREDENTIAL REACHED A STORED COLUMN');
  // ══════════════════════════════════════════════════════════════════════════

  {
    const cpe = cpeFor(fx, 'vigor');
    const secrets = cpe.secretValues();
    ok('the fake CPE really did send credentials', secrets.length >= 3, `${secrets.length} secret values on the wire`);

    // The blunt instrument: search EVERY text and jsonb column of EVERY CWMP
    // table for the literal values the CPE sent. This is the check the last
    // audit's finding (L2TP passwords in a jsonb column served to the UI)
    // would have failed.
    const leaks: string[] = [];
    for (const secret of secrets) {
      for (const table of ['cwmp_parameters', 'cwmp_devices', 'cwmp_tasks', 'cwmp_sessions', 'cwmp_rpc_log']) {
        const hits = await scanTableForLiteral(table, secret);
        if (hits > 0) leaks.push(`${table} contains "${secret.slice(0, 4)}…" (${hits} rows)`);
      }
    }
    ok('no credential value appears anywhere in the CWMP schema', leaks.length === 0, leaks.join('; '));

    const secretRows = (await db('cwmp_parameters')
      .where({ device_id: fx.vigorId, is_secret: true })
      .select('path', 'value')) as Array<{ path: string; value: string | null }>;
    ok('the credential PATHS were kept', secretRows.length >= 3, `${secretRows.length} secret paths`);
    ok('…and every one of them has a NULL value', secretRows.every((r) => r.value === null));

    // The database refuses the row even if a future writer forgets.
    let refused = false;
    try {
      await db('cwmp_parameters').insert({
        device_id: fx.vigorId,
        path: 'InternetGatewayDevice.Test.Password',
        value: 'this-should-be-impossible',
        is_secret: true,
      });
    } catch {
      refused = true;
    }
    ok('the CHECK constraint refuses a secret row that carries a value', refused);

    // And the API layer.
    const listed = await acs.listParameters(fx.vigorId, { prefix: 'InternetGatewayDevice.WANDevice.' });
    const passwordRow = listed.parameters.find((p) => p.path.endsWith('.Password'));
    ok('the API returns the password parameter…', passwordRow !== undefined);
    ok('…with a null value and isSecret=true', passwordRow?.value === null && passwordRow?.isSecret === true);
  }

  {
    // The rpc-log redactor, on a body the parser would have rejected.
    const broken =
      '<Envelope><Name>Device.PPP.Interface.1.Password</Name><Value xsi:type="xsd:string">SuperSecret1</Value>' +
      '<Password>AnotherSecret</Password><unclosed>';
    const redacted = redactEnvelope(broken);
    ok('the envelope redactor works on unparseable XML', !redacted.includes('SuperSecret1') && !redacted.includes('AnotherSecret'), redacted.slice(0, 160));
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('5. TR-181 (Zyxel shape) — the same facts, different paths');
  // ══════════════════════════════════════════════════════════════════════════

  {
    const cpe = cpeFor(fx, 'vmg');
    await bindCwmpId(fx.vmgId, cpe.cwmpId);
    const result = await cpe.session(['0 BOOTSTRAP']);

    ok('the TR-181 session completed', result.error === undefined, result.error ?? '');
    ok('every ACS response was well-formed XML', allXmlValid(result));

    const cwmp = await cpeRow(fx.vmgId);
    eq('the data model was derived as tr181', cwmp.data_model, 'tr181');
    eq('…and the root prefix follows it', cwmp.root_prefix, 'Device.');

    const wanPath = 'Device.IP.Interface.2.IPv4Address.1.IPAddress';
    const values = await acs.valuesFor(fx.vmgId, [wanPath]);
    eq('the TR-181 WAN address was stored at its own path', values.get(wanPath), '90.11.202.44');

    // ── THE POINT OF THE CANONICAL LAYER: one name, two trees ──────────────
    const vigorWan = await canonicalOf(fx, fx.vigorId, 'draytek', 'tr098', 'Vigor2927');
    eq(
      'learn mode found the WAN address in the TR-098 tree',
      vigorWan['wan.external_ip'],
      '81.250.14.7',
    );

    // ── AND THE LIMIT OF IT, TESTED RATHER THAN PAPERED OVER ───────────────
    //
    // On TR-181 the WAN address is `Device.IP.Interface.2.IPv4Address.1.
    // IPAddress` and the LAN address is `Device.IP.Interface.1.IPv4Address.1.
    // IPAddress`. The two are STRUCTURALLY IDENTICAL — only the instance
    // number differs, and which instance is the WAN varies by model and by
    // firmware. TR-098 names the role in the path (`WANPPPConnection`);
    // TR-181 does not.
    //
    // Learn mode therefore refuses to guess, and that refusal is what is
    // asserted here: guessing mislabels a customer's LAN address as their
    // public one, which is worse than a blank field in every direction that
    // matters. The key comes back UNMAPPED, an operator maps it once for the
    // model, and it resolves from then on.
    const vmgCtx = {
      tenantId: fx.tenantId,
      dataModel: 'tr181' as const,
      brand: 'zyxel',
      model: 'DX5401-B0',
      firmware: null,
    };
    const unmapped = await acs.unmappedKeys(vmgCtx);
    ok(
      'learn mode refuses to guess the TR-181 WAN interface instance',
      unmapped.includes('wan.external_ip'),
      `unmapped: ${unmapped.join(', ')}`,
    );

    await acs.upsertMapping(fx.tenantId, {
      canonicalKey: 'wan.external_ip',
      dataModel: 'tr181',
      brand: 'zyxel',
      modelPattern: 'DX5401*',
      paramPath: 'Device.IP.Interface.2.IPv4Address.1.IPAddress',
      priority: 50,
    });
    const vmgWan = await canonicalOf(fx, fx.vmgId, 'zyxel', 'tr181', 'DX5401-B0');
    eq(
      "…and an operator's mapping resolves the TR-181 box's real address",
      vmgWan['wan.external_ip'],
      '90.11.202.44',
    );
    ok(
      'one canonical key now answers on both data models',
      vigorWan['wan.external_ip'] === '81.250.14.7' &&
        vmgWan['wan.external_ip'] === '90.11.202.44',
    );

    const learned = await acs.listMappings(fx.tenantId, { learnedOnly: true });
    ok('learn mode wrote its proposals as `learned` rows for review', learned.length >= 8, `${learned.length} learned mappings`);
    ok('…generalised with {i} instance placeholders', learned.some((m) => m.paramPath.includes('{i}')), learned.map((m) => m.paramPath).find((p) => p.includes('{i}')) ?? 'none');

    // A learned mapping must NEVER be a shipped-library row.
    const libraryLearned = (await db('cwmp_param_map').whereNull('tenant_id').andWhere('learned', true).count<{ count: string }[]>('* as count'))[0];
    eq('learn mode never writes into the shipped library', Number(libraryLearned.count), 0);
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('6. The quirks — one per broken firmware behaviour');
  // ══════════════════════════════════════════════════════════════════════════

  {
    // SINGLE-ELEMENT ARRAY. Without `isArray` the parser returns an object and
    // everything downstream throws. The session simply has to work.
    const cpe = cpeFor(fx, 'vigor', { singleElementArray: true });
    const result = await cpe.session(['2 PERIODIC']);
    ok('a one-element ParameterList does not break the parser', result.error === undefined, result.error ?? '');
    ok('…and the session still produced a valid InformResponse', result.exchanges.some((e) => e.responseBody.includes('InformResponse')));
  }

  {
    const cpe = cpeFor(fx, 'vigor', { badXsiType: true });
    const result = await cpe.session(['2 PERIODIC']);
    ok('a bad or missing xsi:type does not break the session', result.error === undefined, result.error ?? '');
    const quirks = await quirksOf(fx.vigorId);
    ok('…and it is recorded as the quirk `badXsiType`', quirks.badXsiType === true);
    const types = (await db('cwmp_parameters')
      .where({ device_id: fx.vigorId })
      .distinct('value_type')
      .pluck('value_type')) as string[];
    ok('…and every stored value_type is still a canonical xsd type', types.every((t) => t.startsWith('xsd:')), types.join(','));
  }

  {
    const cpe = cpeFor(fx, 'vigor', { noCwmpId: true });
    const result = await cpe.session(['2 PERIODIC']);
    ok('an envelope with no cwmp:ID is accepted', result.error === undefined, result.error ?? '');
    const quirks = await quirksOf(fx.vigorId);
    ok('…and recorded as the quirk `noCwmpId`', quirks.noCwmpId === true);
  }

  {
    const cpe = cpeFor(fx, 'vigor', { arrayCountMismatch: true });
    await cpe.session(['2 PERIODIC']);
    const quirks = await quirksOf(fx.vigorId);
    ok('a lying soap-enc:arrayType count is recorded, not fatal', quirks.arrayCountMismatch === true);
  }

  {
    // NO COOKIE — and there is NO LONGER an address-keyed fallback behind it.
    //
    // A cookie-less CPE used to be matched on its source address, which is how
    // an unauthenticated empty POST could adopt a live session and be handed a
    // vault value (audit finding 1); under A6 that address is the Docker bridge
    // for the whole fleet, so it did not even mean "another CPE of the same
    // customer". What is asserted here is the honest consequence: the box is
    // READ but never DRIVEN, its task is not mis-delivered, and the quirk is
    // recorded on the next Inform — where the box has proved who it is.
    const task = await acs.enqueueTask(fx.vigorId, {
      kind: 'get_parameter_values',
      paths: ['InternetGatewayDevice.DeviceInfo.SerialNumber'],
    });
    const cpe = cpeFor(fx, 'vigor', { noCookie: true });

    const first = await cpe.session(['2 PERIODIC']);
    ok('a cookie-less CPE still gets its InformResponse', first.error === undefined, first.error ?? '');
    ok(
      '…but receives NO RPC: a source address is not an identity',
      !first.rpcsReceived.includes('GetParameterValues'),
      first.rpcsReceived.join(', '),
    );
    eq('…and its task is left queued, not mis-delivered', (await acs.getTask(task.id))?.state, 'queued');

    const second = await cpe.session(['2 PERIODIC']);
    ok('…and the box keeps informing', second.error === undefined, second.error ?? '');
    const quirks = await quirksOf(fx.vigorId);
    ok('…and the dropped cookie is recorded as the quirk `noCookie`', quirks.noCookie === true);
    await acs.cancelTask(task.id, fx.vigorId);
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('7. The task queue — and decision D3');
  // ══════════════════════════════════════════════════════════════════════════

  {
    let refused = false;
    let message = '';
    try {
      await acs.enqueueTask(fx.vigorId, { kind: 'reboot' });
    } catch (err) {
      refused = err instanceof acs.TaskRefusedError;
      message = (err as Error).message;
    }
    ok('a reboot without a change job is REFUSED (D3)', refused, message);
  }

  {
    let refused = false;
    try {
      await acs.enqueueTask(fx.vigorId, {
        kind: 'set_parameter_values',
        ops: [{ path: 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID', valueType: 'xsd:string', value: 'x' }],
      });
    } catch (err) {
      refused = err instanceof acs.TaskRefusedError;
    }
    ok('a parameter write without a change job is REFUSED (D3)', refused);
  }

  {
    // The narrow, whitelisted plumbing exception.
    const task = await acs.enqueueTask(
      fx.vigorId,
      {
        kind: 'set_parameter_values',
        ops: [
          {
            path: 'InternetGatewayDevice.ManagementServer.PeriodicInformInterval',
            valueType: 'xsd:unsignedInt',
            value: '60',
          },
        ],
      },
      { acsPlumbing: true },
    );
    ok('the inform-interval write IS allowed as ACS plumbing', task.state === 'queued');
    await acs.cancelTask(task.id, fx.vigorId);
  }

  {
    // …and the exception cannot be widened by claiming the flag.
    let refused = false;
    try {
      await acs.enqueueTask(
        fx.vigorId,
        {
          kind: 'set_parameter_values',
          ops: [
            { path: 'InternetGatewayDevice.ManagementServer.PeriodicInformInterval', valueType: 'xsd:unsignedInt', value: '60' },
            { path: 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID', valueType: 'xsd:string', value: 'pwned' },
          ],
        },
        { acsPlumbing: true },
      );
    } catch (err) {
      refused = err instanceof acs.TaskRefusedError;
    }
    ok('claiming `acsPlumbing` on a non-whitelisted path is refused', refused);
  }

  {
    // ── The two independent guards on a credential in a task payload ───────
    //
    // 1. THE DATABASE. `cwmp_tasks_payload_no_secret_chk` refuses any payload
    //    carrying a JSON KEY named like a credential — the shape a writer
    //    produces when they take the obvious shortcut (`{password: "..."}`).
    let dbRefused = false;
    try {
      await db('cwmp_tasks').insert({
        device_id: fx.vigorId,
        kind: 'set_parameter_values',
        command_key: acs.newCommandKey('dbchk'),
        payload: JSON.stringify({ kind: 'set_parameter_values', password: 'oops', ops: [] }),
        expires_at: new Date(Date.now() + 60_000),
      });
    } catch {
      dbRefused = true;
    }
    ok('the database refuses a task payload with a credential-shaped key', dbRefused);

    // 2. THE SERIALISER. A payload whose KEYS are innocent but whose VALUE is a
    //    literal on a credential PATH gets past the CHECK — and must then be
    //    refused at the one place a secret is ever resolved, on the way to the
    //    socket. Proven end to end: the task is dispatched to a live CPE and
    //    comes back FAILED without a single byte of the value leaving here.
    const job = await openChangeJob(fx, fx.vigorId, 'reboot');
    const task = await acs.enqueueTask(
      fx.vigorId,
      {
        kind: 'set_parameter_values',
        ops: [
          {
            path: 'InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password',
            valueType: 'xsd:string',
            value: 'plaintext-in-a-task-row',
          },
        ],
      },
      { changeJobId: job },
    );

    const cpe = cpeFor(fx, 'vigor');
    const result = await cpe.session(['2 PERIODIC']);
    const after = await acs.getTask(task.id);
    eq('the serialiser refuses a literal on a credential path', after?.state, 'failed');
    ok('…and the value never reached the CPE', !JSON.stringify(result).includes('plaintext-in-a-task-row'));
    ok(
      '…and the fault says why',
      (after?.fault?.faultString ?? '').includes('vault'),
      after?.fault?.faultString ?? '',
    );
    await closeChangeJob(job);
  }

  {
    // The refresh that does not lie.
    const outcome = await acs.requestRefresh(fx.vigorId, null);
    eq('refresh reports that Connection Request is NOT supported', outcome.supported, false);
    eq('…and that what it did was lower the inform interval', outcome.action, 'periodic_interval_lowered');
    ok('…and it carries the verbatim explanation for the UI', outcome.explanation.includes('Connection Request'));
    ok('…and an ETA derived from the CURRENT interval', typeof outcome.etaSeconds === 'number');

    const again = await acs.requestRefresh(fx.vigorId, null);
    eq('a second refresh does not stack a second write', again.action, 'already_pending');

    // Clean up so it does not interfere with the download test below.
    for (const t of await acs.listTasks(fx.vigorId, { states: ['queued'] })) {
      await acs.cancelTask(t.id, fx.vigorId);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('8. Download, the HTTP fetch, and TransferComplete across sessions');
  // ══════════════════════════════════════════════════════════════════════════

  {
    const job = await openChangeJob(fx, fx.vigorId, 'firmware');

    const file = await acs.getFile(fx.fileId, fx.tenantId);
    ok('the firmware file is visible to its tenant', file !== null);

    // The model gate: this image says Vigor29*, so a Zyxel must be refused.
    let mismatch = false;
    try {
      acs.assertFileFitsDevice(file!, { brand: 'zyxel', model: 'DX5401-B0' });
    } catch (err) {
      mismatch = err instanceof acs.TransferRefusedError;
    }
    ok('a firmware image is refused for the wrong brand/model', mismatch);

    const task = await acs.enqueueTask(
      fx.vigorId,
      {
        kind: 'download',
        fileType: '1 Firmware Upgrade Image',
        fileId: fx.fileId,
        fileSize: file!.sizeBytes,
      },
      { changeJobId: job },
    );

    // Session A: the ACS sends Download, the CPE accepts with Status = 1.
    const cpe = cpeFor(fx, 'vigor');
    const sessionA = await cpe.session(['2 PERIODIC']);
    ok('the CPE received the Download RPC', cpe.downloads.length === 1, sessionA.rpcsReceived.join(', '));
    const download = cpe.downloads[0];
    eq('…carrying the task CommandKey', download.commandKey, task.commandKey);
    eq('…and the right FileType', download.fileType, '1 Firmware Upgrade Image');
    ok('…and a tokenised URL with no credentials in it', download.url.includes('/cwmp-files/') && !download.url.includes('@'), download.url.replace(/\/cwmp-files\/.*/, '/cwmp-files/<token>'));

    // The CPE fetches the file over plain HTTP, with no session of ours.
    const fetched = await rawRequest({ method: 'GET', path: new URL(download.url).pathname });
    eq('the file server serves the image on the token alone', fetched.status, 200);
    eq('…with the exact byte count', fetched.body.length, file!.sizeBytes);
    eq(
      '…and the exact content',
      crypto.createHash('sha256').update(fetched.body).digest('hex'),
      file!.sha256,
    );

    const forged = await rawRequest({ method: 'GET', path: '/cwmp-files/' + 'z'.repeat(43) });
    eq('a forged token is a 404, not a 403 (no oracle)', forged.status, 404);

    // Session B: the TransferComplete arrives LATER, correlated by CommandKey
    // and by nothing else.
    const sessionB = await cpe.transferComplete(task.commandKey, '0', '');
    ok('the TransferComplete session completed', sessionB.error === undefined, sessionB.error ?? '');

    const transfer = (await db('cwmp_transfers').where({ command_key: task.commandKey }).first()) as
      | { state: string; http_fetched_at: Date | null; fetch_count: number }
      | undefined;
    eq('the transfer is completed', transfer?.state, 'completed');
    ok('…and it recorded that the CPE actually fetched', transfer!.fetch_count >= 1);

    const after = await acs.getTaskByCommandKey(task.commandKey);
    eq('the task is done', after?.state, 'done');
    await closeChangeJob(job);
  }

  {
    // A FAILED transfer must correct the task, not leave it saying "succeeded".
    const job = await openChangeJob(fx, fx.vigorId, 'firmware');

    const file = await acs.getFile(fx.fileId, fx.tenantId);
    const task = await acs.enqueueTask(
      fx.vigorId,
      { kind: 'download', fileType: '1 Firmware Upgrade Image', fileId: fx.fileId, fileSize: file!.sizeBytes },
      { changeJobId: job },
    );

    const cpe = cpeFor(fx, 'vigor');
    await cpe.session(['2 PERIODIC']);
    await cpe.transferComplete(task.commandKey, '9010', 'Download failure');

    const after = await acs.getTaskByCommandKey(task.commandKey);
    eq('a failed transfer flips the task back to failed', after?.state, 'failed');
    eq('…carrying the CPE fault code', after?.fault?.code, '9010');
    await closeChangeJob(job);
  }

  {
    const unmatched = await acs.completeTransfer({
      commandKey: 'not-a-command-key-we-ever-issued',
      faultCode: '0',
      faultString: '',
      startTime: null,
      completeTime: null,
    });
    eq('an unmatched TransferComplete is reported, not swallowed', unmatched.matched, false);
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('9. Risk R2 — the coverage the product SHOWS');
  // ══════════════════════════════════════════════════════════════════════════

  {
    let refused = false;
    let message = '';
    try {
      await acs.enrolDevice(fx.mikrotikId, fx.tenantId, 'obliwan-acs', 'http://x', SLUG);
    } catch (err) {
      refused = err instanceof acs.AcsEnrolmentError;
      message = (err as Error).message;
    }
    ok('a MikroTik cannot be enrolled in the ACS', refused);
    ok('…and the refusal says WHY, in words for the operator', message.includes('RouterOS has no TR-069 client'), message.slice(0, 100));

    const report = await acs.coverageReport(fx.tenantId);
    const mikrotik = report.fleet.find((f) => f.brand === 'mikrotik');
    const draytek = report.fleet.find((f) => f.brand === 'draytek');
    eq('the coverage report counts the MikroTik in the fleet', mikrotik?.devices, 1);
    eq('…and reports zero of them enrolled', mikrotik?.cwmpEnrolled, 0);
    eq('…while the DrayTek is enrolled', draytek?.cwmpEnrolled, 1);
    ok('…and it says out loud that Connection Request is unsupported', report.connectionRequestSupported === false && report.connectionRequestExplanation.length > 80);
    eq('…for all four brands, including the two with no CWMP client', report.brands.filter((b) => !b.hasCwmpClient).map((b) => b.brand), ['mikrotik', 'sonicwall']);
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('10. The unknown CPE, the session reaper, and the sweeps');
  // ══════════════════════════════════════════════════════════════════════════

  {
    const stranger = new FakeCpe({
      host: HOST,
      port: PORT,
      path: `/${SLUG}`,
      oui: 'AABBCC',
      productClass: 'Vigor166',
      serialNumber: 'NEVER-SEEN-0001',
      dataModel: 'tr098',
      username: 'x',
      password: 'y',
    });
    const result = await stranger.session(['0 BOOTSTRAP']);
    ok('an unknown CPE is refused', result.error !== undefined);

    const knocks = await acs.listUnknownCallers();
    ok(
      '…and RECORDED so an operator can see it knocking',
      knocks.some((k) => k.cwmpId === 'AABBCC-Vigor166-NEVER-SEEN-0001'),
      knocks.map((k) => k.cwmpId).join(', '),
    );
    const devices = await db('devices').where({ serial: 'NEVER-SEEN-0001' }).count<{ count: string }[]>('* as count');
    eq('…and NO device row was created for it (risk R4)', Number(devices[0].count), 0);
  }

  {
    // A task handed out and never answered has to come back.
    const task = await acs.enqueueTask(fx.vigorId, {
      kind: 'get_parameter_values',
      paths: ['InternetGatewayDevice.DeviceInfo.UpTime'],
    });
    // Open a session and take the RPC, then walk away.
    const cpe = cpeFor(fx, 'vigor');
    await cpe.session(['2 PERIODIC'], 1); // Inform only; the loop is capped
    await db('cwmp_sessions')
      .where({ device_id: fx.vigorId, state: 'open' })
      .update({ pending_task_id: task.id, last_seen_at: db.raw("now() - interval '1 hour'") });
    await db('cwmp_tasks').where({ id: task.id }).update({ state: 'sent', sent_at: db.fn.now(), attempts: 1 });

    const reaped = await acs.reapIdleSessions(60);
    ok('the reaper closed the abandoned session', reaped >= 1, `${reaped} sessions`);
    const after = await acs.listTasks(fx.vigorId, { limit: 200 });
    const requeued = after.find((t) => t.id === task.id);
    eq('…and returned its in-flight task to the queue', requeued?.state, 'queued');
    await acs.cancelTask(task.id, fx.vigorId);
  }

  {
    const task = await acs.enqueueTask(
      fx.vigorId,
      { kind: 'get_parameter_values', paths: ['InternetGatewayDevice.DeviceInfo.UpTime'] },
      { ttlSeconds: 1 },
    );
    await db('cwmp_tasks').where({ id: task.id }).update({ expires_at: db.raw("now() - interval '1 minute'") });
    const expired = await acs.expireStaleTasks();
    ok('stale intent expires rather than executing a week late', expired >= 1);
    const after = (await db('cwmp_tasks').where({ id: task.id }).first('state')) as { state: string };
    eq('…and the task is `expired`', after.state, 'expired');
  }

  {
    await db('cwmp_devices').where({ device_id: fx.vigorId }).update({
      last_inform_at: db.raw("now() - interval '3 hours'"),
      periodic_inform_interval: 300,
    });
    const { changed } = await acs.refreshReachability();
    ok('reachability decays with time, without any event', changed >= 1, `${changed} devices reclassified`);
    const cwmp = await cpeRow(fx.vigorId);
    eq('…to `lost` after many missed informs', cwmp.reachability, 'lost');
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('11. The RPC log — off by default, on twice to turn on (risk R7)');
  // ══════════════════════════════════════════════════════════════════════════

  {
    eq('logging is off by default', await acs.loggingEnabledFor(fx.vigorId), false);

    await db('cwmp_devices').where({ device_id: fx.vigorId }).update({ rpc_log_enabled: true });
    acs.invalidateRpcLogGate();
    eq('the device switch alone is not enough', await acs.loggingEnabledFor(fx.vigorId), false);

    await acs.updateSettings(fx.tenantId, { rpcLogEnabled: true });
    acs.invalidateRpcLogGate();
    eq('both switches together enable it', await acs.loggingEnabledFor(fx.vigorId), true);

    await db('cwmp_devices').where({ device_id: fx.vigorId }).update({ periodic_inform_interval: 300 });

    // Queue a SUBTREE read so the logged session carries a
    // GetParameterValuesResponse containing the PPPoE password and the Wi-Fi
    // passphrase. Logging a session that happens to contain no credential
    // would make the assertion below pass for the wrong reason.
    await acs.enqueueTask(fx.vigorId, {
      kind: 'get_parameter_values',
      paths: ['InternetGatewayDevice.'],
    });
    const cpe = cpeFor(fx, 'vigor');
    await cpe.session(['2 PERIODIC']);

    const entries = await acs.readRpcLog({ deviceId: fx.vigorId, limit: 50 });
    ok('envelopes are logged once it is on', entries.length >= 4, `${entries.length} entries`);
    ok(
      '…including the subtree response that carries the credentials',
      entries.some((e) => (e.body ?? '').includes('WANPPPConnection.1.Password')),
    );
    const bodies = entries.map((e) => e.body ?? '').join('\n');
    const secrets = cpe.secretValues();
    ok(
      'and NOT ONE credential appears in a logged body',
      secrets.every((s) => !bodies.includes(s)),
      secrets.find((s) => bodies.includes(s)) ? 'a secret leaked into the log' : '',
    );
    ok('…while the redaction marker does', bodies.includes('***REDACTED***'));
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('12. The driver layer — the ACS is a transport, not an island');
  // ══════════════════════════════════════════════════════════════════════════

  {
    // Enrolment must have created the `device_transports` row, or
    // `pickTransport(ctx, 'cwmp')` finds nothing and the driver's CWMP branch
    // is skipped in silence — device enrolled, informing happily, probed as
    // "no channel answered".
    const transport = (await db('device_transports')
      .where({ device_id: fx.vigorId, transport: 'cwmp' })
      .first('enabled', 'priority', 'host')) as
      | { enabled: boolean; priority: number; host: string | null }
      | undefined;
    ok('enrolment created the cwmp device_transports row', transport !== undefined);
    ok('…enabled and ahead of ssh in the priority order', transport?.enabled === true && transport!.priority < 100);
    eq('…with no host, because there is nothing to dial', transport?.host, null);
  }

  {
    const draytek = getDriver('draytek_vigor');
    const zyxelCpe = getDriver('zyxel_cpe');
    ok('the DrayTek driver now declares CWMP', draytek.capabilities.supportsCwmp === true);
    ok('the Zyxel CPE driver now declares CWMP', zyxelCpe.capabilities.supportsCwmp === true);
    eq(
      '…and CWMP is first in the DrayTek priority order',
      draytek.capabilities.transportPriority[0],
      'cwmp',
    );
    // Risk R2, at the driver layer this time.
    ok(
      'MikroTik still declares no CWMP, and always will',
      getDriver('mikrotik_routeros7').capabilities.supportsCwmp === false,
    );
    ok(
      'SonicWall still declares no CWMP, and always will',
      getDriver('sonicwall_sonicos').capabilities.supportsCwmp === false,
    );
  }

  {
    // Make the Vigor look freshly informed again — section 10 aged it out.
    await db('cwmp_devices').where({ device_id: fx.vigorId }).update({ last_inform_at: db.fn.now() });

    const facts = await acs.cwmpInventory(fx.vigorId);
    eq('the ACS bridge reports the model off the wire', facts?.model, 'Vigor2927');
    eq('…the firmware version', facts?.osVersion, '4.4.5.1');
    eq('…and the WAN address through the canonical map', facts?.wanAddress, '81.250.14.7');
    ok('…with the time the CPE actually said it, not now()', facts?.observedAt !== null);

    const inventory = await draytekInventory(fx.vigorId);
    eq('the DrayTek driver identifies over CWMP without dialling', inventory.collectedVia, 'cwmp');
    eq('…reporting the same model', inventory.model, 'Vigor2927');
    eq(
      '…and stamping collectedAt with the last inform, not the clock',
      inventory.collectedAt,
      facts?.observedAt,
    );
  }

  {
    const document = await acs.cwmpConfigDocument(fx.vigorId);
    ok('the parameter tree renders as a stable configuration document', (document ?? '').length > 500);
    ok('…sorted, so an unchanged CPE hashes identically twice', isSorted((document ?? '').split('\n')));
    ok(
      '…with credential paths PRESENT but marked, never dropped',
      (document ?? '').includes('WANPPPConnection.1.Password = (secret, not stored)'),
      (document ?? '').split('\n').find((l) => l.includes('.Password')) ?? 'no password line',
    );
    const secrets = cpeFor(fx, 'vigor').secretValues();
    ok('…and no credential value in it', secrets.every((s) => !(document ?? '').includes(s)));

    const twice = await acs.cwmpConfigDocument(fx.vigorId);
    eq('…and it is byte-identical on a second render', twice, document);
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('13. The audit findings, reproduced and closed');
  // ══════════════════════════════════════════════════════════════════════════
  //
  // Every block below FIRST replays the exact attack the audit reported, then
  // asserts that the legitimate flow it sits next to still works. A guard that
  // also breaks the CPE is not a fix, it is an outage with a good excuse.

  {
    // ── F1. A session may not be adopted from a source address ────────────
    //
    // Was: an empty POST with no cookie fell back to "the most recent open
    // session of this address", which under A6 is "the last CPE of this tenant
    // to inform, whichever one it was", and was handed the next queued RPC —
    // with a vault value decrypted into it.
    const job = await openChangeJob(fx, fx.vigorId, 'reboot');
    const secret = `VAULT-PPPOE-${crypto.randomBytes(6).toString('hex')}`;
    const task = await acs.enqueueTask(
      fx.vigorId,
      {
        kind: 'set_parameter_values',
        ops: [
          {
            path: 'InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password',
            valueType: 'xsd:string',
            secretRef: encrypt(secret),
          },
        ],
      },
      { changeJobId: job },
    );

    // The CPE informs and STOPS: an open, authenticated session with a task
    // waiting for it. This is the window the attacker used.
    const cpe = cpeFor(fx, 'vigor');
    const opened = await cpe.session(['2 PERIODIC'], 0);
    ok('the CPE opened an authenticated session', opened.error === undefined, opened.error ?? '');
    eq('…and it is open in the database', await openSessionsFor(fx.vigorId), 1);

    // The attack: one empty POST. Same address, no cookie, no Inform, no
    // credential. Twice, because the task is requeued and was harvestable in a
    // loop.
    for (const attempt of [1, 2]) {
      const attacker = await rawRequest(
        { method: 'POST', path: `/${SLUG}`, headers: { 'Content-Length': '0' } },
        '',
      );
      ok(
        `an empty POST with no cookie cannot adopt a session (attempt ${attempt})`,
        attacker.status === 204,
        `status ${attacker.status}`,
      );
      ok(
        `…and gets no vault value (attempt ${attempt})`,
        !attacker.body.toString().includes(secret),
      );
    }
    eq('…and the task was not consumed by it', (await acs.getTask(task.id))?.state, 'queued');

    // …and the CPE that holds the cookie still gets its write.
    const legit = cpeFor(fx, 'vigor');
    const done = await legit.session(['2 PERIODIC']);
    ok(
      'the CPE that authenticated still receives the SetParameterValues',
      done.rpcsReceived.includes('SetParameterValues'),
      done.rpcsReceived.join(', '),
    );
    ok(
      '…with the value resolved from the vault',
      legit.setsApplied.some((s) => s.value === secret),
    );
    eq('…and the task completes', (await acs.getTask(task.id))?.state, 'done');

    // §8.2, on the path this test just exercised.
    const leaks: string[] = [];
    for (const table of ['cwmp_parameters', 'cwmp_devices', 'cwmp_tasks', 'cwmp_sessions', 'cwmp_rpc_log']) {
      if ((await scanTableForLiteral(table, secret)) > 0) leaks.push(table);
    }
    ok('…and the vault value is in no stored column', leaks.length === 0, leaks.join(', '));
    await closeChangeJob(job);
  }

  {
    // ── F2. Three branches of four had no authentication gate ─────────────
    //
    // An auto-bound CPE has a `cwmp_devices` row and NO credential: the ACS
    // accepts its Inform read-only. The guard used to live in `handleEmptyPost`
    // alone, so a forged `GetParameterValuesResponse` on that same session both
    // wrote into `cwmp_parameters` and collected the next queued RPC.
    await acs.updateSettings(fx.tenantId, { allowAutoEnroll: true });
    acs.invalidateAcsSettings();

    const serial = `AUTOBIND-${crypto.randomBytes(3).toString('hex')}`;
    const strayId = await mkFixtureDevice(fx, 'stray', 'draytek', 'draytek_vigor', 'Vigor2927', serial);

    const stray = new FakeCpe({
      host: HOST,
      port: PORT,
      path: `/${SLUG}`,
      oui: '00507F',
      productClass: 'Vigor2927',
      serialNumber: serial,
      manufacturer: 'DrayTek',
      dataModel: 'tr098',
      username: 'nobody',
      password: 'nothing',
    });
    const bound = await stray.session(['0 BOOTSTRAP'], 0);
    ok('an auto-bound CPE with no credential is accepted read-only', bound.error === undefined, bound.error ?? '');
    const strayRow = await cwmpRowOf(strayId);
    eq('…with no credential stored for it', strayRow.acs_auth_ha1_enc ?? null, null);

    const cookie = cookieOf(bound);
    ok('…and it was given a session cookie', cookie !== null);

    // A mutating task with a vault value is waiting. The forged response must
    // neither collect it nor write a parameter.
    const job = await openChangeJob(fx, strayId, 'reboot');
    const secret = `VAULT-UNAUTH-${crypto.randomBytes(6).toString('hex')}`;
    await acs.enqueueTask(
      strayId,
      {
        kind: 'set_parameter_values',
        ops: [
          {
            path: 'InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password',
            valueType: 'xsd:string',
            secretRef: encrypt(secret),
          },
        ],
      },
      { changeJobId: job },
    );

    const forged = await rawRequest(
      {
        method: 'POST',
        path: `/${SLUG}`,
        headers: { 'Content-Type': 'text/xml', Cookie: `ACSsession=${cookie}` },
      },
      forgedGpvResponse('InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID', 'FORGED-BY-ATTACKER'),
    );
    ok(
      'a forged RPC response on an unauthenticated session is refused',
      forged.status === 204,
      `status ${forged.status}`,
    );
    ok('…and receives no RPC of ours', !forged.body.toString().includes('SetParameterValues'));
    ok('…and no vault value', !forged.body.toString().includes(secret));

    const injected = (await db('cwmp_parameters')
      .where({ device_id: strayId, path: 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID' })
      .first('value')) as { value: string | null } | undefined;
    ok(
      '…and nothing was injected into cwmp_parameters',
      injected === undefined || injected.value !== 'FORGED-BY-ATTACKER',
      JSON.stringify(injected ?? null),
    );

    // The empty-POST branch, which DID have the guard, still has it.
    const empty = await rawRequest(
      { method: 'POST', path: `/${SLUG}`, headers: { 'Content-Length': '0', Cookie: `ACSsession=${cookie}` } },
      '',
    );
    eq('the empty-POST branch is still guarded too', empty.status, 204);

    await closeChangeJob(job);
    await acs.updateSettings(fx.tenantId, { allowAutoEnroll: false });
    acs.invalidateAcsSettings();
  }

  {
    // ── F3. X-Forwarded-For is not evidence of anything ───────────────────
    //
    // Was: honoured whenever the peer looked private — which, under the
    // shipped `docker-compose.yml`, it always is. One header bypassed
    // `trusted_cidrs` from anywhere on the internet.
    await acs.updateSettings(fx.tenantId, { trustedCidrs: ['203.0.113.0/24'] });
    acs.invalidateAcsSettings();

    const plain = await rawRequest(
      { method: 'POST', path: `/${SLUG}`, headers: { 'Content-Length': '0' } },
      '',
    );
    eq('the trusted-CIDR filter refuses an address outside the range', plain.status, 403);

    const spoofed = await rawRequest(
      {
        method: 'POST',
        path: `/${SLUG}`,
        headers: { 'Content-Length': '0', 'X-Forwarded-For': '203.0.113.9' },
      },
      '',
    );
    eq('…and X-Forwarded-For does not lift it', spoofed.status, 403);

    const chained = await rawRequest(
      {
        method: 'POST',
        path: `/${SLUG}`,
        headers: { 'Content-Length': '0', 'X-Forwarded-For': '203.0.113.9, 10.0.0.1' },
      },
      '',
    );
    eq('…not even a chain of them', chained.status, 403);

    await acs.updateSettings(fx.tenantId, { trustedCidrs: [] });
    acs.invalidateAcsSettings();
    const allowed = await rawRequest(
      { method: 'POST', path: `/${SLUG}`, headers: { 'Content-Length': '0' } },
      '',
    );
    eq('…and an empty CIDR list still means "no restriction"', allowed.status, 204);
  }

  {
    // ── F4. From enrolDevice() to an InformResponse, with NO SQL fixture ───
    //
    // Was: `enrolDevice` wrote `PENDING-<id>-<serial>` and nothing ever
    // replaced it, so a device an operator enrolled was challenged for ever.
    // The harness hid it by rewriting the column in SQL before every section;
    // this block is deliberately the one that does not.
    const serial = `VG-REAL-${crypto.randomBytes(3).toString('hex')}`;
    const deviceId = await mkFixtureDevice(fx, 'enrolled', 'draytek', 'draytek_vigor', 'Vigor2927', serial);
    const creds = await acs.enrolDevice(
      deviceId,
      fx.tenantId,
      'obliwan-acs',
      `http://${HOST}:${PORT}`,
      SLUG,
    );
    const before = await cwmpRowOf(deviceId);
    ok(
      'a freshly enrolled device carries a provisional cwmp_id',
      acs.isProvisionalCwmpId(String(before.cwmp_id)),
      String(before.cwmp_id),
    );

    // First, the serial alone must NOT be enough. It is printed on a sticker.
    const impostor = new FakeCpe({
      host: HOST,
      port: PORT,
      path: `/${SLUG}`,
      oui: '00507F',
      productClass: 'Vigor2927',
      serialNumber: serial,
      manufacturer: 'DrayTek',
      dataModel: 'tr098',
      username: creds.username,
      password: 'not-the-enrolment-password',
    });
    const refused = await impostor.session(['1 BOOT']);
    ok('the inventory serial alone does not claim the provisional row', refused.error !== undefined, refused.error ?? '');
    const stillPending = await cwmpRowOf(deviceId);
    ok(
      '…and the cwmp_id is untouched',
      acs.isProvisionalCwmpId(String(stillPending.cwmp_id)),
      String(stillPending.cwmp_id),
    );

    // Now the box itself, with the credential the operator typed into it.
    const real = new FakeCpe({
      host: HOST,
      port: PORT,
      path: `/${SLUG}`,
      oui: '00507F',
      productClass: 'Vigor2927',
      serialNumber: serial,
      manufacturer: 'DrayTek',
      dataModel: 'tr098',
      username: creds.username,
      password: creds.password,
    });
    const result = await real.session(['1 BOOT', '0 BOOTSTRAP']);
    ok('an enrolled device authenticates on its first Inform', result.error === undefined, result.error ?? '');
    ok(
      '…and gets an InformResponse without one SQL fixture',
      result.exchanges.some((e) => e.responseBody.includes('InformResponse')),
    );
    eq('…after exactly one challenge', result.authChallenges, 1);

    const after = await cwmpRowOf(deviceId);
    eq('…the provisional cwmp_id was replaced by the reported identity', String(after.cwmp_id), real.cwmpId);
    ok('…and the Inform was counted', Number(after.inform_count) >= 1, String(after.inform_count));
    ok('…and the box is online', after.reachability === 'online');

    // Second session: the binding is not a one-shot that leaves the box broken.
    const again = await real.session(['2 PERIODIC']);
    ok('…and it keeps working on the next session', again.error === undefined, again.error ?? '');
  }

  {
    // ── F5. A session cookie is scoped to the tenant of the URL ───────────
    //
    // Was: `findSession` resolved a cookie by token alone. Tenant A's CPE
    // posted its own legitimate cookie to /victim and the machine mixed A's
    // device id with B's tenant id — learn mode then wrote A's paths, A's model
    // and A's device id into B's `cwmp_param_map`.
    const victimSlug = `m10victim${crypto.randomBytes(3).toString('hex')}`;
    const [victim] = (await db('tenants')
      .insert({ name: `M10 victim ${victimSlug}`, slug: victimSlug })
      .returning('id')) as Array<{ id: number }>;
    await db('cwmp_acs_settings').insert({
      tenant_id: victim.id,
      tenant_slug: victimSlug,
      digest_realm: 'obliwan-acs',
      allow_auto_enroll: false,
      rpc_log_enabled: false,
      default_periodic_inform_interval: 300,
    });
    acs.invalidateAcsSettings();

    try {
      const before = await paramMapRows(victim.id);
      eq('the victim tenant starts with no parameter map of its own', before, 0);

      // The attacker's own CPE, mid-session, with a SUBTREE read outstanding —
      // which is what makes the answer feed learn mode, the thing that wrote
      // into the victim's map.
      await acs.enqueueTask(fx.vigorId, {
        kind: 'get_parameter_values',
        paths: ['InternetGatewayDevice.'],
      });
      const cpe = cpeFor(fx, 'vigor');
      const opened = await cpe.session(['2 PERIODIC'], 1);
      ok(
        'the attacker CPE holds a session with a subtree read outstanding',
        opened.rpcsReceived.includes('GetParameterValues'),
        opened.rpcsReceived.join(', '),
      );
      const cookie = cookieOf(opened);
      ok('…and a legitimate cookie of his OWN tenant', cookie !== null);

      const crossed = await rawRequest(
        {
          method: 'POST',
          path: `/${victimSlug}`,
          headers: { 'Content-Type': 'text/xml', Cookie: `ACSsession=${cookie}` },
        },
        forgedGpvResponse('InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID', 'Vigor2927-ATTACKER'),
      );
      eq("a tenant-A cookie spent on tenant B's slug resolves to nothing", crossed.status, 204);
      eq('…and wrote no row into the victim tenant parameter map', await paramMapRows(victim.id), 0);
      eq(
        '…and no parameter of the victim tenant either',
        Number(
          (
            (await db('cwmp_parameters as p')
              .join('devices as d', 'd.id', 'p.device_id')
              .where('d.tenant_id', victim.id)
              .count<{ count: string }[]>('* as count')) as Array<{ count: string }>
          )[0].count,
        ),
        0,
      );

      // …while the same envelope on the RIGHT slug is business as usual: the
      // fix is a tenant scope, not a refusal to work.
      const mineBefore = await paramMapRows(fx.tenantId);
      const home = await rawRequest(
        {
          method: 'POST',
          path: `/${SLUG}`,
          headers: { 'Content-Type': 'text/xml', Cookie: `ACSsession=${cookie}` },
        },
        forgedGpvResponse('InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID', 'Cabinet-Dupont'),
      );
      ok(
        '…and the same cookie still works on its own tenant',
        home.status === 200 || home.status === 204,
        `status ${home.status}`,
      );
      ok(
        '…where learn mode did run, on the tenant that owns the device',
        (await paramMapRows(fx.tenantId)) >= mineBefore,
      );
    } finally {
      await db('tenants').where({ id: victim.id }).del();
      acs.invalidateAcsSettings();
    }
  }

  {
    // ── F6. A FaultString is a place a vault plaintext comes back out ─────
    //
    // Was: `redactEnvelope` needed `<Name>`/`<Value>` adjacency, which a
    // SetParameterValuesFault does not have; `failTask` stored the fault
    // verbatim in `cwmp_tasks.fault`, a column with no retention that the API
    // serves; and the migration-015 CHECK covered `payload` only.
    await db('cwmp_devices').where({ device_id: fx.vigorId }).update({ rpc_log_enabled: true });
    await acs.updateSettings(fx.tenantId, { rpcLogEnabled: true });
    acs.invalidateRpcLogGate();
    acs.invalidateAcsSettings();

    const job = await openChangeJob(fx, fx.vigorId, 'reboot');
    const secret = `VAULT-ECHOED-${crypto.randomBytes(6).toString('hex')}`;
    const task = await acs.enqueueTask(
      fx.vigorId,
      {
        kind: 'set_parameter_values',
        ops: [
          {
            path: 'InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Password',
            valueType: 'xsd:string',
            secretRef: encrypt(secret),
          },
        ],
      },
      { changeJobId: job },
    );

    const cpe = cpeFor(fx, 'vigor', { echoRejectedValueInFault: true });
    const result = await cpe.session(['2 PERIODIC']);
    ok('the CPE received the write', result.rpcsReceived.includes('SetParameterValues'), result.rpcsReceived.join(', '));
    ok('…and answered a 9007 that repeats the value', result.faultsSent.includes('9007'), result.faultsSent.join(', '));

    const after = await acs.getTask(task.id);
    eq('the task failed, as a mutation must (never auto-retried)', after?.state, 'failed');
    ok(
      'the stored fault does NOT carry the vault plaintext',
      !JSON.stringify(after?.fault ?? {}).includes(secret),
      JSON.stringify(after?.fault ?? {}),
    );
    ok(
      '…and it still says something an operator can use',
      (after?.fault?.code ?? '') === '9003' || (after?.fault?.code ?? '').length > 0,
      after?.fault?.code ?? '',
    );

    // The blunt instrument again: every text-ish column of every CWMP table,
    // including the rpc-log partitions.
    const leaks: string[] = [];
    for (const table of ['cwmp_parameters', 'cwmp_devices', 'cwmp_tasks', 'cwmp_sessions', 'cwmp_rpc_log', 'cwmp_transfers']) {
      const hits = await scanTableForLiteral(table, secret);
      if (hits > 0) leaks.push(`${table} (${hits})`);
    }
    ok('the echoed vault value is in NO stored column', leaks.length === 0, leaks.join(', '));

    // The database refuses a credential-shaped key in `fault`, as it already
    // did for `payload` (migration 018).
    let dbRefused = false;
    try {
      await db('cwmp_tasks')
        .where({ id: task.id })
        .update({ fault: JSON.stringify({ faultCode: 'Client', code: '9007', password: 'oops' }) });
    } catch {
      dbRefused = true;
    }
    ok('the database refuses a credential-shaped key in cwmp_tasks.fault', dbRefused);

    // And the redactors, on the shapes themselves.
    const faultXml =
      '<SetParameterValuesFault><ParameterName>Device.PPP.Interface.1.Password</ParameterName>' +
      '<FaultCode>9007</FaultCode><FaultString>Invalid parameter value: Hunter2</FaultString>' +
      '</SetParameterValuesFault>';
    const redacted = redactEnvelope(faultXml);
    ok(
      'redactEnvelope now reaches inside a SetParameterValuesFault',
      !redacted.includes('Hunter2'),
      redacted,
    );

    const cleaned = acs.redactFault(
      { faultCode: 'Client', code: '9003', faultString: `9007 rejected value ${secret}` },
      after,
    );
    ok(
      'redactFault removes a plaintext the XML never labelled as one',
      !cleaned.faultString.includes(secret),
      cleaned.faultString,
    );

    await closeChangeJob(job);
  }
}

/** The DrayTek driver's own `getInventory`, with an otherwise empty context. */
async function draytekInventory(deviceId: number) {
  return getDriver('draytek_vigor').getInventory({
    deviceId,
    transports: [],
    timeoutMs: 5_000,
  } as never);
}

function isSorted(lines: readonly string[]): boolean {
  for (let i = 1; i < lines.length; i++) {
    if (lines[i - 1] > lines[i]) return false;
  }
  return true;
}

// ============================================================================
// Query helpers
// ============================================================================

/** The `cwmp_devices` row, untyped: these blocks read columns test-by-test. */
async function cwmpRowOf(deviceId: number): Promise<Record<string, unknown>> {
  return (await db('cwmp_devices').where({ device_id: deviceId }).first()) as Record<
    string,
    unknown
  >;
}

/** A device in the fixture tenant, created for one block. */
async function mkFixtureDevice(
  fx: Fixture,
  name: string,
  brand: string,
  family: string,
  model: string,
  serial: string,
): Promise<number> {
  const [row] = (await db('devices')
    .insert({
      tenant_id: fx.tenantId,
      name: `${name}-${serial}`,
      brand,
      family,
      model,
      serial,
      role: 'cpe',
      status: 'active',
    })
    .returning('id')) as Array<{ id: number }>;
  return row.id;
}

/** The `ACSsession` value the ACS handed out during a session, if any. */
function cookieOf(result: SessionResult): string | null {
  for (let i = result.exchanges.length - 1; i >= 0; i--) {
    const raw = result.exchanges[i].headers['set-cookie'];
    if (!raw) continue;
    const hit = (Array.isArray(raw) ? raw : [raw])
      .map((c) => c.split(';')[0])
      .find((c) => c.startsWith('ACSsession='));
    if (hit) return hit.slice('ACSsession='.length);
  }
  return null;
}

/**
 * A `GetParameterValuesResponse` built by hand, the way an attacker would.
 *
 * Twelve lines of XML, no credential, no Inform. The point of the finding it
 * reproduces is that this used to be enough to write into `cwmp_parameters` and
 * to collect the next queued RPC.
 */
function forgedGpvResponse(path: string, value: string): string {
  return (
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ' +
    'xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/" ' +
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema" ' +
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +
    'xmlns:cwmp="urn:dslforum-org:cwmp-1-0">' +
    '<soap:Header><cwmp:ID soap:mustUnderstand="1">forged-1</cwmp:ID></soap:Header>' +
    '<soap:Body><cwmp:GetParameterValuesResponse>' +
    '<ParameterList soap-enc:arrayType="cwmp:ParameterValueStruct[1]">' +
    `<ParameterValueStruct><Name>${path}</Name>` +
    `<Value xsi:type="xsd:string">${value}</Value>` +
    '</ParameterValueStruct></ParameterList>' +
    '</cwmp:GetParameterValuesResponse></soap:Body></soap:Envelope>'
  );
}

/** Rows a tenant owns in the canonical parameter map. */
async function paramMapRows(tenantId: number): Promise<number> {
  const rows = (await db('cwmp_param_map')
    .where({ tenant_id: tenantId })
    .count<{ count: string }[]>('* as count')) as Array<{ count: string }>;
  return Number(rows[0].count);
}


async function cpeRow(deviceId: number): Promise<Record<string, never> & {
  data_model: string;
  root_prefix: string;
  reachability: string;
  software_version: string | null;
  last_bootstrap_at: Date | null;
}> {
  return (await db('cwmp_devices').where({ device_id: deviceId }).first()) as never;
}

async function quirksOf(deviceId: number): Promise<Record<string, boolean>> {
  const row = (await db('cwmp_devices').where({ device_id: deviceId }).first('vendor_quirks')) as
    | { vendor_quirks: Record<string, boolean> }
    | undefined;
  return row?.vendor_quirks ?? {};
}

/**
 * A `change_jobs` row that exists only to be the D3 authorisation token.
 *
 * `change_jobs_one_in_flight_uq` (migration 009) allows exactly ONE live job
 * per device — which is the correct rule for the product and means these tests
 * have to close each one before opening the next. `guard_verdict = 'ACCEPT'`
 * satisfies `change_jobs_guard_required_chk`: the Management-Path Guard is
 * M6's gate and is not what M10 is proving here.
 */
async function openChangeJob(fx: Fixture, deviceId: number, kind: string): Promise<number> {
  const [row] = (await db('change_jobs')
    .insert({
      tenant_id: fx.tenantId,
      device_id: deviceId,
      kind,
      status: 'queued',
      base_state_hash: crypto.randomBytes(32).toString('hex'),
      safety_level: 'armed',
      guard_verdict: 'ACCEPT',
    })
    .returning('id')) as Array<{ id: number }>;
  return Number(row.id);
}

async function closeChangeJob(id: number): Promise<void> {
  await db('change_jobs').where({ id }).del();
}

async function openSessionsFor(deviceId: number): Promise<number> {
  const rows = await db('cwmp_sessions')
    .where({ device_id: deviceId, state: 'open' })
    .count<{ count: string }[]>('* as count');
  return Number(rows[0].count);
}

async function canonicalOf(
  fx: Fixture,
  deviceId: number,
  brand: string,
  dataModel: 'tr098' | 'tr181',
  model: string,
): Promise<Record<string, string | null>> {
  const paths = await acs.knownPaths(deviceId);
  const values = await acs.valuesFor(deviceId, paths);
  return (await acs.canonicalValues(
    { tenantId: fx.tenantId, dataModel, brand, model, firmware: null },
    paths,
    values,
  )) as Record<string, string | null>;
}

/**
 * Search every text-ish column of a table for a literal.
 *
 * Built from `information_schema` rather than from a hand-written column list,
 * deliberately: a hand-written list stops covering the column somebody adds
 * next year, which is exactly when this check stops being worth running.
 */
async function scanTableForLiteral(table: string, literal: string): Promise<number> {
  const cols = (await db('information_schema.columns')
    .where({ table_schema: 'public', table_name: table })
    .whereIn('data_type', ['text', 'character varying', 'jsonb', 'json'])
    .pluck('column_name')) as string[];
  if (cols.length === 0) return 0;

  const predicate = cols.map((c) => `coalesce(${quoteIdent(c)}::text, '') LIKE ?`).join(' OR ');
  const bindings = cols.map(() => `%${literal}%`);
  const result = (await db.raw(
    `SELECT count(*)::int AS n FROM ${quoteIdent(table)} WHERE ${predicate}`,
    bindings,
  )) as { rows: Array<{ n: number }> };
  return result.rows[0]?.n ?? 0;
}

function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

/** The Inform envelope alone, for the tests that need the raw 401. */
function informOnly(cpe: FakeCpe): string {
  // `session()` handles the challenge for us; this reaches into the private
  // builder through the only public thing that produces one — a transfer
  // complete carries the same DeviceId — so instead we build a minimal Inform
  // by hand. Kept tiny on purpose: it only has to be routed and challenged.
  return (
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ' +
    'xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/" ' +
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema" ' +
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' +
    'xmlns:cwmp="urn:dslforum-org:cwmp-1-0">' +
    '<soap:Header><cwmp:ID soap:mustUnderstand="1">bare-1</cwmp:ID></soap:Header>' +
    '<soap:Body><cwmp:Inform><DeviceId>' +
    `<Manufacturer>DrayTek</Manufacturer><OUI>${cpe.opts.oui}</OUI>` +
    `<ProductClass>${cpe.opts.productClass}</ProductClass>` +
    `<SerialNumber>${cpe.opts.serialNumber}</SerialNumber>` +
    '</DeviceId>' +
    '<Event soap-enc:arrayType="cwmp:EventStruct[1]">' +
    '<EventStruct><EventCode>2 PERIODIC</EventCode><CommandKey/></EventStruct></Event>' +
    '<MaxEnvelopes>1</MaxEnvelopes>' +
    `<CurrentTime>${new Date().toISOString()}</CurrentTime><RetryCount>0</RetryCount>` +
    '<ParameterList soap-enc:arrayType="cwmp:ParameterValueStruct[1]">' +
    '<ParameterValueStruct><Name>InternetGatewayDevice.DeviceInfo.SoftwareVersion</Name>' +
    '<Value xsi:type="xsd:string">4.4.5.1</Value></ParameterValueStruct></ParameterList>' +
    '</cwmp:Inform></soap:Body></soap:Envelope>'
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
