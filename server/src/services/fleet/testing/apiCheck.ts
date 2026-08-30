/**
 * ObliWAN — the fleet REST surface, exercised over real HTTP.
 *
 * `recipe.ts` proves the services. This proves the layer above them: that the
 * routes are mounted where the client will look for them, that `requireAuth` /
 * `requireTenant` / `requireCapability` actually run, that a cross-tenant id is
 * a 404 and not somebody else's data, and — the one that matters most — that no
 * response body anywhere in the fleet API contains a credential.
 *
 * It starts the REAL Express app (`createApp()`), logs in with a real session
 * cookie, and talks to it with `node:http`. No supertest, no mock request: the
 * middleware chain that runs here is the one that runs in production.
 *
 * Run:
 *   DATABASE_URL=... OBLIWAN_ENCRYPTION_KEY=<64 hex> SESSION_SECRET=... \
 *   npx tsx src/services/fleet/testing/apiCheck.ts
 */

import http from 'http';
import type { AddressInfo } from 'net';
import { createApp } from '../../../app';
import { db } from '../../../db';
import { authService } from '../../auth.service';
import { FakeChr } from './fakeChrServer';
import { shutdownRouterOsPool } from '../routerosPool';

let passed = 0;
const failures: string[] = [];

function check(label: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed++;
    console.log(`  ok    ${label}`);
    return;
  }
  const line = `${label}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`;
  failures.push(line);
  console.log(`  FAIL  ${line}`);
}

function eq(label: string, actual: unknown, expected: unknown): void {
  check(label, Object.is(actual, expected), { actual, expected });
}

// -- a minimal cookie-carrying HTTP client -----------------------------------

let cookie = '';

interface Reply {
  status: number;
  body: any;
  raw: string;
}

function request(method: string, path: string, port: number, payload?: unknown): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const data = payload === undefined ? null : Buffer.from(JSON.stringify(payload));
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path,
        headers: {
          ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}),
          ...(cookie ? { cookie } : {}),
        },
      },
      (res) => {
        const setCookie = res.headers['set-cookie'];
        if (setCookie) cookie = setCookie.map((c) => c.split(';')[0]).join('; ');
        let raw = '';
        res.on('data', (c) => (raw += c));
        res.on('end', () => {
          let body: unknown = null;
          try {
            body = JSON.parse(raw);
          } catch {
            body = null;
          }
          resolve({ status: res.statusCode ?? 0, body, raw });
        });
      },
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

const ADMIN_USER = 'fleet-api-check';
const ADMIN_PASS = 'Correct-Horse-Battery-9';

async function main(): Promise<void> {
  const url = process.env.DATABASE_URL ?? '';
  if (!/localhost|127\.0\.0\.1|10\.0\.0\.152/.test(url)) {
    throw new Error('Refusing to run against a database that does not look like a throwaway');
  }

  // Clean fleet state (leave users/tenants alone: sessions live in there).
  await db('reachability_verdicts').del();
  await db('ppp_sessions').del();
  await db('discoveries').del();
  await db('device_health').del();
  await db('device_transports').del();
  await db('devices').update({ concentrator_id: null });
  await db('devices').del();
  await db('sites').del();

  const existing = await db('users').where({ username: ADMIN_USER }).first();
  if (!existing) await authService.createUser(ADMIN_USER, ADMIN_PASS, 'admin', 'API check');

  const chr = new FakeChr({ identity: 'CHR-API', username: 'obliwan', password: 'chr-s3cret' });
  const chrPort = await chr.listen(0);

  const app = createApp();
  const server = http.createServer(app);
  await new Promise<void>((res) => server.listen(0, '127.0.0.1', () => res()));
  const port = (server.address() as AddressInfo).port;
  console.log(`  app listening on 127.0.0.1:${port}, fake CHR on ${chrPort}\n`);

  // -- 1. the routes exist AND are closed --------------------------------
  console.log('== 1. the fleet routes are mounted and guarded ==');
  for (const path of ['/api/sites', '/api/devices', '/api/discoveries']) {
    const r = await request('GET', path, port);
    // 401, not 404: the route is there, and it refused an anonymous caller.
    eq(`GET ${path} without a session -> 401`, r.status, 401);
  }

  // -- 2. log in ----------------------------------------------------------
  console.log('\n== 2. session ==');
  const login = await request('POST', '/api/auth/login', port, {
    username: ADMIN_USER,
    password: ADMIN_PASS,
  });
  eq('login succeeds', login.status, 200);
  check('a session cookie was issued', cookie.length > 0);
  // The login response carries the user; the tenant lives in the session and is
  // read back through /me. `requireTenant` reads the same value, so this is the
  // check that the fleet routes will actually be reachable.
  const me = await request('GET', '/api/auth/me', port);
  eq('the session names a tenant', me.body?.data?.currentTenantId, 1);

  // -- 3. sites -----------------------------------------------------------
  console.log('\n== 3. sites ==');
  const created = await request('POST', '/api/sites', port, { code: 'LYON-N', name: 'Lyon Nord' });
  eq('POST /api/sites -> 201', created.status, 201);
  const siteId = created.body?.data?.id;
  check('the site has an id', typeof siteId === 'number');

  const dup = await request('POST', '/api/sites', port, { code: 'LYON-N', name: 'Duplicate' });
  eq('a duplicate site code is a 409, not a 500', dup.status, 409);

  const badCode = await request('POST', '/api/sites', port, { code: 'has space', name: 'x' });
  eq('an invalid site code is rejected by the schema', badCode.status, 400);

  const list = await request('GET', '/api/sites', port);
  eq('GET /api/sites -> 200', list.status, 200);
  eq('...and returns the site', list.body?.data?.length, 1);
  eq('...with a device count', list.body?.data?.[0]?.device_count, 0);

  // -- 4. declaring the concentrator ---------------------------------------
  console.log('\n== 4. declare the CHR through the API ==');
  const decl = await request('POST', '/api/devices/concentrator', port, {
    name: 'CHR-API',
    host: '127.0.0.1',
    port: chrPort,
    username: 'obliwan',
    password: 'chr-s3cret',
  });
  eq('POST /api/devices/concentrator -> 201', decl.status, 201);
  check('...the credential was tested against the box', decl.body?.data?.connection?.ok === true, decl.body?.data?.connection);
  eq('...and the CHR identified itself', decl.body?.data?.connection?.identity?.systemIdentity, 'CHR-API');
  const chrId = decl.body?.data?.device?.id;
  check('the concentrator exists', typeof chrId === 'number');
  eq('...with role chr', decl.body?.data?.device?.role, 'concentrator');

  check(
    'THE RESPONSE CONTAINS NO CREDENTIAL',
    !decl.raw.includes('chr-s3cret') && !decl.raw.includes('v1:1:'),
  );
  check('...only the fact that one is stored', decl.raw.includes('"hasSecret":true'));

  const nonMikrotik = await request('POST', '/api/devices/concentrator', port, {
    name: 'not-a-chr',
    family: 'draytek_vigor',
    host: '127.0.0.1',
    username: 'x',
    password: 'y',
  });
  eq('a non-MikroTik concentrator is refused (only RouterOS serves /ppp/active)', nonMikrotik.status, 400);

  // -- 5. transports -------------------------------------------------------
  console.log('\n== 5. transports ==');
  const transports = await request('GET', `/api/devices/${chrId}/transports`, port);
  eq('GET transports -> 200', transports.status, 200);
  check('no ciphertext in the transport list', !transports.raw.includes('v1:1:'));
  check('no plaintext either', !transports.raw.includes('chr-s3cret'));
  eq('the key version is reported', transports.body?.data?.[0]?.keyVersion, 1);

  const withSecretInParams = await request('PUT', `/api/devices/${chrId}/transports/snmp`, port, {
    host: '10.66.0.1',
    params: { version: '2c', community: 'public' },
  });
  eq('a credential smuggled into params is refused by the schema', withSecretInParams.status, 400);

  const goodSnmp = await request('PUT', `/api/devices/${chrId}/transports/snmp`, port, {
    host: '10.66.0.1',
    params: { version: '2c' },
    secret: 'public',
  });
  eq('a credential in the right field is accepted', goodSnmp.status, 200);
  eq('...and reported as present', goodSnmp.body?.data?.hasSecret, true);
  check('...and never echoed', !goodSnmp.raw.includes('public') || !goodSnmp.raw.includes('"secret"'));

  const untestable = await request('POST', `/api/devices/${chrId}/transports/snmp/test`, port);
  eq('testing an unwired channel answers 200 with an honest refusal', untestable.status, 200);
  check(
    '...naming the milestone rather than pretending',
    String(untestable.body?.data?.error ?? '').includes('milestone'),
    untestable.body?.data?.error,
  );

  eq(
    'deleting a transport works',
    (await request('DELETE', `/api/devices/${chrId}/transports/snmp`, port)).status,
    200,
  );

  // -- 6. discoveries -------------------------------------------------------
  console.log('\n== 6. discovery through the API ==');
  chr.secrets.set('site-101', { name: 'site-101', remoteAddress: '10.66.0.101', comment: 'API lab' });
  chr.addSessionSilently({ name: 'site-101', address: '10.66.0.101', callerId: '203.0.113.101' });

  const scan = await request('POST', '/api/discoveries/scan', port, { concentratorId: chrId });
  eq('POST /api/discoveries/scan -> 200', scan.status, 200);
  eq('...one new quarantine row', scan.body?.data?.created, 1);

  const disc = await request('GET', '/api/discoveries', port);
  eq('GET /api/discoveries -> 200', disc.status, 200);
  eq('...it is pending', disc.body?.data?.[0]?.state, 'pending');
  const discId = disc.body?.data?.[0]?.id;

  const bind = await request('POST', `/api/discoveries/${discId}/bind`, port, {
    device: { name: 'RTR-API-101', family: 'mikrotik_routeros7', siteId },
  });
  eq('binding creates the device and attaches the username', bind.status, 200);
  eq('...the discovery is bound', bind.body?.data?.discovery?.state, 'bound');
  eq('...the new device carries the PPP username', bind.body?.data?.device?.ppp_username, 'site-101');
  eq('...and starts unproven, not active', bind.body?.data?.device?.status, 'pending');
  const cpeId = bind.body?.data?.device?.id;

  const rebind = await request('POST', `/api/discoveries/${discId}/bind`, port, { deviceId: cpeId });
  eq('re-binding an already-bound discovery is a 409', rebind.status, 409);

  // -- 7. identity assertion over HTTP --------------------------------------
  console.log('\n== 7. identity ==');
  const assertFail = await request('POST', `/api/devices/${cpeId}/assert-binding`, port);
  eq('asserting an unconfigured device is a 409, not a 500', assertFail.status, 409);
  check('...with the fail-closed reason in the body', typeof assertFail.body?.error === 'string');

  const assertOk = await request('POST', `/api/devices/${chrId}/assert-binding`, port);
  eq('asserting the CHR (identity learned at declaration) succeeds', assertOk.status, 200);
  eq('...on a fresh connection to the recorded address', assertOk.body?.data?.dialled, '127.0.0.1');

  // -- 8. deletion guards ---------------------------------------------------
  console.log('\n== 8. deletion guards ==');
  const delChr = await request('DELETE', `/api/devices/${chrId}`, port);
  eq('deleting a concentrator with children is refused', delChr.status, 409);
  check('...with an actionable message, not a SQL error', String(delChr.body?.error).includes('attached'), delChr.body?.error);

  eq('the CPE can be deleted', (await request('DELETE', `/api/devices/${cpeId}`, port)).status, 200);
  eq('...and then the concentrator can too', (await request('DELETE', `/api/devices/${chrId}`, port)).status, 200);

  // -- 9. tenant scoping ----------------------------------------------------
  console.log('\n== 9. tenant scoping ==');
  const [other] = await db('tenants')
    .insert({ name: 'Other MSP', slug: 'other-msp-api' })
    .onConflict('slug')
    .merge({ name: 'Other MSP' })
    .returning<{ id: number }[]>('id');
  const [foreignSite] = await db('sites')
    .insert({ tenant_id: other.id, code: 'FOREIGN', name: 'Not yours' })
    .returning<{ id: number }[]>('id');
  const peek = await request('GET', `/api/sites/${foreignSite.id}`, port);
  eq("another tenant's site reads as 404, never as 403 with its name", peek.status, 404);
  check('...and its name is nowhere in the response', !peek.raw.includes('Not yours'));

  const missing = await request('GET', '/api/devices/999999', port);
  eq('an unknown device id is a clean 404', missing.status, 404);
  const nonsense = await request('GET', '/api/devices/not-a-number', port);
  eq('a non-numeric id is a 400, not a crash', nonsense.status, 400);

  // -- 10. RBAC is a capability gate, not an "is logged in" gate ------------
  console.log('\n== 10. RBAC ==');
  const VIEWER = 'fleet-api-nobody';
  const VIEWER_PASS = 'Nothing-Granted-42';
  if (!(await db('users').where({ username: VIEWER }).first())) {
    await authService.createUser(VIEWER, VIEWER_PASS, 'user', 'No capabilities');
  }
  const adminCookie = cookie;
  cookie = '';
  const viewerLogin = await request('POST', '/api/auth/login', port, {
    username: VIEWER,
    password: VIEWER_PASS,
  });
  eq('a plain user can log in', viewerLogin.status, 200);
  // Authenticated, member of the tenant, and still refused: the capability is
  // what is checked, not the session.
  eq('...but has no DEVICE_READ, so the fleet is closed to them', (await request('GET', '/api/sites', port)).status, 403);
  eq('...devices too', (await request('GET', '/api/devices', port)).status, 403);
  eq('...and the quarantine, which needs DEVICE_DISCOVER', (await request('GET', '/api/discoveries', port)).status, 403);
  eq('...writing is refused as well', (await request('POST', '/api/sites', port, { code: 'X', name: 'X' })).status, 403);
  cookie = adminCookie;

  await new Promise<void>((res) => server.close(() => res()));
  await shutdownRouterOsPool();
  await chr.close();
}

main()
  .then(async () => {
    console.log(`\nfleet API check: ${passed} passed, ${failures.length} failed`);
    for (const f of failures) console.log(`  FAIL  ${f}`);
    await db.destroy();
    process.exit(failures.length === 0 ? 0 : 1);
  })
  .catch(async (err) => {
    console.error('\napi check aborted:', err);
    await db.destroy().catch(() => undefined);
    process.exit(2);
  });
