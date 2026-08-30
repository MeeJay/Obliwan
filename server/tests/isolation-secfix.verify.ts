/* Adversarial service-level verification of the remaining isolation defects.
   Run: DATABASE_URL=... npx tsx tests/isolation-secfix.verify.ts   (on a FRESH migrated DB)   */
import { db } from '../src/db';
import { notificationService } from '../src/services/notification.service';
import { smtpServerService } from '../src/services/smtpServer.service';
import { teamService } from '../src/services/team.service';
import { permissionService } from '../src/services/permission.service';
import { topoSort, findCycles, CycleError } from '../src/utils/topoSort';
import fs from 'fs';
import path from 'path';

let pass = 0, fail = 0;
const failures: string[] = [];
function ok(name: string, cond: boolean, detail = '') {
  if (cond) { pass++; console.log(`  PASS  ${name}${detail ? ' -- ' + detail : ''}`); }
  else { fail++; failures.push(name); console.log(`  FAIL  ${name}${detail ? ' -- ' + detail : ''}`); }
}
async function throws(fn: () => Promise<unknown>): Promise<Error | null> {
  try { await fn(); return null; } catch (e) { return e as Error; }
}
const SRC = path.resolve(__dirname, '../src');

async function main() {
  // -- fixtures ------------------------------------------------------------
  const t1 = (await db('tenants').where({ slug: 'default' }).first('id'))
    ?? (await db('tenants').insert({ name: 'Default', slug: 'default' }).returning('id'))[0];
  const [tA] = await db('tenants').insert({ name: 'Acme', slug: 'acme' }).returning('id');
  const [tB] = await db('tenants').insert({ name: 'Globex', slug: 'globex' }).returning('id');
  const ACME = tA.id as number, GLOBEX = tB.id as number;
  console.log(`tenants: default=${t1.id} acme=${ACME} globex=${GLOBEX}`);

  const mkUser = async (u: string, role: string) =>
    (await db('users').insert({ username: u, password_hash: 'x', role, display_name: u }).returning('id'))[0].id as number;
  const alice = await mkUser('alice', 'user');      // member of ACME
  const bob = await mkUser('bob', 'user');          // member of GLOBEX
  const carol = await mkUser('carol', 'user');      // member of BOTH
  const mallory = await mkUser('mallory', 'user');  // member of NOTHING
  const padmin = await mkUser('padmin', 'admin');   // platform admin, no membership

  await db('user_tenants').insert([
    { user_id: alice, tenant_id: ACME, role: 'admin' },
    { user_id: bob, tenant_id: GLOBEX, role: 'admin' },
    { user_id: carol, tenant_id: ACME, role: 'member' },
    { user_id: carol, tenant_id: GLOBEX, role: 'member' },
  ]);

  const mkGroup = async (name: string, tenant: number) =>
    (await db('device_groups').insert({ name, slug: name.toLowerCase(), tenant_id: tenant }).returning('id'))[0].id as number;
  const gAcme = await mkGroup('AcmeRoot', ACME);
  const gGlobex = await mkGroup('GlobexRoot', GLOBEX);
  await db('group_closure').insert([
    { ancestor_id: gAcme, descendant_id: gAcme, depth: 0 },
    { ancestor_id: gGlobex, descendant_id: gGlobex, depth: 0 },
  ]);

  const mkDevice = async (name: string, tenant: number) =>
    (await db('devices').insert({ name, tenant_id: tenant, brand: 'mikrotik', family: 'mikrotik_routeros7' }).returning('id'))[0].id as number;
  const dAcme = await mkDevice('acme-cpe-1', ACME);
  const dGlobex = await mkDevice('globex-cpe-1', GLOBEX);

  const mkTeam = async (name: string, tenant: number) =>
    (await db('user_teams').insert({ name, tenant_id: tenant, can_create: true }).returning('id'))[0].id as number;
  const teamAcme = await mkTeam('NOC-Acme', ACME);
  const teamGlobex = await mkTeam('NOC-Globex', GLOBEX);
  await db('team_memberships').insert([
    { team_id: teamAcme, user_id: carol },
    { team_id: teamGlobex, user_id: carol },
  ]);
  await db('team_permissions').insert([
    { team_id: teamAcme, scope: 'group', scope_id: gAcme, level: 'rw' },
    { team_id: teamGlobex, scope: 'group', scope_id: gGlobex, level: 'rw' },
  ]);

  // == 1. R2 -- updateChannel / deleteChannel / channel-tenants scoping =====
  console.log('\n[1] R2 -- notification channel writes are tenant-scoped');
  const chGlobex = await notificationService.createChannel(
    { name: 'Globex Discord', type: 'discord',
      config: { webhookUrl: 'https://discord.com/api/webhooks/AAA/GLOBEX-SECRET' } }, GLOBEX);

  ok('GET channel of Globex from Acme -> null',
    (await notificationService.getChannelById(chGlobex.id, ACME)) === null);

  const hijack = await notificationService.updateChannel(chGlobex.id, { name: 'HIJACKED' }, ACME);
  ok('PUT channel of Globex from Acme -> null (no config returned)', hijack === null,
    hijack ? `LEAKED ${JSON.stringify((hijack as { config: unknown }).config)}` : 'no row, no secret');

  const stillThere = await db('notification_channels').where({ id: chGlobex.id }).first('name');
  ok('  ...and the row was NOT renamed', stillThere.name === 'Globex Discord', `name=${stillThere.name}`);

  ok('DELETE channel of Globex from Acme -> false',
    (await notificationService.deleteChannel(chGlobex.id, ACME)) === false);
  ok('  ...and the row still exists',
    (await db('notification_channels').where({ id: chGlobex.id }).first('id')) !== undefined);

  ok('getChannelTenants of Globex channel from Acme -> null',
    (await notificationService.getChannelTenants(chGlobex.id, ACME)) === null);
  ok('setChannelTenants of Globex channel from Acme -> false',
    (await notificationService.setChannelTenants(chGlobex.id, [ACME], ACME)) === false);
  ok('  ...no sharing row was written',
    (await db('notification_channel_tenants').where({ channel_id: chGlobex.id }).first()) === undefined);

  ok('owner CAN update its own channel',
    (await notificationService.updateChannel(chGlobex.id, { name: 'Globex Discord v2' }, GLOBEX))?.name === 'Globex Discord v2');
  ok('owner CAN read its sharing list',
    Array.isArray(await notificationService.getChannelTenants(chGlobex.id, GLOBEX)));

  await notificationService.setChannelTenants(chGlobex.id, [ACME], GLOBEX);
  ok('shared channel IS readable from Acme',
    (await notificationService.getChannelById(chGlobex.id, ACME))?.id === chGlobex.id);
  ok('shared channel is still NOT writable from Acme (share = use, not control)',
    (await notificationService.updateChannel(chGlobex.id, { name: 'X' }, ACME)) === null);
  ok('shared channel is still NOT deletable from Acme',
    (await notificationService.deleteChannel(chGlobex.id, ACME)) === false);
  await notificationService.setChannelTenants(chGlobex.id, [], GLOBEX);

  // == 2. R3 -- getUserPermissions without a tenant =========================
  console.log('\n[2] R3 -- getUserPermissions with no current tenant');
  const noTenant = await permissionService.getUserPermissions(carol, false, undefined);
  ok('teams == []', noTenant.teams.length === 0, JSON.stringify(noTenant.teams));
  ok('permissions == {}', Object.keys(noTenant.permissions).length === 0, JSON.stringify(noTenant.permissions));
  ok('capabilities == []', noTenant.capabilities.length === 0);
  ok('canCreate == false', noTenant.canCreate === false);

  const onAcme = await permissionService.getUserPermissions(carol, false, ACME);
  ok('on Acme: only the Acme team', onAcme.teams.length === 1 && onAcme.teams[0] === teamAcme,
    JSON.stringify(onAcme.teams));
  ok('on Acme: only the Acme group grant',
    Object.keys(onAcme.permissions).length === 1 && onAcme.permissions[`group:${gAcme}`] === 'rw',
    JSON.stringify(onAcme.permissions));
  ok('on Acme: Globex grant absent', onAcme.permissions[`group:${gGlobex}`] === undefined);
  const onGlobex = await permissionService.getUserPermissions(carol, false, GLOBEX);
  ok('on Globex: only the Globex grant (no over-blocking)',
    onGlobex.permissions[`group:${gGlobex}`] === 'rw' && onGlobex.permissions[`group:${gAcme}`] === undefined);
  ok('getUserTeamIds(carol, undefined) still crosses tenants (raw helper)',
    (await permissionService.getUserTeamIds(carol, undefined)).length === 2,
    'so the guard in getUserPermissions is what closes it');

  // == 3. R5 -- assertScopeInTenant covers scope=device =====================
  console.log('\n[3] R5 -- settings scope=device is checked against the tenant');
  const { settingsController } = await import('../src/controllers/settings.controller');
  const setS = (tenantId: number, scope: string, scopeId: string, body: unknown) =>
    new Promise<{ status: number; msg: string }>((resolve) => {
      const req = { params: { scope, scopeId }, body, tenantId, app: { get: () => null }, session: {} };
      const res = { json: () => resolve({ status: 200, msg: 'ok' }) };
      settingsController.set(req as never, res as never, ((e: unknown) => resolve({
        status: (e as { statusCode?: number })?.statusCode ?? 500,
        msg: (e as Error)?.message ?? String(e),
      })) as never);
    });

  const r1 = await setS(GLOBEX, 'device', '4242', { key: 'snmp_timeout', value: 4000 });
  ok('PUT settings/device/4242 (nonexistent) -> 404', r1.status === 404, `${r1.status} ${r1.msg}`);
  const r2 = await setS(GLOBEX, 'device', String(dAcme), { key: 'snmp_timeout', value: 4000 });
  ok(`PUT settings/device/${dAcme} (Acme device) from Globex -> 404`, r2.status === 404, `${r2.status} ${r2.msg}`);
  ok('  ...same wording for both (no existence oracle)', r1.msg === r2.msg, r2.msg);
  ok('  ...no orphan settings row was written',
    String((await db('settings').where({ scope: 'device' }).count('* as c'))[0].c) === '0');
  const r3 = await setS(GLOBEX, 'device', String(dGlobex), { key: 'snmp_timeout', value: 4000 });
  ok('PUT settings/device/<own device> -> 200 (no over-blocking)', r3.status === 200, `${r3.status} ${r3.msg}`);
  const r4 = await setS(GLOBEX, 'group', String(gAcme), { key: 'snmp_timeout', value: 4000 });
  ok('PUT settings/group/<Acme group> from Globex -> 404', r4.status === 404, `${r4.status} ${r4.msg}`);
  const r5 = await setS(GLOBEX, 'global', 'null', { key: 'snmp_timeout', value: 4000 });
  ok('PUT settings/global -> 200 (no over-blocking)', r5.status === 200, `${r5.status} ${r5.msg}`);

  // == 4. Socket.io rooms -- static assertion on the emitters ===============
  console.log('\n[4] Socket.io: no emitter targets the global role:admin room');
  for (const rel of ['controllers/groups.controller.ts', 'controllers/settings.controller.ts']) {
    const s = fs.readFileSync(path.join(SRC, rel), 'utf8');
    const emits = [...s.matchAll(/io\.to\((.+?)\)\.emit\(\s*'([^']+)'/g)];
    ok(`${rel}: every emit targets tenant:{id}:admin`,
      emits.length > 0 && emits.every((m) => m[1].trim() === 'adminRoom(req)'),
      `${emits.length} emits: ${emits.map((m) => m[2]).join(', ')}`);
    ok(`${rel}: no io.to('role:admin')`, !/io\.to\(\s*['"]role:admin/.test(s));
    ok(`${rel}: adminRoom() builds tenant:$\{req.tenantId}:admin`,
      /return\s+`tenant:\$\{req\.tenantId\}:admin`/.test(s));
    ok(`${rel}: every payload carries tenantId`,
      [...s.matchAll(/\.emit\('[^']+',\s*\{([^}]*)\}/g)].every((m) => m[1].includes('tenantId: req.tenantId')));
  }

  // == 5. SMTP relay: platform vs tenant ====================================
  console.log('\n[5] SMTP relay -- platform relay creation + instance-wide scope');
  const relayAcme = await smtpServerService.create({
    name: 'Acme private relay', host: 'smtp.acme.local', port: 587, secure: false,
    username: 'svc-acme', password: 'p', fromAddress: 'noc@acme.local', tenantId: ACME,
  });
  const relayPlat = await smtpServerService.create({
    name: 'Platform relay', host: 'smtp.obliwan.local', port: 587, secure: false,
    username: 'svc-plat', password: 'p', fromAddress: 'no-reply@obliwan.local',
    tenantId: ACME, isPlatform: true,
  });
  const rowPlat = await db('smtp_servers').where({ id: relayPlat.id }).first('tenant_id');
  ok('isPlatform:true writes tenant_id NULL even with tenantId set', rowPlat.tenant_id === null,
    `tenant_id=${rowPlat.tenant_id}`);
  const rowAcme = await db('smtp_servers').where({ id: relayAcme.id }).first('tenant_id');
  ok('without isPlatform the relay belongs to the tenant', rowAcme.tenant_id === ACME);

  ok('instance scope refuses a TENANT relay (this is the OTP path)',
    (await smtpServerService.getById(relayAcme.id)) === null);
  ok('instance scope accepts the PLATFORM relay',
    (await smtpServerService.getById(relayPlat.id))?.id === relayPlat.id);
  ok('getTransportConfig(acmeRelay) with no tenant -> null (OTP refuses to send)',
    (await smtpServerService.getTransportConfig(relayAcme.id)) === null);
  ok('getTransportConfig(platformRelay) with no tenant -> usable',
    (await smtpServerService.getTransportConfig(relayPlat.id))?.host === 'smtp.obliwan.local');
  ok('isPlatformRelay(acmeRelay) == false', (await smtpServerService.isPlatformRelay(relayAcme.id)) === false);
  ok('isPlatformRelay(platformRelay) == true', (await smtpServerService.isPlatformRelay(relayPlat.id)) === true);
  ok('Globex may NOT use Acme relay', (await smtpServerService.isUsableBy(relayAcme.id, GLOBEX)) === false);
  ok('Acme may use its own relay', (await smtpServerService.isUsableBy(relayAcme.id, ACME)) === true);
  ok('Globex may use the platform relay', (await smtpServerService.isUsableBy(relayPlat.id, GLOBEX)) === true);
  ok('list(GLOBEX) = own + platform only',
    (await smtpServerService.list(GLOBEX)).map((s) => s.id).join(',') === String(relayPlat.id));
  ok('list() with no tenant = platform relays only',
    (await smtpServerService.list()).map((s) => s.id).join(',') === String(relayPlat.id));

  // == 6. resolveChannelConfig / smtpServerId ownership =====================
  console.log('\n[6] #6 -- smtpServerId in a channel config is checked against the tenant');
  const e1 = await throws(() => notificationService.createChannel(
    { name: 'Globex mail via Acme relay', type: 'smtp',
      config: { smtpServerId: relayAcme.id, to: 'noc@globex' } }, GLOBEX));
  ok('createChannel(Globex) naming Acme relay -> refused', e1 !== null, e1?.message);
  ok('  ...and no channel row was written',
    (await db('notification_channels').where({ tenant_id: GLOBEX, type: 'smtp' }).first()) === undefined);

  const chOk = await notificationService.createChannel(
    { name: 'Acme mail', type: 'smtp', config: { smtpServerId: relayAcme.id, to: 'noc@acme' } }, ACME);
  ok('createChannel(Acme) naming its own relay -> accepted', chOk.id > 0);
  const chPlat = await notificationService.createChannel(
    { name: 'Globex mail via platform relay', type: 'smtp',
      config: { smtpServerId: relayPlat.id, to: 'noc@globex' } }, GLOBEX);
  ok('createChannel(Globex) naming the PLATFORM relay -> accepted', chPlat.id > 0);

  const e2 = await throws(() => notificationService.updateChannel(
    chPlat.id, { config: { smtpServerId: relayAcme.id, to: 'noc@globex' } }, GLOBEX));
  ok('updateChannel swapping in Acme relay -> refused', e2 !== null, e2?.message);
  const cfgAfter = await db('notification_channels').where({ id: chPlat.id }).first('config');
  const parsed = typeof cfgAfter.config === 'string' ? JSON.parse(cfgAfter.config) : cfgAfter.config;
  ok('  ...stored config unchanged', Number(parsed.smtpServerId) === relayPlat.id);

  // a blob written before the guard existed must still not fire
  await db('notification_channels').where({ id: chPlat.id })
    .update({ config: JSON.stringify({ smtpServerId: relayAcme.id, to: 'noc@globex' }) });
  const legacy = await notificationService.getChannelById(chPlat.id, GLOBEX);
  const e3 = await throws(() => notificationService.resolveChannelConfig(legacy!, GLOBEX));
  ok('resolveChannelConfig on a pre-existing bad blob -> refused (no credential handed over)',
    e3 !== null, e3?.message);
  ok('  ...the refusal leaked no host/username',
    !!e3 && !e3.message.includes('smtp.acme.local') && !e3.message.includes('svc-acme'), e3?.message);
  const good = await notificationService.getChannelById(chOk.id, ACME);
  const resolved = await notificationService.resolveChannelConfig(good!, ACME);
  ok('resolveChannelConfig on a legitimate channel still works',
    (resolved as { host: string }).host === 'smtp.acme.local');

  // == 7. team.setMembers + user listing ====================================
  console.log('\n[7] #9 -- setMembers requires tenant membership; /api/users is scoped');
  const e4 = await throws(() => teamService.setMembers(teamAcme, [carol, bob], ACME));
  ok('setMembers(Acme team, [carol, bob]) -> refused (bob is Globex-only)', e4 !== null, e4?.message);
  ok('  ...names the rejected id', !!e4 && e4.message.includes(String(bob)), e4?.message);
  ok('  ...previous membership list intact',
    (await db('team_memberships').where({ team_id: teamAcme }).pluck('user_id')).join(',') === String(carol));
  const e5 = await throws(() => teamService.setMembers(teamAcme, [carol], GLOBEX));
  ok('setMembers on ANOTHER tenant team -> 404', (e5 as { statusCode?: number })?.statusCode === 404, e5?.message);
  const e6 = await throws(() => teamService.setMembers(teamAcme, [mallory], ACME));
  ok('setMembers with a user of NO tenant -> refused', e6 !== null, e6?.message);
  await teamService.setMembers(teamAcme, [carol, alice], ACME);
  ok('setMembers with legitimate members -> accepted',
    (await db('team_memberships').where({ team_id: teamAcme }).pluck('user_id')).sort().join(',')
    === [carol, alice].sort().join(','));
  await teamService.setMembers(teamAcme, [carol, carol, alice], ACME);
  ok('duplicate ids collapse instead of a 500 on the unique key',
    String((await db('team_memberships').where({ team_id: teamAcme }).count('* as c'))[0].c) === '2');
  ok('teamGlobex untouched throughout',
    (await db('team_memberships').where({ team_id: teamGlobex }).pluck('user_id')).join(',') === String(carol));

  const { usersController } = await import('../src/controllers/users.controller');
  const listUsers = (tenantId: number, role: string, scope?: string) =>
    new Promise<number[]>((resolve, reject) => {
      usersController.list(
        { tenantId, session: { role }, query: scope ? { scope } : {} } as never,
        { json: (b: { data: { id: number }[] }) => resolve(b.data.map((u) => u.id)) } as never,
        reject as never);
    });
  const acmeList = await listUsers(ACME, 'user');
  ok('GET /api/users on Acme excludes bob (Globex)', !acmeList.includes(bob), `ids=${acmeList}`);
  ok('  ...excludes mallory (no tenant)', !acmeList.includes(mallory));
  ok('  ...includes alice and carol', acmeList.includes(alice) && acmeList.includes(carol));
  const globexList = await listUsers(GLOBEX, 'user');
  ok('GET /api/users on Globex excludes alice', !globexList.includes(alice), `ids=${globexList}`);
  const allList = await listUsers(ACME, 'admin', 'all');
  ok('?scope=all as platform admin still returns everybody',
    allList.includes(bob) && allList.includes(mallory) && allList.includes(padmin));
  const spoof = await listUsers(ACME, 'user', 'all');
  ok('?scope=all as a NON platform admin is ignored', !spoof.includes(bob), `ids=${spoof}`);

  // == 8. topoSort cycle detection ==========================================
  console.log('\n[8] #8 -- topoSort detects cycles instead of ordering them');
  const acyclic = [
    { uuid: 'c', parentUuid: 'b', name: 'C' },
    { uuid: 'b', parentUuid: 'a', name: 'B' },
    { uuid: 'a', parentUuid: null, name: 'A' },
  ];
  ok('acyclic input: parents precede children',
    topoSort(acyclic, 'uuid', 'parentUuid').map((x) => x.uuid).join(',') === 'a,b,c');
  ok('parent absent from the bundle (anchor in DB) is a root',
    topoSort([{ uuid: 'x', parentUuid: 'not-in-bundle' }], 'uuid', 'parentUuid').length === 1);
  ok('items without a uuid are emitted once, in order',
    topoSort([{ uuid: null, name: 'n1' }, { uuid: 'a', parentUuid: null }], 'uuid', 'parentUuid').length === 2);

  const c1 = await throws(async () => topoSort([{ uuid: 'a', parentUuid: 'a', name: 'A' }], 'uuid', 'parentUuid'));
  ok('self-reference -> CycleError', c1 instanceof CycleError, c1?.message);
  const two = [{ uuid: 'a', parentUuid: 'b', name: 'A' }, { uuid: 'b', parentUuid: 'a', name: 'B' }];
  const c2 = await throws(async () => topoSort(two, 'uuid', 'parentUuid'));
  ok('two-node loop -> CycleError', c2 instanceof CycleError, c2?.message);
  ok('  ...names both members', (c2 as CycleError).allCyclicKeys.slice().sort().join(',') === 'a,b');
  const three = [{ uuid: 'a', parentUuid: 'c' }, { uuid: 'b', parentUuid: 'a' }, { uuid: 'c', parentUuid: 'b' }];
  ok('three-node loop -> CycleError',
    (await throws(async () => topoSort(three, 'uuid', 'parentUuid'))) instanceof CycleError);
  const mixed = [{ uuid: 'r', parentUuid: null }, { uuid: 'a', parentUuid: 'b' }, { uuid: 'b', parentUuid: 'a' }];
  ok('a loop is caught even when a clean root sorts first',
    (await throws(async () => topoSort(mixed, 'uuid', 'parentUuid'))) instanceof CycleError);
  const disjoint = [
    { uuid: 'a', parentUuid: 'b' }, { uuid: 'b', parentUuid: 'a' },
    { uuid: 'x', parentUuid: 'y' }, { uuid: 'y', parentUuid: 'z' }, { uuid: 'z', parentUuid: 'x' },
    { uuid: 'r', parentUuid: null }, { uuid: 'leaf', parentUuid: 'a' },
  ];
  const dc = findCycles(disjoint, 'uuid', 'parentUuid').slice().sort().join(',');
  ok('findCycles reports every DISJOINT cycle in one pass', dc === 'a,b,x,y,z', dc);
  ok('  ...and does not accuse a node that merely POINTS INTO a cycle', !dc.split(',').includes('leaf'));
  ok('findCycles on clean input -> []', findCycles(acyclic, 'uuid', 'parentUuid').length === 0);
  const deep = Array.from({ length: 20000 }, (_, i) => ({ uuid: `n${i}`, parentUuid: i === 0 ? null : `n${i - 1}` }));
  ok('20000-deep chain sorts without a stack overflow',
    topoSort(deep.slice().reverse(), 'uuid', 'parentUuid').length === 20000);

  // == 9. the import controller turns the cycle into a 400 ==================
  console.log('\n[9] #8 -- importExport turns the cycle into an actionable 400');
  const { importExportController } = await import('../src/controllers/importExport.controller');
  // The exact reported scenario: BOTH groups already exist in the target
  // tenant, so conflictStrategy 'update' reaches `reparentGroupClosure` — the
  // path that used to raise 23505 on group_closure_pkey and answer a bare 500.
  const uNord = '11111111-1111-1111-1111-111111111111';
  const uSud = '22222222-2222-2222-2222-222222222222';
  const gNord = (await db('device_groups')
    .insert({ name: 'Nord', slug: 'nord', tenant_id: ACME, uuid: uNord }).returning('id'))[0].id as number;
  const gSud = (await db('device_groups')
    .insert({ name: 'Sud', slug: 'sud', tenant_id: ACME, uuid: uSud, parent_id: gNord }).returning('id'))[0].id as number;
  await db('group_closure').insert([
    { ancestor_id: gNord, descendant_id: gNord, depth: 0 },
    { ancestor_id: gSud, descendant_id: gSud, depth: 0 },
    { ancestor_id: gNord, descendant_id: gSud, depth: 1 },
  ]);
  const data = {
    formatVersion: 1, exportedAt: new Date().toISOString(), tenantSlug: 'acme',
    // parentUuid crossed between a parent and its child — the operator's
    // copy/paste slip described in the report.
    deviceGroups: [
      { uuid: uNord, parentUuid: uSud, name: 'Nord' },
      { uuid: uSud, parentUuid: uNord, name: 'Sud' },
    ],
    settings: [{ scope: 'global', key: 'snmp_timeout', value: 5000 }],
  };
  const groupsBefore = Number((await db('device_groups').where({ tenant_id: ACME }).count('* as c'))[0].c);
  const closureBefore = Number((await db('group_closure').count('* as c'))[0].c);
  const impErr = await new Promise<{ status: number; msg: string }>((resolve) => {
    importExportController.importData(
      { tenantId: ACME, session: { userId: alice, role: 'admin' },
        body: { data, sections: ['deviceGroups', 'settings'], conflictStrategy: 'update' } } as never,
      { json: (b: unknown) => resolve({ status: 200, msg: JSON.stringify(b) }) } as never,
      ((e: unknown) => resolve({
        status: (e as { statusCode?: number })?.statusCode ?? 500,
        msg: (e as Error)?.message ?? String(e),
      })) as never);
  });
  ok('import of a cyclic bundle -> 400, not 500', impErr.status === 400, `${impErr.status} ${impErr.msg.slice(0, 220)}`);
  ok('  ...names both offending groups by name AND uuid',
    impErr.msg.includes('"Nord"') && impErr.msg.includes('"Sud"')
    && impErr.msg.includes('11111111-1111-1111-1111-111111111111'), impErr.msg.slice(0, 300));
  ok('  ...tells the operator what to do', /Set parentUuid to null/.test(impErr.msg));
  ok('  ...nothing was written (transaction rolled back / never opened)',
    Number((await db('device_groups').where({ tenant_id: ACME }).count('* as c'))[0].c) === groupsBefore);
  ok('  ...group_closure is untouched (no 23505 half-write)',
    Number((await db('group_closure').count('* as c'))[0].c) === closureBefore);
  ok('  ...the settings section of the same bundle was not applied either (all-or-nothing)',
    (await db('settings').where({ tenant_id: ACME, scope: 'global', key: 'snmp_timeout' }).first()) === undefined);

  // Non-regression: the same bundle with the loop broken imports cleanly.
  const good2 = JSON.parse(JSON.stringify(data));
  good2.deviceGroups[0].parentUuid = null;
  const impOk = await new Promise<{ status: number; msg: string }>((resolve) => {
    importExportController.importData(
      { tenantId: ACME, session: { userId: alice, role: 'admin' },
        body: { data: good2, sections: ['deviceGroups', 'settings'], conflictStrategy: 'update' } } as never,
      { json: (b: unknown) => resolve({ status: 200, msg: JSON.stringify(b) }) } as never,
      ((e: unknown) => resolve({
        status: (e as { statusCode?: number })?.statusCode ?? 500,
        msg: (e as Error)?.message ?? String(e),
      })) as never);
  });
  ok('the same bundle with the loop broken imports cleanly (no over-blocking)',
    impOk.status === 200, `${impOk.status} ${impOk.msg.slice(0, 200)}`);

  // == 10. import may not smuggle another tenant's SMTP relay into a channel =
  console.log('\n[10] #6 (import side) -- a bundle cannot name another tenant relay');
  const runImport = (tenantId: number, data: unknown, sections: string[]) =>
    new Promise<{ status: number; body: unknown; msg: string }>((resolve) => {
      importExportController.importData(
        { tenantId, session: { userId: alice, role: 'admin' }, body: { data, sections, conflictStrategy: 'update' } } as never,
        { json: (b: unknown) => resolve({ status: 200, body: b, msg: '' }) } as never,
        ((e: unknown) => resolve({
          status: (e as { statusCode?: number })?.statusCode ?? 500, body: null,
          msg: (e as Error)?.message ?? String(e),
        })) as never);
    });

  const smuggle = {
    formatVersion: 1, exportedAt: new Date().toISOString(), tenantSlug: 'globex',
    notificationChannels: [{
      uuid: '33333333-3333-3333-3333-333333333333', name: 'Smuggled mail', type: 'smtp',
      config: { smtpServerId: relayAcme.id, to: 'noc@globex' }, configRedacted: false,
      isEnabled: true, bindings: [],
    }],
  };
  const impSm = await runImport(GLOBEX, smuggle, ['notificationChannels']);
  ok('import into Globex naming Acme relay -> 200 with a warning',
    impSm.status === 200
    && Array.isArray((impSm.body as { data: { notificationChannels: { warnings?: string[] } } })
      .data.notificationChannels.warnings),
    JSON.stringify(impSm.body ?? impSm.msg).slice(0, 240));
  const smRow = await db('notification_channels')
    .where({ uuid: '33333333-3333-3333-3333-333333333333' }).first('config', 'is_enabled', 'tenant_id');
  const smCfg = typeof smRow.config === 'string' ? JSON.parse(smRow.config) : smRow.config;
  ok('  ...the foreign smtpServerId is NOT in the stored config', smCfg.smtpServerId === undefined,
    JSON.stringify(smCfg));
  ok('  ...the channel was imported DISABLED', smRow.is_enabled === false);
  ok('  ...and belongs to Globex', smRow.tenant_id === GLOBEX);
  ok('  ...the rest of the config survived', smCfg.to === 'noc@globex');

  const legit = JSON.parse(JSON.stringify(smuggle));
  legit.notificationChannels[0].uuid = '44444444-4444-4444-4444-444444444444';
  legit.notificationChannels[0].config.smtpServerId = relayPlat.id;
  const impLg = await runImport(GLOBEX, legit, ['notificationChannels']);
  ok('import naming the PLATFORM relay is untouched (no over-blocking)',
    impLg.status === 200
    && (impLg.body as { data: { notificationChannels: { warnings?: string[] } } })
      .data.notificationChannels.warnings === undefined,
    JSON.stringify(impLg.body ?? impLg.msg).slice(0, 200));
  const lgRow = await db('notification_channels')
    .where({ uuid: '44444444-4444-4444-4444-444444444444' }).first('config', 'is_enabled');
  const lgCfg = typeof lgRow.config === 'string' ? JSON.parse(lgRow.config) : lgRow.config;
  ok('  ...kept its smtpServerId and stayed enabled',
    Number(lgCfg.smtpServerId) === relayPlat.id && lgRow.is_enabled === true);

  // == 11. #15 -- a cross-tenant closure edge cannot pick the wrong ancestor =
  console.log('\n[11] #15 -- shouldSuppressIndividual re-confronts the ancestor with the tenant');
  const { groupNotificationService } = await import('../src/services/groupNotification.service');
  await db('device_groups').where({ id: gAcme }).update({ group_notifications: true });
  // The residue the FK composite does not cover and checkClosureIntegrity only
  // logs: an ancestor edge from an Acme group onto a Globex group.
  await db('group_closure').insert({ ancestor_id: gAcme, descendant_id: gGlobex, depth: 1 });
  ok('without a tenant the raw closure still answers with the Acme group',
    (await groupNotificationService.shouldSuppressIndividual(gGlobex)) === gAcme,
    'this is the helper in group.service.ts, another agent owns it');
  ok('with the tenant, the foreign ancestor is refused',
    (await groupNotificationService.shouldSuppressIndividual(gGlobex, GLOBEX)) === null);
  ok('a legitimate ancestor in the right tenant is still returned',
    (await groupNotificationService.shouldSuppressIndividual(gAcme, ACME)) === gAcme);
  await db('group_closure').where({ ancestor_id: gAcme, descendant_id: gGlobex }).del();

  console.log(`\n-------- ${pass} passed, ${fail} failed --------`);
  if (fail) console.log('FAILURES:\n  ' + failures.join('\n  '));
  await db.destroy();
  process.exit(fail ? 1 : 0);
}
main().catch(async (e) => { console.error(e); await db.destroy(); process.exit(2); });
