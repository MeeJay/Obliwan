/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Adversarial verification of the VERIF-SECFIX / VERIF-SECFIX-AUTRES fixes.
 * Run against a DISPOSABLE PostgreSQL. Direct service + controller calls.
 */
import { db } from '../src/db';
import { notificationService } from '../src/services/notification.service';
import { smtpServerService } from '../src/services/smtpServer.service';
import { teamService } from '../src/services/team.service';
import { permissionService } from '../src/services/permission.service';
import { settingsController } from '../src/controllers/settings.controller';
import { groupsController } from '../src/controllers/groups.controller';
import { teamsController } from '../src/controllers/teams.controller';
import { usersController } from '../src/controllers/users.controller';
import { notificationsController } from '../src/controllers/notifications.controller';
import { importExportController } from '../src/controllers/importExport.controller';
import { topoSort, findCycles, CycleError } from '../src/utils/topoSort';
import { AppError } from '../src/middleware/errorHandler';

let pass = 0, fail = 0;
const failures: string[] = [];
function ok(name: string, cond: boolean, detail = '') {
  if (cond) { pass++; console.log(`PASS  ${name}${detail ? ' :: ' + detail : ''}`); }
  else { fail++; failures.push(name + (detail ? ' :: ' + detail : '')); console.log(`FAIL  ${name} :: ${detail}`); }
}

// ── fake express plumbing ────────────────────────────────────────────────────
interface Emitted { room: string; event: string; payload: any }
function makeReq(over: any = {}): any {
  const emitted: Emitted[] = over.__emitted ?? [];
  return {
    params: {}, body: {}, query: {}, session: {},
    app: { get: (k: string) => (k === 'io' ? {
      to(room: string) { return { emit(event: string, payload: any) { emitted.push({ room, event, payload }); } }; },
    } : undefined) },
    __emitted: emitted,
    ...over,
  };
}
function runCtl(fn: any, req: any): Promise<{ status: number; body: any; err: any }> {
  return new Promise((resolve) => {
    let status = 200;
    const res: any = {
      status(s: number) { status = s; return res; },
      json(body: any) { resolve({ status, body, err: null }); },
    };
    fn(req, res, (err: any) => resolve({ status: err?.statusCode ?? 500, body: null, err }));
  });
}

async function main() {
  // ── fixtures ───────────────────────────────────────────────────────────────
  const [acme] = await db('tenants').insert({ name: 'Acme', slug: 'acme' }).returning('id');
  const [globex] = await db('tenants').insert({ name: 'Globex', slug: 'globex' }).returning('id');
  const A = acme.id as number, G = globex.id as number;

  const mkUser = async (username: string, role = 'user') =>
    (await db('users').insert({ username, password_hash: 'x', role, is_active: true, display_name: username }).returning('id'))[0].id as number;

  const padmin = await mkUser('padmin', 'admin');
  const auser = await mkUser('auser');
  const auser2 = await mkUser('auser2');
  const guser = await mkUser('guser');
  const orphan = await mkUser('orphan');
  await db('user_tenants').insert([
    { user_id: padmin, tenant_id: A, role: 'admin' },
    { user_id: auser, tenant_id: A, role: 'member' },
    { user_id: auser2, tenant_id: A, role: 'member' },
    { user_id: guser, tenant_id: G, role: 'member' },
  ]);

  const mkGroup = async (name: string, tenant: number) => {
    const [g] = await db('device_groups').insert({ name, slug: name.toLowerCase(), tenant_id: tenant, is_general: false }).returning('id');
    await db('group_closure').insert({ ancestor_id: g.id, descendant_id: g.id, depth: 0 });
    return g.id as number;
  };
  const gA = await mkGroup('acmegrp', A);
  const gG = await mkGroup('globexgrp', G);

  const mkDevice = async (name: string, tenant: number) =>
    (await db('devices').insert({ name, brand: 'mikrotik', family: 'mikrotik_routeros7', tenant_id: tenant }).returning('id'))[0].id as number;
  const dA = await mkDevice('acme-cpe', A);
  const dG = await mkDevice('globex-cpe', G);

  const mkTeam = async (name: string, tenant: number) =>
    (await db('user_teams').insert({ name, tenant_id: tenant, can_create: true }).returning('id'))[0].id as number;
  const tA = await mkTeam('NOC-A', A);
  const tG = await mkTeam('NOC-G', G);
  await db('team_memberships').insert([{ team_id: tA, user_id: auser }, { team_id: tG, user_id: auser }]);
  await db('team_permissions').insert([
    { team_id: tA, scope: 'group', scope_id: gA, level: 'rw' },
    { team_id: tG, scope: 'group', scope_id: gG, level: 'rw' },
  ]);

  console.log(`\n== fixtures: acme=${A} globex=${G} gA=${gA} gG=${gG} dA=${dA} dG=${dG} tA=${tA} tG=${tG}\n`);

  // ══ 1. R2 — updateChannel / deleteChannel / channel-tenants scoping ═════════
  console.log('-- R2 : notification channel write scoping --');
  const chG = await notificationService.createChannel(
    { name: 'GlobexDiscord', type: 'discord', config: { webhookUrl: 'https://discord.com/api/webhooks/AAA/SECRET' } }, G);
  const chA = await notificationService.createChannel(
    { name: 'AcmeDiscord', type: 'discord', config: { webhookUrl: 'https://discord.com/api/webhooks/BBB/ACME' } }, A);

  ok('R2 getChannelById(globex ch, acme) -> null', (await notificationService.getChannelById(chG.id, A)) === null);
  const upd = await notificationService.updateChannel(chG.id, { name: 'HIJACKED' }, A);
  ok('R2 updateChannel(globex ch, acme) -> null (no secret returned)', upd === null, JSON.stringify(upd));
  const stillNamed = await db('notification_channels').where({ id: chG.id }).first('name');
  ok('R2 globex channel name untouched', stillNamed.name === 'GlobexDiscord', stillNamed.name);
  ok('R2 deleteChannel(globex ch, acme) -> false', (await notificationService.deleteChannel(chG.id, A)) === false);
  ok('R2 globex channel still exists', !!(await db('notification_channels').where({ id: chG.id }).first()));
  ok('R2 getChannelTenants(globex ch, acme) -> null', (await notificationService.getChannelTenants(chG.id, A)) === null);
  ok('R2 setChannelTenants(globex ch, acme) -> false', (await notificationService.setChannelTenants(chG.id, [A], G === 0 ? G : A)) === false);
  ok('R2 sharing table untouched', (await db('notification_channel_tenants').where({ channel_id: chG.id })).length === 0);
  // non-regression: the owner still can
  const own = await notificationService.updateChannel(chA.id, { name: 'AcmeRenamed' }, A);
  ok('R2 owner may still rename its own channel', own?.name === 'AcmeRenamed');
  ok('R2 owner may set its sharing list', (await notificationService.setChannelTenants(chA.id, [G], A)) === true);
  ok('R2 owner may read its sharing list', JSON.stringify(await notificationService.getChannelTenants(chA.id, A)) === JSON.stringify([G]));
  // a channel SHARED to globex is readable but not writable from globex
  ok('R2 shared channel readable from grantee', (await notificationService.getChannelById(chA.id, G)) !== null);
  ok('R2 shared channel NOT writable from grantee', (await notificationService.updateChannel(chA.id, { name: 'x' }, G)) === null);
  ok('R2 shared channel NOT deletable from grantee', (await notificationService.deleteChannel(chA.id, G)) === false);
  // HTTP-level
  const r2http = await runCtl(notificationsController.updateChannel, makeReq({ params: { id: String(chG.id) }, body: { name: 'HIJACKED' }, tenantId: A, session: { userId: padmin, role: 'admin' } }));
  ok('R2 PUT /channels/:id cross-tenant -> 404', r2http.status === 404 && r2http.err?.message === 'Channel not found', `${r2http.status} ${r2http.err?.message}`);
  const r2del = await runCtl(notificationsController.deleteChannel, makeReq({ params: { id: String(chG.id) }, tenantId: A, session: { userId: padmin, role: 'admin' } }));
  ok('R2 DELETE /channels/:id cross-tenant -> 404', r2del.status === 404, String(r2del.status));

  // ══ 2. R3 — getUserPermissions without a tenant ════════════════════════════
  console.log('\n-- R3 : getUserPermissions without a tenant --');
  const permA = await permissionService.getUserPermissions(auser, false, A);
  ok('R3 with tenant acme: sees only acme grants',
    permA.teams.length === 1 && permA.teams[0] === tA && permA.permissions[`group:${gA}`] === 'rw' && permA.permissions[`group:${gG}`] === undefined,
    JSON.stringify(permA));
  const permNone = await permissionService.getUserPermissions(auser, false, undefined);
  ok('R3 without tenant: teams []', permNone.teams.length === 0, JSON.stringify(permNone.teams));
  ok('R3 without tenant: permissions {}', Object.keys(permNone.permissions).length === 0, JSON.stringify(permNone.permissions));
  ok('R3 without tenant: capabilities []', permNone.capabilities.length === 0);
  ok('R3 without tenant: canCreate false', permNone.canCreate === false);

  // ══ 3. R5 — assertScopeInTenant covers device ══════════════════════════════
  console.log('\n-- R5 : settings scope=device --');
  const s1 = await runCtl(settingsController.set, makeReq({ params: { scope: 'device', scopeId: '4242' }, body: { key: 'snmp_timeout', value: 4000 }, tenantId: A }));
  ok('R5 PUT /settings/device/4242 (nonexistent) -> 404', s1.status === 404 && s1.err?.message === 'Device not found', `${s1.status} ${s1.err?.message}`);
  const s2 = await runCtl(settingsController.set, makeReq({ params: { scope: 'device', scopeId: String(dG) }, body: { key: 'snmp_timeout', value: 4000 }, tenantId: A }));
  ok('R5 PUT /settings/device/<globex device> from acme -> 404', s2.status === 404, `${s2.status} ${s2.err?.message}`);
  ok('R5 no orphan settings row written', (await db('settings').where({ scope: 'device' })).length === 0);
  const s3 = await runCtl(settingsController.set, makeReq({ params: { scope: 'device', scopeId: String(dA) }, body: { key: 'snmp_timeout', value: 4000 }, tenantId: A }));
  ok('R5 non-regression: own device -> 200', s3.status === 200 && s3.body?.success === true, `${s3.status} ${s3.err?.message}`);
  const s4 = await runCtl(settingsController.setBulk, makeReq({ params: { scope: 'device', scopeId: String(dG) }, body: { overrides: [{ key: 'snmp_timeout', value: 4000 }] }, tenantId: A }));
  ok('R5 bulk on foreign device -> 404', s4.status === 404, String(s4.status));
  const s5 = await runCtl(settingsController.remove, makeReq({ params: { scope: 'device', scopeId: String(dG), key: 'snmp_timeout' }, tenantId: A }));
  ok('R5 delete on foreign device -> 404', s5.status === 404, String(s5.status));
  const s6 = await runCtl(settingsController.set, makeReq({ params: { scope: 'group', scopeId: String(gG) }, body: { key: 'snmp_timeout', value: 4000 }, tenantId: A }));
  ok('R5 non-regression: group scope still 404 cross-tenant', s6.status === 404, String(s6.status));

  // ══ 4. Socket.io rooms ═════════════════════════════════════════════════════
  console.log('\n-- Socket.io rooms --');
  const emitted: Emitted[] = [];
  const reqG = makeReq({ tenantId: G, masterView: false, session: { userId: padmin, role: 'admin' }, body: { name: 'GlobexPrivateSite' }, __emitted: emitted });
  const cg = await runCtl(groupsController.create, reqG);
  ok('SOCK group:created emitted', emitted.length === 1, JSON.stringify(emitted));
  ok('SOCK room is tenant:<globex>:admin, not role:admin', emitted[0]?.room === `tenant:${G}:admin`, emitted[0]?.room);
  ok('SOCK payload carries tenantId', emitted[0]?.payload?.tenantId === G, JSON.stringify(emitted[0]?.payload?.tenantId));
  const newGroupId = cg.body?.data?.id as number;

  const em2: Emitted[] = [];
  await runCtl(groupsController.update, makeReq({ tenantId: G, params: { id: String(newGroupId) }, body: { name: 'Renamed' }, session: { role: 'admin', userId: padmin }, __emitted: em2 }));
  ok('SOCK group:updated room', em2[0]?.room === `tenant:${G}:admin`, em2[0]?.room);
  const em3: Emitted[] = [];
  await runCtl(groupsController.move, makeReq({ tenantId: G, params: { id: String(newGroupId) }, body: { newParentId: gG }, session: { role: 'admin', userId: padmin }, __emitted: em3 }));
  ok('SOCK group:moved room', em3[0]?.room === `tenant:${G}:admin`, em3[0]?.room);
  const em4: Emitted[] = [];
  await runCtl(groupsController.reorder, makeReq({ tenantId: G, body: { items: [{ id: newGroupId, sortOrder: 3 }] }, session: { role: 'admin', userId: padmin }, __emitted: em4 }));
  ok('SOCK group:reordered room', em4[0]?.room === `tenant:${G}:admin`, em4[0]?.room);
  const em5: Emitted[] = [];
  await runCtl(groupsController.delete, makeReq({ tenantId: G, params: { id: String(newGroupId) }, session: { role: 'admin', userId: padmin }, __emitted: em5 }));
  ok('SOCK group:deleted room', em5[0]?.room === `tenant:${G}:admin`, em5[0]?.room);
  const em6: Emitted[] = [];
  await runCtl(settingsController.set, makeReq({ params: { scope: 'global', scopeId: 'null' }, body: { key: 'snmp_retries', value: 7 }, tenantId: G, __emitted: em6 }));
  ok('SOCK settings:updated room', em6[0]?.room === `tenant:${G}:admin`, em6[0]?.room);
  ok('SOCK settings payload carries tenantId', em6[0]?.payload?.tenantId === G);
  const em7: Emitted[] = [];
  await runCtl(settingsController.setBulk, makeReq({ params: { scope: 'global', scopeId: 'null' }, body: { overrides: [{ key: 'snmp_retries', value: 4 }] }, tenantId: G, __emitted: em7 }));
  ok('SOCK settings bulk room', em7[0]?.room === `tenant:${G}:admin`, em7[0]?.room);
  const em8: Emitted[] = [];
  await runCtl(settingsController.remove, makeReq({ params: { scope: 'global', scopeId: 'null', key: 'snmp_retries' }, tenantId: G, __emitted: em8 }));
  ok('SOCK settings remove room', em8[0]?.room === `tenant:${G}:admin`, em8[0]?.room);

  // ══ 5. SMTP platform relay ═════════════════════════════════════════════════
  console.log('\n-- SMTP relay scoping --');
  const relayPlat = await smtpServerService.create({ name: 'platform', host: 'smtp.platform', port: 587, secure: false, username: 'u', password: 'p', fromAddress: 'a@p', tenantId: A, isPlatform: true });
  const relayA = await smtpServerService.create({ name: 'acme', host: 'smtp.acme.local', port: 587, secure: false, username: 'ua', password: 'pa', fromAddress: 'a@acme', tenantId: A });
  const relayG = await smtpServerService.create({ name: 'globex', host: 'smtp.globex.local', port: 587, secure: false, username: 'ug', password: 'pg', fromAddress: 'a@globex', tenantId: G });
  const platRow = await db('smtp_servers').where({ id: relayPlat.id }).first('tenant_id');
  ok('SMTP platform relay is created with tenant_id NULL', platRow.tenant_id === null, String(platRow.tenant_id));
  ok('SMTP getTransportConfig(acme relay) with NO tenant (instance scope) -> null',
    (await smtpServerService.getTransportConfig(relayA.id)) === null);
  ok('SMTP getTransportConfig(platform relay) with NO tenant -> resolved',
    (await smtpServerService.getTransportConfig(relayPlat.id))?.host === 'smtp.platform');
  ok('SMTP getById(acme relay) with no tenant -> null (OTP path refuses a tenant relay)',
    (await smtpServerService.getById(relayA.id)) === null);
  ok('SMTP getTransportConfig(globex relay, acme) -> null',
    (await smtpServerService.getTransportConfig(relayG.id, A)) === null);
  ok('SMTP getTransportConfig(acme relay, acme) -> resolved',
    (await smtpServerService.getTransportConfig(relayA.id, A))?.host === 'smtp.acme.local');
  ok('SMTP getTransportConfig(platform relay, acme) -> resolved (platform usable by all)',
    (await smtpServerService.getTransportConfig(relayPlat.id, A))?.host === 'smtp.platform');
  const listA = await smtpServerService.list(A);
  ok('SMTP list(acme) = own + platform, never globex',
    listA.length === 2 && listA.some((s) => s.id === relayA.id) && listA.some((s) => s.id === relayPlat.id) && !listA.some((s) => s.id === relayG.id),
    listA.map((s) => s.name).join(','));
  const listPlat = await smtpServerService.list();
  ok('SMTP list() = platform only', listPlat.length === 1 && listPlat[0].id === relayPlat.id);
  ok('SMTP isPlatformRelay(acme relay) false', (await smtpServerService.isPlatformRelay(relayA.id)) === false);
  ok('SMTP isPlatformRelay(platform relay) true', (await smtpServerService.isPlatformRelay(relayPlat.id)) === true);

  // ══ 6. resolveChannelConfig / smtpServerId cross-tenant ════════════════════
  console.log('\n-- resolveChannelConfig : smtpServerId ownership --');
  let threw = '';
  try { await notificationService.createChannel({ name: 'evil', type: 'smtp', config: { smtpServerId: relayG.id, to: 'noc@acme' } }, A); }
  catch (e: any) { threw = e.message; }
  ok('CFG createChannel(acme) with globex smtpServerId is refused', threw.includes('not found'), threw);
  ok('CFG no channel row was written', (await db('notification_channels').where({ name: 'evil' })).length === 0);

  const chSmtp = await notificationService.createChannel({ name: 'acme-smtp', type: 'smtp', config: { smtpServerId: relayA.id, to: 'noc@acme' } }, A);
  ok('CFG non-regression: own relay accepted at create', !!chSmtp.id);
  const chSmtpPlat = await notificationService.createChannel({ name: 'acme-smtp-plat', type: 'smtp', config: { smtpServerId: relayPlat.id, to: 'noc@acme' } }, A);
  ok('CFG non-regression: platform relay accepted at create', !!chSmtpPlat.id);

  threw = '';
  try { await notificationService.updateChannel(chSmtp.id, { config: { smtpServerId: relayG.id, to: 'x' } }, A); }
  catch (e: any) { threw = e.message; }
  ok('CFG updateChannel to a foreign smtpServerId is refused', threw.includes('not found'), threw);
  const afterUpd = await db('notification_channels').where({ id: chSmtp.id }).first('config');
  const cfgNow = typeof afterUpd.config === 'string' ? JSON.parse(afterUpd.config) : afterUpd.config;
  ok('CFG config unchanged after refusal', Number(cfgNow.smtpServerId) === relayA.id, JSON.stringify(cfgNow));

  // a row forged directly in the DB (pre-existing bad blob) must still not fire
  await db('notification_channels').where({ id: chSmtp.id }).update({ config: JSON.stringify({ smtpServerId: relayG.id, to: 'x' }) });
  const forged = await notificationService.getChannelById(chSmtp.id, A);
  threw = '';
  try { await notificationService.resolveChannelConfig(forged as any, A); } catch (e: any) { threw = e.message; }
  ok('CFG resolveChannelConfig refuses a pre-existing cross-tenant relay', threw.includes('not found'), threw);
  const resolvedOwn = await notificationService.resolveChannelConfig(
    { type: 'smtp', config: { smtpServerId: relayA.id, to: 'x' } } as any, A);
  ok('CFG non-regression: own relay resolves with credentials', (resolvedOwn as any).password === 'pa');

  // ══ 7. team.setMembers + GET /api/users ════════════════════════════════════
  console.log('\n-- team.setMembers / users listing --');
  let e7: any = null;
  try { await teamService.setMembers(tA, [auser2, guser], A); } catch (e) { e7 = e; }
  ok('TEAM setMembers with a foreign user -> AppError 400', e7 instanceof AppError && e7.statusCode === 400, e7?.message);
  ok('TEAM message names the rejected id', String(e7?.message).includes(String(guser)), e7?.message);
  ok('TEAM nothing was written', (await db('team_memberships').where({ team_id: tA, user_id: guser })).length === 0);
  ok('TEAM the pre-existing membership survived the refusal', (await db('team_memberships').where({ team_id: tA, user_id: auser })).length === 1);
  e7 = null;
  try { await teamService.setMembers(tG, [auser], A); } catch (e) { e7 = e; }
  ok('TEAM setMembers on another tenant\'s team -> 404', e7 instanceof AppError && e7.statusCode === 404, e7?.message);
  await teamService.setMembers(tA, [auser, auser2], A);
  ok('TEAM non-regression: legitimate members accepted',
    (await teamService.getMembers(tA, A) ?? []).sort().join(',') === [auser, auser2].sort().join(','));
  await teamService.setMembers(tA, [auser, auser, auser2], A);
  ok('TEAM duplicate ids collapse instead of a unique-key 500', (await teamService.getMembers(tA, A) ?? []).length === 2);

  const th = await runCtl(teamsController.setMembers, makeReq({ params: { id: String(tG) }, body: { userIds: [auser] }, tenantId: A, session: { role: 'admin', userId: padmin } }));
  ok('TEAM PUT /teams/<globex team>/members from acme -> 404', th.status === 404, String(th.status));

  const ul = await runCtl(usersController.list, makeReq({ tenantId: A, query: {}, session: { role: 'admin', userId: padmin } }));
  const ids = (ul.body?.data ?? []).map((u: any) => u.id).sort((x: number, y: number) => x - y);
  ok('USERS GET /api/users on acme lists only acme members',
    !ids.includes(guser) && !ids.includes(orphan) && ids.includes(auser) && ids.includes(padmin), JSON.stringify(ids));
  const ulAll = await runCtl(usersController.list, makeReq({ tenantId: A, query: { scope: 'all' }, session: { role: 'admin', userId: padmin } }));
  ok('USERS ?scope=all (platform admin) still lists everybody',
    (ulAll.body?.data ?? []).some((u: any) => u.id === guser) && (ulAll.body?.data ?? []).some((u: any) => u.id === orphan),
    String((ulAll.body?.data ?? []).length));
  const ulAllNonAdmin = await runCtl(usersController.list, makeReq({ tenantId: A, query: { scope: 'all' }, session: { role: 'user', userId: auser } }));
  ok('USERS ?scope=all is ignored for a non platform admin',
    !(ulAllNonAdmin.body?.data ?? []).some((u: any) => u.id === guser), String((ulAllNonAdmin.body?.data ?? []).length));

  // ══ 7bis. team accessors by bare id (#13) + grant scopeId (#14) ═══════════
  console.log();
  console.log("-- team accessors / grant scope --");
  ok('TEAM13 getById(globex team, acme) -> null', (await teamService.getById(tG, A)) === null);
  ok('TEAM13 getById(acme team, acme) -> found', (await teamService.getById(tA, A))?.id === tA);
  ok('TEAM13 getMembers(globex team, acme) -> null', (await teamService.getMembers(tG, A)) === null);
  ok('TEAM13 getPermissions(globex team, acme) -> null', (await teamService.getPermissions(tG, A)) === null);
  ok('TEAM13 update(globex team, acme) -> null', (await teamService.update(tG, { name: 'PWNED' }, A)) === null);
  ok('TEAM13 globex team name untouched', (await db('user_teams').where({ id: tG }).first('name')).name === 'NOC-G');
  ok('TEAM13 delete(globex team, acme) -> false', (await teamService.delete(tG, A)) === false);
  ok('TEAM13 globex team still exists', !!(await db('user_teams').where({ id: tG }).first()));
  const permG = (await db('team_permissions').where({ team_id: tG }).first('id')).id as number;
  ok('TEAM13 removePermission(acme team, globex perm row, acme) -> false',
    (await teamService.removePermission(tA, permG, A)) === false);
  ok('TEAM13 globex grant row survives the scan', !!(await db('team_permissions').where({ id: permG }).first()));
  const rp = await runCtl(teamsController.removePermission, makeReq({ params: { id: String(tA), permId: String(permG) }, tenantId: A, session: { role: 'admin', userId: padmin } }));
  ok('TEAM13 DELETE /teams/:id/permissions/:permId cross-tenant -> 404', rp.status === 404, String(rp.status));
  const permA0 = (await db('team_permissions').where({ team_id: tA }).first('id')).id as number;
  ok('TEAM13 non-regression: own grant removable', (await teamService.removePermission(tA, permA0, A)) === true);
  let e14: any = null;
  try { await teamService.setPermissions(tA, [{ scope: 'group', scopeId: gG, level: 'rw' }], A); } catch (e) { e14 = e; }
  ok('TEAM14 setPermissions on a foreign group -> 404', e14 instanceof AppError && e14.statusCode === 404, e14?.message);
  ok('TEAM14 nothing written', (await db('team_permissions').where({ team_id: tA, scope_id: gG })).length === 0);
  e14 = null;
  try { await teamService.setPermissions(tA, [{ scope: 'device', scopeId: dG, level: 'rw' }], A); } catch (e) { e14 = e; }
  ok('TEAM14 setPermissions on a foreign device -> 404', e14 instanceof AppError && e14.statusCode === 404, e14?.message);
  await teamService.setPermissions(tA, [{ scope: 'group', scopeId: gA, level: 'rw' }, { scope: 'device', scopeId: dA, level: 'ro' }], A);
  ok('TEAM14 non-regression: own group+device grants accepted', ((await teamService.getPermissions(tA, A)) ?? []).length === 2);
  const ab = await runCtl(notificationsController.addBinding, makeReq({ body: { channelId: chA.id, scope: 'group', scopeId: gG, overrideMode: 'merge' }, tenantId: A, session: { role: 'admin', userId: padmin } }));
  ok('BIND14 addBinding on a foreign group -> 404', ab.status === 404, String(ab.status));
  ok('BIND14 no orphan binding row', (await db('notification_bindings').where({ scope_id: gG })).length === 0);
  const ab2 = await runCtl(notificationsController.addBinding, makeReq({ body: { channelId: chA.id, scope: 'group', scopeId: gA, overrideMode: 'merge' }, tenantId: A, session: { role: 'admin', userId: padmin } }));
  ok('BIND14 non-regression: own group binding accepted', ab2.status === 201, String(ab2.status));
  // ══ 8. topoSort cycle detection + import ═══════════════════════════════════
  console.log('\n-- topoSort cycles --');
  const acyclic = [{ uuid: 'c', parentUuid: 'b' }, { uuid: 'b', parentUuid: 'a' }, { uuid: 'a', parentUuid: null }];
  ok('TOPO acyclic still sorts parents first',
    topoSort(acyclic, 'uuid', 'parentUuid').map((i) => i.uuid).join('') === 'abc',
    topoSort(acyclic, 'uuid', 'parentUuid').map((i) => i.uuid).join(''));
  ok('TOPO parent absent from the batch is a root',
    topoSort([{ uuid: 'x', parentUuid: 'not-in-batch' }], 'uuid', 'parentUuid').length === 1);
  let ce: any = null;
  try { topoSort([{ uuid: 'a', parentUuid: 'b' }, { uuid: 'b', parentUuid: 'a' }], 'uuid', 'parentUuid'); } catch (e) { ce = e; }
  ok('TOPO 2-cycle detected', ce instanceof CycleError, ce?.message);
  ce = null;
  try { topoSort([{ uuid: 'a', parentUuid: 'a' }], 'uuid', 'parentUuid'); } catch (e) { ce = e; }
  ok('TOPO self-cycle detected', ce instanceof CycleError, ce?.message);
  ok('TOPO findCycles names both members',
    findCycles([{ uuid: 'a', parentUuid: 'b' }, { uuid: 'b', parentUuid: 'a' }, { uuid: 'z', parentUuid: null }], 'uuid', 'parentUuid').sort().join(',') === 'a,b');
  ok('TOPO findCycles clean batch -> []',
    findCycles(acyclic, 'uuid', 'parentUuid').length === 0);
  // deep chain: no stack overflow
  const deep = Array.from({ length: 20000 }, (_, i) => ({ uuid: `n${i}`, parentUuid: i === 0 ? null : `n${i - 1}` }));
  ok('TOPO 20000-deep chain sorts without blowing the stack', topoSort(deep, 'uuid', 'parentUuid').length === 20000);

  console.log('\n-- import with a cyclic bundle --');
  // Two groups that already exist in acme, with their parentUuid crossed.
  const [ua] = await db('device_groups').where({ id: gA }).select('uuid');
  const gA2 = await mkGroup('acmegrp2', A);
  const [ub] = await db('device_groups').where({ id: gA2 }).select('uuid');
  const settingsBefore = await db('settings').where({ tenant_id: A }).count('* as c');
  const imp = await runCtl(importExportController.importData, makeReq({
    tenantId: A, session: { role: 'admin', userId: padmin },
    body: {
      sections: ['deviceGroups', 'settings'], conflictStrategy: 'update',
      data: {
        deviceGroups: [
          { uuid: ua.uuid, name: 'acmegrp', parentUuid: ub.uuid },
          { uuid: ub.uuid, name: 'acmegrp2', parentUuid: ua.uuid },
        ],
        settings: [{ scope: 'global', key: 'snmp_timeout', value: 1234 }],
      },
    },
  }));
  ok('IMPORT cyclic bundle -> 400, not 500', imp.status === 400, `${imp.status} :: ${imp.err?.message}`);
  ok('IMPORT error names both offending groups',
    String(imp.err?.message).includes(ua.uuid) && String(imp.err?.message).includes(ub.uuid), String(imp.err?.message));
  ok('IMPORT error is actionable (mentions parentUuid)', String(imp.err?.message).includes('parentUuid'));
  ok('IMPORT nothing was written (transaction rolled back)',
    (await db('device_groups').where({ id: gA }).first('parent_id')).parent_id === null);
  const settingsAfter = await db('settings').where({ tenant_id: A }).count('* as c');
  ok('IMPORT the settings section of the same bundle was not applied either',
    settingsBefore[0].c === settingsAfter[0].c, `${settingsBefore[0].c} -> ${settingsAfter[0].c}`);
  // non-regression: a clean bundle still imports
  const impOk = await runCtl(importExportController.importData, makeReq({
    tenantId: A, session: { role: 'admin', userId: padmin },
    body: {
      sections: ['deviceGroups'], conflictStrategy: 'update',
      data: { deviceGroups: [{ uuid: ua.uuid, name: 'acmegrp', parentUuid: null }, { uuid: ub.uuid, name: 'acmegrp2', parentUuid: ua.uuid }] },
    },
  }));
  ok('IMPORT non-regression: acyclic bundle still imports', impOk.status === 200 && impOk.body?.data?.deviceGroups?.updated === 2,
    JSON.stringify(impOk.body?.data) + String(impOk.err?.message ?? ''));
  ok('IMPORT non-regression: closure rebuilt',
    (await db('group_closure').where({ ancestor_id: gA, descendant_id: gA2 }).first()) !== undefined);

  console.log(`\n=================  ${pass} PASS / ${fail} FAIL  =================`);
  if (failures.length) console.log(failures.map((f) => ' - ' + f).join('\n'));
  await db.destroy();
  process.exit(fail === 0 ? 0 : 1);
}

main().catch(async (e) => { console.error(e); await db.destroy(); process.exit(2); });
