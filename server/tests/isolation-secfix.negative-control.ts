/* Negative control: re-runs the PRE-FIX code paths verbatim against the same
   fixtures, to prove the assertions in isolation.verify.ts are not vacuous.
   Run it AFTER isolation-secfix.verify.ts, on the same database: it reuses that
   script's fixtures (tenants acme/globex, users, channels, relays).
   Nothing here imports the fixed services — each block is the old query.       */
import { db } from '../src/db';

let leaks = 0;
function leaked(name: string, detail: string) { leaks++; console.log(`  LEAK  ${name} -- ${detail}`); }
function safe(name: string, detail: string) { console.log(`  ok    ${name} -- ${detail}`); }

async function main() {
  const ACME = (await db('tenants').where({ slug: 'acme' }).first('id')).id as number;
  const GLOBEX = (await db('tenants').where({ slug: 'globex' }).first('id')).id as number;
  const carol = (await db('users').where({ username: 'carol' }).first('id')).id as number;
  const bob = (await db('users').where({ username: 'bob' }).first('id')).id as number;
  const teamAcme = (await db('user_teams').where({ name: 'NOC-Acme' }).first('id')).id as number;
  const chGlobex = (await db('notification_channels').where({ tenant_id: GLOBEX, type: 'discord' }).first('id')).id as number;
  const relayAcme = (await db('smtp_servers').where({ name: 'Acme private relay' }).first('id')).id as number;
  const dAcme = (await db('devices').where({ tenant_id: ACME }).first('id')).id as number;

  console.log('\n== R2: OLD updateChannel — `where({ id })`, no tenant ==');
  const [old2] = await db('notification_channels').where({ id: chGlobex })
    .update({ updated_at: new Date() }).returning('*');
  const cfg = typeof old2.config === 'string' ? JSON.parse(old2.config) : old2.config;
  if (old2 && cfg.webhookUrl) leaked('a PUT from Acme returns Globex config', JSON.stringify(cfg));
  else safe('no config returned', '');

  console.log('\n== R3: OLD getUserPermissions — grants unfiltered without a tenant ==');
  const oldTeams = await db('team_memberships').where({ user_id: carol }).pluck('team_id');
  const oldPerms = await db('team_permissions').whereIn('team_id', oldTeams).select('scope', 'scope_id', 'level');
  if (oldTeams.length > 1) leaked('teams across tenants', `teams=${oldTeams} grants=${JSON.stringify(oldPerms)}`);
  else safe('single tenant', String(oldTeams));

  console.log('\n== R5: OLD assertScopeInTenant — `if (scope !== \'group\' || scopeId === null) return` ==');
  const oldGuard = (scope: string, scopeId: number | null) => (scope !== 'group' || scopeId === null);
  if (oldGuard('device', 4242)) leaked('scope=device/4242 waved through', 'returns before any lookup');
  if (oldGuard('device', dAcme)) leaked(`scope=device/${dAcme} (Acme device) waved through from Globex`, 'no tenant check');

  console.log('\n== #5: OLD smtpServerService.getById — `where({ id })` for instance-wide mail ==');
  const oldRelay = await db('smtp_servers').where({ id: relayAcme }).first();
  if (oldRelay) leaked('OTP would send through a TENANT relay',
    `${oldRelay.name} host=${oldRelay.host} user=${oldRelay.username} tenant_id=${oldRelay.tenant_id}`);

  console.log('\n== #9: OLD setMembers — no eligibility check ==');
  const eligible = await db('user_tenants').where({ tenant_id: ACME }).whereIn('user_id', [bob]).pluck('user_id');
  if (eligible.length === 0) leaked('bob (Globex-only) would have been written into an Acme team',
    `team_id=${teamAcme}, user_id=${bob}, no user_tenants row on Acme`);

  console.log('\n== #9b: OLD GET /api/users — no tenant filter ==');
  const allUsers = await db('users').pluck('username');
  const acmeUsers = await db('user_tenants').where({ tenant_id: ACME })
    .join('users', 'users.id', 'user_tenants.user_id').pluck('users.username');
  if (allUsers.length > acmeUsers.length)
    leaked('the dropdown was fed cross-tenant', `all=${allUsers} vs acme=${acmeUsers}`);

  console.log('\n== #8: OLD topoSort — visited-set only, cycles ordered not detected ==');
  function oldTopoSort<T extends Record<string, unknown>>(items: T[], uuidKey: string, parentKey: string): T[] {
    const byUuid = new Map(items.map((i) => [i[uuidKey] as string, i]));
    const sorted: T[] = [];
    const visited = new Set<string>();
    function visit(item: T) {
      const key = item[uuidKey] as string;
      if (!key || visited.has(key)) return;
      visited.add(key);
      const parentK = item[parentKey] as string | null;
      if (parentK && byUuid.has(parentK)) visit(byUuid.get(parentK)!);
      sorted.push(item);
    }
    for (const i of items) visit(i);
    return sorted;
  }
  const cyc = [{ uuid: 'a', parentUuid: 'b' }, { uuid: 'b', parentUuid: 'a' }];
  let threw = false;
  let out: unknown[] = [];
  try { out = oldTopoSort(cyc, 'uuid', 'parentUuid'); } catch { threw = true; }
  if (!threw) leaked('a 2-node cycle was ORDERED, not refused',
    `emitted ${out.length} items: ${out.map((o) => (o as { uuid: string }).uuid).join(',')} — the comment said "silently ignored"`);

  console.log(`\n-------- ${leaks} pre-fix leaks reproduced (each one is what the fixed run now refuses) --------`);
  await db.destroy();
}
main().catch(async (e) => { console.error(e); await db.destroy(); process.exit(2); });
