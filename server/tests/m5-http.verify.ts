/**
 * ObliWAN M5 — HTTP surface verification.
 *
 * The routers written for this milestone are NOT mounted (`routes/index.ts`
 * belongs to the M4 workstream), so this harness mounts them itself, exactly as
 * the lead will: under a router that has already run `requireAuth` and
 * `requireTenant`.
 *
 * What it proves:
 *   - route ORDER: no literal prefix is swallowed by `/:id`;
 *   - the R6 capability boundary: `POST /templates/preview` (arbitrary body)
 *     needs TEMPLATE_WRITE, `POST /templates/revisions/:id/preview` (stored
 *     body) needs only TEMPLATE_READ;
 *   - multi-tenant scoping on reads AND writes;
 *   - the shipped library is readable and NOT writable;
 *   - a stale plan is refused with 409, not accepted with a warning.
 *
 * Runs against the same disposable PostgreSQL as `m5-planner.verify.ts`, and
 * expects that harness to have seeded tenant 900 first.
 */

import express from 'express';
import type { Server } from 'http';
import { db } from '../src/db';
import { errorHandler } from '../src/middleware/errorHandler';
import templatesRoutes from '../src/routes/templates.routes';
import variablesRoutes from '../src/routes/variables.routes';
import planRoutes from '../src/routes/plan.routes';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function ok(label: string, cond: boolean, extra = ''): void {
  if (cond) { passed++; console.log(`  PASS  ${label}${extra ? ' — ' + extra : ''}`); }
  else { failed++; failures.push(label); console.log(`  FAIL  ${label}${extra ? ' — ' + extra : ''}`); }
}
function section(t: string): void { console.log(`\n=== ${t} ===`); }

const TENANT = 900;
const OTHER_TENANT = 901;
const DEVICE_BASE = 9000;
const PORT = 45517;

/** userId -> the session this request pretends to carry. Set per-request via a
 *  header, so one server serves every persona without re-listening. */
interface Persona { userId: number; role: 'admin' | 'user'; tenantId: number }
const PERSONAS: Record<string, Persona> = {
  platformAdmin: { userId: 8001, role: 'admin', tenantId: TENANT },
  engineer: { userId: 8002, role: 'user', tenantId: TENANT },      // tenant admin -> TEMPLATE_WRITE
  operator: { userId: 8003, role: 'user', tenantId: TENANT },      // tenant member -> read + plan only
  otherTenant: { userId: 8004, role: 'user', tenantId: OTHER_TENANT },
};

async function seedUsers(): Promise<void> {
  await db.raw('DELETE FROM user_tenants WHERE user_id >= 8000');
  await db.raw('DELETE FROM users WHERE id >= 8000');
  await db.raw('DELETE FROM devices WHERE tenant_id = ?', [OTHER_TENANT]);
  await db.raw('DELETE FROM tenants WHERE id = ?', [OTHER_TENANT]);
  await db('tenants').insert({ id: OTHER_TENANT, name: 'M5 Other', slug: 'm5-other' });

  for (const [name, p] of Object.entries(PERSONAS)) {
    await db('users').insert({
      id: p.userId, username: `m5-${name}`, email: `${name}@m5.test`,
      password_hash: 'x', display_name: name,
      role: p.role === 'admin' ? 'admin' : 'user', is_active: true,
    });
  }
  await db('user_tenants').insert([
    { user_id: PERSONAS.platformAdmin.userId, tenant_id: TENANT, role: 'admin' },
    { user_id: PERSONAS.engineer.userId, tenant_id: TENANT, role: 'admin' },
    { user_id: PERSONAS.operator.userId, tenant_id: TENANT, role: 'member' },
    { user_id: PERSONAS.otherTenant.userId, tenant_id: OTHER_TENANT, role: 'admin' },
  ]);
}

function buildApp(): express.Express {
  const app = express();
  app.use(express.json({ limit: '2mb' }));
  // Stands in for `requireAuth` + `requireTenant`. The real pair is applied by
  // `tenantRouter` in routes/index.ts; nothing in the routers below reads
  // anything these two do not set.
  app.use((req, _res, next) => {
    const who = String(req.headers['x-test-persona'] ?? 'engineer');
    const p = PERSONAS[who];
    (req as unknown as { session: unknown }).session = {
      userId: p.userId, role: p.role, currentTenantId: p.tenantId,
    };
    req.tenantId = p.tenantId;
    req.masterView = false;
    next();
  });
  app.use('/templates', templatesRoutes);
  app.use('/variables', variablesRoutes);
  app.use('/plan', planRoutes);
  app.use(errorHandler);
  return app;
}

async function call(
  persona: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method,
    headers: { 'content-type': 'application/json', 'x-test-persona': persona },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json: Record<string, unknown> = {};
  try { json = (await res.json()) as Record<string, unknown>; } catch { /* empty body */ }
  return { status: res.status, json };
}

async function main(): Promise<void> {
  await seedUsers();
  const server: Server = await new Promise((resolve) => {
    const s = buildApp().listen(PORT, '127.0.0.1', () => resolve(s));
  });

  try {
    // ── Fixtures the planner harness left behind ─────────────────────────
    const tpl = (await db('templates').where('tenant_id', TENANT).first('id')) as { id: string };
    const rev = (await db('template_revisions')
      .where({ tenant_id: TENANT, status: 'published' })
      .orderBy('id', 'asc').first('id')) as { id: string };

    section('Route order — no literal is swallowed by /:id');
    const partials = await call('engineer', 'GET', '/templates/partials');
    ok('GET /templates/partials lists partials, not a template named "partials"',
      partials.status === 200 && Array.isArray(partials.json.data),
      `status=${partials.status}`);
    const assignments = await call('engineer', 'GET', '/templates/assignments');
    ok('GET /templates/assignments reaches the assignment handler',
      assignments.status === 200 && Array.isArray(assignments.json.data));
    const resolution = await call('engineer', 'GET', `/templates/devices/${DEVICE_BASE}/resolution`);
    ok('GET /templates/devices/:id/resolution reaches the resolver',
      resolution.status === 200 &&
      Array.isArray((resolution.json.data as { selected: unknown[] }).selected));
    const one = await call('engineer', 'GET', `/templates/${tpl.id}`);
    ok('GET /templates/:id still works', one.status === 200,
      `status=${one.status}`);
    const revGet = await call('engineer', 'GET', `/templates/revisions/${rev.id}`);
    ok('GET /templates/revisions/:revId serves the body and the pins',
      revGet.status === 200 &&
      typeof (revGet.json.data as { body: string }).body === 'string' &&
      (revGet.json.data as { deps: unknown[] }).deps.length === 1);

    section('R6 — the TEMPLATE_WRITE boundary');
    const scratchBody = {
      deviceId: DEVICE_BASE,
      body: '/ip firewall filter\nadd action=accept chain=input comment="obliwan:probe"\n',
    };
    const scratchAsOperator = await call('operator', 'POST', '/templates/preview', scratchBody);
    ok('an OPERATOR (TEMPLATE_READ + PLAN_CREATE) cannot render an arbitrary body',
      scratchAsOperator.status === 403, `status=${scratchAsOperator.status}`);
    const scratchAsEngineer = await call('engineer', 'POST', '/templates/preview', scratchBody);
    ok('an ENGINEER (TEMPLATE_WRITE) can',
      scratchAsEngineer.status === 200 &&
      (scratchAsEngineer.json.data as { ok: boolean }).ok === true,
      `status=${scratchAsEngineer.status} ${JSON.stringify(scratchAsEngineer.json).slice(0, 160)}`);

    const previewAsOperator = await call('operator', 'POST',
      `/templates/revisions/${rev.id}/preview`, { deviceId: DEVICE_BASE });
    ok('the same operator CAN render a STORED revision (the code was chosen under TEMPLATE_WRITE)',
      previewAsOperator.status === 200 &&
      (previewAsOperator.json.data as { status: string }).status === 'ok',
      `status=${previewAsOperator.status}`);

    const authorAsOperator = await call('operator', 'POST', `/templates/${tpl.id}/revisions`,
      { body: '/ip firewall filter\nadd action=drop chain=input\n' });
    ok('an operator cannot author a revision', authorAsOperator.status === 403);
    const publishAsOperator = await call('operator', 'POST',
      `/templates/revisions/${rev.id}/publish`, {});
    ok('an operator cannot publish', publishAsOperator.status === 403);

    section('§8.2 — no endpoint reveals a secret');
    const vars = await call('engineer', 'GET', `/variables/devices/${DEVICE_BASE + 3}`);
    const varsText = JSON.stringify(vars.json);
    ok('the resolved device variables never contain the plaintext',
      vars.status === 200 && !varsText.includes('super-secret-psk-value'),
      `status=${vars.status}`);
    ok('the secret comes back as a placeholder with a fingerprint',
      /__OBLIWAN_SECRET_SITEPSK__/.test(varsText) && /"fingerprint"/.test(varsText));
    const preview3 = await call('engineer', 'POST',
      `/templates/revisions/${rev.id}/preview`, { deviceId: DEVICE_BASE + 3 });
    ok('a render preview never contains the plaintext either',
      !JSON.stringify(preview3.json).includes('super-secret-psk-value'));

    section('Multi-tenant scoping');
    const foreignTemplate = await call('otherTenant', 'GET', `/templates/${tpl.id}`);
    ok('another tenant gets 404 on this tenant\'s template (not 403)',
      foreignTemplate.status === 404, `status=${foreignTemplate.status}`);
    const foreignRevision = await call('otherTenant', 'GET', `/templates/revisions/${rev.id}`);
    ok('and 404 on its revisions', foreignRevision.status === 404);
    const foreignPlan = await call('otherTenant', 'POST', `/plan/devices/${DEVICE_BASE}`, {});
    ok('and cannot compile a plan for its devices',
      foreignPlan.status === 404, `status=${foreignPlan.status}`);
    const foreignVars = await call('otherTenant', 'GET', `/variables/devices/${DEVICE_BASE}`);
    ok('and cannot read their variables', foreignVars.status === 404);
    const foreignWrite = await call('otherTenant', 'PUT', `/variables/at/device/${DEVICE_BASE}`,
      { key: 'lanSubnet', value: '10.0.0.0/8' });
    ok('and cannot WRITE a variable keyed on one of their devices',
      foreignWrite.status === 404, `status=${foreignWrite.status}`);
    const leaked = await db('config_variables')
      .where({ tenant_id: OTHER_TENANT, scope: 'device', scope_id: DEVICE_BASE }).first('id');
    ok('no row was written by that attempt', !leaked);

    section('The shipped library is readable and NOT writable');
    const [lib] = (await db('templates').insert({
      tenant_id: null, name: 'library-standard', brand: 'mikrotik',
    }).returning('id')) as { id: string }[];
    const libList = await call('engineer', 'GET', '/templates');
    ok('the library template appears in this tenant\'s list, flagged isLibrary',
      (libList.json.data as { id: string; isLibrary: boolean }[])
        .some((t) => String(t.id) === String(lib.id) && t.isLibrary === true));
    const libEdit = await call('engineer', 'PATCH', `/templates/${lib.id}`, { name: 'hijacked' });
    ok('editing it is refused with 403 and an explanation, not a silent 404',
      libEdit.status === 403 && /library/i.test(String(libEdit.json.error ?? '')),
      `status=${libEdit.status} ${String(libEdit.json.error ?? '')}`.slice(0, 130));
    const libDraft = await call('engineer', 'POST', `/templates/${lib.id}/revisions`,
      { body: '/ip firewall filter\nadd action=drop chain=input\n' });
    ok('drafting a revision on it is refused too', libDraft.status === 403);
    await db('templates').where('id', lib.id).del();

    section('Variables — scope arity is enforced by the route table');
    const deviceNoId = await call('engineer', 'PUT', '/variables/at/device',
      { key: 'lanSubnet', value: '10.0.0.0/8' });
    ok('PUT /variables/at/device with no scope id is refused',
      deviceNoId.status === 400, `status=${deviceNoId.status}`);
    const globalWithId = await call('engineer', 'PUT', '/variables/at/global/7',
      { key: 'lanSubnet', value: '10.0.0.0/8' });
    ok('PUT /variables/at/global/7 is refused (global is identified by the tenant)',
      globalWithId.status === 400, `status=${globalWithId.status}`);
    const setOk = await call('engineer', 'PUT', `/variables/at/device/${DEVICE_BASE}`,
      { key: 'probeVar', value: 'ok' });
    ok('a well-formed write succeeds', setOk.status === 200);
    const readBack = await call('engineer', 'GET', `/variables/at/device/${DEVICE_BASE}`);
    ok('and reads back at that level',
      Object.keys(readBack.json.data as object).includes('probeVar'));
    const del = await call('engineer', 'DELETE', `/variables/at/device/${DEVICE_BASE}?key=probeVar`);
    ok('and can be removed', del.status === 200);
    const proto = await call('engineer', 'PUT', `/variables/at/device/${DEVICE_BASE}`,
      { key: '__proto__', value: 'pwned' });
    ok('a prototype-poisoning key is refused by the API schema',
      proto.status === 400, `status=${proto.status}`);
    const ctorKey = await call('engineer', 'PUT', `/variables/at/device/${DEVICE_BASE}`,
      { key: 'constructor', value: 'pwned' });
    ok('so is `constructor`, which the database CHECK alone would accept',
      ctorKey.status === 400, `status=${ctorKey.status}`);

    section('Plan — compile, then refuse the stale plan');
    const compiled = await call('operator', 'POST', `/plan/devices/${DEVICE_BASE}`,
      { persistRender: false });
    ok('an operator (PLAN_CREATE) can compile a plan',
      compiled.status === 200, `status=${compiled.status} ${JSON.stringify(compiled.json).slice(0, 200)}`);
    const payload = compiled.json.data as {
      plan: { deviceId: number; baseStateHash: string; expiresAt: string; mgmtPathVerdict: string };
      summary: { opCount: number };
      notice: string;
    };
    ok('the response states, in words, that nothing was applied and K2 is M6',
      /indeterminate/.test(payload.plan.mgmtPathVerdict) && /M6/.test(payload.notice));

    const fresh = await call('operator', 'POST', '/plan/validate', { plan: payload.plan });
    ok('POST /plan/validate accepts the plan while the device has not moved',
      fresh.status === 200 && (fresh.json.data as { fresh: boolean }).fresh === true,
      `status=${fresh.status}`);

    const tampered = { ...payload.plan, baseStateHash: 'f'.repeat(64) };
    const stale = await call('operator', 'POST', '/plan/validate', { plan: tampered });
    ok('a plan whose base state no longer matches is REFUSED with 409',
      stale.status === 409, `status=${stale.status}`);
    ok('and the refusal says the configuration changed',
      /STALE/.test(String(stale.json.error ?? '')),
      String(stale.json.error ?? '').slice(0, 120));

    const notAPlan = await call('operator', 'POST', '/plan/validate', { plan: { deviceId: 1 } });
    ok('a malformed plan is a 400, never silently accepted',
      notAPlan.status === 400, `status=${notAPlan.status}`);

    const fleet = await call('operator', 'POST', '/plan/compile', { groupId: 901 });
    ok('POST /plan/compile compiles the whole group',
      fleet.status === 200 &&
      (fleet.json.data as { summary: { compiled: number } }).summary.compiled >= 8,
      JSON.stringify((fleet.json.data as { summary: unknown })?.summary));
    const foreignGroup = await call('otherTenant', 'POST', '/plan/compile', { groupId: 901 });
    ok('another tenant cannot compile a plan for this group',
      foreignGroup.status === 404, `status=${foreignGroup.status}`);

    section('The authoring write path, end to end over HTTP');
    const newTpl = await call('engineer', 'POST', '/templates',
      { name: 'http-authored', brand: 'mikrotik' });
    ok('POST /templates creates a tenant-owned template',
      newTpl.status === 201 && (newTpl.json.data as { isLibrary: boolean }).isLibrary === false,
      `status=${newTpl.status}`);
    const newTplId = (newTpl.json.data as { id: string }).id;

    const newPartial = await call('engineer', 'POST', '/templates/partials',
      { name: 'http/frag.njk' });
    ok('POST /templates/partials creates a partial', newPartial.status === 201);
    const partialId = (newPartial.json.data as { id: string }).id;
    const partialRev = await call('engineer', 'POST', `/templates/partials/${partialId}/revisions`,
      { body: 'add action=accept chain=input comment="obliwan:http-frag"\n' });
    ok('POST /templates/partials/:id/revisions creates a draft', partialRev.status === 201);
    const partialRevId = (partialRev.json.data as { id: string }).id;
    const pubPartial = await call('engineer', 'POST',
      `/templates/partials/revisions/${partialRevId}/publish`, {});
    ok('POST /templates/partials/revisions/:revId/publish freezes it',
      pubPartial.status === 200 &&
      (pubPartial.json.data as { status: string }).status === 'published');

    const draftA = await call('engineer', 'POST', `/templates/${newTplId}/revisions`, {
      body: '/ip firewall filter\n{% include "http/frag.njk" %}\n',
    });
    ok('POST /templates/:id/revisions creates a draft', draftA.status === 201);
    const draftAId = (draftA.json.data as { id: string }).id;
    const patched = await call('engineer', 'PATCH', `/templates/revisions/${draftAId}`, {
      body: '/ip firewall filter\n{% include "http/frag.njk" %}\nadd action=drop chain=input comment="obliwan:tail"\n',
    });
    ok('PATCH /templates/revisions/:revId edits a draft', patched.status === 200);
    const pubA = await call('engineer', 'POST', `/templates/revisions/${draftAId}/publish`, {});
    ok('POST /templates/revisions/:revId/publish pins the partial',
      pubA.status === 200 && (pubA.json.data as { deps: unknown[] }).deps.length === 1,
      `status=${pubA.status}`);
    const patchPublished = await call('engineer', 'PATCH', `/templates/revisions/${draftAId}`,
      { body: 'hijacked\n' });
    ok('editing a PUBLISHED revision is refused with 409, not silently ignored',
      patchPublished.status === 409, `status=${patchPublished.status}`);

    const draftB = await call('engineer', 'POST', `/templates/${newTplId}/revisions`, {
      body: '/ip firewall filter\n{% include "http/frag.njk" %}\nadd action=drop chain=forward comment="obliwan:tail2"\n',
    });
    const draftBId = (draftB.json.data as { id: string }).id;
    await call('engineer', 'POST', `/templates/revisions/${draftBId}/publish`, {});
    const diff = await call('engineer', 'GET',
      `/templates/revisions/${draftAId}/diff/${draftBId}`);
    ok('GET /templates/revisions/:a/diff/:b returns a unified patch and depChanges',
      diff.status === 200 &&
      typeof (diff.json.data as { patch: string }).patch === 'string' &&
      Array.isArray((diff.json.data as { depChanges: unknown[] }).depChanges),
      `status=${diff.status}`);
    ok('the diff reports the body change',
      (diff.json.data as { addedLines: number }).addedLines > 0);

    const quar = await call('engineer', 'POST', `/templates/revisions/${draftBId}/status`,
      { status: 'quarantined', reason: 'http harness' });
    ok('POST /templates/revisions/:revId/status quarantines it', quar.status === 200);

    const assign = await call('engineer', 'POST', '/templates/assignments',
      { scope: 'group', scopeId: 901, templateId: Number(newTplId), priority: 50 });
    ok('POST /templates/assignments creates a group assignment', assign.status === 201,
      `status=${assign.status} ${JSON.stringify(assign.json).slice(0, 140)}`);
    const assignId = (assign.json.data as { id: string }).id;
    const assignPatch = await call('engineer', 'PATCH', `/templates/assignments/${assignId}`,
      { priority: 10, enabled: false });
    ok('PATCH /templates/assignments/:id updates it', assignPatch.status === 200);
    const assignDel = await call('engineer', 'DELETE', `/templates/assignments/${assignId}`);
    ok('DELETE /templates/assignments/:id removes it', assignDel.status === 200);
    const assignForeign = await call('otherTenant', 'POST', '/templates/assignments',
      { scope: 'group', scopeId: 901, templateId: Number(newTplId), priority: 50 });
    ok('another tenant cannot assign a template it cannot see',
      assignForeign.status === 404, `status=${assignForeign.status}`);

    const render = await call('engineer', 'GET', `/templates/devices/${DEVICE_BASE}/render`);
    ok('GET /templates/devices/:id/render serves the last stored render',
      render.status === 200 && render.json.data !== null,
      `status=${render.status}`);

    section('Variables — bulk, group and tenant views');
    const bulk = await call('engineer', 'PUT', `/variables/bulk/device/${DEVICE_BASE}`, {
      entries: [
        { key: 'bulkA', value: 1 },
        { key: 'bulkB', value: 'two' },
      ],
    });
    ok('PUT /variables/bulk/:scope/:scopeId writes several at once', bulk.status === 200);
    const bulkBad = await call('engineer', 'PUT', `/variables/bulk/device/${DEVICE_BASE}`, {
      entries: [{ key: 'bulkC', value: 3 }, { key: '__proto__', value: 4 }],
    });
    ok('one bad entry rejects the WHOLE bulk write', bulkBad.status === 400);
    const afterBulk = await call('engineer', 'GET', `/variables/at/device/${DEVICE_BASE}`);
    ok('and nothing from the rejected batch was written',
      !Object.keys(afterBulk.json.data as object).includes('bulkC'));
    await call('engineer', 'DELETE', `/variables/at/device/${DEVICE_BASE}?key=bulkA`);
    await call('engineer', 'DELETE', `/variables/at/device/${DEVICE_BASE}?key=bulkB`);

    const groupVars = await call('engineer', 'GET', '/variables/groups/901');
    ok('GET /variables/groups/:id separates inherited from overrides',
      groupVars.status === 200 &&
      'inherited' in (groupVars.json.data as object) &&
      'overrides' in (groupVars.json.data as object),
      `status=${groupVars.status}`);
    const tenantVars = await call('engineer', 'GET', '/variables/tenant');
    ok('GET /variables/tenant resolves the tenant level', tenantVars.status === 200);
    const foreignGroupVars = await call('otherTenant', 'GET', '/variables/groups/901');
    ok('another tenant cannot read this group\'s variables',
      foreignGroupVars.status === 404, `status=${foreignGroupVars.status}`);

    const planConfig = await call('operator', 'GET', '/plan/config');
    ok('GET /plan/config states that applying is not possible at this milestone',
      planConfig.status === 200 &&
      (planConfig.json.data as { canApply: boolean }).canApply === false &&
      (planConfig.json.data as { applyMilestone: string }).applyMilestone === 'M6');

    // Leave the tenant as we found it.
    await db('templates').where('id', newTplId).del();
    await db('template_partials').where('id', partialId).del();

    section('Bad input never reaches a service');
    const badId = await call('engineer', 'GET', '/templates/not-a-number');
    ok('a non-numeric template id is a 400', badId.status === 400, `status=${badId.status}`);
    const badDevice = await call('engineer', 'POST', `/templates/revisions/${rev.id}/preview`,
      { deviceId: -1 });
    ok('a negative device id is a 400', badDevice.status === 400);
    const badScope = await call('engineer', 'GET', '/variables/at/planet');
    ok('an unknown variable scope is a 400', badScope.status === 400);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  console.log(`\n================ ${passed} passed, ${failed} failed ================`);
  if (failures.length > 0) console.log('FAILED:\n - ' + failures.join('\n - '));
}

main()
  .then(() => db.destroy())
  .then(() => process.exit(failed === 0 ? 0 : 1))
  .catch(async (err) => {
    console.error(err);
    await db.destroy();
    process.exit(2);
  });
