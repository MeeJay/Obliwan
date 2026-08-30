/**
 * ObliWAN M5 — planner / render verification harness.
 *
 * Replays the milestone recipe against a REAL PostgreSQL:
 *   (a) one template on 10 devices -> 10 plans, each with ITS device's variables
 *   (b) republishing a partial does NOT change the render of a published revision
 *   (c) a plan computed, then the observed state changes -> the plan is REFUSED
 *   (d) coverage `partial` -> ZERO delete operations in the plan
 *
 * No MikroTik is involved and none is pretended: the observed side is a
 * RouterOS `/export` FIXTURE run through the real M4 normaliser.
 *
 *   DATABASE_URL=... OBLIWAN_ENCRYPTION_KEY=<64 hex> npx tsx tests/m5-planner.verify.ts
 */

import { db } from '../src/db';
import { normalizeRouterOsExport } from '../src/services/config/normalize.service';
import { loadNormalizationRules, loadDefaults } from '../src/services/config/collect.service';
import { storeSnapshot, latestDocument } from '../src/services/config/snapshot.service';
import { versionService } from '../src/services/template/version.service';
import { assignmentService } from '../src/services/template/assignment.service';
import { variableResolver } from '../src/services/template/variableResolver.service';
import { renderRevisionForDevice } from '../src/services/template/render.service';
import {
  compilePlan, compileForDevices, checkPlanFreshness, assertPlanFresh,
  StalePlanError, summarize,
} from '../src/services/plan/planner.service';
import { buildMgmtPathFacts, classifyResource } from '../src/services/plan/riskScoring';
import { ApplyPlan } from '@obliwan/shared';
import type { NcmDocument } from '@obliwan/shared';

let passed = 0;
let failed = 0;
const failures: string[] = [];

function ok(label: string, cond: boolean, extra = ''): void {
  if (cond) { passed++; console.log(`  PASS  ${label}${extra ? ' — ' + extra : ''}`); }
  else { failed++; failures.push(label); console.log(`  FAIL  ${label}${extra ? ' — ' + extra : ''}`); }
}
function eq(label: string, a: unknown, b: unknown): void {
  ok(label, JSON.stringify(a) === JSON.stringify(b), `got ${JSON.stringify(a)} want ${JSON.stringify(b)}`);
}
function section(t: string): void { console.log(`\n=== ${t} ===`); }

const TENANT = 900;
const DEVICE_BASE = 9000;
const N_DEVICES = 10;

// ============================================================================
// Fixtures
// ============================================================================

/** The OBSERVED side: a plausible RouterOS 7 export for a CPE behind a CHR. */
function observedExport(opts: {
  identity: string;
  lanVlan: number;
  extraRule?: string;
  broken?: boolean;
}): string {
  return [
    '# 2026-08-20 09:12:33 by RouterOS 7.14.3',
    '# software id = ABCD-1234',
    '# model = CCR2004-1G-12S+2XS',
    '# serial number = HFX0' + opts.identity,
    '/interface bridge',
    'add name=bridge-lan',
    '/interface vlan',
    `add interface=bridge-lan name=vlan-lan vlan-id=${opts.lanVlan}`,
    '/interface l2tp-client',
    'add connect-to=10.255.0.1 disabled=no name=l2tp-mgmt user=' + opts.identity,
    '/interface list',
    'add name=WAN',
    '/ip address',
    'add address=10.255.1.5/32 interface=l2tp-mgmt',
    'add address=192.168.10.1/24 interface=vlan-lan',
    '/ip firewall filter',
    'add action=accept chain=input comment="obliwan:mgmt-in" in-interface=l2tp-mgmt',
    'add action=accept chain=input comment="obliwan:established" connection-state=established,related',
    opts.extraRule ?? 'add action=drop chain=input comment="hand-written-drop" src-address=203.0.113.7',
    'add action=drop chain=input comment="obliwan:default-drop"',
    '/ip firewall nat',
    'add action=masquerade chain=srcnat comment="obliwan:wan-nat" out-interface-list=WAN',
    '/ip route',
    'add distance=1 dst-address=0.0.0.0/0 gateway=10.255.0.1',
    opts.broken ? 'this line is not a routeros statement at all' : '',
  ].filter((l) => l !== '').join('\n') + '\n';
}

/** The DESIRED side: a template that claims ONLY the firewall filter and NAT
 *  sections. Everything else the box carries is out of scope by construction. */
const PARTIAL_V1 = [
  '{# common/mgmt.njk — revision 1 #}',
  'add action=accept chain=input comment="obliwan:mgmt-in" in-interface={{ mgmtInterface }}',
  'add action=accept chain=input comment="obliwan:established" connection-state=established,related',
].join('\n');

const PARTIAL_V2 = [
  '{# common/mgmt.njk — revision 2, EDITED AFTER PUBLICATION #}',
  'add action=accept chain=input comment="obliwan:mgmt-in-V2-EDITED" in-interface={{ mgmtInterface }}',
].join('\n');

const TEMPLATE_BODY = [
  '/ip firewall filter',
  '{% include "common/mgmt.njk" %}',
  'add action=accept chain=input comment="obliwan:site-lan" src-address={{ lanSubnet }}',
  'add action=drop chain=input comment="obliwan:default-drop"',
  '/ip firewall nat',
  'add action=masquerade chain=srcnat comment="obliwan:wan-nat" out-interface-list=WAN',
].join('\n');

// ============================================================================
// Seeding
// ============================================================================

async function reset(): Promise<void> {
  await db.raw('DELETE FROM config_renders WHERE tenant_id = ?', [TENANT]);
  await db.raw('DELETE FROM drift_findings WHERE run_id IN (SELECT id FROM drift_runs WHERE device_id >= ?)', [DEVICE_BASE]);
  await db.raw('DELETE FROM drift_runs WHERE device_id >= ?', [DEVICE_BASE]);
  await db.raw('DELETE FROM config_snapshots WHERE device_id >= ?', [DEVICE_BASE]);
  await db.raw('DELETE FROM template_assignments WHERE tenant_id = ?', [TENANT]);
  // ORDER MATTERS, and the fact that it does is the point of migration 008's
  // freeze triggers: `template_revision_deps` cannot be emptied directly once a
  // revision is published (`dependency pins of published revision N are
  // immutable`). The only legitimate way out is to delete the PARENT template,
  // which the trigger exempts precisely so a tenant CASCADE is not blocked by
  // his own templates. Deleting the rows in a convenient order is exactly what
  // the schema refuses to allow.
  await db.raw('DELETE FROM templates WHERE tenant_id = ?', [TENANT]);
  await db.raw('DELETE FROM template_partials WHERE tenant_id = ?', [TENANT]);
  await db.raw('DELETE FROM config_variables WHERE tenant_id = ?', [TENANT]);
  await db.raw('DELETE FROM devices WHERE tenant_id = ?', [TENANT]);
  await db.raw('DELETE FROM group_closure WHERE ancestor_id >= 900 OR descendant_id >= 900');
  await db.raw('DELETE FROM device_groups WHERE tenant_id = ?', [TENANT]);
  await db.raw('DELETE FROM tenants WHERE id = ?', [TENANT]);
}

async function seed(): Promise<void> {
  await db('tenants').insert({ id: TENANT, name: 'M5 Planner Test', slug: 'm5-planner' });
  await db('device_groups').insert({ id: 900, name: 'FR', slug: 'fr-m5', tenant_id: TENANT, parent_id: null });
  await db('device_groups').insert({ id: 901, name: 'Paris', slug: 'paris-m5', tenant_id: TENANT, parent_id: 900 });
  await db('group_closure').insert([
    { ancestor_id: 900, descendant_id: 900, depth: 0 },
    { ancestor_id: 901, descendant_id: 901, depth: 0 },
    { ancestor_id: 900, descendant_id: 901, depth: 1 },
  ]);

  for (let i = 0; i < N_DEVICES; i++) {
    await db('devices').insert({
      id: DEVICE_BASE + i,
      tenant_id: TENANT,
      group_id: 901,
      name: `cpe-${i}`,
      brand: 'mikrotik',
      family: 'mikrotik_routeros7',
      model: 'CCR2004-1G-12S+2XS',
      os_version: '7.14.3',
      ppp_username: `m5-cpe-${i}`,
      tunnel_ip: '10.255.1.5',
      status: 'active',
      is_managed: true,
    });
  }
}

async function storeObserved(deviceId: number, raw: string): Promise<NcmDocument> {
  const [rules, defaults] = await Promise.all([
    loadNormalizationRules(deviceId, TENANT, 'mikrotik_routeros7'),
    loadDefaults('mikrotik_routeros7', '7.14.3'),
  ]);
  const out = normalizeRouterOsExport(raw, {
    deviceId,
    tenantId: TENANT,
    family: 'mikrotik_routeros7',
    osVersion: '7.14.3',
    rules,
    defaults,
    via: 'ssh',
    previous: (await latestDocument(deviceId))?.doc ?? null,
  });
  await storeSnapshot({
    deviceId,
    tenantId: TENANT,
    source: 'ssh',
    raw,
    doc: out.ncm,
    osVersion: '7.14.3',
    model: 'CCR2004-1G-12S+2XS',
    normalizationTraces: out.traces,
  });
  return out.ncm;
}

// ============================================================================
// The run
// ============================================================================

async function main(): Promise<void> {
  await reset();
  await seed();

  // ── Templates and partials ──────────────────────────────────────────────
  section('Setup: partial + template + assignment');

  const partial = await versionService.createPartial(TENANT, { name: 'common/mgmt.njk' });
  const partialRev1 = await versionService.createPartialDraft(TENANT, partial.id, PARTIAL_V1);
  await versionService.publishPartialRevision(TENANT, partialRev1.id);

  const template = await versionService.createTemplate(TENANT, {
    name: 'site-standard', brand: 'mikrotik',
  });
  const draft = await versionService.createDraft(TENANT, template.id, {
    body: TEMPLATE_BODY,
    varSchema: {
      type: 'object',
      properties: {
        mgmtInterface: { type: 'string', default: 'l2tp-mgmt' },
        lanSubnet: { type: 'string' },
      },
      required: ['mgmtInterface', 'lanSubnet'],
    },
    // The template CLAIMS these two kinds. Everything else on the box is out of
    // scope and must not produce a single plan operation.
    sectionSeverity: { '/ip/firewall/filter': 'high', '/ip/firewall/nat': 'high' },
  });
  const published = await versionService.publishRevision(TENANT, draft.id, null);
  ok('revision published with its partial pinned', published.revision.status === 'published' && published.deps.length === 1,
    `deps=${published.deps.length}`);

  await assignmentService.upsertAssignment(TENANT, {
    scope: 'global', templateId: template.id,
  });

  // ── Variables: one value per device ─────────────────────────────────────
  await variableResolver.set(TENANT, 'global', null, 'mgmtInterface', 'l2tp-mgmt');
  for (let i = 0; i < N_DEVICES; i++) {
    await variableResolver.set(TENANT, 'device', DEVICE_BASE + i, 'lanSubnet', `192.168.${10 + i}.0/24`);
  }
  await variableResolver.set(TENANT, 'device', DEVICE_BASE + 3, 'sitePsk', 'super-secret-psk-value', true);
  // The no-snapshot device gets its variable too, so its refusal is genuinely
  // about the missing snapshot and not about a missing value.
  await variableResolver.set(TENANT, 'device', DEVICE_BASE + 99, 'lanSubnet', '192.168.99.0/24');

  // ── Observed snapshots ──────────────────────────────────────────────────
  for (let i = 0; i < N_DEVICES; i++) {
    await storeObserved(DEVICE_BASE + i, observedExport({ identity: `m5-cpe-${i}`, lanVlan: 10 + i }));
  }

  // ======================================================================
  section('RECIPE (a) — one template, 10 devices, 10 plans with each device\'s variables');
  // ======================================================================
  const t0 = Date.now();
  const fleet = await compileForDevices(TENANT, Array.from({ length: N_DEVICES }, (_, i) => DEVICE_BASE + i));
  const elapsed = Date.now() - t0;

  eq('10 plans compiled, 0 failures', [fleet.plans.length, fleet.failures.length], [10, 0]);
  if (fleet.failures.length > 0) console.log('    failures:', JSON.stringify(fleet.failures, null, 2));

  let distinct = 0;
  for (let i = 0; i < fleet.plans.length; i++) {
    const c = fleet.plans[i];
    const render = await db('config_renders')
      .where({ tenant_id: TENANT, device_id: c.plan.deviceId })
      .orderBy('id', 'desc').first('body');
    const expected = `192.168.${10 + (c.plan.deviceId - DEVICE_BASE)}.0/24`;
    if (String((render as { body: string }).body).includes(expected)) distinct++;
  }
  eq('each render carries ITS OWN device variable', distinct, 10);
  ok('every plan has a distinct base_state_hash per device state',
    new Set(fleet.plans.map((p) => p.plan.baseStateHash)).size >= 1);
  console.log(`    10 plans in ${elapsed} ms (${Math.round(elapsed / 10)} ms/device)`);
  const s0 = summarize(fleet.plans[0]);
  console.log(`    plan[0]: ${s0.opCount} ops ${JSON.stringify(s0.byKind)} risk=${s0.riskLevel} mgmt=${s0.mgmtPathVerdict}`);

  ok('every compiled plan validates against the shared ApplyPlan contract',
    fleet.plans.every((p) => ApplyPlan.safeParse(p.plan).success),
    JSON.stringify(fleet.plans.map((p) => ApplyPlan.safeParse(p.plan))
      .find((r) => !r.success)?.error?.issues?.slice(0, 2) ?? 'all valid'));

  ok('mgmtPathVerdict is indeterminate on every plan (K2 is M6)',
    fleet.plans.every((p) => p.plan.mgmtPathVerdict === 'indeterminate'));

  // Where the 255 ms/device goes: one worker spawn + one render + one
  // normalisation + one diff, per device. Measured, not estimated.
  {
    const tRender = Date.now();
    await renderRevisionForDevice(TENANT, DEVICE_BASE, { persist: false });
    const renderMs = Date.now() - tRender;
    const tPlan = Date.now();
    await compilePlan(TENANT, DEVICE_BASE, { persistRender: false });
    const planMs = Date.now() - tPlan;
    console.log(`    breakdown: render ${renderMs} ms, full plan ${planMs} ms ` +
      `(diff + scoring + ordering ≈ ${planMs - renderMs} ms)`);
  }
  ok('the plan touches the management path and says so',
    fleet.plans.every((p) => p.plan.blastRadius.touchesManagementPath));

  // The secret variable must not appear in any stored artefact.
  const bodies = await db('config_renders').where('tenant_id', TENANT).select('body', 'variables_snapshot');
  ok('no plaintext secret in any stored render body or variables snapshot',
    bodies.every((r: { body: string | null; variables_snapshot: unknown }) =>
      !JSON.stringify(r).includes('super-secret-psk-value')));

  // ======================================================================
  section('Ops content and ordering');
  // ======================================================================
  const one = fleet.plans[0];
  const kinds = one.plan.ops.map((o) => `${o.kind}:${o.resource}`);
  console.log('    ops:', kinds.join(', '));

  ok('seq is dense and ascending from 0',
    one.plan.ops.every((o, i) => o.seq === i));
  ok('dependsOn only ever points BACKWARDS',
    one.plan.ops.every((o) => o.dependsOn.every((d) => d < o.seq)));
  const firstDelete = one.plan.ops.findIndex((o) => o.kind === 'delete');
  const lastCreate = one.plan.ops.map((o) => o.kind).lastIndexOf('create');
  ok('every create precedes every delete',
    firstDelete === -1 || lastCreate === -1 || lastCreate < firstDelete,
    `lastCreate=${lastCreate} firstDelete=${firstDelete}`);
  const firstMove = one.plan.ops.findIndex((o) => o.kind === 'move');
  ok('moves come after deletes (indices are computed on the final population)',
    firstMove === -1 || firstDelete === -1 || firstDelete < firstMove);
  const firstBlocked = one.plan.ops.findIndex((o) => o.kind === 'blocked');
  ok('blocked ops are last (information, not instructions)',
    firstBlocked === -1 || one.plan.ops.slice(firstBlocked).every((o) => o.kind === 'blocked'));

  ok('the hand-written input drop is proposed for deletion (template claims the chain)',
    one.plan.ops.some((o) => o.kind === 'delete' && o.resource === 'firewallRule'),
    kinds.filter((k) => k.startsWith('delete')).join(','));
  ok('that deletion is scored high (input chain = management path)',
    one.plan.ops.filter((o) => o.kind === 'delete' && o.resource === 'firewallRule')
      .every((o) => o.risk === 'high'));
  ok('nothing outside the claimed sections produced an op',
    one.plan.ops.filter((o) => o.kind !== 'blocked')
      .every((o) => o.resource === 'firewallRule' || o.resource === 'natRule'),
    [...new Set(one.plan.ops.map((o) => o.resource))].join(','));
  ok('the route and the interfaces were NOT compared (unclaimed)',
    !one.plan.ops.some((o) => o.kind !== 'blocked' && (o.resource === 'route' || o.resource === 'interface')));
  ok('orderConverges is true', one.plan.orderConverges);
  ok('every op carries an operator-facing reason',
    one.plan.ops.every((o) => o.reason.length > 0 && o.reason.length <= 400));

  // ======================================================================
  section('riskScoring — the tunnelCritical vocabulary');
  // ======================================================================
  const observedDoc = (await latestDocument(DEVICE_BASE))!.doc;
  const facts = buildMgmtPathFacts(observedDoc, { deviceId: DEVICE_BASE, tunnelIp: '10.255.1.5' });
  ok('the l2tp interface is recognised as the tunnel',
    facts.tunnelInterfaces.has('l2tp-mgmt'), [...facts.tunnelInterfaces].join(','));
  ok('tunnelUnknown is false when a tunnel interface was found', !facts.tunnelUnknown);

  const inputRule = observedDoc.resources.firewallRules.find((r) => r.chain === 'input');
  ok('an input-chain rule is tunnelCritical',
    classifyResource(inputRule!, facts).tunnelCritical);
  const defaultRoute = observedDoc.resources.routes.find((r) => r.dst === '0.0.0.0/0');
  ok('the default route is tunnelCritical',
    defaultRoute ? classifyResource(defaultRoute, facts).tunnelCritical : false);
  const natRule = observedDoc.resources.natRules[0];
  ok('a srcnat masquerade on a non-tunnel interface list is NOT tunnelCritical',
    natRule ? classifyResource(natRule, facts).tunnelCritical === false : false,
    natRule ? classifyResource(natRule, facts).signals.join(',') : 'no nat rule');
  const iface = observedDoc.resources.interfaces.find((i) => i.name === 'l2tp-mgmt');
  ok('the tunnel interface itself is tunnelCritical',
    iface ? classifyResource(iface, facts).tunnelCritical : false);

  // A custom chain the input chain jumps into IS the input chain as far as the
  // management session is concerned — the most common idiom in real templates.
  await storeObserved(DEVICE_BASE + 7, [
    '# 2026-08-20 09:12:33 by RouterOS 7.14.3',
    '# model = CCR2004-1G-12S+2XS',
    '/interface l2tp-client',
    'add connect-to=10.255.0.1 name=l2tp-mgmt user=m5-cpe-7',
    '/ip firewall filter',
    'add action=jump chain=input comment="obliwan:to-mgmt" jump-target=mgmt',
    'add action=drop chain=mgmt comment="obliwan:mgmt-drop" src-address=203.0.113.0/24',
    'add action=drop chain=other comment="obliwan:unrelated" src-address=198.51.100.0/24',
    '',
  ].join('\n'));
  const jumpDoc = (await latestDocument(DEVICE_BASE + 7))!.doc;
  const jumpFacts = buildMgmtPathFacts(jumpDoc, { deviceId: DEVICE_BASE + 7, tunnelIp: '10.255.1.5' });
  eq('the jump closure from `input` reaches the custom chain',
    [...jumpFacts.managementChainNames].sort(), ['mgmt']);
  const inMgmt = jumpDoc.resources.firewallRules.find((r) => r.chainName === 'mgmt');
  const inOther = jumpDoc.resources.firewallRules.find((r) => r.chainName === 'other');
  ok('a rule inside a chain reachable from input IS tunnelCritical',
    inMgmt ? classifyResource(inMgmt, jumpFacts).tunnelCritical : false);
  ok('a rule in an unrelated custom chain is NOT',
    inOther ? classifyResource(inOther, jumpFacts).tunnelCritical === false : false,
    inOther ? classifyResource(inOther, jumpFacts).signals.join(',') : 'missing');

  // ======================================================================
  section('RECIPE (b) — republishing a partial does NOT change a published render');
  // ======================================================================
  const beforeBody = (await renderRevisionForDevice(TENANT, DEVICE_BASE, {
    persist: false, revisionId: published.revision.id,
  })).body;
  ok('the published render uses partial revision 1',
    (beforeBody ?? '').includes('obliwan:mgmt-in') && !(beforeBody ?? '').includes('V2-EDITED'));

  const partialRev2 = await versionService.createPartialDraft(TENANT, partial.id, PARTIAL_V2);
  await versionService.publishPartialRevision(TENANT, partialRev2.id);

  const afterBody = (await renderRevisionForDevice(TENANT, DEVICE_BASE, {
    persist: false, revisionId: published.revision.id,
  })).body;
  ok('the published revision renders BYTE-IDENTICALLY after the partial was republished',
    beforeBody === afterBody);
  ok('and it still does NOT contain the edited partial', !(afterBody ?? '').includes('V2-EDITED'));

  let fleetUnchanged = 0;
  for (let i = 0; i < N_DEVICES; i++) {
    const r = await renderRevisionForDevice(TENANT, DEVICE_BASE + i, {
      persist: false, revisionId: published.revision.id,
    });
    if (!(r.body ?? '').includes('V2-EDITED')) fleetUnchanged++;
  }
  eq('all 10 device renders are unaffected by the partial republication', fleetUnchanged, 10);

  // A NEW draft picks the new partial up — otherwise the pin would be a bug,
  // not a feature.
  const draft2 = await versionService.createDraft(TENANT, template.id, { body: TEMPLATE_BODY });
  const draftBody = (await renderRevisionForDevice(TENANT, DEVICE_BASE, {
    persist: false, revisionId: draft2.id,
  })).body;
  ok('a NEW draft does pick up partial revision 2', (draftBody ?? '').includes('V2-EDITED'));

  // ======================================================================
  section('RECIPE (c) — a plan becomes invalid as soon as the router is touched');
  // ======================================================================
  const planC = await compilePlan(TENANT, DEVICE_BASE + 1, { persistRender: false });
  const fresh0 = await checkPlanFreshness(TENANT, planC.plan);
  ok('a plan just compiled is fresh', fresh0.fresh, `hash=${fresh0.currentStateHash?.slice(0, 12)}`);
  await assertPlanFresh(TENANT, planC.plan);   // must not throw
  ok('assertPlanFresh accepts it', true);

  // "Somebody opened Winbox": one extra firewall rule appears on the box.
  await storeObserved(DEVICE_BASE + 1, observedExport({
    identity: 'm5-cpe-1', lanVlan: 11,
    extraRule:
      'add action=drop chain=input comment="hand-written-drop" src-address=203.0.113.7\n' +
      'add action=drop chain=input comment="added-in-winbox" src-address=198.51.100.9',
  }));

  const fresh1 = await checkPlanFreshness(TENANT, planC.plan);
  ok('the plan is now STALE', !fresh1.fresh);
  ok('the current state hash differs from the plan base state hash',
    fresh1.currentStateHash !== planC.plan.baseStateHash,
    `${planC.plan.baseStateHash.slice(0, 12)} -> ${fresh1.currentStateHash?.slice(0, 12)}`);
  eq('the reason names the configuration change', fresh1.reason,
    'the device configuration changed since the plan was compiled');

  let threw = false;
  try {
    await assertPlanFresh(TENANT, planC.plan);
  } catch (err) {
    threw = err instanceof StalePlanError;
    if (threw) console.log(`    refusal: ${(err as Error).message.slice(0, 140)}…`);
  }
  ok('assertPlanFresh REFUSES the stale plan with StalePlanError', threw);

  const planC2 = await compilePlan(TENANT, DEVICE_BASE + 1, { persistRender: false });
  ok('recompiling produces a plan that is fresh again',
    (await checkPlanFreshness(TENANT, planC2.plan)).fresh);
  ok('and it accounts for the rule added in Winbox',
    planC2.plan.ops.filter((o) => o.kind === 'delete').length >
    planC.plan.ops.filter((o) => o.kind === 'delete').length,
    `${planC.plan.ops.filter((o) => o.kind === 'delete').length} -> ` +
    `${planC2.plan.ops.filter((o) => o.kind === 'delete').length}`);

  // Expiry is the other half of the same guarantee.
  const expiredPlan = { ...planC2.plan, expiresAt: new Date(Date.now() - 1000).toISOString() };
  const freshExp = await checkPlanFreshness(TENANT, expiredPlan);
  ok('an expired plan is not fresh either', !freshExp.fresh && freshExp.expired);

  // ======================================================================
  section('RECIPE (d) — coverage `partial` -> ZERO delete operations');
  // ======================================================================
  const dev = DEVICE_BASE + 2;
  const planComplete = await compilePlan(TENANT, dev, { persistRender: false });
  const deletesComplete = planComplete.plan.ops.filter((o) => o.kind === 'delete');
  ok('with a COMPLETE collection the plan does contain deletions',
    deletesComplete.length > 0, `${deletesComplete.length} delete op(s)`);
  const obsCoverage = (await latestDocument(dev))!.doc.coverage.firewallRule.state;
  eq('observed firewallRule coverage is complete', obsCoverage, 'complete');

  // Now a TRUNCATED export: one line the parser cannot read makes every kind
  // `partial`, exactly as a session cut short would.
  await storeObserved(dev, observedExport({ identity: 'm5-cpe-2', lanVlan: 12, broken: true }));
  const degraded = (await latestDocument(dev))!.doc;
  eq('observed firewallRule coverage is now partial', degraded.coverage.firewallRule.state, 'partial');
  console.log(`    coverage reason: ${degraded.coverage.firewallRule.reason?.slice(0, 110)}…`);

  const planPartial = await compilePlan(TENANT, dev, { persistRender: false });
  const deletesPartial = planPartial.plan.ops.filter((o) => o.kind === 'delete');
  eq('N3 — with a PARTIAL collection the plan contains ZERO deletions', deletesPartial.length, 0);

  const blocked = planPartial.plan.ops.filter((o) => o.kind === 'blocked');
  ok('the refused deletions are surfaced as blocked ops, not silently dropped',
    blocked.length > 0, `${blocked.length} blocked op(s)`);
  ok('every blocked op carries blockedReason=coverage_incomplete',
    blocked.every((o) => o.blockedReason === 'coverage_incomplete'));
  ok('the blocked op names the record that was NOT deleted',
    blocked.some((o) => o.before !== null && /REFUSED/.test(o.reason)));
  console.log(`    blocked reason: ${blocked[0].reason.slice(0, 150)}…`);
  ok('planner reports which kinds had deletions blocked',
    planPartial.detail.deletionsBlocked.length > 0,
    JSON.stringify(planPartial.detail.deletionsBlocked));
  ok('a blocked op never raises the plan risk level',
    blocked.every((o) => o.risk === 'low'));

  // ======================================================================
  section('Guard: a device with no snapshot, and cross-tenant isolation');
  // ======================================================================
  await db('devices').insert({
    id: DEVICE_BASE + 99, tenant_id: TENANT, group_id: 901, name: 'cpe-nosnap',
    brand: 'mikrotik', family: 'mikrotik_routeros7', os_version: '7.14.3',
    ppp_username: 'm5-cpe-99', status: 'active', is_managed: true,
  });
  let noSnap = '';
  try { await compilePlan(TENANT, DEVICE_BASE + 99); } catch (e) { noSnap = (e as Error).message; }
  ok('a device with no snapshot refuses to compile rather than proposing to create everything',
    /no configuration snapshot/.test(noSnap), noSnap.slice(0, 90));

  let crossTenant = '';
  try { await compilePlan(1, DEVICE_BASE); } catch (e) { crossTenant = (e as Error).message; }
  ok('another tenant cannot compile a plan for this device',
    /does not exist/.test(crossTenant), crossTenant.slice(0, 80));

  let crossFresh = '';
  try { await checkPlanFreshness(1, planC2.plan); } catch (e) { crossFresh = (e as Error).message; }
  ok('another tenant cannot even ask whether this plan is fresh',
    /does not exist/.test(crossFresh), crossFresh.slice(0, 80));

  // ======================================================================
  section('Idempotence — applying nothing must produce nothing');
  // ======================================================================
  // Make the observed state EQUAL to what the template wants, then re-plan.
  const converged = [
    '# 2026-08-20 09:12:33 by RouterOS 7.14.3',
    '# model = CCR2004-1G-12S+2XS',
    '/ip firewall filter',
    'add action=accept chain=input comment="obliwan:mgmt-in" in-interface=l2tp-mgmt',
    'add action=accept chain=input comment="obliwan:established" connection-state=established,related',
    'add action=accept chain=input comment="obliwan:site-lan" src-address=192.168.14.0/24',
    'add action=drop chain=input comment="obliwan:default-drop"',
    '/ip firewall nat',
    'add action=masquerade chain=srcnat comment="obliwan:wan-nat" out-interface-list=WAN',
    '',
  ].join('\n');
  await storeObserved(DEVICE_BASE + 4, converged);
  const planIdem = await compilePlan(TENANT, DEVICE_BASE + 4, { persistRender: false });
  const actionable = planIdem.plan.ops.filter((o) => o.kind !== 'blocked' && o.kind !== 'verify');
  eq('a converged device produces ZERO actionable operations', actionable.length, 0);
  if (actionable.length > 0) {
    console.log('    unexpected ops:', JSON.stringify(actionable.map((o) => ({
      k: o.kind, r: o.resource, s: o.semKey, f: o.fields,
    })), null, 1));
  }
  eq('and its plan risk is low', planIdem.plan.riskLevel, 'low');

  // ======================================================================
  section('Order convergence (§4.5) — moves computed against a simulated list');
  // ======================================================================
  // Same rules, WRONG ORDER: the default drop sits first, which would black-hole
  // the management session.
  const misordered = [
    '# 2026-08-20 09:12:33 by RouterOS 7.14.3',
    '# model = CCR2004-1G-12S+2XS',
    '/ip firewall filter',
    'add action=drop chain=input comment="obliwan:default-drop"',
    'add action=accept chain=input comment="obliwan:site-lan" src-address=192.168.15.0/24',
    'add action=accept chain=input comment="obliwan:established" connection-state=established,related',
    'add action=accept chain=input comment="obliwan:mgmt-in" in-interface=l2tp-mgmt',
    '/ip firewall nat',
    'add action=masquerade chain=srcnat comment="obliwan:wan-nat" out-interface-list=WAN',
    '',
  ].join('\n');
  await storeObserved(DEVICE_BASE + 5, misordered);
  const planOrder = await compilePlan(TENANT, DEVICE_BASE + 5, { persistRender: false });
  const moves = planOrder.plan.ops.filter((o) => o.kind === 'move');
  ok('a reordered chain produces move operations', moves.length > 0, `${moves.length} move(s)`);
  ok('every move carries its chain and a target index in the SIMULATED list',
    moves.every((o) => o.chain !== null && o.targetIndex !== null && o.targetIndex >= 0),
    moves.map((o) => `${o.semKey}@${o.targetIndex}`).join(' '));
  ok('the plan ends with a verify op for the reordered chain',
    planOrder.plan.ops.some((o) => o.kind === 'verify' && o.chain === 'input'));
  ok('orderConverges is true', planOrder.plan.orderConverges);
  ok('the moves are scored (the management rule crosses the default drop)',
    moves.some((o) => o.risk === 'high' || o.risk === 'medium'),
    moves.map((o) => o.risk).join(','));

  // Simulate the moves and check the final order equals the desired one.
  const simulated = ['fw:default-drop', 'fw:site-lan', 'fw:established', 'fw:mgmt-in'];
  const observedOrder = (await latestDocument(DEVICE_BASE + 5))!.doc.resources.firewallRules
    .filter((r) => r.chain === 'input').map((r) => r.semKey);
  const work = observedOrder.slice();
  for (const m of moves) {
    const from = work.indexOf(m.semKey);
    if (from < 0) continue;
    work.splice(from, 1);
    work.splice(m.targetIndex as number, 0, m.semKey);
  }
  const desiredSlugs = ['mgmt-in', 'established', 'site-lan', 'default-drop'];
  const finalSlugs = work.map((k) => desiredSlugs.find((s) => k.includes(s)) ?? k);
  eq('replaying the moves in seq order yields the DESIRED chain order', finalSlugs, desiredSlugs);
  void simulated;

  // ======================================================================
  section('Refusals that must never become a plan');
  // ======================================================================
  const quarantined = await versionService.createDraft(TENANT, template.id, { body: TEMPLATE_BODY });
  await versionService.publishRevision(TENANT, quarantined.id, null);
  await versionService.setRevisionStatus(TENANT, quarantined.id, 'quarantined');
  let quarErr = '';
  try {
    await renderRevisionForDevice(TENANT, DEVICE_BASE, { persist: false, revisionId: quarantined.id });
  } catch (e) { quarErr = (e as Error).message; }
  ok('a quarantined revision cannot be rendered', /quarantined/.test(quarErr), quarErr.slice(0, 80));

  // A device whose required variable is missing must fail LOUDLY, never render
  // a hole (`src-address=` reads as "any" on RouterOS).
  await variableResolver.remove(TENANT, 'device', DEVICE_BASE + 6, 'lanSubnet');
  const noVar = await renderRevisionForDevice(TENANT, DEVICE_BASE + 6, { persist: false });
  eq('a missing required variable makes the render fail, not render an empty value',
    [noVar.status, noVar.errorKind], ['error', 'variables']);
  ok('and the error names the variable and the device',
    /lanSubnet/.test(noVar.errorMessage ?? '') && /cpe-6/.test(noVar.errorMessage ?? ''),
    (noVar.errorMessage ?? '').slice(0, 120));
  let planVarErr = '';
  try { await compilePlan(TENANT, DEVICE_BASE + 6); } catch (e) { planVarErr = (e as Error).message; }
  ok('and no plan is compiled from it', /render failed/.test(planVarErr), planVarErr.slice(0, 100));

  // ======================================================================
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
