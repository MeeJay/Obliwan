/**
 * ObliWAN M12 — fleet take-over (K8), verified against a real PostgreSQL.
 *
 * WHAT THIS FILE PROVES, AND WHAT IT CANNOT
 *
 * It proves the MINER: the fact algebra, the cross-site alignment that turns a
 * disagreement into a variable, the weighted-Jaccard hierarchical clustering in
 * a worker, the stopping rule, the coverage arithmetic, the deviation
 * classification and the two conformance scores. It runs the REAL service
 * against the REAL schema of migration 017 — the CHECK constraints, the partial
 * indexes and the composite foreign keys are all live, and several assertions
 * below exist only to make the database refuse something.
 *
 * It proves NOTHING about MikroTik. There is no router on this machine and
 * there never was one on this project: no CHR, no RB5009, no Vigor, no Zyxel,
 * no SonicWall. The fifty configurations in `fixtures.ts` were written by me,
 * by hand, in the NCM shape the M4 collector produces. "Fifty heterogeneous
 * configurations produced three clusters and 94 % coverage" is a strong
 * statement about this miner and says nothing whatsoever about whether a real
 * `/export` parses into those documents.
 *
 * ARCHITECTURE.md §5/M12 states the acceptance criterion, and it is checked
 * here verbatim: import of 50 heterogeneous configs -> at most 4 proposed
 * clusters, at least 80 % of the lines covered by the deduced template, every
 * deviation listed and classifiable.
 *
 *   DATABASE_URL=… npx tsx src/services/baseline/testing/m12-baseline.verify.ts
 */

import { ncmHash, type NcmDocument } from '@obliwan/shared';
import {
  BASELINE_FORBIDDEN_ATTRIBUTES, isForbiddenBaselineAttribute, slotIsForbidden,
  weightedJaccard,
} from '@obliwan/shared/dist/baseline';
import { db } from '../../../db';
import { AppError } from '../../../middleware/errorHandler';
import { extractFacts } from '../facts';
import { agglomerate, similarityMatrix, slotWeight } from '../clusterWorker';
import { clusterSlotSets } from '../cluster';
import {
  BASELINE_MAX_FLEET, FLEET_SNAPSHOT_BATCH,
  classifyDeviation, deleteException, getCluster, getConformance, getDraft, getRun,
  listDeviations,
  listExceptions, promoteDraft, runBaseline,
  type BaselineDeviationDetail, type BaselineRunOutcome,
} from '../miner.service';
import { fleetSpecs, siteDoc, type SiteSpec } from './fixtures';

const TENANT = 1;

/**
 * The regex migration 023 puts on `baseline_slots.slot`, `baseline_exceptions
 * .slot` and `baseline_deviations.slot`, copied here VERBATIM.
 *
 * Copied on purpose rather than imported: the point of the assertion that uses
 * it is that the SQL text and `slotIsForbidden` decide the same way, and a test
 * that imported the constant from the migration could only ever prove the
 * migration agrees with itself. If someone edits the migration and not this
 * line, the probe below stops matching the live constraint and the two
 * `refuses()` cases above it fail — which is the alarm.
 */
const SECRET_SLOT_RE_023 =
  '/([^/]*(password|passphrase|secret|psk|credential|apikey|privatekey|fingerprint)[^/]*' +
  '|presharedkey|community)$';

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
    failures.push(label + (extra ? ` — ${extra}` : ''));
    console.log(`  FAIL  ${label}${extra ? ' — ' + extra : ''}`);
  }
}

async function refuses(label: string, fn: () => Promise<unknown>, needle: string): Promise<void> {
  try {
    await fn();
    ok(label, false, 'it was accepted');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    ok(label, message.toLowerCase().includes(needle.toLowerCase()), message.slice(0, 160));
  }
}

// ============================================================================
// Seeding
// ============================================================================

const deviceIdBySite = new Map<number, number>();
let operatorId: number | null = null;

async function reset(): Promise<void> {
  await db.raw(
    'TRUNCATE baseline_drafts, baseline_conformance, baseline_deviations, ' +
      'baseline_exceptions, baseline_slots, baseline_cluster_members, ' +
      'baseline_clusters, baseline_runs RESTART IDENTITY CASCADE',
  );
  await db('template_revisions').del();
  await db('templates').del();
  await db('config_snapshots').del();
  await db('devices').del();
  await db('sites').del();
  deviceIdBySite.clear();
}

async function seedFleet(specs: SiteSpec[]): Promise<void> {
  await db('tenants').insert({ id: TENANT, name: 'Default', slug: 'default' })
    .onConflict('id').ignore();

  const existing = await db('users').where({ username: 'm12-operator' }).first<{ id: number }>('id');
  if (existing) operatorId = Number(existing.id);
  else {
    const [row] = await db('users')
      .insert({ username: 'm12-operator', display_name: 'm12-operator', role: 'user' })
      .returning<{ id: number }[]>('id');
    operatorId = Number(row.id);
  }

  for (const spec of specs) {
    const [site] = await db('sites')
      .insert({
        tenant_id: TENANT,
        code: spec.name.toUpperCase(),
        name: `Site ${spec.index}`,
        timezone: 'Europe/Paris',
      })
      .returning<{ id: number }[]>('id');

    const [dev] = await db('devices')
      .insert({
        tenant_id: TENANT,
        site_id: Number(site.id),
        name: spec.name,
        brand: 'mikrotik',
        family: 'mikrotik_routeros7',
        model: spec.profile === 'C' ? 'CCR2004' : 'RB5009',
        serial: `SN${String(spec.index).padStart(8, '0')}`,
        os_version: '7.14.3',
        role: 'cpe',
        status: 'active',
        is_managed: false,             // a TAKE-OVER: nothing is managed yet
        ppp_username: spec.name,
        system_identity: spec.name,
      })
      .returning<{ id: number }[]>('id');
    const deviceId = Number(dev.id);
    deviceIdBySite.set(spec.index, deviceId);

    const doc = siteDoc(spec, deviceId);
    await storeDoc(deviceId, doc);
  }
}

async function storeDoc(deviceId: number, doc: NcmDocument): Promise<void> {
  await db('config_snapshots').insert({
    device_id: deviceId,
    source: 'routeros_api',
    ncm: JSON.stringify(doc),
    ncm_hash: ncmHash(doc),
    ncm_version: doc.ncmVersion,
    sem_key_generation: doc.semKeyGeneration,
    normalization_epoch: doc.normalizationEpoch,
    order_analysis: doc.orderAnalysis,
    os_version: doc.device.osVersion,
    model: doc.device.model,
    captured_at: new Date(),
    last_seen_at: new Date(),
  });
}

// ============================================================================
// 1. Pure tests — no database
// ============================================================================

function testPureFacts(): void {
  console.log('\n── Facts, slots and the secret refusal (pure) ──');
  const specs = fleetSpecs();

  const a = extractFacts(siteDoc(specs[0], 1), 1, 1);
  const b = extractFacts(siteDoc(specs[1], 2), 2, 2);
  ok('a site yields facts', a.facts.length > 60, `${a.facts.length} facts, ${a.slots.size} slots`);
  ok('extraction refused nothing', a.refusedAttributes === 0);

  // Two profile-A sites differ ONLY in their addressing: identical slot sets.
  const sameSlots = a.slots.size === b.slots.size && [...a.slots].every((s) => b.slots.has(s));
  ok('two sites of one profile share their slot set', sameSlots);

  // …and their VALUES differ, which is what makes those slots variables.
  const va = new Map(a.facts.map((f) => [f.slot, f.value]));
  const differing = b.facts.filter((f) => va.get(f.slot) !== f.value).length;
  ok('their values differ at the same slots', differing >= 8, `${differing} differing facts`);

  // No fact anywhere in the fleet may come from a credential-bearing attribute,
  // and the fixtures really do carry a PSK fingerprint and an SNMP community
  // fingerprint for the refusal to have something to refuse.
  let allFacts = 0;
  let offending = 0;
  for (const spec of specs) {
    const df = extractFacts(siteDoc(spec, spec.index + 1), spec.index + 1, spec.index + 1);
    allFacts += df.facts.length;
    for (const f of df.facts) if (slotIsForbidden(f.slot)) offending++;
  }
  ok('no fact carries credential material', offending === 0, `${allFacts} facts scanned`);
  ok(
    'the refusal list is actually a refusal',
    BASELINE_FORBIDDEN_ATTRIBUTES.every(isForbiddenBaselineAttribute)
      && isForbiddenBaselineAttribute('wpaPassphrase')
      && isForbiddenBaselineAttribute('radiusSecret'),
  );
  // …and it does NOT reject a customer's own naming.
  ok(
    'a customer named "secretary" is not a secret',
    !slotIsForbidden('localUser/secretary/group') && !slotIsForbidden('dhcpScope/credential-lab/subnet'),
  );
}

function testPureClustering(): void {
  console.log('\n── Weighted Jaccard and the agglomeration (pure) ──');
  const specs = fleetSpecs();
  const sets = specs.map((s) => extractFacts(siteDoc(s, s.index + 1), s.index + 1, s.index + 1));
  const slotSets = sets.map((s) => [...s.slots].sort());

  const sim = similarityMatrix(slotSets);
  const withinA = sim[0][1];
  const acrossAB = sim[0][30];
  const acrossAC = sim[0][45];
  ok('a profile is more self-similar than it is similar to another',
    withinA > acrossAB && withinA > acrossAC,
    `A/A=${withinA.toFixed(3)} A/B=${acrossAB.toFixed(3)} A/C=${acrossAC.toFixed(3)}`);

  ok('weightedJaccard is symmetric and bounded',
    Math.abs(weightedJaccard(new Set(slotSets[0]), new Set(slotSets[30]), slotWeight)
      - weightedJaccard(new Set(slotSets[30]), new Set(slotSets[0]), slotWeight)) < 1e-12
    && acrossAB >= 0 && acrossAB <= 1);

  // Determinism: the same input must agglomerate the same way, twice.
  const first = agglomerate(sim, 'complete', 4);
  const second = agglomerate(sim, 'complete', 4);
  ok('the agglomeration is deterministic',
    JSON.stringify(first.assignments) === JSON.stringify(second.assignments));

  const k3 = first.assignments[3];
  const profileOf = (i: number) => specs[i].profile;
  const pure = [0, 1, 2].every((c) => {
    const members = k3.map((g, i) => (g === c ? i : -1)).filter((i) => i >= 0);
    return new Set(members.map(profileOf)).size === 1;
  });
  ok('k=3 recovers the three seeded profiles exactly', pure,
    `sizes ${[0, 1, 2].map((c) => k3.filter((g) => g === c).length).join('/')}`);
}

// ============================================================================
// 2. The acceptance criterion
// ============================================================================

let outcome: BaselineRunOutcome | null = null;

async function testAcceptance(): Promise<void> {
  console.log('\n── ARCHITECTURE.md §5/M12 acceptance criterion ──');

  const started = Date.now();
  outcome = await runBaseline(TENANT, {}, operatorId);
  const wall = Date.now() - started;

  console.log(
    `  50 configs mined in ${wall} ms ` +
      `(clustering ${outcome.clusterDurationMs} ms, ` +
      `${outcome.ranInWorker ? 'in a worker_thread' : 'INLINE — worker unavailable'})`,
  );
  console.log(`  facts mined: ${outcome.factCount}   devices: ${outcome.deviceCount}   ` +
    `skipped: ${outcome.skippedCount}`);
  console.log('  coverage by k (the evidence behind the stopping rule):');
  for (const c of outcome.coverageByK) {
    console.log(
      `     k=${c.k}  worst member ${(c.coverageMin * 100).toFixed(1)}%  ` +
        `fleet mean ${(c.coverageMean * 100).toFixed(1)}%` +
        (c.k === outcome!.chosenK ? '   <-- chosen' : ''),
    );
  }

  ok('the clustering ran in a worker_thread', outcome.ranInWorker);
  ok('at most 4 clusters proposed', outcome.clusterCount <= 4,
    `${outcome.clusterCount} clusters (k=${outcome.chosenK})`);
  ok('the purity gate was met', outcome.purityGateMet);
  ok('all 50 devices were mined', outcome.deviceCount === 50 && outcome.skippedCount === 0,
    `${outcome.deviceCount} mined, ${outcome.skippedCount} skipped`);

  const conf = await getConformance(TENANT, outcome.runId);
  const worst = Math.min(...conf.devices.map((d) => d.scoreRaw));
  const mean = conf.devices.reduce((a, d) => a + d.factsCovered, 0)
    / conf.devices.reduce((a, d) => a + d.factsTotal, 0);
  console.log(
    `  coverage: worst device ${(worst * 100).toFixed(1)}%, ` +
      `fleet mean ${(mean * 100).toFixed(1)}%`,
  );
  ok('at least 80% of every device\'s lines are covered', worst >= 0.8,
    `worst device ${(worst * 100).toFixed(1)}%`);
  ok('the fleet mean is at least 80%', mean >= 0.8, `${(mean * 100).toFixed(1)}%`);

  const { run, clusters } = await getRun(TENANT, outcome.runId);
  ok('the run stored its own parameters', run.params.maxClusters === 4 && run.params.minCoverage === 0.8);
  console.log('  proposed profiles:');
  for (const c of clusters) {
    console.log(
      `     ${c.label}  ${c.memberCount} members  cohesion ${Number(c.cohesion).toFixed(3)}  ` +
        `coverage min ${(Number(c.coverageMin) * 100).toFixed(1)}%  ` +
        `draft: ${c.lineCount} lines, ${c.variableCount} variables`,
    );
  }
  ok('every cluster produced a draft',
    clusters.every((c) => c.draftId !== null && Number(c.lineCount) > 0));
  ok('every draft found variables by alignment',
    clusters.every((c) => Number(c.variableCount) >= 5),
    clusters.map((c) => `${c.label}:${c.variableCount}`).join(' '));
  ok('every cluster is pure', clusters.every((c) => c.purityOk === true));
}

async function testVariables(): Promise<void> {
  console.log('\n── The variables the alignment discovered ──');
  const run = outcome!;
  const clusters = await db('baseline_clusters')
    .where({ run_id: run.runId, tenant_id: TENANT }).orderBy('cluster_index');
  const first = clusters[0];

  const variables = await db('baseline_slots')
    .where({ cluster_id: first.id, tenant_id: TENANT, role: 'variable' })
    .orderBy('slot');
  console.log(`  ${first.label}: ${variables.length} variables, e.g.`);
  for (const v of variables.slice(0, 8)) {
    console.log(
      `     ${v.slot}  ->  {{ ${v.var_name} }}  ` +
        `(present on ${v.present_on}/${v.member_count}, ${v.distinct_values} distinct)`,
    );
  }

  const slots = variables.map((v) => String(v.slot));
  ok('the LAN prefix became a variable',
    slots.some((s) => s.startsWith('interface/bridge-lan/addresses')));
  ok('the WAN address became a variable',
    slots.some((s) => s.startsWith('interface/ether1/addresses')));
  ok('the default gateway became a variable',
    slots.some((s) => s.includes('cidr:any') && s.endsWith('/gateway')));
  ok('the DHCP pool became a variable',
    slots.some((s) => s.startsWith('dhcpScope/lan/poolFrom')));

  const constants = await db('baseline_slots')
    .where({ cluster_id: first.id, tenant_id: TENANT, role: 'constant' }).count<{ count: string }[]>('* as count');
  ok('the doctrine lines stayed constants', Number(constants[0].count) > 20,
    `${constants[0].count} constants`);

  const divergent = await db('baseline_slots')
    .where({ cluster_id: first.id, tenant_id: TENANT, role: 'divergent' }).count<{ count: string }[]>('* as count');
  ok('no divergent slot reached the body',
    Number(await db('baseline_slots')
      .where({ cluster_id: first.id, tenant_id: TENANT, role: 'divergent', in_body: true })
      .count<{ count: string }[]>('* as count').then((r) => r[0].count)) === 0,
    `${divergent[0].count} divergent slot(s) reported`);

  // "présent sur 27/30" — the counter the spec asks for, in the body itself.
  const draft = await db('baseline_drafts').where({ cluster_id: first.id, tenant_id: TENANT }).first();
  const body = String(draft.body);
  ok('the draft body carries the support counter',
    /present on \d+\/\d+/.test(body) && body.includes('MINED, NOT AUTHORED'));
  ok('the draft body carries no credential material',
    !/password|passphrase|psk|fingerprint/i.test(body));
}

// ============================================================================
// 3. Deviations: listed, and classifiable
// ============================================================================

async function testDeviations(): Promise<void> {
  console.log('\n── Every deviation listed, and classable ──');
  const run = outcome!;

  const { rows, total } = await listDeviations(TENANT, {
    runId: run.runId, limit: 500, offset: 0,
  });
  const byKind = new Map<string, number>();
  for (const r of rows) byKind.set(String(r.kind), (byKind.get(String(r.kind)) ?? 0) + 1);
  console.log(
    `  ${total} deviations: ` +
      [...byKind.entries()].sort().map(([k, n]) => `${n} ${k}`).join(', '),
  );
  ok('the seeded peculiarities surfaced as deviations', total >= 11, `${total} deviations`);
  ok('every deviation starts unclassified',
    rows.every((r) => r.classification === 'unclassified'));

  // The telnet quirk of site 03 must be there, by name.
  const telnetDev = deviceIdBySite.get(3)!;
  const telnet = rows.filter((r) => Number(r.deviceId) === telnetDev
    && String(r.slot).startsWith('service/telnet/'));
  ok('telnet left enabled at site-03 is listed', telnet.length > 0,
    telnet.map((t) => `${t.slot}=${t.deviceValue}`).join(' '));

  // A supplier rule is a legitimate client specificity.
  const supplierDev = deviceIdBySite.get(5)!;
  const supplier = rows.find((r) => Number(r.deviceId) === supplierDev
    && String(r.slot).includes('firewallRule/input'));
  ok('the supplier firewall rule at site-05 is listed', supplier !== undefined,
    supplier ? String(supplier.slot) : '');

  // ── classification ─────────────────────────────────────────────────────
  await refuses(
    'client_specific without a reason is refused',
    () => classifyDeviation(TENANT, Number(supplier!.id), { classification: 'client_specific' }, operatorId),
    'reason',
  );

  const classified = await classifyDeviation(
    TENANT,
    Number(supplier!.id),
    {
      classification: 'client_specific',
      scope: 'device',
      reason: 'Ce client heberge le portail de son fournisseur; regle validee par le RSSI le 2026-06-12.',
      note: 'A revoir a la resiliation du contrat fournisseur.',
    },
    operatorId,
  );
  ok('a client specificity becomes a documented exception',
    classified.classification === 'client_specific' && classified.exceptionId !== null);

  const exceptions = await listExceptions(TENANT);
  ok('the exception carries its reason', exceptions.length === 1
    && String(exceptions[0].reason).includes('RSSI'));

  await refuses(
    'deleting an exception still in use is refused',
    () => deleteException(TENANT, Number(exceptions[0].id)),
    'reclassify',
  );

  // The other three classifications are plain updates.
  await classifyDeviation(TENANT, Number(telnet[0].id), {
    classification: 'to_remediate', note: 'Telnet: a desactiver au prochain change.',
  }, operatorId);
  const routeDev = deviceIdBySite.get(9)!;
  const routeDeviation = rows.find((r) => Number(r.deviceId) === routeDev
    && String(r.slot).startsWith('route/'));
  if (routeDeviation) {
    await classifyDeviation(TENANT, Number(routeDeviation.id), {
      classification: 'template_gap', note: 'Le template ne modelise pas les routes de secours.',
    }, operatorId);
  }

  const after = await listDeviations(TENANT, { runId: run.runId, limit: 500, offset: 0 });
  const classes = new Map<string, number>();
  for (const r of after.rows) classes.set(String(r.classification), (classes.get(String(r.classification)) ?? 0) + 1);
  console.log('  after triage: ' + [...classes.entries()].sort().map(([k, n]) => `${n} ${k}`).join(', '));
  ok('all four classifications are reachable',
    classes.get('client_specific') === 1 && classes.get('to_remediate') === 1
      && (routeDeviation ? classes.get('template_gap') === 1 : true));

  // Filtering is what makes a list of hundreds usable.
  const onlyUnclassified = await listDeviations(TENANT, {
    runId: run.runId, classification: 'unclassified', limit: 500, offset: 0,
  });
  ok('the deviation list filters by classification',
    onlyUnclassified.total === total - (routeDeviation ? 3 : 2),
    `${onlyUnclassified.total} still unclassified of ${total}`);
}

async function testConformance(): Promise<void> {
  console.log('\n── Conformance, raw and adjusted ──');
  const run = outcome!;
  const conf = await getConformance(TENANT, run.runId);

  const supplierDev = deviceIdBySite.get(5)!;
  const row = conf.devices.find((d) => d.deviceId === supplierDev)!;
  console.log(
    `  site-05: ${row.factsCovered}/${row.factsTotal} covered, ${row.deviations} deviation(s), ` +
      `${row.excused} excused -> raw ${(row.scoreRaw * 100).toFixed(1)}%, ` +
      `adjusted ${(row.scoreAdjusted * 100).toFixed(1)}%`,
  );
  ok('signing for a difference moves the ADJUSTED score only',
    row.scoreAdjusted > row.scoreRaw && row.excused === 1);

  const clean = conf.devices.find((d) => d.deviations === 0);
  ok('a site with no deviation scores 100% both ways',
    clean !== undefined && clean.scoreRaw === 1 && clean.scoreAdjusted === 1);

  console.log(`  ${conf.sites.length} client sites scored; five worst:`);
  for (const s of [...conf.sites].sort((a, b) => a.scoreAdjusted - b.scoreAdjusted).slice(0, 5)) {
    console.log(
      `     site ${s.siteId}: ${s.devices} device(s), raw ${(s.scoreRaw * 100).toFixed(1)}%, ` +
        `adjusted ${(s.scoreAdjusted * 100).toFixed(1)}%`,
    );
  }
  ok('a score exists for every client site', conf.sites.length === 50);
  ok('both scores are always reported together',
    conf.devices.every((d) => typeof d.scoreRaw === 'number' && typeof d.scoreAdjusted === 'number'
      && d.scoreAdjusted >= d.scoreRaw - 1e-9));
}

// ============================================================================
// 3b. The excusal arithmetic — audit findings 1 and 2
// ============================================================================

/**
 * Two defects lived in the same three numbers, and both of them turned a
 * conformance score into a number that only ever flattered the fleet.
 *
 * FINDING 1 — a `missing` deviation is NOT in `facts_total`. Signing for one
 * used to be transferred, via `LEAST(excused, facts_total - facts_covered)`,
 * onto differences it has nothing to do with: a site that legitimately lacks
 * nine template slots and carries nine REAL unexplained drifts read 100 %
 * conformant the moment an operator signed the nine absences.
 *
 * FINDING 2 — the score was a RATCHET. `classifyDeviation` refreshed the
 * counters on the `client_specific` branch only, and the refresh itself was an
 * `UPDATE ... FROM (… GROUP BY device_id) WHERE c.device_id = sub.device_id`,
 * so a device with no `client_specific` deviation left produced no row to join
 * against and kept the excusals it no longer had.
 *
 * Both are replayed here the way an operator produces them: PATCHes, in order,
 * through the real service, against the real schema.
 */
async function testExcusalArithmetic(): Promise<void> {
  console.log('\n── Excusals: what is in the denominator, and what comes back down ──');
  const run = outcome!;

  const all = await listDeviations(TENANT, { runId: run.runId, limit: 2000, offset: 0 });
  const byDevice = new Map<number, BaselineDeviationDetail[]>();
  for (const r of all.rows) {
    const id = Number(r.deviceId);
    const list = byDevice.get(id) ?? [];
    list.push(r);
    byDevice.set(id, list);
  }
  // A device carrying BOTH families: `missing` slots the template has and it
  // does not, and `extra`/`value_conflict` facts it has and the template does
  // not explain. Without both, neither finding is reproducible.
  const mixed = [...byDevice.entries()]
    .filter(([, rows]) => rows.some((r) => r.kind === 'missing')
      && rows.some((r) => r.kind !== 'missing'))
    .sort((a, b) => a[0] - b[0]);
  ok('the fleet contains devices with both missing and on-device deviations',
    mixed.length >= 2, `${mixed.length} such device(s)`);
  if (mixed.length < 2) return;

  const [subjectId, subjectRows] = mixed[0];
  const [controlId, controlRows] = mixed[1];
  const missing = subjectRows.filter((r) => r.kind === 'missing');
  const onDevice = subjectRows.filter((r) => r.kind !== 'missing');

  const read = async (deviceId: number) => {
    const conf = await getConformance(TENANT, run.runId);
    return conf.devices.find((d) => d.deviceId === deviceId)!;
  };

  const before = await read(subjectId);
  console.log(
    `  device ${subjectId}: ${before.factsCovered}/${before.factsTotal} covered, `
      + `${missing.length} missing + ${onDevice.length} on-device deviation(s), `
      + `raw ${(before.scoreRaw * 100).toFixed(1)}%`,
  );
  ok('the on-device deviations ARE the uncovered facts, one for one',
    onDevice.length === before.factsTotal - before.factsCovered,
    `${onDevice.length} vs ${before.factsTotal - before.factsCovered}`);

  // ── finding 1 ─────────────────────────────────────────────────────────────
  // Sign every `missing` deviation and NOT ONE of the real drifts. Under the
  // old arithmetic this device reached score_adjusted = 1.00000 here.
  for (const d of missing) {
    await classifyDeviation(TENANT, Number(d.id), {
      classification: 'client_specific',
      scope: 'device',
      reason: 'Ce site ne porte ni la telephonie ni le peer IPsec du siege, par contrat.',
    }, operatorId);
  }
  const afterMissing = await read(subjectId);
  console.log(
    `  after signing the ${missing.length} absences: excused ${afterMissing.excused}, `
      + `excusedMissing ${afterMissing.excusedMissing}, `
      + `adjusted ${(afterMissing.scoreAdjusted * 100).toFixed(1)}%`,
  );
  ok('excusing an ABSENT slot credits nothing to the score',
    afterMissing.excused === 0 && afterMissing.scoreAdjusted === afterMissing.scoreRaw);
  ok('and the device does NOT read 100% while real drifts are unexplained',
    afterMissing.scoreAdjusted < 1,
    `adjusted ${(afterMissing.scoreAdjusted * 100).toFixed(1)}% with `
      + `${onDevice.length} unsigned difference(s)`);
  ok('the absences are still counted, as information',
    afterMissing.excusedMissing === missing.length);

  // ── finding 2 ─────────────────────────────────────────────────────────────
  // Now sign the real drifts too: those are the excusals the score MAY credit.
  for (const d of onDevice) {
    await classifyDeviation(TENANT, Number(d.id), {
      classification: 'client_specific',
      scope: 'device',
      reason: 'Derive acceptee le temps de la reprise; a revoir au prochain change.',
    }, operatorId);
  }
  const signed = await read(subjectId);
  ok('excusing an on-device difference DOES move the adjusted score',
    signed.excused === onDevice.length && signed.scoreAdjusted === 1,
    `excused ${signed.excused}, adjusted ${signed.scoreAdjusted}`);

  // …and the reviewer overturns all of them. Every deviation of this device
  // leaves `client_specific`, which is exactly the row the old UPDATE skipped.
  for (const d of [...onDevice, ...missing]) {
    await classifyDeviation(TENANT, Number(d.id), {
      classification: 'to_remediate', note: 'Revue: ce n est pas une specificite client.',
    }, operatorId);
  }
  const reverted = await read(subjectId);
  const stillSigned = await db('baseline_deviations')
    .where({
      tenant_id: TENANT, run_id: run.runId, device_id: subjectId,
      classification: 'client_specific',
    })
    .count<{ count: string }[]>('* as count');
  console.log(
    `  after overturning all ${subjectRows.length}: excused ${reverted.excused}, `
      + `excusedMissing ${reverted.excusedMissing}, `
      + `adjusted ${(reverted.scoreAdjusted * 100).toFixed(1)}%`,
  );
  ok('un-signing every difference brings the adjusted score back down',
    reverted.excused === 0 && reverted.excusedMissing === 0
      && reverted.scoreAdjusted === reverted.scoreRaw,
    `excused ${reverted.excused}, adjusted ${reverted.scoreAdjusted}, raw ${reverted.scoreRaw}`);
  ok('and the row agrees with the deviations underneath it',
    Number(stillSigned[0].count) === 0);

  // The control device keeps SOME exceptions: the total rewrite must recompute
  // every row from its own deviations, not zero every row it touches.
  const controlOnDevice = controlRows.filter((r) => r.kind !== 'missing');
  for (const d of controlOnDevice) {
    await classifyDeviation(TENANT, Number(d.id), {
      classification: 'client_specific',
      scope: 'device',
      reason: 'Regle du fournisseur de ce client, validee au contrat.',
    }, operatorId);
  }
  const keep = Math.max(1, controlOnDevice.length - 2);
  for (const d of controlOnDevice.slice(keep)) {
    await classifyDeviation(TENANT, Number(d.id), {
      classification: 'to_remediate', note: 'Revue partielle.',
    }, operatorId);
  }
  const control = await read(controlId);
  ok('a device that keeps some exceptions is recomputed, not zeroed',
    control.excused === keep,
    `device ${controlId}: excused ${control.excused} of ${controlOnDevice.length} signed, `
      + `adjusted ${(control.scoreAdjusted * 100).toFixed(1)}%`);
  ok('its adjusted score is exactly (covered + excused) / total',
    Math.abs(control.scoreAdjusted
      - Math.round(((control.factsCovered + control.excused) / control.factsTotal) * 100000)
        / 100000) < 1e-9);
}

// ============================================================================
// 4. What the schema refuses
// ============================================================================

async function testSchemaRefusals(): Promise<void> {
  console.log('\n── What migration 017 refuses ──');
  const run = outcome!;
  const cluster = await db('baseline_clusters')
    .where({ run_id: run.runId, tenant_id: TENANT }).first();

  await refuses(
    'a credential-bearing slot cannot be inserted',
    () => db('baseline_slots').insert({
      run_id: run.runId, tenant_id: TENANT, cluster_id: cluster.id,
      slot: 'ipsecPeer/hq/pskFingerprint', section: 'ipsecPeer', role: 'constant',
      present_on: 1, member_count: 1, distinct_values: 1,
      constant_value: 'AAAAAAAAAAAAAAAAAAAAAA', value_class: 'literal',
    }),
    'slot_secret_chk',
  );

  // ── The lockstep the comment claimed and 017 did not have ───────────────
  //
  // `isForbiddenBaselineAttribute` refuses through TWO mechanisms: an exact
  // Set, then a substring pass. 017's regex transcribed only the substring
  // pass, so the two members of the Set with no matching substring —
  // `preSharedKey` and `community` — were ACCEPTED by all three CHECKs. This
  // assertion was the one that would have caught it, and it only ever tried
  // `pskFingerprint`, which is on the right side of the line either way.
  //
  // Migration 023 adds the second mechanism as a second alternative rather
  // than as two more substrings, which matters: `communityIsWellKnown` is a
  // legitimate mined attribute the function ACCEPTS, and a stricter database
  // would amputate it while looking like a mining bug. Both directions are
  // asserted below, against the real constraint.
  for (const slot of ['ipsecPeer/hq/preSharedKey', 'service/snmp/community']) {
    await refuses(
      `the exact-name half of the refusal is enforced in SQL too (${slot})`,
      () => db('baseline_slots').insert({
        run_id: run.runId, tenant_id: TENANT, cluster_id: cluster.id,
        slot, section: slot.startsWith('ipsecPeer') ? 'ipsecPeer' : 'service',
        role: 'constant', present_on: 1, member_count: 1, distinct_values: 1,
        constant_value: 'AAAAAAAAAAAAAAAAAAAAAA', value_class: 'literal',
      }),
      'slot_secret_chk',
    );
  }

  // Both sides of the same line, over every attribute the fixtures produce
  // plus the names that make the two mechanisms differ: the database must
  // agree with `slotIsForbidden` on EVERY one, in both directions.
  const probes = [
    ...BASELINE_FORBIDDEN_ATTRIBUTES.map((a) => `ipsecPeer/hq/${a}`),
    'service/snmp/communityIsWellKnown', 'localUser/secretary/enabled',
    'interface/pskbridge/mtu', 'dhcpScope/credential-lab/gateway',
    'ipsecPeer/hq/dpdSeconds', 'ipsecPeer/hq/ipsecPolicy', 'wifi/wlan1/wpaPassphrase',
    'service/api/apiKey', 'route/0.0.0.0_0/gateway',
  ];
  const sqlVerdicts = (await db
    .select(db.raw('slot, slot ~* ? AS refused', [SECRET_SLOT_RE_023]))
    .from(db.raw('unnest(?::text[]) AS slot', [probes]))) as unknown;
  const disagreements = (sqlVerdicts as { slot: string; refused: boolean }[])
    .filter((r) => r.refused !== slotIsForbidden(r.slot))
    .map((r) => `${r.slot}: sql=${r.refused} js=${slotIsForbidden(r.slot)}`);
  ok('the CHECK regex and slotIsForbidden agree on every probe, both ways',
    disagreements.length === 0,
    disagreements.length === 0
      ? `${probes.length} slots, no disagreement`
      : disagreements.join('; '));

  await refuses(
    'a variable slot with no variable name is refused',
    () => db('baseline_slots').insert({
      run_id: run.runId, tenant_id: TENANT, cluster_id: cluster.id,
      slot: 'service/ssh/bogus', section: 'service', role: 'variable',
      present_on: 1, member_count: 1, distinct_values: 2, value_class: 'literal',
    }),
    'role_shape_chk',
  );

  await refuses(
    'an exception with a blank reason is refused',
    () => db('baseline_exceptions').insert({
      tenant_id: TENANT, scope: 'tenant', scope_id: null,
      slot: 'service/ssh/port', reason: '   ',
    }),
    'reason_chk',
  );

  await refuses(
    'a client_specific deviation with no exception is refused',
    () => db('baseline_deviations').insert({
      run_id: run.runId, tenant_id: TENANT, cluster_id: cluster.id,
      device_id: deviceIdBySite.get(0), slot: 'service/ssh/port', section: 'service',
      kind: 'value_conflict', template_value: '22', device_value: '2222',
      classification: 'client_specific', exception_id: null, classified_at: new Date(),
    }),
    'client_specific_chk',
  );

  // Decision 6: two partial indexes, not one nullable-column unique.
  await refuses(
    'the fleet-wide slot statistics are unique per run',
    () => db('baseline_slots').insert({
      run_id: run.runId, tenant_id: TENANT, cluster_id: null,
      slot: 'service/ssh/enabled', section: 'service', role: 'constant',
      present_on: 1, member_count: 1, distinct_values: 1,
      constant_value: 'true', value_class: 'boolean',
    }),
    'baseline_slots_run_uq',
  );

  // Decision 2: a baseline row cannot reference another tenant's device.
  const [otherTenant] = await db('tenants')
    .insert({ name: 'Other', slug: `other-${Date.now()}` })
    .returning<{ id: number }[]>('id');
  const [alien] = await db('devices')
    .insert({
      tenant_id: Number(otherTenant.id), name: 'alien', brand: 'mikrotik',
      family: 'mikrotik_routeros7', role: 'cpe', status: 'active',
    })
    .returning<{ id: number }[]>('id');
  // A REAL snapshot id, so the only constraint the row can break is the one
  // under test — a row that fails on an unrelated foreign key would let this
  // assertion pass while proving nothing.
  const anySnapshot = await db('config_snapshots').orderBy('id').first<{ id: number }>('id');
  await refuses(
    'a cluster cannot adopt another tenant\'s device',
    () => db('baseline_cluster_members').insert({
      cluster_id: cluster.id, run_id: run.runId, tenant_id: TENANT,
      device_id: Number(alien.id), snapshot_id: Number(anySnapshot.id),
      facts_total: 1, facts_covered: 1, coverage: 1, distance_to_medoid: 0,
    }),
    'bcm_device_fk',
  );
  await db('devices').where('id', Number(alien.id)).del();
  await db('tenants').where('id', Number(otherTenant.id)).del();
}

// ============================================================================
// 4b. The shapes the API actually returns, and the parameter it refused badly
// ============================================================================

/**
 * `shared/src/baseline.ts` declares `BaselineClusterSummary` and
 * `BaselineDeviationRow`; the service returned Knex rows. Nothing failed, ever,
 * because `Record<string, unknown>` type-checks against anything: a client
 * written against the contract read `undefined` in `deviceId` and
 * `templateValue` and rendered empty cells. This is the third time the project
 * has paid for exactly that (M3, M4, M6), so the shape is asserted here on the
 * real rows rather than trusted to a signature.
 *
 * The second half is the brand. `BaselineParams.brand` is a free
 * `z.string().max(24)` while `baseline_runs_brand_chk` restricts the column, so
 * `{"brand":"cisco"}` used to pass Zod, violate the CHECK with an unmapped
 * SQLSTATE 23514 and come back as a bare 500 — with no `baseline_runs` row, so
 * the history did not even record that somebody tried.
 */
async function testApiShapes(): Promise<void> {
  console.log('\n── The shapes the API returns, and the brand it refuses ──');
  const run = outcome!;

  const { clusters } = await getRun(TENANT, run.runId);
  const c = clusters[0];
  ok('a cluster comes back in the shared camelCase contract',
    typeof c.clusterIndex === 'number' && typeof c.memberCount === 'number'
      && typeof c.purityOk === 'boolean'
      && !('cluster_index' in c) && !('member_count' in c),
    Object.keys(c).join(','));
  // `numeric` arrives from `pg` as a STRING. `Number(c.cohesion)` at every call
  // site is exactly the coercion this mapping exists to stop needing.
  ok('numeric columns come back as numbers, not strings',
    typeof c.cohesion === 'number' && typeof c.coverageMin === 'number'
      && typeof c.coverageMean === 'number',
    `${typeof c.cohesion}/${typeof c.coverageMin}`);

  const detail = await getCluster(TENANT, c.id);
  ok('a cluster member comes back in the contract',
    detail.members.length > 0 && typeof detail.members[0].deviceId === 'number'
      && typeof detail.members[0].deviceName === 'string'
      && typeof detail.members[0].factsCovered === 'number');
  const slot = detail.slots[0];
  ok('a slot row satisfies BaselineSlotStat',
    typeof slot.presentOn === 'number' && typeof slot.memberCount === 'number'
      && typeof slot.valueClass === 'string' && Array.isArray(slot.sampleValues)
      && !('present_on' in slot),
    Object.keys(slot).join(','));

  const draftRow = await db('baseline_drafts')
    .where({ run_id: run.runId, tenant_id: TENANT }).orderBy('id').first();
  const draft = await getDraft(TENANT, Number(draftRow.id));
  ok('a draft comes back in the contract',
    typeof draft.bodySha256 === 'string' && typeof draft.lineCount === 'number'
      && typeof draft.varSchema === 'object' && !('body_sha256' in draft),
    Object.keys(draft).join(','));

  const { rows } = await listDeviations(TENANT, { runId: run.runId, limit: 1, offset: 0 });
  ok('a deviation satisfies BaselineDeviationRow',
    rows.length === 1 && typeof rows[0].deviceId === 'number'
      && 'templateValue' in rows[0] && 'deviceValue' in rows[0]
      && !('device_id' in rows[0]) && !('template_value' in rows[0]),
    Object.keys(rows[0]).join(','));

  // ── the brand ───────────────────────────────────────────────────────────
  const runsBefore = Number(
    (await db('baseline_runs').where('tenant_id', TENANT).count<{ c: string }[]>('* as c'))[0].c,
  );
  await refuses(
    'an unknown brand is a 400 that names the four brands, not a 500',
    () => runBaseline(TENANT, { brand: 'cisco' }, operatorId),
    'Unknown brand',
  );
  let status = 0;
  try {
    await runBaseline(TENANT, { brand: 'cisco' }, operatorId);
  } catch (err) {
    status = err instanceof AppError ? err.statusCode : 0;
  }
  ok('and it carries HTTP 400', status === 400, `status ${status}`);
  const runsAfter = Number(
    (await db('baseline_runs').where('tenant_id', TENANT).count<{ c: string }[]>('* as c'))[0].c,
  );
  ok('a refused brand writes no run row at all', runsAfter === runsBefore,
    `${runsBefore} -> ${runsAfter}`);
  // The other direction, through the real service and not a re-implementation
  // of its guard: `draytek` is a legal brand with no device in this fleet, so
  // it must get PAST the brand check and fail on the scope instead.
  let legalBrandMessage = '';
  try {
    await runBaseline(TENANT, { brand: 'draytek' }, operatorId);
  } catch (err) {
    legalBrandMessage = err instanceof Error ? err.message : String(err);
  }
  ok('a legal brand with no device gets past the brand check',
    legalBrandMessage.includes('No device in scope'), legalBrandMessage.slice(0, 90));
}

// ============================================================================
// 5. Promotion, and determinism
// ============================================================================

async function testPromotion(): Promise<void> {
  console.log('\n── Promotion: a DRAFT revision, and nothing more ──');
  const run = outcome!;
  const draft = await db('baseline_drafts')
    .where({ run_id: run.runId, tenant_id: TENANT }).orderBy('id').first();

  const { templateId, revisionId } = await promoteDraft(
    TENANT, Number(draft.id), 'Golden site — profile A', 'Mined by M12', operatorId,
  );
  const revision = await db('template_revisions').where('id', revisionId).first();
  const template = await db('templates').where('id', templateId).first();

  ok('the revision is a DRAFT, never published',
    revision.status === 'draft' && revision.published_at === null
      && revision.deps_pinned === false);
  ok('the template is tenant-scoped, never library',
    Number(template.tenant_id) === TENANT && template.brand === 'mikrotik');
  ok('the body kept its "rewrite me" header',
    String(revision.body).includes('NOT BRAND SYNTAX'));
  ok('the var_schema declares the mined variables',
    Object.keys(JSON.parse(JSON.stringify(revision.var_schema)).properties).length
      === Number(draft.variable_count));

  await refuses(
    'a draft cannot be promoted twice',
    () => promoteDraft(TENANT, Number(draft.id), 'Golden site — again', null, operatorId),
    'already promoted',
  );
}

async function testDeterminism(): Promise<void> {
  console.log('\n── Reproducibility (the reason there is no LLM in here) ──');
  const first = await db('baseline_drafts')
    .where({ tenant_id: TENANT }).orderBy('id').select('body_sha256', 'cluster_id');

  const second = await runBaseline(TENANT, {}, operatorId);
  const again = await db('baseline_drafts')
    .where({ tenant_id: TENANT, run_id: second.runId }).orderBy('id').select('body_sha256');

  ok('a second run over the same snapshots proposes the same k',
    second.chosenK === outcome!.chosenK && second.clusterCount === outcome!.clusterCount);
  ok('and produces byte-identical draft bodies',
    first.length === again.length
      && first.every((r, i) => r.body_sha256 === again[i].body_sha256),
    first.map((r) => String(r.body_sha256).slice(0, 8)).join(' '));
}

// ============================================================================
// 5b. The worker's ceilings are not a licence to freeze the API — finding 3
// ============================================================================

/** A synthetic fleet whose only job is to cost real time in the clustering
 *  pass. Slot names are shaped like real ones so `slotWeight` does the same
 *  work it does on a customer's fleet. */
function heavySlotSets(devices: number, slots: number): string[][] {
  const out: string[][] = [];
  for (let i = 0; i < devices; i++) {
    const s = new Set<string>();
    for (let j = 0; j < slots; j++) {
      s.add(`firewallRule/input#${((i * 7 + j) % (slots * 2)).toString(16)}/action`);
    }
    out.push([...s].sort());
  }
  return out;
}

/**
 * The watchdog used to call `finishInline`, which ran `similarityMatrix` +
 * `agglomerate` — the same computation, synchronously, on the main thread, with
 * no ceiling. At the §6.3 design point that is ~109 s of frozen event loop
 * AFTER the 120 s timeout: no HTTP handler, no RouterOS keepalive, no liveness
 * probe. The measurement below is the same shape at a size this harness can
 * afford, and it asserts three things: the call REJECTS, it rejects with a 503
 * rather than a fabricated result, and the main thread kept running while it
 * did — which is the whole difference between the two versions.
 */
async function testClusterCeiling(): Promise<void> {
  console.log('\n── A clustering pass that does not come back (audit finding 3) ──');
  const sets = heavySlotSets(250, 400);

  // What the OLD code added to the wall clock, on this thread, after the
  // watchdog had already fired. Measured, not assumed.
  const inlineStart = Date.now();
  const sim = similarityMatrix(sets);
  agglomerate(sim, 'complete', 4);
  const inlineMs = Date.now() - inlineStart;
  console.log(`  this input costs ${inlineMs} ms of blocked main thread if computed inline`);

  const deadline = 1000;
  process.env.BASELINE_CLUSTER_TIMEOUT_MS = String(deadline);
  let maxGapMs = 0;
  let last = Date.now();
  const ticker = setInterval(() => {
    maxGapMs = Math.max(maxGapMs, Date.now() - last);
    last = Date.now();
  }, 25);

  const started = Date.now();
  let rejected: unknown = null;
  try {
    await clusterSlotSets(sets, 'complete', 4);
  } catch (err) {
    rejected = err;
  }
  const elapsed = Date.now() - started;
  clearInterval(ticker);
  // The last segment counts too, and it is the one that matters: the inline
  // recomputation ends by RESOLVING this promise, so its stall would otherwise
  // be measured by a tick that `clearInterval` has already cancelled.
  maxGapMs = Math.max(maxGapMs, Date.now() - last);
  delete process.env.BASELINE_CLUSTER_TIMEOUT_MS;

  console.log(
    `  watchdog set to ${deadline} ms: rejected after ${elapsed} ms, `
      + `worst event-loop gap ${maxGapMs} ms`,
  );
  ok('a clustering pass that exceeds the watchdog REJECTS',
    rejected instanceof AppError && rejected.statusCode === 503,
    rejected instanceof Error ? rejected.message.slice(0, 120) : 'it resolved');
  ok('and it does NOT re-run the same computation on the main thread',
    elapsed < inlineMs,
    `${elapsed} ms elapsed vs ${inlineMs} ms of inline work avoided`);
  ok('the event loop kept turning throughout',
    maxGapMs < Math.max(400, inlineMs / 4), `worst gap ${maxGapMs} ms`);

  // End to end: the run is `failed`, explains itself, and is terminal — the
  // operator retries on a narrower scope instead of watching the API restart.
  process.env.BASELINE_CLUSTER_TIMEOUT_MS = '15';
  await refuses(
    'a run whose clustering times out fails instead of falling back',
    () => runBaseline(TENANT, {}, operatorId),
    'clustering did not complete',
  );
  delete process.env.BASELINE_CLUSTER_TIMEOUT_MS;
  const failedRun = await db('baseline_runs')
    .where({ tenant_id: TENANT }).orderBy('id', 'desc').first();
  ok('that run is terminal and says why',
    failedRun.status === 'failed' && failedRun.finished_at !== null
      && String(failedRun.error).includes('narrow the run'),
    String(failedRun.error).slice(0, 100));

  const succeeded = await db('baseline_runs')
    .where({ tenant_id: TENANT, id: outcome!.runId }).first();
  ok('a successful run records whether it clustered in the worker',
    succeeded.ran_in_worker === true,
    'baseline_runs.ran_in_worker — the degradation survives the move to pg-boss');
}

// ============================================================================
// 5c. The run has bounds — finding 4
// ============================================================================

/**
 * `loadFleet` had neither LIMIT nor pagination: every `ncm` document of the
 * tenant was materialised at once and held for the whole run (1.18 GB of RSS
 * measured at 500 × 3000, on top of the facts and the similarity matrix), and
 * the stopping rule ran every k up to `maxClusters` — 24 is a value the Zod
 * schema accepts — even after it had found its answer.
 */
async function testRunBounds(): Promise<void> {
  console.log('\n── The run is bounded (audit finding 4) ──');

  // (a) snapshots are read in batches, never as one query over the fleet.
  const snapshotQueries: string[] = [];
  const spy = (q: { sql: string }): void => {
    if (/config_snapshots/.test(q.sql) && /select/i.test(q.sql)) snapshotQueries.push(q.sql);
  };
  db.on('query', spy);
  const bounded = await runBaseline(TENANT, { maxClusters: 24 }, operatorId);
  db.off('query', spy);

  const expectedBatches = Math.ceil(bounded.deviceCount / FLEET_SNAPSHOT_BATCH);
  ok('the fleet\'s snapshots are read in batches, not all at once',
    snapshotQueries.length === expectedBatches,
    `${snapshotQueries.length} SELECT(s) for ${bounded.deviceCount} devices `
      + `(batch of ${FLEET_SNAPSHOT_BATCH})`);
  ok('every batch query still carries its own tenant predicate',
    snapshotQueries.every((s) => /"d"\."tenant_id"/.test(s) || /d\.tenant_id/.test(s)),
    'the join to `devices` is the only tenant isolation `config_snapshots` has');

  // (b) the stopping rule stops. maxClusters=24 must not cost 24 alignment
  //     passes when k=3 already clears the purity gate.
  console.log(
    `  maxClusters=24: chose k=${bounded.chosenK} after trying `
      + `${bounded.coverageByK.length} value(s) of k`,
  );
  ok('the stopping rule stops at the first k that clears the gate',
    bounded.purityGateMet && bounded.coverageByK.length === bounded.chosenK
      && bounded.coverageByK[bounded.coverageByK.length - 1].k === bounded.chosenK,
    `${bounded.coverageByK.length} of a possible 24 evaluated`);

  // (c) two runs at once double the peak; the second is refused, not queued in
  //     memory next to the first.
  const [first, second] = await Promise.allSettled([
    runBaseline(TENANT, {}, operatorId),
    runBaseline(TENANT, {}, operatorId),
  ]);
  ok('two concurrent runs on one tenant: the second is refused',
    first.status === 'fulfilled' && second.status === 'rejected'
      && (second.reason as AppError).statusCode === 409,
    second.status === 'rejected' ? String((second.reason as Error).message) : 'both ran');

  // (d) a fleet larger than the ceiling is refused BEFORE any snapshot is read.
  const filler = [];
  for (let i = 0; i < BASELINE_MAX_FLEET + 5; i++) {
    filler.push({
      tenant_id: TENANT, name: `bulk-${i}`, brand: 'mikrotik',
      family: 'mikrotik_routeros7', role: 'cpe', status: 'active',
    });
  }
  for (let i = 0; i < filler.length; i += 500) {
    await db('devices').insert(filler.slice(i, i + 500));
  }
  await refuses(
    'a fleet past the ceiling is refused rather than discovered as an OOM',
    () => runBaseline(TENANT, {}, operatorId),
    'narrow the scope',
  );
  await db('devices').where('tenant_id', TENANT).whereLike('name', 'bulk-%').del();
}

// ============================================================================
// 6. Degraded inputs — what the miner refuses to invent
// ============================================================================

async function testCoverageGate(): Promise<void> {
  console.log('\n── A section we could not read is not a section that is empty ──');
  const specs = fleetSpecs();
  const doc = siteDoc(specs[0], 1);
  const blind = JSON.parse(JSON.stringify(doc)) as NcmDocument;
  (blind.coverage as Record<string, { state: string; reason: string | null }>).firewallRule = {
    state: 'failed', reason: 'API timeout on /ip/firewall/filter',
  } as never;

  const full = extractFacts(doc, 1, 1);
  const partial = extractFacts(blind, 1, 1);
  const fwFacts = [...full.slots].filter((s) => s.startsWith('firewallRule/')).length;
  ok('a failed firewall collection mines no firewall fact',
    [...partial.slots].every((s) => !s.startsWith('firewallRule/'))
      && partial.skippedSections.includes('firewallRule'),
    `${fwFacts} firewall slots dropped instead of being reported as absent`);
  ok('the rest of the document is still mined',
    partial.facts.length > 0 && partial.facts.length < full.facts.length,
    `${partial.facts.length} of ${full.facts.length} facts`);

  // Snapshot retention must not erase the evidence of a past baseline.
  const membersBefore = Number((await db('baseline_cluster_members')
    .where('tenant_id', TENANT).count<{ count: string }[]>('* as count'))[0].count);
  await db('config_snapshots').del();
  const surviving = await db('baseline_cluster_members').where('tenant_id', TENANT);
  ok('pruning the snapshots keeps the cluster membership',
    surviving.length === membersBefore && surviving.every((m) => m.snapshot_id === null),
    `${surviving.length} of ${membersBefore} members kept, snapshot_id nulled`);

  // And a run over a fleet with nothing readable refuses rather than proposing
  // a template built out of a blind spot.
  await refuses(
    'a fleet with no readable snapshot refuses to be mined',
    () => runBaseline(TENANT, {}, operatorId),
    'no usable configuration snapshot',
  );
  const failedRun = await db('baseline_runs')
    .where({ tenant_id: TENANT }).orderBy('id', 'desc').first();
  ok('the failed run explains itself and is terminal',
    failedRun.status === 'failed' && failedRun.error !== null && failedRun.finished_at !== null,
    String(failedRun.error).slice(0, 90));
}

// ============================================================================

async function main(): Promise<void> {
  console.log('ObliWAN M12 — baseline miner / Golden Site (K8)');
  console.log('NOTE: no MikroTik, no CHR, no real equipment exists here.');
  console.log('      The 50 configurations are synthetic and were written by hand.');

  testPureFacts();
  testPureClustering();

  await reset();
  await seedFleet(fleetSpecs());
  await testAcceptance();
  await testVariables();
  await testDeviations();
  await testConformance();
  await testSchemaRefusals();
  await testApiShapes();
  await testPromotion();
  await testDeterminism();
  await testExcusalArithmetic();
  await testClusterCeiling();
  await testRunBounds();
  await testCoverageGate();

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failures.length) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  - ${f}`);
  }
  await db.destroy();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  try { await db.destroy(); } catch { /* ignore */ }
  process.exit(1);
});
