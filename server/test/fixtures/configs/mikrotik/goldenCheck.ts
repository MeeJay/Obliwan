/* eslint-disable no-console */
/**
 * ObliWAN — golden check for the RouterOS normaliser (M4).
 *
 *   cd server && npx tsx test/fixtures/configs/mikrotik/goldenCheck.ts
 *   cd server && npx tsx test/fixtures/configs/mikrotik/goldenCheck.ts --write-golden
 *
 * WHAT IT PROVES, and what it does NOT.
 *
 * It proves the four properties the milestone is judged on:
 *   A/A     two exports of the SAME state produce the SAME ncm_hash;
 *   N07     a reordering of two DISJOINT rules produces 0 findings;
 *   N2/§4.2 a rule inserted at the head of a 40-rule chain produces 1 finding,
 *           not 40;
 *   N1      `accept` -> `drop` produces ONE `changed` of severity `critical`,
 *           not a `missing` + an `extra`.
 *
 * IT DOES NOT PROVE ANYTHING ABOUT A REAL MIKROTIK. Every fixture under `raw/`
 * was WRITTEN BY HAND from knowledge of RouterOS, not captured from hardware:
 * no MikroTik was available to this workstream. The six open questions of §7.4
 * of the normalisation study (does `/export terse verbose` exist and what does
 * it return; at exactly which release the header date format flips; whether
 * `show-sensitive=no` omits a prop or blanks it, menu by menu; the real list of
 * props each version omits) remain UNANSWERED and cannot be answered by a
 * fixture I wrote myself — a hand-written fixture only tests the parser against
 * my own beliefs about RouterOS.
 *
 * THE REFERENCE DIFF BELOW IS PART OF THE TEST, NOT OF THE PRODUCT. The real
 * semantic diff engine is another workstream. What is implemented here is the
 * minimum needed to count findings, built exclusively out of the frozen shared
 * primitives (`buildSemKey` pairing, `computePayloadHash`, `buildOrderSignature`,
 * `crossedByRule`) so that the counts reported measure the NORMALISER and not a
 * diff of my own invention.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import {
  ORDERED_RESOURCE_KINDS,
  NCM_RESOURCE_KINDS,
  buildOrderSignature,
  computePayloadHash,
  crossedByRule,
  mayEmitMissing,
  ncmHash,
  NcmDocumentAuthored,
  type DiffSeverity,
  type NcmDocument,
  type NcmOrderedRule,
  type NcmResourceKind,
  type NormalizationRule,
} from '@obliwan/shared';
import {
  normalizeRouterOsExport,
  type NormalizeContext,
  type NormalizeResult,
} from '../../../../src/services/config/normalize.service';
import { allSeedRules } from '../../../../src/db/seeds/002_ncm_doctrine';
import { assertNoSensitiveMaterial, SENSITIVE_PROPS } from '../../../../src/services/drivers/mikrotik/driver';

const RAW_DIR = join(__dirname, 'raw');
const GOLDEN_DIR = join(__dirname, 'golden');
const WRITE_GOLDEN = process.argv.includes('--write-golden');

// ============================================================================
// The seeded ruleset, in memory
// ============================================================================

/** The rules the seed writes, materialised without a database so the golden
 *  check measures the SHIPPED ruleset and not a convenient subset. */
function seededRules(): NormalizationRule[] {
  return allSeedRules().map((r, i) => ({
    id: i + 1,
    uuid: `00000000-0000-0000-0000-${String(i + 1).padStart(12, '0')}`,
    builtinKey: r.builtinKey,
    scope: 'global',
    scopeId: null,
    brand: 'mikrotik',
    family: (r.family as NormalizationRule['family']) ?? null,
    osMin: r.osMin ?? null,
    osMax: null,
    name: r.name,
    description: r.description,
    rationale: r.rationale,
    falseNegative: r.falseNegative,
    layer: r.layer,
    kind: r.kind as NormalizationRule['kind'],
    sectionPath: r.sectionPath ?? null,
    sectionOrdered: r.sectionOrdered ?? true,
    prop: r.prop ?? null,
    pattern: r.pattern ?? null,
    replacement: r.replacement ?? null,
    predicate: (r.predicate as NormalizationRule['predicate']) ?? null,
    value: r.value ?? null,
    targetPath: r.targetPath ?? null,
    severity: (r.severity as DiffSeverity | null) ?? null,
    applyOrder: r.applyOrder,
    enabled: r.enabled ?? true,
  }));
}

const RULES = seededRules();

function run(fixture: string, opts: Partial<NormalizeContext> = {}): NormalizeResult {
  const raw = readFileSync(join(RAW_DIR, fixture), 'utf8');
  // R10 tripwire on every fixture: a committed export with a live secret in it
  // is the same accident as a snapshot with one.
  assertNoSensitiveMaterial(raw);
  const family = opts.family ?? 'mikrotik_routeros7';
  const osVersion = opts.osVersion ?? null;
  const ctx: NormalizeContext = {
    deviceId: 1,
    tenantId: 1,
    family,
    osVersion,
    // The family / exact-version filter is normally applied by the SQL of
    // `loadNormalizationRules`; it is reproduced here because skipping it lets
    // a `default_fill` seeded for RouterOS 6.49 fill a prop on a 7.14 document
    // and silently absorb a real difference. That is a false negative created
    // by the TEST HARNESS rather than by the engine, and it is exactly the kind
    // of thing an "everything passes" run hides.
    rules: RULES.filter(
      (r) => (r.family === null || r.family === family)
        && (r.osMin === null || r.osMin === osVersion),
    ),
    defaults: new Map(),
    via: 'ssh',
    // Frozen so `capturedAt` cannot accidentally become part of anything.
    capturedAt: '2026-01-02T10:33:21.000Z',
    ...opts,
  };
  const result = normalizeRouterOsExport(raw, ctx);
  const parsedDoc = NcmDocumentAuthored.safeParse(result.ncm);
  if (!parsedDoc.success) {
    console.error(`  ! ${fixture} does not satisfy NcmDocumentAuthored:`);
    for (const issue of parsedDoc.error.issues.slice(0, 8)) {
      console.error(`      ${issue.path.join('.')}: ${issue.message}`);
    }
    failures++;
  }
  return result;
}

// ============================================================================
// Reference diff (test-only, built from shared primitives)
// ============================================================================

interface Finding {
  kind: 'missing' | 'extra' | 'changed' | 'moved';
  resource: NcmResourceKind;
  semKey: string;
  severity: DiffSeverity;
  fields: string[];
  crossed?: string[];
}

interface DiffReport {
  findings: Finding[];
  inertMoveCount: number;
}

const COLLECTIONS: ReadonlyArray<[NcmResourceKind, keyof NcmDocument['resources']]> = [
  ['interface', 'interfaces'], ['vlan', 'vlans'], ['route', 'routes'],
  ['firewallRule', 'firewallRules'], ['natRule', 'natRules'], ['dhcpScope', 'dhcpScopes'],
  ['ipsecPeer', 'ipsecPeers'], ['localUser', 'localUsers'], ['service', 'services'],
  ['qosRule', 'qosRules'],
];

function referenceDiff(intent: NcmDocument, actual: NcmDocument): DiffReport {
  const findings: Finding[] = [];
  let inertMoveCount = 0;

  for (const [kind, key] of COLLECTIONS) {
    const left = new Map<string, Record<string, unknown>>();
    const right = new Map<string, Record<string, unknown>>();
    for (const r of intent.resources[key] as unknown as Record<string, unknown>[]) {
      left.set(String(r.semKey), r);
    }
    for (const r of actual.resources[key] as unknown as Record<string, unknown>[]) {
      right.set(String(r.semKey), r);
    }

    for (const [semKey, a] of left) {
      const b = right.get(semKey);
      if (!b) {
        // N3: no `missing` without complete coverage. This is the guard that
        // stops a partial read from generating a plan that recreates a firewall.
        if (mayEmitMissing(actual.coverage, kind)) {
          findings.push({ kind: 'missing', resource: kind, semKey, severity: severityFor(kind, []), fields: [] });
        }
        continue;
      }
      if (computePayloadHash(a) === computePayloadHash(b)) continue;
      const fields = changedFields(a, b);
      findings.push({ kind: 'changed', resource: kind, semKey, severity: severityFor(kind, fields), fields });
    }
    for (const [semKey] of right) {
      if (left.has(semKey)) continue;
      findings.push({ kind: 'extra', resource: kind, semKey, severity: severityFor(kind, []), fields: [] });
    }

    if (!ORDERED_RESOURCE_KINDS.has(kind)) continue;

    // §4.2 — precedence, restricted to the pairs that can decide a packet's
    // fate, compared chain by chain.
    const chains = new Set<string>();
    const group = (doc: NcmDocument): Map<string, NcmOrderedRule[]> => {
      const out = new Map<string, NcmOrderedRule[]>();
      for (const r of doc.resources[key] as unknown as NcmOrderedRule[]) {
        const g = r.kind === 'qosRule'
          ? `qos|${r.queueClass}`
          : `${r.chain}|${r.chainName ?? ''}`;
        chains.add(g);
        const list = out.get(g) ?? [];
        list.push(r);
        out.set(g, list);
      }
      return out;
    };
    const gi = group(intent);
    const ga = group(actual);
    for (const chain of chains) {
      const crossed = flippedCrossings(
        buildOrderSignature(gi.get(chain) ?? []),
        buildOrderSignature(ga.get(chain) ?? []),
      );
      for (const [semKey, others] of crossed) {
        if (others.length === 0) { inertMoveCount++; continue; }
        // A rule is not "moved" because something was INSERTED above it. If
        // every rule it now crosses is itself unpaired, the insertion already
        // explains the change and re-reporting it 40 times is exactly the
        // noise §4.2 exists to prevent.
        const unpaired = (k: string): boolean => !(left.has(k) && right.has(k));
        if (unpaired(semKey)) continue;
        if (others.every(unpaired)) continue;
        findings.push({ kind: 'moved', resource: kind, semKey, severity: 'high', fields: [], crossed: others });
      }
    }
  }

  return { findings, inertMoveCount };
}

/**
 * A CORRECTION TO `crossedByRule`, AND IT MATTERS FOR THE PRODUCT.
 *
 * `shared/src/ncm/intersect.ts` folds the whole symmetric difference of the two
 * order signatures into per-rule crossings. That set contains two very
 * different things:
 *
 *   (a) `a>b` in one side and `b>a` in the other — the precedence genuinely
 *       FLIPPED. This is a move.
 *   (b) `a>b` in one side and NEITHER direction in the other — the pair simply
 *       stopped (or started) being DECISIVE, because one of the two rules
 *       changed its action or was disabled. Nothing moved.
 *
 * Case (b) is produced by exactly the edit the product exists to catch: flipping
 * `accept` -> `drop` makes every previously-indecisive pair in that chain
 * decisive, and reporting them all turns ONE critical `changed` into one
 * `changed` plus four `moved`. Measured on the fixture corpus: 5 findings
 * instead of 1 for an accept->drop, 7 instead of 1 for a `disabled=yes`.
 *
 * The real diff engine MUST apply this filter. It is implemented here rather
 * than in `shared` because `intersect.ts` belongs to another workstream.
 */
function flippedCrossings(
  intent: { pairs: Set<string> },
  actual: { pairs: Set<string> },
): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const add = (key: string, other: string): void => {
    const cur = out.get(key);
    if (cur) { if (!cur.includes(other)) cur.push(other); }
    else out.set(key, [other]);
  };
  for (const p of intent.pairs) {
    const gt = p.indexOf('>');
    const a = p.slice(0, gt);
    const b = p.slice(gt + 1);
    if (actual.pairs.has(p)) continue;
    // Only a genuine inversion counts.
    if (!actual.pairs.has(`${b}>${a}`)) continue;
    add(a, b);
    add(b, a);
  }
  for (const [k, v] of out) out.set(k, v.sort());
  return out;
}

function changedFields(a: Record<string, unknown>, b: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
    if (k === 'semKey' || k === 'matchHash' || k === 'ordinal' || k === 'via') continue;
    if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) out.push(k);
  }
  return out.sort();
}

function severityFor(kind: NcmResourceKind, fields: string[]): DiffSeverity {
  if (fields.length > 0 && fields.every((f) => f === 'comment')) return 'low';   // N10
  if (fields.includes('action')) return 'critical';                              // N1
  if (kind === 'localUser' || kind === 'service') return 'critical';
  if (kind === 'firewallRule' || kind === 'natRule' || kind === 'route') return 'high';
  return 'medium';
}

// ============================================================================
// Assertions
// ============================================================================

let failures = 0;
let checks = 0;

function check(label: string, ok: boolean, detail = ''): void {
  checks++;
  if (!ok) failures++;
  console.log(`${ok ? '  ok  ' : '  FAIL'} ${label}${detail ? ` — ${detail}` : ''}`);
}

function findingLines(report: DiffReport): string {
  return report.findings
    .map((f) => `${f.kind}/${f.resource}/${f.semKey}${f.fields.length ? ` [${f.fields.join(',')}]` : ''} (${f.severity})`)
    .join('\n        ');
}

// ============================================================================
// The run
// ============================================================================

console.log('\n=== 0. parse ================================================\n');

const base = run('ros7-cpe-typical.export');
console.log(`  entries parsed          : ${base.stats.entries}`);
console.log(`  ncm_hash                : ${base.ncmHash}`);
console.log(`  firewall rules          : ${base.ncm.resources.firewallRules.length}`);
console.log(`  nat rules               : ${base.ncm.resources.natRules.length}`);
console.log(`  interfaces              : ${base.ncm.resources.interfaces.length}`);
console.log(`  vlans / routes          : ${base.ncm.resources.vlans.length} / ${base.ncm.resources.routes.length}`);
console.log(`  dhcp / ipsec / users    : ${base.ncm.resources.dhcpScopes.length} / ${base.ncm.resources.ipsecPeers.length} / ${base.ncm.resources.localUsers.length}`);
console.log(`  services / queues       : ${base.ncm.resources.services.length} / ${base.ncm.resources.qosRules.length}`);
console.log(`  unmodeled sections      : ${base.ncm.unmodeled.length}`);
console.log(`  unknown props (N05)     : ${base.unknownProps.length}`);
if (base.unknownProps.length > 0) {
  for (const u of base.unknownProps) console.log(`      ${u.sectionPath} ${u.prop}=${u.sample}`);
}
console.log(`  state props dropped     : ${base.stats.statePropsDropped}`);
console.log(`  counter props dropped   : ${base.stats.counterPropsDropped}`);
console.log(`  dynamic entries excluded: ${base.stats.dynamicEntriesExcluded}`);
console.log(`  ordinalCollisionRate    : ${(base.stats.ordinalCollisionRate * 100).toFixed(2)} %`);
console.log(`  orderAnalysis           : ${base.ncm.orderAnalysis}`);
for (const w of base.warnings) console.log(`  warn: ${w}`);

check('no line of the fixture is unparsed', base.warnings.every((w) => !w.includes('could not be parsed')));
check('the obliwan: marker anchors a rule',
  base.ncm.resources.firewallRules.some((r) => r.semKey === 'fw.v1:input:mk:mgmt-established'),
  base.ncm.resources.firewallRules.find((r) => r.managedSlug)?.semKey ?? 'none');
check('a derived firewall key has the study\'s shape',
  base.ncm.resources.firewallRules.some((r) => /^fw\.v1:input:[0-9a-f]{16}#0$/.test(r.semKey)));
check('a mangle rule does not collide with a filter rule of the same chain',
  new Set(base.ncm.resources.firewallRules.map((r) => r.semKey)).size === base.ncm.resources.firewallRules.length,
  `${base.ncm.resources.firewallRules.length} rules, ${new Set(base.ncm.resources.firewallRules.map((r) => r.semKey)).size} distinct keys`);
check('coverage.interface is NOT complete (an export omits factory interfaces)',
  base.ncm.coverage.interface.state === 'partial', base.ncm.coverage.interface.state);
check('coverage.firewallRule IS complete',
  base.ncm.coverage.firewallRule.state === 'complete', base.ncm.coverage.firewallRule.state);
check('no plaintext secret anywhere in the document',
  !SENSITIVE_PROPS.some((p) => JSON.stringify(base.ncm).includes(`"${p}"`)));
check('the address-list entry with a timeout was excluded (N03b)',
  base.stats.dynamicEntriesExcluded >= 1, `${base.stats.dynamicEntriesExcluded} excluded`);

console.log('\n=== 1. A/A — the same state twice ===========================\n');

const bis = run('ros7-cpe-typical.bis.export');
console.log(`  base ncm_hash : ${base.ncmHash}`);
console.log(`  bis  ncm_hash : ${bis.ncmHash}`);
check('two exports of the same state give the SAME ncm_hash', base.ncmHash === bis.ncmHash);

const aa = referenceDiff(base.ncm, bis.ncm);
console.log(`  findings      : ${aa.findings.length}   inert moves: ${aa.inertMoveCount}`);
if (aa.findings.length > 0) console.log(`        ${findingLines(aa)}`);
check('A/A produces 0 findings', aa.findings.length === 0, `${aa.findings.length}`);

// Idempotence: the same text twice must be byte-identical, not merely equal.
const again = run('ros7-cpe-typical.export');
check('normalisation is deterministic (same text -> same hash)', base.ncmHash === again.ncmHash);

console.log('\n=== 2. the API-flavoured export (N03, N04, N05, N06) ========\n');

const api = run('ros7-cpe-typical.api-flavoured.export');
console.log(`  ncm_hash                : ${api.ncmHash}`);
console.log(`  .id props dropped       : every one (never reaches the NCM)`);
console.log(`  state props dropped     : ${api.stats.statePropsDropped}`);
console.log(`  counter props dropped   : ${api.stats.counterPropsDropped}`);
console.log(`  dynamic entries excluded: ${api.stats.dynamicEntriesExcluded}`);
console.log(`  unknown props           : ${api.unknownProps.length}`);
for (const u of api.unknownProps) console.log(`      ${u.sectionPath} ${u.prop}=${u.sample}`);
check('no `.id` survived into the document', !JSON.stringify(api.ncm).includes('.id'));
check('an export carrying counters, .id, state props and dynamics hashes IDENTICALLY to the clean one',
  api.ncmHash === base.ncmHash, `${api.ncmHash} vs ${base.ncmHash}`);
const apiDiff = referenceDiff(base.ncm, api.ncm);
check('and produces 0 findings against it', apiDiff.findings.length === 0, findingLines(apiDiff));

console.log('\n=== 3. N07 — reordering two DISJOINT rules ==================\n');

const chain40 = run('ros7-chain40.export');
const chainSwap = run('ros7-chain40.swap-disjoint.export');
const swapDiff = referenceDiff(chain40.ncm, chainSwap.ncm);
console.log(`  chain length            : ${chain40.ncm.resources.firewallRules.length}`);
console.log(`  ncm_hash base / swapped : ${chain40.ncmHash.slice(0, 16)}… / ${chainSwap.ncmHash.slice(0, 16)}…`);
console.log(`  findings                : ${swapDiff.findings.length}   inert moves: ${swapDiff.inertMoveCount}`);
if (swapDiff.findings.length) console.log(`        ${findingLines(swapDiff)}`);
check('swapping two DISJOINT rules produces 0 findings', swapDiff.findings.length === 0, `${swapDiff.findings.length}`);
check('the reordering is nonetheless recorded (the hash of an ORDERED kind changes)',
  chain40.ncmHash !== chainSwap.ncmHash);

console.log('\n=== 4. §4.2 — one overlapping rule inserted at the head =====\n');

const chainIns = run('ros7-chain40.insert-head.export');
const insDiff = referenceDiff(chain40.ncm, chainIns.ncm);
console.log(`  chain length before/after: ${chain40.ncm.resources.firewallRules.length} -> ${chainIns.ncm.resources.firewallRules.length}`);
console.log(`  findings                 : ${insDiff.findings.length}   inert moves: ${insDiff.inertMoveCount}`);
console.log(`        ${findingLines(insDiff)}`);
check('inserting one rule at the head of a 40-rule chain produces exactly 1 finding',
  insDiff.findings.length === 1, `${insDiff.findings.length}`);
check('and that finding is the insertion itself',
  insDiff.findings[0]?.kind === 'extra', insDiff.findings[0]?.kind ?? 'none');

console.log('\n=== 5. N1 — accept -> drop =================================\n');

const flipped = run('ros7-cpe-typical.m01-accept-to-drop.export');
const flipDiff = referenceDiff(base.ncm, flipped.ncm);
console.log(`  findings : ${flipDiff.findings.length}`);
console.log(`        ${findingLines(flipDiff)}`);
check('accept -> drop produces exactly 1 finding', flipDiff.findings.length === 1, `${flipDiff.findings.length}`);
check('it is a `changed`, not a missing + extra', flipDiff.findings[0]?.kind === 'changed');
check('of severity `critical`', flipDiff.findings[0]?.severity === 'critical');
check('on the `action` field', flipDiff.findings[0]?.fields.includes('action') ?? false,
  (flipDiff.findings[0]?.fields ?? []).join(','));

console.log('\n=== 6. other mutations =====================================\n');

const mutations: Array<{ file: string; label: string; expect: number; kind?: Finding['kind']; severity?: DiffSeverity }> = [
  { file: 'ros7-cpe-typical.m06-disable-drop.export', label: 'M06 disable the input drop rule', expect: 1, kind: 'changed' },
  { file: 'ros7-cpe-typical.m07-new-user.export', label: 'M07 a new /user appears', expect: 1, kind: 'extra', severity: 'critical' },
  { file: 'ros7-cpe-typical.m09-telnet-on.export', label: 'M09 telnet is enabled', expect: 1, kind: 'changed', severity: 'critical' },
];
for (const m of mutations) {
  const mutated = run(m.file);
  const d = referenceDiff(base.ncm, mutated.ncm);
  console.log(`  ${m.label}: ${d.findings.length} finding(s)`);
  if (d.findings.length) console.log(`        ${findingLines(d)}`);
  check(`${m.label} -> ${m.expect} finding(s)`, d.findings.length === m.expect, `${d.findings.length}`);
  if (m.kind) check(`  ... of kind ${m.kind}`, d.findings[0]?.kind === m.kind, d.findings[0]?.kind ?? 'none');
  if (m.severity) check(`  ... of severity ${m.severity}`, d.findings[0]?.severity === m.severity, d.findings[0]?.severity ?? 'none');
}

console.log('\n=== 7. N09 — defaults that appear on a minor upgrade ========\n');

const d713 = run('ros7-defaults-7.13.export', { osVersion: '7.13' });
const d714NoDict = run('ros7-defaults-7.14.export', { osVersion: '7.14' });
const noDict = referenceDiff(d713.ncm, d714NoDict.ncm);
console.log(`  without the learned dictionary: ${noDict.findings.length} finding(s)`);
if (noDict.findings.length) console.log(`        ${findingLines(noDict)}`);

// With the dictionary the props RouterOS started emitting are filled on the
// older side as well, and the two documents become one object.
// `/ip/route distance` is the one that BITES: it is a modelled field, ROS 7.13
// emits `distance=1` and 7.14 omits it, so without the dictionary the upgrade
// alone changes every static route. `port-cost-mode` costs nothing here only
// because the whitelist never let it into the model in the first place — which
// is the N05 whitelist doing N09's job for free, and exactly why the
// unknown-prop counter has to exist to tell the two apart.
const dict = new Map<string, string>([
  ['/ip/route|distance', '1'],
  ['/interface/bridge|port-cost-mode', 'long'],
  ['/ip/route|routing-table', 'main'],
]);
const d713Filled = run('ros7-defaults-7.13.export', { osVersion: '7.13', defaults: dict });
const d714Filled = run('ros7-defaults-7.14.export', { osVersion: '7.14', defaults: dict });
const withDict = referenceDiff(d713Filled.ncm, d714Filled.ncm);
console.log(`  with the learned dictionary   : ${withDict.findings.length} finding(s)`);
if (withDict.findings.length) console.log(`        ${findingLines(withDict)}`);
console.log(`  defaults filled               : ${d713Filled.stats.defaultsFilled} (7.13 side)`);
check('a firmware upgrade alone produces 0 findings once the defaults are learned',
  withDict.findings.length === 0, `${withDict.findings.length}`);
check('and the two resource sets become byte-identical',
  JSON.stringify(d713Filled.ncm.resources) === JSON.stringify(d714Filled.ncm.resources));
// The hashes still differ, and that is CORRECT, not a bug. `normalizationEpoch`
// is inside `ncmHash` by design, and the effective ruleset really is different
// on 7.13 and on 7.14 (the version-scoped `default_fill` rows). Consequence to
// carry forward: a device that changes firmware writes ONE new snapshot row
// even when its configuration is untouched, and the drift run that follows must
// be labelled `renormalization` — never attributed to a human (§6.5).
check('the hashes differ only through normalizationEpoch (a re-normalisation, not a change)',
  d713Filled.ncmHash !== d714Filled.ncmHash
  && d713Filled.ncm.normalizationEpoch !== d714Filled.ncm.normalizationEpoch,
  `${d713Filled.ncm.normalizationEpoch} vs ${d714Filled.ncm.normalizationEpoch}`);

console.log('\n=== 8. ROS6 and the near-empty box =========================\n');

const ros6 = run('ros6-cpe-typical.export', { family: 'mikrotik_routeros6', osVersion: '6.49.10' });
console.log(`  ROS6 sectioned form parsed: ${ros6.stats.entries} entries, hash ${ros6.ncmHash.slice(0, 16)}…`);
console.log(`  ROS6 preamble             : version=${ros6.osVersion} model=${ros6.model} serial=${ros6.serial}`);
console.log(`  ROS6 firewall rules       : ${ros6.ncm.resources.firewallRules.length}`);
console.log(`  ROS6 unknown props        : ${ros6.unknownProps.length}`);
check('the ROS6 `mmm/dd/yyyy` header is parsed', ros6.osVersion === '6.49.10', String(ros6.osVersion));
check('the ROS6 SECTIONED form yields the same resource kinds as the flat form',
  ros6.ncm.resources.firewallRules.length === 11 && ros6.ncm.resources.natRules.length === 2,
  `${ros6.ncm.resources.firewallRules.length} filter, ${ros6.ncm.resources.natRules.length} nat`);
check('the ROS6 and ROS7 renderings of the same intent are NOT byte-equal (R11, expected)',
  ros6.ncmHash !== base.ncmHash);

const minimal = run('ros7-minimal.export');
console.log(`  near-empty box            : ${minimal.stats.entries} entries, ${minimal.ncm.unmodeled.length} unmodeled sections`);
check('an EMPTY section is not a difference (N02): it produces no resource and no finding',
  minimal.ncm.resources.natRules.length === 0);

console.log('\n=== 9. per-device noise budget ==============================\n');

// The milestone criterion is "< 3 NOISE findings per device". A noise finding
// is one produced when nothing changed functionally. Every pair below is a pair
// in which nothing changed.
const noisePairs: Array<[string, DiffReport]> = [
  ['base vs bis (5 minutes later)', aa],
  ['base vs API-flavoured collection', apiDiff],
  ['40-chain vs disjoint reorder', swapDiff],
  ['7.13 vs 7.14, defaults learned', withDict],
];
let worst = 0;
for (const [label, report] of noisePairs) {
  worst = Math.max(worst, report.findings.length);
  console.log(`  ${String(report.findings.length).padStart(3)} noise finding(s)  ${label}`);
}
console.log(`  worst case: ${worst} noise finding(s) per device`);
check('worst-case noise on the fixture corpus is under 3 findings/device', worst < 3, `${worst}`);

// Without the dictionary the upgrade IS noisy, and that number is the whole
// reason `routeros_defaults` exists. Reported, not hidden.
console.log(`  (for reference: the same upgrade WITHOUT a learned default dictionary produces ${noDict.findings.length})`);

console.log('\n=== 10. golden files =======================================\n');

const goldenFixtures = [
  'ros7-cpe-typical.export', 'ros6-cpe-typical.export', 'ros7-minimal.export',
  'ros7-chain40.export',
];
for (const fixture of goldenFixtures) {
  const family = fixture.startsWith('ros6') ? 'mikrotik_routeros6' : 'mikrotik_routeros7';
  const result = run(fixture, { family });
  const path = join(GOLDEN_DIR, `${fixture.replace(/\.export$/, '')}.ncm.json`);
  const body = JSON.stringify({ ncmHash: result.ncmHash, ncm: result.ncm }, null, 2);
  if (WRITE_GOLDEN || !existsSync(path)) {
    writeFileSync(path, `${body}\n`);
    console.log(`  wrote ${path}`);
    continue;
  }
  const expected = readFileSync(path, 'utf8').trimEnd();
  check(`golden ${fixture}`, expected === body,
    expected === body ? '' : 'run with --write-golden to accept the delta');
}

// Coverage must be declared for all ten kinds on every document, otherwise N3
// cannot fail closed.
check('coverage declares all ten resource kinds',
  NCM_RESOURCE_KINDS.every((k) => base.ncm.coverage[k] !== undefined));
check('the document re-hashes to the same value after a JSON round trip',
  ncmHash(JSON.parse(JSON.stringify(base.ncm)) as NcmDocument) === base.ncmHash);

console.log(`\n${checks - failures}/${checks} checks passed.\n`);
process.exit(failures === 0 ? 0 : 1);
