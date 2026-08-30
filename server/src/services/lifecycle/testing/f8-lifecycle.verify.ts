/**
 * ObliWAN F8 — End-of-Life Inventory, verified against a real PostgreSQL.
 *
 * WHAT THIS FILE PROVES, AND WHAT IT CANNOT
 *
 * It proves the RULE: the model normalisation, the firmware version parser, the
 * longest-specific match, the two derivations, the priority mapping, the
 * aggregate, the tenant isolation of the one query that reads customer data,
 * and the schema-level catches of migration 027 — the partial unique indexes,
 * the chronology CHECK, the normalised-pattern CHECK and the source CHECK are
 * all live here, and several assertions exist only to make the database refuse
 * something.
 *
 * It proves NOTHING about any vendor's actual dates. Every dated row below is a
 * FIXTURE invented by this test. The seeded catalogue in migration 027 is
 * checked for SHAPE — it exists, it cites sources, and its undated rows produce
 * `unknown` rather than `supported` — and never for factual accuracy, which no
 * test on this machine could establish. That is the honest limit of an offline
 * harness against a catalogue of external facts.
 *
 * THE THREE ACCEPTANCE CHECKS OF THE BRIEF ARE VERIFIED VERBATIM:
 *   firmware older than an end-of-support date   -> flagged
 *   model unknown to the catalogue               -> "unknown", NEVER "supported"
 *   tenant scope on every read                   -> another customer's fleet is
 *                                                   invisible and its device id
 *                                                   is a 404
 *
 *   DATABASE_URL=… npx tsx src/services/lifecycle/testing/f8-lifecycle.verify.ts
 */

import {
  FIRMWARE_SEVERITY, LIFECYCLE_SEVERITY, LifecycleCatalogError, RENEWAL_WATCH_DAYS,
  assessDevice, catalogGaps, compareVersions, daysBetween, deriveFirmwareStatus,
  deriveModelStatus, isIsoDate, matchFirmwareEntry, matchModelEntry, normalizeModelKey,
  parseVersion, renewalPriorityOf, summarizeLifecycle, validateFirmwareEntry,
  validateModelEntry, versionInBranch, worstStatus,
  firmwareCatalogEntrySchema, modelCatalogEntrySchema,
  type FirmwareCatalogEntry, type LifecycleCatalog, type LifecycleDeviceInput,
  type ModelCatalogEntry,
} from '@obliwan/shared/dist/lifecycle';
import { CAPABILITIES } from '@obliwan/shared';
import { db } from '../../../db';
import {
  clearLifecycleCatalogCache, deleteCatalogEntry, getCatalogGaps, getDeviceLifecycle,
  getInventory, getLifecycleCatalog, getLifecycleSummary, importFirmwareEntries,
  importModelEntries, listCatalogImports, serverToday,
} from '../index';
import { AppError } from '../../../middleware/errorHandler';
import { permissionService } from '../../permission.service';
import lifecycleRoutes from '../../../routes/lifecycle.routes';

const TENANT = 1;
const OTHER_TENANT = 2;

/** A fixed "today" for the pure assertions. Everything dated in this file is
 *  positioned relative to it, so no assertion in the offline block can rot. */
const NOW = '2026-06-15';

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

function refusesSync(label: string, fn: () => unknown, needle: string): void {
  try {
    fn();
    ok(label, false, 'it was accepted');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    ok(label, message.toLowerCase().includes(needle.toLowerCase()), message.slice(0, 160));
  }
}

function section(title: string): void {
  console.log(`\n${title}\n${'-'.repeat(title.length)}`);
}

// ============================================================================
// Fixtures
// ============================================================================

let nextId = 1000;

function modelEntry(over: Partial<ModelCatalogEntry> = {}): ModelCatalogEntry {
  return {
    id: (nextId += 1),
    brand: 'sonicwall',
    modelPattern: 'TZ215',
    matchMode: 'exact',
    modelLabel: 'Test TZ 215',
    endOfSale: null,
    endOfSoftwareSupport: null,
    endOfSupport: null,
    declaredStatus: null,
    replacement: null,
    sourceKind: 'manual',
    source: 'F8 harness fixture',
    sourceUrl: null,
    verifiedAt: '2026-01-01',
    note: null,
    ...over,
  };
}

function firmwareEntry(over: Partial<FirmwareCatalogEntry> = {}): FirmwareCatalogEntry {
  return {
    id: (nextId += 1),
    brand: 'mikrotik',
    family: 'mikrotik_routeros6',
    branch: '6',
    branchLabel: 'Test RouterOS 6',
    minSupportedVersion: null,
    endOfSupport: null,
    declaredStatus: null,
    sourceKind: 'manual',
    source: 'F8 harness fixture',
    sourceUrl: null,
    verifiedAt: '2026-01-01',
    note: null,
    ...over,
  };
}

function device(over: Partial<LifecycleDeviceInput> = {}): LifecycleDeviceInput {
  return {
    deviceId: 1,
    name: 'test-router',
    siteId: null,
    siteName: null,
    brand: 'mikrotik',
    family: 'mikrotik_routeros6',
    model: 'RB2011UiAS-RM',
    osVersion: '6.48.6',
    ...over,
  };
}

// ============================================================================
// 1. Offline — normalisation and version arithmetic
// ============================================================================

function offlinePrimitiveTests(): void {
  section('1. Model keys and firmware versions (pure, no database)');

  ok('a model key is uppercased and stripped to A-Z0-9',
    normalizeModelKey('RB2011UiAS-RM') === 'RB2011UIASRM');
  ok('…and the same box typed with spaces produces the SAME key',
    normalizeModelKey('rb 2011 UiAS/RM') === normalizeModelKey('RB2011UiAS-RM'),
    `${normalizeModelKey('rb 2011 UiAS/RM')}`);
  ok('…a string with no letters or digits normalises to null',
    normalizeModelKey('  --  ') === null);
  ok('…and so do null and undefined',
    normalizeModelKey(null) === null && normalizeModelKey(undefined) === null);

  const cases: Array<[string, number[] | null]> = [
    ['7.14.3', [7, 14, 3]],
    ['6.49.10', [6, 49, 10]],
    ['7.14.3 (stable)', [7, 14, 3]],
    ['v7.14', [7, 14]],
    ['4.4.5.1', [4, 4, 5, 1]],
    ['V5.30(ABUV.0)C0', [5, 30]],
    ['6.5.4.8-89n', [6, 5, 4, 8]],
    ['RouterOS 7.1', null],
    ['', null],
    ['unknown', null],
  ];
  for (const [raw, expected] of cases) {
    const got = parseVersion(raw);
    ok(`parseVersion(${JSON.stringify(raw)}) = ${JSON.stringify(expected)}`,
      JSON.stringify(got) === JSON.stringify(expected), JSON.stringify(got));
  }

  ok('6.49.10 is NEWER than 6.49.2 (numeric, not lexicographic)',
    compareVersions([6, 49, 10], [6, 49, 2]) > 0);
  ok('7.14 and 7.14.0 are the same release',
    compareVersions([7, 14], [7, 14, 0]) === 0);
  ok('6.48.6 is older than 6.49', compareVersions([6, 48, 6], [6, 49]) < 0);

  ok('6.49.10 is inside branch 6', versionInBranch([6, 49, 10], '6'));
  ok('6.49.10 is inside branch 6.49', versionInBranch([6, 49, 10], '6.49'));
  ok('6.48.6 is NOT inside branch 6.49', !versionInBranch([6, 48, 6], '6.49'));
  ok('7.14.3 is NOT inside branch 6', !versionInBranch([7, 14, 3], '6'));
  ok('a malformed branch matches NOTHING rather than everything',
    !versionInBranch([6, 49], 'six'));

  ok('2026-02-30 is refused as a calendar date', !isIsoDate('2026-02-30'));
  ok('2024-02-29 is accepted (leap year)', isIsoDate('2024-02-29'));
  ok('daysBetween is signed', daysBetween('2026-06-15', '2026-06-25') === 10
    && daysBetween('2026-06-25', '2026-06-15') === -10);
}

// ============================================================================
// 2. Offline — the matcher
// ============================================================================

function offlineMatchTests(): void {
  section('2. Longest-specific match, deterministic (pure)');

  const broad = modelEntry({ id: 1, brand: 'zyxel', modelPattern: 'USG110', matchMode: 'prefix' });
  const narrow = modelEntry({ id: 2, brand: 'zyxel', modelPattern: 'USG1100', matchMode: 'prefix' });
  ok('USG1100 matches the LONGER prefix, not USG110',
    matchModelEntry('zyxel', 'USG 1100', [broad, narrow])?.id === 2);
  ok('USG110 still matches its own row',
    matchModelEntry('zyxel', 'USG 110', [broad, narrow])?.id === 1);

  const prefix = modelEntry({ id: 3, brand: 'draytek', modelPattern: 'VIGOR29', matchMode: 'prefix' });
  const exact = modelEntry({ id: 4, brand: 'draytek', modelPattern: 'VIGOR2925', matchMode: 'exact' });
  ok('an EXACT row beats a longer-lived prefix row',
    matchModelEntry('draytek', 'Vigor2925', [prefix, exact])?.id === 4);
  ok('…and the order the rows arrive in changes nothing',
    matchModelEntry('draytek', 'Vigor2925', [exact, prefix])?.id === 4);
  ok('a device of another brand never matches',
    matchModelEntry('mikrotik', 'Vigor2925', [prefix, exact]) === null);
  ok('a device with no model matches nothing',
    matchModelEntry('draytek', null, [prefix, exact]) === null);

  const wide = firmwareEntry({ id: 5, family: null, branch: '6' });
  const deep = firmwareEntry({ id: 6, family: 'mikrotik_routeros6', branch: '6.49' });
  const famWide = firmwareEntry({ id: 7, family: 'mikrotik_routeros6', branch: '6' });
  ok('the family-specific branch beats the family-wide one',
    matchFirmwareEntry('mikrotik', 'mikrotik_routeros6', [6, 48, 1], [wide, famWide])?.id === 7);
  ok('…and the deeper branch beats the shallower one',
    matchFirmwareEntry('mikrotik', 'mikrotik_routeros6', [6, 49, 10], [famWide, deep])?.id === 6);
  ok('a version outside every branch matches nothing',
    matchFirmwareEntry('mikrotik', 'mikrotik_routeros6', [7, 14], [famWide, deep]) === null);
  ok('an unparseable version matches nothing',
    matchFirmwareEntry('mikrotik', 'mikrotik_routeros6', null, [wide, famWide, deep]) === null);
}

// ============================================================================
// 3. Offline — THE INVARIANT: `supported` needs a cited future date
// ============================================================================

function offlineVerdictTests(): void {
  section('3. THE INVARIANT — nothing is `supported` without a cited future date');

  // -- ACCEPTANCE CHECK 2: a model the catalogue does not know --------------
  const noEntry = deriveModelStatus(null, true, NOW);
  ok('ACCEPTANCE — an unknown model is `unknown`', noEntry.status === 'unknown', noEntry.status);
  ok('…with the reason `no_catalog_entry`', noEntry.reason === 'no_catalog_entry');
  ok('…and NO citation to wave at a customer', noEntry.citation === null);

  const noModel = deriveModelStatus(null, false, NOW);
  ok('a device with no model recorded is `unknown` too', noModel.status === 'unknown');
  ok('…and says WHICH kind of unknown', noModel.reason === 'no_model_recorded');

  // The stronger form of the same promise: no input at all produces
  // `supported` from an empty catalogue. Exhaustive over the fixture space.
  const emptyCatalog: LifecycleCatalog = { models: [], firmware: [] };
  let anySupported = false;
  for (const model of [null, 'RB2011UiAS-RM', 'TZ215', 'zzz', '']) {
    for (const osVersion of [null, '6.49.10', '7.14.3', 'RouterOS 7', '']) {
      const a = assessDevice(device({ model, osVersion }), emptyCatalog, NOW);
      if (a.hardware.status === 'supported' || a.firmware.status === 'supported') {
        anySupported = true;
      }
    }
  }
  ok('ACCEPTANCE — an EMPTY catalogue calls nothing `supported`, on any input', !anySupported);

  // -- the dated ladder -----------------------------------------------------
  const past = modelEntry({ endOfSale: '2020-01-01', endOfSoftwareSupport: '2022-01-01', endOfSupport: '2024-01-01' });
  ok('all three boundaries passed -> end_of_life',
    deriveModelStatus(past, true, NOW).status === 'end_of_life');
  const softOnly = modelEntry({ endOfSale: '2020-01-01', endOfSoftwareSupport: '2022-01-01', endOfSupport: '2030-01-01' });
  ok('software support passed, hardware support ahead -> end_of_support',
    deriveModelStatus(softOnly, true, NOW).status === 'end_of_support');
  const saleOnly = modelEntry({ endOfSale: '2020-01-01', endOfSoftwareSupport: '2028-01-01' });
  ok('only end of sale passed -> end_of_sale',
    deriveModelStatus(saleOnly, true, NOW).status === 'end_of_sale');
  const ahead = modelEntry({ endOfSale: '2028-01-01', endOfSupport: '2031-01-01' });
  const aheadVerdict = deriveModelStatus(ahead, true, NOW);
  ok('every boundary ahead -> supported', aheadVerdict.status === 'supported');
  ok('…and it cites the source it is supported by', aheadVerdict.citation?.source === 'F8 harness fixture');
  ok('…and reports the days to the NEAREST boundary',
    aheadVerdict.daysUntilNextBoundary === daysBetween(NOW, '2028-01-01'),
    String(aheadVerdict.daysUntilNextBoundary));

  const noDates = modelEntry({ note: 'the vendor publishes nothing' });
  const noDatesVerdict = deriveModelStatus(noDates, true, NOW);
  ok('an entry with a source but NO date is `unknown`, not `supported`',
    noDatesVerdict.status === 'unknown', noDatesVerdict.status);
  ok('…and it still carries its citation, so nobody researches it twice',
    noDatesVerdict.citation !== null && noDatesVerdict.reason === 'no_dates_published');

  // -- the undated declaration can only make things worse -------------------
  const declared = modelEntry({ declaredStatus: 'end_of_support' });
  ok('an undated vendor declaration is honoured',
    deriveModelStatus(declared, true, NOW).status === 'end_of_support');
  ok('…and says so as its reason',
    deriveModelStatus(declared, true, NOW).reason === 'vendor_declared');
  const mixed = modelEntry({ endOfSale: '2020-01-01', declaredStatus: 'end_of_life' });
  ok('a declaration WORSE than the dated verdict wins',
    deriveModelStatus(mixed, true, NOW).status === 'end_of_life');
  const mixed2 = modelEntry({ endOfSoftwareSupport: '2022-01-01', declaredStatus: 'end_of_sale' });
  ok('a declaration MILDER than the dated verdict does NOT soften it',
    deriveModelStatus(mixed2, true, NOW).status === 'end_of_support');
  const futureWithDeclaration = modelEntry({ endOfSupport: '2031-01-01', declaredStatus: 'end_of_sale' });
  ok('a declaration can even overrule a future date — it can never be softened by one',
    deriveModelStatus(futureWithDeclaration, true, NOW).status === 'end_of_sale');

  ok('`unknown` outranks `supported` in the severity order',
    LIFECYCLE_SEVERITY.unknown > LIFECYCLE_SEVERITY.supported
    && FIRMWARE_SEVERITY.unknown > FIRMWARE_SEVERITY.supported);
  ok('worstStatus takes the more severe of two',
    worstStatus('supported', 'end_of_sale') === 'end_of_sale'
    && worstStatus('end_of_life', 'end_of_support') === 'end_of_life');
}

// ============================================================================
// 4. Offline — the firmware verdict
// ============================================================================

function offlineFirmwareTests(): void {
  section('4. Firmware: an end-of-support date in the past is flagged');

  // -- ACCEPTANCE CHECK 1 ---------------------------------------------------
  const deadBranch = firmwareEntry({ endOfSupport: '2024-03-01', branchLabel: 'Test RouterOS 6' });
  const dead = deriveFirmwareStatus(deadBranch, '6.49.10', NOW);
  ok('ACCEPTANCE — a firmware whose branch end-of-support has passed is `unsupported`',
    dead.status === 'unsupported', dead.status);
  ok('…for the stated reason', dead.reason === 'past_branch_end_of_support');
  ok('…and it names the date, so it can be read out loud',
    dead.detail.includes('2024-03-01'), dead.detail);
  ok('…and the LATEST release of a dead branch is still unsupported, never `supported`',
    deriveFirmwareStatus(deadBranch, '6.49.99', NOW).status === 'unsupported');

  const liveBranch = firmwareEntry({ endOfSupport: '2028-01-01', minSupportedVersion: '6.49' });
  ok('a live branch, at or above the floor -> supported',
    deriveFirmwareStatus(liveBranch, '6.49.10', NOW).status === 'supported');
  const behind = deriveFirmwareStatus(liveBranch, '6.48.6', NOW);
  ok('a live branch, BELOW the floor -> outdated', behind.status === 'outdated', behind.status);
  ok('…and it names the release to install',
    behind.detail.includes('6.49') && behind.reason === 'below_min_supported_version');

  const floorOnly = firmwareEntry({ minSupportedVersion: '6.49' });
  ok('a floor with no date: below it is still `outdated`',
    deriveFirmwareStatus(floorOnly, '6.48.6', NOW).status === 'outdated');
  ok('…but AT or above it is `unknown`, NOT `supported` — there is no date to cite',
    deriveFirmwareStatus(floorOnly, '6.49.10', NOW).status === 'unknown',
    deriveFirmwareStatus(floorOnly, '6.49.10', NOW).status);
  ok('…and it says why',
    deriveFirmwareStatus(floorOnly, '6.49.10', NOW).reason === 'no_end_of_support_published');

  const declaredDead = firmwareEntry({ declaredStatus: 'end_of_support' });
  ok('an undated vendor declaration kills the branch',
    deriveFirmwareStatus(declaredDead, '6.49.10', NOW).status === 'unsupported');

  ok('no version recorded -> unknown',
    deriveFirmwareStatus(liveBranch, null, NOW).status === 'unknown');
  ok('an unparseable version -> unknown, and it says so rather than guessing',
    deriveFirmwareStatus(liveBranch, 'RouterOS v6', NOW).reason === 'version_unparseable');
  ok('no branch entry -> unknown',
    deriveFirmwareStatus(null, '6.49.10', NOW).reason === 'no_branch_entry');
}

// ============================================================================
// 5. Offline — priority, aggregate, gaps
// ============================================================================

function offlineAggregateTests(): void {
  section('5. Renewal priority, summary and the research list (pure)');

  const dead = deriveModelStatus(modelEntry({ endOfSoftwareSupport: '2022-01-01' }), true, NOW);
  const fine = deriveModelStatus(modelEntry({ endOfSupport: '2035-01-01' }), true, NOW);
  const sale = deriveModelStatus(modelEntry({ endOfSale: '2020-01-01', endOfSupport: '2031-01-01' }), true, NOW);
  const soon = deriveModelStatus(modelEntry({ endOfSupport: '2026-09-01' }), true, NOW);
  const fwDead = deriveFirmwareStatus(firmwareEntry({ endOfSupport: '2024-01-01' }), '6.49.1', NOW);
  const fwFine = deriveFirmwareStatus(firmwareEntry({ endOfSupport: '2035-01-01' }), '6.49.1', NOW);
  const fwOld = deriveFirmwareStatus(
    firmwareEntry({ endOfSupport: '2035-01-01', minSupportedVersion: '6.49' }), '6.48.1', NOW);
  const fwUnknown = deriveFirmwareStatus(null, '9.9', NOW);

  ok('hardware past software support -> urgent', renewalPriorityOf(dead, fwFine) === 'urgent');
  ok('firmware branch dead -> urgent', renewalPriorityOf(fine, fwDead) === 'urgent');
  ok('end of sale only -> plan', renewalPriorityOf(sale, fwFine) === 'plan');
  ok('firmware behind the floor -> plan', renewalPriorityOf(fine, fwOld) === 'plan');
  ok('either axis unknown -> unknown, never `none`',
    renewalPriorityOf(fine, fwUnknown) === 'unknown');
  ok(`a cited boundary inside ${RENEWAL_WATCH_DAYS} days -> watch`,
    renewalPriorityOf(soon, fwFine) === 'watch');
  ok('both cited and comfortably far -> none', renewalPriorityOf(fine, fwFine) === 'none');

  const catalog: LifecycleCatalog = {
    models: [modelEntry({ brand: 'sonicwall', modelPattern: 'TZ215', declaredStatus: 'end_of_life' })],
    firmware: [firmwareEntry({ endOfSupport: '2024-01-01' })],
  };
  const fleet = [
    device({ deviceId: 1, brand: 'sonicwall', family: 'sonicwall_sonicos', model: 'TZ 215', osVersion: '6.5.4.8-89n' }),
    device({ deviceId: 2, model: 'RB2011UiAS-RM', osVersion: '6.48.6' }),
    device({ deviceId: 3, model: 'RB2011UiAS-RM', osVersion: '6.48.6' }),
    device({ deviceId: 4, model: null, osVersion: null }),
  ];
  const assessed = fleet.map((d) => assessDevice(d, catalog, NOW));
  const summary = summarizeLifecycle(assessed, NOW);

  ok('the summary counts the whole fleet', summary.devicesTotal === 4);
  ok('…one device is end_of_life', summary.byHardwareStatus.end_of_life === 1);
  ok('…three are unknown', summary.byHardwareStatus.unknown === 3, String(summary.byHardwareStatus.unknown));
  ok('…and NOT ONE is `supported`', summary.byHardwareStatus.supported === 0);
  ok('coverage reports how thin the catalogue actually is',
    summary.coverage.hardwareCited === 1 && summary.coverage.hardwareCitedPct === 25,
    `${summary.coverage.hardwareCited}/${summary.coverage.hardwareCitedPct}%`);
  // All four: the TZ215 has a hardware citation but no firmware branch covers
  // SonicOS in this fixture catalogue, and `needsResearch` counts a device
  // when EITHER axis is uncited. That asymmetry is deliberate — a box we can
  // only half vouch for is still a box somebody has to look at.
  ok('…and how many devices need a human to research them (either axis uncited)',
    summary.needsResearch === 4, String(summary.needsResearch));

  const gaps = catalogGaps(assessed);
  ok('the research list groups the two identical RB2011 into one line',
    gaps[0]?.deviceCount === 2 && gaps[0]?.modelKey === 'RB2011UIASRM',
    JSON.stringify(gaps.map((g) => [g.modelKey, g.deviceCount])));
  ok('…and the device with no model at all is a separate, honest line',
    gaps.some((g) => g.modelKey === null));
  ok('…while the model that IS cited is absent from it',
    !gaps.some((g) => g.modelKey === 'TZ215'));
}

// ============================================================================
// 6. Offline — catalogue validation
// ============================================================================

function offlineValidationTests(): void {
  section('6. A catalogue entry without a source is a rumour (pure)');

  const base = {
    brand: 'draytek' as const,
    model: 'Vigor2925',
    modelLabel: 'DrayTek Vigor 2925',
    source: 'DrayTek EOL list',
    verifiedAt: '2026-01-01',
    declaredStatus: 'end_of_support' as const,
  };

  ok('a well-formed entry parses', modelCatalogEntrySchema.safeParse(base).success);
  ok('an entry with NO source is refused',
    !modelCatalogEntrySchema.safeParse({ ...base, source: undefined }).success);
  ok('an entry whose source is whitespace is refused',
    !modelCatalogEntrySchema.safeParse({ ...base, source: '   ' }).success);
  ok('an entry with no verifiedAt is refused',
    !modelCatalogEntrySchema.safeParse({ ...base, verifiedAt: undefined }).success);
  ok('a verifiedAt that is not a calendar date is refused',
    !modelCatalogEntrySchema.safeParse({ ...base, verifiedAt: '2026-02-30' }).success);
  ok('an UNKNOWN KEY is refused rather than ignored (.strict)',
    !modelCatalogEntrySchema.safeParse({ ...base, asOf: '2000-01-01' }).success);
  ok('`declaredStatus: supported` is not even representable',
    !modelCatalogEntrySchema.safeParse({ ...base, declaredStatus: 'supported' }).success);

  refusesSync('a model entry whose dates are out of order is refused',
    () => validateModelEntry(modelCatalogEntrySchema.parse({
      ...base, declaredStatus: null, endOfSale: '2028-01-01', endOfSoftwareSupport: '2022-01-01',
    })), 'is after');
  refusesSync('a model entry with no date, no declaration AND no note is refused',
    () => validateModelEntry(modelCatalogEntrySchema.parse({ ...base, declaredStatus: null })),
    'must carry a note');
  validateModelEntry(modelCatalogEntrySchema.parse({
    ...base, declaredStatus: null, note: 'DrayTek publishes no date for this model.',
  }));
  ok('…but the same entry WITH a note is accepted — "unknown" is a real answer', true);

  const fw = {
    brand: 'mikrotik' as const,
    family: 'mikrotik_routeros6' as const,
    branch: '6',
    branchLabel: 'RouterOS 6',
    source: 'MikroTik',
    verifiedAt: '2026-01-01',
    minSupportedVersion: '6.49',
  };
  ok('a well-formed firmware entry parses', firmwareCatalogEntrySchema.safeParse(fw).success);
  ok('a non-numeric branch is refused',
    !firmwareCatalogEntrySchema.safeParse({ ...fw, branch: 'v6' }).success);
  refusesSync('a floor OUTSIDE its own branch is refused',
    () => validateFirmwareEntry(firmwareCatalogEntrySchema.parse({ ...fw, minSupportedVersion: '7.14' })),
    'not inside branch');
  refusesSync('a firmware entry that can only ever say `unknown`, with no note, is refused',
    () => validateFirmwareEntry(firmwareCatalogEntrySchema.parse({
      ...fw, minSupportedVersion: null,
    })), 'must carry a note');

  ok('LifecycleCatalogError is the error type callers can map to a 400',
    (() => {
      try {
        validateFirmwareEntry(firmwareCatalogEntrySchema.parse({ ...fw, minSupportedVersion: '7.14' }));
        return false;
      } catch (e) { return e instanceof LifecycleCatalogError; }
    })());
}

// ============================================================================
// 7. Database — the schema refusals of migration 027
// ============================================================================

async function schemaTests(): Promise<void> {
  section('7. Migration 027 refuses what the service layer refuses');

  await refuses('an un-normalised model_pattern is refused by the CHECK',
    () => db('lifecycle_models').insert({
      brand: 'draytek', model_pattern: 'Vigor-2925', match_mode: 'exact',
      model_label: 'x', source: 's', verified_at: '2026-01-01',
    }), 'lifecycle_models_pattern_chk');

  await refuses('a whitespace source is refused by the CHECK',
    () => db('lifecycle_models').insert({
      brand: 'draytek', model_pattern: 'VIGORX', match_mode: 'exact',
      model_label: 'x', source: '   ', verified_at: '2026-01-01',
    }), 'lifecycle_models_source_chk');

  await refuses('a NULL verified_at is refused',
    () => db('lifecycle_models').insert({
      brand: 'draytek', model_pattern: 'VIGORY', match_mode: 'exact',
      model_label: 'x', source: 's',
    }), 'verified_at');

  await refuses('dates out of chronological order are refused by the CHECK',
    () => db('lifecycle_models').insert({
      brand: 'draytek', model_pattern: 'VIGORZ', match_mode: 'exact', model_label: 'x',
      source: 's', verified_at: '2026-01-01',
      end_of_sale: '2028-01-01', end_of_software_support: '2022-01-01',
    }), 'chronology');

  await refuses("declared_status = 'supported' is refused by the CHECK",
    () => db('lifecycle_models').insert({
      brand: 'draytek', model_pattern: 'VIGORW', match_mode: 'exact', model_label: 'x',
      source: 's', verified_at: '2026-01-01', declared_status: 'supported',
    }), 'declared_chk');

  await refuses('a floor outside its branch is refused by the CHECK',
    () => db('lifecycle_firmware').insert({
      brand: 'mikrotik', family: 'mikrotik_routeros6', branch: '6', branch_label: 'x',
      min_supported_version: '7.14', source: 's', verified_at: '2026-01-01',
    }), 'minver_in_branch');

  // -- THE PARTIAL UNIQUE INDEXES (decision 3) ------------------------------
  await db('lifecycle_firmware').insert({
    brand: 'zyxel', family: null, branch: '99', branch_label: 'partial-index probe',
    declared_status: 'end_of_support', source: 'probe', verified_at: '2026-01-01',
  });
  await refuses('a SECOND family-wide row for the same brand+branch is refused — ' +
    'the WHERE family IS NULL partial index is what makes NULLS DISTINCT harmless',
    () => db('lifecycle_firmware').insert({
      brand: 'zyxel', family: null, branch: '99', branch_label: 'duplicate',
      declared_status: 'end_of_support', source: 'probe', verified_at: '2026-01-01',
    }), 'anyfamily_uniq');

  await db('lifecycle_firmware').insert({
    brand: 'zyxel', family: 'zyxel_cpe', branch: '99', branch_label: 'family-specific probe',
    declared_status: 'end_of_support', source: 'probe', verified_at: '2026-01-01',
  });
  ok('…while a FAMILY-SPECIFIC row for the same brand+branch is still allowed', true);
  await refuses('…and duplicating THAT one is refused too',
    () => db('lifecycle_firmware').insert({
      brand: 'zyxel', family: 'zyxel_cpe', branch: '99', branch_label: 'duplicate',
      declared_status: 'end_of_support', source: 'probe', verified_at: '2026-01-01',
    }), 'branch_uniq');

  await db('lifecycle_firmware').where('branch', '99').del();

  // -- the seeded catalogue, checked for SHAPE only -------------------------
  const seeded = await db('lifecycle_models').where('source_kind', 'builtin').count<[{ count: string }]>('* as count');
  ok('migration 027 seeded a builtin model catalogue', Number(seeded[0].count) > 0, `${seeded[0].count} rows`);
  const unsourced = await db('lifecycle_models')
    .whereRaw("btrim(source) = ''").orWhereNull('source').count<[{ count: string }]>('* as count');
  ok('…and NOT ONE seeded row lacks a source', Number(unsourced[0].count) === 0);
  const fwSeeded = await db('lifecycle_firmware').where('source_kind', 'builtin').count<[{ count: string }]>('* as count');
  ok('…and a builtin firmware catalogue too', Number(fwSeeded[0].count) > 0, `${fwSeeded[0].count} rows`);
  const noNote = await db('lifecycle_models')
    .whereNull('end_of_sale').whereNull('end_of_software_support').whereNull('end_of_support')
    .whereNull('declared_status').whereNull('note').count<[{ count: string }]>('* as count');
  ok('…and no seeded row is a blank that inflates coverage while saying nothing',
    Number(noNote[0].count) === 0);
}

// ============================================================================
// 8. Database — the real fleet, the real tenant scope
// ============================================================================

interface SeededDevice { id: number; name: string }

async function seedTenants(): Promise<void> {
  await db('tenants')
    .insert([
      { id: TENANT, name: 'Default', slug: 'default' },
      { id: OTHER_TENANT, name: 'Other MSP customer', slug: 'other' },
    ])
    .onConflict('id')
    .ignore();
}

async function seedDevice(
  tenantId: number, name: string, brand: string, family: string,
  model: string | null, osVersion: string | null, siteId: number | null = null,
): Promise<SeededDevice> {
  const [row] = await db('devices')
    .insert({
      tenant_id: tenantId, site_id: siteId, name, brand, family,
      model, os_version: osVersion, role: 'cpe', status: 'active', is_managed: true,
    })
    .returning<Array<{ id: number }>>('id');
  return { id: row.id, name };
}

async function resetFleet(): Promise<void> {
  await db('devices').del();
  await db('sites').del();
}

async function fleetTests(): Promise<void> {
  section('8. The renewal list over a real fleet, scoped by tenant');

  await seedTenants();
  await resetFleet();
  clearLifecycleCatalogCache();

  const [siteA] = await db('sites')
    .insert({ tenant_id: TENANT, code: 'SIEGE', name: 'Siège A' })
    .returning<Array<{ id: number }>>('id');
  const [siteB] = await db('sites')
    .insert({ tenant_id: OTHER_TENANT, code: 'SIEGE', name: 'Siège B' })
    .returning<Array<{ id: number }>>('id');

  // Customer A: one retired SonicWall, one discontinued MikroTik on an old
  // RouterOS 6, one box the catalogue has never heard of.
  const tz = await seedDevice(TENANT, 'a-fw-01', 'sonicwall', 'sonicwall_sonicos', 'TZ 215', '5.9.1.7', siteA.id);
  const rb = await seedDevice(TENANT, 'a-rtr-01', 'mikrotik', 'mikrotik_routeros6', 'RB2011UiAS-RM', '6.48.6', siteA.id);
  const mystery = await seedDevice(TENANT, 'a-rtr-02', 'mikrotik', 'mikrotik_routeros7', 'CCR2216-1G-12XS-2XQ', '7.14.3', siteA.id);
  // Customer B: same shapes, different customer.
  const otherTz = await seedDevice(OTHER_TENANT, 'b-fw-01', 'sonicwall', 'sonicwall_sonicos', 'TZ 215', '5.9.1.7', siteB.id);

  const page = await getInventory(TENANT);
  ok('the inventory returns EXACTLY this tenant\'s three devices',
    page.total === 3, `${page.total}`);
  ok('…and customer B\'s firewall is not among them',
    !page.items.some((i) => i.device.deviceId === otherTz.id));
  ok('…and its site name is customer A\'s, joined on id AND tenant',
    page.items.every((i) => i.device.siteName === 'Siège A'));

  const first = page.items[0];
  ok('the worst device sorts first', first.priority === 'urgent', first.priority);

  const tzRow = page.items.find((i) => i.device.deviceId === tz.id);
  ok('the seeded TZ 215 is picked up as end_of_life by the builtin catalogue',
    tzRow?.hardware.status === 'end_of_life', tzRow?.hardware.status);
  ok('…and it cites SonicWall, not us',
    (tzRow?.hardware.citation?.source ?? '').toLowerCase().includes('sonicwall'),
    tzRow?.hardware.citation?.source);
  ok('…and it carries a replacement to quote',
    (tzRow?.hardware.replacement ?? '').length > 0, tzRow?.hardware.replacement ?? '');
  ok('…and its SonicOS 5 firmware is `unsupported` by the seeded branch row',
    tzRow?.firmware.status === 'unsupported', tzRow?.firmware.status);

  const rbRow = page.items.find((i) => i.device.deviceId === rb.id);
  ok('the RB2011 is end_of_SALE — MikroTik still ships firmware for it',
    rbRow?.hardware.status === 'end_of_sale', rbRow?.hardware.status);
  ok('…and its 6.48.6 is `outdated`, below the 6.49 long-term floor',
    rbRow?.firmware.status === 'outdated', rbRow?.firmware.status);
  ok('…which the seed states WITHOUT inventing a date',
    rbRow?.hardware.endOfSoftwareSupport === null && rbRow?.hardware.endOfSupport === null);

  const mysteryRow = page.items.find((i) => i.device.deviceId === mystery.id);
  ok('ACCEPTANCE — the CCR2216 nobody catalogued is `unknown`',
    mysteryRow?.hardware.status === 'unknown', mysteryRow?.hardware.status);
  ok('…and NEVER `supported`', mysteryRow?.hardware.status !== 'supported');
  ok('…and its RouterOS 7 firmware is `unknown` too, because MikroTik publishes no date',
    mysteryRow?.firmware.status === 'unknown', mysteryRow?.firmware.status);
  ok('…so its renewal priority is `unknown`, not `none`',
    mysteryRow?.priority === 'unknown', mysteryRow?.priority);

  const summary = await getLifecycleSummary(TENANT);
  ok('the summary agrees with the list', summary.devicesTotal === 3);
  ok('…and NOTHING in this fleet is `supported`', summary.byHardwareStatus.supported === 0);
  ok('…coverage is reported honestly',
    summary.coverage.hardwareCited === 2 && summary.needsResearch >= 1,
    JSON.stringify(summary.coverage));

  const gaps = await getCatalogGaps(TENANT);
  ok('the research list names the uncatalogued model',
    gaps.gaps.some((g) => g.modelKey === 'CCR22161G12XS2XQ'),
    JSON.stringify(gaps.gaps.map((g) => g.modelKey)));

  // -- ACCEPTANCE CHECK 3, the sharp end -----------------------------------
  const cross = await getDeviceLifecycle(TENANT, otherTz.id);
  ok('ACCEPTANCE — another customer\'s device id resolves to null (a 404, never a 403)',
    cross === null);
  const own = await getDeviceLifecycle(TENANT, tz.id);
  ok('…while this tenant\'s own device resolves', own?.device.deviceId === tz.id);
  const fromB = await getInventory(OTHER_TENANT);
  ok('customer B sees exactly one device — its own', fromB.total === 1, `${fromB.total}`);
  ok('…and it is not customer A\'s', fromB.items[0]?.device.deviceId === otherTz.id);

  // -- the filters select, they do not decide ------------------------------
  const filtered = await getInventory(TENANT, { status: ['end_of_life'] });
  ok('a status filter narrows the list', filtered.matched === 1, `${filtered.matched}`);
  ok('…while the SUMMARY still covers the whole fleet — a filter is not a fleet change',
    filtered.summary.devicesTotal === 3, `${filtered.summary.devicesTotal}`);
  const unfiltered = await getInventory(TENANT);
  const sameVerdicts = filtered.items.every((f) => {
    const u = unfiltered.items.find((x) => x.device.deviceId === f.device.deviceId);
    return u?.hardware.status === f.hardware.status && u?.priority === f.priority;
  });
  ok('…and NO filter changes a single verdict', sameVerdicts);
  const bySite = await getInventory(TENANT, { siteId: siteB.id });
  ok('filtering on ANOTHER tenant\'s site id yields nothing — the scope is upstream of the filter',
    bySite.matched === 0, `${bySite.matched}`);
}

// ============================================================================
// 9. Database — importing the catalogue
// ============================================================================

async function importTests(): Promise<void> {
  section('9. Catalogue import: journalled, idempotent, stamped `import`');

  const [admin] = await db('users')
    .insert({ username: 'f8-platform-admin', role: 'admin', is_active: true })
    .onConflict('username').merge(['role'])
    .returning<Array<{ id: number }>>('id');

  const entry = {
    brand: 'draytek', model: 'Vigor 2865', modelLabel: 'DrayTek Vigor 2865',
    endOfSale: '2030-01-01', source: 'DrayTek lifecycle page',
    sourceUrl: 'https://www.draytek.co.uk/', verifiedAt: '2026-06-01',
  };
  const bad = { brand: 'draytek', model: 'Vigor 2866', modelLabel: 'x', verifiedAt: '2026-06-01' };

  const result = await importModelEntries([entry, bad], 'draytek-2026-06', admin.id);
  ok('the good row loads', result.rowsLoaded === 1, `${result.rowsLoaded}`);
  ok('…the sourceless row is rejected, alone', result.rowsRejected === 1);
  ok('…and the rejection names its INDEX in the caller\'s array',
    result.rejections[0]?.index === 1, JSON.stringify(result.rejections[0]));
  ok('…and says the row had no source',
    (result.rejections[0]?.reason ?? '').toLowerCase().includes('source'),
    result.rejections[0]?.reason);

  const stored = await db('lifecycle_models')
    .where({ brand: 'draytek', model_pattern: 'VIGOR2865' }).first();
  ok('the model string was normalised on the way in', stored !== undefined);
  ok('…and stamped `import`, never `builtin`', stored?.source_kind === 'import',
    stored?.source_kind);

  const again = await importModelEntries(
    [{ ...entry, endOfSale: '2031-01-01' }], 'draytek-2026-07', admin.id);
  ok('re-importing the same key UPDATES rather than duplicating', again.rowsLoaded === 1);
  const count = await db('lifecycle_models')
    .where({ brand: 'draytek', model_pattern: 'VIGOR2865' }).count<[{ count: string }]>('* as count');
  ok('…and there is still exactly one row', Number(count[0].count) === 1, count[0].count);
  const updated = await db('lifecycle_models')
    .where({ brand: 'draytek', model_pattern: 'VIGOR2865' }).first();
  ok('…carrying the corrected date',
    new Date(updated?.end_of_sale as Date).getFullYear() === 2031,
    String(updated?.end_of_sale));

  const fwResult = await importFirmwareEntries([{
    brand: 'zyxel', family: null, branch: '4.7', branchLabel: 'ZLD 4.7',
    endOfSupport: '2025-01-01', source: 'Zyxel bulletin', verifiedAt: '2026-06-01',
  }], 'zyxel-zld', admin.id);
  ok('a FAMILY-WIDE firmware row loads through the partial-index upsert',
    fwResult.rowsLoaded === 1, JSON.stringify(fwResult.rejections));
  const fwAgain = await importFirmwareEntries([{
    brand: 'zyxel', family: null, branch: '4.7', branchLabel: 'ZLD 4.7 (corrected)',
    endOfSupport: '2025-06-01', source: 'Zyxel bulletin', verifiedAt: '2026-06-02',
  }], 'zyxel-zld-fix', admin.id);
  ok('…and re-importing it updates in place rather than colliding',
    fwAgain.rowsLoaded === 1 && fwAgain.rowsRejected === 0, JSON.stringify(fwAgain.rejections));
  const fwCount = await db('lifecycle_firmware')
    .where({ brand: 'zyxel', branch: '4.7' }).count<[{ count: string }]>('* as count');
  ok('…leaving exactly one family-wide row', Number(fwCount[0].count) === 1, fwCount[0].count);

  const journal = await listCatalogImports(10);
  ok('every import left a journal entry', journal.length >= 4, `${journal.length}`);
  ok('…naming the operator who made it',
    journal[0]?.importedByUsername === 'f8-platform-admin', journal[0]?.importedByUsername ?? '');
  ok('…and how many rows it refused',
    journal.some((j) => j.rowsRejected === 1));

  // The catalogue cache must not outlive the import that changed it.
  const catalog = await getLifecycleCatalog();
  ok('an imported row is visible on the next read — the cache was cleared',
    catalog.models.some((m) => m.modelPattern === 'VIGOR2865'));

  const target = catalog.models.find((m) => m.modelPattern === 'VIGOR2865');
  ok('a wrong row can be deleted', await deleteCatalogEntry('model', target?.id ?? 0));
  ok('…and deleting it twice answers false, so the caller can 404',
    (await deleteCatalogEntry('model', target?.id ?? 0)) === false);
  const after = await getLifecycleCatalog();
  ok('…and it is gone from the next read too',
    !after.models.some((m) => m.modelPattern === 'VIGOR2865'));
}

// ============================================================================
// 10. The guards, run for real
// ============================================================================

function findRoute(method: string, path: string): any {
  for (const layer of (lifecycleRoutes as any).stack ?? []) {
    if (layer.route && layer.route.path === path && layer.route.methods?.[method]) {
      return layer.route;
    }
  }
  return null;
}

async function runGuards(route: any, req: any): Promise<unknown> {
  const guards = (route.stack ?? []).slice(0, -1).map((l: any) => l.handle);
  for (const guard of guards) {
    const refusal = await new Promise<unknown>((resolve) => {
      void Promise.resolve(guard(req, {} as any, (err?: unknown) => resolve(err ?? null)));
    });
    if (refusal !== null) return refusal;
  }
  return null;
}

async function guardTests(): Promise<void> {
  section('10. Every route is guarded, and the catalogue write is platform-only');

  // Nothing may be reachable without a check. This enumerates the router
  // rather than asserting on a list somebody has to remember to update.
  const routes = ((lifecycleRoutes as any).stack ?? []).filter((l: any) => l.route);
  ok('the router exposes routes at all', routes.length > 0, `${routes.length} routes`);
  const unguarded = routes.filter((l: any) => (l.route.stack ?? []).length < 2);
  ok('NOT ONE route reaches its controller without a guard in front of it',
    unguarded.length === 0,
    unguarded.map((l: any) => `${Object.keys(l.route.methods)[0]} ${l.route.path}`).join(', '));

  const [tenantAdmin] = await db('users')
    .insert({ username: 'f8-tenant-b-admin', role: 'user', is_active: true })
    .onConflict('username').merge(['role'])
    .returning<Array<{ id: number }>>('id');
  await db('user_tenants')
    .insert({ user_id: tenantAdmin.id, tenant_id: OTHER_TENANT, role: 'admin' })
    .onConflict(['user_id', 'tenant_id']).merge(['role']);

  const caps = await permissionService.getUserCapabilities(tenantAdmin.id, false, OTHER_TENANT);
  ok('the admin of tenant B genuinely holds settings.manage — that capability IS tenant-scoped',
    caps.includes(CAPABILITIES.SETTINGS_MANAGE));
  ok('…and device.read', caps.includes(CAPABILITIES.DEVICE_READ));

  const asTenantAdmin = {
    session: { userId: tenantAdmin.id, role: 'user', currentTenantId: OTHER_TENANT },
    tenantId: OTHER_TENANT, params: {}, query: {}, body: {},
  };
  const asPlatformAdmin = {
    session: { userId: 1, role: 'admin', currentTenantId: TENANT },
    tenantId: TENANT, params: {}, query: {}, body: {},
  };

  for (const [method, path] of [
    ['post', '/catalog/models'],
    ['post', '/catalog/firmware'],
    ['delete', '/catalog/:kind/:id'],
  ] as const) {
    const route = findRoute(method, path);
    ok(`${method.toUpperCase()} ${path} is a route on this router`, route !== null);
    const refused = await runGuards(route, asTenantAdmin);
    ok(`…a TENANT admin is refused ${method.toUpperCase()} ${path}`,
      refused instanceof AppError && refused.statusCode === 403,
      refused instanceof AppError ? `${refused.statusCode}` : 'it was allowed through');
    const allowed = await runGuards(route, asPlatformAdmin);
    ok(`…and a PLATFORM admin gets through ${method.toUpperCase()} ${path}`,
      allowed === null, String(allowed));
  }

  // BOTH branches of `DELETE /catalog/:kind/:id` sit behind the SAME guard,
  // because the guard is on the route and the branch is in the controller.
  const del = findRoute('delete', '/catalog/:kind/:id');
  for (const kind of ['model', 'firmware']) {
    const refused = await runGuards(del, { ...asTenantAdmin, params: { kind, id: '1' } });
    ok(`…and that holds for kind=${kind} too — the guard is UPSTREAM of the branch`,
      refused instanceof AppError && refused.statusCode === 403);
  }

  const read = findRoute('get', '/inventory');
  const anonymous = await runGuards(read, { session: {}, tenantId: TENANT, params: {}, query: {}, body: {} });
  ok('an unauthenticated caller is refused the renewal list',
    anonymous instanceof AppError && anonymous.statusCode === 401,
    anonymous instanceof AppError ? `${anonymous.statusCode}` : 'it was allowed through');
  const reader = await runGuards(read, asTenantAdmin);
  ok('…while a device.read holder gets it', reader === null, String(reader));
}

// ============================================================================
// 11. `asOf` is not on the wire
// ============================================================================

async function clockTests(): Promise<void> {
  section("11. The verdict date is the SERVER's, and is not a request parameter");

  // EVERY read route is checked, not just the one somebody remembered. The
  // schemas are `.strict()`, so `asOf` on the query string is a 400 rather
  // than a silently ignored parameter — and a future route that forgets
  // `.strict()` fails this assertion instead of quietly accepting a verdict
  // input from the caller.
  const getRoutes = ((lifecycleRoutes as any).stack ?? [])
    .filter((l: any) => l.route && l.route.methods?.get);
  ok('there are read routes to check', getRoutes.length > 0, `${getRoutes.length}`);
  for (const layer of getRoutes) {
    const handler = (layer.route.stack ?? []).slice(-1)[0].handle;
    const outcome = await new Promise<unknown>((resolve) => {
      void Promise.resolve(handler(
        {
          tenantId: TENANT, query: { asOf: '2000-01-01' },
          params: { deviceId: '1', kind: 'model', id: '1' }, body: {}, session: {},
        } as any,
        { json: () => resolve('ACCEPTED') } as any,
        (err?: unknown) => resolve(err ?? null),
      ));
    });
    ok(`GET ${layer.route.path} refuses ?asOf — it is not a parameter of this API`,
      outcome instanceof AppError && outcome.statusCode === 400,
      outcome instanceof AppError ? outcome.message.slice(0, 60) : String(outcome));
  }

  // The honest complement: `asOf` exists as a parameter of the SERVICE, and
  // it really does move verdicts. That is precisely why the HTTP surface must
  // not carry it — and it needs a DATED catalogue row to demonstrate, because
  // every row migration 027 seeds is deliberately undated.
  const [dated] = await db('lifecycle_models')
    .insert({
      brand: 'mikrotik', model_pattern: 'CLOCKPROBE', match_mode: 'exact',
      model_label: 'Clock probe', end_of_sale: '2025-01-01', end_of_support: '2028-01-01',
      source_kind: 'manual', source: 'F8 harness fixture', verified_at: '2026-01-01',
    })
    .returning<Array<{ id: string | number }>>('id');
  const probe = await seedDevice(
    TENANT, 'a-clock-probe', 'mikrotik', 'mikrotik_routeros7', 'ClockProbe', '7.14.3',
  );
  clearLifecycleCatalogCache();

  const before = await getDeviceLifecycle(TENANT, probe.id, '2020-01-01');
  const between = await getDeviceLifecycle(TENANT, probe.id, '2026-06-15');
  const after = await getDeviceLifecycle(TENANT, probe.id, '2030-01-01');
  ok('at 2020 the boundaries are ahead -> supported',
    before?.hardware.status === 'supported', before?.hardware.status);
  ok('at 2026 end of sale has passed -> end_of_sale',
    between?.hardware.status === 'end_of_sale', between?.hardware.status);
  ok('at 2030 the final boundary has passed -> end_of_life',
    after?.hardware.status === 'end_of_life', after?.hardware.status);
  ok('SO: a caller-settable asOf would hand an attacker three different answers ' +
    'about the same box — which is exactly why it is not on the wire',
    before?.hardware.status !== after?.hardware.status);

  await db('lifecycle_models').where('id', dated.id).del();
  await db('devices').where('id', probe.id).del();
  clearLifecycleCatalogCache();

  ok('serverToday() is a well-formed calendar date', isIsoDate(serverToday()), serverToday());
}

// ============================================================================
// 12. No secret can reach this surface
// ============================================================================

async function secretTests(): Promise<void> {
  section('12. §8.2 — nothing on this surface can carry a credential');

  const page = await getInventory(TENANT);
  const serialised = JSON.stringify(page);
  for (const forbidden of [
    'secret_enc', 'private_key_enc', 'password', 'ppp_username', 'community',
    'serial', 'tunnel_ip', 'psk',
  ]) {
    ok(`the inventory payload contains no \`${forbidden}\``,
      !serialised.toLowerCase().includes(forbidden.toLowerCase()));
  }

  const catalog = JSON.stringify(await getLifecycleCatalog());
  ok('and neither does the catalogue payload',
    !/password|secret|private_key/i.test(catalog));

  // The projection is narrow by construction, not by redaction: assert the
  // exact key set a device row exposes.
  const keys = Object.keys(page.items[0]?.device ?? {}).sort().join(',');
  ok('a device row exposes exactly the eight fields the verdict needs',
    keys === 'brand,deviceId,family,model,name,osVersion,siteId,siteName', keys);
}

// ============================================================================

async function main(): Promise<void> {
  console.log('ObliWAN F8 — End-of-Life Inventory verification');
  console.log(`DATABASE_URL=${process.env.DATABASE_URL ?? '(default)'}`);

  try {
    offlinePrimitiveTests();
    offlineMatchTests();
    offlineVerdictTests();
    offlineFirmwareTests();
    offlineAggregateTests();
    offlineValidationTests();
    await schemaTests();
    await fleetTests();
    await importTests();
    await guardTests();
    await clockTests();
    await secretTests();
  } catch (err) {
    failed++;
    failures.push(`harness aborted: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
    console.error(err);
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log(`  ${passed} passed, ${failed} failed`);
  if (failures.length > 0) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  - ${f}`);
  }
  console.log('='.repeat(60));

  await db.destroy();
  process.exit(failed === 0 ? 0 : 1);
}

void main();
