// ============================================================================
// ObliWAN — M11 intent store self-test (needs a real PostgreSQL)
// ============================================================================
//
// The half of the milestone that a pure-function test cannot reach: the two
// partial-index upserts, the gap lifecycle, the tenant scoping and the database
// constraints of migration 016 as the service actually exercises them.
//
// It creates its own tenants, site and devices, and deletes them at the end.
//
// Run:  DATABASE_URL=postgres://... npx tsx src/services/intent/testing/m11-store.verify.ts

import { db } from '../../../db';
import { AppError } from '../../../middleware/errorHandler';
import * as store from '../intentStore.service';
import { referenceSiteIntent, zoneAndCommitIntent } from './fixtures';

let passed = 0;
const failures: string[] = [];

function check(name: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    passed += 1;
    return;
  }
  failures.push(`${name}${detail === undefined ? '' : ` — ${JSON.stringify(detail)}`}`);
}

function eq<T>(name: string, actual: T, expected: T): void {
  check(name, Object.is(actual, expected), { actual, expected });
}

const TENANT_A = 990;
const TENANT_B = 991;
const SITE_A = 990;
const DEVICE_MT = 990;
const DEVICE_SW = 991;
const DEVICE_OTHER_TENANT = 992;

async function seed(): Promise<void> {
  await cleanup();
  await db('tenants').insert([
    { id: TENANT_A, name: 'M11 A', slug: 'm11-a' },
    { id: TENANT_B, name: 'M11 B', slug: 'm11-b' },
  ]);
  await db('sites').insert({ id: SITE_A, tenant_id: TENANT_A, code: 'M11', name: 'M11 site' });
  await db('devices').insert([
    {
      id: DEVICE_MT, tenant_id: TENANT_A, site_id: SITE_A, name: 'm11-mt',
      brand: 'mikrotik', family: 'mikrotik_routeros7', status: 'active',
    },
    {
      id: DEVICE_SW, tenant_id: TENANT_A, site_id: SITE_A, name: 'm11-sw',
      brand: 'sonicwall', family: 'sonicwall_sonicos', status: 'active',
    },
    {
      id: DEVICE_OTHER_TENANT, tenant_id: TENANT_B, name: 'm11-other',
      brand: 'draytek', family: 'draytek_vigor', status: 'active',
    },
  ]);
}

async function cleanup(): Promise<void> {
  await db('devices').whereIn('id', [DEVICE_MT, DEVICE_SW, DEVICE_OTHER_TENANT]).delete();
  await db('sites').where({ id: SITE_A }).delete();
  await db('tenants').whereIn('id', [TENANT_A, TENANT_B]).delete();
}

async function countRows(table: string, intentId: number): Promise<number> {
  const row = await db(table).where({ intent_id: intentId }).count<{ count: string }[]>('* as count');
  return Number(row[0].count);
}

async function main(): Promise<void> {
  await seed();

  // ── create ────────────────────────────────────────────────────────────────
  const created = await store.createIntent(TENANT_A, null, {
    siteId: SITE_A,
    body: referenceSiteIntent(),
  });
  eq('the intent starts at revision 1', created.revision, 1);
  eq('and is bound to its site', created.siteId, SITE_A);
  check('and round-trips through jsonb', created.body.slug === 'lyon-nord');

  // Tenant scoping: another customer sees a 404, not a 403.
  let status = 0;
  try {
    await store.getIntent(TENANT_B, created.id);
  } catch (err) {
    status = err instanceof AppError ? err.statusCode : 0;
  }
  eq("another tenant's intent id is a 404", status, 404);

  // ── compile for two devices and two brand-only targets ────────────────────
  const first = await store.compileAndStore(TENANT_A, null, created.id, {
    deviceIds: [DEVICE_MT, DEVICE_SW],
    families: ['draytek_vigor', 'zyxel_standalone'],
  });
  eq('four targets answered', first.results.length, 4);
  eq('all four compiled', first.results.filter((r) => r.ok).length, 4);
  eq('four compilation rows', await countRows('intent_compilations', created.id), 4);
  eq('and no gaps', await countRows('intent_capability_gaps', created.id), 0);

  const mt = first.results.find((r) => r.deviceId === DEVICE_MT);
  check('the device-scoped row carries its device', mt?.deviceId === DEVICE_MT);
  const draytek = first.results.find((r) => r.family === 'draytek_vigor');
  check('the family-scoped row carries no device', draytek?.deviceId === null);

  // ── idempotence: the same intent again must not grow the table ────────────
  const again = await store.compileAndStore(TENANT_A, null, created.id, {
    deviceIds: [DEVICE_MT, DEVICE_SW],
    families: ['draytek_vigor', 'zyxel_standalone'],
  });
  eq('recompiling the same intent still answers four', again.results.length, 4);
  eq('and the table did not grow', await countRows('intent_compilations', created.id), 4);
  eq(
    'the hash is unchanged',
    again.results.find((r) => r.deviceId === DEVICE_MT)?.ncmHash,
    mt?.ncmHash,
  );

  // ── a device of another tenant is a 404, never a compilation ──────────────
  status = 0;
  try {
    await store.compileAndStore(TENANT_A, null, created.id, { deviceIds: [DEVICE_OTHER_TENANT] });
  } catch (err) {
    status = err instanceof AppError ? err.statusCode : 0;
  }
  eq("a device from another tenant is a 404", status, 404);
  eq('and nothing was written', await countRows('intent_compilations', created.id), 4);

  // ── edit: the same site with demands only SonicWall can meet ──────────────
  const edited = await store.updateIntent(TENANT_A, created.id, {
    siteId: SITE_A,
    body: { ...zoneAndCommitIntent(), slug: 'lyon-nord' },
  });
  eq('editing bumps the revision', edited.revision, 2);

  // ── `siteId` has THREE states, and the PATCH that omits it is one of them ──
  //
  // `updateIntent` used to write `site_id: input.siteId ?? null`, so an edit
  // that never mentioned a site UNFILED the intent: the partial index
  // `site_intents_tenant_site_idx` stopped seeing it and the "intents of this
  // site" screen lost it, with no error and nothing to notice but the `siteId`
  // of the response. The line right underneath already did the right thing for
  // `is_published`; the asymmetry between the two was the whole defect.
  const untouched = await store.updateIntent(TENANT_A, created.id, {
    body: { ...zoneAndCommitIntent(), slug: 'lyon-nord' },
  });
  eq('a PATCH that never mentions a site keeps it', untouched.siteId, SITE_A);
  eq('and it still bumped the revision', untouched.revision, 3);

  const unfiled = await store.updateIntent(TENANT_A, created.id, {
    siteId: null,
    body: { ...zoneAndCommitIntent(), slug: 'lyon-nord' },
  });
  eq('an EXPLICIT null still unfiles it', unfiled.siteId, null);

  const refiled = await store.updateIntent(TENANT_A, created.id, {
    siteId: SITE_A,
    body: { ...zoneAndCommitIntent(), slug: 'lyon-nord' },
  });
  eq('and a site can be given back', refiled.siteId, SITE_A);

  // The ownership check must not have been skipped along the way: a site from
  // another customer is still a 404 when the field IS provided.
  let siteStatus = 0;
  try {
    await store.updateIntent(TENANT_A, created.id, {
      siteId: 999_999,
      body: { ...zoneAndCommitIntent(), slug: 'lyon-nord' },
    });
  } catch (err) {
    siteStatus = err instanceof AppError ? err.statusCode : 0;
  }
  eq('a site that is not this tenant\'s is still refused', siteStatus, 404);

  const strict = await store.compileAndStore(TENANT_A, null, created.id, {
    deviceIds: [DEVICE_MT, DEVICE_SW],
    families: ['draytek_vigor', 'zyxel_standalone'],
  });
  eq('one target compiled', strict.results.filter((r) => r.ok).length, 1);
  eq(
    'and it is the SonicWall',
    strict.results.find((r) => r.ok)?.deviceId,
    DEVICE_SW,
  );
  check(
    'the refusals name their capability',
    strict.results
      .filter((r) => !r.ok)
      .every((r) => r.gaps.length > 0 && r.gaps.every((g) => g.feature.length > 0 && g.brand.length > 0)),
  );
  check('the gaps were recorded', (await countRows('intent_capability_gaps', created.id)) > 0);

  const gaps = await store.listGaps(TENANT_A, created.id);
  check(
    'MikroTik is refused for the zone model',
    gaps.some((g) => g.family === 'mikrotik_routeros7' && g.feature === 'policy.zoneModel'),
  );
  check(
    'DrayTek is refused for the reboot it needs',
    gaps.some((g) => g.family === 'draytek_vigor' && g.feature === 'safety.noRebootApply'),
  );
  // The DrayTek reboot gap is a PRODUCT limit, not a driver gap: the family
  // profile already says the supported restore path is a full `.cfg`. The
  // family verdict short-circuits, so the row carries no capability flag and
  // carries the vendor note instead — which is the sentence an operator can
  // act on. (`requiresRebootToApply` says the same thing from the driver's
  // side; reporting both would be two rows for one feature, which the unique
  // index of migration 016 refuses on purpose.)
  const reboot = gaps.find((g) => g.family === 'draytek_vigor' && g.feature === 'safety.noRebootApply');
  eq('the DrayTek reboot gap is a family limit', reboot?.reason, 'family_cannot_express');
  eq('so it carries no driver flag', reboot?.capabilityFlag, null);
  check('and it carries the vendor explanation', (reboot?.note ?? '').includes('.cfg'), reboot?.note);
  check(
    'the SonicWall has no gap at all',
    !gaps.some((g) => g.family === 'sonicwall_sonicos'),
  );

  // ── the gap set is the CURRENT answer, not a history ──────────────────────
  await store.updateIntent(TENANT_A, created.id, {
    siteId: SITE_A,
    body: { ...referenceSiteIntent(), slug: 'lyon-nord' },
  });
  await store.compileAndStore(TENANT_A, null, created.id, {
    deviceIds: [DEVICE_MT, DEVICE_SW],
    families: ['draytek_vigor', 'zyxel_standalone'],
  });
  eq('reverting the intent clears every gap', await countRows('intent_capability_gaps', created.id), 0);
  check(
    'while the compilations of both revisions are kept',
    (await countRows('intent_compilations', created.id)) >= 4,
  );

  // ── reads ─────────────────────────────────────────────────────────────────
  const list = await store.listCompilations(TENANT_A, created.id);
  check('the list omits the two large columns', list.every((r) => r.artifact === undefined && r.ncm === undefined));
  const one = await store.getCompilation(TENANT_A, created.id, list[0].id);
  check('a single read returns the artefact', typeof one.artifact === 'string' && (one.artifact as string).length > 100);
  check('and the desired NCM', one.ncm !== undefined && one.ncm !== null);
  check(
    'the stored artefact is redacted',
    (one.artifact as string).includes('<<secret:') && !(one.artifact as string).includes('hunter2'),
  );

  status = 0;
  try {
    await store.listCompilations(TENANT_B, created.id);
  } catch (err) {
    status = err instanceof AppError ? err.statusCode : 0;
  }
  eq('reading another tenant compilations is a 404', status, 404);

  // ── delete cascades ───────────────────────────────────────────────────────
  await store.deleteIntent(TENANT_A, created.id);
  eq('deleting the intent removes its compilations', await countRows('intent_compilations', created.id), 0);
  eq('and its gaps', await countRows('intent_capability_gaps', created.id), 0);

  await cleanup();
}

main()
  .catch((err) => {
    failures.push(`unhandled — ${err instanceof Error ? err.message : String(err)}`);
  })
  .finally(async () => {
    await db.destroy();
    process.stdout.write(`\nM11 intent store — ${passed} assertion(s) passed, ${failures.length} failed\n`);
    for (const failure of failures) process.stdout.write(`  FAIL ${failure}\n`);
    process.exitCode = failures.length === 0 ? 0 : 1;
  });
