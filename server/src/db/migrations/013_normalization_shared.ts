import type { Knex } from 'knex';

/**
 * 013_normalization_shared.ts — the normalisation doctrine becomes a SHARED
 * LIBRARY instead of tenant #1's private property.
 *
 * ┌─ THE DEFECT THIS REPAIRS (audit M4/M5, finding F1 — CRITICAL) ────────────┐
 * │                                                                           │
 * │ `007_config.ts` declared `normalization_rules.tenant_id NOT NULL          │
 * │ DEFAULT 1`, and `seeds/002_ncm_doctrine.ts` wrote every one of the        │
 * │ N01..N16 built-in rules with `tenant_id = MASTER_TENANT_ID`. The three    │
 * │ readers (`config/collect.service.loadNormalizationRules`,                 │
 * │ `drift/drift.service.loadLayer4Rules`, and the unused twin in             │
 * │ `config/normalize.service.ts`) all filtered `tenant_id = :tenantId`       │
 * │ strictly.                                                                 │
 * │                                                                           │
 * │ Consequence: EVERY TENANT OTHER THAN 1 NORMALISED WITH AN EMPTY RULE      │
 * │ SET. Layers 1..4 all no-ops. Two measurable effects, both of them the     │
 * │ things this subsystem exists to prevent:                                  │
 * │   - a volatile line (an export header, an `address-list` entry with a     │
 * │     `timeout`, a dated comment) changes `ncm_hash` on every collection,   │
 * │     so `config_snapshots` gains a row per collection — the "row           │
 * │     generator" that decision 1 of `007_config.ts` declares forbidden;     │
 * │   - every drift run reports that noise as findings, which makes M4's      │
 * │     acceptance criterion ("fewer than 3 noise findings per device")       │
 * │     structurally unreachable on any real customer.                        │
 * │                                                                           │
 * │ `builtin_key` being UNIQUE **globally** meant the seed could not simply   │
 * │ be replayed per tenant either: the second insert of `ros.dynamic.exclude` │
 * │ would violate the constraint. So the fix cannot be "duplicate 16 x N      │
 * │ rows"; it has to be a shared library.                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ FIVE DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ───────────────────┐
 * │                                                                           │
 * │ 1. `tenant_id IS NULL` MEANS "SHIPPED LIBRARY, VISIBLE TO EVERY TENANT".  │
 * │    This is not an invention: it is exactly the convention decision 4 of   │
 * │    `008_templates.ts` already froze for `templates.tenant_id` and         │
 * │    `template_partials.tenant_id`, read there as                           │
 * │    `WHERE (tenant_id = :t OR tenant_id IS NULL)`. One convention for      │
 * │    "shipped content" across the schema, not two.                          │
 * │    The `DEFAULT 1` is dropped along with the `NOT NULL`. Keeping it       │
 * │    would mean a writer that omits the column silently donates its rule    │
 * │    to tenant 1 — the previous bug wearing a different hat.                │
 * │                                                                           │
 * │ 2. THE UNIQUE ORDER INDEX BECOMES TWO PARTIAL INDEXES.                    │
 * │    `nr_order_uniq (tenant_id, scope, coalesce(scope_id,0), apply_order)`  │
 * │    stops constraining the library the moment `tenant_id` can be NULL:     │
 * │    PostgreSQL's default is NULLS DISTINCT, so every library row would be  │
 * │    unique by vacuity and sixteen rules could share `apply_order = 10`.    │
 * │    That is the lesson of migration 001, and the same one 008 applies to   │
 * │    `templates_library_name_uq`. Hence one partial index per side.         │
 * │                                                                           │
 * │ 3. `builtin_key` STAYS UNIQUE GLOBALLY, AND IS NOW RESTRICTED TO THE      │
 * │    LIBRARY (`nr_builtin_library_chk`).                                    │
 * │    A global unique key was incoherent while the doctrine lived inside a   │
 * │    tenant; it is exactly right once the doctrine is tenant-less — one     │
 * │    `ros.header.strip` on the whole platform. The CHECK is what makes it   │
 * │    safe: `seeds/002_ncm_doctrine.ts` reconciles by                        │
 * │    `where({ builtin_key }).update(...)` with NO tenant filter, so without │
 * │    it a tenant that typed `ros.header.strip` into a rule of its own would │
 * │    have that rule silently overwritten by the next deployment.            │
 * │                                                                           │
 * │ 4. A TENANT RULE AND A LIBRARY RULE ARE ORDERED BY THE §5.1 COMPARISON    │
 * │    UNCHANGED — `layer, scope specificity, apply_order, id`. No            │
 * │    "tenant beats library" term is added, deliberately: that order is      │
 * │    frozen in SQL (`collect.service.ts`) AND in TypeScript                 │
 * │    (`shared/src/ncm/normalization.ts:compareNormalizationRules`), and     │
 * │    `normalization_epoch` is computed from the result. Adding a term on    │
 * │    one side only is how the two sorts start disagreeing and the epoch     │
 * │    stops describing what was applied. The `id` tiebreak already gives     │
 * │    the wanted behaviour: library rows are seeded first, so they carry     │
 * │    lower ids, and a tenant's own rule at the same `apply_order` applies   │
 * │    LAST and can correct it.                                               │
 * │                                                                           │
 * │ 5. `ncm_section_catalog` AND `routeros_defaults` NEED NOTHING HERE.       │
 * │    Both were created in `007_config.ts` with NO tenant column at all      │
 * │    (`PRIMARY KEY (section_path, family)` and                              │
 * │    `(family, os_version, section_path, prop)`), and their only reader,    │
 * │    `collect.service.loadDefaults`, filters on `family` / `os_version` /   │
 * │    `conflicting` and never on a tenant. They were already shared          │
 * │    libraries; F1 never reached them. Recorded here so the next reader     │
 * │    does not go hunting for a symmetric fix that has no subject.           │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * The three reads change in the same commit — a nullable column with the old
 * strict `WHERE` would be a schema change with no observable effect:
 *   - `services/config/collect.service.ts` (`loadNormalizationRules`, L1-L3)
 *   - `services/drift/drift.service.ts`    (`loadLayer4Rules`, L4)
 *   - `db/seeds/002_ncm_doctrine.ts` now writes `tenant_id: null`.
 */

export async function up(knex: Knex): Promise<void> {
  // ── 1. the column ─────────────────────────────────────────────────────────
  // Drop the unique index FIRST: it is about to mean something different, and
  // rebuilding it under the new nullability is cheaper than reasoning about a
  // half-migrated constraint.
  await knex.schema.raw('DROP INDEX IF EXISTS nr_order_uniq');

  await knex.schema.raw(
    'ALTER TABLE normalization_rules ' +
      'ALTER COLUMN tenant_id DROP NOT NULL, ' +
      'ALTER COLUMN tenant_id DROP DEFAULT',
  );

  // ── 2. the data ───────────────────────────────────────────────────────────
  // Move the ALREADY-SEEDED doctrine into the library. Keyed on `is_builtin`
  // and not on `tenant_id = 1`, so a rule an operator wrote by hand inside
  // tenant 1 stays that operator's rule instead of becoming platform doctrine.
  await knex('normalization_rules')
    .where('is_builtin', true)
    .whereNotNull('tenant_id')
    .update({ tenant_id: null });

  // ── 3. the constraints ────────────────────────────────────────────────────
  // Decision 2. Two partial indexes, because a plain composite leaves the
  // library side unconstrained under NULLS DISTINCT.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX nr_order_library_uq ON normalization_rules ' +
      '(scope, coalesce(scope_id, 0), apply_order) WHERE tenant_id IS NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX nr_order_tenant_uq ON normalization_rules ' +
      '(tenant_id, scope, coalesce(scope_id, 0), apply_order) WHERE tenant_id IS NOT NULL',
  );

  // Decision 3. `builtin_key` identifies a SHIPPED rule; a tenant row may not
  // carry one, because the seed reconciles by that key with no tenant filter.
  await knex.schema.raw(
    'ALTER TABLE normalization_rules ADD CONSTRAINT nr_builtin_library_chk ' +
      'CHECK (builtin_key IS NULL OR tenant_id IS NULL)',
  );

  // ── 4. the read path ──────────────────────────────────────────────────────
  // `nr_lookup (tenant_id, enabled, layer, apply_order)` still serves the
  // `tenant_id = :t` half of the new predicate. The `IS NULL` half is where
  // essentially every row lives (the entire doctrine), so it gets its own
  // partial index rather than a bitmap scan over the largest group in the
  // table.
  await knex.schema.raw(
    'CREATE INDEX nr_lookup_library ON normalization_rules ' +
      '(enabled, layer, apply_order) WHERE tenant_id IS NULL',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DROP INDEX IF EXISTS nr_lookup_library');
  await knex.schema.raw(
    'ALTER TABLE normalization_rules DROP CONSTRAINT IF EXISTS nr_builtin_library_chk',
  );
  await knex.schema.raw('DROP INDEX IF EXISTS nr_order_tenant_uq');
  await knex.schema.raw('DROP INDEX IF EXISTS nr_order_library_uq');

  // Hand the library back to the master tenant. Recreating `nr_order_uniq`
  // below can fail if tenant 1 has since written a rule at an `apply_order`
  // the doctrine already uses — and it SHOULD fail loudly instead of picking a
  // winner.
  await knex('normalization_rules').whereNull('tenant_id').update({ tenant_id: 1 });

  await knex.schema.raw(
    'ALTER TABLE normalization_rules ' +
      'ALTER COLUMN tenant_id SET DEFAULT 1, ' +
      'ALTER COLUMN tenant_id SET NOT NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX nr_order_uniq ON normalization_rules ' +
      '(tenant_id, scope, coalesce(scope_id, 0), apply_order)',
  );
}
