import type { Knex } from 'knex';

/**
 * 008_templates.ts — M5 part 1: the template store.
 *
 * Implements section 3.4 of ARCHITECTURE.md (the `templates` … `config_renders`
 * block) and completes the forward declaration left by 007
 * (`drift_runs.render_id`, a bare column awaiting this migration).
 *
 * ┌─ SIX DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ────────────────────┐
 * │                                                                           │
 * │ 1. A PUBLISHED REVISION IS IMMUTABLE, AND IT IS A TRIGGER, NOT A HABIT.   │
 * │    `template_revisions_freeze` rejects any UPDATE that touches the body,  │
 * │    the schema, the version constraints or the render options of a         │
 * │    non-draft revision, and any DELETE of one. Only the lifecycle status   │
 * │    may still move (published -> quarantined -> deprecated). The service   │
 * │    layer refuses too, but the service layer is not what runs at 2 a.m.    │
 * │    from a psql prompt during an incident.                                 │
 * │                                                                           │
 * │ 2. "EDITING A PARTIAL DOES NOT CHANGE A PUBLISHED REVISION'S RENDER" IS   │
 * │    STRUCTURAL, NOT CONVENTIONAL. It is the conjunction of four database   │
 * │    objects, and removing any one of them breaks the guarantee:            │
 * │      a. partials are append-only: `template_partial_revisions` carries    │
 * │         the same freeze trigger, so a published partial revision's body   │
 * │         can never change — editing a partial can only CREATE a revision;  │
 * │      b. `template_revision_deps` pins `partial_revision_id`, a concrete   │
 * │         immutable row, never `partial_id`;                                │
 * │      c. that FK is ON DELETE RESTRICT — a pinned partial revision cannot  │
 * │         be deleted out from under a published template revision;          │
 * │      d. `template_revision_deps_freeze` forbids inserting, updating or    │
 * │         deleting a pin once its revision has left `draft`, and forbids    │
 * │         pinning a partial revision that is itself still a draft (pinning  │
 * │         a mutable row would defeat (a)).                                  │
 * │    The render path (`loader.ts`) reads partial bodies THROUGH this table  │
 * │    for any non-draft revision. It has no other way to reach them.         │
 * │                                                                           │
 * │ 3. UNIQUENESS GOES THROUGH PARTIAL INDEXES, NOT THROUGH `UNIQUE(...)`.    │
 * │    `NULL` is distinct from `NULL` under the default NULLS DISTINCT, so a  │
 * │    plain `UNIQUE (tenant_id, scope, scope_id, key)` constrains exactly    │
 * │    nothing on the `scope_id IS NULL` rows — which are precisely the       │
 * │    global and tenant scopes, i.e. the rows every device inherits from.    │
 * │    Migration 001 was corrected for this on `settings` and                 │
 * │    `notification_bindings` (AUDIT-CORR §1.1); `template_assignments` and  │
 * │    `config_variables` share the vocabulary, so they share the fix. Every  │
 * │    upsert MUST name the index's WHERE clause in its conflict target.      │
 * │                                                                           │
 * │ 4. `tenant_id` IS IN EVERY UNIQUE KEY AND EVERY READ INDEX. Two clients   │
 * │    must be able to hold a template called "site-standard" without seeing  │
 * │    each other's, and a resolution query must never be able to walk out of │
 * │    its tenant by accident. `templates.tenant_id` and                      │
 * │    `template_partials.tenant_id` are NULLABLE — and only there — because  │
 * │    §3.4 defines `NULL` as "the shipped, cross-tenant library". That       │
 * │    single nullable column is why those two tables also get the pair of    │
 * │    partial unique indexes of decision 3, and why every read is            │
 * │    `WHERE (tenant_id = :t OR tenant_id IS NULL)`.                         │
 * │    On the OWNED objects — assignments, variables, renders — `tenant_id`   │
 * │    is NOT NULL: assigning somebody else's library template is still the   │
 * │    assigning tenant's own act.                                            │
 * │                                                                           │
 * │ 5. A PARTIAL'S NAME IS A LOADER KEY, AND THE DATABASE ENFORCES ITS SHAPE. │
 * │    `template_partials_name_chk` rejects a leading slash, a drive letter,  │
 * │    a backslash and any `..` segment. The sandbox loader resolves names    │
 * │    against an in-memory map and cannot reach a filesystem at all, so this │
 * │    is belt and braces — but it is the cheap half of the belt, and it also │
 * │    stops a name that would be ambiguous the day a second loader exists.   │
 * │                                                                           │
 * │ 6. NO SECRET IN `config_variables.value`, AND IT IS A CHECK CONSTRAINT.   │
 * │    `is_secret` rows carry `secret_enc` (a `secretVault` blob) and a NULL  │
 * │    `value`; non-secret rows carry `value` and a NULL `secret_enc`.        │
 * │    Likewise `config_renders.body` and `.variables_snapshot` are the       │
 * │    MASKED material — the complete rendered body exists in memory only, on │
 * │    the vault -> equipment path (§8.2, and plan.ts says the same of        │
 * │    `PlanOp`). A secret that reaches these columns reaches the drift       │
 * │    screen, the diff, the export bundle and the audit log.                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * DIVERGENCES FROM THE MILESTONE BRIEF, DELIBERATE AND DECLARED:
 *
 *  - The brief lists a table named `renders`; §3.4 of ARCHITECTURE.md calls it
 *    `config_renders`, and 007 already ships `drift_runs.render_id` documented
 *    as "`config_renders` arrives with the template migration". An in-flight
 *    milestone's forward reference wins over a shorthand: the table is
 *    `config_renders`, and this migration adds the FK 007 left dangling.
 *  - Likewise the brief's `template_variables` is §3.4's `config_variables`.
 *  - `os_min` / `os_max` sit on `template_revisions`, not on `templates`.
 *    §3.4's table places them on `templates`; the brief requires them per
 *    revision, and the brief is right: a revision that starts using
 *    `/interface/wifi` is RouterOS 7 only while its predecessor was not, and a
 *    template-level constraint would either block the old revision or let the
 *    new one reach a v6 box. The constraint belongs to the body that carries
 *    the assumption. `templates` keeps `brand` and `model_pattern`, which are
 *    genuinely properties of the template as a whole.
 *
 * ENUMS AS TEXT + CHECK, like 002 / 005 / 007 — adding a value is one
 * DROP/ADD CONSTRAINT inside a transaction, whereas `ALTER TYPE … ADD VALUE`
 * cannot be reverted.
 */

// Inlined literals rather than imports from @obliwan/shared, exactly as 002,
// 005 and 007 do: a migration must keep describing the schema as it was on the
// day it ran, whatever the shared package does later.
const DEVICE_BRANDS = "'mikrotik','draytek','zyxel','sonicwall'";
const TEMPLATE_STATUSES = "'active','archived'";
const REVISION_STATUSES = "'draft','published','quarantined','deprecated'";
const PARTIAL_REVISION_STATUSES = "'draft','published','deprecated'";
const DEP_REF_KINDS = "'extends','include','import','from'";
const ASSIGNMENT_SCOPES = "'global','tenant','group','device'";
const VARIABLE_SCOPES = "'global','tenant','group','device'";
const PIN_MODES = "'latest_published','pinned'";
const RENDER_STATUSES = "'ok','error'";

/** Accepts `7`, `7.14`, `7.14.3`, `6.49.10`, `7.15rc2`, `7.16beta4`.
 *  RouterOS is NOT strictly semver, so the column check is a shape check and
 *  the real comparison happens in `assignment.service` through `semver.coerce`
 *  plus an explicit pre-release tail comparison. A stricter regex here would
 *  reject `7.15rc2`, which is a version MikroTik actually ships. */
const VERSION_SHAPE = "^[0-9]+(\\.[0-9]+){0,2}[A-Za-z0-9.+-]*$";

/** A partial's name is a loader key. No absolute path, no drive letter, no
 *  backslash, no `..` segment, no leading dot. */
const PARTIAL_NAME_SHAPE = '^[A-Za-z0-9][A-Za-z0-9_.-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*)*$';

/** A variable key becomes a Nunjucks identifier inside the sandbox. Refusing
 *  `__proto__`, `constructor` and friends in the DATABASE means the render
 *  context cannot be handed a prototype-poisoning key even by a caller that
 *  forgot to filter — and the leading-lowercase rule makes that structural
 *  rather than a blacklist to keep up to date. */
const VARIABLE_KEY_SHAPE = '^[a-z][a-zA-Z0-9_]{0,119}$';

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // templates — the object an operator names, per brand.
  // ==========================================================================

  await knex.schema.createTable('templates', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    // NULLABLE, and only here + on template_partials: §3.4 defines NULL as the
    // shipped cross-tenant library. See decision 4.
    t.integer('tenant_id').nullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('name', 120).notNullable();
    t.text('description').nullable();

    // A template is brand-specific: its body is RouterOS syntax or it is not.
    // The multi-dialect compiler of M11 works from Intent -> NCM, never from a
    // template body, which is exactly why this column is NOT NULL.
    t.string('brand', 24).notNullable();
    // Optional narrowing, matched case-insensitively against `devices.model` by
    // `assignment.service`. A GLOB (`*`, `?`), not a regular expression: this
    // pattern is operator-authored and evaluated once per candidate per device
    // on the API thread, and a regex there is one nested quantifier away from a
    // denial of service on an input we invite people to type.
    t.string('model_pattern', 120).nullable();

    t.string('status', 16).notNullable().defaultTo('active');

    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.integer('updated_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE templates ADD CONSTRAINT templates_brand_chk CHECK (brand IN (${DEVICE_BRANDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE templates ADD CONSTRAINT templates_status_chk CHECK (status IN (${TEMPLATE_STATUSES}))`,
  );
  await knex.schema.raw(
    "ALTER TABLE templates ADD CONSTRAINT templates_name_chk CHECK (btrim(name) <> '')",
  );
  // Decision 3: two partial indexes, because NULLS DISTINCT means a plain
  // UNIQUE(tenant_id, name) would let the shipped library hold "site-standard"
  // ten times over.
  await knex.schema.raw(
    `CREATE UNIQUE INDEX templates_library_name_uq ON templates (lower(name), brand)
       WHERE tenant_id IS NULL`,
  );
  await knex.schema.raw(
    `CREATE UNIQUE INDEX templates_tenant_name_uq ON templates (tenant_id, lower(name), brand)
       WHERE tenant_id IS NOT NULL`,
  );
  // The read shape: "the templates this tenant may use, for this brand".
  await knex.schema.raw(
    'CREATE INDEX templates_tenant_brand_idx ON templates (tenant_id, brand, status)',
  );
  // Needed by the composite FK carried by template_revisions (decision 4).
  await knex.schema.raw(
    'ALTER TABLE templates ADD CONSTRAINT templates_id_tenant_uq UNIQUE (id, tenant_id)',
  );

  // ==========================================================================
  // template_revisions — append-only, frozen on publication.
  // ==========================================================================

  await knex.schema.createTable('template_revisions', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.bigInteger('template_id').notNullable()
      .references('id').inTable('templates').onDelete('CASCADE');
    // Denormalised so that every read index and every uniqueness key starts
    // with the tenant (decision 4). Kept honest by the composite FK below AND
    // by a BEFORE INSERT trigger that overwrites it from the parent — the FK
    // alone is MATCH SIMPLE and therefore vacuously satisfied when the column
    // is NULL, which is the very case the library templates live in.
    t.integer('tenant_id').nullable();

    t.integer('revision').notNullable();

    t.text('body').notNullable();
    t.string('body_sha256', 64).notNullable();

    // JSON Schema (draft 2020-12) validated with ajv by render.service. An
    // empty object means "no declared variables", not "anything goes" — the
    // resolver still only injects keys it was asked for.
    t.jsonb('var_schema').notNullable().defaultTo(knex.raw("'{}'::jsonb"));
    // Per-section severity overrides consumed by the drift engine.
    t.jsonb('section_severity').notNullable().defaultTo(knex.raw("'{}'::jsonb"));

    // Per-revision OS window (see DIVERGENCES above).
    t.string('os_min', 32).nullable();
    t.string('os_max', 32).nullable();

    t.string('engine', 16).notNullable().defaultTo('nunjucks');
    // Sandbox knobs that must be frozen WITH the body, because they change the
    // output: `throwOnUndefined`, `trimBlocks`, `lstripBlocks`, `autoescape`.
    // A published revision whose autoescape could be flipped afterwards would
    // be a published revision whose escaping is not published.
    t.jsonb('render_options').notNullable().defaultTo(knex.raw("'{}'::jsonb"));

    t.string('status', 16).notNullable().defaultTo('draft');
    t.timestamp('published_at', { useTz: true }).nullable();
    t.integer('published_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    // Set in the same transaction as the status flip, AFTER the pins are
    // written. Its only purpose is to make "published but nothing pinned"
    // impossible to represent (see the CHECK below).
    t.boolean('deps_pinned').notNullable().defaultTo(false);
    // Count of pins written at publication. Zero is legitimate (a template with
    // no partials) — the column exists so that a dep table emptied by hand is
    // detectable, not to gate anything.
    t.integer('deps_count').notNullable().defaultTo(0);

    t.text('notes').nullable();
    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);

    t.unique(['template_id', 'revision']);
  });

  await knex.schema.raw(
    'ALTER TABLE template_revisions ADD CONSTRAINT template_revisions_template_fk ' +
      'FOREIGN KEY (template_id, tenant_id) REFERENCES templates (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE template_revisions ADD CONSTRAINT template_revisions_status_chk
       CHECK (status IN (${REVISION_STATUSES}))`,
  );
  await knex.schema.raw(
    "ALTER TABLE template_revisions ADD CONSTRAINT template_revisions_sha_chk " +
      "CHECK (body_sha256 ~ '^[0-9a-f]{64}$')",
  );
  await knex.schema.raw(
    'ALTER TABLE template_revisions ADD CONSTRAINT template_revisions_revision_chk ' +
      'CHECK (revision >= 1)',
  );
  await knex.schema.raw(
    'ALTER TABLE template_revisions ADD CONSTRAINT template_revisions_osmin_chk ' +
      `CHECK (os_min IS NULL OR os_min ~ '${VERSION_SHAPE}')`,
  );
  await knex.schema.raw(
    'ALTER TABLE template_revisions ADD CONSTRAINT template_revisions_osmax_chk ' +
      `CHECK (os_max IS NULL OR os_max ~ '${VERSION_SHAPE}')`,
  );
  // "Published" is not a flag you can set on its own: it comes with a date and
  // with pinned dependencies, or it does not come at all.
  await knex.schema.raw(
    'ALTER TABLE template_revisions ADD CONSTRAINT template_revisions_publication_chk CHECK (' +
      "(status = 'draft' AND published_at IS NULL AND deps_pinned = false) OR " +
      "(status <> 'draft' AND published_at IS NOT NULL AND deps_pinned = true))",
  );

  await knex.schema.raw(
    'CREATE INDEX template_revisions_lookup_idx ' +
      'ON template_revisions (tenant_id, template_id, status, revision DESC)',
  );
  // "The newest published revision of this template" — the assignment
  // resolver's hot path, and the only query it runs per candidate template.
  await knex.schema.raw(
    "CREATE INDEX template_revisions_published_idx " +
      "ON template_revisions (template_id, revision DESC) WHERE status = 'published'",
  );
  // Needed by the composite FK carried by template_revision_deps.
  await knex.schema.raw(
    'ALTER TABLE template_revisions ADD CONSTRAINT template_revisions_id_tenant_uq ' +
      'UNIQUE (id, tenant_id)',
  );

  // ==========================================================================
  // template_partials — reusable blocks, append-only like the templates.
  // ==========================================================================

  await knex.schema.createTable('template_partials', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('tenant_id').nullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    // THE loader key. `{% include "partials/wan.njk" %}` resolves on this
    // column and on nothing else.
    t.string('name', 160).notNullable();
    t.text('description').nullable();
    t.string('brand', 24).nullable();
    t.string('status', 16).notNullable().defaultTo('active');

    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE template_partials ADD CONSTRAINT template_partials_name_chk ' +
      `CHECK (name ~ '${PARTIAL_NAME_SHAPE}' AND position('..' in name) = 0)`,
  );
  await knex.schema.raw(
    `ALTER TABLE template_partials ADD CONSTRAINT template_partials_brand_chk
       CHECK (brand IS NULL OR brand IN (${DEVICE_BRANDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE template_partials ADD CONSTRAINT template_partials_status_chk
       CHECK (status IN (${TEMPLATE_STATUSES}))`,
  );
  // Same NULLS DISTINCT trap, same fix. Names are matched EXACTLY by the loader
  // (a Nunjucks name is case-sensitive), so these indexes are not `lower(name)`
  // — using lower() here would forbid two names the loader considers distinct.
  await knex.schema.raw(
    "CREATE UNIQUE INDEX template_partials_library_name_uq ON template_partials (name) " +
      'WHERE tenant_id IS NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX template_partials_tenant_name_uq ON template_partials (tenant_id, name) ' +
      'WHERE tenant_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX template_partials_tenant_idx ON template_partials (tenant_id, status)',
  );
  await knex.schema.raw(
    'ALTER TABLE template_partials ADD CONSTRAINT template_partials_id_tenant_uq ' +
      'UNIQUE (id, tenant_id)',
  );

  await knex.schema.createTable('template_partial_revisions', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.bigInteger('partial_id').notNullable()
      .references('id').inTable('template_partials').onDelete('CASCADE');
    t.integer('tenant_id').nullable();

    t.integer('revision').notNullable();
    t.text('body').notNullable();
    t.string('body_sha256', 64).notNullable();

    t.string('status', 16).notNullable().defaultTo('draft');
    t.timestamp('published_at', { useTz: true }).nullable();
    t.integer('published_by').nullable().references('id').inTable('users').onDelete('SET NULL');

    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);

    t.unique(['partial_id', 'revision']);
  });

  await knex.schema.raw(
    'ALTER TABLE template_partial_revisions ADD CONSTRAINT template_partial_revisions_partial_fk ' +
      'FOREIGN KEY (partial_id, tenant_id) REFERENCES template_partials (id, tenant_id) ' +
      'ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE template_partial_revisions ADD CONSTRAINT template_partial_revisions_status_chk
       CHECK (status IN (${PARTIAL_REVISION_STATUSES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE template_partial_revisions ADD CONSTRAINT template_partial_revisions_sha_chk ' +
      "CHECK (body_sha256 ~ '^[0-9a-f]{64}$')",
  );
  await knex.schema.raw(
    'ALTER TABLE template_partial_revisions ADD CONSTRAINT template_partial_revisions_rev_chk ' +
      'CHECK (revision >= 1)',
  );
  await knex.schema.raw(
    'ALTER TABLE template_partial_revisions ' +
      'ADD CONSTRAINT template_partial_revisions_publication_chk CHECK (' +
      "(status = 'draft' AND published_at IS NULL) OR " +
      "(status <> 'draft' AND published_at IS NOT NULL))",
  );
  await knex.schema.raw(
    'CREATE INDEX template_partial_revisions_lookup_idx ' +
      'ON template_partial_revisions (tenant_id, partial_id, status, revision DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX template_partial_revisions_published_idx ' +
      "ON template_partial_revisions (partial_id, revision DESC) WHERE status = 'published'",
  );

  // ==========================================================================
  // template_revision_deps — THE pin table. Decision 2 lives here.
  // ==========================================================================

  await knex.schema.createTable('template_revision_deps', (t) => {
    t.bigIncrements('id').primary();

    t.bigInteger('revision_id').notNullable()
      .references('id').inTable('template_revisions').onDelete('CASCADE');
    t.integer('tenant_id').nullable();

    // The name AS WRITTEN in the template body. The sandbox loader is fed a map
    // keyed on exactly this string, so a rename of the partial cannot silently
    // repoint a published revision: the pin still carries the old name and the
    // old body.
    t.string('name', 160).notNullable();

    t.bigInteger('partial_id').notNullable()
      .references('id').inTable('template_partials').onDelete('RESTRICT');
    // RESTRICT, and this is decision 2(c): the exact body a published revision
    // renders with can never be deleted while that revision exists.
    t.bigInteger('partial_revision_id').notNullable()
      .references('id').inTable('template_partial_revisions').onDelete('RESTRICT');

    t.string('ref_kind', 12).notNullable();
    // 0 = referenced directly by the template body, n = through n partials.
    t.integer('depth').notNullable().defaultTo(0);

    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    // One body per loader name per revision. Two pins for the same name would
    // make the render non-deterministic, which is the one thing a pin exists to
    // prevent.
    t.unique(['revision_id', 'name']);
  });

  await knex.schema.raw(
    'ALTER TABLE template_revision_deps ADD CONSTRAINT template_revision_deps_revision_fk ' +
      'FOREIGN KEY (revision_id, tenant_id) REFERENCES template_revisions (id, tenant_id) ' +
      'ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE template_revision_deps ADD CONSTRAINT template_revision_deps_kind_chk
       CHECK (ref_kind IN (${DEP_REF_KINDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE template_revision_deps ADD CONSTRAINT template_revision_deps_depth_chk ' +
      'CHECK (depth >= 0 AND depth <= 16)',
  );
  await knex.schema.raw(
    'CREATE INDEX template_revision_deps_revision_idx ON template_revision_deps (revision_id)',
  );
  // "Which published revisions would I break by deleting this partial revision"
  // — asked by the UI before offering the button, and by the RESTRICT FK after.
  await knex.schema.raw(
    'CREATE INDEX template_revision_deps_partial_rev_idx ' +
      'ON template_revision_deps (partial_revision_id)',
  );

  // ==========================================================================
  // The freeze triggers. Decisions 1 and 2, as database objects.
  // ==========================================================================

  // Tenant coherence for the two denormalised columns. Written as an overwrite
  // rather than a check: a caller that omits tenant_id gets the right value,
  // and a caller that lies gets corrected instead of silently creating a row
  // that no tenant-scoped index will ever return.
  await knex.schema.raw(`
    CREATE FUNCTION template_sync_tenant() RETURNS trigger AS $fn$
    DECLARE parent_tenant integer;
    BEGIN
      IF TG_TABLE_NAME = 'template_revisions' THEN
        SELECT tenant_id INTO parent_tenant FROM templates WHERE id = NEW.template_id;
      ELSIF TG_TABLE_NAME = 'template_partial_revisions' THEN
        SELECT tenant_id INTO parent_tenant FROM template_partials WHERE id = NEW.partial_id;
      ELSE
        SELECT tenant_id INTO parent_tenant FROM template_revisions WHERE id = NEW.revision_id;
      END IF;
      NEW.tenant_id := parent_tenant;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);

  await knex.schema.raw(`
    CREATE TRIGGER template_revisions_tenant_sync
      BEFORE INSERT OR UPDATE OF template_id ON template_revisions
      FOR EACH ROW EXECUTE FUNCTION template_sync_tenant()
  `);
  await knex.schema.raw(`
    CREATE TRIGGER template_partial_revisions_tenant_sync
      BEFORE INSERT OR UPDATE OF partial_id ON template_partial_revisions
      FOR EACH ROW EXECUTE FUNCTION template_sync_tenant()
  `);
  await knex.schema.raw(`
    CREATE TRIGGER template_revision_deps_tenant_sync
      BEFORE INSERT OR UPDATE OF revision_id ON template_revision_deps
      FOR EACH ROW EXECUTE FUNCTION template_sync_tenant()
  `);

  // ── Decision 1 ────────────────────────────────────────────────────────────
  //
  // Everything that determines the OUTPUT of a render is frozen once the
  // revision leaves `draft`. What is left mutable is exactly the lifecycle:
  // `status` (forward only, into quarantined / deprecated), `notes`, and
  // `updated_at`. `draft -> published` still goes through, because the OLD row
  // is a draft and drafts are freely editable.
  await knex.schema.raw(`
    CREATE FUNCTION template_revisions_freeze() RETURNS trigger AS $fn$
    BEGIN
      IF TG_OP = 'DELETE' THEN
        -- A cascade from "templates" (itself cascaded from "tenants") must
        -- still be able to run: offboarding a client cannot be blocked by his
        -- own published templates. PostgreSQL deletes the parent row BEFORE
        -- running the referential action, so "the parent is already gone" is
        -- exactly, and only, the cascade case. A direct DELETE still sees it.
        IF OLD.status <> 'draft'
           AND EXISTS (SELECT 1 FROM templates WHERE id = OLD.template_id) THEN
          RAISE EXCEPTION
            'template_revision % is published and cannot be deleted (status=%)',
            OLD.id, OLD.status
            USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN OLD;
      END IF;

      IF OLD.status = 'draft' THEN
        RETURN NEW;
      END IF;

      IF NEW.body            <> OLD.body
      OR NEW.body_sha256     <> OLD.body_sha256
      OR NEW.var_schema::text      <> OLD.var_schema::text
      OR NEW.section_severity::text <> OLD.section_severity::text
      OR NEW.render_options::text  <> OLD.render_options::text
      OR NEW.template_id     <> OLD.template_id
      OR NEW.revision        <> OLD.revision
      OR NEW.engine          <> OLD.engine
      OR NEW.deps_pinned     <> OLD.deps_pinned
      OR NEW.deps_count      <> OLD.deps_count
      OR NEW.tenant_id       IS DISTINCT FROM OLD.tenant_id
      OR NEW.os_min          IS DISTINCT FROM OLD.os_min
      OR NEW.os_max          IS DISTINCT FROM OLD.os_max
      OR NEW.published_at    IS DISTINCT FROM OLD.published_at
      THEN
        RAISE EXCEPTION
          'template_revision % is published and immutable; create a new revision instead',
          OLD.id
          USING ERRCODE = 'restrict_violation';
      END IF;

      IF NEW.status NOT IN ('published', 'quarantined', 'deprecated') THEN
        RAISE EXCEPTION
          'template_revision % cannot return to status %', OLD.id, NEW.status
          USING ERRCODE = 'restrict_violation';
      END IF;

      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER template_revisions_freeze
      BEFORE UPDATE OR DELETE ON template_revisions
      FOR EACH ROW EXECUTE FUNCTION template_revisions_freeze()
  `);

  // ── Decision 2(a) ─────────────────────────────────────────────────────────
  //
  // The same freeze on partial revisions. This is the half of the guarantee
  // people forget: pinning is useless if the pinned row can still be edited.
  await knex.schema.raw(`
    CREATE FUNCTION template_partial_revisions_freeze() RETURNS trigger AS $fn$
    BEGIN
      IF TG_OP = 'DELETE' THEN
        -- Same cascade tolerance as template_revisions_freeze, and the same
        -- reason. Note that a partial revision PINNED by a published template
        -- revision is protected independently, by the ON DELETE RESTRICT of
        -- template_revision_deps.partial_revision_id — which no cascade can
        -- talk its way past.
        IF OLD.status <> 'draft'
           AND EXISTS (SELECT 1 FROM template_partials WHERE id = OLD.partial_id) THEN
          RAISE EXCEPTION
            'template_partial_revision % is published and cannot be deleted', OLD.id
            USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN OLD;
      END IF;

      IF OLD.status = 'draft' THEN
        RETURN NEW;
      END IF;

      IF NEW.body        <> OLD.body
      OR NEW.body_sha256 <> OLD.body_sha256
      OR NEW.partial_id  <> OLD.partial_id
      OR NEW.revision    <> OLD.revision
      OR NEW.tenant_id   IS DISTINCT FROM OLD.tenant_id
      OR NEW.published_at IS DISTINCT FROM OLD.published_at
      THEN
        RAISE EXCEPTION
          'template_partial_revision % is published and immutable; create a new revision instead',
          OLD.id
          USING ERRCODE = 'restrict_violation';
      END IF;

      IF NEW.status NOT IN ('published', 'deprecated') THEN
        RAISE EXCEPTION
          'template_partial_revision % cannot return to status %', OLD.id, NEW.status
          USING ERRCODE = 'restrict_violation';
      END IF;

      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER template_partial_revisions_freeze
      BEFORE UPDATE OR DELETE ON template_partial_revisions
      FOR EACH ROW EXECUTE FUNCTION template_partial_revisions_freeze()
  `);

  // ── Decision 2(d) ─────────────────────────────────────────────────────────
  //
  // Pins are written while the revision is still a draft and are sealed with
  // it. And a pin may only ever point at a partial revision that is ITSELF
  // frozen — pinning a draft would pin a moving target.
  //
  // The DELETE branch tolerates the CASCADE from a draft revision being
  // deleted; a published revision cannot be deleted at all (previous trigger),
  // so the cascade can never reach a sealed pin.
  await knex.schema.raw(`
    CREATE FUNCTION template_revision_deps_freeze() RETURNS trigger AS $fn$
    DECLARE rev_status text; part_status text;
    BEGIN
      IF TG_OP = 'DELETE' THEN
        SELECT status INTO rev_status FROM template_revisions WHERE id = OLD.revision_id;
        IF rev_status IS NOT NULL AND rev_status <> 'draft' THEN
          RAISE EXCEPTION
            'dependency pins of published revision % are immutable', OLD.revision_id
            USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN OLD;
      END IF;

      SELECT status INTO rev_status FROM template_revisions WHERE id = NEW.revision_id;
      IF rev_status <> 'draft' THEN
        RAISE EXCEPTION
          'dependency pins of published revision % are immutable', NEW.revision_id
          USING ERRCODE = 'restrict_violation';
      END IF;

      SELECT status INTO part_status
        FROM template_partial_revisions WHERE id = NEW.partial_revision_id;
      IF part_status = 'draft' THEN
        RAISE EXCEPTION
          'cannot pin template_partial_revision %: it is still a draft and therefore mutable',
          NEW.partial_revision_id
          USING ERRCODE = 'restrict_violation';
      END IF;

      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER template_revision_deps_freeze
      BEFORE INSERT OR UPDATE OR DELETE ON template_revision_deps
      FOR EACH ROW EXECUTE FUNCTION template_revision_deps_freeze()
  `);

  // ==========================================================================
  // template_assignments — multi-scope, same precedence vocabulary as settings.
  // ==========================================================================

  await knex.schema.createTable('template_assignments', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    // NOT NULL: assigning a library template is still the assigning tenant's
    // own act, and an assignment with a NULL tenant would apply the same
    // template to every client of the platform.
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    // scope_id is NULL for 'global' AND for 'tenant' — at those two levels the
    // identity of the row is carried by tenant_id (migration 001, `settings`).
    // The two levels are NOT redundant: 'global' is "everything I own",
    // 'tenant' exists so that a future cross-tenant operator view can express
    // "this tenant, from the outside". Keeping the four-value vocabulary
    // identical to settings/notification_bindings is worth more than dropping
    // one level.
    t.string('scope', 20).notNullable();
    t.integer('scope_id').nullable();

    t.bigInteger('template_id').notNullable()
      .references('id').inTable('templates').onDelete('CASCADE');
    // NULL = follow the latest published revision. Non-null = pinned forever.
    t.bigInteger('revision_id').nullable()
      .references('id').inTable('template_revisions').onDelete('RESTRICT');
    t.string('pin_mode', 20).notNullable().defaultTo('latest_published');

    // Tie-break WITHIN a scope level. Precedence between levels is decided by
    // the level itself (device > group > tenant > global) and is NOT
    // configurable — a priority that could invert the levels would make the
    // resolution unexplainable in the UI.
    t.integer('priority').notNullable().defaultTo(100);
    t.boolean('enabled').notNullable().defaultTo(true);
    t.text('reason').nullable();

    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE template_assignments ADD CONSTRAINT template_assignments_scope_chk
       CHECK (scope IN (${ASSIGNMENT_SCOPES}))`,
  );
  // `scope_id IS NULL` is not a free-form choice: it is determined by `scope`.
  // Without this, a 'device' row with a NULL scope_id would land in the
  // unscoped unique index and silently behave like a global assignment.
  await knex.schema.raw(
    'ALTER TABLE template_assignments ADD CONSTRAINT template_assignments_scope_id_chk CHECK (' +
      "(scope IN ('global','tenant') AND scope_id IS NULL) OR " +
      "(scope IN ('group','device') AND scope_id IS NOT NULL))",
  );
  await knex.schema.raw(
    `ALTER TABLE template_assignments ADD CONSTRAINT template_assignments_pin_mode_chk
       CHECK (pin_mode IN (${PIN_MODES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE template_assignments ADD CONSTRAINT template_assignments_pin_chk CHECK (' +
      "(pin_mode = 'pinned' AND revision_id IS NOT NULL) OR " +
      "(pin_mode = 'latest_published' AND revision_id IS NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE template_assignments ADD CONSTRAINT template_assignments_priority_chk ' +
      'CHECK (priority BETWEEN 0 AND 10000)',
  );

  // Decision 3, again. One assignment of a given template per scope point.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX template_assignments_unscoped_uq ' +
      'ON template_assignments (tenant_id, scope, template_id) WHERE scope_id IS NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX template_assignments_scoped_uq ' +
      'ON template_assignments (tenant_id, scope, scope_id, template_id) ' +
      'WHERE scope_id IS NOT NULL',
  );
  // The resolver's read shape.
  await knex.schema.raw(
    'CREATE INDEX template_assignments_resolve_idx ' +
      'ON template_assignments (tenant_id, scope, scope_id) WHERE enabled',
  );
  await knex.schema.raw(
    'CREATE INDEX template_assignments_template_idx ON template_assignments (template_id)',
  );
  // `scope_id` is polymorphic (device_groups.id or devices.id depending on
  // `scope`) and therefore carries no FK — same trade-off as `settings` and
  // `notification_bindings` in 001. The resolver joins on the right table for
  // the scope it is reading, and a dangling scope_id resolves to nothing rather
  // than to somebody else's group.

  // ==========================================================================
  // config_variables — the variable store, modelled on `settings`.
  // ==========================================================================

  await knex.schema.createTable('config_variables', (t) => {
    t.bigIncrements('id').primary();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('scope', 20).notNullable();
    t.integer('scope_id').nullable();

    t.string('key', 120).notNullable();
    // NULL exactly when is_secret — see decision 6.
    t.jsonb('value').nullable();
    t.boolean('is_secret').notNullable().defaultTo(false);
    // AES-256-GCM blob produced by `secretVault`. Never rendered into
    // `config_renders.body`; substituted in memory on the push path only.
    t.text('secret_enc').nullable();

    t.text('description').nullable();
    t.integer('updated_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE config_variables ADD CONSTRAINT config_variables_scope_chk
       CHECK (scope IN (${VARIABLE_SCOPES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_scope_id_chk CHECK (' +
      "(scope IN ('global','tenant') AND scope_id IS NULL) OR " +
      "(scope IN ('group','device') AND scope_id IS NOT NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_key_chk ' +
      `CHECK (key ~ '${VARIABLE_KEY_SHAPE}')`,
  );
  // Decision 6, as a constraint rather than as a comment.
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_secret_chk CHECK (' +
      '(is_secret = false AND secret_enc IS NULL AND value IS NOT NULL) OR ' +
      '(is_secret = true AND secret_enc IS NOT NULL AND value IS NULL))',
  );

  await knex.schema.raw(
    'CREATE UNIQUE INDEX config_variables_unscoped_uq ' +
      'ON config_variables (tenant_id, scope, key) WHERE scope_id IS NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX config_variables_scoped_uq ' +
      'ON config_variables (tenant_id, scope, scope_id, key) WHERE scope_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX config_variables_resolve_idx ON config_variables (tenant_id, scope, scope_id)',
  );

  // ==========================================================================
  // config_renders — the DESIRED side, and the row `drift_runs` points at.
  // ==========================================================================

  await knex.schema.createTable('config_renders', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    // RESTRICT: a render is evidence of what we intended at a point in time.
    // Losing the revision it came from would leave a drift verdict with no
    // provenance.
    t.bigInteger('revision_id').notNullable()
      .references('id').inTable('template_revisions').onDelete('RESTRICT');
    t.bigInteger('assignment_id').nullable()
      .references('id').inTable('template_assignments').onDelete('SET NULL');

    t.string('status', 12).notNullable();

    // MASKED body. Secrets are substituted on the vault -> equipment path only.
    t.text('body').nullable();
    t.string('body_sha256', 64).nullable();

    // The NCM the body means. Parsed back out of `body` by the brand driver, so
    // that drift compares NCM to NCM and never text to text.
    t.jsonb('ncm_desired').nullable();
    t.string('ncm_hash', 64).nullable();

    // MASKED variable snapshot: `{"key": value}` for plain variables,
    // `{"key": {"secret": true, "fingerprint": "..."}}` for secret ones.
    t.jsonb('variables_snapshot').notNullable().defaultTo(knex.raw("'{}'::jsonb"));
    t.string('variables_sha256', 64).notNullable();

    // The exact set of pinned partial revisions this body was produced from,
    // hashed. Two renders of the same revision with the same variables and a
    // different value here mean the pin table was tampered with — which the
    // triggers above make impossible, and this column makes detectable.
    t.string('deps_fingerprint', 64).nullable();

    t.text('render_error').nullable();
    t.string('error_kind', 32).nullable();
    t.integer('duration_ms').nullable();
    // Device OS at render time: what `os_min` / `os_max` were checked against.
    t.string('os_version', 32).nullable();

    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('rendered_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE config_renders ADD CONSTRAINT config_renders_status_chk
       CHECK (status IN (${RENDER_STATUSES}))`,
  );
  // An `ok` render with no body, or an `error` render with no reason, are both
  // rows that would make the drift screen lie about why it has nothing to say.
  await knex.schema.raw(
    'ALTER TABLE config_renders ADD CONSTRAINT config_renders_coherent_chk CHECK (' +
      "(status = 'ok' AND body IS NOT NULL AND body_sha256 IS NOT NULL " +
      'AND render_error IS NULL) OR ' +
      "(status = 'error' AND render_error IS NOT NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE config_renders ADD CONSTRAINT config_renders_sha_chk CHECK (' +
      "(body_sha256 IS NULL OR body_sha256 ~ '^[0-9a-f]{64}$') AND " +
      "variables_sha256 ~ '^[0-9a-f]{64}$' AND " +
      "(ncm_hash IS NULL OR ncm_hash ~ '^[0-9a-f]{64}$') AND " +
      "(deps_fingerprint IS NULL OR deps_fingerprint ~ '^[0-9a-f]{64}$'))",
  );

  await knex.schema.raw(
    'CREATE INDEX config_renders_device_time_idx ON config_renders (tenant_id, device_id, rendered_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX config_renders_revision_idx ON config_renders (revision_id)',
  );
  // "Have I already rendered this exact revision with these exact variables for
  // this device?" — a plain index, not a unique one: a re-render after a
  // template fix must be able to produce a second row, and keeping the history
  // is what makes a plan auditable.
  await knex.schema.raw(
    'CREATE INDEX config_renders_dedup_idx ' +
      'ON config_renders (device_id, revision_id, variables_sha256)',
  );

  // The constraint 007 deliberately left out, now that its target exists.
  await knex.schema.raw(
    'ALTER TABLE drift_runs ADD CONSTRAINT drift_runs_render_fk ' +
      'FOREIGN KEY (render_id) REFERENCES config_renders (id) ON DELETE SET NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX drift_runs_render_idx ON drift_runs (render_id) WHERE render_id IS NOT NULL',
  );

  await knex.schema.raw(
    'COMMENT ON TABLE template_revision_deps IS $$' +
      'Pinned dependencies of a template revision. Written while the revision is ' +
      'a draft, sealed by template_revision_deps_freeze when it is published. ' +
      'partial_revision_id is ON DELETE RESTRICT: this is what makes "editing a ' +
      'partial does not change a published revision" structural.$$',
  );
}

export async function down(knex: Knex): Promise<void> {
  // The FK back into 007's table goes first — 008 added it, 008 removes it.
  await knex.schema.raw('DROP INDEX IF EXISTS drift_runs_render_idx');
  await knex.schema.raw('ALTER TABLE drift_runs DROP CONSTRAINT IF EXISTS drift_runs_render_fk');

  // Triggers are dropped with their tables; the FUNCTIONS are not, and a
  // leftover function makes the next `migrate:latest` fail on CREATE FUNCTION.
  await knex.schema.dropTableIfExists('config_renders');
  await knex.schema.dropTableIfExists('config_variables');
  await knex.schema.dropTableIfExists('template_assignments');
  await knex.schema.dropTableIfExists('template_revision_deps');
  await knex.schema.dropTableIfExists('template_partial_revisions');
  await knex.schema.dropTableIfExists('template_partials');
  await knex.schema.dropTableIfExists('template_revisions');
  await knex.schema.dropTableIfExists('templates');

  await knex.schema.raw('DROP FUNCTION IF EXISTS template_revision_deps_freeze()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS template_partial_revisions_freeze()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS template_revisions_freeze()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS template_sync_tenant()');
}
