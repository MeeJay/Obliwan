import type { Knex } from 'knex';

/**
 * 016_intent.ts — M11: the Intent Compiler (K4).
 *
 * Three tables: what the operator DECLARED (`site_intents`), what the compiler
 * PRODUCED (`intent_compilations`), and what it REFUSED to produce and why
 * (`intent_capability_gaps`).
 *
 * ┌─ THE THIRD TABLE IS NOT AN ERROR LOG ─────────────────────────────────────┐
 * │ "This site cannot be built on that box, because that brand cannot do X"   │
 * │ is the ANSWER the milestone exists to give. It is what lets a technician  │
 * │ who only knows MikroTik decide, before ordering hardware and before       │
 * │ driving to a site, that a Vigor will not do. Storing it makes it          │
 * │ queryable ("which capability blocks the most of my sites"), reviewable    │
 * │ and — when a brand profile is corrected — diffable. An exception in a log │
 * │ file would be none of those.                                             │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ FOUR DECISIONS THAT MUST SURVIVE A REFACTOR ─────────────────────────────┐
 * │                                                                           │
 * │ 1. `site_intents.body` IS CHECKED FOR SECRETS BY THE DATABASE.            │
 * │    The intent schema has no field a password can be typed into — every    │
 * │    credential is a `ref:` into the vault (§8.2). The CHECK below is the   │
 * │    belt to that braces, and it exists because the last audit found the    │
 * │    L2TP passwords of an entire fleet inside a jsonb column that was being │
 * │    served to the UI. A constraint refuses the INSERT; a code review only  │
 * │    refuses the next one.                                                  │
 * │                                                                           │
 * │ 2. NEITHER CHILD TABLE CARRIES A TENANT COLUMN, AND THAT IS DELIBERATE.   │
 * │    Both hang off `site_intents` (tenant-scoped) AND off `devices`         │
 * │    (tenant-scoped), and a row whose two parents disagreed would be a      │
 * │    cross-tenant leak with a foreign key blessing it. A third copy of the  │
 * │    truth would be a third thing that can be wrong, so the triggers        │
 * │    `intent_child_same_tenant()` refuse the write instead, exactly as      │
 * │    `policy_results_same_tenant()` does in 012. Every read still joins     │
 * │    `site_intents` and filters on `tenant_id`: the trigger protects the    │
 * │    write path, the join protects the read path, and neither replaces the  │
 * │    other.                                                                 │
 * │                                                                           │
 * │ 3. `device_id` IS NULLABLE, SO EVERY UNIQUENESS IS TWO PARTIAL INDEXES.   │
 * │    Compiling for a FAMILY with no device in hand is the "which of my      │
 * │    brands could take this site" screen, and it is the cheapest and most   │
 * │    valuable thing K4 does. `UNIQUE (intent_id, device_id, ncm_hash)`      │
 * │    alone would be a no-op on exactly those rows, because NULLS DISTINCT   │
 * │    is the Postgres default and two NULLs never collide — the table would  │
 * │    grow a row per click.                                                  │
 * │                                                                           │
 * │ 4. `compiler_version` IS STORED ON EVERY COMPILATION.                     │
 * │    The renderers are frozen by golden files; the day one is deliberately  │
 * │    changed, every stored artefact predates the change. "This artefact was │
 * │    produced by compiler v1 and today's compiler is v2" must have an       │
 * │    answer other than a shrug — the same argument as                       │
 * │    `saved_queries.compiled_sql_hash` in 012.                              │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

/** `shared/src/device.ts` — DEVICE_FAMILIES. Longest: 'mikrotik_routeros7' (18). */
const FAMILIES =
  "'mikrotik_routeros6','mikrotik_routeros7','draytek_vigor','zyxel_nebula'," +
  "'zyxel_standalone','zyxel_cpe','sonicwall_sonicos'";

/** `shared/src/device.ts` — DEVICE_BRANDS. Longest: 'sonicwall' (9). */
const BRANDS = "'mikrotik','draytek','zyxel','sonicwall'";

/** `shared/src/intent.ts` — ARTIFACT_FORMATS. Longest: 'zyxel_zld_cli' (13). */
const ARTIFACT_FORMATS = "'routeros_script','draytek_cli','zyxel_zld_cli','sonicos_rest'";

/** `shared/src/intent.ts` — CAPABILITY_GAP_REASONS.
 *  Longest: 'driver_capability_conflicts' (27). */
const GAP_REASONS = "'family_cannot_express','driver_capability_missing','driver_capability_conflicts'";

/**
 * Key names that may never appear in a stored intent or in a stored desired
 * document. Matched against the jsonb rendered as text, so it catches a nested
 * object as well as a top-level field.
 *
 * The intent's own vocabulary is `pppoeSecretRef`, `pskRef`, `passwordRef`,
 * `credentialRef` — none of which match, because the pattern demands the key
 * END at the closing quote. That asymmetry is the point: a REFERENCE is
 * welcome, a VALUE is refused.
 */
const NO_SECRET_KEYS =
  "'\"(password|passwd|passphrase|psk|pre_?shared_?key|secret|community|api_?key|" +
  "private_?key|auth_?key|priv_?key|shared_?secret|keystring)\"[[:space:]]*:'";

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // site_intents — what the operator declared the site must be
  // ==========================================================================
  await knex.schema.createTable('site_intents', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    // NULLABLE on purpose: an intent is a REUSABLE site template until it is
    // bound to a site. "The standard branch office" is the shape an MSP
    // actually works with, and forcing a site here would make the first useful
    // thing K4 does impossible to express.
    t.integer('site_id').nullable()
      .references('id').inTable('sites').onDelete('SET NULL');

    // 40, matching `IntentSlug` in shared/src/intent.ts. The slug is not a
    // label: it is the head of every `obliwan:<slug>.<record>` marker written
    // onto the equipment, so changing it re-keys every record ObliWAN owns on
    // that site. That is why it has its own format CHECK.
    t.string('slug', 40).notNullable();
    t.string('name', 120).notNullable();
    t.text('description').nullable();

    t.integer('schema_version').notNullable();
    t.jsonb('body').notNullable();

    // Bumped on every edit. Carried onto each compilation so an artefact can
    // always be traced to the exact text it came from.
    t.integer('revision').notNullable().defaultTo(1);
    t.boolean('is_published').notNullable().defaultTo(false);

    // SET NULL, not CASCADE: deleting the engineer who wrote the site design
    // must not delete the site design.
    t.integer('created_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE site_intents ADD CONSTRAINT site_intents_slug_fmt_chk '
      + "CHECK (slug ~ '^[a-z][a-z0-9-]*[a-z0-9]$')",
  );
  await knex.schema.raw(
    'ALTER TABLE site_intents ADD CONSTRAINT site_intents_schema_version_chk '
      + 'CHECK (schema_version BETWEEN 1 AND 1000)',
  );
  await knex.schema.raw(
    'ALTER TABLE site_intents ADD CONSTRAINT site_intents_revision_chk CHECK (revision >= 1)',
  );
  // Decision 1. The intent has no field for a secret; this refuses the row that
  // would prove otherwise.
  await knex.schema.raw(
    'ALTER TABLE site_intents ADD CONSTRAINT site_intents_no_secret_chk '
      + `CHECK (body::text !~* ${NO_SECRET_KEYS})`,
  );
  // A jsonb document is not a file upload. 256 KiB is ~50x the largest
  // realistic site intent and still small enough to keep out of TOAST hell.
  await knex.schema.raw(
    'ALTER TABLE site_intents ADD CONSTRAINT site_intents_body_size_chk '
      + 'CHECK (length(body::text) BETWEEN 2 AND 262144)',
  );

  // Per TENANT, case-insensitively. Two customers both having a "branch-office"
  // intent is normal; one customer owning "Branch-Office" and "branch-office"
  // is a support ticket — and, because the slug becomes an on-device marker,
  // two markers that differ only in case would pair against each other.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX site_intents_tenant_slug_uq ON site_intents (tenant_id, lower(slug))',
  );
  // PARTIAL: `site_id` is a nullable scope column, and the unbound intents (the
  // reusable templates) are the majority. Indexing their NULLs would be dead
  // weight on every insert.
  await knex.schema.raw(
    'CREATE INDEX site_intents_tenant_site_idx ON site_intents (tenant_id, site_id) '
      + 'WHERE site_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX site_intents_tenant_name_idx ON site_intents (tenant_id, name)',
  );

  // ==========================================================================
  // intent_compilations — the desired NCM and the dialect artefact
  // ==========================================================================
  await knex.schema.createTable('intent_compilations', (t) => {
    t.bigIncrements('id').primary();

    t.integer('intent_id').notNullable()
      .references('id').inTable('site_intents').onDelete('CASCADE');
    // Decision 3: NULL = compiled for a FAMILY, with no device in hand.
    t.integer('device_id').nullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    t.string('family', 48).notNullable();
    t.string('brand', 32).notNullable();

    t.integer('intent_revision').notNullable();
    t.integer('compiler_version').notNullable();

    // The DESIRED document. This is the output that matters: the planner diffs
    // it against `config_snapshots.ncm`, and the artefact below is a rendering
    // of it, not the other way round.
    t.jsonb('ncm').notNullable();
    t.string('ncm_hash', 64).notNullable();

    // 24: longest artefact format is 'zyxel_zld_cli' (13). Headroom, because a
    // column sized to its longest CURRENT value is a `value too long` waiting
    // for the next dialect.
    t.string('artifact_format', 24).notNullable();
    t.string('artifact_sha256', 64).notNullable();
    // REDACTED by construction: `assertArtefactRedacted` refuses to return an
    // artefact whose credential assignments hold anything but a
    // `<<secret:label>>` placeholder (§8.2). This column is shown in the plan,
    // exported in a bundle and read by the audit trail.
    t.text('artifact').notNullable();

    t.jsonb('features').notNullable().defaultTo('[]');
    t.jsonb('warnings').notNullable().defaultTo('[]');

    t.integer('compiled_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('compiled_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    'ALTER TABLE intent_compilations ADD CONSTRAINT intent_compilations_family_chk '
      + `CHECK (family IN (${FAMILIES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE intent_compilations ADD CONSTRAINT intent_compilations_brand_chk '
      + `CHECK (brand IN (${BRANDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE intent_compilations ADD CONSTRAINT intent_compilations_format_chk '
      + `CHECK (artifact_format IN (${ARTIFACT_FORMATS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE intent_compilations ADD CONSTRAINT intent_compilations_hash_fmt_chk '
      + "CHECK (ncm_hash ~ '^[0-9a-f]{64}$' AND artifact_sha256 ~ '^[0-9a-f]{64}$')",
  );
  await knex.schema.raw(
    'ALTER TABLE intent_compilations ADD CONSTRAINT intent_compilations_version_chk '
      + 'CHECK (compiler_version >= 1 AND intent_revision >= 1)',
  );
  // The same key-name guard as the intent body, on the stored desired document.
  //
  // NOT applied to `artifact`, and the omission is a decision rather than an
  // oversight: that column holds free text in four dialects, where `password=`,
  // `password "…"` and `"shared_secret": "…"` are all legal spellings and where
  // the redaction placeholder is itself literally `<<secret:label>>`. Every
  // POSIX pattern that catches the plaintext spellings also matches the
  // placeholder, and a CHECK that rejects correct rows is an outage waiting for
  // the first site build. The guard for the artefact is
  // `assertArtefactRedacted`, which collapses the placeholders BEFORE scanning
  // and is exercised in both directions by the M11 self-test.
  await knex.schema.raw(
    'ALTER TABLE intent_compilations ADD CONSTRAINT intent_compilations_no_secret_chk '
      + `CHECK (ncm::text !~* ${NO_SECRET_KEYS})`,
  );

  // ── idempotence, in two partial indexes (decision 3) ──────────────────────
  await knex.schema.raw(
    'CREATE UNIQUE INDEX intent_compilations_device_uq ON intent_compilations '
      + '(intent_id, device_id, ncm_hash) WHERE device_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX intent_compilations_family_uq ON intent_compilations '
      + '(intent_id, family, ncm_hash) WHERE device_id IS NULL',
  );

  // Reads. Both start with the column the caller filters on, and `intent_id`
  // is tenant-scoped through `site_intents`, which is what keeps these indexes
  // within one customer's data.
  await knex.schema.raw(
    'CREATE INDEX intent_compilations_intent_idx ON intent_compilations '
      + '(intent_id, family, compiled_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX intent_compilations_device_idx ON intent_compilations '
      + '(device_id, compiled_at DESC) WHERE device_id IS NOT NULL',
  );

  // ==========================================================================
  // intent_capability_gaps — the refusals, kept because they are the answer
  // ==========================================================================
  await knex.schema.createTable('intent_capability_gaps', (t) => {
    t.bigIncrements('id').primary();

    t.integer('intent_id').notNullable()
      .references('id').inTable('site_intents').onDelete('CASCADE');
    t.integer('device_id').nullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    t.string('family', 48).notNullable();
    t.string('brand', 32).notNullable();

    // 48: longest feature today is 'mgmt.serviceRestriction' (23). The names
    // are a wire format shared with the client, so the width is headroom and
    // the shape is a CHECK rather than an enum nobody can extend.
    t.string('feature', 48).notNullable();
    // 32: longest reason is 'driver_capability_conflicts' (27).
    t.string('reason', 32).notNullable();
    // 48: longest DeviceCapabilities flag today is 'supportsStructuredDiff'
    // (22). NULL when the family simply cannot express the feature — there is
    // no flag to name, and inventing one would blame the driver for a product
    // limit.
    t.string('capability_flag', 48).nullable();

    t.string('intent_path', 120).notNullable();
    t.text('note').nullable();

    t.timestamp('detected_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    'ALTER TABLE intent_capability_gaps ADD CONSTRAINT intent_gaps_family_chk '
      + `CHECK (family IN (${FAMILIES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE intent_capability_gaps ADD CONSTRAINT intent_gaps_brand_chk '
      + `CHECK (brand IN (${BRANDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE intent_capability_gaps ADD CONSTRAINT intent_gaps_reason_chk '
      + `CHECK (reason IN (${GAP_REASONS}))`,
  );
  // `<group>.<name>`, the shape of every member of INTENT_FEATURES. The digit
  // class is not decoration: `mgmt.snmpV3` is a feature name, and a pattern
  // that forgot it would reject exactly the refusal a DrayTek produces.
  await knex.schema.raw(
    'ALTER TABLE intent_capability_gaps ADD CONSTRAINT intent_gaps_feature_fmt_chk '
      + "CHECK (feature ~ '^[a-z]+\\.[a-zA-Z0-9]+$')",
  );
  // A flag is meaningful only on the two reasons that name one, and its absence
  // is meaningful on the third. Both directions are enforced, because a gap
  // that says "the driver declares undefined = false" helps nobody.
  await knex.schema.raw(
    'ALTER TABLE intent_capability_gaps ADD CONSTRAINT intent_gaps_flag_chk '
      + "CHECK ((reason = 'family_cannot_express' AND capability_flag IS NULL) "
      + "OR (reason <> 'family_cannot_express' AND capability_flag IS NOT NULL))",
  );

  // One row per (intent, family, feature) per target. Re-checking the same
  // intent must refresh the answer, not grow the table — and `device_id` is
  // nullable, so it is two partial indexes for the reason in decision 3.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX intent_gaps_device_uq ON intent_capability_gaps '
      + '(intent_id, device_id, feature) WHERE device_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX intent_gaps_family_uq ON intent_capability_gaps '
      + '(intent_id, family, feature) WHERE device_id IS NULL',
  );
  // "What blocks this site, and on which brand" — the screen this table exists
  // for. Scoped by `intent_id`, which is scoped by tenant through its parent.
  await knex.schema.raw(
    'CREATE INDEX intent_gaps_intent_idx ON intent_capability_gaps (intent_id, feature, family)',
  );

  // ==========================================================================
  // The cross-tenant guard (decision 2)
  // ==========================================================================
  //
  // Two foreign keys into two tenant-scoped tables do not, together, say that
  // both point at the same tenant. Nothing in the schema forbids compiling
  // customer A's site design onto customer B's router, and the artefact would
  // then sit in A's history carrying B's device id.
  await knex.schema.raw(`
    CREATE OR REPLACE FUNCTION intent_child_same_tenant() RETURNS trigger AS $$
    DECLARE
      i_tenant integer;
      d_tenant integer;
      d_family text;
    BEGIN
      IF NEW.device_id IS NULL THEN
        RETURN NEW;
      END IF;
      SELECT tenant_id INTO i_tenant FROM site_intents WHERE id = NEW.intent_id;
      SELECT tenant_id, family INTO d_tenant, d_family FROM devices WHERE id = NEW.device_id;
      IF i_tenant IS DISTINCT FROM d_tenant THEN
        RAISE EXCEPTION 'intent % (tenant %) cannot be compiled onto device % (tenant %)',
          NEW.intent_id, i_tenant, NEW.device_id, d_tenant;
      END IF;
      -- A row whose family disagrees with the device it names would make the
      -- artefact unreadable: it would carry SonicOS operations under a device
      -- the poller talks RouterOS to.
      IF d_family IS DISTINCT FROM NEW.family THEN
        RAISE EXCEPTION 'compilation for family % does not match device % (family %)',
          NEW.family, NEW.device_id, d_family;
      END IF;
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
  `);
  await knex.schema.raw(`
    CREATE TRIGGER intent_compilations_same_tenant_trg
      BEFORE INSERT OR UPDATE OF intent_id, device_id, family ON intent_compilations
      FOR EACH ROW EXECUTE FUNCTION intent_child_same_tenant();
  `);
  await knex.schema.raw(`
    CREATE TRIGGER intent_gaps_same_tenant_trg
      BEFORE INSERT OR UPDATE OF intent_id, device_id, family ON intent_capability_gaps
      FOR EACH ROW EXECUTE FUNCTION intent_child_same_tenant();
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS intent_gaps_same_tenant_trg ON intent_capability_gaps',
  );
  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS intent_compilations_same_tenant_trg ON intent_compilations',
  );
  await knex.schema.dropTableIfExists('intent_capability_gaps');
  await knex.schema.dropTableIfExists('intent_compilations');
  await knex.schema.dropTableIfExists('site_intents');
  // Triggers go with their table; the FUNCTION does not, and a leftover one
  // makes the next `migrate:latest` fail on CREATE FUNCTION.
  await knex.schema.raw('DROP FUNCTION IF EXISTS intent_child_same_tenant()');
}
