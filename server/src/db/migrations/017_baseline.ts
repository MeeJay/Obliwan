import type { Knex } from 'knex';

/**
 * 017_baseline.ts — M12 (K8): fleet take-over / Golden Site.
 *
 * Implements section 5/M12 of ARCHITECTURE.md. The TypeScript contract these
 * tables carry lives in `shared/src/baseline.ts`.
 *
 * The store has one job: make a mined template EXPLAINABLE. Every number the UI
 * shows — "present on 27/30", "this cluster explains 86 % of this site's
 * lines", "eleven differences, four of which you signed for" — has to be a
 * column somebody can read in psql during an argument about whether a push is
 * safe. None of it is recomputable from the drafts alone, because the drafts are
 * the OUTPUT and the evidence is the input.
 *
 * ┌─ SEVEN DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ──────────────────┐
 * │                                                                           │
 * │ 1. EVERY TABLE CARRIES `tenant_id`, NOT NULL, AND IT LEADS EVERY KEY.     │
 * │    Not one of these tables is a shipped library: a baseline is mined FROM │
 * │    one customer's routers and it describes that customer's network. The   │
 * │    NULL-means-library convention of `templates` and `normalization_rules` │
 * │    is deliberately NOT reproduced here — a "library baseline" would be    │
 * │    one customer's topology offered to every other customer.               │
 * │    `tenant_id` is denormalised down the whole tree and kept honest by     │
 * │    composite foreign keys `(parent_id, tenant_id)`, exactly as migration  │
 * │    008 does, so that a cluster can never point at another tenant's run    │
 * │    and a member can never point at another tenant's device.               │
 * │                                                                           │
 * │ 2. `devices` GAINS `UNIQUE (id, tenant_id)`. It is what makes the         │
 * │    composite FK of decision 1 expressible against the fleet. Additive,    │
 * │    guarded by IF NOT EXISTS, dropped on the way down. Without it,         │
 * │    `baseline_cluster_members.device_id` is a bare FK and a bug in the     │
 * │    miner could file customer A's router under customer B's profile — the  │
 * │    same class of accident as R4, in a table nobody would think to audit.  │
 * │                                                                           │
 * │ 3. NO SECRET REACHES THESE TABLES, AND THE DATABASE SAYS SO TOO.          │
 * │    `shared/src/baseline.ts` refuses credential-derived attributes at      │
 * │    extraction time; `baseline_slots_slot_secret_chk` and its twin on      │
 * │    `baseline_deviations` refuse a slot whose NAME looks like one at write │
 * │    time. Two independent refusals, because the previous audit found the   │
 * │    L2TP passwords of an entire fleet in a jsonb column served to the UI,  │
 * │    and a service-layer rule is not what runs when somebody adds an        │
 * │    eleventh resource kind at 2 a.m.                                       │
 * │                                                                           │
 * │ 4. "CLIENT SPECIFICITY" IS A DOCUMENTED EXCEPTION, ENFORCED BY A CHECK.   │
 * │    `baseline_deviations_client_specific_chk` makes it impossible to mark  │
 * │    a deviation `client_specific` without pointing at a row of             │
 * │    `baseline_exceptions`, and `baseline_exceptions.reason` is NOT NULL    │
 * │    and non-blank. This is the same constraint, for the same reason, as    │
 * │    `normalization_rules.rationale` in migration 007: an undocumented      │
 * │    exception is a suppression wearing a better name, and a suppression is │
 * │    how a real difference stops being visible.                             │
 * │                                                                           │
 * │ 5. THE SCORE IS STORED TWICE. `score_raw` is what the fleet looks like;   │
 * │    `score_adjusted` is what it looks like once the exceptions are         │
 * │    honoured. Storing only the second would let a fleet reach 100 % by     │
 * │    signing for everything; storing only the first makes a legitimately    │
 * │    different customer look permanently broken. Both columns, always, and  │
 * │    the API returns them together.                                         │
 * │                                                                           │
 * │ 6. `baseline_slots.cluster_id` IS NULLABLE AND THEREFORE ITS UNIQUENESS   │
 * │    IS TWO PARTIAL INDEXES. NULL means "fleet-wide statistic for this      │
 * │    run", non-NULL means "this cluster's slot". PostgreSQL's default is    │
 * │    NULLS DISTINCT, so a single `UNIQUE (tenant_id, run_id, cluster_id,    │
 * │    slot)` would let the fleet-wide side hold one slot a hundred times.    │
 * │    Same lesson as `templates_library_name_uq` (008) and                   │
 * │    `nr_order_library_uq` (013). `baseline_exceptions` gets the same       │
 * │    treatment for its nullable `scope_id`.                                 │
 * │                                                                           │
 * │ 7. NOTHING HERE WRITES TO AN EQUIPMENT, AND NOTHING HERE PUBLISHES.       │
 * │    `baseline_drafts.template_revision_id` points at a revision this       │
 * │    milestone creates with `status = 'draft'` and never advances: the      │
 * │    freeze trigger of 008 does not even engage on a draft, and a draft     │
 * │    revision cannot be assigned, rendered into a plan or applied. D3 is    │
 * │    untouched — a mined template becomes a change only after a human       │
 * │    holding TEMPLATE_WRITE rewrites it into brand syntax and publishes it. │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ENUMS AS TEXT + CHECK, like every other vocabulary in this schema since 002.
 * Widths are set from the LONGEST value of the CHECK and then rounded up, which
 * is the rule this project already paid for once: `devices.role` was sized for
 * 'chr' and every INSERT of 'concentrator' failed after a rename that compiled.
 */

// Inlined as literals rather than imported from @obliwan/shared: a migration
// describes the schema as it was on the day it ran (002, 005, 007, 008).
const RUN_STATUSES = "'pending','running','succeeded','failed','cancelled'";     // 9
const SLOT_ROLES = "'constant','variable','divergent'";                          // 9
const DEVIATION_KINDS = "'missing','extra','value_conflict'";                    // 14
const DEVIATION_CLASSES =
  "'unclassified','client_specific','to_remediate','template_gap'";              // 15
const DRAFT_STATUSES = "'draft','promoted','discarded'";                         // 9
const LINKAGES = "'complete','average'";                                         // 8
const EXCEPTION_SCOPES = "'tenant','site','device'";                             // 6
const VALUE_CLASSES =
  "'empty','boolean','integer','cidr','ip','iface','fqdn','set','literal'";      // 7
const SECTIONS =
  "'interface','vlan','route','firewallRule','natRule'," +
  "'dhcpScope','ipsecPeer','localUser','service','qosRule'";                     // 12
const DEVICE_BRANDS = "'mikrotik','draytek','zyxel','sonicwall'";                // 9

/**
 * Decision 3, database side. Deliberately the SAME token list as
 * `BASELINE_FORBIDDEN_ATTRIBUTES` in `shared/src/baseline.ts`, written as one
 * case-insensitive regex, anchored on the LAST segment of the slot.
 *
 * Only the last segment, and the narrowness is the point: a slot is
 * `section/discriminator/attribute`, and the discriminator is built from names
 * the CUSTOMER chose. A local user called `secretary`, an interface called
 * `pskbridge` or a DHCP scope called `credential-lab` contains one of these
 * tokens and is not a secret; rejecting those rows would amputate a real
 * customer's baseline while looking like a mining bug. The attribute is the
 * half ObliWAN writes, so it is the half this constraint governs — a match
 * there means the miner tried to turn a credential-bearing attribute into a
 * fact, which is a bug to stop at the INSERT and not a string to sanitise.
 *
 * Kept in exact lockstep with `slotIsForbidden` in `shared/src/baseline.ts`.
 */
const SECRET_SLOT_RE =
  "/[^/]*(password|passphrase|secret|psk|credential|apikey|privatekey|fingerprint)[^/]*$";

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // 0. Decision 2 — the composite target on `devices`.
  // ==========================================================================
  // Guarded rather than plain, because a later migration adding the same
  // constraint must not turn this one into a failed deploy.
  await knex.schema.raw(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'devices_id_tenant_uq'
      ) THEN
        ALTER TABLE devices ADD CONSTRAINT devices_id_tenant_uq UNIQUE (id, tenant_id);
      END IF;
    END $$;
  `);

  // ==========================================================================
  // 1. baseline_runs — one mining pass over a scope of the fleet.
  // ==========================================================================

  await knex.schema.createTable('baseline_runs', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('status', 16).notNullable().defaultTo('pending');

    // The fact/slot algebra this run was mined with. Comparing a run mined at
    // v1 with one mined at v2 is comparing two different questions, and the
    // UI has to be able to refuse to do it.
    t.integer('model_version').notNullable();

    // The full, validated `BaselineParams`. A run that cannot be replayed from
    // its own stored parameters is not evidence.
    t.jsonb('params').notNullable().defaultTo(knex.raw("'{}'::jsonb"));
    // Denormalised out of `params` because the run list filters on it.
    t.string('linkage', 16).notNullable().defaultTo('complete');
    t.string('brand', 24).nullable();

    t.integer('device_count').notNullable().defaultTo(0);
    // Devices in scope that had no usable snapshot. Reported, never hidden: a
    // baseline mined from 31 of 50 routers is a different claim from one mined
    // from all 50, and the difference must not live only in a log line.
    t.integer('skipped_count').notNullable().defaultTo(0);
    t.integer('fact_count').notNullable().defaultTo(0);
    t.integer('slot_count').notNullable().defaultTo(0);
    t.integer('cluster_count').notNullable().defaultTo(0);

    // The k the stopping rule selected, and whether it cleared the purity gate.
    // `purity_gate_met = false` is a legitimate, REPORTED outcome: it means no
    // k up to maxClusters explains minCoverage of every member, and saying so
    // is worth more than silently shipping a template with forty exceptions.
    t.integer('chosen_k').nullable();
    t.boolean('purity_gate_met').notNullable().defaultTo(false);

    t.text('error').nullable();
    t.timestamp('started_at', { useTz: true }).nullable();
    t.timestamp('finished_at', { useTz: true }).nullable();

    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE baseline_runs ADD CONSTRAINT baseline_runs_status_chk
       CHECK (status IN (${RUN_STATUSES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_runs ADD CONSTRAINT baseline_runs_linkage_chk
       CHECK (linkage IN (${LINKAGES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_runs ADD CONSTRAINT baseline_runs_brand_chk
       CHECK (brand IS NULL OR brand IN (${DEVICE_BRANDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_runs ADD CONSTRAINT baseline_runs_counts_chk CHECK (
       device_count >= 0 AND skipped_count >= 0 AND fact_count >= 0
       AND slot_count >= 0 AND cluster_count >= 0
       AND (chosen_k IS NULL OR chosen_k >= 1))`,
  );
  // A terminal run has an end; a non-terminal one does not claim to have had
  // one. Cheap, and it keeps "how long did the last baseline take" honest.
  await knex.schema.raw(
    `ALTER TABLE baseline_runs ADD CONSTRAINT baseline_runs_terminal_chk CHECK (
       (status IN ('succeeded','failed','cancelled') AND finished_at IS NOT NULL)
       OR (status IN ('pending','running') AND finished_at IS NULL))`,
  );
  // A failed run explains itself, and a succeeded one does not carry a corpse.
  await knex.schema.raw(
    `ALTER TABLE baseline_runs ADD CONSTRAINT baseline_runs_error_chk CHECK (
       (status = 'failed' AND error IS NOT NULL) OR (status <> 'failed' AND error IS NULL))`,
  );
  await knex.schema.raw(
    'CREATE INDEX baseline_runs_tenant_idx ON baseline_runs (tenant_id, status, created_at DESC)',
  );
  await knex.schema.raw(
    'ALTER TABLE baseline_runs ADD CONSTRAINT baseline_runs_id_tenant_uq UNIQUE (id, tenant_id)',
  );

  // ==========================================================================
  // 2. baseline_clusters — one proposed site profile.
  // ==========================================================================

  await knex.schema.createTable('baseline_clusters', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.bigInteger('run_id').notNullable();
    t.integer('tenant_id').notNullable();

    t.integer('cluster_index').notNullable();
    t.string('label', 64).notNullable();
    t.string('brand', 24).notNullable();

    t.integer('member_count').notNullable();
    // The member with the smallest total distance to the others: the site to
    // read when somebody asks "what does this profile actually look like".
    // SET NULL and not CASCADE — decommissioning a router must not delete the
    // evidence of a baseline that was mined while it existed.
    t.integer('medoid_device_id').nullable()
      .references('id').inTable('devices').onDelete('SET NULL');

    // numeric, not float: these numbers are shown to operators and compared
    // between runs, and a binary float that prints as 0.8500000000000001 in one
    // client and 0.85 in another is a support ticket.
    t.decimal('cohesion', 6, 5).notNullable();
    t.decimal('coverage_min', 6, 5).notNullable();
    t.decimal('coverage_mean', 6, 5).notNullable();
    t.boolean('purity_ok').notNullable().defaultTo(false);

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE baseline_clusters ADD CONSTRAINT baseline_clusters_run_fk ' +
      'FOREIGN KEY (run_id, tenant_id) REFERENCES baseline_runs (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_clusters ADD CONSTRAINT baseline_clusters_brand_chk
       CHECK (brand IN (${DEVICE_BRANDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_clusters ADD CONSTRAINT baseline_clusters_ranges_chk CHECK (
       cluster_index >= 0 AND member_count >= 1
       AND cohesion BETWEEN 0 AND 1
       AND coverage_min BETWEEN 0 AND 1
       AND coverage_mean BETWEEN 0 AND 1
       AND coverage_min <= coverage_mean + 0.00001)`,
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX baseline_clusters_index_uq ' +
      'ON baseline_clusters (tenant_id, run_id, cluster_index)',
  );
  await knex.schema.raw(
    'ALTER TABLE baseline_clusters ADD CONSTRAINT baseline_clusters_id_tenant_uq ' +
      'UNIQUE (id, tenant_id)',
  );

  // ==========================================================================
  // 3. baseline_cluster_members — which device landed in which profile.
  // ==========================================================================

  await knex.schema.createTable('baseline_cluster_members', (t) => {
    t.bigIncrements('id').primary();

    t.bigInteger('cluster_id').notNullable();
    t.bigInteger('run_id').notNullable();
    t.integer('tenant_id').notNullable();

    t.integer('device_id').notNullable();
    // WHICH snapshot was mined. Without it, "the baseline says ether1 is
    // 10.0.0.1" cannot be checked against anything a month later.
    //
    // NULLABLE, and ON DELETE SET NULL rather than CASCADE, and the difference
    // is not cosmetic: `config_snapshots` is subject to retention, and a
    // CASCADE would silently delete a cluster's MEMBERSHIP rows when an old
    // snapshot is pruned — leaving `baseline_clusters.member_count` claiming
    // twenty-two members over a table that holds none, with nothing in the UI
    // to explain it. The miner always writes this column; a NULL here means
    // "the snapshot this was mined from has since been pruned", which is a
    // true statement the screen can make. Same reasoning as
    // `medoid_device_id`: decommissioning something must not delete the
    // evidence of a baseline that was mined while it existed.
    t.bigInteger('snapshot_id').nullable()
      .references('id').inTable('config_snapshots').onDelete('SET NULL');

    t.integer('facts_total').notNullable();
    t.integer('facts_covered').notNullable();
    t.decimal('coverage', 6, 5).notNullable();
    t.decimal('distance_to_medoid', 6, 5).notNullable();

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE baseline_cluster_members ADD CONSTRAINT bcm_cluster_fk ' +
      'FOREIGN KEY (cluster_id, tenant_id) REFERENCES baseline_clusters (id, tenant_id) ' +
      'ON DELETE CASCADE',
  );
  // Decision 2 in action: the device must belong to the tenant that owns the run.
  await knex.schema.raw(
    'ALTER TABLE baseline_cluster_members ADD CONSTRAINT bcm_device_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_cluster_members ADD CONSTRAINT bcm_counts_chk CHECK (
       facts_total >= 0 AND facts_covered >= 0 AND facts_covered <= facts_total
       AND coverage BETWEEN 0 AND 1 AND distance_to_medoid BETWEEN 0 AND 1)`,
  );
  // A device belongs to exactly ONE cluster per run. Anything else and the
  // conformance score double-counts it.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX bcm_run_device_uq ON baseline_cluster_members (tenant_id, run_id, device_id)',
  );
  await knex.schema.raw(
    'CREATE INDEX bcm_cluster_idx ON baseline_cluster_members (tenant_id, cluster_id, coverage)',
  );

  // ==========================================================================
  // 4. baseline_slots — the alignment table, and where variables are born.
  // ==========================================================================

  await knex.schema.createTable('baseline_slots', (t) => {
    t.bigIncrements('id').primary();

    t.bigInteger('run_id').notNullable();
    t.integer('tenant_id').notNullable();
    // Decision 6: NULL = the fleet-wide statistic for the run.
    t.bigInteger('cluster_id').nullable();

    t.string('slot', 400).notNullable();
    t.string('section', 24).notNullable();
    t.string('role', 16).notNullable();

    // "present on 27/30" — the counter §5/M12 names explicitly.
    t.integer('present_on').notNullable();
    t.integer('member_count').notNullable();
    t.integer('distinct_values').notNullable();

    t.text('constant_value').nullable();
    t.string('var_name', 120).nullable();
    t.string('value_class', 16).notNullable();
    // At most 8 values, sorted. Enough to judge a variable at a glance without
    // turning this column into a second copy of `baseline_facts`.
    t.jsonb('sample_values').notNullable().defaultTo(knex.raw("'[]'::jsonb"));

    // Did this slot make it into the draft body (presence >= bodyPresenceRatio)?
    t.boolean('in_body').notNullable().defaultTo(false);

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE baseline_slots ADD CONSTRAINT baseline_slots_run_fk ' +
      'FOREIGN KEY (run_id, tenant_id) REFERENCES baseline_runs (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE baseline_slots ADD CONSTRAINT baseline_slots_cluster_fk ' +
      'FOREIGN KEY (cluster_id, tenant_id) REFERENCES baseline_clusters (id, tenant_id) ' +
      'ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_slots ADD CONSTRAINT baseline_slots_section_chk
       CHECK (section IN (${SECTIONS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_slots ADD CONSTRAINT baseline_slots_role_chk
       CHECK (role IN (${SLOT_ROLES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_slots ADD CONSTRAINT baseline_slots_class_chk
       CHECK (value_class IN (${VALUE_CLASSES}))`,
  );
  // The role IS the shape of the row. A 'constant' with no value could not be
  // rendered; a 'variable' with no name could not be filled; a 'divergent' slot
  // that reached the body would be a template silently dropping half a firewall.
  await knex.schema.raw(
    `ALTER TABLE baseline_slots ADD CONSTRAINT baseline_slots_role_shape_chk CHECK (
       (role = 'constant'  AND constant_value IS NOT NULL AND var_name IS NULL) OR
       (role = 'variable'  AND var_name IS NOT NULL AND constant_value IS NULL) OR
       (role = 'divergent' AND var_name IS NULL AND constant_value IS NULL AND in_body = false))`,
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_slots ADD CONSTRAINT baseline_slots_counts_chk CHECK (
       present_on >= 0 AND member_count >= 1 AND present_on <= member_count
       AND distinct_values >= 0
       AND jsonb_typeof(sample_values) = 'array' AND jsonb_array_length(sample_values) <= 8)`,
  );
  // A variable key that migration 008's `config_variables.key` would reject is a
  // variable nobody can ever fill in.
  await knex.schema.raw(
    "ALTER TABLE baseline_slots ADD CONSTRAINT baseline_slots_varname_chk " +
      "CHECK (var_name IS NULL OR var_name ~ '^[a-z][a-zA-Z0-9_]{0,119}$')",
  );
  // Decision 3, second refusal.
  await knex.schema.raw(
    `ALTER TABLE baseline_slots ADD CONSTRAINT baseline_slots_slot_secret_chk
       CHECK (slot !~* '${SECRET_SLOT_RE}')`,
  );
  // Decision 6: two partial indexes, because NULLS DISTINCT would make the
  // fleet-wide side unique by vacuity.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX baseline_slots_cluster_uq ON baseline_slots ' +
      '(tenant_id, cluster_id, slot) WHERE cluster_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX baseline_slots_run_uq ON baseline_slots ' +
      '(tenant_id, run_id, slot) WHERE cluster_id IS NULL',
  );
  // The read shape: "the body of this cluster's draft, in order".
  await knex.schema.raw(
    'CREATE INDEX baseline_slots_body_idx ON baseline_slots ' +
      '(tenant_id, cluster_id, section, slot) WHERE cluster_id IS NOT NULL AND in_body',
  );

  // ==========================================================================
  // 5. baseline_exceptions — the signed-for differences. Survives its run.
  // ==========================================================================
  // Deliberately NOT keyed to a run: "this customer runs its own DNS and always
  // will" is a fact about the customer, not about a mining pass. It is looked up
  // by (tenant, scope, slot) on every run, which is why it outlives them.

  await knex.schema.createTable('baseline_exceptions', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    // Same four-level scope vocabulary as settings / assignments / variables,
    // minus 'global' — an exception is never cross-tenant (decision 1).
    t.string('scope', 20).notNullable();
    // NULL exactly for scope = 'tenant'.
    t.integer('scope_id').nullable();

    t.string('slot', 400).notNullable();
    t.text('expected_value').nullable();
    t.text('actual_value').nullable();

    // NOT NULL and non-blank, for the same reason
    // `normalization_rules.rationale` is: an exception nobody wrote a reason for
    // is a suppression, and a suppression is how a real difference stops being
    // visible. It is a database constraint and not a convention because a
    // convention is what gets skipped at 2 a.m.
    t.text('reason').notNullable();

    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE baseline_exceptions ADD CONSTRAINT baseline_exceptions_scope_chk
       CHECK (scope IN (${EXCEPTION_SCOPES}))`,
  );
  await knex.schema.raw(
    "ALTER TABLE baseline_exceptions ADD CONSTRAINT baseline_exceptions_scope_id_chk " +
      "CHECK ((scope = 'tenant') = (scope_id IS NULL))",
  );
  await knex.schema.raw(
    "ALTER TABLE baseline_exceptions ADD CONSTRAINT baseline_exceptions_reason_chk " +
      "CHECK (btrim(reason) <> '')",
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_exceptions ADD CONSTRAINT baseline_exceptions_slot_secret_chk
       CHECK (slot !~* '${SECRET_SLOT_RE}')`,
  );
  // Nullable scope column -> partial indexes, both leading with tenant_id.
  await knex.schema.raw(
    "CREATE UNIQUE INDEX baseline_exceptions_tenant_uq ON baseline_exceptions " +
      "(tenant_id, slot) WHERE scope = 'tenant'",
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX baseline_exceptions_scoped_uq ON baseline_exceptions ' +
      '(tenant_id, scope, scope_id, slot) WHERE scope_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX baseline_exceptions_lookup_idx ON baseline_exceptions (tenant_id, slot, scope)',
  );
  await knex.schema.raw(
    'ALTER TABLE baseline_exceptions ADD CONSTRAINT baseline_exceptions_id_tenant_uq ' +
      'UNIQUE (id, tenant_id)',
  );

  // ==========================================================================
  // 6. baseline_deviations — every difference, listed and classable.
  // ==========================================================================

  await knex.schema.createTable('baseline_deviations', (t) => {
    t.bigIncrements('id').primary();

    t.bigInteger('run_id').notNullable();
    t.integer('tenant_id').notNullable();
    t.bigInteger('cluster_id').notNullable();
    t.integer('device_id').notNullable();

    t.string('slot', 400).notNullable();
    t.string('section', 24).notNullable();
    t.string('kind', 24).notNullable();

    t.text('template_value').nullable();
    t.text('device_value').nullable();

    t.string('classification', 24).notNullable().defaultTo('unclassified');
    // Decision 4: 'client_specific' is unrepresentable without this pointer.
    // RESTRICT, not SET NULL — deleting the exception must not silently turn a
    // signed-for difference back into an unexplained one while it still reads
    // 'client_specific'.
    t.bigInteger('exception_id').nullable();
    t.text('note').nullable();
    t.integer('classified_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('classified_at', { useTz: true }).nullable();

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE baseline_deviations ADD CONSTRAINT baseline_deviations_run_fk ' +
      'FOREIGN KEY (run_id, tenant_id) REFERENCES baseline_runs (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE baseline_deviations ADD CONSTRAINT baseline_deviations_cluster_fk ' +
      'FOREIGN KEY (cluster_id, tenant_id) REFERENCES baseline_clusters (id, tenant_id) ' +
      'ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE baseline_deviations ADD CONSTRAINT baseline_deviations_device_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE baseline_deviations ADD CONSTRAINT baseline_deviations_exception_fk ' +
      'FOREIGN KEY (exception_id, tenant_id) REFERENCES baseline_exceptions (id, tenant_id) ' +
      'ON DELETE RESTRICT',
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_deviations ADD CONSTRAINT baseline_deviations_section_chk
       CHECK (section IN (${SECTIONS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_deviations ADD CONSTRAINT baseline_deviations_kind_chk
       CHECK (kind IN (${DEVIATION_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_deviations ADD CONSTRAINT baseline_deviations_class_chk
       CHECK (classification IN (${DEVIATION_CLASSES}))`,
  );
  // The kind IS which side is missing. A 'missing' carrying a device value is a
  // contradiction the UI would render as an empty diff.
  await knex.schema.raw(
    `ALTER TABLE baseline_deviations ADD CONSTRAINT baseline_deviations_shape_chk CHECK (
       (kind = 'missing' AND template_value IS NOT NULL AND device_value IS NULL) OR
       (kind = 'extra'   AND template_value IS NULL AND device_value IS NOT NULL) OR
       (kind = 'value_conflict' AND template_value IS NOT NULL AND device_value IS NOT NULL))`,
  );
  // Decision 4, the constraint that makes "client specificity" a document.
  await knex.schema.raw(
    "ALTER TABLE baseline_deviations ADD CONSTRAINT baseline_deviations_client_specific_chk " +
      "CHECK (classification <> 'client_specific' OR exception_id IS NOT NULL)",
  );
  // A classification is an act: it has an author and a time, or it has not
  // happened. 'unclassified' is what the miner writes and carries neither.
  await knex.schema.raw(
    "ALTER TABLE baseline_deviations ADD CONSTRAINT baseline_deviations_classified_chk " +
      "CHECK ((classification = 'unclassified') = (classified_at IS NULL))",
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_deviations ADD CONSTRAINT baseline_deviations_slot_secret_chk
       CHECK (slot !~* '${SECRET_SLOT_RE}')`,
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX baseline_deviations_uq ON baseline_deviations ' +
      '(tenant_id, run_id, device_id, slot, kind)',
  );
  // "Show me everything nobody has looked at yet, worst cluster first" — the
  // one screen this table exists for.
  await knex.schema.raw(
    'CREATE INDEX baseline_deviations_triage_idx ON baseline_deviations ' +
      '(tenant_id, run_id, classification, cluster_id)',
  );
  await knex.schema.raw(
    'CREATE INDEX baseline_deviations_device_idx ON baseline_deviations ' +
      '(tenant_id, device_id, run_id)',
  );

  // ==========================================================================
  // 7. baseline_conformance — the score, per device, both ways.
  // ==========================================================================

  await knex.schema.createTable('baseline_conformance', (t) => {
    t.bigIncrements('id').primary();

    t.bigInteger('run_id').notNullable();
    t.integer('tenant_id').notNullable();
    t.bigInteger('cluster_id').nullable();
    t.integer('device_id').notNullable();
    // Denormalised so "score per client site" is one GROUP BY and not a join
    // to `devices` on a table the fleet screen reads on every refresh.
    // SET NULL through devices is not available here (composite FK), so the
    // column is filled at write time and left alone: a site rename must not
    // rewrite historical scores.
    t.integer('site_id').nullable();

    t.integer('facts_total').notNullable();
    t.integer('facts_covered').notNullable();
    t.integer('deviations').notNullable();
    t.integer('excused').notNullable();

    t.decimal('score_raw', 6, 5).notNullable();
    t.decimal('score_adjusted', 6, 5).notNullable();

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE baseline_conformance ADD CONSTRAINT baseline_conformance_run_fk ' +
      'FOREIGN KEY (run_id, tenant_id) REFERENCES baseline_runs (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE baseline_conformance ADD CONSTRAINT baseline_conformance_cluster_fk ' +
      'FOREIGN KEY (cluster_id, tenant_id) REFERENCES baseline_clusters (id, tenant_id) ' +
      'ON DELETE SET NULL',
  );
  await knex.schema.raw(
    'ALTER TABLE baseline_conformance ADD CONSTRAINT baseline_conformance_device_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_conformance ADD CONSTRAINT baseline_conformance_counts_chk CHECK (
       facts_total >= 0 AND facts_covered >= 0 AND facts_covered <= facts_total
       AND deviations >= 0 AND excused >= 0 AND excused <= deviations
       AND score_raw BETWEEN 0 AND 1 AND score_adjusted BETWEEN 0 AND 1
       AND score_adjusted >= score_raw - 0.00001)`,
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX baseline_conformance_uq ON baseline_conformance ' +
      '(tenant_id, run_id, device_id)',
  );
  await knex.schema.raw(
    'CREATE INDEX baseline_conformance_site_idx ON baseline_conformance ' +
      '(tenant_id, run_id, site_id)',
  );

  // ==========================================================================
  // 8. baseline_drafts — the template a human is asked to review.
  // ==========================================================================

  await knex.schema.createTable('baseline_drafts', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.bigInteger('cluster_id').notNullable();
    t.bigInteger('run_id').notNullable();
    t.integer('tenant_id').notNullable();

    t.string('brand', 24).notNullable();
    t.text('body').notNullable();
    t.string('body_sha256', 64).notNullable();
    t.jsonb('var_schema').notNullable().defaultTo(knex.raw("'{}'::jsonb"));

    t.integer('line_count').notNullable();
    t.integer('variable_count').notNullable();
    t.decimal('coverage_mean', 6, 5).notNullable();

    t.string('status', 16).notNullable().defaultTo('draft');
    // Filled on promotion. RESTRICT on the revision: a promoted draft is the
    // provenance of that revision, and deleting the revision under it would
    // leave a row claiming to have produced something that no longer exists.
    t.bigInteger('template_id').nullable()
      .references('id').inTable('templates').onDelete('SET NULL');
    t.bigInteger('template_revision_id').nullable()
      .references('id').inTable('template_revisions').onDelete('RESTRICT');
    t.timestamp('promoted_at', { useTz: true }).nullable();
    t.integer('promoted_by').nullable().references('id').inTable('users').onDelete('SET NULL');

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE baseline_drafts ADD CONSTRAINT baseline_drafts_cluster_fk ' +
      'FOREIGN KEY (cluster_id, tenant_id) REFERENCES baseline_clusters (id, tenant_id) ' +
      'ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE baseline_drafts ADD CONSTRAINT baseline_drafts_run_fk ' +
      'FOREIGN KEY (run_id, tenant_id) REFERENCES baseline_runs (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_drafts ADD CONSTRAINT baseline_drafts_status_chk
       CHECK (status IN (${DRAFT_STATUSES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_drafts ADD CONSTRAINT baseline_drafts_brand_chk
       CHECK (brand IN (${DEVICE_BRANDS}))`,
  );
  await knex.schema.raw(
    "ALTER TABLE baseline_drafts ADD CONSTRAINT baseline_drafts_sha_chk " +
      "CHECK (body_sha256 ~ '^[0-9a-f]{64}$')",
  );
  await knex.schema.raw(
    `ALTER TABLE baseline_drafts ADD CONSTRAINT baseline_drafts_counts_chk CHECK (
       line_count >= 0 AND variable_count >= 0 AND variable_count <= line_count
       AND coverage_mean BETWEEN 0 AND 1)`,
  );
  // Decision 7: 'promoted' is not a flag you can set on its own — it comes with
  // the draft revision it produced, or it does not come at all.
  await knex.schema.raw(
    "ALTER TABLE baseline_drafts ADD CONSTRAINT baseline_drafts_promotion_chk CHECK (" +
      "(status = 'promoted' AND template_revision_id IS NOT NULL AND promoted_at IS NOT NULL) OR " +
      "(status <> 'promoted' AND template_revision_id IS NULL AND promoted_at IS NULL))",
  );
  // One draft per proposed profile.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX baseline_drafts_cluster_uq ON baseline_drafts (tenant_id, cluster_id)',
  );
  await knex.schema.raw(
    'CREATE INDEX baseline_drafts_run_idx ON baseline_drafts (tenant_id, run_id, status)',
  );

  // ==========================================================================
  // 9. Documentation that travels with the schema.
  // ==========================================================================

  await knex.schema.raw(
    "COMMENT ON TABLE baseline_slots IS $$Cross-site alignment table (M12/K8). " +
      "One row per (scope, slot). role='variable' IS the variable detection: the " +
      "members disagree at the same structural place. NO SECRET-BEARING SLOT MAY " +
      "EXIST HERE — enforced twice, in shared/src/baseline.ts and by " +
      "baseline_slots_slot_secret_chk.$$",
  );
  await knex.schema.raw(
    "COMMENT ON TABLE baseline_exceptions IS $$Signed-for client specificities. " +
      "`reason` is NOT NULL and non-blank on purpose: an undocumented exception is " +
      "a suppression, and a suppression is how a real difference stops being " +
      "visible. Outlives the run that revealed it.$$",
  );
  await knex.schema.raw(
    "COMMENT ON COLUMN baseline_conformance.score_adjusted IS $$(covered + excused) " +
      "/ total. ALWAYS shown next to score_raw: a single number invites the reader " +
      "to assume the flattering one.$$",
  );
  await knex.schema.raw(
    "COMMENT ON COLUMN baseline_drafts.body IS $$Mined draft in the baseline FACT " +
      "DIALECT, not brand syntax. Must be rewritten before publication; the header " +
      "of the body says so. M12 owns no brand emitter — that is the M11 compiler.$$",
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('baseline_drafts');
  await knex.schema.dropTableIfExists('baseline_conformance');
  await knex.schema.dropTableIfExists('baseline_deviations');
  await knex.schema.dropTableIfExists('baseline_exceptions');
  await knex.schema.dropTableIfExists('baseline_slots');
  await knex.schema.dropTableIfExists('baseline_cluster_members');
  await knex.schema.dropTableIfExists('baseline_clusters');
  await knex.schema.dropTableIfExists('baseline_runs');

  // Decision 2's constraint is ours to remove — but only if nothing else has
  // started depending on it in the meantime. A dependent foreign key makes the
  // DROP fail, and it SHOULD fail loudly rather than take a shared uniqueness
  // guarantee away from a table that is now using it.
  await knex.schema.raw(
    'ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_id_tenant_uq',
  );
}
