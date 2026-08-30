import type { Knex } from 'knex';

/**
 * 007_config.ts — M4 part 1: the NCM store.
 *
 * Implements section 3.4 of ARCHITECTURE.md, section 6.1 of
 * `docs/M4-NCM-contrat.md` and section 5 of
 * `docs/M4-normalisation-routeros.md`. The TypeScript contract these tables
 * carry lives in `shared/src/ncm/`.
 *
 * ┌─ FIVE DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ───────────────────┐
 * │                                                                           │
 * │ 1. `UNIQUE(device_id, ncm_hash)` IS the deduplication. A router nobody    │
 * │    touched bumps `last_seen_at` and inserts nothing. That only works      │
 * │    because `ncm_hash` is a hash of CONFIGURATION and of nothing else:     │
 * │    `capturedAt`, `coverage[*].recordCount`, `device.osVersion` and        │
 * │    `extensions` are stripped before hashing (`shared/src/ncm/canonical`). │
 * │    Put one counter, one uptime or one firmware string inside that scope   │
 * │    and this table becomes a row generator that grows forever while the    │
 * │    drift screen reports a change every five minutes.                      │
 * │                                                                           │
 * │ 2. The `ncm_*` tables are a CACHE, not the truth. `config_snapshots.ncm`  │
 * │    is the document; `raw_gz` is the archive of reference. Both are        │
 * │    sufficient to rebuild every flattened row, which is why adding a       │
 * │    resource kind is "a new table plus a resumable backfill"               │
 * │    (`ncm_backfill_state`) and never a blocking UPDATE over 200 000 rows.  │
 * │                                                                           │
 * │ 3. `ordinal` is STORED, never recomputed. Section 3.4 of the NCM study    │
 * │    assigns ordinals by pairing with the PREVIOUS snapshot, so that        │
 * │    inserting a rule whose predicate already exists costs one `extra`      │
 * │    instead of cascading false `changed` down the whole collision class.   │
 * │    An ordinal is therefore not a function of the current document alone   │
 * │    and cannot be derived at read time.                                    │
 * │                                                                           │
 * │ 4. `rationale` and `false_negative` are NOT NULL on `normalization_rules`.│
 * │    A rule nobody wrote the false negative of is a rule that can silently  │
 * │    hide a real change — which is the one failure mode this whole          │
 * │    subsystem exists to prevent. It is a database constraint and not a     │
 * │    convention because a convention is what gets skipped at 2 a.m.         │
 * │                                                                           │
 * │ 5. NO SECRET LANDS HERE. `/export show-sensitive=no` is hard-wired (R10), │
 * │    the NCM stores HMAC fingerprints instead of secrets, and `raw_gz` is   │
 * │    the redacted export. `drift_findings.intent_value` / `.actual_value`   │
 * │    carry the same redacted material. If a secret ever reaches these       │
 * │    columns, forbidding `show-sensitive` upstream bought nothing.          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ENUMS AS TEXT + CHECK, not as PostgreSQL ENUM types. `docs/M4-normalisation-
 * routeros.md` §5.1 sketches `CREATE TYPE normalization_kind AS ENUM (…)`;
 * migrations 002 and 005 established text + CHECK for every other vocabulary in
 * this schema, and that form is the one that survives contact with the product:
 * adding a value is one `ALTER TABLE … DROP/ADD CONSTRAINT` inside a
 * transaction, whereas `ALTER TYPE … ADD VALUE` could not run inside a
 * transaction at all before PG 12 and still cannot be reverted. The vocabulary
 * is identical; only its enforcement differs.
 */

// Inlined as literals rather than imported from @obliwan/shared, exactly as 002
// and 005 do: a migration must keep describing the schema as it was on the day
// it ran, whatever the shared package does later.
const SNAPSHOT_SOURCES = "'routeros_api','ssh','rest','cwmp','pre_change','import'";
const TRANSPORTS = "'routeros_api','ssh','rest','cwmp','snmp'";
const KEY_QUALITIES = "'strong','derived','weak'";
const COVERAGE_STATES = "'complete','partial','unsupported','failed'";
const ORDER_ANALYSIS = "'full','partial','skipped'";
const NCM_RESOURCE_KINDS =
  "'interface','vlan','route','firewallRule','natRule'," +
  "'dhcpScope','ipsecPeer','localUser','service','qosRule'";

const NORMALIZATION_SCOPES = "'global','brand','group','device'";
const NORMALIZATION_KINDS =
  "'strip_line','strip_section','canonicalize','ignore_prop','ignore_entry'," +
  "'default_fill','sort_set','map_path','rewrite_value','mask_secret'," +
  "'severity_override','suppress_finding'";

const DRIFT_STATUSES = "'in_sync','drifted','error','unreachable'";
const DRIFT_CAUSES =
  "'scheduled','manual','post_change','renormalization','model_upgrade','takeover'";
const DRIFT_SCOPES = "'managed_only','full'";
const FINDING_KINDS = "'missing','extra','changed','moved'";
const SEVERITIES = "'info','low','medium','high','critical'";
const MATCH_METHODS = "'marker','natural','matchHash','fuzzy','none'";
const SUPPRESSION_REASONS =
  "'coverage_incomplete','version_skew','order_partial','weak_keys'";

/**
 * The ten flattened tables, and which of the four additional columns of §6.1
 * each one carries.
 *
 * `match_hash` and `ordinal` exist ONLY on the ordered rule kinds: an interface
 * has no predicate and no collision class, so the columns would be permanently
 * NULL and would cost an index nobody can use. `key_quality` and `payload_hash`
 * are on every table — the first because finding severity depends on it (a
 * finding on a weak TR-069 key is capped at `info`), the second because it is
 * what lets the indexer detect a `changed` in SQL without deserialising jsonb.
 */
const FLAT_TABLES: readonly {
  table: string;
  kind: string;
  /** match_hash + ordinal, and the B-tree that makes K5/K8 cross-device and
   *  cross-brand rule comparison a join instead of a jsonb scan. */
  ruleLike: boolean;
  /** GIN jsonb_path_ops on `props`. Only where the containment query is the hot
   *  path — ten GIN indexes would tax every snapshot write to accelerate
   *  queries over tables holding a dozen rows per device. */
  ginProps: boolean;
}[] = [
  { table: 'ncm_interfaces', kind: 'interface', ruleLike: false, ginProps: false },
  { table: 'ncm_vlans', kind: 'vlan', ruleLike: false, ginProps: false },
  { table: 'ncm_routes', kind: 'route', ruleLike: false, ginProps: false },
  { table: 'ncm_firewall_rules', kind: 'firewallRule', ruleLike: true, ginProps: true },
  { table: 'ncm_nat_rules', kind: 'natRule', ruleLike: true, ginProps: true },
  { table: 'ncm_dhcp_scopes', kind: 'dhcpScope', ruleLike: false, ginProps: false },
  { table: 'ncm_ipsec_peers', kind: 'ipsecPeer', ruleLike: false, ginProps: false },
  { table: 'ncm_local_users', kind: 'localUser', ruleLike: false, ginProps: false },
  { table: 'ncm_services', kind: 'service', ruleLike: false, ginProps: false },
  { table: 'ncm_qos_rules', kind: 'qosRule', ruleLike: true, ginProps: true },
];

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // config_snapshots — the document, and the archive it was derived from.
  // ==========================================================================

  await knex.schema.createTable('config_snapshots', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    t.string('source', 24).notNullable();

    // ── the archive of reference ────────────────────────────────────────────
    // gzip of the REDACTED export (`/export show-sensitive=no`, hard-wired —
    // R10). It stays the fallback for everything the NCM does not model: a
    // future parser can re-derive a richer document from it as a background
    // job, which is the real escape hatch behind decision N5.
    t.binary('raw_gz').nullable();
    // sha256 of the raw text BEFORE gzip. gzip is not deterministic across
    // library versions and compression levels, so hashing the compressed bytes
    // would make an identical export look different after a Node upgrade.
    t.string('raw_sha256', 64).nullable();
    t.integer('raw_bytes').nullable();

    // ── the document ────────────────────────────────────────────────────────
    t.jsonb('ncm').notNullable();
    t.string('ncm_hash', 64).notNullable();
    t.integer('ncm_version').notNullable();
    // Denormalised out of the document so that "which snapshots need
    // re-normalising / re-keying" is an indexed query and not a full jsonb
    // scan. Both are also INSIDE `ncm_hash`, on purpose (§8.5).
    t.integer('sem_key_generation').notNullable().defaultTo(1);
    t.string('normalization_epoch', 16).notNullable();
    t.string('order_analysis', 8).notNullable().defaultTo('full');

    // Excluded from `ncm_hash` and stored here instead: a firmware upgrade must
    // be visible without creating a snapshot (§8.5).
    t.string('os_version', 32).nullable();
    t.string('model', 64).nullable();

    // Number of `unmodeled[]` sections that can influence forwarding. Kept as a
    // column because K2 reads it on every plan and the UI shows it on every
    // snapshot; going through the jsonb for a number this hot is wasteful.
    t.integer('unmodeled_forwarding_count').notNullable().defaultTo(0);

    t.timestamp('captured_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    // Bumped instead of inserting a duplicate row. "This config has been true
    // since captured_at and was last confirmed at last_seen_at" is the whole
    // value of the deduplication.
    t.timestamp('last_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.integer('seen_count').notNullable().defaultTo(1);

    t.timestamps(true, true);

    // THE deduplication constraint (ARCHITECTURE.md §3.4).
    t.unique(['device_id', 'ncm_hash']);
    t.index(['device_id', 'captured_at'], 'config_snapshots_device_time_idx');
    t.index(['device_id', 'ncm_version'], 'config_snapshots_device_version_idx');
  });

  await knex.schema.raw(
    'ALTER TABLE config_snapshots ADD CONSTRAINT config_snapshots_source_chk ' +
      `CHECK (source IN (${SNAPSHOT_SOURCES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE config_snapshots ADD CONSTRAINT config_snapshots_order_analysis_chk ' +
      `CHECK (order_analysis IN (${ORDER_ANALYSIS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE config_snapshots ADD CONSTRAINT config_snapshots_hash_fmt_chk ' +
      "CHECK (ncm_hash ~ '^[0-9a-f]{64}$')",
  );
  await knex.schema.raw(
    'ALTER TABLE config_snapshots ADD CONSTRAINT config_snapshots_epoch_fmt_chk ' +
      "CHECK (normalization_epoch ~ '^[0-9a-f]{16}$')",
  );
  await knex.schema.raw(
    'ALTER TABLE config_snapshots ADD CONSTRAINT config_snapshots_version_chk ' +
      'CHECK (ncm_version >= 1 AND sem_key_generation >= 1)',
  );
  // A `last_seen_at` before `captured_at` means the dedup path wrote the wrong
  // row; catching it here is cheaper than explaining a negative age in the UI.
  await knex.schema.raw(
    'ALTER TABLE config_snapshots ADD CONSTRAINT config_snapshots_seen_order_chk ' +
      'CHECK (last_seen_at >= captured_at)',
  );

  // ── THE index Fleet Query (K5) is built on ──────────────────────────────
  //
  // `jsonb_path_ops` rather than the default `jsonb_ops`: it indexes hashes of
  // whole paths instead of every individual key and value, which makes it
  // roughly a third of the size and materially faster — at the cost of
  // supporting ONLY the containment operators (`@>`). That restriction is not a
  // sacrifice here, it is the design: §6.2 makes containment the single query
  // shape of the DSL, and §2.1 of the NCM study encodes every selector as a
  // TAGGED STRING rather than a nested object precisely because containment on
  // arrays of scalars is the one pattern this index accelerates.
  //
  //   ncm @> '{"resources":{"firewallRules":[{"chain":"input",
  //             "match":{"srcAddress":["any"],"dstAddress":["any"]}}]}}'
  //
  // Existence (`?`), key iteration and `jsonpath` predicates are NOT covered.
  // A DSL feature that needs them needs its own index, deliberately added.
  await knex.schema.raw(
    'CREATE INDEX config_snapshots_ncm_gin ON config_snapshots USING gin (ncm jsonb_path_ops)',
  );

  // ==========================================================================
  // The flattened NCM — a rebuildable cache, regenerated per snapshot.
  // ==========================================================================

  for (const spec of FLAT_TABLES) {
    await knex.schema.createTable(spec.table, (t) => {
      t.bigIncrements('id').primary();

      // Denormalised from the snapshot so that every K5 query filters on the
      // device without a join. The FK is on `snapshot_id`; this one is a plain
      // column with an index, and the pair is kept consistent by the indexer,
      // which writes both in the same transaction that regenerates the rows.
      t.integer('device_id').notNullable()
        .references('id').inTable('devices').onDelete('CASCADE');
      t.bigInteger('snapshot_id').notNullable()
        .references('id').inTable('config_snapshots').onDelete('CASCADE');

      t.string('sem_key', 180).notNullable();

      // Position within its order group (chain), or NULL for an unordered kind.
      // AUDITABLE, never diffed as a value: N2 says position is not a field.
      // An inert reordering updates this column and produces no finding.
      t.integer('position').nullable();
      // The chain / order group the position is relative to. A rule in `input`
      // cannot precede a rule in `forward` in any meaningful sense.
      t.string('order_group', 80).nullable();

      t.jsonb('props').notNullable();

      // comment ~ '^obliwan:' — phase 1 of the pairing algorithm, and the
      // `scope: 'managed_only'` filter that keeps a taken-over fleet quiet.
      t.boolean('is_managed').notNullable().defaultTo(false);
      t.string('managed_slug', 48).nullable();

      // §6.1, additional column 3/4: the severity of a finding depends on it.
      t.string('key_quality', 8).notNullable().defaultTo('derived');
      // §6.1, additional column 4/4: detect a `changed` in SQL without
      // deserialising the jsonb.
      t.string('payload_hash', 16).notNullable();

      if (spec.ruleLike) {
        // §6.1, additional columns 1/4 and 2/4.
        t.string('match_hash', 16).nullable();
        t.smallint('ordinal').nullable();
      }

      t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

      // Two records sharing a sem_key inside one snapshot is a PARSER BUG: the
      // pairing algorithm would then match one of them arbitrarily and the
      // resulting finding would name the wrong rule. Failing the indexing
      // transaction is loud and cheap; a mispaired finding six weeks later is
      // neither. This is the constraint that keeps `ordinalCollisionRate`
      // honest instead of silently absorbing collisions.
      t.unique(['snapshot_id', 'sem_key']);
      t.index(['device_id', 'sem_key'], `${spec.table}_device_key_idx`);
      t.index(['snapshot_id', 'position'], `${spec.table}_snapshot_pos_idx`);
    });

    await knex.schema.raw(
      `ALTER TABLE ${spec.table} ADD CONSTRAINT ${spec.table}_key_quality_chk ` +
        `CHECK (key_quality IN (${KEY_QUALITIES}))`,
    );
    await knex.schema.raw(
      `ALTER TABLE ${spec.table} ADD CONSTRAINT ${spec.table}_payload_hash_chk ` +
        "CHECK (payload_hash ~ '^[0-9a-f]{16}$')",
    );

    // Partial index: on a taken-over fleet the managed rows are a small
    // minority, and `managed_only` is the DEFAULT diff scope, so this is the
    // hot filter. A partial index keeps it small enough to stay cached.
    await knex.schema.raw(
      `CREATE INDEX ${spec.table}_managed_idx ON ${spec.table} (device_id, managed_slug) ` +
        'WHERE is_managed',
    );

    if (spec.ruleLike) {
      await knex.schema.raw(
        `ALTER TABLE ${spec.table} ADD CONSTRAINT ${spec.table}_match_hash_chk ` +
          "CHECK (match_hash IS NULL OR match_hash ~ '^[0-9a-f]{16}$')",
      );
      // B-tree on the predicate hash: this is what turns "which devices, of any
      // brand, carry this rule" into a join. Cross-brand comparability is the
      // reason `matchHash` is computed from a NORMALISED match and never from
      // brand text (§3.3).
      await knex.schema.raw(
        `CREATE INDEX ${spec.table}_match_hash_idx ON ${spec.table} (match_hash) ` +
          'WHERE match_hash IS NOT NULL',
      );
    }

    if (spec.ginProps) {
      await knex.schema.raw(
        `CREATE INDEX ${spec.table}_props_gin ON ${spec.table} USING gin (props jsonb_path_ops)`,
      );
    }
  }

  // ==========================================================================
  // ncm_backfill_state — §8.3: adding a resource is a job, not a migration.
  // ==========================================================================
  //
  // At 200 000 snapshots an UPDATE in one transaction saturates the WAL and
  // stops the collection. The backfill is a resumable, rate-limited pg-boss job
  // whose cursor lives here. Until it completes, K5 must ANNOUNCE the partial
  // coverage ("41 % of snapshots indexed for this resource") rather than return
  // a confident wrong answer.
  await knex.schema.createTable('ncm_backfill_state', (t) => {
    t.string('resource_kind', 24).primary();
    t.bigInteger('last_snapshot_id').notNullable().defaultTo(0);
    t.bigInteger('total_snapshots').notNullable().defaultTo(0);
    t.bigInteger('done_snapshots').notNullable().defaultTo(0);
    t.boolean('done').notNullable().defaultTo(false);
    t.text('last_error').nullable();
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  await knex.schema.raw(
    'ALTER TABLE ncm_backfill_state ADD CONSTRAINT ncm_backfill_kind_chk ' +
      `CHECK (resource_kind IN (${NCM_RESOURCE_KINDS}))`,
  );

  // ==========================================================================
  // normalization_rules — editable in the UI, and accountable.
  // ==========================================================================

  await knex.schema.createTable('normalization_rules', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable().defaultTo(1)
      .references('id').inTable('tenants').onDelete('CASCADE');

    // ── scope ──────────────────────────────────────────────────────────────
    t.string('scope', 8).notNullable().defaultTo('global');
    t.integer('scope_id').nullable();          // device_groups.id or devices.id
    t.string('brand', 24).nullable();          // NULL = every brand
    t.string('family', 32).nullable();         // NULL = every family
    // R11: a "RouterOS 7.14 default" rule must never apply to a RouterOS 6 box.
    t.string('os_min', 32).nullable();
    t.string('os_max', 32).nullable();

    // ── identity and accountability ────────────────────────────────────────
    t.string('name', 128).notNullable();
    t.text('description').notNullable();
    // WHY this is not a real change.
    t.text('rationale').notNullable();
    // WHAT IT CAN HIDE. Decision 4 of this file's header: NOT NULL, and the
    // service additionally refuses an empty string.
    t.text('false_negative').notNullable();

    // ── body ───────────────────────────────────────────────────────────────
    // The layer makes doctrine D3 executable: the engine cannot apply a
    // semantic rule to raw text, and the UI can demand a review for layer 1.
    t.smallint('layer').notNullable();
    t.string('kind', 24).notNullable();
    t.text('section_path').nullable();         // '/ip/firewall/filter'
    // Default TRUE on purpose (ARCHITECTURE.md §3.4): sorting a firewall chain
    // destroys its semantics. Flipping a section to false is a high-risk
    // gesture and is audited.
    t.boolean('section_ordered').notNullable().defaultTo(true);
    t.text('prop').nullable();
    t.text('pattern').nullable();              // anchored POSIX regex (lint §6.4)
    t.text('replacement').nullable();
    t.jsonb('predicate').nullable();           // {"prop":"dynamic","eq":true}
    t.jsonb('value').nullable();               // default_fill fallback value
    t.text('target_path').nullable();          // map_path destination
    t.string('severity', 8).nullable();        // severity_override

    // ── ordering and lifecycle ─────────────────────────────────────────────
    t.integer('apply_order').notNullable();
    t.boolean('enabled').notNullable().defaultTo(true);
    t.boolean('is_builtin').notNullable().defaultTo(false);
    // Seeded rules are reconciled by key at every migration WITHOUT clobbering
    // the user's `enabled` / `severity` edits.
    t.text('builtin_key').nullable().unique();
    // No test, no activation (§6.4). Enforced by the service, which needs both
    // a `must_suppress` and a `must_not_suppress` case.
    t.boolean('requires_test').notNullable().defaultTo(true);

    // ── observability, written by the engine and never typed in ────────────
    // Without these counters nobody can answer "which rule is hiding what",
    // and the whole test strategy of §6 becomes inapplicable.
    t.bigInteger('hit_count').notNullable().defaultTo(0);
    t.bigInteger('suppressed_count').notNullable().defaultTo(0);
    t.timestamp('last_hit_at', { useTz: true }).nullable();

    t.integer('created_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE normalization_rules ADD CONSTRAINT nr_scope_chk ' +
      `CHECK (scope IN (${NORMALIZATION_SCOPES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE normalization_rules ADD CONSTRAINT nr_kind_chk ' +
      `CHECK (kind IN (${NORMALIZATION_KINDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE normalization_rules ADD CONSTRAINT nr_layer_chk ' +
      'CHECK (layer BETWEEN 1 AND 4)',
  );
  await knex.schema.raw(
    'ALTER TABLE normalization_rules ADD CONSTRAINT nr_severity_chk ' +
      `CHECK (severity IS NULL OR severity IN (${SEVERITIES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE normalization_rules ADD CONSTRAINT nr_scope_id_coherent CHECK (' +
      `  (scope IN ('global','brand') AND scope_id IS NULL)` +
      `  OR (scope IN ('group','device') AND scope_id IS NOT NULL))`,
  );
  // A layer-1 rule with no pattern would strip nothing or everything.
  await knex.schema.raw(
    'ALTER TABLE normalization_rules ADD CONSTRAINT nr_l1_needs_pattern ' +
      'CHECK (layer <> 1 OR pattern IS NOT NULL)',
  );
  await knex.schema.raw(
    'ALTER TABLE normalization_rules ADD CONSTRAINT nr_rewrite_needs_prop ' +
      `CHECK (kind <> 'rewrite_value' OR (prop IS NOT NULL AND pattern IS NOT NULL))`,
  );
  // Decision 4: an unexplained rule is an undebuggable rule.
  await knex.schema.raw(
    'ALTER TABLE normalization_rules ADD CONSTRAINT nr_accountable_chk ' +
      "CHECK (btrim(rationale) <> '' AND btrim(false_negative) <> '')",
  );
  // The application order is total and unambiguous. `coalesce(scope_id,0)`
  // keeps the uniqueness meaningful for the two scopes that have no scope_id.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX nr_order_uniq ON normalization_rules ' +
      '(tenant_id, scope, coalesce(scope_id, 0), apply_order)',
  );
  await knex.schema.raw(
    'CREATE INDEX nr_lookup ON normalization_rules (tenant_id, enabled, layer, apply_order)',
  );
  await knex.schema.raw(
    'CREATE INDEX nr_section ON normalization_rules (section_path) WHERE section_path IS NOT NULL',
  );

  // ==========================================================================
  // normalization_rule_tests — every rule carries its own proof.
  // ==========================================================================
  //
  // Invariant enforced by the service: a rule may not be `enabled` without at
  // least one `must_suppress` AND one `must_not_suppress` test. That is doctrine
  // D1 written into the database — prove what the rule removes, and prove what
  // it lets through.
  await knex.schema.createTable('normalization_rule_tests', (t) => {
    t.bigIncrements('id').primary();
    t.bigInteger('rule_id').notNullable()
      .references('id').inTable('normalization_rules').onDelete('CASCADE');
    t.string('kind', 20).notNullable();
    t.text('fixture_key').notNullable();
    t.text('input_before').notNullable();
    t.text('input_after').notNullable();
    t.jsonb('expect').notNullable();
    t.timestamp('last_run_at', { useTz: true }).nullable();
    t.string('last_result', 8).nullable();
    t.timestamps(true, true);
    t.index('rule_id');
  });
  await knex.schema.raw(
    'ALTER TABLE normalization_rule_tests ADD CONSTRAINT nrt_kind_chk ' +
      `CHECK (kind IN ('must_suppress','must_not_suppress'))`,
  );
  await knex.schema.raw(
    'ALTER TABLE normalization_rule_tests ADD CONSTRAINT nrt_result_chk ' +
      `CHECK (last_result IS NULL OR last_result IN ('pass','fail'))`,
  );

  // ==========================================================================
  // ncm_section_catalog — doctrine, not free-form data.
  // ==========================================================================
  //
  // Deliberately NOT a row of `normalization_rules`: an operator must not be
  // able to declare `/ip/firewall/filter` unordered by accident. Seeded by
  // migration, editable only with DRIFT_MANAGE, and every edit written to
  // `audit_log`.
  await knex.schema.createTable('ncm_section_catalog', (t) => {
    t.text('section_path').notNullable();
    // NULL = every family of the brand. Part of the key so ROS6 and ROS7 can
    // disagree about the same path (risk R11).
    t.string('family', 32).notNullable().defaultTo('*');
    t.boolean('ordered').notNullable();
    t.text('order_group_prop').nullable();      // 'chain'
    t.specificType('sem_key_props', 'text[]').notNullable();
    t.specificType('sem_key_fallback', 'text[]').nullable();
    t.integer('sem_key_version').notNullable().defaultTo(1);
    t.specificType('secret_props', 'text[]').notNullable().defaultTo('{}');
    t.specificType('state_props', 'text[]').notNullable().defaultTo('{}');
    t.specificType('counter_props', 'text[]').notNullable().defaultTo('{}');
    // Hard bound on `default_fill`: filling one of these would be a false
    // negative by construction.
    t.specificType('no_default_fill_props', 'text[]').notNullable().defaultTo('{}');
    t.string('default_severity', 8).notNullable().defaultTo('medium');
    t.text('ros6_path').nullable();
    t.text('ros7_path').nullable();
    t.string('ncm_resource_kind', 24).nullable();
    t.timestamps(true, true);
    t.primary(['section_path', 'family']);
  });
  await knex.schema.raw(
    'ALTER TABLE ncm_section_catalog ADD CONSTRAINT nsc_severity_chk ' +
      `CHECK (default_severity IN (${SEVERITIES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE ncm_section_catalog ADD CONSTRAINT nsc_kind_chk ' +
      `CHECK (ncm_resource_kind IS NULL OR ncm_resource_kind IN (${NCM_RESOURCE_KINDS}))`,
  );

  // ==========================================================================
  // routeros_defaults — the LEARNED oracle (N09), never an extrapolated one.
  // ==========================================================================
  //
  // `/export` omits values equal to the default, the API returns them. Filling
  // the gap needs to know the default, and the default depends on the exact
  // firmware — hence `os_version` in the key and never a semver range.
  //
  // `conflicting = true` DISABLES the fill for that prop: if two devices on the
  // same version disagree about what the default is, then it is not a default
  // (it depends on the model or the hardware), and filling it would create a
  // false negative.
  await knex.schema.createTable('routeros_defaults', (t) => {
    t.string('family', 32).notNullable();
    t.string('os_version', 32).notNullable();
    t.text('section_path').notNullable();
    t.text('prop').notNullable();
    t.jsonb('default_value').notNullable();
    t.string('learned_from', 20).notNullable();
    t.timestamp('learned_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.integer('device_count').notNullable().defaultTo(1);
    t.boolean('conflicting').notNullable().defaultTo(false);
    t.primary(['family', 'os_version', 'section_path', 'prop']);
  });
  await knex.schema.raw(
    'ALTER TABLE routeros_defaults ADD CONSTRAINT rd_learned_from_chk ' +
      `CHECK (learned_from IN ('export_verbose','api_print_detail','seed','manual'))`,
  );

  // ==========================================================================
  // drift_runs / drift_findings
  // ==========================================================================

  await knex.schema.createTable('drift_runs', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');
    // `config_renders` arrives with the template migration. Deliberately a bare
    // column with no FK for now: adding the constraint later is one ALTER,
    // whereas forward-declaring the table here would put the template schema in
    // the wrong migration.
    t.bigInteger('render_id').nullable();
    t.bigInteger('snapshot_id').nullable()
      .references('id').inTable('config_snapshots').onDelete('SET NULL');

    // `error` != `unreachable`, and the distinction is load-bearing: a box we
    // could not reach is an infrastructure event, a run that blew up is our bug.
    // Collapsing them hides our own failures behind the customer's WAN.
    t.string('status', 12).notNullable();
    t.text('error_reason').nullable();

    // K6 must NEVER attribute a run caused by our own deployment to a human.
    // `renormalization` and `model_upgrade` are excluded from attribution by
    // construction (§6.5) — which is why the cause is on the run and not
    // inferred afterwards.
    t.string('cause', 20).notNullable().defaultTo('scheduled');
    t.string('scope', 16).notNullable().defaultTo('managed_only');

    t.integer('findings_count').notNullable().defaultTo(0);
    t.integer('ignored_count').notNullable().defaultTo(0);
    // Reorderings with no effect on forwarding: counted, shown as one line,
    // never emitted as findings (§4.4). This column is the instrumentation of
    // that anti-noise lever — without per-lever counters we cannot know which
    // one to fix if "< 3 noise findings per device" is missed.
    t.integer('inert_move_count').notNullable().defaultTo(0);
    // Objects observed outside any claimed template section under
    // `managed_only`. Keeps the Q2 blind spot VISIBLE instead of silent.
    t.integer('out_of_scope_count').notNullable().defaultTo(0);
    t.string('max_severity', 8).nullable();

    // What the run knew about itself, for a post-mortem months later.
    t.integer('ncm_version').notNullable().defaultTo(1);
    t.string('normalization_epoch', 16).nullable();
    t.string('order_analysis', 8).notNullable().defaultTo('full');
    // Resource kinds the engine declined to evaluate, and why — one row of
    // `[{"resource":"route","reason":"coverage_incomplete"}]`. THE evidence
    // that N3 fired rather than the diff silently finding nothing.
    t.jsonb('suppressed').notNullable().defaultTo('[]');

    t.timestamp('started_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('finished_at', { useTz: true }).nullable();

    t.index(['device_id', 'started_at'], 'drift_runs_device_time_idx');
    t.index(['status', 'started_at'], 'drift_runs_status_time_idx');
  });

  await knex.schema.raw(
    'ALTER TABLE drift_runs ADD CONSTRAINT drift_runs_status_chk ' +
      `CHECK (status IN (${DRIFT_STATUSES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_runs ADD CONSTRAINT drift_runs_cause_chk ' +
      `CHECK (cause IN (${DRIFT_CAUSES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_runs ADD CONSTRAINT drift_runs_scope_chk ' +
      `CHECK (scope IN (${DRIFT_SCOPES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_runs ADD CONSTRAINT drift_runs_severity_chk ' +
      `CHECK (max_severity IS NULL OR max_severity IN (${SEVERITIES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_runs ADD CONSTRAINT drift_runs_order_analysis_chk ' +
      `CHECK (order_analysis IN (${ORDER_ANALYSIS}))`,
  );

  await knex.schema.createTable('drift_findings', (t) => {
    t.bigIncrements('id').primary();
    t.bigInteger('run_id').notNullable()
      .references('id').inTable('drift_runs').onDelete('CASCADE');

    // '<kind>/<semKey>' or '<kind>/<semKey>/<field>'. INDEX-FREE by
    // construction: an array index in this path would invalidate every ignore
    // rule a customer wrote the next time a rule is inserted above.
    t.text('path').notNullable();
    t.string('sem_key', 180).notNullable();
    t.string('resource', 24).notNullable();
    t.string('kind', 8).notNullable();
    t.string('severity', 8).notNullable();

    // Persisted, and not for decoration: K6 must not attribute a fuzzy pairing
    // with the confidence of a marker anchor, and K2 must not prove anything
    // from a fuzzy pair (risk N-R6).
    t.string('match_method', 12).notNullable().defaultTo('none');
    t.decimal('match_confidence', 4, 3).notNullable().defaultTo(1);
    t.boolean('predicate_changed').notNullable().defaultTo(false);

    // ONE row per resource carrying N field diffs — never one row per field.
    // That single choice divides the finding count by 3 to 5 on wide resources.
    t.jsonb('field_diffs').notNullable().defaultTo('[]');
    // `moved` only: the decisive rules this one crossed. Empty means the move
    // was inert and the finding must not exist at all.
    t.jsonb('crossed').notNullable().defaultTo('[]');

    // REDACTED values. R10: a secret must never reach a diffable store.
    t.jsonb('intent_value').nullable();
    t.jsonb('actual_value').nullable();
    t.text('text_patch').nullable();

    // An ignored finding is KEPT, never deleted: "we saw it and chose to ignore
    // it" and "we never saw it" must stay distinguishable, and the rule that
    // silenced it must be nameable months later.
    t.boolean('ignored').notNullable().defaultTo(false);
    t.bigInteger('ignored_by_rule').nullable()
      .references('id').inTable('normalization_rules').onDelete('SET NULL');
    // Survives a `semKeyGeneration` bump: §8.4 keeps the old key on the finding
    // for at least one retention cycle so an operator can still recognise it.
    t.string('legacy_sem_key', 180).nullable();

    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    t.index(['run_id', 'severity'], 'drift_findings_run_sev_idx');
    t.index('sem_key', 'drift_findings_sem_key_idx');
    t.index('ignored_by_rule', 'drift_findings_rule_idx');
  });

  await knex.schema.raw(
    'ALTER TABLE drift_findings ADD CONSTRAINT drift_findings_kind_chk ' +
      `CHECK (kind IN (${FINDING_KINDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_findings ADD CONSTRAINT drift_findings_resource_chk ' +
      `CHECK (resource IN (${NCM_RESOURCE_KINDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_findings ADD CONSTRAINT drift_findings_severity_chk ' +
      `CHECK (severity IN (${SEVERITIES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_findings ADD CONSTRAINT drift_findings_method_chk ' +
      `CHECK (match_method IN (${MATCH_METHODS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_findings ADD CONSTRAINT drift_findings_confidence_chk ' +
      'CHECK (match_confidence >= 0 AND match_confidence <= 1)',
  );
  // A `moved` with an empty `crossed` is an INERT move, and §4.4 forbids
  // emitting it: it belongs in `drift_runs.inert_move_count`. Enforced here
  // because it is the single largest source of reordering noise, and a future
  // refactor of the diff engine must not be able to reintroduce it quietly.
  await knex.schema.raw(
    'ALTER TABLE drift_findings ADD CONSTRAINT drift_findings_moved_needs_crossed ' +
      `CHECK (kind <> 'moved' OR jsonb_array_length(crossed) > 0)`,
  );
  // An unpaired finding cannot carry a pairing method, and a paired one cannot
  // claim `none`. This catches the engine bug where a `missing` is emitted with
  // a leftover match method from the previous iteration.
  await knex.schema.raw(
    'ALTER TABLE drift_findings ADD CONSTRAINT drift_findings_pairing_coherent CHECK (' +
      `  (kind IN ('missing','extra') AND match_method = 'none')` +
      `  OR (kind IN ('changed','moved') AND match_method <> 'none'))`,
  );

  // The vocabulary of `drift_runs.suppressed`, kept next to the table that uses
  // it so a reader does not have to open the shared package to know the four
  // legal reasons. Written with `$$` quoting because the value itself contains
  // the single quotes of the vocabulary literals.
  await knex.schema.raw(
    'COMMENT ON COLUMN drift_runs.suppressed IS $$' +
      `[{"resource": <ncm kind>, "reason": one of ${SUPPRESSION_REASONS}}]$$`,
  );
  await knex.schema.raw(
    `COMMENT ON COLUMN config_snapshots.raw_gz IS ` +
      `'gzip of the REDACTED export (show-sensitive=no, risk R10). Never a secret.'`,
  );
  await knex.schema.raw(
    `COMMENT ON TABLE ncm_firewall_rules IS ` +
      `'Rebuildable cache of config_snapshots.ncm. Truth is the jsonb + raw_gz.'`,
  );
  // Documented in the database because it is the one column whose meaning is
  // routinely misread as "the rule is at position N in the file".
  await knex.schema.raw(
    `COMMENT ON COLUMN ncm_firewall_rules.ordinal IS ` +
      `'Collision discriminator within (chain, match_hash), assigned by pairing with the previous snapshot. NOT a position.'`,
  );

  // Interface transport vocabulary, referenced by ncm props. Declared as a
  // comment rather than a constraint: `via` lives inside the jsonb and a CHECK
  // over jsonb would be evaluated on every row of every snapshot write.
  await knex.schema.raw(
    'COMMENT ON COLUMN config_snapshots.ncm IS $$' +
      `NcmDocument (shared/src/ncm). coverage[*].state in ${COVERAGE_STATES}; ` +
      `resource.via in ${TRANSPORTS}.$$`,
  );
}

export async function down(knex: Knex): Promise<void> {
  // Reverse dependency order: findings -> runs -> flattened tables ->
  // snapshots, then the rule tables (findings reference normalization_rules).
  await knex.schema.dropTableIfExists('drift_findings');
  await knex.schema.dropTableIfExists('drift_runs');

  for (const spec of [...FLAT_TABLES].reverse()) {
    await knex.schema.dropTableIfExists(spec.table);
  }

  await knex.schema.dropTableIfExists('ncm_backfill_state');
  await knex.schema.dropTableIfExists('config_snapshots');

  await knex.schema.dropTableIfExists('normalization_rule_tests');
  await knex.schema.dropTableIfExists('normalization_rules');
  await knex.schema.dropTableIfExists('ncm_section_catalog');
  await knex.schema.dropTableIfExists('routeros_defaults');
}
