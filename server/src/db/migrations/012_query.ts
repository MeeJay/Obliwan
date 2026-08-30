import type { Knex } from 'knex';

/**
 * 012_query.ts — M9: Fleet Query (K5).
 *
 * Implements the `saved_queries` / `policy_results` half of ARCHITECTURE.md
 * §3.7 and the M9 line of §5. The TypeScript contract these tables carry lives
 * in `shared/src/query.ts`; the DSL that fills `dsl` is parsed in
 * `server/src/services/query/dsl.ts`.
 *
 * NOTE ON §3.7: that section lists `audit_log` alongside these two tables. It
 * is NOT created here. The append-only audit is the other half of M8's
 * attribution work and belongs to whoever owns that milestone; creating a
 * second, thinner `audit_log` from the query milestone would be the fastest
 * possible way to end up with two of them.
 *
 * ┌─ FOUR DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ───────────────────┐
 * │                                                                           │
 * │ 1. `policy_results` HAS NO TENANT COLUMN, AND THAT IS DELIBERATE.         │
 * │    It hangs off `saved_queries` (which is tenant-scoped) AND off          │
 * │    `devices` (which is tenant-scoped), and a row whose two parents        │
 * │    disagreed would be a cross-tenant leak with a foreign key blessing it. │
 * │    Rather than store a third copy of the truth and hope, the trigger      │
 * │    `policy_results_same_tenant()` REFUSES the insert. Every read still    │
 * │    joins `devices` and filters on `tenant_id`: the trigger protects the   │
 * │    write path, the join protects the read path, and neither is a          │
 * │    substitute for the other.                                              │
 * │                                                                           │
 * │ 2. A POLICY QUERY MATCHES THE VIOLATORS (`passed = NOT matched`).         │
 * │    The inverse convention reads better in a sentence and is a trap: a     │
 * │    device with no snapshot matches nothing, and would be recorded as      │
 * │    FAILING every policy it was never evaluated against. Matching-is-      │
 * │    violating makes "no data" mean "no violation", which is the direction  │
 * │    that does not manufacture alarm — and `snapshot.missing` is itself a   │
 * │    queryable field, so "who has no data" is a policy you write on         │
 * │    purpose.                                                               │
 * │                                                                           │
 * │ 3. `UNIQUE (query_id, device_id, snapshot_id)` IS THE IDEMPOTENCE.        │
 * │    A policy is evaluated at every snapshot; re-evaluating the SAME        │
 * │    snapshot (a re-run, a retry, a backfill) must not grow the table. The  │
 * │    upsert bumps `evaluated_at` and rewrites `passed` — the same shape as  │
 * │    `config_snapshots.last_seen_at`, for the same reason.                  │
 * │    `snapshot_id` is NULLABLE (a device that has never been collected is   │
 * │    still part of the population), so the constraint is TWO partial unique │
 * │    indexes: `NULLS DISTINCT` is the default and would let one device      │
 * │    accumulate a new NULL-snapshot row on every single evaluation.         │
 * │                                                                           │
 * │ 4. THE `(device_id, last_seen_at DESC, id DESC)` INDEX IS PART OF THE     │
 * │    QUERY ENGINE, not an optimisation. "The device's CURRENT config" is    │
 * │    the row with the greatest `last_seen_at` — NOT `captured_at`: dedup on │
 * │    `UNIQUE(device_id, ncm_hash)` means a router that goes A -> B -> A     │
 * │    resurrects the original A row and bumps its `last_seen_at` while its   │
 * │    `captured_at` stays in the past. Ordering on `captured_at` would       │
 * │    report B as current forever, and every Fleet Query answer would be     │
 * │    quietly one configuration behind.                                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

/** `shared/src/ncm/diff.ts` — DIFF_SEVERITIES. Longest member: 'critical' (8). */
const SEVERITIES = "'info','low','medium','high','critical'";

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // The index the engine reads on every single query
  // ==========================================================================
  //
  // `config_snapshots_device_time_idx` is `(device_id, captured_at)` and cannot
  // serve this ordering (see decision 4 above). Adding the right one here,
  // rather than editing 007, keeps a shipped migration immutable.
  await knex.schema.raw(
    'CREATE INDEX config_snapshots_device_current_idx '
      + 'ON config_snapshots (device_id, last_seen_at DESC, id DESC)',
  );

  // ==========================================================================
  // saved_queries
  // ==========================================================================
  await knex.schema.createTable('saved_queries', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('name', 120).notNullable();
    t.text('description').nullable();

    // The DSL text, verbatim, as the user typed it. It is the SOURCE: the SQL
    // is derived and is never stored, because a stored statement outlives the
    // compiler that produced it and would keep running semantics nobody can
    // still read in the DSL.
    t.text('dsl').notNullable();

    // sha256 of the statement the CURRENT compiler produces for that DSL. Not a
    // cache and not a security control: it is a tripwire. When a compiler
    // change alters the SQL of a stored policy, the mismatch is recorded
    // (`compiled_at` moves) so "this policy started reporting differently in
    // March" has an answer other than a shrug.
    t.string('compiled_sql_hash', 64).notNullable();
    t.timestamp('compiled_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    t.boolean('is_policy').notNullable().defaultTo(false);
    // 16, not 8: 'critical' is exactly 8 characters and a column sized to its
    // longest CURRENT value is a `value too long` waiting for the next enum
    // member. The CHECK is what constrains the domain; the width is headroom.
    t.string('severity', 16).nullable();
    t.boolean('enabled').notNullable().defaultTo(true);

    // SET NULL, not CASCADE: deleting the analyst who wrote the policy must not
    // delete the policy the fleet is judged by.
    t.integer('created_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');

    // Observability of the feature's own promise ("< 200 ms on 300 devices").
    t.timestamp('last_run_at', { useTz: true }).nullable();
    t.integer('last_run_ms').nullable();
    t.integer('last_match_count').nullable();

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE saved_queries ADD CONSTRAINT saved_queries_severity_chk '
      + `CHECK (severity IS NULL OR severity IN (${SEVERITIES}))`,
  );
  // A policy with no severity cannot be ranked next to the drift findings it
  // sits beside on the fleet screen; a severity on a non-policy is a field
  // nothing reads. Both are quiet ways to ship a policy that never surfaces.
  await knex.schema.raw(
    'ALTER TABLE saved_queries ADD CONSTRAINT saved_queries_policy_severity_chk '
      + 'CHECK ((is_policy AND severity IS NOT NULL) OR (NOT is_policy AND severity IS NULL))',
  );
  await knex.schema.raw(
    'ALTER TABLE saved_queries ADD CONSTRAINT saved_queries_hash_fmt_chk '
      + "CHECK (compiled_sql_hash ~ '^[0-9a-f]{64}$')",
  );
  // Mirrors QUERY_LIMITS.maxQueryLength. The parser refuses longer input, so
  // this only ever fires on a row written around the API — an import, a psql
  // session — which is exactly when you want the database to have an opinion.
  await knex.schema.raw(
    'ALTER TABLE saved_queries ADD CONSTRAINT saved_queries_dsl_len_chk '
      + 'CHECK (length(dsl) BETWEEN 1 AND 4096)',
  );

  // Per TENANT, case-insensitively: two tenants both naming a query "SNMP v1"
  // is normal; one tenant owning "SNMP v1" and "snmp v1" is a support ticket.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX saved_queries_tenant_name_uq ON saved_queries (tenant_id, lower(name))',
  );
  // The hot read: "the enabled policies of this tenant", run after every
  // snapshot. Partial, because policies are a minority of saved queries.
  await knex.schema.raw(
    'CREATE INDEX saved_queries_policy_idx ON saved_queries (tenant_id, severity) '
      + 'WHERE is_policy AND enabled',
  );
  await knex.schema.raw(
    'CREATE INDEX saved_queries_tenant_idx ON saved_queries (tenant_id, name)',
  );

  // ==========================================================================
  // policy_results
  // ==========================================================================
  await knex.schema.createTable('policy_results', (t) => {
    t.bigIncrements('id').primary();

    t.integer('query_id').notNullable()
      .references('id').inTable('saved_queries').onDelete('CASCADE');
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');
    // Nullable: a device that has never been collected is still evaluated, and
    // recording "evaluated, no configuration" is the honest row. It is also the
    // reason the uniqueness below is two PARTIAL indexes.
    t.bigInteger('snapshot_id').nullable()
      .references('id').inTable('config_snapshots').onDelete('CASCADE');

    t.boolean('passed').notNullable();
    // Denormalised from `saved_queries.severity` AT EVALUATION TIME. Lowering a
    // policy's severity must not rewrite the history of what it reported.
    t.string('severity', 16).nullable();

    t.timestamp('evaluated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('first_failed_at', { useTz: true }).nullable();
  });

  await knex.schema.raw(
    'ALTER TABLE policy_results ADD CONSTRAINT policy_results_severity_chk '
      + `CHECK (severity IS NULL OR severity IN (${SEVERITIES}))`,
  );
  // `first_failed_at` only means something on a row that is failing.
  await knex.schema.raw(
    'ALTER TABLE policy_results ADD CONSTRAINT policy_results_first_failed_chk '
      + 'CHECK (passed OR first_failed_at IS NOT NULL)',
  );

  // ── the idempotence, in two partial indexes ───────────────────────────────
  //
  // `UNIQUE (query_id, device_id, snapshot_id)` alone is a NO-OP for the rows
  // where `snapshot_id IS NULL`, because NULLS DISTINCT is the Postgres default
  // and two NULLs never collide. Those are precisely the never-collected
  // devices — the ones re-evaluated on every single run — so the "no duplicate"
  // guarantee would hold everywhere except where it is needed most.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX policy_results_snapshot_uq ON policy_results '
      + '(query_id, device_id, snapshot_id) WHERE snapshot_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX policy_results_nosnapshot_uq ON policy_results '
      + '(query_id, device_id) WHERE snapshot_id IS NULL',
  );

  // Reads. Both start with the column the caller actually filters on, and the
  // violation index is partial because "show me what is broken" is the screen.
  await knex.schema.raw(
    'CREATE INDEX policy_results_violations_idx ON policy_results '
      + '(query_id, severity, device_id) WHERE NOT passed',
  );
  await knex.schema.raw(
    'CREATE INDEX policy_results_device_idx ON policy_results (device_id, evaluated_at DESC)',
  );

  // ── the cross-tenant guard ────────────────────────────────────────────────
  //
  // Two foreign keys into two tenant-scoped tables do not, together, say that
  // both point at the SAME tenant. Nothing in the schema forbids attaching
  // customer A's policy to customer B's router, and the row would then show up
  // in A's violation list carrying B's device name. The read path filters on
  // `devices.tenant_id`; this trigger closes the write path.
  await knex.schema.raw(`
    CREATE OR REPLACE FUNCTION policy_results_same_tenant() RETURNS trigger AS $$
    DECLARE
      q_tenant integer;
      d_tenant integer;
      s_device integer;
    BEGIN
      SELECT tenant_id INTO q_tenant FROM saved_queries WHERE id = NEW.query_id;
      SELECT tenant_id INTO d_tenant FROM devices WHERE id = NEW.device_id;
      IF q_tenant IS DISTINCT FROM d_tenant THEN
        RAISE EXCEPTION 'policy_results: query % (tenant %) cannot judge device % (tenant %)',
          NEW.query_id, q_tenant, NEW.device_id, d_tenant;
      END IF;
      IF NEW.snapshot_id IS NOT NULL THEN
        SELECT device_id INTO s_device FROM config_snapshots WHERE id = NEW.snapshot_id;
        IF s_device IS DISTINCT FROM NEW.device_id THEN
          RAISE EXCEPTION 'policy_results: snapshot % does not belong to device %',
            NEW.snapshot_id, NEW.device_id;
        END IF;
      END IF;
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
  `);
  await knex.schema.raw(`
    CREATE TRIGGER policy_results_same_tenant_trg
      BEFORE INSERT OR UPDATE OF query_id, device_id, snapshot_id ON policy_results
      FOR EACH ROW EXECUTE FUNCTION policy_results_same_tenant();
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS policy_results_same_tenant_trg ON policy_results',
  );
  await knex.schema.dropTableIfExists('policy_results');
  await knex.schema.dropTableIfExists('saved_queries');
  // Triggers go with their table; the FUNCTION does not, and a leftover one
  // makes the next `migrate:latest` fail on CREATE FUNCTION.
  await knex.schema.raw('DROP FUNCTION IF EXISTS policy_results_same_tenant()');
  await knex.schema.raw('DROP INDEX IF EXISTS config_snapshots_device_current_idx');
}
