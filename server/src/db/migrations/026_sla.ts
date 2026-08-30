import type { Knex } from 'knex';

/**
 * 026_sla.ts — F7, the CALCULATED SLA (ARCHITECTURE.md §10/F7).
 *
 * The TypeScript contract these tables carry lives in `shared/src/sla.ts`. The
 * vocabularies below are the SAME lists written once more as CHECKs, because a
 * service-layer enum is not what runs when somebody inserts a row from psql
 * during a billing dispute.
 *
 * ┌─ WHAT THIS SCHEMA IS FOR, IN ONE SENTENCE ────────────────────────────────┐
 * │ To make "99.52 %, and here are the 4 h 12 min we excluded because OUR     │
 * │ concentrator was down" a set of rows a customer's auditor can read — and  │
 * │ to make "100 %, because we were not looking" IMPOSSIBLE TO STORE.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ SEVEN DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ──────────────────┐
 * │                                                                           │
 * │ 1. `sla_reports_no_data_has_no_figure` IS THE FEATURE'S SAFETY CATCH.     │
 * │    A CHECK that makes `availability_percent IS NULL` exactly equivalent   │
 * │    to `coverage_status = 'no_data'`. A period with no observation has NO  │
 * │    availability figure — not 100, not 0, not "assumed up". This is the    │
 * │    SAME defect the F2 audit found on the attestation (365 unobserved days │
 * │    rendered as "continuous"), and the only durable fix is the one the     │
 * │    database enforces. `sla_reports_verdict_needs_measurement` is its      │
 * │    twin: a report can be stored as `met` or `missed` only if something    │
 * │    was actually measured.                                                 │
 * │                                                                           │
 * │ 2. `tenant_id` IS ON EVERY TABLE, AND THE FOREIGN KEYS ARE COMPOSITE.     │
 * │    `(site_id, tenant_id) -> sites(id, tenant_id)` and                     │
 * │    `(report_id, tenant_id) -> sla_reports(id, tenant_id)` make            │
 * │    cross-tenant parentage UNREPRESENTABLE rather than merely unwritten.   │
 * │    Same construction as 008, 017 and 021. An SLA report is a statement    │
 * │    about one MSP customer's month; a report whose intervals could belong  │
 * │    to another customer is not a document, it is a leak.                   │
 * │                                                                           │
 * │ 3. THE TWO UNIQUE INDEXES ON `sla_objectives` ARE PARTIAL, AND THEY HAVE  │
 * │    TO BE. `site_id` is NULLABLE — NULL means "this is the tenant-wide     │
 * │    default". Postgres treats NULLs as DISTINCT in a unique index, so a    │
 * │    plain `UNIQUE (tenant_id, site_id)` would constrain the per-site rows  │
 * │    and let a tenant accumulate SEVENTEEN defaults, of which the resolver  │
 * │    would pick one at random. Two partial indexes: one on `(tenant_id)`    │
 * │    WHERE `site_id IS NULL`, one on `(tenant_id, site_id)` WHERE           │
 * │    `site_id IS NOT NULL`.                                                 │
 * │                                                                           │
 * │ 4. THE COMPUTATION KNOB LIVES IN `sla_objectives`, NOT IN THE REQUEST.    │
 * │    `verdict_validity_seconds` decides how long one K7 sample speaks for,  │
 * │    and it therefore moves availability figures. The F2 audit found a      │
 * │    caller-driven parameter that turned 365 unobserved days into a signed  │
 * │    "continuous" attestation; the answer here is that the knob is a stored │
 * │    setting behind `settings.manage`, bounded by a CHECK, copied onto      │
 * │    every report and folded into `params_hash`. THE HTTP LAYER MUST NEVER  │
 * │    ACCEPT IT AS AN ARGUMENT.                                              │
 * │                                                                           │
 * │ 5. A STORED REPORT IS FROZEN AGAINST UPDATE.                              │
 * │    `sla_reports_freeze_trg`. A report handed to a customer in April must  │
 * │    still say in October what it said in April. DELETE is allowed — this   │
 * │    is a computed artefact under a retention policy, not a ledger — and    │
 * │    the deletion cascades to the intervals, which are meaningless without  │
 * │    their header.                                                          │
 * │                                                                           │
 * │ 6. `sla_report_intervals` IS THE AUDIT TRAIL, AND IT IS NOT OPTIONAL.     │
 * │    Every second of the period is one row's worth of a `kind` and a        │
 * │    `reason`: `excluded_management / verdict_concentrator_degraded`,       │
 * │    `excluded_maintenance / maintenance_window`, `unmeasured /             │
 * │    no_observation`. The brief is explicit — an SLA whose exclusions       │
 * │    cannot be audited is worth no more than the spreadsheet it replaced.   │
 * │    The service refuses to store a report whose trail exceeds              │
 * │    `SLA_MAX_STORED_INTERVALS` rather than truncating it: a trail with     │
 * │    holes is worse than no trail, because it looks complete.               │
 * │                                                                           │
 * │ 7. `ppp_sessions` GAINS ONE INDEX AND NOTHING ELSE.                       │
 * │    `(concentrator_id, started_at DESC)`. F7's hot read is "every session  │
 * │    this concentrator held during the period, for anybody" — the           │
 * │    observation mask that separates "the router was off" from "ObliWAN was │
 * │    not installed yet". Migration 002 indexed `(device_id, started_at)`    │
 * │    and `(ppp_username, started_at)`; neither serves it. This is additive  │
 * │    and it is dropped in `down()`.                                         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2 / R10): nothing here reads, stores or transports a credential.
 * The widest datum in these tables is a number of seconds, a site id and a
 * reason string drawn from a closed vocabulary. There is NO jsonb column in
 * this migration at all — deliberately, and worth saying out loud: the audit
 * that preceded this milestone found "the L2TP passwords of the whole fleet in
 * a jsonb column served to the quarantine screen", and the surest way not to
 * repeat it is not to have the column. `ppp_sessions.ppp_username` is READ by
 * the service (it is what identifies a session) and is never written here and
 * never returned by the API.
 *
 * D3: nothing in F7 writes to an equipment. It does not open a session, it
 * does not dial, it does not enqueue a `change_job`. It is arithmetic over rows
 * that M2 (`ppp_sessions`, `reachability_verdicts`, `sites`) already wrote.
 */

// -- Vocabularies. Comment gives the LONGEST value; the column is wider. ------

/** `shared/src/sla.ts` — SLA_INTERVAL_KINDS. Longest: 'excluded_maintenance'
 *  (21); the column is varchar(24). */
const INTERVAL_KINDS =
  "'up','down','excluded_management','excluded_maintenance','unmeasured'";

/** `shared/src/sla.ts` — SLA_COVERAGE_STATUSES. Longest: 'complete' (8);
 *  the column is varchar(12). */
const COVERAGE_STATUSES = "'no_data','partial','complete'";

/** `shared/src/sla.ts` — SLA_OBJECTIVE_VERDICTS. Longest: 'indeterminate'
 *  (13); the column is varchar(16). */
const OBJECTIVE_VERDICTS = "'met','missed','indeterminate'";

/** `shared/src/sla.ts` — SLA_OBJECTIVE_SCOPES. Longest: 'tenant' (6); the
 *  column is varchar(8). */
const OBJECTIVE_SCOPES = "'tenant','site'";

/** `shared/src/sla.ts` — SLA_MIN_OBJECTIVE_PERCENT / SLA_MAX_OBJECTIVE_PERCENT.
 *  The floor is NOT decoration: with an objective of 0, a period with no data
 *  at all satisfies "worst case >= objective" and gets stored as MET. */
const MIN_OBJECTIVE = 50;
const MAX_OBJECTIVE = 100;

/** `shared/src/sla.ts` — MIN/MAX_VERDICT_VALIDITY_SECONDS and the default. */
const MIN_VALIDITY = 60;
const MAX_VALIDITY = 21600;
const DEFAULT_VALIDITY = 900;

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // 0. The composite target on `sites` (decision 2).
  // ==========================================================================
  // `sites.id` is already the PRIMARY KEY, so `UNIQUE (id, tenant_id)` adds no
  // constraint that any INSERT could ever violate — it exists purely so that a
  // composite foreign key can point at it. It is created GUARDED (another
  // migration may add it first) and, following the precedent of 017/021, it is
  // NOT dropped in `down()`: taking a uniqueness guarantee away from somebody
  // else's foreign keys is not a rollback, it is a break, and here it cannot
  // even cost anything to leave behind.
  await knex.schema.raw(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'sites_id_tenant_uq'
      ) THEN
        ALTER TABLE sites ADD CONSTRAINT sites_id_tenant_uq UNIQUE (id, tenant_id);
      END IF;
    END $$;
  `);

  // ==========================================================================
  // 1. sla_objectives — what the contract promises (decisions 3 and 4).
  // ==========================================================================

  await knex.schema.createTable('sla_objectives', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    // NULL = the tenant-wide default. See decision 3 for why the two unique
    // indexes below are partial and why a plain UNIQUE would be a hole.
    t.integer('site_id').nullable();

    t.string('scope', 8).notNullable();

    // 99.5 needs one decimal; five nines needs three. numeric(7,4) leaves room
    // and is the SAME precision the verdict is decided at (`roundPercent`), so
    // the number the customer reads is the number that produced the verdict.
    t.decimal('objective_percent', 7, 4).notNullable();

    // Decision 4. A stored setting, never a request parameter.
    t.integer('verdict_validity_seconds').notNullable().defaultTo(DEFAULT_VALIDITY);

    t.text('note').nullable();
    t.integer('updated_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);

    t.index(['tenant_id', 'site_id']);
  });

  // Cross-tenant parentage is unrepresentable, not merely unwritten.
  await knex.schema.raw(`
    ALTER TABLE sla_objectives
      ADD CONSTRAINT sla_objectives_site_tenant_fk
      FOREIGN KEY (site_id, tenant_id) REFERENCES sites (id, tenant_id)
      ON DELETE CASCADE
  `);

  // `scope` and `site_id` cannot disagree. A row claiming scope 'site' with no
  // site, or scope 'tenant' with one, would make the resolver's precedence
  // meaningless.
  await knex.schema.raw(
    'ALTER TABLE sla_objectives ADD CONSTRAINT sla_objectives_scope_chk ' +
      `CHECK (scope IN (${OBJECTIVE_SCOPES}) AND ` +
      "(scope = 'site') = (site_id IS NOT NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE sla_objectives ADD CONSTRAINT sla_objectives_percent_chk ' +
      `CHECK (objective_percent >= ${MIN_OBJECTIVE} AND objective_percent <= ${MAX_OBJECTIVE})`,
  );
  await knex.schema.raw(
    'ALTER TABLE sla_objectives ADD CONSTRAINT sla_objectives_validity_chk ' +
      `CHECK (verdict_validity_seconds >= ${MIN_VALIDITY} ` +
      `AND verdict_validity_seconds <= ${MAX_VALIDITY})`,
  );

  // DECISION 3. Both partial. `NULLS DISTINCT` (the default, and the only
  // behaviour before PG15) means a non-partial index on (tenant_id, site_id)
  // would constrain NOTHING for the default rows.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX sla_objectives_tenant_default_uq ON sla_objectives ' +
      '(tenant_id) WHERE site_id IS NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX sla_objectives_site_uq ON sla_objectives ' +
      '(tenant_id, site_id) WHERE site_id IS NOT NULL',
  );

  // ==========================================================================
  // 2. sla_reports — the frozen document (decisions 1, 2 and 5).
  // ==========================================================================

  await knex.schema.createTable('sla_reports', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('site_id').notNullable();

    t.timestamp('period_start', { useTz: true }).notNullable();
    t.timestamp('period_end', { useTz: true }).notNullable();
    t.timestamp('generated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    // Text, not a foreign key: the report outlives the account that asked for
    // it, exactly like `audit_log.actor_id` (migration 019).
    t.string('actor_id', 64).nullable();
    t.string('actor_name', 255).nullable();

    // -- The parameters that produced the numbers (decision 4) --------------
    t.decimal('objective_percent', 7, 4).nullable();
    t.string('objective_scope', 8).nullable();
    t.integer('verdict_validity_seconds').notNullable();
    t.string('algorithm_version', 16).notNullable();
    // sha256 over the canonical parameter set. Two reports with the same hash
    // were computed the same way; two with different hashes are two documents,
    // and comparing them without noticing is how a regression gets sold.
    t.specificType('params_hash', 'char(64)').notNullable();

    // -- The seconds (decision 6 gives them their names) --------------------
    t.bigInteger('period_seconds').notNullable();
    t.bigInteger('up_seconds').notNullable().defaultTo(0);
    t.bigInteger('down_seconds').notNullable().defaultTo(0);
    t.bigInteger('excluded_management_seconds').notNullable().defaultTo(0);
    t.bigInteger('excluded_maintenance_seconds').notNullable().defaultTo(0);
    t.bigInteger('unmeasured_seconds').notNullable().defaultTo(0);

    // -- The figures. NULLABLE, and decision 1 explains why ----------------
    t.decimal('availability_percent', 7, 4).nullable();
    t.decimal('worst_case_percent', 7, 4).nullable();
    t.decimal('best_case_percent', 7, 4).nullable();
    t.decimal('coverage_percent', 7, 4).nullable();

    t.string('coverage_status', 12).notNullable();
    t.string('objective_verdict', 16).notNullable();
    t.string('verdict_reason', 64).notNullable();

    // Non-null when `sites.maintenance_window` could not be read. Nothing was
    // excluded for maintenance in that case and the report has to say so: an
    // unreadable window must never become a licence to delete downtime.
    t.string('maintenance_error', 255).nullable();

    t.integer('device_count').notNullable().defaultTo(0);
    t.integer('interval_count').notNullable().defaultTo(0);

    t.index(['tenant_id', 'site_id', 'period_start']);
    t.index(['tenant_id', 'generated_at']);
  });

  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_id_tenant_uq UNIQUE (id, tenant_id)',
  );
  await knex.schema.raw(`
    ALTER TABLE sla_reports
      ADD CONSTRAINT sla_reports_site_tenant_fk
      FOREIGN KEY (site_id, tenant_id) REFERENCES sites (id, tenant_id)
      ON DELETE CASCADE
  `);

  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_period_chk ' +
      'CHECK (period_end > period_start)',
  );
  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_status_chk ' +
      `CHECK (coverage_status IN (${COVERAGE_STATUSES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_verdict_chk ' +
      `CHECK (objective_verdict IN (${OBJECTIVE_VERDICTS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_objective_scope_chk ' +
      `CHECK (objective_scope IS NULL OR objective_scope IN (${OBJECTIVE_SCOPES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_seconds_chk ' +
      'CHECK (period_seconds > 0 AND up_seconds >= 0 AND down_seconds >= 0 ' +
      'AND excluded_management_seconds >= 0 AND excluded_maintenance_seconds >= 0 ' +
      'AND unmeasured_seconds >= 0)',
  );
  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_validity_chk ' +
      `CHECK (verdict_validity_seconds >= ${MIN_VALIDITY} ` +
      `AND verdict_validity_seconds <= ${MAX_VALIDITY})`,
  );
  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_percent_range_chk ' +
      'CHECK (' +
      '(availability_percent IS NULL OR (availability_percent >= 0 AND availability_percent <= 100))' +
      ' AND (worst_case_percent IS NULL OR (worst_case_percent >= 0 AND worst_case_percent <= 100))' +
      ' AND (best_case_percent IS NULL OR (best_case_percent >= 0 AND best_case_percent <= 100))' +
      ' AND (coverage_percent IS NULL OR (coverage_percent >= 0 AND coverage_percent <= 100)))',
  );

  // ── DECISION 1. THE TWO CHECKS THIS WHOLE MIGRATION EXISTS FOR. ──────────
  //
  // A period with no observation has no availability figure. Not 100. The F2
  // audit found the same defect one milestone ago, on an artefact that was
  // signed and handed to an insurer, and prose in a service did not stop it.
  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_no_data_has_no_figure ' +
      "CHECK ((coverage_status = 'no_data') = (availability_percent IS NULL))",
  );
  // ... and nothing that was never measured can be stored as met or missed.
  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_verdict_needs_measurement ' +
      "CHECK (objective_verdict = 'indeterminate' OR availability_percent IS NOT NULL)",
  );
  // A verdict other than `indeterminate` is a statement about an objective,
  // so the objective it was measured against has to be on the row.
  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_verdict_needs_objective ' +
      "CHECK (objective_verdict = 'indeterminate' OR objective_percent IS NOT NULL)",
  );
  // The seconds have to add up to the period. A classification that loses a
  // second silently improves the ratio, and a report whose parts do not sum to
  // its whole is the first thing an auditor checks.
  await knex.schema.raw(
    'ALTER TABLE sla_reports ADD CONSTRAINT sla_reports_seconds_balance_chk ' +
      'CHECK (up_seconds + down_seconds + excluded_management_seconds ' +
      '+ excluded_maintenance_seconds + unmeasured_seconds = period_seconds)',
  );

  // -- Decision 5: frozen against UPDATE ------------------------------------
  await knex.schema.raw(`
    CREATE FUNCTION sla_reports_freeze() RETURNS trigger AS $fn$
    BEGIN
      RAISE EXCEPTION
        'sla_reports is append-only: report % was issued at % and cannot be edited',
        OLD.id, OLD.generated_at
        USING ERRCODE = '23514';
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER sla_reports_freeze_trg
      BEFORE UPDATE ON sla_reports
      FOR EACH ROW EXECUTE FUNCTION sla_reports_freeze()
  `);

  // ==========================================================================
  // 3. sla_report_intervals — the audit trail (decision 6).
  // ==========================================================================

  await knex.schema.createTable('sla_report_intervals', (t) => {
    t.bigIncrements('id').primary();
    t.bigInteger('report_id').notNullable();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.timestamp('started_at', { useTz: true }).notNullable();
    t.timestamp('ended_at', { useTz: true }).notNullable();
    t.integer('seconds').notNullable();

    t.string('kind', 24).notNullable();
    // No CHECK on purpose: the reason is EXPLANATORY, the kind is the
    // load-bearing value, and a new explanation must not need a migration.
    t.string('reason', 64).notNullable();

    t.index(['report_id', 'started_at']);
  });

  await knex.schema.raw(`
    ALTER TABLE sla_report_intervals
      ADD CONSTRAINT sla_report_intervals_report_tenant_fk
      FOREIGN KEY (report_id, tenant_id) REFERENCES sla_reports (id, tenant_id)
      ON DELETE CASCADE
  `);
  await knex.schema.raw(
    'ALTER TABLE sla_report_intervals ADD CONSTRAINT sla_report_intervals_kind_chk ' +
      `CHECK (kind IN (${INTERVAL_KINDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE sla_report_intervals ADD CONSTRAINT sla_report_intervals_span_chk ' +
      'CHECK (ended_at > started_at AND seconds > 0)',
  );

  // ==========================================================================
  // 4. The one index F7 adds to somebody else's table (decision 7).
  // ==========================================================================
  await knex.schema.raw(
    'CREATE INDEX IF NOT EXISTS ppp_sessions_conc_started_idx ON ppp_sessions ' +
      '(concentrator_id, started_at DESC)',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DROP INDEX IF EXISTS ppp_sessions_conc_started_idx');
  await knex.schema.dropTableIfExists('sla_report_intervals');
  // The trigger goes with its table; the FUNCTION does not, so it is dropped by
  // name or a re-run of `migrate:latest` fails with 42723.
  await knex.schema.dropTableIfExists('sla_reports');
  await knex.schema.raw('DROP FUNCTION IF EXISTS sla_reports_freeze()');
  await knex.schema.dropTableIfExists('sla_objectives');
  // `sites_id_tenant_uq` is deliberately NOT dropped — see the note in `up()`.
}
