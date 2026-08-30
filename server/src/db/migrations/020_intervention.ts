import type { Knex } from 'knex';

/**
 * 020_intervention.ts — F3 (intervention mode) and F4 (change → telemetry J+7).
 *
 * ARCHITECTURE.md §10/F3 and §10/F4. The TypeScript contract these tables carry
 * lives in `shared/src/intervention.ts`; every vocabulary below is duplicated
 * here as a SQL string for the same reason migrations 011 and 017 do it — a
 * migration must not import the application at the version it will be replayed
 * at, five years from now, on a restored dump.
 *
 * ┌─ SIX DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ────────────────────┐
 * │                                                                           │
 * │ 1. `interventions` CARRIES `tenant_id`, IT LEADS EVERY KEY, AND THE       │
 * │    COMPOSITE FK `(device_id, tenant_id) → devices(id, tenant_id)` MAKES   │
 * │    "an intervention on another customer's router" UNREPRESENTABLE.        │
 * │    `devices_id_tenant_uq` exists since migration 017 precisely so this    │
 * │    shape is expressible. The children (`intervention_events`,             │
 * │    `intervention_drift_links`) denormalise `tenant_id` and point back     │
 * │    with `(intervention_id, tenant_id)`, exactly as 008 and 017 do.        │
 * │                                                                           │
 * │ 2. AT MOST ONE OPEN INTERVENTION PER DEVICE, AND IT IS A PARTIAL UNIQUE   │
 * │    INDEX. Two overlapping windows on one router would make "which         │
 * │    intervention absorbed this drift" ambiguous, and an ambiguous          │
 * │    attribution is the one thing K6 refuses to produce. Partial because    │
 * │    the constraint applies to `status = 'open'` only — closed windows      │
 * │    accumulate for ever, which is the point.                               │
 * │                                                                           │
 * │ 3. AN INTERVENTION HAS A DEADLINE IN THE SCHEMA, NOT ONLY IN THE          │
 * │    SERVICE. `interventions_window_chk` refuses `expires_at` beyond 72 h   │
 * │    after `opened_at`. The service ceiling is 12 h                         │
 * │    (`INTERVENTION_MAX_WINDOW_MINUTES`); this is the outer wall behind it. │
 * │    An intervention that never ends is a permanent hole in attribution —   │
 * │    every future change on that device excused by a window somebody        │
 * │    opened in March — and that hole is exactly what §10/F3 asks to close.  │
 * │                                                                           │
 * │ 4. NOTHING HERE WRITES TO AN EQUIPMENT. D3 is untouched: an intervention  │
 * │    is a DECLARATION that a human is working, never an authorisation for   │
 * │    this server to act. There is no column in this migration that a job    │
 * │    runner reads, and no path from `interventions` to `change_jobs`.       │
 * │                                                                           │
 * │ 5. NO SECRET, NO CONFIGURATION BODY. The before/after states are stored   │
 * │    as `config_snapshots` IDS, never as text or jsonb here (§8.2 / R10),   │
 * │    and `intervention_events.detail` is guarded by                         │
 * │    `intervention_events_detail_chk`, which refuses a payload carrying a   │
 * │    credential-shaped key. Same two-independent-refusals discipline as     │
 * │    migration 017 decision 3, and for the same reason: the audit that      │
 * │    found an entire fleet's L2TP passwords in a jsonb column served to the │
 * │    UI happened on this project.                                           │
 * │                                                                           │
 * │ 6. `change_aftermath` HAS NO FOREIGN KEYS — deliberately, and by exactly  │
 * │    the same argument as `apply_outcomes` (migration 009 decision 5). It   │
 * │    is written NEXT TO the §8.3 corpus and it is part of it: "what does a  │
 * │    firewall push to an RB5009 on 7.14 look like a week later" is a        │
 * │    cross-client, cross-brand question, and offboarding a customer must    │
 * │    not delete the evidence that answers it. The price is that reads MUST  │
 * │    filter on `tenant_id` themselves; every query in                       │
 * │    `services/change/aftermath.service.ts` does, and the index leads with  │
 * │    it so forgetting is a sequential scan somebody notices.                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE ONE CHANGE THIS MIGRATION MAKES TO ANOTHER MILESTONE'S TABLE ────────┐
 * │ `drift_attributions.verdict` gains the value `'intervention'`. That is    │
 * │ the whole of §10/F3's first property: during a declared window, drift on  │
 * │ that device stops surfacing as an anonymous anomaly. The column is        │
 * │ already `varchar(16)` and `'intervention'` is 12 characters, so no width  │
 * │ change is needed, and `drift_attributions_open_idx` (partial on           │
 * │ `unattributed`/`ambiguous`) automatically stops returning a claimed run.  │
 * │                                                                           │
 * │ NO column is added there and no trigger is installed: the pointer from a  │
 * │ claimed run to its intervention lives in `intervention_drift_links`,      │
 * │ which this migration owns. Coupling the two tables with a column plus a   │
 * │ CHECK would make M8's own `attributeRun(force)` path — which merges a     │
 * │ fresh verdict over the row — fail at the constraint instead of simply     │
 * │ overwriting a claim, and a re-attribution that ERRORS is worse than one   │
 * │ that supersedes.                                                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ENUMS AS TEXT + CHECK, like every vocabulary in this schema since 002.
 * Widths are set from the LONGEST value of each CHECK and rounded up:
 *
 *   intervention status        'cancelled'          =  9 -> varchar(12)
 *   intervention channel       'console'            =  7 -> varchar(12)
 *   intervention disposition   'unreviewed'         = 10 -> varchar(12)
 *   intervention event         'snapshot_before'    = 15 -> varchar(20)
 *   link disposition           'already_explained'  = 17 -> varchar(24)
 *   aftermath verdict          'INSUFFICIENT_DATA'  = 17 -> varchar(20)
 *   aftermath metric           'unexpected_reboots' = 18 -> varchar(24)
 */

const INTERVENTION_STATUSES = "'open','closed','expired','cancelled'";
const INTERVENTION_CHANNELS = "'winbox','ssh','webfig','console','vendor','other'";
const INTERVENTION_DISPOSITIONS = "'unreviewed','no_change','template','exception','rejected'";
const INTERVENTION_EVENTS =
  "'opened','snapshot_before','snapshot_after','closed','expired','cancelled'," +
  "'drift_linked','disposition'";
const LINK_DISPOSITIONS = "'attributed','already_explained','window_too_wide'";
const AFTERMATH_VERDICTS = "'STABLE','DEGRADED','IMPROVED','INSUFFICIENT_DATA'";

/** Mirrors `INTERVENTION_HARD_CAP_MINUTES` in `shared/src/intervention.ts`. */
const HARD_CAP_HOURS = 72;

/**
 * The M8 vocabulary, verbatim from migration 011, plus this feature's value.
 * Written out rather than derived: the CHECK is dropped and recreated, so the
 * full list has to appear here anyway, and a `regexp_replace` on a live
 * constraint definition is not a thing anybody should read at 3 a.m.
 */
const ATTRIBUTION_VERDICTS_WITH_INTERVENTION =
  "'attributed','platform','ambiguous','unattributed','excluded','intervention'";
const ATTRIBUTION_VERDICTS_ORIGINAL =
  "'attributed','platform','ambiguous','unattributed','excluded'";

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // interventions — the declared window (§10/F3)
  // ==========================================================================
  await knex.schema.createTable('interventions', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable();

    t.string('status', 12).notNullable().defaultTo('open');
    t.string('channel', 12).notNullable().defaultTo('winbox');

    // WHO is at the keyboard. Free text and NOT a FK to `users`: the person
    // opening Winbox is very often a subcontractor or the customer's own
    // admin, i.e. somebody with no account here. Forcing a user id would make
    // the honest answer unrepresentable and push operators to declare the
    // intervention under their own name — which is worse than free text,
    // because it would be believed.
    t.string('operator', 96).notNullable();
    // The platform user who DECLARED it. Nullable only for the SET NULL of a
    // deleted account; every service path fills it in.
    t.integer('opened_by').nullable().references('id').inTable('users').onDelete('SET NULL');

    // WHY. NOT NULL and non-blank, the same rule as
    // `normalization_rules.rationale` (007) and `baseline_exceptions.reason`
    // (017): an undeclared reason turns the intervention log into a list of
    // dates, and the list of dates is what nobody reads three months later.
    t.text('reason').notNullable();

    t.timestamp('opened_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    // The DECLARED end. It is what makes the window a window.
    t.timestamp('expires_at', { useTz: true }).notNullable();
    t.timestamp('closed_at', { useTz: true }).nullable();
    t.integer('closed_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    // Set by the expiry sweep. Distinct from `closed_at`, because "nobody ever
    // came back to this" is the fact §10/F3 asks the product to surface.
    t.timestamp('expired_at', { useTz: true }).nullable();
    t.timestamp('cancelled_at', { useTz: true }).nullable();

    // The before/after states, BY REFERENCE. Never a config body here (§8.2).
    // Note that `config_snapshots` deduplicates on (device_id, ncm_hash), so
    // an intervention that changed nothing legitimately ends with
    // `snapshot_before_id = snapshot_after_id`, and that equality IS the
    // "no_change" evidence rather than an anomaly.
    t.bigInteger('snapshot_before_id').nullable()
      .references('id').inTable('config_snapshots').onDelete('SET NULL');
    t.bigInteger('snapshot_after_id').nullable()
      .references('id').inTable('config_snapshots').onDelete('SET NULL');

    // The drift run computed at closing time — the semantic diff offered for
    // promotion to a template or to an F1 exception.
    t.bigInteger('drift_run_id').nullable()
      .references('id').inTable('drift_runs').onDelete('SET NULL');
    t.integer('findings_count').notNullable().defaultTo(0);
    t.string('max_severity', 12).nullable();

    t.string('disposition', 12).notNullable().defaultTo('unreviewed');
    t.text('notes').nullable();

    t.timestamps(true, true);

    // Lets the children carry a composite FK back (decision 1).
    t.unique(['id', 'tenant_id'], { indexName: 'interventions_id_tenant_uq' });
  });

  await knex.schema.raw(
    'ALTER TABLE interventions ADD CONSTRAINT interventions_device_tenant_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );

  await knex.schema.raw(
    `ALTER TABLE interventions ADD CONSTRAINT interventions_status_chk
       CHECK (status IN (${INTERVENTION_STATUSES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE interventions ADD CONSTRAINT interventions_channel_chk
       CHECK (channel IN (${INTERVENTION_CHANNELS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE interventions ADD CONSTRAINT interventions_disposition_chk
       CHECK (disposition IN (${INTERVENTION_DISPOSITIONS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE interventions ADD CONSTRAINT interventions_reason_chk
       CHECK (length(btrim(reason)) > 0 AND length(btrim(operator)) > 0)`,
  );
  // Decision 3 — the deadline is in the schema.
  await knex.schema.raw(
    `ALTER TABLE interventions ADD CONSTRAINT interventions_window_chk
       CHECK (expires_at > opened_at
              AND expires_at <= opened_at + interval '${HARD_CAP_HOURS} hours')`,
  );
  // The three terminal states and their timestamps agree, in both directions.
  // One-directional would let a row claim `closed` with no `closed_at`, and the
  // screen that lists "windows nobody closed" reads exactly that column.
  await knex.schema.raw(
    `ALTER TABLE interventions ADD CONSTRAINT interventions_terminal_chk
       CHECK (
         (status = 'closed')    = (closed_at    IS NOT NULL)
         AND (status = 'expired')   = (expired_at   IS NOT NULL)
         AND (status = 'cancelled') = (cancelled_at IS NOT NULL)
         AND (closed_at IS NULL OR closed_at >= opened_at)
         AND (expired_at IS NULL OR expired_at >= expires_at)
       )`,
  );
  // A window that was cancelled never ran, so it cannot carry a diff; and only
  // a closed one can have been reviewed into a disposition.
  await knex.schema.raw(
    `ALTER TABLE interventions ADD CONSTRAINT interventions_review_chk
       CHECK (
         (disposition = 'unreviewed' OR status = 'closed')
         AND (status <> 'cancelled' OR (snapshot_after_id IS NULL AND drift_run_id IS NULL))
         AND findings_count >= 0
       )`,
  );

  // Decision 2 — one live window per device, and it is PARTIAL.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX interventions_one_open_uq ON interventions (tenant_id, device_id) ' +
      "WHERE status = 'open'",
  );
  // The tenant's list screen, newest first.
  await knex.schema.raw(
    'CREATE INDEX interventions_tenant_time_idx ' +
      'ON interventions (tenant_id, status, opened_at DESC)',
  );
  // "Is this device under intervention right now" — the question the drift
  // attribution asks once per run, and the reason the index is partial.
  await knex.schema.raw(
    'CREATE INDEX interventions_device_live_idx ON interventions (tenant_id, device_id, expires_at) ' +
      "WHERE status = 'open'",
  );
  // The expiry sweep: the ONLY index it needs, and it stays tiny because the
  // predicate throws away every window that already ended.
  await knex.schema.raw(
    "CREATE INDEX interventions_expiry_idx ON interventions (expires_at) WHERE status = 'open'",
  );
  // The device history screen, and the window-overlap lookup of the linker.
  await knex.schema.raw(
    'CREATE INDEX interventions_device_hist_idx ' +
      'ON interventions (tenant_id, device_id, opened_at DESC)',
  );

  // ==========================================================================
  // intervention_events — the append-only lifecycle log.
  //
  // This is how an expiry "says so" (§10/F3). A status column that flips to
  // `expired` is a state; a row that says WHEN it expired, with how much of the
  // window went unattended, is a fact that survives the operator who closes the
  // screen afterwards. `audit_log` does not exist in this schema (migration 012
  // says so explicitly), so the feature keeps its own log rather than inventing
  // a second general-purpose one.
  // ==========================================================================
  await knex.schema.createTable('intervention_events', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable();
    t.bigInteger('intervention_id').notNullable();
    t.string('event', 20).notNullable();
    t.integer('actor_user_id').nullable().references('id').inTable('users').onDelete('SET NULL');
    // Numbers and ids only. See `intervention_events_detail_chk`.
    t.jsonb('detail').notNullable().defaultTo(knex.raw("'{}'::jsonb"));
    t.timestamp('at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    'ALTER TABLE intervention_events ADD CONSTRAINT intervention_events_parent_fk ' +
      'FOREIGN KEY (intervention_id, tenant_id) ' +
      'REFERENCES interventions (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE intervention_events ADD CONSTRAINT intervention_events_kind_chk
       CHECK (event IN (${INTERVENTION_EVENTS}))`,
  );
  // Decision 5. The database refuses a credential-shaped key in the payload,
  // independently of whatever the service believes it is writing. The name list
  // is the same family the audit redactor recognises (`services/audit.service`
  // `isSecretName`).
  //
  // Written as a regex over the RENDERED jsonb and not as
  // `NOT EXISTS (SELECT ... jsonb_object_keys(detail))`, because PostgreSQL
  // refuses a subquery in a CHECK constraint outright. The pattern anchors on
  // the `"name":` shape, so it tests KEYS and not values — a `reason` field
  // that happens to contain the word "password" is legitimate prose and must
  // not make an intervention unloggable.
  await knex.schema.raw(
    `ALTER TABLE intervention_events ADD CONSTRAINT intervention_events_detail_chk
       CHECK (
         jsonb_typeof(detail) = 'object'
         AND detail::text !~*
           '"[a-z0-9_.-]*(pass|pwd|secret|key|psk|token|credential|community)[a-z0-9_.-]*"[[:space:]]*:'
       )`,
  );
  await knex.schema.raw(
    'CREATE INDEX intervention_events_parent_idx ' +
      'ON intervention_events (tenant_id, intervention_id, at DESC)',
  );

  // ==========================================================================
  // intervention_drift_links — what a window absorbed (§10/F3, property 1)
  //
  // A row is written for EVERY drift run considered against an intervention,
  // including the ones the intervention did NOT claim. "We looked and left the
  // K6 verdict alone because a change job already explained it" is a result,
  // and storing only the claims would make the feature look like it explains
  // everything it touches.
  // ==========================================================================
  await knex.schema.createTable('intervention_drift_links', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable();
    t.bigInteger('intervention_id').notNullable();
    t.bigInteger('drift_run_id').notNullable()
      .references('id').inTable('drift_runs').onDelete('CASCADE');
    t.integer('device_id').notNullable();

    t.string('disposition', 24).notNullable();
    // What K6 had concluded on its own, before the window was considered.
    // Kept so the operator can see what the platform would have said — and so
    // that undoing a claim is possible without re-running attribution.
    t.string('prior_verdict', 16).nullable();

    // The two numbers that justify the claim. A two-week change window that
    // overlaps a two-hour intervention by two hours is a coincidence, and the
    // ratio is what lets a screen say so instead of implying certainty.
    t.integer('window_span_seconds').notNullable();
    t.integer('overlap_seconds').notNullable();

    t.timestamp('linked_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    'ALTER TABLE intervention_drift_links ADD CONSTRAINT intervention_drift_links_parent_fk ' +
      'FOREIGN KEY (intervention_id, tenant_id) ' +
      'REFERENCES interventions (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE intervention_drift_links ADD CONSTRAINT intervention_drift_links_device_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE intervention_drift_links ADD CONSTRAINT intervention_drift_links_disp_chk
       CHECK (disposition IN (${LINK_DISPOSITIONS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE intervention_drift_links ADD CONSTRAINT intervention_drift_links_span_chk
       CHECK (window_span_seconds >= 0
              AND overlap_seconds >= 0
              AND overlap_seconds <= window_span_seconds)`,
  );
  // ONE intervention per drift run. Two windows claiming the same change is the
  // ambiguity decision 2 already forbids at the source; this is the second
  // fence, on the table where the ambiguity would be visible.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX intervention_drift_links_run_uq ' +
      'ON intervention_drift_links (tenant_id, drift_run_id)',
  );
  await knex.schema.raw(
    'CREATE INDEX intervention_drift_links_parent_idx ' +
      'ON intervention_drift_links (tenant_id, intervention_id, linked_at DESC)',
  );

  // ==========================================================================
  // The one change to M8's table: a sixth verdict.
  // ==========================================================================
  await knex.schema.raw(
    'ALTER TABLE drift_attributions DROP CONSTRAINT IF EXISTS drift_attributions_verdict_chk',
  );
  await knex.schema.raw(
    `ALTER TABLE drift_attributions ADD CONSTRAINT drift_attributions_verdict_chk
       CHECK (verdict IN (${ATTRIBUTION_VERDICTS_WITH_INTERVENTION}))`,
  );
  await knex.schema.raw(
    "COMMENT ON CONSTRAINT drift_attributions_verdict_chk ON drift_attributions IS $$" +
      "'intervention' was added by migration 020 (F3): a drift run whose change window " +
      'overlaps a DECLARED intervention on the same device is explained by that window ' +
      'and stops appearing as an anomaly nobody owns. The pointer to the window lives in ' +
      'intervention_drift_links, not in a column here — see the header of 020_intervention.ts. ' +
      "The verdict never NAMES anybody: drift_attributions_names_only_when_attributed still " +
      'holds, and the responsible human is one join away in interventions.operator.$$',
  );

  // ==========================================================================
  // change_aftermath — §10/F4, written NEXT TO `apply_outcomes` (§8.3)
  //
  // Decision 6: no foreign keys, same as `apply_outcomes`. The four hardware
  // dimensions are copied in so the corpus can be sliced the same way ("do
  // firewall pushes to a 2927 on 4.4.x degrade a week later?"), which is a
  // question no single vendor can answer and this table can.
  // ==========================================================================
  await knex.schema.createTable('change_aftermath', (t) => {
    t.bigIncrements('id').primary();

    t.integer('tenant_id').notNullable();
    t.integer('device_id').notNullable();
    // The anchor. Exactly one of the two is set — see `change_aftermath_anchor_chk`.
    t.bigInteger('job_id').nullable();
    t.bigInteger('intervention_id').nullable();

    // The pivot. Everything before it is the baseline, everything after is the
    // observation, and the hour containing it belongs to NEITHER (a bucket
    // straddling the change is half pre-change data, and counting it as
    // "after" is the same class of error as blaming a pre-existing fault).
    t.timestamp('change_at', { useTz: true }).notNullable();
    t.integer('horizon_days').notNullable().defaultTo(7);
    t.timestamp('baseline_from', { useTz: true }).notNullable();
    t.timestamp('baseline_to', { useTz: true }).notNullable();
    t.timestamp('after_from', { useTz: true }).notNullable();
    t.timestamp('after_to', { useTz: true }).notNullable();

    t.string('verdict', 20).notNullable();

    // The signal array, as evaluated. Numbers and interface names only — no
    // configuration, no credential (§8.2). `signals` is what makes a verdict
    // arguable: "DEGRADED" alone is an accusation, "ether3 went from 0.2 to 38
    // errors per hour since this change" is evidence.
    t.jsonb('signals').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.integer('degraded_count').notNullable().defaultTo(0);
    t.integer('improved_count').notNullable().defaultTo(0);
    // THE trap-1 counter: subjects excluded because they were ALREADY
    // unhealthy before the change. Stored rather than recomputed because the
    // screen has to show it next to the verdict — a DEGRADED verdict with
    // eleven pre-existing exclusions is a very different sentence from the
    // same verdict with none.
    t.integer('preexisting_count').notNullable().defaultTo(0);
    t.integer('measured_count').notNullable().defaultTo(0);

    t.string('brand', 32).nullable();
    t.string('model', 128).nullable();
    t.string('os_version', 64).nullable();

    t.timestamp('evaluated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    `ALTER TABLE change_aftermath ADD CONSTRAINT change_aftermath_verdict_chk
       CHECK (verdict IN (${AFTERMATH_VERDICTS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE change_aftermath ADD CONSTRAINT change_aftermath_anchor_chk
       CHECK ((job_id IS NULL) <> (intervention_id IS NULL))`,
  );
  // The windows are ordered and the change sits between them. A row that
  // measured "after" from before the change is not a weaker result, it is a
  // wrong one, and this is the constraint that makes it unrepresentable.
  await knex.schema.raw(
    `ALTER TABLE change_aftermath ADD CONSTRAINT change_aftermath_windows_chk
       CHECK (
         baseline_from < baseline_to
         AND baseline_to <= change_at
         AND change_at <= after_from
         AND after_from < after_to
         AND horizon_days BETWEEN 1 AND 90
       )`,
  );
  await knex.schema.raw(
    `ALTER TABLE change_aftermath ADD CONSTRAINT change_aftermath_counts_chk
       CHECK (
         degraded_count >= 0 AND improved_count >= 0
         AND preexisting_count >= 0 AND measured_count >= 0
         AND jsonb_typeof(signals) = 'array'
         AND (verdict <> 'DEGRADED' OR degraded_count > 0)
         AND (verdict <> 'INSUFFICIENT_DATA' OR measured_count = 0)
       )`,
  );

  // One evaluation per anchor per horizon. Both are PARTIAL indexes because
  // both scope columns are nullable, and PostgreSQL's default NULLS DISTINCT
  // would let the same job be evaluated a hundred times at the same horizon —
  // the lesson of `templates_library_name_uq` (008) and `nr_order_library_uq`
  // (013), reapplied.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX change_aftermath_job_uq ' +
      'ON change_aftermath (tenant_id, job_id, horizon_days) WHERE job_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX change_aftermath_intervention_uq ' +
      'ON change_aftermath (tenant_id, intervention_id, horizon_days) ' +
      'WHERE intervention_id IS NOT NULL',
  );
  // Every read path leads with `tenant_id` — decision 6 makes that the ONLY
  // isolation this table has.
  await knex.schema.raw(
    'CREATE INDEX change_aftermath_tenant_time_idx ' +
      'ON change_aftermath (tenant_id, evaluated_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX change_aftermath_device_idx ' +
      'ON change_aftermath (tenant_id, device_id, evaluated_at DESC)',
  );
  // The screen that matters: everything that got worse since a change.
  await knex.schema.raw(
    'CREATE INDEX change_aftermath_degraded_idx ' +
      'ON change_aftermath (tenant_id, evaluated_at DESC) ' +
      "WHERE verdict = 'DEGRADED'",
  );
  // The §8.3 corpus slice, cross-tenant on purpose exactly like
  // `apply_outcomes_corpus_idx`.
  await knex.schema.raw(
    'CREATE INDEX change_aftermath_corpus_idx ' +
      'ON change_aftermath (brand, model, os_version, verdict)',
  );

  await knex.schema.raw(
    'COMMENT ON TABLE change_aftermath IS $$' +
      'F4 (§10): the same device, compared against ITSELF over a long window on ' +
      'both sides of a change. Sibling of apply_outcomes and part of the same §8.3 ' +
      'corpus, hence the absence of foreign keys. The verdict is CORRELATIONAL: it ' +
      'says what happened SINCE the change and never claims the change caused it — ' +
      'shared/src/intervention.ts enforces the wording at runtime.$$',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('change_aftermath');
  await knex.schema.dropTableIfExists('intervention_drift_links');
  await knex.schema.dropTableIfExists('intervention_events');
  await knex.schema.dropTableIfExists('interventions');

  // The claimed rows have to lose the verdict BEFORE the narrower CHECK comes
  // back, or the constraint is rejected against live data and the rollback
  // fails halfway. They become `unattributed` — which is what they were before
  // this feature claimed them, and the honest answer once the window they
  // pointed at no longer exists.
  await knex.raw(
    "UPDATE drift_attributions SET verdict = 'unattributed', reason = 'intervention_rolled_back' " +
      "WHERE verdict = 'intervention'",
  );
  await knex.schema.raw(
    'ALTER TABLE drift_attributions DROP CONSTRAINT IF EXISTS drift_attributions_verdict_chk',
  );
  await knex.schema.raw(
    `ALTER TABLE drift_attributions ADD CONSTRAINT drift_attributions_verdict_chk
       CHECK (verdict IN (${ATTRIBUTION_VERDICTS_ORIGINAL}))`,
  );
}
