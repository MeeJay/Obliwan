import type { Knex } from 'knex';

/**
 * 010_rollouts.ts — M7 / K3: the schema of a WAVE ROLLOUT.
 *
 * Implements §5/M7, §8.3 (the order of the waves) and §8.5 (the subtree
 * interlock). The TypeScript contract these tables carry lives in
 * `shared/src/rollout.ts`; migration 009 forward-declared
 * `change_jobs.rollout_id / wave_index / canary_rank` as bare columns and this
 * migration is where they finally point at something.
 *
 * Migration 009 stored what we did to ONE box. This one stores what we did to
 * a FLEET, in an order we chose, with a gate between each step. The difference
 * is that a mistake here is not one truck, it is a phone call from every
 * customer at once.
 *
 * ┌─ SIX DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ────────────────────┐
 * │                                                                           │
 * │ 1. THE SUBTREE INTERLOCK IS TWO TRIGGERS, NOT A SERVICE CHECK (§8.5).     │
 * │    `rollout_targets_subtree_interlock` refuses to put a concentrator and  │
 * │    one of its children in the same rollout — at COMPOSITION, which is the │
 * │    only moment where refusing is cheap. `change_jobs_subtree_interlock`   │
 * │    refuses, fleet-wide and whatever put them there, an active job on a    │
 * │    concentrator while a job is in flight on one of its children (and the  │
 * │    reverse). §8.5 asks for something "aussi structurel" as 009's          │
 * │    one-job-per-device index; a SELECT followed by an INSERT is not, so    │
 * │    the second trigger takes `pg_advisory_xact_lock` on the concentrator   │
 * │    id first and both writers serialise on the same key.                   │
 * │                                                                           │
 * │ 2. THE BASELINE IS EARLIER THAN THE WAVE, AND IT IS A CHECK CONSTRAINT.   │
 * │    `rollout_targets_baseline_before_chk`: a target that has been queued    │
 * │    (`queued_at IS NOT NULL`) must carry `health_baseline_at <= queued_at`. │
 * │    A gate that compares a device to its own post-change state measures     │
 * │    nothing, and "we take the baseline first" is a sentence in a service    │
 * │    that somebody edits in a hurry. Here the row cannot exist.             │
 * │                                                                           │
 * │ 3. DEGRADED GOES LAST, ENFORCED PER ROW (§8.3).                           │
 * │    `rollout_targets_safety_order` refuses any insert that would put a     │
 * │    device with a weaker net in an EARLIER wave than one with a stronger   │
 * │    net. Two indexed EXISTS per row, symmetric, so insertion order does    │
 * │    not matter. Sending a `degraded` device — no remote recovery at all —  │
 * │    in as the canary is choosing the one failure we cannot undo as our     │
 * │    first experiment.                                                     │
 * │                                                                           │
 * │ 4. ONE ACTIVE ROLLOUT PER DEVICE IS AN INDEX.                             │
 * │    `rollout_targets_one_active_uq` is `UNIQUE (device_id) WHERE status IN │
 * │    ('pending','queued','running')`. `pending` is INSIDE the set on        │
 * │    purpose, exactly as `queued` is inside 009's: two rollouts composed    │
 * │    against the same fleet are two plans against the same world, and the   │
 * │    second describes a world the first will have destroyed. `cancelled`    │
 * │    and `skipped` exist so an abandoned draft RELEASES its devices instead │
 * │    of holding a fleet hostage forever.                                    │
 * │                                                                           │
 * │ 5. A WAVE THAT CANNOT BE EVIDENCE MUST NOT EXIST.                         │
 * │    `rollout_waves_size_chk` forbids `target_count = 0`. `planWaves()`     │
 * │    drops empty checkpoints for the same reason: a gate measured on no     │
 * │    device passes for free, and a gate that passes for free is a gate      │
 * │    somebody will point at afterwards as proof.                           │
 * │                                                                           │
 * │ 6. THE QUARANTINE IS A STATUS FLIP ON AN EXISTING TABLE, NOT A NEW ONE.   │
 * │    `template_revisions.status` already accepts `quarantined` and its      │
 * │    freeze trigger already allows `published -> quarantined` while         │
 * │    refusing everything else (migration 008). M7 adds `rollouts`.          │
 * │    `revision_quarantined_at`, which records WHEN and by WHICH rollout —   │
 * │    a revision that is quarantined with nothing pointing at the rollout    │
 * │    that condemned it is a revision nobody dares un-quarantine.            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * DIVERGENCE FROM THE MILESTONE BRIEF, DELIBERATE AND DECLARED:
 *
 *  - The brief names two tables (`rollouts` / `rollout_waves`); three are
 *    created. A wave is a SET OF DEVICES, and the membership must exist at
 *    composition time — that is precisely when §8.5's interlock has to refuse
 *    the composition, and when the N plans are compiled for the impact screen.
 *    Storing the membership in a jsonb array on `rollout_waves` would put the
 *    interlock, the one-active-rollout rule and the safety ordering out of
 *    reach of every constraint in this file. `rollout_targets` is that table.
 *
 * ENUMS AS TEXT + CHECK, like 002 / 005 / 007 / 008 / 009 — adding a value is
 * one DROP/ADD CONSTRAINT inside a transaction, whereas `ALTER TYPE … ADD
 * VALUE` cannot be reverted.
 *
 * COLUMN WIDTHS were checked against the longest value of each CHECK, which is
 * the mistake §8.5's rename already made once ('concentrator' is 12 characters
 * in a column sized for 'chr'):
 *   status(16)        <- 'rolling_back'  (12)
 *   wave status(16)   <- 'rolled_back'   (11)
 *   target status(16) <- 'rolled_back'   (11)
 *   verdict(16)       <- 'INDETERMINATE' (13)
 *   safety_level(16)  <- 'armed_by_peer' (13)
 *   label(16)         <- 'canary'        (6)
 */

// Inlined literals rather than imports from @obliwan/shared, exactly as 002,
// 005, 007, 008 and 009 do: a migration keeps describing the schema as it was
// on the day it ran. Each list below has a twin in `shared/src/rollout.ts`.

/** `ROLLOUT_STATUSES`. */
const ROLLOUT_STATUSES =
  "'draft','running','paused','rolling_back','succeeded','failed','rolled_back','aborted'";
/** `ACTIVE_ROLLOUT_STATUSES`. */
const ACTIVE_ROLLOUT_STATUSES = "'draft','running','paused','rolling_back'";
/** `TERMINAL_ROLLOUT_STATUSES`. */
const TERMINAL_ROLLOUT_STATUSES = "'succeeded','failed','rolled_back','aborted'";

/** `ROLLOUT_WAVE_STATUSES`. */
const WAVE_STATUSES = "'pending','running','gating','passed','failed','rolled_back','skipped'";
/** `ROLLOUT_TARGET_STATUSES`. */
const TARGET_STATUSES =
  "'pending','queued','running','succeeded','failed','rolled_back','skipped','cancelled'";
/** `ACTIVE_ROLLOUT_TARGET_STATUSES` — decision 4. The predicate of the
 *  one-active-rollout unique index and of nothing else. */
const ACTIVE_TARGET_STATUSES = "'pending','queued','running'";

/** `HEALTH_GATE_VERDICTS`. Uppercase and three-valued, like `GUARD_VERDICTS`:
 *  `INDETERMINATE` is not `PASS`, here as there. */
const GATE_VERDICTS = "'PASS','FAIL','INDETERMINATE'";
/** `GUARD_VERDICTS` (shared/src/change.ts) — copied onto the target row so the
 *  impact screen does not have to join `change_plans` for every device. */
const GUARD_VERDICTS = "'ACCEPT','REJECT','INDETERMINATE'";
/** `SAFETY_LEVELS` (shared/src/device.ts) — §8.3. */
const SAFETY_LEVELS = "'armed','armed_by_peer','degraded'";
/** `RISK_LEVELS` (shared/src/ncm/plan.ts). */
const RISK_LEVELS = "'low','medium','high'";
/** `ROLLOUT_WAVE_PLAN` labels. */
const WAVE_LABELS = "'canary','5%','25%','rest'";

/** `ACTIVE_CHANGE_JOB_STATUSES` (migration 009). Repeated here because
 *  decision 1's trigger is built on exactly the same frontier: a job in one of
 *  these states is a job that holds — or is about to hold — a live dead-man. */
const ACTIVE_JOB_STATUSES =
  "'queued','claimed','backing_up','arming','applying','verifying','soaking','disarming'";

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // rollout_safety_rank — §8.3's ordering, as a function the SQL can use.
  //
  // IMMUTABLE so it may appear in an index expression later; it exists now
  // because decision 3's trigger has to rank two rows and a CASE repeated in
  // two places is a CASE that will diverge.
  // ==========================================================================
  await knex.schema.raw(`
    CREATE FUNCTION rollout_safety_rank(p_level text) RETURNS integer AS $fn$
      SELECT CASE p_level
               WHEN 'armed'         THEN 0
               WHEN 'armed_by_peer' THEN 1
               WHEN 'degraded'      THEN 2
               ELSE 3
             END
    $fn$ LANGUAGE sql IMMUTABLE
  `);
  await knex.schema.raw(
    'COMMENT ON FUNCTION rollout_safety_rank(text) IS $$' +
      'ARCHITECTURE.md 8.3: armed first, degraded last. The wave order of a K3 ' +
      'rollout is sorted on this and nothing else.$$',
  );

  // ==========================================================================
  // rollouts — one template revision, N devices, waves, a gate between them.
  // ==========================================================================
  await knex.schema.createTable('rollouts', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('name', 200).notNullable();
    t.text('description').nullable();

    // WHAT is being rolled out. NOT NULL: a rollout is "push revision R across
    // the fleet in waves", and decision 6's quarantine has nothing to condemn
    // without it. NO ACTION rather than RESTRICT for the same end-of-statement
    // reason as `change_jobs.plan_id` in 009: offboarding a tenant cascades
    // tenants -> templates -> revisions AND tenants -> rollouts in one
    // statement, and RESTRICT would abort on the first row.
    t.bigInteger('template_revision_id').notNullable();

    t.string('status', 16).notNullable().defaultTo('draft');

    // Laid out at composition by `planWaves()`; denormalised so the list screen
    // does not count rows per rollout.
    t.integer('wave_count').notNullable().defaultTo(0);
    t.integer('device_count').notNullable().defaultTo(0);
    t.integer('site_count').notNullable().defaultTo(0);
    // NULL before the launch and after the end. The wave currently running or
    // gating — the number the progress bar reads.
    t.integer('current_wave_index').nullable();

    t.integer('succeeded_count').notNullable().defaultTo(0);
    t.integer('failed_count').notNullable().defaultTo(0);
    t.integer('rolled_back_count').notNullable().defaultTo(0);

    // §8.3's impact screen, aggregated over the N plans compiled BEFORE the
    // launch. Stored so the screen an operator approved can be reproduced
    // afterwards — "what did he actually see" is the first question asked.
    t.jsonb('blast_radius').notNullable().defaultTo(knex.raw("'{}'::jsonb"));

    // Which wave's gate said FAIL. NULL on every other ending.
    t.integer('failed_wave_index').nullable();
    // Decision 6. Set in the same transaction as the `template_revisions`
    // status flip, so "quarantined by nobody" cannot be represented.
    t.timestamp('revision_quarantined_at', { useTz: true }).nullable();

    // Why the train stopped. A pause with no sentence is a pause nobody can
    // resume with any confidence.
    t.text('pause_reason').nullable();
    t.text('abort_reason').nullable();

    // How long the gate waits after the last job of a wave goes terminal
    // before it measures. Per-rollout because a fleet whose poller runs at
    // 300 s needs a longer window than one at 30 s.
    t.integer('gate_settle_ms').notNullable().defaultTo(90000);

    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    // THE signature the automatic rollback of previous waves is attributed to.
    // §8.3 / migration 009 make a non-ACCEPT guard verdict impossible without a
    // named human; a rollback the machine decides on still has to name one, and
    // it names the operator who launched the rollout. He signed for the
    // machinery, including the part that undoes his own change.
    t.integer('started_by').nullable().references('id').inTable('users').onDelete('SET NULL');

    // ── The two signatures §8.3 demands, carried at FLEET scale ───────────
    //
    // Migration 009 makes them impossible to omit on a single job: a non-ACCEPT
    // guard verdict needs `override_reason` + `overridden_by`, and a `degraded`
    // write needs `degraded_confirmed_by`. A rollout composes N such jobs at
    // once, so it collects the two signatures ONCE, at composition, in front of
    // the impact screen that shows how many devices each of them applies to —
    // "12 of these 40 devices have NO remote recovery" is a sentence somebody
    // must read before signing, and it does not exist on a per-job dialog.
    //
    // These columns do not REPLACE the per-job constraints; every job the
    // rollout queues still carries its own signature, copied from here.
    t.text('override_reason').nullable();
    t.integer('overridden_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('overridden_at', { useTz: true }).nullable();
    t.integer('degraded_confirmed_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('degraded_confirmed_at', { useTz: true }).nullable();
    t.timestamp('started_at', { useTz: true }).nullable();
    t.timestamp('finished_at', { useTz: true }).nullable();
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE rollouts ADD CONSTRAINT rollouts_revision_fk ' +
      'FOREIGN KEY (template_revision_id) REFERENCES template_revisions (id)',
  );
  await knex.schema.raw(
    `ALTER TABLE rollouts ADD CONSTRAINT rollouts_status_chk
       CHECK (status IN (${ROLLOUT_STATUSES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE rollouts ADD CONSTRAINT rollouts_counts_chk CHECK (' +
      'wave_count >= 0 AND device_count >= 0 AND site_count >= 0 AND ' +
      'succeeded_count >= 0 AND failed_count >= 0 AND rolled_back_count >= 0 AND ' +
      'succeeded_count <= device_count AND failed_count <= device_count AND ' +
      'rolled_back_count <= device_count)',
  );
  await knex.schema.raw(
    'ALTER TABLE rollouts ADD CONSTRAINT rollouts_wave_index_chk CHECK (' +
      '(current_wave_index IS NULL OR (current_wave_index >= 0 AND current_wave_index < wave_count)) ' +
      'AND (failed_wave_index IS NULL OR (failed_wave_index >= 0 AND failed_wave_index < wave_count)))',
  );
  await knex.schema.raw(
    "ALTER TABLE rollouts ADD CONSTRAINT rollouts_shape_chk CHECK (" +
      "btrim(name) <> '' AND jsonb_typeof(blast_radius) = 'object' AND gate_settle_ms >= 0)",
  );
  // A rollout that is running has been started BY somebody, AT some instant.
  // Both, or neither: "the fleet started changing and we do not know when" is
  // the sentence this constraint exists to make unrepresentable.
  await knex.schema.raw(
    `ALTER TABLE rollouts ADD CONSTRAINT rollouts_started_chk CHECK (
       status IN ('draft','aborted') OR (started_at IS NOT NULL AND started_by IS NOT NULL))`,
  );
  await knex.schema.raw(
    `ALTER TABLE rollouts ADD CONSTRAINT rollouts_finished_chk CHECK (
       (status IN (${TERMINAL_ROLLOUT_STATUSES})) = (finished_at IS NOT NULL))`,
  );
  // A named wave, or none. `failed_wave_index` set on a rollout that succeeded
  // would be a contradiction printed on the incident report.
  await knex.schema.raw(
    `ALTER TABLE rollouts ADD CONSTRAINT rollouts_failed_wave_chk CHECK (
       failed_wave_index IS NULL OR status IN ('rolling_back','failed','rolled_back','aborted','paused'))`,
  );

  // A signature is a name, an instant and a sentence, or it is not a signature.
  // Same shape as `change_jobs_override_chk` (009, decision 3), one level up.
  await knex.schema.raw(
    'ALTER TABLE rollouts ADD CONSTRAINT rollouts_override_chk CHECK (' +
      'override_reason IS NULL OR ' +
      "(btrim(override_reason) <> '' AND overridden_by IS NOT NULL AND overridden_at IS NOT NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE rollouts ADD CONSTRAINT rollouts_degraded_chk ' +
      'CHECK ((degraded_confirmed_by IS NULL) = (degraded_confirmed_at IS NULL))',
  );

  await knex.schema.raw(
    'CREATE INDEX rollouts_tenant_time_idx ON rollouts (tenant_id, created_at DESC)',
  );
  // The driver's query, and the only one it runs per tick: "rollouts of this
  // instance that still have work to do".
  await knex.schema.raw(
    `CREATE INDEX rollouts_active_idx ON rollouts (tenant_id, status)
       WHERE status IN (${ACTIVE_ROLLOUT_STATUSES})`,
  );
  await knex.schema.raw(
    'CREATE INDEX rollouts_revision_idx ON rollouts (template_revision_id)',
  );

  // ==========================================================================
  // rollout_waves — the ordered steps, and the gate verdict of each.
  // ==========================================================================
  await knex.schema.createTable('rollout_waves', (t) => {
    t.bigIncrements('id').primary();
    t.bigInteger('rollout_id').notNullable()
      .references('id').inTable('rollouts').onDelete('CASCADE');
    // Denormalised so every read index starts with the tenant. Overwritten from
    // the parent by a BEFORE INSERT trigger — a caller that omits it gets the
    // right value, a caller that lies gets corrected. Same pattern as
    // `change_job_steps.tenant_id` (migration 009).
    t.integer('tenant_id').notNullable().defaultTo(0);

    t.integer('wave_index').notNullable();
    t.string('label', 16).notNullable();
    t.integer('target_count').notNullable();
    t.string('status', 16).notNullable().defaultTo('pending');

    t.integer('succeeded_count').notNullable().defaultTo(0);
    t.integer('failed_count').notNullable().defaultTo(0);

    // NULL until the gate has run. `INDETERMINATE` is a real answer and is
    // stored as one: it is why the rollout paused, and a NULL there would read
    // as "the gate never ran", which is a different night.
    t.string('gate_verdict', 16).nullable();
    // `HealthGateReason[]` — the comparison, not the conclusion. "We stopped"
    // is useless; "ether3 went from 0 to 412 input errors while up" is not.
    t.jsonb('gate_reasons').notNullable().defaultTo(knex.raw("'[]'::jsonb"));

    t.timestamp('started_at', { useTz: true }).nullable();
    // When every job of the wave went terminal and the settle window opened.
    t.timestamp('gate_started_at', { useTz: true }).nullable();
    t.timestamp('finished_at', { useTz: true }).nullable();
    t.timestamps(true, true);

    t.unique(['rollout_id', 'wave_index'], { indexName: 'rollout_waves_index_uq' });
  });

  await knex.schema.raw(
    `ALTER TABLE rollout_waves ADD CONSTRAINT rollout_waves_status_chk
       CHECK (status IN (${WAVE_STATUSES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE rollout_waves ADD CONSTRAINT rollout_waves_label_chk
       CHECK (label IN (${WAVE_LABELS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE rollout_waves ADD CONSTRAINT rollout_waves_gate_chk
       CHECK (gate_verdict IS NULL OR gate_verdict IN (${GATE_VERDICTS}))`,
  );
  // ── Decision 5 ────────────────────────────────────────────────────────────
  // A wave with no device in it is a gate that passes for free.
  await knex.schema.raw(
    'ALTER TABLE rollout_waves ADD CONSTRAINT rollout_waves_size_chk CHECK (' +
      'wave_index >= 0 AND target_count > 0 AND succeeded_count >= 0 AND failed_count >= 0 AND ' +
      'succeeded_count + failed_count <= target_count)',
  );
  await knex.schema.raw(
    "ALTER TABLE rollout_waves ADD CONSTRAINT rollout_waves_reasons_chk " +
      "CHECK (jsonb_typeof(gate_reasons) = 'array')",
  );
  // A verdict is the OUTPUT of a gate; a gate that never started cannot have
  // produced one.
  await knex.schema.raw(
    'ALTER TABLE rollout_waves ADD CONSTRAINT rollout_waves_verdict_needs_gate_chk ' +
      'CHECK (gate_verdict IS NULL OR gate_started_at IS NOT NULL)',
  );

  await knex.schema.raw(
    'CREATE INDEX rollout_waves_rollout_idx ON rollout_waves (rollout_id, wave_index)',
  );
  await knex.schema.raw(
    'CREATE INDEX rollout_waves_tenant_idx ON rollout_waves (tenant_id, rollout_id)',
  );

  // ==========================================================================
  // rollout_targets — one device inside one wave.
  //
  // This is the table §8.5's interlock, §8.3's ordering and trap 1's baseline
  // all live on. It exists because those three rules are RELATIONS BETWEEN
  // DEVICES, and a jsonb array of device ids is out of reach of every
  // constraint in this file.
  // ==========================================================================
  await knex.schema.createTable('rollout_targets', (t) => {
    t.bigIncrements('id').primary();
    t.bigInteger('rollout_id').notNullable()
      .references('id').inTable('rollouts').onDelete('CASCADE');
    t.bigInteger('wave_id').notNullable()
      .references('id').inTable('rollout_waves').onDelete('CASCADE');
    t.integer('tenant_id').notNullable().defaultTo(0);

    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    // Denormalised from `rollout_waves`: decision 3's trigger compares wave
    // positions on every insert and must not join to do it.
    t.integer('wave_index').notNullable();
    // Position inside the wave, from `orderForWaves`. Copied onto
    // `change_jobs.canary_rank` when the job is queued, so the queue's own
    // trace carries the order the operator was shown.
    t.integer('order_rank').notNullable().defaultTo(0);

    t.string('status', 16).notNullable().defaultTo('pending');

    // ── §8.3, computed at composition and SHOWN before the launch ─────────
    t.string('safety_level', 16).notNullable();
    t.integer('safety_peer_device_id').nullable()
      .references('id').inTable('devices').onDelete('SET NULL');

    // ── The plan compiled BEFORE the launch (the impact screen) ───────────
    // The full `ApplyPlan` envelope, REDACTED (§8.2 — a secret never transits
    // through a PlanOp value). It is EVIDENCE of what the operator approved.
    // The plan actually pushed is recompiled against the pinned revision when
    // the wave starts, because a plan is perishable and wave 4 may run an hour
    // after wave 1 — but the two are compared, and a device whose world moved
    // is reported, never silently re-planned.
    t.jsonb('plan_envelope').nullable();
    t.integer('plan_ops_count').notNullable().defaultTo(0);
    t.string('risk_level', 8).notNullable().defaultTo('low');
    t.string('guard_verdict', 16).nullable();

    // ── The job. No FK: `change_jobs` rows outlive a rollout's deletion, and
    //    a rollout removed for tidiness must not take the queue's trace with
    //    it. Same reasoning as 009's decision 5, one table further out.
    t.bigInteger('job_id').nullable();
    t.timestamp('queued_at', { useTz: true }).nullable();

    // ── Trap 1: the baseline, captured BEFORE the wave is queued ──────────
    // `HealthBaseline`. Written once, read once, by the gate for this wave.
    t.jsonb('health_baseline').nullable();
    t.timestamp('health_baseline_at', { useTz: true }).nullable();
    t.string('health_verdict', 16).nullable();
    t.jsonb('health_reasons').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.timestamp('health_checked_at', { useTz: true }).nullable();

    // ── The undo ──────────────────────────────────────────────────────────
    // The `restore` job queued for this device when an later wave's gate said
    // FAIL, and the pre-change backup it is meant to load.
    t.bigInteger('rollback_job_id').nullable();
    t.bigInteger('rollback_backup_id').nullable();

    t.text('note').nullable();
    t.timestamps(true, true);

    t.unique(['rollout_id', 'device_id'], { indexName: 'rollout_targets_device_uq' });
  });

  await knex.schema.raw(
    `ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_status_chk
       CHECK (status IN (${TARGET_STATUSES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_safety_chk
       CHECK (safety_level IN (${SAFETY_LEVELS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_risk_chk
       CHECK (risk_level IN (${RISK_LEVELS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_guard_chk
       CHECK (guard_verdict IS NULL OR guard_verdict IN (${GUARD_VERDICTS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_health_chk
       CHECK (health_verdict IS NULL OR health_verdict IN (${GATE_VERDICTS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_shape_chk CHECK (' +
      'wave_index >= 0 AND order_rank >= 0 AND plan_ops_count >= 0 AND ' +
      "jsonb_typeof(health_reasons) = 'array' AND " +
      "(plan_envelope IS NULL OR jsonb_typeof(plan_envelope) = 'object') AND " +
      "(health_baseline IS NULL OR jsonb_typeof(health_baseline) = 'object'))",
  );
  // §8.3 / migration 009's `change_plans_peer_chk`, restated one level up: a
  // level that names no peer is a net drawn on a slide.
  await knex.schema.raw(
    'ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_peer_chk CHECK (' +
      "(safety_level = 'armed_by_peer') = (safety_peer_device_id IS NOT NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_peer_not_self_chk ' +
      'CHECK (safety_peer_device_id IS NULL OR safety_peer_device_id <> device_id)',
  );
  await knex.schema.raw(
    'ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_baseline_pair_chk ' +
      'CHECK ((health_baseline IS NULL) = (health_baseline_at IS NULL))',
  );

  // ── DECISION 2 — TRAP 1, AS A CONSTRAINT ─────────────────────────────────
  //
  // The baseline is taken BEFORE the wave. Not "the service takes it first":
  // a target that has been queued without one, or with one captured after the
  // job was queued, CANNOT EXIST. A gate that compares a device to its own
  // post-change state measures nothing at all, and it is the kind of bug that
  // passes every test written by the person who introduced it.
  await knex.schema.raw(
    'ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_baseline_before_chk CHECK (' +
      'queued_at IS NULL OR ' +
      '(health_baseline_at IS NOT NULL AND health_baseline_at <= queued_at))',
  );
  // A queued target names its job, and a target that names a job has been
  // queued. Neither half is informative alone.
  await knex.schema.raw(
    'ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_job_chk ' +
      'CHECK ((job_id IS NULL) = (queued_at IS NULL))',
  );
  // A health verdict is the output of a check; a check that never ran cannot
  // have produced one.
  await knex.schema.raw(
    'ALTER TABLE rollout_targets ADD CONSTRAINT rollout_targets_verdict_chk ' +
      'CHECK ((health_verdict IS NULL) = (health_checked_at IS NULL))',
  );

  // ── DECISION 4 — one active rollout per device ────────────────────────────
  await knex.schema.raw(
    `CREATE UNIQUE INDEX rollout_targets_one_active_uq ON rollout_targets (device_id)
       WHERE status IN (${ACTIVE_TARGET_STATUSES})`,
  );

  await knex.schema.raw(
    'CREATE INDEX rollout_targets_wave_idx ON rollout_targets (rollout_id, wave_index, order_rank)',
  );
  await knex.schema.raw(
    'CREATE INDEX rollout_targets_tenant_idx ON rollout_targets (tenant_id, rollout_id)',
  );
  await knex.schema.raw(
    'CREATE INDEX rollout_targets_device_idx ON rollout_targets (device_id, created_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX rollout_targets_job_idx ON rollout_targets (job_id) WHERE job_id IS NOT NULL',
  );

  // ==========================================================================
  // The tenant sync triggers — same pattern as change_job_steps (009).
  // ==========================================================================
  await knex.schema.raw(`
    CREATE FUNCTION rollout_children_sync_tenant() RETURNS trigger AS $fn$
    DECLARE parent_tenant integer;
    BEGIN
      SELECT tenant_id INTO parent_tenant FROM rollouts WHERE id = NEW.rollout_id;
      NEW.tenant_id := parent_tenant;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER rollout_waves_tenant_sync
      BEFORE INSERT OR UPDATE OF rollout_id ON rollout_waves
      FOR EACH ROW EXECUTE FUNCTION rollout_children_sync_tenant()
  `);
  await knex.schema.raw(`
    CREATE TRIGGER rollout_targets_10_tenant_sync
      BEFORE INSERT OR UPDATE OF rollout_id ON rollout_targets
      FOR EACH ROW EXECUTE FUNCTION rollout_children_sync_tenant()
  `);

  // A target must belong to a wave OF ITS OWN ROLLOUT, and its denormalised
  // `wave_index` must be that wave's. Without this, decision 3's ordering and
  // the whole progress display are computed from a number nobody checked.
  await knex.schema.raw(`
    CREATE FUNCTION rollout_targets_wave_coherent() RETURNS trigger AS $fn$
    DECLARE w RECORD;
    BEGIN
      SELECT rollout_id, wave_index INTO w FROM rollout_waves WHERE id = NEW.wave_id;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'rollout_targets.wave_id % does not exist', NEW.wave_id
          USING ERRCODE = 'foreign_key_violation';
      END IF;
      IF w.rollout_id <> NEW.rollout_id THEN
        RAISE EXCEPTION
          'rollout_targets: wave % belongs to rollout %, not to rollout %',
          NEW.wave_id, w.rollout_id, NEW.rollout_id
          USING ERRCODE = 'restrict_violation';
      END IF;
      NEW.wave_index := w.wave_index;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER rollout_targets_20_wave_coherent
      BEFORE INSERT OR UPDATE OF wave_id, rollout_id ON rollout_targets
      FOR EACH ROW EXECUTE FUNCTION rollout_targets_wave_coherent()
  `);

  // ==========================================================================
  // ── DECISION 1, HALF ONE — §8.5's interlock at COMPOSITION ────────────────
  //
  // A concentrator and one of its children never share a rollout. The refusal
  // happens here, at the only moment where it costs nothing: §8.5 says
  // "Refuse la composition du rollout, ne la répare pas en cours de route".
  //
  // Both directions are checked, so the insertion order does not matter — the
  // child may arrive before the concentrator or after it.
  // ==========================================================================
  await knex.schema.raw(`
    CREATE FUNCTION rollout_targets_subtree_interlock() RETURNS trigger AS $fn$
    DECLARE
      my_role   text;
      my_parent integer;
      clash     integer;
    BEGIN
      SELECT role, concentrator_id INTO my_role, my_parent
        FROM devices WHERE id = NEW.device_id;

      IF my_role = 'concentrator' THEN
        SELECT t.device_id INTO clash
          FROM rollout_targets t
          JOIN devices d ON d.id = t.device_id
         WHERE t.rollout_id = NEW.rollout_id
           AND t.id IS DISTINCT FROM NEW.id
           AND d.concentrator_id = NEW.device_id
         LIMIT 1;
        IF clash IS NOT NULL THEN
          RAISE EXCEPTION
            'subtree interlock: concentrator % and its child % cannot be in the same rollout (ARCHITECTURE.md 8.5)',
            NEW.device_id, clash
            USING ERRCODE = 'restrict_violation';
        END IF;
      END IF;

      IF my_parent IS NOT NULL THEN
        SELECT t.device_id INTO clash
          FROM rollout_targets t
         WHERE t.rollout_id = NEW.rollout_id
           AND t.id IS DISTINCT FROM NEW.id
           AND t.device_id = my_parent
         LIMIT 1;
        IF clash IS NOT NULL THEN
          RAISE EXCEPTION
            'subtree interlock: device % and its concentrator % cannot be in the same rollout (ARCHITECTURE.md 8.5)',
            NEW.device_id, clash
            USING ERRCODE = 'restrict_violation';
        END IF;
      END IF;

      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER rollout_targets_30_subtree_interlock
      BEFORE INSERT OR UPDATE OF device_id, rollout_id ON rollout_targets
      FOR EACH ROW EXECUTE FUNCTION rollout_targets_subtree_interlock()
  `);

  // ==========================================================================
  // ── DECISION 3 — §8.3's order, per row ────────────────────────────────────
  //
  // No device with a weaker net may sit in an earlier wave than one with a
  // stronger net. Two EXISTS, symmetric, both served by
  // `rollout_targets_wave_idx`, so the rule holds whatever order the rows are
  // written in and costs an index probe rather than a self-join.
  // ==========================================================================
  await knex.schema.raw(`
    CREATE FUNCTION rollout_targets_safety_order() RETURNS trigger AS $fn$
    DECLARE
      my_rank integer := rollout_safety_rank(NEW.safety_level);
      clash   RECORD;
    BEGIN
      SELECT t.device_id, t.wave_index, t.safety_level INTO clash
        FROM rollout_targets t
       WHERE t.rollout_id = NEW.rollout_id
         AND t.id IS DISTINCT FROM NEW.id
         AND ((t.wave_index > NEW.wave_index
               AND rollout_safety_rank(t.safety_level) < my_rank)
           OR (t.wave_index < NEW.wave_index
               AND rollout_safety_rank(t.safety_level) > my_rank))
       LIMIT 1;

      IF FOUND THEN
        RAISE EXCEPTION
          'wave order (ARCHITECTURE.md 8.3): device % (%, wave %) cannot be ordered against device % (%, wave %) - the weaker safety net must go LAST',
          NEW.device_id, NEW.safety_level, NEW.wave_index,
          clash.device_id, clash.safety_level, clash.wave_index
          USING ERRCODE = 'restrict_violation';
      END IF;

      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER rollout_targets_40_safety_order
      BEFORE INSERT OR UPDATE OF safety_level, wave_index, wave_id ON rollout_targets
      FOR EACH ROW EXECUTE FUNCTION rollout_targets_safety_order()
  `);

  // ==========================================================================
  // change_jobs — the forward declaration of 009 finally points somewhere.
  // ==========================================================================
  //
  // NO ACTION (the default), for the same end-of-statement reason 009 gives
  // for `plan_id`: a tenant offboarding cascades to BOTH tables in one
  // statement and must succeed, while a bare `DELETE FROM rollouts WHERE id=X`
  // that a job still points at must fail.
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_rollout_fk ' +
      'FOREIGN KEY (rollout_id) REFERENCES rollouts (id)',
  );
  // `change_jobs_rollout_chk` (009) already ties `rollout_id` and `wave_index`
  // together. `canary_rank` is the third of the trio and had no constraint at
  // all: a rank without a wave is a position in nothing.
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_canary_rank_chk CHECK (' +
      'canary_rank IS NULL OR (rollout_id IS NOT NULL AND canary_rank >= 0))',
  );

  // ==========================================================================
  // ── DECISION 1, HALF TWO — §8.5's interlock ON THE QUEUE ──────────────────
  //
  // "Un job visant un concentrateur exige qu'aucun job ne soit en vol sur ses
  // enfants, et bloque la mise en file de nouveaux jobs enfants pendant toute
  // sa durée. Réciproquement, un job enfant ne démarre pas si un job
  // concentrateur est actif sur son parent. […] il doit être aussi structurel
  // que [l'index un-job-en-vol-par-device]."
  //
  // A SELECT followed by an INSERT is not structural: two workers, two API
  // calls or one impatient double-click fit in the gap between them. So the
  // FIRST thing this trigger does is take a transaction-scoped advisory lock
  // KEYED ON THE CONCENTRATOR — the parent's job and the child's job compute
  // the same key and therefore serialise against each other. The window closes.
  //
  // 0x4F57 = 'OW', the same namespace `leaderElection` uses for its own lock;
  // the second key is the concentrator's device id, so two different subtrees
  // never wait on each other.
  //
  // This trigger is fleet-wide and knows nothing about rollouts: the danger is
  // "a dead-man that cannot be disarmed", and that danger exists whether the
  // two jobs came from one rollout, from two rollouts, or from two people
  // clicking Apply.
  // ==========================================================================
  await knex.schema.raw(`
    CREATE FUNCTION change_jobs_subtree_interlock() RETURNS trigger AS $fn$
    DECLARE
      my_role   text;
      my_parent integer;
      clash     bigint;
      clash_dev integer;
    BEGIN
      IF NEW.status NOT IN (${ACTIVE_JOB_STATUSES}) THEN
        RETURN NEW;
      END IF;
      -- An UPDATE that merely walks the state machine on a job that was
      -- already active has nothing new to serialise: the pair was legal when
      -- the job was queued and no third job can have slipped in since without
      -- passing through this same trigger.
      IF TG_OP = 'UPDATE' AND OLD.status IN (${ACTIVE_JOB_STATUSES})
         AND OLD.device_id = NEW.device_id THEN
        RETURN NEW;
      END IF;

      SELECT role, concentrator_id INTO my_role, my_parent
        FROM devices WHERE id = NEW.device_id;

      IF my_role = 'concentrator' THEN
        PERFORM pg_advisory_xact_lock(20311, NEW.device_id);
        SELECT j.id, j.device_id INTO clash, clash_dev
          FROM change_jobs j
          JOIN devices d ON d.id = j.device_id
         WHERE d.concentrator_id = NEW.device_id
           AND j.status IN (${ACTIVE_JOB_STATUSES})
           AND j.id IS DISTINCT FROM NEW.id
         LIMIT 1;
        IF clash IS NOT NULL THEN
          RAISE EXCEPTION
            'subtree interlock (ARCHITECTURE.md 8.5): job % is in flight on device %, a child of concentrator %. A concentrator job cannot run while its children hold armed dead-men.',
            clash, clash_dev, NEW.device_id
            USING ERRCODE = 'restrict_violation';
        END IF;
      ELSIF my_parent IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(20311, my_parent);
        SELECT j.id INTO clash
          FROM change_jobs j
         WHERE j.device_id = my_parent
           AND j.status IN (${ACTIVE_JOB_STATUSES})
           AND j.id IS DISTINCT FROM NEW.id
         LIMIT 1;
        IF clash IS NOT NULL THEN
          RAISE EXCEPTION
            'subtree interlock (ARCHITECTURE.md 8.5): job % is in flight on concentrator %, which carries the tunnel to device %. A child job cannot start while its concentrator is being written to.',
            clash, my_parent, NEW.device_id
            USING ERRCODE = 'restrict_violation';
        END IF;
      END IF;

      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER change_jobs_subtree_interlock
      BEFORE INSERT OR UPDATE OF status, device_id ON change_jobs
      FOR EACH ROW EXECUTE FUNCTION change_jobs_subtree_interlock()
  `);

  // ── Table comments: the one-line version, readable from psql ─────────────
  await knex.schema.raw(
    'COMMENT ON TABLE rollouts IS $$' +
      'K3 (M7): one template revision pushed across a fleet in canary waves ' +
      '(1 -> 5% -> 25% -> rest) with a health gate measured BETWEEN waves. A ' +
      'failed gate rolls the previous waves back and quarantines the revision.$$',
  );
  await knex.schema.raw(
    'COMMENT ON TABLE rollout_targets IS $$' +
      'One device in one wave. Carries the pre-wave health baseline ' +
      '(rollout_targets_baseline_before_chk makes "baseline after the change" ' +
      'unrepresentable), the ARCHITECTURE.md 8.3 safety level that orders the ' +
      'waves, and the 8.5 subtree interlock that refuses a concentrator and its ' +
      'children in one rollout.$$',
  );
  await knex.schema.raw(
    'COMMENT ON FUNCTION change_jobs_subtree_interlock() IS $$' +
      'ARCHITECTURE.md 8.5: never a job on a concentrator while a job is in ' +
      'flight on one of its children, nor the reverse. Takes an advisory lock ' +
      'on the concentrator id first, so the check has no gap to race through.$$',
  );
}

export async function down(knex: Knex): Promise<void> {
  // The additions to `change_jobs` go first: they are the only things in this
  // migration that live on a table 009 owns, and leaving either behind would
  // make the next `migrate:latest` fail on CREATE TRIGGER / ADD CONSTRAINT.
  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS change_jobs_subtree_interlock ON change_jobs',
  );
  await knex.schema.raw('DROP FUNCTION IF EXISTS change_jobs_subtree_interlock()');
  await knex.schema.raw(
    'ALTER TABLE IF EXISTS change_jobs DROP CONSTRAINT IF EXISTS change_jobs_canary_rank_chk',
  );
  await knex.schema.raw(
    'ALTER TABLE IF EXISTS change_jobs DROP CONSTRAINT IF EXISTS change_jobs_rollout_fk',
  );

  // The three forward-declared columns of 009 are RELEASED, not left dangling.
  //
  // Found by rolling this migration back and forward again on a database that
  // had actually run a rollout: `rollouts` is dropped here, so every
  // `change_jobs.rollout_id` still carrying a value points at a row that no
  // longer exists — and the NEXT `migrate:latest` fails on
  // `change_jobs_rollout_fk` with rows nobody can find or fix, because the
  // table they referenced is gone. A `down()` that cannot be followed by an
  // `up()` is not a `down()`.
  //
  // All three are nulled together because `change_jobs_rollout_chk` (009) ties
  // `rollout_id` to `wave_index`, and `change_jobs_canary_rank_chk` (above)
  // ties `canary_rank` to both. The jobs themselves are untouched: what is
  // lost is which wave of which rollout they belonged to, and that history
  // died with the `rollouts` table one statement later.
  await knex.schema.raw(
    'UPDATE change_jobs SET rollout_id = NULL, wave_index = NULL, canary_rank = NULL ' +
      'WHERE rollout_id IS NOT NULL OR wave_index IS NOT NULL OR canary_rank IS NOT NULL',
  );

  await knex.schema.dropTableIfExists('rollout_targets');
  await knex.schema.dropTableIfExists('rollout_waves');
  await knex.schema.dropTableIfExists('rollouts');

  // Triggers are dropped with their tables; the FUNCTIONS are not, and a
  // leftover function makes the next `migrate:latest` fail on CREATE FUNCTION.
  await knex.schema.raw('DROP FUNCTION IF EXISTS rollout_targets_safety_order()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS rollout_targets_subtree_interlock()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS rollout_targets_wave_coherent()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS rollout_children_sync_tenant()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS rollout_safety_rank(text)');
}
