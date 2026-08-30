import type { Knex } from 'knex';

/**
 * 009_change.ts — M6 part 1: the schema of the SAFE WRITE.
 *
 * Implements section 3.5 of ARCHITECTURE.md (the `change_plans` … `command_audit`
 * block), decision D3, risks R1 / R4 / R9 / R10, and sections 8.2 / 8.3. The
 * TypeScript contract these tables carry lives in `shared/src/change.ts`.
 *
 * This is the first migration whose tables describe an ACTION ON SOMEBODY
 * ELSE'S HARDWARE. Everything before it stored what we observed; from here on
 * we store what we did. The difference is a truck.
 *
 * ┌─ SEVEN DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ──────────────────┐
 * │                                                                           │
 * │ 1. ONE JOB IN FLIGHT PER DEVICE IS AN INDEX, NOT A SERVICE CHECK.         │
 * │    `change_jobs_one_in_flight_uq` is `UNIQUE (device_id) WHERE status IN  │
 * │    (the eight active states)`. A `SELECT … WHERE status = 'queued'`       │
 * │    followed by an INSERT is two statements with a gap between them, and   │
 * │    two workers, two API calls or one impatient double-click fit in that   │
 * │    gap. The index has no gap. `queued` is INSIDE the active set on        │
 * │    purpose: two plans stacked against the same `base_state_hash` means    │
 * │    the second describes a world the first already destroyed.              │
 * │                                                                           │
 * │ 2. THE PRE-CHANGE BACKUP IS A CHECK CONSTRAINT (R1).                      │
 * │    `change_jobs_preflight_backup_chk` makes it IMPOSSIBLE to represent a  │
 * │    write job that has reached `arming` or beyond without a                │
 * │    `preflight_backup_id`. Not "the service takes a backup first" — the    │
 * │    row cannot exist. The whole rollback story of R1 rests on that backup  │
 * │    being there, and services are edited by people in a hurry.             │
 * │                                                                           │
 * │ 3. AN OVERRIDE LEAVES EVIDENCE, AND `INDETERMINATE` IS NOT `ACCEPT`.      │
 * │    `change_jobs_override_chk`: a job whose `guard_verdict` is anything    │
 * │    other than `ACCEPT` must carry `override_reason` + `overridden_by` +   │
 * │    `overridden_at`. The destructive acceptance test of M6 — force the     │
 * │    `chain=input drop` past the guard — therefore cannot be run without    │
 * │    naming a human in the database. `INDETERMINATE` sits on the same side  │
 * │    of that constraint as `REJECT`: a guard that could not conclude has    │
 * │    not concluded in our favour.                                           │
 * │                                                                           │
 * │ 4. A CLAIMED SAFETY LEVEL MUST BE A LEVEL THAT EXISTS (§8.3).             │
 * │    `armed_by_peer` without `safety_peer_device_id` is a net drawn on a    │
 * │    slide, so the CHECK is an equivalence, not an implication: the peer    │
 * │    column is non-null exactly when the level is `armed_by_peer`.          │
 * │    `degraded` on a WRITE job requires `degraded_confirmed_by` — §8.3's    │
 * │    "confirmation explicite exigée" is a NOT NULL, not a checkbox. On a    │
 * │    read-only job (`export`, `backup`) no confirmation is asked, because   │
 * │    reading a box cannot lock you out of it.                               │
 * │                                                                           │
 * │ 5. `command_audit` AND `apply_outcomes` CARRY NO FOREIGN KEYS AT ALL.     │
 * │    An audit row must survive the deletion of everything it refers to, and │
 * │    must never be MUTATED by a cascade — and a foreign key is precisely a  │
 * │    mechanism for deleting or mutating a row when its parent moves. So     │
 * │    `device_id`, `user_id`, `job_id` and `tenant_id` are bare columns next │
 * │    to a denormalised `device_uuid` / `username`, and                      │
 * │    `command_audit_append_only` refuses every UPDATE. §8.3's empirical     │
 * │    corpus follows the same rule for a different reason: it is built by    │
 * │    the whole fleet across clients, and offboarding one client must not    │
 * │    delete the evidence that a Vigor 2927 on 4.4.x rolls back one time in  │
 * │    four.                                                                  │
 * │                                                                           │
 * │ 6. THE KILL SWITCH FAILS CLOSED AND IS ONE FUNCTION CALL.                 │
 * │    `kill_switch_blocks(tenant)` returns `true` when the GLOBAL ROW IS     │
 * │    MISSING. A switch that fails open is not a switch. The global row is   │
 * │    seeded here, disengaged, so the panic gesture is an UPDATE of a row    │
 * │    that always exists — nobody has to get an INSERT right at 3 a.m. — and │
 * │    `kill_switch_protect_global` refuses to let that row be deleted.       │
 * │                                                                           │
 * │ 7. NOTHING IN THESE TABLES HOLDS A SECRET (§8.2 / R10).                   │
 * │    Every column that can hold device output is named `*_redacted`, so a   │
 * │    developer about to write an unmasked command into `command_audit`      │
 * │    has to type the word "redacted" while doing it. `change_plans.ops` and │
 * │    `.rendered` are the MASKED plan; the complete rendered config exists   │
 * │    in memory only, on the vault -> equipment path, and                    │
 * │    `device_backups.encryption_password_enc` is a `secretVault` blob and   │
 * │    never a password.                                                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * DIVERGENCES FROM §3.5 AND FROM THE MILESTONE BRIEF, DELIBERATE AND DECLARED:
 *
 *  - §3.5's `change_jobs.status` union is `queued|awaiting_approval|running|
 *    awaiting_confirm|soaking|succeeded|failed|rolled_back|aborted`. The brief's
 *    finer union is implemented instead, and it is the right one: `running`
 *    cannot tell a crash-recovery routine whether the box was written to, and
 *    that single question decides between "requeue" and "never touch this
 *    again". `backing_up` / `arming` are recoverable, `applying` onwards is not.
 *    `awaiting_approval` is NOT a job state here: four-eyes (`change_approvals`,
 *    §3.5) gates the CREATION of the job, so an unapproved change is a plan, not
 *    a queued job holding a device lock. That table is out of this migration's
 *    scope and is a declared gap, not an omission.
 *
 *  - `change_plans` is created here although the brief lists six tables and not
 *    this one. `change_jobs.plan_id` and decision D3's "plan figé" are
 *    meaningless without a frozen plan to point at, no earlier migration
 *    created the table, and the planner (M5) currently compiles plans it throws
 *    away. Freezing the plan is half of D3; it ships with the other half.
 *
 *  - `device_backups.trigger` is spelled `trigger_kind`. `TRIGGER` is a SQL
 *    keyword; the day somebody writes an unquoted query by hand is the day it
 *    matters, and it will be during an incident.
 *
 *  - `rollout_id` / `wave_index` / `canary_rank` are bare nullable columns with
 *    NO foreign key, exactly as 007 forward-declared `drift_runs.render_id`.
 *    M7 owns `rollouts`; adding the constraint later is one ALTER, whereas
 *    forward-declaring the table here would put M7's schema in M6's migration.
 *
 * ENUMS AS TEXT + CHECK, like 002 / 005 / 007 / 008 — adding a value is one
 * DROP/ADD CONSTRAINT inside a transaction, whereas `ALTER TYPE … ADD VALUE`
 * cannot be reverted.
 */

// Inlined literals rather than imports from @obliwan/shared, exactly as 002,
// 005, 007 and 008 do: a migration must keep describing the schema as it was on
// the day it ran, whatever the shared package does later. Each list below has a
// twin in `shared/src/change.ts`; the twin is the one the code reads.

/** `shared/src/change.ts` → `CHANGE_JOB_KINDS`. */
const JOB_KINDS = "'push','export','backup','restore','reboot','firmware'";
/** `WRITE_JOB_KINDS` — the kinds that modify the box. Decisions 2 and 4 key off
 *  this list, so it appears verbatim inside two CHECK constraints. */
const WRITE_KINDS = "'push','restore','reboot','firmware'";

/** `CHANGE_JOB_STATUSES`. */
const JOB_STATUSES =
  "'queued','claimed','backing_up','arming','applying','verifying','soaking'," +
  "'disarming','succeeded','rolled_back','failed','aborted'";
/** `ACTIVE_CHANGE_JOB_STATUSES` — decision 1. The predicate of the in-flight
 *  unique index and of nothing else, which is why it is spelled out once. */
const ACTIVE_STATUSES =
  "'queued','claimed','backing_up','arming','applying','verifying','soaking','disarming'";
/** `TERMINAL_CHANGE_JOB_STATUSES`. */
const TERMINAL_STATUSES = "'succeeded','rolled_back','failed','aborted'";
/** Active AND already holding a worker's lease — every active state but `queued`. */
const LEASED_STATUSES =
  "'claimed','backing_up','arming','applying','verifying','soaking','disarming'";
/** States a WRITE job can only be in if a pre-change backup already exists
 *  (decision 2). Everything from `arming` on, plus the two terminal states that
 *  can only be reached through it. `failed` and `aborted` are excluded: those
 *  are reachable from `backing_up` itself, i.e. from the failure to back up. */
const POST_BACKUP_STATUSES =
  "'arming','applying','verifying','soaking','disarming','succeeded','rolled_back'";

/** `CHANGE_STEP_KINDS`. */
const STEP_KINDS =
  "'lint','bind_assert','guard','preflight_backup','arm_deadman','apply'," +
  "'reconnect','postcheck','soak','disarm','rollback','cleanup','record_outcome'";
/** `CHANGE_STEP_STATUSES`. */
const STEP_STATUSES = "'pending','running','succeeded','failed','skipped'";

/** `SAFETY_LEVELS` (shared/src/device.ts, M2) — §8.3. */
const SAFETY_LEVELS = "'armed','armed_by_peer','degraded'";
/** `GUARD_VERDICTS`. Uppercase, three-valued, and `INDETERMINATE` is a refusal. */
const GUARD_VERDICTS = "'ACCEPT','REJECT','INDETERMINATE'";
/** `MGMT_PATH_VERDICTS` (shared/src/ncm/plan.ts, M5) — the plan's older,
 *  lowercase spelling of the same three-valued answer. `change_plans` keeps it
 *  because M5 already writes it; `shared/src/change.ts` carries the only
 *  authorised bridge (`mgmtPathVerdictOf`). */
const MGMT_PATH_VERDICTS = "'accept','indeterminate','veto'";
/** `RISK_LEVELS` (shared/src/ncm/plan.ts). */
const RISK_LEVELS = "'low','medium','high'";
/** `PLAN_SOURCES` (shared/src/ncm/plan.ts). */
const PLAN_SOURCES = "'template','intent','refactor','restore'";

/** `BACKUP_KINDS` / `BACKUP_TRIGGERS` / `BACKUP_STATUSES` / retention. */
const BACKUP_KINDS = "'binary','rsc'";
const BACKUP_TRIGGERS = "'scheduled','preflight','pre_rollback','manual'";
const BACKUP_STATUSES = "'available','missing','purged','failed'";
const RETENTION_CLASSES = "'short','standard','long','legal_hold'";

/** `APPLY_OUTCOMES` — §8.3. `lost_contact` is the one that means a van. */
const APPLY_OUTCOMES = "'succeeded','rolled_back','lost_contact'";

/** `TRANSPORT_KINDS` (shared/src/device.ts). Telnet is absent by design (R9). */
const TRANSPORT_KINDS = "'routeros_api','ssh','rest','cwmp','snmp'";

/** `KILL_SWITCH_SCOPES`. */
const KILL_SWITCH_SCOPES = "'global','tenant'";

/**
 * How long a `command_audit` row is undeletable. Below this age the
 * append-only trigger refuses DELETE outright, so an incident cannot be tidied
 * away by the person who caused it; above it, a retention job may prune.
 * Deliberately longer than a year: "what did we push last winter" is a question
 * that gets asked.
 */
const AUDIT_IMMUTABLE_DAYS = 400;

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // change_plans — the FROZEN plan (decision D3, "plan figé").
  //
  // A plan is a promise about a world: `base_state_hash` names the snapshot it
  // was computed against, and the executor refuses to apply it if the device
  // has moved since. Freezing the row is what makes that promise checkable
  // hours later, in front of an operator who is about to approve it.
  // ==========================================================================

  await knex.schema.createTable('change_plans', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    t.string('source', 16).notNullable();
    // The render this plan was compiled from, when it came from a template.
    // SET NULL: losing the render must not lose the plan that was applied.
    t.bigInteger('render_id').nullable()
      .references('id').inTable('config_renders').onDelete('SET NULL');
    // The snapshot the plan was computed against, kept as evidence.
    t.bigInteger('snapshot_id').nullable()
      .references('id').inTable('config_snapshots').onDelete('SET NULL');

    // THE staleness key. `ncm_hash` of the snapshot above. A plan whose
    // base_state_hash no longer matches the device is not "slightly out of
    // date" — it is a description of rules that may no longer exist, and
    // applying it deletes things the operator never saw.
    t.specificType('base_state_hash', 'char(64)').notNullable();
    t.integer('ncm_version').notNullable().defaultTo(1);
    t.integer('sem_key_generation').notNullable().defaultTo(1);

    // `PlanOp[]`, REDACTED (§8.2 — a secret never transits through a PlanOp
    // value). Validated against `shared/src/ncm/plan.ts` on the way in AND on
    // the way out, so a plan compiled by one server version cannot be applied
    // blind by another.
    t.jsonb('ops').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.integer('ops_count').notNullable().defaultTo(0);
    // The brand artefact the driver will actually send, MASKED. Stored so the
    // review screen can show RouterOS to somebody who reads RouterOS; the
    // complete version is produced in memory at apply time and never lands here.
    t.jsonb('rendered').nullable();

    t.string('risk_level', 8).notNullable().defaultTo('low');
    // K2's answer, in the plan's own lowercase vocabulary. See MGMT_PATH_VERDICTS.
    t.string('mgmt_path_verdict', 16).notNullable().defaultTo('indeterminate');
    // `GuardReason[]`. The WHY behind the verdict, shown verbatim to the
    // operator: "we refused" is useless, "we refused because the packet
    // CHR -> 10.8.0.42 stops being accepted at rule 3" is actionable.
    t.jsonb('guard_reasons').notNullable().defaultTo(knex.raw("'[]'::jsonb"));

    // §8.3, computed PER DEVICE and displayed on the blast-radius screen BEFORE
    // launch. It lives on the plan and not only on the job so that the level is
    // known at review time, which is the only time it can still change a mind.
    t.string('safety_level', 16).notNullable();
    t.integer('safety_peer_device_id').nullable()
      .references('id').inTable('devices').onDelete('SET NULL');

    t.jsonb('blast_radius').notNullable().defaultTo(knex.raw("'{}'::jsonb"));
    // §4.5: a plan containing `move` ops with this false must never be offered
    // for approval — RouterOS renumbers on every move, so a move sequence that
    // was not proved against a simulated list produces a wrong final order.
    t.boolean('order_converges').notNullable().defaultTo(false);

    // A plan is perishable. Past this instant it must be recompiled, not
    // approved: the world it described is no longer the world.
    t.timestamp('expires_at', { useTz: true }).notNullable();
    // Set when `PLAN_INVALIDATED` fires (the device moved under us). One of the
    // only two columns the freeze trigger still lets an UPDATE touch.
    t.timestamp('invalidated_at', { useTz: true }).nullable();
    t.text('invalidated_reason').nullable();

    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE change_plans ADD CONSTRAINT change_plans_source_chk
       CHECK (source IN (${PLAN_SOURCES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE change_plans ADD CONSTRAINT change_plans_risk_chk
       CHECK (risk_level IN (${RISK_LEVELS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE change_plans ADD CONSTRAINT change_plans_verdict_chk
       CHECK (mgmt_path_verdict IN (${MGMT_PATH_VERDICTS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE change_plans ADD CONSTRAINT change_plans_safety_chk
       CHECK (safety_level IN (${SAFETY_LEVELS}))`,
  );
  await knex.schema.raw(
    "ALTER TABLE change_plans ADD CONSTRAINT change_plans_hash_chk " +
      "CHECK (base_state_hash ~ '^[0-9a-f]{64}$')",
  );
  await knex.schema.raw(
    "ALTER TABLE change_plans ADD CONSTRAINT change_plans_shape_chk CHECK (" +
      "jsonb_typeof(ops) = 'array' AND jsonb_typeof(guard_reasons) = 'array' AND " +
      "jsonb_typeof(blast_radius) = 'object' AND ops_count >= 0)",
  );
  // Decision 4, on the plan side: the level shown on the blast-radius screen
  // must name the peer it depends on, or it is a promise with no address.
  await knex.schema.raw(
    'ALTER TABLE change_plans ADD CONSTRAINT change_plans_peer_chk CHECK (' +
      "(safety_level = 'armed_by_peer') = (safety_peer_device_id IS NOT NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE change_plans ADD CONSTRAINT change_plans_peer_not_self_chk ' +
      'CHECK (safety_peer_device_id IS NULL OR safety_peer_device_id <> device_id)',
  );

  // The compile-time read: "the live plans for this device, newest first".
  await knex.schema.raw(
    'CREATE INDEX change_plans_device_idx ' +
      'ON change_plans (tenant_id, device_id, created_at DESC)',
  );
  // "Plans still worth showing" — the plan list, and the expiry sweeper.
  await knex.schema.raw(
    'CREATE INDEX change_plans_live_idx ON change_plans (tenant_id, expires_at) ' +
      'WHERE invalidated_at IS NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX change_plans_render_idx ON change_plans (render_id) ' +
      'WHERE render_id IS NOT NULL',
  );

  // "Plan figé" — the other half of D3, and it is a trigger for the same reason
  // 008's revision freeze is: the service layer refuses too, but the service
  // layer is not what runs at 2 a.m. from a psql prompt during an incident.
  //
  // What stays mutable is exactly the lifecycle: `invalidated_at`,
  // `invalidated_reason` and `updated_at`. Everything an operator READ before
  // approving — the ops, the hash, the verdict, the blast radius, the safety
  // level, the expiry — is sealed. A plan whose ops can change after approval
  // is an approval of nothing.
  //
  // DELETE is left open: offboarding a client cascades tenants -> devices ->
  // plans, and an offboarding must not be blocked by an old plan. What a
  // deletion cannot do is remove a plan a job still points at — that is
  // `change_jobs.plan_id`'s job, further down.
  await knex.schema.raw(`
    CREATE FUNCTION change_plans_freeze() RETURNS trigger AS $fn$
    BEGIN
      IF NEW.device_id          <> OLD.device_id
      OR NEW.tenant_id          <> OLD.tenant_id
      OR NEW.source             <> OLD.source
      OR NEW.base_state_hash    <> OLD.base_state_hash
      OR NEW.ops::text          <> OLD.ops::text
      OR NEW.ops_count          <> OLD.ops_count
      OR NEW.risk_level         <> OLD.risk_level
      OR NEW.mgmt_path_verdict  <> OLD.mgmt_path_verdict
      OR NEW.guard_reasons::text <> OLD.guard_reasons::text
      OR NEW.safety_level       <> OLD.safety_level
      OR NEW.blast_radius::text <> OLD.blast_radius::text
      OR NEW.order_converges    <> OLD.order_converges
      OR NEW.ncm_version        <> OLD.ncm_version
      OR NEW.sem_key_generation <> OLD.sem_key_generation
      OR NEW.expires_at         <> OLD.expires_at
      OR NEW.rendered::text      IS DISTINCT FROM OLD.rendered::text
      OR NEW.render_id           IS DISTINCT FROM OLD.render_id
      OR NEW.snapshot_id         IS DISTINCT FROM OLD.snapshot_id
      OR NEW.safety_peer_device_id IS DISTINCT FROM OLD.safety_peer_device_id
      OR NEW.created_by          IS DISTINCT FROM OLD.created_by
      THEN
        RAISE EXCEPTION
          'change_plan % is frozen; recompile a new plan instead', OLD.id
          USING ERRCODE = 'restrict_violation';
      END IF;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER change_plans_freeze
      BEFORE UPDATE ON change_plans
      FOR EACH ROW EXECUTE FUNCTION change_plans_freeze()
  `);

  // ==========================================================================
  // change_jobs — THE queue. Decision D3: nothing writes outside this table.
  //
  // `preflight_backup_id` is added by ALTER further down: it points at
  // `device_backups`, which points back here. One of the two FKs has to be a
  // second statement, and it is this one.
  // ==========================================================================

  await knex.schema.createTable('change_jobs', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    // NO ACTION (the default), NOT RESTRICT, and the difference is load-bearing:
    // RESTRICT fires immediately, so cascading a device deletion that removes
    // both the plan and its jobs would abort on the first row. NO ACTION is
    // checked at the end of the statement, so the cascade succeeds while a bare
    // "DELETE FROM change_plans WHERE id = X" that a job still points at still
    // fails, which is the case we actually want to forbid.
    t.bigInteger('plan_id').nullable().references('id').inTable('change_plans');

    t.string('kind', 12).notNullable();
    t.string('status', 16).notNullable().defaultTo('queued');

    // A WRITE IS NOT RETRIED SILENTLY. `max_attempts` defaults to 1: the queue
    // has to be told explicitly that an operation is safe to try twice, and
    // almost none are. `attempt` is bumped on claim, never on resume.
    t.integer('attempt').notNullable().defaultTo(0);
    t.integer('max_attempts').notNullable().defaultTo(1);

    // Copied from the plan at enqueue time and re-checked against the live
    // device before `applying`. Denormalised on purpose: the job must be able
    // to refuse itself even if the plan row is unreachable.
    t.specificType('base_state_hash', 'char(64)').notNullable();

    // ── §8.3, the three levels of net ────────────────────────────────────
    t.string('safety_level', 16).notNullable();
    // The co-located MikroTik carrying the dead-man for `armed_by_peer`,
    // reached through a tunnel this change does not touch.
    t.integer('safety_peer_device_id').nullable()
      .references('id').inTable('devices').onDelete('SET NULL');
    // DEGRADED = detection without recovery. §8.3 demands an explicit
    // confirmation, so it is two NOT-NULL-able columns and a CHECK.
    t.integer('degraded_confirmed_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('degraded_confirmed_at', { useTz: true }).nullable();

    // ── K2, the anti-lockout guard ───────────────────────────────────────
    // NULL for read-only kinds: a backup has nothing to guard. NOT NULL for
    // every write kind (CHECK below).
    t.string('guard_verdict', 16).nullable();
    t.jsonb('guard_reasons').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    // Non-null exactly when the verdict was not ACCEPT. This is the column the
    // destructive acceptance test of M6 has to fill in to force the
    // `chain=input drop` past the guard — the override is possible, and it is
    // signed.
    t.text('override_reason').nullable();
    t.integer('overridden_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('overridden_at', { useTz: true }).nullable();

    // ── The lease: `FOR UPDATE SKIP LOCKED` + crash recovery ─────────────
    // `claimed_by` is a worker identity (host:pid:uuid), not a user.
    t.string('claimed_by', 96).nullable();
    t.timestamp('claimed_at', { useTz: true }).nullable();
    // A worker that dies leaves a `claimed`/`backing_up` job whose lease runs
    // out; the reaper may return THOSE to `queued`. It may never do that to a
    // job in `applying` or beyond — see `WRITE_COMMITTED_STATUSES`.
    t.timestamp('lease_expires_at', { useTz: true }).nullable();

    // ── Scheduling and the maintenance window ────────────────────────────
    t.timestamp('scheduled_for', { useTz: true }).nullable();
    t.timestamp('window_start', { useTz: true }).nullable();
    t.timestamp('window_end', { useTz: true }).nullable();

    // ── The net, as it actually got installed ────────────────────────────
    // Forward FK added after `device_backups` exists.
    t.bigInteger('preflight_backup_id').nullable();
    // The on-box handle of the dead-man: the `/system/scheduler` entry name and
    // the `obliwan-rollback` script it runs. Stored so that a job which died
    // between arming and disarming can still be cleaned up by hand — and so
    // that the operator can be TOLD what is still armed on his router.
    t.string('deadman_handle', 128).nullable();
    t.timestamp('deadman_armed_at', { useTz: true }).nullable();
    t.timestamp('deadman_disarmed_at', { useTz: true }).nullable();
    // The deadline the on-box dead-man is counting down to. If we do not
    // disarm before it, the router restores itself. Kept here so the UI can
    // show a countdown that means something.
    t.timestamp('confirm_deadline', { useTz: true }).nullable();
    t.timestamp('soak_until', { useTz: true }).nullable();

    // ── M7 forward declaration. Bare columns, no FK (see header). ────────
    t.bigInteger('rollout_id').nullable();
    t.integer('wave_index').nullable();
    t.integer('canary_rank').nullable();

    t.integer('requested_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.integer('approved_by').nullable().references('id').inTable('users').onDelete('SET NULL');

    // Mirrors the row written into `apply_outcomes`, so a job carries its own
    // verdict without a join. NULL until the job is terminal.
    t.string('outcome', 16).nullable();
    t.string('error_kind', 48).nullable();
    // Operator-facing sentence. Never a stack trace, never a command, never a
    // device response (§8.2 — that goes to `change_job_steps.error_redacted`).
    t.text('error_message').nullable();

    t.timestamp('started_at', { useTz: true }).nullable();
    t.timestamp('finished_at', { useTz: true }).nullable();
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_kind_chk
       CHECK (kind IN (${JOB_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_status_chk
       CHECK (status IN (${JOB_STATUSES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_safety_chk
       CHECK (safety_level IN (${SAFETY_LEVELS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_guard_chk
       CHECK (guard_verdict IS NULL OR guard_verdict IN (${GUARD_VERDICTS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_outcome_chk
       CHECK (outcome IS NULL OR outcome IN (${APPLY_OUTCOMES}))`,
  );
  await knex.schema.raw(
    "ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_hash_chk " +
      "CHECK (base_state_hash ~ '^[0-9a-f]{64}$')",
  );
  await knex.schema.raw(
    "ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_reasons_chk " +
      "CHECK (jsonb_typeof(guard_reasons) = 'array')",
  );

  // A push applies a plan. Without one there is nothing to apply and no
  // `base_state_hash` to trust, so the row must not exist.
  await knex.schema.raw(
    "ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_push_needs_plan_chk " +
      "CHECK (kind <> 'push' OR plan_id IS NOT NULL)",
  );

  // K2 must have run before any write kind is even queued.
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_guard_required_chk
       CHECK (kind NOT IN (${WRITE_KINDS}) OR guard_verdict IS NOT NULL)`,
  );

  // ── Decision 3 ────────────────────────────────────────────────────────────
  // Anything but ACCEPT — including INDETERMINATE — needs a named human and a
  // written reason. This is the constraint that makes "forcer l'override" an
  // act with a signature rather than a flag.
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_override_chk CHECK (' +
      "guard_verdict IS NULL OR guard_verdict = 'ACCEPT' OR (" +
      "override_reason IS NOT NULL AND btrim(override_reason) <> '' AND " +
      'overridden_by IS NOT NULL AND overridden_at IS NOT NULL))',
  );

  // ── Decision 4 ────────────────────────────────────────────────────────────
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_peer_chk CHECK (' +
      "(safety_level = 'armed_by_peer') = (safety_peer_device_id IS NOT NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_peer_not_self_chk ' +
      'CHECK (safety_peer_device_id IS NULL OR safety_peer_device_id <> device_id)',
  );
  // §8.3: "Confirmation explicite exigée" — on write kinds only. Reading a
  // degraded box cannot lock anybody out of it.
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_degraded_confirm_chk CHECK (' +
      `NOT (safety_level = 'degraded' AND kind IN (${WRITE_KINDS})) OR ` +
      '(degraded_confirmed_by IS NOT NULL AND degraded_confirmed_at IS NOT NULL))',
  );

  // ── Decision 2 — R1's mandatory pre-change backup, structurally ──────────
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_preflight_backup_chk CHECK (' +
      `NOT (kind IN (${WRITE_KINDS}) AND status IN (${POST_BACKUP_STATUSES})) OR ` +
      'preflight_backup_id IS NOT NULL)',
  );

  // ── Lease and lifecycle coherence ────────────────────────────────────────
  // A queued job holds nothing. A leased job names its worker. Between them
  // there is no third state where a device is held by nobody.
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_queued_unclaimed_chk CHECK (' +
      "status <> 'queued' OR " +
      '(claimed_by IS NULL AND claimed_at IS NULL AND lease_expires_at IS NULL))',
  );
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_leased_chk CHECK (
       status NOT IN (${LEASED_STATUSES}) OR (claimed_by IS NOT NULL AND claimed_at IS NOT NULL))`,
  );
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_finished_chk CHECK (
       (status IN (${TERMINAL_STATUSES})) = (finished_at IS NOT NULL))`,
  );
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_started_chk ' +
      'CHECK (started_at IS NULL OR claimed_at IS NOT NULL)',
  );
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_attempt_chk ' +
      'CHECK (attempt >= 0 AND max_attempts >= 1 AND attempt <= max_attempts)',
  );
  // A window is a pair or it is nothing; a window that ends before it starts is
  // a window a scheduler will wait for forever.
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_window_chk CHECK (' +
      '((window_start IS NULL) = (window_end IS NULL)) AND ' +
      '(window_end IS NULL OR window_end > window_start))',
  );
  // You cannot disarm what was never armed. A `deadman_disarmed_at` without an
  // arming is a job claiming it cleaned up a net it never installed.
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_deadman_chk ' +
      'CHECK (deadman_disarmed_at IS NULL OR deadman_armed_at IS NOT NULL)',
  );
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_rollout_chk ' +
      'CHECK ((rollout_id IS NULL) = (wave_index IS NULL))',
  );

  // ── DECISION 1 — the whole milestone in one index ────────────────────────
  //
  // Two active jobs on one device cannot exist. Not "are not created" — cannot
  // exist. Everything else in this file is a rule; this is a fact.
  await knex.schema.raw(
    `CREATE UNIQUE INDEX change_jobs_one_in_flight_uq ON change_jobs (device_id)
       WHERE status IN (${ACTIVE_STATUSES})`,
  );

  // The queue's pick query: oldest eligible queued job first.
  // `scheduled_for NULLS FIRST` because "now" sorts before "later".
  await knex.schema.raw(
    "CREATE INDEX change_jobs_pick_idx ON change_jobs (scheduled_for NULLS FIRST, id) " +
      "WHERE status = 'queued'",
  );
  // The reaper's query: leases that ran out.
  await knex.schema.raw(
    `CREATE INDEX change_jobs_lease_idx ON change_jobs (lease_expires_at)
       WHERE status IN (${LEASED_STATUSES})`,
  );
  // The soak watcher.
  await knex.schema.raw(
    "CREATE INDEX change_jobs_soak_idx ON change_jobs (soak_until) WHERE status = 'soaking'",
  );
  // Read shapes, all tenant-first.
  await knex.schema.raw(
    'CREATE INDEX change_jobs_tenant_time_idx ON change_jobs (tenant_id, created_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX change_jobs_tenant_device_idx ' +
      'ON change_jobs (tenant_id, device_id, created_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX change_jobs_tenant_status_idx ' +
      'ON change_jobs (tenant_id, status, created_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX change_jobs_plan_idx ON change_jobs (plan_id) WHERE plan_id IS NOT NULL',
  );
  // M7 reads this one; the column is a forward declaration but the index is
  // free to create now and awkward to add to a large table later.
  await knex.schema.raw(
    'CREATE INDEX change_jobs_rollout_idx ON change_jobs (rollout_id, wave_index) ' +
      'WHERE rollout_id IS NOT NULL',
  );

  // ==========================================================================
  // change_job_steps — the ordered trace of what was ATTEMPTED.
  //
  // Not a log: a log is what we chose to say. This is the list of steps the
  // machine went through, with the one that stopped it. `(job_id, attempt, seq)`
  // is unique so a retry writes a second trace instead of overwriting the
  // first — the failed attempt is the interesting one.
  // ==========================================================================

  await knex.schema.createTable('change_job_steps', (t) => {
    t.bigIncrements('id').primary();
    t.bigInteger('job_id').notNullable()
      .references('id').inTable('change_jobs').onDelete('CASCADE');
    // Denormalised so every read index starts with the tenant. Overwritten from
    // the parent by a BEFORE INSERT trigger — a caller that omits it gets the
    // right value, and a caller that lies gets corrected.
    t.integer('tenant_id').notNullable().defaultTo(0);

    t.integer('seq').notNullable();
    t.integer('attempt').notNullable().defaultTo(1);
    t.string('kind', 20).notNullable();
    t.string('status', 12).notNullable().defaultTo('pending');
    // The `PlanOp.seq` this step executes, when it executes one. This is the
    // join that lets the UI put a red mark next to the exact line of the plan.
    t.integer('plan_op_seq').nullable();

    t.timestamp('started_at', { useTz: true }).nullable();
    t.timestamp('finished_at', { useTz: true }).nullable();
    t.integer('duration_ms').nullable();

    // §8.2 — MASKED at the source. The driver redacts before it returns; the
    // persistence layer is not where secrets get removed, because by then they
    // have already been through a log line.
    t.text('output_redacted').nullable();
    t.text('error_redacted').nullable();
    t.jsonb('detail_redacted').notNullable().defaultTo(knex.raw("'{}'::jsonb"));

    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    t.unique(['job_id', 'attempt', 'seq'], { indexName: 'change_job_steps_seq_uq' });
  });

  await knex.schema.raw(
    `ALTER TABLE change_job_steps ADD CONSTRAINT change_job_steps_kind_chk
       CHECK (kind IN (${STEP_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE change_job_steps ADD CONSTRAINT change_job_steps_status_chk
       CHECK (status IN (${STEP_STATUSES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE change_job_steps ADD CONSTRAINT change_job_steps_shape_chk CHECK (' +
      'seq >= 0 AND attempt >= 1 AND (duration_ms IS NULL OR duration_ms >= 0) AND ' +
      "jsonb_typeof(detail_redacted) = 'object')",
  );
  // The live job screen reads this, in order, over and over.
  await knex.schema.raw(
    'CREATE INDEX change_job_steps_job_idx ON change_job_steps (job_id, attempt, seq)',
  );
  await knex.schema.raw(
    'CREATE INDEX change_job_steps_tenant_idx ON change_job_steps (tenant_id, job_id)',
  );

  await knex.schema.raw(`
    CREATE FUNCTION change_job_steps_sync_tenant() RETURNS trigger AS $fn$
    DECLARE parent_tenant integer;
    BEGIN
      SELECT tenant_id INTO parent_tenant FROM change_jobs WHERE id = NEW.job_id;
      NEW.tenant_id := parent_tenant;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER change_job_steps_tenant_sync
      BEFORE INSERT OR UPDATE OF job_id ON change_job_steps
      FOR EACH ROW EXECUTE FUNCTION change_job_steps_sync_tenant()
  `);

  // ==========================================================================
  // device_backups — R1's artefact.
  //
  // The binary backup is what the on-box dead-man restores. The `.rsc` is what
  // a human reads at 3 a.m. to understand what he is about to restore. A
  // pre-change job takes both where the driver can, which is why the "one
  // preflight backup per job" unique index is on `(job, kind)` and not on `job`.
  // ==========================================================================

  await knex.schema.createTable('device_backups', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    t.string('kind', 8).notNullable();
    // §3.5 calls this column `trigger`; renamed to dodge the SQL keyword.
    t.string('trigger_kind', 16).notNullable();

    // Where the blob actually is. Relative to the configured backup root, never
    // absolute: an instance that moves its storage must not have to rewrite
    // every row.
    t.text('storage_path').notNullable();
    t.bigInteger('size_bytes').notNullable().defaultTo(0);
    t.specificType('sha256', 'char(64)').notNullable();
    // A `secretVault` blob (AES-256-GCM, `OBLIWAN_ENCRYPTION_KEY` + key_version),
    // NEVER a password. MikroTik binary backups are password-protected and the
    // password is useless to us if it is where the backup is.
    t.text('encryption_password_enc').nullable();

    t.string('retention_class', 16).notNullable().defaultTo('standard');
    t.timestamp('expires_at', { useTz: true }).nullable();
    t.string('status', 12).notNullable().defaultTo('available');

    // THE R1 link: which change this backup was taken to protect. SET NULL, not
    // CASCADE — losing the job must never delete the backup that could undo it.
    t.bigInteger('taken_before_job_id').nullable()
      .references('id').inTable('change_jobs').onDelete('SET NULL');

    // The firmware the backup came off. A binary backup is only restorable onto
    // a compatible RouterOS, so a restore plan that ignores this column is a
    // restore that bricks a box on a version boundary.
    t.string('os_version', 64).nullable();

    t.timestamp('taken_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    // When we last proved the blob is still there and still hashes right. A
    // backup nobody verified is a backup nobody has.
    t.timestamp('verified_at', { useTz: true }).nullable();
    t.timestamp('restored_at', { useTz: true }).nullable();

    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE device_backups ADD CONSTRAINT device_backups_kind_chk
       CHECK (kind IN (${BACKUP_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE device_backups ADD CONSTRAINT device_backups_trigger_chk
       CHECK (trigger_kind IN (${BACKUP_TRIGGERS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE device_backups ADD CONSTRAINT device_backups_status_chk
       CHECK (status IN (${BACKUP_STATUSES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE device_backups ADD CONSTRAINT device_backups_retention_chk
       CHECK (retention_class IN (${RETENTION_CLASSES}))`,
  );
  await knex.schema.raw(
    "ALTER TABLE device_backups ADD CONSTRAINT device_backups_shape_chk CHECK (" +
      "sha256 ~ '^[0-9a-f]{64}$' AND size_bytes >= 0 AND btrim(storage_path) <> '')",
  );
  // A hold that expires is not a hold.
  await knex.schema.raw(
    "ALTER TABLE device_backups ADD CONSTRAINT device_backups_hold_chk " +
      "CHECK (retention_class <> 'legal_hold' OR expires_at IS NULL)",
  );

  await knex.schema.raw(
    'CREATE INDEX device_backups_device_idx ' +
      'ON device_backups (tenant_id, device_id, taken_at DESC)',
  );
  // The retention sweeper, and only the rows it can act on.
  await knex.schema.raw(
    "CREATE INDEX device_backups_expiry_idx ON device_backups (expires_at) " +
      "WHERE status = 'available' AND expires_at IS NOT NULL",
  );
  // One preflight backup of each kind per job. A partial unique index because
  // `taken_before_job_id` is nullable and NULLS DISTINCT would make a plain
  // UNIQUE(taken_before_job_id, kind) constrain exactly nothing on the
  // scheduled and manual backups — which are most of the table. This is the
  // lesson of migration 001, applied to a nullable scope column.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX device_backups_preflight_uq ' +
      'ON device_backups (taken_before_job_id, kind) WHERE taken_before_job_id IS NOT NULL',
  );

  // The other half of the cycle, now that `device_backups` exists. NO ACTION
  // for the same end-of-statement reason as `plan_id` above.
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_preflight_backup_fk ' +
      'FOREIGN KEY (preflight_backup_id) REFERENCES device_backups (id)',
  );
  await knex.schema.raw(
    'CREATE INDEX change_jobs_backup_idx ON change_jobs (preflight_backup_id) ' +
      'WHERE preflight_backup_id IS NOT NULL',
  );

  // ==========================================================================
  // command_audit — EVERY command sent to an equipment, secrets redacted.
  //
  // Decision 5: no foreign keys, on any column. An audit row must outlive the
  // device, the user, the job and the tenant it names, and must never be
  // rewritten by a cascade. Identity is carried denormalised so the trail still
  // reads after the objects are gone.
  //
  // Append-only, enforced by trigger rather than by REVOKE: the migration runs
  // as the table owner, and an owner can always GRANT its own privileges back.
  // A trigger applies to the owner too.
  // ==========================================================================

  await knex.schema.createTable('command_audit', (t) => {
    t.bigIncrements('id').primary();

    // Bare columns. See decision 5.
    t.integer('tenant_id').notNullable();
    t.integer('device_id').nullable();
    t.uuid('device_uuid').nullable();
    t.string('device_name', 255).nullable();
    t.integer('user_id').nullable();
    t.string('username', 64).nullable();
    t.bigInteger('job_id').nullable();
    t.bigInteger('step_id').nullable();

    t.string('transport', 16).notNullable();
    // §8.2 / R10 — THE REDACTED COMMAND. `/ppp/secret/set password=***`, never
    // the password. If a secret ever reaches this column it reaches the audit
    // screen, the export bundle and every log shipper downstream.
    t.text('command').notNullable();
    t.jsonb('args_redacted').notNullable().defaultTo(knex.raw("'{}'::jsonb"));

    // The single most-queried column in an incident: "show me everything that
    // WROTE to this box that night".
    t.boolean('is_write').notNullable();
    // NULL while in flight — a command whose answer never came is itself a
    // finding, and collapsing it into `false` hides a timeout as a refusal.
    t.boolean('success').nullable();
    t.text('error_redacted').nullable();
    t.integer('duration_ms').nullable();
    // Where WE dialled from, for a multi-homed server. Not the device's IP.
    t.specificType('source_ip', 'inet').nullable();
    // Ties one operator gesture to the N commands it produced across M devices.
    t.uuid('correlation_id').nullable();

    t.timestamp('executed_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    `ALTER TABLE command_audit ADD CONSTRAINT command_audit_transport_chk
       CHECK (transport IN (${TRANSPORT_KINDS}))`,
  );
  await knex.schema.raw(
    "ALTER TABLE command_audit ADD CONSTRAINT command_audit_shape_chk CHECK (" +
      "jsonb_typeof(args_redacted) = 'object' AND " +
      '(duration_ms IS NULL OR duration_ms >= 0))',
  );

  await knex.schema.raw(
    'CREATE INDEX command_audit_tenant_time_idx ON command_audit (tenant_id, executed_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX command_audit_device_time_idx ON command_audit (device_id, executed_at DESC) ' +
      'WHERE device_id IS NOT NULL',
  );
  // "What did this job send?" — the forensic read after a rollback.
  await knex.schema.raw(
    'CREATE INDEX command_audit_job_idx ON command_audit (job_id) WHERE job_id IS NOT NULL',
  );
  // "Every write in this tenant, newest first."
  await knex.schema.raw(
    'CREATE INDEX command_audit_writes_idx ON command_audit (tenant_id, executed_at DESC) ' +
      'WHERE is_write',
  );
  await knex.schema.raw(
    'CREATE INDEX command_audit_correlation_idx ON command_audit (correlation_id) ' +
      'WHERE correlation_id IS NOT NULL',
  );

  await knex.schema.raw(`
    CREATE FUNCTION command_audit_append_only() RETURNS trigger AS $fn$
    BEGIN
      IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'command_audit is append-only; row % cannot be modified', OLD.id
          USING ERRCODE = 'restrict_violation';
      END IF;
      -- DELETE is allowed only for retention, and only well past the window in
      -- which somebody might want to make a bad night disappear.
      IF OLD.executed_at > now() - interval '${AUDIT_IMMUTABLE_DAYS} days' THEN
        RAISE EXCEPTION
          'command_audit row % is younger than ${AUDIT_IMMUTABLE_DAYS} days and cannot be deleted',
          OLD.id
          USING ERRCODE = 'restrict_violation';
      END IF;
      RETURN OLD;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER command_audit_append_only
      BEFORE UPDATE OR DELETE ON command_audit
      FOR EACH ROW EXECUTE FUNCTION command_audit_append_only()
  `);

  // ==========================================================================
  // apply_outcomes — §8.3, the laboratory we do not have.
  //
  // One row per application, never a counter: counters cannot be re-sliced, and
  // the question asked six months from now ("does this fail on 4.4.x
  // specifically, or on the 2927 in general?") is a re-slice.
  //
  // No foreign keys, decision 5: the corpus is built by the whole fleet across
  // clients and brands, and that cross-client corpus is the thing a single
  // vendor cannot produce. Offboarding a client must not delete the evidence.
  // ==========================================================================

  await knex.schema.createTable('apply_outcomes', (t) => {
    t.bigIncrements('id').primary();

    t.integer('tenant_id').notNullable();
    t.integer('device_id').nullable();
    t.bigInteger('job_id').nullable();

    // The four dimensions of §8.3: (operation kind, brand, model, firmware).
    t.string('op_kind', 12).notNullable();
    // Finer grain when the operation was a push: which NCM resource it touched.
    // Lets the corpus say "firewall pushes roll back on this box", which is a
    // far more useful sentence than "pushes roll back".
    t.string('resource', 24).nullable();
    t.string('brand', 32).notNullable();
    t.string('model', 128).nullable();
    t.string('os_version', 64).nullable();

    t.string('outcome', 16).notNullable();

    // The context that decides whether the outcome is even comparable: an
    // apply on a `degraded` device that lost contact is a different data point
    // from the same loss under an armed dead-man.
    t.string('safety_level', 16).notNullable();
    t.string('guard_verdict', 16).nullable();
    t.boolean('was_override').notNullable().defaultTo(false);

    t.integer('ops_count').notNullable().defaultTo(0);
    t.integer('duration_ms').nullable();
    t.string('failure_kind', 48).nullable();
    t.jsonb('detail_redacted').notNullable().defaultTo(knex.raw("'{}'::jsonb"));

    t.timestamp('observed_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    `ALTER TABLE apply_outcomes ADD CONSTRAINT apply_outcomes_op_chk
       CHECK (op_kind IN (${JOB_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE apply_outcomes ADD CONSTRAINT apply_outcomes_outcome_chk
       CHECK (outcome IN (${APPLY_OUTCOMES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE apply_outcomes ADD CONSTRAINT apply_outcomes_safety_chk
       CHECK (safety_level IN (${SAFETY_LEVELS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE apply_outcomes ADD CONSTRAINT apply_outcomes_guard_chk
       CHECK (guard_verdict IS NULL OR guard_verdict IN (${GUARD_VERDICTS}))`,
  );
  await knex.schema.raw(
    "ALTER TABLE apply_outcomes ADD CONSTRAINT apply_outcomes_shape_chk CHECK (" +
      "ops_count >= 0 AND (duration_ms IS NULL OR duration_ms >= 0) AND " +
      "jsonb_typeof(detail_redacted) = 'object')",
  );

  // THE planner's lookup, and the only reason this table exists: "what happened
  // the last N times we did THIS to a box like THAT". Cross-tenant on purpose.
  await knex.schema.raw(
    'CREATE INDEX apply_outcomes_corpus_idx ' +
      'ON apply_outcomes (op_kind, brand, model, os_version, outcome)',
  );
  // The same lookup for the rows where we do not even know what we pushed to.
  // A partial index because `model` and `os_version` are nullable and an
  // equality predicate never matches a NULL: without this, the "unknown
  // hardware" bucket is invisible instead of merely empty — and that bucket is
  // exactly where the first DrayTek/Zyxel/SonicWall pushes land.
  await knex.schema.raw(
    'CREATE INDEX apply_outcomes_unknown_idx ON apply_outcomes (op_kind, brand, outcome) ' +
      'WHERE model IS NULL OR os_version IS NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX apply_outcomes_tenant_time_idx ON apply_outcomes (tenant_id, observed_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX apply_outcomes_device_idx ON apply_outcomes (device_id, observed_at DESC) ' +
      'WHERE device_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX apply_outcomes_job_idx ON apply_outcomes (job_id) WHERE job_id IS NOT NULL',
  );

  // ==========================================================================
  // kill_switch — the gesture made in a panic (decision 6).
  // ==========================================================================

  await knex.schema.createTable('kill_switch', (t) => {
    t.increments('id').primary();
    t.string('scope', 8).notNullable();
    // NULL on the global row. The nullable scope column is exactly why the two
    // uniqueness rules below are partial indexes (migration 001's lesson).
    t.integer('tenant_id').nullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.boolean('engaged').notNullable().defaultTo(false);
    // Shown on every refused job. NOT required to engage: a reason field that
    // blocks the panic gesture is a reason field that gets bypassed.
    t.text('reason').nullable();

    t.integer('engaged_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('engaged_at', { useTz: true }).nullable();
    t.integer('released_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('released_at', { useTz: true }).nullable();

    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    `ALTER TABLE kill_switch ADD CONSTRAINT kill_switch_scope_chk CHECK (
       (scope = 'global' AND tenant_id IS NULL) OR
       (scope = 'tenant' AND tenant_id IS NOT NULL))`,
  );
  await knex.schema.raw(
    `ALTER TABLE kill_switch ADD CONSTRAINT kill_switch_scope_values_chk
       CHECK (scope IN (${KILL_SWITCH_SCOPES}))`,
  );
  // An engaged switch has a moment. Without it "who stopped the world, and
  // when" is a question with no answer.
  await knex.schema.raw(
    'ALTER TABLE kill_switch ADD CONSTRAINT kill_switch_engaged_chk ' +
      'CHECK (NOT engaged OR engaged_at IS NOT NULL)',
  );
  // Exactly one global row, at most one row per tenant.
  await knex.schema.raw(
    "CREATE UNIQUE INDEX kill_switch_global_uq ON kill_switch (scope) WHERE tenant_id IS NULL",
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX kill_switch_tenant_uq ON kill_switch (tenant_id) ' +
      'WHERE tenant_id IS NOT NULL',
  );

  // Seeded disengaged so the panic gesture is an UPDATE of a row that always
  // exists. Nobody should have to get an INSERT right at 3 a.m.
  await knex('kill_switch').insert({
    scope: 'global',
    tenant_id: null,
    engaged: false,
    reason: null,
  });

  await knex.schema.raw(`
    CREATE FUNCTION kill_switch_protect_global() RETURNS trigger AS $fn$
    BEGIN
      IF OLD.scope = 'global' THEN
        RAISE EXCEPTION 'the global kill switch row cannot be deleted; disengage it instead'
          USING ERRCODE = 'restrict_violation';
      END IF;
      RETURN OLD;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER kill_switch_protect_global
      BEFORE DELETE ON kill_switch
      FOR EACH ROW EXECUTE FUNCTION kill_switch_protect_global()
  `);

  // ── Decision 6 — the trivial read, and it fails CLOSED ────────────────────
  //
  //   SELECT kill_switch_blocks(:tenantId);
  //
  // `true` means no write may be attempted on any equipment of that tenant.
  // A MISSING global row returns `true`: if somebody managed to delete the row
  // the trigger protects, the answer is "stop", not "carry on".
  // The tenant sub-query defaults to `false` on a missing row because "this
  // tenant has no switch" genuinely means "this tenant is not blocked".
  await knex.schema.raw(`
    CREATE FUNCTION kill_switch_blocks(p_tenant_id integer) RETURNS boolean AS $fn$
      SELECT COALESCE((SELECT engaged FROM kill_switch WHERE scope = 'global'), true)
          OR COALESCE((SELECT engaged FROM kill_switch
                        WHERE scope = 'tenant' AND tenant_id = p_tenant_id), false)
    $fn$ LANGUAGE sql STABLE
  `);

  // ── Table comments: the one-line version, readable from psql ─────────────
  await knex.schema.raw(
    'COMMENT ON TABLE change_jobs IS $$' +
      'Decision D3: nothing writes to an equipment outside this queue. ' +
      'change_jobs_one_in_flight_uq makes "one job per device" a fact rather ' +
      'than a service check; change_jobs_preflight_backup_chk makes R1 backup ' +
      'mandatory; change_jobs_override_chk makes forcing a non-ACCEPT guard ' +
      'verdict impossible without naming a human.$$',
  );
  await knex.schema.raw(
    'COMMENT ON TABLE command_audit IS $$' +
      'Append-only, no foreign keys: an audit row must outlive everything it ' +
      'names and must never be rewritten by a cascade. Secrets are redacted at ' +
      'the source (ARCHITECTURE.md 8.2 / R10) - this table sees the masked ' +
      'command and nothing else.$$',
  );
  await knex.schema.raw(
    'COMMENT ON TABLE apply_outcomes IS $$' +
      'ARCHITECTURE.md 8.3: the empirical memory that replaces the lab we do ' +
      'not have. One row per application, cross-tenant on purpose. While the ' +
      'corpus is empty it protects nothing, and the planner must say so.$$',
  );
  await knex.schema.raw(
    'COMMENT ON FUNCTION kill_switch_blocks(integer) IS $$' +
      'Fail-closed: returns true when the global row is missing. Call it once, ' +
      'before anything else, on every write path.$$',
  );
}

export async function down(knex: Knex): Promise<void> {
  // The forward FK into device_backups goes first: it is what makes the
  // change_jobs <-> device_backups cycle, and a cycle has no drop order.
  await knex.schema.raw('DROP INDEX IF EXISTS change_jobs_backup_idx');
  await knex.schema.raw(
    'ALTER TABLE IF EXISTS change_jobs DROP CONSTRAINT IF EXISTS change_jobs_preflight_backup_fk',
  );

  await knex.schema.dropTableIfExists('kill_switch');
  await knex.schema.dropTableIfExists('apply_outcomes');
  await knex.schema.dropTableIfExists('command_audit');
  await knex.schema.dropTableIfExists('device_backups');
  await knex.schema.dropTableIfExists('change_job_steps');
  await knex.schema.dropTableIfExists('change_jobs');
  await knex.schema.dropTableIfExists('change_plans');

  // Triggers are dropped with their tables; the FUNCTIONS are not, and a
  // leftover function makes the next `migrate:latest` fail on CREATE FUNCTION.
  await knex.schema.raw('DROP FUNCTION IF EXISTS kill_switch_blocks(integer)');
  await knex.schema.raw('DROP FUNCTION IF EXISTS kill_switch_protect_global()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS command_audit_append_only()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS change_job_steps_sync_tenant()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS change_plans_freeze()');
}
