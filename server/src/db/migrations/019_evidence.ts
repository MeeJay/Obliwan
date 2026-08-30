import type { Knex } from 'knex';

/**
 * 019_evidence.ts — F1 (justified drift exceptions) + F2 (compliance
 * attestation). ARCHITECTURE.md §10.
 *
 * ┌─ SIX DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ────────────────────┐
 * │                                                                           │
 * │ 1. AN EXCEPTION WITHOUT A JUSTIFICATION CANNOT EXIST. It is a CHECK on    │
 * │    `drift_exceptions.justification`, not a Zod schema, for the same       │
 * │    reason migration 009 made the pre-change backup a constraint rather    │
 * │    than a convention: the day somebody adds a second write path — an      │
 * │    import, a bulk action, a fixture, a psql session at 2am — application  │
 * │    validation is not there and the database is.                           │
 * │                                                                           │
 * │ 2. `expired` IS NOT A STORED STATUS. It is `status = 'active' AND         │
 * │    review_due_at <= now()`. Storing it would make an expired exception    │
 * │    keep suppressing until some sweeper got round to flipping a column,    │
 * │    and a late sweeper is exactly the "hide the drift forever" hole F1     │
 * │    exists to close. Every read that decides visibility computes it.       │
 * │                                                                           │
 * │ 3. `drift_findings.ignored` NOW REQUIRES A REASON, BY CHECK.              │
 * │    `drift_findings_ignore_justified` refuses `ignored = true` unless the  │
 * │    row names either the normalization rule that silenced it               │
 * │    (`ignored_by_rule`, the pre-existing mechanism) or the exception that  │
 * │    forgives it (`ignored_by_exception`, new here).                        │
 * │                                                                           │
 * │    THIS DELIBERATELY BREAKS the old unjustified manual ignore —           │
 * │    `PATCH /api/drift/findings/:id/ignore {ignored:true}` with no rule id  │
 * │    now fails at the database. That path IS the bug F1 was written         │
 * │    against ("un finding marqué ignoré disparaît, et trois mois plus tard  │
 * │    personne ne sait pourquoi"). The replacement is                        │
 * │    `POST /api/exceptions`, which demands the justification and the date.  │
 * │    The `up()` below also UN-IGNORES every pre-existing row that could not │
 * │    satisfy the constraint: drift that was hidden without a reason becomes │
 * │    visible again, which is the direction this feature is pointing.        │
 * │                                                                           │
 * │ 4. THE EXCEPTION IS KEYED ON `sem_key`, NOT ON A FINDING ID.              │
 * │    A finding belongs to one drift run and every run makes new ones. An    │
 * │    exception pinned to a finding id would be dead the next morning and    │
 * │    an operator would re-justify the same NAT rule every day until he      │
 * │    stopped reading the screen. `origin_finding_id` is kept as provenance  │
 * │    only. Matching also accepts `legacy_sem_key` (§8.4), so a              │
 * │    `semKeyGeneration` bump does not resurrect every suppressed finding in │
 * │    the fleet on the morning the rules change.                             │
 * │                                                                           │
 * │ 5. `audit_log` IS CREATED HERE, AND ITS HASHES ARE COMPUTED BY POSTGRES.  │
 * │    ARCHITECTURE §3.7 specifies it; migration 012 explicitly declined to   │
 * │    create it and `acs.controller.ts` names the gap in a comment. F2 needs │
 * │    a chained ledger it did not compute itself, so it lands here. The      │
 * │    chain is per TENANT (`seq` restarts per tenant): a chain shared across │
 * │    customers cannot be exported to one of them without either leaking the │
 * │    others' row count or breaking the very linkage that makes it worth     │
 * │    exporting.                                                             │
 * │                                                                           │
 * │    The digest is computed in a BEFORE INSERT trigger with core `sha256()` │
 * │    over a LENGTH-PREFIXED preimage. Length-prefixing is not decoration:   │
 * │    plain concatenation lets two different rows produce one preimage,      │
 * │    which is the single thing a chain has to prevent.                      │
 * │                                                                           │
 * │ 6. `attestations` FREEZES THE ISSUED DOCUMENT.                            │
 * │    An attestation handed to an insurer last March must be re-verifiable   │
 * │    this March against WHAT WAS HANDED OVER, not against a fresh render of │
 * │    today's data. The row is frozen by trigger against UPDATE and DELETE.  │
 * │                                                                           │
 * │    `document` is `jsonb`, which does NOT preserve key order — and that is │
 * │    survivable only because `document_digest` is taken over a CANONICAL    │
 * │    serialisation (keys sorted, no whitespace). A digest over raw bytes    │
 * │    would make the document unverifiable the moment it passed through any  │
 * │    JSON parser, including ours.                                           │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * NO SECRET REACHES ANY TABLE HERE (§8.2 / R10). `drift_exceptions` carries
 * operator prose, `audit_log.before/after` carries the field values of the
 * evidence objects this milestone writes (exception rows, attestation
 * metadata) and never a credential, and `attestations.document` carries
 * hashes, timestamps and identifiers — never a configuration body, never a
 * command line.
 */

/** `shared/src/evidence.ts` — MIN_JUSTIFICATION_LENGTH. Kept as a literal on
 *  purpose: a CHECK constraint cannot import TypeScript, and a constraint that
 *  silently drifted from the constant would be worse than one that is
 *  obviously duplicated. Any change moves BOTH, in the same commit. */
const MIN_JUSTIFICATION = 24;

/** `shared/src/evidence.ts` — MAX_REVIEW_HORIZON_DAYS. */
const MAX_REVIEW_HORIZON_DAYS = 366;

/** `shared/src/evidence.ts` — EXCEPTION_STATUSES. Longest member: 'revoked' (7).
 *  Column is varchar(8): §"largeur varchar au moins égale à la plus longue
 *  valeur de son CHECK". */
const EXCEPTION_STATUSES = "'active','revoked'";

/** `shared/src/evidence.ts` — EXCEPTION_DECISIONS. Longest: 'created' (7). */
const EXCEPTION_DECISIONS = "'created','renewed','revoked'";

/** `shared/src/ncm/diff.ts` — DIFF_SEVERITIES. Longest: 'critical' (8). */
const SEVERITIES = "'info','low','medium','high','critical'";

/** `shared/src/ncm/resources.ts` — NCM_RESOURCE_KINDS. Longest: 'firewallRule'
 *  (12); the column is varchar(24) to match `drift_findings.resource`. */
const NCM_RESOURCE_KINDS =
  "'interface','vlan','route','firewallRule','natRule','dhcpScope'," +
  "'ipsecPeer','localUser','service','qosRule'";

/** `shared/src/evidence.ts` — ATTESTATION_VERDICTS. Longest:
 *  'insufficient_evidence' (21). Column is varchar(24). */
const ATTESTATION_VERDICTS =
  "'continuous','continuous_with_gaps','changed','insufficient_evidence'";

/** Who acted. Longest: 'automation' (10) — column varchar(12). */
const AUDIT_ACTOR_TYPES = "'user','system','automation','api'";

/** Same window as `command_audit` (migration 009): an audit row younger than
 *  this cannot be deleted, by anybody, for any reason. */
const AUDIT_IMMUTABLE_DAYS = 400;

/** Arbitrary but FIXED advisory-lock class for the audit chain. Two concurrent
 *  inserts in one tenant must not read the same tail and fork the chain. */
const AUDIT_LOCK_CLASS = 730_119_204;

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // The length-prefixed field encoder, shared by the audit chain trigger.
  //
  //   enc(NULL) = '-1:'      enc(v) = octet_length(v) || ':' || v
  //
  // IMMUTABLE and STRICT-less on purpose: it must return a value FOR null,
  // which a STRICT function cannot do. `octet_length` counts bytes in the
  // database encoding, which is UTF-8 — the same count `TextEncoder` produces
  // in `shared/src/evidence.ts`, which is what makes the two implementations
  // agree.
  // ==========================================================================
  await knex.schema.raw(`
    CREATE FUNCTION obliwan_enc(v text) RETURNS text AS $fn$
      SELECT CASE WHEN v IS NULL THEN '-1:' ELSE octet_length(v)::text || ':' || v END
    $fn$ LANGUAGE sql IMMUTABLE
  `);

  // ==========================================================================
  // F1 — drift_exceptions
  // ==========================================================================

  await knex.schema.createTable('drift_exceptions', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    // tenant_id is CARRIED, not inferred through the device, because every
    // uniqueness key and every read index below has to start with it.
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    // Same widths as `drift_findings`, deliberately: a value that fits there
    // and not here would make an exception impossible to write for exactly the
    // finding that needed one.
    t.string('sem_key', 180).notNullable();
    t.string('resource', 24).notNullable();
    /** `<kind>/<semKey>/<field>` for one field, NULL for the whole resource. */
    t.text('path').nullable();

    // ── THE column this whole feature is about ──────────────────────────────
    t.text('justification').notNullable();

    t.string('status', 8).notNullable().defaultTo('active');

    // The date the acceptance stops being an acceptance. NOT NULL, and past it
    // the finding comes back — see decision 2.
    t.timestamp('review_due_at', { useTz: true }).notNullable();

    // Trace the author. The id goes NULL when the account is deleted; the
    // username is a snapshot and survives, because "who accepted this" must
    // still have an answer after the person has left.
    t.integer('created_by_user_id').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.string('created_by_username', 64).notNullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    t.timestamp('revoked_at', { useTz: true }).nullable();
    t.integer('revoked_by_user_id').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.string('revoked_by_username', 64).nullable();

    t.integer('renewal_count').notNullable().defaultTo(0);
    t.timestamp('last_renewed_at', { useTz: true }).nullable();

    // Provenance only — see decision 4. SET NULL: losing the finding to a
    // retention purge must not lose the justification.
    t.bigInteger('origin_finding_id').nullable()
      .references('id').inTable('drift_findings').onDelete('SET NULL');
    t.string('severity_at_creation', 8).nullable();

    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // ── The constraint the whole feature rests on ────────────────────────────
  //
  // `btrim` first: a justification of 200 spaces is not a justification, and
  // `length(justification) >= 24` would accept it. This is enforced on INSERT
  // *and* on UPDATE, so an exception cannot be emptied after approval either.
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions ADD CONSTRAINT drift_exceptions_justified_chk ' +
      `CHECK (length(btrim(justification)) >= ${MIN_JUSTIFICATION})`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions ADD CONSTRAINT drift_exceptions_status_chk ' +
      `CHECK (status IN (${EXCEPTION_STATUSES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions ADD CONSTRAINT drift_exceptions_resource_chk ' +
      `CHECK (resource IN (${NCM_RESOURCE_KINDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions ADD CONSTRAINT drift_exceptions_severity_chk ' +
      `CHECK (severity_at_creation IS NULL OR severity_at_creation IN (${SEVERITIES}))`,
  );
  // A review date in the past at creation time would be an exception born
  // expired; one ten years out is a permanent suppression wearing a review date
  // as a disguise. Both are refused here rather than in a form.
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions ADD CONSTRAINT drift_exceptions_horizon_chk ' +
      'CHECK (review_due_at > created_at AND review_due_at <= created_at + ' +
      `interval '${MAX_REVIEW_HORIZON_DAYS} days' * (renewal_count + 1))`,
  );
  // A revocation is three columns or none. Half a revocation is an exception
  // nobody can explain the end of.
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions ADD CONSTRAINT drift_exceptions_revocation_chk CHECK (' +
      "(status = 'revoked') = (revoked_at IS NOT NULL) AND " +
      '(revoked_at IS NULL) = (revoked_by_username IS NULL))',
  );
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions ADD CONSTRAINT drift_exceptions_renewal_chk ' +
      'CHECK (renewal_count >= 0 AND (renewal_count = 0) = (last_renewed_at IS NULL))',
  );
  // An empty path is neither "the whole resource" (NULL) nor a field. It is a
  // bug that would match nothing and suppress nothing while looking active.
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions ADD CONSTRAINT drift_exceptions_path_chk ' +
      'CHECK (path IS NULL OR length(btrim(path)) > 0)',
  );

  // ── Uniqueness: PARTIAL, because `path` is nullable ──────────────────────
  //
  // `NULLS DISTINCT` is the Postgres default, so a plain
  // UNIQUE (tenant_id, device_id, sem_key, path) would constrain nothing at all
  // for the whole-resource case and let one device accumulate an unbounded pile
  // of identical "forgive everything about this NAT rule" exceptions. Two
  // partial indexes, and both start with tenant_id.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX drift_exceptions_active_field_uq ON drift_exceptions ' +
      "(tenant_id, device_id, sem_key, path) WHERE status = 'active' AND path IS NOT NULL",
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX drift_exceptions_active_resource_uq ON drift_exceptions ' +
      "(tenant_id, device_id, sem_key) WHERE status = 'active' AND path IS NULL",
  );

  // ── Read indexes. tenant_id leads every one of them. ─────────────────────
  // "What is due for review" is THE screen this feature adds, and it is a range
  // scan over active rows only.
  await knex.schema.raw(
    'CREATE INDEX drift_exceptions_tenant_review_idx ON drift_exceptions ' +
      "(tenant_id, review_due_at) WHERE status = 'active'",
  );
  await knex.schema.raw(
    'CREATE INDEX drift_exceptions_tenant_device_idx ON drift_exceptions ' +
      '(tenant_id, device_id, status, created_at DESC)',
  );
  // The sweeper's own query: every active exception whose review date has
  // passed, across the whole installation. Not tenant-first because the sweep
  // is a maintenance duty and not a customer read — but it is PARTIAL on the
  // status, so it stays small.
  await knex.schema.raw(
    'CREATE INDEX drift_exceptions_due_idx ON drift_exceptions ' +
      "(review_due_at) WHERE status = 'active'",
  );
  await knex.schema.raw(
    'CREATE INDEX drift_exceptions_semkey_idx ON drift_exceptions ' +
      '(tenant_id, sem_key)',
  );

  // The device must belong to the tenant the exception claims. Same shape as
  // `policy_results_same_tenant` (migration 012) and for the same reason: the
  // read path filters on tenant_id, and this closes the write path. A row whose
  // two parents disagreed would silence another customer's drift.
  await knex.schema.raw(`
    CREATE FUNCTION drift_exceptions_same_tenant() RETURNS trigger AS $fn$
    DECLARE
      d_tenant integer;
      f_device integer;
    BEGIN
      SELECT tenant_id INTO d_tenant FROM devices WHERE id = NEW.device_id;
      -- No device row means we are INSIDE a cascade: the device has already
      -- been deleted and this UPDATE is the referential action nulling
      -- origin_finding_id. The FK guarantees the device existed at INSERT, so
      -- a missing one here is never a caller's doing, and raising would make
      -- deleting a device impossible for any tenant that ever wrote one of
      -- these rows.
      IF d_tenant IS NULL THEN
        RETURN NEW;
      END IF;
      IF d_tenant IS DISTINCT FROM NEW.tenant_id THEN
        RAISE EXCEPTION
          'drift_exceptions: device % belongs to tenant %, not tenant %',
          NEW.device_id, d_tenant, NEW.tenant_id
          USING ERRCODE = 'restrict_violation';
      END IF;
      IF NEW.origin_finding_id IS NOT NULL THEN
        SELECT dr.device_id INTO f_device
          FROM drift_findings df JOIN drift_runs dr ON dr.id = df.run_id
         WHERE df.id = NEW.origin_finding_id;
        IF f_device IS DISTINCT FROM NEW.device_id THEN
          RAISE EXCEPTION
            'drift_exceptions: finding % is not a finding of device %',
            NEW.origin_finding_id, NEW.device_id
            USING ERRCODE = 'restrict_violation';
        END IF;
      END IF;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER drift_exceptions_same_tenant_trg
      BEFORE INSERT OR UPDATE OF tenant_id, device_id, origin_finding_id ON drift_exceptions
      FOR EACH ROW EXECUTE FUNCTION drift_exceptions_same_tenant()
  `);

  // ==========================================================================
  // drift_exception_reviews — the reconduction history, append-only.
  //
  // Every renewal carries ITS OWN justification. "Still needed" a year later is
  // a different assertion from the original one, and flattening them into a
  // single mutable column would erase the only evidence that anybody ever
  // looked again.
  // ==========================================================================

  await knex.schema.createTable('drift_exception_reviews', (t) => {
    t.bigIncrements('id').primary();
    t.bigInteger('exception_id').notNullable()
      .references('id').inTable('drift_exceptions').onDelete('CASCADE');
    // Denormalised from the parent so the history can be read and filtered
    // without a join, and so the tenant leads the index.
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('decision', 8).notNullable();
    t.text('justification').notNullable();

    t.integer('reviewed_by_user_id').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.string('reviewed_by_username', 64).notNullable();
    t.timestamp('reviewed_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    t.timestamp('previous_review_due_at', { useTz: true }).nullable();
    t.timestamp('new_review_due_at', { useTz: true }).nullable();
  });

  await knex.schema.raw(
    'ALTER TABLE drift_exception_reviews ADD CONSTRAINT der_decision_chk ' +
      `CHECK (decision IN (${EXCEPTION_DECISIONS}))`,
  );
  // Same rule as the parent: a review entry with no reason is a timestamp
  // pretending to be a decision.
  await knex.schema.raw(
    'ALTER TABLE drift_exception_reviews ADD CONSTRAINT der_justified_chk ' +
      `CHECK (length(btrim(justification)) >= ${MIN_JUSTIFICATION})`,
  );
  // A renewal that does not move the date is not a renewal.
  await knex.schema.raw(
    'ALTER TABLE drift_exception_reviews ADD CONSTRAINT der_renewal_moves_date_chk CHECK (' +
      "decision <> 'renewed' OR (new_review_due_at IS NOT NULL AND " +
      'previous_review_due_at IS NOT NULL AND new_review_due_at > previous_review_due_at))',
  );
  await knex.schema.raw(
    'CREATE INDEX der_tenant_time_idx ON drift_exception_reviews ' +
      '(tenant_id, reviewed_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX der_exception_idx ON drift_exception_reviews (exception_id, reviewed_at)',
  );
  await knex.schema.raw(`
    CREATE FUNCTION drift_exception_reviews_append_only() RETURNS trigger AS $fn$
    BEGIN
      -- The one legal deletion: the parent exception is itself gone, so this
      -- DELETE is the ON DELETE CASCADE and not somebody erasing a decision.
      -- Postgres removes the parent row before firing the referential action,
      -- so the absence of the parent is a reliable discriminator — and without
      -- this escape, deleting a DEVICE would fail for every tenant that ever
      -- reviewed an exception.
      IF TG_OP = 'DELETE'
         AND NOT EXISTS (SELECT 1 FROM drift_exceptions WHERE id = OLD.exception_id) THEN
        RETURN OLD;
      END IF;
      RAISE EXCEPTION 'drift_exception_reviews is append-only; row % cannot be %',
        OLD.id, lower(TG_OP)
        USING ERRCODE = 'restrict_violation';
    END;
    $fn$ LANGUAGE plpgsql
  `);
  // A standalone DELETE is NOT exempted by a retention window, unlike
  // `command_audit`: this table holds one short row per human decision, so
  // there is no retention pressure to relieve, and the ability to delete a
  // review is the ability to delete the trace of who renewed a suppression.
  await knex.schema.raw(`
    CREATE TRIGGER drift_exception_reviews_append_only
      BEFORE UPDATE OR DELETE ON drift_exception_reviews
      FOR EACH ROW EXECUTE FUNCTION drift_exception_reviews_append_only()
  `);

  // ==========================================================================
  // drift_findings — the link, and the guard. Decision 3.
  // ==========================================================================

  await knex.schema.raw(
    'ALTER TABLE drift_findings ADD COLUMN ignored_by_exception bigint NULL ' +
      'REFERENCES drift_exceptions(id) ON DELETE SET NULL',
  );
  // Partial: the overwhelming majority of findings are not suppressed, and the
  // index exists for the sweeper ("give me back everything this exception was
  // hiding"), which only ever asks about non-null values.
  await knex.schema.raw(
    'CREATE INDEX drift_findings_exception_idx ON drift_findings (ignored_by_exception) ' +
      'WHERE ignored_by_exception IS NOT NULL',
  );
  // The sweeper matches on (sem_key, path) within a run's device. Without this,
  // applying one exception is a sequential scan of every finding ever recorded.
  await knex.schema.raw(
    'CREATE INDEX drift_findings_semkey_path_idx ON drift_findings (sem_key, path)',
  );
  await knex.schema.raw(
    'CREATE INDEX drift_findings_legacy_semkey_idx ON drift_findings (legacy_sem_key) ' +
      'WHERE legacy_sem_key IS NOT NULL',
  );

  // Pre-existing rows that were ignored with no reason at all become VISIBLE
  // again. That is not collateral damage, it is the migration doing the
  // feature's job: drift that was hidden without a justification is exactly
  // what F1 says must stop being hidden. Ordered before the CHECK because the
  // CHECK would otherwise refuse to validate the table.
  await knex.schema.raw(
    'UPDATE drift_findings SET ignored = false ' +
      'WHERE ignored AND ignored_by_rule IS NULL AND ignored_by_exception IS NULL',
  );
  // Recompute the runs those findings belong to, or a run keeps claiming
  // `in_sync` while carrying a freshly-visible critical.
  await knex.schema.raw(`
    UPDATE drift_runs dr SET
      ignored_count = s.ignored_count,
      max_severity  = s.max_severity,
      status        = CASE WHEN dr.status IN ('error','unreachable') THEN dr.status
                           WHEN s.visible_count > 0 THEN 'drifted' ELSE 'in_sync' END
    FROM (
      SELECT run_id,
             count(*) FILTER (WHERE ignored)      AS ignored_count,
             count(*) FILTER (WHERE NOT ignored)  AS visible_count,
             (ARRAY_REMOVE(ARRAY_AGG(CASE WHEN NOT ignored THEN severity END ORDER BY
                CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
                              WHEN 'low' THEN 1 ELSE 0 END DESC), NULL))[1] AS max_severity
        FROM drift_findings GROUP BY run_id
    ) s
    WHERE s.run_id = dr.id
  `);

  await knex.schema.raw(
    'ALTER TABLE drift_findings ADD CONSTRAINT drift_findings_ignore_justified CHECK (' +
      'NOT ignored OR ignored_by_rule IS NOT NULL OR ignored_by_exception IS NOT NULL)',
  );
  // An `ignored_by_exception` that does not actually ignore anything is a
  // dangling claim: the sweeper would count it as suppressed while the drift
  // screen shows it. Both directions or neither.
  await knex.schema.raw(
    'ALTER TABLE drift_findings ADD CONSTRAINT drift_findings_exception_implies_ignored ' +
      'CHECK (ignored_by_exception IS NULL OR ignored)',
  );

  // ── The guard on BOTH reasons a finding may be hidden ────────────────────
  //
  // Cheap by construction: it returns almost immediately for every finding a
  // drift run writes, because a fresh finding carries neither a rule nor an
  // exception.
  //
  // ┌─ WHY THE COMPENSATION BRANCH COVERS TWO COLUMNS AND NOT ONE ───────────┐
  // │ `drift_findings_ignore_justified` refuses `ignored = true` unless the   │
  // │ row names a rule or an exception. BOTH of those FKs are ON DELETE SET   │
  // │ NULL, so BOTH of them can be emptied by a referential action on a row   │
  // │ that says `ignored = true` — and the CHECK then aborts the DELETE that  │
  // │ caused it.                                                              │
  // │                                                                         │
  // │ The original version compensated for `ignored_by_exception` only, and   │
  // │ the trigger did not even fire on `ignored_by_rule`. The consequence     │
  // │ was not theoretical: `DELETE FROM normalization_rules WHERE id = 5`     │
  // │ failed with "violates check constraint                                  │
  // │ drift_findings_ignore_justified", and because a finding could name      │
  // │ ANOTHER tenant's rule, `DELETE FROM tenants WHERE id = 2` failed for    │
  // │ the same reason — one customer's offboarding blocked by another         │
  // │ customer's row. A compensation that exists for one column out of two is │
  // │ a guard that is off three quarters of the time.                         │
  // └─────────────────────────────────────────────────────────────────────────┘
  //
  // ┌─ AND THE RULE MUST BE THE FINDING'S OWN TENANT'S ──────────────────────┐
  // │ `ignored_by_rule` is a plain FK to `normalization_rules(id)`. Nothing   │
  // │ tied it to the finding's tenant, so `UPDATE drift_findings SET          │
  // │ ignored = true, ignored_by_rule = <a rule of tenant 2>` on a `critical` │
  // │ of tenant 1 was ACCEPTED — a cross-customer suppression reachable over  │
  // │ HTTP with a small integer. Library rules (`tenant_id IS NULL`, see      │
  // │ migration 013) belong to everybody and are the one accepted value.      │
  // │                                                                         │
  // │ This closes the STORAGE half. The route half — an unjustified manual    │
  // │ ignore must answer 409 and point at POST /api/exceptions, and every     │
  // │ ignore must write an audit_log row — lives in drift.service.ts /        │
  // │ drift.controller.ts and is not this milestone's to edit.                │
  // └─────────────────────────────────────────────────────────────────────────┘
  await knex.schema.raw(`
    CREATE FUNCTION drift_findings_exception_same_device() RETURNS trigger AS $fn$
    DECLARE
      e_device integer;
      f_device integer;
      f_tenant integer;
      r_tenant integer;
    BEGIN
      -- LOSING THE LAST REASON UN-HIDES THE FINDING. This is what makes
      -- ON DELETE SET NULL on EITHER fk compatible with
      -- drift_findings_ignore_justified: without it, deleting a normalization
      -- rule, or an exception (which happens by cascade when a tenant or a
      -- device goes away), would leave ignored = true with no reason at all
      -- and the CHECK would abort the deletion.
      --
      -- UPDATE only. On INSERT the same shape must FAIL loudly rather than be
      -- silently corrected: an insert claiming ignored with no reason is a
      -- caller bug, and the CHECK is there to say so.
      IF TG_OP = 'UPDATE' AND NEW.ignored
         AND NEW.ignored_by_rule IS NULL AND NEW.ignored_by_exception IS NULL THEN
        NEW.ignored := false;
      END IF;

      -- The rule that silences a finding must be one the finding's tenant is
      -- entitled to: its own, or a library rule (tenant_id IS NULL).
      IF NEW.ignored_by_rule IS NOT NULL THEN
        SELECT dr.device_id, d.tenant_id INTO f_device, f_tenant
          FROM drift_runs dr JOIN devices d ON d.id = dr.device_id
         WHERE dr.id = NEW.run_id;
        SELECT tenant_id INTO r_tenant FROM normalization_rules WHERE id = NEW.ignored_by_rule;
        -- A NULL on either side means we are inside a cascade (the run, the
        -- device or the rule is already gone). The FKs guarantee they existed
        -- at write time, so a missing one here is never a caller's doing, and
        -- raising would make deleting a tenant impossible.
        IF f_tenant IS NOT NULL AND r_tenant IS NOT NULL AND r_tenant IS DISTINCT FROM f_tenant
        THEN
          RAISE EXCEPTION
            'drift_findings: normalization rule % belongs to tenant %, finding % is tenant %''s',
            NEW.ignored_by_rule, r_tenant, NEW.id, f_tenant
            USING ERRCODE = 'restrict_violation';
        END IF;
      END IF;

      IF NEW.ignored_by_exception IS NULL THEN
        RETURN NEW;
      END IF;
      SELECT device_id INTO e_device FROM drift_exceptions WHERE id = NEW.ignored_by_exception;
      SELECT device_id INTO f_device FROM drift_runs WHERE id = NEW.run_id;
      IF e_device IS DISTINCT FROM f_device THEN
        RAISE EXCEPTION
          'drift_findings: exception % covers device %, finding % is on device %',
          NEW.ignored_by_exception, e_device, NEW.id, f_device
          USING ERRCODE = 'restrict_violation';
      END IF;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  // `ignored_by_rule` is in the UPDATE OF list — that omission was the whole
  // bug. `ignored` deliberately is NOT: a bare `UPDATE ... SET ignored = true`
  // must still hit drift_findings_ignore_justified and raise 23514, because
  // silently correcting it would turn "this write is refused" into "this write
  // did nothing", and the caller would never learn the difference.
  await knex.schema.raw(`
    CREATE TRIGGER drift_findings_exception_same_device_trg
      BEFORE INSERT OR UPDATE OF ignored_by_exception, ignored_by_rule, run_id
      ON drift_findings
      FOR EACH ROW EXECUTE FUNCTION drift_findings_exception_same_device()
  `);

  // ==========================================================================
  // F2 — audit_log (ARCHITECTURE §3.7). Decision 5.
  // ==========================================================================

  await knex.schema.createTable('audit_log', (t) => {
    t.bigIncrements('id').primary();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    // Position in THIS TENANT'S chain, starting at 1. Assigned by the trigger,
    // never by the caller: a caller-chosen sequence is a caller-chosen place in
    // the chain.
    t.bigInteger('seq').notNullable();

    t.string('actor_type', 12).notNullable();
    // Kept as text and not as an FK: the ledger must outlive the user, the
    // token and the automation it names. A FK with ON DELETE SET NULL would
    // MUTATE a row of an append-only chain and break every hash after it.
    t.string('actor_id', 64).nullable();
    t.string('actor_name', 128).nullable();

    t.string('action', 64).notNullable();
    t.string('entity_type', 48).nullable();
    t.string('entity_id', 64).nullable();

    // Redacted by the caller (§8.2). No secret, ever — the audit ledger is the
    // one table whose whole purpose is to be handed to somebody else.
    t.jsonb('before').nullable();
    t.jsonb('after').nullable();
    t.uuid('correlation_id').nullable();

    // Millisecond precision, deliberately: the hash preimage renders this with
    // `to_char(... 'MS')`, and a microsecond stored but not hashed would make
    // the row's own timestamp unverifiable from the row.
    t.timestamp('occurred_at', { useTz: true, precision: 3 })
      .notNullable().defaultTo(knex.fn.now());

    t.specificType('prev_hash', 'char(64)').nullable();
    t.specificType('hash', 'char(64)').notNullable();
  });

  await knex.schema.raw(
    'ALTER TABLE audit_log ADD CONSTRAINT audit_log_actor_chk ' +
      `CHECK (actor_type IN (${AUDIT_ACTOR_TYPES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE audit_log ADD CONSTRAINT audit_log_hash_fmt_chk ' +
      "CHECK (hash ~ '^[0-9a-f]{64}$' AND (prev_hash IS NULL OR prev_hash ~ '^[0-9a-f]{64}$'))",
  );
  await knex.schema.raw(
    'ALTER TABLE audit_log ADD CONSTRAINT audit_log_seq_chk CHECK (seq >= 1)',
  );
  // Exactly one genesis row per tenant, and it is the only one allowed to have
  // no predecessor. Enforced as a partial unique index rather than left to the
  // trigger: a trigger is code, and this is the property that makes the chain a
  // chain rather than a forest.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX audit_log_genesis_uq ON audit_log (tenant_id) WHERE prev_hash IS NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX audit_log_tenant_seq_uq ON audit_log (tenant_id, seq)',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX audit_log_tenant_hash_uq ON audit_log (tenant_id, hash)',
  );
  await knex.schema.raw(
    'CREATE INDEX audit_log_tenant_time_idx ON audit_log (tenant_id, occurred_at DESC, seq DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX audit_log_tenant_entity_idx ON audit_log ' +
      '(tenant_id, entity_type, entity_id, occurred_at DESC) WHERE entity_type IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX audit_log_tenant_action_idx ON audit_log (tenant_id, action, occurred_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX audit_log_correlation_idx ON audit_log (correlation_id) ' +
      'WHERE correlation_id IS NOT NULL',
  );

  // ── The chain, computed by the database ─────────────────────────────────
  //
  // `pg_advisory_xact_lock` serialises inserts WITHIN one tenant. Without it
  // two concurrent transactions both read the same tail, both compute
  // `seq = n + 1`, and one of them loses on `audit_log_tenant_seq_uq` — which
  // is at least loud, but it also means a legitimate audit write can fail under
  // load, and §"si l'écriture d'audit échoue, l'écriture équipement n'a pas
  // lieu" makes that a refused operation. The lock turns a lost race into a
  // short wait. It is per tenant, so one busy customer does not serialise
  // another's ledger.
  //
  // The preimage is the SAME string `auditRowPreimage()` builds in
  // `shared/src/evidence.ts`. Keeping two implementations is the price of the
  // property that matters: the hash a reader re-computes in JavaScript was
  // produced by Postgres, so agreement between them is evidence and not a
  // tautology.
  await knex.schema.raw(`
    CREATE FUNCTION audit_log_chain() RETURNS trigger AS $fn$
    DECLARE
      prev_seq  bigint;
      prev_hash char(64);
      pre       text;
    BEGIN
      PERFORM pg_advisory_xact_lock(${AUDIT_LOCK_CLASS}, NEW.tenant_id);

      SELECT seq, hash INTO prev_seq, prev_hash
        FROM audit_log WHERE tenant_id = NEW.tenant_id ORDER BY seq DESC LIMIT 1;

      NEW.seq       := COALESCE(prev_seq, 0) + 1;
      NEW.prev_hash := prev_hash;

      pre := 'obliwan.audit.v1'
        || obliwan_enc(NEW.prev_hash)
        || obliwan_enc(NEW.tenant_id::text)
        || obliwan_enc(NEW.seq::text)
        || obliwan_enc(to_char(NEW.occurred_at AT TIME ZONE 'UTC',
                               'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
        || obliwan_enc(NEW.actor_type)
        || obliwan_enc(NEW.actor_id)
        || obliwan_enc(NEW.actor_name)
        || obliwan_enc(NEW.action)
        || obliwan_enc(NEW.entity_type)
        || obliwan_enc(NEW.entity_id)
        || obliwan_enc(NEW.correlation_id::text)
        || obliwan_enc(NEW.before::text)
        || obliwan_enc(NEW.after::text);

      NEW.hash := encode(sha256(convert_to(pre, 'UTF8')), 'hex');
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER audit_log_chain_trg
      BEFORE INSERT ON audit_log
      FOR EACH ROW EXECUTE FUNCTION audit_log_chain()
  `);

  await knex.schema.raw(`
    CREATE FUNCTION audit_log_append_only() RETURNS trigger AS $fn$
    BEGIN
      IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'audit_log is append-only; row % cannot be modified', OLD.id
          USING ERRCODE = 'restrict_violation';
      END IF;
      -- The tenant itself is gone: this DELETE is the ON DELETE CASCADE of the
      -- customer's own removal, which is the one erasure that is legitimate and
      -- the one nobody can be protected from anyway.
      IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = OLD.tenant_id) THEN
        RETURN OLD;
      END IF;
      -- A DELETE anywhere but at the OLDEST end of a tenant's chain leaves a
      -- gap that makes every later row unverifiable. Retention therefore
      -- truncates from the tail and only past the immutable window.
      IF OLD.occurred_at > now() - interval '${AUDIT_IMMUTABLE_DAYS} days' THEN
        RAISE EXCEPTION
          'audit_log row % is younger than ${AUDIT_IMMUTABLE_DAYS} days and cannot be deleted',
          OLD.id
          USING ERRCODE = 'restrict_violation';
      END IF;
      IF EXISTS (SELECT 1 FROM audit_log
                  WHERE tenant_id = OLD.tenant_id AND seq < OLD.seq) THEN
        RAISE EXCEPTION
          'audit_log row % is not the oldest of tenant %; deleting it would break the chain',
          OLD.id, OLD.tenant_id
          USING ERRCODE = 'restrict_violation';
      END IF;
      RETURN OLD;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER audit_log_append_only
      BEFORE UPDATE OR DELETE ON audit_log
      FOR EACH ROW EXECUTE FUNCTION audit_log_append_only()
  `);

  // §3.7 asks for `REVOKE UPDATE, DELETE`. It is applied, and it is the WEAKER
  // of the two protections: the migration runs as the table owner, and an owner
  // is not bound by its own grants. The triggers above are what actually holds,
  // including against the application's own connection. The REVOKE is here so
  // that a read-only reporting role, a BI connection or a future least-
  // privilege application role inherits nothing it should not have.
  await knex.schema.raw('REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC');
  await knex.schema.raw(
    "COMMENT ON TABLE audit_log IS $$Append-only, hash-chained PER TENANT (seq restarts at 1 " +
      "for each tenant). prev_hash/hash/seq are assigned by the audit_log_chain trigger and " +
      'must never be supplied by a caller. Preimage: obliwan.audit.v1 followed by ' +
      'obliwan_enc() of prev_hash, tenant_id, seq, occurred_at (ISO-8601 UTC ms), actor_type, ' +
      'actor_id, actor_name, action, entity_type, entity_id, correlation_id, before::text, ' +
      'after::text. See shared/src/evidence.ts auditRowPreimage().$$',
  );
  await knex.schema.raw(
    "COMMENT ON COLUMN audit_log.before IS $$REDACTED. §8.2 — a secret that lands here has " +
      'been published: this column is designed to leave the building.$$',
  );

  // ==========================================================================
  // F2 — attestations. Decision 6.
  // ==========================================================================

  await knex.schema.createTable('attestations', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    // NO ACTION rather than CASCADE: offboarding a device must not delete the
    // attestations that were issued about it. An attestation is a statement
    // about the past, and the past does not stop having happened when the
    // router is decommissioned. The tenant cascade above still removes them
    // when the customer itself is deleted.
    t.integer('device_id').nullable()
      .references('id').inTable('devices').onDelete('SET NULL');
    // Frozen identity of the subject, so the document stays readable after the
    // device row is gone.
    t.uuid('device_uuid').notNullable();
    t.string('device_name', 255).notNullable();

    t.timestamp('window_from', { useTz: true }).notNullable();
    t.timestamp('window_to', { useTz: true }).notNullable();

    t.string('verdict', 24).notNullable();
    /** The hash the claim is about — NULL when the config changed in-window. */
    t.specificType('claimed_ncm_hash', 'char(64)').nullable();

    // Stable for a given evidence set: it excludes `issuedAt` on purpose, so
    // re-issuing over the same window and getting a DIFFERENT root means the
    // underlying evidence moved. That comparison is the cheapest tamper check
    // this product has.
    t.specificType('evidence_root', 'char(64)').notNullable();
    /** Identifies this exact issued document, `issuedAt` included. */
    t.specificType('document_digest', 'char(64)').notNullable();
    t.integer('entry_count').notNullable();

    // The bytes that were handed over. Hashes, timestamps and identifiers only
    // — never a configuration body, never a command line (§8.2).
    t.jsonb('document').notNullable();

    t.integer('issued_by_user_id').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.string('issued_by_username', 64).notNullable();
    t.timestamp('issued_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    // The ledger row that recorded the issuance, and a BARE COLUMN on purpose
    // — same reasoning as `command_audit` / `apply_outcomes` in migration 009.
    // A real FK would have to pick a referential action, and all three are
    // wrong here: CASCADE lets a retention purge of the ledger delete
    // attestations, SET NULL is an UPDATE that `attestations_frozen` refuses,
    // and NO ACTION makes the ORDER of two cascades during a tenant deletion
    // decide whether the deletion succeeds. The value is verifiable without a
    // constraint: `audit_log_seq` and the chain hash are inside the document.
    t.bigInteger('audit_log_id').nullable();
    t.bigInteger('audit_log_seq').nullable();
  });

  await knex.schema.raw(
    'ALTER TABLE attestations ADD CONSTRAINT attestations_verdict_chk ' +
      `CHECK (verdict IN (${ATTESTATION_VERDICTS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE attestations ADD CONSTRAINT attestations_window_chk ' +
      'CHECK (window_to > window_from)',
  );
  await knex.schema.raw(
    'ALTER TABLE attestations ADD CONSTRAINT attestations_hash_fmt_chk CHECK (' +
      "evidence_root ~ '^[0-9a-f]{64}$' AND document_digest ~ '^[0-9a-f]{64}$' AND " +
      "(claimed_ncm_hash IS NULL OR claimed_ncm_hash ~ '^[0-9a-f]{64}$'))",
  );
  // A continuity verdict names the configuration it is about; a `changed` or an
  // `insufficient_evidence` cannot, because there is no single one.
  await knex.schema.raw(
    'ALTER TABLE attestations ADD CONSTRAINT attestations_claim_coherent_chk CHECK (' +
      "(verdict IN ('continuous','continuous_with_gaps')) = (claimed_ncm_hash IS NOT NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE attestations ADD CONSTRAINT attestations_shape_chk ' +
      "CHECK (entry_count >= 0 AND jsonb_typeof(document) = 'object')",
  );

  // The digest is a function of the whole document, so a duplicate means the
  // exact same bytes were issued twice — which cannot happen, `issuedAt` being
  // inside. Unique per tenant, because a digest collision across tenants is a
  // sha256 collision and not our problem.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX attestations_tenant_digest_uq ON attestations ' +
      '(tenant_id, document_digest)',
  );
  await knex.schema.raw(
    'CREATE INDEX attestations_tenant_device_idx ON attestations ' +
      '(tenant_id, device_id, issued_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX attestations_tenant_time_idx ON attestations (tenant_id, issued_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX attestations_tenant_root_idx ON attestations (tenant_id, evidence_root)',
  );

  await knex.schema.raw(`
    CREATE FUNCTION attestations_frozen() RETURNS trigger AS $fn$
    BEGIN
      -- The subject was decommissioned. device_id is ON DELETE SET NULL so
      -- that removing a router does not remove the statements made about it;
      -- that referential action is an UPDATE, and it is the ONLY one allowed.
      -- to_jsonb(NEW) - 'device_id' = to_jsonb(OLD) - 'device_id' is a total
      -- check that nothing else moved, so this escape cannot be widened by an
      -- UPDATE that happens to null the device on its way past.
      -- device_uuid and device_name are frozen copies and stay, which is
      -- why the document remains readable afterwards.
      IF TG_OP = 'UPDATE'
         AND NEW.device_id IS NULL AND OLD.device_id IS NOT NULL
         AND to_jsonb(NEW) - 'device_id' = to_jsonb(OLD) - 'device_id' THEN
        RETURN NEW;
      END IF;
      -- The tenant is gone: this is the customer's own cascade.
      IF TG_OP = 'DELETE'
         AND NOT EXISTS (SELECT 1 FROM tenants WHERE id = OLD.tenant_id) THEN
        RETURN OLD;
      END IF;
      RAISE EXCEPTION 'attestations are frozen; row % cannot be %', OLD.id, lower(TG_OP)
        USING ERRCODE = 'restrict_violation';
    END;
    $fn$ LANGUAGE plpgsql
  `);
  // An attestation that can be edited is a document whose reader has to trust
  // the issuer twice. Withdrawing one is issuing a superseding one, not
  // deleting the original.
  await knex.schema.raw(`
    CREATE TRIGGER attestations_frozen_trg
      BEFORE UPDATE OR DELETE ON attestations
      FOR EACH ROW EXECUTE FUNCTION attestations_frozen()
  `);
  await knex.schema.raw('REVOKE UPDATE, DELETE ON attestations FROM PUBLIC');

  // The device, when still present, must belong to the tenant.
  await knex.schema.raw(`
    CREATE FUNCTION attestations_same_tenant() RETURNS trigger AS $fn$
    DECLARE d_tenant integer;
    BEGIN
      IF NEW.device_id IS NULL THEN RETURN NEW; END IF;
      SELECT tenant_id INTO d_tenant FROM devices WHERE id = NEW.device_id;
      IF d_tenant IS DISTINCT FROM NEW.tenant_id THEN
        RAISE EXCEPTION 'attestations: device % belongs to tenant %, not tenant %',
          NEW.device_id, d_tenant, NEW.tenant_id
          USING ERRCODE = 'restrict_violation';
      END IF;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER attestations_same_tenant_trg
      BEFORE INSERT ON attestations
      FOR EACH ROW EXECUTE FUNCTION attestations_same_tenant()
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DROP TRIGGER IF EXISTS attestations_same_tenant_trg ON attestations');
  await knex.schema.raw('DROP TRIGGER IF EXISTS attestations_frozen_trg ON attestations');
  await knex.schema.dropTableIfExists('attestations');
  await knex.schema.raw('DROP FUNCTION IF EXISTS attestations_same_tenant()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS attestations_frozen()');

  await knex.schema.raw('DROP TRIGGER IF EXISTS audit_log_append_only ON audit_log');
  await knex.schema.raw('DROP TRIGGER IF EXISTS audit_log_chain_trg ON audit_log');
  await knex.schema.dropTableIfExists('audit_log');
  await knex.schema.raw('DROP FUNCTION IF EXISTS audit_log_append_only()');
  await knex.schema.raw('DROP FUNCTION IF EXISTS audit_log_chain()');

  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS drift_findings_exception_same_device_trg ON drift_findings',
  );
  await knex.schema.raw('DROP FUNCTION IF EXISTS drift_findings_exception_same_device()');
  await knex.schema.raw(
    'ALTER TABLE drift_findings DROP CONSTRAINT IF EXISTS drift_findings_exception_implies_ignored',
  );
  await knex.schema.raw(
    'ALTER TABLE drift_findings DROP CONSTRAINT IF EXISTS drift_findings_ignore_justified',
  );
  await knex.schema.raw('DROP INDEX IF EXISTS drift_findings_legacy_semkey_idx');
  await knex.schema.raw('DROP INDEX IF EXISTS drift_findings_semkey_path_idx');
  await knex.schema.raw('DROP INDEX IF EXISTS drift_findings_exception_idx');
  // Un-ignore first: the column is about to disappear, and leaving rows with
  // `ignored = true` whose only reason was an exception would silently convert
  // them into unjustified suppressions — the exact state this migration exists
  // to abolish.
  await knex.schema.raw(
    'UPDATE drift_findings SET ignored = false WHERE ignored_by_exception IS NOT NULL',
  );
  await knex.schema.raw('ALTER TABLE drift_findings DROP COLUMN IF EXISTS ignored_by_exception');

  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS drift_exception_reviews_append_only ON drift_exception_reviews',
  );
  await knex.schema.dropTableIfExists('drift_exception_reviews');
  await knex.schema.raw('DROP FUNCTION IF EXISTS drift_exception_reviews_append_only()');

  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS drift_exceptions_same_tenant_trg ON drift_exceptions',
  );
  await knex.schema.dropTableIfExists('drift_exceptions');
  await knex.schema.raw('DROP FUNCTION IF EXISTS drift_exceptions_same_tenant()');

  await knex.schema.raw('DROP FUNCTION IF EXISTS obliwan_enc(text)');
}
