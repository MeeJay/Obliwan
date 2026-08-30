import type { Knex } from 'knex';

/**
 * 023_fix_evidence.ts — the three defects of 019_evidence.ts that live in the
 * SCHEMA rather than in a service. ARCHITECTURE.md §10 (F1, F2).
 *
 * Every statement is idempotent: `DROP CONSTRAINT IF EXISTS` before `ADD`,
 * `DROP TRIGGER IF EXISTS` before `CREATE TRIGGER`, `CREATE OR REPLACE
 * FUNCTION`, and a `SET DEFAULT` that is a no-op the second time.
 *
 * ┌─ 1. `btrim` MEANS "STRIP SPACES", AND ONLY U+0020 IS A SPACE TO IT ───────┐
 * │ `CHECK (length(btrim(justification)) >= 24)` was written to mean "24      │
 * │ characters that are not blank" — the migration's own comment says "a      │
 * │ justification of 200 spaces is not a justification". `btrim(text)` with   │
 * │ one argument removes U+0020 and nothing else, so twenty-four NO-BREAK     │
 * │ SPACES satisfied it. The application mirror used `String.trim()`, which   │
 * │ removes more but not U+200B ZERO WIDTH SPACE. The two guards had a hole   │
 * │ in COMMON, and `POST /api/exceptions` walked straight through it:         │
 * │                                                                           │
 * │   justificationProblem(ZWSP x 30)  -> null      (application: accepted)   │
 * │   createException(...)             -> id = 5    (database:    accepted)   │
 * │   rendered on the screen           -> >>                        <<        │
 * │                                                                           │
 * │ An empty justification on a suppression valid for 300 days is exactly the │
 * │ object F1 exists to abolish, wearing the feature's own clothes.           │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 2. `occurred_at` DEFAULTED TO THE TRANSACTION'S START ───────────────────┐
 * │ `now()` is the transaction timestamp; `seq` is assigned at INSERT time,   │
 * │ under the advisory lock. Two writers therefore produced rows whose time   │
 * │ order contradicted their sequence order:                                  │
 * │                                                                           │
 * │   seq=1 occurred_at=…T01:55:05.809Z                                       │
 * │   seq=2 occurred_at=…T01:55:04.296Z   <-- later in seq, earlier in time   │
 * │                                                                           │
 * │ Harmless to the chain — `seq` is what the hash covers — and confusing to  │
 * │ every reader of an attestation, which prints both. `clock_timestamp()` is │
 * │ read at the moment of the INSERT, in the same order the lock grants it.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 3. THE CHAIN'S ADVISORY LOCK ONLY WORKS IN READ COMMITTED ───────────────┐
 * │ `audit_log_chain()` takes `pg_advisory_xact_lock`, then SELECTs the tail  │
 * │ to compute `seq` and `prev_hash`. That is correct — and correct only      │
 * │ because in READ COMMITTED each statement takes a fresh snapshot AFTER the │
 * │ wait. Under REPEATABLE READ the snapshot predates the wait, both writers  │
 * │ read the same tail, and the loser dies on `audit_log_tenant_seq_uq`:      │
 * │                                                                           │
 * │   === REPEATABLE READ                                                     │
 * │     B fails: duplicate key value violates "audit_log_tenant_seq_uq"       │
 * │                                                                           │
 * │ The chain never forks — the failure is loud — but "if the audit write     │
 * │ fails, the equipment write does not happen" would then be triggered by    │
 * │ plain concurrency, and the message names an index rather than the cause.  │
 * │ Nothing in the tree sets an isolation level today, so this is a dormant   │
 * │ mine. It is disarmed here by REFUSING the insert with the real reason,    │
 * │ from a trigger that fires before the chaining one.                        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * NO SECRET REACHES ANY TABLE HERE (§8.2 / R10): two CHECK constraints, one
 * column default and one guard trigger.
 */

/** Same value as 019. Repeated rather than imported: a migration is a record of
 *  what was executed, and it must not change meaning when a constant does. */
const MIN_JUSTIFICATION = 24;

/**
 * Every character that occupies no ink, as a SQL character class.
 *
 * `[[:space:]]` covers ASCII whitespace and, in a UTF-8 database, the Unicode
 * separators — but not the zero-width family, not the bidi marks, not the word
 * joiner, not the BOM, and not U+2800 BRAILLE PATTERN BLANK, which is
 * whitespace to no library at all and renders as nothing.
 *
 * Built by concatenation from a `U&` literal so that this FILE contains no
 * invisible character: a source file that holds the characters it is trying to
 * catch is a file nobody can review. Postgres stores the constraint with the
 * characters themselves, which is where they belong.
 */
const INVISIBLE = "'[[:space:]' || U&'"
  + '\\00a0\\1680\\180e\\2000-\\200f\\202f\\205f\\2060\\2800\\3000\\feff'
  + "' || ']'";

/** "At least 24 characters that exist, and at least one of them is a letter or
 *  a digit." Punctuation alone says nothing that can be read a year later. */
const JUSTIFIED = (col: string): string =>
  `length(regexp_replace(${col}, ${INVISIBLE}, '', 'g')) >= ${MIN_JUSTIFICATION}`
  + ` AND ${col} ~ '[[:alnum:]]'`;

/**
 * Adds a constraint `NOT VALID`, then validates it only if no existing row
 * fails.
 *
 * `NOT VALID` skips the scan of EXISTING rows; every INSERT and every UPDATE is
 * checked from the moment it is added. So the door is shut either way, and the
 * difference is only whether Postgres marks the constraint as proven for the
 * rows already there.
 *
 * That distinction is the whole point. `drift_exception_reviews` is append-only
 * — 019 installed a trigger that refuses UPDATE outright — so a legacy row
 * whose justification is thirty zero-width spaces cannot be repaired, and
 * rewriting an operator's prose to satisfy a constraint would be falsifying the
 * record this table exists to keep. A migration that aborted on such a row
 * would also block every later migration on that installation. The row is left
 * exactly as it is, visible, and no new one can join it.
 */
async function addChecked(
  knex: Knex,
  table: string,
  name: string,
  predicate: string,
): Promise<void> {
  await knex.schema.raw(`ALTER TABLE ${table} DROP CONSTRAINT IF EXISTS ${name}`);
  await knex.schema.raw(
    `ALTER TABLE ${table} ADD CONSTRAINT ${name} CHECK (${predicate}) NOT VALID`,
  );
  await knex.schema.raw(`
    DO $do$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM ${table} WHERE NOT (${predicate})) THEN
        ALTER TABLE ${table} VALIDATE CONSTRAINT ${name};
      END IF;
    END
    $do$
  `);
}

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // 1 — a justification made of invisible characters is not a justification.
  // ==========================================================================
  await addChecked(
    knex,
    'drift_exceptions',
    'drift_exceptions_justified_chk',
    JUSTIFIED('justification'),
  );
  await addChecked(
    knex,
    'drift_exception_reviews',
    'der_justified_chk',
    JUSTIFIED('justification'),
  );
  await knex.schema.raw(
    'COMMENT ON CONSTRAINT drift_exceptions_justified_chk ON drift_exceptions IS '
      + "$$At least 24 characters that occupy ink, and at least one letter or digit. The "
      + 'character class removes Unicode whitespace, the no-break spaces, the zero-width '
      + 'family, the bidi marks, the word joiner, U+2800 and the BOM. The predecessor used '
      + 'btrim(), which strips U+0020 and nothing else, so 24 no-break spaces passed. '
      + 'Mirror: justificationProblemStrict() in server/src/services/attestation/contract.ts.$$',
  );

  // ── The index the new REVIVE-BY-RULE clause reads ────────────────────────
  //
  // `exception.service.sweep()` grew a clause that hands a finding back when
  // the normalization rule hiding it stops applying, and it walks
  // `ignored_by_rule IS NOT NULL` on every pass. 007 indexed the column in
  // full; the column is NULL for all but a small minority of rows, so the
  // index is mostly a list of NULLs that every INSERT pays to maintain and no
  // query ever reads. Same shape 019 already chose for
  // `drift_findings_exception_idx`, and the same reason.
  await knex.schema.raw(
    'CREATE INDEX IF NOT EXISTS drift_findings_rule_active_idx ON drift_findings '
      + '(ignored_by_rule) WHERE ignored_by_rule IS NOT NULL',
  );
  await knex.schema.raw('DROP INDEX IF EXISTS drift_findings_rule_idx');

  // ==========================================================================
  // 2 — `occurred_at` in the order the rows were actually written.
  // ==========================================================================
  //
  // The column is `timestamptz(3)`, and the hash preimage renders it with
  // `to_char(... 'MS')`, so the extra microseconds `clock_timestamp()` returns
  // are truncated by the column type before the trigger ever reads them. The
  // preimage is therefore unchanged and no existing hash moves.
  await knex.schema.raw(
    'ALTER TABLE audit_log ALTER COLUMN occurred_at SET DEFAULT clock_timestamp()',
  );
  await knex.schema.raw(
    'COMMENT ON COLUMN audit_log.occurred_at IS $$clock_timestamp(), not now(): now() is the '
      + 'TRANSACTION timestamp, while seq is assigned at INSERT under the advisory lock, so the '
      + 'two orders diverged and a reader of an attestation saw a row with a higher seq carrying '
      + 'an earlier time. seq remains the authoritative order; this column is now consistent '
      + 'with it for rows written after migration 023.$$',
  );

  // ==========================================================================
  // 3 — say out loud what the chain depends on, and refuse rather than race.
  // ==========================================================================
  //
  // A SEPARATE trigger rather than an edit to `audit_log_chain()`: that
  // function builds the hash preimage that `shared/src/evidence.ts`
  // re-implements line for line, and re-typing it to insert four lines of guard
  // is a risk with no upside. Named `audit_log_0_isolation_trg` because
  // Postgres fires row triggers of the same event in NAME order, and `0` sorts
  // before `c`: the caller gets the real reason before the chaining trigger has
  // a chance to fail on a unique index.
  await knex.schema.raw(`
    CREATE OR REPLACE FUNCTION audit_log_requires_read_committed() RETURNS trigger AS $fn$
    DECLARE
      iso text;
    BEGIN
      iso := current_setting('transaction_isolation');
      IF iso <> 'read committed' THEN
        RAISE EXCEPTION
          'audit_log cannot be appended to in % isolation: the chain trigger reads the '
          'tail AFTER taking pg_advisory_xact_lock, and only READ COMMITTED gives that '
          'read a snapshot newer than the wait. Under % both writers would see the same '
          'tail and one would die on audit_log_tenant_seq_uq. Use the default isolation '
          'for the transaction that writes audit.',
          iso, iso
          USING ERRCODE = 'invalid_transaction_state';
      END IF;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS audit_log_0_isolation_trg ON audit_log',
  );
  await knex.schema.raw(`
    CREATE TRIGGER audit_log_0_isolation_trg
      BEFORE INSERT ON audit_log
      FOR EACH ROW EXECUTE FUNCTION audit_log_requires_read_committed()
  `);
  await knex.schema.raw(
    'COMMENT ON FUNCTION audit_log_chain() IS $$Assigns seq, prev_hash and hash under a '
      + 'per-tenant advisory lock. DEPENDS ON READ COMMITTED: the tail is read after the lock '
      + 'is granted, and only a per-statement snapshot sees what the previous holder committed. '
      + 'audit_log_0_isolation_trg refuses any other isolation level rather than letting the '
      + 'insert lose a race it cannot win.$$',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw(
    'CREATE INDEX IF NOT EXISTS drift_findings_rule_idx ON drift_findings (ignored_by_rule)',
  );
  await knex.schema.raw('DROP INDEX IF EXISTS drift_findings_rule_active_idx');
  await knex.schema.raw('DROP TRIGGER IF EXISTS audit_log_0_isolation_trg ON audit_log');
  await knex.schema.raw('DROP FUNCTION IF EXISTS audit_log_requires_read_committed()');
  await knex.schema.raw('ALTER TABLE audit_log ALTER COLUMN occurred_at SET DEFAULT now()');

  // Back to 019's wording. Restoring a constraint that accepts 24 no-break
  // spaces is a defect, and `down()` restores the schema and not the judgement:
  // an installation rolling back to 022 must get 022's shape.
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions DROP CONSTRAINT IF EXISTS drift_exceptions_justified_chk',
  );
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions ADD CONSTRAINT drift_exceptions_justified_chk '
      + `CHECK (length(btrim(justification)) >= ${MIN_JUSTIFICATION})`,
  );
  await knex.schema.raw(
    'ALTER TABLE drift_exception_reviews DROP CONSTRAINT IF EXISTS der_justified_chk',
  );
  await knex.schema.raw(
    'ALTER TABLE drift_exception_reviews ADD CONSTRAINT der_justified_chk '
      + `CHECK (length(btrim(justification)) >= ${MIN_JUSTIFICATION})`,
  );
}
