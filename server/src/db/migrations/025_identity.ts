import type { Knex } from 'knex';

/**
 * 025_identity.ts — F6, DETECTION OF A REPLACED DEVICE.
 *
 * ┌─ WHAT THIS SCHEMA IS FOR ─────────────────────────────────────────────────┐
 * │ `deviceBinding.assertTargetBinding()` already asks "is this the box I     │
 * │ recorded?" before every write. Nobody asks "is this the same box it was   │
 * │ LAST TIME?" — and every RouterOS connection the platform opens already    │
 * │ reads the answer (`/system/identity`, `/system/routerboard`,              │
 * │ `/system/resource`), compares it to the registry, and throws it away.     │
 * │                                                                          │
 * │ These three tables keep it. A serial that moves is a chassis that was     │
 * │ swapped: RMA, failure, theft, or a technician who replaced hardware and   │
 * │ told nobody. The day the site comes back with a blank router, the drift   │
 * │ explodes and nothing in the product can say why.                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NINE DECISIONS ──────────────────────────────────────────────────────────┐
 * │                                                                           │
 * │ 1. THREE TABLES, AND THE THIRD IS NOT REDUNDANT.                          │
 * │    `device_identity_observations` is the compressed history — one row per │
 * │    DISTINCT identity seen, with `first_seen_at`/`last_seen_at`/           │
 * │    `seen_count`, the same shape `config_snapshots` uses (007) and for the │
 * │    same reason: a five-minute sweep must not write one row per pass.      │
 * │    `device_identity_events` is the append-only record of the CHANGES.     │
 * │    `device_identity_reference` is the STICKY reference, and it is not     │
 * │    "the last observation": an attribute the box did not answer keeps its  │
 * │    previous value there (trap 1), so the reference and the newest         │
 * │    observation legitimately differ. Deriving one from the other would     │
 * │    mean re-deriving stickiness on every read, from rows a retention job   │
 * │    may one day have trimmed.                                              │
 * │                                                                           │
 * │ 2. `tenant_id` IS ON ALL THREE, IT LEADS EVERY INDEX, AND IT IS TIED TO   │
 * │    THE DEVICE BY A COMPOSITE FOREIGN KEY.                                 │
 * │    `(device_id, tenant_id) REFERENCES devices (id, tenant_id)` — the      │
 * │    target `devices_id_tenant_uq` exists since 017 exactly so this is      │
 * │    possible, and 020 and 021 already use it. A row of tenant A pointing   │
 * │    at a device of tenant B is not "prevented by the service"; it does not │
 * │    exist. ON DELETE CASCADE: deleting a device deletes its identity       │
 * │    history, which is the only defensible behaviour — the history is       │
 * │    ABOUT the device and has no meaning without it.                        │
 * │                                                                           │
 * │ 3. AN OBSERVATION THAT ANSWERED NOTHING IS NOT AN OBSERVATION.            │
 * │    `device_identity_observations_nonempty_chk` refuses a row where all    │
 * │    four attributes are NULL. A failed read is a fact about the network,   │
 * │    not a fact about the box, and storing it would put a row in the        │
 * │    history that a later reader would compare against.                     │
 * │                                                                           │
 * │ 4. NO IP, ANYWHERE, IN ANY OF THE THREE TABLES (arbitrage A6).            │
 * │    Not the tunnel address, not the address dialled, not the caller id.    │
 * │    Identity is what the HARDWARE says it is. `deviceBinding` records the  │
 * │    dialled address in its in-memory assertion for the audit trail and is  │
 * │    explicit that it is NOT part of the identity; this schema does not     │
 * │    even keep that, because a stored address invites the next author to    │
 * │    join on it.                                                            │
 * │                                                                           │
 * │ 5. EVERY VARCHAR IS AT LEAST AS WIDE AS ITS LONGEST LEGAL VALUE, AND THE  │
 * │    NUMBERS ARE IN THE COMMENT NEXT TO THE VOCABULARY.                     │
 * │    `kind` varchar(32) vs `system_identity_renamed` (23). `severity`       │
 * │    varchar(16) vs `critical` (8). `source` varchar(16) vs `binding` (7).  │
 * │    The four identity columns are the EXACT widths 002 gave `devices`      │
 * │    (128/128/128/64) and the exact values of `IDENTITY_MAX_LENGTH` in      │
 * │    `shared/src/identity.ts`, which refuses a longer reading rather than   │
 * │    truncating it — a truncated serial forges a match as easily as a       │
 * │    mismatch.                                                              │
 * │                                                                           │
 * │ 6. THE ONE UNIQUE INDEX CARRIES NO NULLABLE COLUMN.                       │
 * │    `device_identity_events_obs_kind_uq (observation_id, kind)`: both are  │
 * │    NOT NULL, so `NULLS DISTINCT` has nothing to be distinct about and a   │
 * │    plain unique index really constrains. It makes `recordIdentityObser-   │
 * │    vation()` idempotent under a retry: the same observation cannot        │
 * │    produce the same event twice. `device_identity_reference` is keyed on  │
 * │    `device_id` alone (a PRIMARY KEY, therefore NOT NULL) for the same     │
 * │    reason.                                                                │
 * │                                                                           │
 * │ 7. THE EVENT TABLE IS APPEND-ONLY, WITH ONE DOOR: ACKNOWLEDGEMENT.        │
 * │    `device_identity_events_immutable_trg` refuses any UPDATE that touches │
 * │    anything but the three acknowledgement columns, and refuses to         │
 * │    re-acknowledge a row already acknowledged. "This chassis was replaced  │
 * │    on the 3rd" is the record the feature exists to produce; a product     │
 * │    that lets it be edited has produced nothing.                           │
 * │    There is deliberately NO delete trigger: a BEFORE DELETE trigger fires │
 * │    on the FK CASCADE too, so refusing DELETE would make deleting a device │
 * │    fail. The cascade from `devices` is the only path in, and it is the    │
 * │    intended one.                                                          │
 * │                                                                           │
 * │ 8. AN ACKNOWLEDGEMENT NEEDS INK.                                          │
 * │    Same predicate as `023_fix_evidence.ts`: at least 12 characters that   │
 * │    are not invisible, and at least one letter or digit. Acknowledging     │
 * │    "the reference config of this site no longer describes it" with        │
 * │    twenty no-break spaces is the object F1 abolished, in a new table.     │
 * │                                                                           │
 * │ 9. NOTHING HERE INVALIDATES ANYTHING. `invalidates_baseline` is a         │
 * │    BOOLEAN ON AN EVENT and no trigger, no view and no service acts on it. │
 * │    A replaced chassis makes the last `config_snapshots` row stop being a  │
 * │    reference — and the correct response is to SAY SO, because a product   │
 * │    that silently discards the reference config of a site has destroyed    │
 * │    the only evidence of what that site used to be. The read side          │
 * │    (`identityWatch.service.baselineTrust()`) joins these events to        │
 * │    `config_snapshots` and reports; it writes nothing.                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * NO SECRET REACHES ANY OF THESE THREE TABLES (§8.2 / R10). There is no
 * credential column, no jsonb, no free-form blob: the widest thing stored is a
 * serial number, a hostname, a model designation, a firmware version, and the
 * sentence an operator typed when acknowledging an event.
 *
 * NOTHING IN THIS MIGRATION WRITES TO A DEVICE (decision D3). It creates three
 * tables, one trigger function and one trigger.
 */

// -- Vocabularies. Comment gives the LONGEST value; the column is wider. ------
// Mirrors `IDENTITY_EVENT_KINDS` in shared/src/identity.ts. Repeated rather
// than imported: a migration is a record of what was executed and must not
// change meaning when a constant does.
const IDENTITY_EVENT_KINDS =
  "'identity_learned','hardware_replacement','factory_reset',"
  + "'system_identity_renamed','firmware_upgraded','firmware_downgraded',"
  + "'firmware_changed','model_changed'";                                   // 23
const IDENTITY_SEVERITIES = "'info','notice','critical'";                   //  8
const IDENTITY_SOURCES = "'probe','sweep','binding','session','import'";    //  7
const IDENTITY_ATTRIBUTES = "'serial','system_identity','model','os_version'";

/** Mirror of `MIN_IDENTITY_ACK_NOTE` in shared/src/identity.ts. */
const MIN_ACK_NOTE = 12;

/**
 * Every character that occupies no ink, as a SQL character class. Copied
 * verbatim from `023_fix_evidence.ts` so the two constraints say the same
 * thing, and built by concatenation from a `U&` literal so that THIS FILE
 * contains no invisible character.
 */
const INVISIBLE = "'[[:space:]' || U&'"
  + '\\00a0\\1680\\180e\\2000-\\200f\\202f\\205f\\2060\\2800\\3000\\feff'
  + "' || ']'";

/** "At least N characters that exist, and at least one of them is a letter or
 *  a digit." Punctuation alone says nothing that can be read a year later. */
const JUSTIFIED = (col: string, min: number): string =>
  `length(regexp_replace(${col}, ${INVISIBLE}, '', 'g')) >= ${min}`
  + ` AND ${col} ~ '[[:alnum:]]'`;

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // 0. The composite target on `devices` (decision 2).
  // ==========================================================================
  // 017 and 021 both assert this, guarded, for the same reason. Re-asserted
  // here rather than assumed so this migration is correct on a database where
  // 017 was rolled back, and deliberately NOT dropped in `down()`: taking a
  // uniqueness guarantee away from somebody else's foreign keys is not a
  // rollback, it is a break.
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
  // 1. device_identity_observations — the compressed history.
  // ==========================================================================

  await knex.schema.createTable('device_identity_observations', (t) => {
    t.bigIncrements('id').primary();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    // No single-column FK: the composite (device_id, tenant_id) one added
    // below is the real constraint, and a second FK on the same column would
    // only duplicate the cascade.
    t.integer('device_id').notNullable();

    // EXACTLY the widths `002_inventory.ts` gave `devices`, and exactly the
    // values of IDENTITY_MAX_LENGTH in shared/src/identity.ts. All four are
    // nullable because "the box did not answer" is the normal case for at
    // least one of them on every CHR in the fleet.
    t.string('serial', 128).nullable();
    t.string('system_identity', 128).nullable();
    t.string('model', 128).nullable();
    t.string('os_version', 64).nullable();

    // Who looked. Set by the server at the call site, NEVER from a request
    // body — a caller able to choose it could dress a hand-made observation
    // as a background fact.
    t.string('source', 16).notNullable();

    // clock_timestamp(), not now(): now() is the TRANSACTION timestamp, and
    // 023 records at length why that produced rows whose time order
    // contradicted their sequence order.
    t.timestamp('first_seen_at', { precision: 3, useTz: true })
      .notNullable().defaultTo(knex.raw('clock_timestamp()'));
    t.timestamp('last_seen_at', { precision: 3, useTz: true })
      .notNullable().defaultTo(knex.raw('clock_timestamp()'));
    // Bumped instead of inserting a duplicate row (decision 1). "This identity
    // has been true since first_seen_at and was last confirmed at
    // last_seen_at" is the whole value of the deduplication.
    t.integer('seen_count').notNullable().defaultTo(1);
  });

  await knex.schema.raw(
    'ALTER TABLE device_identity_observations ADD CONSTRAINT device_identity_observations_device_fk '
      + 'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE device_identity_observations ADD CONSTRAINT device_identity_observations_source_chk '
      + `CHECK (source IN (${IDENTITY_SOURCES}))`,
  );
  // DECISION 3. A read where the box answered nothing at all is a network
  // event, not an identity, and must not enter the history.
  await knex.schema.raw(
    'ALTER TABLE device_identity_observations ADD CONSTRAINT device_identity_observations_nonempty_chk '
      + 'CHECK (serial IS NOT NULL OR system_identity IS NOT NULL '
      + 'OR model IS NOT NULL OR os_version IS NOT NULL)',
  );
  await knex.schema.raw(
    'ALTER TABLE device_identity_observations ADD CONSTRAINT device_identity_observations_span_chk '
      + 'CHECK (last_seen_at >= first_seen_at AND seen_count > 0)',
  );
  // tenant_id leads both indexes; neither is usable to walk another customer.
  await knex.schema.raw(
    'CREATE INDEX device_identity_observations_device_idx ON device_identity_observations '
      + '(tenant_id, device_id, id DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX device_identity_observations_seen_idx ON device_identity_observations '
      + '(tenant_id, last_seen_at DESC)',
  );
  await knex.schema.raw(
    'COMMENT ON TABLE device_identity_observations IS $$F6. One row per DISTINCT identity a '
      + 'device has been seen with, not one row per read: a five-minute sweep bumps '
      + 'last_seen_at/seen_count on the existing row. NULL means "the box did not answer this '
      + 'attribute" and is never compared against (trap 1: a CHR has no RouterBOARD and '
      + 'therefore no serial, forever). Contains no address and no secret.$$',
  );

  // ==========================================================================
  // 2. device_identity_reference — the STICKY reference (decision 1).
  // ==========================================================================

  await knex.schema.createTable('device_identity_reference', (t) => {
    // One row per device, and the PRIMARY KEY says so. NOT NULL by
    // construction, so decision 6 (no nullable column in a unique key) holds
    // without a partial index.
    t.integer('device_id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('serial', 128).nullable();
    t.string('system_identity', 128).nullable();
    t.string('model', 128).nullable();
    t.string('os_version', 64).nullable();

    // When each sticky value was last actually CONFIRMED BY A BOX, as opposed
    // to carried forward. Without this, "serial X" on a device that has not
    // answered a serial in six months reads exactly like one confirmed a
    // minute ago, and an operator cannot tell how much the reference is worth.
    //
    // NULL WITH A NON-NULL VALUE IS LEGAL AND MEANINGFUL: it is a value that
    // came from the `devices` registry (typed by an operator, or learned by
    // `assertTargetBinding()` before F6 existed) and that no box has confirmed
    // to F6 yet. The CHECK below therefore forbids the reverse only — a
    // timestamp with no value, which would be a memory of nothing.
    t.timestamp('serial_seen_at', { precision: 3, useTz: true }).nullable();
    t.timestamp('system_identity_seen_at', { precision: 3, useTz: true }).nullable();

    t.timestamp('first_observed_at', { precision: 3, useTz: true })
      .notNullable().defaultTo(knex.raw('clock_timestamp()'));
    t.timestamp('last_observed_at', { precision: 3, useTz: true })
      .notNullable().defaultTo(knex.raw('clock_timestamp()'));
    t.bigInteger('last_observation_id').nullable()
      .references('id').inTable('device_identity_observations').onDelete('SET NULL');

    t.bigInteger('observation_count').notNullable().defaultTo(0);
    // How many times the box answered WITHOUT a usable serial. This is trap 1
    // made visible: a device with a high count here is one whose serial
    // evidence is thin, and an operator reading a `hardware_replacement` on it
    // deserves to know that before acting.
    t.bigInteger('blank_serial_count').notNullable().defaultTo(0);
  });

  await knex.schema.raw(
    'ALTER TABLE device_identity_reference ADD CONSTRAINT device_identity_reference_device_fk '
      + 'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  // A timestamp with no value behind it is a memory of nothing. The reverse —
  // a value with no timestamp — is the registry-seeded case and is legal; see
  // the column comment above.
  await knex.schema.raw(
    'ALTER TABLE device_identity_reference ADD CONSTRAINT device_identity_reference_seen_chk '
      + 'CHECK ((serial IS NOT NULL OR serial_seen_at IS NULL) '
      + 'AND (system_identity IS NOT NULL OR system_identity_seen_at IS NULL))',
  );
  await knex.schema.raw(
    'ALTER TABLE device_identity_reference ADD CONSTRAINT device_identity_reference_counts_chk '
      + 'CHECK (observation_count >= 0 AND blank_serial_count >= 0 '
      + 'AND blank_serial_count <= observation_count '
      + 'AND last_observed_at >= first_observed_at)',
  );
  await knex.schema.raw(
    'CREATE INDEX device_identity_reference_tenant_idx ON device_identity_reference '
      + '(tenant_id, last_observed_at DESC)',
  );
  await knex.schema.raw(
    'COMMENT ON TABLE device_identity_reference IS $$F6. What we believe this device to BE, '
      + 'carried forward attribute by attribute: an attribute the box did not answer keeps its '
      + 'previous value instead of being overwritten with NULL (trap 1). This is why the '
      + 'reference is a table and not "the newest row of device_identity_observations". It is '
      + 'NOT authoritative over devices.serial — nothing in F6 writes to devices.$$',
  );

  // ==========================================================================
  // 3. device_identity_events — the append-only record of the CHANGES.
  // ==========================================================================

  await knex.schema.createTable('device_identity_events', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable();
    // The observation that produced this event. NOT NULL: an event with no
    // observation behind it is an assertion with no evidence.
    t.bigInteger('observation_id').notNullable()
      .references('id').inTable('device_identity_observations').onDelete('CASCADE');

    t.string('kind', 32).notNullable();      // longest legal value: 23
    t.string('severity', 16).notNullable();  // longest legal value:  8
    // Explicit array rather than jsonb: the set of legal members is closed and
    // a CHECK can say so, where a jsonb column is a place future authors put
    // things (decision 9 of §8.2 — no secret can reach a column whose contents
    // are constrained to four literal words).
    t.specificType('changed_attributes', 'text[]').notNullable();

    // BEFORE and AFTER, as typed columns of the same widths as the
    // observation. No jsonb, no blob: eight columns that a reviewer can read.
    t.string('previous_serial', 128).nullable();
    t.string('observed_serial', 128).nullable();
    t.string('previous_system_identity', 128).nullable();
    t.string('observed_system_identity', 128).nullable();
    t.string('previous_model', 128).nullable();
    t.string('observed_model', 128).nullable();
    t.string('previous_os_version', 64).nullable();
    t.string('observed_os_version', 64).nullable();

    // DECISION 9. A FLAG. Nothing acts on it.
    t.boolean('invalidates_baseline').notNullable().defaultTo(false);
    t.text('reason').notNullable();

    t.timestamp('detected_at', { precision: 3, useTz: true })
      .notNullable().defaultTo(knex.raw('clock_timestamp()'));

    // --- the one legal mutation (decision 7) ---------------------------------
    t.timestamp('acknowledged_at', { precision: 3, useTz: true }).nullable();
    // SET NULL and not CASCADE: deleting the operator who reviewed a chassis
    // replacement must not delete the review.
    t.integer('acknowledged_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.text('acknowledgement').nullable();
  });

  await knex.schema.raw(
    'ALTER TABLE device_identity_events ADD CONSTRAINT device_identity_events_device_fk '
      + 'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE device_identity_events ADD CONSTRAINT device_identity_events_kind_chk '
      + `CHECK (kind IN (${IDENTITY_EVENT_KINDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE device_identity_events ADD CONSTRAINT device_identity_events_severity_chk '
      + `CHECK (severity IN (${IDENTITY_SEVERITIES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE device_identity_events ADD CONSTRAINT device_identity_events_changed_chk '
      + 'CHECK (cardinality(changed_attributes) > 0 '
      + `AND changed_attributes <@ ARRAY[${IDENTITY_ATTRIBUTES}]::text[])`,
  );
  // The two kinds that mean "the reference config no longer describes this
  // box", and the only two allowed to say so. Mirrors
  // `isBaselineInvalidatingKind()` in shared/src/identity.ts: if a later author
  // sets the flag on a rename, the INSERT fails instead of quietly telling an
  // operator their site has no reference.
  await knex.schema.raw(
    'ALTER TABLE device_identity_events ADD CONSTRAINT device_identity_events_invalidation_chk '
      + "CHECK (invalidates_baseline = (kind IN ('hardware_replacement','factory_reset')))",
  );
  // Acknowledgement is all-or-nothing on (when, what was written).
  // `acknowledged_by` is NOT in the pair: it becomes NULL when the user row is
  // deleted, and the review survives that.
  await knex.schema.raw(
    'ALTER TABLE device_identity_events ADD CONSTRAINT device_identity_events_ack_pair_chk '
      + 'CHECK ((acknowledged_at IS NULL AND acknowledgement IS NULL) '
      + 'OR (acknowledged_at IS NOT NULL AND acknowledgement IS NOT NULL))',
  );
  // DECISION 8 — the same predicate as 023, at the same strength.
  await knex.schema.raw(
    'ALTER TABLE device_identity_events ADD CONSTRAINT device_identity_events_ack_justified_chk '
      + `CHECK (acknowledgement IS NULL OR (${JUSTIFIED('acknowledgement', MIN_ACK_NOTE)}))`,
  );

  // DECISION 6 — the one unique index, on two NOT NULL columns.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX device_identity_events_obs_kind_uq ON device_identity_events '
      + '(observation_id, kind)',
  );
  await knex.schema.raw(
    'CREATE INDEX device_identity_events_tenant_at_idx ON device_identity_events '
      + '(tenant_id, detected_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX device_identity_events_device_idx ON device_identity_events '
      + '(tenant_id, device_id, detected_at DESC)',
  );
  // THE hot read: "does this device have an unreviewed reason to distrust its
  // reference config?" Partial, because the answer is NO for all but a handful
  // of rows and an index full of the others is paid for on every INSERT.
  await knex.schema.raw(
    'CREATE INDEX device_identity_events_pending_idx ON device_identity_events '
      + '(tenant_id, device_id, detected_at DESC) '
      + 'WHERE acknowledged_at IS NULL AND invalidates_baseline',
  );

  // -- DECISION 7: append-only, with acknowledgement as the one door. --------
  await knex.schema.raw(`
    CREATE OR REPLACE FUNCTION device_identity_events_immutable() RETURNS trigger AS $fn$
    BEGIN
      IF NEW.id IS DISTINCT FROM OLD.id
         OR NEW.uuid IS DISTINCT FROM OLD.uuid
         OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
         OR NEW.device_id IS DISTINCT FROM OLD.device_id
         OR NEW.observation_id IS DISTINCT FROM OLD.observation_id
         OR NEW.kind IS DISTINCT FROM OLD.kind
         OR NEW.severity IS DISTINCT FROM OLD.severity
         OR NEW.changed_attributes IS DISTINCT FROM OLD.changed_attributes
         OR NEW.previous_serial IS DISTINCT FROM OLD.previous_serial
         OR NEW.observed_serial IS DISTINCT FROM OLD.observed_serial
         OR NEW.previous_system_identity IS DISTINCT FROM OLD.previous_system_identity
         OR NEW.observed_system_identity IS DISTINCT FROM OLD.observed_system_identity
         OR NEW.previous_model IS DISTINCT FROM OLD.previous_model
         OR NEW.observed_model IS DISTINCT FROM OLD.observed_model
         OR NEW.previous_os_version IS DISTINCT FROM OLD.previous_os_version
         OR NEW.observed_os_version IS DISTINCT FROM OLD.observed_os_version
         OR NEW.invalidates_baseline IS DISTINCT FROM OLD.invalidates_baseline
         OR NEW.reason IS DISTINCT FROM OLD.reason
         OR NEW.detected_at IS DISTINCT FROM OLD.detected_at
      THEN
        RAISE EXCEPTION
          'device_identity_events is append-only: only acknowledged_at, acknowledged_by '
          'and acknowledgement may be written after the INSERT. "This chassis was replaced" '
          'is the record F6 exists to produce, and a record that can be edited is not one.'
          USING ERRCODE = 'restrict_violation';
      END IF;
      IF OLD.acknowledged_at IS NOT NULL
         AND (NEW.acknowledged_at IS DISTINCT FROM OLD.acknowledged_at
              OR NEW.acknowledgement IS DISTINCT FROM OLD.acknowledgement)
      THEN
        RAISE EXCEPTION
          'identity event % was already acknowledged at %: an acknowledgement is written '
          'once. Record a new observation if the situation changed.',
          OLD.id, OLD.acknowledged_at
          USING ERRCODE = 'restrict_violation';
      END IF;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS device_identity_events_immutable_trg ON device_identity_events',
  );
  await knex.schema.raw(`
    CREATE TRIGGER device_identity_events_immutable_trg
      BEFORE UPDATE ON device_identity_events
      FOR EACH ROW EXECUTE FUNCTION device_identity_events_immutable()
  `);
  await knex.schema.raw(
    'COMMENT ON TABLE device_identity_events IS $$F6. Append-only. One row per detected '
      + 'identity CHANGE, classified by classifyIdentityChange() in shared/src/identity.ts. '
      + 'invalidates_baseline is a FLAG AND NOTHING ELSE: a replaced chassis means the last '
      + 'config_snapshots row stops being a reference, and F6 says so rather than deleting it. '
      + 'Only acknowledged_at / acknowledged_by / acknowledgement may ever be written after the '
      + 'INSERT, once, and the trigger enforces it.$$',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS device_identity_events_immutable_trg ON device_identity_events',
  );
  await knex.schema.raw('DROP FUNCTION IF EXISTS device_identity_events_immutable()');
  await knex.schema.dropTableIfExists('device_identity_events');
  await knex.schema.dropTableIfExists('device_identity_reference');
  await knex.schema.dropTableIfExists('device_identity_observations');
  // `devices_id_tenant_uq` is NOT dropped: 017 owns it, 020 and 021 depend on
  // it, and removing it here would break their foreign keys.
}
