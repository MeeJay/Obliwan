import type { Knex } from 'knex';

/**
 * 002_inventory.ts — M2 inventory, credential vault and transport health.
 *
 * Implements section 3.2 of ARCHITECTURE.md:
 *   sites, devices, device_transports, device_capabilities, device_health,
 *   discoveries, ppp_sessions, reachability_verdicts.
 *
 * Three things in here are load-bearing and must not be "simplified" later:
 *
 *  - `device_transports.key_version` (arbitrage A3 / risk R8). The column
 *    exists from day one even though only version 1 is ever written today.
 *    Adding it after 300 devices have been provisioned means re-encrypting a
 *    live fleet with no way to tell which rows have already been migrated.
 *
 *  - `discoveries` has NO tenant_id and NO automatic binding. A discovery is a
 *    quarantine record. Auto-binding on tunnel IP is exactly risk R4: PPP pools
 *    reassign addresses, and a stale address would push customer A's config to
 *    customer B's router. Binding is a human gesture, and it is audited
 *    (`reviewed_by`).
 *
 *  - `device_health` persists `circuit_state` / `backoff_ms` / `next_retry_at`.
 *    An in-memory breaker resets on every deploy, so a server restart would
 *    stampede a fleet of 300 unreachable devices (risk R5).
 *
 * Identity is `ppp_username` + `system_identity` + `serial` (D5). The IP
 * columns are `inet`, not text: they carry no identity and exist so the
 * arbiter knows where to dial today, nothing more.
 */

// Kept in lockstep with the unions in @obliwan/shared/device.ts. They are
// inlined as literals rather than imported so that this migration keeps
// describing the schema as it was on the day it ran, whatever the shared
// package does later — a migration must never change meaning retroactively.
const BRANDS = "'mikrotik','draytek','zyxel','sonicwall'";
const FAMILIES =
  "'mikrotik_routeros6','mikrotik_routeros7','draytek_vigor'," +
  "'zyxel_nebula','zyxel_standalone','zyxel_cpe','sonicwall_sonicos'";
const TRANSPORTS = "'routeros_api','ssh','rest','cwmp','snmp'";
const DEVICE_ROLES = "'cpe','concentrator'";
const DEVICE_STATUSES = "'pending','active','quarantined','disabled'";
const DISCOVERY_STATES = "'pending','bound','ignored'";
const CIRCUIT_STATES = "'closed','open','half_open'";
const VERDICTS =
  "'UP','TUNNEL_DOWN_SITE_UP','SITE_DOWN','WAN_FAILOVER'," +
  "'CONCENTRATOR_DEGRADED','UNREACHABLE'";

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // sites — the customer premises. Carries the maintenance window that gates
  // every push (C8).
  // ==========================================================================

  await knex.schema.createTable('sites', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable().defaultTo(1)
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('code', 64).notNullable();
    t.string('name', 255).notNullable();
    t.text('address').nullable();
    t.text('contact').nullable();
    t.string('timezone', 64).notNullable().defaultTo('Europe/Paris');

    // { days: [...], start: 'HH:MM', end: 'HH:MM', tz } — shape owned by the
    // change scheduler at M8, kept opaque here on purpose.
    t.jsonb('maintenance_window').nullable();

    t.timestamps(true, true);

    // Site codes are unique PER TENANT, not globally: two MSP customers are
    // both entitled to a site called "SIEGE".
    t.unique(['tenant_id', 'code']);
    t.index('tenant_id');
  });

  // ==========================================================================
  // devices — the fleet registry.
  // ==========================================================================

  await knex.schema.createTable('devices', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable().defaultTo(1)
      .references('id').inTable('tenants').onDelete('CASCADE');

    // A device may exist before it is filed under a site or a group (it lands
    // there when an operator binds its discovery), hence nullable + SET NULL:
    // deleting a site must never delete the routers that were in it.
    t.integer('site_id').nullable()
      .references('id').inTable('sites').onDelete('SET NULL');
    t.integer('group_id').unsigned().nullable()
      .references('id').inTable('device_groups').onDelete('SET NULL');

    t.string('name', 255).notNullable();
    t.string('brand', 32).notNullable();
    t.string('family', 48).notNullable();
    t.string('model', 128).nullable();
    t.string('serial', 128).nullable();
    t.string('os_version', 64).nullable();

    // 24, not 8: 'concentrator' is 12 characters. The column was sized for the
    // old value 'chr' — which was a MikroTik PRODUCT name, not a function (§8.5)
    // — and a rename that only touched the CHECK constraint would have compiled,
    // migrated, and then failed every INSERT with "value too long". The width is
    // deliberately loose: the next role name is not going to be shorter.
    t.string('role', 24).notNullable().defaultTo('cpe');

    // Self-reference: every CPE points at the CHR that terminates its tunnel.
    // RESTRICT, not CASCADE — deleting a concentrator that still has children
    // would silently orphan the presence source of truth for a whole fleet.
    t.integer('concentrator_id').nullable()
      .references('id').inTable('devices').onDelete('RESTRICT');

    // --- Identity (D5) -----------------------------------------------------
    // ppp_username is globally unique: it is the key the CHR knows the device
    // by, and two devices sharing one would make presence ambiguous.
    t.string('ppp_username', 128).nullable().unique();
    t.string('system_identity', 128).nullable();

    // --- Addressing: where to dial TODAY. Never an identity. ---------------
    t.specificType('tunnel_ip', 'inet').nullable();
    t.specificType('wan_public_ip', 'inet').nullable();
    t.specificType('source_ip_hint', 'inet').nullable();

    t.string('status', 16).notNullable().defaultTo('pending');
    // Distinct from status: a device can be `active` (identity confirmed,
    // readable) yet not managed (no plan may target it).
    t.boolean('is_managed').notNullable().defaultTo(false);

    t.timestamp('first_seen_at', { useTz: true }).nullable();
    t.timestamp('last_seen_at', { useTz: true }).nullable();

    t.text('notes').nullable();
    t.timestamps(true, true);

    t.index(['tenant_id', 'status']);
    t.index('site_id');
    t.index('group_id');
    t.index('concentrator_id');
    t.index('tunnel_ip');
  });

  // UNIQUE(brand, serial) — risk R4's second half. A partial index rather than
  // a table constraint: `serial` is unknown until the first successful probe,
  // and Postgres would happily accept a hundred rows with NULL serial under a
  // plain UNIQUE, which is right, but being explicit documents the intent.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX devices_brand_serial_uniq ON devices (brand, serial) ' +
      'WHERE serial IS NOT NULL',
  );

  await knex.schema.raw(
    `ALTER TABLE devices ADD CONSTRAINT devices_brand_chk CHECK (brand IN (${BRANDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE devices ADD CONSTRAINT devices_family_chk CHECK (family IN (${FAMILIES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE devices ADD CONSTRAINT devices_role_chk CHECK (role IN (${DEVICE_ROLES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE devices ADD CONSTRAINT devices_status_chk CHECK (status IN (${DEVICE_STATUSES}))`,
  );
  // A device cannot be its own concentrator, and a concentrator does not need
  // one. Cheap to state, expensive to discover as an infinite loop in the
  // presence reconciler.
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_concentrator_not_self_chk ' +
      'CHECK (concentrator_id IS NULL OR concentrator_id <> id)',
  );

  // ==========================================================================
  // device_transports — one channel = one row.
  // ==========================================================================

  await knex.schema.createTable('device_transports', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    t.string('transport', 16).notNullable();
    t.boolean('enabled').notNullable().defaultTo(true);
    // Lower wins. The arbiter walks transports in this order.
    t.integer('priority').notNullable().defaultTo(100);

    // Host is nullable: for `cwmp` the CPE dials US, there is nothing to dial.
    t.string('host', 255).nullable();
    t.integer('port').nullable();
    t.string('username', 128).nullable();

    // --- Vault columns (A3). Ciphertext only, never a plaintext fallback. ---
    // Format is produced by secretVault.service.ts:
    //   v1:<key_version>:<iv b64>:<tag b64>:<ciphertext b64>
    t.text('secret_enc').nullable();
    t.text('private_key_enc').nullable();
    // Which OBLIWAN_ENCRYPTION_KEY generation encrypted the columns above.
    // Present from day one so a rotation can proceed row by row instead of
    // requiring a fleet-wide stop-the-world re-encryption (risk R8).
    t.integer('key_version').notNullable().defaultTo(1);

    t.boolean('use_tls').notNullable().defaultTo(false);
    // Pinned on the FIRST successful handshake; a later mismatch is a hard
    // failure, not a warning (risk R9 — API 8728 in clear over transit).
    t.string('tls_fingerprint_sha256', 95).nullable();

    // Transport-specific knobs (snmp version/context, ssh algos, rest base
    // path...). NEVER a secret: those belong in the *_enc columns only.
    t.jsonb('params').notNullable().defaultTo('{}');

    t.timestamp('last_ok_at', { useTz: true }).nullable();
    // Redacted message only. Section 8.2: no secret ever reaches a persisted
    // value outside device_transports.secret_enc.
    t.text('last_error').nullable();

    t.timestamps(true, true);

    t.unique(['device_id', 'transport']);
    t.index(['device_id', 'enabled']);
  });

  await knex.schema.raw(
    'ALTER TABLE device_transports ADD CONSTRAINT device_transports_transport_chk ' +
      `CHECK (transport IN (${TRANSPORTS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE device_transports ADD CONSTRAINT device_transports_key_version_chk ' +
      'CHECK (key_version >= 1)',
  );
  await knex.schema.raw(
    'ALTER TABLE device_transports ADD CONSTRAINT device_transports_port_chk ' +
      'CHECK (port IS NULL OR (port > 0 AND port <= 65535))',
  );

  // ==========================================================================
  // device_capabilities — the gap between what the FAMILY can do and what THIS
  // unit actually answered. The family defaults live in code; only the delta
  // is persisted (risk R11: never a hard-coded path, always the matrix).
  // ==========================================================================

  await knex.schema.createTable('device_capabilities', (t) => {
    t.increments('id').primary();
    t.integer('device_id').notNullable().unique()
      .references('id').inTable('devices').onDelete('CASCADE');

    // Denormalised from devices.family: the row records which family baseline
    // the overrides were measured against, so a re-classified device does not
    // inherit stale deltas.
    t.string('family', 48).notNullable();

    // { canReadVlans: false, ... } — Partial<Record<DeviceCapabilityFlag, boolean>>
    t.jsonb('observed_overrides').notNullable().defaultTo('{}');
    t.jsonb('working_transports').notNullable().defaultTo('[]');
    t.jsonb('failed_transports').notNullable().defaultTo('[]');

    t.timestamp('last_probe_at', { useTz: true }).nullable();
    t.integer('probe_failure_count').notNullable().defaultTo(0);

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE device_capabilities ADD CONSTRAINT device_capabilities_family_chk ' +
      `CHECK (family IN (${FAMILIES}))`,
  );

  // ==========================================================================
  // device_health — backoff and circuit breaker, PERSISTED.
  // ==========================================================================

  await knex.schema.createTable('device_health', (t) => {
    t.increments('id').primary();
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');
    // One breaker per channel: SSH being down says nothing about SNMP.
    t.string('transport', 16).notNullable();

    // Cheap liveness label for the UI ('ok' | 'degraded' | 'down' | 'unknown').
    t.string('conn_state', 16).notNullable().defaultTo('unknown');

    t.string('circuit_state', 16).notNullable().defaultTo('closed');
    t.integer('consecutive_failures').notNullable().defaultTo(0);
    t.integer('backoff_ms').notNullable().defaultTo(0);
    t.timestamp('next_retry_at', { useTz: true }).nullable();

    t.integer('last_rtt_ms').nullable();
    t.timestamp('last_ok_at', { useTz: true }).nullable();
    t.timestamp('last_failure_at', { useTz: true }).nullable();
    // Redacted. See section 8.2.
    t.text('last_error').nullable();

    // Kill-switch per channel, independent of device_transports.enabled: the
    // operator disables the transport, the arbiter disables the health row.
    t.boolean('enabled').notNullable().defaultTo(true);

    t.timestamps(true, true);

    t.unique(['device_id', 'transport']);
  });

  // The scheduler's hot path: "which channels are due for a retry right now".
  await knex.schema.raw(
    'CREATE INDEX device_health_due_idx ON device_health (enabled, next_retry_at)',
  );
  await knex.schema.raw(
    'ALTER TABLE device_health ADD CONSTRAINT device_health_transport_chk ' +
      `CHECK (transport IN (${TRANSPORTS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE device_health ADD CONSTRAINT device_health_circuit_chk ' +
      `CHECK (circuit_state IN (${CIRCUIT_STATES}))`,
  );

  // ==========================================================================
  // discoveries — QUARANTINE. No tenant_id, no automatic binding (risk R4).
  // ==========================================================================

  await knex.schema.createTable('discoveries', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    t.integer('concentrator_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    // What the CHR told us. Raw, unjudged.
    t.string('ppp_username', 128).notNullable();
    t.specificType('remote_address', 'inet').nullable();
    t.specificType('caller_ip', 'inet').nullable();
    t.string('profile', 128).nullable();
    t.text('ppp_comment').nullable();
    // Anything else /ppp/secret or /ppp/active carried, kept verbatim so an
    // operator can identify the box without a second round trip.
    t.jsonb('raw').notNullable().defaultTo('{}');

    // Starts at 'pending' and STAYS there until a human acts. There is no code
    // path in M2 that writes 'bound' without an operator behind it.
    t.string('state', 16).notNullable().defaultTo('pending');
    t.integer('bound_device_id').nullable()
      .references('id').inTable('devices').onDelete('SET NULL');
    t.integer('reviewed_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('reviewed_at', { useTz: true }).nullable();

    t.timestamp('first_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('last_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    t.timestamps(true, true);

    // One quarantine row per (concentrator, ppp_username): the CHR re-announces
    // the same secret on every reconnect, and it must refresh the row rather
    // than pile up duplicates.
    t.unique(['concentrator_id', 'ppp_username']);
    // The Discoveries page: "everything still pending on this CHR".
    t.index(['concentrator_id', 'state']);
  });

  await knex.schema.raw(
    'ALTER TABLE discoveries ADD CONSTRAINT discoveries_state_chk ' +
      `CHECK (state IN (${DISCOVERY_STATES}))`,
  );
  // 'bound' without a device is a half-finished binding — the exact state that
  // makes a stale tunnel IP dangerous. Refuse it at the database.
  await knex.schema.raw(
    'ALTER TABLE discoveries ADD CONSTRAINT discoveries_bound_has_device_chk ' +
      "CHECK (state <> 'bound' OR bound_device_id IS NOT NULL)",
  );

  // ... and make that CHECK survive the deletion of a device.
  //
  // THE BUG THIS FIXES: `bound_device_id` is ON DELETE SET NULL, so deleting a
  // device NULLs the column of every discovery bound to it — while the row is
  // still `state = 'bound'`, which the CHECK above forbids. Postgres therefore
  // refused the DELETE outright: an operator retiring a router got an opaque
  // constraint violation for a perfectly reasonable request. The two rules
  // were written independently and contradicted each other.
  //
  // THE RESOLUTION, and it is a semantic one rather than a patch: a discovery
  // whose device is gone means that PPP username is UNCLAIMED again. It goes
  // back to `pending` and reappears on the review screen, where a human
  // decides what it is now. The alternatives are worse — cascading the delete
  // loses `first_seen_at` and the whole history of the account until the next
  // CHR scan re-finds it, and dropping the CHECK would legalise exactly the
  // half-finished binding (risk R4) it exists to forbid.
  //
  // `reviewed_by` / `reviewed_at` are cleared with it: the review that is
  // being undone was a review of a binding that no longer exists, and leaving
  // a name attached to it would credit somebody with a decision they did not
  // make.
  //
  // A BEFORE UPDATE trigger is the right place because the FK's SET NULL IS an
  // UPDATE on this table: the trigger rewrites the row in the same statement,
  // before the CHECK is evaluated. It also covers the identical application
  // gesture (clearing `bound_device_id` by hand), which is the same event.
  await knex.schema.raw(`
    CREATE FUNCTION discoveries_unbind_on_device_delete() RETURNS trigger AS $$
    BEGIN
      IF OLD.bound_device_id IS NOT NULL
         AND NEW.bound_device_id IS NULL
         AND NEW.state = 'bound' THEN
        NEW.state := 'pending';
        NEW.reviewed_by := NULL;
        NEW.reviewed_at := NULL;
        NEW.updated_at := now();
      END IF;
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER discoveries_unbind_trg
      BEFORE UPDATE ON discoveries
      FOR EACH ROW EXECUTE FUNCTION discoveries_unbind_on_device_delete()
  `);

  // ==========================================================================
  // ppp_sessions — presence history: flaps, public-IP changes, SLA.
  // ==========================================================================

  await knex.schema.createTable('ppp_sessions', (t) => {
    t.bigIncrements('id').primary();

    t.integer('concentrator_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');
    // Nullable: a session can be observed for a username not yet bound to any
    // device. The history is kept anyway — it is what proves, later, that the
    // site was up while the tunnel was down.
    t.integer('device_id').nullable()
      .references('id').inTable('devices').onDelete('SET NULL');

    t.string('ppp_username', 128).notNullable();
    t.specificType('tunnel_ip', 'inet').nullable();
    t.specificType('caller_ip', 'inet').nullable();

    t.timestamp('started_at', { useTz: true }).notNullable();
    // NULL = still open. Exactly one open session per username at a time.
    t.timestamp('ended_at', { useTz: true }).nullable();
    t.integer('duration_seconds').nullable();
    t.string('disconnect_reason', 128).nullable();

    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    t.index(['device_id', 'started_at']);
    t.index(['ppp_username', 'started_at']);
  });

  // Reconciliation (the 60 s sweep) relies on being able to find, and only
  // find, ONE open session per username. Enforced rather than assumed.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX ppp_sessions_open_uniq ON ppp_sessions ' +
      '(concentrator_id, ppp_username) WHERE ended_at IS NULL',
  );

  // ==========================================================================
  // reachability_verdicts — K7. Append-only time series.
  // ==========================================================================

  await knex.schema.createTable('reachability_verdicts', (t) => {
    t.bigIncrements('id').primary();
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');
    t.timestamp('ts', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    // Three-valued on purpose: NULL = "not measured", which is NOT false.
    // Collapsing the two is how a blind observer invents a SITE_DOWN.
    t.boolean('ppp_up').nullable();
    t.boolean('snmp_ok').nullable();
    t.boolean('external_ok').nullable();
    t.boolean('cwmp_recent').nullable();

    t.string('verdict', 32).notNullable();
    // 0..1 — how many independent signals actually backed the verdict.
    t.decimal('confidence', 3, 2).notNullable().defaultTo(0);
    // Which truth-table row fired, for debugging the verdict itself.
    t.string('reason', 128).nullable();
  });

  // "Latest verdict for this device" and "history of this device" — the only
  // two access patterns, both served by this one index.
  await knex.schema.raw(
    'CREATE INDEX reachability_verdicts_device_ts_idx ON reachability_verdicts ' +
      '(device_id, ts DESC)',
  );
  await knex.schema.raw(
    'ALTER TABLE reachability_verdicts ADD CONSTRAINT reachability_verdicts_verdict_chk ' +
      `CHECK (verdict IN (${VERDICTS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE reachability_verdicts ADD CONSTRAINT reachability_verdicts_confidence_chk ' +
      'CHECK (confidence >= 0 AND confidence <= 1)',
  );
}

export async function down(knex: Knex): Promise<void> {
  // Reverse order. Everything below references `devices`, and `devices`
  // references `sites`, so nothing here needs an explicit FK drop.
  await knex.schema.dropTableIfExists('reachability_verdicts');
  await knex.schema.dropTableIfExists('ppp_sessions');
  // The trigger goes with its table; the FUNCTION does not, so it is dropped
  // by name or `migrate:latest` fails on a second run with 42723.
  await knex.schema.dropTableIfExists('discoveries');
  await knex.schema.raw('DROP FUNCTION IF EXISTS discoveries_unbind_on_device_delete()');
  await knex.schema.dropTableIfExists('device_health');
  await knex.schema.dropTableIfExists('device_capabilities');
  await knex.schema.dropTableIfExists('device_transports');
  // devices.concentrator_id references devices itself; dropping the table
  // takes the self-FK with it.
  await knex.schema.dropTableIfExists('devices');
  await knex.schema.dropTableIfExists('sites');
}
