import type { Knex } from 'knex';

/**
 * 015_cwmp.ts — M10: the TR-069 / CWMP ACS (feature C10, arbitrage A1).
 *
 * Implements ARCHITECTURE.md §3.6. The numbering there says `008`; the tree has
 * been at `013` since the normalisation fix, so this is `015` — the section
 * describes a SHAPE, not a slot.
 *
 * The TypeScript contract these tables carry lives in `shared/src/cwmp.ts`. The
 * wire protocol lives in `server/src/cwmp/**` (a SEPARATE Express app on 7547,
 * never behind the API's nginx — Digest and long sessions, §6.2).
 *
 * ┌─ SEVEN DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ──────────────────┐
 * │                                                                           │
 * │ 1. NO TABLE HERE CARRIES `tenant_id`, EXCEPT THE TWO THAT MUST.           │
 * │    Every CWMP table hangs off `devices`, which is tenant-scoped, and the  │
 * │    reads join it — the same shape `config_snapshots`, the ten `ncm_*`     │
 * │    tables and `policy_results` already have. A denormalised copy of the   │
 * │    tenant would be a third source of truth that can disagree with the     │
 * │    other two, and a foreign key would bless the disagreement.             │
 * │    The exceptions are `cwmp_acs_settings` (a per-tenant configuration     │
 * │    row: it has no device) and `cwmp_files` / `cwmp_param_map` (which      │
 * │    follow the `templates.tenant_id` convention of migration 008/013 —     │
 * │    NULL means "shipped library, visible to every tenant").                │
 * │    Every index that serves a tenant-scoped LIST is therefore rooted at    │
 * │    `device_id`, and the tenant filter is the join. That is stated here so │
 * │    nobody later "optimises" a read by dropping the join.                  │
 * │                                                                           │
 * │ 2. `cwmp_devices.cwmp_id` IS UNIQUE GLOBALLY, NOT PER TENANT.             │
 * │    `OUI-ProductClass-Serial` is a HARDWARE identity. The same physical    │
 * │    box cannot be in two tenants, and two rows claiming it is not a        │
 * │    coexistence to allow — it is a provisioning error that must fail at    │
 * │    the INSERT rather than silently split a CPE's history in two. This is  │
 * │    exactly why `devices.ppp_username` and `UNIQUE(brand, serial)` are     │
 * │    already global in migration 002. Scoping it per tenant would let       │
 * │    tenant B enrol a serial that belongs to tenant A and receive its       │
 * │    Informs.                                                               │
 * │                                                                           │
 * │ 3. THE PARAMETER TREE IS FULL OF PASSWORDS, AND THE VALUES ARE NOT        │
 * │    STORED (§8.2). `cwmp_parameters.is_secret` is set at INGESTION by      │
 * │    `isSecretParameterPath()`, and `cwmp_parameters_secret_null_chk`       │
 * │    makes the database refuse a row that carries both. The last audit      │
 * │    found the L2TP passwords of a whole fleet in a jsonb column served to  │
 * │    the UI; a CHECK constraint is the only version of that promise that    │
 * │    cannot be undone by a future writer who forgot.                        │
 * │                                                                           │
 * │ 4. `cwmp_tasks.command_key` IS UNIQUE ACROSS THE WHOLE TABLE.             │
 * │    `TransferComplete` arrives in a LATER session than the `Download` that │
 * │    caused it — minutes later for a config file, hours or days for a       │
 * │    firmware image on a bad line — and `CommandKey` is the only thing      │
 * │    tying the two together. Per-device uniqueness would be enough for      │
 * │    correlation but it would also mean the lookup needs the device, and    │
 * │    the whole point of the correlation is that the session that brings     │
 * │    the TransferComplete may be the first one after a factory reset.       │
 * │                                                                           │
 * │ 5. `cwmp_rpc_log` IS PARTITIONED AND OFF BY DEFAULT (risk R7).            │
 * │    It reuses `ensure_series_partition()` and `series_partition_policy`    │
 * │    from migration 006 rather than growing a second partition mechanism.   │
 * │    Retention 7 days, DROP of partition and never DELETE. `rpc_log_enabled │
 * │    = false` is the shipped default and the flag is per tenant AND per     │
 * │    device: debugging one misbehaving Vigor must not mean logging every    │
 * │    envelope of 300 CPEs.                                                  │
 * │                                                                           │
 * │ 6. THERE IS NO `cr_password_enc`, AND THAT IS DELIBERATE.                 │
 * │    §3.6 lists one. ObliWAN does not implement Connection Request          │
 * │    (arbitrage: STUN/XMPP bindings expire in 30-120 s, the success rate    │
 * │    does not justify the machinery), so that column would be a credential  │
 * │    stored for a code path that does not exist — a liability with no       │
 * │    reader, which §8.2 forbids more clearly than §3.6 requires it.         │
 * │    `connection_request_url` IS kept: the CPE announces it, an operator    │
 * │    debugging a NAT wants to see it, and a URL is not a secret.            │
 * │                                                                           │
 * │ 7. `acs_auth_ha1_enc` IS CIPHERTEXT, NOT A BARE HASH.                     │
 * │    HA1 = MD5(username:realm:password) is PASSWORD-EQUIVALENT for Digest:  │
 * │    anyone holding it can authenticate as the CPE. Storing it in clear     │
 * │    would put a fleet's worth of usable credentials one SELECT away. It    │
 * │    goes through `secretVault.service` like every other credential in this │
 * │    schema, with the same `key_version` column for rotation (R8).          │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

// Kept as literals rather than imported from @obliwan/shared, exactly as
// migration 002 does: a migration must keep describing the schema as it was on
// the day it ran, whatever the shared package does later.
const DATA_MODELS = "'tr098','tr181'";
const REACHABILITY = "'never_seen','online','stale','lost'";
const TASK_KINDS =
  "'get_parameter_values','set_parameter_values','download','reboot'";
const TASK_STATES = "'queued','sent','done','failed','expired','cancelled'";
const VALUE_TYPES =
  "'xsd:string','xsd:int','xsd:unsignedInt','xsd:long','xsd:unsignedLong'," +
  "'xsd:boolean','xsd:dateTime','xsd:base64'";
const FILE_TYPES = "'1 Firmware Upgrade Image','3 Vendor Configuration File'";
const TRANSFER_STATES = "'pending','fetched','completed','failed','expired'";
const SESSION_STATES = "'open','closed','abandoned'";
const RPC_DIRECTIONS = "'cpe_to_acs','acs_to_cpe'";
const CANONICAL_KEYS =
  "'device.manufacturer','device.model','device.serial'," +
  "'device.hardware_version','device.software_version','device.uptime_seconds'," +
  "'mgmt.periodic_inform_enable','mgmt.periodic_inform_interval'," +
  "'mgmt.connection_request_url','mgmt.parameter_key'," +
  "'wan.external_ip','wan.connection_status','wan.connection_type'," +
  "'wan.mac_address','wan.uptime_seconds'," +
  "'lan.ip_address','lan.subnet_mask','lan.dhcp_enable'," +
  "'lan.dhcp_min_address','lan.dhcp_max_address'," +
  "'wifi.ssid','wifi.enable','wifi.channel','wifi.security_mode'," +
  "'hosts.total'";

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // cwmp_acs_settings — one row per tenant, and the tenant is in the URL.
  // ==========================================================================
  //
  // A CPE has no session and no header telling us who it belongs to. What it
  // has is the ACS URL it was provisioned with, so the listener routes on
  // `POST /<tenant_slug>` and this table is the lookup. The slug is UNIQUE and
  // immutable in practice: changing it silently orphans every CPE in the field
  // until somebody re-provisions them one by one.
  await knex.schema.createTable('cwmp_acs_settings', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable().unique()
      .references('id').inTable('tenants').onDelete('CASCADE');

    // Lowercase, url-safe. 64 is generous: it appears in the ACS URL burned
    // into 300 CPEs.
    t.string('tenant_slug', 64).notNullable().unique();

    // The Digest realm. It is part of HA1 = MD5(user:realm:password), so
    // changing it invalidates every stored HA1 in the tenant — hence the
    // comment below rather than a silent UPDATE.
    t.string('digest_realm', 128).notNullable().defaultTo('obliwan-acs');

    // Source addresses allowed to reach the listener for this tenant. Empty
    // array = no restriction, which is the honest default for CPEs behind
    // carrier NAT whose public address changes with the line.
    t.specificType('trusted_cidrs', 'text[]').notNullable().defaultTo(knex.raw("'{}'::text[]"));

    // May a never-seen `cwmp_id` create a `devices` row on its own?
    // FALSE by default, and that is the same decision as `discoveries` in
    // migration 002: automatic attachment to a tenant is risk R4. An operator
    // binds the CPE, and the binding is audited.
    t.boolean('allow_auto_enroll').notNullable().defaultTo(false);

    // Risk R7. Off by default, per tenant; `cwmp_devices.rpc_log_enabled`
    // narrows it further to one device.
    t.boolean('rpc_log_enabled').notNullable().defaultTo(false);

    // What the ACS asks a freshly enrolled CPE to use. 300 s is the interval
    // the volumetry of R7 was recomputed against on 2026-08-29.
    t.integer('default_periodic_inform_interval').notNullable().defaultTo(300);

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE cwmp_acs_settings ADD CONSTRAINT cwmp_acs_settings_slug_fmt_chk ' +
      "CHECK (tenant_slug ~ '^[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]$')",
  );
  await knex.schema.raw(
    'ALTER TABLE cwmp_acs_settings ADD CONSTRAINT cwmp_acs_settings_interval_chk ' +
      'CHECK (default_periodic_inform_interval BETWEEN 30 AND 86400)',
  );

  // ==========================================================================
  // cwmp_devices — the CPE, as the ACS knows it.
  // ==========================================================================
  await knex.schema.createTable('cwmp_devices', (t) => {
    // PK *is* the device: one CPE, one CWMP identity. Decision 1 — no
    // tenant_id; the reads join `devices`.
    t.integer('device_id').primary()
      .references('id').inTable('devices').onDelete('CASCADE');

    // Decision 2. 192 chars — `CWMP_ID_MAX_LENGTH` in shared/src/cwmp.ts.
    t.string('cwmp_id', 192).notNullable().unique();

    // The three fields the identity is built from, kept separately because a
    // CPE that starts populating ProductClass after a firmware upgrade changes
    // its cwmp_id, and reconciling that by hand needs the parts.
    t.string('oui', 8).nullable();
    t.string('product_class', 64).nullable();
    t.string('serial_number', 64).nullable();
    t.string('manufacturer', 64).nullable();

    // 24, not 8: 'InternetGatewayDevice.' is 22 characters. The width rule this
    // project already paid for once on `devices.role`.
    t.string('root_prefix', 32).notNullable();
    t.string('data_model', 8).notNullable();
    // '1.0' .. '1.4'.
    t.string('cwmp_version', 8).nullable();

    t.string('hardware_version', 64).nullable();
    t.string('software_version', 64).nullable();

    // Announced by the CPE, DISPLAYED, never dialled — decision 6.
    t.text('connection_request_url').nullable();

    // Decision 7 — ciphertext produced by secretVault.service.ts:
    //   v1:<key_version>:<iv b64>:<tag b64>:<ciphertext b64>
    t.text('acs_auth_ha1_enc').nullable();
    t.integer('key_version').notNullable().defaultTo(1);
    // The username half of the Digest credential. Not a secret on its own, and
    // needed to build the challenge before the CPE has said anything.
    t.string('auth_username', 192).nullable();

    t.integer('periodic_inform_interval').notNullable().defaultTo(300);

    // 12, not 8: 'never_seen' is 10 characters.
    t.string('reachability', 16).notNullable().defaultTo('never_seen');
    t.timestamp('last_inform_at', { useTz: true }).nullable();
    t.timestamp('last_bootstrap_at', { useTz: true }).nullable();
    t.specificType('last_inform_events', 'text[]').notNullable()
      .defaultTo(knex.raw("'{}'::text[]"));
    t.integer('inform_count').notNullable().defaultTo(0);
    // The last address the CPE called from. Addressing, never identity (D5).
    t.specificType('last_source_ip', 'inet').nullable();

    // OBSERVED quirks — written by the parser when a real envelope forced it to
    // cope. Never a settings blob, and never a secret: `CwmpQuirks` is a record
    // of booleans by construction.
    t.jsonb('vendor_quirks').notNullable().defaultTo('{}');

    // Risk R7, narrowed to one device.
    t.boolean('rpc_log_enabled').notNullable().defaultTo(false);

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE cwmp_devices ADD CONSTRAINT cwmp_devices_data_model_chk ' +
      `CHECK (data_model IN (${DATA_MODELS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE cwmp_devices ADD CONSTRAINT cwmp_devices_reachability_chk ' +
      `CHECK (reachability IN (${REACHABILITY}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE cwmp_devices ADD CONSTRAINT cwmp_devices_interval_chk ' +
      'CHECK (periodic_inform_interval BETWEEN 30 AND 86400)',
  );
  // The root prefix and the data model are two spellings of one fact. Letting
  // them disagree is how a `GetParameterValues` goes out asking a TR-181 box
  // for `InternetGatewayDevice.` and comes back 9005 forever.
  await knex.schema.raw(
    'ALTER TABLE cwmp_devices ADD CONSTRAINT cwmp_devices_root_matches_model_chk ' +
      "CHECK ((data_model = 'tr098' AND root_prefix = 'InternetGatewayDevice.') OR " +
      "(data_model = 'tr181' AND root_prefix = 'Device.'))",
  );
  // Ciphertext only. A bare 32-hex MD5 in this column would be a plaintext
  // HA1, i.e. exactly what decision 7 forbids, so the format is enforced.
  await knex.schema.raw(
    'ALTER TABLE cwmp_devices ADD CONSTRAINT cwmp_devices_ha1_fmt_chk ' +
      "CHECK (acs_auth_ha1_enc IS NULL OR acs_auth_ha1_enc ~ '^v[0-9]+:[0-9]+:')",
  );
  await knex.schema.raw(
    'ALTER TABLE cwmp_devices ADD CONSTRAINT cwmp_devices_quirks_object_chk ' +
      "CHECK (jsonb_typeof(vendor_quirks) = 'object')",
  );

  // The fleet list: "the CPEs that have gone quiet", ordered. The tenant filter
  // is the join on `devices` (decision 1).
  await knex.schema.raw(
    'CREATE INDEX cwmp_devices_reach_inform_idx ON cwmp_devices ' +
      '(reachability, last_inform_at DESC NULLS LAST)',
  );
  // Lookup by identity, on the hot path of every single Inform. The UNIQUE
  // above already provides it; named here so a later "cleanup" of the unique
  // constraint cannot silently remove the index the listener depends on.

  // ==========================================================================
  // cwmp_parameters — the flattened tree. Decision 3.
  // ==========================================================================
  await knex.schema.raw(`
    CREATE TABLE cwmp_parameters (
      device_id     integer     NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      path          varchar(512) NOT NULL,
      -- NULL when is_secret. Also NULL for a partial path we know exists but
      -- have never read: "unknown" and "empty string" are different answers and
      -- the drift engine treats them differently.
      value         text        NULL,
      value_type    varchar(20) NOT NULL DEFAULT 'xsd:string',
      writable      boolean     NOT NULL DEFAULT false,
      notification  smallint    NOT NULL DEFAULT 0,
      is_secret     boolean     NOT NULL DEFAULT false,
      updated_at    timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (device_id, path)
    )
  `);
  await knex.schema.raw(
    'ALTER TABLE cwmp_parameters ADD CONSTRAINT cwmp_parameters_type_chk ' +
      `CHECK (value_type IN (${VALUE_TYPES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE cwmp_parameters ADD CONSTRAINT cwmp_parameters_notification_chk ' +
      'CHECK (notification BETWEEN 0 AND 2)',
  );
  // THE CONSTRAINT OF §8.2. A secret parameter may never carry a value, and
  // this is enforced by the database rather than by the discipline of whoever
  // writes the next ingestion path.
  await knex.schema.raw(
    'ALTER TABLE cwmp_parameters ADD CONSTRAINT cwmp_parameters_secret_null_chk ' +
      'CHECK (NOT is_secret OR value IS NULL)',
  );
  // Prefix search — "everything under InternetGatewayDevice.WANDevice.1." — is
  // the shape of every read in the parameter browser and in the NCM builder.
  // `text_pattern_ops` is what makes `LIKE 'prefix%'` index-only; the default
  // opclass does not, on a non-C collation.
  await knex.schema.raw(
    'CREATE INDEX cwmp_parameters_prefix_idx ON cwmp_parameters ' +
      '(device_id, path varchar_pattern_ops)',
  );

  // ==========================================================================
  // cwmp_files — firmware images and vendor configuration files.
  // ==========================================================================
  //
  // `tenant_id NULL` = shipped library, visible to every tenant. Same
  // convention as `templates.tenant_id` (008) and `normalization_rules` (013);
  // one convention for shipped content across the schema, not two.
  await knex.schema.createTable('cwmp_files', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').nullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('name', 128).notNullable();
    // 32, not 26: '1 Firmware Upgrade Image' is 24 and '3 Vendor Configuration
    // File' is 30. The width rule.
    t.string('file_type', 32).notNullable();

    t.string('storage_path', 512).notNullable();
    t.string('sha256', 64).notNullable();
    t.bigInteger('size_bytes').notNullable();

    // What this image is FOR. A firmware pushed to the wrong model bricks a
    // customer's router, so the match is data and it is checked before the
    // Download task is created — never "the operator will be careful".
    t.string('brand', 32).nullable();
    t.string('model_pattern', 128).nullable();
    t.string('version', 64).nullable();

    t.integer('uploaded_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE cwmp_files ADD CONSTRAINT cwmp_files_type_chk ' +
      `CHECK (file_type IN (${FILE_TYPES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE cwmp_files ADD CONSTRAINT cwmp_files_sha_fmt_chk ' +
      "CHECK (sha256 ~ '^[0-9a-f]{64}$')",
  );
  await knex.schema.raw(
    'ALTER TABLE cwmp_files ADD CONSTRAINT cwmp_files_size_chk CHECK (size_bytes > 0)',
  );
  // Two partial indexes, not one: `tenant_id` is nullable and PostgreSQL's
  // default NULLS DISTINCT would make every library row unique by vacuity —
  // the lesson of migration 001, restated by 008 and 013.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX cwmp_files_tenant_name_uq ON cwmp_files (tenant_id, name) ' +
      'WHERE tenant_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX cwmp_files_library_name_uq ON cwmp_files (name) ' +
      'WHERE tenant_id IS NULL',
  );

  // ==========================================================================
  // cwmp_tasks — the per-CPE queue. Decision 4.
  // ==========================================================================
  await knex.schema.createTable('cwmp_tasks', (t) => {
    t.increments('id').primary();
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    // 32, not 24: 'get_parameter_values' is 20 and the next kind will not be
    // shorter.
    t.string('kind', 32).notNullable();
    t.string('command_key', 64).notNullable().unique();
    t.string('state', 16).notNullable().defaultTo('queued');

    t.integer('attempts').notNullable().defaultTo(0);
    t.integer('max_attempts').notNullable().defaultTo(3);

    // Redacted by construction: a `set_parameter_values` op targeting a secret
    // path carries `secretRef`, a vault handle, never a value (§8.2). The
    // CHECK below is what stops a future writer from taking the shortcut.
    t.jsonb('payload').notNullable();
    t.jsonb('fault').nullable();

    t.integer('created_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');

    // A CPE offline for a week must not be handed a week of stale intent the
    // second it reconnects.
    t.timestamp('expires_at', { useTz: true }).notNullable();
    t.timestamp('sent_at', { useTz: true }).nullable();
    t.timestamp('completed_at', { useTz: true }).nullable();
    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE cwmp_tasks ADD CONSTRAINT cwmp_tasks_kind_chk ' +
      `CHECK (kind IN (${TASK_KINDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE cwmp_tasks ADD CONSTRAINT cwmp_tasks_state_chk ' +
      `CHECK (state IN (${TASK_STATES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE cwmp_tasks ADD CONSTRAINT cwmp_tasks_attempts_chk ' +
      'CHECK (attempts >= 0 AND max_attempts BETWEEN 1 AND 20)',
  );
  // §8.2 AT THE STORAGE LAYER: no key literally named like a credential may
  // appear anywhere in a task payload. `secretRef` is the only channel.
  await knex.schema.raw(
    'ALTER TABLE cwmp_tasks ADD CONSTRAINT cwmp_tasks_payload_no_secret_chk ' +
      "CHECK (payload::text !~* '\"(password|passphrase|presharedkey|privatekey)\"\\s*:')",
  );
  await knex.schema.raw(
    'ALTER TABLE cwmp_tasks ADD CONSTRAINT cwmp_tasks_terminal_time_chk ' +
      "CHECK ((state IN ('done','failed','expired','cancelled')) = (completed_at IS NOT NULL))",
  );

  // THE INDEX THE SESSION MACHINE READS ON EVERY POST. A CPE calls in, the ACS
  // asks "what is queued for you", and that question must not scan the table on
  // a fleet with a million completed tasks. PARTIAL, because `queued` and
  // `sent` are the only states the session ever looks at.
  await knex.schema.raw(
    'CREATE INDEX cwmp_tasks_pending_idx ON cwmp_tasks (device_id, id) ' +
      "WHERE state IN ('queued','sent')",
  );
  // The expiry sweep, and nothing else.
  await knex.schema.raw(
    'CREATE INDEX cwmp_tasks_expiry_idx ON cwmp_tasks (expires_at) ' +
      "WHERE state = 'queued'",
  );
  // The task history of one device, newest first.
  await knex.schema.raw(
    'CREATE INDEX cwmp_tasks_device_recent_idx ON cwmp_tasks (device_id, created_at DESC)',
  );

  // ==========================================================================
  // cwmp_transfers — Download, and the TransferComplete that answers it.
  // ==========================================================================
  //
  // A separate table from `cwmp_tasks` because the lifetimes differ by orders
  // of magnitude: the task is done the moment the CPE acknowledges the
  // `Download` RPC, and the TRANSFER is not finished until an HTTP GET has
  // happened and a `TransferComplete` has arrived — in another session, later.
  await knex.schema.createTable('cwmp_transfers', (t) => {
    t.increments('id').primary();
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');
    t.integer('file_id').nullable()
      .references('id').inTable('cwmp_files').onDelete('SET NULL');

    // The correlation handle, and a foreign key to the task that created it so
    // the two halves are joinable in one direction as well as the other.
    t.string('command_key', 64).notNullable().unique();
    t.integer('task_id').nullable()
      .references('id').inTable('cwmp_tasks').onDelete('SET NULL');

    // The single-use token in the download URL handed to the CPE. The CPE
    // fetches over plain HTTP from a NATed line and cannot present a session,
    // so the token IS the authorisation: unguessable, scoped to one file and
    // one device, and expiring. It is not a secret in the §8.2 sense (it grants
    // read of a firmware image, not of a credential) but it is treated as one
    // in logs: `url_token` is never printed.
    t.string('url_token', 64).notNullable().unique();
    t.timestamp('token_expires_at', { useTz: true }).notNullable();

    t.string('state', 16).notNullable().defaultTo('pending');
    t.timestamp('http_fetched_at', { useTz: true }).nullable();
    t.integer('fetch_count').notNullable().defaultTo(0);

    // Straight out of TransferComplete.
    t.timestamp('start_time', { useTz: true }).nullable();
    t.timestamp('complete_time', { useTz: true }).nullable();
    t.string('fault_code', 8).nullable();
    t.text('fault_string').nullable();

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE cwmp_transfers ADD CONSTRAINT cwmp_transfers_state_chk ' +
      `CHECK (state IN (${TRANSFER_STATES}))`,
  );
  await knex.schema.raw(
    'CREATE INDEX cwmp_transfers_device_idx ON cwmp_transfers (device_id, created_at DESC)',
  );
  // The file server's lookup, on every GET of a firmware image.
  await knex.schema.raw(
    'CREATE INDEX cwmp_transfers_open_token_idx ON cwmp_transfers (url_token) ' +
      "WHERE state IN ('pending','fetched')",
  );

  // ==========================================================================
  // cwmp_sessions — one row per CWMP session, and the cookie fallback.
  // ==========================================================================
  //
  // WHY A TABLE AND NOT A MAP IN MEMORY: `OBLIWAN_ROLE=web` may run several
  // replicas (A5), and a CPE's second POST can land on another one. Full
  // session affinity is out of scope for v1 (arbitrage A5 (c)), but the
  // session RECORD has to survive a restart anyway — otherwise a redeploy in
  // the middle of a 300-CPE inform window loses every in-flight task and each
  // one is retried from scratch.
  await knex.schema.createTable('cwmp_sessions', (t) => {
    t.increments('id').primary();

    // NULLABLE ON PURPOSE. A session exists from the first POST, and the
    // device is only known once the Inform has been parsed and authenticated.
    // A NOT NULL here would mean either inventing a device or refusing to
    // record the exact sessions that are worth recording — the failed ones.
    t.integer('device_id').nullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    // The `ACSsession` cookie value. Unguessable, and the primary continuity
    // key when the CPE honours cookies.
    t.string('session_token', 64).notNullable().unique();

    // THE FALLBACK, for the CPEs that do not (the quirk `noCookie`).
    // `(cwmp_id, source_ip)` is not unique over time — two CPEs behind one NAT
    // share the address — but combined with `cwmp_id` it identifies the box,
    // and combined with `state = 'open'` it identifies at most one live
    // session. Hence the partial unique index below rather than a constraint
    // on the columns themselves.
    t.string('cwmp_id', 192).nullable();
    t.specificType('source_ip', 'inet').nullable();

    t.string('state', 16).notNullable().defaultTo('open');
    t.integer('rpc_count').notNullable().defaultTo(0);
    t.boolean('authenticated').notNullable().defaultTo(false);

    // The `cwmp:ID` of the envelope currently in flight, so a response can be
    // matched to its request even when the CPE reorders.
    t.string('pending_rpc_id', 64).nullable();
    t.integer('pending_task_id').nullable()
      .references('id').inTable('cwmp_tasks').onDelete('SET NULL');

    t.timestamp('started_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('last_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('ended_at', { useTz: true }).nullable();
  });

  await knex.schema.raw(
    'ALTER TABLE cwmp_sessions ADD CONSTRAINT cwmp_sessions_state_chk ' +
      `CHECK (state IN (${SESSION_STATES}))`,
  );
  // At most ONE open session per (cwmp_id, source_ip). This is what makes the
  // cookie-less fallback deterministic instead of "pick the newest and hope".
  await knex.schema.raw(
    'CREATE UNIQUE INDEX cwmp_sessions_fallback_uq ON cwmp_sessions (cwmp_id, source_ip) ' +
      "WHERE state = 'open' AND cwmp_id IS NOT NULL AND source_ip IS NOT NULL",
  );
  await knex.schema.raw(
    'CREATE INDEX cwmp_sessions_reaper_idx ON cwmp_sessions (last_seen_at) ' +
      "WHERE state = 'open'",
  );
  await knex.schema.raw(
    'CREATE INDEX cwmp_sessions_device_idx ON cwmp_sessions (device_id, started_at DESC)',
  );

  // ==========================================================================
  // cwmp_param_map — canonical key <-> vendor path. Rule 1 of the contract.
  // ==========================================================================
  await knex.schema.createTable('cwmp_param_map', (t) => {
    t.increments('id').primary();
    // NULL = shipped library (008/013 convention).
    t.integer('tenant_id').nullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    // 32, not 24: 'mgmt.periodic_inform_interval' is 29.
    t.string('canonical_key', 48).notNullable();
    t.string('data_model', 8).notNullable();

    t.string('brand', 32).nullable();
    t.string('model_pattern', 128).nullable();
    t.string('firmware_pattern', 128).nullable();

    // May contain `{i}` instance placeholders.
    t.string('param_path', 512).notNullable();

    // Lower wins. The narrowing (brand, then model, then firmware) is data, not
    // a chain of ifs in a resolver nobody can test.
    t.integer('priority').notNullable().defaultTo(100);
    // Learned from a live CPE rather than shipped. Learned rows are the ones an
    // operator reviews; shipped ones are the doctrine.
    t.boolean('learned').notNullable().defaultTo(false);
    t.integer('learned_from_device_id').nullable()
      .references('id').inTable('devices').onDelete('SET NULL');

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    'ALTER TABLE cwmp_param_map ADD CONSTRAINT cwmp_param_map_key_chk ' +
      `CHECK (canonical_key IN (${CANONICAL_KEYS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE cwmp_param_map ADD CONSTRAINT cwmp_param_map_model_chk ' +
      `CHECK (data_model IN (${DATA_MODELS}))`,
  );
  // A learned row must say where it came from; a shipped one must not claim a
  // device. Without this the "review the learned mappings" screen has no
  // trustworthy population.
  await knex.schema.raw(
    'ALTER TABLE cwmp_param_map ADD CONSTRAINT cwmp_param_map_learned_chk ' +
      'CHECK (learned OR learned_from_device_id IS NULL)',
  );

  // The uniqueness of a mapping is (tenant, key, model, brand, model_pattern,
  // firmware_pattern). `brand`, `model_pattern` and `firmware_pattern` are all
  // nullable — NULLS DISTINCT would let the same rule be inserted twice — so
  // the unique index is expressed over COALESCE, and split in two on
  // `tenant_id` for exactly the reason decision 2 of migration 013 gives.
  await knex.schema.raw(
    "CREATE UNIQUE INDEX cwmp_param_map_tenant_uq ON cwmp_param_map " +
      "(tenant_id, canonical_key, data_model, coalesce(brand,''), " +
      "coalesce(model_pattern,''), coalesce(firmware_pattern,'')) " +
      'WHERE tenant_id IS NOT NULL',
  );
  await knex.schema.raw(
    "CREATE UNIQUE INDEX cwmp_param_map_library_uq ON cwmp_param_map " +
      "(canonical_key, data_model, coalesce(brand,''), " +
      "coalesce(model_pattern,''), coalesce(firmware_pattern,'')) " +
      'WHERE tenant_id IS NULL',
  );
  // The resolver's read: every candidate for one key and one data model, in
  // priority order.
  await knex.schema.raw(
    'CREATE INDEX cwmp_param_map_lookup_idx ON cwmp_param_map ' +
      '(canonical_key, data_model, priority)',
  );

  // ==========================================================================
  // cwmp_rpc_log — partitioned, OFF by default, 7 days. Decision 5 / risk R7.
  // ==========================================================================
  //
  // Reuses `ensure_series_partition()` and `series_partition_policy` from
  // migration 006. No second partition mechanism, no pg_partman, and the hourly
  // maintenance job in `services/snmp/partition.service.ts` picks this table up
  // the moment the policy row below exists — it is entirely policy-driven.
  await knex.schema.raw(`
    CREATE TABLE cwmp_rpc_log (
      ts          timestamptz NOT NULL,
      device_id   integer     NULL,      -- NULL before the Inform identifies it
      session_id  integer     NULL,      -- no FK: partitions outlive sessions
      direction   varchar(12) NOT NULL,
      method      varchar(48) NULL,      -- NULL for an empty POST
      cwmp_id     varchar(64) NULL,      -- the envelope's cwmp:ID header
      http_status smallint    NULL,
      -- The envelope, ALREADY REDACTED by the writer. A CWMP body carries the
      -- customer's PPPoE password in cleartext XML, so what lands here has been
      -- through the same scrubbing as command_audit.args_redacted (section 8.2).
      body        text        NULL,
      byte_count  integer     NOT NULL DEFAULT 0
    ) PARTITION BY RANGE (ts)
  `);
  await knex.schema.raw(
    'ALTER TABLE cwmp_rpc_log ADD CONSTRAINT cwmp_rpc_log_direction_chk ' +
      `CHECK (direction IN (${RPC_DIRECTIONS}))`,
  );
  await knex.schema.raw(
    'CREATE INDEX cwmp_rpc_log_device_ts_idx ON cwmp_rpc_log (device_id, ts DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX cwmp_rpc_log_ts_brin_idx ON cwmp_rpc_log USING brin (ts)',
  );

  // Grain `day`, retention 7 days, 3 days of look-ahead. The maintenance job
  // reads this row; nothing else has to know the table is partitioned.
  await knex('series_partition_policy').insert({
    parent: 'cwmp_rpc_log',
    grain: 'day',
    part_column: 'ts',
    retention: knex.raw("INTERVAL '7 days'"),
    precreate_units: 3,
    enabled: true,
  });

  // Today plus the look-ahead, created now so the first envelope of a freshly
  // installed instance has somewhere to land (layer 1 of the study's three).
  await knex.raw("SELECT ensure_series_partitions('cwmp_rpc_log'::regclass, 'day', 1, 3)");

  // ==========================================================================
  // Column comments — the schema explains itself to whoever runs \d+ at 3 a.m.
  // ==========================================================================
  await knex.schema.raw(
    "COMMENT ON TABLE cwmp_devices IS $$The CPE as the ACS knows it. No tenant_id: " +
      'reads join devices, which is tenant-scoped (migration 015, decision 1).$$',
  );
  await knex.schema.raw(
    'COMMENT ON COLUMN cwmp_devices.acs_auth_ha1_enc IS $$Digest HA1, ENCRYPTED. ' +
      'HA1 is password-equivalent: whoever holds it can authenticate as the CPE. ' +
      'Never store it in clear (migration 015, decision 7).$$',
  );
  await knex.schema.raw(
    'COMMENT ON COLUMN cwmp_parameters.value IS $$NULL when is_secret. TR-069 ' +
      'parameter trees carry PPPoE/L2TP passwords and Wi-Fi keys; their values are ' +
      'never stored, diffed, exported or returned by the API (§8.2).$$',
  );
  await knex.schema.raw(
    'COMMENT ON TABLE cwmp_rpc_log IS $$Partitioned by day, retention 7 days, ' +
      'DISABLED by default (risk R7). Enable per tenant AND per device. Bodies are ' +
      'redacted before insert.$$',
  );
  await knex.schema.raw(
    'COMMENT ON COLUMN cwmp_devices.connection_request_url IS $$Announced by the ' +
      'CPE and DISPLAYED, never dialled. ObliWAN does not implement Connection ' +
      'Request; the fallback is a shortened PeriodicInformInterval.$$',
  );
}

export async function down(knex: Knex): Promise<void> {
  // Partitions go with the parent; the POLICY row does not, and a leftover one
  // makes the hourly maintenance job log a failure against a table that no
  // longer exists, once an hour, forever.
  await knex('series_partition_policy').where({ parent: 'cwmp_rpc_log' }).del();
  await knex.schema.raw('DROP TABLE IF EXISTS cwmp_rpc_log CASCADE');

  await knex.schema.dropTableIfExists('cwmp_param_map');
  // Before cwmp_tasks: cwmp_sessions references it.
  await knex.schema.dropTableIfExists('cwmp_sessions');
  await knex.schema.dropTableIfExists('cwmp_transfers');
  await knex.schema.dropTableIfExists('cwmp_tasks');
  await knex.schema.dropTableIfExists('cwmp_files');
  await knex.schema.dropTableIfExists('cwmp_parameters');
  await knex.schema.dropTableIfExists('cwmp_devices');
  await knex.schema.dropTableIfExists('cwmp_acs_settings');
}
