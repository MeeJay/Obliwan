import type { Knex } from 'knex';

/**
 * 005_snmp.ts — M3 part 1: the SNMP control plane.
 *
 * Everything in here is SMALL and MUTABLE: credentials, targets, the interface
 * registry, the delta baseline, thresholds and alert state. The time series
 * themselves — big, append-only, partitioned — are 006_timeseries.ts. The split
 * is deliberate: this file is the one an operator reads to understand what the
 * poller is configured to do; that file is the one nobody should ever have to
 * read.
 *
 * Implements section 3.3 of ARCHITECTURE.md and section 1.3 of
 * `docs/M3-series-temporelles.md`.
 *
 * ┌─ FOUR DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ───────────────────┐
 * │                                                                           │
 * │ 1. `snmp_interfaces` is keyed UNIQUE(device_id, if_name), NOT if_index.   │
 * │    ifIndex is MUTABLE — a reboot, a card swap or an "ip service" toggle   │
 * │    renumbers it. Keying on it means that after a reboot the WAN counters  │
 * │    land in the LAN series, silently, forever. That is risk R12, and it is │
 * │    the single most expensive mistake available in this schema because     │
 * │    nothing in the data ever looks wrong. `if_index` is stored, and it is  │
 * │    stored ONLY so that a change can be detected (`needs_rediscovery`).    │
 * │    There is deliberately NO unique index on (device_id, if_index): after  │
 * │    a remap two rows legitimately carry the same stale ifIndex until       │
 * │    rediscovery runs.                                                      │
 * │                                                                           │
 * │ 2. An interface that disappears is NEVER deleted. It moves to             │
 * │    `state = 'vanished'`. Deleting it would orphan (and eventually take    │
 * │    down, via a cascade) millions of series rows, which is exactly what    │
 * │    risk R7 forbids, and it would erase the history of a link that a       │
 * │    customer is asking about precisely because it disappeared.             │
 * │                                                                           │
 * │ 3. `snmp_poll_state` counters are `numeric(20,0)`, not `bigint`.          │
 * │    ifHCInOctets is an UNSIGNED Counter64: it ranges to 1.845e19 while     │
 * │    bigint stops at 9.22e18. A buggy agent or a sloppy BER decode reaches  │
 * │    that in one read and `bigint` turns it into a silent negative. The     │
 * │    table holds ~2400 rows and is written once per cycle; numeric's        │
 * │    arithmetic cost is irrelevant here.                                    │
 * │                                                                           │
 * │ 4. `snmp_thresholds.for_seconds` and `.hysteresis_pct` are NOT NULL AND   │
 * │    HAVE NO DEFAULT. A default would let a caller omit them and get a      │
 * │    threshold that re-notifies on every evaluation cycle the moment a      │
 * │    value sits on the boundary. Making them mandatory at the INSERT is the │
 * │    whole point of the spec wording ("obligatoires").                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS. `community_enc`, `auth_key_enc` and `priv_key_enc` hold secretVault
 * blobs — `v1:<key_version>:<iv>:<tag>:<ciphertext>` — and nothing else. NOT
 * `utils/crypto.ts`, which is the inherited Obliguard mechanism keyed off
 * SESSION_SECRET: rotating a session secret is routine, and doing it would make
 * every SNMP credential in the fleet undecryptable with no error at startup
 * (risk R8). The two formats are distinguishable — the vault prefixes `v<n>:`,
 * the legacy one emits bare `hex:hex:hex` — so a CHECK constraint enforces the
 * choice in the database rather than trusting every future caller.
 */

// Inlined as literals rather than imported from @obliwan/shared, exactly as
// 002 does: a migration must keep describing the schema as it was on the day it
// ran, whatever the shared package does later.
const SNMP_VERSIONS = "'v1','v2c','v3'";
const SNMP_SEC_LEVELS = "'noAuthNoPriv','authNoPriv','authPriv'";
const SNMP_AUTH_PROTOS = "'md5','sha','sha224','sha256','sha384','sha512'";
const SNMP_PRIV_PROTOS = "'des','3des','aes','aes128','aes192','aes256'";
const IF_STATES = "'active','vanished'";
const THRESHOLD_SCOPES = "'global','tenant','group','device','interface'";
const THRESHOLD_COMPARATORS = "'gt','gte','lt','lte'";
const THRESHOLD_SEVERITIES = "'info','warning','critical'";
const ALERT_STATES = "'ok','pending','firing'";
const ALERT_ENTITIES = "'interface','device'";
const THRESHOLD_METRICS =
  "'if_in_bps','if_out_bps','if_in_util_pct','if_out_util_pct'," +
  "'if_in_errs','if_out_errs','if_in_discards','if_out_discards','if_oper_status'," +
  "'dev_cpu_pct','dev_mem_pct','dev_temp_dc','dev_rtt_us','dev_reachable'";

/** A secretVault blob always starts with its format version. The legacy
 *  utils/crypto.ts output (`<ivhex>:<taghex>:<cipherhex>`) does not match, so
 *  this pattern is a real guard and not decoration. */
const VAULT_BLOB_RE = "^v[0-9]+:[0-9]+:";

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // snmp_credentials — one credential, reusable across many targets.
  // ==========================================================================
  // Separated from `device_transports` on purpose. A fleet of 300 sites shares
  // a handful of SNMP credentials; storing the community per device means 300
  // rows to re-encrypt on a rotation and 300 places for one of them to be
  // stale. `snmp_targets.credential_id` points here.

  await knex.schema.createTable('snmp_credentials', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable().defaultTo(1)
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('name', 128).notNullable();
    t.string('version', 8).notNullable().defaultTo('v2c');

    // --- v1 / v2c ----------------------------------------------------------
    // Vault ciphertext. A community string is a password that travels in clear
    // on the wire; that is a reason to encrypt it at rest, not a reason not to.
    t.text('community_enc').nullable();

    // --- v3 USM ------------------------------------------------------------
    t.string('username', 128).nullable();
    t.string('security_level', 16).nullable();
    t.string('auth_proto', 16).nullable();
    t.text('auth_key_enc').nullable();
    t.string('priv_proto', 16).nullable();
    t.text('priv_key_enc').nullable();
    // SNMPv3 context name. Empty string is a VALID context and is not the same
    // as "no context", hence nullable rather than defaulted to ''.
    t.string('context', 128).nullable();
    // Some agents demand the engine ID be supplied rather than discovered.
    t.string('engine_id', 64).nullable();

    // Which OBLIWAN_ENCRYPTION_KEY generation produced the *_enc columns.
    // Present from day one so a rotation walks row by row (risk R8).
    t.integer('key_version').notNullable().defaultTo(1);

    t.timestamps(true, true);

    t.unique(['tenant_id', 'name']);
    t.index('tenant_id');
  });

  await knex.schema.raw(
    'ALTER TABLE snmp_credentials ADD CONSTRAINT snmp_credentials_version_chk ' +
      `CHECK (version IN (${SNMP_VERSIONS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_credentials ADD CONSTRAINT snmp_credentials_seclevel_chk ' +
      `CHECK (security_level IS NULL OR security_level IN (${SNMP_SEC_LEVELS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_credentials ADD CONSTRAINT snmp_credentials_auth_proto_chk ' +
      `CHECK (auth_proto IS NULL OR auth_proto IN (${SNMP_AUTH_PROTOS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_credentials ADD CONSTRAINT snmp_credentials_priv_proto_chk ' +
      `CHECK (priv_proto IS NULL OR priv_proto IN (${SNMP_PRIV_PROTOS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_credentials ADD CONSTRAINT snmp_credentials_key_version_chk ' +
      'CHECK (key_version >= 1)',
  );

  // The shape constraint: a v2c row without a community and a v3 row without a
  // username are both configuration bugs that would surface as "timeout" at
  // 3 a.m. rather than as an error at save time.
  await knex.schema.raw(
    'ALTER TABLE snmp_credentials ADD CONSTRAINT snmp_credentials_shape_chk CHECK (' +
      "  (version IN ('v1','v2c')" +
      '     AND community_enc IS NOT NULL' +
      '     AND username IS NULL AND security_level IS NULL)' +
      '  OR' +
      "  (version = 'v3'" +
      '     AND community_enc IS NULL' +
      '     AND username IS NOT NULL AND security_level IS NOT NULL' +
      // authNoPriv and authPriv both need the auth half...
      "     AND (security_level = 'noAuthNoPriv'" +
      '          OR (auth_proto IS NOT NULL AND auth_key_enc IS NOT NULL))' +
      // ...and only authPriv needs the privacy half.
      "     AND (security_level <> 'authPriv'" +
      '          OR (priv_proto IS NOT NULL AND priv_key_enc IS NOT NULL)))' +
      ')',
  );

  // Vault format, enforced in the database. Blocks utils/crypto.ts output and
  // blocks a plaintext community written "just for a test".
  await knex.schema.raw(
    'ALTER TABLE snmp_credentials ADD CONSTRAINT snmp_credentials_vault_fmt_chk CHECK (' +
      `  (community_enc IS NULL OR community_enc ~ '${VAULT_BLOB_RE}')` +
      `  AND (auth_key_enc IS NULL OR auth_key_enc ~ '${VAULT_BLOB_RE}')` +
      `  AND (priv_key_enc IS NULL OR priv_key_enc ~ '${VAULT_BLOB_RE}')` +
      ')',
  );

  // ==========================================================================
  // snmp_targets — "which device do we poll, how, and when next".
  // ==========================================================================

  await knex.schema.createTable('snmp_targets', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();

    // UNIQUE: one SNMP target per device. Two targets would mean two pollers
    // writing the same (if_id, ts) series from two different baselines.
    t.integer('device_id').notNullable().unique()
      .references('id').inTable('devices').onDelete('CASCADE');

    // RESTRICT: deleting a credential that 200 targets still use must fail
    // loudly, not silently stop 200 sites from being polled.
    t.integer('credential_id').nullable()
      .references('id').inTable('snmp_credentials').onDelete('RESTRICT');

    // Where to dial TODAY. Never an identity (same doctrine as devices.*_ip).
    // Nullable: fall back to devices.tunnel_ip when unset.
    t.string('host', 255).nullable();
    t.integer('port').notNullable().defaultTo(161);

    t.boolean('enabled').notNullable().defaultTo(true);

    // NULL = inherit from settings (tenant/group/global). Resolved by the
    // scheduler and denormalised onto snmp_interfaces.effective_poll_sec.
    t.integer('poll_interval_sec').nullable();

    t.integer('timeout_ms').notNullable().defaultTo(2000);
    t.integer('retries').notNullable().defaultTo(1);
    // GETBULK tuning. Too high fragments the UDP response and a lost fragment
    // costs the whole PDU; 10 is the conservative default that works on the
    // RouterOS/DrayTek/Zyxel mix.
    t.integer('max_repetitions').notNullable().defaultTo(10);

    // Tri-state as two columns would be cleaner, but this is the spec's name.
    // false forces the Counter32 fallback (ifInOctets / ifSpeed).
    t.boolean('supports_hc_counters').notNullable().defaultTo(true);

    // --- Scheduler state ---------------------------------------------------
    // next_poll_at is NOT NULL and defaults to now(): a target created at
    // 02:00 must be polled at 02:00, not skipped until someone sets a date.
    t.timestamp('next_poll_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('last_poll_at', { useTz: true }).nullable();
    t.timestamp('last_ok_at', { useTz: true }).nullable();
    t.integer('consecutive_failures').notNullable().defaultTo(0);
    // Redacted message only — section 8.2. Never a community string.
    t.text('last_error').nullable();

    // Interface discovery is expensive (a full ifTable walk) and is NOT done
    // every cycle; this is when it last ran and when it is next due.
    t.timestamp('last_discovery_at', { useTz: true }).nullable();
    t.timestamp('next_discovery_at', { useTz: true }).nullable();

    t.timestamps(true, true);

    t.index('credential_id');
  });

  // THE SCHEDULER INDEX (spec 3.3). The hot query is
  //   SELECT ... FROM snmp_targets
  //    WHERE enabled AND next_poll_at <= now()
  //    ORDER BY next_poll_at LIMIT n
  // The column order matters: `enabled` is the equality predicate and must come
  // first, `next_poll_at` is the range predicate AND the sort key, so the index
  // serves the WHERE and removes the sort in one scan. Reversing the two would
  // force a full index scan plus a filter.
  //
  // A partial index (`WHERE enabled`) would be marginally smaller, but the spec
  // asks for INDEX(enabled, next_poll_at) and the composite also serves the
  // "what is disabled and overdue" admin view. 300 rows: the difference is
  // noise either way.
  await knex.schema.raw(
    'CREATE INDEX snmp_targets_sched ON snmp_targets (enabled, next_poll_at)',
  );

  await knex.schema.raw(
    'ALTER TABLE snmp_targets ADD CONSTRAINT snmp_targets_port_chk ' +
      'CHECK (port > 0 AND port <= 65535)',
  );
  // 5 s floor: below that the poll cycle overlaps itself on any real WAN.
  // 86400 ceiling: a "poll once a day" target is a configuration mistake, not
  // a monitoring strategy, and it breaks every rollup assumption (§4.6).
  await knex.schema.raw(
    'ALTER TABLE snmp_targets ADD CONSTRAINT snmp_targets_interval_chk ' +
      'CHECK (poll_interval_sec IS NULL OR (poll_interval_sec >= 5 AND poll_interval_sec <= 86400))',
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_targets ADD CONSTRAINT snmp_targets_timeout_chk ' +
      'CHECK (timeout_ms >= 100 AND timeout_ms <= 60000)',
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_targets ADD CONSTRAINT snmp_targets_retries_chk ' +
      'CHECK (retries >= 0 AND retries <= 5)',
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_targets ADD CONSTRAINT snmp_targets_maxrep_chk ' +
      'CHECK (max_repetitions >= 1 AND max_repetitions <= 100)',
  );

  // ==========================================================================
  // snmp_interfaces — the STABLE identity of a series.
  // ==========================================================================

  await knex.schema.createTable('snmp_interfaces', (t) => {
    t.increments('id').primary();
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    // THE identity half. ifName (or ifDescr when the agent has no ifName).
    t.string('if_name', 255).notNullable();

    // THE mutable half. Carried ONLY so that a change can be detected: every
    // poll re-reads ifName at this index and compares (study §3.4-c). It is
    // never, ever part of a uniqueness rule.
    t.integer('if_index').notNullable();

    t.string('if_alias', 255).nullable();
    t.string('if_descr', 255).nullable();
    t.string('phys_address', 64).nullable();
    // IANAifType. 6 = ethernetCsmacd, 24 = softwareLoopback, 23 = ppp...
    t.integer('if_type').nullable();

    // ifHighSpeed x 1e6, or ifSpeed on the Counter32 fallback. 0 = unknown,
    // which the rate calculator must treat as "no clamp possible" and NOT as
    // "zero capacity" (study §3.4-g).
    t.bigInteger('speed_bps').notNullable().defaultTo(0);

    // IF-MIB raw values, 1..7 for oper (up/down/testing/unknown/dormant/
    // notPresent/lowerLayerDown) and 1..3 for admin. 0 = never read.
    t.specificType('admin_status', 'smallint').notNullable().defaultTo(0);
    t.specificType('oper_status', 'smallint').notNullable().defaultTo(0);

    // 'active' | 'vanished'. NEVER deleted — see the header, decision 2.
    t.string('state', 16).notNullable().defaultTo('active');

    // Operator switch: an interface can exist, be discovered, and deliberately
    // not be polled (a loopback, a bridge port nobody cares about).
    t.boolean('monitored').notNullable().defaultTo(true);

    // Denormalised from snmp_targets.poll_interval_sec (after inheritance is
    // resolved). It lives here so the rollup's `expected_count` computation and
    // its `WHERE effective_poll_sec <= 60` tier filter (study §4.6) do not need
    // a join in the hot path. The scheduler is responsible for keeping it true.
    t.integer('effective_poll_sec').notNullable().defaultTo(30);

    // Counter width ACTUALLY obtained for this interface, which can differ from
    // snmp_targets.supports_hc_counters: an agent may advertise HC counters and
    // still answer noSuchObject on one port.
    t.specificType('counter_bits', 'smallint').notNullable().defaultTo(64);

    // Set when a Counter32 cannot be sampled unambiguously at this poll
    // interval for this line speed (study §3.2: a saturated 1 Gbit/s link wraps
    // a Counter32 in 34.4 s). The UI must REFUSE to draw a rate graph for such
    // an interface rather than draw a wrong one.
    t.boolean('counter_unreliable').notNullable().defaultTo(false);

    // Raised when ifName at if_index stopped matching (risk R12). Nothing is
    // written for this interface until discovery confirms the new ifIndex.
    t.boolean('needs_rediscovery').notNullable().defaultTo(false);

    t.timestamp('first_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('last_seen_at', { useTz: true }).nullable();
    t.timestamp('vanished_at', { useTz: true }).nullable();

    t.timestamps(true, true);

    // ── THE constraint of this milestone ──────────────────────────────────
    t.unique(['device_id', 'if_name']);

    // "All the interfaces I must poll on this device", the discovery/scheduler
    // path. Not covered by the unique index above, which leads with device_id
    // but then if_name.
    t.index(['device_id', 'state']);
  });

  await knex.schema.raw(
    'ALTER TABLE snmp_interfaces ADD CONSTRAINT snmp_interfaces_state_chk ' +
      `CHECK (state IN (${IF_STATES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_interfaces ADD CONSTRAINT snmp_interfaces_counter_bits_chk ' +
      'CHECK (counter_bits IN (32, 64))',
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_interfaces ADD CONSTRAINT snmp_interfaces_poll_sec_chk ' +
      'CHECK (effective_poll_sec >= 5 AND effective_poll_sec <= 86400)',
  );
  // A vanished interface without a date is an interface nobody can explain.
  await knex.schema.raw(
    'ALTER TABLE snmp_interfaces ADD CONSTRAINT snmp_interfaces_vanished_chk ' +
      "CHECK (state <> 'vanished' OR vanished_at IS NOT NULL)",
  );
  // The rollup reads effective_poll_sec to build expected_count as a smallint;
  // a 0 here would be a division by zero in the hot path. Guarded above by the
  // >= 5 bound, stated here for the reader.
  await knex.schema.raw(
    'ALTER TABLE snmp_interfaces ADD CONSTRAINT snmp_interfaces_if_index_chk ' +
      'CHECK (if_index >= 0)',
  );

  // ==========================================================================
  // snmp_poll_state — the delta baseline. Study §1.3, verbatim.
  // ==========================================================================
  // This is what makes a rate computable AND correct after a server restart. A
  // memory-only baseline means a one-cycle hole on 2400 interfaces at every
  // deploy, and — worse — no way at all to notice a reboot that happened while
  // we were down.
  //
  // Written entirely in raw SQL rather than through the Knex builder because
  // `numeric(20,0)` is the load-bearing detail of the table (see header,
  // decision 3) and it should be readable as such.

  await knex.schema.raw(`
    CREATE TABLE snmp_poll_state (
      if_id             integer       PRIMARY KEY
                                      REFERENCES snmp_interfaces(id) ON DELETE CASCADE,
      device_id         integer       NOT NULL
                                      REFERENCES devices(id) ON DELETE CASCADE,

      -- Instant of the previous read. mono_ns is the denominator DURING the
      -- life of the process (immune to an NTP step); wall_ts is the fallback
      -- after a restart, where another process's mono_ns is meaningless.
      wall_ts           timestamptz   NOT NULL,
      mono_ns           bigint        NOT NULL,
      writer_epoch      uuid          NOT NULL,

      -- Previous raw counters. numeric(20,0) and NOT bigint: ifHCInOctets is an
      -- UNSIGNED Counter64 (up to 1.845e19), past bigint's 9.22e18.
      in_octets         numeric(20,0) NOT NULL,
      out_octets        numeric(20,0) NOT NULL,
      in_pkts           numeric(20,0) NOT NULL,
      out_pkts          numeric(20,0) NOT NULL,
      in_errs           numeric(20,0) NOT NULL,
      out_errs          numeric(20,0) NOT NULL,
      in_discards       numeric(20,0) NOT NULL,
      out_discards      numeric(20,0) NOT NULL,

      -- EFFECTIVE width of the counters read at the last poll (32 or 64).
      counter_bits      smallint      NOT NULL DEFAULT 64,

      -- sysUpTime of the DEVICE at read time (TimeTicks, 1/100 s). The only
      -- reliable reboot detector. Duplicated per interface to keep a join and a
      -- second UPDATE out of a path executed 2400 times every 30 seconds.
      sys_uptime_ticks  bigint        NOT NULL,
      sys_uptime_epoch  integer       NOT NULL DEFAULT 0,

      -- Link speed at the last poll, in bit/s. 0 = unknown -> no clamp possible.
      line_speed_bps    bigint        NOT NULL DEFAULT 0,

      last_discard         text        NULL,
      consecutive_discards smallint    NOT NULL DEFAULT 0,
      updated_at           timestamptz NOT NULL DEFAULT now()
    )
  `);

  // "Invalidate every baseline of this device", the one-shot query the reboot
  // detector runs (study §3.4-d). Without it that is a seq scan per reboot.
  await knex.schema.raw('CREATE INDEX snmp_poll_state_device ON snmp_poll_state (device_id)');
  await knex.schema.raw(
    'ALTER TABLE snmp_poll_state ADD CONSTRAINT snmp_poll_state_bits_chk ' +
      'CHECK (counter_bits IN (32, 64))',
  );
  // An unsigned Counter64 never exceeds 2^64-1 = 18446744073709551615, and a
  // negative counter is a decode bug we want to hear about at write time.
  await knex.schema.raw(
    'ALTER TABLE snmp_poll_state ADD CONSTRAINT snmp_poll_state_counter_range_chk CHECK (' +
      '  in_octets    BETWEEN 0 AND 18446744073709551615' +
      '  AND out_octets   BETWEEN 0 AND 18446744073709551615' +
      '  AND in_pkts      BETWEEN 0 AND 18446744073709551615' +
      '  AND out_pkts     BETWEEN 0 AND 18446744073709551615' +
      '  AND in_errs      BETWEEN 0 AND 18446744073709551615' +
      '  AND out_errs     BETWEEN 0 AND 18446744073709551615' +
      '  AND in_discards  BETWEEN 0 AND 18446744073709551615' +
      '  AND out_discards BETWEEN 0 AND 18446744073709551615' +
      ')',
  );

  // ==========================================================================
  // snmp_thresholds — for_seconds and hysteresis_pct are the whole point.
  // ==========================================================================

  await knex.schema.createTable('snmp_thresholds', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable().defaultTo(1)
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('name', 128).notNullable();
    t.boolean('enabled').notNullable().defaultTo(true);

    // What the rule applies to. `scope` says which of the three FK columns is
    // meaningful; the CHECK below makes the pair consistent so no evaluator has
    // to guess.
    t.string('scope', 16).notNullable().defaultTo('global');
    t.integer('device_id').nullable()
      .references('id').inTable('devices').onDelete('CASCADE');
    t.integer('group_id').unsigned().nullable()
      .references('id').inTable('device_groups').onDelete('CASCADE');
    t.integer('if_id').nullable()
      .references('id').inTable('snmp_interfaces').onDelete('CASCADE');

    t.string('metric', 32).notNullable();
    t.string('comparator', 4).notNullable().defaultTo('gt');
    // numeric, not double: a threshold of 0.1 % must compare equal to itself
    // after a round trip through the database and the JSON API.
    t.specificType('value', 'numeric(20,4)').notNullable();

    // ── NOT NULL, NO DEFAULT — see the header, decision 4. ─────────────────
    // How long the condition must hold before the alert fires. This is what
    // stops a single 30-second spike from paging anybody.
    t.integer('for_seconds').notNullable();
    // How far BACK below the threshold the value must come before the alert
    // clears, as a percentage of `value`. This is what stops a value sitting on
    // the boundary from firing/clearing/firing every cycle forever.
    t.specificType('hysteresis_pct', 'numeric(5,2)').notNullable();

    t.string('severity', 16).notNullable().defaultTo('warning');

    // Optional routing override; NULL means "use the normal binding rules".
    t.integer('channel_id').nullable()
      .references('id').inTable('notification_channels').onDelete('SET NULL');

    t.timestamps(true, true);

    t.unique(['tenant_id', 'name']);
    t.index(['enabled', 'metric']);
    t.index('device_id');
    t.index('group_id');
    t.index('if_id');
  });

  await knex.schema.raw(
    'ALTER TABLE snmp_thresholds ADD CONSTRAINT snmp_thresholds_scope_chk ' +
      `CHECK (scope IN (${THRESHOLD_SCOPES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_thresholds ADD CONSTRAINT snmp_thresholds_metric_chk ' +
      `CHECK (metric IN (${THRESHOLD_METRICS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_thresholds ADD CONSTRAINT snmp_thresholds_comparator_chk ' +
      `CHECK (comparator IN (${THRESHOLD_COMPARATORS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_thresholds ADD CONSTRAINT snmp_thresholds_severity_chk ' +
      `CHECK (severity IN (${THRESHOLD_SEVERITIES}))`,
  );
  // for_seconds = 0 would mean "fire on the first sample", which is the
  // flapping generator the column exists to prevent. One poll interval is the
  // floor that makes sense; 24 h is the ceiling above which nobody is watching.
  await knex.schema.raw(
    'ALTER TABLE snmp_thresholds ADD CONSTRAINT snmp_thresholds_for_seconds_chk ' +
      'CHECK (for_seconds > 0 AND for_seconds <= 86400)',
  );
  // 0 is allowed (an operator may genuinely want none) but must be TYPED, not
  // inherited from a default. Above 50 % the clear condition becomes so distant
  // that a real recovery would never be reported.
  await knex.schema.raw(
    'ALTER TABLE snmp_thresholds ADD CONSTRAINT snmp_thresholds_hysteresis_chk ' +
      'CHECK (hysteresis_pct >= 0 AND hysteresis_pct <= 50)',
  );
  // scope and the FK columns must agree, exactly one target set (or none, for
  // 'global' / 'tenant').
  await knex.schema.raw(
    'ALTER TABLE snmp_thresholds ADD CONSTRAINT snmp_thresholds_scope_shape_chk CHECK (' +
      "  (scope IN ('global','tenant') AND device_id IS NULL AND group_id IS NULL AND if_id IS NULL)" +
      "  OR (scope = 'device'    AND device_id IS NOT NULL AND group_id IS NULL AND if_id IS NULL)" +
      "  OR (scope = 'group'     AND group_id  IS NOT NULL AND device_id IS NULL AND if_id IS NULL)" +
      "  OR (scope = 'interface' AND if_id     IS NOT NULL AND device_id IS NULL AND group_id IS NULL)" +
      ')',
  );

  // ==========================================================================
  // snmp_alert_state — one row per (rule, entity). ok | pending | firing.
  // ==========================================================================
  // `pending` is not cosmetic: it is the state in which the condition is true
  // but `for_seconds` has not yet elapsed. Collapsing it into `ok` would make
  // the dwell timer unobservable and impossible to debug.

  await knex.schema.createTable('snmp_alert_state', (t) => {
    t.integer('threshold_id').notNullable()
      .references('id').inTable('snmp_thresholds').onDelete('CASCADE');

    // Polymorphic target, because one rule at group scope produces state rows
    // for interfaces AND devices. A pair of nullable FKs would allow "both set"
    // and "neither set"; `entity_kind` + `entity_id` cannot.
    t.string('entity_kind', 16).notNullable();
    t.integer('entity_id').notNullable();

    // Denormalised so the alert list can be tenant-filtered and device-grouped
    // without joining through snmp_interfaces on every render.
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    t.string('state', 16).notNullable().defaultTo('ok');

    // When the CURRENT state began. Drives "firing for 4 h" in the UI.
    t.timestamp('since', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    // When the condition first breached — the start of the for_seconds timer.
    // Distinct from `since`: on the ok -> pending -> firing path they differ.
    t.timestamp('breach_started_at', { useTz: true }).nullable();

    // Study §2.7: at startup, any pending/firing row whose last_eval_at is
    // older than 3 x for_seconds is forced back to 'ok' WITHOUT notifying.
    // Without that sweep, a 3-day outage ends in 300 resolution notifications
    // for alarms nobody was watching any more.
    t.timestamp('last_eval_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.specificType('last_value', 'numeric(20,4)').nullable();

    t.timestamp('notified_at', { useTz: true }).nullable();
    t.integer('notification_count').notNullable().defaultTo(0);

    t.primary(['threshold_id', 'entity_kind', 'entity_id']);

    // The startup staleness sweep and the "what is firing right now" view.
    t.index(['state', 'last_eval_at']);
    t.index('device_id');
  });

  await knex.schema.raw(
    'ALTER TABLE snmp_alert_state ADD CONSTRAINT snmp_alert_state_state_chk ' +
      `CHECK (state IN (${ALERT_STATES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE snmp_alert_state ADD CONSTRAINT snmp_alert_state_entity_chk ' +
      `CHECK (entity_kind IN (${ALERT_ENTITIES}))`,
  );
  // An 'ok' row has nothing pending; a pending/firing row must know when the
  // breach started, otherwise for_seconds cannot be evaluated at all.
  await knex.schema.raw(
    'ALTER TABLE snmp_alert_state ADD CONSTRAINT snmp_alert_state_breach_chk ' +
      "CHECK (state = 'ok' OR breach_started_at IS NOT NULL)",
  );

  // ==========================================================================
  // syslog_ingest_state — the circuit breaker of study §5.5.
  // ==========================================================================
  // The syslog is the dominant disk consumer of M3 (1.04 GB/day at a MODEST
  // 5 msg/device/min, against 1.55 GB/day for every SNMP series combined), and
  // a single device stuck in a log loop fills the volume — and therefore takes
  // down the supervision of all 300 sites — in one night. This table is the
  // per-source daily budget that makes that impossible.
  //
  // Keyed by source_ip and not by device_id: the flood usually arrives from
  // something we have NOT managed to identify, and an unattributed sender is
  // precisely the one that must be capped.

  await knex.schema.createTable('syslog_ingest_state', (t) => {
    t.specificType('source_ip', 'inet').notNullable();
    // UTC day (study §8.1: never a session-local date).
    t.date('day').notNullable();

    t.integer('device_id').nullable()
      .references('id').inTable('devices').onDelete('SET NULL');

    t.bigInteger('bytes_accepted').notNullable().defaultTo(0);
    t.bigInteger('messages_accepted').notNullable().defaultTo(0);
    // Counted, not stored: what the severity floor and the quota threw away.
    t.bigInteger('messages_dropped').notNullable().defaultTo(0);

    // Set when the daily quota is blown. Everything from this source is
    // discarded at the socket until it lapses, and an alert is raised.
    t.timestamp('suppressed_until', { useTz: true }).nullable();

    t.timestamp('first_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('last_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    t.primary(['source_ip', 'day']);
    t.index('device_id');
    // Lets the daily cleanup drop old rows by day without a scan.
    t.index('day');
  });
}

export async function down(knex: Knex): Promise<void> {
  // Reverse dependency order. snmp_alert_state -> snmp_thresholds ->
  // snmp_interfaces -> snmp_targets -> snmp_credentials, and snmp_poll_state
  // hangs off snmp_interfaces.
  await knex.schema.dropTableIfExists('syslog_ingest_state');
  await knex.schema.dropTableIfExists('snmp_alert_state');
  await knex.schema.dropTableIfExists('snmp_thresholds');
  await knex.schema.dropTableIfExists('snmp_poll_state');
  await knex.schema.dropTableIfExists('snmp_interfaces');
  await knex.schema.dropTableIfExists('snmp_targets');
  await knex.schema.dropTableIfExists('snmp_credentials');
}
