import type { Knex } from 'knex';

/**
 * 006_timeseries.ts — M3 part 2: the partitioned series.
 *
 * Implements sections 1 (the DDL) and 2 (the partition machinery) of
 * `docs/M3-series-temporelles.md`, and section 3.3 of ARCHITECTURE.md.
 *
 * SIZING, so that nobody re-derives it from the spec's wrong number. R7 says
 * "300 x 8 interfaces x 30 s ~ 20 M rows/month". That is the figure for a
 * 300-SECOND poll. At the 30 s poll this schema is built for:
 *
 *     300 devices x 8 interfaces          = 2 400 interfaces
 *     86 400 s/day / 30 s                 = 2 880 samples/interface/day
 *                                         = 6 912 000 rows/day
 *                                         = 207 M rows/month
 *
 * i.e. **90 rows/s sustained, 2 700 rows per 30 s cycle**. A batched INSERT
 * sustains 30 000-60 000 rows/s on one connection: the margin is ~400x, and
 * `pg-copy-streams` is pointless at this volume (its real crossover is around
 * 20 000 rows/cycle ~ 2 400 devices). The dominant disk consumer of M3 is the
 * syslog, not the SNMP series.
 *
 * ┌─ FIVE PRINCIPLES THAT GOVERN EVERY TABLE BELOW (study §1.1) ──────────────┐
 * │ (a) NO surrogate key on the sample tables. `id bigserial` would cost 8    │
 * │     bytes/row (+8.7 % on the raw table) and a sequence round trip for a   │
 * │     column nobody will ever read. The identity of a sample is (if_id, ts).│
 * │                                                                           │
 * │ (b) NO foreign key on `if_id` in the series tables. PG accepts one, but   │
 * │     it installs an RI trigger that runs PER ROW — 6.9 M checks/day of a   │
 * │     value the poller just read from its own cache, at a typical cost of   │
 * │     30-40 % of insert throughput. And ON DELETE CASCADE on a partitioned  │
 * │     series table is a trap: deleting one interface would DELETE millions  │
 * │     of rows, which is exactly what R7 forbids. Orphans age out in 48 h;   │
 * │     a nightly consistency check (study §8.4) replaces the constraint.     │
 * │                                                                           │
 * │ (c) NO uniqueness on the raw tables. PK(if_id, ts) would add ~40          │
 * │     bytes/row (+30 %) to guard against a duplicate the scheduler cannot   │
 * │     produce (one lock per interface, one leader). The ROLLUPS do carry    │
 * │     PK(if_id, bucket): that one is indispensable, it is what makes the    │
 * │     incremental computation idempotent through ON CONFLICT.               │
 * │                                                                           │
 * │ (d) Columns ordered 8 bytes, then 4, then 2, and ALL NOT NULL. A naive    │
 * │     order inserts 4 padding bytes per row (27 MB/day thrown away); the    │
 * │     systematic NOT NULL removes the null bitmap and keeps t_hoff at 24    │
 * │     bytes instead of 32 — 8 bytes on an 88-byte row, 9 %.                 │
 * │                                                                           │
 * │ (e) We store RATES, not counters. bits/s already computed and already     │
 * │     validated, never raw ifHCInOctets. Recomputing at read time would put │
 * │     a LAG() window in every graph query and re-introduce every wrap and   │
 * │     reboot trap AT READ TIME, i.e. everywhere. `elapsed_ms` is kept so a  │
 * │     rate stays auditable after the fact.                                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * RETENTION IS BY DROP OF PARTITION, NEVER BY DELETE. On 6.9 M rows a DELETE
 * takes 60-300 s, writes ~1.4 GB of WAL, creates 6.9 M dead tuples, returns
 * ZERO space to the OS, and — the decisive part — makes autovacuum reuse pages
 * in the middle of an append-only file, which DESTROYS the physical correlation
 * the BRIN index depends on. You would lose the space *and* the index. A DROP
 * takes under 50 ms and returns 912 MB immediately. There is no "just this
 * once". See `server/src/services/snmp/partition.service.ts`.
 */

// ── The partition policy, from study §2.1. ─────────────────────────────────
// Kept as data in `series_partition_policy` rather than duplicated between this
// migration and partition.service.ts. One source of truth, inspectable with a
// SELECT during an incident, and changeable without a deploy.
//
//  parent, grain, partition column, retention, units pre-created ahead
//
// "3 live partitions for 48 h of retention" is not a mistake: the unit of
// deletion is the day, so at 00:01 the J-2 partition still holds rows aged 24 h
// to 48 h and cannot go before J+2 00:00. Effective retention therefore swings
// between 48 h and 72 h. Wanting exactly 48 h would require a DELETE. The
// trade is explicit: +50 % disk on the raw table (0.9 GB) against zero bloat.
//
// 14 days ahead, not 2: an empty partition costs 3 relations x 8 KB = 24 KB, so
// 70 pre-created day partitions cost ~1.7 MB. What that buys is a server that
// can be down 13 days, a database restored from last week's backup that works
// immediately, and a maintenance job that can fail 13 days running before
// anyone loses a data point.
const POLICY: Array<[string, 'day' | 'week' | 'month', string, string, number]> = [
  ['snmp_if_samples', 'day', 'ts', '48 hours', 14],
  ['snmp_if_rollup_1m', 'day', 'bucket', '8 days', 14],
  ['snmp_if_rollup_5m', 'week', 'bucket', '90 days', 4],
  ['snmp_if_rollup_1h', 'month', 'bucket', '730 days', 3],
  ['snmp_device_samples', 'day', 'ts', '48 hours', 14],
  ['snmp_device_rollup_1m', 'day', 'bucket', '8 days', 14],
  ['snmp_device_rollup_5m', 'week', 'bucket', '90 days', 4],
  ['snmp_device_rollup_1h', 'month', 'bucket', '730 days', 3],
  ['snmp_traps', 'week', 'ts', '90 days', 4],
  ['syslog_messages', 'day', 'received_at', '7 days', 14],
];

/** The six rollup tiers, seeded into `series_rollup_state`. */
const ROLLUP_TIERS = ['if_1m', 'if_5m', 'if_1h', 'dev_1m', 'dev_5m', 'dev_1h'];

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // ensure_series_partition() — study §2.6.
  // ==========================================================================
  // Written in PL/pgSQL rather than TypeScript because it is called from three
  // places — the server bootstrap, the hourly maintenance job, and the writer's
  // error-recovery path — and because it must stay usable by hand during an
  // incident at 3 a.m.
  //
  // Not pg_partman: that is a pure-SQL extension so formally compatible with
  // D6, but it means installing it in the image, versioning it, migrating it,
  // and one day debugging ITS retention logic. These ~60 lines are readable by
  // the whole team.
  await knex.schema.raw(`
    CREATE OR REPLACE FUNCTION ensure_series_partition(
      p_parent  regclass,
      p_grain   text,
      p_at      timestamptz
    ) RETURNS text
    LANGUAGE plpgsql AS $fn$
    DECLARE
      v_from timestamptz;
      v_to   timestamptz;
      v_name text;
    BEGIN
      IF p_grain NOT IN ('day', 'week', 'month') THEN
        RAISE EXCEPTION 'ensure_series_partition: unsupported grain %', p_grain;
      END IF;

      -- date_trunc in UTC. Partition bounds must NEVER depend on the session
      -- TimeZone, otherwise two nodes in two time zones create overlapping
      -- partitions and the ATTACH fails — in the middle of the night, when
      -- nobody is looking. (study §8.1)
      v_from := date_trunc(p_grain, p_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
      v_to   := v_from + ('1 ' || p_grain)::interval;
      v_name := p_parent::text || '_' || to_char(v_from AT TIME ZONE 'UTC', 'YYYYMMDD');

      IF to_regclass(v_name) IS NOT NULL THEN
        RETURN v_name;                 -- already there: exit without any lock
      END IF;

      BEGIN
        EXECUTE format(
          'CREATE TABLE IF NOT EXISTS %I PARTITION OF %s FOR VALUES FROM (%L) TO (%L)',
          v_name, p_parent::text, v_from, v_to);
      EXCEPTION
        -- Layer 1 of the creation strategy runs on EVERY node, leader or not
        -- (study §2.5), so two nodes booting together race here. Whoever loses
        -- gets duplicate_table or a catalogue unique violation; both mean "the
        -- partition now exists", which is precisely the postcondition asked of
        -- this function. Re-raising would crash a bootstrap for a success.
        WHEN duplicate_table OR unique_violation THEN
          RETURN v_name;
      END;

      -- Raw tables: insert-only, 72 h lifetime, wraparound impossible. We turn
      -- autovacuum off (it would only do useless work) but we KEEP an analyze
      -- policy — without statistics the planner estimates 0 rows and picks a
      -- catastrophic plan for the rollup queries. The hourly job also runs an
      -- explicit ANALYZE on the current partition, because
      -- autovacuum_enabled = false disables the automatic ANALYZE too.
      IF p_parent::text LIKE '%\\_samples' THEN
        EXECUTE format('ALTER TABLE %I SET ('
          || 'autovacuum_enabled = false, '
          || 'autovacuum_analyze_scale_factor = 0.02, '
          || 'autovacuum_analyze_threshold = 50000)', v_name);
      END IF;

      RETURN v_name;
    END $fn$;
  `);

  // Loop helper. Same implementation used by the migration and by
  // partition.service.ts, so "what the installer created" and "what the hourly
  // job maintains" can never drift apart.
  await knex.schema.raw(`
    CREATE OR REPLACE FUNCTION ensure_series_partitions(
      p_parent  regclass,
      p_grain   text,
      p_back    integer,
      p_ahead   integer
    ) RETURNS integer
    LANGUAGE plpgsql AS $fn$
    DECLARE
      i     integer;
      n     integer := 0;
      v_now timestamptz := now();
    BEGIN
      FOR i IN -p_back .. p_ahead LOOP
        PERFORM ensure_series_partition(
          p_parent, p_grain, v_now + (i || ' ' || p_grain)::interval);
        n := n + 1;
      END LOOP;
      RETURN n;
    END $fn$;
  `);

  // ==========================================================================
  // series_partition_policy — grain, retention and look-ahead, as data.
  // ==========================================================================
  await knex.schema.raw(`
    CREATE TABLE series_partition_policy (
      parent           text        PRIMARY KEY,
      grain            text        NOT NULL,
      part_column      text        NOT NULL,
      retention        interval    NOT NULL,
      precreate_units  smallint    NOT NULL,
      -- An escape hatch for an incident: set false and the maintenance job
      -- stops touching this table, without a deploy and without a migration.
      enabled          boolean     NOT NULL DEFAULT true,
      CONSTRAINT series_partition_policy_grain_chk
        CHECK (grain IN ('day', 'week', 'month')),
      CONSTRAINT series_partition_policy_retention_chk
        CHECK (retention >= INTERVAL '1 hour'),
      CONSTRAINT series_partition_policy_precreate_chk
        CHECK (precreate_units BETWEEN 1 AND 60)
    )
  `);

  // ==========================================================================
  // snmp_if_samples — the raw table. Study §1.2.
  // ==========================================================================
  await knex.schema.raw(`
    CREATE TABLE snmp_if_samples (
      -- 8 bytes ---------------------------------------------------------------
      ts              timestamptz NOT NULL,
      in_bps          bigint      NOT NULL,   -- bits/s, already computed, already validated
      out_bps         bigint      NOT NULL,
      -- 4 bytes ---------------------------------------------------------------
      if_id           integer     NOT NULL,   -- -> snmp_interfaces.id, NO FK (principle b)
      in_pps          integer     NOT NULL,   -- packets/s; int4 is enough (14.9 Mpps at 10G)
      out_pps         integer     NOT NULL,
      in_errs         integer     NOT NULL,   -- DELTA over the window, not the absolute counter
      out_errs        integer     NOT NULL,
      in_discards     integer     NOT NULL,
      out_discards    integer     NOT NULL,
      elapsed_ms      integer     NOT NULL,   -- real delta window -> auditability
      -- 2 bytes ---------------------------------------------------------------
      oper_status     smallint    NOT NULL    -- IF-MIB ifOperStatus, 1..7
    ) PARTITION BY RANGE (ts)
  `);

  // Declared on the PARENT during the migration, while the table is EMPTY: each
  // partition created afterwards inherits them automatically (PG11+). NEVER add
  // an index to a populated partitioned parent — ACCESS EXCLUSIVE plus a
  // rebuild of every partition, i.e. the poller stops. The correct late-index
  // procedure is documented in study §8.2 (CREATE INDEX ON ONLY parent, then
  // CREATE INDEX CONCURRENTLY per partition, then ALTER INDEX ... ATTACH).
  //
  // pages_per_range = 32, not the default 128. A 128-page BRIN range covers
  // 128 x 88 = 11 264 rows ~ 141 s of insertion, so a one-minute rollup window
  // would read at least 1 MB for 4 800 useful rows. At 32 pages the grain drops
  // to ~35 s and the query reads ~2 ranges = 512 KB. The cost is a BRIN index
  // 4x larger — still under 500 KB per partition.
  //
  // The BRIN only works because this table is strictly APPEND-ONLY and
  // correlated: one poll cycle writes 2 400 rows with near-identical `ts`, back
  // to back. Any retroactive write (backfill, import) breaks the correlation
  // and makes the BRIN useless. That is one more reason backfill into the raw
  // table is forbidden.
  await knex.schema.raw(
    'CREATE INDEX snmp_if_samples_ts_brin ON snmp_if_samples ' +
      'USING brin (ts) WITH (pages_per_range = 32)',
  );
  // The DESC is not load-bearing and everyone should know it: PostgreSQL walks
  // any B-tree backwards at the same cost, so (if_id, ts) would serve an
  // ORDER BY ts DESC LIMIT n just as well. It is kept because the spec writes
  // it and it costs nothing. The real purpose of this index is to make the
  // "one interface, 6 hours" zoom possible without reading the 1.7 M rows in
  // the window. It is expensive — that is the price of zooming on raw data.
  await knex.schema.raw(
    'CREATE INDEX snmp_if_samples_if_ts ON snmp_if_samples (if_id, ts DESC)',
  );
  // 1..7 is the whole IF-MIB ifOperStatus range. A value outside it is a decode
  // bug, and this table is where it would be preserved forever.
  await knex.schema.raw(
    'ALTER TABLE snmp_if_samples ADD CONSTRAINT snmp_if_samples_oper_chk ' +
      'CHECK (oper_status BETWEEN 1 AND 7)',
  );
  // elapsed_ms = 0 would be a division by zero upstream; a negative rate is an
  // arithmetic bug. Both are cheap to state and impossible to find later.
  await knex.schema.raw(
    'ALTER TABLE snmp_if_samples ADD CONSTRAINT snmp_if_samples_sane_chk ' +
      'CHECK (elapsed_ms > 0 AND in_bps >= 0 AND out_bps >= 0)',
  );

  // ==========================================================================
  // snmp_device_samples — study §1.5.
  // ==========================================================================
  // Doctrine difference with interfaces: here `reachable = false` STILL writes
  // a row. A device not answering is information (it feeds the reachability
  // verdicts and the availability graph), not a doubt about a value. On an
  // interface, a doubtful counter carries no information at all: we write
  // nothing.
  //
  // The sentinels (-1, -32768) rather than NULL avoid the null bitmap, which
  // would push t_hoff from 24 to 32 bytes — 8 bytes on a 76-byte row, +10 % for
  // three rarely-absent columns. THEY ARE DOCUMENTED IN THE TYPESCRIPT TYPE
  // (`shared/src/telemetry.ts`), otherwise somebody displays "CPU: -1 %".
  await knex.schema.raw(`
    CREATE TABLE snmp_device_samples (
      ts              timestamptz NOT NULL,
      uptime_ticks    bigint      NOT NULL,
      mem_used_bytes  bigint      NOT NULL,   -- -1 = not exposed
      mem_total_bytes bigint      NOT NULL,   -- -1 = not exposed
      device_id       integer     NOT NULL,
      rtt_us          integer     NOT NULL,   -- microseconds; -1 = not measured
      cpu_pct         smallint    NOT NULL,   -- 0..100; -1 = not exposed
      temp_dc         smallint    NOT NULL,   -- tenths of degC; -32768 = not exposed
      reachable       boolean     NOT NULL
    ) PARTITION BY RANGE (ts)
  `);
  await knex.schema.raw(
    'CREATE INDEX snmp_device_samples_ts_brin ON snmp_device_samples ' +
      'USING brin (ts) WITH (pages_per_range = 32)',
  );
  await knex.schema.raw(
    'CREATE INDEX snmp_device_samples_dev_ts ON snmp_device_samples (device_id, ts DESC)',
  );
  // The sentinels are part of the contract, so they are part of the constraint:
  // cpu_pct is either -1 or a real percentage, never 137.
  await knex.schema.raw(
    'ALTER TABLE snmp_device_samples ADD CONSTRAINT snmp_device_samples_sentinel_chk ' +
      'CHECK (cpu_pct BETWEEN -1 AND 100 AND rtt_us >= -1)',
  );

  // ==========================================================================
  // The interface rollups — 1m / 5m / 1h. Study §1.4.
  // ==========================================================================
  // Identical at all three levels; only partitioning and retention differ.
  //
  // PostgreSQL requires the partition key to be part of any unique constraint.
  // `bucket` is, so the PK(if_id, bucket) the spec asks for applies directly to
  // a partitioned table with no compromise. The (if_id, bucket) order is the
  // right one: every graph query is "one interface, one time range", and the PK
  // doubles as the covering index.
  //
  // sample_count / expected_count is the GAP MECHANISM at the aggregated level
  // — the pair that distinguishes "0 bit/s" from "we did not measure".
  // `expected_count` comes from snmp_interfaces.effective_poll_sec, denormalised
  // to keep a snmp_interfaces -> snmp_targets join out of the rollup hot path.
  // Display rule: sample_count < expected_count / 2 => the API emits null and
  // Recharts does not connect the line (connectNulls={false}).
  //
  // HONESTY ABOUT p95 AT THE 1-MINUTE LEVEL: at a 30 s poll a one-minute bucket
  // holds TWO samples, and a 95th percentile over 2 values IS the maximum. The
  // columns are kept for schema uniformity (16 bytes/row, 0.44 GB over the
  // 8-day retention — negligible) but THE UI MUST NOT LABEL THEM "p95" AT THE
  // 1 min LEVEL. A percentile only becomes a statistic from ~10 samples, i.e.
  // at the 5 min level.
  for (const table of ['snmp_if_rollup_1m', 'snmp_if_rollup_5m', 'snmp_if_rollup_1h']) {
    await knex.schema.raw(`
      CREATE TABLE ${table} (
        bucket         timestamptz NOT NULL,
        in_avg_bps     bigint      NOT NULL,
        in_max_bps     bigint      NOT NULL,
        in_p95_bps     bigint      NOT NULL,
        out_avg_bps    bigint      NOT NULL,
        out_max_bps    bigint      NOT NULL,
        out_p95_bps    bigint      NOT NULL,
        if_id          integer     NOT NULL,
        in_errs        integer     NOT NULL,
        out_errs       integer     NOT NULL,
        in_discards    integer     NOT NULL,
        out_discards   integer     NOT NULL,
        sample_count   smallint    NOT NULL,
        expected_count smallint    NOT NULL,
        PRIMARY KEY (if_id, bucket)
      ) PARTITION BY RANGE (bucket)
    `);
    // Retention scans by time, the PK leads with if_id. A BRIN on the bucket
    // costs a few KB per partition and is what keeps the nightly consistency
    // check (§8.4) and any time-ranged maintenance from a full scan.
    await knex.schema.raw(
      `CREATE INDEX ${table}_bucket_brin ON ${table} ` +
        'USING brin (bucket) WITH (pages_per_range = 32)',
    );
    await knex.schema.raw(
      `ALTER TABLE ${table} ADD CONSTRAINT ${table}_count_chk ` +
        'CHECK (sample_count >= 0 AND expected_count > 0)',
    );
  }

  // ==========================================================================
  // The device rollups — same three tiers.
  // ==========================================================================
  // Weighted averages are computed on the way IN (study §4.4): the 1 h tier
  // reads the 5 min tier and must weight by sample_count. avg(avg) is THE
  // classic rollup-cascade error — on an hour where 11 buckets are full and the
  // 12th holds a single sample at 10x the rate, avg(avg) overstates by ~7 %.
  // Small, systematic, and impossible to trace back a year later.
  for (const table of [
    'snmp_device_rollup_1m',
    'snmp_device_rollup_5m',
    'snmp_device_rollup_1h',
  ]) {
    await knex.schema.raw(`
      CREATE TABLE ${table} (
        bucket             timestamptz NOT NULL,
        mem_used_avg_bytes bigint      NOT NULL,
        mem_used_max_bytes bigint      NOT NULL,
        mem_total_bytes    bigint      NOT NULL,
        uptime_ticks_max   bigint      NOT NULL,
        device_id          integer     NOT NULL,
        rtt_avg_us         integer     NOT NULL,
        rtt_max_us         integer     NOT NULL,
        rtt_p95_us         integer     NOT NULL,
        cpu_avg_pct        smallint    NOT NULL,
        cpu_max_pct        smallint    NOT NULL,
        temp_avg_dc        smallint    NOT NULL,
        temp_max_dc        smallint    NOT NULL,
        -- How many of the samples in the bucket answered. reachable_count = 0
        -- with sample_count = 120 is a device that was down for the whole
        -- bucket; it is NOT a gap, and the two must not look alike.
        reachable_count    smallint    NOT NULL,
        sample_count       smallint    NOT NULL,
        expected_count     smallint    NOT NULL,
        PRIMARY KEY (device_id, bucket)
      ) PARTITION BY RANGE (bucket)
    `);
    await knex.schema.raw(
      `CREATE INDEX ${table}_bucket_brin ON ${table} ` +
        'USING brin (bucket) WITH (pages_per_range = 32)',
    );
    await knex.schema.raw(
      `ALTER TABLE ${table} ADD CONSTRAINT ${table}_count_chk ` +
        'CHECK (sample_count >= 0 AND expected_count > 0 ' +
        'AND reachable_count >= 0 AND reachable_count <= sample_count)',
    );
  }

  // ==========================================================================
  // snmp_traps — weekly partitions, 90 days. ~10 MB/day: negligible.
  // ==========================================================================
  // `ts` is OUR receive time, not the agent's: a trap carries sysUpTime, not a
  // wall clock. device_id is nullable because a trap from an unknown source is
  // exactly the one worth keeping.
  await knex.schema.raw(`
    CREATE TABLE snmp_traps (
      ts             timestamptz NOT NULL,
      uptime_ticks   bigint      NULL,
      device_id      integer     NULL,
      specific_trap  integer     NULL,
      generic_trap   smallint    NULL,
      version        smallint    NOT NULL,
      source_ip      inet        NOT NULL,
      trap_oid       text        NOT NULL,
      enterprise_oid text        NULL,
      -- The raw varbind list, as received. jsonb and not json: we will query
      -- into it, and jsonb deduplicates keys and stores parsed.
      varbinds       jsonb       NOT NULL DEFAULT '{}'::jsonb,
      -- What the trap MEANS after the MIB/vendor mapping ran. Separate from
      -- varbinds on purpose: reprocessing with a better mapping must never
      -- destroy what the device actually sent.
      parsed         jsonb       NOT NULL DEFAULT '{}'::jsonb
    ) PARTITION BY RANGE (ts)
  `);
  await knex.schema.raw(
    'CREATE INDEX snmp_traps_ts_brin ON snmp_traps USING brin (ts) WITH (pages_per_range = 32)',
  );
  await knex.schema.raw('CREATE INDEX snmp_traps_dev_ts ON snmp_traps (device_id, ts DESC)');

  // ==========================================================================
  // syslog_messages — daily partitions, 7 days by default. Study §5.5.
  // ==========================================================================
  // THE DOMINANT DISK CONSUMER OF M3. At a modest 5 msg/device/min it writes
  // 1.04 GB/day against 1.55 GB/day for every SNMP series combined; a chatty
  // firewall logging sessions triples that on its own. Three rules follow, and
  // they are enforced elsewhere but stated here because this is where the cost
  // lands: 7-day retention (not 30), a severity floor AT INGESTION (what is
  // filtered is never written — no "store it and filter at display"), and the
  // per-source daily quota of `syslog_ingest_state` (005).
  //
  // ── PARTITIONED ON received_at, NOT ON THE DEVICE'S TIMESTAMP ──────────────
  // This is the one place where a partitioned table must not use the "natural"
  // time column. A syslog timestamp comes from the device's clock, and a router
  // that boots without NTP cheerfully reports 1970 or 2035. Partitioning on
  // that means either "no partition found for row" on every such message or,
  // worse, live partitions created decades away that retention never reaches.
  // It would also wreck the BRIN, which needs physical/temporal correlation.
  // `received_at` is OUR clock, always monotonic enough and always present.
  // `device_ts` is kept verbatim, because the difference between the two is
  // itself diagnostic (it is how you notice a fleet with no NTP).
  await knex.schema.raw(`
    CREATE TABLE syslog_messages (
      received_at     timestamptz NOT NULL,
      device_ts       timestamptz NULL,
      device_id       integer     NULL,
      -- RFC 5424 numeric facility (0..23) and severity (0..7). Stored numeric,
      -- not as labels: the label set differs per RFC and per vendor, the number
      -- does not.
      facility        smallint    NOT NULL,
      severity        smallint    NOT NULL,
      source_ip       inet        NOT NULL,
      hostname        text        NULL,
      app_name        text        NULL,
      proc_id         text        NULL,
      msg_id          text        NULL,
      msg             text        NOT NULL,
      structured_data jsonb       NOT NULL DEFAULT '{}'::jsonb,
      parsed          jsonb       NOT NULL DEFAULT '{}'::jsonb
    ) PARTITION BY RANGE (received_at)
  `);
  await knex.schema.raw(
    'CREATE INDEX syslog_messages_recv_brin ON syslog_messages ' +
      'USING brin (received_at) WITH (pages_per_range = 32)',
  );
  await knex.schema.raw(
    'CREATE INDEX syslog_messages_dev_recv ON syslog_messages (device_id, received_at DESC)',
  );
  // "Show me everything at error and above across the fleet" — the first thing
  // anyone does during an incident, and a seq scan over 2 M rows/day without it.
  await knex.schema.raw(
    'CREATE INDEX syslog_messages_sev_recv ON syslog_messages (severity, received_at DESC)',
  );
  await knex.schema.raw(
    'ALTER TABLE syslog_messages ADD CONSTRAINT syslog_messages_rfc_chk ' +
      'CHECK (facility BETWEEN 0 AND 23 AND severity BETWEEN 0 AND 7)',
  );

  // ==========================================================================
  // series_rollup_state — the incremental watermark. Study §4.3.
  // ==========================================================================
  await knex.schema.raw(`
    CREATE TABLE series_rollup_state (
      tier               text        PRIMARY KEY,   -- 'if_1m' | 'if_5m' | ...
      -- Start of the first UNPROCESSED bucket.
      watermark          timestamptz NOT NULL,
      last_run_at        timestamptz NULL,
      last_duration_ms   integer     NULL,
      last_rows          integer     NULL,
      consecutive_errors smallint    NOT NULL DEFAULT 0
    )
  `);

  // Seeded at "now", floored to the hour so all six tiers start aligned. If the
  // instance then sits unused for a month, the §2.7 guard rail applies: when
  // now() - watermark exceeds 2x the raw retention the job JUMPS the watermark
  // forward and logs a series_gap rather than trying to aggregate 4 320 buckets
  // of data that was never written.
  for (const tier of ROLLUP_TIERS) {
    await knex('series_rollup_state').insert({
      tier,
      watermark: knex.raw("date_trunc('hour', now())"),
    });
  }

  // ==========================================================================
  // Policy rows + the initial partitions.
  // ==========================================================================
  for (const [parent, grain, partColumn, retention, precreate] of POLICY) {
    await knex('series_partition_policy').insert({
      parent,
      grain: grain,
      part_column: partColumn,
      retention: knex.raw('?::interval', [retention]),
      precreate_units: precreate,
    });
  }

  // One unit back as well as `precreate` forward. The backward one is not
  // decoration: it covers the UTC-midnight boundary, where a poll cycle that
  // started at 23:59:59 can carry a `ts` on the previous day, and it makes a
  // fresh install immediately able to accept a late-arriving retry.
  //
  // Doing this inside the migration matters: without it, `migrate:latest`
  // leaves a partitioned parent with no partitions at all, and the very first
  // INSERT of the very first poll fails with SQLSTATE 23514. The installer must
  // not depend on the maintenance job having run once.
  for (const [parent, grain, , , precreate] of POLICY) {
    await knex.raw('SELECT ensure_series_partitions(?::regclass, ?, 1, ?)', [
      parent,
      grain,
      precreate,
    ]);
  }
}

export async function down(knex: Knex): Promise<void> {
  // DROP TABLE on a partitioned parent drops every partition with it, so there
  // is nothing to enumerate. The order is free: nothing here references
  // anything else here (principle b — no FKs on the series tables).
  await knex.schema.raw('DROP TABLE IF EXISTS syslog_messages');
  await knex.schema.raw('DROP TABLE IF EXISTS snmp_traps');
  for (const t of [
    'snmp_device_rollup_1h',
    'snmp_device_rollup_5m',
    'snmp_device_rollup_1m',
    'snmp_device_samples',
    'snmp_if_rollup_1h',
    'snmp_if_rollup_5m',
    'snmp_if_rollup_1m',
    'snmp_if_samples',
  ]) {
    await knex.schema.raw(`DROP TABLE IF EXISTS ${t}`);
  }
  await knex.schema.raw('DROP TABLE IF EXISTS series_rollup_state');
  await knex.schema.raw('DROP TABLE IF EXISTS series_partition_policy');
  await knex.schema.raw(
    'DROP FUNCTION IF EXISTS ensure_series_partitions(regclass, text, integer, integer)',
  );
  await knex.schema.raw(
    'DROP FUNCTION IF EXISTS ensure_series_partition(regclass, text, timestamptz)',
  );
}
