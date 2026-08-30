import type { Knex } from 'knex';

/**
 * 021_weather.ts — F5, Operator Weather (ARCHITECTURE.md §10/F5).
 *
 * The TypeScript contract these tables carry lives in `shared/src/weather.ts`.
 * The vocabularies below are the SAME lists, written once more as CHECKs,
 * because a service-layer enum is not what runs when somebody inserts a row
 * from psql during an incident.
 *
 * ┌─ WHAT THIS SCHEMA IS FOR, IN ONE SENTENCE ────────────────────────────────┐
 * │ To make "twelve sites left Orange in ten minutes" a row a human can read, │
 * │ and to make "one site flapped" incapable of becoming one.                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ EIGHT DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ──────────────────┐
 * │                                                                           │
 * │ 1. `operator_incidents_live_uniq` IS THE FEATURE'S SAFETY CATCH.          │
 * │    A PARTIAL UNIQUE INDEX on (tenant_id, asn) WHERE status <> 'closed'.   │
 * │    Twelve sites failing over produce twelve `wan_path_events` and AT MOST │
 * │    ONE incident, and that is guaranteed by Postgres rather than by the    │
 * │    correlator remembering to check. Partial because `closed` incidents    │
 * │    accumulate forever and must be allowed to repeat: the history of an    │
 * │    ASN is exactly what makes the next incident credible.                  │
 * │                                                                           │
 * │ 2. `tenant_id` IS ON EVERY TABLE THAT DESCRIBES A CUSTOMER, IT LEADS      │
 * │    EVERY UNIQUE KEY AND EVERY READ INDEX, AND THE COMPOSITE FOREIGN KEYS  │
 * │    (child_id, tenant_id) -> (parent_id, tenant_id) make cross-tenant      │
 * │    parentage unrepresentable. Same construction as 008 and 017. An        │
 * │    operator incident is a statement about ONE MSP customer's footprint at │
 * │    one carrier; merging two customers' sites into one quorum would both   │
 * │    leak the shape of a fleet and invent incidents out of two unrelated    │
 * │    halves.                                                                │
 * │                                                                           │
 * │ 3. `ip_asn_ranges` IS THE ONE TABLE WITH NO `tenant_id`, ON PURPOSE.      │
 * │    It holds PUBLIC ROUTING INFORMATION — "185.12.64.0/24 is AS2200" — and │
 * │    contains no customer datum of any kind. Per-tenant copies of the BGP   │
 * │    table would be 900 000 rows per customer to say the same thing. It is  │
 * │    reference data in the same sense as the library templates of 008, and  │
 * │    it is never SELECTed on its own by a tenant-scoped read: every path    │
 * │    that reaches it starts from a device the caller already has access to. │
 * │    WRITING it is a cross-tenant act and sits behind SETTINGS_MANAGE.      │
 * │                                                                           │
 * │ 4. THE ENRICHMENT IS OFFLINE, AND THAT IS A DESIGN DECISION WITH A COST.  │
 * │    Longest-prefix match against a locally held table, answered in the     │
 * │    same transaction as everything else. NOT one HTTP call per device per  │
 * │    failover: three hundred sites interrogating a third-party WHOIS every  │
 * │    time a carrier hiccups is a self-inflicted outage, a rate-limit ban    │
 * │    and a publication of the customer's topology to a third party — during │
 * │    the exact minutes the network is already broken. The cost is that the  │
 * │    table has to be loaded and refreshed; `weather_asn_import` records     │
 * │    when, from what, and how many rows, so nobody has to guess how stale   │
 * │    an attribution is.                                                     │
 * │                                                                           │
 * │ 5. `device_wan_path.effective_public_ip` IS A GENERATED COLUMN.           │
 * │    `COALESCE(observed_public_ip, reported_public_ip)` — the concentrator's │
 * │    observation first, the router's self-report only when there is nothing │
 * │    else. GENERATED ALWAYS ... STORED means no INSERT, no UPDATE and no    │
 * │    future service can invert that precedence. §10/F5 says the fallback    │
 * │    must never overwrite the observation; this is that sentence, compiled. │
 * │    `devices.wan_public_ip` is NOT touched by this milestone at all — it   │
 * │    belongs to `applySessionUp` and is mirrored here, never written back.  │
 * │                                                                           │
 * │ 6. `wan_path_events` IS KEYED (tenant_id, device_id, session_id) SO THE   │
 * │    INGESTION IS IDEMPOTENT BY CONSTRUCTION. The detector derives          │
 * │    transitions from `ppp_sessions` history; re-running it over the same   │
 * │    window must not double every vote and hand a quorum to six sites       │
 * │    scanned twice. `session_id` is nullable (an event can come from an     │
 * │    active probe rather than a session), so the unique index is PARTIAL —  │
 * │    NULLS DISTINCT would let the session-derived side repeat freely.       │
 * │                                                                           │
 * │ 7. THE HOT READ IS "AWAY EVENTS FOR THIS TENANT, ON THIS ASN, SINCE T",   │
 * │    and it has its own PARTIAL index — `from_asn` is nullable because a    │
 * │    private or unattributable address gets no ASN, and those rows are      │
 * │    exactly the ones the correlation must never scan.                      │
 * │                                                                           │
 * │ 8. THE POLICY IS STORED, PER TENANT, AND THE ASYMMETRY IS A CHECK.        │
 * │    `weather_settings_hold_down_chk` refuses a policy whose hold-down is   │
 * │    less than twice its window. An incident that closes as fast as it      │
 * │    opens flaps, and a flapping alert is a false positive delivered six    │
 * │    times. `shared/src/weather.ts` refuses the same policy at the same     │
 * │    ratio (`MIN_HOLD_DOWN_RATIO`); two independent refusals, because the   │
 * │    service-layer one is not what runs when a row is edited by hand.       │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2): nothing in this milestone reads, stores or transports a
 * credential. `device_wan_path` holds addresses and interface names; the ASN
 * table holds public routing data. There is no jsonb here that a driver writes
 * into — `operator_incidents.policy` is the tuning that produced the verdict
 * and nothing else, and it is built from `weatherPolicySchema` (`.strict()`),
 * so an unknown key cannot ride in.
 *
 * D3: nothing here writes to an equipment. The active-path probe READS
 * `/ip/route` and `/interface/lte` through the existing pool and writes only
 * into `device_wan_path`.
 */

// -- Vocabularies. Comment gives the LONGEST value; the column is wider. ------
const WAN_PATH_KINDS = "'wan_port','lte','other','unknown'";                     // 8
const WAN_EVENT_DIRECTIONS = "'away','back','lateral'";                          // 7
const WEATHER_SOURCES =
  "'ppp_caller_id','routeros_route','routeros_lte','snmp_if_type','device_reported'"; // 15
const INCIDENT_STATUSES = "'open','clearing','closed'";                          // 8
const ASN_RANGE_SOURCES = "'builtin','import','manual'";                         // 7
const IP_SCOPES =
  "'public','private','cgnat','loopback','linklocal','multicast','invalid'";     // 9

/** Mirror of `MIN_HOLD_DOWN_RATIO` in `shared/src/weather.ts`. Decision 8. */
const MIN_HOLD_DOWN_RATIO = 2;

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // 0. The composite target on `devices` (decision 2).
  // ==========================================================================
  // Migration 017 adds the same constraint, guarded, for the same reason. It is
  // re-asserted here rather than assumed so that this migration is correct on a
  // database where 017 was rolled back, and it is deliberately NOT dropped in
  // `down()` — 017 owns that, and taking a uniqueness guarantee away from
  // somebody else's foreign keys is not a rollback, it is a break.
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
  // 1. ip_asn_ranges — the offline enrichment (decisions 3 and 4).
  // ==========================================================================

  await knex.schema.createTable('ip_asn_ranges', (t) => {
    t.bigIncrements('id').primary();

    // `cidr`, not `text`: containment and longest-prefix are index-backed
    // operators on this type, and the normalisation (host bits refused) is the
    // database's problem rather than every future caller's.
    t.specificType('prefix', 'cidr').notNullable();

    // 32-bit ASN. `bigint` because 4-byte ASNs exceed int4 (AS 4200000000 is a
    // perfectly ordinary private ASN and would overflow silently).
    t.bigInteger('asn').notNullable();

    t.string('as_org', 128).nullable();
    // ISO-3166-1 alpha-2. Deliberately not longer: anything else is not a
    // country code and should fail at the INSERT.
    t.string('country', 2).nullable();
    // Free-form: "FR-IDF", "Nord", whatever the loaded dataset carries.
    t.string('region', 64).nullable();

    t.string('source', 16).notNullable().defaultTo('import');
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    `ALTER TABLE ip_asn_ranges ADD CONSTRAINT ip_asn_ranges_source_chk ` +
      `CHECK (source IN (${ASN_RANGE_SOURCES}))`,
  );
  // 0 is AS0 (reserved, "no origin"), 4294967295 is the top of the 32-bit
  // space. A row outside that is a parse accident in an import file.
  await knex.schema.raw(
    'ALTER TABLE ip_asn_ranges ADD CONSTRAINT ip_asn_ranges_asn_chk ' +
      'CHECK (asn > 0 AND asn <= 4294967295)',
  );
  // One row per prefix. An import that carries the same prefix twice with two
  // different origins is a conflict to resolve at load time (last writer wins,
  // explicitly, through ON CONFLICT), not two rows that make longest-prefix
  // match non-deterministic.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX ip_asn_ranges_prefix_uniq ON ip_asn_ranges (prefix)',
  );
  // THE lookup index: `WHERE prefix >>= $ip ORDER BY masklen(prefix) DESC`.
  // GiST with inet_ops is the only opclass that makes `>>=` index-backed; a
  // btree on `prefix` cannot answer containment and the planner would scan the
  // whole table once per device.
  await knex.schema.raw(
    'CREATE INDEX ip_asn_ranges_prefix_gist ON ip_asn_ranges USING gist (prefix inet_ops)',
  );

  // The import journal. Small, and it is what answers "how old is this
  // attribution?" during an argument with a carrier.
  await knex.schema.createTable('weather_asn_imports', (t) => {
    t.bigIncrements('id').primary();
    t.string('source', 16).notNullable().defaultTo('import');
    // A label, a file name, a dataset version — whatever the operator typed.
    // NEVER a URL with credentials in it: this is displayed in the UI.
    t.string('label', 255).notNullable();
    t.integer('rows_loaded').notNullable().defaultTo(0);
    t.integer('rows_rejected').notNullable().defaultTo(0);
    t.integer('imported_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('imported_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  await knex.schema.raw(
    `ALTER TABLE weather_asn_imports ADD CONSTRAINT weather_asn_imports_source_chk ` +
      `CHECK (source IN (${ASN_RANGE_SOURCES}))`,
  );

  // ==========================================================================
  // 2. device_wan_path — the active egress path, one row per device.
  // ==========================================================================

  await knex.schema.createTable('device_wan_path', (t) => {
    // PK on device_id: this is CURRENT state, not history. The history is
    // `wan_path_events`, which is append-only and is what a correlation reads.
    // No single-column FK here: the composite (device_id, tenant_id) one added
    // below is strictly stronger and a second one would only duplicate the
    // trigger cost on every device delete.
    t.integer('device_id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.string('path_kind', 16).notNullable().defaultTo('unknown');
    // ifName of the interface the active default route leaves by.
    t.string('egress_interface', 64).nullable();
    t.specificType('default_route_gateway', 'inet').nullable();
    t.integer('default_route_distance').nullable();

    // What the capability matrix found: is there a cellular interface at all,
    // and is it registered on a network. `lte_registered` is nullable because
    // "there is no LTE interface" and "there is one and it is not registered"
    // are different facts and only the second is a problem.
    t.boolean('lte_present').notNullable().defaultTo(false);
    t.boolean('lte_registered').nullable();

    // Decision 5. `observed_*` is the concentrator's; `reported_*` is the
    // router's own claim; `effective_public_ip` is generated below and is the
    // only one anything reads.
    t.specificType('observed_public_ip', 'inet').nullable();
    t.specificType('reported_public_ip', 'inet').nullable();

    t.bigInteger('asn').nullable();
    t.string('as_org', 128).nullable();
    t.string('country', 2).nullable();
    t.string('region', 64).nullable();
    // `public` | `private` | `cgnat` | ... — 10 is the longest ('linklocal').
    t.string('ip_scope', 16).notNullable().defaultTo('invalid');

    t.string('source', 24).notNullable().defaultTo('ppp_caller_id');
    // Which capability matrix answered, e.g. `mikrotik_routeros7`. Stored so a
    // wrong path can be blamed on the right firmware (R11).
    t.string('matrix_family', 48).nullable();
    // Honest gaps: "no /interface/lte on this firmware", "SNMP has never
    // discovered an interface here". Displayed, never swallowed.
    t.text('note').nullable();

    t.timestamp('observed_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    'ALTER TABLE device_wan_path ADD CONSTRAINT device_wan_path_device_tenant_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE device_wan_path ADD CONSTRAINT device_wan_path_kind_chk ` +
      `CHECK (path_kind IN (${WAN_PATH_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE device_wan_path ADD CONSTRAINT device_wan_path_source_chk ` +
      `CHECK (source IN (${WEATHER_SOURCES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE device_wan_path ADD CONSTRAINT device_wan_path_scope_chk ` +
      `CHECK (ip_scope IN (${IP_SCOPES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE device_wan_path ADD CONSTRAINT device_wan_path_asn_chk ' +
      'CHECK (asn IS NULL OR (asn > 0 AND asn <= 4294967295))',
  );
  // An unattributable address cannot carry a carrier: the pair (scope, asn) has
  // to agree, or a private caller-id could be filed under an operator and open
  // an incident nobody can explain. The service refuses it too — this is the
  // wall behind that one.
  await knex.schema.raw(
    "ALTER TABLE device_wan_path ADD CONSTRAINT device_wan_path_scope_asn_chk " +
      "CHECK (asn IS NULL OR ip_scope = 'public')",
  );
  // DECISION 5, COMPILED. There is no statement that can make the router's
  // self-report win over the concentrator's observation.
  await knex.schema.raw(
    'ALTER TABLE device_wan_path ADD COLUMN effective_public_ip inet ' +
      'GENERATED ALWAYS AS (COALESCE(observed_public_ip, reported_public_ip)) STORED',
  );

  // Reads are always "this tenant's devices, filtered by path or by carrier".
  // tenant_id leads both indexes; neither is usable to walk another customer.
  await knex.schema.raw(
    'CREATE INDEX device_wan_path_tenant_kind_idx ON device_wan_path (tenant_id, path_kind)',
  );
  // PARTIAL: `asn` is nullable and the null rows are precisely the ones no
  // correlation may ever look at. NULLS DISTINCT would put them in the index
  // for nothing.
  await knex.schema.raw(
    'CREATE INDEX device_wan_path_tenant_asn_idx ON device_wan_path (tenant_id, asn) ' +
      'WHERE asn IS NOT NULL',
  );

  // ==========================================================================
  // 3. wan_path_events — append-only history of egress transitions.
  // ==========================================================================

  await knex.schema.createTable('wan_path_events', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable();
    // Nullable + SET NULL, same shape as `devices.site_id`: deleting a site
    // must not erase the evidence that its router failed over.
    t.integer('site_id').nullable()
      .references('id').inTable('sites').onDelete('SET NULL');

    // The PPP session this transition was derived from. CASCADE: if the
    // session history is pruned, the derived event goes with it — it is a
    // projection of that row and would otherwise outlive its own evidence.
    t.bigInteger('session_id').nullable()
      .references('id').inTable('ppp_sessions').onDelete('CASCADE');

    t.timestamp('at', { useTz: true }).notNullable();
    t.string('direction', 16).notNullable();

    t.specificType('from_ip', 'inet').nullable();
    t.specificType('to_ip', 'inet').nullable();
    // DECISION: `from_asn` is the correlation key. The operator that broke is
    // the one whose address the site STOPPED using — a site failing over to LTE
    // arrives on a mobile ASN, and keying on arrival would name the wrong
    // carrier every single time.
    t.bigInteger('from_asn').nullable();
    t.bigInteger('to_asn').nullable();
    t.string('from_as_org', 128).nullable();
    t.string('to_as_org', 128).nullable();
    t.string('from_path_kind', 16).notNullable().defaultTo('unknown');
    t.string('to_path_kind', 16).notNullable().defaultTo('unknown');

    t.string('source', 24).notNullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    'ALTER TABLE wan_path_events ADD CONSTRAINT wan_path_events_device_tenant_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE wan_path_events ADD CONSTRAINT wan_path_events_direction_chk ` +
      `CHECK (direction IN (${WAN_EVENT_DIRECTIONS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE wan_path_events ADD CONSTRAINT wan_path_events_source_chk ` +
      `CHECK (source IN (${WEATHER_SOURCES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE wan_path_events ADD CONSTRAINT wan_path_events_from_kind_chk ` +
      `CHECK (from_path_kind IN (${WAN_PATH_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE wan_path_events ADD CONSTRAINT wan_path_events_to_kind_chk ` +
      `CHECK (to_path_kind IN (${WAN_PATH_KINDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE wan_path_events ADD CONSTRAINT wan_path_events_asn_chk ' +
      'CHECK ((from_asn IS NULL OR (from_asn > 0 AND from_asn <= 4294967295)) ' +
      'AND (to_asn IS NULL OR (to_asn > 0 AND to_asn <= 4294967295)))',
  );

  // DECISION 6: idempotent ingestion. PARTIAL because `session_id` is nullable
  // and NULLS DISTINCT constrains nothing — without the predicate this index
  // would permit the exact duplicate it exists to forbid.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX wan_path_events_session_uniq ON wan_path_events ' +
      '(tenant_id, device_id, session_id) WHERE session_id IS NOT NULL',
  );
  // DECISION 7: the correlation's only hot read. tenant_id leads it; the
  // predicate keeps the unattributable rows out entirely.
  await knex.schema.raw(
    'CREATE INDEX wan_path_events_tenant_asn_at_idx ON wan_path_events ' +
      '(tenant_id, from_asn, at DESC) WHERE from_asn IS NOT NULL',
  );
  // "What happened on this device / this tenant lately" — the two screens.
  await knex.schema.raw(
    'CREATE INDEX wan_path_events_tenant_at_idx ON wan_path_events (tenant_id, at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX wan_path_events_device_at_idx ON wan_path_events (device_id, at DESC)',
  );

  // ==========================================================================
  // 4. operator_incidents — the aggregation, and the whole feature.
  // ==========================================================================

  await knex.schema.createTable('operator_incidents', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.bigInteger('asn').notNullable();
    t.string('as_org', 128).nullable();

    t.string('status', 16).notNullable().defaultTo('open');
    t.timestamp('opened_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    // Set when recovery is first observed. The hold-down is measured from here,
    // and it is reset to NULL by a relapse — an incident that comes back has
    // not been recovering for the last twenty minutes.
    t.timestamp('clearing_since', { useTz: true }).nullable();
    t.timestamp('closed_at', { useTz: true }).nullable();

    // Sites still off this ASN right now.
    t.integer('current_site_count').notNullable().defaultTo(0);
    // The worst it ever got. Kept because it is the number the post-mortem
    // wants and `current_site_count` will be 0 by the time anybody reads it.
    t.integer('peak_site_count').notNullable().defaultTo(0);
    // The denominator at open time: "14 of your 19 sites on this carrier".
    t.integer('fleet_site_count').notNullable().defaultTo(0);

    // The exact tuning that produced this verdict, frozen. An incident argued
    // about three weeks later must be re-checkable against the quorum that was
    // in force, not the one somebody has since edited.
    t.jsonb('policy').notNullable();
    t.string('open_reason', 160).nullable();
    t.string('close_reason', 160).nullable();

    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    `ALTER TABLE operator_incidents ADD CONSTRAINT operator_incidents_status_chk ` +
      `CHECK (status IN (${INCIDENT_STATUSES}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE operator_incidents ADD CONSTRAINT operator_incidents_asn_chk ' +
      'CHECK (asn > 0 AND asn <= 4294967295)',
  );
  // The three states and their timestamps agree, or the row does not exist.
  // A `closed` incident with no `closed_at` is a row that breaks every
  // duration report downstream and nothing would ever have noticed.
  await knex.schema.raw(
    "ALTER TABLE operator_incidents ADD CONSTRAINT operator_incidents_lifecycle_chk " +
      "CHECK ((status = 'closed') = (closed_at IS NOT NULL) " +
      "AND (status <> 'clearing' OR clearing_since IS NOT NULL) " +
      "AND (status <> 'open' OR clearing_since IS NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE operator_incidents ADD CONSTRAINT operator_incidents_peak_chk ' +
      'CHECK (peak_site_count >= current_site_count AND current_site_count >= 0)',
  );

  // DECISION 1 — THE SAFETY CATCH. One live incident per (tenant, ASN).
  await knex.schema.raw(
    "CREATE UNIQUE INDEX operator_incidents_live_uniq ON operator_incidents " +
      "(tenant_id, asn) WHERE status <> 'closed'",
  );
  await knex.schema.raw(
    'CREATE INDEX operator_incidents_tenant_status_idx ON operator_incidents ' +
      '(tenant_id, status, opened_at DESC)',
  );
  // Composite target for the members' foreign key (decision 2).
  await knex.schema.raw(
    'ALTER TABLE operator_incidents ADD CONSTRAINT operator_incidents_id_tenant_uq ' +
      'UNIQUE (id, tenant_id)',
  );

  // ==========================================================================
  // 5. operator_incident_members — who is in it, and when they came back.
  // ==========================================================================

  await knex.schema.createTable('operator_incident_members', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.bigInteger('incident_id').notNullable();
    t.integer('device_id').notNullable();
    t.integer('site_id').nullable()
      .references('id').inTable('sites').onDelete('SET NULL');

    // The `away` event that (re)joined this device to the incident — the
    // evidence link. It ADVANCES on a relapse: a member that recovered and then
    // left the carrier again is re-joined by a NEWER event, and comparing this
    // column with the incoming one is how the correlator tells "the same
    // evidence seen twice" from "it has just happened again". Getting that
    // wrong in either direction is a bug with teeth: never un-retiring closes
    // an incident that is still running, always un-retiring never closes one.
    t.bigInteger('event_id').nullable()
      .references('id').inTable('wan_path_events').onDelete('SET NULL');

    t.timestamp('joined_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    // NULL = still off the carrier. This column IS the clearing arithmetic:
    // `current_site_count` is a COUNT(DISTINCT site key) over the rows where it
    // is null.
    t.timestamp('recovered_at', { useTz: true }).nullable();

    t.string('from_path_kind', 16).notNullable().defaultTo('unknown');
    t.string('to_path_kind', 16).notNullable().defaultTo('unknown');
  });

  await knex.schema.raw(
    'ALTER TABLE operator_incident_members ADD CONSTRAINT oim_incident_tenant_fk ' +
      'FOREIGN KEY (incident_id, tenant_id) REFERENCES operator_incidents (id, tenant_id) ' +
      'ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE operator_incident_members ADD CONSTRAINT oim_device_tenant_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE operator_incident_members ADD CONSTRAINT oim_from_kind_chk ` +
      `CHECK (from_path_kind IN (${WAN_PATH_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE operator_incident_members ADD CONSTRAINT oim_to_kind_chk ` +
      `CHECK (to_path_kind IN (${WAN_PATH_KINDS}))`,
  );
  // A device joins an incident once. Re-detecting the same failover on the
  // next sweep must refresh the row, not add a second vote to the count that
  // decides whether the incident is still live.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX oim_incident_device_uniq ON operator_incident_members ' +
      '(tenant_id, incident_id, device_id)',
  );
  // "Who is still down in this incident" — the clearing read, every sweep.
  await knex.schema.raw(
    'CREATE INDEX oim_incident_live_idx ON operator_incident_members ' +
      '(tenant_id, incident_id) WHERE recovered_at IS NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX oim_device_idx ON operator_incident_members (device_id, joined_at DESC)',
  );

  // ==========================================================================
  // 6. weather_settings — the per-tenant policy (decision 8).
  // ==========================================================================

  await knex.schema.createTable('weather_settings', (t) => {
    t.integer('tenant_id').primary()
      .references('id').inTable('tenants').onDelete('CASCADE');

    // Columns rather than a jsonb blob: every one of these is a number a human
    // tunes and a CHECK has to see. A jsonb policy is a policy nobody can
    // constrain — and the constraint below is the asymmetry itself.
    t.integer('window_minutes').notNullable().defaultTo(10);
    t.integer('min_sites').notNullable().defaultTo(5);
    t.decimal('min_fraction', 4, 3).notNullable().defaultTo(0.25);
    t.decimal('clear_ratio', 4, 3).notNullable().defaultTo(0.5);
    t.integer('hold_down_minutes').notNullable().defaultTo(30);
    t.integer('fleet_wide_asn_count').notNullable().defaultTo(4);
    t.decimal('fleet_wide_fraction', 4, 3).notNullable().defaultTo(0.3);

    // Master switch. A tenant that does not want carrier correlation should be
    // able to say so without the ingestion stopping — the events keep being
    // recorded, only the incident opening is suppressed.
    t.boolean('enabled').notNullable().defaultTo(true);

    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    'ALTER TABLE weather_settings ADD CONSTRAINT weather_settings_bounds_chk ' +
      'CHECK (window_minutes BETWEEN 1 AND 240 ' +
      'AND min_sites BETWEEN 2 AND 1000 ' +
      'AND min_fraction BETWEEN 0 AND 1 ' +
      'AND clear_ratio BETWEEN 0 AND 1 ' +
      'AND hold_down_minutes BETWEEN 1 AND 1440 ' +
      'AND fleet_wide_asn_count BETWEEN 2 AND 100 ' +
      'AND fleet_wide_fraction BETWEEN 0 AND 1)',
  );
  // DECISION 8. The asymmetry, in the database.
  await knex.schema.raw(
    'ALTER TABLE weather_settings ADD CONSTRAINT weather_settings_hold_down_chk ' +
      `CHECK (hold_down_minutes >= ${MIN_HOLD_DOWN_RATIO} * window_minutes)`,
  );

  // ==========================================================================
  // 7. Comments — the ones a reader in psql needs, not a duplicate of the file.
  // ==========================================================================

  await knex.schema.raw(
    "COMMENT ON INDEX operator_incidents_live_uniq IS $$THE feature's safety catch: " +
      "at most one live incident per (tenant, ASN). Twelve sites failing over produce " +
      "ONE alert, and Postgres is what guarantees it — not the correlator remembering " +
      "to check. Partial on status <> 'closed' so history can repeat.$$",
  );
  await knex.schema.raw(
    "COMMENT ON COLUMN wan_path_events.from_asn IS $$THE correlation key. The operator " +
      "that broke is the one whose address the site STOPPED using; a site failing over " +
      "to LTE arrives on a mobile ASN, so keying on to_asn names the wrong carrier " +
      "every time.$$",
  );
  await knex.schema.raw(
    "COMMENT ON COLUMN device_wan_path.effective_public_ip IS $$GENERATED: " +
      "COALESCE(observed_public_ip, reported_public_ip). The concentrator's observation " +
      "of the caller-id survives NAT and cannot be forged by the router; a self-report " +
      "is a fallback and can never overwrite it. Not writable, by construction.$$",
  );
  await knex.schema.raw(
    "COMMENT ON TABLE ip_asn_ranges IS $$Public routing data, no tenant column on " +
      "purpose: it contains no customer datum and per-tenant copies of the BGP table " +
      "would be 900k rows each. Offline by design — one HTTP call per device per " +
      "failover is a self-inflicted outage during the minutes the network is broken.$$",
  );
  await knex.schema.raw(
    "COMMENT ON CONSTRAINT weather_settings_hold_down_chk ON weather_settings IS " +
      "$$An incident must always take longer to end than it took to start. A carrier " +
      "outage that heals in bursts would otherwise flap the alert, and six notifications " +
      "about one outage cost the same credibility as a false positive.$$",
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('weather_settings');
  await knex.schema.dropTableIfExists('operator_incident_members');
  await knex.schema.dropTableIfExists('operator_incidents');
  await knex.schema.dropTableIfExists('wan_path_events');
  await knex.schema.dropTableIfExists('device_wan_path');
  await knex.schema.dropTableIfExists('weather_asn_imports');
  await knex.schema.dropTableIfExists('ip_asn_ranges');
  // `devices_id_tenant_uq` is NOT dropped here: migration 017 created it first
  // and its own tables still depend on it. Removing a shared uniqueness
  // guarantee on the way out of an unrelated feature is not a rollback.
}
