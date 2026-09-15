import type { Knex } from 'knex';

/**
 * 032_sim.ts — F9, the mobile data line (SIM) fleet.
 *
 * The TypeScript contract these tables carry lives in `shared/src/sim.ts`. The
 * vocabularies below are the SAME lists, written once more as CHECKs, because a
 * service-layer union type is not what runs when somebody updates a recharge
 * row from psql at the end of a billing month (§11.1, motif 7).
 *
 * ┌─ WHAT THIS SCHEMA IS FOR, IN ONE SENTENCE ────────────────────────────────┐
 * │ To know how much data is left on every SIM that keeps a customer site     │
 * │ online, to say so BEFORE the site goes dark, and to be able to hand       │
 * │ accounting a list of exactly which sites were topped up, when, and for    │
 * │ how much.                                                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NINE DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ───────────────────┐
 * │                                                                          │
 * │ 1. DATA QUANTITIES ARE `integer` MEGABYTES, AND THEY ARE NULLABLE.        │
 * │    Not numeric, not float, not "Go". Two reasons, and the second is the   │
 * │    one that matters: an integer comparison against a threshold stored in  │
 * │    the same unit is exact, and `NULL` is a value the schema can hold for  │
 * │    "the partner did not tell us". The prototype this feature comes from   │
 * │    coerced a missing reading to 0, and 0 is the reading that triggers a   │
 * │    purchase. Every `_mb` column here is nullable except                   │
 * │    `threshold_mb_at_proposal`, which is evidence and always known.        │
 * │                                                                          │
 * │ 2. `sim_accounts` HAS NO `tenant_id`, AND THEREFORE WRITING IT IS A       │
 * │    PLATFORM ACT. The contract with Phenix or CFAST belongs to whoever     │
 * │    runs ObliWAN, not to a customer, exactly like `ip_asn_ranges` (021,    │
 * │    decision 3) and `lifecycle_models` (027, decision 2). The consequence  │
 * │    is the important half: a row here holds a CREDENTIAL and changes what  │
 * │    every tenant is shown, so the write cannot sit behind a tenant-scoped  │
 * │    capability. F5 shipped that bug on `ip_asn_ranges` — SETTINGS_MANAGE   │
 * │    is granted to the admin of ANY tenant through                          │
 * │    `TENANT_ROLE_CAPABILITIES` — so `sim.routes.ts` guards every account   │
 * │    route with `requireRole('admin')`, the PLATFORM role from              │
 * │    `users.role`.                                                          │
 * │                                                                          │
 * │ 3. A LINE'S `tenant_id` IS NULLABLE, AND NULL MEANS "POOL".               │
 * │    Lines arrive from the partner before anybody has decided which         │
 * │    customer they belong to. That state is real and is stored as itself,   │
 * │    never guessed from a name and never hidden. Every tenant-scoped read   │
 * │    filters on it, so a pooled line is invisible to customers and visible  │
 * │    to the platform, which is the correct asymmetry.                       │
 * │                                                                          │
 * │ 4. `site_id` AND `device_id` ARE COMPOSITE FOREIGN KEYS THAT CARRY        │
 * │    `tenant_id`. `(device_id, tenant_id) -> devices (id, tenant_id)`       │
 * │    makes "customer A's line points at customer B's router" unrepresentable │
 * │    for any ASSIGNED line, which is the case that leaks. Both use the      │
 * │    Postgres 15+ form `ON DELETE SET NULL (device_id)` — the column list   │
 * │    matters: the plain form would null `tenant_id` too, so deleting a      │
 * │    router would silently return its customer's SIM to the pool.           │
 * │                                                                          │
 * │    THE RESIDUAL HOLE, STATED RATHER THAN HIDDEN: with `tenant_id` NULL,   │
 * │    MATCH SIMPLE does not check the pair at all, so the schema alone would │
 * │    admit a POOLED line pointing at any tenant's device. It cannot be      │
 * │    closed with `CHECK (device_id IS NULL OR tenant_id IS NOT NULL)`,      │
 * │    because CHECK constraints are not deferrable in Postgres and deleting  │
 * │    a tenant fires the two cascades in an unspecified order — the tenant   │
 * │    deletion would then fail, at random, with a check violation. It is     │
 * │    closed in `account.service.assertAssignable`, which refuses a device   │
 * │    or site on a line with no tenant, and MATCH FULL is not usable here    │
 * │    because an assigned line legitimately has no device.                   │
 * │                                                                          │
 * │ 5. THE CURRENT BALANCE AND ITS HISTORY ARE TWO TABLES.                    │
 * │    `sim_balances` is one row per (line, zone), upserted every sweep — the │
 * │    dashboard reads it with no aggregation. `sim_balance_samples` is       │
 * │    append-only and written ONLY when a reading actually changed, the same │
 * │    deduplication idea as config snapshots by `ncm_hash`. A row per line   │
 * │    per zone per sweep would be ~1.3 M rows a year on 300 lines and would  │
 * │    carry no information on the days nothing moved.                        │
 * │                                                                          │
 * │ 6. `sim_balances.low_since` IS THE EPISODE MARKER, AND IT IS WHY NOTHING  │
 * │    PROPOSES TWICE. It is set the first sweep a zone is below its          │
 * │    threshold and cleared the moment it climbs back. `sim_recharges`       │
 * │    carries a UNIQUE `idempotency_key` built from it                       │
 * │    (`shared/src/sim.ts::rechargeIdempotencyKey`), so a second proposal    │
 * │    for the same low episode is refused BY THE DATABASE and not by a       │
 * │    remembering service. On a four-hourly sweep the alternative is six     │
 * │    proposals a day for one line — and six purchases the day an execution  │
 * │    adapter exists.                                                        │
 * │                                                                          │
 * │ 7. A RECHARGE ROW IS DENORMALISED ON PURPOSE AND OUTLIVES ITS LINE.       │
 * │    `sim_id` is `ON DELETE SET NULL`, and `msisdn`, `site_name`,           │
 * │    `tenant_name` and `operator` are copied into the row at proposal time. │
 * │    The reasoning is `notification_log.channel_name`'s: deleting a line    │
 * │    must not erase the invoice lines that explain a bill, and a report     │
 * │    that groups on a live join would also rewrite last quarter's site      │
 * │    names when somebody renames a site.                                    │
 * │                                                                          │
 * │ 8. MONEY CANNOT BE STORED AMBIGUOUSLY. `cost_cents` is an integer, and a  │
 * │    CHECK refuses a cost with no `currency`. "120" with no unit on a       │
 * │    re-invoicing report is a number somebody will read as euros and        │
 * │    invoice as euros. A billable row with NO cost is allowed — that is the │
 * │    normal state right after a top-up is recorded — and the report COUNTS  │
 * │    those separately instead of adding them as zero.                       │
 * │                                                                          │
 * │ 9. THE CAPS EXIST NOW, BEFORE ANYTHING CAN SPEND.                         │
 * │    `monthly_recharge_cap` and `monthly_cost_cap_cents` are on the account │
 * │    from the first migration even though no execution adapter exists. A    │
 * │    ceiling added after the automation is a ceiling that was absent on the │
 * │    day it was first needed.                                               │
 * │                                                                          │
 * │    WHAT THEY GATE, PRECISELY: machine EXECUTION, and only that.           │
 * │    `assertExecutionAllowed` refuses an adapter call when a cap is unset   │
 * │    or would be exceeded — NULL is REFUSE, not unlimited, so the day an    │
 * │    adapter lands it cannot buy anything until somebody has written down   │
 * │    a ceiling. They do NOT gate a proposal (which costs nothing and is the │
 * │    thing that warns a human) and they do NOT gate RECORDING a top-up      │
 * │    bought by hand: that already happened, and refusing to write down a    │
 * │    fact because it breached a ceiling is how a billing report goes wrong. │
 * │    The proposal screen SHOWS the month's usage against the caps instead.  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2): exactly one column in this migration holds vault material —
 * `sim_accounts.credential_blob`, AES-256-GCM under `OBLIWAN_ENCRYPTION_KEY`
 * with its `key_version`, written and read only by `secretVault.service`. No
 * API on this feature returns it, the export bundle does not carry it, and
 * `sim_sync_runs.error` is scrubbed by the connector before it is stored — a
 * partner's 401 body has been known to echo the submitted username.
 *
 * D3: nothing in this feature writes to an equipment. It talks to a partner's
 * web API and to our own Postgres, and it never opens a session on a router.
 */

// ── Vocabularies. Same lists as shared/src/sim.ts. ───────────────────────────
const PLATFORMS = "'phenix','cfast'";                                        // 1
const AUTH_MODES = "'password','token'";                                     // 2
const ACCOUNT_STATUSES = "'active','disabled','auth_failed'";                // 3
const LINE_STATUSES = "'active','suspended','unknown'";                      // 4
const RECHARGE_STATUSES =
  "'proposed','approved','executed','recorded','rejected','failed','expired'"; // 5
const RECHARGE_TRIGGERS = "'threshold','manual'";                            // 6
const SYNC_OUTCOMES = "'ok','partial','auth_failed','error'";                // 7

// ── Column widths, set from the lists above and rounded up. ──────────────────
// platform        varchar(16) >= 6   'phenix'
// auth_mode       varchar(16) >= 8   'password'
// account status  varchar(16) >= 11  'auth_failed'
// line status     varchar(16) >= 9   'suspended'
// recharge status varchar(16) >= 8   'proposed'
// trigger         varchar(16) >= 9   'threshold'
// sync outcome    varchar(16) >= 11  'auth_failed'
// Every one is at least the longest legal value plus room. The failure guarded
// against — a CHECK that admits a string the column cannot hold — surfaces only
// as "value too long for type character varying" on the INSERT, which during a
// sweep means the account stops being polled for a reason nobody can read.

export async function up(knex: Knex): Promise<void> {
  // `sites_id_tenant_uq` is the target of the composite FK in decision 4.
  // Created idempotently here, the same shape migrations 017/021/025 use for
  // `devices_id_tenant_uq`, because no earlier migration needed it.
  await knex.schema.raw(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'sites_id_tenant_uq'
      ) THEN
        ALTER TABLE sites ADD CONSTRAINT sites_id_tenant_uq UNIQUE (id, tenant_id);
      END IF;
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'devices_id_tenant_uq'
      ) THEN
        ALTER TABLE devices ADD CONSTRAINT devices_id_tenant_uq UNIQUE (id, tenant_id);
      END IF;
    END $$;
  `);

  // ==========================================================================
  // 1. sim_accounts — one partner contract. Platform-scoped (decision 2).
  // ==========================================================================

  await knex.schema.createTable('sim_accounts', (t) => {
    t.increments('id').primary();

    // No tenant_id. Decision 2 — and see the guard consequence there.
    t.string('platform', 16).notNullable();
    t.string('name', 120).notNullable();

    // Null = use the connector's built-in default. Stored so an operator can
    // point a test account at a staging host without a redeploy.
    t.string('base_url', 255).nullable();

    // Phenix `partenaireId`. Text rather than integer: it is an opaque partner
    // reference that appears in a URL query, and a future partner's is not
    // guaranteed to be numeric. Decoded from the JWT when the token carries it.
    t.string('partner_ref', 64).nullable();

    t.string('auth_mode', 16).notNullable();

    // THE ONLY VAULT COLUMN IN THIS MIGRATION (§8.2). AES-256-GCM blob holding
    // {username,password} or {token}; `key_version` travels inside the blob the
    // same way every other secret in this product does (arbitrage A3).
    t.text('credential_blob').nullable();

    // Read out of the JWT `exp` when there is one. The point of storing it is
    // to warn BEFORE it dies: a token that expires unnoticed turns into a fleet
    // that silently stopped being watched, which is the one failure this
    // feature cannot afford — the balances go stale exactly like they would if
    // nothing were wrong.
    t.timestamp('token_expires_at', { useTz: true }).nullable();

    t.string('status', 16).notNullable().defaultTo('active');

    // Operator names whose lines this account must not poll. Phenix SFR lines
    // use a different consumption path and answer nothing useful on the normal
    // one; the field prototype skipped them by name and so does this. jsonb
    // rather than a child table: it is a short list of strings edited as a unit.
    t.jsonb('skip_operators').notNullable().defaultTo(JSON.stringify([]));

    // Decision 9. Null is REFUSE in `assertRechargeAllowed`, never unlimited.
    t.integer('monthly_recharge_cap').nullable();
    t.bigInteger('monthly_cost_cap_cents').nullable();

    t.timestamp('last_sync_at', { useTz: true }).nullable();
    // Scrubbed by the connector before it lands here (§8.2).
    t.text('last_sync_error').nullable();
    t.integer('last_sync_line_count').nullable();

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE sim_accounts ADD CONSTRAINT sim_accounts_platform_chk ` +
      `CHECK (platform IN (${PLATFORMS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_accounts ADD CONSTRAINT sim_accounts_auth_mode_chk ` +
      `CHECK (auth_mode IN (${AUTH_MODES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_accounts ADD CONSTRAINT sim_accounts_status_chk ` +
      `CHECK (status IN (${ACCOUNT_STATUSES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_accounts ADD CONSTRAINT sim_accounts_name_chk ` +
      `CHECK (btrim(name) <> '')`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_accounts ADD CONSTRAINT sim_accounts_caps_chk ` +
      `CHECK (monthly_recharge_cap IS NULL OR monthly_recharge_cap >= 0)`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_accounts ADD CONSTRAINT sim_accounts_cost_cap_chk ` +
      `CHECK (monthly_cost_cap_cents IS NULL OR monthly_cost_cap_cents >= 0)`,
  );
  // A list, not an object. A malformed value here would be iterated as a string
  // and skip every operator whose name is a single character.
  await knex.schema.raw(
    `ALTER TABLE sim_accounts ADD CONSTRAINT sim_accounts_skip_ops_chk ` +
      `CHECK (jsonb_typeof(skip_operators) = 'array')`,
  );
  // One account per partner per name. Two rows with the same name on the same
  // platform are two operators each believing they configured "the" account.
  await knex.schema.raw(
    `CREATE UNIQUE INDEX sim_accounts_platform_name_uq ` +
      `ON sim_accounts (platform, lower(btrim(name)))`,
  );

  // ==========================================================================
  // 2. sim_lines — the inventory. One row per MSISDN per account.
  // ==========================================================================

  await knex.schema.createTable('sim_lines', (t) => {
    t.increments('id').primary();

    t.integer('account_id')
      .notNullable()
      .references('id')
      .inTable('sim_accounts')
      .onDelete('CASCADE');

    // Decision 3: NULL = pool. Not "tenant 1", not "the master tenant".
    t.integer('tenant_id').nullable().references('id').inTable('tenants').onDelete('SET NULL');

    t.string('msisdn', 24).notNullable();

    // Decision: NULLABLE, and empty on Phenix today — the partner API returns
    // msisdn / operateur / codeClient and no SIM serial at all. This is the
    // seam for correlating a line with the router that holds it once the fleet
    // is enrolled in the ACS. Two lines with no ICCID must never be considered
    // "the same unknown", which is why the uniqueness below is PARTIAL.
    t.string('iccid', 22).nullable();

    // Nullable because absent is not the same as "". A line whose operator the
    // partner did not report is shown as unknown, and `skip_operators` cannot
    // match it — so it keeps being polled rather than being silently dropped.
    t.string('operator', 60).nullable();
    t.string('client_code', 64).nullable();
    t.string('label', 190).nullable();

    // Decision 4: composite, so an assigned line cannot point across tenants.
    t.integer('site_id').nullable();
    t.integer('device_id').nullable();

    t.string('status', 16).notNullable().defaultTo('unknown');

    // Per-line override of the global threshold, in MB (decision 1).
    t.integer('low_threshold_mb').nullable();

    // Opt-in, per line, off by default. Nothing proposes to spend money on a
    // line for which no human has said it should be topped up.
    t.boolean('auto_recharge_enabled').notNullable().defaultTo(false);
    t.integer('recharge_plan_mb').nullable();

    t.timestamp('first_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('last_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    // ┌─ WHEN THIS LINE BECAME ITS CURRENT CUSTOMER'S ────────────────────────┐
    // │ A SIM moves between customers: a contract ends, the box goes back to  │
    // │ stock, the line is re-let. The physical consumption history in        │
    // │ `sim_balance_samples` belongs to the LINE, but the part of it recorded │
    // │ before a re-assignment is the PREVIOUS customer's business — how much  │
    // │ data they used, month by month. Without this column the new owner's    │
    // │ history screen reads it in full.                                       │
    // │                                                                       │
    // │ `getLineHistory` cuts the series here. NULL means the line has never  │
    // │ been assigned (it is in the pool), and the pool is master-only.        │
    // └───────────────────────────────────────────────────────────────────────┘
    t.timestamp('tenant_assigned_at', { useTz: true }).nullable();

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_status_chk ` +
      `CHECK (status IN (${LINE_STATUSES}))`,
  );
  // The shape that ends up in a partner URL query. Refusing it here means a
  // value that could carry a query separator is unstorable rather than merely
  // unescaped at one call site (§11.1, motif 6).
  //
  // ┌─ `[+]{0,1}` AND NOT `\+?` — THIS IS NOT A STYLE CHOICE ─────────────────┐
  // │ knex's `raw()` treats `?` as a POSITIONAL BINDING PLACEHOLDER and       │
  // │ rewrites it. The first draft of this line read `'^\+?[0-9]{6,19}$'` and │
  // │ reached PostgreSQL as `'^\+$1[0-9]{6,19}$'` — a constraint that         │
  // │ compiles, installs silently, and then refuses EVERY MSISDN. The first   │
  // │ sweep against a real database inserted not one line and left a          │
  // │ constraint-violation line in the log, with an empty fleet on screen.    │
  // │ Caught by `f9-sim.verify.ts` on its first run against PostgreSQL 16;    │
  // │ no amount of typechecking would have found it.                          │
  // │                                                                        │
  // │ Any regex inside a `raw()` on this project carries the same trap. Write │
  // │ an optional character as `{0,1}`, or bind the pattern as a parameter.   │
  // └────────────────────────────────────────────────────────────────────────┘
  await knex.schema.raw(
    `ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_msisdn_chk ` +
      `CHECK (msisdn ~ '^[+]{0,1}[0-9]{6,19}$')`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_iccid_chk ` +
      `CHECK (iccid IS NULL OR iccid ~ '^[0-9]{18,22}$')`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_threshold_chk ` +
      `CHECK (low_threshold_mb IS NULL OR low_threshold_mb >= 0)`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_plan_chk ` +
      `CHECK (recharge_plan_mb IS NULL OR recharge_plan_mb > 0)`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_account_msisdn_uq ` +
      `UNIQUE (account_id, msisdn)`,
  );
  // PARTIAL, and that is the whole point: Postgres indexes are NULLS DISTINCT,
  // so a plain UNIQUE(iccid) would constrain nothing for the many rows with no
  // serial — and a non-partial index over a column that is null on most rows is
  // also an invitation to treat "both unknown" as "the same SIM" later. Same
  // construction, same reason, as `lifecycle_firmware` in 027 (decision 3).
  await knex.schema.raw(
    `CREATE UNIQUE INDEX sim_lines_iccid_uq ON sim_lines (iccid) WHERE iccid IS NOT NULL`,
  );
  // Decision 4. The `(device_id)` / `(site_id)` column list is Postgres 15+ and
  // is not decoration: the plain `ON DELETE SET NULL` nulls every column of the
  // key, so deleting a router would also clear `tenant_id` and hand the
  // customer's SIM back to the pool.
  await knex.schema.raw(
    `ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_device_tenant_fk ` +
      `FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ` +
      `ON DELETE SET NULL (device_id)`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_site_tenant_fk ` +
      `FOREIGN KEY (site_id, tenant_id) REFERENCES sites (id, tenant_id) ` +
      `ON DELETE SET NULL (site_id)`,
  );
  // tenant_id leads, so neither index is usable to walk another customer.
  await knex.schema.raw(
    `CREATE INDEX sim_lines_tenant_idx ON sim_lines (tenant_id, account_id)`,
  );
  await knex.schema.raw(`CREATE INDEX sim_lines_device_idx ON sim_lines (device_id)`);
  await knex.schema.raw(`CREATE INDEX sim_lines_site_idx ON sim_lines (site_id)`);
  // The pool screen's only query: lines nobody has claimed.
  await knex.schema.raw(
    `CREATE INDEX sim_lines_pool_idx ON sim_lines (account_id) WHERE tenant_id IS NULL`,
  );

  // ==========================================================================
  // 3. sim_balances — current state, one row per (line, zone). Decision 5.
  // ==========================================================================

  await knex.schema.createTable('sim_balances', (t) => {
    t.bigIncrements('id').primary();

    t.integer('sim_id')
      .notNullable()
      .references('id')
      .inTable('sim_lines')
      .onDelete('CASCADE');

    // Never '': an unlabelled zone is stored as 'unknown' (shared UNKNOWN_ZONE)
    // so the natural key below can never be keyed on an empty string.
    t.string('zone', 80).notNullable();

    // Decision 1: nullable integers in MB. NULL means the partner did not say.
    t.integer('recharge_mb').nullable();
    t.integer('used_mb').nullable();
    t.integer('rest_mb').nullable();

    t.timestamp('observed_at', { useTz: true }).notNullable();

    // DECISION 6 — the episode marker. Set on the first sweep this zone is at
    // or below its effective threshold, cleared the moment it climbs back, and
    // NOT touched while it stays low. `sim_recharges.idempotency_key` is built
    // from it, so its stability is what makes "one proposal per episode" true.
    t.timestamp('low_since', { useTz: true }).nullable();

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE sim_balances ADD CONSTRAINT sim_balances_zone_chk ` +
      `CHECK (btrim(zone) <> '')`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_balances ADD CONSTRAINT sim_balances_mb_chk CHECK (` +
      `(recharge_mb IS NULL OR recharge_mb >= 0) AND ` +
      `(used_mb IS NULL OR used_mb >= 0) AND ` +
      `(rest_mb IS NULL OR rest_mb >= 0))`,
  );
  // ┌─ THE NATURAL KEY IS CASE-INSENSITIVE, AND THAT IS A MONEY DECISION ────┐
  // │ Each row carries its own `low_since`, so "Europe" and "europe" would be │
  // │ TWO episodes for one real zone — two idempotency keys, two proposals    │
  // │ for a single shortage, and one day two purchases. A partner that        │
  // │ changes the casing of a label between two sweeps is not a hypothetical: │
  // │ it is one backend deployment on their side.                             │
  // │                                                                        │
  // │ `canonicalZone` (shared/src/sim.ts) trims and collapses whitespace on   │
  // │ the way in and PRESERVES case, because the label is displayed. The      │
  // │ functional index below is what makes the case-insensitive uniqueness    │
  // │ true regardless — including for anything that writes without going      │
  // │ through the sweep.                                                      │
  // └────────────────────────────────────────────────────────────────────────┘
  await knex.schema.raw(
    `CREATE UNIQUE INDEX sim_balances_sim_zone_uq ON sim_balances (sim_id, lower(zone))`,
  );
  // The dashboard's query: every low zone, worst first.
  await knex.schema.raw(
    `CREATE INDEX sim_balances_low_idx ON sim_balances (low_since) WHERE low_since IS NOT NULL`,
  );

  // ==========================================================================
  // 4. sim_balance_samples — append-only history, written only on change.
  // ==========================================================================

  await knex.schema.createTable('sim_balance_samples', (t) => {
    t.bigIncrements('id').primary();

    t.integer('sim_id')
      .notNullable()
      .references('id')
      .inTable('sim_lines')
      .onDelete('CASCADE');

    t.string('zone', 80).notNullable();
    t.integer('recharge_mb').nullable();
    t.integer('used_mb').nullable();
    t.integer('rest_mb').nullable();
    t.timestamp('observed_at', { useTz: true }).notNullable();
  });

  await knex.schema.raw(
    `ALTER TABLE sim_balance_samples ADD CONSTRAINT sim_balance_samples_mb_chk CHECK (` +
      `(recharge_mb IS NULL OR recharge_mb >= 0) AND ` +
      `(used_mb IS NULL OR used_mb >= 0) AND ` +
      `(rest_mb IS NULL OR rest_mb >= 0))`,
  );
  // Two sweeps cannot record the same instant for the same zone. Without this,
  // a retried sweep doubles a line's history and any future consumption-rate
  // calculation reads a flat segment as a stall.
  await knex.schema.raw(
    `ALTER TABLE sim_balance_samples ADD CONSTRAINT sim_balance_samples_uq ` +
      `UNIQUE (sim_id, zone, observed_at)`,
  );
  await knex.schema.raw(
    `CREATE INDEX sim_balance_samples_series_idx ` +
      `ON sim_balance_samples (sim_id, zone, observed_at DESC)`,
  );

  // ==========================================================================
  // 5. sim_recharges — the money path. Decisions 6, 7, 8.
  // ==========================================================================

  await knex.schema.createTable('sim_recharges', (t) => {
    t.bigIncrements('id').primary();

    // DECISION 7: the row outlives the line. SET NULL, never CASCADE.
    t.integer('sim_id').nullable().references('id').inTable('sim_lines').onDelete('SET NULL');
    t.integer('account_id')
      .nullable()
      .references('id')
      .inTable('sim_accounts')
      .onDelete('SET NULL');

    // Denormalised identity, frozen at proposal time (decision 7). A site
    // rename must not rewrite last quarter's invoice lines, and a deleted line
    // must not erase the charge it produced.
    t.string('platform', 16).notNullable();
    t.integer('tenant_id').nullable().references('id').inTable('tenants').onDelete('SET NULL');
    t.string('tenant_name', 190).nullable();
    t.string('msisdn', 24).notNullable();
    t.string('operator', 60).nullable();
    t.integer('site_id').nullable();
    t.string('site_name', 190).nullable();
    t.string('device_name', 190).nullable();

    t.string('status', 16).notNullable().defaultTo('proposed');
    t.string('trigger', 16).notNullable();
    t.string('zone', 80).notNullable();

    // The evidence, frozen. `rest_mb_at_proposal` is nullable ONLY so a manual
    // proposal on a line with no reading is representable; the threshold that
    // fired is always known and is therefore NOT NULL.
    t.integer('rest_mb_at_proposal').nullable();
    t.integer('threshold_mb_at_proposal').notNullable();

    t.integer('plan_mb').nullable();

    // DECISION 8. Integer cents, and a currency or nothing.
    t.bigInteger('cost_cents').nullable();
    t.string('currency', 3).nullable();
    t.string('billing_reference', 190).nullable();

    // DECISION 6. UNIQUE, so a duplicate proposal for one low episode is
    // refused by the database rather than by a service that remembers.
    t.string('idempotency_key', 190).notNullable();

    t.timestamp('proposed_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    // NULL = proposed by the sweep. A system act is stored as "no user", never
    // attributed to whoever happened to be logged in.
    t.integer('proposed_by').nullable().references('id').inTable('users').onDelete('SET NULL');

    t.timestamp('decided_at', { useTz: true }).nullable();
    t.integer('decided_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.text('decision_note').nullable();

    t.timestamp('completed_at', { useTz: true }).nullable();
    t.integer('completed_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.text('failure_reason').nullable();

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE sim_recharges ADD CONSTRAINT sim_recharges_platform_chk ` +
      `CHECK (platform IN (${PLATFORMS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_recharges ADD CONSTRAINT sim_recharges_status_chk ` +
      `CHECK (status IN (${RECHARGE_STATUSES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_recharges ADD CONSTRAINT sim_recharges_trigger_chk ` +
      `CHECK (trigger IN (${RECHARGE_TRIGGERS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_recharges ADD CONSTRAINT sim_recharges_threshold_chk ` +
      `CHECK (threshold_mb_at_proposal >= 0)`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_recharges ADD CONSTRAINT sim_recharges_amounts_chk CHECK (` +
      `(rest_mb_at_proposal IS NULL OR rest_mb_at_proposal >= 0) AND ` +
      `(plan_mb IS NULL OR plan_mb > 0) AND ` +
      `(cost_cents IS NULL OR cost_cents >= 0))`,
  );
  // DECISION 8: a number with no unit is a number somebody invoices in euros.
  await knex.schema.raw(
    `ALTER TABLE sim_recharges ADD CONSTRAINT sim_recharges_currency_chk CHECK (` +
      `(cost_cents IS NULL OR currency IS NOT NULL) AND ` +
      `(currency IS NULL OR currency ~ '^[A-Z]{3}$'))`,
  );
  // The state machine's two invariants that a report depends on. Anything past
  // `proposed` was decided by somebody, and a BILLABLE row (executed/recorded)
  // has a completion instant — the column the report groups by month on.
  await knex.schema.raw(
    `ALTER TABLE sim_recharges ADD CONSTRAINT sim_recharges_decided_chk CHECK (` +
      `status = 'proposed' OR decided_at IS NOT NULL)`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_recharges ADD CONSTRAINT sim_recharges_completed_chk CHECK (` +
      `(status NOT IN ('executed','recorded')) = (completed_at IS NULL))`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_recharges ADD CONSTRAINT sim_recharges_idem_uq UNIQUE (idempotency_key)`,
  );
  // The approval queue: everything still waiting, oldest first.
  await knex.schema.raw(
    `CREATE INDEX sim_recharges_pending_idx ON sim_recharges (proposed_at) ` +
      `WHERE status IN ('proposed','approved')`,
  );
  // The re-invoicing report: billable rows in a window, grouped by site.
  await knex.schema.raw(
    `CREATE INDEX sim_recharges_billing_idx ` +
      `ON sim_recharges (completed_at, tenant_id, site_id) ` +
      `WHERE status IN ('executed','recorded')`,
  );
  await knex.schema.raw(`CREATE INDEX sim_recharges_sim_idx ON sim_recharges (sim_id)`);
  await knex.schema.raw(
    `CREATE INDEX sim_recharges_tenant_idx ON sim_recharges (tenant_id, proposed_at DESC)`,
  );

  // ==========================================================================
  // 6. sim_sync_runs — why a balance is stale. The journal of every sweep.
  // ==========================================================================
  //
  // Same purpose as `lifecycle_imports` and `weather_asn_imports`: "why is this
  // line unattributed" must have an answer that is not a shrug. A dashboard
  // showing 40 unknown lines and no reason is a dashboard an operator stops
  // trusting after the second time.

  await knex.schema.createTable('sim_sync_runs', (t) => {
    t.bigIncrements('id').primary();

    t.integer('account_id')
      .notNullable()
      .references('id')
      .inTable('sim_accounts')
      .onDelete('CASCADE');

    t.timestamp('started_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('finished_at', { useTz: true }).nullable();
    t.string('outcome', 16).nullable();

    t.integer('lines_seen').notNullable().defaultTo(0);
    t.integer('lines_new').notNullable().defaultTo(0);
    t.integer('balances_updated').notNullable().defaultTo(0);
    // Lines the partner refused or answered unusably. The number that explains
    // an `unknown` count on the dashboard.
    t.integer('lines_failed').notNullable().defaultTo(0);
    t.integer('proposals_created').notNullable().defaultTo(0);

    // Scrubbed by the connector before it lands here (§8.2): a partner's 401
    // body has been observed echoing the submitted username.
    t.text('error').nullable();
  });

  await knex.schema.raw(
    `ALTER TABLE sim_sync_runs ADD CONSTRAINT sim_sync_runs_outcome_chk ` +
      `CHECK (outcome IS NULL OR outcome IN (${SYNC_OUTCOMES}))`,
  );
  // A finished run has an outcome and an outcome implies a finish. A run that
  // is "done" with no verdict is the state that makes a stale account look
  // healthy, which is exactly what this table exists to prevent.
  await knex.schema.raw(
    `ALTER TABLE sim_sync_runs ADD CONSTRAINT sim_sync_runs_finished_chk ` +
      `CHECK ((finished_at IS NULL) = (outcome IS NULL))`,
  );
  await knex.schema.raw(
    `CREATE INDEX sim_sync_runs_account_idx ON sim_sync_runs (account_id, started_at DESC)`,
  );
}

export async function down(knex: Knex): Promise<void> {
  // Children first. `sim_recharges` references `sim_lines` and `sim_accounts`
  // with SET NULL rather than CASCADE (decision 7), so it must go before them
  // anyway — dropping the parents first would fail on the constraint.
  await knex.schema.dropTableIfExists('sim_sync_runs');
  await knex.schema.dropTableIfExists('sim_recharges');
  await knex.schema.dropTableIfExists('sim_balance_samples');
  await knex.schema.dropTableIfExists('sim_balances');
  await knex.schema.dropTableIfExists('sim_lines');
  await knex.schema.dropTableIfExists('sim_accounts');

  // `sites_id_tenant_uq` is deliberately NOT dropped. It is a plain uniqueness
  // guarantee on a pair that is already unique, other migrations may have come
  // to rely on it since, and `devices_id_tenant_uq` is left alone by 021 and
  // 025 for the same reason.
}
