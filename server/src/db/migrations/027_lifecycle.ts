import type { Knex } from 'knex';

/**
 * 027_lifecycle.ts — F8, End-of-Life Inventory (ARCHITECTURE.md §10/F8).
 *
 * The TypeScript contract these tables carry lives in `shared/src/lifecycle.ts`.
 * The vocabularies below are the SAME lists, written once more as CHECKs,
 * because a service-layer enum is not what runs when somebody inserts a row
 * from psql during a renewal campaign.
 *
 * ┌─ WHAT THIS SCHEMA IS FOR, IN ONE SENTENCE ────────────────────────────────┐
 * │ To let an MSP tell a customer "this firewall stopped getting security     │
 * │ fixes in March, here is the vendor page that says so", and to make it     │
 * │ impossible for this product to tell that customer "you are fine" about a  │
 * │ box it has never heard of.                                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ SEVEN DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ──────────────────┐
 * │                                                                           │
 * │ 1. THE CATALOGUE IS DATA, NOT CODE, AND EVERY ROW CARRIES ITS SOURCE.     │
 * │    `source` is `NOT NULL` with a CHECK that refuses whitespace, and       │
 * │    `verified_at` is `NOT NULL`. There is no representable catalogue row   │
 * │    that asserts a customer's hardware is obsolete without naming who      │
 * │    said so and when we last checked. That is not paperwork: a salesperson │
 * │    who cannot cite the vendor is a salesperson the customer's own vendor  │
 * │    contact contradicts the same week, and the feature dies with the       │
 * │    second contradiction. Seeding this table from code (a TypeScript       │
 * │    constant, a hard-coded list of models) would put the same claims       │
 * │    somewhere no operator can correct them when a vendor changes a date.   │
 * │                                                                           │
 * │ 2. NO `tenant_id`, ON PURPOSE — AND THEREFORE WRITING IT IS A PLATFORM    │
 * │    ACT. "The TZ215 reached end of life" is a fact about SonicWall's       │
 * │    product line, not about a customer, exactly like `ip_asn_ranges` in    │
 * │    migration 021 decision 3. Per-tenant copies would be the same rows a   │
 * │    hundred times and would drift apart. THE CONSEQUENCE IS THE IMPORTANT  │
 * │    HALF: because a row written here changes what EVERY tenant is told,    │
 * │    the write cannot sit behind a tenant-scoped capability. F5 shipped     │
 * │    exactly that bug on `ip_asn_ranges` (SETTINGS_MANAGE is granted to the │
 * │    admin of ANY tenant through `TENANT_ROLE_CAPABILITIES`), so            │
 * │    `lifecycle.routes.ts` guards every write with `requireRole('admin')` — │
 * │    the PLATFORM role read from `users.role`. Reading stays on             │
 * │    DEVICE_READ: it is published vendor information.                       │
 * │                                                                           │
 * │ 3. `lifecycle_firmware` NEEDS *PARTIAL* UNIQUE INDEXES, AND SO WOULD ANY  │
 * │    REPLACEMENT FOR THEM. Its natural key is (brand, family, branch), and  │
 * │    `family` IS NULLABLE — a null means "every family of this brand", the  │
 * │    row that covers a vendor who versions firmware once for the whole      │
 * │    catalogue. Postgres indexes are NULLS DISTINCT by default, so a plain  │
 * │    `UNIQUE (brand, family, branch)` would constrain NOTHING for the       │
 * │    family-wide rows: the same brand+branch could be inserted a hundred    │
 * │    times, and `matchFirmwareEntry` would silently pick whichever had the  │
 * │    lowest id. TWO PARTIAL INDEXES — one `WHERE family IS NOT NULL`, one   │
 * │    `WHERE family IS NULL` — are the only construction that actually says  │
 * │    "one row per branch". Same pattern, same reason, as                    │
 * │    `wan_path_events_session_uniq` in 021 and the intent gaps in 016.      │
 * │                                                                           │
 * │ 4. THE MODEL PATTERN IS STORED ALREADY NORMALISED, AND A CHECK PROVES IT. │
 * │    `model_pattern ~ '^[A-Z0-9]+$'`. Matching happens in                   │
 * │    `shared/src/lifecycle.ts` (`normalizeModelKey`), against a key derived │
 * │    from `devices.model` by that same function. The classic way to get     │
 * │    this wrong is to normalise one side only, and then wonder why          │
 * │    'RB2011UiAS-RM' never matches the row that was typed 'RB2011UiAS-RM'.  │
 * │    The CHECK makes the un-normalised row unstorable instead of silently   │
 * │    unmatchable. It also removes every wildcard character from the         │
 * │    pattern, so nothing here can become a LIKE metacharacter later.        │
 * │                                                                           │
 * │ 5. `declared_status` EXISTS BECAUSE VENDORS RETIRE THINGS WITHOUT DATES,  │
 * │    AND ITS VOCABULARY CANNOT EXPRESS GOOD NEWS. DrayTek publishes an      │
 * │    end-of-life list with no effective dates; SonicWall retires whole      │
 * │    generations the same way. Dropping that fact for want of a date would  │
 * │    be absurd. But the column's CHECK admits only                          │
 * │    'end_of_sale','end_of_support','end_of_life' — never 'supported' and   │
 * │    never 'unknown' — and `deriveModelStatus` combines it with the         │
 * │    date-derived verdict by taking the MORE SEVERE of the two. There is no │
 * │    row in this table that can upgrade a device to `supported`. The ONLY   │
 * │    thing that produces `supported` is a date, in the future, from a       │
 * │    named source.                                                          │
 * │                                                                           │
 * │ 6. CHRONOLOGY IS A CONSTRAINT, NOT A CONVENTION.                          │
 * │    `end_of_sale <= end_of_software_support <= end_of_support`. A vendor   │
 * │    cannot stop fixing a product before it stops selling it, and a row     │
 * │    that says otherwise is a transposition in an import file that would    │
 * │    mark a currently-sold model `end_of_support` on a customer's screen.   │
 * │    `shared/src/lifecycle.ts` refuses the same shapes in                   │
 * │    `validateModelEntry`; two independent refusals, because the            │
 * │    service-layer one is not what runs when a row is edited by hand.       │
 * │                                                                           │
 * │ 7. NOTHING IS DERIVED INTO A COLUMN. There is no `status`, no             │
 * │    `is_end_of_life`, no cached verdict anywhere in this schema. A stored  │
 * │    status is wrong the morning after the date it was computed on, and it  │
 * │    would be wrong SILENTLY — the row still looks fresh. Everything the    │
 * │    screen shows is computed from these dates against the SERVER'S clock   │
 * │    at read time. Same reasoning as F1's expired exceptions.               │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2): nothing in this milestone reads, stores or transports a
 * credential. The columns here hold vendor product names, calendar dates and
 * citation URLs. There is no jsonb anywhere in this schema — deliberately: a
 * jsonb blob is where the L2TP passwords of a whole fleet ended up once on this
 * project, and a catalogue of published vendor facts has no need of one.
 *
 * D3: nothing here writes to an equipment, and F8 does not talk to equipment
 * AT ALL. It reads `devices.model` / `devices.os_version` / `devices.family`,
 * already collected by M2, out of our own Postgres, and joins them to these
 * tables. There is no driver, no session, no pool and no command in this
 * feature.
 */

// ── Vocabularies. The comment gives the LONGEST value; the column is wider. ──
// Mirrors of `shared/src/lifecycle.ts` §1 and `shared/src/device.ts`.
const BRANDS = "'mikrotik','draytek','zyxel','sonicwall'";                       // 9
const FAMILIES =
  "'mikrotik_routeros6','mikrotik_routeros7','draytek_vigor','zyxel_nebula'," +
  "'zyxel_standalone','zyxel_cpe','sonicwall_sonicos'";                          // 18
const MATCH_MODES = "'exact','prefix'";                                          // 6
const SOURCE_KINDS = "'builtin','import','manual'";                              // 7
const DECLARED_STATUSES = "'end_of_sale','end_of_support','end_of_life'";        // 14
const IMPORT_KINDS = "'model','firmware'";                                       // 8

// ── Column widths, set from the lists above and rounded up. ──────────────────
// brand           varchar(32) >= 9   'sonicwall'
// family          varchar(48) >= 18  'mikrotik_routeros6'
// match_mode      varchar(16) >= 6   'prefix'
// source_kind     varchar(16) >= 7   'builtin'
// declared_status varchar(24) >= 14  'end_of_support'
// kind            varchar(16) >= 8   'firmware'
// Every one of these is at least twice its longest legal value. The failure
// this guards against — a CHECK that admits a string the column cannot hold —
// is only ever discovered as "value too long for type character varying" on the
// INSERT, which on an import means the whole dataset is refused at row 400.

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // 1. lifecycle_models — hardware end of sale / support / life.
  // ==========================================================================

  await knex.schema.createTable('lifecycle_models', (t) => {
    t.bigIncrements('id').primary();

    // No tenant_id. Decision 2 — and see the guard consequence there.
    t.string('brand', 32).notNullable();

    // ALREADY NORMALISED (decision 4). `normalizeModelKey` in
    // shared/src/lifecycle.ts produced this from the vendor's own spelling,
    // and produces the comparison key from `devices.model` at read time.
    t.string('model_pattern', 128).notNullable();
    t.string('match_mode', 16).notNullable().defaultTo('exact');

    // What a human calls it. Display only; never compared against anything.
    t.string('model_label', 160).notNullable();

    // The three boundaries, in chronological order. All nullable: "the vendor
    // has not published this one" is the most common state of the world and
    // has to be representable without a lie. Decision 6 constrains their order.
    t.date('end_of_sale').nullable();
    t.date('end_of_software_support').nullable();
    t.date('end_of_support').nullable();

    // Decision 5: bad news without a date. Cannot express good news.
    t.string('declared_status', 24).nullable();

    // What to sell instead. THE revenue field, and nullable because a guess
    // here is worse than a blank: an MSP that quotes the wrong replacement
    // loses the deal twice.
    t.string('replacement', 160).nullable();

    // Decision 1. `source` is the citation a salesperson reads out loud.
    t.string('source_kind', 16).notNullable().defaultTo('import');
    t.string('source', 160).notNullable();
    // Never a URL with credentials in it: this is displayed in the UI and it
    // goes into the export bundle.
    t.string('source_url', 512).nullable();
    t.date('verified_at').notNullable();

    // Honest gaps: "MikroTik publishes no per-model end-of-support date".
    // Mandatory (in `validateModelEntry`) when the row carries no date and no
    // declaration, so a blank row cannot quietly inflate catalogue coverage.
    t.text('note').nullable();

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE lifecycle_models ADD CONSTRAINT lifecycle_models_brand_chk ` +
      `CHECK (brand IN (${BRANDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE lifecycle_models ADD CONSTRAINT lifecycle_models_match_mode_chk ` +
      `CHECK (match_mode IN (${MATCH_MODES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE lifecycle_models ADD CONSTRAINT lifecycle_models_source_kind_chk ` +
      `CHECK (source_kind IN (${SOURCE_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE lifecycle_models ADD CONSTRAINT lifecycle_models_declared_chk ` +
      `CHECK (declared_status IS NULL OR declared_status IN (${DECLARED_STATUSES}))`,
  );
  // DECISION 4, COMPILED. An un-normalised pattern is unstorable rather than
  // silently unmatchable, and the pattern contains no character that could ever
  // be a wildcard in any dialect.
  await knex.schema.raw(
    "ALTER TABLE lifecycle_models ADD CONSTRAINT lifecycle_models_pattern_chk " +
      "CHECK (model_pattern ~ '^[A-Z0-9]+$')",
  );
  // DECISION 1, COMPILED. A row whose source is three spaces cites nothing.
  await knex.schema.raw(
    "ALTER TABLE lifecycle_models ADD CONSTRAINT lifecycle_models_source_chk " +
      "CHECK (btrim(source) <> '')",
  );
  await knex.schema.raw(
    "ALTER TABLE lifecycle_models ADD CONSTRAINT lifecycle_models_label_chk " +
      "CHECK (btrim(model_label) <> '')",
  );
  // DECISION 6, COMPILED. NULLs pass — an unpublished boundary constrains
  // nothing — but two published ones may not be out of order.
  await knex.schema.raw(
    'ALTER TABLE lifecycle_models ADD CONSTRAINT lifecycle_models_chronology_chk CHECK (' +
      '(end_of_sale IS NULL OR end_of_software_support IS NULL OR end_of_sale <= end_of_software_support) AND ' +
      '(end_of_software_support IS NULL OR end_of_support IS NULL OR end_of_software_support <= end_of_support) AND ' +
      '(end_of_sale IS NULL OR end_of_support IS NULL OR end_of_sale <= end_of_support))',
  );

  // One row per (brand, pattern, mode). All three columns are NOT NULL, so a
  // plain unique index genuinely constrains — unlike `lifecycle_firmware`
  // below, whose scope column is nullable and therefore needs partial indexes
  // (decision 3). `match_mode` is part of the key on purpose: an exact row and
  // a prefix row for the same string are two different statements ("the
  // RB2011UiAS-RM specifically" vs "everything starting RB2011"), and
  // `matchModelEntry` resolves the overlap by preferring the exact one.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX lifecycle_models_key_uniq ' +
      'ON lifecycle_models (brand, model_pattern, match_mode)',
  );
  // THE lookup: "every entry for this brand", then matched in TypeScript. The
  // catalogue is small (hundreds of rows) and the match rule — exact beats
  // prefix, longest prefix wins — is the kind of rule that has to be unit
  // testable without a database.
  await knex.schema.raw(
    'CREATE INDEX lifecycle_models_brand_idx ON lifecycle_models (brand)',
  );

  // ==========================================================================
  // 2. lifecycle_firmware — per-branch software support.
  // ==========================================================================

  await knex.schema.createTable('lifecycle_firmware', (t) => {
    t.bigIncrements('id').primary();

    t.string('brand', 32).notNullable();
    // NULLABLE, and that nullability is what forces the partial indexes below.
    // Decision 3.
    t.string('family', 48).nullable();

    // A dotted numeric prefix: '6', '6.49', '7', '4.4'. Matched by
    // `versionInBranch`, which requires the branch components to be an exact
    // prefix of the parsed `devices.os_version`.
    t.string('branch', 32).notNullable();
    t.string('branch_label', 160).notNullable();

    // Lowest release in this branch the vendor still fixes. A device below it
    // is `outdated` — a maintenance ticket, not a sale.
    t.string('min_supported_version', 48).nullable();

    t.date('end_of_support').nullable();
    t.string('declared_status', 24).nullable();

    t.string('source_kind', 16).notNullable().defaultTo('import');
    t.string('source', 160).notNullable();
    t.string('source_url', 512).nullable();
    t.date('verified_at').notNullable();
    t.text('note').nullable();

    t.timestamps(true, true);
  });

  await knex.schema.raw(
    `ALTER TABLE lifecycle_firmware ADD CONSTRAINT lifecycle_firmware_brand_chk ` +
      `CHECK (brand IN (${BRANDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE lifecycle_firmware ADD CONSTRAINT lifecycle_firmware_family_chk ` +
      `CHECK (family IS NULL OR family IN (${FAMILIES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE lifecycle_firmware ADD CONSTRAINT lifecycle_firmware_source_kind_chk ` +
      `CHECK (source_kind IN (${SOURCE_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE lifecycle_firmware ADD CONSTRAINT lifecycle_firmware_declared_chk ` +
      `CHECK (declared_status IS NULL OR declared_status IN (${DECLARED_STATUSES}))`,
  );
  await knex.schema.raw(
    "ALTER TABLE lifecycle_firmware ADD CONSTRAINT lifecycle_firmware_branch_chk " +
      "CHECK (branch ~ '^[0-9]+(\\.[0-9]+)*$')",
  );
  await knex.schema.raw(
    "ALTER TABLE lifecycle_firmware ADD CONSTRAINT lifecycle_firmware_minver_chk " +
      "CHECK (min_supported_version IS NULL OR min_supported_version ~ '^[0-9]+(\\.[0-9]+)*$')",
  );
  // The floor must be INSIDE its own branch. `branch='6'` with
  // `min_supported_version='7.14'` marks every RouterOS 6 box outdated and
  // tells the operator to install a release that does not exist in that tree —
  // one transposed field, fleet-wide false alarm. Expressed here as a string
  // prefix test because that is exactly what `versionInBranch` computes on the
  // parsed components: either the floor IS the branch, or it starts with the
  // branch followed by a dot.
  await knex.schema.raw(
    'ALTER TABLE lifecycle_firmware ADD CONSTRAINT lifecycle_firmware_minver_in_branch_chk CHECK (' +
      "min_supported_version IS NULL OR min_supported_version = branch " +
      "OR min_supported_version LIKE branch || '.%')",
  );
  await knex.schema.raw(
    "ALTER TABLE lifecycle_firmware ADD CONSTRAINT lifecycle_firmware_source_chk " +
      "CHECK (btrim(source) <> '')",
  );
  await knex.schema.raw(
    "ALTER TABLE lifecycle_firmware ADD CONSTRAINT lifecycle_firmware_label_chk " +
      "CHECK (btrim(branch_label) <> '')",
  );

  // DECISION 3, COMPILED. TWO partial indexes, because `family` is nullable and
  // a plain UNIQUE over it would constrain nothing for the family-wide rows.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX lifecycle_firmware_branch_uniq ' +
      'ON lifecycle_firmware (brand, family, branch) WHERE family IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX lifecycle_firmware_branch_anyfamily_uniq ' +
      'ON lifecycle_firmware (brand, branch) WHERE family IS NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX lifecycle_firmware_brand_idx ON lifecycle_firmware (brand)',
  );

  // ==========================================================================
  // 3. lifecycle_imports — the journal.
  // ==========================================================================
  // Small, and it is what answers "where did this claim come from and when?"
  // during an argument with a customer who has just been told their firewall is
  // obsolete. Same shape and same purpose as `weather_asn_imports` in 021.
  //
  // NOT `audit_log`: that ledger is per-tenant and hash-chained, and this
  // catalogue is cross-tenant reference data. Filing a global write under one
  // customer's chain would be a category error and would make the entry
  // invisible to every other customer it affects.

  await knex.schema.createTable('lifecycle_imports', (t) => {
    t.bigIncrements('id').primary();
    t.string('kind', 16).notNullable();
    t.string('source_kind', 16).notNullable().defaultTo('import');
    // A label, a file name, a dataset version — whatever the operator typed.
    t.string('label', 255).notNullable();
    t.integer('rows_loaded').notNullable().defaultTo(0);
    t.integer('rows_rejected').notNullable().defaultTo(0);
    // Who. SET NULL rather than CASCADE: deleting the operator must not erase
    // the record that the catalogue was changed.
    t.integer('imported_by').nullable()
      .references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('imported_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    `ALTER TABLE lifecycle_imports ADD CONSTRAINT lifecycle_imports_kind_chk ` +
      `CHECK (kind IN (${IMPORT_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE lifecycle_imports ADD CONSTRAINT lifecycle_imports_source_kind_chk ` +
      `CHECK (source_kind IN (${SOURCE_KINDS}))`,
  );
  await knex.schema.raw(
    'CREATE INDEX lifecycle_imports_at_idx ON lifecycle_imports (imported_at DESC)',
  );

  // ==========================================================================
  // 4. THE SEED.
  // ==========================================================================
  //
  // ┌─ READ THIS BEFORE QUOTING ANY ROW BELOW TO A CUSTOMER ──────────────────┐
  // │ THIS SEED IS A STARTING POINT, NOT AN AUTHORITY.                        │
  // │                                                                        │
  // │ Every row is marked `source_kind = 'builtin'` and every `note` says so. │
  // │ The rows were written from the maintainers' knowledge of these vendors' │
  // │ published product status AT THE TIME THE MIGRATION WAS WRITTEN. None of │
  // │ them was fetched from a vendor site by a machine, and none of them will │
  // │ ever refresh itself.                                                    │
  // │                                                                        │
  // │ THAT IS WHY ALMOST NONE OF THEM CARRIES A DATE. Where a vendor's        │
  // │ product STATUS is unambiguous and widely published — SonicWall's Gen5   │
  // │ generation is retired, DrayTek's end-of-life list, Zyxel's pre-FLEX USG │
  // │ line — the row records `declared_status` and says plainly that no       │
  // │ effective date was published. Inventing a plausible date would be the   │
  // │ single worst thing this file could do: a wrong date READS AS RESEARCH.  │
  // │ A missing date reads as "go and check", which is exactly what the       │
  // │ salesperson should do. `verified_at` is set to the migration's own date │
  // │ so the UI can show the row's age honestly and it starts ageing at once. │
  // │                                                                        │
  // │ MikroTik is the instructive case: MikroTik does not publish per-model   │
  // │ end-of-support dates at all, and it keeps shipping RouterOS for         │
  // │ hardware it stopped selling years ago. So the MikroTik hardware rows    │
  // │ below say `end_of_sale` ONLY, with a note that says the software        │
  // │ support has NOT ended — which is a genuinely different sales            │
  // │ conversation ("you cannot buy a spare") from the SonicWall one ("no     │
  // │ security fix is coming"). Flattening those two into one "obsolete" flag │
  // │ would produce a renewal list an engineer stops believing.               │
  // │                                                                        │
  // │ Operators replace and extend all of this through                        │
  // │ `POST /api/lifecycle/catalog/*`, which stamps `source_kind='import'`    │
  // │ and journals who and when.                                              │
  // └─────────────────────────────────────────────────────────────────────────┘
  const SEEDED_AT = '2026-08-30';
  const BUILTIN_NOTE =
    "Seeded from ObliWAN's built-in catalogue (migration 027), not fetched from the vendor. " +
    'Re-verify against the vendor before quoting a customer.';

  await knex('lifecycle_firmware').insert([
    {
      brand: 'mikrotik',
      family: 'mikrotik_routeros6',
      branch: '6',
      branch_label: 'MikroTik RouterOS 6',
      // 6.49.x is the v6 long-term series; everything below it is superseded
      // and receives nothing. This is a claim about MikroTik's own release
      // channels, which is checkable, and NOT a claim about a date.
      min_supported_version: '6.49',
      end_of_support: null,
      declared_status: null,
      source_kind: 'builtin',
      source: 'MikroTik RouterOS release channels (long-term tree is 6.49.x)',
      source_url: 'https://mikrotik.com/download',
      verified_at: SEEDED_AT,
      note:
        'MikroTik publishes NO dated end of support for RouterOS 6. All development moved to v7 ' +
        'and only the 6.49.x long-term series still receives fixes, so a box below 6.49 is behind ' +
        `the last release it can get. ${BUILTIN_NOTE}`,
    },
    {
      brand: 'mikrotik',
      family: 'mikrotik_routeros7',
      branch: '7',
      branch_label: 'MikroTik RouterOS 7',
      min_supported_version: null,
      end_of_support: null,
      declared_status: null,
      source_kind: 'builtin',
      source: 'MikroTik RouterOS release channels',
      source_url: 'https://mikrotik.com/download',
      verified_at: SEEDED_AT,
      // No date, no floor, no declaration: this row can only ever produce
      // `unknown`. It is here ON PURPOSE — it is the difference between "we
      // never looked" and "we looked, MikroTik publishes nothing", and it stops
      // the same question being researched a second time.
      note:
        'RouterOS 7 is the current development tree. MikroTik publishes no end-of-support date for ' +
        `it, so this branch can only ever be reported as "end of support unknown". ${BUILTIN_NOTE}`,
    },
    {
      brand: 'sonicwall',
      family: 'sonicwall_sonicos',
      branch: '5',
      branch_label: 'SonicOS 5.x (Gen5)',
      min_supported_version: null,
      end_of_support: null,
      // Decision 5: the generation is retired, the effective date is not
      // something this file is willing to invent.
      declared_status: 'end_of_support',
      source_kind: 'builtin',
      source: 'SonicWall product lifecycle — Gen5 generation retired',
      source_url: 'https://www.sonicwall.com/support/product-lifecycle-tables',
      verified_at: SEEDED_AT,
      note:
        'SonicOS 5.x ran on the Gen5 appliances (TZ 105/205/215, NSA 220/240/250M/2400/3500/4500, ' +
        'E-Class NSA). That generation is retired and receives no firmware. No effective date is ' +
        `recorded here because SonicWall's published date was not verified for this seed. ${BUILTIN_NOTE}`,
    },
    {
      brand: 'sonicwall',
      family: 'sonicwall_sonicos',
      branch: '6',
      branch_label: 'SonicOS 6.x (Gen6)',
      // 6.5.x is the final Gen6 maintenance series; 6.0–6.4 are superseded.
      min_supported_version: '6.5',
      end_of_support: null,
      declared_status: null,
      source_kind: 'builtin',
      source: 'SonicWall SonicOS 6 release notes — 6.5.x is the final Gen6 series',
      source_url: 'https://www.sonicwall.com/support/technical-documentation',
      verified_at: SEEDED_AT,
      note:
        'SonicOS 6.5.x is the last maintained Gen6 branch; builds below 6.5 are superseded. ' +
        `SonicWall's dated end of support for 6.5 was not verified for this seed. ${BUILTIN_NOTE}`,
    },
  ]);

  // ── Hardware. Only models whose vendor product STATUS is unambiguous. ──────
  //
  // Note how few there are. That is the point: a catalogue of twelve
  // well-sourced rows plus an honest "unknown" for everything else is worth
  // more to an MSP than two hundred guesses, because the twelve can be quoted.
  // The `coverage` figure on `GET /api/lifecycle/summary` reports exactly how
  // small this is against the real fleet, so nobody mistakes a thin catalogue
  // for a healthy one.
  const models: Array<Record<string, unknown>> = [];
  const model = (
    brand: string,
    pattern: string,
    matchMode: 'exact' | 'prefix',
    label: string,
    declared: string | null,
    replacement: string | null,
    source: string,
    sourceUrl: string,
    note: string,
    endOfSale: string | null = null,
  ): void => {
    models.push({
      brand,
      model_pattern: pattern,
      match_mode: matchMode,
      model_label: label,
      end_of_sale: endOfSale,
      end_of_software_support: null,
      end_of_support: null,
      declared_status: declared,
      replacement,
      source_kind: 'builtin',
      source,
      source_url: sourceUrl,
      verified_at: SEEDED_AT,
      note: `${note} ${BUILTIN_NOTE}`,
    });
  };

  // -- SonicWall Gen5. Retired generation; no firmware, no RMA. --------------
  const SW_SRC = 'SonicWall product lifecycle tables — Gen5 retired';
  const SW_URL = 'https://www.sonicwall.com/support/product-lifecycle-tables';
  const SW_NOTE =
    'Gen5 appliance: retired generation, no SonicOS builds and no RMA. SonicWall publishes ' +
    'effective dates in its lifecycle tables; none is recorded here because it was not verified.';
  for (const [pattern, label, replacement] of [
    ['TZ105', 'SonicWall TZ 105', 'TZ 270 / TZ 370'],
    ['TZ205', 'SonicWall TZ 205', 'TZ 370'],
    ['TZ215', 'SonicWall TZ 215', 'TZ 370 / TZ 470'],
    ['NSA220', 'SonicWall NSA 220', 'TZ 470 / TZ 570'],
    ['NSA240', 'SonicWall NSA 240', 'TZ 470 / TZ 570'],
    ['NSA250M', 'SonicWall NSA 250M', 'TZ 570'],
    ['NSA2400', 'SonicWall NSA 2400', 'NSa 2700'],
    ['NSA3500', 'SonicWall NSA 3500', 'NSa 3700'],
    ['NSA4500', 'SonicWall NSA 4500', 'NSa 4700'],
    ['NSA5000', 'SonicWall NSA 5000', 'NSa 5700'],
  ] as const) {
    model('sonicwall', pattern, 'exact', label, 'end_of_life', replacement, SW_SRC, SW_URL, SW_NOTE);
  }

  // -- DrayTek. Published end-of-life list, no effective dates. --------------
  const DT_SRC = 'DrayTek end-of-life product list';
  const DT_URL = 'https://www.draytek.co.uk/support/product-lifecycle';
  const DT_EOL_NOTE =
    'DrayTek lists this model as end-of-life: no further firmware, including security fixes. ' +
    'DrayTek publishes the list without effective dates, so none is recorded.';
  for (const [pattern, label, replacement] of [
    ['VIGOR2820', 'DrayTek Vigor 2820', 'Vigor 2865'],
    ['VIGOR2830', 'DrayTek Vigor 2830', 'Vigor 2865'],
    ['VIGOR2850', 'DrayTek Vigor 2850', 'Vigor 2865'],
    ['VIGOR2920', 'DrayTek Vigor 2920', 'Vigor 2927'],
    ['VIGOR2925', 'DrayTek Vigor 2925', 'Vigor 2927'],
    ['VIGOR2960', 'DrayTek Vigor 2960', 'Vigor 3910'],
    ['VIGOR3200', 'DrayTek Vigor 3200', 'Vigor 2927'],
    ['VIGOR3900', 'DrayTek Vigor 3900', 'Vigor 3910'],
  ] as const) {
    model('draytek', pattern, 'prefix', label, 'end_of_support', replacement, DT_SRC, DT_URL, DT_EOL_NOTE);
  }
  // Superseded but NOT declared dead — a weaker and safer claim, and a
  // different conversation: the customer can still get firmware, they just
  // cannot buy another one.
  model(
    'draytek', 'VIGOR2860', 'prefix', 'DrayTek Vigor 2860', 'end_of_sale', 'Vigor 2865',
    DT_SRC, DT_URL,
    'Superseded by the Vigor 2865 and no longer sold. DrayTek has NOT declared it end of ' +
      'software support, so this is a spares/availability signal, not a security one.',
  );

  // -- Zyxel. The pre-FLEX USG / ZyWALL line. -------------------------------
  const ZY_SRC = 'Zyxel end-of-life / end-of-support bulletins — USG & ZyWALL series';
  const ZY_URL = 'https://www.zyxel.com/global/en/support/product-end-of-life';
  const ZY_NOTE =
    'Pre-FLEX USG/ZyWALL generation, superseded by USG FLEX. Zyxel publishes per-model ' +
    'end-of-life bulletins with dates; no date is recorded here because it was not verified.';
  for (const [pattern, label, replacement] of [
    ['USG20', 'Zyxel USG 20 / 20W', 'USG FLEX 50'],
    ['USG40', 'Zyxel USG 40 / 40W', 'USG FLEX 100'],
    ['USG60', 'Zyxel USG 60 / 60W', 'USG FLEX 200'],
    ['USG110', 'Zyxel USG 110', 'USG FLEX 500'],
    ['USG210', 'Zyxel USG 210', 'USG FLEX 500'],
    ['USG310', 'Zyxel USG 310', 'USG FLEX 700'],
    ['USG1100', 'Zyxel USG 1100', 'USG FLEX 700'],
    ['USG1900', 'Zyxel USG 1900', 'USG FLEX 700'],
    ['ZYWALL110', 'Zyxel ZyWALL 110', 'USG FLEX 500'],
    ['ZYWALL310', 'Zyxel ZyWALL 310', 'USG FLEX 700'],
    ['ZYWALL1100', 'Zyxel ZyWALL 1100', 'USG FLEX 700'],
  ] as const) {
    model('zyxel', pattern, 'prefix', label, 'end_of_support', replacement, ZY_SRC, ZY_URL, ZY_NOTE);
  }

  // -- MikroTik. END OF SALE ONLY, and the note says why. --------------------
  // MikroTik keeps shipping RouterOS for hardware it stopped selling years ago,
  // so `end_of_support` here would be a fabrication. What IS true and useful:
  // the customer cannot buy another one.
  const MT_SRC = 'MikroTik product catalogue — model no longer offered';
  const MT_URL = 'https://mikrotik.com/products';
  const MT_NOTE =
    'No longer offered by MikroTik. MikroTik publishes NO per-model end-of-support date and ' +
    'continues to ship RouterOS for discontinued hardware, so this is a SPARES signal only: ' +
    'end of software support for this model is UNKNOWN, not reached.';
  for (const [pattern, label, replacement] of [
    ['RB2011', 'MikroTik RB2011 series', 'hEX / RB5009'],
    ['RB750GL', 'MikroTik RB750GL', 'hEX (RB750Gr3)'],
    ['RB751', 'MikroTik RB751 series', 'hAP ac2 / hAP ax2'],
    ['RB951', 'MikroTik RB951 series', 'hAP ac2 / hAP ax2'],
    ['RB1100AHX2', 'MikroTik RB1100AHx2', 'RB5009 / CCR2004'],
  ] as const) {
    model('mikrotik', pattern, 'prefix', label, 'end_of_sale', replacement, MT_SRC, MT_URL, MT_NOTE);
  }

  await knex('lifecycle_models').insert(models);
}

export async function down(knex: Knex): Promise<void> {
  // Order matters only for readability here — none of the three references the
  // others. `lifecycle_imports` has an FK to `users`, which this migration did
  // not create and must not touch.
  await knex.schema.dropTableIfExists('lifecycle_imports');
  await knex.schema.dropTableIfExists('lifecycle_firmware');
  await knex.schema.dropTableIfExists('lifecycle_models');
}
