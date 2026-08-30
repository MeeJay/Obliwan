import type { Knex } from 'knex';

/**
 * 011_attribution.ts — M8: K6 (who changed this box) and the completion of K7
 * (is this site actually down).
 *
 * Four tables, and each of them exists to make one specific lie impossible.
 *
 * ┌─ 1. `device_login_events` — WHO WAS ON THE BOX, AND FROM WHERE ───────────┐
 * │ Extracted from syslog and from RouterOS `/log`, never from the datagram's │
 * │ source address. `source_ip` here is the address of the HUMAN, parsed out  │
 * │ of the message text; the socket peer address lives in `syslog_messages`   │
 * │ and stays there, because behind the Docker bridge it is the gateway (A6). │
 * │                                                                          │
 * │ `device_id` is NOT NULL and that is deliberate. A login line we could not │
 * │ tie to a device cannot attribute anything, and it is already kept whole   │
 * │ in `syslog_messages` with `device_id IS NULL`. Copying it here as an      │
 * │ orphan would only create a second place to look for the same nothing.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 2. `drift_attributions` — AND THE ROW EXISTS EVEN WHEN WE DO NOT KNOW ───┐
 * │ ONE ROW PER DRIFT RUN, always written, including when the verdict is      │
 * │ `unattributed`. That is the whole point of the milestone: "we looked and  │
 * │ found nobody" is a result that must be stored, queryable and shown, not   │
 * │ an absent row that reads as "we never looked".                            │
 * │                                                                          │
 * │ `candidates` keeps every session that was CONSIDERED with its score. An   │
 * │ operator who disagrees with a verdict has to be able to see the runners-  │
 * │ up and the arithmetic, otherwise the score is an oracle.                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 3. `routeros_log_cursors` — IDEMPOTENT PULL OF `/log` ───────────────────┐
 * │ RouterOS `/log` is a CIRCULAR BUFFER and its `.id` (`*4A2`) is reused     │
 * │ after a wrap. Using it as a cursor silently skips everything after a      │
 * │ reboot. The cursor is therefore a CONTENT HASH of the last row we         │
 * │ ingested plus a timestamp, and the uniqueness that actually protects us   │
 * │ is `device_login_events(device_id, dedupe_key)`.                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 4. `external_probe_state` — THE FOURTH SIGNAL OF K7, WITH A BASELINE ────┐
 * │ `reachability_verdicts.external_ok` has existed since migration 002 and   │
 * │ nothing has ever written it. This table is what finally does — and the    │
 * │ column that matters most in it is `baseline_ok_at`.                       │
 * │                                                                          │
 * │ A TCP probe to a customer's public address that has NEVER succeeded       │
 * │ proves nothing: most sites answer nothing on purpose. Reporting `false`   │
 * │ from such a probe would hand the truth table a second "independent"       │
 * │ negative signal and manufacture `SITE_DOWN` out of a firewall rule. So    │
 * │ the probe may only report `false` once it has been observed UP at least   │
 * │ once. Until then it reports `null`, and `null` means UNREACHABLE, which   │
 * │ is the honest answer.                                                     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * TENANCY. None of these four tables carries a `tenant_id`, exactly like
 * `drift_runs`, the NCM tables and the SNMP series: they all hang off
 * `devices`, and every read scopes through a join on `devices.tenant_id`.
 * Every index below therefore leads with `device_id`, so that join drives it.
 * Removing one of those joins is a cross-tenant disclosure, not a refactor.
 */

// ── CHECK vocabularies, and the varchar widths they dictate ────────────────
// The widths below were computed against the LONGEST member of each list, not
// guessed. A rename that outgrows its column produces `value too long for type
// character varying(n)` at runtime, which no typecheck catches.
//
//   login_method    'console' / 'unknown'          =  7  -> varchar(16)
//   login_event     'login_failed'                 = 12  -> varchar(16)
//   login_origin    'routeros_log'                 = 12  -> varchar(16)
//   verdict         'unattributed'                 = 12  -> varchar(16)
//   probe_kind      'tcp_connect'                  = 11  -> varchar(16)
const LOGIN_METHODS =
  "'winbox','ssh','telnet','api','web','ftp','console','serial','vpn','unknown'";
const LOGIN_EVENTS = "'login','logout','login_failed'";
const LOGIN_ORIGINS = "'syslog','routeros_log'";
const ATTRIBUTION_VERDICTS =
  "'attributed','platform','ambiguous','unattributed','excluded'";
const PROBE_KINDS = "'tcp_connect'";

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // device_login_events
  // ==========================================================================
  await knex.schema.createTable('device_login_events', (t) => {
    t.bigIncrements('id').primary();

    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    // OUR clock: receive time for a syslog line, poll time for a `/log` row.
    // Every window computation in `attribution.service` uses THIS column and
    // never `device_ts` — a router booting without NTP reports 1970, and a
    // window built on that attributes nothing to anybody for ever.
    t.timestamp('ts', { useTz: true }).notNullable();
    // The equipment's own clock, verbatim, when it gave one. Kept because the
    // gap between the two is how a fleet with no NTP becomes visible, and
    // because a forensic reader needs the box's own account of the time.
    t.timestamp('device_ts', { useTz: true }).nullable();

    t.string('event', 16).notNullable();
    // Long enough for `user@realm` and for the decorations RouterOS appends.
    t.string('account', 128).notNullable();
    // Denormalised at write time rather than recomputed at read time: the list
    // of shared account names will grow, and editing it must not retroactively
    // rewrite what we told an operator six months ago.
    t.boolean('shared_account').notNullable().defaultTo(false);
    t.string('method', 16).notNullable().defaultTo('unknown');

    // THE ADDRESS OF THE HUMAN, parsed from the message body. NOT the datagram
    // source (A6). Nullable because a console login legitimately has none, and
    // inventing one would be inventing the operator's location.
    t.specificType('source_ip', 'inet').nullable();

    t.string('origin', 16).notNullable();
    // The line we based this on, truncated. Evidence: an operator contesting an
    // attribution must be able to read what the box actually said.
    t.string('message', 512).notNullable().defaultTo('');

    // Idempotency of the PULL path. `/log` is re-read every cycle and the same
    // rows come back; the `.id` RouterOS gives them is reused after a wrap, so
    // the key is a content hash. NOT NULL so the unique index below is a plain
    // one — a nullable scope column would need a PARTIAL index and would
    // constrain nothing, because NULLs are distinct.
    t.string('dedupe_key', 64).notNullable();

    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // The attribution scan: "every session on device D between T0 and T1".
  // `device_id` leads so the tenant join on `devices` drives the index.
  await knex.schema.raw(
    'CREATE INDEX device_login_events_dev_ts_idx ON device_login_events (device_id, ts DESC)',
  );
  // Ingestion is idempotent or it is nothing: the `/log` poller re-reads the
  // same buffer every cycle and a restart replays it from the top.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX device_login_events_dedupe_uq ON device_login_events (device_id, dedupe_key)',
  );
  // "Who has been logging in on this fleet lately", and the account audit.
  // Partial on `login` only: `logout` and `login_failed` rows are read through
  // the window scan above and never through this one, and including them would
  // triple an index that exists for a screen.
  await knex.schema.raw(
    "CREATE INDEX device_login_events_account_idx ON device_login_events (device_id, account, ts DESC) " +
      "WHERE event = 'login'",
  );

  await knex.schema.raw(
    `ALTER TABLE device_login_events ADD CONSTRAINT device_login_events_event_chk
       CHECK (event IN (${LOGIN_EVENTS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE device_login_events ADD CONSTRAINT device_login_events_method_chk
       CHECK (method IN (${LOGIN_METHODS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE device_login_events ADD CONSTRAINT device_login_events_origin_chk
       CHECK (origin IN (${LOGIN_ORIGINS}))`,
  );
  // An empty account name is not an account. A parser that reaches this state
  // has matched a login pattern without capturing who — which is a bug, and
  // storing it would create a candidate that attributes a change to "".
  await knex.schema.raw(
    `ALTER TABLE device_login_events ADD CONSTRAINT device_login_events_account_chk
       CHECK (length(btrim(account)) > 0)`,
  );

  // ==========================================================================
  // drift_attributions
  // ==========================================================================
  await knex.schema.createTable('drift_attributions', (t) => {
    t.bigIncrements('id').primary();

    // ONE attribution per run. A second row for the same run would mean two
    // contradictory answers to the same question, and nothing downstream would
    // know which one to believe. Re-running attribution UPSERTs.
    t.bigInteger('run_id').notNullable().unique()
      .references('id').inTable('drift_runs').onDelete('CASCADE');

    // Denormalised from the run so the tenant join and the fleet-wide "show me
    // every unattributed change" query do not need a second hop.
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');

    t.string('verdict', 16).notNullable();
    t.decimal('score', 4, 3).notNullable().defaultTo(0);
    // Machine-readable. The UI translates it; nothing parses a sentence.
    // Widest value in use is `candidates_within_ambiguity_margin` (34).
    t.string('reason', 64).notNullable();

    // The interval inside which the change provably happened: from the moment
    // the old config was last CONFIRMED identical to the moment the new one was
    // captured. Stored, not recomputed, because the snapshots it derives from
    // are subject to retention and the window must outlive them.
    t.timestamp('window_from', { useTz: true }).notNullable();
    t.timestamp('window_to', { useTz: true }).notNullable();

    // -- The named party. NULL for every verdict except `attributed`. --------
    t.bigInteger('login_event_id').nullable()
      .references('id').inTable('device_login_events').onDelete('SET NULL');
    t.string('account', 128).nullable();
    t.boolean('shared_account').notNullable().defaultTo(false);
    t.string('method', 16).nullable();
    t.specificType('source_ip', 'inet').nullable();

    // -- The other kind of author: us. --------------------------------------
    t.bigInteger('change_job_id').nullable()
      .references('id').inTable('change_jobs').onDelete('SET NULL');

    // Every session considered, with its score and the four terms that made it.
    t.jsonb('candidates').notNullable().defaultTo(knex.raw("'[]'::jsonb"));

    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    'CREATE INDEX drift_attributions_dev_created_idx ON drift_attributions (device_id, created_at DESC)',
  );
  // "Show me every change nobody owns" — the screen that makes an unattributed
  // change actionable instead of merely honest. Partial, because that query
  // never asks for the attributed ones and they are the majority.
  await knex.schema.raw(
    "CREATE INDEX drift_attributions_open_idx ON drift_attributions (device_id, created_at DESC) " +
      "WHERE verdict IN ('unattributed','ambiguous')",
  );

  await knex.schema.raw(
    `ALTER TABLE drift_attributions ADD CONSTRAINT drift_attributions_verdict_chk
       CHECK (verdict IN (${ATTRIBUTION_VERDICTS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE drift_attributions ADD CONSTRAINT drift_attributions_score_chk
       CHECK (score >= 0 AND score <= 1)`,
  );
  await knex.schema.raw(
    `ALTER TABLE drift_attributions ADD CONSTRAINT drift_attributions_method_chk
       CHECK (method IS NULL OR method IN (${LOGIN_METHODS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE drift_attributions ADD CONSTRAINT drift_attributions_window_chk
       CHECK (window_to >= window_from)`,
  );
  // ── THE CONSTRAINT THAT ENFORCES POINT 1 OF THE MILESTONE ────────────────
  // Only `attributed` may name an account. It is a CHECK and not a service
  // rule because "never invent a culprit" is exactly the kind of invariant a
  // later refactor breaks by accident: an `unattributed` row carrying a
  // leftover account from the previous iteration would be rendered by the UI
  // as an accusation, and nothing else in the stack would notice.
  await knex.schema.raw(
    `ALTER TABLE drift_attributions ADD CONSTRAINT drift_attributions_names_only_when_attributed
       CHECK (
         (verdict = 'attributed' AND account IS NOT NULL)
         OR (verdict <> 'attributed' AND account IS NULL AND login_event_id IS NULL)
       )`,
  );
  // Symmetrically, only `platform` may point at one of our own jobs.
  await knex.schema.raw(
    `ALTER TABLE drift_attributions ADD CONSTRAINT drift_attributions_job_only_when_platform
       CHECK (change_job_id IS NULL OR verdict = 'platform')`,
  );

  // ==========================================================================
  // routeros_log_cursors
  // ==========================================================================
  await knex.schema.createTable('routeros_log_cursors', (t) => {
    // One cursor per device: the pull is serialised per device by construction.
    t.integer('device_id').primary()
      .references('id').inTable('devices').onDelete('CASCADE');

    // Content hash of the last row we ingested, NOT the RouterOS `.id`: that
    // identifier is reused when the circular buffer wraps, so a cursor built on
    // it skips everything written after a reboot.
    t.string('last_hash', 64).nullable();
    // The device-side timestamp of that row, as WE reconstructed it.
    t.timestamp('last_row_ts', { useTz: true }).nullable();

    t.timestamp('last_poll_at', { useTz: true }).nullable();
    t.timestamp('last_ok_at', { useTz: true }).nullable();
    t.integer('consecutive_failures').notNullable().defaultTo(0);
    // Redacted message only (§8.2). Never a credential, never a raw device
    // response.
    t.text('last_error').nullable();

    t.bigInteger('rows_ingested').notNullable().defaultTo(0);
    t.bigInteger('logins_ingested').notNullable().defaultTo(0);

    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // ==========================================================================
  // external_probe_state
  // ==========================================================================
  await knex.schema.createTable('external_probe_state', (t) => {
    t.integer('device_id').primary()
      .references('id').inTable('devices').onDelete('CASCADE');

    t.boolean('enabled').notNullable().defaultTo(true);
    t.string('kind', 16).notNullable().defaultTo('tcp_connect');

    // Where the probe dials. NULL = "use whatever public address presence last
    // observed" (`ppp_sessions.caller_ip` / `devices.wan_public_ip`), which is
    // the address the site reaches the internet from and is therefore genuinely
    // outside the L2TP tunnel. Never `tunnel_ip`: a probe that rides the tunnel
    // is not an independent signal, it is `snmp_ok` wearing a different name.
    t.specificType('target_ip', 'inet').nullable();
    t.integer('target_port').notNullable().defaultTo(443);
    t.integer('timeout_ms').notNullable().defaultTo(3000);
    t.integer('interval_sec').notNullable().defaultTo(120);

    t.timestamp('last_probe_at', { useTz: true }).nullable();
    t.timestamp('last_ok_at', { useTz: true }).nullable();
    t.integer('consecutive_failures').notNullable().defaultTo(0);
    t.text('last_error').nullable();

    // ── THE COLUMN THE WHOLE TABLE EXISTS FOR ─────────────────────────────
    // Set the FIRST time the probe succeeds, and never cleared. Until it is
    // set, a failing probe reports `null` ("not measured"), never `false`:
    // most customer sites answer nothing on their public address by design,
    // and a probe that has never worked is measuring our own ignorance. Let it
    // report `false` and the K7 truth table gains a second independent
    // negative — which is precisely the arithmetic that turns a blind observer
    // into `SITE_DOWN` and sends a technician to a site that is fine.
    t.timestamp('baseline_ok_at', { useTz: true }).nullable();

    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    `ALTER TABLE external_probe_state ADD CONSTRAINT external_probe_state_kind_chk
       CHECK (kind IN (${PROBE_KINDS}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE external_probe_state ADD CONSTRAINT external_probe_state_port_chk
       CHECK (target_port BETWEEN 1 AND 65535)`,
  );
  await knex.schema.raw(
    `ALTER TABLE external_probe_state ADD CONSTRAINT external_probe_state_timing_chk
       CHECK (timeout_ms BETWEEN 100 AND 60000 AND interval_sec BETWEEN 10 AND 86400)`,
  );
  // The due-list of the prober. Partial on `enabled`: a disabled probe is never
  // selected and has no business inflating the index the scheduler walks.
  await knex.schema.raw(
    'CREATE INDEX external_probe_state_due_idx ON external_probe_state (last_probe_at NULLS FIRST) ' +
      'WHERE enabled',
  );
}

export async function down(knex: Knex): Promise<void> {
  // Reverse dependency order: `drift_attributions` points at
  // `device_login_events`.
  await knex.schema.dropTableIfExists('external_probe_state');
  await knex.schema.dropTableIfExists('routeros_log_cursors');
  await knex.schema.dropTableIfExists('drift_attributions');
  await knex.schema.dropTableIfExists('device_login_events');
}
