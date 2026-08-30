import type { Knex } from 'knex';

/**
 * 004_security.ts — the two pieces of schema the security passes needed and
 * could not write, because every one of them was scoped to a set of files that
 * excluded `db/migrations/`.
 *
 * ── 1. `users.totp_last_counter` ────────────────────────────────────────────
 *
 * The TOTP anti-replay of VERIF-SECFIX R6 was implemented as a `Map` in process
 * memory (`services/twoFactor.service.ts`). Its own comment named the limit
 * honestly: it survives neither a restart nor a second replica. That is not a
 * theoretical reserve here — `config.ts` documents arbitrage A5
 * (`OBLIWAN_ROLE=web|worker|all`) and states in as many words that "several
 * `web` replicas may run side by side". The in-memory guard therefore
 * contradicts the deployment shape the project has already chosen: a code
 * captured over a shoulder or relayed by a phishing proxy is replayable for the
 * rest of its ~90 s validity window against any replica that has not seen it,
 * and against the same replica after any restart or deploy.
 *
 * The durable form is a high-water mark of the last absolute counter accepted
 * for the account, moved forward by the same statement that validates it:
 *
 *     UPDATE users SET totp_last_counter = :counter
 *      WHERE id = :id
 *        AND (totp_last_counter IS NULL OR totp_last_counter < :counter)
 *
 * `rowCount = 0` is a replay (or an out-of-order code), and PostgreSQL — not
 * application code — arbitrates the race between two concurrent submissions of
 * the same code, on any number of replicas.
 *
 * NULL means "no code has ever been accepted for this account", which is also
 * the state left behind when a TOTP secret is removed or rotated: the new
 * secret starts with a clean high-water mark. `integer` is sufficient by a wide
 * margin — the counter is `floor(unix_time / 30)`, i.e. ~5.9e7 today and
 * ~7.2e7 at the 2038 boundary of a signed 32-bit epoch.
 *
 * ── 2. Partial unique index on `users.email` ────────────────────────────────
 *
 * AUDIT-SEC #12 asked for it and no pass delivered it: `pg_indexes` on `users`
 * carried only `users_pkey` and `users_username_unique`. The column is what
 * `passwordReset.service.requestReset` resolves an account by, with `.first()`
 * and no `orderBy` — so with two rows sharing an address, WHICH account gets a
 * reset link is decided by the planner. It is also the destination of the
 * e-mail OTP. An address is an authentication factor here; two accounts must
 * not be able to claim the same one.
 *
 * Partial (`WHERE email IS NOT NULL AND btrim(email) <> ''`) because the column
 * is nullable by design — a local account without 2FA has no e-mail — and
 * because the empty string has historically been able to reach it through
 * `profile.update` (`data.email || null` catches '' today, but the column has
 * no CHECK). On `lower(email)` because e-mail domains are case-insensitive and
 * `Alice@acme.tld` must not be able to shadow `alice@acme.tld`; the reset
 * lookup was changed to match on `lower(email)` in the same pass, so the index
 * is the one the query can actually use.
 *
 * A pre-existing duplicate makes this migration FAIL, loudly and with the list
 * of offending rows, rather than skip the index. Failing the upgrade is the
 * conservative choice: silently NULLing the losing rows would disable their
 * e-mail OTP without telling anyone, and silently skipping the index would
 * leave an instance believing it holds a guarantee it does not.
 */

export async function up(knex: Knex): Promise<void> {
  // ── 1. Durable TOTP anti-replay high-water mark ────────────────────────────
  await knex.schema.alterTable('users', (t) => {
    t.integer('totp_last_counter').nullable().defaultTo(null);
  });

  // ── 2. One e-mail address, one account ─────────────────────────────────────
  const dupes = await knex.raw<{
    rows: { email: string; ids: number[] }[];
  }>(`
    SELECT lower(btrim(email)) AS email, array_agg(id ORDER BY id) AS ids
      FROM users
     WHERE email IS NOT NULL AND btrim(email) <> ''
     GROUP BY lower(btrim(email))
    HAVING count(*) > 1
     ORDER BY 1
  `);

  if (dupes.rows.length > 0) {
    const detail = dupes.rows
      .map((r) => `  ${r.email} -> users.id ${r.ids.join(', ')}`)
      .join('\n');
    throw new Error(
      'Migration 004_security cannot create the unique index on users.email: ' +
        `${dupes.rows.length} address(es) are claimed by more than one account.\n${detail}\n` +
        'An e-mail address is an authentication factor in ObliWAN (password reset, e-mail OTP), ' +
        'so it cannot be shared. Decide which account keeps each address and clear the others ' +
        "(UPDATE users SET email = NULL, email_otp_enabled = false WHERE id = <loser>), " +
        'then run the migration again.',
    );
  }

  await knex.raw(`
    CREATE UNIQUE INDEX users_email_lower_unique
        ON users (lower(btrim(email)))
     WHERE email IS NOT NULL AND btrim(email) <> ''
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw('DROP INDEX IF EXISTS users_email_lower_unique');
  await knex.schema.alterTable('users', (t) => {
    t.dropColumn('totp_last_counter');
  });
}
