import type { Knex } from 'knex';

/**
 * 023_fix_m1012.ts — the storage two audit findings needed, one from M10 and
 * one from M12. Two unrelated subsystems, one migration, because each of them
 * is a single column-or-constraint and a deploy step nobody skips is worth
 * more than a tidy filename.
 *
 * ┌─ 1. `cwmp_devices.auth_nonce_seen` — M10 finding 7, the guard that was ───┐
 * │    ONLY EVER A SENTENCE                                                   │
 * │                                                                          │
 * │ `cwmp/digest.ts` justified its stateless nonce with "replay within the    │
 * │ window is bounded by the `nc` counter recorded on the session row". There │
 * │ was no such column on `cwmp_sessions`, no writer, and no comparison:      │
 * │ `verifyDigest` read `creds.nc` only to feed it into the hash. Port 7547   │
 * │ is plain HTTP by design (§6.2 — the fleet was provisioned with `http://`  │
 * │ ACS URLs), so anyone on the path could lift one `Authorization: Digest …` │
 * │ header and re-POST it for the next five minutes to open a session with    │
 * │ `authenticated = true`.                                                   │
 * │                                                                          │
 * │ NOT on `cwmp_sessions`, despite what the sentence said. The Inform IS the │
 * │ authentication exchange and the session row is written only after it      │
 * │ succeeds, so a replayed Inform does not reuse a session — it opens a      │
 * │ second one. A per-session counter would be written once and read never.   │
 * │ `cwmp_devices` is the single row the original and the replay both resolve │
 * │ to, so it is the only place the comparison can happen.                    │
 * │                                                                          │
 * │ The column holds `[{ n: <nonce>, c: <highest nc>, e: <expiry ms> }]`, and │
 * │ `claimDigestNonce` (`services/cwmp/device.service.ts`) is its only        │
 * │ writer: it drops entries whose own nonce has expired — past that instant  │
 * │ `nonceIsValid` refuses them on arithmetic alone — and refuses a           │
 * │ `(nonce, nc)` pair it has already spent. The default `[]` is what lets    │
 * │ every enrolled CPE keep working across the deploy: the first Inform after │
 * │ it simply records its nonce.                                              │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 2. THE THREE `slot_secret_chk` CONSTRAINTS — M12 finding 5, "lockstep" ──┐
 * │    THAT WAS NOT LOCKSTEP                                                  │
 * │                                                                          │
 * │ Migration 017 says twice that its `SECRET_SLOT_RE` is "deliberately the   │
 * │ SAME token list as `BASELINE_FORBIDDEN_ATTRIBUTES`" and "kept in exact    │
 * │ lockstep with `slotIsForbidden`". It was not.                             │
 * │ `isForbiddenBaselineAttribute` refuses through TWO mechanisms — a Set of  │
 * │ exact names, then a substring pass — and the regex transcribed only the   │
 * │ substring pass. Two names of the exact list have no substring in it:      │
 * │                                                                          │
 * │   preSharedKey -> contains neither `psk`, nor `privatekey`, nor `secret`  │
 * │   community    -> contains nothing on the list at all                     │
 * │                                                                          │
 * │ Both were ACCEPTED by all three CHECKs, verified against a real           │
 * │ postgres:16. Decision 3 rests on two independent refusals precisely so    │
 * │ that a writer which does not go through `emit()` — a replay of an         │
 * │ archived run, a backfill, an import — still cannot land a credential in   │
 * │ `baseline_slots.constant_value` / `sample_values`, from where it travels  │
 * │ into the draft body and into `template_revisions.var_schema`. For those   │
 * │ two names there was only ever ONE refusal, which is the exact situation   │
 * │ the decision was written to prevent.                                      │
 * │                                                                          │
 * │ THE TWO MECHANISMS STAY TWO MECHANISMS, and that is the whole subtlety.   │
 * │ Adding `community` to the existing substring alternation would be         │
 * │ STRICTER than the function, not equal to it: `communityIsWellKnown` is a  │
 * │ legitimate mined attribute that `isForbiddenBaselineAttribute` accepts    │
 * │ (the substring pass does not list `community`; only the exact-name Set    │
 * │ does), and a CHECK that refused it would amputate a real fleet's SNMP     │
 * │ facts and look like a mining bug. The regex below therefore has two       │
 * │ alternatives, one per mechanism: "the last segment CONTAINS one of the    │
 * │ eight tokens" or "the last segment IS one of the two exact names".        │
 * │                                                                          │
 * │ Anchored on the LAST segment either way, as in 017: the discriminator in  │
 * │ the middle is built from names the CUSTOMER chose, and a local user       │
 * │ called `secretary` or a DHCP scope called `credential-lab` must keep its  │
 * │ baseline.                                                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

/**
 * Both halves of `isForbiddenBaselineAttribute`, in one anchored expression.
 *
 *   /…token…$   the substring pass — 017 had exactly this and only this
 *   /presharedkey$, /community$   the exact-name Set, which 017 dropped
 *
 * The other eight names of `BASELINE_FORBIDDEN_ATTRIBUTES` need no alternative
 * of their own: `pskFingerprint`, `passwordFingerprint`, `communityFingerprint`
 * and `sshKeyFingerprints` all contain `fingerprint`, and `secret`, `password`,
 * `psk` and `privateKey` are their own substrings.
 *
 * Written out in full rather than composed from 017's value, so that reading
 * this file tells you what the constraint IS.
 */
const SECRET_SLOT_RE =
  '/([^/]*(password|passphrase|secret|psk|credential|apikey|privatekey|fingerprint)[^/]*' +
  '|presharedkey|community)$';

const SLOT_TABLES: readonly [string, string][] = [
  ['baseline_slots', 'baseline_slots_slot_secret_chk'],
  ['baseline_exceptions', 'baseline_exceptions_slot_secret_chk'],
  ['baseline_deviations', 'baseline_deviations_slot_secret_chk'],
];

/** 017's regex, for `down()`. */
const SECRET_SLOT_RE_017 =
  '/[^/]*(password|passphrase|secret|psk|credential|apikey|privatekey|fingerprint)[^/]*$';

export async function up(knex: Knex): Promise<void> {
  // ── 1. The ACS replay record ────────────────────────────────────────────
  await knex.schema.alterTable('cwmp_devices', (t) => {
    t.jsonb('auth_nonce_seen').notNullable().defaultTo('[]');
  });
  await knex.schema.raw(
    'COMMENT ON COLUMN cwmp_devices.auth_nonce_seen IS $$Digest nonces already ' +
      'spent by this CPE: [{n: nonce, c: highest nc accepted, e: expiry ms}]. ' +
      'Written only by claimDigestNonce(); an entry is dropped once its own ' +
      'nonce has expired, because nonceIsValid() refuses it from then on. This ' +
      'is the replay bound digest.ts used to promise and not implement.$$',
  );

  // ── 2. The two names the SQL half of decision 3 was missing ─────────────
  //
  // Existing rows first. No emitter produces these two attributes today —
  // `facts.ts` enumerates its attributes one by one — so the expectation is
  // zero rows moved; it is written anyway because a constraint that cannot be
  // added is a migration that fails on the one deployment that has the
  // problem, and because `baseline_deviations.exception_id` would make the
  // deletion order matter if there ever were any.
  await knex.raw(
    `DELETE FROM baseline_deviations WHERE slot ~* ? AND slot !~* ?`,
    [SECRET_SLOT_RE, SECRET_SLOT_RE_017],
  );
  await knex.raw(
    `DELETE FROM baseline_exceptions WHERE slot ~* ? AND slot !~* ?`,
    [SECRET_SLOT_RE, SECRET_SLOT_RE_017],
  );
  await knex.raw(
    `DELETE FROM baseline_slots WHERE slot ~* ? AND slot !~* ?`,
    [SECRET_SLOT_RE, SECRET_SLOT_RE_017],
  );

  for (const [table, constraint] of SLOT_TABLES) {
    await knex.schema.raw(`ALTER TABLE ${table} DROP CONSTRAINT IF EXISTS ${constraint}`);
    await knex.schema.raw(
      `ALTER TABLE ${table} ADD CONSTRAINT ${constraint} CHECK (slot !~* '${SECRET_SLOT_RE}')`,
    );
  }
}

export async function down(knex: Knex): Promise<void> {
  for (const [table, constraint] of SLOT_TABLES) {
    await knex.schema.raw(`ALTER TABLE ${table} DROP CONSTRAINT IF EXISTS ${constraint}`);
    await knex.schema.raw(
      `ALTER TABLE ${table} ADD CONSTRAINT ${constraint} CHECK (slot !~* '${SECRET_SLOT_RE_017}')`,
    );
  }
  await knex.schema.alterTable('cwmp_devices', (t) => {
    t.dropColumn('auth_nonce_seen');
  });
}
