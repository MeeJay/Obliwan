import type { Knex } from 'knex';

/**
 * Mass credential rotation — the staging column that makes it survivable.
 *
 * ┌─ THE FAILURE THIS EXISTS TO PREVENT ─────────────────────────────────────┐
 * │ Rotating a device password is two writes that must both succeed: one on   │
 * │ the ROUTER and one in the VAULT. There is no transaction spanning them.   │
 * │                                                                          │
 * │ Write the vault first and the router refuses: the vault holds a password  │
 * │ the box never accepted, and the device is unreachable.                    │
 * │ Write the router first and the vault write fails: the box accepts a       │
 * │ password nobody recorded, and the device is unreachable.                  │
 * │                                                                          │
 * │ Either order loses the fleet on a crash, and "rotate every credential"    │
 * │ is precisely the operation somebody runs across four hundred devices at   │
 * │ once. So the answer is not an order — it is a THIRD slot.                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `secret_next_enc` holds the candidate. The sequence becomes:
 *
 *   1. generate, store in `secret_next_enc`   — nothing on the device yet, and
 *                                               `secret_enc` still works
 *   2. write it to the device
 *   3. open a BRAND-NEW session with the candidate and assert identity
 *   4. only then promote: `secret_enc = secret_next_enc`, clear the candidate
 *
 * A crash at any point leaves `secret_enc` valid and a harmless candidate
 * behind. Step 3 is the one that must never be skipped: it is the only proof
 * that the box took the password we are about to make canonical, and it runs
 * on a fresh socket for the same reason `assertTargetBinding` does — a
 * connection that was already open proves nothing about the credential.
 *
 * `rotated_at` is written by the promotion, so "which credentials have never
 * been rotated" is a query rather than an archaeology exercise.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('device_transports', (t) => {
    t.text('secret_next_enc').nullable();
    t.integer('secret_next_key_version').nullable();
    t.timestamp('secret_next_at', { useTz: true }).nullable();
    t.timestamp('rotated_at', { useTz: true }).nullable();
  });

  // A candidate without its key version cannot be decrypted, and a key version
  // without a candidate is a leftover that would confuse the promotion. Both
  // present or both absent — the shape is enforced rather than assumed.
  await knex.schema.raw(
    'ALTER TABLE device_transports ADD CONSTRAINT device_transports_secret_next_chk ' +
      'CHECK ((secret_next_enc IS NULL AND secret_next_key_version IS NULL) ' +
      'OR (secret_next_enc IS NOT NULL AND secret_next_key_version IS NOT NULL))',
  );

  // "Which rotations were started and never promoted" — the query an operator
  // runs the morning after a campaign that was interrupted.
  await knex.schema.raw(
    'CREATE INDEX device_transports_pending_rotation_idx ON device_transports (device_id) ' +
      'WHERE secret_next_enc IS NOT NULL',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DROP INDEX IF EXISTS device_transports_pending_rotation_idx');
  await knex.schema.raw(
    'ALTER TABLE device_transports DROP CONSTRAINT IF EXISTS device_transports_secret_next_chk',
  );
  await knex.schema.alterTable('device_transports', (t) => {
    t.dropColumn('secret_next_enc');
    t.dropColumn('secret_next_key_version');
    t.dropColumn('secret_next_at');
    t.dropColumn('rotated_at');
  });
}
