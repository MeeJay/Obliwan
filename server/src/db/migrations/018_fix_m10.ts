import type { Knex } from 'knex';

/**
 * 018_fix_m10.ts — the storage half of one M10 audit finding.
 *
 * ┌─ WHY `cwmp_tasks.fault` NEEDED THE SAME CHECK AS `cwmp_tasks.payload` ────┐
 * │ Migration 015 put a constraint on `payload` — no JSON key literally named │
 * │ like a credential — because that is the shape a writer produces when they │
 * │ take the obvious shortcut. `fault` got nothing, and `fault` turned out to │
 * │ be the column a secret actually reached:                                  │
 * │                                                                          │
 * │  1. `serialiseTask` decrypts a `secretRef` on the way to the socket;      │
 * │  2. firmware that refuses the value answers 9007 and REPEATS THE VALUE    │
 * │     in its FaultString (documented on DrayTek and on Zyxel alike);        │
 * │  3. `failTask` wrote that string into `cwmp_tasks.fault` verbatim;        │
 * │  4. `cwmp_tasks` has NO retention — `cwmp_rpc_log` is dropped at seven    │
 * │     days, this table is forever — and the column is served by             │
 * │     `GET /api/acs/devices/:id/tasks`.                                     │
 * │                                                                          │
 * │ The real fix is in the code (`redactFault` in `rpcLog.service.ts`, called │
 * │ by `handleCpeFault` before `failTask`). This is the floor under it, in    │
 * │ the same place and the same words as the one `payload` already had — so   │
 * │ that the next writer who forgets is refused by the database rather than   │
 * │ by a review.                                                              │
 * │                                                                          │
 * │ NOTE WHAT IT DOES AND DOES NOT CATCH. It catches a credential-shaped JSON │
 * │ KEY, exactly like its sibling on `payload`. It cannot catch a plaintext   │
 * │ sitting in a `faultString`, because no regular expression knows what a    │
 * │ customer's PPPoE password looks like — that is `redactFault`'s job, and   │
 * │ the constraint is not a substitute for it.                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function up(knex: Knex): Promise<void> {
  // Existing rows first: a constraint that cannot be added is a migration that
  // fails on the one deployment that has the problem. Any offending fault is
  // replaced with a marker that says what happened, because the alternative —
  // leaving it — is keeping the leak in order to keep the diagnostic.
  await knex.raw(
    `UPDATE cwmp_tasks
        SET fault = jsonb_build_object(
              'faultCode', coalesce(fault->>'faultCode', 'Client'),
              'code', coalesce(fault->>'code', '9002'),
              'faultString', '***REDACTED*** (rewritten by migration 018)')
      WHERE fault IS NOT NULL
        AND fault::text ~* '"(password|passphrase|presharedkey|privatekey)"\s*:'`,
  );

  await knex.schema.raw(
    'ALTER TABLE cwmp_tasks ADD CONSTRAINT cwmp_tasks_fault_no_secret_chk ' +
      "CHECK (fault::text !~* '\"(password|passphrase|presharedkey|privatekey)\"\s*:')",
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw(
    'ALTER TABLE cwmp_tasks DROP CONSTRAINT IF EXISTS cwmp_tasks_fault_no_secret_chk',
  );
}
