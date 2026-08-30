import type { Knex } from 'knex';

/**
 * 003_rbac.ts — federated capabilities get their own table.
 *
 * AUDIT-SEC #4 (MAJEUR). The Obligate SSO callback used to persist the
 * capability list asserted for ONE user by writing it onto every
 * `team_permissions` row of every team that user belongs to:
 *
 *     for (const teamId of userTeamIds)
 *       await db('team_permissions').where({ team_id: teamId })
 *         .update({ capabilities: JSON.stringify(t.capabilities) });
 *
 * `team_permissions` is keyed by TEAM, not by user. Three consequences, all
 * observed in the audit scenario:
 *
 *  1. Alice's `secret.read` landed on the NOC team grant, so Bob — read-only by
 *     design, in the same team — held `secret.read` on his next login.
 *  2. The write was an overwrite, not a merge, so the effective capability set
 *     of a whole team became "whatever the last person to log in was granted".
 *  3. The value was written WITHOUT sanitizeCapabilities, so a third-party
 *     system could persist arbitrary strings into our authorisation table.
 *
 * The fix needs a per-(user, tenant) home for federated capabilities, which is
 * exactly what the assertion carries: `assertion.tenants[].capabilities`.
 *
 * `team_permissions.capabilities` is NOT dropped: it keeps its documented
 * meaning (a capability pinned onto a specific group grant, by a local admin).
 * It simply stops being the SSO dumping ground.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('user_tenant_capabilities', (t) => {
    t.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    // Sanitised at every write (sanitizeCapabilities) AND at every read, so a
    // vocabulary that disappears in a later release cannot resurrect a
    // capability the code no longer knows how to enforce.
    t.jsonb('capabilities').notNullable().defaultTo('[]');
    // Provenance: 'obligate' today. A local admin grant would carry 'local'.
    t.string('source', 32).notNullable().defaultTo('obligate');
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    t.primary(['user_id', 'tenant_id']);
    // getUserCapabilities always looks up (user_id, tenant_id) — the PK covers
    // it. This index serves the reverse direction: "who holds federated
    // capabilities on this tenant", used when a tenant is being decommissioned.
    t.index('tenant_id');
  });

  // ── Clean up what the defect already wrote ────────────────────────────────
  // Every capability list currently sitting on a team_permissions row was put
  // there by the SSO callback (nothing else writes that column in M1: verified
  // by grep over the whole server tree). Leaving them would mean the security
  // fix changes nothing for an instance that has already seen one SSO login —
  // Bob would keep holding Alice's `secret.read`. They are not migrated into
  // the new table either: we cannot tell WHOSE capabilities they were, and
  // guessing here would re-create the very leak this migration removes. The
  // next SSO login of each user repopulates user_tenant_capabilities correctly.
  await knex('team_permissions').whereNotNull('capabilities').update({ capabilities: null });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('user_tenant_capabilities');
}
