import type { Knex } from 'knex';
import bcrypt from 'bcrypt';
import { MASTER_TENANT_ID } from '@obliwan/shared';

/**
 * 001_bootstrap.ts — the two rows without which nobody can log in.
 *
 * Idempotent on purpose: `knex seed:run` is safe to re-run, and the same logic
 * is mirrored by `authService.ensureDefaultAdmin()` at boot so a fresh
 * `docker compose up` works without a manual seed step.
 *
 * The admin password is READ FROM THE ENVIRONMENT and never hard-coded here.
 */
export async function seed(knex: Knex): Promise<void> {
  // --- Master tenant (id 1) -------------------------------------------------
  // Normally already inserted by migration 001; re-asserted for the case where
  // an operator deleted it by hand.
  const master = await knex('tenants').where({ id: MASTER_TENANT_ID }).first();
  if (!master) {
    await knex('tenants').insert({ id: MASTER_TENANT_ID, name: 'Default', slug: 'default' });
    await knex.raw(
      "SELECT setval(pg_get_serial_sequence('tenants', 'id'), (SELECT MAX(id) FROM tenants))",
    );
  }

  // --- Default administrator ------------------------------------------------
  // Skipped as soon as ANY admin exists, so the seed can never resurrect a
  // deliberately deleted default account or reset a changed password.
  const existingAdmin = await knex('users').where({ role: 'admin' }).first();
  if (existingAdmin) return;

  const username = process.env.DEFAULT_ADMIN_USERNAME || 'admin';
  const password = process.env.DEFAULT_ADMIN_PASSWORD || 'admin123';
  const passwordHash = await bcrypt.hash(password, 12);

  const [admin] = await knex('users')
    .insert({
      username,
      password_hash: passwordHash,
      display_name: 'Administrator',
      role: 'admin',
      is_active: true,
    })
    .returning('id') as Array<{ id: number }>;

  await knex('user_tenants')
    .insert({ user_id: admin.id, tenant_id: MASTER_TENANT_ID, role: 'admin' })
    .onConflict(['user_id', 'tenant_id'])
    .ignore();
}
