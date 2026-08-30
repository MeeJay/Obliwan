import { db } from '../db';
import { hashPassword } from '../utils/crypto';
import type { User, UserRole, UserTenantAssignment } from '@obliwan/shared';
import { destroyUserSessions } from '../utils/sessions';

interface UserRow {
  id: number;
  username: string;
  password_hash: string;
  display_name: string | null;
  role: string;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
  foreign_source: string | null;
  preferred_language: string | null;
  enrollment_version: number | null;
}

/**
 * AUDIT-CORR §5.4 — `preferredLanguage` and `enrollmentVersion` used to be
 * HARD-CODED to 'en' and 0 here, while `authService.rowToUser` read the same
 * two columns correctly. `/api/auth/me` was therefore right and `/api/users`
 * was wrong for 100% of rows: the admin screen showed every user as English
 * and as never having finished enrolment, which invites a pointless re-enrol.
 */
function rowToUser(row: UserRow): User {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    role: row.role as UserRole,
    isActive: row.is_active,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
    preferredLanguage: row.preferred_language ?? 'en',
    enrollmentVersion: row.enrollment_version ?? 0,
    foreignSource: row.foreign_source ?? null,
  };
}

export const userService = {
  async getAll(): Promise<User[]> {
    const rows = await db<UserRow>('users').orderBy('username');
    return rows.map(rowToUser);
  },

  async getById(id: number): Promise<User | null> {
    const row = await db<UserRow>('users').where({ id }).first();
    return row ? rowToUser(row) : null;
  },

  async create(data: {
    username: string;
    password: string;
    displayName?: string | null;
    role?: UserRole;
  }): Promise<User> {
    const passwordHash = await hashPassword(data.password);

    const [row] = await db<UserRow>('users')
      .insert({
        username: data.username,
        password_hash: passwordHash,
        display_name: data.displayName || null,
        role: data.role || 'user',
      })
      .returning('*');

    return rowToUser(row);
  },

  async update(id: number, data: {
    username?: string;
    displayName?: string | null;
    role?: UserRole;
    isActive?: boolean;
  }): Promise<User | null> {
    const updateData: Record<string, unknown> = { updated_at: new Date() };
    if (data.username !== undefined) updateData.username = data.username;
    if (data.displayName !== undefined) updateData.display_name = data.displayName;
    if (data.role !== undefined) updateData.role = data.role;
    if (data.isActive !== undefined) updateData.is_active = data.isActive;

    const [row] = await db<UserRow>('users')
      .where({ id })
      .update(updateData)
      .returning('*');

    // AUDIT-SEC #6 — a demotion (`role: 'user'`) or a deactivation
    // (`isActive: false`) must not wait for the 7-day cookie: the session still
    // carries `role: 'admin'`, which is what requireRole and requireCapability
    // read. requireAuth re-reads the row within 10 s; this closes the gap.
    if (row && (data.role !== undefined || data.isActive !== undefined)) {
      await destroyUserSessions(id);
    }

    return row ? rowToUser(row) : null;
  },

  async changePassword(id: number, newPassword: string): Promise<boolean> {
    const passwordHash = await hashPassword(newPassword);
    const count = await db('users')
      .where({ id })
      .update({ password_hash: passwordHash, updated_at: new Date() });
    // A password change is also a revocation gesture: whoever knew the old one
    // must not keep a live session.
    if (count > 0) await destroyUserSessions(id);
    return count > 0;
  },

  async delete(id: number): Promise<boolean> {
    const count = await db('users').where({ id }).del();
    if (count > 0) await destroyUserSessions(id);
    return count > 0;
  },

  /** Returns all tenants with this user's membership status and role. */
  async getUserTenantAssignments(userId: number): Promise<UserTenantAssignment[]> {
    const rows = await db('tenants as t')
      .leftJoin('user_tenants as ut', function () {
        this.on('ut.tenant_id', '=', 't.id').andOnVal('ut.user_id', '=', userId);
      })
      .select(
        't.id as tenantId',
        't.name as tenantName',
        't.slug as tenantSlug',
        db.raw('(ut.user_id IS NOT NULL) as is_member'),
        db.raw("COALESCE(ut.role, 'member') as role"),
      )
      .orderBy('t.name');

    return rows.map((r) => ({
      tenantId: r.tenantId,
      tenantName: r.tenantName,
      tenantSlug: r.tenantSlug,
      isMember: Boolean(r.is_member),
      role: r.role as 'admin' | 'member',
    }));
  },

  /**
   * Bulk-replaces all tenant memberships for a user.
   *
   * AUDIT-SEC #2 + #6 — the two defects met here. Calling this with
   * `{assignments: []}` used to REMOVE every membership while leaving the
   * user's live sessions untouched, and their next login then resolved
   * `currentTenantId = 1` through the `?? 1` fallback: revoking all access
   * promoted the account to the god view. The fallback is gone (auth.controller)
   * and the sessions are now revoked here.
   */
  async setUserTenantAssignments(
    userId: number,
    assignments: { tenantId: number; role: 'admin' | 'member' }[],
  ): Promise<void> {
    await db.transaction(async (trx) => {
      await trx('user_tenants').where({ user_id: userId }).del();
      if (assignments.length > 0) {
        await trx('user_tenants').insert(
          assignments.map((a) => ({
            user_id: userId,
            tenant_id: a.tenantId,
            role: a.role,
            created_at: new Date(),
          })),
        );
      }
    });
    await destroyUserSessions(userId);
  },
};
