import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import type { UserTeam, TeamPermission } from '@obliwan/shared';

interface TeamRow {
  id: number;
  name: string;
  description: string | null;
  can_create: boolean;
  tenant_id: number;
  tenant_name?: string; // populated by JOIN when fetching all tenants
  created_at: Date;
  updated_at: Date;
}

interface PermissionRow {
  id: number;
  team_id: number;
  scope: 'group' | 'device';
  scope_id: number;
  level: 'ro' | 'rw';
}

function rowToTeam(row: TeamRow): UserTeam {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    canCreate: row.can_create,
    tenantId: row.tenant_id,
    tenantName: row.tenant_name,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

function rowToPermission(row: PermissionRow): TeamPermission {
  return {
    id: row.id,
    teamId: row.team_id,
    scope: row.scope,
    scopeId: row.scope_id,
    level: row.level,
  };
}

export const teamService = {
  /**
   * Returns teams scoped to a tenant.
   * If tenantId is null (platform admin cross-tenant view), returns ALL teams across
   * all tenants, joined with tenant name.
   */
  async getAll(tenantId: number | null): Promise<UserTeam[]> {
    const query = db('user_teams')
      .join('tenants', 'user_teams.tenant_id', 'tenants.id')
      .select('user_teams.*', 'tenants.name as tenant_name')
      .orderBy('user_teams.name');
    // AUDIT-SEC #2 — the filter used to be dropped as soon as
    // isMasterTenant(tenantId) was true, i.e. for any session merely carrying
    // currentTenantId = 1, which the "?? 1" fallback handed to every user with
    // no tenant at all. Cross-tenant listing is now the explicit null argument,
    // which teamsController only passes for a platform admin who asked for it
    // (?scope=all).
    if (tenantId !== null) {
      query.where('user_teams.tenant_id', tenantId);
    }
    const rows = await query;
    return rows.map(rowToTeam);
  },

  /**
   * VERIF-SECFIX-AUTRES #13 — every accessor below took a bare id. `GET
   * /api/teams/:id` on a team of another tenant answered 200 with its name, its
   * members and its grants, while `GET /api/teams` refused to list it; `update`
   * and `delete` acted on it just as readily, and `removePermission` took a
   * `team_permissions` ROW id that was never confronted with anything at all —
   * the team id in `DELETE /api/teams/:id/permissions/:permId` was not even
   * read, so scanning permId 1..500 erased the grants of every tenant on the
   * instance, answering 200 each time.
   *
   * `tenantId` is mandatory across the whole surface now: a team is addressable
   * exactly where it is visible. Absent and foreign produce the same answer, so
   * there is no existence oracle either.
   */
  async getById(id: number, tenantId: number): Promise<UserTeam | null> {
    const row = await db<TeamRow>('user_teams').where({ id, tenant_id: tenantId }).first();
    return row ? rowToTeam(row) : null;
  },

  async create(data: { name: string; description?: string | null; canCreate?: boolean }, tenantId: number): Promise<UserTeam> {
    const [row] = await db<TeamRow>('user_teams')
      .insert({
        name: data.name,
        description: data.description ?? null,
        can_create: data.canCreate ?? false,
        tenant_id: tenantId,
      })
      .returning('*');
    return rowToTeam(row);
  },

  async update(
    id: number,
    data: { name?: string; description?: string | null; canCreate?: boolean },
    tenantId: number,
  ): Promise<UserTeam | null> {
    const updateData: Record<string, unknown> = { updated_at: new Date() };
    if (data.name !== undefined) updateData.name = data.name;
    if (data.description !== undefined) updateData.description = data.description;
    if (data.canCreate !== undefined) updateData.can_create = data.canCreate;

    const [row] = await db<TeamRow>('user_teams')
      .where({ id, tenant_id: tenantId })
      .update(updateData)
      .returning('*');
    return row ? rowToTeam(row) : null;
  },

  async delete(id: number, tenantId: number): Promise<boolean> {
    const count = await db('user_teams').where({ id, tenant_id: tenantId }).del();
    return count > 0;
  },

  // ── Members ──

  /** null when the team does not belong to `tenantId` (or does not exist). */
  async getMembers(teamId: number, tenantId: number): Promise<number[] | null> {
    const team = await db('user_teams').where({ id: teamId, tenant_id: tenantId }).first('id');
    if (!team) return null;
    const rows = await db('team_memberships')
      .where({ team_id: teamId })
      .select('user_id');
    return rows.map((r) => r.user_id);
  },

  /**
   * Replace a team's membership list.
   *
   * VERIF-SECFIX-AUTRES #9 — neither `teamId` nor the `userIds` were ever
   * confronted with a tenant, while `GET /api/users` listed every account of
   * every customer without saying which tenant each came from. Two "J. Martin"
   * in the dropdown, the admin ticks the wrong one, and a `team_memberships`
   * row is written linking a Globex user to an Acme team. Nothing complains:
   * `getUserCapabilities` returns [] for that user on Acme (he has no
   * `user_tenants` row) and `GET /api/users/:id/teams` is tenant-scoped, so the
   * grant is invisible from BOTH sides — until someone runs
   * `POST /api/tenants/<acme>/members {userId}` months later for an unrelated
   * reason, at which point he silently inherits the team's grants, pinned
   * capabilities included.
   *
   * An authorisation write that references an entity of another tenant is
   * refused AT WRITE TIME, not merely neutralised at read time — the same rule
   * `assertScopeInTenant` applies to settings.
   *
   * Duplicate ids in the payload are collapsed: the previous version inserted
   * them verbatim and died on `team_memberships`'s unique key with a 500.
   */
  async setMembers(teamId: number, userIds: number[], tenantId: number): Promise<void> {
    const team = await db('user_teams').where({ id: teamId, tenant_id: tenantId }).first('id');
    if (!team) throw new AppError(404, 'Team not found');

    const wanted = [...new Set(userIds)];
    if (wanted.length > 0) {
      const eligible = await db('user_tenants')
        .where({ tenant_id: tenantId })
        .whereIn('user_id', wanted)
        .pluck<number[]>('user_id');
      const eligibleSet = new Set(eligible);
      const rejected = wanted.filter((u) => !eligibleSet.has(u));
      if (rejected.length > 0) {
        throw new AppError(
          400,
          `Not members of this tenant: ${rejected.join(', ')}. ` +
            'Grant them access to the tenant before adding them to one of its teams.',
        );
      }
    }

    await db.transaction(async (trx) => {
      await trx('team_memberships').where({ team_id: teamId }).del();
      if (wanted.length > 0) {
        await trx('team_memberships').insert(
          wanted.map((uid) => ({ team_id: teamId, user_id: uid })),
        );
      }
    });
  },

  /**
   * Teams a user belongs to. `tenantId` MUST be passed on every authorisation
   * path: `groupsController.create` used to grant RW on the new group to every
   * `can_create` team of the creator IN ANY TENANT, which handed a team of
   * tenant A a grant on a group of tenant B.
   */
  async getUserTeams(userId: number, tenantId?: number): Promise<UserTeam[]> {
    const q = db<TeamRow>('user_teams')
      .join('team_memberships', 'user_teams.id', 'team_memberships.team_id')
      .where('team_memberships.user_id', userId)
      .select('user_teams.*')
      .orderBy('user_teams.name');
    if (tenantId != null) q.where('user_teams.tenant_id', tenantId);
    const rows = await q;
    return rows.map(rowToTeam);
  },

  // ── Permissions ──

  /** null when the team does not belong to `tenantId` (or does not exist). */
  async getPermissions(teamId: number, tenantId: number): Promise<TeamPermission[] | null> {
    const team = await db('user_teams').where({ id: teamId, tenant_id: tenantId }).first('id');
    if (!team) return null;
    const rows = await db<PermissionRow>('team_permissions')
      .where({ team_id: teamId })
      .orderBy('scope')
      .orderBy('scope_id');
    return rows.map(rowToPermission);
  },

  /**
   * Replace a team's grants.
   *
   * AUDIT-CORR §5.1 — the delete/insert cycle dropped the `capabilities`
   * column: an admin who opened the team-permissions screen just to add a group
   * silently wiped every capability pinned onto that team's grants, on a field
   * no screen ever displays. The pinned lists are read back before the DELETE
   * and re-attached to the (scope, scope_id) pairs that survive the edit.
   */
  async setPermissions(
    teamId: number,
    permissions: Array<{ scope: 'group' | 'device'; scopeId: number; level: 'ro' | 'rw' }>,
    tenantId: number,
  ): Promise<TeamPermission[]> {
    await this._assertGrantTargetsInTenant(teamId, permissions, tenantId);
    return db.transaction(async (trx) => {
      const previous = await trx('team_permissions')
        .where({ team_id: teamId })
        .whereNotNull('capabilities')
        .select('scope', 'scope_id', 'capabilities');
      const pinned = new Map<string, unknown>(
        previous.map((p) => [`${p.scope}:${p.scope_id}`, p.capabilities]),
      );

      await trx('team_permissions').where({ team_id: teamId }).del();
      if (permissions.length > 0) {
        await trx('team_permissions').insert(
          permissions.map((p) => {
            const carried = pinned.get(`${p.scope}:${p.scopeId}`);
            return {
              team_id: teamId,
              scope: p.scope,
              scope_id: p.scopeId,
              level: p.level,
              // JSON.stringify only when the driver handed back a parsed value;
              // knex needs a string (or null) for a jsonb column.
              capabilities:
                carried === undefined || carried === null
                  ? null
                  : typeof carried === 'string'
                    ? carried
                    : JSON.stringify(carried),
            };
          }),
        );
      }
      const rows = await trx<PermissionRow>('team_permissions')
        .where({ team_id: teamId })
        .orderBy('scope')
        .orderBy('scope_id');
      return rows.map(rowToPermission);
    });
  },

  /**
   * VERIF-SECFIX-AUTRES #14 — `scopeId` was validated nowhere: a grant could
   * name a group (or, since migration 002, a device) of another tenant. Such a
   * row is inert on read — every resolution path joins `tenant_id` — but it is
   * carried by the export, re-materialised by an import elsewhere, and it makes
   * the team-permissions screen show a grant on an object the operator cannot
   * see. Refused at write time, like `assertScopeInTenant` does for settings.
   */
  async _assertGrantTargetsInTenant(
    teamId: number,
    permissions: Array<{ scope: 'group' | 'device'; scopeId: number }>,
    tenantId: number,
  ): Promise<void> {
    const team = await db('user_teams').where({ id: teamId, tenant_id: tenantId }).first('id');
    if (!team) throw new AppError(404, 'Team not found');
    if (permissions.length === 0) return;

    for (const [scope, table, label] of [
      ['group', 'device_groups', 'Group'],
      ['device', 'devices', 'Device'],
    ] as const) {
      const wanted = [...new Set(permissions.filter((p) => p.scope === scope).map((p) => p.scopeId))];
      if (wanted.length === 0) continue;
      const found = await db(table)
        .where({ tenant_id: tenantId })
        .whereIn('id', wanted)
        .pluck<number[]>('id');
      const foundSet = new Set(found);
      const missing = wanted.filter((id) => !foundSet.has(id));
      if (missing.length > 0) {
        throw new AppError(404, `${label} not found: ${missing.join(', ')}`);
      }
    }
  },

  async addPermission(
    teamId: number,
    scope: 'group' | 'device',
    scopeId: number,
    level: 'ro' | 'rw',
    tenantId: number,
  ): Promise<TeamPermission> {
    await this._assertGrantTargetsInTenant(teamId, [{ scope, scopeId }], tenantId);
    const [row] = await db<PermissionRow>('team_permissions')
      .insert({ team_id: teamId, scope, scope_id: scopeId, level })
      .onConflict(['team_id', 'scope', 'scope_id'])
      .merge({ level })
      .returning('*');
    return rowToPermission(row);
  },

  /**
   * The route is `DELETE /api/teams/:id/permissions/:permId`; `:id` is now
   * actually used, and both it and the row must belong to `tenantId`. The
   * previous version deleted by row id alone.
   */
  async removePermission(teamId: number, permissionId: number, tenantId: number): Promise<boolean> {
    const count = await db('team_permissions')
      .where({ id: permissionId, team_id: teamId })
      .whereIn('team_id', db('user_teams').select('id').where({ tenant_id: tenantId }))
      .del();
    return count > 0;
  },
};
