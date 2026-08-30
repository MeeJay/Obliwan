import { db } from '../db';
import type { PermissionLevel, UserPermissions, Capability } from '@obliwan/shared';
import {
  ALL_CAPABILITIES,
  expandCapabilities,
  CAPABILITIES,
  BUILTIN_PERMISSION_SETS,
  sanitizeCapabilities,
} from '@obliwan/shared';

/**
 * Team-based authorisation over the `device_groups` tree, plus the capability
 * resolver the RBAC middleware is built on.
 *
 * ── AUDIT-SEC #1 (CRITIQUE) ────────────────────────────────────────────────
 * `getUserCapabilities` used to do this:
 *
 *     if (membership) { for (const c of ALL_CAPABILITIES) held.add(c); }
 *
 * i.e. *belonging* to a tenant granted all 27 capabilities, `secret.read` and
 * `credential.manage` included. `requireCapability()` calls exactly this
 * function, so every capability gate in the application was a no-op for any
 * tenant member, and `permission_sets` / pinned capabilities existed for
 * nothing. Capabilities are now DERIVED FROM AN EXPLICIT MATRIX (below) and
 * unioned with capabilities granted by name.
 *
 * ── AUDIT-SEC #3 (CRITIQUE) ────────────────────────────────────────────────
 * `getGroupPermission` read `device_groups` by id with no `where tenant_id`
 * and returned 'ro' for any `is_general` group. Since every tenant owns
 * general groups, `GET /api/groups/<id>` walked the whole id space of every
 * customer. Tenant scoping is now the FIRST thing every entry point does, and
 * `_getGroupPermissionViaClosure` refuses to inherit through an ancestor that
 * belongs to another tenant, so a forged `group_closure` edge grants nothing.
 */

// ──────────────────────────────────────────────────────────────────────────
// Capability derivation
// ──────────────────────────────────────────────────────────────────────────

/**
 * Capabilities a ROLE may never confer. They are granted BY NAME or not at
 * all — pinned on a team grant by a local admin, or asserted per-user by
 * Obligate (`user_tenant_capabilities`).
 *
 * `secret.read` reveals a device administration password in clear.
 * `credential.manage` rotates and deletes the vault entries holding them.
 * Neither is a consequence of "being a member", nor of "being the admin of a
 * tenant": both are a deliberate, nameable act by whoever runs the platform.
 */
export const NEVER_ROLE_DERIVED: readonly Capability[] = [
  CAPABILITIES.SECRET_READ,
  CAPABILITIES.CREDENTIAL_MANAGE,
];

function builtinSet(slug: 'viewer' | 'operator' | 'engineer'): Capability[] {
  const set = BUILTIN_PERMISSION_SETS.find((s) => s.slug === slug);
  // BUILTIN_PERMISSION_SETS is a compile-time constant in @obliwan/shared; a
  // miss here means the vocabulary was renamed without updating this matrix,
  // and failing loudly at boot beats silently granting nothing (or worse,
  // silently granting everything, which is the defect being fixed).
  if (!set) throw new Error('BUILTIN_PERMISSION_SETS is missing the set: ' + slug);
  return [...set.capabilities];
}

function withoutNeverDerived(caps: Capability[]): Capability[] {
  const banned = new Set<string>(NEVER_ROLE_DERIVED);
  return caps.filter((c) => !banned.has(c));
}

/**
 * `user_tenants.role` → capabilities. The CHECK constraint on that column
 * (migration 001) guarantees only these two values can exist.
 *
 * DIVERGENCE from the audit's suggested `admin: ALL_CAPABILITIES minus
 * SECRET_READ`, in two places, both deliberate:
 *
 *  - `credential.manage` is excluded too (see NEVER_ROLE_DERIVED). Rotating a
 *    fleet credential is not something one inherits by being made admin of a
 *    tenant in a dropdown.
 *  - `tenants.manage` is excluded. It creates, edits and DELETES tenants and
 *    their memberships — a platform act, not a tenant-local one. A tenant
 *    admin holding it could add themselves to another customer's tenant, which
 *    would hand back, through the RBAC layer, exactly the cross-tenant access
 *    the rest of this file is closing. Platform admins (`users.role='admin'`)
 *    keep it, and they are the only ones who ever needed it: every /api/tenants
 *    route is behind requireRole('admin').
 */
export const TENANT_ROLE_CAPABILITIES: Record<'admin' | 'member', Capability[]> = {
  // Tenant admin = network engineer + the tenant-local administration domain.
  admin: withoutNeverDerived([
    ...builtinSet('engineer'),
    CAPABILITIES.GROUP_WRITE,
    CAPABILITIES.USERS_MANAGE,
    CAPABILITIES.SETTINGS_MANAGE,
    CAPABILITIES.NOTIFICATIONS_MANAGE,
    CAPABILITIES.AUDIT_READ,
    CAPABILITIES.EXPORT_RUN,
    CAPABILITIES.IMPORT_RUN,
    CAPABILITIES.CHANGE_APPROVE,
    CAPABILITIES.ACS_ADMIN,
  ]),
  // Plain member = the seeded `operator` set, verbatim. Read plus day-to-day
  // fleet work: no template authoring, no change.apply, no admin domain.
  member: withoutNeverDerived(builtinSet('operator')),
};

// ──────────────────────────────────────────────────────────────────────────

interface GroupScopeRow {
  is_general: boolean;
  tenant_id: number;
}

/**
 * Cross-tenant reads are legitimate ONLY for a caller the middleware has
 * positively established as a member of the master tenant (AUDIT-SEC #2).
 * Never derive `masterView` from `req.session.currentTenantId` alone.
 */
export interface TenantScope {
  tenantId: number;
  /** Set by `requireTenant` after a real `user_tenants` lookup. */
  masterView?: boolean;
}

export const permissionService = {
  /**
   * Get all team IDs a user belongs to.
   *
   * `tenantId` is optional ONLY because `UserPermissions.teams` is a display
   * list. Every authorisation decision must pass it.
   */
  async getUserTeamIds(userId: number, tenantId?: number): Promise<number[]> {
    const q = db('team_memberships')
      .where('team_memberships.user_id', userId)
      .select('team_memberships.team_id');
    if (tenantId != null) {
      q.join('user_teams', 'user_teams.id', 'team_memberships.team_id')
        .where('user_teams.tenant_id', tenantId);
    }
    const rows = await q;
    return rows.map((r) => r.team_id as number);
  },

  /**
   * Check if user (via any of their teams IN THIS TENANT) has canCreate.
   */
  async canCreate(userId: number, isAdmin: boolean, tenantId?: number): Promise<boolean> {
    if (isAdmin) return true;
    const q = db('user_teams')
      .join('team_memberships', 'user_teams.id', 'team_memberships.team_id')
      .where('team_memberships.user_id', userId)
      .where('user_teams.can_create', true);
    if (tenantId != null) q.where('user_teams.tenant_id', tenantId);
    const row = await q.first();
    return !!row;
  },

  /**
   * Effective permission for a user on a group, within a tenant.
   * Direct grants plus anything inherited from an ancestor via the closure
   * table — never across a tenant boundary.
   */
  async getGroupPermission(
    userId: number,
    groupId: number,
    isAdmin: boolean,
    scope: TenantScope,
  ): Promise<PermissionLevel | null> {
    const group = await db('device_groups')
      .where({ id: groupId })
      .first<GroupScopeRow | undefined>('is_general', 'tenant_id');
    if (!group) return null;

    // AUDIT-SEC #3 — short-circuit BEFORE anything else, `is_general` included.
    // A group of another tenant is not "readable but not writable": it does
    // not exist as far as this caller is concerned.
    if (group.tenant_id !== scope.tenantId && scope.masterView !== true) return null;

    // Platform admin. Checked AFTER the tenant gate so an admin positioned on
    // tenant B cannot follow a stale link into tenant A's tree unless the
    // master-tenant view has been explicitly established by the middleware.
    if (isAdmin) return 'rw';

    if (group.is_general) {
      const level = await this._getGroupPermissionViaClosure(userId, groupId, group.tenant_id);
      return level ?? 'ro';
    }

    return this._getGroupPermissionViaClosure(userId, groupId, group.tenant_id);
  },

  async canReadGroup(
    userId: number,
    groupId: number,
    isAdmin: boolean,
    scope: TenantScope,
  ): Promise<boolean> {
    const perm = await this.getGroupPermission(userId, groupId, isAdmin, scope);
    return perm !== null;
  },

  async canWriteGroup(
    userId: number,
    groupId: number,
    isAdmin: boolean,
    scope: TenantScope,
  ): Promise<boolean> {
    const perm = await this.getGroupPermission(userId, groupId, isAdmin, scope);
    return perm === 'rw';
  },

  /**
   * All group IDs visible to a user IN THIS TENANT: groups they hold a grant
   * on, every descendant of those, every ancestor (so the tree can be
   * navigated down to them), and this tenant's general groups. 'all' for
   * platform admins.
   */
  async getVisibleGroupIds(
    userId: number,
    isAdmin: boolean,
    scope: TenantScope,
  ): Promise<number[] | 'all'> {
    if (isAdmin) return 'all';

    // A master-tenant member legitimately sees every tenant's tree; everyone
    // else is confined to theirs. `is_general` used to be read unfiltered.
    const generalQ = db('device_groups').where({ is_general: true }).select('id');
    if (scope.masterView !== true) generalQ.where('tenant_id', scope.tenantId);
    const generalRows = await generalQ;
    const generalIds: number[] = generalRows.map((r) => r.id as number);

    const teamIds = await this.getUserTeamIds(
      userId,
      scope.masterView === true ? undefined : scope.tenantId,
    );
    if (teamIds.length === 0) return generalIds;

    // Groups with a direct grant. Joined onto device_groups so a grant that
    // points at another tenant's group (stale row, hand-edited import) is
    // dropped here rather than expanded into a whole visible subtree.
    const permQ = db('team_permissions')
      .join('device_groups', 'device_groups.id', 'team_permissions.scope_id')
      .whereIn('team_permissions.team_id', teamIds)
      .where('team_permissions.scope', 'group')
      .select('team_permissions.scope_id');
    if (scope.masterView !== true) permQ.where('device_groups.tenant_id', scope.tenantId);
    const groupPerms = await permQ;
    const permGroupIds: number[] = groupPerms.map((r) => r.scope_id as number);

    const ids = new Set<number>(generalIds);
    if (permGroupIds.length > 0) {
      // Descendants (a grant on a group covers its whole subtree) and
      // ancestors (so the UI can render the path down to a granted group).
      // Both sides are re-joined onto device_groups and filtered by tenant:
      // AUDIT-SEC #9 showed a closure edge can straddle two tenants.
      const descQ = db('group_closure')
        .join('device_groups', 'device_groups.id', 'group_closure.descendant_id')
        .whereIn('group_closure.ancestor_id', permGroupIds)
        .select('group_closure.descendant_id');
      const ancQ = db('group_closure')
        .join('device_groups', 'device_groups.id', 'group_closure.ancestor_id')
        .whereIn('group_closure.descendant_id', permGroupIds)
        .select('group_closure.ancestor_id');
      if (scope.masterView !== true) {
        descQ.where('device_groups.tenant_id', scope.tenantId);
        ancQ.where('device_groups.tenant_id', scope.tenantId);
      }
      for (const r of await descQ) ids.add(r.descendant_id as number);
      for (const r of await ancQ) ids.add(r.ancestor_id as number);
    }

    return [...ids];
  },

  /**
   * Build the full UserPermissions object for the current user.
   * Sent to the client on login/session check so the UI can adapt.
   */
  async getUserPermissions(
    userId: number,
    isAdmin: boolean,
    tenantId?: number,
  ): Promise<UserPermissions> {
    if (isAdmin) {
      return { canCreate: true, teams: [], permissions: {}, capabilities: [...ALL_CAPABILITIES] };
    }

    // VERIF-SECFIX R3 — `getUserCapabilities` already returned [] without a
    // tenant, but the `permissions` map and the `teams` list built above it were
    // only filtered `if (tenantId != null)`, and `getUserTeamIds(userId,
    // undefined)` returns the teams of EVERY tenant. Reproduced: a user whose
    // memberships had just been revoked reconnected and `GET /api/auth/me`
    // handed back `teams:[1,2]` and `permissions:{"group:1":"rw","group:2":"rw"}`
    // — group 1 in Globex, group 2 in Acme — while `GET /api/groups` answered
    // 403. Ids only, and every read behind them 404s, but this is precisely the
    // class of defect the capability fix removed and left standing here.
    //
    // No tenant means no scope, and no scope means no authorisation of any kind.
    if (tenantId == null) {
      return { canCreate: false, teams: [], permissions: {}, capabilities: [] };
    }

    const teamIds = await this.getUserTeamIds(userId, tenantId);
    const canCreate = await this.canCreate(userId, false, tenantId);

    // AUDIT-CORR §6.2 / §5.3 — the server authorises through the closure
    // (a grant on an ancestor covers the whole subtree) but this map used to
    // list only DIRECT grants, so the UI hid the edit button on every
    // descendant of a granted group and refused drag-and-drop on rows the API
    // would have accepted. Each grant is expanded over its descendants here:
    // the key format (`group:<id>`) does not change, so no client edit is
    // needed.
    const permissions: Record<string, PermissionLevel> = {};
    if (teamIds.length > 0) {
      const perms = await db('team_permissions')
        .whereIn('team_id', teamIds)
        .select('scope', 'scope_id', 'level');

      const bump = (key: string, level: PermissionLevel) => {
        const existing = permissions[key];
        if (!existing || (existing === 'ro' && level === 'rw')) permissions[key] = level;
      };

      const groupGrantIds = perms
        .filter((p) => p.scope === 'group')
        .map((p) => p.scope_id as number);
      const descendantsByAncestor = new Map<number, number[]>();
      if (groupGrantIds.length > 0) {
        const rowsQ = db('group_closure')
          .join('device_groups', 'device_groups.id', 'group_closure.descendant_id')
          .whereIn('group_closure.ancestor_id', groupGrantIds)
          .select('group_closure.ancestor_id', 'group_closure.descendant_id');
        if (tenantId != null) rowsQ.where('device_groups.tenant_id', tenantId);
        for (const r of await rowsQ) {
          const anc = r.ancestor_id as number;
          const list = descendantsByAncestor.get(anc);
          if (list) list.push(r.descendant_id as number);
          else descendantsByAncestor.set(anc, [r.descendant_id as number]);
        }
      }

      for (const p of perms) {
        if (p.scope === 'group') {
          // The closure always contains (id, id, 0), so the granted group
          // itself is in this list — unless the row is corrupt (§2.2), or the
          // grant points outside the tenant, in which case dropping it is the
          // correct outcome.
          for (const descId of descendantsByAncestor.get(p.scope_id as number) ?? []) {
            bump('group:' + descId, p.level as PermissionLevel);
          }
        } else {
          bump(p.scope + ':' + p.scope_id, p.level as PermissionLevel);
        }
      }
    }

    const capabilities = await this.getUserCapabilities(userId, false, tenantId);

    return { canCreate, teams: teamIds, permissions, capabilities };
  },

  /**
   * Resolve the feature capabilities a user effectively holds for a tenant.
   *
   * Three sources, unioned:
   *   1. the `user_tenants.role` → capability MATRIX above (never `secret.read`
   *      nor `credential.manage`);
   *   2. capabilities pinned onto `team_permissions` rows of the user's teams
   *      IN THIS TENANT (a by-name grant from a local admin);
   *   3. `user_tenant_capabilities` — the per-(user, tenant) list asserted by
   *      Obligate (migration 003, AUDIT-SEC #4).
   *
   * `isAdmin` here means PLATFORM admin (`users.role = 'admin'`), which is a
   * different column from `user_tenants.role`; `requireRole('admin')` reads the
   * same one. A tenant admin goes through the matrix like everybody else.
   *
   * Without a tenant there is no capability at all. The old code fell back to
   * "whatever is pinned on any of your teams, in any tenant", which handed a
   * user their tenant-A capabilities while they operated on tenant B.
   */
  async getUserCapabilities(
    userId: number,
    isAdmin: boolean,
    tenantId?: number,
  ): Promise<Capability[]> {
    if (isAdmin) return [...ALL_CAPABILITIES];
    if (tenantId == null) return [];

    const held = new Set<string>();

    // 1. Tenant role matrix.
    const membership = await db('user_tenants')
      .where({ user_id: userId, tenant_id: tenantId })
      .first<{ role: string } | undefined>('role');
    if (!membership) return []; // not a member of this tenant: nothing at all.
    const roleCaps = TENANT_ROLE_CAPABILITIES[membership.role === 'admin' ? 'admin' : 'member'];
    for (const c of roleCaps) held.add(c);

    // 2. Capabilities pinned onto this tenant's team grants.
    const teamIds = await this.getUserTeamIds(userId, tenantId);
    if (teamIds.length > 0) {
      const rows = await db('team_permissions')
        .whereIn('team_id', teamIds)
        .whereNotNull('capabilities')
        .select('capabilities');
      for (const r of rows) {
        for (const c of this._parseCapabilities((r as { capabilities: unknown }).capabilities)) {
          held.add(c);
        }
      }
    }

    // 3. Federated per-user capabilities (Obligate assertion).
    const fed = await db('user_tenant_capabilities')
      .where({ user_id: userId, tenant_id: tenantId })
      .first<{ capabilities: unknown } | undefined>('capabilities');
    if (fed) for (const c of this._parseCapabilities(fed.capabilities)) held.add(c);

    // Only surface capabilities we actually recognise and enforce, then close the
    // set under CAPABILITY_IMPLIES. The expansion happens HERE — at resolution —
    // and never at storage: a grant stays exactly what an administrator typed.
    // Without it, a hand-made set with CHANGE_APPLY and no PLAN_CREATE can queue
    // a change and then read neither the job, nor its steps, nor the kill switch.
    return expandCapabilities(ALL_CAPABILITIES.filter((c) => held.has(c)));
  },

  // -- Private helpers --

  /** Parse + sanitise a jsonb capability column (string or already parsed). */
  _parseCapabilities(raw: unknown): Capability[] {
    let arr: unknown;
    try {
      arr = typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch {
      return [];
    }
    // Never trust a persisted or federated list blindly.
    return Array.isArray(arr) ? sanitizeCapabilities(arr) : [];
  },

  /**
   * Highest group permission for a user on a group, considering every ancestor
   * through the closure table — but only ancestors that live in `tenantId`,
   * and only grants held by a team of that same tenant.
   *
   * The tenant joins are the applicative half of AUDIT-SEC #9: migration 001
   * now makes a cross-tenant `parent_id` impossible, yet `group_closure`
   * carries no such constraint, so an edge inserted by an older build (or
   * directly in SQL) could still hand tenant A's teams a grant over tenant B's
   * group. Reading through it stops here.
   */
  async _getGroupPermissionViaClosure(
    userId: number,
    groupId: number,
    tenantId: number,
  ): Promise<PermissionLevel | null> {
    const rows = await db('team_permissions')
      .join('team_memberships', 'team_permissions.team_id', 'team_memberships.team_id')
      .join('user_teams', 'user_teams.id', 'team_permissions.team_id')
      .join('group_closure', 'group_closure.ancestor_id', 'team_permissions.scope_id')
      .join('device_groups', 'device_groups.id', 'group_closure.ancestor_id')
      .where('team_memberships.user_id', userId)
      .where('team_permissions.scope', 'group')
      .where('group_closure.descendant_id', groupId)
      .where('device_groups.tenant_id', tenantId)
      .where('user_teams.tenant_id', tenantId)
      .select('team_permissions.level');

    if (rows.length === 0) return null;
    return rows.some((r) => r.level === 'rw') ? 'rw' : 'ro';
  },

  _highest(a: PermissionLevel | null, b: PermissionLevel | null): PermissionLevel | null {
    if (a === 'rw' || b === 'rw') return 'rw';
    if (a === 'ro' || b === 'ro') return 'ro';
    return null;
  },
};
