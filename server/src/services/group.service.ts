import type { Knex } from 'knex';
import { db } from '../db';
import type { DeviceGroup, GroupTreeNode } from '@obliwan/shared';
import { logger } from '../utils/logger';

interface GroupRow {
  id: number;
  name: string;
  slug: string;
  description: string | null;
  parent_id: number | null;
  sort_order: number;
  is_general: boolean;
  group_notifications: boolean;
  tenant_id: number;
  created_at: Date;
  updated_at: Date;
}

/** Raised when a parent group does not exist in the caller's tenant. */
export class CrossTenantParentError extends Error {
  constructor(message = 'Parent group not found in this tenant') {
    super(message);
    this.name = 'CrossTenantParentError';
  }
}

function rowToGroup(row: GroupRow): DeviceGroup {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    description: row.description,
    parentId: row.parent_id,
    sortOrder: row.sort_order,
    isGeneral: row.is_general,
    groupNotifications: row.group_notifications,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * AUDIT-CORR §1.8 — the probe used to sweep the WHOLE table, so a tenant got
 * `paris-1` because ANOTHER tenant already owned `paris`: one customer's URLs
 * and exports depended on another customer's content, and the export stopped
 * being reproducible. The unique constraint is `(tenant_id, slug)` since
 * migration 001, so the probe is scoped to match it.
 */
async function ensureUniqueSlug(
  exec: Knex | Knex.Transaction,
  tenantId: number,
  slug: string,
  excludeId?: number,
): Promise<string> {
  let candidate = slug;
  let i = 1;
  for (;;) {
    const q = exec('device_groups').where({ slug: candidate, tenant_id: tenantId });
    if (excludeId) q.whereNot({ id: excludeId });
    const exists = await q.first();
    if (!exists) return candidate;
    candidate = `${slug}-${i++}`;
  }
}

export const groupService = {
  /**
   * Groups of a tenant.
   *
   * AUDIT-SEC #2 — this used to drop the `where tenant_id` as soon as
   * `isMasterTenant(tenantId)` was true, i.e. for anybody whose session merely
   * carried `currentTenantId = 1`, which the `?? 1` fallback handed out to
   * every user with no tenant at all. The god view is now an explicit opt-in
   * that only `requireTenant` can justify (`req.masterView`), so a caller who
   * forgets the argument gets the SAFE behaviour.
   */
  async getAll(tenantId: number, options?: { crossTenant?: boolean }): Promise<DeviceGroup[]> {
    const q = db<GroupRow>('device_groups').orderBy('sort_order').orderBy('name');
    if (options?.crossTenant !== true) q.where({ tenant_id: tenantId });
    const rows = await q;
    return rows.map(rowToGroup);
  },

  /**
   * A group by id. `tenantId` is optional so the few tenant-agnostic callers
   * (integrity check, tests) keep working, but EVERY request path must pass it:
   * `groupsController.getById` used to call this with the id alone, which is
   * half of AUDIT-SEC #3.
   */
  async getById(id: number, tenantId?: number): Promise<DeviceGroup | null> {
    const q = db<GroupRow>('device_groups').where({ id });
    if (tenantId != null) q.andWhere({ tenant_id: tenantId });
    const row = await q.first();
    return row ? rowToGroup(row) : null;
  },

  /** Same as getById but keeps `tenant_id`, which rowToGroup deliberately hides. */
  async getTenantIdOf(id: number): Promise<number | null> {
    const row = await db('device_groups').where({ id }).first<{ tenant_id: number } | undefined>('tenant_id');
    return row ? row.tenant_id : null;
  },

  /**
   * Create a group and its closure rows.
   *
   * AUDIT-CORR §3.1 (CRITIQUE) — this used to run three separate implicit
   * transactions: INSERT the group, INSERT the self-closure row, INSERT the
   * ancestor rows. A crash between any two left a group that renders normally
   * in the sidebar (getTree reads `parent_id`) but is INVISIBLE to the closure,
   * which is the sole source of truth for settings inheritance and for group
   * permissions. The corruption is permanent and silent. One transaction now.
   *
   * AUDIT-SEC #9 / §3.3 — the parent is loaded `where { id, tenant_id }` INSIDE
   * the same transaction, so a parent from another tenant is refused with a
   * clean 400 rather than reaching the composite FK and surfacing as a 500.
   *
   * `grantRwToTeamIds` folds the controller's post-create grant loop into the
   * transaction: a failure there used to leave a group its creator could not
   * see (AUDIT-CORR §3.1, last paragraph).
   */
  async create(
    data: {
      name: string;
      description?: string | null;
      parentId?: number | null;
      sortOrder?: number;
      isGeneral?: boolean;
      groupNotifications?: boolean;
    },
    tenantId: number,
    options?: { grantRwToTeamIds?: number[] },
  ): Promise<DeviceGroup> {
    return db.transaction(async (trx) => {
      const parentId = data.parentId ?? null;
      if (parentId !== null) {
        const parent = await trx('device_groups')
          .where({ id: parentId, tenant_id: tenantId })
          .first('id');
        if (!parent) throw new CrossTenantParentError();
      }

      const slug = await ensureUniqueSlug(trx, tenantId, slugify(data.name));

      const [row] = await trx<GroupRow>('device_groups')
        .insert({
          name: data.name,
          slug,
          description: data.description ?? null,
          parent_id: parentId,
          sort_order: data.sortOrder ?? 0,
          is_general: data.isGeneral ?? false,
          group_notifications: data.groupNotifications ?? false,
          tenant_id: tenantId,
        })
        .returning('*');

      // Closure: self-reference (depth 0) …
      await trx('group_closure').insert({
        ancestor_id: row.id,
        descendant_id: row.id,
        depth: 0,
      });

      // … then copy the ancestor paths of the parent.
      if (parentId !== null) {
        await trx.raw(
          `INSERT INTO group_closure (ancestor_id, descendant_id, depth)
           SELECT gc.ancestor_id, ?, gc.depth + 1
           FROM group_closure gc
           WHERE gc.descendant_id = ?`,
          [row.id, parentId],
        );
      }

      for (const teamId of options?.grantRwToTeamIds ?? []) {
        await trx('team_permissions')
          .insert({ team_id: teamId, scope: 'group', scope_id: row.id, level: 'rw' })
          .onConflict(['team_id', 'scope', 'scope_id'])
          .merge({ level: 'rw' });
      }

      return rowToGroup(row);
    });
  },

  async update(
    id: number,
    data: {
      name?: string;
      description?: string | null;
      sortOrder?: number;
      isGeneral?: boolean;
      groupNotifications?: boolean;
    },
    tenantId: number,
  ): Promise<DeviceGroup | null> {
    const updateData: Record<string, unknown> = { updated_at: new Date() };

    if (data.name !== undefined) {
      updateData.name = data.name;
      updateData.slug = await ensureUniqueSlug(db, tenantId, slugify(data.name), id);
    }
    if (data.description !== undefined) updateData.description = data.description;
    if (data.sortOrder !== undefined) updateData.sort_order = data.sortOrder;
    if (data.isGeneral !== undefined) updateData.is_general = data.isGeneral;
    if (data.groupNotifications !== undefined) updateData.group_notifications = data.groupNotifications;

    const [row] = await db<GroupRow>('device_groups')
      .where({ id, tenant_id: tenantId })
      .update(updateData)
      .returning('*');

    return row ? rowToGroup(row) : null;
  },

  /**
   * Move a subtree under a new parent.
   *
   * AUDIT-CORR §3.1 (CRITIQUE) — the three steps (cut the outside links,
   * reconnect under the new parent, update `parent_id`) used to be three
   * independent transactions. A SIGTERM between the first and the third left
   * `parent_id` pointing at the OLD parent while the closure held no link at
   * all: the sidebar showed the original tree, the settings of the old parent
   * silently stopped applying to twelve subgroups, and every grant held on that
   * parent silently stopped covering them. One transaction now.
   *
   * AUDIT-SEC #9 — the new parent must belong to the same tenant.
   */
  async move(id: number, newParentId: number | null, tenantId: number): Promise<DeviceGroup | null> {
    return db.transaction(async (trx) => {
      const group = await trx<GroupRow>('device_groups')
        .where({ id, tenant_id: tenantId })
        .first();
      if (!group) return null;

      if (newParentId !== null) {
        const parent = await trx('device_groups')
          .where({ id: newParentId, tenant_id: tenantId })
          .first('id');
        if (!parent) throw new CrossTenantParentError();

        // Prevent a circular reference: newParentId must not be a descendant
        // of id. The depth-0 row makes this cover "move onto itself" too.
        const isDescendant = await trx('group_closure')
          .where({ ancestor_id: id, descendant_id: newParentId })
          .first();
        if (isDescendant) {
          throw new Error('Cannot move group into its own descendant');
        }
      }

      // All descendants of the subtree (including self).
      const subtreeIds = await trx('group_closure')
        .where({ ancestor_id: id })
        .select('descendant_id');
      const descIds = subtreeIds.map((r) => r.descendant_id as number);

      // Cut every closure entry whose ancestor is OUTSIDE the subtree but whose
      // descendant is INSIDE it — the links to the former parent chain.
      await trx('group_closure')
        .whereIn('descendant_id', descIds)
        .whereNotIn('ancestor_id', descIds)
        .del();

      // Reconnect: (every ancestor of newParent) × (every node of the subtree).
      if (newParentId !== null) {
        await trx.raw(
          `INSERT INTO group_closure (ancestor_id, descendant_id, depth)
           SELECT p.ancestor_id, s.descendant_id, p.depth + s.depth + 1
           FROM group_closure p
           CROSS JOIN group_closure s
           WHERE p.descendant_id = ?
             AND s.ancestor_id = ?`,
          [newParentId, id],
        );
      }

      const [row] = await trx<GroupRow>('device_groups')
        .where({ id })
        .update({ parent_id: newParentId, updated_at: new Date() })
        .returning('*');

      return row ? rowToGroup(row) : null;
    });
  },

  /**
   * Delete a group and everything under it.
   *
   * AUDIT-CORR §1.7 — `settings.scope_id` and `team_permissions.scope_id` are
   * polymorphic, so no FK can clean them up, and nothing did. The rows stayed
   * behind; a `pg_restore` or an environment rebuild that replays `setval` can
   * hand id 42 to a NEW group, which then inherits the overrides and the grants
   * of a group deleted six months earlier. The subtree is computed from the
   * closure BEFORE the delete and both tables are purged in the same
   * transaction.
   *
   * AUDIT-CORR §1.4 — the return value used to be `count > 0`, i.e. `true` for
   * "1 group deleted" no matter how many the CASCADE actually destroyed. It now
   * returns the real number of groups removed, so a caller can tell the user.
   */
  async delete(id: number, tenantId: number): Promise<number> {
    return db.transaction(async (trx) => {
      const target = await trx('device_groups')
        .where({ id, tenant_id: tenantId })
        .first('id');
      if (!target) return 0;

      const subtree = await trx('group_closure')
        .where({ ancestor_id: id })
        .pluck('descendant_id') as number[];
      const ids = subtree.length > 0 ? subtree : [id];

      await trx('settings')
        .where({ scope: 'group', tenant_id: tenantId })
        .whereIn('scope_id', ids)
        .del();
      await trx('team_permissions')
        .where({ scope: 'group' })
        .whereIn('scope_id', ids)
        .del();

      // ON DELETE CASCADE on device_groups.parent_id takes the descendants and
      // their closure rows; `count` is 1 (the row named in the WHERE), which is
      // exactly why the audit flagged the old return value.
      await trx('device_groups').where({ id }).del();
      return ids.length;
    });
  },

  // ── Tree queries using closure table ──

  /**
   * VERIF-SECFIX-AUTRES #15 — the four helpers below walk `group_closure`, and
   * all four used to do it with NO tenant filter at all.
   *
   * `group_closure` is a bare `(ancestor_id, descendant_id, depth)` table: it
   * carries no tenant, no FK can express "both ends belong to the same
   * customer", and `checkClosureIntegrity` only LOGS a cross-tenant edge — it
   * does not delete it. So a single bad edge (a bug, a restore, a hand-written
   * `UPDATE parent_id`) turns any of these into a cross-tenant read, and the
   * caller has no way to tell: the answer looks like an ordinary list of
   * groups.
   *
   * The previous pass guarded the one live CALLER instead of the helpers, which
   * left the trap armed: the next caller — and M2/M3 add several, for settings
   * inheritance, for grouped notifications, for the device tree — would be
   * written from the signature, and the signature said no tenant was needed.
   * `tenantId` is therefore REQUIRED and has no default, precisely so that a
   * caller which forgets it fails to compile instead of reading across the
   * boundary. The filter is applied to the GROUP ROWS, on both ends of the
   * closure, never to `group_closure` itself, which cannot express it.
   */

  /**
   * Ancestors of `groupId`, root -> parent (self excluded), within `tenantId`.
   * Returns [] when `groupId` itself is not in the tenant — the ancestry of a
   * group you cannot see is not a question with an answer.
   */
  async getAncestors(groupId: number, tenantId: number): Promise<DeviceGroup[]> {
    const rows = await db<GroupRow>('device_groups')
      .join('group_closure', 'device_groups.id', 'group_closure.ancestor_id')
      // The anchor must belong to the tenant too, otherwise a cross-tenant edge
      // pointing INTO this tenant would answer with legitimate-looking rows.
      .join('device_groups as anchor', 'anchor.id', 'group_closure.descendant_id')
      .where('group_closure.descendant_id', groupId)
      .where('group_closure.depth', '>', 0)
      .where('device_groups.tenant_id', tenantId)
      .where('anchor.tenant_id', tenantId)
      .orderBy('group_closure.depth', 'desc')
      .select('device_groups.*');
    return rows.map(rowToGroup);
  },

  /**
   * Ids of `groupId` and everything under it, within `tenantId`.
   *
   * This one is the most dangerous of the four: its result is fed to
   * `whereIn('scope_id', …)` deletes and to permission resolution, so a foreign
   * descendant id does not merely leak — it gets WRITTEN to.
   */
  async getDescendantIds(groupId: number, tenantId: number): Promise<number[]> {
    return db('group_closure')
      .join('device_groups as d', 'd.id', 'group_closure.descendant_id')
      .join('device_groups as a', 'a.id', 'group_closure.ancestor_id')
      .where('group_closure.ancestor_id', groupId)
      .where('d.tenant_id', tenantId)
      .where('a.tenant_id', tenantId)
      .pluck<number[]>('group_closure.descendant_id');
  },

  /**
   * Direct children of `parentId` (or the roots when null), within `tenantId`.
   *
   * This one does not read the closure, but it had the same hole and the same
   * consequence: `getChildren(null)` returned the ROOT GROUPS OF EVERY TENANT.
   */
  async getChildren(parentId: number | null, tenantId: number): Promise<DeviceGroup[]> {
    const query = db<GroupRow>('device_groups')
      .where({ tenant_id: tenantId })
      .orderBy('sort_order')
      .orderBy('name');
    if (parentId === null) {
      query.whereNull('parent_id');
    } else {
      query.where({ parent_id: parentId });
    }
    const rows = await query;
    return rows.map(rowToGroup);
  },

  async getTree(tenantId: number, options?: { crossTenant?: boolean }): Promise<GroupTreeNode[]> {
    const allGroups = await this.getAll(tenantId, options);
    const groupMap = new Map<number, GroupTreeNode>();

    // Initialize nodes
    for (const g of allGroups) {
      groupMap.set(g.id, { ...g, children: [] });
    }

    // Build tree. AUDIT-CORR §3.2 — a node whose parent is present in the map
    // but which is part of a parent_id cycle would never be reachable from a
    // root, and the whole subtree used to VANISH from the sidebar with no way
    // to get it back from the UI. Roots are collected first, then reachability
    // is checked and anything left over is promoted to a root so it stays
    // visible and fixable.
    const roots: GroupTreeNode[] = [];
    for (const node of groupMap.values()) {
      if (node.parentId && groupMap.has(node.parentId)) {
        groupMap.get(node.parentId)!.children.push(node);
      } else {
        roots.push(node);
      }
    }

    const reachable = new Set<number>();
    const stack = [...roots];
    while (stack.length > 0) {
      const node = stack.pop()!;
      if (reachable.has(node.id)) continue;
      reachable.add(node.id);
      for (const child of node.children) stack.push(child);
    }
    if (reachable.size !== groupMap.size) {
      const orphans = [...groupMap.values()].filter((n) => !reachable.has(n.id));
      // Only the topmost node of each detached cycle is promoted, otherwise the
      // same subtree would be rendered several times.
      const orphanIds = new Set(orphans.map((n) => n.id));
      for (const node of orphans) {
        if (node.parentId === null || !orphanIds.has(node.parentId)) roots.push(node);
      }
      logger.error(
        { tenantId, orphanIds: [...orphanIds] },
        'getTree: groups unreachable from any root (parent_id cycle) — promoted to roots so they stay fixable',
      );
    }

    return roots;
  },

  /** Batch-update sortOrder for multiple groups at once, within one tenant. */
  async reorder(items: { id: number; sortOrder: number }[], tenantId: number): Promise<void> {
    await db.transaction(async (trx) => {
      for (const item of items) {
        await trx('device_groups')
          .where({ id: item.id, tenant_id: tenantId })
          .update({ sort_order: item.sortOrder, updated_at: new Date() });
      }
    });
  },

  /**
   * Find the nearest ancestor (or self) with group_notifications = true, within
   * `tenantId`. Uses the closure table, ordered by depth ASC (self = depth 0).
   *
   * VERIF-SECFIX-AUTRES #15 — in M2 this answer NAMES the group in the
   * notification title, so a stale edge `<acme group> -> <globex group>` would
   * announce a Globex outage under an Acme group's name, through Acme's
   * channels. `groupNotification.shouldSuppressIndividual` used to re-confront
   * the result with the tenant itself, because this helper belonged to another
   * agent; the guard now lives here, where every future caller inherits it.
   */
  async findGroupNotificationAncestor(groupId: number, tenantId: number): Promise<DeviceGroup | null> {
    const row = await db<GroupRow>('device_groups')
      .join('group_closure', 'device_groups.id', 'group_closure.ancestor_id')
      .join('device_groups as anchor', 'anchor.id', 'group_closure.descendant_id')
      .where('group_closure.descendant_id', groupId)
      .where('device_groups.group_notifications', true)
      .where('device_groups.tenant_id', tenantId)
      .where('anchor.tenant_id', tenantId)
      .orderBy('group_closure.depth', 'asc')
      .first('device_groups.*');
    return row ? rowToGroup(row) : null;
  },

  /**
   * Boot-time consistency check of the closure table (AUDIT-CORR §2.2).
   *
   * The closure is the only source of truth for settings inheritance AND for
   * group permissions, and nothing on screen reveals when it is wrong: getTree
   * reads `parent_id`, so a group missing its closure rows renders perfectly
   * while being invisible to authorisation and inheriting nothing.
   *
   * It LOGS LOUDLY and never throws: a corrupt closure is a data problem to be
   * repaired, not a reason to take a fleet-management server offline. The
   * return value lets a future `--repair` flag act on the same findings.
   */
  async checkClosureIntegrity(): Promise<{
    missingSelf: number[];
    crossTenantEdges: Array<{ ancestorId: number; descendantId: number }>;
  }> {
    const missingSelfRows = await db('device_groups as g')
      .leftJoin('group_closure as c', function () {
        this.on('c.ancestor_id', '=', 'g.id').andOn('c.descendant_id', '=', 'g.id');
      })
      .whereNull('c.ancestor_id')
      .pluck('g.id') as number[];

    const crossTenantRows = await db('group_closure as c')
      .join('device_groups as a', 'a.id', 'c.ancestor_id')
      .join('device_groups as d', 'd.id', 'c.descendant_id')
      .whereRaw('a.tenant_id <> d.tenant_id')
      .select('c.ancestor_id as ancestorId', 'c.descendant_id as descendantId') as Array<{
        ancestorId: number;
        descendantId: number;
      }>;

    if (missingSelfRows.length > 0) {
      logger.error(
        { groupIds: missingSelfRows, count: missingSelfRows.length },
        'CLOSURE INTEGRITY: groups with no self-row in group_closure — they inherit no settings and are ' +
          'invisible to every non-admin permission check. Repair: INSERT (id, id, 0) then rebuild their ancestor rows.',
      );
    }
    if (crossTenantRows.length > 0) {
      logger.error(
        { edges: crossTenantRows, count: crossTenantRows.length },
        'CLOSURE INTEGRITY: group_closure edges linking two different tenants — a tenant may be inheriting ' +
          'another tenant settings or granting permissions across the boundary. Reads are filtered by tenant, ' +
          'but these rows must be deleted.',
      );
    }
    if (missingSelfRows.length === 0 && crossTenantRows.length === 0) {
      logger.info('Closure integrity check: OK');
    }

    return { missingSelf: missingSelfRows, crossTenantEdges: crossTenantRows };
  },
};
