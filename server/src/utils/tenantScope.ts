import type { Knex } from 'knex';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';

/**
 * "Does this scopeId belong to the caller's tenant?" — ONE implementation.
 *
 * VERDICT-CONSOLIDATION §3.3.1 — the same rule was written three times, with
 * three different coverages:
 *
 *   * `settings.controller.assertScopeInTenant` + its own `SCOPE_TABLES`
 *     (covers `group` and `device`);
 *   * an inline `db('device_groups').where({id, tenant_id})` in
 *     `notifications.controller.addBinding` (covers `group` ONLY — a
 *     device-scoped binding on another tenant's device id was accepted);
 *   * `teamService._assertGrantTargetsInTenant` (covers `group` and `device`,
 *     batched, different message).
 *
 * That is exactly the shape that produced R5: `assertScopeInTenant` was written
 * for `group`, `device` arrived with migration 002, and only ONE of the three
 * copies learnt about it. The next scope added — a site, a transport, a
 * template — would be covered in two places out of three, and nothing would
 * fail loudly at the third.
 *
 * The rule, stated once:
 *   - the scope kind is resolved through an ALLOW-LIST of table names, never
 *     through an interpolated identifier;
 *   - a row that does not exist and a row that belongs to another tenant get
 *     the SAME 404 with the same wording — no existence oracle on another
 *     customer's inventory;
 *   - an unknown scope kind is a routing bug and is refused (400) rather than
 *     falling through to a write.
 */

/** Scope kinds that address a row of a tenant-owned table. */
export type TenantScopeKind = 'group' | 'device';

/** The ONLY place a scope kind is mapped to a physical table. */
const SCOPE_TABLES: Record<TenantScopeKind, { table: string; label: string }> = {
  group: { table: 'device_groups', label: 'Group' },
  device: { table: 'devices', label: 'Device' },
};

export function isTenantScopeKind(value: unknown): value is TenantScopeKind {
  return value === 'group' || value === 'device';
}

/** Human label of a scope kind, for callers that build their own message. */
export function scopeLabel(scope: TenantScopeKind): string {
  return SCOPE_TABLES[scope].label;
}

/**
 * True when `scopeId` names a row of `scope` owned by `tenantId`.
 * Pass `exec` to run inside an open transaction (import path).
 */
export async function isScopeInTenant(
  scope: TenantScopeKind,
  scopeId: number,
  tenantId: number,
  exec: Knex | Knex.Transaction = db,
): Promise<boolean> {
  const target = SCOPE_TABLES[scope];
  if (!target) return false;
  const row = await exec(target.table).where({ id: scopeId, tenant_id: tenantId }).first('id');
  return !!row;
}

/**
 * Refuse a scopeId that does not belong to `tenantId`.
 *
 * `scope === 'global'` (or a null scopeId) is a no-op: a global scope addresses
 * no row and is already confined by the `tenant_id` column of the table being
 * written.
 *
 * @throws {AppError} 404 when the row is absent or foreign, 400 on an unknown
 *         scope kind.
 */
export async function assertScopeInTenant(
  scope: string,
  scopeId: number | null | undefined,
  tenantId: number,
  exec: Knex | Knex.Transaction = db,
): Promise<void> {
  if (scope === 'global' || scopeId === null || scopeId === undefined) return;
  if (!isTenantScopeKind(scope)) throw new AppError(400, 'Invalid scope');
  if (!(await isScopeInTenant(scope, scopeId, tenantId, exec))) {
    throw new AppError(404, `${SCOPE_TABLES[scope].label} not found`);
  }
}

/**
 * Batch form, for a payload that carries many (scope, scopeId) pairs — one
 * query per kind instead of one per pair. Names every offending id at once so
 * the operator fixes the form in one pass.
 */
export async function assertScopesInTenant(
  targets: Array<{ scope: string; scopeId: number | null | undefined }>,
  tenantId: number,
  exec: Knex | Knex.Transaction = db,
): Promise<void> {
  for (const kind of Object.keys(SCOPE_TABLES) as TenantScopeKind[]) {
    const wanted = [
      ...new Set(
        targets
          .filter((t) => t.scope === kind && t.scopeId !== null && t.scopeId !== undefined)
          .map((t) => t.scopeId as number),
      ),
    ];
    if (wanted.length === 0) continue;
    const found = await exec(SCOPE_TABLES[kind].table)
      .where({ tenant_id: tenantId })
      .whereIn('id', wanted)
      .pluck<number[]>('id');
    const foundSet = new Set(found);
    const missing = wanted.filter((id) => !foundSet.has(id));
    if (missing.length > 0) {
      throw new AppError(404, `${SCOPE_TABLES[kind].label} not found: ${missing.join(', ')}`);
    }
  }

  const bad = targets.find((t) => t.scope !== 'global' && !isTenantScopeKind(t.scope));
  if (bad) throw new AppError(400, 'Invalid scope');
}
