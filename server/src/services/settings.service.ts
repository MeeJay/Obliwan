import type { Knex } from 'knex';
import { db } from '../db';
import type { SettingsScope, ResolvedSettings } from '@obliwan/shared';
import type { SettingsKey } from '@obliwan/shared';
import { SETTINGS_KEYS, HARDCODED_DEFAULTS, SETTINGS_DEFINITIONS } from '@obliwan/shared';

/**
 * Hierarchical settings — TENANT-SCOPED.
 *
 * AUDIT-CORR §1.2 (CRITIQUE): `settings.tenant_id` existed but appeared in no
 * read, no write and no unique key. Two tenants could not physically hold two
 * different values for the same global key, and the last writer silently
 * reconfigured every other client. Every function below now takes `tenantId`
 * as its FIRST parameter — it is not optional and has no default, precisely so
 * that a caller that forgot it fails to compile instead of falling back on the
 * master tenant.
 *
 * AUDIT-CORR §1.1 (CRITIQUE): the uniqueness of a row is enforced by two
 * PARTIAL indexes (`settings_unscoped_uq` / `settings_scoped_uq`, migration
 * 001), because `UNIQUE (scope, scope_id, key)` constrained nothing when
 * scope_id was NULL. The upserts below name those indexes explicitly through
 * their conflict target, WHERE clause included — PostgreSQL cannot infer a
 * partial index from a bare column list.
 */

interface SettingsRow {
  id: number;
  scope: string;
  scope_id: number | null;
  key: string;
  value: unknown;
  tenant_id: number;
  created_at: Date;
  updated_at: Date;
}

export interface SettingOverride {
  key: SettingsKey;
  value: number;
}

/**
 * Conflict target of the partial unique index that covers this row.
 * The WHERE clause is part of the target: without it PostgreSQL raises
 * "there is no unique or exclusion constraint matching the ON CONFLICT
 * specification" instead of quietly inserting a duplicate.
 */
function conflictTarget(scopeId: number | null) {
  return scopeId === null
    ? db.raw('(tenant_id, scope, key) WHERE scope_id IS NULL')
    : db.raw('(tenant_id, scope, scope_id, key) WHERE scope_id IS NOT NULL');
}

function validate(key: SettingsKey, value: number): void {
  const def = SETTINGS_DEFINITIONS.find((d) => d.key === key);
  if (!def) throw new Error(`Unknown setting key: ${key}`);
  if (!Number.isFinite(value)) throw new Error(`Value for ${key} must be a number`);
  if (value < def.min || value > def.max) {
    throw new Error(`Value for ${key} must be between ${def.min} and ${def.max}`);
  }
}

export const settingsService = {
  // ── Raw CRUD ──

  async getByScope(
    tenantId: number,
    scope: SettingsScope,
    scopeId: number | null,
  ): Promise<Record<string, number>> {
    const rows = await db<SettingsRow>('settings')
      .where({ tenant_id: tenantId, scope, scope_id: scopeId })
      .select('key', 'value');

    const result: Record<string, number> = {};
    for (const row of rows) {
      result[row.key] = row.value as number;
    }
    return result;
  },

  async set(
    tenantId: number,
    scope: SettingsScope,
    scopeId: number | null,
    key: SettingsKey,
    value: number,
  ): Promise<void> {
    validate(key, value);
    await this._write(db, tenantId, scope, scopeId, key, value);
  },

  /** Shared by set() and setBulk() so both go through the same conflict target. */
  async _write(
    executor: Knex | Knex.Transaction,
    tenantId: number,
    scope: SettingsScope,
    scopeId: number | null,
    key: SettingsKey,
    value: number,
  ): Promise<void> {
    const now = new Date();
    await executor('settings')
      .insert({
        tenant_id: tenantId,
        scope,
        scope_id: scopeId,
        key,
        value: JSON.stringify(value),
        updated_at: now,
      })
      .onConflict(conflictTarget(scopeId))
      .merge({ value: JSON.stringify(value), updated_at: now });
  },

  async remove(
    tenantId: number,
    scope: SettingsScope,
    scopeId: number | null,
    key: SettingsKey,
  ): Promise<boolean> {
    const count = await db('settings')
      .where({ tenant_id: tenantId, scope, scope_id: scopeId, key })
      .del();
    return count > 0;
  },

  /**
   * AUDIT-CORR §2.4 — was a plain loop over set(): the first overrides were
   * already committed when a later one failed validation, leaving the operator
   * with a half-applied form and no way to tell which half. Validate
   * everything first, then write the lot in ONE transaction.
   */
  async setBulk(
    tenantId: number,
    scope: SettingsScope,
    scopeId: number | null,
    overrides: SettingOverride[],
  ): Promise<void> {
    for (const { key, value } of overrides) validate(key, value);

    await db.transaction(async (trx) => {
      for (const { key, value } of overrides) {
        await this._write(trx, tenantId, scope, scopeId, key, value);
      }
    });
  },

  // ── Inheritance Resolution ──

  /**
   * Load, in ONE query, the overrides of every ancestor of `groupId`, ordered
   * root -> leaf.
   *
   * AUDIT-CORR §2.3 — this used to be one query per ancestry level (8
   * round-trips for a 5-level tree, per device). Harmless in M1 where nothing
   * polls; 2 400 queries per cycle for 300 devices in M2.
   *
   * `includeSelf = false` is the `resolveForGroup` case (depth > 0).
   */
  async _ancestorOverrides(
    tenantId: number,
    groupId: number,
    includeSelf: boolean,
  ): Promise<{ id: number; name: string; key: string; value: number }[]> {
    // INNER JOINs: the extra predicates are equivalent whether they sit in the
    // ON or in the WHERE, and the WHERE form stays readable.
    const q = db('group_closure')
      .join('device_groups', 'device_groups.id', 'group_closure.ancestor_id')
      .join('settings', 'settings.scope_id', 'group_closure.ancestor_id')
      .where('settings.scope', 'group')
      .where('settings.tenant_id', tenantId)
      .where('group_closure.descendant_id', groupId)
      // The ancestors must belong to the caller's tenant. A cross-tenant
      // closure edge (AUDIT-SEC #9) must not leak another client's overrides.
      .where('device_groups.tenant_id', tenantId)
      .orderBy('group_closure.depth', 'desc')
      .select(
        'device_groups.id as id',
        'device_groups.name as name',
        'settings.key as key',
        'settings.value as value',
      );

    if (!includeSelf) q.where('group_closure.depth', '>', 0);

    return (await q) as { id: number; name: string; key: string; value: number }[];
  },

  /**
   * Resolve all settings for a given scope, walking up the hierarchy:
   *   Hardcoded defaults → Global → Group ancestors (root→leaf) → Device
   *
   * Each resolved value tracks its source for UI display.
   */
  async resolveForDevice(
    tenantId: number,
    deviceId: number,
    groupId: number | null,
  ): Promise<ResolvedSettings> {
    // 1. Start with hardcoded defaults
    const resolved: ResolvedSettings = {} as ResolvedSettings;
    const allKeys = Object.values(SETTINGS_KEYS);
    const known = new Set<string>(allKeys);

    for (const key of allKeys) {
      resolved[key] = {
        value: HARDCODED_DEFAULTS[key],
        source: 'default',
        sourceId: null,
        sourceName: 'Default',
      };
    }

    // 2. Apply global overrides
    const globalOverrides = await this.getByScope(tenantId, 'global', null);
    for (const key of allKeys) {
      if (globalOverrides[key] !== undefined) {
        resolved[key] = {
          value: globalOverrides[key],
          source: 'global',
          sourceId: null,
          sourceName: 'Global',
        };
      }
    }

    // 3. Apply group chain (root → leaf) if the device is in a group
    if (groupId !== null) {
      for (const row of await this._ancestorOverrides(tenantId, groupId, true)) {
        if (!known.has(row.key)) continue;
        resolved[row.key as SettingsKey] = {
          value: row.value,
          source: 'group',
          sourceId: row.id,
          sourceName: row.name,
        };
      }
    }

    // 4. Apply device-level overrides
    const deviceOverrides = await this.getByScope(tenantId, 'device', deviceId);
    for (const key of allKeys) {
      if (deviceOverrides[key] !== undefined) {
        resolved[key] = {
          value: deviceOverrides[key],
          source: 'device',
          sourceId: deviceId,
          sourceName: 'This device',
        };
      }
    }

    return resolved;
  },

  /**
   * Resolve settings for a group level (for display in group settings UI).
   * Chain: Hardcoded → Global → Ancestor groups (root→parent)
   * Does NOT include the group's own overrides as resolved — returns them separately.
   */
  async resolveForGroup(
    tenantId: number,
    groupId: number,
  ): Promise<{ resolved: ResolvedSettings; overrides: Record<string, number> }> {
    const allKeys = Object.values(SETTINGS_KEYS);
    const known = new Set<string>(allKeys);

    // 1. Start with hardcoded defaults
    const resolved: ResolvedSettings = {} as ResolvedSettings;
    for (const key of allKeys) {
      resolved[key] = {
        value: HARDCODED_DEFAULTS[key],
        source: 'default',
        sourceId: null,
        sourceName: 'Default',
      };
    }

    // 2. Global
    const globalOverrides = await this.getByScope(tenantId, 'global', null);
    for (const key of allKeys) {
      if (globalOverrides[key] !== undefined) {
        resolved[key] = {
          value: globalOverrides[key],
          source: 'global',
          sourceId: null,
          sourceName: 'Global',
        };
      }
    }

    // 3. Ancestors (root→parent, excluding self)
    for (const row of await this._ancestorOverrides(tenantId, groupId, false)) {
      if (!known.has(row.key)) continue;
      resolved[row.key as SettingsKey] = {
        value: row.value,
        source: 'group',
        sourceId: row.id,
        sourceName: row.name,
      };
    }

    // 4. Get this group's own overrides (separate, not merged into resolved)
    const overrides = await this.getByScope(tenantId, 'group', groupId);

    return { resolved, overrides };
  },

  /**
   * Resolve for global scope (just hardcoded defaults + global overrides)
   */
  async resolveGlobal(
    tenantId: number,
  ): Promise<{ resolved: ResolvedSettings; overrides: Record<string, number> }> {
    const allKeys = Object.values(SETTINGS_KEYS);
    const resolved: ResolvedSettings = {} as ResolvedSettings;

    for (const key of allKeys) {
      resolved[key] = {
        value: HARDCODED_DEFAULTS[key],
        source: 'default',
        sourceId: null,
        sourceName: 'Default',
      };
    }

    const overrides = await this.getByScope(tenantId, 'global', null);

    return { resolved, overrides };
  },
};
