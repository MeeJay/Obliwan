import type { Request, Response, NextFunction } from 'express';
import { db } from '../db';
import { settingsService } from '../services/settings.service';
import type { SettingsScope } from '@obliwan/shared';
import type { SettingsKey } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import type { SetSettingInput, SetSettingsBulkInput, DeleteSettingInput } from '../validators/settings.schema';

/**
 * The Socket.io room a settings mutation may be announced in.
 *
 * VERIF-SECFIX R1 / VERIF-SECFIX-AUTRES #7 — these three emits used to target
 * `role:admin`, a GLOBAL room with no tenant in its name. Two platform admins
 * working on two different customers sat in it together, so an admin looking at
 * Acme received `settings:updated {scope:'global', key:'snmp_timeout',
 * value:600}` the moment another admin saved that value on Globex. His form
 * then showed 600 for Acme, whose stored value was 8000 — and clicking "Save"
 * wrote Globex's value into Acme. The whole tenant scoping of `settings` was
 * defeated by the most ordinary gesture an operator makes.
 *
 * The room convention is fixed platform-wide: `tenant:{id}` for every member,
 * `tenant:{id}:admin` for the admins POSITIONED ON that tenant, `user:{id}` for
 * one account. `socket.ts` joins `tenant:{id}:admin` on connection.
 *
 * The payloads below also carry `tenantId` now: a client that receives an event
 * has no other way to tell whether it concerns the tenant it is displaying, and
 * "the client cannot filter even if it wanted to" is how a stale room becomes a
 * silent data-corruption path again.
 */
function adminRoom(req: Request): string {
  return `tenant:${req.tenantId}:admin`;
}

function parseScope(req: Request): { scope: SettingsScope; scopeId: number | null } {
  const { scope, scopeId } = req.params;

  if (scope === 'global') return { scope: 'global', scopeId: null };
  if (scope === 'group' || scope === 'device') {
    const id = parseInt(scopeId, 10);
    if (isNaN(id)) throw new AppError(400, 'Invalid scope ID');
    return { scope, scopeId: id };
  }
  throw new AppError(400, 'Invalid scope. Must be global, group or device');
}

/**
 * AUDIT-SEC #7 (corollary) — `PUT /api/settings/group/:scopeId` never checked
 * that the group belonged to the current tenant, and neither did
 * `getGroupResolved`. The tenant_id now in the unique key means such a write
 * can no longer overwrite the other tenant's value, but it would still leave an
 * orphan row keyed on a group the caller cannot see. Reject it outright.
 *
 * VERIF-SECFIX R5 — the guard read `if (scope !== 'group' || scopeId === null)
 * return;`, so `device` was waved through: `PUT /api/settings/device/4242`
 * answered 200 on an id belonging to no tenant at all. That was moot in M1;
 * migration 002 created `devices` and `settingsService.resolveForDevice` made
 * the scope real, so the same rule now applies to both scoped kinds. The two
 * tables are addressed by an allow-list, never by an interpolated name.
 */
const SCOPE_TABLES: Record<'group' | 'device', { table: string; label: string }> = {
  group: { table: 'device_groups', label: 'Group' },
  device: { table: 'devices', label: 'Device' },
};

async function assertScopeInTenant(
  scope: SettingsScope,
  scopeId: number | null,
  tenantId: number,
): Promise<void> {
  if (scope === 'global' || scopeId === null) return;
  const target = SCOPE_TABLES[scope];
  // An unknown scope reaching this far would be a routing bug, not a caller
  // mistake — refuse rather than fall through to a write.
  if (!target) throw new AppError(400, 'Invalid scope');
  const row = await db(target.table).where({ id: scopeId, tenant_id: tenantId }).first('id');
  // Same 404 whether the row belongs to another tenant or does not exist: no
  // existence oracle on another customer's inventory.
  if (!row) throw new AppError(404, `${target.label} not found`);
}

/** Validation errors carry a 400, not the generic 500 of `next(err)`. */
function asValidationError(err: unknown): unknown {
  if (
    err instanceof Error &&
    (err.message.includes('must be between') ||
      err.message.includes('must be a number') ||
      err.message.includes('Unknown setting'))
  ) {
    return new AppError(400, err.message);
  }
  return err;
}

export const settingsController = {
  // GET /api/settings/global/resolved
  async getGlobalResolved(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const result = await settingsService.resolveGlobal(req.tenantId);
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },

  // GET /api/settings/group/:scopeId/resolved
  async getGroupResolved(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const groupId = parseInt(req.params.scopeId, 10);
      if (isNaN(groupId)) throw new AppError(400, 'Invalid group ID');
      await assertScopeInTenant('group', groupId, req.tenantId);
      const result = await settingsService.resolveForGroup(req.tenantId, groupId);
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },

  // PUT /api/settings/:scope/:scopeId
  async set(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { scope, scopeId } = parseScope(req);
      const { key, value } = req.body as SetSettingInput;

      await assertScopeInTenant(scope, scopeId, req.tenantId);
      await settingsService.set(req.tenantId, scope, scopeId, key as SettingsKey, value);

      // Broadcast settings update
      const io = req.app.get('io');
      if (io) {
        io.to(adminRoom(req)).emit('settings:updated', { tenantId: req.tenantId, scope, scopeId, key, value });
      }

      res.json({ success: true, message: 'Setting saved' });
    } catch (err: unknown) {
      next(asValidationError(err));
    }
  },

  // PUT /api/settings/:scope/:scopeId/bulk
  async setBulk(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { scope, scopeId } = parseScope(req);
      const { overrides } = req.body as SetSettingsBulkInput;

      await assertScopeInTenant(scope, scopeId, req.tenantId);
      await settingsService.setBulk(
        req.tenantId,
        scope,
        scopeId,
        overrides.map((o) => ({ key: o.key as SettingsKey, value: o.value })),
      );

      const io = req.app.get('io');
      if (io) {
        io.to(adminRoom(req)).emit('settings:updated', { tenantId: req.tenantId, scope, scopeId, overrides });
      }

      res.json({ success: true, message: 'Settings saved' });
    } catch (err) {
      // AUDIT-CORR §2.4 — setBulk validates everything BEFORE writing anything,
      // so a validation failure now means nothing at all was persisted; say so
      // with a 400 instead of the previous opaque 500.
      next(asValidationError(err));
    }
  },

  // DELETE /api/settings/:scope/:scopeId/:key  (reset to inherited)
  async remove(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { scope, scopeId } = parseScope(req);
      const { key } = req.params;

      await assertScopeInTenant(scope, scopeId, req.tenantId);
      const deleted = await settingsService.remove(req.tenantId, scope, scopeId, key as SettingsKey);

      if (deleted) {
        const io = req.app.get('io');
        if (io) {
          io.to(adminRoom(req)).emit('settings:updated', { tenantId: req.tenantId, scope, scopeId, key, removed: true });
        }
      }

      res.json({ success: true, message: deleted ? 'Setting reset to inherited' : 'No override found' });
    } catch (err) {
      next(err);
    }
  },
};
