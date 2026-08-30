import type { Request, Response, NextFunction } from 'express';
import type { Knex } from 'knex';
import { randomUUID } from 'crypto';
import { sanitizeCapabilities, isSettingsKey, getSettingDefinition } from '@obliwan/shared';
import type { SettingsKey } from '@obliwan/shared';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { settingsService } from '../services/settings.service';
import { topoSort, findCycles, CycleError } from '../utils/topoSort';

/**
 * Tenant backup / restore — migrate a customer from one ObliWAN instance to
 * another (arbitrage 1.4 bis: import/export is kept AND levelled up, and
 * "nothing exported may be un-importable").
 *
 * M1 SECTIONS. Every one of them maps to a table that exists in migration 001
 * and is exercised by the same code path in both directions. The Obliguard
 * sections that pointed at tables ObliWAN does not have — monitors, agentGroups,
 * remediationActions, remediationBindings — are NOT stubbed out here: they are
 * gone. The fleet sections (sites, devices, transports, templates, revisions,
 * variables) land with their own migrations from M2 onwards and get added to
 * SECTIONS then, not before.
 *
 * SECRETS ARE NEVER EXPORTED. SMTP passwords, the Obligate API key and (from
 * M2) device credentials stay in the instance that owns them: a bundle is a
 * plain JSON file that travels by e-mail and chat. What crosses is structure.
 */
const SECTIONS = [
  'deviceGroups',
  'settings',
  'notificationChannels',
  'teams',
] as const;

type ExportSection = (typeof SECTIONS)[number];

function isSection(value: string): value is ExportSection {
  return (SECTIONS as readonly string[]).includes(value);
}

/** Bundle envelope version. Bump on any breaking change to the shape. */
const FORMAT_VERSION = 2;

/**
 * What to do when an imported item's UUID already exists in the database.
 *  - update      : overwrite the existing record with the imported data (default)
 *  - generateNew : create a brand-new copy with a fresh UUID
 *  - ignore      : skip the item entirely
 */
type ConflictStrategy = 'update' | 'generateNew' | 'ignore';

const CONFLICT_STRATEGIES: ConflictStrategy[] = ['update', 'generateNew', 'ignore'];

// -- Helpers -----------------------------------------------------------------

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * device_groups.slug is UNIQUE (tenant_id, slug) since the fix of audit-corr
 * §1.8 — it used to be globally unique, which made one tenant's slugs (and
 * therefore its URLs and its export) depend on another tenant's content: a
 * second tenant importing "Paris" silently got `paris-1`, and the same bundle
 * imported twice on two instances produced two different results.
 */
async function ensureUniqueSlugTrx(
  trx: Knex.Transaction,
  slug: string,
  tenantId: number,
): Promise<string> {
  let candidate = slug || 'group';
  let i = 1;
  for (;;) {
    const exists = await trx('device_groups').where({ slug: candidate, tenant_id: tenantId }).first();
    if (!exists) return candidate;
    candidate = `${slug}-${i++}`;
  }
}

/** Insert closure-table entries for a newly created group. */
async function insertGroupClosure(
  trx: Knex.Transaction,
  groupId: number,
  parentId: number | null,
): Promise<void> {
  await trx('group_closure').insert({ ancestor_id: groupId, descendant_id: groupId, depth: 0 });
  if (parentId !== null) {
    await trx.raw(
      `INSERT INTO group_closure (ancestor_id, descendant_id, depth)
       SELECT gc.ancestor_id, ?, gc.depth + 1
       FROM   group_closure gc
       WHERE  gc.descendant_id = ?`,
      [groupId, parentId],
    );
  }
}

/**
 * Rebuild the closure rows for an EXISTING group whose parent just changed.
 * Skipping this is how an import quietly corrupts settings inheritance and
 * group-scoped permissions: both are resolved through `group_closure`, so a
 * stale closure means a user keeps read access to a subtree that was moved out
 * from under them.
 */
async function reparentGroupClosure(
  trx: Knex.Transaction,
  groupId: number,
  parentId: number | null,
): Promise<void> {
  const subtree = await trx('group_closure').where({ ancestor_id: groupId }).pluck('descendant_id');
  const descIds: number[] = subtree.length > 0 ? subtree : [groupId];

  // Cut every link coming from outside the subtree.
  await trx('group_closure')
    .whereIn('descendant_id', descIds)
    .whereNotIn('ancestor_id', descIds)
    .del();

  if (parentId !== null) {
    await trx.raw(
      `INSERT INTO group_closure (ancestor_id, descendant_id, depth)
       SELECT p.ancestor_id, s.descendant_id, p.depth + s.depth + 1
       FROM   group_closure p
       CROSS JOIN group_closure s
       WHERE  p.descendant_id = ?
         AND  s.ancestor_id  = ?`,
      [parentId, groupId],
    );
  }
}

interface SectionResult { created: number; updated: number; skipped: number; warnings?: string[] }

/**
 * VERIF-SECFIX-AUTRES #18 — the import used to write `settings` with a raw
 * DELETE + INSERT: no `SETTINGS_DEFINITIONS`, no min/max, no check that the key
 * exists at all. `PUT /api/settings/global` refuses `snmp_timeout = 999999999`
 * (max 60000) and refuses an invented key outright; a JSON file uploaded to
 * `POST /api/admin/import` put both straight into the table. The row is then
 * read by `settingsService.resolveForDevice`, i.e. by the pollers, and shown by
 * a UI whose slider cannot express it — so the operator cannot even correct it
 * from the screen that displays it.
 *
 * Two write paths onto one table, one validated and one not, is the same shape
 * as #19 just below (and as R2, and as #12). The bundle now goes through the
 * SAME source of truth as the API: `isSettingsKey` / `getSettingDefinition`
 * are the accessors over the very `SETTINGS_DEFINITIONS` array that
 * `settingsService.validate()` reads, and the write itself is delegated to
 * `settingsService._write`, which carries the partial-index conflict target the
 * hand-rolled DELETE+INSERT was working around.
 *
 * A bad value REJECTS THE BUNDLE (400) rather than being skipped: a restore
 * that silently drops half the tuning of a customer is worse than one that
 * refuses and names the line to fix.
 */
function parseSettingValue(rawKey: unknown, rawValue: unknown): { key: SettingsKey; value: number } {
  const key = typeof rawKey === 'string' ? rawKey : String(rawKey);
  if (!isSettingsKey(key)) {
    throw new AppError(
      400,
      `Import aborted: settings contains an unknown key "${key}". ` +
        'Nothing was imported. Remove the entry, or upgrade this instance to a version that defines it.',
    );
  }
  const def = getSettingDefinition(key);

  // The export writes the jsonb value verbatim, so it arrives as a number; a
  // hand-edited bundle may carry "5000". Anything else is a mistake, not a
  // value to coerce.
  const value =
    typeof rawValue === 'number'
      ? rawValue
      : typeof rawValue === 'string' && rawValue.trim() !== ''
        ? Number(rawValue)
        : NaN;

  if (!Number.isFinite(value)) {
    throw new AppError(
      400,
      `Import aborted: setting "${key}" carries a non-numeric value (${JSON.stringify(rawValue)}). ` +
        'Nothing was imported.',
    );
  }
  if (def && (value < def.min || value > def.max)) {
    throw new AppError(
      400,
      `Import aborted: setting "${key}" = ${value} is outside its allowed range ` +
        `[${def.min}, ${def.max}]. Nothing was imported — the pollers read this value.`,
    );
  }
  return { key, value };
}

/**
 * VERIF-SECFIX-AUTRES #6, import side.
 *
 * `notificationsController.createChannel` / `updateChannel` now refuse a
 * `config.smtpServerId` the tenant may not use, but the import writes
 * `notification_channels.config` directly and bypassed that check: a
 * hand-edited (or simply cross-tenant) bundle re-materialised a channel naming
 * ANOTHER customer's private relay. `resolveChannelConfig` refuses it at send
 * time, so no credential is handed over, but the row itself must not exist —
 * an authorisation reference to another tenant's resource is refused at write
 * time, and the operator is told rather than left with a channel that fails
 * only during an outage.
 *
 * The reference is dropped and the channel imported DISABLED, so one bad key
 * does not cost the operator the other forty sections of the bundle.
 */
async function scrubForeignSmtpRef(
  trx: Knex.Transaction,
  config: Record<string, unknown>,
  tenantId: number,
  channelName: string,
  warnings: string[],
): Promise<{ config: Record<string, unknown>; disabled: boolean }> {
  const raw = config.smtpServerId;
  if (raw === undefined || raw === null || raw === '') return { config, disabled: false };

  const id = Number(raw);
  let usable = Number.isInteger(id) && id > 0;
  if (usable) {
    // Own relay or a platform relay (tenant_id IS NULL) — the same rule
    // `smtpServerService.getById` applies outside the transaction.
    const row = await trx('smtp_servers')
      .where({ id })
      .where(function () {
        this.where('tenant_id', tenantId).orWhereNull('tenant_id');
      })
      .first('id');
    usable = !!row;
  }
  if (usable) return { config, disabled: false };

  const { smtpServerId: _dropped, ...rest } = config;
  warnings.push(
    `Channel "${channelName}": smtpServerId ${String(raw)} does not belong to this tenant ` +
      '(and is not a platform relay). The reference was dropped and the channel imported ' +
      'disabled — pick a relay of this tenant before enabling it.',
  );
  return { config: rest, disabled: true };
}

// -- Controller ---------------------------------------------------------------

export const importExportController = {

  // -- EXPORT ----------------------------------------------------------------

  async exportData(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const rawSections = (req.query.sections as string | undefined) ?? '';
      const requested = rawSections ? rawSections.split(',').map((s) => s.trim()).filter(Boolean) : [];

      const unknown = requested.filter((s) => s !== 'all' && !isSection(s));
      if (unknown.length > 0) {
        throw new AppError(400, `Unknown section(s): ${unknown.join(', ')}`);
      }

      const all = requested.length === 0 || requested.includes('all');
      const selected: ExportSection[] = all ? [...SECTIONS] : (requested as ExportSection[]);
      const want = (s: ExportSection) => selected.includes(s);

      // AUDIT-SEC #2 / AUDIT-CORR 4.1 — was `req.session.currentTenantId ?? 1`,
      // i.e. the MASTER tenant for any admin session with no current tenant.
      // `requireTenant` (importExport.routes.ts) now guarantees req.tenantId.
      const tenantId = req.tenantId;
      const tenant = await db('tenants').where({ id: tenantId }).first('slug') as { slug: string } | undefined;

      const entities: Record<string, unknown[]> = {};

      // Group id -> uuid, needed by settings, bindings and team permissions.
      const groupRows = await db('device_groups')
        .where({ tenant_id: tenantId })
        .orderBy('sort_order')
        .orderBy('name')
        .select('id', 'uuid', 'name', 'description', 'parent_id', 'sort_order', 'is_general', 'group_notifications');
      const groupUuidById = new Map<number, string>(groupRows.map((g) => [g.id as number, g.uuid as string]));

      // -- Device groups (the site / equipment tree) ---------------------------
      if (want('deviceGroups')) {
        entities.deviceGroups = groupRows.map((g) => ({
          uuid: g.uuid,
          name: g.name,
          description: g.description,
          parentUuid: g.parent_id != null ? (groupUuidById.get(g.parent_id) ?? null) : null,
          sortOrder: g.sort_order,
          isGeneral: g.is_general,
          groupNotifications: g.group_notifications,
        }));
      }

      // -- Hierarchical settings ------------------------------------------------
      // Device-scoped settings are skipped: `devices` does not exist yet, so a
      // scope='device' row cannot be resolved to a portable uuid. Emitting it
      // would break the "everything exported is importable" rule.
      if (want('settings')) {
        const settings = await db('settings')
          .where({ tenant_id: tenantId })
          .whereIn('scope', ['global', 'group'])
          .orderBy('scope')
          .orderBy('scope_id')
          .orderBy('key');

        entities.settings = settings
          .map((s) => ({
            scope: s.scope,
            scopeUuid: s.scope === 'group' ? (groupUuidById.get(s.scope_id) ?? null) : null,
            key: s.key,
            value: s.value,
          }))
          .filter((s) => s.scope === 'global' || s.scopeUuid !== null);
      }

      // -- Notification channels + their bindings --------------------------------
      // `config` holds webhook URLs and bot tokens, i.e. credentials. It is
      // ALWAYS exported redacted; the import side then keeps whatever the
      // target already had, and creates unknown channels disabled.
      //
      // AUDIT-SEC #10 — this used to honour `?includeSecrets=true`, which
      // handed back every Discord/Slack/Teams webhook URL and every bot token
      // of the tenant in one downloadable JSON file. That flag contradicted
      // this file's own contract ("SECRETS ARE NEVER EXPORTED", top of file)
      // and, once `GET /api/notifications/channels` started redacting, it was
      // simply the same leak one route to the left — the identical
      // "two paths, one fixed" shape as #18 and #19 below. It is gone: a
      // bundle is a plain JSON file that travels by e-mail and chat, and no
      // query parameter should turn it into a credential dump.
      if (want('notificationChannels')) {
        const channels = await db('notification_channels').where({ tenant_id: tenantId }).orderBy('id');
        const channelIds = channels.map((c) => c.id as number);
        // `notification_bindings.tenant_id` exists since the fix of audit-corr
        // §1.2. A channel shared to several tenants carries one binding row PER
        // tenant; exporting them all would ship another client's routing.
        const bindings = channelIds.length
          ? await db('notification_bindings')
              .where({ tenant_id: tenantId })
              .whereIn('channel_id', channelIds)
              .orderBy('channel_id')
          : [];

        entities.notificationChannels = channels.map((c) => ({
          uuid: c.uuid,
          name: c.name,
          type: c.type,
          config: null,
          configRedacted: true,
          isEnabled: c.is_enabled,
          bindings: bindings
            .filter((b) => b.channel_id === c.id)
            .map((b) => ({
              scope: b.scope,
              scopeUuid: b.scope === 'group' ? (groupUuidById.get(b.scope_id) ?? null) : null,
              overrideMode: b.override_mode,
            }))
            .filter((b) => b.scope === 'global' || b.scopeUuid !== null),
        }));
      }

      // -- Teams + permissions (memberships excluded: users are never exported) ---
      if (want('teams')) {
        const teams = await db('user_teams').where({ tenant_id: tenantId }).orderBy('id');
        const teamIds = teams.map((t) => t.id as number);
        const permissions = teamIds.length
          ? await db('team_permissions').whereIn('team_id', teamIds).orderBy('team_id')
          : [];

        entities.teams = teams.map((t) => ({
          uuid: t.uuid,
          name: t.name,
          description: t.description,
          canCreate: t.can_create,
          permissions: permissions
            .filter((p) => p.team_id === t.id && p.scope === 'group')
            .map((p) => ({
              scope: 'group',
              scopeUuid: groupUuidById.get(p.scope_id) ?? null,
              level: p.level,
              capabilities: Array.isArray(p.capabilities)
                ? sanitizeCapabilities(p.capabilities as unknown[])
                : null,
            }))
            .filter((p) => p.scopeUuid !== null),
        }));
      }

      const payload = {
        meta: {
          formatVersion: FORMAT_VERSION,
          producedBy: 'obliwan',
          producedAt: new Date().toISOString(),
          sourceInstance: process.env.APP_URL ?? null,
          tenantSlug: tenant?.slug ?? 'unknown',
          entityCounts: Object.fromEntries(
            Object.entries(entities).map(([k, v]) => [k, v.length]),
          ),
        },
        sections: selected,
        entities,
        // Kept at the top level too, so an operator can diff two bundles without
        // learning the envelope.
        ...entities,
      };

      const filename = `obliwan-export-${new Date().toISOString().slice(0, 10)}.json`;
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Type', 'application/json');
      res.json(payload);
    } catch (err) {
      next(err);
    }
  },

  // -- IMPORT ----------------------------------------------------------------

  async importData(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const {
        sections,
        data,
        conflictStrategy = 'update',
      } = req.body as {
        sections: string[];
        data: Record<string, unknown>;
        conflictStrategy: ConflictStrategy;
      };

      if (!Array.isArray(sections) || sections.length === 0) {
        throw new AppError(400, 'sections array is required');
      }
      const unknownSections = sections.filter((s) => !isSection(s));
      if (unknownSections.length > 0) {
        throw new AppError(400, `Unknown section(s): ${unknownSections.join(', ')}`);
      }
      if (!data || typeof data !== 'object') {
        throw new AppError(400, 'data object is required');
      }
      if (!CONFLICT_STRATEGIES.includes(conflictStrategy)) {
        throw new AppError(400, `conflictStrategy must be one of: ${CONFLICT_STRATEGIES.join(', ')}`);
      }

      // Accept both the enveloped bundle ({ entities: {...} }) and the flat
      // legacy shape, so an older export still restores.
      const bundle = (data.entities && typeof data.entities === 'object'
        ? data.entities
        : data) as Record<string, unknown>;

      const want = (s: ExportSection) => sections.includes(s);
      // AUDIT-SEC #2 / AUDIT-CORR 4.1 — was `req.session.currentTenantId ?? 1`,
      // i.e. the MASTER tenant for any admin session with no current tenant.
      // `requireTenant` (importExport.routes.ts) now guarantees req.tenantId.
      const tenantId = req.tenantId;
      const results: Record<string, SectionResult> = {};

      await db.transaction(async (trx) => {
        // -- Existing UUID -> id maps, scoped to the target tenant --------------
        const groupIdByUuid = new Map<string, number>();
        const channelIdByUuid = new Map<string, number>();
        const teamIdByUuid = new Map<string, number>();

        for (const r of await trx('device_groups').where({ tenant_id: tenantId }).select('id', 'uuid'))
          groupIdByUuid.set(r.uuid, r.id);
        for (const r of await trx('notification_channels').where({ tenant_id: tenantId }).select('id', 'uuid'))
          channelIdByUuid.set(r.uuid, r.id);
        for (const r of await trx('user_teams').where({ tenant_id: tenantId }).select('id', 'uuid'))
          teamIdByUuid.set(r.uuid, r.id);

        // Original-UUID -> new id for items created in THIS run, so a child can
        // resolve a parent that generateNew just gave a fresh UUID to.
        const batchGroupByOrigUuid = new Map<string, number>();

        const resolveGroup = (uuid: string | null | undefined): number | null => {
          if (!uuid) return null;
          return batchGroupByOrigUuid.get(uuid) ?? groupIdByUuid.get(uuid) ?? null;
        };

        // -- Cross-tenant UUID collision pre-check ------------------------------
        // The uuid columns are UNIQUE across the WHOLE table, not per tenant. If
        // an imported UUID belongs to a DIFFERENT tenant we must neither INSERT
        // it (unique violation -> 500) nor UPDATE it (silently mutating another
        // tenant's data). Those are forced to 'generateNew' whatever the caller
        // asked for.
        const listOf = (key: string): Record<string, unknown>[] =>
          Array.isArray(bundle[key]) ? (bundle[key] as Record<string, unknown>[]) : [];

        const uuidsOf = (key: string): string[] =>
          listOf(key).map((i) => i.uuid).filter((u): u is string => typeof u === 'string');

        const foreignUuids = async (
          table: string,
          uuids: string[],
        ): Promise<Set<string>> => {
          if (uuids.length === 0) return new Set();
          const rows = await trx(table)
            .whereIn('uuid', uuids)
            .whereNot({ tenant_id: tenantId })
            .pluck('uuid');
          return new Set<string>(rows as string[]);
        };

        const foreignGroupUuids = await foreignUuids('device_groups', uuidsOf('deviceGroups'));
        const foreignChannelUuids = await foreignUuids('notification_channels', uuidsOf('notificationChannels'));
        const foreignTeamUuids = await foreignUuids('user_teams', uuidsOf('teams'));

        /**
         * Decide the effective (uuid, action) for one incoming item.
         *   no UUID                    -> create with a fresh one
         *   UUID owned by another tenant -> create with a fresh one (forced)
         *   UUID absent from this tenant -> create, keeping the UUID
         *   UUID already here           -> apply conflictStrategy
         */
        type Decision =
          | { action: 'create'; uuid: string }
          | { action: 'update'; uuid: string; existingId: number }
          | { action: 'skip' };

        function resolveConflict(
          inputUuid: unknown,
          idMap: Map<string, number>,
          foreign: Set<string>,
        ): Decision {
          if (typeof inputUuid !== 'string' || !inputUuid) {
            return { action: 'create', uuid: randomUUID() };
          }
          if (foreign.has(inputUuid)) {
            return { action: 'create', uuid: randomUUID() };
          }
          const existingId = idMap.get(inputUuid);
          if (existingId === undefined) {
            return { action: 'create', uuid: inputUuid };
          }
          if (conflictStrategy === 'update') return { action: 'update', uuid: inputUuid, existingId };
          if (conflictStrategy === 'generateNew') return { action: 'create', uuid: randomUUID() };
          return { action: 'skip' };
        }

        // -- Device groups -------------------------------------------------------
        if (want('deviceGroups')) {
          let created = 0, updated = 0, skipped = 0;

          // VERIF-SECFIX-AUTRES #8 — a cycle in `parentUuid` used to be ordered
          // arbitrarily and processed anyway, which made `reparentGroupClosure`
          // reinsert a `(g, g)` pair and blow up on `group_closure_pkey`: a bare
          // 500, the WHOLE bundle rolled back, and nothing telling the operator
          // which lines of the JSON to fix. Refuse BEFORE writing anything, and
          // name every offending uuid in one pass rather than one per attempt.
          let sorted: Record<string, unknown>[];
          try {
            sorted = topoSort(listOf('deviceGroups'), 'uuid', 'parentUuid');
          } catch (err) {
            if (!(err instanceof CycleError)) throw err;
            const all = findCycles(listOf('deviceGroups'), 'uuid', 'parentUuid');
            const names = new Map<string, string>();
            for (const g of listOf('deviceGroups')) {
              if (typeof g.uuid === 'string' && typeof g.name === 'string') names.set(g.uuid, g.name);
            }
            const listed = (all.length > 0 ? all : err.allCyclicKeys)
              .map((u) => (names.has(u) ? `"${names.get(u)}" (${u})` : u))
              .join(', ');
            throw new AppError(
              400,
              'Import aborted: deviceGroups contains a circular parentUuid reference, ' +
                'so no group could be placed and nothing was imported. ' +
                `Set parentUuid to null (or to a group outside the loop) on: ${listed}. ` +
                `Shortest loop found: ${err.cycle.join(' -> ')}.`,
            );
          }

          for (const g of sorted) {
            if (!g.name) { skipped++; continue; }

            const decision = resolveConflict(g.uuid, groupIdByUuid, foreignGroupUuids);
            const parentId = resolveGroup(g.parentUuid as string | null | undefined);

            if (decision.action === 'skip') {
              // Still register the mapping so children resolve their parent.
              const existing = groupIdByUuid.get(g.uuid as string);
              if (existing !== undefined) batchGroupByOrigUuid.set(g.uuid as string, existing);
              skipped++;
              continue;
            }

            if (decision.action === 'update') {
              await trx('device_groups').where({ uuid: decision.uuid, tenant_id: tenantId }).update({
                name: g.name,
                description: (g.description as string | null) ?? null,
                sort_order: (g.sortOrder as number) ?? 0,
                is_general: (g.isGeneral as boolean) ?? false,
                group_notifications: (g.groupNotifications as boolean) ?? false,
                parent_id: parentId,
                updated_at: new Date(),
              });
              // A changed parent MUST be reflected in the closure table.
              await reparentGroupClosure(trx, decision.existingId, parentId);
              batchGroupByOrigUuid.set(decision.uuid, decision.existingId);
              if (typeof g.uuid === 'string') batchGroupByOrigUuid.set(g.uuid, decision.existingId);
              updated++;
            } else {
              const slug = await ensureUniqueSlugTrx(trx, slugify(g.name as string), tenantId);
              const [row] = await trx('device_groups').insert({
                uuid: decision.uuid,
                name: g.name,
                slug,
                description: (g.description as string | null) ?? null,
                parent_id: parentId,
                sort_order: (g.sortOrder as number) ?? 0,
                is_general: (g.isGeneral as boolean) ?? false,
                group_notifications: (g.groupNotifications as boolean) ?? false,
                tenant_id: tenantId,
              }).returning('id');

              await insertGroupClosure(trx, row.id, parentId);
              groupIdByUuid.set(decision.uuid, row.id);
              batchGroupByOrigUuid.set(decision.uuid, row.id);
              if (typeof g.uuid === 'string') batchGroupByOrigUuid.set(g.uuid, row.id);
              created++;
            }
          }
          results.deviceGroups = { created, updated, skipped };
        }

        // -- Settings -------------------------------------------------------------
        if (want('settings')) {
          let created = 0, skipped = 0;

          for (const s of listOf('settings')) {
            if (!s.scope || !s.key) { skipped++; continue; }
            const scope = s.scope as string;
            if (scope !== 'global' && scope !== 'group') { skipped++; continue; }

            let scopeId: number | null = null;
            if (scope === 'group') {
              scopeId = resolveGroup(s.scopeUuid as string | null | undefined);
              if (scopeId === null) { skipped++; continue; }
            }

            // VERIF-SECFIX-AUTRES #18 — same validation as the API (see
            // parseSettingValue) and the SAME write path: `_write` names the
            // partial unique index explicitly, which is what the previous
            // DELETE-then-INSERT existed to avoid having to do.
            const { key, value } = parseSettingValue(s.key, s.value);
            await settingsService._write(trx, tenantId, scope, scopeId, key, value);
            created++;
          }
          results.settings = { created, updated: 0, skipped };
        }

        // -- Notification channels ------------------------------------------------
        if (want('notificationChannels')) {
          let created = 0, updated = 0, skipped = 0;
          const warnings: string[] = [];

          for (const c of listOf('notificationChannels')) {
            if (!c.name || !c.type) { skipped++; continue; }

            const decision = resolveConflict(c.uuid, channelIdByUuid, foreignChannelUuids);
            if (decision.action === 'skip') { skipped++; continue; }

            // A redacted export carries no config. Updating an existing channel
            // must then LEAVE its secrets alone; creating one yields a disabled
            // channel the operator has to fill in, never a silently broken one.
            const redacted = c.configRedacted === true || c.config == null;
            let parsedConfig: Record<string, unknown> = {};
            if (!redacted) {
              try {
                parsedConfig = (typeof c.config === 'string'
                  ? JSON.parse(c.config)
                  : c.config) as Record<string, unknown>;
              } catch {
                skipped++;
                warnings.push(`Channel "${String(c.name)}": config is not valid JSON, channel skipped.`);
                continue;
              }
              if (!parsedConfig || typeof parsedConfig !== 'object') parsedConfig = {};
            }

            // VERIF-SECFIX-AUTRES #6 (import side) — see scrubForeignSmtpRef.
            const scrubbed = redacted
              ? { config: parsedConfig, disabled: false }
              : await scrubForeignSmtpRef(trx, parsedConfig, tenantId, String(c.name), warnings);
            const configValue = JSON.stringify(scrubbed.config);

            // Enablement. A redacted bundle says nothing about the config, so
            // what it implies depends on whether the channel already exists:
            //   create + redacted -> DISABLED. There is no config at all; an
            //     enabled channel with an empty config fails on the first
            //     outage, which is the worst moment to discover it.
            //   update + redacted -> the stored config (secret included) is
            //     left untouched a few lines below, so the channel still works.
            //     Forcing it off here would mean "restoring your own backup
            //     silently switches off all your alerting" — and since every
            //     export is redacted (see the note in exportData), that would
            //     be EVERY restore. Honour the flag the bundle carries.
            // `scrubbed.disabled` always wins: a channel whose smtpServerId was
            // dropped must not fire through a relay it no longer names.
            const isCreate = decision.action !== 'update';
            const channelRow: Record<string, unknown> = {
              name: c.name,
              type: c.type,
              is_enabled:
                scrubbed.disabled || (redacted && isCreate)
                  ? false
                  : ((c.isEnabled as boolean) ?? true),
              tenant_id: tenantId,
              updated_at: new Date(),
            };
            if (!redacted) channelRow.config = configValue;

            let channelId: number;
            if (decision.action === 'update') {
              await trx('notification_channels').where({ uuid: decision.uuid, tenant_id: tenantId }).update(channelRow);
              channelId = decision.existingId;
              updated++;
            } else {
              const [inserted] = await trx('notification_channels')
                .insert({ ...channelRow, config: redacted ? '{}' : configValue, uuid: decision.uuid })
                .returning('id');
              channelId = inserted.id;
              channelIdByUuid.set(decision.uuid, channelId);
              if (typeof c.uuid === 'string') channelIdByUuid.set(c.uuid, channelId);
              created++;
            }

            // Rebuild the bindings from the bundle (delete then re-insert).
            if (Array.isArray(c.bindings)) {
              // Scoped to the importing tenant: a channel shared with another
              // tenant keeps ITS bindings (audit-corr §1.2).
              await trx('notification_bindings')
                .where({ channel_id: channelId, tenant_id: tenantId })
                .del();
              for (const b of c.bindings as Record<string, unknown>[]) {
                const bScope = b.scope as string;
                if (bScope !== 'global' && bScope !== 'group') continue;

                // AUDIT-CORR §4.3 — override_mode used to be taken verbatim.
                // A "Replace" from a hand-edited bundle was stored and then
                // silently treated as a merge: a group meant to alert ONLY its
                // dedicated channel started notifying every inherited one.
                // The CHECK added in migration 001 would now abort the whole
                // import transaction, so filter here and report it as skipped.
                const mode = (b.overrideMode as string) ?? 'merge';
                if (mode !== 'merge' && mode !== 'replace' && mode !== 'exclude') {
                  skipped++;
                  continue;
                }

                let bScopeId: number | null = null;
                if (bScope === 'group') {
                  bScopeId = resolveGroup(b.scopeUuid as string | null | undefined);
                  if (bScopeId === null) continue;
                }

                await trx('notification_bindings').insert({
                  tenant_id: tenantId,
                  channel_id: channelId,
                  scope: bScope,
                  scope_id: bScopeId,
                  override_mode: mode,
                });
              }
            }
          }
          results.notificationChannels = warnings.length
            ? { created, updated, skipped, warnings }
            : { created, updated, skipped };
        }

        // -- Teams ----------------------------------------------------------------
        if (want('teams')) {
          let created = 0, updated = 0, skipped = 0;

          for (const t of listOf('teams')) {
            if (!t.name) { skipped++; continue; }

            const decision = resolveConflict(t.uuid, teamIdByUuid, foreignTeamUuids);
            if (decision.action === 'skip') { skipped++; continue; }

            const teamRow: Record<string, unknown> = {
              name: t.name,
              description: (t.description as string | null) ?? null,
              can_create: (t.canCreate as boolean) ?? false,
              tenant_id: tenantId,
              updated_at: new Date(),
            };

            let teamId: number;
            if (decision.action === 'update') {
              // user_teams.name is globally UNIQUE: a rename onto a name another
              // team already holds must not abort the whole import.
              const nameOwner = await trx('user_teams').where({ name: t.name, tenant_id: tenantId }).first('id') as { id: number } | undefined;
              if (nameOwner && nameOwner.id !== decision.existingId) {
                delete teamRow.name;
              }
              await trx('user_teams').where({ uuid: decision.uuid, tenant_id: tenantId }).update(teamRow);
              teamId = decision.existingId;
              updated++;
            } else {
              const nameConflict = await trx('user_teams').where({ name: t.name, tenant_id: tenantId }).first();
              if (nameConflict) { skipped++; continue; }

              const [inserted] = await trx('user_teams').insert({ ...teamRow, uuid: decision.uuid }).returning('id');
              teamId = inserted.id;
              teamIdByUuid.set(decision.uuid, teamId);
              if (typeof t.uuid === 'string') teamIdByUuid.set(t.uuid, teamId);
              created++;
            }

            if (Array.isArray(t.permissions)) {
              // VERIF-SECFIX-AUTRES #19 / AUDIT-CORR §5.1 — the DELETE below
              // used to drop `capabilities` on the floor. A bundle whose team
              // entries carry no `capabilities` key (every bundle produced
              // before FORMAT_VERSION 2, and every hand-written one) silently
              // wiped every capability pinned onto that team's grants, on a
              // column no screen displays: the operator restores a backup and
              // discovers weeks later that half his delegated rights are gone.
              //
              // `teamService.setPermissions` solved this exact problem by
              // reading the pinned lists back BEFORE the delete and re-attaching
              // them to the (scope, scope_id) pairs that survive the edit. Two
              // write paths onto `team_permissions`, one corrected and one not,
              // is precisely the divergence this pass exists to close — so the
              // import now follows the same rule, with one difference stated
              // explicitly: a bundle that DOES carry `capabilities` is an
              // intentional statement and overrides the pinned list (including
              // an empty array, which clears it).
              const previous = await trx('team_permissions')
                .where({ team_id: teamId })
                .whereNotNull('capabilities')
                .select('scope', 'scope_id', 'capabilities');
              const pinned = new Map<string, unknown>(
                previous.map((p) => [`${p.scope}:${p.scope_id}`, p.capabilities]),
              );

              await trx('team_permissions').where({ team_id: teamId }).del();
              for (const p of t.permissions as Record<string, unknown>[]) {
                if (p.scope !== 'group') continue;
                const scopeId = resolveGroup(p.scopeUuid as string | null | undefined);
                if (scopeId === null) continue;

                let capabilities: string | null;
                if (Array.isArray(p.capabilities)) {
                  // Capabilities are re-validated against the current
                  // vocabulary: a bundle from an older instance may name
                  // capabilities that no longer exist, and those must not be
                  // persisted.
                  const caps = sanitizeCapabilities(p.capabilities as unknown[]);
                  capabilities = caps.length > 0 ? JSON.stringify(caps) : null;
                } else {
                  // Absent (or null) means "the bundle says nothing about
                  // capabilities" — carry what this instance already had.
                  const carried = pinned.get(`group:${scopeId}`);
                  // knex needs a string (or null) for a jsonb column; the pg
                  // driver hands `capabilities` back already parsed.
                  capabilities =
                    carried === undefined || carried === null
                      ? null
                      : typeof carried === 'string'
                        ? carried
                        : JSON.stringify(carried);
                }

                await trx('team_permissions').insert({
                  team_id: teamId,
                  scope: 'group',
                  scope_id: scopeId,
                  level: p.level === 'rw' ? 'rw' : 'ro',
                  capabilities,
                }).onConflict(['team_id', 'scope', 'scope_id']).ignore();
              }
            }
          }
          results.teams = { created, updated, skipped };
        }
      }); // end transaction

      res.json({ success: true, data: results });
    } catch (err) {
      next(err);
    }
  },
};
