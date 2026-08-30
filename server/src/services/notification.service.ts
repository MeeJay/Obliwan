import { db } from '../db';
import type { NotificationChannel, NotificationBinding, NotificationTypeConfig, OverrideMode } from '@obliwan/shared';
import { DEFAULT_NOTIFICATION_TYPES } from '@obliwan/shared';
import type { NotificationPayload } from '../notifications/types';
import { getPlugin } from '../notifications/registry';
import { smtpServerService } from './smtpServer.service';
import { config } from '../config';
import { logger } from '../utils/logger';

interface ChannelRow {
  id: number;
  name: string;
  type: string;
  config: Record<string, unknown>;
  is_enabled: boolean;
  created_by: number | null;
  tenant_id: number;
  created_at: Date;
  updated_at: Date;
}

interface BindingRow {
  id: number;
  channel_id: number;
  scope: string;
  scope_id: number | null;
  override_mode: string;
  tenant_id: number;
}

function rowToChannel(row: ChannelRow, currentTenantId?: number): NotificationChannel {
  const ch: NotificationChannel = {
    id: row.id,
    name: row.name,
    type: row.type,
    config: typeof row.config === 'string' ? JSON.parse(row.config) : row.config,
    isEnabled: row.is_enabled,
    createdBy: row.created_by,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
  if (currentTenantId !== undefined) {
    ch.tenantId = row.tenant_id;
    ch.isShared = row.tenant_id !== currentTenantId;
  }
  return ch;
}

/**
 * AUDIT-SEC #10, redaction half — `GET /api/notifications/channels` returned
 * `"webhookUrl":"https://discord.com/api/webhooks/AAA/SECRET"` IN CLEAR.
 *
 * A Discord/Slack/Teams webhook URL is not an address, it IS the
 * authentication: whoever holds it can post in the customer's channel, from
 * anywhere, with no other credential. Same for a Telegram bot token, a Gotify
 * application token, a Pushover key or the `secret` header of a raw webhook.
 * ARCHITECTURE §8.2: the complete value exists only IN MEMORY, on the path to
 * the target — it is written by the operator, stored, and from then on read
 * back only by the send path. It never travels outward again.
 *
 * The scoping half of #10 was closed first (the route is admin-only and the
 * channel is tenant-scoped), so this is not a cross-tenant leak today. It is a
 * blast-radius problem: a read-only XSS, an over-broad admin, a browser
 * extension, a HAR file attached to a support ticket or a proxy log is enough
 * to walk away with every customer's alerting credentials.
 *
 * The model is the one already retained for the Obligate gateway
 * (`appConfigService.getObligateConfig`): a BOOLEAN `<key>Set` saying whether a
 * value is stored, never the value.
 */

/**
 * What replaces a stored secret on the way out. It is emitted (rather than
 * dropping the key) so a form can keep rendering a non-empty `required` field
 * and be submitted back untouched; the write path maps it to "unchanged".
 */
export const REDACTED_SECRET = '••••••••';

/**
 * Fallback for a `config` blob whose plugin is unknown (a type removed from the
 * registry, or a hand-written row). Better a false positive — a redacted field
 * the operator must retype — than a token printed in an API response.
 */
const SECRET_KEY_PATTERN = /(token|secret|password|passwd|apikey|api_key|userkey|webhookurl)/i;

/**
 * Is this config key a credential?
 *
 * Driven by the plugin registry so a new plugin is covered the day it is
 * registered, with two rules:
 *  - `type: 'password'` — the plugin author already said so;
 *  - the key `webhookUrl` — declared as a `url` for the form widget, but in
 *    Discord, Slack and Teams that URL is a bearer capability. `webhook.url`
 *    is deliberately NOT in this set: it is the operator's own endpoint and
 *    its credential lives in the separate `secret` field.
 */
function isSecretConfigKey(type: string, key: string): boolean {
  const plugin = getPlugin(type);
  const field = plugin?.configFields.find((f) => f.key === key);
  if (field) return field.type === 'password' || field.key === 'webhookUrl';
  return SECRET_KEY_PATTERN.test(key);
}

/** `webhookUrl` -> `webhookUrlSet`. The mirror flag is READ-ONLY. */
function setFlagOf(key: string): string {
  return `${key}Set`;
}

/** Outbound view of a channel config: values replaced by `<key>Set` booleans. */
function redactConfig(type: string, config: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(config)) {
    if (!isSecretConfigKey(type, key)) {
      out[key] = value;
      continue;
    }
    const isSet = value !== undefined && value !== null && String(value).length > 0;
    out[key] = isSet ? REDACTED_SECRET : '';
    out[setFlagOf(key)] = isSet;
  }
  return out;
}

/**
 * Inbound merge: what the caller sent, with the stored secrets carried over.
 *
 * The ergonomic rule, and the reason this function exists: **an absent secret
 * means UNCHANGED, not empty.** Renaming a channel must not require retyping a
 * webhook URL the API refuses to show. Explicitly:
 *
 *   key absent from the payload      -> keep what is stored
 *   key sent back as REDACTED_SECRET -> keep what is stored (untouched form)
 *   key sent with a value            -> replace
 *   key sent as ''                   -> ERASE (the operator cleared the field)
 *
 * The read-only `<key>Set` mirrors are dropped: they are an output of the API,
 * and a client that echoes its GET back into a PUT must not persist them.
 */
function mergeIncomingConfig(
  type: string,
  incoming: Record<string, unknown>,
  stored: Record<string, unknown>,
): Record<string, unknown> {
  const merged: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(incoming)) {
    if (key.endsWith('Set') && isSecretConfigKey(type, key.slice(0, -3))) continue;
    if (isSecretConfigKey(type, key)) {
      if (value === REDACTED_SECRET || value === undefined) continue;
      merged[key] = value;
      continue;
    }
    merged[key] = value;
  }

  for (const [key, value] of Object.entries(stored)) {
    if (!isSecretConfigKey(type, key)) continue;
    if (!(key in merged)) merged[key] = value;
  }

  return merged;
}

function rowToBinding(row: BindingRow): NotificationBinding {
  return {
    id: row.id,
    channelId: row.channel_id,
    scope: row.scope as NotificationBinding['scope'],
    scopeId: row.scope_id,
    overrideMode: row.override_mode as OverrideMode,
  };
}

/**
 * Conflict target of the partial unique index covering a binding row.
 *
 * AUDIT-CORR §1.1 — `UNIQUE (channel_id, scope, scope_id)` constrained nothing
 * on the global scope (NULLS DISTINCT), so `addBinding`'s `onConflict` never
 * fired there: switching a global channel merge -> exclude -> merge left three
 * rows, the exclude was applied after the merges, and the operator could no
 * longer re-enable the channel from the UI.
 */
function bindingConflictTarget(scopeId: number | null) {
  return scopeId === null
    ? db.raw('(tenant_id, channel_id, scope) WHERE scope_id IS NULL')
    : db.raw('(tenant_id, channel_id, scope, scope_id) WHERE scope_id IS NOT NULL');
}

/**
 * Outbound (API) view of a channel. Everything that leaves the process through
 * an HTTP response goes through THIS, never through `rowToChannel`.
 *
 * `rowToChannel` keeps the complete config on purpose: `resolveChannelConfig`
 * and the plugins need it, and they run in-process on the path to the target.
 * The two functions sit next to each other so the difference is impossible to
 * miss when a new read is added.
 */
function rowToPublicChannel(row: ChannelRow, currentTenantId?: number): NotificationChannel {
  const ch = rowToChannel(row, currentTenantId);
  return { ...ch, config: redactConfig(ch.type, ch.config) };
}

export const notificationService = {
  // ── Channel CRUD ──

  async getAllChannels(tenantId: number): Promise<NotificationChannel[]> {
    // Own channels + channels shared to this tenant via the junction table
    const rows = await db<ChannelRow>('notification_channels')
      .where(function () {
        this.where('notification_channels.tenant_id', tenantId)
          .orWhereIn(
            'notification_channels.id',
            db('notification_channel_tenants').select('channel_id').where({ tenant_id: tenantId }),
          );
      })
      .orderBy('name');
    return rows.map((row) => rowToPublicChannel(row, tenantId));
  },

  /**
   * AUDIT-SEC #10 — had no tenant filter at all: a channel id belonging to
   * another tenant resolved, config (bot tokens, Discord/Slack webhook URLs —
   * which ARE the authentication) included. Same visibility rule as
   * getAllChannels: the channel's own tenant, or a tenant it was explicitly
   * shared to.
   */
  async getChannelById(id: number, tenantId: number): Promise<NotificationChannel | null> {
    const row = await this._channelRowById(id, tenantId);
    return row ? rowToPublicChannel(row, tenantId) : null;
  },

  /**
   * The same visibility rule as `getChannelById`, but the row with its
   * COMPLETE config. In-process callers only (send / test / merge-on-update):
   * nothing that reaches an HTTP response may use it.
   */
  async _channelRowById(id: number, tenantId: number): Promise<ChannelRow | null> {
    const row = await db<ChannelRow>('notification_channels')
      .where('notification_channels.id', id)
      .where(function () {
        this.where('notification_channels.tenant_id', tenantId)
          .orWhereIn(
            'notification_channels.id',
            db('notification_channel_tenants').select('channel_id').where({ tenant_id: tenantId }),
          );
      })
      .first();
    return row ?? null;
  },

  async createChannel(data: {
    name: string;
    type: string;
    config: Record<string, unknown>;
    isEnabled?: boolean;
    createdBy?: number;
  }, tenantId: number): Promise<NotificationChannel> {
    const plugin = getPlugin(data.type);
    if (!plugin) throw new Error(`Unknown notification type: ${data.type}`);

    // Nothing is stored yet, so the merge only strips the read-only `<key>Set`
    // mirrors and refuses the mask as a literal value (a client that POSTs back
    // a GET must not persist "••••••••" as a webhook URL).
    const config = mergeIncomingConfig(data.type, data.config, {});

    // VERIF-SECFIX-AUTRES #6 — refuse an smtpServerId this tenant may not use
    // at the moment it is typed, not at the moment of the incident.
    await this._assertConfigResourcesInTenant(config, tenantId);

    const [row] = await db<ChannelRow>('notification_channels')
      .insert({
        name: data.name,
        type: data.type,
        config: JSON.stringify(config) as unknown as Record<string, unknown>,
        is_enabled: data.isEnabled ?? true,
        created_by: data.createdBy ?? null,
        tenant_id: tenantId,
      })
      .returning('*');

    return rowToPublicChannel(row, tenantId);
  },

  /**
   * VERIF-SECFIX R2 — `getChannelById` was scoped and this was not, which made
   * the scoping decorative: `PUT /api/notifications/channels/<id of another
   * tenant>` returned 200 WITH the channel's config in clear — the
   * Discord/Slack webhook URL, which *is* the authentication — while the
   * matching GET answered 404. `DELETE` destroyed another customer's alerting
   * from the same session, without a trace on the victim's side.
   *
   * The write rule is deliberately STRICTER than the read rule: a channel merely
   * SHARED to this tenant (notification_channel_tenants) may be read and bound,
   * but only its owning tenant may rewrite or destroy it. Sharing is a grant of
   * use, not of control.
   */
  async updateChannel(id: number, data: {
    name?: string;
    config?: Record<string, unknown>;
    isEnabled?: boolean;
  }, tenantId: number): Promise<NotificationChannel | null> {
    const updateData: Record<string, unknown> = { updated_at: new Date() };
    if (data.name !== undefined) updateData.name = data.name;
    if (data.isEnabled !== undefined) updateData.is_enabled = data.isEnabled;

    if (data.config !== undefined) {
      // AUDIT-SEC #10, ergonomic half. The API no longer hands the secret back,
      // so the client CANNOT return it, so a config PUT that omits it must not
      // be read as "clear it". Load what is stored and carry the untouched
      // secrets over — see mergeIncomingConfig for the full rule. The row is
      // read under the same OWNERSHIP predicate as the update below (owner
      // only, not merely shared), so this read cannot serve as an oracle on a
      // channel the caller may not rewrite.
      const current = await db<ChannelRow>('notification_channels')
        .where({ id, tenant_id: tenantId })
        .first();
      if (!current) return null;

      const storedConfig = (typeof current.config === 'string'
        ? JSON.parse(current.config)
        : current.config) as Record<string, unknown>;
      const merged = mergeIncomingConfig(current.type, data.config, storedConfig ?? {});
      await this._assertConfigResourcesInTenant(merged, tenantId);
      updateData.config = JSON.stringify(merged);
    }

    const [row] = await db<ChannelRow>('notification_channels')
      .where({ id, tenant_id: tenantId })
      .update(updateData)
      .returning('*');
    return row ? rowToPublicChannel(row, tenantId) : null;
  },

  async deleteChannel(id: number, tenantId: number): Promise<boolean> {
    const count = await db('notification_channels').where({ id, tenant_id: tenantId }).del();
    return count > 0;
  },

  // ── Cross-tenant channel sharing ──

  /**
   * Returns the list of tenant IDs the channel is shared to (not including its
   * own tenant), or null when the channel is not owned by `tenantId`.
   *
   * VERIF-SECFIX R2 — same asymmetry as updateChannel: the sharing list of
   * another tenant's channel was readable (and rewritable) by id alone. Who a
   * channel is shared with is the owner's business only.
   */
  async getChannelTenants(channelId: number, tenantId: number): Promise<number[] | null> {
    const owned = await db('notification_channels')
      .where({ id: channelId, tenant_id: tenantId })
      .first('id');
    if (!owned) return null;
    const rows = await db('notification_channel_tenants')
      .where({ channel_id: channelId })
      .select('tenant_id');
    return rows.map((r: { tenant_id: number }) => r.tenant_id);
  },

  /**
   * Replaces the sharing list for a channel (full replace — not additive).
   * Returns false when the channel is not owned by `tenantId`.
   */
  async setChannelTenants(channelId: number, tenantIds: number[], tenantId: number): Promise<boolean> {
    const owned = await db('notification_channels')
      .where({ id: channelId, tenant_id: tenantId })
      .first('id');
    if (!owned) return false;

    await db.transaction(async (trx) => {
      await trx('notification_channel_tenants').where({ channel_id: channelId }).del();
      if (tenantIds.length > 0) {
        await trx('notification_channel_tenants').insert(
          tenantIds.map((tenant_id) => ({ channel_id: channelId, tenant_id })),
        );
      }
    });
    return true;
  },

  /**
   * VERIF-SECFIX-AUTRES #6 — a channel's `config` is validated as
   * `z.record(z.unknown())`: a free blob. `smtpServerId` inside it is a bare id
   * with no foreign key, so tenant A could name tenant B's private relay and
   * make ObliWAN authenticate to `smtp.globex.local` with Globex's service
   * account to send mail in Acme's name. The refusal belongs at WRITE time, so
   * the operator hears about it while typing, not during an outage.
   */
  async _assertConfigResourcesInTenant(
    cfg: Record<string, unknown>,
    tenantId: number,
  ): Promise<void> {
    const raw = cfg.smtpServerId;
    if (raw === undefined || raw === null || raw === '') return;
    const smtpServerId = Number(raw);
    if (!Number.isInteger(smtpServerId) || smtpServerId <= 0) {
      throw new Error('Unknown notification config: smtpServerId must be a positive integer');
    }
    const usable = await smtpServerService.isUsableBy(smtpServerId, tenantId);
    if (!usable) {
      // Deliberately the same wording whether the row belongs to another tenant
      // or does not exist: no existence oracle on another customer's relays.
      throw new Error(`Unknown notification config: SMTP server #${smtpServerId} not found`);
    }
  },

  /**
   * Resolve the effective config for a channel.
   * For smtp channels using smtpServerId, fetches the SMTP server and injects its credentials.
   * For all other channels, returns config as-is (backward-compat).
   *
   * `tenantId` is the tenant that OWNS the channel (`ChannelRow.tenant_id`), not
   * the tenant of the caller: a channel shared to another tenant keeps using
   * its owner's relay. Rows written before the write-time check above are
   * caught here too, so a pre-existing bad blob cannot fire.
   */
  async resolveChannelConfig(
    channel: NotificationChannel,
    tenantId: number,
  ): Promise<Record<string, unknown>> {
    if (channel.type === 'smtp' && channel.config.smtpServerId) {
      const server = await smtpServerService.getTransportConfig(
        Number(channel.config.smtpServerId),
        tenantId,
      );
      if (!server) throw new Error(`SMTP server #${channel.config.smtpServerId} not found`);
      return {
        host: server.host,
        port: server.port,
        secure: server.secure,
        username: server.username,
        password: server.password,
        from: channel.config.fromOverride || server.fromAddress,
        to: channel.config.to,
      };
    }
    return channel.config;
  },

  async testChannel(id: number, tenantId: number): Promise<void> {
    // The COMPLETE config, deliberately: a test that fired with the redacted
    // view would POST to "••••••••" and report a failure the operator cannot
    // explain. This is the in-memory path to the target of ARCHITECTURE §8.2.
    const row = await this._channelRowById(id, tenantId);
    if (!row) throw new Error('Channel not found');
    const channel = rowToChannel(row, tenantId);

    const plugin = getPlugin(channel.type);
    if (!plugin) throw new Error(`No plugin for type: ${channel.type}`);

    // A channel shared to this tenant is tested through ITS OWNER's relay, not
    // through a relay of the caller's tenant.
    const resolvedConfig = await this.resolveChannelConfig(channel, channel.tenantId ?? tenantId);
    await plugin.sendTest(resolvedConfig);
  },

  // ── Bindings ──

  /**
   * AUDIT-CORR §1.2 (CRITIQUE) — `tenantId` is the FIRST parameter, mandatory
   * and without default. Every binding read used to be tenant-blind, so
   * tenant 1's global Discord binding fired for tenant 2's devices.
   */
  async getBindings(
    tenantId: number,
    scope: string,
    scopeId: number | null,
  ): Promise<NotificationBinding[]> {
    const rows = await db<BindingRow>('notification_bindings')
      .where({ tenant_id: tenantId, scope, scope_id: scopeId });
    return rows.map(rowToBinding);
  },

  async addBinding(
    tenantId: number,
    channelId: number,
    scope: string,
    scopeId: number | null,
    overrideMode: OverrideMode = 'merge',
  ): Promise<NotificationBinding> {
    const [row] = await db<BindingRow>('notification_bindings')
      .insert({
        tenant_id: tenantId,
        channel_id: channelId,
        scope,
        scope_id: scopeId,
        override_mode: overrideMode,
      })
      .onConflict(bindingConflictTarget(scopeId))
      .merge({ override_mode: overrideMode })
      .returning('*');
    return rowToBinding(row);
  },

  async removeBinding(
    tenantId: number,
    channelId: number,
    scope: string,
    scopeId: number | null,
  ): Promise<boolean> {
    const count = await db('notification_bindings')
      .where({ tenant_id: tenantId, channel_id: channelId, scope, scope_id: scopeId })
      .del();
    return count > 0;
  },

  // ── Resolution (merge/replace/exclude inheritance) ──

  /**
   * Apply a set of bindings to the current channel set.
   * 1. If any binding has 'replace' mode → clear the set first
   * 2. Add all 'merge' (and 'replace') bindings to the set
   * 3. Remove all 'exclude' bindings from the set
   */
  _applyBindings(channelIds: Set<number>, bindings: NotificationBinding[]): Set<number> {
    if (bindings.length === 0) return channelIds;

    const hasReplace = bindings.some((b) => b.overrideMode === 'replace');
    if (hasReplace) {
      channelIds = new Set();
    }

    // Add merge/replace bindings
    for (const b of bindings) {
      if (b.overrideMode !== 'exclude') {
        channelIds.add(b.channelId);
      }
    }

    // Remove exclude bindings
    for (const b of bindings) {
      if (b.overrideMode === 'exclude') {
        channelIds.delete(b.channelId);
      }
    }

    return channelIds;
  },

  /**
   * Resolve which channels should fire for a given device.
   * Chain: Global → Group ancestors (root→leaf) → Device
   * 'merge' = add to parent channels, 'replace' = discard parent channels at that level,
   * 'exclude' = remove a specific channel from the inherited set.
   */
  async resolveChannelsForDevice(
    tenantId: number,
    deviceId: number,
    groupId: number | null,
  ): Promise<number[]> {
    let channelIds: Set<number> = new Set();

    // 1. Global bindings
    const globalBindings = await this.getBindings(tenantId, 'global', null);
    channelIds = this._applyBindings(channelIds, globalBindings);

    // 2. Group chain (root → leaf)
    if (groupId !== null) {
      for (const row of await this._ancestorIds(tenantId, groupId, true)) {
        const groupBindings = await this.getBindings(tenantId, 'group', row);
        channelIds = this._applyBindings(channelIds, groupBindings);
      }
    }

    // 3. Device bindings
    const deviceBindings = await this.getBindings(tenantId, 'device', deviceId);
    channelIds = this._applyBindings(channelIds, deviceBindings);

    return Array.from(channelIds);
  },

  /**
   * Ancestor ids of `groupId`, root -> leaf, restricted to `tenantId`.
   * The tenant filter on device_groups is what stops a cross-tenant closure
   * edge (AUDIT-SEC #9) from dragging another client's bindings in.
   */
  async _ancestorIds(tenantId: number, groupId: number, includeSelf: boolean): Promise<number[]> {
    const q = db('group_closure')
      .join('device_groups', 'device_groups.id', 'group_closure.ancestor_id')
      .where('group_closure.descendant_id', groupId)
      .where('device_groups.tenant_id', tenantId)
      .orderBy('group_closure.depth', 'desc')
      .pluck('group_closure.ancestor_id');
    if (!includeSelf) q.where('group_closure.depth', '>', 0);
    return q;
  },

  /**
   * Resolve bindings for a scope WITH source info (for the UI).
   * Shows which channels are active and where they come from.
   * Also tracks excluded channels so the UI can show "Unbind" state.
   */
  async resolveBindingsWithSources(
    tenantId: number,
    scope: 'group' | 'device',
    scopeId: number,
    groupId?: number | null,
  ): Promise<{
    channelId: number;
    channelName: string;
    channelType: string;
    source: 'global' | 'group' | 'device';
    sourceId: number | null;
    sourceName: string;
    isDirect: boolean;
    isExcluded: boolean;
  }[]> {
    interface SourceInfo {
      channelId: number;
      source: 'global' | 'group' | 'device';
      sourceId: number | null;
      sourceName: string;
      isDirect: boolean;
      isExcluded: boolean;
    }

    // Build the inheritance chain
    const result: Map<number, SourceInfo> = new Map();
    // Track excluded channel IDs separately for the final output
    const excludedSet: Set<number> = new Set();

    const applyBindingsWithSources = (
      bindings: NotificationBinding[],
      source: SourceInfo['source'],
      sourceId: number | null,
      sourceName: string,
      isDirect: boolean,
    ) => {
      if (bindings.length === 0) return;

      const hasReplace = bindings.some((b) => b.overrideMode === 'replace');
      if (hasReplace) {
        result.clear();
        excludedSet.clear();
      }

      // Add merge/replace bindings
      for (const b of bindings) {
        if (b.overrideMode !== 'exclude') {
          result.set(b.channelId, {
            channelId: b.channelId,
            source,
            sourceId,
            sourceName,
            isDirect,
            isExcluded: false,
          });
          excludedSet.delete(b.channelId);
        }
      }

      // Process excludes
      for (const b of bindings) {
        if (b.overrideMode === 'exclude') {
          // Keep the entry in result (for UI to show it) but mark as excluded
          const existing = result.get(b.channelId);
          if (existing) {
            existing.isExcluded = true;
          }
          excludedSet.add(b.channelId);
        }
      }
    };

    // 1. Global bindings
    const globalBindings = await this.getBindings(tenantId, 'global', null);
    applyBindingsWithSources(globalBindings, 'global', null, 'Global', false);

    // 2. Group chain. For a group scope the group itself is excluded (its own
    // bindings are added as "Direct" in step 3); for a device scope the whole
    // ancestry including the direct group is walked.
    const chainAnchor = scope === 'group' ? scopeId : groupId;
    if (chainAnchor !== null && chainAnchor !== undefined) {
      const ancestorIds = await this._ancestorIds(tenantId, chainAnchor, scope !== 'group');
      for (const ancestorId of ancestorIds) {
        const groupBindings = await this.getBindings(tenantId, 'group', ancestorId);
        const groupRow = await db('device_groups')
          .where({ id: ancestorId, tenant_id: tenantId })
          .first('name');
        applyBindingsWithSources(
          groupBindings,
          'group',
          ancestorId,
          groupRow?.name || `Group #${ancestorId}`,
          false,
        );
      }
    }

    // 3. Direct bindings at this scope
    const directBindings = await this.getBindings(tenantId, scope, scopeId);
    applyBindingsWithSources(directBindings, scope, scopeId, 'Direct', true);

    // Enrich with channel name/type
    const channelIds = Array.from(result.keys());
    if (channelIds.length === 0) return [];

    const channels = await db<ChannelRow>('notification_channels').whereIn('id', channelIds);
    const channelMap = new Map(channels.map((c) => [c.id, c]));

    return Array.from(result.values()).map((r) => {
      const ch = channelMap.get(r.channelId);
      return {
        ...r,
        channelName: ch?.name || `Channel #${r.channelId}`,
        channelType: ch?.type || 'unknown',
      };
    });
  },

  // ── Send notifications ──

  async sendForDevice(
    tenantId: number,
    deviceId: number,
    groupId: number | null,
    payload: NotificationPayload,
  ): Promise<void> {
    const channelIds = await this.resolveChannelsForDevice(tenantId, deviceId, groupId);
    if (channelIds.length === 0) {
      logger.warn(`No notification channels resolved for device ${deviceId} (event: ${payload.newStatus}) — check global/group/device bindings`);
      return;
    }

    // Enrich payload with app name from config
    const enrichedPayload: NotificationPayload = { ...payload, appName: config.appName };

    const channels = await this._enabledChannels(tenantId, channelIds);

    for (const row of channels) {
      const channel = rowToChannel(row);
      const plugin = getPlugin(channel.type);
      if (!plugin) {
        logger.warn(`No plugin for notification type "${channel.type}"`);
        continue;
      }

      try {
        const resolvedConfig = await this.resolveChannelConfig(channel, row.tenant_id);
        await plugin.send(resolvedConfig, enrichedPayload);
        await this.logNotification(row, deviceId, 'status_change', true);
        logger.info(`Notification sent: ${channel.name} (${channel.type}) for device ${payload.entityName}`);
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error';
        await this.logNotification(row, deviceId, 'status_change', false, errMsg);
        logger.error(`Notification failed: ${channel.name} (${channel.type}): ${errMsg}`);
      }
    }
  },

  /**
   * Enabled channels among `channelIds`, restricted to what `tenantId` may use.
   *
   * AUDIT-CORR §1.2 — belt and braces: the bindings are already tenant-scoped,
   * but a channel shared to a tenant and then un-shared must stop firing, and a
   * binding row that survives a channel's move between tenants must not
   * resurrect it. Same visibility rule as getAllChannels.
   */
  async _enabledChannels(tenantId: number, channelIds: number[]): Promise<ChannelRow[]> {
    if (channelIds.length === 0) return [];
    return db<ChannelRow>('notification_channels')
      .whereIn('notification_channels.id', channelIds)
      .where({ is_enabled: true })
      .where(function () {
        this.where('notification_channels.tenant_id', tenantId)
          .orWhereIn(
            'notification_channels.id',
            db('notification_channel_tenants').select('channel_id').where({ tenant_id: tenantId }),
          );
      });
  },

  /**
   * Resolve channels for a group-level notification.
   * Chain: Global → Group ancestors (root→leaf, including the group itself).
   * No device-level bindings are included.
   */
  async resolveChannelsForGroup(tenantId: number, groupId: number): Promise<number[]> {
    let channelIds: Set<number> = new Set();

    // 1. Global bindings
    const globalBindings = await this.getBindings(tenantId, 'global', null);
    channelIds = this._applyBindings(channelIds, globalBindings);

    // 2. Group chain (root → leaf, including self via depth >= 0)
    for (const ancestorId of await this._ancestorIds(tenantId, groupId, true)) {
      const groupBindings = await this.getBindings(tenantId, 'group', ancestorId);
      channelIds = this._applyBindings(channelIds, groupBindings);
    }

    return Array.from(channelIds);
  },

  /**
   * Send a group-level notification (for grouped notifications feature).
   * Resolves channels at the group level (no device bindings) and dispatches.
   */
  async sendForGroup(
    tenantId: number,
    groupId: number,
    groupName: string,
    payload: NotificationPayload,
  ): Promise<void> {
    const channelIds = await this.resolveChannelsForGroup(tenantId, groupId);
    if (channelIds.length === 0) return;

    const enrichedPayload: NotificationPayload = { ...payload, appName: config.appName };

    const channels = await this._enabledChannels(tenantId, channelIds);

    for (const row of channels) {
      const channel = rowToChannel(row);
      const plugin = getPlugin(channel.type);
      if (!plugin) {
        logger.warn(`No plugin for notification type "${channel.type}"`);
        continue;
      }

      try {
        const resolvedConfig = await this.resolveChannelConfig(channel, row.tenant_id);
        await plugin.send(resolvedConfig, enrichedPayload);
        await this.logNotification(row, null, 'group_status_change', true);
        logger.info(`Group notification sent: ${channel.name} (${channel.type}) for group "${groupName}"`);
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : 'Unknown error';
        await this.logNotification(row, null, 'group_status_change', false, errMsg);
        logger.error(`Group notification failed: ${channel.name} (${channel.type}): ${errMsg}`);
      }
    }
  },

  /**
   * AUDIT-CORR §1.5 — the channel name and type are DENORMALISED into the row,
   * because `notification_log.channel_id` is now ON DELETE SET NULL: deleting a
   * misbehaving channel must not erase the 40 failure lines that explain why it
   * misbehaved, and a log line with a NULL channel_id must still be readable.
   *
   * AUDIT-CORR §5.5 — journalling is ACCESSORY and must never abort the send
   * loop. It used to be awaited bare inside the caller's catch: a full disk or
   * a FK violation propagated out of sendForDevice and the remaining channels
   * were simply never notified.
   */
  async logNotification(
    channel: { id: number; name: string; type: string } | null,
    entityId: number | null,
    eventType: string,
    success: boolean,
    error?: string,
  ): Promise<void> {
    try {
      await db('notification_log').insert({
        channel_id: channel?.id ?? null,
        channel_name: channel?.name ?? null,
        channel_type: channel?.type ?? null,
        entity_id: entityId,
        event_type: eventType,
        success,
        error: error ?? null,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      logger.warn(`notification_log write failed (notification itself was dispatched): ${msg}`);
    }
  },
};
