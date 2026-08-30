import type { Knex } from 'knex';
import { BUILTIN_PERMISSION_SETS, ALL_CAPABILITIES } from '@obliwan/shared';

/**
 * 001_obliwan_core.ts — M1 core schema.
 *
 * Consolidates, in a SINGLE migration, what Obliguard spread over 24: auth,
 * multi-tenancy, the group tree, teams/RBAC, permission sets, hierarchical
 * settings, notifications, SMTP, app_config and live alerts.
 *
 * Deliberate departures from the Obliguard schema (arbitrage A4 — the renaming
 * is free exactly once, and this is that moment):
 *   - `monitor_groups`               -> `device_groups`
 *   - `team_permissions.scope`       -> 'group' | 'device'   (was 'group' | 'monitor')
 *   - `settings.scope`               -> 'global' | 'group' | 'device'
 *   - `notification_bindings.scope`  -> 'global' | 'group' | 'device'
 *   - `permission_sets.capabilities` -> seeded from `@obliwan/shared`
 *     (BUILTIN_PERMISSION_SETS), which is the ONE capability vocabulary.
 *
 * Deliberately NOT carried over (Obliguard IPS / Obliview probes):
 *   monitors, heartbeats, incidents, maintenance_windows, agent_api_keys,
 *   agent_devices, agent_services, remediation_*, service_templates,
 *   ip_events, ip_reputation, ip_bans, ip_whitelist, remote_blocklists,
 *   rate_limit_policies, mikrotik_*, switch_tokens, sso_link_tokens.
 *
 * The inventory (sites/devices/transports/secrets) lands in `002_inventory.ts`
 * at milestone M2, together with the `key_version` column of arbitrage A3.
 */

export async function up(knex: Knex): Promise<void> {
  // gen_random_uuid() lives in pgcrypto before PG13 and in core from PG13 on.
  // Creating the extension is a no-op when it is already built in.
  await knex.raw('CREATE EXTENSION IF NOT EXISTS pgcrypto');

  // ==========================================================================
  // SECTION 1 — Core auth
  // ==========================================================================

  await knex.schema.createTable('users', (t) => {
    t.increments('id').primary();
    t.string('username', 64).notNullable().unique();
    // NULLABLE by design: an Obligate SSO account has no local password.
    t.string('password_hash', 255).nullable();
    t.string('display_name', 128).nullable();
    t.string('role', 16).notNullable().defaultTo('user'); // 'admin' | 'user'
    t.boolean('is_active').notNullable().defaultTo(true);

    // 2FA
    t.string('email', 255).nullable();
    t.text('totp_secret').nullable();
    t.boolean('totp_enabled').notNullable().defaultTo(false);
    t.boolean('email_otp_enabled').notNullable().defaultTo(false);

    // UI preferences blob: { preferredTheme, toastEnabled, toastPosition, ... }
    t.jsonb('preferences').nullable().defaultTo(null);
    t.text('avatar').nullable();

    t.string('preferred_language', 10).notNullable().defaultTo('en');
    t.integer('enrollment_version').notNullable().defaultTo(0);

    // Federated identity (Obligate SSO). `sso_foreign_users` is the real join
    // table; these columns stay as the "primary" source for a single provider.
    t.string('foreign_source', 64).nullable().defaultTo(null);
    t.integer('foreign_id').nullable().defaultTo(null);
    t.text('foreign_source_url').nullable().defaultTo(null);

    t.timestamps(true, true);
  });
  // AUDIT-CORR §1.9 — `role` is an enumeration written by the SSO sync
  // (`sso-user-sync` action 'update-role') and by userService.create. Both
  // normalise today; the CHECK makes a future writer unable to invent a third
  // value that requireRole() would then never match.
  await knex.schema.raw(
    "ALTER TABLE users ADD CONSTRAINT users_role_chk CHECK (role IN ('admin','user'))",
  );

  // session — owned by connect-pg-simple, which runs with createTableIfMissing:false
  await knex.schema.createTable('session', (t) => {
    t.string('sid').primary();
    t.json('sess').notNullable();
    t.timestamp('expire', { useTz: true }).notNullable();
  });
  await knex.schema.raw('CREATE INDEX idx_session_expire ON session(expire)');

  await knex.schema.createTable('password_reset_tokens', (t) => {
    t.increments('id').primary();
    t.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.string('token_hash', 255).notNullable().unique();
    t.timestamp('expires_at', { useTz: true }).notNullable();
    t.timestamp('used_at', { useTz: true }).nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    // AUDIT-CORR §1.6 — every lookup and every invalidation sweep filters on
    // user_id alone; nothing else indexes it.
    t.index('user_id');
  });

  // One local user may be linked to several SSO providers.
  await knex.schema.createTable('sso_foreign_users', (t) => {
    t.increments('id').primary();
    t.string('foreign_source', 64).notNullable();
    t.integer('foreign_user_id').notNullable();
    t.integer('local_user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.timestamps(true, true);
    t.unique(['foreign_source', 'foreign_user_id']);
    // AUDIT-CORR §1.6 — the unique index above only serves the
    // (foreign_source, foreign_user_id) direction; the reverse lookup
    // ("which providers is this local user linked to") had no index.
    t.index('local_user_id');
  });

  // ==========================================================================
  // SECTION 2 — Multi-tenancy
  // ==========================================================================

  await knex.schema.createTable('tenants', (t) => {
    t.increments('id').primary();
    t.string('name', 128).notNullable();
    t.string('slug', 64).notNullable().unique();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable('user_tenants', (t) => {
    t.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.string('role', 16).notNullable().defaultTo('member'); // 'admin' | 'member'
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.primary(['user_id', 'tenant_id']);
    // AUDIT-CORR §1.6 — the PK index starts with user_id, so it cannot serve a
    // predicate on tenant_id alone (tenantService.getMembers, and the
    // membership re-check the security fix adds to requireTenant).
    t.index('tenant_id');
  });
  // AUDIT-CORR §1.9 — the tenant-role matrix that the RBAC fix derives
  // capabilities from is only meaningful if the column cannot hold anything
  // else than the two roles it knows.
  await knex.schema.raw(
    "ALTER TABLE user_tenants ADD CONSTRAINT user_tenants_role_chk CHECK (role IN ('admin','member'))",
  );

  // Master tenant — MASTER_TENANT_ID === 1 in @obliwan/shared. It sees the
  // operational data of every tenant; secrets stay partitioned regardless.
  await knex('tenants').insert({ id: 1, name: 'Default', slug: 'default' });
  // Explicit insert of id=1 leaves the sequence at 1, so the NEXT tenant would
  // collide. Realign it now rather than at the first tenant creation.
  await knex.raw(
    "SELECT setval(pg_get_serial_sequence('tenants', 'id'), (SELECT MAX(id) FROM tenants))",
  );

  // ==========================================================================
  // SECTION 3 — Group tree (sites / equipment) + closure table
  // ==========================================================================

  await knex.schema.createTable('device_groups', (t) => {
    t.increments('id').primary();
    t.string('name', 255).notNullable();
    // AUDIT-CORR §1.8 — the slug was globally unique, against the spec's
    // per-tenant convention (`sites.code UNIQUE(tenant)`): two tenants could
    // not both own a group "Paris", and the second one silently got `paris-1`,
    // making one tenant's URLs and exports depend on another tenant's content.
    t.string('slug', 255).notNullable();
    t.text('description').nullable();
    // The FK is NOT declared here: it is the COMPOSITE
    // (parent_id, tenant_id) -> (id, tenant_id) added right after the table,
    // so that a cross-tenant parent is rejected by PostgreSQL itself.
    t.integer('parent_id').nullable();
    t.integer('sort_order').notNullable().defaultTo(0);
    // A "general" group is readable by every authenticated tenant member.
    t.boolean('is_general').notNullable().defaultTo(false);
    // Consolidate child alerts into one group-level notification.
    t.boolean('group_notifications').notNullable().defaultTo(false);

    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable().defaultTo(1)
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.timestamps(true, true);

    t.unique(['tenant_id', 'slug']);
    t.index('parent_id');
    t.index('tenant_id');
    // Kept: the composite unique above is prefixed by tenant_id, so it cannot
    // serve `ensureUniqueSlug`, which still probes on slug alone.
    t.index('slug');
  });
  // AUDIT-SEC #9 / AUDIT-CORR §3.3 — make a cross-tenant sub-tree IMPOSSIBLE in
  // the database rather than merely unlikely in the controller. The composite
  // unique is the target the composite FK needs; the FK then guarantees that a
  // child and its parent always carry the same tenant_id.
  // MATCH SIMPLE (the default) skips the check when parent_id IS NULL, which is
  // exactly what a root group needs.
  // ON DELETE CASCADE is retained deliberately: switching to RESTRICT is the
  // human arbitration of AUDIT-CORR §1.4 and would break groupService.delete()
  // — see the report handed to the lead.
  await knex.schema.raw(
    'ALTER TABLE device_groups ADD CONSTRAINT device_groups_id_tenant_uq UNIQUE (id, tenant_id)',
  );
  await knex.schema.raw(
    `ALTER TABLE device_groups ADD CONSTRAINT device_groups_parent_same_tenant
       FOREIGN KEY (parent_id, tenant_id) REFERENCES device_groups (id, tenant_id) ON DELETE CASCADE`,
  );

  await knex.schema.createTable('group_closure', (t) => {
    t.integer('ancestor_id').unsigned().notNullable()
      .references('id').inTable('device_groups').onDelete('CASCADE');
    t.integer('descendant_id').unsigned().notNullable()
      .references('id').inTable('device_groups').onDelete('CASCADE');
    t.integer('depth').notNullable();

    t.primary(['ancestor_id', 'descendant_id']);
    t.index('descendant_id');
    t.index('ancestor_id');
  });

  // ==========================================================================
  // SECTION 4 — Teams and RBAC
  // ==========================================================================

  await knex.schema.createTable('user_teams', (t) => {
    t.increments('id').primary();
    // AUDIT-CORR §1.8 — was globally unique: a tenant creating a team named
    // "NOC" made the name unavailable to every other tenant, and the 23505
    // surfaced as a 500 because the name is invisible to the second admin.
    t.string('name', 255).notNullable();
    t.text('description').nullable();
    t.boolean('can_create').notNullable().defaultTo(false);

    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable().defaultTo(1)
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.timestamps(true, true);

    t.unique(['tenant_id', 'name']);
    // AUDIT-CORR §1.6 — teamService.getAll(tenantId) filters on tenant_id alone.
    t.index('tenant_id');
  });

  await knex.schema.createTable('team_memberships', (t) => {
    t.integer('team_id').unsigned().notNullable()
      .references('id').inTable('user_teams').onDelete('CASCADE');
    t.integer('user_id').unsigned().notNullable()
      .references('id').inTable('users').onDelete('CASCADE');
    t.primary(['team_id', 'user_id']);
    // AUDIT-CORR §1.6 — the hottest join of the authorisation path
    // (getUserTeamIds, _getGroupPermissionViaClosure, getUserTeams) starts from
    // user_id, which is the SECOND column of the PK and therefore unindexed.
    t.index('user_id');
  });

  await knex.schema.createTable('team_permissions', (t) => {
    t.increments('id').primary();
    t.integer('team_id').unsigned().notNullable()
      .references('id').inTable('user_teams').onDelete('CASCADE');
    // A4: 'group' | 'device' — 'monitor' no longer exists anywhere.
    t.string('scope', 20).notNullable();
    t.integer('scope_id').notNullable();
    t.string('level', 5).notNullable(); // 'ro' | 'rw'
    // Capability list pinned onto the grant, fed by the Obligate assertion.
    t.jsonb('capabilities').nullable().defaultTo(null);

    t.unique(['team_id', 'scope', 'scope_id']);
    t.index(['scope', 'scope_id']);
    t.index('team_id');
  });
  await knex.schema.raw(
    "ALTER TABLE team_permissions ADD CONSTRAINT team_permissions_scope_chk CHECK (scope IN ('group','device'))",
  );
  // AUDIT-CORR §1.9 — `level` gates every write (requireGroupWrite expects
  // exactly 'rw'); an unknown value silently degrades to "no access" and is
  // undiagnosable from the UI.
  await knex.schema.raw(
    "ALTER TABLE team_permissions ADD CONSTRAINT team_permissions_level_chk CHECK (level IN ('ro','rw'))",
  );

  // permission_sets — named bundles of capabilities, exposed to the Obligate UI.
  await knex.schema.createTable('permission_sets', (t) => {
    t.increments('id').primary();
    t.string('name', 64).notNullable();
    t.string('slug', 64).notNullable().unique();
    t.jsonb('capabilities').notNullable().defaultTo('[]');
    t.boolean('is_default').notNullable().defaultTo(false);
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  // Seeded from shared/capabilities.ts so the wire vocabulary can never drift
  // between the database, the server and the client. 'admin' is added here
  // rather than in shared because "everything" is a server-side notion.
  await knex('permission_sets').insert([
    {
      name: 'Administrator',
      slug: 'admin',
      capabilities: JSON.stringify(ALL_CAPABILITIES),
      is_default: true,
    },
    ...BUILTIN_PERMISSION_SETS.map((s) => ({
      name: s.name,
      slug: s.slug,
      capabilities: JSON.stringify(s.capabilities),
      is_default: true,
    })),
  ]);

  // ==========================================================================
  // SECTION 5 — Hierarchical settings
  // ==========================================================================

  await knex.schema.createTable('settings', (t) => {
    t.increments('id').primary();
    // A4: 'global' | 'tenant' | 'group' | 'device'.
    // scope_id is NULL for 'global' AND for 'tenant' — at those two levels the
    // identity of the row is carried by tenant_id, not by scope_id.
    t.string('scope', 20).notNullable();
    t.integer('scope_id').nullable();
    t.string('key', 100).notNullable();
    t.jsonb('value').notNullable();

    t.integer('tenant_id').notNullable().defaultTo(1)
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.timestamps(true, true);

    // AUDIT-CORR §1.1/§1.2 — the read path is ALWAYS
    // (tenant_id, scope, scope_id); the previous index omitted tenant_id.
    t.index(['tenant_id', 'scope', 'scope_id']);
  });
  // AUDIT-CORR §1.2 + spec §C6 — 'tenant' is the inheritance level the M2
  // template variables need (global -> tenant -> groups -> device). Adding it
  // to the CHECK now costs nothing; adding it after M2 costs a data migration.
  await knex.schema.raw(
    "ALTER TABLE settings ADD CONSTRAINT settings_scope_chk CHECK (scope IN ('global','tenant','group','device'))",
  );

  // --------------------------------------------------------------------------
  // AUDIT-CORR §1.1 (CRITIQUE) — `UNIQUE (scope, scope_id, key)` constrained
  // NOTHING on the two levels that apply to the whole fleet.
  //
  // PostgreSQL 16 still defaults to NULLS DISTINCT, so two rows
  // ('global', NULL, 'snmp_timeout') never conflicted: the service's
  // `onConflict` never fired, every write appended a row, and `getByScope`
  // (no ORDER BY) returned whichever row PostgreSQL handed back last — a value
  // that can flip after a VACUUM FULL with no write having taken place.
  //
  // AUDIT-CORR §1.2 (CRITIQUE) — and tenant_id was not in the key at all, so
  // two tenants could not physically hold two different values for the same
  // global key.
  //
  // Fixed by two PARTIAL unique indexes that spell out both cases explicitly.
  // `scope` is part of the NULL-side key (the audit suggested (tenant_id, key)
  // alone): now that 'tenant' also carries a NULL scope_id, dropping `scope`
  // would make a tenant-level override collide with the global one.
  // --------------------------------------------------------------------------
  await knex.schema.raw(
    `CREATE UNIQUE INDEX settings_unscoped_uq ON settings (tenant_id, scope, key)
       WHERE scope_id IS NULL`,
  );
  await knex.schema.raw(
    `CREATE UNIQUE INDEX settings_scoped_uq ON settings (tenant_id, scope, scope_id, key)
       WHERE scope_id IS NOT NULL`,
  );

  // ==========================================================================
  // SECTION 6 — Notifications
  // ==========================================================================

  await knex.schema.createTable('notification_channels', (t) => {
    t.increments('id').primary();
    t.string('name', 255).notNullable();
    t.string('type', 50).notNullable(); // plugin key: 'webhook', 'discord', ...
    t.jsonb('config').notNullable().defaultTo('{}');
    t.boolean('is_enabled').notNullable().defaultTo(true);
    t.integer('created_by').unsigned().nullable()
      .references('id').inTable('users').onDelete('SET NULL');

    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable().defaultTo(1)
      .references('id').inTable('tenants').onDelete('CASCADE');

    t.timestamps(true, true);
  });

  await knex.schema.createTable('notification_bindings', (t) => {
    t.increments('id').primary();
    t.integer('channel_id').unsigned().notNullable()
      .references('id').inTable('notification_channels').onDelete('CASCADE');
    // A4: 'global' | 'group' | 'device'
    t.string('scope', 20).notNullable();
    t.integer('scope_id').nullable();
    t.string('override_mode', 10).notNullable().defaultTo('merge'); // merge | replace | exclude

    // AUDIT-CORR §1.2 (CRITIQUE) — this column simply did not exist, against
    // the spec's convention. Without it, tenant 1's "NOC interne" Discord bound
    // at global scope was resolved for a device of tenant 2, and client B's
    // incident was posted on client A's channel with no error and no log.
    t.integer('tenant_id').notNullable().defaultTo(1)
      .references('id').inTable('tenants').onDelete('CASCADE');

    // AUDIT-CORR §1.1 — same NULLS DISTINCT trap as `settings`: the global
    // bindings were the ones that could be duplicated, and a duplicated
    // merge/exclude pair is unrecoverable from the UI (the exclude is applied
    // after the merges, so the channel stays mute forever).
    t.index(['tenant_id', 'scope', 'scope_id']);
  });
  await knex.schema.raw(
    "ALTER TABLE notification_bindings ADD CONSTRAINT notification_bindings_scope_chk CHECK (scope IN ('global','group','device'))",
  );
  // AUDIT-CORR §1.9 / §4.3 — the import writes override_mode verbatim. A
  // "Replace" from a hand-edited bundle used to be stored and then silently
  // treated as a 'merge', which is the exact opposite of the intent.
  await knex.schema.raw(
    `ALTER TABLE notification_bindings ADD CONSTRAINT notification_bindings_override_chk
       CHECK (override_mode IN ('merge','replace','exclude'))`,
  );
  await knex.schema.raw(
    `CREATE UNIQUE INDEX notification_bindings_unscoped_uq
       ON notification_bindings (tenant_id, channel_id, scope) WHERE scope_id IS NULL`,
  );
  await knex.schema.raw(
    `CREATE UNIQUE INDEX notification_bindings_scoped_uq
       ON notification_bindings (tenant_id, channel_id, scope, scope_id) WHERE scope_id IS NOT NULL`,
  );

  await knex.schema.createTable('notification_log', (t) => {
    t.increments('id').primary();
    // AUDIT-CORR §1.5 — was NOT NULL + ON DELETE CASCADE, which contradicted
    // the stated intent of this table ("the log outlives the entity it
    // describes"): deleting a misconfigured channel destroyed the only trace of
    // why it was misconfigured. Now SET NULL, with the channel identity
    // denormalised below so the history stays readable.
    t.integer('channel_id').unsigned().nullable()
      .references('id').inTable('notification_channels').onDelete('SET NULL');
    t.string('channel_name', 255).nullable();
    t.string('channel_type', 50).nullable();
    // 'status_change' | 'test' | 'drift' | 'change' | 'threshold' | ...
    t.string('event_type', 50).notNullable();
    // Loose reference to whatever the notification was about (device, group...).
    // Deliberately NOT a foreign key: the log outlives the entity it describes.
    t.integer('entity_id').nullable();
    t.boolean('success').notNullable();
    t.text('message').nullable();
    t.text('error').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    t.index('channel_id');
    t.index('created_at');
  });

  // Cross-tenant channel sharing (a master-tenant channel reused elsewhere).
  await knex.schema.createTable('notification_channel_tenants', (t) => {
    t.integer('channel_id').notNullable()
      .references('id').inTable('notification_channels').onDelete('CASCADE');
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.primary(['channel_id', 'tenant_id']);
  });
  await knex.schema.raw('CREATE INDEX nct_channel_id ON notification_channel_tenants(channel_id)');
  await knex.schema.raw('CREATE INDEX nct_tenant_id ON notification_channel_tenants(tenant_id)');

  // ==========================================================================
  // SECTION 7 — Infrastructure / platform config
  // ==========================================================================

  // tenant_id NULL = platform-level SMTP server, usable by every tenant.
  await knex.schema.createTable('smtp_servers', (t) => {
    t.increments('id').primary();
    t.string('name', 128).notNullable();
    t.string('host', 255).notNullable();
    t.integer('port').notNullable().defaultTo(587);
    t.boolean('secure').notNullable().defaultTo(false);
    t.string('username', 255).notNullable();
    t.string('password', 255).notNullable();
    t.string('from_address', 255).notNullable();
    // AUDIT-CORR §1.3 — NULL carries a BUSINESS meaning here ("visible to every
    // tenant"), which made ON DELETE SET NULL the worst possible choice:
    // deleting a tenant promoted its private relay — host, service account and
    // password — into a platform-wide server offered to every other client.
    // CASCADE: a tenant's SMTP server dies with the tenant.
    t.integer('tenant_id').nullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.index('tenant_id');
  });

  // app_config — flat key/value store for platform settings. `obligate_config`
  // holds { url, apiKey } as JSON; `obligate_enabled` is the SSO master switch.
  await knex.schema.createTable('app_config', (t) => {
    t.string('key', 64).primary();
    t.text('value').notNullable();
  });

  await knex('app_config').insert([
    { key: 'allow_2fa',          value: 'false' },
    { key: 'force_2fa',          value: 'false' },
    { key: 'otp_smtp_server_id', value: '' },
    { key: 'obligate_config',    value: '{}' },
    { key: 'obligate_enabled',   value: 'false' },
  ]);

  await knex.schema.createTable('live_alerts', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('severity', 16).notNullable(); // 'down' | 'up' | 'warning' | 'info'
    t.text('title').notNullable();
    t.text('message').notNullable();
    t.text('navigate_to').nullable();
    // Dedup key: skip if an unread alert with the same (tenant_id, stable_key) exists.
    t.text('stable_key').nullable();
    t.timestamp('read_at', { useTz: true }).nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  await knex.schema.raw(
    'CREATE INDEX live_alerts_tenant_created ON live_alerts(tenant_id, created_at DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX live_alerts_stable_key ON live_alerts(tenant_id, stable_key) WHERE stable_key IS NOT NULL',
  );
  // AUDIT-CORR §1.9 — the client renders one icon/colour per severity and falls
  // through silently on an unknown one.
  await knex.schema.raw(
    `ALTER TABLE live_alerts ADD CONSTRAINT live_alerts_severity_chk
       CHECK (severity IN ('down','up','warning','info'))`,
  );
}

/**
 * Reverse dependency order. Every table is dropped explicitly rather than
 * relying on CASCADE, so a partial down() surfaces as an error instead of
 * silently taking a neighbouring table's data with it.
 */
export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('live_alerts');
  await knex.schema.dropTableIfExists('app_config');
  await knex.schema.dropTableIfExists('smtp_servers');

  await knex.schema.dropTableIfExists('notification_channel_tenants');
  await knex.schema.dropTableIfExists('notification_log');
  await knex.schema.dropTableIfExists('notification_bindings');
  await knex.schema.dropTableIfExists('notification_channels');

  await knex.schema.dropTableIfExists('settings');

  await knex.schema.dropTableIfExists('permission_sets');
  await knex.schema.dropTableIfExists('team_permissions');
  await knex.schema.dropTableIfExists('team_memberships');
  await knex.schema.dropTableIfExists('user_teams');

  await knex.schema.dropTableIfExists('group_closure');
  await knex.schema.dropTableIfExists('device_groups');

  await knex.schema.dropTableIfExists('user_tenants');
  await knex.schema.dropTableIfExists('tenants');

  await knex.schema.dropTableIfExists('sso_foreign_users');
  await knex.schema.dropTableIfExists('password_reset_tokens');
  await knex.schema.dropTableIfExists('session');
  await knex.schema.dropTableIfExists('users');
}
