import type { Knex } from 'knex';

/**
 * NCM v2 — the `dhcpClient` resource kind.
 *
 * ┌─ WHAT THIS KIND IS FOR, IN ONE PARAGRAPH ────────────────────────────────┐
 * │ `NcmAddress` drops DHCP-learned addresses because they are STATE: they    │
 * │ change on renewal, and diffing them would report drift every time a lease │
 * │ turned over. But `/ip/dhcp-client` is a DECLARED object — an operator     │
 * │ creates it and deletes it — and dropping it along with the address it     │
 * │ learns made a real piece of configuration invisible to the model.         │
 * │                                                                          │
 * │ It mattered concretely. On a MikroTik fronted by a bridged Zyxel DSL      │
 * │ modem, this client is the only reason the MikroTik holds an address in    │
 * │ the modem's management subnet — which is the only reason it can reach it, │
 * │ which is the only reason it could ever carry a dead-man for it (§8.3).    │
 * │ Before this kind existed, deleting that client destroyed the safety net   │
 * │ and produced no finding anywhere.                                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * THE HASH IS NOT DISTURBED. `HASHED_COLLECTIONS` in `shared/src/ncm/
 * canonical.ts` carries a `since` per collection, and `dhcpClients` is
 * `since: 2`. A document stamped `ncmVersion: 1` therefore serialises exactly
 * as it did before this migration, so every `ncm_hash` already in
 * `config_snapshots` and every `base_state_hash` on a frozen plan stays valid.
 * Without that mechanism, adding one collection would have shifted every hash
 * in the fleet at once and reported all of it as drifted — risk R3 arriving in
 * a single sweep.
 *
 * The one visible effect: the first collection after `NCM_VERSION` becomes 2
 * writes ONE new snapshot per device, because `ncmVersion` is inside the
 * hashing scope. Drift does not move — `semanticDiff` compares resources, not
 * hashes, and identical resources yield zero findings.
 */

/** `shared/src/ncm/resources.ts` — NCM_RESOURCE_KINDS, v2. */
const NCM_RESOURCE_KINDS =
  "'interface','vlan','route','firewallRule','natRule'," +
  "'dhcpScope','ipsecPeer','localUser','service','qosRule','dhcpClient'";

/** `shared/src/ncm/resources.ts` — KEY_QUALITIES. */
const KEY_QUALITIES = "'strong','derived','weak'";

export async function up(knex: Knex): Promise<void> {
  // ── 1. The flat table ─────────────────────────────────────────────────────
  // Same shape as the other unordered kinds (migration 007). `ruleLike` is
  // false: a DHCP client has no position in a chain and no match to hash.
  await knex.schema.createTable('ncm_dhcp_clients', (t) => {
    t.bigIncrements('id').primary();
    t.integer('device_id').notNullable()
      .references('id').inTable('devices').onDelete('CASCADE');
    t.bigInteger('snapshot_id').notNullable()
      .references('id').inTable('config_snapshots').onDelete('CASCADE');
    t.string('sem_key', 180).notNullable();
    t.integer('position').nullable();
    t.string('order_group', 80).nullable();
    t.jsonb('props').notNullable();
    t.boolean('is_managed').notNullable().defaultTo(false);
    t.string('managed_slug', 48).nullable();
    t.string('key_quality', 8).notNullable().defaultTo('derived');
    t.string('payload_hash', 16).notNullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    // Two records sharing a sem_key inside one snapshot is a PARSER BUG — see
    // the note in 007. One client per interface is also what RouterOS enforces.
    t.unique(['snapshot_id', 'sem_key']);
    t.index(['device_id', 'sem_key'], 'ncm_dhcp_clients_device_key_idx');
    t.index(['snapshot_id', 'position'], 'ncm_dhcp_clients_snapshot_pos_idx');
  });

  await knex.schema.raw(
    'ALTER TABLE ncm_dhcp_clients ADD CONSTRAINT ncm_dhcp_clients_key_quality_chk ' +
      `CHECK (key_quality IN (${KEY_QUALITIES}))`,
  );

  // ── 2. The CHECK constraints that enumerate the kinds ─────────────────────
  // Dropped and recreated rather than altered: PostgreSQL has no ADD VALUE for
  // a CHECK, and a constraint listing ten kinds would reject every row of the
  // eleventh — silently at first, because nothing writes one until the parser
  // ships, and then loudly on the first device that has a DHCP client.
  await knex.schema.raw('ALTER TABLE ncm_backfill_state DROP CONSTRAINT ncm_backfill_kind_chk');
  await knex.schema.raw(
    'ALTER TABLE ncm_backfill_state ADD CONSTRAINT ncm_backfill_kind_chk ' +
      `CHECK (resource_kind IN (${NCM_RESOURCE_KINDS}))`,
  );

  await knex.schema.raw(
    'ALTER TABLE drift_exceptions DROP CONSTRAINT drift_exceptions_resource_chk',
  );
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions ADD CONSTRAINT drift_exceptions_resource_chk ' +
      `CHECK (resource IN (${NCM_RESOURCE_KINDS}))`,
  );
}

export async function down(knex: Knex): Promise<void> {
  const V1_KINDS =
    "'interface','vlan','route','firewallRule','natRule'," +
    "'dhcpScope','ipsecPeer','localUser','service','qosRule'";

  // Rows naming the v2 kind must go before the v1 constraint is put back, or
  // the ALTER fails on data this migration is responsible for.
  await knex('drift_exceptions').where({ resource: 'dhcpClient' }).delete();
  await knex('ncm_backfill_state').where({ resource_kind: 'dhcpClient' }).delete();

  await knex.schema.raw(
    'ALTER TABLE drift_exceptions DROP CONSTRAINT drift_exceptions_resource_chk',
  );
  await knex.schema.raw(
    'ALTER TABLE drift_exceptions ADD CONSTRAINT drift_exceptions_resource_chk ' +
      `CHECK (resource IN (${V1_KINDS}))`,
  );

  await knex.schema.raw('ALTER TABLE ncm_backfill_state DROP CONSTRAINT ncm_backfill_kind_chk');
  await knex.schema.raw(
    'ALTER TABLE ncm_backfill_state ADD CONSTRAINT ncm_backfill_kind_chk ' +
      `CHECK (resource_kind IN (${V1_KINDS}))`,
  );

  await knex.schema.dropTableIfExists('ncm_dhcp_clients');
}
