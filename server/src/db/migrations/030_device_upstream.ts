import type { Knex } from 'knex';

/**
 * `devices.upstream_device_id` — the device immediately upstream ON THE
 * MANAGEMENT PATH.
 *
 * ┌─ IT IS NOT THE CABLING, AND THE DIFFERENCE IS THE WHOLE POINT ───────────┐
 * │ Take the pairing this fleet actually has: a MikroTik behind a Zyxel DSL   │
 * │ modem in bridge mode.                                                     │
 * │                                                                          │
 * │ PHYSICALLY the Zyxel is upstream — it holds the line, the MikroTik hangs  │
 * │ off it. But in bridge mode the Zyxel has no routable WAN address at all:  │
 * │ ObliWAN reaches it only because the MikroTik routes its management subnet │
 * │ into the tunnel. From the platform's point of view the MikroTik is        │
 * │ upstream, and the Zyxel sits behind it.                                   │
 * │                                                                          │
 * │ The two orderings are OPPOSITE on the same site, and it is the second one │
 * │ that decides who can rescue whom. A peer is a safety net only if it       │
 * │ survives the cut AND can still reach the casualty locally — which is to   │
 * │ say only if it is the casualty's management upstream. Before this column  │
 * │ existed, `resolveSafetyNet` picked "any co-located MikroTik" and had no    │
 * │ way to know whether that neighbour was on the right side of the break.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Nullable, and null is the honest default: nobody has declared the topology
 * yet, so nothing may be inferred from it. Every consumer treats null as "the
 * relationship is unknown" and takes the closed branch — never as "there is no
 * upstream".
 *
 * ON DELETE SET NULL rather than CASCADE: retiring a modem must not delete the
 * router behind it. Losing the edge is right; losing the node is not.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (t) => {
    t.integer('upstream_device_id').nullable()
      .references('id').inTable('devices').onDelete('SET NULL');
  });

  // A device cannot be its own upstream. The longer loops (A -> B -> A) are NOT
  // constrained here: expressing them needs a recursive check, and a trigger
  // that runs on every device write to catch a mistake nobody has made yet is a
  // cost paid on every row forever. The consumers walk this edge at most one
  // hop, so a loop degrades to "unknown" rather than hanging.
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_upstream_not_self_chk ' +
      'CHECK (upstream_device_id IS NULL OR upstream_device_id <> id)',
  );

  // "Which devices sit behind this one" — the question the blast radius asks,
  // and the direction that has no natural index without this.
  await knex.schema.raw(
    'CREATE INDEX devices_upstream_idx ON devices (upstream_device_id) ' +
      'WHERE upstream_device_id IS NOT NULL',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DROP INDEX IF EXISTS devices_upstream_idx');
  await knex.schema.raw(
    'ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_upstream_not_self_chk',
  );
  await knex.schema.alterTable('devices', (t) => {
    t.dropColumn('upstream_device_id');
  });
}
