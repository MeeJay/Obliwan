import type { Knex } from 'knex';

/**
 * 023_fix_weather.ts — one column that was narrower than the values it stores.
 *
 * ┌─ WHAT THIS MIGRATION IS FOR, IN ONE SENTENCE ─────────────────────────────┐
 * │ `device_wan_path.egress_interface` holds an interface NAME, and the table │
 * │ that name is read from declares it `varchar(255)` while this column       │
 * │ declared it `varchar(64)`.                                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * THE DEFECT. `egressPath.service.resolveEgressFromSnmp()` returns
 * `snmp_interfaces.if_name` verbatim and `observeEgressPath()` inserts it
 * verbatim. `snmp_interfaces.if_name` is `varchar(255)` (migration 005), which
 * is the right width: IF-MIB's `ifName` is an `OCTET STRING (SIZE (0..255))`
 * and agents that derive `ifName` from `ifDescr` routinely publish more than
 * sixty-four characters. An eighty-four character name therefore aborted the
 * INSERT with `value too long for type character varying(64)` — which surfaced
 * as a 500 on `POST /api/weather/devices/:deviceId/probe`, and as nothing at
 * all in `tsc`, because a varchar width is not part of any type this codebase
 * has. It is the same shape of defect this project has already shipped once.
 *
 * ┌─ THREE DECISIONS ─────────────────────────────────────────────────────────┐
 * │                                                                           │
 * │ 1. WIDEN, DO NOT TRUNCATE. Truncating at the write would have kept the    │
 * │    INSERT alive at the cost of storing a name that matches nothing: the   │
 * │    value's whole purpose is to be recognisable as the interface the SNMP  │
 * │    inventory and the router itself call by that name, and a silently      │
 * │    shortened `ether1-gpon-uplink-to-the-...` is worse than a loud 500     │
 * │    because nobody goes looking for it. 255 is not a round number chosen   │
 * │    for comfort: it is exactly the width of the source column, which is    │
 * │    exactly the IF-MIB bound. The rule this project states — a column is   │
 * │    at least as wide as the longest value that can reach it — is applied   │
 * │    here across TABLES rather than against a CHECK.                        │
 * │                                                                           │
 * │ 2. A CLAMP STAYS IN THE SERVICE ANYWAY. The RouterOS half of the same     │
 * │    field (`immediate-gw`'s `%iface` suffix, or `gateway-interface`) is    │
 * │    read off a live box and bounded by nothing this schema controls. The   │
 * │    widened column is the fix; the clamp is the floor under it, so that a  │
 * │    box inventing a 400-character name degrades to a shortened note        │
 * │    instead of taking the probe down. Belt and braces, in that order.      │
 * │                                                                           │
 * │ 3. NO REWRITE, NO DEFAULT, NO INDEX. `ALTER TABLE ... TYPE varchar(255)`  │
 * │    from `varchar(64)` is a widening of the same type: PostgreSQL          │
 * │    validates it against the type system alone and does not rewrite the    │
 * │    heap or invalidate anything. The column is nullable, carries no CHECK  │
 * │    and is in no index, so there is nothing else to move.                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * THE DOWN. Narrowing back to 64 would fail on any row this migration made
 * possible, so `down()` truncates first, explicitly and visibly. A rollback
 * that silently destroys data is worse than one that says what it destroyed;
 * a rollback that cannot run at all is worse than both.
 *
 * SECRETS (§8.2): an interface name. The same datum `snmp_interfaces` has held
 * since M3. No credential, no vault reference.
 */

/** The width of `snmp_interfaces.if_name`, which is the width of IF-MIB's
 *  `ifName`. Stated once, used by the migration and quoted by the service. */
const EGRESS_INTERFACE_WIDTH = 255;

export async function up(knex: Knex): Promise<void> {
  await knex.schema.raw(
    `ALTER TABLE device_wan_path ALTER COLUMN egress_interface ` +
      `TYPE varchar(${EGRESS_INTERFACE_WIDTH})`,
  );
}

export async function down(knex: Knex): Promise<void> {
  // Anything longer than the old width only exists because of this migration.
  await knex.schema.raw(
    'UPDATE device_wan_path SET egress_interface = left(egress_interface, 64) ' +
      'WHERE egress_interface IS NOT NULL AND length(egress_interface) > 64',
  );
  await knex.schema.raw(
    'ALTER TABLE device_wan_path ALTER COLUMN egress_interface TYPE varchar(64)',
  );
}
