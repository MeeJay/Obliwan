import type { Knex } from 'knex';

/**
 * §8.3 — a fourth safety level: `armed_by_second_uplink`.
 *
 * ┌─ THE GAP IT FILLS ───────────────────────────────────────────────────────┐
 * │ The three original levels all answer "does something REPAIR this device   │
 * │ if the change cuts us off". They had no answer for the cheaper and far    │
 * │ more common case: does the device come BACK, by itself, on a path the     │
 * │ change did not touch.                                                    │
 * │                                                                          │
 * │ Nearly every MikroTik and DrayTek in a real fleet carries a backup LTE    │
 * │ SIM. Break the wired WAN and the box fails over, redials the             │
 * │ concentrator and reappears — different medium, different operator,        │
 * │ different point of failure. K7 already names that event `WAN_FAILOVER`.   │
 * │                                                                          │
 * │ Under the three-way split those devices were filed `degraded`, whose      │
 * │ own text reads "detection WITHOUT recovery — repair means a visit". For   │
 * │ a box with a live LTE uplink that is simply false, and a confirmation     │
 * │ dialog that states something false is a confirmation people learn to      │
 * │ click. Correcting the classification is the point; the new level is the   │
 * │ means.                                                                   │
 * │                                                                          │
 * │ IT IS NOT A DEAD-MAN, and the ordering says so: `armed` (0) repairs any   │
 * │ cut including a firewall that denies management everywhere;               │
 * │ `armed_by_peer` (1) is a repair by a neighbour that answered;             │
 * │ `armed_by_second_uplink` (2) is only a WAY HOME, and it dies with the     │
 * │ first one if the input chain is what broke; `degraded` (3) is nothing.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Widening a CHECK is backward-compatible by construction: every row already
 * stored names one of the three old values, all of which remain legal. Nothing
 * is rewritten and no existing job changes meaning.
 */

/** `shared/src/device.ts` — SAFETY_LEVELS, after §8.3's fourth level. */
const SAFETY_LEVELS = "'armed','armed_by_peer','armed_by_second_uplink','degraded'";
const SAFETY_LEVELS_V1 = "'armed','armed_by_peer','degraded'";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE change_plans DROP CONSTRAINT change_plans_safety_chk');
  await knex.schema.raw(
    `ALTER TABLE change_plans ADD CONSTRAINT change_plans_safety_chk
       CHECK (safety_level IN (${SAFETY_LEVELS}))`,
  );

  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_safety_chk');
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_safety_chk
       CHECK (safety_level IN (${SAFETY_LEVELS}))`,
  );
}

export async function down(knex: Knex): Promise<void> {
  // Rows naming the new level must be reclassified before the old CHECK is put
  // back, or the ALTER fails on data this migration made possible. They go to
  // `degraded` and NOT to `armed_by_peer`: rolling back the schema must never
  // upgrade a safety claim, and `degraded` is the value that demands the
  // explicit confirmation. Losing the distinction is the honest cost of a
  // downgrade; inventing a net is not an acceptable one.
  await knex('change_plans')
    .where({ safety_level: 'armed_by_second_uplink' })
    .update({ safety_level: 'degraded' });
  await knex('change_jobs')
    .where({ safety_level: 'armed_by_second_uplink' })
    .update({ safety_level: 'degraded' });

  await knex.schema.raw('ALTER TABLE change_plans DROP CONSTRAINT change_plans_safety_chk');
  await knex.schema.raw(
    `ALTER TABLE change_plans ADD CONSTRAINT change_plans_safety_chk
       CHECK (safety_level IN (${SAFETY_LEVELS_V1}))`,
  );

  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_safety_chk');
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_safety_chk
       CHECK (safety_level IN (${SAFETY_LEVELS_V1}))`,
  );
}
