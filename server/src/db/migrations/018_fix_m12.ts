import type { Knex } from 'knex';

/**
 * 018_fix_m12.ts — the two columns the M12 audit made necessary.
 *
 * Migration 017 shipped `baseline_conformance.excused` as a single counter over
 * every signed-for difference, and `score_adjusted` as
 * `(facts_covered + excused) / facts_total`. Those two facts do not fit
 * together, and the audit found the hole:
 *
 * ┌─ A `missing` DEVIATION IS NOT IN THE DENOMINATOR ─────────────────────────┐
 * │ `facts_total` counts the facts the DEVICE carries. An `extra` or a        │
 * │ `value_conflict` is one of those facts failing to be explained, so        │
 * │ excusing it legitimately moves it from "unexplained" to "explained":      │
 * │ #extra + #value_conflict == facts_total - facts_covered, exactly.         │
 * │ A `missing` deviation is the opposite — a template slot the device does   │
 * │ NOT carry. It was never in `facts_total` and excusing it can only inflate │
 * │ a numerator against a denominator it never entered. A site with twenty    │
 * │ template slots it does not have (no telephony VLAN, no head-office IPsec  │
 * │ peer) and five real unsigned drifts would score 100 % conformant.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * So the counter is split. `excused` keeps its name and its role in the score
 * but now counts ONLY the kinds that are in the denominator; `excused_missing`
 * carries the other half as information — it is a real number an operator
 * wants ("you signed for 20 template slots this site does not have"), it is
 * simply not a conformance number.
 *
 * The new CHECK is the point of the migration as much as the column is: it
 * makes the arithmetic that produced the false 100 % unrepresentable, rather
 * than merely absent from today's service code. `excused <= facts_total -
 * facts_covered` is the invariant the split creates, and a future writer that
 * forgets it now fails at the INSERT instead of at an audit.
 *
 * `baseline_runs.ran_in_worker` is the second column, and it exists because a
 * degradation nobody can see is a degradation nobody fixes: `ranInWorker` was
 * returned in an HTTP response and stored nowhere, so the day `POST /runs`
 * moves to pg-boss (the controller already says it should) the fact that a
 * clustering pass ran on the main thread would stop being observable at all.
 * NULL for the runs mined before this migration: unknown is not false.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('baseline_conformance', (t) => {
    t.integer('excused_missing').notNullable().defaultTo(0);
  });

  await knex.schema.alterTable('baseline_runs', (t) => {
    t.boolean('ran_in_worker').nullable();
  });

  // Backfill BEFORE the constraint, from the deviations themselves — the rows
  // written by 017's service carry the conflated counter and would fail the
  // new CHECK. Recomputed, never guessed: `baseline_deviations` is the record.
  await knex.raw(
    `UPDATE baseline_conformance c
        SET excused = sub.on_device,
            excused_missing = sub.missing,
            score_adjusted = CASE
              WHEN c.facts_total = 0 THEN 1
              ELSE LEAST(1, (c.facts_covered + sub.on_device)::numeric / c.facts_total)
            END,
            updated_at = now()
       FROM (
         SELECT c2.id,
                COALESCE(d.on_device, 0) AS on_device,
                COALESCE(d.missing, 0)   AS missing
           FROM baseline_conformance c2
           LEFT JOIN (
             SELECT tenant_id, run_id, device_id,
                    COUNT(*) FILTER (WHERE kind IN ('extra','value_conflict'))::int AS on_device,
                    COUNT(*) FILTER (WHERE kind = 'missing')::int                    AS missing
               FROM baseline_deviations
              WHERE classification = 'client_specific'
              GROUP BY tenant_id, run_id, device_id
           ) d ON d.tenant_id = c2.tenant_id
              AND d.run_id    = c2.run_id
              AND d.device_id = c2.device_id
       ) sub
      WHERE c.id = sub.id`,
  );

  await knex.schema.raw(
    `ALTER TABLE baseline_conformance
       ADD CONSTRAINT baseline_conformance_excused_chk CHECK (
         excused_missing >= 0
         AND excused + excused_missing <= deviations
         AND excused <= facts_total - facts_covered)`,
  );

  await knex.schema.raw(
    "COMMENT ON COLUMN baseline_conformance.excused IS $$Signed-for differences " +
      "that are IN the denominator (kind 'extra' or 'value_conflict'): facts this " +
      "device carries that the template does not explain. The only excusals " +
      "score_adjusted may credit.$$",
  );
  await knex.schema.raw(
    "COMMENT ON COLUMN baseline_conformance.excused_missing IS $$Signed-for " +
      "'missing' deviations: template slots this device does not carry. " +
      "Information only — they were never in facts_total and crediting them to " +
      "score_adjusted is how a site with five unsigned drifts reads as 100 %.$$",
  );
  await knex.schema.raw(
    "COMMENT ON COLUMN baseline_runs.ran_in_worker IS $$false when the weighted-" +
      "Jaccard pass ran on the main thread instead of the clustering worker. NULL " +
      "for runs mined before migration 018.$$",
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw(
    'ALTER TABLE baseline_conformance DROP CONSTRAINT IF EXISTS baseline_conformance_excused_chk',
  );
  await knex.schema.alterTable('baseline_conformance', (t) => {
    t.dropColumn('excused_missing');
  });
  await knex.schema.alterTable('baseline_runs', (t) => {
    t.dropColumn('ran_in_worker');
  });
}
