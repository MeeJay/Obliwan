import type { Knex } from 'knex';

/**
 * 022_fix_evidence.ts — repairs three defects of 019_evidence.ts on installations
 * that already ran it. ARCHITECTURE.md §10 (F1).
 *
 * 019 has been corrected in place for FRESH installations; this file is what an
 * existing database needs, and it is written to be a no-op on a database whose
 * 019 was already the corrected one. Every statement is idempotent:
 * `CREATE OR REPLACE FUNCTION`, `DROP TRIGGER IF EXISTS` before `CREATE TRIGGER`,
 * and data statements whose `WHERE` no longer matches anything once they have run.
 *
 * ┌─ 1. DELETING A NORMALIZATION RULE WAS IMPOSSIBLE, AND SO WAS OFFBOARDING ─┐
 * │ `drift_findings.ignored_by_rule` references `normalization_rules(id)`      │
 * │ ON DELETE SET NULL (migration 007). Deleting a rule therefore issues an    │
 * │ UPDATE that empties the column on rows carrying `ignored = true` — which   │
 * │ `drift_findings_ignore_justified` refuses. 019 anticipated exactly this    │
 * │ trap for `ignored_by_exception` and built the compensating branch          │
 * │ (`NEW.ignored := false`) into `drift_findings_exception_same_device` — but │
 * │ declared the trigger `BEFORE INSERT OR UPDATE OF ignored_by_exception,     │
 * │ run_id`, so the referential action on the OTHER column never fired it.     │
 * │ The compensation existed for one column out of two.                        │
 * │                                                                            │
 * │   DELETE FROM normalization_rules WHERE id = 5;                            │
 * │   ERROR: new row for relation "drift_findings" violates check constraint    │
 * │          "drift_findings_ignore_justified"                                  │
 * │                                                                            │
 * │ Combined with defect 2 below it crossed customers: a finding of tenant 1   │
 * │ could name a rule of tenant 2, so `DELETE FROM tenants WHERE id = 2`       │
 * │ failed on a row belonging to tenant 1. One customer's offboarding blocked  │
 * │ by another customer's data.                                                │
 * └────────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 2. A FINDING COULD BE SILENCED BY ANOTHER TENANT'S RULE ─────────────────┐
 * │ `ignored_by_rule` was a plain FK with no tenant relationship at all, so    │
 * │ `UPDATE drift_findings SET ignored = true, ignored_by_rule = <a rule of    │
 * │ tenant 2> WHERE id = <a critical of tenant 1>` was ACCEPTED. Library rules │
 * │ (`tenant_id IS NULL`, migration 013) belong to everybody and remain the    │
 * │ one legal cross-tenant value.                                              │
 * │                                                                            │
 * │ This closes the STORAGE half only. The route half — an unjustified manual  │
 * │ ignore must answer 409 and point at `POST /api/exceptions`, and every      │
 * │ ignore must leave an `audit_log` row — lives in `drift.service.ts` and     │
 * │ `drift.controller.ts`.                                                     │
 * └────────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 3. EXCEPTIONS PINNED TO A PATH THAT WAS NEVER A FIELD ───────────────────┐
 * │ `drift_exceptions.path` is documented as `<kind>/<semKey>/<field>`, "one   │
 * │ field", NULL meaning the whole resource. The engine never emits a          │
 * │ field-scoped path — all three `findingPath` call sites in                  │
 * │ `semanticDiff.ts` pass two arguments — so `drift_findings.path` is always  │
 * │ `<kind>/<semKey>`. `exception.service` decided "this is field-scoped" with │
 * │ `path.split('/').length > 2`, which is true whenever the SEM KEY contains  │
 * │ a slash: every route (`route.v1:main:0.0.0.0/0:10.255.0.1`), every         │
 * │ interface, DHCP scope or local user whose name has one.                    │
 * │                                                                            │
 * │ Those exceptions were pinned to `changed/route.v1:…`, and the APPLY clause │
 * │ requires `df.path = e.path` — so the morning the same route reappeared as  │
 * │ `missing` or `moved`, the exception stopped matching and the operator      │
 * │ re-justified the same route again. The rows are converted here to what     │
 * │ they always meant: the whole resource.                                     │
 * └────────────────────────────────────────────────────────────────────────────┘
 *
 * NO SECRET REACHES ANY TABLE HERE (§8.2 / R10): this migration writes two
 * booleans, one nullable text column and one trigger function.
 */

/** `shared/src/ncm/diff.ts` — DIFF_KINDS. The first segment of a finding path is
 *  the DIFF KIND, never the resource kind; the whole point of defect 3 is that
 *  those two were confused. */
const DIFF_KINDS = ['changed', 'missing', 'extra', 'moved'];

/** The recomputation `exception.service.recomputeRuns` and 019 both already
 *  carry. A run whose `max_severity` is stale keeps a device green while a
 *  critical is visible on the findings list. */
const RECOMPUTE_RUNS = `
  UPDATE drift_runs dr SET
    ignored_count = s.ignored_count,
    max_severity  = s.max_severity,
    status        = CASE WHEN dr.status IN ('error','unreachable') THEN dr.status
                         WHEN s.visible_count > 0 THEN 'drifted' ELSE 'in_sync' END
  FROM (
    SELECT run_id,
           count(*) FILTER (WHERE ignored)      AS ignored_count,
           count(*) FILTER (WHERE NOT ignored)  AS visible_count,
           (ARRAY_REMOVE(ARRAY_AGG(CASE WHEN NOT ignored THEN severity END ORDER BY
              CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
                            WHEN 'low' THEN 1 ELSE 0 END DESC), NULL))[1] AS max_severity
      FROM drift_findings GROUP BY run_id
  ) s
  WHERE s.run_id = dr.id
`;

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // 1 + 2 — the guard, replaced in place.
  // ==========================================================================
  //
  // `CREATE OR REPLACE` rather than DROP + CREATE: the trigger below depends on
  // the function, and dropping it would need a CASCADE that also takes out any
  // trigger a later migration may have attached to it.
  await knex.schema.raw(`
    CREATE OR REPLACE FUNCTION drift_findings_exception_same_device() RETURNS trigger AS $fn$
    DECLARE
      e_device integer;
      f_device integer;
      f_tenant integer;
      r_tenant integer;
    BEGIN
      -- LOSING THE LAST REASON UN-HIDES THE FINDING. Both fks are ON DELETE
      -- SET NULL, so both can be emptied by a referential action on a row that
      -- says ignored = true, and drift_findings_ignore_justified would then
      -- abort the DELETE that caused it.
      --
      -- UPDATE only. On INSERT the same shape must FAIL loudly rather than be
      -- silently corrected: an insert claiming ignored with no reason is a
      -- caller bug, and the CHECK is there to say so.
      IF TG_OP = 'UPDATE' AND NEW.ignored
         AND NEW.ignored_by_rule IS NULL AND NEW.ignored_by_exception IS NULL THEN
        NEW.ignored := false;
      END IF;

      -- The rule that silences a finding must be one the finding's tenant is
      -- entitled to: its own, or a library rule (tenant_id IS NULL).
      IF NEW.ignored_by_rule IS NOT NULL THEN
        SELECT dr.device_id, d.tenant_id INTO f_device, f_tenant
          FROM drift_runs dr JOIN devices d ON d.id = dr.device_id
         WHERE dr.id = NEW.run_id;
        SELECT tenant_id INTO r_tenant FROM normalization_rules WHERE id = NEW.ignored_by_rule;
        -- A NULL on either side means we are inside a cascade (the run, the
        -- device or the rule is already gone). The fks guarantee they existed
        -- at write time, so a missing one here is never a caller's doing, and
        -- raising would make deleting a tenant impossible.
        IF f_tenant IS NOT NULL AND r_tenant IS NOT NULL AND r_tenant IS DISTINCT FROM f_tenant
        THEN
          RAISE EXCEPTION
            'drift_findings: normalization rule % belongs to tenant %, finding % is tenant %''s',
            NEW.ignored_by_rule, r_tenant, NEW.id, f_tenant
            USING ERRCODE = 'restrict_violation';
        END IF;
      END IF;

      IF NEW.ignored_by_exception IS NULL THEN
        RETURN NEW;
      END IF;
      SELECT device_id INTO e_device FROM drift_exceptions WHERE id = NEW.ignored_by_exception;
      SELECT device_id INTO f_device FROM drift_runs WHERE id = NEW.run_id;
      IF e_device IS DISTINCT FROM f_device THEN
        RAISE EXCEPTION
          'drift_findings: exception % covers device %, finding % is on device %',
          NEW.ignored_by_exception, e_device, NEW.id, f_device
          USING ERRCODE = 'restrict_violation';
      END IF;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);

  // `ignored_by_rule` joins the UPDATE OF list — its absence was the whole
  // defect. `ignored` deliberately stays OUT of it: a bare
  // `UPDATE ... SET ignored = true` must still raise 23514 on
  // drift_findings_ignore_justified, because silently correcting it would turn
  // "this write is refused" into "this write did nothing" and the caller would
  // never learn the difference.
  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS drift_findings_exception_same_device_trg ON drift_findings',
  );
  await knex.schema.raw(`
    CREATE TRIGGER drift_findings_exception_same_device_trg
      BEFORE INSERT OR UPDATE OF ignored_by_exception, ignored_by_rule, run_id
      ON drift_findings
      FOR EACH ROW EXECUTE FUNCTION drift_findings_exception_same_device()
  `);

  // ── Rows already written through the hole ────────────────────────────────
  //
  // A finding silenced by ANOTHER tenant's rule is a suppression that customer
  // never asked for. It becomes visible again, exactly as 019 made unjustified
  // ignores visible again: the direction this feature points is "show it".
  await knex.schema.raw(`
    UPDATE drift_findings df
       SET ignored = CASE WHEN df.ignored_by_exception IS NULL THEN false ELSE df.ignored END,
           ignored_by_rule = NULL
     WHERE df.ignored_by_rule IS NOT NULL
       AND EXISTS (
             SELECT 1
               FROM drift_runs dr
               JOIN devices d ON d.id = dr.device_id
               JOIN normalization_rules nr ON nr.id = df.ignored_by_rule
              WHERE dr.id = df.run_id
                AND nr.tenant_id IS NOT NULL
                AND nr.tenant_id IS DISTINCT FROM d.tenant_id
           )
  `);
  await knex.schema.raw(RECOMPUTE_RUNS);

  // ==========================================================================
  // 3 — exceptions pinned to a whole-resource path.
  // ==========================================================================
  //
  // `<kind>/<semKey>` for one of the four DIFF kinds, and nothing after it, is
  // by construction the whole-resource path `findingPath(kind, semKey)`
  // produces. Rewriting it to NULL is not a widening: it is the value the row
  // would have carried had `exception.service` asked `findingPath` instead of
  // counting slashes.
  //
  // The NOT EXISTS is the collision guard. Both uniqueness indexes over `path`
  // are PARTIAL on `status = 'active'`, so two ACTIVE rows of the same
  // (tenant, device, sem_key) cannot both become NULL — the second would
  // violate `drift_exceptions_active_resource_uq` and abort the migration. A
  // group with more than one active row is therefore left exactly as it is,
  // visible and unchanged, for an operator to resolve. Non-active rows are
  // outside both indexes and are always safe to convert.
  const kinds = DIFF_KINDS.map((k) => `'${k}/' || e.sem_key`).join(', ');
  await knex.schema.raw(`
    UPDATE drift_exceptions e
       SET path = NULL, updated_at = now()
     WHERE e.path IS NOT NULL
       AND e.path IN (${kinds})
       AND (
            e.status <> 'active'
         OR NOT EXISTS (
              SELECT 1 FROM drift_exceptions o
               WHERE o.id <> e.id
                 AND o.status = 'active'
                 AND o.tenant_id = e.tenant_id
                 AND o.device_id = e.device_id
                 AND o.sem_key = e.sem_key
            )
       )
  `);

  // Those exceptions now forgive the whole resource, which may cover findings
  // the pinned form was missing. `exception.service.sweep()` materialises that
  // on its next pass — at the head of every read and once a minute on the
  // timer — so nothing is recomputed here: doing it in SQL would be a third
  // copy of the APPLY clause, and a third copy is a third thing to keep in
  // step.
}

export async function down(knex: Knex): Promise<void> {
  // Only the schema object is reverted. The data statements above are NOT
  // undone, and deliberately: re-hiding a finding that another customer's rule
  // was silencing, or re-pinning an exception to a path that never matched
  // what it claimed to, would be restoring the defect rather than the schema.
  await knex.schema.raw(
    'DROP TRIGGER IF EXISTS drift_findings_exception_same_device_trg ON drift_findings',
  );
  await knex.schema.raw(`
    CREATE OR REPLACE FUNCTION drift_findings_exception_same_device() RETURNS trigger AS $fn$
    DECLARE
      e_device integer;
      f_device integer;
    BEGIN
      IF NEW.ignored_by_exception IS NULL THEN
        IF TG_OP = 'UPDATE' AND NEW.ignored AND NEW.ignored_by_rule IS NULL THEN
          NEW.ignored := false;
        END IF;
        RETURN NEW;
      END IF;
      SELECT device_id INTO e_device FROM drift_exceptions WHERE id = NEW.ignored_by_exception;
      SELECT device_id INTO f_device FROM drift_runs WHERE id = NEW.run_id;
      IF e_device IS DISTINCT FROM f_device THEN
        RAISE EXCEPTION
          'drift_findings: exception % covers device %, finding % is on device %',
          NEW.ignored_by_exception, e_device, NEW.id, f_device
          USING ERRCODE = 'restrict_violation';
      END IF;
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `);
  await knex.schema.raw(`
    CREATE TRIGGER drift_findings_exception_same_device_trg
      BEFORE INSERT OR UPDATE OF ignored_by_exception, run_id ON drift_findings
      FOR EACH ROW EXECUTE FUNCTION drift_findings_exception_same_device()
  `);
}
