import type { Knex } from 'knex';

/**
 * 014_fk_tenant.ts — two references stop being tenant-blind.
 *
 * ┌─ WHAT THIS REPAIRS ───────────────────────────────────────────────────────┐
 * │                                                                           │
 * │ A. `devices.group_id` (audit M2/M3, finding 5 — MAJEUR)                   │
 * │    `assertReferencesInTenant()` checked `site_id` and `concentrator_id`   │
 * │    and NOT `group_id`, while `deviceColumns()` wrote the column from the  │
 * │    request body. `POST /api/devices {"groupId": <a group of tenant B>}`   │
 * │    therefore returned 201, and the leak was immediate and in READ:        │
 * │    `services/query/compiler.ts` joins `device_groups` on `d.group_id`     │
 * │    and scopes on `d.tenant_id` alone — correctly — so tenant A's device   │
 * │    displayed tenant B's group NAME, and an id sweep enumerated another    │
 * │    customer's group tree. Settings and rights inherit down the group      │
 * │    closure, so the write was not cosmetic either.                         │
 * │                                                                           │
 * │ B. `template_assignments.(template_id, revision_id)`                      │
 * │    (audit M4/M5, finding F4 — MAJEUR)                                     │
 * │    `008_templates.ts` poses two INDEPENDENT foreign keys, one to          │
 * │    `templates` and one to `template_revisions`, and nothing tied them     │
 * │    together. An assignment could carry `template_id = T_edge` with        │
 * │    `revision_id = <a revision of T_core>`, and the resolver resolves it   │
 * │    (it loads candidates with `whereIn('template_id', templateIds)` over   │
 * │    every template assigned to the device). The render then compiles       │
 * │    T_core's body while the resolution screen and                          │
 * │    `RenderResultRecord.templateId` both say T_edge: the four-eyes         │
 * │    approval is given on a name that does not describe the bytes pushed.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY IN THE SCHEMA AND NOT ONLY IN THE SERVICE ───────────────────────────┐
 * │ Both defects are, in code, one missing `if`. Both were written by         │
 * │ authors who knew the rule — the sibling checks sit two lines above in     │
 * │ each case. An applicative guard covers the write paths that exist today;  │
 * │ a constraint covers the ones written next year, the seeds, the imports,   │
 * │ the `psql` session at 3 a.m. Migration 001 already made choice A          │
 * │ possible on purpose (`device_groups_id_tenant_uq`, quoted in its own      │
 * │ comment as "the target the composite FK needs") and then used it only     │
 * │ for `device_groups.parent_id`. The tool was built and not plugged in.     │
 * │                                                                           │
 * │ The service-side checks are added in the same commit                      │
 * │ (`fleet/device.service.ts::assertReferencesInTenant`,                     │
 * │ `template/assignment.service.ts::assertRevisionBelongsToTemplate`) and    │
 * │ are NOT redundant with these constraints: they produce the sentence an    │
 * │ operator can act on, where the constraint produces `23503`.               │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ FOUR DECISIONS ─────────────────────────────────────────────────────────┐
 * │                                                                           │
 * │ 1. MATCH SIMPLE (the default) IS WHAT WE WANT, IN BOTH CASES.             │
 * │    It skips the check as soon as ONE column of the pair is NULL. A device │
 * │    with no group (`group_id IS NULL`) and an assignment that follows the  │
 * │    latest published revision (`revision_id IS NULL`) are the two nominal  │
 * │    cases, and neither must be constrained. This is the same reasoning     │
 * │    `001_obliwan_core.ts` records for `device_groups.parent_id` on a root  │
 * │    group. MATCH FULL would reject both.                                   │
 * │                                                                           │
 * │ 2. `ON DELETE SET NULL (group_id)` — THE COLUMN LIST IS LOAD-BEARING.     │
 * │    The behaviour to preserve is 002's: deleting a group un-files its      │
 * │    devices, it does not delete them, and it does not fail. A bare         │
 * │    `ON DELETE SET NULL` on a composite FK nulls EVERY referencing column, │
 * │    `devices.tenant_id` included — which is NOT NULL, so every group       │
 * │    deletion would fail with a constraint violation. The per-column form   │
 * │    is PostgreSQL 15+. On an older server the migration keeps 002's simple │
 * │    FK for its referential ACTION and adds the composite one as a          │
 * │    deferred check: the SET NULL fires first, the deferred check then sees │
 * │    `group_id IS NULL` and passes by decision 1.                           │
 * │                                                                           │
 * │ 3. THE TEMPLATE PAIR IS `DEFERRABLE INITIALLY DEFERRED`.                  │
 * │    Deleting a template cascades into `template_revisions` AND into        │
 * │    `template_assignments` in the same statement. A non-deferrable check   │
 * │    would be evaluated in the middle of that cascade, in an order the      │
 * │    schema does not get to choose, and could see an assignment row whose   │
 * │    revision has already gone. Deferring to COMMIT means the check reads   │
 * │    a settled state. It changes nothing for the case that matters: an      │
 * │    INSERT of an incoherent pair still fails, at COMMIT rather than at the │
 * │    statement — and the applicative guard refuses it long before, in 400.  │
 * │    `revision_id`'s existing simple FK (ON DELETE RESTRICT — a pinned      │
 * │    revision may not be deleted) is untouched and keeps that behaviour.    │
 * │                                                                           │
 * │ 4. THE DATA IS REPAIRED BEFORE THE CONSTRAINT IS POSED, NOT AFTER.        │
 * │    Rows already written through the two holes exist by construction on    │
 * │    any deployment that has served traffic. `ALTER TABLE ... ADD           │
 * │    CONSTRAINT` would fail on them and leave the migration half-applied.   │
 * │    Both repairs null the offending reference — the least destructive      │
 * │    move available, and the one the FK itself would have made — and log    │
 * │    what they touched so it is not silent.                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

async function supportsColumnListSetNull(knex: Knex): Promise<boolean> {
  const res = await knex.raw('SHOW server_version_num');
  const raw = (res.rows?.[0]?.server_version_num ?? '0') as string;
  return Number.parseInt(raw, 10) >= 150000;
}

export async function up(knex: Knex): Promise<void> {
  // ══ A. devices.group_id ═══════════════════════════════════════════════════

  // Decision 4. Un-file every device sitting in another tenant's group.
  const orphaned = await knex.raw(
    `UPDATE devices d SET group_id = NULL, updated_at = now()
       WHERE d.group_id IS NOT NULL
         AND NOT EXISTS (
           SELECT 1 FROM device_groups g
            WHERE g.id = d.group_id AND g.tenant_id = d.tenant_id)
     RETURNING d.id`,
  );
  const unfiled = (orphaned.rows ?? []) as Array<{ id: number }>;
  if (unfiled.length > 0) {
    // eslint-disable-next-line no-console
    console.warn(
      `[014_fk_tenant] ${unfiled.length} device(s) were filed under a group belonging to ` +
        `another tenant and have been un-filed: ${unfiled.map((r) => r.id).join(', ')}. ` +
        'This is the AUDIT M2/M3 finding 5 defect; the group names those devices exposed ' +
        'through Fleet Query should be treated as disclosed.',
    );
  }

  const perColumnSetNull = await supportsColumnListSetNull(knex);

  if (perColumnSetNull) {
    // Decision 2, nominal path. The simple FK is replaced outright: keeping
    // both would mean two constraints on one column with two different ideas
    // of what a valid reference is, and the weaker one is the one a future
    // reader would trust.
    await knex.schema.raw('ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_group_id_foreign');
    await knex.schema.raw(
      `ALTER TABLE devices ADD CONSTRAINT devices_group_same_tenant
         FOREIGN KEY (group_id, tenant_id) REFERENCES device_groups (id, tenant_id)
         ON DELETE SET NULL (group_id)`,
    );
  } else {
    // Decision 2, fallback for PostgreSQL < 15. `devices_group_id_foreign` is
    // KEPT, because it is the only thing that can express "null just this
    // column on delete" there. The composite one is added as a deferred check
    // so it is evaluated after the SET NULL has run.
    await knex.schema.raw(
      `ALTER TABLE devices ADD CONSTRAINT devices_group_same_tenant
         FOREIGN KEY (group_id, tenant_id) REFERENCES device_groups (id, tenant_id)
         DEFERRABLE INITIALLY DEFERRED`,
    );
  }

  // ══ B. template_assignments.(template_id, revision_id) ════════════════════

  // The unique the composite FK needs, in the shape 001 and 008 already use
  // for `device_groups` and `templates`. `(id, template_id)` rather than
  // `(template_id, id)`: the index is then also usable for a lookup by id
  // alone, which is what `assertRevisionBelongsToTemplate` does.
  await knex.schema.raw(
    'ALTER TABLE template_revisions ADD CONSTRAINT template_revisions_id_template_uq ' +
      'UNIQUE (id, template_id)',
  );

  // Decision 4, second repair. An assignment pinning a foreign template's
  // revision goes back to following the latest published one — the safe
  // default, and the state the row claims to be in when `pin_mode` is read
  // without `revision_id`.
  const mispinned = await knex.raw(
    `UPDATE template_assignments a
        SET revision_id = NULL, pin_mode = 'latest_published', updated_at = now()
      WHERE a.revision_id IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM template_revisions r
           WHERE r.id = a.revision_id AND r.template_id = a.template_id)
    RETURNING a.id`,
  );
  const unpinned = (mispinned.rows ?? []) as Array<{ id: string }>;
  if (unpinned.length > 0) {
    // eslint-disable-next-line no-console
    console.warn(
      `[014_fk_tenant] ${unpinned.length} template assignment(s) pinned a revision of a ` +
        `DIFFERENT template and were reset to 'latest_published': ` +
        `${unpinned.map((r) => String(r.id)).join(', ')}. Any config_render produced from ` +
        'them recorded a template name that does not describe the body it compiled ' +
        '(AUDIT M4/M5 finding F4); the corresponding approvals are worth re-reading.',
    );
  }

  // Decision 3.
  await knex.schema.raw(
    `ALTER TABLE template_assignments ADD CONSTRAINT template_assignments_revision_of_template
       FOREIGN KEY (template_id, revision_id) REFERENCES template_revisions (template_id, id)
       DEFERRABLE INITIALLY DEFERRED`,
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw(
    'ALTER TABLE template_assignments DROP CONSTRAINT IF EXISTS template_assignments_revision_of_template',
  );
  await knex.schema.raw(
    'ALTER TABLE template_revisions DROP CONSTRAINT IF EXISTS template_revisions_id_template_uq',
  );

  await knex.schema.raw(
    'ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_group_same_tenant',
  );
  // Restore 002's simple FK if this ran on a server where it was dropped. The
  // `IF NOT EXISTS`-less form is deliberate: `down()` failing loudly on an
  // already-present constraint is better than a silent no-op that leaves the
  // column with no referential integrity at all.
  const exists = await knex.raw(
    `SELECT 1 FROM pg_constraint WHERE conname = 'devices_group_id_foreign'`,
  );
  if ((exists.rows ?? []).length === 0) {
    await knex.schema.raw(
      `ALTER TABLE devices ADD CONSTRAINT devices_group_id_foreign
         FOREIGN KEY (group_id) REFERENCES device_groups (id) ON DELETE SET NULL`,
    );
  }
}
