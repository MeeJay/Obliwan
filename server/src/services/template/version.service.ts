import type { Knex } from 'knex';
import { createTwoFilesPatch, structuredPatch } from 'diff';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import {
  ENTRY_NAME,
  depsFingerprint,
  extractDependencies,
  resolveLiveClosure,
  sha256,
  type PinnedDep,
} from './loader';

/**
 * version.service.ts — draft, publish, freeze, diff.
 *
 * ┌─ WHAT PUBLICATION ACTUALLY IS ────────────────────────────────────────────┐
 * │ Publishing is not "set status = 'published'". It is, in ONE transaction:  │
 * │                                                                           │
 * │   1. lock the draft (`FOR UPDATE`) so two publishers cannot both compute  │
 * │      a closure against the same partial set and both write pins;          │
 * │   2. parse the body and walk its `{% extends %}` / `{% include %}` /      │
 * │      `{% import %}` graph against the live partial store;                 │
 * │   3. write one `template_revision_deps` row per reached partial, PINNING  │
 * │      the concrete `template_partial_revisions.id` — not the partial;      │
 * │   4. only then flip the status, stamp `published_at`, and set             │
 * │      `deps_pinned` / `deps_count`.                                        │
 * │                                                                           │
 * │ The order is load-bearing. `template_revision_deps_freeze` refuses to     │
 * │ write a pin whose revision has already left `draft`, so steps 3 and 4     │
 * │ cannot be swapped; and `template_revisions_publication_chk` refuses a     │
 * │ non-draft row with `deps_pinned = false`, so step 4 cannot happen without │
 * │ step 3. A publication that crashes between them rolls back whole.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Every refusal in this file is ALSO a database constraint. That is deliberate
 * duplication and not an oversight: the service exists to give an operator a
 * sentence they can act on, the constraint exists because the service is not
 * the only thing that will ever hold a connection to this database.
 */

export type RevisionStatus = 'draft' | 'published' | 'quarantined' | 'deprecated';
export type PartialRevisionStatus = 'draft' | 'published' | 'deprecated';

export class TemplateVersionError extends Error {
  constructor(message: string) { super(message); this.name = 'TemplateVersionError'; }
}

/** Thrown for any attempt to change what a published revision RENDERS. */
export class ImmutableRevisionError extends TemplateVersionError {
  constructor(revisionId: string | number, status: string) {
    super(
      `template revision ${revisionId} is ${status} and immutable; ` +
        'create a new revision instead',
    );
    this.name = 'ImmutableRevisionError';
  }
}

export interface TemplateRecord {
  id: string;
  uuid: string;
  tenant_id: number | null;
  name: string;
  description: string | null;
  brand: string;
  model_pattern: string | null;
  status: string;
}

export interface RevisionRecord {
  id: string;
  uuid: string;
  tenant_id: number | null;
  template_id: string;
  revision: number;
  body: string;
  body_sha256: string;
  var_schema: unknown;
  section_severity: unknown;
  os_min: string | null;
  os_max: string | null;
  engine: string;
  render_options: Record<string, unknown>;
  status: RevisionStatus;
  published_at: Date | null;
  deps_pinned: boolean;
  deps_count: number;
  notes: string | null;
}

/** `tenant_id IS NOT DISTINCT FROM :t` — the only correct way to scope a
 *  nullable tenant column. `= NULL` matches nothing, which would make every
 *  library template invisible to the platform administrator who owns it. */
function whereTenant<T extends Knex.QueryBuilder>(q: T, column: string, tenantId: number | null): T {
  return q.whereRaw(`${column} IS NOT DISTINCT FROM ?`, [tenantId]) as T;
}

// ============================================================================
// Templates
// ============================================================================

export async function createTemplate(
  tenantId: number | null,
  input: {
    name: string;
    brand: string;
    description?: string | null;
    modelPattern?: string | null;
    createdBy?: number | null;
  },
  trx: Knex | Knex.Transaction = db,
): Promise<TemplateRecord> {
  const [row] = await trx('templates')
    .insert({
      tenant_id: tenantId,
      name: input.name.trim(),
      brand: input.brand,
      description: input.description ?? null,
      model_pattern: input.modelPattern ?? null,
      created_by: input.createdBy ?? null,
      updated_by: input.createdBy ?? null,
    })
    .returning('*');
  return row as TemplateRecord;
}

async function loadTemplate(
  trx: Knex | Knex.Transaction,
  tenantId: number | null,
  templateId: string | number,
): Promise<TemplateRecord> {
  const row = await whereTenant(
    trx('templates').where('id', templateId),
    'tenant_id',
    tenantId,
  ).first();
  if (!row) throw new TemplateVersionError(`template ${templateId} does not exist for this tenant`);
  return row as TemplateRecord;
}

// ============================================================================
// Revisions — drafting
// ============================================================================

export interface DraftInput {
  body: string;
  varSchema?: unknown;
  sectionSeverity?: unknown;
  osMin?: string | null;
  osMax?: string | null;
  renderOptions?: Record<string, unknown>;
  notes?: string | null;
  createdBy?: number | null;
}

/**
 * A new draft revision, numbered after the highest existing one.
 *
 * The body is PARSED here, not only at publication. A draft that does not parse
 * is a draft nobody can publish, and finding that out at authoring time costs
 * one round trip while finding it out at rollout time costs a maintenance
 * window. It is not a security check — the sandbox does not trust this parse —
 * it is a courtesy that happens to also stop a computed `{% include %}` from
 * being written at all.
 */
export async function createDraft(
  tenantId: number | null,
  templateId: string | number,
  input: DraftInput,
  trx: Knex | Knex.Transaction = db,
): Promise<RevisionRecord> {
  const template = await loadTemplate(trx, tenantId, templateId);
  extractDependencies(input.body, ENTRY_NAME); // throws on syntax / computed refs

  const [{ max }] = (await trx('template_revisions')
    .where('template_id', template.id)
    .max({ max: 'revision' })) as { max: number | null }[];

  const [row] = await trx('template_revisions')
    .insert({
      template_id: template.id,
      // Overwritten by `template_revisions_tenant_sync`; passed anyway so the
      // INSERT reads the way the table does.
      tenant_id: template.tenant_id,
      revision: (max ?? 0) + 1,
      body: input.body,
      body_sha256: sha256(input.body),
      var_schema: JSON.stringify(input.varSchema ?? {}),
      section_severity: JSON.stringify(input.sectionSeverity ?? {}),
      os_min: input.osMin ?? null,
      os_max: input.osMax ?? null,
      render_options: JSON.stringify(input.renderOptions ?? {}),
      notes: input.notes ?? null,
      status: 'draft',
      created_by: input.createdBy ?? null,
    })
    .returning('*');
  return row as RevisionRecord;
}

export async function getRevision(
  revisionId: string | number,
  trx: Knex | Knex.Transaction = db,
): Promise<RevisionRecord> {
  const row = await trx('template_revisions').where('id', revisionId).first();
  if (!row) throw new TemplateVersionError(`template revision ${revisionId} does not exist`);
  return row as RevisionRecord;
}

/**
 * Edit a DRAFT. Refuses anything else — and the refusal is checked under a row
 * lock, because "read the status, then update" without one is a race that ends
 * with a write landing on a revision that was published a millisecond earlier.
 * The trigger would still catch it; this way the operator gets the right error.
 */
export async function updateDraft(
  tenantId: number | null,
  revisionId: string | number,
  patch: Partial<DraftInput>,
  executor: Knex | Knex.Transaction = db,
): Promise<RevisionRecord> {
  const run = async (trx: Knex.Transaction): Promise<RevisionRecord> => {
    const current = (await whereTenant(
      trx('template_revisions').where('id', revisionId),
      'tenant_id',
      tenantId,
    ).forUpdate().first()) as RevisionRecord | undefined;

    if (!current) {
      throw new TemplateVersionError(`template revision ${revisionId} does not exist for this tenant`);
    }
    if (current.status !== 'draft') {
      throw new ImmutableRevisionError(revisionId, current.status);
    }

    const update: Record<string, unknown> = { updated_at: new Date() };
    if (patch.body !== undefined) {
      extractDependencies(patch.body, ENTRY_NAME);
      update.body = patch.body;
      update.body_sha256 = sha256(patch.body);
    }
    if (patch.varSchema !== undefined) update.var_schema = JSON.stringify(patch.varSchema);
    if (patch.sectionSeverity !== undefined) {
      update.section_severity = JSON.stringify(patch.sectionSeverity);
    }
    if (patch.osMin !== undefined) update.os_min = patch.osMin;
    if (patch.osMax !== undefined) update.os_max = patch.osMax;
    if (patch.renderOptions !== undefined) {
      update.render_options = JSON.stringify(patch.renderOptions);
    }
    if (patch.notes !== undefined) update.notes = patch.notes;

    const [row] = await trx('template_revisions')
      .where('id', revisionId)
      .update(update)
      .returning('*');
    return row as RevisionRecord;
  };

  return isTransaction(executor) ? run(executor) : db.transaction(run);
}

function isTransaction(x: Knex | Knex.Transaction): x is Knex.Transaction {
  return typeof (x as Knex.Transaction).commit === 'function';
}

// ============================================================================
// Publication
// ============================================================================

export interface PublishResult {
  revision: RevisionRecord;
  deps: PinnedDep[];
  depsFingerprint: string;
}

export async function publishRevision(
  tenantId: number | null,
  revisionId: string | number,
  publishedBy: number | null,
  executor: Knex | Knex.Transaction = db,
): Promise<PublishResult> {
  const run = async (trx: Knex.Transaction): Promise<PublishResult> => {
    const current = (await whereTenant(
      trx('template_revisions').where('id', revisionId),
      'tenant_id',
      tenantId,
    ).forUpdate().first()) as RevisionRecord | undefined;

    if (!current) {
      throw new TemplateVersionError(`template revision ${revisionId} does not exist for this tenant`);
    }
    if (current.status !== 'draft') {
      throw new ImmutableRevisionError(revisionId, current.status);
    }

    // Step 2 — resolve the closure against the LIVE partial store. This is the
    // last moment at which "the current partial" means anything for this
    // revision; from the next statement on, it means the pinned one forever.
    const { deps } = await resolveLiveClosure(trx, current.tenant_id, current.body);

    // Step 3 — pin. Written while the row is still a draft, which is the only
    // window `template_revision_deps_freeze` allows.
    if (deps.length > 0) {
      await trx('template_revision_deps').insert(
        deps.map((d) => ({
          revision_id: current.id,
          tenant_id: current.tenant_id,
          name: d.name,
          partial_id: d.partialId,
          partial_revision_id: d.partialRevisionId,
          ref_kind: d.refKind,
          depth: d.depth,
        })),
      );
    }

    // Step 4 — seal.
    const [row] = await trx('template_revisions')
      .where('id', current.id)
      .update({
        status: 'published',
        published_at: new Date(),
        published_by: publishedBy,
        deps_pinned: true,
        deps_count: deps.length,
        updated_at: new Date(),
      })
      .returning('*');

    const fingerprint = depsFingerprint(deps);
    logger.info(
      {
        revisionId: current.id,
        templateId: current.template_id,
        deps: deps.length,
        depsFingerprint: fingerprint,
      },
      'template revision published and its partials pinned',
    );

    return { revision: row as RevisionRecord, deps, depsFingerprint: fingerprint };
  };

  return isTransaction(executor) ? run(executor) : db.transaction(run);
}

/**
 * The only mutation a published revision accepts: moving forward along its
 * lifecycle. `quarantined` is what a failed rollout sets (K3), `deprecated` is
 * what an operator sets. There is no path back to `draft`, here or in the
 * trigger — a revision that could be un-published is a revision whose renders
 * lose their provenance.
 */
export async function setRevisionStatus(
  tenantId: number | null,
  revisionId: string | number,
  status: Extract<RevisionStatus, 'quarantined' | 'deprecated' | 'published'>,
  trx: Knex | Knex.Transaction = db,
): Promise<RevisionRecord> {
  const current = (await whereTenant(
    trx('template_revisions').where('id', revisionId),
    'tenant_id',
    tenantId,
  ).first()) as RevisionRecord | undefined;

  if (!current) {
    throw new TemplateVersionError(`template revision ${revisionId} does not exist for this tenant`);
  }
  if (current.status === 'draft') {
    throw new TemplateVersionError(
      `template revision ${revisionId} is a draft; publish it before changing its lifecycle status`,
    );
  }

  const [row] = await trx('template_revisions')
    .where('id', revisionId)
    .update({ status, updated_at: new Date() })
    .returning('*');
  return row as RevisionRecord;
}

// ============================================================================
// Partials
// ============================================================================

export async function createPartial(
  tenantId: number | null,
  input: { name: string; description?: string | null; brand?: string | null; createdBy?: number | null },
  trx: Knex | Knex.Transaction = db,
): Promise<{ id: string; name: string; tenant_id: number | null }> {
  const [row] = await trx('template_partials')
    .insert({
      tenant_id: tenantId,
      name: input.name,
      description: input.description ?? null,
      brand: input.brand ?? null,
      created_by: input.createdBy ?? null,
    })
    .returning('*');
  return row as { id: string; name: string; tenant_id: number | null };
}

export async function createPartialDraft(
  tenantId: number | null,
  partialId: string | number,
  body: string,
  createdBy: number | null = null,
  trx: Knex | Knex.Transaction = db,
): Promise<{ id: string; revision: number; status: PartialRevisionStatus }> {
  const partial = await whereTenant(
    trx('template_partials').where('id', partialId),
    'tenant_id',
    tenantId,
  ).first();
  if (!partial) throw new TemplateVersionError(`partial ${partialId} does not exist for this tenant`);

  extractDependencies(body, (partial as { name: string }).name);

  const [{ max }] = (await trx('template_partial_revisions')
    .where('partial_id', partialId)
    .max({ max: 'revision' })) as { max: number | null }[];

  const [row] = await trx('template_partial_revisions')
    .insert({
      partial_id: partialId,
      tenant_id: (partial as { tenant_id: number | null }).tenant_id,
      revision: (max ?? 0) + 1,
      body,
      body_sha256: sha256(body),
      status: 'draft',
      created_by: createdBy,
    })
    .returning('*');
  return row as { id: string; revision: number; status: PartialRevisionStatus };
}

/**
 * Freeze a partial revision so it becomes pinnable.
 *
 * This is the step that makes "editing a partial" a CREATE rather than an
 * UPDATE: after it, `template_partial_revisions_freeze` refuses every change to
 * the body, and every published template revision that pinned it keeps
 * rendering exactly what it rendered yesterday.
 */
export async function publishPartialRevision(
  tenantId: number | null,
  partialRevisionId: string | number,
  publishedBy: number | null = null,
  trx: Knex | Knex.Transaction = db,
): Promise<{ id: string; status: PartialRevisionStatus }> {
  const current = (await whereTenant(
    trx('template_partial_revisions').where('id', partialRevisionId),
    'tenant_id',
    tenantId,
  ).first()) as { id: string; status: PartialRevisionStatus } | undefined;

  if (!current) {
    throw new TemplateVersionError(
      `partial revision ${partialRevisionId} does not exist for this tenant`,
    );
  }
  if (current.status !== 'draft') {
    throw new TemplateVersionError(
      `partial revision ${partialRevisionId} is already ${current.status} and immutable`,
    );
  }

  const [row] = await trx('template_partial_revisions')
    .where('id', partialRevisionId)
    .update({ status: 'published', published_at: new Date(), published_by: publishedBy, updated_at: new Date() })
    .returning('*');
  return row as { id: string; status: PartialRevisionStatus };
}

// ============================================================================
// Diff
// ============================================================================

export interface RevisionDiff {
  from: { revisionId: string; revision: number; status: string; sha256: string };
  to: { revisionId: string; revision: number; status: string; sha256: string };
  identical: boolean;
  /** Unified patch, ready to be shown verbatim or coloured by the client. */
  patch: string;
  addedLines: number;
  removedLines: number;
  /** Pins that differ between the two revisions. A revision can render
   *  differently from its predecessor WITHOUT a single line of body changing —
   *  it is enough for a partial to have been republished between the two
   *  publications. A body diff alone would show nothing and the operator would
   *  approve a change they never saw. */
  depChanges: {
    name: string;
    fromPartialRevisionId: string | null;
    toPartialRevisionId: string | null;
  }[];
}

export async function diffRevisions(
  fromRevisionId: string | number,
  toRevisionId: string | number,
  trx: Knex | Knex.Transaction = db,
): Promise<RevisionDiff> {
  const [from, to] = await Promise.all([
    getRevision(fromRevisionId, trx),
    getRevision(toRevisionId, trx),
  ]);

  const label = (r: RevisionRecord) => `revision ${r.revision} (${r.status})`;
  const patch = createTwoFilesPatch(
    label(from), label(to),
    from.body, to.body,
    undefined, undefined,
    { context: 3 },
  );

  const structured = structuredPatch(
    label(from), label(to), from.body, to.body, undefined, undefined, { context: 0 },
  );
  let addedLines = 0;
  let removedLines = 0;
  for (const hunk of structured.hunks) {
    for (const line of hunk.lines) {
      if (line.startsWith('+')) addedLines++;
      else if (line.startsWith('-')) removedLines++;
    }
  }

  const pins = (await trx('template_revision_deps')
    .whereIn('revision_id', [from.id, to.id])
    .select('revision_id', 'name', 'partial_revision_id')) as {
    revision_id: string; name: string; partial_revision_id: string;
  }[];

  const fromPins = new Map<string, string>();
  const toPins = new Map<string, string>();
  for (const p of pins) {
    (String(p.revision_id) === String(from.id) ? fromPins : toPins)
      .set(p.name, String(p.partial_revision_id));
  }
  const depChanges: RevisionDiff['depChanges'] = [];
  for (const name of new Set([...fromPins.keys(), ...toPins.keys()])) {
    const a = fromPins.get(name) ?? null;
    const b = toPins.get(name) ?? null;
    if (a !== b) depChanges.push({ name, fromPartialRevisionId: a, toPartialRevisionId: b });
  }
  depChanges.sort((x, y) => x.name.localeCompare(y.name));

  return {
    from: { revisionId: String(from.id), revision: from.revision, status: from.status, sha256: from.body_sha256 },
    to: { revisionId: String(to.id), revision: to.revision, status: to.status, sha256: to.body_sha256 },
    identical: from.body_sha256 === to.body_sha256 && depChanges.length === 0,
    patch,
    addedLines,
    removedLines,
    depChanges,
  };
}

export const versionService = {
  createTemplate,
  createDraft,
  updateDraft,
  getRevision,
  publishRevision,
  setRevisionStatus,
  createPartial,
  createPartialDraft,
  publishPartialRevision,
  diffRevisions,
};
