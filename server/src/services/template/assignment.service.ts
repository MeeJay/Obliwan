import semver from 'semver';
import type { Knex } from 'knex';
import { db } from '../../db';

/**
 * assignment.service.ts — which revision applies to which device, and WHY.
 *
 * ┌─ TWO RULES THAT MAKE THE ANSWER EXPLAINABLE ──────────────────────────────┐
 * │ 1. PRECEDENCE IS THE SCOPE LEVEL, AND IT IS NOT CONFIGURABLE.             │
 * │      device (3) > group, deepest first (2) > tenant (1) > global (0)      │
 * │    exactly the chain `settings.service` walks. `priority` only breaks     │
 * │    ties WITHIN a level. A priority that could invert the levels would     │
 * │    make "why did this device get that template" unanswerable in the UI,   │
 * │    and an unanswerable rollout is one nobody dares launch.                │
 * │                                                                           │
 * │ 2. EVERY REJECTION IS RETURNED WITH ITS REASON.                           │
 * │    A resolver that returns `null` teaches an operator nothing. The one    │
 * │    here returns the winners AND the candidates it refused — "revision 7   │
 * │    requires RouterOS >= 7.10, the device runs 6.49.10" — because at       │
 * │    rollout time the interesting devices are the ones that got NOTHING,    │
 * │    and silence about them is how 3 of 300 routers stay unconfigured for a │
 * │    month.                                                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * A QUARANTINED REVISION IS NEVER SELECTED, including through an explicit pin.
 * K3 quarantines the revision that broke a wave; if a `pin_mode = 'pinned'`
 * assignment could still resolve to it, the quarantine would protect every
 * device except the ones somebody cared enough about to pin. The pin becomes a
 * REJECTION WITH A REASON instead, which is visible, rather than a silent
 * fallback to another revision, which is not.
 */

export const ASSIGNMENT_SCOPES = ['global', 'tenant', 'group', 'device'] as const;
export type AssignmentScope = (typeof ASSIGNMENT_SCOPES)[number];

const SCOPE_RANK: Readonly<Record<AssignmentScope, number>> = {
  global: 0, tenant: 1, group: 2, device: 3,
};

export type RejectionReason =
  | 'brand_mismatch'
  | 'model_mismatch'
  | 'template_archived'
  | 'no_published_revision'
  | 'pinned_revision_not_published'
  | 'os_below_min'
  | 'os_above_max'
  | 'os_unknown'
  | 'outranked';

export interface AssignmentCandidate {
  assignmentId: string;
  templateId: string;
  templateName: string;
  brand: string;
  scope: AssignmentScope;
  scopeId: number | null;
  /** Depth of the assigning group in the device's ancestry: 0 is the device's
   *  own group, larger is further up the tree. `null` outside `scope='group'`. */
  groupDepth: number | null;
  priority: number;
  pinMode: 'latest_published' | 'pinned';
  revisionId: string | null;
  revision: number | null;
  osMin: string | null;
  osMax: string | null;
}

export interface RejectedCandidate extends AssignmentCandidate {
  reason: RejectionReason;
  detail: string;
}

export interface DeviceTemplateResolution {
  deviceId: number;
  tenantId: number;
  brand: string | null;
  model: string | null;
  osVersion: string | null;
  /** At most one per template: the highest-precedence assignment that survived
   *  every constraint. */
  selected: AssignmentCandidate[];
  rejected: RejectedCandidate[];
}

// ============================================================================
// Version comparison
// ============================================================================

/**
 * RouterOS is NOT semver. `6.49.10`, `7.14.3`, `7.15rc2` and `7.16beta4` all
 * ship. `semver.coerce` reads the numeric head of each and DROPS the tail, so
 * `7.15rc2` and `7.15` coerce to the same `7.15.0` — which would let a revision
 * that requires 7.15 land on a release candidate that is, by definition, not
 * 7.15 yet.
 *
 * So: compare the coerced heads first, and when they are equal, a version with
 * a pre-release tail sorts BEFORE the same version without one. That is the
 * only place this file deviates from `semver`, and it deviates towards refusing
 * to install rather than towards installing.
 */
function tailOf(version: string): string {
  const m = /^[vV]?\d+(?:\.\d+){0,2}(.*)$/.exec(version.trim());
  return m ? m[1].trim() : '';
}

export function compareOsVersions(a: string, b: string): number | null {
  const ca = semver.coerce(a);
  const cb = semver.coerce(b);
  if (!ca || !cb) return null;
  const head = semver.compare(ca, cb);
  if (head !== 0) return head;
  const ta = tailOf(a);
  const tb = tailOf(b);
  if (ta === tb) return 0;
  if (ta === '') return 1;   // 7.15 is newer than 7.15rc2
  if (tb === '') return -1;
  return ta < tb ? -1 : 1;
}

/** `null` when the comparison cannot be made — never `true`. */
export function satisfiesOsWindow(
  osVersion: string | null,
  osMin: string | null,
  osMax: string | null,
): { ok: boolean; reason: RejectionReason | null; detail: string } {
  if (osMin === null && osMax === null) return { ok: true, reason: null, detail: '' };
  if (!osVersion) {
    return {
      ok: false,
      reason: 'os_unknown',
      detail:
        'the revision declares an OS window but the device has no known os_version; ' +
        'refusing to guess',
    };
  }
  if (osMin !== null) {
    const c = compareOsVersions(osVersion, osMin);
    if (c === null || c < 0) {
      return {
        ok: false,
        reason: 'os_below_min',
        detail: `the revision requires OS >= ${osMin}, the device runs ${osVersion}`,
      };
    }
  }
  if (osMax !== null) {
    const c = compareOsVersions(osVersion, osMax);
    if (c === null || c > 0) {
      return {
        ok: false,
        reason: 'os_above_max',
        detail: `the revision requires OS <= ${osMax}, the device runs ${osVersion}`,
      };
    }
  }
  return { ok: true, reason: null, detail: '' };
}

// ============================================================================
// Model matching
// ============================================================================

/**
 * `templates.model_pattern` is a GLOB — `*` and `?` — and not a regular
 * expression, on purpose.
 *
 * The pattern is authored by an operator and evaluated on the API thread for
 * every candidate of every device of a 300-device rollout. A regular expression
 * there is a denial of service one nested quantifier away
 * (`(a+)+$` against a long model string), from an input we invite people to
 * type. A glob compiled to an anchored, quantifier-free regex cannot backtrack,
 * covers what operators actually write (`CCR2004*`, `RB4011*`, `hEX?`), and is
 * one sentence to explain in the UI.
 */
export function modelMatches(pattern: string | null, model: string | null): boolean {
  if (!pattern) return true;
  if (model === null) return false;
  const rx = new RegExp(
    '^' + pattern.replace(/[.*+?^${}()|[\]\\]/g, (ch) => (ch === '*' ? '[^]*' : ch === '?' ? '[^]' : '\\' + ch)) + '$',
    'i',
  );
  return rx.test(model);
}

// ============================================================================
// Resolution
// ============================================================================

interface DeviceRow {
  id: number;
  tenant_id: number;
  group_id: number | null;
  brand: string | null;
  model: string | null;
  os_version: string | null;
}

interface AssignmentRow {
  assignment_id: string;
  scope: AssignmentScope;
  scope_id: number | null;
  priority: number;
  pin_mode: 'latest_published' | 'pinned';
  pinned_revision_id: string | null;
  template_id: string;
  template_name: string;
  template_brand: string;
  template_status: string;
  model_pattern: string | null;
}

interface RevisionRow {
  id: string;
  template_id: string;
  revision: number;
  status: string;
  os_min: string | null;
  os_max: string | null;
}

/**
 * Ancestors of the device's group, root -> leaf, with their closure depth.
 * Restricted to the caller's tenant on BOTH the closure and the group, because
 * a cross-tenant closure edge (AUDIT-SEC #9, the same defect
 * `settings.service._ancestorOverrides` guards against) would otherwise let one
 * client's group assign a template onto another client's device.
 */
async function ancestorGroups(
  q: Knex | Knex.Transaction,
  tenantId: number,
  groupId: number | null,
): Promise<{ id: number; depth: number }[]> {
  if (groupId === null) return [];
  const rows = (await q('group_closure as gc')
    .join('device_groups as g', 'g.id', 'gc.ancestor_id')
    .where('gc.descendant_id', groupId)
    .where('g.tenant_id', tenantId)
    .orderBy('gc.depth', 'asc')
    .select('g.id as id', 'gc.depth as depth')) as { id: number; depth: number }[];
  return rows;
}

export async function resolveForDevice(
  tenantId: number,
  deviceId: number,
  opts: { trx?: Knex | Knex.Transaction } = {},
): Promise<DeviceTemplateResolution> {
  const q = opts.trx ?? db;

  const device = (await q('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first('id', 'tenant_id', 'group_id', 'brand', 'model', 'os_version')) as DeviceRow | undefined;
  if (!device) {
    throw new Error(`device ${deviceId} does not exist for tenant ${tenantId}`);
  }

  const ancestors = await ancestorGroups(q, tenantId, device.group_id);
  const depthOf = new Map(ancestors.map((a) => [a.id, a.depth]));

  // One query. The scope predicates are ORed inside a single WHERE so that the
  // partial index `template_assignments_resolve_idx` is usable and so that a
  // device with a five-level group chain still costs one round trip, not five
  // (the mistake AUDIT-CORR §2.3 corrected in settings.service).
  const rows = (await q('template_assignments as a')
    .join('templates as t', 't.id', 'a.template_id')
    .where('a.tenant_id', tenantId)
    .where('a.enabled', true)
    // The template must be visible to this tenant: his own, or the shipped
    // library. Never another tenant's.
    .whereRaw('(t.tenant_id IS NULL OR t.tenant_id = ?)', [tenantId])
    .where((w) => {
      w.where((s) => s.whereIn('a.scope', ['global', 'tenant']).whereNull('a.scope_id'));
      w.orWhere((s) => s.where('a.scope', 'device').where('a.scope_id', deviceId));
      if (ancestors.length > 0) {
        w.orWhere((s) =>
          s.where('a.scope', 'group').whereIn('a.scope_id', ancestors.map((x) => x.id)),
        );
      }
    })
    .select(
      'a.id as assignment_id',
      'a.scope as scope',
      'a.scope_id as scope_id',
      'a.priority as priority',
      'a.pin_mode as pin_mode',
      'a.revision_id as pinned_revision_id',
      't.id as template_id',
      't.name as template_name',
      't.brand as template_brand',
      't.status as template_status',
      't.model_pattern as model_pattern',
    )) as AssignmentRow[];

  const templateIds = [...new Set(rows.map((r) => r.template_id))];
  const revisions = templateIds.length === 0 ? [] : ((await q('template_revisions')
    .whereIn('template_id', templateIds)
    .whereIn('status', ['published', 'quarantined', 'deprecated'])
    .orderBy([{ column: 'template_id' }, { column: 'revision', order: 'desc' }])
    .select('id', 'template_id', 'revision', 'status', 'os_min', 'os_max')) as RevisionRow[]);

  const byTemplate = new Map<string, RevisionRow[]>();
  for (const r of revisions) {
    const list = byTemplate.get(String(r.template_id)) ?? [];
    list.push(r);
    byTemplate.set(String(r.template_id), list);
  }
  const byId = new Map(revisions.map((r) => [String(r.id), r]));

  const rejected: RejectedCandidate[] = [];
  const winners = new Map<string, AssignmentCandidate>();

  const describe = (row: AssignmentRow, rev: RevisionRow | null): AssignmentCandidate => ({
    assignmentId: String(row.assignment_id),
    templateId: String(row.template_id),
    templateName: row.template_name,
    brand: row.template_brand,
    scope: row.scope,
    scopeId: row.scope_id,
    groupDepth: row.scope === 'group' && row.scope_id !== null
      ? depthOf.get(row.scope_id) ?? null
      : null,
    priority: row.priority,
    pinMode: row.pin_mode,
    revisionId: rev ? String(rev.id) : null,
    revision: rev ? rev.revision : null,
    osMin: rev ? rev.os_min : null,
    osMax: rev ? rev.os_max : null,
  });

  const reject = (
    row: AssignmentRow, rev: RevisionRow | null, reason: RejectionReason, detail: string,
  ) => { rejected.push({ ...describe(row, rev), reason, detail }); };

  for (const row of rows) {
    if (row.template_status !== 'active') {
      reject(row, null, 'template_archived', `template '${row.template_name}' is archived`);
      continue;
    }
    if (device.brand !== null && row.template_brand !== device.brand) {
      reject(row, null, 'brand_mismatch',
        `template '${row.template_name}' targets ${row.template_brand}, the device is ${device.brand}`);
      continue;
    }
    if (!modelMatches(row.model_pattern, device.model)) {
      reject(row, null, 'model_mismatch',
        `template '${row.template_name}' targets models matching '${row.model_pattern}', ` +
        `the device is '${device.model ?? 'unknown'}'`);
      continue;
    }

    let chosen: RevisionRow | null = null;

    if (row.pin_mode === 'pinned') {
      const pinned = row.pinned_revision_id ? byId.get(String(row.pinned_revision_id)) ?? null : null;
      if (!pinned || pinned.status !== 'published') {
        reject(row, pinned, 'pinned_revision_not_published',
          pinned
            ? `the pinned revision ${pinned.revision} is ${pinned.status}, not published`
            : 'the pinned revision does not exist or was never published');
        continue;
      }
      const os = satisfiesOsWindow(device.os_version, pinned.os_min, pinned.os_max);
      if (!os.ok) { reject(row, pinned, os.reason!, os.detail); continue; }
      chosen = pinned;
    } else {
      // Newest first; the first one that is published AND fits the device wins.
      // Walking down instead of taking the newest and failing is what lets a
      // fleet on mixed RouterOS versions converge: 7.x boxes get revision 9,
      // the three 6.49 boxes get revision 4, and nobody is left unconfigured.
      const candidates = byTemplate.get(String(row.template_id)) ?? [];
      let lastFailure: { reason: RejectionReason; detail: string; rev: RevisionRow } | null = null;
      for (const rev of candidates) {
        if (rev.status !== 'published') continue;
        const os = satisfiesOsWindow(device.os_version, rev.os_min, rev.os_max);
        if (os.ok) { chosen = rev; break; }
        if (!lastFailure) lastFailure = { reason: os.reason!, detail: os.detail, rev };
      }
      if (!chosen) {
        if (lastFailure) reject(row, lastFailure.rev, lastFailure.reason, lastFailure.detail);
        else reject(row, null, 'no_published_revision',
          `template '${row.template_name}' has no published revision`);
        continue;
      }
    }

    const candidate = describe(row, chosen);
    const key = candidate.templateId;
    const incumbent = winners.get(key);
    if (!incumbent) { winners.set(key, candidate); continue; }

    if (outranks(candidate, incumbent)) {
      winners.set(key, candidate);
      rejected.push({
        ...incumbent, reason: 'outranked',
        detail: `superseded by the ${candidate.scope} assignment` +
          (candidate.scope === 'group' ? ` of group ${candidate.scopeId}` : ''),
      });
    } else {
      rejected.push({
        ...candidate, reason: 'outranked',
        detail: `superseded by the ${incumbent.scope} assignment` +
          (incumbent.scope === 'group' ? ` of group ${incumbent.scopeId}` : ''),
      });
    }
  }

  return {
    deviceId: device.id,
    tenantId,
    brand: device.brand,
    model: device.model,
    osVersion: device.os_version,
    selected: [...winners.values()].sort((a, b) => rank(b) - rank(a)),
    rejected,
  };
}

function rank(c: AssignmentCandidate): number {
  return SCOPE_RANK[c.scope];
}

/** device > deepest group > … > root group > tenant > global, then `priority`,
 *  then the newer assignment. Total and deterministic: two runs of the resolver
 *  on the same data must never disagree, or a rollout becomes unrepeatable. */
function outranks(a: AssignmentCandidate, b: AssignmentCandidate): boolean {
  if (rank(a) !== rank(b)) return rank(a) > rank(b);
  if (a.scope === 'group' && b.scope === 'group') {
    const da = a.groupDepth ?? Number.MAX_SAFE_INTEGER;
    const dbp = b.groupDepth ?? Number.MAX_SAFE_INTEGER;
    if (da !== dbp) return da < dbp;  // depth 0 is the device's own group
  }
  if (a.priority !== b.priority) return a.priority > b.priority;
  return Number(a.assignmentId) > Number(b.assignmentId);
}

/**
 * The single revision to render for this device, or `null` with the reasons.
 * For the common "one template per device" case; `resolveForDevice` is what a
 * device page shows.
 */
export async function resolveRevisionForDevice(
  tenantId: number,
  deviceId: number,
  opts: { trx?: Knex | Knex.Transaction } = {},
): Promise<{ candidate: AssignmentCandidate | null; resolution: DeviceTemplateResolution }> {
  const resolution = await resolveForDevice(tenantId, deviceId, opts);
  return { candidate: resolution.selected[0] ?? null, resolution };
}

// ============================================================================
// Writing assignments
// ============================================================================

/**
 * A write this module refuses. `kind` carries the ONLY thing the HTTP layer
 * needs in order to pick a status code, and it carries no status code itself:
 * a service that names 400 and 404 is a service that has stopped being usable
 * from a job runner.
 *
 *   'invalid'   -> 400. The caller sent an incoherent pair.
 *   'not_found' -> 404. The caller named a row it may not see. Rule 2 of
 *                  `templates.controller.ts`: a cross-tenant id is a 404, never
 *                  a 403, because "it exists elsewhere" is already a leak.
 */
export class AssignmentInputError extends Error {
  constructor(message: string, readonly kind: 'invalid' | 'not_found' = 'invalid') {
    super(message);
    this.name = 'AssignmentInputError';
  }
}

/**
 * A `group` or `device` scope id must belong to THIS tenant before anything is
 * written against it (audit M4/M5, finding F4).
 *
 * `template_assignments.scope_id` is polymorphic — `device_groups.id` when
 * `scope='group'`, `devices.id` when `scope='device'` — and therefore carries
 * no foreign key at all (`008_templates.ts` says so explicitly, as `settings`
 * and `notification_bindings` do in 001). Nothing in the schema stops
 * `POST /api/templates/assignments {"scope":"device","scopeId":<another
 * customer's device>}` from being written. The read path would never surface
 * that row — the resolver only ever asks about ids of the current tenant — so
 * it is not a live cross-tenant leak; it is a dormant one, invisible in the UI,
 * that becomes a real assignment the day the id is reused.
 *
 * THIS FUNCTION LIVES HERE, IN THE SERVICE, RATHER THAN IN THE CONTROLLER
 * The identical check already existed as a private helper in
 * `variables.controller.ts`, on the sibling table `config_variables` which
 * makes exactly the same polymorphic trade-off. Writing a second copy in
 * `templates.controller.ts` would have made it two, and this project has
 * already paid for "three divergent implementations of one guard". It sits in
 * the shared module both controllers can import; `variables.controller.ts` is
 * outside this change's perimeter and still holds its private copy, which is
 * the one line of follow-up this leaves behind.
 */
export async function assertScopeTargetOwned(
  tenantId: number,
  scope: AssignmentScope,
  scopeId: number | null,
  q: Knex | Knex.Transaction = db,
): Promise<void> {
  if (scopeId === null || scopeId === undefined) return;
  if (scope !== 'group' && scope !== 'device') return;
  const table = scope === 'group' ? 'device_groups' : 'devices';
  const row = await q(table).where({ id: scopeId, tenant_id: tenantId }).first('id');
  if (!row) {
    throw new AssignmentInputError(`No ${scope} ${scopeId} in this tenant.`, 'not_found');
  }
}

/**
 * A pinned revision must belong to the template it is pinned on
 * (audit M4/M5, finding F4).
 *
 * The controller validated "this template is visible to you" and "this revision
 * is visible to you" as two independent questions, and nothing asked whether
 * they had anything to do with each other; `008_templates.ts` poses two
 * separate simple FKs and no composite one. So an assignment could carry
 * `template_id = T_edge` and `revision_id = <a revision of T_core>`, and the
 * resolver RESOLVES it: it loads candidate revisions with
 * `whereIn('template_id', templateIds)` over every template assigned to the
 * device, so the foreign revision is in `byId` as soon as its own template is
 * also assigned. The render then compiles T_core's body while the resolution
 * screen, `describe()` and `RenderResultRecord.templateId` all report T_edge.
 * The four-eyes approval is given on a template name that does not describe the
 * bytes being pushed — which is the one failure this milestone cannot have.
 *
 * Migration 014 adds the composite FK that makes the pair unforgeable at the
 * database. This check stays because it is what produces a 400 with a sentence
 * an operator can act on instead of a constraint-violation string.
 */
export async function assertRevisionBelongsToTemplate(
  templateId: string | number,
  revisionId: string | number,
  q: Knex | Knex.Transaction = db,
): Promise<void> {
  const rev = (await q('template_revisions')
    .where('id', revisionId)
    .first('id', 'template_id')) as { id: string; template_id: string } | undefined;
  if (!rev) {
    throw new AssignmentInputError(`Template revision ${revisionId} not found`, 'not_found');
  }
  if (String(rev.template_id) !== String(templateId)) {
    throw new AssignmentInputError(
      `Revision ${revisionId} belongs to template ${rev.template_id}, not to template ` +
        `${templateId}. An assignment pins a revision OF the template it assigns.`,
    );
  }
}

export interface AssignmentInput {
  scope: AssignmentScope;
  scopeId?: number | null;
  templateId: string | number;
  revisionId?: string | number | null;
  priority?: number;
  enabled?: boolean;
  reason?: string | null;
  createdBy?: number | null;
}

/**
 * Upsert on the PARTIAL unique index that covers this row — WHERE clause
 * included. PostgreSQL cannot infer a partial index from a bare column list and
 * raises "there is no unique or exclusion constraint matching the ON CONFLICT
 * specification" instead of quietly inserting a duplicate; naming it here is
 * the same fix `settings.service.conflictTarget` applies for the same reason.
 */
function conflictTarget(scopeId: number | null) {
  return scopeId === null
    ? db.raw('(tenant_id, scope, template_id) WHERE scope_id IS NULL')
    : db.raw('(tenant_id, scope, scope_id, template_id) WHERE scope_id IS NOT NULL');
}

export async function upsertAssignment(
  tenantId: number,
  input: AssignmentInput,
  trx: Knex | Knex.Transaction = db,
): Promise<{ id: string }> {
  const scopeId = input.scopeId ?? null;
  if ((input.scope === 'global' || input.scope === 'tenant') && scopeId !== null) {
    throw new Error(`scope '${input.scope}' does not take a scope_id`);
  }
  if ((input.scope === 'group' || input.scope === 'device') && scopeId === null) {
    throw new Error(`scope '${input.scope}' requires a scope_id`);
  }
  // Both guards run HERE and not only in the controller: `upsertAssignment` is
  // the single write path for this table, and the invariant belongs to whoever
  // owns the row. A rollout job, a seed or an import that starts calling this
  // tomorrow inherits the rule instead of re-deriving it.
  await assertScopeTargetOwned(tenantId, input.scope, scopeId, trx);
  if (input.revisionId !== null && input.revisionId !== undefined) {
    await assertRevisionBelongsToTemplate(input.templateId, input.revisionId, trx);
  }

  const pinMode = input.revisionId ? 'pinned' : 'latest_published';
  const now = new Date();
  const [row] = await trx('template_assignments')
    .insert({
      tenant_id: tenantId,
      scope: input.scope,
      scope_id: scopeId,
      template_id: input.templateId,
      revision_id: input.revisionId ?? null,
      pin_mode: pinMode,
      priority: input.priority ?? 100,
      enabled: input.enabled ?? true,
      reason: input.reason ?? null,
      created_by: input.createdBy ?? null,
      updated_at: now,
    })
    .onConflict(conflictTarget(scopeId))
    .merge({
      revision_id: input.revisionId ?? null,
      pin_mode: pinMode,
      priority: input.priority ?? 100,
      enabled: input.enabled ?? true,
      reason: input.reason ?? null,
      updated_at: now,
    })
    .returning('id');
  return row as { id: string };
}

export async function removeAssignment(
  tenantId: number,
  assignmentId: string | number,
  trx: Knex | Knex.Transaction = db,
): Promise<boolean> {
  const count = await trx('template_assignments')
    .where({ id: assignmentId, tenant_id: tenantId })
    .del();
  return count > 0;
}

export const assignmentService = {
  resolveForDevice,
  resolveRevisionForDevice,
  upsertAssignment,
  removeAssignment,
  assertScopeTargetOwned,
  assertRevisionBelongsToTemplate,
  satisfiesOsWindow,
  compareOsVersions,
  modelMatches,
};
