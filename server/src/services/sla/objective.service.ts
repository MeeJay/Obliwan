// ============================================================================
// ObliWAN F7 — SLA objectives: what the contract promises, per tenant or site
// ============================================================================
//
// ┌─ THE OBJECTIVE IS A STORED SETTING, NEVER A REQUEST PARAMETER ────────────┐
// │ Nothing on the HTTP surface may pass an objective to a calculation. The   │
// │ objective is read from `sla_objectives`, written only through             │
// │ `settings.manage`, and copied onto every report next to the numbers it    │
// │ judged. The same is true of `verdictValiditySeconds`, which decides how   │
// │ long one K7 sample speaks for and therefore MOVES availability figures.   │
// │                                                                          │
// │ This is not caution for its own sake. The F2 audit found a caller-driven  │
// │ parameter that turned 365 days without a single observation into a signed │
// │ "continuous" attestation. A `?objective=50` query string would be the     │
// │ same defect with a different name, and a `?verdictValidity=31536000` one  │
// │ would be worse: it would silently declare a year measured on the strength │
// │ of one UP row.                                                            │
// └───────────────────────────────────────────────────────────────────────────┘
//
// EVERY query in this file is scoped by `tenant_id`, and the tenant comes from
// the SESSION (`req.tenantId`), never from a body. `sla_objectives.site_id` is
// additionally protected by a COMPOSITE foreign key
// `(site_id, tenant_id) -> sites (id, tenant_id)`: pointing an objective at
// another customer's site is not merely refused here, it is unrepresentable.
//
// D3: nothing in this file touches an equipment. It reads and writes two of our
// own tables.

import {
  SLA_MAX_OBJECTIVE_PERCENT, SLA_MIN_OBJECTIVE_PERCENT,
  SlaObjectiveError,
  clampVerdictValiditySeconds, validateObjectivePercent,
  type SlaObjectiveScope,
} from '@obliwan/shared/dist/sla';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';

export interface SlaObjective {
  id: string;
  tenantId: number;
  siteId: number | null;
  scope: SlaObjectiveScope;
  objectivePercent: number;
  verdictValiditySeconds: number;
  note: string | null;
  updatedBy: number | null;
  createdAt: string;
  updatedAt: string;
}

interface ObjectiveRow {
  id: string;
  tenant_id: number;
  site_id: number | null;
  scope: string;
  objective_percent: string;
  verdict_validity_seconds: number;
  note: string | null;
  updated_by: number | null;
  created_at: Date;
  updated_at: Date;
}

/** `numeric` comes back from `pg` as a STRING, on purpose (it is arbitrary
 *  precision). Every read of `objective_percent` goes through here. */
function toObjective(row: ObjectiveRow): SlaObjective {
  return {
    id: String(row.id),
    tenantId: row.tenant_id,
    siteId: row.site_id,
    scope: row.scope as SlaObjectiveScope,
    objectivePercent: Number(row.objective_percent),
    verdictValiditySeconds: row.verdict_validity_seconds,
    note: row.note,
    updatedBy: row.updated_by,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

/** Tenant-scoped. Both the default row (`site_id IS NULL`) and every override. */
export async function listObjectives(tenantId: number): Promise<SlaObjective[]> {
  const rows: ObjectiveRow[] = await db('sla_objectives')
    .where({ tenant_id: tenantId })
    .orderByRaw('site_id NULLS FIRST')
    .select('*');
  return rows.map(toObjective);
}

/**
 * The objective that applies to one site: its own override, else the tenant
 * default, else nothing at all.
 *
 * "Nothing at all" is a first-class answer and it is NOT a default of 99.5 %.
 * An MSP that has not declared what it sells must not have a number invented
 * for it, and `evaluateSla` answers `indeterminate / no_objective_configured`
 * rather than judging the fleet against a figure nobody agreed to.
 */
export interface ResolvedObjective {
  objectivePercent: number | null;
  scope: SlaObjectiveScope | null;
  verdictValiditySeconds: number;
}

export function resolveForSite(
  objectives: readonly SlaObjective[],
  siteId: number,
): ResolvedObjective {
  const site = objectives.find((o) => o.siteId === siteId);
  if (site) {
    return {
      objectivePercent: site.objectivePercent,
      scope: 'site',
      verdictValiditySeconds: clampVerdictValiditySeconds(site.verdictValiditySeconds),
    };
  }
  const tenant = objectives.find((o) => o.siteId === null);
  if (tenant) {
    return {
      objectivePercent: tenant.objectivePercent,
      scope: 'tenant',
      verdictValiditySeconds: clampVerdictValiditySeconds(tenant.verdictValiditySeconds),
    };
  }
  return {
    objectivePercent: null,
    scope: null,
    verdictValiditySeconds: clampVerdictValiditySeconds(undefined),
  };
}

export interface SetObjectiveInput {
  objectivePercent: number;
  verdictValiditySeconds?: number;
  note?: string | null;
}

/**
 * Upsert the tenant default (`siteId === null`) or one site override.
 *
 * `validateObjectivePercent` refuses out of range with a sentence; the CHECK in
 * migration 026 refuses the same range with a 23514. Two independent refusals,
 * because this one is not what runs when a row is edited by hand.
 */
export async function setObjective(
  tenantId: number,
  siteId: number | null,
  input: SetObjectiveInput,
  actorUserId: number | null,
): Promise<SlaObjective> {
  let percent: number;
  try {
    percent = validateObjectivePercent(input.objectivePercent);
  } catch (err) {
    if (err instanceof SlaObjectiveError) throw new AppError(400, err.message);
    throw err;
  }
  const validity = clampVerdictValiditySeconds(input.verdictValiditySeconds);

  if (siteId !== null) {
    // Tenant scope BEFORE the write, so that a site belonging to another
    // customer answers 404 rather than 23503. The composite FK would refuse it
    // anyway; a 404 is the answer that does not confirm the id exists.
    const site = await db('sites')
      .where({ tenant_id: tenantId, id: siteId })
      .first('id');
    if (!site) throw new AppError(404, 'Site not found');
  }

  const patch = {
    tenant_id: tenantId,
    site_id: siteId,
    scope: siteId === null ? 'tenant' : 'site',
    objective_percent: percent,
    verdict_validity_seconds: validity,
    note: input.note ?? null,
    updated_by: actorUserId,
    updated_at: db.fn.now(),
  };

  // The two partial unique indexes of migration 026 are what make this an
  // UPSERT rather than a race. `ON CONFLICT` needs the index predicate spelled
  // out so Postgres can pick the partial index as the arbiter.
  const conflict = siteId === null
    ? db.raw('(tenant_id) WHERE site_id IS NULL')
    : db.raw('(tenant_id, site_id) WHERE site_id IS NOT NULL');

  const [row]: ObjectiveRow[] = await db('sla_objectives')
    .insert(patch)
    .onConflict(conflict as never)
    .merge([
      'objective_percent', 'verdict_validity_seconds', 'note', 'updated_by', 'updated_at',
    ])
    .returning('*');
  return toObjective(row);
}

/** Tenant-scoped delete. Returns false when nothing matched — which is a 404
 *  at the controller, never a 403: a 403 confirms the row exists. */
export async function deleteObjective(
  tenantId: number,
  siteId: number | null,
): Promise<boolean> {
  const q = db('sla_objectives').where({ tenant_id: tenantId });
  const deleted = siteId === null
    ? await q.whereNull('site_id').delete()
    : await q.where({ site_id: siteId }).delete();
  return deleted > 0;
}

export const OBJECTIVE_BOUNDS = {
  minPercent: SLA_MIN_OBJECTIVE_PERCENT,
  maxPercent: SLA_MAX_OBJECTIVE_PERCENT,
} as const;
