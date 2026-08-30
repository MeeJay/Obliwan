// ============================================================================
// @obliwan/shared — plan types
// ============================================================================
//
// THE TYPE ONLY. The planner is M5 (`planner.service`), the executor is M6.
// What lives here is the contract that `change_plans.ops jsonb` is validated
// against on the way in and on the way out, so that a plan compiled by one
// server version cannot be applied blind by another.
//
// A plan is BRAND-NEUTRAL: it says "this NCM resource must become that", never
// "run this RouterOS command". The brand artefact is produced by the driver at
// apply time and stored separately (`change_plans.rendered`). That separation
// is what lets the same plan be reviewed by a human who does not read RouterOS.
//
// R10 / §8.2, and it is not negotiable: A SECRET NEVER TRANSITS THROUGH A
// PlanOp VALUE. The plan the operator sees, the plan stored in the database and
// the plan written to `command_audit` are the redacted version. The complete
// version exists in memory only, on the vault -> equipment path.

import { z } from 'zod';
import { NCM_RESOURCE_KINDS } from './resources';

/** Matches `change_plans.risk_level`. Four-eyes approval is mandatory at
 *  `high` (`change_approvals`, ARCHITECTURE.md §3.5). */
export const RISK_LEVELS = ['low', 'medium', 'high'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const RISK_RANK: Readonly<Record<RiskLevel, number>> = { low: 0, medium: 1, high: 2 };

/**
 * The Management-Path Guard verdict (K2), carried on the plan.
 *
 *  'accept'        the guard proved the management path survives the change.
 *  'indeterminate' the guard COULD NOT prove it — `unmodeled[]` contains a
 *                  `forwardingRelevant` section, or a rule on the analysed path
 *                  carries `unmodeledMatch`, or `orderAnalysis === 'partial'`
 *                  (§6.4). Requires explicit confirmation. This is the
 *                  fail-closed value and the counterpart of N5: a partial model
 *                  may exist only if it knows its own partiality and refuses to
 *                  conclude beyond it.
 *  'veto'          the guard proved the change cuts the management path.
 */
export const MGMT_PATH_VERDICTS = ['accept', 'indeterminate', 'veto'] as const;
export type MgmtPathVerdict = (typeof MGMT_PATH_VERDICTS)[number];

export const PLAN_SOURCES = ['template', 'intent', 'refactor', 'restore'] as const;
export type PlanSource = (typeof PLAN_SOURCES)[number];

/**
 * `move` is separate from `update` on purpose. On RouterOS,
 * `/ip/firewall/filter/move numbers=X destination=Y` RENUMBERS the list on every
 * move, so a sequence of moves computed independently of one another produces a
 * wrong final order (§4.5). Move ops must be generated against a SIMULATED
 * list, op by op, and the plan must end with a `verify` op asserting that the
 * chain obtained equals the chain desired. The M5 convergence test is
 * "apply the plan, then re-diff: zero findings".
 */
export const PLAN_OP_KINDS = [
  'create', 'update', 'delete', 'move', 'enable', 'disable', 'verify', 'blocked',
] as const;
export type PlanOpKind = (typeof PLAN_OP_KINDS)[number];

/** Why an op could not be produced. A `blocked` op is INFORMATION, not a
 *  failure: the operator sees why, instead of a greyed-out button. */
export const PLAN_BLOCK_REASONS = [
  'coverage_incomplete',      // N3: we may not claim something is missing
  'unsupported_by_family',    // capabilityCheck failed before any network access
  'credentials_missing',
  'unmodeled_resource',       // it exists on the box, outside the model (N5)
  'weak_key',                 // identity too weak to act on safely
  'version_skew',
  'mgmt_path_veto',
] as const;
export type PlanBlockReason = (typeof PLAN_BLOCK_REASONS)[number];

export const PlanOp = z.object({
  /** Position in the plan. Ops are applied in ascending `seq`, and `seq` is
   *  what `dependsOn` and `change_job_steps` refer to. */
  seq: z.number().int().min(0),
  kind: z.enum(PLAN_OP_KINDS),
  resource: z.enum(NCM_RESOURCE_KINDS),
  /** The semantic key the op acts on. Stable across the whole plan lifetime —
   *  which is why a plan can be reviewed hours after it was compiled. */
  semKey: z.string().max(180),
  risk: z.enum(RISK_LEVELS),

  /** REDACTED resource values. `null` on the side that does not exist. */
  before: z.unknown().nullable(),
  after: z.unknown().nullable(),
  /** Field paths this op changes — mirrors `NcmFieldDiff.field`. */
  fields: z.array(z.string().max(120)),

  // ── `move` only ──────────────────────────────────────────────────────────
  /** Which chain the move happens in; a move is meaningless across chains. */
  chain: z.string().max(80).nullable(),
  /** Target index IN THE SIMULATED LIST at the moment this op runs — NOT the
   *  index in the original document. See §4.5. */
  targetIndex: z.number().int().min(0).nullable(),

  /** Ops (by `seq`) that must have succeeded first. */
  dependsOn: z.array(z.number().int().min(0)),
  /** Set on `blocked`. */
  blockedReason: z.enum(PLAN_BLOCK_REASONS).nullable(),
  /** Operator-facing sentence. Shown verbatim; never a stack trace. */
  reason: z.string().max(400),
  /** True when applying this op needs a reconnect / may drop the session — the
   *  dead-man arming decision reads this. */
  disruptive: z.boolean(),
}).strict();
export type PlanOp = z.infer<typeof PlanOp>;

/** Who and what the change touches, for the blast-radius screen shown BEFORE
 *  launch (`change_plans.blast_radius`). */
export const BlastRadius = z.object({
  deviceCount: z.number().int().min(0),
  siteCount: z.number().int().min(0),
  /** Interfaces / subnets whose forwarding the plan can alter. */
  affectedInterfaces: z.array(z.string().max(64)),
  affectedSubnets: z.array(z.string().max(49)),
  /** True when the plan touches a rule on the CHR -> management-IP path. */
  touchesManagementPath: z.boolean(),
}).strict();
export type BlastRadius = z.infer<typeof BlastRadius>;

/**
 * The full plan envelope — `change_plans` as a value.
 *
 * `baseStateHash` is the `ncm_hash` of the snapshot the plan was computed
 * against. The executor MUST refuse to apply a plan whose `baseStateHash` no
 * longer matches the device's current snapshot: a stale plan applied to a box
 * somebody edited in the meantime is how an operator deletes a rule they never
 * saw.
 */
export const ApplyPlan = z.object({
  planUuid: z.string().uuid(),
  deviceId: z.number().int().positive(),
  source: z.enum(PLAN_SOURCES),
  ncmVersion: z.number().int().positive(),
  semKeyGeneration: z.number().int().positive(),
  baseStateHash: z.string().length(64),
  ops: z.array(PlanOp),
  riskLevel: z.enum(RISK_LEVELS),
  mgmtPathVerdict: z.enum(MGMT_PATH_VERDICTS),
  blastRadius: BlastRadius,
  /** A plan is perishable. Past this instant it must be recompiled, not
   *  approved: the world it described is no longer the world. */
  expiresAt: z.string().datetime(),
  /** True once the planner has proved, against the simulated list, that
   *  applying `ops` yields the desired chain order (§4.5). A plan containing
   *  `move` ops with this false must not be offered for approval. */
  orderConverges: z.boolean(),
}).strict();
export type ApplyPlan = z.infer<typeof ApplyPlan>;

/** Plan-level risk is the maximum of its ops', never an average: one high-risk
 *  op in fifty makes the whole plan high-risk, and four-eyes applies. */
export function planRisk(ops: readonly PlanOp[]): RiskLevel {
  let best: RiskLevel = 'low';
  for (const op of ops) if (RISK_RANK[op.risk] > RISK_RANK[best]) best = op.risk;
  return best;
}
