/**
 * ObliWAN F9 — the money path: propose, approve, complete, report.
 *
 * ┌─ THE RULE THIS MODULE EXISTS TO ENFORCE ──────────────────────────────────┐
 * │ Decision D3 says nothing is written to an equipment outside the change    │
 * │ queue, because an unguarded write bricks a router. The analogue here is   │
 * │ blunter: A TOP-UP SPENDS REAL MONEY AND NOTHING UNDOES IT. So no code     │
 * │ path anywhere in this product buys data except through this file, and     │
 * │ this file refuses to buy at all until `SIM_RECHARGE_ADAPTERS` has an      │
 * │ entry — which it does not, on purpose (`types.ts`).                       │
 * │                                                                          │
 * │ The chain is: a sweep DETECTS, this module PROPOSES, a human holding      │
 * │ SIM_RECHARGE APPROVES, somebody buys on the partner's portal, and the     │
 * │ purchase is RECORDED here. Every step is a row, every row is frozen       │
 * │ evidence, and the billing report reads the last one.                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ FOUR THINGS THAT MUST NOT BE "SIMPLIFIED" LATER ─────────────────────────┐
 * │                                                                          │
 * │ 1. `unknown` NEVER PROPOSES. A line whose balance could not be read is    │
 * │    not a line that is empty. `evaluateBalance` returns `unknown` for a    │
 * │    null reading and `proposeForLowZone` is only ever called with a `low`  │
 * │    verdict. The tempting "if we cannot read it, top it up to be safe" is  │
 * │    a standing order to buy data for every line the day the partner        │
 * │    renames a field.                                                        │
 * │                                                                          │
 * │ 2. ONE PROPOSAL PER LOW EPISODE, ENFORCED BY THE DATABASE. The unique     │
 * │    `idempotency_key` is built from `sim_balances.low_since`, which is     │
 * │    stable for as long as one episode lasts. A duplicate insert is caught  │
 * │    as a constraint violation and swallowed, NOT prevented by a service    │
 * │    that remembers — two workers, or one worker restarted mid-sweep, would │
 * │    both "remember" nothing.                                               │
 * │                                                                          │
 * │ 3. THE EVIDENCE IS FROZEN INTO THE ROW. `rest_mb_at_proposal` and         │
 * │    `threshold_mb_at_proposal` are copied at proposal time, along with the │
 * │    site and tenant names. An approver a week later must see the numbers   │
 * │    that caused the proposal, not today's — and a report must not rewrite  │
 * │    last quarter's site names when somebody renames a site.                │
 * │                                                                          │
 * │ 4. RECORDING IS NEVER REFUSED BY A CAP. The caps gate what the MACHINE    │
 * │    may buy. A top-up an operator already bought on the portal is a fact;  │
 * │    refusing to write it down because it breached a ceiling produces a     │
 * │    bill that does not match reality, which is worse than a breached       │
 * │    ceiling somebody can see.                                              │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * §8.2: no credential is within reach of this module. It reads MSISDNs, data
 * quantities and money.
 */

import {
  SIM_BILLABLE_STATUSES,
  canRechargeTransition,
  rechargeIdempotencyKey,
  simPlatformInfo,
  type SimPlatform,
  type SimRecharge,
  type SimRechargeCompletionInput,
  type SimRechargeStatus,
  type SimRechargeTrigger,
} from '@obliwan/shared';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { appendAudit } from '../attestation/auditLog.service';
import { SimAccountError } from './account.service';
import { getLine, type SimScope } from './line.service';
import { getRechargeAdapter } from './registry';

/**
 * How long a proposal stays actionable.
 *
 * A proposal is a claim about a balance at an instant. Two weeks later the line
 * has either been topped up by somebody else, been suspended, or run dry — and
 * approving on a fortnight-old reading buys data on evidence nobody checked.
 *
 * Expiry alone would SILENCE the line rather than retire the proposal: the next
 * sweep would rebuild the same idempotency key from the same unmoved
 * `low_since`, collide with the expired row's UNIQUE index, and quietly propose
 * nothing — a line that is still empty and no longer announced. So `expireStale`
 * also reopens the episode, but ONLY when the episode it was keyed on is still
 * the current one. See the block there for what the unconditional version did.
 */
export const PROPOSAL_TTL_DAYS = 14;

const EXPIRY_NOTE = `Expired automatically after ${PROPOSAL_TTL_DAYS} days with no decision.`;

// ============================================================================
// Rows
// ============================================================================

interface RechargeRow {
  id: string | number;
  sim_id: number | null;
  account_id: number | null;
  platform: SimPlatform;
  tenant_id: number | null;
  tenant_name: string | null;
  msisdn: string;
  operator: string | null;
  site_id: number | null;
  site_name: string | null;
  device_name: string | null;
  status: SimRechargeStatus;
  trigger: SimRechargeTrigger;
  zone: string;
  rest_mb_at_proposal: number | null;
  threshold_mb_at_proposal: number;
  plan_mb: number | null;
  cost_cents: string | number | null;
  currency: string | null;
  billing_reference: string | null;
  idempotency_key: string;
  proposed_at: Date | string;
  proposed_by: number | null;
  proposed_by_name?: string | null;
  decided_at: Date | string | null;
  decided_by: number | null;
  decided_by_name?: string | null;
  decision_note: string | null;
  completed_at: Date | string | null;
  completed_by: number | null;
  failure_reason: string | null;
  updated_at?: Date | string;
}

function iso(v: Date | string | null): string | null {
  if (v === null) return null;
  return v instanceof Date ? v.toISOString() : new Date(v).toISOString();
}

function toRecharge(row: RechargeRow): SimRecharge {
  return {
    id: Number(row.id),
    simId: row.sim_id,
    accountId: row.account_id,
    platform: row.platform,
    tenantId: row.tenant_id,
    tenantName: row.tenant_name,
    msisdn: row.msisdn,
    operator: row.operator,
    siteId: row.site_id,
    siteName: row.site_name,
    deviceName: row.device_name,
    status: row.status,
    trigger: row.trigger,
    zone: row.zone,
    restMbAtProposal: row.rest_mb_at_proposal,
    thresholdMbAtProposal: row.threshold_mb_at_proposal,
    planMb: row.plan_mb,
    costCents: row.cost_cents === null ? null : Number(row.cost_cents),
    currency: row.currency,
    billingReference: row.billing_reference,
    idempotencyKey: row.idempotency_key,
    proposedAt: iso(row.proposed_at)!,
    proposedBy: row.proposed_by,
    proposedByName: row.proposed_by_name ?? null,
    decidedAt: iso(row.decided_at),
    decidedBy: row.decided_by,
    decidedByName: row.decided_by_name ?? null,
    decisionNote: row.decision_note,
    completedAt: iso(row.completed_at),
    completedBy: row.completed_by,
    failureReason: row.failure_reason,
  };
}

function scopeRecharges(scope: SimScope, executor: Knex | Knex.Transaction = db) {
  const q = executor<RechargeRow>('sim_recharges as r')
    .leftJoin('users as pu', 'pu.id', 'r.proposed_by')
    .leftJoin('users as du', 'du.id', 'r.decided_by')
    .select('r.*', 'pu.username as proposed_by_name', 'du.username as decided_by_name');
  if (!scope.masterView) q.where('r.tenant_id', scope.tenantId);
  return q;
}

// ============================================================================
// Proposal
// ============================================================================

export interface LowZoneContext {
  simId: number;
  accountId: number;
  platform: SimPlatform;
  tenantId: number;
  tenantName: string | null;
  msisdn: string;
  operator: string | null;
  siteId: number | null;
  siteName: string | null;
  deviceName: string | null;
  zone: string;
  restMb: number | null;
  thresholdMb: number;
  planMb: number | null;
  /** The episode marker this proposal is keyed on. */
  lowSince: string;
}

/**
 * Creates the one proposal a low episode is entitled to.
 *
 * Returns the row on the first call and `null` on every subsequent call for the
 * same episode. The duplicate is detected as a UNIQUE violation rather than by
 * a pre-read: the pre-read version has a race window that two sweeps, or one
 * sweep and one manual proposal, walk straight through — and on this feature
 * the consequence of losing that race is a double purchase.
 */
export async function proposeForLowZone(ctx: LowZoneContext): Promise<SimRecharge | null> {
  const key = rechargeIdempotencyKey(ctx.simId, ctx.zone, ctx.lowSince);
  try {
    return await db.transaction(async (trx) => {
      const [row] = await trx<RechargeRow>('sim_recharges')
        .insert({
          sim_id: ctx.simId,
          account_id: ctx.accountId,
          platform: ctx.platform,
          tenant_id: ctx.tenantId,
          tenant_name: ctx.tenantName,
          msisdn: ctx.msisdn,
          operator: ctx.operator,
          site_id: ctx.siteId,
          site_name: ctx.siteName,
          device_name: ctx.deviceName,
          status: 'proposed',
          trigger: 'threshold',
          zone: ctx.zone,
          rest_mb_at_proposal: ctx.restMb,
          threshold_mb_at_proposal: ctx.thresholdMb,
          plan_mb: ctx.planMb,
          idempotency_key: key,
          // NULL actor: the sweep proposed this. Never attributed to whoever
          // happened to be logged in when the timer fired.
          proposed_by: null,
        } as Partial<RechargeRow>)
        .returning('*');

      // Inside the transaction: a proposal the ledger did not record is a spend
      // request with no trail, and `auditLog.service` states that rule.
      await appendAudit(
        {
          tenantId: ctx.tenantId,
          actorType: 'automation',
          actorId: 'sim-sweep',
          actorName: 'SIM balance sweep',
          action: 'sim_recharge.proposed',
          entityType: 'sim_recharge',
          entityId: String(row.id),
          after: {
            msisdn: ctx.msisdn,
            zone: ctx.zone,
            restMb: ctx.restMb,
            thresholdMb: ctx.thresholdMb,
            planMb: ctx.planMb,
          },
        },
        trx,
      );

      return toRecharge(row);
    });
  } catch (err) {
    if (isUniqueViolation(err)) return null;
    throw err;
  }
}

/**
 * A proposal raised by a human, outside any threshold.
 *
 * Keyed on the instant rather than on an episode, because there is no episode:
 * an operator who wants a top-up now is allowed one now, and a second click is
 * a second decision rather than a duplicate of the first.
 */
export async function proposeManual(
  scope: SimScope,
  input: { simId: number; zone: string; planMb?: number | null; note?: string | null },
  actor: { id: number; name: string },
): Promise<SimRecharge> {
  const line = await getLine(scope, input.simId);
  if (!line) throw new SimAccountError('Line not found', 404);
  if (line.tenantId === null) {
    // A pooled line belongs to nobody, so there is nobody to re-invoice and no
    // tenant to write the audit entry against. Assign it first.
    throw new SimAccountError(
      'This line is not assigned to a workspace, so a top-up could not be re-invoiced. ' +
        'Assign it to a customer first.',
    );
  }

  const zone = line.zones.find((z) => z.zone === input.zone) ?? null;
  const tenantName = await tenantNameOf(line.tenantId);

  return db.transaction(async (trx) => {
    const [row] = await trx<RechargeRow>('sim_recharges')
      .insert({
        sim_id: line.id,
        account_id: line.accountId,
        platform: line.platform,
        tenant_id: line.tenantId,
        tenant_name: tenantName,
        msisdn: line.msisdn,
        operator: line.operator,
        site_id: line.siteId,
        site_name: line.siteName,
        device_name: line.deviceName,
        status: 'proposed',
        trigger: 'manual',
        zone: input.zone,
        rest_mb_at_proposal: zone?.restMb ?? null,
        threshold_mb_at_proposal: line.thresholdMb,
        plan_mb: input.planMb ?? line.rechargePlanMb ?? null,
        idempotency_key: `manual:${line.id}:${input.zone.trim().toLowerCase()}:${Date.now()}`,
        proposed_by: actor.id,
        decision_note: input.note ?? null,
      } as Partial<RechargeRow>)
      .returning('*');

    await appendAudit(
      {
        tenantId: line.tenantId!,
        actorType: 'user',
        actorId: actor.id,
        actorName: actor.name,
        action: 'sim_recharge.proposed_manual',
        entityType: 'sim_recharge',
        entityId: String(row.id),
        after: { msisdn: line.msisdn, zone: input.zone, planMb: input.planMb ?? null },
      },
      trx,
    );
    return toRecharge(row);
  });
}

// ============================================================================
// Decisions
// ============================================================================

async function transition(
  scope: SimScope,
  id: number,
  to: SimRechargeStatus,
  actor: { id: number; name: string },
  patch: Record<string, unknown>,
  audit: { action: string; after?: Record<string, unknown> },
): Promise<SimRecharge> {
  return db.transaction(async (trx) => {
    // FOR UPDATE: two approvers clicking at the same instant must not both see
    // `proposed` and both write a decision. The row lock makes the state
    // machine's check meaningful rather than advisory.
    const q = trx<RechargeRow>('sim_recharges').where('id', id).forUpdate();
    if (!scope.masterView) q.where('tenant_id', scope.tenantId);
    const current = await q.first();
    // 404 rather than 403 — a 403 confirms the id exists (enumeration oracle).
    if (!current) throw new SimAccountError('Top-up not found', 404);

    if (!canRechargeTransition(current.status, to)) {
      throw new SimAccountError(
        `A top-up that is ${current.status} cannot become ${to}.`,
        409,
      );
    }

    const [row] = await trx<RechargeRow>('sim_recharges')
      .where('id', id)
      .update({ status: to, updated_at: trx.fn.now(), ...patch })
      .returning('*');

    await appendAudit(
      {
        // `tenant_id` is NOT NULL on every proposal this product can create:
        // the sweep only proposes for assigned lines and `proposeManual`
        // refuses a pooled one. The fallback keeps the ledger writable if a row
        // predates that rule rather than losing the entry.
        tenantId: current.tenant_id ?? scope.tenantId,
        actorType: 'user',
        actorId: actor.id,
        actorName: actor.name,
        action: audit.action,
        entityType: 'sim_recharge',
        entityId: String(id),
        before: { status: current.status },
        after: { status: to, ...(audit.after ?? {}) },
      },
      trx,
    );

    return toRecharge(row);
  });
}

export async function approve(
  scope: SimScope,
  id: number,
  actor: { id: number; name: string },
  note: string | null,
): Promise<SimRecharge> {
  return transition(
    scope,
    id,
    'approved',
    actor,
    { decided_at: db.fn.now(), decided_by: actor.id, decision_note: note },
    { action: 'sim_recharge.approved' },
  );
}

export async function reject(
  scope: SimScope,
  id: number,
  actor: { id: number; name: string },
  note: string | null,
): Promise<SimRecharge> {
  return transition(
    scope,
    id,
    'rejected',
    actor,
    { decided_at: db.fn.now(), decided_by: actor.id, decision_note: note },
    { action: 'sim_recharge.rejected' },
  );
}

/**
 * Records a top-up that a human bought on the partner's portal.
 *
 * THE NORMAL TERMINAL STATE TODAY, and deliberately not `executed`: the report
 * must always be able to answer "did the machine buy this, or did a person".
 *
 * Never refused by a cap (rule 4 in the header). The cost is optional, because
 * the invoice often arrives later — and the report counts unpriced rows rather
 * than adding them as zero.
 */
export async function recordCompletion(
  scope: SimScope,
  id: number,
  actor: { id: number; name: string },
  input: SimRechargeCompletionInput,
): Promise<SimRecharge> {
  const patch: Record<string, unknown> = {
    completed_at: db.fn.now(),
    completed_by: actor.id,
    failure_reason: null,
  };
  // A cost with no currency is refused by a CHECK in migration 032 (decision
  // 8). Defaulting the currency instead of failing would be inventing one.
  if (input.costCents !== undefined) patch.cost_cents = input.costCents;
  if (input.currency !== undefined) {
    patch.currency = input.currency === null ? null : input.currency.toUpperCase();
  }
  if (input.billingReference !== undefined) patch.billing_reference = input.billingReference;
  if (input.planMb !== undefined) patch.plan_mb = input.planMb;
  // APPENDED, never overwritten: the approver's reason for authorising the
  // spend and the buyer's note about the purchase are two different statements
  // by two possibly different people, and a billing record that keeps only the
  // second one has lost the first half of its own four-eyes trail.
  if (input.note !== undefined && input.note !== null && input.note !== '') {
    patch.decision_note = db.raw(
      `CASE WHEN decision_note IS NULL OR btrim(decision_note) = '' THEN ? ` +
        `ELSE decision_note || E'
' || ? END`,
      [input.note, input.note],
    );
  }
  // ┌─ WHY COALESCE AND NOT A PLAIN ASSIGNMENT ────────────────────────────────┐
  // │ Because the decision must be PRESERVED, not restamped. Recording a       │
  // │ purchase does not re-decide it: whoever approved it a week ago stays the │
  // │ approver, and a plain `decided_by = actor.id` would quietly rewrite the  │
  // │ four-eyes trail so that the person who typed in the invoice also appears │
  // │ to have authorised the spend.                                            │
  // │                                                                         │
  // │ The NULL branch is defence in depth and, as of migration 032, provably  │
  // │ unreachable: `sim_recharges_decided_chk` refuses any non-`proposed` row  │
  // │ with a null `decided_at`, and `recorded` is only ever reached from       │
  // │ `approved` or `failed`, both of which already carry one. `f9-sim.verify` │
  // │ asserts that unreachability directly rather than assuming it.            │
  // └─────────────────────────────────────────────────────────────────────────┘
  patch.decided_at = db.raw('COALESCE(decided_at, now())');
  patch.decided_by = db.raw('COALESCE(decided_by, ?)', [actor.id]);

  return transition(scope, id, 'recorded', actor, patch, {
    action: 'sim_recharge.recorded',
    after: {
      costCents: input.costCents ?? null,
      currency: input.currency ?? null,
      billingReference: input.billingReference ?? null,
    },
  });
}

/**
 * Prices a top-up that was already recorded.
 *
 * ┌─ WITHOUT THIS, "RECORD THEIR COST FIRST" WAS AN INSTRUCTION TO NOWHERE ──┐
 * │ `recorded` is a TERMINAL state (`SIM_RECHARGE_TRANSITIONS`), there is no │
 * │ generic PATCH on a top-up, and `recordCompletion` refuses a second call. │
 * │ So the cost, the currency, the invoice reference and the volume could be │
 * │ entered exactly ONCE — at the instant of recording.                       │
 * │                                                                         │
 * │ Every statement in this feature assumes the opposite. `recordCompletion` │
 * │ says the cost is optional "because the invoice often arrives later";     │
 * │ the report counts unpriced rows so somebody can price them; and          │
 * │ `assertExecutionAllowed` refuses to spend against an unpriced month with │
 * │ the words "Record their cost first". One top-up recorded with the cost   │
 * │ box blank therefore poisoned that account for the rest of the month,     │
 * │ with no remedy anywhere in the product.                                   │
 * │                                                                         │
 * │ This is NOT a state transition: the row stays exactly as billable as it  │
 * │ was. It fills in what the partner's invoice says, which is why it is     │
 * │ restricted to the billable states — pricing a rejected proposal would be │
 * │ inventing a charge.                                                       │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
export async function priceRecharge(
  scope: SimScope,
  id: number,
  actor: { id: number; name: string },
  input: SimRechargeCompletionInput,
): Promise<SimRecharge> {
  return db.transaction(async (trx) => {
    const q = trx<RechargeRow>('sim_recharges').where('id', id).forUpdate();
    if (!scope.masterView) q.where('tenant_id', scope.tenantId);
    const current = await q.first();
    // 404, never 403 — no existence oracle over another customer's charges.
    if (!current) throw new SimAccountError('Top-up not found', 404);

    if (!SIM_BILLABLE_STATUSES.includes(current.status)) {
      throw new SimAccountError(
        `Only a top-up that was actually bought can be priced; this one is ${current.status}.`,
        409,
      );
    }

    const patch: Record<string, unknown> = { updated_at: trx.fn.now() };
    if (input.costCents !== undefined) patch.cost_cents = input.costCents;
    if (input.currency !== undefined) {
      patch.currency = input.currency === null ? null : input.currency.toUpperCase();
    }
    if (input.billingReference !== undefined) patch.billing_reference = input.billingReference;
    if (input.planMb !== undefined) patch.plan_mb = input.planMb;
    if (input.note !== undefined && input.note !== null && input.note !== '') {
      // Appended, like every other note write in this file.
      patch.decision_note = trx.raw(
        `CASE WHEN decision_note IS NULL OR btrim(decision_note) = '' THEN ? ` +
          `ELSE decision_note || E'\n' || ? END`,
        [input.note, input.note],
      );
    }

    const [row] = await trx<RechargeRow>('sim_recharges')
      .where('id', id)
      .update(patch)
      .returning('*');

    await appendAudit(
      {
        tenantId: current.tenant_id ?? scope.tenantId,
        actorType: 'user',
        actorId: actor.id,
        actorName: actor.name,
        action: 'sim_recharge.priced',
        entityType: 'sim_recharge',
        entityId: String(id),
        before: {
          costCents: current.cost_cents === null ? null : Number(current.cost_cents),
          currency: current.currency,
        },
        after: {
          costCents: input.costCents ?? null,
          currency: input.currency ?? null,
          billingReference: input.billingReference ?? null,
        },
      },
      trx,
    );

    return toRecharge(row);
  });
}

// ============================================================================
// Execution — refuses, today and by design
// ============================================================================

export interface CapUsage {
  monthlyRechargeCap: number | null;
  monthlyCostCapCents: number | null;
  rechargesThisMonth: number;
  /** Priced rows only. Unpriced ones are in `unpricedThisMonth`, never here. */
  costThisMonthCents: number;
  unpricedThisMonth: number;
}

/** This account's spend so far this month, for display next to its ceilings. */
export async function capUsage(accountId: number): Promise<CapUsage> {
  const account = await db('sim_accounts')
    .where('id', accountId)
    .first<
      { monthly_recharge_cap: number | null; monthly_cost_cap_cents: string | number | null } | undefined
    >('monthly_recharge_cap', 'monthly_cost_cap_cents');

  const monthStart = new Date();
  monthStart.setUTCDate(1);
  monthStart.setUTCHours(0, 0, 0, 0);

  const rows = await db('sim_recharges')
    .where('account_id', accountId)
    .whereIn('status', [...SIM_BILLABLE_STATUSES])
    .where('completed_at', '>=', monthStart)
    .select<Array<{ cost_cents: string | number | null }>>('cost_cents');

  return {
    monthlyRechargeCap: account?.monthly_recharge_cap ?? null,
    monthlyCostCapCents:
      account?.monthly_cost_cap_cents == null ? null : Number(account.monthly_cost_cap_cents),
    rechargesThisMonth: rows.length,
    costThisMonthCents: rows
      .filter((r) => r.cost_cents !== null)
      .reduce((s, r) => s + Number(r.cost_cents), 0),
    // An unpriced top-up is not a free one — it is one whose invoice has not
    // arrived. Counted, never added as zero: `assertExecutionAllowed` refuses
    // to spend against a month it cannot price, because summing the unknown as
    // zero is how a cost ceiling silently stops being a ceiling.
    unpricedThisMonth: rows.filter((r) => r.cost_cents === null).length,
  };
}

/**
 * May the MACHINE buy this one?
 *
 * NULL IS REFUSE. An account with no ceiling written down is an account nobody
 * has decided a budget for, and "unlimited by default" is the setting that
 * turns one misread balance into a month of purchases. The operator must name
 * a number before automation is allowed to act — which is also the moment they
 * think about what the number should be.
 *
 * Not called on proposal (costs nothing) and not called on recording (already
 * happened). Called only from `execute`.
 */
export async function assertExecutionAllowed(
  accountId: number,
  estimatedCostCents: number | null,
): Promise<void> {
  const usage = await capUsage(accountId);
  if (usage.monthlyRechargeCap === null || usage.monthlyCostCapCents === null) {
    throw new SimAccountError(
      'Automatic top-ups are refused on this account: no monthly ceiling is configured. ' +
        'Set a maximum number of top-ups and a maximum monthly cost first.',
      409,
    );
  }
  if (usage.rechargesThisMonth + 1 > usage.monthlyRechargeCap) {
    throw new SimAccountError(
      `This account has already reached its ceiling of ${usage.monthlyRechargeCap} top-ups ` +
        `this month.`,
      409,
    );
  }
  // A month containing top-ups whose cost is unknown cannot be checked against
  // a cost ceiling at all: the running total is a floor, not a total, and
  // treating it as one lets the ceiling be exceeded by exactly the amount
  // nobody has recorded yet. Refusing is the conservative reading, and the
  // operator's way out is to record the missing invoice.
  if (usage.unpricedThisMonth > 0) {
    throw new SimAccountError(
      `This account has ${usage.unpricedThisMonth} top-up(s) this month with no recorded cost, ` +
        `so the monthly ceiling cannot be checked. Record their cost first.`,
      409,
    );
  }
  // An estimate of `null` is an unknown price, and an unknown price cannot be
  // shown to fit under a ceiling either.
  if (estimatedCostCents === null) {
    throw new SimAccountError(
      'This top-up has no expected cost, so it cannot be checked against the monthly ceiling.',
      409,
    );
  }
  if (usage.costThisMonthCents + estimatedCostCents > usage.monthlyCostCapCents) {
    throw new SimAccountError('This top-up would exceed the account monthly cost ceiling.', 409);
  }
}

/**
 * Buys the top-up through a partner adapter.
 *
 * Refuses for every platform today, because `SIM_RECHARGE_ADAPTERS` is empty on
 * purpose (`types.ts`). The refusal names what is missing so an operator reads
 * "nobody has an endpoint for this" rather than "something went wrong".
 */
export async function execute(
  scope: SimScope,
  id: number,
  actor: { id: number; name: string },
): Promise<SimRecharge> {
  const q = db<RechargeRow>('sim_recharges').where('id', id);
  if (!scope.masterView) q.where('tenant_id', scope.tenantId);
  const row = await q.first();
  if (!row) throw new SimAccountError('Top-up not found', 404);

  // ┌─ THE FOUR-EYES CHECK, ON THE ONLY PATH THAT CAN SPEND ─────────────────┐
  // │ The first draft went straight to the adapter lookup, so the one route  │
  // │ in this product capable of committing money never asked whether the    │
  // │ top-up had been approved. It is unreachable today only because the     │
  // │ adapter registry is empty — which is precisely the kind of latent hole │
  // │ that becomes live the day somebody fills the registry and reasonably   │
  // │ assumes the guard was already there.                                    │
  // │                                                                        │
  // │ Expressed through the shared transition table rather than as a literal │
  // │ `=== 'approved'`, so it cannot disagree with the state machine.        │
  // └────────────────────────────────────────────────────────────────────────┘
  if (!canRechargeTransition(row.status, 'executed')) {
    throw new SimAccountError(
      `A top-up that is ${row.status} cannot be bought: it has not been approved.`,
      409,
    );
  }

  // The ACCESSOR, not merely the predicate: this is the line that will hand the
  // adapter to the call the day one exists, so it is the shape the code should
  // already have. `getRechargeAdapter` had no caller while `canExecuteRecharge`
  // did the asking — two ways to ask one question (§11.1, motif 2).
  const adapter = getRechargeAdapter(row.platform);
  if (!adapter) {
    const info = simPlatformInfo(row.platform);
    // Logged, not merely refused: somebody holding SIM_RECHARGE asked the
    // machine to buy. That is worth a line the day an adapter exists and this
    // stops being a refusal, and it keeps `actor` a real parameter rather than
    // a signature nobody uses (§11.1, motif 2, in miniature).
    logger.info(
      { rechargeId: id, platform: row.platform, userId: actor.id },
      'Refused a machine-executed top-up: no adapter for this platform',
    );
    throw new SimAccountError(
      `ObliWAN cannot buy a top-up on ${info.label}: no partner endpoint for it has been ` +
        `confirmed, so no execution adapter exists. Buy it on the partner portal and ` +
        `record it here — the re-invoicing report counts it either way.`,
      501,
    );
  }

  // Unreachable today. Written now so that the day an adapter lands, the caps
  // check is already upstream of the call rather than something to remember —
  // §11.1 motif 2 is a function that states a rule and has no caller, and the
  // inverse defect is a call site that forgot the rule.
  await assertExecutionAllowed(row.account_id!, row.cost_cents === null ? null : Number(row.cost_cents));
  throw new SimAccountError(
    'Execution adapter present but not wired. Refusing rather than guessing.',
    501,
  );
}

// ============================================================================
// Reads and housekeeping
// ============================================================================

export interface RechargeFilters {
  status?: SimRechargeStatus[];
  simId?: number;
  from?: Date;
  to?: Date;
  limit?: number;
}

export async function listRecharges(
  scope: SimScope,
  filters: RechargeFilters = {},
): Promise<SimRecharge[]> {
  const q = scopeRecharges(scope);
  if (filters.status?.length) q.whereIn('r.status', filters.status);
  if (filters.simId !== undefined) q.where('r.sim_id', filters.simId);
  if (filters.from) q.where('r.proposed_at', '>=', filters.from);
  if (filters.to) q.where('r.proposed_at', '<=', filters.to);
  const rows = await q.orderBy('r.proposed_at', 'desc').limit(Math.min(filters.limit ?? 200, 2000));
  return rows.map(toRecharge);
}

export async function getRecharge(scope: SimScope, id: number): Promise<SimRecharge | null> {
  const row = await scopeRecharges(scope).where('r.id', id).first();
  return row ? toRecharge(row) : null;
}

/**
 * Retires proposals nobody acted on, and reopens the episode.
 *
 * The second half is what makes this safe to run on a timer. Expiring alone
 * would leave `sim_balances.low_since` untouched, so the next sweep would
 * rebuild the SAME idempotency key, hit the unique index against the expired
 * row, and silently propose nothing — a line that is still empty and no longer
 * announced. Clearing the marker lets the next sweep open a fresh episode with
 * a fresh key, which is the honest behaviour: still low, said again.
 */
export async function expireStale(): Promise<number> {
  const cutoff = new Date(Date.now() - PROPOSAL_TTL_DAYS * 86_400_000);
  return db.transaction(async (trx) => {
    const stale = await trx<RechargeRow>('sim_recharges')
      .where('status', 'proposed')
      .where('proposed_at', '<', cutoff)
      .forUpdate()
      .select('id', 'sim_id', 'zone', 'tenant_id', 'idempotency_key');

    if (stale.length === 0) return 0;

    await trx('sim_recharges')
      .whereIn('id', stale.map((r) => r.id))
      .update({
        status: 'expired',
        decided_at: trx.fn.now(),
        // APPENDED, not overwritten — the same rule `recordCompletion` follows.
        // A manual proposal carries the operator's reason for raising it, and
        // replacing it with "expired automatically" destroys the only record of
        // why anybody asked for this top-up in the first place.
        decision_note: trx.raw(
          `CASE WHEN decision_note IS NULL OR btrim(decision_note) = '' THEN ? ` +
            `ELSE decision_note || E'
' || ? END`,
          [EXPIRY_NOTE, EXPIRY_NOTE],
        ),
        updated_at: trx.fn.now(),
      });

    // ┌─ CLEAR THE EPISODE THIS PROPOSAL WAS KEYED ON, AND NO OTHER ───────────┐
    // │ The first draft cleared `low_since` for the (line, zone) pair          │
    // │ unconditionally, which is wrong whenever the marker has MOVED ON since │
    // │ the proposal was made:                                                 │
    // │                                                                        │
    // │   day 0   line falls  -> episode E1, proposal P1                       │
    // │   day 3   line recovers, is topped up elsewhere, falls again           │
    // │           -> E1 cleared, episode E2 opened, proposal P2 created        │
    // │   day 14  P1 expires  -> the old code cleared E2's marker              │
    // │   day 14  next sweep sees no marker, opens E3, creates proposal P3     │
    // │                                                                        │
    // │ Two live proposals for one ongoing shortage — and, the day an          │
    // │ execution adapter exists, two purchases. That is exactly the outcome   │
    // │ decision 5 and the UNIQUE index were built to make impossible, undone  │
    // │ by the housekeeping job.                                               │
    // │                                                                        │
    // │ So the marker is cleared only when the CURRENT episode is still the    │
    // │ one this proposal was keyed on. The comparison rebuilds the key with   │
    // │ the same shared function that minted it, so the two cannot drift.      │
    // └────────────────────────────────────────────────────────────────────────┘
    let reopened = 0;
    for (const r of stale) {
      if (r.sim_id === null) continue;
      // `lower(zone)` for the same reason `upsertZone` does: row identity in
      // `sim_balances` is the functional index, and a case-sensitive lookup
      // here silently finds nothing and reopens no episode.
      const balance = await trx('sim_balances')
        .where('sim_id', r.sim_id)
        .whereRaw('lower(zone) = lower(?)', [r.zone])
        .forUpdate()
        .first<{ low_since: Date | string | null } | undefined>('low_since');
      if (!balance?.low_since) continue;

      const currentEpisode = new Date(balance.low_since).toISOString();
      if (rechargeIdempotencyKey(r.sim_id, r.zone, currentEpisode) !== r.idempotency_key) {
        // The line has fallen again since; a newer proposal owns that episode.
        continue;
      }
      await trx('sim_balances')
        .where('sim_id', r.sim_id)
        .whereRaw('lower(zone) = lower(?)', [r.zone])
        .update({ low_since: null, updated_at: trx.fn.now() });
      reopened += 1;
    }

    logger.info(
      { expired: stale.length, episodesReopened: reopened },
      'Expired stale SIM top-up proposals',
    );
    return stale.length;
  });
}

async function tenantNameOf(tenantId: number | null): Promise<string | null> {
  if (tenantId === null) return null;
  const row = await db('tenants').where('id', tenantId).first<{ name: string } | undefined>('name');
  return row?.name ?? null;
}

/** Postgres unique_violation. */
function isUniqueViolation(err: unknown): boolean {
  return (err as { code?: string } | null)?.code === '23505';
}
