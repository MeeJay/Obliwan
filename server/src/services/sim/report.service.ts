/**
 * ObliWAN F9 — the re-invoicing report.
 *
 * ┌─ WHAT THIS REPORT IS FOR ─────────────────────────────────────────────────┐
 * │ An MSP tops up a customer's SIM and has to bill it back. Today that is a  │
 * │ spreadsheet somebody maintains from memory, and the top-ups that get      │
 * │ forgotten are pure loss. This answers, for a period: WHICH SITES were     │
 * │ topped up, WHEN, HOW MUCH data, and HOW MUCH it cost.                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ FOUR RULES THAT MAKE IT AUDITABLE INSTEAD OF MERELY PLAUSIBLE ───────────┐
 * │                                                                          │
 * │ 1. ONLY BILLABLE ROWS. `executed` and `recorded` — a top-up that was      │
 * │    actually bought. A `proposed` or `approved` row has cost nobody        │
 * │    anything and appearing as a charge would over-invoice.                 │
 * │                                                                          │
 * │ 2. GROUPED ON THE FROZEN NAMES, NOT ON A LIVE JOIN. The site and tenant   │
 * │    names come from the recharge row, copied at proposal time (migration   │
 * │    032, decision 7). A live join would rewrite last quarter's report      │
 * │    every time somebody renames a site, and would drop every row whose     │
 * │    line has since been deleted — which is exactly the row somebody is     │
 * │    looking for when they cannot find a charge.                            │
 * │                                                                          │
 * │ 3. AN UNPRICED TOP-UP IS COUNTED, NEVER SUMMED AS ZERO. `cost_cents` is   │
 * │    legitimately null right after a top-up is recorded — the partner's     │
 * │    invoice arrives later. Adding it as 0 produces a total that looks      │
 * │    complete and under-charges silently. So `unpricedCount` travels with   │
 * │    every total, and a period where nothing is priced reports `null`       │
 * │    rather than `0`. This is the same rule F7 got from the F2 audit: a     │
 * │    period with no data is "no measurement", not 100 %.                    │
 * │                                                                          │
 * │ 4. MIXED CURRENCIES ARE REPORTED, NOT ADDED. If two currencies appear,    │
 * │    the total is arithmetic on incompatible units. `currencies` carries    │
 * │    what was found so the screen can refuse to show one number.            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2): MSISDNs, site names, dates and money. No credential is in
 * reach of this module.
 */

import {
  SIM_BILLABLE_STATUSES,
  suggestsPlanChange,
  type SimPlatform,
  type SimRechargeReport,
  type SimRechargeReportRow,
} from '@obliwan/shared';
import { db } from '../../db';
import type { SimScope } from './line.service';

interface BillableRow {
  sim_id: number | null;
  tenant_id: number | null;
  tenant_name: string | null;
  site_id: number | null;
  site_name: string | null;
  msisdn: string;
  platform: SimPlatform;
  operator: string | null;
  plan_mb: number | null;
  cost_cents: string | number | null;
  currency: string | null;
  completed_at: Date | string;
}

/**
 * A key that groups by LINE within a site.
 *
 * Grouping by site alone would merge two SIMs at the same site into one row and
 * lose which line was topped up — the first question asked when a charge is
 * queried. `site_id` may be null (a line assigned to a customer but not to a
 * site), and null is its own group rather than being folded into the first one.
 */
function groupKey(r: BillableRow): string {
  return `${r.tenant_id ?? 'none'}|${r.site_id ?? 'none'}|${r.msisdn}`;
}

/** `2026-03` — the bucket `monthsWithRecharge` counts distinct values of. */
function monthKey(d: Date): string {
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

/**
 * Today's subscribed allowance per line, summed across zones.
 *
 * Read from `sim_balances`, which is the CURRENT state — no partner tells us
 * what the plan was last March, and the report says so on screen rather than
 * implying a point-in-time figure. A line whose zones report no plan size at
 * all returns nothing and the row shows `null`, never 0: "we do not know this
 * line's allowance" and "this line has no allowance" are opposite findings.
 */
async function basePlans(scope: SimScope, simIds: number[]): Promise<Map<number, number>> {
  const out = new Map<number, number>();
  if (simIds.length === 0) return out;

  // ┌─ THE TENANT PREDICATE IS NOT OPTIONAL HERE (§11.1, motif 4) ────────────┐
  // │ `sim_balances` has no tenant column of its own, so the ONLY possible    │
  // │ isolation is the join to `sim_lines` below.                             │
  // │                                                                        │
  // │ The ids reaching this function come from `sim_recharges.sim_id`, which  │
  // │ is FROZEN at proposal time and points at the LIVE line — and a line can │
  // │ be re-assigned to another customer afterwards. Without the join, tenant │
  // │ A's March invoice would print tenant B's current subscribed allowance   │
  // │ in its "Plan today" column, and `suggestsPlanChange` would compute      │
  // │ "plan too small" for A from B's live subscription.                      │
  // │                                                                        │
  // │ A line that has since moved workspaces simply contributes nothing, and  │
  // │ the report renders that as "—" (unknown allowance) rather than as 0 —   │
  // │ which is the honest answer: we no longer know what that line's plan is. │
  // └────────────────────────────────────────────────────────────────────────┘
  const q = db('sim_balances as b')
    .join('sim_lines as l', 'l.id', 'b.sim_id')
    .whereIn('b.sim_id', simIds)
    .whereNotNull('b.recharge_mb');
  if (!scope.masterView) q.where('l.tenant_id', scope.tenantId);

  const rows = await q.select<Array<{ sim_id: number; recharge_mb: number }>>(
    'b.sim_id',
    'b.recharge_mb',
  );
  for (const r of rows) {
    out.set(r.sim_id, (out.get(r.sim_id) ?? 0) + Number(r.recharge_mb));
  }
  return out;
}

export async function rechargeReport(
  scope: SimScope,
  from: Date,
  to: Date,
): Promise<SimRechargeReport> {
  const q = db<BillableRow>('sim_recharges')
    .whereIn('status', [...SIM_BILLABLE_STATUSES])
    .where('completed_at', '>=', from)
    .where('completed_at', '<=', to)
    .select(
      'sim_id',
      'tenant_id',
      'tenant_name',
      'site_id',
      'site_name',
      'msisdn',
      'platform',
      'operator',
      'plan_mb',
      'cost_cents',
      'currency',
      'completed_at',
    );
  // The scope predicate. A tenant sees its own charges and nothing else; the
  // master view sees every tenant's, which is what an MSP needs to invoice.
  if (!scope.masterView) q.where('tenant_id', scope.tenantId);

  const rows = await q.orderBy('completed_at', 'asc');

  const groups = new Map<string, SimRechargeReportRow>();
  // Distinct calendar months per group. A Set rather than a counter because the
  // same month appearing three times is ONE month of recurrence, and it is the
  // recurrence — not the number of top-ups — that says a plan is the wrong size.
  const monthsByGroup = new Map<string, Set<string>>();
  const currencies = new Set<string>();
  let totalCostCents = 0;
  let pricedRows = 0;
  let unpricedTotal = 0;
  let unknownVolumeTotal = 0;

  for (const r of rows) {
    const completedAt = (r.completed_at instanceof Date
      ? r.completed_at
      : new Date(r.completed_at)
    ).toISOString();
    const cost = r.cost_cents === null ? null : Number(r.cost_cents);
    if (cost === null) unpricedTotal += 1;
    else {
      totalCostCents += cost;
      pricedRows += 1;
    }
    if (r.plan_mb === null) unknownVolumeTotal += 1;
    if (r.currency) currencies.add(r.currency);

    const key = groupKey(r);
    const completedDate =
      r.completed_at instanceof Date ? r.completed_at : new Date(r.completed_at);
    const months = monthsByGroup.get(key) ?? new Set<string>();
    months.add(monthKey(completedDate));
    monthsByGroup.set(key, months);

    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, {
        siteId: r.site_id,
        siteName: r.site_name,
        tenantId: r.tenant_id,
        tenantName: r.tenant_name,
        simId: r.sim_id,
        msisdn: r.msisdn,
        platform: r.platform,
        operator: r.operator,
        rechargeCount: 1,
        totalMb: r.plan_mb,
        totalCostCents: cost,
        // A group whose rows disagree on currency reports none rather than the
        // first one seen — rule 4, applied per row as well as per report.
        currency: r.currency,
        firstRechargeAt: completedAt,
        lastRechargeAt: completedAt,
        unpricedCount: cost === null ? 1 : 0,
        // The same rule as `unpricedCount`, applied to the other partial sum:
        // a top-up recorded with the volume left blank contributes nothing to
        // `totalMb`, and a total that silently omits it understates what the
        // line consumed — which is the number `suggestsPlanChange` reads.
        unknownVolumeCount: r.plan_mb === null ? 1 : 0,
        // Both filled after the loop: the allowance needs one batched read, and
        // the month count is only final once every row has been seen.
        basePlanMb: null,
        monthsWithRecharge: 0,
      });
      continue;
    }

    existing.rechargeCount += 1;
    // A group mixing known and unknown volumes keeps the known part and says
    // how many rows carried nothing, rather than presenting a partial sum as a
    // complete one.
    existing.totalMb =
      r.plan_mb === null ? existing.totalMb : (existing.totalMb ?? 0) + r.plan_mb;
    existing.totalCostCents =
      cost === null ? existing.totalCostCents : (existing.totalCostCents ?? 0) + cost;
    if (cost === null) existing.unpricedCount += 1;
    if (r.plan_mb === null) existing.unknownVolumeCount += 1;
    // ┌─ A MISSING CURRENCY IS NOT A CONFLICTING ONE ──────────────────────┐
    // │ An UNPRICED row carries `currency = null` (the CHECK only demands  │
    // │ one when there is a cost). Comparing `existing.currency !== null`  │
    // │ therefore wiped the currency of any group mixing a priced and an   │
    // │ unpriced top-up — and the row then printed an amount with no unit, │
    // │ which is migration 032 decision 8's named failure, on the very     │
    // │ screen that exists to be handed to accounting.                      │
    // │                                                                   │
    // │ Only two DIFFERENT non-null currencies are a genuine conflict.      │
    // └───────────────────────────────────────────────────────────────────┘
    if (r.currency !== null) {
      existing.currency = existing.currency === null ? r.currency : existing.currency;
      if (existing.currency !== r.currency) existing.currency = null;
    }
    // Rows arrive ordered by `completed_at`, so the last one wins the max.
    existing.lastRechargeAt = completedAt;
    // A deleted line leaves `sim_id` null on later rows; keep the first id we
    // saw so the allowance lookup still has something to match on.
    if (existing.simId === null) existing.simId = r.sim_id;
  }

  // ── The two decision fields ───────────────────────────────────────────────
  const plans = await basePlans(
    scope,
    [...groups.values()].map((g) => g.simId).filter((v): v is number => v !== null),
  );
  for (const [key, g] of groups) {
    g.monthsWithRecharge = monthsByGroup.get(key)?.size ?? 0;
    // `?? null`, never `?? 0`: a line whose partner reports no plan size is a
    // line whose allowance we do not know, and 0 would read as "no allowance
    // at all" — the opposite finding, and the one that makes every such line
    // look like it needs a bigger plan.
    g.basePlanMb = g.simId === null ? null : (plans.get(g.simId) ?? null);
  }

  return {
    from: from.toISOString(),
    to: to.toISOString(),
    // ┌─ ORDERED BY WHAT THE SCREEN EXISTS TO ANSWER: WHO COSTS THE MOST ────┐
    // │ Cost first, then recurrence, then count. `?? -1` puts a line whose    │
    // │ cost is UNKNOWN last among priced lines rather than first, which is   │
    // │ the right default — an unpriced line is not evidence of a large       │
    // │ spend — and the recurrence tiebreak then lifts a line with three      │
    // │ unpriced top-ups above one with a single cheap priced one. The first  │
    // │ draft's comment claimed the opposite of what the comparator did; the  │
    // │ comparator is right and the sentence was wrong.                        │
    // └──────────────────────────────────────────────────────────────────────┘
    rows: [...groups.values()].sort(
      (a, b) =>
        (b.totalCostCents ?? -1) - (a.totalCostCents ?? -1) ||
        b.monthsWithRecharge - a.monthsWithRecharge ||
        b.rechargeCount - a.rechargeCount ||
        (a.siteName ?? '￿').localeCompare(b.siteName ?? '￿'),
    ),
    totalRecharges: rows.length,
    // Rule 3: nothing priced → `null`, never `0`.
    totalCostCents: pricedRows === 0 ? null : totalCostCents,
    unpricedCount: unpricedTotal,
    unknownVolumeCount: unknownVolumeTotal,
    currencies: [...currencies].sort(),
  };
}

/**
 * The same data as a CSV, for the person who actually builds the invoice.
 *
 * Written here rather than in the controller so the report and its export
 * cannot drift apart — a CSV that disagrees with the screen it was exported
 * from is worse than no CSV.
 *
 * Every field is quoted and internal quotes are doubled. A site name beginning
 * with `=` is prefixed with an apostrophe: a spreadsheet would otherwise
 * evaluate it as a formula, which is both a corrupted invoice and a well-known
 * injection into whoever opens the file.
 */
export function reportToCsv(report: SimRechargeReport): string {
  const header = [
    'Workspace',
    'Site',
    'MSISDN',
    'Platform',
    'Operator',
    'Top-ups',
    'Months with a top-up',
    'Plan today (MB)',
    'Topped up (MB)',
    'Cost',
    'Currency',
    'Unpriced',
    'Volume unknown',
    'Plan looks undersized',
    'First',
    'Last',
  ];
  const lines = [header.map(csvCell).join(',')];
  for (const r of report.rows) {
    lines.push(
      [
        r.tenantName ?? '',
        r.siteName ?? '',
        r.msisdn,
        r.platform,
        r.operator ?? '',
        String(r.rechargeCount),
        String(r.monthsWithRecharge),
        // Empty, not '0'. An unknown allowance is not a zero allowance, and a
        // spreadsheet that reads 0 there shows every such line as undersized.
        r.basePlanMb === null ? '' : String(r.basePlanMb),
        r.totalMb === null ? '' : String(r.totalMb),
        r.totalCostCents === null ? '' : (r.totalCostCents / 100).toFixed(2),
        r.currency ?? '',
        String(r.unpricedCount),
        String(r.unknownVolumeCount),
        suggestsPlanChange(r) ? 'yes' : '',
        r.firstRechargeAt,
        r.lastRechargeAt,
      ]
        .map(csvCell)
        .join(','),
    );
  }
  return lines.join('\r\n');
}

function csvCell(value: string): string {
  const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${guarded.replace(/"/g, '""')}"`;
}
