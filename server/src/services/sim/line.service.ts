/**
 * ObliWAN F9 — the SIM inventory: reads, assignment, thresholds.
 *
 * ┌─ EVERY READ IN THIS FILE IS SCOPED, AND THE POOL IS THE INTERESTING CASE ─┐
 * │ `sim_lines.tenant_id` is nullable and NULL means "nobody has claimed this │
 * │ line yet" (migration 032, decision 3). So there are two scopes, not one:  │
 * │                                                                          │
 * │   a tenant sees `tenant_id = :tenantId`. Full stop. Never the pool — a    │
 * │   pooled line may be about to be assigned to a competitor, and its        │
 * │   MSISDN is somebody's property.                                          │
 * │                                                                          │
 * │   the master tenant sees everything INCLUDING the pool, because the pool  │
 * │   is the queue of work: lines the partner reported that nobody has        │
 * │   attached to a customer.                                                 │
 * │                                                                          │
 * │ `scopeLines()` is the ONE place that predicate is written, and every      │
 * │ exported read goes through it. `masterView` is never derived from         │
 * │ `req.session.currentTenantId`; it comes from `requireTenant`, which       │
 * │ established it against a real `user_tenants` row (AUDIT-SEC #2).          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A LINE IS NEVER DELETED BY A SWEEP, AND THAT IS DELIBERATE ──────────────┐
 * │ `GetLigneGsmByFilterPaged` is, by its own name, paged — and the field     │
 * │ prototype read page one and stopped. If a sweep deleted lines it did not  │
 * │ see, one truncated page would silently retire half the fleet, and the     │
 * │ dashboard would show a smaller, perfectly healthy-looking inventory.      │
 * │                                                                          │
 * │ So the sweep only ever inserts and updates, and `last_seen_at` is what    │
 * │ says a line has gone quiet. Retiring one is a human act.                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2): nothing here can return vault material. The widest object is
 * an MSISDN, an operator name, a site name and a data quantity.
 *
 * D3: no path in this file opens a session on an equipment.
 */

import {
  HARDCODED_DEFAULTS,
  MASTER_TENANT_ID,
  SIM_BILLABLE_STATUSES,
  SETTINGS_KEYS,
  clampSetting,
  effectiveThresholdMb,
  lineVerdict,
  stalenessHorizonMs,
  type BalanceVerdict,
  type ReadingFreshness,
  type SettingsKey,
  type SimFleetSummary,
  type SimLine,
  type SimLineUpdate,
  type SimPlatform,
  type SimZoneBalance,
} from '@obliwan/shared';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { settingsService } from '../settings.service';
import { SimAccountError, assertAssignable } from './account.service';
import { isPollable } from './registry';

export interface SimScope {
  tenantId: number;
  /** Set by `requireTenant` after a real `user_tenants` lookup. Never inferred. */
  masterView?: boolean;
}

// ============================================================================
// Settings
// ============================================================================

/**
 * The global default low-data threshold, in MB, for one tenant.
 *
 * A POOLED line has no tenant and therefore no tenant-scoped override; it falls
 * back to `HARDCODED_DEFAULTS`. That is the honest answer — a line nobody owns
 * cannot inherit a customer's policy — and it only affects whether the line is
 * DISPLAYED as low, because a pooled line has no auto-recharge and produces no
 * proposal.
 */
export async function globalThresholdMb(tenantId: number | null): Promise<number> {
  const key: SettingsKey = SETTINGS_KEYS.SIM_LOW_DATA_THRESHOLD;
  if (tenantId === null) return HARDCODED_DEFAULTS[key];
  const overrides = await settingsService.getByScope(tenantId, 'global', null);
  const raw = overrides[key];
  return clampSetting(key, typeof raw === 'number' ? raw : HARDCODED_DEFAULTS[key]);
}

/**
 * How old a reading may be before it stops counting as an answer.
 *
 * NOT exported: the RULE lives in `shared/src/sim.ts` (`stalenessHorizonMs`,
 * `isReadingStale`, `lineVerdict`) where it is pure and asserted by
 * `f9-rules.verify.ts`. This is only the plumbing that fetches the interval,
 * and an exported helper with no external caller is §11.1 motif 2.
 *
 * The sweep does NOT need it: `applyBalances` judges a reading it has just
 * fetched, so its verdict is fresh by construction. Freshness matters on the
 * READ paths, where a value of unbounded age would otherwise be reported as an
 * answer.
 *
 * Derived from the PLATFORM-WIDE sweep interval (the same master-tenant value
 * `services/sim/index.ts` paces the sweep with), because the question "is this
 * reading stale" is a question about whether the sweep is running, and the
 * sweep is one per installation.
 */
async function readingFreshness(): Promise<ReadingFreshness> {
  const minutes = await globalNumber(MASTER_TENANT_ID, SETTINGS_KEYS.SIM_SYNC_INTERVAL);
  return { now: Date.now(), maxAgeMs: stalenessHorizonMs(minutes) };
}

/** Any numeric setting at global scope, clamped to its definition. */
export async function globalNumber(tenantId: number, key: SettingsKey): Promise<number> {
  const overrides = await settingsService.getByScope(tenantId, 'global', null);
  const raw = overrides[key];
  return clampSetting(key, typeof raw === 'number' ? raw : HARDCODED_DEFAULTS[key]);
}

// ============================================================================
// Rows
// ============================================================================

interface LineRow {
  id: number;
  account_id: number;
  platform: SimPlatform;
  account_name: string;
  tenant_id: number | null;
  msisdn: string;
  iccid: string | null;
  operator: string | null;
  client_code: string | null;
  label: string | null;
  site_id: number | null;
  site_name: string | null;
  device_id: number | null;
  device_name: string | null;
  status: 'active' | 'suspended' | 'unknown';
  low_threshold_mb: number | null;
  auto_recharge_enabled: boolean;
  recharge_plan_mb: number | null;
  first_seen_at: Date | string;
  last_seen_at: Date | string;
}

interface BalanceRow {
  sim_id: number;
  zone: string;
  recharge_mb: number | null;
  used_mb: number | null;
  rest_mb: number | null;
  observed_at: Date | string;
  low_since: Date | string | null;
}

function iso(v: Date | string | null): string | null {
  if (v === null) return null;
  return v instanceof Date ? v.toISOString() : new Date(v).toISOString();
}

/**
 * The base query, with the scope predicate and the two tenant-safe joins.
 *
 * Both joins match on id AND tenant, exactly like `loadFleet` in F8: `site_id`
 * and `device_id` are nullable with SET NULL semantics, so the pair really can
 * go stale, and a site name must never be borrowed from another customer even
 * if one did.
 */
function scopeLines(scope: SimScope, executor: Knex | Knex.Transaction = db) {
  const q = executor<LineRow>('sim_lines as l')
    .join('sim_accounts as a', 'a.id', 'l.account_id')
    .leftJoin('sites as s', function joinSite() {
      this.on('s.id', '=', 'l.site_id').andOn('s.tenant_id', '=', 'l.tenant_id');
    })
    .leftJoin('devices as d', function joinDevice() {
      this.on('d.id', '=', 'l.device_id').andOn('d.tenant_id', '=', 'l.tenant_id');
    })
    .select(
      'l.id',
      'l.account_id',
      'a.platform',
      'a.name as account_name',
      'l.tenant_id',
      'l.msisdn',
      'l.iccid',
      'l.operator',
      'l.client_code',
      'l.label',
      'l.site_id',
      's.name as site_name',
      'l.device_id',
      'd.name as device_name',
      'l.status',
      'l.low_threshold_mb',
      'l.auto_recharge_enabled',
      'l.recharge_plan_mb',
      'l.first_seen_at',
      'l.last_seen_at',
    );

  if (scope.masterView) {
    // Everything, pool included. The pool IS the master view's work queue.
    return q;
  }
  return q.where('l.tenant_id', scope.tenantId);
}

async function balancesFor(simIds: number[]): Promise<Map<number, SimZoneBalance[]>> {
  const out = new Map<number, SimZoneBalance[]>();
  if (simIds.length === 0) return out;
  const rows = await db<BalanceRow>('sim_balances')
    .whereIn('sim_id', simIds)
    .orderBy(['sim_id', 'zone']);
  for (const r of rows) {
    const list = out.get(r.sim_id) ?? [];
    list.push({
      zone: r.zone,
      rechargeMb: r.recharge_mb,
      usedMb: r.used_mb,
      restMb: r.rest_mb,
      observedAt: iso(r.observed_at)!,
      lowSince: iso(r.low_since),
    });
    out.set(r.sim_id, list);
  }
  return out;
}

function toLine(row: LineRow, zones: SimZoneBalance[]): SimLine {
  return {
    id: row.id,
    accountId: row.account_id,
    platform: row.platform,
    accountName: row.account_name,
    tenantId: row.tenant_id,
    msisdn: row.msisdn,
    iccid: row.iccid,
    operator: row.operator,
    clientCode: row.client_code,
    label: row.label,
    siteId: row.site_id,
    siteName: row.site_name,
    deviceId: row.device_id,
    deviceName: row.device_name,
    status: row.status,
    lowThresholdMb: row.low_threshold_mb,
    autoRechargeEnabled: row.auto_recharge_enabled,
    rechargePlanMb: row.recharge_plan_mb,
    firstSeenAt: iso(row.first_seen_at)!,
    lastSeenAt: iso(row.last_seen_at)!,
    zones,
  };
}

// ============================================================================
// Reads
// ============================================================================

export interface SimLineFilters {
  accountId?: number;
  /** 'pool' is only meaningful under masterView; a tenant never sees one. */
  assignment?: 'assigned' | 'pool';
  verdict?: BalanceVerdict;
  search?: string;
  limit?: number;
}

export interface SimLineListItem extends SimLine {
  verdict: BalanceVerdict;
  /** The threshold actually applied to this line, for display. */
  thresholdMb: number;
  /** The zone the verdict came from. Null when nothing is readable. */
  worstZone: SimZoneBalance | null;
  /**
   * `unknown` BECAUSE the readings are too old, rather than because there never
   * were any. Both are unknown; only this one means "the sweep has stopped",
   * which is an operator action rather than a line that was never polled.
   */
  stale: boolean;
}

export async function listLines(
  scope: SimScope,
  filters: SimLineFilters = {},
): Promise<SimLineListItem[]> {
  const q = scopeLines(scope);
  if (filters.accountId !== undefined) q.where('l.account_id', filters.accountId);
  if (filters.assignment === 'pool') q.whereNull('l.tenant_id');
  if (filters.assignment === 'assigned') q.whereNotNull('l.tenant_id');
  if (filters.search) {
    // Bound parameters, and the wildcards are ours. The operator's text is
    // never concatenated into the SQL (§11.1, motif 6).
    const term = `%${filters.search.trim()}%`;
    q.where((b) =>
      b
        .whereILike('l.msisdn', term)
        .orWhereILike('l.label', term)
        .orWhereILike('l.client_code', term)
        .orWhereILike('s.name', term),
    );
  }
  // ┌─ THE ORDER OF LIMIT AND FILTER IS LOAD-BEARING ─────────────────────────┐
  // │ A verdict cannot be a SQL predicate: it comes from a threshold resolved │
  // │ per line out of a setting plus a per-line override, and duplicating     │
  // │ that resolution in SQL would be a second implementation of the rule     │
  // │ that decides whether money gets spent.                                  │
  // │                                                                        │
  // │ So the filter runs in TypeScript — and the caller's limit must run      │
  // │ AFTER it. The first draft applied `.limit(n)` in SQL and then filtered, │
  // │ so `listLines({verdict:'low', limit:50})` meant "the first 50 lines by  │
  // │ MSISDN, of which the low ones": the dashboard's "running low" panel     │
  // │ disagreed with its own "running low" tile, which counts over the whole  │
  // │ fleet. Here the SQL cap is a HARD safety bound on the read, the         │
  // │ caller's limit is applied to the filtered result, and a truncation says │
  // │ so in the log rather than silently reading as "that is all of them".    │
  // └────────────────────────────────────────────────────────────────────────┘
  const HARD_CAP = 5000;
  q.orderBy('l.msisdn').limit(HARD_CAP + 1);

  const rows = await q;
  if (rows.length > HARD_CAP) {
    rows.length = HARD_CAP;
    logger.warn(
      { tenantId: scope.tenantId, cap: HARD_CAP },
      'SIM line listing truncated at the hard cap — counts on this page are incomplete',
    );
  }
  const zones = await balancesFor(rows.map((r) => r.id));

  // The threshold is resolved per tenant, once per distinct tenant rather than
  // once per line: a 400-line fleet would otherwise issue 400 settings reads.
  const thresholds = await thresholdCache(rows.map((r) => r.tenant_id));

  // One clock for the whole listing: judging row 1 against a different instant
  // from row 400 would make a long read report two different fleets.
  const freshness = await readingFreshness();

  const items = rows.map((row) => {
    const z = zones.get(row.id) ?? [];
    const thresholdMb = effectiveThresholdMb(
      row.low_threshold_mb,
      thresholds.get(row.tenant_id) ?? HARDCODED_DEFAULTS[SETTINGS_KEYS.SIM_LOW_DATA_THRESHOLD],
    );
    const { verdict, zone, stale } = lineVerdict(z, thresholdMb, freshness);
    return { ...toLine(row, z), verdict, thresholdMb, worstZone: zone, stale };
  });

  const filtered = filters.verdict
    ? items.filter((i) => i.verdict === filters.verdict)
    : items;
  return filtered.slice(0, Math.min(filters.limit ?? 1000, HARD_CAP));
}

async function thresholdCache(tenantIds: (number | null)[]): Promise<Map<number | null, number>> {
  const out = new Map<number | null, number>();
  for (const t of new Set(tenantIds)) {
    out.set(t, await globalThresholdMb(t));
  }
  return out;
}

export async function getLine(scope: SimScope, id: number): Promise<SimLineListItem | null> {
  const rows = await scopeLines(scope).where('l.id', id);
  const row = rows[0];
  // 404, never 403: a 403 confirms the id exists, which on a serial primary key
  // is an enumeration oracle over another customer's SIM inventory.
  if (!row) return null;
  const zones = (await balancesFor([row.id])).get(row.id) ?? [];
  const thresholdMb = effectiveThresholdMb(row.low_threshold_mb, await globalThresholdMb(row.tenant_id));
  const { verdict, zone, stale } = lineVerdict(zones, thresholdMb, await readingFreshness());
  return { ...toLine(row, zones), verdict, thresholdMb, worstZone: zone, stale };
}

/** The zone history of one line, newest first. Read by the line detail screen. */
export async function getLineHistory(
  scope: SimScope,
  id: number,
  days = 90,
): Promise<Array<{ zone: string; restMb: number | null; usedMb: number | null; observedAt: string }>> {
  // Scope first: the history query below is keyed on sim_id alone, so it MUST
  // be gated by a scoped existence check or it reads any customer's line.
  const line = await getLine(scope, id);
  if (!line) return [];
  const since = new Date(Date.now() - Math.min(Math.max(days, 1), 730) * 86_400_000);

  // ┌─ THE SERIES IS CUT AT THE ASSIGNMENT BOUNDARY ─────────────────────────┐
  // │ `sim_balance_samples` is the LINE's physical record and survives a      │
  // │ re-assignment, which is right — but the part recorded before the move   │
  // │ is the previous customer's consumption, month by month, and handing it  │
  // │ to the new owner is handing over a competitor's usage. The master view  │
  // │ sees the whole series: it is the one scope that legitimately looks      │
  // │ across customers.                                                       │
  // └────────────────────────────────────────────────────────────────────────┘
  const q = db<BalanceRow>('sim_balance_samples')
    .where('sim_id', id)
    .where('observed_at', '>=', since);
  if (!scope.masterView) {
    const owned = await db('sim_lines')
      .where('id', id)
      .first<{ tenant_assigned_at: Date | string | null } | undefined>('tenant_assigned_at');
    if (owned?.tenant_assigned_at) q.where('observed_at', '>=', owned.tenant_assigned_at);
  }
  const rows = await q.orderBy('observed_at', 'desc').limit(2000);
  return rows.map((r) => ({
    zone: r.zone,
    restMb: r.rest_mb,
    usedMb: r.used_mb,
    observedAt: iso(r.observed_at)!,
  }));
}

// ============================================================================
// Assignment and per-line policy
// ============================================================================

/**
 * Updates a line. SIM_MANAGE, never SIM_RECHARGE.
 *
 * Changing `autoRechargeEnabled` here decides whether a line will ever PRODUCE
 * a proposal; it does not approve one and cannot spend anything. That split is
 * why the two capabilities exist separately.
 */
export async function updateLine(
  scope: SimScope,
  id: number,
  patch: SimLineUpdate,
): Promise<SimLineListItem> {
  const current = await getLine(scope, id);
  if (!current) throw new SimAccountError('Line not found', 404);

  const nextTenantId =
    patch.tenantId !== undefined ? patch.tenantId : current.tenantId;

  // Re-assigning a line to another tenant is a PLATFORM act. A tenant admin
  // moving a line into their own tenant would be helping themselves to somebody
  // else's inventory, and moving one out would hide a charge from a bill.
  if (patch.tenantId !== undefined && patch.tenantId !== current.tenantId && !scope.masterView) {
    throw new SimAccountError(
      'Re-assigning a line to another workspace is a platform action.',
      403,
    );
  }

  // ┌─ CLEARING THE TENANT ALSO CLEARS WHAT HUNG OFF IT — BEFORE THE CHECK ──┐
  // │ Returning a line to the pool is a legitimate act (a customer leaves, a │
  // │ SIM comes back to stock). The first draft computed the next site and   │
  // │ router from the CURRENT row, ran `assertAssignable` on that, and only  │
  // │ nulled them further down — so `updateLine({tenantId: null})` on an     │
  // │ assigned line threw "a line with no tenant cannot be attached to a     │
  // │ site", and no line that had ever been assigned could ever be returned  │
  // │ to the pool.                                                            │
  // └────────────────────────────────────────────────────────────────────────┘
  const clearingTenant = patch.tenantId === null;
  const nextSiteId = clearingTenant
    ? null
    : patch.siteId !== undefined
      ? patch.siteId
      : current.siteId;
  const nextDeviceId = clearingTenant
    ? null
    : patch.deviceId !== undefined
      ? patch.deviceId
      : current.deviceId;

  // Closes migration 032's decision-4 residual hole. See `assertAssignable`.
  assertAssignable({ tenantId: nextTenantId, siteId: nextSiteId, deviceId: nextDeviceId });

  // The composite FKs refuse a cross-tenant pair at the database, but a clear
  // message beats a constraint name in a 500. Both checks are kept: this one
  // for the operator, the constraint for everything that does not come through
  // this function.
  if (nextTenantId !== null) {
    if (nextSiteId !== null) await assertBelongs('sites', nextSiteId, nextTenantId, 'site');
    if (nextDeviceId !== null) await assertBelongs('devices', nextDeviceId, nextTenantId, 'router');
  }

  const update: Record<string, unknown> = { updated_at: db.fn.now() };
  if (patch.tenantId !== undefined) update.tenant_id = patch.tenantId;
  if (patch.siteId !== undefined) update.site_id = patch.siteId;
  if (patch.deviceId !== undefined) update.device_id = patch.deviceId;
  if (patch.iccid !== undefined) update.iccid = patch.iccid;
  if (patch.label !== undefined) update.label = patch.label;
  if (patch.lowThresholdMb !== undefined) update.low_threshold_mb = patch.lowThresholdMb;
  if (patch.autoRechargeEnabled !== undefined) {
    update.auto_recharge_enabled = patch.autoRechargeEnabled;
  }
  if (patch.rechargePlanMb !== undefined) update.recharge_plan_mb = patch.rechargePlanMb;

  // Applied from the values `assertAssignable` was actually given, so the row
  // written is exactly the row that was validated.
  if (clearingTenant) {
    update.site_id = null;
    update.device_id = null;
  }

  const movingTenant = patch.tenantId !== undefined && patch.tenantId !== current.tenantId;
  if (movingTenant) update.tenant_assigned_at = nextTenantId === null ? null : db.fn.now();

  await db.transaction(async (trx) => {
    await trx('sim_lines').where({ id }).update(update);
    if (movingTenant) await settleOpenWorkOnMove(trx, id, current.tenantId);
  });

  // Re-read through the CALLER'S OWN scope, unchanged. A non-master caller
  // cannot move a line to another tenant (refused above), so their scope still
  // contains it; a master caller sees every tenant anyway. The first draft
  // rebuilt a scope from `nextTenantId` here, which for a non-master caller
  // always evaluated to the scope it already had — dead complexity in front of
  // a security-relevant read, which is the worst place to put any.
  const refreshed = await getLine(scope, id);
  if (!refreshed) {
    // A concurrent re-assignment moved the line out of this workspace between
    // the update and the read. Report it rather than returning a stale body.
    throw new SimAccountError('Line is no longer visible in this workspace', 409);
  }
  return refreshed;
}

/**
 * What happens to a line's open work when it changes customer.
 *
 * ┌─ AN OPEN PROPOSAL IS EVIDENCE ABOUT A CUSTOMER, NOT ABOUT A SIM ────────┐
 * │ A proposal freezes the tenant, the site name and the balance at the      │
 * │ instant it was raised. Leaving it open across a re-assignment produces   │
 * │ two wrong outcomes at once: the OLD customer can still approve — and be  │
 * │ invoiced for — a top-up on a line that is no longer theirs, and the NEW  │
 * │ customer is never proposed anything, because the episode marker is still │
 * │ set and its idempotency key is already taken.                            │
 * │                                                                        │
 * │ So the open rows are EXPIRED with a stated reason, and the episode is    │
 * │ reopened so the next sweep proposes to whoever owns the line now.        │
 * │                                                                        │
 * │ Billable rows (`executed` / `recorded`) are NOT touched: that money was  │
 * │ really spent on the old customer's behalf and their invoice must keep    │
 * │ saying so. They carry their own frozen tenant and site name (migration   │
 * │ 032, decision 7) precisely so this stays true.                            │
 * └────────────────────────────────────────────────────────────────────────┘
 */
async function settleOpenWorkOnMove(
  trx: Knex.Transaction,
  simId: number,
  previousTenantId: number | null,
): Promise<void> {
  const closed = await trx('sim_recharges')
    .where('sim_id', simId)
    .whereIn('status', ['proposed', 'approved'])
    .update({
      status: 'expired',
      decided_at: trx.raw('COALESCE(decided_at, now())'),
      decision_note: trx.raw(
        `CASE WHEN decision_note IS NULL OR btrim(decision_note) = '' THEN ? ` +
          `ELSE decision_note || E'
' || ? END`,
        [MOVE_NOTE, MOVE_NOTE],
      ),
      updated_at: trx.fn.now(),
    });

  // Reopen every episode on the line, so the new owner is proposed afresh
  // rather than inheriting a marker whose key is already spent.
  await trx('sim_balances')
    .where('sim_id', simId)
    .whereNotNull('low_since')
    .update({ low_since: null, updated_at: trx.fn.now() });

  if (closed > 0) {
    logger.info(
      { simId, previousTenantId, closed },
      'SIM line re-assigned: open top-up proposals expired and episodes reopened',
    );
  }
}

const MOVE_NOTE =
  'Expired automatically: the line was re-assigned to another workspace, so this ' +
  'proposal no longer describes the customer it was raised for.';

async function assertBelongs(
  table: 'sites' | 'devices',
  id: number,
  tenantId: number,
  label: string,
): Promise<void> {
  const row = await db(table).where({ id, tenant_id: tenantId }).first('id');
  if (!row) throw new SimAccountError(`That ${label} does not exist in this workspace`, 400);
}

// ============================================================================
// Dashboard summary
// ============================================================================

export async function fleetSummary(scope: SimScope): Promise<SimFleetSummary> {
  const lines = await listLines(scope, { limit: 5000 });

  let ok = 0;
  let low = 0;
  let unknown = 0;
  let stale = 0;
  let assigned = 0;
  for (const l of lines) {
    if (l.tenantId !== null) assigned += 1;
    if (l.verdict === 'ok') ok += 1;
    else if (l.verdict === 'low') low += 1;
    else {
      unknown += 1;
      // A subset of `unknown`, not a fourth bucket: the line IS unknown. This
      // says WHY, which is the difference between "never polled" and "we have
      // stopped polling", and only the second is somebody's job today.
      if (l.stale) stale += 1;
    }
  }

  // Accounts are platform-level. A tenant is told HOW MANY are unhealthy, never
  // which — the count explains why its own lines read `unknown`, and the names
  // and hosts stay on the admin screen.
  // ┌─ ONLY THE ACCOUNTS THIS WORKSPACE ACTUALLY HAS LINES ON ───────────────┐
  // │ Accounts are platform-level, so an unscoped read put a red "partner     │
  // │ accounts unhealthy" banner on EVERY customer's dashboard the moment one │
  // │ account — possibly serving only one other customer — lost its token.    │
  // │ The count is meant to explain why THIS workspace's own lines read       │
  // │ `unknown`; an account it has no line on explains nothing.               │
  // │                                                                        │
  // │ The names and hosts still never leave the admin screen: this is a       │
  // │ COUNT, joined through `sim_lines` on the tenant predicate.              │
  // └────────────────────────────────────────────────────────────────────────┘
  const accountQuery = db('sim_accounts as a').select<
    Array<{ platform: SimPlatform; status: string; last_sync_at: Date | string | null }>
  >('a.platform', 'a.status', 'a.last_sync_at');
  if (!scope.masterView) {
    accountQuery.whereExists(
      db('sim_lines as sl').whereRaw('sl.account_id = a.id').where('sl.tenant_id', scope.tenantId),
    );
  }
  const accounts = await accountQuery;
  const failedAccounts = accounts.filter((a) => a.status === 'auth_failed').length;

  // ┌─ ONLY AN ACCOUNT THE SWEEP ACTUALLY POLLS CAN BE "STALE" ───────────────┐
  // │ A CFAST account is not polled by anything — its connector declares no   │
  // │ `pull` ingestion — so its `last_sync_at` is null forever. The           │
  // │ first draft counted null as stale, which put a permanent "partner       │
  // │ accounts unhealthy" banner on every tenant dashboard for a condition    │
  // │ nobody can clear — and a banner that is always on is a banner nobody    │
  // │ reads on the day it means something.                                     │
  // │                                                                        │
  // │ "Stale" is otherwise deliberately generous: a missed sweep is normal,   │
  // │ two in a row at the slowest allowed interval is not.                    │
  // └────────────────────────────────────────────────────────────────────────┘
  const staleCutoff = Date.now() - 2 * 1440 * 60_000;
  const staleAccounts = accounts.filter((a) => {
    if (!isPollable(a.platform)) return false;
    if (a.status !== 'active') return false;
    return a.last_sync_at !== null && new Date(a.last_sync_at).getTime() < staleCutoff;
  }).length;

  const monthStart = new Date();
  monthStart.setUTCDate(1);
  monthStart.setUTCHours(0, 0, 0, 0);

  const rechargeQuery = db('sim_recharges')
    .whereIn('status', [...SIM_BILLABLE_STATUSES])
    .where('completed_at', '>=', monthStart);
  if (!scope.masterView) rechargeQuery.where('tenant_id', scope.tenantId);
  // `currency` is selected, and that is the point: without it the tile below
  // would add euros to pounds and print the result with no unit at all.
  const billed = await rechargeQuery.select<
    Array<{ cost_cents: string | number | null; currency: string | null }>
  >('cost_cents', 'currency');

  const pendingQuery = db('sim_recharges').whereIn('status', ['proposed', 'approved']);
  if (!scope.masterView) pendingQuery.where('tenant_id', scope.tenantId);
  const pending = await pendingQuery.count<{ count: string }[]>('id as count');

  // ┌─ TWO REASONS THE TILE MAY REFUSE A NUMBER, AND BOTH ARE HONEST ────────┐
  // │ 1. Nothing priced yet -> `null`, not 0. Summing absent costs as zero is │
  // │    how a re-invoicing figure silently under-states.                      │
  // │ 2. More than one currency -> `null` too. The report screen already      │
  // │    refuses a single total across currencies (report rule 4); a          │
  // │    dashboard tile that prints one number for two currencies is worse,   │
  // │    because a tile has nowhere to put the caveat.                         │
  // │ `currencies` travels with the figure so the tile can print the unit,    │
  // │ which it could not do at all before — migration 032, decision 8.        │
  // └────────────────────────────────────────────────────────────────────────┘
  const priced = billed.filter((r) => r.cost_cents !== null);
  const currencies = [...new Set(billed.map((r) => r.currency).filter((c): c is string => !!c))].sort();
  const costThisMonthCents =
    priced.length === 0 || currencies.length > 1
      ? null
      : priced.reduce((sum, r) => sum + Number(r.cost_cents), 0);

  return {
    totalLines: lines.length,
    assignedLines: assigned,
    unassignedLines: lines.length - assigned,
    okLines: ok,
    lowLines: low,
    unknownLines: unknown,
    staleLines: stale,
    pendingProposals: Number(pending[0]?.count ?? 0),
    failedAccounts,
    staleAccounts,
    rechargesThisMonth: billed.length,
    costThisMonthCents,
    currencies,
    unpricedThisMonth: billed.length - priced.length,
  };
}
