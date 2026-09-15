/**
 * ObliWAN F9 — the sweep: read a partner, store what it said, announce what
 * changed.
 *
 * ┌─ WHAT THIS FUNCTION IS ALLOWED TO CONCLUDE ───────────────────────────────┐
 * │ Three things, and nothing else:                                           │
 * │                                                                          │
 * │   "this line exists"            → insert or refresh `last_seen_at`        │
 * │   "this zone has N MB left"     → upsert `sim_balances`, sample on change │
 * │   "this zone is below its bar"  → open an episode, alert, maybe propose   │
 * │                                                                          │
 * │ It NEVER deletes a line, NEVER writes a balance it could not read as      │
 * │ zero, and NEVER buys anything.                                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY A LINE THE PARTNER DID NOT LIST IS NOT A LINE THAT IS GONE ──────────┐
 * │ `GetLigneGsmByFilterPaged` is paged by its own name, and the connector    │
 * │ reads one page. If this sweep deleted — or even marked inactive — every   │
 * │ line absent from the answer, a single truncated page would retire half a  │
 * │ customer's fleet, and the dashboard would show a smaller inventory that   │
 * │ looks perfectly healthy. So absence updates nothing at all; `last_seen_at`│
 * │ is the signal, and retiring a line is a human act.                        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ AUTH FAILURE STOPS THE ACCOUNT. ONE LINE FAILING DOES NOT. ──────────────┐
 * │ A dead token fails identically on every line, so continuing produces a    │
 * │ `lines_failed` count equal to the fleet size and an account that reads as │
 * │ flaky rather than logged out. `AUTH_FAILED` therefore aborts the sweep,   │
 * │ flips the account to `auth_failed` (taking it out of the poll list) and   │
 * │ raises one alert. Any other per-line error is counted and skipped.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * §8.2: `sim_sync_runs.error` is written from `SimConnectorError.message`,
 * which was scrubbed of credential literals in its constructor. Nothing here
 * logs a URL — the MSISDN travels in the query string and is customer data.
 *
 * D3: no equipment is contacted. This talks to a partner's web API and to our
 * own Postgres.
 */

import {
  SETTINGS_KEYS,
  canonicalZone,
  simMsisdnSchema,
  effectiveThresholdMb,
  evaluateBalance,
  formatData,
  worstZone,
  type SimPlatform,
  type SimZoneBalance,
} from '@obliwan/shared';
import pLimit from 'p-limit';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { liveAlertService } from '../liveAlert.service';
import { notificationService } from '../notification.service';
import {
  loadCredential,
  markAuthFailed,
  type SimAccountRow,
} from './account.service';
import { globalNumber, globalThresholdMb } from './line.service';
import { proposeForLowZone } from './recharge.service';
import { stripQuery } from './phenix.connector';
import { getConnector } from './registry';
import { SimConnectorError, isAuthFailure, type RawSimBalance, type SimSession } from './types';

/**
 * Concurrent balance reads per account.
 *
 * One request PER LINE is the shape of this API, so a 400-line fleet is 400
 * calls. Four at a time keeps a sweep to a couple of minutes without looking
 * like a scraper to a partner that publishes no rate limit — and a partner that
 * rate-limits us produces an empty balance column, which is the one failure
 * this feature cannot afford because it is indistinguishable from good news.
 */
const BALANCE_CONCURRENCY = 4;

export interface SyncOutcome {
  accountId: number;
  outcome: 'ok' | 'partial' | 'auth_failed' | 'error';
  linesSeen: number;
  linesNew: number;
  balancesUpdated: number;
  linesFailed: number;
  proposalsCreated: number;
  error: string | null;
}

interface LineRow {
  id: number;
  tenant_id: number | null;
  msisdn: string;
  operator: string | null;
  site_id: number | null;
  device_id: number | null;
  low_threshold_mb: number | null;
  auto_recharge_enabled: boolean;
  recharge_plan_mb: number | null;
}

// ============================================================================
// Entry point
// ============================================================================

export async function syncAccount(account: SimAccountRow): Promise<SyncOutcome> {
  const [run] = await db('sim_sync_runs')
    .insert({ account_id: account.id })
    .returning<Array<{ id: string }>>('id');

  const result: SyncOutcome = {
    accountId: account.id,
    outcome: 'ok',
    linesSeen: 0,
    linesNew: 0,
    balancesUpdated: 0,
    linesFailed: 0,
    proposalsCreated: 0,
    error: null,
  };

  const connector = getConnector(account.platform);
  let session: SimSession | null = null;
  /** Lines the partner says exist and did not return. See the block below. */
  let truncatedBy = 0;

  try {
    session = await connector.open({
      accountId: account.id,
      baseUrl: account.base_url,
      partnerRef: account.partner_ref,
      authMode: account.auth_mode,
      credential: loadCredential(account),
    });

    // The token knows its own partner id and expiry; persist what it told us so
    // the account screen can warn before it dies.
    await db('sim_accounts')
      .where({ id: account.id })
      .update({
        partner_ref: session.partnerRef ?? account.partner_ref,
        token_expires_at: session.tokenExpiresAt ?? account.token_expires_at,
        updated_at: db.fn.now(),
      });

    const listing = await session.listLines();
    const remote = listing.lines;
    result.linesSeen = remote.length;

    // ┌─ A TRUNCATED PAGE IS NOT A SMALLER FLEET ──────────────────────────────┐
    // │ The listing endpoint is paged and the connector reads page one. If the │
    // │ partner declares more lines than it returned, the remainder is         │
    // │ invisible: never inserted, never balance-read, never proposed for,     │
    // │ never invoiced. Reporting `ok` over that is the silent, permanent,     │
    // │ grows-with-the-customer failure the interface note describes — so the  │
    // │ run is marked `partial` and says what is missing.                       │
    // └────────────────────────────────────────────────────────────────────────┘
    if (listing.declaredTotal !== null && listing.declaredTotal > remote.length) {
      truncatedBy = listing.declaredTotal - remote.length;
      logger.warn(
        { accountId: account.id, returned: remote.length, declared: listing.declaredTotal },
        'SIM inventory listing is truncated: the partner reports more lines than it returned',
      );
    }

    const skip = new Set(
      (Array.isArray(account.skip_operators) ? account.skip_operators : [])
        .filter((s): s is string => typeof s === 'string')
        .map((s) => s.trim().toLowerCase()),
    );

    // ┌─ 1. INVENTORY — ONE BAD ROW MUST NOT BLIND THE WHOLE ACCOUNT ─────────┐
    // │ `sim_lines` carries CHECK constraints the partner knows nothing about │
    // │ (migration 032: the MSISDN pattern, the ICCID pattern, the column     │
    // │ widths). The first draft awaited every upsert in a bare loop, so one  │
    // │ malformed row — a test line, a placeholder, a number with an          │
    // │ extension — threw a constraint violation that aborted the ENTIRE      │
    // │ sweep. Every subsequent line went unread, every balance went stale,   │
    // │ and it recurred on every sweep forever, because the partner keeps     │
    // │ returning that row.                                                   │
    // │                                                                      │
    // │ So the row is validated against the SAME schema the API boundary uses │
    // │ — `simMsisdnSchema`, which until now stated a rule and had no caller  │
    // │ at all (§11.1, motif 2) — and a row that fails is counted and skipped │
    // │ rather than thrown. The count reaches `sim_sync_runs.lines_failed`,   │
    // │ so "why is this line missing" has an answer.                          │
    // └──────────────────────────────────────────────────────────────────────┘
    for (const line of remote) {
      const parsed = simMsisdnSchema.safeParse(line.msisdn);
      if (!parsed.success) {
        result.linesFailed += 1;
        // The MSISDN itself is NOT logged: it is customer data, and this branch
        // is reached precisely when it is malformed rather than identifying.
        logger.warn(
          { accountId: account.id },
          'SIM inventory: skipped a line whose number the partner reported in an unusable shape',
        );
        continue;
      }
      try {
        const created = await upsertLine(account.id, { ...line, msisdn: parsed.data });
        if (created) result.linesNew += 1;
      } catch (err) {
        result.linesFailed += 1;
        logger.warn(
          { accountId: account.id },
          `SIM inventory upsert failed for one line: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    // ── 2. Balances ─────────────────────────────────────────────────────────
    const stored = await db<LineRow>('sim_lines')
      .where('account_id', account.id)
      .select(
        'id',
        'tenant_id',
        'msisdn',
        'operator',
        'site_id',
        'device_id',
        'low_threshold_mb',
        'auto_recharge_enabled',
        'recharge_plan_mb',
      );
    const byMsisdn = new Map(stored.map((r) => [r.msisdn, r]));

    const limit = pLimit(BALANCE_CONCURRENCY);
    let authFailure: SimConnectorError | null = null;
    // Lines deliberately not polled are not lines that failed: counting them in
    // would make an account whose whole fleet is on a skipped operator look
    // like a total failure on every sweep.
    let skippedByOperator = 0;

    await Promise.all(
      remote.map((line) =>
        limit(async () => {
          // A partner error on one line must not stop the sweep, but an auth
          // failure must — checked here so the remaining queued tasks return
          // immediately instead of producing N identical 401s.
          if (authFailure) return;
          if (line.operator && skip.has(line.operator.trim().toLowerCase())) {
            skippedByOperator += 1;
            return;
          }

          const row = byMsisdn.get(line.msisdn);
          if (!row) return;

          try {
            const zones = await session!.fetchBalances(line.msisdn);
            const outcome = await applyBalances(row, zones);
            result.balancesUpdated += outcome.updated;
            result.proposalsCreated += outcome.proposals;
          } catch (err) {
            // `isAuthFailure` rather than a hand-rolled `instanceof` + code
            // comparison: the same predicate the rest of the module reasons
            // with, so the two cannot drift apart.
            if (isAuthFailure(err)) {
              authFailure = err as SimConnectorError;
              return;
            }
            result.linesFailed += 1;
            // Logged with the line id, never the MSISDN: the id is ours, the
            // number is the customer's (§8.2 spirit — log what identifies the
            // row for us, not what identifies the subscriber).
            // `stripQuery` here as well as in the connector: this log line's
            // own comment promises no MSISDN, and a promise that depends on
            // every upstream throw site remembering is not one.
            logger.warn(
              { accountId: account.id, simId: row.id },
              `SIM balance read failed: ${stripQuery(
                err instanceof Error ? err.message : String(err),
              )}`,
            );
          }
        }),
      ),
    );

    if (authFailure) throw authFailure;

    // ┌─ "PARTIAL" MUST NOT COVER "NOTHING WORKED" ────────────────────────────┐
    // │ A 429 is thrown by the transport rather than returned, so it lands in  │
    // │ the per-line catch and is counted — for every line, four at a time.    │
    // │ The first draft then reported `partial` whether ONE line failed or ALL │
    // │ FOUR HUNDRED did, wrote no `last_sync_error`, and set                  │
    // │ `last_sync_line_count` to the number of lines LISTED — so the account  │
    // │ screen stayed green and `fleetSummary.failedAccounts` stayed 0 while   │
    // │ not a single balance had been read.                                     │
    // │                                                                        │
    // │ `BALANCE_CONCURRENCY`'s own comment calls that "the one failure this   │
    // │ feature cannot afford, because it is indistinguishable from good       │
    // │ news". It was, and this is what makes it distinguishable. The stale-   │
    // │ reading horizon (`readingFreshness`) is the second half: the balances  │
    // │ themselves stop reading as answers.                                     │
    // └────────────────────────────────────────────────────────────────────────┘
    const attempted = result.linesSeen - skippedByOperator;
    if (attempted > 0 && result.linesFailed >= attempted) {
      result.outcome = 'error';
      result.error =
        `Every balance read failed (${result.linesFailed} of ${attempted}). The partner is ` +
        `refusing or throttling this account; no remaining data was updated.`;
    } else if (truncatedBy > 0) {
      result.outcome = 'partial';
      result.error =
        `The partner reports ${truncatedBy} more line(s) than it returned. This listing is ` +
        `one page: the remainder is not tracked, not alerted on and not invoiced.`;
    } else {
      result.outcome = result.linesFailed > 0 ? 'partial' : 'ok';
    }
  } catch (err) {
    const isAuth = isAuthFailure(err);
    const notImplemented = err instanceof SimConnectorError && err.code === 'NOT_IMPLEMENTED';
    result.outcome = isAuth ? 'auth_failed' : 'error';
    result.error = err instanceof Error ? err.message : String(err);

    if (isAuth) {
      await markAuthFailed(account.id, result.error);
      await announceAccountProblem(account, result.error);
    } else if (notImplemented) {
      // Not an incident: this account is a container for lines loaded from a
      // file. Recorded so the journal explains the lack of fresh balances, and
      // deliberately not alerted — an alert every interval for something nobody
      // can fix is how a channel gets muted.
      logger.debug({ accountId: account.id }, 'SIM account platform is not pollable');
    } else {
      logger.error({ accountId: account.id }, `SIM sweep failed: ${result.error}`);
    }
  } finally {
    await session?.close().catch(() => undefined);
  }

  await db('sim_sync_runs')
    .where({ id: run.id })
    .update({
      finished_at: db.fn.now(),
      outcome: result.outcome,
      lines_seen: result.linesSeen,
      lines_new: result.linesNew,
      balances_updated: result.balancesUpdated,
      lines_failed: result.linesFailed,
      proposals_created: result.proposalsCreated,
      error: result.error,
    });

  await db('sim_accounts')
    .where({ id: account.id })
    .update({
      last_sync_at: db.fn.now(),
      last_sync_error: result.error,
      // Not updated on a failed sweep: `last_sync_line_count` is read on the
      // account screen as "lines seen on the last sweep", and overwriting it
      // with the number LISTED during a sweep that read no balance at all is
      // the green tick this whole block exists to remove.
      last_sync_line_count: result.outcome === 'error' ? account.last_sync_line_count : result.linesSeen,
      updated_at: db.fn.now(),
    });

  return result;
}

// ============================================================================
// Inventory
// ============================================================================

/** Returns true when the line was created by this call. */
async function upsertLine(
  accountId: number,
  line: { msisdn: string; operator: string | null; clientCode: string | null; iccid: string | null; status: string },
): Promise<boolean> {
  const existing = await db('sim_lines')
    .where('account_id', accountId)
    .where('msisdn', line.msisdn)
    .first<{ id: number } | undefined>('id');

  if (existing) {
    // `tenant_id`, `site_id`, `device_id`, the threshold and the auto-recharge
    // flag are NOT in this patch, and must never be: they are an operator's
    // decisions, and a partner's inventory feed has no business overwriting
    // them on every sweep.
    await db('sim_lines')
      .where('id', existing.id)
      .update({
        operator: line.operator,
        client_code: line.clientCode,
        status: line.status,
        // An ICCID is only ever FILLED, never cleared: the partner does not
        // return one today, so a null from the feed means "not reported", not
        // "this SIM has no serial" — and clearing it would destroy a value an
        // operator typed or the ACS will one day supply.
        ...(line.iccid ? { iccid: line.iccid } : {}),
        last_seen_at: db.fn.now(),
        updated_at: db.fn.now(),
      });
    return false;
  }

  await db('sim_lines').insert({
    account_id: accountId,
    // NULL — the pool. A new line is never guessed into a tenant.
    tenant_id: null,
    msisdn: line.msisdn,
    operator: line.operator,
    client_code: line.clientCode,
    iccid: line.iccid,
    status: line.status,
  });
  return true;
}

// ============================================================================
// Balances, episodes and proposals
// ============================================================================

interface BalanceStateRow {
  id: string;
  zone: string;
  recharge_mb: number | null;
  used_mb: number | null;
  rest_mb: number | null;
  low_since: Date | string | null;
}

/**
 * Exported ONLY for `f9-sim.verify.ts`, which needs to drive one zone at a
 * time to prove the casing invariant — a full `syncAccount` goes through the
 * fake partner and cannot vary a single label. Nothing in production calls the
 * exported name; the sweep calls it directly.
 */
export const applyBalancesForTest = (
  line: Parameters<typeof applyBalances>[0],
  zones: RawSimBalance[],
): Promise<{ updated: number; proposals: number }> => applyBalances(line, zones);

async function applyBalances(
  line: LineRow,
  zones: RawSimBalance[],
): Promise<{ updated: number; proposals: number }> {
  const thresholdMb = effectiveThresholdMb(
    line.low_threshold_mb,
    await globalThresholdMb(line.tenant_id),
  );

  let updated = 0;
  let proposals = 0;
  const nowIso = new Date().toISOString();
  const applied: SimZoneBalance[] = [];

  for (const z of zones) {
    // Canonicalised ONCE, here: `sim_balances` is keyed on (sim_id, zone) and
    // each row carries its own episode marker, so two spellings of one zone
    // are two episodes and two proposals for one shortage.
    const zone = canonicalZone(z.zone);
    const state = await db.transaction(async (trx) => upsertZone(trx, line, zone, z, thresholdMb));
    if (state.changed) updated += 1;
    applied.push({
      zone,
      rechargeMb: z.rechargeMb,
      usedMb: z.usedMb,
      restMb: z.restMb,
      observedAt: nowIso,
      lowSince: state.lowSince,
    });

    // A proposal is only ever created for a zone that is DEFINITELY low, on a
    // line somebody opted in, in a workspace that can be re-invoiced. `unknown`
    // never reaches here — `evaluateBalance` returns it for a null reading and
    // this branch requires `low`.
    if (
      state.verdict === 'low' &&
      state.lowSince !== null &&
      line.auto_recharge_enabled &&
      line.tenant_id !== null
    ) {
      const created = await proposeForLowZone({
        simId: line.id,
        accountId: await accountIdOf(line.id),
        platform: await platformOf(line.id),
        tenantId: line.tenant_id,
        tenantName: await tenantNameOf(line.tenant_id),
        msisdn: line.msisdn,
        operator: line.operator,
        siteId: line.site_id,
        siteName: await siteNameOf(line.site_id, line.tenant_id),
        deviceName: await deviceNameOf(line.device_id, line.tenant_id),
        zone,
        restMb: z.restMb,
        thresholdMb,
        planMb: line.recharge_plan_mb,
        lowSince: state.lowSince,
      });
      if (created) proposals += 1;
    }
  }

  await announceLineIfLow(line, applied, thresholdMb);
  return { updated, proposals };
}

/**
 * Upserts one zone and maintains its episode marker.
 *
 * `low_since` is the load-bearing column (migration 032, decision 6):
 *   - not low → cleared, which ENDS the episode and makes the next fall a new
 *     one with a new idempotency key;
 *   - low and no marker → set to now, which OPENS the episode;
 *   - low with a marker → left exactly as it is. Touching it here would mint a
 *     new key on every sweep and propose a top-up every four hours.
 *
 * `unknown` leaves the marker ALONE rather than clearing it: a partner that
 * stops answering for one sweep must not silently close an open episode and
 * then reopen it as a duplicate proposal on the next reading.
 */
async function upsertZone(
  trx: Knex.Transaction,
  line: LineRow,
  zone: string,
  z: RawSimBalance,
  thresholdMb: number,
): Promise<{ changed: boolean; lowSince: string | null; verdict: 'ok' | 'low' | 'unknown' }> {
  // ┌─ THE READ MUST MATCH THE INDEX THE WRITE CONFLICTS ON ──────────────────┐
  // │ Row identity in `sim_balances` is `(sim_id, lower(zone))` — a FUNCTIONAL │
  // │ unique index (migration 032). A `.where('zone', zone)` is Postgres `=`,  │
  // │ which is case-SENSITIVE, so the two disagreed the moment the partner     │
  // │ changed a label's casing, which migration 032 itself calls "one backend  │
  // │ deployment on their side":                                               │
  // │                                                                         │
  // │   the read misses        -> `existing` undefined -> a NEW `low_since`    │
  // │   the write conflicts    -> MERGEs into the very row the read missed,    │
  // │                             overwriting the open episode                 │
  // │   `zone` was not merged  -> the stored casing stayed frozen, so the      │
  // │                             next sweep missed again, and the next...     │
  // │                                                                         │
  // │ Result: a fresh episode, a fresh idempotency key and therefore a FRESH   │
  // │ PROPOSAL on every sweep — six a day at the default interval — with the   │
  // │ unique index intact and doing nothing, plus a notification on each and a │
  // │ history row on each. Precisely decision 5's stated failure, reached      │
  // │ through the fix that was meant to prevent it.                            │
  // │                                                                         │
  // │ `zone` is now in the merge as well, so the stored label follows the      │
  // │ partner's current casing instead of being frozen at first insert.        │
  // └─────────────────────────────────────────────────────────────────────────┘
  const existing = await trx<BalanceStateRow>('sim_balances')
    .where('sim_id', line.id)
    .whereRaw('lower(zone) = lower(?)', [zone])
    .forUpdate()
    .first();

  const verdict = evaluateBalance(z.restMb, thresholdMb);

  let lowSince: Date | null = existing?.low_since ? new Date(existing.low_since) : null;
  if (verdict === 'ok') lowSince = null;
  else if (verdict === 'low' && lowSince === null) lowSince = new Date();

  const changed =
    !existing ||
    existing.rest_mb !== z.restMb ||
    existing.used_mb !== z.usedMb ||
    existing.recharge_mb !== z.rechargeMb;

  const now = new Date();
  await trx('sim_balances')
    .insert({
      sim_id: line.id,
      zone,
      recharge_mb: z.rechargeMb,
      used_mb: z.usedMb,
      rest_mb: z.restMb,
      observed_at: now,
      low_since: lowSince,
    })
    // The conflict target is the FUNCTIONAL index `(sim_id, lower(zone))`, not
    // a plain column pair — see migration 032. Expressed as raw because that is
    // the only form knex can point at a functional index with.
    .onConflict(db.raw('(sim_id, lower(zone))') as unknown as string)
    .merge({
      // `zone` IS merged: the stored label follows the partner's current
      // casing. Frozen at first insert, it made every later read miss.
      zone,
      recharge_mb: z.rechargeMb,
      used_mb: z.usedMb,
      rest_mb: z.restMb,
      observed_at: now,
      // ┌─ THE EPISODE IS SETTLED BY THE DATABASE, NOT BY THE READ ──────────┐
      // │ Two sweeps can reach a zone with no row yet — the timer and the    │
      // │ manual `POST /accounts/:id/sync` — and both would then compute     │
      // │ their own `now()` as the episode start, producing two markers and  │
      // │ two idempotency keys for one shortage. Written as a CASE over the  │
      // │ EXISTING row so the earliest start always wins, whoever lands      │
      // │ second: not low clears it, low keeps whatever is already there.    │
      // └────────────────────────────────────────────────────────────────────┘
      low_since:
        lowSince === null
          ? null
          : db.raw('COALESCE(sim_balances.low_since, EXCLUDED.low_since)'),
      updated_at: now,
    });

  // History is written ONLY on change (migration 032, decision 5). A row per
  // sweep would be 1.3 M rows a year carrying no information on the days
  // nothing moved. `onConflict().ignore()` covers a retried sweep landing on
  // the same instant.
  if (changed) {
    await trx('sim_balance_samples')
      .insert({
        sim_id: line.id,
        zone,
        recharge_mb: z.rechargeMb,
        used_mb: z.usedMb,
        rest_mb: z.restMb,
        observed_at: now,
      })
      .onConflict(['sim_id', 'zone', 'observed_at'])
      .ignore();
  }

  // Re-read the settled marker: with the COALESCE above, the row may carry an
  // EARLIER `low_since` than this sweep proposed (a concurrent sweep won the
  // race). Returning the local guess would build the idempotency key on an
  // episode that is not the stored one — the exact mismatch this whole section
  // is about.
  const settled = await trx<BalanceStateRow>('sim_balances')
    .where('sim_id', line.id)
    .whereRaw('lower(zone) = lower(?)', [zone])
    .first();

  return {
    changed,
    lowSince: settled?.low_since ? new Date(settled.low_since).toISOString() : null,
    verdict,
  };
}

// ============================================================================
// Announcements
// ============================================================================

/**
 * Raises the in-browser alert and the notification-channel message for a line
 * that is low.
 *
 * ┌─ ONE ALERT PER EPISODE PER REMINDER WINDOW, COMPUTED NOT REMEMBERED ──────┐
 * │ `stableKey` carries the episode start AND a bucket index derived from     │
 * │ `SIM_ALERT_REMIND_HOURS`. `liveAlertService.add` skips an insert when an  │
 * │ UNREAD alert with the same key already exists, so:                        │
 * │   - within one reminder window the operator is told once;                 │
 * │   - the window after, the bucket changes and a still-low line says so     │
 * │     again;                                                                │
 * │   - a new episode has a new `lowSince` and is therefore always new.       │
 * │ No state table, nothing to reconcile, and a restarted worker behaves      │
 * │ identically — which the prototype's `state.json` did not.                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
async function announceLineIfLow(
  line: LineRow,
  zones: SimZoneBalance[],
  thresholdMb: number,
): Promise<void> {
  // A pooled line has no tenant to notify. It is still shown as low on the
  // platform dashboard; it just has nobody to tell.
  if (line.tenant_id === null) return;

  const worst = worstZone(zones);
  if (!worst || evaluateBalance(worst.restMb, thresholdMb) !== 'low' || !worst.lowSince) return;

  const remindHours = await globalNumber(line.tenant_id, SETTINGS_KEYS.SIM_ALERT_REMIND_HOURS);
  const elapsedMs = Date.now() - new Date(worst.lowSince).getTime();
  const bucket = Math.floor(elapsedMs / (remindHours * 3_600_000));

  const title = 'Mobile data running out';
  const message =
    `${line.msisdn} has ${formatData(worst.restMb)} left in ${worst.zone} ` +
    `(threshold ${formatData(thresholdMb)}).`;

  const raised = await liveAlertService.add(line.tenant_id, {
    severity: 'warning',
    title,
    message,
    navigateTo: `/mobile/lines/${line.id}`,
    stableKey: `sim-low:${line.id}:${worst.zone}:${worst.lowSince}:${bucket}`,
  });

  // ┌─ THE CHANNEL MESSAGE RIDES ON THE BROWSER ALERT'S DEDUPLICATION ────────┐
  // │ `liveAlertService.add` returns the inserted row, or `null` when an      │
  // │ unread alert with the same `stableKey` already exists. Sending the      │
  // │ channel message unconditionally would put a Teams/Slack/e-mail message  │
  // │ on EVERY sweep for a line that is still low — six a day at the default  │
  // │ four-hour interval, against one browser alert per 24-hour reminder      │
  // │ window. That is how a notification channel gets muted, and a muted      │
  // │ channel is how the one that mattered gets missed.                       │
  // └────────────────────────────────────────────────────────────────────────┘
  if (raised === null) return;

  await notificationService
    .sendForTenant(line.tenant_id, 'sim_low_data', {
      entityName: line.msisdn,
      entityUrl: `/mobile/lines/${line.id}`,
      oldStatus: 'ok',
      newStatus: 'low',
      message,
      timestamp: new Date().toISOString(),
    })
    .catch((err: unknown) => {
      // A notification failure must never abort a sweep: the balance is already
      // stored and the browser alert already raised.
      logger.warn({ simId: line.id }, `SIM low-data notification failed: ${String(err)}`);
    });
}

async function announceAccountProblem(account: SimAccountRow, reason: string): Promise<void> {
  // An account is platform-level and has no tenant, so the alert goes to every
  // tenant that has lines on it — they are the ones whose balances just went
  // stale, and a silent staleness is the failure this feature cannot afford.
  const tenants = await db('sim_lines')
    .where('account_id', account.id)
    .whereNotNull('tenant_id')
    .distinct<Array<{ tenant_id: number }>>('tenant_id');

  // ┌─ WHAT A TENANT IS TOLD, AND WHAT STAYS ON THE ADMIN SCREEN ────────────┐
  // │ `sim_accounts` is PLATFORM-scoped (migration 032, decision 2): its name │
  // │ is the operator's own contract label ("CFAST — Nexytel"), its           │
  // │ `last_sync_error` is the partner's raw response, and neither is a       │
  // │ customer's business. The first draft interpolated both into every       │
  // │ affected tenant's alert feed, which is the same over-sharing            │
  // │ `fleetSummary` deliberately avoids by reporting only a COUNT of         │
  // │ unhealthy accounts.                                                     │
  // │                                                                        │
  // │ A tenant is told the thing that is true for them and actionable by      │
  // │ them: their SIM balances are no longer being read. The name, the host   │
  // │ and the partner's error stay in `sim_accounts` and `sim_sync_runs`,     │
  // │ behind `requireRole('admin')`, where the person who can fix it looks.   │
  // └────────────────────────────────────────────────────────────────────────┘
  logger.error({ accountId: account.id, reason }, 'SIM partner account cannot authenticate');
  for (const t of tenants) {
    await liveAlertService.add(t.tenant_id, {
      severity: 'down',
      title: 'Mobile data is no longer being read',
      message:
        'Remaining data can no longer be read for some of the SIM lines in this workspace: ' +
        'the mobile partner connection needs attention. Those lines show as not readable ' +
        'until it is restored.',
      navigateTo: '/mobile',
      // No bucket: this is not a reminder, it is a standing fault. One unread
      // alert until somebody reads it or fixes the token.
      stableKey: `sim-account-auth:${account.id}`,
    });
  }
}

// ============================================================================
// Small lookups
// ============================================================================
//
// Read per proposal rather than joined into the sweep's main query on purpose:
// a proposal is rare (one per low episode) and its fields are FROZEN into the
// row, so they must be read at the instant the proposal is made rather than
// from a snapshot taken at the top of a sweep that may have run for minutes.

async function accountIdOf(simId: number): Promise<number> {
  const row = await db('sim_lines')
    .where('id', simId)
    .first<{ account_id: number } | undefined>('account_id');
  return row!.account_id;
}

async function platformOf(simId: number): Promise<SimPlatform> {
  const row = await db('sim_lines as l')
    .join('sim_accounts as a', 'a.id', 'l.account_id')
    .where('l.id', simId)
    .first<{ platform: SimPlatform } | undefined>('a.platform');
  return row!.platform;
}

async function tenantNameOf(tenantId: number): Promise<string | null> {
  const row = await db('tenants').where('id', tenantId).first<{ name: string } | undefined>('name');
  return row?.name ?? null;
}

async function siteNameOf(siteId: number | null, tenantId: number): Promise<string | null> {
  if (siteId === null) return null;
  // Matched on id AND tenant: `site_id` is nullable with SET NULL semantics, so
  // the pair really can go stale, and a borrowed site name on an invoice line
  // is a customer reading another customer's site.
  const row = await db('sites')
    .where('id', siteId)
    .where('tenant_id', tenantId)
    .first<{ name: string } | undefined>('name');
  return row?.name ?? null;
}

async function deviceNameOf(deviceId: number | null, tenantId: number): Promise<string | null> {
  if (deviceId === null) return null;
  const row = await db('devices')
    .where('id', deviceId)
    .where('tenant_id', tenantId)
    .first<{ name: string } | undefined>('name');
  return row?.name ?? null;
}
