/**
 * ObliWAN — K6: who changed this box.
 *
 * ┌─ THE ONE SENTENCE THIS FILE IS BUILT AROUND ─────────────────────────────┐
 * │ A WRONG ATTRIBUTION IS WORSE THAN NO ATTRIBUTION, BECAUSE IT WILL BE      │
 * │ BELIEVED.                                                                 │
 * │                                                                          │
 * │ Nothing downstream re-checks this verdict. It goes into an incident       │
 * │ review with a colleague's name on it, into a customer report, and into a  │
 * │ conversation that has consequences. So every decision below is biased     │
 * │ towards refusing to answer:                                              │
 * │                                                                          │
 * │  - a run we caused ourselves is `excluded`, never a human's fault;        │
 * │  - a change made by one of our own `change_jobs` is `platform`;           │
 * │  - two sessions that fit equally well are `ambiguous`, not "the first";   │
 * │  - a best candidate under the threshold is `unattributed`;                │
 * │  - `admin` names nobody, and the row says so out loud.                    │
 * │                                                                          │
 * │ `unattributed` IS the deliverable in a large fraction of cases, and it is │
 * │ a useful one: a configuration change with no trace means either an        │
 * │ out-of-band access nobody declared, or a device whose logs never reach    │
 * │ us. Both are worth a screen. Neither is worth a name.                     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE WINDOW IS NOT A LOOKBACK ───────────────────────────────────────────┐
 * │ It runs from the moment the OLD configuration was last CONFIRMED still    │
 * │ true (`config_snapshots.last_seen_at` of the previous snapshot) to the    │
 * │ moment the new one was captured. Outside that interval a session          │
 * │ provably cannot explain the diff, because we verified the config was      │
 * │ unchanged after it ended.                                                 │
 * │                                                                          │
 * │ A fixed "24 h before the run" window would drag in every session since    │
 * │ yesterday even when we checked the box an hour ago — inflating the        │
 * │ candidate list, which under this scoring turns clean attributions into    │
 * │ `ambiguous` ones. The width of the window is itself reported, because a   │
 * │ two-week window is weak evidence and the UI has to be able to say so.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * This file DOES NOT modify `drift.service.ts` or `semanticDiff.ts`. It reads
 * `drift_runs` and writes `drift_attributions`, which is why attribution can be
 * re-run months later against improved parsers without touching a drift result.
 */

import { db } from '../../db';
import { logger } from '../../utils/logger';
import { UNATTRIBUTABLE_CAUSES, type DriftCause } from './drift.service';
import {
  ATTRIBUTION_TUNING,
  WRITE_CAPABLE_LOGIN_METHODS,
  type AttributionCandidate,
  type AttributionVerdict,
  type DriftAttribution,
  type LoginMethod,
} from '../logs/contract';

// ============================================================================
// The pure core
// ============================================================================

/** A login/logout pair, as reconstructed from `device_login_events`. */
export interface Session {
  loginEventId: string;
  account: string;
  sharedAccount: boolean;
  method: LoginMethod;
  sourceIp: string | null;
  loginAt: Date;
  /** null = still open as far as we know. */
  logoutAt: Date | null;
}

export interface Window {
  from: Date;
  to: Date;
}

function round3(n: number): number {
  return Math.round(n * 1000) / 1000;
}

/**
 * How well a session is placed in time to explain the change.
 *
 *   1                        the session STARTED inside the window — the
 *                            strongest statement available, because the change
 *                            and the session begin in the same interval;
 *   1 -> minTemporalFit      it started before the window but was still open
 *                            when the window opened, decaying across the grace;
 *   0                        it had already ended when the window opened, and
 *                            such a session is not a candidate at all.
 */
export function temporalFit(session: Session, window: Window): number {
  if (session.logoutAt && session.logoutAt.getTime() < window.from.getTime()) return 0;
  if (session.loginAt.getTime() > window.to.getTime()) return 0;
  if (session.loginAt.getTime() >= window.from.getTime()) return 1;

  const ageSec = (window.from.getTime() - session.loginAt.getTime()) / 1000;
  const grace = ATTRIBUTION_TUNING.preWindowGraceSeconds;
  const floor = ATTRIBUTION_TUNING.minTemporalFit;
  if (ageSec >= grace) return floor;
  return floor + (1 - floor) * (1 - ageSec / grace);
}

/**
 * Can this door change a configuration at all?
 *
 * `unknown` scores half: we did not read the method, which is not the same as
 * reading a method that cannot write. Scoring it 1 would reward a parser
 * failure; scoring it 0 would make every login from a vendor whose wording we
 * do not fully understand unattributable.
 */
export function methodFit(method: LoginMethod): number {
  if (method === 'unknown') return 0.5;
  return WRITE_CAPABLE_LOGIN_METHODS.includes(method) ? 1 : 0;
}

export interface ScoredCandidates {
  candidates: AttributionCandidate[];
  verdict: Extract<AttributionVerdict, 'attributed' | 'ambiguous' | 'unattributed'>;
  reason: string;
  winner: AttributionCandidate | null;
}

/**
 * Rank the sessions and decide. PURE: no clock, no database — the whole of K6's
 * judgement is one function a reviewer can read and a test can drive without a
 * fleet, which matters because there is no fleet in this environment.
 */
export function scoreSessions(sessions: readonly Session[], window: Window): ScoredCandidates {
  const overlapping = sessions.filter((s) => temporalFit(s, window) > 0);

  if (overlapping.length === 0) {
    return {
      candidates: [],
      verdict: 'unattributed',
      reason: 'no_login_event_in_window',
      winner: null,
    };
  }

  const exclusivity = 1 / overlapping.length;
  const candidates: AttributionCandidate[] = overlapping
    .map((s) => {
      const t = temporalFit(s, window);
      const m = methodFit(s.method);
      const evidence =
        ATTRIBUTION_TUNING.weightTemporal * t +
        ATTRIBUTION_TUNING.weightExclusivity * exclusivity +
        ATTRIBUTION_TUNING.weightMethod * m;
      // The shared-account multiplier is applied HERE and only here: after the
      // evidence is final, so it can never re-order two candidates.
      const score = s.sharedAccount
        ? evidence * ATTRIBUTION_TUNING.sharedAccountConfidence
        : evidence;
      return {
        loginEventId: s.loginEventId,
        account: s.account,
        sharedAccount: s.sharedAccount,
        method: s.method,
        sourceIp: s.sourceIp,
        loginAt: s.loginAt.toISOString(),
        logoutAt: s.logoutAt ? s.logoutAt.toISOString() : null,
        evidence: round3(evidence),
        score: round3(score),
        components: { temporalFit: round3(t), exclusivity: round3(exclusivity), methodFit: m },
      };
    })
    // Ranked on EVIDENCE, never on score: see ATTRIBUTION_TUNING.
    .sort((a, b) => b.evidence - a.evidence);

  const best = candidates[0];
  const runnerUp = candidates[1];

  // Ambiguity is decided BEFORE the threshold. Two indistinguishable sessions
  // must read as "we will not choose", not as "the best of them was weak" —
  // the two say different things to an operator and lead to different actions.
  if (runnerUp && best.evidence - runnerUp.evidence < ATTRIBUTION_TUNING.ambiguityMargin) {
    return {
      candidates,
      verdict: 'ambiguous',
      reason: 'candidates_within_ambiguity_margin',
      winner: null,
    };
  }

  if (best.score < ATTRIBUTION_TUNING.minScore) {
    return {
      candidates,
      verdict: 'unattributed',
      reason: 'best_candidate_below_threshold',
      winner: null,
    };
  }

  return {
    candidates,
    verdict: 'attributed',
    reason: runnerUp ? 'best_session_clear_of_runners_up' : 'single_session_in_window',
    winner: best,
  };
}

/**
 * Pair logins with logouts.
 *
 * Matched on `(account, method)` and not on the source address: an operator's
 * NAT address can differ between the login line and the logout line on the same
 * session, and an unmatched logout would leave a session open for ever — which
 * makes it a candidate for every window until the end of time.
 *
 * A `login_failed` never opens a session. It changed nothing on the box, and
 * treating it as a candidate would attribute a change to somebody who failed to
 * get in — the most defamatory error this file could make.
 */
export function buildSessions(
  events: ReadonlyArray<{
    id: string;
    event: string;
    account: string;
    shared_account: boolean;
    method: string;
    source_ip: string | null;
    ts: Date;
  }>,
): Session[] {
  const sorted = [...events].sort((a, b) => a.ts.getTime() - b.ts.getTime());
  const open = new Map<string, Session>();
  const sessions: Session[] = [];

  for (const e of sorted) {
    const key = `${e.account.toLowerCase()}|${e.method}`;
    if (e.event === 'login') {
      const session: Session = {
        loginEventId: String(e.id),
        account: e.account,
        sharedAccount: e.shared_account,
        method: e.method as LoginMethod,
        sourceIp: e.source_ip,
        loginAt: e.ts,
        logoutAt: null,
      };
      // A second login for the same key before a logout means we missed the
      // logout (a dropped datagram, a reboot). Close the previous session at
      // the new login rather than leaving it open for ever.
      const previous = open.get(key);
      if (previous) previous.logoutAt = e.ts;
      open.set(key, session);
      sessions.push(session);
    } else if (e.event === 'logout') {
      const session = open.get(key);
      if (session) {
        session.logoutAt = e.ts;
        open.delete(key);
      }
      // A logout with no matching login is a session that began before our
      // retention window. Deliberately NOT synthesised into a session: we do
      // not know when it started, so we cannot place it in any window, and
      // inventing a start time would invent a candidate.
    }
  }
  return sessions;
}

// ============================================================================
// Persistence
// ============================================================================

interface RunRow {
  id: string;
  device_id: number;
  device_name: string | null;
  status: string;
  cause: string;
  snapshot_id: string | null;
  started_at: Date;
}

interface AttributionRow {
  id: string;
  run_id: string;
  device_id: number;
  device_name: string | null;
  verdict: string;
  score: string | number;
  reason: string;
  window_from: Date;
  window_to: Date;
  login_event_id: string | null;
  account: string | null;
  shared_account: boolean;
  method: string | null;
  source_ip: string | null;
  change_job_id: string | null;
  candidates: unknown;
  created_at: Date;
}

function toAttribution(r: AttributionRow): DriftAttribution {
  const from = r.window_from.toISOString();
  const to = r.window_to.toISOString();
  return {
    id: String(r.id),
    runId: String(r.run_id),
    deviceId: r.device_id,
    deviceName: r.device_name ?? null,
    verdict: r.verdict as AttributionVerdict,
    score: Number(r.score),
    reason: r.reason,
    window: {
      from,
      to,
      spanSeconds: Math.max(
        0,
        Math.round((r.window_to.getTime() - r.window_from.getTime()) / 1000),
      ),
    },
    account: r.account,
    sharedAccount: r.shared_account,
    sourceIp: r.source_ip,
    method: (r.method as LoginMethod | null) ?? null,
    loginEventId: r.login_event_id === null ? null : String(r.login_event_id),
    changeJobId: r.change_job_id === null ? null : String(r.change_job_id),
    candidates: (r.candidates as AttributionCandidate[]) ?? [],
    createdAt: r.created_at.toISOString(),
  };
}

/**
 * The interval the change provably happened in.
 *
 * `to` is when the drifted snapshot was captured. `from` is when the PREVIOUS
 * snapshot of the same device was last confirmed still true — which is later
 * than when it was captured, and that difference is exactly what makes this
 * window tight instead of a lookback.
 */
async function resolveWindow(
  deviceId: number,
  snapshotId: string | null,
  fallback: Date,
): Promise<{ window: Window; hasBaseline: boolean }> {
  if (!snapshotId) {
    return { window: { from: fallback, to: fallback }, hasBaseline: false };
  }
  const current = await db('config_snapshots')
    .where({ id: snapshotId })
    .first<{ captured_at: Date } | undefined>('captured_at');
  const to = current?.captured_at ?? fallback;

  const previous = await db('config_snapshots')
    .where({ device_id: deviceId })
    .andWhere('id', '<', snapshotId)
    .orderBy('id', 'desc')
    .first<{ last_seen_at: Date | null; captured_at: Date } | undefined>(
      'last_seen_at',
      'captured_at',
    );
  if (!previous) return { window: { from: to, to }, hasBaseline: false };

  const from = previous.last_seen_at ?? previous.captured_at;
  // Clock skew between two rows of the same table should be impossible, but a
  // restored backup or a manual insert can produce `from > to`, and the CHECK
  // on the table would then reject the row and lose the attribution entirely.
  return { window: { from: from > to ? to : from, to }, hasBaseline: true };
}

/**
 * Did WE write this box inside the window?
 *
 * Checked before any human is considered. A `change_jobs` row that reached the
 * device during the window explains the diff completely, and attributing our
 * own write to whoever happened to be logged in at the time would be the single
 * most damaging false positive this service can produce — it would blame an
 * operator for the platform's action, on the platform's own evidence.
 */
async function overlappingChangeJob(
  deviceId: number,
  window: Window,
): Promise<string | null> {
  const row = await db('change_jobs')
    .where({ device_id: deviceId })
    // `started_at` is set when the job begins touching the device. A job that
    // started before the window and finished inside it also counts, hence the
    // comparison on `finished_at` too.
    .andWhere((qb) => {
      void qb
        .whereBetween('started_at', [window.from, window.to])
        .orWhereBetween('finished_at', [window.from, window.to]);
    })
    .orderBy('id', 'desc')
    .first<{ id: string } | undefined>('id');
  return row ? String(row.id) : null;
}

export interface AttributeOptions {
  /** Recompute even if an attribution already exists (better parsers, a late
   *  `/log` pull that finally delivered the login). */
  force?: boolean;
}

/**
 * Attribute one drift run, and ALWAYS write a row.
 *
 * Returns null only when the run does not describe a change at all (`in_sync`,
 * `error`, `unreachable`): there is nothing to attribute, and writing an
 * `unattributed` row for a run that found no drift would fill the "changes
 * nobody owns" screen with non-events.
 */
export async function attributeRun(
  runId: string,
  options: AttributeOptions = {},
): Promise<DriftAttribution | null> {
  const run = await db('drift_runs as dr')
    .join('devices as d', 'd.id', 'dr.device_id')
    .where('dr.id', runId)
    .first<RunRow | undefined>(
      'dr.id', 'dr.device_id', 'dr.status', 'dr.cause', 'dr.snapshot_id',
      'dr.started_at', 'd.name as device_name',
    );
  if (!run) return null;
  if (run.status !== 'drifted') return null;

  if (!options.force) {
    const existing = await loadByRunId(runId);
    if (existing) return existing;
  }

  const { window, hasBaseline } = await resolveWindow(
    run.device_id,
    run.snapshot_id,
    run.started_at,
  );

  let verdict: AttributionVerdict;
  let reason: string;
  let score = 0;
  let winner: AttributionCandidate | null = null;
  let candidates: AttributionCandidate[] = [];
  let changeJobId: string | null = null;

  // ── Gate 1: §6.5. A diff caused by OUR OWN re-normalisation or by a model
  // upgrade is not somebody's change. Decided from the run's recorded cause,
  // never inferred from a timestamp — and read from `drift.service`'s own list
  // rather than a copy, so the two can never disagree.
  const ourJob =
    UNATTRIBUTABLE_CAUSES.has(run.cause as DriftCause) || !hasBaseline
      ? null
      : await overlappingChangeJob(run.device_id, window);

  if (UNATTRIBUTABLE_CAUSES.has(run.cause as DriftCause)) {
    verdict = 'excluded';
    reason = `cause_${run.cause}`;
  } else if (!hasBaseline) {
    // No previous snapshot: this is the first configuration we ever saw of this
    // device, so "what changed" has no answer and neither does "who".
    verdict = 'unattributed';
    reason = 'no_baseline_snapshot';
  } else if (ourJob !== null) {
    verdict = 'platform';
    reason = 'overlapping_change_job';
    changeJobId = ourJob;
  } else {
    const events = await db('device_login_events')
      .where({ device_id: run.device_id })
      .andWhere('ts', '>=', new Date(
        window.from.getTime() - ATTRIBUTION_TUNING.preWindowGraceSeconds * 1000,
      ))
      // Logouts are fetched past the end of the window so a session that closed
      // after the snapshot can still be closed here. Without this a session
      // would read as "still open" and stay a candidate for every later window.
      .andWhere('ts', '<=', new Date(window.to.getTime() + 86_400_000))
      .orderBy('ts', 'asc')
      .select<
        Array<{
          id: string;
          event: string;
          account: string;
          shared_account: boolean;
          method: string;
          source_ip: string | null;
          ts: Date;
        }>
      >('id', 'event', 'account', 'shared_account', 'method', 'source_ip', 'ts');

    const scored = scoreSessions(buildSessions(events), window);
    verdict = scored.verdict;
    reason = scored.reason;
    candidates = scored.candidates;
    winner = scored.winner;
    score = winner ? winner.score : 0;
  }

  // The CHECK constraint `drift_attributions_names_only_when_attributed`
  // refuses a row that names an account under any other verdict. These
  // conditionals exist so that constraint is never the thing that discovers a
  // bug in production — but it stays there, because a service rule is edited by
  // people in a hurry and a CHECK is not.
  const named: AttributionCandidate | null = verdict === 'attributed' ? winner : null;

  const row = {
    run_id: runId,
    device_id: run.device_id,
    verdict,
    score,
    reason,
    window_from: window.from,
    window_to: window.to,
    login_event_id: named ? named.loginEventId : null,
    account: named ? named.account : null,
    shared_account: named ? named.sharedAccount : false,
    method: named ? named.method : null,
    source_ip: named ? named.sourceIp : null,
    change_job_id: verdict === 'platform' ? changeJobId : null,
    candidates: JSON.stringify(candidates),
    created_at: new Date(),
  };

  await db('drift_attributions').insert(row).onConflict('run_id').merge();

  if (verdict === 'attributed' && winner?.sharedAccount) {
    logger.info(
      { runId, deviceId: run.device_id, account: winner.account, sourceIp: winner.sourceIp },
      'Drift attributed to a SHARED account — the account names a role, not a person',
    );
  }

  const stored = await loadByRunId(runId);
  return stored;
}

function scopedAttributions(tenantId: number) {
  // No tenant column here either: the join on `devices` is the isolation.
  return db('drift_attributions as a')
    .join('devices as d', 'd.id', 'a.device_id')
    .where('d.tenant_id', tenantId);
}

const ATTRIBUTION_COLUMNS = [
  'a.id', 'a.run_id', 'a.device_id', 'a.verdict', 'a.score', 'a.reason',
  'a.window_from', 'a.window_to', 'a.login_event_id', 'a.account',
  'a.shared_account', 'a.method', 'a.source_ip', 'a.change_job_id',
  'a.candidates', 'a.created_at', 'd.name as device_name',
];

/** Internal read, NOT tenant-scoped: used right after a write on a run whose
 *  tenant is already established. Never reachable from HTTP. */
async function loadByRunId(runId: string): Promise<DriftAttribution | null> {
  const row = await db('drift_attributions as a')
    .join('devices as d', 'd.id', 'a.device_id')
    .where('a.run_id', runId)
    .first<AttributionRow | undefined>(...ATTRIBUTION_COLUMNS);
  return row ? toAttribution(row) : null;
}

export async function getAttributionForRun(
  tenantId: number,
  runId: string,
): Promise<DriftAttribution | null> {
  const row = await scopedAttributions(tenantId)
    .andWhere('a.run_id', runId)
    .first<AttributionRow | undefined>(...ATTRIBUTION_COLUMNS);
  return row ? toAttribution(row) : null;
}

export interface ListAttributionsFilter {
  deviceId?: number;
  verdict?: AttributionVerdict;
  /** Shortcut for the screen that matters: everything nobody owns. */
  openOnly?: boolean;
  limit?: number;
  offset?: number;
}

export async function listAttributions(
  tenantId: number,
  filter: ListAttributionsFilter = {},
): Promise<DriftAttribution[]> {
  const q = scopedAttributions(tenantId);
  if (filter.deviceId) void q.andWhere('a.device_id', filter.deviceId);
  if (filter.verdict) void q.andWhere('a.verdict', filter.verdict);
  if (filter.openOnly) void q.whereIn('a.verdict', ['unattributed', 'ambiguous']);

  const rows = await q
    .orderBy('a.created_at', 'desc')
    .orderBy('a.id', 'desc')
    .limit(Math.min(filter.limit ?? 100, 500))
    .offset(filter.offset ?? 0)
    .select<AttributionRow[]>(...ATTRIBUTION_COLUMNS);
  return rows.map(toAttribution);
}

/**
 * Attribute every drifted run that has none yet.
 *
 * Called on a timer by the logs runtime rather than inline in `runDrift()`:
 * `services/drift/drift.service.ts` is outside this milestone's perimeter, and
 * — more usefully — a login line often arrives AFTER the drift run that needs
 * it, either because the `/log` pull is on a five-minute cycle or because the
 * syslog datagram was in flight. Attributing on a sweep gives the evidence time
 * to land; attributing inline would freeze an `unattributed` verdict a few
 * seconds before the proof arrived.
 */
export async function attributePendingRuns(limit = 50): Promise<{
  processed: number;
  attributed: number;
  unattributed: number;
}> {
  const rows = await db('drift_runs as dr')
    .leftJoin('drift_attributions as a', 'a.run_id', 'dr.id')
    .where('dr.status', 'drifted')
    .whereNull('a.id')
    .orderBy('dr.id', 'asc')
    .limit(limit)
    .select<{ id: string }[]>('dr.id');

  let attributed = 0;
  let unattributed = 0;
  for (const row of rows) {
    try {
      const result = await attributeRun(String(row.id));
      if (result?.verdict === 'attributed') attributed += 1;
      if (result?.verdict === 'unattributed') unattributed += 1;
    } catch (err) {
      logger.error({ err, runId: row.id }, 'Attribution failed for drift run');
    }
  }
  return { processed: rows.length, attributed, unattributed };
}
