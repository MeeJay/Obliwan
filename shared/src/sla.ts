// ============================================================================
// @obliwan/shared — F7, the CALCULATED SLA
// ============================================================================
//
// ONE SENTENCE: an MSP sells 99.5 % and proves it with a spreadsheet; this file
// is the arithmetic that replaces the spreadsheet, and the reason it is worth
// more than one is that it knows the difference between "the customer's site
// was dead" and "OUR tunnel was".
//
// ┌─ THE THREE THINGS THIS FILE EXISTS TO MAKE UNTAKEABLE ────────────────────┐
// │                                                                          │
// │ 1. AN UNOBSERVED PERIOD IS NEVER 100 %.                                   │
// │    `availabilityPercent` is `null` when nothing was measured — not 100,   │
// │    not 0, not "assumed up". This is the SAME defect the F2 audit found on │
// │    the attestation (365 unobserved days rendered as "continuous"), and it │
// │    is the single easiest way to make this feature a lie that gets signed. │
// │    Migration 026 re-states it as a CHECK, because a service-layer rule is │
// │    not what runs when somebody inserts a row from psql.                    │
// │                                                                          │
// │ 2. AN OUTAGE OF *OUR* MANAGEMENT PLANE IS NOT THE CUSTOMER'S OUTAGE.      │
// │    `CONCENTRATOR_DEGRADED` (our CHR is broken) and `TUNNEL_DOWN_SITE_UP`  │
// │    (the tunnel died, an independent signal says the site is alive) are    │
// │    removed from BOTH sides of the ratio and reported separately, with     │
// │    their seconds and their reason. An SLA whose exclusions cannot be      │
// │    audited is worth exactly as much as the spreadsheet it replaced.       │
// │                                                                          │
// │ 3. `UNREACHABLE` IS NOT DOWNTIME AND IT IS NOT UPTIME.                    │
// │    `shared/src/telemetry.ts` is explicit: `SITE_DOWN` means "we know it   │
// │    is dead", `UNREACHABLE` means "WE CANNOT TELL". A verdict that carries │
// │    no opinion must not be allowed to manufacture one. `stateForVerdict`   │
// │    returns `null` for it, `UNREACHABLE` rows never override the presence  │
// │    history, and the seconds they cover land in `unmeasured` unless        │
// │    something else says otherwise.                                        │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ HOW A SECOND IS CLASSIFIED. READ THIS BEFORE CHANGING ANYTHING. ─────────┐
// │                                                                          │
// │ Per DEVICE, in strict order — the first rule that applies wins:           │
// │                                                                          │
// │   a. A DECISIVE K7 verdict covers the instant → its state.                │
// │      "Decisive" = anything but `UNREACHABLE`. A verdict governs from its  │
// │      `ts` until the FIRST of: the next decisive verdict, the end of       │
// │      `verdictValiditySeconds`, and the next PPP session transition. A     │
// │      sample is a point observation — letting one stretch forever is how a │
// │      single UP row from March pays for April, and letting one outlive the │
// │      moment the tunnel came back is how an exclusion eats observed        │
// │      uptime.                                                             │
// │                                                                          │
// │   b. The device's own PPP session was open → `up`.                        │
// │      `ppp_sessions` is the presence source of truth (D4).                 │
// │                                                                          │
// │   c. NO session, but WE CAN PROVE WE WERE WATCHING → `down`.              │
// │      The proof is the OBSERVATION MASK: the intervals during which the    │
// │      concentrator that terminates this device's tunnel held a session for │
// │      *anybody*. If the CHR was writing sessions for other customers while │
// │      this device had none, this device was disconnected. This is what     │
// │      separates "the router was off" from "ObliWAN was not installed yet", │
// │      and it is why a fresh install does not bill its customer for the 362 │
// │      days that preceded it.                                              │
// │                                                                          │
// │   d. Otherwise → `unmeasured`.                                            │
// │                                                                          │
// │ Per SITE, combining its devices at each instant, highest wins:            │
// │                                                                          │
// │   up  >  excluded_management  >  down  >  unmeasured                      │
// │                                                                          │
// │   `up` first: one router carrying traffic means the site had service,     │
// │   whatever its neighbour was doing. `excluded_management` before `down`:  │
// │   if ANY device at the site says the fault is provably ours, we do not    │
// │   bill that instant to the customer on the strength of another device's   │
// │   silence. That asymmetry is deliberate and it points the same way as     │
// │   every other refusal in this product — toward not charging for our own   │
// │   failure.                                                               │
// │                                                                          │
// │ Then the declared MAINTENANCE WINDOW overrides all four. Maintenance is a │
// │ property of the SITE, it is agreed in the contract, and it is counted     │
// │ separately so that "we excluded 6 h" is a number on the report instead of │
// │ a rounding difference nobody can explain.                                 │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHY THERE ARE THREE AVAILABILITY NUMBERS AND NOT ONE ────────────────────┐
// │ availability  = up / (up + down)          the point estimate              │
// │ worstCase     = up / accountable          every unobserved second is down │
// │ bestCase      = (up + unmeasured) / accountable    ... is up              │
// │                                                                          │
// │ The OBJECTIVE is decided on the bracket, never on the point estimate:     │
// │   bestCase  <  objective  → MISSED   (true whatever the gaps hid)         │
// │   worstCase >= objective  → MET      (true whatever the gaps hid)         │
// │   otherwise               → INDETERMINATE                                 │
// │                                                                          │
// │ With no data at all the bracket is [0 %, 100 %] and the verdict is        │
// │ INDETERMINATE — which is the correct answer and the one a spreadsheet     │
// │ never gives. Half a month of gaps cannot buy a "met", and it cannot be    │
// │ used to invent a "missed" either.                                        │
// └───────────────────────────────────────────────────────────────────────────┘
//
// EVERY FUNCTION HERE IS PURE. No clock (`now` is always an argument), no I/O,
// no database, no `Date.now()`. The rule that decides whether an MSP owes its
// customer a service credit has to be exercisable offline, and it is: the F7
// harness runs the whole of section 4 with no Postgres at all.
//
// D3 / equipment: nothing in this file, or in anything that calls it, sends a
// byte to a device. F7 is arithmetic over rows that M2 and M3 already wrote.

import type { ReachabilityVerdict } from './telemetry';

// ============================================================================
// 1. Vocabularies
//
// Text + CHECK in the database (migration 026), exactly like every other
// vocabulary in this codebase. The comment on each constant gives the LONGEST
// member so the varchar width can be checked by eye against the migration.
// ============================================================================

/** How one second of one period was classified. Longest: `excluded_maintenance`
 *  (21) — `sla_report_intervals.kind` is varchar(24). */
export const SLA_INTERVAL_KINDS = [
  /** Service was delivered. Counts in the numerator AND the denominator. */
  'up',
  /** Service was not delivered and the fault is not provably ours. Counts in
   *  the denominator only. */
  'down',
  /** OUR management plane failed (`CONCENTRATOR_DEGRADED` /
   *  `TUNNEL_DOWN_SITE_UP`). Removed from BOTH sides, reported separately. */
  'excluded_management',
  /** Inside the site's declared maintenance window. Removed from both sides,
   *  reported separately, and never merged with the line above. */
  'excluded_maintenance',
  /** We have no observation. NOT uptime, NOT downtime. */
  'unmeasured',
] as const;
export type SlaIntervalKind = (typeof SLA_INTERVAL_KINDS)[number];

/** The kinds that leave the calculation. Exported as DATA so that the report,
 *  the API and the tests cannot each keep their own list. */
export const SLA_EXCLUDED_KINDS: readonly SlaIntervalKind[] = [
  'excluded_management',
  'excluded_maintenance',
] as const;

/** Longest: `complete` (8) — `sla_reports.coverage_status` is varchar(12). */
export const SLA_COVERAGE_STATUSES = [
  /** Nothing at all was measured. `availabilityPercent` is `null`. */
  'no_data',
  /** Something was measured, and something was not. */
  'partial',
  /** Every accountable second of the period carries an observation. */
  'complete',
] as const;
export type SlaCoverageStatus = (typeof SLA_COVERAGE_STATUSES)[number];

/** Longest: `indeterminate` (13) — `sla_reports.objective_verdict` is
 *  varchar(16). */
export const SLA_OBJECTIVE_VERDICTS = ['met', 'missed', 'indeterminate'] as const;
export type SlaObjectiveVerdict = (typeof SLA_OBJECTIVE_VERDICTS)[number];

/** Longest: `tenant` (6) — `sla_objectives.scope` / `sla_reports.objective_scope`
 *  are varchar(8). */
export const SLA_OBJECTIVE_SCOPES = ['tenant', 'site'] as const;
export type SlaObjectiveScope = (typeof SLA_OBJECTIVE_SCOPES)[number];

/**
 * The reason attached to every interval. Closed vocabulary, in the DB as a
 * varchar(64) WITHOUT a CHECK on purpose: a reason is explanatory, the kind is
 * the load-bearing value, and a new explanation must not need a migration.
 * Longest member today: `ppp_absent_while_concentrator_observing` (38).
 */
export const SLA_INTERVAL_REASONS = [
  'ppp_session_open',
  'ppp_absent_while_concentrator_observing',
  'verdict_up',
  'verdict_wan_failover',
  'verdict_site_down',
  'verdict_concentrator_degraded',
  'verdict_tunnel_down_site_up',
  'no_observation',
  'no_active_device_at_site',
  'maintenance_window',
] as const;
export type SlaIntervalReason = (typeof SLA_INTERVAL_REASONS)[number];

// ============================================================================
// 2. Server-side caps and constants
//
// NONE of these is caller-driven. They are here, in shared, so that the server
// and the verification harness cannot disagree about them, and every one of
// them that could move a verdict is written into the stored report and into
// its `params_hash`.
// ============================================================================

/** Bumped whenever the classification above changes meaning. Stored on every
 *  report: a report computed by a different algorithm is a different document,
 *  and comparing the two without noticing is how a regression gets sold. */
export const SLA_ALGORITHM_VERSION = 'f7.1';

/** How long one K7 sample speaks for. A verdict is a POINT observation; the
 *  default is twenty times the M2 sweep period, which is generous, and the
 *  cap below is what stops a caller from turning one UP row into a year. */
export const DEFAULT_VERDICT_VALIDITY_SECONDS = 900;
export const MIN_VERDICT_VALIDITY_SECONDS = 60;
export const MAX_VERDICT_VALIDITY_SECONDS = 21_600; // 6 h

/** The longest period a single report may cover, and the shortest. A yearly
 *  SLA report is the point of the feature; two years of `ppp_sessions` in one
 *  request is a denial of service against our own database. */
export const SLA_MAX_PERIOD_DAYS = 366;
export const SLA_MIN_PERIOD_SECONDS = 60;

/** Refusal thresholds for the STORED report. Beyond these the answer is a 400
 *  naming the number, never a silently truncated audit trail: a report whose
 *  exclusions were dropped because there were too many of them is precisely
 *  the document this feature exists to replace. */
export const SLA_MAX_STORED_INTERVALS = 5_000;
/** Rows read from `ppp_sessions` / `reachability_verdicts` per device. */
export const SLA_MAX_ROWS_PER_DEVICE = 20_000;
/** Devices per site. A site with more than this is not a site. */
export const SLA_MAX_DEVICES_PER_SITE = 200;
/** Sites per request. Beyond this the answer is a 400 naming the number. */
export const SLA_MAX_SITES_PER_REQUEST = 200;
/**
 * Rows read while building the OBSERVATION MASK — every session the relevant
 * concentrators held for anybody during the period. A truncated mask would
 * silently reclassify real outages as `unmeasured` and improve the customer's
 * availability, so hitting this cap is a REFUSAL, never a truncation.
 */
export const SLA_MAX_OBSERVATION_ROWS = 100_000;

/** Percentages are stored `numeric(7,4)` and DECIDED at the same precision, so
 *  the number on the report is the number that produced the verdict. 1e-4 of a
 *  percentage point is 31 seconds per year. */
export const SLA_PERCENT_DECIMALS = 4;

/** An objective outside this range is refused by `validateObjectivePercent`
 *  AND by a CHECK in migration 026. The lower bound is not decoration: with
 *  `objective = 0` a period with no data at all would satisfy
 *  `worstCase >= objective` and be stored as MET. */
export const SLA_MIN_OBJECTIVE_PERCENT = 50;
export const SLA_MAX_OBJECTIVE_PERCENT = 100;

// ============================================================================
// 3. Interval algebra
//
// Half-open [start, end) throughout, epoch milliseconds throughout. Half-open
// because two adjacent intervals must not both own the instant between them —
// which, on a 365-day report, is how the totals stop adding up to the period.
// ============================================================================

export interface SlaInterval {
  /** Epoch ms, inclusive. */
  start: number;
  /** Epoch ms, exclusive. */
  end: number;
}

/** Sort, drop the empty ones, merge everything that touches or overlaps. */
export function normalizeIntervals(intervals: readonly SlaInterval[]): SlaInterval[] {
  const kept = intervals
    .filter((i) => Number.isFinite(i.start) && Number.isFinite(i.end) && i.end > i.start)
    .sort((a, b) => a.start - b.start || a.end - b.end);
  const out: SlaInterval[] = [];
  for (const i of kept) {
    const last = out[out.length - 1];
    if (last && i.start <= last.end) {
      if (i.end > last.end) last.end = i.end;
    } else {
      out.push({ start: i.start, end: i.end });
    }
  }
  return out;
}

/** Clip a set of intervals to a window. Returns a normalized set. */
export function clipIntervals(
  intervals: readonly SlaInterval[],
  from: number,
  to: number,
): SlaInterval[] {
  const clipped: SlaInterval[] = [];
  for (const i of intervals) {
    const start = Math.max(i.start, from);
    const end = Math.min(i.end, to);
    if (end > start) clipped.push({ start, end });
  }
  return normalizeIntervals(clipped);
}

/** Is `t` inside any of `intervals`? `intervals` MUST be normalized (sorted,
 *  disjoint) — this is a binary search, not a scan. */
export function coversInstant(intervals: readonly SlaInterval[], t: number): boolean {
  let lo = 0;
  let hi = intervals.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const iv = intervals[mid];
    if (t < iv.start) hi = mid - 1;
    else if (t >= iv.end) lo = mid + 1;
    else return true;
  }
  return false;
}

// ============================================================================
// 4. K7 verdicts → SLA state
// ============================================================================

/** The three states a DECISIVE observation can assert. */
export type SlaObservedState = 'up' | 'down' | 'excluded_management';

/**
 * Map a K7 verdict onto an SLA state, or `null` when the verdict carries no
 * opinion.
 *
 * `UNREACHABLE` → `null`, AND THAT IS THE WHOLE POINT (see the header, item 3).
 * `shared/src/telemetry.ts`: "`UNREACHABLE` means we cannot tell". Folding it
 * into `down` bills the customer for our blindness; folding it into `up` sells
 * them an availability we never observed. It is neither, so it is nothing, and
 * the presence history underneath decides instead.
 *
 * `WAN_FAILOVER` → `up`. The site is reachable, through a different path than
 * the nominal one. That is a degraded service and a thing an operator must be
 * told about (F5 exists for it), but it is NOT an outage, and counting it as
 * one would hand the customer a service credit for a link that worked.
 */
export function stateForVerdict(verdict: ReachabilityVerdict): SlaObservedState | null {
  switch (verdict) {
    case 'UP':
    case 'WAN_FAILOVER':
      return 'up';
    case 'SITE_DOWN':
      return 'down';
    case 'CONCENTRATOR_DEGRADED':
    case 'TUNNEL_DOWN_SITE_UP':
      return 'excluded_management';
    case 'UNREACHABLE':
      return null;
    default: {
      // Exhaustiveness: a verdict added to `REACHABILITY_VERDICTS` without a
      // decision here must not silently become "no opinion".
      const never: never = verdict;
      return never;
    }
  }
}

/** The reason string a decisive verdict contributes. */
export function reasonForVerdict(verdict: ReachabilityVerdict): SlaIntervalReason {
  switch (verdict) {
    case 'UP': return 'verdict_up';
    case 'WAN_FAILOVER': return 'verdict_wan_failover';
    case 'SITE_DOWN': return 'verdict_site_down';
    case 'CONCENTRATOR_DEGRADED': return 'verdict_concentrator_degraded';
    case 'TUNNEL_DOWN_SITE_UP': return 'verdict_tunnel_down_site_up';
    default: return 'no_observation';
  }
}

// ============================================================================
// 5. The device timeline
// ============================================================================

export interface SlaVerdictSample {
  /** Epoch ms. */
  ts: number;
  verdict: ReachabilityVerdict;
}

export interface SlaSegment {
  start: number;
  end: number;
  kind: SlaIntervalKind;
  reason: SlaIntervalReason;
}

export interface DeviceTimelineInput {
  from: number;
  to: number;
  /** Intervals during which THIS device held an open PPP session. */
  sessions: readonly SlaInterval[];
  /**
   * Intervals during which we can PROVE ObliWAN was observing this device's
   * concentrator — normally the union of that concentrator's sessions for every
   * username. Empty means "we cannot prove we were watching", and every second
   * without a session then lands in `unmeasured` rather than in `down`.
   */
  observation: readonly SlaInterval[];
  /** K7 samples, any order. `UNREACHABLE` may be present; it is dropped here. */
  verdicts: readonly SlaVerdictSample[];
  /** Capped by the caller to [MIN, MAX]_VERDICT_VALIDITY_SECONDS. */
  verdictValiditySeconds: number;
}

/**
 * Classify every instant of [from, to) for ONE device.
 *
 * The implementation is a boundary sweep: collect every timestamp at which the
 * answer could change, then decide each elementary slice once. It is O(n log n)
 * and, more usefully, it is obviously correct — an interval-merging version of
 * the same thing has four ways to lose a second at a boundary and this has
 * none, because the totals are re-derived from the slices themselves.
 */
export function buildDeviceTimeline(input: DeviceTimelineInput): SlaSegment[] {
  const { from, to } = input;
  if (!(to > from)) return [];

  const sessions = clipIntervals(input.sessions, from, to);
  const observation = clipIntervals(input.observation, from, to);

  // -- Decisive verdicts, sorted, `UNREACHABLE` dropped ---------------------
  const validityMs = input.verdictValiditySeconds * 1000;
  const decisive = input.verdicts
    .filter((v) => stateForVerdict(v.verdict) !== null)
    .filter((v) => v.ts < to) // a sample taken after the period says nothing about it
    .sort((a, b) => a.ts - b.ts);

  // ── HOW LONG ONE SAMPLE SPEAKS FOR ───────────────────────────────────────
  // A sample governs [ts, X) where X is the FIRST of:
  //   - the next decisive verdict,
  //   - the end of its validity,
  //   - THE NEXT PPP SESSION TRANSITION for this device,
  //   - the end of the period.
  //
  // The third bound is not an optimisation. A session starting or ending is a
  // DATED OBSERVATION of exactly the thing the verdict is about, and it is
  // newer. Without it, a `CONCENTRATOR_DEGRADED` sample taken ten minutes
  // before the tunnel came back would keep excluding minutes during which we
  // hold direct proof that service was being delivered — an exclusion is
  // removed from the customer's bill, so letting a stale sample stretch over
  // observed uptime is an error in the one direction this file must not take.
  //
  // A sample taken BEFORE the period still speaks for the beginning of it, for
  // at most `validity`, which is why the loader fetches a lookback window.
  const transitions: number[] = [];
  for (const s of sessions) { transitions.push(s.start, s.end); }
  transitions.sort((a, b) => a - b);
  const nextTransitionAfter = (t: number): number => {
    let lo = 0;
    let hi = transitions.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (transitions[mid] <= t) lo = mid + 1; else hi = mid;
    }
    return lo < transitions.length ? transitions[lo] : Number.POSITIVE_INFINITY;
  };

  const governed: Array<{ start: number; end: number; sample: SlaVerdictSample }> = [];
  for (let i = 0; i < decisive.length; i++) {
    const sample = decisive[i];
    const next = decisive[i + 1];
    const end = Math.min(
      sample.ts + validityMs,
      next ? next.ts : Number.POSITIVE_INFINITY,
      nextTransitionAfter(sample.ts),
      to,
    );
    const start = Math.max(sample.ts, from);
    if (end > start) governed.push({ start, end, sample });
  }

  // -- Boundaries -----------------------------------------------------------
  const marks = new Set<number>([from, to]);
  const mark = (t: number): void => { if (t > from && t < to) marks.add(t); };
  for (const s of sessions) { mark(s.start); mark(s.end); }
  for (const o of observation) { mark(o.start); mark(o.end); }
  for (const g of governed) { mark(g.start); mark(g.end); }

  const points = [...marks].sort((a, b) => a - b);

  // -- Decide each slice ----------------------------------------------------
  const out: SlaSegment[] = [];
  for (let i = 0; i < points.length - 1; i++) {
    const start = points[i];
    const end = points[i + 1];
    if (end <= start) continue;
    // Any instant inside the slice answers for all of it: every timestamp at
    // which the answer could change is a boundary, by construction.
    const probe = start;

    let kind: SlaIntervalKind;
    let reason: SlaIntervalReason;

    const g = governed.find((x) => probe >= x.start && probe < x.end);
    if (g) {
      const state = stateForVerdict(g.sample.verdict);
      kind = state === null ? 'unmeasured' : state;
      reason = reasonForVerdict(g.sample.verdict);
    } else if (coversInstant(sessions, probe)) {
      kind = 'up';
      reason = 'ppp_session_open';
    } else if (coversInstant(observation, probe)) {
      kind = 'down';
      reason = 'ppp_absent_while_concentrator_observing';
    } else {
      kind = 'unmeasured';
      reason = 'no_observation';
    }

    const last = out[out.length - 1];
    if (last && last.end === start && last.kind === kind && last.reason === reason) {
      last.end = end;
    } else {
      out.push({ start, end, kind, reason });
    }
  }
  return out;
}

// ============================================================================
// 6. The site timeline
// ============================================================================

/**
 * `up > excluded_management > down > unmeasured`. See the header for why
 * `excluded_management` sits above `down` and below `up`.
 */
const SITE_PRECEDENCE: Record<SlaIntervalKind, number> = {
  up: 4,
  excluded_management: 3,
  down: 2,
  unmeasured: 1,
  // Maintenance is a SITE property applied afterwards by `applyMaintenance`,
  // and no device timeline can ever produce it. It is ranked above everything
  // so that the precedence table stays total rather than partial.
  excluded_maintenance: 5,
};

/**
 * Combine the per-device timelines of ONE site.
 *
 * `deviceTimelines` empty — a site with no active CPE — yields the whole period
 * as `unmeasured / no_active_device_at_site`. It emphatically does not yield
 * 100 %: a site we monitor nothing at is a site we can say nothing about, and
 * that is the difference between this and the spreadsheet.
 */
export function combineSiteTimeline(
  deviceTimelines: readonly (readonly SlaSegment[])[],
  from: number,
  to: number,
): SlaSegment[] {
  if (!(to > from)) return [];
  const live = deviceTimelines.filter((t) => t.length > 0);
  if (live.length === 0) {
    return [{ start: from, end: to, kind: 'unmeasured', reason: 'no_active_device_at_site' }];
  }

  const marks = new Set<number>([from, to]);
  for (const timeline of live) {
    for (const seg of timeline) {
      if (seg.start > from && seg.start < to) marks.add(seg.start);
      if (seg.end > from && seg.end < to) marks.add(seg.end);
    }
  }
  const points = [...marks].sort((a, b) => a - b);

  const out: SlaSegment[] = [];
  for (let i = 0; i < points.length - 1; i++) {
    const start = points[i];
    const end = points[i + 1];
    if (end <= start) continue;

    let kind: SlaIntervalKind = 'unmeasured';
    let reason: SlaIntervalReason = 'no_observation';
    let best = 0;
    for (const timeline of live) {
      const seg = timeline.find((s) => start >= s.start && start < s.end);
      if (!seg) continue;
      const rank = SITE_PRECEDENCE[seg.kind];
      if (rank > best) { best = rank; kind = seg.kind; reason = seg.reason; }
    }

    const last = out[out.length - 1];
    if (last && last.end === start && last.kind === kind && last.reason === reason) {
      last.end = end;
    } else {
      out.push({ start, end, kind, reason });
    }
  }
  return out;
}

/**
 * Overlay the declared maintenance windows. They win over everything, they are
 * counted separately, and they are removed from both sides of the ratio.
 */
export function applyMaintenance(
  segments: readonly SlaSegment[],
  maintenance: readonly SlaInterval[],
): SlaSegment[] {
  const windows = normalizeIntervals(maintenance);
  if (windows.length === 0) return segments.map((s) => ({ ...s }));

  const out: SlaSegment[] = [];
  const push = (start: number, end: number, kind: SlaIntervalKind, reason: SlaIntervalReason): void => {
    if (end <= start) return;
    const last = out[out.length - 1];
    if (last && last.end === start && last.kind === kind && last.reason === reason) {
      last.end = end;
    } else {
      out.push({ start, end, kind, reason });
    }
  };

  for (const seg of segments) {
    let cursor = seg.start;
    for (const w of windows) {
      if (w.end <= cursor) continue;
      if (w.start >= seg.end) break;
      const overlapStart = Math.max(w.start, cursor);
      const overlapEnd = Math.min(w.end, seg.end);
      if (overlapEnd <= overlapStart) continue;
      push(cursor, overlapStart, seg.kind, seg.reason);
      push(overlapStart, overlapEnd, 'excluded_maintenance', 'maintenance_window');
      cursor = overlapEnd;
    }
    push(cursor, seg.end, seg.kind, seg.reason);
  }
  return out;
}

// ============================================================================
// 7. Totals and the verdict
// ============================================================================

export interface SlaTotals {
  periodSeconds: number;
  upSeconds: number;
  downSeconds: number;
  excludedManagementSeconds: number;
  excludedMaintenanceSeconds: number;
  unmeasuredSeconds: number;
  /** `up + down`. The denominator of the point estimate. */
  measuredSeconds: number;
  /** `period - maintenance - management`. What the customer may be billed for. */
  accountableSeconds: number;
}

const ZERO_TOTALS: SlaTotals = {
  periodSeconds: 0,
  upSeconds: 0,
  downSeconds: 0,
  excludedManagementSeconds: 0,
  excludedMaintenanceSeconds: 0,
  unmeasuredSeconds: 0,
  measuredSeconds: 0,
  accountableSeconds: 0,
};

/**
 * Sum the segments. The period is taken from [from, to) and NOT from the
 * segments, and anything the segments failed to cover lands in `unmeasured` —
 * a hole in the timeline must inflate the unobserved time, never shrink the
 * period and quietly improve the ratio.
 */
export function totalsFor(
  segments: readonly SlaSegment[],
  from: number,
  to: number,
): SlaTotals {
  if (!(to > from)) return { ...ZERO_TOTALS };
  const ms: Record<SlaIntervalKind, number> = {
    up: 0, down: 0, excluded_management: 0, excluded_maintenance: 0, unmeasured: 0,
  };
  let covered = 0;
  for (const s of segments) {
    const start = Math.max(s.start, from);
    const end = Math.min(s.end, to);
    if (end <= start) continue;
    ms[s.kind] += end - start;
    covered += end - start;
  }
  const periodMs = to - from;
  ms.unmeasured += Math.max(0, periodMs - covered);

  // ── THE BUCKETS MUST ADD UP TO THE PERIOD, EXACTLY. ─────────────────────
  // Rounding each bucket on its own loses or invents up to two seconds, and
  // migration 026 refuses the row with `sla_reports_seconds_balance_chk` — as
  // it should: a report whose parts do not sum to its whole is the first thing
  // an auditor checks, and the second thing he stops believing. Rounding the
  // RUNNING TOTAL and taking differences makes the sum exact by construction
  // and keeps every bucket non-negative (a cumulative sum is monotonic).
  const order = ['up', 'down', 'excluded_management', 'excluded_maintenance', 'unmeasured'] as const;
  const sec: Record<SlaIntervalKind, number> = {
    up: 0, down: 0, excluded_management: 0, excluded_maintenance: 0, unmeasured: 0,
  };
  let accMs = 0;
  let allocated = 0;
  for (const kind of order) {
    accMs += ms[kind];
    const cumulative = Math.round(accMs / 1000);
    sec[kind] = cumulative - allocated;
    allocated = cumulative;
  }

  return {
    periodSeconds: allocated,
    upSeconds: sec.up,
    downSeconds: sec.down,
    excludedManagementSeconds: sec.excluded_management,
    excludedMaintenanceSeconds: sec.excluded_maintenance,
    unmeasuredSeconds: sec.unmeasured,
    measuredSeconds: sec.up + sec.down,
    accountableSeconds: sec.up + sec.down + sec.unmeasured,
  };
}

/** Round to the precision the report is STORED at, so the number that decided
 *  the verdict is the number the reader sees. */
export function roundPercent(value: number): number {
  const f = 10 ** SLA_PERCENT_DECIMALS;
  return Math.round(value * f) / f;
}

export interface SlaOutcome {
  totals: SlaTotals;
  /** `up / measured`, as a percentage. **`null` when nothing was measured.** */
  availabilityPercent: number | null;
  /** Every unobserved second counted as an outage. `null` when there is no
   *  accountable time at all. */
  worstCasePercent: number | null;
  /** Every unobserved second counted as service. */
  bestCasePercent: number | null;
  /** `measured / accountable`, as a percentage. How much of the billable period
   *  we actually saw. */
  coveragePercent: number | null;
  status: SlaCoverageStatus;
  objectivePercent: number | null;
  objectiveVerdict: SlaObjectiveVerdict;
  /** Why the verdict is what it is. Machine-readable; the UI translates it. */
  verdictReason: string;
}

/**
 * Turn totals + an objective into the answer.
 *
 * THE ORDER OF THE TESTS BELOW IS THE FEATURE. `no_data` is checked before
 * anything can compute a ratio, and `missed` is checked before `met` so that a
 * bracket which straddles the objective can never be resolved optimistically.
 */
export function evaluateSla(
  totals: SlaTotals,
  objectivePercent: number | null,
): SlaOutcome {
  const {
    upSeconds, measuredSeconds, unmeasuredSeconds, accountableSeconds,
  } = totals;

  const base: Omit<SlaOutcome,
    'availabilityPercent' | 'worstCasePercent' | 'bestCasePercent' | 'coveragePercent'
    | 'status' | 'objectiveVerdict' | 'verdictReason'> = {
    totals,
    objectivePercent,
  };

  // -- The whole period was excluded ---------------------------------------
  // Maintenance covering everything, or a concentrator outage that lasted the
  // month. There is no billable time, so there is nothing to be met or missed.
  if (accountableSeconds <= 0) {
    return {
      ...base,
      availabilityPercent: null,
      worstCasePercent: null,
      bestCasePercent: null,
      coveragePercent: null,
      status: 'no_data',
      objectiveVerdict: 'indeterminate',
      verdictReason: 'entire_period_excluded',
    };
  }

  const worst = roundPercent((upSeconds / accountableSeconds) * 100);
  const best = roundPercent(((upSeconds + unmeasuredSeconds) / accountableSeconds) * 100);
  const coverage = roundPercent((measuredSeconds / accountableSeconds) * 100);

  // -- Nothing was measured -------------------------------------------------
  // THE F2 DEFECT, AND THE ONE THING THIS FUNCTION MUST NEVER GET WRONG.
  // `availabilityPercent` is null, not 100. Migration 026 refuses the row that
  // would say otherwise.
  if (measuredSeconds === 0) {
    return {
      ...base,
      availabilityPercent: null,
      worstCasePercent: worst,
      bestCasePercent: best,
      coveragePercent: coverage,
      status: 'no_data',
      objectiveVerdict: 'indeterminate',
      verdictReason: 'no_measurement',
    };
  }

  const availability = roundPercent((upSeconds / measuredSeconds) * 100);
  const status: SlaCoverageStatus = unmeasuredSeconds === 0 ? 'complete' : 'partial';

  let objectiveVerdict: SlaObjectiveVerdict = 'indeterminate';
  let verdictReason = 'no_objective_configured';
  if (objectivePercent !== null) {
    if (best < objectivePercent) {
      objectiveVerdict = 'missed';
      verdictReason = 'observed_downtime_alone_breaches_objective';
    } else if (worst >= objectivePercent) {
      objectiveVerdict = 'met';
      verdictReason = 'objective_held_even_if_every_gap_was_an_outage';
    } else {
      objectiveVerdict = 'indeterminate';
      verdictReason = 'coverage_insufficient_to_decide';
    }
  }

  return {
    ...base,
    availabilityPercent: availability,
    worstCasePercent: worst,
    bestCasePercent: best,
    coveragePercent: coverage,
    status,
    objectiveVerdict,
    verdictReason,
  };
}

/** Every exclusion, with its seconds and its reason, as the report prints it.
 *  An SLA whose exclusions cannot be enumerated is a spreadsheet. */
export interface SlaExclusionLine {
  kind: 'excluded_management' | 'excluded_maintenance';
  reason: SlaIntervalReason;
  seconds: number;
  occurrences: number;
}

export function summariseExclusions(segments: readonly SlaSegment[]): SlaExclusionLine[] {
  const acc = new Map<string, SlaExclusionLine>();
  for (const s of segments) {
    if (s.kind !== 'excluded_management' && s.kind !== 'excluded_maintenance') continue;
    const key = `${s.kind}|${s.reason}`;
    const line = acc.get(key) ?? { kind: s.kind, reason: s.reason, seconds: 0, occurrences: 0 };
    line.seconds += Math.round((s.end - s.start) / 1000);
    line.occurrences += 1;
    acc.set(key, line);
  }
  return [...acc.values()].sort((a, b) => b.seconds - a.seconds);
}

// ============================================================================
// 8. Objectives
// ============================================================================

export class SlaObjectiveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SlaObjectiveError';
  }
}

/** Refuses what migration 026's CHECK refuses, at the same bounds, with a
 *  sentence instead of a 23514. Two independent refusals on purpose: this one
 *  is not what runs when a row is edited by hand. */
export function validateObjectivePercent(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new SlaObjectiveError('objectivePercent must be a finite number');
  }
  const rounded = roundPercent(value);
  if (rounded < SLA_MIN_OBJECTIVE_PERCENT || rounded > SLA_MAX_OBJECTIVE_PERCENT) {
    throw new SlaObjectiveError(
      `objectivePercent must be between ${SLA_MIN_OBJECTIVE_PERCENT} and `
      + `${SLA_MAX_OBJECTIVE_PERCENT} (got ${rounded}). An objective of 0 would make a `
      + 'period with no data at all satisfy "worst case >= objective" and be sold as met.',
    );
  }
  return rounded;
}

export function clampVerdictValiditySeconds(value: unknown): number {
  const n = typeof value === 'number' && Number.isFinite(value)
    ? Math.round(value)
    : DEFAULT_VERDICT_VALIDITY_SECONDS;
  return Math.min(
    MAX_VERDICT_VALIDITY_SECONDS,
    Math.max(MIN_VERDICT_VALIDITY_SECONDS, n),
  );
}

// ============================================================================
// 9. Maintenance windows
//
// `sites.maintenance_window` (migration 002) is `{ days, start, end, tz? }` and
// has been writable by hand since M2. `jobQueue.service.ts` reads it as a
// POINT predicate ("may I push right now"); F7 needs the same window EXPANDED
// into intervals over a year. Same column, same semantics, two different
// questions — and the semantics are kept identical on purpose: a window that
// blocks a push on Sunday at 03:00 must be the same window that is excluded
// from the SLA on Sunday at 03:00.
//
// ┌─ THE FAILURE DIRECTION IS INVERTED, AND IT HAS TO BE ─────────────────────┐
// │ `isWithinMaintenanceWindow` FAILS CLOSED: an unreadable window refuses    │
// │ the push. Here an unreadable window EXCLUDES NOTHING, and the report      │
// │ carries the parse error. Both point the same way — toward the customer.   │
// │ A window we cannot read must never become a licence to delete downtime    │
// │ from an invoice, and "we could not parse your maintenance window so we    │
// │ excluded six hours" is the shape of a dispute nobody wins.                │
// └───────────────────────────────────────────────────────────────────────────┘
// ============================================================================

const DAY_NAMES = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'] as const;
const DAY_MS = 86_400_000;

export interface MaintenanceExpansion {
  intervals: SlaInterval[];
  /** Non-null when the window could not be read. `intervals` is then empty. */
  error: string | null;
}

function parseHhMm(raw: string): number | null {
  const m = /^(\d{1,2}):(\d{2})$/.exec(raw.trim());
  if (!m) return null;
  const h = Number(m[1]);
  const min = Number(m[2]);
  if (h > 23 || min > 59) return null;
  return h * 60 + min;
}

/** The offset, in ms, that `tz` was at the instant `utcMs`. */
function tzOffsetMs(utcMs: number, tz: string): number {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tz,
    hourCycle: 'h23',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  }).formatToParts(new Date(utcMs));
  const get = (type: string): number => {
    const raw = parts.find((p) => p.type === type)?.value;
    const n = Number(raw);
    if (!Number.isFinite(n)) throw new Error(`unreadable ${type}`);
    return n;
  };
  const asIfUtc = Date.UTC(get('year'), get('month') - 1, get('day'), get('hour'), get('minute'), get('second'));
  return asIfUtc - utcMs;
}

/**
 * A wall-clock time in `tz` → the instant it names.
 *
 * Two passes because the offset depends on the instant we are trying to find.
 * Across a DST transition the first guess is up to an hour out and the second
 * pass corrects it; in the spring-forward hole (a wall time that does not
 * exist) the two passes disagree and the result lands on the transition, which
 * is the conventional answer and is at worst an hour of a maintenance window.
 */
function wallToUtc(y: number, m: number, d: number, minutes: number, tz: string): number {
  const naive = Date.UTC(y, m - 1, d, Math.floor(minutes / 60), minutes % 60, 0);
  const first = tzOffsetMs(naive, tz);
  const guess = naive - first;
  const second = tzOffsetMs(guess, tz);
  return second === first ? guess : naive - second;
}

/** The civil date `utcMs` falls on, in `tz`. */
function civilDate(utcMs: number, tz: string): { y: number; m: number; d: number } {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
  }).formatToParts(new Date(utcMs));
  const get = (type: string): number => Number(parts.find((p) => p.type === type)?.value);
  return { y: get('year'), m: get('month'), d: get('day') };
}

export interface MaintenanceWindowSpec {
  days?: Array<string | number> | null;
  start?: string | null;
  end?: string | null;
  tz?: string | null;
  enabled?: boolean | null;
}

/**
 * Expand a site's declared window into the intervals of [from, to) it covers.
 *
 * Accepts BOTH spellings of `days` (three-letter/full names and 0-6 with
 * 0 = Sunday) for the same reason `jobQueue.service.ts` does: the column has
 * been writable with no validator in front of it since M2.
 *
 * Semantics, matching the point predicate exactly:
 *   - `enabled === false`, or no `days` and no times → no window at all.
 *   - days without times → the whole of each named local day.
 *   - `start === end` → the whole of each named local day ("no time limit").
 *   - `start > end` → the window wraps midnight, and the day test applies to
 *     THE INSTANT, not to the window's start. `{days:['sun'],22:00→06:00}` is
 *     open Sunday 22:00-24:00 and NOT Monday 00:00-06:00 — which is what
 *     `isWithinMaintenanceWindow` answers, and two different readings of one
 *     column is a bug nobody ever finds.
 */
export function expandMaintenanceWindow(
  window: unknown,
  siteTimezone: string | null,
  from: number,
  to: number,
): MaintenanceExpansion {
  const none: MaintenanceExpansion = { intervals: [], error: null };
  if (window === null || window === undefined) return none;
  if (typeof window !== 'object' || Array.isArray(window)) {
    return { intervals: [], error: 'maintenance_window is not an object' };
  }
  const w = window as MaintenanceWindowSpec;
  if (w.enabled === false) return none;

  const hasDays = Array.isArray(w.days) && w.days.length > 0;
  const hasTimes = typeof w.start === 'string' && typeof w.end === 'string';
  if (!hasDays && !hasTimes) return none;

  const tz = (typeof w.tz === 'string' && w.tz) || siteTimezone || 'UTC';
  try {
    tzOffsetMs(from, tz);
  } catch {
    return { intervals: [], error: `invalid timezone "${tz}"` };
  }

  let allowed: Set<number> | null = null;
  if (hasDays) {
    allowed = new Set<number>();
    for (const raw of w.days as Array<string | number>) {
      if (typeof raw === 'number' && Number.isInteger(raw) && raw >= 0 && raw <= 6) {
        allowed.add(raw);
      } else if (typeof raw === 'string') {
        const idx = (DAY_NAMES as readonly string[]).indexOf(raw.trim().toLowerCase().slice(0, 3));
        if (idx < 0) {
          return { intervals: [], error: `unreadable day "${raw}" in maintenance_window` };
        }
        allowed.add(idx);
      } else {
        return { intervals: [], error: 'unreadable entry in maintenance_window.days' };
      }
    }
  }

  let startMin = 0;
  let endMin = 0;
  let wholeDay = true;
  if (hasTimes) {
    const s = parseHhMm(w.start as string);
    const e = parseHhMm(w.end as string);
    if (s === null || e === null) {
      return { intervals: [], error: 'maintenance_window start/end are not HH:MM' };
    }
    startMin = s;
    endMin = e;
    wholeDay = s === e;
  }

  // Walk the LOCAL calendar days that can touch the period. One day of slack on
  // each side: a window that wraps midnight contributes to the day before, and
  // the local date at `to` can be the next one.
  const firstCivil = civilDate(from, tz);
  const lastCivil = civilDate(to, tz);
  let cursor = Date.UTC(firstCivil.y, firstCivil.m - 1, firstCivil.d) - DAY_MS;
  const stop = Date.UTC(lastCivil.y, lastCivil.m - 1, lastCivil.d) + DAY_MS;

  const intervals: SlaInterval[] = [];
  // Hard stop: 368 iterations at most for a 366-day period, but a corrupt
  // `to` must not spin forever.
  let guard = 0;
  while (cursor <= stop && guard++ < 512) {
    const day = new Date(cursor);
    const y = day.getUTCFullYear();
    const m = day.getUTCMonth() + 1;
    const d = day.getUTCDate();
    const dow = day.getUTCDay();
    cursor += DAY_MS;

    if (allowed && !allowed.has(dow)) continue;

    const dayStart = wallToUtc(y, m, d, 0, tz);
    // The true end of the LOCAL day, not `dayStart + 24 h`: a DST day is 23 or
    // 25 hours long, and a fixed day drifts the boundary by an hour twice a
    // year — which is exactly the hour an operator schedules maintenance in.
    const next = new Date(Date.UTC(y, m - 1, d) + DAY_MS);
    const dayEnd = wallToUtc(
      next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate(), 0, tz,
    );
    if (wholeDay) {
      intervals.push({ start: dayStart, end: dayEnd });
      continue;
    }
    if (startMin < endMin) {
      intervals.push({
        start: wallToUtc(y, m, d, startMin, tz),
        end: wallToUtc(y, m, d, endMin, tz),
      });
    } else {
      // Wrapping. The day test applies to the instant, so this local day
      // contributes [start, midnight) and [midnight, end) — the second half of
      // the PREVIOUS night only if the previous day is itself allowed, which
      // its own iteration handles.
      intervals.push({ start: wallToUtc(y, m, d, startMin, tz), end: dayEnd });
      intervals.push({ start: dayStart, end: wallToUtc(y, m, d, endMin, tz) });
    }
  }

  return { intervals: clipIntervals(intervals, from, to), error: null };
}

// ============================================================================
// 10. The report shape the API serves
// ============================================================================

export interface SlaPeriod {
  /** ISO-8601. */
  from: string;
  to: string;
}

export interface SlaSiteReport {
  siteId: number;
  siteCode: string;
  siteName: string;
  siteTimezone: string;
  deviceCount: number;
  period: SlaPeriod;
  outcome: SlaOutcome;
  exclusions: SlaExclusionLine[];
  /** Non-null when `sites.maintenance_window` could not be read. Nothing was
   *  excluded for maintenance in that case, and the report says so. */
  maintenanceError: string | null;
  objectiveScope: SlaObjectiveScope | null;
  algorithmVersion: string;
  verdictValiditySeconds: number;
}

/**
 * The published method. Served by `GET /api/sla/method` so that a customer
 * disputing a report can read what was counted without reading this file — and
 * so that changing the rule without changing the sentence is a visible lie
 * rather than an invisible one.
 */
export const SLA_METHOD: readonly string[] = [
  'Availability = seconds of proven service / (seconds of proven service + seconds of proven outage).',
  'Seconds we did not observe are reported as unmeasured. They are never counted as service, '
  + 'and a period with no observation at all has NO availability figure — not 100 %.',
  'An outage of the ObliWAN management plane is excluded from both sides of the ratio: '
  + 'the K7 verdicts CONCENTRATOR_DEGRADED (our concentrator was down) and TUNNEL_DOWN_SITE_UP '
  + '(the tunnel died while an independent signal proved the site alive). '
  + 'Their seconds are reported separately, with their reason.',
  'The K7 verdict UNREACHABLE means "we cannot tell". It is neither uptime nor downtime and '
  + 'never overrides the PPP presence history.',
  'Declared maintenance windows (sites.maintenance_window) are excluded from both sides and '
  + 'counted separately. A window that cannot be parsed excludes nothing, and the report says so.',
  'A second with no PPP session counts as an outage only when the concentrator that terminates '
  + 'the tunnel was demonstrably holding sessions for other subscribers at that instant. '
  + 'Otherwise ObliWAN was not observing, and the second is unmeasured.',
  'The objective is decided on the bracket [worst case, best case], never on the point estimate: '
  + 'met only if the objective holds when every unobserved second is treated as an outage, '
  + 'missed only if it fails when every unobserved second is treated as service, '
  + 'and indeterminate otherwise.',
];
