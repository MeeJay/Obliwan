// ============================================================================
// ObliWAN — F3 (intervention mode) and F4 (change → telemetry, one week later)
// ============================================================================
//
// The contract both halves of ARCHITECTURE.md §10/F3-F4 are written against.
// Server and client read THIS file; neither keeps a copy of a vocabulary, a
// threshold or a verdict rule, because the day the two copies disagree is the
// day the screen and the database say different things about the same router.
//
// ┌─ F3 — AN INTERVENTION IS A DECLARATION, NEVER A PERMISSION ───────────────┐
// │ Opening an intervention says "a human is about to work on this box, here  │
// │ is who, why, and for how long". It does NOT authorise this server to      │
// │ write anything: D3 stands untouched — nothing reaches an equipment        │
// │ outside `change_jobs`. The only device access the intervention flow ever  │
// │ makes is a config READ, to take the before/after snapshots, and it is     │
// │ opt-in on every call.                                                     │
// │                                                                          │
// │ The two properties that make the feature worth its schema:                │
// │  1. drift observed on the device during a declared window is ATTRIBUTED   │
// │     to the intervention instead of surfacing as an anonymous anomaly —    │
// │     that is M4's main false-positive source going away;                   │
// │  2. an intervention nobody closes EXPIRES BY ITSELF and says so. An       │
// │     open-for-ever window is a permanent attribution hole: everything on   │
// │     that device would be excused for the rest of time.                    │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ F4 — "SINCE", NEVER "BECAUSE" ──────────────────────────────────────────┐
// │ The health gate of M7 measures five minutes after a wave. F4 measures     │
// │ seven days, on the same discipline and with the same trap in front of it: │
// │ a device that was ALREADY degraded before the change must not make the    │
// │ change look guilty. `healthGate.ts` solved that with `alreadyDown` /      │
// │ `alreadyErroring`; here the same idea is the `preexisting` signal         │
// │ outcome, and it EXCLUDES the subject from the comparison rather than      │
// │ folding it into a verdict.                                                │
// │                                                                          │
// │ And the second trap, which is a product decision and not a statistical    │
// │ one: correlation is not causation. Every sentence this feature produces   │
// │ says "since this change"; none of them says "because of this change".     │
// │ `assertCorrelationalWording()` is not documentation — it runs on every    │
// │ message the server builds, and it throws.                                 │
// └───────────────────────────────────────────────────────────────────────────┘

// ============================================================================
// F3 — vocabularies
// ============================================================================

/**
 * Lifecycle of a declared intervention.
 *
 *  open       the window is running. Drift on this device is attributable to
 *             it, and the device is expected to change.
 *  closed     a human closed it and looked at the diff.
 *  expired    NOBODY closed it and the declared window ran out. Distinct from
 *             `closed` on purpose: "we do not know what happened at the end of
 *             this intervention" is a different fact from "somebody reviewed
 *             it", and collapsing the two would hide exactly the case that
 *             needs chasing.
 *  cancelled  declared and then called off; the window never counted.
 *
 * Longest value 'cancelled' = 9 characters → varchar(12) in migration 020.
 */
export const INTERVENTION_STATUSES = ['open', 'closed', 'expired', 'cancelled'] as const;
export type InterventionStatus = (typeof INTERVENTION_STATUSES)[number];

/** A window that is still counting: drift lands on it. */
export function interventionIsLive(status: InterventionStatus): boolean {
  return status === 'open';
}

/**
 * How the human is getting in. Recorded because it decides what evidence to
 * expect afterwards: a Winbox session leaves a `device_login_events` line with
 * `method = 'winbox'`, a console session leaves nothing at all, and an
 * intervention declared as `console` that produced no login event is therefore
 * NOT a missing-log incident.
 *
 * Longest value 'console' = 7 → varchar(12).
 */
export const INTERVENTION_CHANNELS = [
  'winbox',
  'ssh',
  'webfig',
  'console',
  'vendor',
  'other',
] as const;
export type InterventionChannel = (typeof INTERVENTION_CHANNELS)[number];

/**
 * What was decided about the diff the intervention produced.
 *
 * `unreviewed` is the honest default at closing time and stays until somebody
 * acts: the point of F3 is that legitimate work becomes a CONTRIBUTION to the
 * model (a template, or a signed exception), and a disposition that defaulted
 * to "fine" would quietly drop every such contribution on the floor.
 *
 * Longest value 'unreviewed' = 10 → varchar(12).
 */
export const INTERVENTION_DISPOSITIONS = [
  'unreviewed',
  'no_change',
  'template',
  'exception',
  'rejected',
] as const;
export type InterventionDisposition = (typeof INTERVENTION_DISPOSITIONS)[number];

/**
 * The lifecycle log of one intervention. Appended, never updated: "this window
 * expired unattended" has to survive the operator who later closes the screen.
 *
 * Longest value 'snapshot_before' = 15 → varchar(20).
 */
export const INTERVENTION_EVENTS = [
  'opened',
  'snapshot_before',
  'snapshot_after',
  'closed',
  'expired',
  'cancelled',
  'drift_linked',
  'disposition',
] as const;
export type InterventionEvent = (typeof INTERVENTION_EVENTS)[number];

// ── The declared window ─────────────────────────────────────────────────────

/** Two hours: long enough for real work, short enough that forgetting to close
 *  one costs an afternoon of attribution and not a quarter. */
export const INTERVENTION_DEFAULT_WINDOW_MINUTES = 120;
/** Below five minutes the window is narrower than the drift detector's own
 *  granularity and would attribute nothing. */
export const INTERVENTION_MIN_WINDOW_MINUTES = 5;
/** Twelve hours — the service ceiling. A full working day of "everything on
 *  this router is excused" is already generous. */
export const INTERVENTION_MAX_WINDOW_MINUTES = 720;
/**
 * Seventy-two hours — the CHECK in migration 020, and deliberately looser than
 * the service ceiling above. The service rule is what operators meet; the
 * database rule is what survives the next person editing the service in a
 * hurry. Same reasoning as `drift_attributions_names_only_when_attributed`.
 */
export const INTERVENTION_HARD_CAP_MINUTES = 72 * 60;

/**
 * A drift whose change-window is wider than this is NOT attributed to an
 * intervention, even when the two overlap.
 *
 * Three times the longest declarable intervention. The reasoning is the one
 * K6 already applies to its own window: a change that provably happened
 * somewhere inside nine days is not explained by a two-hour window that
 * happens to fall inside it. Such a run is still LINKED to the intervention —
 * the operator sees the coincidence — but the K6 verdict is left alone.
 */
export const INTERVENTION_MAX_ATTRIBUTION_WINDOW_MINUTES = 3 * INTERVENTION_HARD_CAP_MINUTES;

/**
 * How much of the change window a declared intervention must actually cover
 * before it is allowed to EXPLAIN it.
 *
 * The ceiling above is not enough on its own: a change window of eight days is
 * UNDER it, and a five-minute intervention overlapping it by one minute would
 * satisfy it. The two numbers migration 020 stores on every link —
 * `window_span_seconds` and `overlap_seconds`, "the two numbers that justify
 * the claim" — have to be a CRITERION and not a display, or nothing justifies
 * the claim.
 *
 * A half is the weakest defensible statement: the declared window covers MOST
 * of the interval the change provably happened in. Below it the overlap is a
 * coincidence, and a coincidence that rewrites a K6 verdict deletes the very
 * "changes nobody owns" line the operator needed to see.
 */
export const INTERVENTION_MIN_OVERLAP_RATIO = 0.5;

/**
 * Does this declared window cover enough of the change window to explain it?
 *
 * Stated ONCE, here, for the same reason `effectiveEnd` lives in a module of
 * its own: the rule decides an attribution verdict, and a second copy of it
 * would disagree the first time either is tuned.
 *
 * A change window of zero length (both snapshots confirmed at the same instant)
 * is covered by definition once it falls inside the declared window — there is
 * no interval left for the intervention to miss.
 */
export function interventionCoversChangeWindow(
  overlapSeconds: number,
  windowSpanSeconds: number,
): boolean {
  if (windowSpanSeconds <= 0) return true;
  return overlapSeconds >= windowSpanSeconds * INTERVENTION_MIN_OVERLAP_RATIO;
}

/**
 * The verdict written into `drift_attributions.verdict` when a declared
 * intervention explains a drift run.
 *
 * It is NOT in `ATTRIBUTION_VERDICTS` (shared/src/logs.ts) — that file belongs
 * to M8 and is outside this feature's perimeter. Migration 020 widens the CHECK
 * on the column and this constant is the single place the string is written, so
 * adding the value to the M8 union is a one-line change at the junction rather
 * than a hunt through the service layer.
 */
export const INTERVENTION_ATTRIBUTION_VERDICT = 'intervention';

/**
 * What happened when an intervention met a drift run.
 *
 * `already_explained` is the one that keeps this feature honest. K6 answers
 * `platform` when one of OUR change jobs wrote the box, and `attributed` when
 * a login session names a person. Both are strictly more precise than "a
 * window was open at the time", so the intervention does not overwrite them —
 * it resolves the UNKNOWN (`unattributed`, `ambiguous`) and records the link
 * for everything else.
 *
 * Longest value 'already_explained' = 17 → varchar(24).
 */
export const INTERVENTION_LINK_DISPOSITIONS = [
  'attributed',
  'already_explained',
  'window_too_wide',
] as const;
export type InterventionLinkDisposition = (typeof INTERVENTION_LINK_DISPOSITIONS)[number];

// ── DTOs ────────────────────────────────────────────────────────────────────

export interface InterventionSummary {
  id: string;
  uuid: string;
  tenantId: number;
  deviceId: number;
  deviceName: string | null;
  status: InterventionStatus;
  channel: InterventionChannel;
  /** WHO is at the keyboard. Free text on purpose: it is very often a
   *  subcontractor or the customer's own admin, i.e. somebody who has no
   *  account on this platform. `openedBy` is the platform user who declared
   *  it, and the two are not the same person. */
  operator: string;
  openedBy: number | null;
  reason: string;
  openedAt: string;
  expiresAt: string;
  closedAt: string | null;
  closedBy: number | null;
  expiredAt: string | null;
  /** `expiresAt` for an open window, the real end otherwise. The interval drift
   *  is matched against. */
  effectiveEndAt: string;
  snapshotBeforeId: string | null;
  snapshotAfterId: string | null;
  /** The drift run computed at closing time, when one was. */
  driftRunId: string | null;
  findingsCount: number;
  maxSeverity: string | null;
  disposition: InterventionDisposition;
  notes: string | null;
  /** How many drift runs this window absorbed. */
  linkedRunCount: number;
  createdAt: string;
}

export interface InterventionEventRow {
  id: string;
  interventionId: string;
  event: InterventionEvent;
  actorUserId: number | null;
  detail: Record<string, unknown>;
  at: string;
}

export interface InterventionLink {
  id: string;
  interventionId: string;
  driftRunId: string;
  deviceId: number;
  disposition: InterventionLinkDisposition;
  /** What K6 had concluded before the intervention was considered. Kept so an
   *  operator can see what the platform would have said on its own. */
  priorVerdict: string | null;
  windowSpanSeconds: number;
  overlapSeconds: number;
  linkedAt: string;
}

// ============================================================================
// F4 — vocabularies and arithmetic
// ============================================================================

/**
 * The five comparable quantities. Every one of them is measured on BOTH sides
 * of the change, from the same table, at the same grain — an "after" number
 * compared against a differently-derived "before" number is not a comparison.
 *
 * All five come from the HOURLY rollups (`snmp_*_rollup_1h`, migration 006),
 * never from the raw tables: raw retention is 48 hours, so a seven-day window
 * over `snmp_if_samples` would silently be a two-day window — the exact
 * mistake `healthGate.readRttBaseline` documents.
 */
export const AFTERMATH_METRICS = [
  /** ifInErrors + ifOutErrors per hour, per interface. */
  'if_errors',
  /** p95 round-trip time to the device. */
  'rtt',
  /** reachable polls / attempted polls. */
  'availability',
  /** sysUpTime going backwards between two consecutive hourly buckets. */
  'unexpected_reboots',
  /** p95 throughput against `snmp_interfaces.speed_bps`, per interface. */
  'saturation',
] as const;
export type AftermathMetric = (typeof AFTERMATH_METRICS)[number];

/**
 * What one measured quantity says.
 *
 *  degraded      worse after than before, past the tolerance.
 *  improved      better after than before, past the same tolerance. Kept
 *                because "since this change the WAN errors stopped" is as
 *                useful a sentence as its opposite, and a feature that only
 *                ever reports bad news teaches people to dread it.
 *  stable        measured on both sides, inside tolerance.
 *  preexisting   THE trap. The subject was already unhealthy BEFORE the
 *                change, so it is excluded from the comparison and reported
 *                as context. Not `degraded`, not `stable` — excluded.
 *  no_baseline   nothing to compare against on the before side (an interface
 *                that did not exist, a device that was not yet polled).
 *  not_measured  neither side had usable data.
 *
 * Longest value 'not_measured' = 12 → varchar(16).
 */
export const AFTERMATH_SIGNAL_OUTCOMES = [
  'degraded',
  'improved',
  'stable',
  'preexisting',
  'no_baseline',
  'not_measured',
] as const;
export type AftermathSignalOutcome = (typeof AFTERMATH_SIGNAL_OUTCOMES)[number];

/**
 * The report-level verdict. Four-valued, and `INSUFFICIENT_DATA` is not
 * `STABLE` for the same reason `INDETERMINATE` is not `PASS` in M7: a device
 * nobody polls has not been proven healthy, it has not been looked at.
 *
 * Longest value 'INSUFFICIENT_DATA' = 17 → varchar(20).
 */
export const AFTERMATH_VERDICTS = [
  'STABLE',
  'DEGRADED',
  'IMPROVED',
  'INSUFFICIENT_DATA',
] as const;
export type AftermathVerdict = (typeof AFTERMATH_VERDICTS)[number];

/**
 * Every threshold F4 uses, frozen in one object.
 *
 * NONE of them is an absolute statement about a fleet: like the health gate,
 * every rule below is a comparison of a device against ITSELF a week earlier.
 * §5.0.3 — nothing in this project has ever talked to a real equipment, so an
 * absolute threshold would be a number somebody made up.
 */
export const AFTERMATH_TUNING = Object.freeze({
  /** §10/F4: "une semaine après". Configurable per call. */
  horizonDaysDefault: 7,
  horizonDaysMin: 1,
  horizonDaysMax: 90,
  /**
   * Hourly buckets required on EACH side before a metric is comparable. One
   * full day. Below it the comparison is a quiet Sunday against a Monday
   * morning, which is the `RTT_BASELINE_INSUFFICIENT` lesson of M7.
   */
  minBucketsPerSide: 24,
  /**
   * Errors per hour under which an interface counts as CLEAN. Not zero: a
   * single frame lost in a week would otherwise make an interface
   * "preexisting" and exclude it from the comparison for ever, which is a
   * false NEGATIVE — the direction that hurts most here.
   */
  errorRateCleanPerHour: 1,
  /**
   * Error rate that must be exceeded, as a multiple of the baseline rate, for
   * an interface to read as degraded. §10/F4's own example is ×40; ×5 catches
   * it with room to spare and stays clear of ordinary weekly variation.
   */
  errorRegressionFactor: 5,
  /** Same factor and floor as `RTT_REGRESSION_FACTOR` / `RTT_REGRESSION_FLOOR_US`
   *  in `shared/src/rollout.ts`. One discipline, two horizons. */
  rttRegressionFactor: 2.0,
  rttRegressionFloorUs: 5_000,
  /** A device already answering fewer than 98 % of its polls was ALREADY
   *  flapping; it is excluded, not accused. */
  availabilityHealthyFloor: 0.98,
  /** Five points of availability lost is a degradation. */
  availabilityDropPoints: 0.05,
  /** A link already above 70 % of its line rate was already saturated. */
  saturationHealthyCeiling: 0.7,
  /** Fifteen points of utilisation gained is a degradation. */
  saturationRisePoints: 0.15,
  /** A device that ALREADY rebooted during the baseline week reboots for
   *  reasons that predate the change: excluded. */
  rebootBaselineTolerance: 0,
  /** Symmetric with `errorRegressionFactor`: five times better is `improved`. */
  improvementFactor: 5,
});

/** One measured quantity, with the two numbers that produced its outcome. */
export interface AftermathSignal {
  metric: AftermathMetric;
  /** Interface name for per-interface metrics, `null` for device-level ones. */
  subject: string | null;
  outcome: AftermathSignalOutcome;
  /** The baseline value, in the metric's own unit. `null` when unmeasured. */
  before: number | null;
  after: number | null;
  /** after / before when both are positive numbers, else `null`. */
  ratio: number | null;
  /** Operator-facing sentence. Correlational by construction — see
   *  `assertCorrelationalWording`. */
  message: string;
}

export interface AftermathWindows {
  changeAt: string;
  horizonDays: number;
  baselineFrom: string;
  baselineTo: string;
  afterFrom: string;
  afterTo: string;
}

export interface AftermathReport {
  id: string | null;
  tenantId: number;
  deviceId: number;
  deviceName: string | null;
  jobId: string | null;
  interventionId: string | null;
  windows: AftermathWindows;
  verdict: AftermathVerdict;
  signals: AftermathSignal[];
  degradedCount: number;
  improvedCount: number;
  /** How many subjects were EXCLUDED because they were already unhealthy. The
   *  number the screen must show next to the verdict: "four interfaces were
   *  already erroring before this change and were left out". */
  preexistingCount: number;
  /** How many signals were actually comparable. Zero → INSUFFICIENT_DATA. */
  measuredCount: number;
  brand: string | null;
  model: string | null;
  osVersion: string | null;
  evaluatedAt: string;
}

/**
 * Fold signal outcomes into one verdict. Severity, never majority — the same
 * rule as `healthGateVerdictFrom` and `guardVerdictFrom`.
 *
 * `preexisting`, `no_baseline` and `not_measured` are NOT evidence of health:
 * a report made only of those is `INSUFFICIENT_DATA`. That is the whole
 * difference between "this change looks fine" and "we could not look".
 */
export function aftermathVerdictFrom(
  outcomes: readonly AftermathSignalOutcome[],
): AftermathVerdict {
  let comparable = 0;
  let improved = 0;
  for (const o of outcomes) {
    if (o === 'degraded') return 'DEGRADED';
    if (o === 'improved') {
      comparable += 1;
      improved += 1;
    } else if (o === 'stable') {
      comparable += 1;
    }
  }
  if (comparable === 0) return 'INSUFFICIENT_DATA';
  return improved > 0 ? 'IMPROVED' : 'STABLE';
}

// ── Trap 2, enforced ────────────────────────────────────────────────────────

/** The words F4 is allowed to use about the relationship it found. */
export const AFTERMATH_CORRELATION_PHRASE = 'since this change';

/**
 * Words that assert causation. English and French, because the screens are
 * French and the code is English and the mistake is available in both.
 *
 * `blamed`/`blame` are in the list even though no message would plausibly use
 * them: the pattern is a fence, and a fence with a gap in it is decoration.
 */
export const CAUSAL_CLAIM_PATTERN =
  /\b(because|caused?\s+by|causes?|due\s+to|blames?|blamed|responsible\s+for|resulted\s+in|à\s+cause\s+de|provoqu|entraîn|responsable\s+de)/i;

/**
 * Refuse a sentence that claims causation.
 *
 * NOT a lint rule and NOT a comment: `aftermath.service.ts` runs every message
 * it builds through this function, and the acceptance test proves it throws.
 * The reason it is worth a runtime guard is in §10/F4 — a product that accuses
 * a healthy change teaches its users to ignore its alerts, and the accusation
 * enters the product through a sentence somebody wrote in a hurry.
 */
export function assertCorrelationalWording(message: string): void {
  if (CAUSAL_CLAIM_PATTERN.test(message)) {
    throw new Error(
      'F4 refuses a causal claim: a correlation over a seven-day window cannot ' +
        `establish causation. Say "${AFTERMATH_CORRELATION_PHRASE}", not "because of it". ` +
        `Offending text: ${JSON.stringify(message.slice(0, 160))}`,
    );
  }
}

/** True when a report is worth putting in front of a human. */
export function aftermathNeedsAttention(v: AftermathVerdict): boolean {
  return v === 'DEGRADED';
}
