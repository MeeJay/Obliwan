// ============================================================================
// ObliWAN — F4: the change → telemetry correlation, one week later
// ============================================================================
//
// §10/F4: "Les portes de santé de K3 mesurent PENDANT la vague, sur une fenêtre
// de soak de cinq minutes. Rien ne regarde huit jours plus tard, alors que les
// séries SNMP sont juste à côté."
//
// This file is the missing half of the health gate. Same discipline, same two
// traps, a thousand times the horizon.
//
// ┌─ TRAP 1 — THE BASELINE PRECEDES THE CHANGE, AND A DEVICE ALREADY BROKEN ──┐
// │ BEFORE IT MUST NOT MAKE IT LOOK GUILTY.                                   │
// │                                                                           │
// │ `services/change/healthGate.ts` solved exactly this for the five-minute   │
// │ window: `InterfaceBaseline.alreadyDown` / `alreadyErroring`, and the word │
// │ NEW in `NEW_IF_IN_ERRORS`. That discipline is REUSED here rather than     │
// │ reinvented — the shape is `AftermathSignalOutcome.preexisting`, which     │
// │ takes a subject OUT of the comparison instead of folding it into a        │
// │ verdict, and `preexisting_count` is stored so the screen can show how     │
// │ many subjects were excluded next to the verdict itself.                   │
// │                                                                           │
// │ The other half of trap 1 is arithmetic: the hour bucket CONTAINING the    │
// │ change belongs to neither side. Half of it is pre-change data, and        │
// │ counting it as "after" is the same error wearing a different hat.         │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ TRAP 2 — CORRELATION IS NOT CAUSATION, AND THE PRODUCT MUST SAY SO ──────┐
// │ Every sentence here says "SINCE this change". None says "because of it".  │
// │ That is not a style rule: a product that accuses a healthy change teaches │
// │ its users to ignore its alerts, and the first false accusation costs more │
// │ trust than ten correct ones buy. `assertCorrelationalWording()` runs on   │
// │ every message this file builds and throws on a causal claim — a guard     │
// │ with a caller, not a comment.                                             │
// │                                                                           │
// │ The verdict vocabulary carries the same care: `DEGRADED` means "these     │
// │ numbers are worse than they were", `INSUFFICIENT_DATA` is never folded    │
// │ into `STABLE`, and nothing in this file ever writes the word "cause".     │
// └───────────────────────────────────────────────────────────────────────────┘
//
// SHAPE: the judging half is PURE (`judgeAftermath`) and the reading half is a
// set of narrow queries — the same split as the health gate, for the same
// reason: it lets the acceptance test prove the arithmetic without inventing a
// fleet, and prove the queries without re-implementing the arithmetic.
//
// WHERE THE RESULT GOES: `change_aftermath`, next to `apply_outcomes` and part
// of the same §8.3 corpus (migration 020, decision 6). No foreign keys, the
// four hardware dimensions copied in, and `tenant_id` filtered by every read in
// this file because it is the only isolation such a table has.
//
// SECRETS (§8.2 / R10): counters, timestamps and interface names. Nothing here
// can carry a credential or a configuration body.

import type { Knex } from 'knex';
import {
  AFTERMATH_CORRELATION_PHRASE,
  AFTERMATH_TUNING,
  aftermathNeedsAttention,
  aftermathVerdictFrom,
  assertCorrelationalWording,
  type AftermathMetric,
  type AftermathReport,
  type AftermathSignal,
  type AftermathSignalOutcome,
  type AftermathVerdict,
} from '@obliwan/shared/dist/intervention';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { AppError } from '../../middleware/errorHandler';

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

/** How many interfaces one report will look at. A CCR with 200 VLANs would
 *  otherwise produce a 400-signal jsonb nobody reads; the busiest ports come
 *  first because the list is ordered by name and, more usefully, because
 *  `preexisting_count` still counts every one of them. */
const MAX_INTERFACES = 64;

// ============================================================================
// The pure core — every rule of F4 lives here and nowhere else
// ============================================================================

export interface InterfaceMeasurement {
  ifName: string;
  /** `ifHighSpeed`×1e6. 0 = unknown, and 0 means saturation is NOT computable
   *  rather than "the link has no capacity" (study §3.4-g). */
  speedBps: number;
  bucketsBefore: number;
  bucketsAfter: number;
  errorsBefore: number;
  errorsAfter: number;
  /** max over the window of max(in_p95_bps, out_p95_bps). */
  peakBpsBefore: number;
  peakBpsAfter: number;
}

export interface DeviceMeasurement {
  /** Rollup ROWS on each side. The denominator of nothing: a row exists for an
   *  hour the poller could not reach the device at all. */
  bucketsBefore: number;
  bucketsAfter: number;
  /**
   * Buckets that actually CARRY an RTT, i.e. `rtt_p95_us >= 0`.
   *
   * `rollup.service.ts` writes `-1` for an hour with no reachable sample, and
   * the aggregate that computes `rttBeforeUs` filters those out — so counting
   * `bucketsBefore` and dividing a filtered percentile by it compared two
   * different populations. A week of WAN outage with ONE hour of return
   * produced a "baseline" of a single measurement, and the LTE failover that
   * followed read as a regression against it.
   *
   * A guard has to count the rows the metric was computed from. Same rule for
   * availability below.
   */
  rttBucketsBefore: number;
  rttBucketsAfter: number;
  /** Buckets that carry at least one poll attempt (`sample_count > 0`). */
  availBucketsBefore: number;
  availBucketsAfter: number;
  /** p95 of the hourly p95s, µs. `null` when never measured. */
  rttBeforeUs: number | null;
  rttAfterUs: number | null;
  reachableBefore: number;
  samplesBefore: number;
  reachableAfter: number;
  samplesAfter: number;
  /** Buckets whose `uptime_ticks_max` is lower than the previous bucket's. */
  rebootsBefore: number;
  rebootsAfter: number;
}

export interface AftermathMeasurements {
  device: DeviceMeasurement;
  interfaces: InterfaceMeasurement[];
}

export interface AftermathJudgement {
  signals: AftermathSignal[];
  verdict: AftermathVerdict;
  degradedCount: number;
  improvedCount: number;
  preexistingCount: number;
  measuredCount: number;
}

/**
 * Build one operator-facing sentence, and refuse it if it claims causation.
 *
 * THE caller of `assertCorrelationalWording`. Every message in this file goes
 * through here; there is no second path that builds a signal.
 */
function say(text: string): string {
  assertCorrelationalWording(text);
  return text;
}

function signal(
  metric: AftermathMetric,
  subject: string | null,
  outcome: AftermathSignalOutcome,
  before: number | null,
  after: number | null,
  message: string,
): AftermathSignal {
  const said = say(message);
  // Refusing a causal claim is only half of trap 2. The other half is that a
  // sentence which STATES a change in the numbers has to name the frame it is
  // stating it in: "ether1 is taking 40 errors an hour" reads as a fact about
  // the change, "…since this change" reads as what it is. So the two outcomes
  // that make a claim must carry the phrase, and it is checked here rather
  // than left to whoever writes the next metric at 2 a.m.
  if (
    (outcome === 'degraded' || outcome === 'improved') &&
    !said.toLowerCase().includes(AFTERMATH_CORRELATION_PHRASE)
  ) {
    throw new Error(
      `F4 refuses a ${outcome} signal that does not say "${AFTERMATH_CORRELATION_PHRASE}": ` +
        'a statement about the numbers without the window it was measured over reads as a ' +
        `statement about the change. Offending text: ${JSON.stringify(said.slice(0, 160))}`,
    );
  }
  const ratio =
    before !== null && after !== null && before > 0 ? Math.round((after / before) * 100) / 100 : null;
  return { metric, subject, outcome, before, after, ratio, message: said };
}

function round(n: number, digits = 2): number {
  const f = 10 ** digits;
  return Math.round(n * f) / f;
}

/**
 * Interface errors — the signal §10/F4 names explicitly ("les erreurs WAN de ce
 * site ont été multipliées par 40").
 *
 * Measured as a RATE per hour and not as a total, because the two windows are
 * never exactly the same length: a seven-day baseline against a five-day
 * observation compared on totals would report a 30 % improvement on a link
 * that did not move.
 */
function judgeInterfaceErrors(i: InterfaceMeasurement): AftermathSignal {
  const t = AFTERMATH_TUNING;
  if (i.bucketsBefore < t.minBucketsPerSide) {
    return signal(
      'if_errors',
      i.ifName,
      'no_baseline',
      null,
      null,
      `${i.ifName} has only ${i.bucketsBefore} hour(s) of error history before this change ` +
        `(minimum ${t.minBucketsPerSide}). There is nothing to compare against, so this ` +
        'interface is reported and not judged.',
    );
  }
  if (i.bucketsAfter < t.minBucketsPerSide) {
    return signal(
      'if_errors',
      i.ifName,
      'not_measured',
      null,
      null,
      `${i.ifName} has only ${i.bucketsAfter} hour(s) of telemetry since this change ` +
        `(minimum ${t.minBucketsPerSide}). Too early to say anything.`,
    );
  }

  const before = round(i.errorsBefore / i.bucketsBefore, 3);
  const after = round(i.errorsAfter / i.bucketsAfter, 3);

  // TRAP 1. An interface that was ALREADY dropping frames is excluded from the
  // accusation entirely — the `alreadyErroring` flag of the health gate, at a
  // seven-day horizon. It can still be reported as IMPROVED, because "since
  // this change that link stopped erroring" is a true and useful sentence.
  if (before >= t.errorRateCleanPerHour) {
    if (after * t.improvementFactor < before) {
      return signal(
        'if_errors',
        i.ifName,
        'improved',
        before,
        after,
        `${i.ifName} was already erroring before this change (${before}/h) and has been ` +
          `quieter since this change (${after}/h).`,
      );
    }
    return signal(
      'if_errors',
      i.ifName,
      'preexisting',
      before,
      after,
      `${i.ifName} was ALREADY erroring before this change (${before}/h, now ${after}/h). ` +
        'It is excluded from the comparison: a fault that predates a change is not evidence ' +
        'against it.',
    );
  }

  const ceiling = Math.max(t.errorRateCleanPerHour, before * t.errorRegressionFactor);
  if (after > ceiling) {
    return signal(
      'if_errors',
      i.ifName,
      'degraded',
      before,
      after,
      `${i.ifName} was clean before this change (${before} error/h) and has been taking ` +
        `${after} error/h since this change.`,
    );
  }
  return signal(
    'if_errors',
    i.ifName,
    'stable',
    before,
    after,
    `${i.ifName}: ${before} error/h before, ${after} error/h since this change.`,
  );
}

/**
 * Saturation — utilisation against the line rate, and the crossing matters.
 *
 * A link going from 5 % to 20 % gained fifteen points and is not saturated;
 * reporting it would train an operator to ignore this metric. The rule is a
 * rise AND a crossing of the healthy ceiling.
 */
function judgeSaturation(i: InterfaceMeasurement): AftermathSignal {
  const t = AFTERMATH_TUNING;
  if (i.speedBps <= 0) {
    return signal(
      'saturation',
      i.ifName,
      'not_measured',
      null,
      null,
      `${i.ifName} reports no line speed (ifHighSpeed = 0), so utilisation is not computable ` +
        'on it. Guessing a capacity would make every number below fiction.',
    );
  }
  if (i.bucketsBefore < t.minBucketsPerSide) {
    return signal('saturation', i.ifName, 'no_baseline', null, null,
      `${i.ifName} has too little throughput history before this change to compare against.`);
  }
  if (i.bucketsAfter < t.minBucketsPerSide) {
    return signal('saturation', i.ifName, 'not_measured', null, null,
      `${i.ifName} has too little throughput history since this change to compare.`);
  }

  const before = round(i.peakBpsBefore / i.speedBps, 3);
  const after = round(i.peakBpsAfter / i.speedBps, 3);

  if (before >= t.saturationHealthyCeiling) {
    if (after <= before - t.saturationRisePoints) {
      return signal('saturation', i.ifName, 'improved', before, after,
        `${i.ifName} was already running at ${Math.round(before * 100)} % of its line rate ` +
          `before, and at ${Math.round(after * 100)} % since this change.`);
    }
    return signal('saturation', i.ifName, 'preexisting', before, after,
      `${i.ifName} was ALREADY saturated before this change (${Math.round(before * 100)} % of ` +
        `line rate, now ${Math.round(after * 100)} %). Excluded from the comparison.`);
  }
  if (after >= before + t.saturationRisePoints && after >= t.saturationHealthyCeiling) {
    return signal('saturation', i.ifName, 'degraded', before, after,
      `${i.ifName} has gone from ${Math.round(before * 100)} % to ${Math.round(after * 100)} % ` +
        'of its line rate since this change, crossing the saturation threshold.');
  }
  return signal('saturation', i.ifName, 'stable', before, after,
    `${i.ifName}: ${Math.round(before * 100)} % of line rate before, ` +
      `${Math.round(after * 100)} % since this change.`);
}

function judgeRtt(d: DeviceMeasurement): AftermathSignal {
  const t = AFTERMATH_TUNING;
  // `rttBuckets*`, never `buckets*`: an hour the device was unreachable is a
  // rollup row with `rtt_p95_us = -1`, which contributes to one and not to the
  // other. Testing the wrong one is how 167 unreachable hours out of 168 became
  // a baseline of one measurement.
  if (d.rttBucketsBefore < t.minBucketsPerSide || d.rttBeforeUs === null) {
    return signal('rtt', null, 'no_baseline', null, null,
      `Only ${d.rttBucketsBefore} of the ${d.bucketsBefore} hourly buckets before this ` +
        `change carry an RTT at all (minimum ${t.minBucketsPerSide}). Comparing against ` +
        'half a day of data turns a quiet Sunday into a regression.');
  }
  if (d.rttBucketsAfter < t.minBucketsPerSide || d.rttAfterUs === null) {
    return signal('rtt', null, 'not_measured', d.rttBeforeUs, null,
      `Only ${d.rttBucketsAfter} of the ${d.bucketsAfter} hourly buckets since this change ` +
        `carry an RTT (minimum ${t.minBucketsPerSide}). Too early to compare.`);
  }
  const ceiling = Math.max(t.rttRegressionFloorUs, Math.round(d.rttBeforeUs * t.rttRegressionFactor));
  if (d.rttAfterUs > ceiling) {
    return signal('rtt', null, 'degraded', d.rttBeforeUs, d.rttAfterUs,
      `RTT p95 is ${d.rttAfterUs} µs since this change, against ${d.rttBeforeUs} µs before it ` +
        `(tolerance ×${t.rttRegressionFactor}, floor ${t.rttRegressionFloorUs} µs).`);
  }
  if (
    d.rttBeforeUs > t.rttRegressionFloorUs &&
    d.rttAfterUs * t.rttRegressionFactor < d.rttBeforeUs
  ) {
    return signal('rtt', null, 'improved', d.rttBeforeUs, d.rttAfterUs,
      `RTT p95 is ${d.rttAfterUs} µs since this change, against ${d.rttBeforeUs} µs before it.`);
  }
  return signal('rtt', null, 'stable', d.rttBeforeUs, d.rttAfterUs,
    `RTT p95: ${d.rttBeforeUs} µs before, ${d.rttAfterUs} µs since this change.`);
}

function judgeAvailability(d: DeviceMeasurement): AftermathSignal {
  const t = AFTERMATH_TUNING;
  // `samplesBefore > 0` was the entire guard on the denominator: ONE poll in a
  // week satisfied it. What has to be counted is how many hourly buckets were
  // polled at all.
  if (d.availBucketsBefore < t.minBucketsPerSide || d.samplesBefore === 0) {
    return signal('availability', null, 'no_baseline', null, null,
      `This device was polled during ${d.availBucketsBefore} of the ${d.bucketsBefore} ` +
        'hours before this change — not long enough for its availability to mean anything.');
  }
  if (d.availBucketsAfter < t.minBucketsPerSide || d.samplesAfter === 0) {
    return signal('availability', null, 'not_measured', null, null,
      'Not enough polling has happened since this change to compare availability.');
  }
  const before = round(d.reachableBefore / d.samplesBefore, 4);
  const after = round(d.reachableAfter / d.samplesAfter, 4);

  // TRAP 1 again: a box that was already flapping is not made guilty by a
  // change that landed in the middle of its flapping.
  if (before < t.availabilityHealthyFloor) {
    if (after >= before + t.availabilityDropPoints) {
      return signal('availability', null, 'improved', before, after,
        `This device answered ${Math.round(before * 100)} % of its polls before this change ` +
          `and ${Math.round(after * 100)} % since this change.`);
    }
    return signal('availability', null, 'preexisting', before, after,
      `This device was ALREADY missing polls before this change (${Math.round(before * 100)} % ` +
        `reachable, now ${Math.round(after * 100)} %). Excluded from the comparison.`);
  }
  if (after < before - t.availabilityDropPoints) {
    return signal('availability', null, 'degraded', before, after,
      `This device answered ${Math.round(before * 100)} % of its polls before this change and ` +
        `${Math.round(after * 100)} % since this change.`);
  }
  return signal('availability', null, 'stable', before, after,
    `Availability: ${Math.round(before * 100)} % before, ${Math.round(after * 100)} % since ` +
      'this change.');
}

function judgeReboots(d: DeviceMeasurement): AftermathSignal {
  const t = AFTERMATH_TUNING;
  if (d.bucketsBefore < t.minBucketsPerSide) {
    return signal('unexpected_reboots', null, 'no_baseline', null, null,
      'Not enough uptime history before this change to know whether this device was already ' +
        'restarting on its own.');
  }
  if (d.bucketsAfter < t.minBucketsPerSide) {
    return signal('unexpected_reboots', null, 'not_measured', null, null,
      'Not enough uptime history since this change to count restarts.');
  }
  if (d.rebootsBefore > t.rebootBaselineTolerance) {
    if (d.rebootsAfter === 0) {
      return signal('unexpected_reboots', null, 'improved', d.rebootsBefore, d.rebootsAfter,
        `This device restarted ${d.rebootsBefore} time(s) before, and none since this change.`);
    }
    return signal('unexpected_reboots', null, 'preexisting', d.rebootsBefore, d.rebootsAfter,
      `This device was ALREADY restarting before this change (${d.rebootsBefore} time(s), ` +
        `${d.rebootsAfter} since). Excluded from the comparison.`);
  }
  if (d.rebootsAfter > 0) {
    return signal('unexpected_reboots', null, 'degraded', 0, d.rebootsAfter,
      `sysUpTime has gone backwards ${d.rebootsAfter} time(s) since this change; it never did ` +
        'during the baseline window.');
  }
  return signal('unexpected_reboots', null, 'stable', 0, 0,
    'No unexpected restart before or since this change.');
}

/**
 * The whole verdict, from measurements to signals to one word. PURE.
 *
 * The verdict is DERIVED from the outcomes through the shared fold, never
 * decided a second time here: collecting reasons and then setting a verdict
 * separately is how a DEGRADED ends up displayed next to a green tick
 * (`healthGateVerdictFrom`, same rule).
 */
export function judgeAftermath(m: AftermathMeasurements): AftermathJudgement {
  const signals: AftermathSignal[] = [
    judgeRtt(m.device),
    judgeAvailability(m.device),
    judgeReboots(m.device),
  ];
  for (const i of m.interfaces) {
    signals.push(judgeInterfaceErrors(i));
    signals.push(judgeSaturation(i));
  }

  const outcomes = signals.map((s) => s.outcome);
  return {
    signals,
    verdict: aftermathVerdictFrom(outcomes),
    degradedCount: outcomes.filter((o) => o === 'degraded').length,
    improvedCount: outcomes.filter((o) => o === 'improved').length,
    preexistingCount: outcomes.filter((o) => o === 'preexisting').length,
    measuredCount: outcomes.filter((o) => o === 'degraded' || o === 'improved' || o === 'stable')
      .length,
  };
}

// ============================================================================
// Reading — the hourly rollups, on both sides of the pivot
// ============================================================================

export interface AftermathWindowBounds {
  changeAt: Date;
  baselineFrom: Date;
  baselineTo: Date;
  afterFrom: Date;
  afterTo: Date;
  horizonDays: number;
}

/**
 * The two windows, around a piece of work that HAS A DURATION.
 *
 * ┌─ AN INTERVENTION HAS TWO PIVOTS, NOT ONE ────────────────────────────────┐
 * │ A change job is an instant. A declared intervention is up to twelve hours │
 * │ of a human at a keyboard, and computing its baseline backwards from its   │
 * │ END put the ENTIRE window of work INSIDE the baseline it is supposed to   │
 * │ precede. The reboot the technician performed at 14:00 during his own      │
 * │ 09:00-19:00 window counted as evidence that the device was ALREADY        │
 * │ restarting — so `preexisting`, the protection of F4, excluded the very    │
 * │ metric the work had disturbed. The trap-1 guard turned into an eraser.    │
 * │                                                                           │
 * │ So: `baselineTo` is the start of the hour the work BEGAN in, `afterFrom`  │
 * │ the end of the hour it FINISHED in. Everything in between is the work,    │
 * │ and belongs to neither side — which is what the comment on `resolveAnchor`│
 * │ already claimed. `change_aftermath_windows_chk` accepts this shape as it  │
 * │ stands: `baseline_to <= change_at <= after_from`.                         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * The hour bucket the work started in, and the one it ended in, are BOTH
 * excluded, for the reason trap 1 already gives: a bucket straddling the
 * boundary is half one side's data, and counting it whole is the same class of
 * error as blaming a pre-existing fault.
 */
export function windowsForInterval(
  workFrom: Date,
  workTo: Date,
  horizonDays: number,
): AftermathWindowBounds {
  const span = horizonDays * DAY_MS;
  // The baseline stops at the START of the hour the work STARTED in, and the
  // observation begins at the END of the hour it FINISHED in. Everything
  // between the two is the work itself and belongs to neither side.
  const baselineTo = new Date(Math.floor(workFrom.getTime() / HOUR_MS) * HOUR_MS);
  const afterFrom = new Date(Math.floor(workTo.getTime() / HOUR_MS) * HOUR_MS + HOUR_MS);
  return {
    changeAt: workTo,
    baselineFrom: new Date(baselineTo.getTime() - span),
    baselineTo,
    afterFrom,
    afterTo: new Date(afterFrom.getTime() + span),
    horizonDays,
  };
}

/**
 * The degenerate case: an instantaneous change, where the work has no duration
 * worth excluding. `windowsForInterval(t, t, h)` — identical arithmetic, stated
 * once.
 */
export function windowsFor(changeAt: Date, horizonDays: number): AftermathWindowBounds {
  return windowsForInterval(changeAt, changeAt, horizonDays);
}

async function readDeviceSide(
  tenantId: number,
  deviceId: number,
  from: Date,
  to: Date,
  q: Knex | Knex.Transaction,
): Promise<{
  buckets: number;
  rttBuckets: number;
  availBuckets: number;
  rttUs: number | null;
  reachable: number;
  samples: number;
  reboots: number;
}> {
  const agg = (await q('snmp_device_rollup_1h as r')
    // `snmp_device_rollup_1h` has no tenant column: the join on `devices` IS
    // the isolation, exactly as in M3 and M7. Removing it is a cross-tenant
    // disclosure, not a refactor.
    .join('devices as d', 'd.id', 'r.device_id')
    .where('d.tenant_id', tenantId)
    .andWhere('r.device_id', deviceId)
    .andWhere('r.bucket', '>=', from)
    .andWhere('r.bucket', '<', to)
    .select(
      q.raw('count(*)::int as n'),
      // COUNTED WITH THE SAME FILTER THE VALUE IS COMPUTED WITH. `-1` is the
      // sentinel `rollup.service.ts` writes for an hour with no reachable
      // sample: a bucket carrying it is a row, not a measurement, and a guard
      // that counts rows guards nothing.
      q.raw('count(*) filter (where r.rtt_p95_us >= 0)::int as rtt_n'),
      q.raw('count(*) filter (where r.sample_count > 0)::int as avail_n'),
      q.raw(
        'percentile_cont(0.95) within group (order by r.rtt_p95_us) ' +
          'filter (where r.rtt_p95_us >= 0) as rtt',
      ),
      q.raw('coalesce(sum(r.reachable_count), 0)::bigint as reachable'),
      q.raw('coalesce(sum(r.sample_count), 0)::bigint as samples'),
    )
    .first()) as
    | {
        n: number;
        rtt_n: number;
        avail_n: number;
        rtt: string | number | null;
        reachable: string;
        samples: string;
      }
    | undefined;

  // sysUpTime going backwards between two consecutive hourly buckets. Done in
  // SQL with `lag()` because pulling a week of buckets into Node to subtract
  // them pairwise is the same computation, moved somewhere slower.
  const rebootRow = (await q
    .select<{ n: number }>(q.raw('count(*)::int as n'))
    .from(
      q
        .select(
          'r.uptime_ticks_max as u',
          q.raw('lag(r.uptime_ticks_max) over (order by r.bucket) as prev'),
        )
        .from('snmp_device_rollup_1h as r')
        .join('devices as d', 'd.id', 'r.device_id')
        .where('d.tenant_id', tenantId)
        .andWhere('r.device_id', deviceId)
        .andWhere('r.bucket', '>=', from)
        .andWhere('r.bucket', '<', to)
        .as('t'),
    )
    .whereRaw('t.prev is not null and t.u < t.prev')
    .first()) as { n: number } | undefined;

  return {
    buckets: Number(agg?.n ?? 0),
    rttBuckets: Number(agg?.rtt_n ?? 0),
    availBuckets: Number(agg?.avail_n ?? 0),
    rttUs: agg?.rtt === null || agg?.rtt === undefined ? null : Math.round(Number(agg.rtt)),
    reachable: Number(agg?.reachable ?? 0),
    samples: Number(agg?.samples ?? 0),
    reboots: Number(rebootRow?.n ?? 0),
  };
}

async function readInterfaceSide(
  tenantId: number,
  deviceId: number,
  ifIds: readonly number[],
  from: Date,
  to: Date,
  q: Knex | Knex.Transaction,
): Promise<Map<number, { buckets: number; errors: number; peakBps: number }>> {
  const out = new Map<number, { buckets: number; errors: number; peakBps: number }>();
  if (ifIds.length === 0) return out;
  const rows = (await q('snmp_if_rollup_1h as r')
    .join('snmp_interfaces as i', 'i.id', 'r.if_id')
    .join('devices as d', 'd.id', 'i.device_id')
    .where('d.tenant_id', tenantId)
    .andWhere('i.device_id', deviceId)
    .whereIn('r.if_id', ifIds as number[])
    .andWhere('r.bucket', '>=', from)
    .andWhere('r.bucket', '<', to)
    .groupBy('r.if_id')
    .select(
      'r.if_id',
      q.raw('count(*)::int as buckets'),
      q.raw('coalesce(sum(r.in_errs + r.out_errs), 0)::bigint as errors'),
      q.raw('coalesce(max(greatest(r.in_p95_bps, r.out_p95_bps)), 0)::bigint as peak'),
    )) as Array<{ if_id: number; buckets: number; errors: string; peak: string }>;
  for (const r of rows) {
    out.set(Number(r.if_id), {
      buckets: Number(r.buckets),
      errors: Number(r.errors),
      peakBps: Number(r.peak),
    });
  }
  return out;
}

/**
 * Collect both sides for one device.
 *
 * The interface set is read ONCE and the same `if_id`s are used on both sides:
 * an interface that appeared after the change has no baseline and would be
 * compared against zero, which reads as "clean before, erroring since" on a
 * port that simply did not exist. `needs_rediscovery` interfaces are excluded
 * for R12's reason — their counters are not comparable across the change.
 */
export async function measure(
  tenantId: number,
  deviceId: number,
  w: AftermathWindowBounds,
  q: Knex | Knex.Transaction = db,
): Promise<AftermathMeasurements> {
  const ifaces = (await q('snmp_interfaces as i')
    .join('devices as d', 'd.id', 'i.device_id')
    .where('d.tenant_id', tenantId)
    .andWhere('i.device_id', deviceId)
    .andWhere('i.state', 'active')
    .andWhere('i.monitored', true)
    .andWhere('i.needs_rediscovery', false)
    .orderBy('i.if_name')
    .limit(MAX_INTERFACES)
    .select('i.id', 'i.if_name', 'i.speed_bps')) as Array<{
    id: number;
    if_name: string;
    speed_bps: string | number;
  }>;
  const ifIds = ifaces.map((i) => Number(i.id));

  const [before, after, ifBefore, ifAfter] = await Promise.all([
    readDeviceSide(tenantId, deviceId, w.baselineFrom, w.baselineTo, q),
    readDeviceSide(tenantId, deviceId, w.afterFrom, w.afterTo, q),
    readInterfaceSide(tenantId, deviceId, ifIds, w.baselineFrom, w.baselineTo, q),
    readInterfaceSide(tenantId, deviceId, ifIds, w.afterFrom, w.afterTo, q),
  ]);

  return {
    device: {
      bucketsBefore: before.buckets,
      bucketsAfter: after.buckets,
      rttBucketsBefore: before.rttBuckets,
      rttBucketsAfter: after.rttBuckets,
      availBucketsBefore: before.availBuckets,
      availBucketsAfter: after.availBuckets,
      rttBeforeUs: before.rttUs,
      rttAfterUs: after.rttUs,
      reachableBefore: before.reachable,
      samplesBefore: before.samples,
      reachableAfter: after.reachable,
      samplesAfter: after.samples,
      rebootsBefore: before.reboots,
      rebootsAfter: after.reboots,
    },
    interfaces: ifaces.map((i) => {
      const b = ifBefore.get(Number(i.id));
      const a = ifAfter.get(Number(i.id));
      return {
        ifName: i.if_name,
        speedBps: Number(i.speed_bps),
        bucketsBefore: b?.buckets ?? 0,
        bucketsAfter: a?.buckets ?? 0,
        errorsBefore: b?.errors ?? 0,
        errorsAfter: a?.errors ?? 0,
        peakBpsBefore: b?.peakBps ?? 0,
        peakBpsAfter: a?.peakBps ?? 0,
      };
    }),
  };
}

// ============================================================================
// The anchors: a change job, or a declared intervention
// ============================================================================

export interface AftermathAnchor {
  jobId?: string;
  interventionId?: string;
}

interface ResolvedAnchor {
  deviceId: number;
  deviceName: string | null;
  /**
   * When the work BEGAN. Equal to `changeAt` for a change job — a push is an
   * instant on this scale — and `opened_at` for an intervention, which is the
   * whole point: the baseline must stop where the human started, not where he
   * stopped.
   */
  workFrom: Date;
  /** When the work ENDED; the row's `change_at`. */
  changeAt: Date;
  jobId: string | null;
  interventionId: string | null;
  brand: string | null;
  model: string | null;
  osVersion: string | null;
}

async function resolveAnchor(
  tenantId: number,
  anchor: AftermathAnchor,
): Promise<ResolvedAnchor> {
  if ((anchor.jobId === undefined) === (anchor.interventionId === undefined)) {
    throw new AppError(400, 'Exactly one of jobId or interventionId is required.');
  }

  if (anchor.jobId !== undefined) {
    const job = (await db('change_jobs as j')
      .join('devices as d', 'd.id', 'j.device_id')
      .where('j.tenant_id', tenantId)
      .andWhere('j.id', anchor.jobId)
      .first(
        'j.id', 'j.device_id', 'j.finished_at', 'j.started_at', 'j.status',
        'd.name as device_name', 'd.brand', 'd.model', 'd.os_version',
      )) as
      | {
          id: string;
          device_id: number;
          finished_at: Date | null;
          started_at: Date | null;
          status: string;
          device_name: string | null;
          brand: string | null;
          model: string | null;
          os_version: string | null;
        }
      | undefined;
    if (!job) throw new AppError(404, 'Change job not found');
    const changeAt = job.finished_at ?? job.started_at;
    if (!changeAt) {
      throw new AppError(
        409,
        'This job never reached the device, so there is no instant to measure around. A ' +
          'job that was refused before it started changed nothing to correlate with.',
      );
    }
    return {
      deviceId: Number(job.device_id),
      deviceName: job.device_name,
      // A push is treated as instantaneous on a seven-day scale: its own
      // execution is minutes, and K3's five-minute soak already measures it.
      workFrom: changeAt,
      changeAt,
      jobId: String(job.id),
      interventionId: null,
      brand: job.brand,
      model: job.model,
      osVersion: job.os_version,
    };
  }

  const iv = (await db('interventions as i')
    .join('devices as d', 'd.id', 'i.device_id')
    .where('i.tenant_id', tenantId)
    .andWhere('i.id', anchor.interventionId as string)
    .first(
      'i.id', 'i.device_id', 'i.status', 'i.opened_at', 'i.closed_at', 'i.expired_at',
      'i.expires_at',
      'd.name as device_name', 'd.brand', 'd.model', 'd.os_version',
    )) as
    | {
        id: string;
        device_id: number;
        status: string;
        opened_at: Date;
        closed_at: Date | null;
        expired_at: Date | null;
        expires_at: Date;
        device_name: string | null;
        brand: string | null;
        model: string | null;
        os_version: string | null;
      }
    | undefined;
  if (!iv) throw new AppError(404, 'Intervention not found');
  if (iv.status === 'open') {
    throw new AppError(409, 'This intervention is still open: the work is not finished yet.');
  }
  if (iv.status === 'cancelled') {
    throw new AppError(409, 'This intervention was cancelled and never ran.');
  }
  const workTo = iv.closed_at ?? iv.expired_at ?? iv.expires_at;
  return {
    deviceId: Number(iv.device_id),
    deviceName: iv.device_name,
    // TWO pivots. `change_at` stays the END of the human's window — that is the
    // instant the report is "since" — but the baseline stops at `opened_at`,
    // because everything inside the window is the work itself and belongs to
    // neither side. Reading the baseline back from `closed_at` put ten hours of
    // manual work INSIDE the week it was supposed to be compared against.
    //
    // `workFrom` is clamped so that a row where `opened_at` somehow sits after
    // the end cannot produce `baseline_to > change_at` and be refused by
    // `change_aftermath_windows_chk` at the very end of the evaluation.
    workFrom: iv.opened_at < workTo ? iv.opened_at : workTo,
    changeAt: workTo,
    jobId: null,
    interventionId: String(iv.id),
    brand: iv.brand,
    model: iv.model,
    osVersion: iv.os_version,
  };
}

// ============================================================================
// Evaluating and storing
// ============================================================================

export interface EvaluateOptions {
  horizonDays?: number;
  /** Store the report in `change_aftermath`. Default true — the corpus of §8.3
   *  is the point of the feature; a preview is the exception. */
  persist?: boolean;
  now?: Date;
}

interface AftermathRow {
  id: string;
  tenant_id: number;
  device_id: number;
  job_id: string | null;
  intervention_id: string | null;
  change_at: Date;
  horizon_days: number;
  baseline_from: Date;
  baseline_to: Date;
  after_from: Date;
  after_to: Date;
  verdict: string;
  signals: unknown;
  degraded_count: number;
  improved_count: number;
  preexisting_count: number;
  measured_count: number;
  brand: string | null;
  model: string | null;
  os_version: string | null;
  evaluated_at: Date;
  device_name?: string | null;
}

function toReport(r: AftermathRow): AftermathReport {
  return {
    id: String(r.id),
    tenantId: Number(r.tenant_id),
    deviceId: Number(r.device_id),
    deviceName: r.device_name ?? null,
    jobId: r.job_id === null ? null : String(r.job_id),
    interventionId: r.intervention_id === null ? null : String(r.intervention_id),
    windows: {
      changeAt: r.change_at.toISOString(),
      horizonDays: Number(r.horizon_days),
      baselineFrom: r.baseline_from.toISOString(),
      baselineTo: r.baseline_to.toISOString(),
      afterFrom: r.after_from.toISOString(),
      afterTo: r.after_to.toISOString(),
    },
    verdict: r.verdict as AftermathVerdict,
    signals: (r.signals as AftermathSignal[]) ?? [],
    degradedCount: Number(r.degraded_count),
    improvedCount: Number(r.improved_count),
    preexistingCount: Number(r.preexisting_count),
    measuredCount: Number(r.measured_count),
    brand: r.brand,
    model: r.model,
    osVersion: r.os_version,
    evaluatedAt: r.evaluated_at.toISOString(),
  };
}

/**
 * Measure one change, seven days later (or whatever horizon was asked for).
 *
 * Idempotent per (tenant, anchor, horizon): the row is updated in place rather
 * than duplicated, because "we looked twice and got different answers" is
 * information about the telemetry and not about the change, and the unique
 * indexes of migration 020 say so too.
 */
export async function evaluateAftermath(
  tenantId: number,
  anchor: AftermathAnchor,
  options: EvaluateOptions = {},
): Promise<AftermathReport> {
  const t = AFTERMATH_TUNING;
  const horizonDays = options.horizonDays ?? t.horizonDaysDefault;
  if (
    !Number.isInteger(horizonDays) ||
    horizonDays < t.horizonDaysMin ||
    horizonDays > t.horizonDaysMax
  ) {
    throw new AppError(
      400,
      `horizonDays must be an integer between ${t.horizonDaysMin} and ${t.horizonDaysMax}.`,
    );
  }

  const resolved = await resolveAnchor(tenantId, anchor);
  const windows = windowsForInterval(resolved.workFrom, resolved.changeAt, horizonDays);
  const measurements = await measure(tenantId, resolved.deviceId, windows);
  const judged = judgeAftermath(measurements);
  const evaluatedAt = options.now ?? new Date();

  const report: AftermathReport = {
    id: null,
    tenantId,
    deviceId: resolved.deviceId,
    deviceName: resolved.deviceName,
    jobId: resolved.jobId,
    interventionId: resolved.interventionId,
    windows: {
      changeAt: windows.changeAt.toISOString(),
      horizonDays,
      baselineFrom: windows.baselineFrom.toISOString(),
      baselineTo: windows.baselineTo.toISOString(),
      afterFrom: windows.afterFrom.toISOString(),
      afterTo: windows.afterTo.toISOString(),
    },
    verdict: judged.verdict,
    signals: judged.signals,
    degradedCount: judged.degradedCount,
    improvedCount: judged.improvedCount,
    preexistingCount: judged.preexistingCount,
    measuredCount: judged.measuredCount,
    brand: resolved.brand,
    model: resolved.model,
    osVersion: resolved.osVersion,
    evaluatedAt: evaluatedAt.toISOString(),
  };

  if (options.persist === false) return report;

  // ┌─ A MEASUREMENT WHOSE WINDOW IS STILL OPEN IS NOT A RESULT ──────────────┐
  // │ `persist` defaults to true, and nothing else here required the          │
  // │ observation window to be over: `afterTo` is simply `afterFrom + horizon`│
  // │ and may well be in the future. An operator calling                      │
  // │ `POST /aftermath/evaluate` an hour after a push therefore wrote an      │
  // │ INSUFFICIENT_DATA row — and `sweepAftermath`'s anti-join then skipped   │
  // │ that job for ever, so "nothing looks eight days later" became true      │
  // │ again for the one change somebody cared enough about to look at early.  │
  // │                                                                          │
  // │ The report is still RETURNED, in full: looking early is legitimate. It  │
  // │ is only forbidden to enter the §8.3 corpus, where a row means "this      │
  // │ horizon was observed to its end".                                        │
  // └──────────────────────────────────────────────────────────────────────────┘
  if (windows.afterTo.getTime() > evaluatedAt.getTime()) {
    logger.info(
      {
        tenantId,
        deviceId: resolved.deviceId,
        jobId: resolved.jobId,
        interventionId: resolved.interventionId,
        afterTo: windows.afterTo.toISOString(),
      },
      'Aftermath evaluated before its observation window closed — returned, not stored: a ' +
        'partial horizon must not become the stored answer for the full one',
    );
    return report;
  }

  const row = {
    tenant_id: tenantId,
    device_id: resolved.deviceId,
    job_id: resolved.jobId,
    intervention_id: resolved.interventionId,
    change_at: windows.changeAt,
    horizon_days: horizonDays,
    baseline_from: windows.baselineFrom,
    baseline_to: windows.baselineTo,
    after_from: windows.afterFrom,
    after_to: windows.afterTo,
    verdict: judged.verdict,
    signals: JSON.stringify(judged.signals),
    degraded_count: judged.degradedCount,
    improved_count: judged.improvedCount,
    preexisting_count: judged.preexistingCount,
    measured_count: judged.measuredCount,
    brand: resolved.brand,
    model: resolved.model,
    os_version: resolved.osVersion,
    evaluated_at: evaluatedAt,
  };

  // Explicit read-then-write rather than `onConflict().merge()`: the two
  // uniqueness rules are PARTIAL indexes (one scope column is always NULL),
  // and PostgreSQL only infers a partial index when the statement repeats its
  // predicate — which knex's `onConflict` cannot express. A lookup on the same
  // index is one indexed read, and it keeps the SQL honest.
  const existing = (await db('change_aftermath')
    .where({ tenant_id: tenantId, horizon_days: horizonDays })
    .modify((qb) => {
      if (resolved.jobId !== null) void qb.andWhere('job_id', resolved.jobId);
      else void qb.andWhere('intervention_id', resolved.interventionId as string);
    })
    .first('id')) as { id: string } | undefined;

  let id: string;
  if (existing) {
    await db('change_aftermath').where('id', existing.id).update(row);
    id = String(existing.id);
  } else {
    const [inserted] = await db('change_aftermath')
      .insert(row)
      .returning<{ id: string }[]>('id');
    id = String(inserted.id);
  }

  if (aftermathNeedsAttention(judged.verdict)) {
    logger.warn(
      {
        tenantId,
        deviceId: resolved.deviceId,
        jobId: resolved.jobId,
        interventionId: resolved.interventionId,
        degraded: judged.degradedCount,
        preexisting: judged.preexistingCount,
      },
      'Telemetry has been worse since this change — a correlation over the horizon window, ' +
        'not a demonstration that the change is at fault',
    );
  }

  return { ...report, id };
}

export interface AftermathSweepOutcome {
  considered: number;
  evaluated: number;
  degraded: number;
  insufficient: number;
}

/**
 * Evaluate every change job old enough to have a full observation window and
 * not yet evaluated at this horizon.
 *
 * THE engine of §10/F4 — "rien ne regarde huit jours plus tard" is answered by
 * this function running on a timer, and by `POST /aftermath/sweep` for the
 * instance where nobody wired a timer up.
 *
 * A job is a candidate once `finished_at` is older than the horizon PLUS one
 * hour: the extra hour is the bucket containing the change, which belongs to
 * neither window and would otherwise make the last observation hour missing.
 */
export async function sweepAftermath(
  tenantId: number,
  options: { horizonDays?: number; limit?: number; now?: Date } = {},
): Promise<AftermathSweepOutcome> {
  const horizonDays = options.horizonDays ?? AFTERMATH_TUNING.horizonDaysDefault;
  const now = options.now ?? new Date();
  const limit = Math.min(options.limit ?? 50, 500);
  const cutoff = new Date(now.getTime() - horizonDays * DAY_MS - HOUR_MS);

  const rows = (await db('change_jobs as j')
    .leftJoin('change_aftermath as a', function joinAftermath() {
      this.on('a.job_id', '=', 'j.id')
        .andOn('a.tenant_id', '=', db.raw('?', [tenantId]))
        .andOn('a.horizon_days', '=', db.raw('?', [horizonDays]));
    })
    .where('j.tenant_id', tenantId)
    .whereNotNull('j.finished_at')
    .andWhere('j.finished_at', '<=', cutoff)
    // NOT simply "no row yet". A row written before its own observation window
    // closed — every such row predates the refusal in `evaluateAftermath`, and
    // a direct writer could still produce one — is a measurement of a partial
    // horizon wearing the label of a full one. It has to be RECOMPUTED, not
    // treated as an answer, and `a.after_to > a.evaluated_at` is exactly the
    // "we looked before the window was over" predicate. Once recomputed after
    // the window closed, `evaluated_at >= after_to` and the row stops matching,
    // so this does not make the sweep re-evaluate the world on every tick.
    .where((qb) => {
      void qb.whereNull('a.id').orWhereRaw('a.after_to > a.evaluated_at');
    })
    .orderBy('j.finished_at', 'desc')
    .limit(limit)
    .select('j.id')) as Array<{ id: string }>;

  const outcome: AftermathSweepOutcome = {
    considered: rows.length,
    evaluated: 0,
    degraded: 0,
    insufficient: 0,
  };
  for (const r of rows) {
    try {
      const report = await evaluateAftermath(tenantId, { jobId: String(r.id) }, {
        horizonDays,
        now,
      });
      outcome.evaluated += 1;
      if (report.verdict === 'DEGRADED') outcome.degraded += 1;
      if (report.verdict === 'INSUFFICIENT_DATA') outcome.insufficient += 1;
    } catch (err) {
      logger.error({ err, jobId: r.id, tenantId }, 'Aftermath evaluation failed for change job');
    }
  }
  return outcome;
}

// ============================================================================
// Reading back
// ============================================================================

export interface ListAftermathFilter {
  deviceId?: number;
  verdict?: AftermathVerdict;
  jobId?: string;
  interventionId?: string;
  /** The screen that matters: everything that got worse. */
  degradedOnly?: boolean;
  limit?: number;
  offset?: number;
}

/** `change_aftermath` has NO foreign key to `tenants` (decision 6), so this
 *  predicate is the ONLY isolation the table has. It is never optional. */
function scopedAftermath(tenantId: number) {
  return db('change_aftermath as a')
    .leftJoin('devices as d', function joinDevice() {
      this.on('d.id', '=', 'a.device_id').andOn('d.tenant_id', '=', db.raw('?', [tenantId]));
    })
    .where('a.tenant_id', tenantId);
}

const AFTERMATH_COLUMNS = [
  'a.id', 'a.tenant_id', 'a.device_id', 'a.job_id', 'a.intervention_id', 'a.change_at',
  'a.horizon_days', 'a.baseline_from', 'a.baseline_to', 'a.after_from', 'a.after_to',
  'a.verdict', 'a.signals', 'a.degraded_count', 'a.improved_count', 'a.preexisting_count',
  'a.measured_count', 'a.brand', 'a.model', 'a.os_version', 'a.evaluated_at',
  'd.name as device_name',
];

export async function listAftermath(
  tenantId: number,
  filter: ListAftermathFilter = {},
): Promise<AftermathReport[]> {
  const q = scopedAftermath(tenantId);
  if (filter.deviceId !== undefined) void q.andWhere('a.device_id', filter.deviceId);
  if (filter.verdict) void q.andWhere('a.verdict', filter.verdict);
  if (filter.jobId) void q.andWhere('a.job_id', filter.jobId);
  if (filter.interventionId) void q.andWhere('a.intervention_id', filter.interventionId);
  if (filter.degradedOnly) void q.andWhere('a.verdict', 'DEGRADED');
  const rows = (await q
    .orderBy('a.evaluated_at', 'desc')
    .orderBy('a.id', 'desc')
    .limit(Math.min(filter.limit ?? 50, 200))
    .offset(filter.offset ?? 0)
    .select(AFTERMATH_COLUMNS)) as AftermathRow[];
  return rows.map(toReport);
}

export async function getAftermath(
  tenantId: number,
  id: string,
): Promise<AftermathReport | null> {
  const row = (await scopedAftermath(tenantId)
    .andWhere('a.id', id)
    .first(AFTERMATH_COLUMNS)) as AftermathRow | undefined;
  return row ? toReport(row) : null;
}
