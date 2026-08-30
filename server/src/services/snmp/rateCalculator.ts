/**
 * rateCalculator.ts -- the heart of M3. Section 3 of
 * `docs/M3-series-temporelles.md`, implemented literally.
 *
 * THE ONE RULE: IN CASE OF DOUBT, DISCARD. Never a NULL row, never a zero,
 * never a "suspicious" flag on a written value. The ABSENCE of a row IS the
 * hole, and the hole travels all the way to the chart through
 * `sample_count < expected_count / 2`.
 *
 * The reason is not fastidiousness. One 40 Gbit/s spike on a 100 Mbit/s link
 * and nobody looks at any graph again -- the same mechanism as risk R3 for
 * config drift. A missing minute is a question; a wrong minute is a lie, and a
 * lie is indistinguishable from a measurement once it is on the axis.
 *
 * THIS FILE IS PURE. No database, no clock, no logger, no I/O. Everything it
 * needs is an argument, and everything it decides is in the return value --
 * which is what makes the twelve discard paths testable without an agent, a
 * reboot or a 497-day wait.
 *
 * ORDER OF THE TESTS IS NOT DECORATIVE (study section 3.4). A reboot tested
 * after the delta produces the spike before it is detected. An ifIndex check
 * tested last writes the WAN octets into the LAN series (R12) and only then
 * notices.
 */

import type { DiscardReason, IfSampleRow, PollState, RateResult } from '@obliwan/shared';
import { IF_OPER_STATUS } from '@obliwan/shared';

// ============================================================================
// The numbers of section 3.2, once, as named constants
// ============================================================================

/** 2^32. A Counter32 wraps here; sysUpTime (TimeTicks) wraps here too. */
export const WRAP32 = 4_294_967_296n;

/** 2^32 as a JS number, for the TimeTicks arithmetic (exact below 2^53). */
const WRAP32_N = 4_294_967_296;

/**
 * Absolute sanity ceiling when the link speed is unknown -- 400 Gbit/s.
 *
 * `ifHighSpeed` is absent or zero on PPP links, tunnels and most virtual
 * interfaces, and there is then NO clamp available. This is not a clamp: it is
 * the line past which a number is not a measurement, and it is a discard, not
 * a truncation.
 */
export const ABSOLUTE_MAX_BPS = 400_000_000_000n;

/**
 * How far past `ifHighSpeed` a rate may go and still be treated as a
 * measurement artefact worth clamping rather than a broken reading worth
 * dropping.
 *
 * 0 to 5 % over is an artefact: imprecision in `elapsed`, an agent that
 * samples its own counters on its own schedule, a link advertised at "100" and
 * really clocked at 100.1. Clamping there is correct. 400 % over is NOT an
 * artefact -- it is a missed wrap or a wrong `ifHighSpeed`, and clamping it to
 * 100 % would turn a detectable error into a perfectly plausible plateau at
 * full saturation, i.e. INTO A FALSE SATURATION ALERT indistinguishable from a
 * real one.
 *
 * The 5 % is a chosen number, not a measured one (study section 3.4g flags it
 * "to arbitrate"). The `clamped` counter is the instrument that will settle
 * it: above a few per mille, `ifHighSpeed` is wrong on the equipment.
 */
export const CLAMP_TOLERANCE_PCT = 5n;

/** elapsed below this fraction of the expected interval: a double poll, or a
 *  clock that went backwards. */
export const WINDOW_SHORT_FACTOR = 0.5;

/**
 * elapsed above this multiple of the expected interval: polls were missed.
 *
 * The upper bound is not fussiness. The longer the window, the more room a
 * Counter32 wrap has to hide in it, and the easier it is for a reboot followed
 * by a fast restart to pass unnoticed. THIS IS ALSO WHAT GUARANTEES THE CLEAN
 * HOLE AFTER A THREE-DAY OUTAGE (study section 2.7) -- one rule, two jobs.
 */
export const WINDOW_LONG_FACTOR = 3;

/** Above 20 % of drift between sysUpTime's progress and real time, the agent
 *  is lying or only its SNMP daemon restarted (agent uptime != system uptime). */
const UPTIME_DRIFT_TOLERANCE = 0.2;

/** A reconstructed sysUpTime wrap must match real elapsed time this closely. */
const UPTIME_WRAP_TOLERANCE = 0.05;

/** int4 ceiling. `in_pps`, `in_errs` and friends are `integer` in the schema. */
const INT4_MAX = 2_147_483_647;

/** Bytes assumed per packet when bounding a plausible packet delta. Smaller
 *  than the real minimum Ethernet frame on the wire (84 B with preamble and
 *  IFG) ON PURPOSE: over-estimating the plausible packet count makes
 *  AMBIGUOUS_WRAP fire MORE often, and erring toward the discard is the whole
 *  doctrine of this file. */
const MIN_BYTES_PER_PACKET = 64n;

// ============================================================================
// What one poll learned about one interface
// ============================================================================

/**
 * The counters as read at ONE ifIndex during ONE poll.
 *
 * Every counter is `bigint | null`, and `null` means "the agent did not answer
 * this varbind". It is NEVER read as zero: zero would make the next delta
 * compute from 0 and produce one enormous spike. A null on any REQUIRED
 * counter is AGENT_ERROR.
 */
export interface CounterReading {
  ifId: number;
  deviceId: number;
  ifIndex: number;

  /**
   * R12, THE VARBIND THAT MUST NEVER BE OPTIMISED AWAY.
   *
   * `ifDescr` as read at `ifIndex` DURING THIS POLL, and `expectedName` is
   * what `snmp_interfaces` says should be there. One extra varbind per
   * interface per poll -- 2 400 varbinds per cycle at fleet size, which is
   * 9 % of the poll's varbind budget and the cheapest insurance in the whole
   * milestone.
   *
   * Without it, a reboot that renumbers ifIndex writes the WAN counters into
   * the LAN series, silently, forever, and NOTHING IN THE DATA EVER LOOKS
   * WRONG. `null` means the index stopped answering, which is itself the same
   * event.
   */
  observedName: string | null;
  expectedName: string;

  /** Width ACTUALLY obtained for this interface -- an agent may advertise HC
   *  counters and still answer noSuchObject on one port. */
  counterBits: 32 | 64;

  inOctets: bigint | null;
  outOctets: bigint | null;
  inPkts: bigint | null;
  outPkts: bigint | null;
  inErrs: bigint | null;
  outErrs: bigint | null;
  inDiscards: bigint | null;
  outDiscards: bigint | null;

  /** IF-MIB ifOperStatus, 1..7. Written as read: no forced zero rate on a
   *  `down` interface. If the counters say 0 the maths gives 0 by itself; if
   *  they say something else (an interface that fell mid-window) the real
   *  value is more informative than a fabricated one. */
  operStatus: number | null;

  /** `ifHighSpeed * 1e6`, or `ifSpeed` as a fallback. 0 means UNKNOWN, which
   *  means NO CLAMP IS POSSIBLE -- not "zero capacity". */
  lineSpeedBps: bigint;
}

/** Everything about the moment of the read that is not the counters. */
export interface RateContext {
  /** The persisted baseline, or null on the first poll of this interface. */
  baseline: PollState | null;
  /** This process's epoch. A baseline from another one has an incomparable
   *  `monoNs`. */
  writerEpoch: string;
  /** `process.hrtime.bigint()` at the read. */
  monoNs: bigint;
  /** Wall clock at the read -- the `ts` of the row, and the fallback
   *  denominator across a restart. */
  wallTs: Date;
  /** Device sysUpTime in TimeTicks at this poll. Null when the device did not
   *  answer sysUpTime, which is AGENT_ERROR for the whole device. */
  sysUptimeTicks: bigint | null;
  /** `snmp_interfaces.effective_poll_sec`. The reference the window bounds are
   *  measured against. */
  expectedIntervalSec: number;
  /**
   * Device-level reboot verdict, computed ONCE per device by
   * `classifySysUptime` and applied to EVERY interface of that device.
   *
   * Deciding it per interface would produce a spike on any interface whose
   * counter happened to restart ABOVE its previous value.
   */
  deviceVerdict: UptimeVerdict;
}

// ============================================================================
// sysUpTime: reboot, wrap, or an agent that lies -- study section 3.4d
// ============================================================================

export type UptimeVerdict =
  /** Nominal. `suspectAgentRestart` when sysUpTime advanced very differently
   *  from real time: the SNMP daemon restarted while the box did not, so the
   *  counters may or may not have survived. Not fatal, but worth a metric. */
  | { kind: 'ok'; epoch: number; suspectAgentRestart: boolean }
  /** sysUpTime went backwards AND the numbers only fit a 497-day wrap. The
   *  octet counters did NOT restart: we keep computing. */
  | { kind: 'wrapped'; epoch: number }
  /** sysUpTime went backwards and it is not a wrap. Every counter on the
   *  device restarted at zero. HOLE, NOT SPIKE. */
  | { kind: 'reboot'; epoch: number }
  /** No previous sysUpTime to compare against. */
  | { kind: 'unknown'; epoch: number };

/**
 * Classify what sysUpTime did between two polls.
 *
 * The wrap test rests on TWO CONJOINED conditions -- the reconstructed delta
 * must match real elapsed time to 5 %, AND the previous value must have been
 * near the 2^32 ceiling. A reboot satisfies both with probability of order
 * 30 s / 497 d, about 7e-7: after a reboot `nowTicks` is a few thousand, so
 * `wrapDelta` is roughly `2^32 - prevTicks`, which only matches `expectedTicks`
 * if `prevTicks` was within a minute of the ceiling.
 *
 * A single threshold ("it went back by more than X") cannot separate the two
 * and would call every 497-day wrap a reboot -- one gratuitous fleet-wide hole
 * every year and a half, on the most stable devices in the estate.
 */
export function classifySysUptime(
  prevTicks: bigint | null,
  prevEpoch: number,
  nowTicks: bigint,
  elapsedMs: number,
): UptimeVerdict {
  if (prevTicks === null) return { kind: 'unknown', epoch: prevEpoch };

  const prev = Number(prevTicks);
  const now = Number(nowTicks);
  // TimeTicks are hundredths of a second.
  const expectedTicks = elapsedMs / 10;
  const delta = now - prev;

  if (delta >= 0) {
    const drift =
      expectedTicks > 0 ? Math.abs(delta - expectedTicks) > UPTIME_DRIFT_TOLERANCE * expectedTicks : false;
    return { kind: 'ok', epoch: prevEpoch, suspectAgentRestart: drift };
  }

  const wrapDelta = delta + WRAP32_N;
  const looksLikeWrap =
    expectedTicks > 0 &&
    Math.abs(wrapDelta - expectedTicks) < UPTIME_WRAP_TOLERANCE * expectedTicks &&
    prev > WRAP32_N - expectedTicks * 4;

  return looksLikeWrap
    ? { kind: 'wrapped', epoch: prevEpoch + 1 }
    : { kind: 'reboot', epoch: 0 };
}

// ============================================================================
// Counter deltas -- study section 3.4f
// ============================================================================

export type DeltaResult = { ok: true; delta: bigint } | { ok: false; reason: DiscardReason };

/**
 * The delta of one counter across the window.
 *
 * `maxPlausibleDelta` is what the link could physically have carried in this
 * window. Pass `null` when it cannot be bounded (unknown line speed) -- and
 * note what that costs: a Counter32 going backwards then becomes undecidable
 * and is discarded rather than guessed.
 *
 * ON A COUNTER64 A DECREASE IS NEVER A WRAP. 2^64 octets is 46.8 years at
 * 100 Gbit/s. A Counter64 going backwards is an agent reset, a hardware swap
 * or a bug, and the answer is always DISCARD. Any line of code computing
 * `now + 2^64 - prev` is wrong by construction.
 */
export function counterDelta(
  prev: bigint,
  now: bigint,
  bits: 32 | 64,
  maxPlausibleDelta: bigint | null,
): DeltaResult {
  if (now >= prev) {
    const delta = now - prev;
    // A forward jump larger than the link could carry is a counter that was
    // reset UPWARDS or an agent returning garbage. The clamp stage would
    // otherwise turn it into a plausible saturation plateau.
    if (maxPlausibleDelta !== null && delta > maxPlausibleDelta * 2n) {
      return { ok: false, reason: 'COUNTER_RESET' };
    }
    return { ok: true, delta };
  }

  if (bits === 64) return { ok: false, reason: 'COUNTER_RESET' };

  // Counter32: ONE wrap is plausible, two are not. If the link could have
  // pushed 2^32 units through the window, then "the counter went backwards" is
  // equally compatible with 1, 2 or 3 wraps and there is nothing to arbitrate.
  // No heuristic rescues this -- no "take the most likely". We throw it away.
  if (maxPlausibleDelta === null || maxPlausibleDelta >= WRAP32) {
    return { ok: false, reason: 'AMBIGUOUS_WRAP' };
  }
  return { ok: true, delta: now + WRAP32 - prev };
}

/**
 * Delta of a counter that has no meaningful physical ceiling: errors and
 * discards, which exist only as Counter32 in the ifTable.
 *
 * A decrease is a reset (`clear counters`, or an agent restart) and never a
 * wrap: 2^32 errors on an interface is not a thing that happens between two
 * polls. Consistent with the doctrine, a reset is a discard -- we lose one
 * sample and keep the series honest.
 */
export function monotonicDelta(prev: bigint, now: bigint): DeltaResult {
  if (now < prev) return { ok: false, reason: 'COUNTER_RESET' };
  const delta = now - prev;
  if (delta > BigInt(INT4_MAX)) return { ok: false, reason: 'COUNTER_RESET' };
  return { ok: true, delta };
}

// ============================================================================
// The clamp -- study section 3.4g
// ============================================================================

export type ClampResult =
  | { ok: true; bps: bigint; clamped: boolean }
  | { ok: false; reason: DiscardReason };

export function clampRate(bps: bigint, lineSpeedBps: bigint): ClampResult {
  if (lineSpeedBps > 0n) {
    if (bps * 100n > lineSpeedBps * (100n + CLAMP_TOLERANCE_PCT)) {
      return { ok: false, reason: 'OVER_LINE_SPEED' };
    }
    if (bps > lineSpeedBps) return { ok: true, bps: lineSpeedBps, clamped: true };
    return { ok: true, bps, clamped: false };
  }
  if (bps > ABSOLUTE_MAX_BPS) return { ok: false, reason: 'OVER_LINE_SPEED' };
  return { ok: true, bps, clamped: false };
}

/**
 * Is a Counter32 usable at all at this poll interval on this link?
 *
 * 2^32 octets is 34.36 Gbit. On a saturated 1 Gbit/s link that is 34.4 seconds
 * -- LESS than one 30 s poll. Between two polls you cannot tell "no wrap" from
 * "one wrap", and past 35 s you cannot tell "one" from "two".
 *
 * A CONCLUSION THAT BELONGS IN THE CODE AND NOT ONLY IN THE STUDY: a Counter32
 * on a gigabit link is not measurable at a 30-second poll. The interface is
 * flagged `counter_unreliable` and the UI must refuse to draw a rate for it,
 * with an actionable message ("32-bit counters insufficient for this link
 * speed -- move the device to SNMPv2c/v3 or shorten the interval to 15 s").
 * Refusing to draw is actionable; a wrong graph is not.
 */
export function counterUnreliable(bits: 32 | 64, elapsedSec: number, lineSpeedBps: bigint): boolean {
  if (bits === 64 || lineSpeedBps <= 0n) return false;
  const halfWrapSec = (Number(WRAP32) * 8) / 2 / Number(lineSpeedBps);
  return elapsedSec > halfWrapSec;
}

// ============================================================================
// The algorithm
// ============================================================================

function baselineFrom(
  reading: CounterReading,
  ctx: RateContext,
  epoch: number,
  lastDiscard: DiscardReason | null,
  consecutive: number,
): PollState | null {
  // A baseline is only worth writing when every counter that feeds a delta is
  // present. A partial baseline would make the NEXT poll compute against a
  // value that was never read.
  if (
    reading.inOctets === null ||
    reading.outOctets === null ||
    reading.inPkts === null ||
    reading.outPkts === null ||
    reading.inErrs === null ||
    reading.outErrs === null ||
    reading.inDiscards === null ||
    reading.outDiscards === null ||
    ctx.sysUptimeTicks === null
  ) {
    return null;
  }
  return {
    ifId: reading.ifId,
    deviceId: reading.deviceId,
    wallTs: ctx.wallTs.toISOString(),
    monoNs: ctx.monoNs,
    writerEpoch: ctx.writerEpoch,
    inOctets: reading.inOctets,
    outOctets: reading.outOctets,
    inPkts: reading.inPkts,
    outPkts: reading.outPkts,
    inErrs: reading.inErrs,
    outErrs: reading.outErrs,
    inDiscards: reading.inDiscards,
    outDiscards: reading.outDiscards,
    counterBits: reading.counterBits,
    sysUptimeTicks: ctx.sysUptimeTicks,
    sysUptimeEpoch: epoch,
    lineSpeedBps: reading.lineSpeedBps,
    lastDiscard,
    consecutiveDiscards: consecutive,
  };
}

/**
 * How long the window really was, in milliseconds.
 *
 * `monoNs` when the baseline comes from THIS process: `process.hrtime.bigint()`
 * is immune to an NTP step. Using `Date.now()` where hrtime is available means
 * accepting that a 200 ms NTP adjustment over a 30 s window is a 0.7 % error
 * on every rate, and that a one-second step is a 3 % spike across the fleet.
 *
 * Across a restart the monotonic clocks are incomparable and `wall_ts` is all
 * there is -- which is exactly why a different `writer_epoch` is a discard
 * rather than a silent fallback.
 */
function elapsedMsOf(baseline: PollState, ctx: RateContext): number {
  if (baseline.writerEpoch === ctx.writerEpoch) {
    return Number((ctx.monoNs - baseline.monoNs) / 1_000_000n);
  }
  return ctx.wallTs.getTime() - new Date(baseline.wallTs).getTime();
}

/**
 * One interface, one poll, one decision.
 *
 * The order below is the order of study section 3.4 and must not be
 * rearranged for readability.
 */
export function computeRate(reading: CounterReading, ctx: RateContext): RateResult {
  const { baseline } = ctx;

  const discard = (reason: DiscardReason, epoch: number): RateResult => ({
    kind: 'discard',
    reason,
    nextBaseline: baselineFrom(
      reading,
      ctx,
      epoch,
      reason,
      (baseline?.consecutiveDiscards ?? 0) + 1,
    ),
  });

  // -- (c) ifIndex coherence, R12 -- FIRST, BEFORE ANYTHING ELSE ------------
  // If the index has moved, the counters in `reading` belong to a DIFFERENT
  // interface, so they must not become anybody's baseline. `nextBaseline:
  // null` leaves this interface's baseline untouched; the caller sets
  // `needs_rediscovery` and writes nothing until rediscovery confirms the new
  // ifIndex.
  //
  // THIS TEST RUNS BEFORE THE COMPLETENESS CHECK, and that ordering was found
  // by the bench, not by reading the study. A renumbering very often makes the
  // counters unreadable as well -- the port that inherited the index may not
  // expose the ifXTable HC columns the old one did -- so a completeness check
  // placed first swallows the remap and reports a generic AGENT_ERROR. The
  // operator then sees "the agent is misbehaving" instead of "ifIndex moved",
  // NOTHING SETS `needs_rediscovery`, no rediscovery is scheduled, and the
  // interface stays dark for ever. Observed exactly like that on the first run.
  //
  // This is the most vicious scenario in the milestone precisely because it is
  // silent: without this test the octets land in the wrong series and
  // everything looks normal.
  if (reading.observedName === null || reading.observedName !== reading.expectedName) {
    return { kind: 'discard', reason: 'IFINDEX_REMAP', nextBaseline: null };
  }

  // -- (0) Did we actually read everything? --------------------------------
  // The other case that leaves `nextBaseline: null`: there is no coherent read
  // to start from, so there is nothing to persist.
  const required = [
    reading.inOctets,
    reading.outOctets,
    reading.inPkts,
    reading.outPkts,
    reading.inErrs,
    reading.outErrs,
    reading.inDiscards,
    reading.outDiscards,
  ];
  if (required.some((v) => v === null) || reading.operStatus === null || ctx.sysUptimeTicks === null) {
    return { kind: 'discard', reason: 'AGENT_ERROR', nextBaseline: null };
  }

  // -- (d) device reboot ----------------------------------------------------
  // Before the baseline tests too: a reboot on the very first poll after a
  // restart must read as a reboot, and the epoch has to be carried into the
  // baseline we are about to write in either case.
  const epoch =
    ctx.deviceVerdict.kind === 'unknown' ? (baseline?.sysUptimeEpoch ?? 0) : ctx.deviceVerdict.epoch;

  if (ctx.deviceVerdict.kind === 'reboot') {
    // Hole, not spike. The baseline IS refreshed -- from the zeroed counters --
    // otherwise the interface would reject for ever after a single reboot.
    return discard('DEVICE_REBOOT', epoch);
  }

  // -- (a) no baseline ------------------------------------------------------
  if (!baseline) return discard('NO_BASELINE', epoch);

  // -- (b) the baseline belongs to another process --------------------------
  // `monoNs` is not comparable across processes. Falling back to `wall_ts`
  // would mean trusting a wall clock that may have stepped during the outage.
  // One sample per interface is the price of a deployment: 2 400 points,
  // invisible on a graph.
  if (baseline.writerEpoch !== ctx.writerEpoch) return discard('PROCESS_RESTART', epoch);

  // -- (e) the window -------------------------------------------------------
  const elapsedMs = elapsedMsOf(baseline, ctx);
  const expectedMs = ctx.expectedIntervalSec * 1000;
  if (elapsedMs <= 0 || elapsedMs < expectedMs * WINDOW_SHORT_FACTOR) {
    return discard('WINDOW_TOO_SHORT', epoch);
  }
  if (elapsedMs > expectedMs * WINDOW_LONG_FACTOR) {
    return discard('WINDOW_TOO_LONG', epoch);
  }
  const elapsedSec = elapsedMs / 1000;

  // -- Counter32 on a link too fast for this interval (section 3.2) ---------
  if (counterUnreliable(reading.counterBits, elapsedSec, reading.lineSpeedBps)) {
    return discard('COUNTER_UNRELIABLE', epoch);
  }

  // -- (f) deltas -----------------------------------------------------------
  const maxOctets =
    reading.lineSpeedBps > 0n
      ? (reading.lineSpeedBps * BigInt(Math.ceil(elapsedMs))) / 8000n
      : null;
  const maxPkts = maxOctets === null ? null : maxOctets / MIN_BYTES_PER_PACKET + 1n;

  const inOct = counterDelta(baseline.inOctets, reading.inOctets!, reading.counterBits, maxOctets);
  if (!inOct.ok) return discard(inOct.reason, epoch);
  const outOct = counterDelta(baseline.outOctets, reading.outOctets!, reading.counterBits, maxOctets);
  if (!outOct.ok) return discard(outOct.reason, epoch);
  const inPkt = counterDelta(baseline.inPkts, reading.inPkts!, reading.counterBits, maxPkts);
  if (!inPkt.ok) return discard(inPkt.reason, epoch);
  const outPkt = counterDelta(baseline.outPkts, reading.outPkts!, reading.counterBits, maxPkts);
  if (!outPkt.ok) return discard(outPkt.reason, epoch);

  const inErr = monotonicDelta(baseline.inErrs, reading.inErrs!);
  if (!inErr.ok) return discard(inErr.reason, epoch);
  const outErr = monotonicDelta(baseline.outErrs, reading.outErrs!);
  if (!outErr.ok) return discard(outErr.reason, epoch);
  const inDisc = monotonicDelta(baseline.inDiscards, reading.inDiscards!);
  if (!inDisc.ok) return discard(inDisc.reason, epoch);
  const outDisc = monotonicDelta(baseline.outDiscards, reading.outDiscards!);
  if (!outDisc.ok) return discard(outDisc.reason, epoch);

  // -- (g) rates and clamp --------------------------------------------------
  const ms = BigInt(Math.round(elapsedMs));
  const inBpsRaw = (inOct.delta * 8000n) / ms;
  const outBpsRaw = (outOct.delta * 8000n) / ms;

  const inClamp = clampRate(inBpsRaw, reading.lineSpeedBps);
  if (!inClamp.ok) return discard(inClamp.reason, epoch);
  const outClamp = clampRate(outBpsRaw, reading.lineSpeedBps);
  if (!outClamp.ok) return discard(outClamp.reason, epoch);

  const pps = (delta: bigint): number => {
    const v = (delta * 1000n) / ms;
    return v > BigInt(INT4_MAX) ? INT4_MAX : Number(v);
  };

  // -- (h) ifOperStatus, as read -------------------------------------------
  const operStatus =
    reading.operStatus >= 1 && reading.operStatus <= 7 ? reading.operStatus : IF_OPER_STATUS.unknown;

  const sample: IfSampleRow = {
    ifId: reading.ifId,
    ts: ctx.wallTs.toISOString(),
    inBps: inClamp.bps,
    outBps: outClamp.bps,
    inPps: pps(inPkt.delta),
    outPps: pps(outPkt.delta),
    inErrs: Number(inErr.delta),
    outErrs: Number(outErr.delta),
    inDiscards: Number(inDisc.delta),
    outDiscards: Number(outDisc.delta),
    elapsedMs: Math.round(elapsedMs),
    operStatus: operStatus as IfSampleRow['operStatus'],
  };

  const nextBaseline = baselineFrom(reading, ctx, epoch, null, 0);
  if (!nextBaseline) {
    // Unreachable: step (0) already proved every counter is present. Kept
    // because the alternative is a non-null assertion on the public contract.
    return { kind: 'discard', reason: 'AGENT_ERROR', nextBaseline: null };
  }

  return { kind: 'sample', sample, clamped: inClamp.clamped || outClamp.clamped, nextBaseline };
}

/**
 * Consecutive discards past which the COLLECTION ITSELF is the incident.
 *
 * A hole is normal; ten in a row on one interface means it stopped reporting
 * and nobody would notice, because a missing series looks exactly like a quiet
 * link. This is a collection-health alert and it is deliberately NOT one of
 * the business thresholds of `threshold.service.ts`.
 */
export const DISCARD_HEALTH_THRESHOLD = 10;
