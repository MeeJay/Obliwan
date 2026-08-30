/**
 * One device, one poll cycle.
 *
 * The sequence is fixed and every step exists because skipping it produces a
 * WRONG GRAPH rather than an error:
 *
 *   1. rediscover if the inventory is stale or an ifIndex remap was flagged;
 *   2. read sysUpTime ONCE per device, and 11 varbinds per interface;
 *   3. classify sysUpTime ONCE per device (reboot / 497-day wrap / nominal);
 *   4. compute one rate per interface, in the order of study section 3.4;
 *   5. write the samples, the baselines and the device row;
 *   6. evaluate the thresholds on what was just written.
 *
 * Step 3 IS PER DEVICE, NOT PER INTERFACE. A reboot zeroes every counter on
 * the box at once; deciding it interface by interface would spare the ones
 * whose counter happened to restart ABOVE its previous value, and those are
 * exactly the ones that would then draw a spike.
 *
 * WHAT THIS POLLER DOES NOT READ: CPU, memory and temperature. They live in
 * per-vendor private MIBs (MikroTik 14988, DrayTek 7367, Zyxel 890, SonicWall
 * 8741) with four different shapes, and guessing wrong writes a number that
 * looks like a percentage and is not. The columns are written with their
 * documented SENTINELS (`SENTINEL.NOT_AVAILABLE`, `TEMP_NOT_AVAILABLE`), which
 * is the schema's way of saying "not measured" without a NULL bitmap. Wiring
 * the vendor MIBs is a driver-layer job.
 */

import { randomUUID } from 'crypto';
import type { DeviceSampleRow, DiscardReason, IfSampleRow, PollState } from '@obliwan/shared';
import { SENTINEL } from '@obliwan/shared';
import { logger } from '../../utils/logger';
import { IF_TABLE, IFX_TABLE, SYS_OID, instance } from './oids';
import {
  asCounter,
  asInt,
  getMany,
  openSnmpConnection,
  type SnmpTarget,
  type SnmpVarbind,
} from '../transport/snmp.transport';
import {
  classifySysUptime,
  computeRate,
  type CounterReading,
  type RateContext,
  type UptimeVerdict,
} from './rateCalculator';
import { coherenceProbe, discoverDevice, flagForRediscovery } from './discovery';
import {
  backoffSeconds,
  discoveryDue,
  listInterfaceRows,
  markDiscovered,
  recordPollOutcome,
  resolveTarget,
  type ResolvedTarget,
  type SnmpInterfaceRow,
} from './targets';
import {
  bumpDiscardCounters,
  loadBaselines,
  saveBaselines,
  writeDeviceSamples,
  writeIfSamples,
} from './writer';
import { snmpConfig } from './config';
import { evaluateDevice } from './threshold.service';

/**
 * Identifies THIS process for the lifetime of THIS process.
 *
 * `snmp_poll_state.mono_ns` is a `process.hrtime.bigint()` reading, which is
 * only comparable within one process. A baseline carrying a different
 * `writer_epoch` therefore has an unusable denominator, and the rate
 * calculator turns that into a PROCESS_RESTART discard instead of silently
 * falling back to a wall clock that may have stepped during the outage.
 */
export const WRITER_EPOCH = randomUUID();

export interface PollOutcome {
  targetId: number;
  deviceId: number;
  ok: boolean;
  interfaces: number;
  samples: number;
  discards: Partial<Record<DiscardReason, number>>;
  clamped: number;
  durationMs: number;
  rediscovered: boolean;
  error?: string;
}

// ============================================================================
// Building the request
// ============================================================================

/** The 11 varbinds of study section 3.1, for one interface. */
function interfaceOids(row: SnmpInterfaceRow): {
  coherence: string;
  expected: string;
  inOctets: string;
  outOctets: string;
  inPkts: string;
  outPkts: string;
  inErrs: string;
  outErrs: string;
  inDiscards: string;
  outDiscards: string;
  operStatus: string;
  highSpeed: string;
} {
  const idx = row.if_index;
  const hc = Number(row.counter_bits) === 64;
  const probe = coherenceProbe(row);
  return {
    coherence: probe.oid,
    expected: probe.expected,
    inOctets: hc ? instance(IFX_TABLE.ifHCInOctets, idx) : instance(IF_TABLE.ifInOctets, idx),
    outOctets: hc ? instance(IFX_TABLE.ifHCOutOctets, idx) : instance(IF_TABLE.ifOutOctets, idx),
    inPkts: hc
      ? instance(IFX_TABLE.ifHCInUcastPkts, idx)
      : instance(IF_TABLE.ifInUcastPkts, idx),
    outPkts: hc
      ? instance(IFX_TABLE.ifHCOutUcastPkts, idx)
      : instance(IF_TABLE.ifOutUcastPkts, idx),
    // Errors and discards exist ONLY as Counter32 in the ifTable. There is no
    // HC variant; RFC 2863 never defined one.
    inErrs: instance(IF_TABLE.ifInErrors, idx),
    outErrs: instance(IF_TABLE.ifOutErrors, idx),
    inDiscards: instance(IF_TABLE.ifInDiscards, idx),
    outDiscards: instance(IF_TABLE.ifOutDiscards, idx),
    operStatus: instance(IF_TABLE.ifOperStatus, idx),
    // Re-read every poll rather than trusted from discovery: an operator who
    // reconfigures a 100 M port to 1 G would otherwise have every sample
    // rejected as OVER_LINE_SPEED until the next hourly discovery.
    highSpeed: instance(IFX_TABLE.ifHighSpeed, idx),
  };
}

function lineSpeedOf(vb: SnmpVarbind | undefined, row: SnmpInterfaceRow): bigint {
  const mbit = asInt(vb);
  if (mbit !== null && mbit > 0) return BigInt(mbit) * 1_000_000n;
  // Falls back to what discovery stored (ifHighSpeed x 1e6, or ifSpeed). 0
  // means UNKNOWN, and unknown means NO CLAMP -- not "zero capacity".
  const stored = BigInt(row.speed_bps ?? 0);
  return stored > 0n ? stored : 0n;
}

// ============================================================================
// The poll
// ============================================================================

export async function pollTarget(resolved: ResolvedTarget): Promise<PollOutcome> {
  const started = Date.now();
  const { target, deviceId } = resolved;
  const outcome: PollOutcome = {
    targetId: target.id,
    deviceId,
    ok: false,
    interfaces: 0,
    samples: 0,
    discards: {},
    clamped: 0,
    durationMs: 0,
    rediscovered: false,
  };
  const bump = (reason: DiscardReason): void => {
    outcome.discards[reason] = (outcome.discards[reason] ?? 0) + 1;
  };

  let dialable: SnmpTarget;
  try {
    dialable = resolveTarget(resolved);
  } catch (err) {
    outcome.error = err instanceof Error ? err.message : String(err);
    outcome.durationMs = Date.now() - started;
    await recordPollOutcome(target.id, {
      ok: false,
      error: outcome.error,
      backoffSec: backoffSeconds(resolved.pollIntervalSec, target.consecutive_failures + 1),
    });
    return outcome;
  }

  // No socket is opened here: the connection is a handle onto the ONE session
  // cache in `transport/snmp.transport.ts`, and the session is acquired (or
  // reused) by the first request that actually goes on the wire.
  const connection = openSnmpConnection(dialable);

  try {
    // -- 1. inventory ------------------------------------------------------
    let interfaces = await listInterfaceRows(deviceId, { monitoredOnly: true });
    const remapFlagged = interfaces.some((r) => r.needs_rediscovery);
    if (discoveryDue(target, interfaces.length > 0) || remapFlagged) {
      const result = await discoverDevice(deviceId, connection, resolved.pollIntervalSec);
      await markDiscovered(target.id, snmpConfig.discoveryIntervalSec);
      outcome.rediscovered = true;
      interfaces = result.interfaces.filter((r) => r.monitored);
      logger.debug(
        {
          deviceId,
          discovered: result.discovered,
          created: result.created,
          updated: result.updated,
          remapped: result.remapped,
          vanished: result.vanished,
        },
        'SNMP discovery completed',
      );
    }
    outcome.interfaces = interfaces.length;

    // -- 2. the read -------------------------------------------------------
    const plans = interfaces.map((row) => ({ row, oids: interfaceOids(row) }));
    const oids: string[] = [SYS_OID.sysUpTime];
    for (const p of plans) {
      oids.push(
        p.oids.coherence,
        p.oids.inOctets,
        p.oids.outOctets,
        p.oids.inPkts,
        p.oids.outPkts,
        p.oids.inErrs,
        p.oids.outErrs,
        p.oids.inDiscards,
        p.oids.outDiscards,
        p.oids.operStatus,
        p.oids.highSpeed,
      );
    }

    const readStarted = process.hrtime.bigint();
    const answers = await getMany(connection, oids);
    const monoNs = process.hrtime.bigint();
    const wallTs = new Date();
    const rttUs = Number((monoNs - readStarted) / 1000n);

    const sysUptimeTicks = asCounter(answers.get(SYS_OID.sysUpTime));

    // -- 3. sysUpTime, ONCE for the device ---------------------------------
    const baselines = await loadBaselines(deviceId);
    // Any baseline of this device carries the previous sysUpTime; they are all
    // written in the same cycle. The most recently updated one is used so a
    // freshly-added interface (whose baseline is a cycle behind) cannot drag
    // the comparison window.
    let reference: PollState | null = null;
    for (const state of baselines.values()) {
      if (!reference || state.monoNs > reference.monoNs) reference = state;
    }
    const deviceElapsedMs = reference
      ? reference.writerEpoch === WRITER_EPOCH
        ? Number((monoNs - reference.monoNs) / 1_000_000n)
        : wallTs.getTime() - new Date(reference.wallTs).getTime()
      : 0;

    const deviceVerdict: UptimeVerdict =
      sysUptimeTicks === null
        ? { kind: 'unknown', epoch: reference?.sysUptimeEpoch ?? 0 }
        : classifySysUptime(
            reference?.sysUptimeTicks ?? null,
            reference?.sysUptimeEpoch ?? 0,
            sysUptimeTicks,
            deviceElapsedMs,
          );

    if (deviceVerdict.kind === 'reboot') {
      logger.info(
        { deviceId, previousTicks: reference?.sysUptimeTicks?.toString(), nowTicks: sysUptimeTicks?.toString() },
        'SNMP: device rebooted — this cycle is a HOLE in every series of the device, not a spike',
      );
    } else if (deviceVerdict.kind === 'wrapped') {
      logger.info({ deviceId, epoch: deviceVerdict.epoch }, 'SNMP: sysUpTime wrapped (497 days)');
    } else if (deviceVerdict.kind === 'ok' && deviceVerdict.suspectAgentRestart) {
      logger.warn(
        { deviceId },
        'SNMP: sysUpTime drifted more than 20% from real time — SNMP daemon restart suspected',
      );
    }

    // -- 4. one rate per interface ----------------------------------------
    const samples: IfSampleRow[] = [];
    const nextBaselines: PollState[] = [];
    const agentErrorIfIds: number[] = [];
    const remapIfIds: number[] = [];

    for (const { row, oids: o } of plans) {
      const reading: CounterReading = {
        ifId: row.id,
        deviceId,
        ifIndex: row.if_index,
        observedName: (() => {
          const vb = answers.get(o.coherence);
          if (!vb || vb.missing || vb.value === null) return null;
          return String(vb.value).replace(/\0+$/, '').trim() || null;
        })(),
        expectedName: o.expected,
        counterBits: (Number(row.counter_bits) === 32 ? 32 : 64) as 32 | 64,
        inOctets: asCounter(answers.get(o.inOctets)),
        outOctets: asCounter(answers.get(o.outOctets)),
        inPkts: asCounter(answers.get(o.inPkts)),
        outPkts: asCounter(answers.get(o.outPkts)),
        inErrs: asCounter(answers.get(o.inErrs)),
        outErrs: asCounter(answers.get(o.outErrs)),
        inDiscards: asCounter(answers.get(o.inDiscards)),
        outDiscards: asCounter(answers.get(o.outDiscards)),
        operStatus: asInt(answers.get(o.operStatus)),
        lineSpeedBps: lineSpeedOf(answers.get(o.highSpeed), row),
      };

      const ctx: RateContext = {
        baseline: baselines.get(row.id) ?? null,
        writerEpoch: WRITER_EPOCH,
        monoNs,
        wallTs,
        sysUptimeTicks,
        expectedIntervalSec: row.effective_poll_sec || resolved.pollIntervalSec,
        deviceVerdict,
      };

      const result = computeRate(reading, ctx);
      if (result.kind === 'sample') {
        samples.push(result.sample);
        if (result.clamped) outcome.clamped += 1;
        nextBaselines.push(result.nextBaseline);
      } else {
        bump(result.reason);
        if (result.reason === 'IFINDEX_REMAP') remapIfIds.push(row.id);
        if (result.nextBaseline) nextBaselines.push(result.nextBaseline);
        else agentErrorIfIds.push(row.id);
      }
    }

    // -- 5. write ----------------------------------------------------------
    // Baselines FIRST. If the sample insert fails, the next cycle must still
    // have a fresh baseline: with a stale one it would compute a delta over a
    // doubled window, and `WINDOW_TOO_LONG` would then hide the real problem.
    await saveBaselines(nextBaselines);
    if (agentErrorIfIds.length > 0) await bumpDiscardCounters(agentErrorIfIds, 'AGENT_ERROR');
    if (remapIfIds.length > 0) {
      await flagForRediscovery(remapIfIds);
      logger.warn(
        { deviceId, ifIds: remapIfIds },
        'SNMP: ifIndex no longer matches the stored name (R12) — nothing written, ' +
          'rediscovery scheduled for the next cycle',
      );
    }
    outcome.samples = await writeIfSamples(samples);

    const deviceRow: DeviceSampleRow = {
      deviceId,
      ts: wallTs.toISOString(),
      uptimeTicks: sysUptimeTicks ?? 0n,
      // See the file header: the vendor MIBs are not wired, and a sentinel is
      // the honest answer. `unsentinel()` turns them back into null on the way
      // to a screen or an average.
      memUsedBytes: BigInt(SENTINEL.NOT_AVAILABLE),
      memTotalBytes: BigInt(SENTINEL.NOT_AVAILABLE),
      rttUs: Number.isFinite(rttUs) ? Math.min(rttUs, 2_147_483_647) : SENTINEL.NOT_AVAILABLE,
      cpuPct: SENTINEL.NOT_AVAILABLE,
      tempDc: SENTINEL.TEMP_NOT_AVAILABLE,
      // A device row IS written when the device did not answer -- unlike an
      // interface, `reachable = false` is information, not a doubt.
      reachable: sysUptimeTicks !== null,
    };
    await writeDeviceSamples([deviceRow]);

    // -- 6. thresholds -----------------------------------------------------
    // Evaluated on what was just measured, never on a re-read: a threshold
    // that queries the series back would evaluate a bucket that the rollup has
    // not closed yet, and would flap on every gap.
    try {
      await evaluateDevice({
        deviceId,
        tenantId: resolved.tenantId,
        groupId: resolved.groupId,
        deviceName: resolved.deviceName,
        at: wallTs,
        interfaces,
        samples,
        deviceSample: deviceRow,
      });
    } catch (err) {
      // Alerting is downstream of measuring. A broken channel must not lose a
      // cycle of metrics that has already been written.
      logger.error({ err, deviceId }, 'SNMP: threshold evaluation failed (samples were written)');
    }

    outcome.ok = sysUptimeTicks !== null;
    outcome.durationMs = Date.now() - started;
    await recordPollOutcome(target.id, {
      ok: outcome.ok,
      error: outcome.ok ? null : 'device did not answer sysUpTime',
      backoffSec: outcome.ok
        ? undefined
        : backoffSeconds(resolved.pollIntervalSec, target.consecutive_failures + 1),
    });
    return outcome;
  } catch (err) {
    // The transport already evicts the session on a wire failure (timeout or
    // agent error), in one place. This covers the rest of the cycle: if the
    // discovery, the writer or the baseline load threw, the session is of
    // unknown health and the next cycle should start from a fresh one.
    connection.close();
    outcome.error = err instanceof Error ? err.message : String(err);
    outcome.durationMs = Date.now() - started;
    logger.warn({ deviceId, targetId: target.id, err: outcome.error }, 'SNMP poll failed');
    await recordPollOutcome(target.id, {
      ok: false,
      error: outcome.error,
      backoffSec: backoffSeconds(resolved.pollIntervalSec, target.consecutive_failures + 1),
    });
    return outcome;
  }
}
