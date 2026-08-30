// ObliWAN client — SNMP / time-series DTOs (M3).
//
// Same rule as `types/fleet.ts`: these are the shapes the CLIENT expects on the
// wire. `@obliwan/shared` is owned by another agent this milestone, so the
// vocabularies (`IfOperStatusCode`, `RollupGranularity`, `SnmpThreshold`, …)
// are IMPORTED from there and never redeclared, while the transport envelopes
// below live here until the lead consolidates them into
// `shared/src/telemetry.ts`.
//
// ── ONE CONTRACT NOTE THAT MATTERS ──────────────────────────────────────────
// `shared/src/telemetry.ts` types the counters as `bigint` because the DATABASE
// stores `numeric(20,0)` (an unsigned Counter64 reaches 1.845e19, past bigint).
// What travels on THIS boundary is not a counter — it is a RATE, already
// divided by the window. A bit/s value is bounded by the line speed: 400 Gbit/s
// is 4e11, which is 13 000x below `Number.MAX_SAFE_INTEGER` (9.007e15).
// So every rate field below is a plain JSON `number`, and the server MUST NOT
// serialise them as strings — a string silently sorts "9" above "100" and
// renders "1000000000" instead of "1 Gbit/s".

import type {
  AlertEntityKind,
  IfOperStatusCode,
  InterfaceState,
  RollupGranularity,
  ThresholdComparator,
  ThresholdMetric,
  ThresholdScope,
  ThresholdSeverity,
  ThresholdState,
} from '@obliwan/shared';

// ── Series granularity ──────────────────────────────────────────────────────

/**
 * `raw` is the un-aggregated `snmp_if_samples` table; the other three are the
 * rollups. It is NOT a member of `RollupGranularity` in shared and must not be
 * folded into it: a rollup row carries `sampleCount`/`expectedCount` and a raw
 * row does not.
 */
export type SeriesGranularity = 'raw' | RollupGranularity;

// ── Interfaces ──────────────────────────────────────────────────────────────

/**
 * The freshest `snmp_if_samples` row for an interface, as the list endpoint
 * joins it. `null` when the interface has never produced a valid sample —
 * which is a real state (a target polled once has a baseline and no rate yet)
 * and must never render as zero traffic.
 */
export interface IfLastSample {
  ts: string;
  inBps: number;
  outBps: number;
  inPps: number;
  outPps: number;
  /** DELTA over the window, not the absolute counter. */
  inErrs: number;
  outErrs: number;
  inDiscards: number;
  outDiscards: number;
  elapsedMs: number;
  operStatus: IfOperStatusCode;
}

/**
 * One row of `snmp_interfaces`, joined with its device and last sample.
 *
 * `speedBps` is `null` — not 0 — when `ifHighSpeed`/`ifSpeed` is unknown.
 * 0 would mean "zero capacity" and would make every utilisation ratio divide
 * by zero or, worse, read as 100 %. Risk R12 lives here too: `ifIndex` is
 * displayed but is NEVER the identity; `(deviceId, ifName)` is.
 */
export interface NetInterface {
  id: number;
  deviceId: number;
  deviceName?: string | null;
  siteId?: number | null;
  siteName?: string | null;
  ifName: string;
  ifAlias: string | null;
  ifDescr: string | null;
  /** Last observed ifIndex. Informational only — see R12. */
  ifIndex: number | null;
  state: InterfaceState;
  vanishedAt: string | null;
  /** IF-MIB ifAdminStatus: 1 up, 2 down, 3 testing. */
  adminStatus: number | null;
  operStatus: IfOperStatusCode | null;
  /** bit/s. `null` = unknown, which forbids any utilisation figure. */
  speedBps: number | null;
  counterBits: 32 | 64;
  /** A 32-bit counter on a link fast enough to wrap inside the poll window. */
  counterUnreliable: boolean;
  needsRediscovery: boolean;
  /** Drives the rollup tiers this interface actually has (study §4.6). */
  effectivePollSec: number;
  /** IF-MIB ifType. Informational. */
  ifType?: number | null;
  /** Whether the poller is actually asking for this interface. */
  monitored?: boolean;
  lastSeenAt?: string | null;
  /**
   * COLLECTION HEALTH, from `snmp_poll_state` — and it is not cosmetic.
   * An interface whose every sample is being discarded produces an EMPTY
   * series, which on screen is indistinguishable from a link carrying no
   * traffic. These two fields are the only thing that tells them apart, so
   * the table and the chart panel both surface them.
   */
  lastDiscard?: string | null;
  consecutiveDiscards?: number;
  /** Only the fleet-wide list endpoint joins this. */
  lastSample: IfLastSample | null;
}

export interface InterfaceListParams {
  search?: string;
  deviceId?: number;
  siteId?: number;
  state?: InterfaceState;
  operStatus?: number;
}

// ── Series ──────────────────────────────────────────────────────────────────

/**
 * One point of an interface series.
 *
 * EVERY metric is nullable and that is the whole point: `null` means "not
 * measured", 0 means "measured, and it was zero". The chart must render the
 * first as a HOLE and the second as a value on the floor. Folding them
 * together invents traffic data, which is the one thing a monitoring product
 * may never do.
 */
export interface IfSeriesPoint {
  ts: string;
  inBps: number | null;
  outBps: number | null;
  inPps: number | null;
  outPps: number | null;
  /** Rollup tiers: the bucket maximum, so a burst averaged away at the 1 h
   *  tier is still visible. On the raw tier it equals the sample itself. */
  inMaxBps: number | null;
  outMaxBps: number | null;
  inErrs: number | null;
  outErrs: number | null;
  inDiscards: number | null;
  outDiscards: number | null;
  operStatus?: number | null;
  /** Not emitted by the current server; kept optional because the rollup
   *  tables carry them and a later revision may expose them. */
  sampleCount?: number;
  expectedCount?: number;
}

export interface IfSeriesResponse {
  ifId: number;
  /**
   * Echoed back by the server, which MAY DOWNGRADE our request: asking for
   * `raw` on a window older than the 48 h retention would otherwise return an
   * honest-looking empty array, indistinguishable from a silent link. The UI
   * labels the chart with what it RECEIVED, never with what it asked for.
   *
   * Named `resolution` to match the server's `SeriesResponse`.
   */
  resolution: SeriesGranularity;
  /** Nominal spacing between points, in seconds. For `raw` this is the
   *  interface's effective poll interval, not a bucket width. */
  bucketSec: number;
  from: string;
  to: string;
  points: IfSeriesPoint[];
  /** Buckets the server emitted as null because they were absent or
   *  under-sampled. Counted server-side; the client counts its own too. */
  gaps: number;
  /** True when a throughput chart must NOT be drawn at all: a 32-bit counter
   *  on a link fast enough to wrap more than once inside the poll window makes
   *  the rate a guess (study §3.2). */
  counterUnreliable: boolean;
  /** Line speed for the reference line, when the server provides it. */
  speedBps?: number | null;
}

export interface IfSeriesParams {
  from: string;
  to: string;
  granularity: SeriesGranularity;
}

// ── Thresholds ──────────────────────────────────────────────────────────────

/**
 * `SnmpThreshold` from shared, plus the joined labels the list screen needs.
 * Redeclared rather than extended so an added shared field cannot silently
 * change what this screen believes it is editing.
 */
export interface Threshold {
  id: number;
  uuid: string;
  tenantId: number;
  name: string;
  enabled: boolean;
  scope: ThresholdScope;
  deviceId: number | null;
  deviceName?: string | null;
  groupId: number | null;
  groupName?: string | null;
  ifId: number | null;
  ifName?: string | null;
  metric: ThresholdMetric;
  comparator: ThresholdComparator;
  value: number;
  /** Always > 0 — the database refuses NULL and refuses 0. */
  forSeconds: number;
  /** 0..50. */
  hysteresisPct: number;
  severity: ThresholdSeverity;
  channelId: number | null;
  /** Rollup the list endpoint may provide: how many entities are non-ok. */
  firingCount?: number;
  pendingCount?: number;
}

export interface ThresholdInput {
  name: string;
  enabled: boolean;
  scope: ThresholdScope;
  deviceId: number | null;
  groupId: number | null;
  ifId: number | null;
  metric: ThresholdMetric;
  comparator: ThresholdComparator;
  value: number;
  forSeconds: number;
  hysteresisPct: number;
  severity: ThresholdSeverity;
  channelId: number | null;
}

/** One row of `snmp_alert_state`, joined with the entity's label. */
export interface AlertStateRow {
  thresholdId: number;
  thresholdName?: string | null;
  entityKind: AlertEntityKind;
  entityId: number;
  entityLabel?: string | null;
  deviceId: number;
  deviceName?: string | null;
  state: ThresholdState;
  since: string;
  breachStartedAt: string | null;
  lastEvalAt: string;
  lastValue: number | null;
  notifiedAt: string | null;
  notificationCount: number;
}
