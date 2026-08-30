// ObliWAN — telemetry and reachability contracts.
//
// `InterfaceSample` is the SNMP series shape (consumed at M3).
// `ReachabilityVerdict` is K7, and it is needed at M2 already: the acceptance
// criterion for the milestone is that UNREACHABLE reads differently from
// SITE_DOWN.

import type { DeviceFamily } from './device';

// ============================================================================
// K7 — the reachability verdict
// ============================================================================

/**
 * The verdict crosses FOUR independent signals so that one lying signal cannot
 * decide alone (risk R5: the CHR is a SPOF that lies — its own outage would
 * otherwise read as 300 dead sites).
 *
 *  - `UP`                    every signal agrees the device is reachable and
 *                            healthy.
 *  - `TUNNEL_DOWN_SITE_UP`   the PPP session is down but an independent signal
 *                            (external probe, recent CWMP Inform) says the site
 *                            is alive. The tunnel is the problem, not the site.
 *  - `SITE_DOWN`             POSITIVE knowledge that the site is dead: several
 *                            independent signals concur. Alertable.
 *  - `WAN_FAILOVER`          the site is reachable, but through a different
 *                            public address / path than the nominal one. The
 *                            silent failover that nothing else reports.
 *  - `CONCENTRATOR_DEGRADED` the CHR itself is unhealthy or unreachable through
 *                            its out-of-tunnel path. Every child verdict from
 *                            this concentrator is suppressed, not raised.
 *  - `UNREACHABLE`           WE DO NOT KNOW. Not enough independent evidence to
 *                            distinguish a dead site from a blind observer.
 *
 * `UNREACHABLE` and `SITE_DOWN` are NOT interchangeable and must never be
 * collapsed in the UI, in an alert, or in a query. `SITE_DOWN` means "we know
 * it is dead"; `UNREACHABLE` means "we cannot tell". Paging a technician to
 * drive to a site is a decision that belongs to the first, never the second.
 */
export const REACHABILITY_VERDICTS = [
  'UP',
  'TUNNEL_DOWN_SITE_UP',
  'SITE_DOWN',
  'WAN_FAILOVER',
  'CONCENTRATOR_DEGRADED',
  'UNREACHABLE',
] as const;
export type ReachabilityVerdict = (typeof REACHABILITY_VERDICTS)[number];

/** Verdicts that assert positive knowledge of an outage and may raise an
 *  alert. `UNREACHABLE` is deliberately absent: it is an observability
 *  problem, and it must be surfaced as such, not as a site outage. */
export const ALERTABLE_VERDICTS: readonly ReachabilityVerdict[] = [
  'SITE_DOWN',
  'CONCENTRATOR_DEGRADED',
] as const;

/**
 * The four independent signals, as read at verdict time. `null` means "not
 * measured / no data", which is a THIRD value distinct from `false` — folding
 * "we did not look" into "it failed" is precisely how SITE_DOWN gets invented.
 */
export interface ReachabilitySignals {
  /** PPP session present in the concentrator's `/ppp/active` (D4). */
  pppUp: boolean | null;
  /** SNMP answered through the tunnel. */
  snmpOk: boolean | null;
  /** An out-of-tunnel probe reached the site's public address. */
  externalOk: boolean | null;
  /** A CWMP Inform arrived recently enough to count as a live signal. */
  cwmpRecent: boolean | null;
}

/** One row of `reachability_verdicts`. */
export interface ReachabilityAssessment extends ReachabilitySignals {
  deviceId: number;
  ts: string;
  verdict: ReachabilityVerdict;
  /** 0..1 — how many independent signals actually backed the verdict. Low
   *  confidence on anything but `UNREACHABLE` is a bug in the truth table. */
  confidence: number;
}

// ============================================================================
// Presence — the socket payload behind `wan:site:presence`
// ============================================================================

/** Why a PPP session ended, as reported by the concentrator. Free-form on the
 *  wire; these are the values we normalise to. */
export type PppDisconnectReason = string;

/** Emitted when the concentrator's view of a device's presence changes. Sub-2s
 *  in the M2 acceptance test, because it rides `/ppp/active/listen` rather than
 *  a poll. */
export interface SitePresenceEvent {
  deviceId: number | null;
  siteId: number | null;
  concentratorId: number;
  pppUsername: string;
  /** true = session came up, false = session went down. */
  up: boolean;
  tunnelIp: string | null;
  callerIp: string | null;
  /** Best current verdict for the device, or `UNREACHABLE` while unknown. */
  verdict: ReachabilityVerdict;
  at: string;
}

// ============================================================================
// SNMP series (M3) — the shape M2 must not contradict
// ============================================================================

/**
 * One interface counter sample. Identity is the STABLE key `(deviceId, ifName)`
 * — never `ifIndex`, which is mutable across reboots and would silently move
 * the WAN counters into the LAN series (risk R12).
 */
export interface InterfaceSample {
  deviceId: number;
  /** Stable identity half. */
  ifName: string;
  /** Mutable; carried only to detect that it moved. */
  ifIndex: number;
  ts: string;
  /** 64-bit HC counters when the agent has them, else the 32-bit ones. */
  inOctets: bigint | null;
  outOctets: bigint | null;
  inErrors: number | null;
  outErrors: number | null;
  inDiscards: number | null;
  outDiscards: number | null;
  operUp: boolean | null;
  adminUp: boolean | null;
  speedBps: number | null;
  /** True when the counter went backwards or sysUpTime reset — the delta from
   *  the previous sample is meaningless and must be dropped, not clamped. */
  counterDiscontinuity: boolean;
}

/** Device-level sample (cpu / memory / temperature / uptime / rtt). */
export interface DeviceSample {
  deviceId: number;
  ts: string;
  cpuPercent: number | null;
  memoryUsedPercent: number | null;
  temperatureC: number | null;
  uptimeSeconds: number | null;
  reachable: boolean;
  rttMs: number | null;
}

/** What a probe learned about a unit, before it is folded into
 *  `device_capabilities`. */
export interface CapabilityProbeResult {
  deviceId: number;
  family: DeviceFamily;
  workingTransports: string[];
  failedTransports: string[];
  probedAt: string;
}

// ============================================================================
// SNMP series (M3) — the storage contract
// ============================================================================
//
// Everything below describes what `snmp_*` / `syslog_*` actually hold, as
// created by migrations 005_snmp.ts and 006_timeseries.ts. `InterfaceSample`
// and `DeviceSample` above stay exactly as M2 wrote them: they are the POLLER's
// view (raw counters, nullable, "what the agent answered"). The `*Row` types
// below are the DATABASE's view (rates, non-null, "what we decided to keep").
// Conflating the two is how a raw counter ends up on a graph axis.

/**
 * `snmp_interfaces.state`.
 *
 * An interface that disappears from the ifTable is NEVER deleted — it becomes
 * `vanished`. Deleting it would orphan (and, with a cascade, destroy) millions
 * of series rows, and it would erase the history of exactly the link somebody
 * is asking about *because* it disappeared.
 */
export const INTERFACE_STATES = ['active', 'vanished'] as const;
export type InterfaceState = (typeof INTERFACE_STATES)[number];

/** IF-MIB `ifOperStatus`, stored as the raw 1..7 integer. */
export const IF_OPER_STATUS = {
  up: 1,
  down: 2,
  testing: 3,
  unknown: 4,
  dormant: 5,
  notPresent: 6,
  lowerLayerDown: 7,
} as const;
export type IfOperStatusName = keyof typeof IF_OPER_STATUS;
export type IfOperStatusCode = (typeof IF_OPER_STATUS)[IfOperStatusName];

const IF_OPER_STATUS_NAMES: readonly IfOperStatusName[] = [
  'up', 'down', 'testing', 'unknown', 'dormant', 'notPresent', 'lowerLayerDown',
];

/** 1..7 -> name. Anything else is a decode bug and reads as `unknown`. */
export function ifOperStatusName(code: number): IfOperStatusName {
  return IF_OPER_STATUS_NAMES[code - 1] ?? 'unknown';
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

export const SNMP_VERSIONS = ['v1', 'v2c', 'v3'] as const;
export type SnmpVersion = (typeof SNMP_VERSIONS)[number];

export const SNMP_SECURITY_LEVELS = ['noAuthNoPriv', 'authNoPriv', 'authPriv'] as const;
export type SnmpSecurityLevel = (typeof SNMP_SECURITY_LEVELS)[number];

export const SNMP_AUTH_PROTOCOLS = ['md5', 'sha', 'sha224', 'sha256', 'sha384', 'sha512'] as const;
export type SnmpAuthProtocol = (typeof SNMP_AUTH_PROTOCOLS)[number];

export const SNMP_PRIV_PROTOCOLS = ['des', '3des', 'aes', 'aes128', 'aes192', 'aes256'] as const;
export type SnmpPrivProtocol = (typeof SNMP_PRIV_PROTOCOLS)[number];

/**
 * A credential as the API hands it out. There is deliberately NO field for the
 * community or the keys: the ciphertext never leaves the server, and a
 * "masked" plaintext field is how a secret eventually reaches a log.
 */
export interface SnmpCredentialSummary {
  id: number;
  uuid: string;
  tenantId: number;
  name: string;
  version: SnmpVersion;
  username: string | null;
  securityLevel: SnmpSecurityLevel | null;
  authProtocol: SnmpAuthProtocol | null;
  privProtocol: SnmpPrivProtocol | null;
  context: string | null;
  /** True when a ciphertext is present. Never the value, never its length. */
  hasCommunity: boolean;
  hasAuthKey: boolean;
  hasPrivKey: boolean;
}

// ---------------------------------------------------------------------------
// The delta calculation
// ---------------------------------------------------------------------------

/**
 * Why a sample was not written. Each value is an exported counter
 * (`series_discard_total{reason}`) — that is the point of enumerating them
 * rather than logging a string.
 */
export const DISCARD_REASONS = [
  'NO_BASELINE',        // first poll of this interface, or an invalidated baseline
  'PROCESS_RESTART',    // different writer_epoch: mono_ns is not comparable
  'IFINDEX_REMAP',      // ifName at if_index no longer matches (risk R12)
  'DEVICE_REBOOT',      // sysUpTime went backwards, and not by a wrap
  'COUNTER_RESET',      // Counter64 went backwards, or an unexplainable Counter32 drop
  'WINDOW_TOO_SHORT',   // elapsed < 0.5x expected
  'WINDOW_TOO_LONG',    // elapsed > 3x expected
  'AMBIGUOUS_WRAP',     // Counter32: more than one wrap fits in the window
  'OVER_LINE_SPEED',    // rate > ifHighSpeed x 1.05
  'COUNTER_UNRELIABLE', // 32-bit counter, link too fast for the interval
  'AGENT_ERROR',        // noSuchInstance / partial timeout on a required varbind
] as const;
export type DiscardReason = (typeof DISCARD_REASONS)[number];

/**
 * One row of `snmp_poll_state` — the persisted delta baseline.
 *
 * Counters are `bigint` in TypeScript and `numeric(20,0)` in PostgreSQL, NOT
 * `bigint` in PostgreSQL: ifHCInOctets is an UNSIGNED Counter64 ranging to
 * 1.845e19 while PG's bigint stops at 9.22e18. A JS `bigint` is unbounded, so
 * the TS side is safe either way; the database side is not.
 */
export interface PollState {
  ifId: number;
  deviceId: number;
  /** Wall clock of the previous read. The fallback denominator after a restart. */
  wallTs: string;
  /** `process.hrtime.bigint()` of the previous read. The denominator DURING the
   *  life of a process — immune to an NTP step, meaningless across processes. */
  monoNs: bigint;
  /** Identifies the process that wrote this baseline. A different value means
   *  `monoNs` must not be used. */
  writerEpoch: string;
  inOctets: bigint;
  outOctets: bigint;
  inPkts: bigint;
  outPkts: bigint;
  inErrs: bigint;
  outErrs: bigint;
  inDiscards: bigint;
  outDiscards: bigint;
  /** Width ACTUALLY obtained for this interface, which can differ from the
   *  target's `supportsHcCounters`: an agent may advertise HC counters and
   *  still answer noSuchObject on one port. */
  counterBits: 32 | 64;
  /** Device sysUpTime in TimeTicks (1/100 s). The only reliable reboot signal. */
  sysUptimeTicks: bigint;
  /** How many times sysUpTime has wrapped (it wraps every 497.1 days — a
   *  branch RouterOS really does reach that). */
  sysUptimeEpoch: number;
  /** Link speed in bit/s at the last poll. 0 = unknown, which means NO CLAMP IS
   *  POSSIBLE — not "zero capacity". */
  lineSpeedBps: bigint;
  lastDiscard: DiscardReason | null;
  consecutiveDiscards: number;
}

/** One row of `snmp_if_samples`. Rates, already computed and already validated
 *  — never raw counters (principle (e) of the study). */
export interface IfSampleRow {
  ifId: number;
  ts: string;
  inBps: bigint;
  outBps: bigint;
  inPps: number;
  outPps: number;
  /** DELTA over the window, not the absolute counter. */
  inErrs: number;
  outErrs: number;
  inDiscards: number;
  outDiscards: number;
  /** The real width of the delta window, kept so a rate stays auditable. */
  elapsedMs: number;
  operStatus: IfOperStatusCode;
}

/**
 * The result of one rate computation.
 *
 * `nextBaseline` is present EVEN ON A DISCARD, and that is the easiest thing in
 * this whole subsystem to get wrong: rejecting a sample without refreshing the
 * baseline condemns the interface to reject forever. The typical case is a
 * reboot, where we must both drop the sample AND restart from the zeroed
 * counters. Only `AGENT_ERROR` — where we have no coherent read at all — leaves
 * it null.
 *
 * `clamped` travels all the way to the written row: a clamped sample is one we
 * know was retouched. If the clamp rate rises above a few per mille, it means
 * `ifHighSpeed` is wrong on the equipment, not that the traffic is high.
 */
export type RateResult =
  | { kind: 'sample'; sample: IfSampleRow; clamped: boolean; nextBaseline: PollState }
  | { kind: 'discard'; reason: DiscardReason; nextBaseline: PollState | null };

// ---------------------------------------------------------------------------
// Device samples — and their sentinels
// ---------------------------------------------------------------------------

/**
 * `snmp_device_samples` uses SENTINELS RATHER THAN NULL. That is a storage
 * decision (a null bitmap would push t_hoff from 24 to 32 bytes, +10 % on a
 * 76-byte row for three rarely-absent columns), and it is a trap for anybody
 * who renders the value straight: -1 % CPU is not a reading.
 *
 * ALWAYS pass through `unsentinel()` before display or aggregation.
 */
export const SENTINEL = {
  /** `cpu_pct`, `rtt_us`, `mem_used_bytes`, `mem_total_bytes`: not exposed / not measured. */
  NOT_AVAILABLE: -1,
  /** `temp_dc` only: -1 is a legitimate temperature (-0.1 degC), so the
   *  sentinel has to live outside the value domain. */
  TEMP_NOT_AVAILABLE: -32768,
} as const;

/** Sentinel -> null, for anything that is about to be displayed or averaged. */
export function unsentinel(value: number, sentinel: number = SENTINEL.NOT_AVAILABLE): number | null {
  return value === sentinel ? null : value;
}

/** One row of `snmp_device_samples`. Unlike interfaces, a row IS written when
 *  the device did not answer: `reachable = false` is information (it feeds the
 *  availability graph), not a doubt about a value. */
export interface DeviceSampleRow {
  deviceId: number;
  ts: string;
  uptimeTicks: bigint;
  /** SENTINEL.NOT_AVAILABLE when not exposed. */
  memUsedBytes: bigint;
  memTotalBytes: bigint;
  /** Microseconds. SENTINEL.NOT_AVAILABLE when not measured. */
  rttUs: number;
  /** 0..100, or SENTINEL.NOT_AVAILABLE. */
  cpuPct: number;
  /** Tenths of a degree C, or SENTINEL.TEMP_NOT_AVAILABLE. */
  tempDc: number;
  reachable: boolean;
}

// ---------------------------------------------------------------------------
// Rollups
// ---------------------------------------------------------------------------

export const ROLLUP_GRANULARITIES = ['1m', '5m', '1h'] as const;
export type RollupGranularity = (typeof ROLLUP_GRANULARITIES)[number];

/** Bucket width, in seconds. */
export const ROLLUP_BUCKET_SECONDS: Record<RollupGranularity, number> = {
  '1m': 60,
  '5m': 300,
  '1h': 3600,
};

/** `series_rollup_state.tier` — one watermark per (subject, granularity). */
export const SERIES_TIERS = ['if_1m', 'if_5m', 'if_1h', 'dev_1m', 'dev_5m', 'dev_1h'] as const;
export type SeriesTier = (typeof SERIES_TIERS)[number];

/**
 * Which rollup tiers make sense for a given poll interval (study §4.6).
 *
 * Above a 60 s poll the 1-minute tier stops meaning anything: most buckets
 * would be empty and the rest would hold a single sample. Without this filter a
 * fleet moved to a 5-minute poll would fill `snmp_if_rollup_1m` with 3.45 M
 * rows/day of which 80 % are empty buckets — MORE ROLLUP ROWS THAN RAW DATA.
 */
export function rollupTiersFor(effectivePollSec: number): RollupGranularity[] {
  if (effectivePollSec <= 60) return ['1m', '5m', '1h'];
  if (effectivePollSec <= 300) return ['5m', '1h'];
  return ['1h'];
}

/**
 * One row of `snmp_if_rollup_1m` / `_5m` / `_1h`.
 *
 * `sampleCount` / `expectedCount` is the GAP MECHANISM: it is what tells
 * "0 bit/s" apart from "we did not measure". Display rule, and it is not
 * optional — `sampleCount < expectedCount / 2` means the API emits `null` and
 * the chart does not connect across the hole.
 *
 * CAVEAT ON p95 AT THE 1-MINUTE TIER: at a 30 s poll a one-minute bucket holds
 * two samples, and a 95th percentile over two values IS the maximum. The
 * columns exist for schema uniformity across the three tiers. THE UI MUST NOT
 * LABEL THEM "p95" AT THE 1m TIER.
 */
export interface IfRollupRow {
  ifId: number;
  bucket: string;
  inAvgBps: bigint;
  inMaxBps: bigint;
  inP95Bps: bigint;
  outAvgBps: bigint;
  outMaxBps: bigint;
  outP95Bps: bigint;
  inErrs: number;
  outErrs: number;
  inDiscards: number;
  outDiscards: number;
  sampleCount: number;
  expectedCount: number;
}

/** One row of `snmp_device_rollup_1m` / `_5m` / `_1h`. */
export interface DeviceRollupRow {
  deviceId: number;
  bucket: string;
  memUsedAvgBytes: bigint;
  memUsedMaxBytes: bigint;
  memTotalBytes: bigint;
  uptimeTicksMax: bigint;
  rttAvgUs: number;
  rttMaxUs: number;
  rttP95Us: number;
  cpuAvgPct: number;
  cpuMaxPct: number;
  tempAvgDc: number;
  tempMaxDc: number;
  /** How many of `sampleCount` answered. 0 with a full sampleCount is a device
   *  that was down for the whole bucket — that is NOT a gap. */
  reachableCount: number;
  sampleCount: number;
  expectedCount: number;
}

/** True when a bucket carries too few samples to be drawn as a value. */
export function isRollupGap(sampleCount: number, expectedCount: number): boolean {
  return sampleCount < expectedCount / 2;
}

// ---------------------------------------------------------------------------
// Thresholds and alert state
// ---------------------------------------------------------------------------

export const THRESHOLD_SCOPES = ['global', 'tenant', 'group', 'device', 'interface'] as const;
export type ThresholdScope = (typeof THRESHOLD_SCOPES)[number];

export const THRESHOLD_COMPARATORS = ['gt', 'gte', 'lt', 'lte'] as const;
export type ThresholdComparator = (typeof THRESHOLD_COMPARATORS)[number];

export const THRESHOLD_SEVERITIES = ['info', 'warning', 'critical'] as const;
export type ThresholdSeverity = (typeof THRESHOLD_SEVERITIES)[number];

export const THRESHOLD_METRICS = [
  'if_in_bps', 'if_out_bps', 'if_in_util_pct', 'if_out_util_pct',
  'if_in_errs', 'if_out_errs', 'if_in_discards', 'if_out_discards', 'if_oper_status',
  'dev_cpu_pct', 'dev_mem_pct', 'dev_temp_dc', 'dev_rtt_us', 'dev_reachable',
] as const;
export type ThresholdMetric = (typeof THRESHOLD_METRICS)[number];

/**
 * `snmp_alert_state.state`.
 *
 *  - `ok`      the condition is not met.
 *  - `pending` the condition IS met but `forSeconds` has not elapsed yet. This
 *              state is not cosmetic: folding it into `ok` makes the dwell
 *              timer unobservable and impossible to debug.
 *  - `firing`  the condition has held for `forSeconds`. Notified once; it does
 *              not re-notify until it has cleared through the hysteresis band.
 */
export const THRESHOLD_STATES = ['ok', 'pending', 'firing'] as const;
export type ThresholdState = (typeof THRESHOLD_STATES)[number];

export const ALERT_ENTITY_KINDS = ['interface', 'device'] as const;
export type AlertEntityKind = (typeof ALERT_ENTITY_KINDS)[number];

/**
 * One row of `snmp_thresholds`.
 *
 * `forSeconds` and `hysteresisPct` are MANDATORY in the database — NOT NULL and
 * with no default — because they are the two mechanisms that stop an alert
 * re-notifying in a loop. `forSeconds` stops one 30-second spike from paging
 * anybody; `hysteresisPct` stops a value parked on the boundary from
 * firing/clearing/firing every cycle forever.
 */
export interface SnmpThreshold {
  id: number;
  uuid: string;
  tenantId: number;
  name: string;
  enabled: boolean;
  scope: ThresholdScope;
  deviceId: number | null;
  groupId: number | null;
  ifId: number | null;
  metric: ThresholdMetric;
  comparator: ThresholdComparator;
  value: number;
  /** How long the condition must hold before firing. Always > 0. */
  forSeconds: number;
  /** How far back past the threshold the value must come to clear, as a
   *  percentage of `value`. 0..50. */
  hysteresisPct: number;
  severity: ThresholdSeverity;
  channelId: number | null;
}

/** One row of `snmp_alert_state`, keyed by (thresholdId, entityKind, entityId). */
export interface SnmpAlertState {
  thresholdId: number;
  entityKind: AlertEntityKind;
  entityId: number;
  deviceId: number;
  state: ThresholdState;
  /** When the CURRENT state began — drives "firing for 4 h". */
  since: string;
  /** When the condition first breached: the start of the forSeconds timer.
   *  Distinct from `since` on the ok -> pending -> firing path. */
  breachStartedAt: string | null;
  lastEvalAt: string;
  lastValue: number | null;
  notifiedAt: string | null;
  notificationCount: number;
}

/**
 * The clear threshold for a firing alert, given its comparator.
 *
 * For a `gt`/`gte` rule the value must fall BELOW `value * (1 - h)`; for a
 * `lt`/`lte` rule it must rise ABOVE `value * (1 + h)`. Applying hysteresis in
 * the wrong direction makes an alert impossible to clear, which looks exactly
 * like a stuck alert.
 */
export function alertClearValue(
  value: number,
  comparator: ThresholdComparator,
  hysteresisPct: number,
): number {
  const factor = hysteresisPct / 100;
  return comparator === 'gt' || comparator === 'gte'
    ? value * (1 - factor)
    : value * (1 + factor);
}

// ---------------------------------------------------------------------------
// Syslog
// ---------------------------------------------------------------------------

/** RFC 5424 numeric severities. Stored as the number, never as a label: the
 *  label set differs per RFC and per vendor, the number does not. */
export const SYSLOG_SEVERITY = {
  emergency: 0,
  alert: 1,
  critical: 2,
  error: 3,
  warning: 4,
  notice: 5,
  informational: 6,
  debug: 7,
} as const;
export type SyslogSeverityName = keyof typeof SYSLOG_SEVERITY;
export type SyslogSeverityCode = (typeof SYSLOG_SEVERITY)[SyslogSeverityName];

/**
 * Default ingestion floor: `notice` and above (numerically <= 5).
 *
 * Applied AT INGESTION. What is filtered is never written — there is no "store
 * everything and filter at display". The syslog is the dominant disk consumer
 * of M3 (1.04 GB/day at a modest 5 msg/device/min, against 1.55 GB/day for all
 * the SNMP series combined) and a single device in a log loop fills the volume,
 * and therefore takes the whole supervision down, in one night.
 */
export const SYSLOG_DEFAULT_SEVERITY_FLOOR: SyslogSeverityCode = SYSLOG_SEVERITY.notice;

// ---------------------------------------------------------------------------
// Partitions
// ---------------------------------------------------------------------------

/** Partition granularity of a series table, as stored in
 *  `series_partition_policy.grain`. */
export const PARTITION_GRAINS = ['day', 'week', 'month'] as const;
export type PartitionGrain = (typeof PARTITION_GRAINS)[number];

/**
 * One row of `series_partition_policy`.
 *
 * Retention is enforced by DROPPING a partition, NEVER by DELETE. On 6.9 M rows
 * a DELETE takes 60-300 s, writes ~1.4 GB of WAL, returns zero space to the OS,
 * and makes autovacuum reuse pages in the middle of an append-only file — which
 * destroys the physical correlation the BRIN index depends on. You lose the
 * space AND the index. A DROP takes under 50 ms.
 */
export interface SeriesPartitionPolicy {
  parent: string;
  grain: PartitionGrain;
  /** The partitioning column: `ts`, `bucket`, or `received_at` for syslog. */
  partColumn: string;
  /** PostgreSQL interval literal, e.g. '48:00:00' or '7 days'. */
  retention: string;
  /** How many `grain` units ahead partitions are pre-created. 14 days for the
   *  daily tables: an empty partition costs ~24 KB, and it buys a server that
   *  can be down 13 days, a restore from last week's backup that works
   *  immediately, and 13 consecutive failures of the maintenance job before
   *  anybody loses a data point. */
  precreateUnits: number;
  enabled: boolean;
}
