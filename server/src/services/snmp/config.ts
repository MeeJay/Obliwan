/**
 * M3 runtime knobs.
 *
 * These belong in `server/src/config.ts` with the rest of the process
 * configuration; that file is owned by another workstream, so they live here
 * and are read from `process.env` with the same discipline: every value is
 * validated, every fallback is documented, and a value that cannot be parsed
 * falls back LOUDLY (the caller logs it) rather than silently becoming 0.
 *
 * MOVING THEM LATER IS A COPY-PASTE. The names are already the ones a
 * `.env.example` would carry.
 */

function int(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const n = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(n) || n < min || n > max) return fallback;
  return n;
}

function bool(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  return /^(1|true|yes|on)$/i.test(raw.trim());
}

export const snmpConfig = {
  // -- Poller ---------------------------------------------------------------
  /** Default poll interval when `snmp_targets.poll_interval_sec` is NULL. The
   *  whole study is dimensioned on 30 s (scenario S30). */
  defaultPollIntervalSec: int('SNMP_POLL_INTERVAL_SEC', 30, 5, 86_400),
  /** Devices polled at the same time. 300 devices at a 30 s interval need 10
   *  starts per second; 24 in flight covers a fleet where a quarter of the
   *  devices are timing out at 2 s. */
  pollConcurrency: int('SNMP_POLL_CONCURRENCY', 24, 1, 256),
  /** Targets claimed per scheduler tick. */
  pollBatchSize: int('SNMP_POLL_BATCH', 64, 1, 1000),
  /** How often the scheduler looks for due targets. */
  schedulerTickMs: int('SNMP_SCHEDULER_TICK_MS', 1_000, 100, 60_000),
  /** Jitter applied to `next_poll_at`, as a percentage of the interval. Zero
   *  jitter means 300 devices are polled in the same 100 ms every 30 s, which
   *  is a self-inflicted burst on the tunnel and on the database alike. */
  pollJitterPct: int('SNMP_POLL_JITTER_PCT', 10, 0, 50),
  /** Interval between two full IF-MIB discoveries of a device. */
  discoveryIntervalSec: int('SNMP_DISCOVERY_INTERVAL_SEC', 3_600, 60, 86_400),

  // -- Rollups --------------------------------------------------------------
  rollupTickMs: int('SNMP_ROLLUP_TICK_MS', 60_000, 5_000, 600_000),

  // -- Trap receiver --------------------------------------------------------
  trapEnabled: bool('SNMP_TRAP_ENABLED', true),
  trapPort: int('SNMP_TRAP_PORT', 162, 1, 65_535),
  trapBind: process.env.SNMP_TRAP_BIND?.trim() || '0.0.0.0',
  /** Traps accepted per second, all sources combined, before shedding. */
  trapRateLimit: int('SNMP_TRAP_RATE_LIMIT', 200, 1, 100_000),

  // -- Syslog receiver ------------------------------------------------------
  syslogEnabled: bool('SYSLOG_ENABLED', true),
  syslogPort: int('SYSLOG_PORT', 514, 1, 65_535),
  syslogBind: process.env.SYSLOG_BIND?.trim() || '0.0.0.0',
  /**
   * Messages accepted per second per source IP.
   *
   * THE SYSLOG IS THE REAL BOTTLENECK OF M3, not the SNMP series (study
   * section 5.5): 1.04 GB/day at a modest 5 msg/device/min against 1.55 GB/day
   * for every SNMP series combined. One device in a log loop fills the volume
   * in a night and takes the supervision of 300 sites down with it.
   */
  syslogRateLimitPerSource: int('SYSLOG_RATE_LIMIT_PER_SOURCE', 50, 1, 100_000),
  /** Messages a source may write in one UTC day before the circuit breaker in
   *  `syslog_ingest_state` opens. 5 msg/min is 7 200/day; 50 000 leaves seven
   *  times that headroom and still stops a loop. */
  syslogDailyQuota: int('SYSLOG_DAILY_QUOTA', 50_000, 100, 100_000_000),
  /** How long a source stays suppressed once it blows its quota. */
  syslogSuppressMinutes: int('SYSLOG_SUPPRESS_MINUTES', 60, 1, 1_440),
  /** RFC 5424 severity floor AT INGESTION (<= is kept). What is filtered is
   *  never written: there is no "store everything and filter at display". */
  syslogSeverityFloor: int('SYSLOG_SEVERITY_FLOOR', 5, 0, 7),
  /** Rows per INSERT batch, and how long a message may wait for one. */
  syslogFlushBatch: int('SYSLOG_FLUSH_BATCH', 500, 1, 10_000),
  syslogFlushMs: int('SYSLOG_FLUSH_MS', 1_000, 50, 60_000),
  /**
   * Hard ceiling on the in-memory queue. THE POINT IS THE BOUND, not its
   * value: an unbounded buffer in front of a database turns a slow disk into
   * an OOM kill, and losing the supervision is worse than losing log lines.
   * Past this, messages are DROPPED and counted.
   */
  syslogQueueMax: int('SYSLOG_QUEUE_MAX', 20_000, 100, 1_000_000),
};

export type SnmpConfig = typeof snmpConfig;
