/**
 * M8 runtime knobs.
 *
 * A file of its own rather than three more lines in `services/snmp/config.ts`,
 * because that folder belongs to M3 and M8 only owns the syslog receiver
 * inside it. Same discipline as its neighbour: every value validated, every
 * fallback documented, a bad value falls back to the default rather than
 * silently becoming zero — a `0` on a rate limit is not "no limit", it is
 * "accept nothing", and it would take ingestion down without an error.
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

export const logsConfig = {
  // -- Syslog over TCP (RFC 6587) ------------------------------------------
  /**
   * Why TCP at all when UDP already works: UDP silently drops, and the one
   * message class M8 depends on — "user X logged in" — is exactly the one an
   * attribution cannot do without. A dropped counter sample is a gap in a
   * graph; a dropped login line is a change attributed to nobody.
   */
  syslogTcpEnabled: bool('SYSLOG_TCP_ENABLED', true),
  syslogTcpPort: int('SYSLOG_TCP_PORT', 514, 1, 65_535),
  syslogTcpBind: process.env.SYSLOG_TCP_BIND?.trim() || '0.0.0.0',
  /**
   * A bound on CONNECTIONS, not just on bytes. TCP moves the flooding problem
   * from "how many datagrams" to "how many sockets", and an unbounded accept
   * loop is a file-descriptor exhaustion that takes the API down with it.
   */
  syslogTcpMaxConnections: int('SYSLOG_TCP_MAX_CONNECTIONS', 256, 1, 10_000),
  /**
   * Longest single frame we will assemble. A sender that never emits a
   * delimiter would otherwise grow one buffer without limit — the same
   * unbounded-buffer failure the UDP path already refuses, arriving through a
   * different door.
   */
  syslogTcpMaxFrameBytes: int('SYSLOG_TCP_MAX_FRAME_BYTES', 64 * 1024, 1024, 1024 * 1024),
  /** A connection that says nothing for this long is closed. */
  syslogTcpIdleTimeoutMs: int('SYSLOG_TCP_IDLE_TIMEOUT_MS', 300_000, 5_000, 3_600_000),

  // -- RouterOS `/log` pull -------------------------------------------------
  /**
   * The pull path exists because the push path is lossy AND because a device
   * whose syslog was never configured still has a full local log. It is polled,
   * so it is leader-gated (A5): two pollers would double every row and race the
   * cursor.
   */
  routerosLogEnabled: bool('ROUTEROS_LOG_ENABLED', true),
  routerosLogIntervalSec: int('ROUTEROS_LOG_INTERVAL_SEC', 300, 30, 86_400),
  /** Devices pulled per tick, and how many at once. Conservative: this shares
   *  the single socket-per-device pool with everything else (R5). */
  routerosLogBatch: int('ROUTEROS_LOG_BATCH', 20, 1, 500),
  routerosLogConcurrency: int('ROUTEROS_LOG_CONCURRENCY', 4, 1, 64),
  /** Rows requested per device per cycle. RouterOS `/log` is a circular buffer;
   *  asking for the whole of it every five minutes is pointless traffic. */
  routerosLogMaxRows: int('ROUTEROS_LOG_MAX_ROWS', 200, 10, 5_000),
  routerosLogTimeoutMs: int('ROUTEROS_LOG_TIMEOUT_MS', 10_000, 1_000, 120_000),

  // -- Retention ------------------------------------------------------------
  /**
   * `device_login_events` is not partitioned: at a few dozen rows per device
   * per day it is four orders of magnitude below the series tables, and a
   * DELETE on it is cheap. 90 days so an attribution stays re-derivable well
   * past the 7-day syslog retention it came from.
   */
  loginEventRetentionDays: int('LOGIN_EVENT_RETENTION_DAYS', 90, 7, 3_650),
  retentionSweepMs: int('LOGS_RETENTION_SWEEP_MS', 6 * 3_600_000, 60_000, 24 * 3_600_000),

  // -- The out-of-tunnel probe (K7, fourth signal) --------------------------
  externalProbeEnabled: bool('EXTERNAL_PROBE_ENABLED', true),
  externalProbeTickMs: int('EXTERNAL_PROBE_TICK_MS', 30_000, 5_000, 600_000),
  externalProbeBatch: int('EXTERNAL_PROBE_BATCH', 32, 1, 500),
  externalProbeConcurrency: int('EXTERNAL_PROBE_CONCURRENCY', 8, 1, 128),
  /**
   * How many consecutive failures a probe WITH AN ESTABLISHED BASELINE must
   * accumulate before it reports `false`. One lost SYN is not a dead site, and
   * `external_ok = false` is one of the two signals that can produce
   * `SITE_DOWN` — the verdict that dispatches a technician.
   */
  externalProbeFailuresForDown: int('EXTERNAL_PROBE_FAILURES_FOR_DOWN', 3, 1, 100),
  /**
   * A probe result older than this is stale and reports `null`, not its last
   * value. "The prober has been dead for an hour" must never read as "the site
   * has been up for an hour".
   */
  externalProbeStaleSec: int('EXTERNAL_PROBE_STALE_SEC', 900, 60, 86_400),

  // -- Reachability freshness ----------------------------------------------
  /**
   * How long a `CONCENTRATOR_DEGRADED` verdict on a parent keeps suppressing
   * its children's verdicts. Bounded on purpose: a stuck degraded verdict that
   * never expires would silence a whole subtree for ever, which is the exact
   * opposite failure of the 300 alerts it exists to prevent.
   */
  concentratorDegradedTtlSec: int('CONCENTRATOR_DEGRADED_TTL_SEC', 900, 60, 86_400),
  /** SNMP counts as "answered" only if the last success is within this many
   *  poll intervals. Beyond it the signal is stale, and stale is `null`. */
  snmpOkIntervals: int('SNMP_OK_INTERVALS', 3, 1, 100),
};

export type LogsConfig = typeof logsConfig;
