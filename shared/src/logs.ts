// ============================================================================
// @obliwan/shared — M8: unified logs, login events and drift attribution (K6)
// ============================================================================
//
// The contract behind three things that are usually conflated and must not be:
//
//   1. A LOG LINE   — what an equipment said. Syslog, an SNMP trap, or a row of
//                     RouterOS `/log`. Three transports, one reading surface.
//   2. A LOGIN EVENT — the subset of log lines that says WHO opened a session
//                     on the box, from WHERE, and through WHICH door.
//   3. AN ATTRIBUTION — the *conclusion* that a configuration change is
//                     explained by one of those sessions. It is a judgement,
//                     it carries a score, and it is allowed to say "no".
//
// ┌─ THE RULE THAT GOVERNS THIS ENTIRE FILE ─────────────────────────────────┐
// │ `unattributed` IS A RESULT, NOT A FAILURE.                               │
// │                                                                          │
// │ A wrong attribution is strictly worse than no attribution, because it    │
// │ will be believed: it names a colleague in an incident review, it ends up │
// │ in a customer report, and nothing downstream re-checks it. So the        │
// │ vocabulary below has FIVE verdicts and only one of them names somebody.  │
// │ `ambiguous` exists so that "two people were logged in" never silently    │
// │ collapses into "the first one did it".                                   │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ AND THE ONE THAT GOVERNS IDENTITY (arbitrage A6) ───────────────────────┐
// │ `UnifiedLogEntry.sourceIp` is the address the DATAGRAM came from. Behind │
// │ the Docker bridge that is the gateway, not the router. It is forensic    │
// │ material and NEVER an identity.                                          │
// │                                                                          │
// │ `DeviceLoginEvent.sourceIp` is a DIFFERENT address with a different      │
// │ meaning: it is parsed out of the message TEXT and it is the address of   │
// │ the HUMAN who opened the session. That one identifies a person's         │
// │ workstation, which is exactly what attribution needs, and it is the      │
// │ reason the two fields do not share a name in the same object.            │
// └──────────────────────────────────────────────────────────────────────────┘

// ============================================================================
// Log sources
// ============================================================================

/**
 * Where a unified log entry came from. Kept as three values rather than merged
 * into "logs", because the failure modes differ: syslog is pushed and lossy,
 * a trap is pushed and structured, `/log` is PULLED by us and therefore the
 * only one that survives a lost datagram.
 */
export const LOG_SOURCES = ['syslog', 'trap', 'routeros_log'] as const;
export type LogSource = (typeof LOG_SOURCES)[number];

/** RFC 5424 severities, index = numeric value. 0 is the worst. */
export const SYSLOG_SEVERITY_LABELS = [
  'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug',
] as const;
export type SyslogSeverityLabel = (typeof SYSLOG_SEVERITY_LABELS)[number];

export function syslogSeverityLabel(severity: number): SyslogSeverityLabel | 'unknown' {
  return SYSLOG_SEVERITY_LABELS[severity] ?? 'unknown';
}

/** RFC 5424 facilities, index = numeric value. */
export const SYSLOG_FACILITY_LABELS = [
  'kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
  'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7',
] as const;

export function syslogFacilityLabel(facility: number): string {
  return SYSLOG_FACILITY_LABELS[facility] ?? 'unknown';
}

/**
 * One row of the unified journal. The three sources are normalised onto this
 * shape at READ time, not at write time: a trap keeps its varbinds and a
 * syslog line keeps its RFC fields in their own tables, because reprocessing a
 * trap with a better MIB mapping must not have destroyed what the box sent.
 */
export interface UnifiedLogEntry {
  source: LogSource;
  /** OUR receive clock, always present, always monotonic enough to sort on. */
  receivedAt: string;
  /**
   * The equipment's own clock, when it sent one. The GAP between this and
   * `receivedAt` is diagnostic in itself — it is how a fleet with no NTP
   * becomes visible.
   */
  deviceTs: string | null;
  /** NULL when nothing in the payload matched a device. Never guessed from the
   *  source IP (A6). */
  deviceId: number | null;
  deviceName: string | null;
  /** RFC 5424 severity, 0..7. Traps and `/log` rows are mapped onto the same
   *  scale so one filter covers the three sources. */
  severity: number;
  severityLabel: SyslogSeverityLabel | 'unknown';
  facility: number | null;
  /** Syslog HOSTNAME, or the trap's sysName varbind. What the box CLAIMS to be. */
  hostname: string | null;
  /** Syslog APP-NAME, RouterOS topic list, or the trap OID. */
  tag: string | null;
  message: string;
  /** Socket-level peer address. FORENSICS ONLY — see the header. */
  sourceIp: string | null;
  /** Structured extras: trap varbinds, RFC 5424 SD, parsed vendor fields. */
  extra: Record<string, unknown>;
}

// ============================================================================
// Login events
// ============================================================================

/**
 * The door a session came through. `unknown` is a first-class value: a parser
 * that recognised a login but not its transport must say so rather than pick
 * the most likely one.
 */
export const LOGIN_METHODS = [
  'winbox', 'ssh', 'telnet', 'api', 'web', 'ftp', 'console', 'serial', 'vpn', 'unknown',
] as const;
export type LoginMethod = (typeof LOGIN_METHODS)[number];

/**
 * Methods through which a configuration can actually be written. `ftp` moves
 * files (so it can replace a config file, hence its presence) but a `vpn`
 * session is a user of the SERVICE, not an administrator of the box — it can
 * never explain a config change and must not score as if it could.
 */
export const WRITE_CAPABLE_LOGIN_METHODS: readonly LoginMethod[] = [
  'winbox', 'ssh', 'telnet', 'api', 'web', 'console', 'serial', 'ftp',
] as const;

export const LOGIN_EVENT_KINDS = ['login', 'logout', 'login_failed'] as const;
export type LoginEventKind = (typeof LOGIN_EVENT_KINDS)[number];

/** How we learned about the event. */
export const LOGIN_EVENT_ORIGINS = ['syslog', 'routeros_log'] as const;
export type LoginEventOrigin = (typeof LOGIN_EVENT_ORIGINS)[number];

/**
 * Account names that DO NOT DESIGNATE A PERSON.
 *
 * This list is the whole of point 1 of the milestone made mechanical. When a
 * change is attributed to `admin`, the honest statement is "somebody used the
 * shared admin account from 10.0.0.5" — the source IP is then the only thing
 * that narrows it down to a human, and the UI must say so instead of printing
 * a name next to a face.
 *
 * Matching is case-insensitive and also covers the `admin@site` /
 * `admin+winbox` decorations RouterOS and Zyxel append.
 */
export const SHARED_ACCOUNT_NAMES: readonly string[] = [
  'admin', 'administrator', 'root', 'user', 'support', 'operator', 'manager',
  'service', 'sysadmin', 'netadmin', 'supervisor', 'guest', 'mikrotik',
  'draytek', 'zyxel', 'sonicwall', 'default', 'installer', 'technician',
] as const;

/** True when the account is a role, not a person. */
export function isSharedAccount(account: string | null | undefined): boolean {
  if (!account) return false;
  // RouterOS logs `admin+cte` / `admin@ppp`; Zyxel logs `admin(1)`. Strip the
  // decoration before comparing, or every decorated shared login silently
  // reads as a named individual.
  const bare = account.trim().toLowerCase().split(/[@+([]/, 1)[0].trim();
  return SHARED_ACCOUNT_NAMES.includes(bare);
}

export interface DeviceLoginEvent {
  id: string;
  deviceId: number;
  deviceName: string | null;
  /** OUR clock. What the window arithmetic uses — see `AttributionWindow`. */
  ts: string;
  /** The equipment's clock, verbatim, when it gave one. */
  deviceTs: string | null;
  event: LoginEventKind;
  account: string;
  /** `admin` designates nobody. Carried on the row so no consumer has to
   *  re-derive it, and so a future edit of the list cannot silently rewrite
   *  history. */
  sharedAccount: boolean;
  method: LoginMethod;
  /** The HUMAN's address, parsed from the message text. Not the datagram's. */
  sourceIp: string | null;
  origin: LoginEventOrigin;
  message: string;
}

// ============================================================================
// K6 — attribution
// ============================================================================

/**
 * The five possible answers, and why there are five.
 *
 *  - `attributed`    one session explains the change well enough to be named.
 *  - `platform`      ObliWAN itself wrote the box (a `change_jobs` row overlaps
 *                    the window). Naming a human for our own write would be the
 *                    most damaging false positive of the lot.
 *  - `ambiguous`     several sessions fit and none stands out. We know somebody
 *                    did it and we refuse to pick. This is NOT a degraded
 *                    `attributed`; it is a different statement.
 *  - `unattributed`  no session explains it. Explicit, expected, and a finding
 *                    in its own right: a change with no trace is either an
 *                    out-of-band access or a device whose logs never reach us.
 *  - `excluded`      the drift run itself is not attributable — we changed the
 *                    normalisation rules or the model version, so the diff is
 *                    ours (§6.5). Never a human's.
 */
export const ATTRIBUTION_VERDICTS = [
  'attributed', 'platform', 'ambiguous', 'unattributed', 'excluded',
] as const;
export type AttributionVerdict = (typeof ATTRIBUTION_VERDICTS)[number];

/** Verdicts that put a name on a change. Exactly one, on purpose. */
export const NAMING_ATTRIBUTION_VERDICTS: readonly AttributionVerdict[] = ['attributed'] as const;

/**
 * One session that was CONSIDERED, with the arithmetic that ranked it. Stored
 * with the attribution and shown in the UI: an operator who disagrees with a
 * verdict must be able to see the other candidates and the numbers, otherwise
 * the score is an oracle and nobody can argue with it.
 */
export interface AttributionCandidate {
  loginEventId: string;
  account: string;
  sharedAccount: boolean;
  method: LoginMethod;
  sourceIp: string | null;
  loginAt: string;
  /** When the session ended, or null if it was still open at the window's end. */
  logoutAt: string | null;
  /**
   * How strongly this session is PLACED to explain the change, 0..1. Ranking
   * uses this and nothing else — see `ATTRIBUTION_TUNING` for why the account
   * name is deliberately kept out of it.
   */
  evidence: number;
  /** `evidence`, reduced when the account names nobody. Reported, never ranked. */
  score: number;
  /** The three weighted terms, so a score can be explained without re-running. */
  components: {
    temporalFit: number;
    exclusivity: number;
    methodFit: number;
  };
}

/**
 * The window inside which the change must have happened.
 *
 * NOT a fixed lookback. `from` is the moment the OLD configuration was last
 * CONFIRMED still true (`config_snapshots.last_seen_at` of the baseline) and
 * `to` is the moment the new one was captured. Anything outside that interval
 * provably cannot explain the diff, and a fixed 24 h window would drag in
 * sessions from before the config was last verified identical.
 */
export interface AttributionWindow {
  from: string;
  to: string;
  /** Seconds. Wide windows are weak evidence and the UI must be able to say so
   *  without recomputing the subtraction. */
  spanSeconds: number;
}

export interface DriftAttribution {
  id: string;
  runId: string;
  deviceId: number;
  deviceName: string | null;
  verdict: AttributionVerdict;
  /** 0..1. Meaningless for `unattributed` / `excluded`, where it is 0. */
  score: number;
  /** Machine-readable reason for the verdict. The UI translates it; nothing
   *  parses the human sentence. */
  reason: string;
  window: AttributionWindow;
  /** Populated only for `attributed`. */
  account: string | null;
  sharedAccount: boolean;
  sourceIp: string | null;
  method: LoginMethod | null;
  loginEventId: string | null;
  /** Populated only for `platform`. */
  changeJobId: string | null;
  candidates: AttributionCandidate[];
  createdAt: string;
}

/**
 * Scoring knobs, exported so the server and the UI agree on the same numbers
 * and a threshold change is one edit rather than two.
 *
 * ┌─ WHY THE ACCOUNT NAME IS NOT ONE OF THE WEIGHTS ─────────────────────────┐
 * │ The obvious design gives a named account a scoring bonus over a shared    │
 * │ one. It is wrong, and subtly so: "how identifiable is this account" is    │
 * │ not "how likely is it that this session made the change". Under that      │
 * │ design, `alice` and `admin` logged in at the same minute would resolve to │
 * │ `alice` — an accusation produced by nothing but the fact that her name is │
 * │ more specific than his role.                                              │
 * │                                                                          │
 * │ So EVIDENCE (three terms, summing to 1) does the ranking, and the shared  │
 * │ account applies a flat confidence multiplier afterwards. It can lower a   │
 * │ verdict below the naming threshold; it can never re-order two candidates. │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export const ATTRIBUTION_TUNING = {
  /** The three evidence terms. They sum to 1 and they alone decide the ranking. */
  weightTemporal: 0.5,
  weightExclusivity: 0.3,
  weightMethod: 0.2,
  /**
   * Multiplier applied to a shared account's evidence. Not a penalty for being
   * `admin`: an acknowledgement that "the admin account did it" is a weaker
   * statement about a PERSON than "alice did it", even when it is an equally
   * strong statement about a session.
   */
  sharedAccountConfidence: 0.8,
  /**
   * Floor of the temporal term for a session that was open during the window
   * but started before it. It never reaches zero, because such a session
   * genuinely was on the box; it never reaches one, because we cannot place
   * its beginning inside the interval the change happened in.
   */
  minTemporalFit: 0.3,
  /** Below this, the best candidate is not good enough to name: `unattributed`. */
  minScore: 0.55,
  /**
   * Two candidates within this distance of each other are indistinguishable
   * and the verdict is `ambiguous`. Without this margin the ranking would
   * always produce a winner, which is precisely how a coincidence becomes an
   * accusation.
   */
  ambiguityMargin: 0.15,
  /**
   * A session that opened this long BEFORE the window may still explain the
   * change (the operator logged in, then worked). Across that hour the
   * temporal term decays from 1 to `minTemporalFit`.
   */
  preWindowGraceSeconds: 3600,
} as const;

// ============================================================================
// Query shapes
// ============================================================================

export interface LogQuery {
  deviceId?: number;
  /** Inclusive upper bound on the stored NUMBER, i.e. a lower bound on
   *  importance: `maxSeverity: 4` returns emerg..warning. Named for what it
   *  does to the value actually stored. */
  maxSeverity?: number;
  sources?: LogSource[];
  from?: string;
  to?: string;
  /** Substring match on the message. */
  search?: string;
  limit?: number;
  offset?: number;
}

/**
 * What the unattributed feed returns. NO MESSAGE BODIES: a log line we could
 * not tie to a device cannot be tied to a tenant either, so returning its text
 * inside a tenant-scoped API would hand customer A the logs of customer B.
 * What an operator needs to FIX the mapping is who is talking and what name
 * they claim, and that is all this carries.
 */
export interface UnattributedSource {
  sourceIp: string;
  hostname: string | null;
  count: number;
  firstSeen: string;
  lastSeen: string;
}

export interface SyslogIngestHealth {
  received: number;
  accepted: number;
  belowFloor: number;
  /** Kept despite being under the floor because the line looks like account
   *  activity — the one exception, counted so its volume stays visible. */
  belowFloorKeptAccount: number;
  malformed: number;
  rateLimited: number;
  quotaSuppressed: number;
  queueDropped: number;
  stored: number;
  /** Current depth of the bounded queue, and the bound. The ratio is the only
   *  early warning that ingestion is losing the race with the disk. */
  queueDepth: number;
  queueMax: number;
  /** Sources currently silenced by the circuit breaker. */
  suppressedSources: number;
}
