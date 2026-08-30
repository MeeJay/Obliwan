// ObliWAN client — M8 log + attribution DTOs (killers K6 and K7).
//
// Two things land in this milestone and they share one screen family:
//   * the unified log (syslog UDP/TCP 514, SNMP traps, and RouterOS `/log`),
//   * the ATTRIBUTION of a drift finding to an identity.
//
// ── THE ONE RULE OF THIS FILE ───────────────────────────────────────────────
// `unattributed` IS A VALUE, NOT AN ABSENCE.
//
// §5/M8 asks for "`unattributed` explicite, comptes partagés marqués". An
// attribution engine that cannot decide must SAY it cannot decide. The failure
// mode is not a blank cell — it is a plausible name in that cell, because
// somebody will act on it: they will call that person, or file the change under
// their name in a customer report. So `AttributionState` has four members and
// exactly one of them names a person with confidence.
//
// ── AND THE SECOND RULE ─────────────────────────────────────────────────────
// A SHARED ACCOUNT IS MARKED AS SHARED, ALWAYS.
//
// Three engineers logging in as `admin` produce a match that is technically
// correct and practically worthless. `shared` says "the account is right, the
// human is not identified" — which is a different sentence from both "we know
// who" and "we have no idea", and it is the sentence a customer report has to
// carry.
//
// ── §8.2 ────────────────────────────────────────────────────────────────────
// Log lines from a device can contain anything a device chose to print,
// including a secret its own firmware leaked into a log message. The renderer
// therefore runs `utils/secretScan` over every line it paints. This is the one
// data path in the product where redaction cannot be a server guarantee: we did
// not author the string.

// ── Sources ─────────────────────────────────────────────────────────────────

/**
 * Where a line came from, and why the three are one screen.
 *
 * An operator investigating "what happened on this box at 02:14" does not care
 * that the login attempt arrived over syslog, the link flap arrived as an SNMP
 * trap and the config write was read from `/log` over the API. Splitting them
 * across three screens means correlating by hand, with three clocks.
 *
 * They are still LABELLED, because their trustworthiness differs sharply:
 * `trap` in particular is UDP with a NAT-mangled source address (arbitrage A6),
 * so a trap must never be the thing that identifies an equipment.
 */
export const LOG_SOURCES = ['syslog', 'trap', 'device_log'] as const;
export type LogSource = (typeof LOG_SOURCES)[number];

/** Syslog severities, RFC 5424 order — 0 is the worst. Traps and `/log` lines
 *  are mapped onto the same ladder so one filter covers all three. */
export const LOG_SEVERITIES = [
  'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug',
] as const;
export type LogSeverity = (typeof LOG_SEVERITIES)[number];

export const LOG_SEVERITY_RANK: Readonly<Record<LogSeverity, number>> = {
  emerg: 0, alert: 1, crit: 2, err: 3, warning: 4, notice: 5, info: 6, debug: 7,
};

export interface LogEntryView {
  id: string;
  /** Device-reported time. May be wrong — a box with no NTP is a box with a
   *  fantasy clock — which is why `receivedAt` is kept beside it. */
  timestamp: string;
  /** When OUR ingest saw it. The only clock we control. */
  receivedAt: string | null;
  source: LogSource;
  severity: LogSeverity;
  deviceId: number | null;
  deviceName: string | null;
  siteName: string | null;
  /** Syslog facility / trap OID / RouterOS topic, as the parser labelled it. */
  facility: string | null;
  /** The line itself. Painted through `secretScan`, never trusted. */
  message: string;
  /** Source address the line arrived from. `null` on a trap behind the Docker
   *  bridge NAT (A6): a wrong address is worse than none. */
  sourceIp: string | null;
  /** Login name the parser extracted, when the line carries one. NOT an
   *  attribution — see `AttributionView`. */
  username: string | null;
}

export interface LogSourceCount {
  source: LogSource;
  count: number;
  /** Newest line seen from this source. A source with no recent line is an
   *  ingest that stopped, which is the failure this counter exists to show. */
  lastSeenAt: string | null;
}

export interface LogQueryParams {
  source?: LogSource | '';
  severity?: LogSeverity | '';
  deviceId?: number;
  q?: string;
  since?: string;
  until?: string;
  limit?: number;
}

// ── Attribution (K6) ────────────────────────────────────────────────────────

/**
 * The four possible answers, and only one of them names somebody.
 *
 *  `attributed`   — a login event matched the change window and the account is
 *                   individual. The name may be shown.
 *  `shared`       — the account matched, and the account is known to be shared.
 *                   The ACCOUNT is shown, the human is explicitly not claimed.
 *  `ambiguous`    — several candidate sessions fit the window. Candidates are
 *                   listed; none is promoted to "the" answer.
 *  `unattributed` — no session fits. Shown as such, in words, forever. It is
 *                   NOT an error and NOT a pending state.
 */
export const ATTRIBUTION_STATES = ['attributed', 'shared', 'ambiguous', 'unattributed'] as const;
export type AttributionState = (typeof ATTRIBUTION_STATES)[number];

/** One login session the engine considered. Shown for every state except
 *  `unattributed`, so the operator can judge the match instead of trusting it. */
export interface AttributionCandidate {
  eventId: number | null;
  username: string;
  /** True when this account is flagged shared. Carried per candidate because
   *  one window can hold both an individual and a shared login. */
  sharedAccount: boolean;
  sourceIp: string | null;
  via: string | null;
  loggedInAt: string | null;
  loggedOutAt: string | null;
  /** 0..1. Distance in the time window plus the corroborating signals. */
  score: number;
}

export interface AttributionView {
  state: AttributionState;
  /** The winning candidate. `null` for `unattributed` AND for `ambiguous` —
   *  an ambiguous window has no winner, and inventing one is the bug this
   *  whole type exists to prevent. */
  identity: AttributionCandidate | null;
  candidates: AttributionCandidate[];
  /** The window the engine searched, so "no session fits" is checkable. */
  windowStart: string | null;
  windowEnd: string | null;
  /** Server sentence explaining the verdict. Shown verbatim. */
  rationale: string | null;
  /** False when the endpoint is not served by this build: the banner then says
   *  "attribution not available", never "unattributed". Those are different
   *  facts and only one of them is about the change. */
  available: boolean;
}

export const ATTRIBUTION_UNAVAILABLE: AttributionView = {
  state: 'unattributed',
  identity: null,
  candidates: [],
  windowStart: null,
  windowEnd: null,
  rationale: null,
  available: false,
};

/** Whether this verdict may print a person's name. The ONLY predicate any
 *  screen is allowed to use for that decision. */
export function namesAnIndividual(view: AttributionView): boolean {
  return view.available && view.state === 'attributed' && view.identity !== null;
}
