import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';
import { isRouteAbsent } from './change.api';
import type {
  AttributionCandidate,
  AttributionState,
  AttributionView,
  LogEntryView,
  LogQueryParams,
  LogSeverity,
  LogSource,
  LogSourceCount,
} from '@/types/logs';
import { ATTRIBUTION_UNAVAILABLE, LOG_SEVERITIES, LOG_SOURCES } from '@/types/logs';

/**
 * The unified log and the attribution verdict (M8, killers K6 + K7).
 *
 * ── THE ROUTE PREFIXES — CHECKED, NOT ASSUMED ───────────────────────────────
 * `server/src/routes/index.ts` was READ at the time of writing and mounts
 * NOTHING under `/logs`. `drift.routes.ts` was read too: it serves
 * `/drift/runs/:id`, `/drift/runs/:id/findings`, `/drift/findings/:id` and the
 * two `ignore` PATCHes — and NO attribution route. So the EXACT paths this
 * module calls are listed here for the lead to mount, and every one of them
 * degrades to a stated absence rather than to a blank screen:
 *
 *   GET /api/logs?source&severity&deviceId&q&since&until&limit -> LogEntryView[]
 *   GET /api/logs/sources                        -> LogSourceCount[]
 *   GET /api/drift/findings/:id/attribution      -> AttributionView
 *   GET /api/drift/runs/:id/attribution          -> AttributionView (run-level)
 *
 * The attribution routes are deliberately hung under the `/drift` prefix that
 * already exists rather than under a new `/attribution` one: the verdict is a
 * property OF a finding, it is read with `DRIFT_READ`, and a second prefix
 * would be a second place to forget the tenant scope.
 *
 * ── `unattributed` IS NEVER MANUFACTURED HERE ───────────────────────────────
 * When the endpoint is absent, this module returns `ATTRIBUTION_UNAVAILABLE`,
 * whose `available: false` makes the banner say "attribution is not served by
 * this build". It does NOT say "unattributed". A missing service and a search
 * that found nobody are different facts, and only the second one is about the
 * change the operator is looking at.
 *
 * ── AND A NAME IS NEVER PROMOTED ────────────────────────────────────────────
 * `identity` is set only for the `attributed` state. For `ambiguous` it stays
 * null even when the payload names a "best" candidate, because a window with
 * several plausible sessions has no winner — picking the highest score would
 * put a person's name on a change they may not have made.
 */

type Raw = Record<string, unknown>;

function pick(row: Raw, camel: string): unknown {
  if (camel in row) return row[camel];
  const snake = camel.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
  return row[snake];
}

function n(v: unknown, fallback: number): number {
  if (v === null || v === undefined || v === '') return fallback;
  const x = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(x) ? x : fallback;
}

function nOrNull(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const x = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(x) ? x : null;
}

function s(v: unknown): string | null {
  return v === null || v === undefined || v === '' ? null : String(v);
}

function bool(v: unknown): boolean {
  if (typeof v === 'boolean') return v;
  return v === 'true' || v === 't' || v === 1 || v === '1';
}

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  if (payload && typeof payload === 'object') {
    const p = payload as Raw;
    const items = p.items ?? p.rows ?? p.entries ?? p.logs ?? p.sources;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

// ── Normalisers ─────────────────────────────────────────────────────────────

const SOURCES: readonly string[] = LOG_SOURCES;
const SEVERITIES: readonly string[] = LOG_SEVERITIES;

/**
 * An unrecognised source is `syslog`, the LEAST trusted of the three.
 *
 * The asymmetry matters: `device_log` lines are read by us over an
 * authenticated channel from a device we identified, and are therefore the only
 * ones whose origin we can vouch for. Folding an unknown source to
 * `device_log` would upgrade the trustworthiness of a line nobody can place.
 */
function sourceOf(v: unknown): LogSource {
  const str = String(v ?? '').toLowerCase();
  return (SOURCES.includes(str) ? str : 'syslog') as LogSource;
}

/**
 * An unrecognised severity is `warning`, not `info` and not `emerg`.
 *
 * `info` would hide the line behind the default filter; `emerg` would make one
 * malformed parser flood the top of an incident screen. `warning` keeps it
 * visible without letting it shout over lines that really are critical.
 */
function severityOf(v: unknown): LogSeverity {
  const str = String(v ?? '').toLowerCase();
  if (SEVERITIES.includes(str)) return str as LogSeverity;
  // Numeric RFC 5424 severities are accepted too — traps and raw syslog carry
  // the number, not the word.
  const num = Number(v);
  if (Number.isInteger(num) && num >= 0 && num <= 7) return LOG_SEVERITIES[num];
  return 'warning';
}

export function normalizeLogEntry(raw: Raw, index: number): LogEntryView {
  const timestamp = s(pick(raw, 'timestamp') ?? pick(raw, 'ts') ?? pick(raw, 'loggedAt'));
  return {
    // A line with no id still has to be renderable and keyed: an ingest that
    // forgets an id must not collapse a hundred rows into one.
    id: String(pick(raw, 'id') ?? `${timestamp ?? 'na'}#${index}`),
    timestamp: timestamp ?? '',
    receivedAt: s(pick(raw, 'receivedAt')),
    source: sourceOf(pick(raw, 'source')),
    severity: severityOf(pick(raw, 'severity')),
    deviceId: nOrNull(pick(raw, 'deviceId')),
    deviceName: s(pick(raw, 'deviceName')),
    siteName: s(pick(raw, 'siteName')),
    facility: s(pick(raw, 'facility') ?? pick(raw, 'topic') ?? pick(raw, 'oid')),
    message: String(pick(raw, 'message') ?? pick(raw, 'text') ?? ''),
    sourceIp: s(pick(raw, 'sourceIp') ?? pick(raw, 'sourceAddress')),
    username: s(pick(raw, 'username') ?? pick(raw, 'user')),
  };
}

export function normalizeSourceCount(raw: Raw): LogSourceCount {
  return {
    source: sourceOf(pick(raw, 'source')),
    count: n(pick(raw, 'count'), 0),
    lastSeenAt: s(pick(raw, 'lastSeenAt') ?? pick(raw, 'lastAt')),
  };
}

function candidate(raw: unknown): AttributionCandidate | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Raw;
  const username = s(pick(row, 'username') ?? pick(row, 'user'));
  if (!username) return null;
  const score = Number(pick(row, 'score'));
  return {
    eventId: nOrNull(pick(row, 'eventId') ?? pick(row, 'id')),
    username,
    sharedAccount: bool(pick(row, 'sharedAccount') ?? pick(row, 'shared')),
    sourceIp: s(pick(row, 'sourceIp') ?? pick(row, 'sourceAddress')),
    via: s(pick(row, 'via') ?? pick(row, 'transport')),
    loggedInAt: s(pick(row, 'loggedInAt') ?? pick(row, 'startedAt')),
    loggedOutAt: s(pick(row, 'loggedOutAt') ?? pick(row, 'endedAt')),
    // An unreadable score is 0, never 1: it must not sort itself to the top of
    // a candidate list it has no claim to.
    score: Number.isFinite(score) ? Math.min(1, Math.max(0, score)) : 0,
  };
}

const STATES: readonly string[] = ['attributed', 'shared', 'ambiguous', 'unattributed'];

export function normalizeAttribution(raw: unknown): AttributionView {
  if (!raw || typeof raw !== 'object') return { ...ATTRIBUTION_UNAVAILABLE, available: true };
  const row = raw as Raw;
  const candidates = (Array.isArray(pick(row, 'candidates')) ? (pick(row, 'candidates') as unknown[]) : [])
    .map(candidate)
    .filter((c): c is AttributionCandidate => c !== null)
    .sort((a, b) => b.score - a.score);

  const declared = String(pick(row, 'state') ?? '').toLowerCase();
  const winner = candidate(pick(row, 'identity') ?? pick(row, 'attributedTo'));

  // The state is DERIVED as well as read, and the pessimistic reading wins.
  // A payload that says `attributed` while naming a shared account is reported
  // as `shared`; a payload that says `attributed` with no identity at all is
  // reported as `unattributed`. Neither is a hypothetical: the server folds one
  // flag, the client folds the other, and only the conjunction is safe.
  let state: AttributionState = (STATES.includes(declared) ? declared : 'unattributed') as AttributionState;
  if (state === 'attributed' && !winner) state = 'unattributed';
  if (state === 'attributed' && winner?.sharedAccount) state = 'shared';

  return {
    state,
    // `ambiguous` keeps a null identity ON PURPOSE — see the header comment.
    identity: state === 'attributed' || state === 'shared' ? winner : null,
    candidates,
    windowStart: s(pick(row, 'windowStart')),
    windowEnd: s(pick(row, 'windowEnd')),
    rationale: s(pick(row, 'rationale') ?? pick(row, 'summary')),
    available: true,
  };
}

// ── The client ──────────────────────────────────────────────────────────────

function clean(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

export const logsApi = {
  /** `null` = the log API is not served by this build. */
  async list(params: LogQueryParams = {}): Promise<LogEntryView[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/logs', {
        params: clean(params as Record<string, unknown>),
      });
      return asRows(res.data.data).map(normalizeLogEntry);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** Per-source counters. Their real job is to show an ingest that STOPPED:
   *  a syslog receiver that died is invisible in a log list — the list simply
   *  has fewer lines — and very visible in a "last seen 4 h ago" cell. */
  async sources(): Promise<LogSourceCount[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/logs/sources');
      return asRows(res.data.data).map(normalizeSourceCount);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },
};

export const attributionApi = {
  /** NEVER throws. An unreachable attribution service reports itself as
   *  unavailable; it never reports a change as unattributed. */
  async ofFinding(findingId: number): Promise<AttributionView> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/drift/findings/${findingId}/attribution`);
      return normalizeAttribution(res.data.data);
    } catch {
      return ATTRIBUTION_UNAVAILABLE;
    }
  },

  async ofRun(runId: number): Promise<AttributionView> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/drift/runs/${runId}/attribution`);
      return normalizeAttribution(res.data.data);
    } catch {
      return ATTRIBUTION_UNAVAILABLE;
    }
  },
};
