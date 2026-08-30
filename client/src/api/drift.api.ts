import apiClient from './client';
import type { ApiResponse, DiffSeverity, NcmFieldDiff } from '@obliwan/shared';
import type {
  DriftCause,
  DriftFinding,
  DriftRunDetail,
  DriftRunSummary,
  DriftStatus,
  DriftSuppression,
} from '@/types/config';

/**
 * Drift runs and findings (M4).
 *
 * ── THE ROUTE PREFIX ────────────────────────────────────────────────────────
 * Checked, not assumed (see the same note in `config.api.ts`):
 * `server/src/routes/index.ts` currently mounts no drift router at all. These
 * are the EXACT paths this client calls, following the `/snmp` shape M3
 * settled on:
 *
 *   GET   /api/drift/runs?deviceId&siteId&status&severity&limit
 *   GET   /api/drift/devices/:deviceId/runs?limit
 *   GET   /api/drift/runs/:id            -> run + findings
 *   GET   /api/drift/runs/:id/findings   -> findings alone (fallback)
 *   PATCH /api/drift/findings/:id        -> { ignored: boolean }
 *
 * ── ON IGNORING A FINDING ───────────────────────────────────────────────────
 * R3 makes "ignore this" a one-click, zero-latency gesture: an operator facing
 * a first-run wall of findings must be able to knock the noise down as fast as
 * he can read it. The UI therefore applies the ignore OPTIMISTICALLY and only
 * then persists. `ignoreFinding` returns `false` when the route is absent, and
 * the screen keeps the local ignore while stating out loud that it will not
 * survive a reload — a silent local-only ignore would be far worse, because the
 * operator would believe he had triaged a run that is still red for everybody
 * else.
 *
 * An ignored finding is KEPT, never deleted: "we saw it and chose to ignore it"
 * and "we never saw it" must stay distinguishable.
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
  return v === null || v === undefined ? null : String(v);
}

function bool(v: unknown, fallback = false): boolean {
  if (v === null || v === undefined) return fallback;
  if (typeof v === 'boolean') return v;
  return v === 'true' || v === 't' || v === 1 || v === '1';
}

function statusOf(err: unknown): number | undefined {
  return (err as { response?: { status?: number } }).response?.status;
}

function isRouteAbsent(err: unknown): boolean {
  const st = statusOf(err);
  return st === 404 || st === 501;
}

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  if (payload && typeof payload === 'object') {
    const items =
      (payload as Raw).items ?? (payload as Raw).rows ??
      (payload as Raw).runs ?? (payload as Raw).findings;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

/** `jsonb` columns come back parsed from `pg`, but a driver or a proxy that
 *  hands them over as text must not blank the field silently. */
function asJson<T>(v: unknown, fallback: T): T {
  if (v === null || v === undefined) return fallback;
  if (typeof v === 'string') {
    try { return JSON.parse(v) as T; } catch { return fallback; }
  }
  return v as T;
}

const STATUSES: readonly string[] = ['in_sync', 'drifted', 'error', 'unreachable'];
function statusValue(v: unknown): DriftStatus {
  const str = String(v ?? '');
  // Unknown status degrades to `error`, never to `in_sync`. Painting an
  // unrecognised run green is the one mistake this screen cannot make.
  return (STATUSES.includes(str) ? str : 'error') as DriftStatus;
}

const CAUSES: readonly string[] = [
  'scheduled', 'manual', 'post_change', 'renormalization', 'model_upgrade', 'takeover',
];
function causeValue(v: unknown): DriftCause {
  const str = String(v ?? '');
  return (CAUSES.includes(str) ? str : 'scheduled') as DriftCause;
}

const SEVERITIES: readonly string[] = ['info', 'low', 'medium', 'high', 'critical'];
function severityValue(v: unknown, fallback: DiffSeverity = 'info'): DiffSeverity {
  const str = String(v ?? '');
  return (SEVERITIES.includes(str) ? str : fallback) as DiffSeverity;
}

function orderAnalysisValue(v: unknown): DriftRunSummary['orderAnalysis'] {
  return v === 'full' || v === 'partial' || v === 'skipped' ? v : 'partial';
}

export function normalizeRun(raw: Raw): DriftRunSummary {
  const sev = pick(raw, 'maxSeverity');
  return {
    id: n(pick(raw, 'id'), 0),
    uuid: String(pick(raw, 'uuid') ?? ''),
    deviceId: n(pick(raw, 'deviceId'), 0),
    deviceName: s(pick(raw, 'deviceName')),
    siteId: nOrNull(pick(raw, 'siteId')),
    siteName: s(pick(raw, 'siteName')),
    renderId: nOrNull(pick(raw, 'renderId')),
    snapshotId: nOrNull(pick(raw, 'snapshotId')),
    status: statusValue(pick(raw, 'status')),
    errorReason: s(pick(raw, 'errorReason')),
    cause: causeValue(pick(raw, 'cause')),
    scope: pick(raw, 'scope') === 'full' ? 'full' : 'managed_only',
    findingsCount: n(pick(raw, 'findingsCount'), 0),
    ignoredCount: n(pick(raw, 'ignoredCount'), 0),
    inertMoveCount: n(pick(raw, 'inertMoveCount'), 0),
    outOfScopeCount: n(pick(raw, 'outOfScopeCount'), 0),
    maxSeverity: sev === null || sev === undefined ? null : severityValue(sev),
    ncmVersion: n(pick(raw, 'ncmVersion'), 1),
    normalizationEpoch: s(pick(raw, 'normalizationEpoch')),
    orderAnalysis: orderAnalysisValue(pick(raw, 'orderAnalysis')),
    suppressed: asJson<DriftSuppression[]>(pick(raw, 'suppressed'), []),
    startedAt: String(pick(raw, 'startedAt') ?? ''),
    finishedAt: s(pick(raw, 'finishedAt')),
  };
}

const KINDS: readonly string[] = ['missing', 'extra', 'changed', 'moved'];
const METHODS: readonly string[] = ['marker', 'natural', 'matchHash', 'fuzzy', 'none'];

export function normalizeFinding(raw: Raw): DriftFinding {
  const kind = String(pick(raw, 'kind') ?? '');
  const method = String(pick(raw, 'matchMethod') ?? '');
  return {
    id: n(pick(raw, 'id'), 0),
    runId: n(pick(raw, 'runId'), 0),
    path: String(pick(raw, 'path') ?? ''),
    semKey: String(pick(raw, 'semKey') ?? ''),
    resource: String(pick(raw, 'resource') ?? 'interface') as DriftFinding['resource'],
    kind: (KINDS.includes(kind) ? kind : 'changed') as DriftFinding['kind'],
    severity: severityValue(pick(raw, 'severity')),
    matchMethod: (METHODS.includes(method) ? method : 'none') as DriftFinding['matchMethod'],
    // `numeric(4,3)` arrives as a STRING from pg. Left as text it compares
    // lexicographically and a 0.9 confidence sorts below 0.65.
    matchConfidence: n(pick(raw, 'matchConfidence'), 1),
    predicateChanged: bool(pick(raw, 'predicateChanged')),
    fieldDiffs: asJson<NcmFieldDiff[]>(pick(raw, 'fieldDiffs'), []),
    crossed: asJson<string[]>(pick(raw, 'crossed'), []),
    intentValue: asJson<unknown>(pick(raw, 'intentValue'), null),
    actualValue: asJson<unknown>(pick(raw, 'actualValue'), null),
    textPatch: s(pick(raw, 'textPatch')),
    ignored: bool(pick(raw, 'ignored')),
    ignoredByRule: nOrNull(pick(raw, 'ignoredByRule')),
    legacySemKey: s(pick(raw, 'legacySemKey')),
  };
}

export interface DriftListParams {
  deviceId?: number;
  siteId?: number;
  status?: DriftStatus;
  severity?: DiffSeverity;
  limit?: number;
}

function clean(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

export const driftApi = {
  /** Fleet-wide run list. `null` = endpoint not served by this build. */
  async listRuns(params: DriftListParams = {}): Promise<DriftRunSummary[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/drift/runs', {
        params: clean(params as Record<string, unknown>),
      });
      return asRows(res.data.data).map(normalizeRun);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** The runs of ONE device, newest first. `null` = route absent. */
  async forDevice(deviceId: number, limit = 30): Promise<DriftRunSummary[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/drift/devices/${deviceId}/runs`, {
        params: { limit },
      });
      return asRows(res.data.data).map(normalizeRun);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * One run with its findings.
   *
   * The findings may travel inside the run payload or behind a sub-route
   * depending on how the server agent splits it; both are accepted rather than
   * guessed, because getting this wrong shows up as a detail page that is
   * permanently empty and never as an error.
   *
   * A 404 is NOT swallowed: it means the run does not exist in this tenant.
   */
  async getRun(id: number): Promise<DriftRunDetail | null> {
    const res = await apiClient.get<ApiResponse<unknown>>(`/drift/runs/${id}`);
    const payload = res.data.data;
    if (!payload || typeof payload !== 'object') return null;
    const row = payload as Raw;
    const run = normalizeRun((row.run as Raw) ?? row);
    const inline = pick(row, 'findings');
    if (Array.isArray(inline)) {
      return { ...run, findings: (inline as Raw[]).map(normalizeFinding) };
    }
    const findings = await this.findings(id);
    return { ...run, findings: findings ?? [] };
  },

  /** Findings alone. `null` = the sub-route is not served. */
  async findings(runId: number): Promise<DriftFinding[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/drift/runs/${runId}/findings`);
      return asRows(res.data.data).map(normalizeFinding);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * Persist an ignore. Returns `false` when the route is absent so the caller
   * can keep the optimistic local state AND tell the operator it is local.
   * Any other error propagates — a 403 on a missing DRIFT_MANAGE capability
   * must not look like an unimplemented build.
   */
  async ignoreFinding(findingId: number, ignored: boolean): Promise<boolean> {
    try {
      await apiClient.patch<ApiResponse<unknown>>(`/drift/findings/${findingId}`, { ignored });
      return true;
    } catch (err) {
      if (isRouteAbsent(err)) return false;
      throw err;
    }
  },
};
