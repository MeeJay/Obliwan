import apiClient from './client';
import type { ApiResponse, DeviceBrand, DeviceFamily } from '@obliwan/shared';
import { DEVICE_BRANDS, DEVICE_FAMILIES } from '@obliwan/shared';
import { isRouteAbsent } from './change.api';
import type {
  BaselineFact,
  BaselineRun,
  BaselineRunState,
  ClusterMember,
  ConformanceRow,
  DeducedVariable,
  FactClass,
  FactCluster,
  StartRunRequest,
  TemplateDraft,
} from '@/types/baseline';
import { BASELINE_RUN_STATES, FACT_CLASSES } from '@/types/baseline';

/**
 * Fleet takeover / Golden Site (M12, killer K8).
 *
 * ── THE ROUTE PREFIX — CHECKED, NOT ASSUMED ─────────────────────────────────
 * `server/src/routes/index.ts` was READ while writing this file and mounts
 * NOTHING under `/baseline`. The EXACT paths this module calls:
 *
 *   GET    /api/baseline/runs                        -> BaselineRun[]
 *   POST   /api/baseline/runs                        -> StartRunRequest -> BaselineRun
 *   GET    /api/baseline/runs/:id/clusters           -> FactCluster[]
 *   GET    /api/baseline/clusters/:id/facts?class    -> BaselineFact[]
 *   GET    /api/baseline/clusters/:id/draft          -> TemplateDraft
 *   POST   /api/baseline/facts/:id/exception         -> { reason } -> BaselineFact
 *   DELETE /api/baseline/facts/:id/exception         -> BaselineFact
 *   GET    /api/baseline/runs/:id/conformance        -> ConformanceRow[]
 *   POST   /api/baseline/clusters/:id/promote        -> { name } -> { templateId }
 *
 * Every one degrades to a stated absence.
 *
 * ── THE COUNTS ARE NEVER SYNTHESISED ────────────────────────────────────────
 * `presentOn` / `total` are read straight through and a missing `total` becomes
 * 0, not the member count. A denominator this client invented would produce
 * "present on 27/27" for a fact the miner saw on 27 of 30 boxes — which is the
 * single most misleading sentence this feature could print, because it turns a
 * three-site divergence into a unanimous baseline.
 *
 * ── §8.2 ────────────────────────────────────────────────────────────────────
 * `DeducedVariable.sampleValues` is the dangerous field of this milestone: the
 * miner's whole job is to notice that a value differs per site, and a PPPoE
 * password differs per site. The normaliser DROPS sample values whose variable
 * name or fact path looks secret, and the renderer scans what survives. The
 * server must not send them; this is the second lock.
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

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  if (payload && typeof payload === 'object') {
    const p = payload as Raw;
    const items = p.items ?? p.rows ?? p.runs ?? p.clusters ?? p.facts
      ?? p.members ?? p.variables ?? p.conformance;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

function brandOf(v: unknown): DeviceBrand | null {
  const raw = s(v);
  return raw && (DEVICE_BRANDS as readonly string[]).includes(raw) ? (raw as DeviceBrand) : null;
}

function familyOf(v: unknown): DeviceFamily | null {
  const raw = s(v);
  return raw && (DEVICE_FAMILIES as readonly string[]).includes(raw) ? (raw as DeviceFamily) : null;
}

/** Unknown run state degrades to `running`: it claims the least and it keeps
 *  the screen polling instead of declaring a result nobody produced. */
function runStateOf(v: unknown): BaselineRunState {
  const raw = (s(v) ?? '').toLowerCase();
  return (BASELINE_RUN_STATES as readonly string[]).includes(raw)
    ? (raw as BaselineRunState)
    : 'running';
}

/** Unknown fact class degrades to `outlier` — the class that DEMANDS a human
 *  decision. Guessing `common` would silently fold an unclassified divergence
 *  into the template everybody is about to deploy. */
function factClassOf(v: unknown): FactClass {
  const raw = (s(v) ?? '').toLowerCase();
  return (FACT_CLASSES as readonly string[]).includes(raw) ? (raw as FactClass) : 'outlier';
}

/** §8.2 — variable names and fact paths that must not carry sample values. */
const SECRET_VARIABLE_HINTS = [
  'password', 'passwd', 'passphrase', 'secret', 'psk', 'preshared', 'pre-shared',
  'key', 'credential', 'token', 'community',
];

function looksSecretVariable(name: string, factPath: string): boolean {
  const hay = `${name} ${factPath}`.toLowerCase();
  return SECRET_VARIABLE_HINTS.some((h) => hay.includes(h));
}

export function normalizeRun(raw: Raw): BaselineRun {
  return {
    id: n(pick(raw, 'id'), 0),
    state: runStateOf(pick(raw, 'state') ?? pick(raw, 'status')),
    deviceCount: n(pick(raw, 'deviceCount'), 0),
    devicesWithoutSnapshot: n(pick(raw, 'devicesWithoutSnapshot'), 0),
    clusterCount: n(pick(raw, 'clusterCount'), 0),
    startedAt: String(pick(raw, 'startedAt') ?? pick(raw, 'createdAt') ?? ''),
    finishedAt: s(pick(raw, 'finishedAt')),
    error: s(pick(raw, 'error')),
    createdByName: s(pick(raw, 'createdByName')),
  };
}

function memberOf(raw: Raw): ClusterMember {
  return {
    deviceId: n(pick(raw, 'deviceId'), 0),
    deviceName: s(pick(raw, 'deviceName')),
    siteName: s(pick(raw, 'siteName')),
    brand: brandOf(pick(raw, 'brand')),
    family: familyOf(pick(raw, 'family')),
    similarity: n(pick(raw, 'similarity'), 0),
    divergenceCount: n(pick(raw, 'divergenceCount'), 0),
  };
}

export function normalizeVariable(raw: Raw): DeducedVariable {
  const name = String(pick(raw, 'name') ?? '');
  const factPath = String(pick(raw, 'factPath') ?? pick(raw, 'path') ?? '');
  const samples = pick(raw, 'sampleValues') ?? pick(raw, 'samples');
  const list = Array.isArray(samples) ? samples.map((x) => String(x)) : [];
  return {
    name,
    factPath,
    // A "variable" extracted over a secret field is exactly the last audit's
    // finding with a new name on it. The samples are dropped here; the count
    // survives, because "12 distinct values" is the useful part anyway.
    sampleValues: looksSecretVariable(name, factPath) ? [] : list,
    distinctCount: n(pick(raw, 'distinctCount'), list.length),
    presentOn: n(pick(raw, 'presentOn'), 0),
  };
}

export function normalizeCluster(raw: Raw): FactCluster {
  const members = asRows(pick(raw, 'members')).map(memberOf);
  return {
    id: n(pick(raw, 'id'), 0),
    name: String(pick(raw, 'name') ?? `cluster-${n(pick(raw, 'id'), 0)}`),
    brand: brandOf(pick(raw, 'brand')),
    family: familyOf(pick(raw, 'family')),
    members,
    commonFactCount: n(pick(raw, 'commonFactCount'), 0),
    variableFactCount: n(pick(raw, 'variableFactCount'), 0),
    variables: asRows(pick(raw, 'variables')).map(normalizeVariable),
    cohesion: n(pick(raw, 'cohesion'), 0),
  };
}

export function normalizeFact(raw: Raw): BaselineFact {
  const exception = pick(raw, 'exception');
  const missing = pick(raw, 'missingFrom');
  return {
    id: String(pick(raw, 'id') ?? ''),
    resource: String(pick(raw, 'resource') ?? ''),
    semKey: String(pick(raw, 'semKey') ?? ''),
    summary: String(pick(raw, 'summary') ?? ''),
    klass: factClassOf(pick(raw, 'klass') ?? pick(raw, 'class')),
    presentOn: n(pick(raw, 'presentOn'), 0),
    // NOT defaulted to the member count — see the header. A denominator this
    // client invented is a lie with a number in it.
    total: n(pick(raw, 'total'), 0),
    missingFrom: Array.isArray(missing)
      ? (missing as Raw[]).map((m) => ({
          deviceId: n(pick(m, 'deviceId'), 0),
          deviceName: s(pick(m, 'deviceName')),
        }))
      : [],
    exception: exception && typeof exception === 'object'
      ? {
          reason: String(pick(exception as Raw, 'reason') ?? ''),
          createdByName: s(pick(exception as Raw, 'createdByName')),
          createdAt: String(pick(exception as Raw, 'createdAt') ?? ''),
        }
      : null,
  };
}

export function normalizeDraft(payload: unknown, clusterId: number): TemplateDraft | null {
  if (!payload || typeof payload !== 'object') return null;
  const row = payload as Raw;
  const uncovered = pick(row, 'uncoveredFactIds') ?? pick(row, 'uncovered');
  return {
    clusterId: n(pick(row, 'clusterId'), clusterId),
    body: String(pick(row, 'body') ?? pick(row, 'template') ?? ''),
    variables: asRows(pick(row, 'variables')).map(normalizeVariable),
    coveredFacts: n(pick(row, 'coveredFacts'), 0),
    totalFacts: n(pick(row, 'totalFacts'), 0),
    uncoveredFactIds: Array.isArray(uncovered) ? uncovered.map((x) => String(x)) : [],
    generatedAt: String(pick(row, 'generatedAt') ?? ''),
  };
}

export function normalizeConformance(raw: Raw): ConformanceRow {
  return {
    deviceId: n(pick(raw, 'deviceId'), 0),
    deviceName: s(pick(raw, 'deviceName')),
    siteName: s(pick(raw, 'siteName')),
    clusterId: nOrNull(pick(raw, 'clusterId')),
    clusterName: s(pick(raw, 'clusterName')),
    // `null` and not 0: a device with no snapshot has no score, and 0 reads as
    // "totally non-conformant" for a box nobody has ever collected.
    score: nOrNull(pick(raw, 'score')),
    matchedFacts: n(pick(raw, 'matchedFacts'), 0),
    divergences: n(pick(raw, 'divergences'), 0),
    documentedExceptions: n(pick(raw, 'documentedExceptions'), 0),
    evaluatedAt: s(pick(raw, 'evaluatedAt')),
  };
}

// ── The client ──────────────────────────────────────────────────────────────

export const baselineApi = {
  async listRuns(): Promise<BaselineRun[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/baseline/runs');
      return asRows(res.data.data).map(normalizeRun);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async startRun(req: StartRunRequest): Promise<BaselineRun | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>('/baseline/runs', req);
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      return normalizeRun(payload as Raw);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },


  async listClusters(runId: number): Promise<FactCluster[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/baseline/runs/${runId}/clusters`);
      return asRows(res.data.data).map(normalizeCluster);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async listFacts(clusterId: number, klass?: FactClass): Promise<BaselineFact[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/baseline/clusters/${clusterId}/facts`, {
        params: { class: klass || undefined },
      });
      return asRows(res.data.data).map(normalizeFact);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async getDraft(clusterId: number): Promise<TemplateDraft | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/baseline/clusters/${clusterId}/draft`);
      return normalizeDraft(res.data.data, clusterId);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * Mark a divergence as a documented client specificity.
   *
   * `reason` is required by the signature, not by a validator: an exception
   * without a reason is an ignore button, and a fleet of unexplained ignores
   * makes the conformance score meaningless within a year.
   */
  async addException(factId: string, reason: string): Promise<BaselineFact | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>(
        `/baseline/facts/${encodeURIComponent(factId)}/exception`, { reason },
      );
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      return normalizeFact(payload as Raw);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async removeException(factId: string): Promise<boolean> {
    try {
      await apiClient.delete<ApiResponse<unknown>>(
        `/baseline/facts/${encodeURIComponent(factId)}/exception`,
      );
      return true;
    } catch (err) {
      if (isRouteAbsent(err)) return false;
      throw err;
    }
  },

  async conformance(runId: number): Promise<ConformanceRow[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/baseline/runs/${runId}/conformance`);
      return asRows(res.data.data).map(normalizeConformance);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** Hand a draft to `/templates` as an unpublished revision. The publish step
   *  stays there, behind TEMPLATE_WRITE — this screen proposes, it never
   *  publishes, and it never touches a device (D3). */
  async promote(clusterId: number, name: string): Promise<number | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>(
        `/baseline/clusters/${clusterId}/promote`, { name },
      );
      const payload = (res.data.data ?? {}) as Raw;
      return nOrNull(pick(payload, 'templateId') ?? pick(payload, 'id'));
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },
};
