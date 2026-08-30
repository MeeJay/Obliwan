import apiClient from './client';
import type { ApiResponse, ApplyPlan, ChangeJobKind, RiskLevel } from '@obliwan/shared';
import { CHANGE_JOB_STATUSES } from '@obliwan/shared';
import { errorMessageOf, isRouteAbsent, normalizeGuard, normalizeSafetyNet } from './change.api';
import { planApi } from './plan.api';
import { devicesApi } from './devices.api';
import type { DeviceImpact, SafetyNetLevel } from '@/types/change';
import type {
  GateState,
  HealthGateKind,
  HealthGateView,
  ImpactRadius,
  ImpactRow,
  RolloutDetail,
  RolloutLaunchRequest,
  RolloutStatus,
  RolloutTargetView,
  RolloutView,
  RolloutWaveView,
  WaveComposition,
  WaveStatus,
} from '@/types/rollout';
import {
  GATE_STATES,
  HEALTH_GATE_KINDS,
  ROLLOUT_STATUSES,
  WAVE_STATUSES,
  compareForWaveOrder,
} from '@/types/rollout';

/**
 * Wave rollouts (M7, killer K3).
 *
 * ── THE ROUTE PREFIXES — CHECKED, NOT ASSUMED ───────────────────────────────
 * `server/src/routes/index.ts` was READ at the time of writing. It mounts
 * `/sites /devices /discoveries /snmp /config /drift /templates /variables
 * /plan /changes` on the tenant router and NOTHING under `/rollouts`. The M7
 * API does not exist yet. So the EXACT paths this module calls are listed
 * here — the lead mounts them, this client does not guess them — and every one
 * of them degrades to a stated "endpoint unavailable", never to a blank screen:
 *
 *   GET    /api/rollouts?status&limit          -> RolloutView[]
 *   GET    /api/rollouts/config                -> { canLaunch, milestone, gates }
 *   GET    /api/rollouts/:id                   -> rollout + waves + targets
 *   GET    /api/rollouts/:id/waves             -> RolloutWaveView[]
 *   POST   /api/rollouts                       -> launch (RolloutLaunchRequest)
 *   POST   /api/rollouts/:id/pause             -> { reason }
 *   POST   /api/rollouts/:id/resume            -> {}
 *   POST   /api/rollouts/:id/abort             -> { reason }
 *
 * ── THE IMPACT-RADIUS SCREEN DOES NOT WAIT FOR M7 ───────────────────────────
 * §5/M7 asks for "compilation des N plans avant lancement" and §8.3 asks for
 * the safety net "affiché AVANT le lancement, jamais après". Both are buildable
 * TODAY out of endpoints that exist and that were read in the server source:
 *
 *   POST /api/plan/devices/:id (M5, mounted)  -> ONE plan, ops in FULL
 *   POST /api/changes/preview  (M6, mounted)  -> per-device net + guard verdict
 *
 * The per-device compile is used rather than the cheaper `POST /plan/compile`
 * on purpose: the fleet endpoint ships every op with `before`/`after` nulled
 * (`planDto(c, false)` in `plan.controller.ts`), and a Management-Path Guard
 * asked to simulate forwarding over nulled resources would answer about a plan
 * nobody is going to apply. A slower screen is worth an honest verdict.
 *
 * So `buildImpactRadius()` below is REAL against the current server: it
 * compiles, it previews, and it composes the waves. Only the LAUNCH needs M7.
 * That split is deliberate — the screen that decides whether to press the
 * button must not be the screen that is stubbed.
 *
 * ── WAVE COMPOSITION IS COMPUTED HERE AND SENT VERBATIM ─────────────────────
 * §8.3: a rollout mixing ARMED and DEGRADED treats the DEGRADED LAST. §8.5: a
 * concentrator's blast radius is its whole subtree, so it never belongs in a
 * canary wave. Both rules live in `compareForWaveOrder` and are applied here,
 * once; the resulting grouping is POSTed explicitly rather than recomputed
 * server-side, because a screen that shows one grouping and posts another is
 * the exact failure this screen exists to prevent.
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

function numbers(v: unknown): number[] {
  return Array.isArray(v) ? v.map((x) => Number(x)).filter((x) => Number.isFinite(x)) : [];
}

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  if (payload && typeof payload === 'object') {
    const p = payload as Raw;
    const items = p.items ?? p.rows ?? p.rollouts ?? p.waves ?? p.targets;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

// ── Normalisers, all pessimistic ────────────────────────────────────────────

const STATUSES: readonly string[] = ROLLOUT_STATUSES;
const WAVE: readonly string[] = WAVE_STATUSES;
const GATES: readonly string[] = HEALTH_GATE_KINDS;
const GATE_STATE: readonly string[] = GATE_STATES;
const JOB_STATUSES: readonly string[] = CHANGE_JOB_STATUSES;

/** An unrecognised rollout status is `failed`, never `succeeded`. Painting an
 *  unknown terminal state green would tell an operator that twenty routers he
 *  never checked are fine. */
function rolloutStatus(v: unknown): RolloutStatus {
  const str = String(v ?? '');
  return (STATUSES.includes(str) ? str : 'failed') as RolloutStatus;
}

function waveStatus(v: unknown): WaveStatus {
  const str = String(v ?? '');
  return (WAVE.includes(str) ? str : 'failed') as WaveStatus;
}

/** An unrecognised gate state is `unknown`, and `unknown` is NOT a pass. */
function gateState(v: unknown): GateState {
  const str = String(v ?? '');
  return (GATE_STATE.includes(str) ? str : 'unknown') as GateState;
}

function riskLevel(v: unknown): RiskLevel | null {
  const str = String(v ?? '');
  return str === 'low' || str === 'medium' || str === 'high' ? str : null;
}

export function normalizeGate(raw: unknown): HealthGateView | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Raw;
  const kind = String(pick(row, 'kind') ?? '');
  // A gate we do not know the NAME of cannot be rendered honestly — we would be
  // inventing a label for a signal we cannot describe. Dropped, and the wave
  // header reports the count mismatch instead.
  if (!GATES.includes(kind)) return null;
  return {
    kind: kind as HealthGateKind,
    state: gateState(pick(row, 'state') ?? pick(row, 'status')),
    failedDeviceIds: numbers(pick(row, 'failedDeviceIds')),
    observedAt: s(pick(row, 'observedAt')),
    detail: s(pick(row, 'detail') ?? pick(row, 'message')),
  };
}

export function normalizeWave(raw: Raw): RolloutWaveView {
  const gates = (Array.isArray(pick(raw, 'gates')) ? (pick(raw, 'gates') as unknown[]) : [])
    .map(normalizeGate)
    .filter((g): g is HealthGateView => g !== null);
  return {
    id: nOrNull(pick(raw, 'id')),
    rolloutId: n(pick(raw, 'rolloutId'), 0),
    index: n(pick(raw, 'index') ?? pick(raw, 'waveIndex'), 0),
    label: s(pick(raw, 'label')),
    status: waveStatus(pick(raw, 'status')),
    deviceIds: numbers(pick(raw, 'deviceIds')),
    gates,
    startedAt: s(pick(raw, 'startedAt')),
    finishedAt: s(pick(raw, 'finishedAt')),
    succeeded: n(pick(raw, 'succeeded'), 0),
    rolledBack: n(pick(raw, 'rolledBack'), 0),
    failed: n(pick(raw, 'failed'), 0),
  };
}

export function normalizeTarget(raw: Raw): RolloutTargetView {
  const outcome = String(pick(raw, 'outcome') ?? 'pending');
  const jobStatus = String(pick(raw, 'jobStatus') ?? '');
  return {
    deviceId: n(pick(raw, 'deviceId'), 0),
    deviceName: s(pick(raw, 'deviceName')),
    siteId: nOrNull(pick(raw, 'siteId')),
    siteName: s(pick(raw, 'siteName')),
    brand: String(pick(raw, 'brand') ?? ''),
    waveIndex: n(pick(raw, 'waveIndex') ?? pick(raw, 'index'), 0),
    // §8.3 — the fold happens in ONE place for the whole client and it folds
    // towards the worst reading of an unknown value.
    safetyNet: normalizeSafetyNet(pick(raw, 'safetyNet') ?? pick(raw, 'safetyLevel')),
    safetyPeerDeviceName: s(pick(raw, 'safetyPeerDeviceName') ?? pick(raw, 'peerDeviceName')),
    jobId: nOrNull(pick(raw, 'jobId')),
    jobStatus: JOB_STATUSES.includes(jobStatus)
      ? (jobStatus as RolloutTargetView['jobStatus'])
      : null,
    outcome: (['pending', 'applied', 'rolled_back', 'failed', 'skipped'].includes(outcome)
      ? outcome
      : 'failed') as RolloutTargetView['outcome'],
    errorMessage: s(pick(raw, 'errorMessage')),
  };
}

export function normalizeRollout(raw: Raw): RolloutView {
  return {
    id: n(pick(raw, 'id'), 0),
    uuid: String(pick(raw, 'uuid') ?? ''),
    name: String(pick(raw, 'name') ?? ''),
    status: rolloutStatus(pick(raw, 'status')),
    kind: (String(pick(raw, 'kind') ?? 'push')) as ChangeJobKind,
    revisionId: nOrNull(pick(raw, 'revisionId')),
    revision: nOrNull(pick(raw, 'revision')),
    templateName: s(pick(raw, 'templateName')),
    deviceCount: n(pick(raw, 'deviceCount'), 0),
    waveCount: n(pick(raw, 'waveCount'), 0),
    currentWave: nOrNull(pick(raw, 'currentWave')),
    riskLevel: riskLevel(pick(raw, 'riskLevel')),
    quarantinedRevisionId: nOrNull(pick(raw, 'quarantinedRevisionId')),
    quarantineReason: s(pick(raw, 'quarantineReason')),
    pausedReason: s(pick(raw, 'pausedReason')),
    requestedByName: s(pick(raw, 'requestedByName')),
    startedAt: s(pick(raw, 'startedAt')),
    finishedAt: s(pick(raw, 'finishedAt')),
    createdAt: String(pick(raw, 'createdAt') ?? ''),
    applied: n(pick(raw, 'applied'), 0),
    rolledBack: n(pick(raw, 'rolledBack'), 0),
    failed: n(pick(raw, 'failed'), 0),
    pending: n(pick(raw, 'pending'), 0),
  };
}

// ── The M6 preview, mapped onto `DeviceImpact` ──────────────────────────────

/**
 * `POST /api/changes/preview` returns the shape `previewChange()` declares in
 * `server/src/services/change/apply.service.ts` — `{ device, guard, safetyNet,
 * killSwitch, freshness, requiresOverride, requiresDegradedConfirmation }`.
 * That is NOT `DeviceImpact`, and this is the one place the two are bridged.
 *
 * Two foldings matter and both are pessimistic:
 *  - `guard.unavailable === true` becomes `ran: false`, which the badge paints
 *    as NOT RUN, on the refusing side. The guard admitting it could not run is
 *    not the guard concluding.
 *  - `requiresExplicitConfirmation` is OR-ed, never trusted: a DEGRADED net or
 *    a non-ACCEPT verdict demands the confirmation whatever the flags say.
 */
export function impactOfPreview(raw: unknown, fallbackDeviceId: number): DeviceImpact | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Raw;
  const deviceRaw = (pick(row, 'device') ?? {}) as Raw;
  const netRaw = (pick(row, 'safetyNet') ?? {}) as Raw;
  const guardRaw = pick(row, 'guard');
  const guard = normalizeGuard(guardRaw);
  const unavailable = Boolean(
    guardRaw && typeof guardRaw === 'object' && pick(guardRaw as Raw, 'unavailable'),
  );
  const safetyNet = normalizeSafetyNet(pick(netRaw, 'level'));
  return {
    deviceId: n(pick(deviceRaw, 'id'), fallbackDeviceId),
    deviceName: String(pick(deviceRaw, 'name') ?? ''),
    siteId: nOrNull(pick(deviceRaw, 'siteId')),
    siteName: s(pick(deviceRaw, 'siteName')),
    brand: String(pick(deviceRaw, 'brand') ?? ''),
    safetyNet,
    safetyPeerDeviceId: nOrNull(pick(netRaw, 'peerDeviceId')),
    safetyPeerDeviceName: s(pick(netRaw, 'peerDeviceName')),
    guard: { ...guard, ran: guard.ran && !unavailable },
    // The preview carries no risk level: it decides safety, not size. `high` is
    // the documented fail-closed value of `DeviceImpact`, and the impact screen
    // reads its risk from the COMPILED PLAN instead of from here.
    riskLevel: 'high',
    changeOpCount: 0,
    blockedOpCount: 0,
    disruptiveOpCount: 0,
    byOpKind: {},
    affectedInterfaces: [],
    affectedSubnets: [],
    touchesManagementPath: false,
    requiresExplicitConfirmation:
      Boolean(pick(row, 'requiresDegradedConfirmation')) ||
      Boolean(pick(row, 'requiresOverride')) ||
      safetyNet === 'DEGRADED' ||
      guard.verdict !== 'ACCEPT' ||
      unavailable,
  };
}

// ── Wave composition ────────────────────────────────────────────────────────

/**
 * Split an ordered device set into waves.
 *
 * The sizes are the canary ladder: one device, then a small wave, then the
 * rest in chunks. `compareForWaveOrder` has already put ARMED first and
 * DEGRADED and concentrators last, so the ladder gets the safest boxes first
 * by construction rather than by the operator remembering to sort.
 */
export function composeWaves(rows: ImpactRow[], sizes: number[] = [1, 3]): WaveComposition[] {
  const ordered = rows.slice().sort(compareForWaveOrder);
  const waves: WaveComposition[] = [];
  let cursor = 0;
  let index = 0;
  while (cursor < ordered.length) {
    const size = index < sizes.length
      ? Math.max(1, sizes[index])
      : Math.max(1, Math.ceil((ordered.length - cursor) / 2));
    waves.push({
      index,
      label: index === 0 ? 'canary' : `wave-${index + 1}`,
      rows: ordered.slice(cursor, cursor + size),
    });
    cursor += size;
    index += 1;
  }
  return waves;
}

export interface ImpactRadiusOptions {
  kind: ChangeJobKind;
  revisionId?: number | null;
  waveSizes?: number[];
  /** Progress callback so a 300-device set can show a counter instead of a
   *  spinner that looks hung. */
  onProgress?: (done: number, total: number) => void;
}

/**
 * THE pre-launch screen, computed against the REAL server.
 *
 * Step 1 compiles the N plans (`POST /plan/devices/:id`, `persistRender: false`
 * — a radius preview must not leave `config_renders` rows behind).
 * Step 2 asks the M6 preview for each device's safety net and guard verdict.
 * Step 3 composes the waves under the §8.3 / §8.5 ordering.
 *
 * A device whose plan did not compile is NOT previewed and NOT silently
 * dropped: it keeps a row, it carries `planError`, and its net reads DEGRADED
 * because a net we did not observe is a net we may not claim.
 */
export async function buildImpactRadius(
  deviceIds: number[],
  opts: ImpactRadiusOptions,
): Promise<ImpactRadius> {
  const devices = await devicesApi.list();
  const byId = new Map(devices.map((d) => [d.id, d]));
  const childCount = new Map<number, number>();
  const childSites = new Map<number, Set<number>>();
  for (const d of devices) {
    if (d.concentratorId === null) continue;
    childCount.set(d.concentratorId, (childCount.get(d.concentratorId) ?? 0) + 1);
    if (d.siteId !== null) {
      const set = childSites.get(d.concentratorId) ?? new Set<number>();
      set.add(d.siteId);
      childSites.set(d.concentratorId, set);
    }
  }

  const warnings: string[] = [];
  const rows: ImpactRow[] = [];
  let compiledCount = 0;
  let done = 0;

  for (const deviceId of deviceIds) {
    const device = byId.get(deviceId);

    // ── Step 1: this device's plan, ops in full ─────────────────────────────
    let plan: ApplyPlan | undefined;
    let planError: string | null = null;
    let risk: RiskLevel | null = null;
    let opCount = 0;
    let touchesMgmt = false;

    if (opts.kind === 'push') {
      try {
        const compiled = await planApi.compileDevice(deviceId, {
          revisionId: opts.revisionId ?? null,
          persistRender: false,
        });
        if (compiled === null) {
          planError = 'PLAN_ENDPOINT_ABSENT';
          if (!warnings.includes('PLAN_ENDPOINT_ABSENT')) warnings.push('PLAN_ENDPOINT_ABSENT');
        } else {
          plan = compiled.plan;
          risk = compiled.plan.riskLevel;
          opCount = compiled.plan.ops.filter((op) => op.kind !== 'verify').length;
          touchesMgmt = compiled.plan.blastRadius.touchesManagementPath;
          compiledCount += 1;
        }
      } catch (err) {
        planError = errorMessageOf(err) ?? 'PLAN_COMPILE_FAILED';
      }
    }

    // ── Step 2: this device's net + guard ───────────────────────────────────
    let impact: DeviceImpact | null = null;
    let impactError: string | null = null;

    // A `push` with no plan cannot be previewed honestly — the guard would have
    // no operations to simulate — so we do not ask, and we do not pretend.
    const previewable = opts.kind !== 'push' || plan !== undefined;
    if (previewable) {
      try {
        impact = await rolloutApi.previewDevice(deviceId, opts.kind, plan);
        if (impact === null) impactError = 'PREVIEW_ENDPOINT_ABSENT';
      } catch (err) {
        impactError = errorMessageOf(err) ?? 'PREVIEW_FAILED';
      }
    } else {
      impactError = planError ? 'PLAN_DID_NOT_COMPILE' : 'NO_PLAN';
    }

    const safetyNet: SafetyNetLevel = impact ? impact.safetyNet : 'DEGRADED';
    rows.push({
      deviceId,
      deviceName: device?.name ?? impact?.deviceName ?? `#${deviceId}`,
      siteName: device?.siteName ?? null,
      brand: device?.brand ?? impact?.brand ?? '',
      role: device?.role ?? 'cpe',
      concentratorId: device?.concentratorId ?? null,
      subtreeSize: childCount.get(deviceId) ?? 0,
      impact,
      impactError,
      planCompiled: plan !== undefined,
      planError,
      changeOpCount: opCount,
      riskLevel: risk,
      touchesManagementPath: touchesMgmt,
      safetyNet,
    });
    done += 1;
    opts.onProgress?.(done, deviceIds.length);
  }

  // ── Step 3: waves, blockers, warnings ─────────────────────────────────────
  const waves = composeWaves(rows, opts.waveSizes);
  const degradedCount = rows.filter((r) => r.safetyNet === 'DEGRADED').length;
  const guardRefusedCount = rows.filter(
    (r) => !r.impact || !r.impact.guard.ran || r.impact.guard.verdict !== 'ACCEPT',
  ).length;
  const concentrators = rows.filter((r) => r.role === 'concentrator');
  const subtreeSites = new Set<number>();
  for (const c of concentrators) {
    for (const siteId of childSites.get(c.deviceId) ?? []) subtreeSites.add(siteId);
  }

  const blockers: string[] = [];
  if (rows.length === 0) blockers.push('NO_DEVICES');
  if (opts.kind === 'push' && compiledCount === 0) blockers.push('NO_PLAN_COMPILED');

  return {
    rows,
    waves,
    degradedCount,
    guardRefusedCount,
    concentratorCount: concentrators.length,
    subtreeSiteCount: subtreeSites.size,
    blockers,
    warnings,
  };
}

// ── Config ──────────────────────────────────────────────────────────────────

export interface RolloutConfig {
  /** FAIL-CLOSED: false whenever the endpoint could not be read. A client that
   *  decided for itself that launching is possible is a client that queues N
   *  writes against a server with no rollout runner behind it. */
  canLaunch: boolean;
  milestone: string | null;
  /** Default canary ladder, server-owned so it is not a constant duplicated
   *  in the client. */
  waveSizes: number[];
  gates: HealthGateKind[];
}

export const ROLLOUT_CONFIG_FAIL_CLOSED: RolloutConfig = {
  canLaunch: false,
  milestone: 'M7',
  waveSizes: [1, 3],
  gates: [...HEALTH_GATE_KINDS],
};

// ── The client ──────────────────────────────────────────────────────────────

function clean(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

export const rolloutApi = {
  /** NEVER throws, ALWAYS fails closed. */
  async config(): Promise<RolloutConfig> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/rollouts/config');
      const row = (res.data.data ?? {}) as Raw;
      const sizes = numbers(pick(row, 'waveSizes'));
      const gates = (Array.isArray(pick(row, 'gates')) ? (pick(row, 'gates') as unknown[]) : [])
        .map((g) => String(g))
        .filter((g): g is HealthGateKind => GATES.includes(g));
      return {
        canLaunch: pick(row, 'canLaunch') === true,
        milestone: s(pick(row, 'milestone')) ?? null,
        waveSizes: sizes.length > 0 ? sizes : ROLLOUT_CONFIG_FAIL_CLOSED.waveSizes,
        gates: gates.length > 0 ? gates : ROLLOUT_CONFIG_FAIL_CLOSED.gates,
      };
    } catch {
      return ROLLOUT_CONFIG_FAIL_CLOSED;
    }
  },

  /** `null` = the rollout API is not served by this build. */
  async list(params: { status?: string; limit?: number } = {}): Promise<RolloutView[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/rollouts', {
        params: clean(params as Record<string, unknown>),
      });
      return asRows(res.data.data).map(normalizeRollout);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** One rollout with its waves and targets. Waves may travel inline or behind
   *  the sub-route; both are accepted rather than guessed, because getting it
   *  wrong shows up as a permanently empty wave list and never as an error. */
  async get(id: number): Promise<RolloutDetail | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/rollouts/${id}`);
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      const row = payload as Raw;
      const base = normalizeRollout((pick(row, 'rollout') ?? row) as Raw);
      const inlineWaves = pick(row, 'waves');
      const waves = Array.isArray(inlineWaves)
        ? (inlineWaves as Raw[]).map(normalizeWave)
        : ((await this.waves(id)) ?? []);
      const targets = asRows(pick(row, 'targets')).map(normalizeTarget);
      return { ...base, waves, targets };
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async waves(rolloutId: number): Promise<RolloutWaveView[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/rollouts/${rolloutId}/waves`);
      return asRows(res.data.data).map(normalizeWave);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * The M6 impact preview for ONE device — `POST /api/changes/preview`, which
   * is mounted TODAY. `null` means that route is absent from this build.
   *
   * The `plan` is sent whole when there is one: the server re-parses it with
   * the shared `ApplyPlan` schema, and a uuid would let a plan compiled by one
   * server version be reinterpreted by another.
   */
  async previewDevice(
    deviceId: number,
    kind: ChangeJobKind,
    plan?: ApplyPlan,
  ): Promise<DeviceImpact | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>('/changes/preview', {
        deviceId,
        kind,
        ...(plan ? { plan } : {}),
      });
      return impactOfPreview(res.data.data, deviceId);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** Launch. `null` = the M7 route is absent; the caller says so and writes
   *  nothing. */
  async launch(req: RolloutLaunchRequest): Promise<RolloutView | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>('/rollouts', req);
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      return normalizeRollout((pick(payload as Raw, 'rollout') ?? payload) as Raw);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async pause(id: number, reason: string): Promise<boolean> {
    return post(`/rollouts/${id}/pause`, { reason });
  },

  async resume(id: number): Promise<boolean> {
    return post(`/rollouts/${id}/resume`, {});
  },

  /** Abort stops what has NOT started. It does not un-apply what has: waves
   *  already applied stay applied unless their own dead-man fires. The screen
   *  says that sentence next to the button. */
  async abort(id: number, reason: string): Promise<boolean> {
    return post(`/rollouts/${id}/abort`, { reason });
  },
};

async function post(path: string, body: unknown): Promise<boolean> {
  try {
    await apiClient.post<ApiResponse<unknown>>(path, body);
    return true;
  } catch (err) {
    if (isRouteAbsent(err)) return false;
    throw err;
  }
}
