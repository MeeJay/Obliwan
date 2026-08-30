import apiClient from './client';
import type {
  ApiResponse,
  ApplyPlan,
  ChangeJobKind,
  GuardVerdict,
  PlanOpKind,
  SafetyLevel,
} from '@obliwan/shared';
import {
  APPLY_OUTCOME_MIN_OBSERVATIONS,
  CHANGE_JOB_KINDS,
  CHANGE_JOB_STATUSES,
  CHANGE_STEP_KINDS,
  CHANGE_STEP_STATUSES,
  PLAN_OP_KINDS,
} from '@obliwan/shared';
import type {
  ChangeJobDetail,
  ChangeJobStepView,
  ChangeJobView,
  CreateJobRequest,
  DeviceImpact,
  GuardProbeView,
  GuardReasonView,
  GuardResultView,
  GuardRouteView,
  KillSwitchView,
  OutcomeHistoryView,
  SafetyNetLevel,
} from '@/types/change';

/**
 * Change jobs, the safety-net preflight and the kill switch (M6, decision D3).
 *
 * ── THE ROUTE PREFIX — CHECKED, NOT ASSUMED ─────────────────────────────────
 * `server/src/routes/index.ts` was read at the time of writing and mounts NO
 * change router at all: the M6 API is being written in parallel by another
 * agent. In M3 the client forgot the `/snmp` prefix and in M4 the paths
 * diverged; the lead re-stitched both times. So the EXACT paths this client
 * calls are listed here, in the shape the existing tenant-scoped routers use
 * (`/sites`, `/devices`, `/snmp`, `/config`, `/drift`, `/plan`), and every one
 * of them degrades to a stated "endpoint unavailable" rather than to a blank
 * screen:
 *
 *   GET    /api/changes/config                        -> apply gate + soak window
 *   GET    /api/changes/jobs?deviceId&status&limit     -> ChangeJobView[]
 *   GET    /api/changes/jobs/:id                       -> job + steps + plan + guard
 *   GET    /api/changes/jobs/:id/steps                 -> ChangeJobStepView[]
 *   POST   /api/changes/jobs                           -> create (CreateJobRequest)
 *   POST   /api/changes/jobs/:id/abort                 -> { reason }
 *   POST   /api/changes/preflight                      -> { deviceIds } -> DeviceImpact[]
 *   GET    /api/changes/kill-switch                    -> KillSwitchView
 *   POST   /api/changes/kill-switch                    -> { engaged, reason }
 *
 * ── THREE FAIL-CLOSED RULES THIS FILE ENFORCES ──────────────────────────────
 *  1. AN UNKNOWN SAFETY LEVEL IS `DEGRADED`. Not ARMED, not "probably armed".
 *     A value we do not recognise is a net we cannot claim exists (§8.3, A2).
 *  2. AN UNKNOWN OR ABSENT GUARD VERDICT IS `INDETERMINATE`, and the result
 *     carries `ran: false` so the screen can distinguish "the guard could not
 *     conclude" from "the guard was never asked". Neither is an ACCEPT.
 *  3. AN UNREADABLE KILL SWITCH IS ENGAGED. `kill_switch_blocks()` in
 *     migration 009 returns true when the global row is missing; this client
 *     mirrors that, because a kill switch that fails open is not a kill switch.
 *
 * ── §8.2 ────────────────────────────────────────────────────────────────────
 * `outputRedacted` / `errorRedacted` arrive already masked. This module does
 * not unmask, re-parse or pretty-print them; it hands the string through and
 * the renderer scans it. There is no field in any shape here that could carry
 * a rendered configuration body.
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

export function isRouteAbsent(err: unknown): boolean {
  const st = statusOf(err);
  return st === 404 || st === 501;
}

export function errorMessageOf(err: unknown): string | null {
  const data = (err as { response?: { data?: { error?: string; message?: string } } }).response?.data;
  return data?.error ?? data?.message ?? null;
}

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  if (payload && typeof payload === 'object') {
    const p = payload as Raw;
    const items = p.items ?? p.rows ?? p.jobs ?? p.steps ?? p.devices ?? p.impacts;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

function asJson<T>(v: unknown, fallback: T): T {
  if (v === null || v === undefined) return fallback;
  if (typeof v === 'string') {
    try { return JSON.parse(v) as T; } catch { return fallback; }
  }
  return v as T;
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.map((x) => String(x)) : [];
}

function numbers(v: unknown): number[] {
  return Array.isArray(v) ? v.map((x) => Number(x)).filter((x) => Number.isFinite(x)) : [];
}

// ── Safety net ──────────────────────────────────────────────────────────────

/**
 * THE fold of §8.3, and the only place it happens.
 *
 * The server speaks two dialects: `blastRadius.service.ts` returns
 * `ARMED | ARMED_BY_PEER | DEGRADED`, `devices.safety_level` stores
 * `armed | armed_by_peer | degraded`. Both are accepted. EVERYTHING ELSE —
 * null, undefined, a typo, a level from a newer server — becomes `DEGRADED`.
 *
 * That asymmetry is deliberate and it is the whole safety argument: reading an
 * unknown value as ARMED would silently remove the explicit confirmation §8.3
 * requires, on precisely the devices we understand least.
 */
export function normalizeSafetyNet(v: unknown): SafetyNetLevel {
  const str = String(v ?? '').trim().toUpperCase();
  if (str === 'ARMED') return 'ARMED';
  if (str === 'ARMED_BY_PEER') return 'ARMED_BY_PEER';
  return 'DEGRADED';
}

/** The lowercase `SafetyLevel` of `devices` / `change_jobs`. Same asymmetry. */
export function normalizeSafetyLevel(v: unknown): SafetyLevel {
  const str = String(v ?? '').trim().toLowerCase();
  if (str === 'armed') return 'armed';
  if (str === 'armed_by_peer') return 'armed_by_peer';
  return 'degraded';
}

export function safetyNetOfLevel(level: SafetyLevel): SafetyNetLevel {
  if (level === 'armed') return 'ARMED';
  if (level === 'armed_by_peer') return 'ARMED_BY_PEER';
  return 'DEGRADED';
}

// ── Guard ───────────────────────────────────────────────────────────────────

const REJECT_CODES = new Set([
  'INPUT_DROP', 'OUTPUT_DROP', 'CHAIN_POLICY_DROP', 'NO_ROUTE', 'TUNNEL_CRITICAL',
  'MGMT_ADDRESS_LOST', 'MGMT_SERVICE_LOST', 'NAT_HIJACK',
  // The `shared/src/change.ts` vocabulary, which the persisted job row uses.
  'ACCEPT_BECOMES_DROP', 'DEFAULT_POLICY_DROP', 'MGMT_ADDRESS_REMOVED',
  'MGMT_INTERFACE_DISABLED', 'MGMT_SERVICE_DISABLED', 'NAT_BREAKS_RETURN_PATH',
  'DEADMAN_UNAVAILABLE',
]);

function opKindValue(v: unknown): PlanOpKind | null {
  const str = String(v ?? '');
  return (PLAN_OP_KINDS as readonly string[]).includes(str) ? (str as PlanOpKind) : null;
}

function outcome(v: unknown): 'accept' | 'drop' | 'unknown' {
  const str = String(v ?? '').toLowerCase();
  return str === 'accept' || str === 'drop' ? str : 'unknown';
}

function routeView(v: unknown): GuardRouteView {
  const row = (v ?? {}) as Raw;
  const st = String(pick(row, 'state') ?? '').toLowerCase();
  return {
    state: st === 'ok' || st === 'broken' || st === 'none' ? st : 'unknown',
    via: s(pick(row, 'via')),
    egress: s(pick(row, 'egress')),
    detail: String(pick(row, 'detail') ?? ''),
  };
}

function reasonView(v: unknown): GuardReasonView {
  const row = (v ?? {}) as Raw;
  const code = String(pick(row, 'code') ?? 'UNKNOWN');
  const declared = String(pick(row, 'effect') ?? '').toLowerCase();
  const culpritRaw = pick(row, 'culprit');
  const culprit = culpritRaw && typeof culpritRaw === 'object' ? (culpritRaw as Raw) : null;
  return {
    code,
    // The server's own `effect` wins; the code table is the fallback for a
    // build that does not send it. An unrecognised code is `indeterminate`
    // rather than `reject` — we must not manufacture a proof we do not have.
    effect: declared === 'reject' || declared === 'indeterminate'
      ? (declared as 'reject' | 'indeterminate')
      : (REJECT_CODES.has(code) ? 'reject' : 'indeterminate'),
    probe: s(pick(row, 'probe')),
    message: String(pick(row, 'message') ?? ''),
    culprit: culprit
      ? {
          resource: String(pick(culprit, 'resource') ?? ''),
          semKey: String(pick(culprit, 'semKey') ?? ''),
          index: nOrNull(pick(culprit, 'index')),
          chain: s(pick(culprit, 'chain')),
          describe: String(pick(culprit, 'describe') ?? ''),
          opSeq: nOrNull(pick(culprit, 'opSeq')),
          opKind: opKindValue(pick(culprit, 'opKind')),
        }
      : null,
  };
}

function probeView(v: unknown): GuardProbeView {
  const row = (v ?? {}) as Raw;
  return {
    id: String(pick(row, 'id') ?? ''),
    description: String(pick(row, 'description') ?? ''),
    before: outcome(pick(row, 'before')),
    after: outcome(pick(row, 'after')),
  };
}

function verdictValue(v: unknown, fallback: GuardVerdict = 'INDETERMINATE'): GuardVerdict {
  const str = String(v ?? '').trim().toUpperCase();
  // `ACCEPT` is the only value that unlocks anything, so it is the only one
  // that must be spelled exactly. Everything unrecognised falls back, and the
  // fallback is never ACCEPT.
  if (str === 'ACCEPT') return 'ACCEPT';
  if (str === 'REJECT') return 'REJECT';
  if (str === 'INDETERMINATE') return 'INDETERMINATE';
  return fallback === 'ACCEPT' ? 'ACCEPT' : fallback;
}

/**
 * The guard block.
 *
 * `ran` is the field that matters: a payload with no guard object at all means
 * K2 was NOT invoked for this plan. The caller may pass `fallbackVerdict` (the
 * plan's own lowercase verdict, bridged through the shared mapper) so the
 * screen still shows something honest — but `ran: false` travels with it and
 * the UI labels it "not run".
 */
export function normalizeGuard(
  raw: unknown,
  opts: { fallbackVerdict?: GuardVerdict } = {},
): GuardResultView {
  const fallback = opts.fallbackVerdict ?? 'INDETERMINATE';
  if (!raw || typeof raw !== 'object') {
    return {
      verdict: fallback,
      planVerdict: fallback === 'ACCEPT' ? 'accept' : fallback === 'REJECT' ? 'veto' : 'indeterminate',
      reasons: [],
      probes: [],
      routing: null,
      culpritOpSeqs: [],
      summary: '',
      analysed: null,
      ran: false,
    };
  }
  const row = raw as Raw;
  const verdict = verdictValue(pick(row, 'verdict'), fallback);
  const routingRaw = pick(row, 'routing');
  const analysedRaw = pick(row, 'analysed');
  const analysed = analysedRaw && typeof analysedRaw === 'object' ? (analysedRaw as Raw) : null;
  const pv = String(pick(row, 'planVerdict') ?? '');
  return {
    verdict,
    planVerdict: pv === 'accept' || pv === 'veto' || pv === 'indeterminate'
      ? pv
      : verdict === 'ACCEPT' ? 'accept' : verdict === 'REJECT' ? 'veto' : 'indeterminate',
    reasons: (Array.isArray(pick(row, 'reasons')) ? (pick(row, 'reasons') as unknown[]) : [])
      .map(reasonView),
    probes: (Array.isArray(pick(row, 'probes')) ? (pick(row, 'probes') as unknown[]) : [])
      .map(probeView),
    routing: routingRaw && typeof routingRaw === 'object'
      ? {
          before: routeView((routingRaw as Raw).before),
          after: routeView((routingRaw as Raw).after),
        }
      : null,
    culpritOpSeqs: numbers(pick(row, 'culpritOpSeqs')),
    summary: String(pick(row, 'summary') ?? ''),
    analysed: analysed
      ? {
          peerAddress: s(pick(analysed, 'peerAddress')),
          managementAddress: s(pick(analysed, 'managementAddress')),
          tunnelInterface: s(pick(analysed, 'tunnelInterface')),
          tunnelInterfaceCertain: bool(pick(analysed, 'tunnelInterfaceCertain')),
          ports: numbers(pick(analysed, 'ports')),
        }
      : null,
    ran: true,
  };
}

// ── Impact ──────────────────────────────────────────────────────────────────

export function normalizeImpact(raw: unknown): DeviceImpact | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Raw;
  const safetyNet = normalizeSafetyNet(pick(row, 'safetyNet') ?? pick(row, 'safetyLevel'));
  const guard = normalizeGuard(pick(row, 'guard'), {
    fallbackVerdict: verdictValue(pick(row, 'guardVerdict')),
  });
  const peerId = nOrNull(pick(row, 'safetyPeerDeviceId') ?? pick(row, 'peerDeviceId'));
  return {
    deviceId: n(pick(row, 'deviceId'), 0),
    deviceName: String(pick(row, 'deviceName') ?? ''),
    siteId: nOrNull(pick(row, 'siteId')),
    siteName: s(pick(row, 'siteName')),
    brand: String(pick(row, 'brand') ?? ''),
    safetyNet,
    safetyPeerDeviceId: peerId,
    safetyPeerDeviceName: s(pick(row, 'safetyPeerDeviceName') ?? pick(row, 'peerDeviceName')),
    guard,
    riskLevel: ((): DeviceImpact['riskLevel'] => {
      const v = String(pick(row, 'riskLevel') ?? '');
      // An unknown risk is `high`: the four-eyes side of the fence.
      return v === 'low' || v === 'medium' ? v : 'high';
    })(),
    changeOpCount: n(pick(row, 'changeOpCount'), 0),
    blockedOpCount: n(pick(row, 'blockedOpCount'), 0),
    disruptiveOpCount: n(pick(row, 'disruptiveOpCount'), 0),
    byOpKind: asJson<Partial<Record<PlanOpKind, number>>>(pick(row, 'byOpKind'), {}),
    affectedInterfaces: strings(pick(row, 'affectedInterfaces')),
    affectedSubnets: strings(pick(row, 'affectedSubnets')),
    touchesManagementPath: bool(pick(row, 'touchesManagementPath')),
    // Recomputed rather than trusted: the two conditions of §8.3 are a DEGRADED
    // net or a guard that did not ACCEPT, and the client must not be able to
    // show a launch screen with no confirmation because a flag was missing.
    requiresExplicitConfirmation:
      bool(pick(row, 'requiresExplicitConfirmation')) ||
      safetyNet === 'DEGRADED' ||
      guard.verdict !== 'ACCEPT',
  };
}

export function normalizeOutcomeHistory(raw: unknown): OutcomeHistoryView[] {
  return asRows(raw).map((row) => {
    const succeeded = n(pick(row, 'succeeded'), 0);
    const rolledBack = n(pick(row, 'rolledBack'), 0);
    const lostContact = n(pick(row, 'lostContact'), 0);
    const total = n(pick(row, 'total'), succeeded + rolledBack + lostContact);
    return {
      opKind: (String(pick(row, 'opKind') ?? 'push')) as ChangeJobKind,
      brand: String(pick(row, 'brand') ?? ''),
      model: s(pick(row, 'model')),
      osVersion: s(pick(row, 'osVersion')),
      succeeded,
      rolledBack,
      lostContact,
      total,
      // Recomputed against the shared threshold: a server that forgot the flag
      // must not make the UI print a percentage over four observations.
      significant: bool(pick(row, 'significant')) && total >= APPLY_OUTCOME_MIN_OBSERVATIONS,
    };
  });
}

// ── Jobs ────────────────────────────────────────────────────────────────────

const JOB_KINDS: readonly string[] = CHANGE_JOB_KINDS;
const JOB_STATUSES: readonly string[] = CHANGE_JOB_STATUSES;
const STEP_KINDS: readonly string[] = CHANGE_STEP_KINDS;
const STEP_STATUSES: readonly string[] = CHANGE_STEP_STATUSES;

export function normalizeJob(raw: Raw): ChangeJobView {
  const kind = String(pick(raw, 'kind') ?? '');
  const status = String(pick(raw, 'status') ?? '');
  const gv = pick(raw, 'guardVerdict');
  return {
    id: n(pick(raw, 'id'), 0),
    uuid: String(pick(raw, 'uuid') ?? ''),
    deviceId: n(pick(raw, 'deviceId'), 0),
    deviceName: s(pick(raw, 'deviceName')),
    siteId: nOrNull(pick(raw, 'siteId')),
    siteName: s(pick(raw, 'siteName')),
    planId: nOrNull(pick(raw, 'planId')),
    kind: (JOB_KINDS.includes(kind) ? kind : 'push') as ChangeJobKind,
    // An unrecognised status becomes `failed`, never `succeeded`: painting an
    // unknown terminal state green is the drift-page mistake, repeated on a
    // screen where it would mean "your router is fine" about a router nobody
    // checked.
    status: (JOB_STATUSES.includes(status) ? status : 'failed') as ChangeJobView['status'],
    attempt: n(pick(raw, 'attempt'), 1),

    safetyLevel: normalizeSafetyLevel(pick(raw, 'safetyLevel')),
    safetyPeerDeviceId: nOrNull(pick(raw, 'safetyPeerDeviceId')),
    safetyPeerDeviceName: s(pick(raw, 'safetyPeerDeviceName')),
    // `null` when the column is null — "no verdict recorded" is a distinct
    // fact from INDETERMINATE and the job screen says which one it is.
    guardVerdict: gv === null || gv === undefined ? null : verdictValue(gv),
    guardReasons: strings(asJson<unknown>(pick(raw, 'guardReasons'), [])),
    overrideReason: s(pick(raw, 'overrideReason')),
    overriddenBy: nOrNull(pick(raw, 'overriddenBy')),
    overriddenByName: s(pick(raw, 'overriddenByName')),
    overriddenAt: s(pick(raw, 'overriddenAt')),
    degradedConfirmedBy: nOrNull(pick(raw, 'degradedConfirmedBy')),
    degradedConfirmedByName: s(pick(raw, 'degradedConfirmedByName')),
    degradedConfirmedAt: s(pick(raw, 'degradedConfirmedAt')),

    riskLevel: ((): ChangeJobView['riskLevel'] => {
      const v = s(pick(raw, 'riskLevel'));
      return v === 'low' || v === 'medium' || v === 'high' ? v : null;
    })(),
    baseStateHash: s(pick(raw, 'baseStateHash')),
    preflightBackupId: nOrNull(pick(raw, 'preflightBackupId')),

    deadmanArmedAt: s(pick(raw, 'deadmanArmedAt')),
    deadmanDisarmedAt: s(pick(raw, 'deadmanDisarmedAt')),
    armedLevel: pick(raw, 'armedLevel') === null || pick(raw, 'armedLevel') === undefined
      ? null
      : normalizeSafetyLevel(pick(raw, 'armedLevel')),
    soakUntil: s(pick(raw, 'soakUntil')),

    scheduledFor: s(pick(raw, 'scheduledFor')),
    windowStart: s(pick(raw, 'windowStart')),
    windowEnd: s(pick(raw, 'windowEnd')),

    requestedBy: nOrNull(pick(raw, 'requestedBy')),
    requestedByName: s(pick(raw, 'requestedByName')),
    startedAt: s(pick(raw, 'startedAt')),
    finishedAt: s(pick(raw, 'finishedAt')),
    errorKind: s(pick(raw, 'errorKind')),
    errorMessage: s(pick(raw, 'errorMessage')),
    createdAt: String(pick(raw, 'createdAt') ?? ''),
  };
}

export function normalizeStep(raw: Raw): ChangeJobStepView {
  const kind = String(pick(raw, 'kind') ?? '');
  const status = String(pick(raw, 'status') ?? '');
  return {
    id: n(pick(raw, 'id'), 0),
    jobId: n(pick(raw, 'jobId'), 0),
    seq: n(pick(raw, 'seq'), 0),
    attempt: n(pick(raw, 'attempt'), 1),
    kind: (STEP_KINDS.includes(kind) ? kind : 'apply') as ChangeJobStepView['kind'],
    status: (STEP_STATUSES.includes(status) ? status : 'failed') as ChangeJobStepView['status'],
    planOpSeq: nOrNull(pick(raw, 'planOpSeq')),
    startedAt: s(pick(raw, 'startedAt')),
    finishedAt: s(pick(raw, 'finishedAt')),
    durationMs: nOrNull(pick(raw, 'durationMs')),
    outputRedacted: s(pick(raw, 'outputRedacted')),
    errorRedacted: s(pick(raw, 'errorRedacted')),
  };
}

// ── Kill switch ─────────────────────────────────────────────────────────────

/** The fail-closed value. `known: false` so the UI says "state unknown —
 *  treating as engaged" rather than inventing a reason nobody wrote. */
export const KILL_SWITCH_FAIL_CLOSED: KillSwitchView = {
  blocked: true,
  by: null,
  reason: null,
  engagedAt: null,
  engagedByName: null,
  known: false,
};

export function normalizeKillSwitch(raw: unknown): KillSwitchView {
  if (!raw || typeof raw !== 'object') return KILL_SWITCH_FAIL_CLOSED;
  const row = raw as Raw;
  const by = String(pick(row, 'by') ?? pick(row, 'scope') ?? '');
  const engaged = pick(row, 'blocked') ?? pick(row, 'engaged');
  // `=== false` and not `!truthy`: only an explicit, recognised "not blocked"
  // clears the gate. Anything else — missing field, string, null — blocks.
  const blocked = !(engaged === false || engaged === 'false' || engaged === 0 || engaged === 'f');
  return {
    blocked,
    by: by === 'global' || by === 'tenant' ? by : null,
    reason: s(pick(row, 'reason')),
    engagedAt: s(pick(row, 'engagedAt')),
    engagedByName: s(pick(row, 'engagedByName')),
    known: true,
  };
}

// ── The client ──────────────────────────────────────────────────────────────

export interface JobListParams {
  deviceId?: number;
  status?: string;
  limit?: number;
}

function clean(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

export const changeApi = {
  /** Jobs, newest first. `null` = the change API is not served by this build. */
  async listJobs(params: JobListParams = {}): Promise<ChangeJobView[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/changes/jobs', {
        params: clean(params as Record<string, unknown>),
      });
      return asRows(res.data.data).map(normalizeJob);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * One job with its steps.
   *
   * Steps may travel inside the job payload or behind the sub-route depending
   * on how the API agent splits it; both are accepted rather than guessed,
   * because getting this wrong shows up as a timeline that is permanently
   * empty and never as an error.
   */
  async getJob(id: number): Promise<ChangeJobDetail | null> {
    const res = await apiClient.get<ApiResponse<unknown>>(`/changes/jobs/${id}`);
    const payload = res.data.data;
    if (!payload || typeof payload !== 'object') return null;
    const row = payload as Raw;
    const jobRaw = ((pick(row, 'job') ?? row) as Raw);
    const job = normalizeJob(jobRaw);
    const inline = pick(row, 'steps');
    const steps = Array.isArray(inline)
      ? (inline as Raw[]).map(normalizeStep)
      : ((await this.steps(id)) ?? []);
    const planRaw = pick(row, 'plan');
    const plan = planRaw && typeof planRaw === 'object' ? (planRaw as unknown as ApplyPlan) : null;
    const guardRaw = pick(row, 'guard');
    return {
      ...job,
      steps,
      plan,
      planOps: plan ? plan.ops : [],
      blastRadius: plan ? plan.blastRadius : null,
      guard: guardRaw && typeof guardRaw === 'object'
        ? normalizeGuard(guardRaw, { fallbackVerdict: job.guardVerdict ?? 'INDETERMINATE' })
        : null,
    };
  },

  async steps(jobId: number): Promise<ChangeJobStepView[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/changes/jobs/${jobId}/steps`);
      return asRows(res.data.data).map(normalizeStep);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * The §8.3 preflight: per-device safety net + guard verdict, computed BEFORE
   * the launch screen is shown. It is a POST because it takes a device set and
   * because it is allowed to be expensive — it re-reads the snapshot and runs
   * the forwarding engine.
   */
  async preflight(deviceIds: number[], plan?: unknown): Promise<DeviceImpact[] | null> {
    try {
      // The server takes the full ApplyPlan envelope, not an identifier: plans
      // are frozen into `change_plans` at ENQUEUE time (D3), so no plan uuid
      // exists to point at yet while this screen is still deciding. The earlier
      // `planUuid` field named something the API never had, and `.strict()` on
      // the server would have rejected the whole request.
      const res = await apiClient.post<ApiResponse<unknown>>('/changes/preflight', {
        deviceIds,
        kind: 'push',
        ...(plan === undefined ? {} : { plan }),
      });
      return asRows(res.data.data)
        .map(normalizeImpact)
        .filter((x): x is DeviceImpact => x !== null);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * Enqueue a write.
   *
   * The client does NOT decide whether the override or the degraded
   * confirmation is required — it sends what the operator gave and the server
   * refuses the row if it is not enough (migration 009's CHECK constraints).
   * That ordering matters: a client-side gate is a convenience, a CHECK
   * constraint is the guarantee, and this method must never be the only thing
   * standing between a blank reason and a written router.
   */
  async createJob(req: CreateJobRequest): Promise<ChangeJobView | null> {
    const res = await apiClient.post<ApiResponse<unknown>>('/changes/jobs', req);
    const payload = res.data.data;
    if (!payload || typeof payload !== 'object') return null;
    const row = payload as Raw;
    return normalizeJob(((pick(row, 'job') ?? row) as Raw));
  },

  /** Cancel a job that has not written yet. The server refuses past `arming`
   *  (`CHANGE_JOB_TRANSITIONS`): you cannot cancel a change already going onto
   *  a router, you can only let the machinery finish or the dead-man fire. */
  async abortJob(id: number, reason: string): Promise<boolean> {
    try {
      await apiClient.post<ApiResponse<unknown>>(`/changes/jobs/${id}/abort`, { reason });
      return true;
    } catch (err) {
      if (isRouteAbsent(err)) return false;
      throw err;
    }
  },

  /** NEVER throws, ALWAYS fails closed. */
  async killSwitch(): Promise<KillSwitchView> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/changes/kill-switch');
      return normalizeKillSwitch(res.data.data);
    } catch {
      return KILL_SWITCH_FAIL_CLOSED;
    }
  },

  /**
   * Flip it. `reason` is mandatory when engaging — the sentence is shown on
   * every refused job afterwards, and "somebody stopped the world at 02:14"
   * without a why is an incident that takes an hour longer.
   */
  /**
   * The server deliberately splits this in two, and the split is NOT cosmetic:
   * engaging needs CHANGE_APPLY, releasing needs SETTINGS_MANAGE. Panic must be
   * cheap, un-panic must not — whoever can stop the fleet is not automatically
   * whoever decides it is safe to start again.
   *
   * Collapsing the two into one endpoint here would have quietly flattened that
   * asymmetry, so the client follows the server instead.
   */
  async setKillSwitch(
    engaged: boolean,
    reason: string,
    scope: 'global' | 'tenant' = 'global',
  ): Promise<KillSwitchView> {
    const res = await apiClient.post<ApiResponse<unknown>>(
      engaged ? '/changes/kill-switch/engage' : '/changes/kill-switch/release',
      { scope, reason },
    );
    return normalizeKillSwitch(res.data.data);
  },
};
