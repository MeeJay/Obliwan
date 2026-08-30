import apiClient from './client';
import type { ApiResponse, ApplyPlan, PlanOp } from '@obliwan/shared';
import { guardVerdictOfMgmtPath } from '@obliwan/shared';
import type { CompiledPlan, PlanConfig } from '@/types/change';
import { normalizeGuard, normalizeImpact, normalizeOutcomeHistory } from './change.api';

/**
 * Plan compilation (M5) + the M6 apply gate.
 *
 * ── THE ROUTE PREFIX ────────────────────────────────────────────────────────
 * CHECKED, NOT ASSUMED — `server/src/routes/index.ts` mounts `planRoutes` on
 * `tenantRouter` at `/plan`, and `plan.routes.ts` declares exactly four paths.
 * All four exist today:
 *
 *   GET  /api/plan/config                 -> { planTtlMs, canApply, applyMilestone }
 *   POST /api/plan/devices/:deviceId      -> { plan, summary, detail, notice }
 *   POST /api/plan/compile                -> { plans, failures, summary }
 *   POST /api/plan/validate               -> 200 fresh | 409 stale
 *
 * The M6 additions this client READS but does not require — `guard`, `impact`,
 * `outcomeHistory` on the per-device payload — are absent from the M5 server.
 * Their absence is handled as "the guard was NOT RUN", never as an ACCEPT.
 *
 * ── WHY `canApply` IS FETCHED AND NEVER ASSUMED ─────────────────────────────
 * M5 answers `{ canApply: false, applyMilestone: 'M6' }`. Every apply control
 * in this client is gated on that single boolean, read from the server on every
 * page mount. A client that decided for itself that applying is possible would
 * be a client that queues a write against a server with no queue behind it.
 * On ANY failure to read it, `canApply` is false: fail-closed.
 *
 * ── STALENESS IS A REFUSAL, NOT A WARNING ───────────────────────────────────
 * `POST /plan/validate` answers 409 when the device moved under the plan. This
 * module surfaces that as `{ fresh: false, message }` rather than throwing,
 * because the caller is a screen that must show the sentence — but no caller is
 * allowed to render an Apply button on `fresh: false`. A stale plan applied to
 * a box somebody edited in Winbox is how an operator deletes a rule he never
 * saw.
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

function statusOf(err: unknown): number | undefined {
  return (err as { response?: { status?: number } }).response?.status;
}

function isRouteAbsent(err: unknown): boolean {
  const st = statusOf(err);
  return st === 404 || st === 501;
}

function messageOf(err: unknown): string | null {
  const data = (err as { response?: { data?: { error?: string; message?: string } } }).response?.data;
  return data?.error ?? data?.message ?? null;
}

function asArray(v: unknown): Raw[] {
  return Array.isArray(v) ? (v as Raw[]) : [];
}

/**
 * The fail-closed default.
 *
 * Note `canApply: false` AND `applyMilestone: null`. A client that could not
 * reach `/plan/config` does not know which milestone it is waiting for either,
 * and inventing 'M6' here would put a reassuring sentence under a control that
 * is disabled for an entirely different reason (the server is down).
 */
export const PLAN_CONFIG_FAIL_CLOSED: PlanConfig = {
  planTtlMs: 0,
  canApply: false,
  applyMilestone: null,
  mgmtPathGuard: null,
  soakMs: null,
};

function normalizePlanConfig(raw: unknown): PlanConfig {
  if (!raw || typeof raw !== 'object') return PLAN_CONFIG_FAIL_CLOSED;
  const row = raw as Raw;
  return {
    planTtlMs: n(pick(row, 'planTtlMs'), 0),
    // `=== true` and not a truthiness test: a server that answers the string
    // "false" must not unlock the write path.
    canApply: pick(row, 'canApply') === true,
    applyMilestone: s(pick(row, 'applyMilestone')),
    mgmtPathGuard: s(pick(row, 'mgmtPathGuard')),
    soakMs: nOrNull(pick(row, 'soakMs')),
  };
}

/**
 * The plan envelope.
 *
 * The server sends it already shaped by `ApplyPlan`; this only fills the holes
 * a build without M6 leaves, and never rewrites a field the server sent. In
 * particular `mgmtPathVerdict` is taken VERBATIM: the M5 planner hard-codes
 * `indeterminate` and that is the truth about that build, not a default to be
 * improved upon.
 */
function normalizePlan(raw: Raw): ApplyPlan {
  const ops = asArray(pick(raw, 'ops')) as unknown as PlanOp[];
  return {
    planUuid: String(pick(raw, 'planUuid') ?? ''),
    deviceId: n(pick(raw, 'deviceId'), 0),
    source: (s(pick(raw, 'source')) ?? 'template') as ApplyPlan['source'],
    ncmVersion: n(pick(raw, 'ncmVersion'), 1),
    semKeyGeneration: n(pick(raw, 'semKeyGeneration'), 1),
    baseStateHash: String(pick(raw, 'baseStateHash') ?? ''),
    ops,
    riskLevel: (s(pick(raw, 'riskLevel')) ?? 'high') as ApplyPlan['riskLevel'],
    // Unknown verdict degrades to `indeterminate`, never to `accept`.
    mgmtPathVerdict: ((): ApplyPlan['mgmtPathVerdict'] => {
      const v = s(pick(raw, 'mgmtPathVerdict'));
      return v === 'accept' || v === 'veto' ? v : 'indeterminate';
    })(),
    blastRadius: (pick(raw, 'blastRadius') as ApplyPlan['blastRadius']) ?? {
      deviceCount: 1,
      siteCount: 0,
      affectedInterfaces: [],
      affectedSubnets: [],
      touchesManagementPath: false,
    },
    expiresAt: String(pick(raw, 'expiresAt') ?? ''),
    orderConverges: pick(raw, 'orderConverges') === true,
  };
}

function normalizeDetail(raw: unknown): CompiledPlan['detail'] {
  const row = (raw ?? {}) as Raw;
  const diff = (pick(row, 'diff') ?? {}) as Raw;
  return {
    deviceName: s(pick(row, 'deviceName')),
    renderId: nOrNull(pick(row, 'renderId')),
    revisionId: nOrNull(pick(row, 'revisionId')),
    revision: nOrNull(pick(row, 'revision')),
    templateId: nOrNull(pick(row, 'templateId')),
    observedSnapshotId: s(pick(row, 'observedSnapshotId')),
    observedCapturedAt: s(pick(row, 'observedCapturedAt')),
    deletionsBlocked: n(pick(row, 'deletionsBlocked'), 0),
    warnings: Array.isArray(pick(row, 'warnings'))
      ? (pick(row, 'warnings') as unknown[]).map(String)
      : [],
    diff: {
      findingCount: n(pick(diff, 'findingCount'), 0),
      inertMoveCount: n(pick(diff, 'inertMoveCount'), 0),
      outOfScopeCount: n(pick(diff, 'outOfScopeCount'), 0),
    },
  };
}

export function normalizeCompiledPlan(payload: unknown): CompiledPlan | null {
  if (!payload || typeof payload !== 'object') return null;
  const row = payload as Raw;
  const planRaw = (pick(row, 'plan') ?? row) as Raw;
  const plan = normalizePlan(planRaw);

  // The guard block, when the server carries one. When it does NOT, the plan's
  // own lowercase `mgmtPathVerdict` is the only thing we have — it is mapped
  // through the shared bridge and flagged `ran: false`, so the screen can say
  // "the guard did not run" instead of showing a verdict nobody computed.
  const guard = normalizeGuard(pick(row, 'guard') ?? pick(row, 'mgmtGuard'), {
    fallbackVerdict: guardVerdictOfMgmtPath(plan.mgmtPathVerdict),
  });

  return {
    plan,
    detail: normalizeDetail(pick(row, 'detail')),
    guard,
    impact: normalizeImpact(pick(row, 'impact') ?? pick(row, 'deviceImpact')),
    outcomeHistory: normalizeOutcomeHistory(
      pick(row, 'outcomeHistory') ?? pick(row, 'applyOutcomes'),
    ),
    notice: s(pick(row, 'notice')),
  };
}

export interface PlanFreshness {
  fresh: boolean;
  /** Server sentence on a 409. Shown verbatim; it names both hashes. */
  message: string | null;
  /** True when the endpoint is not served by this build. */
  unavailable: boolean;
}

export interface CompileOptions {
  revisionId?: number | null;
  snapshotId?: string | null;
  /** `false` = preview: do not write a `config_renders` row. */
  persistRender?: boolean;
}

export const planApi = {
  /**
   * The apply gate. NEVER throws and NEVER returns `canApply: true` on an
   * error path — see `PLAN_CONFIG_FAIL_CLOSED`.
   */
  async config(): Promise<PlanConfig> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/plan/config');
      return normalizePlanConfig(res.data.data);
    } catch {
      return PLAN_CONFIG_FAIL_CLOSED;
    }
  },

  /** Compile the plan for one device. `null` = the route is absent. */
  async compileDevice(deviceId: number, opts: CompileOptions = {}): Promise<CompiledPlan | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>(`/plan/devices/${deviceId}`, {
        revisionId: opts.revisionId ?? null,
        snapshotId: opts.snapshotId ?? null,
        persistRender: opts.persistRender ?? false,
      });
      return normalizeCompiledPlan(res.data.data);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * Is this plan still applicable?
   *
   * A 409 is the EXPECTED answer for a stale plan and is folded into
   * `{ fresh: false }` with the server's sentence, because the screen must show
   * it. Everything else propagates: a 403 on a missing capability must not read
   * as "your plan went stale".
   */
  async validate(plan: ApplyPlan): Promise<PlanFreshness> {
    try {
      await apiClient.post<ApiResponse<unknown>>('/plan/validate', { plan });
      return { fresh: true, message: null, unavailable: false };
    } catch (err) {
      if (isRouteAbsent(err)) return { fresh: false, message: null, unavailable: true };
      if (statusOf(err) === 409) {
        return { fresh: false, message: messageOf(err), unavailable: false };
      }
      throw err;
    }
  },
};
