import apiClient from './client';
import type {
  ApiResponse,
  SimAccount,
  SimAccountInput,
  SimCredentialInput,
  SimFleetSummary,
  SimLine,
  SimLineUpdate,
  SimPlatformInfo,
  SimRecharge,
  SimRechargeCompletionInput,
  SimRechargeReport,
  SimRechargeStatus,
  SimZoneBalance,
} from '@obliwan/shared';

/**
 * Mobile data lines (F9).
 *
 * ┌─ EVERY NUMBER THAT CROSSES THIS BOUNDARY CAN BE `null`, AND `null` IS NOT  ┐
 * │ ZERO. `restMb === null` means the partner did not tell us. Rendering it as │
 * │ "0 Mo" would show an operator a fleet-wide emergency that does not exist,  │
 * │ and `??  0` anywhere in this file or in a component reading it recreates   │
 * │ exactly the defect the whole feature was designed around (see              │
 * │ `shared/src/sim.ts`, decision 2). Use `formatData`, which renders an       │
 * │ absent reading as "—".                                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * `cost_cents` arrives as a STRING for the same reason the SNMP thresholds do:
 * PostgreSQL `bigint` is serialised as text by `pg` to avoid losing precision.
 * `num()` is applied on every money and data field rather than trusting the
 * wire — a string silently coerced by `+` elsewhere in a component would sort
 * "9" after "10".
 */

function statusOf(err: unknown): number | undefined {
  return (err as { response?: { status?: number } }).response?.status;
}

/** A route this build does not serve, or a capability the session lacks. */
export function isRouteAbsent(err: unknown): boolean {
  const s = statusOf(err);
  return s === 404 || s === 403;
}

export function errorMessageOf(err: unknown): string {
  const data = (err as { response?: { data?: { error?: string; message?: string } } }).response
    ?.data;
  return data?.error ?? data?.message ?? (err instanceof Error ? err.message : 'Unknown error');
}

type Raw = Record<string, unknown>;

function rows(payload: unknown): Raw[] {
  return Array.isArray(payload) ? (payload as Raw[]) : [];
}

/** Number, or null. NEVER a zero fallback — see the header. */
function num(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? n : null;
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}

function normalizeZone(raw: Raw): SimZoneBalance {
  return {
    zone: String(raw.zone ?? 'unknown'),
    rechargeMb: num(raw.rechargeMb),
    usedMb: num(raw.usedMb),
    restMb: num(raw.restMb),
    observedAt: String(raw.observedAt ?? ''),
    lowSince: str(raw.lowSince),
  };
}

export interface SimLineListItem extends SimLine {
  verdict: 'ok' | 'low' | 'unknown';
  thresholdMb: number;
  worstZone: SimZoneBalance | null;
  /** `unknown` because the readings aged out, not because there were none. */
  stale: boolean;
}

function normalizeLine(raw: Raw): SimLineListItem {
  const zones = Array.isArray(raw.zones) ? (raw.zones as Raw[]).map(normalizeZone) : [];
  return {
    id: Number(raw.id),
    accountId: Number(raw.accountId),
    platform: raw.platform as SimLineListItem['platform'],
    accountName: String(raw.accountName ?? ''),
    tenantId: num(raw.tenantId),
    msisdn: String(raw.msisdn ?? ''),
    iccid: str(raw.iccid),
    operator: str(raw.operator),
    clientCode: str(raw.clientCode),
    label: str(raw.label),
    siteId: num(raw.siteId),
    siteName: str(raw.siteName),
    deviceId: num(raw.deviceId),
    deviceName: str(raw.deviceName),
    status: (raw.status as SimLine['status']) ?? 'unknown',
    lowThresholdMb: num(raw.lowThresholdMb),
    autoRechargeEnabled: raw.autoRechargeEnabled === true,
    rechargePlanMb: num(raw.rechargePlanMb),
    firstSeenAt: String(raw.firstSeenAt ?? ''),
    lastSeenAt: String(raw.lastSeenAt ?? ''),
    zones,
    verdict: (raw.verdict as SimLineListItem['verdict']) ?? 'unknown',
    // The only field with a fallback, and it is a THRESHOLD, not a reading:
    // a missing threshold would make `evaluateBalance` compare against NaN and
    // report every line as ok. 1024 MB is the shared hardcoded default.
    thresholdMb: num(raw.thresholdMb) ?? 1024,
    worstZone: raw.worstZone ? normalizeZone(raw.worstZone as Raw) : null,
    stale: raw.stale === true,
  };
}

function normalizeRecharge(raw: Raw): SimRecharge {
  return {
    id: Number(raw.id),
    simId: num(raw.simId),
    accountId: num(raw.accountId),
    platform: raw.platform as SimRecharge['platform'],
    tenantId: num(raw.tenantId),
    tenantName: str(raw.tenantName),
    msisdn: String(raw.msisdn ?? ''),
    operator: str(raw.operator),
    siteId: num(raw.siteId),
    siteName: str(raw.siteName),
    deviceName: str(raw.deviceName),
    status: raw.status as SimRechargeStatus,
    trigger: raw.trigger as SimRecharge['trigger'],
    zone: String(raw.zone ?? ''),
    restMbAtProposal: num(raw.restMbAtProposal),
    thresholdMbAtProposal: num(raw.thresholdMbAtProposal) ?? 0,
    planMb: num(raw.planMb),
    costCents: num(raw.costCents),
    currency: str(raw.currency),
    billingReference: str(raw.billingReference),
    idempotencyKey: String(raw.idempotencyKey ?? ''),
    proposedAt: String(raw.proposedAt ?? ''),
    proposedBy: num(raw.proposedBy),
    proposedByName: str(raw.proposedByName),
    decidedAt: str(raw.decidedAt),
    decidedBy: num(raw.decidedBy),
    decidedByName: str(raw.decidedByName),
    decisionNote: str(raw.decisionNote),
    completedAt: str(raw.completedAt),
    completedBy: num(raw.completedBy),
    failureReason: str(raw.failureReason),
  };
}

export interface SimSyncRun {
  id: number;
  startedAt: string;
  finishedAt: string | null;
  outcome: string | null;
  linesSeen: number;
  linesNew: number;
  balancesUpdated: number;
  linesFailed: number;
  proposalsCreated: number;
  error: string | null;
}

/** `sim_sync_runs` is served as raw knex rows — snake_case, bigint as text. */
function normalizeRun(raw: Raw): SimSyncRun {
  return {
    id: Number(raw.id),
    startedAt: String(raw.started_at ?? ''),
    finishedAt: str(raw.finished_at),
    outcome: str(raw.outcome),
    linesSeen: num(raw.lines_seen) ?? 0,
    linesNew: num(raw.lines_new) ?? 0,
    balancesUpdated: num(raw.balances_updated) ?? 0,
    linesFailed: num(raw.lines_failed) ?? 0,
    proposalsCreated: num(raw.proposals_created) ?? 0,
    error: str(raw.error),
  };
}

export interface SimCapUsage {
  monthlyRechargeCap: number | null;
  monthlyCostCapCents: number | null;
  rechargesThisMonth: number;
  /** Priced rows only — an unpriced top-up is counted below, never added here. */
  costThisMonthCents: number;
  unpricedThisMonth: number;
}

export interface SimConnectionTest {
  ok: boolean;
  partnerRef: string | null;
  tokenExpiresAt: string | null;
  lineCount: number | null;
  error: string | null;
  errorCode: string | null;
}

export const simApi = {
  // ── Coverage matrix ───────────────────────────────────────────────────────
  async platforms(): Promise<SimPlatformInfo[]> {
    const res = await apiClient.get<ApiResponse<unknown>>('/sim/platforms');
    return rows(res.data.data) as unknown as SimPlatformInfo[];
  },

  // ── Fleet ─────────────────────────────────────────────────────────────────
  async summary(): Promise<SimFleetSummary> {
    const res = await apiClient.get<ApiResponse<SimFleetSummary>>('/sim/summary');
    return res.data.data as SimFleetSummary;
  },

  async lines(params: {
    accountId?: number;
    assignment?: 'assigned' | 'pool';
    verdict?: 'ok' | 'low' | 'unknown';
    search?: string;
    limit?: number;
  } = {}): Promise<SimLineListItem[]> {
    const res = await apiClient.get<ApiResponse<unknown>>('/sim/lines', { params });
    return rows(res.data.data).map(normalizeLine);
  },

  async line(id: number): Promise<SimLineListItem> {
    const res = await apiClient.get<ApiResponse<unknown>>(`/sim/lines/${id}`);
    return normalizeLine((res.data.data ?? {}) as Raw);
  },

  async lineHistory(
    id: number,
    days = 90,
  ): Promise<Array<{ zone: string; restMb: number | null; usedMb: number | null; observedAt: string }>> {
    const res = await apiClient.get<ApiResponse<unknown>>(`/sim/lines/${id}/history`, {
      params: { days },
    });
    return rows(res.data.data).map((r) => ({
      zone: String(r.zone ?? ''),
      restMb: num(r.restMb),
      usedMb: num(r.usedMb),
      observedAt: String(r.observedAt ?? ''),
    }));
  },

  async updateLine(id: number, patch: SimLineUpdate): Promise<SimLineListItem> {
    const res = await apiClient.patch<ApiResponse<unknown>>(`/sim/lines/${id}`, patch);
    return normalizeLine((res.data.data ?? {}) as Raw);
  },

  // ── Top-ups ───────────────────────────────────────────────────────────────
  async recharges(params: { status?: string; simId?: number; limit?: number } = {}): Promise<SimRecharge[]> {
    const res = await apiClient.get<ApiResponse<unknown>>('/sim/recharges', { params });
    return rows(res.data.data).map(normalizeRecharge);
  },

  async propose(input: {
    simId: number;
    zone: string;
    planMb?: number | null;
    note?: string | null;
  }): Promise<SimRecharge> {
    const res = await apiClient.post<ApiResponse<unknown>>('/sim/recharges', input);
    return normalizeRecharge((res.data.data ?? {}) as Raw);
  },

  async approve(id: number, note?: string | null): Promise<SimRecharge> {
    const res = await apiClient.post<ApiResponse<unknown>>(`/sim/recharges/${id}/approve`, { note });
    return normalizeRecharge((res.data.data ?? {}) as Raw);
  },

  async reject(id: number, note?: string | null): Promise<SimRecharge> {
    const res = await apiClient.post<ApiResponse<unknown>>(`/sim/recharges/${id}/reject`, { note });
    return normalizeRecharge((res.data.data ?? {}) as Raw);
  },

  async record(id: number, input: SimRechargeCompletionInput): Promise<SimRecharge> {
    const res = await apiClient.post<ApiResponse<unknown>>(`/sim/recharges/${id}/record`, input);
    return normalizeRecharge((res.data.data ?? {}) as Raw);
  },

  /** Fills in the invoice after the fact. Moves no state; changes what is billed. */
  async price(id: number, input: SimRechargeCompletionInput): Promise<SimRecharge> {
    const res = await apiClient.post<ApiResponse<unknown>>(`/sim/recharges/${id}/price`, input);
    return normalizeRecharge((res.data.data ?? {}) as Raw);
  },

  // ── Re-invoicing report ───────────────────────────────────────────────────
  async report(from: string, to: string): Promise<SimRechargeReport> {
    const res = await apiClient.get<ApiResponse<SimRechargeReport>>('/sim/report', {
      params: { from, to },
    });
    return res.data.data as SimRechargeReport;
  },

  /** The CSV URL, opened by the browser so the download carries the session
   *  cookie. Built here so the screen and its export cannot drift apart. */
  reportCsvUrl(from: string, to: string): string {
    const qs = new URLSearchParams({ from, to });
    return `/api/sim/report.csv?${qs.toString()}`;
  },

  // ── Partner accounts — platform admin only ────────────────────────────────
  async accounts(): Promise<SimAccount[]> {
    const res = await apiClient.get<ApiResponse<unknown>>('/sim/accounts');
    return rows(res.data.data) as unknown as SimAccount[];
  },

  async createAccount(input: SimAccountInput): Promise<SimAccount> {
    const res = await apiClient.post<ApiResponse<SimAccount>>('/sim/accounts', input);
    return res.data.data as SimAccount;
  },

  async updateAccount(id: number, input: Partial<SimAccountInput>): Promise<SimAccount> {
    const res = await apiClient.patch<ApiResponse<SimAccount>>(`/sim/accounts/${id}`, input);
    return res.data.data as SimAccount;
  },

  async deleteAccount(id: number): Promise<void> {
    await apiClient.delete(`/sim/accounts/${id}`);
  },

  async setCredential(id: number, cred: SimCredentialInput): Promise<SimAccount> {
    const res = await apiClient.put<ApiResponse<SimAccount>>(`/sim/accounts/${id}/credential`, cred);
    return res.data.data as SimAccount;
  },

  async authenticateWithCode(
    id: number,
    input: { username: string; password: string; code: string },
  ): Promise<SimAccount> {
    const res = await apiClient.post<ApiResponse<SimAccount>>(`/sim/accounts/${id}/otp`, input);
    return res.data.data as SimAccount;
  },

  async testAccount(id: number): Promise<SimConnectionTest> {
    const res = await apiClient.post<ApiResponse<SimConnectionTest>>(`/sim/accounts/${id}/test`);
    return res.data.data as SimConnectionTest;
  },

  async syncAccount(id: number): Promise<Record<string, unknown>> {
    const res = await apiClient.post<ApiResponse<Record<string, unknown>>>(
      `/sim/accounts/${id}/sync`,
    );
    return (res.data.data ?? {}) as Record<string, unknown>;
  },

  async runs(id: number): Promise<SimSyncRun[]> {
    const res = await apiClient.get<ApiResponse<unknown>>(`/sim/accounts/${id}/runs`);
    return rows(res.data.data).map(normalizeRun);
  },

  async caps(id: number): Promise<SimCapUsage> {
    const res = await apiClient.get<ApiResponse<SimCapUsage>>(`/sim/accounts/${id}/caps`);
    return res.data.data as SimCapUsage;
  },
};
