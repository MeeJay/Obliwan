import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';
import type { AlertStateRow, Threshold, ThresholdInput } from '@/types/telemetry';
import { normalizeAlertState, normalizeThreshold } from './normalize';

/**
 * SNMP thresholds (M3, spec §5/M3 — "seuils `for` + hystérésis").
 *
 * `forSeconds` and `hysteresisPct` are sent on EVERY write, always, including
 * on an edit that only renames the rule. The database declares both NOT NULL
 * with no DEFAULT precisely so an omitted value is a hard failure rather than
 * a silently inherited one; a client that dropped them on a PATCH would turn
 * that deliberate constraint into a 500 nobody can explain.
 *
 * Reads go through `normalizeThreshold`: the server's `listThresholds()`
 * returns raw knex rows, so `value` and `hysteresis_pct` arrive as STRINGS
 * (PostgreSQL `numeric`). See `api/normalize.ts` for why that is not a
 * cosmetic problem.
 */

function statusOf(err: unknown): number | undefined {
  return (err as { response?: { status?: number } }).response?.status;
}

function isRouteAbsent(err: unknown): boolean {
  const s = statusOf(err);
  return s === 501 || s === 404;
}

function asRows(payload: unknown): Record<string, unknown>[] {
  return Array.isArray(payload) ? (payload as Record<string, unknown>[]) : [];
}

export const thresholdsApi = {
  /** `null` = the endpoint is not served by this build. */
  async list(): Promise<Threshold[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/snmp/thresholds');
      return asRows(res.data.data).map(normalizeThreshold);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async create(data: ThresholdInput): Promise<Threshold> {
    const res = await apiClient.post<ApiResponse<unknown>>('/snmp/thresholds', data);
    return normalizeThreshold((res.data.data ?? {}) as Record<string, unknown>);
  },

  async update(id: number, data: ThresholdInput): Promise<Threshold> {
    const res = await apiClient.put<ApiResponse<unknown>>(`/snmp/thresholds/${id}`, data);
    return normalizeThreshold((res.data.data ?? {}) as Record<string, unknown>);
  },

  async remove(id: number): Promise<void> {
    await apiClient.delete(`/snmp/thresholds/${id}`);
  },

  /**
   * Current alert state, for the "what is firing right now" view.
   *
   * `pending` rows are returned AND displayed. Hiding them until they fire is
   * how the dwell timer becomes unobservable: an operator who cannot see that
   * a rule is 40 seconds into its 5-minute `for` has no way to tell a working
   * threshold from a dead one.
   */
  async alertStates(): Promise<AlertStateRow[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/snmp/alerts');
      return asRows(res.data.data).map(normalizeAlertState);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },
};
