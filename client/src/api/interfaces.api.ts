import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';
import type {
  IfSeriesParams,
  IfSeriesResponse,
  InterfaceListParams,
  NetInterface,
} from '@/types/telemetry';
import { normalizeInterface, normalizeSeries } from './normalize';

/**
 * SNMP interfaces and their time series (M3).
 *
 * ── ON THE `null` RETURNS ───────────────────────────────────────────────────
 * Same convention M2 established for `devicesApi.transports()`: `null` means
 * "this deployment does not serve the endpoint", which every screen renders as
 * an explicit "not available yet" panel. An empty array is a DIFFERENT answer
 * — "we asked, and this device has no interface" — and the two must never draw
 * the same way.
 *
 * A 404 is folded into `null` **only on the collection routes**, where it can
 * only mean "no such route". On `/interfaces/:id/series` a 404 means "no such
 * interface in your tenant", which is a real answer the caller must see, and
 * it is deliberately left to throw.
 *
 * This matters right now: the M3 server exposes
 * `listInterfaces(tenantId, deviceId)` — a PER-DEVICE list — and has no
 * fleet-wide route yet. Until one exists, `/interfaces` 404s and the fleet
 * page says so instead of showing an empty fleet, which would read as "no
 * interfaces are being polled anywhere".
 */

function clean(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

function statusOf(err: unknown): number | undefined {
  return (err as { response?: { status?: number } }).response?.status;
}

/** Collection routes only — see the note above. */
function isRouteAbsent(err: unknown): boolean {
  const s = statusOf(err);
  return s === 501 || s === 404;
}

function asRows(payload: unknown): Record<string, unknown>[] {
  return Array.isArray(payload) ? (payload as Record<string, unknown>[]) : [];
}

export const interfacesApi = {
  /** Fleet-wide interface list. `null` = endpoint not served by this build. */
  async list(params: InterfaceListParams = {}): Promise<NetInterface[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/snmp/interfaces', {
        params: clean(params as Record<string, unknown>),
      });
      return asRows(res.data.data).map(normalizeInterface);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * The interfaces of one device.
   *
   * `includeVanished` is passed through rather than filtered here: a vanished
   * interface keeps its whole history (deleting it would orphan millions of
   * series rows and erase exactly the link somebody is asking about), so
   * whether to load them is a question for the caller, not a default.
   */
  async forDevice(deviceId: number, includeVanished = true): Promise<NetInterface[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/snmp/devices/${deviceId}/interfaces`, {
        params: { includeVanished },
      });
      return asRows(res.data.data).map(normalizeInterface);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * One interface's series over a window.
   *
   * `granularity` is REQUESTED, not imposed. The server echoes back what it
   * actually served in `resolution`, and the UI labels the chart with the
   * echo. A server that downgrades our request — because the raw retention no
   * longer covers the window, or because this interface's poll interval means
   * the 1-minute rollup was never written — is behaving correctly; a UI that
   * keeps claiming the granularity it asked for is not.
   *
   * A 404 here is NOT swallowed: it means the interface does not exist in this
   * tenant, which the caller is entitled to see as an error.
   */
  async series(
    ifId: number,
    params: IfSeriesParams,
    fallbackBucketSec: number,
  ): Promise<IfSeriesResponse | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/snmp/interfaces/${ifId}/series`, {
        // Sent under BOTH names. The service parameter is called `requested`
        // and the response field `resolution`, but the query-string name is a
        // controller decision that has not been made yet; an ignored extra
        // query parameter costs nothing, a missed one silently downgrades
        // every chart to the server's own default tier.
        params: { ...params, resolution: params.granularity },
      });
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      return normalizeSeries(payload as Record<string, unknown>, fallbackBucketSec);
    } catch (err) {
      if (statusOf(err) === 501) return null;
      throw err;
    }
  },
};
