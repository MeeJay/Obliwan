import apiClient from './client';
import type { ApiResponse, DiscoveryState } from '@obliwan/shared';
import type {
  Discovery,
  DiscoveryBindInput,
  DiscoveryStateInput,
  DeviceDetail,
} from '@/types/fleet';

export interface DiscoveryListParams {
  state?: DiscoveryState;
  concentratorId?: number;
  search?: string;
}

export const discoveriesApi = {
  async list(params: DiscoveryListParams = {}): Promise<Discovery[]> {
    const res = await apiClient.get<ApiResponse<Discovery[]>>('/discoveries', { params });
    return res.data.data ?? [];
  },

  /**
   * Bind a quarantined PPP session to a device.
   *
   * This is the one write in M2 that can push customer A's configuration to
   * customer B's router if it is wrong (risk R4). The authority is entirely
   * server-side: the target device must already be in the caller's session
   * tenant (404 otherwise), and a device created here is created in that same
   * tenant. The dialog's attestation and retyped username are guard rails on
   * the operator, not credentials — see `DiscoveryBindInput`.
   *
   * The response carries the updated discovery AND the resulting device, so
   * the caller can refresh both without a second round trip.
   */
  async bind(
    id: number,
    data: DiscoveryBindInput,
  ): Promise<{ discovery: Discovery; device: DeviceDetail | null }> {
    const res = await apiClient.post<
      ApiResponse<{ discovery: Discovery; device: DeviceDetail | null }>
    >(`/discoveries/${id}/bind`, data);
    return res.data.data!;
  },

  /** File a row as "not ours", or push it back into the review queue. */
  async setState(id: number, data: DiscoveryStateInput): Promise<Discovery> {
    const res = await apiClient.post<ApiResponse<Discovery>>(`/discoveries/${id}/state`, data);
    return res.data.data!;
  },

  /** Convenience wrapper over `setState` for the one-click "ignore" button. */
  async ignore(id: number): Promise<Discovery> {
    return discoveriesApi.setState(id, { state: 'ignored' });
  },
};
