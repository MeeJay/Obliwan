import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';
import type { Site, SiteInput, PppSession, Device } from '@/types/fleet';

export interface SiteListParams {
  search?: string;
}

export const sitesApi = {
  async list(params: SiteListParams = {}): Promise<Site[]> {
    const res = await apiClient.get<ApiResponse<Site[]>>('/sites', { params });
    return res.data.data ?? [];
  },

  async getById(id: number): Promise<Site> {
    const res = await apiClient.get<ApiResponse<Site>>(`/sites/${id}`);
    return res.data.data!;
  },

  async create(data: SiteInput): Promise<Site> {
    const res = await apiClient.post<ApiResponse<Site>>('/sites', data);
    return res.data.data!;
  },

  async update(id: number, data: Partial<SiteInput>): Promise<Site> {
    const res = await apiClient.patch<ApiResponse<Site>>(`/sites/${id}`, data);
    return res.data.data!;
  },

  async remove(id: number): Promise<void> {
    await apiClient.delete(`/sites/${id}`);
  },

  /**
   * The devices filed under this site.
   *
   * Server-side filter, not a browser-side one over the whole fleet: the
   * collection endpoint is paginated, so filtering a truncated list renders a
   * busy site as emptier than it is — and on an MSP-sized fleet it costs a
   * full inventory fetch to draw one page.
   */
  async devices(siteId: number): Promise<Device[]> {
    const res = await apiClient.get<ApiResponse<Device[]>>(`/sites/${siteId}/devices`);
    return res.data.data ?? [];
  },

  /**
   * PPP timeline for a site (spec §4.2 — "chronologie PPP").
   *
   * The route now exists server-side. The `null` branch is KEPT on purpose: it
   * distinguishes "this deployment does not serve the endpoint" from "this site
   * has never connected", and those two must never render the same way. An
   * empty array here is a real answer; `null` is the absence of one.
   */
  async pppSessions(siteId: number, limit = 100): Promise<PppSession[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<PppSession[]>>(
        `/sites/${siteId}/ppp-sessions`,
        { params: { limit } },
      );
      return res.data.data ?? [];
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (status === 501) return null;
      throw err;
    }
  },
};
