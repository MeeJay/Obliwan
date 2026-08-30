import apiClient from './client';
import type { ResolvedSettings, ApiResponse, SettingsScope } from '@obliwan/shared';
import type { SettingsKey } from '@obliwan/shared';

interface ResolvedWithOverrides {
  resolved: ResolvedSettings;
  overrides: Record<string, number>;
}

export const settingsApi = {
  async getGlobalResolved(): Promise<ResolvedWithOverrides> {
    const res = await apiClient.get<ApiResponse<ResolvedWithOverrides>>('/settings/global/resolved');
    return res.data.data!;
  },

  async getGroupResolved(groupId: number): Promise<ResolvedWithOverrides> {
    const res = await apiClient.get<ApiResponse<ResolvedWithOverrides>>(`/settings/group/${groupId}/resolved`);
    return res.data.data!;
  },

  async getMonitorResolved(monitorId: number): Promise<ResolvedWithOverrides> {
    const res = await apiClient.get<ApiResponse<ResolvedWithOverrides>>(`/settings/monitor/${monitorId}/resolved`);
    return res.data.data!;
  },

  async set(scope: SettingsScope, scopeId: string, key: SettingsKey, value: number): Promise<void> {
    await apiClient.put(`/settings/${scope}/${scopeId}`, { key, value });
  },

  async setBulk(
    scope: SettingsScope,
    scopeId: string,
    overrides: Array<{ key: SettingsKey; value: number }>,
  ): Promise<void> {
    await apiClient.put(`/settings/${scope}/${scopeId}/bulk`, { overrides });
  },

  async remove(scope: SettingsScope, scopeId: string, key: SettingsKey): Promise<void> {
    await apiClient.delete(`/settings/${scope}/${scopeId}/${key}`);
  },
};
