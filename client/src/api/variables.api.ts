import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';

/**
 * Inherited configuration variables (M5).
 *
 * ┌─ THE ONE THING THIS API WILL NEVER GIVE YOU BACK ────────────────────────┐
 * │ A variable marked secret is encrypted on the way in and NEVER returned.   │
 * │ The read shape carries `isSecret` and no value — not a masked value, no   │
 * │ value at all. A field the API can render as `••••` is a field one         │
 * │ refactor away from rendering as itself, and §8.2 says the rendered        │
 * │ configuration holding secrets exists in memory only, on the vault →       │
 * │ device path.                                                              │
 * │                                                                          │
 * │ So the screen can show that a secret EXISTS at a scope, and can replace   │
 * │ it. It can never show it.                                                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Scopes resolve global → tenant → group chain → device, which is the same
 * inheritance `settings.service` implements. A value set closer to the device
 * wins; that is the whole point, and the screen shows where each one came from.
 */

export type VariableScope = 'global' | 'tenant' | 'group' | 'device';

export interface VariableEntry {
  key: string;
  /** Absent for secrets — see the box above. */
  value?: unknown;
  isSecret: boolean;
  /** Which scope this value was set at, when the server reports provenance. */
  scope?: VariableScope;
}

/** The server folds the chain; the shape is intentionally loose because the
 *  resolver owns it and this module must not re-derive it. */
export type ResolvedVariables = Record<string, unknown> & {
  variables?: VariableEntry[];
};

export const variablesApi = {
  /** Everything that applies to a device, after the whole chain is folded. */
  async forDevice(deviceId: number): Promise<ResolvedVariables> {
    const res = await apiClient.get<ApiResponse<ResolvedVariables>>(`/variables/devices/${deviceId}`);
    return res.data.data ?? {};
  },

  async forGroup(groupId: number): Promise<ResolvedVariables> {
    const res = await apiClient.get<ApiResponse<ResolvedVariables>>(`/variables/groups/${groupId}`);
    return res.data.data ?? {};
  },

  async forTenant(): Promise<ResolvedVariables> {
    const res = await apiClient.get<ApiResponse<ResolvedVariables>>('/variables/tenant');
    return res.data.data ?? {};
  },

  /** The variables set AT one scope, without inheritance folded in. */
  async atScope(scope: VariableScope, scopeId?: number): Promise<ResolvedVariables> {
    const path = scopeId === undefined ? `/variables/at/${scope}` : `/variables/at/${scope}/${scopeId}`;
    const res = await apiClient.get<ApiResponse<ResolvedVariables>>(path);
    return res.data.data ?? {};
  },

  async setAtScope(
    scope: VariableScope,
    scopeId: number | undefined,
    body: { key: string; value?: unknown; isSecret?: boolean },
  ): Promise<void> {
    const path = scopeId === undefined ? `/variables/at/${scope}` : `/variables/at/${scope}/${scopeId}`;
    await apiClient.put(path, body);
  },

  async removeAtScope(scope: VariableScope, scopeId: number | undefined, key: string): Promise<void> {
    const path = scopeId === undefined ? `/variables/at/${scope}` : `/variables/at/${scope}/${scopeId}`;
    await apiClient.delete(path, { data: { key } });
  },
};
