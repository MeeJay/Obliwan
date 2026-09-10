import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';

/**
 * SNMP credentials.
 *
 * ┌─ THE SERVER HAS ALWAYS HAD THIS CRUD; THE CLIENT NEVER HAD THE SCREEN ───┐
 * │ Which made the fleet's supervision reachable only through curl, and made  │
 * │ the "name a credential and every confirmed device is polled" setting a    │
 * │ sentence pointing at a page that did not exist.                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * WHAT NEVER COMES BACK: there is no field on `SnmpCredential` capable of
 * holding a community string or a USM key, and that is deliberate rather than
 * an omission. The server exposes `hasCommunity` / `hasAuthKey` / `hasPrivKey`
 * booleans instead. There is no "masked" variant either — a masked secret is a
 * secret that has already travelled (section 8.2).
 */

export interface SnmpCredential {
  id: number;
  name: string;
  version: 'v1' | 'v2c' | 'v3';
  /** v3 only. */
  username: string | null;
  securityLevel: string | null;
  authProto: string | null;
  privProto: string | null;
  context: string | null;
  /** Booleans, never the value. */
  hasCommunity: boolean;
  hasAuthKey: boolean;
  hasPrivKey: boolean;
  createdAt: string;
}

export interface SnmpCredentialInput {
  name: string;
  version: 'v1' | 'v2c' | 'v3';
  /** v1 / v2c. Write-only: it goes to the vault and never comes back. */
  community?: string;
  username?: string;
  securityLevel?: string;
  authProtocol?: string;
  authKey?: string;
  privProtocol?: string;
  privKey?: string;
  context?: string;
}

function rows(payload: unknown): SnmpCredential[] {
  if (Array.isArray(payload)) return payload as SnmpCredential[];
  if (payload && typeof payload === 'object') {
    const inner = (payload as { items?: unknown; credentials?: unknown });
    if (Array.isArray(inner.items)) return inner.items as SnmpCredential[];
    if (Array.isArray(inner.credentials)) return inner.credentials as SnmpCredential[];
  }
  return [];
}

export const snmpApi = {
  async listCredentials(): Promise<SnmpCredential[]> {
    const res = await apiClient.get<ApiResponse<unknown>>('/snmp/credentials');
    return rows(res.data.data);
  },

  async createCredential(input: SnmpCredentialInput): Promise<SnmpCredential> {
    const res = await apiClient.post<ApiResponse<SnmpCredential>>('/snmp/credentials', input);
    return res.data.data!;
  },

  /** The server refuses with 409 while any target still uses it — deleting it
   *  anyway would take those devices out of supervision, silently. */
  async deleteCredential(id: number): Promise<void> {
    await apiClient.delete(`/snmp/credentials/${id}`);
  },
};

// ── Per-device target ───────────────────────────────────────────────────────

export interface SnmpTargetSummary {
  id: number;
  deviceId: number;
  /** `null` = INHERIT from the fleet setting. Not "none". */
  credentialId: number | null;
  /** What the poller will actually use, pin or inheritance resolved. */
  effectiveCredentialId: number | null;
  effectiveCredentialName: string | null;
  inherited: boolean;
  host: string | null;
  port: number;
  enabled: boolean;
  pollIntervalSec: number | null;
  lastOkAt: string | null;
  lastError: string | null;
  consecutiveFailures: number;
  lastDiscoveryAt: string | null;
}

export const snmpTargetApi = {
  /** `null` = this device has no target yet. */
  async get(deviceId: number): Promise<SnmpTargetSummary | null> {
    try {
      const res = await apiClient.get<ApiResponse<SnmpTargetSummary>>(
        `/snmp/devices/${deviceId}/target`,
      );
      return res.data.data ?? null;
    } catch {
      return null;
    }
  },

  /**
   * `credentialId: null` restores inheritance — it does not clear supervision.
   * That distinction is the whole feature: a device follows the fleet until
   * somebody decides it should not.
   */
  async put(
    deviceId: number,
    input: { credentialId?: number | null; enabled?: boolean; pollIntervalSec?: number | null },
  ): Promise<SnmpTargetSummary> {
    const res = await apiClient.put<ApiResponse<SnmpTargetSummary>>(
      `/snmp/devices/${deviceId}/target`,
      input,
    );
    return res.data.data!;
  },
};
