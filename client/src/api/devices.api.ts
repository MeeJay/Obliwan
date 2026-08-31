import apiClient from './client';
import type { ApiResponse, DeviceBrand, DeviceStatus, DeviceRole, DeviceFamily } from '@obliwan/shared';
import type {
  Device,
  DeviceDetail,
  DeviceInput,
  DeviceTransport,
  DeviceTransportInput,
  TestConnectionResponse,
  TransportTestResult,
} from '@/types/fleet';

export interface DeviceListParams {
  search?: string;
  brand?: DeviceBrand;
  model?: string;
  status?: DeviceStatus;
  role?: DeviceRole;
  siteId?: number;
  groupId?: number;
}

/** Strip empty filters so the query string stays readable in the network tab
 *  and the server never has to decide what `brand=` means. */
function clean(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

export const devicesApi = {
  async list(params: DeviceListParams = {}): Promise<Device[]> {
    const res = await apiClient.get<ApiResponse<Device[]>>('/devices', {
      params: clean(params as Record<string, unknown>),
    });
    return res.data.data ?? [];
  },

  async getById(id: number): Promise<DeviceDetail> {
    const res = await apiClient.get<ApiResponse<DeviceDetail>>(`/devices/${id}`);
    return res.data.data!;
  },

  /**
   * Enrol a directly reachable device: the SERVER dials it, reads its identity
   * and keeps the credential in the vault.
   *
   * Distinct from `create()` — which only records a row — and from the bench
   * tool's `/enroll`, which transmits NO credential because a factory password
   * never leaves the preparer's workstation. Here the operator types the one
   * ObliWAN will keep, so the route demands CREDENTIAL_MANAGE.
   *
   * The device lands `pending` whatever happens: a row somebody typed is a
   * CLAIM about a box, confirmed by a human afterwards with the identity the
   * hardware actually reported in front of them (D5 / R4).
   */
  async enrollProbe(data: {
    name: string; family: DeviceFamily; host: string; username: string; password: string;
    port?: number; useTls?: boolean; siteId?: number | null; notes?: string | null;
  }): Promise<{ device: DeviceDetail | null; identityRead: boolean; connection: unknown }> {
    const res = await apiClient.post('/devices/enroll-probe', data);
    return res.data.data;
  },

  async create(data: DeviceInput): Promise<Device> {
    const res = await apiClient.post<ApiResponse<Device>>('/devices', data);
    return res.data.data!;
  },

  async update(id: number, data: Partial<DeviceInput>): Promise<Device> {
    const res = await apiClient.patch<ApiResponse<Device>>(`/devices/${id}`, data);
    return res.data.data!;
  },

  async remove(id: number): Promise<void> {
    await apiClient.delete(`/devices/${id}`);
  },

  /**
   * The device's channels — never their credentials.
   *
   * Each row carries `hasSecret` / `hasPrivateKey` booleans; `secret_enc` and
   * `private_key_enc` do not exist in this response, encrypted or otherwise
   * (section 8.2). If either ever appears here, that is a server bug worth
   * stopping the release for, not a field to render.
   *
   * `null` means the endpoint is absent, which the Settings tab says out loud
   * rather than pretending the device has no channel. A 404 is NOT folded in:
   * on this route it means "no such device in your tenant", which is a real
   * answer the caller must be allowed to see.
   */
  async transports(deviceId: number): Promise<DeviceTransport[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<DeviceTransport[]>>(
        `/devices/${deviceId}/transports`,
      );
      return res.data.data ?? [];
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (status === 501) return null;
      throw err;
    }
  },

  /**
   * Create or replace one channel.
   *
   * RECONCILED WITH THE SERVER: `PUT /devices/:id/transports/:transport`, not
   * `POST` on the collection. A device has at most one channel of each kind —
   * `(device_id, transport)` is a unique key — so the natural key belongs in
   * the URL and the write is an idempotent upsert. Retrying a `POST` that
   * timed out would otherwise be a second, different question.
   *
   * `secret` is write-only. It is sent once and never read back.
   */
  async upsertTransport(
    deviceId: number,
    data: DeviceTransportInput,
  ): Promise<DeviceTransport> {
    const { transport, ...body } = data;
    const res = await apiClient.put<ApiResponse<DeviceTransport>>(
      `/devices/${deviceId}/transports/${transport}`,
      body,
    );
    return res.data.data!;
  },

  async removeTransport(deviceId: number, transport: string): Promise<void> {
    await apiClient.delete(`/devices/${deviceId}/transports/${transport}`);
  },

  /**
   * Open every ENABLED channel of the device once and report.
   *
   * A failing channel is a result, not an exception: the operator asked a
   * question and "no" is an answer. Only a device that does not exist in this
   * tenant raises. An unrecognised payload yields an empty result set — never
   * a fabricated "OK", which is the one outcome that would be worse than an
   * error.
   */
  async testConnection(deviceId: number): Promise<TransportTestResult[]> {
    const res = await apiClient.post<ApiResponse<TestConnectionResponse | TransportTestResult[]>>(
      `/devices/${deviceId}/test-connection`,
    );
    const payload = res.data.data;
    if (Array.isArray(payload)) return payload;
    if (payload && Array.isArray(payload.results)) return payload.results;
    return [];
  },
};
