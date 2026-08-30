import apiClient from './client';
import type {
  SmtpServer,
  ApiResponse,
  CreateSmtpServerRequest,
  UpdateSmtpServerRequest,
} from '@obliwan/shared';

// Re-exported for consumers that used to import them from this module.
export type { CreateSmtpServerRequest, UpdateSmtpServerRequest };

export const smtpServerApi = {
  async list(): Promise<SmtpServer[]> {
    const res = await apiClient.get<ApiResponse<SmtpServer[]>>('/admin/smtp-servers');
    return res.data.data!;
  },

  async create(data: CreateSmtpServerRequest): Promise<SmtpServer> {
    const res = await apiClient.post<ApiResponse<SmtpServer>>('/admin/smtp-servers', data);
    return res.data.data!;
  },

  async update(id: number, data: UpdateSmtpServerRequest): Promise<SmtpServer> {
    const res = await apiClient.put<ApiResponse<SmtpServer>>(`/admin/smtp-servers/${id}`, data);
    return res.data.data!;
  },

  async delete(id: number): Promise<void> {
    await apiClient.delete(`/admin/smtp-servers/${id}`);
  },

  async test(id: number): Promise<void> {
    await apiClient.post(`/admin/smtp-servers/${id}/test`);
  },
};
