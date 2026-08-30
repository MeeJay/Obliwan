import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';

export interface TwoFactorStatus {
  totpEnabled: boolean;
  emailOtpEnabled: boolean;
  email: string | null;
}

export interface TotpSetupData {
  secret: string;
  qrDataUrl: string;
}

/** Proof of account ownership required to remove a second factor. */
export interface TwoFactorProof {
  currentPassword?: string;
  code?: string;
}

export const twoFactorApi = {
  async getStatus(): Promise<TwoFactorStatus> {
    const res = await apiClient.get<ApiResponse<TwoFactorStatus>>('/profile/2fa/status');
    return res.data.data!;
  },

  async totpSetup(): Promise<TotpSetupData> {
    const res = await apiClient.post<ApiResponse<TotpSetupData>>('/profile/2fa/totp/setup');
    return res.data.data!;
  },

  async totpEnable(code: string): Promise<void> {
    await apiClient.post('/profile/2fa/totp/enable', { code });
  },

  /**
   * Disabling a second factor now requires proving you are the account holder:
   * a stolen session alone must not be able to strip MFA. Send `currentPassword`,
   * or `code` from the factor being removed. The server refuses an empty body
   * with 400 — do not "fix" that by relaxing the guard, ask the user instead.
   */
  async totpDisable(proof: TwoFactorProof): Promise<void> {
    await apiClient.delete('/profile/2fa/totp', { data: proof });
  },

  async emailSetup(email: string): Promise<void> {
    await apiClient.post('/profile/2fa/email/setup', { email });
  },

  async emailEnable(code: string): Promise<void> {
    await apiClient.post('/profile/2fa/email/enable', { code });
  },

  async emailDisable(proof: TwoFactorProof): Promise<void> {
    await apiClient.delete('/profile/2fa/email', { data: proof });
  },

  async verify(code: string, method: 'totp' | 'email'): Promise<{ user: unknown }> {
    const res = await apiClient.post<ApiResponse<{ user: unknown }>>('/profile/2fa/verify', { code, method });
    return res.data.data!;
  },

  async resendEmail(): Promise<void> {
    await apiClient.post('/profile/2fa/resend-email');
  },
};
