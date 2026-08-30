import type { Request, Response, NextFunction } from 'express';
import { appConfigService } from '../services/appConfig.service';
import { AppError } from '../middleware/errorHandler';

const ALLOWED_KEYS = [
  'allow_2fa', 'force_2fa', 'otp_smtp_server_id',
  'obligate_enabled',
] as const;

export const appConfigController = {
  async getAll(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const cfg = await appConfigService.getAll();
      res.json({ success: true, data: cfg });
    } catch (err) { next(err); }
  },

  async set(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const key = req.params.key as typeof ALLOWED_KEYS[number];
      if (!ALLOWED_KEYS.includes(key)) throw new AppError(400, `Unknown config key: ${key}`);
      const { value } = req.body;
      if (value === undefined) throw new AppError(400, 'Missing value');
      await appConfigService.set(key, String(value));
      res.json({ success: true });
    } catch (err) { next(err); }
  },

  // ── Obligate SSO gateway ────────────────────────────────────────────────

  /** GET /admin/config/obligate — returns { url, apiKeySet, enabled } (admin only) */
  async getObligateConfig(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const cfg = await appConfigService.getObligateConfig();
      res.json({ success: true, data: cfg });
    } catch (err) { next(err); }
  },

  /** PUT /admin/config/obligate — sets url and/or apiKey and/or enabled (admin only) */
  async setObligateConfig(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const patch: { url?: string | null; apiKey?: string | null; clientId?: string | null; enabled?: boolean } = {};
      if ('url'     in req.body) patch.url     = (req.body as { url?: string | null }).url ?? null;
      if ('apiKey'  in req.body) patch.apiKey  = (req.body as { apiKey?: string | null }).apiKey ?? null;
      // The public application id. Distinct from apiKey ON PURPOSE: apiKey is the
      // server-to-server bearer and must never reach a URL, while clientId is the
      // only half /auth/sso-redirect is allowed to publish. Without this field the
      // redirect fails closed and SSO cannot be turned on from the admin UI at all.
      if ('clientId' in req.body) patch.clientId = (req.body as { clientId?: string | null }).clientId ?? null;
      if ('enabled' in req.body) patch.enabled = !!(req.body as { enabled?: boolean }).enabled;
      const updated = await appConfigService.patchObligateConfig(patch);
      res.json({ success: true, data: updated });
    } catch (err) { next(err); }
  },
};
