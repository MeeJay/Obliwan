import type { Request, Response, NextFunction } from 'express';
import { smtpServerService } from '../services/smtpServer.service';
import { AppError } from '../middleware/errorHandler';

// A relay is either a PLATFORM relay (tenant_id NULL — carries the OTP and
// password-reset mail of every tenant) or a tenant's own. Only a platform admin
// may create or repoint the former. Without this, three unscoped where({id})
// let any tenant admin edit, delete or test another customer's relay.
function scopeOf(req: Request): { tenantId: number | undefined; isPlatformAdmin: boolean } {
  return { tenantId: req.tenantId, isPlatformAdmin: req.session.role === 'admin' };
}

export const smtpServerController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const servers = await smtpServerService.list(req.tenantId);
      res.json({ success: true, data: servers });
    } catch (err) { next(err); }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { name, host, port, secure, username, password, fromAddress, isPlatform } = req.body as {
        name?: string; host?: string; port?: number; secure?: boolean;
        username?: string; password?: string; fromAddress?: string; isPlatform?: boolean;
      };
      if (!name || !host || !port || !username || !password || !fromAddress) {
        throw new AppError(400, 'Missing required fields');
      }
      // The route is mounted under tenantRouter, so req.tenantId is always set and
      // the service's whereNull('tenant_id') branch was unreachable: no platform
      // relay could be created at all, which silently killed OTP and password-reset
      // mail. A platform admin can now say so explicitly.
      const wantsPlatform = isPlatform === true;
      if (wantsPlatform && req.session.role !== 'admin') {
        throw new AppError(403, 'Only a platform administrator can create an instance-wide relay');
      }
      const server = await smtpServerService.create({
        name, host, port: Number(port), secure: Boolean(secure), username, password, fromAddress,
        tenantId: req.tenantId,
        isPlatform: wantsPlatform,
      });
      res.status(201).json({ success: true, data: server });
    } catch (err) { next(err); }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const { name, host, port, secure, username, password, fromAddress } = req.body;
      const server = await smtpServerService.update(id, {
        ...(name !== undefined && { name }),
        ...(host !== undefined && { host }),
        ...(port !== undefined && { port: Number(port) }),
        ...(secure !== undefined && { secure: Boolean(secure) }),
        ...(username !== undefined && { username }),
        ...(password !== undefined && { password }),
        ...(fromAddress !== undefined && { fromAddress }),
      }, scopeOf(req));
      if (!server) throw new AppError(404, 'SMTP server not found');
      res.json({ success: true, data: server });
    } catch (err) { next(err); }
  },

  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      const removed = await smtpServerService.delete(id, scopeOf(req));
      if (!removed) throw new AppError(404, 'SMTP server not found');
      res.json({ success: true });
    } catch (err) { next(err); }
  },

  async test(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseInt(req.params.id, 10);
      await smtpServerService.test(id, scopeOf(req));
      res.json({ success: true, message: 'Connection successful' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Connection failed';
      next(new AppError(400, `SMTP test failed: ${msg}`));
    }
  },
};
