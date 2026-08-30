import type { Request, Response, NextFunction } from 'express';
import { authService, SsoOnlyError } from '../services/auth.service';
import { appConfigService } from '../services/appConfig.service';
import { twoFactorService } from '../services/twoFactor.service';
import { permissionService } from '../services/permission.service';
import { tenantService } from '../services/tenant.service';
import { PENDING_MFA_TTL_MS } from './twoFactor.controller';
import { AppError } from '../middleware/errorHandler';
import { regenerateSession } from '../middleware/auth';
import { obligateService } from '../services/obligate.service';
import { db } from '../db';
import { config } from '../config';
import { logger } from '../utils/logger';
import type { LoginInput } from '../validators/auth.schema';

/**
 * Resolve & store the first accessible tenant in the session.
 *
 * AUDIT-SEC #2 (CRITIQUE) — this used to be:
 *
 *     req.session.currentTenantId = tenant?.id ?? 1;   // 1 === MASTER_TENANT_ID
 *
 * and `shared/src/tenants.ts` documents tenant 1 as the GOD VIEW. A user with
 * no `user_tenants` row — a freshly created account (`POST /api/users` creates
 * none), or one whose tenants were just revoked with
 * `PUT /api/users/:id/tenants {assignments: []}` — therefore landed in the
 * master tenant and read the live alerts and the group trees of every customer.
 *
 * There is no fallback any more. No membership means no current tenant, and
 * `requireTenant` answers 403. The key is DELETED rather than left stale, so a
 * user whose access was revoked cannot keep operating on the tenant their
 * session still names.
 */
async function setSessionTenant(req: Request, userId: number): Promise<void> {
  const tenant = await tenantService.getFirstTenantForUser(userId);
  if (tenant) {
    req.session.currentTenantId = tenant.id;
    return;
  }
  delete req.session.currentTenantId;
  logger.warn(
    { userId },
    'Session established with no tenant membership: no current tenant set, tenant-scoped routes will ' +
      'answer 403. Assign one with PUT /api/users/:id/tenants.',
  );
}

export const authController = {
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { username, password } = req.body as LoginInput;
      let user;
      try {
        user = await authService.authenticate(username, password);
      } catch (authErr) {
        if (authErr instanceof SsoOnlyError) {
          // Return 401 with a special code so the client can show the SSO redirect hint
          res.status(401).json({
            success: false,
            error: 'Ce compte utilise la connexion SSO.',
            code: 'SSO_ONLY',
            foreignSource: authErr.foreignSource,
          });
          return;
        }
        throw authErr;
      }

      if (!user) {
        throw new AppError(401, 'Invalid username or password');
      }

      const hasMfa = user.totpEnabled || user.emailOtpEnabled;

      if (hasMfa) {
        // Step 1: store pending MFA, don't create real session yet.
        //
        // VERIF-SECFIX-AUTRES #17 — `pendingMfaUserId` used to have no expiry at
        // all and therefore lived for the cookie's seven days: an attacker who
        // held the password never had to redo this step between two salvos of
        // code guessing. It now dies with the codes it waits for, and the
        // per-session attempt counter is reset for this fresh attempt.
        req.session.pendingMfaUserId = user.id;
        req.session.pendingMfaExpires = Date.now() + PENDING_MFA_TTL_MS;
        delete req.session.mfaAttempts;

        // If email OTP is enabled, auto-send a code
        if (user.emailOtpEnabled && user.email) {
          const cfg = await appConfigService.getAll();
          if (cfg.otp_smtp_server_id) {
            const code = twoFactorService.generateEmailOtp();
            req.session.pendingEmailOtp = { code, email: user.email, expires: Date.now() + 10 * 60 * 1000 };
            await twoFactorService.sendEmailOtp(cfg.otp_smtp_server_id, user.email, code);
          }
        }

        res.json({
          success: true,
          data: {
            requires2fa: true,
            methods: { totp: user.totpEnabled ?? false, email: user.emailOtpEnabled ?? false },
          },
        });
        return;
      }

      // No 2FA — complete session immediately.
      //
      // AUDIT-SEC #5 (MAJEUR, session fixation) — the session id must NOT
      // survive the privilege elevation. `GET /auth/sso-redirect` hands a valid
      // `connect.sid` to a fully anonymous caller (it writes `oauthState` then
      // calls `session.save()`), so an attacker who can plant that cookie in a
      // victim's browser used to own the victim's session the instant they
      // logged in — as platform admin if the victim was one.
      await regenerateSession(req);
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;
      await setSessionTenant(req, user.id);

      res.json({ success: true, data: { user } });
    } catch (err) {
      next(err);
    }
  },

  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      req.session.destroy((err) => {
        if (err) {
          next(new AppError(500, 'Failed to logout'));
          return;
        }
        res.clearCookie('connect.sid');
        res.json({ success: true, message: 'Logged out' });
      });
    } catch (err) {
      next(err);
    }
  },

  async me(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.session.userId!;

      // Sync preferences from Obligate for SSO users (throttled 60s — await so /me returns fresh prefs)
      const fRow = await db('users').where({ id: userId }).select('foreign_source', 'foreign_id').first() as
        { foreign_source: string | null; foreign_id: number | null } | undefined;
      if (fRow?.foreign_source === 'obligate' && fRow.foreign_id) {
        await obligateService.syncUserPreferences(userId, fRow.foreign_id).catch(() => {});
      }

      const user = await authService.getUserById(userId);
      if (!user) {
        throw new AppError(401, 'User not found');
      }

      // Repair missing currentTenantId (e.g. sessions from before Phase 13)
      if (!req.session.currentTenantId) {
        await setSessionTenant(req, user.id);
      }

      const isAdmin = user.role === 'admin';
      const permissions = await permissionService.getUserPermissions(user.id, isAdmin, req.session.currentTenantId);

      // Check if force 2FA applies to this user
      let requires2faSetup = false;
      if (!config.disable2faForce) {
        const cfg = await appConfigService.getAll();
        if (cfg.force_2fa && !user.totpEnabled && !user.emailOtpEnabled) {
          requires2faSetup = true;
        }
      }

      res.json({
        success: true,
        data: { user, permissions, requires2faSetup, currentTenantId: req.session.currentTenantId },
      });
    } catch (err) {
      next(err);
    }
  },

  async permissions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const isAdmin = req.session.role === 'admin';
      const permissions = await permissionService.getUserPermissions(req.session.userId!, isAdmin, req.session.currentTenantId);
      res.json({ success: true, data: permissions });
    } catch (err) {
      next(err);
    }
  },
};
