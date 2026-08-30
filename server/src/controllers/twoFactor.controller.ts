import type { Request, Response, NextFunction } from 'express';
import { db } from '../db';
import { twoFactorService } from '../services/twoFactor.service';
import { appConfigService } from '../services/appConfig.service';
import { authService } from '../services/auth.service';
import { tenantService } from '../services/tenant.service';
import { AppError } from '../middleware/errorHandler';
import { regenerateSession } from '../middleware/auth';
import { comparePassword } from '../utils/crypto';
import { logger } from '../utils/logger';

// Extend session type for 2FA state
declare module 'express-session' {
  interface SessionData {
    pendingMfaUserId?: number;
    /**
     * VERIF-SECFIX-AUTRES #17 — `pendingMfaUserId` used to live as long as the
     * cookie (seven days), so an attacker who knew the password never had to
     * redo step 1 between two salvos of code guessing. The half-authenticated
     * state now expires with the codes it is waiting for.
     */
    pendingMfaExpires?: number;
    /**
     * VERIF-SECFIX R6 — failed second-factor attempts, counted for BOTH
     * methods. It used to live inside `pendingEmailOtp`, which meant the TOTP
     * branch counted nothing at all.
     */
    mfaAttempts?: number;
    pendingMfaLinkToken?: string;
    pendingTotpSecret?: string;
    pendingEmailOtp?: { code: string; email: string; expires: number; attempts?: number };
    pendingEmailOtpSetup?: { code: string; email: string; expires: number };
  }
}

/** How long a half-authenticated session may wait for its second factor. */
export const PENDING_MFA_TTL_MS = 10 * 60 * 1000;

/** Failed second-factor attempts before the pending login is destroyed. */
const MAX_MFA_ATTEMPTS = 5;

interface ReauthRow {
  id: number;
  password_hash: string | null;
  totp_secret: string | null;
  totp_enabled: boolean;
  email_otp_enabled: boolean;
  email: string | null;
}

/**
 * VERIF-SECFIX-AUTRES #11 — re-authentication before WEAKENING the account.
 *
 * `DELETE /api/profile/2fa/totp` and `DELETE /api/profile/2fa/email` were
 * guarded by `requireAuth` alone, so a session borrowed for thirty seconds (an
 * unlocked workstation, a same-site XSS) was enough to strip the second factor
 * permanently and silently. The asymmetry was glaring in the same codebase:
 * ENABLING TOTP requires a valid code, and changing the password requires the
 * old one — only the operation that removes protection asked for nothing.
 *
 * Accepted proofs, in order:
 *   1. `currentPassword`, when the account has one;
 *   2. a valid TOTP code, when TOTP is enabled (it is burnt, like at login);
 *   3. the e-mail code from a fresh `POST /api/profile/2fa/email/setup`, which
 *      is the only factor an SSO-only account with e-mail OTP possesses.
 */
async function assertReauthenticated(req: Request): Promise<ReauthRow> {
  const userId = req.session.userId!;
  const row = (await db('users')
    .where({ id: userId })
    .first('id', 'password_hash', 'totp_secret', 'totp_enabled', 'email_otp_enabled', 'email')) as
    ReauthRow | undefined;
  if (!row) throw new AppError(401, 'User not found');

  const body = (req.body ?? {}) as { currentPassword?: unknown; code?: unknown };
  const currentPassword = body.currentPassword === undefined ? null : String(body.currentPassword);
  const code = body.code === undefined ? null : String(body.code);

  if (currentPassword !== null && row.password_hash) {
    if (await comparePassword(currentPassword, row.password_hash)) return row;
    logger.warn({ userId }, '2FA disable refused: wrong current password');
    throw new AppError(400, 'Current password is incorrect');
  }

  if (code !== null) {
    if (row.totp_enabled && row.totp_secret) {
      const counter = twoFactorService.validateTotp(row.totp_secret, code);
      if (counter !== null && (await twoFactorService.consumeTotpCounter(row.id, counter))) return row;
    }
    // The e-mail proof is only a proof when the code went to the address the
    // account ALREADY uses as its second factor.
    //
    // `POST /api/profile/2fa/email/setup` takes the destination address FROM
    // THE REQUEST BODY, so accepting any live `pendingEmailOtpSetup` handed the
    // whole re-authentication back to the attacker: with a borrowed session,
    //   POST /api/profile/2fa/email/setup {"email":"attacker@evil"}   -> 200
    //   (the code lands in the attacker's own inbox)
    //   DELETE /api/profile/2fa/totp {"code":"<that code>"}           -> 200
    // and the second factor is gone without the password and without ever
    // touching the victim's mailbox. Comparing the address turns the check back
    // into "prove you hold the registered factor", which is the only case this
    // branch exists for: an SSO-only account (`password_hash IS NULL`) whose
    // sole credential is its enrolled e-mail OTP.
    const setup = req.session.pendingEmailOtpSetup;
    const registered = row.email_otp_enabled && row.email ? row.email.trim().toLowerCase() : null;
    if (setup && Date.now() <= setup.expires && setup.code === code) {
      if (registered !== null && String(setup.email).trim().toLowerCase() === registered) {
        delete req.session.pendingEmailOtpSetup;
        return row;
      }
      logger.warn(
        { userId },
        '2FA disable refused: the confirmation code was sent to an address that is not the ' +
          "account's enrolled second factor",
      );
      throw new AppError(400, 'Invalid code');
    }
    logger.warn({ userId }, '2FA disable refused: invalid confirmation code');
    throw new AppError(400, 'Invalid code');
  }

  throw new AppError(
    400,
    row.password_hash
      ? 'Re-authentication required: send currentPassword, or a valid code from your second factor'
      : 'Re-authentication required: send a valid code from your second factor',
  );
}

export const twoFactorController = {
  // ── Profile endpoints (authenticated) ─────────────────────────────────────

  async status(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const user = await authService.getUserById(req.session.userId!);
      if (!user) throw new AppError(401, 'User not found');
      res.json({ success: true, data: {
        totpEnabled: user.totpEnabled ?? false,
        emailOtpEnabled: user.emailOtpEnabled ?? false,
        email: user.email ?? null,
      }});
    } catch (err) { next(err); }
  },

  // TOTP setup step 1: generate secret + QR (stored in session)
  async totpSetup(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const user = await authService.getUserById(req.session.userId!);
      if (!user) throw new AppError(401, 'User not found');
      const { secret, uri } = twoFactorService.generateTotpSecret(user.username);
      const qrDataUrl = await twoFactorService.generateTotpQr(uri);
      req.session.pendingTotpSecret = secret;
      res.json({ success: true, data: { secret, qrDataUrl } });
    } catch (err) { next(err); }
  },

  // TOTP setup step 2: verify code, save secret and enable
  async totpEnable(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { code } = req.body;
      const secret = req.session.pendingTotpSecret;
      if (!secret) throw new AppError(400, 'No pending TOTP setup. Call /setup first.');
      if (!twoFactorService.verifyTotp(secret, String(code))) {
        throw new AppError(400, 'Invalid code');
      }
      await db('users').where({ id: req.session.userId }).update({
        totp_secret: secret,
        totp_enabled: true,
      });
      delete req.session.pendingTotpSecret;
      res.json({ success: true });
    } catch (err) { next(err); }
  },

  async totpDisable(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      await assertReauthenticated(req);
      await db('users').where({ id: req.session.userId }).update({
        totp_secret: null,
        totp_enabled: false,
      });
      await twoFactorService.forgetTotpCounters(req.session.userId!);
      logger.warn({ userId: req.session.userId }, '2FA: TOTP disabled by the account holder');
      res.json({ success: true });
    } catch (err) { next(err); }
  },

  // Email OTP setup step 1: send OTP to given email
  async emailSetup(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { email } = req.body;
      if (!email) throw new AppError(400, 'Missing email');
      const cfg = await appConfigService.getAll();
      if (!cfg.otp_smtp_server_id) throw new AppError(400, 'No SMTP server configured for OTP. Ask your administrator.');
      const code = twoFactorService.generateEmailOtp();
      req.session.pendingEmailOtpSetup = { code, email, expires: Date.now() + 10 * 60 * 1000 };
      await twoFactorService.sendEmailOtp(cfg.otp_smtp_server_id, email, code);
      res.json({ success: true, message: `Code sent to ${email}` });
    } catch (err) { next(err); }
  },

  // Email OTP setup step 2: verify code, save email and enable
  async emailEnable(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { code } = req.body;
      const pending = req.session.pendingEmailOtpSetup;
      if (!pending) throw new AppError(400, 'No pending email OTP setup. Call /setup first.');
      if (Date.now() > pending.expires) throw new AppError(400, 'Code expired');
      if (pending.code !== String(code)) throw new AppError(400, 'Invalid code');
      await db('users').where({ id: req.session.userId }).update({
        email: pending.email,
        email_otp_enabled: true,
      });
      delete req.session.pendingEmailOtpSetup;
      res.json({ success: true });
    } catch (err) { next(err); }
  },

  async emailDisable(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      await assertReauthenticated(req);
      await db('users').where({ id: req.session.userId }).update({ email_otp_enabled: false });
      logger.warn({ userId: req.session.userId }, '2FA: e-mail OTP disabled by the account holder');
      res.json({ success: true });
    } catch (err) { next(err); }
  },

  // ── Auth endpoints (after step-1 login, session has pendingMfaUserId) ─────

  async verify(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { code, method } = req.body;
      const userId = req.session.pendingMfaUserId;
      if (!userId) throw new AppError(400, 'No pending 2FA session');

      // VERIF-SECFIX-AUTRES #17 — the half-authenticated window is bounded.
      if (req.session.pendingMfaExpires && Date.now() > req.session.pendingMfaExpires) {
        delete req.session.pendingMfaUserId;
        delete req.session.pendingMfaExpires;
        delete req.session.pendingEmailOtp;
        delete req.session.mfaAttempts;
        throw new AppError(401, '2FA session expired — restart the login');
      }

      const row = await db('users')
        .where({ id: userId })
        .first('id', 'username', 'role', 'totp_secret', 'totp_enabled', 'email_otp_enabled', 'email');

      if (!row) throw new AppError(400, 'User not found');

      let valid = false;

      if (method === 'totp' && row.totp_enabled && row.totp_secret) {
        // VERIF-SECFIX R6 (b) — anti-replay. `validate({window})` accepts a code
        // for the whole period plus the tolerance, and nothing used to record
        // that a code had been spent: a code seen once over a shoulder, in a
        // screen share or through a phishing proxy could simply be replayed.
        // The counter it matched is burnt on success.
        const counter = twoFactorService.validateTotp(row.totp_secret, String(code));
        if (counter !== null) {
          valid = await twoFactorService.consumeTotpCounter(row.id, counter);
          if (!valid) {
            logger.warn({ userId, counter }, '2FA: TOTP code replayed — refused');
          }
        }
      } else if (method === 'totp') {
        logger.warn({ userId, totpEnabled: row.totp_enabled, hasSecret: !!row.totp_secret },
          'TOTP verify: totp_enabled or totp_secret missing in DB');
      } else if (method === 'email' && row.email_otp_enabled) {
        const pending = req.session.pendingEmailOtp;
        if (pending && Date.now() <= pending.expires && pending.code === String(code)) {
          valid = true;
        }
      }

      if (!valid) {
        // VERIF-SECFIX R6 (a) — the attempt counter now covers BOTH branches.
        // It used to live inside `pendingEmailOtp`, so the TOTP branch counted
        // nothing, burnt nothing and left `pendingMfaUserId` alive for the
        // cookie's seven days. `authLimiter` is no help here: its key is
        // `${ip}:${req.body.username}` and this route carries no `username`, so
        // the key degenerates to `ip:` and rotating IPs buys unlimited tries.
        // Five failures destroy the pending login, whatever the method, which
        // forces the attacker back through the password step every five
        // guesses (and through a fresh CSPRNG draw for the e-mail code).
        const attempts = (req.session.mfaAttempts ?? 0) + 1;
        req.session.mfaAttempts = attempts;
        if (attempts >= MAX_MFA_ATTEMPTS) {
          delete req.session.pendingEmailOtp;
          delete req.session.pendingMfaUserId;
          delete req.session.pendingMfaExpires;
          delete req.session.mfaAttempts;
          logger.warn({ userId, method }, `2FA: pending login destroyed after ${MAX_MFA_ATTEMPTS} failed attempts`);
          throw new AppError(401, 'Too many invalid codes — restart the login');
        }
        throw new AppError(401, 'Invalid code');
      }

      // AUDIT-SEC #5 — regenerate BEFORE elevating: this is the second of the
      // three points where an anonymous session becomes an authenticated one.
      // Everything pre-auth (pendingMfaUserId, pendingEmailOtp, oauthState) is
      // destroyed with the old session rather than carried over.
      await regenerateSession(req);

      // Complete the session
      req.session.userId = row.id;
      req.session.username = row.username;
      req.session.role = row.role;

      // Set tenant in session. AUDIT-SEC #2 — no `?? 1` fallback: tenant 1 is
      // the god view, and handing it to a user with no membership is exactly
      // the defect. No membership means no current tenant and a 403 from
      // requireTenant.
      const firstTenant = await tenantService.getFirstTenantForUser(row.id);
      if (firstTenant) {
        req.session.currentTenantId = firstTenant.id;
      } else {
        delete req.session.currentTenantId;
        logger.warn({ userId: row.id }, '2FA login with no tenant membership: no current tenant set');
      }

      const user = await authService.getUserById(row.id);
      res.json({ success: true, data: { user } });
    } catch (err) { next(err); }
  },

  async resendEmail(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.session.pendingMfaUserId;
      if (!userId) throw new AppError(400, 'No pending 2FA session');
      if (req.session.pendingMfaExpires && Date.now() > req.session.pendingMfaExpires) {
        delete req.session.pendingMfaUserId;
        delete req.session.pendingMfaExpires;
        delete req.session.pendingEmailOtp;
        delete req.session.mfaAttempts;
        throw new AppError(401, '2FA session expired — restart the login');
      }

      const row = await db('users').where({ id: userId }).first('email', 'email_otp_enabled');
      if (!row || !row.email_otp_enabled || !row.email) {
        throw new AppError(400, 'Email OTP not configured for this user');
      }

      const cfg = await appConfigService.getAll();
      if (!cfg.otp_smtp_server_id) throw new AppError(400, 'No SMTP server configured for OTP');

      const code = twoFactorService.generateEmailOtp();
      req.session.pendingEmailOtp = { code, email: row.email, expires: Date.now() + 10 * 60 * 1000 };
      await twoFactorService.sendEmailOtp(cfg.otp_smtp_server_id, row.email, code);
      res.json({ success: true, message: `Code sent to ${row.email}` });
    } catch (err) { next(err); }
  },
};
