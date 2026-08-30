import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { db } from '../db';
import { hashPassword } from '../utils/crypto';
import { appConfigService } from './appConfig.service';
import { smtpServerService } from './smtpServer.service';
import { destroyUserSessions } from '../utils/sessions';
import { config } from '../config';
import { logger } from '../utils/logger';

const TOKEN_EXPIRY_MS = 60 * 60 * 1000; // 1 hour

interface ResettableUser {
  id: number;
  email: string | null;
  foreign_source: string | null;
  is_active: boolean;
}

/**
 * AUDIT-SEC #12 — the ONE definition of "this account may be given a local
 * password through the reset flow".
 *
 * `db('users').where({ email }).first()` accepted anything the column held.
 * Two consequences, both reachable from the unauthenticated
 * `POST /api/auth/forgot-password`:
 *
 *  1. **SSO bypass.** An account federated by Obligate has `foreign_source =
 *     'obligate'` and `password_hash IS NULL` by design (migration 001), and
 *     `authService` refuses it a local login for exactly that reason. Resetting
 *     it wrote a `password_hash`, which turned the account into a locally
 *     authenticable one — a credential the identity provider does not know
 *     about, cannot see, cannot rotate, and cannot revoke when the employee
 *     leaves. Every other write path already refuses this
 *     (`usersController.changePassword`, `profileController.changePassword`,
 *     `usersController.update`); this one did not.
 *  2. **Deactivated accounts.** `is_active = false` is the revocation gesture of
 *     `PUT /api/users/:id {isActive:false}` and of the SSO sync. Nothing stopped
 *     a reset from landing on one, so whoever still controlled the mailbox of a
 *     dismissed user could keep setting the password of a dead account — and on
 *     the day someone re-enabled it, the attacker's password was already in.
 *
 * The predicate is applied at BOTH ends — when the token is issued and again
 * when it is spent — because an account can be federated or deactivated during
 * the one-hour life of a token.
 *
 * Matching is on `lower(btrim(email))` so it uses, and agrees with, the partial
 * unique index created by migration 004: `Alice@acme.tld` and `alice@acme.tld`
 * are the same address and can no longer be two accounts.
 */
function resettableUsers() {
  return db<ResettableUser>('users')
    .whereNull('foreign_source')
    .where({ is_active: true });
}

export const passwordResetService = {
  /** Generate a reset token, store its hash, send the email. Always resolves (no enumeration). */
  async requestReset(email: string): Promise<void> {
    const user = await resettableUsers()
      .whereRaw('lower(btrim(email)) = lower(btrim(?))', [email])
      // Deterministic even if the unique index of migration 004 were ever
      // dropped: `.first()` with no ORDER BY let the planner decide which of two
      // accounts sharing an address received the link.
      .orderBy('id')
      .first();

    if (!user) {
      // Silently succeed to prevent email enumeration. The reason is logged
      // server-side so an operator can tell "no such address" from "that address
      // belongs to a federated or disabled account" — which the CALLER must not
      // be able to tell apart.
      const shadow = await db('users')
        .whereRaw('lower(btrim(email)) = lower(btrim(?))', [email])
        .first('id', 'foreign_source', 'is_active');
      if (shadow) {
        logger.warn(
          { userId: shadow.id, foreignSource: shadow.foreign_source, isActive: shadow.is_active },
          'Password reset refused: that address belongs to a federated or deactivated account ' +
            '(the caller got the usual non-committal 200)',
        );
      }
      return;
    }

    // Invalidate any existing unused tokens for this user
    await db('password_reset_tokens')
      .where({ user_id: user.id })
      .whereNull('used_at')
      .delete();

    // Generate a secure random token
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + TOKEN_EXPIRY_MS);

    await db('password_reset_tokens').insert({
      user_id: user.id,
      token_hash: tokenHash,
      expires_at: expiresAt,
    });

    // Send the reset email if SMTP is configured
    const cfg = await appConfigService.getAll();
    if (!cfg.otp_smtp_server_id) {
      logger.warn('Password reset requested but no SMTP server configured');
      return;
    }

    const smtp = await smtpServerService.getTransportConfig(cfg.otp_smtp_server_id);
    if (!smtp) return;

    const resetUrl = `${config.appUrl}/reset-password?token=${rawToken}`;

    const transport = nodemailer.createTransport({
      host: smtp.host,
      port: smtp.port,
      secure: smtp.secure,
      auth: { user: smtp.username, pass: smtp.password },
    });

    // Deliver to the address AS STORED, not as typed by the caller: the lookup
    // is case- and whitespace-insensitive, so the two can differ, and the link
    // must reach the account's own mailbox.
    const recipient = user.email ?? email;

    await transport.sendMail({
      from: smtp.fromAddress,
      to: recipient,
      subject: `${config.appName} — Reset your password`,
      text: `You requested a password reset for your ${config.appName} account.\n\nClick this link to reset your password (valid for 1 hour):\n${resetUrl}\n\nIf you did not request this, ignore this email.`,
      html: `
        <h2>${config.appName} — Password reset</h2>
        <p>You requested a password reset for your account.</p>
        <p style="margin:24px 0">
          <a href="${resetUrl}" style="background:#3b82f6;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">
            Reset password
          </a>
        </p>
        <p style="color:#888;font-size:12px">This link expires in 1 hour. If you did not request this, ignore this email.</p>
      `,
    });

    logger.info(`Password reset email sent to ${recipient}`);
  },

  /** Validate a raw token. Returns the user_id if valid, null otherwise. */
  async validateToken(rawToken: string): Promise<number | null> {
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const row = await db('password_reset_tokens')
      .where({ token_hash: tokenHash })
      .whereNull('used_at')
      .where('expires_at', '>', new Date())
      .first();

    if (!row) return null;

    // A token issued before the account was federated or deactivated must stop
    // being valid the moment it is. Reported as invalid rather than forbidden:
    // the caller holds a token, not a session, and must learn nothing about the
    // account behind it.
    const user = await resettableUsers().where({ id: row.user_id }).first();
    return user ? row.user_id : null;
  },

  /** Consume a raw token and update the user's password. */
  async resetPassword(rawToken: string, newPassword: string): Promise<boolean> {
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const row = await db('password_reset_tokens')
      .where({ token_hash: tokenHash })
      .whereNull('used_at')
      .where('expires_at', '>', new Date())
      .first();

    if (!row) return false;

    const newHash = await hashPassword(newPassword);

    const applied = await db.transaction(async (trx) => {
      // Burn the token FIRST, and only if it is still unused: two concurrent
      // submissions of the same link then race on a single UPDATE, and the loser
      // gets `used === 0` instead of both writing a password.
      const used = await trx('password_reset_tokens')
        .where({ id: row.id })
        .whereNull('used_at')
        .update({ used_at: new Date() });
      if (used === 0) return false;

      // Re-check the account HERE, in the same transaction, and let the WHERE
      // clause carry the rule: a plain `.where({ id })` writes the hash whatever
      // the row has become since the token was issued.
      const updated = await trx('users')
        .where({ id: row.user_id, is_active: true })
        .whereNull('foreign_source')
        .update({ password_hash: newHash, updated_at: new Date() });

      if (updated === 0) {
        // The token stays burnt on purpose: it was spent, and leaving it live
        // would let someone grind the same link against an account waiting to be
        // re-enabled.
        logger.warn(
          { userId: row.user_id },
          'Password reset token refused at redemption: the account became federated or ' +
            'deactivated after the token was issued',
        );
        return false;
      }
      return true;
    });

    if (!applied) return false;

    // A reset is a RECOVERY gesture, which means the person being locked out may
    // be the very one currently holding the account. This path wrote a new hash
    // and left every live session untouched, so an intruder who was already
    // inside kept their session and the legitimate owner's reset removed nobody.
    // `userService.changePassword` already treats a password change as a
    // revocation; the recovery path is where it matters most.
    await destroyUserSessions(row.user_id);

    return true;
  },
};
