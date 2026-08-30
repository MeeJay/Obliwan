import type { Request, Response, NextFunction } from 'express';
import { db } from '../db';
import { comparePassword, hashPassword } from '../utils/crypto';
import { AppError } from '../middleware/errorHandler';
import { destroyUserSessions } from '../utils/sessions';
import { logger } from '../utils/logger';
import type { UpdateProfileInput, ChangePasswordInput } from '../validators/profile.schema';

/** Promise wrapper over the callback-style `req.session.save`. */
function saveSession(req: Request): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.save((err) => (err ? reject(err) : resolve()));
  });
}

function buildUserResponse(row: Record<string, unknown>) {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    role: row.role,
    isActive: row.is_active,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    preferences: row.preferences ?? null,
    email: row.email ?? null,
    preferredLanguage: row.preferred_language ?? 'en',
    enrollmentVersion: row.enrollment_version ?? 0,
    hasPassword: !!row.password_hash,
    avatar: row.avatar ?? null,
  };
}

export const profileController = {
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await db('users')
        .select('id', 'username', 'display_name', 'role', 'is_active', 'created_at', 'updated_at', 'preferences', 'email', 'preferred_language', 'enrollment_version', 'password_hash', 'avatar')
        .where({ id: req.session.userId })
        .first();

      if (!row) throw new AppError(404, 'User not found');

      res.json({ success: true, data: buildUserResponse(row) });
    } catch (err) {
      next(err);
    }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = req.body as UpdateProfileInput;

      const updatePayload: Record<string, unknown> = { updated_at: new Date() };

      if ('displayName' in data) updatePayload.display_name = data.displayName;
      if ('preferences' in data) {
        updatePayload.preferences = data.preferences !== undefined ? JSON.stringify(data.preferences) : null;
      }
      if ('email' in data) updatePayload.email = data.email || null;
      if ('preferredLanguage' in data) updatePayload.preferred_language = data.preferredLanguage;

      // If email changes and email OTP is enabled, disable it for security
      if ('email' in data && data.email) {
        const current = await db('users').select('email', 'email_otp_enabled').where({ id: req.session.userId }).first();
        if (current?.email_otp_enabled && current.email !== data.email) {
          updatePayload.email_otp_enabled = false;
        }
      }

      const [row] = await db('users')
        .where({ id: req.session.userId })
        .update(updatePayload)
        .returning(['id', 'username', 'display_name', 'role', 'is_active', 'created_at', 'updated_at', 'preferences', 'email', 'preferred_language', 'enrollment_version', 'avatar']);

      if (!row) throw new AppError(404, 'User not found');

      res.json({ success: true, data: buildUserResponse(row) });
    } catch (err) {
      next(err);
    }
  },

  async changePassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { currentPassword, newPassword } = req.body as ChangePasswordInput;

      const user = await db('users').select('password_hash').where({ id: req.session.userId }).first();
      if (!user) throw new AppError(404, 'User not found');

      // VERIF-SECFIX-AUTRES #20 — `password_hash` is nullable by design (SSO
      // accounts, migration 001). `bcrypt.compare(pw, null)` throws, so an SSO
      // user opening Profile → Change password got a bare 500.
      // `usersController.changePassword` already refuses this case in 400 for an
      // admin acting on a third party; the "self" path did not.
      if (!user.password_hash) {
        throw new AppError(400, 'This account has no local password — manage it from your identity provider');
      }

      const valid = await comparePassword(currentPassword, user.password_hash);
      if (!valid) throw new AppError(400, 'Current password is incorrect');

      const newHash = await hashPassword(newPassword);
      await db('users').where({ id: req.session.userId }).update({ password_hash: newHash, updated_at: new Date() });

      // VERIF-SECFIX-AUTRES #20, secondary half — never done.
      //
      // `userService.changePassword` documents a password change as a revocation
      // gesture and calls `destroyUserSessions`; the SELF path — the one a user
      // takes precisely because they suspect their password is known — wrote the
      // new hash and left every other live session of the account signed in. An
      // intruder holding a stolen `connect.sid` was untouched by the victim's
      // reaction, for the remaining seven days of the cookie.
      //
      // ERGONOMICS: `destroyUserSessions` is a per-USER revocation, so it also
      // deletes the row of the session making this very request. Re-saving it
      // immediately after puts the caller's own session back (same sid, same
      // contents, `connect-pg-simple.set` is an upsert) — the OTHER sessions
      // stay dead. The alternative, filtering on `sid` at the SQL level, would
      // be a fourth copy of that query living outside `utils/sessions.ts` and
      // would skip its identity/membership cache invalidation.
      const userId = req.session.userId!;
      await destroyUserSessions(userId);
      try {
        await saveSession(req);
      } catch (saveErr) {
        // The password change itself is committed; only the caller's own
        // convenience is lost. Say so and let them log in again rather than
        // failing a request that already succeeded.
        logger.warn({ err: saveErr, userId },
          'Password changed and other sessions revoked, but the caller\'s own session could not be ' +
            're-saved — they will have to log in again');
        res.json({
          success: true,
          message: 'Password changed successfully — please sign in again',
        });
        return;
      }

      logger.info({ userId }, 'Password changed by the account holder: other live sessions revoked');
      res.json({ success: true, message: 'Password changed successfully' });
    } catch (err) {
      next(err);
    }
  },
};
