import { db } from '../db';
import { logger } from './logger';
import { invalidateIdentityCache } from '../middleware/auth';
import { invalidateMembershipCache } from '../middleware/tenant';

/**
 * Hard revocation of every live session of a user (AUDIT-SEC #6).
 *
 * `requireAuth` / `requireTenant` already re-check `is_active`, the role and
 * tenant membership on a 10 s cache, so access dies on its own shortly after a
 * revocation. This function closes the remaining window for the acts where
 * "shortly" is not good enough — an account deleted, deactivated from Obligate,
 * or stripped of a tenant — by deleting the server-side rows outright.
 *
 * `session.sess` is a `json` column owned by connect-pg-simple;
 * `sess->>'userId'` yields the number as text, hence the String() cast. This is
 * a maintenance operation on someone else's table, so a failure is logged and
 * swallowed: the caller's business act (delete the user, remove the membership)
 * has already succeeded and must not be rolled back because a cleanup query
 * could not run.
 */
export async function destroyUserSessions(userId: number): Promise<number> {
  invalidateIdentityCache(userId);
  invalidateMembershipCache(userId);
  try {
    const deleted = await db('session')
      .whereRaw("sess->>'userId' = ?", [String(userId)])
      .del();
    if (deleted > 0) {
      logger.info({ userId, deleted }, 'Revoked live sessions for user');
    }
    return deleted;
  } catch (err) {
    logger.warn({ err, userId }, 'Failed to revoke live sessions (in-memory caches were cleared)');
    return 0;
  }
}
