import type { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler';
import { db } from '../db';
import { logger } from '../utils/logger';

// Extend express-session types
declare module 'express-session' {
  interface SessionData {
    userId: number;
    username: string;
    role: string;
    /**
     * The tenant the session is currently operating on.
     *
     * OPTIONAL BY DESIGN (AUDIT-SEC #2). It used to be written as
     * `tenant?.id ?? 1`, and 1 is MASTER_TENANT_ID — the god view. A user with
     * no `user_tenants` row (freshly created account, account whose tenants
     * were just revoked) therefore landed in the master tenant and read the
     * live alerts and group trees of every customer. There is no longer any
     * fallback: no membership means no current tenant, and `requireTenant`
     * answers 403.
     */
    currentTenantId?: number;
    oauthState: string;
    requestedTenantSlug?: string;
  }
}

interface IdentityRow {
  role: string;
  is_active: boolean;
}

/**
 * Short-lived cache of (is_active, role) so re-validating the session on every
 * request costs one indexed PK lookup per user per REVALIDATE_MS, not one per
 * request. The window is the maximum time a revoked account keeps its access;
 * it used to be `sessionMaxAge` = 7 days (AUDIT-SEC #6).
 *
 * Deliberately a plain Map: this process is the only reader, entries are two
 * booleans, and the eviction below keeps it bounded. A revocation that must be
 * instant also purges the server-side session rows (utils/sessions.ts), which
 * bypasses this cache entirely.
 */
const REVALIDATE_MS = 10_000;
const IDENTITY_CACHE_MAX = 5_000;
const identityCache = new Map<number, { at: number; row: IdentityRow | null }>();

/** Drop a user from the revalidation cache (called after a role/status write). */
export function invalidateIdentityCache(userId?: number): void {
  if (userId === undefined) identityCache.clear();
  else identityCache.delete(userId);
}

async function loadIdentity(userId: number): Promise<IdentityRow | null> {
  const hit = identityCache.get(userId);
  const now = Date.now();
  if (hit && now - hit.at < REVALIDATE_MS) return hit.row;

  const row = (await db('users')
    .where({ id: userId })
    .first('role', 'is_active')) as IdentityRow | undefined;

  if (identityCache.size >= IDENTITY_CACHE_MAX) identityCache.clear();
  identityCache.set(userId, { at: now, row: row ?? null });
  return row ?? null;
}

/**
 * AUDIT-SEC #6 (MAJEUR) — `requireAuth` used to trust the session blindly.
 * Neither `users.is_active` nor `users.role` was ever re-read, so:
 *   - an account deactivated from Obligate (`sso-user-sync` action
 *     `deactivate`) kept full HTTP access for the 7-day cookie lifetime, and
 *   - a user demoted from `admin` to `user` kept `req.session.role === 'admin'`,
 *     which is what `requireRole('admin')` and `requireCapability()` read.
 *
 * The row is now re-read (cached REVALIDATE_MS) and the session is refreshed
 * from it, so a revocation takes effect within seconds instead of a week.
 */
export function requireAuth(req: Request, _res: Response, next: NextFunction): void {
  const userId = req.session?.userId;
  if (!userId) {
    // ┌─ WHICH 401 IS THIS? ────────────────────────────────────────────────┐
    // │ Two completely different failures answer 401 here and the response   │
    // │ cannot tell them apart — deliberately, since it is unauthenticated:  │
    // │                                                                     │
    // │   NO COOKIE AT ALL   the browser sent nothing. The cookie was never  │
    // │                      stored (Secure over plain HTTP), or it was      │
    // │                      stored for a different host than the one being  │
    // │                      called — the classic SSO case, where the        │
    // │                      callback lands on one hostname and the app is   │
    // │                      then used on another.                           │
    // │   COOKIE, NO SESSION the browser sent an id the store does not have: │
    // │                      the row expired, the store was wiped, or the    │
    // │                      session was regenerated and this is the old id. │
    // │                                                                     │
    // │ Logged at debug so a normal anonymous hit does not spam production,  │
    // │ and carrying the HOST, because "it works in one tab and 401s in      │
    // │ another" is almost always two hostnames sharing one deployment.      │
    // └─────────────────────────────────────────────────────────────────────┘
    const sentCookie = typeof req.headers.cookie === 'string'
      && /(^|;\s*)connect\.sid=/.test(req.headers.cookie);
    logger.debug(
      { path: req.path, host: req.headers.host, sentCookie, sessionId: req.sessionID },
      sentCookie
        ? '401: a session cookie arrived but no session backs it'
        : '401: NO session cookie was sent by the browser',
    );
    next(new AppError(401, 'Authentication required'));
    return;
  }

  loadIdentity(userId)
    .then((identity) => {
      if (!identity) {
        // The account was deleted while the session lived on.
        req.session.destroy(() => undefined);
        next(new AppError(401, 'Authentication required'));
        return;
      }
      if (!identity.is_active) {
        req.session.destroy(() => undefined);
        next(new AppError(403, 'Account disabled'));
        return;
      }
      // The database is the authority on the role, not the cookie.
      if (req.session.role !== identity.role) {
        logger.info(
          { userId, sessionRole: req.session.role, dbRole: identity.role },
          'requireAuth: session role was stale, refreshed from the database',
        );
        req.session.role = identity.role;
      }
      next();
    })
    .catch(next);
}

/**
 * Elevate an anonymous session into an authenticated one WITHOUT keeping the
 * session id (AUDIT-SEC #5, session fixation).
 *
 * `GET /auth/sso-redirect` writes `oauthState` and calls `req.session.save()`,
 * which materialises a server-side session and emits a `connect.sid` cookie to
 * an entirely anonymous caller. Because the three login paths only assigned
 * `req.session.userId` on top of the existing session, an attacker able to
 * plant that cookie in a victim's browser (XSS on a sibling Obli* subdomain, or
 * a cookie injection over plain HTTP while `cookie.secure` follows
 * `FORCE_HTTPS`) owned the victim's session the moment they logged in — as
 * platform admin if the victim was one.
 *
 * `regenerate()` issues a brand-new id and an empty session; the few keys the
 * flow genuinely needs to survive are copied over explicitly, by name. Anything
 * an anonymous caller may have planted (`oauthState`, `pendingMfaUserId`,
 * `pendingEmailOtp`, ...) is destroyed rather than inherited.
 */
export function regenerateSession(
  req: Request,
  preserve?: Partial<Record<'requestedTenantSlug', unknown>>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) {
        reject(new AppError(500, 'Failed to establish session'));
        return;
      }
      if (preserve?.requestedTenantSlug !== undefined) {
        req.session.requestedTenantSlug = String(preserve.requestedTenantSlug);
      }
      resolve();
    });
  });
}
