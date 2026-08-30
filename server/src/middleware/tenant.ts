import type { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler';
import { db } from '../db';
import { isMasterTenant, MASTER_TENANT_ID } from '@obliwan/shared';

// Extend Express.Request to carry the resolved tenantId
declare global {
  namespace Express {
    interface Request {
      tenantId: number;
      /**
       * True only when the caller is operating on the master tenant AND has a
       * real `user_tenants` row for it. This is the ONLY thing services may
       * consult before widening a query across tenants — never
       * `isMasterTenant(req.tenantId)` on its own, which is satisfied by any
       * session that merely carries `currentTenantId = 1`.
       */
      masterView: boolean;
    }
  }
}

/**
 * Short-lived membership cache, same rationale as the identity cache in
 * `auth.ts`: one indexed PK lookup per (user, tenant) per MEMBERSHIP_TTL_MS
 * rather than one per request. The TTL bounds how long a removed member keeps
 * access; it used to be the 7-day cookie lifetime (AUDIT-SEC #6).
 */
const MEMBERSHIP_TTL_MS = 10_000;
const MEMBERSHIP_CACHE_MAX = 10_000;
const membershipCache = new Map<string, { at: number; member: boolean }>();

export function invalidateMembershipCache(userId?: number): void {
  if (userId === undefined) {
    membershipCache.clear();
    return;
  }
  const prefix = userId + ':';
  for (const key of membershipCache.keys()) {
    if (key.startsWith(prefix)) membershipCache.delete(key);
  }
}

/**
 * Paths under `tenantRouter` that a PLATFORM ADMIN (`users.role = 'admin'`) may
 * reach with NO current tenant at all.
 *
 * VERIF-SECFIX R8 (RÉGRESSION) — dropping the `?? 1` fallback was right, but it
 * locked the platform out of itself. `POST /api/users` writes no `user_tenants`
 * row, so a freshly created platform admin has no `currentTenantId`, so every
 * route under `tenantRouter` answers 403 — and `/api/users` is itself mounted
 * under `tenantRouter`, which puts the one route that would REPAIR the account
 * (`PUT /api/users/:id/tenants`) behind the very guard that rejects it. The
 * same happens to the founding admin the moment someone posts
 * `PUT /api/users/1/tenants {"assignments": []}`.
 *
 * The exemption is narrow on all three axes:
 *   - platform admins only — every route under `/users` is already behind
 *     `requireRole('admin')`, so this reaches nothing new;
 *   - account administration only — `usersController` reads and writes `users`,
 *     `user_tenants` and `tenants`, none of which is scoped by `req.tenantId`;
 *   - `req.tenantId` stays UNSET and `req.masterView` is forced to false, so a
 *     handler that does need a tenant fails closed instead of silently widening
 *     to every customer. `routes/users.routes.ts` puts `requireResolvedTenant`
 *     in front of the single handler in that file which reads `req.tenantId`
 *     (`GET /:id/teams`).
 *
 * This is NOT a fallback to tenant 1: no tenant is invented and no
 * tenant-scoped data is served. The account can inspect and fix tenant
 * assignments, then `POST /api/tenant/switch` onto a real tenant.
 */
const TENANTLESS_PLATFORM_ADMIN_PATHS: RegExp[] = [/^\/users(?:\/|$)/];

function isTenantlessAdminPath(path: string): boolean {
  return TENANTLESS_PLATFORM_ADMIN_PATHS.some((re) => re.test(path));
}

async function isMember(userId: number, tenantId: number): Promise<boolean> {
  const key = userId + ':' + tenantId;
  const hit = membershipCache.get(key);
  const now = Date.now();
  if (hit && now - hit.at < MEMBERSHIP_TTL_MS) return hit.member;

  const row = await db('user_tenants')
    .where({ user_id: userId, tenant_id: tenantId })
    .first('user_id');
  const member = !!row;
  if (membershipCache.size >= MEMBERSHIP_CACHE_MAX) membershipCache.clear();
  membershipCache.set(key, { at: now, member });
  return member;
}

/**
 * Resolves `req.tenantId` from the session. Applied after `requireAuth` on
 * every route that touches tenant-scoped data.
 *
 * Two audit findings land here.
 *
 * AUDIT-SEC #2 — the session no longer falls back to tenant 1, so a user with
 * no tenant at all arrives with `currentTenantId === undefined` and is refused.
 * The status is 403 ("no tenant granted"), not the previous 400: this is an
 * authorisation outcome, and a 400 invites the client to retry with a
 * different body, which cannot help.
 *
 * AUDIT-SEC #6 — membership is RE-VERIFIED here instead of being trusted from
 * the session. `DELETE /api/tenants/:id/members/:uid` and
 * `PUT /api/users/:id/tenants` used to leave every live session of the removed
 * user reading that tenant's data until the cookie expired.
 */
export function requireTenant(req: Request, _res: Response, next: NextFunction): void {
  const tid = req.session?.currentTenantId;
  const userId = req.session?.userId;

  if (!userId) {
    next(new AppError(401, 'Authentication required'));
    return;
  }
  // Platform admins (`users.role = 'admin'`, re-read from the database by
  // requireAuth on every request) have implicit access to every tenant: that is
  // what `POST /api/tenant/switch` and the Obligate cross-app handoff already
  // rely on, and what `requireRole('admin')` grants them everywhere else. They
  // are exempt from the membership row, NOT from the tenant being named.
  const isPlatformAdmin = req.session?.role === 'admin';

  if (!tid) {
    // R8 escape hatch — see TENANTLESS_PLATFORM_ADMIN_PATHS above. No tenant is
    // resolved: `req.tenantId` stays undefined and the god view stays off.
    if (isPlatformAdmin && isTenantlessAdminPath(req.path)) {
      req.masterView = false;
      next();
      return;
    }
    next(new AppError(403, 'No tenant granted for this account'));
    return;
  }

  isMember(userId, tid)
    .then((member) => {
      if (!member && !isPlatformAdmin) {
        // The session names a tenant the user no longer belongs to. Drop the
        // stale value so the next /api/auth/me re-resolves a legitimate one
        // instead of looping on a tenant that will never come back.
        delete req.session.currentTenantId;
        next(new AppError(403, 'No access to the selected tenant'));
        return;
      }
      req.tenantId = tid;
      // The god view is a property of the CALLER, established here, never of
      // the number sitting in the session.
      //
      // VERIF-SECFIX R4 — a plain `member` row on the master tenant used to be
      // enough. Tenant 1 is the one migration 001 creates under the name
      // "Default": it is where every "for now" account is parked and the only
      // tenant that exists before the first customer is created, so
      // `POST /api/tenants/1/members {userId, role:'member'}` — an ordinary
      // gesture in the UI — handed a non-admin a read across every customer's
      // group tree. The god view is a PLATFORM property and now requires
      // `users.role = 'admin'`, which requireAuth re-reads from the database on
      // every request. Master-tenant membership alone grants nothing beyond the
      // master tenant's own data.
      req.masterView = tid === MASTER_TENANT_ID && isMasterTenant(tid) && isPlatformAdmin;
      next();
    })
    .catch(next);
}
