import { appConfigService } from './appConfig.service';
import { db } from '../db';
import { logger } from '../utils/logger';

export interface ObligateUserAssertion {
  obligateUserId: number;
  username: string;
  email: string | null;
  displayName: string | null;
  role: string;
  tenants: Array<{ slug: string; role: string; capabilities?: string[] }>;
  teams: string[];
  capabilities?: string[];
  authSource: 'local' | 'ldap';
  linkedLocalUserId: number | null;
  preferences?: {
    preferredTheme?: string;
    toastEnabled?: boolean;
    toastPosition?: string;
    profilePhotoUrl?: string | null;
    preferredLanguage?: string;
    anonymousMode?: boolean;
    appSpecific?: Record<string, string>;
  };
}

/**
 * SECFIX — shape the remote answer before anything downstream reads it.
 *
 * `exchangeCode` used to hand `data.data` to `/auth/callback` verbatim, with
 * the `ObligateUserAssertion` type as the only guarantee — and a TypeScript
 * interface guarantees nothing about JSON that arrived over the wire from
 * another process. Two consequences the callback had to defend against on its
 * own, and one it could not:
 *
 *   - `tenants` / `teams` / `capabilities` sent as something other than an
 *     array made `for (const t of ...)` or `sanitizeCapabilities(...).filter`
 *     throw, and the callback's outer catch turns any throw into
 *     `/login?error=sso_failed`: an unexplained login failure.
 *   - `linkedLocalUserId` sent as a string ("1") or a float slipped past
 *     `if (assertion.linkedLocalUserId)` into a `where({ id })`.
 *
 * Normalising here means the callback reasons about values whose TYPE it can
 * trust, and keeps every "is this really an array" check in one place. It does
 * NOT make the content trustworthy: `linkedLocalUserId` remains an untrusted
 * claim, checked against our own records in obligateCallback.routes.ts.
 */
function toStringOrNull(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function normaliseAssertion(raw: unknown): ObligateUserAssertion | null {
  if (!raw || typeof raw !== 'object') return null;
  const a = raw as Record<string, unknown>;

  const obligateUserId = Number(a.obligateUserId);
  if (!Number.isInteger(obligateUserId) || obligateUserId <= 0) {
    logger.warn({ obligateUserId: a.obligateUserId }, 'Obligate exchange: assertion has no usable obligateUserId');
    return null;
  }
  const username = typeof a.username === 'string' ? a.username.trim() : '';
  if (!username) {
    logger.warn({ obligateUserId }, 'Obligate exchange: assertion has no username');
    return null;
  }

  const rawLinked = Number(a.linkedLocalUserId);
  const linkedLocalUserId = Number.isInteger(rawLinked) && rawLinked > 0 ? rawLinked : null;

  const tenants = (Array.isArray(a.tenants) ? a.tenants : [])
    .map((t) => {
      const o = (t && typeof t === 'object' ? t : {}) as Record<string, unknown>;
      const slug = typeof o.slug === 'string' ? o.slug.trim() : '';
      if (!slug) return null;
      return {
        slug,
        role: o.role === 'admin' ? 'admin' : 'member',
        // Left as unknown strings on purpose: sanitizeCapabilities() is the
        // single vocabulary gate and runs at the point of WRITE.
        capabilities: (Array.isArray(o.capabilities) ? o.capabilities : []).map((c) => String(c)),
      };
    })
    .filter((t): t is { slug: string; role: string; capabilities: string[] } => t !== null);

  const teams = (Array.isArray(a.teams) ? a.teams : []).map((t) => String(t));

  return {
    obligateUserId,
    username,
    email: toStringOrNull(a.email),
    displayName: toStringOrNull(a.displayName),
    role: a.role === 'admin' ? 'admin' : 'user',
    tenants,
    teams,
    capabilities: (Array.isArray(a.capabilities) ? a.capabilities : []).map((c) => String(c)),
    authSource: a.authSource === 'ldap' ? 'ldap' : 'local',
    linkedLocalUserId,
    preferences: (a.preferences && typeof a.preferences === 'object'
      ? a.preferences
      : undefined) as ObligateUserAssertion['preferences'],
  };
}

export const obligateService = {
  /**
   * Check if Obligate is configured and reachable.
   */
  async getSsoConfig(): Promise<{ obligateUrl: string | null; obligateReachable: boolean; obligateEnabled: boolean }> {
    const cfg = await appConfigService.getObligateConfig();
    if (!cfg.url || !cfg.enabled) {
      return { obligateUrl: cfg.url, obligateReachable: false, obligateEnabled: cfg.enabled };
    }

    // ┌─ THE TIMEOUT WAS 2 SECONDS, AND THAT WAS THE BUG ────────────────────┐
    // │ This probe decides whether the login page shows "centralised auth is  │
    // │ UNAVAILABLE, degraded local mode". Two seconds is fine on a LAN and   │
    // │ far too short for the real deployment: Obligate sits behind Oblihub,  │
    // │ so the first call of the day pays DNS, a cold TCP connect and a full  │
    // │ TLS handshake through a reverse proxy. Exceeding 2 s there is normal, │
    // │ not a failure — and the operator was told SSO was down while the      │
    // │ redirect itself worked perfectly.                                     │
    // │                                                                      │
    // │ A banner that cries wolf on a healthy system is worse than no banner: │
    // │ it is the one people learn to ignore before the day it is right.      │
    // └──────────────────────────────────────────────────────────────────────┘
    const PROBE_TIMEOUT_MS = 8000;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
      const res = await fetch(`${cfg.url}/health`, { signal: controller.signal });
      clearTimeout(timeout);
      if (!res.ok) {
        logger.warn(
          { url: cfg.url, status: res.status },
          'Obligate /health answered but not OK — the login page will offer degraded local mode',
        );
      }
      return { obligateUrl: cfg.url, obligateReachable: res.ok, obligateEnabled: true };
    } catch (err) {
      // Logged, because "unreachable" used to be silent and an operator had no
      // way to tell a DNS failure from a timeout from a wrong URL. This runs on
      // a public, unauthenticated route: the reason goes to the log, never to
      // the response.
      logger.warn(
        { url: cfg.url, err: err instanceof Error ? err.message : String(err), timeoutMs: PROBE_TIMEOUT_MS },
        'Obligate reachability probe failed — check that the server CONTAINER can reach this URL, '
          + 'not just your browser',
      );
      return { obligateUrl: cfg.url, obligateReachable: false, obligateEnabled: true };
    }
  },

  /**
   * Exchange an authorization code with Obligate for user info.
   */
  async exchangeCode(code: string, redirectUri: string): Promise<ObligateUserAssertion | null> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) {
      logger.warn('Obligate exchange failed: not configured');
      return null;
    }

    try {
      const res = await fetch(`${raw.url}/api/oauth/token/exchange`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify({ code, redirect_uri: redirectUri }),
      });

      if (!res.ok) {
        logger.warn(`Obligate exchange failed: HTTP ${res.status}`);
        return null;
      }

      const data = await res.json() as { success?: unknown; data?: unknown };
      if (!data.success || !data.data) return null;

      // Never return the remote object verbatim — see normaliseAssertion above.
      return normaliseAssertion(data.data);
    } catch (err) {
      logger.error(err, 'Obligate exchange error');
      return null;
    }
  },

  /**
   * Report a provisioned user back to Obligate.
   */
  async reportProvision(obligateUserId: number, remoteUserId: number): Promise<void> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;

    try {
      await fetch(`${raw.url}/api/apps/report-provision`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify({ obligateUserId, remoteUserId }),
      });
    } catch (err) {
      logger.error(err, 'Failed to report provision to Obligate');
    }
  },

  /**
   * NOTE - syncCapabilitySchemas() is deliberately ABSENT.
   *
   * Obliguard called POST /api/apps/sync-capability-schemas at every boot with
   * a hard-coded list ('monitor_rw', 'bans', 'whitelist'...). That endpoint does
   * not exist on Obligate, so the call always failed and was swallowed; and the
   * list it pushed is no longer ObliWAN's vocabulary anyway (see
   * @obliwan/shared/capabilities.ts). Spec 3.1 lists it among the things not to
   * carry over. The capability catalogue is served to Obligate through
   * GET /api/auth/app-info instead.
   */

  /**
   * Fetch latest preferences from Obligate and sync to local DB.
   * Throttled: once per 60s per user. Runs in background, never throws.
   */
  _prefThrottle: new Map<number, number>(),
  async syncUserPreferences(localUserId: number, obligateUserId: number): Promise<void> {
    const now = Date.now();
    if (now - (this._prefThrottle.get(localUserId) ?? 0) < 60 * 1000) return;

    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;

    try {
      const res = await fetch(`${raw.url}/api/apps/user-preferences/${obligateUserId}`, {
        headers: { 'Authorization': `Bearer ${raw.apiKey}` },
      });
      if (!res.ok) return;
      this._prefThrottle.set(localUserId, now);

      const { success, data } = await res.json() as { success: boolean; data?: {
        preferredTheme?: string; toastEnabled?: boolean; toastPosition?: string;
        preferredLanguage?: string; anonymousMode?: boolean; profilePhotoUrl?: string | null;
      } };
      if (!success || !data) return;

      // Sync language + avatar columns
      const colUpdate: Record<string, unknown> = {};
      if (data.preferredLanguage) colUpdate.preferred_language = data.preferredLanguage;
      if (data.profilePhotoUrl !== undefined) colUpdate.avatar = data.profilePhotoUrl;
      if (Object.keys(colUpdate).length > 0) {
        await db('users').where({ id: localUserId }).update(colUpdate);
      }

      // Sync UI prefs into preferences JSON
      const uiPrefs: Record<string, unknown> = {};
      if (data.preferredTheme) uiPrefs.preferredTheme = data.preferredTheme;
      if (data.toastEnabled !== undefined) uiPrefs.toastEnabled = data.toastEnabled;
      if (data.toastPosition) uiPrefs.toastPosition = data.toastPosition;
      if (data.anonymousMode !== undefined) uiPrefs.anonymousMode = data.anonymousMode;
      if (Object.keys(uiPrefs).length > 0) {
        const row = await db('users').where({ id: localUserId }).select('preferences').first() as { preferences: unknown } | undefined;
        const existing = (typeof row?.preferences === 'string' ? JSON.parse(row.preferences) : row?.preferences) ?? {};
        await db('users').where({ id: localUserId }).update({
          preferences: JSON.stringify({ ...existing, ...uiPrefs }),
        });
      }
    } catch { /* non-critical */ }
  },

  /**
   * Get the list of connected apps from Obligate (for cross-app nav buttons).
   */
  async getConnectedApps(
    obligateUserId?: number | null,
  ): Promise<Array<{ appType: string; name: string; baseUrl: string; icon: string | null; color: string | null }>> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return [];

    // Scope to the user's Obligate entitlements when we know who they are.
    // Without the userId, Obligate returns EVERY connected app, so the
    // header app switcher would show apps the user has no access to.
    const url = obligateUserId
      ? `${raw.url}/api/apps/connected?userId=${encodeURIComponent(obligateUserId)}`
      : `${raw.url}/api/apps/connected`;
    try {
      const res = await fetch(url, {
        headers: { 'Authorization': `Bearer ${raw.apiKey}` },
      });
      if (!res.ok) return [];
      const data = await res.json() as { success: boolean; data?: Array<{ appType: string; name: string; baseUrl: string; icon: string | null; color: string | null }> };
      return data.data ?? [];
    } catch {
      return [];
    }
  },
};
