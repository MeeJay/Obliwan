import { db } from '../db';
import type { AppConfig, ObligateConfig } from '@obliwan/shared';

const OBLIGATE_CONFIG_KEY     = 'obligate_config';

/**
 * SECFIX-C1 (CRITIQUE) — the Obligate integration used to carry ONE value,
 * `apiKey`, and made it play two incompatible roles:
 *
 *   1. server-to-server bearer credential — `Authorization: Bearer <apiKey>`
 *      on `/api/oauth/token/exchange`, `/api/apps/report-provision`,
 *      `/api/apps/user-preferences` and `/api/apps/connected` — and the value
 *      `requireObligateKey` compares to admit `/app-info`,
 *      `/dashboard-stats` and `/sso-user-sync`;
 *   2. the OAuth2 `client_id` pasted into the `Location` header of
 *      `GET /auth/sso-redirect`, i.e. handed to an ANONYMOUS visitor, to his
 *      browser history, to every intermediate proxy log and to Obligate's own
 *      access log.
 *
 * A `client_id` is public by definition; a bearer credential is not. The two
 * are now separate settings. `clientId` is the public application identifier
 * and is the ONLY one that may appear in a URL; `apiKey` never leaves this
 * process except inside an `Authorization` header.
 *
 * Where `clientId` comes from, in order:
 *   1. `obligate_config.clientId` in `app_config` (written through
 *      `patchObligateConfig({ clientId })`);
 *   2. the `OBLIGATE_CLIENT_ID` environment variable.
 *
 * If neither is set, `/auth/sso-redirect` refuses to build the URL rather
 * than fall back to the secret — see the long note in
 * `routes/obligateCallback.routes.ts` about what Obligate itself must ship
 * before a genuine public client_id can exist.
 */
const CLIENT_ID_ENV = 'OBLIGATE_CLIENT_ID';

function envClientId(): string | null {
  const v = (process.env[CLIENT_ID_ENV] ?? '').trim();
  return v.length > 0 ? v : null;
}

export interface ObligateBlob {
  url: string | null;
  /** Bearer credential. Server-to-server only. Never serialise this. */
  apiKey: string | null;
  /** Public application identifier. The only half that may travel in a URL. */
  clientId: string | null;
}

export const appConfigService = {
  async get(key: string): Promise<string | null> {
    const row = await db('app_config').where({ key }).first('value');
    return row?.value ?? null;
  },

  async set(key: string, value: string): Promise<void> {
    await db('app_config')
      .insert({ key, value })
      .onConflict('key')
      .merge({ value });
  },

  async getAll(): Promise<AppConfig> {
    const rows = await db('app_config').select('key', 'value');
    const map = Object.fromEntries(rows.map((r: { key: string; value: string }) => [r.key, r.value]));

    /** Extract only the URL from a JSON config blob (never expose apiKey) */
    const parseUrl = (key: string): string | null => {
      if (!map[key]) return null;
      try { return (JSON.parse(map[key]) as { url?: string }).url || null; } catch { return null; }
    };

    return {
      allow_2fa: map['allow_2fa'] === 'true',
      force_2fa: map['force_2fa'] === 'true',
      otp_smtp_server_id: map['otp_smtp_server_id'] ? parseInt(map['otp_smtp_server_id'], 10) : null,
      obligate_url:     parseUrl(OBLIGATE_CONFIG_KEY),
      obligate_enabled: map['obligate_enabled'] === 'true',
    };
  },

  // ── Obligate SSO gateway ───────────────────────────────────────────────

  async getObligateConfig(): Promise<ObligateConfig> {
    const raw = await this.get(OBLIGATE_CONFIG_KEY);
    const enabled = await this.get('obligate_enabled');
    // The env fallback counts: OBLIGATE_CLIENT_ID alone is enough to make the
    // redirect work, so reporting clientIdSet:false while it is set would send
    // an operator hunting for a problem that does not exist.
    const envCid = envClientId() !== null;
    if (!raw) return { url: null, apiKeySet: false, clientIdSet: envCid, enabled: enabled === 'true' };
    try {
      const cfg = JSON.parse(raw) as { url?: string; apiKey?: string; clientId?: string };
      return {
        url: cfg.url ?? null,
        apiKeySet: !!cfg.apiKey,
        clientIdSet: !!(cfg.clientId && cfg.clientId.trim().length > 0) || envCid,
        enabled: enabled === 'true',
      };
    } catch { return { url: null, apiKeySet: false, clientIdSet: envCid, enabled: enabled === 'true' }; }
  },

  /**
   * The stored blob, verbatim, with NO environment fallback. Used by the patch
   * path so a value that came from `OBLIGATE_CLIENT_ID` is never silently
   * frozen into the database row behind the operator's back.
   */
  async _getObligateStored(): Promise<ObligateBlob> {
    const raw = await this.get(OBLIGATE_CONFIG_KEY);
    if (!raw) return { url: null, apiKey: null, clientId: null };
    try {
      const cfg = JSON.parse(raw) as { url?: string; apiKey?: string; clientId?: string };
      const cid = typeof cfg.clientId === 'string' ? cfg.clientId.trim() : '';
      return {
        url: cfg.url ?? null,
        apiKey: cfg.apiKey ?? null,
        clientId: cid.length > 0 ? cid : null,
      };
    } catch { return { url: null, apiKey: null, clientId: null }; }
  },

  /**
   * Server-side view of the gateway settings. NEVER hand `apiKey` to a client,
   * a URL, a redirect, a log line or a template — only to an `Authorization`
   * header addressed to `url`. `clientId` is the public half and is the value
   * that belongs in an `/authorize` query string.
   */
  async getObligateRaw(): Promise<ObligateBlob> {
    const stored = await this._getObligateStored();
    return { ...stored, clientId: stored.clientId ?? envClientId() };
  },

  async patchObligateConfig(patch: {
    url?: string | null;
    apiKey?: string | null;
    clientId?: string | null;
    enabled?: boolean;
  }): Promise<ObligateConfig> {
    const existing = await this._getObligateStored();
    const patchedClientId = typeof patch.clientId === 'string' ? patch.clientId.trim() : patch.clientId;
    const merged = {
      url: 'url' in patch ? (patch.url ?? null) : existing.url,
      apiKey: ('apiKey' in patch && patch.apiKey) ? patch.apiKey : existing.apiKey,
      // Unlike `apiKey`, an empty or null `clientId` is an explicit ERASURE.
      // An operator who mistyped it must be able to clear it, and clearing it
      // fails the redirect CLOSED — it never falls back to the secret.
      clientId: 'clientId' in patch ? (patchedClientId || null) : existing.clientId,
    };
    await this.set(OBLIGATE_CONFIG_KEY, JSON.stringify(merged));
    if ('enabled' in patch) {
      await this.set('obligate_enabled', patch.enabled ? 'true' : 'false');
    }
    const enabled = await this.get('obligate_enabled');
    return {
      url: merged.url,
      apiKeySet: !!merged.apiKey,
      clientIdSet: !!(merged.clientId && merged.clientId.trim().length > 0) || envClientId() !== null,
      enabled: enabled === 'true',
    };
  },

};
