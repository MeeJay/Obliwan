import './env';

/**
 * Execution role — arbitrage A5.
 *   web    : serves HTTP + Socket.io only. Never runs pollers or job runners.
 *   worker : background duties only (pollers, job queue, drift runs). No HTTP
 *            listener beyond /health.
 *   all    : single process doing both. The default, and what `docker compose
 *            up` gives you.
 *
 * Several `web` replicas may run side by side; the background duties are held
 * by ONE leader elected through a PostgreSQL advisory lock (leaderElection.ts).
 */
export const OBLIWAN_ROLES = ['web', 'worker', 'all'] as const;
export type ObliwanRole = (typeof OBLIWAN_ROLES)[number];

function readRole(): ObliwanRole {
  const raw = (process.env.OBLIWAN_ROLE || 'all').trim().toLowerCase();
  if (!(OBLIWAN_ROLES as readonly string[]).includes(raw)) {
    // Refuse to start rather than silently degrade: a typo'd OBLIWAN_ROLE that
    // fell back to 'all' would give two leaders pushing config to the same
    // fleet, which is exactly the failure mode arbitrage A5 exists to prevent.
    throw new Error(
      `Invalid OBLIWAN_ROLE="${process.env.OBLIWAN_ROLE}". ` +
        `Expected one of: ${OBLIWAN_ROLES.join(' | ')}. ` +
        'Fix the value in your .env (see .env.example) and restart.',
    );
  }
  return raw as ObliwanRole;
}

/**
 * Dedicated credential-vault key — arbitrage A3 / risk R8.
 *
 * NOT USED YET: the vault itself (`secretVault.service.ts`, the `*_enc` columns
 * and the `key_version` column) arrives with migration 002 at milestone M2. It
 * is read and validated HERE, from day one, so that an operator discovers a
 * missing or malformed key at first boot — not on the day the first device
 * credential fails to decrypt.
 *
 * Expected format: 64 hex characters (32 bytes). Generate with
 * `openssl rand -hex 32`.
 */
function readEncryptionKey(): { raw: string | null; valid: boolean } {
  const raw = (process.env.OBLIWAN_ENCRYPTION_KEY || '').trim();
  if (!raw) return { raw: null, valid: false };
  return { raw, valid: /^[0-9a-fA-F]{64}$/.test(raw) };
}

const role = readRole();
const encryptionKey = readEncryptionKey();

export const config = {
  port: parseInt(process.env.PORT || '3001', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  isDev: (process.env.NODE_ENV || 'development') === 'development',

  // Execution role (A5)
  role,
  /** True when this process serves HTTP / Socket.io. */
  servesHttp: role === 'web' || role === 'all',
  /** True when this process is ALLOWED to run background duties — it still has
   *  to win the leader election before it actually does any. */
  runsBackground: role === 'worker' || role === 'all',

  // Database
  databaseUrl: process.env.DATABASE_URL || 'postgres://obliwan:changeme@localhost:5432/obliwan',

  // Session
  sessionSecret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  sessionMaxAge: 7 * 24 * 60 * 60 * 1000, // 7 days

  // Credential vault (A3) — see readEncryptionKey() above.
  encryptionKey: encryptionKey.raw,
  encryptionKeyValid: encryptionKey.valid,

  // CORS
  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:5173',

  // HTTPS — set to "true" if behind an HTTPS reverse proxy
  forceHttps: process.env.FORCE_HTTPS === 'true',

  // App name (used as prefix in SMS/push notifications)
  appName: process.env.APP_NAME || 'ObliWAN',

  // Default admin
  defaultAdminUsername: process.env.DEFAULT_ADMIN_USERNAME || 'admin',
  defaultAdminPassword: process.env.DEFAULT_ADMIN_PASSWORD || 'admin123',

  // 2FA bypass — set DISABLE_2FA_FORCE=true to skip forced 2FA requirement
  disable2faForce: process.env.DISABLE_2FA_FORCE === 'true',

  // App URL — used in password reset emails
  appUrl: process.env.APP_URL || 'http://localhost:5173',

  /**
   * ACS TR-069 / CWMP (M10 — feature C10, arbitrage A1).
   *
   * ┌─ WHY THESE PORTS ARE NOT `config.port` ──────────────────────────────┐
   * │ The ACS is a SEPARATE Express app on a SEPARATE listener (§6.2), and  │
   * │ it is the one thing in the suite that is not behind the client's      │
   * │ nginx. Two reasons, both structural:                                  │
   * │  - HTTP Digest. A reverse proxy that touches the request line or the  │
   * │    URI invalidates HA2 = MD5(method:uri) and every CPE fails to       │
   * │    authenticate, with no error anyone can read.                       │
   * │  - Long sessions. A CWMP session is a dozen POSTs over up to a few    │
   * │    minutes, and proxy buffering plus idle timeouts cut it in the      │
   * │    middle, which the CPE reports as a transfer failure days later.    │
   * │                                                                       │
   * │ 7547 and 7548 are ALREADY published by the compose files from M1 and  │
   * │ nothing has been listening on them until now.                         │
   * └───────────────────────────────────────────────────────────────────────┘
   */
  cwmp: {
    /** Master switch. On by default: the ports are published, and a published
     *  port with nothing behind it is worse than an open one — it answers
     *  RST and the CPE logs "ACS unreachable" forever. */
    enabled: process.env.CWMP_ENABLED !== 'false',
    port: parseInt(process.env.CWMP_PORT || '7547', 10),
    bind: process.env.CWMP_BIND || '0.0.0.0',

    /**
     * TLS listener for CPEs provisioned with an `https://` ACS URL.
     * OPTIONAL and off unless a certificate is provided: a TLS server with a
     * self-signed certificate is worse than no TLS server at all, because a
     * CPE that cannot validate it retries forever instead of falling back.
     */
    tlsPort: parseInt(process.env.CWMP_TLS_PORT || '7548', 10),
    tlsCertPath: process.env.CWMP_TLS_CERT || '',
    tlsKeyPath: process.env.CWMP_TLS_KEY || '',

    /**
     * Public base URL the CPE is told to fetch firmware from.
     *
     * It is a SEPARATE knob from `appUrl` because the CPE reaches the ACS from
     * the customer's line, not from the operator's browser, and the two
     * addresses are almost never the same. Empty means "derive it from the
     * Host header the CPE used", which is right in a single-homed deployment
     * and wrong the moment there is a NAT in front — hence the explicit knob.
     */
    publicBaseUrl: process.env.CWMP_PUBLIC_BASE_URL || '',

    /** Largest envelope the listener accepts. A GetParameterValuesResponse on
     *  a full TR-181 subtree is genuinely large; 8 MB is roughly ten times the
     *  worst real one and still small enough to bound memory at 300 sessions. */
    maxBodyBytes: parseInt(process.env.CWMP_MAX_BODY_BYTES || String(8 * 1024 * 1024), 10),

    /** A session with no POST for this long is abandoned and its in-flight
     *  task is returned to the queue. CPEs disappear mid-session constantly
     *  (the line drops, the box reboots); without a reaper each one would pin
     *  a task in `sent` forever. */
    sessionIdleSeconds: parseInt(process.env.CWMP_SESSION_IDLE_SECONDS || '180', 10),

    /** How long a download URL token stays fetchable. */
    downloadTokenTtlSeconds: parseInt(process.env.CWMP_DOWNLOAD_TTL_SECONDS || '3600', 10),

    /** Where firmware images and vendor config files live on disk. */
    fileStorageDir: process.env.CWMP_FILE_DIR || './data/cwmp-files',

    /** What a "please call back sooner" request lowers the interval to. This is
     *  the ONLY refresh mechanism the product has, and the UI says so
     *  (`CWMP_NO_CONNECTION_REQUEST_EXPLANATION`). */
    refreshIntervalSeconds: parseInt(process.env.CWMP_REFRESH_INTERVAL_SECONDS || '60', 10),
  },
};

/**
 * Startup validation. Called once from index.ts BEFORE anything connects.
 * Throws on a fatal misconfiguration; returns the non-fatal warnings so the
 * caller can log them through pino rather than console.
 */
export function validateConfig(): string[] {
  const warnings: string[] = [];

  // Every placeholder this repository ships, not just the one the code happens to
  // default to. `docker-compose.yml` defaults to `change-this-in-production` and
  // `.env.example` to `change-this-to-a-random-secret`: a `docker compose up` with
  // no `.env` therefore started in PRODUCTION with a session secret printed in a
  // public repository, and this guard — which exists for exactly that case —
  // said nothing because it compared against a single literal.
  //
  // The length floor is the second half: a placeholder nobody thought to list is
  // still almost always short.
  const SHIPPED_PLACEHOLDERS = new Set([
    'dev-secret-change-me',
    'dev-secret',
    'change-this-in-production',
    'change-this-to-a-random-secret',
    'changeme',
    'secret',
  ]);
  const MIN_SESSION_SECRET_LENGTH = 32;

  if (!config.isDev) {
    const s = config.sessionSecret.trim();
    if (SHIPPED_PLACEHOLDERS.has(s.toLowerCase())) {
      throw new Error(
        `SESSION_SECRET is still the placeholder "${s}" shipped in this repository. `
          + 'Anyone can forge a session cookie against it. Generate one with: '
          + 'openssl rand -hex 32',
      );
    }
    if (s.length < MIN_SESSION_SECRET_LENGTH) {
      throw new Error(
        `SESSION_SECRET is ${s.length} characters; at least ${MIN_SESSION_SECRET_LENGTH} are `
          + 'required outside development. Generate one with: openssl rand -hex 32',
      );
    }
  }

  if (!config.encryptionKey) {
    warnings.push(
      'OBLIWAN_ENCRYPTION_KEY is not set. No device credential can be stored ' +
        'until it is (milestone M2). Generate one with: openssl rand -hex 32',
    );
  } else if (!config.encryptionKeyValid) {
    // Not fatal in M1 (nothing is encrypted yet) but it WILL be at M2, and a
    // silent warning now is far cheaper than an unreadable vault later.
    warnings.push(
      'OBLIWAN_ENCRYPTION_KEY is set but is not 64 hex characters (32 bytes). ' +
        'It will be rejected when the credential vault lands in M2. ' +
        'Generate a valid one with: openssl rand -hex 32',
    );
  }

  return warnings;
}
