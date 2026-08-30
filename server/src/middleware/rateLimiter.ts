import rateLimit from 'express-rate-limit';
import type { Request } from 'express';

// Global API limiter.
//
// IMPORTANT: This limiter runs AFTER session middleware (see app.ts) so that
// req.session.userId is populated.
//
// AUDIT-SEC / VERIF-SECFIX — authenticated users used to be skipped ENTIRELY
// (`skip: () => !!req.session?.userId`). The stated reason was real: behind a
// reverse proxy every user shares one apparent IP, so an IP bucket would lock
// the whole customer base out at once. The conclusion was not: it left every
// id-enumeration primitive in the product free in volume — `GET /api/groups/1`
// through `/9999`, `GET /api/users/:id`, `DELETE /api/teams/1/permissions/:n`
// — and a 404/403 sweep over the whole id space costs nothing when nothing
// counts it.
//
// The fix keeps the shared-IP argument intact by changing the BUCKET rather
// than removing the limit: an authenticated request is keyed on its user id, so
// one user's traffic can never lock out another, and the ceiling is set high
// enough that the dashboard's normal chatter never reaches it.
//
//   unauthenticated : 500 requests / 5 min, keyed on the IP
//   authenticated   : AUTHENTICATED_MAX / 5 min, keyed on the user id
//
// 1500 per five minutes is five requests per second sustained, per user — far
// above an operator clicking through screens (the heaviest screen in the
// product fires a few dozen calls), and far below what a scan of a five-digit
// id space needs.
const WINDOW_MS = 5 * 60 * 1000;
const ANONYMOUS_MAX = 500;
const AUTHENTICATED_MAX = 1500;

export const apiLimiter = rateLimit({
  windowMs: WINDOW_MS,
  limit: (req: Request) => (req.session?.userId ? AUTHENTICATED_MAX : ANONYMOUS_MAX),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    // Per-user bucket for authenticated traffic: a shared proxy IP no longer
    // makes one user's burst everybody's problem, which is what motivated the
    // blanket exemption in the first place.
    const userId = req.session?.userId;
    return userId ? `u:${userId}` : `ip:${req.ip ?? 'unknown'}`;
  },
  skip: (req: Request) =>
    // ── Public informational endpoints ─────────────────────────────────────
    // Health check is polled by the login page to show the server version;
    // rate-limiting it would block the login page's UI, not improve security.
    req.path === '/health' ||
    // Auth state probe — returns 401 for unauthenticated callers, no info leak,
    // and the client polls it to detect session expiry.
    req.path === '/api/auth/me' ||
    // ── Machine-to-machine endpoints ───────────────────────────────────────
    // All /api/agent/* paths are API-key authenticated (X-API-Key header).
    // Rate-limiting them would cause false positives when agents post metrics,
    // version checks, download updates, and serve installer scripts at their
    // natural cadence. Security is provided by the API key itself.
    req.path.startsWith('/api/agent/') ||
    // Passive heartbeats (token authenticated, triggered by external systems).
    req.path.startsWith('/api/heartbeat/'),
  message: {
    success: false,
    error: 'Too many requests, please try again later',
  },
});

// Login-specific limiter — stricter window to slow down brute-force attempts.
//
// Key = IP + username so that:
//   a) A shared proxy IP does NOT cause all users to share one rate-limit bucket.
//      User A hitting the limit doesn't lock out User B.
//   b) An attacker cannot brute-force a single account faster than the limit allows.
//   c) req.body is available here because authLimiter is applied per-route in
//      auth.routes.ts, after express.json() has already run globally.
//
// skipSuccessfulRequests: successful logins (HTTP 200) do not count toward the
// limit, so a legitimate user who eventually gets their password right is not
// penalised for earlier typos.  Only failed attempts (4xx) accumulate.
export const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes — resets quickly after an accidental lock-out
  max: 20,                  // 20 failed attempts per 5-minute window per IP+username
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ip       = req.ip ?? 'unknown';
    const username = (req.body as { username?: string })?.username?.toLowerCase() ?? '';
    // Combine both so shared-IP users each get their own bucket per account.
    return `${ip}:${username}`;
  },
  message: {
    success: false,
    error: 'Too many login attempts, please try again in 5 minutes',
  },
});

/**
 * Second-factor limiter, for `POST /api/profile/2fa/verify` and
 * `/2fa/resend-email`.
 *
 * VERIF-SECFIX R6 — `authLimiter` was doing nothing on these two routes.
 * Its key is `${ip}:${req.body.username}` and neither route carries a
 * `username`, so the key degenerated to `ip:` — one bucket shared by every
 * account behind a given address, defeated by rotating the address.
 *
 * The key here is the account under attack (`pendingMfaUserId`, which the
 * attacker cannot choose without first passing the password step), so the
 * budget follows the target instead of the source. `skipSuccessfulRequests`
 * keeps a legitimate user who mistypes once from being penalised.
 */
export const mfaLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    const pending = req.session?.pendingMfaUserId;
    // No pending login: fall back to the address, so an unauthenticated caller
    // cannot hammer the route to probe it either.
    return pending ? `mfa:${pending}` : `mfa-ip:${req.ip ?? 'unknown'}`;
  },
  message: {
    success: false,
    error: 'Too many verification attempts, please try again in 5 minutes',
  },
});
