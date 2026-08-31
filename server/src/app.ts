import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import path from 'path';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

// Read server version from package.json at startup.
// process.cwd() is the server directory in both dev (npx tsx) and Docker (WORKDIR /app/server).
let serverVersion = 'dev';
try {
  const pkg = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf-8')) as { version: string };
  serverVersion = pkg.version;
} catch { /* ignore */ }
import { config } from './config';
import { errorHandler } from './middleware/errorHandler';
import { apiLimiter } from './middleware/rateLimiter';
import { routes } from './routes';
import obligateCallbackRoutes from './routes/obligateCallback.routes';
import acsRoutes from './routes/acs.routes';
import { logger } from './utils/logger';

const PgSession = connectPgSimple(session);

/**
 * Session middleware, built ONCE at module scope.
 *
 * It is exported because Socket.io reuses this exact instance to authenticate
 * handshakes (see socket.ts, risk R14): the WebSocket upgrade carries the same
 * cookie as an HTTP request, so running the same middleware over it yields the
 * same server-side session — instead of trusting a userId the client typed
 * into `handshake.auth`.
 */
const sessionStore = new PgSession({
  conString: config.databaseUrl,
  tableName: 'session',
  createTableIfMissing: false,
});
sessionStore.on('error', (err: Error) => {
  logger.error(err, 'Session store error — sessions may fail until DB connection recovers');
});

/**
 * ALIGNED WITH THE SUITE — and this is a REVERSAL, stated as one.
 *
 * ┌─ WHAT WAS CHANGED AND WHY IT WAS WRONG ──────────────────────────────────┐
 * │ AUDIT-SEC #5 derived this flag from the environment instead of reading    │
 * │ `FORCE_HTTPS`: `!config.isDev || config.forceHttps`, so every production  │
 * │ deployment got a `Secure` cookie whether or not it was told it had TLS.   │
 * │ The reasoning was sound in the abstract — a security flag should not      │
 * │ depend on somebody remembering an env var.                                │
 * │                                                                          │
 * │ It broke SSO in the real deployment, and the failure was invisible:       │
 * │ `express-session` REFUSES to emit a `Secure` cookie when it does not      │
 * │ consider the connection secure. Obligate authenticated the user, the      │
 * │ callback created the session, the redirect landed — and every request     │
 * │ after it answered 401, with nothing in any log saying why. "Authentication│
 * │ is broken" was the symptom of a cookie that was never sent.               │
 * │                                                                          │
 * │ Obliguard and Obliance both ship `secure: config.forceHttps` and both     │
 * │ work. A lone hardening that diverges from the suite, is not exercised by  │
 * │ the suite's deployments, and fails closed in a way nobody can diagnose is │
 * │ not a hardening — it is a local opinion with a production cost. So it     │
 * │ goes back to the suite's shape.                                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The concern behind the audit is real and NOT dismissed: a seven-day session
 * cookie without `Secure` is one downgraded request away from being handed to
 * whoever is on the path. It is answered where it belongs — `FORCE_HTTPS=true`
 * belongs in every `.env` served over TLS, and the startup log below says so
 * out loud on every boot that omits it, instead of silently breaking login.
 */
const cookieSecure = config.forceHttps;

export const sessionMiddleware = session({
  store: sessionStore,
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: cookieSecure,
    httpOnly: true,
    maxAge: config.sessionMaxAge,
    sameSite: 'lax',
  },
});

if (!cookieSecure) {
  logger.warn(
    { forceHttps: false, nodeEnv: config.nodeEnv },
    'Session cookie is NOT marked Secure. Correct for local HTTP development. In production '
      + 'behind TLS, set FORCE_HTTPS=true — without it a seven-day session cookie will travel on '
      + 'any downgraded request. It is NOT enabled automatically: express-session silently '
      + 'refuses to send a Secure cookie when it does not see the connection as secure, and that '
      + 'presents as "login works, then everything answers 401".',
  );
}

export function createApp() {
  const app = express();

  // Trust the first reverse proxy hop so req.ip uses X-Forwarded-For.
  // Required for accurate rate limiting when behind Nginx / Nginx Proxy Manager.
  app.set('trust proxy', 1);

  // Security headers
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "blob:"],
          connectSrc: ["'self'", "wss:", "ws:"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
        },
      },
      hsts: { maxAge: 31536000, includeSubDomains: true },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    }),
  );
  app.use(
    cors({
      origin: config.clientOrigin,
      credentials: true,
    }),
  );

  // Parsing — cookieParser must come before session (session reads the cookie).
  app.use(express.json({ limit: '1mb' }));
  app.use(cookieParser());

  // Sessions — stored in PostgreSQL via connect-pg-simple (see sessionMiddleware
  // above). MUST be set up before apiLimiter so that req.session.userId is
  // available in the limiter's skip() function: authenticated users are excluded
  // from rate limiting to avoid shared-IP false positives behind a proxy.
  app.use(sessionMiddleware);

  // ┌─ THE SILENT 401 FACTORY ────────────────────────────────────────────────┐
  // │ With NODE_ENV=production the session cookie is always `Secure`. A       │
  // │ browser reaching this server over plain HTTP DISCARDS it without a      │
  // │ word: the login succeeds, the redirect lands, and every request after   │
  // │ it answers 401. Nothing in the server logs, nothing in the console —    │
  // │ the failure looks like broken authentication when it is a missing `s`   │
  // │ in a URL.                                                               │
  // │                                                                        │
  // │ It cannot be detected at startup: the process has no idea how it will   │
  // │ be reached. So it is detected on the first request that matters, and    │
  // │ said once rather than on every hit — an operator needs the sentence,    │
  // │ not a flood.                                                            │
  // │                                                                        │
  // │ This does NOT relax the cookie. The fix is TLS (Oblihub terminates it   │
  // │ for the whole suite), or FORCE_HTTPS if something else already does.    │
  // └────────────────────────────────────────────────────────────────────────┘
  if (cookieSecure) {
    let warned = false;
    app.use((req, _res, next) => {
      if (!warned && req.protocol !== 'https' && req.headers['x-forwarded-proto'] !== 'https') {
        warned = true;
        logger.error(
          {
            host: req.headers.host,
            path: req.path,
            xForwardedProto: req.headers['x-forwarded-proto'] ?? null,
          },
          'THE SESSION COOKIE WILL NOT BE STORED. This request arrived over plain HTTP while the '
            + 'cookie is marked Secure (NODE_ENV=production), so the browser silently drops it and '
            + 'every authenticated call — /api/auth/me included — answers 401. Serve this instance '
            + 'over TLS (Oblihub does it for the suite). If TLS is terminated upstream, that hop '
            + 'must forward X-Forwarded-Proto: https.',
        );
      }
      next();
    });
  }

  // Rate limiting — runs after session so authenticated users can be skipped.
  // Only unauthenticated endpoints (login page, public health, etc.) are limited.
  app.use(apiLimiter);

  // Obligate SSO callback — mounted at /auth (OUTSIDE /api) so Obligate can
  // redirect the browser straight here after authentication.
  app.use('/auth', obligateCallbackRoutes);

  // ACS admin API (M10).
  //
  // MOUNTED HERE AND NOT IN `routes/index.ts`, and that is a deviation worth
  // naming: `routes/index.ts` is off limits to the milestone that wrote this,
  // and a router file with no mount is dead code — the exact defect the last
  // audit found three times. The precedent is `obligateCallbackRoutes`, two
  // lines below, which is also mounted straight onto the app.
  //
  // It MUST come before `app.use('/api', routes)` is irrelevant (the prefixes
  // do not overlap) but it MUST come before the production SPA catch-all
  // further down, which would otherwise answer `/api/acs/*` with index.html.
  // Whoever consolidates the route table later: move this line into
  // `routes/index.ts` under `tenantRouter` and delete the `requireAuth` /
  // `requireTenant` calls at the top of `acs.routes.ts`.
  app.use('/api/acs', acsRoutes);

  // API routes
  app.use('/api', routes);

  // Health check (public — also used by login page to display server version)
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', version: serverVersion, timestamp: new Date().toISOString() });
  });

  // An unmatched /api path is a 404 and must never reach the SPA fallback below.
  //
  // Without this, `GET /api/sla` — a router that has no route at its own root,
  // like /changes and /variables — fell through to the catch-all, which tried to
  // sendFile a client build the SERVER IMAGE DOES NOT CONTAIN (nginx serves the
  // SPA in the shipped topology). Every unmatched API path answered 500 with a
  // container filesystem path in the log instead of a plain 404. Found by
  // actually running the compose stack, never by a test.
  app.use('/api', (_req, res) => {
    res.status(404).json({ success: false, error: 'No such API route' });
  });

  // Serve the static client build — only when this process actually has one.
  //
  // In the compose topology it does NOT: `client/dist` lives in the nginx image
  // and the server image never copies it. Registering a fallback that cannot
  // deliver turns every stray path into a 500. Checked once at startup rather
  // than per request, and its absence is logged as the normal state it is.
  if (!config.isDev) {
    const clientDist = path.join(__dirname, '../../client/dist');
    if (existsSync(path.join(clientDist, 'index.html'))) {
      app.use(express.static(clientDist));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(clientDist, 'index.html'));
      });
    } else {
      logger.info(
        { clientDist },
        'No client build in this image — the SPA is served by the client container. '
          + 'Non-API paths will answer 404 here, which is what nginx expects.',
      );
    }
  }

  // Error handling
  app.use(errorHandler);

  return app;
}
