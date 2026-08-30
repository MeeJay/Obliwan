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
 * AUDIT-SEC #5, the reserve the report left open and no pass lifted.
 *
 * `secure: config.forceHttps` made the Secure attribute depend on an OPT-IN
 * environment variable (`FORCE_HTTPS=true`). Its default is false, so the
 * default production deployment shipped a seven-day session cookie WITHOUT
 * Secure — i.e. a cookie the browser will put on a plain-HTTP request. Behind
 * the reverse proxy this product expects, that is one downgraded request (a
 * stray `http://` link, a captive portal, an attacker-injected image) away from
 * handing the session to anyone on the path, and TLS on the front door does not
 * help: the browser sends it before the proxy can redirect.
 *
 * A security flag must not be something the operator has to remember to switch
 * on. It is derived from the environment instead: OFF in development (where the
 * dev server is `http://localhost:5173` -> `http://localhost:3001` and a Secure
 * cookie would simply never be stored, breaking every local login), ON
 * everywhere else. `FORCE_HTTPS` is kept in the OR so that anyone who set it
 * explicitly — including in development, deliberately, behind a local TLS
 * proxy — keeps the behaviour they asked for.
 *
 * The consequence to be aware of before deploying: a production instance served
 * over plain HTTP no longer holds a session. That is the intended reading of
 * "fail closed", and the fix is TLS, not a flag.
 */
const cookieSecure = !config.isDev || config.forceHttps;

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
    'Session cookie is NOT marked Secure (NODE_ENV=development). This is correct for local ' +
      'HTTP development and MUST NOT be the case in production — set NODE_ENV=production.',
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
