import { Server as SocketIOServer } from 'socket.io';
import type { Server as HttpServer } from 'http';
import type { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import { CLIENT_EVENTS, socketRooms } from '@obliwan/shared';
import { sessionMiddleware } from './app';
import { config } from './config';
import { logger } from './utils/logger';
import { authService } from './services/auth.service';
import { db } from './db';
import { setFleetIO } from './services/fleet/fleetEvents';

/**
 * Adapts an Express middleware to Socket.io's `io.use()` signature.
 *
 * The handshake is a real HTTP request, so express-session can read its cookie,
 * look the session up in Postgres and hang `req.session` on it exactly as it
 * would for `/api/...`. Socket.io only ever gives us `socket.request`, hence the
 * casts — they are shape assertions, not a bypass of anything.
 */
function wrap(mw: (req: Request, res: Response, next: NextFunction) => void) {
  return (socket: { request: unknown }, next: (err?: Error) => void): void => {
    mw(socket.request as Request, {} as Response, next as NextFunction);
  };
}

export function createSocketServer(httpServer: HttpServer): SocketIOServer {
  const io = new SocketIOServer(httpServer, {
    cors: {
      // Reflect the request origin so any deployment URL works without
      // reconfiguring CLIENT_ORIGIN. Authorisation is enforced by the session
      // middleware below, never by the CORS origin list.
      origin: true,
      credentials: true,
    },
    transports: ['websocket', 'polling'],
  });

  // Risk R14 — Obliguard authenticated sockets from `handshake.auth.userId`,
  // a value the CLIENT chooses. Anyone who could open a WebSocket could claim
  // to be user 1 and join the admin rooms. We now run the SAME session
  // middleware the HTTP API uses and take the identity from the server-side
  // session, so a socket can only ever be as privileged as the cookie it
  // carries. `handshake.auth` is no longer read for identity at all.
  io.use(wrap(cookieParser()));
  io.use(wrap(sessionMiddleware as unknown as (req: Request, res: Response, next: NextFunction) => void));

  io.use(async (socket, next) => {
    try {
      const session = (socket.request as Request).session;
      const userId = session?.userId;

      if (!userId) {
        next(new Error('Authentication required'));
        return;
      }

      const user = await authService.getUserById(userId);
      if (!user || !user.isActive) {
        next(new Error('Invalid user'));
        return;
      }

      // The tenant is taken from the session too. A client that wants to switch
      // tenant does it through POST /api/tenant (which re-writes the session)
      // and then reconnects — it cannot pick a tenant from the handshake.
      //
      // RISK R1 — there used to be a `?? 1` here. It was declared "dead" on the
      // grounds that a session without `currentTenantId` would fail the
      // membership check below; it did not, because that check exempts platform
      // admins. A platform admin with NO `user_tenants` row therefore landed in
      // tenant 1 and joined its rooms, while every HTTP route answered 403.
      // There is no defensible default tenant: refuse instead of guessing.
      // This mirrors `requireTenant` exactly (middleware/tenant.ts) — a named
      // tenant is required of everyone, membership is required of everyone but
      // a platform admin.
      const tenantId = session.currentTenantId;
      if (!tenantId) {
        next(new Error('No tenant granted for this account'));
        return;
      }

      const membership = await db('user_tenants')
        .where({ user_id: userId, tenant_id: tenantId })
        .first();
      if (!membership && user.role !== 'admin') {
        next(new Error('Tenant access denied'));
        return;
      }

      socket.data.user = user;
      socket.data.tenantId = tenantId;
      next();
    } catch (err) {
      logger.error(err, 'Socket authentication failed');
      next(new Error('Authentication failed'));
    }
  });

  io.on('connection', (socket) => {
    const user = socket.data.user;
    const tenantId: number = socket.data.tenantId;
    logger.info(`Socket connected: ${user.username} (id: ${user.id}, tenant: ${tenantId})`);

    // ── Room convention ───────────────────────────────────────────────────
    // Exactly three shapes exist, and every one of them names a tenant or a
    // single user:
    //
    //   tenant:{id}          every member of that tenant
    //   tenant:{id}:admin    the admins POSITIONED ON that tenant
    //   user:{id}            one account
    //
    // The global `role:admin` room is GONE. It was tenant-blind: it put every
    // platform admin in one bucket regardless of the tenant they were working
    // on, so the eight group/settings emits that targeted it delivered one
    // customer's group names and setting values to an admin sitting on
    // another customer. A broadcast room that outlives the tenant scope is a
    // cross-tenant channel by construction, whatever the emitter intended.
    //
    // `general` went with it: nothing ever emitted to it, and a room nobody
    // can name a tenant for is the next `role:admin` waiting to be reused.
    socket.join(`user:${user.id}`);
    socket.join(socketRooms.tenant(tenantId));
    if (user.role === 'admin') {
      socket.join(`tenant:${tenantId}:admin`);
    }

    // Notification rooms for EVERY tenant this user can access, so a cross-tenant
    // live alert reaches them even while they are looking at another tenant.
    db('user_tenants')
      .where('user_id', user.id)
      .pluck('tenant_id')
      .then((tenantIds: number[]) => {
        for (const tid of tenantIds) {
          socket.join(socketRooms.tenantNotifications(tid));
        }
      })
      .catch((err: unknown) => logger.error(err, 'Failed to join notification rooms'));

    // ── Per-device subscription (M2) ──────────────────────────────────────
    // A device detail page asks for `device:{id}` so it gets presence, verdict
    // and transport-state events without every other client paying for them.
    //
    // The room name is derived from a number the CLIENT sent, so membership is
    // checked against the socket's tenant before joining — otherwise anyone
    // could subscribe to `device:1` and watch another customer's tunnel flap.
    // This is the same lesson as R14: never trust the handshake, and never
    // trust an id that arrived over the wire either.
    socket.on(CLIENT_EVENTS.DEVICE_SUBSCRIBE, async (raw: unknown) => {
      const deviceId = Number(raw);
      if (!Number.isInteger(deviceId) || deviceId <= 0) return;
      try {
        const owned = await db('devices')
          .where({ id: deviceId, tenant_id: tenantId })
          .first('id');
        if (!owned) {
          logger.warn(
            { userId: user.id, tenantId, deviceId },
            'Refused a device subscription outside the socket tenant',
          );
          return;
        }
        socket.join(socketRooms.device(deviceId));
      } catch (err) {
        logger.error({ err, deviceId }, 'Device subscription failed');
      }
    });

    socket.on(CLIENT_EVENTS.DEVICE_UNSUBSCRIBE, (raw: unknown) => {
      const deviceId = Number(raw);
      if (!Number.isInteger(deviceId) || deviceId <= 0) return;
      socket.leave(socketRooms.device(deviceId));
    });

    socket.on('disconnect', () => {
      logger.debug(`Socket disconnected: ${user.username}`);
    });
  });

  if (!config.servesHttp) {
    logger.info({ role: config.role }, 'Socket.io created on a non-web role — no client will reach it');
  }

  // The fleet services emit `wan:*` through `services/fleet/fleetEvents`, which
  // holds nothing but this handle. They never import THIS module: doing so
  // would close a require cycle (app -> routes -> controller -> service ->
  // socket -> app) and hand somebody a half-initialised module under CommonJS.
  setFleetIO(io);

  // The fleet runtime (presence, the RouterOS pool) is NOT armed here any more.
  // It used to be, for want of write access to `index.ts`; arming a background
  // duty is a startup act and it now happens in the startup sequence, right
  // after this function returns and the `io` handle above has been published.
  return io;
}
