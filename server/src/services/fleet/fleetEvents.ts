/**
 * ObliWAN — the `wan:*` emitter.
 *
 * A deliberately tiny module with no dependency but `@obliwan/shared` and the
 * logger. `socket.ts` pushes the live `io` in at boot; every fleet service
 * imports THIS, never `socket.ts`. Importing `socket.ts` from a service would
 * close a require cycle (app -> routes -> controller -> service -> socket ->
 * app) and, under CommonJS, hand somebody a half-initialised module.
 *
 * Emitting is best-effort by construction: on a `worker` replica there is no
 * `io` at all, and presence must keep writing history whether or not anyone is
 * watching. A missing socket server is therefore a no-op, never an error.
 */

import type { Server as SocketIOServer } from 'socket.io';
import { SOCKET_EVENTS, socketRooms, type SitePresenceEvent } from '@obliwan/shared';
import { logger } from '../../utils/logger';

let io: SocketIOServer | null = null;

/** Called once from `socket.ts` after the Socket.io server is created. */
export function setFleetIO(server: SocketIOServer | null): void {
  io = server;
}

export function hasFleetIO(): boolean {
  return io !== null;
}

/** Emit to everyone currently looking at this tenant. */
export function emitToTenant(tenantId: number, event: string, payload: unknown): void {
  if (!io) return;
  try {
    io.to(socketRooms.tenant(tenantId)).emit(event, payload);
  } catch (err) {
    logger.warn({ err, event }, 'wan:* emit failed');
  }
}

/** Emit to the subscribers of one device detail page. */
export function emitToDevice(deviceId: number, event: string, payload: unknown): void {
  if (!io) return;
  try {
    io.to(socketRooms.device(deviceId)).emit(event, payload);
  } catch (err) {
    logger.warn({ err, event }, 'wan:* device emit failed');
  }
}

/**
 * Discoveries carry NO tenant of their own (migration 002: quarantine is
 * pre-tenant, by design — risk R4), so they must not go to a tenant-wide room:
 * a PPP username seen on a concentrator is not something every member of the
 * tenant is entitled to review.
 *
 * They do, however, have a tenant: the CONCENTRATOR's. That is the same
 * scoping the discoveries controller uses for its HTTP reads, and it is the
 * one this emitter uses. The global `role:admin` room this function used to
 * target was tenant-blind — it delivered one customer's PPP usernames to any
 * platform admin, whatever tenant they were positioned on. It no longer
 * exists; `tenant:{id}:admin` replaces it everywhere.
 */
export function emitToTenantAdmins(tenantId: number, event: string, payload: unknown): void {
  if (!io) return;
  try {
    io.to(`tenant:${tenantId}:admin`).emit(event, payload);
  } catch (err) {
    logger.warn({ err, event }, 'wan:* admin emit failed');
  }
}

/**
 * `wan:site:presence` — the M2 acceptance event.
 *
 * Sent to the tenant room (the fleet tree pastille) AND to the device room (the
 * detail page), because those are two different audiences with two different
 * subscription lifetimes. `wan:device:presence` carries the same payload for
 * consumers that only care about one box.
 */
export function emitSitePresence(tenantId: number, event: SitePresenceEvent): void {
  emitToTenant(tenantId, SOCKET_EVENTS.SITE_PRESENCE, event);
  if (event.deviceId !== null) {
    emitToDevice(event.deviceId, SOCKET_EVENTS.DEVICE_PRESENCE, event);
  }
}
