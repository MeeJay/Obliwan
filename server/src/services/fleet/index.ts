/**
 * ObliWAN — fleet runtime.
 *
 * Barrel plus the leadership gate. Presence is the only background duty M2
 * introduces, and it MUST run on exactly one process (arbitrage A5): two
 * replicas would each open a `/ppp/active/listen` on the same concentrator and
 * each write session history, doubling every flap and racing every close.
 *
 * The gate is `leaderElection.onChange()`, which fires immediately with the
 * current state — so a process that is already the leader when this runs starts
 * presence at once, and a `web` replica (which never campaigns) simply never
 * gets a `true`.
 *
 * WHERE THIS IS CALLED FROM
 * `server/src/index.ts`, step 6 of the startup sequence: after the migrations,
 * after the vault guard (`assertVaultUsable`), and after `createSocketServer()`
 * has published the `io` handle that presence emits through. It used to be
 * called from `socket.ts` for want of write access to `index.ts`; that was a
 * workaround, and it is gone. The call is idempotent and safe on every role.
 *
 * `stopFleetRuntime()` is wired to the same file's graceful shutdown.
 *
 * TWO HALVES OF THE PRESENCE LIFECYCLE, AND WHY THE OTHER ONE IS NOT HERE
 * (audit M2/M3, finding 4)
 *
 * This file owns the COARSE half: leadership changes, which start or stop the
 * whole set of monitors at once. It cannot own the fine half — "this
 * concentrator was just declared / disabled / deleted / re-credentialled" —
 * because that half has to fire on the write itself, and the writes live in
 * `device.service.ts`. Until this audit nobody owned it at all: `watch()` and
 * `unwatch()` had no caller outside `startAll()`/`stopAll()` and the self-test,
 * so a concentrator created through the API was invisible to presence until the
 * next restart, and a deleted one left a monitor retrying forever.
 *
 * `deviceService.syncConcentratorPresence()` is that half. It is re-exported
 * here so the runtime's two entry points read as one API, and it is gated on
 * `leaderElection.isLeader()` for the same reason `startAll()` is: two replicas
 * listening on one CHR would double every session row (arbitrage A5).
 */

import { leaderElection } from '../leaderElection';
import { logger } from '../../utils/logger';
import { pppPresence } from './pppPresence.service';
import { getRouterOsPool, shutdownRouterOsPool } from './routerosPool';

export * from './fleetEvents';
export * from './reachability.service';
export * from './concentratorDiscovery.service';
export * from './pppPresence.service';
export * from './deviceBinding.service';
export * from './routerosPool';
export * as siteService from './site.service';
export * as deviceService from './device.service';
export { syncConcentratorPresence, stopConcentratorPresence } from './device.service';

let unsubscribe: (() => void) | null = null;
let starting: Promise<void> | null = null;

/**
 * Wire presence to leadership. Idempotent: calling twice is a no-op, which
 * matters because a reconnecting socket server must not stack subscriptions.
 */
export function startFleetRuntime(): void {
  if (unsubscribe) return;

  // Creating the pool here (rather than lazily on the first query) also
  // registers the MikroTik channel factory, which both the driver layer and
  // the transport layer flagged as "must happen once at boot".
  getRouterOsPool();

  unsubscribe = leaderElection.onChange((isLeader) => {
    if (isLeader) {
      starting = pppPresence
        .startAll()
        .then(() => undefined)
        .catch((err) => {
          logger.error(err, 'Fleet runtime: presence failed to start');
        });
      return;
    }
    // Losing leadership must cancel the `listen` on the router, not just stop
    // reading it: an abandoned listen stays registered on the CHR forever.
    void (starting ?? Promise.resolve())
      .then(() => pppPresence.stopAll())
      .catch((err) => logger.error(err, 'Fleet runtime: presence failed to stop'));
  });

  logger.info('Fleet runtime armed (presence follows leadership)');
}

/** Tear everything down. Used by tests and by a graceful shutdown. */
export async function stopFleetRuntime(): Promise<void> {
  unsubscribe?.();
  unsubscribe = null;
  await pppPresence.stopAll().catch(() => undefined);
  await shutdownRouterOsPool().catch(() => undefined);
}
