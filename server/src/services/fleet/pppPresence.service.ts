/**
 * ObliWAN — PPP presence (D4).
 *
 * The concentrator is the source of truth for "is this site reachable", not
 * ping. Two mechanisms, and BOTH are required:
 *
 *   1. `/ppp/active/listen` — a single streaming command on the single socket
 *      the pool holds to the CHR. This is what makes the state flip in under
 *      two seconds instead of on the next poll tick.
 *
 *   2. A full `/ppp/active` reconciliation every 60 s. Not a fallback, a
 *      correction: a `listen` can miss an event, can be silently cancelled by
 *      the router, or can survive as a TCP connection that no longer carries
 *      anything. Presence that only ever hears about deltas drifts, and drifts
 *      quietly — the failure mode is a device shown online for a week.
 *
 * The reconciliation is also what makes a restart correct: on start the
 * in-memory view is empty and the database may hold sessions the CHR forgot
 * about during the outage. The first sweep closes them.
 *
 * WHY `.id` IS KEPT IN MEMORY AND NEVER STORED
 * A `listen` teardown event carries `.id` and `.dead=true` — and often nothing
 * else, not even the username. So the monitor keeps a `.id -> username` map
 * built from the sessions it has seen. RouterOS `.id` values are recycled
 * across reboots, which is precisely why the map is per-stream, in memory, and
 * thrown away when the stream dies. An unknown `.id` does not guess: it forces
 * an immediate reconciliation.
 *
 * LEADERSHIP: only the leader may run this (arbitrage A5). Two replicas would
 * open two `listen` commands on the same CHR and double-write session history.
 * The gate lives in `./index.ts`; this service exposes plain start/stop.
 */

import { SOCKET_EVENTS, type SitePresenceEvent } from '@obliwan/shared';
import type { RouterOsStream } from '../transport/routeros';
import type { Sentence } from '../transport/routeros';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { getRouterOsPool, resolveRouterOsTarget } from './routerosPool';
import { emitSitePresence, emitToTenant } from './fleetEvents';
import { asInetOrNull, parseActiveRow, requireConcentrator, type PppActiveEntry } from './concentratorDiscovery.service';
import { assessDevice, markConcentratorDegraded, recordVerdict } from './reachability.service';

/** How often the full sweep runs. The spec fixes this at 60 s. */
export const RECONCILE_INTERVAL_MS = 60_000;

/** How long to wait before re-opening a `listen` that died. */
const STREAM_RETRY_MS = 5_000;

// ============================================================================
// Session bookkeeping
// ============================================================================

interface DeviceRef {
  id: number;
  tenant_id: number;
  site_id: number | null;
  wan_public_ip: string | null;
}

/**
 * The device a PPP username belongs to — ON THIS CONCENTRATOR.
 *
 * `concentratorId` is not optional and the filter is not cosmetic. `ppp_username`
 * is UNIQUE GLOBALLY (migration 002), so a lookup by name alone resolves a name
 * seen on ANY concentrator to a device that may belong to a different tenant
 * entirely — and `applySessionUp` then writes `tunnel_ip` on it. That address is
 * what `assertTargetBinding` dials at M6, with that customer's decrypted RouterOS
 * password: whoever published the session gets handed the credential.
 *
 * A name seen on a concentrator the device is not attached to yields null. The
 * session is still recorded without a device_id — the same shape as an unclaimed
 * account — and the collision is logged, because it is itself a signal.
 */
async function deviceForUsername(
  username: string,
  concentratorId: number,
): Promise<DeviceRef | null> {
  const row = await db('devices')
    .where({ ppp_username: username, concentrator_id: concentratorId })
    .first<DeviceRef | undefined>('id', 'tenant_id', 'site_id', 'wan_public_ip');
  if (row) return row;

  const elsewhere = await db('devices')
    .where({ ppp_username: username })
    .first<{ id: number; concentrator_id: number | null } | undefined>('id', 'concentrator_id');
  if (elsewhere) {
    logger.warn(
      { username, concentratorId, deviceId: elsewhere.id, attachedTo: elsewhere.concentrator_id },
      'PPP session refused: this username belongs to a device attached to ANOTHER concentrator. ' +
        'Session recorded without a device. Either the device was re-homed and its ' +
        'concentrator_id is stale, or two concentrators declare the same account name.',
    );
  }
  return null;
}

export interface PresenceChange {
  concentratorId: number;
  pppUsername: string;
  up: boolean;
  deviceId: number | null;
  siteId: number | null;
  tunnelIp: string | null;
  callerIp: string | null;
  /** True when the database actually changed state (a duplicate `up` for an
   *  already-open session is not a change and must not emit). */
  changed: boolean;
  at: string;
}

/**
 * A session came up.
 *
 * Idempotent: `ppp_sessions` carries a partial unique index guaranteeing at
 * most one open row per (concentrator, username), so a duplicate event from the
 * listen and the sweep racing each other refreshes the row instead of forking
 * the history.
 */
export async function applySessionUp(
  concentratorId: number,
  entry: { username: string; tunnelIp: string | null; callerIp: string | null },
  options: { emit?: boolean } = {},
): Promise<PresenceChange> {
  const now = new Date();
  const device = await deviceForUsername(entry.username, concentratorId);
  const tunnelIp = asInetOrNull(entry.tunnelIp);
  const callerIp = asInetOrNull(entry.callerIp);

  const open = await db('ppp_sessions')
    .where({ concentrator_id: concentratorId, ppp_username: entry.username })
    .whereNull('ended_at')
    .first<{ id: string; tunnel_ip: string | null } | undefined>('id', 'tunnel_ip');

  let changed = false;
  if (open) {
    // Already up. Refresh addressing only — re-opening would lose the real
    // start time and inflate the flap count.
    await db('ppp_sessions')
      .where({ id: open.id })
      .update({ tunnel_ip: tunnelIp, caller_ip: callerIp, device_id: device?.id ?? null });
  } else {
    await db('ppp_sessions').insert({
      concentrator_id: concentratorId,
      device_id: device?.id ?? null,
      ppp_username: entry.username,
      tunnel_ip: tunnelIp,
      caller_ip: callerIp,
      started_at: now,
    });
    changed = true;
  }

  if (device) {
    await db('devices')
      .where({ id: device.id })
      .update({
        last_seen_at: now,
        // "Where to dial today" (D5). Never used as an identity: every write
        // path goes through assertTargetBinding() first.
        tunnel_ip: tunnelIp,
        wan_public_ip: callerIp ?? device.wan_public_ip,
        first_seen_at: db.raw('COALESCE(first_seen_at, ?)', [now]),
        updated_at: now,
      });
  }

  const change: PresenceChange = {
    concentratorId,
    pppUsername: entry.username,
    up: true,
    deviceId: device?.id ?? null,
    siteId: device?.site_id ?? null,
    tunnelIp,
    callerIp,
    changed,
    at: now.toISOString(),
  };

  if (changed && options.emit !== false) {
    await publish(change, device, {
      // A session that comes back from a different public address is a silent
      // WAN failover. Only meaningful when we had a baseline to compare to.
      publicPathChanged:
        device?.wan_public_ip && callerIp ? device.wan_public_ip !== callerIp : null,
    });
  }
  return change;
}

/** A session went away. */
export async function applySessionDown(
  concentratorId: number,
  username: string,
  reason: string | null,
  options: { emit?: boolean } = {},
): Promise<PresenceChange> {
  const now = new Date();
  const device = await deviceForUsername(username, concentratorId);

  const open = await db('ppp_sessions')
    .where({ concentrator_id: concentratorId, ppp_username: username })
    .whereNull('ended_at')
    .first<{ id: string; started_at: Date; tunnel_ip: string | null; caller_ip: string | null } | undefined>(
      'id',
      'started_at',
      'tunnel_ip',
      'caller_ip',
    );

  let changed = false;
  if (open) {
    const duration = Math.max(0, Math.round((now.getTime() - open.started_at.getTime()) / 1000));
    await db('ppp_sessions').where({ id: open.id }).update({
      ended_at: now,
      duration_seconds: duration,
      disconnect_reason: reason ? reason.slice(0, 128) : null,
    });
    changed = true;
  }

  const change: PresenceChange = {
    concentratorId,
    pppUsername: username,
    up: false,
    deviceId: device?.id ?? null,
    siteId: device?.site_id ?? null,
    tunnelIp: open?.tunnel_ip ?? null,
    callerIp: open?.caller_ip ?? null,
    changed,
    at: now.toISOString(),
  };

  if (changed && options.emit !== false) {
    await publish(change, device, {});
  }
  return change;
}

/**
 * Verdict + socket, in that order.
 *
 * The verdict is computed BEFORE the event is emitted so the payload carries a
 * verdict the UI can trust rather than a "we will tell you later". When the
 * username is not bound to any device there is nothing to assess — the history
 * row is still written, and the event still fires for the discoveries screen.
 */
async function publish(
  change: PresenceChange,
  device: DeviceRef | null,
  context: { publicPathChanged?: boolean | null },
): Promise<void> {
  let verdict: SitePresenceEvent['verdict'] = 'UNREACHABLE';

  if (device) {
    try {
      const recorded = await recordVerdict(
        device.id,
        { pppUp: change.up },
        { publicPathChanged: context.publicPathChanged ?? null },
      );
      verdict = recorded.verdict;
    } catch (err) {
      logger.error({ err, deviceId: device.id }, 'Verdict evaluation failed; reporting UNREACHABLE');
    }
  }

  const event: SitePresenceEvent = {
    deviceId: change.deviceId,
    siteId: change.siteId,
    concentratorId: change.concentratorId,
    pppUsername: change.pppUsername,
    up: change.up,
    tunnelIp: change.tunnelIp,
    callerIp: change.callerIp,
    verdict,
    at: change.at,
  };

  if (device) {
    emitSitePresence(device.tenant_id, event);
  } else {
    // Unbound username: the concentrator's tenant is the only audience that
    // could act on it.
    const chr = await db('devices')
      .where({ id: change.concentratorId })
      .first<{ tenant_id: number } | undefined>('tenant_id');
    if (chr) emitToTenant(chr.tenant_id, SOCKET_EVENTS.SITE_PRESENCE, event);
  }

  logger.info(
    {
      concentratorId: change.concentratorId,
      pppUsername: change.pppUsername,
      up: change.up,
      deviceId: change.deviceId,
      verdict,
    },
    'PPP presence change',
  );
}

// ============================================================================
// Reconciliation
// ============================================================================

export interface ReconcileResult {
  concentratorId: number;
  activeOnChr: number;
  openInDb: number;
  opened: number;
  closed: number;
  at: string;
}

/**
 * Make the database agree with the concentrator. This is the correction pass;
 * it is the reason a missed `listen` event costs at most 60 seconds of
 * staleness rather than an indefinite lie.
 */
export async function reconcile(
  concentratorId: number,
  activeEntries?: PppActiveEntry[],
): Promise<ReconcileResult> {
  let entries: PppActiveEntry[];
  if (activeEntries) {
    entries = activeEntries;
  } else {
    const target = await resolveRouterOsTarget(concentratorId);
    const rows = await getRouterOsPool().withConnection(target, (conn) =>
      conn.query(['/ppp/active/print']),
    );
    entries = rows.map(parseActiveRow).filter((e): e is PppActiveEntry => e !== null);
  }

  const byName = new Map<string, PppActiveEntry>(entries.map((e) => [e.name, e]));

  const openRows = await db('ppp_sessions')
    .where({ concentrator_id: concentratorId })
    .whereNull('ended_at')
    .select<Array<{ ppp_username: string }>>('ppp_username');
  const openNames = new Set(openRows.map((r) => r.ppp_username));

  let opened = 0;
  let closed = 0;

  for (const [name, entry] of byName) {
    if (openNames.has(name)) continue;
    await applySessionUp(concentratorId, {
      username: name,
      tunnelIp: entry.address,
      callerIp: entry.callerId,
    });
    opened++;
  }

  for (const name of openNames) {
    if (byName.has(name)) continue;
    // The CHR no longer lists it and never told us. That is exactly the event
    // a `listen` can drop, and exactly why this sweep exists.
    await applySessionDown(concentratorId, name, 'reconciled-missing');
    closed++;
  }

  const result: ReconcileResult = {
    concentratorId,
    activeOnChr: byName.size,
    openInDb: openNames.size,
    opened,
    closed,
    at: new Date().toISOString(),
  };
  if (opened || closed) {
    logger.info(result, 'PPP reconciliation corrected the presence view');
  } else {
    logger.debug(result, 'PPP reconciliation: no drift');
  }
  return result;
}

// ============================================================================
// The live monitor
// ============================================================================

interface TrackedSession {
  username: string;
  address: string | null;
  callerId: string | null;
}

class ConcentratorMonitor {
  private stream: RouterOsStream | null = null;
  private reconcileTimer: NodeJS.Timeout | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private stopped = false;
  /** RouterOS `.id` -> session. Per-stream, in memory, never persisted. */
  private readonly byRouterId = new Map<string, TrackedSession>();
  /** Serialises DB work so a burst of listen events cannot interleave an
   *  up and a down for the same username. */
  private queue: Promise<void> = Promise.resolve();

  constructor(readonly concentratorId: number) {}

  async start(): Promise<void> {
    this.stopped = false;
    await this.openStream();
    // The first sweep runs immediately: on a cold start the database may hold
    // sessions from before the process died.
    await this.safeReconcile();
    this.reconcileTimer = setInterval(() => void this.safeReconcile(), RECONCILE_INTERVAL_MS);
    this.reconcileTimer.unref();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.reconcileTimer) clearInterval(this.reconcileTimer);
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.reconcileTimer = null;
    this.retryTimer = null;
    const stream = this.stream;
    this.stream = null;
    // Never leave a `listen` registered on the router: an abandoned one stays
    // there forever and the next leader will add a second.
    if (stream) await stream.cancel().catch(() => undefined);
    await this.queue.catch(() => undefined);
  }

  get isStreaming(): boolean {
    return this.stream !== null && !this.stream.isClosed;
  }

  private enqueue(fn: () => Promise<void>): void {
    this.queue = this.queue.then(fn).catch((err) => {
      logger.error({ err, concentratorId: this.concentratorId }, 'Presence task failed');
    });
  }

  private async openStream(): Promise<void> {
    if (this.stopped || this.stream) return;
    try {
      const target = await resolveRouterOsTarget(this.concentratorId);
      const conn = await getRouterOsPool().acquire(target);
      this.byRouterId.clear();
      this.stream = conn.stream(['/ppp/active/listen'], {
        onRow: (row) => this.onListenRow(row),
        onDone: () => this.onStreamGone(null),
        onError: (err) => this.onStreamGone(err),
      });
      logger.info(
        { concentratorId: this.concentratorId, tag: this.stream.tag },
        'PPP listen established on the concentrator',
      );
    } catch (err) {
      logger.warn(
        { err, concentratorId: this.concentratorId },
        'Could not open /ppp/active/listen; will retry',
      );
      this.enqueue(async () => {
        await markConcentratorDegraded(
          this.concentratorId,
          err instanceof Error ? err.message : String(err),
        );
      });
      this.scheduleRetry();
    }
  }

  private onStreamGone(err: Error | null): void {
    if (this.stopped) return;
    this.stream = null;
    this.byRouterId.clear();
    logger.warn(
      { concentratorId: this.concentratorId, err: err?.message },
      'PPP listen ended; re-opening',
    );
    this.scheduleRetry();
  }

  private scheduleRetry(): void {
    if (this.stopped || this.retryTimer) return;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      void this.openStream().then(() => this.safeReconcile());
    }, STREAM_RETRY_MS);
    this.retryTimer.unref();
  }

  /**
   * One `!re` from the listen.
   *
   * RouterOS pushes an add event with the full attribute set, and a teardown
   * event that carries `.id` plus `.dead=true` and frequently nothing else.
   * That asymmetry is why the `.id` map exists.
   */
  private onListenRow(row: Sentence): void {
    const attrs = row.attrs;
    const routerId = attrs['.id'] ?? null;
    const dead = attrs['.dead'] === 'true' || attrs['.dead'] === 'yes';

    if (dead) {
      const known = routerId ? this.byRouterId.get(routerId) : undefined;
      const username = attrs.name ?? known?.username ?? null;
      if (routerId) this.byRouterId.delete(routerId);
      if (!username) {
        // We were told a session died and cannot say which. Guessing would be
        // worse than useless: sweep instead.
        logger.warn(
          { concentratorId: this.concentratorId, routerId },
          'PPP teardown for an unknown .id — forcing a reconciliation',
        );
        this.enqueue(() => this.safeReconcile());
        return;
      }
      this.enqueue(async () => {
        await applySessionDown(this.concentratorId, username, attrs['disconnect-reason'] ?? 'listen');
      });
      return;
    }

    const entry = parseActiveRow(attrs);
    if (!entry) {
      // An add event with no name is unusable on its own; the sweep will pick
      // the session up within 60 s.
      logger.debug({ concentratorId: this.concentratorId, attrs: Object.keys(attrs) }, 'PPP listen row without a name');
      return;
    }
    if (routerId) {
      this.byRouterId.set(routerId, {
        username: entry.name,
        address: entry.address,
        callerId: entry.callerId,
      });
    }
    this.enqueue(async () => {
      await applySessionUp(this.concentratorId, {
        username: entry.name,
        tunnelIp: entry.address,
        callerIp: entry.callerId,
      });
    });
  }

  private async safeReconcile(): Promise<void> {
    if (this.stopped) return;
    try {
      const entries = await this.readActive();
      // Refresh the `.id` map from ground truth so a teardown that arrives
      // after a stream restart still resolves to a username.
      this.byRouterId.clear();
      for (const e of entries) {
        if (e.routerId) {
          this.byRouterId.set(e.routerId, {
            username: e.name,
            address: e.address,
            callerId: e.callerId,
          });
        }
      }
      await reconcile(this.concentratorId, entries);
    } catch (err) {
      logger.warn(
        { err, concentratorId: this.concentratorId },
        'PPP reconciliation failed; the concentrator is degraded',
      );
      // R5: one alert on the concentrator, and every child verdict suppressed.
      // The sessions in the database are NOT closed — we do not know that they
      // ended, and inventing 300 outages is the failure this guards against.
      await markConcentratorDegraded(
        this.concentratorId,
        err instanceof Error ? err.message : String(err),
      ).catch(() => undefined);
    }
  }

  private async readActive(): Promise<PppActiveEntry[]> {
    const target = await resolveRouterOsTarget(this.concentratorId);
    const rows = await getRouterOsPool().withConnection(target, (conn) =>
      conn.query(['/ppp/active/print']),
    );
    return rows.map(parseActiveRow).filter((e): e is PppActiveEntry => e !== null);
  }
}

// ============================================================================
// Service facade
// ============================================================================

class PppPresenceService {
  private readonly monitors = new Map<number, ConcentratorMonitor>();
  private running = false;

  get isRunning(): boolean {
    return this.running;
  }

  get watched(): number[] {
    return Array.from(this.monitors.keys());
  }

  isWatching(concentratorId: number): boolean {
    return this.monitors.has(concentratorId);
  }

  /** Watch one concentrator. Idempotent. */
  async watch(concentratorId: number): Promise<void> {
    if (this.monitors.has(concentratorId)) return;
    await requireConcentrator(concentratorId);
    const monitor = new ConcentratorMonitor(concentratorId);
    this.monitors.set(concentratorId, monitor);
    try {
      await monitor.start();
    } catch (err) {
      this.monitors.delete(concentratorId);
      throw err;
    }
  }

  async unwatch(concentratorId: number): Promise<void> {
    const monitor = this.monitors.get(concentratorId);
    if (!monitor) return;
    this.monitors.delete(concentratorId);
    await monitor.stop();
  }

  /**
   * Start watching every enabled concentrator. Called by the leadership gate;
   * a follower never reaches this.
   */
  async startAll(): Promise<number[]> {
    this.running = true;
    const rows = await db('devices')
      .where({ role: 'concentrator' })
      .whereNotIn('status', ['disabled'])
      .select<Array<{ id: number; name: string }>>('id', 'name');

    const started: number[] = [];
    for (const row of rows) {
      try {
        await this.watch(row.id);
        started.push(row.id);
      } catch (err) {
        // One unreachable CHR must not stop the others from being watched.
        logger.error({ err, concentratorId: row.id }, 'Could not start presence on concentrator');
      }
    }
    logger.info({ concentrators: started }, 'PPP presence started');
    return started;
  }

  async stopAll(): Promise<void> {
    this.running = false;
    const ids = Array.from(this.monitors.keys());
    await Promise.all(ids.map((id) => this.unwatch(id)));
    logger.info('PPP presence stopped');
  }

  /** Force a sweep now (used by the API and by tests). */
  reconcileNow(concentratorId: number): Promise<ReconcileResult> {
    return reconcile(concentratorId);
  }

  /** Re-assess every device of a concentrator without touching the CHR. */
  async assessChildren(concentratorId: number): Promise<number> {
    const children = await db('devices')
      .where({ concentrator_id: concentratorId })
      .pluck<number[]>('id');
    for (const id of children) {
      await assessDevice(id).catch((err) =>
        logger.warn({ err, deviceId: id }, 'Assessment failed'),
      );
    }
    return children.length;
  }
}

export const pppPresence = new PppPresenceService();
