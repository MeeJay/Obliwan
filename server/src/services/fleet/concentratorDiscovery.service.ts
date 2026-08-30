/**
 * ObliWAN — fleet discovery from the concentrator (C4).
 *
 * The CHR is a `devices` row with `role = 'concentrator'`. It knows two things nobody
 * else does:
 *
 *   /ppp/secret   the accounts that were DECLARED — every site that is supposed
 *                 to exist, including the ones that have never dialled in.
 *   /ppp/active   the sessions that are UP right now.
 *
 * Every PPP username the platform does not already know becomes a row in
 * `discoveries`, state `pending`. That is a QUARANTINE, and it is the whole
 * point: nothing here binds a discovery to a tenant, to a site, or to a device.
 *
 * Why so strict — risk R4. PPP pools reassign addresses. If discovery guessed
 * "this username at 10.66.0.11 must be customer A's router", then a pool
 * reshuffle silently turns that guess into pushing customer A's configuration
 * onto customer B's box. There is no clever heuristic that makes that safe, so
 * there is no heuristic at all: a human binds, and `discoveries.reviewed_by`
 * records who.
 *
 * The scan is idempotent. `discoveries` carries UNIQUE(concentrator_id,
 * ppp_username), so a re-scan refreshes `last_seen_at` through an UPSERT rather
 * than exploding on the second reconnect of the same secret.
 */

import { SOCKET_EVENTS } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { getRouterOsPool, resolveRouterOsTarget } from './routerosPool';
import { redactSentence } from '../transport/routeros/protocol';
import { emitToTenantAdmins } from './fleetEvents';

// ============================================================================
// What the CHR tells us
// ============================================================================

/** One row of `/ppp/active`. Field names are RouterOS's, normalised to camel. */
export interface PppActiveEntry {
  /** RouterOS internal `.id` (`*1`). Volatile across reboots — used ONLY to
   *  correlate a `listen` event with the session it refers to, never stored as
   *  an identity. */
  routerId: string | null;
  name: string;
  service: string | null;
  /** Tunnel address handed to the peer. "Where to dial today" (D5). */
  address: string | null;
  /** Peer's public address as the CHR sees it. */
  callerId: string | null;
  uptime: string | null;
  raw: Record<string, string>;
}

/** One row of `/ppp/secret`. */
export interface PppSecretEntry {
  routerId: string | null;
  name: string;
  service: string | null;
  profile: string | null;
  remoteAddress: string | null;
  comment: string | null;
  disabled: boolean;
  raw: Record<string, string>;
}

/** RouterOS booleans are the strings `true` / `false` / `yes` / `no`. */
function rosBool(value: string | undefined): boolean {
  return value === 'true' || value === 'yes';
}

function orNull(value: string | undefined): string | null {
  const v = value?.trim();
  return v ? v : null;
}

/**
 * `inet` columns reject anything that is not an address, and a malformed
 * `caller-id` (RouterOS puts a MAC there for PPPoE, and a hostname for some
 * L2TP clients) would abort the whole scan on one bad row. Anything that is not
 * plainly an IPv4/IPv6 literal is dropped to NULL and kept in `raw`, where it
 * remains visible to the operator.
 */
export function asInetOrNull(value: string | null | undefined): string | null {
  if (!value) return null;
  const v = value.trim().split('%')[0];
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
    return v.split('.').every((o) => Number(o) <= 255) ? v : null;
  }
  // A MAC address is colon-separated hex too, and RouterOS puts one in
  // `caller-id` for PPPoE. Six groups of exactly two hex digits is a MAC, not
  // an IPv6 address — refuse it before the loose check below lets it through.
  if (/^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$/.test(v)) return null;
  // Deliberately loose on IPv6 beyond that: Postgres is the real validator, and
  // all this needs to do is keep the obvious non-addresses out of an `inet`
  // column so one odd row cannot abort a whole discovery scan.
  if (/^[0-9a-fA-F:]+$/.test(v) && v.includes(':')) return v;
  return null;
}

export function parseActiveRow(row: Record<string, string>): PppActiveEntry | null {
  const name = orNull(row.name);
  if (!name) return null;
  return {
    routerId: orNull(row['.id']),
    name,
    service: orNull(row.service),
    address: orNull(row.address),
    callerId: orNull(row['caller-id']),
    uptime: orNull(row.uptime),
    raw: row,
  };
}

export function parseSecretRow(row: Record<string, string>): PppSecretEntry | null {
  const name = orNull(row.name);
  if (!name) return null;
  return {
    routerId: orNull(row['.id']),
    name,
    service: orNull(row.service),
    profile: orNull(row.profile),
    remoteAddress: orNull(row['remote-address']),
    comment: orNull(row.comment),
    disabled: rosBool(row.disabled),
    raw: row,
  };
}

// ============================================================================
// Reading the concentrator
// ============================================================================

export interface ConcentratorRow {
  id: number;
  tenant_id: number;
  name: string;
  role: string;
  status: string;
}

/** Load a device and refuse it if it is not a concentrator. */
export async function requireConcentrator(concentratorId: number): Promise<ConcentratorRow> {
  const row = await db('devices')
    .where({ id: concentratorId })
    .first<ConcentratorRow | undefined>('id', 'tenant_id', 'name', 'role', 'status');
  if (!row) throw new Error(`Device ${concentratorId} does not exist`);
  if (row.role !== 'concentrator') {
    throw new Error(`Device ${concentratorId} is not a concentrator (role=${row.role})`);
  }
  return row;
}

/** `/ppp/active/print` on the concentrator, through the shared pool socket. */
export async function readPppActive(concentratorId: number): Promise<PppActiveEntry[]> {
  const target = await resolveRouterOsTarget(concentratorId);
  const rows = await getRouterOsPool().withConnection(target, (conn) =>
    conn.query(['/ppp/active/print']),
  );
  return rows.map(parseActiveRow).filter((e): e is PppActiveEntry => e !== null);
}

/** `/ppp/secret/print` — the declared accounts, present or not. */
export async function readPppSecrets(concentratorId: number): Promise<PppSecretEntry[]> {
  const target = await resolveRouterOsTarget(concentratorId);
  const rows = await getRouterOsPool().withConnection(target, (conn) =>
    // `show-sensitive=no` IN HARD, exactly like `/export` in collect.service and
    // backup.service (risk R10). Without it RouterOS returns `=password=` for any
    // API account carrying the `sensitive` policy — which the ObliWAN service
    // account does — and that password is every site's L2TP credential.
    //
    // The proplist is the second half: an allow-list cannot leak a field a future
    // RouterOS version decides to add. Discovery needs identity and routing, not
    // credentials.
    conn.query([
      '/ppp/secret/print',
      '=show-sensitive=no',
      '=.proplist=.id,name,service,profile,remote-address,local-address,comment,disabled',
    ]),
  );
  return rows.map(parseSecretRow).filter((e): e is PppSecretEntry => e !== null);
}

// ============================================================================
// The scan
// ============================================================================

export interface DiscoveryScanResult {
  concentratorId: number;
  /** Accounts declared on the CHR. */
  secrets: number;
  /** Sessions up at scan time. */
  active: number;
  /** Usernames already bound to a `devices` row: skipped entirely. */
  known: number;
  /** New quarantine rows. */
  created: number;
  /** Existing quarantine rows whose `last_seen_at` / details were refreshed. */
  refreshed: number;
  /** The usernames that landed in quarantine on THIS scan. */
  newUsernames: string[];
  scannedAt: string;
}

interface Candidate {
  username: string;
  remoteAddress: string | null;
  callerIp: string | null;
  profile: string | null;
  comment: string | null;
  online: boolean;
  raw: Record<string, unknown>;
}

/**
 * Merge `/ppp/secret` and `/ppp/active` into one candidate per username.
 *
 * Pure, so the merge rules are testable without a router. The active session
 * wins on addressing (it is what is true right now); the secret wins on profile
 * and comment (that is where an operator writes the site name).
 */
export function mergeCandidates(
  secrets: PppSecretEntry[],
  active: PppActiveEntry[],
): Candidate[] {
  const byName = new Map<string, Candidate>();

  for (const s of secrets) {
    byName.set(s.name, {
      username: s.name,
      remoteAddress: asInetOrNull(s.remoteAddress),
      callerIp: null,
      profile: s.profile,
      comment: s.comment,
      online: false,
      raw: { secret: redactSentence(s.raw) },
    });
  }

  for (const a of active) {
    const existing = byName.get(a.name);
    if (existing) {
      existing.online = true;
      existing.remoteAddress = asInetOrNull(a.address) ?? existing.remoteAddress;
      existing.callerIp = asInetOrNull(a.callerId);
      existing.raw = { ...existing.raw, active: a.raw };
      continue;
    }
    // A session with no declared secret: RADIUS, or a secret removed while the
    // session stayed up. It is still a device on the fleet, so it is still a
    // discovery — that is exactly what quarantine is for.
    byName.set(a.name, {
      username: a.name,
      remoteAddress: asInetOrNull(a.address),
      callerIp: asInetOrNull(a.callerId),
      profile: null,
      comment: null,
      online: true,
      raw: { active: redactSentence(a.raw), note: 'active session with no /ppp/secret entry' },
    });
  }

  return Array.from(byName.values());
}

/**
 * Full discovery pass. Safe to run repeatedly and safe to run concurrently with
 * presence reconciliation: every write is an UPSERT on the unique key.
 */
export async function runChrDiscovery(concentratorId: number): Promise<DiscoveryScanResult> {
  const chr = await requireConcentrator(concentratorId);

  const [secrets, active] = await Promise.all([
    readPppSecrets(concentratorId).catch((err) => {
      // A CHR whose /ppp/secret is not readable (permissions) still gives us
      // the live sessions, which is the more valuable half. Degrade, do not
      // abort: an empty inventory would look like "no sites".
      logger.warn({ err, concentratorId }, '/ppp/secret unreadable; scanning active sessions only');
      return [] as PppSecretEntry[];
    }),
    readPppActive(concentratorId),
  ]);

  const candidates = mergeCandidates(secrets, active);

  // Usernames already attached to a device are not discoveries any more. The
  // lookup is global, not tenant-scoped: `devices.ppp_username` is UNIQUE
  // fleet-wide precisely so presence can never be ambiguous.
  const usernames = candidates.map((c) => c.username);
  const bound = usernames.length
    ? await db('devices').whereIn('ppp_username', usernames).pluck<string[]>('ppp_username')
    : [];
  const boundSet = new Set(bound);

  // Which quarantine rows already exist. Read up-front rather than inferred
  // from the UPSERT's return value: "did this INSERT actually insert" is not
  // something `ON CONFLICT ... RETURNING` answers portably, and a wrong answer
  // here would re-announce every known site as a new discovery on every scan.
  const existing = new Set(
    await db('discoveries')
      .where({ concentrator_id: concentratorId })
      .pluck<string[]>('ppp_username'),
  );

  const now = new Date();
  let created = 0;
  let refreshed = 0;
  const newUsernames: string[] = [];

  for (const c of candidates) {
    if (boundSet.has(c.username)) continue;
    const isNew = !existing.has(c.username);

    // `state` is deliberately absent from the merge list: a row an operator
    // moved to `ignored` must stay ignored, and one moved to `bound` must not
    // be dragged back to `pending` by the next scan.
    const inserted = await db('discoveries')
      .insert({
        concentrator_id: concentratorId,
        ppp_username: c.username,
        remote_address: c.remoteAddress,
        caller_ip: c.callerIp,
        profile: c.profile,
        ppp_comment: c.comment,
        raw: JSON.stringify(c.raw),
        state: 'pending',
        first_seen_at: now,
        last_seen_at: now,
      })
      .onConflict(['concentrator_id', 'ppp_username'])
      .merge({
        remote_address: c.remoteAddress,
        caller_ip: c.callerIp,
        profile: c.profile,
        ppp_comment: c.comment,
        raw: JSON.stringify(c.raw),
        last_seen_at: now,
        updated_at: now,
      })
      .returning<Array<{ id: number; state: string }>>(['id', 'state']);

    const row = inserted[0];
    if (isNew && row) {
      created++;
      newUsernames.push(c.username);
      emitToTenantAdmins(chr.tenant_id, SOCKET_EVENTS.DISCOVERY_NEW, {
        id: row.id,
        concentratorId,
        concentratorName: chr.name,
        pppUsername: c.username,
        remoteAddress: c.remoteAddress,
        callerIp: c.callerIp,
        profile: c.profile,
        online: c.online,
        state: row.state,
        at: now.toISOString(),
      });
    } else {
      refreshed++;
    }
  }

  const result: DiscoveryScanResult = {
    concentratorId,
    secrets: secrets.length,
    active: active.length,
    known: candidates.filter((c) => boundSet.has(c.username)).length,
    created,
    refreshed,
    newUsernames,
    scannedAt: now.toISOString(),
  };

  logger.info(result, 'CHR discovery scan complete');
  return result;
}

// ============================================================================
// Quarantine review — the human gesture
// ============================================================================

export interface DiscoveryRow {
  id: number;
  uuid: string;
  concentrator_id: number;
  ppp_username: string;
  remote_address: string | null;
  caller_ip: string | null;
  profile: string | null;
  ppp_comment: string | null;
  raw: Record<string, unknown>;
  state: string;
  bound_device_id: number | null;
  reviewed_by: number | null;
  reviewed_at: Date | null;
  first_seen_at: Date;
  last_seen_at: Date;
}

export interface ListDiscoveriesFilter {
  /** Concentrators visible to the caller's tenant. Always supplied by the
   *  controller — `discoveries` has no tenant column of its own. */
  concentratorIds: number[];
  state?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export async function listDiscoveries(
  filter: ListDiscoveriesFilter,
): Promise<{ items: Array<DiscoveryRow & { concentrator_name: string }>; total: number }> {
  if (filter.concentratorIds.length === 0) return { items: [], total: 0 };

  const base = db('discoveries as d')
    .join('devices as c', 'c.id', 'd.concentrator_id')
    .whereIn('d.concentrator_id', filter.concentratorIds);

  if (filter.state) base.andWhere('d.state', filter.state);
  if (filter.search) {
    const like = `%${filter.search}%`;
    base.andWhere((q) => {
      q.whereILike('d.ppp_username', like).orWhereILike('d.ppp_comment', like);
    });
  }

  const [{ count }] = await base.clone().clearSelect().count<{ count: string }[]>('d.id as count');
  const items = await base
    .clone()
    .select('d.*', 'c.name as concentrator_name')
    .orderBy('d.last_seen_at', 'desc')
    .limit(filter.limit ?? 100)
    .offset(filter.offset ?? 0);

  return { items, total: Number(count) };
}

export async function getDiscovery(id: number): Promise<DiscoveryRow | undefined> {
  return db('discoveries').where({ id }).first<DiscoveryRow | undefined>();
}

/**
 * Bind a quarantined username to an existing device.
 *
 * Everything that makes this safe is a constraint, not a convention:
 *  - the target device must be in the caller's tenant (checked by the caller);
 *  - `devices.ppp_username` is UNIQUE fleet-wide, so binding the same username
 *    to a second device is refused by Postgres, not by an `if`;
 *  - `discoveries.state='bound'` without `bound_device_id` is refused by a
 *    CHECK constraint, so there is no half-finished binding to trip over.
 */
export async function bindDiscovery(
  discoveryId: number,
  deviceId: number,
  reviewedBy: number,
): Promise<DiscoveryRow> {
  return db.transaction(async (trx) => {
    const discovery = await trx('discoveries')
      .where({ id: discoveryId })
      .forUpdate()
      .first<DiscoveryRow | undefined>();
    if (!discovery) throw new Error(`Discovery ${discoveryId} does not exist`);
    if (discovery.state === 'bound') {
      throw new Error(`Discovery ${discoveryId} is already bound to device ${discovery.bound_device_id}`);
    }

    const device = await trx('devices')
      .where({ id: deviceId })
      .first<{ id: number; ppp_username: string | null; concentrator_id: number | null } | undefined>(
        'id',
        'ppp_username',
        'concentrator_id',
      );
    if (!device) throw new Error(`Device ${deviceId} does not exist`);
    if (device.ppp_username && device.ppp_username !== discovery.ppp_username) {
      throw new Error(
        `Device ${deviceId} is already bound to PPP user '${device.ppp_username}'`,
      );
    }

    await trx('devices').where({ id: deviceId }).update({
      ppp_username: discovery.ppp_username,
      concentrator_id: discovery.concentrator_id,
      // The tunnel address is recorded because the arbiter needs somewhere to
      // dial. It is NOT an identity, and `assertTargetBinding()` re-proves the
      // identity on a fresh connection before anything is written (D5 / R4).
      tunnel_ip: discovery.remote_address,
      wan_public_ip: discovery.caller_ip,
      first_seen_at: trx.raw('COALESCE(first_seen_at, ?)', [discovery.first_seen_at]),
      updated_at: trx.fn.now(),
    });

    // Adopt any session history the CHR observed before the binding existed.
    await trx('ppp_sessions')
      .where({
        concentrator_id: discovery.concentrator_id,
        ppp_username: discovery.ppp_username,
      })
      .whereNull('device_id')
      .update({ device_id: deviceId });

    const [updated] = await trx('discoveries')
      .where({ id: discoveryId })
      .update({
        state: 'bound',
        bound_device_id: deviceId,
        reviewed_by: reviewedBy,
        reviewed_at: trx.fn.now(),
        updated_at: trx.fn.now(),
      })
      .returning<DiscoveryRow[]>('*');

    return updated;
  });
}

/**
 * Mark a discovery as deliberately not ours (a test account, another MSP), or
 * push it back into the review queue.
 *
 * A `bound` row is refused: clearing `bound_device_id` while the device keeps
 * `ppp_username` is exactly how the two halves of an identity drift apart, and
 * a drifted identity is R4. Unbinding is a device-level gesture (clear
 * `ppp_username` on the device), not a discovery-level one.
 */
export async function setDiscoveryState(
  discoveryId: number,
  state: 'pending' | 'ignored',
  reviewedBy: number,
): Promise<DiscoveryRow> {
  const current = await getDiscovery(discoveryId);
  if (!current) throw new Error(`Discovery ${discoveryId} does not exist`);
  if (current.state === 'bound') {
    throw new Error(
      `Discovery ${discoveryId} is bound to device ${current.bound_device_id}; ` +
        'clear the device PPP username first',
    );
  }

  const [row] = await db('discoveries')
    .where({ id: discoveryId })
    .update({
      state,
      reviewed_by: reviewedBy,
      reviewed_at: db.fn.now(),
      updated_at: db.fn.now(),
    })
    .returning<DiscoveryRow[]>('*');
  if (!row) throw new Error(`Discovery ${discoveryId} does not exist`);

  // The quarantine row has no tenant; its concentrator does, and that is the
  // scope the review screen is served under. One lookup, so the event cannot
  // reach an admin positioned on a different customer.
  const owner = await db('devices')
    .where({ id: row.concentrator_id })
    .first<{ tenant_id: number } | undefined>('tenant_id');
  if (owner) {
    emitToTenantAdmins(owner.tenant_id, SOCKET_EVENTS.DISCOVERY_RESOLVED, {
      id: discoveryId,
      state,
    });
  }
  return row;
}
