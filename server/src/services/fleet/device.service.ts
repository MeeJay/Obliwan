/**
 * ObliWAN — devices and their transports.
 *
 * TWO INVARIANTS THIS FILE ENFORCES, BOTH NON-NEGOTIABLE
 *
 * 1. NO SECRET EVER LEAVES THROUGH THE API. `device_transports.secret_enc` and
 *    `private_key_enc` are never selected into a response shape — not for an
 *    operator, not for an admin. `toPublicTransport()` is the ONLY serialiser,
 *    and it emits `hasSecret: boolean` instead of anything derived from the
 *    ciphertext. Revealing a stored secret is a separate capability
 *    (`SECRET_READ`) with no route behind it in M2, on purpose: an endpoint
 *    that does not exist cannot be mis-permissioned. (Section 8.2.)
 *
 * 2. EVERY QUERY IS TENANT-SCOPED, from the session. A device id in a URL is
 *    an untrusted integer; it is always paired with `tenant_id` in the WHERE
 *    clause rather than fetched and then checked, so there is no window where
 *    the row exists in a variable before the check runs.
 *
 * On `key_version`: the writer stores `currentKeyVersion()` in the SAME
 * statement as `secret_enc`. The column has a DEFAULT of 1, so an INSERT that
 * forgets it succeeds silently and becomes wrong on the day of the first key
 * rotation. There is one place that writes a secret, and it is below.
 */

import {
  DEVICE_FAMILIES,
  FAMILY_BRAND,
  SOCKET_EVENTS,
  TRANSPORT_KINDS,
  type DeviceFamily,
  type TransportKind,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { leaderElection } from '../leaderElection';
import { currentKeyVersion, encrypt } from '../secretVault.service';
import { emitToTenant } from './fleetEvents';
import { toDeviceDto } from './dto';
import { getRouterOsPool, resolveRouterOsTarget } from './routerosPool';
import { readRouterOsIdentity } from './deviceBinding.service';
// Direct import of the service, NOT of `./index`: the barrel re-exports this
// very file, and going through it would close an import cycle whose only
// visible symptom would be an `undefined is not a function` at boot.
import { pppPresence } from './pppPresence.service';

// ============================================================================
// Row shapes
// ============================================================================

export interface DeviceRow {
  id: number;
  uuid: string;
  tenant_id: number;
  site_id: number | null;
  group_id: number | null;
  name: string;
  brand: string;
  family: string;
  model: string | null;
  serial: string | null;
  os_version: string | null;
  role: string;
  concentrator_id: number | null;
  ppp_username: string | null;
  system_identity: string | null;
  tunnel_ip: string | null;
  wan_public_ip: string | null;
  source_ip_hint: string | null;
  status: string;
  is_managed: boolean;
  first_seen_at: Date | null;
  last_seen_at: Date | null;
  notes: string | null;
  created_at: Date;
  updated_at: Date;
}

/** A transport as the API is allowed to show it. Note what is NOT here. */
export interface PublicTransport {
  id: number;
  uuid: string;
  transport: TransportKind;
  enabled: boolean;
  priority: number;
  host: string | null;
  port: number | null;
  username: string | null;
  /** Whether a credential is stored — never the credential, never its length,
   *  never a masked rendering of it. */
  hasSecret: boolean;
  hasPrivateKey: boolean;
  keyVersion: number;
  useTls: boolean;
  tlsFingerprintSha256: string | null;
  params: Record<string, unknown>;
  lastOkAt: string | null;
  lastError: string | null;
}

interface TransportRow {
  id: number;
  uuid: string;
  transport: string;
  enabled: boolean;
  priority: number;
  host: string | null;
  port: number | null;
  username: string | null;
  secret_enc: string | null;
  private_key_enc: string | null;
  key_version: number;
  use_tls: boolean;
  tls_fingerprint_sha256: string | null;
  params: Record<string, unknown> | null;
  last_ok_at: Date | null;
  last_error: string | null;
}

/** The one and only transport serialiser. */
export function toPublicTransport(row: TransportRow): PublicTransport {
  return {
    id: row.id,
    uuid: row.uuid,
    transport: row.transport as TransportKind,
    enabled: row.enabled,
    priority: row.priority,
    host: row.host,
    port: row.port,
    username: row.username,
    hasSecret: row.secret_enc !== null,
    hasPrivateKey: row.private_key_enc !== null,
    keyVersion: row.key_version,
    useTls: row.use_tls,
    tlsFingerprintSha256: row.tls_fingerprint_sha256,
    params: row.params ?? {},
    lastOkAt: row.last_ok_at ? row.last_ok_at.toISOString() : null,
    lastError: row.last_error,
  };
}

// ============================================================================
// Listing
// ============================================================================

export interface ListDevicesFilter {
  siteId?: number;
  role?: string;
  status?: string;
  brand?: string;
  family?: string;
  concentratorId?: number;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface DeviceListItem extends DeviceRow {
  site_code: string | null;
  site_name: string | null;
  /** Open PPP session on the concentrator — the D4 definition of online. */
  ppp_up: boolean;
  ppp_since: string | null;
  verdict: string | null;
}

export async function listDevices(
  tenantId: number,
  filter: ListDevicesFilter = {},
): Promise<{ items: DeviceListItem[]; total: number }> {
  const base = db('devices as d').where('d.tenant_id', tenantId);

  if (filter.siteId !== undefined) base.andWhere('d.site_id', filter.siteId);
  if (filter.role) base.andWhere('d.role', filter.role);
  if (filter.status) base.andWhere('d.status', filter.status);
  if (filter.brand) base.andWhere('d.brand', filter.brand);
  if (filter.family) base.andWhere('d.family', filter.family);
  if (filter.concentratorId !== undefined) base.andWhere('d.concentrator_id', filter.concentratorId);
  if (filter.search) {
    const like = `%${filter.search}%`;
    base.andWhere((q) => {
      q.whereILike('d.name', like)
        .orWhereILike('d.ppp_username', like)
        .orWhereILike('d.serial', like)
        .orWhereILike('d.system_identity', like);
    });
  }

  const [{ count }] = await base.clone().count<{ count: string }[]>('d.id as count');

  const rows = await base
    .clone()
    .leftJoin('sites as s', 's.id', 'd.site_id')
    .leftJoin('ppp_sessions as p', function joinOpen(this: any) {
      this.on('p.device_id', '=', 'd.id').andOnNull('p.ended_at');
    })
    .leftJoin(
      db('reachability_verdicts')
        .distinctOn('device_id')
        .select('device_id', 'verdict')
        .orderBy('device_id')
        .orderBy('ts', 'desc')
        .as('v'),
      'v.device_id',
      'd.id',
    )
    .select<Array<DeviceRow & { site_code: string | null; site_name: string | null; started_at: Date | null; verdict: string | null }>>(
      'd.*',
      's.code as site_code',
      's.name as site_name',
      'p.started_at',
      'v.verdict',
    )
    .orderBy('d.name')
    .limit(filter.limit ?? 200)
    .offset(filter.offset ?? 0);

  return {
    total: Number(count),
    items: rows.map((r) => {
      const { started_at, ...rest } = r;
      return {
        ...rest,
        ppp_up: started_at !== null,
        ppp_since: started_at ? started_at.toISOString() : null,
      } as DeviceListItem;
    }),
  };
}

export async function getDevice(tenantId: number, id: number): Promise<DeviceRow | undefined> {
  return db('devices').where({ id, tenant_id: tenantId }).first<DeviceRow | undefined>();
}

/** Device + its transports (redacted) + health + latest verdict. */
export async function getDeviceDetail(
  tenantId: number,
  id: number,
): Promise<
  | (DeviceRow & {
      transports: PublicTransport[];
      health: Array<{ transport: string; connState: string; circuitState: string; consecutiveFailures: number; nextRetryAt: string | null; lastError: string | null }>;
      pppUp: boolean;
      verdict: string | null;
    })
  | undefined
> {
  const device = await getDevice(tenantId, id);
  if (!device) return undefined;

  const [transports, health, open, verdict] = await Promise.all([
    db('device_transports').where({ device_id: id }).orderBy('priority').select<TransportRow[]>('*'),
    db('device_health')
      .where({ device_id: id })
      .select<Array<{ transport: string; conn_state: string; circuit_state: string; consecutive_failures: number; next_retry_at: Date | null; last_error: string | null }>>('*'),
    db('ppp_sessions').where({ device_id: id }).whereNull('ended_at').first('id'),
    db('reachability_verdicts')
      .where({ device_id: id })
      .orderBy('ts', 'desc')
      .first<{ verdict: string } | undefined>('verdict'),
  ]);

  return {
    ...device,
    transports: transports.map(toPublicTransport),
    health: health.map((h) => ({
      transport: h.transport,
      connState: h.conn_state,
      circuitState: h.circuit_state,
      consecutiveFailures: h.consecutive_failures,
      nextRetryAt: h.next_retry_at ? h.next_retry_at.toISOString() : null,
      lastError: h.last_error,
    })),
    pppUp: !!open,
    verdict: verdict?.verdict ?? null,
  };
}

// ============================================================================
// Create / update / delete
// ============================================================================

export interface CreateDeviceData {
  name: string;
  family: DeviceFamily;
  role?: 'cpe' | 'concentrator';
  siteId?: number | null;
  groupId?: number | null;
  model?: string | null;
  serial?: string | null;
  osVersion?: string | null;
  concentratorId?: number | null;
  pppUsername?: string | null;
  systemIdentity?: string | null;
  tunnelIp?: string | null;
  wanPublicIp?: string | null;
  sourceIpHint?: string | null;
  status?: 'pending' | 'active' | 'quarantined' | 'disabled';
  isManaged?: boolean;
  notes?: string | null;
}

export type UpdateDeviceData = Partial<CreateDeviceData>;

function deviceColumns(data: UpdateDeviceData): Record<string, unknown> {
  const row: Record<string, unknown> = {};
  if (data.name !== undefined) row.name = data.name;
  if (data.family !== undefined) {
    row.family = data.family;
    // brand is DERIVED, never accepted from the client: the client could send
    // a (brand, family) pair that disagrees, and every driver lookup after that
    // would resolve to the wrong dialect.
    row.brand = FAMILY_BRAND[data.family];
  }
  if (data.role !== undefined) row.role = data.role;
  if (data.siteId !== undefined) row.site_id = data.siteId;
  if (data.groupId !== undefined) row.group_id = data.groupId;
  if (data.model !== undefined) row.model = data.model;
  if (data.serial !== undefined) row.serial = data.serial;
  if (data.osVersion !== undefined) row.os_version = data.osVersion;
  if (data.concentratorId !== undefined) row.concentrator_id = data.concentratorId;
  if (data.pppUsername !== undefined) row.ppp_username = data.pppUsername;
  if (data.systemIdentity !== undefined) row.system_identity = data.systemIdentity;
  if (data.tunnelIp !== undefined) row.tunnel_ip = data.tunnelIp;
  if (data.wanPublicIp !== undefined) row.wan_public_ip = data.wanPublicIp;
  if (data.sourceIpHint !== undefined) row.source_ip_hint = data.sourceIpHint;
  if (data.status !== undefined) row.status = data.status;
  if (data.isManaged !== undefined) row.is_managed = data.isManaged;
  if (data.notes !== undefined) row.notes = data.notes;
  return row;
}

/** Cross-tenant references are refused here rather than at the database: the
 *  FKs are tenant-blind by design (a device_group is a tenant-scoped tree, a
 *  site is not reachable from the FK), so the check has to be explicit. */
async function assertReferencesInTenant(
  tenantId: number,
  data: UpdateDeviceData,
  selfId?: number,
): Promise<void> {
  if (data.siteId) {
    const site = await db('sites').where({ id: data.siteId, tenant_id: tenantId }).first('id');
    if (!site) throw new Error(`Site ${data.siteId} does not exist in this tenant`);
  }
  if (data.concentratorId) {
    if (selfId !== undefined && data.concentratorId === selfId) {
      throw new Error('A device cannot be its own concentrator');
    }
    const chr = await db('devices')
      .where({ id: data.concentratorId, tenant_id: tenantId })
      .first<{ role: string } | undefined>('role');
    if (!chr) throw new Error(`Concentrator ${data.concentratorId} does not exist in this tenant`);
    if (chr.role !== 'concentrator') throw new Error(`Device ${data.concentratorId} is not a concentrator`);
  }
  // AUDIT M2/M3 finding 5. This branch used to be missing while `deviceColumns`
  // happily wrote `group_id`, so `POST /api/devices {groupId: <another tenant's
  // group>}` returned 201. The leak is immediate and in READ: the Fleet Query
  // compiler joins `device_groups` on `d.group_id` and scopes on `d.tenant_id`
  // only — as it should — so the device of tenant A displays the group NAME of
  // tenant B, and an id sweep enumerates another customer's group tree.
  // Settings and rights inherit down the group closure as well.
  //
  // Migration 014 poses the composite FK `(group_id, tenant_id) REFERENCES
  // device_groups (id, tenant_id)` that makes this unforgeable from ANY write
  // path. This check stays because it produces the operator-readable message;
  // the constraint stays because this check can be forgotten again.
  if (data.groupId) {
    const group = await db('device_groups')
      .where({ id: data.groupId, tenant_id: tenantId })
      .first('id');
    if (!group) throw new Error(`Group ${data.groupId} does not exist in this tenant`);
  }
}

// ============================================================================
// PPP presence lifecycle — AUDIT M2/M3, finding 4
// ============================================================================

/**
 * Reconcile the presence monitors with what the database now says.
 *
 * `pppPresence.watch()` / `unwatch()` had NO caller outside `startAll()` /
 * `stopAll()` and the self-test recipe. A concentrator declared through the API
 * was therefore not watched until the next process restart or leader
 * failover — `ppp_sessions` stayed empty, `last_seen_at` stayed null, and every
 * CPE behind it was reported `UNREACHABLE`. Symmetrically, deleting a
 * concentrator left its `ConcentratorMonitor` alive, re-opening a stream every
 * 5 s against a device id that no longer resolves, forever.
 *
 * The gestures that change the answer all live in this file, so the hook lives
 * here too. It is:
 *
 *  - IDEMPOTENT — `watch()` returns immediately when already watching and
 *    `unwatch()` when not; calling this after every write is safe.
 *  - GATED ON LEADERSHIP (arbitrage A5) — two replicas each opening
 *    `/ppp/active/listen` on the same CHR would double every session row. A
 *    follower does nothing here; when it wins the election, `startAll()` picks
 *    the whole fleet up.
 *  - CONDITIONED ON A USABLE TRANSPORT — a concentrator with no enabled
 *    `routeros_api` row cannot be listened to, and starting a monitor for it
 *    would only produce a 5-second retry loop and a `markConcentratorDegraded`
 *    per attempt. `createConcentrator()` creates the device BEFORE its
 *    transport, which is exactly that window; the `upsertTransport` call that
 *    follows re-enters here and starts the watch for real.
 *  - NEVER FATAL — presence is a background duty; it must not turn a successful
 *    device write into a 500.
 */
export async function syncConcentratorPresence(
  deviceId: number,
  opts: { restart?: boolean } = {},
): Promise<void> {
  if (!leaderElection.isLeader()) return;

  const row = await db('devices as d')
    .where('d.id', deviceId)
    .first<{ role: string; status: string; transports: string } | undefined>(
      'd.role',
      'd.status',
      db.raw(
        "(SELECT count(*) FROM device_transports t WHERE t.device_id = d.id " +
          "AND t.transport = 'routeros_api' AND t.enabled) as transports",
      ),
    );

  const shouldWatch =
    !!row && row.role === 'concentrator' && row.status !== 'disabled' && Number(row.transports) > 0;

  try {
    if (!shouldWatch) {
      await pppPresence.unwatch(deviceId);
      return;
    }
    // `restart` is for "the target moved under the monitor": the stream is bound
    // to the socket the pool held for the OLD host/credential, and cancelling it
    // before re-opening is what stops a listen from being left registered on the
    // previous box.
    if (opts.restart) await pppPresence.unwatch(deviceId);
    if (!pppPresence.isRunning) return;
    await pppPresence.watch(deviceId);
  } catch (err) {
    logger.warn(
      { err, deviceId },
      'Could not reconcile PPP presence for this concentrator; the next leader ' +
        'election or restart will pick it up',
    );
  }
}

/** Stop watching, whatever the database says. Used on the paths that are about
 *  to make the device un-watchable (delete, transport removal). */
export async function stopConcentratorPresence(deviceId: number): Promise<void> {
  try {
    await pppPresence.unwatch(deviceId);
  } catch (err) {
    logger.warn({ err, deviceId }, 'Could not stop PPP presence for this concentrator');
  }
}

export async function createDevice(tenantId: number, data: CreateDeviceData): Promise<DeviceRow> {
  if (!DEVICE_FAMILIES.includes(data.family)) {
    throw new Error(`Unknown device family '${data.family}'`);
  }
  await assertReferencesInTenant(tenantId, data);

  const [row] = await db('devices')
    .insert({
      ...deviceColumns(data),
      tenant_id: tenantId,
      // A hand-declared device starts `pending`: it has not proven its identity
      // yet, and `active` is a statement about a box that answered.
      status: data.status ?? 'pending',
    })
    .returning<DeviceRow[]>('*');

  emitToTenant(tenantId, SOCKET_EVENTS.DEVICE_CREATED, { device: toDeviceDto(row) });
  if (row.role === 'concentrator') await syncConcentratorPresence(row.id);
  return row;
}

export async function updateDevice(
  tenantId: number,
  id: number,
  data: UpdateDeviceData,
): Promise<DeviceRow | undefined> {
  if (data.family !== undefined && !DEVICE_FAMILIES.includes(data.family)) {
    throw new Error(`Unknown device family '${data.family}'`);
  }
  await assertReferencesInTenant(tenantId, data, id);

  const columns = deviceColumns(data);
  if (Object.keys(columns).length === 0) return getDevice(tenantId, id);

  const [row] = await db('devices')
    .where({ id, tenant_id: tenantId })
    .update({ ...columns, updated_at: db.fn.now() })
    .returning<DeviceRow[]>('*');
  if (row) emitToTenant(tenantId, SOCKET_EVENTS.DEVICE_UPDATED, { device: toDeviceDto(row) });
  // `role` and `status` are the two columns that decide whether this device is
  // watched. Promotion to `concentrator` starts a monitor, demotion to `cpe` or
  // `disabled` stops one; the call is also made when the row IS a concentrator
  // and neither changed, because it is idempotent and cheaper to reason about
  // than a set of conditions that must stay in sync with `syncConcentratorPresence`.
  if (row && (row.role === 'concentrator' || data.role !== undefined)) {
    await syncConcentratorPresence(row.id);
  }
  return row;
}

/**
 * Delete a device.
 *
 * `devices.concentrator_id` is ON DELETE RESTRICT, so deleting a CHR that still
 * has children fails at the database. That is deliberate — it is the presence
 * source of truth for a whole fleet — and the caller turns the constraint
 * violation into a message an operator can act on.
 */
export async function deleteDevice(tenantId: number, id: number): Promise<boolean> {
  // There used to be a pre-DELETE sweep here, pushing every discovery bound to
  // this device back to `pending` by hand, because the schema's ON DELETE SET
  // NULL contradicted its own `CHECK (state <> 'bound' OR bound_device_id IS
  // NOT NULL)` and Postgres refused the delete. That contradiction was fixed in
  // the schema (migration 002: a BEFORE UPDATE trigger moves the row back to
  // `pending` as the FK NULLs the column), so the sweep is gone.
  //
  // It matters that it is gone rather than kept "for safety": a rule enforced
  // in two places is a rule that will be enforced in one of them after the next
  // edit, and the one that survives is never the one you expected.
  //
  // The presence monitor, on the other hand, IS this file's business: nothing
  // in the schema tears it down, and a monitor whose device has been deleted
  // re-opens a stream every 5 s and calls `markConcentratorDegraded` on a row
  // the CASCADE already removed — a loop that only ends with the process
  // (audit M2/M3, finding 4). It is stopped BEFORE the DELETE so that no sweep
  // can run against a half-deleted device, and restored if the DELETE is
  // refused (`concentrator_id` is ON DELETE RESTRICT: a CHR with children
  // cannot be removed, and that attempt must not silently blind the fleet).
  const target = await db('devices')
    .where({ id, tenant_id: tenantId })
    .first<{ role: string } | undefined>('role');
  const wasConcentrator = target?.role === 'concentrator';
  if (wasConcentrator) await stopConcentratorPresence(id);

  let deleted: number;
  try {
    deleted = await db('devices').where({ id, tenant_id: tenantId }).delete();
  } catch (err) {
    if (wasConcentrator) await syncConcentratorPresence(id);
    throw err;
  }
  if (deleted === 0 && wasConcentrator) await syncConcentratorPresence(id);
  if (deleted > 0) emitToTenant(tenantId, SOCKET_EVENTS.DEVICE_DELETED, { deviceId: id });
  return deleted > 0;
}

/** How many CPEs still point at this concentrator. Used to give the operator a
 *  real answer instead of a foreign-key error string. */
export async function concentratorChildCount(tenantId: number, id: number): Promise<number> {
  const [{ count }] = await db('devices')
    .where({ concentrator_id: id, tenant_id: tenantId })
    .count<{ count: string }[]>('id as count');
  return Number(count);
}

// ============================================================================
// Transports and the vault
// ============================================================================

export interface UpsertTransportData {
  enabled?: boolean;
  priority?: number;
  host?: string | null;
  port?: number | null;
  username?: string | null;
  /** Plaintext in, ciphertext stored. Absent = leave the stored one alone;
   *  explicit `null` = delete it. */
  secret?: string | null;
  privateKey?: string | null;
  useTls?: boolean;
  tlsFingerprintSha256?: string | null;
  params?: Record<string, unknown>;
}

/**
 * Create or replace one channel of one device.
 *
 * The vault write is the only interesting part: `secret_enc` and `key_version`
 * are set in the same statement, because a row whose ciphertext and version
 * disagree is undecryptable and nothing will notice until the next rotation.
 */
export async function upsertTransport(
  tenantId: number,
  deviceId: number,
  transport: TransportKind,
  data: UpsertTransportData,
): Promise<PublicTransport> {
  if (!TRANSPORT_KINDS.includes(transport)) {
    throw new Error(`Unknown transport '${transport}'`);
  }
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);

  const columns: Record<string, unknown> = {};
  if (data.enabled !== undefined) columns.enabled = data.enabled;
  if (data.priority !== undefined) columns.priority = data.priority;
  if (data.host !== undefined) columns.host = data.host;
  if (data.port !== undefined) columns.port = data.port;
  if (data.username !== undefined) columns.username = data.username;
  if (data.useTls !== undefined) columns.use_tls = data.useTls;
  if (data.tlsFingerprintSha256 !== undefined) {
    columns.tls_fingerprint_sha256 = data.tlsFingerprintSha256;
  }
  if (data.params !== undefined) {
    // params must never carry a credential; the shape is documented per
    // transport by the driver layer and validated by the Zod schema.
    columns.params = JSON.stringify(data.params);
  }
  if (data.secret !== undefined) {
    columns.secret_enc = data.secret === null ? null : encrypt(data.secret);
    columns.key_version = currentKeyVersion();
  }
  if (data.privateKey !== undefined) {
    columns.private_key_enc = data.privateKey === null ? null : encrypt(data.privateKey);
    columns.key_version = currentKeyVersion();
  }

  const [row] = await db('device_transports')
    .insert({ device_id: deviceId, transport, ...columns })
    .onConflict(['device_id', 'transport'])
    .merge({ ...columns, updated_at: db.fn.now() })
    .returning<TransportRow[]>('*');

  logger.info(
    { deviceId, transport, secretChanged: data.secret !== undefined },
    'Device transport saved',
  );

  if (transport === 'routeros_api') {
    // The pool compares a target fingerprint on every `acquire()` since audit
    // M2/M3 finding 3, so a stale session would be dropped lazily anyway. Doing
    // it here as well makes the rotation take effect on the spot rather than on
    // the next dial, which is what an operator who just changed a password
    // expects — and it is the only way the CHR's `/ppp/active/listen`, which
    // holds the socket open indefinitely, ever notices.
    getRouterOsPool().close(String(deviceId));
    if (device.role === 'concentrator') {
      await syncConcentratorPresence(deviceId, { restart: true });
    }
  }
  return toPublicTransport(row);
}

export async function listTransports(
  tenantId: number,
  deviceId: number,
): Promise<PublicTransport[]> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);
  const rows = await db('device_transports')
    .where({ device_id: deviceId })
    .orderBy('priority')
    .select<TransportRow[]>('*');
  return rows.map(toPublicTransport);
}

export async function deleteTransport(
  tenantId: number,
  deviceId: number,
  transport: TransportKind,
): Promise<boolean> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);
  const n = await db('device_transports').where({ device_id: deviceId, transport }).delete();
  if (n > 0 && transport === 'routeros_api') {
    getRouterOsPool().close(String(deviceId));
    // No transport left to listen on: a monitor kept alive here would retry
    // every 5 s against a device that can no longer be dialled.
    if (device.role === 'concentrator') await stopConcentratorPresence(deviceId);
  }
  return n > 0;
}

// ============================================================================
// Connection test
// ============================================================================

export interface ConnectionTestResult {
  ok: boolean;
  transport: TransportKind;
  /** Address actually dialled — reported so an operator can see that a stale
   *  tunnel IP is what failed, rather than guessing. */
  dialled: string | null;
  latencyMs: number | null;
  identity: { systemIdentity: string | null; serial: string | null; pppUsername: string | null } | null;
  tlsFingerprintSha256: string | null;
  error: string | null;
}

/**
 * "Does this credential work?" — the button next to a transport row.
 *
 * Only `routeros_api` is wired in M2. The other four channels have transports
 * written (`ssh`, `snmp`, `rest`) but none of them has ever spoken to real
 * hardware, so this returns an explicit refusal naming the milestone rather
 * than a green tick that means nothing.
 */
export async function testTransport(
  tenantId: number,
  deviceId: number,
  transport: TransportKind,
): Promise<ConnectionTestResult> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);

  const base: ConnectionTestResult = {
    ok: false,
    transport,
    dialled: null,
    latencyMs: null,
    identity: null,
    tlsFingerprintSha256: null,
    error: null,
  };

  if (transport !== 'routeros_api') {
    return {
      ...base,
      error: `Connection test for '${transport}' is not wired yet (milestone M3 for snmp, M6 for ssh/rest)`,
    };
  }

  const started = Date.now();
  try {
    const target = await resolveRouterOsTarget(deviceId);
    const identity = await getRouterOsPool().withConnection(target, (conn) =>
      readRouterOsIdentity(conn),
    );
    const latencyMs = Date.now() - started;

    await db('device_transports')
      .where({ device_id: deviceId, transport })
      .update({ last_ok_at: db.fn.now(), last_error: null, updated_at: db.fn.now() });

    return {
      ...base,
      ok: true,
      dialled: target.host,
      latencyMs,
      identity,
    };
  } catch (err) {
    // The transport layer's errors are already redacted (proven by its own
    // self-test); truncating is belt-and-braces before it reaches a column.
    const message = (err instanceof Error ? err.message : String(err)).slice(0, 500);
    await db('device_transports')
      .where({ device_id: deviceId, transport })
      .update({ last_error: message, updated_at: db.fn.now() });
    return { ...base, latencyMs: Date.now() - started, error: message };
  }
}

/**
 * "Test this device" — every ENABLED channel it has, once, in priority order.
 *
 * This is the device-level gesture behind the button on the detail page;
 * `testTransport()` above is the channel-level one. Both exist because they
 * answer different questions ("can we reach this box at all?" vs "does this
 * credential work?").
 *
 * Sequential on purpose. Opening four channels to the same box at once is how
 * a management CPU on a small CPE gets saturated by a diagnostic, and the
 * RouterOS channel in particular shares one pooled socket per device whose
 * dial budget is global (risk R5). A device with four channels takes four
 * round trips; that is the correct cost of the question.
 *
 * A failing channel is a RESULT, not an error: the operator asked, and "no"
 * is the answer. Only a device that does not exist in this tenant throws.
 */
export async function testAllTransports(
  tenantId: number,
  deviceId: number,
): Promise<ConnectionTestResult[]> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);

  const rows = await db('device_transports')
    .where({ device_id: deviceId, enabled: true })
    .orderBy('priority')
    .select<Array<{ transport: string }>>('transport');

  const results: ConnectionTestResult[] = [];
  for (const row of rows) {
    results.push(await testTransport(tenantId, deviceId, row.transport as TransportKind));
  }
  return results;
}

// ============================================================================
// Session history
// ============================================================================

export async function deviceSessions(
  tenantId: number,
  deviceId: number,
  limit = 50,
): Promise<
  Array<{
    id: string;
    pppUsername: string;
    tunnelIp: string | null;
    callerIp: string | null;
    startedAt: string;
    endedAt: string | null;
    durationSeconds: number | null;
    disconnectReason: string | null;
  }>
> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);
  const rows = await db('ppp_sessions')
    .where({ device_id: deviceId })
    .orderBy('started_at', 'desc')
    .limit(limit)
    .select<
      Array<{
        id: string;
        ppp_username: string;
        tunnel_ip: string | null;
        caller_ip: string | null;
        started_at: Date;
        ended_at: Date | null;
        duration_seconds: number | null;
        disconnect_reason: string | null;
      }>
    >('*');
  return rows.map((r) => ({
    id: String(r.id),
    pppUsername: r.ppp_username,
    tunnelIp: r.tunnel_ip,
    callerIp: r.caller_ip,
    startedAt: r.started_at.toISOString(),
    endedAt: r.ended_at ? r.ended_at.toISOString() : null,
    durationSeconds: r.duration_seconds,
    disconnectReason: r.disconnect_reason,
  }));
}

export async function deviceVerdicts(
  tenantId: number,
  deviceId: number,
  limit = 50,
): Promise<
  Array<{
    ts: string;
    verdict: string;
    confidence: number;
    reason: string | null;
    signals: { pppUp: boolean | null; snmpOk: boolean | null; externalOk: boolean | null; cwmpRecent: boolean | null };
  }>
> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);
  const rows = await db('reachability_verdicts')
    .where({ device_id: deviceId })
    .orderBy('ts', 'desc')
    .limit(limit)
    .select<
      Array<{
        ts: Date;
        verdict: string;
        confidence: string;
        reason: string | null;
        ppp_up: boolean | null;
        snmp_ok: boolean | null;
        external_ok: boolean | null;
        cwmp_recent: boolean | null;
      }>
    >('*');
  return rows.map((r) => ({
    ts: r.ts.toISOString(),
    verdict: r.verdict,
    confidence: Number(r.confidence),
    reason: r.reason,
    signals: {
      pppUp: r.ppp_up,
      snmpOk: r.snmp_ok,
      externalOk: r.external_ok,
      cwmpRecent: r.cwmp_recent,
    },
  }));
}

/** Concentrators visible to a tenant. The Discoveries page needs this because
 *  `discoveries` has no tenant column of its own (quarantine is pre-tenant). */
export async function concentratorIdsForTenant(tenantId: number): Promise<number[]> {
  return db('devices').where({ tenant_id: tenantId, role: 'concentrator' }).pluck<number[]>('id');
}
