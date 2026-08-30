/**
 * ObliWAN F6 — DETECTION OF A REPLACED DEVICE.
 *
 * ┌─ THE GAP THIS FILLS ──────────────────────────────────────────────────────┐
 * │ `deviceBinding.assertTargetBinding()` verifies identity before every      │
 * │ write — `ppp_username` + `system_identity` + `serial`, on a fresh socket, │
 * │ fail closed. It answers "is this the box I recorded?". Nothing answers    │
 * │ "is this the same box it was LAST TIME?", and the data needed to answer   │
 * │ it is read on every single connection and dropped on the floor:           │
 * │                                                                          │
 * │   device.service.testTransport()      -> readRouterOsIdentity() -> HTTP   │
 * │   deviceBinding.assertTargetBinding() -> readRouterOsIdentity() -> compare│
 * │   change/backup.openDeviceSession()   -> readRouterOsIdentity() -> compare│
 * │                                                                          │
 * │ None of the three writes it down. A serial that moves is a chassis that   │
 * │ was swapped: RMA, failure, theft, or a technician who replaced hardware   │
 * │ and told nobody. The day that site comes back with a blank router, the    │
 * │ drift explodes and nobody can say why.                                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT THIS SERVICE DOES AND, MORE IMPORTANTLY, WHAT IT REFUSES TO DO ─────┐
 * │ IT READS. `/system/identity/print`, `/system/routerboard/print` and       │
 * │ `/system/resource/print` — three `print` commands, no argument, no        │
 * │ interpolation, no `set`, no `add`. DECISION D3 IS UNTOUCHED: nothing      │
 * │ outside `change_jobs` writes to an equipment, and nothing here writes to  │
 * │ an equipment at all.                                                      │
 * │                                                                          │
 * │ IT DOES NOT WRITE TO `devices`. Not `serial`, not `system_identity`, not  │
 * │ `os_version`, not `status`. That registry belongs to `device.service` and │
 * │ to `assertTargetBinding()`'s opportunistic learning. A watcher that       │
 * │ repaired the thing it watches would erase the very evidence of the        │
 * │ change on the next pass.                                                  │
 * │                                                                          │
 * │ IT DOES NOT TOUCH BASELINES, SNAPSHOTS, DRIFT FINDINGS OR EXCEPTIONS.     │
 * │ This is the second trap of the brief and the more dangerous one. A        │
 * │ replacement DOES invalidate what rested on the old box — the last         │
 * │ `config_snapshots` row is no longer a reference and the drift that        │
 * │ follows is not drift. The right response is to SAY SO and let a human     │
 * │ decide. `baselineTrust()` below is that sentence, and it is a SELECT.     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * TENANT SCOPE (R4). Every exported function takes `tenantId` as its first
 * argument and there is no "current tenant" read from anything in this file.
 * `assertDeviceInTenant()` is the single door: it resolves the device with
 * `WHERE d.id = ? AND d.tenant_id = ?` and every other query in the file is
 * either scoped on `tenant_id` directly (the three F6 tables all carry it, and
 * the composite FK ties it to the device's) or joined through `devices` for
 * the one table that has no tenant column (`config_snapshots`, migration 007).
 *
 * NO IDENTIFICATION BY IP (arbitrage A6). Not one line of this file reads a
 * source address, a caller id or an `X-Forwarded-For`. The identity of a box
 * is what the box says about itself; the address is only where we dialled, and
 * it is not stored.
 *
 * NO SECRET LEAVES THIS FILE. `resolveRouterOsTarget()` decrypts a vault
 * credential into a `RouterOsTarget` that lives for the duration of one dial
 * and is never logged, never returned and never stored. The three F6 tables
 * have no credential column. Every object returned by an exported function
 * below is built field by field from identity columns.
 */

import {
  IDENTITY_ATTRIBUTES,
  IDENTITY_EVENT_SEVERITIES,
  IDENTITY_OBSERVATION_SOURCES,
  classifyIdentityChange,
  identityAckNoteProblem,
  isBaselineInvalidatingKind,
  isFirmwareEventKind,
  normalizeIdentitySnapshot,
  type IdentityAttributeName,
  type IdentityChange,
  type IdentityEventKind,
  type IdentityEventSeverity,
  type IdentityObservationSource,
  type IdentitySnapshot,
} from '@obliwan/shared/dist/identity';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { RouterOsTrapError, type RouterOsConnection } from '../transport/routeros';
import { getRouterOsPool, resolveRouterOsTarget } from './routerosPool';

// ============================================================================
// Errors
// ============================================================================

export class IdentityWatchError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'IdentityWatchError';
    this.status = status;
  }
}

// ============================================================================
// Public shapes
// ============================================================================

export interface IdentityReference extends IdentitySnapshot {
  deviceId: number;
  serialSeenAt: string | null;
  systemIdentitySeenAt: string | null;
  firstObservedAt: string;
  lastObservedAt: string;
  observationCount: number;
  /** How many observations answered no usable serial. Trap 1 made visible. */
  blankSerialCount: number;
}

export interface IdentityObservationRecord extends IdentitySnapshot {
  id: number;
  deviceId: number;
  source: IdentityObservationSource;
  firstSeenAt: string;
  lastSeenAt: string;
  seenCount: number;
}

export interface IdentityEventRecord {
  id: number;
  uuid: string;
  deviceId: number;
  deviceName: string | null;
  observationId: number;
  kind: IdentityEventKind;
  severity: IdentityEventSeverity;
  changedAttributes: IdentityAttributeName[];
  previous: IdentitySnapshot;
  observed: IdentitySnapshot;
  invalidatesBaseline: boolean;
  reason: string;
  detectedAt: string;
  acknowledgedAt: string | null;
  acknowledgedBy: number | null;
  acknowledgement: string | null;
}

export interface RecordOutcome {
  deviceId: number;
  /** `null` when the read answered nothing usable — nothing was stored. */
  observationId: number | null;
  /** `true` when the observation matched the newest one and only bumped its
   *  counter. Not an error: it is the normal outcome of a healthy fleet. */
  deduplicated: boolean;
  events: IdentityEventRecord[];
  reference: IdentityReference | null;
  unanswered: IdentityAttributeName[];
  /** Trap 1, stated in the response: the box gave no serial this time, so no
   *  serial comparison was made and no replacement could be reported. */
  serialUnanswered: boolean;
}

export interface ObserveOutcome extends RecordOutcome {
  ok: boolean;
  /** A failed dial is a RESULT, not an exception: the operator asked, and
   *  "the box did not answer" is the answer. */
  error: string | null;
}

export interface BaselineTrustReport {
  deviceId: number;
  /** The newest config snapshot of this device, or `null` if it has none. */
  snapshot: { id: number; capturedAt: string } | null;
  /** `false` when an UNACKNOWLEDGED replacement or factory reset happened at
   *  or after that snapshot was captured. */
  trusted: boolean;
  /** The events standing between the snapshot and trust. Never mutated. */
  blockingEvents: IdentityEventRecord[];
  /** Same box, different firmware since the snapshot: not an invalidation,
   *  but an export it is compared against will legitimately differ. */
  firmwareChangedSince: boolean;
  reason: string;
}

// ============================================================================
// Row shapes
// ============================================================================

interface ReferenceRow {
  device_id: number;
  tenant_id: number;
  serial: string | null;
  system_identity: string | null;
  model: string | null;
  os_version: string | null;
  serial_seen_at: Date | null;
  system_identity_seen_at: Date | null;
  first_observed_at: Date;
  last_observed_at: Date;
  last_observation_id: string | number | null;
  observation_count: string | number;
  blank_serial_count: string | number;
}

interface ObservationRow {
  id: string | number;
  device_id: number;
  serial: string | null;
  system_identity: string | null;
  model: string | null;
  os_version: string | null;
  source: string;
  first_seen_at: Date;
  last_seen_at: Date;
  seen_count: number;
}

interface EventRow {
  id: string | number;
  uuid: string;
  device_id: number;
  device_name?: string | null;
  observation_id: string | number;
  kind: string;
  severity: string;
  changed_attributes: string[];
  previous_serial: string | null;
  observed_serial: string | null;
  previous_system_identity: string | null;
  observed_system_identity: string | null;
  previous_model: string | null;
  observed_model: string | null;
  previous_os_version: string | null;
  observed_os_version: string | null;
  invalidates_baseline: boolean;
  reason: string;
  detected_at: Date;
  acknowledged_at: Date | null;
  acknowledged_by: number | null;
  acknowledgement: string | null;
}

interface DeviceRow {
  id: number;
  tenant_id: number;
  name: string;
  brand: string;
  status: string;
  serial: string | null;
  system_identity: string | null;
  model: string | null;
  os_version: string | null;
}

// ============================================================================
// Helpers
// ============================================================================

/** `bigint` arrives from `pg` as a string. Every count in this file goes
 *  through here so no response ever carries `"12"` where the client expects
 *  `12`. */
function asNumber(value: string | number | null | undefined): number {
  if (value === null || value === undefined) return 0;
  return typeof value === 'number' ? value : Number.parseInt(value, 10);
}

function iso(value: Date | null): string | null {
  return value ? value.toISOString() : null;
}

function toReference(row: ReferenceRow): IdentityReference {
  return {
    deviceId: row.device_id,
    serial: row.serial,
    systemIdentity: row.system_identity,
    model: row.model,
    osVersion: row.os_version,
    serialSeenAt: iso(row.serial_seen_at),
    systemIdentitySeenAt: iso(row.system_identity_seen_at),
    firstObservedAt: row.first_observed_at.toISOString(),
    lastObservedAt: row.last_observed_at.toISOString(),
    observationCount: asNumber(row.observation_count),
    blankSerialCount: asNumber(row.blank_serial_count),
  };
}

function toObservation(row: ObservationRow): IdentityObservationRecord {
  return {
    id: asNumber(row.id),
    deviceId: row.device_id,
    serial: row.serial,
    systemIdentity: row.system_identity,
    model: row.model,
    osVersion: row.os_version,
    source: row.source as IdentityObservationSource,
    firstSeenAt: row.first_seen_at.toISOString(),
    lastSeenAt: row.last_seen_at.toISOString(),
    seenCount: row.seen_count,
  };
}

function toEvent(row: EventRow): IdentityEventRecord {
  return {
    id: asNumber(row.id),
    uuid: row.uuid,
    deviceId: row.device_id,
    deviceName: row.device_name ?? null,
    observationId: asNumber(row.observation_id),
    kind: row.kind as IdentityEventKind,
    severity: row.severity as IdentityEventSeverity,
    changedAttributes: row.changed_attributes as IdentityAttributeName[],
    previous: {
      serial: row.previous_serial,
      systemIdentity: row.previous_system_identity,
      model: row.previous_model,
      osVersion: row.previous_os_version,
    },
    observed: {
      serial: row.observed_serial,
      systemIdentity: row.observed_system_identity,
      model: row.observed_model,
      osVersion: row.observed_os_version,
    },
    invalidatesBaseline: row.invalidates_baseline,
    reason: row.reason,
    detectedAt: row.detected_at.toISOString(),
    acknowledgedAt: iso(row.acknowledged_at),
    acknowledgedBy: row.acknowledged_by,
    acknowledgement: row.acknowledgement,
  };
}

const EVENT_COLUMNS = [
  'e.id',
  'e.uuid',
  'e.device_id',
  'e.observation_id',
  'e.kind',
  'e.severity',
  'e.changed_attributes',
  'e.previous_serial',
  'e.observed_serial',
  'e.previous_system_identity',
  'e.observed_system_identity',
  'e.previous_model',
  'e.observed_model',
  'e.previous_os_version',
  'e.observed_os_version',
  'e.invalidates_baseline',
  'e.reason',
  'e.detected_at',
  'e.acknowledged_at',
  'e.acknowledged_by',
  'e.acknowledgement',
] as const;

/**
 * THE tenant door. Every exported function in this file goes through it before
 * touching anything, and it is the reason no query below has to prove its own
 * scope: a device that is not in this tenant produces a 404 here and the
 * function returns before any other row is read.
 *
 * A device belonging to another customer is a 404 and never a 403 — a 403
 * confirms the id exists, which on a serial `devices.id` is an enumeration
 * oracle over another MSP customer's fleet.
 */
async function assertDeviceInTenant(
  tenantId: number,
  deviceId: number,
  trx?: Knex.Transaction,
): Promise<DeviceRow> {
  const q = (trx ?? db)('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<DeviceRow | undefined>(
      'id',
      'tenant_id',
      'name',
      'brand',
      'status',
      'serial',
      'system_identity',
      'model',
      'os_version',
    );
  const row = await q;
  if (!row) throw new IdentityWatchError(404, `Device ${deviceId} does not exist in this tenant`);
  return row;
}

// ============================================================================
// Reading identity off a live RouterOS box — THREE `print` COMMANDS
// ============================================================================

/**
 * `!trap` = "this menu does not exist here". A CHR has no RouterBOARD and says
 * so with a trap; that is an ANSWER, not a failure, and it is the origin of
 * trap 1 — the serial is legitimately absent forever on every virtual
 * concentrator in the fleet.
 */
async function optionalRow(
  conn: RouterOsConnection,
  path: string,
): Promise<Record<string, string> | null> {
  try {
    return await conn.queryFirst([path]);
  } catch (err) {
    if (err instanceof RouterOsTrapError) return null;
    throw err;
  }
}

/**
 * The four attributes, off one connection.
 *
 * `deviceBinding.readRouterOsIdentity()` reads three of the values this needs
 * and is deliberately NOT reused: it also opens `/interface/l2tp-client/print`
 * to read `ppp_username`, which F6 does not watch (it is our provisioning key,
 * not something the box IS — see `shared/src/identity.ts`), and it returns no
 * model and no firmware version. Calling it and then issuing two more commands
 * would cost a fourth round trip on a small CPE's management CPU for a field
 * this feature throws away.
 *
 * EVERY WORD SENT HERE IS A LITERAL IN THIS FILE. There is no interpolation,
 * no caller-supplied path and no argument of any kind, so there is nothing to
 * escape per dialect: the three strings below are the entire vocabulary this
 * service speaks to an equipment.
 */
export async function readFullIdentity(conn: RouterOsConnection): Promise<IdentitySnapshot> {
  const identity = await optionalRow(conn, '/system/identity/print');
  const routerboard = await optionalRow(conn, '/system/routerboard/print');
  const resource = await optionalRow(conn, '/system/resource/print');

  return normalizeIdentitySnapshot({
    systemIdentity: identity?.name ?? null,
    // `serial-number` is absent on a CHR and occasionally omitted by a busy
    // physical box. Both land on `null`, which decision 1 carries forward.
    serial: routerboard?.['serial-number'] ?? null,
    // The RouterBOARD model is the precise one ("RB760iGS"); `board-name` from
    // /system/resource is the fallback and is what a CHR answers ("CHR").
    model: routerboard?.model ?? resource?.['board-name'] ?? null,
    osVersion: resource?.version ?? null,
  });
}

// ============================================================================
// Recording an observation — the heart of F6
// ============================================================================

export interface RecordOptions {
  source: IdentityObservationSource;
}

/**
 * Store one observed identity, classify what changed, and append the events.
 *
 * WHY A TRANSACTION AND AN ADVISORY LOCK
 * Two observations of the same device landing at once would both read the same
 * reference, both classify against it, and both append the same event — or
 * worse, the second would compare against a reference the first had already
 * moved, and a genuine replacement would be classified as "no change". The
 * lock is per device and per transaction; it is released by COMMIT.
 * `device_identity_events_obs_kind_uq` is the belt to this pair of braces.
 *
 * WHERE THE COMPARISON REFERENCE COMES FROM, AND WHY THAT ORDER
 *   1. `device_identity_reference` if F6 has ever observed this device;
 *   2. otherwise the `devices` registry row — `serial`, `system_identity`,
 *      `model`, `os_version` as they stand.
 * Step 2 is what makes the FIRST F6 observation useful: a device recorded with
 * serial X that now answers Y fires a replacement immediately, instead of
 * quietly adopting Y as its reference and reporting the swap never.
 *
 * NOTHING IS ACCEPTED FROM AN HTTP BODY HERE. `observed` comes from a socket
 * to the equipment, `source` is a server-side literal at the call site, and
 * `tenantId` comes from `requireTenant`. There is no caller-driven parameter
 * in this function that can change a verdict.
 */
export async function recordIdentityObservation(
  tenantId: number,
  deviceId: number,
  observed: Partial<IdentitySnapshot>,
  options: RecordOptions,
): Promise<RecordOutcome> {
  return db.transaction(async (trx) => {
    const device = await assertDeviceInTenant(tenantId, deviceId, trx);

    // `source` is a server-side literal at every call site, and this checks it
    // anyway. `recordIdentityObservation()` is exported so that the three
    // services that already read identity on every connection
    // (`assertTargetBinding`, `openDeviceSession`, `testTransport`) can feed
    // it without a round trip of their own — and a future caller passing a word
    // the vocabulary does not contain must be told so here, in a sentence,
    // rather than by `device_identity_observations_source_chk` five statements
    // later with the transaction already half-written.
    if (!(IDENTITY_OBSERVATION_SOURCES as readonly string[]).includes(options.source)) {
      throw new IdentityWatchError(
        400,
        `Unknown observation source '${options.source}'; expected one of `
          + IDENTITY_OBSERVATION_SOURCES.join(', '),
      );
    }

    // Serialise every observation of one device. `pg_advisory_xact_lock` takes
    // two int4s; the first is a namespace constant for F6 so this lock cannot
    // collide with another feature's lock on the same device id.
    await trx.raw('SELECT pg_advisory_xact_lock(?, ?)', [0x0f6, deviceId]);

    const existing = await trx('device_identity_reference')
      .where({ device_id: deviceId, tenant_id: tenantId })
      .first<ReferenceRow | undefined>('*');

    const comparisonReference: IdentitySnapshot | null = existing
      ? {
          serial: existing.serial,
          systemIdentity: existing.system_identity,
          model: existing.model,
          osVersion: existing.os_version,
        }
      : {
          serial: device.serial,
          systemIdentity: device.system_identity,
          model: device.model,
          osVersion: device.os_version,
        };

    const verdict = classifyIdentityChange(comparisonReference, observed);
    const serialUnanswered = verdict.unanswered.includes('serial');

    if (verdict.empty) {
      // The box answered nothing usable. That is a fact about the network, not
      // about the box, and `device_identity_observations_nonempty_chk` would
      // refuse the row anyway. Nothing is written — in particular the
      // reference is NOT touched, so a flaky read cannot erode it.
      logger.debug(
        { tenantId, deviceId, source: options.source },
        'F6: identity read answered nothing usable; nothing recorded',
      );
      return {
        deviceId,
        observationId: null,
        deduplicated: false,
        events: [],
        reference: existing ? toReference(existing) : null,
        unanswered: verdict.unanswered,
        serialUnanswered,
      };
    }

    const obs = normalizeIdentitySnapshot(observed);

    // ── The compressed history (decision 1 of migration 025) ───────────────
    const newest = await trx('device_identity_observations')
      .where({ tenant_id: tenantId, device_id: deviceId })
      .orderBy('id', 'desc')
      .first<ObservationRow | undefined>('*');

    const identical =
      newest !== undefined &&
      newest.serial === obs.serial &&
      newest.system_identity === obs.systemIdentity &&
      newest.model === obs.model &&
      newest.os_version === obs.osVersion;

    let observationId: number;
    if (identical && newest) {
      await trx('device_identity_observations')
        // `tenant_id` here as well as in the SELECT that produced `newest.id`:
        // no write in this file is allowed to be the one place that trusts an
        // id it was handed rather than the tenant it belongs to.
        .where({ id: newest.id, tenant_id: tenantId, device_id: deviceId })
        .update({
          last_seen_at: trx.raw('clock_timestamp()'),
          seen_count: trx.raw('seen_count + 1'),
        });
      observationId = asNumber(newest.id);
    } else {
      const [inserted] = await trx('device_identity_observations')
        .insert({
          tenant_id: tenantId,
          device_id: deviceId,
          serial: obs.serial,
          system_identity: obs.systemIdentity,
          model: obs.model,
          os_version: obs.osVersion,
          source: options.source,
        })
        .returning<Array<{ id: string | number }>>('id');
      observationId = asNumber(inserted.id);
    }

    // ── The events. Append-only; the unique index makes a retry idempotent. ─
    const stored: IdentityEventRecord[] = [];
    for (const change of verdict.events) {
      const rows = await trx('device_identity_events')
        .insert(eventColumns(tenantId, deviceId, observationId, change))
        .onConflict(['observation_id', 'kind'])
        .ignore()
        .returning<EventRow[]>([...EVENT_COLUMNS].map((c) => c.replace('e.', '')));
      for (const row of rows) stored.push({ ...toEvent(row), deviceName: device.name });
    }

    // ── The sticky reference (trap 1) ──────────────────────────────────────
    const reference = await upsertReference(trx, {
      tenantId,
      deviceId,
      carried: verdict.reference,
      confirmedSerial: obs.serial !== null,
      confirmedIdentity: obs.systemIdentity !== null,
      observationId,
      blankSerial: serialUnanswered,
      existing,
    });

    if (stored.length > 0) {
      logger.info(
        {
          tenantId,
          deviceId,
          source: options.source,
          kinds: stored.map((e) => e.kind),
          // Deliberately NOT logging the serials: an identity value is not a
          // secret, but a log line is the one place §8.2 says to stay narrow.
        },
        'F6: identity change detected',
      );
    }

    return {
      deviceId,
      observationId,
      deduplicated: identical,
      events: stored,
      reference,
      unanswered: verdict.unanswered,
      serialUnanswered,
    };
  });
}

function eventColumns(
  tenantId: number,
  deviceId: number,
  observationId: number,
  change: IdentityChange,
): Record<string, unknown> {
  // `invalidates_baseline` is recomputed from the kind rather than copied from
  // the change object, and migration 025 poses the same rule as a CHECK. Two
  // statements of one rule, so a future caller that hand-builds an
  // `IdentityChange` cannot mark a rename as invalidating.
  return {
    tenant_id: tenantId,
    device_id: deviceId,
    observation_id: observationId,
    kind: change.kind,
    severity: change.severity,
    changed_attributes: change.changed,
    previous_serial: change.previous.serial,
    observed_serial: change.observed.serial,
    previous_system_identity: change.previous.systemIdentity,
    observed_system_identity: change.observed.systemIdentity,
    previous_model: change.previous.model,
    observed_model: change.observed.model,
    previous_os_version: change.previous.osVersion,
    observed_os_version: change.observed.osVersion,
    invalidates_baseline: isBaselineInvalidatingKind(change.kind),
    reason: change.reason,
  };
}

interface UpsertArgs {
  tenantId: number;
  deviceId: number;
  carried: IdentitySnapshot;
  confirmedSerial: boolean;
  confirmedIdentity: boolean;
  observationId: number;
  blankSerial: boolean;
  existing: ReferenceRow | undefined;
}

async function upsertReference(
  trx: Knex.Transaction,
  args: UpsertArgs,
): Promise<IdentityReference> {
  const now = new Date();
  // A `*_seen_at` moves only when a BOX answered that attribute. Carried
  // values keep the timestamp they had — or `null` when they were seeded from
  // the `devices` registry and no box has confirmed them to F6 yet.
  const serialSeenAt = args.confirmedSerial ? now : (args.existing?.serial_seen_at ?? null);
  const identitySeenAt = args.confirmedIdentity
    ? now
    : (args.existing?.system_identity_seen_at ?? null);

  const [row] = await trx('device_identity_reference')
    .insert({
      device_id: args.deviceId,
      tenant_id: args.tenantId,
      serial: args.carried.serial,
      system_identity: args.carried.systemIdentity,
      model: args.carried.model,
      os_version: args.carried.osVersion,
      serial_seen_at: args.carried.serial === null ? null : serialSeenAt,
      system_identity_seen_at: args.carried.systemIdentity === null ? null : identitySeenAt,
      last_observation_id: args.observationId,
      last_observed_at: trx.raw('clock_timestamp()'),
      observation_count: 1,
      blank_serial_count: args.blankSerial ? 1 : 0,
    })
    .onConflict('device_id')
    .merge({
      serial: args.carried.serial,
      system_identity: args.carried.systemIdentity,
      model: args.carried.model,
      os_version: args.carried.osVersion,
      serial_seen_at: args.carried.serial === null ? null : serialSeenAt,
      system_identity_seen_at: args.carried.systemIdentity === null ? null : identitySeenAt,
      last_observation_id: args.observationId,
      last_observed_at: trx.raw('clock_timestamp()'),
      observation_count: trx.raw('device_identity_reference.observation_count + 1'),
      blank_serial_count: trx.raw(
        'device_identity_reference.blank_serial_count + ?',
        [args.blankSerial ? 1 : 0],
      ),
    })
    .returning<ReferenceRow[]>('*');
  return toReference(row);
}

// ============================================================================
// Observing a live device
// ============================================================================

export interface ObserveOptions {
  source?: IdentityObservationSource;
}

/**
 * Dial the device, read its identity, record the observation.
 *
 * READ-ONLY ON THE EQUIPMENT (D3). Three `print` commands, no argument.
 *
 * The dial goes through the shared pool for the same reason
 * `device.service.testTransport()` does — one socket per device, one global
 * dial budget, one circuit breaker (risk R5). This is deliberately NOT
 * `assertTargetBinding()`'s fresh-socket rule: that rule exists because a
 * pooled socket proves the identity of whatever answered when the pool
 * dialled, which is worthless as a PRE-WRITE proof. F6 writes to nothing, and
 * "whatever answered when the pool dialled" is exactly the population it is
 * meant to be watching — if the lease moved and the pool is now talking to a
 * different box, that is a finding, not a flaw in the method.
 */
export async function observeDeviceIdentity(
  tenantId: number,
  deviceId: number,
  options: ObserveOptions = {},
): Promise<ObserveOutcome> {
  const device = await assertDeviceInTenant(tenantId, deviceId);
  const source = options.source ?? 'probe';

  const empty: ObserveOutcome = {
    ok: false,
    error: null,
    deviceId,
    observationId: null,
    deduplicated: false,
    events: [],
    reference: null,
    unanswered: [...IDENTITY_ATTRIBUTES],
    serialUnanswered: true,
  };

  if (device.brand !== 'mikrotik') {
    // An honest refusal rather than a silent pass. DrayTek / Zyxel / SonicWall
    // identity reads ride SSH and REST; returning `ok: true` with four nulls
    // would put "no change detected" on a screen about a box nobody looked at.
    return {
      ...empty,
      error:
        `no identity read path for brand '${device.brand}' yet (milestone M6) — ` +
        'refusing rather than reporting "no change" about a box we did not question',
    };
  }
  if (device.status === 'disabled') {
    return { ...empty, error: "device status is 'disabled'; no transport may be opened" };
  }

  let observed: IdentitySnapshot;
  try {
    const target = await resolveRouterOsTarget(deviceId);
    observed = await getRouterOsPool().withConnection(target, (conn) => readFullIdentity(conn));
  } catch (err) {
    // The transport layer's errors are already redacted (proven by its own
    // self-test). Truncating is belt-and-braces before it reaches a response.
    const message = (err instanceof Error ? err.message : String(err)).slice(0, 500);
    return { ...empty, error: message };
  }

  const outcome = await recordIdentityObservation(tenantId, deviceId, observed, { source });
  return { ...outcome, ok: true, error: null };
}

// ============================================================================
// The tenant-wide pass
// ============================================================================

/** Server-side ceiling. A caller may ask for fewer devices, never more: a
 *  sweep dials real routers, and an unbounded one is a self-inflicted denial
 *  of service on a customer's management plane. */
export const MAX_SWEEP_DEVICES = 200;

export interface SweepResult {
  scanned: number;
  ok: number;
  failed: number;
  events: IdentityEventRecord[];
  failures: Array<{ deviceId: number; error: string }>;
}

/**
 * Walk this tenant's MikroTik devices that have a usable RouterOS channel and
 * observe each one.
 *
 * Sequential on purpose, same reasoning as `device.service.testAllTransports`:
 * the RouterOS channel shares one pooled socket per device whose dial budget is
 * global (risk R5), and a burst of parallel dials is how a small CPE's
 * management CPU gets saturated by a diagnostic.
 *
 * A device that cannot be reached is a RESULT, not an exception. The sweep
 * finishes and reports what it could not do.
 */
export async function sweepTenantIdentities(
  tenantId: number,
  options: { limit?: number } = {},
): Promise<SweepResult> {
  const limit = Math.min(Math.max(1, options.limit ?? MAX_SWEEP_DEVICES), MAX_SWEEP_DEVICES);

  const ids = await db('devices as d')
    .join('device_transports as t', function joinRouterOs(this: Knex.JoinClause) {
      this.on('t.device_id', '=', 'd.id').andOn('t.transport', '=', db.raw('?', ['routeros_api']));
    })
    .where('d.tenant_id', tenantId)
    .andWhere('d.brand', 'mikrotik')
    .andWhereNot('d.status', 'disabled')
    .andWhere('t.enabled', true)
    .orderBy('d.id')
    .limit(limit)
    .pluck<number[]>('d.id');

  const result: SweepResult = { scanned: 0, ok: 0, failed: 0, events: [], failures: [] };
  for (const deviceId of ids) {
    result.scanned++;
    try {
      const outcome = await observeDeviceIdentity(tenantId, deviceId, { source: 'sweep' });
      if (outcome.ok) {
        result.ok++;
        result.events.push(...outcome.events);
      } else {
        result.failed++;
        result.failures.push({ deviceId, error: outcome.error ?? 'unknown' });
      }
    } catch (err) {
      result.failed++;
      result.failures.push({
        deviceId,
        error: (err instanceof Error ? err.message : String(err)).slice(0, 500),
      });
    }
  }
  return result;
}

// ============================================================================
// Reads
// ============================================================================

export const MAX_EVENT_PAGE = 500;

export interface EventFilter {
  deviceId?: number;
  kind?: IdentityEventKind;
  /** `critical` alone is the "what must a human look at today" view. */
  severity?: IdentityEventSeverity;
  /** Only events nobody has reviewed yet. */
  pendingOnly?: boolean;
  /** Only events that mean the reference config is no longer a reference. */
  invalidatingOnly?: boolean;
  sinceHours?: number;
  limit?: number;
}

/**
 * The event feed for this tenant.
 *
 * Every filter below is a NARROWING one: `tenant_id` is applied first and
 * unconditionally, and no argument of this function can widen the result past
 * it. `limit` is clamped server-side; a caller asking for a million rows gets
 * `MAX_EVENT_PAGE`.
 */
export async function listIdentityEvents(
  tenantId: number,
  filter: EventFilter = {},
): Promise<IdentityEventRecord[]> {
  const limit = Math.min(Math.max(1, filter.limit ?? 100), MAX_EVENT_PAGE);

  // The device filter goes through the tenant door too: an id from another
  // customer produces a 404 instead of an empty list, which is the same answer
  // an id that does not exist gets.
  if (filter.deviceId !== undefined) await assertDeviceInTenant(tenantId, filter.deviceId);

  const q = db('device_identity_events as e')
    .leftJoin('devices as d', 'd.id', 'e.device_id')
    .where('e.tenant_id', tenantId)
    .orderBy('e.detected_at', 'desc')
    .orderBy('e.id', 'desc')
    .limit(limit)
    .select<EventRow[]>([...EVENT_COLUMNS, 'd.name as device_name']);

  if (filter.deviceId !== undefined) q.andWhere('e.device_id', filter.deviceId);
  if (filter.kind !== undefined) q.andWhere('e.kind', filter.kind);
  if (filter.severity !== undefined) {
    // Checked against the vocabulary rather than interpolated on trust: this is
    // the only string filter on this surface that is not already an enum in the
    // controller's schema when the service is called from somewhere else.
    if (!(IDENTITY_EVENT_SEVERITIES as readonly string[]).includes(filter.severity)) {
      throw new IdentityWatchError(400, `Unknown severity '${filter.severity}'`);
    }
    q.andWhere('e.severity', filter.severity);
  }
  if (filter.pendingOnly) q.whereNull('e.acknowledged_at');
  if (filter.invalidatingOnly) q.andWhere('e.invalidates_baseline', true);
  if (filter.sinceHours !== undefined) {
    q.andWhere('e.detected_at', '>=', db.raw("now() - (? * interval '1 hour')", [filter.sinceHours]));
  }

  return (await q).map(toEvent);
}

export async function getIdentityEvent(
  tenantId: number,
  eventId: number,
): Promise<IdentityEventRecord | null> {
  const row = await db('device_identity_events as e')
    .leftJoin('devices as d', 'd.id', 'e.device_id')
    .where('e.tenant_id', tenantId)
    .andWhere('e.id', eventId)
    .first<EventRow | undefined>(...EVENT_COLUMNS, 'd.name as device_name');
  return row ? toEvent(row) : null;
}

export interface DeviceIdentityReport {
  deviceId: number;
  deviceName: string;
  /** What the `devices` registry says. F6 never writes here; it is shown side
   *  by side with the reference so a divergence is visible rather than
   *  silently reconciled. */
  registry: IdentitySnapshot;
  reference: IdentityReference | null;
  history: IdentityObservationRecord[];
  events: IdentityEventRecord[];
}

/** Everything F6 knows about one device. */
export async function getDeviceIdentity(
  tenantId: number,
  deviceId: number,
  options: { historyLimit?: number } = {},
): Promise<DeviceIdentityReport> {
  const device = await assertDeviceInTenant(tenantId, deviceId);
  const historyLimit = Math.min(Math.max(1, options.historyLimit ?? 50), MAX_EVENT_PAGE);

  const reference = await db('device_identity_reference')
    .where({ device_id: deviceId, tenant_id: tenantId })
    .first<ReferenceRow | undefined>('*');

  const history = await db('device_identity_observations')
    .where({ tenant_id: tenantId, device_id: deviceId })
    .orderBy('id', 'desc')
    .limit(historyLimit)
    .select<ObservationRow[]>('*');

  const events = await listIdentityEvents(tenantId, { deviceId, limit: historyLimit });

  return {
    deviceId,
    deviceName: device.name,
    registry: {
      serial: device.serial,
      systemIdentity: device.system_identity,
      model: device.model,
      osVersion: device.os_version,
    },
    reference: reference ? toReference(reference) : null,
    history: history.map(toObservation),
    events,
  };
}

/**
 * "Is the last config snapshot of this device still a reference?"
 *
 * THE SECOND TRAP OF THE BRIEF, ANSWERED AS A SENTENCE AND NOT AS A REPAIR.
 * A replaced chassis (or a factory-reset one) means the newest
 * `config_snapshots` row describes a box that is no longer there, and the
 * drift computed against it is not drift. This function SAYS so. It runs one
 * SELECT and one SELECT only: no snapshot is deleted, no baseline retired, no
 * finding closed, no device touched. A human acknowledges, and the
 * acknowledgement is the thing that clears the flag.
 *
 * TENANT SCOPE, THE JOINED CASE: `config_snapshots` has no `tenant_id`
 * (migration 007), so it is scoped by joining `devices` and filtering on
 * `d.tenant_id`. `assertDeviceInTenant()` has already refused a foreign
 * device, and the join is the second lock on the same door.
 */
export async function baselineTrust(
  tenantId: number,
  deviceId: number,
): Promise<BaselineTrustReport> {
  await assertDeviceInTenant(tenantId, deviceId);

  const snapshot = await db('config_snapshots as cs')
    .join('devices as d', 'd.id', 'cs.device_id')
    .where('cs.device_id', deviceId)
    .andWhere('d.tenant_id', tenantId)
    .orderBy('cs.captured_at', 'desc')
    .orderBy('cs.id', 'desc')
    .first<{ id: string | number; captured_at: Date } | undefined>('cs.id', 'cs.captured_at');

  if (!snapshot) {
    return {
      deviceId,
      snapshot: null,
      trusted: true,
      blockingEvents: [],
      firmwareChangedSince: false,
      reason: 'this device has no config snapshot, so there is no reference to distrust',
    };
  }

  const capturedAt = snapshot.captured_at;

  // Only events at or AFTER the capture matter. A replacement recorded before
  // the snapshot was taken means the snapshot is already of the NEW box, and
  // holding it against that snapshot forever would make the flag permanent.
  const since = await db('device_identity_events as e')
    .leftJoin('devices as d', 'd.id', 'e.device_id')
    .where('e.tenant_id', tenantId)
    .andWhere('e.device_id', deviceId)
    .andWhere('e.detected_at', '>=', capturedAt)
    .orderBy('e.detected_at', 'desc')
    .select<EventRow[]>([...EVENT_COLUMNS, 'd.name as device_name']);

  const records = since.map(toEvent);
  const blockingEvents = records.filter(
    (e) => e.acknowledgedAt === null && isBaselineInvalidatingKind(e.kind),
  );
  const firmwareChangedSince = records.some((e) => isFirmwareEventKind(e.kind));

  const trusted = blockingEvents.length === 0;
  return {
    deviceId,
    snapshot: { id: asNumber(snapshot.id), capturedAt: capturedAt.toISOString() },
    trusted,
    blockingEvents,
    firmwareChangedSince,
    reason: trusted
      ? firmwareChangedSince
        ? 'no unreviewed replacement since this snapshot; note that the firmware moved, so '
          + 'an export compared against it will legitimately differ in places'
        : 'no unreviewed replacement or factory reset since this snapshot'
      : `${blockingEvents.length} unreviewed event(s) mean this snapshot describes a box that `
        + 'is no longer there: the drift computed against it is not drift. Review and '
        + 'acknowledge before treating it as a reference. NOTHING HAS BEEN DELETED.',
  };
}

// ============================================================================
// Acknowledgement — the one legal mutation
// ============================================================================

/**
 * Record that a human looked at an identity event and what they concluded.
 *
 * This does NOT repair anything. It does not delete a snapshot, re-baseline a
 * device, or write to `devices`. It writes three columns on one append-only
 * row, once — migration 025's trigger refuses everything else, including a
 * second acknowledgement of the same row.
 *
 * The note is required and must carry ink: `MIN_IDENTITY_ACK_NOTE` characters
 * that are not invisible, and at least one letter or digit. The same predicate
 * exists as a CHECK in migration 025, so the two guards close the same hole
 * that `023_fix_evidence.ts` documents at length — an application `trim()` and
 * a SQL `btrim()` both let twenty-four no-break spaces through.
 */
export async function acknowledgeIdentityEvent(
  tenantId: number,
  eventId: number,
  userId: number,
  note: string,
): Promise<IdentityEventRecord> {
  // ONE predicate, stated twice: here and as a CHECK in migration 025. NOT
  // `note.trim().length >= N` — `String.trim()` does not remove U+200B, so
  // forty zero-width spaces walked through the application guard and were then
  // refused by the database, which turns a 400 with a reason into a 500 with a
  // constraint name. This is the hole 023_fix_evidence.ts exists to document.
  const problem = identityAckNoteProblem(note);
  if (problem !== null) {
    throw new IdentityWatchError(400, `${problem}. "ok" is not a review of a chassis replacement.`);
  }
  const trimmed = note.trim();

  const existing = await getIdentityEvent(tenantId, eventId);
  if (!existing) throw new IdentityWatchError(404, `Identity event ${eventId} does not exist`);
  if (existing.acknowledgedAt !== null) {
    throw new IdentityWatchError(
      409,
      `Identity event ${eventId} was already acknowledged at ${existing.acknowledgedAt}`,
    );
  }

  // `tenant_id` in the WHERE as well as in the pre-read: between the two there
  // is a window, and the UPDATE must not be the one place that trusts an id.
  const updated = await db('device_identity_events')
    .where({ id: eventId, tenant_id: tenantId })
    .whereNull('acknowledged_at')
    .update({
      acknowledged_at: db.raw('clock_timestamp()'),
      acknowledged_by: userId,
      acknowledgement: trimmed,
    });
  if (updated === 0) {
    throw new IdentityWatchError(409, `Identity event ${eventId} was acknowledged concurrently`);
  }

  const after = await getIdentityEvent(tenantId, eventId);
  if (!after) throw new IdentityWatchError(404, `Identity event ${eventId} does not exist`);
  logger.info(
    { tenantId, eventId, userId, kind: after.kind },
    'F6: identity event acknowledged (nothing was repaired; the flag was reviewed)',
  );
  return after;
}
