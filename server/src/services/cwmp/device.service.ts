/**
 * ObliWAN — the CPE as the ACS knows it: identity, enrolment, reachability.
 *
 * ┌─ THE ACS NEVER CREATES A `devices` ROW ───────────────────────────────────┐
 * │ An Inform from an unknown `cwmp_id` is a KNOCK AT THE DOOR, not a         │
 * │ provisioning event. Migration 002 already settled this shape for PPP      │
 * │ (`discoveries`: quarantine, no automatic attachment to a tenant, binding  │
 * │ is a human gesture and it is audited) and the reasoning is identical      │
 * │ here — anyone who can reach port 7547 can claim to be any serial number.  │
 * │                                                                          │
 * │ So an unknown CPE is CHALLENGED, refused, and RECORDED as an             │
 * │ unauthenticated session row. An operator sees "4 unknown CPEs have been   │
 * │ knocking" on the ACS screen and binds them by hand. `allow_auto_enroll`   │
 * │ relaxes exactly one step of that — it lets a CPE whose serial ALREADY     │
 * │ matches a device in the tenant enrol itself — and it is off by default.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE FAMILY GATE IS THE PRODUCT'S HONESTY ABOUT RISK R2 ──────────────────┐
 * │ `acsCoversFamily()` is checked at enrolment. A MikroTik cannot be enrolled│
 * │ in the ACS because RouterOS has no CWMP client — a row claiming otherwise │
 * │ would be a lie stored in a database, and it would show up on the coverage │
 * │ panel as evidence that the ACS covers a brand it does not.                │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { db } from '../../db';
import { logger } from '../../utils/logger';
import { encrypt, decrypt, currentKeyVersion } from '../secretVault.service';
import { computeHa1, generateCpePassword, nonceExpiry } from '../../cwmp/digest';
import {
  CWMP_ROOT_PREFIX,
  acsCoversFamily,
  buildCwmpId,
  chooseDataModel,
  classifyReachability,
  informIsBootstrap,
  type CwmpDataModel,
  type CwmpQuirks,
  type CwmpReachability,
} from './contract';

export interface CwmpDeviceRow {
  device_id: number;
  cwmp_id: string;
  oui: string | null;
  product_class: string | null;
  serial_number: string | null;
  manufacturer: string | null;
  root_prefix: string;
  data_model: CwmpDataModel;
  cwmp_version: string | null;
  hardware_version: string | null;
  software_version: string | null;
  connection_request_url: string | null;
  acs_auth_ha1_enc: string | null;
  key_version: number;
  auth_username: string | null;
  periodic_inform_interval: number;
  reachability: CwmpReachability;
  last_inform_at: Date | null;
  last_bootstrap_at: Date | null;
  last_inform_events: string[] | null;
  inform_count: number;
  last_source_ip: string | null;
  vendor_quirks: CwmpQuirks;
  rpc_log_enabled: boolean;
}

/** A CPE resolved to a device, with the tenant it belongs to. */
export interface ResolvedCpe {
  deviceId: number;
  tenantId: number;
  deviceName: string;
  brand: string;
  family: string;
  model: string | null;
  cwmp: CwmpDeviceRow;
}

export class AcsEnrolmentError extends Error {
  constructor(message: string, readonly code: 'unsupported_family' | 'already_enrolled' | 'no_device') {
    super(message);
    this.name = 'AcsEnrolmentError';
  }
}

// ============================================================================
// Resolution
// ============================================================================

/**
 * Find the CPE behind a `cwmp_id`, scoped to the tenant the URL named.
 *
 * The tenant filter is the JOIN on `devices` — the CWMP tables carry no
 * `tenant_id` of their own (migration 015, decision 1) — and it is not
 * optional: without it, a CPE provisioned with tenant B's slug but carrying
 * tenant A's serial would be served tenant A's task queue.
 */
export async function resolveCpe(cwmpId: string, tenantId: number): Promise<ResolvedCpe | null> {
  const row = (await db('cwmp_devices as c')
    .join('devices as d', 'd.id', 'c.device_id')
    .where('c.cwmp_id', cwmpId)
    .andWhere('d.tenant_id', tenantId)
    .first(
      'c.*',
      'd.tenant_id as d_tenant_id',
      'd.name as d_name',
      'd.brand as d_brand',
      'd.family as d_family',
      'd.model as d_model',
    )) as (CwmpDeviceRow & Record<string, unknown>) | undefined;

  if (!row) return null;
  return {
    deviceId: row.device_id,
    tenantId: Number(row.d_tenant_id),
    deviceName: String(row.d_name),
    brand: String(row.d_brand),
    family: String(row.d_family),
    model: (row.d_model as string | null) ?? null,
    cwmp: row,
  };
}

// ============================================================================
// The replay bound the digest header used to only promise
// ============================================================================

/**
 * How many live nonces one CPE may have in flight before the oldest is
 * forgotten.
 *
 * A record is normally dropped because its own nonce expired, not because of
 * this cap: a CPE authenticates once per session and `NONCE_TTL_MS` is five
 * minutes, so the set holds one or two entries in ordinary operation. The cap
 * exists so that a box stuck in a challenge loop cannot grow the column without
 * bound. It is deliberately far above any legitimate rate — and the fact that
 * evicting an unexpired entry would make that entry replayable again is why it
 * is logged when it happens rather than silently trimmed.
 */
const NONCE_MEMORY = 32;

interface SeenNonce {
  /** The nonce, verbatim. Not a secret — it is public in a 401 header. */
  n: string;
  /** The highest `nc` accepted for it so far. */
  c: number;
  /** Its own expiry, so the record can be dropped without re-parsing. */
  e: number;
}

function parseSeen(raw: unknown): SeenNonce[] {
  if (!Array.isArray(raw)) return [];
  const out: SeenNonce[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const r = item as Record<string, unknown>;
    if (typeof r.n !== 'string' || typeof r.c !== 'number' || typeof r.e !== 'number') continue;
    out.push({ n: r.n, c: r.c, e: r.e });
  }
  return out;
}

/**
 * Spend a `(nonce, nc)` pair for this CPE. Returns false when it has been spent
 * already — that is a REPLAY, and the caller must refuse the request.
 *
 * ┌─ WHY THIS IS ON THE DEVICE ROW AND NOT ON THE SESSION ROW ────────────────┐
 * │ The Inform is the authentication exchange, and `cwmp_sessions` gets its   │
 * │ row only once that exchange has succeeded. A replayed Inform therefore    │
 * │ does not reuse a session — it OPENS one, authenticated, with a brand new  │
 * │ row. A counter kept per session would be written once, read never, and    │
 * │ would see none of the traffic it was supposed to bound. `cwmp_devices` is │
 * │ the row the original and its replay both resolve to, so it is the only    │
 * │ place the comparison can happen at all.                                   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * `SELECT … FOR UPDATE` and not a read-modify-write: two POSTs carrying the
 * same captured header, arriving together, is precisely the case this refuses,
 * and it is also precisely the case a lost update would let through. The lock
 * is on one device row for the length of one small statement.
 *
 * Never fails open. A database error here propagates, and `handleInform`
 * answers a challenge — an ACS that cannot record a nonce must not accept one.
 */
export async function claimDigestNonce(
  deviceId: number,
  nonce: string,
  nc: number,
  now: number = Date.now(),
): Promise<boolean> {
  const expiry = nonceExpiry(nonce);
  // Shapeless nonce: `nonceIsValid` has already refused it, so this is
  // unreachable from `handleInform`. Refused rather than admitted, because the
  // only way to get here is a caller that skipped the verification.
  if (expiry === null) return false;

  return db.transaction(async (trx) => {
    const row = (await trx('cwmp_devices')
      .where({ device_id: deviceId })
      .forUpdate()
      .first('auth_nonce_seen')) as { auth_nonce_seen: unknown } | undefined;
    if (!row) return false;

    // Expired records first: past its own expiry a nonce is refused by
    // `nonceIsValid` anyway, so remembering it buys nothing.
    const seen = parseSeen(row.auth_nonce_seen).filter((s) => s.e >= now);

    const hit = seen.find((s) => s.n === nonce);
    if (hit && nc <= hit.c) return false;

    if (hit) hit.c = nc;
    else seen.push({ n: nonce, c: nc, e: expiry });

    // Oldest-expiry-first eviction, and it is loud: dropping an entry that has
    // not expired re-opens the replay window for that one header.
    seen.sort((a, b) => a.e - b.e);
    if (seen.length > NONCE_MEMORY) {
      logger.warn(
        { deviceId, live: seen.length },
        'ACS: more live Digest nonces than the replay memory holds — oldest forgotten',
      );
      seen.splice(0, seen.length - NONCE_MEMORY);
    }

    await trx('cwmp_devices')
      .where({ device_id: deviceId })
      .update({ auth_nonce_seen: JSON.stringify(seen) });
    return true;
  });
}

/** The decrypted Digest HA1 of a CPE, for the length of one verification. */
export function ha1Of(cwmp: CwmpDeviceRow): string | null {
  if (!cwmp.acs_auth_ha1_enc) return null;
  try {
    return decrypt(cwmp.acs_auth_ha1_enc);
  } catch (err) {
    // Never echo the ciphertext or the key. A vault that cannot read this row
    // is an operator problem (R8) and it must be loud and identifiable.
    logger.error(
      { deviceId: cwmp.device_id, keyVersion: cwmp.key_version },
      'ACS: stored HA1 could not be decrypted — check OBLIWAN_ENCRYPTION_KEY',
    );
    return null;
  }
}

// ============================================================================
// Enrolment
// ============================================================================

export interface EnrolmentResult {
  username: string;
  /** SHOWN ONCE. It is not stored anywhere: only HA1 is, and encrypted. The
   *  operator provisions it into the CPE and the platform forgets it (§8.2). */
  password: string;
  cwmpId: string | null;
  acsUrl: string;
}

/**
 * Enrol a device into the ACS, or rotate its credentials.
 *
 * Refuses a family the ACS does not cover, and the refusal is the product's
 * answer to risk R2 rather than an implementation limit — hence the error text,
 * which is written to be shown to the operator verbatim.
 *
 * `cwmpId` is OPTIONAL here: it is only knowable once the CPE has informed
 * (the serial the box reports and the serial in the inventory are frequently
 * spelled differently). Until then the row is keyed on a provisional identity
 * derived from the inventory, and the first authenticated Inform rewrites it.
 */
export async function enrolDevice(
  deviceId: number,
  tenantId: number,
  realm: string,
  acsBaseUrl: string,
  slug: string,
): Promise<EnrolmentResult> {
  const device = (await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first('id', 'brand', 'family', 'serial', 'name')) as
    | { id: number; brand: string; family: string; serial: string | null; name: string }
    | undefined;

  if (!device) throw new AcsEnrolmentError(`device ${deviceId} not found`, 'no_device');

  if (!acsCoversFamily(device.family)) {
    throw new AcsEnrolmentError(
      `The ACS does not cover ${device.family}. ${device.brand === 'mikrotik'
        ? 'RouterOS has no TR-069 client, in any version'
        : device.brand === 'sonicwall'
          ? 'SonicOS has no TR-069 client'
          : 'this family is not a CWMP CPE'
      } — this device is managed over its own transport, not over the ACS (risk R2).`,
      'unsupported_family',
    );
  }

  const password = generateCpePassword();
  // The username is the device UUID-free, stable, operator-visible handle. Not
  // the cwmp_id: that is not known until the first Inform, and a credential
  // that cannot be provisioned before the box calls in is a credential that can
  // never be provisioned at all.
  const username = `cpe-${deviceId}`;
  const ha1 = computeHa1(username, realm, password);

  const existing = (await db('cwmp_devices').where({ device_id: deviceId }).first()) as
    | CwmpDeviceRow
    | undefined;

  if (existing) {
    await db('cwmp_devices')
      .where({ device_id: deviceId })
      .update({
        auth_username: username,
        acs_auth_ha1_enc: encrypt(ha1),
        key_version: currentKeyVersion(),
        updated_at: db.fn.now(),
      });
  } else {
    // A provisional cwmp_id. It is UNIQUE-constrained like the real thing, so
    // two devices cannot share one, and the first AUTHENTICATED Inform replaces
    // it with the identity the CPE actually reports — see `findProvisionalCpe`
    // and `bindProvisionalCwmpId` below, which are the code that keeps that
    // promise. Until they existed this sentence was the whole of the feature.
    const provisional = provisionalCwmpId(deviceId, device.serial);
    await db('cwmp_devices').insert({
      device_id: deviceId,
      cwmp_id: provisional,
      // TR-098 until the CPE says otherwise. Guessing TR-181 would be the
      // modern-looking choice and wrong for most of the DrayTek estate.
      data_model: 'tr098',
      root_prefix: CWMP_ROOT_PREFIX.tr098,
      auth_username: username,
      acs_auth_ha1_enc: encrypt(ha1),
      key_version: currentKeyVersion(),
    });
  }

  // THE TRANSPORT ROW. Without it `pickTransport(ctx, 'cwmp')` finds nothing
  // and the driver's CWMP branch is skipped silently — the device would be
  // enrolled, informing happily, and still probed as "no channel answered".
  // `host` and `port` stay NULL because there is nothing to dial: migration 002
  // made them nullable for exactly this transport.
  await db('device_transports')
    .insert({
      device_id: deviceId,
      transport: 'cwmp',
      enabled: true,
      // Ahead of ssh (100) and snmp: the CPE has already pushed its tree to us,
      // so reading it costs nothing and never contends with the single CLI
      // session a Vigor allows.
      priority: 10,
      username,
      params: JSON.stringify({ acsSlug: slug }),
    })
    .onConflict(['device_id', 'transport'])
    .merge(['enabled', 'username', 'params', 'updated_at']);

  logger.info(
    { deviceId, tenantId, username },
    'ACS: device enrolled (credential shown once, only HA1 stored)',
  );

  return {
    username,
    password,
    cwmpId: existing?.cwmp_id ?? null,
    acsUrl: `${acsBaseUrl.replace(/\/+$/, '')}/${slug}`,
  };
}

/**
 * Bind an informing CPE to a device whose serial already matches, when the
 * tenant has allowed it.
 *
 * This is the ONLY automatic path, it never creates a device, and it never
 * crosses a tenant. It exists because the alternative — an operator typing 300
 * serial numbers — is the reason zero-touch enrolment is on the roadmap at all.
 */
export async function autoBind(
  tenantId: number,
  serialNumber: string,
  cwmpId: string,
): Promise<number | null> {
  if (!serialNumber) return null;
  const device = (await db('devices')
    .where({ tenant_id: tenantId, serial: serialNumber })
    .whereIn('family', ['draytek_vigor', 'zyxel_cpe'])
    .first('id', 'family')) as { id: number; family: string } | undefined;
  if (!device) return null;

  const taken = (await db('cwmp_devices').where({ device_id: device.id }).first('device_id')) as
    | { device_id: number }
    | undefined;
  if (taken) return null;

  await db('cwmp_devices').insert({
    device_id: device.id,
    cwmp_id: cwmpId,
    data_model: 'tr098',
    root_prefix: CWMP_ROOT_PREFIX.tr098,
  });
  logger.info({ deviceId: device.id, cwmpId, tenantId }, 'ACS: CPE auto-bound on serial match');
  return device.id;
}

// ============================================================================
// The provisional identity, and how a device stops having one
// ============================================================================

/**
 * ┌─ AN ENROLLED DEVICE HAS AN IDENTITY IT INVENTED FOR ITSELF ───────────────┐
 * │ `enrolDevice()` has to write a `cwmp_id` before the CPE has ever spoken,  │
 * │ because the column is NOT NULL and UNIQUE and because the operator needs  │
 * │ the credential NOW, to type into the box. So it writes                    │
 * │ `PENDING-<deviceId>-<inventory serial>` and the file used to say "the     │
 * │ first authenticated Inform rewrites it".                                  │
 * │                                                                          │
 * │ NOTHING REWROTE IT. `handleInform` resolves on the identity the CPE       │
 * │ announces (`OUI-ProductClass-Serial`), which never equals a `PENDING-…`   │
 * │ string; `applyInform`, the only writer, runs AFTER that resolution        │
 * │ succeeds; and `autoBind` refuses outright when a `cwmp_devices` row       │
 * │ already exists — which is exactly the state an enrolled device is in.     │
 * │ An enrolled DrayTek therefore got 401 for ever, and re-enrolling only     │
 * │ rotated the HA1. The harness did not see it because it rewrote the        │
 * │ column in SQL before every section.                                       │
 * │                                                                          │
 * │ These two functions are the missing step, and the ORDER is the whole      │
 * │ safety argument: the row is FOUND on the inventory serial (a number       │
 * │ printed on a sticker — not a secret, not an authorisation) and is BOUND   │
 * │ only after the CPE has answered the Digest challenge with the HA1 the     │
 * │ enrolment stored. Whoever holds the credential is the box.                │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export const PROVISIONAL_CWMP_ID_PREFIX = 'PENDING-';

export function provisionalCwmpId(deviceId: number, serial: string | null): string {
  return `${PROVISIONAL_CWMP_ID_PREFIX}${deviceId}-${serial ?? 'noserial'}`.slice(0, 192);
}

export function isProvisionalCwmpId(cwmpId: string): boolean {
  return cwmpId.startsWith(PROVISIONAL_CWMP_ID_PREFIX);
}

/**
 * The enrolled-but-never-heard-from row this Inform might belong to.
 *
 * Scoped to the tenant of the URL by the same JOIN as `resolveCpe`, matched on
 * the inventory serial, and REQUIRES a stored credential: a provisional row
 * with no HA1 cannot be claimed at all, because there would be nothing for the
 * caller to prove. Returning it is not a decision to trust it — the caller must
 * still authenticate before calling `bindProvisionalCwmpId`.
 */
export async function findProvisionalCpe(
  tenantId: number,
  serialNumber: string,
): Promise<ResolvedCpe | null> {
  if (!serialNumber) return null;

  const row = (await db('cwmp_devices as c')
    .join('devices as d', 'd.id', 'c.device_id')
    .where('d.tenant_id', tenantId)
    .andWhere('d.serial', serialNumber)
    .andWhere('c.cwmp_id', 'like', `${PROVISIONAL_CWMP_ID_PREFIX}%`)
    .whereNotNull('c.acs_auth_ha1_enc')
    .first(
      'c.*',
      'd.tenant_id as d_tenant_id',
      'd.name as d_name',
      'd.brand as d_brand',
      'd.family as d_family',
      'd.model as d_model',
    )) as (CwmpDeviceRow & Record<string, unknown>) | undefined;

  if (!row) return null;
  return {
    deviceId: row.device_id,
    tenantId: Number(row.d_tenant_id),
    deviceName: String(row.d_name),
    brand: String(row.d_brand),
    family: String(row.d_family),
    model: (row.d_model as string | null) ?? null,
    cwmp: row,
  };
}

/**
 * Replace a provisional `cwmp_id` with the identity the CPE reported.
 *
 * Returns false rather than throwing when the identity is already held by
 * another row: `cwmp_devices.cwmp_id` is UNIQUE across the whole table (a CPE
 * belongs to one customer, globally), and an `UPDATE` that violated it would
 * surface as a 500 on the listener instead of as a fact an operator can act on.
 * The `WHERE cwmp_id LIKE 'PENDING-%'` is what makes this safe to call twice:
 * it can only ever consume a provisional identity, never overwrite a real one.
 */
export async function bindProvisionalCwmpId(deviceId: number, cwmpId: string): Promise<boolean> {
  const clash = (await db('cwmp_devices')
    .where({ cwmp_id: cwmpId })
    .whereNot({ device_id: deviceId })
    .first('device_id')) as { device_id: number } | undefined;
  if (clash) return false;

  const updated = await db('cwmp_devices')
    .where({ device_id: deviceId })
    .andWhere('cwmp_id', 'like', `${PROVISIONAL_CWMP_ID_PREFIX}%`)
    .update({ cwmp_id: cwmpId, updated_at: db.fn.now() });

  if (updated > 0) {
    logger.info({ deviceId, cwmpId }, 'ACS: provisional cwmp_id replaced by the reported identity');
  }
  return updated > 0;
}

// ============================================================================
// What an Inform teaches us
// ============================================================================

export interface InformFacts {
  manufacturer: string | null;
  oui: string;
  productClass: string | null;
  serialNumber: string;
  events: string[];
  parameterPaths: string[];
  hardwareVersion: string | null;
  softwareVersion: string | null;
  connectionRequestUrl: string | null;
  periodicInformInterval: number | null;
  sourceIp: string;
  cwmpVersion: string | null;
}

/**
 * Fold one Inform into `cwmp_devices`.
 *
 * The data model is RE-DERIVED on every Inform rather than trusted from the
 * row, because a firmware upgrade genuinely moves a box from TR-098 to TR-181 —
 * and a stale `root_prefix` means every subsequent GetParameterValues asks for
 * a subtree that no longer exists and comes back 9005 forever, which reads on
 * screen as "the CPE stopped answering".
 */
export async function applyInform(
  deviceId: number,
  facts: InformFacts,
  quirks: CwmpQuirks,
): Promise<void> {
  const model = chooseDataModel(facts.parameterPaths);
  const update: Record<string, unknown> = {
    manufacturer: facts.manufacturer,
    oui: facts.oui || null,
    product_class: facts.productClass,
    serial_number: facts.serialNumber || null,
    cwmp_id: buildCwmpId({
      oui: facts.oui,
      productClass: facts.productClass,
      serialNumber: facts.serialNumber,
    }),
    last_inform_at: db.fn.now(),
    last_inform_events: facts.events,
    last_source_ip: facts.sourceIp,
    inform_count: db.raw('inform_count + 1'),
    reachability: 'online',
    updated_at: db.fn.now(),
  };

  if (model) {
    update.data_model = model;
    update.root_prefix = CWMP_ROOT_PREFIX[model];
  }
  if (facts.hardwareVersion) update.hardware_version = facts.hardwareVersion;
  if (facts.softwareVersion) update.software_version = facts.softwareVersion;
  if (facts.connectionRequestUrl) update.connection_request_url = facts.connectionRequestUrl;
  if (facts.cwmpVersion) update.cwmp_version = facts.cwmpVersion;
  if (facts.periodicInformInterval && facts.periodicInformInterval >= 30) {
    update.periodic_inform_interval = facts.periodicInformInterval;
  }
  if (informIsBootstrap(facts.events)) {
    // A BOOTSTRAP means the CPE has forgotten everything we ever set. Recording
    // WHEN is what lets the reconciler know that its parameter cache is void
    // rather than merely old.
    update.last_bootstrap_at = db.fn.now();
  }

  await db('cwmp_devices').where({ device_id: deviceId }).update(update);
  if (Object.keys(quirks).length > 0) await mergeQuirks(deviceId, quirks);
}

/**
 * Record an observed quirk.
 *
 * A MERGE, never a replace: quirks accumulate across sessions because they are
 * observations, and a session in which the CPE happened not to send a
 * single-element array is not evidence that it never will.
 */
export async function mergeQuirks(deviceId: number, quirks: CwmpQuirks): Promise<void> {
  const entries = Object.entries(quirks).filter(([, v]) => v === true);
  if (entries.length === 0) return;
  const patch = Object.fromEntries(entries);
  await db('cwmp_devices')
    .where({ device_id: deviceId })
    .update({
      vendor_quirks: db.raw('vendor_quirks || ?::jsonb', [JSON.stringify(patch)]),
      updated_at: db.fn.now(),
    });
}

/**
 * Recompute `reachability` for every enrolled CPE.
 *
 * Runs on a timer because reachability decays with TIME and nothing else: a CPE
 * that stops calling in produces no event to react to, which is precisely what
 * makes it interesting. A column that only ever changed on an Inform would say
 * `online` forever for the boxes that are gone.
 */
export async function refreshReachability(): Promise<{ changed: number }> {
  const rows = (await db('cwmp_devices').select(
    'device_id',
    'last_inform_at',
    'periodic_inform_interval',
    'reachability',
  )) as Array<{
    device_id: number;
    last_inform_at: Date | null;
    periodic_inform_interval: number;
    reachability: CwmpReachability;
  }>;

  const now = new Date();
  let changed = 0;
  for (const row of rows) {
    const next = classifyReachability(row.last_inform_at, row.periodic_inform_interval, now);
    if (next === row.reachability) continue;
    await db('cwmp_devices').where({ device_id: row.device_id }).update({ reachability: next });
    changed++;
  }
  return { changed };
}

/**
 * ┌─ K7's FOURTH SIGNAL IS NOT WIRED, AND THIS IS THE NOTE THAT SAYS SO ──────┐
 * │ `reachability_verdicts.cwmp_recent` (migration 002) is the fourth column   │
 * │ of the accessibility truth table, and `cwmp_devices.reachability` is now   │
 * │ the fact that would fill it: `online` or `stale` means the CPE called in   │
 * │ recently, `lost` means it has not.                                         │
 * │                                                                          │
 * │ The join is deliberately NOT written here. `reachability_verdicts` is      │
 * │ owned by `services/fleet/reachability.service.ts`, which composes all four │
 * │ signals; a reader added from this side would be a function with no caller  │
 * │ waiting for a workstream to notice it — the exact defect the last audit    │
 * │ found three times. Whoever owns K7 reads `cwmp_devices.reachability` on    │
 * │ the join it already does to `devices`, and nothing has to be added here.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
