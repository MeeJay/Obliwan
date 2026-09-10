/**
 * ObliWAN — SNMP targets that create themselves.
 *
 * ┌─ WHY THIS EXISTS ────────────────────────────────────────────────────────┐
 * │ A target had to be configured by hand, one device at a time, through     │
 * │ `PUT /snmp/devices/:id/target`. That is a defensible shape for a tool     │
 * │ that manages twenty routers and an absurd one for a product whose stated  │
 * │ scale is a few hundred sites: five hundred devices meant five hundred     │
 * │ identical gestures, and a fleet where "no interfaces discovered" is the   │
 * │ normal state of every device nobody has gotten round to yet.              │
 * │                                                                          │
 * │ The gesture is now made ONCE, as a setting, and inherited: name the       │
 * │ credential for the tenant (or for one group, if a customer has its own    │
 * │ community) and every confirmed device is polled.                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── WHY IT WILL NOT POLL EVERYTHING IT CAN SEE ──────────────────────────────
 * Only `active` devices get a target. A `pending` device is one whose identity
 * has NOT been confirmed by a human (D5): its address may today belong to a
 * different box than the row claims. Polling it would not merely be useless —
 * the series are keyed on `(device_id, if_name)`, so counters read from
 * somebody else's router would be written down as this device's history, and a
 * wrong graph is worse than a missing one because it is believed. `pending` is
 * the state that says "we do not know yet", and this respects it.
 *
 * ── AND WHY IT NEVER INVENTS A CREDENTIAL ───────────────────────────────────
 * `SNMP_AUTO_TARGET_CREDENTIAL` defaults to 0, which is off. A community string
 * is a shared secret; picking one on an operator's behalf ("public"?) would be
 * a guess sprayed at a customer's fleet. Nothing here happens until a human
 * names a credential — and then it happens for everything, forever, which is
 * the trade this file exists to make.
 */

import { db } from '../../db';
import { logger } from '../../utils/logger';
import { settingsService } from '../settings.service';
import { SETTINGS_KEYS } from '@obliwan/shared';

export interface ProvisionOutcome {
  /** Devices that gained a target on this pass. */
  created: number;
  /** Confirmed devices with no target and no credential named for them. */
  awaitingCredential: number;
  /** Devices whose inherited credential id no longer exists in their tenant. */
  danglingCredential: number;
  /** Devices skipped because there is nowhere to send a packet. */
  noAddress: number;
}

interface Candidate {
  id: number;
  tenant_id: number;
  group_id: number | null;
  name: string;
  tunnel_ip: string | null;
  transport_host: string | null;
}

/**
 * Confirmed devices that have no SNMP target.
 *
 * `concentrator` is included deliberately: the CHR is the single most important
 * box in the fleet and the one whose interface counters an operator wants at
 * 3am. It is not exempt from supervision because it is infrastructure.
 */
async function findCandidates(limit: number): Promise<Candidate[]> {
  return db('devices as d')
    .leftJoin('snmp_targets as t', 't.device_id', 'd.id')
    // The highest-priority transport carries the address for a standalone
    // device, which has no tunnel and therefore no `tunnel_ip`.
    .leftJoin(
      db('device_transports')
        .select('device_id')
        .min({ priority: 'priority' })
        .groupBy('device_id')
        .as('tp'),
      'tp.device_id',
      'd.id',
    )
    .leftJoin('device_transports as dt', function joinBest(this: any) {
      this.on('dt.device_id', '=', 'd.id').andOn('dt.priority', '=', 'tp.priority');
    })
    .whereNull('t.id')
    .where('d.status', 'active')
    .whereIn('d.role', ['cpe', 'concentrator'])
    .orderBy('d.id')
    .limit(limit)
    .select<Candidate[]>(
      'd.id', 'd.tenant_id', 'd.group_id', 'd.name',
      db.raw('host(d.tunnel_ip) as tunnel_ip'),
      db.raw('min(dt.host) as transport_host'),
    )
    .groupBy('d.id', 'd.tenant_id', 'd.group_id', 'd.name', 'd.tunnel_ip');
}

/**
 * Give every confirmed, unpolled device the target its settings call for.
 *
 * Idempotent and cheap: one query finds the gap, and a fleet already fully
 * provisioned costs exactly that query. `snmp_targets.device_id` is UNIQUE, so
 * a race with an operator creating the same target by hand ends as a conflict
 * that is ignored rather than as two pollers on one device.
 */
export async function provisionMissingTargets(limit = 500): Promise<ProvisionOutcome> {
  const out: ProvisionOutcome = {
    created: 0, awaitingCredential: 0, danglingCredential: 0, noAddress: 0,
  };

  const candidates = await findCandidates(limit);
  if (candidates.length === 0) return out;

  // Credential ids are tenant-scoped; cache the existence check per tenant so a
  // fleet of 500 costs one query per distinct credential, not 500.
  const credentialExists = new Map<string, boolean>();

  for (const device of candidates) {
    const settings = await settingsService.resolveForDevice(
      device.tenant_id, device.id, device.group_id,
    );
    const credentialId = Number(settings[SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL]?.value ?? 0);

    if (!credentialId) {
      out.awaitingCredential++;
      continue;
    }

    const cacheKey = `${device.tenant_id}:${credentialId}`;
    let exists = credentialExists.get(cacheKey);
    if (exists === undefined) {
      const row = await db('snmp_credentials')
        .where({ id: credentialId, tenant_id: device.tenant_id })
        .first('id');
      exists = Boolean(row);
      credentialExists.set(cacheKey, exists);
    }
    if (!exists) {
      out.danglingCredential++;
      continue;
    }

    // ── The address, and the one subtlety worth reading ─────────────────────
    // `host` is left NULL whenever the device has a tunnel IP, because
    // `addressOf()` then follows `devices.tunnel_ip` on every poll. Copying the
    // address here instead would freeze it, and a dynamic PPP pool reassigns
    // addresses — the target would keep polling whatever box inherited it (D5,
    // risk R4). Only a device with no tunnel at all gets an explicit host, from
    // its highest-priority transport, because there is nothing to follow.
    const host = device.tunnel_ip ? null : device.transport_host;
    if (!device.tunnel_ip && !host) {
      out.noAddress++;
      continue;
    }

    const inserted = await db('snmp_targets')
      .insert({
        device_id: device.id,
        // NULL, not `credentialId`. NULL means INHERIT, and `attachCredentials`
        // resolves it from the settings tree on every poll. Writing today's
        // resolved value here would look identical and behave differently: the
        // setting would become a default that applied only to devices enrolled
        // after it, and rotating a community would leave 400 targets pinned to
        // the old one with nothing on any screen to say so. The credential id
        // was still resolved above — as a PRECONDITION, so a target is never
        // created for a fleet that has named nothing.
        credential_id: null,
        host,
        enabled: true,
        // Interval, timeout and retries stay NULL / at their column defaults so
        // they keep inheriting from settings. Writing today's resolved value
        // onto the row would silently detach this device from a later change.
      })
      .onConflict('device_id')
      .ignore()
      .returning<Array<{ id: number }>>('id');

    if (inserted.length > 0) {
      out.created++;
      logger.info(
        { deviceId: device.id, device: device.name, credentialId, host: host ?? '(tunnel ip)' },
        'SNMP target provisioned automatically',
      );
    }
  }

  return out;
}

// ============================================================================
// One device, on demand
// ============================================================================

export type ProvisionReason =
  | 'created'
  | 'already_had_one'
  | 'not_confirmed'
  | 'no_credential_named'
  | 'credential_missing'
  | 'no_address';

/**
 * Provision THIS device's target now, and say precisely why if it cannot.
 *
 * ┌─ WHY THIS EXISTS SEPARATELY FROM THE SWEEP ──────────────────────────────┐
 * │ "Discover now" used to refuse a device with no target by telling the      │
 * │ operator to go and name a credential in Settings — advice that is useless │
 * │ to somebody who just did, and insulting to somebody who did it an hour    │
 * │ ago and is waiting on a five-minute sweep they cannot see.                │
 * │                                                                          │
 * │ The gesture means "poll this box". If the settings already allow it, the  │
 * │ correct answer is to DO it, not to describe the paperwork. The sweep is   │
 * │ for the other 499 devices; this is for the one in front of you.           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The refusals it can still return are separated on purpose — "you named no
 * credential", "the one you named is gone" and "this device is not confirmed
 * yet" send an operator to three different places, and the message that lumped
 * them together sent everyone to the wrong one.
 */
export async function provisionTargetForDevice(
  tenantId: number,
  deviceId: number,
): Promise<{ reason: ProvisionReason; credentialId?: number; resolvedFrom?: string }> {
  const device = await db('devices as d')
    .leftJoin('snmp_targets as t', 't.device_id', 'd.id')
    .where({ 'd.id': deviceId, 'd.tenant_id': tenantId })
    .first<
      | {
          id: number; tenant_id: number; group_id: number | null; status: string;
          tunnel_ip: string | null; target_id: number | null;
        }
      | undefined
    >(
      'd.id', 'd.tenant_id', 'd.group_id', 'd.status',
      db.raw('host(d.tunnel_ip) as tunnel_ip'),
      't.id as target_id',
    );
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);
  if (device.target_id !== null) return { reason: 'already_had_one' };

  // Same rule as the sweep, and for the same reason: an unconfirmed device's
  // address may today belong to somebody else's router, and its counters would
  // be written down as this device's history (D5).
  if (device.status !== 'active') return { reason: 'not_confirmed' };

  const settings = await settingsService.resolveForDevice(
    device.tenant_id, device.id, device.group_id,
  );
  const setting = settings[SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL];
  const credentialId = Number(setting?.value ?? 0);

  // The RESOLVED value and where it came from, reported to the caller.
  //
  // Not decoration: "no credential is named" is a claim about a setting the
  // operator can see set on their own screen, and when the two disagree the
  // only way out of the argument is for the server to say what IT resolved and
  // from which scope. Guessing on the operator's behalf — "did you really save
  // it?" — is how a support conversation goes three rounds without evidence.
  const resolvedFrom = setting
    ? `${setting.source}${setting.sourceName ? ` (${setting.sourceName})` : ''}`
    : 'default';

  if (!credentialId) return { reason: 'no_credential_named', resolvedFrom };

  const cred = await db('snmp_credentials')
    .where({ id: credentialId, tenant_id: device.tenant_id })
    .first('id');
  if (!cred) return { reason: 'credential_missing', credentialId, resolvedFrom };

  const transport = await db('device_transports')
    .where({ device_id: deviceId })
    .orderBy('priority')
    .first<{ host: string | null } | undefined>('host');

  // NULL host when there is a tunnel, so the target follows `devices.tunnel_ip`
  // instead of freezing an address a PPP pool will reassign (R4).
  const host = device.tunnel_ip ? null : (transport?.host ?? null);
  if (!device.tunnel_ip && !host) return { reason: 'no_address' };

  // NULL = inherit, resolved at poll time. See the sweep above and
  // `attachCredentials`: the operator pins one from the device screen when they
  // want THIS box polled differently; otherwise the fleet setting stays live.
  await db('snmp_targets')
    .insert({ device_id: deviceId, credential_id: null, host, enabled: true })
    .onConflict('device_id')
    .ignore();

  logger.info(
    { deviceId, credentialId, host: host ?? '(tunnel ip)' },
    'SNMP target provisioned on demand',
  );
  return { reason: 'created', credentialId };
}

// ============================================================================
// The periodic sweep
// ============================================================================

let timer: NodeJS.Timeout | null = null;
/** Said once per transition, not once per sweep: a fleet with no credential
 *  named must not produce a warning every five minutes forever. */
let lastAwaiting = -1;

/**
 * Run on the leader only. Five minutes is deliberately unhurried: a device
 * becomes `active` when a human confirms its identity, and nobody confirms an
 * identity and then watches a graph in the same breath.
 */
export function startSnmpAutoProvision(intervalMs = 300_000): void {
  if (timer) return;

  const tick = async () => {
    try {
      const out = await provisionMissingTargets();
      if (out.created > 0) {
        logger.info(out, `SNMP auto-provisioning: ${out.created} target(s) created`);
      }
      if (out.danglingCredential > 0) {
        logger.warn(
          out,
          'SNMP auto-provisioning: the credential named by settings no longer exists for '
            + `${out.danglingCredential} device(s). They will not be polled until it is fixed.`,
        );
      }
      if (out.noAddress > 0) {
        logger.warn(
          out,
          `SNMP auto-provisioning: ${out.noAddress} device(s) have neither a tunnel IP nor a `
            + 'transport host, so there is no address to poll.',
        );
      }
      if (out.awaitingCredential !== lastAwaiting) {
        lastAwaiting = out.awaitingCredential;
        if (out.awaitingCredential > 0) {
          logger.warn(
            { devices: out.awaitingCredential },
            `${out.awaitingCredential} confirmed device(s) have no SNMP target and no credential `
              + 'is named. Set "Automatic SNMP target credential" once, at tenant or group level, '
              + 'and they will all be polled — no per-device configuration.',
          );
        }
      }
    } catch (err) {
      logger.error({ err }, 'SNMP auto-provisioning sweep failed');
    }
  };

  timer = setInterval(() => void tick(), intervalMs);
  timer.unref?.();
  // Once at startup too: a deploy is exactly when a fleet acquires devices that
  // were confirmed while this process was not running.
  void tick();
  logger.info({ intervalMs }, 'SNMP target auto-provisioning armed (leader)');
}

export function stopSnmpAutoProvision(): void {
  if (!timer) return;
  clearInterval(timer);
  timer = null;
  lastAwaiting = -1;
}
