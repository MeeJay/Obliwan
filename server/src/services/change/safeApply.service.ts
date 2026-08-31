/**
 * ObliWAN — M6 / K1. Safe-Apply: the sequence, and its order is the contract.
 *
 * This is the file that turns "we never touch production" into "we push on a
 * Tuesday". It is also the file that can take a customer off the air, so every
 * decision below is written in the form "what happens when this step is the one
 * that goes wrong".
 *
 *   a. assertTargetBinding() ON A FRESH CONNECTION (R4). Never the remembered
 *      IP, never a pooled socket. A PPP pool reassigns tunnel addresses; without
 *      this we push client A's firewall onto client B's router and everything
 *      else in this file works perfectly on the wrong box.
 *   b. PRE-CHANGE BACKUP, VERIFIED (R1). Size and digest, checked against a
 *      re-read from our own disk, before anything else happens. A backup that
 *      answered !done and produced 40 bytes is the classic silent failure.
 *   c. ARM THE DEAD-MAN, THEN PROVE IT IS ARMED. On a SECOND, fresh session:
 *      verifying the arming on the socket that did the arming proves the router
 *      accepted our sentences, not that the configuration is there. A dead-man
 *      we believe in and that does not exist is worse than none at all, because
 *      we then push with unjustified confidence.
 *   d. APPLY through `/system/script` wrapped in `:do{} on-error={rollback}`.
 *      NOT `/import`: it stops at the first error and leaves the router half
 *      configured with no handler.
 *   e. RECONNECT ON A BRAND-NEW SOCKET. An already-open socket survives a rule
 *      that blocks NEW connections and will happily tell you everything is fine
 *      from inside a box nobody can reach any more.
 *   f. POST-CONDITIONS: the device answers, its identity is the right one, the
 *      PPP session holds.
 *   g. SOAK 5 MINUTES. Many cuts do not show up immediately — a conntrack entry
 *      keeps the current flow alive while every new one is dropped.
 *   h. DISARM, WITH RETRY UNTIL IT SUCCEEDS. A failed disarm is a router that
 *      will revert a GOOD change at the next tick. If it fails definitively it
 *      is an incident to raise loudly, not a warning to log.
 *
 * WHAT THE DEAD-MAN IS, AND WHAT IT IS NOT
 * It is `/system/scheduler start-time=startup interval=T` running a script that
 * loads the preflight backup. It runs on the EQUIPMENT. It repairs the router
 * when the ObliWAN server is dead, when the network is cut, when this very
 * process no longer exists. A rollback driven from here would be exactly the
 * thing that cannot work once we have cut our own leg off, which is why the
 * server-driven path in `rollback.service.ts` is a convenience and never the
 * net.
 *
 * §8.2 THROUGHOUT: the rendered configuration exists in TWO versions. The
 * complete one, with the secrets the vault injected, exists only as
 * `RenderedChange.commands` in memory, on its way into the `=source=` word of a
 * `/system/script/add`. The redacted one is what reaches `change_job_steps`,
 * `command_audit`, the logs and the UI. `redactForAudit()` collapses `=source=`
 * to a byte count, and `assertNoSecrets()` refuses to persist a line in which a
 * declared secret still appears.
 */

import {
  FAMILY_BRAND,
  canTransition,
  guardAllowsApply,
  isWriteJobKind,
  requiresExplicitConfirmation,
  type ApplyOutcome,
  type ChangeJobKind,
  type ChangeJobStatus,
  type ChangeStepKind,
  type DeviceFamily,
  type GuardVerdict,
  type SafetyLevel,
} from '@obliwan/shared';
import { db } from '../../db';
import { findSecondUplink } from '../config/snapshot.service';
import { logger } from '../../utils/logger';
import { assertTargetBinding } from '../fleet/deviceBinding.service';
import {
  ChangeError,
  assertNoSecrets,
  backupPassword,
  getBackup,
  loadDeviceTarget,
  openDeviceSession,
  redactForAudit,
  takeDeviceBackup,
  type DeviceSession,
  type DeviceTarget,
  type DialFn,
} from './backup.service';
import {
  applyMarkerGlobal,
  armDeadman,
  buildApplyScriptSource,
  cleanupDeadmanArtefacts,
  deadmanNames,
  deadmanNamesFromHandle,
  disarmWithRetry,
  inspectDeadman,
  judgeArming,
  readDeadmanState,
  rollbackViaScript,
  type DeadmanEvidence,
  type DeadmanNames,
} from './rollback.service';
import { TransferReceiver } from './transfer.service';

// ============================================================================
// Timings
// ============================================================================

export interface SafeApplyTimings {
  /** How long the on-box dead-man waits before restoring. §5/M6 wants a window
   *  wide enough to reconnect, verify and soak, and narrow enough that a real
   *  cut is repaired before anybody drives anywhere. */
  deadmanSeconds: number;
  /** §5/M6: soak 5 minutes. */
  soakMs: number;
  /** How long to wait after the apply before the first reconnection attempt.
   *  Long enough for a firewall rule to take effect, short enough that we are
   *  not the reason the deadline is missed. */
  reconnectDelayMs: number;
  reconnectAttempts: number;
  reconnectIntervalMs: number;
  /** How often we re-probe the device during the soak. */
  soakProbeIntervalMs: number;
  disarmAttempts: number;
  disarmBackoffMs: number;
  /** After a lost contact, how long past the dead-man deadline we keep trying
   *  before declaring `lost_contact`. */
  recoveryGraceMs: number;
  recoveryProbeIntervalMs: number;
  connectTimeoutMs: number;
}

export const SAFE_APPLY_DEFAULTS: SafeApplyTimings = {
  deadmanSeconds: 600,
  soakMs: 5 * 60_000,
  reconnectDelayMs: 5_000,
  reconnectAttempts: 6,
  reconnectIntervalMs: 10_000,
  soakProbeIntervalMs: 30_000,
  disarmAttempts: 6,
  disarmBackoffMs: 3_000,
  recoveryGraceMs: 3 * 60_000,
  recoveryProbeIntervalMs: 15_000,
  connectTimeoutMs: 10_000,
};

/**
 * The dead-man window must be strictly longer than everything that has to
 * happen inside it, or a perfectly good change gets reverted because we were
 * still soaking when the router lost patience. Checked before arming, refused
 * rather than clamped: silently stretching an operator's window is how a
 * 10-minute net becomes a 40-minute one nobody asked for.
 */
export function assertTimingsCoherent(t: SafeApplyTimings): void {
  const needed =
    t.reconnectDelayMs +
    t.reconnectAttempts * t.reconnectIntervalMs +
    t.soakMs +
    t.disarmAttempts * t.disarmBackoffMs;
  if (t.deadmanSeconds * 1000 <= needed) {
    throw new ChangeError(
      'BACKUP_FAILED',
      `the dead-man window (${t.deadmanSeconds}s) is not longer than the ${Math.ceil(
        needed / 1000,
      )}s the reconnect + soak + disarm sequence needs. ` +
        'Widen the window or shorten the soak; do not let a good change be reverted by our own clock.',
      { deadmanSeconds: t.deadmanSeconds, neededMs: needed },
    );
  }
}

// ============================================================================
// §8.3 — the three levels of net, computed PER DEVICE
// ============================================================================

export interface SafetyNetAssessment {
  level: SafetyLevel;
  peerDeviceId: number | null;
  peerDeviceName: string | null;
  /** THE property of §8.3: does the net survive the death of this server? */
  survivesServerLoss: boolean;
  /** DEGRADED demands an explicit, recorded confirmation before any write. */
  requiresConfirmation: boolean;
  reason: string;
  checks: string[];
}

/**
 * A peer-carried net needs a way for the PEER to restore the TARGET without
 * ObliWAN. For a MikroTik that is `/system/script/run` over the LAN; for a
 * DrayTek, a Zyxel or a SonicWall it is a vendor CLI the peer would have to
 * speak, with a credential staged on the peer.
 *
 * THE MAP IS EMPTY AND THAT IS THE HONEST STATE OF THE WORLD. §8.3's
 * ARMED_BY_PEER is a real level, but it is a claim about a mechanism, and the
 * mechanism does not exist for any family yet. An empty map means
 * `resolveSafetyNet()` returns DEGRADED where a co-located MikroTik exists,
 * which is a level that is LOWER than reality might allow and never HIGHER.
 * "Un niveau de filet faux est pire qu'un niveau bas."
 *
 * Filling this in is not a formality: it stages a credential for the target on
 * a second device, which is a §8.2 tension that has to be arbitrated, not
 * assumed.
 */
export interface PeerRecoveryAdapter {
  family: DeviceFamily;
  /** Commands the PEER runs, on its own, to restore the target. */
  buildPeerRecovery(ctx: { target: DeviceTarget; peer: DeviceTarget }): string[];
}
/**
 * DELIBERATELY EMPTY, and it is not an oversight — it is the honest state.
 *
 * An entry here makes `armed_by_peer` REACHABLE, i.e. it makes the product
 * tell an operator "the dead-man is carried by MK-SHOP-12". Naming a rescuer
 * changes what a human approves: they read that line and click faster. So an
 * adapter may only be added once its command sequence has been run against
 * real hardware — a restore of a Vigor or a Zyxel driven from a RouterOS
 * script has never been executed here, and a net that has never been sprung is
 * a claim, not a net.
 *
 * Until then every non-MikroTik target resolves to `degraded`: detection
 * without recovery, with the explicit recorded confirmation §8.3 demands. That
 * is a worse product and a truthful one.
 */
/**
 * HOW A MIKROTIK RESCUES THE BOX NEXT TO IT — and why it is not "log in and
 * undo".
 *
 * ┌─ THE MECHANISM ──────────────────────────────────────────────────────────┐
 * │ A RouterOS script cannot drive a Vigor or a SonicWall CLI: there is no    │
 * │ scriptable SSH client on the box, and inventing one inside a scheduler    │
 * │ script is how you get a rescue that fails at 3am with no transcript.      │
 * │                                                                          │
 * │ But it does not need one. Zyxel ZLD and SonicOS both keep a change        │
 * │ PENDING until an explicit verb makes it durable — `write` and `commit`,   │
 * │ the two recorded in `SSH_DIALECTS`. So the recovery is not an undo, it is │
 * │ a REFUSAL TO COMMIT plus a power cycle: cut PoE, restore it, and the box  │
 * │ boots on the last configuration it actually saved. The pre-change state,  │
 * │ exactly, with no session, no credential and no CLI dialect involved.      │
 * │                                                                          │
 * │ That is what makes this a real dead-man: the scheduler fires ON THE PEER, │
 * │ on its own clock, while ObliWAN is unreachable and while the casualty is  │
 * │ unreachable. Nothing in the loop needs either of them to answer.          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY DRAYTEK IS ABSENT AND IT IS NOT AN OVERSIGHT ───────────────────────┐
 * │ The Vigor CLI applies per line — `SSH_DIALECTS.draytek_vigor.commitVerb`  │
 * │ is `null` and says so. A power cycle therefore reboots a Vigor onto the   │
 * │ configuration it was just given, which is the broken one. The mechanism   │
 * │ does not merely fail to help; it would be announced as a net and be none. │
 * │ A family belongs here only if withholding the commit is a real undo.      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * THE PORT IS RESOLVED BY THE PEER, AT RUN TIME. The script looks for the
 * ethernet port whose comment carries `obliwan:powers:<target-uuid>` — a
 * convention, not a schema, so no migration and no second place for the truth
 * to rot. If no port carries the marker the script logs and does nothing:
 * `assertPoePortDeclared()` below is what stops a net from being CLAIMED in
 * that case, and it runs before the arming, not after.
 *
 * STILL UNPROVEN, and the reason the map below is not simply switched on: no
 * Zyxel or SonicWall has ever been power-cycled by this code. The commands are
 * RouterOS's own and are covered by `m6-sshapply.verify.ts`'s sibling harness,
 * but "the box boots on its last saved config" is a claim about the CASUALTY,
 * and only a real one can settle it.
 */
export function poeMarkerFor(targetUuid: string): string {
  return `obliwan:powers:${targetUuid}`;
}

function buildPoeCycle(ctx: { target: DeviceTarget; peer: DeviceTarget }): string[] {
  const marker = poeMarkerFor(ctx.target.uuid);
  const port = `[/interface/ethernet find where comment~"${marker}"]`;
  return [
    `:local p ${port};`,
    ':if ([:len $p] = 0) do={' +
      `:log error "obliwan: no port carries ${marker}; cannot rescue ${ctx.target.name}"; ` +
      ':error "no poe port";' +
      '}',
    // Off, settle, on. The settle is not politeness: a PoE port toggled faster
    // than the PSE's own debounce leaves the far side powered and the rescue
    // silently does nothing.
    '/interface/ethernet/poe/set $p poe-out=off;',
    ':delay 8s;',
    '/interface/ethernet/poe/set $p poe-out=auto-on;',
    `:log warning "obliwan: power-cycled ${ctx.target.name} — dead-man fired on ${ctx.peer.name}";`,
  ];
}

export const PEER_RECOVERY_ADAPTERS: Partial<Record<DeviceFamily, PeerRecoveryAdapter>> = {
  zyxel_standalone: { family: 'zyxel_standalone', buildPeerRecovery: buildPoeCycle },
  sonicwall_sonicos: { family: 'sonicwall_sonicos', buildPeerRecovery: buildPoeCycle },
};

/**
 * Can the peer actually reach the target, right now, from where it stands?
 *
 * Read-only and best-effort-hostile: anything other than a clearly successful
 * ping counts as "no". `/ping` on RouterOS returns one sentence per probe with
 * a `received` word; a single reply is enough, because the question is "is
 * there a path at all", not "is the path good".
 */
/**
 * Does the peer actually POWER the target?
 *
 * Read-only, on the peer, at arming time. The convention is a comment on the
 * ethernet port (`obliwan:powers:<uuid>`) rather than a column: the fact lives
 * where the cable is, an operator can see it in Winbox next to the port it
 * describes, and it cannot drift out of sync with a database nobody looks at.
 *
 * Anything other than exactly one matching port is `false`. Two ports claiming
 * the same casualty is a mistake, and cycling the wrong one takes down a
 * device nobody was changing.
 */
async function peerPowersTarget(
  peerSession: { run: (words: string[], opts: { isWrite: boolean; skipAudit: boolean }) => Promise<unknown> },
  target: DeviceTarget,
  checks: string[],
): Promise<boolean> {
  const marker = poeMarkerFor(target.uuid);
  try {
    const out = (await peerSession.run(
      ['/interface/ethernet/print', `?comment=${marker}`],
      { isWrite: false, skipAudit: true },
    )) as Array<Record<string, string>> | undefined;
    const n = (out ?? []).length;
    checks.push(
      n === 1
        ? `peer powers the target: one port carries "${marker}"`
        : `peer does NOT power the target: ${n} ports carry "${marker}" (exactly 1 required)`,
    );
    return n === 1;
  } catch (err) {
    checks.push(`poe marker probe failed: ${err instanceof Error ? err.message : String(err)}`);
    return false;
  }
}

async function peerCanReachTarget(
  peerSession: { run: (words: string[], opts: { isWrite: boolean; skipAudit: boolean }) => Promise<unknown> },
  target: DeviceTarget,
  checks: string[],
): Promise<boolean> {
  const row = await db('device_transports')
    .where({ device_id: target.id, enabled: true })
    .whereNotNull('host')
    .orderBy('priority')
    .first<{ host: string } | undefined>('host');
  const address = row?.host ?? target.tunnelIp;
  if (!address) {
    checks.push('peer reachability NOT tested: the target has no management address on record');
    return false;
  }
  try {
    const out = (await peerSession.run(['/ping', `=address=${address}`, '=count=2'], {
      isWrite: false,
      skipAudit: true,
    })) as Array<Record<string, string>> | undefined;
    const received = (out ?? []).some((s) => Number(s.received ?? s['=received'] ?? 0) > 0);
    checks.push(
      received
        ? `peer reached the target at ${address}`
        : `peer could NOT reach the target at ${address} (no ICMP reply)`,
    );
    return received;
  } catch (err) {
    checks.push(`peer reachability probe failed: ${err instanceof Error ? err.message : String(err)}`);
    return false;
  }
}

export interface SafetyNetOptions {
  /** Actually dial the device (and the peer) to check the net can be built.
   *  Default true. `false` gives the inventory-arithmetic answer, which is a
   *  FALLBACK and is labelled as such in `reason`. */
  probe?: boolean;
  dial?: DialFn;
  connectTimeoutMs?: number;
}

/**
 * Compute the real level of net for one device — §8.3, before the launch and
 * never after it.
 *
 * ARMED requires four things to be TRUE, not assumed:
 *   the family is MikroTik; we can open a session; `/system/scheduler` answers;
 *   `/system/script` answers. A box that cannot hold a scheduler cannot hold a
 *   dead-man, whatever its badge says.
 */
export async function resolveSafetyNet(
  deviceId: number,
  options: SafetyNetOptions = {},
): Promise<SafetyNetAssessment> {
  const probe = options.probe !== false;
  const target = await loadDeviceTarget(deviceId);
  const brand = FAMILY_BRAND[target.family];
  const checks: string[] = [`family=${target.family} brand=${brand ?? 'unknown'}`];

  if (brand === 'mikrotik') {
    if (!probe) {
      return {
        level: 'armed',
        peerDeviceId: null,
        peerDeviceName: null,
        survivesServerLoss: true,
        requiresConfirmation: false,
        reason:
          'MikroTik: an on-box dead-man is expected to be installable. NOT PROBED — this is the ' +
          'inventory fallback and the probed level overrides it.',
        checks,
      };
    }
    let session: DeviceSession | null = null;
    try {
      session = await openDeviceSession(deviceId, {
        purpose: 'safety-net-probe',
        dial: options.dial,
        connectTimeoutMs: options.connectTimeoutMs,
      });
      await session.run(['/system/scheduler/print', '?name=obliwan-nonexistent'], {
        isWrite: false,
        skipAudit: true,
      });
      checks.push('/system/scheduler answers');
      await session.run(['/system/script/print', '?name=obliwan-nonexistent'], {
        isWrite: false,
        skipAudit: true,
      });
      checks.push('/system/script answers');
      return {
        level: 'armed',
        peerDeviceId: null,
        peerDeviceName: null,
        survivesServerLoss: true,
        requiresConfirmation: false,
        reason:
          'ARMED: the box holds its own dead-man — /system/scheduler start-time=startup plus a ' +
          'restore script. It repairs itself even if this server is dead.',
        checks,
      };
    } catch (err) {
      checks.push(`probe failed: ${err instanceof Error ? err.message : String(err)}`);
      return {
        level: 'degraded',
        peerDeviceId: null,
        peerDeviceName: null,
        survivesServerLoss: false,
        requiresConfirmation: true,
        reason:
          'DEGRADED: this is a MikroTik but we could not prove it can carry a scheduler and a ' +
          'script right now. Refusing to claim a net we did not see.',
        checks,
      };
    } finally {
      session?.close();
    }
  }

  // --- the other three brands (A2) ----------------------------------------
  //
  // §8.3's condition has two halves and only one of them was ever measured.
  // The old probe asked "can the peer hold a scheduler". It never asked the
  // question that actually decides whether the net exists: CAN THE PEER REACH
  // THE TARGET. On the one pairing this fleet actually has — a MikroTik with a
  // bridged Zyxel DSL modem — the answer depends on whether anyone put an
  // address on the WAN port in the modem's management subnet. A DHCP client
  // does it; the NCM cannot see that it did, because `resources.ts:106` drops
  // DHCP-learned addresses as state. So the fact is unknowable from the model
  // and has to be MEASURED, from the rescuer, at the moment the net is strung.
  const adapter = PEER_RECOVERY_ADAPTERS[target.family];

  // ── THE PEER MUST BE THE MANAGEMENT UPSTREAM, NOT MERELY A NEIGHBOUR ──────
  //
  // This used to take "any co-located MikroTik", ordered by id. On the pairing
  // this fleet actually has — a MikroTik behind a bridged Zyxel — that is the
  // right box by luck, not by reasoning, and on a site with two MikroTiks it
  // would pick whichever was created first.
  //
  // A rescuer only works if it is on OUR side of the break: it must survive the
  // cut and still reach the casualty locally. That is exactly what
  // `upstream_device_id` records (migration 030), and it is deliberately the
  // MANAGEMENT ordering, which on a bridged modem is the opposite of the
  // cabling. When it is null nobody has declared the topology, so nothing may
  // be inferred: the query falls back to the co-located search and the arming
  // probe still has to prove reachability before any net is claimed.
  const upstreamId = target.upstreamDeviceId;
  const peer = upstreamId
    ? await db('devices')
        .where({ id: upstreamId, is_managed: true })
        .whereIn('family', ['mikrotik_routeros6', 'mikrotik_routeros7'])
        .whereNot('status', 'disabled')
        .first<any>('id', 'name')
    : target.siteId
      ? await db('devices')
          .where({ site_id: target.siteId, is_managed: true })
          .whereIn('family', ['mikrotik_routeros6', 'mikrotik_routeros7'])
          .whereNot('id', deviceId)
          .whereNot('status', 'disabled')
          .orderBy('id')
          .first<any>('id', 'name')
      : null;
  if (upstreamId && peer) checks.push(`peer is the declared management upstream (#${peer.id})`);
  else if (!upstreamId) checks.push('no upstream declared: fell back to a co-located MikroTik');

  if (peer) checks.push(`co-located MikroTik candidate: #${peer.id} ${peer.name}`);
  else checks.push(target.siteId ? 'no co-located MikroTik on this site' : 'device has no site');

  if (peer && adapter) {
    // Both halves of §8.3's condition must hold: a peer that is REACHABLE, and
    // a tunnel to it that this change does not touch. The second half is not
    // computable here — it is a question about the plan, and the plan is K2's.
    // So this returns armed_by_peer only when a caller has supplied the
    // adapter AND the probe succeeded, and it still says out loud that the
    // untouched-tunnel half is the caller's to establish.
    if (probe) {
      try {
        const peerSession = await openDeviceSession(peer.id, {
          purpose: 'peer-net-probe',
          dial: options.dial,
          connectTimeoutMs: options.connectTimeoutMs,
        });
        await peerSession.run(['/system/scheduler/print', '?name=obliwan-nonexistent'], {
          isWrite: false,
          skipAudit: true,
        });
        checks.push('peer answered and can hold a scheduler');

        // THE SECOND HALF. A rescuer that cannot reach the casualty is not a
        // rescuer. Read-only, from the peer, to the target's management
        // address — and a failure DOWNGRADES rather than warns, because the
        // whole defect this guards against is a net that is announced and
        // absent.
        const reachable = await peerCanReachTarget(peerSession, target, checks);

        // The PoE marker: the peer must actually POWER the casualty, or the
        // recovery script has nothing to cycle. Asked HERE, on the peer, at
        // arming time — the only moment where the answer is worth anything —
        // and a missing marker DOWNGRADES rather than warns. A net announced
        // and absent is the whole defect this file has been fighting.
        const powered = await peerPowersTarget(peerSession, target, checks);
        peerSession.close();
        if (!powered) {
          return {
            level: 'degraded',
            peerDeviceId: peer.id,
            peerDeviceName: peer.name,
            survivesServerLoss: false,
            requiresConfirmation: true,
            reason:
              `DEGRADED: MikroTik #${peer.id} is the management upstream and answers, but no ` +
              `ethernet port on it carries the comment "${poeMarkerFor(target.uuid)}". The ` +
              'recovery is a power cycle; without a declared port there is nothing to cycle.',
            checks,
          };
        }
        if (!reachable) {
          return {
            level: 'degraded',
            peerDeviceId: peer.id,
            peerDeviceName: peer.name,
            survivesServerLoss: false,
            requiresConfirmation: true,
            reason:
              `DEGRADED: MikroTik #${peer.id} is co-located and could hold a scheduler, but it ` +
              'cannot reach this device on its management address. It would detect the loss and ' +
              'be unable to repair it — that is not a net.',
            checks,
          };
        }
        return {
          level: 'armed_by_peer',
          peerDeviceId: peer.id,
          peerDeviceName: peer.name,
          survivesServerLoss: true,
          requiresConfirmation: false,
          reason:
            `ARMED_BY_PEER: the dead-man is carried by MikroTik #${peer.id} on the same site. ` +
            'The caller must still establish that the change does not touch the tunnel to that peer.',
          checks,
        };
      } catch (err) {
        checks.push(`peer probe failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  } else if (peer && !adapter) {
    checks.push(
      `a co-located MikroTik exists but there is NO peer-recovery adapter for '${target.family}': ` +
        'the peer would detect the loss and be unable to repair it',
    );
  }

  // Before promising a van: does this box have a way home of its own? Same
  // reading as `resolveSafetyNet` in apply.service.ts, and it MUST agree with
  // it — the rule of §8.3 is that the level the operator lives with is the one
  // reported here, and a job stops when this one is worse. Two functions
  // disagreeing about LTE would halt every DrayTek write with no explanation.
  const uplink = await findSecondUplink(target.id);
  if (uplink) {
    checks.push(`second uplink present: "${uplink}" (type lte, enabled)`);
    return {
      level: 'armed_by_second_uplink',
      peerDeviceId: null,
      peerDeviceName: null,
      // NOT a dead-man: nothing repairs the device. It comes BACK, which is a
      // different promise, and it only holds if the change did not deny
      // management on every interface.
      survivesServerLoss: false,
      requiresConfirmation: false,
      reason:
        `ARMED_BY_SECOND_UPLINK: "${uplink}" is a live uplink on another medium. A mistake on ` +
        'the wired path is expected to be repairable remotely once the box fails over. This is ' +
        'not a dead-man and it does not survive a change that denies management everywhere.',
      checks,
    };
  }
  checks.push('no second uplink in the latest NCM');

  return {
    level: 'degraded',
    peerDeviceId: null,
    peerDeviceName: null,
    survivesServerLoss: false,
    requiresConfirmation: true,
    reason:
      `DEGRADED: '${target.family}' has no native dead-man, no peer can carry one for it, and ` +
      'it has no second uplink. Detection without recovery — we will know the CPE stopped ' +
      'answering and we will not be able to fix it remotely. §8.3 demands an explicit recorded ' +
      'confirmation before any write.',
    checks,
  };
}

// ============================================================================
// The rendered change — §8.2's two versions, side by side
// ============================================================================

export interface RenderedChange {
  /** THE COMPLETE VERSION. Secrets included. Exists in memory only, on the
   *  vault -> equipment path, and goes nowhere else. */
  commands: string[];
  /** The masked version. This is the ONLY one the database, the UI, the export
   *  and the logs are allowed to see. */
  redacted: string[];
  /** Literal secret values injected into `commands`. Used to scrub the audit
   *  trail and to refuse a persist that still contains one. */
  secretValues: string[];
}

/** Refuse a rendering whose "redacted" half still contains a secret. Called
 *  before anything is written anywhere. */
export function assertRenderingIsSafe(rendered: RenderedChange): void {
  if (rendered.commands.length === 0) {
    throw new ChangeError('BACKUP_FAILED', 'the rendered change is empty; there is nothing to apply');
  }
  for (const line of rendered.redacted) assertNoSecrets(line, rendered.secretValues);
}

// ============================================================================
// Job persistence
// ============================================================================

export interface ChangeJobRow {
  id: number;
  uuid: string;
  tenantId: number;
  deviceId: number;
  planId: number | null;
  kind: ChangeJobKind;
  status: ChangeJobStatus;
  attempt: number;
  maxAttempts: number;
  baseStateHash: string;
  safetyLevel: SafetyLevel;
  safetyPeerDeviceId: number | null;
  degradedConfirmedBy: number | null;
  guardVerdict: GuardVerdict | null;
  overrideReason: string | null;
  overriddenBy: number | null;
  preflightBackupId: number | null;
  deadmanHandle: string | null;
  deadmanArmedAt: Date | null;
  requestedBy: number | null;
  claimedBy: string | null;
}

export async function loadJob(jobId: number): Promise<ChangeJobRow> {
  const row = await db('change_jobs').where({ id: jobId }).first<any>();
  if (!row) throw new ChangeError('DEVICE_UNKNOWN', `change_job ${jobId} does not exist`);
  return {
    id: row.id,
    uuid: row.uuid,
    tenantId: row.tenant_id,
    deviceId: row.device_id,
    planId: row.plan_id ?? null,
    kind: row.kind,
    status: row.status,
    attempt: row.attempt,
    maxAttempts: row.max_attempts,
    baseStateHash: row.base_state_hash,
    safetyLevel: row.safety_level,
    safetyPeerDeviceId: row.safety_peer_device_id ?? null,
    degradedConfirmedBy: row.degraded_confirmed_by ?? null,
    guardVerdict: row.guard_verdict ?? null,
    overrideReason: row.override_reason ?? null,
    overriddenBy: row.overridden_by ?? null,
    preflightBackupId: row.preflight_backup_id ?? null,
    deadmanHandle: row.deadman_handle ?? null,
    deadmanArmedAt: row.deadman_armed_at ? new Date(row.deadman_armed_at) : null,
    requestedBy: row.requested_by ?? null,
    claimedBy: row.claimed_by ?? null,
  };
}

/**
 * Move a job, refusing an edge the state machine does not have.
 *
 * `CHANGE_JOB_TRANSITIONS` is advisory in the database (there is no trigger, by
 * design, because crash recovery legitimately needs unusual edges). It is NOT
 * advisory here: this is the only writer on the happy path and it honours the
 * map, so a bug that tries to jump `queued -> succeeded` fails at the first
 * step rather than at the post-mortem.
 */
export async function moveJob(
  jobId: number,
  from: ChangeJobStatus,
  to: ChangeJobStatus,
  patch: Record<string, unknown> = {},
): Promise<void> {
  if (!canTransition(from, to)) {
    throw new ChangeError('BACKUP_FAILED', `illegal job transition ${from} -> ${to}`, { jobId });
  }
  const terminal = ['succeeded', 'rolled_back', 'failed', 'aborted'].includes(to);
  const updated = await db('change_jobs')
    .where({ id: jobId, status: from })
    .update({
      status: to,
      ...(terminal ? { finished_at: db.fn.now() } : {}),
      ...patch,
      updated_at: db.fn.now(),
    });
  if (updated !== 1) {
    throw new ChangeError(
      'BACKUP_FAILED',
      `job ${jobId} was no longer in '${from}' when moving to '${to}' — ` +
        'somebody else is driving this job',
    );
  }
}

// ============================================================================
// Step recording
// ============================================================================

class StepRecorder {
  private seq = 0;
  constructor(
    private readonly jobId: number,
    private readonly attempt: number,
    private readonly secrets: readonly string[],
    private readonly emit?: (event: string, payload: unknown) => void,
  ) {}

  async run<T>(
    kind: ChangeStepKind,
    fn: (setOutput: (text: string) => void) => Promise<T>,
    options: { planOpSeq?: number | null } = {},
  ): Promise<T> {
    const seq = this.seq++;
    const startedAt = new Date();
    const [row] = await db('change_job_steps')
      .insert({
        job_id: this.jobId,
        attempt: this.attempt,
        seq,
        kind,
        status: 'running',
        plan_op_seq: options.planOpSeq ?? null,
        started_at: startedAt,
      })
      .returning('id');
    const stepId = typeof row === 'object' ? Number((row as any).id) : Number(row);
    this.emit?.('step', { jobId: this.jobId, seq, kind, status: 'running' });
    let output: string | null = null;
    const setOutput = (text: string) => {
      // Every string that reaches the database goes through the same scrub.
      const line = redactForAudit([text], this.secrets);
      assertNoSecrets(line, this.secrets);
      output = line;
    };
    try {
      const result = await fn(setOutput);
      await db('change_job_steps')
        .where({ id: stepId })
        .update({
          status: 'succeeded',
          finished_at: new Date(),
          duration_ms: Date.now() - startedAt.getTime(),
          output_redacted: output,
        });
      this.emit?.('step', { jobId: this.jobId, seq, kind, status: 'succeeded' });
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const safe = redactForAudit([message], this.secrets);
      await db('change_job_steps')
        .where({ id: stepId })
        .update({
          status: 'failed',
          finished_at: new Date(),
          duration_ms: Date.now() - startedAt.getTime(),
          output_redacted: output,
          error_redacted: safe,
        });
      this.emit?.('step', { jobId: this.jobId, seq, kind, status: 'failed', error: safe });
      throw err;
    }
  }

  async skip(kind: ChangeStepKind, why: string): Promise<void> {
    const seq = this.seq++;
    await db('change_job_steps').insert({
      job_id: this.jobId,
      attempt: this.attempt,
      seq,
      kind,
      status: 'skipped',
      started_at: new Date(),
      finished_at: new Date(),
      duration_ms: 0,
      output_redacted: why,
    });
    this.emit?.('step', { jobId: this.jobId, seq, kind, status: 'skipped', why });
  }
}

// ============================================================================
// The kill switch — read once, fail closed
// ============================================================================

export interface KillSwitchDecisionRow {
  blocked: boolean;
  scope: 'global' | 'tenant' | null;
  reason: string | null;
}

/**
 * FAIL CLOSED. A missing global row blocks. Migration 009 seeds it disengaged
 * and a trigger refuses its deletion, so the normal read always finds it — but
 * "the row is not there" must never read as "go ahead".
 */
export async function checkKillSwitch(tenantId: number): Promise<KillSwitchDecisionRow> {
  const rows = await db('kill_switch')
    .where({ scope: 'global' })
    .orWhere(function tenantRow(this: any) {
      this.where({ scope: 'tenant', tenant_id: tenantId });
    })
    .select<any[]>('scope', 'engaged', 'reason');
  const global = rows.find((r) => r.scope === 'global');
  if (!global) {
    return {
      blocked: true,
      scope: 'global',
      reason: 'the global kill-switch row is missing; refusing every write (fail closed)',
    };
  }
  if (global.engaged) return { blocked: true, scope: 'global', reason: global.reason ?? null };
  const tenant = rows.find((r) => r.scope === 'tenant');
  if (tenant?.engaged) return { blocked: true, scope: 'tenant', reason: tenant.reason ?? null };
  return { blocked: false, scope: null, reason: null };
}

// ============================================================================
// Safe apply
// ============================================================================

export interface SafeApplyOptions {
  jobId: number;
  /** The complete + redacted rendering. §8.2. */
  rendered: RenderedChange;
  worker?: string;
  timings?: Partial<SafeApplyTimings>;
  dial?: DialFn;
  receiver?: TransferReceiver;
  callbackHost?: string;
  correlationId?: string | null;
  emit?: (event: string, payload: unknown) => void;
  /** Skip the (slow) soak. Only the self-test passes this, and it says so in
   *  the step trace so a shortened soak can never be mistaken for a full one. */
  soakOverrideMs?: number;
}

export interface SafeApplyResult {
  jobId: number;
  status: ChangeJobStatus;
  outcome: ApplyOutcome | null;
  deadmanHandle: string | null;
  deadmanArmedAt: string | null;
  deadmanDisarmedAt: string | null;
  preflightBackupId: number | null;
  rscBackupId: number | null;
  evidence: DeadmanEvidence | null;
  errorKind: string | null;
  errorMessage: string | null;
  timeline: Array<{ at: string; what: string }>;
}

const RECONNECT_FAILURE = /closed|reset|timed out|refus|ECONNRESET|EPIPE|EHOSTUNREACH|ENETUNREACH|not established/i;

/**
 * Run the whole sequence for one claimed job.
 *
 * The caller (`jobQueue`, another agent's file) is responsible for having
 * claimed the job — this function refuses a job that is not in `claimed`,
 * because a second worker running the sequence on a device that already has one
 * is the failure `change_jobs_one_in_flight_uq` exists to make impossible.
 */
export async function runSafeApply(options: SafeApplyOptions): Promise<SafeApplyResult> {
  const timings: SafeApplyTimings = { ...SAFE_APPLY_DEFAULTS, ...(options.timings ?? {}) };
  if (options.soakOverrideMs !== undefined) timings.soakMs = options.soakOverrideMs;
  assertTimingsCoherent(timings);
  assertRenderingIsSafe(options.rendered);

  const timeline: Array<{ at: string; what: string }> = [];
  const mark = (what: string) => {
    timeline.push({ at: new Date().toISOString(), what });
    logger.info({ jobId: options.jobId, step: what }, 'safeApply');
  };

  const job = await loadJob(options.jobId);
  const secrets = options.rendered.secretValues;
  const steps = new StepRecorder(job.id, job.attempt, secrets, options.emit);

  const result: SafeApplyResult = {
    jobId: job.id,
    status: job.status,
    outcome: null,
    deadmanHandle: null,
    deadmanArmedAt: null,
    deadmanDisarmedAt: null,
    preflightBackupId: null,
    rscBackupId: null,
    evidence: null,
    errorKind: null,
    errorMessage: null,
    timeline,
  };

  const fail = async (
    from: ChangeJobStatus,
    kind: string,
    message: string,
  ): Promise<SafeApplyResult> => {
    result.errorKind = kind;
    result.errorMessage = message;
    result.status = 'failed';
    await moveJob(job.id, from, 'failed', {
      error_kind: kind.slice(0, 48),
      error_message: message,
    }).catch((e) => logger.error({ err: e }, 'could not mark the job failed'));
    options.emit?.('failed', { jobId: job.id, errorKind: kind, message });
    return result;
  };

  // ---- gates that must hold before a single byte goes out ------------------
  if (job.status !== 'claimed') {
    throw new ChangeError(
      'BACKUP_FAILED',
      `job ${job.id} is '${job.status}', not 'claimed'. runSafeApply drives a claimed job only.`,
    );
  }
  const kill = await checkKillSwitch(job.tenantId);
  if (kill.blocked) {
    return fail(
      'claimed',
      'KILL_SWITCH',
      `the ${kill.scope} kill switch is engaged: ${kill.reason ?? 'no reason recorded'}`,
    );
  }
  if (isWriteJobKind(job.kind)) {
    if (!job.guardVerdict) {
      return fail('claimed', 'GUARD_MISSING', 'a write job without a guard verdict cannot proceed');
    }
    if (!guardAllowsApply(job.guardVerdict) && !job.overrideReason) {
      // Belt and braces: migration 009 already refuses this row shape. The
      // check is repeated because `verdict !== 'REJECT'` is the exact mistake
      // shared/change.ts warns about, and a second reader is cheap.
      return fail(
        'claimed',
        'GUARD_BLOCKED',
        `guard verdict ${job.guardVerdict} and no recorded override — refusing to apply`,
      );
    }
    if (requiresExplicitConfirmation(job.safetyLevel) && !job.degradedConfirmedBy) {
      return fail(
        'claimed',
        'DEGRADED_UNCONFIRMED',
        '§8.3: a DEGRADED device requires an explicit recorded confirmation before a write',
      );
    }
  }

  const ownReceiver = !options.receiver;
  const receiver = options.receiver ?? new TransferReceiver();
  if (ownReceiver) await receiver.start();

  const sessionOptions = {
    jobId: job.id,
    userId: job.requestedBy,
    correlationId: options.correlationId ?? job.uuid,
    dial: options.dial,
    connectTimeoutMs: timings.connectTimeoutMs,
    secretValues: secrets,
  };
  const freshSession = (purpose: string) =>
    openDeviceSession(job.deviceId, { purpose, ...sessionOptions });

  let names: DeadmanNames | null = null;
  let armedAt: Date | null = null;
  let binaryBackupId: number | null = null;
  let rscBackupId: number | null = null;
  let backupPasswordPlain: string | null = null;

  try {
    // ================= a. R4 — identity, on a fresh connection ==============
    await steps.run('bind_assert', async (out) => {
      const assertion = await assertTargetBinding(job.deviceId, { throwOnFailure: true });
      out(
        `identity confirmed on ${assertion.matched} attribute(s) over a fresh socket to ` +
          `${assertion.dialled}`,
      );
    });
    mark('bind_assert ok');
    await db('change_jobs')
      .where({ id: job.id })
      .update({ started_at: db.fn.now(), updated_at: db.fn.now() });

    // ================= b. the mandatory pre-change backup ==================
    await moveJob(job.id, 'claimed', 'backing_up');
    result.status = 'backing_up';
    const dm = deadmanNames(job.id);
    names = dm;

    const backupSet = await steps.run('preflight_backup', async (out) => {
      const set = await takeDeviceBackup({
        deviceId: job.deviceId,
        trigger: 'preflight',
        kinds: ['binary', 'rsc'],
        jobId: job.id,
        retentionClass: 'standard',
        createdBy: job.requestedBy,
        correlationId: options.correlationId ?? job.uuid,
        dial: options.dial,
        receiver,
        callbackHost: options.callbackHost,
        // The binary blob STAYS on the router: the dead-man loads it with the
        // tunnel down. It is deleted at disarm, and the job cannot succeed
        // while it is there.
        keepOnDeviceKinds: ['binary'],
        fileBaseName: { binary: dm.backupFileBase },
      });
      out(
        `binary ${set.binary?.sizeBytes ?? 0} B sha256=${(set.binary?.sha256 ?? '').slice(0, 16)}… ` +
          `(kept on device as ${set.binary?.onDeviceFileName ?? '-'}), ` +
          `rsc ${set.rsc?.sizeBytes ?? 0} B erased from the device, ` +
          `total ${set.totalMs} ms`,
      );
      return set;
    });
    binaryBackupId = backupSet.binary?.id ?? null;
    rscBackupId = backupSet.rsc?.id ?? null;
    result.preflightBackupId = binaryBackupId;
    result.rscBackupId = rscBackupId;
    if (!binaryBackupId) {
      return await fail('backing_up', 'BACKUP_FAILED', 'no binary preflight backup was produced');
    }
    await db('change_jobs')
      .where({ id: job.id })
      .update({ preflight_backup_id: binaryBackupId, updated_at: db.fn.now() });
    const stored = await getBackup(binaryBackupId);
    backupPasswordPlain = stored ? backupPassword(stored) : null;
    if (!backupPasswordPlain) {
      return await fail(
        'backing_up',
        'BACKUP_FAILED',
        'the preflight backup has no recoverable password; the dead-man could not load it',
      );
    }
    mark(`preflight backup ${binaryBackupId} taken and verified`);

    // ================= c. arm the dead-man, THEN prove it ==================
    await moveJob(job.id, 'backing_up', 'arming');
    result.status = 'arming';

    await steps.run('arm_deadman', async (out) => {
      const arming = await freshSession('arm');
      try {
        await armDeadman(arming, {
          jobId: job.id,
          backupFileName: dm.backupFileName,
          backupPassword: backupPasswordPlain as string,
          intervalSeconds: timings.deadmanSeconds,
        });
      } finally {
        arming.close();
      }

      // THE VERIFICATION, ON A SECOND SOCKET. Verifying on the socket that did
      // the arming proves the router accepted our sentences, not that the
      // configuration is there.
      const check = await freshSession('arm-verify');
      let verdict;
      try {
        verdict = judgeArming(await readDeadmanState(check, dm), {
          schedulerName: dm.schedulerName,
          scriptName: dm.scriptName,
          intervalSeconds: timings.deadmanSeconds,
        });
      } finally {
        check.close();
      }
      if (!verdict.armed) {
        throw new ChangeError(
          'BACKUP_FAILED',
          `the dead-man is NOT armed: ${verdict.problems.join('; ')}. ` +
            'Refusing to apply — pushing with a net we only believe in is worse than not pushing.',
        );
      }
      out(
        `armed and verified on a second socket: scheduler '${dm.schedulerName}' ` +
          `start-time=startup interval=${verdict.state.schedulerIntervalSeconds}s -> ` +
          `'${dm.scriptName}', blob ${dm.backupFileName} present`,
      );
    });

    armedAt = new Date();
    result.deadmanHandle = dm.handle;
    result.deadmanArmedAt = armedAt.toISOString();
    await db('change_jobs')
      .where({ id: job.id })
      .update({
        deadman_handle: dm.handle,
        deadman_armed_at: armedAt,
        confirm_deadline: new Date(armedAt.getTime() + timings.deadmanSeconds * 1000),
        updated_at: db.fn.now(),
      });
    options.emit?.('armed', {
      jobId: job.id,
      handle: dm.handle,
      deadlineAt: new Date(armedAt.getTime() + timings.deadmanSeconds * 1000).toISOString(),
    });
    mark(`dead-man armed and verified (window ${timings.deadmanSeconds}s)`);

    // ================= d. apply, via /system/script, NOT /import ===========
    await moveJob(job.id, 'arming', 'applying');
    result.status = 'applying';
    const marker = applyMarkerGlobal(job.id);
    const applyScriptName = `obliwan-apply-${job.id}`;

    let applyMarker: string | null = null;
    try {
      await steps.run('apply', async (out) => {
        const session = await freshSession('apply');
        try {
          const source = buildApplyScriptSource({
            jobId: job.id,
            commands: options.rendered.commands,
            rollbackScriptName: dm.scriptName,
            markerGlobal: marker,
          });
          // Remove a leftover from a previous attempt before adding.
          const existing = await session
            .run(['/system/script/print', `?name=${applyScriptName}`], {
              isWrite: false,
              skipAudit: true,
            })
            .catch(() => [] as Record<string, string>[]);
          if (existing.length > 0) {
            await session.run(['/system/script/remove', `=numbers=${applyScriptName}`], {
              isWrite: true,
            });
          }
          await session.run(
            [
              '/system/script/add',
              `=name=${applyScriptName}`,
              '=policy=read,write,policy,test',
              `=source=${source}`,
            ],
            { isWrite: true },
          );
          await session.run(['/system/script/run', `=number=${applyScriptName}`], {
            isWrite: true,
            timeoutMs: 120_000,
          });
          // `/system/script/run` answers !done whether the body worked or the
          // on-error branch ran — that is what an error handler IS. The global
          // is the only thing that distinguishes them.
          const env = await session
            .run(['/system/script/environment/print', `?name=${marker}`], {
              isWrite: false,
              skipAudit: true,
            })
            .catch(() => [] as Record<string, string>[]);
          applyMarker = env.find((r) => r.name === marker)?.value ?? null;
          out(
            `${options.rendered.redacted.length} command(s) applied through /system/script ` +
              `wrapped in :do{} on-error={${dm.scriptName}}; marker=${applyMarker ?? 'unreadable'}`,
          );
        } finally {
          session.close();
        }
      });
    } catch (err) {
      // The write may or may not have landed. We are past the frontier: no
      // retry, and the dead-man is armed and counting.
      mark(`apply threw: ${err instanceof Error ? err.message : String(err)}`);
      applyMarker = null;
    }
    mark(`apply issued (marker=${applyMarker ?? 'unreadable'})`);

    // ================= e/f. reconnect on a NEW socket, post-conditions =====
    await moveJob(job.id, 'applying', 'verifying');
    result.status = 'verifying';

    const reconnected = await steps.run('reconnect', async (out) => {
      await sleep(timings.reconnectDelayMs);
      let lastError = '';
      for (let i = 1; i <= timings.reconnectAttempts; i++) {
        try {
          const session = await freshSession('reconnect');
          session.close();
          out(`reconnected on a brand-new socket at attempt ${i}`);
          return true;
        } catch (err) {
          lastError = err instanceof Error ? err.message : String(err);
          if (i < timings.reconnectAttempts) await sleep(timings.reconnectIntervalMs);
        }
      }
      out(`no new socket could be opened in ${timings.reconnectAttempts} attempts: ${lastError}`);
      return false;
    });

    if (!reconnected) {
      // THE CASE THE WHOLE MILESTONE EXISTS FOR. We cannot reach the box. We do
      // not panic, we do not retry the write, and above all we do not "fix" it
      // from here — we WAIT for the on-box dead-man, which is doing its job
      // precisely because we are not part of it any more.
      mark('contact lost after the apply — waiting for the on-box dead-man');
      return await awaitDeadmanRecovery({
        job,
        names: dm,
        armedAt,
        timings,
        steps,
        freshSession,
        receiver,
        callbackHost: options.callbackHost,
        rscBackupId,
        opsCount: options.rendered.commands.length,
        result,
        emit: options.emit,
        mark,
      });
    }

    if (applyMarker === 'failed') {
      // The on-box handler already fired the rollback. Wait for it the same way
      // we would wait for the dead-man.
      mark('the on-error branch ran on the router: the change failed and rollback was triggered');
      return await awaitDeadmanRecovery({
        job,
        names: dm,
        armedAt,
        timings,
        steps,
        freshSession,
        receiver,
        callbackHost: options.callbackHost,
        rscBackupId,
        opsCount: options.rendered.commands.length,
        result,
        emit: options.emit,
        mark,
      });
    }

    await steps.run('postcheck', async (out) => {
      const session = await freshSession('postcheck');
      try {
        const identity = await session.run(['/system/identity/print'], {
          isWrite: false,
          skipAudit: true,
        });
        const ppp = await checkPppSession(job.deviceId);
        // The identity was already re-verified by `openDeviceSession` (R4), so
        // reaching this line IS the identity post-condition.
        out(
          `device answers as '${identity[0]?.name ?? '?'}'; identity re-asserted on the new socket; ` +
            `ppp session: ${ppp}`,
        );
      } finally {
        session.close();
      }
    });
    mark('post-conditions hold');

    // ================= g. soak ============================================
    await moveJob(job.id, 'verifying', 'soaking', {
      soak_until: new Date(Date.now() + timings.soakMs),
    });
    result.status = 'soaking';
    options.emit?.('soaking', { jobId: job.id, soakMs: timings.soakMs });

    const soakOk = await steps.run('soak', async (out) => {
      const until = Date.now() + timings.soakMs;
      let probes = 0;
      let failures = 0;
      while (Date.now() < until) {
        await sleep(Math.min(timings.soakProbeIntervalMs, Math.max(0, until - Date.now())));
        if (Date.now() >= until && probes > 0) break;
        probes++;
        try {
          const s = await freshSession('soak-probe');
          s.close();
        } catch (err) {
          failures++;
          const message = err instanceof Error ? err.message : String(err);
          out(
            `probe ${probes} FAILED after ${Math.round(
              (Date.now() - (until - timings.soakMs)) / 1000,
            )}s: ${message}`,
          );
          if (RECONNECT_FAILURE.test(message)) return false;
        }
      }
      out(
        `soaked ${Math.round(timings.soakMs / 1000)}s, ${probes} fresh-socket probe(s), ` +
          `${failures} failure(s)` +
          (options.soakOverrideMs !== undefined
            ? ' — SOAK SHORTENED BY THE CALLER (test run), this is not a 5-minute soak'
            : ''),
      );
      return true;
    });

    if (!soakOk) {
      mark('the device stopped answering during the soak');
      return await awaitDeadmanRecovery({
        job,
        names: dm,
        armedAt,
        timings,
        steps,
        freshSession,
        receiver,
        callbackHost: options.callbackHost,
        rscBackupId,
        opsCount: options.rendered.commands.length,
        result,
        emit: options.emit,
        mark,
      });
    }

    // ================= h. disarm, with retry until it succeeds =============
    await moveJob(job.id, 'soaking', 'disarming');
    result.status = 'disarming';

    const disarm = await steps.run('disarm', async (out) => {
      const outcome = await disarmWithRetry({
        openSession: () => freshSession('disarm'),
        names: dm,
        attempts: timings.disarmAttempts,
        backoffMs: timings.disarmBackoffMs,
        onAttempt: (attempt, error) =>
          logger.warn({ jobId: job.id, attempt, error }, 'disarm attempt failed, retrying'),
      });
      out(
        outcome.disarmed
          ? `disarmed and verified after ${outcome.attempts} attempt(s) in ${outcome.elapsedMs} ms; ` +
              `dead-man blob removed: ${outcome.backupRemoved}`
          : `DISARM FAILED after ${outcome.attempts} attempts: ${outcome.lastError ?? 'unknown'}`,
      );
      return outcome;
    }).catch((err) => {
      logger.error({ err, jobId: job.id }, 'the disarm step itself threw');
      return null;
    });

    if (!disarm || !disarm.disarmed) {
      // NOT a warning. The router is up, the change is good, and it carries a
      // scheduler that will revert it at the next tick. Somebody must be told.
      const deadline = armedAt
        ? new Date(armedAt.getTime() + timings.deadmanSeconds * 1000).toISOString()
        : 'unknown';
      logger.fatal(
        { jobId: job.id, deviceId: job.deviceId, handle: dm.handle, deadline },
        'INCIDENT: the change applied and verified, but the dead-man could NOT be disarmed. ' +
          'The equipment will revert this change by itself. Manual intervention required.',
      );
      options.emit?.('incident', {
        jobId: job.id,
        kind: 'DEADMAN_STILL_ARMED',
        handle: dm.handle,
        revertsAt: deadline,
      });
      return await fail(
        'disarming',
        'DEADMAN_STILL_ARMED',
        `the change is applied and verified but the dead-man could not be disarmed; ` +
          `the equipment will restore itself at ${deadline}. Manual intervention required.`,
      );
    }

    if (!disarm.backupRemoved) {
      logger.error(
        { jobId: job.id, file: dm.backupFileName },
        'the dead-man backup blob is still on the equipment after a successful disarm',
      );
    }

    await db('change_jobs')
      .where({ id: job.id })
      .update({ deadman_disarmed_at: new Date(), updated_at: db.fn.now() });
    result.deadmanDisarmedAt = new Date().toISOString();
    options.emit?.('disarmed', { jobId: job.id, handle: dm.handle });
    mark(`dead-man disarmed after ${disarm.attempts} attempt(s)`);

    await moveJob(job.id, 'disarming', 'succeeded', { outcome: 'succeeded' });
    result.status = 'succeeded';
    result.outcome = 'succeeded';
    await steps.run('record_outcome', async (out) => {
      await recordApplyOutcome(job, 'succeeded', { opsCount: options.rendered.commands.length });
      out('apply_outcomes: succeeded');
    });
    options.emit?.('succeeded', { jobId: job.id });
    mark('succeeded');
    return result;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const safe = redactForAudit([message], secrets);
    logger.error({ err, jobId: job.id }, 'safeApply aborted');
    const current = (await loadJob(job.id)).status;
    if (!['succeeded', 'rolled_back', 'failed', 'aborted'].includes(current)) {
      result.errorKind = err instanceof ChangeError ? err.kind : 'UNEXPECTED';
      result.errorMessage = safe;
      await moveJob(job.id, current, 'failed', {
        error_kind: (result.errorKind ?? 'UNEXPECTED').slice(0, 48),
        error_message: safe,
      }).catch((e) => logger.error({ err: e }, 'could not mark the job failed'));
      result.status = 'failed';
    }
    return result;
  } finally {
    if (ownReceiver) await receiver.stop();
  }
}

// ============================================================================
// The recovery path — waiting for a net we are not part of
// ============================================================================

interface RecoveryContext {
  job: ChangeJobRow;
  names: DeadmanNames;
  armedAt: Date | null;
  timings: SafeApplyTimings;
  steps: StepRecorder;
  freshSession: (purpose: string) => Promise<DeviceSession>;
  receiver: TransferReceiver;
  callbackHost?: string;
  rscBackupId: number | null;
  opsCount: number;
  result: SafeApplyResult;
  emit?: (event: string, payload: unknown) => void;
  mark: (what: string) => void;
}

/**
 * Wait for the equipment to repair itself, then say what happened.
 *
 * Two clocks are involved and neither is ours: the router's scheduler interval,
 * and the reboot that `/system/backup/load` triggers. We wait until the
 * deadline plus a grace period, probing on a FRESH socket each time, and then:
 *
 *   - it answered again and the evidence says the dead-man fired ->
 *     `rolled_back`, which is a SUCCESSFUL outcome of the safety machinery;
 *   - it answered again and everything is still armed -> the cut was transient
 *     and the change is still live. We do NOT call that success: we stop, mark
 *     the job failed, and leave the dead-man armed so the box reverts. A
 *     half-understood state must not be disarmed;
 *   - it never answered -> `lost_contact`. That is the outcome that means a
 *     van, and it is a separate value from `rolled_back` precisely so nobody
 *     can average the two into a reassuring success rate.
 */
async function awaitDeadmanRecovery(ctx: RecoveryContext): Promise<SafeApplyResult> {
  const { job, names, timings, steps, result } = ctx;
  const deadline = ctx.armedAt
    ? ctx.armedAt.getTime() + timings.deadmanSeconds * 1000
    : Date.now() + timings.deadmanSeconds * 1000;
  const giveUpAt = deadline + timings.recoveryGraceMs;

  // Best effort, and only best effort: if the box is still reachable, firing the
  // rollback now saves the customer the rest of the countdown. If it is not, we
  // lose nothing — the on-box net is already counting and does not need us.
  await steps
    .run('rollback', async (out) => {
      let triggered = false;
      try {
        const session = await ctx.freshSession('rollback-nudge');
        try {
          const r = await rollbackViaScript(session, names);
          triggered = r.triggered;
          out(
            r.triggered
              ? 'the device was still reachable: its own rollback script was fired immediately ' +
                  'instead of waiting out the dead-man interval'
              : `could not fire the rollback script: ${r.error}`,
          );
        } finally {
          session.close();
        }
      } catch (err) {
        out(
          'the device is unreachable, which is exactly the case the on-box dead-man exists for. ' +
            `Waiting for it. (${err instanceof Error ? err.message : String(err)})`,
        );
      }
      return triggered;
    })
    .catch(() => undefined);

  const from = result.status as ChangeJobStatus;
  ctx.mark(`waiting for the dead-man; deadline ${new Date(deadline).toISOString()}`);

  const evidence = await steps.run('postcheck', async (out) => {
    let lastError = '';
    while (Date.now() < giveUpAt) {
      await sleep(timings.recoveryProbeIntervalMs);
      let session: DeviceSession | null = null;
      try {
        session = await ctx.freshSession('recovery-probe');
        const e = await inspectDeadman({
          session,
          handle: names.handle,
          armedAt: ctx.armedAt,
          receiver: ctx.receiver,
          rscBackupId: ctx.rscBackupId,
          callbackHost: ctx.callbackHost,
        });
        if (e.verdict === 'fired_restored') {
          // Clean up the blob the restore could not remove (it is a file, not
          // configuration, so it survived).
          const cleanup = await cleanupDeadmanArtefacts(session, names.handle).catch(() => ({
            ok: false,
            detail: 'cleanup threw',
          }));
          out(
            `the device came back and the dead-man fired (${e.confidence}): ` +
              `${e.observations.join('; ')}. Cleanup: ${cleanup.detail}`,
          );
          return e;
        }
        if (e.verdict === 'still_armed' && Date.now() > deadline + 30_000) {
          out(
            'the device answers and the dead-man is STILL armed past its deadline — ' +
              'the scheduler did not fire. Leaving it armed and stopping here.',
          );
          return e;
        }
        lastError = `still ${e.verdict}`;
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
      } finally {
        session?.close();
      }
    }
    out(`the device never came back: ${lastError}`);
    return null;
  });

  result.evidence = evidence;

  if (evidence?.verdict === 'fired_restored') {
    await moveJob(job.id, from, 'rolled_back', {
      outcome: 'rolled_back',
      error_kind: 'DEADMAN_FIRED',
      error_message:
        'the equipment restored itself from the pre-change backup without any intervention ' +
        `(${evidence.confidence})`,
    });
    result.status = 'rolled_back';
    result.outcome = 'rolled_back';
    await steps.run('record_outcome', async (out) => {
      await recordApplyOutcome(job, 'rolled_back', { opsCount: ctx.opsCount, failureKind: 'DEADMAN_FIRED' });
      out('apply_outcomes: rolled_back');
    });
    ctx.emit?.('rolled_back', { jobId: job.id, confidence: evidence.confidence });
    ctx.mark(`rolled_back (${evidence.confidence})`);
    return result;
  }

  if (evidence?.verdict === 'still_armed') {
    await moveJob(job.id, from, 'failed', {
      error_kind: 'DEADMAN_DID_NOT_FIRE',
      error_message:
        'contact was lost and then recovered, but the dead-man is still armed past its deadline. ' +
        'The change may still be live. The net is deliberately left armed.',
    });
    result.status = 'failed';
    result.errorKind = 'DEADMAN_DID_NOT_FIRE';
    return result;
  }

  await moveJob(job.id, from, 'failed', {
    outcome: 'lost_contact',
    error_kind: 'LOST_CONTACT',
    error_message:
      'the equipment stopped answering after the change and never came back within the ' +
      'dead-man deadline plus grace. If its net was DEGRADED, this means a site visit.',
  });
  result.status = 'failed';
  result.outcome = 'lost_contact';
  result.errorKind = 'LOST_CONTACT';
  await steps.run('record_outcome', async (out) => {
    await recordApplyOutcome(job, 'lost_contact', { opsCount: ctx.opsCount, failureKind: 'LOST_CONTACT' });
    out('apply_outcomes: lost_contact');
  });
  ctx.emit?.('lost_contact', { jobId: job.id });
  ctx.mark('lost_contact');
  return result;
}

// ============================================================================
// §8.3 — the empirical corpus
// ============================================================================

/**
 * One row per application. Never a counter: the question asked six months from
 * now ("does this fail on 4.4.x specifically, or on the 2927 in general?") is a
 * re-slice, and a counter cannot be re-sliced.
 *
 * Honest limit, restated: while the corpus is empty this protects nothing.
 */
export async function recordApplyOutcome(
  job: ChangeJobRow,
  outcome: ApplyOutcome,
  extra: { opsCount?: number; durationMs?: number | null; failureKind?: string | null } = {},
): Promise<void> {
  const target = await loadDeviceTarget(job.deviceId).catch(() => null);
  await db('apply_outcomes').insert({
    tenant_id: job.tenantId,
    device_id: job.deviceId,
    job_id: job.id,
    op_kind: job.kind,
    brand: target?.brand ?? 'unknown',
    model: target?.model ?? null,
    os_version: target?.osVersion ?? null,
    outcome,
    // The context that decides whether two rows are even comparable: a lost
    // contact under an armed dead-man and a lost contact on a degraded box are
    // not the same data point, and averaging them is how a fleet gets a
    // reassuring number it has not earned.
    safety_level: job.safetyLevel,
    guard_verdict: job.guardVerdict,
    was_override: job.overrideReason !== null,
    ops_count: extra.opsCount ?? 0,
    duration_ms: extra.durationMs ?? null,
    failure_kind: extra.failureKind ?? null,
  });
}

// ============================================================================
// Post-conditions
// ============================================================================

/**
 * "The PPP session holds."
 *
 * Asked of the CONCENTRATOR, not of the device: the device's own view of its
 * tunnel is worth little when the question is whether the tunnel came back. If
 * there is no concentrator on the row, or it cannot be read, this answers
 * `not_checked` — a string, deliberately, so that the caller writes "not
 * checked" into the step trace rather than a reassuring boolean.
 */
export async function checkPppSession(deviceId: number): Promise<string> {
  const target = await loadDeviceTarget(deviceId).catch(() => null);
  if (!target) return 'not_checked (device row unreadable)';
  if (!target.pppUsername) return 'not_checked (no ppp_username recorded)';
  const row = await db('ppp_sessions')
    .where({ device_id: deviceId })
    .orderBy('id', 'desc')
    .first<any>('state', 'updated_at')
    .catch(() => null);
  if (!row) return 'not_checked (no ppp_sessions row)';
  return `${row.state} (as of ${row.updated_at})`;
}

// ============================================================================
// The other three brands (A2) — the write path exists, the net does not
// ============================================================================

import { SSH_DIALECTS, DEFAULT_PROMPT_PATTERN } from './sshDialects';
// Re-exported so every existing caller keeps its import path.
export { SSH_DIALECTS, DEFAULT_PROMPT_PATTERN, type SshDialect } from './sshDialects';

export interface SshApplyOptions {
  host: string;
  port?: number;
  username: string;
  password?: string;
  privateKey?: string;
  /** Complete rendering. In memory only. */
  commands: string[];
  /** Masked rendering, one line per command, for the audit trail. */
  redacted: string[];
  secretValues: string[];
  /** Regex that identifies an error in the device's own echo. Brand-specific:
   *  none of these boxes sets a useful exit code on a config line. */
  errorPattern: RegExp;
  /** End-of-answer marker. Defaults to the historical `/[>#$]s*$/`, which is
   *  right for every dialect in `SSH_DIALECTS` but not for a device whose
   *  prompt ends in something else. Pass the dialect's, not a guess. */
  promptPattern?: RegExp;
  timeoutMs?: number;
  onLine?: (redactedLine: string) => void;
}

/** Per-family knobs for the CLI write path. Everything here is from vendor
 *  documentation; NONE of it has been executed against hardware (A2 — there is
 *  no lab). */
export const CLI_WRITE_PROFILES: Partial<
  Record<DeviceFamily, { errorPattern: RegExp; prologue: string[]; epilogue: string[] }>
> = {
  draytek_vigor: {
    errorPattern: /(%\s*Error|Invalid|Command failed|syntax error)/i,
    prologue: [],
    epilogue: ['sys commit'],
  },
  zyxel_standalone: {
    errorPattern: /(ERROR|Invalid|error:)/i,
    prologue: ['configure terminal'],
    epilogue: ['exit', 'write memory'],
  },
  sonicwall_sonicos: {
    errorPattern: /(%\s*Error|Invalid|failed)/i,
    prologue: ['configure'],
    epilogue: ['commit', 'exit'],
  },
};

/**
 * Push configuration over SSH, one line at a time, stopping at the first error.
 *
 * WHY LINE BY LINE AND NOT A BULK PASTE: it is the same argument that rejected
 * `/import` on MikroTik. A bulk paste that fails halfway leaves the box in a
 * state nobody described, and these three brands have no `:do{} on-error={}`
 * equivalent — so the only error handling available is OUR loop, and it only
 * works if it can see each line's answer.
 *
 * WHAT THIS DOES NOT DO, AND WILL NOT PRETEND TO: there is no dead-man. A cut
 * pushed here is not repaired by the box. `resolveSafetyNet()` returns
 * DEGRADED for these families, and DEGRADED demands a recorded human
 * confirmation before the job may even exist (migration 009 CHECK). That is the
 * honest arrangement: the write path is real, the net is not, and the level
 * says so.
 *
 * HONESTY NOTE, LOAD-BEARING — REVISED, because the old one is no longer true
 * and a stale disclaimer is worse than none.
 *
 * WHAT IS NOW PROVEN. `m6-sshapply.verify.ts` drives this function through a
 * real ssh2 server on a real socket with a real interactive channel
 * (`fakeSshRouter.ts`): a clean batch, a refusal stopping AT its line with the
 * rest never written, answers fragmented across two TCP writes, a device that
 * wedges mid-apply, a connection dropped mid-apply, and a secret that reaches
 * the equipment while never reaching the audit trail. Its first run found a
 * real defect — the banner prompt was counted as an answer, so `applied` ran
 * one ahead of the device and the last command was reported without being
 * sent. §8.3 sizes a rollback from that number, so over-reporting restored too
 * little. Fixed above; the harness holds the fix.
 *
 * WHAT IS STILL NOT PROVEN, and it is a different claim entirely: that a Vigor,
 * a Zyxel or a SonicWall behaves like that fake. The prompt strings, the error
 * patterns and the commit verbs still come from documentation. The harness
 * proves this FUNCTION is correct given a device that answers as described; it
 * cannot prove the description. Read §8.3 before the first real push.
 */
export async function applyOverSsh(
  options: SshApplyOptions,
): Promise<{ applied: number; failedAt: number | null; error: string | null }> {
  const { Client } = await import('ssh2');
  const timeout = options.timeoutMs ?? 120_000;
  return new Promise((resolve) => {
    const client = new Client();
    let applied = 0;
    let failedAt: number | null = null;
    let error: string | null = null;
    const finish = () => {
      client.end();
      resolve({ applied, failedAt, error });
    };
    const timer = setTimeout(() => {
      error = 'ssh apply timed out';
      finish();
    }, timeout);

    client
      .on('ready', () => {
        client.shell({ term: 'vt100' }, (err, stream) => {
          if (err) {
            clearTimeout(timer);
            error = err.message;
            return finish();
          }
          let buffer = '';
          let index = 0;
          // ┌─ THE BANNER IS NOT AN ANSWER ────────────────────────────────┐
          // │ Every CLI prints a greeting and a first prompt before it      │
          // │ accepts anything. Sending command 0 immediately and then      │
          // │ treating the FIRST prompt as its answer credits each command  │
          // │ with the previous one's prompt: `applied` runs one ahead of   │
          // │ reality, and the loop finishes believing it sent a line it    │
          // │ never wrote. Found by `m6-sshapply.verify.ts` on the first    │
          // │ run this function ever had — three lines queued, two reached  │
          // │ the device, three reported applied.                           │
          // │                                                              │
          // │ That number is not cosmetic: §8.3 decides how much to roll    │
          // │ back from it, so over-reporting restores TOO LITTLE and       │
          // │ leaves a router half-configured with a green job.             │
          // │                                                              │
          // │ So the first prompt is CONSUMED, and only then does the first │
          // │ command go out. A device that greets with silence hangs until │
          // │ the timeout — the honest failure, and one this loop already   │
          // │ reports with the partial count.                               │
          // └──────────────────────────────────────────────────────────────┘
          let primed = false;
          const sendNext = () => {
            if (index >= options.commands.length) {
              clearTimeout(timer);
              return finish();
            }
            stream.write(`${options.commands[index]}\n`);
          };
          stream.on('data', (chunk: Buffer) => {
            buffer += chunk.toString('utf8');
            if (!(options.promptPattern ?? DEFAULT_PROMPT_PATTERN).test(buffer)) return;
            if (!primed) {
              primed = true;
              buffer = '';
              return sendNext();
            }
            if (options.errorPattern.test(buffer)) {
              clearTimeout(timer);
              failedAt = index;
              error = `line ${index + 1} was refused by the device`;
              options.onLine?.(`${options.redacted[index] ?? '<line>'} -> REFUSED`);
              return finish();
            }
            applied = index + 1;
            options.onLine?.(`${options.redacted[index] ?? '<line>'} -> ok`);
            buffer = '';
            index++;
            sendNext();
          });
          stream.on('close', () => {
            clearTimeout(timer);
            finish();
          });
          // NOT sendNext(): the first command goes out when the banner prompt
          // has been consumed. See the box above.
        });
      })
      .on('error', (err: Error) => {
        clearTimeout(timer);
        error = err.message;
        finish();
      })
      .connect({
        host: options.host,
        port: options.port ?? 22,
        username: options.username,
        password: options.password,
        privateKey: options.privateKey,
        readyTimeout: 30_000,
      });
  });
}

// ============================================================================
// The seam `apply.service.ts` (K1's queue half, another workstream) looks for
// ============================================================================

/**
 * `apply.service.ts` resolves `./safeApply.service` dynamically and expects an
 * object with five methods, because IT drives the state machine and calls us
 * step by step. `runSafeApply()` above drives the state machine itself. Both
 * decompositions are defensible; what is not defensible is shipping two halves
 * of a milestone that cannot be joined, so this adapter exists.
 *
 * ONE THING THE SEAM CANNOT CARRY, AND IT IS THE IMPORTANT ONE.
 * `ExecContext.ops` is documented there as "the frozen plan's ops, REDACTED
 * (§8.2)". Redacted ops are exactly what must NEVER be sent to a router: they
 * contain `password=***` where a PSK belongs. So `applyChange()` below REFUSES
 * unless a renderer has been registered that can turn a job id into the
 * complete in-memory rendering. That is not obstruction — it is the §8.2
 * boundary showing up where it always was: something has to go from the vault
 * to the equipment, and a redacted op cannot.
 *
 * Until `registerChangeRenderer()` is called from the composition root, the
 * queue will accept jobs, arm nothing, and refuse the write with a message that
 * names the missing piece. That is the correct failure: a milestone that
 * refuses is a meeting, a milestone that pushes `***` into a router's firewall
 * is a van.
 */
export type ChangeRenderer = (job: {
  id: number;
  deviceId: number;
  planId: number | null;
}) => Promise<RenderedChange>;

let changeRenderer: ChangeRenderer | null = null;

export function registerChangeRenderer(renderer: ChangeRenderer | null): void {
  changeRenderer = renderer;
}
export function isChangeRendererRegistered(): boolean {
  return changeRenderer !== null;
}

/** The subset of the queue's `ExecContext` this adapter actually reads. Duck
 *  typed on purpose: the shape belongs to the other file and must be free to
 *  grow without dragging a compile error into this one. */
interface ExecContextLike {
  job: { id: number; device_id?: number; deviceId?: number; tenant_id?: number };
  correlationId?: string;
  preflightBackupId?: number | null;
  deadmanHandle?: string | null;
  planId?: number | null;
  safetyLevel?: SafetyLevel;
}

function ctxDeviceId(ctx: ExecContextLike): number {
  const id = ctx.job.device_id ?? ctx.job.deviceId;
  if (typeof id !== 'number') {
    throw new ChangeError('DEVICE_UNKNOWN', 'the exec context carries no device id');
  }
  return id;
}

/** The object `apply.service.ts` picks up through its dynamic import. */
export const changeExecutor = {
  async takePreflightBackup(ctx: ExecContextLike): Promise<{ backupId: number }> {
    const deviceId = ctxDeviceId(ctx);
    const names = deadmanNames(ctx.job.id);
    const receiver = new TransferReceiver();
    await receiver.start();
    try {
      const set = await takeDeviceBackup({
        deviceId,
        trigger: 'preflight',
        kinds: ['binary', 'rsc'],
        jobId: ctx.job.id,
        correlationId: ctx.correlationId ?? null,
        receiver,
        // The binary blob stays for the dead-man to load; disarm removes it.
        keepOnDeviceKinds: ['binary'],
        fileBaseName: { binary: names.backupFileBase },
      });
      if (!set.binary) {
        throw new ChangeError('BACKUP_FAILED', 'no binary preflight backup was produced');
      }
      return { backupId: set.binary.id };
    } finally {
      await receiver.stop();
    }
  },

  async armDeadman(ctx: ExecContextLike): Promise<{
    handle: string;
    level: SafetyLevel;
    confirmDeadline: Date;
    peerDeviceId?: number | null;
  }> {
    const deviceId = ctxDeviceId(ctx);
    const names = deadmanNames(ctx.job.id);
    const backupId = ctx.preflightBackupId ?? null;
    if (!backupId) {
      throw new ChangeError('BACKUP_FAILED', 'cannot arm a dead-man with no preflight backup');
    }
    const stored = await getBackup(backupId);
    const password = stored ? backupPassword(stored) : null;
    if (!password) {
      throw new ChangeError(
        'BACKUP_FAILED',
        'the preflight backup has no recoverable password; the dead-man could not load it',
      );
    }
    const seconds = SAFE_APPLY_DEFAULTS.deadmanSeconds;
    const open = (purpose: string) =>
      openDeviceSession(deviceId, {
        purpose,
        jobId: ctx.job.id,
        correlationId: ctx.correlationId ?? null,
        secretValues: [password],
      });

    const arming = await open('arm');
    try {
      await armDeadman(arming, {
        jobId: ctx.job.id,
        backupFileName: names.backupFileName,
        backupPassword: password,
        intervalSeconds: seconds,
      });
    } finally {
      arming.close();
    }
    // The verification is on a SECOND socket. See the long note in the header.
    const check = await open('arm-verify');
    let verdict;
    try {
      verdict = judgeArming(await readDeadmanState(check, names), {
        schedulerName: names.schedulerName,
        scriptName: names.scriptName,
        intervalSeconds: seconds,
      });
    } finally {
      check.close();
    }
    if (!verdict.armed) {
      throw new ChangeError(
        'BACKUP_FAILED',
        `the dead-man is NOT armed: ${verdict.problems.join('; ')}. Refusing to apply.`,
      );
    }
    // The level ACTUALLY obtained, which the seam explicitly asks for: we just
    // installed and verified an on-box net, so it is `armed` and nothing else.
    return {
      handle: names.handle,
      level: 'armed',
      confirmDeadline: new Date(Date.now() + seconds * 1000),
      peerDeviceId: null,
    };
  },

  async applyChange(
    ctx: ExecContextLike,
  ): Promise<{ appliedOps: number; outputRedacted?: string | null }> {
    if (!changeRenderer) {
      throw new ChangeError(
        'SECRET_LEAK_REFUSED',
        'no change renderer is registered. The queue hands the executor REDACTED ops (§8.2), ' +
          'and a redacted op carries `***` where a secret belongs — pushing it would write ' +
          'literal asterisks into a customer firewall. Register the vault -> equipment renderer ' +
          'with registerChangeRenderer() from the composition root.',
      );
    }
    const deviceId = ctxDeviceId(ctx);
    const rendering = await changeRenderer({
      id: ctx.job.id,
      deviceId,
      planId: ctx.planId ?? null,
    });
    assertRenderingIsSafe(rendering);
    const names = deadmanNames(ctx.job.id);
    const marker = applyMarkerGlobal(ctx.job.id);
    const scriptName = `obliwan-apply-${ctx.job.id}`;
    const session = await openDeviceSession(deviceId, {
      purpose: 'apply',
      jobId: ctx.job.id,
      correlationId: ctx.correlationId ?? null,
      secretValues: rendering.secretValues,
    });
    try {
      const source = buildApplyScriptSource({
        jobId: ctx.job.id,
        commands: rendering.commands,
        rollbackScriptName: names.scriptName,
        markerGlobal: marker,
      });
      await session
        .run(['/system/script/remove', `=numbers=${scriptName}`], { isWrite: true })
        .catch(() => undefined);
      await session.run(
        ['/system/script/add', `=name=${scriptName}`, '=policy=read,write,policy,test', `=source=${source}`],
        { isWrite: true },
      );
      await session.run(['/system/script/run', `=number=${scriptName}`], {
        isWrite: true,
        timeoutMs: 120_000,
      });
      const env = await session
        .run(['/system/script/environment/print', `?name=${marker}`], {
          isWrite: false,
          skipAudit: true,
        })
        .catch(() => [] as Record<string, string>[]);
      const value = env.find((r) => r.name === marker)?.value ?? null;
      if (value === 'failed') {
        throw new ChangeError(
          'BACKUP_FAILED',
          'the on-error branch ran on the router: the change failed and the rollback was triggered',
        );
      }
      return {
        appliedOps: rendering.commands.length,
        outputRedacted: `${rendering.commands.length} command(s) applied through /system/script wrapped in :do{} on-error={${names.scriptName}}; marker=${value ?? 'unreadable'}`,
      };
    } finally {
      session.close();
    }
  },

  async verify(
    ctx: ExecContextLike,
  ): Promise<{ ok: boolean; detail?: Record<string, unknown>; errorRedacted?: string | null }> {
    const deviceId = ctxDeviceId(ctx);
    await sleep(SAFE_APPLY_DEFAULTS.reconnectDelayMs);
    let lastError = '';
    for (let i = 1; i <= SAFE_APPLY_DEFAULTS.reconnectAttempts; i++) {
      try {
        // A BRAND-NEW socket. The one that carried the change may well survive
        // a rule that refuses new connections.
        const session = await openDeviceSession(deviceId, {
          purpose: 'verify',
          jobId: ctx.job.id,
          correlationId: ctx.correlationId ?? null,
        });
        try {
          const ppp = await checkPppSession(deviceId);
          return { ok: true, detail: { attempt: i, pppSession: ppp } };
        } finally {
          session.close();
        }
      } catch (err) {
        lastError = err instanceof Error ? err.message : String(err);
        if (i < SAFE_APPLY_DEFAULTS.reconnectAttempts) {
          await sleep(SAFE_APPLY_DEFAULTS.reconnectIntervalMs);
        }
      }
    }
    return { ok: false, errorRedacted: redactForAudit([lastError], []) };
  },

  async disarmDeadman(ctx: ExecContextLike): Promise<void> {
    const deviceId = ctxDeviceId(ctx);
    const names = ctx.deadmanHandle
      ? deadmanNamesFromHandle(ctx.deadmanHandle)
      : deadmanNames(ctx.job.id);
    const outcome = await disarmWithRetry({
      openSession: () =>
        openDeviceSession(deviceId, {
          purpose: 'disarm',
          jobId: ctx.job.id,
          correlationId: ctx.correlationId ?? null,
        }),
      names,
      attempts: SAFE_APPLY_DEFAULTS.disarmAttempts,
      backoffMs: SAFE_APPLY_DEFAULTS.disarmBackoffMs,
    });
    if (!outcome.disarmed) {
      // Loud, and it throws: the caller must not record `succeeded` on a box
      // that is going to revert the change by itself.
      throw new ChangeError(
        'ONDEVICE_CLEANUP_FAILED',
        `the dead-man could not be disarmed after ${outcome.attempts} attempts ` +
          `(${outcome.lastError ?? 'unknown'}). The equipment WILL restore itself.`,
      );
    }
  },

  async observeRollback(ctx: ExecContextLike): Promise<boolean> {
    const deviceId = ctxDeviceId(ctx);
    if (!ctx.deadmanHandle) return false;
    const receiver = new TransferReceiver();
    await receiver.start();
    let session: DeviceSession | null = null;
    try {
      session = await openDeviceSession(deviceId, {
        purpose: 'observe-rollback',
        jobId: ctx.job.id,
        correlationId: ctx.correlationId ?? null,
      });
      const rsc = await db('device_backups')
        .where({ taken_before_job_id: ctx.job.id, kind: 'rsc' })
        .first<any>('id');
      const armedAtRow = await db('change_jobs').where({ id: ctx.job.id }).first<any>('deadman_armed_at');
      const evidence = await inspectDeadman({
        session,
        handle: ctx.deadmanHandle,
        armedAt: armedAtRow?.deadman_armed_at ? new Date(armedAtRow.deadman_armed_at) : null,
        receiver,
        rscBackupId: rsc?.id ?? null,
      });
      return evidence.verdict === 'fired_restored';
    } catch {
      // We could not look. That is not a rollback — `lost_contact` and
      // `rolled_back` are different nights and must not be averaged.
      return false;
    } finally {
      session?.close();
      await receiver.stop();
    }
  },
};

// ============================================================================
// Small helpers
// ============================================================================

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, Math.max(0, ms)));
}
