// ============================================================================
// ObliWAN — blast radius: what a plan touches, and how far it reaches
// ============================================================================
//
// PURE. Same discipline as `riskScoring` and `mgmtPathGuard`: everything this
// module needs is handed to it. It reads no table and opens no socket, which is
// what lets the rollout screen render the same numbers the job queue will act
// on, computed by the same code, without a second query.
//
// ┌─ WHO CONSUMES THIS ──────────────────────────────────────────────────────┐
// │ • the impact screen shown BEFORE a launch (§8.3: "the level is computed   │
// │   per device and displayed on the impact screen BEFORE the launch, never  │
// │   after");                                                               │
// │ • the canary waves of K3 / M7, which need the site count to size a wave   │
// │   and the safety-net level to order it;                                  │
// │ • `change_plans.blast_radius`, whose shape is `BlastRadius` in the shared │
// │   contract and is produced here for one device.                          │
// └──────────────────────────────────────────────────────────────────────────┘
//
// THE NUMBER THAT MATTERS IS `siteCount`, NOT `deviceCount`.
// The fleet is multi-customer. Twelve devices on one site is an outage for one
// customer; twelve devices on twelve sites is twelve customers, twelve phone
// calls and potentially twelve vans. Every aggregate below therefore counts
// sites first and devices second, and a device with no site is counted as its
// own unknown rather than folded into zero — an unattached device is an
// inventory gap, and hiding it behind a tidy total is how it stays one.

import type {
  ApplyPlan, BlastRadius, DeviceBrand, DeviceFamily, NcmResource, PlanOp,
  PlanOpKind, RiskLevel,
} from '@obliwan/shared';
import { RISK_RANK } from '@obliwan/shared';
import type { RiskAssessment } from './riskScoring';
import type { MgmtGuardVerdict } from './mgmtPathGuard';

// ============================================================================
// §8.3 — the three levels of safety net
// ============================================================================

/**
 * How well this device can save ITSELF if the change goes wrong.
 *
 *  ARMED          the dead-man runs ON THE EQUIPMENT (`/system/scheduler
 *                 start-time=startup` plus a restore script). The router
 *                 repairs itself even if the ObliWAN server is dead. That
 *                 independence is the whole property — a net that depends on
 *                 the thing that might have crashed is not a net.
 *  ARMED_BY_PEER  the dead-man is carried by a MikroTik CO-LOCATED on the same
 *                 site, reached over the tunnel the change does not touch. One
 *                 brand repairs another. Weaker than ARMED: it assumes the peer
 *                 stays up and that the change really does not touch its path.
 *  DEGRADED       detection without recovery. We will know the CPE stopped
 *                 reporting; we can do nothing about it remotely. §8.3 requires
 *                 an EXPLICIT confirmation before any apply at this level.
 *
 * The ordering is deliberate and is consumed by `orderForWaves`: DEGRADED goes
 * last in a canary rollout, because by the time it runs we have already learnt
 * whatever the armed devices had to teach us.
 */
export const SAFETY_NET_LEVELS = ['ARMED', 'ARMED_BY_PEER', 'DEGRADED'] as const;
export type SafetyNetLevel = (typeof SAFETY_NET_LEVELS)[number];

export const SAFETY_NET_RANK: Readonly<Record<SafetyNetLevel, number>> = {
  ARMED: 0, ARMED_BY_PEER: 1, DEGRADED: 2,
};

/**
 * The §8.3 table, as a function.
 *
 * FALLBACK, NOT AUTHORITY. The device that actually arms the dead-man is what
 * decides whether it is armed, and that is `safeApply` / K1 at apply time —
 * this classification is what the IMPACT SCREEN shows before anything has been
 * armed, from inventory alone. A caller that already holds the real, probed
 * level must pass it in `BlastDeviceInput.safetyNet` and this function is not
 * consulted.
 *
 * It is honest in one specific way that matters (decision A2): for DrayTek,
 * Zyxel and SonicWall it returns DEGRADED unless a co-located MikroTik is
 * present. No laboratory hardware exists for those three brands, the write
 * path for them is written but never rehearsed on real metal, and claiming a
 * dead-man where none exists is exactly the lie §8.3 was written to forbid.
 */
export function classifySafetyNet(input: {
  brand: DeviceBrand | string;
  /** Another MikroTik on the SAME site, reachable over a tunnel this plan does
   *  not touch. The caller establishes both halves of that sentence. */
  hasColocatedMikrotik?: boolean;
}): SafetyNetLevel {
  if (input.brand === 'mikrotik') return 'ARMED';
  return input.hasColocatedMikrotik ? 'ARMED_BY_PEER' : 'DEGRADED';
}

/** §8.3: "a wave rollout that mixes ARMED and DEGRADED devices treats the
 *  DEGRADED ones last". Stable within a level so a rollout is reproducible. */
export function orderForWaves<T extends { safetyNet: SafetyNetLevel; deviceId: number }>(
  devices: readonly T[],
): T[] {
  return [...devices].sort(
    (a, b) => SAFETY_NET_RANK[a.safetyNet] - SAFETY_NET_RANK[b.safetyNet] || a.deviceId - b.deviceId,
  );
}

// ============================================================================
// Input
// ============================================================================

export interface BlastDeviceInput {
  deviceId: number;
  deviceName: string;
  /** NULL is a real value: a device attached to no site. Counted separately. */
  siteId: number | null;
  siteName?: string | null;
  brand: DeviceBrand | string;
  family?: DeviceFamily | null;
  ops: readonly PlanOp[];
  /** `change_plans.risk_level`, when the plan envelope is at hand. */
  riskLevel?: RiskLevel;
  /** Per-op assessments from `scoreOp`, indexed by `seq`. Without them the
   *  management-path flag falls back to the ops' own `disruptive` bit. */
  signals?: Record<number, RiskAssessment>;
  /** K2's verdict for this device, when it has been run. */
  guardVerdict?: MgmtGuardVerdict | null;
  /** The real, probed safety-net level. Overrides `classifySafetyNet`. */
  safetyNet?: SafetyNetLevel | null;
  /** Used only by `classifySafetyNet` when `safetyNet` is absent. */
  hasColocatedMikrotik?: boolean;
}

/** Convenience shape for a caller that already holds a compiled plan. */
export function fromPlan(
  plan: Pick<ApplyPlan, 'deviceId' | 'ops' | 'riskLevel'>,
  device: Omit<BlastDeviceInput, 'deviceId' | 'ops' | 'riskLevel'>,
): BlastDeviceInput {
  return { ...device, deviceId: plan.deviceId, ops: plan.ops, riskLevel: plan.riskLevel };
}

// ============================================================================
// One device
// ============================================================================

/**
 * Caps on the two string lists. `BlastRadius` is rendered on a screen a human
 * reads before pressing a button, and four hundred interface names is not
 * information, it is a wall. The COUNTS stay exact; only the enumerations are
 * cut, and `truncated` says so rather than letting the list end silently.
 */
export const MAX_LISTED_INTERFACES = 200;
export const MAX_LISTED_SUBNETS = 200;

export interface DeviceBlastRadius {
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  siteName: string | null;
  brand: string;
  family: DeviceFamily | null;
  safetyNet: SafetyNetLevel;
  guardVerdict: MgmtGuardVerdict | null;
  riskLevel: RiskLevel;
  /** Ops that will actually be sent to the box (`blocked` and `verify` are not
   *  changes and never inflate this). */
  changeOpCount: number;
  blockedOpCount: number;
  /** Ops that may drop the session they are applied through — what the K1
   *  arming decision reads. */
  disruptiveOpCount: number;
  byOpKind: Record<PlanOpKind, number>;
  affectedInterfaces: string[];
  affectedSubnets: string[];
  touchesManagementPath: boolean;
  /** True when §8.3 requires an explicit human confirmation for this device:
   *  a DEGRADED net, or a guard verdict that is not ACCEPT. */
  requiresExplicitConfirmation: boolean;
}

function emptyKindCounts(): Record<PlanOpKind, number> {
  return {
    create: 0, update: 0, delete: 0, move: 0,
    enable: 0, disable: 0, verify: 0, blocked: 0,
  };
}

function asResource(v: unknown): NcmResource | null {
  if (!v || typeof v !== 'object') return null;
  const r = v as { kind?: unknown };
  return typeof r.kind === 'string' ? (v as NcmResource) : null;
}

/**
 * Interfaces and subnets one op can alter the forwarding of.
 *
 * BOTH SIDES of the op are read. An update that moves a rule off `ether3` and
 * onto `ether4` touches both, and a screen that showed only the destination
 * would understate the change on exactly the interface somebody is about to
 * lose.
 */
function collectTouched(
  op: PlanOp,
  interfaces: Set<string>,
  subnets: Set<string>,
): void {
  for (const side of [op.before, op.after]) {
    const r = asResource(side);
    if (!r) continue;
    switch (r.kind) {
      case 'interface':
        interfaces.add(r.name);
        for (const a of r.addresses) subnets.add(a.cidr);
        if (r.parent) interfaces.add(r.parent);
        break;
      case 'vlan':
        if (r.name) interfaces.add(r.name);
        if (r.parent) interfaces.add(r.parent);
        for (const p of r.taggedPorts) interfaces.add(p);
        for (const p of r.untaggedPorts) interfaces.add(p);
        break;
      case 'route':
        subnets.add(r.dst);
        if (r.gateway?.startsWith('iface:')) interfaces.add(r.gateway.slice('iface:'.length));
        break;
      case 'dhcpScope':
        subnets.add(r.subnet);
        if (r.onInterface.startsWith('iface:')) interfaces.add(r.onInterface.slice('iface:'.length));
        break;
      case 'firewallRule':
      case 'natRule':
        for (const atom of [...r.match.inInterface, ...r.match.outInterface]) {
          if (atom.startsWith('iface:')) interfaces.add(atom.slice('iface:'.length));
        }
        for (const atom of [...r.match.srcAddress, ...r.match.dstAddress]) {
          if (atom.startsWith('cidr:')) subnets.add(atom.slice('cidr:'.length));
        }
        break;
      case 'qosRule':
        for (const atom of r.target) {
          if (atom.startsWith('iface:')) interfaces.add(atom.slice('iface:'.length));
          if (atom.startsWith('cidr:')) subnets.add(atom.slice('cidr:'.length));
        }
        break;
      case 'ipsecPeer':
        for (const s of [...r.localSubnets, ...r.remoteSubnets]) subnets.add(s);
        break;
      default:
        break;
    }
  }
}

export function blastRadiusForDevice(input: BlastDeviceInput): DeviceBlastRadius {
  const interfaces = new Set<string>();
  const subnets = new Set<string>();
  const byOpKind = emptyKindCounts();
  let touchesManagementPath = false;
  let disruptiveOpCount = 0;
  let changeOpCount = 0;
  let worstRisk: RiskLevel = 'low';

  for (const op of input.ops) {
    byOpKind[op.kind] += 1;
    if (op.kind === 'blocked') continue;
    if (op.kind !== 'verify') {
      changeOpCount += 1;
      if (RISK_RANK[op.risk] > RISK_RANK[worstRisk]) worstRisk = op.risk;
    }
    const signal = input.signals?.[op.seq];
    if (signal?.tunnelCritical) touchesManagementPath = true;
    if (signal ? signal.disruptive : op.disruptive) disruptiveOpCount += 1;
    collectTouched(op, interfaces, subnets);
  }

  const safetyNet = input.safetyNet ?? classifySafetyNet({
    brand: input.brand,
    hasColocatedMikrotik: input.hasColocatedMikrotik,
  });
  const guardVerdict = input.guardVerdict ?? null;

  return {
    deviceId: input.deviceId,
    deviceName: input.deviceName,
    siteId: input.siteId,
    siteName: input.siteName ?? null,
    brand: input.brand,
    family: input.family ?? null,
    safetyNet,
    guardVerdict,
    riskLevel: input.riskLevel ?? worstRisk,
    changeOpCount,
    blockedOpCount: byOpKind.blocked,
    disruptiveOpCount,
    byOpKind,
    affectedInterfaces: [...interfaces].filter((s) => s.length > 0 && s.length <= 64).sort()
      .slice(0, MAX_LISTED_INTERFACES),
    affectedSubnets: [...subnets].filter((s) => s.length > 0 && s.length <= 49).sort()
      .slice(0, MAX_LISTED_SUBNETS),
    touchesManagementPath,
    // §8.3. Two independent triggers, and either one is enough. A DEGRADED
    // device has no way back; a non-ACCEPT guard means nobody has proved there
    // is one.
    requiresExplicitConfirmation:
      safetyNet === 'DEGRADED' || (guardVerdict !== null && guardVerdict !== 'ACCEPT'),
  };
}

/** The shared `BlastRadius` value stored on `change_plans.blast_radius`, for a
 *  single-device plan. Same numbers as `blastRadiusForDevice`, projected onto
 *  the contract's shape so the two can never disagree. */
export function toPlanBlastRadius(d: DeviceBlastRadius): BlastRadius {
  return {
    deviceCount: 1,
    siteCount: d.siteId === null ? 0 : 1,
    affectedInterfaces: d.affectedInterfaces,
    affectedSubnets: d.affectedSubnets,
    touchesManagementPath: d.touchesManagementPath,
  };
}

// ============================================================================
// N devices
// ============================================================================

export interface SiteBlastRadius {
  siteId: number | null;
  siteName: string | null;
  deviceCount: number;
  deviceIds: number[];
  worstRisk: RiskLevel;
  /** The WEAKEST net on the site — the level the site as a whole is protected
   *  at. One DEGRADED device makes the site's recovery story DEGRADED, and
   *  averaging that away is how the confirmation gets skipped. */
  weakestSafetyNet: SafetyNetLevel;
  touchesManagementPath: boolean;
  requiresExplicitConfirmation: boolean;
}

export interface FleetBlastRadius {
  deviceCount: number;
  /** Distinct sites with at least one device in the plan set. Devices with no
   *  site are NOT counted here — see `unassignedDeviceCount`. */
  siteCount: number;
  unassignedDeviceCount: number;
  sites: SiteBlastRadius[];
  devices: DeviceBlastRadius[];

  totalOpCount: number;
  changeOpCount: number;
  blockedOpCount: number;
  disruptiveOpCount: number;
  byOpKind: Record<PlanOpKind, number>;
  byRisk: Record<RiskLevel, number>;
  bySafetyNet: Record<SafetyNetLevel, number>;
  byGuardVerdict: Record<MgmtGuardVerdict | 'NOT_RUN', number>;

  affectedInterfaces: string[];
  affectedSubnets: string[];
  interfacesTruncated: boolean;
  subnetsTruncated: boolean;

  touchesManagementPath: boolean;
  /** Devices whose management path this plan can alter. The list, not just the
   *  flag: on a 300-device rollout "some of them" is not actionable. */
  managementPathDeviceIds: number[];
  /** Devices K2 has not cleared (REJECT, INDETERMINATE, or never run). */
  guardNotClearedDeviceIds: number[];
  worstRisk: RiskLevel;
  requiresExplicitConfirmation: boolean;
  /** The wave order of §8.3: armed first, degraded last. */
  waveOrder: number[];
}

export function aggregateBlastRadius(inputs: readonly BlastDeviceInput[]): FleetBlastRadius {
  const devices = inputs.map(blastRadiusForDevice);

  const byOpKind = emptyKindCounts();
  const byRisk: Record<RiskLevel, number> = { low: 0, medium: 0, high: 0 };
  const bySafetyNet: Record<SafetyNetLevel, number> = { ARMED: 0, ARMED_BY_PEER: 0, DEGRADED: 0 };
  const byGuardVerdict: Record<MgmtGuardVerdict | 'NOT_RUN', number> = {
    ACCEPT: 0, REJECT: 0, INDETERMINATE: 0, NOT_RUN: 0,
  };

  const interfaces = new Set<string>();
  const subnets = new Set<string>();
  const sites = new Map<string, SiteBlastRadius>();
  const managementPathDeviceIds: number[] = [];
  const guardNotClearedDeviceIds: number[] = [];

  let totalOpCount = 0;
  let changeOpCount = 0;
  let blockedOpCount = 0;
  let disruptiveOpCount = 0;
  let unassignedDeviceCount = 0;
  let worstRisk: RiskLevel = 'low';
  let requiresExplicitConfirmation = false;

  for (const d of devices) {
    for (const kind of Object.keys(byOpKind) as PlanOpKind[]) byOpKind[kind] += d.byOpKind[kind];
    totalOpCount += Object.values(d.byOpKind).reduce((a, b) => a + b, 0);
    changeOpCount += d.changeOpCount;
    blockedOpCount += d.blockedOpCount;
    disruptiveOpCount += d.disruptiveOpCount;
    byRisk[d.riskLevel] += 1;
    bySafetyNet[d.safetyNet] += 1;
    byGuardVerdict[d.guardVerdict ?? 'NOT_RUN'] += 1;
    if (RISK_RANK[d.riskLevel] > RISK_RANK[worstRisk]) worstRisk = d.riskLevel;
    if (d.requiresExplicitConfirmation) requiresExplicitConfirmation = true;
    if (d.touchesManagementPath) managementPathDeviceIds.push(d.deviceId);
    if (d.guardVerdict !== 'ACCEPT') guardNotClearedDeviceIds.push(d.deviceId);
    if (d.siteId === null) unassignedDeviceCount += 1;

    for (const i of d.affectedInterfaces) interfaces.add(i);
    for (const s of d.affectedSubnets) subnets.add(s);

    // Sites are keyed by id; an unattached device gets its OWN bucket rather
    // than joining a phantom "site null", because two devices with no site are
    // two unknowns, not one site.
    const key = d.siteId === null ? `unassigned:${d.deviceId}` : `site:${d.siteId}`;
    const existing = sites.get(key);
    if (existing) {
      existing.deviceCount += 1;
      existing.deviceIds.push(d.deviceId);
      if (RISK_RANK[d.riskLevel] > RISK_RANK[existing.worstRisk]) existing.worstRisk = d.riskLevel;
      if (SAFETY_NET_RANK[d.safetyNet] > SAFETY_NET_RANK[existing.weakestSafetyNet]) {
        existing.weakestSafetyNet = d.safetyNet;
      }
      existing.touchesManagementPath ||= d.touchesManagementPath;
      existing.requiresExplicitConfirmation ||= d.requiresExplicitConfirmation;
    } else {
      sites.set(key, {
        siteId: d.siteId,
        siteName: d.siteName,
        deviceCount: 1,
        deviceIds: [d.deviceId],
        worstRisk: d.riskLevel,
        weakestSafetyNet: d.safetyNet,
        touchesManagementPath: d.touchesManagementPath,
        requiresExplicitConfirmation: d.requiresExplicitConfirmation,
      });
    }
  }

  const allInterfaces = [...interfaces].sort();
  const allSubnets = [...subnets].sort();

  return {
    deviceCount: devices.length,
    siteCount: new Set(devices.map((d) => d.siteId).filter((s): s is number => s !== null)).size,
    unassignedDeviceCount,
    sites: [...sites.values()].sort(
      (a, b) => (b.deviceCount - a.deviceCount) || ((a.siteId ?? -1) - (b.siteId ?? -1)),
    ),
    devices,

    totalOpCount,
    changeOpCount,
    blockedOpCount,
    disruptiveOpCount,
    byOpKind,
    byRisk,
    bySafetyNet,
    byGuardVerdict,

    affectedInterfaces: allInterfaces.slice(0, MAX_LISTED_INTERFACES),
    affectedSubnets: allSubnets.slice(0, MAX_LISTED_SUBNETS),
    interfacesTruncated: allInterfaces.length > MAX_LISTED_INTERFACES,
    subnetsTruncated: allSubnets.length > MAX_LISTED_SUBNETS,

    touchesManagementPath: managementPathDeviceIds.length > 0,
    managementPathDeviceIds: managementPathDeviceIds.sort((a, b) => a - b),
    guardNotClearedDeviceIds: guardNotClearedDeviceIds.sort((a, b) => a - b),
    worstRisk,
    requiresExplicitConfirmation,
    waveOrder: orderForWaves(devices).map((d) => d.deviceId),
  };
}

/**
 * One sentence for the top of the impact screen.
 *
 * It leads with sites, not devices, and it never rounds a customer away: "3
 * sites" and "3 customers offline" are the same sentence to whoever answers the
 * phone.
 */
export function describeBlastRadius(r: FleetBlastRadius): string {
  const bits: string[] = [];
  bits.push(`${r.deviceCount} device${r.deviceCount === 1 ? '' : 's'}`);
  bits.push(`${r.siteCount} site${r.siteCount === 1 ? '' : 's'}`);
  if (r.unassignedDeviceCount > 0) bits.push(`${r.unassignedDeviceCount} with no site recorded`);
  bits.push(`${r.changeOpCount} change${r.changeOpCount === 1 ? '' : 's'}`);
  const head = bits.join(', ');

  const warn: string[] = [];
  if (r.managementPathDeviceIds.length > 0) {
    warn.push(`${r.managementPathDeviceIds.length} touch the management path`);
  }
  if (r.bySafetyNet.DEGRADED > 0) {
    warn.push(`${r.bySafetyNet.DEGRADED} have NO remote recovery (safety net DEGRADED)`);
  }
  if (r.byGuardVerdict.REJECT > 0) {
    warn.push(`${r.byGuardVerdict.REJECT} refused by the Management-Path Guard`);
  }
  if (r.byGuardVerdict.INDETERMINATE + r.byGuardVerdict.NOT_RUN > 0) {
    warn.push(`${r.byGuardVerdict.INDETERMINATE + r.byGuardVerdict.NOT_RUN} not cleared by the Management-Path Guard`);
  }
  return warn.length === 0 ? `${head}.` : `${head}. ${warn.join('; ')}.`;
}

export const blastRadiusService = {
  blastRadiusForDevice,
  aggregateBlastRadius,
  toPlanBlastRadius,
  classifySafetyNet,
  orderForWaves,
  describeBlastRadius,
  fromPlan,
};
