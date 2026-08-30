// ============================================================================
// ObliWAN — brand profiles: the vendor knowledge, as data (M11 — K4)
// ============================================================================
//
// ┌─ THIS FILE IS THE POINT OF THE MILESTONE ─────────────────────────────────┐
// │ Everything a senior engineer knows about "can a Vigor do that, and what   │
// │ is the port called" lives here, in one table per family, reviewable in a  │
// │ diff. Nothing else in the server is allowed to know that MikroTik calls   │
// │ its first uplink `ether1` and SonicWall calls it `X1`.                    │
// │                                                                           │
// │ Every profile SPREADS `NO_INTENT_SUPPORT`. A feature is supported only    │
// │ because a line here says `true` and a renderer exists for it. A feature   │
// │ somebody forgot is `false`, which refuses the compilation — the safe      │
// │ direction. This is the same discipline `NO_CAPABILITIES` imposes on the   │
// │ driver layer, and it is imposed here for the same reason.                 │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ HONESTY ABOUT WHERE THESE ANSWERS COME FROM (§8.3) ──────────────────────┐
// │ There is NO lab. No Vigor, no Zyxel, no SonicWall, and no MikroTik has    │
// │ been asked any of this. Every `true` below is a claim made from vendor    │
// │ documentation and experience, and every `false` is either a genuine       │
// │ product limit or "no renderer written for it yet" — the two are           │
// │ distinguished by the `note`, which travels all the way into the refusal   │
// │ message the operator reads.                                               │
// │                                                                           │
// │ A wrong `true` here is the dangerous direction: it produces an artefact   │
// │ the box will reject at apply time. A wrong `false` merely refuses a       │
// │ compilation, loudly, with the feature name in the message. That asymmetry │
// │ is why the default is `false` and why the doubtful entries are `false`.   │
// └───────────────────────────────────────────────────────────────────────────┘

import type { DeviceBrand, DeviceFamily, InterfaceType } from '@obliwan/shared';
import { DEVICE_FAMILIES, FAMILY_BRAND } from '@obliwan/shared';
import type { ArtifactFormat, IntentSupport, LanSegment } from '@obliwan/shared/dist/intent';
import { NO_INTENT_SUPPORT } from '@obliwan/shared/dist/intent';

/** Everything the namer needs that is not the record it is naming. */
export interface NamingContext {
  /** How many uplinks the intent declares. LAN ports are numbered after them
   *  on every brand whose ports share one namespace. */
  wanCount: number;
}

export interface BrandNaming {
  /** Physical uplink `n` (1-based). */
  wan(uplinkIndex: number, ctx: NamingContext): string;
  /** The tagged sub-interface when the operator hands off a VLAN on the WAN. */
  wanVlan(uplinkIndex: number, vlanId: number, ctx: NamingContext): string;
  /** The L2 domain the LAN segments hang off (bridge / native LAN interface). */
  lanTrunk(ctx: NamingContext): string;
  /** The L3 interface that carries one segment. */
  segment(segment: LanSegment, index: number, ctx: NamingContext): string;
  /** Physical access port `n` (1-based, counted among the LAN ports). */
  accessPort(portIndex: number, ctx: NamingContext): string;
  /** Security zone of the uplinks — `null` on a family with no zone model. */
  wanZone(): string | null;
  /** Security zone of one segment — `null` on a family with no zone model. */
  segmentZone(segment: LanSegment, index: number): string | null;
}

export interface BrandProfile {
  family: DeviceFamily;
  brand: DeviceBrand;
  /** `null` when no renderer exists for this family. Its support matrix is
   *  then `NO_INTENT_SUPPORT`, so `capabilityCheck` refuses first and the
   *  missing renderer is never reached by an honest caller. */
  artifactFormat: ArtifactFormat | null;
  support: IntentSupport;
  /** Per-feature explanation, surfaced verbatim in the refusal message. Only
   *  the entries where "why not" is not obvious carry one. */
  featureNotes: Partial<Record<keyof IntentSupport, string>>;
  /** Shown in the brand-coverage panel (risk R2). */
  notes: string[];
  naming: BrandNaming;
  /**
   * What the LAN trunk IS on this family. A MikroTik bridge is a configuration
   * object that has to be created; a Vigor `LAN1`, a Zyxel `ge2` and a
   * SonicWall `X0` are physical ports that already exist. The NCM interface
   * record and every renderer read this one field rather than each deciding
   * for itself what a trunk is.
   */
  trunkType: InterfaceType;
}

// ============================================================================
// MikroTik — RouterOS 6 and 7
// ============================================================================

const routerosNaming: BrandNaming = {
  wan: (i) => `ether${i}`,
  wanVlan: (i, vlanId) => `vlan${vlanId}-wan${i}`,
  lanTrunk: () => 'bridge-lan',
  segment: (segment, _index, ctx) =>
    segment.vlanId === null ? routerosNaming.lanTrunk(ctx) : `vlan${segment.vlanId}-${segment.id}`,
  accessPort: (portIndex, ctx) => `ether${ctx.wanCount + portIndex}`,
  // RouterOS has no zone object. `ncm/primitives.ts` is explicit that brands
  // without a zone model emit `null`, and inventing a zone name here would
  // make a MikroTik rule hash differently from the identical rule elsewhere.
  wanZone: () => null,
  segmentZone: () => null,
};

function routerosSupport(): IntentSupport {
  return {
    ...NO_INTENT_SUPPORT,
    'wan.dhcp': true,
    'wan.static': true,
    'wan.pppoe': true,
    'wan.vlanTag': true,
    'wan.multiUplink': true,

    'lan.multiSegment': true,
    'lan.vlanSegmentation': true,
    'lan.dhcpServer': true,
    'lan.dhcpReservation': true,
    'lan.segmentIsolation': true,

    'policy.statefulFirewall': true,
    // NOT a zone firewall: `/ip firewall filter` matches on interfaces and
    // interface lists. Modelling those as zones would be a lie the drift engine
    // would then have to live with.
    'policy.zoneModel': false,
    'policy.portForward': true,
    'policy.interSegmentControl': true,
    'policy.icmpControl': true,

    'vpn.ipsecSiteToSite': true,
    'vpn.ikev2': true,

    'mgmt.serviceRestriction': true,
    'mgmt.localUsers': true,
    'mgmt.snmpV3': true,

    'qos.shaping': true,
    'qos.perSegmentPriority': true,

    // The dead-man of K1 IS a RouterOS scheduler script, so the family can do
    // it. Whether THIS driver may promise it is a `DeviceCapabilities`
    // question, answered by `canScheduleOnDevice`, and `capabilityCheck` reads
    // both. Two sources, both defaulting to "no".
    'safety.onDeviceDeadMan': true,
    // RouterOS applies each line as it is parsed; there is no staging area.
    'safety.atomicCommit': false,
    'safety.noRebootApply': true,
    'safety.structuredDiff': true,
  };
}

const routerosNotes = (family: DeviceFamily): string[] => [
  family === 'mikrotik_routeros6'
    ? 'RouterOS 6 dialect: /interface/wireless, /system/health as a single record (R11).'
    : 'RouterOS 7 dialect: /interface/wifi, /system/health as rows (R11).',
  'No staging area: a script applies line by line. Safety comes from the on-box dead-man (K1), not from an atomic commit.',
  'No zone object — the firewall matches interfaces and interface lists.',
];

// ============================================================================
// DrayTek Vigor
// ============================================================================

const draytekNaming: BrandNaming = {
  wan: (i) => `WAN${i}`,
  wanVlan: (i, vlanId) => `WAN${i}.${vlanId}`,
  lanTrunk: () => 'LAN1',
  // A Vigor carries up to eight LAN SUBNETS, LAN1..LAN8, each optionally bound
  // to a VLAN tag. The segment index therefore IS the LAN number.
  segment: (_segment, index) => `LAN${index + 1}`,
  accessPort: (portIndex) => `P${portIndex}`,
  wanZone: () => null,
  segmentZone: () => null,
};

const draytekSupport: IntentSupport = {
  ...NO_INTENT_SUPPORT,
  'wan.dhcp': true,
  'wan.static': true,
  'wan.pppoe': true,
  'wan.vlanTag': true,
  'wan.multiUplink': true,

  'lan.multiSegment': true,
  'lan.vlanSegmentation': true,
  'lan.dhcpServer': true,
  'lan.dhcpReservation': true,
  'lan.segmentIsolation': true,

  'policy.statefulFirewall': true,
  'policy.zoneModel': false,
  'policy.portForward': true,
  'policy.interSegmentControl': true,
  'policy.icmpControl': true,

  'vpn.ipsecSiteToSite': true,
  'vpn.ikev2': true,

  'mgmt.serviceRestriction': true,
  'mgmt.localUsers': true,
  // Left false on purpose. SNMP v3 exists on the recent Vigor firmware and is
  // absent on much of the installed base; with no lab to settle it, the
  // conservative answer refuses a compilation instead of shipping a config the
  // box silently ignores — which is how a fleet ends up "monitored" by nothing.
  'mgmt.snmpV3': false,

  'qos.shaping': true,
  'qos.perSegmentPriority': true,

  'safety.onDeviceDeadMan': false,
  'safety.atomicCommit': false,
  // The supported restore path is a whole `.cfg`, and it reboots. This is the
  // same fact `DeviceCapabilities.requiresRebootToApply` states, and
  // `capabilityCheck` reads both — a disagreement between the two is a bug that
  // must surface, not be averaged.
  'safety.noRebootApply': false,
  // `configFormat: 'binary_opaque'` — the drift engine gets a fingerprint.
  'safety.structuredDiff': false,
};

const draytekFeatureNotes: BrandProfile['featureNotes'] = {
  'policy.zoneModel':
    'a Vigor filters by direction (LAN/WAN/VPN) and by call filter / data filter sets, not by named zones',
  'mgmt.snmpV3':
    'v3 is firmware- and model-dependent across the Vigor range and is not claimed without a unit to verify it against (§8.3)',
  'safety.noRebootApply': 'the supported restore path is a full .cfg, which reboots the router',
  'safety.structuredDiff': 'the configuration is an opaque binary .cfg; drift is a fingerprint, not a line diff',
};

// ============================================================================
// Zyxel — standalone (USG FLEX / ATP / VPN, ZLD CLI)
// ============================================================================

const zyxelNaming: BrandNaming = {
  wan: (i) => `ge${i}`,
  wanVlan: (_i, vlanId) => `vlan${vlanId}`,
  lanTrunk: (ctx) => `ge${ctx.wanCount + 1}`,
  segment: (segment, _index, ctx) =>
    segment.vlanId === null ? zyxelNaming.lanTrunk(ctx) : `vlan${segment.vlanId}`,
  accessPort: (portIndex, ctx) => `ge${ctx.wanCount + portIndex}`,
  wanZone: () => 'WAN',
  // ZLD zones are user-defined objects; one per segment keeps the policy
  // readable and keeps the NCM `zone` field meaningful across brands.
  segmentZone: (segment) => segment.id.replace(/-/g, '_').toUpperCase().slice(0, 31),
};

const zyxelStandaloneSupport: IntentSupport = {
  ...NO_INTENT_SUPPORT,
  'wan.dhcp': true,
  'wan.static': true,
  'wan.pppoe': true,
  'wan.vlanTag': true,
  'wan.multiUplink': true,

  'lan.multiSegment': true,
  'lan.vlanSegmentation': true,
  'lan.dhcpServer': true,
  'lan.dhcpReservation': true,
  'lan.segmentIsolation': true,

  'policy.statefulFirewall': true,
  'policy.zoneModel': true,
  'policy.portForward': true,
  'policy.interSegmentControl': true,
  'policy.icmpControl': true,

  'vpn.ipsecSiteToSite': true,
  'vpn.ikev2': true,

  'mgmt.serviceRestriction': true,
  'mgmt.localUsers': true,
  'mgmt.snmpV3': true,

  'qos.shaping': true,
  'qos.perSegmentPriority': true,

  'safety.onDeviceDeadMan': false,
  // ZLD writes take effect as they are entered; `write` persists them.
  'safety.atomicCommit': false,
  'safety.noRebootApply': true,
  'safety.structuredDiff': true,
};

// ============================================================================
// SonicWall — SonicOS 6.5 / 7.x
// ============================================================================

const sonicwallNaming: BrandNaming = {
  // X0 is the LAN by default and X1 the WAN; the uplinks therefore start at X1
  // and the LAN trunk is X0.
  wan: (i) => `X${i}`,
  wanVlan: (i, vlanId) => `X${i}:V${vlanId}`,
  lanTrunk: () => 'X0',
  segment: (segment) => (segment.vlanId === null ? 'X0' : `X0:V${segment.vlanId}`),
  accessPort: (portIndex, ctx) => (portIndex === 1 ? 'X0' : `X${ctx.wanCount + portIndex - 1}`),
  wanZone: () => 'WAN',
  segmentZone: (segment, index) => (index === 0 ? 'LAN' : segment.id.replace(/-/g, '_').toUpperCase().slice(0, 31)),
};

const sonicwallSupport: IntentSupport = {
  ...NO_INTENT_SUPPORT,
  'wan.dhcp': true,
  'wan.static': true,
  'wan.pppoe': true,
  'wan.vlanTag': true,
  'wan.multiUplink': true,

  'lan.multiSegment': true,
  'lan.vlanSegmentation': true,
  'lan.dhcpServer': true,
  'lan.dhcpReservation': true,
  'lan.segmentIsolation': true,

  'policy.statefulFirewall': true,
  'policy.zoneModel': true,
  'policy.portForward': true,
  'policy.interSegmentControl': true,
  'policy.icmpControl': true,

  'vpn.ipsecSiteToSite': true,
  'vpn.ikev2': true,

  'mgmt.serviceRestriction': true,
  'mgmt.localUsers': true,
  'mgmt.snmpV3': true,

  'qos.shaping': true,
  'qos.perSegmentPriority': true,

  'safety.onDeviceDeadMan': false,
  // THE reason a SonicWall is the safest brand to push to: everything stages in
  // a pending configuration and is committed all-or-nothing. A rejected commit
  // leaves the appliance byte-identical to what it was.
  'safety.atomicCommit': true,
  'safety.noRebootApply': true,
  'safety.structuredDiff': true,
};

// ============================================================================
// Zyxel families with no renderer
// ============================================================================

/** A profile whose support matrix is entirely `NO_INTENT_SUPPORT`: every
 *  compilation against it is refused by `capabilityCheck` before anything is
 *  rendered, and the refusal names the missing feature and the brand. */
function unrenderedProfile(family: DeviceFamily, note: string): BrandProfile {
  return {
    family,
    brand: FAMILY_BRAND[family],
    artifactFormat: null,
    support: { ...NO_INTENT_SUPPORT },
    featureNotes: {},
    notes: [note],
    naming: {
      wan: (i) => `wan${i}`,
      wanVlan: (i, vlanId) => `wan${i}.${vlanId}`,
      lanTrunk: () => 'lan',
      segment: (_s, index) => `lan${index + 1}`,
      accessPort: (portIndex) => `port${portIndex}`,
      wanZone: () => null,
      segmentZone: () => null,
    },
    trunkType: 'ethernet',
  };
}

// ============================================================================
// The table
// ============================================================================

/**
 * Exhaustive over `DeviceFamily`: adding a family to the shared union without
 * deciding what it can express is a compile error, not a runtime surprise on
 * the day somebody provisions one.
 */
const PROFILES: Readonly<Record<DeviceFamily, BrandProfile>> = {
  mikrotik_routeros6: {
    family: 'mikrotik_routeros6',
    brand: 'mikrotik',
    artifactFormat: 'routeros_script',
    support: routerosSupport(),
    featureNotes: {
      'policy.zoneModel': 'RouterOS filters on interfaces and interface lists; it has no zone object',
      'safety.atomicCommit': 'a RouterOS script applies line by line; there is no staging area to commit',
    },
    notes: routerosNotes('mikrotik_routeros6'),
    naming: routerosNaming,
    trunkType: 'bridge',
  },
  mikrotik_routeros7: {
    family: 'mikrotik_routeros7',
    brand: 'mikrotik',
    artifactFormat: 'routeros_script',
    support: routerosSupport(),
    featureNotes: {
      'policy.zoneModel': 'RouterOS filters on interfaces and interface lists; it has no zone object',
      'safety.atomicCommit': 'a RouterOS script applies line by line; there is no staging area to commit',
    },
    notes: routerosNotes('mikrotik_routeros7'),
    naming: routerosNaming,
    trunkType: 'bridge',
  },
  draytek_vigor: {
    family: 'draytek_vigor',
    brand: 'draytek',
    artifactFormat: 'draytek_cli',
    support: draytekSupport,
    featureNotes: draytekFeatureNotes,
    notes: [
      'Up to eight LAN subnets (LAN1..LAN8), each optionally bound to a VLAN tag.',
      'The configuration is an opaque .cfg: drift is a fingerprint, and a restore reboots the router.',
      'No named zones — filtering is by direction and by filter set.',
    ],
    naming: draytekNaming,
    trunkType: 'ethernet',
  },
  zyxel_standalone: {
    family: 'zyxel_standalone',
    brand: 'zyxel',
    artifactFormat: 'zyxel_zld_cli',
    support: zyxelStandaloneSupport,
    featureNotes: {
      'safety.atomicCommit': 'ZLD applies each command as it is entered; "write" persists, it does not commit',
    },
    notes: [
      'ZLD CLI with named zones and address objects; every policy references objects, never literals.',
      'Interfaces are ge1..geN; VLAN interfaces are vlan<id> bound to a base port.',
    ],
    naming: zyxelNaming,
    trunkType: 'ethernet',
  },
  sonicwall_sonicos: {
    family: 'sonicwall_sonicos',
    brand: 'sonicwall',
    artifactFormat: 'sonicos_rest',
    support: sonicwallSupport,
    featureNotes: {},
    notes: [
      'X0 is the LAN and X1 the first WAN; VLAN sub-interfaces are X0:V<id>.',
      'Every write stages in a pending configuration and is committed all-or-nothing (or discarded).',
      'Administrative sessions are scarce: one session, held for the shortest possible time, logged out in a finally.',
    ],
    naming: sonicwallNaming,
    trunkType: 'ethernet',
  },
  zyxel_nebula: unrenderedProfile(
    'zyxel_nebula',
    'Nebula devices are configured through the cloud organisation API, not on the box. No intent renderer is written for it, so every feature is false and a compilation is refused rather than half-produced.',
  ),
  zyxel_cpe: unrenderedProfile(
    'zyxel_cpe',
    'xDSL / GPON CPE reachable only over TR-069. The parameter-tree renderer belongs to the ACS workstream; until it exists every feature is false and a compilation is refused.',
  ),
};

/** The profile of a family. Throws rather than degrading: unlike `getDriver`,
 *  which must keep a fleet scan alive, a compilation with no profile has no
 *  honest partial answer. */
export function brandProfile(family: DeviceFamily): BrandProfile {
  return PROFILES[family];
}

/** Every profile, for the brand-coverage panel and for the golden-file run. */
export function allBrandProfiles(): BrandProfile[] {
  return DEVICE_FAMILIES.map((f) => PROFILES[f]);
}

/** The families a compilation can actually target today. */
export function renderableFamilies(): DeviceFamily[] {
  return DEVICE_FAMILIES.filter((f) => PROFILES[f].artifactFormat !== null);
}
