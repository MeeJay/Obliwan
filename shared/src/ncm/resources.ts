// ============================================================================
// @obliwan/shared — NCM resources
// ============================================================================
//
// The ten modelled resource kinds. Implements §2.2 and §2.3 of
// `docs/M4-NCM-contrat.md`, verbatim where the study wrote the schema.
//
// ADMISSION CRITERION (§7.4) — a resource belongs here only if all three hold:
//   1. Manageable  — we can write it back on at least one brand, and express a
//                    PlanOp for it.
//   2. Keyable     — it admits a stable identity (natural name, or predicate +
//                    ordinal).
//   3. Useful      — a killer feature consumes it (K2, K4, K5 or K8).
// A failure on any of the three means `unmodeled[]` or `extensions`: visible,
// counted, NOT diffed. A half-modelled resource is worse than no resource — the
// diff announces `missing` on fields we never read, and the planner proposes to
// recreate what already exists.

import { z } from 'zod';
import { TRANSPORT_KINDS } from '../device';
import {
  SelectorAtom, Selector, PortSet, Protocol, Zone, SecretFingerprint,
} from './primitives';

export const NCM_RESOURCE_KINDS = [
  'interface', 'vlan', 'route', 'firewallRule', 'natRule',
  'dhcpScope', 'ipsecPeer', 'localUser', 'service', 'qosRule',
  // v2 — see HASHED_COLLECTIONS.since in canonical.ts before adding another.
  'dhcpClient',
] as const;
export type NcmResourceKind = (typeof NCM_RESOURCE_KINDS)[number];

/**
 * Resource kinds whose ARRAY ORDER carries meaning. For these, the canonical
 * serializer preserves the collected order; for all others it sorts by semKey.
 * This single set is what makes `ncm_hash` both stable AND order-sensitive
 * exactly where a firewall needs it to be.
 */
export const ORDERED_RESOURCE_KINDS: ReadonlySet<NcmResourceKind> =
  new Set<NcmResourceKind>(['firewallRule', 'natRule', 'qosRule']);

/** The plural document key each resource kind lives under, and its inverse.
 *  Kept here so nothing downstream re-derives it by string surgery. */
export const RESOURCE_KIND_TO_COLLECTION: Readonly<Record<NcmResourceKind, string>> = {
  interface: 'interfaces',
  dhcpClient: 'dhcpClients',
  vlan: 'vlans',
  route: 'routes',
  firewallRule: 'firewallRules',
  natRule: 'natRules',
  dhcpScope: 'dhcpScopes',
  ipsecPeer: 'ipsecPeers',
  localUser: 'localUsers',
  service: 'services',
  qosRule: 'qosRules',
};

/**
 * How much we trust the identity of this record.
 *  'strong'  — the device itself carries a stable name/id we did not invent
 *              (interface name, username, service name, `obliwan:` marker).
 *  'derived' — computed from content (matchHash) — stable while the content is.
 *  'weak'    — no usable identity; we fell back to an instance index (TR-069
 *              `{i}` with no Name parameter). Findings on weak keys are capped
 *              at severity 'info' unless the payload changed materially.
 */
export const KEY_QUALITIES = ['strong', 'derived', 'weak'] as const;
export type KeyQuality = (typeof KEY_QUALITIES)[number];

/**
 * Who owns this record.
 *  'obliwan' — comment matches /^obliwan:([a-z0-9._-]{1,48})/ ; the slug is the
 *              anchor used by phase 1 of the pairing algorithm and by the
 *              `is_managed` column of the flattened tables.
 *  'foreign' — a marker of another management system (a known prefix list).
 *  'unknown' — hand-written, or written before ObliWAN existed.
 */
export const MANAGED_BY = ['obliwan', 'foreign', 'unknown'] as const;
export type ManagedBy = (typeof MANAGED_BY)[number];

/** Shape spread into every resource. Kept as a plain object literal rather than
 *  a base schema so `.strict()` composes without surprises. */
const ncmBase = {
  semKey: z.string().min(5).max(180),
  keyQuality: z.enum(KEY_QUALITIES),
  managedBy: z.enum(MANAGED_BY),
  /** The slug after `obliwan:` when managedBy === 'obliwan', else null. */
  managedSlug: z.string().max(48).nullable(),
  /** Free comment, WITHOUT the obliwan: marker (which is parsed out).
   *  Excluded from matchHash, included in payload -> editing a comment is a
   *  `changed` of severity 'info', never a missing+extra pair. */
  comment: z.string().max(512).nullable(),
  disabled: z.boolean(),
  /** Which transport produced this record (audit + partial-state UI). */
  via: z.enum(TRANSPORT_KINDS),
};

// ── interface ───────────────────────────────────────────────────────────────
export const INTERFACE_TYPES = [
  'ethernet', 'sfp', 'wifi', 'bridge', 'vlan', 'bond', 'lte', 'pppoe',
  'l2tp', 'ipsec', 'wireguard', 'gre', 'loopback', 'other',
] as const;
export type InterfaceType = (typeof INTERFACE_TYPES)[number];

export const NcmAddress = z.object({
  /** Canonical CIDR, host bits PRESERVED for an interface address: `10.0.0.1/24`
   *  means "this box is .1 in that /24", and zeroing it destroys the config. */
  cidr: z.string().min(4).max(49),
  /** DHCP/PPP-learned addresses are STATE, not config: the parser drops them.
   *  This flag exists only for the brands that cannot tell us, so the diff can
   *  downgrade the finding instead of claiming a static address vanished. */
  originUnknown: z.boolean(),
}).strict();
export type NcmAddress = z.infer<typeof NcmAddress>;

export const NcmInterface = z.object({
  ...ncmBase,
  kind: z.literal('interface'),
  name: z.string().min(1).max(64),
  type: z.enum(INTERFACE_TYPES),
  alias: z.string().max(256).nullable(),
  /** Parent interface NAME for vlan / bridge port / bond member. Never a semKey
   *  of another document — the NCM must stay a self-contained value. */
  parent: z.string().max(64).nullable(),
  mtu: z.number().int().min(64).max(65535).nullable(),
  /** Static L3 addressing only. */
  addresses: z.array(NcmAddress),
  /** Interface-list / zone membership — the selector vocabulary of the firewall
   *  depends on it, so it is config, not state. */
  lists: z.array(z.string().max(64)),
  zone: Zone,
}).strict();
export type NcmInterface = z.infer<typeof NcmInterface>;

// ── vlan ────────────────────────────────────────────────────────────────────
export const NcmVlan = z.object({
  ...ncmBase,
  kind: z.literal('vlan'),
  vlanId: z.number().int().min(1).max(4094),
  name: z.string().max(64).nullable(),
  /** Bridge / switch the VLAN lives on; null on brands with a global VLAN table. */
  parent: z.string().max(64).nullable(),
  taggedPorts: z.array(z.string().max(64)),
  untaggedPorts: z.array(z.string().max(64)),
}).strict();
export type NcmVlan = z.infer<typeof NcmVlan>;

// ── route ───────────────────────────────────────────────────────────────────
// STATIC routes only. Connected / DHCP / OSPF / BGP routes are state and live
// in the telemetry model — putting them here makes ncm_hash change every time a
// WAN reconnects (§7.1).
export const NcmRoute = z.object({
  ...ncmBase,
  kind: z.literal('route'),
  dst: z.string().min(4).max(49),        // canonical CIDR, host bits zeroed
  gateway: SelectorAtom.nullable(),      // 'ip:…' | 'iface:…' | null (blackhole)
  distance: z.number().int().min(1).max(255).nullable(),
  scope: z.number().int().min(0).max(255).nullable(),
  targetScope: z.number().int().min(0).max(255).nullable(),
  table: z.string().max(32),             // 'main' by default, never null
  /** Recursive next-hop / check-gateway behaviour, normalized to a small enum. */
  checkGateway: z.enum(['none', 'ping', 'arp', 'bfd']).nullable(),
  vrf: z.string().max(32).nullable(),
}).strict();
export type NcmRoute = z.infer<typeof NcmRoute>;

// ── firewall & nat ──────────────────────────────────────────────────────────
export const NCM_CHAINS = [
  'input', 'output', 'forward', 'prerouting', 'postrouting', 'custom',
] as const;
export type NcmChain = (typeof NCM_CHAINS)[number];

export const FIREWALL_ACTIONS = [
  'accept', 'drop', 'reject', 'log', 'passthrough', 'jump', 'return',
  'tarpit', 'fasttrack', 'addToList', 'other',
] as const;
export type FirewallAction = (typeof FIREWALL_ACTIONS)[number];

/**
 * TERMINAL actions decide the fate of a packet. §4.2 step 2: an ordering swap
 * only matters when at least one of the two crossed rules is terminal AND their
 * effects differ — two `log`/`passthrough` rules crossing each other change no
 * forwarding at all, and emitting a finding for that is pure noise (R3).
 */
export const TERMINAL_ACTIONS: ReadonlySet<FirewallAction> = new Set<FirewallAction>([
  'accept', 'drop', 'reject', 'jump', 'return', 'fasttrack',
]);

/** The MATCH side. Everything here — and nothing else — feeds `matchHash`. */
export const NcmMatch = z.object({
  protocol: Protocol,
  srcAddress: Selector,
  dstAddress: Selector,
  srcPort: PortSet,
  dstPort: PortSet,
  inInterface: Selector,
  outInterface: Selector,
  srcZone: Zone,
  dstZone: Zone,
  /** Sorted set: 'established' | 'related' | 'new' | 'invalid' | 'untracked'. */
  connectionState: z.array(z.string().max(16)),
  connectionNat: z.array(z.string().max(16)),
  /** Sorted TCP flag tokens, e.g. ['!ack','syn']. */
  tcpFlags: z.array(z.string().max(12)),
  icmpType: z.string().max(16).nullable(),
  ipsecPolicy: z.string().max(24).nullable(),
  /** Anything the parser matched but does not model. NON-EMPTY makes the rule
   *  `matchIncomplete` and forbids K2 from proving anything about it (§6.4). */
  unmodeledMatch: z.array(z.string().max(120)),
}).strict();
export type NcmMatch = z.infer<typeof NcmMatch>;

/** The "matches everything" match, and the base every parser starts from: every
 *  selector it does not see stays `any`, which is rule 1 of §3.3 made
 *  structural rather than a convention a parser can forget. */
export const EMPTY_MATCH: NcmMatch = {
  protocol: null,
  srcAddress: ['any'],
  dstAddress: ['any'],
  srcPort: null,
  dstPort: null,
  inInterface: ['any'],
  outInterface: ['any'],
  srcZone: null,
  dstZone: null,
  connectionState: [],
  connectionNat: [],
  tcpFlags: [],
  icmpType: null,
  ipsecPolicy: null,
  unmodeledMatch: [],
};

export const NcmFirewallRule = z.object({
  ...ncmBase,
  kind: z.literal('firewallRule'),
  chain: z.enum(NCM_CHAINS),
  /** Set when chain === 'custom'; part of the identity. */
  chainName: z.string().max(64).nullable(),
  match: NcmMatch,
  // ── payload: compared, never hashed into the identity ──
  action: z.enum(FIREWALL_ACTIONS),
  jumpTarget: z.string().max(64).nullable(),
  rejectWith: z.string().max(32).nullable(),
  log: z.boolean(),
  logPrefix: z.string().max(64).nullable(),
  addToList: z.string().max(64).nullable(),
  addToListTimeout: z.number().int().nullable(),
  /** Discriminator when two rules of the same chain share a matchHash (§3.4). */
  ordinal: z.number().int().min(0),
  matchHash: z.string().length(16),
}).strict();
export type NcmFirewallRule = z.infer<typeof NcmFirewallRule>;

export const NAT_ACTIONS = [
  'masquerade', 'srcnat', 'dstnat', 'netmap', 'redirect', 'accept', 'other',
] as const;
export type NatAction = (typeof NAT_ACTIONS)[number];

export const NcmNatRule = z.object({
  ...ncmBase,
  kind: z.literal('natRule'),
  chain: z.enum(['prerouting', 'postrouting', 'custom']),
  chainName: z.string().max(64).nullable(),
  match: NcmMatch,
  action: z.enum(NAT_ACTIONS),
  toAddresses: Selector.nullable(),
  toPorts: PortSet,
  ordinal: z.number().int().min(0),
  matchHash: z.string().length(16),
}).strict();
export type NcmNatRule = z.infer<typeof NcmNatRule>;

// ── dhcp ────────────────────────────────────────────────────────────────────
export const NcmDhcpReservation = z.object({
  semKey: z.string().min(5).max(180),
  mac: z.string().regex(/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/),
  address: z.string().min(7).max(45),
  hostname: z.string().max(128).nullable(),
  comment: z.string().max(256).nullable(),
}).strict();
export type NcmDhcpReservation = z.infer<typeof NcmDhcpReservation>;

export const NcmDhcpScope = z.object({
  ...ncmBase,
  kind: z.literal('dhcpScope'),
  name: z.string().min(1).max(64),
  /** Interface the server listens on — 'iface:bridge-lan'. */
  onInterface: SelectorAtom,
  subnet: z.string().min(4).max(49),
  poolFrom: z.string().max(45).nullable(),
  poolTo: z.string().max(45).nullable(),
  gateway: z.string().max(45).nullable(),
  dnsServers: z.array(z.string().max(45)),
  ntpServers: z.array(z.string().max(45)),
  domain: z.string().max(128).nullable(),
  leaseSeconds: z.number().int().min(60).nullable(),
  /** STATIC reservations only. Dynamic leases are state. */
  reservations: z.array(NcmDhcpReservation),
  /** Vendor options we can round-trip; anything else lands in unmodeled[]. */
  options: z.array(z.object({ code: z.number().int(), value: z.string().max(256) }).strict()),
}).strict();
export type NcmDhcpScope = z.infer<typeof NcmDhcpScope>;

// ── ipsec ───────────────────────────────────────────────────────────────────
export const NcmIpsecProposal = z.object({
  encryption: z.array(z.string().max(24)),
  integrity: z.array(z.string().max(24)),
  dhGroup: z.array(z.string().max(24)),
  lifetimeSeconds: z.number().int().nullable(),
  pfsGroup: z.string().max(24).nullable(),
}).strict();
export type NcmIpsecProposal = z.infer<typeof NcmIpsecProposal>;

export const NcmIpsecPeer = z.object({
  ...ncmBase,
  kind: z.literal('ipsecPeer'),
  name: z.string().max(64).nullable(),
  remote: z.string().max(255),                    // IP or FQDN, lowercased
  localId: z.string().max(255).nullable(),
  remoteId: z.string().max(255).nullable(),
  exchangeMode: z.enum(['ike1-main', 'ike1-aggressive', 'ike2', 'unknown']),
  authMethod: z.enum(['psk', 'rsa', 'eap', 'unknown']),
  /** Never the PSK itself. */
  pskFingerprint: SecretFingerprint,
  proposal: NcmIpsecProposal,
  localSubnets: z.array(z.string().max(49)),
  remoteSubnets: z.array(z.string().max(49)),
  dpdSeconds: z.number().int().nullable(),
  natTraversal: z.boolean().nullable(),
}).strict();
export type NcmIpsecPeer = z.infer<typeof NcmIpsecPeer>;

// ── local users ─────────────────────────────────────────────────────────────
export const NcmLocalUser = z.object({
  ...ncmBase,
  kind: z.literal('localUser'),
  username: z.string().min(1).max(64),            // lowercased for the key only
  group: z.string().max(64).nullable(),           // 'full' | 'read' | 'write' | brand role
  /** Sorted, canonicalised permission tokens where the brand exposes them. */
  permissions: z.array(z.string().max(32)),
  allowedFrom: Selector,
  passwordFingerprint: SecretFingerprint,
  /** true when the parser matched it against the vendor default-credentials
   *  table — the single most valuable K5 query on day one. */
  isVendorDefault: z.boolean(),
  sshKeyFingerprints: z.array(z.string().max(64)),
  twoFactor: z.boolean().nullable(),
}).strict();
export type NcmLocalUser = z.infer<typeof NcmLocalUser>;

// ── dhcp client (v2) ────────────────────────────────────────────────────────
/**
 * A DHCP CLIENT declared on an interface — configuration, not the lease.
 *
 * ┌─ THE DISTINCTION THIS RESOURCE EXISTS TO MAKE ────────────────────────────┐
 * │ `NcmAddress` above drops DHCP- and PPP-learned addresses, and it is right │
 * │ to: the address is STATE, it changes on its own, and treating it as       │
 * │ config would report drift every time a lease renewed.                     │
 * │                                                                          │
 * │ But the CLIENT is not state. `/ip/dhcp-client` on RouterOS is an object   │
 * │ an operator creates and deletes, and dropping it with the address it      │
 * │ learns made a piece of real configuration invisible to the model — so     │
 * │ invisible that removing it was not drift.                                 │
 * │                                                                          │
 * │ That mattered concretely: on a MikroTik + bridged Zyxel site, the DHCP    │
 * │ client on the WAN port is the ONLY reason the MikroTik can reach the      │
 * │ modem's management address, which is the only reason it could ever act as │
 * │ the peer that carries a dead-man for it (§8.3). Delete the client and the │
 * │ safety net disappears in silence, while the product keeps offering it.    │
 * │                                                                          │
 * │ So: the client is modelled, the address it learns is still not.           │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export const NcmDhcpClient = z.object({
  ...ncmBase,
  kind: z.literal('dhcpClient'),
  /** Interface the client runs on. The semKey is built from it. */
  interfaceName: z.string().min(1).max(64),
  /** Does the lease install a default route on this box? */
  addDefaultRoute: z.boolean().nullable(),
  /** Does the lease overwrite the resolver list? */
  usePeerDns: z.boolean().nullable(),
  /** Does the lease set the clock source? */
  usePeerNtp: z.boolean().nullable(),
  /** Brand-declared route distance when `addDefaultRoute`. Null when unmodelled. */
  defaultRouteDistance: z.number().int().min(0).max(255).nullable(),
  /**
   * The `script=` body RouterOS runs on every lease bind. CONFIGURATION, and
   * the most load-bearing field of this resource.
   *
   * ┌─ WHY IT IS MODELLED AND NOT DISCARDED ────────────────────────────────┐
   * │ It was discarded, until a real export off a production CHR showed what │
   * │ actually lives in there:                                              │
   * │                                                                       │
   * │   :if ($bound=1) do={                                                 │
   * │     /ip/route/set [find where comment="NW-WAN1"]  gateway=$"gateway…" │
   * │     /ip/route/set [find where comment="WAN1-GW"]  gateway=$"gateway…" │
   * │   }                                                                   │
   * │                                                                       │
   * │ That is a WAN failover wired into the DHCP client: two static routes   │
   * │ re-pointed at whatever gateway the lease hands out. Editing it changes │
   * │ where the site's default route goes. Dropping it made a change to the  │
   * │ routing of a site invisible to drift — the exact class of blindness    │
   * │ this model exists to remove.                                          │
   * │                                                                       │
   * │ Kept VERBATIM apart from line-ending canonicalisation: reformatting a  │
   * │ script would either invent findings or hide them, and the platform has │
   * │ no business deciding that two spellings of a script are the same.      │
   * └───────────────────────────────────────────────────────────────────────┘
   */
  bindScript: z.string().max(8000).nullable(),
}).strict();
export type NcmDhcpClient = z.infer<typeof NcmDhcpClient>;

// ── management services ─────────────────────────────────────────────────────
export const NCM_SERVICE_NAMES = [
  'ssh', 'telnet', 'ftp', 'http', 'https', 'api', 'api-ssl', 'winbox',
  'snmp', 'cwmp', 'dns', 'ntp', 'upnp', 'romon', 'bandwidth-test', 'other',
] as const;
export type NcmServiceName = (typeof NCM_SERVICE_NAMES)[number];

export const NcmService = z.object({
  ...ncmBase,
  kind: z.literal('service'),
  service: z.enum(NCM_SERVICE_NAMES),
  /** Present when service === 'other'. */
  rawName: z.string().max(64).nullable(),
  enabled: z.boolean(),
  port: z.number().int().min(1).max(65535).nullable(),
  /** Address restriction — 'any' here is what K5 hunts for. */
  allowedFrom: Selector,
  tlsRequired: z.boolean().nullable(),
  certificate: z.string().max(128).nullable(),
  /** SNMP only: 'v1' | 'v2c' | 'v3'. */
  version: z.string().max(8).nullable(),
  communityFingerprint: SecretFingerprint.nullable(),
  /** SNMP only, and deliberately NOT a fingerprint: knowing that a community is
   *  literally "public" or "private" is the whole point of the audit query
   *  (§7.2, the one assumed exception to "no secret material in the NCM"). */
  communityIsWellKnown: z.boolean().nullable(),
}).strict();
export type NcmService = z.infer<typeof NcmService>;

// ── qos ─────────────────────────────────────────────────────────────────────
// Open arbitration Q4: the model is defined now, and every family except
// `mikrotik_routeros*` is expected to declare `coverage.qosRule = 'unsupported'`
// until M11. `coverage` is what makes shipping the shape early safe (N3).
/**
 * ADDITIVE DIVERGENCE FROM THE STUDY, minimal and required.
 *
 * §3.1 gives the qos key as `qos.v1:simple:ether1-limit` — the queue CLASS is
 * part of the key. No field in the study's `NcmQosRule` carries it, so
 * `buildSemKey()` could not re-derive that key from the document, and a key
 * that cannot be re-derived from the document is not a key: the client could
 * not line a finding up with a resource, and the indexer could not check the
 * parser. One enum field is a much smaller change than dropping the class from
 * the key would be.
 */
export const QOS_CLASSES = ['simple', 'tree', 'shaper', 'other'] as const;
export type QosClass = (typeof QOS_CLASSES)[number];

export const NcmQosRule = z.object({
  ...ncmBase,
  kind: z.literal('qosRule'),
  /** RouterOS simple queue vs queue tree, and the brand equivalents. */
  queueClass: z.enum(QOS_CLASSES),
  name: z.string().max(64).nullable(),
  target: Selector,                 // interface or address the queue applies to
  match: NcmMatch.nullable(),       // null for a plain interface queue
  parent: z.string().max(64).nullable(),
  priority: z.number().int().min(1).max(8).nullable(),
  maxLimitUpBps: z.number().int().nullable(),
  maxLimitDownBps: z.number().int().nullable(),
  limitAtUpBps: z.number().int().nullable(),
  limitAtDownBps: z.number().int().nullable(),
  queueType: z.string().max(32).nullable(),
  ordinal: z.number().int().min(0),
  matchHash: z.string().length(16).nullable(),
}).strict();
export type NcmQosRule = z.infer<typeof NcmQosRule>;

export const NcmResource = z.discriminatedUnion('kind', [
  NcmInterface, NcmVlan, NcmRoute, NcmFirewallRule, NcmNatRule,
  NcmDhcpScope, NcmIpsecPeer, NcmLocalUser, NcmService, NcmQosRule,
]);
export type NcmResource = z.infer<typeof NcmResource>;

/** Narrowing helper for the three ordered kinds — they are the only ones that
 *  carry `ordinal` and a chain, and the only ones the order analysis reads. */
export type NcmOrderedRule = NcmFirewallRule | NcmNatRule | NcmQosRule;
