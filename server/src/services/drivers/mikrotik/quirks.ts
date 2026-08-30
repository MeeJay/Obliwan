/**
 * ObliWAN — RouterOS doctrine (layer 3 knowledge).
 *
 * This file is the machine-readable form of `docs/M4-normalisation-routeros.md`
 * §3 (the N01–N16 catalogue), §4 (the `sem_key` table) and §5.2
 * (`ncm_section_catalog`). It is imported by three consumers that must not be
 * allowed to disagree:
 *
 *   - `config/normalize.service.ts`, which builds the NCM;
 *   - `db/seeds/002_ncm_doctrine.ts`, which writes the same table rows into
 *     `ncm_section_catalog` and `routeros_defaults`;
 *   - the golden fixtures, which assert the two agree.
 *
 * THE RULE EVERY ENTRY IN THIS FILE OBEYS. A prop is removed from the NCM only
 * with a written reason and a written FALSE NEGATIVE. §0/D1 of the study:
 * over-normalising is worse than noise, because noise is visible and a false
 * negative is not. `stateProps` and `counterProps` therefore carry a `why`
 * string; a bare list would be undebuggable six weeks later.
 *
 * WHY `(section, prop)` AND NEVER `prop` ALONE. `mac-address` is state on a
 * bridge (inherited from the master port, and it changes at reboot when
 * `auto-mac=yes`) and it is CONFIGURATION on `/interface/ethernet`
 * (`admin-mac`) and on a static DHCP lease, where it is the identity itself.
 * A global "ignore mac-address" rule would make a re-addressed DHCP
 * reservation invisible. Every entry below is scoped to a section.
 */

import type { DeviceFamily, DiffSeverity, NcmResourceKind } from '@obliwan/shared';

// ============================================================================
// Section catalogue — N07 (ordering) + §4 (sem_key) + §5.2
// ============================================================================

export interface RouterOsSectionSpec {
  sectionPath: string;
  /** null = both RouterOS families. */
  family: DeviceFamily | null;
  /**
   * N07. `true` means position carries meaning and a reordering is a real
   * change; `false` means the section is a SET and the NCM sorts it, so a
   * reordering produces no snapshot at all.
   *
   * FALSE NEGATIVE OF `ordered: false`: total and silent for that section — the
   * tool stops seeing reorderings there forever. That is why this list is a
   * seeded, tested table and not free-form data, why flipping a section to
   * `false` is a `risk='high'` gesture gated by DRIFT_MANAGE, and why every
   * first-match evaluation below is `true` even when it costs noise.
   */
  ordered: boolean;
  /**
   * Position is relative to THIS prop's value, not to the file. Adding a rule
   * at the head of `chain=forward` shifts every `chain=input` rule in
   * RouterOS's own numbering; with an absolute position that is 40 `moved`
   * findings for a change that affects nothing. The study calls this single
   * detail worth several findings/device/day.
   */
  orderGroupProp: string | null;
  semKeyProps: string[];
  semKeyFallback: string[] | null;
  /** N11 — never compared, never rendered, never logged (R10). */
  secretProps: string[];
  /** N06 — looks like config, is state. */
  stateProps: string[];
  /** N05 — counters. */
  counterProps: string[];
  /** N09 hard bound: absence and presence are always two different things
   *  for these, so `default_fill` may never touch them. */
  noDefaultFillProps: string[];
  defaultSeverity: DiffSeverity;
  ros6Path: string | null;
  ros7Path: string | null;
  ncmResourceKind: NcmResourceKind | null;
  /** WHY the state/counter props above are not configuration, and what
   *  ignoring them can hide. Written into the seed row's rationale. */
  why: string;
  falseNegative: string;
}

/**
 * The props that are state or counters on EVERY section they appear on. They
 * still have to be listed per section in the catalogue rows below — this set
 * exists so the parser can recognise one on a section it has never seen and
 * not report it as an unknown prop (which would create a permanent ticket for
 * a counter).
 */
export const UNIVERSAL_STATE_PROPS: ReadonlySet<string> = new Set([
  'dynamic', 'invalid', 'inactive', 'running', 'slave', 'default',
  'bytes', 'packets', 'dropped', 'queued-bytes', 'queued-packets',
  'rate', 'packet-rate', 'last-seen', 'active', 'builtin',
]);

/**
 * `disabled` is CONFIGURATION and must never join the set above. Disabling the
 * WAN drop rule is a deliberate act and it is often the first thing a
 * troubleshooter does and forgets to undo; `inactive` next to it is derived
 * state. Confusing the two costs exactly the change the product exists to
 * catch, so the distinction gets its own named constant rather than living in
 * a comment.
 */
export const CONFIG_LOOKING_LIKE_STATE: ReadonlySet<string> = new Set(['disabled']);

const NO_FILL_FIREWALL = [
  'action', 'chain', 'disabled', 'passthrough', 'log', 'src-address', 'dst-address',
  'to-addresses', 'to-ports', 'in-interface', 'out-interface', 'in-interface-list',
  'out-interface-list', 'connection-state', 'src-port', 'dst-port', 'protocol',
];

export const ROUTEROS_SECTION_CATALOG: readonly RouterOsSectionSpec[] = [
  // ── firewall: ordered, first-match, the whole reason this product exists ──
  {
    sectionPath: '/ip/firewall/filter',
    family: null,
    ordered: true,
    orderGroupProp: 'chain',
    semKeyProps: ['chain', 'comment'],
    semKeyFallback: ['chain', 'matchHash'],
    secretProps: [],
    stateProps: ['dynamic', 'invalid'],
    counterProps: ['bytes', 'packets'],
    noDefaultFillProps: NO_FILL_FIREWALL,
    defaultSeverity: 'high',
    ros6Path: '/ip/firewall/filter',
    ros7Path: '/ip/firewall/filter',
    ncmResourceKind: 'firewallRule',
    why: 'bytes/packets move on every packet; `dynamic` marks a rule the router wrote itself (hotspot, ipsec policy).',
    falseNegative: 'a hand-written rule recreated as dynamic becomes invisible — which is why firewall dynamics are DOWNGRADED, not excluded (N03).',
  },
  {
    sectionPath: '/ip/firewall/nat',
    family: null,
    ordered: true,
    orderGroupProp: 'chain',
    semKeyProps: ['chain', 'comment'],
    semKeyFallback: ['chain', 'matchHash'],
    secretProps: [],
    stateProps: ['dynamic', 'invalid'],
    counterProps: ['bytes', 'packets'],
    noDefaultFillProps: NO_FILL_FIREWALL,
    defaultSeverity: 'high',
    ros6Path: '/ip/firewall/nat',
    ros7Path: '/ip/firewall/nat',
    ncmResourceKind: 'natRule',
    why: 'same as filter; NAT is first-match per chain.',
    falseNegative: 'as above.',
  },
  {
    sectionPath: '/ip/firewall/mangle',
    family: null,
    ordered: true,
    orderGroupProp: 'chain',
    semKeyProps: ['chain', 'comment'],
    semKeyFallback: ['chain', 'matchHash'],
    secretProps: [],
    stateProps: ['dynamic', 'invalid'],
    counterProps: ['bytes', 'packets'],
    noDefaultFillProps: NO_FILL_FIREWALL,
    defaultSeverity: 'medium',
    ros6Path: '/ip/firewall/mangle',
    ros7Path: '/ip/firewall/mangle',
    ncmResourceKind: 'firewallRule',
    why: 'marks are posted upstream and consumed downstream: order is load-bearing.',
    falseNegative: 'as above.',
  },
  {
    sectionPath: '/ip/firewall/raw',
    family: null,
    ordered: true,
    orderGroupProp: 'chain',
    semKeyProps: ['chain', 'comment'],
    semKeyFallback: ['chain', 'matchHash'],
    secretProps: [],
    stateProps: ['dynamic', 'invalid'],
    counterProps: ['bytes', 'packets'],
    noDefaultFillProps: NO_FILL_FIREWALL,
    defaultSeverity: 'high',
    ros6Path: '/ip/firewall/raw',
    ros7Path: '/ip/firewall/raw',
    ncmResourceKind: 'firewallRule',
    why: 'evaluated before conntrack; first-match.',
    falseNegative: 'as above.',
  },
  {
    // THE CLASSIC TRAP of N07: simple queues are evaluated in order and the
    // first match wins. Treating them as a set would silently stop reporting
    // a reordering that changes which customer gets the bandwidth.
    sectionPath: '/queue/simple',
    family: null,
    ordered: true,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: ['target', 'max-limit'],
    secretProps: [],
    stateProps: ['dynamic', 'invalid'],
    counterProps: ['bytes', 'packets', 'dropped', 'rate', 'packet-rate', 'queued-bytes', 'total-bytes', 'total-packets'],
    noDefaultFillProps: ['max-limit', 'limit-at', 'target', 'disabled'],
    defaultSeverity: 'medium',
    ros6Path: '/queue/simple',
    ros7Path: '/queue/simple',
    ncmResourceKind: 'qosRule',
    why: 'queue counters move continuously.',
    falseNegative: 'none for the counters; the ordering is kept precisely because it is the trap.',
  },
  {
    sectionPath: '/queue/tree',
    family: null,
    ordered: true,
    orderGroupProp: 'parent',
    semKeyProps: ['name'],
    semKeyFallback: null,
    secretProps: [],
    stateProps: ['dynamic', 'invalid'],
    counterProps: ['bytes', 'packets', 'dropped', 'rate', 'packet-rate', 'queued-bytes'],
    noDefaultFillProps: ['max-limit', 'limit-at', 'priority', 'parent'],
    defaultSeverity: 'medium',
    ros6Path: '/queue/tree',
    ros7Path: '/queue/tree',
    ncmResourceKind: 'qosRule',
    why: 'as above. Order between siblings matters through `priority`, not raw position — hence the group prop.',
    falseNegative: 'as above.',
  },
  {
    sectionPath: '/ip/ipsec/policy',
    family: null,
    ordered: true,
    orderGroupProp: null,
    semKeyProps: ['src-address', 'dst-address', 'protocol'],
    semKeyFallback: null,
    secretProps: [],
    stateProps: ['dynamic', 'invalid', 'active', 'ph2-state'],
    counterProps: ['ph2-count'],
    noDefaultFillProps: ['src-address', 'dst-address', 'action', 'level'],
    defaultSeverity: 'high',
    ros6Path: '/ip/ipsec/policy',
    ros7Path: '/ip/ipsec/policy',
    ncmResourceKind: 'ipsecPeer',
    why: 'SA selection is ordered; `ph2-state` and `active` describe a live tunnel, not its configuration.',
    falseNegative: 'a tunnel that stopped establishing looks unchanged here — that is supervision (M3/M8), not drift.',
  },

  // ── unordered: sets, looked up by name or by key ──────────────────────────
  {
    sectionPath: '/ip/address',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['address', 'interface'],
    semKeyFallback: null,
    secretProps: [],
    // `network` is DERIVED from `address` and yet the export emits it. Storing
    // it doubles every address finding.
    stateProps: ['dynamic', 'invalid', 'actual-interface', 'network', 'slave'],
    counterProps: [],
    noDefaultFillProps: ['address', 'interface'],
    defaultSeverity: 'high',
    ros6Path: '/ip/address',
    ros7Path: '/ip/address',
    ncmResourceKind: 'interface',
    why: 'no ordered evaluation: an IP is matched by longest prefix, not by rank. `network` is a function of `address`.',
    falseNegative: 'a hand-edited `network=` inconsistent with `address=` is not reported — RouterOS recomputes it anyway.',
  },
  {
    sectionPath: '/ip/route',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['dst-address', 'routing-table', 'gateway'],
    semKeyFallback: ['dst-address', 'gateway'],
    secretProps: [],
    stateProps: ['dynamic', 'active', 'inactive', 'static', 'connect', 'dhcp', 'blackhole-state', 'immediate-gw', 'gateway-status', 'pref-src'],
    counterProps: [],
    // `distance` is deliberately ABSENT from this list: ROS6 emits `distance=1`
    // where ROS7 omits it, and 1 really is the default, so completing it makes
    // the same intent hash identically on both branches. `dst-address` and
    // `gateway` stay: for those, absence and presence are never the same thing.
    noDefaultFillProps: ['dst-address', 'gateway', 'routing-table'],
    defaultSeverity: 'high',
    ros6Path: '/ip/route',
    ros7Path: '/ip/route',
    ncmResourceKind: 'route',
    why: 'selection is longest-prefix plus `distance`, never file order. Learned routes are state and belong to the telemetry model.',
    falseNegative: 'the DISAPPEARANCE of a learned default route produces no drift finding. It is a supervision signal (M3/M8) and the study is explicit that duplicating it here would create two truths.',
  },
  {
    sectionPath: '/ip/firewall/address-list',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['list', 'address'],
    semKeyFallback: null,
    secretProps: [],
    stateProps: ['dynamic', 'creation-time', 'timeout'],
    counterProps: [],
    noDefaultFillProps: ['list', 'address'],
    defaultSeverity: 'medium',
    ros6Path: '/ip/firewall/address-list',
    ros7Path: '/ip/firewall/address-list',
    ncmResourceKind: null,
    why: 'a set, and the single worst noise generator in the fleet: an `add-src-to-address-list` feeds it several times a minute.',
    falseNegative: 'a STATIC entry given a timeout by hand disappears from the diff. Accepted: with the timeout it is transient by definition.',
  },
  {
    sectionPath: '/interface/ethernet',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: ['default-name'],
    secretProps: [],
    stateProps: ['running', 'slave', 'actual-mtu', 'l2mtu', 'mac-address', 'switch', 'driver-rx-byte', 'driver-tx-byte'],
    counterProps: ['rx-byte', 'tx-byte', 'rx-packet', 'tx-packet', 'rx-drop', 'tx-drop', 'rx-error', 'tx-error', 'fp-rx-byte', 'fp-tx-byte', 'link-downs'],
    noDefaultFillProps: ['name', 'disabled', 'mtu'],
    defaultSeverity: 'medium',
    ros6Path: '/interface/ethernet',
    ros7Path: '/interface/ethernet',
    ncmResourceKind: 'interface',
    why: '`actual-mtu` and `l2mtu` are negotiated and follow the bridge; `running` is the physical link.',
    falseNegative: 'an MTU drop caused by a change of encapsulation is invisible here. Compensated: the CONFIGURED `mtu` stays in the NCM, and `actual-mtu` is already collected with history by the M3 SNMP pipeline, where it belongs.',
  },
  {
    sectionPath: '/interface/bridge',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: null,
    secretProps: [],
    // A bridge inherits the MAC of its master port and it changes at reboot
    // when `auto-mac=yes`, which is the default.
    stateProps: ['running', 'actual-mtu', 'l2mtu', 'mac-address'],
    counterProps: ['rx-byte', 'tx-byte', 'rx-packet', 'tx-packet'],
    noDefaultFillProps: ['name', 'disabled', 'vlan-filtering', 'pvid'],
    defaultSeverity: 'medium',
    ros6Path: '/interface/bridge',
    ros7Path: '/interface/bridge',
    ncmResourceKind: 'interface',
    why: 'the bridge MAC is inherited and changes at reboot with the default `auto-mac=yes`.',
    falseNegative: 'a deliberately pinned `admin-mac` change on a bridge is not reported. Rare, and it does not move a packet.',
  },
  {
    sectionPath: '/interface/bridge/port',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['bridge', 'interface'],
    semKeyFallback: null,
    secretProps: [],
    stateProps: ['inactive', 'running', 'dynamic', 'designated-cost', 'role', 'edge-port-discovery', 'forwarding', 'learning'],
    counterProps: [],
    noDefaultFillProps: ['bridge', 'interface', 'pvid', 'disabled'],
    defaultSeverity: 'high',
    ros6Path: '/interface/bridge/port',
    ros7Path: '/interface/bridge/port',
    ncmResourceKind: 'interface',
    why: 'STP role, forwarding and learning are computed by the protocol, not written by an operator.',
    falseNegative: 'an STP topology change is not drift. It is supervision.',
  },
  {
    sectionPath: '/interface/bridge/vlan',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['bridge', 'vlan-ids'],
    semKeyFallback: null,
    secretProps: [],
    stateProps: ['dynamic', 'current-tagged', 'current-untagged'],
    counterProps: [],
    noDefaultFillProps: ['bridge', 'vlan-ids', 'tagged', 'untagged'],
    defaultSeverity: 'high',
    ros6Path: '/interface/bridge/vlan',
    ros7Path: '/interface/bridge/vlan',
    ncmResourceKind: 'vlan',
    why: '`current-tagged`/`current-untagged` are the resolved membership including dynamic ports.',
    falseNegative: 'a port that joined a VLAN dynamically is not reported as a config change — it is not one.',
  },
  {
    sectionPath: '/interface/vlan',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: ['interface', 'vlan-id'],
    secretProps: [],
    stateProps: ['running', 'mac-address', 'actual-mtu', 'l2mtu'],
    counterProps: ['rx-byte', 'tx-byte'],
    noDefaultFillProps: ['name', 'vlan-id', 'interface', 'disabled'],
    defaultSeverity: 'high',
    ros6Path: '/interface/vlan',
    ros7Path: '/interface/vlan',
    ncmResourceKind: 'vlan',
    why: 'the MAC of a VLAN interface is inherited from its parent.',
    falseNegative: 'none of consequence.',
  },
  {
    sectionPath: '/interface/list/member',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['list', 'interface'],
    semKeyFallback: null,
    secretProps: [],
    stateProps: ['dynamic', 'inactive'],
    counterProps: [],
    noDefaultFillProps: ['list', 'interface'],
    defaultSeverity: 'high',
    ros6Path: '/interface/list/member',
    ros7Path: '/interface/list/member',
    ncmResourceKind: 'interface',
    why: 'membership drives the firewall selector vocabulary, so it is configuration; only the dynamic flag is state.',
    falseNegative: 'none. Removing an interface from `WAN` is a `changed` on that interface.',
  },
  {
    sectionPath: '/ip/dhcp-server',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: null,
    secretProps: [],
    stateProps: ['dynamic', 'invalid', 'leases-taken'],
    counterProps: ['leases-taken'],
    noDefaultFillProps: ['name', 'interface', 'address-pool', 'disabled'],
    defaultSeverity: 'medium',
    ros6Path: '/ip/dhcp-server',
    ros7Path: '/ip/dhcp-server',
    ncmResourceKind: 'dhcpScope',
    why: 'lease counters move constantly.',
    falseNegative: 'none.',
  },
  {
    sectionPath: '/ip/dhcp-server/network',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['address'],
    semKeyFallback: null,
    secretProps: [],
    stateProps: ['dynamic'],
    counterProps: [],
    noDefaultFillProps: ['address', 'gateway', 'dns-server'],
    defaultSeverity: 'medium',
    ros6Path: '/ip/dhcp-server/network',
    ros7Path: '/ip/dhcp-server/network',
    ncmResourceKind: 'dhcpScope',
    why: 'a lookup table, never ordered.',
    falseNegative: 'none.',
  },
  {
    sectionPath: '/ip/dhcp-server/lease',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['mac-address', 'server'],
    semKeyFallback: ['address'],
    secretProps: [],
    // The whole point of N03/N06 in one row: everything about a lease except
    // the static reservation itself is state.
    stateProps: ['dynamic', 'status', 'expires-after', 'last-seen', 'active-address', 'active-mac-address', 'active-server', 'active-client-id', 'host-name', 'radius', 'blocked'],
    counterProps: [],
    noDefaultFillProps: ['mac-address', 'address', 'server'],
    defaultSeverity: 'medium',
    ros6Path: '/ip/dhcp-server/lease',
    ros7Path: '/ip/dhcp-server/lease',
    ncmResourceKind: 'dhcpScope',
    why: 'a non-static lease is an allocation, not a configuration line. Only `dynamic=no` reservations enter the NCM.',
    falseNegative: 'a static reservation converted to dynamic looks like a deletion — which it functionally is.',
  },
  {
    sectionPath: '/ip/pool',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: null,
    secretProps: [],
    stateProps: [],
    counterProps: [],
    noDefaultFillProps: ['name', 'ranges'],
    defaultSeverity: 'medium',
    ros6Path: '/ip/pool',
    ros7Path: '/ip/pool',
    ncmResourceKind: 'dhcpScope',
    why: 'lookup by name.',
    falseNegative: 'none.',
  },
  {
    sectionPath: '/ip/service',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: null,
    secretProps: [],
    stateProps: ['invalid'],
    counterProps: [],
    // `disabled` and `address` on a management service are exactly what an
    // audit looks at: never filled from a default.
    noDefaultFillProps: ['name', 'disabled', 'address', 'port', 'certificate'],
    defaultSeverity: 'critical',
    ros6Path: '/ip/service',
    ros7Path: '/ip/service',
    ncmResourceKind: 'service',
    why: 'nothing here is state except the derived `invalid`.',
    falseNegative: 'none. This section is deliberately the least normalised of the whole catalogue.',
  },
  {
    sectionPath: '/user',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: null,
    secretProps: ['password'],
    stateProps: ['last-logged-in'],
    counterProps: [],
    noDefaultFillProps: ['name', 'group', 'address', 'disabled'],
    defaultSeverity: 'critical',
    ros6Path: '/user',
    ros7Path: '/user',
    ncmResourceKind: 'localUser',
    why: '`last-logged-in` is an event timestamp.',
    falseNegative: 'a PASSWORD CHANGE IS NOT DETECTABLE — `show-sensitive=no` never emits it (R10, N11). What stays detectable, and is the far more common attack, is the APPEARANCE of an account and a change of `group`.',
  },
  {
    sectionPath: '/user/group',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: null,
    secretProps: [],
    stateProps: ['default'],
    counterProps: [],
    noDefaultFillProps: ['name', 'policy'],
    defaultSeverity: 'critical',
    ros6Path: '/user/group',
    ros7Path: '/user/group',
    ncmResourceKind: null,
    why: '`default` marks a system object.',
    falseNegative: 'NCM v1 has no resource for a permission group: a policy edit on a custom group lands in `unmodeled[]` and is counted, not diffed. Declared, not hidden (N5).',
  },
  {
    sectionPath: '/ip/ipsec/peer',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: ['address'],
    secretProps: ['secret', 'passive'],
    stateProps: ['dynamic', 'responder', 'ph1-state'],
    counterProps: ['rx-bytes', 'tx-bytes', 'last-seen'],
    noDefaultFillProps: ['address', 'exchange-mode', 'profile'],
    defaultSeverity: 'high',
    ros6Path: '/ip/ipsec/peer',
    ros7Path: '/ip/ipsec/peer',
    ncmResourceKind: 'ipsecPeer',
    why: 'phase-1 state and byte counters describe a live SA.',
    falseNegative: 'a PSK rotation is undetectable (R10). Compensated by the fact that losing the PSK entirely — `psk` to `none` — IS detectable through the fingerprint\'s `unavailable` flag versus an absent identity.',
  },
  {
    sectionPath: '/ip/ipsec/identity',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['peer'],
    semKeyFallback: null,
    secretProps: ['secret', 'key', 'password'],
    stateProps: ['dynamic'],
    counterProps: [],
    noDefaultFillProps: ['peer', 'auth-method', 'my-id', 'remote-id'],
    defaultSeverity: 'high',
    ros6Path: '/ip/ipsec/identity',
    ros7Path: '/ip/ipsec/identity',
    ncmResourceKind: 'ipsecPeer',
    why: 'nothing here is state beyond the dynamic flag.',
    falseNegative: 'as above for the secret.',
  },
  {
    sectionPath: '/snmp/community',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: null,
    secretProps: ['authentication-password', 'encryption-password'],
    stateProps: ['default'],
    counterProps: [],
    noDefaultFillProps: ['name', 'addresses', 'security', 'read-access', 'write-access'],
    defaultSeverity: 'high',
    ros6Path: '/snmp/community',
    ros7Path: '/snmp/community',
    ncmResourceKind: 'service',
    why: 'the v3 auth/priv passwords are secrets; the community NAME is not one and is deliberately kept in clear (§7.2) because "is this community literally public" is the whole audit question.',
    falseNegative: 'a v3 password rotation is invisible. A drop from v3 to v2c is not.',
  },
  {
    sectionPath: '/snmp',
    family: null,
    ordered: false,
    orderGroupProp: null,
    semKeyProps: [],
    semKeyFallback: null,
    secretProps: [],
    stateProps: [],
    counterProps: [],
    noDefaultFillProps: ['enabled', 'trap-version', 'trap-community'],
    defaultSeverity: 'high',
    ros6Path: '/snmp',
    ros7Path: '/snmp',
    ncmResourceKind: 'service',
    why: 'a singleton; nothing here is state.',
    falseNegative: 'none.',
  },
  {
    sectionPath: '/interface/wireguard',
    family: 'mikrotik_routeros7',
    ordered: false,
    orderGroupProp: null,
    semKeyProps: ['name'],
    semKeyFallback: null,
    secretProps: ['private-key'],
    stateProps: ['running', 'public-key'],
    counterProps: ['rx', 'tx'],
    noDefaultFillProps: ['name', 'listen-port', 'disabled'],
    defaultSeverity: 'high',
    ros6Path: null,
    ros7Path: '/interface/wireguard',
    ncmResourceKind: 'interface',
    why: 'the public key is derived from the private one, which we never see.',
    falseNegative: 'a rotated WireGuard key pair is invisible for the same reason as any secret.',
  },
];

const CATALOG_BY_PATH = new Map<string, RouterOsSectionSpec>(
  ROUTEROS_SECTION_CATALOG.map((s) => [s.sectionPath, s]),
);

export function sectionSpec(path: string): RouterOsSectionSpec | null {
  return CATALOG_BY_PATH.get(path) ?? null;
}

/**
 * N07 default. An UNKNOWN section is treated as ORDERED, which is the
 * conservative answer: assuming a section is a set is the failure mode that
 * silently stops reporting reorderings, and `section_ordered` defaults to
 * `true` in the schema for the same reason.
 */
export function isOrderedSection(path: string): boolean {
  return sectionSpec(path)?.ordered ?? true;
}

// ============================================================================
// N15 / `map_path` — RouterOS 6 and 7 rendering the same thing differently
// ============================================================================

/**
 * ONLY for cases where the two paths express STRICTLY the same object. BGP and
 * OSPF are deliberately absent: their model changed, not merely their name, and
 * an alias there would be a lie that produces confident nonsense. They stay two
 * distinct unmodeled sections until someone models both.
 */
export const SECTION_ALIASES: Readonly<Record<string, string>> = {
  // ROS7 renamed the menu; the object is identical.
  '/interface/bridge/settings': '/interface/bridge/settings',
  // ROS6 wrote `/ip/firewall/service-port`, ROS7 kept it: listed to document
  // that it was checked and needs no alias.
};

/** Canonical section path after aliasing. Pure, and the identity by default —
 *  a missing alias must never invent one. */
export function aliasSection(path: string): string {
  return SECTION_ALIASES[path] ?? path;
}

// ============================================================================
// N03 — dynamic entries
// ============================================================================

/**
 * `/export` already omits most dynamic objects; the API does not, and M4 uses
 * the API as a complement. This predicate is therefore mostly a rule of the
 * API path and a belt on the export path.
 *
 * The `timeout` clause covers `/ip/firewall/address-list`, where an entry fed
 * by `add-src-to-address-list` changes several times a minute and never carries
 * `dynamic=yes` in an export.
 */
export function isDynamicEntry(props: Readonly<Record<string, string>>, sectionPath: string): boolean {
  const d = props['dynamic'];
  if (d === 'yes' || d === 'true') return true;
  if (sectionPath === '/ip/firewall/address-list' && (props['timeout'] ?? '') !== '') return true;
  if (sectionPath === '/ip/dhcp-server/lease' && props['dynamic'] !== 'no' && props['address'] === undefined) return true;
  return false;
}

// ============================================================================
// Vocabulary mapping — RouterOS words to NCM words
// ============================================================================

/**
 * RouterOS firewall actions to the NCM's fixed vocabulary. Anything unknown
 * becomes `other` AND is recorded, never guessed into an existing value: a
 * mangle action silently mapped to `passthrough` would make the order analysis
 * declare a rule non-terminal when it is not.
 */
export const FIREWALL_ACTION_MAP: Readonly<Record<string, string>> = {
  accept: 'accept',
  drop: 'drop',
  reject: 'reject',
  log: 'log',
  passthrough: 'passthrough',
  jump: 'jump',
  return: 'return',
  tarpit: 'tarpit',
  'fasttrack-connection': 'fasttrack',
  'add-src-to-address-list': 'addToList',
  'add-dst-to-address-list': 'addToList',
};

export const NAT_ACTION_MAP: Readonly<Record<string, string>> = {
  masquerade: 'masquerade',
  'src-nat': 'srcnat',
  'dst-nat': 'dstnat',
  netmap: 'netmap',
  redirect: 'redirect',
  accept: 'accept',
};

/** `/ip/service` names to the NCM service vocabulary. `www` is `http` and
 *  `www-ssl` is `https`: the RouterOS spelling is an implementation detail and
 *  a cross-brand audit query must not have to know it. */
export const SERVICE_NAME_MAP: Readonly<Record<string, string>> = {
  ssh: 'ssh',
  telnet: 'telnet',
  ftp: 'ftp',
  www: 'http',
  'www-ssl': 'https',
  api: 'api',
  'api-ssl': 'api-ssl',
  winbox: 'winbox',
};

/** Section path to `NcmInterface.type`. */
export const INTERFACE_TYPE_BY_SECTION: Readonly<Record<string, string>> = {
  '/interface/ethernet': 'ethernet',
  '/interface/bridge': 'bridge',
  '/interface/vlan': 'vlan',
  '/interface/bonding': 'bond',
  '/interface/lte': 'lte',
  '/interface/pppoe-client': 'pppoe',
  '/interface/l2tp-client': 'l2tp',
  '/interface/l2tp-server': 'l2tp',
  '/interface/wireguard': 'wireguard',
  '/interface/gre': 'gre',
  '/interface/eoip': 'gre',
  '/interface/wifi': 'wifi',
  '/interface/wireless': 'wifi',
  '/interface/veth': 'other',
  '/interface/list': 'other',
};

/**
 * Sections that are configuration but that NCM v1 does not model. Listed
 * explicitly so that `unmodeled[]` carries `forwardingRelevant` honestly:
 * K2 must degrade its verdict when a routing protocol it cannot read is
 * present, and must NOT degrade it because the box has an e-mail alert.
 */
export const FORWARDING_RELEVANT_UNMODELED: readonly RegExp[] = [
  /^\/routing\//,
  /^\/ip\/firewall\/(layer7-protocol|service-port|connection)/,
  /^\/interface\/(wireless|wifi|bonding|eoip|gre|ipip|vrrp|6to4)/,
  /^\/ppp\//,
  /^\/interface\/(pppoe|l2tp|sstp|ovpn|pptp)-(client|server)/,
  /^\/ip\/(proxy|hotspot|socks|dns)/,
  /^\/mpls/,
  /^\/ipv6\//,
  /^\/system\/(script|scheduler)/,
  /^\/tool\/netwatch/,
];

export function isForwardingRelevant(sectionPath: string): boolean {
  return FORWARDING_RELEVANT_UNMODELED.some((re) => re.test(sectionPath));
}

// ============================================================================
// N09 — the seeded corner of the defaults dictionary
// ============================================================================

/**
 * `routeros_defaults` is meant to be LEARNED (`/export terse verbose` or
 * `print detail`), not typed in: a hand-written dictionary is wrong within two
 * releases. These rows exist only as the "last resort" tier the study allows,
 * for the handful of props whose appearance across a minor upgrade is the
 * documented noise scenario of N09 — one `changed` per bridge on every device
 * on the same night.
 *
 * `os_version` is EXACT. It is never extrapolated to a newer release: a value
 * that stopped being the default is a false negative, and this table is the
 * one place where guessing would create one on a whole fleet at once.
 */
export interface SeededDefault {
  family: DeviceFamily;
  osVersion: string;
  sectionPath: string;
  prop: string;
  value: string;
  why: string;
}

export const SEEDED_ROUTEROS_DEFAULTS: readonly SeededDefault[] = [
  {
    family: 'mikrotik_routeros7',
    osVersion: '7.14',
    sectionPath: '/interface/bridge',
    prop: 'port-cost-mode',
    value: 'long',
    why: 'added in the 7.13 -> 7.14 range and emitted on every bridge afterwards; the documented "one finding per bridge on 30 devices in one night" case of N09.',
  },
  {
    family: 'mikrotik_routeros7',
    osVersion: '7.14',
    sectionPath: '/ip/route',
    prop: 'routing-table',
    value: 'main',
    why: 'ROS7 introduced routing tables; `main` is what a ROS6 route implicitly was.',
  },
  {
    family: 'mikrotik_routeros6',
    osVersion: '6.49.10',
    sectionPath: '/ip/route',
    prop: 'distance',
    value: '1',
    why: 'ROS6 emits `distance=1` where ROS7 omits it. Filling it on the ROS6 side makes the same intent hash identically on both.',
  },
];

// ============================================================================
// N10 — comment volatility
// ============================================================================

/**
 * Anchored at END OF STRING and matching an EXPLICIT date format. The study is
 * blunt about why: a pattern like `.*\d.*` would eat `comment="VLAN 30
 * clients"`, and an unstable comment destroys the best pairing key the firewall
 * has. The rule lint refuses any unanchored pattern on `comment`.
 *
 * FALSE NEGATIVE: someone who hides information in the dated suffix and edits
 * only that suffix is not reported. A comment moves no packet; accepted.
 */
export const COMMENT_VOLATILE_SUFFIX =
  '\\s*[-\u2013]\\s*checked\\s+\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}(:\\d{2})?$';

/** MikroTik's own `defconf:` comments are rewritten by the vendor on reset and
 *  on some upgrades. They are recognised so the diff can classify them, never
 *  so they can be dropped. */
export const DEFCONF_COMMENT_PREFIX = 'defconf:';
