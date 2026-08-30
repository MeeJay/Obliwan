/**
 * ObliWAN M12 — the fifty synthetic configurations the acceptance test mines.
 *
 * HONESTY, FIRST AND IN FULL. There is no MikroTik on this machine, and there
 * never was one in this project: no router, no CHR, no Vigor, no Zyxel, no
 * SonicWall. Every document below was written by me, by hand, in the exact NCM
 * shape `services/config/collect.service.ts` produces. What the acceptance test
 * therefore proves is the MINER — the fact algebra, the cross-site alignment,
 * the clustering, the stopping rule, the coverage arithmetic, the deviation
 * classification and the two conformance scores. It proves nothing whatsoever
 * about whether a real RouterOS export parses into these documents; that is
 * M4's claim and M4's test, not this one's.
 *
 * What the fleet is meant to look like, and why it is shaped this way:
 *
 *   PROFILE A — 22 small branches. One WAN, one LAN bridge, a stock firewall.
 *   PROFILE B — 17 branches with a voice VLAN and an IPsec tunnel to HQ.
 *   PROFILE C — 11 large sites with a second WAN, failover routing and QoS.
 *
 * Inside a profile, every site differs in the ways a real MSP fleet differs:
 * its LAN prefix, its WAN address and gateway, its DNS servers, its DHCP pool,
 * its domain, its IPsec peer. Those are the VARIABLES the miner has to discover
 * by alignment — not by being told. Across profiles the STRUCTURE differs, and
 * that is what the clustering has to separate.
 *
 * On top of that, eleven sites carry a genuine local peculiarity — an extra
 * firewall rule for a customer's supplier, telnet left enabled, an extra static
 * route, an unusual SSH port. Those are the deviations the operator must be
 * able to see and classify. They are deliberately NOT distributed evenly: a
 * baseline miner that only works on a tidy fleet is a baseline miner that works
 * on a fleet that never needed one.
 *
 * Test scaffolding. Never imported by the server at runtime; it lives under
 * `src/` only so `tsc` type-checks it.
 */

import type {
  NcmCoverageMap, NcmDhcpScope, NcmDocument, NcmFirewallRule, NcmInterface,
  NcmIpsecPeer, NcmLocalUser, NcmNatRule, NcmQosRule, NcmRoute, NcmService,
  NcmVlan,
} from '@obliwan/shared';
import { EMPTY_MATCH, NCM_RESOURCE_KINDS, UNAVAILABLE_SECRET } from '@obliwan/shared';

export type ProfileName = 'A' | 'B' | 'C';

export interface SiteSpec {
  index: number;
  name: string;
  profile: ProfileName;
  /** Third octet of the site's private space: 10.<octet>.0.0/24 for the LAN. */
  octet: number;
  /** Local peculiarities, the things an operator will have to classify. */
  quirks: {
    telnetEnabled?: boolean;
    sshPort?: number;
    supplierRule?: string;   // a CIDR allowed inbound
    extraRoute?: string;     // a static route nobody else has
    jumboMtu?: boolean;
  };
}

function coverage(): NcmCoverageMap {
  const out = {} as Record<string, unknown>;
  for (const kind of NCM_RESOURCE_KINDS) {
    out[kind] = { state: 'complete', via: 'routeros_api', reason: null, recordCount: 1 };
  }
  return out as NcmCoverageMap;
}

const base = (via: 'routeros_api' = 'routeros_api') => ({
  keyQuality: 'strong' as const,
  managedBy: 'unknown' as const,
  managedSlug: null,
  comment: null,
  disabled: false,
  via,
});

function iface(o: Partial<NcmInterface> & { name: string; type: NcmInterface['type'] }): NcmInterface {
  return {
    ...base(),
    semKey: `if.v1:${o.name}`,
    kind: 'interface',
    alias: null,
    parent: null,
    mtu: null,
    addresses: [],
    lists: [],
    zone: null,
    ...o,
  };
}

function route(o: { dst: string; gateway: string | null; distance?: number | null }): NcmRoute {
  return {
    ...base(),
    semKey: `route.v1:main:${o.dst}`,
    kind: 'route',
    dst: o.dst,
    gateway: o.gateway,
    distance: o.distance ?? 1,
    scope: null,
    targetScope: null,
    table: 'main',
    checkGateway: null,
    vrf: null,
  };
}

let seq = 0;
function fw(o: {
  slug: string;
  chain: NcmFirewallRule['chain'];
  action: NcmFirewallRule['action'];
  match?: Partial<NcmFirewallRule['match']>;
}): NcmFirewallRule {
  seq += 1;
  return {
    ...base(),
    semKey: `fw.v1:${o.chain}:${o.slug}`,
    kind: 'firewallRule',
    chain: o.chain,
    chainName: null,
    match: { ...EMPTY_MATCH, ...(o.match ?? {}) },
    action: o.action,
    jumpTarget: null,
    rejectWith: null,
    log: false,
    logPrefix: null,
    addToList: null,
    addToListTimeout: null,
    ordinal: seq % 64,
    matchHash: String(seq).padStart(16, '0'),
  };
}

function nat(o: { slug: string; out: string }): NcmNatRule {
  seq += 1;
  return {
    ...base(),
    semKey: `nat.v1:postrouting:${o.slug}`,
    kind: 'natRule',
    chain: 'postrouting',
    chainName: null,
    match: { ...EMPTY_MATCH, outInterface: [`ifaceList:${o.out}`] },
    action: 'masquerade',
    toAddresses: null,
    toPorts: null,
    ordinal: seq % 64,
    matchHash: String(seq).padStart(16, '0'),
  };
}

function svc(o: Partial<NcmService> & { service: NcmService['service'] }): NcmService {
  return {
    ...base(),
    semKey: `svc.v1:${o.service}`,
    kind: 'service',
    rawName: null,
    enabled: true,
    port: null,
    allowedFrom: ['any'],
    tlsRequired: null,
    certificate: null,
    version: null,
    // The two secret-bearing fields of a service. They are populated exactly as
    // the collector populates them, so the acceptance test proves the refusal
    // on a document that really does carry them — not on a sanitised one.
    communityFingerprint: null,
    communityIsWellKnown: null,
    ...o,
  };
}

function user(o: Partial<NcmLocalUser> & { username: string }): NcmLocalUser {
  return {
    ...base(),
    semKey: `user.v1:${o.username}`,
    kind: 'localUser',
    group: 'full',
    permissions: [],
    allowedFrom: ['any'],
    passwordFingerprint: UNAVAILABLE_SECRET,
    isVendorDefault: false,
    sshKeyFingerprints: [],
    twoFactor: null,
    ...o,
  };
}

function dhcp(o: Partial<NcmDhcpScope> & { name: string; subnet: string }): NcmDhcpScope {
  return {
    ...base(),
    semKey: `dhcp.v1:${o.name}`,
    kind: 'dhcpScope',
    onInterface: 'iface:bridge-lan',
    poolFrom: null,
    poolTo: null,
    gateway: null,
    dnsServers: [],
    ntpServers: [],
    domain: null,
    leaseSeconds: 86400,
    reservations: [],
    options: [],
    ...o,
  };
}

function vlan(o: Partial<NcmVlan> & { vlanId: number }): NcmVlan {
  return {
    ...base(),
    semKey: `vlan.v1:bridge-lan:${o.vlanId}`,
    kind: 'vlan',
    name: null,
    parent: 'bridge-lan',
    taggedPorts: [],
    untaggedPorts: [],
    ...o,
  };
}

function ipsec(o: Partial<NcmIpsecPeer> & { remote: string }): NcmIpsecPeer {
  return {
    ...base(),
    semKey: `ipsec.v1:${o.remote}`,
    kind: 'ipsecPeer',
    name: 'hq',
    localId: null,
    remoteId: null,
    exchangeMode: 'ike2',
    authMethod: 'psk',
    // A real PSK fingerprint, present in the document exactly as the collector
    // leaves it. The miner must never turn it into a fact.
    pskFingerprint: { algo: 'hmac-sha256/v1', fp: 'AAAAAAAAAAAAAAAAAAAAAA', unavailable: false },
    proposal: {
      encryption: ['aes-256-cbc'],
      integrity: ['sha256'],
      dhGroup: ['modp2048'],
      lifetimeSeconds: 28800,
      pfsGroup: 'modp2048',
    },
    localSubnets: [],
    remoteSubnets: ['10.200.0.0/16'],
    dpdSeconds: 30,
    natTraversal: true,
    ...o,
  };
}

function qos(o: Partial<NcmQosRule> & { name: string }): NcmQosRule {
  seq += 1;
  return {
    ...base(),
    semKey: `qos.v1:simple:${o.name}`,
    kind: 'qosRule',
    queueClass: 'simple',
    target: ['iface:ether1'],
    match: null,
    parent: null,
    priority: 4,
    maxLimitUpBps: null,
    maxLimitDownBps: null,
    limitAtUpBps: null,
    limitAtDownBps: null,
    queueType: 'pcq',
    ordinal: seq % 64,
    matchHash: null,
    ...o,
  };
}

const MGMT = 'cidr:10.255.0.0/24';

/**
 * The fifty specs. Deterministic, and written out as a function rather than as
 * a literal so the distribution of the quirks stays readable.
 */
export function fleetSpecs(): SiteSpec[] {
  const specs: SiteSpec[] = [];
  for (let i = 0; i < 50; i++) {
    const profile: ProfileName = i < 22 ? 'A' : i < 39 ? 'B' : 'C';
    specs.push({
      index: i,
      name: `site-${String(i).padStart(2, '0')}`,
      profile,
      octet: 10 + i,
      quirks: {},
    });
  }
  // Eleven local peculiarities, clustered on the sites a real fleet clusters
  // them on: the oldest branches and the two the customer administers itself.
  specs[3].quirks.telnetEnabled = true;
  specs[7].quirks.telnetEnabled = true;
  specs[5].quirks.supplierRule = '203.0.113.0/28';
  specs[12].quirks.supplierRule = '198.18.7.0/24';
  specs[41].quirks.supplierRule = '203.0.113.64/28';
  specs[9].quirks.extraRoute = '172.20.4.0/24';
  specs[26].quirks.extraRoute = '172.31.9.0/24';
  specs[44].quirks.extraRoute = '172.16.88.0/24';
  specs[2].quirks.sshPort = 2222;
  specs[30].quirks.sshPort = 2222;
  specs[47].quirks.jumboMtu = true;
  return specs;
}

/** One site's NCM document. */
export function siteDoc(spec: SiteSpec, deviceId: number): NcmDocument {
  const o = spec.octet;
  const lan = `10.${o}.0.0/24`;
  const lanGw = `10.${o}.0.1/24`;
  const wan = `198.51.${o}.2/30`;
  const wanGw = `ip:198.51.${o}.1`;

  const interfaces: NcmInterface[] = [
    iface({
      name: 'ether1', type: 'ethernet', lists: ['WAN'],
      addresses: [{ cidr: wan, originUnknown: false }],
      mtu: spec.quirks.jumboMtu ? 9000 : 1500,
    }),
    iface({ name: 'ether2', type: 'ethernet', parent: 'bridge-lan', mtu: 1500 }),
    iface({ name: 'ether3', type: 'ethernet', parent: 'bridge-lan', mtu: 1500 }),
    iface({
      name: 'bridge-lan', type: 'bridge', lists: ['LAN'],
      addresses: [{ cidr: lanGw, originUnknown: false }], mtu: 1500,
    }),
  ];

  const routes: NcmRoute[] = [route({ dst: '0.0.0.0/0', gateway: wanGw })];

  const firewallRules: NcmFirewallRule[] = [
    fw({ slug: 'in-est', chain: 'input', action: 'accept', match: { connectionState: ['established', 'related'] } }),
    fw({ slug: 'in-mgmt', chain: 'input', action: 'accept', match: { protocol: 'tcp', srcAddress: [MGMT], dstPort: [[spec.quirks.sshPort ?? 22, spec.quirks.sshPort ?? 22]] } }),
    fw({ slug: 'in-lan', chain: 'input', action: 'accept', match: { inInterface: ['iface:bridge-lan'] } }),
    fw({ slug: 'in-drop', chain: 'input', action: 'drop' }),
    fw({ slug: 'fw-est', chain: 'forward', action: 'accept', match: { connectionState: ['established', 'related'] } }),
    fw({ slug: 'fw-inv', chain: 'forward', action: 'drop', match: { connectionState: ['invalid'] } }),
    fw({ slug: 'fw-out', chain: 'forward', action: 'accept', match: { inInterface: ['iface:bridge-lan'], outInterface: ['ifaceList:WAN'] } }),
  ];

  const services: NcmService[] = [
    svc({ service: 'ssh', enabled: true, port: spec.quirks.sshPort ?? 22, allowedFrom: [MGMT] }),
    svc({ service: 'winbox', enabled: true, port: 8291, allowedFrom: [MGMT] }),
    svc({ service: 'api', enabled: false, port: 8728, allowedFrom: [MGMT] }),
    svc({ service: 'http', enabled: false, port: 80, allowedFrom: ['any'] }),
    svc({ service: 'ftp', enabled: false, port: 21, allowedFrom: ['any'] }),
    svc({
      service: 'snmp', enabled: true, port: 161, version: 'v3', allowedFrom: [MGMT],
      communityFingerprint: UNAVAILABLE_SECRET, communityIsWellKnown: false,
    }),
  ];
  if (spec.quirks.telnetEnabled) {
    services.push(svc({ service: 'telnet', enabled: true, port: 23, allowedFrom: ['any'] }));
  }

  const localUsers: NcmLocalUser[] = [
    user({ username: 'obliwan-svc', group: 'full', allowedFrom: [MGMT], permissions: ['api', 'read', 'write'] }),
    user({ username: 'readonly', group: 'read', allowedFrom: [MGMT], permissions: ['read'] }),
  ];

  const dhcpScopes: NcmDhcpScope[] = [
    dhcp({
      name: 'lan', subnet: lan,
      poolFrom: `10.${o}.0.100`, poolTo: `10.${o}.0.200`,
      gateway: `10.${o}.0.1`,
      dnsServers: [`10.${o}.0.1`, '9.9.9.9'],
      domain: `${spec.name}.acme.lan`,
    }),
  ];

  const natRules: NcmNatRule[] = [nat({ slug: 'wan-nat', out: 'WAN' })];
  const vlans: NcmVlan[] = [];
  const ipsecPeers: NcmIpsecPeer[] = [];
  const qosRules: NcmQosRule[] = [];

  // ── profile B: voice VLAN + IPsec to HQ ─────────────────────────────────
  if (spec.profile === 'B') {
    const voice = `10.${o}.30.0/24`;
    interfaces.push(iface({
      name: 'vlan30', type: 'vlan', parent: 'bridge-lan',
      addresses: [{ cidr: `10.${o}.30.1/24`, originUnknown: false }],
      lists: ['VOICE'], mtu: 1500,
    }));
    vlans.push(vlan({ vlanId: 30, name: 'voice', taggedPorts: ['ether2'], untaggedPorts: ['ether3'] }));
    dhcpScopes.push(dhcp({
      name: 'voice', subnet: voice, onInterface: 'iface:vlan30',
      poolFrom: `10.${o}.30.50`, poolTo: `10.${o}.30.200`,
      gateway: `10.${o}.30.1`, dnsServers: [`10.${o}.0.1`],
      domain: `voice.${spec.name}.acme.lan`,
      options: [{ code: 66, value: `10.${o}.30.5` }],
    }));
    firewallRules.push(fw({
      slug: 'fw-voice', chain: 'forward', action: 'accept',
      match: { srcAddress: [`cidr:${voice}`], dstAddress: ['cidr:10.200.0.0/16'] },
    }));
    routes.push(route({ dst: '10.200.0.0/16', gateway: 'iface:ipsec-hq', distance: 1 }));
    ipsecPeers.push(ipsec({
      remote: `vpn-${spec.name}.acme.net`,
      localId: `${spec.name}@acme.net`,
      localSubnets: [lan, voice],
    }));
  }

  // ── profile C: second WAN, failover, QoS ────────────────────────────────
  if (spec.profile === 'C') {
    interfaces.push(iface({
      name: 'ether4', type: 'ethernet', lists: ['WAN2'],
      addresses: [{ cidr: `100.${o}.1.2/30`, originUnknown: false }], mtu: 1500,
    }));
    routes.push(route({ dst: '0.0.0.0/0', gateway: `ip:100.${o}.1.1`, distance: 20 }));
    natRules.push(nat({ slug: 'wan2-nat', out: 'WAN2' }));
    firewallRules.push(fw({
      slug: 'fw-out2', chain: 'forward', action: 'accept',
      match: { inInterface: ['iface:bridge-lan'], outInterface: ['ifaceList:WAN2'] },
    }));
    qosRules.push(qos({ name: 'wan-shape', maxLimitUpBps: 100_000_000, maxLimitDownBps: 500_000_000 }));
    qosRules.push(qos({ name: 'lan-shape', target: ['iface:bridge-lan'], maxLimitUpBps: 1_000_000_000 }));
  }

  // ── the local peculiarities ─────────────────────────────────────────────
  if (spec.quirks.supplierRule) {
    firewallRules.push(fw({
      slug: 'in-supplier', chain: 'input', action: 'accept',
      match: { protocol: 'tcp', srcAddress: [`cidr:${spec.quirks.supplierRule}`], dstPort: [[443, 443]] },
    }));
  }
  if (spec.quirks.extraRoute) {
    routes.push(route({ dst: spec.quirks.extraRoute, gateway: `ip:10.${o}.0.254` }));
  }

  return {
    ncmVersion: 1,
    semKeyGeneration: 1,
    normalizationEpoch: 'a1b2c3d4e5f60718',
    capturedAt: new Date('2026-08-20T09:00:00.000Z').toISOString(),
    device: {
      deviceId,
      brand: 'mikrotik',
      family: 'mikrotik_routeros7',
      model: spec.profile === 'C' ? 'CCR2004' : 'RB5009',
      serial: `SN${String(spec.index).padStart(8, '0')}`,
      systemIdentity: spec.name,
      pppUsername: spec.name,
      osVersion: '7.14.3',
    },
    coverage: coverage(),
    orderAnalysis: 'full',
    resources: {
      interfaces, vlans, routes, firewallRules, natRules,
      dhcpScopes, ipsecPeers, localUsers, services, qosRules,
      dhcpClients: [],
    },
    unmodeled: [],
    extensions: {},
  };
}
