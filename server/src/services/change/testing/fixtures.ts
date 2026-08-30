/**
 * ObliWAN M6 — fixtures shared by the change-queue verification scripts.
 *
 * A plausible CPE behind a CHR over L2TP, in the exact NCM shape the collector
 * produces, so the Management-Path Guard runs on a real document rather than on
 * a mock. The builders are deliberately the same shape as the ones in
 * `plan/testing/mgmtPathGuard.selftest.ts` — a second, divergent fixture set
 * would eventually prove the guard on a document the collector never emits.
 *
 * Test scaffolding. Never imported by the server at runtime; it lives under
 * `src/` only so `tsc` type-checks it.
 */

import type {
  NcmCoverageMap, NcmDocument, NcmFirewallRule, NcmInterface, NcmNatRule,
  NcmResourceKind, NcmRoute, NcmService, PlanOp,
} from '@obliwan/shared';
import { EMPTY_MATCH, NCM_RESOURCE_KINDS } from '@obliwan/shared';

export const CHR_ADDRESS = '10.255.0.1';
export const MGMT_ADDRESS = '10.255.1.5';
export const TUNNEL = 'l2tp-mgmt';

function coverage(): NcmCoverageMap {
  const out = {} as NcmCoverageMap;
  for (const kind of NCM_RESOURCE_KINDS) {
    (out as Record<string, unknown>)[kind] = {
      state: 'complete', via: 'routeros_api', reason: null, recordCount: 1,
    };
  }
  return out;
}

function iface(
  opts: Partial<NcmInterface> & { name: string; type: NcmInterface['type'] },
): NcmInterface {
  return {
    semKey: `if.v1:${opts.name}`,
    keyQuality: 'strong',
    managedBy: 'unknown',
    managedSlug: null,
    comment: null,
    disabled: false,
    via: 'routeros_api',
    kind: 'interface',
    alias: null,
    parent: null,
    mtu: null,
    addresses: [],
    lists: [],
    ...opts,
    zone: opts.zone ?? null,
  };
}

let ruleSeq = 0;

export function rule(opts: {
  slug: string;
  chain: NcmFirewallRule['chain'];
  action: NcmFirewallRule['action'];
  match?: Partial<NcmFirewallRule['match']>;
}): NcmFirewallRule {
  ruleSeq += 1;
  return {
    semKey: `fw.v1:${opts.chain}:${opts.slug}`,
    keyQuality: 'strong',
    managedBy: 'obliwan',
    managedSlug: opts.slug,
    comment: null,
    disabled: false,
    via: 'routeros_api',
    kind: 'firewallRule',
    chain: opts.chain,
    chainName: null,
    match: { ...EMPTY_MATCH, ...(opts.match ?? {}) },
    action: opts.action,
    jumpTarget: null,
    rejectWith: null,
    log: false,
    logPrefix: null,
    addToList: null,
    addToListTimeout: null,
    ordinal: ruleSeq,
    matchHash: String(ruleSeq).padStart(16, '0'),
  };
}

function natRule(): NcmNatRule {
  ruleSeq += 1;
  return {
    semKey: 'nat.v1:postrouting:wan-nat',
    keyQuality: 'strong',
    managedBy: 'obliwan',
    managedSlug: 'wan-nat',
    comment: null,
    disabled: false,
    via: 'routeros_api',
    kind: 'natRule',
    chain: 'postrouting',
    chainName: null,
    match: { ...EMPTY_MATCH, outInterface: ['ifaceList:WAN'] },
    action: 'masquerade',
    toAddresses: null,
    toPorts: null,
    ordinal: ruleSeq,
    matchHash: String(ruleSeq).padStart(16, '0'),
  };
}

function route(opts: { slug: string; dst: string; gateway: string | null }): NcmRoute {
  return {
    semKey: `rt.v1:${opts.slug}`,
    keyQuality: 'strong',
    managedBy: 'unknown',
    managedSlug: null,
    comment: null,
    disabled: false,
    via: 'routeros_api',
    kind: 'route',
    dst: opts.dst,
    gateway: opts.gateway,
    distance: 1,
    scope: null,
    targetScope: null,
    table: 'main',
    checkGateway: null,
    vrf: null,
  };
}

function service(opts: { name: NcmService['service']; port: number }): NcmService {
  return {
    semKey: `svc.v1:${opts.name}`,
    keyQuality: 'strong',
    managedBy: 'unknown',
    managedSlug: null,
    comment: null,
    disabled: false,
    via: 'routeros_api',
    kind: 'service',
    service: opts.name,
    rawName: null,
    enabled: true,
    port: opts.port,
    allowedFrom: ['any'],
    tlsRequired: null,
    certificate: null,
    version: null,
    communityFingerprint: null,
    communityIsWellKnown: null,
  };
}

/** The baseline CPE: management arrives on the tunnel and is accepted; the rest
 *  of the input chain is dropped. */
export function baseDoc(deviceId: number, identity: string, serial: string): NcmDocument {
  ruleSeq = 0;
  return {
    ncmVersion: 1,
    semKeyGeneration: 1,
    normalizationEpoch: '0000000000000000',
    capturedAt: '2026-08-29T09:00:00.000Z',
    device: {
      deviceId,
      brand: 'mikrotik',
      family: 'mikrotik_routeros7',
      model: 'hEX-S',
      serial,
      systemIdentity: identity,
      pppUsername: identity,
      osVersion: '7.14.3',
    },
    coverage: coverage(),
    orderAnalysis: 'full',
    unmodeled: [],
    extensions: {},
    resources: {
      interfaces: [
        iface({
          name: TUNNEL,
          type: 'l2tp',
          addresses: [{ cidr: `${MGMT_ADDRESS}/32`, originUnknown: false }],
          lists: ['MGMT'],
        }),
        iface({
          name: 'bridge-lan',
          type: 'bridge',
          addresses: [{ cidr: '192.168.10.1/24', originUnknown: false }],
          lists: ['LAN'],
        }),
        iface({
          name: 'ether1',
          type: 'ethernet',
          addresses: [{ cidr: '192.0.2.2/30', originUnknown: false }],
          lists: ['WAN'],
        }),
      ],
      vlans: [],
      routes: [
        route({ slug: 'to-chr', dst: '10.255.0.0/24', gateway: `iface:${TUNNEL}` }),
        route({ slug: 'default', dst: '0.0.0.0/0', gateway: 'ip:192.0.2.1' }),
      ],
      firewallRules: [
        rule({
          slug: 'established',
          chain: 'input',
          action: 'accept',
          match: { connectionState: ['established', 'related'] },
        }),
        rule({ slug: 'mgmt-in', chain: 'input', action: 'accept', match: { inInterface: [`iface:${TUNNEL}`] } }),
        rule({ slug: 'default-drop', chain: 'input', action: 'drop' }),
      ],
      natRules: [natRule()],
      dhcpScopes: [],
      ipsecPeers: [],
      localUsers: [],
      services: [service({ name: 'ssh', port: 22 }), service({ name: 'api', port: 8728 })],
      qosRules: [],
      dhcpClients: [],
    },
  };
}

let opSeq = 0;

/**
 * THE destructive op of the milestone recipe: `chain=input action=drop` placed
 * at the HEAD of the input chain, above the rule that accepts the tunnel.
 *
 * `ordinal: 0` is what puts it first, and being first is what makes it a
 * lockout instead of a dead rule below an accept.
 */
export function lockoutOps(): PlanOp[] {
  const dropRule = rule({ slug: 'lockout', chain: 'input', action: 'drop' });
  const create: PlanOp = {
    seq: (opSeq += 1),
    kind: 'create',
    resource: 'firewallRule',
    semKey: dropRule.semKey,
    risk: 'high',
    before: null,
    after: dropRule,
    fields: [],
    chain: null,
    targetIndex: null,
    dependsOn: [],
    blockedReason: null,
    reason: 'M6 destructive acceptance test: `chain=input action=drop`.',
    disruptive: true,
  };
  // A create alone APPENDS, and a drop below the tunnel accept is a dead rule.
  // The move is what makes it a lockout — and it is also why §4.5 exists: on
  // RouterOS the position IS the semantics.
  const move: PlanOp = {
    seq: (opSeq += 1),
    kind: 'move',
    resource: 'firewallRule',
    semKey: dropRule.semKey,
    risk: 'high',
    before: null,
    after: null,
    fields: [],
    chain: 'input',
    targetIndex: 0,
    dependsOn: [create.seq],
    blockedReason: null,
    reason: 'Move the drop to the head of the input chain — above the tunnel accept.',
    disruptive: true,
  };
  return [create, move];
}

/**
 * A provably harmless op: a COMMENT on a rule that already exists in the
 * observed document.
 *
 * It is built FROM the document on purpose. An op naming a `semKey` the
 * document does not contain makes `projectPlan` mark itself incomplete, and an
 * incomplete projection can never yield ACCEPT — correctly, but it would make
 * this fixture prove the wrong thing. A harmless plan has to be harmless AND
 * simulable.
 */
export function harmlessOp(doc: NcmDocument): PlanOp {
  opSeq += 1;
  const before = doc.resources.firewallRules.find((r) => r.semKey.endsWith(':default-drop'));
  if (!before) throw new Error('fixture: the baseline document has no default-drop rule');
  const after = { ...before, comment: 'reviewed 2026-08' };
  return {
    seq: opSeq,
    kind: 'update',
    resource: 'firewallRule',
    semKey: before.semKey,
    risk: 'low',
    before,
    after,
    fields: ['comment'],
    chain: null,
    targetIndex: null,
    dependsOn: [],
    blockedReason: null,
    reason: 'A comment. Nothing forwards differently.',
    disruptive: false,
  };
}
