/**
 * ObliWAN M6 / K2 — Management-Path Guard self-test.
 *
 * WHY THIS FILE EXISTS AND MUST NOT BE DELETED
 *
 * K2 is the only part of the write path that can be proved without hardware:
 * it is pure computation over two NCM documents. Everything else in M6 — the
 * dead-man, the rollback script, the reconnection on a fresh socket — needs a
 * router to be believed. This does not. So it is proved here, exhaustively,
 * and the milestone's honesty about what is TESTED versus what is merely
 * WRITTEN rests on the line this file draws.
 *
 * The property under test is asymmetric and the tests are written to catch the
 * dangerous direction only:
 *
 *   a false REJECT costs a meeting;
 *   a false ACCEPT costs a van, a customer outage, and the product's credibility.
 *
 * So every case that ends in ACCEPT is a case where ACCEPT is provably right,
 * and every case with a shred of doubt in it asserts NOT-ACCEPT. If you weaken
 * one of those assertions to make a change pass, you have not fixed a test, you
 * have removed the guard.
 *
 *   npx tsx src/services/plan/testing/mgmtPathGuard.selftest.ts
 *
 * No database, no network, no clock. Exits non-zero on the first failure count.
 */

import type {
  NcmCoverageMap, NcmDocument, NcmFirewallRule, NcmInterface, NcmNatRule,
  NcmResourceKind, NcmRoute, NcmService, PlanOp, Selector,
} from '@obliwan/shared';
import { EMPTY_MATCH, NCM_RESOURCE_KINDS } from '@obliwan/shared';
import { buildMgmtPathFacts, classifyResource } from '../riskScoring';
import {
  evaluateMgmtPath, guardPlan, projectPlan, blocksApply, toPlanVerdict,
  UNKNOWN_CHAIN_POLICY,
  type MgmtGuardResult, type MgmtGuardReasonCode,
} from '../mgmtPathGuard';
import {
  aggregateBlastRadius, blastRadiusForDevice, classifySafetyNet, describeBlastRadius,
  type BlastDeviceInput,
} from '../blastRadius.service';

// ============================================================================
// Harness
// ============================================================================

let passed = 0;
let failed = 0;
const failures: string[] = [];

function ok(label: string, cond: boolean, extra = ''): void {
  if (cond) { passed++; console.log(`  PASS  ${label}${extra ? ' — ' + extra : ''}`); }
  else { failed++; failures.push(label); console.log(`  FAIL  ${label}${extra ? ' — ' + extra : ''}`); }
}
function eq(label: string, a: unknown, b: unknown): void {
  ok(label, JSON.stringify(a) === JSON.stringify(b), `got ${JSON.stringify(a)} want ${JSON.stringify(b)}`);
}
function section(t: string): void { console.log(`\n=== ${t} ===`); }

function codes(r: MgmtGuardResult): MgmtGuardReasonCode[] {
  return r.reasons.map((x) => x.code);
}
function has(r: MgmtGuardResult, code: MgmtGuardReasonCode): boolean {
  return codes(r).includes(code);
}
function reasonFor(r: MgmtGuardResult, code: MgmtGuardReasonCode) {
  return r.reasons.find((x) => x.code === code) ?? null;
}

// ============================================================================
// Fixture builders — a plausible CPE behind a CHR over L2TP
// ============================================================================

const CHR = '10.255.0.1';          // the concentrator: source of the mgmt session
const MGMT = '10.255.1.5';         // devices.tunnel_ip
const TUNNEL = 'l2tp-mgmt';
const DEVICE_ID = 4242;

function coverage(overrides: Partial<Record<NcmResourceKind, NcmCoverageMap[keyof NcmCoverageMap]>> = {}): NcmCoverageMap {
  const out = {} as NcmCoverageMap;
  for (const kind of NCM_RESOURCE_KINDS) {
    (out as Record<string, unknown>)[kind] =
      overrides[kind] ?? { state: 'complete', via: 'routeros_api', reason: null, recordCount: 1 };
  }
  return out;
}

function iface(opts: Partial<NcmInterface> & { name: string; type: NcmInterface['type'] }): NcmInterface {
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
function rule(opts: {
  slug: string;
  chain: NcmFirewallRule['chain'];
  chainName?: string | null;
  action: NcmFirewallRule['action'];
  jumpTarget?: string | null;
  addToList?: string | null;
  disabled?: boolean;
  match?: Partial<NcmFirewallRule['match']>;
}): NcmFirewallRule {
  ruleSeq += 1;
  return {
    semKey: `fw.v1:${opts.chainName ?? opts.chain}:${opts.slug}`,
    keyQuality: 'strong',
    managedBy: 'obliwan',
    managedSlug: opts.slug,
    comment: null,
    disabled: opts.disabled ?? false,
    via: 'routeros_api',
    kind: 'firewallRule',
    chain: opts.chain,
    chainName: opts.chainName ?? null,
    match: { ...EMPTY_MATCH, ...(opts.match ?? {}) },
    action: opts.action,
    jumpTarget: opts.jumpTarget ?? null,
    rejectWith: null,
    log: false,
    logPrefix: null,
    addToList: opts.addToList ?? null,
    addToListTimeout: null,
    ordinal: ruleSeq,
    matchHash: String(ruleSeq).padStart(16, '0'),
  };
}

function natRule(opts: {
  slug: string;
  chain: NcmNatRule['chain'];
  action: NcmNatRule['action'];
  toAddresses?: Selector | null;
  match?: Partial<NcmNatRule['match']>;
}): NcmNatRule {
  ruleSeq += 1;
  return {
    semKey: `nat.v1:${opts.chain}:${opts.slug}`,
    keyQuality: 'strong',
    managedBy: 'obliwan',
    managedSlug: opts.slug,
    comment: null,
    disabled: false,
    via: 'routeros_api',
    kind: 'natRule',
    chain: opts.chain,
    chainName: null,
    match: { ...EMPTY_MATCH, ...(opts.match ?? {}) },
    action: opts.action,
    toAddresses: opts.toAddresses ?? null,
    toPorts: null,
    ordinal: ruleSeq,
    matchHash: String(ruleSeq).padStart(16, '0'),
  };
}

function route(opts: { slug: string; dst: string; gateway: string | null; distance?: number }): NcmRoute {
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
    distance: opts.distance ?? 1,
    scope: null,
    targetScope: null,
    table: 'main',
    checkGateway: null,
    vrf: null,
  };
}

function service(opts: {
  name: NcmService['service']; enabled: boolean; port: number; allowedFrom?: Selector;
}): NcmService {
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
    enabled: opts.enabled,
    port: opts.port,
    allowedFrom: opts.allowedFrom ?? ['any'],
    tlsRequired: null,
    certificate: null,
    version: null,
    communityFingerprint: null,
    communityIsWellKnown: null,
  };
}

/**
 * THE BASELINE DEVICE.
 *
 * A CPE reached over L2TP: the tunnel interface carries the management /32, the
 * input chain accepts established traffic and anything arriving on the tunnel,
 * then drops the rest. There is a specific route back to the concentrator AND a
 * default route out of the WAN — which is what makes the "delete the return
 * route" case interesting rather than trivial.
 */
function baseDoc(): NcmDocument {
  return {
    ncmVersion: 1,
    semKeyGeneration: 1,
    normalizationEpoch: '0000000000000000',
    capturedAt: '2026-08-29T09:00:00.000Z',
    device: {
      deviceId: DEVICE_ID,
      brand: 'mikrotik',
      family: 'mikrotik_routeros7',
      model: 'hEX-S',
      serial: 'HFX0TEST',
      systemIdentity: 'cpe-test',
      pppUsername: 'cpe-test',
      osVersion: '7.14.3',
    },
    coverage: coverage(),
    orderAnalysis: 'full',
    unmodeled: [],
    extensions: {},
    resources: {
      interfaces: [
        iface({ name: TUNNEL, type: 'l2tp', addresses: [{ cidr: `${MGMT}/32`, originUnknown: false }], lists: ['MGMT'] }),
        iface({ name: 'bridge-lan', type: 'bridge', addresses: [{ cidr: '192.168.10.1/24', originUnknown: false }], lists: ['LAN'] }),
        iface({ name: 'ether1', type: 'ethernet', addresses: [{ cidr: '192.0.2.2/30', originUnknown: false }], lists: ['WAN'] }),
      ],
      vlans: [],
      routes: [
        route({ slug: 'to-chr', dst: '10.255.0.0/24', gateway: `iface:${TUNNEL}` }),
        route({ slug: 'default', dst: '0.0.0.0/0', gateway: 'ip:192.0.2.1' }),
      ],
      firewallRules: [
        rule({ slug: 'established', chain: 'input', action: 'accept', match: { connectionState: ['established', 'related'] } }),
        rule({ slug: 'mgmt-in', chain: 'input', action: 'accept', match: { inInterface: [`iface:${TUNNEL}`] } }),
        rule({ slug: 'default-drop', chain: 'input', action: 'drop' }),
      ],
      natRules: [
        natRule({ slug: 'wan-nat', chain: 'postrouting', action: 'masquerade', match: { outInterface: ['ifaceList:WAN'] } }),
      ],
      dhcpScopes: [],
      ipsecPeers: [],
      localUsers: [],
      services: [
        service({ name: 'ssh', enabled: true, port: 22 }),
        service({ name: 'api', enabled: true, port: 8728 }),
      ],
      qosRules: [],
      dhcpClients: [],
    },
  };
}

function clone(doc: NcmDocument): NcmDocument {
  return JSON.parse(JSON.stringify(doc)) as NcmDocument;
}

const OBSERVED = baseDoc();
const FACTS = buildMgmtPathFacts(OBSERVED, { deviceId: DEVICE_ID, tunnelIp: MGMT });

/** Run the guard against a hand-built target. */
function run(target: NcmDocument, ops: readonly PlanOp[] = [], observed = OBSERVED): MgmtGuardResult {
  return evaluateMgmtPath({
    observed,
    target,
    facts: buildMgmtPathFacts(observed, { deviceId: DEVICE_ID, tunnelIp: MGMT }),
    peerAddress: CHR,
    ops,
    family: 'mikrotik_routeros7',
  });
}

let opSeq = 0;
function op(o: Partial<PlanOp> & { kind: PlanOp['kind']; resource: PlanOp['resource']; semKey: string }): PlanOp {
  return {
    seq: opSeq++,
    risk: 'high',
    before: null,
    after: null,
    fields: [],
    chain: null,
    targetIndex: null,
    dependsOn: [],
    blockedReason: null,
    reason: 'test fixture',
    disruptive: true,
    ...o,
  };
}

// ============================================================================
async function main(): Promise<void> {
  // ==========================================================================
  section('0. The baseline is sane — everything below is a delta against it');
  // ==========================================================================
  const identity = run(clone(OBSERVED));
  eq('an empty plan on a healthy device is ACCEPT', identity.verdict, 'ACCEPT');
  eq('  …and maps to the plan-level `accept`', identity.planVerdict, 'accept');
  ok('  …and does not block the apply', !blocksApply(identity.verdict));
  eq('  the guard identified the tunnel interface with certainty',
    [identity.analysed.tunnelInterface, identity.analysed.tunnelInterfaceCertain], [TUNNEL, true]);
  eq('  it probed the ports the box actually listens on', identity.analysed.ports, [22, 8728]);
  eq('  it ran 3 probes per port (new in, established in, reply out)',
    identity.probes.length, identity.analysed.ports.length * 3);
  ok('  every probe is accepted today AND after', identity.probes.every((p) => p.before === 'accept' && p.after === 'accept'));
  eq('  the return path is resolved through the tunnel', identity.routing.after.egress, TUNNEL);
  eq('  no reason at all', identity.reasons.length, 0);

  // ==========================================================================
  section('1. RECIPE — `chain=input action=drop` at the head of the chain');
  // ==========================================================================
  {
    const target = clone(OBSERVED);
    const killer = rule({ slug: 'kill', chain: 'input', action: 'drop' });
    target.resources.firewallRules.unshift(killer);
    const ops = [op({ kind: 'create', resource: 'firewallRule', semKey: killer.semKey, after: killer })];
    const r = run(target, ops);

    eq('a bare `chain=input action=drop` at the head is REJECTED', r.verdict, 'REJECT');
    eq('  …and vetoes the plan', r.planVerdict, 'veto');
    ok('  the reason is INPUT_DROP', has(r, 'INPUT_DROP'), codes(r).join(','));
    const why = reasonFor(r, 'INPUT_DROP');
    ok('  it names the rule in cause', why?.culprit?.semKey === killer.semKey, why?.culprit?.semKey ?? 'none');
    ok('  it names the plan operation in cause', why?.culprit?.opSeq === ops[0].seq, String(why?.culprit?.opSeq));
    ok('  the rule is spelled out for the operator',
      (why?.message ?? '').includes('chain=input action=drop'), why?.message ?? '');
    ok('  the message says the packet is accepted TODAY',
      (why?.message ?? '').includes('currently on the device'));
    eq('  the plan op is surfaced for the UI to highlight', r.culpritOpSeqs, [ops[0].seq]);
    ok('  every INBOUND probe flipped accept -> drop',
      r.probes.filter((p) => p.id.startsWith('in:')).every((p) => p.before === 'accept' && p.after === 'drop'));
    ok('  the reply leg is untouched — an `input` rule cannot deny an outbound packet',
      r.probes.filter((p) => p.id.startsWith('out:')).every((p) => p.after === 'accept'));
  }

  // ==========================================================================
  section('2. RECIPE — the same rule, with an accept for the CHR above it');
  // ==========================================================================
  {
    const target = clone(OBSERVED);
    const killer = rule({ slug: 'kill', chain: 'input', action: 'drop' });
    const savior = rule({ slug: 'allow-chr', chain: 'input', action: 'accept', match: { srcAddress: [`ip:${CHR}`] } });
    target.resources.firewallRules.unshift(killer);
    target.resources.firewallRules.unshift(savior);
    const r = run(target);
    eq('an accept for the CHR ABOVE the drop makes the same plan ACCEPT', r.verdict, 'ACCEPT');
    eq('  no reason is raised', r.reasons.length, 0);
    ok('  the inbound probes are accepted', r.probes.filter((p) => p.id.startsWith('in:')).every((p) => p.after === 'accept'));
  }
  {
    // …and the ORDER is what decides it: the same two rules the other way round.
    const target = clone(OBSERVED);
    const killer = rule({ slug: 'kill', chain: 'input', action: 'drop' });
    const savior = rule({ slug: 'allow-chr', chain: 'input', action: 'accept', match: { srcAddress: [`ip:${CHR}`] } });
    target.resources.firewallRules.unshift(savior);
    target.resources.firewallRules.unshift(killer);   // now FIRST
    const r = run(target);
    eq('with the drop first, the very same two rules are REJECTED', r.verdict, 'REJECT');
  }

  // ==========================================================================
  section('3. RECIPE — the return route disappears');
  // ==========================================================================
  {
    // The interesting version, and the one that actually happens: the specific
    // route is deleted and a DEFAULT ROUTE is still there, so a naive "is there
    // a route" test would say yes. The reply silently leaves through the WAN.
    const target = clone(OBSERVED);
    const gone = OBSERVED.resources.routes[0];
    target.resources.routes = target.resources.routes.filter((x) => x.semKey !== gone.semKey);
    const ops = [op({ kind: 'delete', resource: 'route', semKey: gone.semKey, before: gone })];
    const r = run(target, ops);
    eq('deleting the route to the CHR is REJECTED even though a default route remains', r.verdict, 'REJECT');
    ok('  the reason is NO_ROUTE', has(r, 'NO_ROUTE'), codes(r).join(','));
    ok('  the message explains the reply now leaves the WAN',
      (reasonFor(r, 'NO_ROUTE')?.message ?? '').includes('ether1'),
      reasonFor(r, 'NO_ROUTE')?.message ?? '');
    eq('  the egress moved off the tunnel', [r.routing.before.egress, r.routing.after.egress], [TUNNEL, 'ether1']);
  }
  {
    // The blunt version: nothing covers the CHR any more.
    const observed = clone(OBSERVED);
    observed.resources.routes = [observed.resources.routes[0]];   // only the /24
    const target = clone(observed);
    target.resources.routes = [];
    const r = run(target, [], observed);
    eq('with no route left at all, NO_ROUTE and REJECT', r.verdict, 'REJECT');
    ok('  the reason is NO_ROUTE', has(r, 'NO_ROUTE'), codes(r).join(','));
    eq('  the state degrades ok -> none', [r.routing.before.state, r.routing.after.state], ['ok', 'none']);
  }
  {
    // …and a blackhole is a cut, not an absence.
    const target = clone(OBSERVED);
    target.resources.routes[0] = { ...target.resources.routes[0], gateway: null };
    const r = run(target);
    eq('turning the return route into a blackhole is REJECTED', r.verdict, 'REJECT');
    ok('  the reason is NO_ROUTE', has(r, 'NO_ROUTE'), codes(r).join(','));
  }

  // ==========================================================================
  section('4. RECIPE — the tunnel interface is disabled');
  // ==========================================================================
  {
    const disableOp = op({
      kind: 'disable', resource: 'interface', semKey: `if.v1:${TUNNEL}`,
      before: OBSERVED.resources.interfaces[0],
    });
    const r = guardPlan({
      observed: OBSERVED, ops: [disableOp], facts: FACTS,
      peerAddress: CHR, family: 'mikrotik_routeros7',
    });
    eq('disabling the tunnel interface is REJECTED', r.verdict, 'REJECT');
    ok('  the reason is TUNNEL_CRITICAL', has(r, 'TUNNEL_CRITICAL'), codes(r).join(','));
    ok('  it names the interface', (reasonFor(r, 'TUNNEL_CRITICAL')?.message ?? '').includes(TUNNEL));
    ok('  the route through it is reported dead too', has(r, 'NO_ROUTE'), codes(r).join(','));
    ok('  the projection of a `disable` op is complete', r.projection.complete);
  }
  {
    // Deleting it outright is the same verdict by a different route.
    const target = clone(OBSERVED);
    target.resources.interfaces = target.resources.interfaces.filter((i) => i.name !== TUNNEL);
    const r = run(target);
    eq('deleting the tunnel interface is REJECTED', r.verdict, 'REJECT');
    ok('  the reason is TUNNEL_CRITICAL', has(r, 'TUNNEL_CRITICAL'), codes(r).join(','));
  }

  // ==========================================================================
  section('5. THE ONE THAT MATTERS MOST — INDETERMINATE is never ACCEPT');
  // ==========================================================================
  {
    // A plan that is harmless by every other measure, on a document whose
    // firewall was only partly read.
    const observed = clone(OBSERVED);
    observed.coverage.firewallRule = {
      state: 'partial', via: 'ssh', reason: '/export truncated at 500 lines', recordCount: 3,
    };
    const target = clone(observed);
    const r = run(target, [], observed);
    eq('coverage: partial makes an otherwise-clean plan INDETERMINATE', r.verdict, 'INDETERMINATE');
    ok('  it is NOT accept', r.verdict !== ('ACCEPT' as string));
    ok('  the reason is COVERAGE_INCOMPLETE', has(r, 'COVERAGE_INCOMPLETE'), codes(r).join(','));
    ok('  the collector\'s own reason is quoted verbatim to the operator',
      (reasonFor(r, 'COVERAGE_INCOMPLETE')?.message ?? '').includes('/export truncated'));
    ok('  every probe still says accept — the walk agreed, the guard still refused',
      r.probes.every((p) => p.after === 'accept'));
    eq('  the plan verdict is the fail-closed one', r.planVerdict, 'indeterminate');
    ok('  and it blocks the apply', blocksApply(r.verdict));
  }
  {
    const observed = clone(OBSERVED);
    observed.unmodeled = [{ section: '/routing/ospf', lineCount: 22, forwardingRelevant: true }];
    const r = run(clone(observed), [], observed);
    eq('a forwarding-relevant unmodeled section makes it INDETERMINATE', r.verdict, 'INDETERMINATE');
    ok('  the reason names the section',
      (reasonFor(r, 'UNMODELED_FORWARDING_SECTION')?.message ?? '').includes('/routing/ospf'));
  }
  {
    const observed = clone(OBSERVED);
    observed.unmodeled = [{ section: '/system/note', lineCount: 3, forwardingRelevant: false }];
    const r = run(clone(observed), [], observed);
    eq('an unmodeled section that CANNOT affect forwarding does not blind the guard', r.verdict, 'ACCEPT');
  }
  {
    const observed = clone(OBSERVED);
    observed.orderAnalysis = 'partial';
    const r = run(clone(observed), [], observed);
    eq('orderAnalysis: partial makes it INDETERMINATE', r.verdict, 'INDETERMINATE');
    ok('  the reason is ORDER_ANALYSIS_PARTIAL', has(r, 'ORDER_ANALYSIS_PARTIAL'), codes(r).join(','));
  }
  {
    const observed = clone(OBSERVED);
    observed.orderAnalysis = 'skipped';
    const r = run(clone(observed), [], observed);
    eq('orderAnalysis: skipped is treated the same way', r.verdict, 'INDETERMINATE');
  }

  // ==========================================================================
  section('6. RECIPE — an unmodelled selector on the analysed path');
  // ==========================================================================
  {
    const target = clone(OBSERVED);
    const opaque = rule({
      slug: 'l7', chain: 'input', action: 'drop',
      match: { unmodeledMatch: ['layer7-protocol=teamviewer'] },
    });
    target.resources.firewallRules.unshift(opaque);
    const r = run(target, [op({ kind: 'create', resource: 'firewallRule', semKey: opaque.semKey, after: opaque })]);
    eq('a drop carrying an unread selector, above the mgmt accept, is INDETERMINATE', r.verdict, 'INDETERMINATE');
    ok('  NOT accept', r.verdict !== ('ACCEPT' as string));
    ok('  NOT silently ignored either', r.verdict !== ('REJECT' as string));
    ok('  the reason is UNMODELED_MATCH', has(r, 'UNMODELED_MATCH'), codes(r).join(','));
    ok('  it names the rule and the plan line',
      reasonFor(r, 'UNMODELED_MATCH')?.culprit?.semKey === opaque.semKey &&
      reasonFor(r, 'UNMODELED_MATCH')?.culprit?.opSeq !== null);
    ok('  the probes report `unknown`, not a guess',
      r.probes.filter((p) => p.id.startsWith('in:')).every((p) => p.after === 'unknown'));
  }
  {
    // An unread selector on an ACCEPT that lets the packet through is still a
    // path we did not prove.
    const target = clone(OBSERVED);
    const opaque = rule({
      slug: 'l7ok', chain: 'input', action: 'log',
      match: { unmodeledMatch: ['ipv4-options=any'] },
    });
    target.resources.firewallRules.unshift(opaque);
    const r = run(target);
    eq('an unread selector on a non-deciding rule on the path still blinds the guard', r.verdict, 'INDETERMINATE');
    ok('  the reason is UNMODELED_MATCH', has(r, 'UNMODELED_MATCH'), codes(r).join(','));
  }
  {
    // …but one that is provably OFF the path is not our problem.
    const target = clone(OBSERVED);
    target.resources.firewallRules.unshift(rule({
      slug: 'l7-lan', chain: 'input', action: 'drop',
      match: { unmodeledMatch: ['layer7-protocol=bittorrent'], inInterface: ['iface:bridge-lan'] },
    }));
    const r = run(target);
    eq('an unread selector on a rule that provably cannot match the probe is ignored', r.verdict, 'ACCEPT');
  }

  // ==========================================================================
  section('7. RECIPE — a harmless plan really is ACCEPT');
  // ==========================================================================
  {
    const target = clone(OBSERVED);
    const harmless = rule({
      slug: 'seen-list', chain: 'input', action: 'addToList', addToList: 'seen-sources',
    });
    target.resources.firewallRules.unshift(harmless);   // at the HEAD, and matching everything
    const r = run(target, [op({ kind: 'create', resource: 'firewallRule', semKey: harmless.semKey, after: harmless, risk: 'low' })]);
    eq('adding an address-list rule at the head of the input chain is ACCEPT', r.verdict, 'ACCEPT');
    eq('  with no reason to show', r.reasons.length, 0);
    ok('  the summary says so plainly', r.summary.startsWith('Management-Path Guard: ACCEPT'), r.summary);
  }
  {
    // Deleting the established/related accept while the interface accept stays
    // is safe, and the guard must not cry wolf about it.
    const target = clone(OBSERVED);
    target.resources.firewallRules = target.resources.firewallRules.filter((x) => x.managedSlug !== 'established');
    const r = run(target);
    eq('removing the established accept while the tunnel accept remains is ACCEPT', r.verdict, 'ACCEPT');
  }
  {
    // Removing BOTH is the classic self-inflicted lockout.
    const target = clone(OBSERVED);
    target.resources.firewallRules = target.resources.firewallRules.filter((x) => x.action !== 'accept');
    const r = run(target);
    eq('removing every accept leaves the default drop and is REJECTED', r.verdict, 'REJECT');
    ok('  the culprit is the default-drop rule',
      reasonFor(r, 'INPUT_DROP')?.culprit?.semKey.includes('default-drop') === true,
      reasonFor(r, 'INPUT_DROP')?.culprit?.semKey ?? 'none');
  }

  // ==========================================================================
  section('8. RECIPE — a reordering that puts a drop above an accept');
  // ==========================================================================
  {
    const drop = OBSERVED.resources.firewallRules[2];
    const moveOp = op({
      kind: 'move', resource: 'firewallRule', semKey: drop.semKey,
      before: drop, after: drop, chain: 'input', targetIndex: 0, fields: ['position'],
    });
    const projected = projectPlan(OBSERVED, [moveOp]);
    eq('the projection moves the rule to the head of its chain',
      projected.doc.resources.firewallRules.map((x) => x.managedSlug),
      ['default-drop', 'established', 'mgmt-in']);
    ok('  and reports itself complete', projected.complete);

    const r = guardPlan({
      observed: OBSERVED, ops: [moveOp], facts: FACTS,
      peerAddress: CHR, family: 'mikrotik_routeros7',
    });
    eq('reordering the default drop above the accepts is REJECTED', r.verdict, 'REJECT');
    ok('  the reason is INPUT_DROP', has(r, 'INPUT_DROP'), codes(r).join(','));
    ok('  the move operation is named', reasonFor(r, 'INPUT_DROP')?.culprit?.opKind === 'move');
    eq('  the op is surfaced', r.culpritOpSeqs, [moveOp.seq]);
  }
  {
    // A reorder that crosses nothing decisive must NOT be refused: the whole
    // anti-noise argument of §4.4 depends on this staying quiet.
    const est = OBSERVED.resources.firewallRules[0];
    const moveOp = op({
      kind: 'move', resource: 'firewallRule', semKey: est.semKey,
      before: est, after: est, chain: 'input', targetIndex: 1, fields: ['position'],
    });
    const r = guardPlan({
      observed: OBSERVED, ops: [moveOp], facts: FACTS,
      peerAddress: CHR, family: 'mikrotik_routeros7',
    });
    eq('swapping the two accepts changes nothing and is ACCEPT', r.verdict, 'ACCEPT');
  }

  // ==========================================================================
  section('9. Custom chains, jumps, and the walk\'s own safety');
  // ==========================================================================
  {
    const target = clone(OBSERVED);
    target.resources.firewallRules = [
      rule({ slug: 'to-mgmt-chain', chain: 'input', action: 'jump', jumpTarget: 'mgmt' }),
      rule({ slug: 'chain-drop', chain: 'custom', chainName: 'mgmt', action: 'drop', match: { srcAddress: [`cidr:${CHR}/32`] } }),
      ...OBSERVED.resources.firewallRules,
    ];
    const r = run(target);
    eq('a drop hidden inside a chain the input chain jumps into is REJECTED', r.verdict, 'REJECT');
    eq('  and the culprit is the rule INSIDE the custom chain',
      reasonFor(r, 'INPUT_DROP')?.culprit?.chain, 'mgmt');
  }
  {
    const target = clone(OBSERVED);
    target.resources.firewallRules = [
      rule({ slug: 'to-mgmt-chain', chain: 'input', action: 'jump', jumpTarget: 'mgmt' }),
      rule({ slug: 'chain-drop-lan', chain: 'custom', chainName: 'mgmt', action: 'drop', match: { srcAddress: ['cidr:192.168.0.0/16'] } }),
      ...OBSERVED.resources.firewallRules,
    ];
    const r = run(target);
    eq('a jump into a chain that does not match falls back through and is ACCEPT', r.verdict, 'ACCEPT');
  }
  {
    const target = clone(OBSERVED);
    target.resources.firewallRules = [
      rule({ slug: 'a', chain: 'input', action: 'jump', jumpTarget: 'loop-a' }),
      rule({ slug: 'b', chain: 'custom', chainName: 'loop-a', action: 'jump', jumpTarget: 'loop-b' }),
      rule({ slug: 'c', chain: 'custom', chainName: 'loop-b', action: 'jump', jumpTarget: 'loop-a' }),
      ...OBSERVED.resources.firewallRules,
    ];
    const started = Date.now();
    const r = run(target);
    ok('a jump cycle terminates instead of hanging', Date.now() - started < 2000, `${Date.now() - started} ms`);
    ok('  …and yields a non-ACCEPT verdict', r.verdict !== ('ACCEPT' as string), r.verdict);
  }
  {
    const target = clone(OBSERVED);
    target.resources.firewallRules.unshift(
      rule({ slug: 'weird', chain: 'input', action: 'other' }),
    );
    const r = run(target);
    eq('an action the model does not understand blinds the guard', r.verdict, 'INDETERMINATE');
    ok('  the reason is UNKNOWN_ACTION', has(r, 'UNKNOWN_ACTION'), codes(r).join(','));
  }
  {
    const target = clone(OBSERVED);
    target.resources.firewallRules[2] = { ...target.resources.firewallRules[2], disabled: true };
    target.resources.firewallRules.unshift(
      rule({ slug: 'disabled-kill', chain: 'input', action: 'drop', disabled: true }),
    );
    const r = run(target);
    eq('a DISABLED drop decides nothing', r.verdict, 'ACCEPT');
  }

  // ==========================================================================
  section('10. The other four lockout motifs');
  // ==========================================================================
  {
    const target = clone(OBSERVED);
    target.resources.interfaces[0] = { ...target.resources.interfaces[0], addresses: [] };
    const r = run(target);
    eq('losing the management address is REJECTED', r.verdict, 'REJECT');
    ok('  the reason is MGMT_ADDRESS_LOST', has(r, 'MGMT_ADDRESS_LOST'), codes(r).join(','));
  }
  {
    const target = clone(OBSERVED);
    target.resources.services = target.resources.services.map((s) => ({ ...s, enabled: false }));
    const r = run(target);
    eq('disabling every management service is REJECTED', r.verdict, 'REJECT');
    ok('  the reason is MGMT_SERVICE_LOST', has(r, 'MGMT_SERVICE_LOST'), codes(r).join(','));
  }
  {
    const target = clone(OBSERVED);
    target.resources.services = target.resources.services.map((s) => ({ ...s, allowedFrom: ['cidr:192.168.10.0/24'] }));
    const r = run(target);
    eq('restricting `/ip/service address=` to a subnet that excludes the CHR is REJECTED', r.verdict, 'REJECT');
    ok('  the reason is MGMT_SERVICE_LOST', has(r, 'MGMT_SERVICE_LOST'), codes(r).join(','));
  }
  {
    const target = clone(OBSERVED);
    target.resources.services = target.resources.services.map((s) => ({ ...s, allowedFrom: ['ref:MGMT-ALLOWED'] }));
    const r = run(target);
    eq('an address LIST we cannot expand is INDETERMINATE, not ACCEPT', r.verdict, 'INDETERMINATE');
    ok('  the guard refuses to assume the list still contains us',
      (reasonFor(r, 'AMBIGUOUS_RULE')?.message ?? '').includes('will not assume'),
      reasonFor(r, 'AMBIGUOUS_RULE')?.message ?? codes(r).join(','));
  }
  {
    const target = clone(OBSERVED);
    target.resources.natRules.unshift(natRule({
      slug: 'steal', chain: 'prerouting', action: 'dstnat',
      toAddresses: ['ip:192.168.10.50'],
      match: { dstAddress: [`ip:${MGMT}`], protocol: 'tcp' },
    }));
    const r = run(target);
    eq('a prerouting dst-nat that captures the management address is REJECTED', r.verdict, 'REJECT');
    ok('  the reason is NAT_HIJACK', has(r, 'NAT_HIJACK'), codes(r).join(','));
  }
  {
    const target = clone(OBSERVED);
    target.resources.natRules.unshift(natRule({
      slug: 'dns', chain: 'prerouting', action: 'redirect',
      match: { dstPort: [[53, 53]], protocol: 'udp' },
    }));
    const r = run(target);
    eq('the ordinary DNS-redirect idiom is NOT a hijack', r.verdict, 'ACCEPT');
  }

  // ==========================================================================
  section('11. Proof beats blindness; blindness never beats a proof');
  // ==========================================================================
  {
    const observed = clone(OBSERVED);
    observed.coverage.firewallRule = { state: 'partial', via: 'ssh', reason: 'truncated', recordCount: 3 };
    const target = clone(observed);
    target.resources.firewallRules.unshift(rule({ slug: 'kill', chain: 'input', action: 'drop' }));
    const r = run(target, [], observed);
    eq('a proven drop on a partially-read document is still a REJECT', r.verdict, 'REJECT');
    ok('  and the blindness is still reported alongside it',
      has(r, 'COVERAGE_INCOMPLETE') && has(r, 'INPUT_DROP'), codes(r).join(','));
    eq('  proofs are listed before blind spots', r.reasons[0].effect, 'reject');
  }
  {
    const observed = clone(OBSERVED);
    observed.resources.firewallRules.unshift(rule({ slug: 'already-dead', chain: 'input', action: 'drop' }));
    const r = run(clone(observed), [], observed);
    eq('a model that says we cannot reach a device we ARE reaching refuses to conclude', r.verdict, 'INDETERMINATE');
    ok('  the reason is BASELINE_CONTRADICTION', has(r, 'BASELINE_CONTRADICTION'), codes(r).join(','));
    ok('  …and the plan is NOT blamed for a cut that pre-dates it', !has(r, 'INPUT_DROP'), codes(r).join(','));
  }
  {
    // The anti-noise counterpart, and it matters as much as the guard itself:
    // a management service that is enabled but already firewalled off is a
    // service nobody administers through. Its fate is not a regression, and
    // reporting it as one would flood the operator with refusals about
    // sessions that do not exist.
    const observed = clone(OBSERVED);
    observed.resources.firewallRules.unshift(rule({
      slug: 'no-ssh-from-wan', chain: 'input', action: 'drop',
      match: { protocol: 'tcp', dstPort: [[22, 22]] },
    }));
    const r = run(clone(observed), [], observed);
    eq('one management port closed today, another open: the guard stays quiet', r.verdict, 'ACCEPT');
    eq('  the probes report the truth on both ports',
      r.probes.filter((p) => p.id.startsWith('in:new')).map((p) => `${p.id}=${p.before}`),
      ['in:new:tcp/22=drop', 'in:new:tcp/8728=accept']);

    // …but closing the port that IS in use is still caught.
    const target = clone(observed);
    target.resources.firewallRules.unshift(rule({
      slug: 'no-api', chain: 'input', action: 'drop',
      match: { protocol: 'tcp', dstPort: [[8728, 8728]] },
    }));
    const r2 = run(target, [], observed);
    eq('closing the port that IS in use is REJECTED', r2.verdict, 'REJECT');
    ok('  and only the port in use is blamed',
      (reasonFor(r2, 'INPUT_DROP')?.message ?? '').includes('8728'),
      reasonFor(r2, 'INPUT_DROP')?.message ?? '');
  }

  // ==========================================================================
  section('12. Missing coordinates — the guard cannot probe what it cannot address');
  // ==========================================================================
  {
    const r = evaluateMgmtPath({
      observed: OBSERVED, target: clone(OBSERVED), facts: FACTS,
      peerAddress: null, family: 'mikrotik_routeros7',
    });
    eq('no concentrator address -> INDETERMINATE', r.verdict, 'INDETERMINATE');
    ok('  the reason is PEER_ADDRESS_UNKNOWN', has(r, 'PEER_ADDRESS_UNKNOWN'), codes(r).join(','));
    eq('  and nothing was probed', r.probes.length, 0);
  }
  {
    const facts = buildMgmtPathFacts(OBSERVED, { deviceId: DEVICE_ID, tunnelIp: null });
    const r = evaluateMgmtPath({
      observed: OBSERVED, target: clone(OBSERVED), facts,
      peerAddress: CHR, family: 'mikrotik_routeros7',
    });
    eq('no management address -> INDETERMINATE', r.verdict, 'INDETERMINATE');
    ok('  the reason is MGMT_ADDRESS_UNKNOWN', has(r, 'MGMT_ADDRESS_UNKNOWN'), codes(r).join(','));
  }
  {
    const observed = clone(OBSERVED);
    observed.resources.interfaces = observed.resources.interfaces.filter((i) => i.type !== 'l2tp');
    const facts = buildMgmtPathFacts(observed, { deviceId: DEVICE_ID, tunnelIp: MGMT });
    const r = evaluateMgmtPath({
      observed, target: clone(observed), facts, peerAddress: CHR, family: 'mikrotik_routeros7',
    });
    eq('no identifiable tunnel interface -> INDETERMINATE', r.verdict, 'INDETERMINATE');
    ok('  the reason is TUNNEL_UNKNOWN', has(r, 'TUNNEL_UNKNOWN'), codes(r).join(','));
  }

  // ==========================================================================
  section('13. Brands with no modelled default policy (A2 / §8.3 honesty)');
  // ==========================================================================
  {
    const observed = clone(OBSERVED);
    observed.device.brand = 'draytek';
    observed.device.family = 'draytek_vigor';
    // No rule accepts the probe explicitly: the fate depends on a zone default
    // this product has never seen on real hardware.
    observed.resources.firewallRules = [];
    const r = evaluateMgmtPath({
      observed, target: clone(observed),
      facts: buildMgmtPathFacts(observed, { deviceId: DEVICE_ID, tunnelIp: MGMT }),
      peerAddress: CHR, family: 'draytek_vigor',
    });
    eq('on a brand whose chain policy is unmodelled, silence is INDETERMINATE', r.verdict, 'INDETERMINATE');
    ok('  the reason is CHAIN_POLICY_UNKNOWN', has(r, 'CHAIN_POLICY_UNKNOWN'), codes(r).join(','));
    eq('  the policy shown to the operator is honest', r.analysed.chainPolicy, UNKNOWN_CHAIN_POLICY);
  }
  {
    const observed = clone(OBSERVED);
    observed.resources.firewallRules = [
      rule({ slug: 'zone-kill', chain: 'input', action: 'drop', match: { srcAddress: [`ip:${CHR}`] } }),
    ];
    const r = evaluateMgmtPath({
      observed: clone(OBSERVED), target: observed,
      facts: FACTS, peerAddress: CHR, family: 'sonicwall_sonicos',
    });
    eq('…but a PROVEN drop is proven on any brand', r.verdict, 'REJECT');
  }

  // ==========================================================================
  section('14. `projectPlan` — the target document really is the post-state');
  // ==========================================================================
  {
    const created = rule({ slug: 'new', chain: 'input', action: 'accept' });
    const p = projectPlan(OBSERVED, [
      op({ kind: 'create', resource: 'firewallRule', semKey: created.semKey, after: created }),
      op({ kind: 'move', resource: 'firewallRule', semKey: created.semKey, chain: 'input', targetIndex: 0 }),
    ]);
    eq('create then move lands the rule at the head of its chain',
      p.doc.resources.firewallRules.map((x) => x.managedSlug),
      ['new', 'established', 'mgmt-in', 'default-drop']);
    ok('  the observed document was not mutated',
      OBSERVED.resources.firewallRules.length === 3);
    ok('  the projection is complete', p.complete);
  }
  {
    const p = projectPlan(OBSERVED, [
      op({ kind: 'delete', resource: 'firewallRule', semKey: 'fw.v1:input:does-not-exist' }),
    ]);
    ok('deleting a record that is not there marks the projection INCOMPLETE', !p.complete);
    ok('  and says why', p.warnings.some((w) => w.includes('absent from the observed document')), p.warnings.join(' | '));
    const r = evaluateMgmtPath({
      observed: OBSERVED, target: p.doc, facts: FACTS, peerAddress: CHR,
      family: 'mikrotik_routeros7', projectionComplete: p.complete,
    });
    eq('  and an incomplete projection can never yield ACCEPT', r.verdict, 'INDETERMINATE');
    ok('  the reason is PROJECTION_INCOMPLETE', has(r, 'PROJECTION_INCOMPLETE'), codes(r).join(','));
  }
  {
    const p = projectPlan(OBSERVED, [
      op({ kind: 'blocked', resource: 'firewallRule', semKey: 'fw.v1:input:x', blockedReason: 'coverage_incomplete' }),
    ]);
    ok('a `blocked` op changes nothing but is reported', p.complete && p.warnings.length === 1, p.warnings.join('|'));
  }
  {
    // A move must not disturb the relative order of the OTHER chains that share
    // the array — that is what makes a per-chain targetIndex meaningful at all.
    const observed = clone(OBSERVED);
    observed.resources.firewallRules = [
      rule({ slug: 'fwd-a', chain: 'forward', action: 'accept' }),
      ...observed.resources.firewallRules,
      rule({ slug: 'fwd-b', chain: 'forward', action: 'drop' }),
    ];
    const drop = observed.resources.firewallRules.find((x) => x.managedSlug === 'default-drop')!;
    const p = projectPlan(observed, [
      op({ kind: 'move', resource: 'firewallRule', semKey: drop.semKey, chain: 'input', targetIndex: 0 }),
    ]);
    eq('a move inside `input` leaves the `forward` rules where they were',
      p.doc.resources.firewallRules.map((x) => x.managedSlug),
      ['fwd-a', 'default-drop', 'established', 'mgmt-in', 'fwd-b']);
  }

  // ==========================================================================
  section('15. riskScoring — the two families M6 adds to `tunnelCritical`');
  // ==========================================================================
  {
    const hijack = natRule({
      slug: 'steal', chain: 'prerouting', action: 'dstnat',
      match: { dstAddress: [`ip:${MGMT}`] },
    });
    const v = classifyResource(hijack, FACTS);
    ok('a prerouting dst-nat on the management address is tunnelCritical', v.tunnelCritical, v.signals.join(','));
    ok('  with the `natHijack` signal', v.signals.includes('natHijack'), v.signals.join(','));
  }
  {
    const dns = natRule({
      slug: 'dns', chain: 'prerouting', action: 'redirect',
      match: { dstPort: [[53, 53]], protocol: 'udp' },
    });
    ok('the DNS-redirect idiom is NOT flagged as a hijack',
      !classifyResource(dns, FACTS).signals.includes('natHijack'),
      classifyResource(dns, FACTS).signals.join(','));
  }
  {
    const masq = OBSERVED.resources.natRules[0];
    ok('a srcnat masquerade on the WAN list is still NOT tunnelCritical (M5 behaviour preserved)',
      classifyResource(masq, FACTS).tunnelCritical === false,
      classifyResource(masq, FACTS).signals.join(','));
  }
  {
    const v = classifyResource(OBSERVED.resources.interfaces[0], FACTS);
    ok('the interface carrying the management address raises `managementAddress`',
      v.signals.includes('managementAddress'), v.signals.join(','));
    const lan = classifyResource(OBSERVED.resources.interfaces[1], FACTS);
    ok('a LAN bridge does not', !lan.signals.includes('managementAddress'), lan.signals.join(','));
  }
  {
    const fwd = rule({ slug: 'lan-to-cpe', chain: 'forward', action: 'drop', match: { dstAddress: [`ip:${MGMT}`] } });
    const v = classifyResource(fwd, FACTS);
    ok('a FORWARD rule that names the management address is tunnelCritical', v.tunnelCritical, v.signals.join(','));
    const other = rule({ slug: 'lan-out', chain: 'forward', action: 'drop', match: { dstAddress: ['cidr:198.51.100.0/24'] } });
    ok('a forward rule about somebody else is not',
      classifyResource(other, FACTS).tunnelCritical === false,
      classifyResource(other, FACTS).signals.join(','));
  }

  // ==========================================================================
  section('16. blastRadius — sites first, DEGRADED last');
  // ==========================================================================
  {
    eq('MikroTik is ARMED', classifySafetyNet({ brand: 'mikrotik' }), 'ARMED');
    eq('a DrayTek with a MikroTik on site is ARMED_BY_PEER',
      classifySafetyNet({ brand: 'draytek', hasColocatedMikrotik: true }), 'ARMED_BY_PEER');
    eq('a DrayTek alone is DEGRADED — no dead-man is claimed where none exists',
      classifySafetyNet({ brand: 'draytek' }), 'DEGRADED');
    eq('same for Zyxel', classifySafetyNet({ brand: 'zyxel' }), 'DEGRADED');
    eq('same for SonicWall', classifySafetyNet({ brand: 'sonicwall' }), 'DEGRADED');
  }
  {
    const killer = rule({ slug: 'kill', chain: 'input', action: 'drop' });
    const mk = (id: number, site: number | null, brand: string, verdict: 'ACCEPT' | 'REJECT' | null): BlastDeviceInput => ({
      deviceId: id,
      deviceName: `cpe-${id}`,
      siteId: site,
      siteName: site === null ? null : `site-${site}`,
      brand,
      ops: [
        op({ kind: 'create', resource: 'firewallRule', semKey: `${killer.semKey}:${id}`, after: killer, risk: 'high' }),
        op({ kind: 'blocked', resource: 'route', semKey: `rt.v1:x${id}`, risk: 'low', blockedReason: 'coverage_incomplete' }),
      ],
      riskLevel: 'high',
      guardVerdict: verdict,
    });

    const agg = aggregateBlastRadius([
      mk(1, 10, 'mikrotik', 'ACCEPT'),
      mk(2, 10, 'mikrotik', 'REJECT'),
      mk(3, 11, 'draytek', null),
      mk(4, null, 'mikrotik', 'ACCEPT'),
    ]);

    eq('four devices', agg.deviceCount, 4);
    eq('two sites — the number a customer count is read off', agg.siteCount, 2);
    eq('the device with no site is counted apart, not folded into zero', agg.unassignedDeviceCount, 1);
    eq('site 10 carries two devices', agg.sites.find((s) => s.siteId === 10)?.deviceCount, 2);
    eq('blocked ops do not count as changes', [agg.changeOpCount, agg.blockedOpCount], [4, 4]);
    eq('the safety-net census is exact',
      agg.bySafetyNet, { ARMED: 3, ARMED_BY_PEER: 0, DEGRADED: 1 });
    eq('the guard census counts a device never analysed as NOT_RUN',
      agg.byGuardVerdict, { ACCEPT: 2, REJECT: 1, INDETERMINATE: 0, NOT_RUN: 1 });
    eq('the devices the guard did not clear are named, not counted',
      agg.guardNotClearedDeviceIds, [2, 3]);
    eq('the DEGRADED device is scheduled LAST in the wave order (§8.3)',
      agg.waveOrder[agg.waveOrder.length - 1], 3);
    ok('an explicit confirmation is required', agg.requiresExplicitConfirmation);
    ok('the sentence leads with devices and sites',
      describeBlastRadius(agg).startsWith('4 devices, 2 sites'), describeBlastRadius(agg));
    ok('…and it says what is not covered',
      describeBlastRadius(agg).includes('NO remote recovery'), describeBlastRadius(agg));
  }
  {
    const one = blastRadiusForDevice({
      deviceId: 7, deviceName: 'cpe-7', siteId: 3, brand: 'mikrotik',
      ops: [op({
        kind: 'update', resource: 'route', semKey: 'rt.v1:to-chr', risk: 'high',
        before: OBSERVED.resources.routes[0],
        after: { ...OBSERVED.resources.routes[0], gateway: 'iface:ether1' },
      })],
    });
    eq('a route op reports both the subnet and both gateway interfaces',
      [one.affectedSubnets, one.affectedInterfaces],
      [['10.255.0.0/24'], ['ether1', TUNNEL]]);
    ok('a device with no guard verdict and an ARMED net needs no extra confirmation',
      !one.requiresExplicitConfirmation);
  }

  // ==========================================================================
  section('17. Vocabulary bridges');
  // ==========================================================================
  eq('ACCEPT -> accept', toPlanVerdict('ACCEPT'), 'accept');
  eq('REJECT -> veto', toPlanVerdict('REJECT'), 'veto');
  eq('INDETERMINATE -> indeterminate', toPlanVerdict('INDETERMINATE'), 'indeterminate');
  ok('only ACCEPT lets an apply through',
    !blocksApply('ACCEPT') && blocksApply('REJECT') && blocksApply('INDETERMINATE'));

  // ==========================================================================
  console.log(`\n${'='.repeat(72)}`);
  console.log(`  ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.log('\n  FAILURES:');
    for (const f of failures) console.log(`   - ${f}`);
  }
  console.log('='.repeat(72));
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
