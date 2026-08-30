// ============================================================================
// @obliwan/shared — stable semantic keys
// ============================================================================
//
// Implements §3 of `docs/M4-NCM-contrat.md`. Pure, deterministic, no I/O: the
// client re-derives keys to line a finding up with a resource, and the whole
// testability of the milestone rests on these functions being callable from a
// unit test with no database.
//
// THE ONE RULE THAT GOVERNS THIS FILE (N1): the identity of an anonymous rule
// is WHICH PACKETS IT SELECTS, not what it does with them. Flipping
// `accept -> drop` on the management rule must yield ONE `changed` finding of
// severity `critical`, because the match side is untouched and the pairing is
// exact. If `action` were part of the identity, the single most dangerous edit
// available in the product would surface as a `missing` + an `extra` and would
// depend on a fuzzy matcher to be recognised as one event. That trade is not
// acceptable.
//
// Cost, stated honestly: two rules of the same chain that select the same
// packets and act differently collide. That is a real configuration smell (the
// second rule is dead code) and it is handled by `ordinal` — see §3.4 and
// `ordinalCollisionRate`, which is a milestone exit criterion, not a curiosity.

import { canonicalJson, sha256Short } from './hash';
import { SEM_KEY_GENERATION } from './model';
import type {
  NcmMatch, NcmResource, NcmResourceKind, KeyQuality, ManagedBy,
} from './resources';

/** Key prefix per resource kind. The `.v<n>` suffix is SEM_KEY_GENERATION, and
 *  it is present from day one precisely so that a bump is survivable (§8.4). */
export const SEM_KEY_PREFIX: Readonly<Record<NcmResourceKind, string>> = {
  interface: 'if',
  vlan: 'vlan',
  route: 'route',
  firewallRule: 'fw',
  natRule: 'nat',
  dhcpScope: 'dhcp',
  ipsecPeer: 'ipsec',
  localUser: 'user',
  service: 'svc',
  qosRule: 'qos',
};

/** `sem_key` is `varchar(180)` in the flattened tables and `z.string().max(180)`
 *  in the schema. A 200-character interface name would otherwise make a valid
 *  device unstoreable, so an over-long key is truncated and disambiguated by a
 *  hash of the full value. Deterministic, therefore still a stable key. */
const MAX_SEM_KEY = 180;

function capKey(key: string): string {
  if (key.length <= MAX_SEM_KEY) return key;
  return `${key.slice(0, MAX_SEM_KEY - 17)}~${sha256Short(key)}`;
}

function gen(prefix: string): string {
  return `${prefix}.v${SEM_KEY_GENERATION}`;
}

// ============================================================================
// The `obliwan:` marker — the strongest identity mechanism in the product
// ============================================================================

/**
 * A record ObliWAN wrote carries `obliwan:<slug>` at the head of its comment.
 * Phase 1 of the pairing algorithm anchors on that slug, which is why such a
 * record stays paired even after its action, its selectors AND its comment tail
 * have all changed. The marker is not decoration.
 */
export const OBLIWAN_MARKER_RE = /^obliwan:([a-z0-9._-]{1,48})\s*/;

/** Markers of OTHER management systems. A record carrying one of these is
 *  `managedBy: 'foreign'`: we neither own it nor pretend it is hand-written. */
export const FOREIGN_MARKER_PREFIXES: readonly string[] = [
  'unms:', 'uisp:', 'netbox:', 'ansible:', 'terraform:', 'rancid:', 'oxidized:',
  'acs:', 'genieacs:', 'zabbix:',
];

export interface ParsedComment {
  managedBy: ManagedBy;
  managedSlug: string | null;
  /** The comment WITHOUT the marker. `null` when nothing is left. */
  comment: string | null;
}

/** Splits a device comment into ownership + free text. The free text is what
 *  goes in `comment`, so editing the human half of a comment can never be read
 *  as a change of ownership. */
export function parseComment(raw: string | null | undefined): ParsedComment {
  const s = (raw ?? '').trim();
  if (!s) return { managedBy: 'unknown', managedSlug: null, comment: null };

  const m = OBLIWAN_MARKER_RE.exec(s);
  if (m) {
    const tail = s.slice(m[0].length).trim();
    return { managedBy: 'obliwan', managedSlug: m[1], comment: tail || null };
  }
  const lower = s.toLowerCase();
  for (const p of FOREIGN_MARKER_PREFIXES) {
    if (lower.startsWith(p)) {
      return { managedBy: 'foreign', managedSlug: null, comment: s };
    }
  }
  return { managedBy: 'unknown', managedSlug: null, comment: s };
}

// ============================================================================
// matchHash — the identity of an anonymous rule (§3.2)
// ============================================================================

/**
 * WHAT GOES IN: the canonical chain plus the fourteen selectors below,
 * `unmodeledMatch` INCLUDED (two rules, one of which carries a selector we do
 * not understand, are not the same rule).
 *
 * WHAT STAYS OUT, and why:
 *   action / jumpTarget / toAddresses / toPorts / rejectWith — THE change to
 *       detect, so it is payload (N1)
 *   disabled            — disabling a rule is a high-severity `changed`, not a
 *                         deletion
 *   comment / log / logPrefix — editing a comment must break nothing
 *   position            — never a field (N2)
 *   RouterOS `.id`, SonicOS uuid, TR-069 `{i}` — churn on every edit
 *   counters, bytes, packets, dynamic, invalid — state, not config (N4)
 *
 * The short keys are not cosmetic: this string is hashed for every rule of
 * every device of every collection, and the field names would otherwise be the
 * bulk of the hashed bytes.
 */
export function computeMatchHash(
  chain: string,
  chainName: string | null,
  m: NcmMatch,
): string {
  const payload = canonicalJson({
    c: chainName ? `${chain}:${chainName}` : chain,
    p: m.protocol,
    sa: m.srcAddress, da: m.dstAddress,
    sp: m.srcPort, dp: m.dstPort,
    ii: m.inInterface, oi: m.outInterface,
    sz: m.srcZone, dz: m.dstZone,
    cs: m.connectionState, cn: m.connectionNat,
    tf: m.tcpFlags, it: m.icmpType, ip: m.ipsecPolicy,
    um: m.unmodeledMatch,
  });
  return sha256Short(payload);
}

/**
 * `payload_hash` (§6.1): lets the indexer detect a `changed` in SQL without
 * deserialising the jsonb.
 *
 * Excluded, and each exclusion is load-bearing:
 *   semKey, matchHash   — derived from fields that are already included
 *   managedBy, managedSlug — derived from `comment`, which IS included
 *   keyQuality, via     — metadata about the COLLECTION, not about the config;
 *                         switching a device from SSH to the API must not make
 *                         all of its records look changed
 *   ordinal             — a position discriminator; N2 says position is never a
 *                         field, and a `moved` is not a `changed`
 */
const PAYLOAD_EXCLUDED = new Set([
  'semKey', 'matchHash', 'managedBy', 'managedSlug', 'keyQuality', 'via', 'ordinal',
]);

export function computePayloadHash(resource: Record<string, unknown>): string {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(resource)) {
    if (PAYLOAD_EXCLUDED.has(k)) continue;
    out[k] = resource[k];
  }
  return sha256Short(canonicalJson(out));
}

// ============================================================================
// The key builders (§3.1)
// ============================================================================

/** `if.v1:ether1` */
export function interfaceKey(name: string): string {
  return capKey(`${gen('if')}:${name}`);
}

/** `vlan.v1:bridge-lan:200`, or `vlan.v1:200` on a brand with a global VLAN
 *  table (parent omitted, never faked). */
export function vlanKey(parent: string | null, vlanId: number): string {
  return capKey(parent ? `${gen('vlan')}:${parent}:${vlanId}` : `${gen('vlan')}:${vlanId}`);
}

/** `route.v1:main:0.0.0.0/0:ip:10.255.0.1` — table, destination, gateway atom.
 *  A blackhole route has no gateway and keys on `blackhole`. */
export function routeKey(table: string, dst: string, gateway: string | null): string {
  return capKey(`${gen('route')}:${table || 'main'}:${dst}:${gateway ?? 'blackhole'}`);
}

/** `dhcp.v1:dhcp-lan` */
export function dhcpScopeKey(name: string): string {
  return capKey(`${gen('dhcp')}:${name}`);
}

/** `dhcp.v1:dhcp-lan:res:aa:bb:cc:dd:ee:01` — the MAC is the identity, not the
 *  address: re-addressing a reservation is a `changed`, not a delete+create. */
export function dhcpReservationKey(scopeName: string, mac: string): string {
  return capKey(`${gen('dhcp')}:${scopeName}:res:${mac.toLowerCase()}`);
}

/** `ipsec.v1:vpn.client-a.fr:CN=site-lyon` — remote peer plus local id, because
 *  two tunnels to the same head-end with different local identities are two
 *  different tunnels. */
export function ipsecPeerKey(remote: string, localId: string | null): string {
  const r = remote.trim().toLowerCase();
  return capKey(localId ? `${gen('ipsec')}:${r}:${localId}` : `${gen('ipsec')}:${r}`);
}

/** `user.v1:admin` — lowercased FOR THE KEY ONLY; `username` keeps its case, so
 *  a rename from `Admin` to `admin` shows up as a `changed` on the field rather
 *  than a delete+create of an administrator account. */
export function localUserKey(username: string): string {
  return capKey(`${gen('user')}:${username.trim().toLowerCase()}`);
}

/** `svc.v1:winbox`, or `svc.v1:other:<rawName>` for a service outside the
 *  canonical vocabulary. */
export function serviceKey(service: string, rawName: string | null): string {
  return capKey(
    service === 'other' && rawName
      ? `${gen('svc')}:other:${rawName.trim().toLowerCase()}`
      : `${gen('svc')}:${service}`,
  );
}

/**
 * `fw.v1:input:mk:mgmt-established`  (marker-anchored, keyQuality 'strong')
 * `fw.v1:input:3c9a1f77e0b45d21#0`   (derived, keyQuality 'derived')
 *
 * The marker form is what makes drift SILENT on everything ObliWAN owns: such a
 * rule stays paired through a change of action, of selectors and of comment.
 */
export function orderedRuleKey(
  kind: 'firewallRule' | 'natRule' | 'qosRule',
  chain: string,
  chainName: string | null,
  matchHash: string | null,
  ordinal: number,
  managedSlug: string | null,
): string {
  const prefix = gen(SEM_KEY_PREFIX[kind]);
  const chainPart = chainName ? `${chain}:${chainName}` : chain;
  if (managedSlug) return capKey(`${prefix}:${chainPart}:mk:${managedSlug}`);
  return capKey(`${prefix}:${chainPart}:${matchHash ?? 'nomatch'}#${ordinal}`);
}

/** `qos.v1:simple:ether1-limit` when the brand names the queue,
 *  `qos.v1:simple:<matchHash>#<ordinal>` when it does not. */
export function qosRuleKey(
  queueClass: string,
  name: string | null,
  matchHash: string | null,
  ordinal: number,
  managedSlug: string | null,
): string {
  const prefix = gen('qos');
  if (managedSlug) return capKey(`${prefix}:${queueClass}:mk:${managedSlug}`);
  if (name) return capKey(`${prefix}:${queueClass}:${name}`);
  return capKey(`${prefix}:${queueClass}:${matchHash ?? 'nomatch'}#${ordinal}`);
}

/**
 * The key quality a builder is entitled to claim. Centralised so a parser
 * cannot hand-write `'strong'` on a key it derived from content — the severity
 * of every finding depends on this value (§3.4 case 3).
 */
export function keyQualityFor(
  opts: { managedSlug?: string | null; naturalName?: string | null; matchHash?: string | null },
): KeyQuality {
  if (opts.managedSlug) return 'strong';
  if (opts.naturalName && opts.naturalName.trim() !== '') return 'strong';
  if (opts.matchHash) return 'derived';
  return 'weak';
}

/**
 * Re-derives the semKey of an already-built resource. Used by the client (to
 * line a finding up with a resource without shipping the parser) and by the
 * indexer as a consistency check: a resource whose stored `semKey` disagrees
 * with this function is a parser bug, and it is far cheaper to catch it at
 * index time than to debug a mispaired finding six weeks later.
 */
export function buildSemKey(r: NcmResource): string {
  switch (r.kind) {
    case 'interface':
      return interfaceKey(r.name);
    case 'vlan':
      return vlanKey(r.parent, r.vlanId);
    case 'route':
      return routeKey(r.table, r.dst, r.gateway);
    case 'dhcpScope':
      return dhcpScopeKey(r.name);
    case 'ipsecPeer':
      return ipsecPeerKey(r.remote, r.localId);
    case 'localUser':
      return localUserKey(r.username);
    case 'service':
      return serviceKey(r.service, r.rawName);
    case 'firewallRule':
      return orderedRuleKey('firewallRule', r.chain, r.chainName, r.matchHash, r.ordinal, r.managedSlug);
    case 'natRule':
      return orderedRuleKey('natRule', r.chain, r.chainName, r.matchHash, r.ordinal, r.managedSlug);
    case 'qosRule':
      return qosRuleKey(r.queueClass, r.name, r.matchHash, r.ordinal, r.managedSlug);
  }
}

/** The resource kind a stored key belongs to, and the generation it was built
 *  with. Returns null on anything that is not a semKey — a stored key from a
 *  previous generation parses fine and reports its own generation, which is
 *  what the §8.4 migration procedure needs. */
export function parseSemKey(key: string): { kind: NcmResourceKind; generation: number } | null {
  const m = /^([a-z]+)\.v(\d+):/.exec(key);
  if (!m) return null;
  const entry = (Object.keys(SEM_KEY_PREFIX) as NcmResourceKind[])
    .find((k) => SEM_KEY_PREFIX[k] === m[1]);
  if (!entry) return null;
  return { kind: entry, generation: Number(m[2]) };
}
