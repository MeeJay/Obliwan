// ============================================================================
// ObliWAN — the four dialect renderers (M11 — K4)
// ============================================================================
//
// ┌─ WHAT A RENDERER IS ALLOWED TO DO ────────────────────────────────────────┐
// │ Walk the NCM document the compiler just built, and say the same thing in  │
// │ one brand's words. It re-derives NOTHING: not an interface name, not a    │
// │ rule order, not a marker. `ResolvedSite` is consulted only for the facts  │
// │ the NCM deliberately does not carry — the VLAN id behind a vlan-typed     │
// │ interface, the PPPoE username, and the vault reference of a secret.       │
// │                                                                           │
// │ That constraint is what `crossCheckArtifact` can then verify: every       │
// │ interface, every scope and every firewall marker in the document has to   │
// │ appear in the text. Two independent renderings of one site is the bug     │
// │ this design removes rather than tests for.                                │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ HONESTY, STATED IN THE ARTEFACT ITSELF (§8.3) ───────────────────────────┐
// │ There is no lab. Not one of these dialects has been spoken to a real      │
// │ appliance. Every artefact therefore carries an UNVERIFIED banner in its   │
// │ own header, so the person about to push it reads it before they push it   │
// │ rather than after. The golden files freeze OUR rendering — they prove the │
// │ compiler is deterministic and that a change was intended, and they prove  │
// │ nothing whatsoever about what a Vigor will accept.                        │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ §8.2 ────────────────────────────────────────────────────────────────────┐
// │ Every credential is rendered as `<<secret:label>>`. The M6 push path      │
// │ substitutes the vault value in memory on the way to the device. Nothing   │
// │ here has access to a plaintext secret, because the intent has no field    │
// │ that could hold one.                                                      │
// └───────────────────────────────────────────────────────────────────────────┘

import type {
  NcmDocument,
  NcmFirewallRule,
  NcmMatch,
  PortSet,
  Selector,
} from '@obliwan/shared';
import type { ArtifactFormat, LocalUserIntent, VpnTunnel } from '@obliwan/shared/dist/intent';
import { INTENT_COMPILER_VERSION, secretPlaceholder } from '@obliwan/shared/dist/intent';
import type { SonicOsStagedOp } from '../drivers/sonicwall/sonicosSession';
import { markerComment } from './siteModel';
import type { ResolvedSite } from './siteModel';

// ============================================================================
// Shared helpers
// ============================================================================

/** Every selector the compiler emits is single-atom (see `compiler.service`).
 *  `null` means "any", which every dialect spells by omitting the clause. */
function one(selector: Selector | null | undefined): string | null {
  if (!selector || selector.length === 0) return null;
  const atom = selector[0];
  if (atom === 'any') return null;
  const colon = atom.indexOf(':');
  return colon < 0 ? atom : atom.slice(colon + 1);
}

function ports(set: PortSet): string | null {
  if (!set || set.length === 0) return null;
  return set.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`)).join(',');
}

/** The first port of a set — for dialects that cannot express a list in one
 *  rule. Only ever reached on the DNS/DHCP rule, which is the one place the
 *  compiler emits two intervals. */
function firstPort(set: PortSet): number | null {
  return set && set.length > 0 ? set[0][0] : null;
}

/** `obliwan:<site>.<record> <text>` — the exact comment the NCM record holds,
 *  rebuilt from the record so the two can never drift apart. */
function comment(record: { managedSlug: string | null; comment: string | null }): string {
  const marker = record.managedSlug ? `obliwan:${record.managedSlug}` : '';
  return [marker, record.comment ?? ''].filter((s) => s.length > 0).join(' ').trim();
}

// ┌─ ESCAPING: THE ONLY THING BETWEEN A TEXT FIELD AND A COMMAND ─────────────┐
// │ Every free-text field of a site intent — a segment name, a rule comment,  │
// │ a DHCP domain, a reservation hostname, a local username, a VPN peer's     │
// │ remote — is written by whoever holds TEMPLATE_WRITE and ends up           │
// │ interpolated into a line of RouterOS script, Vigor CLI or ZLD CLI. One    │
// │ newline in one of them closes our line and opens one of theirs: a segment │
// │ named  x"⏎/user add name=bd group=full⏎#  renders SIXTEEN standalone      │
// │ `/user add` lines into a RouterOS artefact a reviewer approves as a LAN   │
// │ rename. Neither `assertArtefactRedacted` (it hunts credential            │
// │ assignments) nor the old `crossCheckArtifact` (it hunted MISSING records, │
// │ never lines in excess) could see it.                                      │
// │                                                                           │
// │ So no intent-derived string reaches a template literal raw. Two shapes,   │
// │ per dialect:                                                              │
// │   rosQuote / vigorText / zldText — the value sits inside a quoted string  │
// │                    or a comment; line breaks and that dialect's own       │
// │                    metacharacters are substituted.                        │
// │   token()        — the value sits BARE in a command, where a space is     │
// │                    already an injection; only a conservative alphabet     │
// │                    survives.                                              │
// │                                                                           │
// │ Substitution, not refusal, on purpose. The schema refuses these           │
// │ characters at the API door (`SAFE_TEXT` in shared/src/intent.ts) and      │
// │ `intentStore.toRow` re-validates every stored document on the way out,    │
// │ so today nothing that reaches a renderer has skipped them. That is        │
// │ exactly why the escaping cannot live in the schema alone: the day a       │
// │ bulk importer, a schema relaxation or a second entry point builds a       │
// │ `SiteIntentDocument` another way, the barrier has to be here, in the      │
// │ one place that writes the command. Mangling a comment is then the         │
// │ right answer — refusing to render a site that is already deployed is      │
// │ not.                                                                      │
// │                                                                           │
// │ `assertLine` below is the hard stop that turns a call site somebody       │
// │ FORGOT into a failed compilation instead of a silent injection, and       │
// │ `crossCheckArtifact` counts the lines afterwards from the outside.        │
// └───────────────────────────────────────────────────────────────────────────┘

/** C0/C1 controls, DEL included. CR and LF are the dangerous two; the rest
 *  have no business in a configuration line either. */
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/g;

/** Collapse a free-text value onto ONE line. Shared by every dialect. */
function flatten(text: string): string {
  return text.replace(CONTROL_CHARS, ' ').replace(/ {2,}/g, ' ').trim();
}

/** RouterOS expands `$var` and `[command]` INSIDE double quotes, and `;`
 *  separates two commands, so a quoted comment is not a safe harbour. */
export function rosQuote(text: string): string {
  return flatten(text).replace(/["\\$;\[\]{}`]/g, '_');
}

/** Vigor CLI: a quoted argument ends at the quote, and backslash escapes. */
export function vigorText(text: string): string {
  return flatten(text).replace(/["\\`]/g, '_');
}

/** ZLD CLI: same shape as the Vigor. */
export function zldText(text: string): string {
  return flatten(text).replace(/["\\`]/g, '_');
}

/** SonicOS values travel inside `JSON.stringify`, which escapes quotes and
 *  newlines itself — the flattening here is hygiene for the human reading the
 *  artefact, not the barrier. */
export function sonicText(text: string): string {
  return flatten(text);
}

/**
 * A value that sits BARE in a command line: an interface name, a username, a
 * DHCP domain, a peer address, a queue name. A space is already an injection
 * there, so the alphabet is a whitelist rather than a blacklist.
 */
export function token(text: string): string {
  return text.replace(CONTROL_CHARS, '').replace(/[^A-Za-z0-9._:@/+-]/g, '_');
}

/**
 * The hard stop.
 *
 * Every renderer pushes every line through this. A line that still carries a
 * line break means one interpolation escaped the helpers above, and then the
 * artefact is not returned at all: a half-escaped renderer must fail loudly on
 * the compile path rather than ship a backdoor to a reviewer reading a diff of
 * comments.
 */
function assertLine(line: string): string {
  if (/[\r\n]/.test(line)) {
    throw new Error(
      'intent renderer produced a line containing a line break — an intent field reached the ' +
        'artefact unescaped (see the escaping block in renderers.ts); refusing to render',
    );
  }
  return line;
}

interface SecretLookup {
  /** vault reference of the PPPoE password of an uplink, by L3 interface name. */
  pppoe: Map<string, { username: string; ref: string }>;
  vpn: Map<string, VpnTunnel>;
  users: Map<string, LocalUserIntent>;
  snmpRef: string | null;
  /** vlan id carried by an interface, by interface name. Covers a tagged WAN
   *  hand-off as well as a segment VLAN — the NCM records the interface TYPE
   *  but not the tag, and a renderer must never guess a tag. */
  vlanOf: Map<string, number>;
  /**
   * L3 interfaces that learn their address by DHCP. The NCM cannot say it: a
   * DHCP-learned address is state, so the record simply carries no address —
   * which is also true of the PHYSICAL parent of a tagged uplink. Without this
   * set a renderer would put `ip address dhcp` on the parent port and the
   * appliance would take two addresses on one link.
   */
  dhcpL3: Set<string>;
}

function secretLookup(site: ResolvedSite): SecretLookup {
  const pppoe = new Map<string, { username: string; ref: string }>();
  const vlanOf = new Map<string, number>();
  const dhcpL3 = new Set<string>();
  for (const w of site.wans) {
    if (w.intent.mode === 'pppoe' && w.intent.pppoeUsername && w.intent.pppoeSecretRef) {
      pppoe.set(w.l3Name, { username: w.intent.pppoeUsername, ref: w.intent.pppoeSecretRef });
    }
    if (w.intent.mode === 'dhcp') dhcpL3.add(w.l3Name);
    if (w.tagged && w.intent.vlanId !== null) vlanOf.set(w.l3Name, w.intent.vlanId);
  }
  for (const s of site.segments) {
    if (s.intent.vlanId !== null) vlanOf.set(s.ifName, s.intent.vlanId);
  }
  return {
    pppoe,
    vlanOf,
    dhcpL3,
    vpn: new Map(site.intent.vpn.map((v) => [v.id, v])),
    users: new Map(site.intent.management.localUsers.map((u) => [u.username, u])),
    snmpRef: site.intent.management.snmp?.credentialRef ?? null,
  };
}

/** The banner every artefact carries. */
function banner(
  site: ResolvedSite,
  commentToken: string,
  esc: (t: string) => string = flatten,
): string[] {
  return [
    `${commentToken} ObliWAN — compiled from site intent "${site.intent.slug}" (${esc(site.intent.name)})`,
    `${commentToken} family: ${site.profile.family} · intent schema v${site.intent.schemaVersion} · compiler v${INTENT_COMPILER_VERSION}`,
    `${commentToken} UNVERIFIED AGAINST HARDWARE — no ${site.profile.brand} appliance exists to test this rendering against (§8.3).`,
    `${commentToken} Secrets appear as <<secret:label>> and are substituted from the vault, in memory, on the push path only (§8.2).`,
    `${commentToken} Nothing here is applied outside a change_jobs row (D3).`,
  ];
}

// ============================================================================
// RouterOS
// ============================================================================

function routerosMatch(m: NcmMatch): string[] {
  const out: string[] = [];
  if (m.protocol) out.push(`protocol=${m.protocol}`);
  const src = one(m.srcAddress);
  if (src) out.push(`src-address=${src}`);
  const dst = one(m.dstAddress);
  if (dst) out.push(`dst-address=${dst}`);
  const sp = ports(m.srcPort);
  if (sp) out.push(`src-port=${sp}`);
  const dp = ports(m.dstPort);
  if (dp) out.push(`dst-port=${dp}`);
  const inIf = one(m.inInterface);
  if (inIf) out.push(`in-interface=${inIf}`);
  const outIf = one(m.outInterface);
  if (outIf) out.push(`out-interface=${outIf}`);
  if (m.connectionState.length > 0) out.push(`connection-state=${m.connectionState.join(',')}`);
  if (m.connectionNat.length > 0) out.push(`connection-nat-state=${m.connectionNat.join(',')}`);
  return out;
}

const ROUTEROS_ACTIONS: Readonly<Record<string, string>> = {
  accept: 'accept',
  drop: 'drop',
  reject: 'reject',
  masquerade: 'masquerade',
  dstnat: 'dst-nat',
  srcnat: 'src-nat',
};

function renderRouterOs(site: ResolvedSite, doc: NcmDocument): string[] {
  const lookup = secretLookup(site);
  const cmt = (record: { managedSlug: string | null; comment: string | null }): string =>
    rosQuote(comment(record));
  const out: string[] = banner(site, '#', rosQuote);
  const add = (line: string): void => {
    out.push(assertLine(line));
  };

  add('');
  add('# --- interfaces -----------------------------------------------------------');
  for (const iface of doc.resources.interfaces) {
    const c = cmt(iface);
    if (iface.type === 'bridge') {
      add(`/interface bridge add name=${iface.name} comment="${c}"`);
    } else if (iface.type === 'vlan') {
      const vlanId = lookup.vlanOf.get(iface.name);
      add(
        `/interface vlan add name=${iface.name} vlan-id=${vlanId ?? 0} interface=${iface.parent ?? site.trunkName} comment="${c}"`,
      );
    } else if (iface.type === 'pppoe') {
      const creds = lookup.pppoe.get(iface.name);
      add(
        `/interface pppoe-client add name=${iface.name} interface=${iface.parent ?? iface.name} ` +
          `user="${rosQuote(creds?.username ?? '')}" password="${creds ? secretPlaceholder(creds.ref) : ''}" ` +
          `add-default-route=yes use-peer-dns=no comment="${c}"`,
      );
    } else if (iface.parent) {
      add(`/interface bridge port add bridge=${iface.parent} interface=${iface.name} comment="${c}"`);
    } else {
      add(`/interface ethernet set [ find default-name=${iface.name} ] comment="${c}"`);
    }
    if (iface.mtu !== null) add(`/interface set [ find name=${iface.name} ] mtu=${iface.mtu}`);
    for (const address of iface.addresses) {
      add(`/ip address add address=${address.cidr} interface=${iface.name} comment="${c}"`);
    }
    for (const list of iface.lists) {
      add(`/interface list member add list=${list} interface=${iface.name} comment="${c}"`);
    }
  }
  for (const w of site.wans) {
    if (w.intent.mode === 'dhcp') {
      add(
        `/ip dhcp-client add interface=${w.l3Name} add-default-route=yes use-peer-dns=no ` +
          `comment="${rosQuote(`${markerComment(site.intent, `wan-w${site.wans.indexOf(w)}`)} ${w.intent.id} uplink`)}"`,
      );
    }
  }

  add('');
  add('# --- routes ---------------------------------------------------------------');
  for (const route of doc.resources.routes) {
    const gateway = one([route.gateway ?? 'any']);
    add(
      `/ip route add dst-address=${route.dst} gateway=${gateway ?? 'blackhole'} ` +
        `distance=${route.distance ?? 1}${route.checkGateway ? ` check-gateway=${route.checkGateway}` : ''} comment="${cmt(route)}"`,
    );
  }

  add('');
  add('# --- dhcp -----------------------------------------------------------------');
  for (const scope of doc.resources.dhcpScopes) {
    const iface = one([scope.onInterface]);
    add(`/ip pool add name=pool-${token(scope.name)} ranges=${scope.poolFrom}-${scope.poolTo}`);
    add(
      `/ip dhcp-server add name=${token(scope.name)} interface=${iface} address-pool=pool-${token(scope.name)} ` +
        `lease-time=${scope.leaseSeconds}s disabled=no comment="${cmt(scope)}"`,
    );
    add(
      `/ip dhcp-server network add address=${scope.subnet} gateway=${scope.gateway}` +
        `${scope.dnsServers.length > 0 ? ` dns-server=${scope.dnsServers.join(',')}` : ''}` +
        `${scope.domain ? ` domain=${token(scope.domain)}` : ''} comment="${cmt(scope)}"`,
    );
    for (const reservation of scope.reservations) {
      add(
        `/ip dhcp-server lease add server=${token(scope.name)} mac-address=${reservation.mac.toUpperCase()} ` +
          `address=${reservation.address}${reservation.hostname ? ` comment="${rosQuote(`${reservation.comment ?? ''} ${reservation.hostname}`)}"` : ` comment="${rosQuote(reservation.comment ?? '')}"`}`,
      );
    }
  }

  add('');
  add('# --- firewall -------------------------------------------------------------');
  for (const rule of doc.resources.firewallRules) {
    const parts = [
      `chain=${rule.chain}`,
      `action=${ROUTEROS_ACTIONS[rule.action] ?? rule.action}`,
      ...routerosMatch(rule.match),
    ];
    if (rule.log) parts.push('log=yes', `log-prefix=${rule.logPrefix ?? 'obliwan'}`);
    add(`/ip firewall filter add ${parts.join(' ')} comment="${cmt(rule)}"`);
  }
  for (const rule of doc.resources.natRules) {
    const parts = [
      `chain=${rule.chain === 'prerouting' ? 'dstnat' : 'srcnat'}`,
      `action=${ROUTEROS_ACTIONS[rule.action] ?? rule.action}`,
      ...routerosMatch(rule.match),
    ];
    const to = one(rule.toAddresses);
    if (to) parts.push(`to-addresses=${to}`);
    const toPorts = ports(rule.toPorts);
    if (toPorts) parts.push(`to-ports=${toPorts}`);
    add(`/ip firewall nat add ${parts.join(' ')} comment="${cmt(rule)}"`);
  }

  if (doc.resources.ipsecPeers.length > 0) {
    add('');
    add('# --- ipsec ----------------------------------------------------------------');
    for (const peer of doc.resources.ipsecPeers) {
      const tunnel = peer.name ? lookup.vpn.get(peer.name) : undefined;
      const profileName = `prof-${token(peer.name ?? peer.remote)}`;
      add(
        `/ip ipsec profile add name=${profileName} enc-algorithm=${peer.proposal.encryption.join(',')} ` +
          `hash-algorithm=${peer.proposal.integrity[0] ?? 'sha256'} dh-group=${peer.proposal.dhGroup.join(',')}` +
          `${peer.dpdSeconds !== null ? ` dpd-interval=${peer.dpdSeconds}s` : ''}`,
      );
      add(
        `/ip ipsec peer add name=${token(peer.name ?? peer.remote)} address=${token(peer.remote)} ` +
          `exchange-mode=${peer.exchangeMode === 'ike2' ? 'ike2' : 'main'} profile=${profileName} comment="${cmt(peer)}"`,
      );
      add(
        `/ip ipsec identity add peer=${token(peer.name ?? peer.remote)} auth-method=pre-shared-key ` +
          `secret="${tunnel ? secretPlaceholder(tunnel.pskRef) : ''}"`,
      );
      for (const local of peer.localSubnets) {
        for (const remote of peer.remoteSubnets) {
          add(
            `/ip ipsec policy add peer=${token(peer.name ?? peer.remote)} src-address=${local} dst-address=${remote} ` +
              `tunnel=yes action=encrypt comment="${cmt(peer)}"`,
          );
        }
      }
    }
  }

  add('');
  add('# --- management -----------------------------------------------------------');
  for (const service of doc.resources.services) {
    if (service.service === 'snmp') {
      add(`/snmp set enabled=${service.enabled ? 'yes' : 'no'} contact="obliwan"`);
      if (lookup.snmpRef) {
        add(
          `/snmp community set [ find default=yes ] name="${secretPlaceholder(lookup.snmpRef)}"` +
            `${one(service.allowedFrom) ? ` addresses=${one(service.allowedFrom)}` : ''}`,
        );
      }
      continue;
    }
    const address = one(service.allowedFrom);
    add(
      `/ip service set ${service.service} disabled=${service.enabled ? 'no' : 'yes'}` +
        `${service.port !== null ? ` port=${service.port}` : ''}${address ? ` address=${address}` : ''}`,
    );
  }
  for (const user of doc.resources.localUsers) {
    const intent = lookup.users.get(user.username);
    const address = one(user.allowedFrom);
    add(
      `/user add name=${token(user.username)} group=${user.group ?? 'read'} ` +
        `password="${intent ? secretPlaceholder(intent.passwordRef) : ''}"` +
        `${address ? ` address=${address}` : ''} comment="${cmt(user)}"`,
    );
  }

  if (doc.resources.qosRules.length > 0) {
    add('');
    add('# --- queues ---------------------------------------------------------------');
    for (const queue of doc.resources.qosRules) {
      const target = one(queue.target) ?? '';
      const limit = `${queue.maxLimitUpBps ?? 0}/${queue.maxLimitDownBps ?? 0}`;
      add(
        `/queue simple add name=${token(queue.name ?? 'queue')} target=${target} max-limit=${limit}` +
          `${queue.parent ? ` parent=${token(queue.parent)}` : ''}${queue.priority !== null ? ` priority=${queue.priority}` : ''} comment="${cmt(queue)}"`,
      );
    }
  }

  out.push('');
  return out;
}

// ============================================================================
// DrayTek Vigor — telnet / SSH CLI
// ============================================================================

function draytekAction(action: string): string {
  return action === 'accept' ? 'pass' : action === 'reject' ? 'reject' : 'block';
}

function renderDraytek(site: ResolvedSite, doc: NcmDocument): string[] {
  const lookup = secretLookup(site);
  const cmt = (record: { managedSlug: string | null; comment: string | null }): string =>
    vigorText(comment(record));
  const out: string[] = banner(site, '#', vigorText);
  const add = (line: string): void => {
    out.push(assertLine(line));
  };

  add('');
  add('# --- WAN ------------------------------------------------------------------');
  site.wans.forEach((w, i) => {
    const c = markerComment(site.intent, `wan-w${i}`);
    add(`# ${c} ${w.intent.id}`);
    if (w.tagged && w.intent.vlanId !== null) {
      add(`wan vlan ${w.intent.uplinkIndex} enable 1 tag ${w.intent.vlanId}    # ${w.l3Name}`);
    }
    switch (w.intent.mode) {
      case 'dhcp':
        add(`wan interface ${w.physicalName} mode dhcp`);
        break;
      case 'static':
        add(`wan interface ${w.physicalName} mode static ip ${w.address ?? ''} gateway ${w.gateway ?? ''}`);
        break;
      case 'pppoe': {
        const creds = lookup.pppoe.get(w.l3Name);
        add(
          `wan interface ${w.physicalName} mode pppoe username "${vigorText(creds?.username ?? '')}" ` +
            `password "${creds ? secretPlaceholder(creds.ref) : ''}"`,
        );
        break;
      }
    }
    if (w.intent.mtu !== null) add(`wan mtu ${w.intent.uplinkIndex} ${w.intent.mtu}`);
    if (w.intent.role === 'backup') add(`wan failover ${w.intent.uplinkIndex} backup enable`);
  });

  add('');
  add('# --- LAN subnets ----------------------------------------------------------');
  site.segments.forEach((s, i) => {
    add(`# ${vigorText(`${markerComment(site.intent, `lan-s${i}`)} ${s.intent.name}`)}`);
    add(`ip lan ${s.ifName} ipaddr ${s.gatewayIp} netmask /${s.prefix} enable 1`);
    if (s.intent.vlanId !== null) {
      add(`vlan tag ${s.ifName} enable 1 vid ${s.intent.vlanId}`);
    }
    for (const portName of s.accessPorts) {
      add(`vlan port ${portName} subnet ${s.ifName} untagged`);
    }
    add(`ip lan ${s.ifName} interlan ${site.intent.policy.interSegment === 'deny' || s.intent.isolated ? 'block' : 'pass'}`);
  });

  add('');
  add('# --- DHCP -----------------------------------------------------------------');
  for (const scope of doc.resources.dhcpScopes) {
    const iface = one([scope.onInterface]) ?? site.trunkName;
    add(`# ${cmt(scope)}  (${token(scope.name)})`);
    add(
      `srv dhcp ${iface} enable start ${scope.poolFrom} end ${scope.poolTo} ` +
        `gateway ${scope.gateway ?? ''} lease ${scope.leaseSeconds ?? 86400}`,
    );
    if (scope.dnsServers.length > 0) add(`srv dhcp ${iface} dns1 ${scope.dnsServers[0]}${scope.dnsServers[1] ? ` dns2 ${scope.dnsServers[1]}` : ''}`);
    if (scope.domain) add(`srv dhcp ${iface} domain ${token(scope.domain)}`);
    scope.reservations.forEach((reservation, j) => {
      add(`srv dhcp fixip add ${j + 1} ${reservation.address} ${reservation.mac} ${token(reservation.hostname ?? '')}`.trimEnd());
    });
  }

  add('');
  add('# --- routes ---------------------------------------------------------------');
  doc.resources.routes.forEach((route, i) => {
    add(`# ${cmt(route)}`);
    add(`ip route add ${route.dst} gateway ${one([route.gateway ?? 'any']) ?? ''} idx ${i + 1} rtype static`);
  });

  add('');
  add('# --- filter rules ---------------------------------------------------------');
  doc.resources.firewallRules.forEach((rule, i) => {
    add(`# ${cmt(rule)}`);
    add(draytekFilterLine(rule, i + 1));
  });

  add('');
  add('# --- NAT ------------------------------------------------------------------');
  doc.resources.natRules.forEach((rule, i) => {
    add(`# ${cmt(rule)}`);
    if (rule.action === 'dstnat') {
      add(
        `srv nat portmap ${i + 1} ${rule.managedSlug ?? `pm${i + 1}`} ${rule.match.protocol ?? 'tcp'} ` +
          `${firstPort(rule.match.dstPort) ?? 0} ${one(rule.toAddresses) ?? ''} ${firstPort(rule.toPorts) ?? 0}`,
      );
    } else {
      add(`srv nat masquerade ${one(rule.match.outInterface) ?? ''} source ${one(rule.match.srcAddress) ?? 'any'} enable`);
    }
  });

  if (doc.resources.ipsecPeers.length > 0) {
    add('');
    add('# --- VPN ------------------------------------------------------------------');
    doc.resources.ipsecPeers.forEach((peer, i) => {
      const tunnel = peer.name ? lookup.vpn.get(peer.name) : undefined;
      add(`# ${cmt(peer)}`);
      add(
        `vpn profile ${i + 1} name ${token(peer.name ?? peer.remote)} type ipsec remote ${token(peer.remote)} ` +
          `ike ${peer.exchangeMode === 'ike2' ? 'v2' : 'v1main'} ` +
          `psk "${tunnel ? secretPlaceholder(tunnel.pskRef) : ''}"`,
      );
      add(
        `vpn profile ${i + 1} phase2 enc ${peer.proposal.encryption.join('/')} auth ${peer.proposal.integrity.join('/')} ` +
          `pfs ${peer.proposal.dhGroup.join('/')} local ${peer.localSubnets.join(',')} remote ${peer.remoteSubnets.join(',')}`,
      );
    });
  }

  add('');
  add('# --- management -----------------------------------------------------------');
  for (const service of doc.resources.services) {
    add(`# ${cmt(service)}`);
    if (service.service === 'snmp') {
      add(
        `srv snmp enable ${service.enabled ? 1 : 0} version ${service.version ?? 'v2c'} ` +
          `community "${lookup.snmpRef ? secretPlaceholder(lookup.snmpRef) : ''}" ` +
          `manager ${one(service.allowedFrom) ?? 'any'}`,
      );
      continue;
    }
    add(
      `sys mngt ${service.service} enable ${service.enabled ? 1 : 0}` +
        `${service.port !== null ? ` port ${service.port}` : ''} acl ${one(service.allowedFrom) ?? 'any'}`,
    );
  }
  for (const user of doc.resources.localUsers) {
    const intent = lookup.users.get(user.username);
    add(`# ${cmt(user)}`);
    add(
      `sys admin add ${token(user.username)} password "${intent ? secretPlaceholder(intent.passwordRef) : ''}" ` +
        `level ${user.group ?? 'read'} acl ${one(user.allowedFrom) ?? 'any'}`,
    );
  }

  if (doc.resources.qosRules.length > 0) {
    add('');
    add('# --- bandwidth ------------------------------------------------------------');
    doc.resources.qosRules.forEach((queue, i) => {
      add(`# ${cmt(queue)}`);
      add(
        `qos class ${i + 1} name ${token(queue.name ?? `q${i + 1}`)} target ${one(queue.target) ?? ''} ` +
          `up ${queue.maxLimitUpBps ?? 0} down ${queue.maxLimitDownBps ?? 0} priority ${queue.priority ?? 4}`,
      );
    });
  }

  add('');
  add('# The Vigor keeps the running configuration in memory until it is written.');
  add('sys commit');
  out.push('');
  return out;
}

function draytekFilterLine(rule: NcmFirewallRule, index: number): string {
  const m = rule.match;
  const parts = [
    `ip filter rule ${rule.chain === 'input' ? 'mgmt' : 'data'} ${index}`,
    `-e 1`,
    `-a ${draytekAction(rule.action)}`,
  ];
  if (m.protocol) parts.push(`-p ${m.protocol}`);
  const src = one(m.srcAddress);
  parts.push(`-s ${src ?? 'any'}`);
  const dst = one(m.dstAddress);
  parts.push(`-d ${dst ?? 'any'}`);
  const dp = ports(m.dstPort);
  if (dp) parts.push(`-P ${dp}`);
  const inIf = one(m.inInterface);
  if (inIf) parts.push(`-i ${inIf}`);
  const outIf = one(m.outInterface);
  if (outIf) parts.push(`-o ${outIf}`);
  if (m.connectionState.length > 0) parts.push(`-k ${m.connectionState.join(',')}`);
  if (rule.log) parts.push('-l 1');
  return parts.join(' ');
}

// ============================================================================
// Zyxel — ZLD CLI
// ============================================================================

function renderZyxel(site: ResolvedSite, doc: NcmDocument): string[] {
  const lookup = secretLookup(site);
  const cmt = (record: { managedSlug: string | null; comment: string | null }): string =>
    zldText(comment(record));
  const out: string[] = banner(site, '!', zldText);
  const add = (line: string): void => {
    out.push(assertLine(line));
  };

  add('');
  add('configure terminal');

  add('!');
  add('! --- interfaces ----------------------------------------------------------');
  for (const iface of doc.resources.interfaces) {
    add(`! ${cmt(iface)}`);
    add(`interface ${iface.name}`);
    const vlanId = lookup.vlanOf.get(iface.name);
    if (vlanId !== undefined) {
      add(` vlan-id ${vlanId}`);
      add(` port ${iface.parent ?? site.trunkName}`);
    }
    if (iface.type === 'pppoe') {
      const creds = lookup.pppoe.get(iface.name);
      add(` encapsulation pppoe`);
      add(` account "${zldText(creds?.username ?? '')}" password "${creds ? secretPlaceholder(creds.ref) : ''}"`);
    }
    if (lookup.dhcpL3.has(iface.name)) {
      add(' ip address dhcp');
    }
    for (const address of iface.addresses) {
      const [ip, prefix] = address.cidr.split('/');
      add(` ip address ${ip} /${prefix}`);
    }
    if (iface.mtu !== null) add(` mtu ${iface.mtu}`);
    add(' exit');
  }

  add('!');
  add('! --- zones ---------------------------------------------------------------');
  const zones = new Map<string, string[]>();
  for (const iface of doc.resources.interfaces) {
    if (!iface.zone) continue;
    const members = zones.get(iface.zone) ?? [];
    if (!members.includes(iface.name)) members.push(iface.name);
    zones.set(iface.zone, members);
  }
  for (const [zone, members] of Array.from(zones.entries()).sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    add(`zone ${zone}`);
    for (const member of members) add(` interface ${member}`);
    add(' exit');
  }

  add('!');
  add('! --- address objects -----------------------------------------------------');
  const objects = new Map<string, string>();
  const objectFor = (value: string): string => {
    const existing = objects.get(value);
    if (existing) return existing;
    const name = `OBW_${value.replace(/[./:]/g, '_')}`.slice(0, 63);
    objects.set(value, name);
    return name;
  };
  // Every address a later section will REFERENCE has to be declared here: ZLD
  // policies name objects, never literals, and a policy that names an object
  // the configuration never created is refused by the appliance at the line
  // that mentions it. The management services are in this pre-pass for exactly
  // that reason — they were the one place that referenced an object nothing had
  // declared.
  for (const rule of [...doc.resources.firewallRules, ...doc.resources.natRules]) {
    for (const selector of [rule.match.srcAddress, rule.match.dstAddress]) {
      const value = one(selector);
      if (value) objectFor(value);
    }
  }
  for (const service of doc.resources.services) {
    if (service.service === 'snmp') continue;
    const allowed = one(service.allowedFrom);
    if (allowed) objectFor(allowed);
  }
  for (const [value, name] of Array.from(objects.entries()).sort((a, b) => (a[1] < b[1] ? -1 : 1))) {
    add(
      value.includes('/')
        ? `address-object ${name} SUBNET ${value.split('/')[0]} ${value.split('/')[1]}`
        : `address-object ${name} HOST ${value}`,
    );
  }

  add('!');
  add('! --- dhcp ----------------------------------------------------------------');
  for (const scope of doc.resources.dhcpScopes) {
    const iface = one([scope.onInterface]) ?? site.trunkName;
    add(`! ${cmt(scope)}  (${token(scope.name)})`);
    add(`interface ${iface}`);
    add(` ip dhcp-pool ${token(scope.name)}`);
    add(`  starting-address ${scope.poolFrom} pool-size ${scope.poolTo}`);
    if (scope.gateway) add(`  default-router ${scope.gateway}`);
    scope.dnsServers.forEach((dns, i) => add(`  first-dns-server ${i === 0 ? dns : dns}`));
    if (scope.domain) add(`  domain-name ${token(scope.domain)}`);
    add(`  lease ${scope.leaseSeconds ?? 86400}`);
    for (const reservation of scope.reservations) {
      add(`  static ${reservation.mac} ${reservation.address}`);
    }
    add('  exit');
    add(' exit');
  }

  add('!');
  add('! --- routes --------------------------------------------------------------');
  for (const route of doc.resources.routes) {
    add(`! ${cmt(route)}`);
    const [dst, prefix] = route.dst.split('/');
    add(`ip route ${dst} /${prefix} ${one([route.gateway ?? 'any']) ?? ''} ${route.distance ?? 1}`);
  }

  add('!');
  add('! --- security policy -----------------------------------------------------');
  doc.resources.firewallRules.forEach((rule, i) => {
    add(`! ${cmt(rule)}`);
    add(`secure-policy ${i + 1}`);
    add(` from ${rule.match.srcZone ?? 'any'}`);
    add(` to ${rule.chain === 'input' ? 'ZyWALL' : (rule.match.dstZone ?? 'any')}`);
    const src = one(rule.match.srcAddress);
    if (src) add(` sourceip ${objectFor(src)}`);
    const dst = one(rule.match.dstAddress);
    if (dst) add(` destinationip ${objectFor(dst)}`);
    const dp = ports(rule.match.dstPort);
    if (dp) add(` service ${rule.match.protocol ?? 'tcp'}_${dp.replace(/[,-]/g, '_')}`);
    add(` action ${rule.action === 'accept' ? 'allow' : rule.action === 'reject' ? 'reject' : 'deny'}`);
    if (rule.log) add(' log log');
    add(` description ${token(rule.managedSlug ?? `rule${i + 1}`)}`);
    add(' exit');
  });

  add('!');
  add('! --- nat -----------------------------------------------------------------');
  doc.resources.natRules.forEach((rule, i) => {
    add(`! ${cmt(rule)}`);
    if (rule.action === 'dstnat') {
      add(`ip virtual-server ${rule.managedSlug ?? `vs${i + 1}`}`);
      add(` interface ${one(rule.match.inInterface) ?? ''}`);
      add(` original-ip any`);
      add(` mapped-ip ${one(rule.toAddresses) ?? ''}`);
      add(` protocol ${rule.match.protocol ?? 'tcp'}`);
      add(` original-port ${firstPort(rule.match.dstPort) ?? 0} mapped-port ${firstPort(rule.toPorts) ?? 0}`);
      add(' exit');
    } else {
      add(
        `ip nat-policy ${rule.managedSlug ?? `snat${i + 1}`} outgoing-interface ${one(rule.match.outInterface) ?? ''} ` +
          `source ${one(rule.match.srcAddress) ?? 'any'} snat outgoing-interface`,
      );
    }
  });

  if (doc.resources.ipsecPeers.length > 0) {
    add('!');
    add('! --- ipsec ---------------------------------------------------------------');
    for (const peer of doc.resources.ipsecPeers) {
      const tunnel = peer.name ? lookup.vpn.get(peer.name) : undefined;
      add(`! ${cmt(peer)}`);
      add(`isakmp policy ${token(peer.name ?? peer.remote)}`);
      add(` mode ${peer.exchangeMode === 'ike2' ? 'ikev2' : 'main'}`);
      add(` peer-ip ${token(peer.remote)}`);
      add(` authentication pre-share`);
      add(` keystring "${tunnel ? secretPlaceholder(tunnel.pskRef) : ''}"`);
      add(` transform-set ${peer.proposal.encryption.join('-')}-${peer.proposal.integrity.join('-')}`);
      if (peer.dpdSeconds !== null) add(` dpd ${peer.dpdSeconds}`);
      add(' exit');
      add(`crypto map ${token(peer.name ?? peer.remote)}`);
      add(` local-policy ${peer.localSubnets.join(',')}`);
      add(` remote-policy ${peer.remoteSubnets.join(',')}`);
      add(' exit');
    }
  }

  add('!');
  add('! --- management ----------------------------------------------------------');
  for (const service of doc.resources.services) {
    add(`! ${cmt(service)}`);
    if (service.service === 'snmp') {
      add(`snmp-server ${service.enabled ? 'enable' : 'disable'} version ${service.version ?? 'v2c'}`);
      if (lookup.snmpRef) add(`snmp-server community "${secretPlaceholder(lookup.snmpRef)}" ro`);
      const allowed = one(service.allowedFrom);
      if (allowed) add(`snmp-server host ${allowed}`);
      continue;
    }
    add(
      `ip ${service.service} server ${service.enabled ? 'enable' : 'disable'}` +
        `${service.port !== null ? ` port ${service.port}` : ''}`,
    );
    const allowed = one(service.allowedFrom);
    if (allowed) add(`ip ${service.service} server-access ${objectFor(allowed)}`);
  }
  for (const user of doc.resources.localUsers) {
    const intent = lookup.users.get(user.username);
    add(`! ${cmt(user)}`);
    add(`username ${token(user.username)} password "${intent ? secretPlaceholder(intent.passwordRef) : ''}" user-type ${user.group ?? 'user'}`);
  }

  if (doc.resources.qosRules.length > 0) {
    add('!');
    add('! --- bandwidth -----------------------------------------------------------');
    doc.resources.qosRules.forEach((queue, i) => {
      add(`! ${cmt(queue)}`);
      add(`bwm ${i + 1} description ${token(queue.name ?? `bwm${i + 1}`)}`);
      add(` interface ${one(queue.target) ?? ''}`);
      add(` inbound-kbps ${Math.floor((queue.maxLimitDownBps ?? 0) / 1000)}`);
      add(` outbound-kbps ${Math.floor((queue.maxLimitUpBps ?? 0) / 1000)}`);
      add(` priority ${queue.priority ?? 4}`);
      add(' exit');
    });
    add('bwm enable');
  }

  add('exit');
  add('write');
  out.push('');
  return out;
}

// ============================================================================
// SonicOS — staged REST operations
// ============================================================================

/**
 * The SonicOS artefact is not text to be typed: it is the exact list of staged
 * writes `applyStagedOps` sends, in order, between one login and one atomic
 * commit. Rendering it as anything else would mean the operator reviews one
 * thing on the plan screen and the appliance receives another.
 */
export interface SonicOsArtifact {
  $comment: string[];
  compilerVersion: number;
  intentSlug: string;
  ops: SonicOsStagedOp[];
}

function sonicOsAction(action: string): string {
  return action === 'accept' ? 'allow' : action === 'reject' ? 'discard' : 'deny';
}

function renderSonicOs(site: ResolvedSite, doc: NcmDocument): string {
  const lookup = secretLookup(site);
  const cmt = (record: { managedSlug: string | null; comment: string | null }): string =>
    sonicText(comment(record));
  const ops: SonicOsStagedOp[] = [];
  const push = (
    method: SonicOsStagedOp['method'],
    path: string,
    body: unknown,
    description: string,
  ): void => {
    ops.push({ method, path, body, description });
  };

  for (const iface of doc.resources.interfaces) {
    const address = iface.addresses[0] ?? null;
    const [ip, prefix] = address ? address.cidr.split('/') : [null, null];
    const creds = lookup.pppoe.get(iface.name);
    push(
      'POST',
      '/interfaces/ipv4',
      {
        interface: {
          name: iface.name,
          zone: iface.zone ?? 'LAN',
          comment: cmt(iface),
          ...(lookup.vlanOf.has(iface.name)
            ? { vlan: { tag: lookup.vlanOf.get(iface.name), parent: iface.parent ?? site.trunkName } }
            : {}),
          ...(iface.mtu !== null ? { mtu: iface.mtu } : {}),
          ip_assignment: creds
            ? {
                mode: 'pppoe',
                pppoe: { username: creds.username, password: secretPlaceholder(creds.ref) },
              }
            : ip
              ? { mode: 'static', static: { ip, prefix: Number(prefix) } }
              : { mode: lookup.dhcpL3.has(iface.name) ? 'dhcp' : 'unassigned' },
        },
      },
      `interface ${iface.name}`,
    );
  }

  const addressObjects = new Map<string, string>();
  const objectFor = (value: string): string => {
    const existing = addressObjects.get(value);
    if (existing) return existing;
    const name = `OBW_${value.replace(/[./:]/g, '_')}`.slice(0, 63);
    addressObjects.set(value, name);
    push(
      'POST',
      '/address-objects/ipv4',
      value.includes('/')
        ? {
            address_object: {
              ipv4: { name, zone: 'WAN', network: { subnet: value.split('/')[0], mask: value.split('/')[1] } },
            },
          }
        : { address_object: { ipv4: { name, zone: 'WAN', host: { ip: value } } } },
      `address object ${name}`,
    );
    return name;
  };

  for (const scope of doc.resources.dhcpScopes) {
    push(
      'POST',
      '/dhcp-server/lease-scopes/dynamic/ipv4',
      {
        lease_scope: {
          name: scope.name,
          comment: cmt(scope),
          range: { start: scope.poolFrom, end: scope.poolTo },
          interface: one([scope.onInterface]),
          gateway: scope.gateway,
          dns: { primary: scope.dnsServers[0] ?? null, secondary: scope.dnsServers[1] ?? null },
          domain: scope.domain,
          lease_time: scope.leaseSeconds,
        },
      },
      `dhcp scope ${scope.name}`,
    );
    for (const reservation of scope.reservations) {
      push(
        'POST',
        '/dhcp-server/lease-scopes/static/ipv4',
        {
          lease_scope: {
            name: `${scope.name}-${reservation.mac.replace(/:/g, '')}`,
            comment: reservation.comment === null ? null : sonicText(reservation.comment),
            ethernet: reservation.mac,
            ip: reservation.address,
          },
        },
        `dhcp reservation ${reservation.mac}`,
      );
    }
  }

  for (const route of doc.resources.routes) {
    push(
      'POST',
      '/route-policies/ipv4',
      {
        route_policy: {
          name: route.managedSlug ?? 'default',
          comment: cmt(route),
          destination: { any: route.dst === '0.0.0.0/0' ? true : undefined, network: route.dst === '0.0.0.0/0' ? undefined : route.dst },
          gateway: one([route.gateway ?? 'any']),
          metric: route.distance ?? 1,
          probe: route.checkGateway ? { type: 'ping' } : undefined,
        },
      },
      `route ${route.dst}`,
    );
  }

  doc.resources.firewallRules.forEach((rule, i) => {
    const src = one(rule.match.srcAddress);
    const dst = one(rule.match.dstAddress);
    push(
      'POST',
      '/access-rules/ipv4',
      {
        access_rule: {
          ipv4: {
            name: rule.managedSlug ?? `rule-${i}`,
            comment: cmt(rule),
            enable: !rule.disabled,
            from: rule.match.srcZone ?? 'Any',
            to: rule.chain === 'input' ? 'Firewall' : (rule.match.dstZone ?? 'Any'),
            action: sonicOsAction(rule.action),
            source: { address: src ? { name: objectFor(src) } : { any: true } },
            destination: { address: dst ? { name: objectFor(dst) } : { any: true } },
            service: ports(rule.match.dstPort)
              ? { name: `${rule.match.protocol ?? 'tcp'}/${ports(rule.match.dstPort)}` }
              : { any: true },
            logging: rule.log,
          },
        },
      },
      `access rule ${rule.managedSlug ?? i}`,
    );
  });

  doc.resources.natRules.forEach((rule, i) => {
    const isDstNat = rule.action === 'dstnat';
    push(
      'POST',
      '/nat-policies/ipv4',
      {
        nat_policy: {
          name: rule.managedSlug ?? `nat-${i}`,
          comment: cmt(rule),
          inbound: one(rule.match.inInterface),
          outbound: one(rule.match.outInterface),
          original: {
            source: one(rule.match.srcAddress) ? { name: objectFor(one(rule.match.srcAddress) as string) } : { any: true },
            destination: { any: true },
            service: ports(rule.match.dstPort) ? { name: `${rule.match.protocol ?? 'tcp'}/${ports(rule.match.dstPort)}` } : { any: true },
          },
          translated: isDstNat
            ? {
                destination: { name: objectFor(one(rule.toAddresses) as string) },
                service: { name: `${rule.match.protocol ?? 'tcp'}/${ports(rule.toPorts)}` },
              }
            : { source: { original: false, interface: true } },
        },
      },
      `nat policy ${rule.managedSlug ?? i}`,
    );
  });

  for (const peer of doc.resources.ipsecPeers) {
    const tunnel = peer.name ? lookup.vpn.get(peer.name) : undefined;
    push(
      'POST',
      '/vpn/policies/ipv4/site-to-site',
      {
        vpn_policy: {
          name: peer.name ?? peer.remote,
          comment: cmt(peer),
          gateway: { primary: peer.remote },
          auth_method: 'shared_secret',
          shared_secret: tunnel ? secretPlaceholder(tunnel.pskRef) : null,
          proposal: {
            ike: {
              exchange: peer.exchangeMode === 'ike2' ? 'ikev2_mode' : 'main_mode',
              dh_group: peer.proposal.dhGroup,
              encryption: peer.proposal.encryption,
              authentication: peer.proposal.integrity,
            },
          },
          network: { local: peer.localSubnets, remote: peer.remoteSubnets },
          ...(peer.dpdSeconds !== null ? { dead_peer_detection: { interval: peer.dpdSeconds } } : {}),
        },
      },
      `vpn policy ${peer.name ?? peer.remote}`,
    );
  }

  for (const service of doc.resources.services) {
    if (service.service === 'snmp') {
      push(
        'PUT',
        '/snmp',
        {
          snmp: {
            enable: service.enabled,
            version: service.version ?? 'v2c',
            community: lookup.snmpRef ? secretPlaceholder(lookup.snmpRef) : null,
            comment: cmt(service),
          },
        },
        'snmp',
      );
      continue;
    }
    push(
      'PUT',
      `/administration/${service.service}`,
      {
        management: {
          enable: service.enabled,
          port: service.port,
          comment: cmt(service),
          allowed: one(service.allowedFrom) ? { name: objectFor(one(service.allowedFrom) as string) } : { any: true },
        },
      },
      `management ${service.service}`,
    );
  }

  for (const user of doc.resources.localUsers) {
    const intent = lookup.users.get(user.username);
    push(
      'POST',
      '/user/local/users',
      {
        user: {
          local: {
            name: user.username,
            comment: cmt(user),
            password: intent ? secretPlaceholder(intent.passwordRef) : null,
            group: user.group === 'full' ? 'SonicWALL Administrators' : 'Limited Administrators',
          },
        },
      },
      `local user ${user.username}`,
    );
  }

  doc.resources.qosRules.forEach((queue, i) => {
    push(
      'POST',
      '/bwm/elastic',
      {
        bandwidth_object: {
          name: queue.name ?? `bwm-${i}`,
          comment: cmt(queue),
          guaranteed_kbps: 0,
          maximum_kbps: Math.floor((queue.maxLimitDownBps ?? 0) / 1000),
          upstream_kbps: Math.floor((queue.maxLimitUpBps ?? 0) / 1000),
          priority: queue.priority ?? 4,
          target: one(queue.target),
        },
      },
      `bandwidth ${queue.name ?? i}`,
    );
  });

  const artifact: SonicOsArtifact = {
    $comment: banner(site, '', sonicText).map((line) => line.trim()),
    compilerVersion: INTENT_COMPILER_VERSION,
    intentSlug: site.intent.slug,
    ops,
  };
  // Two-space JSON with the key order this file wrote: deterministic, diffable,
  // and reviewable next to the golden file it is frozen against.
  return `${JSON.stringify(artifact, null, 2)}\n`;
}

// ============================================================================
// Dispatch
// ============================================================================

/**
 * The only entry point. Exhaustive over `ArtifactFormat`, so adding a dialect
 * to the shared union without writing its renderer is a compile error.
 */
export interface RenderedArtifact {
  format: ArtifactFormat;
  body: string;
  /**
   * How many lines the renderer ACTUALLY emitted — one per `add()` call.
   *
   * `crossCheckArtifact` compares it with the number of lines the body
   * splits into. They differ by exactly the number of line breaks that an
   * intent field carried into the middle of a rendered line, which is the
   * injection this count exists to catch. It is an identity, not a
   * heuristic ceiling: a RouterOS interface legitimately produces four or
   * five lines, so "no more lines than NCM records" would have to be tuned
   * per dialect and would drift the day a renderer grows a line.
   *
   * `null` for `sonicos_rest`: that artefact is `JSON.stringify` output,
   * where a line break inside a value is escaped to `\\n` by the
   * serializer and can never become a line — counting its lines would only
   * compare the serializer with itself.
   */
  emittedLines: number | null;
}

export function renderArtifact(site: ResolvedSite, document: NcmDocument): RenderedArtifact {
  const format = site.profile.artifactFormat;
  if (format === null) {
    throw new Error(`no renderer is declared for ${site.profile.family}`);
  }
  switch (format) {
    case 'routeros_script':
      return joined(format, renderRouterOs(site, document));
    case 'draytek_cli':
      return joined(format, renderDraytek(site, document));
    case 'zyxel_zld_cli':
      return joined(format, renderZyxel(site, document));
    case 'sonicos_rest':
      return { format, body: renderSonicOs(site, document), emittedLines: null };
  }
}

function joined(format: ArtifactFormat, lines: string[]): RenderedArtifact {
  return { format, body: lines.join('\n'), emittedLines: lines.length };
}

/** Read the staged operations back out of a SonicOS artefact. The apply path
 *  parses the artefact it was given rather than re-rendering one, so what an
 *  operator approved is byte-for-byte what the appliance receives. */
export function sonicOsOpsOf(artifactBody: string): SonicOsStagedOp[] {
  const parsed = JSON.parse(artifactBody) as Partial<SonicOsArtifact>;
  if (!parsed || !Array.isArray(parsed.ops)) {
    throw new Error('SonicOS artefact carries no "ops" array');
  }
  return parsed.ops;
}



