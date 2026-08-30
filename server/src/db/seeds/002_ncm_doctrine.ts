import type { Knex } from 'knex';
import {
  COMMENT_VOLATILE_SUFFIX,
  ROUTEROS_SECTION_CATALOG,
  SEEDED_ROUTEROS_DEFAULTS,
  type RouterOsSectionSpec,
} from '../../services/drivers/mikrotik/quirks';

/**
 * 002_ncm_doctrine.ts — the seeded normalisation doctrine (M4).
 *
 * Writes three tables from ONE source of truth
 * (`services/drivers/mikrotik/quirks.ts`):
 *
 *   ncm_section_catalog   §5.2 — ordering, sem_key props, state/counter/secret
 *                         props, the hard bound on default_fill.
 *   normalization_rules   §5.1 — the N01..N16 rules, editable in the UI, with
 *                         an application order.
 *   routeros_defaults     §5.3 — the "last resort" tier of the N09 dictionary.
 *
 * ┌─ THREE PROPERTIES THIS SEED MUST KEEP ────────────────────────────────────┐
 * │                                                                           │
 * │ 1. IDEMPOTENT AND NON-CLOBBERING. Builtin rules are reconciled by         │
 * │    `builtin_key`. Re-running the seed refreshes the BODY of a rule (its   │
 * │    pattern, its predicate, its documentation) and NEVER touches           │
 * │    `enabled`, `severity` or the counters: an operator who disabled a rule │
 * │    after it hid something must not have it silently switched back on by   │
 * │    the next deployment.                                                   │
 * │                                                                           │
 * │ 2. EVERY RULE CARRIES ITS FALSE NEGATIVE. `rationale` and                 │
 * │    `false_negative` are NOT NULL with a non-blank CHECK. That is doctrine │
 * │    D1 written into the schema: a rule nobody wrote the false negative of  │
 * │    is a rule that can silently hide a real change, which is the one       │
 * │    failure mode this subsystem exists to prevent.                         │
 * │                                                                           │
 * │ 3. EVERY ENABLED RULE CARRIES ITS PROOF. `normalization_rule_tests` gets  │
 * │    one `must_suppress` (prove what it removes) and one                    │
 * │    `must_not_suppress` (prove what it lets through) per rule. The service │
 * │    refuses to enable a rule without both.                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ALL THREE TABLES ARE PLATFORM LIBRARIES, NOT TENANT DATA — and the three
 * are library in three different ways, which is worth stating once so nobody
 * goes looking for a symmetric fix that has no subject:
 *
 *   normalization_rules   `tenant_id` NULLABLE since migration 013, and the
 *                         doctrine is written with `tenant_id: null`. Readers
 *                         say `(nr.tenant_id = :t OR nr.tenant_id IS NULL)`,
 *                         the convention 008 already froze for `templates`.
 *                         A tenant may still add rules OF ITS OWN, which sort
 *                         after the library at equal `apply_order` (higher
 *                         `id`) and can therefore correct it.
 *   ncm_section_catalog   NO tenant column at all (PK `section_path, family`),
 *                         never had one. It describes RouterOS, not a customer.
 *   routeros_defaults     NO tenant column at all (PK `family, os_version,
 *                         section_path, prop`). `loadDefaults()` filters on
 *                         family/os_version/conflicting and takes no tenant
 *                         argument. It was already shared; F1 never reached it
 *                         — what was broken for tenant ≠ 1 was the
 *                         `ros.defaults.fill:*` RULES that drive it, which is
 *                         fixed by the line above and nowhere else.
 *
 * THE STATE/COUNTER ROWS ARE GENERATED, NOT TYPED. §3/N06 requires one rule per
 * `(section_path, prop)` and forbids a global rule on a prop name: `mac-address`
 * is state on a bridge and it is the IDENTITY of a static DHCP lease. Writing
 * ~150 rows by hand would guarantee a divergence with the parser within a
 * month, so they are derived from the same catalogue the parser reads.
 */

interface SeedRule {
  builtinKey: string;
  name: string;
  description: string;
  rationale: string;
  falseNegative: string;
  layer: 1 | 2 | 3 | 4;
  kind: string;
  sectionPath?: string | null;
  sectionOrdered?: boolean;
  prop?: string | null;
  pattern?: string | null;
  replacement?: string | null;
  predicate?: unknown;
  value?: unknown;
  targetPath?: string | null;
  severity?: string | null;
  applyOrder: number;
  enabled?: boolean;
  family?: string | null;
  osMin?: string | null;
  /** `must_suppress` proof: two texts that differ only in what the rule eats. */
  suppress: { before: string; after: string };
  /** `must_not_suppress` proof: a real change the rule must let through. */
  keep: { before: string; after: string; expect?: Record<string, unknown> };
}

// ============================================================================
// The hand-written rules of §3
// ============================================================================

const HAND_WRITTEN: SeedRule[] = [
  {
    builtinKey: 'ros.header.strip',
    name: 'N01 — strip the export preamble',
    description:
      'Removes the contiguous `#` block at the head of the file, AFTER parsing the OS version, ' +
      'the model and the serial out of it. Double-anchored: `^#` AND before the first line ' +
      'starting with `/`.',
    rationale:
      'The header carries the export timestamp and the firmware string, so it differs on 100 % of ' +
      'exports of 100 % of devices. It is the most trivially guaranteed source of noise there is.',
    falseNegative:
      'Near zero AS LONG AS the preamble is parsed before it is removed. A naive `grep -v "^#"` ' +
      'would cost (a) upgrade detection, (b) hardware-swap detection — a serial that changes at ' +
      'constant ppp_username is a replaced box — and (c) any user comment rendered on a `#` line. ' +
      'The rule is bounded to the preamble by a double anchor for exactly that reason.',
    layer: 1,
    kind: 'strip_line',
    pattern: '^#',
    applyOrder: 10,
    suppress: {
      before: '# 2026-01-02 10:33:21 by RouterOS 7.14\n/ip address add address=10.0.0.1/24 interface=bridge-lan',
      after: '# 2026-01-03 04:11:02 by RouterOS 7.14\n/ip address add address=10.0.0.1/24 interface=bridge-lan',
    },
    keep: {
      before: '# 2026-01-02 10:33:21 by RouterOS 7.14\n/ip address add address=10.0.0.1/24 interface=bridge-lan',
      after: '# 2026-01-02 10:33:21 by RouterOS 7.14\n/ip address add address=10.0.0.2/24 interface=bridge-lan',
      expect: { findings: 1, kind: 'changed' },
    },
  },
  {
    builtinKey: 'ros.line.unfold',
    name: 'N13 — join wrapped lines',
    description:
      'Joins a line ending in an odd number of backslashes with the next one, normalises CRLF to ' +
      'LF, strips trailing whitespace and the trailing blank line.',
    rationale:
      'With a pty, RouterOS wraps long lines at the terminal width, which would make the width of ' +
      'the collector\'s terminal an input to ncm_hash.',
    falseNegative:
      'None. But the rule does NOT excuse the cause: a continuation in a `terse` export means a ' +
      'pty was allocated, and the collector raises a warning so the transport gets fixed instead ' +
      'of the symptom being absorbed forever.',
    layer: 1,
    kind: 'canonicalize',
    pattern: '\\\\$',
    applyOrder: 20,
    suppress: {
      before: '/ip firewall filter add action=accept chain=input \\\n    connection-state=established,related',
      after: '/ip firewall filter add action=accept chain=input connection-state=established,related',
    },
    keep: {
      before: '/ip firewall filter add action=accept chain=input connection-state=established,related',
      after: '/ip firewall filter add action=drop chain=input connection-state=established,related',
      expect: { findings: 1, kind: 'changed', severity: 'critical' },
    },
  },
  {
    builtinKey: 'ros.id.drop',
    name: 'N04 — `.id` never crosses the parser',
    description: '`.id`, `.nextid` and friends are removed during tokenisation and have no field in the NCM.',
    rationale:
      'A RouterOS `.id` is a rank in an internal table. It changes on every insertion and on every ' +
      '`move`. A diff keyed on it reports three `changed` where one rule was inserted.',
    falseNegative:
      'None: `.id` carries no functional information. It stays indispensable at APPLY time ' +
      '(`/ip/firewall/filter/move`) but it is resolved then, on a fresh socket, and never read ' +
      'back from a snapshot — a `.id` read six hours ago and replayed is exactly the mechanism ' +
      'that deletes the wrong rule.',
    layer: 2,
    kind: 'canonicalize',
    applyOrder: 30,
    suppress: {
      before: '/ip firewall filter add .id=*1 action=drop chain=input',
      after: '/ip firewall filter add .id=*7 action=drop chain=input',
    },
    keep: {
      before: '/ip firewall filter add .id=*1 action=drop chain=input',
      after: '/ip firewall filter add .id=*1 action=accept chain=input',
      expect: { findings: 1, kind: 'changed', severity: 'critical' },
    },
  },
  {
    builtinKey: 'ros.token.unquote',
    name: 'N12 — unquote, unescape, NFC',
    description:
      'The tokeniser removes quoting and escaping and normalises free strings to Unicode NFC. ' +
      'The quoting never crosses layer 2.',
    rationale:
      'RouterOS quotes a value only when it has to, and the heuristic changed between versions ' +
      'and between `terse` and normal mode: `name=CPE-Lyon` and `name="CPE-Lyon"` are one identity.',
    falseNegative:
      'Two comments differing ONLY by Unicode composition become identical. No functional ' +
      'consequence — a comment does not forward a packet — and the alternative is a finding every ' +
      'time a technician types an accent from a different keyboard layout.',
    layer: 2,
    kind: 'canonicalize',
    applyOrder: 40,
    suppress: {
      before: '/system identity set name=CPE-Lyon',
      after: '/system identity set name="CPE-Lyon"',
    },
    keep: {
      before: '/system identity set name="CPE-Lyon"',
      after: '/system identity set name="CPE-Nantes"',
      expect: { findings: 1, kind: 'changed' },
    },
  },
  {
    builtinKey: 'ros.props.canonical-order',
    name: 'N08 — prop order is not information',
    description: 'A line becomes a map; the NCM serialises keys sorted before hashing.',
    rationale:
      'RouterOS emits props in the order of the menu\'s internal schema, which is stable for one ' +
      'version and CHANGES between versions when a prop is inserted in the middle. A textual diff ' +
      'sees an entirely modified line.',
    falseNegative: 'None. Prop order has no semantics in RouterOS.',
    layer: 2,
    kind: 'canonicalize',
    applyOrder: 50,
    suppress: {
      before: '/ip firewall filter add action=accept chain=input comment=mgmt',
      after: '/ip firewall filter add chain=input comment=mgmt action=accept',
    },
    keep: {
      before: '/ip firewall filter add action=accept chain=input comment=mgmt',
      after: '/ip firewall filter add action=accept chain=forward comment=mgmt',
      expect: { findings: 2 },
    },
  },
  {
    builtinKey: 'ros.emptysection.drop',
    name: 'N02 — an empty section is not a difference',
    description: 'Absence of a section and a section with zero entries are the same object.',
    rationale:
      'An empty menu produces nothing, or a lone `#`, or a bare menu line, depending on the ' +
      'version and the menu. On a CPE with no NAT rule the section appears and disappears across ' +
      'upgrades.',
    falseNegative:
      'None. This is a canonicalisation of REPRESENTATION, not a suppression: a section going ' +
      'from 3 entries to 0 still produces 3 `missing`.',
    layer: 3,
    kind: 'canonicalize',
    applyOrder: 60,
    suppress: {
      before: '/ip firewall nat\n/ip address add address=10.0.0.1/24 interface=bridge-lan',
      after: '/ip address add address=10.0.0.1/24 interface=bridge-lan',
    },
    keep: {
      before: '/ip firewall nat add action=masquerade chain=srcnat out-interface=ether1',
      after: '/ip firewall nat',
      expect: { findings: 1, kind: 'missing' },
    },
  },
  {
    builtinKey: 'ros.dynamic.exclude',
    name: 'N03 — dynamic entries are not configuration',
    description:
      'An entry carrying `dynamic=yes` is excluded from the diff. EXCEPT under `/ip/firewall/*`, ' +
      'where it is kept and downgraded instead.',
    rationale:
      'Learned routes, DHCP leases, PPP sessions and hotspot rules have no intention behind them: ' +
      'no template produces them, so an intent-versus-reality diff over them is structurally noise. ' +
      'Several of them already have a dedicated table (`ppp_sessions`, `discoveries`, `snmp_*`), ' +
      'and duplicating them into the NCM would create two truths.',
    falseNegative:
      'REAL, AND ASSUMED: a static firewall rule recreated as a dynamic one becomes invisible. ' +
      'That is why the firewall is the ONE place where the entry is not dropped but produces an ' +
      '`info` + `ignored` finding — visible in a query, absent from the drift count. The firewall ' +
      'is the only section where the risk justifies paying that cost.',
    layer: 3,
    kind: 'ignore_entry',
    predicate: { prop: 'dynamic', eq: true },
    applyOrder: 100,
    suppress: {
      before: '/ip route add dst-address=10.9.0.0/24 gateway=10.255.0.1 dynamic=yes',
      after: '',
    },
    keep: {
      before: '/ip route add dst-address=10.9.0.0/24 gateway=10.255.0.1',
      after: '',
      expect: { findings: 1, kind: 'missing', severity: 'high' },
    },
  },
  {
    builtinKey: 'ros.addresslist.timeout.exclude',
    name: 'N03b — address-list entries with a timeout',
    description:
      'Under `/ip/firewall/address-list`, an entry with a non-empty `timeout` is excluded even ' +
      'when `dynamic` is not set.',
    rationale:
      'An address-list fed by `add-src-to-address-list` changes several times a minute. With the ' +
      'export header it is the single largest potential noise generator in a fleet.',
    falseNegative:
      'A STATIC entry to which someone added a timeout by hand disappears from the diff. Accepted: ' +
      'with a timeout it is transient by definition.',
    layer: 3,
    kind: 'ignore_entry',
    sectionPath: '/ip/firewall/address-list',
    predicate: { prop: 'timeout', notEmpty: true },
    applyOrder: 101,
    suppress: {
      before: '/ip firewall address-list add address=203.0.113.9 list=blocked timeout=1h',
      after: '/ip firewall address-list add address=198.51.100.4 list=blocked timeout=1h',
    },
    keep: {
      before: '/ip firewall address-list add address=203.0.113.9 list=blocked',
      after: '/ip firewall address-list add address=198.51.100.4 list=blocked',
      expect: { findings: 2 },
    },
  },
  {
    builtinKey: 'ros.props.whitelist',
    name: 'N05 — the NCM is a whitelist, never a blacklist',
    description:
      'The typed model declares which props are retained per section; everything else falls, and ' +
      'every prop that falls WITHOUT being in the catalogue is counted in `ncm_unknown_props`.',
    rationale:
      'A blacklist would let a future firmware\'s counters into the model. `passthrough()` on the ' +
      'Zod schemas is forbidden for the same reason.',
    falseNegative:
      'THE REAL DIFFICULTY OF THIS RULE. A FUNCTIONAL prop added by a future version is not in the ' +
      'model and becomes invisible — the day `/ip/firewall/filter` gained `connection-nat-state`, ' +
      'a frozen whitelist would have ignored it and a NAT-aware rule would have passed under the ' +
      'radar. The MANDATORY mitigation is the unknown-prop counter, shipped the same day: an ' +
      'unknown prop produces a TICKET, not a finding. Without that counter this whitelist is a ' +
      'black hole and the milestone\'s noise/false-negative ratio is a lie.',
    layer: 3,
    kind: 'canonicalize',
    applyOrder: 110,
    suppress: {
      before: '/ip firewall filter add action=drop chain=input bytes=918273645 packets=1204',
      after: '/ip firewall filter add action=drop chain=input bytes=4 packets=1',
    },
    keep: {
      before: '/ip firewall filter add action=drop chain=input bytes=918273645',
      after: '/ip firewall filter add action=drop chain=input src-address=10.0.0.0/8 bytes=918273645',
      expect: { findings: 2 },
    },
  },
  {
    builtinKey: 'ros.comment.volatile-suffix',
    name: 'N10 — strip a dated suffix written by a third-party script',
    description:
      'Removes an END-ANCHORED dated suffix from a `comment` and leaves the rest untouched.',
    rationale:
      'Supervision scripts stamp the comment with a date (`- checked 2026-01-02 03:15`), which ' +
      'changes every day on every rule they touch.',
    falseNegative:
      'Someone who edits ONLY the dated suffix to hide information there is not reported. A comment ' +
      'forwards no packet; accepted. THE REAL RISK IS THE OTHER ONE: a badly anchored regex that ' +
      'eats the whole comment makes the best pairing key the firewall has unstable. Hence the ' +
      'anchor, and hence the lint that refuses any unanchored pattern on `comment`.',
    layer: 3,
    kind: 'rewrite_value',
    prop: 'comment',
    pattern: COMMENT_VOLATILE_SUFFIX,
    replacement: '',
    applyOrder: 120,
    suppress: {
      before: '/ip firewall filter add action=accept chain=input comment="WAN backup - checked 2026-01-02 03:15"',
      after: '/ip firewall filter add action=accept chain=input comment="WAN backup - checked 2026-01-03 03:15"',
    },
    keep: {
      before: '/ip firewall filter add action=accept chain=input comment="WAN backup - checked 2026-01-02 03:15"',
      after: '/ip firewall filter add action=accept chain=input comment="WAN principal - checked 2026-01-02 03:15"',
      expect: { findings: 1, kind: 'changed', severity: 'low' },
    },
  },
  {
    builtinKey: 'ros.comment.managed',
    name: 'N10b — `obliwan:` is a reserved, structural prefix',
    description:
      'A comment starting with `obliwan:<slug>` is parsed into ownership + free text. The marker ' +
      'is never rewritten and never ignored; it feeds `is_managed`.',
    rationale:
      'The marker is the strongest identity mechanism in the product: an anchored rule stays paired ' +
      'through a change of action, of selectors AND of comment. It is not decoration.',
    falseNegative:
      'A human comment that legitimately begins with `obliwan:` is misread as ObliWAN-owned. The ' +
      'prefix is therefore RESERVED, and a record carrying it that no job explains is a `high` ' +
      'finding rather than a silent one.',
    layer: 3,
    kind: 'canonicalize',
    applyOrder: 121,
    suppress: {
      before: '/ip firewall filter add action=accept chain=input comment="obliwan:mgmt-established" connection-state=established',
      after: '/ip firewall filter add action=accept chain=input comment="obliwan:mgmt-established note" connection-state=established',
    },
    keep: {
      before: '/ip firewall filter add action=accept chain=input comment="obliwan:mgmt-established"',
      after: '/ip firewall filter add action=drop chain=input comment="obliwan:mgmt-established"',
      expect: { findings: 1, kind: 'changed', severity: 'critical' },
    },
  },
  {
    builtinKey: 'ros.secret.absent',
    name: 'N11 — a secret is never compared',
    description:
      'The sensitive props declared in the catalogue never enter the NCM. They carry a ' +
      'fingerprint shape whose value is `unavailable`, on BOTH sides of the diff.',
    rationale:
      '`/export show-sensitive=no` is hard-wired (R10) and the RouterOS service account is denied ' +
      'the `sensitive` policy. There is no secret to compare, by construction.',
    falseNegative:
      'GRAVE, STRUCTURAL AND ASSUMED: A PASSWORD OR PSK CHANGE PRODUCES NO FINDING. It is the price ' +
      'of R10 and it is the right trade — bringing a fleet\'s PSKs into a database and a UI is a ' +
      'far worse risk. It is compensated, not hidden: the appearance of an unexpected local user ' +
      'IS detected, an auth method dropping from `psk` to none IS detected, and the drift screen ' +
      'must say in writing that secret VALUES are not compared. A user who believes the tool ' +
      'watches passwords is in more danger than one with no tool at all.',
    layer: 3,
    kind: 'mask_secret',
    applyOrder: 130,
    suppress: {
      before: '/ppp secret add name=site01 service=l2tp',
      after: '/ppp secret add name=site01 service=l2tp',
    },
    keep: {
      before: '/user add name=admin group=full',
      after: '/user add name=admin group=full\n/user add name=backdoor group=full',
      expect: { findings: 1, kind: 'extra', severity: 'critical' },
    },
  },
  {
    builtinKey: 'ros.comment.severity',
    name: 'N10c — a comment-only difference is `low`, never `high`',
    description: 'A finding whose only field diff is `comment` is downgraded to `low`. It stays VISIBLE.',
    rationale:
      'A comment does not forward a packet, so it cannot be a high-severity change. It is kept ' +
      'visible on purpose: a comment that changed is often the only trace of a human intervention, ' +
      'and the attribution engine (K6) uses it.',
    falseNegative:
      'A comment carrying operational meaning (a change ticket number, a "DO NOT REMOVE") is ' +
      'demoted with the rest. Accepted; it is still on screen.',
    layer: 4,
    kind: 'severity_override',
    prop: 'comment',
    severity: 'low',
    applyOrder: 200,
    suppress: {
      before: '/ip firewall filter add action=drop chain=input comment=a',
      after: '/ip firewall filter add action=drop chain=input comment=b',
      // Not zero findings: a severity override does not suppress. What it
      // proves is that the finding is not `high`.
    },
    keep: {
      before: '/ip firewall filter add action=drop chain=input comment=a',
      after: '/ip firewall filter add action=accept chain=input comment=a',
      expect: { findings: 1, kind: 'changed', severity: 'critical' },
    },
  },
  {
    builtinKey: 'ros.obliwan.owned',
    name: 'N14 — what ObliWAN itself put on the box',
    description:
      'An entry named `obliwan-*` or commented `obliwan:` produces an `info` + `ignored` finding ' +
      'while a change job of that device was active in the window, and a `high` one otherwise.',
    rationale:
      'From M6 ObliWAN places a rollback script and a startup scheduler on the router and removes ' +
      'them on disarm. A snapshot taken inside a change window sees them; the next day\'s does not.',
    falseNegative:
      'An attacker who prefixes their objects with `obliwan-` becomes discreet. Mitigated by the ' +
      'prefix being reserved AND by the correlation with `change_jobs`: an unexplained ' +
      '`obliwan-*` object is `high`, and the DISAPPEARANCE of one outside a disarm is `high` too ' +
      '(either someone removed the dead-man, or the disarm failed).',
    layer: 4,
    kind: 'severity_override',
    severity: 'info',
    applyOrder: 201,
    suppress: {
      before: '/system scheduler add name=obliwan-rollback on-event=":log info x" start-time=startup',
      after: '',
    },
    keep: {
      before: '/system scheduler add name=nightly-backup on-event=":log info x"',
      after: '',
      expect: { findings: 1, kind: 'missing', severity: 'high' },
    },
  },
  {
    builtinKey: 'ros.version.rebaseline',
    name: 'N15 — one tolerated run after a MAJOR version change',
    description:
      'When `config_snapshots.os_version` crosses a major boundary versus the previous snapshot of ' +
      'the same device, the whole diff is computed and stored but every finding is `info` + ' +
      '`ignored`, and the run is flagged "re-baseline required".',
    rationale:
      'RouterOS 6 and 7 render an identical intention very differently: wireless, BGP, OSPF and ' +
      'route filters were re-modelled, not renamed. A 6->7 upgrade produces a hundred textual ' +
      'differences for zero intentional changes.',
    falseNegative:
      'THIS IS THE MOST DANGEROUS RULE IN THE DOCUMENT AND IT MUST BE SAID: IT MASKS EVERYTHING, ' +
      'IN BLOCK, FOR A WINDOW. Its bounds are mandatory and are NOT yet implemented (the drift ' +
      'engine is a later workstream), which is why it ships DISABLED. Required before enabling: ' +
      '(a) triggered only by a version gap PROVEN by the preamble, never manually; (b) a window of ' +
      'exactly ONE run; (c) an exception list that stays `high` even during a re-baseline — a new ' +
      '`/user`, an enabled `/ip/service`, an `action=accept` in `chain=input`, a security profile ' +
      'dropping to `none`. Those are precisely the changes an upgrade is used to camouflage.',
    layer: 4,
    kind: 'suppress_finding',
    severity: 'info',
    applyOrder: 202,
    enabled: false,
    suppress: {
      before: '# jan/02/2026 10:33:21 by RouterOS 6.49.10\n/interface bridge add name=bridge-lan protocol-mode=rstp',
      after: '# 2026-01-03 10:33:21 by RouterOS 7.14\n/interface bridge add name=bridge-lan port-cost-mode=long protocol-mode=rstp',
    },
    keep: {
      before: '# jan/02/2026 10:33:21 by RouterOS 6.49.10\n/user add name=admin group=full',
      after: '# 2026-01-03 10:33:21 by RouterOS 7.14\n/user add name=admin group=full\n/user add name=backdoor group=full',
      expect: { findings: 1, kind: 'extra', severity: 'critical' },
    },
  },
];

// ============================================================================
// Generated rules
// ============================================================================

/** N06/N05 — one `ignore_prop` row per `(section, prop)`, generated from the
 *  same catalogue the parser reads so the two cannot drift apart. */
function generatedStateRules(startOrder: number): SeedRule[] {
  const out: SeedRule[] = [];
  let order = startOrder;
  for (const spec of ROUTEROS_SECTION_CATALOG) {
    for (const prop of spec.stateProps) {
      out.push(propRule(spec, prop, 'state', order++));
    }
    for (const prop of spec.counterProps) {
      if (spec.stateProps.includes(prop)) continue;
      out.push(propRule(spec, prop, 'counter', order++));
    }
  }
  return out;
}

function propRule(
  spec: RouterOsSectionSpec,
  prop: string,
  family: 'state' | 'counter',
  applyOrder: number,
): SeedRule {
  const kindLabel = family === 'counter' ? 'N05 counter' : 'N06 operational state';
  const sample = `${spec.sectionPath.split('/').slice(0, -1).join(' ')} ${spec.sectionPath.split('/').pop()}`;
  return {
    builtinKey: `ros.state.ignore:${spec.sectionPath}:${prop}`,
    name: `${kindLabel} — ${spec.sectionPath} ${prop}`,
    description: `Drops \`${prop}\` on \`${spec.sectionPath}\` before the NCM is built.`,
    rationale: `${spec.why} (${kindLabel})`,
    falseNegative: spec.falseNegative,
    layer: 3,
    kind: 'ignore_prop',
    sectionPath: spec.sectionPath,
    sectionOrdered: spec.ordered,
    prop,
    applyOrder,
    suppress: {
      before: `${sample} add ${prop}=1`,
      after: `${sample} add ${prop}=999999`,
    },
    keep: {
      before: `${sample} add ${prop}=1 disabled=no`,
      after: `${sample} add ${prop}=1 disabled=yes`,
      expect: { findings: 1, kind: 'changed' },
    },
  };
}

/** N07 — one `sort_set` row per UNORDERED section. The lint refuses `sort_set`
 *  on a section the catalogue declares ordered, which is the hard stop that
 *  keeps someone from quietly turning the firewall into a set. */
function generatedSortRules(startOrder: number): SeedRule[] {
  let order = startOrder;
  return ROUTEROS_SECTION_CATALOG.filter((s) => !s.ordered).map((spec) => ({
    builtinKey: `ros.section.unordered:${spec.sectionPath}`,
    name: `N07 — ${spec.sectionPath} is a set`,
    description:
      `Entries of \`${spec.sectionPath}\` are sorted by sem_key before hashing, and the diff never ` +
      'emits a `moved` for them.',
    rationale: spec.why,
    falseNegative:
      'TOTAL AND SILENT FOR THIS SECTION: reorderings there stop being reported, forever. That is ' +
      'why the ordered/unordered classification is a tested seed and not free-form data, why ' +
      'editing it needs DRIFT_MANAGE plus an audit entry, and why flipping a section from ordered ' +
      'to unordered is a `risk=high` gesture. This section is a set because ' + spec.why,
    layer: 3,
    kind: 'sort_set',
    sectionPath: spec.sectionPath,
    sectionOrdered: false,
    applyOrder: order++,
    suppress: {
      before: '/ip address add address=10.0.0.1/24 interface=bridge-lan\n/ip address add address=192.0.2.1/30 interface=ether1',
      after: '/ip address add address=192.0.2.1/30 interface=ether1\n/ip address add address=10.0.0.1/24 interface=bridge-lan',
    },
    keep: {
      before: '/ip address add address=10.0.0.1/24 interface=bridge-lan',
      after: '/ip address add address=10.0.0.1/25 interface=bridge-lan',
      expect: { findings: 2 },
    },
  }));
}

/** N09 — one `default_fill` row per seeded default. */
function generatedDefaultRules(startOrder: number): SeedRule[] {
  let order = startOrder;
  return SEEDED_ROUTEROS_DEFAULTS.map((d) => ({
    builtinKey: `ros.defaults.fill:${d.family}:${d.osVersion}:${d.sectionPath}:${d.prop}`,
    name: `N09 — ${d.sectionPath} ${d.prop} on ${d.osVersion}`,
    description:
      `Completes BOTH sides of the diff with \`${d.prop}=${d.value}\` on \`${d.sectionPath}\` for ` +
      `${d.family} ${d.osVersion}, so that "absent" and "present with the default" are one object.`,
    rationale: d.why,
    falseNegative:
      'IMPORTANT AND BOUNDED. If the dictionary claims a default of X while this model actually ' +
      'defaults to Y, an operator who explicitly sets X becomes indistinguishable from "did ' +
      'nothing". Bounds: never applied to a prop listed in `no_default_fill_props` (action, chain, ' +
      'disabled, addresses, gateways); never extrapolated to a firmware newer than the one ' +
      'observed; disabled entirely for a prop two devices of the same version disagree about ' +
      '(`conflicting`); and every fill is counted and shown in the masked finding\'s detail.',
    layer: 3,
    kind: 'default_fill',
    sectionPath: d.sectionPath,
    prop: d.prop,
    value: d.value,
    family: d.family,
    osMin: d.osVersion,
    applyOrder: order++,
    suppress: {
      before: `${d.sectionPath.replace(/\//g, ' ').trim().replace(/^(\w+)/, '/$1')} add name=x`,
      after: `${d.sectionPath.replace(/\//g, ' ').trim().replace(/^(\w+)/, '/$1')} add name=x ${d.prop}=${d.value}`,
    },
    keep: {
      before: `${d.sectionPath.replace(/\//g, ' ').trim().replace(/^(\w+)/, '/$1')} add name=x ${d.prop}=${d.value}`,
      after: `${d.sectionPath.replace(/\//g, ' ').trim().replace(/^(\w+)/, '/$1')} add name=x ${d.prop}=other`,
      expect: { findings: 1, kind: 'changed' },
    },
  }));
}

export function allSeedRules(): SeedRule[] {
  return [
    ...HAND_WRITTEN,
    ...generatedDefaultRules(300),
    ...generatedSortRules(400),
    ...generatedStateRules(1000),
  ];
}

// ============================================================================
// The seed
// ============================================================================

export async function seed(knex: Knex): Promise<void> {
  await seedSectionCatalog(knex);
  await seedDefaults(knex);
  await seedRules(knex);
}

async function seedSectionCatalog(knex: Knex): Promise<void> {
  for (const spec of ROUTEROS_SECTION_CATALOG) {
    const row = {
      section_path: spec.sectionPath,
      family: spec.family ?? '*',
      ordered: spec.ordered,
      order_group_prop: spec.orderGroupProp,
      sem_key_props: toPgArray(spec.semKeyProps),
      sem_key_fallback: spec.semKeyFallback ? toPgArray(spec.semKeyFallback) : null,
      sem_key_version: 1,
      secret_props: toPgArray(spec.secretProps),
      state_props: toPgArray(spec.stateProps),
      counter_props: toPgArray(spec.counterProps),
      no_default_fill_props: toPgArray(spec.noDefaultFillProps),
      default_severity: spec.defaultSeverity,
      ros6_path: spec.ros6Path,
      ros7_path: spec.ros7Path,
      ncm_resource_kind: spec.ncmResourceKind,
      updated_at: knex.fn.now(),
    };
    await knex('ncm_section_catalog')
      .insert(row)
      .onConflict(['section_path', 'family'])
      .merge();
  }
}

async function seedDefaults(knex: Knex): Promise<void> {
  for (const d of SEEDED_ROUTEROS_DEFAULTS) {
    // `learned_from='seed'` is the LOWEST tier of N09 on purpose. A row learned
    // from `/export terse verbose` on a real device must win over this one, so
    // an existing row is never overwritten here.
    await knex('routeros_defaults')
      .insert({
        family: d.family,
        os_version: d.osVersion,
        section_path: d.sectionPath,
        prop: d.prop,
        default_value: JSON.stringify(d.value),
        learned_from: 'seed',
        device_count: 0,
        conflicting: false,
      })
      .onConflict(['family', 'os_version', 'section_path', 'prop'])
      .ignore();
  }
}

async function seedRules(knex: Knex): Promise<void> {
  for (const rule of allSeedRules()) {
    const body = {
      // `NULL` = SHARED LIBRARY, visible to every tenant.
      //
      // This used to be `MASTER_TENANT_ID`, and that one literal WAS the
      // critical defect of audit M4/M5 F1: the readers filtered
      // `tenant_id = :tenantId` strictly, so every tenant except #1
      // normalised with an EMPTY rule set — layers 1..4 all no-ops, a new
      // `config_snapshots` row on every collection (the "row generator"
      // decision 1 of `007_config.ts` forbids), and phantom drift findings
      // on every run. Migration `013_normalization_shared.ts` made the
      // column nullable and moved the already-seeded doctrine across; this
      // line is what stops a FRESH install from re-creating the bug.
      //
      // Duplicating the doctrine per tenant was never available: `builtin_key`
      // is UNIQUE GLOBALLY (`007_config.ts`), so the second insert of
      // `ros.dynamic.exclude` would violate it. 013 turns that constraint
      // from an accident into the invariant (`nr_builtin_library_chk`:
      // only a library row may carry a `builtin_key`), which is also what
      // makes the tenant-less reconciliation below safe — see there.
      tenant_id: null,
      scope: 'global',
      scope_id: null,
      brand: 'mikrotik',
      family: rule.family ?? null,
      os_min: rule.osMin ?? null,
      os_max: null,
      name: rule.name,
      description: rule.description,
      rationale: rule.rationale,
      false_negative: rule.falseNegative,
      layer: rule.layer,
      kind: rule.kind,
      section_path: rule.sectionPath ?? null,
      section_ordered: rule.sectionOrdered ?? true,
      prop: rule.prop ?? null,
      pattern: rule.pattern ?? null,
      replacement: rule.replacement ?? null,
      predicate: rule.predicate === undefined ? null : JSON.stringify(rule.predicate),
      value: rule.value === undefined ? null : JSON.stringify(rule.value),
      target_path: rule.targetPath ?? null,
      severity: rule.severity ?? null,
      apply_order: rule.applyOrder,
      is_builtin: true,
      builtin_key: rule.builtinKey,
      requires_test: true,
      updated_at: knex.fn.now(),
    };

    // NO TENANT FILTER, and that is now guaranteed safe rather than merely
    // habitual: 013's `nr_builtin_library_chk` (`builtin_key IS NULL OR
    // tenant_id IS NULL`) means a row carrying a `builtin_key` can only be a
    // library row. Before that CHECK existed, a tenant that had typed
    // `ros.header.strip` into a rule of its own would have had that rule
    // silently overwritten by the next deployment — including its
    // `tenant_id`, which would have donated it to every other customer.
    const existing = await knex('normalization_rules')
      .where({ builtin_key: rule.builtinKey })
      .first('id');

    let id: number;
    if (existing) {
      // NON-CLOBBERING: `enabled`, `severity` and the counters are the
      // operator's, not ours. A rule someone disabled because it hid something
      // must not come back on with the next deployment.
      const { severity: _severity, ...refreshable } = body;
      await knex('normalization_rules').where({ id: existing.id }).update(refreshable);
      id = Number(existing.id);
    } else {
      const [inserted] = await knex('normalization_rules')
        .insert({ ...body, enabled: rule.enabled ?? true })
        .returning('id') as Array<{ id: number }>;
      id = Number(inserted.id);
    }

    await seedRuleTests(knex, id, rule);
  }
}

/**
 * D1 in the database: prove what the rule REMOVES, and prove what it LETS
 * THROUGH. The service refuses `enabled = true` without both.
 */
async function seedRuleTests(knex: Knex, ruleId: number, rule: SeedRule): Promise<void> {
  await knex('normalization_rule_tests').where({ rule_id: ruleId }).delete();
  await knex('normalization_rule_tests').insert([
    {
      rule_id: ruleId,
      kind: 'must_suppress',
      fixture_key: `${rule.builtinKey}/suppress`,
      input_before: rule.suppress.before,
      input_after: rule.suppress.after,
      expect: JSON.stringify({ findings: 0 }),
    },
    {
      rule_id: ruleId,
      kind: 'must_not_suppress',
      fixture_key: `${rule.builtinKey}/keep`,
      input_before: rule.keep.before,
      input_after: rule.keep.after,
      expect: JSON.stringify(rule.keep.expect ?? { findings: 1 }),
    },
  ]);
}

function toPgArray(values: readonly string[]): string {
  // Knex has no portable text[] literal helper; the values here are prop names
  // from a compiled-in catalogue, never user input.
  return `{${values.map((v) => `"${v.replace(/"/g, '\\"')}"`).join(',')}}`;
}
