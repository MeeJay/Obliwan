// ============================================================================
// @obliwan/shared — fleet take-over / Golden Site (M12 — K8)
// ============================================================================
//
// This is the adoption wall. Before it, ObliWAN asks an operator to hand-write
// templates for a fleet the operator did not build and does not remember. After
// it, the fleet writes the first draft of its own templates and tells you, per
// line, how many sites agree with it.
//
// ┌─ SIX DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ────────────────────┐
// │                                                                           │
// │ 1. NO LLM. ARCHITECTURE.md §5/M12 says it in the same breath as the       │
// │    algorithm: weighted Jaccard, hierarchical, in a worker. The reason is  │
// │    not cost, it is that a template draft has to be REPRODUCIBLE and       │
// │    EXPLAINABLE — "this line is in the template because 27 of your 30      │
// │    sites carry it" is auditable, and a model's opinion is not. Every      │
// │    function in this file is pure and deterministic, and the clustering    │
// │    that consumes it breaks ties by index so that two runs over the same   │
// │    snapshots produce byte-identical output.                               │
// │                                                                           │
// │ 2. A FACT IS A (SLOT, VALUE) PAIR, AND THE SLOT IS SITE-INDEPENDENT.      │
// │    That split IS the variable detection. Alignment happens on the slot;   │
// │    a slot whose value differs between two sites at the same place is,     │
// │    by definition, a variable. Nothing else in the pipeline needs to guess │
// │    what a variable is.                                                    │
// │                                                                           │
// │ 3. THE SLOT GENERALISES THE *ADDRESSES*, NEVER THE *STRUCTURE*.           │
// │    `10.20.0.0/24` and `10.30.0.0/24` collapse to `cidr:private` inside a  │
// │    slot, so the same firewall rule at two sites lines up. `ether1` and    │
// │    `ether2` do NOT collapse, and `vlan30` and `vlan40` do not either:     │
// │    those are different structures, and merging them would produce the     │
// │    template nobody can apply. This is the concrete form of the doctrine   │
// │    "more clusters, purer" — a naming divergence is allowed to split a     │
// │    cluster, because it really is a different site profile.                │
// │                                                                           │
// │ 4. NO SECRET, NOT EVEN A FINGERPRINT (§8.2, R10). `pskFingerprint`,       │
// │    `passwordFingerprint`, `communityFingerprint` and                      │
// │    `sshKeyFingerprints` are HMACs of live credentials. A baseline fact    │
// │    lands in a jsonb column, in a draft template body, in an API response  │
// │    and in an export — the exact four places §8.2 forbids. They are        │
// │    refused by name, by a list this file owns and a predicate the miner    │
// │    calls on every single attribute. `communityIsWellKnown` stays: it is   │
// │    a boolean about a community, not the community, and §7.2 of the NCM    │
// │    contract already carved it out as the one audit signal worth keeping.  │
// │                                                                           │
// │ 5. A DEVIATION IS CLASSIFIED, NEVER SILENTLY DROPPED. "Client             │
// │    specificity" is a first-class outcome that turns a deviation into a    │
// │    DOCUMENTED EXCEPTION with a mandatory reason, not into a suppression.  │
// │    A conformance score is therefore always reported twice: raw, and       │
// │    adjusted for the exceptions somebody signed for.                       │
// │                                                                           │
// │ 6. A MINED TEMPLATE IS A DRAFT, IN A FACT DIALECT, AND IT SAYS SO.        │
// │    This milestone owns no brand emitter — that is the M11 compiler. The   │
// │    body it produces is a reviewable list of facts with their support      │
// │    counters, carrying a header that states plainly it must be rewritten   │
// │    into brand syntax before publication. Publishing is TEMPLATE_WRITE and │
// │    a human; nothing here can publish anything.                            │
// └───────────────────────────────────────────────────────────────────────────┘

import { z } from 'zod';
import { NCM_RESOURCE_KINDS, type NcmResourceKind } from './ncm/resources';
import { parseCidr, parseIp } from './ncm/primitives';
import { sha256Short } from './ncm/hash';

/** Bumped on ANY change to the fact/slot algebra. A run carries the version it
 *  was mined with, because comparing a run mined under v1 with one mined under
 *  v2 is comparing two different questions. */
export const BASELINE_MODEL_VERSION = 1;

// ============================================================================
// 1. Vocabularies — kept in lockstep with migration 017's CHECK constraints
// ============================================================================

export const BASELINE_RUN_STATUSES = [
  'pending', 'running', 'succeeded', 'failed', 'cancelled',
] as const;
export type BaselineRunStatus = (typeof BASELINE_RUN_STATUSES)[number];

/**
 * What a slot turned out to be, once every member of the scope was aligned on
 * it.
 *
 *  'constant'  — every member that carries the slot carries the SAME value.
 *                It goes into the template body as a literal.
 *  'variable'  — the members disagree, one value each. It goes into the body
 *                as `{{ name }}` and into `var_schema`. This is the whole of
 *                "detection de variables par alignement inter-sites".
 *  'divergent' — a member carries SEVERAL values for the slot (a repeated
 *                structure we failed to key apart). Never templated: a
 *                divergent slot is reported so the operator can see the miner's
 *                blind spot rather than receive a template that quietly drops
 *                half a firewall.
 */
export const BASELINE_SLOT_ROLES = ['constant', 'variable', 'divergent'] as const;
export type BaselineSlotRole = (typeof BASELINE_SLOT_ROLES)[number];

/**
 *  'missing'        — the template carries the slot, this device does not.
 *  'extra'          — this device carries a slot the template does not.
 *  'value_conflict' — both carry it, the template pins a constant, the device
 *                     disagrees.
 */
export const BASELINE_DEVIATION_KINDS = ['missing', 'extra', 'value_conflict'] as const;
export type BaselineDeviationKind = (typeof BASELINE_DEVIATION_KINDS)[number];

/**
 * The four verdicts an operator may put on a deviation. `unclassified` is the
 * only one the miner may write; the other three are human acts.
 *
 *  'client_specific' — legitimate, this customer is different. Becomes a
 *                      documented exception with a mandatory reason and stops
 *                      counting against the adjusted conformance score.
 *  'to_remediate'    — the device is wrong. Feeds the plan, later.
 *  'template_gap'    — the TEMPLATE is wrong. Feeds the next mining round.
 */
export const BASELINE_DEVIATION_CLASSES = [
  'unclassified', 'client_specific', 'to_remediate', 'template_gap',
] as const;
export type BaselineDeviationClass = (typeof BASELINE_DEVIATION_CLASSES)[number];

export const BASELINE_DRAFT_STATUSES = ['draft', 'promoted', 'discarded'] as const;
export type BaselineDraftStatus = (typeof BASELINE_DRAFT_STATUSES)[number];

/**
 * Agglomeration linkage. Both are deterministic; `complete` is the default and
 * the doctrinal one — it merges two groups only when their WORST pair is close,
 * which is what "prefer more, purer clusters" means when written as a formula.
 * `average` is offered because a fleet with one eccentric site can otherwise be
 * blocked from ever merging, and an operator who sees that should be able to
 * say so without editing code.
 */
export const BASELINE_LINKAGES = ['complete', 'average'] as const;
export type BaselineLinkage = (typeof BASELINE_LINKAGES)[number];

/** Scope levels of a documented exception — same four-level vocabulary the rest
 *  of the schema uses for settings, assignments and variables. */
export const BASELINE_EXCEPTION_SCOPES = ['tenant', 'site', 'device'] as const;
export type BaselineExceptionScope = (typeof BASELINE_EXCEPTION_SCOPES)[number];

/**
 * The generalisation class of a value. Drives two things and nothing else: the
 * `var_schema` type a variable gets, and how a value is abstracted when it is
 * folded into a slot.
 */
export const BASELINE_VALUE_CLASSES = [
  'empty', 'boolean', 'integer', 'cidr', 'ip', 'iface', 'fqdn', 'set', 'literal',
] as const;
export type BaselineValueClass = (typeof BASELINE_VALUE_CLASSES)[number];

// ============================================================================
// 2. Secrets — the refusal list, and the predicate that enforces it
// ============================================================================

/**
 * NCM attribute names that carry credential-derived material. §8.2 is a list of
 * four places a secret may never reach — a log, a diff, an export, a jsonb
 * column, an API response — and a baseline fact reaches all of them.
 *
 * These are FINGERPRINTS, not secrets, and they are still refused. A stable
 * HMAC of a password, replicated across a fleet's worth of facts and served to
 * a UI, is an oracle: it says "these eleven sites share one root password" to
 * anyone who can read a drafts screen. The last audit found the L2TP passwords
 * of an entire fleet in a jsonb column served to the UI; this list is what stops
 * the fingerprint version of that finding.
 */
export const BASELINE_FORBIDDEN_ATTRIBUTES: readonly string[] = [
  'pskFingerprint',
  'passwordFingerprint',
  'communityFingerprint',
  'sshKeyFingerprints',
  'secret',
  'password',
  'psk',
  'preSharedKey',
  'privateKey',
  'community',
];

const FORBIDDEN_LOWER = new Set(BASELINE_FORBIDDEN_ATTRIBUTES.map((a) => a.toLowerCase()));

/**
 * Called by the miner on EVERY attribute it is about to turn into a fact, and
 * again by the persistence layer before a batch insert. Two call sites for one
 * rule is deliberate: the first is the design, the second is what survives
 * somebody adding a resource kind and forgetting the first.
 */
export function isForbiddenBaselineAttribute(attribute: string): boolean {
  const a = attribute.toLowerCase();
  if (FORBIDDEN_LOWER.has(a)) return true;
  // Substring pass for names we did not enumerate: `wpaPassphrase`,
  // `radiusSecret`, `apiKey`. A false positive costs one missing fact in a
  // draft; a false negative costs a fleet's credentials on a screen.
  return (
    a.includes('password') || a.includes('passphrase') || a.includes('secret') ||
    a.includes('psk') || a.includes('credential') || a.includes('apikey') ||
    a.includes('privatekey') || a.includes('fingerprint')
  );
}

/**
 * A slot is `section/discriminator/attribute`. Only the LAST segment is checked,
 * and the narrowness is deliberate: the discriminator is built from names the
 * CUSTOMER chose. A local user called `secretary`, an interface called
 * `pskbridge` or a DHCP scope called `credential-lab` contains one of the
 * refused tokens and is not a secret — rejecting those slots would silently
 * amputate a real customer's baseline and look like a mining bug. The attribute
 * is the half ObliWAN writes, so it is the half the refusal governs.
 *
 * Kept in exact lockstep with `baseline_slots_slot_secret_chk` in migration 017,
 * which anchors the same token list on the same final segment.
 */
export function slotIsForbidden(slot: string): boolean {
  const attribute = slot.slice(slot.lastIndexOf('/') + 1);
  return isForbiddenBaselineAttribute(attribute);
}

// ============================================================================
// 3. Weights — what makes two sites "the same site"
// ============================================================================

/**
 * Jaccard weight per resource kind. A fleet whose sites all run the same DHCP
 * options but disagree on every firewall rule is NOT one profile, and an
 * unweighted Jaccard would say it is, because DHCP options are numerous and
 * firewall chains are few. The weights therefore follow forwarding relevance,
 * which is the same ordering K2 uses to decide what it is allowed to prove.
 */
export const BASELINE_SECTION_WEIGHTS: Readonly<Record<NcmResourceKind, number>> = {
  firewallRule: 3,
  // A DHCP client decides whether this box has a default route and a resolver
  // at all — forwarding-relevant, but one object, not a chain.
  dhcpClient: 1.5,
  natRule: 3,
  route: 2.5,
  ipsecPeer: 2,
  interface: 2,
  vlan: 2,
  dhcpScope: 1.5,
  service: 1.5,
  qosRule: 1,
  localUser: 1,
};

/**
 * Weighted Jaccard over two slot SETS (never over values — two sites with the
 * same structure and different addresses must be near each other, or the
 * variable detection of decision 2 has nothing to detect).
 *
 * Returns 1 for two empty sets: two devices we could read nothing from are not
 * "maximally different", they are indistinguishable, and pretending otherwise
 * scatters unreadable devices across every cluster.
 */
export function weightedJaccard(
  a: ReadonlySet<string>,
  b: ReadonlySet<string>,
  weightOf: (slot: string) => number,
): number {
  if (a.size === 0 && b.size === 0) return 1;
  let inter = 0;
  let union = 0;
  for (const slot of a) {
    const w = weightOf(slot);
    union += w;
    if (b.has(slot)) inter += w;
  }
  for (const slot of b) {
    if (!a.has(slot)) union += weightOf(slot);
  }
  return union === 0 ? 1 : inter / union;
}

// ============================================================================
// 4. Values: classification and generalisation
// ============================================================================

const V4_PRIVATE = [
  { net: [10, 0, 0, 0], bits: 8 },
  { net: [172, 16, 0, 0], bits: 12 },
  { net: [192, 168, 0, 0], bits: 16 },
  { net: [100, 64, 0, 0], bits: 10 },   // CGNAT — a WAN address at an MSP
  { net: [169, 254, 0, 0], bits: 16 },
];

function isPrivateV4(bytes: Uint8Array): boolean {
  for (const { net, bits } of V4_PRIVATE) {
    let ok = true;
    for (let i = 0; i < 4; i++) {
      const keep = Math.min(8, Math.max(0, bits - i * 8));
      const mask = keep === 0 ? 0 : (0xff << (8 - keep)) & 0xff;
      if ((bytes[i] & mask) !== (net[i] & mask)) { ok = false; break; }
    }
    if (ok) return true;
  }
  return false;
}

/** Deterministic. The `set` class is checked first because a joined selector
 *  (`cidr:… cidr:…`) would otherwise be classified by its first atom. */
export function classifyBaselineValue(value: string): BaselineValueClass {
  if (value === '') return 'empty';
  if (value.includes(' ')) return 'set';
  if (value === 'true' || value === 'false') return 'boolean';
  if (/^-?\d{1,18}$/.test(value)) return 'integer';
  const colon = value.indexOf(':');
  if (colon > 0) {
    const tag = value.slice(0, colon);
    if (tag === 'cidr') return 'cidr';
    if (tag === 'ip' || tag === 'range') return 'ip';
    if (tag === 'iface' || tag === 'ifaceList') return 'iface';
    if (tag === 'fqdn') return 'fqdn';
  }
  if (parseCidr(value)) return 'cidr';
  if (parseIp(value)) return 'ip';
  return 'literal';
}

/**
 * Decision 3, in one function. Folds a value down to the coarsest token that
 * still distinguishes two STRUCTURES, so that the same rule at two sites
 * produces the same slot.
 *
 *   'cidr:10.20.0.0/24'   -> 'cidr:private/24'
 *   'cidr:0.0.0.0/0'      -> 'cidr:any'
 *   'ip:203.0.113.7'      -> 'ip:public'
 *   'iface:ether1'        -> 'iface:ether1'      (structure, kept verbatim)
 *   'fqdn:vpn.acme.net'   -> 'fqdn:*'
 *   'any'                 -> 'any'
 *
 * The prefix LENGTH is kept for CIDRs on purpose: a site addressed in /24 and a
 * site addressed in /16 are not running the same design, and collapsing them
 * hides exactly the kind of difference that later makes a push wrong.
 */
export function generalizeBaselineValue(value: string): string {
  if (value === '' || value === 'any') return value;
  if (value.includes(' ')) {
    return value.split(' ').map(generalizeBaselineValue).join(' ');
  }
  const colon = value.indexOf(':');
  const tag = colon > 0 ? value.slice(0, colon) : '';
  const rest = colon > 0 ? value.slice(colon + 1) : value;

  if (tag === 'cidr' || (!tag && parseCidr(value))) {
    const parsed = parseCidr(rest);
    if (!parsed) return 'cidr:*';
    if (parsed.prefix === 0) return 'cidr:any';
    const scope = parsed.version === 4
      ? (isPrivateV4(parsed.bytes) ? 'private' : 'public')
      : 'v6';
    return `cidr:${scope}/${parsed.prefix}`;
  }
  if (tag === 'ip' || tag === 'range' || (!tag && parseIp(value))) {
    const first = rest.split('-')[0];
    const parsed = parseIp(first);
    if (!parsed) return `${tag || 'ip'}:*`;
    const scope = parsed.version === 4
      ? (isPrivateV4(parsed.bytes) ? 'private' : 'public')
      : 'v6';
    return `${tag || 'ip'}:${scope}`;
  }
  if (tag === 'fqdn') return 'fqdn:*';
  if (tag === 'mac') return 'mac:*';
  // 'iface:', 'ifaceList:', 'ref:' and every bare token: structure. Verbatim.
  return value;
}

// ============================================================================
// 5. Slots and variable names
// ============================================================================

/** `^[a-z][a-zA-Z0-9_]{0,119}$` — migration 008's `config_variables.key` shape.
 *  A mined variable that cannot be promoted to a config variable is a variable
 *  that cannot be filled, so the constraint is enforced HERE and not discovered
 *  at the INSERT. */
const VARIABLE_KEY_MAX = 120;

/**
 * Slot -> variable key. Deterministic and total.
 *
 * `disambiguate` appends a hash of the full slot; the miner sets it when two
 * distinct slots would otherwise claim one name (which happens as soon as a
 * slot segment contains a character the key shape forbids and both segments
 * sanitise to the same thing).
 */
export function slotToVarName(slot: string, disambiguate = false): string {
  let base = slot.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  if (base === '' || !/^[a-z]/.test(base)) base = `v_${base}`;
  if (disambiguate) {
    const suffix = `_${sha256Short(slot).slice(0, 8)}`;
    base = base.slice(0, VARIABLE_KEY_MAX - suffix.length) + suffix;
  } else if (base.length > VARIABLE_KEY_MAX) {
    const suffix = `_${sha256Short(slot).slice(0, 8)}`;
    base = base.slice(0, VARIABLE_KEY_MAX - suffix.length) + suffix;
  }
  return base;
}

/** The section a slot belongs to is its first segment. Kept as a function so
 *  nothing downstream re-derives it by string surgery. */
const SECTION_BY_PREFIX = new Map<string, NcmResourceKind>(
  NCM_RESOURCE_KINDS.map((k) => [k, k] as [string, NcmResourceKind]),
);

export function sectionOfSlot(slot: string): NcmResourceKind | null {
  const head = slot.slice(0, Math.max(0, slot.indexOf('/')));
  return SECTION_BY_PREFIX.get(head) ?? null;
}

/** JSON Schema fragment for a mined variable, by value class. Consumed as-is by
 *  `template_revisions.var_schema`, which ajv validates at render time. */
export function varSchemaFor(klass: BaselineValueClass): Record<string, unknown> {
  switch (klass) {
    case 'boolean':
      return { type: 'boolean' };
    case 'integer':
      return { type: 'integer' };
    case 'cidr':
      return { type: 'string', minLength: 4, maxLength: 49, pattern: '^[0-9A-Fa-f.:]+/[0-9]{1,3}$' };
    case 'ip':
      return { type: 'string', minLength: 3, maxLength: 64 };
    case 'iface':
      return { type: 'string', minLength: 1, maxLength: 96 };
    case 'fqdn':
      return { type: 'string', minLength: 1, maxLength: 255 };
    case 'set':
      return { type: 'string', maxLength: 1024 };
    case 'empty':
    case 'literal':
    default:
      return { type: 'string', maxLength: 512 };
  }
}

// ============================================================================
// 6. Parameters
// ============================================================================

/**
 * Every knob the miner has, with the defaults the acceptance test runs on.
 * Exposed on the API so a run is reproducible from its own stored parameters —
 * a run that cannot be replayed is not evidence.
 */
export const BaselineParams = z.object({
  /** Hard ceiling on proposed clusters. ARCHITECTURE.md's acceptance test says
   *  four for fifty heterogeneous configs. */
  maxClusters: z.number().int().min(1).max(24).default(4),
  /**
   * The purity gate. A cluster is acceptable only when EVERY member has at
   * least this fraction of its facts explained by the cluster's template.
   * The number of clusters is the smallest k in 1..maxClusters that clears it —
   * so k grows only to buy purity, which is "prefer more, purer clusters"
   * expressed as a stopping rule rather than as a taste.
   */
  minCoverage: z.number().min(0.5).max(1).default(0.8),
  /** A fact enters the template body when this fraction of the cluster's
   *  members carry it. Below it, it is a deviation to classify, not a line to
   *  push. 1.0 would make one eccentric site erase a line 29 sites share. */
  bodyPresenceRatio: z.number().min(0.5).max(1).default(0.8),
  linkage: z.enum(BASELINE_LINKAGES).default('complete'),
  /** Devices whose newest snapshot is older than this are excluded and SAID to
   *  be excluded. Mining a fleet against a config nobody has confirmed in a
   *  year produces a confident template about a fleet that no longer exists. */
  maxSnapshotAgeDays: z.number().int().min(1).max(3650).default(365),
  /** Restrict the run to one brand. A template body is brand-specific
   *  (migration 008, `templates.brand NOT NULL`), so a cluster that spans two
   *  brands could not become one template anyway. */
  brand: z.string().max(24).nullable().default(null),
  /** Restrict the run to a device group / site subset. Empty = the whole
   *  tenant's managed fleet. */
  deviceIds: z.array(z.number().int().positive()).max(2000).default([]),
}).strict();
export type BaselineParams = z.infer<typeof BaselineParams>;

export const BASELINE_DEFAULT_PARAMS: BaselineParams = BaselineParams.parse({});

// ============================================================================
// 7. The shapes the API returns
// ============================================================================

/** One atomic fact: WHERE (site-independent) and WHAT (verbatim). */
export interface BaselineFact {
  slot: string;
  section: NcmResourceKind;
  value: string;
  klass: BaselineValueClass;
}

export interface BaselineSlotStat {
  slot: string;
  section: NcmResourceKind;
  role: BaselineSlotRole;
  /** "present on 27/30" — the counter §5/M12 asks for by name. */
  presentOn: number;
  memberCount: number;
  distinctValues: number;
  /** Non-null exactly when role === 'constant'. */
  constantValue: string | null;
  /** Non-null exactly when role === 'variable'. */
  varName: string | null;
  valueClass: BaselineValueClass;
  /** At most 8, sorted, for the UI. Never for a secret-bearing slot — those
   *  never become facts at all. */
  sampleValues: string[];
}

export interface BaselineClusterSummary {
  id: number;
  clusterIndex: number;
  label: string;
  memberCount: number;
  medoidDeviceId: number | null;
  /** Mean intra-cluster weighted Jaccard similarity. 1 = identical structures. */
  cohesion: number;
  coverageMin: number;
  coverageMean: number;
  purityOk: boolean;
}

export interface BaselineDeviationRow {
  id: number;
  deviceId: number;
  clusterId: number | null;
  slot: string;
  section: NcmResourceKind;
  kind: BaselineDeviationKind;
  templateValue: string | null;
  deviceValue: string | null;
  classification: BaselineDeviationClass;
  note: string | null;
}

export interface BaselineConformanceRow {
  deviceId: number;
  clusterId: number | null;
  factsTotal: number;
  factsCovered: number;
  deviations: number;
  /** Signed-for deviations that are IN the denominator: `extra` and
   *  `value_conflict`, i.e. facts this device carries that the template does
   *  not explain. The ONLY excusals `scoreAdjusted` may credit. */
  excused: number;
  /** Signed-for `missing` deviations: template slots this device does not
   *  carry. Reportable — "you signed for 20 slots this site does not have" is
   *  a thing an operator wants to see — but never a conformance number: they
   *  were never counted in `factsTotal`, so crediting them is how a site with
   *  five unexplained drifts reads as 100 % conformant. */
  excusedMissing: number;
  /** covered / total. What the fleet actually looks like. */
  scoreRaw: number;
  /** (covered + excused) / total. What it looks like once somebody has signed
   *  for each difference. The two are always reported together: a single number
   *  invites the reader to assume the flattering one. */
  scoreAdjusted: number;
}

// ============================================================================
// 8. The draft body dialect
// ============================================================================

/**
 * Decision 6. The header is not decoration: this body will be sitting in
 * `template_revisions.body` with `status = 'draft'`, and the next person to
 * open it has to know in the first three lines that it is not RouterOS yet.
 */
export function baselineDraftHeader(
  label: string,
  memberCount: number,
  brand: string,
  coverageMean: number,
): string {
  return [
    '{#',
    '  ObliWAN baseline draft (M12 / K8) — MINED, NOT AUTHORED.',
    `  Cluster: ${label} — ${memberCount} member device(s) — brand: ${brand}`,
    `  Mean fact coverage of its members: ${(coverageMean * 100).toFixed(1)}%`,
    '',
    '  Each line below is ONE atomic fact mined from config_snapshots, in the',
    '  form `slot = value`, with the number of cluster members that carry it.',
    '  `{{ name }}` marks a value that differs between members at the same slot',
    '  — that is what makes it a variable, and it is declared in var_schema.',
    '',
    '  THIS IS NOT BRAND SYNTAX. It must be rewritten into a RouterOS (or other',
    '  brand) body before this revision may be published. Publishing is',
    '  TEMPLATE_WRITE and a human decision; the miner cannot publish anything.',
    '#}',
  ].join('\n');
}

/** One body line. `{{ }}` for a variable, the literal for a constant. */
export function baselineDraftLine(stat: BaselineSlotStat): string {
  const rhs = stat.role === 'variable' ? `{{ ${stat.varName} }}` : stat.constantValue ?? '';
  const support = `{# present on ${stat.presentOn}/${stat.memberCount} #}`;
  return `${stat.slot} = ${rhs}    ${support}`;
}
