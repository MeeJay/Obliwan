/**
 * ObliWAN — the normalisation engine: RouterOS text in, `NcmDocument` out.
 *
 * Implements `docs/M4-normalisation-routeros.md` §1 (the L0..L4 pipeline), §3
 * (the N01–N16 catalogue), §4 (`sem_key`) and §5.5 (the TypeScript contract),
 * against the frozen NCM contract in `shared/src/ncm/`.
 *
 * ┌─ WHAT THIS FILE IS FOR, IN ONE SENTENCE ──────────────────────────────────┐
 * │ Two exports of the SAME unchanged router must produce the SAME ncm_hash,  │
 * │ and one real change must still produce exactly one finding.               │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * THE ASYMMETRY THAT GOVERNS EVERY DECISION BELOW (§0/D1 of the study). Too
 * much noise and nobody reads the drift screen. Too much normalisation and the
 * tool says "in sync" about a router somebody changed in Winbox. The second is
 * WORSE, because noise is visible and a false negative is not. So every rule
 * here carries, in a comment, the change it can hide. A rule without that
 * comment has no business in the product, and the database enforces the same
 * thing with `rationale`/`false_negative` NOT NULL.
 *
 * WHERE THE NOISE IS ACTUALLY KILLED, in order of contribution (§9 of the
 * study): the semantic key and the per-chain ordering (in `shared/src/ncm`),
 * then the whitelist model built here, then the handful of editable rules in
 * `normalization_rules`. The table is the ABSORBER for what the model did not
 * foresee — an install that accumulates 200 hand-written rules is an install
 * whose NCM model is wrong.
 */

import type { Knex } from 'knex';
import {
  ANY_SELECTOR,
  EMPTY_MATCH,
  NCM_RESOURCE_KINDS,
  NCM_VERSION,
  SEM_KEY_GENERATION,
  UNAVAILABLE_SECRET,
  addressAtom,
  buildOrderSignature,
  canonicalizeCidr,
  compareNormalizationRules,
  computeMatchHash,
  computeNormalizationEpoch,
  dhcpReservationKey,
  dhcpScopeKey,
  interfaceKey,
  ipsecPeerKey,
  localUserKey,
  macAtom,
  ncmHash,
  normalizeBoolean,
  normalizePortSet,
  normalizeProtocol,
  normalizeSelector,
  normalizeTokenSet,
  orderedRuleKey,
  parseCidr,
  parseComment,
  parsePortExpression,
  qosRuleKey,
  rangeAtom,
  routeKey,
  serviceKey,
  vlanKey,
  type CoverageState,
  type DeviceFamily,
  type EntryPredicate,
  type NcmCoverage,
  type NcmCoverageMap,
  type NcmDhcpReservation,
  type NcmDhcpScope,
  type NcmDocument,
  type NcmFirewallRule,
  type NcmInterface,
  type NcmIpsecPeer,
  type NcmLocalUser,
  type NcmMatch,
  type NcmNatRule,
  type NcmOrderedRule,
  type NcmQosRule,
  type NcmResourceKind,
  type NcmRoute,
  type NcmService,
  type NcmUnmodeled,
  type NcmVlan,
  type NormalizationRule,
  type NormalizationTrace,
  type OrderAnalysisState,
  type PortSet,
  type Selector,
  type TransportKind,
} from '@obliwan/shared';
import {
  parseExport,
  canonicalizeText,
  unfoldLines,
  type ParsedExport,
  type RouterOsEntry,
} from '../drivers/mikrotik/parse';
import {
  CONFIG_LOOKING_LIKE_STATE,
  FIREWALL_ACTION_MAP,
  INTERFACE_TYPE_BY_SECTION,
  NAT_ACTION_MAP,
  SERVICE_NAME_MAP,
  UNIVERSAL_STATE_PROPS,
  aliasSection,
  isDynamicEntry,
  isForwardingRelevant,
  sectionSpec,
} from '../drivers/mikrotik/quirks';

// ============================================================================
// Context and result (§5.5 of the study)
// ============================================================================

export interface NormalizeContext {
  deviceId: number;
  tenantId: number;
  family: DeviceFamily;
  /** From the export preamble when present; `null` disables `default_fill`
   *  entirely, because the dictionary is indexed by EXACT version and an
   *  extrapolated default is a fleet-wide false negative. */
  osVersion: string | null;
  /** Already sorted by `compareNormalizationRules`. The engine does not
   *  re-sort: two sorts is two orders waiting to disagree. */
  rules: NormalizationRule[];
  /** `'<sectionPath>|<prop>' -> value`, from `routeros_defaults`, filtered to
   *  the exact `osVersion` and to `conflicting = false`. */
  defaults: Map<string, string>;
  via: TransportKind;
  capturedAt?: string;
  /**
   * §3.4 case 2. Ordinals are assigned by pairing with the PREVIOUS snapshot,
   * so that inserting a rule whose predicate already exists costs one `extra`
   * instead of cascading false `changed` down the whole collision class.
   * Absent (first snapshot, or a multi-day collection gap) the assignment falls
   * back to absolute order, which is the documented residual limit.
   */
  previous?: NcmDocument | null;
}

export interface NormalizeResult {
  ncm: NcmDocument;
  ncmHash: string;
  osVersion: string | null;
  model: string | null;
  serial: string | null;
  /** ALWAYS produced. This is what answers "why is this router in_sync when I
   *  just changed it?" by naming the rule responsible. Without it the first bad
   *  normalisation in production costs a day of investigation and the
   *  operator's trust in the tool. */
  traces: NormalizationTrace[];
  /**
   * N05. The whitelist model would be a silent black hole without this: a prop
   * a future firmware adds is invisible to the diff, and the only way that is
   * acceptable is if it produces a TICKET. Feeds `ncm_unknown_props`.
   */
  unknownProps: Array<{ sectionPath: string; prop: string; sample: string }>;
  warnings: string[];
  /** Per-lever instrumentation for the milestone's noise budget. */
  stats: {
    entries: number;
    dynamicEntriesExcluded: number;
    statePropsDropped: number;
    counterPropsDropped: number;
    defaultsFilled: number;
    unmodeledSections: number;
    ordinalCollisionRate: number;
  };
}

// ============================================================================
// Database access
// ============================================================================

/**
 * The frozen resolution order of §5.1, in SQL, mirrored by
 * `compareNormalizationRules` in `shared`. Both exist because the engine sorts
 * in memory after merging scopes and the database must not hand back a
 * different order to the rule editor.
 *
 *   layer ASC, scope specificity ASC, apply_order ASC, id ASC
 *
 * The MOST specific rule applies LAST, so it can correct the more general one.
 */
export async function loadNormalizationRules(
  db: Knex,
  opts: {
    tenantId: number;
    brand: string;
    family: DeviceFamily;
    groupIds?: number[];
    deviceId?: number;
  },
): Promise<NormalizationRule[]> {
  const rows = await db('normalization_rules')
    .where({ tenant_id: opts.tenantId, enabled: true })
    .andWhere((q) => {
      void q.whereNull('brand').orWhere('brand', opts.brand);
    })
    .andWhere((q) => {
      void q.whereNull('family').orWhere('family', opts.family);
    })
    .andWhere((q) => {
      void q
        .whereIn('scope', ['global', 'brand'])
        .orWhere((s) => {
          void s.where('scope', 'group').whereIn('scope_id', opts.groupIds ?? []);
        })
        .orWhere((s) => {
          void s.where('scope', 'device').where('scope_id', opts.deviceId ?? -1);
        });
    })
    .orderBy([{ column: 'layer' }, { column: 'apply_order' }, { column: 'id' }]);

  return rows.map(rowToRule).sort(compareNormalizationRules);
}

function rowToRule(r: Record<string, unknown>): NormalizationRule {
  return {
    id: Number(r.id),
    uuid: String(r.uuid),
    builtinKey: (r.builtin_key as string | null) ?? null,
    scope: r.scope as NormalizationRule['scope'],
    scopeId: r.scope_id === null || r.scope_id === undefined ? null : Number(r.scope_id),
    brand: (r.brand as NormalizationRule['brand']) ?? null,
    family: (r.family as NormalizationRule['family']) ?? null,
    osMin: (r.os_min as string | null) ?? null,
    osMax: (r.os_max as string | null) ?? null,
    name: String(r.name),
    description: String(r.description),
    rationale: String(r.rationale),
    falseNegative: String(r.false_negative),
    layer: Number(r.layer) as NormalizationRule['layer'],
    kind: r.kind as NormalizationRule['kind'],
    sectionPath: (r.section_path as string | null) ?? null,
    sectionOrdered: Boolean(r.section_ordered),
    prop: (r.prop as string | null) ?? null,
    pattern: (r.pattern as string | null) ?? null,
    replacement: (r.replacement as string | null) ?? null,
    predicate: (r.predicate as EntryPredicate | null) ?? null,
    value: r.value ?? null,
    targetPath: (r.target_path as string | null) ?? null,
    severity: (r.severity as NormalizationRule['severity']) ?? null,
    applyOrder: Number(r.apply_order),
    enabled: Boolean(r.enabled),
  };
}

/**
 * The N09 dictionary, for ONE exact firmware version.
 *
 * `conflicting = true` rows are excluded: two devices on the same version that
 * disagree about a "default" prove it is not one (it depends on the model or
 * the hardware), and filling it would manufacture a false negative on every
 * device of that model.
 */
export async function loadRouterOsDefaults(
  db: Knex,
  family: DeviceFamily,
  osVersion: string | null,
): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  if (!osVersion) return out;      // never extrapolate
  const rows = await db('routeros_defaults')
    .where({ family, os_version: osVersion, conflicting: false })
    .select('section_path', 'prop', 'default_value');
  for (const r of rows as Array<Record<string, unknown>>) {
    out.set(`${String(r.section_path)}|${String(r.prop)}`, jsonToScalar(r.default_value));
  }
  return out;
}

function jsonToScalar(v: unknown): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return JSON.stringify(v);
}

// ============================================================================
// The pipeline
// ============================================================================

export function normalizeRouterOsExport(raw: string, ctx: NormalizeContext): NormalizeResult {
  const traces: NormalizationTrace[] = [];
  const warnings: string[] = [];

  // ── L1 ────────────────────────────────────────────────────────────────────
  const l1 = applyLayer1(raw, ctx.rules, traces, warnings);

  // ── L2 ────────────────────────────────────────────────────────────────────
  const parsed = parseExport(l1);
  warnings.push(...parsed.warnings);

  // ── L3 ────────────────────────────────────────────────────────────────────
  const prepared = applyLayer3(parsed, ctx, traces, warnings);

  // ── build ─────────────────────────────────────────────────────────────────
  const result = buildDocument(parsed, prepared, ctx, traces, warnings);
  // A per-entry warning ("default_fill refused for …") is a statement about the
  // RULESET, not about the entry, and repeating it once per route buries the
  // rest. Deduplicated at the end so the order of first occurrence is kept.
  result.warnings = Array.from(new Set(result.warnings));
  return result;
}

// ----------------------------------------------------------------------------
// L1 — raw text
// ----------------------------------------------------------------------------

/**
 * The two builtin L1 rules (`ros.header.strip`, `ros.line.unfold`) are
 * implemented in `parse.ts` and their database rows exist for accountability
 * and counters, not for dispatch: a regex that can be disabled must not be able
 * to change what a version string is parsed from.
 *
 * A HAND-WRITTEN L1 rule is applied here, generically, behind the §6.4 lint —
 * anchored pattern, and a hard refusal past 5 % of the file's lines. D3 is
 * explicit that L1 is where a regex eats something it does not understand, and
 * a rule that eats 40 % of an export is almost certainly wrong.
 */
const L1_LINE_BUDGET = 0.05;

function applyLayer1(
  raw: string,
  rules: readonly NormalizationRule[],
  traces: NormalizationTrace[],
  warnings: string[],
): string {
  const custom = rules.filter(
    (r) => r.layer === 1 && r.kind === 'strip_line' && r.builtinKey !== 'ros.header.strip',
  );
  if (custom.length === 0) return raw;

  let lines = canonicalizeText(raw);
  const total = lines.length || 1;

  for (const rule of custom) {
    if (!rule.pattern) continue;
    if (!/^\^|\$$/.test(rule.pattern)) {
      warnings.push(
        `normalization rule ${rule.builtinKey ?? rule.id} is layer 1 with an UNANCHORED pattern ` +
          `(${rule.pattern}) and was SKIPPED. §6.4 refuses it: an unanchored regex over raw text ` +
          'does not know what it is eating.',
      );
      continue;
    }
    let re: RegExp;
    try {
      re = new RegExp(rule.pattern);
    } catch {
      warnings.push(`normalization rule ${rule.builtinKey ?? rule.id} has an invalid regex; skipped.`);
      continue;
    }
    const kept: string[] = [];
    let removed = 0;
    lines.forEach((line, index) => {
      if (re.test(line)) {
        removed++;
        traces.push({
          ruleId: rule.id,
          builtinKey: rule.builtinKey,
          sectionPath: null,
          semKey: null,
          prop: null,
          before: line,
          after: null,
          sourceLine: index + 1,
        });
      } else kept.push(line);
    });
    if (removed / total > L1_LINE_BUDGET) {
      warnings.push(
        `normalization rule ${rule.builtinKey ?? rule.id} matched ${removed}/${total} lines ` +
          `(> ${L1_LINE_BUDGET * 100} %) and was NOT applied (§6.4 lint).`,
      );
      continue;
    }
    lines = kept;
  }

  return lines.join('\n');
}

// ----------------------------------------------------------------------------
// L3 — entries
// ----------------------------------------------------------------------------

interface PreparedEntries {
  /** Section path -> entries, in file order. */
  bySection: Map<string, RouterOsEntry[]>;
  dynamicExcluded: number;
  statePropsDropped: number;
  counterPropsDropped: number;
  defaultsFilled: number;
}

function applyLayer3(
  parsed: ParsedExport,
  ctx: NormalizeContext,
  traces: NormalizationTrace[],
  warnings: string[],
): PreparedEntries {
  const bySection = new Map<string, RouterOsEntry[]>();
  let dynamicExcluded = 0;
  let statePropsDropped = 0;
  let counterPropsDropped = 0;
  let defaultsFilled = 0;

  const l3 = ctx.rules.filter((r) => r.layer === 3);
  const mapPath = l3.filter((r) => r.kind === 'map_path');
  const ignoreEntry = l3.filter((r) => r.kind === 'ignore_entry');
  const ignoreProp = l3.filter((r) => r.kind === 'ignore_prop');
  const rewrite = l3.filter((r) => r.kind === 'rewrite_value');
  const defaultFill = l3.filter((r) => r.kind === 'default_fill');

  for (const entry of parsed.entries) {
    // ── map_path (N15) ─────────────────────────────────────────────────────
    let sectionPath = aliasSection(entry.sectionPath);
    for (const rule of mapPath) {
      if (rule.sectionPath === sectionPath && rule.targetPath) {
        traces.push(trace(rule, sectionPath, null, null, sectionPath, rule.targetPath, entry.sourceLine));
        sectionPath = rule.targetPath;
      }
    }

    const spec = sectionSpec(sectionPath);

    // ── ignore_entry: dynamics (N03) ───────────────────────────────────────
    //
    // FALSE NEGATIVE, stated: a hand-written rule recreated as a dynamic one
    // becomes invisible. On the FIREWALL that is a security hole, so firewall
    // dynamics are NOT dropped here — they are kept and flagged, and the diff
    // engine downgrades them to `info` + `ignored` (N03's own mitigation).
    // Everywhere else the record has no intent behind it and diffing it is
    // structurally noise.
    if (isDynamicEntry(entry.props, sectionPath)) {
      const isFirewall = sectionPath.startsWith('/ip/firewall/');
      if (!isFirewall) {
        dynamicExcluded++;
        traces.push(trace(
          builtinLike('ros.dynamic.exclude'), sectionPath, null, 'dynamic',
          entry.props['dynamic'] ?? 'timeout', null, entry.sourceLine,
        ));
        continue;
      }
    }

    let dropped = false;
    for (const rule of ignoreEntry) {
      if (rule.sectionPath && rule.sectionPath !== sectionPath) continue;
      if (!rule.predicate || !predicateMatches(rule.predicate, entry.props)) continue;
      traces.push(trace(rule, sectionPath, null, rule.predicate.prop, entry.props[rule.predicate.prop] ?? null, null, entry.sourceLine));
      dropped = true;
      break;
    }
    if (dropped) { dynamicExcluded++; continue; }

    const props: Record<string, string> = { ...entry.props };

    // ── ignore_prop rules FIRST, the section catalogue as a backstop ───────
    //
    // The order is deliberate. The seeded `ros.state.ignore:<section>:<prop>`
    // rows are generated FROM the catalogue, so the two agree; running the rows
    // first is what gives them a real `hit_count` and a real trace. Without
    // that, the shadow-mode query of §6.3 ("what did rule 42 hide last week?")
    // returns nothing for every state prop in the product and the whole
    // false-negative review becomes impossible to run.
    //
    // `disabled` can never be dropped by either path: disabling the WAN drop
    // rule is a deliberate act, and confusing it with the derived `inactive`
    // costs exactly the change this product exists to catch.
    for (const rule of ignoreProp) {
      if (!rule.prop) continue;
      if (rule.sectionPath && rule.sectionPath !== sectionPath) continue;
      if (CONFIG_LOOKING_LIKE_STATE.has(rule.prop)) {
        warnings.push(
          `normalization rule ${rule.builtinKey ?? rule.id} tries to ignore "${rule.prop}", ` +
            'which is CONFIGURATION, not state. Refused.',
        );
        continue;
      }
      if (!(rule.prop in props)) continue;
      traces.push(trace(rule, sectionPath, null, rule.prop, props[rule.prop], null, entry.sourceLine));
      delete props[rule.prop];
      statePropsDropped++;
    }

    // ── state and counter props (N05, N06) ─────────────────────────────────
    //
    // Scoped to (section, prop), NEVER to a prop name alone: `mac-address` is
    // state on a bridge and identity on a static DHCP lease.
    for (const key of Object.keys(props)) {
      if (CONFIG_LOOKING_LIKE_STATE.has(key)) continue;
      const isState = spec?.stateProps.includes(key) ?? false;
      const isCounter = spec?.counterProps.includes(key) ?? false;
      const isUniversal = !spec && UNIVERSAL_STATE_PROPS.has(key);
      if (!isState && !isCounter && !isUniversal) continue;
      if (isCounter) counterPropsDropped++; else statePropsDropped++;
      delete props[key];
    }

    // ── rewrite_value (N10) ────────────────────────────────────────────────
    for (const rule of rewrite) {
      if (!rule.prop || !rule.pattern) continue;
      if (rule.sectionPath && rule.sectionPath !== sectionPath) continue;
      const before = props[rule.prop];
      if (before === undefined) continue;
      if (rule.prop === 'comment' && !/^\^|\$$/.test(rule.pattern)) {
        warnings.push(
          `rewrite_value on \`comment\` with an UNANCHORED pattern (${rule.builtinKey ?? rule.id}) ` +
            'was skipped: §6.4 refuses it, because a suffix regex that eats the whole comment ' +
            'destroys the best pairing key the firewall has.',
        );
        continue;
      }
      let re: RegExp;
      try { re = new RegExp(rule.pattern); } catch { continue; }
      const after = before.replace(re, rule.replacement ?? '');
      if (after === before) continue;
      traces.push(trace(rule, sectionPath, null, rule.prop, before, after, entry.sourceLine));
      props[rule.prop] = after;
    }

    // ── default_fill (N09) ─────────────────────────────────────────────────
    //
    // Both sides of the diff are completed with the default learned for THIS
    // EXACT firmware, so "absent" and "present with the default" stop being two
    // objects. The hard bound is `noDefaultFillProps`: on `action`, `chain`,
    // `disabled`, an address or a gateway, absence and presence are always two
    // different things and filling one is a false negative by construction.
    if (ctx.osVersion) {
      for (const rule of defaultFill) {
        if (!rule.prop) continue;
        if (rule.sectionPath && rule.sectionPath !== sectionPath) continue;
        if (rule.prop in props) continue;
        if (spec?.noDefaultFillProps.includes(rule.prop)) {
          warnings.push(
            `default_fill refused for ${sectionPath}.${rule.prop}: the section catalogue lists it ` +
              'in no_default_fill_props (N09 hard bound).',
          );
          continue;
        }
        const learned = ctx.defaults.get(`${sectionPath}|${rule.prop}`);
        const value = learned ?? (typeof rule.value === 'string' ? rule.value : null);
        if (value === null) continue;
        props[rule.prop] = value;
        defaultsFilled++;
        traces.push(trace(rule, sectionPath, null, rule.prop, null, value, entry.sourceLine));
      }
      // Defaults learned from the verbose oracle apply even without an explicit
      // rule row: the dictionary IS the rule (N09's preferred source).
      for (const [key, value] of ctx.defaults) {
        const bar = key.indexOf('|');
        if (key.slice(0, bar) !== sectionPath) continue;
        const prop = key.slice(bar + 1);
        if (prop in props) continue;
        if (spec?.noDefaultFillProps.includes(prop)) continue;
        props[prop] = value;
        defaultsFilled++;
      }
    }

    const list = bySection.get(sectionPath);
    const normalised: RouterOsEntry = { ...entry, sectionPath, props };
    if (list) list.push(normalised);
    else bySection.set(sectionPath, [normalised]);
  }

  return { bySection, dynamicExcluded, statePropsDropped, counterPropsDropped, defaultsFilled };
}

function predicateMatches(p: EntryPredicate, props: Readonly<Record<string, string>>): boolean {
  const value = props[p.prop];
  if (p.notEmpty === true) return value !== undefined && value !== '';
  if (p.eq !== undefined) {
    if (typeof p.eq === 'boolean') return normalizeBoolean(value) === p.eq;
    return value === String(p.eq);
  }
  if (p.matches) {
    if (value === undefined) return false;
    try { return new RegExp(p.matches).test(value); } catch { return false; }
  }
  return false;
}

function trace(
  rule: Pick<NormalizationRule, 'id' | 'builtinKey'>,
  sectionPath: string | null,
  semKey: string | null,
  prop: string | null,
  before: unknown,
  after: unknown,
  sourceLine: number | null,
): NormalizationTrace {
  return { ruleId: rule.id, builtinKey: rule.builtinKey, sectionPath, semKey, prop, before, after, sourceLine };
}

/** A trace for a rule that is implemented in code and mirrored in the database
 *  for accountability. `id: 0` means "builtin, not dispatched from a row". */
function builtinLike(key: string): Pick<NormalizationRule, 'id' | 'builtinKey'> {
  return { id: 0, builtinKey: key };
}

// ============================================================================
// Prop reading, with accounting (N05)
// ============================================================================

/**
 * The whitelist made auditable. Every prop the builders consume is READ through
 * this object; whatever is left at the end is a prop the model does not know
 * about, and it is reported rather than dropped in silence.
 *
 * This is the mitigation the study makes MANDATORY: "without this counter, the
 * whitelist is a black hole and the noise/false-negative ratio of M4 is a lie".
 * A prop that shows up here produces a ticket, never a finding.
 */
class PropReader {
  private readonly seen = new Set<string>();
  constructor(readonly entry: RouterOsEntry) {}

  get(name: string): string | undefined {
    this.seen.add(name);
    const v = this.entry.props[name];
    return v;
  }

  /** Marks a prop as handled without reading it (state, or handled elsewhere). */
  consume(...names: string[]): void {
    for (const n of names) this.seen.add(n);
  }

  str(name: string): string | null {
    const v = this.get(name);
    return v === undefined || v === '' ? null : v;
  }

  bool(name: string): boolean | null {
    return normalizeBoolean(this.get(name));
  }

  num(name: string): number | null {
    const v = this.get(name);
    if (v === undefined || v.trim() === '') return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

  leftovers(): string[] {
    return Object.keys(this.entry.props).filter((k) => !this.seen.has(k));
  }
}

// ============================================================================
// Document assembly
// ============================================================================

function buildDocument(
  parsed: ParsedExport,
  prepared: PreparedEntries,
  ctx: NormalizeContext,
  traces: NormalizationTrace[],
  warnings: string[],
): NormalizeResult {
  const unknownProps: NormalizeResult['unknownProps'] = [];
  const consumedSections = new Set<string>();
  const readers = new Map<RouterOsEntry, PropReader>();

  const section = (path: string): RouterOsEntry[] => {
    consumedSections.add(path);
    return prepared.bySection.get(path) ?? [];
  };
  const reader = (e: RouterOsEntry): PropReader => {
    const existing = readers.get(e);
    if (existing) return existing;
    const r = new PropReader(e);
    readers.set(e, r);
    return r;
  };

  const via = ctx.via;

  // ── identity singletons ───────────────────────────────────────────────────
  let systemIdentity: string | null = null;
  for (const e of section('/system/identity')) {
    const r = reader(e);
    systemIdentity = r.str('name') ?? systemIdentity;
  }
  let pppUsername: string | null = null;
  for (const e of section('/interface/pppoe-client')) {
    const r = reader(e);
    pppUsername = r.str('user') ?? pppUsername;
    r.consume('password');
  }

  // ── the ten resource collections ──────────────────────────────────────────
  const ctxAll = { section, reader, via, unknownProps, warnings };
  const { interfaces, vlans } = buildInterfacesAndVlans(ctxAll);
  const routes = buildRoutes(ctxAll);
  const firewallRules = buildFirewallRules(ctxAll, ctx);
  const natRules = buildNatRules(ctxAll, ctx);
  const dhcpScopes = buildDhcpScopes(ctxAll);
  const ipsecPeers = buildIpsecPeers(ctxAll);
  const localUsers = buildLocalUsers(ctxAll);
  const services = buildServices(ctxAll);
  const qosRules = buildQosRules(ctxAll);

  // ── unknown props (N05) ───────────────────────────────────────────────────
  for (const [, r] of readers) {
    for (const prop of r.leftovers()) {
      unknownProps.push({
        sectionPath: r.entry.sectionPath,
        prop,
        sample: r.entry.props[prop].slice(0, 60),
      });
    }
  }

  // ── unmodeled (N5 of the NCM contract) ────────────────────────────────────
  const unmodeled: NcmUnmodeled[] = [];
  for (const [path, entries] of prepared.bySection) {
    if (consumedSections.has(path)) continue;
    unmodeled.push({
      section: path,
      lineCount: entries.length,
      forwardingRelevant: isForwardingRelevant(path),
    });
  }
  for (const [path, count] of parsed.sectionLineCounts) {
    if (count !== 0) continue;                       // only the empty headers
    if (consumedSections.has(path) || prepared.bySection.has(path)) continue;
    // N02: an empty section is NOT a difference. It is recorded with a zero
    // count so the UI can say "seen, empty" rather than "never seen".
    unmodeled.push({ section: path, lineCount: 0, forwardingRelevant: isForwardingRelevant(path) });
  }
  unmodeled.sort((a, b) => (a.section < b.section ? -1 : a.section > b.section ? 1 : 0));

  // ── ordinals (§3.4 case 2) ────────────────────────────────────────────────
  const collisionRate = assignOrdinals(firewallRules, natRules, qosRules, ctx.previous ?? null);

  // ── order analysis (§4.3) ─────────────────────────────────────────────────
  const orderAnalysis = computeOrderAnalysis([...firewallRules, ...natRules, ...qosRules]);

  // ── coverage (N3) ─────────────────────────────────────────────────────────
  const coverage = computeCoverage(parsed, ctx, {
    interface: interfaces.length,
    vlan: vlans.length,
    route: routes.length,
    firewallRule: firewallRules.length,
    natRule: natRules.length,
    dhcpScope: dhcpScopes.length,
    ipsecPeer: ipsecPeers.length,
    localUser: localUsers.length,
    service: services.length,
    qosRule: qosRules.length,
  });

  const doc: NcmDocument = {
    ncmVersion: NCM_VERSION,
    semKeyGeneration: SEM_KEY_GENERATION,
    normalizationEpoch: computeNormalizationEpoch(ctx.rules),
    capturedAt: ctx.capturedAt ?? new Date().toISOString(),
    device: {
      deviceId: ctx.deviceId,
      brand: 'mikrotik',
      family: ctx.family,
      model: parsed.preamble.model,
      serial: parsed.preamble.serial,
      systemIdentity,
      pppUsername,
      osVersion: parsed.preamble.osVersion ?? ctx.osVersion,
    },
    coverage,
    orderAnalysis,
    resources: {
      interfaces, vlans, routes, firewallRules, natRules,
      dhcpScopes, ipsecPeers, localUsers, services, qosRules,
    },
    unmodeled,
    // Deliberately empty. `extensions` is excluded from the hash and from the
    // diff, so anything a parser puts there is invisible forever; and it is one
    // of the two doors a secret could still walk through (risk N-R9).
    extensions: {},
  };

  return {
    ncm: doc,
    ncmHash: ncmHash(doc),
    osVersion: parsed.preamble.osVersion,
    model: parsed.preamble.model,
    serial: parsed.preamble.serial,
    traces,
    unknownProps,
    warnings,
    stats: {
      entries: parsed.entries.length,
      dynamicEntriesExcluded: prepared.dynamicExcluded,
      statePropsDropped: prepared.statePropsDropped,
      counterPropsDropped: prepared.counterPropsDropped,
      defaultsFilled: prepared.defaultsFilled,
      unmodeledSections: unmodeled.length,
      ordinalCollisionRate: collisionRate,
    },
  };
}

interface BuildCtx {
  section: (path: string) => RouterOsEntry[];
  reader: (e: RouterOsEntry) => PropReader;
  via: TransportKind;
  unknownProps: NormalizeResult['unknownProps'];
  warnings: string[];
}

// ----------------------------------------------------------------------------
// Base fields shared by every resource
// ----------------------------------------------------------------------------

/**
 * N10 + the `obliwan:` marker. The comment is split into OWNERSHIP and free
 * text: a record ObliWAN wrote stays paired through a change of action, of
 * selectors and of comment, which is the strongest identity mechanism in the
 * product and the reason the platform stamps everything it writes.
 *
 * The marker is stripped from `comment`, so editing the human half of a comment
 * can never read as a change of ownership.
 */
function baseOf(r: PropReader, via: TransportKind) {
  const parsedComment = parseComment(r.str('comment'));
  return {
    managedBy: parsedComment.managedBy,
    managedSlug: parsedComment.managedSlug,
    comment: parsedComment.comment,
    disabled: r.bool('disabled') ?? false,
    via,
  };
}

// ----------------------------------------------------------------------------
// interfaces + vlans
// ----------------------------------------------------------------------------

const INTERFACE_SECTIONS = [
  '/interface/ethernet', '/interface/bridge', '/interface/vlan', '/interface/bonding',
  '/interface/wireguard', '/interface/lte', '/interface/gre', '/interface/eoip',
  '/interface/pppoe-client', '/interface/l2tp-client', '/interface/veth',
];

function buildInterfacesAndVlans(c: BuildCtx): { interfaces: NcmInterface[]; vlans: NcmVlan[] } {
  const byName = new Map<string, NcmInterface>();
  const order: string[] = [];

  const ensure = (name: string, type: string): NcmInterface => {
    const found = byName.get(name);
    if (found) return found;
    const created: NcmInterface = {
      semKey: interfaceKey(name),
      keyQuality: 'strong',
      managedBy: 'unknown',
      managedSlug: null,
      comment: null,
      disabled: false,
      via: c.via,
      kind: 'interface',
      name,
      type: type as NcmInterface['type'],
      alias: null,
      parent: null,
      mtu: null,
      addresses: [],
      lists: [],
      zone: null,
    };
    byName.set(name, created);
    order.push(name);
    return created;
  };

  for (const path of INTERFACE_SECTIONS) {
    for (const e of c.section(path)) {
      const r = c.reader(e);
      // `set [ find default-name=ether1 ] name=wan` — the identity is the
      // CURRENT name, which is what every other section references.
      const name = r.str('name') ?? e.find?.['name'] ?? e.find?.['default-name'] ?? e.positional[0] ?? null;
      if (!name) continue;
      r.consume('default-name');
      const iface = ensure(name, INTERFACE_TYPE_BY_SECTION[path] ?? 'other');
      Object.assign(iface, baseOf(r, c.via));
      iface.semKey = interfaceKey(name);
      iface.mtu = r.num('mtu');
      iface.alias = r.str('comment') === null ? null : iface.alias;
      const parent = r.str('interface') ?? r.str('slave-of');
      if (parent) iface.parent = parent;
      // Everything below is consumed on purpose: it is either state already
      // removed at L3, or a knob NCM v1 does not model but that is not a
      // surprise worth a ticket on every device of the fleet.
      r.consume('arp', 'arp-timeout', 'auto-negotiation', 'advertise', 'bandwidth',
        'loop-protect', 'poe-out', 'poe-priority', 'rx-flow-control', 'tx-flow-control',
        'speed', 'full-duplex', 'cable-settings', 'sfp-rate-select', 'sfp-shutdown-temperature',
        'protocol-mode', 'auto-mac', 'admin-mac', 'ageing-time', 'priority', 'vlan-filtering',
        'pvid', 'igmp-snooping', 'dhcp-snooping', 'fast-forward', 'port-cost-mode',
        'listen-port', 'private-key', 'mac-address', 'use-peer-dns', 'add-default-route');
    }
  }

  // Bridge ports give the parent of a member interface.
  for (const e of c.section('/interface/bridge/port')) {
    const r = c.reader(e);
    const bridge = r.str('bridge');
    const member = r.str('interface');
    // The comment of a bridge-port row has no field in `NcmInterface`. It is
    // CONSUMED rather than reported as unknown: an unknown prop is a ticket to
    // model something, and `defconf` on every bridge port of every device would
    // be a permanent ticket for a decision already taken.
    r.consume('comment');
    r.consume('pvid', 'frame-types', 'ingress-filtering', 'hw', 'horizon', 'path-cost',
      'internal-path-cost', 'edge', 'point-to-point', 'learn', 'unknown-unicast-flood',
      'multicast-router', 'trusted', 'bpdu-guard', 'auto-isolate', 'restricted-role');
    if (!bridge || !member) continue;
    ensure(bridge, 'bridge');
    const iface = ensure(member, guessType(member));
    iface.parent = bridge;
  }

  // Interface-list membership is CONFIG: the firewall's selector vocabulary
  // depends on it (`in-interface-list=WAN`), so removing an interface from
  // `WAN` changes which packets a rule selects.
  for (const e of c.section('/interface/list/member')) {
    const r = c.reader(e);
    const list = r.str('list');
    const member = r.str('interface');
    if (!list || !member) continue;
    const iface = ensure(member, guessType(member));
    if (!iface.lists.includes(list)) iface.lists.push(list);
  }
  c.section('/interface/list');   // names only; membership is what matters

  // Static addressing. A DHCP/PPP-learned address is STATE and never reaches
  // here: `dynamic=yes` was dropped at L3.
  for (const e of c.section('/ip/address')) {
    const r = c.reader(e);
    const address = r.str('address');
    const on = r.str('interface');
    // `network` is DERIVED from `address` and yet the export emits it; storing
    // it would double every address finding. `comment` on an address row has no
    // field in `NcmAddress` — same reasoning as the bridge port above.
    r.consume('network', 'broadcast', 'actual-interface', 'comment');
    if (!address || !on) continue;
    const iface = ensure(on, guessType(on));
    // Host bits are PRESERVED here: `10.0.0.1/24` means "this box is .1", and
    // zeroing them would destroy the configuration.
    const cidr = canonicalizeCidr(address, true);
    if (!cidr) { c.warnings.push(`/ip/address: unparsable address "${address}"`); continue; }
    if (!iface.addresses.some((a) => a.cidr === cidr)) {
      iface.addresses.push({ cidr, originUnknown: false });
    }
  }

  // ── VLANs ────────────────────────────────────────────────────────────────
  const vlans = new Map<string, NcmVlan>();
  const vlanRecord = (parent: string | null, id: number): NcmVlan => {
    const key = vlanKey(parent, id);
    const found = vlans.get(key);
    if (found) return found;
    const created: NcmVlan = {
      semKey: key,
      keyQuality: 'strong',
      managedBy: 'unknown',
      managedSlug: null,
      comment: null,
      disabled: false,
      via: c.via,
      kind: 'vlan',
      vlanId: id,
      name: null,
      parent,
      taggedPorts: [],
      untaggedPorts: [],
    };
    vlans.set(key, created);
    return created;
  };

  for (const e of c.section('/interface/vlan')) {
    const r = c.reader(e);
    const name = r.str('name');
    const parent = r.str('interface');
    const id = r.num('vlan-id');
    r.consume('use-service-tag', 'loop-protect');
    if (id === null) continue;
    const v = vlanRecord(parent, id);
    v.name = name;
    Object.assign(v, { ...baseOf(r, c.via), semKey: v.semKey });
  }

  for (const e of c.section('/interface/bridge/vlan')) {
    const r = c.reader(e);
    const bridge = r.str('bridge');
    const ids = r.str('vlan-ids');
    const tagged = splitList(r.str('tagged'));
    const untagged = splitList(r.str('untagged'));
    if (!ids) continue;
    for (const id of expandVlanIds(ids)) {
      const v = vlanRecord(bridge, id);
      v.taggedPorts = mergeSorted(v.taggedPorts, tagged);
      v.untaggedPorts = mergeSorted(v.untaggedPorts, untagged);
    }
  }

  return {
    interfaces: order.map((n) => byName.get(n) as NcmInterface),
    vlans: Array.from(vlans.values()),
  };
}

/** Only used for an interface referenced by another section but never declared
 *  in its own menu — a hEX at factory settings emits no `/interface/ethernet`
 *  line at all. Never overrides a declared type. */
function guessType(name: string): string {
  if (/^bridge/i.test(name)) return 'bridge';
  if (/^vlan|\.\d+$/i.test(name)) return 'vlan';
  if (/^(ether|sfp|combo)/i.test(name)) return 'ethernet';
  if (/^(wlan|wifi)/i.test(name)) return 'wifi';
  if (/^(pppoe|l2tp|sstp|ovpn|pptp)/i.test(name)) return 'pppoe';
  if (/^(wg|wireguard)/i.test(name)) return 'wireguard';
  if (/^(lte|ppp-out)/i.test(name)) return 'lte';
  return 'other';
}

function splitList(v: string | null): string[] {
  if (!v) return [];
  return v.split(',').map((s) => s.trim()).filter(Boolean);
}

function mergeSorted(a: readonly string[], b: readonly string[]): string[] {
  return Array.from(new Set([...a, ...b])).sort();
}

/** `100,200-202` -> [100, 200, 201, 202]. */
function expandVlanIds(expr: string): number[] {
  const out: number[] = [];
  for (const part of expr.split(',')) {
    const t = part.trim();
    const dash = t.indexOf('-');
    if (dash > 0) {
      const a = Number(t.slice(0, dash));
      const b = Number(t.slice(dash + 1));
      if (Number.isInteger(a) && Number.isInteger(b) && b >= a && b - a < 4096) {
        for (let i = a; i <= b; i++) out.push(i);
      }
      continue;
    }
    const n = Number(t);
    if (Number.isInteger(n)) out.push(n);
  }
  return out;
}

// ----------------------------------------------------------------------------
// routes
// ----------------------------------------------------------------------------

function buildRoutes(c: BuildCtx): NcmRoute[] {
  const out: NcmRoute[] = [];
  for (const e of c.section('/ip/route')) {
    const r = c.reader(e);
    const dstRaw = r.str('dst-address') ?? '0.0.0.0/0';
    const dst = canonicalizeCidr(dstRaw, false);
    if (!dst) { c.warnings.push(`/ip/route: unparsable dst-address "${dstRaw}"`); continue; }
    const table = r.str('routing-table') ?? r.str('routing-mark') ?? 'main';
    const gatewayRaw = r.str('gateway');
    const type = r.str('type');
    r.consume('vrf-interface', 'suppress-hw-offload', 'target-scope', 'comment');

    const gateway = type === 'blackhole' || type === 'unreachable' || type === 'prohibit'
      ? null
      : gatewayAtom(gatewayRaw);

    const base = baseOf(r, c.via);
    out.push({
      ...base,
      semKey: routeKey(table, dst, gateway),
      keyQuality: 'strong',
      kind: 'route',
      dst,
      gateway,
      distance: r.num('distance'),
      scope: r.num('scope'),
      targetScope: r.num('target-scope'),
      table,
      checkGateway: mapCheckGateway(r.str('check-gateway')),
      vrf: r.str('vrf') ?? null,
    });
  }
  return out;
}

/** `10.255.0.1` -> `ip:10.255.0.1`; `ether1` -> `iface:ether1`;
 *  `10.255.0.1%ether1` -> the address, since that is what selects the path. */
function gatewayAtom(raw: string | null): string | null {
  if (!raw) return null;
  const first = raw.split(',')[0].trim();
  const pct = first.indexOf('%');
  const head = pct >= 0 ? first.slice(0, pct) : first;
  const atom = addressAtom(head);
  if (atom.startsWith('ip:') || atom.startsWith('cidr:')) return atom;
  return `iface:${head}`;
}

function mapCheckGateway(v: string | null): NcmRoute['checkGateway'] {
  if (!v) return null;
  if (v === 'ping') return 'ping';
  if (v === 'arp') return 'arp';
  if (v === 'bfd') return 'bfd';
  if (v === 'none') return 'none';
  return null;
}

// ----------------------------------------------------------------------------
// firewall / nat — the match side (N1 of the NCM contract)
// ----------------------------------------------------------------------------

/**
 * DIVERGENCE, DELIBERATE AND DOCUMENTED — the table qualifier.
 *
 * `NcmFirewallRule.chain` is an enum of six values and carries no notion of
 * WHICH firewall table a rule lives in. A `filter` rule and a `mangle` rule in
 * `chain=input` with the same selectors would otherwise produce the same
 * `matchHash`, hence the same `semKey`, hence a collision the pairing algorithm
 * would resolve arbitrarily and an order analysis that compares rules from two
 * tables that never see each other.
 *
 * `chainName` carries the table for everything that is not `filter`, and
 * `computeMatchHash` folds it in as `<chain>:<chainName>`. `filter` keeps
 * `chainName: null`, so the study's own literal example (`fw.v1:input:<hash>#0`)
 * is preserved byte for byte.
 */
const FIREWALL_TABLES: readonly { path: string; table: string | null }[] = [
  { path: '/ip/firewall/filter', table: null },
  { path: '/ip/firewall/mangle', table: 'mangle' },
  { path: '/ip/firewall/raw', table: 'raw' },
];

const STANDARD_CHAINS = new Set(['input', 'output', 'forward', 'prerouting', 'postrouting']);

function buildFirewallRules(c: BuildCtx, _ctx: NormalizeContext): NcmFirewallRule[] {
  const out: NcmFirewallRule[] = [];
  for (const { path, table } of FIREWALL_TABLES) {
    for (const e of c.section(path)) {
      const r = c.reader(e);
      const rawChain = (r.str('chain') ?? 'forward').toLowerCase();
      const isStandard = STANDARD_CHAINS.has(rawChain);
      const chain = (isStandard ? rawChain : 'custom') as NcmFirewallRule['chain'];
      const chainName = isStandard
        ? (table ?? null)
        : table ? `${table}:${rawChain}` : rawChain;

      const match = buildMatch(r, c);
      const rawAction = (r.str('action') ?? 'accept').toLowerCase();
      // A mangle `mark-*` action has no NCM verb, but whether it is TERMINAL is
      // load-bearing: `TERMINAL_ACTIONS` drives the decisive-pair test of §4.2,
      // and calling a passthrough rule terminal would make every reordering
      // around it look like a forwarding change. `passthrough` defaults to yes
      // on the mark actions, so an unmapped action is `passthrough` unless the
      // rule says otherwise.
      const passthrough = r.bool('passthrough');
      const action = (
        FIREWALL_ACTION_MAP[rawAction] ?? (passthrough === false ? 'other' : 'passthrough')
      ) as NcmFirewallRule['action'];

      // Mangle's payload (`new-routing-mark`, `new-connection-mark`, …) has no
      // field in NCM v1. Recording it in `unmodeledMatch` puts it in the
      // IDENTITY rather than in the payload, which is a divergence from N1 with
      // a known cost: changing a routing mark yields a `missing` + an `extra`
      // (two findings) instead of one `changed`. The alternative — dropping it
      // — yields ZERO findings, which is a false negative on a rule that
      // redirects traffic to a different WAN. Noise over blindness, per D1.
      for (const prop of ['new-routing-mark', 'new-connection-mark', 'new-packet-mark',
        'new-mss', 'new-dscp', 'new-priority', 'new-ttl', 'route-dst', 'sniff-target']) {
        const v = r.str(prop);
        if (v !== null) match.unmodeledMatch.push(`action:${prop}=${v}`);
      }
      match.unmodeledMatch.sort();

      const matchHash = computeMatchHash(chain, chainName, match);
      const base = baseOf(r, c.via);
      out.push({
        ...base,
        semKey: '',                                  // assigned with the ordinal
        keyQuality: base.managedSlug ? 'strong' : 'derived',
        kind: 'firewallRule',
        chain,
        chainName,
        match,
        action,
        jumpTarget: r.str('jump-target'),
        rejectWith: r.str('reject-with'),
        log: r.bool('log') ?? false,
        logPrefix: r.str('log-prefix'),
        addToList: r.str('address-list'),
        addToListTimeout: parseDuration(r.str('address-list-timeout')),
        ordinal: 0,
        matchHash,
      });
    }
  }
  return out;
}

function buildNatRules(c: BuildCtx, _ctx: NormalizeContext): NcmNatRule[] {
  const out: NcmNatRule[] = [];
  for (const e of c.section('/ip/firewall/nat')) {
    const r = c.reader(e);
    const rawChain = (r.str('chain') ?? 'srcnat').toLowerCase();
    const chain = (rawChain === 'srcnat' ? 'postrouting'
      : rawChain === 'dstnat' ? 'prerouting'
        : rawChain === 'prerouting' || rawChain === 'postrouting' ? rawChain
          : 'custom') as NcmNatRule['chain'];
    const chainName = chain === 'custom' ? rawChain : null;

    const match = buildMatch(r, c);
    const rawAction = (r.str('action') ?? 'accept').toLowerCase();
    const action = (NAT_ACTION_MAP[rawAction] ?? 'other') as NcmNatRule['action'];
    const toAddresses = r.str('to-addresses');
    const matchHash = computeMatchHash(chain, chainName, match);
    const base = baseOf(r, c.via);
    out.push({
      ...base,
      semKey: '',
      keyQuality: base.managedSlug ? 'strong' : 'derived',
      kind: 'natRule',
      chain,
      chainName,
      match,
      action,
      toAddresses: toAddresses ? normalizeSelector([addressAtom(toAddresses)]) : null,
      toPorts: portsOf(r.str('to-ports'), c),
      ordinal: 0,
      matchHash,
    });
  }
  return out;
}

/**
 * §3.3 — the canonicalisation the whole identity rests on.
 *
 * RULE 1 IS THE ONE THAT MATTERS: absent means `any`. `/export` omits a default
 * `src-address` while the API returns it, and without collapsing the two, the
 * day a device switches from SSH to the API every rule in its firewall looks
 * changed. That is the study's documented number-one source of false drift, and
 * it is handled structurally by starting from `EMPTY_MATCH` rather than by
 * remembering to write `?? 'any'` at fourteen call sites.
 */
function buildMatch(r: PropReader, c: BuildCtx): NcmMatch {
  const m: NcmMatch = {
    ...EMPTY_MATCH,
    srcAddress: ANY_SELECTOR,
    dstAddress: ANY_SELECTOR,
    inInterface: ANY_SELECTOR,
    outInterface: ANY_SELECTOR,
    connectionState: [],
    connectionNat: [],
    tcpFlags: [],
    unmodeledMatch: [],
  };

  m.protocol = normalizeProtocol(r.str('protocol'));

  m.srcAddress = selectorOf([
    addr(r.str('src-address')),
    range(r.str('src-address-range')),
    // An address list is a REFERENCE and is never expanded: expanding it makes
    // every rule that uses it change the day a member is added to the list.
    ref(r.str('src-address-list')),
    mac(r.str('src-mac-address')),
  ]);
  m.dstAddress = selectorOf([
    addr(r.str('dst-address')),
    range(r.str('dst-address-range')),
    ref(r.str('dst-address-list')),
  ]);
  m.inInterface = selectorOf([
    iface(r.str('in-interface')),
    ifaceList(r.str('in-interface-list')),
    iface(r.str('in-bridge-port')),
  ]);
  m.outInterface = selectorOf([
    iface(r.str('out-interface')),
    ifaceList(r.str('out-interface-list')),
    iface(r.str('out-bridge-port')),
  ]);

  m.srcPort = portsOf(r.str('src-port'), c);
  m.dstPort = portsOf(r.str('dst-port'), c);
  m.connectionState = normalizeTokenSet(r.str('connection-state'));
  m.connectionNat = normalizeTokenSet(r.str('connection-nat-state'));
  m.tcpFlags = normalizeTokenSet(r.str('tcp-flags'));
  m.icmpType = r.str('icmp-options');
  m.ipsecPolicy = r.str('ipsec-policy');

  // RouterOS `port=` matches EITHER side. Modelling it as `dstPort` would
  // narrow the rule and let the intersection test declare two overlapping rules
  // disjoint — a false negative in the order analysis, which §4.3 says must
  // never happen. It goes to `unmodeledMatch`, which keeps it inside the
  // identity and marks the rule as not fully understood, so K2 refuses to prove
  // anything from it.
  const bothPort = r.str('port');
  if (bothPort) m.unmodeledMatch.push(`port=${bothPort}`);

  for (const prop of UNMODELED_MATCH_PROPS) {
    const v = r.str(prop);
    if (v !== null) m.unmodeledMatch.push(`${prop}=${v}`);
  }
  m.unmodeledMatch.sort();
  return m;
}

/** Match props NCM v1 does not model. They are kept INSIDE `matchHash`: two
 *  rules, one of which carries a selector we do not understand, are not the
 *  same rule. */
const UNMODELED_MATCH_PROPS: readonly string[] = [
  'connection-mark', 'packet-mark', 'routing-mark', 'routing-table', 'connection-type',
  'content', 'layer7-protocol', 'time', 'limit', 'dst-limit', 'nth', 'random',
  'per-connection-classifier', 'psd', 'hotspot', 'dscp', 'priority', 'packet-size',
  'ttl', 'tls-host', 'connection-bytes', 'connection-rate', 'connection-limit',
  'src-mac-address', 'fragment', 'ipv4-options', 'in-bridge-port-list',
  'out-bridge-port-list', 'ingress-priority', 'jump-target-list',
];

function selectorOf(atoms: Array<string | null>): Selector {
  return normalizeSelector(atoms.filter((a): a is string => a !== null));
}
function addr(v: string | null): string | null { return v === null ? null : addressAtom(v); }
function range(v: string | null): string | null {
  if (v === null) return null;
  const dash = v.indexOf('-');
  return dash > 0 ? rangeAtom(v.slice(0, dash), v.slice(dash + 1)) : addressAtom(v);
}
function ref(v: string | null): string | null { return v === null ? null : `ref:${v}`; }
function mac(v: string | null): string | null { return v === null ? null : macAtom(v); }
function iface(v: string | null): string | null { return v === null ? null : `iface:${v}`; }
function ifaceList(v: string | null): string | null { return v === null ? null : `ifaceList:${v}`; }

function portsOf(expr: string | null, c: BuildCtx): PortSet {
  if (expr === null) return null;
  const parsed = parsePortExpression(expr);
  if (parsed === 'unparsable') {
    c.warnings.push(`unparsable port expression "${expr}" (a named service?); treated as "any"`);
    return null;
  }
  return parsed;
}

/** RouterOS durations: `1d00:00:00`, `30m`, `1h30m`, `00:00:30`. */
function parseDuration(v: string | null): number | null {
  if (!v) return null;
  let seconds = 0;
  let matched = false;
  const dm = /(\d+)d/.exec(v);
  if (dm) { seconds += Number(dm[1]) * 86400; matched = true; }
  const clock = /(\d{1,2}):(\d{2}):(\d{2})/.exec(v);
  if (clock) {
    seconds += Number(clock[1]) * 3600 + Number(clock[2]) * 60 + Number(clock[3]);
    matched = true;
  } else {
    for (const [re, mul] of [[/(\d+)w/, 604800], [/(\d+)h/, 3600], [/(\d+)m(?!s)/, 60], [/(\d+)s/, 1]] as const) {
      const m = re.exec(v);
      if (m) { seconds += Number(m[1]) * mul; matched = true; }
    }
  }
  if (!matched) {
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }
  return seconds;
}

// ----------------------------------------------------------------------------
// dhcp
// ----------------------------------------------------------------------------

function buildDhcpScopes(c: BuildCtx): NcmDhcpScope[] {
  const pools = new Map<string, { from: string | null; to: string | null }>();
  for (const e of c.section('/ip/pool')) {
    const r = c.reader(e);
    const name = r.str('name');
    const ranges = r.str('ranges');
    r.consume('next-pool');
    if (!name) continue;
    const first = (ranges ?? '').split(',')[0].trim();
    const dash = first.indexOf('-');
    pools.set(name, dash > 0
      ? { from: first.slice(0, dash).trim(), to: first.slice(dash + 1).trim() }
      : { from: first || null, to: null });
  }

  interface NetworkRow {
    address: string;
    gateway: string | null;
    dns: string[];
    ntp: string[];
    domain: string | null;
  }
  const networks: NetworkRow[] = [];
  for (const e of c.section('/ip/dhcp-server/network')) {
    const r = c.reader(e);
    const address = r.str('address');
    r.consume('caps-manager', 'wins-server', 'next-server', 'boot-file-name', 'dhcp-option', 'dhcp-option-set');
    if (!address) continue;
    networks.push({
      address,
      gateway: r.str('gateway'),
      dns: splitList(r.str('dns-server')),
      ntp: splitList(r.str('ntp-server')),
      domain: r.str('domain'),
    });
  }

  const leasesByServer = new Map<string, NcmDhcpReservation[]>();
  for (const e of c.section('/ip/dhcp-server/lease')) {
    const r = c.reader(e);
    // Only STATIC reservations. A dynamic lease is an allocation, and it was
    // already removed at L3 by the N03 predicate.
    const macRaw = r.str('mac-address');
    const address = r.str('address');
    const server = r.str('server') ?? '*';
    r.consume('client-id', 'lease-time', 'insert-queue-before', 'address-lists', 'comment', 'block-access');
    if (!macRaw || !address) continue;
    const atom = macAtom(macRaw);
    if (!atom.startsWith('mac:')) continue;
    const macValue = atom.slice(4);
    const list = leasesByServer.get(server) ?? [];
    list.push({
      semKey: dhcpReservationKey(server, macValue),
      mac: macValue,
      address,
      hostname: r.str('host-name'),
      comment: r.str('comment'),
    });
    leasesByServer.set(server, list);
  }

  const out: NcmDhcpScope[] = [];
  for (const e of c.section('/ip/dhcp-server')) {
    const r = c.reader(e);
    const name = r.str('name');
    if (!name) continue;
    const onIface = r.str('interface') ?? 'unknown';
    const poolName = r.str('address-pool');
    const pool = poolName ? pools.get(poolName) : undefined;
    r.consume('lease-script', 'authoritative', 'add-arp', 'always-broadcast', 'bootp-support',
      'conflict-detection', 'delay-threshold', 'use-radius', 'allow-dual-stack-queue',
      'parent-queue', 'insert-queue-before', 'client-mac-limit', 'relay', 'src-address');

    const net = pickNetworkFor(networks, pool?.from ?? null);
    const subnet = net ? canonicalizeCidr(net.address, false) : null;

    out.push({
      ...baseOf(r, c.via),
      semKey: dhcpScopeKey(name),
      keyQuality: 'strong',
      kind: 'dhcpScope',
      name,
      onInterface: `iface:${onIface}`,
      // A scope without a matching `/ip/dhcp-server/network` line keeps a
      // placeholder rather than inventing a subnet: `0.0.0.0/0` here would make
      // the record look like a wide-open scope in a K5 audit.
      subnet: subnet ?? '0.0.0.0/32',
      poolFrom: pool?.from ?? null,
      poolTo: pool?.to ?? null,
      gateway: net?.gateway ?? null,
      dnsServers: net?.dns ?? [],
      ntpServers: net?.ntp ?? [],
      domain: net?.domain ?? null,
      leaseSeconds: parseDuration(r.str('lease-time')),
      reservations: (leasesByServer.get(name) ?? leasesByServer.get('*') ?? [])
        .slice()
        .sort((a, b) => (a.semKey < b.semKey ? -1 : 1)),
      options: [],
    });
  }
  return out;
}

/** The network row whose CIDR contains the pool's first address. Falls back to
 *  the single network when there is exactly one — and to nothing otherwise,
 *  because a wrong join here silently attaches a gateway to the wrong subnet. */
function pickNetworkFor<T extends { address: string }>(networks: T[], probe: string | null): T | null {
  if (networks.length === 0) return null;
  if (probe) {
    const ip = parseCidr(probe);
    if (ip) {
      for (const n of networks) {
        const net = parseCidr(n.address);
        if (net && net.version === ip.version && sameNetwork(ip.bytes, net.bytes, net.prefix)) return n;
      }
    }
  }
  return networks.length === 1 ? networks[0] : null;
}

function sameNetwork(a: Uint8Array, b: Uint8Array, prefix: number): boolean {
  for (let i = 0; i < a.length; i++) {
    const bitsBefore = i * 8;
    if (prefix >= bitsBefore + 8) { if (a[i] !== b[i]) return false; continue; }
    if (prefix <= bitsBefore) return true;
    const mask = (0xff << (8 - (prefix - bitsBefore))) & 0xff;
    return (a[i] & mask) === (b[i] & mask);
  }
  return true;
}

// ----------------------------------------------------------------------------
// ipsec
// ----------------------------------------------------------------------------

function buildIpsecPeers(c: BuildCtx): NcmIpsecPeer[] {
  const proposals = new Map<string, { enc: string[]; auth: string[]; pfs: string | null; lifetime: number | null }>();
  for (const e of c.section('/ip/ipsec/proposal')) {
    const r = c.reader(e);
    const name = r.str('name');
    if (!name) continue;
    proposals.set(name, {
      enc: normalizeTokenSet(r.str('enc-algorithms')),
      auth: normalizeTokenSet(r.str('auth-algorithms')),
      pfs: r.str('pfs-group'),
      lifetime: parseDuration(r.str('lifetime')),
    });
  }

  interface IdentityRow { peer: string; authMethod: string | null; myId: string | null; remoteId: string | null }
  const identities = new Map<string, IdentityRow>();
  for (const e of c.section('/ip/ipsec/identity')) {
    const r = c.reader(e);
    const peer = r.str('peer');
    // The secret is NEVER read. `show-sensitive=no` should already have
    // removed it; reading it here would be the one line that makes R10 a lie.
    r.consume('secret', 'key', 'password', 'certificate', 'remote-certificate', 'generate-policy',
      'match-by', 'mode-config', 'policy-template-group', 'notrack-chain', 'eap-methods');
    if (!peer) continue;
    identities.set(peer, {
      peer,
      authMethod: r.str('auth-method'),
      myId: r.str('my-id'),
      remoteId: r.str('remote-id'),
    });
  }

  interface PolicyRow { peer: string | null; src: string | null; dst: string | null; proposal: string | null }
  const policies: PolicyRow[] = [];
  for (const e of c.section('/ip/ipsec/policy')) {
    const r = c.reader(e);
    r.consume('template', 'group', 'level', 'ipsec-protocols', 'action', 'tunnel', 'protocol',
      'src-port', 'dst-port', 'sa-src-address', 'sa-dst-address');
    policies.push({
      peer: r.str('peer'),
      src: r.str('src-address'),
      dst: r.str('dst-address'),
      proposal: r.str('proposal'),
    });
  }

  const out: NcmIpsecPeer[] = [];
  for (const e of c.section('/ip/ipsec/peer')) {
    const r = c.reader(e);
    const name = r.str('name');
    const remote = (r.str('address') ?? '').replace(/\/\d+$/, '').toLowerCase();
    r.consume('profile', 'passive', 'send-initial-contact', 'local-address', 'port');
    if (!remote && !name) continue;

    const ident = name ? identities.get(name) : undefined;
    const mine = policies.filter((p) => p.peer === name);
    const proposalName = mine.find((p) => p.proposal)?.proposal ?? 'default';
    const prop = proposals.get(proposalName);

    const authMethod = mapAuthMethod(ident?.authMethod ?? null);
    out.push({
      ...baseOf(r, c.via),
      semKey: ipsecPeerKey(remote || (name as string), ident?.myId ?? null),
      keyQuality: 'strong',
      kind: 'ipsecPeer',
      name,
      remote: remote || (name as string),
      localId: ident?.myId ?? null,
      remoteId: ident?.remoteId ?? null,
      exchangeMode: mapExchangeMode(r.str('exchange-mode')),
      authMethod,
      // ALWAYS unavailable on MikroTik: `show-sensitive=no` is hard-wired, so
      // there is no PSK to fingerprint. `fp: null` + `unavailable: true` is
      // distinguishable from an empty secret, which is what keeps "the PSK was
      // removed" different from "we could not read the PSK".
      //
      // FALSE NEGATIVE, structural and accepted (N11): A PSK ROTATION PRODUCES
      // NO FINDING. What stays visible is the auth METHOD dropping from `psk`
      // to something else, and the disappearance of the identity altogether.
      pskFingerprint: UNAVAILABLE_SECRET,
      proposal: {
        encryption: prop?.enc ?? [],
        integrity: prop?.auth ?? [],
        dhGroup: prop?.pfs ? [prop.pfs] : [],
        lifetimeSeconds: prop?.lifetime ?? null,
        pfsGroup: prop?.pfs ?? null,
      },
      localSubnets: mine.map((p) => p.src).filter((s): s is string => !!s).sort(),
      remoteSubnets: mine.map((p) => p.dst).filter((s): s is string => !!s).sort(),
      dpdSeconds: parseDuration(r.str('dpd-interval')),
      natTraversal: r.bool('nat-traversal'),
    });
  }
  return out;
}

function mapExchangeMode(v: string | null): NcmIpsecPeer['exchangeMode'] {
  switch (v) {
    case 'main': return 'ike1-main';
    case 'aggressive': return 'ike1-aggressive';
    case 'ike2': return 'ike2';
    default: return 'unknown';
  }
}

function mapAuthMethod(v: string | null): NcmIpsecPeer['authMethod'] {
  switch (v) {
    case 'pre-shared-key':
    case 'pre-shared-key-xauth': return 'psk';
    case 'rsa-signature':
    case 'digital-signature':
    case 'rsa-key': return 'rsa';
    case 'eap':
    case 'eap-radius': return 'eap';
    default: return 'unknown';
  }
}

// ----------------------------------------------------------------------------
// local users
// ----------------------------------------------------------------------------

/** The RouterOS factory account. `isVendorDefault` says the vendor default
 *  ACCOUNT still exists — NOT that the vendor default PASSWORD is still set,
 *  which `show-sensitive=no` makes structurally unknowable. */
const ROUTEROS_FACTORY_ACCOUNTS = new Set(['admin']);

function buildLocalUsers(c: BuildCtx): NcmLocalUser[] {
  const groupPolicies = new Map<string, string[]>();
  for (const e of c.section('/user/group')) {
    const r = c.reader(e);
    const name = r.str('name') ?? e.find?.['name'] ?? e.positional[0] ?? null;
    r.consume('skin', 'comment');
    if (!name) continue;
    groupPolicies.set(name, normalizeTokenSet(r.str('policy')));
  }

  const out: NcmLocalUser[] = [];
  for (const e of c.section('/user')) {
    const r = c.reader(e);
    const username = r.str('name') ?? e.find?.['name'] ?? e.positional[0] ?? null;
    // NEVER read. Not present under `show-sensitive=no`, and reading it would
    // be the leak R10 exists to prevent.
    r.consume('password', 'last-logged-in', 'expired', 'inactivity-policy', 'inactivity-timeout');
    if (!username) continue;
    const group = r.str('group');
    const allowed = r.str('address');
    out.push({
      ...baseOf(r, c.via),
      semKey: localUserKey(username),
      keyQuality: 'strong',
      kind: 'localUser',
      username,
      group,
      // Resolved from `/user/group`, so promoting a user from `read` to `full`
      // is ONE finding with two field diffs rather than a change nobody can
      // interpret without opening a second screen.
      permissions: group ? (groupPolicies.get(group) ?? []) : [],
      allowedFrom: allowed
        ? normalizeSelector(splitList(allowed).map((a) => addressAtom(a)))
        : ANY_SELECTOR,
      passwordFingerprint: UNAVAILABLE_SECRET,
      isVendorDefault: ROUTEROS_FACTORY_ACCOUNTS.has(username.toLowerCase()),
      sshKeyFingerprints: [],
      twoFactor: null,
    });
  }
  return out;
}

// ----------------------------------------------------------------------------
// management services
// ----------------------------------------------------------------------------

function buildServices(c: BuildCtx): NcmService[] {
  const out: NcmService[] = [];

  for (const e of c.section('/ip/service')) {
    const r = c.reader(e);
    const raw = (r.str('name') ?? e.find?.['name'] ?? e.positional[0] ?? '').toLowerCase();
    if (!raw) continue;
    const mapped = SERVICE_NAME_MAP[raw] ?? 'other';
    const disabled = r.bool('disabled') ?? false;
    const allowed = r.str('address');
    out.push({
      ...baseOf(r, c.via),
      semKey: serviceKey(mapped, mapped === 'other' ? raw : null),
      keyQuality: 'strong',
      kind: 'service',
      service: mapped as NcmService['service'],
      rawName: mapped === 'other' ? raw : null,
      enabled: !disabled,
      port: r.num('port'),
      allowedFrom: allowed
        ? normalizeSelector(splitList(allowed).map((a) => addressAtom(a)))
        : ANY_SELECTOR,
      tlsRequired: raw === 'www-ssl' || raw === 'api-ssl' ? true : null,
      certificate: r.str('certificate'),
      version: null,
      communityFingerprint: null,
      communityIsWellKnown: null,
    });
  }

  for (const e of c.section('/snmp')) {
    const r = c.reader(e);
    r.consume('contact', 'location', 'engine-id', 'src-address', 'trap-generators',
      'trap-target', 'trap-interfaces', 'engine-id-suffix', 'vrf');
    out.push({
      ...baseOf(r, c.via),
      semKey: serviceKey('snmp', null),
      keyQuality: 'strong',
      kind: 'service',
      service: 'snmp',
      rawName: null,
      enabled: r.bool('enabled') ?? false,
      port: null,
      allowedFrom: ANY_SELECTOR,
      tlsRequired: null,
      certificate: null,
      version: r.str('trap-version'),
      communityFingerprint: null,
      communityIsWellKnown: null,
    });
  }

  for (const e of c.section('/snmp/community')) {
    const r = c.reader(e);
    const name = r.str('name') ?? e.find?.['name'] ?? e.positional[0] ?? null;
    // The v3 auth/priv passwords are secrets and are never read.
    r.consume('authentication-password', 'encryption-password', 'authentication-protocol',
      'encryption-protocol', 'read-access', 'write-access');
    if (!name) continue;
    const security = r.str('security');
    out.push({
      ...baseOf(r, c.via),
      semKey: serviceKey('other', `snmp-community:${name.toLowerCase()}`),
      keyQuality: 'strong',
      kind: 'service',
      service: 'other',
      rawName: `snmp-community:${name}`,
      enabled: !(r.bool('disabled') ?? false),
      port: null,
      allowedFrom: (() => {
        const addresses = r.str('addresses');
        return addresses
          ? normalizeSelector(splitList(addresses).map((a) => addressAtom(a)))
          : ANY_SELECTOR;
      })(),
      tlsRequired: null,
      certificate: null,
      version: security === 'authorized' || security === 'private' ? 'v3' : 'v2c',
      communityFingerprint: null,
      // §7.2, the ONE assumed exception to "no secret material in the NCM":
      // knowing that a community is literally `public` is the entire point of
      // the audit query, and a fingerprint would destroy it.
      communityIsWellKnown: WELL_KNOWN_COMMUNITIES.has(name.toLowerCase()),
    });
  }

  return out;
}

const WELL_KNOWN_COMMUNITIES = new Set(['public', 'private', 'community', 'admin', 'snmp']);

// ----------------------------------------------------------------------------
// qos
// ----------------------------------------------------------------------------

function buildQosRules(c: BuildCtx): NcmQosRule[] {
  const out: NcmQosRule[] = [];

  for (const e of c.section('/queue/simple')) {
    const r = c.reader(e);
    const name = r.str('name');
    const target = r.str('target');
    const limits = splitRate(r.str('max-limit'));
    const limitAt = splitRate(r.str('limit-at'));
    r.consume('burst-limit', 'burst-threshold', 'burst-time', 'total-queue', 'time',
      'dst', 'packet-marks', 'queue', 'bucket-size');
    const base = baseOf(r, c.via);
    out.push({
      ...base,
      semKey: '',
      keyQuality: name ? 'strong' : 'derived',
      kind: 'qosRule',
      queueClass: 'simple',
      name,
      target: target
        ? normalizeSelector(splitList(target).map((t) => (t.includes('/') || /^\d/.test(t) ? addressAtom(t) : `iface:${t}`)))
        : ANY_SELECTOR,
      // A simple queue selects by target, not by a packet predicate: `match`
      // stays null and the key is the name, which is what RouterOS gives us.
      match: null,
      parent: r.str('parent'),
      priority: firstPriority(r.str('priority')),
      maxLimitUpBps: limits.up,
      maxLimitDownBps: limits.down,
      limitAtUpBps: limitAt.up,
      limitAtDownBps: limitAt.down,
      queueType: r.str('queue'),
      ordinal: 0,
      matchHash: null,
    });
  }

  for (const e of c.section('/queue/tree')) {
    const r = c.reader(e);
    const name = r.str('name');
    const limits = splitRate(r.str('max-limit'));
    const limitAt = splitRate(r.str('limit-at'));
    r.consume('burst-limit', 'burst-threshold', 'burst-time', 'queue', 'packet-mark', 'bucket-size');
    const base = baseOf(r, c.via);
    out.push({
      ...base,
      semKey: '',
      keyQuality: name ? 'strong' : 'derived',
      kind: 'qosRule',
      queueClass: 'tree',
      name,
      target: ANY_SELECTOR,
      match: null,
      parent: r.str('parent'),
      priority: firstPriority(r.str('priority')),
      maxLimitUpBps: limits.up,
      maxLimitDownBps: limits.down,
      limitAtUpBps: limitAt.up,
      limitAtDownBps: limitAt.down,
      queueType: r.str('queue'),
      ordinal: 0,
      matchHash: null,
    });
  }

  return out;
}

/** `2M/10M` -> { up: 2_000_000, down: 10_000_000 }. RouterOS suffixes are
 *  decimal (`1k` = 1000), not binary. */
function splitRate(v: string | null): { up: number | null; down: number | null } {
  if (!v) return { up: null, down: null };
  const [a, b] = v.split('/');
  return { up: rateToBps(a), down: rateToBps(b ?? a) };
}

function rateToBps(v: string | undefined): number | null {
  if (!v) return null;
  const m = /^(\d+(?:\.\d+)?)\s*([kMG]?)$/.exec(v.trim());
  if (!m) return null;
  const mul = m[2] === 'k' ? 1e3 : m[2] === 'M' ? 1e6 : m[2] === 'G' ? 1e9 : 1;
  return Math.round(Number(m[1]) * mul);
}

function firstPriority(v: string | null): number | null {
  if (!v) return null;
  const n = Number(v.split('/')[0]);
  return Number.isInteger(n) && n >= 1 && n <= 8 ? n : null;
}

// ============================================================================
// Ordinals (§3.4) and order analysis (§4.3)
// ============================================================================

/**
 * Assigns `ordinal` inside each collision class and finalises every `semKey`.
 *
 * THE PROBLEM, restated. Two rules of one chain that select the same packets
 * and act differently share a `matchHash`. `ordinal` discriminates them.
 * Assigned ABSOLUTELY, inserting a third rule of the same predicate at position
 * 3 shifts `#1`->`#2`, `#2`->`#3`… and produces a cascade of false `changed`.
 *
 * THE FIX (§3.4 case 2): ordinals are assigned by PAIRING WITH THE PREVIOUS
 * SNAPSHOT — greedy assignment on `|posA − posB|` inside each collision class,
 * unpaired rules taking the first free ordinal. The cascade collapses to one
 * `extra` for the rule actually inserted.
 *
 * RESIDUAL LIMIT, stated: the very first snapshot of a device, and any snapshot
 * after a multi-day collection gap, fall back to absolute assignment. That is
 * why `ordinalCollisionRate` is instrumented — §3.4 makes it a milestone EXIT
 * criterion: past ~2 % of rules in a collision class, the key design has to be
 * revisited rather than patched.
 *
 * @returns the fraction of ordered rules that live in a collision class of size > 1.
 */
function assignOrdinals(
  firewallRules: NcmFirewallRule[],
  natRules: NcmNatRule[],
  qosRules: NcmQosRule[],
  previous: NcmDocument | null,
): number {
  let collided = 0;
  let total = 0;

  const run = <T extends NcmOrderedRule>(
    rules: T[],
    kind: 'firewallRule' | 'natRule' | 'qosRule',
    prior: readonly T[],
  ): void => {
    // Collision class = (chain, chainName, matchHash). A marker-anchored rule
    // is outside every class: its key is the marker.
    const classes = new Map<string, T[]>();
    rules.forEach((rule) => {
      total++;
      if (rule.managedSlug) return;
      const cls = classKey(rule);
      const list = classes.get(cls);
      if (list) list.push(rule); else classes.set(cls, [rule]);
    });

    const priorByClass = new Map<string, Array<{ ordinal: number; index: number }>>();
    prior.forEach((rule, index) => {
      if (rule.managedSlug) return;
      const cls = classKey(rule);
      const list = priorByClass.get(cls) ?? [];
      list.push({ ordinal: rule.ordinal, index });
      priorByClass.set(cls, list);
    });

    for (const [cls, members] of classes) {
      if (members.length > 1) collided += members.length;
      const old = (priorByClass.get(cls) ?? []).slice();
      const used = new Set<number>();
      const assigned = new Map<T, number>();

      // Greedy nearest-position pairing with the previous snapshot.
      const positions = members.map((m) => rules.indexOf(m));
      const pairs: Array<{ dist: number; member: number; old: number }> = [];
      members.forEach((_, i) => {
        old.forEach((o, j) => pairs.push({ dist: Math.abs(positions[i] - o.index), member: i, old: j }));
      });
      pairs.sort((a, b) => a.dist - b.dist || a.member - b.member || a.old - b.old);
      const takenMembers = new Set<number>();
      const takenOld = new Set<number>();
      for (const p of pairs) {
        if (takenMembers.has(p.member) || takenOld.has(p.old)) continue;
        if (used.has(old[p.old].ordinal)) continue;
        takenMembers.add(p.member);
        takenOld.add(p.old);
        used.add(old[p.old].ordinal);
        assigned.set(members[p.member], old[p.old].ordinal);
      }

      let next = 0;
      members.forEach((m, i) => {
        if (assigned.has(m)) return;
        while (used.has(next)) next++;
        used.add(next);
        assigned.set(m, next);
        void i;
      });

      for (const m of members) m.ordinal = assigned.get(m) ?? 0;
      void cls;
    }

    for (const rule of rules) {
      rule.semKey = kind === 'qosRule'
        ? qosRuleKey(
          (rule as NcmQosRule).queueClass,
          (rule as NcmQosRule).name,
          rule.matchHash,
          rule.ordinal,
          rule.managedSlug,
        )
        : orderedRuleKey(
          kind,
          (rule as NcmFirewallRule | NcmNatRule).chain,
          (rule as NcmFirewallRule | NcmNatRule).chainName,
          rule.matchHash,
          rule.ordinal,
          rule.managedSlug,
        );
    }
  };

  const priorFw = previous?.resources.firewallRules ?? [];
  const priorNat = previous?.resources.natRules ?? [];
  const priorQos = previous?.resources.qosRules ?? [];
  run(firewallRules, 'firewallRule', priorFw);
  run(natRules, 'natRule', priorNat);
  run(qosRules, 'qosRule', priorQos);

  return total === 0 ? 0 : collided / total;
}

function classKey(rule: NcmOrderedRule): string {
  if (rule.kind === 'qosRule') return `${rule.queueClass}|${rule.name ?? rule.matchHash ?? ''}`;
  return `${rule.chain}|${rule.chainName ?? ''}|${rule.matchHash}`;
}

/**
 * §4.3. `partial` means at least one chain went past the O(n²) budget and only
 * a ±25 window was compared; the drift UI shows the order analysis as degraded
 * and K2 refuses to return ACCEPT on it. Recorded on the DOCUMENT because it is
 * a property of what we managed to analyse, not of a particular run.
 */
function computeOrderAnalysis(rules: readonly NcmOrderedRule[]): OrderAnalysisState {
  const chains = new Map<string, NcmOrderedRule[]>();
  for (const rule of rules) {
    const key = rule.kind === 'qosRule'
      ? `qosRule|${rule.queueClass}|${rule.parent ?? ''}`
      : `${rule.kind}|${rule.chain}|${rule.chainName ?? ''}`;
    const list = chains.get(key);
    if (list) list.push(rule); else chains.set(key, [rule]);
  }
  let partial = false;
  for (const [, chain] of chains) {
    if (buildOrderSignature(chain).analysis === 'partial') partial = true;
  }
  return partial ? 'partial' : 'full';
}

// ============================================================================
// Coverage (N3) — the guard that stops a partial read from proposing a wipe
// ============================================================================

/**
 * N3 IS THE ANTI-CATASTROPHE GUARD, and this function is where honesty is
 * expensive. `complete` is the ONLY value that lets the diff emit `missing`,
 * i.e. the only value that lets the planner propose to CREATE something because
 * it is absent. Claiming `complete` when the collection was partial is how a
 * plan that recreates a whole firewall gets generated.
 *
 * TWO KINDS ARE DELIBERATELY NEVER `complete` FROM AN EXPORT ALONE:
 *
 *  - `interface`: `/export` does not emit an interface left at its factory
 *    settings. A hEX with ether2..ether5 untouched shows none of them. The
 *    list we build is "what was modified, plus what carries an address, a
 *    bridge port or a list membership". Declaring it complete would make the
 *    diff announce `missing` on four interfaces that exist.
 *  - `service`: `/ip/service` at its factory value is omitted too, and the
 *    factory value differs between models and between defconf generations. It
 *    becomes `complete` only when the N09 dictionary has been LEARNED for this
 *    EXACT firmware, which is precisely what `/export terse verbose` is for.
 *
 * And ANY unparsed line downgrades EVERYTHING: a line we could not read may
 * have been a firewall rule, and no per-kind reasoning survives that.
 */
function computeCoverage(
  parsed: ParsedExport,
  ctx: NormalizeContext,
  counts: Record<NcmResourceKind, number>,
): NcmCoverageMap {
  const parseGap = parsed.unparsed.length > 0;
  const serviceDefaultsLearned = [...ctx.defaults.keys()].some((k) => k.startsWith('/ip/service|'));

  const make = (kind: NcmResourceKind): NcmCoverage => {
    let state: CoverageState = 'complete';
    let reason: string | null = null;

    if (kind === 'interface') {
      state = 'partial';
      reason = '/export omits an interface left at its factory settings; the list is what was ' +
        'modified plus what carries an address, a bridge port or an interface-list membership.';
    } else if (kind === 'service' && !serviceDefaultsLearned) {
      state = 'partial';
      reason = '/ip/service at its factory value is omitted by /export, and the factory value ' +
        'differs by model and by defconf generation. Learn the defaults ' +
        '(`/export terse verbose`, N09) to make this complete.';
    } else if (kind === 'qosRule' && counts.qosRule === 0) {
      // Nothing to say: an absent /queue section really does mean no queues.
      state = 'complete';
    }

    if (parseGap) {
      state = 'partial';
      reason = `${parsed.unparsed.length} line(s) of the export could not be parsed ` +
        `(first at line ${parsed.unparsed[0].line}); completeness cannot be claimed for any kind.`;
    }
    return { state, via: ctx.via, reason, recordCount: counts[kind] };
  };

  const out = {} as Record<NcmResourceKind, NcmCoverage>;
  for (const kind of NCM_RESOURCE_KINDS) out[kind] = make(kind);
  return out as NcmCoverageMap;
}

// ============================================================================
// Re-exports for the collector, so a caller needs one import
// ============================================================================

export { canonicalizeText, unfoldLines };
