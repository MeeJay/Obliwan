// ============================================================================
// M12 / K8 — step 2: aligning sites, and reading the variables off the result
// ============================================================================
//
// Everything in this file is PURE and DETERMINISTIC. Two runs over the same
// documents produce byte-identical drafts, which is the whole reason
// ARCHITECTURE.md forbids an LLM here: "present on 27 of your 30 sites" is a
// sentence an operator can check, and a model's opinion is not.
//
// ┌─ THE ONE IDEA ────────────────────────────────────────────────────────────┐
// │ Group every member's facts by slot. A slot on which the members AGREE is  │
// │ a constant and goes into the body as a literal. A slot on which they      │
// │ DISAGREE — same structural place, different values — is a variable, and   │
// │ that is the entirety of "détection de variables par alignement            │
// │ inter-sites". A slot on which a SINGLE member disagrees with itself is    │
// │ divergent: the miner failed to key two resources apart, and it says so    │
// │ instead of templating one of them at random.                              │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHY COVERAGE IS COUNTED PER MEMBER AND NOT PER TEMPLATE ─────────────────┐
// │ "80 % of the lines covered" has to mean "80 % of what is ON THIS ROUTER   │
// │ is explained by the template". Counting the other way — what fraction of  │
// │ the template's lines a device satisfies — flatters a small template: an   │
// │ empty template covers 100 % of itself and 0 % of the fleet. The           │
// │ denominator is therefore always the DEVICE's fact count.                  │
// └───────────────────────────────────────────────────────────────────────────┘

import {
  BASELINE_SECTION_WEIGHTS, baselineDraftHeader, baselineDraftLine,
  slotIsForbidden, slotToVarName, varSchemaFor,
  type BaselineDeviationKind, type BaselineParams, type BaselineSlotStat,
  type BaselineValueClass,
} from '@obliwan/shared/dist/baseline';
import { sha256Hex, type NcmResourceKind } from '@obliwan/shared';
import type { DeviceFacts } from './facts';

// ============================================================================
// 1. Alignment
// ============================================================================

interface SlotAccumulator {
  section: NcmResourceKind;
  klass: BaselineValueClass;
  /** deviceId -> the distinct values that device carries at this slot. */
  byDevice: Map<number, Set<string>>;
  /** Every distinct value, across every device. */
  values: Set<string>;
}

/**
 * Aligns a set of members on their slots.
 *
 * `members` is expected to be sorted by deviceId by the caller; the output is
 * sorted by slot regardless, so the draft body of a given cluster never depends
 * on the order rows came back from Postgres.
 */
export function alignMembers(
  members: readonly DeviceFacts[],
  params: BaselineParams,
): BaselineSlotStat[] {
  const acc = new Map<string, SlotAccumulator>();

  for (const m of members) {
    for (const f of m.facts) {
      // Belt to the braces of `emit()` in facts.ts: this is the second of the
      // two independent secret refusals, and it is the one that still fires if
      // somebody builds a fact list without going through the sink.
      if (slotIsForbidden(f.slot)) continue;
      let a = acc.get(f.slot);
      if (!a) {
        a = { section: f.section, klass: f.klass, byDevice: new Map(), values: new Set() };
        acc.set(f.slot, a);
      }
      let set = a.byDevice.get(m.deviceId);
      if (!set) { set = new Set(); a.byDevice.set(m.deviceId, set); }
      set.add(f.value);
      a.values.add(f.value);
    }
  }

  const memberCount = members.length;
  const stats: BaselineSlotStat[] = [];
  // Variable names must be unique inside one template: `var_schema` is an
  // object and Nunjucks resolves by name. A collision is resolved by hashing
  // the full slot, deterministically, so it survives a re-run.
  const takenVarNames = new Set<string>();

  for (const slot of [...acc.keys()].sort()) {
    const a = acc.get(slot)!;
    const presentOn = a.byDevice.size;
    const divergent = [...a.byDevice.values()].some((s) => s.size > 1);
    const distinct = a.values.size;

    let role: BaselineSlotStat['role'];
    let constantValue: string | null = null;
    let varName: string | null = null;

    if (divergent) {
      role = 'divergent';
    } else if (distinct === 1) {
      role = 'constant';
      constantValue = [...a.values][0];
    } else {
      role = 'variable';
      let name = slotToVarName(slot);
      if (takenVarNames.has(name)) name = slotToVarName(slot, true);
      takenVarNames.add(name);
      varName = name;
    }

    stats.push({
      slot,
      section: a.section,
      role,
      presentOn,
      memberCount,
      distinctValues: distinct,
      constantValue,
      varName,
      valueClass: a.klass,
      sampleValues: [...a.values].sort().slice(0, 8),
    });
  }

  return stats;
}

/**
 * Which of the aligned slots make it into the draft body.
 *
 * A `divergent` slot never does (decision: a template that silently drops half
 * a firewall is worse than a template with a hole somebody can see). A slot
 * carried by fewer than `bodyPresenceRatio` of the members does not either: it
 * is a difference to classify, not a line to push. `1.0` would let one
 * eccentric site erase a line the other twenty-nine share, which is precisely
 * the failure mode the ratio exists to avoid.
 */
export function bodySlots(
  stats: readonly BaselineSlotStat[],
  params: BaselineParams,
): BaselineSlotStat[] {
  const min = params.bodyPresenceRatio * (stats[0]?.memberCount ?? 0);
  return stats.filter((s) => s.role !== 'divergent' && s.presentOn >= min - 1e-9);
}

// ============================================================================
// 2. Coverage and deviations
// ============================================================================

export interface MemberDeviation {
  deviceId: number;
  slot: string;
  section: NcmResourceKind;
  kind: BaselineDeviationKind;
  templateValue: string | null;
  deviceValue: string | null;
}

export interface MemberEvaluation {
  deviceId: number;
  factsTotal: number;
  factsCovered: number;
  coverage: number;
  deviations: MemberDeviation[];
}

/**
 * One member against the template its cluster produced.
 *
 * A `variable` slot absorbs ANY value — that is what makes it a variable, and
 * it is why a fleet with thirty different LAN prefixes can still reach 100 %
 * coverage on one template. A `constant` slot only covers the value it pins;
 * anything else is a `value_conflict`, which is the honest answer: the template
 * says one thing and this router says another, and somebody has to decide which
 * of the two is wrong.
 */
export function evaluateMember(
  member: DeviceFacts,
  body: readonly BaselineSlotStat[],
): MemberEvaluation {
  const bodyBySlot = new Map(body.map((s) => [s.slot, s]));
  const deviations: MemberDeviation[] = [];
  const seen = new Set<string>();
  let covered = 0;

  for (const f of member.facts) {
    if (slotIsForbidden(f.slot)) continue;
    seen.add(f.slot);
    const stat = bodyBySlot.get(f.slot);
    if (!stat) {
      deviations.push({
        deviceId: member.deviceId,
        slot: f.slot,
        section: f.section,
        kind: 'extra',
        templateValue: null,
        deviceValue: f.value,
      });
      continue;
    }
    if (stat.role === 'variable' || stat.constantValue === f.value) {
      covered++;
      continue;
    }
    deviations.push({
      deviceId: member.deviceId,
      slot: f.slot,
      section: f.section,
      kind: 'value_conflict',
      templateValue: stat.constantValue,
      deviceValue: f.value,
    });
  }

  for (const stat of body) {
    if (seen.has(stat.slot)) continue;
    deviations.push({
      deviceId: member.deviceId,
      slot: stat.slot,
      section: stat.section,
      kind: 'missing',
      // A missing VARIABLE has no single expected value; the shape constraint
      // of migration 017 still requires one, and the honest one is the name of
      // the variable that was never filled — not a value picked from another
      // site, which would read as an instruction to copy one customer's
      // addressing onto another's router.
      templateValue: stat.role === 'variable' ? `{{ ${stat.varName} }}` : stat.constantValue,
      deviceValue: null,
    });
  }

  const total = member.facts.filter((f) => !slotIsForbidden(f.slot)).length;
  return {
    deviceId: member.deviceId,
    factsTotal: total,
    factsCovered: covered,
    coverage: total === 0 ? 1 : covered / total,
    deviations,
  };
}

// ============================================================================
// 3. Cohesion
// ============================================================================

/** Mean pairwise weighted-Jaccard similarity inside a cluster. 1 for a
 *  singleton: one site is perfectly consistent with itself, and reporting 0
 *  would make every eccentric site look like a data error. */
export function cohesionOf(similarity: number[][], members: readonly number[]): number {
  if (members.length < 2) return 1;
  let sum = 0;
  let n = 0;
  for (let i = 0; i < members.length; i++) {
    for (let j = i + 1; j < members.length; j++) {
      sum += similarity[members[i]][members[j]];
      n++;
    }
  }
  return n === 0 ? 1 : sum / n;
}

/** The member with the smallest total distance to the others — the site to open
 *  when somebody asks what this profile actually looks like. Ties break on the
 *  lowest index, so the answer is stable across runs. */
export function medoidOf(similarity: number[][], members: readonly number[]): number {
  let best = members[0];
  let bestCost = Number.POSITIVE_INFINITY;
  for (const i of members) {
    let cost = 0;
    for (const j of members) if (i !== j) cost += 1 - similarity[i][j];
    if (cost < bestCost - 1e-12) { bestCost = cost; best = i; }
  }
  return best;
}

// ============================================================================
// 4. The draft body
// ============================================================================

export interface DraftBody {
  body: string;
  bodySha256: string;
  varSchema: Record<string, unknown>;
  lineCount: number;
  variableCount: number;
}

/** Section order in the rendered body. Not alphabetical: a reviewer reads a
 *  configuration from the interfaces outwards, and the drafts are read by
 *  humans before they are read by anything else. */
const SECTION_ORDER: readonly NcmResourceKind[] = [
  'interface', 'vlan', 'route', 'dhcpScope', 'ipsecPeer',
  'firewallRule', 'natRule', 'qosRule', 'service', 'localUser',
];

export function renderDraft(
  label: string,
  brand: string,
  memberCount: number,
  coverageMean: number,
  body: readonly BaselineSlotStat[],
): DraftBody {
  const lines: string[] = [baselineDraftHeader(label, memberCount, brand, coverageMean)];
  const properties: Record<string, unknown> = {};
  const required: string[] = [];
  let variableCount = 0;
  let lineCount = 0;

  for (const section of SECTION_ORDER) {
    const inSection = body.filter((s) => s.section === section);
    if (inSection.length === 0) continue;
    lines.push('');
    lines.push(
      `{# ── ${section} — ${inSection.length} fact(s), weight ` +
        `${BASELINE_SECTION_WEIGHTS[section]} ── #}`,
    );
    for (const stat of inSection) {
      lines.push(baselineDraftLine(stat));
      lineCount++;
      if (stat.role === 'variable' && stat.varName) {
        variableCount++;
        properties[stat.varName] = varSchemaWithTitle(stat);
        required.push(stat.varName);
      }
    }
  }

  const text = lines.join('\n') + '\n';
  return {
    body: text,
    bodySha256: sha256Hex(text),
    varSchema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties,
      // Every mined variable is REQUIRED, and that pairs with
      // `throwOnUndefined` being the default of the render engine: a variable
      // nobody filled must break the render, not silently emit an empty
      // `src-address=` that RouterOS reads as "any".
      required: required.sort(),
      additionalProperties: false,
    },
    lineCount,
    variableCount,
  };
}

/** The JSON Schema fragment for one mined variable, carrying the provenance
 *  that makes it fillable: which slot it came from and what the fleet already
 *  uses there. */
function varSchemaWithTitle(stat: BaselineSlotStat): Record<string, unknown> {
  return {
    ...varSchemaFor(stat.valueClass),
    title: stat.slot,
    description:
      `Mined from ${stat.presentOn}/${stat.memberCount} member(s); ` +
      `${stat.distinctValues} distinct value(s) observed, e.g. ` +
      stat.sampleValues.slice(0, 3).join(', '),
  };
}
