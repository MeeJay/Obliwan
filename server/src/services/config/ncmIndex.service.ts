// ============================================================================
// ObliWAN — the flattened NCM index, and the ordinal reconciliation
// ============================================================================
//
// Implements §6.1 and §8.3 of `docs/M4-NCM-contrat.md` plus decision 2 and 3 of
// migration `007_config.ts`.
//
// ┌─ WHAT THESE TABLES ARE, AND WHAT THEY ARE NOT ────────────────────────────┐
// │ `ncm_*` is a CACHE. The truth is `config_snapshots.ncm` (the document)    │
// │ and `config_snapshots.raw_gz` (the archive it was derived from). Every    │
// │ row here can be thrown away and rebuilt from the jsonb; that is why       │
// │ adding a resource kind is "a new table plus a resumable backfill" and     │
// │ never a blocking UPDATE over 200 000 rows. Nothing in the product may     │
// │ read a flattened row as authoritative — it exists to make Fleet Query     │
// │ (K5) a SQL join instead of a jsonb scan.                                  │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THE ORDINAL, WHICH IS THE HARD PART ─────────────────────────────────────┐
// │ §3.4 case 2: inserting a rule whose predicate ALREADY EXISTS shifts every │
// │ following ordinal of its collision class by one. With absolute            │
// │ assignment that is a cascade of false `changed` down the whole class —    │
// │ ten findings for one inserted rule, which is exactly R3.                  │
// │                                                                          │
// │ The mitigation is that ordinals are assigned BY PAIRING WITH THE PREVIOUS │
// │ SNAPSHOT (greedy on |Δposition| inside each collision class). The         │
// │ cascade then collapses to ONE `extra` for the rule actually inserted.     │
// │                                                                          │
// │ The consequence is structural and must not be undone: an ordinal is NOT a │
// │ function of the current document alone. It is written into the document   │
// │ before hashing and persisted; recomputing it at read time reintroduces    │
// │ the cascade this whole mechanism exists to remove.                        │
// └───────────────────────────────────────────────────────────────────────────┘

import type { Knex } from 'knex';
import type {
  NcmDocument, NcmOrderedRule, NcmResource, NcmResourceKind,
} from '@obliwan/shared';
import { buildSemKey, computePayloadHash, RESOURCE_KIND_TO_COLLECTION } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';

// ============================================================================
// Table mapping
// ============================================================================

/** The ten flattened tables of migration 007, and which carry the two
 *  rule-only columns. Mirrors `FLAT_TABLES` in that migration; a mismatch here
 *  is an insert that throws, which is the failure mode we want. */
export const FLAT_TABLE: Readonly<Record<NcmResourceKind, { table: string; ruleLike: boolean }>> = {
  interface: { table: 'ncm_interfaces', ruleLike: false },
  // v2 — no flat table yet: nothing parses this kind, so nothing is indexed.
  dhcpClient: { table: 'ncm_dhcp_clients', ruleLike: false },
  vlan: { table: 'ncm_vlans', ruleLike: false },
  route: { table: 'ncm_routes', ruleLike: false },
  firewallRule: { table: 'ncm_firewall_rules', ruleLike: true },
  natRule: { table: 'ncm_nat_rules', ruleLike: true },
  dhcpScope: { table: 'ncm_dhcp_scopes', ruleLike: false },
  ipsecPeer: { table: 'ncm_ipsec_peers', ruleLike: false },
  localUser: { table: 'ncm_local_users', ruleLike: false },
  service: { table: 'ncm_services', ruleLike: false },
  qosRule: { table: 'ncm_qos_rules', ruleLike: true },
};

/** Every resource of a document, kind by kind, in the document's own order. */
export function resourcesOf(doc: NcmDocument, kind: NcmResourceKind): NcmResource[] {
  const key = RESOURCE_KIND_TO_COLLECTION[kind] as keyof NcmDocument['resources'];
  return (doc.resources[key] ?? []) as unknown as NcmResource[];
}

/**
 * The ORDER GROUP a position is relative to. A rule in `input` cannot precede a
 * rule in `forward` in any meaningful sense, so a position that is not
 * qualified by its chain is a number that means nothing.
 */
export function orderGroupOf(r: NcmResource): string | null {
  if (r.kind === 'firewallRule' || r.kind === 'natRule') {
    return r.chainName ? `${r.chain}:${r.chainName}` : r.chain;
  }
  if (r.kind === 'qosRule') return r.queueClass;
  return null;
}

/**
 * The COLLISION CLASS of an ordered rule: the set within which `ordinal`
 * discriminates. Two rules of the same class are indistinguishable by
 * predicate — which, per N1, is the whole of their identity.
 */
export function collisionClassOf(r: NcmOrderedRule): string {
  const group = orderGroupOf(r) ?? '';
  return `${group}|${r.matchHash ?? 'nomatch'}`;
}

// ============================================================================
// Ordinal reconciliation (§3.4 case 2)
// ============================================================================

export interface OrdinalReconciliation {
  /** A NEW document. The input is never mutated: it may be the object a caller
   *  still holds a hash of. */
  doc: NcmDocument;
  /** How many rules received an ordinal different from the one the parser
   *  assigned. Zero on an unchanged device, which is what makes the
   *  deduplication survive this step. */
  rewritten: number;
  /** §3.4's milestone exit metric: the share of ordered rules that live in a
   *  collision class of size > 1. Above ~2 % on a real fleet, the key design
   *  itself must be revisited before going further. */
  ordinalCollisionRate: number;
  ruleCount: number;
  collidingCount: number;
}

interface Slot {
  index: number;      // position inside the chain, as collected
  rule: NcmOrderedRule;
}

/** `computePayloadHash` already excludes `ordinal` and `semKey`, which is what
 *  makes it usable as the pairing signal here: it is the part of the rule that
 *  an ordinal reassignment must not be allowed to influence. */
function payloadOf(rule: NcmOrderedRule): string {
  return computePayloadHash(rule as unknown as Record<string, unknown>);
}

/**
 * Greedy assignment inside one collision class: IDENTICAL PAYLOAD FIRST, then
 * |Δposition|.
 *
 * ── DIVERGENCE FROM THE LITERAL TEXT OF §3.4, AND WHY ──────────────────────
 * The study writes "affectation gloutonne sur |posA − posB|" — position alone.
 * That does not work, and the study's own worked example is the proof. Take a
 * collision class of four rules A B C D carrying ordinals 0 1 2 3, and insert a
 * new rule N of the same predicate at position 1:
 *
 *     previous:  A@0  B@1  C@2  D@3
 *     current:   A@0  N@1  B@2  C@3  D@4
 *
 * Greedy on |Δpos| alone pairs A-A (d=0), N-B (d=0), B-C (d=0), C-D (d=0) and
 * leaves D with the first free ordinal. Every rule of the class then reports a
 * `changed` — which is EXACTLY the cascade the mitigation exists to remove, and
 * exactly what absolute assignment would have produced. Position is the one
 * signal that shifts by construction when a rule is inserted, so it cannot be
 * the signal that detects the insertion.
 *
 * Ranking equal payloads first pairs A-A, B-B, C-C, D-D and leaves N unpaired:
 * ONE `extra`, which is the outcome §3.4 states it wants.
 *
 * ── THE PRICE, STATED ─────────────────────────────────────────────────────
 * §3.4 case 1 (two rules of one class whose actions are SWAPPED) then keeps its
 * ordinals attached to its payloads, so the pair surfaces as ONE `moved`
 * carrying the other rule in `crossed`, rather than as the TWO `changed` the
 * study predicts. One operator action produces one finding instead of two, the
 * severity is `high` either way, and `crossed` names the rule whose precedence
 * flipped. Under R3 that is the better of the two, and it is the only reading
 * under which case 1 and case 2 are both satisfied by one rule.
 *
 * Greedy and not Hungarian, for the reason §3.5 gives for the fuzzy matcher: at
 * these sizes the optimality gain does not pay for the complexity, and a
 * sub-optimal assignment produces noise, never a wrong security decision.
 */
function assignClass(current: Slot[], previous: Slot[]): Map<number, number> {
  // index-in-chain -> ordinal
  const out = new Map<number, number>();
  const takenOrdinals = new Set<number>();

  const payload = new Map<number, string>();
  for (const c of current) payload.set(c.index, payloadOf(c.rule));
  const prevPayload = new Map<number, string>();
  for (const p of previous) prevPayload.set(p.index, payloadOf(p.rule));

  const pairs: { c: number; p: number; d: number; same: number }[] = [];
  for (const c of current) {
    for (const p of previous) {
      pairs.push({
        c: c.index,
        p: p.index,
        d: Math.abs(c.index - p.index),
        same: payload.get(c.index) === prevPayload.get(p.index) ? 0 : 1,
      });
    }
  }
  // Stable: payload identity, then distance, then the current position, then
  // the previous position. Without the tie-breaks two runs over the same input
  // could disagree, and a non-deterministic ordinal is a non-deterministic
  // ncm_hash — which would turn the deduplication into a row generator.
  pairs.sort((x, y) => x.same - y.same || x.d - y.d || x.c - y.c || x.p - y.p);

  const usedCurrent = new Set<number>();
  const usedPrevious = new Set<number>();
  const prevByIndex = new Map(previous.map((s) => [s.index, s.rule]));

  for (const pair of pairs) {
    if (usedCurrent.has(pair.c) || usedPrevious.has(pair.p)) continue;
    const prevRule = prevByIndex.get(pair.p);
    if (!prevRule) continue;
    if (takenOrdinals.has(prevRule.ordinal)) continue;
    usedCurrent.add(pair.c);
    usedPrevious.add(pair.p);
    takenOrdinals.add(prevRule.ordinal);
    out.set(pair.c, prevRule.ordinal);
  }

  // Anything unpaired — the genuinely new rules — takes the first free ordinal.
  let next = 0;
  for (const c of current) {
    if (out.has(c.index)) continue;
    while (takenOrdinals.has(next)) next++;
    takenOrdinals.add(next);
    out.set(c.index, next);
  }
  return out;
}

/**
 * Re-key the three ordered collections of `doc` against `previous`.
 *
 * MUST run BEFORE `ncmHash()`: `ordinal` is part of a derived `semKey`, and a
 * `semKey` is part of the hashed resource. Running it after would store a
 * document whose hash does not describe its own content.
 *
 * `previous` is `null` for a device's first snapshot, and after a collection
 * gap long enough that the previous document is no longer a useful reference.
 * Both fall back to absolute assignment, which §3.4 states as the residual
 * limit rather than hiding it.
 */
export function reconcileOrdinals(
  doc: NcmDocument,
  previous: NcmDocument | null,
): OrdinalReconciliation {
  const ORDERED: NcmResourceKind[] = ['firewallRule', 'natRule', 'qosRule'];
  const resources = { ...doc.resources };
  let rewritten = 0;
  let ruleCount = 0;
  let collidingCount = 0;

  for (const kind of ORDERED) {
    const key = RESOURCE_KIND_TO_COLLECTION[kind] as keyof NcmDocument['resources'];
    const rules = (doc.resources[key] ?? []) as unknown as NcmOrderedRule[];
    if (rules.length === 0) continue;
    ruleCount += rules.length;

    const prevRules = previous
      ? ((previous.resources[key] ?? []) as unknown as NcmOrderedRule[])
      : [];

    const curByClass = new Map<string, Slot[]>();
    rules.forEach((rule, index) => {
      const cls = collisionClassOf(rule);
      const list = curByClass.get(cls);
      if (list) list.push({ index, rule });
      else curByClass.set(cls, [{ index, rule }]);
    });

    const prevByClass = new Map<string, Slot[]>();
    prevRules.forEach((rule, index) => {
      const cls = collisionClassOf(rule);
      const list = prevByClass.get(cls);
      if (list) list.push({ index, rule });
      else prevByClass.set(cls, [{ index, rule }]);
    });

    const next = rules.slice();
    for (const [cls, slots] of curByClass) {
      if (slots.length > 1) collidingCount += slots.length;
      const assignment = assignClass(slots, prevByClass.get(cls) ?? []);
      for (const slot of slots) {
        const ordinal = assignment.get(slot.index);
        if (ordinal === undefined || ordinal === slot.rule.ordinal) continue;
        const updated = { ...slot.rule, ordinal } as NcmOrderedRule;
        // The semKey of a derived key EMBEDS the ordinal; the semKey of a
        // marker-anchored key does not. `buildSemKey` knows which, so nothing
        // here has to.
        (updated as { semKey: string }).semKey = buildSemKey(updated as NcmResource);
        next[slot.index] = updated;
        rewritten++;
      }
    }
    (resources as Record<string, unknown>)[key] = next;
  }

  return {
    doc: { ...doc, resources },
    rewritten,
    ruleCount,
    collidingCount,
    ordinalCollisionRate: ruleCount === 0 ? 0 : collidingCount / ruleCount,
  };
}

// ============================================================================
// Flattening
// ============================================================================

export interface FlatRow {
  device_id: number;
  snapshot_id: string;
  sem_key: string;
  position: number | null;
  order_group: string | null;
  props: string;
  is_managed: boolean;
  managed_slug: string | null;
  key_quality: string;
  payload_hash: string;
  match_hash?: string | null;
  ordinal?: number | null;
}

/**
 * One document -> the rows of one table.
 *
 * `position` is the index inside the ORDER GROUP, not inside the collection: a
 * chain restarts at 0. It is auditable and NEVER diffed as a value — N2 says
 * position is not a field, and an inert reordering updates this column while
 * producing no finding at all.
 */
export function flattenKind(
  doc: NcmDocument,
  kind: NcmResourceKind,
  deviceId: number,
  snapshotId: string,
): FlatRow[] {
  const ruleLike = FLAT_TABLE[kind].ruleLike;
  const positionByGroup = new Map<string, number>();
  const rows: FlatRow[] = [];

  for (const r of resourcesOf(doc, kind)) {
    const group = orderGroupOf(r);
    let position: number | null = null;
    if (group !== null) {
      const p = positionByGroup.get(group) ?? 0;
      position = p;
      positionByGroup.set(group, p + 1);
    }
    const row: FlatRow = {
      device_id: deviceId,
      snapshot_id: snapshotId,
      sem_key: r.semKey,
      position,
      order_group: group,
      props: JSON.stringify(r),
      is_managed: r.managedBy === 'obliwan',
      managed_slug: r.managedSlug,
      key_quality: r.keyQuality,
      payload_hash: computePayloadHash(r as unknown as Record<string, unknown>),
    };
    if (ruleLike) {
      const rule = r as NcmOrderedRule;
      row.match_hash = rule.matchHash ?? null;
      row.ordinal = rule.ordinal;
    }
    rows.push(row);
  }
  return rows;
}

export class SemKeyCollisionError extends Error {
  readonly table: string;
  readonly semKey: string;
  constructor(table: string, semKey: string) {
    super(
      `Two records share sem_key '${semKey}' inside one snapshot (${table}). That is a parser ` +
        'bug: the pairing algorithm would match one of them arbitrarily and the resulting ' +
        'finding would name the wrong rule. Indexing is refused.',
    );
    this.name = 'SemKeyCollisionError';
    this.table = table;
    this.semKey = semKey;
  }
}

/**
 * Regenerate every flattened row for one snapshot, in ONE transaction.
 *
 * The `UNIQUE(snapshot_id, sem_key)` of migration 007 is a deliberate tripwire
 * and it is checked here first, in TypeScript, so the error names the key
 * instead of surfacing as a Postgres 23505 with a constraint name. The database
 * constraint stays as the backstop for anything that bypasses this function.
 *
 * The consequence is stated in the migration and repeated here: a parser bug
 * BLOCKS indexing rather than degrading it. Absorbing the collision would make
 * `ordinalCollisionRate` — a milestone exit criterion — silently wrong.
 */
export async function indexSnapshot(
  trx: Knex | Knex.Transaction,
  input: { snapshotId: string; deviceId: number; doc: NcmDocument },
): Promise<{ rows: number; byKind: Record<string, number> }> {
  const byKind: Record<string, number> = {};
  let total = 0;

  for (const kind of Object.keys(FLAT_TABLE) as NcmResourceKind[]) {
    const { table } = FLAT_TABLE[kind];
    // A rebuild must be idempotent: the cache is regenerated per snapshot, and
    // a re-index after a parser fix must not append a second copy.
    await trx(table).where({ snapshot_id: input.snapshotId }).del();

    const rows = flattenKind(input.doc, kind, input.deviceId, input.snapshotId);
    const seen = new Set<string>();
    for (const row of rows) {
      if (seen.has(row.sem_key)) throw new SemKeyCollisionError(table, row.sem_key);
      seen.add(row.sem_key);
    }
    if (rows.length > 0) {
      // Chunked: a 500-rule firewall on 10 tables is still one statement per
      // chunk, and a single 20 000-parameter INSERT trips the pg driver.
      for (let i = 0; i < rows.length; i += 500) {
        await trx(table).insert(rows.slice(i, i + 500));
      }
    }
    byKind[kind] = rows.length;
    total += rows.length;
  }

  return { rows: total, byKind };
}

/** Rebuild the cache of one stored snapshot from its jsonb. The escape hatch of
 *  §8.3: nothing else has to be true for this to work. */
export async function reindexSnapshot(snapshotId: string): Promise<{ rows: number }> {
  const row = await db('config_snapshots')
    .where({ id: snapshotId })
    .first<{ id: string; device_id: number; ncm: unknown } | undefined>('id', 'device_id', 'ncm');
  if (!row) throw new Error(`Snapshot ${snapshotId} does not exist`);

  const result = await db.transaction((trx) =>
    indexSnapshot(trx, {
      snapshotId: String(row.id),
      deviceId: row.device_id,
      doc: row.ncm as NcmDocument,
    }),
  );
  logger.info({ snapshotId, rows: result.rows }, 'NCM index rebuilt');
  return { rows: result.rows };
}
