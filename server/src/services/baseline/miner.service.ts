// ============================================================================
// M12 / K8 — the miner: a fleet in, a set of reviewable templates out
// ============================================================================
//
// This is the adoption wall of ARCHITECTURE.md §5/M12. Before it, ObliWAN asks
// an operator to hand-write templates for a fleet somebody else built. After
// it, the fleet writes its own first draft and states, per line, how many sites
// agree with it.
//
// THE PIPELINE, IN ORDER
//   1. `facts.ts`   — every readable section of every device's newest NCM
//                     snapshot is cut into atomic (slot, value) facts.
//   2. `cluster.ts` — weighted Jaccard over the SLOT SETS, hierarchical, in a
//                     worker, without an LLM. Structure clusters; values do not.
//   3. `align.ts`   — inside a candidate cluster, a slot the members agree on
//                     is a constant, a slot they disagree on is a VARIABLE.
//   4. here         — the stopping rule, the drafts, the deviations, the
//                     exceptions and the two conformance scores.
//
// ┌─ THE STOPPING RULE, AND WHY IT IS THE WHOLE MILESTONE ────────────────────┐
// │ "Le piège : un cluster mal choisi produit un template que personne ne     │
// │ peut appliquer." So k is not chosen by an elbow, a silhouette or a taste. │
// │ It is the SMALLEST k in 1..maxClusters such that EVERY member of EVERY    │
// │ cluster has at least `minCoverage` of its own facts explained by its      │
// │ cluster's template. Purity is a hard gate; the cluster count only grows   │
// │ to buy it. That is "prefer more, purer clusters" as a stopping rule       │
// │ instead of as a preference, and it is auditable: the run stores the       │
// │ coverage of every k it tried.                                             │
// │                                                                          │
// │ When no k up to maxClusters clears the gate, the run SUCCEEDS with        │
// │ `purity_gate_met = false` and says so. It does not quietly ship the best  │
// │ of a bad set as though it were fine, and it does not fail either — the    │
// │ deviations of a k=4 answer on a fleet that needs six profiles are still   │
// │ the most useful thing anyone has about that fleet.                        │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHAT THIS FILE DOES NOT DO ──────────────────────────────────────────────┐
// │ It does not write to an equipment (D3: nothing does, outside              │
// │ `change_jobs`). It does not publish a template revision: promotion writes │
// │ a `draft` revision, which cannot be assigned, rendered into a plan or     │
// │ applied. It does not emit RouterOS — the draft body is the fact dialect   │
// │ and its own header says so. And it never mines a credential: `facts.ts`   │
// │ refuses the attribute, `align.ts` refuses the slot, and migration 017     │
// │ refuses the INSERT.                                                       │
// └───────────────────────────────────────────────────────────────────────────┘

import type { Knex } from 'knex';
import {
  DEVICE_BRANDS, NcmDocumentStored,
  type NcmDocument, type NcmResourceKind,
} from '@obliwan/shared';
import {
  BASELINE_MODEL_VERSION, BaselineParams, slotIsForbidden,
  type BaselineClusterSummary, type BaselineConformanceRow, type BaselineDeviationRow,
  type BaselineDeviationClass, type BaselineDeviationKind, type BaselineSlotRole,
  type BaselineSlotStat, type BaselineValueClass,
} from '@obliwan/shared/dist/baseline';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { AppError } from '../../middleware/errorHandler';
import { extractFacts, type DeviceFacts } from './facts';
import {
  alignMembers, bodySlots, cohesionOf, evaluateMember, medoidOf, renderDraft,
  type MemberDeviation, type MemberEvaluation,
} from './align';
import { clusterSlotSets } from './cluster';

// ============================================================================
// Row shapes (only the columns this service reads)
// ============================================================================

interface DeviceRow {
  id: number;
  tenant_id: number;
  site_id: number | null;
  name: string;
  brand: string;
}

interface SnapshotRow {
  id: number;
  device_id: number;
  ncm: unknown;
  captured_at: Date;
}

interface ExceptionRow {
  id: number;
  scope: string;
  scope_id: number | null;
  slot: string;
}

export interface BaselineRunSummary {
  id: number;
  uuid: string;
  status: string;
  modelVersion: number;
  params: BaselineParams;
  brand: string | null;
  deviceCount: number;
  skippedCount: number;
  factCount: number;
  slotCount: number;
  clusterCount: number;
  chosenK: number | null;
  purityGateMet: boolean;
  error: string | null;
  startedAt: string | null;
  finishedAt: string | null;
}

// ============================================================================
// 1. Loading the fleet
// ============================================================================

/**
 * How many `ncm` documents may be resident at once.
 *
 * A device row is five small columns; its snapshot is a whole configuration as
 * jsonb, and at the 500-site design point of §6.3 the fleet's documents alone
 * are hundreds of megabytes. The earlier version of this file materialised ALL
 * of them into one Map and held that Map alive for the entire run, on top of
 * the facts, on top of the similarity matrix, on top of the copy `postMessage`
 * clones back from the worker — measured at 1.18 GB of RSS on a 500 × 3000
 * fleet, which is a process kill on the 1 GB container an API normally gets,
 * and with it every RouterOS session the process was holding.
 *
 * So the documents are read in batches and the facts are extracted batch by
 * batch: after `extractFacts`, the document is garbage and is allowed to be.
 * The facts themselves are what the run is FOR and they stay.
 */
export const FLEET_SNAPSHOT_BATCH = 25;

/**
 * The largest fleet one run may take in a single pass.
 *
 * A ceiling that is discovered as an OOM is not a ceiling. `deviceIds` is
 * capped at 2000 by `BaselineParams`, but the default scope is "the whole
 * tenant" and nothing bounded that. Refusing with a message naming the two
 * parameters that narrow a run is the difference between an operator who
 * retries correctly and an operator who watches the API restart.
 */
export const BASELINE_MAX_FLEET = 1000;

/**
 * The devices in scope, bounded.
 *
 * `LIMIT n + 1` rather than `LIMIT n`: the extra row is how the caller can tell
 * "exactly at the ceiling" from "over it" and refuse the second, instead of
 * silently mining an arbitrary prefix of somebody's fleet and calling it a
 * baseline of that fleet.
 */
async function loadDevices(
  trx: Knex,
  tenantId: number,
  params: BaselineParams,
): Promise<DeviceRow[]> {
  const deviceQuery = trx<DeviceRow>('devices')
    .select('id', 'tenant_id', 'site_id', 'name', 'brand')
    .where('tenant_id', tenantId)
    .orderBy('id', 'asc')
    .limit(BASELINE_MAX_FLEET + 1);
  if (params.brand) deviceQuery.andWhere('brand', params.brand);
  if (params.deviceIds.length > 0) deviceQuery.whereIn('id', params.deviceIds);
  return deviceQuery;
}

/**
 * The newest snapshot of each device in ONE batch, no older than
 * `maxSnapshotAgeDays`.
 *
 * `config_snapshots` carries NO tenant column (migration 007) — the join to
 * `devices` is the ONLY thing standing between one customer's baseline and
 * another customer's firewall. It is written here as an inner join with an
 * explicit `devices.tenant_id = ?` and never as a post-filter in JavaScript.
 * Batching does not weaken that: the join and the predicate are inside the
 * batch query, not applied once to a wider result.
 */
async function loadSnapshotBatch(
  trx: Knex,
  tenantId: number,
  deviceIds: readonly number[],
  cutoff: Date,
): Promise<Map<number, SnapshotRow>> {
  if (deviceIds.length === 0) return new Map();
  const rows = (await trx
    .select('s.id', 's.device_id', 's.ncm', 's.captured_at')
    .from(trx.raw('?? as ??', ['config_snapshots', 's']))
    .join(trx.raw('?? as ??', ['devices', 'd']), 's.device_id', 'd.id')
    .where('d.tenant_id', tenantId)
    .whereIn('s.device_id', [...deviceIds])
    .andWhere('s.last_seen_at', '>=', cutoff)
    .orderBy([{ column: 's.device_id' }, { column: 's.last_seen_at', order: 'desc' }])
    .distinctOn('s.device_id')) as unknown as SnapshotRow[];
  return new Map(rows.map((r) => [r.device_id, r]));
}

// ============================================================================
// 2. Candidate partitions
// ============================================================================

interface CandidateCluster {
  members: number[];              // indices into `facts`
  stats: BaselineSlotStat[];
  body: BaselineSlotStat[];
  evaluations: MemberEvaluation[];
  coverageMin: number;
  coverageMean: number;
  cohesion: number;
  medoid: number;
}

function buildCandidate(
  facts: readonly DeviceFacts[],
  similarity: number[][],
  members: number[],
  params: BaselineParams,
): CandidateCluster {
  const memberFacts = members.map((i) => facts[i]);
  const stats = alignMembers(memberFacts, params);
  const body = bodySlots(stats, params);
  const evaluations = memberFacts.map((m) => evaluateMember(m, body));
  const coverages = evaluations.map((e) => e.coverage);
  return {
    members,
    stats,
    body,
    evaluations,
    coverageMin: coverages.length ? Math.min(...coverages) : 1,
    coverageMean: coverages.length
      ? coverages.reduce((a, b) => a + b, 0) / coverages.length
      : 1,
    cohesion: cohesionOf(similarity, members),
    medoid: medoidOf(similarity, members),
  };
}

/** Assignment array -> member index lists, ordered by first appearance. */
function partitionOf(assignment: readonly number[]): number[][] {
  const groups = new Map<number, number[]>();
  for (let i = 0; i < assignment.length; i++) {
    const g = groups.get(assignment[i]);
    if (g) g.push(i); else groups.set(assignment[i], [i]);
  }
  return [...groups.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v);
}

// ============================================================================
// 3. The run
// ============================================================================

export interface BaselineRunOutcome {
  runId: number;
  chosenK: number;
  purityGateMet: boolean;
  deviceCount: number;
  skippedCount: number;
  factCount: number;
  clusterCount: number;
  /** coverage per k tried, in order — the evidence behind the stopping rule. */
  coverageByK: { k: number; coverageMin: number; coverageMean: number }[];
  ranInWorker: boolean;
  clusterDurationMs: number;
}

/**
 * One mining pass per tenant at a time.
 *
 * A run holds the whole scope's facts and an n² similarity matrix; two
 * concurrent runs hold two of each, and nothing in `CONFIG_READ` stops an
 * operator (or a double-clicked button) from starting the second. In-process
 * rather than a `status = 'running'` lookup on purpose: a row left `running` by
 * a killed process would block the tenant forever, whereas this set dies with
 * the process that owns it. It stops the double-click, not a second replica —
 * the real bound on the second replica is `BASELINE_MAX_FLEET`, and the real
 * fix is the pg-boss queue the controller already describes.
 */
const runsInFlight = new Set<number>();

/**
 * The brand filter, checked HERE because the shared schema types it as a
 * string.
 *
 * `BaselineParams.brand` is `z.string().max(24).nullable()` and `baseline_runs`
 * carries `baseline_runs_brand_chk` restricting the column to the four brands.
 * `{"brand":"cisco"}` therefore passed Zod, reached the INSERT, violated the
 * CHECK with SQLSTATE 23514 — which `mapPgError` does not map — and came back
 * as a bare 500 "Internal server error". Worse than the wrong status code: the
 * INSERT is the row that RECORDS the attempt, so the run history showed nothing
 * at all and the operator had a 500 and no trace to point at.
 *
 * The right shape is an enum in `shared/src/baseline.ts`, where the list
 * already exists as `DEVICE_BRANDS` and the client would get it for free. Until
 * that schema can move, the service refuses it with the message the API owes:
 * which value was wrong, and which ones are not.
 */
function assertKnownBrand(brand: string | null): void {
  if (brand === null) return;
  if ((DEVICE_BRANDS as readonly string[]).includes(brand)) return;
  throw new AppError(
    400,
    `Unknown brand "${brand}" — a baseline run can be narrowed to one of: ` +
      `${DEVICE_BRANDS.join(', ')}`,
  );
}

export async function runBaseline(
  tenantId: number,
  rawParams: unknown,
  userId: number | null,
): Promise<BaselineRunOutcome> {
  const params = BaselineParams.parse(rawParams ?? {});
  assertKnownBrand(params.brand);

  if (runsInFlight.has(tenantId)) {
    throw new AppError(409, 'A baseline run is already in progress for this tenant');
  }
  runsInFlight.add(tenantId);
  try {
    return await startRun(tenantId, params, userId);
  } finally {
    runsInFlight.delete(tenantId);
  }
}

async function startRun(
  tenantId: number,
  params: BaselineParams,
  userId: number | null,
): Promise<BaselineRunOutcome> {
  // The INSERT is INSIDE the try. It used to sit above it, which meant the one
  // statement that can fail on a constraint — `baseline_runs_brand_chk`,
  // `baseline_runs_params_chk` — was the one statement nothing caught: an
  // unmapped SQLSTATE surfaced as a bare 500 with no `baseline_runs` row to
  // show for it. `runId` stays null until the row exists so the failure handler
  // can tell "the run failed" from "the run never started".
  let runId: number | null = null;
  try {
    const [run] = await db('baseline_runs')
      .insert({
        tenant_id: tenantId,
        status: 'running',
        model_version: BASELINE_MODEL_VERSION,
        params: JSON.stringify(params),
        linkage: params.linkage,
        brand: params.brand,
        started_at: db.fn.now(),
        created_by: userId,
      })
      .returning<{ id: number }[]>('id');
    runId = Number(run.id);
    return await mine(runId, tenantId, params, userId);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (runId !== null) {
      // A failed run explains itself (migration 017's `baseline_runs_error_chk`)
      // and does not stay `running` for a human to garbage-collect by hand.
      await db('baseline_runs').where({ id: runId, tenant_id: tenantId }).update({
        status: 'failed',
        error: message.slice(0, 4000),
        finished_at: db.fn.now(),
      });
    }
    logger.error({ runId, tenantId, err: message }, 'baseline run failed');
    throw err instanceof AppError ? err : new AppError(500, `Baseline run failed: ${message}`);
  }
}

async function mine(
  runId: number,
  tenantId: number,
  params: BaselineParams,
  userId: number | null,
): Promise<BaselineRunOutcome> {
  const devices = await loadDevices(db, tenantId, params);
  if (devices.length === 0) {
    throw new AppError(400, 'No device in scope for this baseline run');
  }
  if (devices.length > BASELINE_MAX_FLEET) {
    throw new AppError(
      400,
      `${BASELINE_MAX_FLEET}+ devices are in scope for this run. One pass holds every `
        + 'device\'s facts and the full similarity matrix in memory at once; narrow the '
        + 'scope with `brand` or `deviceIds` and mine the fleet in several runs.',
    );
  }

  // ── extract, one batch of snapshots at a time ─────────────────────────────
  // The loop body is the only place an `ncm` document is alive. Nothing outside
  // it keeps a reference — see FLEET_SNAPSHOT_BATCH for why that matters more
  // than it looks.
  const facts: DeviceFacts[] = [];
  const deviceById = new Map<number, DeviceRow>();
  const skippedSections = new Map<NcmResourceKind, number>();
  let skipped = 0;
  let refused = 0;
  const cutoff = new Date(Date.now() - params.maxSnapshotAgeDays * 86_400_000);

  for (let start = 0; start < devices.length; start += FLEET_SNAPSHOT_BATCH) {
    const batch = devices.slice(start, start + FLEET_SNAPSHOT_BATCH);
    const snapshots = await loadSnapshotBatch(db, tenantId, batch.map((d) => d.id), cutoff);

    for (const d of batch) {
      const snap = snapshots.get(d.id);
      if (!snap) { skipped++; continue; }
      const parsed = NcmDocumentStored.safeParse(snap.ncm);
      // The raw jsonb is dropped as soon as it has been validated: the parsed
      // copy is the only one the extractor needs, and both die with the batch.
      snapshots.delete(d.id);
      if (!parsed.success) {
        // A snapshot we cannot read is a device we cannot mine, and saying "31
        // of 50" is a different claim from "50 of 50". Counted, never hidden.
        skipped++;
        logger.warn({ deviceId: d.id, snapshotId: snap.id }, 'baseline: unreadable NCM document');
        continue;
      }
      const df = extractFacts(parsed.data as NcmDocument, d.id, Number(snap.id));
      if (df.facts.length === 0) { skipped++; continue; }
      for (const s of df.skippedSections) {
        skippedSections.set(s, (skippedSections.get(s) ?? 0) + 1);
      }
      refused += df.refusedAttributes;
      facts.push(df);
      deviceById.set(d.id, d);
    }
  }

  if (refused > 0) {
    // Never with the value, never with the slot: the count alone is the alarm.
    logger.error(
      { runId, tenantId, refused },
      'baseline: credential-bearing attributes were refused during extraction — a parser is emitting secret material',
    );
  }

  if (facts.length === 0) {
    throw new AppError(
      400,
      `No usable configuration snapshot in scope (${devices.length} device(s), ` +
        `${skipped} without a readable snapshot no older than ${params.maxSnapshotAgeDays} days)`,
    );
  }

  // ── one brand per run ─────────────────────────────────────────────────────
  // `templates.brand` is NOT NULL (migration 008): a cluster spanning two
  // brands could never become one template, so a mixed fleet is narrowed to its
  // majority brand and the rest is counted as skipped rather than silently
  // averaged into a profile nobody can use.
  const brandCounts = new Map<string, number>();
  for (const f of facts) {
    const b = deviceById.get(f.deviceId)!.brand;
    brandCounts.set(b, (brandCounts.get(b) ?? 0) + 1);
  }
  const brand = params.brand
    ?? [...brandCounts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0][0];
  const kept = facts.filter((f) => deviceById.get(f.deviceId)!.brand === brand);
  skipped += facts.length - kept.length;

  // Deterministic member order: by device id. Everything downstream — cluster
  // numbering, medoids, draft bytes — is a function of this order.
  kept.sort((a, b) => a.deviceId - b.deviceId);

  // ── cluster ───────────────────────────────────────────────────────────────
  const slotSets = kept.map((f) => [...f.slots].sort());
  const maxK = Math.min(params.maxClusters, kept.length);
  const clustering = await clusterSlotSets(slotSets, params.linkage, maxK);

  // ── the stopping rule ─────────────────────────────────────────────────────
  // It runs on THIS thread, and each k costs a full alignment pass plus one
  // evaluation per member — at 250 routers of ~3000 slots, 34 s of blocked
  // event loop if it is allowed to run to `maxClusters` (24 is a value the Zod
  // schema accepts). It is not allowed to: the rule is "the SMALLEST k that
  // clears the gate", so the first k that clears it is the answer and every
  // later k is work whose result the rule would discard anyway. `coverageByK`
  // is the evidence of the ks that were TRIED, which is exactly what an
  // auditor needs — it never claimed to be a sweep of the whole range.
  const coverageByK: BaselineRunOutcome['coverageByK'] = [];
  let chosen: { k: number; clusters: CandidateCluster[] } | null = null;
  let fallback: { k: number; clusters: CandidateCluster[] } | null = null;

  for (let k = 1; k <= maxK; k++) {
    const assignment = clustering.assignments[k];
    if (!assignment) continue;
    const clusters = partitionOf(assignment).map((members) =>
      buildCandidate(kept, clustering.similarity, members, params));
    const coverageMin = Math.min(...clusters.map((c) => c.coverageMin));
    const coverageMean =
      clusters.reduce((a, c) => a + c.coverageMean * c.members.length, 0) / kept.length;
    coverageByK.push({ k, coverageMin, coverageMean });
    fallback = { k, clusters };
    if (coverageMin >= params.minCoverage - 1e-9) {
      chosen = { k, clusters };
      break;
    }
  }

  const purityGateMet = chosen !== null;
  const selected = chosen ?? fallback;
  if (!selected) throw new AppError(500, 'Clustering produced no candidate partition');

  // ── persist ───────────────────────────────────────────────────────────────
  const exceptions = await loadExceptions(db, tenantId);
  let factCount = 0;
  for (const f of kept) factCount += f.facts.length;

  await db.transaction(async (trx) => {
    const fleetStats = alignMembers(kept, params);
    await insertSlots(trx, tenantId, runId, null, fleetStats, new Set());

    let clusterIndex = 0;
    for (const c of selected.clusters) {
      const label = `profile-${String.fromCharCode(65 + clusterIndex)}`;
      const medoidDeviceId = kept[c.medoid].deviceId;

      const [cluster] = await trx('baseline_clusters')
        .insert({
          run_id: runId,
          tenant_id: tenantId,
          cluster_index: clusterIndex,
          label,
          brand,
          member_count: c.members.length,
          medoid_device_id: medoidDeviceId,
          cohesion: round5(c.cohesion),
          coverage_min: round5(c.coverageMin),
          coverage_mean: round5(Math.max(c.coverageMean, c.coverageMin)),
          purity_ok: c.coverageMin >= params.minCoverage - 1e-9,
        })
        .returning<{ id: number }[]>('id');
      const clusterId = Number(cluster.id);

      const bodySlotSet = new Set(c.body.map((s) => s.slot));
      await insertSlots(trx, tenantId, runId, clusterId, c.stats, bodySlotSet);

      // members
      const memberRows = c.members.map((idx, i) => {
        const ev = c.evaluations[i];
        return {
          cluster_id: clusterId,
          run_id: runId,
          tenant_id: tenantId,
          device_id: kept[idx].deviceId,
          snapshot_id: kept[idx].snapshotId,
          facts_total: ev.factsTotal,
          facts_covered: ev.factsCovered,
          coverage: round5(ev.coverage),
          distance_to_medoid: round5(1 - clustering.similarity[idx][c.medoid]),
        };
      });
      await trx('baseline_cluster_members').insert(memberRows);

      // draft
      const draft = renderDraft(label, brand, c.members.length, c.coverageMean, c.body);
      await trx('baseline_drafts').insert({
        cluster_id: clusterId,
        run_id: runId,
        tenant_id: tenantId,
        brand,
        body: draft.body,
        body_sha256: draft.bodySha256,
        var_schema: JSON.stringify(draft.varSchema),
        line_count: draft.lineCount,
        variable_count: draft.variableCount,
        coverage_mean: round5(c.coverageMean),
        status: 'draft',
      });

      // deviations + conformance
      for (let i = 0; i < c.members.length; i++) {
        const idx = c.members[i];
        const ev = c.evaluations[i];
        const device = deviceById.get(kept[idx].deviceId)!;
        const excused = await insertDeviations(
          trx, tenantId, runId, clusterId, ev.deviations, device, exceptions,
        );
        // No clamp between the two numbers: `excused.onDevice` counts excused
        // `extra`/`value_conflict` deviations, and those ARE the uncovered
        // facts, one for one. `baseline_conformance_excused_chk` (migration
        // 018) says the same thing to the database, so an arithmetic that
        // drifts from this comment fails at the INSERT rather than at an audit.
        await trx('baseline_conformance').insert({
          run_id: runId,
          tenant_id: tenantId,
          cluster_id: clusterId,
          device_id: device.id,
          site_id: device.site_id,
          facts_total: ev.factsTotal,
          facts_covered: ev.factsCovered,
          deviations: ev.deviations.length,
          excused: excused.onDevice,
          excused_missing: excused.missing,
          score_raw: round5(ev.coverage),
          score_adjusted: round5(
            ev.factsTotal === 0
              ? 1
              : Math.min(1, (ev.factsCovered + excused.onDevice) / ev.factsTotal),
          ),
        });
      }

      clusterIndex++;
    }

    await trx('baseline_runs').where({ id: runId, tenant_id: tenantId }).update({
      status: 'succeeded',
      brand,
      // Persisted, not just returned: a run that had to cluster on the main
      // thread is a degradation, and a degradation whose only trace is an HTTP
      // response body stops existing the day this moves to pg-boss.
      ran_in_worker: clustering.ranInWorker,
      device_count: kept.length,
      skipped_count: skipped,
      fact_count: factCount,
      slot_count: fleetStats.length,
      cluster_count: selected.clusters.length,
      chosen_k: selected.k,
      purity_gate_met: purityGateMet,
      finished_at: trx.fn.now(),
    });
  });

  logger.info(
    {
      runId, tenantId, brand, devices: kept.length, clusters: selected.clusters.length,
      k: selected.k, purityGateMet, ranInWorker: clustering.ranInWorker,
      // Which sections were unreadable, and on how many devices. A thin
      // baseline has to be explainable: "the firewall section failed on 6 of
      // 50 routers" is the difference between a template with a hole and a
      // template that believes those routers have no firewall.
      unreadableSections: Object.fromEntries([...skippedSections].sort()),
    },
    'baseline run finished',
  );

  return {
    runId,
    chosenK: selected.k,
    purityGateMet,
    deviceCount: kept.length,
    skippedCount: skipped,
    factCount,
    clusterCount: selected.clusters.length,
    coverageByK,
    ranInWorker: clustering.ranInWorker,
    clusterDurationMs: clustering.durationMs,
  };
}

/** numeric(6,5): five decimals, and the rounding happens ONCE, here, so the
 *  number the API returns is the number the database holds. */
function round5(x: number): number {
  return Math.round(Math.min(1, Math.max(0, x)) * 100000) / 100000;
}

/**
 * The second refusal of decision 3, at the place its own documentation says it
 * lives.
 *
 * `isForbiddenBaselineAttribute` is commented in `shared/src/baseline.ts` as
 * being called "by the miner on EVERY attribute it is about to turn into a
 * fact, and again by the persistence layer before a batch insert. Two call
 * sites for one rule is deliberate: the first is the design, the second is what
 * survives somebody adding a resource kind and forgetting the first."
 *
 * The second call site did not exist. `insertSlots` and `insertDeviations`
 * inserted `s.slot` and `d.slot` with no guard at all, so the only thing
 * standing behind `emit()` was the CHECK constraint of migration 017 — which
 * for two attribute names (`preSharedKey`, `community`) did not fire either,
 * until migration 023. One design-time refusal and nothing else is exactly the
 * state decision 3 was written to prevent.
 *
 * It DROPS rather than throws, for the same reason `facts.ts` counts its
 * refusals instead of failing the run: a whole fleet's baseline is worth more
 * than the one slot that got here by mistake, and the count in the log is the
 * alarm. Never the slot and never the value — logging the thing you refused for
 * being a credential is how the credential ends up in the log.
 */
function refuseSecretSlots<T extends { slot: string }>(
  rows: readonly T[],
  where: string,
  context: Record<string, unknown>,
): T[] {
  const kept = rows.filter((r) => !slotIsForbidden(r.slot));
  if (kept.length !== rows.length) {
    logger.error(
      { ...context, refused: rows.length - kept.length, where },
      'baseline: credential-bearing slots refused at the insert — an emitter bypassed emit()',
    );
  }
  return kept;
}

async function insertSlots(
  trx: Knex,
  tenantId: number,
  runId: number,
  clusterId: number | null,
  stats: readonly BaselineSlotStat[],
  bodySlotSet: ReadonlySet<string>,
): Promise<void> {
  if (stats.length === 0) return;
  const rows = refuseSecretSlots(stats, 'baseline_slots', { runId, tenantId, clusterId })
    .map((s) => ({
      run_id: runId,
      tenant_id: tenantId,
      cluster_id: clusterId,
      slot: s.slot.slice(0, 400),
      section: s.section,
      role: s.role,
      present_on: s.presentOn,
      member_count: s.memberCount,
      distinct_values: s.distinctValues,
      constant_value: s.constantValue,
      var_name: s.varName,
      value_class: s.valueClass,
      sample_values: JSON.stringify(s.sampleValues),
      in_body: clusterId !== null && bodySlotSet.has(s.slot),
    }));
  if (rows.length === 0) return;
  // Chunked: a 500-site fleet produces tens of thousands of slot rows and one
  // INSERT with 30 000 bound parameters exceeds what the driver will carry.
  for (let i = 0; i < rows.length; i += 500) {
    await trx('baseline_slots').insert(rows.slice(i, i + 500));
  }
}

/**
 * The two excusal counters, and why there are two of them.
 *
 * `score_adjusted` is `(facts_covered + excused) / facts_total`, so an excusal
 * may only be credited if the thing it excuses was in `facts_total` in the
 * first place. It is in the denominator exactly when the deviation is a fact
 * the DEVICE carries and the template does not explain — `extra` or
 * `value_conflict`; and `#extra + #value_conflict == facts_total -
 * facts_covered`, exactly, by construction of `evaluateMember`.
 *
 * A `missing` deviation is the mirror image: a template slot the device does
 * NOT carry. It was never counted in `facts_total`, and crediting it inflates a
 * numerator against a denominator it never entered. A site that legitimately
 * lacks twenty template slots (no telephony VLAN, no head-office IPsec peer)
 * and carries five REAL unsigned drifts used to read as 100 % conformant once
 * an operator signed the twenty — the five nobody explained disappeared behind
 * them, and the next run rematched the exceptions and brought the false 100 %
 * back with no human in the loop at all.
 */
interface ExcusedCounts {
  /** kind IN ('extra','value_conflict') — in the denominator, scoreable. */
  onDevice: number;
  /** kind = 'missing' — real, reportable, and NOT a conformance number. */
  missing: number;
}

/**
 * Writes the deviations and auto-excuses the ones a human already signed for.
 *
 * An exception is matched most-specific-first (device, then site, then tenant),
 * the same precedence `template_assignments` uses, because "this ROUTER is
 * special" must beat "this CUSTOMER is special" and not the other way round.
 *
 * Returns how many were excused, split by whether they are in the denominator.
 */
async function insertDeviations(
  trx: Knex,
  tenantId: number,
  runId: number,
  clusterId: number,
  deviations: readonly MemberDeviation[],
  device: DeviceRow,
  exceptions: ExceptionMatcher,
): Promise<ExcusedCounts> {
  const excused: ExcusedCounts = { onDevice: 0, missing: 0 };
  if (deviations.length === 0) return excused;
  // Before the counters, not after: a refused row must not be counted as an
  // excusal it will never have a deviation to attach to.
  const admissible = refuseSecretSlots(deviations, 'baseline_deviations', {
    runId, tenantId, clusterId, deviceId: device.id,
  });
  if (admissible.length === 0) return excused;
  const rows = admissible.map((d) => {
    const exceptionId = exceptions.match(d.slot, device.id, device.site_id);
    if (exceptionId !== null) {
      if (d.kind === 'missing') excused.missing++; else excused.onDevice++;
    }
    return {
      run_id: runId,
      tenant_id: tenantId,
      cluster_id: clusterId,
      device_id: device.id,
      slot: d.slot.slice(0, 400),
      section: d.section,
      kind: d.kind,
      template_value: d.templateValue,
      device_value: d.deviceValue,
      classification: exceptionId === null ? 'unclassified' : 'client_specific',
      exception_id: exceptionId,
      // The CHECK of migration 017 makes `classified_at` and the classification
      // inseparable: a signed-for difference carries the moment it was matched.
      classified_at: exceptionId === null ? null : trx.fn.now(),
    };
  });
  for (let i = 0; i < rows.length; i += 500) {
    await trx('baseline_deviations').insert(rows.slice(i, i + 500));
  }
  return excused;
}

// ============================================================================
// 4. Exceptions
// ============================================================================

class ExceptionMatcher {
  constructor(
    private readonly byDevice: Map<string, number>,
    private readonly bySite: Map<string, number>,
    private readonly byTenant: Map<string, number>,
  ) {}

  match(slot: string, deviceId: number, siteId: number | null): number | null {
    return (
      this.byDevice.get(`${deviceId}\u0000${slot}`)
      ?? (siteId !== null ? this.bySite.get(`${siteId}\u0000${slot}`) : undefined)
      ?? this.byTenant.get(slot)
      ?? null
    );
  }
}

async function loadExceptions(trx: Knex, tenantId: number): Promise<ExceptionMatcher> {
  const rows = await trx<ExceptionRow>('baseline_exceptions')
    .select('id', 'scope', 'scope_id', 'slot')
    .where('tenant_id', tenantId);
  const byDevice = new Map<string, number>();
  const bySite = new Map<string, number>();
  const byTenant = new Map<string, number>();
  for (const r of rows) {
    if (r.scope === 'device' && r.scope_id !== null) {
      byDevice.set(`${r.scope_id}\u0000${r.slot}`, Number(r.id));
    } else if (r.scope === 'site' && r.scope_id !== null) {
      bySite.set(`${r.scope_id}\u0000${r.slot}`, Number(r.id));
    } else if (r.scope === 'tenant') {
      byTenant.set(r.slot, Number(r.id));
    }
  }
  return new ExceptionMatcher(byDevice, bySite, byTenant);
}

// ============================================================================
// 5. Read paths
// ============================================================================

function toSummary(row: Record<string, unknown>): BaselineRunSummary {
  const rawParams = row.params;
  const parsed = BaselineParams.safeParse(
    typeof rawParams === 'string' ? JSON.parse(rawParams) : rawParams,
  );
  return {
    id: Number(row.id),
    uuid: String(row.uuid),
    status: String(row.status),
    modelVersion: Number(row.model_version),
    params: parsed.success ? parsed.data : BaselineParams.parse({}),
    brand: (row.brand as string | null) ?? null,
    deviceCount: Number(row.device_count),
    skippedCount: Number(row.skipped_count),
    factCount: Number(row.fact_count),
    slotCount: Number(row.slot_count),
    clusterCount: Number(row.cluster_count),
    chosenK: row.chosen_k === null ? null : Number(row.chosen_k),
    purityGateMet: Boolean(row.purity_gate_met),
    error: (row.error as string | null) ?? null,
    startedAt: row.started_at ? new Date(row.started_at as string).toISOString() : null,
    finishedAt: row.finished_at ? new Date(row.finished_at as string).toISOString() : null,
  };
}

export async function listRuns(tenantId: number, limit = 25): Promise<BaselineRunSummary[]> {
  const rows = await db('baseline_runs')
    .where('tenant_id', tenantId)
    .orderBy('id', 'desc')
    .limit(Math.min(Math.max(limit, 1), 100));
  return rows.map(toSummary);
}

/**
 * ┌─ THE SHARED CONTRACT IS THE ANSWER, NOT THE ROW KNEX HANDED BACK ─────────┐
 * │ `getRun`, `getCluster`, `getDraft` and `listDeviations` were typed        │
 * │ `Record<string, unknown>[]` and returned Knex rows verbatim. The          │
 * │ controller is a pass-through, so `GET …/deviations` shipped               │
 * │ `device_id`, `template_value`, `classified_at` — while                    │
 * │ `shared/src/baseline.ts` declared `BaselineDeviationRow` with `deviceId`  │
 * │ and `templateValue`, and `BaselineClusterSummary` next to it. Neither     │
 * │ interface had a single consumer. A client written against the contract    │
 * │ read `undefined` in every cell and `tsc` said nothing, because            │
 * │ `Record<string, unknown>` type-checks against anything.                   │
 * │                                                                          │
 * │ This is the third time this project has paid for the same thing (M3, M4,  │
 * │ M6). The rule that came out of it: the shared contract is the API, the    │
 * │ mapping is explicit and lives HERE, and the service signature names the   │
 * │ interface so the compiler is the one enforcing it.                        │
 * │                                                                          │
 * │ It also fixes a second, quieter defect: `numeric` columns arrive from     │
 * │ `pg` as STRINGS. `cohesion`, `coverage_min` and `coverage_mean` were      │
 * │ being serialised as `"0.94210"`, and every consumer had to remember to    │
 * │ coerce. `getConformance` already did all of this correctly — it is the    │
 * │ model these four now follow.                                             │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

/** A cluster, plus what its draft looks like — the run screen needs both. */
export interface BaselineClusterRow extends BaselineClusterSummary {
  brand: string;
  draftId: number | null;
  draftStatus: string | null;
  lineCount: number | null;
  variableCount: number | null;
  templateRevisionId: number | null;
}

export interface BaselineClusterMemberRow {
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  snapshotId: number;
  factsTotal: number;
  factsCovered: number;
  coverage: number;
  distanceToMedoid: number;
}

/** `BaselineSlotStat` is the shared shape; these three are the row's identity
 *  and its membership of the draft body, which the stat itself does not carry. */
export interface BaselineSlotRow extends BaselineSlotStat {
  id: number;
  clusterId: number | null;
  inBody: boolean;
}

export interface BaselineDraftRow {
  id: number;
  clusterId: number;
  runId: number;
  brand: string;
  body: string;
  bodySha256: string;
  varSchema: Record<string, unknown>;
  lineCount: number;
  variableCount: number;
  coverageMean: number;
  status: string;
  templateId: number | null;
  templateRevisionId: number | null;
  promotedAt: string | null;
}

/** `BaselineDeviationRow` plus the three fields the triage screen writes and
 *  reads back: which exception justifies it, and when it was signed. */
export interface BaselineDeviationDetail extends BaselineDeviationRow {
  runId: number;
  exceptionId: number | null;
  classifiedBy: number | null;
  classifiedAt: string | null;
}

type Row = Record<string, unknown>;

function num(v: unknown): number {
  return typeof v === 'number' ? v : Number(v);
}

function numOrNull(v: unknown): number | null {
  return v === null || v === undefined ? null : num(v);
}

function isoOrNull(v: unknown): string | null {
  return v === null || v === undefined ? null : new Date(v as string).toISOString();
}

function toClusterRow(r: Row): BaselineClusterRow {
  return {
    id: num(r.id),
    clusterIndex: num(r.cluster_index),
    label: String(r.label),
    brand: String(r.brand),
    memberCount: num(r.member_count),
    medoidDeviceId: numOrNull(r.medoid_device_id),
    cohesion: num(r.cohesion),
    coverageMin: num(r.coverage_min),
    coverageMean: num(r.coverage_mean),
    purityOk: r.purity_ok === true,
    draftId: numOrNull(r.draft_id),
    draftStatus: r.draft_status === null || r.draft_status === undefined
      ? null : String(r.draft_status),
    lineCount: numOrNull(r.line_count),
    variableCount: numOrNull(r.variable_count),
    templateRevisionId: numOrNull(r.template_revision_id),
  };
}

function toSlotRow(r: Row): BaselineSlotRow {
  const samples = r.sample_values;
  return {
    id: num(r.id),
    clusterId: numOrNull(r.cluster_id),
    inBody: r.in_body === true,
    slot: String(r.slot),
    section: r.section as NcmResourceKind,
    role: r.role as BaselineSlotRole,
    presentOn: num(r.present_on),
    memberCount: num(r.member_count),
    distinctValues: num(r.distinct_values),
    constantValue: (r.constant_value as string | null) ?? null,
    varName: (r.var_name as string | null) ?? null,
    valueClass: r.value_class as BaselineValueClass,
    // jsonb comes back parsed on `pg`, but a text column that once held JSON
    // would not: parsed defensively rather than trusted, and never invented.
    sampleValues: Array.isArray(samples)
      ? samples.map((x) => String(x))
      : typeof samples === 'string'
        ? (JSON.parse(samples) as unknown[]).map((x) => String(x))
        : [],
  };
}

function toDeviationRow(r: Row): BaselineDeviationDetail {
  return {
    id: num(r.id),
    runId: num(r.run_id),
    deviceId: num(r.device_id),
    clusterId: numOrNull(r.cluster_id),
    slot: String(r.slot),
    section: r.section as NcmResourceKind,
    kind: r.kind as BaselineDeviationKind,
    templateValue: (r.template_value as string | null) ?? null,
    deviceValue: (r.device_value as string | null) ?? null,
    classification: r.classification as BaselineDeviationClass,
    note: (r.note as string | null) ?? null,
    exceptionId: numOrNull(r.exception_id),
    classifiedBy: numOrNull(r.classified_by),
    classifiedAt: isoOrNull(r.classified_at),
  };
}

function toDraftRow(r: Row): BaselineDraftRow {
  const schema = r.var_schema;
  return {
    id: num(r.id),
    clusterId: num(r.cluster_id),
    runId: num(r.run_id),
    brand: String(r.brand),
    body: String(r.body),
    bodySha256: String(r.body_sha256),
    varSchema: (typeof schema === 'string' ? JSON.parse(schema) : schema ?? {}) as Record<
      string,
      unknown
    >,
    lineCount: num(r.line_count),
    variableCount: num(r.variable_count),
    coverageMean: num(r.coverage_mean),
    status: String(r.status),
    templateId: numOrNull(r.template_id),
    templateRevisionId: numOrNull(r.template_revision_id),
    promotedAt: isoOrNull(r.promoted_at),
  };
}

export async function getRun(tenantId: number, runId: number): Promise<{
  run: BaselineRunSummary;
  clusters: BaselineClusterRow[];
}> {
  const row = await db('baseline_runs').where({ id: runId, tenant_id: tenantId }).first();
  // A run belonging to another customer is a 404 and never a 403: a 403
  // confirms the row exists, which is itself the leak.
  if (!row) throw new AppError(404, 'Baseline run not found');

  const clusters = await db('baseline_clusters as c')
    .leftJoin('baseline_drafts as dr', function join() {
      this.on('dr.cluster_id', '=', 'c.id').andOn('dr.tenant_id', '=', 'c.tenant_id');
    })
    .where({ 'c.run_id': runId, 'c.tenant_id': tenantId })
    .orderBy('c.cluster_index', 'asc')
    .select(
      'c.id', 'c.cluster_index', 'c.label', 'c.brand', 'c.member_count',
      'c.medoid_device_id', 'c.cohesion', 'c.coverage_min', 'c.coverage_mean',
      'c.purity_ok',
      'dr.id as draft_id', 'dr.status as draft_status', 'dr.line_count',
      'dr.variable_count', 'dr.template_revision_id',
    );

  return { run: toSummary(row), clusters: clusters.map(toClusterRow) };
}

export async function getCluster(tenantId: number, clusterId: number): Promise<{
  cluster: BaselineClusterRow;
  members: BaselineClusterMemberRow[];
  slots: BaselineSlotRow[];
}> {
  const cluster = await db('baseline_clusters')
    .where({ id: clusterId, tenant_id: tenantId }).first();
  if (!cluster) throw new AppError(404, 'Baseline cluster not found');

  const members = await db('baseline_cluster_members as m')
    .join('devices as d', function join() {
      this.on('d.id', '=', 'm.device_id').andOn('d.tenant_id', '=', 'm.tenant_id');
    })
    .where({ 'm.cluster_id': clusterId, 'm.tenant_id': tenantId })
    .orderBy('m.coverage', 'asc')
    .select(
      'm.device_id', 'm.snapshot_id', 'm.facts_total', 'm.facts_covered',
      'm.coverage', 'm.distance_to_medoid', 'd.name as device_name', 'd.site_id',
    );

  const slots = await db('baseline_slots')
    .where({ cluster_id: clusterId, tenant_id: tenantId })
    .orderBy([{ column: 'section' }, { column: 'slot' }]);

  return {
    // The cluster read alone has no draft joined to it; the four draft fields
    // are null rather than absent, so one shape describes both call sites.
    cluster: toClusterRow(cluster as Row),
    members: (members as Row[]).map((m) => ({
      deviceId: num(m.device_id),
      deviceName: String(m.device_name),
      siteId: numOrNull(m.site_id),
      snapshotId: num(m.snapshot_id),
      factsTotal: num(m.facts_total),
      factsCovered: num(m.facts_covered),
      coverage: num(m.coverage),
      distanceToMedoid: num(m.distance_to_medoid),
    })),
    slots: (slots as Row[]).map(toSlotRow),
  };
}

export async function getDraft(tenantId: number, draftId: number): Promise<BaselineDraftRow> {
  const draft = await db('baseline_drafts').where({ id: draftId, tenant_id: tenantId }).first();
  if (!draft) throw new AppError(404, 'Baseline draft not found');
  return toDraftRow(draft as Row);
}

export interface DeviationFilter {
  runId: number;
  clusterId?: number;
  deviceId?: number;
  classification?: string;
  kind?: string;
  limit: number;
  offset: number;
}

export async function listDeviations(
  tenantId: number,
  filter: DeviationFilter,
): Promise<{ rows: BaselineDeviationDetail[]; total: number }> {
  const base = () => {
    const q = db('baseline_deviations')
      .where({ tenant_id: tenantId, run_id: filter.runId });
    if (filter.clusterId) q.andWhere('cluster_id', filter.clusterId);
    if (filter.deviceId) q.andWhere('device_id', filter.deviceId);
    if (filter.classification) q.andWhere('classification', filter.classification);
    if (filter.kind) q.andWhere('kind', filter.kind);
    return q;
  };
  const [{ count }] = await base().count<{ count: string }[]>('* as count');
  const rows = await base()
    .orderBy([{ column: 'device_id' }, { column: 'slot' }])
    .limit(filter.limit)
    .offset(filter.offset);
  return { rows: (rows as Row[]).map(toDeviationRow), total: Number(count) };
}

/**
 * Conformance, per device AND per site.
 *
 * Both scores travel together, always (decision 5 of migration 017). The site
 * aggregate is a weighted mean over facts and not a mean of means: a site with
 * one tiny router and one large one is not 50 % that router's opinion.
 */
export async function getConformance(tenantId: number, runId: number): Promise<{
  devices: (BaselineConformanceRow & { deviceName: string; siteId: number | null })[];
  sites: { siteId: number | null; devices: number; scoreRaw: number; scoreAdjusted: number }[];
}> {
  const rows = await db('baseline_conformance as c')
    .join('devices as d', function join() {
      this.on('d.id', '=', 'c.device_id').andOn('d.tenant_id', '=', 'c.tenant_id');
    })
    .where({ 'c.tenant_id': tenantId, 'c.run_id': runId })
    .orderBy('c.score_adjusted', 'asc')
    .select(
      'c.device_id', 'c.cluster_id', 'c.site_id', 'c.facts_total', 'c.facts_covered',
      'c.deviations', 'c.excused', 'c.excused_missing', 'c.score_raw', 'c.score_adjusted',
      'd.name as device_name',
    );

  const devices = rows.map((r) => ({
    deviceId: Number(r.device_id),
    clusterId: r.cluster_id === null ? null : Number(r.cluster_id),
    siteId: r.site_id === null ? null : Number(r.site_id),
    deviceName: String(r.device_name),
    factsTotal: Number(r.facts_total),
    factsCovered: Number(r.facts_covered),
    deviations: Number(r.deviations),
    excused: Number(r.excused),
    excusedMissing: Number(r.excused_missing),
    scoreRaw: Number(r.score_raw),
    scoreAdjusted: Number(r.score_adjusted),
  }));

  const bySite = new Map<number | null, { devices: number; total: number; covered: number; excused: number }>();
  for (const d of devices) {
    const acc = bySite.get(d.siteId) ?? { devices: 0, total: 0, covered: 0, excused: 0 };
    acc.devices++;
    acc.total += d.factsTotal;
    acc.covered += d.factsCovered;
    // No clamp: `excused` counts only the deviations that ARE uncovered facts
    // (see `ExcusedCounts`), and migration 018's CHECK holds the row to it.
    acc.excused += d.excused;
    bySite.set(d.siteId, acc);
  }

  const sites = [...bySite.entries()]
    .sort((a, b) => (a[0] ?? -1) - (b[0] ?? -1))
    .map(([siteId, a]) => ({
      siteId,
      devices: a.devices,
      scoreRaw: a.total === 0 ? 1 : round5(a.covered / a.total),
      scoreAdjusted: a.total === 0 ? 1 : round5(Math.min(1, (a.covered + a.excused) / a.total)),
    }));

  return { devices, sites };
}

// ============================================================================
// 6. Classifying a deviation — where "client specificity" becomes a document
// ============================================================================

export interface ClassifyInput {
  classification: 'unclassified' | 'client_specific' | 'to_remediate' | 'template_gap';
  note?: string | null;
  /** Required for 'client_specific': the exception's scope and its REASON. */
  scope?: 'tenant' | 'site' | 'device';
  reason?: string;
}

/**
 * The one write an operator performs on a baseline, and the constraint that
 * makes it worth having: `client_specific` cannot be recorded without creating
 * or reusing a `baseline_exceptions` row, and that row's `reason` is NOT NULL
 * and non-blank. An exception nobody wrote a reason for is a suppression, and a
 * suppression is how a real difference stops being visible.
 */
export async function classifyDeviation(
  tenantId: number,
  deviationId: number,
  input: ClassifyInput,
  userId: number | null,
): Promise<BaselineDeviationDetail> {
  return db.transaction(async (trx) => {
    const dev = await trx('baseline_deviations')
      .where({ id: deviationId, tenant_id: tenantId })
      .first();
    if (!dev) throw new AppError(404, 'Baseline deviation not found');

    if (input.classification !== 'client_specific') {
      const [updated] = await trx('baseline_deviations')
        .where({ id: deviationId, tenant_id: tenantId })
        .update({
          classification: input.classification,
          note: input.note ?? null,
          exception_id: null,
          classified_by: input.classification === 'unclassified' ? null : userId,
          classified_at: input.classification === 'unclassified' ? null : trx.fn.now(),
          updated_at: trx.fn.now(),
        })
        .returning<Record<string, unknown>[]>('*');
      // THIS branch needs the refresh at least as much as the other one: it is
      // the branch that TAKES an excusal away. Without it the score only ever
      // climbs, and a reviewer who overturns twenty "client specific" calls
      // leaves the device still reading 100 % conformant.
      await refreshExcusedCounts(trx, tenantId, Number(dev.run_id));
      return toDeviationRow(updated as Row);
    }

    const reason = (input.reason ?? '').trim();
    if (reason === '') {
      throw new AppError(
        400,
        'A client-specific deviation needs a reason: it becomes a documented exception, ' +
          'not a suppression',
      );
    }
    const scope = input.scope ?? 'device';
    const device = await trx('devices')
      .where({ id: dev.device_id, tenant_id: tenantId })
      .first<{ id: number; site_id: number | null }>();
    if (!device) throw new AppError(404, 'Device not found');

    let scopeId: number | null = null;
    if (scope === 'device') scopeId = Number(device.id);
    else if (scope === 'site') {
      if (device.site_id === null) {
        throw new AppError(400, 'This device is not filed under a site; use scope "device"');
      }
      scopeId = Number(device.site_id);
    }

    const exceptionId = await upsertException(trx, tenantId, {
      scope,
      scopeId,
      slot: String(dev.slot),
      expectedValue: (dev.template_value as string | null) ?? null,
      actualValue: (dev.device_value as string | null) ?? null,
      reason,
      userId,
    });

    const [updated] = await trx('baseline_deviations')
      .where({ id: deviationId, tenant_id: tenantId })
      .update({
        classification: 'client_specific',
        exception_id: exceptionId,
        note: input.note ?? null,
        classified_by: userId,
        classified_at: trx.fn.now(),
        updated_at: trx.fn.now(),
      })
      .returning<Record<string, unknown>[]>('*');

    await refreshExcusedCounts(trx, tenantId, Number(dev.run_id));
    return toDeviationRow(updated as Row);
  });
}

interface UpsertExceptionInput {
  scope: 'tenant' | 'site' | 'device';
  scopeId: number | null;
  slot: string;
  expectedValue: string | null;
  actualValue: string | null;
  reason: string;
  userId: number | null;
}

async function upsertException(
  trx: Knex,
  tenantId: number,
  input: UpsertExceptionInput,
): Promise<number> {
  const existing = await trx('baseline_exceptions')
    .where({ tenant_id: tenantId, scope: input.scope, slot: input.slot })
    .modify((q) => {
      if (input.scopeId === null) q.whereNull('scope_id');
      else q.where('scope_id', input.scopeId);
    })
    .first<{ id: number }>();

  if (existing) {
    await trx('baseline_exceptions').where({ id: existing.id, tenant_id: tenantId }).update({
      reason: input.reason,
      expected_value: input.expectedValue,
      actual_value: input.actualValue,
      updated_at: trx.fn.now(),
    });
    return Number(existing.id);
  }

  const [row] = await trx('baseline_exceptions')
    .insert({
      tenant_id: tenantId,
      scope: input.scope,
      scope_id: input.scopeId,
      slot: input.slot,
      expected_value: input.expectedValue,
      actual_value: input.actualValue,
      reason: input.reason,
      created_by: input.userId,
    })
    .returning<{ id: number }[]>('id');
  return Number(row.id);
}

/**
 * Recomputes `baseline_conformance.excused`, `excused_missing` and
 * `score_adjusted` for a run, from `baseline_deviations` alone.
 *
 * Called from BOTH branches of `classifyDeviation` — and that is the point:
 * without this call site, signing for a difference would change the deviation
 * list and leave the conformance score claiming the fleet is as non-conformant
 * as it was, which is the score becoming a number nobody trusts. The reverse
 * matters just as much and was the bug: UN-signing a difference has to bring
 * the score back DOWN, or `score_adjusted` is a ratchet an operator can only
 * push upwards and a reviewer can never undo.
 *
 * ┌─ WHY IT IS A TOTAL REWRITE AND NOT A JOIN ────────────────────────────────┐
 * │ The earlier version was `UPDATE ... FROM (SELECT ... GROUP BY device_id)  │
 * │ sub WHERE c.device_id = sub.device_id`. A device whose LAST               │
 * │ `client_specific` deviation has just been reclassified produces no row in │
 * │ `sub`, so it was never rewritten and kept the excusals it no longer had:  │
 * │ `excused = 40` with not one `client_specific` line under it, and          │
 * │ `score_adjusted = 1.00000` on a device at 60 % raw. Every row of the run  │
 * │ is rewritten here, `COALESCE`d to zero, so "no exception left" is a value │
 * │ the statement can produce and not a row it silently skips.                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Only `extra` and `value_conflict` reach `excused`: see `ExcusedCounts`.
 */
async function refreshExcusedCounts(trx: Knex, tenantId: number, runId: number): Promise<void> {
  await trx.raw(
    `UPDATE baseline_conformance c
        SET excused = sub.on_device,
            excused_missing = sub.missing,
            score_adjusted = CASE
              WHEN c.facts_total = 0 THEN 1
              ELSE LEAST(1, (c.facts_covered + sub.on_device)::numeric / c.facts_total)
            END,
            updated_at = now()
       FROM (
         SELECT c2.id,
                COALESCE(d.on_device, 0) AS on_device,
                COALESCE(d.missing, 0)   AS missing
           FROM baseline_conformance c2
           LEFT JOIN (
             SELECT device_id,
                    COUNT(*) FILTER (WHERE kind IN ('extra','value_conflict'))::int AS on_device,
                    COUNT(*) FILTER (WHERE kind = 'missing')::int                    AS missing
               FROM baseline_deviations
              WHERE tenant_id = ? AND run_id = ? AND classification = 'client_specific'
              GROUP BY device_id
           ) d ON d.device_id = c2.device_id
          WHERE c2.tenant_id = ? AND c2.run_id = ?
       ) sub
      WHERE c.id = sub.id`,
    [tenantId, runId, tenantId, runId],
  );
}

export async function listExceptions(tenantId: number): Promise<Record<string, unknown>[]> {
  return db('baseline_exceptions')
    .where('tenant_id', tenantId)
    .orderBy([{ column: 'scope' }, { column: 'slot' }]);
}

/** RESTRICT on `baseline_deviations.exception_id` means a live classification
 *  blocks the delete. That refusal is the feature: silently un-documenting a
 *  signed-for difference while the deviation still reads `client_specific` is
 *  exactly the state decision 4 of migration 017 forbids. */
export async function deleteException(tenantId: number, exceptionId: number): Promise<void> {
  const inUse = await db('baseline_deviations')
    .where({ tenant_id: tenantId, exception_id: exceptionId })
    .first<{ id: number }>('id');
  if (inUse) {
    throw new AppError(
      409,
      'This exception is still the justification of at least one deviation. ' +
        'Reclassify those deviations first.',
    );
  }
  const deleted = await db('baseline_exceptions')
    .where({ id: exceptionId, tenant_id: tenantId })
    .delete();
  if (deleted === 0) throw new AppError(404, 'Baseline exception not found');
}

// ============================================================================
// 7. Promotion — a draft becomes a DRAFT template revision, and nothing more
// ============================================================================

/**
 * Writes `templates` + `template_revisions` with `status = 'draft'`.
 *
 * Decision 7 of migration 017: a draft revision is not frozen (008's trigger
 * only engages on a published one), cannot be assigned, cannot be rendered into
 * a plan and cannot be applied. Turning this body into something a router will
 * see requires a human holding TEMPLATE_WRITE to rewrite it into brand syntax
 * and publish it — which is the M5 path, untouched, and D3 beyond it.
 */
export async function promoteDraft(
  tenantId: number,
  draftId: number,
  name: string,
  description: string | null,
  userId: number | null,
): Promise<{ templateId: number; revisionId: number }> {
  return db.transaction(async (trx) => {
    const draft = await trx('baseline_drafts')
      .where({ id: draftId, tenant_id: tenantId })
      .first();
    if (!draft) throw new AppError(404, 'Baseline draft not found');
    if (draft.status !== 'draft') {
      throw new AppError(409, `This draft is already ${draft.status}`);
    }

    let templateId: number;
    try {
      const [tpl] = await trx('templates')
        .insert({
          tenant_id: tenantId,
          name,
          description,
          brand: draft.brand,
          status: 'active',
          created_by: userId,
          updated_by: userId,
        })
        .returning<{ id: number }[]>('id');
      templateId = Number(tpl.id);
    } catch (err) {
      const code = (err as { code?: string }).code;
      if (code === '23505') {
        throw new AppError(409, `A ${draft.brand} template named "${name}" already exists`);
      }
      throw err;
    }

    const [rev] = await trx('template_revisions')
      .insert({
        template_id: templateId,
        revision: 1,
        body: draft.body,
        body_sha256: draft.body_sha256,
        var_schema: draft.var_schema,
        status: 'draft',
        engine: 'nunjucks',
        notes:
          'Mined by the M12 baseline miner. The body is in the baseline FACT DIALECT ' +
          'and must be rewritten into brand syntax before publication.',
        created_by: userId,
      })
      .returning<{ id: number }[]>('id');
    const revisionId = Number(rev.id);

    await trx('baseline_drafts').where({ id: draftId, tenant_id: tenantId }).update({
      status: 'promoted',
      template_id: templateId,
      template_revision_id: revisionId,
      promoted_at: trx.fn.now(),
      promoted_by: userId,
      updated_at: trx.fn.now(),
    });

    return { templateId, revisionId };
  });
}
