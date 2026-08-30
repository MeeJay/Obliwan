// ============================================================================
// M12 / K8 — the hierarchical clustering, off the API thread
// ============================================================================
//
// ARCHITECTURE.md §5/M12 spells the algorithm out and it is followed to the
// letter: weighted Jaccard, hierarchical, IN A WORKER, WITHOUT AN LLM.
//
// Why a worker, honestly: at fifty sites the whole thing runs in single-digit
// milliseconds and the thread buys nothing. It is O(n²) in sites and O(n²·m) in
// slot comparisons, and the product is specified for up to 500 sites, where the
// same code is 250 000 set intersections over ~300 slots each. That is a
// multi-second synchronous burn on the event loop of the process that also
// holds every RouterOS session in the fleet — the CHR reconnection storm of R5
// does not care that we were busy proposing templates.
//
// Why NO LLM, from the spec and worth restating: the output of this file is the
// justification of a template somebody will push to thirty routers. "These
// twelve sites are one profile because their weighted Jaccard similarity is
// 0.87 and the worst pair inside the group is 0.81" can be checked, argued
// with, and reproduced next Tuesday. A model's answer to the same question can
// be none of those things, and would also be non-deterministic across runs on
// input that did not change.
//
// EVERY TIE BREAKS ON THE LOWEST INDEX. Two runs over the same snapshots must
// produce the same clusters, the same medoids and the same draft bytes.

import { parentPort, workerData } from 'worker_threads';
import {
  BASELINE_SECTION_WEIGHTS, sectionOfSlot, weightedJaccard,
  type BaselineLinkage,
} from '@obliwan/shared/dist/baseline';

export interface ClusterWorkerInput {
  /** One entry per device, in the caller's order. Slot lists are deduplicated
   *  and sorted by the caller; this worker does not re-sort them. */
  slotSets: string[][];
  linkage: BaselineLinkage;
  /** Assignments are returned for every k from 1 to this value. */
  maxK: number;
}

export interface ClusterWorkerOutput {
  /** Full weighted-Jaccard similarity matrix, symmetric, 1 on the diagonal.
   *  Returned because cohesion, the medoid and the "distance to medoid" column
   *  are all read off it, and recomputing it on the main thread would undo the
   *  entire point of this file. */
  similarity: number[][];
  /** The agglomeration, in order. Indices are into the ORIGINAL items for the
   *  two representatives merged, plus the resulting size and linkage distance —
   *  this is the dendrogram, and it is what makes the choice of k auditable. */
  merges: { a: number; b: number; distance: number; size: number }[];
  /** k -> assignment[i] = cluster ordinal of item i, numbered by first
   *  appearance so the numbering is stable. */
  assignments: Record<number, number[]>;
}

export type ClusterWorkerMessage =
  /** Posted before the first byte of work, and read by `cluster.ts` as the
   *  boundary between "this thread never started" (fall back inline, it is a
   *  packaging accident) and "this thread started and then died" (503; do NOT
   *  re-run the same computation on the API thread). Explicit rather than
   *  inferred from the `online` event, which also fires for a thread that goes
   *  on to fail loading this very module. */
  | { type: 'started' }
  | { type: 'result'; output: ClusterWorkerOutput }
  | { type: 'fatal'; message: string };

/** Section weight of a slot; anything unrecognised weighs 1 rather than 0, so a
 *  future resource kind still influences the clustering instead of silently
 *  becoming invisible to it. */
export function slotWeight(slot: string): number {
  const section = sectionOfSlot(slot);
  return section ? BASELINE_SECTION_WEIGHTS[section] : 1;
}

export function similarityMatrix(slotSets: readonly string[][]): number[][] {
  const sets = slotSets.map((s) => new Set(s));
  const n = sets.length;
  const m: number[][] = Array.from({ length: n }, () => new Array<number>(n).fill(1));
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const s = weightedJaccard(sets[i], sets[j], slotWeight);
      m[i][j] = s;
      m[j][i] = s;
    }
  }
  return m;
}

/**
 * Agglomerative clustering with Lance-Williams updates.
 *
 * `complete` is the default and the doctrinal one: it merges two groups only
 * when their WORST pair is close, which is "prefer more, purer clusters"
 * written as a formula rather than as a preference. `average` exists because a
 * fleet with one genuinely eccentric site can otherwise never merge anything,
 * and an operator who sees that should be able to say so without a code change.
 */
export function agglomerate(
  similarity: readonly number[][],
  linkage: BaselineLinkage,
  maxK: number,
): { merges: ClusterWorkerOutput['merges']; assignments: Record<number, number[]> } {
  const n = similarity.length;
  // Distance matrix between live clusters, indexed by their representative
  // (the lowest original index they contain).
  const d: number[][] = Array.from({ length: n }, (_, i) =>
    Array.from({ length: n }, (_, j) => (i === j ? 0 : 1 - similarity[i][j])),
  );

  const alive: boolean[] = new Array(n).fill(true);
  const size: number[] = new Array(n).fill(1);
  /** Original item -> its current representative. */
  const owner: number[] = Array.from({ length: n }, (_, i) => i);

  const merges: ClusterWorkerOutput['merges'] = [];
  /** Snapshot of `owner` at each k, taken before the merge that reduces k. */
  const assignments: Record<number, number[]> = {};

  const snapshot = (k: number): void => {
    if (k > maxK) return;
    const ordinalOf = new Map<number, number>();
    const out = new Array<number>(n);
    for (let i = 0; i < n; i++) {
      const rep = owner[i];
      let ord = ordinalOf.get(rep);
      if (ord === undefined) { ord = ordinalOf.size; ordinalOf.set(rep, ord); }
      out[i] = ord;
    }
    assignments[k] = out;
  };

  let live = n;
  snapshot(live);

  while (live > 1) {
    // Lowest distance wins; ties break on the lowest (i, j). `>` and not `>=`
    // in the comparison is what makes that true.
    let bi = -1;
    let bj = -1;
    let best = Number.POSITIVE_INFINITY;
    for (let i = 0; i < n; i++) {
      if (!alive[i]) continue;
      for (let j = i + 1; j < n; j++) {
        if (!alive[j]) continue;
        if (d[i][j] < best - 1e-12) { best = d[i][j]; bi = i; bj = j; }
      }
    }
    if (bi < 0) break;

    // The merged cluster keeps the LOWER index as its representative, which is
    // what makes cluster numbering a function of the data and not of the merge
    // order.
    for (let i = 0; i < n; i++) if (owner[i] === bj) owner[i] = bi;
    const newSize = size[bi] + size[bj];

    for (let c = 0; c < n; c++) {
      if (!alive[c] || c === bi || c === bj) continue;
      const nd = linkage === 'complete'
        ? Math.max(d[bi][c], d[bj][c])
        : (size[bi] * d[bi][c] + size[bj] * d[bj][c]) / newSize;
      d[bi][c] = nd;
      d[c][bi] = nd;
    }

    alive[bj] = false;
    size[bi] = newSize;
    merges.push({ a: bi, b: bj, distance: best, size: newSize });
    live--;
    snapshot(live);
  }

  return { merges, assignments };
}

// ============================================================================
// Worker entry point
// ============================================================================
//
// `parentPort` is null when this module is imported directly (the unit tests
// import `agglomerate` and `similarityMatrix` without spawning a thread), so
// the side effect is guarded rather than unconditional.

if (parentPort) {
  const port = parentPort;
  port.postMessage({ type: 'started' } as ClusterWorkerMessage);
  try {
    const input = workerData as ClusterWorkerInput;
    const similarity = similarityMatrix(input.slotSets);
    const { merges, assignments } = agglomerate(similarity, input.linkage, input.maxK);
    const message: ClusterWorkerMessage = {
      type: 'result',
      output: { similarity, merges, assignments },
    };
    port.postMessage(message);
  } catch (err) {
    const message: ClusterWorkerMessage = {
      type: 'fatal',
      message: err instanceof Error ? err.message : String(err),
    };
    port.postMessage(message);
  }
}
