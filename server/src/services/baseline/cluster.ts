// ============================================================================
// M12 / K8 — the gate in front of the clustering worker
// ============================================================================
//
// Same shape as `services/template/engine.ts` and for the same reasons: the
// thread is spawned with an explicit memory ceiling, an empty environment, and
// a watchdog that TERMINATES it rather than waiting on it. A clustering job
// that never returns is a baseline run stuck in `running` forever, and a run
// stuck in `running` is one a human eventually kills with a DELETE.
//
// `env: {}` matters here for the same reason it matters for the render worker:
// `OBLIWAN_ENCRYPTION_KEY` lives in this process's environment (R8) and a thread
// whose entire job is intersecting sets of strings has no business being able
// to read it.
//
// ┌─ THE FALLBACK IS FOR A THREAD THAT NEVER STARTED, AND FOR NOTHING ELSE ───┐
// │ A worker that cannot be SPAWNED — no entry file after a packaging         │
// │ accident, a platform without worker_threads, a loader that cannot reach   │
// │ the module — has computed nothing, and running the same pure functions    │
// │ inline is strictly better than a baseline that refuses to exist. That     │
// │ fallback stays, and it says so in `ranInWorker`.                          │
// │                                                                          │
// │ A worker that STARTED and then failed is the opposite case, and the       │
// │ earlier version of this file got it exactly backwards: the watchdog, the  │
// │ 256 MB heap ceiling (`ERR_WORKER_OUT_OF_MEMORY`), a non-zero exit and a   │
// │ `fatal` message all re-ran THE SAME COMPUTATION, synchronously, on the    │
// │ main thread, with no ceiling and no watchdog. At the 500-site design      │
// │ point of §6.3 the similarity pass alone is ~109 s: the watchdog fired at  │
// │ 120 s and the process then froze for another two minutes — no HTTP        │
// │ handler, no RouterOS keepalive, no liveness probe — and the memory case   │
// │ was worse still, since the allocation the ceiling had just refused was    │
// │ retried in a heap that has no ceiling at all.                             │
// │                                                                          │
// │ So: started-then-failed REJECTS with 503 and the run is marked `failed`.  │
// │ A baseline an operator can retry on a narrower scope is not an outage;    │
// │ the fallback that produced one was.                                       │
// └───────────────────────────────────────────────────────────────────────────┘

import { Worker } from 'worker_threads';
import fs from 'fs';
import path from 'path';
import type { BaselineLinkage } from '@obliwan/shared/dist/baseline';
import { logger } from '../../utils/logger';
import { AppError } from '../../middleware/errorHandler';
import {
  agglomerate, similarityMatrix,
  type ClusterWorkerInput, type ClusterWorkerMessage, type ClusterWorkerOutput,
} from './clusterWorker';

/** 500 sites × ~400 slots is the design point of §6.3 R7's fleet size. The
 *  matrix itself is 500² doubles = 2 MB; the slot strings dominate. */
export const CLUSTER_WORKER_RESOURCE_LIMITS = {
  maxOldGenerationSizeMb: 256,
  maxYoungGenerationSizeMb: 32,
  codeRangeSizeMb: 16,
  stackSizeMb: 4,
} as const;

/** Generous, because this is a batch job an operator started on purpose and not
 *  a request path. It is a ceiling on a runaway, not a latency budget. */
export const CLUSTER_TIMEOUT_MS = 120_000;

/**
 * The watchdog's deadline, read at CALL time and overridable by environment.
 *
 * Two reasons, and the second is the one that matters. An instance smaller than
 * the §6.3 design point wants a smaller ceiling — two minutes of a thread on a
 * one-core container is not a runaway anyone wants to wait out. And a ceiling
 * nothing can exercise is a ceiling nobody has ever watched fire: this is what
 * lets `m12-baseline.verify.ts` prove, against the real worker, that a timeout
 * rejects instead of re-running the same computation on the API thread.
 */
export function clusterTimeoutMs(): number {
  const raw = Number(process.env.BASELINE_CLUSTER_TIMEOUT_MS);
  return Number.isFinite(raw) && raw >= 10 ? raw : CLUSTER_TIMEOUT_MS;
}

export interface ClusterResult extends ClusterWorkerOutput {
  /** false when the worker could not be SPAWNED and the pure path ran inline.
   *  NEVER false because a started worker failed — that case rejects. Surfaced,
   *  never swallowed, and persisted on `baseline_runs.ran_in_worker` so the
   *  degradation stays visible once the run moves off the request path. */
  ranInWorker: boolean;
  durationMs: number;
}

/** `dist/**` after `tsc`, `src/**` under `tsx`. Probed rather than branched on
 *  NODE_ENV, exactly as `template/engine.ts` does: a wrong branch here fails at
 *  the first baseline run of the day rather than at boot. */
let cachedWorkerPath: string | null = null;
function workerEntryPath(): string | null {
  if (cachedWorkerPath === null) {
    const candidates = [
      path.join(__dirname, 'clusterWorker.js'),
      path.join(__dirname, 'clusterWorker.ts'),
    ];
    cachedWorkerPath = candidates.find((c) => fs.existsSync(c)) ?? '';
  }
  return cachedWorkerPath === '' ? null : cachedWorkerPath;
}

function inline(input: ClusterWorkerInput): ClusterWorkerOutput {
  const similarity = similarityMatrix(input.slotSets);
  const { merges, assignments } = agglomerate(similarity, input.linkage, input.maxK);
  return { similarity, merges, assignments };
}

export async function clusterSlotSets(
  slotSets: readonly string[][],
  linkage: BaselineLinkage,
  maxK: number,
): Promise<ClusterResult> {
  const startedAt = Date.now();
  const input: ClusterWorkerInput = {
    slotSets: slotSets.map((s) => [...s]),
    linkage,
    maxK: Math.max(1, Math.min(maxK, slotSets.length)),
  };

  const entry = workerEntryPath();
  if (!entry) {
    logger.warn('baseline: clusterWorker entry not found; clustering inline on the main thread');
    return { ...inline(input), ranInWorker: false, durationMs: Date.now() - startedAt };
  }

  return new Promise<ClusterResult>((resolve, reject) => {
    let settled = false;
    // Set by the worker's FIRST message, and it is the discriminator between
    // the two failure families. It is explicit rather than inferred from
    // `online`, which also fires for a thread that then dies loading its own
    // module — a startup accident, not a computation that ran out of room.
    let started = false;
    let worker: Worker | undefined;

    const settle = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      fn();
    };

    /** The worker never began computing: the pure path inline is a real answer
     *  to a packaging problem, and it is what the header defends. */
    const fallbackInline = (why: string): void => settle(() => {
      logger.warn({ why }, 'baseline: clustering worker never started; running inline');
      resolve({ ...inline(input), ranInWorker: false, durationMs: Date.now() - startedAt });
    });

    /** The worker began and did not finish — timeout, heap ceiling, non-zero
     *  exit, or the algorithm throwing. The one thing we must NOT do here is
     *  run that same computation on this thread. */
    const abort = (why: string): void => settle(() => {
      void worker?.terminate();
      logger.error(
        { why, devices: slotSets.length, maxK: input.maxK },
        'baseline: clustering failed inside the worker; NOT retried on the main thread',
      );
      reject(new AppError(
        503,
        `Baseline clustering did not complete (${why}). The fleet in scope is too large `
          + 'for one pass — narrow the run with `brand` or `deviceIds` and retry.',
      ));
    });

    const deadlineMs = clusterTimeoutMs();
    const watchdog = setTimeout(() => {
      abort(`no result after ${deadlineMs} ms`);
    }, deadlineMs);

    try {
      worker = new Worker(entry, {
        workerData: input,
        resourceLimits: { ...CLUSTER_WORKER_RESOURCE_LIMITS },
        env: {},
        argv: [],
        // Inherited on purpose: it is how the TypeScript loader reaches a
        // worker in development, and it is our configuration rather than
        // anything the mined data can influence.
        stdin: false,
        stdout: true,
        stderr: true,
      });
    } catch (err) {
      fallbackInline(err instanceof Error ? err.message : String(err));
      return;
    }

    worker.on('message', (msg: ClusterWorkerMessage) => {
      if (msg.type === 'started') { started = true; return; }
      if (msg.type === 'result') {
        settle(() => {
          resolve({ ...msg.output, ranInWorker: true, durationMs: Date.now() - startedAt });
          void worker?.terminate();
        });
        return;
      }
      // `fatal` is the algorithm itself throwing. Inline would throw the same.
      abort(msg.message);
    });

    // ERR_WORKER_OUT_OF_MEMORY arrives here: the 256 MB ceiling doing its job.
    // Answering it by allocating the same structures in the unbounded main heap
    // is how a memory limit turns into a process kill.
    worker.on('error', (err: Error) => {
      const code = (err as NodeJS.ErrnoException).code;
      const why = `${code ?? 'error'}: ${err.message}`;
      // The heap ceiling is decisive on its own, `started` or not: it can fire
      // while the thread is still deserialising `workerData` (the slot sets are
      // ~220 MB of RSS at 500 × 3000), i.e. before this module runs. Falling
      // back inline there would answer "256 MB was not enough" by allocating
      // the very same structures in a heap with no limit at all.
      if (started || code === 'ERR_WORKER_OUT_OF_MEMORY') abort(why);
      else fallbackInline(why);
    });

    worker.on('exit', (code: number) => {
      if (settled || code === 0) return;
      const why = `clustering worker exited with code ${code}`;
      if (started) abort(why); else fallbackInline(why);
    });
  });
}
