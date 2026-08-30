/**
 * ObliWAN M6 — one worker PROCESS that drains the queue and reports what it got.
 *
 * Spawned N times by `m6-queue.verify.ts` to answer the one question a
 * single-process test cannot: do two workers racing on `FOR UPDATE SKIP LOCKED`
 * ever get the same job? A single process with two `await`s proves nothing —
 * it shares a connection pool, a transaction manager and an event loop with
 * itself.
 *
 * Prints one JSON line on stdout: `{"worker":"…","claimed":[…]}`.
 *
 *   npx tsx src/services/change/testing/claimer.child.ts
 */

import { db } from '../../../db';
import { claimNextJob, WORKER_ID } from '../jobQueue.service';

async function main(): Promise<void> {
  const claimed: number[] = [];
  // Drain: keep claiming until the queue hands back nothing. The workers are
  // started at the same moment, so the interesting window is the first few
  // milliseconds when both are scanning the same rows.
  for (;;) {
    const job = await claimNextJob();
    if (!job) break;
    claimed.push(Number(job.id));
  }
  process.stdout.write(`${JSON.stringify({ worker: WORKER_ID, claimed })}\n`);
  await db.destroy();
}

main().catch(async (err) => {
  process.stdout.write(`${JSON.stringify({ error: String(err) })}\n`);
  try {
    await db.destroy();
  } catch {
    /* going down anyway */
  }
  process.exit(1);
});
