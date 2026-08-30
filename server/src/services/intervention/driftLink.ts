// ============================================================================
// ObliWAN — F3, property 1: drift during a declared window is not an anomaly
// ============================================================================
//
// §10/F3: "pendant une intervention déclarée, la dérive détectée sur cet
// appareil est ATTRIBUÉE à l'intervention au lieu d'apparaître comme une
// anomalie. C'est ce qui supprime la principale source de faux positifs."
//
// ┌─ THE INTERVENTION RESOLVES THE UNKNOWN. IT DOES NOT OVERRULE THE KNOWN ───┐
// │ K6 (`services/drift/attribution.service.ts`) already answers "who changed │
// │ this box" with five verdicts. Two of them are precise statements:         │
// │ `platform` (one of OUR change jobs wrote it, on our own evidence) and     │
// │ `attributed` (a login session names a person). A third, `excluded`, says  │
// │ the diff is ours — a re-normalisation or a model upgrade (§6.5).          │
// │                                                                           │
// │ A declared window is weaker evidence than any of those three: it says     │
// │ "somebody said they would be working here". So it claims ONLY the runs    │
// │ K6 left unexplained — `unattributed` and `ambiguous` — which is exactly   │
// │ the set that fills the "changes nobody owns" screen and exactly the       │
// │ false-positive source §10/F3 is about. Everything else is LINKED and      │
// │ left alone, with the K6 verdict recorded in `prior_verdict`.              │
// │                                                                           │
// │ Overwriting `attributed` with "an intervention was open" would DELETE a   │
// │ name the platform had evidence for. That is the K6 header's own rule —    │
// │ a wrong attribution is worse than no attribution — applied one level up.  │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THE WINDOW IS K6'S, NOT A SECOND ONE ────────────────────────────────────┐
// │ The interval a change provably happened in is computed by                 │
// │ `attribution.service.resolveWindow()` — from `config_snapshots`,          │
// │ `last_seen_at` to `captured_at` — and it is not trivial. This file does   │
// │ NOT recompute it: it calls `attributeRun()` and reads the window off the  │
// │ row that call always writes. Two implementations of "when did this        │
// │ change happen" would disagree the first time either is improved, and the  │
// │ disagreement would be invisible.                                          │
// │                                                                           │
// │ A consequence worth stating: a change window WIDER than                   │
// │ `INTERVENTION_MAX_ATTRIBUTION_WINDOW_MINUTES` is not claimed at all. A    │
// │ two-hour window sitting somewhere inside nine days of uncertainty is a    │
// │ coincidence, not an explanation. The link row is still written, with      │
// │ `window_too_wide`, because an operator looking at that screen deserves to │
// │ see the coincidence and decide for himself.                               │
// │                                                                           │
// │ That ceiling is an ABSOLUTE bound and it is not the whole rule. The       │
// │ second one is a RATIO: the declared window must cover at least            │
// │ `INTERVENTION_MIN_OVERLAP_RATIO` of the change interval                   │
// │ (`interventionCoversChangeWindow`). Without it a five-minute window       │
// │ declared after the fact claims a seven-day interval on sixty seconds of   │
// │ overlap — under the ceiling, and 0.0099 % of the evidence.                │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ AND IT EXPIRES WHAT NOBODY CLOSED ───────────────────────────────────────┐
// │ `sweepInterventionLinks` is the function a scheduler arms, so it is where │
// │ `expireOverdue` is called from. Property 2 of §10/F3 used to depend on a  │
// │ human opening a screen: every other caller of `expireOverdue` is an HTTP  │
// │ READ path. A guard nothing periodic invokes is a guard that does not run. │
// └───────────────────────────────────────────────────────────────────────────┘

import {
  INTERVENTION_ATTRIBUTION_VERDICT,
  INTERVENTION_MAX_ATTRIBUTION_WINDOW_MINUTES,
  INTERVENTION_MIN_OVERLAP_RATIO,
  interventionCoversChangeWindow,
  type InterventionLink,
  type InterventionLinkDisposition,
} from '@obliwan/shared/dist/intervention';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { attributeRun } from '../drift/attribution.service';
import { expireOverdue } from './expiry';
import { effectiveEnd } from './window';

/** Verdicts that already say something more precise than "a window was open".
 *  Kept as a set so the list is stated once and read twice. */
const ALREADY_EXPLAINED_VERDICTS: ReadonlySet<string> = new Set([
  'attributed',
  'platform',
  'excluded',
]);

const MAX_WINDOW_MS = INTERVENTION_MAX_ATTRIBUTION_WINDOW_MINUTES * 60_000;

interface CandidateRow {
  id: string;
  status: string;
  opened_at: Date;
  expires_at: Date;
  closed_at: Date | null;
  expired_at: Date | null;
  cancelled_at: Date | null;
}

function overlapSeconds(a: [Date, Date], b: [Date, Date]): number {
  const from = Math.max(a[0].getTime(), b[0].getTime());
  const to = Math.min(a[1].getTime(), b[1].getTime());
  return to <= from ? 0 : Math.round((to - from) / 1000);
}

/**
 * Consider one drift run against the interventions declared on its device.
 *
 * Returns `null` when there is nothing to say: the run is not this tenant's,
 * it found no drift, or no declared window comes anywhere near its change
 * interval. A `null` is not a failure — most drift is not covered by an
 * intervention, and inventing a link for it is how a feature that suppresses
 * false positives starts suppressing true ones.
 */
export async function linkRunToIntervention(
  tenantId: number,
  runId: string,
  now: Date = new Date(),
): Promise<InterventionLink | null> {
  // Tenant isolation FIRST, and through `devices`: `drift_runs` carries no
  // tenant column (the M4/M8 convention), so the join is the only isolation
  // there is.
  const run = (await db('drift_runs as dr')
    .join('devices as d', 'd.id', 'dr.device_id')
    .where('d.tenant_id', tenantId)
    .andWhere('dr.id', runId)
    .first('dr.id', 'dr.device_id', 'dr.status')) as
    | { id: string; device_id: number; status: string }
    | undefined;
  if (!run) return null;
  if (run.status !== 'drifted') return null;

  // K6's own window and K6's own verdict. `attributeRun` is idempotent and
  // returns the existing row when there is one, so calling it here costs a
  // lookup on the normal path and produces the row on the path where the
  // attribution sweep has not run yet.
  const attribution = await attributeRun(runId);
  if (!attribution) return null;

  const windowFrom = new Date(attribution.window.from);
  const windowTo = new Date(attribution.window.to);
  const windowSpanSeconds = Math.max(
    0,
    Math.round((windowTo.getTime() - windowFrom.getTime()) / 1000),
  );

  // Loose SQL filter, exact arithmetic in TypeScript: a window closed EARLY
  // ends before `expires_at`, so `expires_at >= windowFrom` is a superset of
  // the real overlap and `effectiveEnd()` — the one definition of "when did
  // this window really end" — decides.
  const candidates = (await db('interventions')
    .where({ tenant_id: tenantId, device_id: Number(run.device_id) })
    .whereNot('status', 'cancelled')
    .andWhere('opened_at', '<=', windowTo)
    .andWhere('expires_at', '>=', windowFrom)
    .orderBy('opened_at', 'desc')
    .select(
      'id',
      'status',
      'opened_at',
      'expires_at',
      'closed_at',
      'expired_at',
      'cancelled_at',
    )) as CandidateRow[];

  let best: { row: CandidateRow; overlap: number } | null = null;
  for (const row of candidates) {
    const overlap = overlapSeconds(
      [windowFrom, windowTo],
      [row.opened_at, effectiveEnd(row)],
    );
    // A zero-length change window (both snapshots confirmed at the same
    // instant) still counts as covered when it falls inside the declared
    // window: `overlapSeconds` would return 0 for it, so containment is
    // checked explicitly rather than inferred from a duration.
    const contained =
      windowFrom >= row.opened_at && windowTo <= effectiveEnd(row);
    if (overlap === 0 && !contained) continue;
    if (!best || overlap > best.overlap) best = { row, overlap };
  }
  if (!best) return null;

  // Widened to `string` on purpose. `AttributionVerdict` (shared/src/logs.ts,
  // M8) does not yet list `'intervention'`: migration 020 widens the CHECK on
  // the column, but that union belongs to another milestone and is outside this
  // feature's perimeter. Adding the value to it is a one-line change at the
  // junction; until then the comparison is made on the string, which is what
  // the column actually holds.
  const prior: string = attribution.verdict;
  let disposition: InterventionLinkDisposition;
  // TWO quantitative refusals, not one.
  //
  // The absolute ceiling below ("nine days of uncertainty is never explained by
  // a window") is necessary and NOT sufficient: an eight-day change window sits
  // under it, and a five-minute intervention overlapping it by sixty seconds
  // would have claimed it — 0.0099 % of the interval deciding a verdict, with
  // the operator named by the very person who declared the window.
  //
  // So the RATIO the link row already stores is the second refusal. It is the
  // shared rule (`interventionCoversChangeWindow`) and not a local comparison,
  // because a threshold that decides an attribution belongs next to the
  // vocabulary it decides, where the client can read it too.
  const coversWindow = interventionCoversChangeWindow(best.overlap, windowSpanSeconds);
  if (windowSpanSeconds * 1000 > MAX_WINDOW_MS || !coversWindow) {
    // Still LINKED, deliberately: the coincidence stays visible on the screen
    // and both numbers stay in the database, but K6 keeps its verdict and the
    // run keeps its place on "changes nobody owns".
    disposition = 'window_too_wide';
  } else if (prior === INTERVENTION_ATTRIBUTION_VERDICT) {
    // Already claimed — by this same window, since a run can only ever be
    // linked once (`intervention_drift_links_run_uq`). Idempotent re-run.
    disposition = 'attributed';
  } else if (ALREADY_EXPLAINED_VERDICTS.has(prior)) {
    disposition = 'already_explained';
  } else {
    disposition = 'attributed';
  }

  if (disposition === 'attributed' && prior !== INTERVENTION_ATTRIBUTION_VERDICT) {
    // THE claim. Every naming column is cleared on the way: the CHECK
    // `drift_attributions_names_only_when_attributed` forbids a name under any
    // verdict but `attributed`, and the responsible human is one join away in
    // `interventions.operator` anyway — which is a DECLARATION, not a device
    // login account, and the two must not be written into the same column.
    await db('drift_attributions')
      .where('run_id', runId)
      // The run was already established as this tenant's twelve lines above,
      // and `run_id` is unique on this table — but the predicate is repeated
      // here anyway. `drift_attributions` carries no tenant column, an UPDATE
      // is the one statement where forgetting the join writes to somebody
      // else's row instead of merely reading it, and this project has already
      // shipped an audit finding for reads that forgot exactly this.
      .whereIn(
        'run_id',
        db('drift_runs as dr')
          .join('devices as d', 'd.id', 'dr.device_id')
          .where('d.tenant_id', tenantId)
          .andWhere('dr.id', runId)
          .select('dr.id'),
      )
      .update({
        verdict: INTERVENTION_ATTRIBUTION_VERDICT,
        reason: 'declared_intervention',
        score: 0,
        account: null,
        login_event_id: null,
        method: null,
        source_ip: null,
        shared_account: false,
        change_job_id: null,
      });
    logger.info(
      {
        runId,
        deviceId: Number(run.device_id),
        interventionId: String(best.row.id),
        priorVerdict: prior,
      },
      'Drift attributed to a declared intervention — it is no longer an anomaly nobody owns',
    );
  }

  // WHICH WINDOW THE ROW POINTS AT IS PART OF WHAT THE MERGE HAS TO UPDATE.
  //
  // `best` is NOT stable across sweeps. `effectiveEnd()` reads the row's
  // status, so a window still marked `open` (which therefore ends at its
  // deadline) ends somewhere else once it is actually closed, and a competing
  // window on the same device can overtake the one elected last time. Leaving
  // `intervention_id` out of the merge kept the OLD window on the row while
  // `overlap_seconds`, `window_span_seconds` and `disposition` were
  // overwritten with the NEW one's: `GET /interventions/:id/drift` then showed,
  // under window A, the two numbers that justify window B's claim. Migration
  // 020 calls those "the two numbers that justify the claim"; documenting a
  // window they were not measured against is the one thing they must not do.
  //
  // So the pointer travels with its evidence, and the move is LOGGED: a link
  // changing hands re-attributes one person's drift to another person's
  // declared window, and that should be readable afterwards rather than
  // inferred from a row that quietly changed.
  const existingLink = (await db('intervention_drift_links')
    .where({ tenant_id: tenantId, drift_run_id: runId })
    .first('id', 'intervention_id')) as
    | { id: string; intervention_id: string }
    | undefined;
  if (existingLink && String(existingLink.intervention_id) !== String(best.row.id)) {
    logger.warn(
      {
        runId,
        deviceId: Number(run.device_id),
        fromInterventionId: String(existingLink.intervention_id),
        toInterventionId: String(best.row.id),
        overlapSeconds: best.overlap,
        windowSpanSeconds,
      },
      'Drift link re-elected a different intervention — the link and both its numbers move together',
    );
  }

  const [linkRow] = (await db('intervention_drift_links')
    .insert({
      tenant_id: tenantId,
      intervention_id: best.row.id,
      drift_run_id: runId,
      device_id: Number(run.device_id),
      disposition,
      // The K6 verdict as it stood BEFORE this call. On an idempotent re-run
      // the row already exists and `merge` leaves the original value alone —
      // see the `onConflict` below.
      prior_verdict: prior === INTERVENTION_ATTRIBUTION_VERDICT ? null : prior,
      window_span_seconds: windowSpanSeconds,
      overlap_seconds: Math.min(best.overlap, windowSpanSeconds),
      linked_at: now,
    })
    .onConflict(['tenant_id', 'drift_run_id'])
    .merge([
      // `intervention_id` FIRST and deliberately: the three columns below
      // describe ONE specific window and are only true of the window this row
      // names. `prior_verdict` stays out — it is what K6 said the FIRST time,
      // and refreshing it after this function has already written
      // `intervention` would overwrite the evidence with its own effect.
      'intervention_id',
      'disposition',
      'overlap_seconds',
      'window_span_seconds',
      'linked_at',
    ])
    .returning<{ id: string }[]>('id')) as { id: string }[];

  await db('intervention_events').insert({
    tenant_id: tenantId,
    intervention_id: best.row.id,
    event: 'drift_linked',
    detail: JSON.stringify({
      driftRunId: String(runId),
      disposition,
      priorVerdict: prior,
      overlapSeconds: best.overlap,
      windowSpanSeconds,
      // The ratio is what makes `window_too_wide` readable on the screen:
      // "your two-hour window overlaps 0.1 % of a seven-day change interval".
      coverage:
        windowSpanSeconds > 0
          ? Math.round((best.overlap / windowSpanSeconds) * 10_000) / 10_000
          : 1,
      minCoverage: INTERVENTION_MIN_OVERLAP_RATIO,
    }),
    at: now,
  });

  return {
    id: String(linkRow?.id ?? ''),
    interventionId: String(best.row.id),
    driftRunId: String(runId),
    deviceId: Number(run.device_id),
    disposition,
    priorVerdict: prior === INTERVENTION_ATTRIBUTION_VERDICT ? null : prior,
    windowSpanSeconds,
    overlapSeconds: Math.min(best.overlap, windowSpanSeconds),
    linkedAt: now.toISOString(),
  };
}

export interface SweepOutcome {
  considered: number;
  attributed: number;
  alreadyExplained: number;
  tooWide: number;
}

export interface SweepOptions {
  deviceId?: number;
  limit?: number;
  now?: Date;
}

/**
 * Walk the drifted runs that no intervention has considered yet.
 *
 * The candidate filter is a deliberate SUPERSET: a run is picked up when its
 * device has a non-cancelled window that opened before the run was computed and
 * ended no more than `INTERVENTION_MAX_ATTRIBUTION_WINDOW_MINUTES` before it.
 * The exact overlap is then decided by `linkRunToIntervention`, which is the
 * only place that arithmetic exists. Selecting loosely and deciding precisely
 * is what keeps the SQL readable AND the verdict correct; the reverse — a
 * clever predicate that decides in SQL — is how the two would drift apart.
 *
 * Called from `closeIntervention` (so a window never leaves its own diff on the
 * anomaly screen) and from `POST /interventions/sweep`. It is also the function
 * a scheduler should call next to `attributePendingRuns`, and it is safe to
 * call as often as one likes: the unique index on `(tenant_id, drift_run_id)`
 * makes every pass after the first a no-op.
 */
export async function sweepInterventionLinks(
  tenantId: number,
  options: SweepOptions = {},
): Promise<SweepOutcome> {
  const now = options.now ?? new Date();
  const limit = Math.min(options.limit ?? 200, 1000);

  // EXPIRE FIRST, and here rather than in the scheduler.
  //
  // `expireOverdue` states property 2 of §10/F3 — "an intervention nobody
  // closes expires by itself" — and until this line it ran on HTTP READ paths
  // only: an unread screen meant a window declared for five minutes was still
  // open five days later. This function is the one the periodic sweep arms, so
  // the guard is armed where the sweep is, and the next caller of the sweep
  // inherits it instead of having to remember it.
  //
  // It must run BEFORE the attribution below: `effectiveEnd()` reads the row's
  // status, and a window still marked `open` an hour past its deadline would
  // absorb a change made after it ran out.
  //
  // A failure here must not abort the link sweep — expiring is one property of
  // the feature and attributing is the other, and losing both because of one is
  // worse than losing one.
  try {
    await expireOverdue(tenantId, now);
  } catch (err) {
    logger.error(
      { err, tenantId },
      'Intervention expiry sweep failed — windows past their deadline may still read as open',
    );
  }

  const q = db('drift_runs as dr')
    .join('devices as d', 'd.id', 'dr.device_id')
    .leftJoin('intervention_drift_links as l', function joinLinks() {
      this.on('l.drift_run_id', '=', 'dr.id').andOn('l.tenant_id', '=', db.raw('?', [tenantId]));
    })
    .where('d.tenant_id', tenantId)
    .andWhere('dr.status', 'drifted')
    .whereNull('l.id')
    .whereExists((qb) => {
      void qb
        .select(db.raw('1'))
        .from('interventions as i')
        .whereRaw('i.device_id = dr.device_id')
        .andWhere('i.tenant_id', tenantId)
        .andWhereNot('i.status', 'cancelled')
        .andWhereRaw('i.opened_at <= dr.started_at')
        .andWhereRaw(`i.expires_at >= dr.started_at - interval '${MAX_WINDOW_MS / 1000} seconds'`);
    });
  if (options.deviceId !== undefined) void q.andWhere('dr.device_id', options.deviceId);

  const rows = (await q
    .orderBy('dr.id', 'desc')
    .limit(limit)
    .select('dr.id')) as Array<{ id: string }>;

  const outcome: SweepOutcome = {
    considered: rows.length,
    attributed: 0,
    alreadyExplained: 0,
    tooWide: 0,
  };
  for (const row of rows) {
    try {
      const link = await linkRunToIntervention(tenantId, String(row.id), now);
      if (!link) continue;
      if (link.disposition === 'attributed') outcome.attributed += 1;
      else if (link.disposition === 'already_explained') outcome.alreadyExplained += 1;
      else outcome.tooWide += 1;
    } catch (err) {
      // One unlinkable run must not abort the sweep, for the same reason one
      // dead CPE must not abort a fleet drift sweep.
      logger.error({ err, runId: row.id, tenantId }, 'Intervention link failed for drift run');
    }
  }
  return outcome;
}

interface LinkRow {
  id: string;
  intervention_id: string;
  drift_run_id: string;
  device_id: number;
  disposition: string;
  prior_verdict: string | null;
  window_span_seconds: number;
  overlap_seconds: number;
  linked_at: Date;
}

function toLink(r: LinkRow): InterventionLink {
  return {
    id: String(r.id),
    interventionId: String(r.intervention_id),
    driftRunId: String(r.drift_run_id),
    deviceId: Number(r.device_id),
    disposition: r.disposition as InterventionLinkDisposition,
    priorVerdict: r.prior_verdict,
    windowSpanSeconds: Number(r.window_span_seconds),
    overlapSeconds: Number(r.overlap_seconds),
    linkedAt: r.linked_at.toISOString(),
  };
}

export async function listLinks(
  tenantId: number,
  interventionId: string,
): Promise<InterventionLink[]> {
  const rows = (await db('intervention_drift_links')
    .where({ tenant_id: tenantId, intervention_id: interventionId })
    .orderBy('linked_at', 'desc')
    .orderBy('id', 'desc')
    .select(
      'id',
      'intervention_id',
      'drift_run_id',
      'device_id',
      'disposition',
      'prior_verdict',
      'window_span_seconds',
      'overlap_seconds',
      'linked_at',
    )) as LinkRow[];
  return rows.map(toLink);
}
