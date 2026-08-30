// ============================================================================
// ObliWAN — F3: the intervention mode (ARCHITECTURE.md §10/F3)
// ============================================================================
//
// Today the product discovers a technician's work AFTER the fact, as drift. The
// mechanism is forensic and never cooperative. This file is the cooperative
// half: a human declares "I am about to open Winbox on this router, here is who
// I am, why, and for how long", and the platform frames the gesture instead of
// investigating it afterwards.
//
// ┌─ AN OPEN INTERVENTION IS NOT AN AUTHORISATION TO WRITE ───────────────────┐
// │ D3 is untouched. Nothing in this file, and nothing in this feature,       │
// │ enqueues a change job, renders a plan or opens a write session. The only  │
// │ device access here is `collectAndStore` — a configuration READ, the same  │
// │ one `runDrift({ collect: true })` makes — and it is opt-in on every call. │
// │ An intervention changes what the platform SAYS about a change, never who  │
// │ is allowed to make one.                                                   │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ AN INTERVENTION THAT IS NEVER CLOSED MUST EXPIRE BY ITSELF ──────────────┐
// │ It is the failure mode that would quietly destroy the feature: a window   │
// │ left open in March excuses every drift on that router until somebody      │
// │ notices, which is a permanent hole in attribution — precisely the thing   │
// │ K6 exists to close.                                                       │
// │                                                                           │
// │ So `expireOverdue()` is not a background nicety, and it does not depend   │
// │ on a scheduler being wired up: it runs on the READ and OPEN paths of this │
// │ service. `openIntervention` calls it FIRST, and that call is              │
// │ load-bearing — the partial unique index `interventions_one_open_uq` would │
// │ otherwise refuse a new window on a device whose last one ran out weeks    │
// │ ago. The sweep is not decoration; the feature does not work without it.   │
// │                                                                           │
// │ Those callers are ALL HTTP paths, and that was not enough: an instance    │
// │ whose intervention screen nobody opened left a five-minute window open    │
// │ for five days. `driftLink.sweepInterventionLinks()` — the one function a  │
// │ scheduler arms — now calls it too, which is why `expireOverdue` lives in  │
// │ `./expiry` rather than in this file.                                      │
// │                                                                           │
// │ "…and says so": expiry writes an `intervention_events` row carrying how   │
// │ many seconds of the window went unattended, and logs a warning. A status  │
// │ flipping in place would be a state; the row is a fact that outlives the   │
// │ screen.                                                                   │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ §8.4's NETWATCH DOES NOT EXIST YET ──────────────────────────────────────┐
// │ §10/F3 mentions "netwatch armé" among the bricks. It is not in this       │
// │ schema and this file does not presuppose it: the window is bounded by a   │
// │ declared deadline and by the expiry sweep, not by an on-box watchdog.     │
// │ When §8.4 lands, arming it belongs BETWEEN `openIntervention` and the     │
// │ human's first click, and the shape of this service does not have to move  │
// │ for that — `intervention_events` already has a place for the arming.      │
// └───────────────────────────────────────────────────────────────────────────┘
//
// SECRETS (§8.2 / R10): this file stores snapshot IDS, never configuration
// text; `intervention_events.detail` is additionally refused by the database
// when it carries a credential-shaped key (migration 020, decision 5).

import type { Knex } from 'knex';
import {
  INTERVENTION_DEFAULT_WINDOW_MINUTES,
  interventionIsLive,
  INTERVENTION_MAX_WINDOW_MINUTES,
  INTERVENTION_MIN_WINDOW_MINUTES,
  type InterventionChannel,
  type InterventionDisposition,
  type InterventionEvent,
  type InterventionEventRow,
  type InterventionStatus,
  type InterventionSummary,
} from '@obliwan/shared/dist/intervention';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { AppError } from '../../middleware/errorHandler';
import { collectAndStore, hasNormalizer } from '../config/collect.service';
import { latestDocument } from '../config/snapshot.service';
import { runDrift } from '../drift/drift.service';
import { linkRunToIntervention, sweepInterventionLinks } from './driftLink';
import { expireOverdue, logEvent } from './expiry';
import { effectiveEnd } from './window';

// One implementation, its historical import surface preserved. See ./expiry.
export { expireOverdue } from './expiry';
export type { ExpiryOutcome } from './expiry';

// ============================================================================
// Rows and mapping
// ============================================================================

interface InterventionRow {
  id: string;
  uuid: string;
  tenant_id: number;
  device_id: number;
  device_name: string | null;
  status: string;
  channel: string;
  operator: string;
  opened_by: number | null;
  reason: string;
  opened_at: Date;
  expires_at: Date;
  closed_at: Date | null;
  closed_by: number | null;
  expired_at: Date | null;
  cancelled_at: Date | null;
  snapshot_before_id: string | null;
  snapshot_after_id: string | null;
  drift_run_id: string | null;
  findings_count: number;
  max_severity: string | null;
  disposition: string;
  notes: string | null;
  created_at: Date;
  linked_run_count?: string | number;
}

const COLUMNS = [
  'i.id', 'i.uuid', 'i.tenant_id', 'i.device_id', 'i.status', 'i.channel', 'i.operator',
  'i.opened_by', 'i.reason', 'i.opened_at', 'i.expires_at', 'i.closed_at', 'i.closed_by',
  'i.expired_at', 'i.cancelled_at', 'i.snapshot_before_id', 'i.snapshot_after_id',
  'i.drift_run_id', 'i.findings_count', 'i.max_severity', 'i.disposition', 'i.notes',
  'i.created_at', 'd.name as device_name',
];

function toSummary(r: InterventionRow): InterventionSummary {
  return {
    id: String(r.id),
    uuid: r.uuid,
    tenantId: Number(r.tenant_id),
    deviceId: Number(r.device_id),
    deviceName: r.device_name ?? null,
    status: r.status as InterventionStatus,
    channel: r.channel as InterventionChannel,
    operator: r.operator,
    openedBy: r.opened_by === null ? null : Number(r.opened_by),
    reason: r.reason,
    openedAt: r.opened_at.toISOString(),
    expiresAt: r.expires_at.toISOString(),
    closedAt: r.closed_at ? r.closed_at.toISOString() : null,
    closedBy: r.closed_by === null ? null : Number(r.closed_by),
    expiredAt: r.expired_at ? r.expired_at.toISOString() : null,
    effectiveEndAt: effectiveEnd(r).toISOString(),
    snapshotBeforeId: r.snapshot_before_id === null ? null : String(r.snapshot_before_id),
    snapshotAfterId: r.snapshot_after_id === null ? null : String(r.snapshot_after_id),
    driftRunId: r.drift_run_id === null ? null : String(r.drift_run_id),
    findingsCount: Number(r.findings_count),
    maxSeverity: r.max_severity,
    disposition: r.disposition as InterventionDisposition,
    notes: r.notes,
    linkedRunCount: Number(r.linked_run_count ?? 0),
    createdAt: r.created_at.toISOString(),
  };
}

function scoped(tenantId: number, q: Knex | Knex.Transaction = db) {
  // `interventions` DOES carry `tenant_id`, and the join on `devices` is for
  // the name only — but the predicate stays on `i.tenant_id` so that a device
  // row cannot be what decides isolation.
  return q('interventions as i')
    .leftJoin('devices as d', 'd.id', 'i.device_id')
    .where('i.tenant_id', tenantId);
}

/** The linked-run counter, as a correlated subquery rather than a GROUP BY:
 *  the list is small, and a GROUP BY over the whole join would have to repeat
 *  every column of `COLUMNS` in the grouping clause. */
function linkedCount(q: Knex | Knex.Transaction = db) {
  return q.raw(
    '(SELECT count(*) FROM intervention_drift_links l ' +
      "WHERE l.intervention_id = i.id AND l.tenant_id = i.tenant_id AND l.disposition = 'attributed'" +
      ') as linked_run_count',
  );
}

// ============================================================================
// The lifecycle log, and the expiry
// ============================================================================
//
// `logEvent` and `expireOverdue` live in `./expiry`. They moved there so that
// `driftLink.sweepInterventionLinks()` — the only entry point a scheduler ever
// arms — can run the expiry without importing this file back and closing a
// cycle. Both are re-exported at the top of this file, so every existing
// caller and `services/intervention/index.ts` still see them where they have
// always been, and there is still exactly ONE implementation of each.

export async function listEvents(
  tenantId: number,
  interventionId: string,
): Promise<InterventionEventRow[]> {
  const rows = (await db('intervention_events')
    .where({ tenant_id: tenantId, intervention_id: interventionId })
    .orderBy('at', 'asc')
    .orderBy('id', 'asc')
    .select('id', 'intervention_id', 'event', 'actor_user_id', 'detail', 'at')) as Array<{
    id: string;
    intervention_id: string;
    event: string;
    actor_user_id: number | null;
    detail: unknown;
    at: Date;
  }>;
  return rows.map((r) => ({
    id: String(r.id),
    interventionId: String(r.intervention_id),
    event: r.event as InterventionEvent,
    actorUserId: r.actor_user_id === null ? null : Number(r.actor_user_id),
    detail: (r.detail as Record<string, unknown>) ?? {},
    at: r.at.toISOString(),
  }));
}

// ============================================================================
// Opening
// ============================================================================

export interface OpenInterventionInput {
  deviceId: number;
  operator: string;
  reason: string;
  channel?: InterventionChannel;
  windowMinutes?: number;
  /** Take a fresh configuration READ as the before-state. Opt-in: it opens an
   *  SSH session, and a device somebody is about to fix by hand is often
   *  exactly the device that will not answer. */
  collect?: boolean;
  openedBy: number | null;
}

export interface OpenInterventionResult {
  intervention: InterventionSummary;
  /** Non-null when `collect` was asked for and the device refused. The window
   *  still opens: refusing to declare an intervention because the box is
   *  unreachable would push the technician to work undeclared, which is the
   *  behaviour this feature exists to replace. */
  collectError: string | null;
}

export async function openIntervention(
  tenantId: number,
  input: OpenInterventionInput,
  now: Date = new Date(),
): Promise<OpenInterventionResult> {
  const windowMinutes = input.windowMinutes ?? INTERVENTION_DEFAULT_WINDOW_MINUTES;
  if (
    !Number.isFinite(windowMinutes) ||
    windowMinutes < INTERVENTION_MIN_WINDOW_MINUTES ||
    windowMinutes > INTERVENTION_MAX_WINDOW_MINUTES
  ) {
    throw new AppError(
      400,
      `The declared window must be between ${INTERVENTION_MIN_WINDOW_MINUTES} and ` +
        `${INTERVENTION_MAX_WINDOW_MINUTES} minutes.`,
    );
  }
  if (input.reason.trim().length === 0 || input.operator.trim().length === 0) {
    throw new AppError(400, 'An intervention needs an operator and a reason.');
  }

  const device = await db('devices')
    .where({ id: input.deviceId, tenant_id: tenantId })
    .first<{ id: number } | undefined>('id');
  if (!device) throw new AppError(404, 'Device not found');

  // LOAD-BEARING. Without it, a window that ran out three weeks ago still holds
  // `interventions_one_open_uq` and this call fails with a unique violation on
  // a constraint the operator cannot see.
  await expireOverdue(tenantId, now, input.deviceId);

  const open = await db('interventions')
    .where({ tenant_id: tenantId, device_id: input.deviceId, status: 'open' })
    .first<{ id: string } | undefined>('id');
  if (open) {
    throw new AppError(
      409,
      `This device already has an open intervention (#${open.id}). Close it before ` +
        'declaring another one — two overlapping windows make "which one explains this ' +
        'change" unanswerable.',
    );
  }

  let snapshotBeforeId: string | null = null;
  let collectError: string | null = null;
  if (input.collect && hasNormalizer()) {
    try {
      const out = await collectAndStore(input.deviceId, tenantId, { source: 'ssh' });
      snapshotBeforeId = String(out.snapshot.snapshotId);
    } catch (err) {
      collectError = err instanceof Error ? err.message : String(err);
    }
  } else if (input.collect) {
    collectError = 'no NCM normaliser is registered on this build';
  }
  if (snapshotBeforeId === null) {
    const latest = await latestDocument(input.deviceId);
    snapshotBeforeId = latest ? latest.id : null;
  }

  const expiresAt = new Date(now.getTime() + windowMinutes * 60_000);

  const [row] = await db('interventions')
    .insert({
      tenant_id: tenantId,
      device_id: input.deviceId,
      status: 'open',
      channel: input.channel ?? 'winbox',
      operator: input.operator.trim().slice(0, 96),
      opened_by: input.openedBy,
      reason: input.reason.trim(),
      opened_at: now,
      expires_at: expiresAt,
      snapshot_before_id: snapshotBeforeId,
    })
    .returning<{ id: string }[]>('id');

  await logEvent(db, tenantId, String(row.id), 'opened', input.openedBy, {
    windowMinutes,
    channel: input.channel ?? 'winbox',
    collectAttempted: Boolean(input.collect),
    collectFailed: collectError !== null,
  });
  if (snapshotBeforeId !== null) {
    await logEvent(db, tenantId, String(row.id), 'snapshot_before', input.openedBy, {
      snapshotId: snapshotBeforeId,
      fresh: Boolean(input.collect) && collectError === null,
    });
  }

  const intervention = await getIntervention(tenantId, String(row.id), { sweep: false });
  return { intervention: intervention as InterventionSummary, collectError };
}

// ============================================================================
// Closing
// ============================================================================

export interface CloseInterventionInput {
  /** Take a fresh configuration READ as the after-state. */
  collect?: boolean;
  notes?: string | null;
  closedBy: number | null;
}

export interface CloseInterventionResult {
  intervention: InterventionSummary;
  /** The semantic diff of the window, ready to be promoted into a template or
   *  signed as an F1 exception. `null` when the configuration did not move. */
  driftRunId: string | null;
  findingsCount: number;
  /** How many drift runs this window absorbed as it closed. */
  linkedRuns: number;
  collectError: string | null;
}

/**
 * Close a window: take the after-state, diff it against the before-state, and
 * hand the operator the difference.
 *
 * The diff is produced by `runDrift` with BOTH snapshot ids pinned. It is not a
 * new comparison engine: the semantic diff, its layer-4 suppression rules and
 * its `renormalization` / `model_upgrade` exclusions are M4's, and an
 * intervention that reproduced them would be a second opinion nobody asked for.
 */
export async function closeIntervention(
  tenantId: number,
  interventionId: string,
  input: CloseInterventionInput,
  now: Date = new Date(),
): Promise<CloseInterventionResult> {
  const row = await db('interventions')
    .where({ tenant_id: tenantId, id: interventionId })
    .first<InterventionRow | undefined>('*');
  if (!row) throw new AppError(404, 'Intervention not found');
  if (row.status === 'cancelled') {
    throw new AppError(409, 'This intervention was cancelled and never ran.');
  }
  if (row.status === 'closed') {
    throw new AppError(409, 'This intervention is already closed.');
  }
  // An EXPIRED window can still be closed, and that is deliberate: the diff is
  // still worth capturing, and refusing would punish the operator for the one
  // thing the expiry sweep already recorded against them.

  let collectError: string | null = null;
  let snapshotAfterId: string | null = null;
  if (input.collect && hasNormalizer()) {
    try {
      const out = await collectAndStore(Number(row.device_id), tenantId, { source: 'ssh' });
      snapshotAfterId = String(out.snapshot.snapshotId);
    } catch (err) {
      collectError = err instanceof Error ? err.message : String(err);
    }
  } else if (input.collect) {
    collectError = 'no NCM normaliser is registered on this build';
  }
  if (snapshotAfterId === null) {
    const latest = await latestDocument(Number(row.device_id));
    snapshotAfterId = latest ? latest.id : null;
  }

  let driftRunId: string | null = null;
  let findingsCount = 0;
  let maxSeverity: string | null = null;

  const before = row.snapshot_before_id === null ? null : String(row.snapshot_before_id);
  if (before !== null && snapshotAfterId !== null && before !== snapshotAfterId) {
    const run = await runDrift(tenantId, Number(row.device_id), {
      cause: 'manual',
      baselineSnapshotId: before,
      snapshotId: snapshotAfterId,
      // `full`, not the `managed_only` default of §5.3. Under `managed_only` a
      // resource we do not manage that APPEARED during the window is counted
      // as out-of-scope instead of reported — and a firewall rule a technician
      // added by hand is precisely such a resource. The whole point of the
      // window is to capture what the human did, including the parts of the
      // box the platform does not own.
      scope: 'full',
    });
    if (run) {
      driftRunId = run.id;
      findingsCount = run.findingsCount - run.ignoredCount;
      maxSeverity = run.maxSeverity;
    }
  }
  // `before === snapshotAfterId` is NOT a failure: `config_snapshots`
  // deduplicates on (device_id, ncm_hash), so an intervention that touched
  // nothing legitimately ends on the very same row it started from. That
  // equality IS the evidence of "no change", and it is why the disposition
  // below is `no_change` rather than `unreviewed`.
  const noChange = before !== null && before === snapshotAfterId;

  await db('interventions')
    .where({ tenant_id: tenantId, id: interventionId })
    .update({
      status: 'closed',
      closed_at: now,
      closed_by: input.closedBy,
      snapshot_after_id: snapshotAfterId,
      drift_run_id: driftRunId,
      findings_count: findingsCount,
      max_severity: maxSeverity,
      disposition: noChange && findingsCount === 0 ? 'no_change' : 'unreviewed',
      notes: input.notes ?? row.notes,
      updated_at: now,
    });

  if (snapshotAfterId !== null) {
    await logEvent(db, tenantId, interventionId, 'snapshot_after', input.closedBy, {
      snapshotId: snapshotAfterId,
      fresh: Boolean(input.collect) && collectError === null,
    });
  }
  await logEvent(db, tenantId, interventionId, 'closed', input.closedBy, {
    findingsCount,
    driftRunId,
    noChange,
  });

  // The window is terminal now, so everything it should absorb is knowable.
  // Claiming the closing run FIRST means the diff this intervention produced
  // never shows up on the "changes nobody owns" screen even for a second.
  if (driftRunId !== null) await linkRunToIntervention(tenantId, driftRunId, now);
  await sweepInterventionLinks(tenantId, { deviceId: Number(row.device_id), now });

  const intervention = (await getIntervention(tenantId, interventionId, {
    sweep: false,
  })) as InterventionSummary;

  return {
    intervention,
    driftRunId,
    findingsCount,
    // Read back from the link table rather than counted from the sweep's
    // return value: the closing run is claimed before the sweep and would
    // otherwise be missing from the number the operator is shown.
    linkedRuns: intervention.linkedRunCount,
    collectError,
  };
}

export async function cancelIntervention(
  tenantId: number,
  interventionId: string,
  actorUserId: number | null,
  now: Date = new Date(),
): Promise<InterventionSummary> {
  const row = await db('interventions')
    .where({ tenant_id: tenantId, id: interventionId })
    .first<InterventionRow | undefined>('id', 'status');
  if (!row) throw new AppError(404, 'Intervention not found');
  if (row.status !== 'open') {
    throw new AppError(409, `Only an open intervention can be cancelled (this one is ${row.status}).`);
  }
  await db('interventions')
    .where({ tenant_id: tenantId, id: interventionId })
    .update({ status: 'cancelled', cancelled_at: now, updated_at: now });
  await logEvent(db, tenantId, interventionId, 'cancelled', actorUserId, {});
  return (await getIntervention(tenantId, interventionId, { sweep: false })) as InterventionSummary;
}

/**
 * Record what was decided about the diff (F1's neighbour).
 *
 * This service does NOT create the template or the exception itself: promoting
 * a diff into a template is `TEMPLATE_WRITE` territory (R6) and signing an
 * exception is F1's, and an intervention that quietly authored either would be
 * doing privileged work under a capability that does not cover it. What it
 * records is the DECISION, so a window stops reading as unreviewed.
 */
export async function setDisposition(
  tenantId: number,
  interventionId: string,
  disposition: InterventionDisposition,
  notes: string | null,
  actorUserId: number | null,
): Promise<InterventionSummary> {
  const row = await db('interventions')
    .where({ tenant_id: tenantId, id: interventionId })
    .first<{ status: string } | undefined>('status');
  if (!row) throw new AppError(404, 'Intervention not found');
  if (row.status !== 'closed') {
    throw new AppError(
      409,
      'A disposition can only be recorded on a CLOSED intervention: there is no diff to ' +
        'decide about until the after-state has been taken.',
    );
  }
  await db('interventions')
    .where({ tenant_id: tenantId, id: interventionId })
    .update({ disposition, notes, updated_at: new Date() });
  await logEvent(db, tenantId, interventionId, 'disposition', actorUserId, { disposition });
  return (await getIntervention(tenantId, interventionId, { sweep: false })) as InterventionSummary;
}

// ============================================================================
// Reading
// ============================================================================

export interface ListInterventionsFilter {
  deviceId?: number;
  status?: InterventionStatus;
  /** The screen that matters most: windows that ran out unattended. */
  expiredOnly?: boolean;
  /** Closed windows whose diff nobody decided about yet. */
  unreviewedOnly?: boolean;
  limit?: number;
  offset?: number;
}

export async function listInterventions(
  tenantId: number,
  filter: ListInterventionsFilter = {},
): Promise<InterventionSummary[]> {
  // Every read path sweeps first: an operator must never be shown an `open`
  // window whose deadline passed an hour ago.
  await expireOverdue(tenantId);

  const q = scoped(tenantId);
  if (filter.deviceId !== undefined) void q.andWhere('i.device_id', filter.deviceId);
  if (filter.status) void q.andWhere('i.status', filter.status);
  if (filter.expiredOnly) void q.andWhere('i.status', 'expired');
  if (filter.unreviewedOnly) {
    void q.andWhere('i.status', 'closed').andWhere('i.disposition', 'unreviewed');
  }
  const rows = await q
    .orderBy('i.opened_at', 'desc')
    .orderBy('i.id', 'desc')
    .limit(Math.min(filter.limit ?? 50, 200))
    .offset(filter.offset ?? 0)
    .select<InterventionRow[]>([...COLUMNS, linkedCount()]);
  return rows.map(toSummary);
}

export async function getIntervention(
  tenantId: number,
  interventionId: string,
  options: { sweep?: boolean } = {},
): Promise<InterventionSummary | null> {
  if (options.sweep !== false) await expireOverdue(tenantId);
  const row = await scoped(tenantId)
    .andWhere('i.id', interventionId)
    .first<InterventionRow | undefined>([...COLUMNS, linkedCount()]);
  return row ? toSummary(row) : null;
}

/**
 * The live window for a device, if any — the question the drift linker asks.
 *
 * Returns the row even when its deadline has passed and the sweep has not run
 * yet? NO: it sweeps first. A window past its deadline stops absorbing drift at
 * the instant it expires, not at the instant somebody notices.
 */
export async function liveInterventionFor(
  tenantId: number,
  deviceId: number,
  now: Date = new Date(),
): Promise<InterventionSummary | null> {
  await expireOverdue(tenantId, now, deviceId);
  const row = await scoped(tenantId)
    .andWhere('i.device_id', deviceId)
    .andWhere('i.status', 'open')
    .first<InterventionRow | undefined>([...COLUMNS, linkedCount()]);
  return row ? toSummary(row) : null;
}

export interface InterventionOverview {
  open: number;
  expiredUnclosed: number;
  closedUnreviewed: number;
  attributedRuns: number;
}

/** The counters a dashboard tile needs, in one round trip. */
export async function overview(tenantId: number): Promise<InterventionOverview> {
  await expireOverdue(tenantId);
  const counts = (await db('interventions')
    .where('tenant_id', tenantId)
    .select('status', 'disposition')
    .count<{ status: string; disposition: string; count: string }[]>('* as count')
    .groupBy('status', 'disposition')) as unknown as Array<{
    status: string;
    disposition: string;
    count: string;
  }>;
  const linked = (await db('intervention_drift_links')
    .where({ tenant_id: tenantId, disposition: 'attributed' })
    .count<{ count: string }[]>('* as count')
    .first()) as { count: string } | undefined;

  let open = 0;
  let expiredUnclosed = 0;
  let closedUnreviewed = 0;
  for (const c of counts) {
    const n = Number(c.count);
    // Through the shared predicate, not a string comparison: "which statuses
    // are still absorbing drift" is a rule the client reads from the same
    // place, and two answers to it would put a different number on the tile
    // than on the list.
    if (interventionIsLive(c.status as InterventionStatus)) open += n;
    if (c.status === 'expired') expiredUnclosed += n;
    if (c.status === 'closed' && c.disposition === 'unreviewed') closedUnreviewed += n;
  }
  return {
    open,
    expiredUnclosed,
    closedUnreviewed,
    attributedRuns: Number(linked?.count ?? 0),
  };
}
