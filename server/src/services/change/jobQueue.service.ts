// ============================================================================
// ObliWAN — `change_jobs`: THE queue (M6, decision D3)
// ============================================================================
//
// Nothing writes to an equipment outside this table. This file owns the
// MECHANICS of that queue — claiming, leasing, reaping, stepping, transitioning
// — and knows nothing about what a job actually does to a router. The
// orchestration (guard, backup, dead-man, apply, outcome) is `apply.service.ts`
// and is injected as a runner at startup, which is also what keeps the two
// modules acyclic.
//
// ┌─ FOUR PROPERTIES, AND THREE OF THEM ARE THE DATABASE'S, NOT MINE ─────────┐
// │                                                                           │
// │ 1. ONE JOB IN FLIGHT PER DEVICE. Enforced by                              │
// │    `change_jobs_one_in_flight_uq` (migration 009): UNIQUE (device_id)      │
// │    WHERE status IN (the eight active states). This service does NOT        │
// │    re-implement it with a SELECT-then-INSERT — that pair has a gap in the  │
// │    middle and two API calls, two workers or one double-click fit in it.    │
// │    `enqueue` lets the 23505 come back and translates it into a 409.        │
// │                                                                           │
// │ 2. TWO WORKERS NEVER GET THE SAME JOB. `FOR UPDATE SKIP LOCKED` inside a   │
// │    CTE, with the UPDATE re-asserting `status = 'queued'`. The row lock is  │
// │    what serialises the claim; the status predicate is what makes a claim   │
// │    that lost the race return zero rows instead of stealing a running job.  │
// │                                                                           │
// │ 3. A DEAD WORKER RELEASES ITS DEVICE — BY A LEASE, NOT BY A FLAG. A flag   │
// │    needs somebody alive to clear it, and the process that would clear it   │
// │    is the process that died. `lease_expires_at` runs out on its own.       │
// │                                                                           │
// │ 4. THE REAPER NEVER REQUEUES A JOB THAT MAY HAVE WRITTEN.                  │
// │    `WRITE_COMMITTED_STATUSES` (applying / verifying / soaking / disarming) │
// │    are left EXACTLY where they are and reported for human inspection. The  │
// │    only thing worse than a half-applied router is a twice-applied one,     │
// │    and the on-box dead-man is already handling the first case.             │
// └───────────────────────────────────────────────────────────────────────────┘
//
// MAINTENANCE WINDOWS (`sites.maintenance_window`, migration 002): a job
// outside its window WAITS. It is not claimed, not failed, not touched — the
// pick query simply does not see it this tick. Two consequences that are
// deliberate: (a) a job that waits burns no `attempt`, which is why the window
// is evaluated BEFORE the claim and not after it; (b) a window we cannot PARSE
// makes the job wait too, loudly, rather than be pushed on a guess.

import os from 'os';
import crypto from 'crypto';
import type { Knex } from 'knex';
import {
  ACTIVE_CHANGE_JOB_STATUSES,
  SOCKET_EVENTS,
  WRITE_COMMITTED_STATUSES,
  canTransition,
  isTerminalJobStatus,
  isWriteJobKind,
  type ChangeJobKind,
  type ChangeJobStatus,
  type ChangeJobSummary,
  type ChangeStepKind,
  type ChangeStepStatus,
  type GuardVerdict,
  type SafetyLevel,
} from '@obliwan/shared';
import { db } from '../../db';
import { config } from '../../config';
import { logger } from '../../utils/logger';
import { leaderElection } from '../leaderElection';
import { emitToDevice, emitToTenant } from '../fleet/fleetEvents';

// ============================================================================
// Identity and timing
// ============================================================================

/**
 * `claimed_by` is a WORKER identity, not a user: host, pid and a per-process
 * uuid. The uuid matters — two containers on the same host can share a pid
 * namespace, and a restarted process reuses pids often enough that "the same
 * host:pid" would let a new worker silently inherit a dead one's lease.
 */
export const WORKER_ID = `${os.hostname()}:${process.pid}:${crypto.randomUUID().slice(0, 8)}`;

/**
 * How long a claim is good for without a renewal.
 *
 * Long enough that a slow `/system/backup` on a congested tunnel does not lose
 * its lease mid-flight; short enough that a killed worker's device is free
 * again within a coffee. `apply.service` renews it at every phase boundary, so
 * a job that legitimately takes twenty minutes never relies on this number —
 * only a job whose worker STOPPED does.
 */
export const LEASE_TTL_MS = 120_000;

/** How often the worker looks for work and reaps expired leases. */
export const POLL_INTERVAL_MS = 3_000;

/**
 * Jobs run in parallel PER PROCESS. Not per device — that is the database's
 * unique index — and deliberately small: every one of these is a live session
 * onto somebody's production router.
 */
export const MAX_CONCURRENT_JOBS = Number(process.env.OBLIWAN_CHANGE_CONCURRENCY) || 4;

/** How many queued rows the window pre-pass looks at per tick. */
const PICK_SCAN_LIMIT = 200;

// ============================================================================
// Errors
// ============================================================================

/** A second active job was refused BY THE DATABASE. Carries the device so the
 *  controller can say which box is busy rather than "conflict". */
export class DeviceBusyError extends Error {
  constructor(readonly deviceId: number) {
    super(
      `Device ${deviceId} already has a change job in flight. ` +
        'One job per device is a unique index, not a policy: a second plan compiled ' +
        'against the same base state describes a world the first one is about to change.',
    );
    this.name = 'DeviceBusyError';
  }
}

/** The lease was lost while the job was running (another process reaped it, or
 *  the row was moved under us). The runner must stop touching the device. */
export class LeaseLostError extends Error {
  constructor(readonly jobId: number) {
    super(`Job ${jobId} no longer holds its lease; this worker must stop.`);
    this.name = 'LeaseLostError';
  }
}

export class InvalidTransitionError extends Error {
  constructor(readonly from: ChangeJobStatus, readonly to: ChangeJobStatus) {
    super(`Illegal change_job transition ${from} -> ${to}`);
    this.name = 'InvalidTransitionError';
  }
}

// ============================================================================
// Rows
// ============================================================================

export interface ChangeJobRow {
  id: string | number;
  uuid: string;
  tenant_id: number;
  device_id: number;
  plan_id: string | number | null;
  kind: ChangeJobKind;
  status: ChangeJobStatus;
  attempt: number;
  max_attempts: number;
  base_state_hash: string;
  safety_level: SafetyLevel;
  safety_peer_device_id: number | null;
  degraded_confirmed_by: number | null;
  degraded_confirmed_at: Date | null;
  guard_verdict: GuardVerdict | null;
  guard_reasons: unknown;
  override_reason: string | null;
  overridden_by: number | null;
  overridden_at: Date | null;
  claimed_by: string | null;
  claimed_at: Date | null;
  lease_expires_at: Date | null;
  scheduled_for: Date | null;
  window_start: Date | null;
  window_end: Date | null;
  preflight_backup_id: string | number | null;
  deadman_handle: string | null;
  deadman_armed_at: Date | null;
  deadman_disarmed_at: Date | null;
  confirm_deadline: Date | null;
  soak_until: Date | null;
  requested_by: number | null;
  approved_by: number | null;
  outcome: string | null;
  error_kind: string | null;
  error_message: string | null;
  started_at: Date | null;
  finished_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

function iso(d: Date | null): string | null {
  return d ? new Date(d).toISOString() : null;
}

export function toJobSummary(row: ChangeJobRow, deviceName = ''): ChangeJobSummary {
  return {
    id: Number(row.id),
    uuid: row.uuid,
    tenantId: row.tenant_id,
    deviceId: row.device_id,
    deviceName,
    planId: row.plan_id === null ? null : Number(row.plan_id),
    kind: row.kind,
    status: row.status,
    attempt: row.attempt,
    safetyLevel: row.safety_level,
    safetyPeerDeviceId: row.safety_peer_device_id,
    // The type says `GuardVerdict`; the column is nullable for read-only kinds.
    // INDETERMINATE is the honest stand-in for "no guard was run", never ACCEPT.
    guardVerdict: row.guard_verdict ?? 'INDETERMINATE',
    guardReasons: [],
    overrideReason: row.override_reason,
    baseStateHash: row.base_state_hash,
    preflightBackupId: row.preflight_backup_id === null ? null : Number(row.preflight_backup_id),
    deadmanArmedAt: iso(row.deadman_armed_at),
    deadmanDisarmedAt: iso(row.deadman_disarmed_at),
    soakUntil: iso(row.soak_until),
    scheduledFor: iso(row.scheduled_for),
    windowStart: iso(row.window_start),
    windowEnd: iso(row.window_end),
    requestedBy: row.requested_by,
    startedAt: iso(row.started_at),
    finishedAt: iso(row.finished_at),
    errorKind: row.error_kind,
    errorMessage: row.error_message,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

/** The raw guard reasons as `mgmtPathGuard` produced them — richer than the
 *  shared `GuardReason` union (they carry a message, a culprit record and the
 *  plan line), which is why they are stored and returned as-is. */
export function guardReasonsOf(row: ChangeJobRow): unknown[] {
  const raw = row.guard_reasons;
  if (Array.isArray(raw)) return raw as unknown[];
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw) as unknown;
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

// ============================================================================
// Maintenance windows — `sites.maintenance_window`
// ============================================================================

/**
 * The shape migration 002 declared and left opaque:
 *   { days: ['mon','tue'] | [1,2], start: 'HH:MM', end: 'HH:MM', tz?: string }
 *
 * Both spellings of `days` are accepted (three-letter / full names, and 0-6
 * with 0 = Sunday, the JavaScript convention) because the column has been
 * writable since M2 with no validator in front of it, and a site whose window
 * was typed by hand must not become unpushable.
 */
export interface MaintenanceWindow {
  days?: Array<string | number> | null;
  start?: string | null;
  end?: string | null;
  tz?: string | null;
  enabled?: boolean | null;
}

const DAY_NAMES = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];

export type WindowVerdict =
  | { open: true; reason: null }
  | { open: false; reason: string };

const OPEN: WindowVerdict = { open: true, reason: null };

function parseHhMm(raw: string): number | null {
  const m = /^(\d{1,2}):(\d{2})$/.exec(raw.trim());
  if (!m) return null;
  const h = Number(m[1]);
  const min = Number(m[2]);
  if (h > 23 || min > 59) return null;
  return h * 60 + min;
}

/**
 * Is `at` inside the window, in the SITE's timezone?
 *
 * The site's timezone, never the server's: a French MSP administering a site in
 * Réunion has a maintenance window that means 02:00 there, and evaluating it in
 * Europe/Paris pushes to a live shop at 22:00.
 *
 * FAIL CLOSED. A window we cannot parse — a bad timezone, a malformed time, a
 * `days` array of objects — returns CLOSED with the reason. The job waits and
 * the log says why. "We could not tell whether this is a maintenance window" is
 * not permission to write during business hours.
 */
export function isWithinMaintenanceWindow(
  window: unknown,
  timezone: string | null,
  at: Date = new Date(),
): WindowVerdict {
  if (window === null || window === undefined) return OPEN;
  if (typeof window !== 'object' || Array.isArray(window)) {
    return { open: false, reason: 'maintenance_window is not an object' };
  }

  const w = window as MaintenanceWindow;
  if (w.enabled === false) return OPEN;

  const hasDays = Array.isArray(w.days) && w.days.length > 0;
  const hasTimes = typeof w.start === 'string' && typeof w.end === 'string';
  // An object with neither constraint is an empty window, i.e. no constraint.
  if (!hasDays && !hasTimes) return OPEN;

  const tz = (typeof w.tz === 'string' && w.tz) || timezone || 'UTC';

  let localDay: number;
  let localMinutes: number;
  try {
    const fmt = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      weekday: 'short',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
    const parts = fmt.formatToParts(at);
    const weekday = parts.find((p) => p.type === 'weekday')?.value?.toLowerCase() ?? '';
    const hour = Number(parts.find((p) => p.type === 'hour')?.value ?? NaN);
    const minute = Number(parts.find((p) => p.type === 'minute')?.value ?? NaN);
    localDay = DAY_NAMES.indexOf(weekday.slice(0, 3));
    // Intl renders midnight as "24" in some ICU versions under hour12:false.
    localMinutes = ((hour === 24 ? 0 : hour) * 60 + minute) | 0;
    if (localDay < 0 || !Number.isFinite(hour) || !Number.isFinite(minute)) {
      return { open: false, reason: `could not read the local time in timezone "${tz}"` };
    }
  } catch {
    return { open: false, reason: `invalid timezone "${tz}"` };
  }

  if (hasDays) {
    const allowed = new Set<number>();
    for (const raw of w.days as Array<string | number>) {
      if (typeof raw === 'number' && Number.isInteger(raw) && raw >= 0 && raw <= 6) {
        allowed.add(raw);
      } else if (typeof raw === 'string') {
        const idx = DAY_NAMES.indexOf(raw.trim().toLowerCase().slice(0, 3));
        if (idx < 0) return { open: false, reason: `unreadable day "${raw}" in maintenance_window` };
        allowed.add(idx);
      } else {
        return { open: false, reason: 'unreadable entry in maintenance_window.days' };
      }
    }
    if (!allowed.has(localDay)) {
      return { open: false, reason: `${DAY_NAMES[localDay]} is not a maintenance day (tz ${tz})` };
    }
  }

  if (!hasTimes) return OPEN;

  const start = parseHhMm(w.start as string);
  const end = parseHhMm(w.end as string);
  if (start === null || end === null) {
    return { open: false, reason: 'maintenance_window start/end are not HH:MM' };
  }
  if (start === end) return OPEN; // a zero-length window means "no time limit"

  // An overnight window (22:00 -> 06:00) wraps midnight. Getting this wrong is
  // how the one window an operator actually uses becomes permanently closed.
  const inside = start < end
    ? localMinutes >= start && localMinutes < end
    : localMinutes >= start || localMinutes < end;

  return inside
    ? OPEN
    : {
        open: false,
        reason: `outside the maintenance window ${w.start}-${w.end} (tz ${tz}, local ${String(
          Math.floor(localMinutes / 60),
        ).padStart(2, '0')}:${String(localMinutes % 60).padStart(2, '0')})`,
      };
}

// ============================================================================
// Claiming
// ============================================================================

interface Candidate {
  id: string | number;
  device_id: number;
  maintenance_window: unknown;
  timezone: string | null;
}

/** Sites whose window we have already complained about, so a permanently
 *  malformed window logs once per process instead of once per 3 seconds. */
const warnedWindows = new Set<number>();

/**
 * The rows a worker could claim RIGHT NOW, after the maintenance-window filter.
 *
 * Deliberately a separate, lock-free SELECT before the claim: the window lives
 * in a jsonb column on another table and is evaluated in a timezone, which is
 * not something to express in the pick query — and claiming first and releasing
 * after would burn an `attempt` on a job that never ran.
 */
async function eligibleJobIds(q: Knex | Knex.Transaction = db): Promise<number[]> {
  const rows = (await q('change_jobs as j')
    .join('devices as d', 'd.id', 'j.device_id')
    .leftJoin('sites as s', 's.id', 'd.site_id')
    .where('j.status', 'queued')
    .whereRaw('j.attempt < j.max_attempts')
    .whereRaw('(j.scheduled_for IS NULL OR j.scheduled_for <= now())')
    .whereRaw('(j.window_start IS NULL OR now() >= j.window_start)')
    .whereRaw('(j.window_end IS NULL OR now() < j.window_end)')
    .orderByRaw('j.scheduled_for NULLS FIRST, j.id')
    .limit(PICK_SCAN_LIMIT)
    .select(
      'j.id',
      'j.device_id',
      's.maintenance_window',
      's.timezone',
    )) as Candidate[];

  const now = new Date();
  const out: number[] = [];
  for (const row of rows) {
    const verdict = isWithinMaintenanceWindow(row.maintenance_window, row.timezone, now);
    if (verdict.open) {
      out.push(Number(row.id));
      continue;
    }
    if (!warnedWindows.has(row.device_id)) {
      warnedWindows.add(row.device_id);
      logger.info(
        { jobId: Number(row.id), deviceId: row.device_id, reason: verdict.reason },
        'change queue: job waiting for its maintenance window (it is NOT failed)',
      );
    }
  }
  return out;
}

/**
 * Take ONE job, atomically.
 *
 * `FOR UPDATE SKIP LOCKED` inside the CTE is what stops two workers taking the
 * same row: the second one skips the locked row instead of blocking on it, so
 * a busy queue never serialises into a single-file line. The UPDATE re-asserts
 * `status = 'queued'`, which is what makes a claim that lost the race return
 * zero rows rather than stealing a job somebody else already started.
 */
export async function claimNextJob(
  workerId: string = WORKER_ID,
  q: Knex | Knex.Transaction = db,
): Promise<ChangeJobRow | null> {
  const eligible = await eligibleJobIds(q);
  if (eligible.length === 0) return null;

  const result = (await q.raw(
    `
    WITH candidate AS (
      SELECT id
        FROM change_jobs
       WHERE status = 'queued'
         AND attempt < max_attempts
         AND id = ANY(?)
         AND (scheduled_for IS NULL OR scheduled_for <= now())
         AND (window_start IS NULL OR now() >= window_start)
         AND (window_end   IS NULL OR now() <  window_end)
       ORDER BY scheduled_for NULLS FIRST, id
       FOR UPDATE SKIP LOCKED
       LIMIT 1
    )
    UPDATE change_jobs j
       SET status           = 'claimed',
           claimed_by       = ?,
           claimed_at       = now(),
           lease_expires_at = now() + (? || ' milliseconds')::interval,
           attempt          = j.attempt + 1,
           started_at       = COALESCE(j.started_at, now()),
           updated_at       = now()
      FROM candidate c
     WHERE j.id = c.id
       AND j.status = 'queued'
    RETURNING j.*
    `,
    [eligible, workerId, String(LEASE_TTL_MS)],
  )) as { rows: ChangeJobRow[] };

  const row = result.rows[0] ?? null;
  if (row) {
    logger.info(
      { jobId: Number(row.id), deviceId: row.device_id, kind: row.kind, worker: workerId },
      'change queue: job claimed',
    );
    emitJob(row, SOCKET_EVENTS.JOB_STARTED);
  }
  return row;
}

/**
 * Push the lease out. Returns FALSE when this worker no longer owns the job —
 * the caller must then stop touching the device immediately: somebody else is,
 * or the row was reaped.
 */
export async function renewLease(
  jobId: number,
  workerId: string = WORKER_ID,
  q: Knex | Knex.Transaction = db,
): Promise<boolean> {
  const updated = await q('change_jobs')
    .where({ id: jobId, claimed_by: workerId })
    .whereNotIn('status', ['queued', 'succeeded', 'rolled_back', 'failed', 'aborted'])
    .update({
      lease_expires_at: db.raw(`now() + (? || ' milliseconds')::interval`, [String(LEASE_TTL_MS)]),
      updated_at: db.fn.now(),
    });
  return updated > 0;
}

/** Throwing form, for the phase boundaries inside `apply.service`. */
export async function assertLease(jobId: number, workerId: string = WORKER_ID): Promise<void> {
  if (!(await renewLease(jobId, workerId))) throw new LeaseLostError(jobId);
}

// ============================================================================
// Transitions
// ============================================================================

export interface TransitionPatch {
  outcome?: string | null;
  errorKind?: string | null;
  errorMessage?: string | null;
  preflightBackupId?: number | null;
  deadmanHandle?: string | null;
  deadmanArmedAt?: Date | null;
  deadmanDisarmedAt?: Date | null;
  confirmDeadline?: Date | null;
  soakUntil?: Date | null;
  safetyLevel?: SafetyLevel;
  safetyPeerDeviceId?: number | null;
  guardVerdict?: GuardVerdict;
  guardReasons?: unknown[];
}

/**
 * Move a job, refusing an edge the state machine does not have.
 *
 * `CHANGE_JOB_TRANSITIONS` is advisory in the database (no trigger enforces
 * it), so this function is where it becomes real for every path that goes
 * through the service — and every write path does, because D3 says so.
 */
export async function transitionJob(
  job: ChangeJobRow,
  to: ChangeJobStatus,
  patch: TransitionPatch = {},
  q: Knex | Knex.Transaction = db,
): Promise<ChangeJobRow> {
  if (job.status !== to && !canTransition(job.status, to)) {
    throw new InvalidTransitionError(job.status, to);
  }

  const update: Record<string, unknown> = { status: to, updated_at: db.fn.now() };

  if (patch.outcome !== undefined) update.outcome = patch.outcome;
  if (patch.errorKind !== undefined) update.error_kind = patch.errorKind;
  if (patch.errorMessage !== undefined) update.error_message = patch.errorMessage;
  if (patch.preflightBackupId !== undefined) update.preflight_backup_id = patch.preflightBackupId;
  if (patch.deadmanHandle !== undefined) update.deadman_handle = patch.deadmanHandle;
  if (patch.deadmanArmedAt !== undefined) update.deadman_armed_at = patch.deadmanArmedAt;
  if (patch.deadmanDisarmedAt !== undefined) update.deadman_disarmed_at = patch.deadmanDisarmedAt;
  if (patch.confirmDeadline !== undefined) update.confirm_deadline = patch.confirmDeadline;
  if (patch.soakUntil !== undefined) update.soak_until = patch.soakUntil;
  if (patch.safetyLevel !== undefined) update.safety_level = patch.safetyLevel;
  if (patch.safetyPeerDeviceId !== undefined) {
    update.safety_peer_device_id = patch.safetyPeerDeviceId;
  }
  if (patch.guardVerdict !== undefined) update.guard_verdict = patch.guardVerdict;
  if (patch.guardReasons !== undefined) {
    update.guard_reasons = JSON.stringify(patch.guardReasons);
  }

  // `change_jobs_finished_chk`: terminal IFF finished_at is set. Setting it
  // here rather than at each call site is what stops a 23514 from a forgotten
  // timestamp on the one path that matters (a failure).
  if (isTerminalJobStatus(to)) update.finished_at = db.fn.now();

  // `change_jobs_queued_unclaimed_chk`: a queued job holds nothing. And
  // `change_jobs_started_chk` forbids a `started_at` without a `claimed_at`,
  // so releasing the claim releases the start with it — which is also the
  // truth: the attempt that set it never got anywhere.
  if (to === 'queued') {
    update.claimed_by = null;
    update.claimed_at = null;
    update.lease_expires_at = null;
    update.started_at = null;
  }

  const rows = (await q('change_jobs')
    .where({ id: job.id })
    .update(update)
    .returning('*')) as ChangeJobRow[];
  const next = rows[0];

  emitTransition(next);
  return next;
}

function emitTransition(row: ChangeJobRow): void {
  switch (row.status) {
    case 'arming':
      emitJob(row, SOCKET_EVENTS.JOB_ARMED);
      break;
    case 'soaking':
      emitJob(row, SOCKET_EVENTS.JOB_SOAKING);
      break;
    case 'disarming':
      emitJob(row, SOCKET_EVENTS.JOB_DISARMED);
      break;
    case 'rolled_back':
      emitJob(row, SOCKET_EVENTS.JOB_ROLLED_BACK);
      emitJob(row, SOCKET_EVENTS.JOB_FINISHED);
      break;
    case 'succeeded':
    case 'failed':
    case 'aborted':
      emitJob(row, SOCKET_EVENTS.JOB_FINISHED);
      break;
    default:
      emitJob(row, SOCKET_EVENTS.JOB_STEP);
  }
}

// ============================================================================
// Steps — the ordered trace of what was ATTEMPTED
// ============================================================================

export interface StepHandle {
  id: number;
  jobId: number;
  seq: number;
  attempt: number;
  kind: ChangeStepKind;
  startedAt: number;
}

/**
 * Open a step. `(job, attempt, seq)` is unique, so a retry writes a SECOND
 * trace rather than overwriting the first — and the failed attempt is the
 * interesting one.
 */
export async function startStep(
  job: ChangeJobRow,
  seq: number,
  kind: ChangeStepKind,
  planOpSeq: number | null = null,
  q: Knex | Knex.Transaction = db,
): Promise<StepHandle> {
  const rows = (await q('change_job_steps')
    .insert({
      job_id: job.id,
      // Overwritten from the parent by `change_job_steps_tenant_sync`; supplied
      // anyway so the NOT NULL is satisfied without relying on the default.
      tenant_id: job.tenant_id,
      seq,
      attempt: job.attempt,
      kind,
      status: 'running',
      plan_op_seq: planOpSeq,
      started_at: db.fn.now(),
    })
    .returning('id')) as Array<{ id: string | number }>;

  const handle: StepHandle = {
    id: Number(rows[0].id),
    jobId: Number(job.id),
    seq,
    attempt: job.attempt,
    kind,
    startedAt: Date.now(),
  };
  emitStep(job, handle, 'running', null);
  return handle;
}

export async function finishStep(
  job: ChangeJobRow,
  handle: StepHandle,
  status: ChangeStepStatus,
  detail: {
    /** ALREADY REDACTED by the driver. This layer is not where secrets are
     *  removed — by the time a value reaches here it has been through a log. */
    output?: string | null;
    error?: string | null;
    detail?: Record<string, unknown>;
  } = {},
  q: Knex | Knex.Transaction = db,
): Promise<void> {
  const durationMs = Date.now() - handle.startedAt;
  await q('change_job_steps')
    .where({ id: handle.id })
    .update({
      status,
      finished_at: db.fn.now(),
      duration_ms: durationMs,
      output_redacted: detail.output ?? null,
      error_redacted: detail.error ?? null,
      detail_redacted: JSON.stringify(detail.detail ?? {}),
    });
  emitStep(job, handle, status, detail.error ?? null, durationMs);
}

/** A step that did NOT happen, recorded as a fact rather than as an absent row.
 *  "We did not arm a dead-man" must be visible in the trace. */
export async function skipStep(
  job: ChangeJobRow,
  seq: number,
  kind: ChangeStepKind,
  why: string,
  q: Knex | Knex.Transaction = db,
): Promise<void> {
  const handle = await startStep(job, seq, kind, null, q);
  await finishStep(job, handle, 'skipped', { output: why }, q);
}

function emitStep(
  job: ChangeJobRow,
  handle: StepHandle,
  status: ChangeStepStatus,
  error: string | null,
  durationMs?: number,
): void {
  const payload = {
    jobId: Number(job.id),
    stepId: handle.id,
    seq: handle.seq,
    attempt: handle.attempt,
    kind: handle.kind,
    status,
    errorRedacted: error,
    durationMs: durationMs ?? null,
  };
  emitToTenant(job.tenant_id, SOCKET_EVENTS.JOB_STEP, payload);
  emitToDevice(job.device_id, SOCKET_EVENTS.JOB_STEP, payload);
}

function emitJob(row: ChangeJobRow, event: string): void {
  const payload = toJobSummary(row);
  emitToTenant(row.tenant_id, event, payload);
  emitToDevice(row.device_id, event, payload);
}

// ============================================================================
// The reaper — crash recovery, property 3 and property 4
// ============================================================================

export interface ReapReport {
  requeued: number;
  failed: number;
  /** Jobs whose worker died AFTER bytes may have reached the router. Never
   *  touched, only counted and named. */
  needingInspection: number[];
}

/**
 * Return the devices held by dead workers.
 *
 * ┌─ THE FRONTIER, AND IT IS THE WHOLE POINT OF THE FINE-GRAINED STATUSES ────┐
 * │ claimed      -> queued. No I/O beyond an identity assertion has happened. │
 * │                `attempt` is DECREMENTED: the attempt did not occur, and   │
 * │                with `max_attempts = 1` (the default, because a write is   │
 * │                never retried silently) leaving it bumped would make the   │
 * │                job permanently unclaimable — a device locked for ever by  │
 * │                a process that crashed between two statements.             │
 * │ backing_up   -> failed. Nothing was written to the box, but a backup of   │
 * │                unknown completeness exists and R1's artefact must be      │
 * │                taken again from a clean start, not resumed.               │
 * │ arming       -> failed. NOTHING WAS APPLIED, BUT A DEAD-MAN MAY BE ARMED. │
 * │                The job is failed and `deadman_handle` names what is still │
 * │                on the router, so an operator can be TOLD.                 │
 * │ applying / verifying / soaking / disarming -> UNTOUCHED.                  │
 * │                Bytes may already be on a production router. Requeueing    │
 * │                here applies the same change twice and disarms a net this  │
 * │                process never armed. The on-box dead-man is the recovery   │
 * │                mechanism; ours is a human.                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function reapExpiredLeases(q: Knex | Knex.Transaction = db): Promise<ReapReport> {
  const report: ReapReport = { requeued: 0, failed: 0, needingInspection: [] };

  // 1. `claimed` — the only backward edge in the state machine.
  const requeued = (await q('change_jobs')
    .where('status', 'claimed')
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'queued',
      claimed_by: null,
      claimed_at: null,
      lease_expires_at: null,
      // `change_jobs_started_chk` is `started_at IS NULL OR claimed_at IS NOT
      // NULL`, and clearing the claim without clearing the start would violate
      // it. The constraint is right and the semantics agree with it: a job
      // whose worker died before touching anything did not start.
      started_at: null,
      attempt: db.raw('GREATEST(attempt - 1, 0)'),
      updated_at: db.fn.now(),
    })
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  report.requeued = requeued.length;
  for (const r of requeued) {
    logger.warn(
      { jobId: Number(r.id), deviceId: r.device_id },
      'change queue: lease expired on a CLAIMED job — requeued (no device I/O had happened)',
    );
  }

  // 2. `backing_up` / `arming` — recoverable, but not resumable.
  for (const status of ['backing_up', 'arming'] as const) {
    const failed = (await q('change_jobs')
      .where('status', status)
      .whereNotNull('lease_expires_at')
      .whereRaw('lease_expires_at < now()')
      .update({
        status: 'failed',
        finished_at: db.fn.now(),
        error_kind: 'worker_lost',
        error_message:
          status === 'arming'
            ? 'The worker died while installing the safety net. NOTHING WAS APPLIED, but a ' +
              'dead-man may still be armed on the device — check deadman_handle before retrying.'
            : 'The worker died while taking the pre-change backup. Nothing was applied. ' +
              'Recompile the plan and start again.',
        updated_at: db.fn.now(),
      })
      .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
    report.failed += failed.length;
    for (const r of failed) {
      logger.error(
        { jobId: Number(r.id), deviceId: r.device_id, status },
        'change queue: lease expired before the write — job failed, device released',
      );
    }
  }

  // 3. Past the frontier. COUNTED AND NAMED, NEVER TOUCHED.
  const stuck = (await q('change_jobs')
    .whereIn('status', [...WRITE_COMMITTED_STATUSES])
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .select('id', 'device_id', 'status')) as Array<{
    id: string | number;
    device_id: number;
    status: string;
  }>;
  report.needingInspection = stuck.map((r) => Number(r.id));
  for (const r of stuck) {
    logger.error(
      { jobId: Number(r.id), deviceId: r.device_id, status: r.status },
      'change queue: a job whose worker died AFTER the write began. NOT requeued and NOT failed ' +
        '— it needs human inspection. The on-box dead-man is the recovery path.',
    );
  }

  return report;
}

// ============================================================================
// Reads
// ============================================================================

export interface JobQuery {
  deviceId?: number;
  status?: ChangeJobStatus[];
  activeOnly?: boolean;
  limit?: number;
  offset?: number;
}

/**
 * `ChangeJobSummary` with the guard's OWN reason objects rather than the bare
 * `GuardReason` codes. The UI needs the message, the offending record and the
 * plan line it came from; a code on its own is "we refused" with nothing an
 * operator can act on.
 */
export type ChangeJobView = Omit<ChangeJobSummary, 'guardReasons'> & { guardReasons: unknown[] };

export async function listJobs(
  tenantId: number,
  query: JobQuery = {},
): Promise<{ rows: ChangeJobView[]; total: number }> {
  const limit = Math.min(Math.max(query.limit ?? 50, 1), 200);
  const offset = Math.max(query.offset ?? 0, 0);

  const base = () => {
    const q = db('change_jobs as j').where('j.tenant_id', tenantId);
    if (query.deviceId) void q.where('j.device_id', query.deviceId);
    if (query.status?.length) void q.whereIn('j.status', query.status);
    if (query.activeOnly) void q.whereIn('j.status', [...ACTIVE_CHANGE_JOB_STATUSES]);
    return q;
  };

  const [{ count }] = (await base().count({ count: '*' })) as Array<{ count: string }>;
  const rows = (await base()
    .leftJoin('devices as d', 'd.id', 'j.device_id')
    .orderBy('j.created_at', 'desc')
    .orderBy('j.id', 'desc')
    .limit(limit)
    .offset(offset)
    .select('j.*', 'd.name as device_name')) as Array<ChangeJobRow & { device_name: string | null }>;

  return {
    rows: rows.map((r) => ({
      ...toJobSummary(r, r.device_name ?? ''),
      guardReasons: guardReasonsOf(r),
    })),
    total: Number(count),
  };
}

/** Tenant-scoped by construction: a job of another tenant reads as absent. */
export async function getJobRow(
  tenantId: number,
  jobId: number,
  q: Knex | Knex.Transaction = db,
): Promise<(ChangeJobRow & { device_name: string | null }) | null> {
  const row = (await q('change_jobs as j')
    .leftJoin('devices as d', 'd.id', 'j.device_id')
    .where({ 'j.id': jobId, 'j.tenant_id': tenantId })
    .first('j.*', 'd.name as device_name')) as
    | (ChangeJobRow & { device_name: string | null })
    | undefined;
  return row ?? null;
}

export async function listJobSteps(
  tenantId: number,
  jobId: number,
): Promise<Array<Record<string, unknown>>> {
  const rows = (await db('change_job_steps')
    .where({ job_id: jobId, tenant_id: tenantId })
    .orderBy('attempt')
    .orderBy('seq')
    .select('*')) as Array<Record<string, unknown>>;

  return rows.map((r) => ({
    id: Number(r.id),
    jobId: Number(r.job_id),
    seq: r.seq,
    attempt: r.attempt,
    kind: r.kind,
    status: r.status,
    planOpSeq: r.plan_op_seq,
    startedAt: r.started_at ? new Date(r.started_at as Date).toISOString() : null,
    finishedAt: r.finished_at ? new Date(r.finished_at as Date).toISOString() : null,
    durationMs: r.duration_ms,
    outputRedacted: r.output_redacted,
    errorRedacted: r.error_redacted,
  }));
}

// ============================================================================
// Abort
// ============================================================================

/**
 * Cancel a job that has NOT started writing.
 *
 * `aborted` is unreachable from `applying` onward, in the state machine and
 * here: you cannot cancel a change that is already going onto a router. You can
 * only let the machinery finish or let the dead-man fire. A route that offered
 * "abort" on an applying job would be offering a button that does nothing, at
 * the exact moment somebody is desperate enough to press it twice.
 */
export async function abortJob(
  tenantId: number,
  jobId: number,
  userId: number | null,
  reason: string | null,
): Promise<ChangeJobRow> {
  const job = await getJobRow(tenantId, jobId);
  if (!job) throw new Error(`Change job ${jobId} not found`);
  if (!canTransition(job.status, 'aborted')) {
    throw new InvalidTransitionError(job.status, 'aborted');
  }
  return transitionJob(job, 'aborted', {
    errorKind: 'aborted',
    errorMessage:
      `Aborted by user ${userId ?? 'unknown'}` + (reason ? `: ${reason}` : '') +
      '. Nothing had been written to the device.',
  });
}

// ============================================================================
// The worker
// ============================================================================

export type JobRunner = (job: ChangeJobRow) => Promise<void>;

let timer: NodeJS.Timeout | null = null;
let runner: JobRunner | null = null;
let armed = false;
const inFlight = new Set<number>();

/**
 * Should THIS process take jobs?
 *
 * Arbitrage A5, with the one deliberate asymmetry the brief asks for: a
 * dedicated `worker` role processes jobs whether or not it holds the leadership
 * lock, because several workers side by side is precisely the deployment
 * `FOR UPDATE SKIP LOCKED` exists for. An `all` process must win the election
 * first — otherwise two `docker compose up` on the same database would both
 * push to the same fleet, which is the failure A5 was written to prevent.
 *
 * A `web` replica never reaches here: `config.runsBackground` is false and
 * `startChangeWorker` returns before arming anything.
 */
export function shouldProcessJobs(): boolean {
  if (!config.runsBackground) return false;
  return config.role === 'worker' || leaderElection.isLeader();
}

export function startChangeWorker(jobRunner: JobRunner): void {
  if (armed) return;
  runner = jobRunner;

  if (!config.runsBackground) {
    logger.info(
      { role: config.role },
      'Change queue: not armed (OBLIWAN_ROLE=web serves HTTP only) — no write will originate here',
    );
    return;
  }

  armed = true;
  timer = setInterval(() => {
    void tick();
  }, POLL_INTERVAL_MS);
  // A queue must never be the reason the process refuses to exit.
  timer.unref();

  logger.info(
    { worker: WORKER_ID, role: config.role, concurrency: MAX_CONCURRENT_JOBS },
    'Change queue armed — this process may now write to equipment through change_jobs',
  );
}

/**
 * Stop taking new work. In-flight jobs are AWAITED, not cancelled: killing a
 * session mid-apply is how a half-configured router happens. If they outlast
 * the grace period the process exits anyway and their leases expire, which is
 * the crash path — and the crash path is safe by construction (see the reaper).
 */
export async function stopChangeWorker(graceMs = 8_000): Promise<void> {
  armed = false;
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  const deadline = Date.now() + graceMs;
  while (inFlight.size > 0 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 200));
  }
  if (inFlight.size > 0) {
    logger.warn(
      { jobs: [...inFlight] },
      'Change queue: shutting down with jobs still in flight — their leases will expire and the ' +
        'reaper will classify them. Nothing is requeued past the write frontier.',
    );
  }
  logger.info('Change queue stopped');
}

/** One poll: reap, then fill the free slots. Exported for the tests, which must
 *  be able to drive the queue without a 3-second wall clock. */
export async function tick(): Promise<void> {
  if (!armed || !runner) return;
  if (!shouldProcessJobs()) return;

  try {
    await reapExpiredLeases();
  } catch (err) {
    logger.error(err, 'Change queue: the reaper failed this tick');
  }

  while (inFlight.size < MAX_CONCURRENT_JOBS && armed && shouldProcessJobs()) {
    let job: ChangeJobRow | null = null;
    try {
      job = await claimNextJob();
    } catch (err) {
      logger.error(err, 'Change queue: claim failed');
      return;
    }
    if (!job) return;

    const id = Number(job.id);
    inFlight.add(id);
    const currentRunner = runner;
    void currentRunner(job)
      .catch((err) => {
        // `runJob` is written not to throw; this is the net under the net.
        logger.error({ err, jobId: id }, 'Change queue: the runner threw — job left as it stands');
      })
      .finally(() => {
        inFlight.delete(id);
      });
  }
}

export function inFlightJobIds(): number[] {
  return [...inFlight];
}

export const jobQueue = {
  WORKER_ID,
  claimNextJob,
  renewLease,
  assertLease,
  transitionJob,
  startStep,
  finishStep,
  skipStep,
  reapExpiredLeases,
  listJobs,
  getJobRow,
  listJobSteps,
  abortJob,
  startChangeWorker,
  stopChangeWorker,
  tick,
  shouldProcessJobs,
  isWithinMaintenanceWindow,
  inFlightJobIds,
};

/** Re-exported so a caller need not import `@obliwan/shared` to ask the one
 *  question that decides whether a job may be retried at all. */
export { isWriteJobKind };
