import { useEffect, useRef } from 'react';
import { CLIENT_EVENTS, SOCKET_EVENTS } from '@obliwan/shared';
import { getSocket } from '@/socket/socketClient';
import { normalizeJob, normalizeStep } from '@/api/change.api';
import type { ChangeJobStepView, ChangeJobView } from '@/types/change';

/**
 * Live `wan:job:*` subscription.
 *
 * ── THE PAYLOAD SHAPES ARE NOT DECLARED ANYWHERE ────────────────────────────
 * `shared/src/socketEvents.ts` declares event NAMES only — that is the file's
 * convention and the M6 schema agent left it that way deliberately. So this
 * hook accepts BOTH shapes for every frame: a bare row, or a row wrapped in
 * `{ job }` / `{ step }`. Both go through the same `normalizeJob` /
 * `normalizeStep` used by the HTTP layer, which means every fail-closed rule
 * (unknown status becomes `failed`, unknown safety level becomes `degraded`,
 * unknown verdict becomes `INDETERMINATE`) applies to socket frames too. A
 * socket path that skipped those normalisers would be a second, laxer door into
 * the same screen.
 *
 * ── WHY THE THREE NET EVENTS ARE HANDLED SEPARATELY ─────────────────────────
 * `JOB_ARMED`, `JOB_SOAKING` and `JOB_DISARMED` carry the same job row as the
 * generic frames, but they are the three moments the operator is actually
 * waiting for: a net now exists on the box, the change is live and being
 * watched, the net has been removed. They get their own callback so a screen
 * can react to them (a countdown starting, a banner clearing) without
 * pattern-matching on a status string.
 *
 * ── SUBSCRIPTION ────────────────────────────────────────────────────────────
 * Step-level frames are emitted into the `job:{id}` room, so the detail screen
 * must join it explicitly (`wan:job:subscribe`). The list screen passes no
 * `jobId` and relies on the tenant room it is already in. The unsubscribe on
 * unmount is not politeness: leaving a hundred job rooms joined after a night
 * of browsing means every step of every job is pushed to a tab nobody is
 * looking at.
 */

export interface JobSocketHandlers {
  /** Any frame carrying a job row: queued, started, armed, soaking, disarmed,
   *  finished, rolledBack. */
  onJob?: (job: ChangeJobView) => void;
  /** `wan:job:step`. */
  onStep?: (step: ChangeJobStepView) => void;
  /** The dead-man was installed. Carries the level ACTUALLY obtained. */
  onArmed?: (job: ChangeJobView) => void;
  /** Applied and verified; the soak clock is running and the net is still on. */
  onSoaking?: (job: ChangeJobView) => void;
  /** The dead-man has been removed and confirmed gone. */
  onDisarmed?: (job: ChangeJobView) => void;
  /** The dead-man fired and the device restored itself. NOT an error. */
  onRolledBack?: (job: ChangeJobView) => void;
  /** Join `job:{id}` so step frames arrive. Omit on list screens. */
  jobId?: number;
}

type Raw = Record<string, unknown>;

function jobOf(payload: unknown): ChangeJobView | null {
  if (!payload || typeof payload !== 'object') return null;
  const row = payload as Raw;
  const inner = (row.job ?? row) as Raw;
  if (typeof inner !== 'object' || inner === null) return null;
  const job = normalizeJob(inner);
  // A frame with no id is a frame we cannot fold into a list without
  // corrupting it. Dropping it is better than inserting a phantom row 0.
  return job.id > 0 ? job : null;
}

function stepOf(payload: unknown): ChangeJobStepView | null {
  if (!payload || typeof payload !== 'object') return null;
  const row = payload as Raw;
  const inner = (row.step ?? row) as Raw;
  if (typeof inner !== 'object' || inner === null) return null;
  return normalizeStep(inner);
}

export function useJobSocket(handlers: JobSocketHandlers): void {
  // Handlers are kept in a ref so a caller passing inline closures does not
  // re-subscribe on every render — which, on the detail page, would mean
  // leaving and rejoining the job room several times a second.
  const ref = useRef(handlers);
  ref.current = handlers;

  const { jobId } = handlers;

  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;

    const emitJob = (payload: unknown, extra?: (j: ChangeJobView) => void) => {
      const job = jobOf(payload);
      if (!job) return;
      ref.current.onJob?.(job);
      extra?.(job);
    };

    const onQueued = (p: unknown) => emitJob(p);
    const onStarted = (p: unknown) => emitJob(p);
    const onFinished = (p: unknown) => emitJob(p);
    const onArmed = (p: unknown) => emitJob(p, (j) => ref.current.onArmed?.(j));
    const onSoaking = (p: unknown) => emitJob(p, (j) => ref.current.onSoaking?.(j));
    const onDisarmed = (p: unknown) => emitJob(p, (j) => ref.current.onDisarmed?.(j));
    const onRolledBack = (p: unknown) => emitJob(p, (j) => ref.current.onRolledBack?.(j));
    const onStep = (p: unknown) => {
      const step = stepOf(p);
      if (step) ref.current.onStep?.(step);
      // A step frame may carry the whole job alongside it; fold it if present
      // so the header status does not lag the timeline by one event.
      if (p && typeof p === 'object' && (p as Raw).job) emitJob(p);
    };

    socket.on(SOCKET_EVENTS.JOB_QUEUED, onQueued);
    socket.on(SOCKET_EVENTS.JOB_STARTED, onStarted);
    socket.on(SOCKET_EVENTS.JOB_STEP, onStep);
    socket.on(SOCKET_EVENTS.JOB_ARMED, onArmed);
    socket.on(SOCKET_EVENTS.JOB_SOAKING, onSoaking);
    socket.on(SOCKET_EVENTS.JOB_DISARMED, onDisarmed);
    socket.on(SOCKET_EVENTS.JOB_FINISHED, onFinished);
    socket.on(SOCKET_EVENTS.JOB_ROLLED_BACK, onRolledBack);

    if (typeof jobId === 'number' && jobId > 0) {
      socket.emit(CLIENT_EVENTS.JOB_SUBSCRIBE, { jobId });
    }

    return () => {
      socket.off(SOCKET_EVENTS.JOB_QUEUED, onQueued);
      socket.off(SOCKET_EVENTS.JOB_STARTED, onStarted);
      socket.off(SOCKET_EVENTS.JOB_STEP, onStep);
      socket.off(SOCKET_EVENTS.JOB_ARMED, onArmed);
      socket.off(SOCKET_EVENTS.JOB_SOAKING, onSoaking);
      socket.off(SOCKET_EVENTS.JOB_DISARMED, onDisarmed);
      socket.off(SOCKET_EVENTS.JOB_FINISHED, onFinished);
      socket.off(SOCKET_EVENTS.JOB_ROLLED_BACK, onRolledBack);
      if (typeof jobId === 'number' && jobId > 0) {
        socket.emit(CLIENT_EVENTS.JOB_UNSUBSCRIBE, { jobId });
      }
    };
  }, [jobId]);
}
