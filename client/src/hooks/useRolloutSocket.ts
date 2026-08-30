import { useEffect, useRef } from 'react';
import { CLIENT_EVENTS, SOCKET_EVENTS } from '@obliwan/shared';
import { getSocket } from '@/socket/socketClient';
import { normalizeRollout, normalizeWave } from '@/api/rollout.api';
import type { RolloutView, RolloutWaveView } from '@/types/rollout';

/**
 * Live `wan:rollout:*` subscription (M7, killer K3).
 *
 * ── SAME CONTRACT AS `useJobSocket`, FOR THE SAME REASON ────────────────────
 * `shared/src/socketEvents.ts` declares event NAMES only — it is that file's
 * convention. So this hook accepts BOTH frame shapes: a bare row, or a row
 * wrapped in `{ rollout }` / `{ wave }`. Both go through the same
 * `normalizeRollout` / `normalizeWave` the HTTP layer uses, which means every
 * pessimistic rule (an unknown status becomes `failed`, an unknown gate state
 * becomes `unknown` and `unknown` is not a pass) applies to socket frames too.
 * A socket path that skipped those normalisers would be a second, laxer door
 * into the same screen.
 *
 * ── SUBSCRIPTION IS PER `rolloutId`, AS THE MILESTONE ASKS ──────────────────
 * §5/M7: "progression Socket.io par `rolloutId`". Wave-level frames go to the
 * `rollout:{id}` room (`socketRooms.rollout`), so the detail screen joins it
 * explicitly with `wan:rollout:subscribe`. The LIST screen passes no id and
 * relies on the tenant room it is already in — otherwise watching a list would
 * mean joining forty rooms.
 *
 * The unsubscribe on unmount is not politeness: a rollout pushes a frame per
 * device per wave, and leaving rooms joined after a night of browsing means a
 * tab nobody is looking at receives every one of them.
 */

export interface RolloutSocketHandlers {
  /** Any frame carrying a rollout row: progress, finished. */
  onRollout?: (rollout: RolloutView) => void;
  /** `wan:rollout:wave` — a wave changed state, gates included. */
  onWave?: (wave: RolloutWaveView) => void;
  /** Terminal frame. NOT necessarily a success: a halted rollout finishes too,
   *  and `status` is the only thing that says which happened. */
  onFinished?: (rollout: RolloutView) => void;
  /** Join `rollout:{id}` so wave frames arrive. Omit on list screens. */
  rolloutId?: number;
}

type Raw = Record<string, unknown>;

function rolloutOf(payload: unknown): RolloutView | null {
  if (!payload || typeof payload !== 'object') return null;
  const row = payload as Raw;
  const inner = (row.rollout ?? row) as Raw;
  if (typeof inner !== 'object' || inner === null) return null;
  const rollout = normalizeRollout(inner);
  // A frame with no id cannot be folded into a list without corrupting it.
  // Dropping it beats inserting a phantom row 0.
  return rollout.id > 0 ? rollout : null;
}

function waveOf(payload: unknown): RolloutWaveView | null {
  if (!payload || typeof payload !== 'object') return null;
  const row = payload as Raw;
  const inner = (row.wave ?? row) as Raw;
  if (typeof inner !== 'object' || inner === null) return null;
  return normalizeWave(inner);
}

export function useRolloutSocket(handlers: RolloutSocketHandlers): void {
  // Handlers live in a ref so inline closures do not re-subscribe on every
  // render — which on the detail page would mean leaving and rejoining the
  // rollout room several times a second.
  const ref = useRef(handlers);
  ref.current = handlers;

  const { rolloutId } = handlers;

  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;

    const onProgress = (p: unknown) => {
      const rollout = rolloutOf(p);
      if (rollout) ref.current.onRollout?.(rollout);
      // A progress frame may carry the wave that moved alongside it; fold it so
      // the wave strip does not lag the header by one event.
      const wave = p && typeof p === 'object' && (p as Raw).wave ? waveOf(p) : null;
      if (wave) ref.current.onWave?.(wave);
    };

    const onWave = (p: unknown) => {
      const wave = waveOf(p);
      if (wave) ref.current.onWave?.(wave);
      if (p && typeof p === 'object' && (p as Raw).rollout) {
        const rollout = rolloutOf(p);
        if (rollout) ref.current.onRollout?.(rollout);
      }
    };

    const onFinished = (p: unknown) => {
      const rollout = rolloutOf(p);
      if (!rollout) return;
      ref.current.onRollout?.(rollout);
      ref.current.onFinished?.(rollout);
    };

    socket.on(SOCKET_EVENTS.ROLLOUT_PROGRESS, onProgress);
    socket.on(SOCKET_EVENTS.ROLLOUT_WAVE_CHANGED, onWave);
    socket.on(SOCKET_EVENTS.ROLLOUT_FINISHED, onFinished);

    if (typeof rolloutId === 'number' && rolloutId > 0) {
      socket.emit(CLIENT_EVENTS.ROLLOUT_SUBSCRIBE, { rolloutId });
    }

    return () => {
      socket.off(SOCKET_EVENTS.ROLLOUT_PROGRESS, onProgress);
      socket.off(SOCKET_EVENTS.ROLLOUT_WAVE_CHANGED, onWave);
      socket.off(SOCKET_EVENTS.ROLLOUT_FINISHED, onFinished);
      if (typeof rolloutId === 'number' && rolloutId > 0) {
        socket.emit(CLIENT_EVENTS.ROLLOUT_UNSUBSCRIBE, { rolloutId });
      }
    };
  }, [rolloutId]);
}
