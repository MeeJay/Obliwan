import { create } from 'zustand';
import type { PlanConfig } from '@/types/change';
import type { KillSwitchView } from '@/types/change';
import { changeApi, KILL_SWITCH_FAIL_CLOSED, normalizeKillSwitch } from '@/api/change.api';
import { planApi, PLAN_CONFIG_FAIL_CLOSED } from '@/api/plan.api';

/**
 * The two facts every apply control in this client is gated on.
 *
 * They live in a store rather than in each page's state for one reason: the
 * kill switch must be able to drop every Apply button in the application from a
 * single socket frame (`wan:killSwitch:changed`), whatever page the operator is
 * on. A per-page fetch would leave a stale Apply button live on a screen
 * somebody opened five minutes ago — which is precisely the click the kill
 * switch exists to prevent.
 *
 * ── BOTH DEFAULTS ARE THE REFUSING ONES ─────────────────────────────────────
 * The store starts at `canApply: false` and `killSwitch.blocked: true`, and
 * both fetchers fall back to those values on any error. Before the first
 * successful read, this client will not offer to write to anything. That is
 * the correct behaviour for a boot sequence and for a server that is down:
 * "un plan bloqué coûte une réunion ; un site coupé coûte un camion".
 *
 * `killSwitchKnown` is separate from `blocked` on purpose. "Engaged because an
 * operator engaged it" and "treated as engaged because we could not read it"
 * are two different sentences on screen, and collapsing them would teach
 * operators to ignore the banner.
 */
interface ChangeStore {
  planConfig: PlanConfig;
  planConfigLoaded: boolean;

  killSwitch: KillSwitchView;
  killSwitchLoading: boolean;

  fetchPlanConfig: () => Promise<void>;
  fetchKillSwitch: () => Promise<void>;
  /** Applied from the `wan:killSwitch:changed` frame — no refetch, so the
   *  buttons drop in the same tick the switch flips. */
  applyKillSwitchEvent: (payload: unknown) => void;
  setKillSwitch: (engaged: boolean, reason: string) => Promise<void>;

  /** The single predicate every screen asks before rendering a write control.
   *  It answers the whole question: the server can apply, and nothing is
   *  currently stopping the world. */
  writesAllowed: () => boolean;
}

export const useChangeStore = create<ChangeStore>((set, get) => ({
  planConfig: PLAN_CONFIG_FAIL_CLOSED,
  planConfigLoaded: false,

  killSwitch: KILL_SWITCH_FAIL_CLOSED,
  killSwitchLoading: false,

  fetchPlanConfig: async () => {
    // `planApi.config()` never throws and never returns canApply on an error.
    const planConfig = await planApi.config();
    set({ planConfig, planConfigLoaded: true });
  },

  fetchKillSwitch: async () => {
    set({ killSwitchLoading: true });
    const killSwitch = await changeApi.killSwitch();
    set({ killSwitch, killSwitchLoading: false });
  },

  applyKillSwitchEvent: (payload) => {
    set({ killSwitch: normalizeKillSwitch(payload) });
  },

  setKillSwitch: async (engaged, reason) => {
    set({ killSwitchLoading: true });
    try {
      const killSwitch = await changeApi.setKillSwitch(engaged, reason);
      set({ killSwitch, killSwitchLoading: false });
    } catch (err) {
      // A failed RELEASE leaves the switch engaged, which is the safe side and
      // is what the server still believes. A failed ENGAGE is the dangerous
      // one: the operator pressed the panic button and it did not take. We
      // re-read rather than assume, and we re-throw so the caller shouts.
      set({ killSwitchLoading: false });
      await get().fetchKillSwitch();
      throw err;
    }
  },

  writesAllowed: () => {
    const { planConfig, killSwitch } = get();
    return planConfig.canApply && !killSwitch.blocked;
  },
}));
