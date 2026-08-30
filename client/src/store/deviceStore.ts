import { create } from 'zustand';
import type { ReachabilityVerdict, SitePresenceEvent } from '@obliwan/shared';
import type { Device, DevicePresence } from '@/types/fleet';
import { devicesApi, type DeviceListParams } from '@/api/devices.api';

/**
 * Live presence overlay.
 *
 * `wan:site:presence` / `wan:device:presence` arrive faster than any refetch,
 * so the socket writes here and the table reads `presenceOf()`, which layers
 * the socket value over whatever the last HTTP response carried. The list is
 * never re-fetched on a presence event — that is the whole point of the
 * sub-2 s acceptance criterion.
 */
export interface FleetFilters {
  search: string;
  brand: string;
  model: string;
  status: string;
  role: string;
  siteId: number | null;
}

export const EMPTY_FILTERS: FleetFilters = {
  search: '',
  brand: '',
  model: '',
  status: '',
  role: '',
  siteId: null,
};

/** Aggregated presence of one site, computed from its devices. */
export interface SitePresenceRollup {
  total: number;
  up: number;
  down: number;
  /** Devices whose state is genuinely unknown — NOT counted as down. */
  unknown: number;
  /** Worst verdict currently observed on the site, or null when nothing is known. */
  worstVerdict: ReachabilityVerdict | null;
}

/**
 * Severity order for rolling several device verdicts up to one site pastille.
 * `UNREACHABLE` sits ABOVE `UP` but BELOW every positive-knowledge outage: a
 * blind observer is a problem worth showing, and it is not an outage.
 */
const VERDICT_SEVERITY: Record<ReachabilityVerdict, number> = {
  UP: 0,
  WAN_FAILOVER: 1,
  UNREACHABLE: 2,
  TUNNEL_DOWN_SITE_UP: 3,
  CONCENTRATOR_DEGRADED: 4,
  SITE_DOWN: 5,
};

export function verdictSeverity(v: ReachabilityVerdict): number {
  return VERDICT_SEVERITY[v] ?? 0;
}

interface DeviceStore {
  devices: Device[];
  isLoading: boolean;
  loadError: string | null;
  /** deviceId → live presence pushed over the socket. */
  presence: Record<number, DevicePresence>;
  filters: FleetFilters;

  fetchDevices: (params?: DeviceListParams) => Promise<void>;
  setFilters: (patch: Partial<FleetFilters>) => void;
  resetFilters: () => void;

  upsertDevice: (device: Device) => void;
  removeDevice: (deviceId: number) => void;

  /** Fold a `wan:site:presence` / `wan:device:presence` payload into the store. */
  applyPresenceEvent: (event: SitePresenceEvent) => void;
  /** Fold a `wan:device:reachability` payload (verdict only, no up/down flip). */
  applyReachability: (payload: { deviceId: number; verdict: ReachabilityVerdict; ts?: string }) => void;

  presenceOf: (device: Device) => DevicePresence | null;
  presenceById: (deviceId: number) => DevicePresence | null;
  siteRollup: (siteId: number) => SitePresenceRollup;
  getDevice: (id: number) => Device | undefined;
}

export const useDeviceStore = create<DeviceStore>((set, get) => ({
  devices: [],
  isLoading: false,
  loadError: null,
  presence: {},
  filters: { ...EMPTY_FILTERS },

  fetchDevices: async (params) => {
    set({ isLoading: true, loadError: null });
    try {
      const devices = await devicesApi.list(params);
      set({ devices, isLoading: false });
    } catch (err) {
      const message =
        (err as { response?: { data?: { error?: string } } }).response?.data?.error ??
        (err as Error).message;
      set({ isLoading: false, loadError: message ?? 'unknown error' });
    }
  },

  setFilters: (patch) => set((s) => ({ filters: { ...s.filters, ...patch } })),
  resetFilters: () => set({ filters: { ...EMPTY_FILTERS } }),

  upsertDevice: (device) =>
    set((s) => {
      const idx = s.devices.findIndex((d) => d.id === device.id);
      if (idx === -1) return { devices: [...s.devices, device] };
      const devices = s.devices.slice();
      devices[idx] = { ...devices[idx], ...device };
      return { devices };
    }),

  removeDevice: (deviceId) =>
    set((s) => {
      const presence = { ...s.presence };
      delete presence[deviceId];
      return { devices: s.devices.filter((d) => d.id !== deviceId), presence };
    }),

  applyPresenceEvent: (event) => {
    // A session for a username that is not bound to any device yet still has
    // meaning (it feeds the discovery queue) but has nothing to colour here.
    if (event.deviceId == null) return;
    set((s) => ({
      presence: {
        ...s.presence,
        [event.deviceId as number]: {
          up: event.up,
          verdict: event.verdict,
          at: event.at,
          tunnelIp: event.tunnelIp,
          callerIp: event.callerIp,
        },
      },
    }));
  },

  applyReachability: ({ deviceId, verdict, ts }) =>
    set((s) => {
      const previous = s.presence[deviceId];
      return {
        presence: {
          ...s.presence,
          [deviceId]: {
            // A verdict change alone never invents an up/down transition:
            // whatever PPP last said stays, `null` included.
            up: previous?.up ?? null,
            verdict,
            at: ts ?? previous?.at ?? null,
            tunnelIp: previous?.tunnelIp ?? null,
            callerIp: previous?.callerIp ?? null,
          },
        },
      };
    }),

  presenceOf: (device) => get().presence[device.id] ?? device.presence ?? null,

  presenceById: (deviceId) => {
    const live = get().presence[deviceId];
    if (live) return live;
    return get().devices.find((d) => d.id === deviceId)?.presence ?? null;
  },

  siteRollup: (siteId) => {
    const { devices, presence } = get();
    const rollup: SitePresenceRollup = {
      total: 0,
      up: 0,
      down: 0,
      unknown: 0,
      worstVerdict: null,
    };
    for (const device of devices) {
      if (device.siteId !== siteId) continue;
      rollup.total += 1;
      const p = presence[device.id] ?? device.presence ?? null;
      if (!p || p.up === null) {
        rollup.unknown += 1;
      } else if (p.up) {
        rollup.up += 1;
      } else {
        rollup.down += 1;
      }
      // A device with no verdict on record contributes NOTHING to the site
      // pastille. It is already counted in `unknown` above; letting it also
      // stand in as some default verdict would either invent an outage or
      // paint over a real one.
      if (p && p.verdict !== null) {
        if (
          rollup.worstVerdict === null ||
          verdictSeverity(p.verdict) > verdictSeverity(rollup.worstVerdict)
        ) {
          rollup.worstVerdict = p.verdict;
        }
      }
    }
    return rollup;
  },

  getDevice: (id) => get().devices.find((d) => d.id === id),
}));
