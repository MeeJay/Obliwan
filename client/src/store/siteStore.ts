import { create } from 'zustand';
import type { Site } from '@/types/fleet';
import { sitesApi } from '@/api/sites.api';

interface SiteStore {
  sites: Site[];
  isLoading: boolean;
  loadError: string | null;
  /** Set once the first fetch has resolved, so a genuinely empty fleet reads
   *  differently from "not loaded yet" in the sidebar tree. */
  loaded: boolean;

  fetchSites: () => Promise<void>;
  upsertSite: (site: Site) => void;
  removeSite: (siteId: number) => void;
  getSite: (id: number) => Site | undefined;
}

export const useSiteStore = create<SiteStore>((set, get) => ({
  sites: [],
  isLoading: false,
  loadError: null,
  loaded: false,

  fetchSites: async () => {
    set({ isLoading: true, loadError: null });
    try {
      const sites = await sitesApi.list();
      set({ sites, isLoading: false, loaded: true });
    } catch (err) {
      const message =
        (err as { response?: { data?: { error?: string } } }).response?.data?.error ??
        (err as Error).message;
      set({ isLoading: false, loadError: message ?? 'unknown error', loaded: true });
    }
  },

  upsertSite: (site) =>
    set((s) => {
      const idx = s.sites.findIndex((x) => x.id === site.id);
      if (idx === -1) return { sites: [...s.sites, site] };
      const sites = s.sites.slice();
      sites[idx] = { ...sites[idx], ...site };
      return { sites };
    }),

  removeSite: (siteId) => set((s) => ({ sites: s.sites.filter((x) => x.id !== siteId) })),

  getSite: (id) => get().sites.find((s) => s.id === id),
}));
