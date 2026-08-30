import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { FileCode, Search, X } from 'lucide-react';
import { useDeviceStore } from '@/store/deviceStore';
import { useSiteStore } from '@/store/siteStore';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { DeviceConfigTab } from '@/components/config/DeviceConfigTab';
import { cn } from '@/utils/cn';

/**
 * `ConfigPage` — spec §4.2: "snapshots, comparaison N/N-1, arbre NCM, export".
 *
 * A configuration belongs to ONE device, so the fleet-level page is a device
 * picker wrapped around `DeviceConfigTab` — the exact same component the
 * `Configuration` tab of `DeviceDetailPage` renders. Writing the four features
 * twice would guarantee they diverge, and the tab is the one an operator
 * reaches for most.
 *
 * The picker is client-side over the device store, like `DevicesPage` and
 * `InterfacesPage`, and for the same reason: at this product's fleet size the
 * whole list is already in memory, and a server round trip per keystroke buys
 * nothing but flicker.
 */

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

export function ConfigPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { deviceId: deviceIdParam } = useParams<{ deviceId: string }>();
  const { devices, fetchDevices, isLoading } = useDeviceStore();
  const { sites, fetchSites } = useSiteStore();

  const [search, setSearch] = useState('');
  const [siteId, setSiteId] = useState('');

  useEffect(() => {
    void fetchDevices();
    void fetchSites();
  }, [fetchDevices, fetchSites]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return devices.filter((d) => {
      if (siteId && d.siteId !== Number(siteId)) return false;
      if (!needle) return true;
      return [d.name, d.model, d.systemIdentity, d.siteName]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(needle));
    });
  }, [devices, search, siteId]);

  const selectedId = deviceIdParam ? Number(deviceIdParam) : null;
  const selected = selectedId !== null ? devices.find((d) => d.id === selectedId) ?? null : null;

  // A page opened with no device selected picks the first one it can see rather
  // than showing an empty right-hand pane: the operator came here to look at a
  // configuration, and "pick something" is a step the screen can take itself.
  useEffect(() => {
    if (selectedId === null && filtered.length > 0) {
      navigate(`/config/${filtered[0].id}`, { replace: true });
    }
  }, [selectedId, filtered, navigate]);

  return (
    <div className="p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">{t('nav.configurations')}</h1>
          <p className="mt-1 text-sm text-text-muted">{t('config.subtitle')}</p>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[18rem_1fr]">
        {/* device picker */}
        <aside className="rounded-lg border border-border bg-bg-secondary">
          <div className="space-y-2 border-b border-border px-3 py-2">
            <div className="relative">
              <Search
                size={13}
                className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted"
              />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={t('config.searchDevices')}
                className="w-full rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
              />
            </div>
            <div className="flex items-center gap-2">
              <select
                className={cn(selectClass, 'flex-1')}
                value={siteId}
                onChange={(e) => setSiteId(e.target.value)}
              >
                <option value="">{t('devices.filters.allSites')}</option>
                {sites.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
              {(search || siteId) && (
                <button
                  onClick={() => { setSearch(''); setSiteId(''); }}
                  className="rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
                >
                  <X size={12} />
                </button>
              )}
            </div>
          </div>

          {isLoading && devices.length === 0 ? (
            <div className="flex justify-center py-10"><LoadingSpinner size="md" /></div>
          ) : filtered.length === 0 ? (
            <p className="px-3 py-10 text-center text-sm text-text-muted">
              {devices.length === 0 ? t('devices.empty') : t('devices.noMatch')}
            </p>
          ) : (
            <ul className="max-h-[70vh] divide-y divide-border overflow-auto">
              {filtered.map((d) => (
                <li key={d.id}>
                  <button
                    onClick={() => navigate(`/config/${d.id}`)}
                    className={cn(
                      'w-full px-3 py-2 text-left hover:bg-bg-hover',
                      selectedId === d.id && 'bg-accent/10',
                    )}
                  >
                    <div className="truncate text-[13px] text-text-primary">{d.name}</div>
                    <div className="truncate text-[11px] text-text-muted">
                      {[d.siteName, d.model].filter(Boolean).join(' · ') || '—'}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </aside>

        {/* the configuration itself */}
        <div className="min-w-0">
          {selectedId === null ? (
            <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
              <FileCode size={28} className="mx-auto mb-2 text-text-muted" />
              <p className="text-sm text-text-muted">{t('config.pickDevice')}</p>
            </div>
          ) : (
            <DeviceConfigTab
              key={selectedId}
              deviceId={selectedId}
              deviceName={selected?.name ?? null}
            />
          )}
        </div>
      </div>
    </div>
  );
}
