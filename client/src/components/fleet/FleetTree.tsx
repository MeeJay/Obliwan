import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ChevronDown, ChevronRight, MapPin, Router, Radio } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/utils/cn';
import { useSiteStore } from '@/store/siteStore';
import { useDeviceStore } from '@/store/deviceStore';
import { anonHostname } from '@/utils/anonymize';
import { PresenceDot } from './PresenceDot';
import type { Device } from '@/types/fleet';

// Same persistence helper shape as the group tree, kept local so the sidebar
// and this section cannot drift apart on the storage key convention.
function usePersistedFlag(key: string, initial: boolean): [boolean, () => void] {
  const [value, setValue] = useState<boolean>(() => {
    try {
      const stored = localStorage.getItem(key);
      return stored !== null ? (JSON.parse(stored) as boolean) : initial;
    } catch {
      return initial;
    }
  });
  const toggle = useCallback(() => {
    setValue((prev) => {
      const next = !prev;
      localStorage.setItem(key, JSON.stringify(next));
      return next;
    });
  }, [key]);
  return [value, toggle];
}

function DeviceLeaf({ device, depth }: { device: Device; depth: number }) {
  const location = useLocation();
  const presence = useDeviceStore((s) => s.presence[device.id]) ?? device.presence ?? null;
  const active = location.pathname === `/devices/${device.id}`;

  return (
    <Link
      to={`/devices/${device.id}`}
      className={cn(
        'flex items-center gap-2 rounded-md py-1 pr-2 text-[12px] transition-colors',
        active
          ? 'bg-bg-active text-text-primary'
          : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
      )}
      style={{ paddingLeft: `${depth * 14 + 22}px` }}
    >
      <PresenceDot presence={presence} size={7} />
      {device.role === 'concentrator' ? (
        <Radio size={11} className="shrink-0 text-accent" />
      ) : (
        <Router size={11} className="shrink-0 text-text-muted" />
      )}
      <span className="truncate flex-1">{anonHostname(device.name)}</span>
    </Link>
  );
}

function SiteBranch({
  siteId,
  label,
  devices,
}: {
  siteId: number | null;
  label: string;
  devices: Device[];
}) {
  const location = useLocation();
  const [expanded, toggle] = usePersistedFlag(`sidebar:site-${siteId ?? 'none'}-open`, true);
  // Subscribing to the presence map (not to `siteRollup`, which is a stable
  // function reference) is what makes the "up/total" counter repaint when a
  // tunnel drops. A selector on the function alone would never re-render.
  const livePresence = useDeviceStore((s) => s.presence);
  const upCount = devices.filter(
    (d) => (livePresence[d.id] ?? d.presence ?? null)?.up === true,
  ).length;
  const active = siteId !== null && location.pathname === `/sites/${siteId}`;

  return (
    <div>
      <div className="flex items-center gap-0.5">
        <button
          onClick={toggle}
          className={cn(
            'p-0.5 text-text-muted hover:text-text-primary shrink-0 transition-colors',
            devices.length === 0 && 'invisible pointer-events-none',
          )}
          aria-label={label}
        >
          {expanded ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
        </button>

        {siteId === null ? (
          <span className="flex flex-1 items-center gap-2 rounded-md px-2 py-1 text-[13px] text-text-muted italic">
            <MapPin size={13} className="shrink-0" />
            <span className="truncate flex-1">{label}</span>
            <span className="font-mono text-[10px]">{devices.length}</span>
          </span>
        ) : (
          <Link
            to={`/sites/${siteId}`}
            className={cn(
              'flex flex-1 items-center gap-2 rounded-md px-2 py-1 text-[13px] transition-colors',
              active
                ? 'bg-bg-active text-text-primary'
                : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
            )}
          >
            <MapPin size={13} className="shrink-0 text-text-muted" />
            <span className="truncate flex-1 font-medium">{anonHostname(label)}</span>
            {devices.length > 0 && (
              <span className="font-mono text-[10px] text-text-muted">
                {upCount}/{devices.length}
              </span>
            )}
          </Link>
        )}
      </div>

      {expanded &&
        devices.map((device) => <DeviceLeaf key={device.id} device={device} depth={1} />)}
    </div>
  );
}

/**
 * Sites → devices tree with live PPP pastilles (spec §4.1).
 *
 * It reads the same `deviceStore` the Fleet page reads, so a `wan:site:presence`
 * event repaints the dot here without a refetch and without the page having to
 * be open.
 */
export function FleetTree() {
  const { t } = useTranslation();
  const { sites, fetchSites, loaded } = useSiteStore();
  const devices = useDeviceStore((s) => s.devices);
  const fetchDevices = useDeviceStore((s) => s.fetchDevices);
  const [expanded, toggle] = usePersistedFlag('sidebar:fleet-open', true);

  useEffect(() => {
    void fetchSites();
    void fetchDevices();
  }, [fetchSites, fetchDevices]);

  const bySite = useMemo(() => {
    const map = new Map<number | null, Device[]>();
    for (const device of devices) {
      const key = device.siteId ?? null;
      const bucket = map.get(key);
      if (bucket) bucket.push(device);
      else map.set(key, [device]);
    }
    for (const bucket of map.values()) {
      bucket.sort((a, b) => a.name.localeCompare(b.name));
    }
    return map;
  }, [devices]);

  const orderedSites = useMemo(
    () => [...sites].sort((a, b) => a.name.localeCompare(b.name)),
    [sites],
  );

  const orphans = bySite.get(null) ?? [];

  return (
    <div className="mt-2 pt-2 border-t border-border">
      <button
        onClick={toggle}
        className="w-full px-2 py-1.5 flex items-center gap-2 text-[11px] font-mono font-medium text-text-muted uppercase tracking-[0.12em] hover:text-text-secondary transition-colors"
      >
        <MapPin size={12} />
        <span className="flex-1 text-left">{t('nav.sites')}</span>
        {expanded ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
      </button>

      {expanded && (
        <>
          {orderedSites.length === 0 && orphans.length === 0 ? (
            <div className="px-2 py-2 text-[12px] text-text-muted">
              {loaded ? t('sites.empty') : t('common.loading')}
            </div>
          ) : (
            <>
              {orderedSites.map((site) => (
                <SiteBranch
                  key={site.id}
                  siteId={site.id}
                  label={site.name}
                  devices={bySite.get(site.id) ?? []}
                />
              ))}
              {orphans.length > 0 && (
                <SiteBranch siteId={null} label={t('fleet.unassignedSite')} devices={orphans} />
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}
