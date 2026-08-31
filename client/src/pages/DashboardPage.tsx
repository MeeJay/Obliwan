import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Router, MapPin, GitCompareArrows, PlayCircle } from 'lucide-react';
import { systemApi, type SystemInfo } from '@/api/system.api';
import { devicesApi } from '@/api/devices.api';
import { sitesApi } from '@/api/sites.api';

/**
 * The fleet dashboard.
 *
 * ┌─ WHAT THIS PAGE USED TO BE, AND WHY IT CHANGED ──────────────────────────┐
 * │ It was the M1 shell: four tiles reading "—", each stamped with the        │
 * │ milestone that would fill it, over a banner explaining that fleet         │
 * │ features were greyed out. That was honest in M1 and became a lie the day  │
 * │ M2 landed — and it stayed on the first screen an operator sees for every  │
 * │ milestone after it, telling them the product did not exist yet.           │
 * │                                                                          │
 * │ Placeholder copy has no expiry date. This page now counts what is really  │
 * │ there, and when there is nothing it says so as a fact about THE FLEET,    │
 * │ never as a fact about the software.                                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Counts come from the list endpoints rather than a dedicated stats route: one
 * fewer surface to keep consistent, and a tile that disagrees with the page it
 * links to is worse than a tile that loads a little slower. `null` means the
 * call failed and the tile shows "—" — an unreachable API must never render as
 * a fleet of zero.
 */

interface TileProps {
  label: string;
  icon: React.ReactNode;
  value: number | null;
  to: string;
  /** Shown under the number: "3 pending", "2 down". Never invented. */
  detail?: string | null;
}

function StatCard({ label, icon, value, to, detail }: TileProps) {
  return (
    <Link
      to={to}
      className="block rounded-lg border border-border bg-bg-secondary p-4 transition-colors hover:border-text-muted"
    >
      <div className="mb-2 flex items-center gap-2">
        <span className="text-text-muted">{icon}</span>
        <span className="text-sm text-text-secondary">{label}</span>
      </div>
      <div className={`text-2xl font-bold ${value === null ? 'text-text-muted' : 'text-text-primary'}`}>
        {value === null ? '—' : value}
      </div>
      <div className="mt-1 h-4 text-[11px] text-text-muted">{detail ?? ''}</div>
    </Link>
  );
}

export function DashboardPage() {
  const { t } = useTranslation();
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [devices, setDevices] = useState<{ total: number; pending: number; quarantined: number } | null>(null);
  const [sites, setSites] = useState<number | null>(null);

  useEffect(() => {
    systemApi.getInfo().then(setSystemInfo).catch(() => setSystemInfo(null));

    devicesApi
      .list({})
      .then((list) =>
        setDevices({
          total: list.length,
          pending: list.filter((d) => d.status === 'pending').length,
          quarantined: list.filter((d) => d.status === 'quarantined').length,
        }),
      )
      .catch(() => setDevices(null));

    sitesApi.list({}).then((l) => setSites(l.length)).catch(() => setSites(null));
  }, []);

  // Quarantine before pending: a device that FAILED an identity assertion (R4)
  // is a different kind of urgent from one merely waiting to be placed.
  const deviceDetail = devices === null
    ? null
    : devices.quarantined > 0
      ? t('dashboard.quarantined', { count: devices.quarantined, defaultValue: '{{count}} quarantined' })
      : devices.pending > 0
        ? t('dashboard.pending', { count: devices.pending, defaultValue: '{{count}} awaiting binding' })
        : null;

  const fleetIsEmpty = devices !== null && devices.total === 0;

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-text-primary">
          {t('dashboard.title', { defaultValue: 'Dashboard' })}
        </h1>
        {systemInfo && (
          <span className="font-mono text-xs text-text-muted">
            ObliWAN v{systemInfo.appVersion}
          </span>
        )}
      </div>

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label={t('dashboard.devices', { defaultValue: 'Devices' })}
          icon={<Router size={16} />}
          value={devices?.total ?? null}
          detail={deviceDetail}
          to="/devices"
        />
        <StatCard
          label={t('dashboard.sites', { defaultValue: 'Sites' })}
          icon={<MapPin size={16} />}
          value={sites}
          to="/sites"
        />
        <StatCard
          label={t('dashboard.drift', { defaultValue: 'Drift' })}
          icon={<GitCompareArrows size={16} />}
          value={null}
          detail={t('dashboard.openRuns', { defaultValue: 'see detail' })}
          to="/drift"
        />
        <StatCard
          label={t('dashboard.changes', { defaultValue: 'Changes' })}
          icon={<PlayCircle size={16} />}
          value={null}
          detail={t('dashboard.openRuns', { defaultValue: 'see detail' })}
          to="/changes"
        />
      </div>

      {fleetIsEmpty && (
        <div className="rounded-lg border border-border bg-bg-secondary">
          <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
            <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-bg-tertiary">
              <Router size={26} className="text-text-muted" />
            </div>
            <h2 className="mb-2 text-base font-semibold text-text-primary">
              {t('dashboard.emptyTitle', { defaultValue: 'No equipment yet' })}
            </h2>
            <p className="max-w-md text-sm text-text-secondary">
              {t('dashboard.emptyBody', {
                defaultValue:
                  'Declare the concentrator and its PPP sessions will populate the quarantine, or enrol a directly reachable device by hand.',
              })}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
