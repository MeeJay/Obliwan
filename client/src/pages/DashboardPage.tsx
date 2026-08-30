import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Router, MapPin, GitCompareArrows, PlayCircle, Info } from 'lucide-react';
import { systemApi, type SystemInfo } from '@/api/system.api';

/**
 * M1 dashboard.
 *
 * The real dashboard (spec §4.2 — sites online / tunnels down, open drift by
 * severity, running jobs, saturated interfaces, abnormal reachability
 * verdicts) needs the inventory (M2), telemetry (M3) and drift (M4). None of
 * that exists yet, so this page shows the visual shell with an explicit empty
 * state instead of fabricated numbers. Every tile reads "—" and says which
 * milestone will fill it.
 */

interface TileProps {
  label: string;
  icon: React.ReactNode;
  hint: string;
}

function EmptyStatCard({ label, icon, hint }: TileProps) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="mb-2 flex items-center gap-2">
        <span className="text-text-muted">{icon}</span>
        <span className="text-sm text-text-secondary">{label}</span>
      </div>
      <div className="text-2xl font-bold text-text-muted">—</div>
      <div className="mt-1 font-mono text-[10px] uppercase tracking-wider text-text-muted">
        {hint}
      </div>
    </div>
  );
}

export function DashboardPage() {
  const { t } = useTranslation();
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);

  useEffect(() => {
    systemApi.getInfo().then(setSystemInfo).catch(() => setSystemInfo(null));
  }, []);

  return (
    <div className="p-6">
      {/* Header */}
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

      {/* Stats row — shell only, no data source yet */}
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <EmptyStatCard
          label={t('dashboard.sitesOnline', { defaultValue: 'Sites online' })}
          icon={<MapPin size={16} />}
          hint="M2"
        />
        <EmptyStatCard
          label={t('dashboard.devicesManaged', { defaultValue: 'Managed devices' })}
          icon={<Router size={16} />}
          hint="M2"
        />
        <EmptyStatCard
          label={t('dashboard.openDrift', { defaultValue: 'Open drift' })}
          icon={<GitCompareArrows size={16} />}
          hint="M4"
        />
        <EmptyStatCard
          label={t('dashboard.runningJobs', { defaultValue: 'Running jobs' })}
          icon={<PlayCircle size={16} />}
          hint="M6"
        />
      </div>

      {/* Empty state */}
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
                'The fleet inventory — sites, devices, transports and CHR discovery — arrives at milestone M2. Until then this dashboard has nothing real to show.',
            })}
          </p>
        </div>
      </div>

      {/* What works today */}
      <div className="mt-6 flex items-start gap-3 rounded-lg border border-border bg-bg-secondary p-4">
        <Info size={16} className="mt-0.5 shrink-0 text-text-muted" />
        <div className="text-sm text-text-secondary">
          <div className="mb-1 font-medium text-text-primary">
            {t('dashboard.m1Title', { defaultValue: 'Milestone M1' })}
          </div>
          <p>
            {t('dashboard.m1Body', {
              defaultValue:
                'Authentication via Obligate SSO, workspaces, groups, settings, notifications and themes are live. Fleet features are greyed out in the sidebar with the milestone that unlocks them.',
            })}
          </p>
        </div>
      </div>
    </div>
  );
}
