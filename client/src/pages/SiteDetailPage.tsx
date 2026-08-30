import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, CalendarClock, MapPin, Radio, Router, Trash2, History } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { CAPABILITIES } from '@obliwan/shared';
import { sitesApi } from '@/api/sites.api';
import { useSiteStore } from '@/store/siteStore';
import { useDeviceStore } from '@/store/deviceStore';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { PresenceDot } from '@/components/fleet/PresenceDot';
import { VerdictBadge } from '@/components/fleet/VerdictBadge';
import { cn } from '@/utils/cn';
import { deviceStatusStyle } from '@/utils/verdict';
import { weekdayNames, formatMaintenanceWindow } from '@/utils/maintenance';
import { anonHostname } from '@/utils/anonymize';
import type { Device, PppSession, Site } from '@/types/fleet';
import toast from 'react-hot-toast';

function formatDuration(seconds: number | null, endedAt: string | null, startedAt: string): string {
  const total = seconds ?? Math.max(
    0,
    Math.round(((endedAt ? new Date(endedAt).getTime() : Date.now()) - new Date(startedAt).getTime()) / 1000),
  );
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function SiteDetailPage() {
  const { id } = useParams<{ id: string }>();
  const siteId = Number(id);
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { hasCapability } = useAuthStore();
  const { removeSite, upsertSite } = useSiteStore();
  const { fetchDevices, presence, siteRollup } = useDeviceStore();

  const canWrite = hasCapability(CAPABILITIES.DEVICE_WRITE);

  const [site, setSite] = useState<Site | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  /** `null` = the PPP timeline endpoint is not implemented yet — which is NOT
   *  the same thing as "this site has never connected". */
  const [sessions, setSessions] = useState<PppSession[] | null>(null);
  const [sessionsUnavailable, setSessionsUnavailable] = useState(false);
  const [sessionsLoading, setSessionsLoading] = useState(true);

  /** Devices filed under THIS site, filtered by the server (not by the
   *  browser over a paginated fleet list, which used to under-report a busy
   *  site as soon as the collection endpoint truncated). */
  const [siteDevices, setSiteDevices] = useState<Device[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const detail = await sitesApi.getById(siteId);
      setSite(detail);
      upsertSite(detail);
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (status === 404) setNotFound(true);
      else toast.error(t('sites.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [siteId, t, upsertSite]);

  useEffect(() => {
    if (!Number.isFinite(siteId)) { setNotFound(true); setLoading(false); return; }
    void load();
    // The global fleet fetch still runs: the store feeds the live presence
    // overlay and the sidebar rollup, which are page-wide.
    void fetchDevices();
    sitesApi.devices(siteId).then(setSiteDevices).catch(() => setSiteDevices([]));
    setSessionsLoading(true);
    sitesApi.pppSessions(siteId)
      .then((rows) => {
        setSessions(rows);
        setSessionsUnavailable(rows === null);
      })
      .catch(() => { setSessions(null); setSessionsUnavailable(true); })
      .finally(() => setSessionsLoading(false));
  }, [siteId, load, fetchDevices]);

  const sortedSiteDevices = useMemo(
    () => [...siteDevices].sort((a, b) => a.name.localeCompare(b.name)),
    [siteDevices],
  );

  if (loading && !site) {
    return <div className="flex h-full items-center justify-center"><LoadingSpinner size="lg" /></div>;
  }

  if (notFound || !site) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4">
        <p className="text-text-muted">{t('sites.notFound')}</p>
        <Link to="/sites"><Button variant="secondary">{t('sites.backToSites')}</Button></Link>
      </div>
    );
  }

  const rollup = siteRollup(site.id);

  const handleDelete = async () => {
    if (!confirm(t('sites.confirmDelete', { name: site.name }))) return;
    try {
      await sitesApi.remove(site.id);
      removeSite(site.id);
      toast.success(t('sites.deleted'));
      navigate('/sites');
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('sites.failedDelete'));
    }
  };

  return (
    <div className="p-6">
      <Link to="/sites" className="mb-4 inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary">
        <ArrowLeft size={14} />
        {t('sites.backToSites')}
      </Link>

      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/10">
            <MapPin size={24} className="text-accent" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-text-primary">{anonHostname(site.name)}</h1>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-text-muted">
              <span className="font-mono">{site.code}</span>
              {site.address && <span>· {site.address}</span>}
              {site.contact && <span>· {site.contact}</span>}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {rollup.total > 0 && (
            <span className="flex items-center gap-2 rounded-md border border-border bg-bg-secondary px-3 py-1.5">
              <span className="font-mono text-sm text-text-primary">{rollup.up}/{rollup.total}</span>
              <VerdictBadge verdict={rollup.worstVerdict} />
            </span>
          )}
          {canWrite && (
            <Button variant="danger" size="sm" onClick={handleDelete}>
              <Trash2 size={14} className="mr-1.5" />
              {t('common.delete')}
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Devices */}
        <section className="rounded-lg border border-border bg-bg-secondary p-4 lg:col-span-2">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">
            <Router size={14} />
            {t('sites.sections.devices')}
            <span className="font-mono text-[11px] normal-case text-text-muted">({sortedSiteDevices.length})</span>
          </h2>
          {sortedSiteDevices.length === 0 ? (
            <p className="rounded-md border border-dashed border-border px-3 py-6 text-center text-sm text-text-muted">
              {t('sites.noDevice')}
            </p>
          ) : (
            <ul className="divide-y divide-border rounded-md border border-border">
              {sortedSiteDevices.map((device) => {
                const live = presence[device.id] ?? device.presence ?? null;
                return (
                  <li key={device.id} className="flex flex-wrap items-center gap-2 px-3 py-2">
                    <PresenceDot presence={live} size={8} />
                    {device.role === 'concentrator'
                      ? <Radio size={13} className="shrink-0 text-accent" />
                      : <Router size={13} className="shrink-0 text-text-muted" />}
                    <Link to={`/devices/${device.id}`} className="text-sm font-medium text-text-primary hover:text-accent">
                      {anonHostname(device.name)}
                    </Link>
                    <span className="text-[11px] text-text-muted">
                      {t(`fleet.brand.${device.brand}`)} · {device.model ?? '—'}
                    </span>
                    <span className={cn(
                      'rounded-full border px-1.5 py-0.5 text-[10px] font-medium',
                      deviceStatusStyle(device.status),
                    )}>
                      {t(`fleet.status.${device.status}`)}
                    </span>
                    <span className="ml-auto">
                      <VerdictBadge verdict={live?.verdict ?? null} />
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        {/* Maintenance window */}
        <MaintenanceCard site={site} canWrite={canWrite} onSaved={(s) => { setSite(s); upsertSite(s); }} />

        {/* PPP timeline */}
        <section className="rounded-lg border border-border bg-bg-secondary p-4">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">
            <History size={14} />
            {t('sites.sections.pppTimeline')}
          </h2>
          {sessionsLoading ? (
            <div className="flex justify-center py-6"><LoadingSpinner /></div>
          ) : sessionsUnavailable ? (
            <p className="rounded-md border border-dashed border-border px-3 py-6 text-center text-xs text-text-muted">
              {t('sites.pppUnavailable')}
            </p>
          ) : !sessions || sessions.length === 0 ? (
            <p className="rounded-md border border-dashed border-border px-3 py-6 text-center text-xs text-text-muted">
              {t('sites.noPppSession')}
            </p>
          ) : (
            <ol className="space-y-2">
              {sessions.map((session) => (
                <li key={session.id} className="flex items-start gap-2 border-l-2 border-border pl-3">
                  <span
                    className={cn(
                      'mt-1.5 inline-block h-2 w-2 shrink-0 rounded-full',
                      session.endedAt === null ? 'bg-status-up' : 'bg-text-muted',
                    )}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline gap-2">
                      <span className="font-mono text-[12px] text-text-primary">{session.pppUsername}</span>
                      <span className="text-[11px] text-text-muted">
                        {new Date(session.startedAt).toLocaleString()}
                        {' → '}
                        {session.endedAt
                          ? new Date(session.endedAt).toLocaleString()
                          : t('sites.stillOpen')}
                      </span>
                      <span className="font-mono text-[11px] text-text-muted">
                        {formatDuration(session.durationSeconds, session.endedAt, session.startedAt)}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2 font-mono text-[10px] text-text-muted">
                      {session.tunnelIp && <span>tunnel {session.tunnelIp}</span>}
                      {session.callerIp && <span>caller {session.callerIp}</span>}
                      {session.disconnectReason && <span>{session.disconnectReason}</span>}
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>
    </div>
  );
}

// ── Maintenance window editor ───────────────────────────────────────────────

function MaintenanceCard({
  site,
  canWrite,
  onSaved,
}: {
  site: Site;
  canWrite: boolean;
  onSaved: (site: Site) => void;
}) {
  const { t, i18n } = useTranslation();
  const names = weekdayNames(i18n.language);

  const [days, setDays] = useState<number[]>(site.maintenanceWindow?.days ?? []);
  const [start, setStart] = useState(site.maintenanceWindow?.start ?? '');
  const [end, setEnd] = useState(site.maintenanceWindow?.end ?? '');
  const [saving, setSaving] = useState(false);

  const toggleDay = (day: number) =>
    setDays((prev) => (prev.includes(day) ? prev.filter((d) => d !== day) : [...prev, day].sort()));

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const window =
        days.length === 0 && !start && !end
          ? null
          : { days, start: start || undefined, end: end || undefined, tz: site.timezone };
      const updated = await sitesApi.update(site.id, { maintenanceWindow: window });
      toast.success(t('sites.maintenanceSaved'));
      onSaved(updated);
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('sites.maintenanceFailed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-4">
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">
        <CalendarClock size={14} />
        {t('sites.sections.maintenance')}
      </h2>

      <p className="mb-3 text-xs text-text-muted">{t('sites.maintenanceHint')}</p>

      <div className="mb-3 rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary">
        {formatMaintenanceWindow(site.maintenanceWindow, i18n.language)
          ?? <span className="italic text-text-muted">{t('sites.noMaintenanceWindow')}</span>}
      </div>

      <form onSubmit={save} className="space-y-3">
        <div className="flex flex-wrap gap-1.5">
          {names.map((label, day) => (
            <button
              key={day}
              type="button"
              disabled={!canWrite}
              onClick={() => toggleDay(day)}
              className={cn(
                'rounded-md border px-2 py-1 text-[12px] transition-colors disabled:cursor-not-allowed disabled:opacity-50',
                days.includes(day)
                  ? 'border-accent bg-accent/10 text-accent'
                  : 'border-border bg-bg-tertiary text-text-muted hover:text-text-primary',
              )}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Input
            label={t('sites.fields.windowStart')}
            type="time"
            value={start}
            disabled={!canWrite}
            onChange={(e) => setStart(e.target.value)}
          />
          <Input
            label={t('sites.fields.windowEnd')}
            type="time"
            value={end}
            disabled={!canWrite}
            onChange={(e) => setEnd(e.target.value)}
          />
        </div>
        <p className="font-mono text-[11px] text-text-muted">{t('sites.fields.timezone')}: {site.timezone}</p>
        {canWrite && <Button type="submit" size="sm" loading={saving}>{t('common.save')}</Button>}
      </form>
    </section>
  );
}
