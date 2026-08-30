import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Activity, BellRing, RotateCw, Search, Unplug, X } from 'lucide-react';
import { CAPABILITIES, IF_OPER_STATUS, INTERFACE_STATES, type InterfaceState } from '@obliwan/shared';
import { interfacesApi } from '@/api/interfaces.api';
import { useDeviceStore } from '@/store/deviceStore';
import { useSiteStore } from '@/store/siteStore';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { InterfacesTable, peakUtil } from '@/components/telemetry/InterfacesTable';
import { cn } from '@/utils/cn';
import { formatBps } from '@/utils/series';
import { operStatusLabelKey } from '@/utils/interfaceStatus';
import type { NetInterface } from '@/types/telemetry';

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

const OPER_FILTER_CODES = [
  IF_OPER_STATUS.up,
  IF_OPER_STATUS.down,
  IF_OPER_STATUS.lowerLayerDown,
  IF_OPER_STATUS.dormant,
  IF_OPER_STATUS.unknown,
];

/**
 * Fleet-wide interface view (spec §4.2 — "vue parc, débit/erreurs, tri par
 * saturation").
 *
 * Filtering is client-side, exactly as `DevicesPage` does and for the same
 * reason: at the fleet size this product targets (300 devices × 8 interfaces =
 * 2 400 rows, study §0) the whole list is one request, and a server-side
 * filtered refetch on every keystroke would make the table flicker for no gain.
 * The threshold at which this stops being true is stated in the study: past
 * ~2 500 devices the exploitation model changes anyway.
 */
export function InterfacesPage() {
  const { t } = useTranslation();
  const { devices, fetchDevices } = useDeviceStore();
  const { sites, fetchSites } = useSiteStore();
  const { hasCapability, isAdmin } = useAuthStore();

  const [interfaces, setInterfaces] = useState<NetInterface[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [search, setSearch] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [siteId, setSiteId] = useState('');
  const [operStatus, setOperStatus] = useState('');
  const [state, setState] = useState<InterfaceState | ''>('active');
  const [saturatedOnly, setSaturatedOnly] = useState(false);

  const canManageThresholds = isAdmin() || hasCapability(CAPABILITIES.SNMP_ADMIN);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const rows = await interfacesApi.list();
      if (rows === null) {
        setUnavailable(true);
        setInterfaces([]);
      } else {
        setUnavailable(false);
        setInterfaces(rows);
      }
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setLoadError(message ?? t('interfaces.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void load();
    void fetchDevices();
    void fetchSites();
  }, [load, fetchDevices, fetchSites]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return interfaces.filter((i) => {
      if (deviceId && i.deviceId !== Number(deviceId)) return false;
      if (siteId && i.siteId !== Number(siteId)) return false;
      if (operStatus && i.operStatus !== Number(operStatus)) return false;
      if (state && i.state !== state) return false;
      if (saturatedOnly) {
        const pct = peakUtil(i);
        // An interface with no measurable saturation is EXCLUDED from a
        // "saturated only" filter rather than included by default: we do not
        // know that it is saturated, and inventing that it is would be as
        // wrong as inventing that it is idle.
        if (pct === null || pct < 70) return false;
      }
      if (!needle) return true;
      return [i.ifName, i.ifAlias, i.ifDescr, i.deviceName, i.siteName]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(needle));
    });
  }, [interfaces, search, deviceId, siteId, operStatus, state, saturatedOnly]);

  const activeFilterCount =
    (search ? 1 : 0) +
    (deviceId ? 1 : 0) +
    (siteId ? 1 : 0) +
    (operStatus ? 1 : 0) +
    (state !== 'active' ? 1 : 0) +
    (saturatedOnly ? 1 : 0);

  const resetFilters = () => {
    setSearch('');
    setDeviceId('');
    setSiteId('');
    setOperStatus('');
    setState('active');
    setSaturatedOnly(false);
  };

  // Header summary. `null` saturations are counted separately and never folded
  // into "healthy" — an unmeasurable link is not a green one.
  const summary = useMemo(() => {
    let saturated = 0;
    let unmeasurable = 0;
    let down = 0;
    let totalIn = 0;
    let totalOut = 0;
    for (const i of interfaces) {
      if (i.state !== 'active') continue;
      const pct = peakUtil(i);
      if (pct === null) unmeasurable += 1;
      else if (pct >= 70) saturated += 1;
      if (i.operStatus === IF_OPER_STATUS.down && i.adminStatus !== 2) down += 1;
      if (i.lastSample) {
        totalIn += i.lastSample.inBps;
        totalOut += i.lastSample.outBps;
      }
    }
    return { saturated, unmeasurable, down, totalIn, totalOut };
  }, [interfaces]);

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">{t('nav.interfaces')}</h1>
          <p className="mt-1 text-sm text-text-muted">
            {t('interfaces.subtitle', { count: interfaces.length })}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
          {canManageThresholds && (
            <Link to="/interfaces/thresholds">
              <Button size="sm" variant="secondary">
                <BellRing size={14} className="mr-1.5" />
                {t('thresholds.title')}
              </Button>
            </Link>
          )}
        </div>
      </div>

      {/* Summary strip */}
      {!unavailable && interfaces.length > 0 && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
          <SummaryCard
            label={t('interfaces.summary.saturated')}
            value={String(summary.saturated)}
            tone={summary.saturated > 0 ? 'warn' : 'ok'}
            hint={t('interfaces.summary.saturatedHint')}
          />
          <SummaryCard
            label={t('interfaces.summary.down')}
            value={String(summary.down)}
            tone={summary.down > 0 ? 'bad' : 'ok'}
            hint={t('interfaces.summary.downHint')}
          />
          <SummaryCard
            label={t('interfaces.summary.unmeasurable')}
            value={String(summary.unmeasurable)}
            tone="muted"
            hint={t('interfaces.summary.unmeasurableHint')}
          />
          <SummaryCard
            label={t('interfaces.summary.aggregate')}
            value={`${formatBps(summary.totalIn, 1)} / ${formatBps(summary.totalOut, 1)}`}
            tone="muted"
            hint={t('interfaces.summary.aggregateHint')}
          />
        </div>
      )}

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search
            size={13}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted"
          />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('interfaces.searchPlaceholder')}
            className="w-64 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>

        <select className={selectClass} value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          <option value="">{t('interfaces.filters.allDevices')}</option>
          {devices.map((d) => (
            <option key={d.id} value={d.id}>{d.name}</option>
          ))}
        </select>

        <select className={selectClass} value={siteId} onChange={(e) => setSiteId(e.target.value)}>
          <option value="">{t('devices.filters.allSites')}</option>
          {sites.map((s) => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>

        <select
          className={selectClass}
          value={operStatus}
          onChange={(e) => setOperStatus(e.target.value)}
        >
          <option value="">{t('interfaces.filters.allStates')}</option>
          {OPER_FILTER_CODES.map((code) => (
            <option key={code} value={code}>{t(operStatusLabelKey(code))}</option>
          ))}
        </select>

        <select
          className={selectClass}
          value={state}
          onChange={(e) => setState(e.target.value as InterfaceState | '')}
        >
          <option value="">{t('interfaces.filters.allLifecycles')}</option>
          {INTERFACE_STATES.map((s) => (
            <option key={s} value={s}>{t(`interfaces.state.${s}`)}</option>
          ))}
        </select>

        <label
          className="flex cursor-pointer items-center gap-1.5 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-secondary"
          title={t('interfaces.filters.saturatedHint')}
        >
          <input
            type="checkbox"
            checked={saturatedOnly}
            onChange={(e) => setSaturatedOnly(e.target.checked)}
            className="h-3.5 w-3.5 rounded border-border bg-bg-tertiary accent-accent"
          />
          {t('interfaces.filters.saturatedOnly')}
        </label>

        {activeFilterCount > 0 && (
          <button
            onClick={resetFilters}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            <X size={12} />
            {t('devices.filters.clear')}
          </button>
        )}

        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('devices.showing', { shown: filtered.length, total: interfaces.length })}
        </span>
      </div>

      {/* Body */}
      {unavailable ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('interfaces.endpointUnavailable')}</p>
        </div>
      ) : loadError ? (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
          {t('interfaces.loadFailed')} — <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : loading && interfaces.length === 0 ? (
        <div className="flex justify-center py-16">
          <LoadingSpinner size="lg" />
        </div>
      ) : interfaces.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Activity size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('interfaces.empty')}</p>
          <p className="mt-1 text-xs text-text-muted">{t('interfaces.emptyHint')}</p>
        </div>
      ) : (
        <InterfacesTable interfaces={filtered} emptyLabel={t('interfaces.noMatch')} />
      )}
    </div>
  );
}

// ── Summary card ────────────────────────────────────────────────────────────

const TONES = {
  ok: 'text-status-up',
  warn: 'text-status-ssl-warning',
  bad: 'text-status-ssl-expired',
  muted: 'text-text-primary',
};

function SummaryCard({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: string;
  tone: keyof typeof TONES;
  hint: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-3" title={hint}>
      <div className="text-[11px] uppercase tracking-wider text-text-muted">{label}</div>
      <div className={cn('mt-1 font-display text-xl font-semibold tabular-nums', TONES[tone])}>
        {value}
      </div>
    </div>
  );
}
