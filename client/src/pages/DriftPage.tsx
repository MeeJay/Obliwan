import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { GitCompareArrows, RotateCw, Search, Unplug, X } from 'lucide-react';
import { DIFF_SEVERITIES, SEVERITY_RANK, type DiffSeverity } from '@obliwan/shared';
import { driftApi } from '@/api/drift.api';
import { useSiteStore } from '@/store/siteStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { CauseChip, DriftStatusBadge, SeverityBadge } from '@/components/config/DriftBadges';
import { cn } from '@/utils/cn';
import type { DriftRunSummary, DriftStatus } from '@/types/config';

/**
 * `DriftPage` — spec §4.2, the fleet-level drift list.
 *
 * ── WHY THE DEFAULT IS "LATEST RUN PER DEVICE" ──────────────────────────────
 * `drift_runs` is a HISTORY: a fleet of 300 devices on an hourly schedule
 * writes 7 200 rows a day. A fleet page that lists them all is a log file, not a
 * status screen, and the operator's actual question — "which of my devices is
 * drifted RIGHT NOW" — becomes unanswerable in exactly the way R3 warns about.
 * So the page folds the history to one row per device by default and says so;
 * the toggle brings the full history back for a post-mortem.
 *
 * ── THE NOISE STRIP IS NOT DECORATION ───────────────────────────────────────
 * The milestone's exit criterion is a NUMBER — fewer than three noise findings
 * per device — and the four counters at the top are what makes it readable
 * without a SQL client: findings per device, inert moves folded away, findings
 * already ignored, objects out of scope. If the criterion is missed, these say
 * which lever to pull. They are averaged over the devices actually shown, and
 * the page states that rather than implying a fleet-wide truth.
 */

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

const STATUSES: DriftStatus[] = ['drifted', 'in_sync', 'error', 'unreachable'];

export function DriftPage() {
  const { t, i18n } = useTranslation();
  const { sites, fetchSites } = useSiteStore();

  const [runs, setRuns] = useState<DriftRunSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [search, setSearch] = useState('');
  const [siteId, setSiteId] = useState('');
  const [status, setStatus] = useState<DriftStatus | ''>('');
  const [minSeverity, setMinSeverity] = useState<DiffSeverity | ''>('');
  const [latestOnly, setLatestOnly] = useState(true);

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' }),
    [i18n.language],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const rows = await driftApi.listRuns({ limit: 500 });
      if (rows === null) { setUnavailable(true); setRuns([]); }
      else { setUnavailable(false); setRuns(rows); }
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setLoadError(message ?? t('drift.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void load();
    void fetchSites();
  }, [load, fetchSites]);

  /** One row per device, keeping the newest run. */
  const folded = useMemo(() => {
    if (!latestOnly) return runs;
    const best = new Map<number, DriftRunSummary>();
    for (const r of runs) {
      const cur = best.get(r.deviceId);
      if (!cur || new Date(r.startedAt).getTime() > new Date(cur.startedAt).getTime()) {
        best.set(r.deviceId, r);
      }
    }
    return [...best.values()];
  }, [runs, latestOnly]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const floor = minSeverity ? SEVERITY_RANK[minSeverity] : -1;
    const rows = folded.filter((r) => {
      if (siteId && r.siteId !== Number(siteId)) return false;
      if (status && r.status !== status) return false;
      if (floor >= 0) {
        if (r.maxSeverity === null) return false;
        if (SEVERITY_RANK[r.maxSeverity] < floor) return false;
      }
      if (!needle) return true;
      return [r.deviceName, r.siteName]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(needle));
    });
    // Worst first, then most recent. The first screenful is the bad news.
    rows.sort((a, b) => {
      const sa = a.maxSeverity ? SEVERITY_RANK[a.maxSeverity] : -1;
      const sb = b.maxSeverity ? SEVERITY_RANK[b.maxSeverity] : -1;
      if (sa !== sb) return sb - sa;
      return new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime();
    });
    return rows;
  }, [folded, search, siteId, status, minSeverity]);

  const summary = useMemo(() => {
    const devices = new Set(filtered.map((r) => r.deviceId));
    let findings = 0;
    let ignored = 0;
    let inert = 0;
    let outOfScope = 0;
    let drifted = 0;
    let broken = 0;
    for (const r of filtered) {
      findings += r.findingsCount;
      ignored += r.ignoredCount;
      inert += r.inertMoveCount;
      outOfScope += r.outOfScopeCount;
      if (r.status === 'drifted') drifted++;
      if (r.status === 'error' || r.status === 'unreachable') broken++;
    }
    const n = Math.max(1, devices.size);
    return {
      deviceCount: devices.size,
      drifted,
      broken,
      findings,
      ignored,
      inert,
      outOfScope,
      perDevice: findings / n,
    };
  }, [filtered]);

  const activeFilters =
    (search ? 1 : 0) + (siteId ? 1 : 0) + (status ? 1 : 0) + (minSeverity ? 1 : 0);

  return (
    <div className="p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">{t('nav.drift')}</h1>
          <p className="mt-1 text-sm text-text-muted">{t('drift.subtitle')}</p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => void load()}>
          <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
          {t('devices.refresh')}
        </Button>
      </div>

      {!unavailable && runs.length > 0 && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
          <SummaryCard
            label={t('drift.summary.drifted')}
            value={`${summary.drifted}/${summary.deviceCount}`}
            tone={summary.drifted > 0 ? 'warn' : 'ok'}
            hint={t('drift.summary.driftedHint')}
          />
          <SummaryCard
            label={t('drift.summary.perDevice')}
            value={summary.perDevice.toFixed(1)}
            tone={summary.perDevice < 3 ? 'ok' : 'warn'}
            hint={t('drift.summary.perDeviceHint')}
          />
          <SummaryCard
            label={t('drift.summary.folded')}
            value={`${summary.inert} / ${summary.ignored}`}
            tone="muted"
            hint={t('drift.summary.foldedHint')}
          />
          <SummaryCard
            label={t('drift.summary.broken')}
            value={String(summary.broken)}
            tone={summary.broken > 0 ? 'bad' : 'ok'}
            hint={t('drift.summary.brokenHint')}
          />
        </div>
      )}

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
            placeholder={t('drift.searchPlaceholder')}
            className="w-64 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>

        <select className={selectClass} value={siteId} onChange={(e) => setSiteId(e.target.value)}>
          <option value="">{t('devices.filters.allSites')}</option>
          {sites.map((s) => (
            <option key={s.id} value={s.id}>{s.name}</option>
          ))}
        </select>

        <select
          className={selectClass}
          value={status}
          onChange={(e) => setStatus(e.target.value as DriftStatus | '')}
        >
          <option value="">{t('drift.filters.allStatuses')}</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{t(`drift.status.${s}`)}</option>
          ))}
        </select>

        <select
          className={selectClass}
          value={minSeverity}
          onChange={(e) => setMinSeverity(e.target.value as DiffSeverity | '')}
        >
          <option value="">{t('drift.filters.allSeverities')}</option>
          {[...DIFF_SEVERITIES].reverse().map((s) => (
            <option key={s} value={s}>{t('drift.filters.atLeast', { severity: t(`ncm.severity.${s}`) })}</option>
          ))}
        </select>

        <label
          className="flex cursor-pointer items-center gap-1.5 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-secondary"
          title={t('drift.filters.latestOnlyHint')}
        >
          <input
            type="checkbox"
            checked={latestOnly}
            onChange={(e) => setLatestOnly(e.target.checked)}
            className="h-3.5 w-3.5 rounded border-border bg-bg-tertiary accent-accent"
          />
          {t('drift.filters.latestOnly')}
        </label>

        {activeFilters > 0 && (
          <button
            onClick={() => { setSearch(''); setSiteId(''); setStatus(''); setMinSeverity(''); }}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            <X size={12} />
            {t('devices.filters.clear')}
          </button>
        )}

        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('devices.showing', { shown: filtered.length, total: folded.length })}
        </span>
      </div>

      {unavailable ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('drift.endpointUnavailable')}</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
            {t('drift.endpointUnavailableHint')}
          </p>
        </div>
      ) : loadError ? (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
          {t('drift.loadFailed')} — <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : loading && runs.length === 0 ? (
        <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
      ) : runs.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <GitCompareArrows size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('drift.empty')}</p>
          <p className="mt-1 text-xs text-text-muted">{t('drift.emptyHint')}</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full min-w-[60rem] text-left text-[13px]">
            <thead className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">{t('drift.columns.device')}</th>
                <th className="px-3 py-2 font-medium">{t('drift.columns.status')}</th>
                <th className="px-3 py-2 font-medium">{t('drift.columns.severity')}</th>
                <th className="px-3 py-2 text-right font-medium">{t('drift.columns.findings')}</th>
                <th className="px-3 py-2 text-right font-medium">{t('drift.columns.ignored')}</th>
                <th className="px-3 py-2 text-right font-medium">{t('drift.columns.inert')}</th>
                <th className="px-3 py-2 text-right font-medium">{t('drift.columns.outOfScope')}</th>
                <th className="px-3 py-2 font-medium">{t('drift.columns.cause')}</th>
                <th className="px-3 py-2 font-medium">{t('drift.columns.started')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-3 py-10 text-center text-text-muted">
                    {t('drift.noMatch')}
                  </td>
                </tr>
              ) : (
                filtered.map((r) => (
                  <tr key={r.id} className="hover:bg-bg-hover">
                    <td className="px-3 py-2">
                      <Link to={`/drift/${r.id}`} className="block">
                        <span className="text-text-primary hover:text-accent">
                          {r.deviceName ?? `#${r.deviceId}`}
                        </span>
                        <span className="block text-[11px] text-text-muted">{r.siteName ?? '—'}</span>
                      </Link>
                    </td>
                    <td className="px-3 py-2"><DriftStatusBadge status={r.status} /></td>
                    <td className="px-3 py-2"><SeverityBadge severity={r.maxSeverity} /></td>
                    <td className="px-3 py-2 text-right font-mono tabular-nums">{r.findingsCount}</td>
                    <td className="px-3 py-2 text-right font-mono tabular-nums text-text-muted">
                      {r.ignoredCount}
                    </td>
                    <td className="px-3 py-2 text-right font-mono tabular-nums text-text-muted">
                      {r.inertMoveCount}
                    </td>
                    <td className="px-3 py-2 text-right font-mono tabular-nums text-text-muted">
                      {r.outOfScopeCount}
                    </td>
                    <td className="px-3 py-2"><CauseChip cause={r.cause} /></td>
                    <td className="px-3 py-2 font-mono text-[11px] text-text-muted">
                      {dateFmt.format(new Date(r.startedAt))}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

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
