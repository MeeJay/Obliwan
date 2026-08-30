import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ChevronRight, GitCompareArrows, RotateCw, Unplug } from 'lucide-react';
import { driftApi } from '@/api/drift.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { CauseChip, DriftStatusBadge, SeverityBadge } from '@/components/config/DriftBadges';
import { cn } from '@/utils/cn';
import type { DriftRunSummary } from '@/types/config';

/**
 * The `Dérive` tab of a device: the run history, newest first.
 *
 * The counters on each row are the per-lever instrumentation of R3 —
 * `findings`, `ignored`, `inert moves`, `out of scope`. They are shown on the
 * LIST and not only in the detail because the milestone's exit criterion is a
 * number per device ("fewer than 3 noise findings per device"), and a screen
 * where you have to open twelve runs to count it is a screen nobody uses to
 * measure anything.
 */

export interface DeviceDriftTabProps {
  deviceId: number;
  className?: string;
}

export function DeviceDriftTab({ deviceId, className }: DeviceDriftTabProps) {
  const { t, i18n } = useTranslation();
  const [runs, setRuns] = useState<DriftRunSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' }),
    [i18n.language],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await driftApi.forDevice(deviceId);
      if (rows === null) { setUnavailable(true); setRuns([]); }
      else { setUnavailable(false); setRuns(rows); }
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setError(message ?? t('drift.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [deviceId, t]);

  useEffect(() => { void load(); }, [load]);

  if (unavailable) {
    return (
      <div className={cn('rounded-lg border border-border bg-bg-secondary py-16 text-center', className)}>
        <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{t('drift.endpointUnavailable')}</p>
        <p className="mx-auto mt-1 max-w-lg text-xs text-text-muted">
          {t('drift.endpointUnavailableHint')}
        </p>
      </div>
    );
  }

  if (loading && runs.length === 0) {
    return <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>;
  }

  if (error) {
    return (
      <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
        {error}
      </div>
    );
  }

  if (runs.length === 0) {
    return (
      <div className={cn('rounded-lg border border-border bg-bg-secondary py-16 text-center', className)}>
        <GitCompareArrows size={28} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{t('drift.deviceEmpty')}</p>
        <p className="mt-1 text-xs text-text-muted">{t('drift.deviceEmptyHint')}</p>
        <Button variant="secondary" size="sm" className="mt-4" onClick={() => void load()}>
          <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
          {t('devices.refresh')}
        </Button>
      </div>
    );
  }

  return (
    <div className={cn('rounded-lg border border-border bg-bg-secondary', className)}>
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <h3 className="text-sm font-semibold text-text-primary">{t('drift.runs')}</h3>
        <span className="font-mono text-[11px] text-text-muted">{runs.length}</span>
        <button
          onClick={() => void load()}
          title={t('devices.refresh')}
          className="ml-auto rounded p-1 text-text-muted hover:bg-bg-hover hover:text-text-primary"
        >
          <RotateCw size={13} className={cn(loading && 'animate-spin')} />
        </button>
      </div>
      <ul className="divide-y divide-border">
        {runs.map((run) => (
          <li key={run.id}>
            <Link
              to={`/drift/${run.id}`}
              className="flex flex-wrap items-center gap-2 px-3 py-2 hover:bg-bg-hover"
            >
              <span className="text-[13px] text-text-primary">
                {dateFmt.format(new Date(run.startedAt))}
              </span>
              <DriftStatusBadge status={run.status} />
              <SeverityBadge severity={run.maxSeverity} />
              <CauseChip cause={run.cause} />
              <span className="font-mono text-[11px] text-text-muted">
                {t('drift.findingsCount', { count: run.findingsCount })}
              </span>
              {run.ignoredCount > 0 && (
                <span className="font-mono text-[11px] text-text-muted">
                  {t('drift.ignoredShort', { count: run.ignoredCount })}
                </span>
              )}
              {run.inertMoveCount > 0 && (
                <span
                  className="font-mono text-[11px] text-text-muted"
                  title={t('config.diff.inertMoves', { count: run.inertMoveCount })}
                >
                  {t('drift.inertShort', { count: run.inertMoveCount })}
                </span>
              )}
              {run.outOfScopeCount > 0 && (
                <span
                  className="font-mono text-[11px] text-text-muted"
                  title={t('config.diff.outOfScope', { count: run.outOfScopeCount })}
                >
                  {t('drift.outOfScopeShort', { count: run.outOfScopeCount })}
                </span>
              )}
              {run.status === 'error' && run.errorReason && (
                <span className="truncate font-mono text-[11px] text-status-ssl-expired">
                  {run.errorReason}
                </span>
              )}
              <ChevronRight size={14} className="ml-auto shrink-0 text-text-muted" />
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
