import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Gauge, RotateCw, ShieldAlert, Unplug } from 'lucide-react';
import { interfacesApi } from '@/api/interfaces.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { PeriodSelector } from '@/components/common/PeriodSelector';
import { cn } from '@/utils/cn';
import {
  DEFAULT_PERIOD,
  chooseGranularity,
  countGaps,
  granularityBucketSec,
  periodSeconds,
  seriesPointBudget,
  toChartPoints,
  windowExceedsRetention,
  MAX_CHART_POINTS,
} from '@/utils/series';
import type { IfSeriesResponse, NetInterface, SeriesGranularity } from '@/types/telemetry';
import { ThroughputChart } from './ThroughputChart';
import { ErrorsChart } from './ErrorsChart';

interface InterfaceSeriesPanelProps {
  iface: NetInterface;
  className?: string;
}

const GRANULARITY_LABEL: Record<SeriesGranularity, string> = {
  raw: 'interfaces.granularity.raw',
  '1m': 'interfaces.granularity.1m',
  '5m': 'interfaces.granularity.5m',
  '1h': 'interfaces.granularity.1h',
};

/**
 * Throughput + errors for one interface, over a selectable window.
 *
 * THE GRANULARITY IS DERIVED FROM THE WINDOW, never chosen by the operator.
 * `chooseGranularity()` walks the tier ladder of study §2.1/§4.6 and picks the
 * finest tier that (a) is actually written for this interface's poll interval
 * and (b) retains data as far back as the window reaches. Asking for 90 days
 * of raw samples would not return a heavy answer, it would return a mutilated
 * one: the raw table keeps 48 h, so 88 of those 90 days come back empty.
 *
 * The badge shows the granularity the SERVER SERVED (echoed in the response),
 * not the one we asked for, so a server-side downgrade stays visible.
 */
export function InterfaceSeriesPanel({ iface, className }: InterfaceSeriesPanelProps) {
  const { t } = useTranslation();
  const [period, setPeriod] = useState(DEFAULT_PERIOD);
  const [series, setSeries] = useState<IfSeriesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [range, setRange] = useState<{ from: number; to: number }>(() => {
    const to = Date.now();
    return { from: to - periodSeconds(DEFAULT_PERIOD) * 1000, to };
  });

  const windowSec = periodSeconds(period);
  const requested = useMemo(
    () => chooseGranularity(windowSec, iface.effectivePollSec),
    [windowSec, iface.effectivePollSec],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const to = Date.now();
    const from = to - windowSec * 1000;
    setRange({ from, to });
    try {
      const res = await interfacesApi.series(
        iface.id,
        {
          from: new Date(from).toISOString(),
          to: new Date(to).toISOString(),
          granularity: requested,
        },
        granularityBucketSec(requested, iface.effectivePollSec),
      );
      if (res === null) {
        setUnavailable(true);
        setSeries(null);
      } else {
        setUnavailable(false);
        setSeries(res);
      }
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setError(message ?? t('interfaces.seriesFailed'));
      setSeries(null);
    } finally {
      setLoading(false);
    }
  }, [iface.id, windowSec, requested, t]);

  useEffect(() => {
    void load();
  }, [load]);

  const served: SeriesGranularity = series?.resolution ?? requested;
  const bucketSec =
    series?.bucketSec && series.bucketSec > 0
      ? series.bucketSec
      : granularityBucketSec(served, iface.effectivePollSec);

  const points = useMemo(
    () => (series ? toChartPoints(series.points, bucketSec) : []),
    [series, bucketSec],
  );
  const gaps = useMemo(() => countGaps(points), [points]);

  const overBudget = seriesPointBudget(windowSec, served, iface.effectivePollSec) > MAX_CHART_POINTS;
  const truncated = windowExceedsRetention(windowSec, served);
  const speedBps = series?.speedBps ?? iface.speedBps;

  // The server is the authority here: it knows the counter width it actually
  // obtained, which can differ from what the target advertises. Study §3.2 —
  // a 32-bit counter on a link fast enough to wrap more than once inside the
  // poll window makes the rate a GUESS, so the throughput chart is not drawn
  // at all. Errors and discards are small counters and stay readable, so that
  // chart survives.
  const rateUntrustworthy = series?.counterUnreliable ?? iface.counterUnreliable;

  // An interface whose every sample is discarded returns an EMPTY series,
  // which on screen is a quiet link. These two fields are the only thing that
  // tells the two apart.
  const discardStreak = iface.consecutiveDiscards ?? 0;

  return (
    <div className={cn('rounded-lg border border-border bg-bg-secondary', className)}>
      {/* Head — period, granularity, refresh */}
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Gauge size={14} className="text-text-muted" />
          <span className="font-mono text-[13px] text-text-primary">{iface.ifName}</span>
          {iface.ifAlias && (
            <span className="truncate text-[12px] text-text-muted">{iface.ifAlias}</span>
          )}
        </div>

        <div className="ml-auto flex flex-wrap items-center gap-2">
          <span
            className="inline-flex items-center gap-1 rounded-full border border-border bg-bg-tertiary px-2 py-0.5 font-mono text-[10px] text-text-secondary"
            title={t('interfaces.granularityHint', {
              granularity: t(GRANULARITY_LABEL[served]),
              window: period,
            })}
          >
            {t(GRANULARITY_LABEL[served])}
          </span>
          <PeriodSelector value={period} onChange={setPeriod} />
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RotateCw size={13} className={cn(loading && 'animate-spin')} />
          </Button>
        </div>
      </div>

      {/* Notices */}
      {(truncated || overBudget || discardStreak > 0) && (
        <div className="space-y-1 border-b border-border px-4 py-2">
          {truncated && (
            <p className="flex items-start gap-1.5 text-[11px] text-status-ssl-warning">
              <AlertTriangle size={11} className="mt-0.5 shrink-0" />
              {t('interfaces.retentionTruncated', {
                granularity: t(GRANULARITY_LABEL[served]),
              })}
            </p>
          )}
          {overBudget && (
            <p className="flex items-start gap-1.5 text-[11px] text-text-muted">
              <AlertTriangle size={11} className="mt-0.5 shrink-0" />
              {t('interfaces.coarsestTier')}
            </p>
          )}
          {/* The single most valuable line on this panel when it appears: an
              empty chart caused by discarded samples is otherwise identical to
              an empty chart caused by an idle link. */}
          {discardStreak > 0 && (
            <p className="flex items-start gap-1.5 text-[11px] text-status-ssl-warning">
              <ShieldAlert size={11} className="mt-0.5 shrink-0" />
              {t('interfaces.discardStreak', {
                count: discardStreak,
                reason: iface.lastDiscard
                  ? t(`interfaces.discard.${iface.lastDiscard}`, {
                      defaultValue: iface.lastDiscard,
                    })
                  : t('interfaces.discard.unknown'),
              })}
            </p>
          )}
        </div>
      )}

      {/* Body */}
      {unavailable ? (
        <div className="flex flex-col items-center gap-2 px-4 py-12 text-center">
          <Unplug size={22} className="text-text-muted" />
          <p className="text-sm text-text-muted">{t('interfaces.seriesUnavailable')}</p>
        </div>
      ) : error ? (
        <div className="px-4 py-8 text-center text-sm text-status-ssl-expired">{error}</div>
      ) : loading && !series ? (
        <div className="flex justify-center py-16">
          <LoadingSpinner size="md" />
        </div>
      ) : points.length === 0 ? (
        <div className="px-4 py-12 text-center text-sm text-text-muted">
          {t('interfaces.seriesEmpty')}
        </div>
      ) : (
        <div className="space-y-4 px-2 py-3">
          <div>
            <h3 className="px-2 text-[11px] uppercase tracking-wider text-text-muted">
              {t('interfaces.chart.throughput')}
            </h3>
            {rateUntrustworthy ? (
              // NOT a chart with a warning on top. The server states that the
              // rate for this interface is a guess (32-bit counter, link fast
              // enough to wrap more than once inside the poll window — study
              // §3.2), and a plotted guess is read as a measurement. The only
              // honest rendering is to decline and say why.
              <div className="mx-2 flex flex-col items-center gap-2 rounded-md border border-dashed border-status-ssl-warning/40 bg-status-ssl-warning/5 px-4 py-8 text-center">
                <ShieldAlert size={20} className="text-status-ssl-warning" />
                <p className="text-[13px] font-medium text-status-ssl-warning">
                  {t('interfaces.chart.rateRefused')}
                </p>
                <p className="max-w-md text-[11px] leading-relaxed text-text-muted">
                  {t('interfaces.counterUnreliableHint')}
                </p>
              </div>
            ) : (
              <ThroughputChart
                data={points}
                fromMs={range.from}
                toMs={range.to}
                windowSec={windowSec}
                speedBps={speedBps}
              />
            )}
          </div>
          <div>
            <h3 className="px-2 text-[11px] uppercase tracking-wider text-text-muted">
              {t('interfaces.chart.errors')}
            </h3>
            <ErrorsChart
              data={points}
              fromMs={range.from}
              toMs={range.to}
              windowSec={windowSec}
            />
          </div>

          {/* A sparse chart must say WHY it is sparse. Without this line an
              operator cannot tell a quiet link from a link we stopped
              measuring — which is the whole reason the gaps are drawn. */}
          <p className="px-2 font-mono text-[10px] text-text-muted">
            {t('interfaces.seriesFooter', {
              points: series?.points.length ?? 0,
              granularity: t(GRANULARITY_LABEL[served]),
            })}
            {gaps > 0 && ` · ${t('interfaces.gapCount', { count: gaps })}`}
          </p>
        </div>
      )}
    </div>
  );
}
