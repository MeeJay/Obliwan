import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Download, Info, RefreshCw, TrendingUp } from 'lucide-react';
import toast from 'react-hot-toast';
import { suggestsPlanChange, type SimRechargeReport } from '@obliwan/shared';
import { simApi, errorMessageOf } from '@/api/sim.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { DataAmount, EmptyState, Money, Panel, When } from '@/components/mobile/SimBits';
import { cn } from '@/utils/cn';

/**
 * ObliWAN F9 — who costs money, and which plans are the wrong size.
 *
 * ┌─ TWO QUESTIONS ON ONE SCREEN, BECAUSE THEY SHARE EVERY ROW ───────────────┐
 * │                                                                          │
 * │ 1. RE-INVOICING. Which sites were topped up, when, how much, what it      │
 * │    cost. An MSP hands this to accounting.                                 │
 * │                                                                          │
 * │ 2. PLAN SIZING. A top-up is bought at a worse price per megabyte than the │
 * │    allowance it tops up. So a line that runs out most months is not an    │
 * │    incident, it is a purchasing mistake that repeats — and the number     │
 * │    that shows it is MONTHS WITH A TOP-UP, not the count of top-ups. Six   │
 * │    top-ups in one bad March is one problem; one top-up in each of six     │
 * │    months is a plan.                                                      │
 * │                                                                          │
 * │ ObliWAN renegotiates nothing and cannot change a plan. It makes the case  │
 * │ visible and cites the rows it is built on.                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT THE "PLAN TODAY" COLUMN IS, PRECISELY ──────────────────────────────┐
 * │ The allowance the partner reports for the line RIGHT NOW, summed across   │
 * │ its zones. It is not a historical figure — no partner tells us what the   │
 * │ plan was last March — and the footnote on this page says so. Comparing    │
 * │ today's allowance against a period's top-ups is exactly the question      │
 * │ being asked ("is this plan the right size"), and labelling it as anything │
 * │ else would be inventing a measurement.                                    │
 * │                                                                          │
 * │ An unknown allowance prints "—" and never 0: 0 would make every line with │
 * │ an unreported plan look undersized.                                       │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export function MobileReportPage() {
  const { t } = useTranslation();
  const [report, setReport] = useState<SimRechargeReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [months, setMonths] = useState(6);

  const window = useMemo(() => {
    const to = new Date();
    const from = new Date(
      Date.UTC(to.getUTCFullYear(), to.getUTCMonth() - (months - 1), 1, 0, 0, 0),
    );
    return { from: from.toISOString(), to: to.toISOString() };
  }, [months]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setReport(await simApi.report(window.from, window.to));
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setLoading(false);
    }
  }, [window]);

  useEffect(() => {
    void load();
  }, [load]);

  const undersized = useMemo(
    () => (report?.rows ?? []).filter(suggestsPlanChange).length,
    [report],
  );
  const mixedCurrency = (report?.currencies.length ?? 0) > 1;

  return (
    <div className="p-6">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">{t('mobile.report.title')}</h1>
          <p className="mt-1 text-sm text-text-secondary">{t('mobile.report.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <select
            className="rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            value={months}
            onChange={(e) => setMonths(Number(e.target.value))}
          >
            {[1, 3, 6, 12].map((m) => (
              <option key={m} value={m}>
                {t('mobile.report.lastMonths', { count: m })}
              </option>
            ))}
          </select>
          <a href={simApi.reportCsvUrl(window.from, window.to)}>
            <Button variant="secondary" size="sm">
              <Download size={14} className="mr-1.5" />
              {t('mobile.report.csv')}
            </Button>
          </a>
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RefreshCw size={14} className="mr-1.5" />
            {t('common.refresh')}
          </Button>
        </div>
      </div>

      {report ? (
        <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Summary label={t('mobile.report.totalTopUps')} value={String(report.totalRecharges)} />
          <Summary
            label={t('mobile.report.totalCost')}
            value={
              // The banner below already says the totals are not comparable —
              // and the tile printed one anyway, stamped with whichever
              // currency sorted first. A refusal is the only honest value.
              report.totalCostCents === null || report.currencies.length > 1
                ? '—'
                : `${(report.totalCostCents / 100).toFixed(2)} ${report.currencies[0] ?? ''}`
            }
            detail={
              report.currencies.length > 1
                ? t('mobile.report.mixedShort', { list: report.currencies.join(', ') })
                : report.unpricedCount > 0
                  ? t('mobile.report.unpricedDetail', { count: report.unpricedCount })
                  : undefined
            }
            tone={report.unpricedCount > 0 || report.currencies.length > 1 ? 'warn' : 'neutral'}
          />
          <Summary label={t('mobile.report.sites')} value={String(report.rows.length)} />
          <Summary
            label={t('mobile.report.undersized')}
            value={String(undersized)}
            tone={undersized > 0 ? 'warn' : 'neutral'}
            detail={t('mobile.report.undersizedDetail')}
          />
        </div>
      ) : null}

      {mixedCurrency ? (
        // Rule 4 of the report service, surfaced: a single total across two
        // currencies is arithmetic on incompatible units.
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3 text-xs text-text-secondary">
          <AlertTriangle size={14} className="mt-0.5 shrink-0 text-status-ssl-warning" />
          <p>{t('mobile.report.mixedCurrency', { list: report?.currencies.join(', ') })}</p>
        </div>
      ) : null}

      <Panel title={t('mobile.report.tableTitle')}>
        {loading ? (
          <div className="flex h-48 items-center justify-center">
            <LoadingSpinner />
          </div>
        ) : !report || report.rows.length === 0 ? (
          <EmptyState message={t('mobile.report.empty')} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs text-text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.site')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.msisdn')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.report.topUps')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.report.months')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.report.basePlan')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.report.toppedUp')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.report.cost')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.report.lastTopUp')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.report.signal')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {report.rows.map((r) => {
                  const flag = suggestsPlanChange(r);
                  return (
                    <tr
                      key={`${r.siteId ?? 'none'}-${r.msisdn}`}
                      className={cn('hover:bg-bg-hover', flag && 'bg-status-ssl-warning/5')}
                    >
                      <td className="px-4 py-2 text-text-primary">
                        {r.siteName ?? <span className="text-text-muted">—</span>}
                        {r.tenantName ? (
                          <span className="block text-[11px] text-text-muted">{r.tenantName}</span>
                        ) : null}
                      </td>
                      <td className="px-4 py-2">
                        {r.simId === null ? (
                          <span className="font-mono text-text-secondary">{r.msisdn}</span>
                        ) : (
                          <Link
                            to={`/mobile/lines/${r.simId}`}
                            className="font-mono text-text-primary hover:text-accent"
                          >
                            {r.msisdn}
                          </Link>
                        )}
                      </td>
                      <td className="px-4 py-2 text-right tabular-nums text-text-primary">
                        {r.rechargeCount}
                      </td>
                      <td className="px-4 py-2 text-right tabular-nums">
                        <span className={flag ? 'font-semibold text-status-ssl-warning' : ''}>
                          {r.monthsWithRecharge}
                        </span>
                        <span className="text-text-muted"> / {months}</span>
                      </td>
                      <td className="px-4 py-2 text-right">
                        <DataAmount mb={r.basePlanMb} />
                      </td>
                      <td className="px-4 py-2 text-right">
                        <DataAmount mb={r.totalMb} />
                        {/* The same honesty as the cost column: a top-up
                            recorded with no volume is counted, never folded
                            into the sum as zero. */}
                        {r.unknownVolumeCount > 0 ? (
                          <span className="block text-[11px] text-status-ssl-warning">
                            {t('mobile.report.unknownVolumeRows', { count: r.unknownVolumeCount })}
                          </span>
                        ) : null}
                      </td>
                      <td className="px-4 py-2 text-right">
                        <Money cents={r.totalCostCents} currency={r.currency} />
                        {r.unpricedCount > 0 ? (
                          <span className="block text-[11px] text-status-ssl-warning">
                            {t('mobile.report.unpricedRows', { count: r.unpricedCount })}
                          </span>
                        ) : null}
                      </td>
                      <td className="px-4 py-2 text-xs">
                        <When iso={r.lastRechargeAt} />
                      </td>
                      <td className="px-4 py-2">
                        {flag ? (
                          <span className="inline-flex items-center gap-1 rounded-full border border-status-ssl-warning/30 bg-status-ssl-warning/15 px-2 py-0.5 text-[11px] text-status-ssl-warning">
                            <TrendingUp size={11} />
                            {t('mobile.report.planFlag')}
                          </span>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="flex items-start gap-2 border-t border-border px-4 py-2 text-[11px] text-text-muted">
          <Info size={12} className="mt-0.5 shrink-0" />
          {t('mobile.report.basePlanFootnote')}
        </p>
      </Panel>
    </div>
  );
}

function Summary({
  label,
  value,
  detail,
  tone = 'neutral',
}: {
  label: string;
  value: string;
  detail?: string;
  tone?: 'neutral' | 'warn';
}) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="text-sm text-text-secondary">{label}</div>
      <div
        className={cn(
          'mt-1 text-2xl font-bold tabular-nums',
          tone === 'warn' ? 'text-status-ssl-warning' : 'text-text-primary',
        )}
      >
        {value}
      </div>
      <div className="mt-1 h-4 text-[11px] text-text-muted">{detail ?? ''}</div>
    </div>
  );
}
