import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  HelpCircle,
  KeyRound,
  Receipt,
  RefreshCw,
  Signal,
  SignalLow,
  Wallet,
} from 'lucide-react';
import toast from 'react-hot-toast';
import {
  CAPABILITIES,
  formatData,
  suggestsPlanChange,
  type SimFleetSummary,
  type SimPlatformInfo,
  type SimRecharge,
  type SimRechargeReportRow,
} from '@obliwan/shared';
import { simApi, errorMessageOf, type SimLineListItem } from '@/api/sim.api';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import {
  DataAmount,
  EmptyState,
  Money,
  Panel,
  RechargeStatusBadge,
  StatCard,
  VerdictBadge,
  When,
} from '@/components/mobile/SimBits';

/**
 * ObliWAN F9 — the 4G dashboard.
 *
 * ┌─ WHAT THIS SCREEN REFUSES TO DO ──────────────────────────────────────────┐
 * │ Show a green fleet when it cannot see the fleet.                          │
 * │                                                                          │
 * │ `unknownLines` has its own tile, next to a tile counting partner accounts │
 * │ that cannot authenticate — because the second is almost always the        │
 * │ EXPLANATION of the first, and an operator who sees them apart spends a    │
 * │ morning on the wrong problem. A dead token, a renamed partner field and a │
 * │ rate limit all look like "nothing to report" on a dashboard that folds    │
 * │ unknown into ok.                                                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE COVERAGE STRIP IS DATA, NOT DECORATION ──────────────────────────────┐
 * │ `SIM_PLATFORM_CATALOG` is served by the API and rendered verbatim. A      │
 * │ partner ObliWAN cannot read says so ON THIS SCREEN, in the same place an  │
 * │ operator looks for balances — the same choice `CwmpCoverage` makes for    │
 * │ RouterOS and SonicOS having no CWMP client.                               │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export function MobileDashboardPage() {
  const { t } = useTranslation();
  const hasCapability = useAuthStore((s) => s.hasCapability);
  const canApprove = hasCapability(CAPABILITIES.SIM_RECHARGE);

  const [summary, setSummary] = useState<SimFleetSummary | null>(null);
  const [platforms, setPlatforms] = useState<SimPlatformInfo[]>([]);
  const [lowLines, setLowLines] = useState<SimLineListItem[]>([]);
  const [pending, setPending] = useState<SimRecharge[]>([]);
  const [topSites, setTopSites] = useState<SimRechargeReportRow[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      // Six months, not this month: the number worth acting on is how many
      // DISTINCT MONTHS a site needed a top-up, and a one-month window cannot
      // express recurrence at all. Same endpoint as the report screen, so the
      // two can never disagree about who costs the most.
      const to = new Date();
      const from = new Date(Date.UTC(to.getUTCFullYear(), to.getUTCMonth() - 5, 1));

      const [s, p, low, queue, report] = await Promise.all([
        simApi.summary(),
        simApi.platforms(),
        simApi.lines({ verdict: 'low', limit: 50 }),
        simApi.recharges({ status: 'proposed,approved', limit: 20 }),
        simApi.report(from.toISOString(), to.toISOString()),
      ]);
      setSummary(s);
      setPlatforms(p);
      setLowLines(low);
      setPending(queue);
      // The report already sorts by cost, then recurrence, then volume.
      setTopSites(report.rows.slice(0, 8));
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading && !summary) {
    return (
      <div className="flex h-64 items-center justify-center">
        <LoadingSpinner />
      </div>
    );
  }

  const blind = (summary?.unknownLines ?? 0) > 0;

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">{t('mobile.title')}</h1>
          <p className="mt-1 text-sm text-text-secondary">{t('mobile.subtitle')}</p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => void load()}>
          <RefreshCw size={14} className="mr-1.5" />
          {t('common.refresh')}
        </Button>
      </div>

      {/* The two tiles that must be read together — see the header. */}
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard
          icon={<Signal size={16} />}
          label={t('mobile.stat.lines')}
          value={summary?.totalLines ?? 0}
          detail={t('mobile.stat.linesDetail', {
            assigned: summary?.assignedLines ?? 0,
            pool: summary?.unassignedLines ?? 0,
          })}
        />
        <StatCard
          icon={<SignalLow size={16} />}
          label={t('mobile.stat.low')}
          value={summary?.lowLines ?? 0}
          tone={(summary?.lowLines ?? 0) > 0 ? 'warn' : 'good'}
          detail={t('mobile.stat.lowDetail')}
        />
        <StatCard
          icon={<HelpCircle size={16} />}
          label={t('mobile.stat.unknown')}
          value={summary?.unknownLines ?? 0}
          tone={blind ? 'bad' : 'neutral'}
          detail={
            // "Not readable" splits into two causes with different fixes:
            // never polled, and no longer polled. The second is the one an
            // operator can act on today, so it is the one the tile names.
            (summary?.staleLines ?? 0) > 0
              ? t('mobile.stat.unknownStale', { count: summary?.staleLines ?? 0 })
              : t('mobile.stat.unknownDetail')
          }
        />
        <StatCard
          icon={<Wallet size={16} />}
          label={t('mobile.stat.pending')}
          value={summary?.pendingProposals ?? 0}
          tone={(summary?.pendingProposals ?? 0) > 0 ? 'warn' : 'neutral'}
          detail={t('mobile.stat.pendingDetail')}
        />
        <StatCard
          icon={<Receipt size={16} />}
          label={t('mobile.stat.month')}
          value={summary?.rechargesThisMonth ?? 0}
          detail={
            // ┌─ THREE ANSWERS, AND ONLY ONE OF THEM IS A NUMBER ───────────┐
            // │ The first draft printed `(cents/100).toFixed(2)` with NO   │
            // │ currency at all, over a sum the server had taken across    │
            // │ currencies. Migration 032 decision 8 names that exact       │
            // │ failure: a number with no unit is a number somebody reads   │
            // │ as euros and invoices as euros.                             │
            // │                                                            │
            // │ The server now returns `null` both when nothing is priced   │
            // │ and when several currencies appear, and hands back the      │
            // │ currency list so the unit can actually be printed.           │
            // └────────────────────────────────────────────────────────────┘
            summary === null
              ? ''
              : summary.costThisMonthCents === null
                ? (summary.currencies?.length ?? 0) > 1
                  ? t('mobile.stat.monthMixed')
                  : t('mobile.stat.monthUnpriced')
                : // A priced total that still hides unpriced rows is a partial
                  // sum presented as a complete one. `unpricedThisMonth`
                  // crossed the wire and was never rendered.
                  `${(summary.costThisMonthCents / 100).toFixed(2)} ${summary.currencies[0] ?? ''}` +
                  (summary.unpricedThisMonth > 0
                    ? ` · ${t('mobile.stat.monthPlusUnpriced', { count: summary.unpricedThisMonth })}`
                    : '')
          }
        />
      </div>

      {/* A partner that cannot authenticate is why balances went stale. */}
      {summary && (summary.failedAccounts > 0 || summary.staleAccounts > 0) ? (
        <div className="mb-6 flex items-start gap-3 rounded-lg border border-status-down/40 bg-status-down/5 p-4">
          <KeyRound size={18} className="mt-0.5 shrink-0 text-status-down" />
          <div className="text-sm">
            <p className="font-medium text-text-primary">{t('mobile.accountsUnhealthy.title')}</p>
            <p className="mt-1 text-text-secondary">
              {t('mobile.accountsUnhealthy.body', {
                failed: summary.failedAccounts,
                stale: summary.staleAccounts,
              })}
            </p>
          </div>
        </div>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel
          title={t('mobile.lowPanel.title')}
          action={
            <Link to="/mobile/lines" className="text-xs text-accent hover:underline">
              {t('mobile.lowPanel.all')}
            </Link>
          }
        >
          {lowLines.length === 0 ? (
            <EmptyState message={t('mobile.lowPanel.empty')} />
          ) : (
            <ul className="divide-y divide-border">
              {lowLines.slice(0, 8).map((l) => (
                <li key={l.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
                  <div className="min-w-0">
                    <Link
                      to={`/mobile/lines/${l.id}`}
                      className="block truncate font-mono text-sm text-text-primary hover:text-accent"
                    >
                      {l.msisdn}
                    </Link>
                    <p className="truncate text-xs text-text-muted">
                      {l.siteName ?? t('mobile.noSite')} · {l.operator ?? t('mobile.noOperator')}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <span className="text-right text-sm">
                      <DataAmount mb={l.worstZone?.restMb ?? null} />
                      <span className="block text-[11px] text-text-muted">
                        {t('mobile.ofThreshold', { value: formatData(l.thresholdMb) })}
                      </span>
                    </span>
                    <VerdictBadge verdict={l.verdict} stale={l.stale} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title={t('mobile.queuePanel.title')}
          action={
            <Link to="/mobile/recharges" className="text-xs text-accent hover:underline">
              {t('mobile.queuePanel.all')}
            </Link>
          }
        >
          {pending.length === 0 ? (
            <EmptyState message={t('mobile.queuePanel.empty')} />
          ) : (
            <ul className="divide-y divide-border">
              {pending.slice(0, 8).map((r) => (
                <li key={r.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
                  <div className="min-w-0">
                    <p className="truncate font-mono text-sm text-text-primary">{r.msisdn}</p>
                    <p className="truncate text-xs text-text-muted">
                      {r.siteName ?? t('mobile.noSite')} · <When iso={r.proposedAt} />
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <Money cents={r.costCents} currency={r.currency} />
                    <RechargeStatusBadge status={r.status} />
                  </div>
                </li>
              ))}
            </ul>
          )}
          {!canApprove && pending.length > 0 ? (
            <p className="border-t border-border px-4 py-2 text-[11px] text-text-muted">
              {t('mobile.queuePanel.noPermission')}
            </p>
          ) : null}
        </Panel>
      </div>

      {/* ── Who costs money ────────────────────────────────────────────────
          A top-up is bought at a worse price per megabyte than the allowance it
          tops up, so a site appearing here every month is a purchasing problem
          rather than an incident. ObliWAN changes no plan; it shows the case. */}
      <Panel
        className="mt-6"
        title={t('mobile.topSites.title')}
        action={
          <Link to="/mobile/report" className="text-xs text-accent hover:underline">
            {t('mobile.topSites.all')}
          </Link>
        }
      >
        {topSites.length === 0 ? (
          <EmptyState message={t('mobile.topSites.empty')} />
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
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {topSites.map((r) => (
                  <tr
                    key={`${r.siteId ?? 'none'}-${r.msisdn}`}
                    className={suggestsPlanChange(r) ? 'bg-status-ssl-warning/5' : undefined}
                  >
                    <td className="px-4 py-2 text-text-primary">
                      {r.siteName ?? <span className="text-text-muted">—</span>}
                    </td>
                    <td className="px-4 py-2">
                      {r.simId === null ? (
                        <span className="font-mono text-xs text-text-secondary">{r.msisdn}</span>
                      ) : (
                        <Link
                          to={`/mobile/lines/${r.simId}`}
                          className="font-mono text-xs text-text-primary hover:text-accent"
                        >
                          {r.msisdn}
                        </Link>
                      )}
                    </td>
                    <td className="px-4 py-2 text-right tabular-nums text-text-primary">
                      {r.rechargeCount}
                    </td>
                    <td className="px-4 py-2 text-right tabular-nums">
                      <span
                        className={
                          suggestsPlanChange(r)
                            ? 'font-semibold text-status-ssl-warning'
                            : 'text-text-secondary'
                        }
                      >
                        {r.monthsWithRecharge} / 6
                      </span>
                    </td>
                    <td className="px-4 py-2 text-right">
                      <DataAmount mb={r.basePlanMb} />
                    </td>
                    <td className="px-4 py-2 text-right">
                      <DataAmount mb={r.totalMb} />
                    </td>
                    <td className="px-4 py-2 text-right">
                      <Money cents={r.totalCostCents} currency={r.currency} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="border-t border-border px-4 py-2 text-[11px] text-text-muted">
          {t('mobile.topSites.footnote')}
        </p>
      </Panel>

      {/* Coverage, straight from the shared catalogue. */}
      <Panel className="mt-6" title={t('mobile.coverage.title')}>
        <div className="grid gap-px bg-border sm:grid-cols-2">
          {platforms.map((p) => (
            <div key={p.platform} className="bg-bg-secondary p-4">
              <div className="mb-1 flex items-center gap-2">
                <span className="text-sm font-medium text-text-primary">{p.label}</span>
                <span
                  className={
                    p.readImplemented
                      ? 'rounded-full border border-status-up/30 bg-status-up/15 px-2 py-0.5 text-[11px] text-status-up'
                      : 'rounded-full border border-border bg-text-muted/10 px-2 py-0.5 text-[11px] text-text-secondary'
                  }
                >
                  {p.readImplemented ? t('mobile.coverage.read') : t('mobile.coverage.noRead')}
                </span>
                <span
                  className={
                    p.rechargeImplemented
                      ? 'rounded-full border border-status-up/30 bg-status-up/15 px-2 py-0.5 text-[11px] text-status-up'
                      : 'rounded-full border border-border bg-text-muted/10 px-2 py-0.5 text-[11px] text-text-secondary'
                  }
                >
                  {p.rechargeImplemented
                    ? t('mobile.coverage.buys')
                    : t('mobile.coverage.noBuy')}
                </span>
              </div>
              <p className="text-xs leading-relaxed text-text-secondary">{p.note}</p>
            </div>
          ))}
        </div>
      </Panel>

      <div className="mt-4 flex items-start gap-2 text-xs text-text-muted">
        <AlertTriangle size={14} className="mt-0.5 shrink-0" />
        <p>{t('mobile.manualBuyNote')}</p>
      </div>
    </div>
  );
}
