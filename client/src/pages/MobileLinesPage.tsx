import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { RefreshCw, Search, Sparkles } from 'lucide-react';
import toast from 'react-hot-toast';
import { formatData } from '@obliwan/shared';
import { simApi, errorMessageOf, type SimLineListItem } from '@/api/sim.api';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { DataAmount, EmptyState, VerdictBadge, When } from '@/components/mobile/SimBits';
import { cn } from '@/utils/cn';

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

/**
 * ObliWAN F9 — the SIM inventory.
 *
 * ┌─ THE POOL IS A FIRST-CLASS FILTER, NOT A HIDDEN STATE ────────────────────┐
 * │ A line the partner reported and nobody has attached to a customer sits in │
 * │ the pool (`tenant_id IS NULL`). It is only visible from the master        │
 * │ workspace — the server decides that, not this screen — and it is the      │
 * │ queue of work: every pooled line is a SIM somebody is paying for that no  │
 * │ customer is being billed for. Hiding it behind a default filter is how it │
 * │ stays unbilled.                                                           │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Filtering by verdict is done SERVER-SIDE for `verdict` and client-side for
 * nothing: the threshold that produces a verdict is resolved per line from a
 * setting plus an override, and duplicating that resolution here would be a
 * second implementation of the rule that decides whether money gets spent.
 */
export function MobileLinesPage() {
  const { t } = useTranslation();
  const [lines, setLines] = useState<SimLineListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [verdict, setVerdict] = useState<'' | 'ok' | 'low' | 'unknown'>('');
  const [assignment, setAssignment] = useState<'' | 'assigned' | 'pool'>('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setLines(
        await simApi.lines({
          verdict: verdict || undefined,
          assignment: assignment || undefined,
          search: search.trim() || undefined,
          limit: 2000,
        }),
      );
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setLoading(false);
    }
  }, [verdict, assignment, search]);

  useEffect(() => {
    void load();
  }, [load]);

  const poolCount = useMemo(() => lines.filter((l) => l.tenantId === null).length, [lines]);

  return (
    <div className="p-6">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">{t('mobile.lines.title')}</h1>
          <p className="mt-1 text-sm text-text-secondary">
            {t('mobile.lines.count', { count: lines.length })}
            {poolCount > 0 ? ` · ${t('mobile.lines.poolCount', { count: poolCount })}` : ''}
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => void load()}>
          <RefreshCw size={14} className="mr-1.5" />
          {t('common.refresh')}
        </Button>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search
            size={14}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted"
          />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('mobile.lines.searchPlaceholder')}
            className="pl-8"
          />
        </div>
        <select
          className={selectClass}
          value={verdict}
          onChange={(e) => setVerdict(e.target.value as typeof verdict)}
        >
          <option value="">{t('mobile.lines.allVerdicts')}</option>
          <option value="low">{t('mobile.verdict.low')}</option>
          <option value="ok">{t('mobile.verdict.ok')}</option>
          <option value="unknown">{t('mobile.verdict.unknown')}</option>
        </select>
        <select
          className={selectClass}
          value={assignment}
          onChange={(e) => setAssignment(e.target.value as typeof assignment)}
        >
          <option value="">{t('mobile.lines.allAssignments')}</option>
          <option value="assigned">{t('mobile.lines.assigned')}</option>
          <option value="pool">{t('mobile.lines.pool')}</option>
        </select>
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-bg-secondary">
        {loading ? (
          <div className="flex h-48 items-center justify-center">
            <LoadingSpinner />
          </div>
        ) : lines.length === 0 ? (
          <EmptyState message={t('mobile.lines.empty')} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs text-text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.msisdn')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.site')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.operator')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.lines.remaining')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.zone')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.state')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.auto')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.seen')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {lines.map((l) => (
                  <tr key={l.id} className="hover:bg-bg-hover">
                    <td className="px-4 py-2">
                      <Link
                        to={`/mobile/lines/${l.id}`}
                        className="font-mono text-text-primary hover:text-accent"
                      >
                        {l.msisdn}
                      </Link>
                      {l.label ? (
                        <span className="ml-2 text-xs text-text-muted">{l.label}</span>
                      ) : null}
                    </td>
                    <td className="px-4 py-2">
                      {l.tenantId === null ? (
                        // The pool badge. Loud on purpose: an unassigned line is
                        // a SIM being paid for and billed to nobody.
                        <span className="rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11px] text-accent">
                          {t('mobile.lines.pool')}
                        </span>
                      ) : (
                        <span className="text-text-secondary">
                          {l.siteName ?? t('mobile.noSite')}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">
                      {l.operator ?? <span className="text-text-muted">—</span>}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <DataAmount mb={l.worstZone?.restMb ?? null} />
                      <span className="block text-[11px] text-text-muted">
                        {t('mobile.ofThreshold', { value: formatData(l.thresholdMb) })}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-text-secondary">
                      {l.worstZone?.zone ?? <span className="text-text-muted">—</span>}
                    </td>
                    <td className="px-4 py-2">
                      <VerdictBadge verdict={l.verdict} stale={l.stale} />
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={cn(
                          'text-xs',
                          l.autoRechargeEnabled ? 'text-status-up' : 'text-text-muted',
                        )}
                      >
                        {l.autoRechargeEnabled ? (
                          <>
                            <Sparkles size={12} className="mr-1 inline" />
                            {t('mobile.lines.autoOn')}
                          </>
                        ) : (
                          t('mobile.lines.autoOff')
                        )}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs">
                      <When iso={l.lastSeenAt} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
