import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import {
  Boxes,
  FileCode2,
  Gauge,
  Play,
  ShieldAlert,
  SquareStack,
  Unplug,
  X,
} from 'lucide-react';
import { CAPABILITIES } from '@obliwan/shared';
import { baselineApi } from '@/api/baseline.api';
import { errorMessageOf } from '@/api/change.api';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { scanTextForSecrets } from '@/utils/secretScan';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import { BRAND_LABELS } from '@/types/intent';
import type {
  BaselineFact,
  BaselineRun,
  ConformanceRow,
  FactClass,
  FactCluster,
  TemplateDraft,
} from '@/types/baseline';
import { draftCoverage } from '@/types/baseline';

/**
 * `BaselinePage` — fleet takeover / Golden Site (M12, killer K8).
 *
 * ┌─ THE THREE NUMBERS THIS SCREEN REFUSES TO ROUND ─────────────────────────┐
 * │ 1. "PRESENT ON 27 / 30", never "90 %". The denominator is the whole      │
 * │    argument: a fact common to 27 of 30 sites is a baseline, the same     │
 * │    fact on 27 of 27 is a tautology, and both print as 90 % and 100 % in  │
 * │    a way nobody interrogates. The fraction is shown raw, everywhere.     │
 * │ 2. DEVICES WITHOUT A SNAPSHOT are counted apart from the run's device    │
 * │    count. A mine over 12 of 30 boxes that presents itself as a mine over │
 * │    30 produces a template "present on 12/12" — a unanimous baseline      │
 * │    drawn from a minority.                                                │
 * │ 3. TEMPLATE COVERAGE is two counts, and the UNCOVERED facts are          │
 * │    enumerable. §5/M12's acceptance test is "≥ 80 % des lignes couvertes  │
 * │    ET chaque écart listé et classable"; a takeover tool that reports     │
 * │    only its successes leaves the other 20 % to be discovered the day a   │
 * │    site breaks.                                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── MARKING A SPECIFICITY IS WRITING A REASON ───────────────────────────────
 * The "client specificity" gesture opens a dialog with a mandatory reason and
 * records who wrote it. An ignore button with no reason field is how a fleet
 * accumulates four hundred unexplained exceptions in a year, at which point the
 * conformance score is decoration. The reason is what turns a divergence into a
 * documented exception, and only a documented exception stops costing points.
 *
 * ── NO LLM, AND THE SCREEN SAYS SO ──────────────────────────────────────────
 * §5/M12: hierarchical clustering, weighted Jaccard, in a worker, WITHOUT an
 * LLM. `cohesion` and `similarity` are numbers the operator can argue with, and
 * the cut threshold is exposed on the run form — because he is the only one who
 * knows whether his two clusters are one customer with two eras of installer.
 *
 * ── D3 ──────────────────────────────────────────────────────────────────────
 * Nothing here touches an equipment. A draft is PROPOSED to `/templates`;
 * publishing happens there, applying happens through `change_jobs`, and this
 * page has no button that reaches either.
 */

type Tab = 'clusters' | 'conformance';

const FACT_CLASS_STYLES: Record<FactClass, string> = {
  common: 'border-status-up/50 bg-status-up/10 text-status-up',
  variable: 'border-accent/50 bg-accent/10 text-accent',
  outlier: 'border-status-ssl-warning/50 bg-status-ssl-warning/10 text-status-ssl-warning',
  exception: 'border-border bg-bg-tertiary text-text-muted',
};

export function BaselinePage() {
  const { t, i18n } = useTranslation();
  const { hasCapability, isAdmin } = useAuthStore();
  const canRead = isAdmin() || hasCapability(CAPABILITIES.CONFIG_READ);
  const canPromote = isAdmin() || hasCapability(CAPABILITIES.TEMPLATE_WRITE);

  const [runs, setRuns] = useState<BaselineRun[] | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [runId, setRunId] = useState<number | null>(null);
  const [threshold, setThreshold] = useState(0.35);
  const [starting, setStarting] = useState(false);

  const [tab, setTab] = useState<Tab>('clusters');
  const [clusters, setClusters] = useState<FactCluster[] | null>(null);
  const [clusterId, setClusterId] = useState<number | null>(null);
  const [facts, setFacts] = useState<BaselineFact[] | null>(null);
  const [factFilter, setFactFilter] = useState<FactClass | ''>('');
  const [draft, setDraft] = useState<TemplateDraft | null>(null);
  const [conformance, setConformance] = useState<ConformanceRow[] | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [exceptionFor, setExceptionFor] = useState<BaselineFact | null>(null);

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' }),
    [i18n.language],
  );

  const run = useMemo(() => (runs ?? []).find((r) => r.id === runId) ?? null, [runs, runId]);
  const cluster = useMemo(
    () => (clusters ?? []).find((c) => c.id === clusterId) ?? null,
    [clusters, clusterId],
  );

  const loadRuns = useCallback(async () => {
    setLoading(true);
    try {
      const rows = await baselineApi.listRuns();
      if (rows === null) { setUnavailable(true); setRuns(null); }
      else {
        setUnavailable(false);
        setRuns(rows);
        setRunId((prev) => (prev !== null && rows.some((r) => r.id === prev) ? prev : rows[0]?.id ?? null));
      }
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('baseline.loadFailed'));
      setRuns([]);
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => { void loadRuns(); }, [loadRuns]);

  useEffect(() => {
    if (runId === null) { setClusters(null); return; }
    void (async () => {
      setDetailLoading(true);
      try {
        const rows = await baselineApi.listClusters(runId);
        setClusters(rows);
        setClusterId(rows && rows.length > 0 ? rows[0].id : null);
        if (tab === 'conformance') setConformance(await baselineApi.conformance(runId));
      } catch (err) {
        toast.error(errorMessageOf(err) ?? t('baseline.loadFailed'));
      } finally {
        setDetailLoading(false);
      }
    })();
  }, [runId, tab, t]);

  const loadCluster = useCallback(async (id: number) => {
    setDetailLoading(true);
    try {
      setFacts(await baselineApi.listFacts(id, factFilter || undefined));
      setDraft(await baselineApi.getDraft(id));
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('baseline.loadFailed'));
    } finally {
      setDetailLoading(false);
    }
  }, [factFilter, t]);

  useEffect(() => {
    if (clusterId === null) { setFacts(null); setDraft(null); return; }
    void loadCluster(clusterId);
  }, [clusterId, loadCluster]);

  const start = useCallback(async () => {
    setStarting(true);
    try {
      const created = await baselineApi.startRun({ threshold });
      if (created === null) { toast.error(t('baseline.endpointUnavailable')); return; }
      toast.success(t('baseline.runStarted'));
      await loadRuns();
      setRunId(created.id);
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('baseline.startFailed'));
    } finally {
      setStarting(false);
    }
  }, [threshold, loadRuns, t]);

  if (!canRead) {
    return (
      <div className="p-6">
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <ShieldAlert size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('baseline.forbidden')}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="mb-5">
        <h1 className="font-display text-2xl font-semibold text-text-primary">{t('nav.baseline')}</h1>
        <p className="mt-1 text-sm text-text-muted">{t('baseline.subtitle')}</p>
      </div>

      {unavailable ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('baseline.endpointUnavailable')}</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
            {t('baseline.endpointUnavailableHint')}
          </p>
        </div>
      ) : (
        <div className="grid gap-4 xl:grid-cols-[20rem_1fr]">
          {/* ── runs ── */}
          <aside className="min-w-0 space-y-3">
            <section className="rounded-lg border border-border bg-bg-secondary p-3">
              <h2 className="mb-2 text-sm font-semibold text-text-primary">{t('baseline.newRun')}</h2>
              <label className="block text-[12px] text-text-secondary">
                {t('baseline.threshold')}
                <input
                  type="range"
                  min={0.05}
                  max={0.8}
                  step={0.05}
                  value={threshold}
                  onChange={(e) => setThreshold(Number(e.target.value))}
                  className="mt-1 w-full accent-accent"
                />
                <span className="font-mono text-[11px] text-text-muted">{threshold.toFixed(2)}</span>
              </label>
              <p className="mt-1 text-[11px] text-text-muted">{t('baseline.thresholdHint')}</p>
              <Button
                variant="primary"
                size="sm"
                className="mt-2 w-full"
                loading={starting}
                onClick={() => void start()}
              >
                <Play size={14} className="mr-1.5" />
                {t('baseline.startRun')}
              </Button>
            </section>

            <section className="rounded-lg border border-border bg-bg-secondary">
              <h2 className="border-b border-border px-3 py-2 text-sm font-semibold text-text-primary">
                {t('baseline.runs')}
              </h2>
              {loading && runs === null ? (
                <div className="flex justify-center py-8"><LoadingSpinner /></div>
              ) : (runs ?? []).length === 0 ? (
                <p className="px-3 py-4 text-[12px] text-text-muted">{t('baseline.noRun')}</p>
              ) : (
                <ul className="divide-y divide-border">
                  {(runs ?? []).map((r) => (
                    <li key={r.id}>
                      <button
                        onClick={() => setRunId(r.id)}
                        className={cn(
                          'w-full px-3 py-2 text-left transition-colors',
                          r.id === runId ? 'bg-bg-active' : 'hover:bg-bg-hover',
                        )}
                      >
                        <span className="flex items-center gap-2 text-[13px] text-text-primary">
                          {t('baseline.runLabel', { id: r.id })}
                          <span className="ml-auto font-mono text-[10px] uppercase tracking-wider text-text-muted">
                            {t(`baseline.runState.${r.state}`)}
                          </span>
                        </span>
                        <span className="mt-0.5 block text-[11px] text-text-muted">
                          {t('baseline.runSummary', { devices: r.deviceCount, clusters: r.clusterCount })}
                        </span>
                        {/* Never folded into `deviceCount` — see the header. */}
                        {r.devicesWithoutSnapshot > 0 && (
                          <span className="mt-0.5 block text-[11px] text-status-ssl-warning">
                            {t('baseline.excluded', { count: r.devicesWithoutSnapshot })}
                          </span>
                        )}
                        <span className="mt-0.5 block font-mono text-[10px] text-text-muted">
                          {r.startedAt ? dateFmt.format(new Date(r.startedAt)) : '—'}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </aside>

          {/* ── clusters / conformance ── */}
          <div className="min-w-0 space-y-3">
            {run === null ? (
              <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
                <Boxes size={28} className="mx-auto mb-2 text-text-muted" />
                <p className="text-sm text-text-muted">{t('baseline.selectRun')}</p>
              </div>
            ) : (
              <>
                <div className="flex flex-wrap gap-1 border-b border-border">
                  {([
                    { id: 'clusters' as const, icon: <SquareStack size={14} />, label: t('baseline.tabs.clusters') },
                    { id: 'conformance' as const, icon: <Gauge size={14} />, label: t('baseline.tabs.conformance') },
                  ]).map((def) => (
                    <button
                      key={def.id}
                      onClick={() => setTab(def.id)}
                      className={cn(
                        'flex items-center gap-1.5 border-b-2 px-3 py-2 text-[13px] transition-colors',
                        tab === def.id
                          ? 'border-accent text-text-primary'
                          : 'border-transparent text-text-secondary hover:text-text-primary',
                      )}
                    >
                      {def.icon}
                      {def.label}
                    </button>
                  ))}
                </div>

                {detailLoading ? (
                  <div className="flex justify-center py-12"><LoadingSpinner /></div>
                ) : tab === 'conformance' ? (
                  <ConformancePanel rows={conformance} dateFmt={dateFmt} />
                ) : clusters === null ? (
                  <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
                    <p className="text-sm text-text-muted">{t('baseline.clustersUnavailable')}</p>
                  </div>
                ) : clusters.length === 0 ? (
                  <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
                    <p className="text-sm text-text-muted">{t('baseline.noCluster')}</p>
                    <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">{t('baseline.noClusterHint')}</p>
                  </div>
                ) : (
                  <>
                    <div className="flex flex-wrap gap-2">
                      {clusters.map((c) => (
                        <button
                          key={c.id}
                          onClick={() => setClusterId(c.id)}
                          className={cn(
                            'rounded-md border px-2.5 py-1.5 text-left text-[12px] transition-colors',
                            c.id === clusterId
                              ? 'border-accent/50 bg-accent/10 text-accent'
                              : 'border-border bg-bg-tertiary text-text-secondary hover:text-text-primary',
                          )}
                        >
                          <span className="block font-medium">{c.name}</span>
                          <span className="block text-[10px] text-text-muted">
                            {t('baseline.clusterChip', {
                              members: c.members.length,
                              brand: c.brand ? BRAND_LABELS[c.brand] : '—',
                            })}
                          </span>
                        </button>
                      ))}
                    </div>

                    {cluster && (
                      <ClusterPanel
                        cluster={cluster}
                        facts={facts}
                        factFilter={factFilter}
                        onFactFilter={setFactFilter}
                        draft={draft}
                        canPromote={canPromote}
                        onMarkException={(fact) => setExceptionFor(fact)}
                        onClearException={async (fact) => {
                          if (!(await baselineApi.removeException(fact.id))) {
                            toast.error(t('baseline.endpointUnavailable'));
                            return;
                          }
                          void loadCluster(cluster.id);
                        }}
                        onPromote={async () => {
                          const id = await baselineApi.promote(cluster.id, cluster.name);
                          if (id === null) { toast.error(t('baseline.promoteUnavailable')); return; }
                          toast.success(t('baseline.promoted'));
                        }}
                      />
                    )}
                  </>
                )}
              </>
            )}
          </div>
        </div>
      )}

      {exceptionFor && (
        <ExceptionDialog
          fact={exceptionFor}
          onClose={() => setExceptionFor(null)}
          onSubmit={async (reason) => {
            const updated = await baselineApi.addException(exceptionFor.id, reason);
            setExceptionFor(null);
            if (updated === null) { toast.error(t('baseline.endpointUnavailable')); return; }
            if (clusterId !== null) void loadCluster(clusterId);
          }}
        />
      )}
    </div>
  );
}

// ── Cluster ─────────────────────────────────────────────────────────────────

function ClusterPanel({
  cluster,
  facts,
  factFilter,
  onFactFilter,
  draft,
  canPromote,
  onMarkException,
  onClearException,
  onPromote,
}: {
  cluster: FactCluster;
  facts: BaselineFact[] | null;
  factFilter: FactClass | '';
  onFactFilter: (v: FactClass | '') => void;
  draft: TemplateDraft | null;
  canPromote: boolean;
  onMarkException: (fact: BaselineFact) => void;
  onClearException: (fact: BaselineFact) => void;
  onPromote: () => void;
}) {
  const { t } = useTranslation();
  const coverage = draft ? draftCoverage(draft) : null;

  return (
    <div className="space-y-3">
      <section className="rounded-lg border border-border bg-bg-secondary p-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="font-display text-lg font-semibold text-text-primary">{cluster.name}</h2>
          <span className="font-mono text-[11px] text-text-muted">
            {t('baseline.cohesion', { value: (cluster.cohesion * 100).toFixed(0) })}
          </span>
          <span className="text-[11px] text-text-muted">
            {t('baseline.factCounts', {
              common: cluster.commonFactCount,
              variable: cluster.variableFactCount,
            })}
          </span>
        </div>

        <ul className="mt-2 flex flex-wrap gap-1.5">
          {cluster.members.map((m) => (
            <li key={m.deviceId}>
              <Link
                to={`/devices/${m.deviceId}`}
                className="inline-flex items-center gap-1 rounded border border-border bg-bg-tertiary px-1.5 py-0.5 text-[11px] text-text-secondary hover:text-accent"
                title={t('baseline.memberHint', {
                  similarity: (m.similarity * 100).toFixed(0),
                  divergences: m.divergenceCount,
                })}
              >
                {anonHostname(m.deviceName ?? `#${m.deviceId}`)}
                <span className="font-mono text-[9px] text-text-muted">
                  {(m.similarity * 100).toFixed(0)}%
                </span>
              </Link>
            </li>
          ))}
        </ul>

        {cluster.variables.length > 0 && (
          <div className="mt-3">
            <h3 className="text-[11px] uppercase tracking-wider text-text-muted">
              {t('baseline.deducedVariables')}
            </h3>
            <ul className="mt-1 space-y-1">
              {cluster.variables.map((v) => (
                <li key={v.name} className="flex flex-wrap items-center gap-2 text-[12px]">
                  <span className="font-mono text-accent">{`{{ ${v.name} }}`}</span>
                  <span className="font-mono text-[10px] text-text-muted">{v.factPath}</span>
                  <span className="ml-auto text-[11px] text-text-muted">
                    {/* Raw fraction. Never a percentage — see the header. */}
                    {t('baseline.presentOn', { present: v.presentOn, total: cluster.members.length })}
                    {' · '}
                    {t('baseline.distinctValues', { count: v.distinctCount })}
                  </span>
                  {v.sampleValues.length === 0 && v.distinctCount > 0 && (
                    <span className="rounded border border-border bg-bg-tertiary px-1 py-0.5 text-[10px] text-text-muted">
                      {t('baseline.samplesWithheld')}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      {/* ── the draft ── */}
      <section className="rounded-lg border border-border bg-bg-secondary">
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
          <h3 className="flex items-center gap-1.5 text-sm font-semibold text-text-primary">
            <FileCode2 size={14} className="text-text-muted" />
            {t('baseline.draftTitle')}
          </h3>
          {draft && (
            <span className="font-mono text-[11px] text-text-muted">
              {t('baseline.coverage', { covered: draft.coveredFacts, total: draft.totalFacts })}
              {coverage !== null ? ` (${(coverage * 100).toFixed(0)} %)` : ''}
            </span>
          )}
          {canPromote && draft && (
            <Button variant="secondary" size="sm" className="ml-auto" onClick={onPromote}>
              {t('baseline.promote')}
            </Button>
          )}
        </div>
        {draft === null ? (
          <p className="px-3 py-4 text-[12px] text-text-muted">{t('baseline.draftUnavailable')}</p>
        ) : (
          <div className="p-3">
            <DraftBody body={draft.body} />
            {draft.uncoveredFactIds.length > 0 && (
              <p className="mt-2 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 px-2.5 py-1.5 text-[11px] text-status-ssl-warning">
                {t('baseline.uncovered', { count: draft.uncoveredFactIds.length })}
              </p>
            )}
            {!canPromote && (
              <p className="mt-2 text-[11px] text-text-muted">{t('baseline.promoteForbidden')}</p>
            )}
          </div>
        )}
      </section>

      {/* ── the facts ── */}
      <section className="rounded-lg border border-border bg-bg-secondary">
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
          <h3 className="text-sm font-semibold text-text-primary">{t('baseline.factsTitle')}</h3>
          <select
            value={factFilter}
            onChange={(e) => onFactFilter(e.target.value as FactClass | '')}
            className="ml-auto rounded-md border border-border bg-bg-tertiary px-2 py-1 text-[12px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
          >
            <option value="">{t('baseline.allClasses')}</option>
            {(['common', 'variable', 'outlier', 'exception'] as FactClass[]).map((k) => (
              <option key={k} value={k}>{t(`baseline.factClass.${k}`)}</option>
            ))}
          </select>
        </div>
        {facts === null ? (
          <p className="px-3 py-4 text-[12px] text-text-muted">{t('baseline.factsUnavailable')}</p>
        ) : facts.length === 0 ? (
          <p className="px-3 py-4 text-[12px] text-text-muted">{t('baseline.factsEmpty')}</p>
        ) : (
          <ul className="divide-y divide-border">
            {facts.map((fact) => (
              <FactRow
                key={fact.id}
                fact={fact}
                onMark={() => onMarkException(fact)}
                onClear={() => onClearException(fact)}
              />
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function FactRow({
  fact,
  onMark,
  onClear,
}: {
  fact: BaselineFact;
  onMark: () => void;
  onClear: () => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);

  // §8.2 — a fact summary is a redacted line of somebody's configuration.
  const hits = scanTextForSecrets(fact.summary, 1);

  return (
    <li className="px-3 py-2">
      <div className="flex flex-wrap items-start gap-2">
        <span
          className={cn(
            'shrink-0 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
            FACT_CLASS_STYLES[fact.klass],
          )}
        >
          {t(`baseline.factClass.${fact.klass}`)}
        </span>
        <div className="min-w-0 flex-1">
          <p className="font-mono text-[11px] text-text-muted">
            {fact.resource}
            {fact.semKey ? ` · ${fact.semKey}` : ''}
          </p>
          {hits.length > 0 ? (
            <p className="mt-0.5 inline-flex items-center gap-1.5 rounded border border-status-ssl-expired/60 bg-status-ssl-expired/15 px-2 py-0.5 text-[11px] text-status-ssl-expired">
              <ShieldAlert size={11} />
              {t('baseline.factRedacted', { keys: hits.map((h) => h.label).join(', ') })}
            </p>
          ) : (
            <p className="mt-0.5 break-words font-mono text-[12px] text-text-secondary">{fact.summary}</p>
          )}
        </div>
        {/* THE NUMBER. Raw fraction, always. */}
        <span className="shrink-0 font-mono text-[12px] text-text-primary" title={t('baseline.presentOnHint')}>
          {fact.presentOn} / {fact.total || '?'}
        </span>
      </div>

      {fact.exception && (
        <p className="mt-1 rounded-md border border-border bg-bg-tertiary px-2 py-1 text-[11px] text-text-secondary">
          {t('baseline.exceptionBy', {
            who: fact.exception.createdByName ?? '—',
            reason: fact.exception.reason,
          })}
        </p>
      )}

      <div className="mt-1 flex flex-wrap items-center gap-2">
        {fact.missingFrom.length > 0 && (
          <button
            onClick={() => setOpen((v) => !v)}
            className="text-[11px] text-text-muted hover:text-text-primary"
          >
            {t('baseline.missingFrom', { count: fact.missingFrom.length })}
          </button>
        )}
        {fact.klass === 'outlier' && !fact.exception && (
          <button onClick={onMark} className="text-[11px] text-accent hover:underline">
            {t('baseline.markException')}
          </button>
        )}
        {fact.exception && (
          <button onClick={onClear} className="text-[11px] text-text-muted hover:text-status-ssl-expired">
            {t('baseline.clearException')}
          </button>
        )}
      </div>

      {open && (
        // "3 sites differ" is a statistic; naming them is a work list.
        <ul className="mt-1 flex flex-wrap gap-1.5">
          {fact.missingFrom.map((d) => (
            <li key={d.deviceId}>
              <Link
                to={`/devices/${d.deviceId}`}
                className="rounded border border-border bg-bg-tertiary px-1.5 py-0.5 text-[11px] text-text-secondary hover:text-accent"
              >
                {anonHostname(d.deviceName ?? `#${d.deviceId}`)}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

function DraftBody({ body }: { body: string }) {
  const { t } = useTranslation();
  const hits = scanTextForSecrets(body, 3);

  if (hits.length > 0) {
    return (
      <p className="inline-flex items-center gap-1.5 rounded border border-status-ssl-expired/60 bg-status-ssl-expired/15 px-2 py-1 text-[11px] text-status-ssl-expired">
        <ShieldAlert size={12} />
        {t('baseline.draftSecret', { keys: hits.map((h) => h.label).join(', ') })}
      </p>
    );
  }

  return (
    <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-md border border-border bg-bg-primary/40 p-2 font-mono text-[11px] text-text-secondary">
      {body || t('baseline.draftEmpty')}
    </pre>
  );
}

// ── Conformance ─────────────────────────────────────────────────────────────

function ConformancePanel({
  rows,
  dateFmt,
}: {
  rows: ConformanceRow[] | null;
  dateFmt: Intl.DateTimeFormat;
}) {
  const { t } = useTranslation();

  if (rows === null) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
        <p className="text-sm text-text-muted">{t('baseline.conformanceUnavailable')}</p>
      </div>
    );
  }
  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
        <p className="text-sm text-text-muted">{t('baseline.conformanceEmpty')}</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
      <table className="w-full min-w-[44rem] text-left text-[13px]">
        <thead className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
          <tr>
            <th className="px-3 py-2 font-medium">{t('baseline.col.device')}</th>
            <th className="px-3 py-2 font-medium">{t('baseline.col.cluster')}</th>
            <th className="px-3 py-2 font-medium">{t('baseline.col.score')}</th>
            <th className="px-3 py-2 font-medium">{t('baseline.col.divergences')}</th>
            <th className="px-3 py-2 font-medium">{t('baseline.col.exceptions')}</th>
            <th className="px-3 py-2 font-medium">{t('baseline.col.evaluated')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {rows.map((row) => (
            <tr key={row.deviceId} className="hover:bg-bg-hover">
              <td className="px-3 py-2">
                <Link to={`/devices/${row.deviceId}`} className="text-text-primary hover:text-accent">
                  {anonHostname(row.deviceName ?? `#${row.deviceId}`)}
                </Link>
                <span className="block text-[11px] text-text-muted">{row.siteName ?? '—'}</span>
              </td>
              <td className="px-3 py-2 text-text-secondary">{row.clusterName ?? '—'}</td>
              <td className="px-3 py-2 font-mono">
                {row.score === null ? (
                  // Never 0 — "no snapshot" is not "totally non-conformant".
                  <span className="text-text-muted" title={t('baseline.noScoreHint')}>
                    {t('baseline.noScore')}
                  </span>
                ) : (
                  <span
                    className={cn(
                      row.score >= 0.9 ? 'text-status-up'
                        : row.score >= 0.7 ? 'text-status-ssl-warning'
                          : 'text-status-ssl-expired',
                    )}
                  >
                    {(row.score * 100).toFixed(0)} %
                  </span>
                )}
              </td>
              <td className="px-3 py-2 font-mono text-text-secondary">{row.divergences}</td>
              <td className="px-3 py-2 font-mono text-text-muted">{row.documentedExceptions}</td>
              <td className="px-3 py-2 font-mono text-[11px] text-text-muted">
                {row.evaluatedAt ? dateFmt.format(new Date(row.evaluatedAt)) : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * "Client specificity" — a documented exception, not an ignore.
 *
 * The reason field is required and the submit button stays disabled without it.
 * That is the entire difference between an exception register somebody can read
 * in two years and four hundred silent dismissals.
 */
function ExceptionDialog({
  fact,
  onClose,
  onSubmit,
}: {
  fact: BaselineFact;
  onClose: () => void;
  onSubmit: (reason: string) => void;
}) {
  const { t } = useTranslation();
  const [reason, setReason] = useState('');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-lg rounded-lg border border-border bg-bg-secondary p-4 shadow-xl">
        <div className="mb-3 flex items-start justify-between gap-2">
          <h2 className="text-sm font-semibold text-text-primary">{t('baseline.exceptionTitle')}</h2>
          <button onClick={onClose} className="rounded p-1 text-text-muted hover:bg-bg-hover hover:text-text-primary">
            <X size={14} />
          </button>
        </div>

        <p className="mb-2 break-words rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 font-mono text-[11px] text-text-secondary">
          {fact.resource}{fact.semKey ? ` · ${fact.semKey}` : ''}
        </p>
        <p className="mb-2 text-[12px] text-text-muted">
          {t('baseline.presentOn', { present: fact.presentOn, total: fact.total || 0 })}
        </p>

        <label className="block text-[12px] text-text-secondary" htmlFor="baseline-reason">
          {t('baseline.exceptionReason')}
        </label>
        <textarea
          id="baseline-reason"
          rows={3}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder={t('baseline.exceptionReasonPlaceholder')}
          className="mt-1 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
        />
        <p className="mt-1 text-[11px] text-text-muted">{t('baseline.exceptionReasonHint')}</p>

        <div className="mt-3 flex justify-end gap-2">
          <Button variant="secondary" size="sm" onClick={onClose}>{t('common.cancel')}</Button>
          <Button
            variant="primary"
            size="sm"
            disabled={reason.trim().length === 0}
            onClick={() => onSubmit(reason.trim())}
          >
            {t('baseline.exceptionSave')}
          </Button>
        </div>
      </div>
    </div>
  );
}
