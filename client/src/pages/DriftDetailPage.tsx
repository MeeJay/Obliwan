import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  ArrowLeft,
  FileCode,
  FileText,
  Lock,
  RotateCw,
} from 'lucide-react';
import { CAPABILITIES } from '@obliwan/shared';
import { driftApi } from '@/api/drift.api';
import { attributionApi } from '@/api/logs.api';
import { AttributionBanner } from '@/components/drift/AttributionBanner';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { DiffViewer } from '@/components/common/DiffViewer';
import { ConfigDiff } from '@/components/config/ConfigDiff';
import { CauseChip, DriftStatusBadge, SeverityBadge } from '@/components/config/DriftBadges';
import { cn } from '@/utils/cn';
import type {
  DriftFinding,
  DriftRunDetail,
  SemanticChange,
  SemanticChangeSet,
} from '@/types/config';
import type { AttributionView } from '@/types/logs';

/**
 * `DriftDetailPage` — spec §4.2, literally: "diff sémantique à gauche, patch
 * textuel à droite".
 *
 * The layout is the product argument D1 made visible. The SEMANTIC diff is the
 * truth: it is what the engine reasoned about, what a plan will act on, and
 * what survives a cosmetic reformatting of the export. The textual patch is the
 * COMPLEMENT — it is there because an operator recognises his own configuration
 * in the router's own words, not in ours. Putting the text on the left, or
 * giving it the larger pane, would quietly reinstate textual drift as the
 * product's notion of truth, which is the one thing this milestone exists to
 * replace.
 *
 * ── THE ATTRIBUTION BANNER (M8, K6) ─────────────────────────────────────────
 * The slot below the header used to say "arrives at M8". It now carries the
 * real verdict — and the reason the whole thing is a four-state type rather
 * than a name is unchanged: a guessed attribution is worse than none, because
 * somebody will act on the name it shows. `unattributed` is rendered in words,
 * a shared account is marked as shared, and a build with no attribution service
 * says "not available" rather than "nobody".
 *
 * The banner is scoped to the RUN by default and to the selected FINDING when
 * there is one. Those are genuinely different questions — "who touched this box
 * in this window" and "who made this specific change" — and the banner labels
 * which one it is answering rather than letting the operator assume.
 *
 * "GENERATE A PLAN" lands at M5 with the templates and the compiler. The button
 * is rendered DISABLED with its milestone, rather than omitted, because an
 * operator looking at a drift needs to know that turning it into a change is a
 * thing the product will do — and needs to not be able to click it today.
 */

export function DriftDetailPage() {
  const { id } = useParams<{ id: string }>();
  const runId = Number(id);
  const { t, i18n } = useTranslation();
  const { hasCapability, isAdmin } = useAuthStore();

  const [run, setRun] = useState<DriftRunDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [ignoreNotice, setIgnoreNotice] = useState<string | null>(null);
  const [runAttribution, setRunAttribution] = useState<AttributionView | null>(null);
  const [findingAttribution, setFindingAttribution] = useState<AttributionView | null>(null);

  const canManage = isAdmin() || hasCapability(CAPABILITIES.DRIFT_MANAGE);

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'short' }),
    [i18n.language],
  );
  const when = useCallback((iso: string | null) => {
    if (!iso) return '—';
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? '—' : dateFmt.format(d);
  }, [dateFmt]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const detail = await driftApi.getRun(runId);
      if (!detail) setNotFound(true);
      else setRun(detail);
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (status === 404) setNotFound(true);
      else {
        const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
        setError(message ?? t('drift.loadFailed'));
      }
    } finally {
      setLoading(false);
    }
  }, [runId, t]);

  useEffect(() => {
    if (!Number.isFinite(runId)) { setNotFound(true); setLoading(false); return; }
    void load();
    // `attributionApi` never throws: an absent service reports itself as
    // unavailable, which the banner renders as "not available" and never as
    // "unattributed".
    void attributionApi.ofRun(runId).then(setRunAttribution);
  }, [runId, load]);

  /** `DriftFinding[]` -> the one shape `ConfigDiff` renders. */
  const changeSet: SemanticChangeSet | null = useMemo(() => {
    if (!run) return null;
    return {
      changes: run.findings.map(toChange),
      inertMoveCount: run.inertMoveCount,
      outOfScopeCount: run.outOfScopeCount,
      suppressed: run.suppressed,
      scope: run.scope,
      orderAnalysis: run.orderAnalysis,
      origin: 'server',
    };
  }, [run]);

  const selected = useMemo(
    () => changeSet?.changes.find((c) => c.id === selectedId) ?? null,
    [changeSet, selectedId],
  );

  // Finding-level attribution. Deliberately NOT merged into the run-level one:
  // "who touched this box in this window" and "who made this exact change" are
  // two questions, and answering the second with the first is how a shared
  // account becomes a named engineer.
  useEffect(() => {
    const findingId = selected?.findingId;
    if (findingId === undefined) { setFindingAttribution(null); return; }
    let cancelled = false;
    void attributionApi.ofFinding(findingId).then((view) => {
      if (!cancelled) setFindingAttribution(view);
    });
    return () => { cancelled = true; };
  }, [selected]);

  /**
   * Optimistic, and deliberately so: the row leaves the list on the same frame
   * the operator clicks. Triage that costs a round trip per finding is triage
   * nobody performs, and R3 is lost on the screen long before it is lost in the
   * engine. If the write fails, the row comes back and says why.
   */
  const toggleIgnore = useCallback(async (change: SemanticChange, ignored: boolean) => {
    if (!run || change.findingId === undefined) return;
    const findingId = change.findingId;
    setRun((prev) => prev && ({
      ...prev,
      findings: prev.findings.map((f) => (f.id === findingId ? { ...f, ignored } : f)),
    }));
    try {
      const persisted = await driftApi.ignoreFinding(findingId, ignored);
      if (!persisted) setIgnoreNotice(t('drift.ignoreNotPersisted'));
    } catch (err) {
      setRun((prev) => prev && ({
        ...prev,
        findings: prev.findings.map((f) => (f.id === findingId ? { ...f, ignored: !ignored } : f)),
      }));
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setIgnoreNotice(message ?? t('drift.ignoreFailed'));
    }
  }, [run, t]);

  if (loading && !run) {
    return <div className="flex h-full items-center justify-center"><LoadingSpinner size="lg" /></div>;
  }

  if (notFound) {
    return (
      <div className="p-6">
        <Link to="/drift" className="mb-4 inline-flex items-center gap-1.5 text-sm text-text-muted hover:text-text-primary">
          <ArrowLeft size={14} /> {t('nav.drift')}
        </Link>
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <p className="text-sm text-text-muted">{t('drift.runNotFound')}</p>
        </div>
      </div>
    );
  }

  if (!run || !changeSet) {
    return (
      <div className="p-6">
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
          {error ?? t('drift.loadFailed')}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* ── header ── */}
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <Link
            to="/drift"
            className="mb-2 inline-flex items-center gap-1.5 text-sm text-text-muted hover:text-text-primary"
          >
            <ArrowLeft size={14} /> {t('nav.drift')}
          </Link>
          <h1 className="flex flex-wrap items-center gap-2 text-2xl font-semibold text-text-primary">
            <Link to={`/devices/${run.deviceId}`} className="hover:text-accent">
              {run.deviceName ?? `#${run.deviceId}`}
            </Link>
            <DriftStatusBadge status={run.status} />
            <SeverityBadge severity={run.maxSeverity} />
            <CauseChip cause={run.cause} />
          </h1>
          <p className="mt-1 text-sm text-text-muted">
            {t('drift.detail.window', { start: when(run.startedAt), end: when(run.finishedAt) })}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
          {run.snapshotId !== null && (
            <Link to={`/config/${run.deviceId}`}>
              <Button variant="secondary" size="sm">
                <FileCode size={14} className="mr-1.5" />
                {t('drift.detail.openSnapshot')}
              </Button>
            </Link>
          )}
          {/* M5. Disabled, milestone announced — never omitted, never clickable. */}
          <button
            type="button"
            disabled
            aria-disabled="true"
            title={t('drift.detail.planLocked', { milestone: 'M5' })}
            className="inline-flex cursor-not-allowed select-none items-center gap-1.5 rounded-md border border-border bg-bg-tertiary px-3 py-1.5 text-sm text-text-muted opacity-50"
          >
            {t('drift.detail.generatePlan')}
            <Lock size={11} />
            <span className="font-mono text-[10px] tracking-wider">M5</span>
          </button>
        </div>
      </div>

      {/* ── run metadata ── */}
      <section className="mb-4 rounded-lg border border-border bg-bg-secondary p-4">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-[12px] md:grid-cols-5">
          <Meta label={t('drift.detail.scope')} value={t(`drift.scope.${run.scope}`)} />
          <Meta label={t('config.meta.ncmVersion')} value={String(run.ncmVersion)} />
          <Meta label={t('config.meta.epoch')} value={run.normalizationEpoch ?? '—'} />
          <Meta
            label={t('config.meta.orderAnalysis')}
            value={t(`ncm.orderAnalysis.${run.orderAnalysis}`)}
            tone={run.orderAnalysis === 'full' ? undefined : 'warn'}
          />
          <Meta label={t('drift.detail.snapshot')} value={run.snapshotId ? `#${run.snapshotId}` : '—'} />
        </dl>

        {run.scope === 'managed_only' && (
          <p className="mt-3 text-[12px] text-text-muted">{t('drift.detail.managedOnlyHint')}</p>
        )}

        {run.orderAnalysis !== 'full' && (
          <p className="mt-2 flex items-start gap-1.5 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 px-3 py-2 text-[12px] text-status-ssl-warning">
            <AlertTriangle size={13} className="mt-0.5 shrink-0" />
            {t('drift.detail.orderDegraded')}
          </p>
        )}

        {run.status === 'error' && run.errorReason && (
          <p className="mt-2 rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/5 px-3 py-2 font-mono text-[12px] text-status-ssl-expired">
            {run.errorReason}
          </p>
        )}
        {run.status === 'unreachable' && (
          <p className="mt-2 rounded-md border border-border bg-bg-tertiary px-3 py-2 text-[12px] text-text-muted">
            {t('drift.detail.unreachableHint')}
          </p>
        )}
      </section>

      {/* ── attribution banner — M8 / K6 ── */}
      <div className="mb-4">
        <p className="mb-1 text-[11px] uppercase tracking-wider text-text-muted">
          {findingAttribution
            ? t('drift.detail.attributionScopeFinding')
            : t('drift.detail.attributionScopeRun')}
        </p>
        {findingAttribution ?? runAttribution ? (
          <AttributionBanner
            attribution={(findingAttribution ?? runAttribution)!}
            deviceId={run.deviceId}
          />
        ) : (
          <div className="rounded-lg border border-dashed border-border bg-bg-secondary/60 px-4 py-3 text-[12px] text-text-muted">
            {t('attribution.loading')}
          </div>
        )}
      </div>

      {/* ── §4.2: semantic left, textual right ── */}
      <div className="grid gap-4 xl:grid-cols-2">
        <ConfigDiff
          set={changeSet}
          selectedId={selectedId}
          onSelect={(c) => setSelectedId(c.id)}
          onToggleIgnore={canManage ? (c, ignored) => { void toggleIgnore(c, ignored); } : undefined}
          notice={ignoreNotice}
        />

        <div className="min-w-0">
          {!selected ? (
            <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
              <FileText size={26} className="mx-auto mb-2 text-text-muted" />
              <p className="text-sm text-text-muted">{t('drift.detail.pickFinding')}</p>
              <p className="mx-auto mt-1 max-w-md text-xs text-text-muted">
                {t('drift.detail.textualIsComplement')}
              </p>
            </div>
          ) : selected.textPatch ? (
            <DiffViewer
              patch={selected.textPatch}
              leftLabel={t('config.diff.intent')}
              rightLabel={t('config.diff.actual')}
              bodyClassName="max-h-[70vh]"
            />
          ) : (
            <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
              <p className="text-sm text-text-muted">{t('drift.detail.noPatch')}</p>
              <p className="mx-auto mt-1 max-w-md text-xs text-text-muted">
                {t('drift.detail.noPatchHint')}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── helpers ─────────────────────────────────────────────────────────────────

function Meta({ label, value, tone }: { label: string; value: string; tone?: 'warn' }) {
  return (
    <div>
      <dt className="text-[10px] uppercase tracking-wider text-text-muted">{label}</dt>
      <dd className={cn('mt-0.5 font-mono text-[12px]', tone === 'warn' ? 'text-status-ssl-warning' : 'text-text-primary')}>
        {value}
      </dd>
    </div>
  );
}

function toChange(f: DriftFinding): SemanticChange {
  return {
    id: String(f.id),
    kind: f.kind,
    resource: f.resource,
    semKey: f.semKey,
    path: f.path,
    severity: f.severity,
    matchMethod: f.matchMethod,
    matchConfidence: f.matchConfidence,
    predicateChanged: f.predicateChanged,
    fieldDiffs: f.fieldDiffs,
    crossed: f.crossed,
    // The diff is oriented intent -> observed, so `intentValue` is the "before"
    // column and `actualValue` the "after". Same orientation as the snapshot
    // comparison, so one legend covers both.
    beforeValue: f.intentValue,
    afterValue: f.actualValue,
    textPatch: f.textPatch,
    ignored: f.ignored,
    ignoredByRule: f.ignoredByRule,
    origin: 'server',
    findingId: f.id,
  };
}
