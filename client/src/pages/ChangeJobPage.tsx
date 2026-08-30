import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { ArrowLeft, Ban, RotateCw, ShieldX, Unplug, User } from 'lucide-react';
import { hasWriteCommitted } from '@obliwan/shared';
import { changeApi, errorMessageOf, isRouteAbsent, safetyNetOfLevel } from '@/api/change.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { JobKindChip, JobStatusBadge } from '@/components/change/JobStatusBadge';
import { DeadmanPanel } from '@/components/change/DeadmanPanel';
import { JobTimeline } from '@/components/change/JobTimeline';
import { SafetyNetBadge } from '@/components/change/SafetyNetBadge';
import { GuardVerdictPanel } from '@/components/plan/GuardVerdictPanel';
import { GuardVerdictBadge, RiskBadge } from '@/components/plan/RiskBadge';
import { useJobSocket } from '@/hooks/useJobSocket';
import { useSocketStore } from '@/store/socketStore';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import type { ChangeJobDetail, ChangeJobStepView, ChangeJobView } from '@/types/change';

/**
 * `ChangeJobPage` — one job, live.
 *
 * ── THE PAGE IS ORGANISED AROUND THE FIVE MINUTES OF SOAK ───────────────────
 * During the soak the operator is not reading; he is watching. So the layout
 * puts the two things that answer "is my site safe right now" above everything
 * else:
 *
 *   1. the STATUS, large;
 *   2. the DEAD-MAN panel — armed / soaking with a countdown / disarmed.
 *
 * The step timeline, the command output and the guard verdict come after. They
 * are what he reads afterwards, or when something has gone wrong.
 *
 * ── SOCKET FIRST, POLL AS A BACKSTOP ────────────────────────────────────────
 * Steps arrive over `wan:job:step` in the `job:{id}` room. The page ALSO
 * re-fetches every 10 s while the job is active, and says so in the header
 * when the socket is down. A live screen that silently stops updating is worse
 * than one that admits it: an operator reading a frozen "applying" believes the
 * change is still in flight when the box may already have rolled back.
 *
 * ── THE ABORT BUTTON DISAPPEARS AT THE RIGHT MOMENT ─────────────────────────
 * `hasWriteCommitted()` from `@obliwan/shared` is the frontier: once the job is
 * `applying` or beyond, bytes have reached a production router and cancelling
 * is not a thing that exists. The button is REMOVED rather than disabled, and
 * a sentence explains why — a greyed-out Abort during an apply reads as a UI
 * bug and invites somebody to go looking for another way to stop it.
 */

export function ChangeJobPage() {
  const { id } = useParams<{ id: string }>();
  const jobId = Number(id);
  const { t } = useTranslation();
  const socketStatus = useSocketStore((s) => s.status);

  const [job, setJob] = useState<ChangeJobDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [aborting, setAborting] = useState(false);

  const load = useCallback(async () => {
    if (!Number.isInteger(jobId) || jobId <= 0) return;
    setLoadError(null);
    try {
      const detail = await changeApi.getJob(jobId);
      if (detail === null) setNotFound(true);
      else { setJob(detail); setNotFound(false); }
    } catch (err) {
      if (isRouteAbsent(err)) { setUnavailable(true); return; }
      setLoadError(errorMessageOf(err) ?? t('change.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [jobId, t]);

  useEffect(() => { void load(); }, [load]);

  const isActive = job !== null && !['succeeded', 'rolled_back', 'failed', 'aborted'].includes(job.status);

  // Backstop poll. Only while the job is live — a terminal job never changes
  // again and polling it forever is how a dashboard left open all night becomes
  // a load problem.
  useEffect(() => {
    if (!isActive) return;
    const handle = window.setInterval(() => { void load(); }, 10_000);
    return () => window.clearInterval(handle);
  }, [isActive, load]);

  const mergeJob = useCallback((incoming: ChangeJobView) => {
    setJob((prev) => {
      if (!prev || prev.id !== incoming.id) return prev;
      return { ...prev, ...incoming };
    });
  }, []);

  const mergeStep = useCallback((step: ChangeJobStepView) => {
    setJob((prev) => {
      if (!prev) return prev;
      if (step.jobId !== 0 && step.jobId !== prev.id) return prev;
      // Keyed by (attempt, seq): a retry writes a SECOND trace and must not
      // overwrite the failed first pass, which is the post-mortem.
      const idx = prev.steps.findIndex(
        (s) => s.attempt === step.attempt && s.seq === step.seq,
      );
      const steps = prev.steps.slice();
      if (idx === -1) steps.push(step);
      else steps[idx] = { ...steps[idx], ...step };
      return { ...prev, steps };
    });
  }, []);

  useJobSocket({
    jobId: Number.isInteger(jobId) && jobId > 0 ? jobId : undefined,
    onJob: mergeJob,
    onStep: mergeStep,
    onArmed: () => toast.success(t('change.toast.armed')),
    onSoaking: () => toast(t('change.toast.soaking')),
    onDisarmed: () => toast.success(t('change.toast.disarmed')),
    onRolledBack: () => toast(t('change.toast.rolledBack'), { icon: '↩' }),
  });

  const abort = useCallback(async () => {
    if (!job) return;
    setAborting(true);
    try {
      const ok = await changeApi.abortJob(job.id, t('change.abortReason'));
      if (!ok) toast.error(t('change.apiUnavailable'));
      else { toast.success(t('change.abortRequested')); void load(); }
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('change.abortFailed'));
    } finally {
      setAborting(false);
    }
  }, [job, load, t]);

  const canAbort = useMemo(
    () => job !== null && isActive && !hasWriteCommitted(job.status),
    [job, isActive],
  );

  if (unavailable) {
    return (
      <div className="p-6">
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('change.endpointUnavailable')}</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
            {t('change.endpointUnavailableHint')}
          </p>
        </div>
      </div>
    );
  }

  if (loading && !job) {
    return <div className="flex justify-center py-20"><LoadingSpinner size="lg" /></div>;
  }

  if (notFound || !job) {
    return (
      <div className="p-6">
        <Link to="/changes" className="mb-3 inline-flex items-center gap-1 text-[12px] text-text-muted hover:text-text-primary">
          <ArrowLeft size={12} />
          {t('change.backToList')}
        </Link>
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center text-sm text-text-muted">
          {loadError ?? t('change.jobNotFound')}
        </div>
      </div>
    );
  }

  const netLevel = safetyNetOfLevel(job.armedLevel ?? job.safetyLevel);

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <Link to="/changes" className="mb-1 inline-flex items-center gap-1 text-[12px] text-text-muted hover:text-text-primary">
            <ArrowLeft size={12} />
            {t('change.backToList')}
          </Link>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="font-display text-2xl font-semibold text-text-primary">
              {t('change.jobTitle', { id: job.id })}
            </h1>
            <JobStatusBadge status={job.status} size="lg" />
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-text-muted">
            <Link to={`/devices/${job.deviceId}`} className="font-mono hover:text-accent">
              {anonHostname(job.deviceName ?? `#${job.deviceId}`)}
            </Link>
            {job.siteName && <span>· {job.siteName}</span>}
            <JobKindChip kind={job.kind} />
            {job.riskLevel && <RiskBadge risk={job.riskLevel} />}
            <SafetyNetBadge level={netLevel} />
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
          {canAbort && (
            <Button variant="danger" size="sm" loading={aborting} onClick={() => void abort()}>
              <Ban size={14} className="mr-1.5" />
              {t('change.abort')}
            </Button>
          )}
        </div>
      </div>

      {isActive && socketStatus !== 'connected' && (
        <p className="mb-4 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-2.5 text-[12px] text-status-ssl-warning">
          {t('change.socketDownLive')}
        </p>
      )}

      {isActive && !canAbort && (
        <p className="mb-4 rounded-md border border-border bg-bg-secondary p-2.5 text-[12px] text-text-secondary">
          {t('change.cannotAbort')}
        </p>
      )}

      {/* 2 — the dead-man, high. */}
      <DeadmanPanel job={job} className="mb-5" />

      {job.status === 'rolled_back' && (
        <div className="mb-5 rounded-lg border border-status-ssl-warning/50 bg-status-ssl-warning/10 p-4">
          <h2 className="text-sm font-semibold text-status-ssl-warning">
            {t('change.rolledBackTitle')}
          </h2>
          <p className="mt-1 text-[13px] text-text-secondary">{t('change.rolledBackBody')}</p>
        </div>
      )}

      {job.errorMessage && (
        <div className="mb-5 rounded-lg border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-4">
          <h2 className="text-sm font-semibold text-status-ssl-expired">
            {t('change.errorTitle')}
            {job.errorKind && <span className="ml-2 font-mono text-[11px]">{job.errorKind}</span>}
          </h2>
          <p className="mt-1 text-[13px] text-text-secondary">{job.errorMessage}</p>
        </div>
      )}

      {/* The override, if there was one. It is displayed prominently and
          permanently: a job that bypassed the guard must never look like an
          ordinary job in the history six months later. */}
      {job.overrideReason && (
        <div className="mb-5 rounded-lg border border-status-ssl-expired/50 bg-status-ssl-expired/5 p-4">
          <h2 className="flex items-center gap-1.5 text-sm font-semibold text-status-ssl-expired">
            <ShieldX size={15} />
            {t('change.overrideTitle')}
          </h2>
          <p className="mt-1.5 whitespace-pre-wrap text-[13px] text-text-primary">
            {job.overrideReason}
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-3 font-mono text-[11px] text-text-muted">
            {job.overriddenByName && (
              <span className="inline-flex items-center gap-1">
                <User size={11} />
                {job.overriddenByName}
              </span>
            )}
            {job.overriddenAt && <span>{new Date(job.overriddenAt).toLocaleString()}</span>}
            {job.guardVerdict && <GuardVerdictBadge state={job.guardVerdict} />}
          </div>
        </div>
      )}

      {job.degradedConfirmedAt && (
        <div className="mb-5 rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-3">
          <h2 className="text-[12px] font-semibold text-status-ssl-expired">
            {t('change.degradedConfirmedTitle')}
          </h2>
          <p className="mt-1 text-[12px] text-text-secondary">
            {t('change.degradedConfirmedBody')}
          </p>
          <div className="mt-1 font-mono text-[11px] text-text-muted">
            {[job.degradedConfirmedByName, new Date(job.degradedConfirmedAt).toLocaleString()]
              .filter(Boolean)
              .join(' · ')}
          </div>
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <h2 className="mb-2 text-sm font-semibold text-text-primary">
            {t('change.timeline.title')}
          </h2>
          <JobTimeline steps={job.steps} showExpected={isActive} />
        </div>

        <aside className="space-y-4">
          <section className="rounded-lg border border-border bg-bg-secondary p-4">
            <h2 className="mb-2 text-[11px] font-medium uppercase tracking-wider text-text-muted">
              {t('change.facts')}
            </h2>
            <dl className="space-y-1.5 text-[12px]">
              <Fact label={t('change.fact.uuid')} value={job.uuid} mono />
              <Fact label={t('change.fact.attempt')} value={String(job.attempt)} mono />
              <Fact label={t('change.fact.requestedBy')} value={job.requestedByName ?? '—'} />
              <Fact
                label={t('change.fact.backup')}
                value={
                  job.preflightBackupId !== null
                    ? `#${job.preflightBackupId}`
                    : t('change.fact.noBackup')
                }
                mono
                tone={job.preflightBackupId === null ? 'bad' : undefined}
              />
              <Fact
                label={t('change.fact.baseState')}
                value={job.baseStateHash ? job.baseStateHash.slice(0, 16) : '—'}
                mono
              />
              <Fact label={t('change.fact.created')} value={fmt(job.createdAt)} mono />
              <Fact label={t('change.fact.started')} value={fmt(job.startedAt)} mono />
              <Fact label={t('change.fact.finished')} value={fmt(job.finishedAt)} mono />
              <Fact label={t('change.fact.scheduled')} value={fmt(job.scheduledFor)} mono />
              <Fact
                label={t('change.fact.window')}
                value={
                  job.windowStart || job.windowEnd
                    ? `${fmt(job.windowStart)} → ${fmt(job.windowEnd)}`
                    : '—'
                }
                mono
              />
            </dl>
            {job.preflightBackupId === null && (
              <p className="mt-2 text-[11px] text-status-ssl-expired">
                {t('change.fact.noBackupHint')}
              </p>
            )}
          </section>

          {job.planId !== null && (
            <Link
              to={`/plan/${job.deviceId}`}
              className="block rounded-lg border border-border bg-bg-secondary p-3 text-[13px] text-accent hover:bg-bg-hover"
            >
              {t('change.openPlan')}
            </Link>
          )}
        </aside>
      </div>

      {/* The guard verdict as it was at launch. Kept at the bottom because
          during the job it is history — but never removed, because it is the
          answer to "why was this allowed to run". */}
      {job.guard && (
        <div className="mt-6">
          <h2 className="mb-2 text-sm font-semibold text-text-primary">
            {t('change.guardAtLaunch')}
          </h2>
          <GuardVerdictPanel guard={job.guard} />
        </div>
      )}

      {!job.guard && job.guardReasons.length > 0 && (
        <div className="mt-6 rounded-lg border border-border bg-bg-secondary p-4">
          <h2 className="mb-2 text-sm font-semibold text-text-primary">
            {t('change.guardAtLaunch')}
          </h2>
          <div className="flex flex-wrap gap-1.5">
            {job.guardReasons.map((r) => (
              <span
                key={r}
                className="rounded border border-border bg-bg-tertiary px-1.5 py-0.5 font-mono text-[10px] text-text-secondary"
              >
                {r}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Fact({
  label,
  value,
  mono,
  tone,
}: {
  label: string;
  value: string;
  mono?: boolean;
  tone?: 'bad';
}) {
  return (
    <div className="flex gap-2">
      <dt className="w-28 shrink-0 text-text-muted">{label}</dt>
      <dd
        className={cn(
          'min-w-0 flex-1 break-all',
          mono && 'font-mono',
          tone === 'bad' ? 'text-status-ssl-expired' : 'text-text-secondary',
        )}
      >
        {value}
      </dd>
    </div>
  );
}

function fmt(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}
