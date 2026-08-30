import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  ArrowLeft,
  Ban,
  StopCircle,
  PauseCircle,
  PlayCircle,
  RotateCw,
  Rocket,
  Unplug,
} from 'lucide-react';
import { rolloutApi } from '@/api/rollout.api';
import { errorMessageOf } from '@/api/change.api';
import { useChangeStore } from '@/store/changeStore';
import { useSocketStore } from '@/store/socketStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { KillSwitchBanner } from '@/components/change/KillSwitch';
import { JobStatusBadge } from '@/components/change/JobStatusBadge';
import { SafetyNetBadge } from '@/components/change/SafetyNetBadge';
import { RolloutStatusBadge, WaveStatusBadge } from '@/components/rollout/RolloutBadges';
import { HealthGatePanel, HealthGateStrip, allGatesCleared } from '@/components/rollout/HealthGates';
import { useRolloutSocket } from '@/hooks/useRolloutSocket';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import type { RolloutDetail, RolloutTargetView, RolloutWaveView } from '@/types/rollout';

/**
 * `RolloutDetailPage` — one rollout, live (§5/M7).
 *
 * ── PAUSE, RESUME, ABORT — AND WHAT EACH ONE ACTUALLY DOES ──────────────────
 * The three buttons are not variations of "stop". They are said in full next to
 * themselves because an operator reaching for one of them is under pressure:
 *
 *   PAUSE   stops the NEXT wave. The wave running now keeps running: its
 *           devices are mid-apply with a dead-man armed, and pretending we can
 *           freeze them would be a lie the machinery cannot honour.
 *   RESUME  opens the next wave. It does NOT re-run the gates of the wave that
 *           was paused — those already concluded.
 *   ABORT   cancels every wave that has not started. It does NOT un-apply the
 *           waves that already did. Reverting those is the dead-man's job, or a
 *           new rollout's.
 *
 * ── THE PROGRESSION IS LIVE, PER `rolloutId` ────────────────────────────────
 * §5/M7 asks for exactly that. `useRolloutSocket({ rolloutId })` joins the
 * `rollout:{id}` room, wave frames fold in place, and the header status comes
 * from the same frames rather than from a poll — so a gate refusing wave 2 is
 * on screen the moment it refuses, not thirty seconds later.
 */

export function RolloutDetailPage() {
  const { id } = useParams<{ id: string }>();
  const rolloutId = Number(id);
  const { t, i18n } = useTranslation();
  const socketStatus = useSocketStore((s) => s.status);
  const fetchKillSwitch = useChangeStore((s) => s.fetchKillSwitch);

  const [detail, setDetail] = useState<RolloutDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [openWave, setOpenWave] = useState<number | null>(0);

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'medium' }),
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
      const row = await rolloutApi.get(rolloutId);
      if (row === null) { setUnavailable(true); setDetail(null); }
      else { setUnavailable(false); setDetail(row); }
    } catch (err) {
      setError(errorMessageOf(err) ?? t('rollout.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [rolloutId, t]);

  useEffect(() => {
    if (!Number.isFinite(rolloutId) || rolloutId <= 0) { setUnavailable(true); setLoading(false); return; }
    void load();
    void fetchKillSwitch();
  }, [rolloutId, load, fetchKillSwitch]);

  useRolloutSocket({
    rolloutId: Number.isFinite(rolloutId) && rolloutId > 0 ? rolloutId : undefined,
    onRollout: (rollout) => {
      setDetail((prev) => (prev && prev.id === rollout.id ? { ...prev, ...rollout } : prev));
    },
    onWave: (wave) => {
      setDetail((prev) => {
        if (!prev) return prev;
        const idx = prev.waves.findIndex((w) => w.index === wave.index);
        const waves = prev.waves.slice();
        if (idx === -1) waves.push(wave);
        else waves[idx] = { ...waves[idx], ...wave };
        waves.sort((a, b) => a.index - b.index);
        return { ...prev, waves };
      });
    },
  });

  const deviceNames = useMemo(() => {
    const map = new Map<number, string>();
    for (const target of detail?.targets ?? []) {
      map.set(target.deviceId, anonHostname(target.deviceName ?? `#${target.deviceId}`));
    }
    return map;
  }, [detail]);

  const act = useCallback(
    async (action: 'pause' | 'resume' | 'abort', reason: string) => {
      setBusy(true);
      setNotice(null);
      try {
        const ok = action === 'resume'
          ? await rolloutApi.resume(rolloutId)
          : action === 'pause'
            ? await rolloutApi.pause(rolloutId, reason)
            : await rolloutApi.abort(rolloutId, reason);
        if (!ok) setNotice(t('rollout.detail.actionEndpointAbsent'));
        else await load();
      } catch (err) {
        setNotice(errorMessageOf(err) ?? t('rollout.detail.actionFailed'));
      } finally {
        setBusy(false);
      }
    },
    [rolloutId, load, t],
  );

  if (loading && !detail) {
    return <div className="flex h-full items-center justify-center"><LoadingSpinner size="lg" /></div>;
  }

  if (unavailable || !detail) {
    return (
      <div className="p-6">
        <Link to="/rollouts" className="mb-4 inline-flex items-center gap-1.5 text-sm text-text-muted hover:text-text-primary">
          <ArrowLeft size={14} /> {t('nav.rollouts')}
        </Link>
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('rollout.endpointUnavailable')}</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
            {t('rollout.endpointUnavailableHint')}
          </p>
          {error && <p className="mt-2 font-mono text-xs text-status-ssl-expired">{error}</p>}
        </div>
      </div>
    );
  }

  const canPause = detail.status === 'running';
  const canResume = detail.status === 'paused';
  const canAbort = detail.status === 'running' || detail.status === 'paused' || detail.status === 'draft';

  return (
    <div className="p-6">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <Link
            to="/rollouts"
            className="mb-2 inline-flex items-center gap-1.5 text-sm text-text-muted hover:text-text-primary"
          >
            <ArrowLeft size={14} /> {t('nav.rollouts')}
          </Link>
          <h1 className="flex flex-wrap items-center gap-2 text-2xl font-semibold text-text-primary">
            <Rocket size={20} className="text-text-muted" />
            {detail.name || `#${detail.id}`}
            <RolloutStatusBadge status={detail.status} size="lg" />
          </h1>
          <p className="mt-1 text-sm text-text-muted">
            {t('rollout.detail.header', {
              devices: detail.deviceCount,
              waves: detail.waveCount,
              by: detail.requestedByName ?? '—',
            })}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
          {canPause && (
            <Button
              variant="secondary"
              size="sm"
              disabled={busy}
              onClick={() => void act('pause', 'paused from the rollout screen')}
            >
              <PauseCircle size={14} className="mr-1.5" />
              {t('rollout.detail.pause')}
            </Button>
          )}
          {canResume && (
            <Button
              variant="secondary"
              size="sm"
              disabled={busy}
              onClick={() => void act('resume', '')}
            >
              <PlayCircle size={14} className="mr-1.5" />
              {t('rollout.detail.resume')}
            </Button>
          )}
          {canAbort && (
            <Button
              variant="danger"
              size="sm"
              disabled={busy}
              onClick={() => void act('abort', 'aborted from the rollout screen')}
            >
              <Ban size={14} className="mr-1.5" />
              {t('rollout.detail.abort')}
            </Button>
          )}
        </div>
      </div>

      <KillSwitchBanner className="mb-4" />

      {/* What each control actually does, next to the controls. */}
      <p className="mb-4 rounded-md border border-border bg-bg-tertiary px-3 py-2 text-[12px] text-text-muted">
        {t('rollout.detail.controlsExplained')}
      </p>

      {socketStatus !== 'connected' && (
        <p className="mb-4 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-2.5 text-[12px] text-status-ssl-warning">
          {t('rollout.socketDown')}
        </p>
      )}

      {notice && (
        <p className="mb-4 rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-2.5 text-[12px] text-status-ssl-expired">
          {notice}
        </p>
      )}

      {detail.status === 'paused' && detail.pausedReason && (
        <p className="mb-4 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-2.5 text-[12px] text-status-ssl-warning">
          {t('rollout.detail.pausedBecause', { reason: detail.pausedReason })}
        </p>
      )}

      {detail.quarantinedRevisionId !== null && (
        <p className="mb-4 flex items-start gap-2 rounded-md border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-3 text-[13px] text-status-ssl-expired">
          <StopCircle size={15} className="mt-0.5 shrink-0" />
          <span>
            {t('rollout.detail.quarantined', { revision: detail.quarantinedRevisionId })}
            {detail.quarantineReason && (
              <span className="mt-0.5 block font-mono text-[11px]">{detail.quarantineReason}</span>
            )}
          </span>
        </p>
      )}

      {/* ── waves ── */}
      <div className="space-y-3">
        {detail.waves.length === 0 ? (
          <div className="rounded-lg border border-border bg-bg-secondary py-10 text-center text-sm text-text-muted">
            {t('rollout.detail.noWaves')}
          </div>
        ) : (
          detail.waves.map((wave) => (
            <WaveSection
              key={wave.index}
              wave={wave}
              targets={detail.targets.filter((x) => x.waveIndex === wave.index)}
              deviceNames={deviceNames}
              open={openWave === wave.index}
              onToggle={() => setOpenWave(openWave === wave.index ? null : wave.index)}
              when={when}
            />
          ))
        )}
      </div>
    </div>
  );
}

function WaveSection({
  wave,
  targets,
  deviceNames,
  open,
  onToggle,
  when,
}: {
  wave: RolloutWaveView;
  targets: RolloutTargetView[];
  deviceNames: Map<number, string>;
  open: boolean;
  onToggle: () => void;
  when: (iso: string | null) => string;
}) {
  const { t } = useTranslation();
  const isCanary = wave.index === 0;

  return (
    <section
      className={cn(
        'overflow-hidden rounded-lg border bg-bg-secondary',
        wave.status === 'failed' ? 'border-status-ssl-expired/50'
          : wave.status === 'running' || wave.status === 'gating' ? 'border-accent/40'
            : 'border-border',
      )}
    >
      <button
        onClick={onToggle}
        className="flex w-full flex-wrap items-center gap-2 px-3 py-2 text-left hover:bg-bg-hover"
      >
        <span className="text-sm font-semibold text-text-primary">
          {isCanary ? t('rollout.impact.canary') : t('rollout.impact.waveN', { n: wave.index + 1 })}
        </span>
        <WaveStatusBadge status={wave.status} />
        <span className="font-mono text-[11px] text-text-muted">
          {t('rollout.detail.waveCounts', {
            devices: wave.deviceIds.length || targets.length,
            succeeded: wave.succeeded,
            rolledBack: wave.rolledBack,
            failed: wave.failed,
          })}
        </span>
        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {when(wave.startedAt)} → {when(wave.finishedAt)}
        </span>
      </button>

      <div className="border-t border-border px-3 py-2">
        <HealthGateStrip gates={wave.gates} />
        {/* The server said this wave passed; its gate payload does not show a
            complete set of cleared gates. Said out loud rather than smoothed
            over — a green badge over incomplete evidence is how a gap in the
            evidence becomes a fact. */}
        {wave.status === 'passed' && !allGatesCleared(wave.gates) && (
          <p className="mt-1.5 text-[11px] text-status-ssl-warning">
            {t('rollout.gate.passedButIncomplete')}
          </p>
        )}
      </div>

      {open && (
        <div className="grid gap-3 border-t border-border p-3 xl:grid-cols-[2fr_1fr]">
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full min-w-[36rem] text-left text-[13px]">
              <thead className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
                <tr>
                  <th className="px-3 py-2 font-medium">{t('rollout.impact.columns.device')}</th>
                  <th className="px-3 py-2 font-medium">{t('rollout.impact.columns.safetyNet')}</th>
                  <th className="px-3 py-2 font-medium">{t('rollout.detail.columns.job')}</th>
                  <th className="px-3 py-2 font-medium">{t('rollout.detail.columns.outcome')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {targets.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-3 py-6 text-center text-[12px] text-text-muted">
                      {t('rollout.detail.noTargets')}
                    </td>
                  </tr>
                ) : (
                  targets.map((target) => (
                    <tr key={target.deviceId} className="hover:bg-bg-hover">
                      <td className="px-3 py-2">
                        <Link to={`/devices/${target.deviceId}`} className="text-text-primary hover:text-accent">
                          {deviceNames.get(target.deviceId) ?? `#${target.deviceId}`}
                        </Link>
                        <span className="block text-[11px] text-text-muted">{target.siteName ?? '—'}</span>
                      </td>
                      <td className="px-3 py-2"><SafetyNetBadge level={target.safetyNet} /></td>
                      <td className="px-3 py-2">
                        {target.jobId !== null ? (
                          <Link to={`/changes/${target.jobId}`} className="inline-flex items-center gap-1.5">
                            {target.jobStatus ? (
                              <JobStatusBadge status={target.jobStatus} />
                            ) : (
                              <span className="font-mono text-[11px] text-text-muted">#{target.jobId}</span>
                            )}
                          </Link>
                        ) : (
                          <span className="text-[11px] text-text-muted">{t('rollout.detail.notQueued')}</span>
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <OutcomeChip outcome={target.outcome} />
                        {target.errorMessage && (
                          <span className="mt-0.5 block font-mono text-[10px] text-status-ssl-expired">
                            {target.errorMessage}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <HealthGatePanel gates={wave.gates} deviceNames={deviceNames} />
        </div>
      )}
    </section>
  );
}

const OUTCOME_TONE: Record<RolloutTargetView['outcome'], string> = {
  pending: 'text-text-muted border-border bg-bg-tertiary',
  applied: 'text-status-up border-status-up/50 bg-status-up/10',
  // Amber, not red. The dead-man firing IS the machinery working.
  rolled_back: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  failed: 'text-status-ssl-expired border-status-ssl-expired/60 bg-status-ssl-expired/15',
  skipped: 'text-text-muted border-border bg-bg-tertiary',
};

function OutcomeChip({ outcome }: { outcome: RolloutTargetView['outcome'] }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
        OUTCOME_TONE[outcome],
      )}
      title={t(`rollout.outcome.hint.${outcome}`)}
    >
      {t(`rollout.outcome.label.${outcome}`)}
    </span>
  );
}
