import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { FileCog, PlayCircle, Unplug } from 'lucide-react';
import { CAPABILITIES } from '@obliwan/shared';
import { changeApi, errorMessageOf, safetyNetOfLevel } from '@/api/change.api';
import { useAuthStore } from '@/store/authStore';
import { useChangeStore } from '@/store/changeStore';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { JobKindChip, JobStatusBadge } from '@/components/change/JobStatusBadge';
import { SafetyNetBadge, SafetyNetPanel } from '@/components/change/SafetyNetBadge';
import { GuardVerdictBadge } from '@/components/plan/RiskBadge';
import { KillSwitchBanner } from '@/components/change/KillSwitch';
import { useJobSocket } from '@/hooks/useJobSocket';
import type { ChangeJobView, DeviceImpact } from '@/types/change';

/**
 * The `Changements` tab of `DeviceDetailPage` — this box's change history and
 * its current safety net.
 *
 * ── THE NET IS AT THE TOP, NOT IN THE HISTORY ───────────────────────────────
 * §8.3 says the level is shown BEFORE the launch. This tab is one of the two
 * places an operator starts a change from, so the net panel sits above the
 * "compile a plan" link rather than beside a past job. Reading "DEGRADED"
 * before deciding to open the planner is the whole point; reading it in a
 * table of finished jobs is trivia.
 *
 * ── WHY THERE IS NO APPLY BUTTON HERE ───────────────────────────────────────
 * The only write gesture on this tab is a link to `PlanPage`. A change is
 * launched from a screen that shows the compiled plan, the guard verdict and
 * the blast radius — never from a device page where none of those are visible.
 */
export function DeviceChangesTab({
  deviceId,
  deviceName,
}: {
  deviceId: number;
  deviceName: string;
}) {
  const { t } = useTranslation();
  const { hasCapability, isAdmin } = useAuthStore();
  const fetchKillSwitch = useChangeStore((s) => s.fetchKillSwitch);

  const [jobs, setJobs] = useState<ChangeJobView[]>([]);
  const [impact, setImpact] = useState<DeviceImpact | null>(null);
  const [impactKnown, setImpactKnown] = useState(false);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const canPlan = isAdmin() || hasCapability(CAPABILITIES.PLAN_CREATE);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const rows = await changeApi.listJobs({ deviceId, limit: 50 });
      if (rows === null) { setUnavailable(true); setJobs([]); }
      else { setUnavailable(false); setJobs(rows); }
    } catch (err) {
      setLoadError(errorMessageOf(err) ?? t('change.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [deviceId, t]);

  useEffect(() => {
    void load();
    void fetchKillSwitch();
  }, [load, fetchKillSwitch]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const rows = await changeApi.preflight([deviceId]);
        if (cancelled || rows === null) return;
        const row = rows.find((r) => r.deviceId === deviceId) ?? rows[0] ?? null;
        if (row) { setImpact(row); setImpactKnown(true); }
      } catch { /* the net stays unknown, i.e. DEGRADED */ }
    })();
    return () => { cancelled = true; };
  }, [deviceId]);

  useJobSocket({
    onJob: (job) => {
      if (job.deviceId !== deviceId) return;
      setJobs((prev) => {
        const idx = prev.findIndex((j) => j.id === job.id);
        if (idx === -1) return [job, ...prev];
        const next = prev.slice();
        next[idx] = { ...next[idx], ...job };
        return next;
      });
    },
  });

  return (
    <div className="space-y-4">
      <KillSwitchBanner />

      {/* §8.3 — before anything else on this tab. */}
      <div>
        <SafetyNetPanel
          level={impact?.safetyNet ?? 'DEGRADED'}
          deviceName={deviceName}
          peerName={impact?.safetyPeerDeviceName ?? null}
        />
        {!impactKnown && (
          <p className="mt-2 rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-2.5 text-[12px] text-status-ssl-expired">
            {t('change.safetyNet.unknownEndpoint')}
          </p>
        )}
      </div>

      {canPlan && (
        <Link
          to={`/plan/${deviceId}`}
          className="inline-flex items-center gap-2 rounded-md border border-border bg-bg-secondary px-3 py-2 text-[13px] text-accent hover:bg-bg-hover"
        >
          <FileCog size={14} />
          {t('change.compilePlan')}
        </Link>
      )}

      {unavailable ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
          <Unplug size={26} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('change.endpointUnavailable')}</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
            {t('change.endpointUnavailableHint')}
          </p>
        </div>
      ) : loadError ? (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
          {loadError}
        </div>
      ) : loading && jobs.length === 0 ? (
        <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
      ) : jobs.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
          <PlayCircle size={26} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('change.noJobsForDevice')}</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full min-w-[46rem] text-left text-[13px]">
            <thead className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">{t('change.columns.job')}</th>
                <th className="px-3 py-2 font-medium">{t('change.columns.kind')}</th>
                <th className="px-3 py-2 font-medium">{t('change.columns.status')}</th>
                <th className="px-3 py-2 font-medium">{t('change.columns.safetyNet')}</th>
                <th className="px-3 py-2 font-medium">{t('change.columns.guard')}</th>
                <th className="px-3 py-2 font-medium">{t('change.columns.created')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {jobs.map((j) => (
                <tr key={j.id} className="hover:bg-bg-hover">
                  <td className="px-3 py-2">
                    <Link to={`/changes/${j.id}`} className="font-mono text-accent hover:underline">
                      #{j.id}
                    </Link>
                  </td>
                  <td className="px-3 py-2"><JobKindChip kind={j.kind} /></td>
                  <td className="px-3 py-2"><JobStatusBadge status={j.status} /></td>
                  <td className="px-3 py-2">
                    <SafetyNetBadge level={safetyNetOfLevel(j.armedLevel ?? j.safetyLevel)} />
                  </td>
                  <td className="px-3 py-2">
                    {j.guardVerdict ? (
                      <GuardVerdictBadge state={j.guardVerdict} />
                    ) : (
                      <span className="text-[11px] text-text-muted">{t('change.noGuardRecorded')}</span>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-text-muted">
                    {j.createdAt ? new Date(j.createdAt).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
