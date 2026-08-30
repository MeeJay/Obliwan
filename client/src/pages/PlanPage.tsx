import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import {
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  RotateCw,
  Rocket,
  ShieldX,
  Siren,
  Unplug,
} from 'lucide-react';
import { CAPABILITIES } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { useAuthStore } from '@/store/authStore';
import { useDeviceStore } from '@/store/deviceStore';
import { useChangeStore } from '@/store/changeStore';
import { changeApi, errorMessageOf, isRouteAbsent } from '@/api/change.api';
import { planApi } from '@/api/plan.api';
import { PlanViewer } from '@/components/plan/PlanViewer';
import { GuardVerdictPanel } from '@/components/plan/GuardVerdictPanel';
import { guardClears } from '@/components/plan/RiskBadge';
import { SafetyNetPanel } from '@/components/change/SafetyNetBadge';
import { KillSwitchBanner } from '@/components/change/KillSwitch';
import { LaunchChangeDialog, type LaunchSubmit } from '@/components/change/LaunchChangeDialog';
import { OverrideDialog, type OverrideSubmit } from '@/components/change/OverrideDialog';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import type { CompiledPlan, DeviceImpact, SafetyNetLevel } from '@/types/change';

/**
 * `PlanPage` — spec §4.2: "rayon d'impact, ops colorées, verdict Management-Path
 * Guard, bouton Approuver".
 *
 * ── THE ORDER OF THIS PAGE IS THE ARGUMENT ──────────────────────────────────
 *   1. the kill-switch banner, if the world is stopped;
 *   2. the GUARD VERDICT, full width, unavoidable;
 *   3. the SAFETY NET (§8.3) — what repairs this box if we are wrong;
 *   4. the plan: blast radius, then operations coloured by risk;
 *   5. the launch block — and ONLY if the guard cleared the plan;
 *   6. far below, visually separated, the override block.
 *
 * The verdict comes before the plan because an operator who reads fifty
 * well-formatted operations first has already decided to apply them by the time
 * he reaches the refusal. And the override block comes last, in its own
 * red-bordered box, because the one thing this page must never do is put
 * "bypass the anti-lockout guard" within a mis-aimed click of "Apply".
 *
 * ── WHAT HAPPENS WHEN THE SERVER CANNOT APPLY YET ───────────────────────────
 * `GET /plan/config` answers `{ canApply: false, applyMilestone: 'M6' }` on an
 * M5 build. The page then compiles, displays and explains the plan in full —
 * everything except the launch — and says WHICH milestone the button is waiting
 * for. It never renders an enabled control that would POST to a route that does
 * not exist.
 *
 * ── THE SAFETY NET WHEN NOTHING TOLD US ─────────────────────────────────────
 * The level comes from `POST /changes/preflight` (or from `impact` on the plan
 * payload). When neither is available the page shows DEGRADED and says the
 * level could not be established. That is not pessimism for its own sake: A2
 * forbids claiming a net that has not been observed, and a screen that guessed
 * ARMED would remove the §8.3 confirmation on exactly the devices we know least
 * about.
 */

export function PlanPage() {
  const { deviceId: deviceIdParam } = useParams<{ deviceId: string }>();
  const deviceId = Number(deviceIdParam);
  const navigate = useNavigate();
  const { t } = useTranslation();

  const { user, hasCapability, isAdmin } = useAuthStore();
  const { devices, fetchDevices } = useDeviceStore();
  const planConfig = useChangeStore((s) => s.planConfig);
  const killSwitch = useChangeStore((s) => s.killSwitch);
  const fetchPlanConfig = useChangeStore((s) => s.fetchPlanConfig);
  const fetchKillSwitch = useChangeStore((s) => s.fetchKillSwitch);
  const writesAllowed = useChangeStore((s) => s.writesAllowed);

  const [compiled, setCompiled] = useState<CompiledPlan | null>(null);
  const [impact, setImpact] = useState<DeviceImpact | null>(null);
  const [impactUnavailable, setImpactUnavailable] = useState(false);
  const [loading, setLoading] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [fresh, setFresh] = useState<boolean | null>(null);
  const [freshMessage, setFreshMessage] = useState<string | null>(null);

  const [launchOpen, setLaunchOpen] = useState(false);
  const [overrideOpen, setOverrideOpen] = useState(false);
  const [overrideBlockOpen, setOverrideBlockOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [focusedOpSeq, setFocusedOpSeq] = useState<number | null>(null);

  const admin = isAdmin();
  const canApplyCapability = admin || hasCapability(CAPABILITIES.CHANGE_APPLY);
  // Overriding a guard verdict is `CHANGE_APPROVE`, NOT `CHANGE_APPLY`: the
  // capability matrix keeps "may enqueue a change" and "may override a veto"
  // apart, and this page must not merge them back together.
  const canOverride = admin || hasCapability(CAPABILITIES.CHANGE_APPROVE);

  const device = useMemo(
    () => devices.find((d) => d.id === deviceId) ?? null,
    [devices, deviceId],
  );
  const deviceName = compiled?.detail.deviceName ?? device?.name ?? `#${deviceId}`;

  useEffect(() => {
    void fetchDevices();
    void fetchPlanConfig();
    void fetchKillSwitch();
  }, [fetchDevices, fetchPlanConfig, fetchKillSwitch]);

  const compile = useCallback(async () => {
    if (!Number.isInteger(deviceId) || deviceId <= 0) return;
    setLoading(true);
    setLoadError(null);
    setUnavailable(false);
    setFresh(null);
    setFreshMessage(null);
    try {
      const result = await planApi.compileDevice(deviceId, { persistRender: false });
      if (result === null) {
        setUnavailable(true);
        setCompiled(null);
      } else {
        setCompiled(result);
        setImpact(result.impact);
        // Freshness is checked immediately, not on the Apply click: an operator
        // who spends four minutes reading a plan should learn it went stale
        // while he was reading, not when he presses the button.
        const verdict = await planApi.validate(result.plan);
        setFresh(verdict.unavailable ? null : verdict.fresh);
        setFreshMessage(verdict.message);
      }
    } catch (err) {
      setLoadError(errorMessageOf(err) ?? t('plan.compileFailed'));
      setCompiled(null);
    } finally {
      setLoading(false);
    }
  }, [deviceId, t]);

  useEffect(() => { void compile(); }, [compile]);

  // §8.3 — the per-device safety net, fetched separately so a build without the
  // change API still shows the plan (and still refuses to claim a net).
  useEffect(() => {
    if (!Number.isInteger(deviceId) || deviceId <= 0) return;
    let cancelled = false;
    void (async () => {
      try {
        // The compiled plan ITSELF, not its uuid: no plan row exists server-side
        // until enqueue freezes one (D3), so there is nothing for an identifier
        // to point at while this screen is still deciding.
        const rows = await changeApi.preflight([deviceId], compiled?.plan);
        if (cancelled) return;
        if (rows === null) { setImpactUnavailable(true); return; }
        setImpactUnavailable(false);
        const row = rows.find((r) => r.deviceId === deviceId) ?? rows[0] ?? null;
        if (row) setImpact(row);
      } catch {
        if (!cancelled) setImpactUnavailable(true);
      }
    })();
    return () => { cancelled = true; };
  }, [deviceId, compiled?.plan.planUuid]);

  /** The fail-closed reading of §8.3: no information means no net claimed. */
  const safetyNet: SafetyNetLevel = impact?.safetyNet ?? 'DEGRADED';
  const safetyNetKnown = impact !== null;
  const peerName = impact?.safetyPeerDeviceName ?? null;

  const cleared = compiled ? guardClears(compiled.guard) : false;

  const focusOp = useCallback((seq: number) => {
    setFocusedOpSeq(seq);
    const el = document.getElementById(`plan-op-${seq}`);
    el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }, []);

  const submitJob = useCallback(
    async (extra: { overrideReason?: string; degradedConfirmed: boolean; scheduledFor?: string | null }) => {
      if (!compiled) return;
      setSubmitting(true);
      try {
        const job = await changeApi.createJob({
          deviceId,
          kind: 'push',
          planUuid: compiled.plan.planUuid,
          plan: compiled.plan,
          overrideReason: extra.overrideReason,
          degradedConfirmed: extra.degradedConfirmed,
          scheduledFor: extra.scheduledFor ?? null,
        });
        toast.success(t('change.launch.queued'));
        setLaunchOpen(false);
        setOverrideOpen(false);
        if (job) navigate(`/changes/${job.id}`);
        else navigate('/changes');
      } catch (err) {
        if (isRouteAbsent(err)) {
          toast.error(t('change.apiUnavailable'));
        } else {
          toast.error(errorMessageOf(err) ?? t('change.launch.failed'));
        }
      } finally {
        setSubmitting(false);
      }
    },
    [compiled, deviceId, navigate, t],
  );

  const onLaunch = useCallback(
    (req: LaunchSubmit) =>
      void submitJob({
        degradedConfirmed: req.degradedConfirmed,
        scheduledFor: req.scheduledFor,
      }),
    [submitJob],
  );

  const onOverride = useCallback(
    (req: OverrideSubmit) =>
      void submitJob({
        overrideReason: req.overrideReason,
        degradedConfirmed: req.degradedConfirmed,
      }),
    [submitJob],
  );

  // ── device picker when no device is in the URL ────────────────────────────
  if (!Number.isInteger(deviceId) || deviceId <= 0) {
    return <PlanDevicePicker />;
  }

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <Link
            to={`/devices/${deviceId}`}
            className="mb-1 inline-flex items-center gap-1 text-[12px] text-text-muted hover:text-text-primary"
          >
            <ArrowLeft size={12} />
            {t('plan.backToDevice')}
          </Link>
          <h1 className="font-display text-2xl font-semibold text-text-primary">
            {t('plan.title')}
          </h1>
          <p className="mt-1 font-mono text-sm text-text-muted">{anonHostname(deviceName)}</p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => void compile()}>
          <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
          {t('plan.recompile')}
        </Button>
      </div>

      <KillSwitchBanner className="mb-4" />

      {unavailable ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('plan.endpointUnavailable')}</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
            {t('plan.endpointUnavailableHint')}
          </p>
        </div>
      ) : loadError ? (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
          {t('plan.compileFailed')} — <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : loading && !compiled ? (
        <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
      ) : !compiled ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center text-sm text-text-muted">
          {t('plan.empty')}
        </div>
      ) : (
        <div className="space-y-5">
          {/* 2 — the verdict, first and full width. */}
          <GuardVerdictPanel guard={compiled.guard} onFocusOp={focusOp} />

          {/* 3 — the net. §8.3: before the launch, never after. */}
          <div>
            <SafetyNetPanel
              level={safetyNet}
              deviceName={anonHostname(deviceName)}
              peerName={peerName}
            />
            {!safetyNetKnown && (
              <p className="mt-2 rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-2.5 text-[12px] text-status-ssl-expired">
                {impactUnavailable
                  ? t('change.safetyNet.unknownEndpoint')
                  : t('change.safetyNet.unknownYet')}
              </p>
            )}
          </div>

          {/* Freshness. A stale plan is a refusal, not a warning. */}
          {fresh === false && (
            <div className="rounded-lg border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-4">
              <h2 className="text-sm font-semibold text-status-ssl-expired">
                {t('plan.staleTitle')}
              </h2>
              <p className="mt-1 text-[13px] text-text-secondary">
                {freshMessage ?? t('plan.staleBody')}
              </p>
              <Button variant="secondary" size="sm" className="mt-2" onClick={() => void compile()}>
                <RotateCw size={13} className="mr-1.5" />
                {t('plan.recompile')}
              </Button>
            </div>
          )}

          {/* 4 — the plan itself. */}
          <PlanViewer
            compiled={compiled}
            culpritOpSeqs={compiled.guard.culpritOpSeqs}
            focusedOpSeq={focusedOpSeq}
          />

          {/* 5 — launch, only when the guard cleared. */}
          <section
            className={cn(
              'rounded-lg border p-4',
              cleared ? 'border-border bg-bg-secondary' : 'border-border bg-bg-secondary/60',
            )}
          >
            <h2 className="text-sm font-semibold text-text-primary">{t('plan.applyTitle')}</h2>

            {!canApplyCapability ? (
              <p className="mt-1 text-[13px] text-text-muted">{t('change.noApplyCapability')}</p>
            ) : !cleared ? (
              <p className="mt-1 text-[13px] text-text-secondary">
                {t('plan.applyBlockedByGuard')}
              </p>
            ) : !planConfig.canApply ? (
              <p className="mt-1 text-[13px] text-text-secondary">
                {planConfig.applyMilestone
                  ? t('plan.applyMilestone', { milestone: planConfig.applyMilestone })
                  : t('plan.applyServerRefuses')}
              </p>
            ) : killSwitch.blocked ? (
              <p className="mt-1 text-[13px] text-status-ssl-expired">
                {t('plan.applyKillSwitch')}
              </p>
            ) : (
              <>
                <p className="mt-1 text-[13px] text-text-secondary">{t('plan.applyReady')}</p>
                <Button
                  variant="primary"
                  size="md"
                  className="mt-3"
                  onClick={() => setLaunchOpen(true)}
                >
                  <Rocket size={15} className="mr-1.5" />
                  {t('plan.applyButton')}
                </Button>
              </>
            )}
          </section>

          {/* 6 — THE OVERRIDE. Separate block, far from Apply, collapsed by
              default, red only once opened. Nothing here can be triggered by a
              click aimed at the button above. */}
          {!cleared && canOverride && (
            <section className="rounded-lg border border-dashed border-status-ssl-expired/40 bg-bg-secondary/40">
              <button
                type="button"
                onClick={() => setOverrideBlockOpen((v) => !v)}
                className="flex w-full items-center gap-2 px-4 py-3 text-left"
              >
                {overrideBlockOpen ? (
                  <ChevronDown size={14} className="text-text-muted" />
                ) : (
                  <ChevronRight size={14} className="text-text-muted" />
                )}
                <ShieldX size={15} className="text-status-ssl-expired" />
                <span className="text-sm font-semibold text-text-secondary">
                  {t('change.override.blockTitle')}
                </span>
              </button>
              {overrideBlockOpen && (
                <div className="border-t border-border px-4 py-3">
                  <p className="text-[13px] text-text-secondary">
                    {t('change.override.blockBody')}
                  </p>
                  <p className="mt-1.5 text-[12px] text-text-muted">
                    {t('change.override.blockHint')}
                  </p>
                  <Button
                    variant="secondary"
                    size="sm"
                    className="mt-3 border-status-ssl-expired/50 text-status-ssl-expired"
                    disabled={!canApplyCapability || !planConfig.canApply || killSwitch.blocked}
                    onClick={() => setOverrideOpen(true)}
                  >
                    <Siren size={14} className="mr-1.5" />
                    {t('change.override.open')}
                  </Button>
                  {(!planConfig.canApply || killSwitch.blocked) && (
                    <p className="mt-2 text-[12px] text-text-muted">
                      {killSwitch.blocked
                        ? t('plan.applyKillSwitch')
                        : planConfig.applyMilestone
                          ? t('plan.applyMilestone', { milestone: planConfig.applyMilestone })
                          : t('plan.applyServerRefuses')}
                    </p>
                  )}
                </div>
              )}
            </section>
          )}

          {!cleared && !canOverride && (
            <p className="rounded-lg border border-border bg-bg-secondary p-4 text-[13px] text-text-muted">
              {t('change.override.noCapability')}
            </p>
          )}
        </div>
      )}

      {launchOpen && compiled && (
        <LaunchChangeDialog
          compiled={compiled}
          deviceName={deviceName}
          safetyNet={safetyNet}
          peerName={peerName}
          writesAllowed={writesAllowed()}
          killSwitchBlocked={killSwitch.blocked}
          applyMilestone={planConfig.applyMilestone}
          fresh={fresh}
          freshMessage={freshMessage}
          submitting={submitting}
          onSubmit={onLaunch}
          onClose={() => setLaunchOpen(false)}
        />
      )}

      {overrideOpen && compiled && (
        <OverrideDialog
          compiled={compiled}
          deviceName={deviceName}
          safetyNet={safetyNet}
          peerName={peerName}
          operatorName={user?.displayName || user?.username || '—'}
          submitting={submitting}
          onSubmit={onOverride}
          onClose={() => setOverrideOpen(false)}
        />
      )}
    </div>
  );
}

/** `/plan` with no device: the plan is compiled per device, so the page asks
 *  which one rather than compiling the whole fleet by surprise. */
function PlanDevicePicker() {
  const { t } = useTranslation();
  const { devices, fetchDevices, isLoading } = useDeviceStore();
  const [search, setSearch] = useState('');

  useEffect(() => { void fetchDevices(); }, [fetchDevices]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const rows = devices.filter((d) => d.isManaged);
    if (!needle) return rows.slice(0, 200);
    return rows
      .filter((d) => `${d.name} ${d.siteName ?? ''}`.toLowerCase().includes(needle))
      .slice(0, 200);
  }, [devices, search]);

  return (
    <div className="p-6">
      <h1 className="font-display text-2xl font-semibold text-text-primary">{t('plan.title')}</h1>
      <p className="mt-1 text-sm text-text-muted">{t('plan.pickDevice')}</p>

      <input
        type="text"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder={t('common.search')}
        className="mt-4 w-72 rounded-md border border-border bg-bg-tertiary px-3 py-2 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
      />

      {isLoading && devices.length === 0 ? (
        <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
      ) : filtered.length === 0 ? (
        <p className="mt-6 text-sm text-text-muted">{t('plan.noDevices')}</p>
      ) : (
        <ul className="mt-4 divide-y divide-border rounded-lg border border-border bg-bg-secondary">
          {filtered.map((d) => (
            <li key={d.id}>
              <Link
                to={`/plan/${d.id}`}
                className="flex items-center gap-3 px-3 py-2 text-[13px] hover:bg-bg-hover"
              >
                <span className="flex-1 truncate text-text-primary">{anonHostname(d.name)}</span>
                <span className="truncate text-[12px] text-text-muted">{d.siteName ?? '—'}</span>
                <span className="font-mono text-[11px] text-text-muted">{d.brand}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
