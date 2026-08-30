import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, ClipboardCheck, AlertOctagon, Rocket } from 'lucide-react';
import type { ChangeJobKind } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import { Button } from '@/components/common/Button';
import { GuardVerdictBadge, RiskBadge, guardBadgeState, guardClears } from '@/components/plan/RiskBadge';
import { SafetyNetPanel } from './SafetyNetBadge';
import type { CompiledPlan, SafetyNetLevel } from '@/types/change';

/**
 * The launch screen — the last thing an operator sees before ObliWAN writes to
 * a customer's router.
 *
 * ┌─ WHAT THIS DIALOG IS ALLOWED TO DO ──────────────────────────────────────┐
 * │ It launches a change whose guard verdict is ACCEPT. Nothing else.        │
 * │                                                                          │
 * │ There is NO override control anywhere in this file, not disabled, not    │
 * │ behind a checkbox: absent. Overriding an anti-lockout protection must    │
 * │ not be reachable by a mis-aimed click next to "Apply", so it lives on a  │
 * │ separate screen (`OverrideDialog`) opened from a separate, visually      │
 * │ distinct part of the page. If the guard has not cleared this plan, this  │
 * │ dialog refuses to render its button at all.                              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── §8.3: THE NET IS SHOWN BEFORE, AND THE DEGRADED CONFIRMATION IS COSTLY ──
 * The safety-net panel is the FIRST block, above the plan summary, because the
 * question "what repairs this box if I am wrong" outranks "what am I
 * changing". On a DEGRADED device the confirmation is:
 *
 *   - not a pre-checked box. Not a checkbox at all.
 *   - a sentence the operator must READ and a device name he must TYPE.
 *
 * Typing the hostname is the cheapest gesture that cannot be performed by
 * reflex, and it is the same gesture every destructive-delete dialog in this
 * industry uses — which is exactly why an operator recognises it as "this one
 * is different".
 */

export interface LaunchSubmit {
  kind: ChangeJobKind;
  degradedConfirmed: boolean;
  scheduledFor: string | null;
}

interface LaunchChangeDialogProps {
  compiled: CompiledPlan;
  deviceName: string;
  safetyNet: SafetyNetLevel;
  peerName: string | null;
  /** From `changeStore.writesAllowed()`. False = the server cannot apply, or
   *  the kill switch is engaged. The dialog states which. */
  writesAllowed: boolean;
  killSwitchBlocked: boolean;
  applyMilestone: string | null;
  /** Freshness verdict from `POST /plan/validate`, re-checked on open. */
  fresh: boolean | null;
  freshMessage: string | null;
  submitting: boolean;
  onSubmit: (req: LaunchSubmit) => void;
  onClose: () => void;
}

export function LaunchChangeDialog({
  compiled,
  deviceName,
  safetyNet,
  peerName,
  writesAllowed,
  killSwitchBlocked,
  applyMilestone,
  fresh,
  freshMessage,
  submitting,
  onSubmit,
  onClose,
}: LaunchChangeDialogProps) {
  const { t } = useTranslation();
  const [typed, setTyped] = useState('');
  const [scheduledFor, setScheduledFor] = useState('');

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !submitting) onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, submitting]);

  const degraded = safetyNet === 'DEGRADED';
  const cleared = guardClears(compiled.guard);
  const nameMatches = typed.trim() === deviceName.trim() && deviceName.trim().length > 0;

  const changeOps = useMemo(
    () => compiled.plan.ops.filter((o) => o.kind !== 'verify' && o.kind !== 'blocked'),
    [compiled.plan.ops],
  );
  const disruptive = useMemo(
    () => changeOps.filter((o) => o.disruptive).length,
    [changeOps],
  );

  // Every reason the button stays down, listed rather than implied. A disabled
  // button with no sentence next to it is the single most common cause of an
  // operator inventing a workaround.
  const blockers: string[] = [];
  if (!cleared) blockers.push(t('change.launch.blocked.guard'));
  if (killSwitchBlocked) blockers.push(t('change.launch.blocked.killSwitch'));
  if (!writesAllowed && !killSwitchBlocked) {
    blockers.push(
      applyMilestone
        ? t('change.launch.blocked.milestone', { milestone: applyMilestone })
        : t('change.launch.blocked.serverRefuses'),
    );
  }
  if (fresh === false) blockers.push(t('change.launch.blocked.stale'));
  if (!compiled.plan.orderConverges) blockers.push(t('change.launch.blocked.convergence'));
  if (changeOps.length === 0) blockers.push(t('change.launch.blocked.noOps'));
  if (degraded && !nameMatches) blockers.push(t('change.launch.blocked.degradedConfirm'));

  const canLaunch = blockers.length === 0 && !submitting;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
      <div className="my-8 w-full max-w-2xl rounded-xl border border-border bg-bg-secondary shadow-2xl">
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <Rocket size={18} className="text-accent" />
          <div>
            <h2 className="text-base font-semibold text-text-primary">
              {t('change.launch.title')}
            </h2>
            <p className="font-mono text-[11px] text-text-muted">{deviceName}</p>
          </div>
        </div>

        <div className="space-y-4 p-5">
          {/* §8.3 — the net, first, before the plan summary. */}
          <SafetyNetPanel level={safetyNet} peerName={peerName} />

          {/* The guard verdict is restated here rather than assumed read on the
              page behind the dialog: this is the moment of commitment. */}
          <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-bg-primary/40 p-3">
            <GuardVerdictBadge state={guardBadgeState(compiled.guard)} />
            <span className="min-w-[12rem] flex-1 text-[12px] text-text-secondary">
              {compiled.guard.ran && compiled.guard.summary
                ? compiled.guard.summary
                : t(`plan.guard.body.${guardBadgeState(compiled.guard)}`)}
            </span>
            <RiskBadge risk={compiled.plan.riskLevel} />
          </div>

          {/* What is about to happen, in counts. */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label={t('change.launch.opsToApply')} value={String(changeOps.length)} />
            <Stat
              label={t('change.launch.disruptive')}
              value={String(disruptive)}
              tone={disruptive > 0 ? 'warn' : 'muted'}
            />
            <Stat
              label={t('change.launch.mgmtPath')}
              value={compiled.plan.blastRadius.touchesManagementPath ? t('common.yes') : t('common.no')}
              tone={compiled.plan.blastRadius.touchesManagementPath ? 'bad' : 'muted'}
            />
            <Stat label={t('change.launch.sites')} value={String(compiled.plan.blastRadius.siteCount)} />
          </div>

          {/* What the machinery will do on its own, spelled out. An operator who
              knows a backup is taken and a net armed does not go looking for a
              manual backup button that does not exist. */}
          <div className="rounded-lg border border-border bg-bg-primary/40 p-3">
            <h3 className="mb-1.5 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-text-muted">
              <ClipboardCheck size={12} />
              {t('change.launch.sequenceTitle')}
            </h3>
            <ol className="list-inside list-decimal space-y-0.5 text-[12px] text-text-secondary">
              <li>{t('change.launch.sequence.bind')}</li>
              <li>{t('change.launch.sequence.backup')}</li>
              <li>{t('change.launch.sequence.arm')}</li>
              <li>{t('change.launch.sequence.apply')}</li>
              <li>{t('change.launch.sequence.reconnect')}</li>
              <li>{t('change.launch.sequence.soak')}</li>
              <li>{t('change.launch.sequence.disarm')}</li>
            </ol>
          </div>

          {fresh === false && (
            <div className="rounded-md border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-3">
              <h3 className="flex items-center gap-1.5 text-[12px] font-semibold text-status-ssl-expired">
                <AlertTriangle size={13} />
                {t('change.launch.staleTitle')}
              </h3>
              <p className="mt-1 text-[12px] text-text-secondary">
                {freshMessage ?? t('change.launch.staleBody')}
              </p>
            </div>
          )}

          {/* §8.3's explicit confirmation. Typed, never checked. */}
          {degraded && (
            <div className="rounded-lg border border-status-ssl-expired/60 bg-status-ssl-expired/10 p-4">
              <h3 className="flex items-center gap-1.5 text-sm font-semibold text-status-ssl-expired">
                <AlertOctagon size={15} />
                {t('change.launch.degradedTitle')}
              </h3>
              <p className="mt-1.5 text-[13px] text-text-primary">
                {t('change.launch.degradedBody1')}
              </p>
              <p className="mt-1.5 text-[13px] text-text-primary">
                {t('change.launch.degradedBody2')}
              </p>
              <label className="mt-3 block text-[12px] font-medium text-text-secondary">
                {t('change.launch.typeDeviceName', { name: deviceName })}
              </label>
              <input
                type="text"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder={deviceName}
                className={cn(
                  'mt-1 w-full rounded-md border bg-bg-tertiary px-3 py-2 font-mono text-[13px] text-text-primary focus:outline-none focus:ring-1',
                  nameMatches
                    ? 'border-status-up/60 focus:ring-status-up'
                    : 'border-status-ssl-expired/60 focus:ring-status-ssl-expired',
                )}
              />
            </div>
          )}

          {/* Optional maintenance window start. */}
          <div>
            <label className="mb-1 block text-[12px] font-medium text-text-secondary">
              {t('change.launch.scheduleLabel')}
            </label>
            <input
              type="datetime-local"
              value={scheduledFor}
              onChange={(e) => setScheduledFor(e.target.value)}
              className="rounded-md border border-border bg-bg-tertiary px-3 py-2 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            />
            <p className="mt-1 text-[11px] text-text-muted">{t('change.launch.scheduleHint')}</p>
          </div>

          {blockers.length > 0 && (
            <div className="rounded-md border border-border bg-bg-primary/40 p-3">
              <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wider text-text-muted">
                {t('change.launch.blockedTitle')}
              </h3>
              <ul className="list-inside list-disc space-y-0.5 text-[12px] text-text-secondary">
                {blockers.map((b, i) => <li key={i}>{b}</li>)}
              </ul>
            </div>
          )}
        </div>

        <div className="flex flex-wrap justify-end gap-2 border-t border-border px-5 py-3">
          <Button variant="ghost" size="sm" onClick={onClose} disabled={submitting}>
            {t('common.cancel')}
          </Button>
          <Button
            variant="primary"
            size="sm"
            loading={submitting}
            disabled={!canLaunch}
            onClick={() =>
              onSubmit({
                kind: 'push',
                degradedConfirmed: degraded && nameMatches,
                scheduledFor: scheduledFor ? new Date(scheduledFor).toISOString() : null,
              })
            }
          >
            <Rocket size={14} className="mr-1.5" />
            {t('change.launch.confirm')}
          </Button>
        </div>
      </div>
    </div>
  );
}

const TONES = {
  warn: 'text-status-ssl-warning',
  bad: 'text-status-ssl-expired',
  muted: 'text-text-primary',
};

function Stat({
  label,
  value,
  tone = 'muted',
}: {
  label: string;
  value: string;
  tone?: keyof typeof TONES;
}) {
  return (
    <div className="rounded-md border border-border bg-bg-primary/40 p-2.5">
      <div className="text-[10px] uppercase tracking-wider text-text-muted">{label}</div>
      <div className={cn('mt-0.5 font-display text-lg font-semibold tabular-nums', TONES[tone])}>
        {value}
      </div>
    </div>
  );
}
