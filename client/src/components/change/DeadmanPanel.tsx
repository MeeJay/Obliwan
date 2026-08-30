import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { HeartPulse, ShieldCheck, ShieldOff, Timer, AlertTriangle } from 'lucide-react';
import { cn } from '@/utils/cn';
import { safetyNetOfLevel } from '@/api/change.api';
import type { ChangeJobView } from '@/types/change';
import { SafetyNetBadge } from './SafetyNetBadge';

/**
 * The dead-man, in one glance.
 *
 * ┌─ THE INFORMATION THAT REASSURES OR ALARMS DURING THE FIVE-MINUTE SOAK ───┐
 * │ There are exactly three questions an operator asks while a change is     │
 * │ live, and this panel answers all three without a click:                  │
 * │                                                                          │
 * │   1. IS THERE A NET ON THE BOX RIGHT NOW?  -> ARMED / NOT ARMED          │
 * │   2. HOW LONG UNTIL THE SOAK ENDS?          -> the countdown             │
 * │   3. HAS IT BEEN REMOVED YET?               -> DISARMED                  │
 * │                                                                          │
 * │ Question 3 is the one every other tool gets wrong. Until the disarm      │
 * │ lands, the router still carries a scheduler that will REVERT this change │
 * │ at its next boot. A job reported "succeeded" while a live router still   │
 * │ holds that scheduler is a lie waiting for a power cut — so DISARMED is   │
 * │ a state of its own here, with its own timestamp, and the panel says      │
 * │ plainly what an un-disarmed net means.                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── ARMED IS A FACT, NOT A PLAN ─────────────────────────────────────────────
 * `job.safetyLevel` is what was PLANNED at creation; `job.armedLevel` is what
 * was actually obtained on the box. They can differ — an `armed_by_peer`
 * intention can come back `degraded` when the peer did not answer. The panel
 * shows the obtained level once it exists and flags the downgrade, because a
 * screen that kept showing the intention would be showing a net nobody
 * installed.
 */

type DeadmanState = 'not_armed' | 'armed' | 'soaking' | 'disarmed' | 'fired';

function deadmanState(job: ChangeJobView): DeadmanState {
  if (job.status === 'rolled_back') return 'fired';
  if (job.deadmanDisarmedAt) return 'disarmed';
  if (!job.deadmanArmedAt) return 'not_armed';
  if (job.status === 'soaking') return 'soaking';
  return 'armed';
}

const STATE_TONE: Record<DeadmanState, string> = {
  not_armed: 'border-border bg-bg-secondary',
  armed: 'border-status-up/40 bg-status-up/5',
  soaking: 'border-accent/50 bg-accent/5',
  disarmed: 'border-border bg-bg-secondary',
  fired: 'border-status-ssl-warning/50 bg-status-ssl-warning/5',
};

const STATE_TEXT: Record<DeadmanState, string> = {
  not_armed: 'text-text-muted',
  armed: 'text-status-up',
  soaking: 'text-accent',
  disarmed: 'text-text-secondary',
  fired: 'text-status-ssl-warning',
};

const STATE_ICON: Record<DeadmanState, React.ReactNode> = {
  not_armed: <ShieldOff size={16} />,
  armed: <HeartPulse size={16} />,
  soaking: <Timer size={16} />,
  disarmed: <ShieldCheck size={16} />,
  fired: <AlertTriangle size={16} />,
};

export function DeadmanPanel({ job, className }: { job: ChangeJobView; className?: string }) {
  const { t } = useTranslation();
  const state = deadmanState(job);
  const remaining = useSoakCountdown(job.soakUntil, state === 'soaking');

  const plannedNet = safetyNetOfLevel(job.safetyLevel);
  const obtainedNet = job.armedLevel ? safetyNetOfLevel(job.armedLevel) : null;
  const downgraded = obtainedNet !== null && obtainedNet !== plannedNet;

  return (
    <section className={cn('rounded-lg border p-4', STATE_TONE[state], className)} aria-live="polite">
      <div className="flex flex-wrap items-start gap-3">
        <span className={cn('mt-0.5', STATE_TEXT[state])}>{STATE_ICON[state]}</span>
        <div className="min-w-[14rem] flex-1">
          <h3 className={cn('font-display text-base font-semibold', STATE_TEXT[state])}>
            {t(`change.deadman.title.${state}`)}
          </h3>
          <p className="mt-0.5 text-[13px] text-text-secondary">
            {t(`change.deadman.body.${state}`)}
          </p>
        </div>

        {state === 'soaking' && (
          <div className="text-right">
            <div className="text-[10px] uppercase tracking-wider text-text-muted">
              {t('change.deadman.soakRemaining')}
            </div>
            <div className="font-mono text-2xl font-semibold tabular-nums text-accent">
              {remaining === null ? '—' : formatDuration(remaining)}
            </div>
          </div>
        )}
      </div>

      {/* The net level actually obtained. */}
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-border/60 pt-3">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-text-muted">
            {t('change.deadman.plannedNet')}
          </div>
          <SafetyNetBadge level={plannedNet} className="mt-1" />
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-text-muted">
            {t('change.deadman.obtainedNet')}
          </div>
          {obtainedNet ? (
            <SafetyNetBadge level={obtainedNet} className="mt-1" />
          ) : (
            <span className="mt-1 block text-[12px] text-text-muted">
              {t('change.deadman.notArmedYet')}
            </span>
          )}
        </div>
        {job.safetyPeerDeviceName && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-text-muted">
              {t('change.deadman.peer')}
            </div>
            <span className="mt-1 block font-mono text-[12px] text-text-primary">
              {job.safetyPeerDeviceName}
            </span>
          </div>
        )}
      </div>

      {downgraded && (
        <p className="mt-2 rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/10 p-2.5 text-[12px] text-status-ssl-expired">
          {t('change.deadman.downgraded')}
        </p>
      )}

      {/* Timestamps. The disarm one is the important half. */}
      <dl className="mt-3 grid gap-x-6 gap-y-1 border-t border-border/60 pt-3 text-[12px] sm:grid-cols-2">
        <Stamp label={t('change.deadman.armedAt')} value={job.deadmanArmedAt} />
        <Stamp label={t('change.deadman.disarmedAt')} value={job.deadmanDisarmedAt} />
      </dl>

      {/* The sentence that must exist somewhere on this page. */}
      {state === 'armed' || state === 'soaking' ? (
        <p className="mt-2 text-[12px] font-medium text-text-primary">
          {t('change.deadman.stillArmedWarning')}
        </p>
      ) : state === 'disarmed' ? (
        <p className="mt-2 text-[12px] text-text-muted">{t('change.deadman.disarmedNote')}</p>
      ) : null}
    </section>
  );
}

function Stamp({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex gap-2">
      <dt className="w-28 shrink-0 text-text-muted">{label}</dt>
      <dd className="font-mono text-text-secondary">
        {value ? new Date(value).toLocaleString() : '—'}
      </dd>
    </div>
  );
}

/**
 * The countdown ticks in the CLIENT but the deadline comes from the SERVER
 * (`soakUntil`). A soak duration hard-coded here would drift from the executor
 * the first time somebody tunes it, and the operator would be watching a clock
 * that is not the one deciding.
 */
function useSoakCountdown(soakUntil: string | null, active: boolean): number | null {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active || !soakUntil) return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [active, soakUntil]);
  if (!soakUntil) return null;
  const end = new Date(soakUntil).getTime();
  if (Number.isNaN(end)) return null;
  return Math.max(0, end - now);
}

export function formatDuration(ms: number): string {
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}
