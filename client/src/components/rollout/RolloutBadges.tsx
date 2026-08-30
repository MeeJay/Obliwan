import { useTranslation } from 'react-i18next';
import {
  Activity,
  CheckCircle2,
  CircleDashed,
  CircleSlash,
  Clock,
  HeartPulse,
  MinusCircle,
  StopCircle,
  PauseCircle,
  Rocket,
  ShieldQuestion,
  Undo2,
  XCircle,
} from 'lucide-react';
import { cn } from '@/utils/cn';
import type { GateState, RolloutStatus, WaveStatus } from '@/types/rollout';

/**
 * The badges the rollout screens share.
 *
 * ┌─ THE RULE, INHERITED FROM `RiskBadge.tsx` ───────────────────────────────┐
 * │ A GATE THAT DID NOT CONCLUDE IS PAINTED ON THE REFUSING SIDE.            │
 * │                                                                          │
 * │ `unknown` means the signal never arrived: no PPP event, no SNMP sample,  │
 * │ no baseline to compare against. That proves nothing about the twenty     │
 * │ routers behind it, so it is NOT the amber that operators have been       │
 * │ trained by every other screen to click through, and it is NOT green.     │
 * │ The health gates of K3 exist to stop wave 2 from starting; a gate whose  │
 * │ default reading is "probably fine" is a gate that has been deleted.      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `rolled_back` is deliberately NOT red. The dead-man firing is the machinery
 * working — §8.3's whole argument — and a dashboard that files it under
 * failures teaches operators to disable the thing that saved them. It gets its
 * own amber-with-an-undo-arrow, on every screen, exactly as `ChangesPage`
 * counts it on its own line.
 */

// ── Rollout status ──────────────────────────────────────────────────────────

const ROLLOUT_TONE: Record<RolloutStatus, string> = {
  draft: 'text-text-muted border-border bg-bg-tertiary',
  running: 'text-accent border-accent/50 bg-accent/10',
  paused: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  halted: 'text-status-ssl-expired border-status-ssl-expired/60 bg-status-ssl-expired/15',
  aborted: 'text-text-muted border-border bg-bg-tertiary',
  rolled_back: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  succeeded: 'text-status-up border-status-up/50 bg-status-up/10',
  failed: 'text-status-ssl-expired border-status-ssl-expired/60 bg-status-ssl-expired/15',
};

const ROLLOUT_ICON: Record<RolloutStatus, React.ReactNode> = {
  draft: <CircleDashed size={11} />,
  running: <Rocket size={11} />,
  paused: <PauseCircle size={11} />,
  halted: <StopCircle size={11} />,
  aborted: <CircleSlash size={11} />,
  rolled_back: <Undo2 size={11} />,
  succeeded: <CheckCircle2 size={11} />,
  failed: <XCircle size={11} />,
};

export function RolloutStatusBadge({
  status,
  size = 'sm',
  className,
}: {
  status: RolloutStatus;
  size?: 'sm' | 'lg';
  className?: string;
}) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded border font-medium uppercase tracking-wider',
        size === 'lg' ? 'px-3 py-1.5 text-[13px]' : 'px-1.5 py-0.5 text-[10px]',
        ROLLOUT_TONE[status],
        className,
      )}
      title={t(`rollout.status.hint.${status}`)}
    >
      {ROLLOUT_ICON[status]}
      {t(`rollout.status.label.${status}`)}
    </span>
  );
}

// ── Wave status ─────────────────────────────────────────────────────────────

const WAVE_TONE: Record<WaveStatus, string> = {
  pending: 'text-text-muted border-border bg-bg-tertiary',
  running: 'text-accent border-accent/50 bg-accent/10',
  gating: 'text-status-pending border-status-pending/50 bg-status-pending/10',
  passed: 'text-status-up border-status-up/50 bg-status-up/10',
  failed: 'text-status-ssl-expired border-status-ssl-expired/60 bg-status-ssl-expired/15',
  rolled_back: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  skipped: 'text-text-muted border-border bg-bg-tertiary',
};

const WAVE_ICON: Record<WaveStatus, React.ReactNode> = {
  pending: <Clock size={11} />,
  running: <Activity size={11} />,
  gating: <HeartPulse size={11} />,
  passed: <CheckCircle2 size={11} />,
  failed: <XCircle size={11} />,
  rolled_back: <Undo2 size={11} />,
  skipped: <MinusCircle size={11} />,
};

export function WaveStatusBadge({ status, className }: { status: WaveStatus; className?: string }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
        WAVE_TONE[status],
        className,
      )}
      title={t(`rollout.wave.hint.${status}`)}
    >
      {WAVE_ICON[status]}
      {t(`rollout.wave.label.${status}`)}
    </span>
  );
}

// ── Gate state ──────────────────────────────────────────────────────────────

const GATE_TONE: Record<GateState, string> = {
  pending: 'text-text-muted border-border bg-bg-tertiary',
  pass: 'text-status-up border-status-up/50 bg-status-up/10',
  // Two reds again, and for the same reason as `RiskBadge`: `fail` is a proof
  // that a signal went bad, `unknown` is an admission that no signal arrived.
  // Neither is amber and neither reads as "carry on".
  fail: 'text-status-ssl-expired border-status-ssl-expired/60 bg-status-ssl-expired/15',
  unknown: 'text-status-down border-status-down/60 bg-status-down/15',
  skipped: 'text-text-muted border-border bg-bg-tertiary',
};

const GATE_ICON: Record<GateState, React.ReactNode> = {
  pending: <Clock size={10} />,
  pass: <CheckCircle2 size={10} />,
  fail: <XCircle size={10} />,
  unknown: <ShieldQuestion size={10} />,
  skipped: <MinusCircle size={10} />,
};

export function GateStateBadge({ state, className }: { state: GateState; className?: string }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
        GATE_TONE[state],
        className,
      )}
      title={t(`rollout.gate.stateHint.${state}`)}
    >
      {GATE_ICON[state]}
      {t(`rollout.gate.state.${state}`)}
    </span>
  );
}

/** A gate has cleared only when it says so. Everything else — pending,
 *  unknown, skipped, fail — is "not cleared". There is no other reading of a
 *  gate anywhere in this client. */
export function gateCleared(state: GateState): boolean {
  return state === 'pass';
}
