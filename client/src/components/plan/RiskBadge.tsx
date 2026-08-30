import { useTranslation } from 'react-i18next';
import {
  ArrowDownUp,
  Ban,
  CheckCircle2,
  PlusCircle,
  Eye,
  EyeOff,
  FileCheck2,
  Pencil,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Trash2,
  Zap,
} from 'lucide-react';
import type { GuardVerdict, PlanOpKind, RiskLevel } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import type { GuardResultView } from '@/types/change';

/**
 * The badges the plan and change screens share.
 *
 * ┌─ THE ONE RULE OF THIS FILE ──────────────────────────────────────────────┐
 * │ `INDETERMINATE` IS PAINTED AS A REFUSAL, NOT AS A WARNING.               │
 * │                                                                          │
 * │ It is red, it carries a shield-with-a-bar icon, and the word next to it  │
 * │ is REFUSED. It is deliberately NOT the amber used everywhere else in     │
 * │ this application for "look at this later", because amber is the colour   │
 * │ operators have been trained by every other screen to click through.      │
 * │                                                                          │
 * │ `shared/src/change.ts` says it in the type: "anywhere this union is      │
 * │ narrowed with `!== 'REJECT'`, the milestone is broken". A yellow chip is │
 * │ that narrowing, expressed in CSS instead of TypeScript. The two reds are │
 * │ different shades only so the operator can tell a PROOF of a cut from an  │
 * │ ADMISSION of blindness — never so that one of them reads as safe.        │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

// ── Risk ────────────────────────────────────────────────────────────────────

const RISK_TONE: Record<RiskLevel, string> = {
  low: 'text-status-pending border-status-pending/50 bg-status-pending/10',
  medium: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  high: 'text-status-ssl-expired border-status-ssl-expired/50 bg-status-ssl-expired/10',
};

/**
 * Plan risk. Amber is legitimate HERE: `medium` genuinely is "read this before
 * you press", and the risk level does not gate the apply — the guard does.
 *
 * `high` is not decoration either: `change_approvals` (§3.5) makes four-eyes
 * mandatory at `high`, so this badge is the operator's first sight of the fact
 * that this plan will need a second pair of eyes.
 */
export function RiskBadge({
  risk,
  className,
  showLabel = true,
}: {
  risk: RiskLevel;
  className?: string;
  showLabel?: boolean;
}) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
        RISK_TONE[risk],
        className,
      )}
      title={t(`plan.riskHint.${risk}`)}
    >
      {showLabel ? t(`plan.risk.${risk}`) : ''}
    </span>
  );
}

// ── Guard verdict ───────────────────────────────────────────────────────────

/**
 * `notRun` is a FOURTH visual state and it is on the refusing side.
 *
 * A plan compiled by an M5 server carries `mgmtPathVerdict: 'indeterminate'`
 * because the guard did not exist, not because it looked and could not tell.
 * Rendering that as an ordinary INDETERMINATE would let an operator believe a
 * forwarding engine examined his firewall. It did not.
 */
export type GuardBadgeState = GuardVerdict | 'NOT_RUN';

export function guardBadgeState(guard: GuardResultView | null | undefined): GuardBadgeState {
  if (!guard || !guard.ran) return 'NOT_RUN';
  return guard.verdict;
}

/** THE predicate. Only a guard that RAN and answered ACCEPT clears a plan.
 *  Everything else — REJECT, INDETERMINATE, never-run — needs a signed
 *  override. There is no other reading of this anywhere in the client. */
export function guardClears(guard: GuardResultView | null | undefined): boolean {
  return guardBadgeState(guard) === 'ACCEPT';
}

const VERDICT_TONE: Record<GuardBadgeState, string> = {
  ACCEPT: 'text-status-up border-status-up/50 bg-status-up/10',
  // Two reds, both red. `REJECT` is the proof, `INDETERMINATE` is the
  // admission of blindness; neither is amber and neither is clickable-through.
  REJECT: 'text-status-ssl-expired border-status-ssl-expired/60 bg-status-ssl-expired/15',
  INDETERMINATE: 'text-status-down border-status-down/60 bg-status-down/15',
  NOT_RUN: 'text-status-down border-status-down/60 bg-status-down/15',
};

const VERDICT_ICON: Record<GuardBadgeState, React.ReactNode> = {
  ACCEPT: <ShieldCheck size={12} />,
  REJECT: <ShieldX size={12} />,
  INDETERMINATE: <ShieldAlert size={12} />,
  NOT_RUN: <ShieldAlert size={12} />,
};

export function GuardVerdictBadge({
  state,
  size = 'sm',
  className,
}: {
  state: GuardBadgeState;
  size?: 'sm' | 'lg';
  className?: string;
}) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded border font-medium uppercase tracking-wider',
        size === 'lg' ? 'px-3 py-1.5 text-[13px]' : 'px-1.5 py-0.5 text-[10px]',
        VERDICT_TONE[state],
        className,
      )}
      title={t(`plan.guard.hint.${state}`)}
    >
      {VERDICT_ICON[state]}
      {t(`plan.guard.verdict.${state}`)}
    </span>
  );
}

// ── Plan op kinds ───────────────────────────────────────────────────────────

const OP_TONE: Record<PlanOpKind, string> = {
  create: 'text-status-up border-status-up/40 bg-status-up/10',
  update: 'text-status-ssl-warning border-status-ssl-warning/40 bg-status-ssl-warning/10',
  delete: 'text-status-ssl-expired border-status-ssl-expired/40 bg-status-ssl-expired/10',
  move: 'text-status-pending border-status-pending/40 bg-status-pending/10',
  enable: 'text-status-up border-status-up/40 bg-status-up/10',
  disable: 'text-status-down border-status-down/40 bg-status-down/10',
  verify: 'text-text-muted border-border bg-bg-tertiary',
  blocked: 'text-text-muted border-border bg-bg-tertiary',
};

const OP_ICON: Record<PlanOpKind, React.ReactNode> = {
  create: <PlusCircle size={11} />,
  update: <Pencil size={11} />,
  delete: <Trash2 size={11} />,
  move: <ArrowDownUp size={11} />,
  enable: <Eye size={11} />,
  disable: <EyeOff size={11} />,
  verify: <FileCheck2 size={11} />,
  blocked: <Ban size={11} />,
};

/** `blocked` is INFORMATION, not a failure (`PLAN_BLOCK_REASONS`): the operator
 *  gets to read why an op could not be produced instead of a greyed-out
 *  button. It is therefore chipped like everything else, in the muted tone. */
export function OpKindChip({ kind, className }: { kind: PlanOpKind; className?: string }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px]',
        OP_TONE[kind],
        className,
      )}
    >
      {OP_ICON[kind]}
      {t(`plan.opKind.${kind}`)}
    </span>
  );
}

/**
 * The disruptive marker.
 *
 * `PlanOp.disruptive` is what the K1 arming decision reads: an op that may drop
 * the session it is applied through. It is shown on the plan line because it is
 * the operator's only advance warning that the connection he is watching the
 * job over is the one about to go away.
 */
export function DisruptiveChip({ className }: { className?: string }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border border-status-ssl-warning/40 bg-status-ssl-warning/10 px-1.5 py-0.5 text-[10px] text-status-ssl-warning',
        className,
      )}
      title={t('plan.disruptiveHint')}
    >
      <Zap size={10} />
      {t('plan.disruptive')}
    </span>
  );
}

/** Used on the op rows the guard blamed. Not a badge — a marker, so the eye
 *  lands on the three lines out of fifty that caused the refusal. */
export function CulpritChip({ className }: { className?: string }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border border-status-ssl-expired/60 bg-status-ssl-expired/15 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-status-ssl-expired',
        className,
      )}
      title={t('plan.culpritHint')}
    >
      <ShieldX size={10} />
      {t('plan.culprit')}
    </span>
  );
}

/** Green tick used by the freshness / convergence lines. Kept here so the one
 *  green in these screens has exactly one definition. */
export function OkChip({ label, className }: { label: string; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border border-status-up/40 bg-status-up/10 px-1.5 py-0.5 text-[10px] text-status-up',
        className,
      )}
    >
      <CheckCircle2 size={10} />
      {label}
    </span>
  );
}
