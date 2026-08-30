import { useTranslation } from 'react-i18next';
import {
  Ban,
  CheckCircle2,
  CircleDashed,
  Clock,
  Cpu,
  Download,
  HeartPulse,
  Undo2,
  Loader2,
  ShieldOff,
  Timer,
  XCircle,
  Zap,
} from 'lucide-react';
import type { ChangeJobStatus } from '@obliwan/shared';
import { cn } from '@/utils/cn';

/**
 * The twelve job states, painted.
 *
 * ┌─ THE TWO COLOUR DECISIONS THAT ARE NOT AESTHETIC ────────────────────────┐
 * │ 1. `rolled_back` IS NOT RED. It is amber, and its tooltip says the words │
 * │    out loud: the safety machinery WORKED. The device restored itself,    │
 * │    the configuration on the box is the pre-change configuration, and the │
 * │    site is up. Painting it as a failure teaches operators to fear the    │
 * │    one outcome that saved them a van, and an operator who fears the net  │
 * │    starts overriding it.                                                 │
 * │                                                                          │
 * │ 2. `succeeded` IS THE ONLY GREEN, and a job is not `succeeded` until the │
 * │    dead-man has been DISARMED. Until then the router still carries a     │
 * │    scheduler that reverts the change at its next boot. `disarming` is    │
 * │    therefore its own visible state and not a spinner on "finishing".     │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

const TONE: Record<ChangeJobStatus, string> = {
  queued: 'text-text-muted border-border bg-bg-tertiary',
  claimed: 'text-text-secondary border-border bg-bg-tertiary',
  backing_up: 'text-status-pending border-status-pending/40 bg-status-pending/10',
  arming: 'text-accent border-accent/40 bg-accent/10',
  applying: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  verifying: 'text-status-pending border-status-pending/40 bg-status-pending/10',
  soaking: 'text-accent border-accent/50 bg-accent/10',
  disarming: 'text-status-pending border-status-pending/40 bg-status-pending/10',
  succeeded: 'text-status-up border-status-up/50 bg-status-up/10',
  rolled_back: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  failed: 'text-status-ssl-expired border-status-ssl-expired/50 bg-status-ssl-expired/10',
  aborted: 'text-text-muted border-border bg-bg-tertiary',
};

const ICON: Record<ChangeJobStatus, React.ReactNode> = {
  queued: <Clock size={11} />,
  claimed: <CircleDashed size={11} />,
  backing_up: <Download size={11} />,
  arming: <HeartPulse size={11} />,
  applying: <Zap size={11} />,
  verifying: <Cpu size={11} />,
  soaking: <Timer size={11} />,
  disarming: <ShieldOff size={11} />,
  succeeded: <CheckCircle2 size={11} />,
  rolled_back: <Undo2 size={11} />,
  failed: <XCircle size={11} />,
  aborted: <Ban size={11} />,
};

/** The states in which something is actively happening — the badge spins. */
const SPINNING: ReadonlySet<ChangeJobStatus> = new Set<ChangeJobStatus>([
  'claimed', 'backing_up', 'arming', 'applying', 'verifying', 'disarming',
]);

export function JobStatusBadge({
  status,
  size = 'sm',
  className,
}: {
  status: ChangeJobStatus;
  size?: 'sm' | 'lg';
  className?: string;
}) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded border font-medium uppercase tracking-wider',
        size === 'lg' ? 'px-3 py-1.5 text-[13px]' : 'px-1.5 py-0.5 text-[10px]',
        TONE[status],
        className,
      )}
      title={t(`change.status.hint.${status}`)}
    >
      {SPINNING.has(status) ? (
        <Loader2 size={size === 'lg' ? 13 : 11} className="animate-spin" />
      ) : (
        ICON[status]
      )}
      {t(`change.status.label.${status}`)}
    </span>
  );
}

/** Kind chip: `push` / `export` / `backup` / `restore` / `reboot` / `firmware`.
 *  The read-only kinds are muted; they are jobs so the per-device lock covers
 *  them, but they cannot lock anybody out. */
const WRITE_KINDS = new Set(['push', 'restore', 'reboot', 'firmware']);

export function JobKindChip({ kind, className }: { kind: string; className?: string }) {
  const { t } = useTranslation();
  const isWrite = WRITE_KINDS.has(kind);
  return (
    <span
      className={cn(
        'rounded border px-1.5 py-0.5 font-mono text-[10px]',
        isWrite
          ? 'border-status-ssl-warning/40 bg-status-ssl-warning/10 text-status-ssl-warning'
          : 'border-border bg-bg-tertiary text-text-muted',
        className,
      )}
      title={isWrite ? t('change.kindWriteHint') : t('change.kindReadHint')}
    >
      {t(`change.kind.${kind}`, { defaultValue: kind })}
    </span>
  );
}
