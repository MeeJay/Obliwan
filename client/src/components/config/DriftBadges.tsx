import { useTranslation } from 'react-i18next';
import { AlertTriangle, CheckCircle2, GitCompareArrows, PlugZap } from 'lucide-react';
import type { DiffSeverity } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import type { DriftCause, DriftStatus } from '@/types/config';

/**
 * The three badges the drift screens share.
 *
 * ── ONE DISTINCTION THAT MUST NEVER BE COLLAPSED ────────────────────────────
 * `error` and `unreachable` are different colours, different icons and
 * different words. A box we could not reach is an infrastructure event that the
 * customer's WAN explains; a run that blew up is OUR bug. Painting them the
 * same shade of red is how our own failures spend six months hiding behind
 * somebody's flaky DSL line — which is exactly why migration 007 keeps them as
 * two separate values instead of one `failed`.
 *
 * `in_sync` is the only green, and it is green even when the run counted inert
 * moves or out-of-scope objects: neither is a finding, and colouring a device
 * amber for them would reintroduce the noise §4.4 removed.
 */

const STATUS_TONE: Record<DriftStatus, string> = {
  in_sync: 'text-status-up border-status-up/40 bg-status-up/10',
  drifted: 'text-status-ssl-warning border-status-ssl-warning/40 bg-status-ssl-warning/10',
  error: 'text-status-ssl-expired border-status-ssl-expired/40 bg-status-ssl-expired/10',
  unreachable: 'text-text-muted border-border bg-bg-tertiary',
};

const STATUS_ICON: Record<DriftStatus, React.ReactNode> = {
  in_sync: <CheckCircle2 size={11} />,
  drifted: <GitCompareArrows size={11} />,
  error: <AlertTriangle size={11} />,
  unreachable: <PlugZap size={11} />,
};

export function DriftStatusBadge({ status, className }: { status: DriftStatus; className?: string }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px]',
        STATUS_TONE[status],
        className,
      )}
      title={t(`drift.statusHint.${status}`)}
    >
      {STATUS_ICON[status]}
      {t(`drift.status.${status}`)}
    </span>
  );
}

const SEVERITY_TONE: Record<DiffSeverity, string> = {
  critical: 'text-status-ssl-expired border-status-ssl-expired/50 bg-status-ssl-expired/10',
  high: 'text-status-down border-status-down/50 bg-status-down/10',
  medium: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  low: 'text-status-pending border-status-pending/50 bg-status-pending/10',
  info: 'text-text-muted border-border bg-bg-tertiary',
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: DiffSeverity | null;
  className?: string;
}) {
  const { t } = useTranslation();
  if (severity === null) {
    return <span className={cn('text-[11px] text-text-muted', className)}>—</span>;
  }
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
        SEVERITY_TONE[severity],
        className,
      )}
    >
      {t(`ncm.severity.${severity}`)}
    </span>
  );
}

/**
 * `renormalization` and `model_upgrade` are OURS: §6.5 excludes them from
 * attribution by construction. They are chipped differently on purpose, so that
 * when M8 lands and the attribution banner appears, "nobody did this, we did"
 * is already the sentence the screen was saying.
 */
export function CauseChip({ cause, className }: { cause: DriftCause; className?: string }) {
  const { t } = useTranslation();
  const ours = cause === 'renormalization' || cause === 'model_upgrade';
  return (
    <span
      className={cn(
        'rounded border px-1.5 py-0.5 font-mono text-[10px]',
        ours
          ? 'border-accent/40 bg-accent/10 text-accent'
          : 'border-border bg-bg-tertiary text-text-muted',
        className,
      )}
      title={ours ? t('drift.causeOursHint') : undefined}
    >
      {t(`drift.cause.${cause}`)}
    </span>
  );
}
