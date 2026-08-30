import { useTranslation } from 'react-i18next';
import { HelpCircle } from 'lucide-react';
import type { ReachabilityVerdict } from '@obliwan/shared';
import { ALERTABLE_VERDICTS } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import { verdictStyle, verdictLabelKey, verdictHintKey } from '@/utils/verdict';

interface VerdictBadgeProps {
  verdict: ReachabilityVerdict | null | undefined;
  /** Show the one-line explanation next to the pill (detail pages). */
  withHint?: boolean;
  className?: string;
}

/**
 * K7 verdict pill.
 *
 * `UNREACHABLE` gets a dashed border and a question mark rather than a solid
 * colour: it is an observability gap, not a site outage, and it is
 * deliberately absent from `ALERTABLE_VERDICTS`. The badge says so out loud so
 * nobody dispatches a van on the strength of a grey pill.
 */
export function VerdictBadge({ verdict, withHint = false, className }: VerdictBadgeProps) {
  const { t } = useTranslation();
  const effective: ReachabilityVerdict = verdict ?? 'UNREACHABLE';
  const style = verdictStyle(effective);
  const alertable = ALERTABLE_VERDICTS.includes(effective);

  return (
    <span className={cn('inline-flex items-center gap-1.5', className)}>
      <span
        className={cn(
          'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium whitespace-nowrap',
          style.pill,
        )}
        title={t(verdictHintKey(effective))}
      >
        {effective === 'UNREACHABLE' && <HelpCircle size={10} />}
        {t(verdictLabelKey(effective))}
      </span>
      {withHint && (
        <span className="text-xs text-text-muted">
          {t(verdictHintKey(effective))}
          {!alertable && effective !== 'UP' && (
            <span className="ml-1 italic">({t('fleet.notAlertable')})</span>
          )}
        </span>
      )}
    </span>
  );
}
