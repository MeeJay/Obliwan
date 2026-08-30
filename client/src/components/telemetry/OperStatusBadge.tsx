import { useTranslation } from 'react-i18next';
import { PowerOff } from 'lucide-react';
import { cn } from '@/utils/cn';
import {
  adminStatusLabelKey,
  isAdminDown,
  operStatusLabelKey,
  operStatusStyle,
} from '@/utils/interfaceStatus';
import type { IfOperStatusCode } from '@obliwan/shared';

interface OperStatusBadgeProps {
  operStatus: IfOperStatusCode | number | null | undefined;
  adminStatus: number | null | undefined;
  className?: string;
}

/**
 * The operational state of a port, with its administrative state folded in.
 *
 * An `oper=down` port that is also `admin=down` is drawn MUTED with a power
 * icon, not red: it is switched off on purpose. Only a port that is
 * administratively up and operationally down is an event.
 */
export function OperStatusBadge({ operStatus, adminStatus, className }: OperStatusBadgeProps) {
  const { t } = useTranslation();
  const adminDown = isAdminDown(adminStatus);

  return (
    <span className={cn('inline-flex items-center gap-1.5', className)}>
      <span
        className={cn(
          'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium',
          adminDown
            ? 'border-dashed border-text-muted/50 bg-transparent text-text-muted'
            : operStatusStyle(operStatus),
        )}
        title={t(operStatusLabelKey(operStatus))}
      >
        {t(operStatusLabelKey(operStatus))}
      </span>
      {adminDown && (
        <span
          className="inline-flex items-center gap-0.5 text-[10px] text-text-muted"
          title={t('interfaces.adminDownHint')}
        >
          <PowerOff size={9} />
          {t(adminStatusLabelKey(adminStatus))}
        </span>
      )}
    </span>
  );
}
