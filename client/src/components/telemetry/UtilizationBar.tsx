import { useTranslation } from 'react-i18next';
import { cn } from '@/utils/cn';
import { formatPct } from '@/utils/series';
import { UTIL_BAND_FILL, UTIL_BAND_TEXT, utilBand } from '@/utils/interfaceStatus';

interface UtilizationBarProps {
  /** `null` = line speed unknown. Rendered as unknown, never as 0 %. */
  pct: number | null;
  className?: string;
}

/**
 * Saturation of a link as a fraction of its line speed.
 *
 * `pct === null` means `ifHighSpeed` was never read, so the ratio does not
 * exist. It is drawn as a HATCHED empty track with an em dash — visibly
 * different from a link measured at 0 %, which gets a real (tiny) bar. An
 * empty grey bar for both would tell an operator that a link he cannot measure
 * is idle.
 */
export function UtilizationBar({ pct, className }: UtilizationBarProps) {
  const { t } = useTranslation();
  const band = utilBand(pct);
  const width = pct === null ? 0 : Math.max(0, Math.min(100, pct));

  return (
    <div className={cn('flex items-center gap-2', className)}>
      <div
        className={cn(
          'h-1.5 w-16 shrink-0 overflow-hidden rounded-full',
          pct === null ? 'bg-bg-tertiary opacity-60' : 'bg-bg-tertiary',
        )}
        title={pct === null ? t('interfaces.speedUnknownHint') : formatPct(pct)}
        style={
          pct === null
            ? {
                backgroundImage:
                  'repeating-linear-gradient(45deg, currentColor 0 2px, transparent 2px 5px)',
                color: 'rgb(var(--c-text-muted) / 0.35)',
              }
            : undefined
        }
      >
        {pct !== null && (
          <div
            className={cn('h-full rounded-full transition-[width]', UTIL_BAND_FILL[band])}
            style={{ width: `${width}%` }}
          />
        )}
      </div>
      <span className={cn('font-mono text-[11px] tabular-nums', UTIL_BAND_TEXT[band])}>
        {formatPct(pct, 0)}
      </span>
    </div>
  );
}
