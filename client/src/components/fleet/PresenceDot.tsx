import { useTranslation } from 'react-i18next';
import type { ReachabilityVerdict } from '@obliwan/shared';
import type { DevicePresence } from '@/types/fleet';
import { cn } from '@/utils/cn';
import { verdictStyle, verdictLabelKey, verdictHintKey } from '@/utils/verdict';

interface PresenceDotProps {
  presence: DevicePresence | null;
  size?: number;
  className?: string;
}

/**
 * The live PPP pastille.
 *
 * Three states, never two:
 *   • filled colour   — a verdict is known (green UP, red SITE_DOWN, …)
 *   • hollow ring     — UNREACHABLE: the observer is blind, not the site dead
 *   • hollow ring     — nothing observed at all yet
 *
 * `presence === null` is NOT rendered as an outage. A page that has just
 * loaded knows nothing, and saying "down" would page a technician for a fleet
 * that is perfectly healthy.
 */
export function PresenceDot({ presence, size = 8, className }: PresenceDotProps) {
  const { t } = useTranslation();
  const verdict: ReachabilityVerdict = presence?.verdict ?? 'UNREACHABLE';
  const style = verdictStyle(verdict);
  const unknown = !presence || presence.up === null;

  const label = t(verdictLabelKey(verdict));
  const hint = t(verdictHintKey(verdict));
  const at = presence?.at ? new Date(presence.at).toLocaleString() : null;

  return (
    <span
      role="img"
      aria-label={label}
      title={`${label} — ${hint}${at ? `\n${t('fleet.lastChange')}: ${at}` : ''}`}
      className={cn(
        'inline-block shrink-0 rounded-full',
        unknown ? 'bg-transparent border-2 border-text-muted/60' : style.dot,
        className,
      )}
      style={{ width: size, height: size }}
    />
  );
}
