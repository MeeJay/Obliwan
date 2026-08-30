import type { MaintenanceWindow } from '@/types/fleet';

/**
 * Localised weekday names, derived from `Intl` rather than from 18 × 7
 * translation keys. 2024-01-07 is a Sunday, so index 0 = Sunday, matching the
 * convention the change scheduler stores.
 */
export function weekdayNames(locale: string): string[] {
  const fmt = new Intl.DateTimeFormat(locale, { weekday: 'short' });
  return Array.from({ length: 7 }, (_, i) => fmt.format(new Date(Date.UTC(2024, 0, 7 + i))));
}

/**
 * Render a maintenance window for display.
 *
 * Returns `null` when there is no window — the caller decides how to say "no
 * window configured", because "no window" and "window 00:00–00:00" are two
 * very different facts for a change that is about to be pushed.
 */
export function formatMaintenanceWindow(
  window: MaintenanceWindow | null | undefined,
  locale: string,
): string | null {
  if (!window) return null;
  const { days, start, end, tz } = window;
  const hasHours = Boolean(start && end);
  const hasDays = Array.isArray(days) && days.length > 0;
  if (!hasHours && !hasDays) return null;

  const names = weekdayNames(locale);
  const dayPart = hasDays
    ? days!
        .slice()
        .sort((a, b) => a - b)
        .map((d) => names[((d % 7) + 7) % 7])
        .join(', ')
    : null;
  const hourPart = hasHours ? `${start}–${end}` : null;

  return [dayPart, hourPart, tz].filter(Boolean).join(' · ');
}
