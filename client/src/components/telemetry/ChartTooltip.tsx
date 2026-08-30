import { useTranslation } from 'react-i18next';

/**
 * Recharts injects `active` / `payload` / `label` into whatever element is
 * given to `<Tooltip content={…} />`, so every one of them is optional here.
 */
export interface TooltipEntry {
  dataKey?: string | number;
  name?: string | number;
  value?: number | string | null;
  color?: string;
  payload?: Record<string, unknown>;
}

export interface ChartTooltipProps {
  active?: boolean;
  payload?: TooltipEntry[];
  label?: string | number;
  /** Renders one datum. Receives the raw value. */
  formatValue: (value: number) => string;
  /** i18n key per dataKey, e.g. `{ inBps: 'interfaces.chart.inbound' }`. */
  labels: Record<string, string>;
  /** Epoch-ms → human timestamp. */
  formatTime: (t: number) => string;
}

/**
 * The tooltip is where the gap rule gets its second enforcement.
 *
 * A hovered point whose value is `null` prints "no measurement", never "0".
 * The chart already refuses to draw a line across the hole; if the tooltip
 * said "0 bit/s" there, we would have hidden the outage in the one place an
 * operator looks to confirm what he is seeing.
 */
export function ChartTooltip({
  active,
  payload,
  label,
  formatValue,
  labels,
  formatTime,
}: ChartTooltipProps) {
  const { t } = useTranslation();
  if (!active || !payload || payload.length === 0) return null;

  const ts = typeof label === 'number' ? formatTime(label) : String(label ?? '');

  // A rollup bucket that carried too few samples arrives with null metrics and
  // a sampleCount the API kept. Surfacing it turns "why is there a hole here"
  // into an answer instead of a support ticket.
  const first = payload[0]?.payload as
    | { sampleCount?: number; expectedCount?: number; gap?: boolean }
    | undefined;
  const allNull = payload.every((e) => e.value === null || e.value === undefined);

  return (
    <div
      className="rounded-md border border-border-light bg-bg-secondary px-2.5 py-2 shadow-lg"
      style={{ minWidth: 150 }}
    >
      <div className="mb-1 font-mono text-[10px] text-text-muted">{ts}</div>
      {allNull ? (
        <div className="text-[12px] text-text-muted">{t('interfaces.chart.noMeasurement')}</div>
      ) : (
        <ul className="space-y-0.5">
          {payload.map((entry) => {
            const key = String(entry.dataKey ?? '');
            const value = entry.value;
            return (
              <li key={key} className="flex items-center gap-2 text-[12px]">
                <span
                  className="inline-block h-2 w-2 shrink-0 rounded-sm"
                  style={{ backgroundColor: entry.color }}
                />
                <span className="flex-1 text-text-secondary">{t(labels[key] ?? key)}</span>
                <span className="font-mono tabular-nums text-text-primary">
                  {typeof value === 'number'
                    ? formatValue(value)
                    : t('interfaces.chart.noMeasurement')}
                </span>
              </li>
            );
          })}
        </ul>
      )}
      {first?.sampleCount !== undefined && first.expectedCount !== undefined && (
        <div className="mt-1 border-t border-border pt-1 font-mono text-[10px] text-text-muted">
          {t('interfaces.chart.samples', {
            count: first.sampleCount,
            expected: first.expectedCount,
          })}
        </div>
      )}
    </div>
  );
}
