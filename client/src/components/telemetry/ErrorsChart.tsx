import { useTranslation } from 'react-i18next';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useChartColors } from '@/hooks/useChartColors';
import { formatCount, tickFormatter, type ChartPoint } from '@/utils/series';
import { ChartTooltip } from './ChartTooltip';

interface ErrorsChartProps {
  data: ChartPoint[];
  fromMs: number;
  toMs: number;
  windowSec: number;
  height?: number;
}

const LABELS = {
  inErrs: 'interfaces.chart.inErrors',
  outErrs: 'interfaces.chart.outErrors',
  inDiscards: 'interfaces.chart.inDiscards',
  outDiscards: 'interfaces.chart.outDiscards',
};

/**
 * Errors and discards, as a DELTA over each bucket — never the raw counter.
 *
 * Lines rather than bars, and that is a correctness choice, not a taste one: a
 * missing bar and a zero-height bar are the same pixel. On a chart whose entire
 * job is to distinguish "no errors" from "no measurement", bars would erase the
 * distinction the rest of this feature works to preserve. A line with
 * `connectNulls={false}` breaks visibly at a hole and sits flat on the floor at
 * a real zero.
 */
export function ErrorsChart({ data, fromMs, toMs, windowSec, height = 180 }: ErrorsChartProps) {
  const { t } = useTranslation();
  const colors = useChartColors();
  const fmtTick = tickFormatter(windowSec);

  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 4 }}>
        <CartesianGrid stroke={colors.grid} strokeDasharray="3 3" vertical={false} />
        <XAxis
          dataKey="t"
          type="number"
          scale="time"
          domain={[fromMs, toMs]}
          allowDataOverflow
          tickFormatter={fmtTick}
          stroke={colors.axis}
          tick={{ fontSize: 10, fill: colors.axis }}
          tickLine={false}
          minTickGap={48}
        />
        <YAxis
          allowDecimals={false}
          stroke={colors.axis}
          tick={{ fontSize: 10, fill: colors.axis }}
          tickLine={false}
          axisLine={false}
          width={48}
        />
        <Tooltip
          cursor={{ stroke: colors.axis, strokeDasharray: '3 3' }}
          content={
            <ChartTooltip
              formatValue={(v) => formatCount(v)}
              labels={LABELS}
              formatTime={(v) => new Date(v).toLocaleString()}
            />
          }
        />
        <Legend
          verticalAlign="top"
          height={24}
          iconType="plainline"
          iconSize={12}
          formatter={(value) => (
            <span style={{ color: colors.axis, fontSize: 11 }}>
              {t(LABELS[value as keyof typeof LABELS] ?? value)}
            </span>
          )}
        />

        <Line
          type="linear"
          dataKey="inErrs"
          stroke={colors.errIn}
          strokeWidth={1.5}
          dot={false}
          activeDot={{ r: 3 }}
          connectNulls={false}
          isAnimationActive={false}
        />
        <Line
          type="linear"
          dataKey="outErrs"
          stroke={colors.errOut}
          strokeWidth={1.5}
          dot={false}
          activeDot={{ r: 3 }}
          connectNulls={false}
          isAnimationActive={false}
        />
        {/* Discards are dashed: they are a capacity symptom, not a media fault,
            and conflating the two sends an operator to change a cable when the
            queue is simply full. */}
        <Line
          type="linear"
          dataKey="inDiscards"
          stroke={colors.errIn}
          strokeWidth={1}
          strokeDasharray="4 3"
          dot={false}
          activeDot={{ r: 3 }}
          connectNulls={false}
          isAnimationActive={false}
        />
        <Line
          type="linear"
          dataKey="outDiscards"
          stroke={colors.errOut}
          strokeWidth={1}
          strokeDasharray="4 3"
          dot={false}
          activeDot={{ r: 3 }}
          connectNulls={false}
          isAnimationActive={false}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
