import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useChartColors } from '@/hooks/useChartColors';
import { formatBps, formatBpsShort, tickFormatter, type ChartPoint } from '@/utils/series';
import { ChartTooltip } from './ChartTooltip';

interface ThroughputChartProps {
  data: ChartPoint[];
  /** Window bounds in epoch ms — the axis domain, so an empty period still
   *  renders the period the operator asked for instead of collapsing. */
  fromMs: number;
  toMs: number;
  windowSec: number;
  /** Line speed in bit/s, for the saturation reference line. `null` = unknown,
   *  and then NO reference line is drawn — an invented ceiling is worse than
   *  no ceiling. */
  speedBps: number | null;
  height?: number;
}

const LABELS = {
  inBps: 'interfaces.chart.inbound',
  outBps: 'interfaces.chart.outbound',
};

/**
 * Inbound / outbound throughput.
 *
 * `connectNulls={false}` on both areas is the single most important prop in
 * this file. A router reboot, a failed poll or a three-day server outage
 * arrives as a null row from `toChartPoints()`; with `connectNulls` left at its
 * default the chart would bridge the hole with a straight line and present
 * interpolated traffic as measured traffic.
 *
 * `type="linear"` for the same reason: `monotone` smoothing invents curvature
 * between samples, which on a burst-y WAN link reads as a shape that never
 * happened.
 */
export function ThroughputChart({
  data,
  fromMs,
  toMs,
  windowSec,
  speedBps,
  height = 220,
}: ThroughputChartProps) {
  const { t } = useTranslation();
  const colors = useChartColors();
  // Gradient ids must be unique per instance: two charts on one page sharing
  // an id makes the second one paint with the first one's fill.
  const uid = useId().replace(/:/g, '');
  const inGrad = `in-${uid}`;
  const outGrad = `out-${uid}`;
  const fmtTick = tickFormatter(windowSec);

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 4 }}>
        <defs>
          <linearGradient id={inGrad} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={colors.in} stopOpacity={0.35} />
            <stop offset="100%" stopColor={colors.in} stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id={outGrad} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={colors.out} stopOpacity={0.3} />
            <stop offset="100%" stopColor={colors.out} stopOpacity={0.02} />
          </linearGradient>
        </defs>

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
          tickFormatter={formatBpsShort}
          stroke={colors.axis}
          tick={{ fontSize: 10, fill: colors.axis }}
          tickLine={false}
          axisLine={false}
          width={72}
        />

        <Tooltip
          cursor={{ stroke: colors.axis, strokeDasharray: '3 3' }}
          content={
            <ChartTooltip
              formatValue={(v) => formatBps(v)}
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

        {speedBps !== null && speedBps > 0 && (
          <ReferenceLine
            y={speedBps}
            stroke={colors.reference}
            strokeDasharray="4 4"
            label={{
              value: t('interfaces.chart.lineSpeed', { speed: formatBps(speedBps, 0) }),
              position: 'insideTopRight',
              fill: colors.axis,
              fontSize: 10,
            }}
          />
        )}

        <Area
          type="linear"
          dataKey="inBps"
          stroke={colors.in}
          strokeWidth={1.5}
          fill={`url(#${inGrad})`}
          connectNulls={false}
          dot={false}
          activeDot={{ r: 3 }}
          isAnimationActive={false}
        />
        <Area
          type="linear"
          dataKey="outBps"
          stroke={colors.out}
          strokeWidth={1.5}
          fill={`url(#${outGrad})`}
          connectNulls={false}
          dot={false}
          activeDot={{ r: 3 }}
          isAnimationActive={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
