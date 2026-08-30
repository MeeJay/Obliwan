import { useEffect, useState } from 'react';

/**
 * Chart colours, resolved from the active theme's CSS custom properties.
 *
 * WHY A HOOK AND NOT A CONSTANT. Recharts writes its colours into SVG
 * PRESENTATION ATTRIBUTES (`stroke="…"`, `fill="…"`). Presentation attributes
 * are not CSS declarations, so `var(--c-accent)` inside one does not resolve —
 * it silently produces a black stroke. Hard-coded hex would be the other
 * failure: `obli-daylight` is a LIGHT theme, and a palette picked on the dark
 * default is unreadable on it. So we read the same custom properties Tailwind
 * reads, at runtime, and re-read them whenever `data-theme` changes.
 *
 * The values are space-separated RGB triplets ("245 166 35"), the format the
 * rest of the design system stores them in.
 */

export interface ChartColors {
  /** Inbound traffic. */
  in: string;
  /** Outbound traffic. */
  out: string;
  /** Inbound errors. */
  errIn: string;
  /** Outbound errors / discards. */
  errOut: string;
  grid: string;
  axis: string;
  tooltipBg: string;
  tooltipBorder: string;
  text: string;
  /** The line-speed / threshold reference line. */
  reference: string;
}

const FALLBACK: ChartColors = {
  in: 'rgb(79 123 255)',
  out: 'rgb(245 166 35)',
  errIn: 'rgb(224 58 58)',
  errOut: 'rgb(245 166 35)',
  grid: 'rgb(42 48 72)',
  axis: 'rgb(130 140 175)',
  tooltipBg: 'rgb(19 23 40)',
  tooltipBorder: 'rgb(42 48 72)',
  text: 'rgb(240 244 252)',
  reference: 'rgb(130 140 175)',
};

function readVar(style: CSSStyleDeclaration, name: string, fallback: string): string {
  const raw = style.getPropertyValue(name).trim();
  return raw ? `rgb(${raw})` : fallback;
}

function readColors(): ChartColors {
  if (typeof window === 'undefined') return FALLBACK;
  const style = getComputedStyle(document.documentElement);
  return {
    // Inbound is the "pending" blue and outbound the brand amber: two hues far
    // enough apart to survive deuteranopia, which a green/red pair would not.
    in: readVar(style, '--c-status-pending', FALLBACK.in),
    out: readVar(style, '--c-accent', FALLBACK.out),
    errIn: readVar(style, '--c-status-ssl-expired', FALLBACK.errIn),
    errOut: readVar(style, '--c-status-ssl-warning', FALLBACK.errOut),
    grid: readVar(style, '--c-border', FALLBACK.grid),
    axis: readVar(style, '--c-text-muted', FALLBACK.axis),
    tooltipBg: readVar(style, '--c-bg-secondary', FALLBACK.tooltipBg),
    tooltipBorder: readVar(style, '--c-border-light', FALLBACK.tooltipBorder),
    text: readVar(style, '--c-text-primary', FALLBACK.text),
    reference: readVar(style, '--c-text-muted', FALLBACK.reference),
  };
}

export function useChartColors(): ChartColors {
  const [colors, setColors] = useState<ChartColors>(readColors);

  useEffect(() => {
    const observer = new MutationObserver(() => setColors(readColors()));
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    });
    return () => observer.disconnect();
  }, []);

  return colors;
}
