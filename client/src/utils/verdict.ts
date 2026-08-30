import type { ReachabilityVerdict, DeviceStatus, TransportKind } from '@obliwan/shared';
import type { ConnState } from '@/types/fleet';

/**
 * Visual vocabulary for K7 verdicts.
 *
 * The one rule this file exists to enforce: `UNREACHABLE` and `SITE_DOWN` must
 * never be rendered the same way. `SITE_DOWN` is positive knowledge of an
 * outage — filled, red, alertable. `UNREACHABLE` is "we cannot tell" — a
 * HOLLOW ring in muted grey. The difference is a shape difference, not only a
 * colour one, so it survives a colour-blind operator and a bad monitor.
 */
export interface VerdictStyle {
  /** Tailwind classes for the presence pastille. */
  dot: string;
  /** Text colour for the label. */
  text: string;
  /** Pill background + border. */
  pill: string;
}

const VERDICT_STYLES: Record<ReachabilityVerdict, VerdictStyle> = {
  UP: {
    dot: 'bg-status-up',
    text: 'text-status-up',
    pill: 'bg-status-up/10 border-status-up/30 text-status-up',
  },
  TUNNEL_DOWN_SITE_UP: {
    dot: 'bg-status-ssl-warning',
    text: 'text-status-ssl-warning',
    pill: 'bg-status-ssl-warning/10 border-status-ssl-warning/30 text-status-ssl-warning',
  },
  SITE_DOWN: {
    dot: 'bg-status-down',
    text: 'text-status-down',
    pill: 'bg-status-down/10 border-status-down/40 text-status-down',
  },
  WAN_FAILOVER: {
    dot: 'bg-status-maintenance',
    text: 'text-status-maintenance',
    pill: 'bg-status-maintenance/10 border-status-maintenance/30 text-status-maintenance',
  },
  CONCENTRATOR_DEGRADED: {
    dot: 'bg-status-ssl-expired',
    text: 'text-status-ssl-expired',
    pill: 'bg-status-ssl-expired/10 border-status-ssl-expired/30 text-status-ssl-expired',
  },
  // Hollow on purpose — see the doc comment above.
  UNREACHABLE: {
    dot: 'bg-transparent border-2 border-text-muted',
    text: 'text-text-muted',
    pill: 'bg-transparent border-dashed border-text-muted/50 text-text-muted',
  },
};

export function verdictStyle(verdict: ReachabilityVerdict | null | undefined): VerdictStyle {
  if (!verdict) return VERDICT_STYLES.UNREACHABLE;
  return VERDICT_STYLES[verdict] ?? VERDICT_STYLES.UNREACHABLE;
}

/** i18n key for a verdict label. */
export function verdictLabelKey(verdict: ReachabilityVerdict): string {
  return `fleet.verdict.${verdict}`;
}

/** i18n key for the one-line explanation shown in tooltips and detail panels. */
export function verdictHintKey(verdict: ReachabilityVerdict): string {
  return `fleet.verdictHint.${verdict}`;
}

// ── Device lifecycle status ─────────────────────────────────────────────────

export function deviceStatusStyle(status: DeviceStatus): string {
  switch (status) {
    case 'active':
      return 'bg-status-up/10 border-status-up/30 text-status-up';
    case 'pending':
      return 'bg-status-pending/10 border-status-pending/30 text-status-pending';
    case 'quarantined':
      return 'bg-status-ssl-warning/10 border-status-ssl-warning/30 text-status-ssl-warning';
    case 'disabled':
      return 'bg-bg-tertiary border-border text-text-muted';
    default:
      return 'bg-bg-tertiary border-border text-text-muted';
  }
}

// ── Transport health ────────────────────────────────────────────────────────

export function connStateStyle(state: ConnState): string {
  switch (state) {
    case 'ok':
      return 'bg-status-up/10 border-status-up/30 text-status-up';
    case 'degraded':
      return 'bg-status-ssl-warning/10 border-status-ssl-warning/30 text-status-ssl-warning';
    case 'down':
      return 'bg-status-down/10 border-status-down/40 text-status-down';
    default:
      return 'bg-transparent border-dashed border-text-muted/50 text-text-muted';
  }
}

/** Default port shown as a placeholder when an operator adds a channel. */
export const TRANSPORT_DEFAULT_PORT: Record<TransportKind, number | null> = {
  routeros_api: 8728,
  ssh: 22,
  rest: 443,
  // The CPE dials us; there is nothing to dial back.
  cwmp: null,
  snmp: 161,
};
