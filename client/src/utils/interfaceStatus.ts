import { IF_OPER_STATUS, ifOperStatusName, type IfOperStatusCode } from '@obliwan/shared';

/**
 * Visual vocabulary for IF-MIB interface state (M3).
 *
 * The rule this file exists to enforce, and it is the interface-level twin of
 * the `UNREACHABLE` / `SITE_DOWN` rule in `verdict.ts`:
 *
 *   ifOperStatus = down (2) on a port whose ifAdminStatus is ALSO down (2) is
 *   NOT AN INCIDENT. It is a port somebody switched off on purpose. Painting it
 *   the same red as a link that dropped on its own is how an operator learns to
 *   ignore red.
 *
 * `unknown` (4) and `notPresent` (6) are absence of knowledge, not failure, and
 * are rendered hollow/muted — never red.
 */

export function operStatusStyle(code: IfOperStatusCode | number | null | undefined): string {
  switch (code) {
    case IF_OPER_STATUS.up:
      return 'bg-status-up/10 border-status-up/30 text-status-up';
    case IF_OPER_STATUS.down:
      return 'bg-status-ssl-expired/10 border-status-ssl-expired/40 text-status-ssl-expired';
    case IF_OPER_STATUS.lowerLayerDown:
    case IF_OPER_STATUS.testing:
      return 'bg-status-ssl-warning/10 border-status-ssl-warning/30 text-status-ssl-warning';
    case IF_OPER_STATUS.dormant:
      return 'bg-status-pending/10 border-status-pending/30 text-status-pending';
    default:
      // unknown, notPresent, and anything the agent invents.
      return 'bg-transparent border-dashed border-text-muted/50 text-text-muted';
  }
}

/** Dot colour for the compact table cell. `unknown` is a hollow ring. */
export function operStatusDot(code: IfOperStatusCode | number | null | undefined): string {
  switch (code) {
    case IF_OPER_STATUS.up:
      return 'bg-status-up';
    case IF_OPER_STATUS.down:
      return 'bg-status-ssl-expired';
    case IF_OPER_STATUS.lowerLayerDown:
    case IF_OPER_STATUS.testing:
      return 'bg-status-ssl-warning';
    case IF_OPER_STATUS.dormant:
      return 'bg-status-pending';
    default:
      return 'bg-transparent border-2 border-text-muted';
  }
}

/** i18n key for an ifOperStatus code. */
export function operStatusLabelKey(code: IfOperStatusCode | number | null | undefined): string {
  if (code === null || code === undefined) return 'fleet.ifOper.unknown';
  return `fleet.ifOper.${ifOperStatusName(code)}`;
}

/** ifAdminStatus: 1 up, 2 down, 3 testing. */
export function adminStatusLabelKey(code: number | null | undefined): string {
  if (code === 2) return 'fleet.ifAdmin.down';
  if (code === 3) return 'fleet.ifAdmin.testing';
  if (code === 1) return 'fleet.ifAdmin.up';
  return 'fleet.ifAdmin.unknown';
}

/** True when the port is administratively disabled — see the note at the top. */
export function isAdminDown(adminStatus: number | null | undefined): boolean {
  return adminStatus === 2;
}

/**
 * Colour band for a utilisation percentage.
 *
 * `null` (unknown line speed) has NO band. It is not green, and it is not red:
 * we do not know, and the bar renders as a hatched "unknown" instead of a
 * reassuring empty gauge.
 */
export function utilBand(pct: number | null): 'unknown' | 'low' | 'medium' | 'high' | 'critical' {
  if (pct === null || !Number.isFinite(pct)) return 'unknown';
  if (pct >= 90) return 'critical';
  if (pct >= 70) return 'high';
  if (pct >= 40) return 'medium';
  return 'low';
}

export const UTIL_BAND_FILL: Record<ReturnType<typeof utilBand>, string> = {
  unknown: 'bg-text-muted/25',
  low: 'bg-status-up',
  medium: 'bg-status-pending',
  high: 'bg-status-ssl-warning',
  critical: 'bg-status-ssl-expired',
};

export const UTIL_BAND_TEXT: Record<ReturnType<typeof utilBand>, string> = {
  unknown: 'text-text-muted',
  low: 'text-status-up',
  medium: 'text-status-pending',
  high: 'text-status-ssl-warning',
  critical: 'text-status-ssl-expired',
};
