import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { formatData, type BalanceVerdict, type SimRechargeStatus } from '@obliwan/shared';
import { cn } from '@/utils/cn';

/**
 * ObliWAN F9 — the small pieces every mobile screen shares.
 *
 * ┌─ THE ONE RULE THESE COMPONENTS ENFORCE ───────────────────────────────────┐
 * │ `unknown` IS RENDERED AS ITS OWN THING, never as zero and never folded    │
 * │ into "ok". A line whose balance could not be read is the single most      │
 * │ important state on these screens: it is what a dead partner token, a      │
 * │ renamed API field or a rate limit looks like, and all three present as a  │
 * │ perfectly calm dashboard if `unknown` is drawn in the same grey as        │
 * │ "fine". `formatData(null)` is "—", and `VerdictBadge` gives unknown its   │
 * │ own colour and its own word.                                              │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

// ── Data quantity ───────────────────────────────────────────────────────────

export function DataAmount({
  mb,
  className,
}: {
  mb: number | null | undefined;
  className?: string;
}) {
  // `formatData` renders an absent reading as an em dash. Never `?? 0`.
  return (
    <span
      className={cn(
        'tabular-nums',
        mb === null || mb === undefined ? 'text-text-muted' : 'text-text-primary',
        className,
      )}
    >
      {formatData(mb)}
    </span>
  );
}

// ── Verdict ─────────────────────────────────────────────────────────────────

const VERDICT_CLASS: Record<BalanceVerdict, string> = {
  ok: 'bg-status-up/15 text-status-up border-status-up/30',
  low: 'bg-status-ssl-warning/15 text-status-ssl-warning border-status-ssl-warning/30',
  // Not grey-on-grey: an unreadable line is a problem, and the palette has to
  // say so or nobody investigates a token that died three weeks ago.
  unknown: 'bg-text-muted/10 text-text-secondary border-border',
};

export function VerdictBadge({
  verdict,
  stale,
}: {
  verdict: BalanceVerdict;
  /** `unknown` because the readings aged out rather than never existed. Worth
   *  its own word: one means nobody has polled this line, the other means we
   *  have STOPPED polling it, and only the second is somebody's job today. */
  stale?: boolean;
}) {
  const { t } = useTranslation();
  const label = verdict === 'unknown' && stale ? 'mobile.verdict.stale' : `mobile.verdict.${verdict}`;
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium',
        verdict === 'unknown' && stale
          ? 'bg-status-ssl-warning/15 text-status-ssl-warning border-status-ssl-warning/30'
          : VERDICT_CLASS[verdict],
      )}
    >
      {t(label)}
    </span>
  );
}

// ── Top-up status ───────────────────────────────────────────────────────────

const STATUS_CLASS: Record<SimRechargeStatus, string> = {
  proposed: 'bg-accent/15 text-accent border-accent/30',
  approved: 'bg-status-ssl-warning/15 text-status-ssl-warning border-status-ssl-warning/30',
  // `executed` and `recorded` are both "bought" and are deliberately distinct:
  // the report must always be able to say which ones the machine bought.
  executed: 'bg-status-up/15 text-status-up border-status-up/30',
  recorded: 'bg-status-up/15 text-status-up border-status-up/30',
  rejected: 'bg-text-muted/10 text-text-secondary border-border',
  expired: 'bg-text-muted/10 text-text-secondary border-border',
  failed: 'bg-status-down/15 text-status-down border-status-down/30',
};

export function RechargeStatusBadge({ status }: { status: SimRechargeStatus }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium',
        STATUS_CLASS[status],
      )}
    >
      {t(`mobile.rechargeStatus.${status}`)}
    </span>
  );
}

// ── Money ───────────────────────────────────────────────────────────────────

/**
 * Renders a cost, or says there is none.
 *
 * An unpriced top-up prints "—", not "0,00 €". The partner's invoice often
 * arrives after the top-up, so `null` is the normal state of a fresh row — and
 * a report that shows it as zero under-invoices without saying so.
 */
export function Money({
  cents,
  currency,
}: {
  cents: number | null | undefined;
  currency: string | null | undefined;
}) {
  if (cents === null || cents === undefined) {
    return <span className="text-text-muted">—</span>;
  }
  return (
    <span className="tabular-nums text-text-primary">
      {(cents / 100).toFixed(2)} {currency ?? ''}
    </span>
  );
}

// ── Layout ──────────────────────────────────────────────────────────────────

export function StatCard({
  label,
  value,
  detail,
  tone = 'neutral',
  icon,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  tone?: 'neutral' | 'good' | 'warn' | 'bad';
  icon?: ReactNode;
}) {
  const toneClass = {
    neutral: 'text-text-primary',
    good: 'text-status-up',
    warn: 'text-status-ssl-warning',
    bad: 'text-status-down',
  }[tone];
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="mb-2 flex items-center gap-2">
        {icon ? <span className="text-text-muted">{icon}</span> : null}
        <span className="text-sm text-text-secondary">{label}</span>
      </div>
      <div className={cn('text-2xl font-bold tabular-nums', toneClass)}>{value}</div>
      <div className="mt-1 h-4 text-[11px] text-text-muted">{detail ?? ''}</div>
    </div>
  );
}

export function Panel({
  title,
  action,
  children,
  className,
}: {
  title: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn('rounded-lg border border-border bg-bg-secondary', className)}>
      <header className="flex items-center justify-between border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold text-text-primary">{title}</h2>
        {action}
      </header>
      {children}
    </section>
  );
}

export function EmptyState({ message }: { message: string }) {
  return <div className="px-4 py-10 text-center text-sm text-text-secondary">{message}</div>;
}

/** A short, local date-time. Absent renders as an em dash, like everything else. */
export function When({ iso }: { iso: string | null | undefined }) {
  if (!iso) return <span className="text-text-muted">—</span>;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return <span className="text-text-muted">—</span>;
  return <span className="tabular-nums text-text-secondary">{d.toLocaleString()}</span>;
}
