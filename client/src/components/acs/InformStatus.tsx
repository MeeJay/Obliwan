import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Clock, Radio, Send, Zap } from 'lucide-react';
import { Button } from '@/components/common/Button';
import { formatDuration } from '@/utils/series';
import { cn } from '@/utils/cn';
import type { CwmpCpe, CwmpReachability } from '@/types/acs';
import { nextInformExpectedAt } from '@/types/acs';

/**
 * "When will this CPE actually hear us?" — the honesty core of M10.
 *
 * ┌─ THE BUTTON THAT DOES NOT EXIST ─────────────────────────────────────────┐
 * │ There is NO "Refresh now" on this component, and there never will be.    │
 * │ CWMP is CPE-initiated: the ACS may not speak until the CPE opens a       │
 * │ session. The only lever the standard gives an ACS is a Connection        │
 * │ Request — an HTTP poke at an address the CPE published, which behind a   │
 * │ carrier NAT, a CGNAT pool or a firewalled WAN simply does not arrive.    │
 * │                                                                          │
 * │ A button labelled "Refresh now" that enqueues a task and spins is a lie  │
 * │ with a progress indicator on it: the operator waits, sees nothing        │
 * │ change, and concludes the product is broken. What he needs instead is    │
 * │ the SENTENCE: "queued — the CPE is due to call in in 21 minutes."        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The three states this component distinguishes, and never merges:
 *
 *  1. NO CONNECTION REQUEST ON FILE — the only path is the periodic Inform.
 *     The countdown is the whole answer, and the action reads "queue it".
 *  2. CONNECTION REQUEST ON FILE, NEVER TRIED — a poke may be attempted, and
 *     the label says "attempt", not "refresh". The expected fallback delay is
 *     printed next to it, BEFORE the click, so nobody discovers it afterwards.
 *  3. CONNECTION REQUEST TRIED AND FAILED — the poke is still offered (a NAT
 *     mapping can come back) but the last failure is stated, so a second click
 *     is an informed one.
 *
 * A CPE that has NEVER informed has no interval and no last contact: the
 * countdown is impossible and the component says so instead of inventing one.
 */

const REACHABILITY_STYLES: Record<CwmpReachability, string> = {
  online: 'border-status-up/50 bg-status-up/10 text-status-up',
  idle: 'border-border bg-bg-tertiary text-text-secondary',
  overdue: 'border-status-ssl-warning/50 bg-status-ssl-warning/10 text-status-ssl-warning',
  never_informed: 'border-status-pending/50 bg-status-pending/10 text-status-pending',
  unknown: 'border-border bg-bg-tertiary text-text-muted',
};

export function ReachabilityChip({ value }: { value: CwmpReachability }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
        REACHABILITY_STYLES[value],
      )}
      title={t(`acs.reachabilityHint.${value}`)}
    >
      <Radio size={10} />
      {t(`acs.reachability.${value}`)}
    </span>
  );
}

/** Live "in 21 m 4 s" / "overdue by 3 m". Ticks locally; no polling. */
function useCountdown(target: Date | null): number | null {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!target) return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [target]);
  if (!target) return null;
  return Math.round((target.getTime() - now) / 1000);
}

export function InformStatus({
  cpe,
  onQueue,
  onConnectionRequest,
  busy = false,
  queueLabel,
  className,
}: {
  cpe: CwmpCpe;
  /** Enqueue whatever the caller is composing. May be omitted on read-only
   *  views — the countdown is useful on its own. */
  onQueue?: () => void;
  onConnectionRequest?: () => void;
  busy?: boolean;
  /** What is being queued, so the button never says the generic "run". */
  queueLabel?: string;
  className?: string;
}) {
  const { t, i18n } = useTranslation();
  const next = useMemo(() => nextInformExpectedAt(cpe), [cpe]);
  const secondsLeft = useCountdown(next);

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'medium' }),
    [i18n.language],
  );

  const lastInform = cpe.lastInformAt ? new Date(cpe.lastInformAt) : null;
  const lastInformValid = lastInform !== null && !Number.isNaN(lastInform.getTime());

  // The one sentence the whole component exists to produce.
  const waitSentence = (() => {
    if (!lastInformValid) return t('acs.inform.neverInformed');
    if (secondsLeft === null) return t('acs.inform.noInterval');
    if (secondsLeft <= 0) return t('acs.inform.overdueBy', { delay: formatDuration(-secondsLeft) });
    return t('acs.inform.expectedIn', { delay: formatDuration(secondsLeft) });
  })();

  return (
    <section className={cn('rounded-lg border border-border bg-bg-secondary p-3', className)}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold text-text-primary">
          <Clock size={14} className="text-text-muted" />
          {t('acs.inform.title')}
        </h3>
        <ReachabilityChip value={cpe.reachability} />
      </div>

      <dl className="mt-2 grid gap-x-6 gap-y-1 text-[12px] sm:grid-cols-2">
        <div className="flex justify-between gap-2">
          <dt className="text-text-muted">{t('acs.inform.last')}</dt>
          <dd className="font-mono text-text-secondary">
            {lastInformValid ? dateFmt.format(lastInform) : t('acs.inform.never')}
          </dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-text-muted">{t('acs.inform.event')}</dt>
          <dd className="font-mono text-text-secondary">{cpe.lastInformEvent ?? '—'}</dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-text-muted">{t('acs.inform.interval')}</dt>
          <dd className="font-mono text-text-secondary">
            {cpe.periodicInformInterval ? formatDuration(cpe.periodicInformInterval) : '—'}
          </dd>
        </div>
        <div className="flex justify-between gap-2">
          <dt className="text-text-muted">{t('acs.inform.next')}</dt>
          <dd className="font-mono text-text-secondary">
            {next ? dateFmt.format(next) : t('acs.inform.unknown')}
          </dd>
        </div>
      </dl>

      {/* The sentence, given its own line and its own weight. */}
      <p
        className={cn(
          'mt-2 rounded-md border px-2.5 py-1.5 text-[12px]',
          secondsLeft !== null && secondsLeft <= 0
            ? 'border-status-ssl-warning/40 bg-status-ssl-warning/5 text-status-ssl-warning'
            : 'border-border bg-bg-tertiary text-text-secondary',
        )}
      >
        {waitSentence}
      </p>

      {/* ── Actions. Every label states what actually happens. ── */}
      {(onQueue || onConnectionRequest) && (
        <div className="mt-2.5 space-y-2">
          {onQueue && (
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="primary" size="sm" loading={busy} onClick={onQueue}>
                <Send size={14} className="mr-1.5" />
                {queueLabel ?? t('acs.inform.queue')}
              </Button>
              <span className="text-[11px] text-text-muted">{t('acs.inform.queueHint')}</span>
            </div>
          )}

          {onConnectionRequest && (
            cpe.hasConnectionRequest ? (
              <div className="flex flex-wrap items-center gap-2">
                <Button variant="secondary" size="sm" disabled={busy} onClick={onConnectionRequest}>
                  <Zap size={14} className="mr-1.5" />
                  {t('acs.inform.attemptCr')}
                </Button>
                <span className="text-[11px] text-text-muted">
                  {cpe.connectionRequestOk === false
                    ? t('acs.inform.crLastFailed', {
                        when: cpe.lastConnectionRequestAt
                          ? dateFmt.format(new Date(cpe.lastConnectionRequestAt))
                          : '—',
                      })
                    : cpe.connectionRequestOk === true
                      ? t('acs.inform.crLastOk')
                      : t('acs.inform.crNeverTried')}
                </span>
              </div>
            ) : (
              <p className="flex items-start gap-1.5 text-[11px] text-text-muted">
                <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                {t('acs.inform.noCr')}
              </p>
            )
          )}
        </div>
      )}
    </section>
  );
}
