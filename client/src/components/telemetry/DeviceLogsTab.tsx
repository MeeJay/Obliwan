import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { RotateCw, ScrollText, AlertTriangle } from 'lucide-react';
import { logsApi } from '@/api/logs.api';
import type { LogEntryView, LogSeverity } from '@/types/logs';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { cn } from '@/utils/cn';

/**
 * This device's syslog, traps and RouterOS log, newest first.
 *
 * The tab was greyed out behind an "M8" padlock long after M8 shipped and
 * `GET /logs?deviceId=` started answering. The marker outlived the condition it
 * described, and a padlock is worse than an empty pane: it tells an operator
 * the feature does not exist, so they stop looking for it.
 *
 * ┌─ TWO CLOCKS, BOTH SHOWN ─────────────────────────────────────────────────┐
 * │ `timestamp` is what the equipment said. `receivedAt` is when our ingest   │
 * │ saw the line. They are kept apart because a router with no NTP has a      │
 * │ fantasy clock, and a log page that silently picks one of the two can put  │
 * │ an event days from where it happened. When they disagree meaningfully,    │
 * │ both are shown rather than the page choosing a winner.                    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `sourceIp` is deliberately allowed to be null and is never invented: behind
 * the Docker bridge a trap's source address is NATed to the gateway (A6), and a
 * wrong address on a security-relevant line is worse than no address.
 */

const SEVERITY_STYLE: Record<string, string> = {
  emerg: 'border-status-down/40 bg-status-down/10 text-status-down',
  alert: 'border-status-down/40 bg-status-down/10 text-status-down',
  crit: 'border-status-down/40 bg-status-down/10 text-status-down',
  err: 'border-status-down/40 bg-status-down/10 text-status-down',
  warning: 'border-status-warn/40 bg-status-warn/10 text-status-warn',
  notice: 'border-border text-text-secondary',
  info: 'border-border text-text-secondary',
  debug: 'border-border text-text-muted',
};

const SEVERITIES: LogSeverity[] = [
  'emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug',
];

/** More than a minute apart is a real disagreement, not clock jitter. */
function clocksDisagree(a: string, b: string | null): boolean {
  if (!b) return false;
  return Math.abs(new Date(a).getTime() - new Date(b).getTime()) > 60_000;
}

export function DeviceLogsTab({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation();
  const [rows, setRows] = useState<LogEntryView[] | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [severity, setSeverity] = useState<LogSeverity | ''>('');
  const [q, setQ] = useState('');
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const res = await logsApi.list({
        deviceId,
        severity: severity || undefined,
        q: q || undefined,
        limit: 300,
      });
      // `null` is the API telling us this build does not serve logs — which is
      // a different statement from "this device has produced none".
      if (res === null) { setUnavailable(true); setRows([]); }
      else { setUnavailable(false); setRows(res); }
    } catch {
      setRows([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, [deviceId, severity]);

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <select
          className="rounded-md border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary"
          value={severity}
          onChange={(e) => setSeverity(e.target.value as LogSeverity | '')}
        >
          <option value="">{t('logs.allSeverities', { defaultValue: 'All severities' })}</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{t(`logs.severity.${s}`, { defaultValue: s })}</option>
          ))}
        </select>
        <input
          className="min-w-[14rem] flex-1 rounded-md border border-border bg-bg-secondary px-2 py-1.5 text-sm text-text-primary"
          placeholder={t('logs.searchPlaceholder', { defaultValue: 'Search in messages…' })}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') void load(); }}
        />
        <Button size="sm" variant="secondary" onClick={() => void load()}>
          <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
          {t('common.refresh', { defaultValue: 'Refresh' })}
        </Button>
      </div>

      {unavailable && (
        <p className="mb-3 flex items-center gap-2 text-xs text-text-muted">
          <AlertTriangle size={13} />
          {t('logs.unavailable', {
            defaultValue: 'This build does not serve the log API.',
          })}
        </p>
      )}

      {loading ? <LoadingSpinner /> : !rows || rows.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary px-6 py-12 text-center">
          <ScrollText size={22} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-secondary">
            {t('logs.deviceEmpty', { defaultValue: 'No log line recorded for this device yet.' })}
          </p>
          <p className="mx-auto mt-2 max-w-xl text-xs text-text-muted">
            {t('logs.deviceEmptyHint', {
              defaultValue:
                'Lines arrive when the equipment is configured to send its syslog and traps here. '
                + 'A device matched only by its system identity is matched without a tenant '
                + 'predicate — a UDP datagram carries none — so the name must be unique.',
            })}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full text-sm">
            <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">{t('logs.when', { defaultValue: 'When' })}</th>
                <th className="px-3 py-2 font-medium">{t('logs.severityLabel', { defaultValue: 'Severity' })}</th>
                <th className="px-3 py-2 font-medium">{t('logs.source', { defaultValue: 'Source' })}</th>
                <th className="px-3 py-2 font-medium">{t('logs.message', { defaultValue: 'Message' })}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map((l) => (
                <tr key={l.id}>
                  <td className="whitespace-nowrap px-3 py-2 align-top font-mono text-xs text-text-muted">
                    {new Date(l.timestamp).toLocaleString()}
                    {/* The device's clock and ours disagree — say so rather
                        than quietly placing the event on one of the two. */}
                    {clocksDisagree(l.timestamp, l.receivedAt) && (
                      <span
                        className="block text-[10px] text-status-warn"
                        title={t('logs.clockSkewHint', {
                          defaultValue: 'The equipment clock differs from ours; both are shown.',
                        })}
                      >
                        {t('logs.received', { defaultValue: 'received' })}{' '}
                        {new Date(l.receivedAt!).toLocaleString()}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <span className={cn(
                      'inline-flex rounded-full border px-2 py-0.5 text-[10px] font-medium',
                      SEVERITY_STYLE[l.severity] ?? 'border-border text-text-muted',
                    )}>
                      {t(`logs.severity.${l.severity}`, { defaultValue: l.severity })}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 align-top text-xs text-text-secondary">
                    {t(`logs.sourceKind.${l.source}`, { defaultValue: l.source })}
                    {l.facility && (
                      <span className="ml-1.5 font-mono text-[10px] text-text-muted">{l.facility}</span>
                    )}
                    {l.sourceIp && (
                      <span className="block font-mono text-[10px] text-text-muted">{l.sourceIp}</span>
                    )}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <span className="whitespace-pre-wrap break-words font-mono text-xs text-text-primary">
                      {l.message}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
