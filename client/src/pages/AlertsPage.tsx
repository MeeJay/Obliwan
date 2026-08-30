import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  ArrowDownCircle,
  ArrowUpCircle,
  BellRing,
  CheckCheck,
  Info,
  RotateCw,
  Search,
  Trash2,
  AlertTriangle,
  X,
} from 'lucide-react';
import { useLiveAlertsStore, countUnread } from '@/store/liveAlertsStore';
import type { AlertSeverity, LiveAlert } from '@/store/liveAlertsStore';
import { useTenantStore } from '@/store/tenantStore';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';

/**
 * `AlertsPage` — the alert history behind the bell (spec §4.1, `/alerts`).
 *
 * ┌─ WHY THIS SCREEN EXISTS SEPARATELY FROM THE TOASTS ──────────────────────┐
 * │ A toast is a thing you MISSED. It lives 60 seconds and disappears; if an │
 * │ operator was in a meeting when a site went down, the only trace is a     │
 * │ counter on a bell. The bell dropdown answers "what is unread"; this page │
 * │ answers "what happened", which is the question asked after the incident, │
 * │ by somebody writing it up.                                               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── CROSS-TENANT BY DESIGN, AND LABELLED ────────────────────────────────────
 * `/api/live-alerts/all` returns alerts for every tenant the session can see —
 * that is an MSP's actual working set, and the whole reason the store fetches
 * that route rather than the tenant-scoped one. The tenant column is therefore
 * never hidden: an alert read without knowing WHICH customer it belongs to is
 * an alert that gets actioned on the wrong network.
 *
 * ── NO SEVERITY IS INVENTED ─────────────────────────────────────────────────
 * The four severities come from the server (`LiveAlertData`). This page groups
 * and colours them; it does not derive, upgrade or downgrade any of them.
 */

const SEVERITY_TONE: Record<AlertSeverity, string> = {
  down: 'text-status-ssl-expired border-status-ssl-expired/60 bg-status-ssl-expired/15',
  up: 'text-status-up border-status-up/50 bg-status-up/10',
  warning: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  info: 'text-text-secondary border-border bg-bg-tertiary',
};

const SEVERITY_ICON: Record<AlertSeverity, React.ReactNode> = {
  down: <ArrowDownCircle size={11} />,
  up: <ArrowUpCircle size={11} />,
  warning: <AlertTriangle size={11} />,
  info: <Info size={11} />,
};

const SEVERITIES: AlertSeverity[] = ['down', 'warning', 'up', 'info'];

export function AlertsPage() {
  const { t, i18n } = useTranslation();
  const alerts = useLiveAlertsStore((s) => s.alerts);
  const fetchAlerts = useLiveAlertsStore((s) => s.fetchAlerts);
  const markAlertRead = useLiveAlertsStore((s) => s.markAlertRead);
  const markAllRead = useLiveAlertsStore((s) => s.markAllRead);
  const removeAlert = useLiveAlertsStore((s) => s.removeAlert);
  const currentTenantId = useTenantStore((s) => s.currentTenantId);

  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState<AlertSeverity | ''>('');
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [thisTenantOnly, setThisTenantOnly] = useState(false);

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'medium' }),
    [i18n.language],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    try { await fetchAlerts(); } finally { setLoading(false); }
  }, [fetchAlerts]);

  useEffect(() => { void refresh(); }, [refresh]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return alerts
      .filter((a) => {
        if (severity && a.severity !== severity) return false;
        if (unreadOnly && a.read) return false;
        if (thisTenantOnly && currentTenantId !== null && a.tenantId !== currentTenantId) return false;
        if (!needle) return true;
        return [a.title, a.message, a.tenantName]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(needle));
      })
      .slice()
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }, [alerts, search, severity, unreadOnly, thisTenantOnly, currentTenantId]);

  const unread = countUnread(alerts);

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold text-text-primary">{t('nav.alerts')}</h1>
          <p className="mt-1 text-sm text-text-muted">{t('alerts.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" disabled={unread === 0} onClick={() => void markAllRead()}>
            <CheckCheck size={14} className="mr-1.5" />
            {t('alerts.markAllRead')}
          </Button>
          <Button variant="secondary" size="sm" onClick={() => void refresh()}>
            <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
        </div>
      </div>

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
        <Tile label={t('alerts.total')} value={String(alerts.length)} tone="muted" />
        <Tile label={t('alerts.unread')} value={String(unread)} tone={unread > 0 ? 'warn' : 'ok'} />
        {SEVERITIES.slice(0, 3).map((s) => (
          <Tile
            key={s}
            label={t(`alerts.severity.${s}`)}
            value={String(alerts.filter((a) => a.severity === s).length)}
            tone={s === 'down' ? 'bad' : s === 'warning' ? 'warn' : 'ok'}
          />
        ))}
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('alerts.searchPlaceholder')}
            className="w-64 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value as AlertSeverity | '')}
          className="rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
        >
          <option value="">{t('alerts.allSeverities')}</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{t(`alerts.severity.${s}`)}</option>
          ))}
        </select>
        <label className="flex items-center gap-1.5 text-[12px] text-text-secondary">
          <input type="checkbox" checked={unreadOnly} onChange={(e) => setUnreadOnly(e.target.checked)} className="accent-accent" />
          {t('alerts.unreadOnly')}
        </label>
        <label className="flex items-center gap-1.5 text-[12px] text-text-secondary">
          <input type="checkbox" checked={thisTenantOnly} onChange={(e) => setThisTenantOnly(e.target.checked)} className="accent-accent" />
          {t('alerts.thisTenantOnly')}
        </label>
        {(search || severity || unreadOnly || thisTenantOnly) && (
          <button
            onClick={() => { setSearch(''); setSeverity(''); setUnreadOnly(false); setThisTenantOnly(false); }}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            <X size={12} /> {t('devices.filters.clear')}
          </button>
        )}
        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('devices.showing', { shown: filtered.length, total: alerts.length })}
        </span>
      </div>

      {filtered.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <BellRing size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('alerts.empty')}</p>
          <p className="mt-1 text-xs text-text-muted">{t('alerts.emptyHint')}</p>
        </div>
      ) : (
        <ul className="space-y-2">
          {filtered.map((alert) => (
            <AlertRow
              key={alert.id}
              alert={alert}
              dateFmt={dateFmt}
              onRead={() => void markAlertRead(alert.id)}
              onRemove={() => void removeAlert(alert.id)}
            />
          ))}
        </ul>
      )}
    </div>
  );
}

function AlertRow({
  alert,
  dateFmt,
  onRead,
  onRemove,
}: {
  alert: LiveAlert;
  dateFmt: Intl.DateTimeFormat;
  onRead: () => void;
  onRemove: () => void;
}) {
  const { t } = useTranslation();
  const created = new Date(alert.createdAt);

  return (
    <li
      className={cn(
        'flex items-start gap-3 rounded-lg border bg-bg-secondary px-3 py-2.5',
        alert.read ? 'border-border' : 'border-accent/40',
      )}
    >
      <span
        className={cn(
          'mt-0.5 inline-flex shrink-0 items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
          SEVERITY_TONE[alert.severity],
        )}
      >
        {SEVERITY_ICON[alert.severity]}
        {t(`alerts.severity.${alert.severity}`)}
      </span>

      <div className="min-w-0 flex-1">
        <p className="flex flex-wrap items-center gap-2 text-[13px] font-medium text-text-primary">
          {alert.title}
          {!alert.read && (
            <span className="rounded bg-accent/15 px-1.5 py-px text-[9px] uppercase tracking-wider text-accent">
              {t('alerts.new')}
            </span>
          )}
        </p>
        <p className="mt-0.5 whitespace-pre-wrap break-words text-[12px] text-text-secondary">
          {alert.message}
        </p>
        <p className="mt-1 flex flex-wrap items-center gap-2 font-mono text-[11px] text-text-muted">
          <span>{Number.isNaN(created.getTime()) ? '—' : dateFmt.format(created)}</span>
          {/* Never hidden: an MSP reads these across customers. */}
          <span className="rounded border border-border px-1 py-px">
            {alert.tenantName ?? `#${alert.tenantId}`}
          </span>
          {alert.navigateTo && (
            <Link to={alert.navigateTo} className="text-accent hover:underline">
              {t('alerts.open')}
            </Link>
          )}
        </p>
      </div>

      <div className="flex shrink-0 items-center gap-1">
        {!alert.read && (
          <button
            onClick={onRead}
            title={t('alerts.markRead')}
            className="rounded p-1.5 text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            <CheckCheck size={13} />
          </button>
        )}
        <button
          onClick={onRemove}
          title={t('alerts.delete')}
          className="rounded p-1.5 text-text-muted hover:bg-bg-hover hover:text-status-ssl-expired"
        >
          <Trash2 size={13} />
        </button>
      </div>
    </li>
  );
}

const TONES = {
  ok: 'text-status-up',
  warn: 'text-status-ssl-warning',
  bad: 'text-status-ssl-expired',
  muted: 'text-text-primary',
};

function Tile({ label, value, tone }: { label: string; value: string; tone: keyof typeof TONES }) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-3">
      <div className="text-[11px] uppercase tracking-wider text-text-muted">{label}</div>
      <div className={cn('mt-1 font-display text-xl font-semibold tabular-nums', TONES[tone])}>
        {value}
      </div>
    </div>
  );
}
