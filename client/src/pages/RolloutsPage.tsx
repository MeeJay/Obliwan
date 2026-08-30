import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Plus, Rocket, RotateCw, Search, Unplug, X } from 'lucide-react';
import { rolloutApi, ROLLOUT_CONFIG_FAIL_CLOSED } from '@/api/rollout.api';
import type { RolloutConfig } from '@/api/rollout.api';
import { errorMessageOf } from '@/api/change.api';
import { useChangeStore } from '@/store/changeStore';
import { useSocketStore } from '@/store/socketStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { KillSwitchBanner, KillSwitchButton } from '@/components/change/KillSwitch';
import { RolloutStatusBadge } from '@/components/rollout/RolloutBadges';
import { NewRolloutPanel } from '@/components/rollout/NewRolloutPanel';
import { useRolloutSocket } from '@/hooks/useRolloutSocket';
import { cn } from '@/utils/cn';
import type { RolloutStatus, RolloutView } from '@/types/rollout';
import { ACTIVE_ROLLOUT_STATUSES, ROLLOUT_STATUSES } from '@/types/rollout';

/**
 * `RolloutsPage` — the fleet-wide wave-rollout queue (M7, killer K3).
 *
 * ── THE KILL SWITCH IS HERE TOO, AND FOR THE SAME REASON ────────────────────
 * `ChangesPage` puts it in the header because that is the screen an operator is
 * looking at when a change goes wrong. A rollout is N changes; if anything, the
 * button matters MORE here. It is the first control, it is red, it never
 * scrolls away.
 *
 * ── A ROLLOUT THAT HALTED IS NOT A ROLLOUT THAT FAILED ──────────────────────
 * `halted` has its own counter and its own colour. A health gate refusing wave
 * 2 is K3 working exactly as designed — it is the mechanism that stopped the
 * other 280 boxes from getting the same bad change. Filing it under "failed"
 * would teach operators to widen the gates, which is the one lesson this
 * milestone must not teach. Same argument as `rolled_back` on `ChangesPage`.
 *
 * ── WHAT THIS SCREEN DOES WITHOUT AN M7 SERVER ──────────────────────────────
 * The list degrades to a stated "endpoint unavailable". The IMPACT RADIUS does
 * not: it is computed from `/plan/devices/:id` and `/changes/preview`, both
 * mounted today, so the screen that decides whether to press the button works
 * even while the button itself is inert.
 */

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

const ACTIVE: ReadonlySet<string> = new Set(ACTIVE_ROLLOUT_STATUSES);

export function RolloutsPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const fetchKillSwitch = useChangeStore((s) => s.fetchKillSwitch);
  const fetchPlanConfig = useChangeStore((s) => s.fetchPlanConfig);
  const socketStatus = useSocketStore((s) => s.status);

  const [rollouts, setRollouts] = useState<RolloutView[]>([]);
  const [config, setConfig] = useState<RolloutConfig>(ROLLOUT_CONFIG_FAIL_CLOSED);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [search, setSearch] = useState('');
  const [status, setStatus] = useState<RolloutStatus | ''>('');

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' }),
    [i18n.language],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const rows = await rolloutApi.list({ limit: 200 });
      if (rows === null) { setUnavailable(true); setRollouts([]); }
      else { setUnavailable(false); setRollouts(rows); }
    } catch (err) {
      setLoadError(errorMessageOf(err) ?? t('rollout.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void load();
    void fetchKillSwitch();
    void fetchPlanConfig();
    void rolloutApi.config().then(setConfig);
  }, [load, fetchKillSwitch, fetchPlanConfig]);

  // Live: `wan:rollout:*` frames fold into the list in place. No per-rollout
  // subscription on a list screen — the tenant room already carries these.
  useRolloutSocket({
    onRollout: (rollout) => {
      setRollouts((prev) => {
        const idx = prev.findIndex((r) => r.id === rollout.id);
        if (idx === -1) return [rollout, ...prev];
        const next = prev.slice();
        next[idx] = { ...next[idx], ...rollout };
        return next;
      });
    },
  });

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const rows = rollouts.filter((r) => {
      if (status && r.status !== status) return false;
      if (!needle) return true;
      return [r.name, r.uuid, r.templateName]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(needle));
    });
    rows.sort((a, b) => {
      const aActive = ACTIVE.has(a.status) ? 1 : 0;
      const bActive = ACTIVE.has(b.status) ? 1 : 0;
      if (aActive !== bActive) return bActive - aActive;
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    });
    return rows;
  }, [rollouts, search, status]);

  const counts = useMemo(() => {
    let running = 0, halted = 0, succeeded = 0, rolledBack = 0, failed = 0;
    for (const r of rollouts) {
      if (r.status === 'running' || r.status === 'paused') running++;
      if (r.status === 'halted') halted++;
      if (r.status === 'succeeded') succeeded++;
      if (r.status === 'rolled_back') rolledBack++;
      if (r.status === 'failed') failed++;
    }
    return { running, halted, succeeded, rolledBack, failed };
  }, [rollouts]);

  if (creating) {
    return (
      <div className="p-6">
        <div className="mb-5">
          <h1 className="font-display text-2xl font-semibold text-text-primary">
            {t('rollout.new.title')}
          </h1>
          <p className="mt-1 text-sm text-text-muted">{t('rollout.new.subtitle')}</p>
        </div>
        <KillSwitchBanner className="mb-4" />
        <NewRolloutPanel
          config={config}
          onCancel={() => setCreating(false)}
          onLaunched={(rollout) => {
            setCreating(false);
            void load();
            navigate(`/rollouts/${rollout.id}`);
          }}
        />
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold text-text-primary">
            {t('nav.rollouts')}
          </h1>
          <p className="mt-1 text-sm text-text-muted">{t('rollout.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          {/* The panic button. First, red, permanent. */}
          <KillSwitchButton />
          <Button variant="primary" size="sm" onClick={() => setCreating(true)}>
            <Plus size={14} className="mr-1.5" />
            {t('rollout.newRollout')}
          </Button>
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
        </div>
      </div>

      <KillSwitchBanner className="mb-4" />

      {socketStatus !== 'connected' && !unavailable && (
        <p className="mb-4 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-2.5 text-[12px] text-status-ssl-warning">
          {t('rollout.socketDown')}
        </p>
      )}

      {!unavailable && rollouts.length > 0 && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
          <SummaryCard label={t('rollout.summary.running')} value={String(counts.running)} tone="muted" hint={t('rollout.summary.runningHint')} />
          {/* Its own tile, never folded into "failed": a halted rollout is the
              gate doing its job. */}
          <SummaryCard label={t('rollout.summary.halted')} value={String(counts.halted)} tone="warn" hint={t('rollout.summary.haltedHint')} />
          <SummaryCard label={t('rollout.summary.succeeded')} value={String(counts.succeeded)} tone="ok" hint={t('rollout.summary.succeededHint')} />
          <SummaryCard label={t('rollout.summary.rolledBack')} value={String(counts.rolledBack)} tone="warn" hint={t('rollout.summary.rolledBackHint')} />
          <SummaryCard label={t('rollout.summary.failed')} value={String(counts.failed)} tone={counts.failed > 0 ? 'bad' : 'ok'} hint={t('rollout.summary.failedHint')} />
        </div>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('rollout.searchPlaceholder')}
            className="w-64 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>
        <select
          className={selectClass}
          value={status}
          onChange={(e) => setStatus(e.target.value as RolloutStatus | '')}
        >
          <option value="">{t('rollout.filters.allStatuses')}</option>
          {ROLLOUT_STATUSES.map((s) => (
            <option key={s} value={s}>{t(`rollout.status.label.${s}`)}</option>
          ))}
        </select>
        {(search || status) && (
          <button
            onClick={() => { setSearch(''); setStatus(''); }}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            <X size={12} />
            {t('devices.filters.clear')}
          </button>
        )}
        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('devices.showing', { shown: filtered.length, total: rollouts.length })}
        </span>
      </div>

      {unavailable ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('rollout.endpointUnavailable')}</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
            {t('rollout.endpointUnavailableHint')}
          </p>
          <Button variant="secondary" size="sm" className="mt-3" onClick={() => setCreating(true)}>
            {t('rollout.computeAnyway')}
          </Button>
        </div>
      ) : loadError ? (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
          {t('rollout.loadFailed')} — <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : loading && rollouts.length === 0 ? (
        <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
      ) : rollouts.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Rocket size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('rollout.empty')}</p>
          <p className="mt-1 text-xs text-text-muted">{t('rollout.emptyHint')}</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full min-w-[60rem] text-left text-[13px]">
            <thead className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">{t('rollout.columns.name')}</th>
                <th className="px-3 py-2 font-medium">{t('rollout.columns.status')}</th>
                <th className="px-3 py-2 font-medium">{t('rollout.columns.wave')}</th>
                <th className="px-3 py-2 font-medium">{t('rollout.columns.progress')}</th>
                <th className="px-3 py-2 font-medium">{t('rollout.columns.quarantine')}</th>
                <th className="px-3 py-2 font-medium">{t('rollout.columns.created')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((r) => (
                <tr key={r.id} className="hover:bg-bg-hover">
                  <td className="px-3 py-2">
                    <Link to={`/rollouts/${r.id}`} className="block">
                      <span className="text-text-primary hover:text-accent">{r.name || `#${r.id}`}</span>
                      <span className="block text-[11px] text-text-muted">
                        {r.templateName ?? t('rollout.noTemplate')}
                        {r.revision !== null && ` · r${r.revision}`}
                      </span>
                    </Link>
                  </td>
                  <td className="px-3 py-2"><RolloutStatusBadge status={r.status} /></td>
                  <td className="px-3 py-2 font-mono text-[11px] text-text-secondary">
                    {r.currentWave === null
                      ? '—'
                      : t('rollout.waveOf', { current: r.currentWave + 1, total: r.waveCount })}
                  </td>
                  <td className="px-3 py-2">
                    <ProgressCell rollout={r} />
                  </td>
                  <td className="px-3 py-2">
                    {r.quarantinedRevisionId !== null ? (
                      <span
                        className="inline-flex items-center rounded border border-status-ssl-expired/50 bg-status-ssl-expired/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-status-ssl-expired"
                        title={r.quarantineReason ?? undefined}
                      >
                        {t('rollout.quarantined', { revision: r.quarantinedRevisionId })}
                      </span>
                    ) : (
                      <span className="text-[11px] text-text-muted">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-text-muted">
                    {r.createdAt ? dateFmt.format(new Date(r.createdAt)) : '—'}
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

function ProgressCell({ rollout }: { rollout: RolloutView }) {
  const { t } = useTranslation();
  const total = Math.max(1, rollout.deviceCount);
  const applied = (rollout.applied / total) * 100;
  const rolled = (rollout.rolledBack / total) * 100;
  const failed = (rollout.failed / total) * 100;
  return (
    <div className="min-w-[10rem]">
      <div className="flex h-1.5 overflow-hidden rounded bg-bg-tertiary">
        <div className="bg-status-up" style={{ width: `${applied}%` }} />
        <div className="bg-status-ssl-warning" style={{ width: `${rolled}%` }} />
        <div className="bg-status-ssl-expired" style={{ width: `${failed}%` }} />
      </div>
      <span className="mt-1 block font-mono text-[10px] text-text-muted">
        {t('rollout.progressLabel', {
          applied: rollout.applied,
          rolledBack: rollout.rolledBack,
          failed: rollout.failed,
          total: rollout.deviceCount,
        })}
      </span>
    </div>
  );
}

const TONES = {
  ok: 'text-status-up',
  warn: 'text-status-ssl-warning',
  bad: 'text-status-ssl-expired',
  muted: 'text-text-primary',
};

function SummaryCard({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: string;
  tone: keyof typeof TONES;
  hint: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-3" title={hint}>
      <div className="text-[11px] uppercase tracking-wider text-text-muted">{label}</div>
      <div className={cn('mt-1 font-display text-xl font-semibold tabular-nums', TONES[tone])}>
        {value}
      </div>
    </div>
  );
}
