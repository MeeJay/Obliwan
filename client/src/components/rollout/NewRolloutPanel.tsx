import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  ArrowLeft,
  Calculator,
  Rocket,
  Search,
  ServerCrash,
  ShieldX,
  X,
} from 'lucide-react';
import type { ChangeJobKind } from '@obliwan/shared';
import { CHANGE_JOB_KINDS } from '@obliwan/shared';
import { devicesApi } from '@/api/devices.api';
import { buildImpactRadius, composeWaves, rolloutApi } from '@/api/rollout.api';
import type { RolloutConfig } from '@/api/rollout.api';
import { errorMessageOf } from '@/api/change.api';
import { useChangeStore } from '@/store/changeStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { WaveCompositionList } from './WaveComposition';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import type { Device } from '@/types/fleet';
import type { ImpactRadius, RolloutView } from '@/types/rollout';

/**
 * The impact-radius screen — §5/M7's "compilation des N plans AVANT lancement".
 *
 * ┌─ THE ORDER OF THE THREE STEPS IS THE FEATURE ────────────────────────────┐
 * │ 1. pick the devices                                                      │
 * │ 2. COMPUTE — compile every plan, ask the M6 preview for every safety net │
 * │    and every Management-Path Guard verdict                               │
 * │ 3. read the composition, then launch                                     │
 * │                                                                          │
 * │ Step 2 is not optional and its result is not cached across a change of   │
 * │ device set: the Launch button does not exist until a radius has been     │
 * │ computed for exactly the set that is about to be launched. §8.3 says the │
 * │ level is shown "AVANT le lancement, jamais après", and a stale radius    │
 * │ from a previous selection is an "après" wearing an "avant" costume.      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The two confirmations below are NOT client-side politeness. §8.3 requires an
 * explicit recorded confirmation for a DEGRADED net, and a non-ACCEPT guard
 * verdict — INDETERMINATE included — requires a signed override. Both are sent
 * in the launch request; the server re-checks them and refuses the row if they
 * are not enough. A client-side gate is a convenience, a CHECK constraint is
 * the guarantee.
 */

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

export function NewRolloutPanel({
  config,
  onCancel,
  onLaunched,
}: {
  config: RolloutConfig;
  onCancel: () => void;
  onLaunched: (rollout: RolloutView) => void;
}) {
  const { t } = useTranslation();
  const writesAllowed = useChangeStore((s) => s.writesAllowed);
  const killSwitch = useChangeStore((s) => s.killSwitch);

  const [devices, setDevices] = useState<Device[]>([]);
  const [devicesLoading, setDevicesLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Set<number>>(new Set());

  const [name, setName] = useState('');
  const [kind, setKind] = useState<ChangeJobKind>('push');
  const [canarySize, setCanarySize] = useState(1);
  const [secondSize, setSecondSize] = useState(3);
  const [haltOnGateFailure, setHaltOnGateFailure] = useState(true);
  const [quarantineOnFailure, setQuarantineOnFailure] = useState(true);

  const [radius, setRadius] = useState<ImpactRadius | null>(null);
  /** The exact set the radius was computed for. A radius is only valid for the
   *  set it was computed against — see the block comment above. */
  const [radiusKey, setRadiusKey] = useState<string>('');
  const [computing, setComputing] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [degradedConfirmed, setDegradedConfirmed] = useState(false);
  const [overrideReason, setOverrideReason] = useState('');
  const [launching, setLaunching] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const rows = await devicesApi.list();
        if (!cancelled) setDevices(rows);
      } catch (err) {
        if (!cancelled) setError(errorMessageOf(err) ?? t('rollout.new.devicesFailed'));
      } finally {
        if (!cancelled) setDevicesLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [t]);

  const selectedIds = useMemo(() => [...selected].sort((a, b) => a - b), [selected]);
  const currentKey = useMemo(
    () => `${kind}:${selectedIds.join(',')}`,
    [kind, selectedIds],
  );
  const radiusIsStale = radius !== null && radiusKey !== currentKey;

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return devices
      .filter((d) => !needle || [d.name, d.siteName, d.model, d.brand]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(needle)))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [devices, search]);

  const toggle = useCallback((id: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const compute = useCallback(async () => {
    if (selectedIds.length === 0) return;
    setComputing(true);
    setError(null);
    setProgress({ done: 0, total: selectedIds.length });
    try {
      const result = await buildImpactRadius(selectedIds, {
        kind,
        waveSizes: [Math.max(1, canarySize), Math.max(1, secondSize)],
        onProgress: (done, total) => setProgress({ done, total }),
      });
      setRadius(result);
      setRadiusKey(currentKey);
      // A fresh radius invalidates whatever was confirmed against the old one.
      setDegradedConfirmed(false);
      setOverrideReason('');
    } catch (err) {
      setError(errorMessageOf(err) ?? t('rollout.new.computeFailed'));
    } finally {
      setComputing(false);
      setProgress(null);
    }
  }, [selectedIds, kind, canarySize, secondSize, currentKey, t]);

  // Re-composing on a slider change must not re-run 300 previews: the rows are
  // already computed, only the grouping changes.
  const waves = useMemo(() => {
    if (!radius) return [];
    return composeWaves(radius.rows, [Math.max(1, canarySize), Math.max(1, secondSize)]);
  }, [radius, canarySize, secondSize]);

  const needsDegradedConfirmation = (radius?.degradedCount ?? 0) > 0;
  const needsOverride = (radius?.guardRefusedCount ?? 0) > 0;

  const blockers = useMemo(() => {
    const list: string[] = [];
    if (!radius) return list;
    for (const b of radius.blockers) list.push(t(`rollout.new.blocker.${b}`, { defaultValue: b }));
    if (radiusIsStale) list.push(t('rollout.new.blocker.STALE_RADIUS'));
    if (!name.trim()) list.push(t('rollout.new.blocker.NO_NAME'));
    if (!config.canLaunch) {
      list.push(t('rollout.new.blocker.ENDPOINT_ABSENT', { milestone: config.milestone ?? 'M7' }));
    }
    if (killSwitch.blocked) list.push(t('rollout.new.blocker.KILL_SWITCH'));
    if (!writesAllowed()) list.push(t('rollout.new.blocker.WRITES_DISABLED'));
    if (needsDegradedConfirmation && !degradedConfirmed) {
      list.push(t('rollout.new.blocker.DEGRADED_UNCONFIRMED'));
    }
    if (needsOverride && overrideReason.trim().length < 8) {
      list.push(t('rollout.new.blocker.OVERRIDE_REQUIRED'));
    }
    return list;
  }, [
    radius, radiusIsStale, name, config, killSwitch.blocked, writesAllowed,
    needsDegradedConfirmation, degradedConfirmed, needsOverride, overrideReason, t,
  ]);

  const launch = useCallback(async () => {
    if (!radius || blockers.length > 0) return;
    setLaunching(true);
    setError(null);
    try {
      const rollout = await rolloutApi.launch({
        name: name.trim(),
        kind,
        waves: waves.map((w) => ({
          index: w.index,
          label: w.label,
          deviceIds: w.rows.map((r) => r.deviceId),
        })),
        degradedConfirmed: needsDegradedConfirmation ? true : undefined,
        overrideReason: needsOverride ? overrideReason.trim() : undefined,
        haltOnGateFailure,
        quarantineOnFailure,
      });
      if (rollout === null) {
        setError(t('rollout.new.launchEndpointAbsent'));
        return;
      }
      onLaunched(rollout);
    } catch (err) {
      setError(errorMessageOf(err) ?? t('rollout.new.launchFailed'));
    } finally {
      setLaunching(false);
    }
  }, [
    radius, blockers, name, kind, waves, needsDegradedConfirmation, needsOverride,
    overrideReason, haltOnGateFailure, quarantineOnFailure, onLaunched, t,
  ]);

  return (
    <div className="space-y-4">
      <button
        onClick={onCancel}
        className="inline-flex items-center gap-1.5 text-sm text-text-muted hover:text-text-primary"
      >
        <ArrowLeft size={14} /> {t('rollout.new.back')}
      </button>

      {/* ── step 1: what, and on which boxes ── */}
      <section className="rounded-lg border border-border bg-bg-secondary p-4">
        <h2 className="text-sm font-semibold text-text-primary">{t('rollout.new.step1')}</h2>
        <p className="mb-3 text-[12px] text-text-muted">{t('rollout.new.step1Hint')}</p>

        <div className="mb-3 flex flex-wrap items-end gap-3">
          <label className="block">
            <span className="mb-1 block text-[11px] uppercase tracking-wider text-text-muted">
              {t('rollout.new.name')}
            </span>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('rollout.new.namePlaceholder')}
              className="w-72 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </label>

          <label className="block">
            <span className="mb-1 block text-[11px] uppercase tracking-wider text-text-muted">
              {t('rollout.new.kind')}
            </span>
            <select
              className={selectClass}
              value={kind}
              onChange={(e) => setKind(e.target.value as ChangeJobKind)}
            >
              {CHANGE_JOB_KINDS.map((k) => (
                <option key={k} value={k}>{t(`change.kind.${k}`, { defaultValue: k })}</option>
              ))}
            </select>
          </label>

          <label className="block">
            <span className="mb-1 block text-[11px] uppercase tracking-wider text-text-muted">
              {t('rollout.new.canarySize')}
            </span>
            <input
              type="number"
              min={1}
              value={canarySize}
              onChange={(e) => setCanarySize(Math.max(1, Number(e.target.value) || 1))}
              className="w-20 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </label>

          <label className="block">
            <span className="mb-1 block text-[11px] uppercase tracking-wider text-text-muted">
              {t('rollout.new.secondSize')}
            </span>
            <input
              type="number"
              min={1}
              value={secondSize}
              onChange={(e) => setSecondSize(Math.max(1, Number(e.target.value) || 1))}
              className="w-20 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </label>
        </div>

        <div className="mb-2 flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t('rollout.new.searchPlaceholder')}
              className="w-64 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </div>
          <button
            onClick={() => setSelected(new Set(filtered.map((d) => d.id)))}
            className="rounded-md border border-border bg-bg-tertiary px-2 py-1.5 text-[12px] text-text-secondary hover:bg-bg-hover"
          >
            {t('rollout.new.selectAll')}
          </button>
          {selected.size > 0 && (
            <button
              onClick={() => setSelected(new Set())}
              className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
            >
              <X size={12} /> {t('devices.filters.clear')}
            </button>
          )}
          <span className="ml-auto font-mono text-[11px] text-text-muted">
            {t('rollout.new.selectedCount', { count: selected.size })}
          </span>
        </div>

        {devicesLoading ? (
          <div className="flex justify-center py-8"><LoadingSpinner /></div>
        ) : (
          <div className="max-h-64 overflow-y-auto rounded-md border border-border">
            <table className="w-full text-left text-[13px]">
              <tbody className="divide-y divide-border">
                {filtered.map((d) => (
                  <tr key={d.id} className="hover:bg-bg-hover">
                    <td className="w-8 px-2 py-1.5">
                      <input
                        type="checkbox"
                        checked={selected.has(d.id)}
                        onChange={() => toggle(d.id)}
                        className="accent-accent"
                      />
                    </td>
                    <td className="px-2 py-1.5 text-text-primary">{anonHostname(d.name)}</td>
                    <td className="px-2 py-1.5 text-[11px] text-text-muted">{d.siteName ?? '—'}</td>
                    <td className="px-2 py-1.5 font-mono text-[11px] text-text-muted">{d.brand}</td>
                    <td className="px-2 py-1.5 font-mono text-[11px] text-text-muted">
                      {d.role === 'concentrator' ? t('rollout.new.roleConcentrator') : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* ── step 2: compute ── */}
      <section className="rounded-lg border border-border bg-bg-secondary p-4">
        <h2 className="text-sm font-semibold text-text-primary">{t('rollout.new.step2')}</h2>
        <p className="mb-3 text-[12px] text-text-muted">{t('rollout.new.step2Hint')}</p>
        <div className="flex flex-wrap items-center gap-3">
          <Button
            variant="secondary"
            size="sm"
            disabled={selectedIds.length === 0 || computing}
            loading={computing}
            onClick={() => void compute()}
          >
            <Calculator size={14} className="mr-1.5" />
            {t('rollout.new.compute')}
          </Button>
          {progress && (
            <span className="font-mono text-[12px] text-text-muted">
              {t('rollout.new.progress', { done: progress.done, total: progress.total })}
            </span>
          )}
          {radiusIsStale && (
            <span className="inline-flex items-center gap-1.5 rounded border border-status-ssl-warning/50 bg-status-ssl-warning/10 px-2 py-1 text-[12px] text-status-ssl-warning">
              <AlertTriangle size={12} />
              {t('rollout.new.staleRadius')}
            </span>
          )}
        </div>
      </section>

      {error && (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-3 text-sm text-status-ssl-expired">
          {error}
        </div>
      )}

      {/* ── step 3: the radius, the waves, the confirmations ── */}
      {radius && (
        <>
          <section className="grid grid-cols-2 gap-3 md:grid-cols-5">
            <Tile label={t('rollout.impact.devices')} value={String(radius.rows.length)} tone="muted" />
            <Tile
              label={t('rollout.impact.degraded')}
              value={String(radius.degradedCount)}
              tone={radius.degradedCount > 0 ? 'bad' : 'ok'}
              hint={t('rollout.impact.degradedHint')}
            />
            <Tile
              label={t('rollout.impact.guardRefused')}
              value={String(radius.guardRefusedCount)}
              tone={radius.guardRefusedCount > 0 ? 'bad' : 'ok'}
              hint={t('rollout.impact.guardRefusedHint')}
            />
            <Tile
              label={t('rollout.impact.concentrators')}
              value={String(radius.concentratorCount)}
              tone={radius.concentratorCount > 0 ? 'bad' : 'muted'}
              hint={t('rollout.impact.concentratorsHint')}
            />
            <Tile
              label={t('rollout.impact.subtreeSites')}
              value={String(radius.subtreeSiteCount)}
              tone={radius.subtreeSiteCount > 0 ? 'bad' : 'muted'}
              hint={t('rollout.impact.subtreeSitesHint')}
            />
          </section>

          {/* §8.5 — the sentence that is NOT in the §8.3 table. */}
          {radius.concentratorCount > 0 && (
            <div className="rounded-lg border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-3">
              <p className="flex items-start gap-2 text-[13px] text-status-ssl-expired">
                <AlertTriangle size={15} className="mt-0.5 shrink-0" />
                {t('rollout.impact.concentratorWarning', { sites: radius.subtreeSiteCount })}
              </p>
              <p className="mt-1 pl-6 text-[12px] text-status-ssl-expired">
                {t('rollout.impact.concentratorRecovery')}
              </p>
            </div>
          )}

          {radius.warnings.length > 0 && (
            <div className="rounded-lg border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3 text-[12px] text-status-ssl-warning">
              {radius.warnings.map((w) => (
                <p key={w} className="font-mono">{t(`rollout.new.warning.${w}`, { defaultValue: w })}</p>
              ))}
            </div>
          )}

          <WaveCompositionList waves={waves} />

          {/* ── the two confirmations §8.3 requires ── */}
          {needsDegradedConfirmation && (
            <label className="flex cursor-pointer items-start gap-2 rounded-lg border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-3">
              <input
                type="checkbox"
                checked={degradedConfirmed}
                onChange={(e) => setDegradedConfirmed(e.target.checked)}
                className="mt-0.5 accent-red-500"
              />
              <span>
                <span className="flex items-center gap-1.5 text-[13px] font-medium text-status-ssl-expired">
                  <ServerCrash size={14} />
                  {t('rollout.new.degradedConfirm', { count: radius.degradedCount })}
                </span>
                <span className="mt-0.5 block text-[12px] text-status-ssl-expired">
                  {t('rollout.new.degradedConfirmHint')}
                </span>
              </span>
            </label>
          )}

          {needsOverride && (
            <div className="rounded-lg border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-3">
              <p className="flex items-center gap-1.5 text-[13px] font-medium text-status-ssl-expired">
                <ShieldX size={14} />
                {t('rollout.new.overrideTitle', { count: radius.guardRefusedCount })}
              </p>
              <p className="mt-0.5 text-[12px] text-status-ssl-expired">
                {t('rollout.new.overrideHint')}
              </p>
              <textarea
                value={overrideReason}
                onChange={(e) => setOverrideReason(e.target.value)}
                rows={2}
                placeholder={t('rollout.new.overridePlaceholder')}
                className="mt-2 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
              />
            </div>
          )}

          <section className="rounded-lg border border-border bg-bg-secondary p-4">
            <div className="mb-3 flex flex-wrap gap-4">
              <label className="flex items-center gap-2 text-[13px] text-text-secondary">
                <input
                  type="checkbox"
                  checked={haltOnGateFailure}
                  onChange={(e) => setHaltOnGateFailure(e.target.checked)}
                  className="accent-accent"
                />
                {t('rollout.new.haltOnGateFailure')}
              </label>
              <label className="flex items-center gap-2 text-[13px] text-text-secondary">
                <input
                  type="checkbox"
                  checked={quarantineOnFailure}
                  onChange={(e) => setQuarantineOnFailure(e.target.checked)}
                  className="accent-accent"
                />
                {t('rollout.new.quarantineOnFailure')}
              </label>
            </div>

            {blockers.length > 0 && (
              <ul className="mb-3 space-y-1">
                {blockers.map((b) => (
                  <li key={b} className="flex items-start gap-1.5 text-[12px] text-status-ssl-expired">
                    <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                    {b}
                  </li>
                ))}
              </ul>
            )}

            <Button
              variant="danger"
              disabled={blockers.length > 0 || launching}
              loading={launching}
              onClick={() => void launch()}
            >
              <Rocket size={15} className="mr-1.5" />
              {t('rollout.new.launch', { count: radius.rows.length, waves: waves.length })}
            </Button>
          </section>
        </>
      )}
    </div>
  );
}

const TONES = {
  ok: 'text-status-up',
  bad: 'text-status-ssl-expired',
  muted: 'text-text-primary',
};

function Tile({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: string;
  tone: keyof typeof TONES;
  hint?: string;
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
