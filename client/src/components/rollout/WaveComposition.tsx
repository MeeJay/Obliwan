import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { AlertTriangle, Network, Rocket, ServerCrash } from 'lucide-react';
import { SafetyNetBadge } from '@/components/change/SafetyNetBadge';
import { GuardVerdictBadge, RiskBadge, guardBadgeState } from '@/components/plan/RiskBadge';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import type { ImpactRow, WaveComposition as Wave } from '@/types/rollout';

/**
 * The wave composition, as the operator sees it BEFORE launch.
 *
 * ┌─ WHY THE SAFETY NET IS A COLUMN AND NOT A TOOLTIP ───────────────────────┐
 * │ §8.3: the level is "calculé par device et affiché sur l'écran de rayon   │
 * │ d'impact AVANT le lancement, jamais après", and a rollout mixing ARMED   │
 * │ and DEGRADED "traite les DÉGRADÉ en dernier". Both sentences are about   │
 * │ the COMPOSITION, so the composition is what carries the badge — one per  │
 * │ device, on the row, at full size, never folded into a count.             │
 * │                                                                          │
 * │ A DEGRADED device in the CANARY wave gets a red banner across the wave   │
 * │ header as well. Wave 0 is the wave an operator watches least carefully   │
 * │ because it is "only one box"; it is also the wave where a box with no    │
 * │ recovery path costs a van. If the ordering rule ever regresses, this     │
 * │ banner is what makes it visible on the screen instead of in a diff.      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * §8.5 gets the same treatment for concentrators: one line, red, naming the
 * number of sites that lose management — because that is the only equipment in
 * the fleet whose mistake is counted in customers rather than in a customer.
 */

export function WaveCompositionList({
  waves,
  className,
}: {
  waves: Wave[];
  className?: string;
}) {
  const { t } = useTranslation();

  if (waves.length === 0) {
    return (
      <div className={cn('rounded-lg border border-border bg-bg-secondary py-10 text-center', className)}>
        <Rocket size={24} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{t('rollout.impact.noWaves')}</p>
      </div>
    );
  }

  return (
    <div className={cn('space-y-3', className)}>
      {waves.map((wave) => (
        <WaveCard key={wave.index} wave={wave} />
      ))}
    </div>
  );
}

function WaveCard({ wave }: { wave: Wave }) {
  const { t } = useTranslation();
  const isCanary = wave.index === 0;
  const degraded = wave.rows.filter((r) => r.safetyNet === 'DEGRADED');
  const concentrators = wave.rows.filter((r) => r.role === 'concentrator');
  const lostSites = concentrators.reduce((sum, r) => sum + r.subtreeSize, 0);

  return (
    <section
      className={cn(
        'overflow-hidden rounded-lg border bg-bg-secondary',
        isCanary && degraded.length > 0
          ? 'border-status-ssl-expired/60'
          : isCanary
            ? 'border-accent/40'
            : 'border-border',
      )}
    >
      <header className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <span
          className={cn(
            'inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider',
            isCanary
              ? 'border-accent/50 bg-accent/10 text-accent'
              : 'border-border bg-bg-tertiary text-text-secondary',
          )}
        >
          {isCanary ? <Rocket size={11} /> : <Network size={11} />}
          {isCanary ? t('rollout.impact.canary') : t('rollout.impact.waveN', { n: wave.index + 1 })}
        </span>
        <span className="font-mono text-[11px] text-text-muted">{wave.label}</span>
        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('rollout.impact.deviceCount', { count: wave.rows.length })}
        </span>
      </header>

      {/* §8.3 — a device with no recovery path, in the wave nobody watches. */}
      {isCanary && degraded.length > 0 && (
        <p className="flex items-start gap-2 border-b border-status-ssl-expired/40 bg-status-ssl-expired/10 px-3 py-2 text-[12px] text-status-ssl-expired">
          <ServerCrash size={14} className="mt-0.5 shrink-0" />
          {t('rollout.impact.degradedInCanary', { count: degraded.length })}
        </p>
      )}

      {/* §8.5 — the subtree, not a site. */}
      {concentrators.length > 0 && (
        <p className="flex items-start gap-2 border-b border-status-ssl-expired/40 bg-status-ssl-expired/10 px-3 py-2 text-[12px] text-status-ssl-expired">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" />
          {t('rollout.impact.concentratorInWave', {
            count: concentrators.length,
            sites: lostSites,
          })}
        </p>
      )}

      <div className="overflow-x-auto">
        <table className="w-full min-w-[52rem] text-left text-[13px]">
          <thead className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
            <tr>
              <th className="px-3 py-2 font-medium">{t('rollout.impact.columns.device')}</th>
              <th className="px-3 py-2 font-medium">{t('rollout.impact.columns.safetyNet')}</th>
              <th className="px-3 py-2 font-medium">{t('rollout.impact.columns.guard')}</th>
              <th className="px-3 py-2 font-medium">{t('rollout.impact.columns.plan')}</th>
              <th className="px-3 py-2 font-medium">{t('rollout.impact.columns.risk')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {wave.rows.map((row) => (
              <ImpactRowLine key={row.deviceId} row={row} />
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ImpactRowLine({ row }: { row: ImpactRow }) {
  const { t } = useTranslation();
  const guardState = guardBadgeState(row.impact?.guard ?? null);

  return (
    <tr className={cn('hover:bg-bg-hover', row.safetyNet === 'DEGRADED' && 'bg-status-ssl-expired/5')}>
      <td className="px-3 py-2">
        <Link to={`/devices/${row.deviceId}`} className="block">
          <span className="text-text-primary hover:text-accent">
            {anonHostname(row.deviceName)}
          </span>
          <span className="block text-[11px] text-text-muted">
            {row.siteName ?? '—'}
            {row.role === 'concentrator' && (
              <span className="ml-1.5 rounded border border-status-ssl-expired/50 bg-status-ssl-expired/10 px-1 py-px font-mono text-[9px] uppercase tracking-wider text-status-ssl-expired">
                {t('rollout.impact.concentrator', { count: row.subtreeSize })}
              </span>
            )}
          </span>
        </Link>
      </td>

      <td className="px-3 py-2">
        <SafetyNetBadge level={row.safetyNet} />
        {/* A net we did not observe is shown as DEGRADED and SAID to be
            unobserved. Silently showing the pessimistic badge without the
            sentence would let an operator read "this box has no dead-man" when
            the truth is "we could not ask". */}
        {!row.impact && (
          <span className="mt-1 block text-[10px] text-status-ssl-expired">
            {t('rollout.impact.netNotEstablished')}
          </span>
        )}
      </td>

      <td className="px-3 py-2">
        <GuardVerdictBadge state={guardState} />
        {row.impactError && (
          <span className="mt-1 block font-mono text-[10px] text-text-muted">
            {row.impactError}
          </span>
        )}
      </td>

      <td className="px-3 py-2">
        {row.planCompiled ? (
          <span className="font-mono text-[11px] text-text-secondary">
            {t('rollout.impact.ops', { count: row.changeOpCount })}
            {row.touchesManagementPath && (
              <span className="ml-1.5 rounded border border-status-ssl-warning/50 bg-status-ssl-warning/10 px-1 py-px text-[9px] uppercase tracking-wider text-status-ssl-warning">
                {t('rollout.impact.touchesMgmt')}
              </span>
            )}
          </span>
        ) : (
          <span className="font-mono text-[11px] text-status-ssl-expired">
            {row.planError ?? t('rollout.impact.noPlan')}
          </span>
        )}
      </td>

      <td className="px-3 py-2">
        {row.riskLevel ? (
          <RiskBadge risk={row.riskLevel} />
        ) : (
          <span className="text-[11px] text-text-muted">—</span>
        )}
      </td>
    </tr>
  );
}
