import { useTranslation } from 'react-i18next';
import { HeartPulse, Link2, ServerCrash, ShieldOff } from 'lucide-react';
import { cn } from '@/utils/cn';
import type { SafetyNetLevel } from '@/types/change';

/**
 * The §8.3 safety net — WHAT REPAIRS THE ROUTER IF WE ARE WRONG.
 *
 * ┌─ WHY THIS IS SHOWN BEFORE THE LAUNCH AND NEVER AFTER ────────────────────┐
 * │ §8.3: "Le niveau est calculé par device et affiché sur l'écran de rayon  │
 * │ d'impact AVANT le lancement, jamais après." Learning that a box had no   │
 * │ dead-man once it has stopped answering is not information, it is a       │
 * │ post-mortem. Every screen that can start a job in this client shows this │
 * │ badge above the button that starts it.                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 *  ARMED          the dead-man is ON the equipment (`/system/scheduler
 *                 start-time=startup` + a restore script). The router repairs
 *                 itself EVEN IF THE OBLIWAN SERVER IS DEAD. That independence
 *                 is the property; a net that needs us alive is not a net.
 *  ARMED_BY_PEER  the dead-man is carried by a co-located MikroTik on the same
 *                 site, reached over a tunnel this change does not touch. It is
 *                 a real net and a WEAKER one: it needs a second box to still
 *                 be alive and reachable.
 *  DEGRADED       detection without recovery. We will know the CPE stopped
 *                 informing, and we will be able to do nothing about it
 *                 remotely. An explicit, recorded confirmation is required.
 *
 * The colours follow that ladder and DEGRADED is red, not amber: it is not
 * "slightly worse", it is the level at which a mistake becomes a van.
 */

const TONE: Record<SafetyNetLevel, string> = {
  ARMED: 'text-status-up border-status-up/50 bg-status-up/10',
  ARMED_BY_PEER: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  DEGRADED: 'text-status-ssl-expired border-status-ssl-expired/60 bg-status-ssl-expired/15',
};

const ICON: Record<SafetyNetLevel, React.ReactNode> = {
  ARMED: <HeartPulse size={12} />,
  ARMED_BY_PEER: <Link2 size={12} />,
  DEGRADED: <ShieldOff size={12} />,
};

export function SafetyNetBadge({
  level,
  size = 'sm',
  className,
}: {
  level: SafetyNetLevel;
  size?: 'sm' | 'lg';
  className?: string;
}) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded border font-medium uppercase tracking-wider',
        size === 'lg' ? 'px-3 py-1.5 text-[13px]' : 'px-1.5 py-0.5 text-[10px]',
        TONE[level],
        className,
      )}
      title={t(`change.safetyNet.hint.${level}`)}
    >
      {ICON[level]}
      {t(`change.safetyNet.label.${level}`)}
    </span>
  );
}

/**
 * The full explanation block. Rendered on the launch screen, never collapsed.
 *
 * `peerName` is not decoration: `ARMED_BY_PEER` is a claim about a SPECIFIC
 * other device, and a claim with no device named is an empty claim. When the
 * peer is unknown the panel says so IN the panel — it does not silently show
 * the reassuring label with nothing behind it.
 */
export function SafetyNetPanel({
  level,
  deviceName,
  peerName,
  className,
}: {
  level: SafetyNetLevel;
  deviceName?: string | null;
  peerName?: string | null;
  className?: string;
}) {
  const { t } = useTranslation();
  const peerMissing = level === 'ARMED_BY_PEER' && !peerName;

  return (
    <section
      className={cn(
        'rounded-lg border p-4',
        level === 'DEGRADED'
          ? 'border-status-ssl-expired/50 bg-status-ssl-expired/5'
          : level === 'ARMED_BY_PEER'
            ? 'border-status-ssl-warning/40 bg-status-ssl-warning/5'
            : 'border-status-up/40 bg-status-up/5',
        className,
      )}
    >
      <div className="flex flex-wrap items-center gap-3">
        <SafetyNetBadge level={level} size="lg" />
        <div className="min-w-[14rem] flex-1">
          <h3 className="text-sm font-semibold text-text-primary">
            {t(`change.safetyNet.title.${level}`)}
          </h3>
          {deviceName && (
            <p className="font-mono text-[11px] text-text-muted">{deviceName}</p>
          )}
        </div>
      </div>

      <p className="mt-2 text-[13px] text-text-secondary">
        {t(`change.safetyNet.body.${level}`)}
      </p>

      {/* The sentence that separates ARMED from ARMED_BY_PEER, spelled out
          rather than left to the badge colour. */}
      <p
        className={cn(
          'mt-2 text-[12px] font-medium',
          level === 'DEGRADED' ? 'text-status-ssl-expired' : 'text-text-primary',
        )}
      >
        {t(`change.safetyNet.survives.${level}`)}
      </p>

      {level === 'ARMED_BY_PEER' && (
        <div className="mt-2 rounded-md border border-border bg-bg-primary/40 p-2.5 text-[12px]">
          {peerMissing ? (
            <span className="text-status-ssl-expired">{t('change.safetyNet.peerMissing')}</span>
          ) : (
            <>
              <span className="text-text-muted">{t('change.safetyNet.peerIs')} </span>
              <span className="font-mono text-text-primary">{peerName}</span>
              <p className="mt-1 text-[11px] text-text-muted">
                {t('change.safetyNet.peerCaveat')}
              </p>
            </>
          )}
        </div>
      )}

      {level === 'DEGRADED' && (
        <div className="mt-2 flex items-start gap-2 rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/10 p-2.5">
          <ServerCrash size={14} className="mt-0.5 shrink-0 text-status-ssl-expired" />
          <p className="text-[12px] text-status-ssl-expired">
            {t('change.safetyNet.degradedWarning')}
          </p>
        </div>
      )}
    </section>
  );
}
