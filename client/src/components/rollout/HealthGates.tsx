import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { GateStateBadge, gateCleared } from './RolloutBadges';
import { cn } from '@/utils/cn';
import type { HealthGateKind, HealthGateView } from '@/types/rollout';
import { HEALTH_GATE_KINDS } from '@/types/rollout';

/**
 * The health gates of a wave (§5/M7, extended by §8.4).
 *
 * ── WHY EVERY GATE IS RENDERED, INCLUDING THE ONES THE SERVER DID NOT SEND ──
 * A gate the payload omits is a gate that was NOT evaluated. Rendering only the
 * gates present would make an incomplete evaluation look like a complete one —
 * three green ticks and no hint that two signals were never collected. So the
 * six known gates are always drawn, and a missing one reads `unknown`, which
 * `GateStateBadge` paints on the refusing side.
 *
 * ── §8.4, AND WHY IT HAS ITS OWN GATE ───────────────────────────────────────
 * `netwatch` is the only gate that watches the CLIENT's service rather than our
 * management path. The Management-Path Guard is blind to a NAT rule that kills
 * VoIP while leaving our tunnel intact; this gate is the one that is not. It is
 * listed last because it is the newest, not because it matters least.
 */

const GATE_ORDER: readonly HealthGateKind[] = HEALTH_GATE_KINDS;

export function HealthGateStrip({
  gates,
  className,
}: {
  gates: HealthGateView[];
  className?: string;
}) {
  const { t } = useTranslation();
  const byKind = new Map(gates.map((g) => [g.kind, g]));

  return (
    <div className={cn('flex flex-wrap gap-1.5', className)}>
      {GATE_ORDER.map((kind) => {
        const gate = byKind.get(kind);
        return (
          <span
            key={kind}
            className="inline-flex items-center gap-1.5 rounded border border-border bg-bg-tertiary px-1.5 py-0.5"
            title={gate?.detail ?? t(`rollout.gate.hint.${kind}`)}
          >
            <span className="text-[10px] uppercase tracking-wider text-text-muted">
              {t(`rollout.gate.label.${kind}`)}
            </span>
            <GateStateBadge state={gate?.state ?? 'unknown'} />
          </span>
        );
      })}
    </div>
  );
}

/** The expanded panel: one row per gate, with the devices that failed it. The
 *  drill-down is the point — "if_errors FAILED" is a sentence, "if_errors
 *  FAILED on these two boxes" is a diagnosis. */
export function HealthGatePanel({
  gates,
  deviceNames,
  className,
}: {
  gates: HealthGateView[];
  /** deviceId -> name, so a failed gate can name the boxes rather than the ids. */
  deviceNames: Map<number, string>;
  className?: string;
}) {
  const { t } = useTranslation();
  const byKind = new Map(gates.map((g) => [g.kind, g]));
  const anyUnknown = GATE_ORDER.some((k) => (byKind.get(k)?.state ?? 'unknown') === 'unknown');

  return (
    <section className={cn('rounded-lg border border-border bg-bg-secondary', className)}>
      <header className="border-b border-border px-3 py-2">
        <h3 className="text-sm font-semibold text-text-primary">{t('rollout.gate.title')}</h3>
        <p className="text-[11px] text-text-muted">{t('rollout.gate.subtitle')}</p>
      </header>

      <ul className="divide-y divide-border">
        {GATE_ORDER.map((kind) => {
          const gate = byKind.get(kind);
          const state = gate?.state ?? 'unknown';
          return (
            <li key={kind} className="px-3 py-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[13px] text-text-primary">
                  {t(`rollout.gate.label.${kind}`)}
                </span>
                <GateStateBadge state={state} />
                {!gate && (
                  <span className="text-[11px] text-text-muted">
                    {t('rollout.gate.notEvaluated')}
                  </span>
                )}
              </div>
              <p className="mt-0.5 text-[11px] text-text-muted">
                {gate?.detail ?? t(`rollout.gate.hint.${kind}`)}
              </p>
              {gate && gate.failedDeviceIds.length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {gate.failedDeviceIds.map((id) => (
                    <Link
                      key={id}
                      to={`/devices/${id}`}
                      className="rounded border border-status-ssl-expired/50 bg-status-ssl-expired/10 px-1.5 py-0.5 font-mono text-[10px] text-status-ssl-expired hover:bg-status-ssl-expired/20"
                    >
                      {deviceNames.get(id) ?? `#${id}`}
                    </Link>
                  ))}
                </div>
              )}
            </li>
          );
        })}
      </ul>

      {anyUnknown && (
        <p className="border-t border-border px-3 py-2 text-[11px] text-status-down">
          {t('rollout.gate.unknownWarning')}
        </p>
      )}
    </section>
  );
}

/**
 * Whether a wave's gates ALL cleared.
 *
 * This client never decides anything with it — the server opens the next wave.
 * It exists so `RolloutDetailPage` can spot a DISAGREEMENT: a wave the server
 * marked `passed` whose gate payload does not show six cleared gates. That is
 * either a gate that was never evaluated or a payload that lost one, and both
 * are worth a line on screen. An interface that silently accepts "passed" from
 * a wave whose evidence is incomplete is an interface that launders a gap in
 * the evidence into a green badge.
 *
 * A gate list SHORTER than the known set is not cleared: an unsent gate is an
 * unevaluated gate.
 */
export function allGatesCleared(gates: HealthGateView[]): boolean {
  if (gates.length < GATE_ORDER.length) return false;
  return gates.every((g) => gateCleared(g.state));
}
