import { useTranslation } from 'react-i18next';
import { ArrowRight, Crosshair, Route as RouteIcon, ShieldAlert } from 'lucide-react';
import { cn } from '@/utils/cn';
import type { GuardResultView, GuardRouteView } from '@/types/change';
import { GuardVerdictBadge, guardBadgeState, type GuardBadgeState } from './RiskBadge';

/**
 * The Management-Path Guard verdict, rendered as the FIRST thing on the plan
 * screen and sized so it cannot be scrolled past.
 *
 * ── WHY THIS PANEL IS AS LOUD AS IT IS ──────────────────────────────────────
 * R1: a push can cut the tunnel we administer through, and the repair is then a
 * van. The guard is the only thing between a compiled plan and that van, and a
 * guard whose answer is a small grey line at the bottom of a table is a guard
 * nobody reads. So the verdict is a full-width block, the verb is in the
 * heading, and the reasons are listed with the RECORD and the PLAN LINE that
 * caused each one — because "REJECT" alone is an argument and "REJECT because
 * op #7 inserts `chain=input action=drop` above your management accept" is a
 * fix. An operator who is refused without being told why turns the guard off
 * within a week.
 *
 * ── THE FOUR STATES, AND THE THREE THAT REFUSE ──────────────────────────────
 *  ACCEPT         the guard PROVED the management path survives.
 *  REJECT         the guard PROVED the change cuts it.
 *  INDETERMINATE  the guard could not prove either. A REFUSAL. Red.
 *  NOT_RUN        nobody asked the guard. Also a refusal, and labelled
 *                 differently so it is never mistaken for a considered opinion.
 *
 * The panel never renders a "proceed anyway" control. The override lives on its
 * own screen, reached from elsewhere, and that separation is deliberate: see
 * `components/change/OverrideDialog.tsx`.
 */

const HEAD_TONE: Record<GuardBadgeState, string> = {
  ACCEPT: 'border-status-up/40 bg-status-up/5',
  REJECT: 'border-status-ssl-expired/60 bg-status-ssl-expired/10',
  INDETERMINATE: 'border-status-down/60 bg-status-down/10',
  NOT_RUN: 'border-status-down/60 bg-status-down/10',
};

const HEAD_TEXT: Record<GuardBadgeState, string> = {
  ACCEPT: 'text-status-up',
  REJECT: 'text-status-ssl-expired',
  INDETERMINATE: 'text-status-down',
  NOT_RUN: 'text-status-down',
};

const OUTCOME_TONE: Record<'accept' | 'drop' | 'unknown', string> = {
  accept: 'text-status-up',
  drop: 'text-status-ssl-expired',
  unknown: 'text-text-muted',
};

const ROUTE_TONE: Record<'ok' | 'broken' | 'none' | 'unknown', string> = {
  ok: 'text-status-up',
  broken: 'text-status-ssl-expired',
  none: 'text-status-ssl-expired',
  unknown: 'text-text-muted',
};

export function GuardVerdictPanel({
  guard,
  onFocusOp,
  className,
}: {
  guard: GuardResultView | null;
  /** Jump to the plan line a reason blames. */
  onFocusOp?: (opSeq: number) => void;
  className?: string;
}) {
  const { t } = useTranslation();
  const state = guardBadgeState(guard);

  const proofs = (guard?.reasons ?? []).filter((r) => r.effect === 'reject');
  const blind = (guard?.reasons ?? []).filter((r) => r.effect === 'indeterminate');

  return (
    <section
      className={cn('rounded-lg border', HEAD_TONE[state], className)}
      aria-live="polite"
    >
      {/* Heading — verdict, verb, one sentence. */}
      <div className="flex flex-wrap items-start gap-x-4 gap-y-2 border-b border-border/60 p-4">
        <GuardVerdictBadge state={state} size="lg" />
        <div className="min-w-[16rem] flex-1">
          <h2 className={cn('font-display text-lg font-semibold', HEAD_TEXT[state])}>
            {t(`plan.guard.headline.${state}`)}
          </h2>
          <p className="mt-1 text-[13px] text-text-secondary">
            {guard?.summary && guard.ran
              ? guard.summary
              : t(`plan.guard.body.${state}`)}
          </p>
          {state !== 'ACCEPT' && (
            <p className="mt-2 text-[12px] font-medium text-text-primary">
              {t('plan.guard.consequence')}
            </p>
          )}
        </div>
      </div>

      {/* What the engine actually reasoned about. Shown next to the verdict so
          nobody has to guess which address and which interface it analysed —
          a confidently wrong `peerAddress` produces a confidently wrong probe. */}
      {guard?.analysed && (
        <div className="flex flex-wrap gap-x-6 gap-y-2 border-b border-border/60 px-4 py-3 text-[12px]">
          <Analysed label={t('plan.guard.analysed.peer')} value={guard.analysed.peerAddress} />
          <Analysed label={t('plan.guard.analysed.mgmt')} value={guard.analysed.managementAddress} />
          <Analysed
            label={t('plan.guard.analysed.tunnel')}
            value={guard.analysed.tunnelInterface}
            suffix={
              guard.analysed.tunnelInterface && !guard.analysed.tunnelInterfaceCertain
                ? t('plan.guard.analysed.uncertain')
                : null
            }
          />
          <Analysed
            label={t('plan.guard.analysed.ports')}
            value={guard.analysed.ports.length > 0 ? guard.analysed.ports.join(', ') : null}
          />
        </div>
      )}

      {/* Reasons — proofs first, then blindness. Both are refusals; the two
          headings exist so an operator can tell which kind he is facing, and
          therefore whether recompiling after a collect would change anything. */}
      {(proofs.length > 0 || blind.length > 0) && (
        <div className="space-y-4 p-4">
          {proofs.length > 0 && (
            <ReasonGroup
              title={t('plan.guard.proofs')}
              hint={t('plan.guard.proofsHint')}
              tone="proof"
              reasons={proofs}
              onFocusOp={onFocusOp}
            />
          )}
          {blind.length > 0 && (
            <ReasonGroup
              title={t('plan.guard.blindness')}
              hint={t('plan.guard.blindnessHint')}
              tone="blind"
              reasons={blind}
              onFocusOp={onFocusOp}
            />
          )}
        </div>
      )}

      {/* Probes — the packet table. `before` is how the box behaves TODAY: a
          probe already dropped today carries no information about this plan,
          and the column makes that visible instead of leaving the operator to
          wonder why the guard is silent about ssh. */}
      {guard?.ran && guard.probes.length > 0 && (
        <div className="border-t border-border/60 p-4">
          <h3 className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-text-muted">
            <Crosshair size={12} />
            {t('plan.guard.probes')}
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[32rem] text-left text-[12px]">
              <thead className="text-[10px] uppercase tracking-wider text-text-muted">
                <tr>
                  <th className="py-1 pr-3 font-medium">{t('plan.guard.probeCol.packet')}</th>
                  <th className="py-1 pr-3 font-medium">{t('plan.guard.probeCol.before')}</th>
                  <th className="py-1 pr-3 font-medium" />
                  <th className="py-1 font-medium">{t('plan.guard.probeCol.after')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {guard.probes.map((p) => {
                  const regressed = p.before === 'accept' && p.after !== 'accept';
                  return (
                    <tr key={p.id} className={cn(regressed && 'bg-status-ssl-expired/5')}>
                      <td className="py-1.5 pr-3 font-mono text-[11px] text-text-secondary">
                        {p.description || p.id}
                      </td>
                      <td className={cn('py-1.5 pr-3 font-mono', OUTCOME_TONE[p.before])}>
                        {t(`plan.guard.outcome.${p.before}`)}
                      </td>
                      <td className="py-1.5 pr-3 text-text-muted">
                        <ArrowRight size={11} />
                      </td>
                      <td className={cn('py-1.5 font-mono', OUTCOME_TONE[p.after])}>
                        {t(`plan.guard.outcome.${p.after}`)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Routing. `state: ok` on both sides with a CHANGED EGRESS is the
          silent-default-route motif: the reply does not vanish, it leaves
          through the WAN and dies at the first ISP router. The egress is
          therefore shown as a first-class column, not as a detail string. */}
      {guard?.ran && guard.routing && (
        <div className="border-t border-border/60 p-4">
          <h3 className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-text-muted">
            <RouteIcon size={12} />
            {t('plan.guard.returnRoute')}
          </h3>
          <div className="grid gap-3 sm:grid-cols-2">
            <RouteCard title={t('plan.guard.routeBefore')} route={guard.routing.before} />
            <RouteCard
              title={t('plan.guard.routeAfter')}
              route={guard.routing.after}
              highlight={guard.routing.before.egress !== guard.routing.after.egress}
              highlightLabel={t('plan.guard.egressChanged')}
            />
          </div>
        </div>
      )}
    </section>
  );
}

function Analysed({
  label,
  value,
  suffix,
}: {
  label: string;
  value: string | null;
  suffix?: string | null;
}) {
  const { t } = useTranslation();
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-text-muted">{label}</div>
      <div className="font-mono text-[12px] text-text-primary">
        {value ?? <span className="text-status-down">{t('plan.guard.analysed.missing')}</span>}
        {suffix && <span className="ml-1.5 text-[11px] text-status-down">({suffix})</span>}
      </div>
    </div>
  );
}

function ReasonGroup({
  title,
  hint,
  tone,
  reasons,
  onFocusOp,
}: {
  title: string;
  hint: string;
  tone: 'proof' | 'blind';
  reasons: GuardResultView['reasons'];
  onFocusOp?: (opSeq: number) => void;
}) {
  const { t } = useTranslation();
  return (
    <div>
      <h3
        className={cn(
          'mb-1 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider',
          tone === 'proof' ? 'text-status-ssl-expired' : 'text-status-down',
        )}
      >
        <ShieldAlert size={12} />
        {title}
      </h3>
      <p className="mb-2 text-[11px] text-text-muted">{hint}</p>
      <ul className="space-y-2">
        {reasons.map((r, i) => (
          <li
            key={`${r.code}-${i}`}
            className={cn(
              'rounded-md border p-2.5',
              tone === 'proof'
                ? 'border-status-ssl-expired/30 bg-status-ssl-expired/5'
                : 'border-status-down/30 bg-status-down/5',
            )}
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded border border-border bg-bg-tertiary px-1.5 py-0.5 font-mono text-[10px] text-text-secondary">
                {r.code}
              </span>
              {r.probe && (
                <span className="font-mono text-[10px] text-text-muted">{r.probe}</span>
              )}
            </div>
            <p className="mt-1.5 text-[13px] text-text-primary">{r.message}</p>
            {r.culprit && (
              <div className="mt-2 space-y-1 rounded border border-border/70 bg-bg-primary/40 p-2">
                {/* Brand-neutral, secret-free by construction: the NCM carries
                    no values §8.2 would object to. */}
                <div className="font-mono text-[11px] text-text-secondary break-all">
                  {r.culprit.describe}
                </div>
                <div className="flex flex-wrap items-center gap-2 text-[10px] text-text-muted">
                  <span className="font-mono">{r.culprit.semKey}</span>
                  {r.culprit.chain && (
                    <span className="font-mono">chain={r.culprit.chain}</span>
                  )}
                  {r.culprit.index !== null && (
                    <span className="font-mono">#{r.culprit.index}</span>
                  )}
                  {r.culprit.opSeq !== null && (
                    <button
                      type="button"
                      onClick={() => onFocusOp?.(r.culprit!.opSeq as number)}
                      className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-accent hover:bg-accent/20"
                    >
                      {t('plan.guard.fromOp', {
                        seq: r.culprit.opSeq,
                        kind: r.culprit.opKind ?? '?',
                      })}
                    </button>
                  )}
                </div>
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function RouteCard({
  title,
  route,
  highlight,
  highlightLabel,
}: {
  title: string;
  route: GuardRouteView;
  highlight?: boolean;
  highlightLabel?: string;
}) {
  const { t } = useTranslation();
  return (
    <div
      className={cn(
        'rounded-md border p-2.5',
        highlight ? 'border-status-ssl-expired/50 bg-status-ssl-expired/5' : 'border-border bg-bg-primary/40',
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] uppercase tracking-wider text-text-muted">{title}</span>
        <span className={cn('font-mono text-[11px]', ROUTE_TONE[route.state])}>
          {t(`plan.guard.routeState.${route.state}`)}
        </span>
      </div>
      <dl className="mt-1.5 space-y-0.5 text-[11px]">
        <div className="flex gap-2">
          <dt className="w-14 shrink-0 text-text-muted">{t('plan.guard.routeVia')}</dt>
          <dd className="font-mono text-text-secondary break-all">{route.via ?? '—'}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-14 shrink-0 text-text-muted">{t('plan.guard.routeEgress')}</dt>
          <dd className="font-mono text-text-primary break-all">{route.egress ?? '—'}</dd>
        </div>
      </dl>
      {route.detail && <p className="mt-1.5 text-[11px] text-text-muted">{route.detail}</p>}
      {highlight && highlightLabel && (
        <p className="mt-1.5 text-[11px] font-medium text-status-ssl-expired">{highlightLabel}</p>
      )}
    </div>
  );
}
