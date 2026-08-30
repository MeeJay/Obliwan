import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  Building2,
  Cable,
  ChevronDown,
  ChevronRight,
  Clock,
  History,
  Network,
  Router as RouterIcon,
  ShieldX,
} from 'lucide-react';
import type { ApplyPlan, PlanOp, PlanOpKind, RiskLevel } from '@obliwan/shared';
import { RISK_RANK } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import { scanValueForSecrets } from '@/utils/secretScan';
import type { CompiledPlan, OutcomeHistoryView } from '@/types/change';
import { CulpritChip, DisruptiveChip, OkChip, OpKindChip, RiskBadge } from './RiskBadge';

/**
 * `PlanViewer` — the compiled plan: blast radius, then the ops, coloured by
 * risk, with the guard's culprits marked.
 *
 * ── WHAT THIS COMPONENT REFUSES TO DO ───────────────────────────────────────
 * It renders no Apply button and takes no `onApply`. A plan viewer is a reading
 * surface; the launch gesture lives on the launch screen, behind the safety-net
 * panel and the confirmations. Putting a write control inside a scrollable list
 * of fifty rows is how a mis-aimed click becomes a change job.
 *
 * ── ORDERING ────────────────────────────────────────────────────────────────
 * Ops are shown in `seq` order and NOT sorted by risk, because `seq` is the
 * order they will be applied in and because `move` ops are only meaningful in
 * sequence (§4.5: RouterOS renumbers the list on every move). A "worst first"
 * sort would be a friendlier list and a lying one. The risk filter is there for
 * the operator who wants to see only the high-risk lines, and it says how many
 * it is hiding.
 *
 * ── §8.2 ────────────────────────────────────────────────────────────────────
 * `before` / `after` are REDACTED resource values. They are rendered as JSON in
 * a collapsed pane, and every one of them goes through `scanValueForSecrets`
 * first: on a hit the pane refuses to draw the value and says which key tripped
 * it. The server guarantees the redaction; this is the check of that guarantee,
 * not a substitute for it.
 */

interface PlanViewerProps {
  compiled: CompiledPlan;
  /** `seq` values the guard blamed — highlighted and filterable. */
  culpritOpSeqs?: number[];
  /** Set by the page when a guard reason was clicked. */
  focusedOpSeq?: number | null;
  className?: string;
}

export function PlanViewer({
  compiled,
  culpritOpSeqs = [],
  focusedOpSeq = null,
  className,
}: PlanViewerProps) {
  const { t } = useTranslation();
  const { plan, detail, outcomeHistory } = compiled;

  const [minRisk, setMinRisk] = useState<RiskLevel | ''>('');
  const [culpritsOnly, setCulpritsOnly] = useState(false);
  const culprits = useMemo(() => new Set(culpritOpSeqs), [culpritOpSeqs]);

  const ops = useMemo(() => [...plan.ops].sort((a, b) => a.seq - b.seq), [plan.ops]);

  const shown = useMemo(() => {
    const floor = minRisk ? RISK_RANK[minRisk] : -1;
    return ops.filter((op) => {
      if (culpritsOnly && !culprits.has(op.seq)) return false;
      if (floor >= 0 && RISK_RANK[op.risk] < floor) return false;
      return true;
    });
  }, [ops, minRisk, culpritsOnly, culprits]);

  const counts = useMemo(() => {
    const byKind: Partial<Record<PlanOpKind, number>> = {};
    let disruptive = 0;
    for (const op of ops) {
      byKind[op.kind] = (byKind[op.kind] ?? 0) + 1;
      if (op.disruptive) disruptive++;
    }
    return { byKind, disruptive };
  }, [ops]);

  return (
    <div className={cn('space-y-4', className)}>
      <BlastRadiusPanel plan={plan} disruptiveCount={counts.disruptive} />

      {/* Convergence and freshness — two facts that decide whether this plan
          may be offered for approval at all (§4.5, `baseStateHash`). */}
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-bg-secondary p-3 text-[12px]">
        {plan.orderConverges ? (
          <OkChip label={t('plan.converges')} />
        ) : (
          <span className="inline-flex items-center gap-1 rounded border border-status-ssl-expired/50 bg-status-ssl-expired/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-status-ssl-expired">
            <AlertTriangle size={10} />
            {t('plan.doesNotConverge')}
          </span>
        )}
        <span className="flex items-center gap-1.5 text-text-muted">
          <Clock size={12} />
          {t('plan.expiresAt', { at: formatWhen(plan.expiresAt) })}
        </span>
        <span className="font-mono text-[11px] text-text-muted" title={plan.baseStateHash}>
          {t('plan.baseState', { hash: plan.baseStateHash.slice(0, 12) })}
        </span>
        <span className="ml-auto flex items-center gap-2">
          <span className="text-text-muted">{t('plan.planRisk')}</span>
          <RiskBadge risk={plan.riskLevel} />
        </span>
      </div>

      {!plan.orderConverges && (
        <p className="rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-3 text-[12px] text-status-ssl-expired">
          {t('plan.doesNotConvergeHint')}
        </p>
      )}

      {detail.warnings.length > 0 && (
        <div className="rounded-lg border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3">
          <h3 className="mb-1.5 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-status-ssl-warning">
            <AlertTriangle size={12} />
            {t('plan.warnings')}
          </h3>
          <ul className="list-inside list-disc space-y-1 text-[12px] text-text-secondary">
            {detail.warnings.map((w, i) => <li key={i}>{w}</li>)}
          </ul>
        </div>
      )}

      {detail.deletionsBlocked > 0 && (
        <p className="rounded-md border border-border bg-bg-secondary p-3 text-[12px] text-text-secondary">
          {t('plan.deletionsBlocked', { n: detail.deletionsBlocked })}
        </p>
      )}

      <OutcomeHistoryPanel rows={outcomeHistory} />

      {/* Ops */}
      <div className="rounded-lg border border-border bg-bg-secondary">
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <h3 className="text-sm font-semibold text-text-primary">
            {t('plan.operations', { n: ops.length })}
          </h3>
          <div className="flex flex-wrap items-center gap-1.5">
            {(Object.keys(counts.byKind) as PlanOpKind[]).map((k) => (
              <span key={k} className="inline-flex items-center gap-1">
                <OpKindChip kind={k} />
                <span className="font-mono text-[11px] text-text-muted">{counts.byKind[k]}</span>
              </span>
            ))}
          </div>

          <div className="ml-auto flex flex-wrap items-center gap-2">
            {culprits.size > 0 && (
              <label className="flex cursor-pointer items-center gap-1.5 rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/10 px-2 py-1 text-[12px] text-status-ssl-expired">
                <input
                  type="checkbox"
                  checked={culpritsOnly}
                  onChange={(e) => setCulpritsOnly(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-border bg-bg-tertiary accent-accent"
                />
                {t('plan.culpritsOnly', { n: culprits.size })}
              </label>
            )}
            <select
              value={minRisk}
              onChange={(e) => setMinRisk(e.target.value as RiskLevel | '')}
              className="rounded-md border border-border bg-bg-tertiary px-2.5 py-1 text-[12px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            >
              <option value="">{t('plan.filters.allRisks')}</option>
              {(['high', 'medium', 'low'] as RiskLevel[]).map((r) => (
                <option key={r} value={r}>
                  {t('plan.filters.atLeast', { risk: t(`plan.risk.${r}`) })}
                </option>
              ))}
            </select>
            <span className="font-mono text-[11px] text-text-muted">
              {t('plan.showing', { shown: shown.length, total: ops.length })}
            </span>
          </div>
        </div>

        {ops.length === 0 ? (
          <div className="py-12 text-center">
            <p className="text-sm text-text-muted">{t('plan.noOps')}</p>
            <p className="mt-1 text-xs text-text-muted">{t('plan.noOpsHint')}</p>
          </div>
        ) : shown.length === 0 ? (
          <div className="py-10 text-center text-sm text-text-muted">{t('plan.noOpsMatch')}</div>
        ) : (
          <ul className="divide-y divide-border">
            {shown.map((op) => (
              <OpRow
                key={op.seq}
                op={op}
                isCulprit={culprits.has(op.seq)}
                focused={focusedOpSeq === op.seq}
              />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

// ── Blast radius ────────────────────────────────────────────────────────────

/**
 * §8.3 and M7 both hang off this block, and the SITE count is deliberately
 * first: the fleet is multi-customer, a site is a customer, and "3 sites" is
 * the sentence that makes an operator pause where "12 objects" does not.
 */
export function BlastRadiusPanel({
  plan,
  disruptiveCount,
  className,
}: {
  plan: ApplyPlan;
  disruptiveCount: number;
  className?: string;
}) {
  const { t } = useTranslation();
  const br = plan.blastRadius;
  return (
    <section className={cn('rounded-lg border border-border bg-bg-secondary p-4', className)}>
      <h3 className="mb-3 text-[11px] font-medium uppercase tracking-wider text-text-muted">
        {t('plan.blastRadius')}
      </h3>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Metric
          icon={<Building2 size={13} />}
          label={t('plan.sites')}
          value={String(br.siteCount)}
          tone={br.siteCount > 1 ? 'warn' : 'muted'}
          hint={t('plan.sitesHint')}
        />
        <Metric
          icon={<RouterIcon size={13} />}
          label={t('plan.devices')}
          value={String(br.deviceCount)}
          tone="muted"
          hint={t('plan.devicesHint')}
        />
        <Metric
          icon={<Cable size={13} />}
          label={t('plan.disruptiveOps')}
          value={String(disruptiveCount)}
          tone={disruptiveCount > 0 ? 'warn' : 'ok'}
          hint={t('plan.disruptiveOpsHint')}
        />
        <Metric
          icon={<ShieldX size={13} />}
          label={t('plan.mgmtPath')}
          value={br.touchesManagementPath ? t('common.yes') : t('common.no')}
          tone={br.touchesManagementPath ? 'bad' : 'ok'}
          hint={t('plan.mgmtPathHint')}
        />
      </div>

      {(br.affectedInterfaces.length > 0 || br.affectedSubnets.length > 0) && (
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <TokenList
            icon={<Network size={12} />}
            label={t('plan.affectedInterfaces')}
            items={br.affectedInterfaces}
          />
          <TokenList
            icon={<Network size={12} />}
            label={t('plan.affectedSubnets')}
            items={br.affectedSubnets}
          />
        </div>
      )}
    </section>
  );
}

const TONES = {
  ok: 'text-status-up',
  warn: 'text-status-ssl-warning',
  bad: 'text-status-ssl-expired',
  muted: 'text-text-primary',
};

function Metric({
  icon,
  label,
  value,
  tone,
  hint,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  tone: keyof typeof TONES;
  hint: string;
}) {
  return (
    <div className="rounded-md border border-border bg-bg-primary/40 p-2.5" title={hint}>
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-text-muted">
        {icon}
        {label}
      </div>
      <div className={cn('mt-1 font-display text-lg font-semibold tabular-nums', TONES[tone])}>
        {value}
      </div>
    </div>
  );
}

function TokenList({
  icon,
  label,
  items,
}: {
  icon: React.ReactNode;
  label: string;
  items: string[];
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const visible = open ? items : items.slice(0, 12);
  if (items.length === 0) return null;
  return (
    <div>
      <div className="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-text-muted">
        {icon}
        {label} <span className="font-mono">({items.length})</span>
      </div>
      <div className="flex flex-wrap gap-1">
        {visible.map((x) => (
          <span
            key={x}
            className="rounded border border-border bg-bg-tertiary px-1.5 py-0.5 font-mono text-[10px] text-text-secondary"
          >
            {x}
          </span>
        ))}
        {items.length > 12 && (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="rounded border border-border px-1.5 py-0.5 text-[10px] text-accent hover:bg-bg-hover"
          >
            {open ? t('common.less') : t('plan.andMore', { n: items.length - 12 })}
          </button>
        )}
      </div>
    </div>
  );
}

// ── §8.3 empirical memory ───────────────────────────────────────────────────

/**
 * "The laboratory we do not have", surfaced BEFORE the apply.
 *
 * Two honesty rules are enforced here and neither is negotiable:
 *  - below `significant`, NO percentage is shown. Three rollbacks out of three
 *    is not a 100 % failure rate, it is three rollbacks, and a percentage over
 *    four observations is a number that means nothing and reads as a fact.
 *  - `lostContact` is displayed as its own column and never folded into
 *    `rolledBack`. On a DEGRADED device that outcome means a van, and averaging
 *    it into a reassuring success rate is exactly what §8.3 forbids.
 *
 * When the corpus is empty the panel says so out loud rather than disappearing:
 * an absent panel reads as "no known problems", which is a claim nobody made.
 */
export function OutcomeHistoryPanel({ rows }: { rows: OutcomeHistoryView[] }) {
  const { t } = useTranslation();
  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary p-3">
        <h3 className="mb-1 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-text-muted">
          <History size={12} />
          {t('plan.history.title')}
        </h3>
        <p className="text-[12px] text-text-muted">{t('plan.history.empty')}</p>
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-3">
      <h3 className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-text-muted">
        <History size={12} />
        {t('plan.history.title')}
      </h3>
      <ul className="space-y-2">
        {rows.map((r, i) => (
          <li key={i} className="rounded-md border border-border bg-bg-primary/40 p-2.5">
            <div className="font-mono text-[11px] text-text-secondary">
              {[r.brand, r.model, r.osVersion].filter(Boolean).join(' · ')} — {r.opKind}
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-3 text-[12px]">
              <span className="text-status-up">
                {t('plan.history.succeeded')} <span className="font-mono">{r.succeeded}</span>
              </span>
              <span className="text-status-ssl-warning">
                {t('plan.history.rolledBack')} <span className="font-mono">{r.rolledBack}</span>
              </span>
              <span className="text-status-ssl-expired">
                {t('plan.history.lostContact')} <span className="font-mono">{r.lostContact}</span>
              </span>
              <span className="text-text-muted">
                {t('plan.history.total')} <span className="font-mono">{r.total}</span>
              </span>
            </div>
            <p className="mt-1 text-[11px] text-text-muted">
              {r.significant
                ? t('plan.history.significant')
                : t('plan.history.insufficient', { n: r.total })}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ── One op ──────────────────────────────────────────────────────────────────

const RISK_STRIPE: Record<RiskLevel, string> = {
  low: 'border-l-status-pending',
  medium: 'border-l-status-ssl-warning',
  high: 'border-l-status-ssl-expired',
};

function OpRow({
  op,
  isCulprit,
  focused,
}: {
  op: PlanOp;
  isCulprit: boolean;
  focused: boolean;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const hasBody = op.before !== null || op.after !== null;

  return (
    <li
      id={`plan-op-${op.seq}`}
      className={cn(
        'border-l-2 px-3 py-2.5 transition-colors',
        RISK_STRIPE[op.risk],
        isCulprit && 'bg-status-ssl-expired/5',
        focused && 'ring-1 ring-inset ring-accent',
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="w-8 shrink-0 font-mono text-[11px] text-text-muted">#{op.seq}</span>
        <OpKindChip kind={op.kind} />
        <span className="rounded border border-border bg-bg-tertiary px-1.5 py-0.5 font-mono text-[10px] text-text-secondary">
          {t(`ncm.kind.${op.resource}`, { defaultValue: op.resource })}
        </span>
        <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-text-primary" title={op.semKey}>
          {op.semKey}
        </span>
        {op.disruptive && <DisruptiveChip />}
        {isCulprit && <CulpritChip />}
        <RiskBadge risk={op.risk} />
        {hasBody && (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="rounded p-0.5 text-text-muted hover:bg-bg-hover hover:text-text-primary"
            aria-label={t('plan.toggleDetail')}
          >
            {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
        )}
      </div>

      {op.reason && <p className="mt-1 pl-10 text-[12px] text-text-secondary">{op.reason}</p>}

      {op.kind === 'blocked' && op.blockedReason && (
        <p className="mt-1 pl-10 text-[11px] text-text-muted">
          {t(`plan.blockedReason.${op.blockedReason}`, { defaultValue: op.blockedReason })}
        </p>
      )}

      {op.kind === 'move' && (
        <p className="mt-1 pl-10 font-mono text-[11px] text-text-muted">
          {t('plan.moveTarget', { chain: op.chain ?? '—', index: op.targetIndex ?? '—' })}
        </p>
      )}

      {op.fields.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-1 pl-10">
          {op.fields.map((f) => (
            <span key={f} className="rounded bg-bg-tertiary px-1.5 py-0.5 font-mono text-[10px] text-text-muted">
              {f}
            </span>
          ))}
        </div>
      )}

      {open && hasBody && (
        <div className="mt-2 grid gap-2 pl-10 sm:grid-cols-2">
          <ValuePane label={t('plan.before')} value={op.before} />
          <ValuePane label={t('plan.after')} value={op.after} />
        </div>
      )}
    </li>
  );
}

/**
 * §8.2's last checkpoint before pixels.
 *
 * On a `scanValueForSecrets` hit we do NOT render the value — not partially,
 * not masked character by character, because a masked secret still leaks its
 * length and its shape. We name the KEY that tripped and tell the operator to
 * report it: the server is supposed to have redacted this, and a hit here is a
 * server bug that must not be quietly papered over by the UI.
 */
function ValuePane({ label, value }: { label: string; value: unknown }) {
  const { t } = useTranslation();
  const hits = useMemo(() => scanValueForSecrets(value), [value]);
  const body = useMemo(() => {
    if (value === null || value === undefined) return null;
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }, [value]);

  return (
    <div className="rounded-md border border-border bg-bg-primary/40">
      <div className="border-b border-border px-2 py-1 text-[10px] uppercase tracking-wider text-text-muted">
        {label}
      </div>
      {hits.length > 0 ? (
        <div className="p-2 text-[11px] text-status-ssl-expired">
          <div className="font-medium">{t('plan.secretSuspected')}</div>
          <div className="mt-1 font-mono">{hits.join(', ')}</div>
          <div className="mt-1 text-text-muted">{t('plan.secretSuspectedHint')}</div>
        </div>
      ) : body === null ? (
        <div className="p-2 text-[11px] text-text-muted">{t('plan.absent')}</div>
      ) : (
        <pre className="max-h-64 overflow-auto p-2 font-mono text-[11px] leading-relaxed text-text-secondary">
          {body}
        </pre>
      )}
    </div>
  );
}

function formatWhen(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}
