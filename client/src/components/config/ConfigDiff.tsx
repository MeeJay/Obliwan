import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ArrowDownUp,
  ChevronDown,
  ChevronRight,
  Eye,
  EyeOff,
  Info,
  MoveVertical,
  ShieldAlert,
  Sparkles,
} from 'lucide-react';
import { DIFF_SEVERITIES, SEVERITY_RANK, type DiffKind, type DiffSeverity } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import { scanValueForSecrets } from '@/utils/secretScan';
import type { SemanticChange, SemanticChangeSet } from '@/types/config';

/**
 * The SEMANTIC diff panel — the left half of §4.2's drift screen, and the
 * comparison panel of ConfigPage.
 *
 * ── THIS COMPONENT IS WHERE THE MILESTONE IS WON OR LOST ────────────────────
 * R3 is a UI requirement as much as an engine one: a screen that dumps 200
 * findings in a flat list has failed even when every finding is correct,
 * because nobody reads the 201st. Four things are therefore structural here and
 * not options:
 *
 *  1. SORTED BY SEVERITY BY DEFAULT, descending, always. The first screenful is
 *     the worst news. Changing the sort is one click; it is never the default.
 *  2. IGNORING IS ONE CLICK AND TAKES EFFECT IMMEDIATELY. The row leaves the
 *     list on the same frame the operator clicks, and persistence happens
 *     behind it. Triage that costs a round trip per finding is triage nobody
 *     does.
 *  3. AN INERT MOVE IS ONE AGGREGATED LINE. §4.4 forbids emitting it as a
 *     finding at all; this component shows the COUNT, so that the decision
 *     stays visible instead of becoming a silent hole. Forty reordered rules
 *     that change no forwarding are one line, never forty.
 *  4. ONE ROW PER RESOURCE, N FIELD DIFFS INSIDE. Never one row per field: that
 *     single choice divides the count by three to five on wide resources.
 *
 * ── ONE COMPONENT, TWO SOURCES ──────────────────────────────────────────────
 * It renders a `SemanticChangeSet`, whatever produced it: the server drift
 * engine (`origin: 'server'`, real severities, persistent ignores) or the
 * browser-side snapshot comparison (`origin: 'local'`, everything `info`, no
 * ignore persistence). The difference is stated in the header rather than
 * hidden, because a local comparison has no normalisation rules behind it and
 * must not be read as a drift verdict.
 */

export interface ConfigDiffProps {
  set: SemanticChangeSet;
  selectedId?: string | null;
  onSelect?: (change: SemanticChange) => void;
  /** Absent = the ignore control is not rendered at all (missing capability,
   *  or a local comparison where there is nothing to ignore). */
  onToggleIgnore?: (change: SemanticChange, ignored: boolean) => void;
  /** Shown under the header when an ignore could not be persisted. */
  notice?: string | null;
  beforeLabel?: string;
  afterLabel?: string;
  className?: string;
}

type SortMode = 'severity' | 'resource' | 'key';

const SEVERITY_TONE: Record<DiffSeverity, string> = {
  critical: 'text-status-ssl-expired border-status-ssl-expired/50 bg-status-ssl-expired/10',
  high: 'text-status-down border-status-down/50 bg-status-down/10',
  medium: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  low: 'text-status-pending border-status-pending/50 bg-status-pending/10',
  info: 'text-text-muted border-border bg-bg-tertiary',
};

const KIND_TONE: Record<DiffKind, string> = {
  missing: 'text-status-down border-status-down/50 bg-status-down/10',
  extra: 'text-status-up border-status-up/50 bg-status-up/10',
  changed: 'text-accent border-accent/50 bg-accent/10',
  moved: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
};

const KIND_ICON: Record<DiffKind, React.ReactNode> = {
  missing: <span className="font-mono text-[11px]">−</span>,
  extra: <span className="font-mono text-[11px]">+</span>,
  changed: <span className="font-mono text-[11px]">~</span>,
  moved: <MoveVertical size={10} />,
};

function valueText(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'string') return v === '' ? '""' : v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  try { return JSON.stringify(v); } catch { return String(v); }
}

export function ConfigDiff({
  set,
  selectedId,
  onSelect,
  onToggleIgnore,
  notice,
  beforeLabel,
  afterLabel,
  className,
}: ConfigDiffProps) {
  const { t } = useTranslation();
  const [sort, setSort] = useState<SortMode>('severity');
  const [severityFilter, setSeverityFilter] = useState<Set<DiffSeverity>>(new Set());
  const [kindFilter, setKindFilter] = useState<Set<DiffKind>>(new Set());
  const [showIgnored, setShowIgnored] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const counts = useMemo(() => {
    const bySeverity = { info: 0, low: 0, medium: 0, high: 0, critical: 0 } as Record<DiffSeverity, number>;
    const byKind = { missing: 0, extra: 0, changed: 0, moved: 0 } as Record<DiffKind, number>;
    let ignored = 0;
    for (const c of set.changes) {
      if (c.ignored) { ignored++; continue; }
      bySeverity[c.severity]++;
      byKind[c.kind]++;
    }
    return { bySeverity, byKind, ignored };
  }, [set.changes]);

  const visible = useMemo(() => {
    const rows = set.changes.filter((c) => {
      // Ignored rows only appear when the operator asks for them; and when he
      // does, he sees ONLY them, so "what did I silence" stays answerable
      // months later. An ignored finding is hidden, never deleted.
      if (showIgnored ? !c.ignored : c.ignored) return false;
      if (severityFilter.size > 0 && !severityFilter.has(c.severity)) return false;
      if (kindFilter.size > 0 && !kindFilter.has(c.kind)) return false;
      return true;
    });
    const sorted = [...rows];
    sorted.sort((a, b) => {
      if (sort === 'severity') {
        const d = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
        if (d !== 0) return d;
        return a.resource.localeCompare(b.resource) || a.semKey.localeCompare(b.semKey);
      }
      if (sort === 'resource') {
        return a.resource.localeCompare(b.resource)
          || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
          || a.semKey.localeCompare(b.semKey);
      }
      return a.semKey.localeCompare(b.semKey);
    });
    return sorted;
  }, [set.changes, severityFilter, kindFilter, showIgnored, sort]);

  const toggleSeverity = (s: DiffSeverity) => {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s); else next.add(s);
      return next;
    });
  };

  const toggleKind = (k: DiffKind) => {
    setKindFilter((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k); else next.add(k);
      return next;
    });
  };

  const toggleExpanded = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const activeCount = set.changes.filter((c) => !c.ignored).length;

  return (
    <div className={cn('rounded-lg border border-border bg-bg-secondary', className)}>
      {/* Header */}
      <div className="border-b border-border px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-sm font-semibold text-text-primary">{t('config.diff.title')}</h3>
          <span className="font-mono text-[11px] text-text-muted">
            {t('config.diff.count', { count: activeCount })}
          </span>
          {set.origin === 'local' && (
            <span
              className="rounded border border-border bg-bg-tertiary px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-text-muted"
              title={t('config.diff.localHint')}
            >
              {t('config.diff.local')}
            </span>
          )}
          <div className="ml-auto flex items-center gap-1.5">
            <ArrowDownUp size={12} className="text-text-muted" />
            <select
              value={sort}
              onChange={(e) => setSort(e.target.value as SortMode)}
              className="rounded-md border border-border bg-bg-tertiary px-2 py-1 text-[12px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            >
              <option value="severity">{t('config.diff.sort.severity')}</option>
              <option value="resource">{t('config.diff.sort.resource')}</option>
              <option value="key">{t('config.diff.sort.key')}</option>
            </select>
          </div>
        </div>

        {/* Severity chips — the primary triage control, always visible. */}
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          {[...DIFF_SEVERITIES].reverse().map((s) => (
            <button
              key={s}
              onClick={() => toggleSeverity(s)}
              disabled={counts.bySeverity[s] === 0 && !severityFilter.has(s)}
              className={cn(
                'rounded border px-1.5 py-0.5 text-[11px] transition-colors disabled:opacity-30',
                SEVERITY_TONE[s],
                severityFilter.has(s) && 'ring-1 ring-accent',
              )}
            >
              {t(`ncm.severity.${s}`)} {counts.bySeverity[s]}
            </button>
          ))}
          <span className="mx-1 h-4 w-px bg-border" />
          {(['missing', 'extra', 'changed', 'moved'] as DiffKind[]).map((k) => (
            <button
              key={k}
              onClick={() => toggleKind(k)}
              disabled={counts.byKind[k] === 0 && !kindFilter.has(k)}
              className={cn(
                'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] transition-colors disabled:opacity-30',
                KIND_TONE[k],
                kindFilter.has(k) && 'ring-1 ring-accent',
              )}
            >
              {KIND_ICON[k]} {t(`ncm.diffKind.${k}`)} {counts.byKind[k]}
            </button>
          ))}
          {/* `|| showIgnored` matters: un-ignoring the last row while looking
              at the ignored list must not remove the only way back. */}
          {(counts.ignored > 0 || showIgnored) && (
            <button
              onClick={() => setShowIgnored((v) => !v)}
              className={cn(
                'ml-auto inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-[11px] text-text-muted hover:text-text-primary',
                showIgnored && 'ring-1 ring-accent',
              )}
            >
              {showIgnored ? <Eye size={11} /> : <EyeOff size={11} />}
              {t('config.diff.ignoredCount', { count: counts.ignored })}
            </button>
          )}
        </div>
      </div>

      {notice && (
        <div className="border-b border-status-ssl-warning/40 bg-status-ssl-warning/5 px-3 py-2 text-[12px] text-status-ssl-warning">
          {notice}
        </div>
      )}

      {/* The anti-noise lines. These are counters, never rows. */}
      {(set.inertMoveCount > 0 || set.outOfScopeCount > 0 || set.suppressed.length > 0) && (
        <div className="space-y-1 border-b border-border bg-bg-primary/30 px-3 py-2">
          {set.inertMoveCount > 0 && (
            <p className="flex items-start gap-1.5 text-[12px] text-text-muted">
              <MoveVertical size={12} className="mt-0.5 shrink-0" />
              {t('config.diff.inertMoves', { count: set.inertMoveCount })}
            </p>
          )}
          {set.outOfScopeCount > 0 && (
            <p className="flex items-start gap-1.5 text-[12px] text-text-muted">
              <Info size={12} className="mt-0.5 shrink-0" />
              {t('config.diff.outOfScope', { count: set.outOfScopeCount })}
            </p>
          )}
          {set.suppressed.map((s, i) => (
            <p
              key={`${s.resource}-${s.reason}-${i}`}
              className="flex items-start gap-1.5 text-[12px] text-status-ssl-warning"
            >
              <ShieldAlert size={12} className="mt-0.5 shrink-0" />
              {t('config.diff.suppressed', {
                resource: t(`ncm.kind.${s.resource}`),
                reason: t(`ncm.suppression.${s.reason}`),
              })}
            </p>
          ))}
        </div>
      )}

      {/* Rows */}
      {visible.length === 0 ? (
        <div className="px-3 py-10 text-center">
          <p className="text-sm text-text-muted">
            {set.changes.length === 0 ? t('config.diff.none') : t('config.diff.noMatch')}
          </p>
          {set.changes.length === 0 && (
            <p className="mt-1 text-xs text-text-muted">{t('config.diff.noneHint')}</p>
          )}
        </div>
      ) : (
        <ul className="divide-y divide-border">
          {visible.map((c) => (
            <ChangeRow
              key={c.id}
              change={c}
              expanded={expanded.has(c.id)}
              selected={selectedId === c.id}
              beforeLabel={beforeLabel}
              afterLabel={afterLabel}
              onToggle={() => toggleExpanded(c.id)}
              onSelect={onSelect}
              onToggleIgnore={onToggleIgnore}
            />
          ))}
        </ul>
      )}
    </div>
  );
}

// ── one row ─────────────────────────────────────────────────────────────────

interface ChangeRowProps {
  change: SemanticChange;
  expanded: boolean;
  selected: boolean;
  beforeLabel?: string;
  afterLabel?: string;
  onToggle: () => void;
  onSelect?: (c: SemanticChange) => void;
  onToggleIgnore?: (c: SemanticChange, ignored: boolean) => void;
}

function ChangeRow({
  change,
  expanded,
  selected,
  beforeLabel,
  afterLabel,
  onToggle,
  onSelect,
  onToggleIgnore,
}: ChangeRowProps) {
  const { t } = useTranslation();
  const secretPaths = useMemo(
    () => new Set(scanValueForSecrets({ before: change.beforeValue, after: change.afterValue }, 6)),
    [change.beforeValue, change.afterValue],
  );

  return (
    <li className={cn(selected && 'bg-accent/5', change.ignored && 'opacity-60')}>
      <div className="flex items-center gap-2 px-3 py-1.5">
        <button
          onClick={() => { onToggle(); onSelect?.(change); }}
          className="flex min-w-0 flex-1 items-center gap-2 text-left"
        >
          {expanded ? <ChevronDown size={12} className="shrink-0 text-text-muted" />
                    : <ChevronRight size={12} className="shrink-0 text-text-muted" />}
          <span className={cn('shrink-0 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider', SEVERITY_TONE[change.severity])}>
            {t(`ncm.severity.${change.severity}`)}
          </span>
          <span className={cn('inline-flex shrink-0 items-center gap-1 rounded border px-1.5 py-0.5 text-[10px]', KIND_TONE[change.kind])}>
            {KIND_ICON[change.kind]} {t(`ncm.diffKind.${change.kind}`)}
          </span>
          <span className="truncate font-mono text-[11px] text-text-secondary" title={change.semKey}>
            {change.semKey}
          </span>
          {change.fieldDiffs.length > 0 && (
            <span className="shrink-0 font-mono text-[10px] text-text-muted">
              {t('config.diff.fields', { count: change.fieldDiffs.length })}
            </span>
          )}
          {change.kind === 'moved' && change.crossed.length > 0 && (
            <span className="shrink-0 font-mono text-[10px] text-status-ssl-warning">
              {t('config.diff.crossed', { count: change.crossed.length })}
            </span>
          )}
          {change.matchMethod === 'fuzzy' && (
            <span
              className="inline-flex shrink-0 items-center gap-1 rounded border border-status-ssl-warning/40 bg-status-ssl-warning/10 px-1.5 py-0.5 text-[10px] text-status-ssl-warning"
              title={t('config.diff.fuzzyHint')}
            >
              <Sparkles size={9} />
              {Math.round(change.matchConfidence * 100)}%
            </span>
          )}
        </button>

        {onToggleIgnore && (
          <button
            onClick={() => onToggleIgnore(change, !change.ignored)}
            title={change.ignored ? t('config.diff.unignore') : t('config.diff.ignore')}
            className="shrink-0 rounded p-1 text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            {change.ignored ? <Eye size={13} /> : <EyeOff size={13} />}
          </button>
        )}
      </div>

      {expanded && (
        <div className="border-t border-border/40 bg-bg-primary/20 px-3 py-2">
          <p className="mb-1.5 font-mono text-[10px] text-text-muted">{change.path}</p>

          {change.kind === 'moved' ? (
            <div className="text-[12px] text-text-secondary">
              <p className="mb-1">{t('config.diff.movedExplain')}</p>
              <ul className="space-y-0.5">
                {change.crossed.map((k) => (
                  <li key={k} className="font-mono text-[11px] text-text-muted">{k}</li>
                ))}
              </ul>
            </div>
          ) : change.fieldDiffs.length > 0 ? (
            <table className="w-full table-fixed text-[12px]">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wider text-text-muted">
                  <th className="w-1/4 pb-1">{t('config.diff.field')}</th>
                  <th className="w-[37.5%] pb-1">{beforeLabel ?? t('config.diff.intent')}</th>
                  <th className="w-[37.5%] pb-1">{afterLabel ?? t('config.diff.actual')}</th>
                </tr>
              </thead>
              <tbody>
                {change.fieldDiffs.map((fd, i) => (
                  <tr key={`${fd.field}-${i}`} className="align-top">
                    <td className="py-0.5 pr-2 font-mono text-[11px] text-text-muted">{fd.field}</td>
                    <td className="break-all py-0.5 pr-2 font-mono text-[11px] text-status-down">
                      {valueText(fd.intent)}
                    </td>
                    <td className="break-all py-0.5 font-mono text-[11px] text-status-up">
                      {valueText(fd.actual)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <ValuePreview
              value={change.kind === 'missing' ? change.beforeValue : change.afterValue}
              withheld={secretPaths.size > 0}
            />
          )}

          <p className="mt-1.5 text-[10px] text-text-muted">
            {t('config.diff.pairedBy', { method: t(`ncm.matchMethod.${change.matchMethod}`) })}
            {change.predicateChanged ? ` · ${t('config.diff.predicateChanged')}` : ''}
          </p>
        </div>
      )}
    </li>
  );
}

function ValuePreview({ value, withheld }: { value: unknown; withheld: boolean }) {
  const { t } = useTranslation();
  if (withheld) {
    return (
      <p className="inline-flex items-center gap-1 rounded bg-status-ssl-expired/15 px-1.5 py-0.5 text-[11px] text-status-ssl-expired">
        <ShieldAlert size={10} />
        {t('config.diff.valueWithheld')}
      </p>
    );
  }
  if (value === null || value === undefined) {
    return <p className="text-[12px] text-text-muted">—</p>;
  }
  const obj = typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!obj) return <p className="font-mono text-[11px] text-text-primary">{valueText(value)}</p>;
  return (
    <dl className="grid grid-cols-[9rem_1fr] gap-x-3 text-[11px]">
      {Object.entries(obj).map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-mono text-text-muted">{k}</dt>
          <dd className="break-all font-mono text-text-primary">{valueText(v)}</dd>
        </div>
      ))}
    </dl>
  );
}
