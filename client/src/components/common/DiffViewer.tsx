import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Columns2, Copy, Rows3, ShieldAlert } from 'lucide-react';
import { cn } from '@/utils/cn';
import {
  DEFAULT_MAX_LINES,
  diffLines,
  parseUnifiedPatch,
  type DiffHunk,
  type DiffLine,
  type DiffResult,
} from '@/utils/textDiff';
import { scanTextForSecrets } from '@/utils/secretScan';

/**
 * The ONE text-diff component (spec §8.1: "trois diffs, un seul moteur, un seul
 * composant `DiffViewer`").
 *
 * The three consumers are a configuration snapshot against another, the textual
 * patch attached to a drift finding, and — later — an export bundle against the
 * current instance, which is the import plan. So this component knows NOTHING
 * about the NCM, about drift, or about snapshots. Its entire vocabulary is two
 * strings, or one unified patch. Every prop below would make as much sense for
 * the import plan as it does for a router config, and that is the test any
 * future addition to this file has to pass.
 *
 * ── SECRETS (§8.2) ──────────────────────────────────────────────────────────
 * Redaction is the server's guarantee. This component nevertheless scans every
 * line it is about to paint, and on a hit it replaces the LINE — it does not
 * mask the value, because a masked secret still leaks its length and its shape
 * — and raises a banner naming the field so the operator can report it. A
 * false positive costs one unreadable line; a miss costs a customer's VPN.
 */

export type DiffViewerMode = 'unified' | 'split';

export interface DiffViewerProps {
  /** Left / "before" text. Ignored when `patch` is given. */
  left?: string;
  /** Right / "after" text. Ignored when `patch` is given. */
  right?: string;
  /** A ready-made unified patch, rendered instead of computing one. */
  patch?: string;
  leftLabel?: string;
  rightLabel?: string;
  defaultMode?: DiffViewerMode;
  /** Hides the mode / whitespace controls for embedded, read-only uses. */
  toolbar?: boolean;
  context?: number;
  maxLines?: number;
  /** Shown when the two sides are identical. */
  identicalLabel?: string;
  className?: string;
  /** Cap on the rendered height; the body scrolls inside it. */
  bodyClassName?: string;
}

interface ScannedLine extends DiffLine {
  /** Non-null when the secret scan tripped: the KEY name, never the value. */
  secretLabel: string | null;
}

interface ScannedHunk extends Omit<DiffHunk, 'lines'> {
  lines: ScannedLine[];
}

function scanHunks(hunks: DiffHunk[]): { hunks: ScannedHunk[]; labels: string[] } {
  const labels = new Set<string>();
  const out = hunks.map((h) => ({
    ...h,
    lines: h.lines.map((l) => {
      // Context lines are scanned too: a secret sitting unchanged in both
      // snapshots is still a secret we are about to put on a screen.
      const hit = l.text.length > 0 ? scanTextForSecrets(l.text, 1)[0] : undefined;
      if (hit) labels.add(hit.label);
      return { ...l, secretLabel: hit ? hit.label : null };
    }),
  }));
  return { hunks: out, labels: [...labels] };
}

const LINE_BG: Record<DiffLine['type'], string> = {
  add: 'bg-status-up/10',
  del: 'bg-status-down/10',
  context: '',
};

const MARKER: Record<DiffLine['type'], string> = { add: '+', del: '-', context: ' ' };

const MARKER_COLOR: Record<DiffLine['type'], string> = {
  add: 'text-status-up',
  del: 'text-status-down',
  context: 'text-text-muted',
};

export function DiffViewer({
  left = '',
  right = '',
  patch,
  leftLabel,
  rightLabel,
  defaultMode = 'unified',
  toolbar = true,
  context = 3,
  maxLines = DEFAULT_MAX_LINES,
  identicalLabel,
  className,
  bodyClassName,
}: DiffViewerProps) {
  const { t } = useTranslation();
  const [mode, setMode] = useState<DiffViewerMode>(defaultMode);
  const [ignoreWhitespace, setIgnoreWhitespace] = useState(false);
  const [copied, setCopied] = useState(false);

  const result: DiffResult = useMemo(() => {
    if (typeof patch === 'string') return parseUnifiedPatch(patch, maxLines);
    return diffLines(left, right, {
      context,
      maxLines,
      transform: ignoreWhitespace ? (l) => l.trim().replace(/\s+/g, ' ') : undefined,
    });
  }, [patch, left, right, context, maxLines, ignoreWhitespace]);

  const { hunks, labels } = useMemo(() => scanHunks(result.hunks), [result]);

  const copy = () => {
    const text = hunks
      .flatMap((h) => h.lines.map((l) => `${MARKER[l.type]}${l.secretLabel ? '' : l.text}`))
      .join('\n');
    void navigator.clipboard?.writeText(text).then(
      () => { setCopied(true); window.setTimeout(() => setCopied(false), 1500); },
      () => undefined,
    );
  };

  return (
    <div className={cn('rounded-lg border border-border bg-bg-secondary', className)}>
      {toolbar && (
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
          <span className="font-mono text-[11px] text-text-muted">
            {leftLabel ?? t('diff.left')} → {rightLabel ?? t('diff.right')}
          </span>
          <span className="font-mono text-[11px] text-status-up">+{result.added}</span>
          <span className="font-mono text-[11px] text-status-down">−{result.removed}</span>

          <div className="ml-auto flex items-center gap-1">
            {typeof patch !== 'string' && (
              <label
                className="mr-1 flex cursor-pointer items-center gap-1.5 text-[12px] text-text-secondary"
                title={t('diff.ignoreWhitespaceHint')}
              >
                <input
                  type="checkbox"
                  checked={ignoreWhitespace}
                  onChange={(e) => setIgnoreWhitespace(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-border bg-bg-tertiary accent-accent"
                />
                {t('diff.ignoreWhitespace')}
              </label>
            )}
            <button
              onClick={() => setMode('unified')}
              title={t('diff.unified')}
              className={cn(
                'rounded p-1.5',
                mode === 'unified'
                  ? 'bg-bg-active text-text-primary'
                  : 'text-text-muted hover:bg-bg-hover hover:text-text-primary',
              )}
            >
              <Rows3 size={14} />
            </button>
            <button
              onClick={() => setMode('split')}
              title={t('diff.split')}
              className={cn(
                'rounded p-1.5',
                mode === 'split'
                  ? 'bg-bg-active text-text-primary'
                  : 'text-text-muted hover:bg-bg-hover hover:text-text-primary',
              )}
            >
              <Columns2 size={14} />
            </button>
            <button
              onClick={copy}
              title={t('diff.copy')}
              className="rounded p-1.5 text-text-muted hover:bg-bg-hover hover:text-text-primary"
            >
              <Copy size={14} />
            </button>
            {copied && <span className="text-[11px] text-text-muted">{t('diff.copied')}</span>}
          </div>
        </div>
      )}

      {labels.length > 0 && (
        <div className="flex items-start gap-2 border-b border-status-ssl-expired/40 bg-status-ssl-expired/5 px-3 py-2 text-[12px] text-status-ssl-expired">
          <ShieldAlert size={14} className="mt-0.5 shrink-0" />
          <span>
            {t('diff.secretDetected', { fields: labels.join(', ') })}
          </span>
        </div>
      )}

      {result.degraded && (
        <div className="flex items-start gap-2 border-b border-status-ssl-warning/40 bg-status-ssl-warning/5 px-3 py-2 text-[12px] text-status-ssl-warning">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" />
          <span>{t('diff.degraded')}</span>
        </div>
      )}

      {result.identical ? (
        <div className="px-3 py-10 text-center text-sm text-text-muted">
          {identicalLabel ?? t('diff.identical')}
        </div>
      ) : hunks.length === 0 ? (
        <div className="px-3 py-10 text-center text-sm text-text-muted">{t('diff.empty')}</div>
      ) : (
        <div className={cn('overflow-auto', bodyClassName ?? 'max-h-[60vh]')}>
          {mode === 'unified'
            ? <UnifiedBody hunks={hunks} />
            : <SplitBody hunks={hunks} leftLabel={leftLabel} rightLabel={rightLabel} />}
        </div>
      )}

      {result.truncated && (
        <div className="border-t border-border px-3 py-2 text-[11px] text-text-muted">
          {t('diff.truncated', { count: maxLines })}
        </div>
      )}
    </div>
  );
}

// ── bodies ──────────────────────────────────────────────────────────────────

function SecretCell({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded bg-status-ssl-expired/15 px-1.5 py-0.5 text-[11px] font-medium text-status-ssl-expired">
      <ShieldAlert size={10} />
      {label}
    </span>
  );
}

function Gap({ count }: { count: number }) {
  const { t } = useTranslation();
  return (
    <div className="bg-bg-tertiary/60 px-3 py-1 font-mono text-[10px] text-text-muted">
      {t('diff.skipped', { count })}
    </div>
  );
}

function UnifiedBody({ hunks }: { hunks: ScannedHunk[] }) {
  return (
    <div className="min-w-max font-mono text-[12px] leading-[1.55]">
      {hunks.map((h, hi) => (
        <div key={`${h.leftStart}-${h.rightStart}-${hi}`}>
          {h.skippedBefore > 0 && <Gap count={h.skippedBefore} />}
          {h.lines.map((l, li) => (
            <div key={li} className={cn('flex', LINE_BG[l.type])}>
              <span className="w-12 shrink-0 select-none border-r border-border/60 px-2 text-right text-text-muted">
                {l.leftNo ?? ''}
              </span>
              <span className="w-12 shrink-0 select-none border-r border-border/60 px-2 text-right text-text-muted">
                {l.rightNo ?? ''}
              </span>
              <span className={cn('w-4 shrink-0 select-none pl-1.5', MARKER_COLOR[l.type])}>
                {MARKER[l.type]}
              </span>
              <span className="whitespace-pre px-1 text-text-primary">
                {l.secretLabel ? <SecretCell label={l.secretLabel} /> : l.text || ' '}
              </span>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

/**
 * Side-by-side. Deletions and additions of one run are zipped onto the same
 * rows, which is what makes a one-word change readable; when the runs are
 * uneven the shorter side gets empty rows rather than being padded with
 * repeated content.
 */
function SplitBody({
  hunks,
  leftLabel,
  rightLabel,
}: {
  hunks: ScannedHunk[];
  leftLabel?: string;
  rightLabel?: string;
}) {
  const { t } = useTranslation();
  return (
    <div className="min-w-max font-mono text-[12px] leading-[1.55]">
      <div className="sticky top-0 z-10 flex border-b border-border bg-bg-secondary text-[11px] text-text-muted">
        <span className="w-1/2 px-3 py-1">{leftLabel ?? t('diff.left')}</span>
        <span className="w-1/2 border-l border-border px-3 py-1">{rightLabel ?? t('diff.right')}</span>
      </div>
      {hunks.map((h, hi) => (
        <div key={`${h.leftStart}-${h.rightStart}-${hi}`}>
          {h.skippedBefore > 0 && <Gap count={h.skippedBefore} />}
          {zip(h.lines).map((pair, i) => (
            <div key={i} className="flex">
              <SplitCell line={pair[0]} side="left" />
              <SplitCell line={pair[1]} side="right" />
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

function SplitCell({ line, side }: { line: ScannedLine | null; side: 'left' | 'right' }) {
  return (
    <div
      className={cn(
        'flex w-1/2 min-w-[16rem]',
        side === 'right' && 'border-l border-border',
        line ? LINE_BG[line.type] : 'bg-bg-tertiary/30',
      )}
    >
      <span className="w-12 shrink-0 select-none border-r border-border/60 px-2 text-right text-text-muted">
        {line ? (side === 'left' ? line.leftNo : line.rightNo) ?? '' : ''}
      </span>
      <span className="whitespace-pre px-2 text-text-primary">
        {!line
          ? ' '
          : line.secretLabel
            ? <SecretCell label={line.secretLabel} />
            : line.text || ' '}
      </span>
    </div>
  );
}

/** Pairs a run of deletions with the run of additions that follows it. */
function zip(lines: ScannedLine[]): [ScannedLine | null, ScannedLine | null][] {
  const out: [ScannedLine | null, ScannedLine | null][] = [];
  let i = 0;
  while (i < lines.length) {
    const l = lines[i];
    if (l.type === 'context') {
      out.push([l, l]);
      i++;
      continue;
    }
    const dels: ScannedLine[] = [];
    const adds: ScannedLine[] = [];
    while (i < lines.length && lines[i].type === 'del') dels.push(lines[i++]);
    while (i < lines.length && lines[i].type === 'add') adds.push(lines[i++]);
    if (dels.length === 0 && adds.length === 0) { i++; continue; }
    const n = Math.max(dels.length, adds.length);
    for (let k = 0; k < n; k++) out.push([dels[k] ?? null, adds[k] ?? null]);
  }
  return out;
}
