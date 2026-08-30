import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Check,
  ChevronDown,
  ChevronRight,
  CircleDashed,
  Loader2,
  MinusCircle,
  X,
} from 'lucide-react';
import type { ChangeStepKind, ChangeStepStatus } from '@obliwan/shared';
import { CHANGE_STEP_KINDS } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import { scanTextForSecrets } from '@/utils/secretScan';
import type { ChangeJobStepView } from '@/types/change';

/**
 * The live step timeline of a change job.
 *
 * ── WHY THE EXPECTED STEPS ARE DRAWN BEFORE THEY HAPPEN ─────────────────────
 * A timeline that only shows what already happened cannot answer "what is it
 * about to do to my router". This one renders the whole `CHANGE_STEP_KINDS`
 * spine greyed out and lights each entry as its row arrives, so `arm_deadman`
 * is visible as a step that WILL happen before `apply` does — and so its
 * ABSENCE from a finished job is visible too. `bind_assert` (R4) and `guard`
 * (K2) are on that spine for exactly that reason: they are steps precisely so
 * that a job which skipped them is readable as having skipped them.
 *
 * ── `skipped` IS NOT MISSING ────────────────────────────────────────────────
 * `CHANGE_STEP_STATUSES` has an explicit `skipped`, and this renderer shows it
 * as a distinct state with its own icon. "We did not arm a dead-man" must be a
 * recorded fact on the screen, never an absent row the eye slides over.
 *
 * ── RETRIES DO NOT OVERWRITE ────────────────────────────────────────────────
 * Steps are keyed by (attempt, seq). A retry writes a SECOND trace rather than
 * replacing the failed one, and the timeline groups by attempt so the failed
 * first pass stays readable. That is the post-mortem, and losing it to a
 * cosmetic de-duplication is how "why did it retry" becomes unanswerable.
 *
 * ── §8.2 ────────────────────────────────────────────────────────────────────
 * `outputRedacted` arrives masked from the driver. It is scanned again here,
 * and on a hit the pane refuses to draw the output at all and names the key
 * that tripped. A masked secret still leaks its length; a suppressed one does
 * not.
 */

const STATUS_ICON: Record<ChangeStepStatus, React.ReactNode> = {
  pending: <CircleDashed size={13} />,
  running: <Loader2 size={13} className="animate-spin" />,
  succeeded: <Check size={13} />,
  failed: <X size={13} />,
  skipped: <MinusCircle size={13} />,
};

const STATUS_TONE: Record<ChangeStepStatus, string> = {
  pending: 'text-text-muted border-border bg-bg-tertiary',
  running: 'text-accent border-accent/50 bg-accent/10',
  succeeded: 'text-status-up border-status-up/40 bg-status-up/10',
  failed: 'text-status-ssl-expired border-status-ssl-expired/50 bg-status-ssl-expired/10',
  skipped: 'text-text-muted border-border bg-bg-tertiary',
};

/** The steps whose presence or absence is a SAFETY fact, not a progress fact.
 *  They are labelled on the spine even when no row exists for them yet. */
const SAFETY_STEPS: ReadonlySet<ChangeStepKind> = new Set<ChangeStepKind>([
  'bind_assert', 'guard', 'preflight_backup', 'arm_deadman', 'disarm', 'rollback',
]);

interface TimelineProps {
  steps: ChangeJobStepView[];
  /** Draw the not-yet-reached steps of the spine. Off for terminal jobs, where
   *  a greyed-out `disarm` that will never run reads as a pending action. */
  showExpected?: boolean;
  className?: string;
}

export function JobTimeline({ steps, showExpected = true, className }: TimelineProps) {
  const { t } = useTranslation();

  const attempts = useMemo(() => {
    const byAttempt = new Map<number, ChangeJobStepView[]>();
    for (const s of steps) {
      const list = byAttempt.get(s.attempt) ?? [];
      list.push(s);
      byAttempt.set(s.attempt, list);
    }
    for (const list of byAttempt.values()) list.sort((a, b) => a.seq - b.seq);
    return [...byAttempt.entries()].sort((a, b) => a[0] - b[0]);
  }, [steps]);

  const latestAttempt = attempts.length > 0 ? attempts[attempts.length - 1][0] : 1;
  const seenKinds = useMemo(
    () => new Set(steps.filter((s) => s.attempt === latestAttempt).map((s) => s.kind)),
    [steps, latestAttempt],
  );
  const expected = useMemo(
    () => CHANGE_STEP_KINDS.filter((k) => !seenKinds.has(k)),
    [seenKinds],
  );

  if (steps.length === 0 && !showExpected) {
    return (
      <div className={cn('rounded-lg border border-border bg-bg-secondary py-10 text-center', className)}>
        <p className="text-sm text-text-muted">{t('change.timeline.empty')}</p>
      </div>
    );
  }

  return (
    <div className={cn('space-y-4', className)}>
      {attempts.map(([attempt, list]) => (
        <div key={attempt}>
          {attempts.length > 1 && (
            <div className="mb-2 flex items-center gap-2">
              <span className="rounded border border-border bg-bg-tertiary px-1.5 py-0.5 font-mono text-[10px] text-text-secondary">
                {t('change.timeline.attempt', { n: attempt })}
              </span>
              {attempt < latestAttempt && (
                <span className="text-[11px] text-text-muted">
                  {t('change.timeline.attemptKept')}
                </span>
              )}
              <div className="h-px flex-1 bg-border" />
            </div>
          )}
          <ol className="space-y-1.5">
            {list.map((step) => (
              <StepRow key={`${step.attempt}-${step.seq}-${step.id}`} step={step} />
            ))}
          </ol>
        </div>
      ))}

      {showExpected && expected.length > 0 && (
        <div>
          <div className="mb-2 flex items-center gap-2">
            <span className="text-[10px] uppercase tracking-wider text-text-muted">
              {t('change.timeline.expected')}
            </span>
            <div className="h-px flex-1 bg-border" />
          </div>
          <ol className="space-y-1">
            {expected.map((kind) => (
              <li
                key={kind}
                className="flex items-center gap-2.5 rounded-md border border-dashed border-border px-3 py-1.5 opacity-50"
              >
                <span className="rounded border border-border bg-bg-tertiary p-1 text-text-muted">
                  <CircleDashed size={13} />
                </span>
                <span className="text-[13px] text-text-muted">
                  {t(`change.step.${kind}`)}
                </span>
                {SAFETY_STEPS.has(kind) && (
                  <span className="ml-auto rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-text-muted">
                    {t('change.timeline.safetyStep')}
                  </span>
                )}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}

function StepRow({ step }: { step: ChangeJobStepView }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(step.status === 'failed');
  const hasOutput = Boolean(step.outputRedacted || step.errorRedacted);

  return (
    <li
      className={cn(
        'rounded-md border px-3 py-2',
        step.status === 'failed'
          ? 'border-status-ssl-expired/40 bg-status-ssl-expired/5'
          : step.status === 'running'
            ? 'border-accent/40 bg-accent/5'
            : 'border-border bg-bg-secondary',
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className={cn('rounded border p-1', STATUS_TONE[step.status])}>
          {STATUS_ICON[step.status]}
        </span>
        <span className="w-7 shrink-0 font-mono text-[11px] text-text-muted">#{step.seq}</span>
        <span className="text-[13px] font-medium text-text-primary">
          {t(`change.step.${step.kind}`, { defaultValue: step.kind })}
        </span>
        {SAFETY_STEPS.has(step.kind) && (
          <span
            className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-accent"
            title={t('change.timeline.safetyStepHint')}
          >
            {t('change.timeline.safetyStep')}
          </span>
        )}
        {step.planOpSeq !== null && (
          <a
            href={`#plan-op-${step.planOpSeq}`}
            className="rounded border border-border bg-bg-tertiary px-1.5 py-0.5 font-mono text-[10px] text-accent hover:bg-bg-hover"
          >
            {t('change.timeline.planOp', { seq: step.planOpSeq })}
          </a>
        )}
        <span
          className={cn(
            'rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
            step.status === 'skipped' ? 'border border-border text-text-muted' : 'text-text-muted',
          )}
        >
          {t(`change.stepStatus.${step.status}`)}
        </span>

        <span className="ml-auto flex items-center gap-3 font-mono text-[11px] text-text-muted">
          {step.durationMs !== null && <span>{formatMs(step.durationMs)}</span>}
          {step.startedAt && <span>{new Date(step.startedAt).toLocaleTimeString()}</span>}
          {hasOutput && (
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              className="rounded p-0.5 text-text-muted hover:bg-bg-hover hover:text-text-primary"
              aria-label={t('change.timeline.toggleOutput')}
            >
              {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
          )}
        </span>
      </div>

      {step.status === 'skipped' && (
        <p className="mt-1 pl-9 text-[11px] text-text-muted">{t('change.timeline.skippedNote')}</p>
      )}

      {open && hasOutput && (
        <div className="mt-2 space-y-2 pl-9">
          {step.errorRedacted && (
            <OutputPane label={t('change.timeline.error')} text={step.errorRedacted} tone="error" />
          )}
          {step.outputRedacted && (
            <OutputPane label={t('change.timeline.output')} text={step.outputRedacted} tone="normal" />
          )}
        </div>
      )}
    </li>
  );
}

function OutputPane({
  label,
  text,
  tone,
}: {
  label: string;
  text: string;
  tone: 'normal' | 'error';
}) {
  const { t } = useTranslation();
  const hits = useMemo(() => scanTextForSecrets(text), [text]);
  return (
    <div
      className={cn(
        'rounded-md border',
        tone === 'error' ? 'border-status-ssl-expired/40' : 'border-border',
      )}
    >
      <div className="flex items-center justify-between border-b border-border px-2 py-1">
        <span className="text-[10px] uppercase tracking-wider text-text-muted">{label}</span>
        <span className="text-[10px] text-text-muted">{t('change.timeline.redactedBySource')}</span>
      </div>
      {hits.length > 0 ? (
        <div className="p-2 text-[11px] text-status-ssl-expired">
          <div className="font-medium">{t('change.timeline.secretSuspected')}</div>
          <div className="mt-1 font-mono">
            {hits.map((h) => `${h.label}@${h.line + 1}`).join(', ')}
          </div>
          <div className="mt-1 text-text-muted">{t('change.timeline.secretSuspectedHint')}</div>
        </div>
      ) : (
        <pre
          className={cn(
            'max-h-72 overflow-auto whitespace-pre-wrap break-all p-2 font-mono text-[11px] leading-relaxed',
            tone === 'error' ? 'text-status-ssl-expired' : 'text-text-secondary',
          )}
        >
          {text}
        </pre>
      )}
    </div>
  );
}

function formatMs(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.floor(ms / 60_000)} m ${Math.round((ms % 60_000) / 1000)} s`;
}
