import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowLeft, ArrowRight, AlertOctagon, ShieldX, Siren } from 'lucide-react';
import { cn } from '@/utils/cn';
import { Button } from '@/components/common/Button';
import { GuardVerdictBadge, guardBadgeState } from '@/components/plan/RiskBadge';
import { SafetyNetPanel } from './SafetyNetBadge';
import type { CompiledPlan, SafetyNetLevel } from '@/types/change';

/**
 * Overriding the Management-Path Guard.
 *
 * ┌─ THE ONE UI RULE OF THIS MILESTONE ──────────────────────────────────────┐
 * │ THIS BUTTON IS NOT NEXT TO "APPLY".                                      │
 * │                                                                          │
 * │ Bypassing an anti-lockout protection must not be reachable by a          │
 * │ mis-aimed click. The launch dialog contains no override control at all;  │
 * │ this screen is opened from a separate, differently-styled block further  │
 * │ down the page, and it is three steps deep before anything can be sent.   │
 * │                                                                          │
 * │ Everything below is friction on purpose. Friction is the product here.   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── THE THREE STEPS ─────────────────────────────────────────────────────────
 *  1. READ. Every guard reason is listed in full — its code, its sentence, the
 *     offending record and the plan line that produced it. Not a summary: the
 *     operator must see exactly what he is deciding to ignore.
 *  2. WRITE. A mandatory, non-blank reason, with a real minimum length. This is
 *     `change_jobs.override_reason` and it is a CHECK constraint server-side
 *     (migration 009 refuses a whitespace-only reason and demands
 *     `overridden_by` + `overridden_at`). The database names a human; this
 *     screen is where the human is told that it will.
 *  3. TYPE. The device hostname, exactly. The cheapest gesture that cannot be
 *     performed by reflex.
 *
 * ── ON `INDETERMINATE` ──────────────────────────────────────────────────────
 * This screen makes no distinction of PRIVILEGE between REJECT and
 * INDETERMINATE — both require all three steps. It makes a distinction of
 * WORDING, because they are different mistakes: on REJECT you are overriding a
 * proof, on INDETERMINATE you are overriding an admission that the model has a
 * hole in it, and the hole is exactly where the rule that cuts you lives.
 */

/** Long enough that "ok" and "asap" do not pass; short enough that a real
 *  sentence ("CHR migration, tunnel moves to l2tp-mgmt2, validated with the
 *  customer") clears it in one breath. */
export const MIN_OVERRIDE_REASON = 20;

export interface OverrideSubmit {
  overrideReason: string;
  degradedConfirmed: boolean;
}

interface OverrideDialogProps {
  compiled: CompiledPlan;
  deviceName: string;
  safetyNet: SafetyNetLevel;
  peerName: string | null;
  /** The signed-in operator, shown back at them: the override is attributed. */
  operatorName: string;
  submitting: boolean;
  onSubmit: (req: OverrideSubmit) => void;
  onClose: () => void;
}

export function OverrideDialog({
  compiled,
  deviceName,
  safetyNet,
  peerName,
  operatorName,
  submitting,
  onSubmit,
  onClose,
}: OverrideDialogProps) {
  const { t } = useTranslation();
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [reason, setReason] = useState('');
  const [typed, setTyped] = useState('');

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !submitting) onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, submitting]);

  const state = guardBadgeState(compiled.guard);
  const degraded = safetyNet === 'DEGRADED';
  const reasonOk = reason.trim().length >= MIN_OVERRIDE_REASON;
  const nameMatches = typed.trim() === deviceName.trim() && deviceName.trim().length > 0;

  const proofs = useMemo(
    () => compiled.guard.reasons.filter((r) => r.effect === 'reject'),
    [compiled.guard.reasons],
  );
  const blind = useMemo(
    () => compiled.guard.reasons.filter((r) => r.effect === 'indeterminate'),
    [compiled.guard.reasons],
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4">
      <div className="my-8 w-full max-w-2xl rounded-xl border border-status-ssl-expired/60 bg-bg-secondary shadow-2xl">
        {/* Header — red, and it says the word. */}
        <div className="flex items-start gap-3 rounded-t-xl border-b border-status-ssl-expired/40 bg-status-ssl-expired/10 px-5 py-4">
          <Siren size={20} className="mt-0.5 shrink-0 text-status-ssl-expired" />
          <div className="flex-1">
            <h2 className="text-base font-semibold text-status-ssl-expired">
              {t('change.override.title')}
            </h2>
            <p className="mt-0.5 text-[12px] text-text-secondary">
              {t('change.override.subtitle', { name: deviceName })}
            </p>
          </div>
          <StepDots step={step} />
        </div>

        {/* ── Step 1 — READ ────────────────────────────────────────────── */}
        {step === 1 && (
          <div className="space-y-4 p-5">
            <div className="flex flex-wrap items-center gap-3">
              <GuardVerdictBadge state={state} size="lg" />
              <p className="min-w-[14rem] flex-1 text-[13px] text-text-primary">
                {t(`change.override.whatYouOverride.${state}`)}
              </p>
            </div>

            <p className="rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-3 text-[13px] font-medium text-status-ssl-expired">
              {t('change.override.consequence')}
            </p>

            {proofs.length > 0 && (
              <ReasonList
                title={t('change.override.proofsTitle')}
                hint={t('change.override.proofsHint')}
                reasons={proofs}
                tone="proof"
              />
            )}
            {blind.length > 0 && (
              <ReasonList
                title={t('change.override.blindTitle')}
                hint={t('change.override.blindHint')}
                reasons={blind}
                tone="blind"
              />
            )}
            {proofs.length === 0 && blind.length === 0 && (
              <div className="rounded-md border border-status-down/50 bg-status-down/10 p-3 text-[13px] text-status-down">
                {t('change.override.noReasons')}
              </div>
            )}

            {/* The net is repeated HERE, because the two questions are one:
                what did the guard refuse, and what repairs the box when the
                refusal turns out to have been right. */}
            <SafetyNetPanel level={safetyNet} peerName={peerName} />
          </div>
        )}

        {/* ── Step 2 — WRITE ───────────────────────────────────────────── */}
        {step === 2 && (
          <div className="space-y-4 p-5">
            <p className="text-[13px] text-text-secondary">
              {t('change.override.reasonIntro')}
            </p>
            <div>
              <label className="mb-1 block text-[12px] font-medium text-text-secondary">
                {t('change.override.reasonLabel')}
              </label>
              <textarea
                autoFocus
                rows={4}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder={t('change.override.reasonPlaceholder')}
                className={cn(
                  'w-full rounded-md border bg-bg-tertiary px-3 py-2 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1',
                  reasonOk
                    ? 'border-border focus:ring-accent'
                    : 'border-status-ssl-expired/60 focus:ring-status-ssl-expired',
                )}
              />
              <div className="mt-1 flex items-center justify-between text-[11px]">
                <span className="text-text-muted">{t('change.override.reasonHint')}</span>
                <span
                  className={cn(
                    'font-mono',
                    reasonOk ? 'text-status-up' : 'text-status-ssl-expired',
                  )}
                >
                  {reason.trim().length} / {MIN_OVERRIDE_REASON}
                </span>
              </div>
            </div>

            <div className="rounded-md border border-border bg-bg-primary/40 p-3 text-[12px]">
              <div className="text-text-muted">{t('change.override.attribution')}</div>
              <div className="mt-1 font-mono text-text-primary">{operatorName}</div>
              <p className="mt-1.5 text-[11px] text-text-muted">
                {t('change.override.attributionHint')}
              </p>
            </div>
          </div>
        )}

        {/* ── Step 3 — TYPE ────────────────────────────────────────────── */}
        {step === 3 && (
          <div className="space-y-4 p-5">
            <div className="rounded-lg border border-status-ssl-expired/60 bg-status-ssl-expired/10 p-4">
              <h3 className="flex items-center gap-1.5 text-sm font-semibold text-status-ssl-expired">
                <AlertOctagon size={15} />
                {t('change.override.finalTitle')}
              </h3>
              <ul className="mt-2 list-inside list-disc space-y-1 text-[13px] text-text-primary">
                <li>{t(`change.override.finalBullet.${state}`)}</li>
                <li>{t(`change.override.finalNet.${safetyNet}`)}</li>
                <li>{t('change.override.finalAudit')}</li>
              </ul>
            </div>

            <div className="rounded-md border border-border bg-bg-primary/40 p-3">
              <div className="text-[10px] uppercase tracking-wider text-text-muted">
                {t('change.override.yourReason')}
              </div>
              <p className="mt-1 whitespace-pre-wrap text-[13px] text-text-primary">
                {reason.trim()}
              </p>
            </div>

            <div>
              <label className="mb-1 block text-[12px] font-medium text-text-secondary">
                {t('change.override.typeDeviceName', { name: deviceName })}
              </label>
              <input
                type="text"
                autoFocus
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder={deviceName}
                className={cn(
                  'w-full rounded-md border bg-bg-tertiary px-3 py-2 font-mono text-[13px] text-text-primary focus:outline-none focus:ring-1',
                  nameMatches
                    ? 'border-status-up/60 focus:ring-status-up'
                    : 'border-status-ssl-expired/60 focus:ring-status-ssl-expired',
                )}
              />
              {degraded && (
                <p className="mt-2 text-[12px] font-medium text-status-ssl-expired">
                  {t('change.override.degradedAlso')}
                </p>
              )}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-5 py-3">
          <Button variant="ghost" size="sm" onClick={onClose} disabled={submitting}>
            {t('change.override.abandon')}
          </Button>

          <div className="flex gap-2">
            {step > 1 && (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setStep((s) => (s === 3 ? 2 : 1))}
                disabled={submitting}
              >
                <ArrowLeft size={14} className="mr-1.5" />
                {t('common.back')}
              </Button>
            )}
            {step < 3 ? (
              <Button
                variant="secondary"
                size="sm"
                disabled={step === 2 && !reasonOk}
                onClick={() => setStep((s) => (s === 1 ? 2 : 3))}
              >
                {t('change.override.next')}
                <ArrowRight size={14} className="ml-1.5" />
              </Button>
            ) : (
              <Button
                variant="danger"
                size="sm"
                loading={submitting}
                disabled={!reasonOk || !nameMatches || submitting}
                onClick={() =>
                  onSubmit({
                    overrideReason: reason.trim(),
                    // On a DEGRADED box the override carries the §8.3
                    // confirmation too: the typed hostname is the same gesture
                    // and it would be dishonest to make the operator perform it
                    // twice, but the FLAG is still sent explicitly so the
                    // server records both facts separately.
                    degradedConfirmed: degraded,
                  })
                }
              >
                <ShieldX size={14} className="mr-1.5" />
                {t('change.override.confirm')}
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function StepDots({ step }: { step: 1 | 2 | 3 }) {
  return (
    <div className="flex items-center gap-1.5 pt-1">
      {[1, 2, 3].map((i) => (
        <span
          key={i}
          className={cn(
            'h-1.5 w-6 rounded-full',
            i <= step ? 'bg-status-ssl-expired' : 'bg-border',
          )}
        />
      ))}
    </div>
  );
}

function ReasonList({
  title,
  hint,
  reasons,
  tone,
}: {
  title: string;
  hint: string;
  reasons: CompiledPlan['guard']['reasons'];
  tone: 'proof' | 'blind';
}) {
  const { t } = useTranslation();
  return (
    <div>
      <h3
        className={cn(
          'mb-1 text-[11px] font-medium uppercase tracking-wider',
          tone === 'proof' ? 'text-status-ssl-expired' : 'text-status-down',
        )}
      >
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
            <span className="rounded border border-border bg-bg-tertiary px-1.5 py-0.5 font-mono text-[10px] text-text-secondary">
              {r.code}
            </span>
            <p className="mt-1.5 text-[13px] text-text-primary">{r.message}</p>
            {r.culprit && (
              <div className="mt-1.5 rounded border border-border/70 bg-bg-primary/40 p-2 font-mono text-[11px] text-text-secondary break-all">
                {r.culprit.describe}
                {r.culprit.opSeq !== null && (
                  <span className="ml-2 text-accent">
                    {t('plan.guard.fromOp', {
                      seq: r.culprit.opSeq,
                      kind: r.culprit.opKind ?? '?',
                    })}
                  </span>
                )}
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
