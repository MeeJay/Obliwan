import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { HelpCircle, ShieldOff, Play, ShieldQuestion } from 'lucide-react';
import { cn } from '@/utils/cn';
import { Button } from '@/components/common/Button';
import { useChangeStore } from '@/store/changeStore';
import { errorMessageOf, isRouteAbsent } from '@/api/change.api';

/**
 * The kill switch — the button somebody looks for in a panic.
 *
 * ┌─ WHY IT IS NOT IN THE SETTINGS PAGE ─────────────────────────────────────┐
 * │ §4.2 lists the global kill-switch under SettingsPage, and that is where  │
 * │ its CONFIGURATION belongs. The GESTURE does not. A control reached in a  │
 * │ panic must be one gesture from the screen where the panic happens, and   │
 * │ the screen where an operator watches a change go wrong is ChangesPage.   │
 * │ So the trigger lives in the header of the changes screen, permanently    │
 * │ visible, red, and it never scrolls away.                                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── ONE CLICK TO OPEN, ONE CLICK TO STOP — AND A REASON ─────────────────────
 * The dialog asks for a sentence and nothing else. Engaging is DESTRUCTIVE OF
 * NOTHING: it refuses writes, it does not touch a router. So it is deliberately
 * cheap to engage and deliberately explicit to release — the asymmetry runs the
 * safe way. The reason is required because "somebody stopped the world at
 * 02:14" without a why is an incident that takes an hour longer, and because
 * the sentence is shown on every job the switch subsequently refuses.
 *
 * ── FAIL-CLOSED, VISIBLY ────────────────────────────────────────────────────
 * When the state cannot be read the store reports `blocked: true, known: false`
 * and this component says "state unknown — treated as engaged". It does not
 * say "engaged", because an operator who reads "engaged" goes looking for the
 * colleague who engaged it.
 */

/**
 * KNOWN-ENGAGED, NOT JUST BLOCKED.
 *
 * The store blocks writes both when the switch IS engaged and when its state
 * could not be read. Those two must not offer the same action: on an unread
 * state the switch may well be disengaged, and offering "Resume" would let an
 * operator release something nobody engaged — or, worse, believe he released a
 * switch that is still on. So the control offers ENGAGE whenever we do not
 * positively know the switch is engaged. Engaging is the safe direction and it
 * is the one that must never be unavailable in a panic.
 */
function knownEngaged(k: { blocked: boolean; known: boolean }): boolean {
  return k.known && k.blocked;
}

export function KillSwitchButton({ className }: { className?: string }) {
  const { t } = useTranslation();
  const killSwitch = useChangeStore((s) => s.killSwitch);
  const [open, setOpen] = useState(false);
  const engaged = knownEngaged(killSwitch);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={cn(
          'inline-flex items-center gap-2 rounded-md border px-3 py-2 text-sm font-semibold transition-colors',
          engaged
            ? 'border-status-ssl-expired bg-status-ssl-expired/15 text-status-ssl-expired hover:bg-status-ssl-expired/25'
            : 'border-status-ssl-expired/60 text-status-ssl-expired hover:bg-status-ssl-expired/10',
          className,
        )}
        title={t('change.killSwitch.buttonHint')}
      >
        {engaged ? <Play size={16} /> : <ShieldOff size={16} />}
        {engaged ? t('change.killSwitch.release') : t('change.killSwitch.engage')}
      </button>
      {open && <KillSwitchDialog onClose={() => setOpen(false)} />}
    </>
  );
}

/** The banner. Rendered at the top of every screen that can start a write, so
 *  no page can offer an Apply button without saying why it is inert. */
export function KillSwitchBanner({ className }: { className?: string }) {
  const { t } = useTranslation();
  const killSwitch = useChangeStore((s) => s.killSwitch);
  if (!killSwitch.blocked) return null;

  const unknown = !killSwitch.known;
  return (
    <div
      className={cn(
        'flex flex-wrap items-start gap-3 rounded-lg border p-4',
        unknown
          ? 'border-status-down/50 bg-status-down/10'
          : 'border-status-ssl-expired/60 bg-status-ssl-expired/10',
        className,
      )}
      role="alert"
    >
      {unknown ? (
        <ShieldQuestion size={18} className="mt-0.5 shrink-0 text-status-down" />
      ) : (
        <ShieldOff size={18} className="mt-0.5 shrink-0 text-status-ssl-expired" />
      )}
      <div className="min-w-[16rem] flex-1">
        <h3
          className={cn(
            'text-sm font-semibold',
            unknown ? 'text-status-down' : 'text-status-ssl-expired',
          )}
        >
          {unknown ? t('change.killSwitch.unknownTitle') : t('change.killSwitch.engagedTitle')}
        </h3>
        <p className="mt-0.5 text-[13px] text-text-secondary">
          {unknown
            ? t('change.killSwitch.unknownBody')
            : t('change.killSwitch.engagedBody', {
                scope: t(`change.killSwitch.scope.${killSwitch.by ?? 'global'}`),
              })}
        </p>
        {killSwitch.reason && (
          <p className="mt-1.5 rounded border border-border bg-bg-primary/40 p-2 text-[12px] text-text-primary">
            {killSwitch.reason}
          </p>
        )}
        {(killSwitch.engagedByName || killSwitch.engagedAt) && (
          <p className="mt-1 font-mono text-[11px] text-text-muted">
            {[killSwitch.engagedByName, killSwitch.engagedAt
              ? new Date(killSwitch.engagedAt).toLocaleString()
              : null]
              .filter(Boolean)
              .join(' · ')}
          </p>
        )}
      </div>
    </div>
  );
}

function KillSwitchDialog({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const killSwitch = useChangeStore((s) => s.killSwitch);
  const setKillSwitch = useChangeStore((s) => s.setKillSwitch);
  const loading = useChangeStore((s) => s.killSwitchLoading);

  // Engaging is offered whenever the switch is not KNOWN to be engaged — see
  // knownEngaged() above. The panic direction is never the unavailable one.
  const engaging = !knownEngaged(killSwitch);
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const submit = async () => {
    const trimmed = reason.trim();
    if (trimmed.length === 0) {
      setError(t('change.killSwitch.reasonRequired'));
      return;
    }
    try {
      await setKillSwitch(engaging, trimmed);
      toast.success(
        engaging ? t('change.killSwitch.engagedToast') : t('change.killSwitch.releasedToast'),
      );
      onClose();
    } catch (err) {
      if (isRouteAbsent(err)) {
        setError(t('change.killSwitch.unavailable'));
        return;
      }
      setError(errorMessageOf(err) ?? t('change.killSwitch.failed'));
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-lg rounded-xl border border-border bg-bg-secondary shadow-2xl">
        <div
          className={cn(
            'flex items-center gap-2 rounded-t-xl border-b px-5 py-4',
            engaging
              ? 'border-status-ssl-expired/40 bg-status-ssl-expired/10'
              : 'border-border',
          )}
        >
          {engaging ? (
            <ShieldOff size={18} className="text-status-ssl-expired" />
          ) : (
            <Play size={18} className="text-text-secondary" />
          )}
          <h2 className="text-base font-semibold text-text-primary">
            {engaging ? t('change.killSwitch.engageTitle') : t('change.killSwitch.releaseTitle')}
          </h2>
        </div>

        <div className="space-y-3 p-5">
          <p className="text-[13px] text-text-secondary">
            {engaging ? t('change.killSwitch.engageBody') : t('change.killSwitch.releaseBody')}
          </p>

          {!killSwitch.known && (
            <p className="rounded-md border border-status-down/50 bg-status-down/10 p-2.5 text-[12px] text-status-down">
              {t('change.killSwitch.unknownBody')}
            </p>
          )}

          {!engaging && (
            <div className="flex items-start gap-2 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/10 p-2.5">
              <HelpCircle size={14} className="mt-0.5 shrink-0 text-status-ssl-warning" />
              <p className="text-[12px] text-status-ssl-warning">
                {t('change.killSwitch.releaseWarning')}
              </p>
            </div>
          )}

          <div>
            <label className="mb-1 block text-[12px] font-medium text-text-secondary">
              {engaging
                ? t('change.killSwitch.reasonLabel')
                : t('change.killSwitch.releaseReasonLabel')}
            </label>
            <textarea
              autoFocus
              rows={3}
              value={reason}
              onChange={(e) => { setReason(e.target.value); setError(null); }}
              placeholder={t('change.killSwitch.reasonPlaceholder')}
              className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
            />
            <p className="mt-1 text-[11px] text-text-muted">
              {t('change.killSwitch.reasonHint')}
            </p>
          </div>

          {error && (
            <p className="rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-2 text-[12px] text-status-ssl-expired">
              {error}
            </p>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
          <Button variant="ghost" size="sm" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button
            variant={engaging ? 'danger' : 'primary'}
            size="sm"
            loading={loading}
            onClick={() => void submit()}
          >
            {engaging ? t('change.killSwitch.engageConfirm') : t('change.killSwitch.releaseConfirm')}
          </Button>
        </div>
      </div>
    </div>
  );
}
