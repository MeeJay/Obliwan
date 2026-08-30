import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import {
  HelpCircle,
  ScrollText,
  ShieldQuestion,
  UserCheck,
  UserSearch,
  Users,
} from 'lucide-react';
import { anonIp, anonUsername } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import { namesAnIndividual } from '@/types/logs';
import type { AttributionCandidate, AttributionState, AttributionView } from '@/types/logs';

/**
 * The attribution banner (K6) — who touched this router, or the honest refusal
 * to say.
 *
 * ┌─ THE FOUR STATES ARE FOUR DIFFERENT SENTENCES, NOT FOUR SHADES ──────────┐
 * │ ATTRIBUTED    a name, with the session that proves it. Green.            │
 * │ SHARED        an ACCOUNT, and an explicit "this account is shared, so    │
 * │               this does not identify a person". Amber. §5/M8 asks for    │
 * │               "comptes partagés marqués" — this is that marking, and it  │
 * │               is a first-class state rather than an asterisk on a name.  │
 * │ AMBIGUOUS     several sessions fit. Every candidate is listed and NONE   │
 * │               is promoted. There is no "most likely" line, because the   │
 * │               moment one exists somebody quotes it in a ticket.          │
 * │ UNATTRIBUTED  no session fits the window. Said in words, permanently.    │
 * │               NOT a spinner, NOT an error, NOT an empty cell.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * And a fifth rendering that is NOT one of the four: `available: false` means
 * the attribution service is not served by this build. "We did not look" and
 * "we looked and found nobody" are different facts and this banner never
 * conflates them — the first one is not a statement about the change at all.
 *
 * ── WHY NAMES GO THROUGH `anonUsername` ─────────────────────────────────────
 * The demo/anonymised mode is a product feature of this suite, and an
 * attribution banner is exactly the widget that would leak a real customer's
 * engineer name into a screenshot. Same treatment as every other identity in
 * this client.
 */

const TONE: Record<AttributionState, string> = {
  attributed: 'border-status-up/40 bg-status-up/5',
  shared: 'border-status-ssl-warning/40 bg-status-ssl-warning/5',
  ambiguous: 'border-status-ssl-warning/40 bg-status-ssl-warning/5',
  unattributed: 'border-border bg-bg-secondary',
};

const ICON: Record<AttributionState, React.ReactNode> = {
  attributed: <UserCheck size={15} className="text-status-up" />,
  shared: <Users size={15} className="text-status-ssl-warning" />,
  ambiguous: <ShieldQuestion size={15} className="text-status-ssl-warning" />,
  unattributed: <UserSearch size={15} className="text-text-muted" />,
};

export function AttributionBanner({
  attribution,
  deviceId,
  className,
}: {
  attribution: AttributionView;
  /** Used for the "open the logs for this box" link — the natural next click
   *  when the verdict is `unattributed` or `ambiguous`. */
  deviceId?: number | null;
  className?: string;
}) {
  const { t, i18n } = useTranslation();
  const fmt = new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'medium' });
  const when = (iso: string | null) => {
    if (!iso) return '—';
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? '—' : fmt.format(d);
  };

  // The fifth rendering. Not a state of the change — a state of the server.
  if (!attribution.available) {
    return (
      <section
        className={cn(
          'flex items-start gap-2 rounded-lg border border-dashed border-border bg-bg-secondary/60 px-4 py-3',
          className,
        )}
      >
        <HelpCircle size={15} className="mt-0.5 shrink-0 text-text-muted" />
        <div>
          <p className="text-[13px] text-text-secondary">{t('attribution.unavailable')}</p>
          <p className="mt-0.5 text-[12px] text-text-muted">{t('attribution.unavailableHint')}</p>
        </div>
      </section>
    );
  }

  const { state, identity, candidates } = attribution;
  // THE predicate for "may this widget print a person's name". It is asked
  // once, here, and every other branch of this component renders an ACCOUNT or
  // renders nothing. Re-deriving it per branch is how `shared` eventually gets
  // rendered like `attributed` by somebody adding a case.
  const mayNameAPerson = namesAnIndividual(attribution);

  return (
    <section className={cn('rounded-lg border px-4 py-3', TONE[state], className)}>
      <div className="flex flex-wrap items-start gap-2">
        <span className="mt-0.5 shrink-0">{ICON[state]}</span>
        <div className="min-w-[16rem] flex-1">
          <p className="text-[13px] font-semibold text-text-primary">
            {t(`attribution.title.${state}`)}
          </p>

          {mayNameAPerson && identity && (
            <p className="mt-0.5 text-[13px] text-text-secondary">
              <span className="font-mono text-text-primary">{anonUsername(identity.username)}</span>
              {identity.sourceIp && (
                <>
                  {' · '}
                  <span className="font-mono">{anonIp(identity.sourceIp)}</span>
                </>
              )}
              {identity.via && <> · {identity.via}</>}
            </p>
          )}

          {state === 'shared' && identity && (
            <>
              <p className="mt-0.5 text-[13px] text-text-secondary">
                <span className="font-mono text-text-primary">{anonUsername(identity.username)}</span>
                {identity.sourceIp && (
                  <>
                    {' · '}
                    <span className="font-mono">{anonIp(identity.sourceIp)}</span>
                  </>
                )}
              </p>
              {/* The sentence §5/M8 requires, spelled out and not left to a colour. */}
              <p className="mt-1 rounded border border-status-ssl-warning/40 bg-status-ssl-warning/10 px-2 py-1 text-[12px] text-status-ssl-warning">
                {t('attribution.sharedWarning')}
              </p>
            </>
          )}

          {state === 'ambiguous' && (
            <p className="mt-0.5 text-[12px] text-text-secondary">
              {t('attribution.ambiguousHint', { count: candidates.length })}
            </p>
          )}

          {state === 'unattributed' && (
            <p className="mt-0.5 text-[12px] text-text-secondary">
              {t('attribution.unattributedHint')}
            </p>
          )}

          {attribution.rationale && (
            <p className="mt-1 text-[12px] text-text-muted">{attribution.rationale}</p>
          )}

          <p className="mt-1 font-mono text-[11px] text-text-muted">
            {t('attribution.window', {
              start: when(attribution.windowStart),
              end: when(attribution.windowEnd),
            })}
          </p>
        </div>

        {deviceId !== null && deviceId !== undefined && (
          <Link
            to={`/logs?deviceId=${deviceId}`}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[12px] text-text-secondary hover:bg-bg-hover hover:text-text-primary"
          >
            <ScrollText size={13} />
            {t('attribution.openLogs')}
          </Link>
        )}
      </div>

      {/* Candidates. Rendered for every state that has any — including
          `attributed`, so the operator can see WHAT was rejected and judge the
          match rather than trust it. */}
      {candidates.length > 0 && (
        <ul className="mt-2 space-y-1 border-t border-border/60 pt-2">
          {candidates.map((c, i) => (
            <CandidateLine key={`${c.eventId ?? 'na'}-${i}`} candidate={c} when={when} />
          ))}
        </ul>
      )}
    </section>
  );
}

function CandidateLine({
  candidate,
  when,
}: {
  candidate: AttributionCandidate;
  when: (iso: string | null) => string;
}) {
  const { t } = useTranslation();
  return (
    <li className="flex flex-wrap items-center gap-2 text-[12px]">
      <span className="font-mono text-text-primary">{anonUsername(candidate.username)}</span>
      {candidate.sharedAccount && (
        <span className="rounded border border-status-ssl-warning/50 bg-status-ssl-warning/10 px-1 py-px text-[9px] uppercase tracking-wider text-status-ssl-warning">
          {t('attribution.sharedChip')}
        </span>
      )}
      {candidate.sourceIp && (
        <span className="font-mono text-text-muted">{anonIp(candidate.sourceIp)}</span>
      )}
      <span className="text-text-muted">
        {when(candidate.loggedInAt)} → {when(candidate.loggedOutAt)}
      </span>
      {/* The score is shown raw, to two decimals, and never as a percentage
          with a bar: a bar reads as a confidence the engine does not have. */}
      <span className="ml-auto font-mono text-[11px] text-text-muted">
        {t('attribution.score', { score: candidate.score.toFixed(2) })}
      </span>
    </li>
  );
}
