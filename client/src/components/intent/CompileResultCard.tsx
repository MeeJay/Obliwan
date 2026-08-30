import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  AlertCircle,
  CircleSlash,
  ShieldAlert,
  AlertTriangle,
} from 'lucide-react';
import { cn } from '@/utils/cn';
import { scanTextForSecrets } from '@/utils/secretScan';
import type { BrandCompileResult, CapabilityGap, CompileStatus } from '@/types/intent';
import { BRAND_LABELS, CAPABILITY_FLAG_LABEL_KEYS } from '@/types/intent';

/**
 * One brand's answer to "does this intent compile?" — killer K4's payload.
 *
 * ┌─ THE MESSAGE IS THE FEATURE ─────────────────────────────────────────────┐
 * │ §1.2/K4 sells this: "la connaissance constructeur quitte la tête du      │
 * │ senior pour entrer dans le produit". That transfer happens in exactly    │
 * │ one place — the refusal sentence. A red cross labelled "unsupported"     │
 * │ transfers nothing and sends the technician back to the senior, which is  │
 * │ the cost the feature exists to delete.                                   │
 * │                                                                          │
 * │ So every gap prints, in this order:                                      │
 * │   • the BRAND (and the family/model when the gap is narrower),           │
 * │   • the CAPABILITY, by its name in the `DeviceCapabilities` contract     │
 * │     plus a plain sentence for what that capability is,                   │
 * │   • the PART OF THE INTENT that needed it.                               │
 * │                                                                          │
 * │ `gapSentence()` below composes that from the flag alone when the server  │
 * │ sends no prose, so the message can degrade in richness but never to      │
 * │ nothing.                                                                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `partial` is a status of its own and is never rounded up to `ok`: an intent
 * that compiles except for its failover leg is a site that will not fail over,
 * and the operator has to see that before he schedules the change, not after.
 */

const STATUS_STYLES: Record<CompileStatus, { chip: string; icon: JSX.Element }> = {
  ok: {
    chip: 'border-status-up/50 bg-status-up/10 text-status-up',
    icon: <CheckCircle2 size={13} />,
  },
  partial: {
    chip: 'border-status-ssl-warning/50 bg-status-ssl-warning/10 text-status-ssl-warning',
    icon: <AlertTriangle size={13} />,
  },
  unsupported: {
    chip: 'border-border bg-bg-tertiary text-text-muted',
    icon: <CircleSlash size={13} />,
  },
  error: {
    chip: 'border-status-ssl-expired/60 bg-status-ssl-expired/15 text-status-ssl-expired',
    icon: <AlertCircle size={13} />,
  },
};

export function CompileResultCard({ result }: { result: BrandCompileResult }) {
  const { t } = useTranslation();
  const [showArtifact, setShowArtifact] = useState(false);

  const style = STATUS_STYLES[result.status];

  return (
    <section className="rounded-lg border border-border bg-bg-secondary">
      <header className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
        <span className="text-[14px] font-semibold text-text-primary">
          {BRAND_LABELS[result.brand]}
        </span>
        {result.family && (
          <span className="font-mono text-[10px] text-text-muted">{result.family}</span>
        )}
        <span
          className={cn(
            'ml-auto inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
            style.chip,
          )}
        >
          {style.icon}
          {t(`intent.status.${result.status}`)}
        </span>
      </header>

      <div className="px-3 py-2">
        <p className="text-[11px] text-text-muted">
          {t('intent.deviceCount', { count: result.deviceCount })}
          {result.artifact ? ` · ${t('intent.opCount', { count: result.artifact.opCount })}` : ''}
        </p>

        {result.notice && (
          <p className="mt-1.5 rounded-md border border-border bg-bg-tertiary px-2 py-1.5 text-[11px] text-text-muted">
            {result.notice}
          </p>
        )}

        {/* ── The refusal. Never empty, never a bare cross. ── */}
        {result.gaps.length > 0 && (
          <ul className="mt-2 space-y-1.5">
            {result.gaps.map((gap, i) => (
              <GapRow key={`${gap.capability ?? 'x'}-${gap.intentPath}-${i}`} gap={gap} />
            ))}
          </ul>
        )}

        {result.artifact && (
          <div className="mt-2">
            <button
              onClick={() => setShowArtifact((v) => !v)}
              className="flex items-center gap-1.5 text-[12px] text-text-secondary hover:text-text-primary"
            >
              {showArtifact ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              {t('intent.showArtifact', { format: result.artifact.format })}
            </button>
            {showArtifact && <ArtifactBody body={result.artifact.body} />}
          </div>
        )}
      </div>
    </section>
  );
}

/**
 * The sentence that carries the vendor knowledge.
 *
 * Built here rather than taken from the server so it exists even when the
 * compiler returns only a flag — and so it is translated, which a server
 * string never is.
 */
function GapRow({ gap }: { gap: CapabilityGap }) {
  const { t } = useTranslation();

  const brandLabel = BRAND_LABELS[gap.brand];
  const scope = gap.model
    ? `${brandLabel} ${gap.model}`
    : gap.family
      ? `${brandLabel} (${gap.family})`
      : brandLabel;

  const capabilityLabel = gap.capability
    ? t(CAPABILITY_FLAG_LABEL_KEYS[gap.capability])
    : null;

  // Three levels of richness, all of which name the brand.
  const headline = gap.capability
    ? t('intent.gapNamed', { scope, capability: capabilityLabel })
    : gap.detail
      ? t('intent.gapReasoned', { scope })
      : t('intent.gapUnexplained', { scope });

  return (
    <li className="rounded-md border border-border bg-bg-tertiary p-2">
      <p className="flex items-start gap-1.5 text-[12px] text-text-primary">
        <ShieldAlert size={12} className="mt-0.5 shrink-0 text-status-ssl-warning" />
        <span>{headline}</span>
      </p>
      {gap.capability && (
        <p className="mt-0.5 pl-[18px] font-mono text-[10px] text-text-muted">{gap.capability}</p>
      )}
      {gap.detail && (
        <p className="mt-0.5 pl-[18px] text-[11px] text-text-secondary">{gap.detail}</p>
      )}
      {gap.intentPath && gap.intentPath !== '—' && (
        <p className="mt-0.5 pl-[18px] text-[11px] text-text-muted">
          {t('intent.gapNeededBy', { path: gap.intentPath })}
        </p>
      )}
    </li>
  );
}

/**
 * §8.2 — the compiler resolves vault references at APPLY time, so an artefact
 * previewed here must contain no secret at all. Anything the scanner finds is a
 * server bug, and the whole point of scanning is to catch it before it lands in
 * a screenshot.
 */
function ArtifactBody({ body }: { body: string }) {
  const { t } = useTranslation();
  const hits = scanTextForSecrets(body, 3);

  if (hits.length > 0) {
    return (
      <p className="mt-1.5 inline-flex items-center gap-1.5 rounded border border-status-ssl-expired/60 bg-status-ssl-expired/15 px-2 py-1 text-[11px] text-status-ssl-expired">
        <ShieldAlert size={12} />
        {t('intent.artifactSecret', { keys: hits.map((h) => h.label).join(', ') })}
      </p>
    );
  }

  return (
    <pre className="mt-1.5 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md border border-border bg-bg-primary/40 p-2 font-mono text-[11px] text-text-secondary">
      {body}
    </pre>
  );
}
