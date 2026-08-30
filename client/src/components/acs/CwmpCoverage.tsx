import { useTranslation } from 'react-i18next';
import { CheckCircle2, CircleSlash, Info, MinusCircle } from 'lucide-react';
import type { DeviceBrand } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import { BRAND_LABELS } from '@/types/intent';
import type { CwmpBrandCoverage, CwmpCoverageLevel } from '@/types/acs';
import { CWMP_BRAND_COVERAGE, coverageOfBrand } from '@/types/acs';

/**
 * The brand-coverage strip of `AcsPage` — decision D2, made visible.
 *
 * ── WHY THIS IS THE FIRST THING ON THE SCREEN ───────────────────────────────
 * §0/D2 and §1.1/C10 both say it in one breath: RouterOS has no TR-069 client,
 * SonicOS has none either, and the ACS covers DrayTek plus Zyxel CPE — "assumé
 * et affiché dans l'UI". An ACS screen that simply lists the CPEs it happens to
 * know teaches the operator, by omission, that his 300 MikroTiks are missing
 * from a screen where they ought to be. He then opens a ticket, and the answer
 * to that ticket is an architectural decision that should have been on the page.
 *
 * So the strip is rendered ALWAYS — with zero CPEs, with a full fleet, while
 * loading, and even when the ACS API is not served at all. It is a constant
 * (`CWMP_BRAND_COVERAGE`) and not a fetch, precisely so that no state of the
 * network can make it disappear.
 *
 * ── `partial` IS NOT A HEDGE ────────────────────────────────────────────────
 * Zyxel is genuinely split: the `zyxel_cpe` family (VMG / DX / EX) is TR-069
 * only, while `zyxel_nebula` and `zyxel_standalone` are managed over REST/SSH
 * and will never appear here. Collapsing that into "supported" would send a
 * technician looking for a USG FLEX in the CPE list forever.
 */

const LEVEL_STYLES: Record<CwmpCoverageLevel, { chip: string; icon: JSX.Element }> = {
  supported: {
    chip: 'border-status-up/50 bg-status-up/10 text-status-up',
    icon: <CheckCircle2 size={13} />,
  },
  partial: {
    chip: 'border-status-ssl-warning/50 bg-status-ssl-warning/10 text-status-ssl-warning',
    icon: <MinusCircle size={13} />,
  },
  absent: {
    // Deliberately NOT red. "No CWMP client" is a fact about the vendor, not a
    // fault in the fleet, and painting it as an error trains operators to
    // ignore red.
    chip: 'border-border bg-bg-tertiary text-text-muted',
    icon: <CircleSlash size={13} />,
  },
};

export function CwmpCoverageStrip({ className }: { className?: string }) {
  const { t } = useTranslation();

  return (
    <section
      className={cn('rounded-lg border border-border bg-bg-secondary p-3', className)}
      aria-label={t('acs.coverage.title')}
    >
      <h2 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-text-primary">
        <Info size={14} className="text-text-muted" />
        {t('acs.coverage.title')}
      </h2>
      <p className="mb-3 max-w-3xl text-[12px] text-text-muted">{t('acs.coverage.intro')}</p>

      <ul className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {CWMP_BRAND_COVERAGE.map((row) => (
          <li key={row.brand} className="rounded-md border border-border bg-bg-tertiary p-2.5">
            <div className="flex items-center gap-2">
              <span className="text-[13px] font-medium text-text-primary">
                {BRAND_LABELS[row.brand]}
              </span>
              <span
                className={cn(
                  'ml-auto inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
                  LEVEL_STYLES[row.level].chip,
                )}
              >
                {LEVEL_STYLES[row.level].icon}
                {t(`acs.coverage.level.${row.level}`)}
              </span>
            </div>
            <p className="mt-1.5 text-[12px] leading-snug text-text-secondary">{t(row.reasonKey)}</p>
            {row.families.length > 0 && (
              <p className="mt-1 font-mono text-[10px] text-text-muted">{row.families.join(' · ')}</p>
            )}
            {row.insteadKey && (
              <p className="mt-1 text-[11px] italic text-text-muted">{t(row.insteadKey)}</p>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

/**
 * The same statement, scoped to one device — for the TR-069 tab of
 * `DeviceDetailPage`.
 *
 * Opening the TR-069 tab on a MikroTik is the single most likely way an
 * operator meets D2, and "no data" is the worst possible answer there. This
 * component gives the reason and the alternative transport instead.
 */
export function BrandCwmpNotice({ brand }: { brand: DeviceBrand | null }) {
  const { t } = useTranslation();
  const coverage: CwmpBrandCoverage | null = coverageOfBrand(brand);

  if (!coverage) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary p-4 text-center">
        <CircleSlash size={24} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{t('acs.coverage.unknownBrand')}</p>
      </div>
    );
  }

  if (coverage.level === 'supported') return null;

  const absent = coverage.level === 'absent';
  return (
    <div
      className={cn(
        'rounded-lg border p-4',
        absent ? 'border-border bg-bg-tertiary' : 'border-status-ssl-warning/40 bg-status-ssl-warning/5',
      )}
    >
      <p className="flex items-center gap-2 text-sm font-medium text-text-primary">
        {LEVEL_STYLES[coverage.level].icon}
        {t(`acs.coverage.headline.${coverage.level}`, { brand: BRAND_LABELS[coverage.brand] })}
      </p>
      <p className="mt-1.5 text-[13px] text-text-secondary">{t(coverage.reasonKey)}</p>
      {coverage.insteadKey && (
        <p className="mt-1 text-[12px] text-text-muted">{t(coverage.insteadKey)}</p>
      )}
    </div>
  );
}
