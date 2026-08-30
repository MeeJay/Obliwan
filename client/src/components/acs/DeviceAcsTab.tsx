import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { RadioTower, Unplug } from 'lucide-react';
import type { DeviceBrand, DeviceFamily } from '@obliwan/shared';
import { CAPABILITIES } from '@obliwan/shared';
import { acsApi } from '@/api/acs.api';
import { useAuthStore } from '@/store/authStore';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { BrandCwmpNotice } from '@/components/acs/CwmpCoverage';
import { InformStatus } from '@/components/acs/InformStatus';
import { CWMP_CAPABLE_FAMILIES } from '@/types/acs';
import type { CwmpCpe, CwmpTask } from '@/types/acs';

/**
 * The `TR-069` tab of `DeviceDetailPage` (§4.2, M10).
 *
 * ── THE TAB'S REAL JOB IS TO SAY "NOT THIS BRAND" ───────────────────────────
 * Opening this tab on one of the fleet's 300 MikroTiks is by far the most
 * likely way an operator meets decision D2, and it is the moment where an
 * empty panel does the most damage: it reads as "the ACS lost my router". So
 * the family check happens FIRST, before any fetch, and the answer is a
 * sentence naming the brand and the transport to use instead.
 *
 * Only `draytek_vigor` and `zyxel_cpe` ever get as far as the network call.
 * That is not an optimisation — it is the tab refusing to ask a question whose
 * answer would be misread.
 */
export function DeviceAcsTab({
  deviceId,
  brand,
  family,
}: {
  deviceId: number;
  brand: DeviceBrand | null;
  family: DeviceFamily | null;
}) {
  const { t } = useTranslation();
  const { hasCapability, isAdmin } = useAuthStore();
  const canAdmin = isAdmin() || hasCapability(CAPABILITIES.ACS_ADMIN);

  const cwmpCapable = family !== null && CWMP_CAPABLE_FAMILIES.includes(family);

  const [cpe, setCpe] = useState<CwmpCpe | null>(null);
  const [tasks, setTasks] = useState<CwmpTask[] | null>(null);
  const [loading, setLoading] = useState(cwmpCapable);
  const [unavailable, setUnavailable] = useState(false);

  const load = useCallback(async () => {
    if (!cwmpCapable) return;
    setLoading(true);
    try {
      const row = await acsApi.getCpe(deviceId);
      if (row === null) { setUnavailable(true); setCpe(null); }
      else {
        setUnavailable(false);
        setCpe(row);
        setTasks(await acsApi.listTasks(deviceId, 20));
      }
    } catch {
      setCpe(null);
    } finally {
      setLoading(false);
    }
  }, [deviceId, cwmpCapable]);

  useEffect(() => { void load(); }, [load]);

  // 1. The brand answer, before anything else.
  if (!cwmpCapable) {
    return (
      <div className="space-y-3">
        <BrandCwmpNotice brand={brand} />
        {brand === 'zyxel' && (
          <p className="text-[12px] text-text-muted">
            {t('acs.coverage.zyxelFamilyHint', { family: family ?? '—' })}
          </p>
        )}
      </div>
    );
  }

  if (!canAdmin) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
        <p className="text-sm text-text-muted">{t('acs.forbidden')}</p>
      </div>
    );
  }

  if (loading) {
    return <div className="flex justify-center py-12"><LoadingSpinner /></div>;
  }

  if (unavailable) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
        <Unplug size={24} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{t('acs.endpointUnavailable')}</p>
        <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">{t('acs.endpointUnavailableHint')}</p>
      </div>
    );
  }

  // 2. A CWMP-capable box the ACS has never heard from. Distinct from "no ACS".
  if (cpe === null) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
        <RadioTower size={24} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{t('acs.device.notEnrolled')}</p>
        <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">{t('acs.device.notEnrolledHint')}</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <InformStatus cpe={cpe} />

      <section className="rounded-lg border border-border bg-bg-secondary p-3">
        <h3 className="mb-2 text-sm font-semibold text-text-primary">{t('acs.device.queue')}</h3>
        {tasks === null || tasks.length === 0 ? (
          <p className="text-[12px] text-text-muted">{t('acs.tasks.empty')}</p>
        ) : (
          <ul className="space-y-1">
            {tasks.slice(0, 8).map((task) => (
              <li key={task.id} className="flex items-center gap-2 text-[12px]">
                <span className="font-mono text-text-primary">{task.command}</span>
                <span className="truncate font-mono text-[11px] text-text-muted">{task.summary ?? ''}</span>
                <span className="ml-auto shrink-0 font-mono text-[10px] uppercase tracking-wider text-text-muted">
                  {t(`acs.tasks.state.${task.state}`, { defaultValue: task.state })}
                </span>
              </li>
            ))}
          </ul>
        )}
        <Link
          to="/acs"
          className="mt-2 inline-block text-[12px] text-accent hover:underline"
        >
          {t('acs.device.openFullScreen')}
        </Link>
      </section>
    </div>
  );
}
