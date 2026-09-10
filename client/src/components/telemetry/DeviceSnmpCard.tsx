import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Radio, RotateCw } from 'lucide-react';
import toast from 'react-hot-toast';
import {
  snmpApi, snmpTargetApi,
  type SnmpCredential, type SnmpTargetSummary,
} from '@/api/snmp.api';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';

/**
 * This device's SNMP supervision — pinned here, or inherited from the fleet.
 *
 * ┌─ NULL MEANS INHERIT, AND THAT IS THE FEATURE ────────────────────────────┐
 * │ `credentialId === null` on the target does NOT mean "no credential". It   │
 * │ means the poller resolves one at poll time from the settings tree, so a   │
 * │ community rotated once at tenant level actually changes what the whole    │
 * │ fleet is polled with. Pinning the resolved value at creation would have   │
 * │ looked identical and behaved differently — the setting would apply only   │
 * │ to devices enrolled after it.                                            │
 * │                                                                          │
 * │ Choosing a credential here PINS it, for this box only, until somebody     │
 * │ puts it back on "inherit". That is the escape hatch for the one customer  │
 * │ whose router has its own community.                                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The card always shows what the poller will ACTUALLY use, not just the pin:
 * "inherited" without saying inherited FROM WHAT is the same non-answer as
 * showing nothing.
 */
export function DeviceSnmpCard({ deviceId, canWrite }: { deviceId: number; canWrite: boolean }) {
  const { t } = useTranslation();
  const [target, setTarget] = useState<SnmpTargetSummary | null>(null);
  const [credentials, setCredentials] = useState<SnmpCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const [tg, creds] = await Promise.all([
      snmpTargetApi.get(deviceId),
      snmpApi.listCredentials().catch(() => [] as SnmpCredential[]),
    ]);
    setTarget(tg);
    setCredentials(creds);
    setLoading(false);
  }, [deviceId]);

  useEffect(() => { void load(); }, [load]);

  const change = async (value: string) => {
    setSaving(true);
    try {
      // '' is the inherit option, and it is sent as an explicit null rather
      // than omitted: an absent field means "unchanged" on this endpoint.
      const credentialId = value === '' ? null : Number(value);
      await snmpTargetApi.put(deviceId, { credentialId, enabled: true });
      toast.success(t('snmpTarget.saved'));
      await load();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('snmpTarget.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-text-primary">
          <Radio size={15} /> {t('snmpTarget.title')}
        </h3>
        <Button size="sm" variant="secondary" onClick={() => void load()}>
          <RotateCw size={13} className={cn(loading && 'animate-spin')} />
        </Button>
      </div>

      {loading ? (
        <p className="py-3 text-xs text-text-muted">…</p>
      ) : (
        <>
          <div className="mb-2 space-y-1">
            <label className="block text-xs uppercase tracking-wide text-text-muted">
              {t('snmpTarget.credential')}
            </label>
            <select
              className="w-full rounded-md border border-border bg-bg-tertiary px-2 py-2 text-sm text-text-primary disabled:cursor-not-allowed disabled:text-text-muted"
              value={target?.credentialId ?? ''}
              disabled={!canWrite || saving}
              onChange={(e) => void change(e.target.value)}
            >
              <option value="">
                {t('snmpTarget.inheritOption', {
                  name: target?.inherited && target.effectiveCredentialName
                    ? target.effectiveCredentialName
                    : t('snmpTarget.inheritNothing'),
                })}
              </option>
              {credentials.map((c) => (
                <option key={c.id} value={c.id}>{c.name} ({c.version})</option>
              ))}
            </select>
          </div>

          {/* What the poller will really use — pin or inheritance, resolved. */}
          <p className="text-xs text-text-muted">
            {target === null
              ? t('snmpTarget.noTarget')
              : target.effectiveCredentialId === null
                ? t('snmpTarget.effectiveNone')
                : t('snmpTarget.effective', {
                  name: target.effectiveCredentialName ?? `#${target.effectiveCredentialId}`,
                  source: target.inherited ? t('snmpTarget.fromFleet') : t('snmpTarget.pinned'),
                })}
          </p>

          {target?.lastError && (
            <p className="mt-2 break-words font-mono text-[11px] text-status-down">
              {target.lastError}
            </p>
          )}
          {target && target.consecutiveFailures > 0 && (
            <p className="mt-1 text-[11px] text-status-warn">
              {t('snmpTarget.failures', { count: target.consecutiveFailures })}
            </p>
          )}
        </>
      )}
    </div>
  );
}
