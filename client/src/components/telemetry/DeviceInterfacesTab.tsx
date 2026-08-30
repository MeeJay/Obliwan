import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, RotateCw, Unplug } from 'lucide-react';
import { interfacesApi } from '@/api/interfaces.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { InterfacesTable } from '@/components/telemetry/InterfacesTable';
import { cn } from '@/utils/cn';
import type { NetInterface } from '@/types/telemetry';

interface DeviceInterfacesTabProps {
  deviceId: number;
}

/**
 * The Interfaces tab of a device (spec §4.2), unlocked at M3.
 *
 * Vanished interfaces are HIDDEN BY DEFAULT and counted, never deleted and
 * never silently dropped: an interface that disappeared from the ifTable keeps
 * its whole history, because "what happened on the port that disappeared" is
 * precisely the question somebody will ask. The toggle brings them back.
 */
export function DeviceInterfacesTab({ deviceId }: DeviceInterfacesTabProps) {
  const { t } = useTranslation();
  const [interfaces, setInterfaces] = useState<NetInterface[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showVanished, setShowVanished] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await interfacesApi.forDevice(deviceId);
      if (rows === null) {
        setUnavailable(true);
        setInterfaces([]);
      } else {
        setUnavailable(false);
        setInterfaces(rows);
      }
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setError(message ?? t('interfaces.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [deviceId, t]);

  useEffect(() => {
    void load();
  }, [load]);

  const vanishedCount = useMemo(
    () => interfaces.filter((i) => i.state === 'vanished').length,
    [interfaces],
  );
  const visible = useMemo(
    () => (showVanished ? interfaces : interfaces.filter((i) => i.state === 'active')),
    [interfaces, showVanished],
  );

  if (unavailable) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
        <Unplug size={26} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{t('interfaces.endpointUnavailable')}</p>
      </div>
    );
  }

  if (loading && interfaces.length === 0) {
    return (
      <div className="flex justify-center py-16">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
        {t('interfaces.loadFailed')} — <span className="font-mono text-xs">{error}</span>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-sm text-text-muted">
          {t('interfaces.deviceSubtitle', { count: interfaces.length })}
        </p>
        {vanishedCount > 0 && (
          <label className="flex cursor-pointer items-center gap-1.5 text-[12px] text-text-secondary">
            <input
              type="checkbox"
              checked={showVanished}
              onChange={(e) => setShowVanished(e.target.checked)}
              className="h-3.5 w-3.5 rounded border-border bg-bg-tertiary accent-accent"
            />
            {t('interfaces.showVanished', { count: vanishedCount })}
          </label>
        )}
        <Button variant="secondary" size="sm" className="ml-auto" onClick={() => void load()}>
          <RotateCw size={13} className={cn('mr-1.5', loading && 'animate-spin')} />
          {t('devices.refresh')}
        </Button>
      </div>

      {interfaces.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Activity size={26} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('interfaces.deviceEmpty')}</p>
          <p className="mt-1 text-xs text-text-muted">{t('interfaces.emptyHint')}</p>
        </div>
      ) : (
        <InterfacesTable
          interfaces={visible}
          showDevice={false}
          emptyLabel={t('interfaces.allVanished')}
        />
      )}
    </div>
  );
}
