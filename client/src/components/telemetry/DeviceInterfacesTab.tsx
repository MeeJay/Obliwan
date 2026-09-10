import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, RotateCw, Unplug, Radar, History, ShuffleIcon } from 'lucide-react';
import toast from 'react-hot-toast';
import { interfacesApi, discoveryApi, type DiscoveryHistory } from '@/api/interfaces.api';
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
  const [discovering, setDiscovering] = useState(false);
  const [history, setHistory] = useState<DiscoveryHistory | null>(null);
  const [showHistory, setShowHistory] = useState(false);

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

  const loadHistory = useCallback(async () => {
    setHistory(await discoveryApi.history(deviceId));
  }, [deviceId]);

  useEffect(() => {
    void load();
    void loadHistory();
  }, [load, loadHistory]);

  /**
   * Walk the ifTable now.
   *
   * The poller rediscovers on its own schedule, hours apart, because a full walk
   * is expensive and interfaces rarely move. That is right by default and wrong
   * in the one moment it matters: somebody has just plugged in an SFP, renamed a
   * bridge, or finished turning SNMP on, and cannot tell "not yet" apart from
   * "silently broken" without waiting an hour.
   */
  const handleDiscover = async () => {
    setDiscovering(true);
    try {
      const r = await discoveryApi.force(deviceId);
      // Counted rather than summarised: "12 interfaces" hides that two of them
      // are new and one vanished, which is the whole news.
      toast.success(
        t('interfaces.discoveryDone', {
          discovered: r.discovered, created: r.created, vanished: r.vanished,
        }),
      );
      // `remapped` gets its own line and its own tone: an ifIndex that moved
      // means samples were being attributed to the wrong port until this run
      // caught it (R12). It is never good news, only news.
      if (r.remapped > 0) {
        toast(t('interfaces.discoveryRemapped', { count: r.remapped }), { duration: 9000 });
      }
      await load();
      await loadHistory();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('interfaces.discoveryFailed'));
    } finally {
      setDiscovering(false);
    }
  };

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
        <div className="ml-auto flex items-center gap-2">
          {history && (
            <button
              type="button"
              onClick={() => setShowHistory((v) => !v)}
              className="flex items-center gap-1.5 text-[12px] text-text-secondary hover:text-text-primary"
            >
              <History size={13} />
              {t('interfaces.historyToggle', { count: history.entries.length })}
            </button>
          )}
          <Button variant="secondary" size="sm" onClick={() => void handleDiscover()} disabled={discovering}>
            <Radar size={13} className={cn('mr-1.5', discovering && 'animate-pulse')} />
            {discovering ? t('interfaces.discovering') : t('interfaces.discoverNow')}
          </Button>
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RotateCw size={13} className={cn('mr-1.5', loading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
        </div>
      </div>

      {/* ── Discovery history ──
          Derived from `snmp_interfaces` itself, not from an event log: an
          interface is never deleted, so `first_seen_at` / `vanished_at` already
          ARE the history. A second table would be a second account of the same
          facts, free to disagree — and the one that disagrees is always the one
          somebody reads. */}
      {showHistory && history && (
        <div className="rounded-lg border border-border bg-bg-secondary p-4">
          <p className="mb-3 text-xs text-text-muted">
            {t('interfaces.historyWhen', {
              last: history.lastDiscoveryAt
                ? new Date(history.lastDiscoveryAt).toLocaleString()
                : t('interfaces.historyNever'),
              next: history.nextDiscoveryAt
                ? new Date(history.nextDiscoveryAt).toLocaleString()
                : '—',
            })}
          </p>
          <ul className="space-y-1">
            {history.entries.map((e) => (
              <li key={`${e.ifName}-${e.ifIndex}-${e.firstSeenAt}`} className="flex flex-wrap items-baseline gap-2 text-xs">
                <span className="font-mono text-text-primary">{e.ifName}</span>
                <span className="font-mono text-[10px] text-text-muted">ifIndex {e.ifIndex}</span>
                <span className="text-text-muted">
                  {t('interfaces.historyFirstSeen', {
                    at: new Date(e.firstSeenAt).toLocaleString(),
                  })}
                </span>
                {e.vanishedAt && (
                  <span className="text-status-down">
                    {t('interfaces.historyVanished', {
                      at: new Date(e.vanishedAt).toLocaleString(),
                    })}
                  </span>
                )}
                {e.needsRediscovery && (
                  <span className="inline-flex items-center gap-1 text-status-warn">
                    <ShuffleIcon size={11} />
                    {t('interfaces.historyNeedsRediscovery')}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

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
