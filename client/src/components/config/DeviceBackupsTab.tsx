import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Archive, RotateCw, ShieldAlert } from 'lucide-react';
import apiClient from '@/api/client';
import type { ApiResponse } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';

/**
 * This device's pre-change backups.
 *
 * The tab carried an "M4" padlock long after the server half existed. The route
 * has always accepted `?deviceId=`; nothing was missing but this pane.
 *
 * There is no download button here either, for the same reason as on the fleet
 * screen: a backup is a device's COMPLETE configuration, the API returns
 * neither its encryption password nor its storage path, and restoring goes
 * through the change queue like every other write (D3). A link would be a
 * second path to the same bytes, around that rule.
 *
 * `takenBeforeJobId` is what makes this worth opening: it ties an archive to
 * the change it was taken to protect, which is the question an operator has at
 * 2am — "which one do I restore to undo job 412".
 */

interface BackupRow {
  id: number;
  kind: string;
  triggerKind: string;
  sizeBytes: number;
  retentionClass: string;
  expiresAt: string | null;
  status: string;
  takenBeforeJobId: number | null;
  osVersion: string | null;
  createdAt: string;
}

function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function DeviceBackupsTab({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation();
  const [rows, setRows] = useState<BackupRow[]>([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const res = await apiClient.get<ApiResponse<BackupRow[]>>('/backups', {
        params: { deviceId, limit: 200 },
      });
      setRows(res.data.data ?? []);
    } catch {
      setRows([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, [deviceId]);

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <p className="text-xs text-text-muted">
          {t('backups.hint', {
            defaultValue:
              'Taken automatically before every change. There is no download: restoring goes through '
              + 'the change queue, and the archive password never leaves the server.',
          })}
        </p>
        <Button size="sm" variant="secondary" onClick={() => void load()}>
          <RotateCw size={14} className="mr-1.5" />
          {t('common.refresh', { defaultValue: 'Refresh' })}
        </Button>
      </div>

      {loading ? <LoadingSpinner /> : rows.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary px-6 py-12 text-center">
          <Archive size={22} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-secondary">
            {t('backups.deviceEmpty', {
              defaultValue: 'No backup for this device yet. The first one is taken before its first change.',
            })}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full text-sm">
            <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">{t('backups.when', { defaultValue: 'When' })}</th>
                <th className="px-4 py-2 font-medium">{t('backups.trigger', { defaultValue: 'Taken because' })}</th>
                <th className="px-4 py-2 font-medium">{t('backups.size', { defaultValue: 'Size' })}</th>
                <th className="px-4 py-2 font-medium">{t('backups.retention', { defaultValue: 'Retention' })}</th>
                <th className="px-4 py-2 font-medium">{t('backups.status', { defaultValue: 'Status' })}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map((b) => (
                <tr key={b.id}>
                  <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-text-muted">
                    {new Date(b.createdAt).toLocaleString()}
                    {b.osVersion && (
                      <span className="ml-2 text-[10px] text-text-muted">{b.osVersion}</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-text-secondary">
                    {b.triggerKind}
                    {b.takenBeforeJobId !== null && (
                      <span className="ml-2 font-mono text-[10px] text-text-muted">
                        {t('backups.beforeJob', {
                          defaultValue: 'before job #{{id}}',
                          id: b.takenBeforeJobId,
                        })}
                      </span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-text-secondary">
                    {humanSize(b.sizeBytes)} · {b.kind}
                  </td>
                  <td className="px-4 py-2 text-xs text-text-secondary">
                    {b.retentionClass}
                    {b.expiresAt && (
                      <span className="ml-1 text-text-muted">
                        → {new Date(b.expiresAt).toLocaleDateString()}
                      </span>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2 text-xs">
                    {b.status === 'available' ? (
                      <span className="text-text-secondary">{b.status}</span>
                    ) : (
                      // The net that was supposed to be there is not: the only
                      // thing on this pane worth interrupting somebody for.
                      <span className="inline-flex items-center gap-1.5 text-text-primary">
                        <ShieldAlert size={13} /> {b.status}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
