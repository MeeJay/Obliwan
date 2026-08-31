import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Archive, RotateCw, ShieldAlert } from 'lucide-react';
import apiClient from '@/api/client';
import type { ApiResponse } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';

/**
 * Pre-change backups (M6).
 *
 * ┌─ THERE IS NO DOWNLOAD BUTTON, AND THAT IS THE DESIGN ────────────────────┐
 * │ A backup is a device's COMPLETE configuration. A download link turns a    │
 * │ controlled artefact into a file in somebody's Downloads folder, on a      │
 * │ laptop, forever — and the API deliberately returns neither the archive's  │
 * │ encryption password nor its storage path, so there would be nothing       │
 * │ honest to link to anyway.                                                 │
 * │                                                                          │
 * │ What a backup is FOR is restoring, and restoring goes through the change  │
 * │ queue like every other write (D3): one job in flight per device, a        │
 * │ guarded plan, a recorded outcome. A list that quietly offered a second    │
 * │ path to the same bytes would be a way around that.                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `takenBeforeJobId` is the column that makes this screen worth opening: it
 * ties an archive to the change it was taken to protect. "Which backup would I
 * restore to undo job 412" is the question an operator actually has at 2am.
 */

interface BackupRow {
  id: number;
  deviceId: number | null;
  deviceName: string | null;
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

export function BackupsPage() {
  const { t } = useTranslation();
  const [rows, setRows] = useState<BackupRow[]>([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const res = await apiClient.get<ApiResponse<BackupRow[]>>('/backups', { params: { limit: 200 } });
      setRows(res.data.data ?? []);
    } catch {
      setRows([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  return (
    <div className="p-6">
      <div className="mb-5 flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <Archive size={22} /> {t('nav.backups')}
        </h1>
        <Button size="sm" variant="secondary" onClick={() => void load()}>
          <RotateCw size={14} className="mr-1.5" />{t('common.refresh', { defaultValue: 'Refresh' })}
        </Button>
      </div>

      <p className="mb-4 text-xs text-text-muted">
        {t('backups.hint', {
          defaultValue:
            'Taken automatically before every change. There is no download: restoring goes through '
            + 'the change queue, and the archive password never leaves the server.',
        })}
      </p>

      {loading ? <LoadingSpinner /> : rows.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary px-6 py-12 text-center text-sm text-text-secondary">
          {t('backups.empty', {
            defaultValue: 'No backup yet. The first one is taken before the first change.',
          })}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full text-sm">
            <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">{t('backups.when', { defaultValue: 'When' })}</th>
                <th className="px-4 py-2 font-medium">{t('audit.device', { defaultValue: 'Device' })}</th>
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
                  </td>
                  <td className="px-4 py-2 text-text-secondary">
                    {b.deviceName ?? `#${b.deviceId ?? '—'}`}
                    {b.osVersion && <span className="ml-2 font-mono text-[10px] text-text-muted">{b.osVersion}</span>}
                  </td>
                  <td className="px-4 py-2 text-text-secondary">
                    {b.triggerKind}
                    {/* The link between an archive and the change it protects. */}
                    {b.takenBeforeJobId !== null && (
                      <span className="ml-2 font-mono text-[10px] text-text-muted">
                        {t('backups.beforeJob', { defaultValue: 'before job #{{id}}', id: b.takenBeforeJobId })}
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
                      // A backup that is not available is the one thing on this
                      // screen worth interrupting somebody for: the net that was
                      // supposed to be there is not.
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
