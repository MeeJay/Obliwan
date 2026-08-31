import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck, RotateCw, AlertTriangle } from 'lucide-react';
import apiClient from '@/api/client';
import type { ApiResponse } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';

/**
 * Command audit — every command ever sent to a device.
 *
 * ┌─ THREE THINGS THIS TABLE SAYS THAT NOTHING ELSE DOES ────────────────────┐
 * │ 1. `command` IS ALREADY MASKED, at write time, and there is no unmasked   │
 * │    version anywhere. This screen therefore has no reveal control, because │
 * │    there is nothing behind it. §8.2: the complete rendering exists in     │
 * │    memory only, on the vault → device path.                               │
 * │                                                                          │
 * │ 2. `success: null` IS NOT "unknown, probably fine". It means the command  │
 * │    was SENT and no outcome was ever recorded — the device stopped         │
 * │    answering mid-exchange, or the process died between the two writes.    │
 * │    That is a finding, and it is rendered as one rather than as a blank.   │
 * │                                                                          │
 * │ 3. The table is APPEND-ONLY in the database — a trigger refuses every     │
 * │    UPDATE, and it carries no foreign key to `tenants` so it outlives an   │
 * │    offboarding. Nothing here offers to edit or delete a line, because     │
 * │    nothing could.                                                         │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The default view is WRITES ONLY. A read is a question; a write changed
 * somebody's router, and that is what an audit screen is opened to find.
 */

interface CommandAuditRow {
  id: number;
  deviceId: number | null;
  deviceName: string | null;
  username: string | null;
  jobId: number | null;
  transport: string;
  command: string;
  isWrite: boolean;
  success: boolean | null;
  errorRedacted: string | null;
  durationMs: number | null;
  executedAt: string;
}

export function AuditPage() {
  const { t } = useTranslation();
  const [rows, setRows] = useState<CommandAuditRow[]>([]);
  const [total, setTotal] = useState(0);
  const [writesOnly, setWritesOnly] = useState(true);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const res = await apiClient.get<ApiResponse<{ rows: CommandAuditRow[]; total: number }>>(
        '/changes/audit',
        { params: { writesOnly: writesOnly ? 'true' : undefined, limit: 200 } },
      );
      setRows(res.data.data?.rows ?? []);
      setTotal(res.data.data?.total ?? 0);
    } catch {
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, [writesOnly]);

  return (
    <div className="p-6">
      <div className="mb-5 flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <ShieldCheck size={22} /> {t('nav.audit')}
        </h1>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-sm text-text-secondary">
            <input
              type="checkbox"
              checked={writesOnly}
              onChange={(e) => setWritesOnly(e.target.checked)}
            />
            {t('audit.writesOnly', { defaultValue: 'Writes only' })}
          </label>
          <Button size="sm" variant="secondary" onClick={() => void load()}>
            <RotateCw size={14} className="mr-1.5" />{t('common.refresh', { defaultValue: 'Refresh' })}
          </Button>
        </div>
      </div>

      <p className="mb-4 text-xs text-text-muted">
        {t('audit.hint', {
          defaultValue:
            'Every command sent to a device, with secrets already masked at write time. The table is '
            + 'append-only: no line here can be edited or removed.',
        })}
      </p>

      {loading ? <LoadingSpinner /> : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          {rows.length === 0 ? (
            <div className="px-6 py-12 text-center text-sm text-text-secondary">
              {t('audit.empty', { defaultValue: 'No command recorded yet.' })}
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">{t('audit.when', { defaultValue: 'When' })}</th>
                  <th className="px-4 py-2 font-medium">{t('audit.device', { defaultValue: 'Device' })}</th>
                  <th className="px-4 py-2 font-medium">{t('audit.who', { defaultValue: 'Who' })}</th>
                  <th className="px-4 py-2 font-medium">{t('audit.command', { defaultValue: 'Command' })}</th>
                  <th className="px-4 py-2 font-medium">{t('audit.result', { defaultValue: 'Result' })}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-text-muted">
                      {new Date(r.executedAt).toLocaleString()}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">{r.deviceName ?? `#${r.deviceId ?? '—'}`}</td>
                    <td className="px-4 py-2 text-text-secondary">{r.username ?? '—'}</td>
                    <td className="max-w-md px-4 py-2">
                      <span className="block truncate font-mono text-xs text-text-primary" title={r.command}>
                        {r.command}
                      </span>
                      {r.errorRedacted && (
                        <span className="block truncate text-xs text-text-muted">{r.errorRedacted}</span>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2">
                      {r.success === null ? (
                        // NOT a blank. See the box at the top: sent, never answered.
                        <span className="inline-flex items-center gap-1.5 text-xs text-text-primary">
                          <AlertTriangle size={13} />
                          {t('audit.noOutcome', { defaultValue: 'sent, no outcome recorded' })}
                        </span>
                      ) : (
                        <span className="text-xs text-text-secondary">
                          {r.success
                            ? t('audit.ok', { defaultValue: 'ok' })
                            : t('audit.failed', { defaultValue: 'refused' })}
                          {r.durationMs !== null ? ` · ${r.durationMs} ms` : ''}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {total > rows.length && (
        <p className="mt-3 text-xs text-text-muted">
          {t('audit.truncated', {
            defaultValue: 'Showing {{shown}} of {{total}} — narrow the filter to see older lines.',
            shown: rows.length,
            total,
          })}
        </p>
      )}
    </div>
  );
}
