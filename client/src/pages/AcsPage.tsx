import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import {
  Ban,
  FileDown,
  HardDriveDownload,
  ListTree,
  RadioTower,
  RefreshCw,
  ScrollText,
  ShieldAlert,
  Trash2,
  Unplug,
  X,
} from 'lucide-react';
import type { DeviceFamily } from '@obliwan/shared';
import { CAPABILITIES } from '@obliwan/shared';
import { acsApi } from '@/api/acs.api';
import { errorMessageOf } from '@/api/change.api';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { CwmpCoverageStrip } from '@/components/acs/CwmpCoverage';
import { InformStatus, ReachabilityChip } from '@/components/acs/InformStatus';
import { ParameterTree } from '@/components/acs/ParameterTree';
import { scanTextForSecrets } from '@/utils/secretScan';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import { BRAND_LABELS } from '@/types/intent';
import type {
  CwmpCpe,
  CwmpFile,
  CwmpParameter,
  CwmpRpcLogView,
  CwmpTask,
  CwmpTaskState,
} from '@/types/acs';

/**
 * `AcsPage` — TR-069 / CWMP (M10, feature C10 + decision D2).
 *
 * ┌─ THE TWO THINGS THIS SCREEN IS NOT ALLOWED TO IMPLY ─────────────────────┐
 * │ 1. THAT THE ACS COVERS THE FLEET. It does not, and never will:           │
 * │    RouterOS ships no TR-069 client and neither does SonicOS. The         │
 * │    coverage strip is the FIRST element on the page, it is a constant     │
 * │    rather than a fetch, and it is rendered even when the ACS API is      │
 * │    absent — no network state can make that statement disappear.          │
 * │ 2. THAT AN ACTION HAPPENS NOW. CWMP is CPE-initiated. Every write on     │
 * │    this page is an ENQUEUE, the button says so, and `InformStatus`       │
 * │    prints the delay before the click rather than after it.               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── §8.2 ────────────────────────────────────────────────────────────────────
 * The TR-069 data model carries PPP, WLAN and IPsec passwords as standard
 * leaves — the exact shape of the last audit's finding. Values are redacted in
 * `acs.api.ts` by path, the tree refuses to paint a redacted leaf even masked,
 * every surviving value is scanned at paint time, and the SPV editor uses a
 * password field whose content is posted and then dropped, never echoed into
 * the task list.
 *
 * ── WHAT IS DELIBERATELY ABSENT ─────────────────────────────────────────────
 * No firmware UPLOAD. §3.6 has `cwmp_files` + `cwmp_transfers` with a
 * `url_token`, i.e. the ACS serves the image over a one-shot URL; pushing a
 * multi-megabyte binary through this SPA would add an upload path to a screen
 * whose job is to schedule, and the registration of an image is an operator act
 * that belongs with the deployment. The page LISTS images and pushes them.
 */

type DetailTab = 'params' | 'tasks' | 'rpc';

const TASK_STATE_STYLES: Record<CwmpTaskState, string> = {
  queued: 'border-status-pending/50 bg-status-pending/10 text-status-pending',
  sent: 'border-accent/50 bg-accent/10 text-accent',
  done: 'border-status-up/50 bg-status-up/10 text-status-up',
  failed: 'border-status-ssl-expired/60 bg-status-ssl-expired/15 text-status-ssl-expired',
  // NOT red: nothing was ever sent to the device. See `types/acs.ts`.
  expired: 'border-status-ssl-warning/50 bg-status-ssl-warning/10 text-status-ssl-warning',
  cancelled: 'border-border bg-bg-tertiary text-text-muted',
};

export function AcsPage() {
  const { t, i18n } = useTranslation();
  const { hasCapability, isAdmin } = useAuthStore();
  const canAdmin = isAdmin() || hasCapability(CAPABILITIES.ACS_ADMIN);

  const [cpes, setCpes] = useState<CwmpCpe[] | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const [tab, setTab] = useState<DetailTab>('params');
  const [params, setParams] = useState<CwmpParameter[] | null>(null);
  const [paramFilter, setParamFilter] = useState('');
  const [tasks, setTasks] = useState<CwmpTask[] | null>(null);
  const [rpcLog, setRpcLog] = useState<CwmpRpcLogView | null>(null);
  const [firmware, setFirmware] = useState<CwmpFile[] | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<CwmpParameter | null>(null);

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'medium' }),
    [i18n.language],
  );

  const selected = useMemo(
    () => (cpes ?? []).find((c) => c.deviceId === selectedId) ?? null,
    [cpes, selectedId],
  );

  const loadCpes = useCallback(async () => {
    setLoading(true);
    try {
      const rows = await acsApi.listCpe({ search: search.trim() || undefined });
      if (rows === null) { setUnavailable(true); setCpes(null); }
      else {
        setUnavailable(false);
        setCpes(rows);
        setSelectedId((prev) => (prev !== null && rows.some((r) => r.deviceId === prev)
          ? prev
          : rows[0]?.deviceId ?? null));
      }
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('acs.loadFailed'));
      setCpes([]);
    } finally {
      setLoading(false);
    }
  }, [search, t]);

  // Debounced: `loadCpes` closes over `search`, so an undebounced effect fires
  // one request per keystroke against a route that joins cwmp_devices to the
  // fleet. 250 ms is below the threshold where typing feels laggy and above
  // the inter-keystroke interval of anyone actually typing a serial.
  useEffect(() => {
    const id = window.setTimeout(() => { void loadCpes(); }, 250);
    return () => window.clearTimeout(id);
  }, [loadCpes]);

  useEffect(() => {
    void (async () => {
      try {
        setFirmware(await acsApi.listFirmware());
      } catch {
        setFirmware(null);
      }
    })();
  }, []);

  const loadDetail = useCallback(async (deviceId: number, which: DetailTab) => {
    setDetailLoading(true);
    try {
      if (which === 'params') setParams(await acsApi.listParameters(deviceId));
      else if (which === 'tasks') setTasks(await acsApi.listTasks(deviceId));
      else setRpcLog(await acsApi.rpcLog(deviceId));
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('acs.loadFailed'));
    } finally {
      setDetailLoading(false);
    }
  }, [t]);

  useEffect(() => {
    if (selectedId === null) return;
    void loadDetail(selectedId, tab);
  }, [selectedId, tab, loadDetail]);

  // ── Actions. Every one of them ENQUEUES; none of them "runs". ──
  const enqueue = useCallback(async (
    command: CwmpTask['command'],
    extra: { paths?: string[]; values?: Record<string, string>; fileId?: number } = {},
  ) => {
    if (selectedId === null) return;
    setBusy(true);
    try {
      const task = await acsApi.enqueue({ deviceId: selectedId, command, ...extra });
      if (task === null) { toast.error(t('acs.tasks.endpointAbsent')); return; }
      toast.success(t('acs.tasks.queued', { command }));
      if (tab === 'tasks') void loadDetail(selectedId, 'tasks');
      void loadCpes();
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('acs.tasks.queueFailed'));
    } finally {
      setBusy(false);
    }
  }, [selectedId, tab, loadDetail, loadCpes, t]);

  const attemptConnectionRequest = useCallback(async () => {
    if (selectedId === null) return;
    setBusy(true);
    try {
      const outcome = await acsApi.connectionRequest(selectedId);
      if (outcome === null) { toast.error(t('acs.tasks.endpointAbsent')); return; }
      if (outcome.delivered) toast.success(t('acs.inform.crDelivered'));
      // The honest failure: the poke did not land, the work is still queued.
      else toast(t('acs.inform.crUndelivered', { reason: outcome.reason ?? t('acs.inform.crNoReason') }));
      void loadCpes();
    } finally {
      setBusy(false);
    }
  }, [selectedId, loadCpes, t]);

  const cancelTask = useCallback(async (task: CwmpTask) => {
    setBusy(true);
    try {
      if (!(await acsApi.cancelTask(task.id))) { toast.error(t('acs.tasks.endpointAbsent')); return; }
      if (selectedId !== null) void loadDetail(selectedId, 'tasks');
    } finally {
      setBusy(false);
    }
  }, [selectedId, loadDetail, t]);

  if (!canAdmin) {
    return (
      <div className="p-6">
        {/* The coverage statement survives even the permission refusal: it is
            an architectural fact, not privileged information. */}
        <CwmpCoverageStrip className="mb-4" />
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <ShieldAlert size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('acs.forbidden')}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-display text-2xl font-semibold text-text-primary">{t('nav.acs')}</h1>
          <p className="mt-1 text-sm text-text-muted">{t('acs.subtitle')}</p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => void loadCpes()} disabled={loading}>
          <RefreshCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
          {t('acs.reloadList')}
        </Button>
      </div>

      {/* D2, stated before anything else on the page. */}
      <CwmpCoverageStrip className="mb-4" />

      {unavailable ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('acs.endpointUnavailable')}</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">{t('acs.endpointUnavailableHint')}</p>
        </div>
      ) : (
        <div className="grid gap-4 xl:grid-cols-[22rem_1fr]">
          {/* ── CPE list ── */}
          <aside className="min-w-0 space-y-3">
            <section className="rounded-lg border border-border bg-bg-secondary">
              <div className="border-b border-border p-2">
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder={t('acs.searchPlaceholder')}
                  className="w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
                />
              </div>
              {loading && cpes === null ? (
                <div className="flex justify-center py-10"><LoadingSpinner /></div>
              ) : (cpes ?? []).length === 0 ? (
                <div className="px-3 py-8 text-center">
                  <p className="text-[13px] text-text-muted">{t('acs.noCpe')}</p>
                  <p className="mt-1 text-[11px] text-text-muted">{t('acs.noCpeHint')}</p>
                </div>
              ) : (
                <ul className="max-h-[32rem] divide-y divide-border overflow-y-auto">
                  {(cpes ?? []).map((cpe) => (
                    <li key={cpe.deviceId}>
                      <button
                        onClick={() => setSelectedId(cpe.deviceId)}
                        className={cn(
                          'w-full px-3 py-2 text-left transition-colors',
                          cpe.deviceId === selectedId ? 'bg-bg-active' : 'hover:bg-bg-hover',
                        )}
                      >
                        <span className="flex items-center gap-2">
                          <span className="min-w-0 flex-1 truncate text-[13px] text-text-primary">
                            {anonHostname(cpe.deviceName ?? `#${cpe.deviceId}`)}
                          </span>
                          <ReachabilityChip value={cpe.reachability} />
                        </span>
                        <span className="mt-0.5 block truncate font-mono text-[10px] text-text-muted">
                          {cpe.cwmpId || '—'}
                        </span>
                        <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-text-muted">
                          {cpe.brand && <span>{BRAND_LABELS[cpe.brand]}</span>}
                          {cpe.dataModel && <span className="font-mono">{cpe.dataModel}</span>}
                          {cpe.queuedTasks > 0 && (
                            <span className="rounded border border-status-pending/50 bg-status-pending/10 px-1 text-status-pending">
                              {t('acs.queuedCount', { count: cpe.queuedTasks })}
                            </span>
                          )}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <FirmwarePanel
              files={firmware}
              dateFmt={dateFmt}
              disabled={busy || selected === null}
              selectedFamily={selected?.family ?? null}
              onPush={(file) => void enqueue('Download', { fileId: file.id })}
              onRemove={async (file) => {
                if (!(await acsApi.removeFirmware(file.id))) {
                  toast.error(t('acs.firmware.endpointAbsent'));
                  return;
                }
                setFirmware(await acsApi.listFirmware());
              }}
            />
          </aside>

          {/* ── Detail ── */}
          <div className="min-w-0 space-y-3">
            {selected === null ? (
              <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
                <RadioTower size={28} className="mx-auto mb-2 text-text-muted" />
                <p className="text-sm text-text-muted">{t('acs.selectCpe')}</p>
              </div>
            ) : (
              <>
                <CpeHeader cpe={selected} />

                <InformStatus
                  cpe={selected}
                  busy={busy}
                  queueLabel={t('acs.tasks.queueGpv')}
                  onQueue={() => void enqueue('GetParameterValues', {
                    paths: [selected.rootPrefix ?? ''],
                  })}
                  onConnectionRequest={() => void attemptConnectionRequest()}
                />

                <div className="flex flex-wrap gap-1 border-b border-border">
                  {([
                    { id: 'params' as const, icon: <ListTree size={14} />, label: t('acs.tabs.params') },
                    { id: 'tasks' as const, icon: <HardDriveDownload size={14} />, label: t('acs.tabs.tasks') },
                    { id: 'rpc' as const, icon: <ScrollText size={14} />, label: t('acs.tabs.rpc') },
                  ]).map((def) => (
                    <button
                      key={def.id}
                      onClick={() => setTab(def.id)}
                      className={cn(
                        'flex items-center gap-1.5 border-b-2 px-3 py-2 text-[13px] transition-colors',
                        tab === def.id
                          ? 'border-accent text-text-primary'
                          : 'border-transparent text-text-secondary hover:text-text-primary',
                      )}
                    >
                      {def.icon}
                      {def.label}
                    </button>
                  ))}
                </div>

                {detailLoading ? (
                  <div className="flex justify-center py-12"><LoadingSpinner /></div>
                ) : tab === 'params' ? (
                  params === null ? (
                    <EndpointAbsent hint={t('acs.params.endpointAbsent')} />
                  ) : (
                    <>
                      <div className="flex flex-wrap items-center gap-2">
                        <input
                          type="text"
                          value={paramFilter}
                          onChange={(e) => setParamFilter(e.target.value)}
                          placeholder={t('acs.params.filterPlaceholder')}
                          className="min-w-0 flex-1 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 font-mono text-[12px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
                        />
                        <Button
                          variant="secondary"
                          size="sm"
                          disabled={busy}
                          onClick={() => void enqueue('GetParameterNames', {
                            paths: [selected.rootPrefix ?? ''],
                          })}
                        >
                          <ListTree size={14} className="mr-1.5" />
                          {t('acs.tasks.queueGpn')}
                        </Button>
                      </div>
                      <ParameterTree
                        parameters={params}
                        filter={paramFilter}
                        onEdit={(p) => setEditing(p)}
                      />
                    </>
                  )
                ) : tab === 'tasks' ? (
                  tasks === null ? (
                    <EndpointAbsent hint={t('acs.tasks.endpointAbsentHint')} />
                  ) : (
                    <TaskQueue tasks={tasks} dateFmt={dateFmt} busy={busy} onCancel={cancelTask} />
                  )
                ) : (
                  rpcLog === null ? (
                    <EndpointAbsent hint={t('acs.rpc.endpointAbsent')} />
                  ) : (
                    <RpcLogPanel view={rpcLog} dateFmt={dateFmt} />
                  )
                )}
              </>
            )}
          </div>
        </div>
      )}

      {editing && selected && (
        <SetValueDialog
          param={editing}
          busy={busy}
          onClose={() => setEditing(null)}
          onSubmit={(value) => {
            void enqueue('SetParameterValues', { values: { [editing.path]: value } });
            setEditing(null);
          }}
        />
      )}
    </div>
  );
}

// ── Pieces ──────────────────────────────────────────────────────────────────

function EndpointAbsent({ hint }: { hint: string }) {
  const { t } = useTranslation();
  return (
    <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
      <Unplug size={24} className="mx-auto mb-2 text-text-muted" />
      <p className="text-sm text-text-muted">{t('acs.endpointUnavailable')}</p>
      <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">{hint}</p>
    </div>
  );
}

function CpeHeader({ cpe }: { cpe: CwmpCpe }) {
  const { t } = useTranslation();
  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Link
          to={`/devices/${cpe.deviceId}`}
          className="font-display text-lg font-semibold text-text-primary hover:text-accent"
        >
          {anonHostname(cpe.deviceName ?? `#${cpe.deviceId}`)}
        </Link>
        {cpe.siteName && <span className="text-[12px] text-text-muted">{cpe.siteName}</span>}
      </div>
      <dl className="mt-2 grid gap-x-6 gap-y-1 text-[12px] sm:grid-cols-2 lg:grid-cols-3">
        <Field label={t('acs.field.cwmpId')} value={cpe.cwmpId || '—'} mono />
        <Field label={t('acs.field.dataModel')} value={cpe.dataModel ?? '—'} mono />
        <Field label={t('acs.field.rootPrefix')} value={cpe.rootPrefix ?? '—'} mono />
        <Field label={t('acs.field.cwmpVersion')} value={cpe.cwmpVersion ?? '—'} mono />
        <Field label={t('acs.field.software')} value={cpe.softwareVersion ?? '—'} mono />
        <Field label={t('acs.field.parameters')} value={String(cpe.parameterCount)} mono />
      </dl>
      {cpe.vendorQuirks.length > 0 && (
        <p className="mt-2 flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] uppercase tracking-wider text-text-muted">
            {t('acs.field.quirks')}
          </span>
          {cpe.vendorQuirks.map((q) => (
            <span
              key={q}
              className="rounded border border-status-ssl-warning/40 bg-status-ssl-warning/10 px-1.5 py-0.5 font-mono text-[10px] text-status-ssl-warning"
            >
              {q}
            </span>
          ))}
        </p>
      )}
    </section>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-2">
      <dt className="text-text-muted">{label}</dt>
      <dd className={cn('truncate text-text-secondary', mono && 'font-mono')} title={value}>{value}</dd>
    </div>
  );
}

function TaskQueue({
  tasks,
  dateFmt,
  busy,
  onCancel,
}: {
  tasks: CwmpTask[];
  dateFmt: Intl.DateTimeFormat;
  busy: boolean;
  onCancel: (task: CwmpTask) => void;
}) {
  const { t } = useTranslation();

  if (tasks.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
        <p className="text-sm text-text-muted">{t('acs.tasks.empty')}</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
      <table className="w-full min-w-[44rem] text-left text-[13px]">
        <thead className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
          <tr>
            <th className="px-3 py-2 font-medium">{t('acs.tasks.col.command')}</th>
            <th className="px-3 py-2 font-medium">{t('acs.tasks.col.summary')}</th>
            <th className="px-3 py-2 font-medium">{t('acs.tasks.col.state')}</th>
            <th className="px-3 py-2 font-medium">{t('acs.tasks.col.created')}</th>
            <th className="w-10 px-2 py-2" />
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {tasks.map((task) => (
            <tr key={task.id} className="hover:bg-bg-hover">
              <td className="px-3 py-2">
                <span className="font-mono text-[12px] text-text-primary">{task.command}</span>
                <span className="block truncate font-mono text-[10px] text-text-muted" title={task.commandKey}>
                  {task.commandKey}
                </span>
              </td>
              <td className="max-w-[18rem] px-3 py-2">
                <span className="block truncate font-mono text-[11px] text-text-secondary" title={task.summary ?? ''}>
                  {task.summary ?? '—'}
                </span>
                {task.faultCode && (
                  <span className="mt-0.5 block text-[11px] text-status-ssl-expired">
                    {task.faultCode}{task.faultString ? ` · ${task.faultString}` : ''}
                  </span>
                )}
              </td>
              <td className="px-3 py-2">
                <span
                  className={cn(
                    'inline-block rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
                    TASK_STATE_STYLES[task.state] ?? TASK_STATE_STYLES.queued,
                  )}
                  title={t(`acs.tasks.stateHint.${task.state}`, { defaultValue: '' })}
                >
                  {t(`acs.tasks.state.${task.state}`, { defaultValue: task.state })}
                </span>
                {task.attempts > 0 && (
                  <span className="ml-1 font-mono text-[10px] text-text-muted">
                    {t('acs.tasks.attempts', { count: task.attempts })}
                  </span>
                )}
              </td>
              <td className="px-3 py-2 font-mono text-[11px] text-text-muted">
                {task.createdAt ? dateFmt.format(new Date(task.createdAt)) : '—'}
              </td>
              <td className="px-2 py-2">
                {(task.state === 'queued' || task.state === 'sent') && (
                  <button
                    onClick={() => onCancel(task)}
                    disabled={busy}
                    title={t('acs.tasks.cancel')}
                    className="rounded p-1 text-text-muted hover:bg-bg-hover hover:text-status-ssl-expired disabled:opacity-40"
                  >
                    <Ban size={12} />
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RpcLogPanel({ view, dateFmt }: { view: CwmpRpcLogView; dateFmt: Intl.DateTimeFormat }) {
  const { t } = useTranslation();

  // §3.6 — capture is DISABLED by default. An empty log means two opposite
  // things depending on this flag, and only one of them is a problem.
  if (!view.enabled) {
    return (
      <div className="rounded-lg border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-4">
        <p className="text-sm font-medium text-status-ssl-warning">{t('acs.rpc.disabled')}</p>
        <p className="mt-1 text-[12px] text-text-secondary">{t('acs.rpc.disabledHint')}</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <p className="text-[11px] text-text-muted">
        {view.retentionDays
          ? t('acs.rpc.retention', { days: view.retentionDays })
          : t('acs.rpc.retentionUnknown')}
      </p>
      {view.entries.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
          <p className="text-sm text-text-muted">{t('acs.rpc.empty')}</p>
        </div>
      ) : (
        <ul className="space-y-1.5">
          {view.entries.map((entry) => {
            // A SOAP envelope for SetParameterValues literally contains the
            // values that were set. Scan before painting — §8.2.
            const hits = entry.bodyExcerpt ? scanTextForSecrets(entry.bodyExcerpt, 2) : [];
            return (
              <li key={entry.id} className="rounded-md border border-border bg-bg-secondary p-2">
                <div className="flex flex-wrap items-center gap-2 text-[11px]">
                  <span className="font-mono text-text-muted">
                    {entry.at ? dateFmt.format(new Date(entry.at)) : '—'}
                  </span>
                  <span
                    className={cn(
                      'rounded border px-1.5 py-0.5 font-mono text-[10px]',
                      entry.direction === 'acs_to_cpe'
                        ? 'border-accent/40 bg-accent/10 text-accent'
                        : 'border-border bg-bg-tertiary text-text-secondary',
                    )}
                  >
                    {t(`acs.rpc.direction.${entry.direction}`)}
                  </span>
                  <span className="font-mono text-text-primary">{entry.rpc}</span>
                  {entry.httpStatus !== null && (
                    <span className="font-mono text-text-muted">HTTP {entry.httpStatus}</span>
                  )}
                  {entry.faultCode && (
                    <span className="rounded border border-status-ssl-expired/60 bg-status-ssl-expired/15 px-1.5 py-0.5 text-[10px] text-status-ssl-expired">
                      {entry.faultCode}
                    </span>
                  )}
                </div>
                {entry.bodyExcerpt && (
                  hits.length > 0 ? (
                    <p className="mt-1 inline-flex items-center gap-1.5 rounded border border-status-ssl-expired/60 bg-status-ssl-expired/15 px-2 py-1 text-[11px] text-status-ssl-expired">
                      <ShieldAlert size={12} />
                      {t('acs.rpc.secretRedacted', { keys: hits.map((h) => h.label).join(', ') })}
                    </p>
                  ) : (
                    <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] text-text-secondary">
                      {entry.bodyExcerpt}
                    </pre>
                  )
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function FirmwarePanel({
  files,
  dateFmt,
  disabled,
  selectedFamily,
  onPush,
  onRemove,
}: {
  files: CwmpFile[] | null;
  dateFmt: Intl.DateTimeFormat;
  disabled: boolean;
  selectedFamily: DeviceFamily | null;
  onPush: (file: CwmpFile) => void;
  onRemove: (file: CwmpFile) => void;
}) {
  const { t } = useTranslation();

  return (
    <section className="rounded-lg border border-border bg-bg-secondary">
      <h2 className="flex items-center gap-1.5 border-b border-border px-3 py-2 text-sm font-semibold text-text-primary">
        <FileDown size={14} className="text-text-muted" />
        {t('acs.firmware.title')}
      </h2>
      {files === null ? (
        <p className="px-3 py-4 text-[12px] text-text-muted">{t('acs.firmware.endpointAbsent')}</p>
      ) : files.length === 0 ? (
        <p className="px-3 py-4 text-[12px] text-text-muted">{t('acs.firmware.empty')}</p>
      ) : (
        <ul className="divide-y divide-border">
          {files.map((file) => {
            // Pushing a Vigor image to a Zyxel is a brick. "The operator will
            // be careful" is not a safety mechanism, so a mismatch disables the
            // button and says which family the image is for.
            const compatible = selectedFamily !== null
              && file.families.length > 0
              && file.families.includes(selectedFamily);
            return (
              <li key={file.id} className="px-3 py-2">
                <div className="flex items-start gap-2">
                  <div className="min-w-0 flex-1">
                    <span className="block truncate text-[13px] text-text-primary" title={file.name}>
                      {file.name}
                    </span>
                    <span className="block font-mono text-[10px] text-text-muted">
                      {file.version ?? '—'}
                      {file.sizeBytes ? ` · ${Math.round(file.sizeBytes / 1024)} kB` : ''}
                      {file.uploadedAt ? ` · ${dateFmt.format(new Date(file.uploadedAt))}` : ''}
                    </span>
                    <span className="mt-0.5 block font-mono text-[10px] text-text-muted">
                      {file.families.length > 0 ? file.families.join(' · ') : t('acs.firmware.noFamily')}
                    </span>
                  </div>
                  <button
                    onClick={() => onRemove(file)}
                    title={t('common.delete')}
                    className="shrink-0 rounded p-1 text-text-muted hover:bg-bg-hover hover:text-status-ssl-expired"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
                <Button
                  variant="secondary"
                  size="sm"
                  className="mt-1.5 w-full"
                  disabled={disabled || !compatible}
                  title={compatible ? undefined : t('acs.firmware.incompatible')}
                  onClick={() => onPush(file)}
                >
                  <HardDriveDownload size={13} className="mr-1.5" />
                  {t('acs.firmware.queueDownload')}
                </Button>
              </li>
            );
          })}
        </ul>
      )}
      <p className="border-t border-border px-3 py-2 text-[11px] text-text-muted">
        {t('acs.firmware.hint')}
      </p>
    </section>
  );
}

/**
 * SetParameterValues, for one leaf.
 *
 * The input is `type="password"` whenever the leaf is a redacted one, the value
 * is held in local state for exactly as long as the dialog is open, and it is
 * never written back into the task list — `normalizeTask` summarises an SPV by
 * its PATHS. §8.2 makes that a rule and not a nicety: an SPV on
 * `...WANPPPConnection.1.Password` is precisely the material the last audit
 * found leaking.
 */
function SetValueDialog({
  param,
  busy,
  onClose,
  onSubmit,
}: {
  param: CwmpParameter;
  busy: boolean;
  onClose: () => void;
  onSubmit: (value: string) => void;
}) {
  const { t } = useTranslation();
  const [value, setValue] = useState('');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-lg rounded-lg border border-border bg-bg-secondary p-4 shadow-xl">
        <div className="mb-3 flex items-start justify-between gap-2">
          <h2 className="text-sm font-semibold text-text-primary">{t('acs.spv.title')}</h2>
          <button onClick={onClose} className="rounded p-1 text-text-muted hover:bg-bg-hover hover:text-text-primary">
            <X size={14} />
          </button>
        </div>

        <p className="mb-2 break-all rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 font-mono text-[11px] text-text-secondary">
          {param.path}
        </p>

        <label className="block text-[12px] text-text-secondary" htmlFor="acs-spv-value">
          {t('acs.spv.newValue')}
        </label>
        <input
          id="acs-spv-value"
          type={param.redacted ? 'password' : 'text'}
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className="mt-1 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 font-mono text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
        />

        {param.redacted && (
          <p className="mt-1.5 flex items-start gap-1.5 text-[11px] text-status-ssl-warning">
            <ShieldAlert size={12} className="mt-0.5 shrink-0" />
            {t('acs.spv.secretNotice')}
          </p>
        )}

        <p className="mt-2 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[11px] text-text-muted">
          {t('acs.spv.queueNotice')}
        </p>

        <div className="mt-3 flex justify-end gap-2">
          <Button variant="secondary" size="sm" onClick={onClose}>{t('common.cancel')}</Button>
          <Button
            variant="primary"
            size="sm"
            loading={busy}
            disabled={value.length === 0}
            onClick={() => onSubmit(value)}
          >
            {t('acs.spv.queue')}
          </Button>
        </div>
      </div>
    </div>
  );
}
