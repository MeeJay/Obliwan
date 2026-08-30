import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Download,
  FileCode,
  FileText,
  GitCompareArrows,
  ListTree,
  RotateCw,
  Unplug,
} from 'lucide-react';
import type { NcmDocumentStored } from '@obliwan/shared';
import { configApi } from '@/api/config.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { DiffViewer } from '@/components/common/DiffViewer';
import { ConfigDiff } from '@/components/config/ConfigDiff';
import { NcmTree } from '@/components/config/NcmTree';
import { cn } from '@/utils/cn';
import { compareSnapshots } from '@/utils/ncmCompare';
import type {
  ConfigSnapshotDetail,
  ConfigSnapshotSummary,
  SnapshotRawText,
} from '@/types/config';

/**
 * The configuration screen for ONE device — the body of `ConfigPage` and of the
 * `Configuration` tab of `DeviceDetailPage`, which is why it is a component and
 * not a page: spec §4.2 lists the same four things in both places (snapshots,
 * N/N-1 comparison, NCM tree, export) and two implementations of that would
 * drift apart within a milestone.
 *
 * ── THE SNAPSHOT LIST TELLS THE TRUTH ABOUT DEDUPLICATION ───────────────────
 * `UNIQUE(device_id, ncm_hash)` means a router nobody touched inserts NOTHING
 * and bumps `last_seen_at`/`seen_count` instead. A list that showed only
 * `captured_at` would therefore look like a collector that stopped working on a
 * stable fleet — which is the opposite of what it means. Every row states "seen
 * N times, last confirmed at T", and that is the whole value of the constraint
 * made visible.
 *
 * ── THE COMPARISON IS SEMANTIC FIRST, TEXTUAL SECOND ────────────────────────
 * Same ordering as the drift screen and for the same reason (D1): the semantic
 * diff is the truth, the text is the readable complement. The text is loaded
 * only when asked for — `raw_gz` is the archive of reference, not something to
 * pull down on every snapshot click.
 */

export interface DeviceConfigTabProps {
  deviceId: number;
  deviceName?: string | null;
  className?: string;
}

type View = 'tree' | 'compare' | 'raw';

function shortHash(h: string): string {
  return h ? h.slice(0, 12) : '—';
}

function formatBytes(n: number | null): string {
  if (n === null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** Browser download of a string. Kept here rather than in a util because it is
 *  three lines and has exactly one caller family. */
function download(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function DeviceConfigTab({ deviceId, deviceName, className }: DeviceConfigTabProps) {
  const { t, i18n } = useTranslation();

  const [snapshots, setSnapshots] = useState<ConfigSnapshotSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [againstId, setAgainstId] = useState<number | null>(null);
  const [view, setView] = useState<View>('tree');

  // Documents and raw texts are cached per snapshot id: a snapshot is immutable
  // by construction (its identity IS its hash), so re-fetching one the operator
  // already opened can only cost time.
  const [details, setDetails] = useState<Record<number, ConfigSnapshotDetail>>({});
  const [raws, setRaws] = useState<Record<number, SnapshotRawText | null>>({});
  const [busy, setBusy] = useState(false);
  const [rawUnavailable, setRawUnavailable] = useState(false);
  const inflight = useRef<Set<number>>(new Set());

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' }),
    [i18n.language],
  );
  const when = useCallback(
    (iso: string | null) => {
      if (!iso) return '—';
      const d = new Date(iso);
      return Number.isNaN(d.getTime()) ? '—' : dateFmt.format(d);
    },
    [dateFmt],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await configApi.forDevice(deviceId);
      if (rows === null) {
        setUnavailable(true);
        setSnapshots([]);
      } else {
        setUnavailable(false);
        setSnapshots(rows);
        // Newest is selected, and the one before it is the comparison base:
        // "what changed since last time" is the question this screen is opened
        // with, so it must be answered before anybody clicks anything.
        setSelectedId(rows[0]?.id ?? null);
        setAgainstId(rows[1]?.id ?? null);
      }
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setError(message ?? t('config.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [deviceId, t]);

  useEffect(() => { void load(); }, [load]);

  const fetchDetail = useCallback(async (id: number) => {
    if (details[id] || inflight.current.has(id)) return;
    inflight.current.add(id);
    setBusy(true);
    try {
      const detail = await configApi.getSnapshot(id);
      if (detail) setDetails((prev) => ({ ...prev, [id]: detail }));
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setError(message ?? t('config.loadFailed'));
    } finally {
      inflight.current.delete(id);
      setBusy(false);
    }
  }, [details, t]);

  useEffect(() => {
    if (selectedId !== null) void fetchDetail(selectedId);
  }, [selectedId, fetchDetail]);

  useEffect(() => {
    if (view === 'compare' && againstId !== null) void fetchDetail(againstId);
  }, [view, againstId, fetchDetail]);

  /** Returns the text as well as caching it: the export button needs the value
   *  it just fetched, and reading it back out of `raws` inside the same click
   *  handler would read the pre-fetch render's copy and silently download
   *  nothing. */
  const fetchRaw = useCallback(async (id: number): Promise<SnapshotRawText | null> => {
    if (id in raws) return raws[id];
    setBusy(true);
    try {
      const raw = await configApi.getRaw(id);
      setRaws((prev) => ({ ...prev, [id]: raw }));
      if (raw === null) setRawUnavailable(true);
      return raw;
    } catch {
      setRaws((prev) => ({ ...prev, [id]: null }));
      setRawUnavailable(true);
      return null;
    } finally {
      setBusy(false);
    }
  }, [raws]);

  useEffect(() => {
    if (view === 'raw' && selectedId !== null) void fetchRaw(selectedId);
  }, [view, selectedId, fetchRaw]);

  const selected = selectedId !== null ? snapshots.find((s) => s.id === selectedId) ?? null : null;
  const selectedDetail = selectedId !== null ? details[selectedId] ?? null : null;
  const againstDetail = againstId !== null ? details[againstId] ?? null : null;

  const comparison = useMemo(() => {
    if (!selectedDetail || !againstDetail) return null;
    // Older document on the left, newer on the right — the same orientation the
    // drift engine uses, so one legend covers both panels.
    const a = new Date(againstDetail.capturedAt).getTime();
    const b = new Date(selectedDetail.capturedAt).getTime();
    const [before, after] = a <= b
      ? [againstDetail, selectedDetail]
      : [selectedDetail, againstDetail];
    return {
      before,
      after,
      set: compareSnapshots(
        before.ncm as NcmDocumentStored | null,
        after.ncm as NcmDocumentStored | null,
      ),
    };
  }, [selectedDetail, againstDetail]);

  const changedKeys = useMemo(
    () => new Set(comparison?.set.changes.map((c) => c.semKey) ?? []),
    [comparison],
  );

  // ── states ────────────────────────────────────────────────────────────────

  if (unavailable) {
    return (
      <div className={cn('rounded-lg border border-border bg-bg-secondary py-16 text-center', className)}>
        <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{t('config.endpointUnavailable')}</p>
        <p className="mx-auto mt-1 max-w-lg text-xs text-text-muted">
          {t('config.endpointUnavailableHint')}
        </p>
      </div>
    );
  }

  if (loading && snapshots.length === 0) {
    return <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>;
  }

  if (snapshots.length === 0) {
    return (
      <div className={cn('rounded-lg border border-border bg-bg-secondary py-16 text-center', className)}>
        <FileCode size={28} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{t('config.empty')}</p>
        <p className="mt-1 text-xs text-text-muted">{t('config.emptyHint')}</p>
        <Button variant="secondary" size="sm" className="mt-4" onClick={() => void load()}>
          <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
          {t('devices.refresh')}
        </Button>
      </div>
    );
  }

  return (
    <div className={cn('grid gap-4 lg:grid-cols-[20rem_1fr]', className)}>
      {/* ── snapshot list ── */}
      <aside className="rounded-lg border border-border bg-bg-secondary">
        <div className="flex items-center gap-2 border-b border-border px-3 py-2">
          <h3 className="text-sm font-semibold text-text-primary">{t('config.snapshots')}</h3>
          <span className="font-mono text-[11px] text-text-muted">{snapshots.length}</span>
          <button
            onClick={() => void load()}
            title={t('devices.refresh')}
            className="ml-auto rounded p-1 text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            <RotateCw size={13} className={cn(loading && 'animate-spin')} />
          </button>
        </div>
        <ul className="max-h-[70vh] divide-y divide-border overflow-auto">
          {snapshots.map((s) => (
            <li key={s.id}>
              <button
                onClick={() => setSelectedId(s.id)}
                className={cn(
                  'w-full px-3 py-2 text-left hover:bg-bg-hover',
                  selectedId === s.id && 'bg-accent/10',
                )}
              >
                <div className="flex items-center gap-2">
                  <span className="text-[13px] text-text-primary">{when(s.capturedAt)}</span>
                  <span className="ml-auto rounded border border-border bg-bg-tertiary px-1.5 py-0.5 font-mono text-[10px] text-text-muted">
                    {t(`config.source.${s.source}`)}
                  </span>
                </div>
                <div className="mt-0.5 flex items-center gap-2">
                  <span className="font-mono text-[10px] text-text-muted">{shortHash(s.ncmHash)}</span>
                  {s.seenCount > 1 && (
                    <span
                      className="font-mono text-[10px] text-text-muted"
                      title={t('config.seenHint', { at: when(s.lastSeenAt) })}
                    >
                      ×{s.seenCount}
                    </span>
                  )}
                  {s.orderAnalysis !== 'full' && (
                    <span className="rounded border border-status-ssl-warning/40 bg-status-ssl-warning/10 px-1 py-0.5 text-[9px] uppercase text-status-ssl-warning">
                      {t(`ncm.orderAnalysis.${s.orderAnalysis}`)}
                    </span>
                  )}
                </div>
              </button>
            </li>
          ))}
        </ul>
      </aside>

      {/* ── selected snapshot ── */}
      <div className="min-w-0 space-y-4">
        {error && (
          <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-3 text-sm text-status-ssl-expired">
            {error}
          </div>
        )}

        {selected && (
          <section className="rounded-lg border border-border bg-bg-secondary p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-text-primary">
                  {deviceName ? `${deviceName} — ` : ''}{when(selected.capturedAt)}
                </h2>
                <p className="mt-0.5 font-mono text-[11px] text-text-muted">
                  {t('config.meta.hash')} {shortHash(selected.ncmHash)} ·
                  {' '}{t('config.meta.ncmVersion')} {selected.ncmVersion} ·
                  {' '}{t('config.meta.semKeyGeneration')} {selected.semKeyGeneration} ·
                  {' '}{t('config.meta.epoch')} {selected.normalizationEpoch || '—'}
                </p>
                <p className="mt-0.5 text-[11px] text-text-muted">
                  {t('config.meta.seen', { count: selected.seenCount, at: when(selected.lastSeenAt) })}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  disabled={!selectedDetail?.ncm}
                  onClick={() => {
                    if (!selectedDetail?.ncm) return;
                    download(
                      `ncm-${deviceId}-${shortHash(selected.ncmHash)}.json`,
                      JSON.stringify(selectedDetail.ncm, null, 2),
                      'application/json',
                    );
                  }}
                >
                  <Download size={14} className="mr-1.5" />
                  {t('config.exportNcm')}
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    void (async () => {
                      const raw = await fetchRaw(selected.id);
                      if (raw?.text) {
                        download(
                          `export-${deviceId}-${shortHash(selected.ncmHash)}.rsc`,
                          raw.text,
                          'text/plain',
                        );
                      }
                    })();
                  }}
                >
                  <Download size={14} className="mr-1.5" />
                  {t('config.exportRaw')}
                </Button>
              </div>
            </div>

            <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 text-[12px] md:grid-cols-4">
              <Meta label={t('config.meta.osVersion')} value={selected.osVersion ?? '—'} />
              <Meta label={t('config.meta.model')} value={selected.model ?? '—'} />
              <Meta label={t('config.meta.rawSize')} value={formatBytes(selected.rawBytes)} />
              <Meta
                label={t('config.meta.orderAnalysis')}
                value={t(`ncm.orderAnalysis.${selected.orderAnalysis}`)}
                tone={selected.orderAnalysis === 'full' ? undefined : 'warn'}
              />
            </dl>

            {selected.unmodeledForwardingCount > 0 && (
              <p className="mt-3 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 px-3 py-2 text-[12px] text-status-ssl-warning">
                {t('config.unmodeledForwarding', { count: selected.unmodeledForwardingCount })}
              </p>
            )}
          </section>
        )}

        {/* view switch */}
        <div className="flex flex-wrap items-center gap-1 border-b border-border">
          <ViewTab active={view === 'tree'} onClick={() => setView('tree')} icon={<ListTree size={14} />}>
            {t('config.view.tree')}
          </ViewTab>
          <ViewTab
            active={view === 'compare'}
            onClick={() => setView('compare')}
            icon={<GitCompareArrows size={14} />}
          >
            {t('config.view.compare')}
          </ViewTab>
          <ViewTab active={view === 'raw'} onClick={() => setView('raw')} icon={<FileText size={14} />}>
            {t('config.view.raw')}
          </ViewTab>
          {busy && <LoadingSpinner size="sm" />}
        </div>

        {view === 'tree' && (
          <NcmTree
            document={(selectedDetail?.ncm as NcmDocumentStored | null) ?? null}
            highlighted={changedKeys}
          />
        )}

        {view === 'compare' && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-secondary px-3 py-2">
              <span className="text-[12px] text-text-muted">{t('config.compareAgainst')}</span>
              <select
                value={againstId ?? ''}
                onChange={(e) => setAgainstId(e.target.value === '' ? null : Number(e.target.value))}
                className="rounded-md border border-border bg-bg-tertiary px-2 py-1 text-[12px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              >
                <option value="">{t('config.compareNone')}</option>
                {snapshots
                  .filter((s) => s.id !== selectedId)
                  .map((s) => (
                    <option key={s.id} value={s.id}>
                      {when(s.capturedAt)} — {shortHash(s.ncmHash)}
                    </option>
                  ))}
              </select>
            </div>

            {!comparison ? (
              <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center text-sm text-text-muted">
                {againstId === null ? t('config.compareHint') : t('common.loading')}
              </div>
            ) : comparison.before.ncmHash === comparison.after.ncmHash ? (
              <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
                <p className="text-sm text-text-muted">{t('config.identicalHash')}</p>
                <p className="mt-1 text-xs text-text-muted">{t('config.identicalHashHint')}</p>
              </div>
            ) : (
              <>
                <ConfigDiff
                  set={comparison.set}
                  beforeLabel={when(comparison.before.capturedAt)}
                  afterLabel={when(comparison.after.capturedAt)}
                />
                <RawComparison
                  before={comparison.before}
                  after={comparison.after}
                  raws={raws}
                  onNeed={fetchRaw}
                  unavailable={rawUnavailable}
                  labelBefore={when(comparison.before.capturedAt)}
                  labelAfter={when(comparison.after.capturedAt)}
                />
              </>
            )}
          </div>
        )}

        {view === 'raw' && selected && (
          <RawPanel raw={selectedId !== null ? raws[selectedId] : undefined} />
        )}
      </div>
    </div>
  );
}

// ── pieces ──────────────────────────────────────────────────────────────────

function Meta({ label, value, tone }: { label: string; value: string; tone?: 'warn' }) {
  return (
    <div>
      <dt className="text-[10px] uppercase tracking-wider text-text-muted">{label}</dt>
      <dd className={cn('mt-0.5 font-mono text-[12px]', tone === 'warn' ? 'text-status-ssl-warning' : 'text-text-primary')}>
        {value}
      </dd>
    </div>
  );
}

function ViewTab({
  active,
  onClick,
  icon,
  children,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex items-center gap-1.5 border-b-2 px-3 py-2 text-[13px] transition-colors',
        active ? 'border-accent text-text-primary' : 'border-transparent text-text-secondary hover:text-text-primary',
      )}
    >
      {icon}
      {children}
    </button>
  );
}

function RawPanel({ raw }: { raw: SnapshotRawText | null | undefined }) {
  const { t } = useTranslation();
  if (raw === undefined) {
    return <div className="flex justify-center py-12"><LoadingSpinner size="md" /></div>;
  }
  if (raw === null) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
        <Unplug size={24} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{t('config.rawUnavailable')}</p>
      </div>
    );
  }
  if (!raw.text) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
        <p className="text-sm text-text-muted">{t('config.rawEmpty')}</p>
        <p className="mt-1 text-xs text-text-muted">{t('config.rawEmptyHint')}</p>
      </div>
    );
  }
  // Rendered through DiffViewer with an empty left side so the raw export gets
  // the SAME secret scan every diff gets. A separate <pre> here would be one
  // more surface where a leak could reach a screen unchecked.
  return (
    <DiffViewer
      left=""
      right={raw.text}
      leftLabel={t('config.rawNothing')}
      rightLabel={t('config.rawExport')}
      defaultMode="unified"
      context={0}
      bodyClassName="max-h-[70vh]"
    />
  );
}

function RawComparison({
  before,
  after,
  raws,
  onNeed,
  unavailable,
  labelBefore,
  labelAfter,
}: {
  before: ConfigSnapshotSummary;
  after: ConfigSnapshotSummary;
  raws: Record<number, SnapshotRawText | null>;
  onNeed: (id: number) => Promise<SnapshotRawText | null>;
  unavailable: boolean;
  labelBefore: string;
  labelAfter: string;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const a = raws[before.id];
  const b = raws[after.id];

  if (unavailable) return null;

  if (!open) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary px-3 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <FileText size={14} className="text-text-muted" />
          <span className="text-[12px] text-text-muted">{t('config.textualHint')}</span>
          <Button
            variant="secondary"
            size="sm"
            className="ml-auto"
            onClick={() => {
              setOpen(true);
              void onNeed(before.id);
              void onNeed(after.id);
            }}
          >
            {t('config.showTextual')}
          </Button>
        </div>
      </div>
    );
  }

  if (a === undefined || b === undefined) {
    return <div className="flex justify-center py-8"><LoadingSpinner size="md" /></div>;
  }
  if (a === null || b === null || (!a.text && !b.text)) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-8 text-center text-sm text-text-muted">
        {t('config.rawUnavailable')}
      </div>
    );
  }
  return (
    <DiffViewer
      left={a.text}
      right={b.text}
      leftLabel={labelBefore}
      rightLabel={labelAfter}
      defaultMode="unified"
      identicalLabel={t('config.textualIdentical')}
    />
  );
}
