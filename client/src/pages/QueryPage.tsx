import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  BookmarkPlus,
  ChevronDown,
  ChevronRight,
  Download,
  FileJson,
  Play,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Unplug,
} from 'lucide-react';
import { CAPABILITIES } from '@obliwan/shared';
import {
  downloadText,
  queryApi,
  queryErrorOf,
  resultToCsv,
  resultToJson,
} from '@/api/query.api';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { QueryEditor } from '@/components/query/QueryEditor';
import { EXAMPLE_QUERIES } from '@/components/query/ncmSchema';
import { scanValueForSecrets } from '@/utils/secretScan';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import type { PolicySeverity, QueryError, QueryResult, QueryRow, SavedQuery } from '@/types/query';
import { POLICY_SEVERITIES } from '@/types/query';

/**
 * `QueryPage` — Fleet Query (M9, killer K5).
 *
 * ┌─ THE THREE THINGS THIS SCREEN REFUSES TO ROUND OFF ──────────────────────┐
 * │ 1. "12 matched" is never shown without "of N examined". A fleet answer   │
 * │    with no denominator is a number, not an audit.                        │
 * │ 2. A TRUNCATED result is labelled, loudly, and the label travels into    │
 * │    the CSV and the JSON. An export that silently dropped rows certifies  │
 * │    boxes nobody looked at.                                               │
 * │ 3. Devices with NO SNAPSHOT are counted separately and never folded into │
 * │    "no match". Never-collected and clean are different facts, and only   │
 * │    one of them is good news.                                             │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── DRILL-DOWN IS THE POINT ─────────────────────────────────────────────────
 * §5/M9 asks for "résultats drill-down". A row expands to the RESOURCES that
 * matched — the actual firewall rule, the actual service entry — because
 * "device X has an any/any rule" is not actionable until you can see which
 * rule. Every expanded value is scanned for secrets before it is painted
 * (§8.2): the NCM stores fingerprints rather than values, but `extensions`
 * carries unversioned brand data and that door is open by construction.
 *
 * ── SAVING AND PROMOTING ────────────────────────────────────────────────────
 * A saved query becomes a POLICY evaluated at every snapshot. The promotion
 * never re-sends the DSL text: a policy whose expression drifted from the query
 * it was promoted from is a policy nobody reviewed.
 */

export function QueryPage() {
  const { t, i18n } = useTranslation();
  const { hasCapability, isAdmin } = useAuthStore();
  const canRun = isAdmin() || hasCapability(CAPABILITIES.QUERY_RUN);

  const [dsl, setDsl] = useState('');
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState<QueryError | null>(null);
  const [running, setRunning] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const [saved, setSaved] = useState<SavedQuery[] | null>(null);
  const [saveName, setSaveName] = useState('');
  const [saveAsPolicy, setSaveAsPolicy] = useState(false);
  const [saveSeverity, setSaveSeverity] = useState<PolicySeverity>('warning');
  const [notice, setNotice] = useState<string | null>(null);

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' }),
    [i18n.language],
  );

  const loadSaved = useCallback(async () => {
    try {
      setSaved(await queryApi.listSaved());
    } catch {
      setSaved(null);
    }
  }, []);

  useEffect(() => { void loadSaved(); }, [loadSaved]);

  const run = useCallback(async () => {
    if (!dsl.trim()) return;
    setRunning(true);
    setError(null);
    setNotice(null);
    try {
      const res = await queryApi.run(dsl.trim());
      if (res === null) { setUnavailable(true); setResult(null); }
      else { setUnavailable(false); setResult(res); setExpanded(new Set()); }
    } catch (err) {
      setError(queryErrorOf(err));
      setResult(null);
    } finally {
      setRunning(false);
    }
  }, [dsl]);

  const check = useCallback(async () => {
    if (!dsl.trim()) return;
    setError(await queryApi.validate(dsl.trim()));
  }, [dsl]);

  const save = useCallback(async () => {
    if (!saveName.trim() || !dsl.trim()) return;
    setNotice(null);
    try {
      const row = await queryApi.save({
        name: saveName.trim(),
        dsl: dsl.trim(),
        isPolicy: saveAsPolicy,
        severity: saveSeverity,
      });
      if (row === null) { setNotice(t('query.saveEndpointAbsent')); return; }
      setSaveName('');
      await loadSaved();
    } catch (err) {
      setNotice(queryErrorOf(err).message);
    }
  }, [saveName, dsl, saveAsPolicy, saveSeverity, loadSaved, t]);

  const togglePolicy = useCallback(async (row: SavedQuery) => {
    setNotice(null);
    try {
      const updated = await queryApi.setPolicy(row.id, !row.isPolicy, row.severity);
      if (updated === null) { setNotice(t('query.policyEndpointAbsent')); return; }
      await loadSaved();
    } catch (err) {
      setNotice(queryErrorOf(err).message);
    }
  }, [loadSaved, t]);

  const remove = useCallback(async (row: SavedQuery) => {
    setNotice(null);
    try {
      if (!(await queryApi.remove(row.id))) { setNotice(t('query.saveEndpointAbsent')); return; }
      await loadSaved();
    } catch (err) {
      setNotice(queryErrorOf(err).message);
    }
  }, [loadSaved, t]);

  const toggleRow = useCallback((deviceId: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(deviceId)) next.delete(deviceId); else next.add(deviceId);
      return next;
    });
  }, []);

  if (!canRun) {
    return (
      <div className="p-6">
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <ShieldAlert size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('query.forbidden')}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="mb-5">
        <h1 className="font-display text-2xl font-semibold text-text-primary">{t('nav.query')}</h1>
        <p className="mt-1 text-sm text-text-muted">{t('query.subtitle')}</p>
      </div>

      <div className="grid gap-4 xl:grid-cols-[2fr_1fr]">
        <div className="min-w-0 space-y-4">
          <QueryEditor
            value={dsl}
            onChange={setDsl}
            onRun={() => void run()}
            error={error}
            disabled={running}
          />

          <div className="flex flex-wrap items-center gap-2">
            <Button variant="primary" size="sm" loading={running} disabled={!dsl.trim()} onClick={() => void run()}>
              <Play size={14} className="mr-1.5" />
              {t('query.run')}
            </Button>
            <Button variant="secondary" size="sm" disabled={!dsl.trim()} onClick={() => void check()}>
              <ShieldCheck size={14} className="mr-1.5" />
              {t('query.check')}
            </Button>
            {result && (
              <>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => downloadText('fleet-query.csv', 'text/csv', resultToCsv(result))}
                >
                  <Download size={14} className="mr-1.5" />
                  {t('query.exportCsv')}
                </Button>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => downloadText('fleet-query.json', 'application/json', resultToJson(result, dsl))}
                >
                  <FileJson size={14} className="mr-1.5" />
                  {t('query.exportJson')}
                </Button>
              </>
            )}
          </div>

          {/* The three acceptance queries of §5/M9, one click away. */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] uppercase tracking-wider text-text-muted">
              {t('query.examples')}
            </span>
            {EXAMPLE_QUERIES.map((ex) => (
              <button
                key={ex.key}
                onClick={() => setDsl(ex.dsl)}
                className="rounded-md border border-border bg-bg-tertiary px-2 py-1 text-[12px] text-text-secondary hover:bg-bg-hover hover:text-text-primary"
              >
                {t(`query.example.${ex.key}`)}
              </button>
            ))}
          </div>

          {notice && (
            <p className="rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 px-3 py-2 text-[12px] text-status-ssl-warning">
              {notice}
            </p>
          )}

          {unavailable ? (
            <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
              <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
              <p className="text-sm text-text-muted">{t('query.endpointUnavailable')}</p>
              <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
                {t('query.endpointUnavailableHint')}
              </p>
            </div>
          ) : running && !result ? (
            <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
          ) : result ? (
            <ResultPanel
              result={result}
              expanded={expanded}
              onToggleRow={toggleRow}
              dateFmt={dateFmt}
            />
          ) : (
            <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
              <Search size={28} className="mx-auto mb-2 text-text-muted" />
              <p className="text-sm text-text-muted">{t('query.noResultYet')}</p>
              <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">{t('query.snapshotCaveat')}</p>
            </div>
          )}
        </div>

        {/* ── saved queries and policies ── */}
        <aside className="space-y-3">
          <section className="rounded-lg border border-border bg-bg-secondary p-3">
            <h2 className="mb-2 text-sm font-semibold text-text-primary">{t('query.saveTitle')}</h2>
            <input
              type="text"
              value={saveName}
              onChange={(e) => setSaveName(e.target.value)}
              placeholder={t('query.savePlaceholder')}
              className="w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
            />
            <label className="mt-2 flex items-center gap-2 text-[12px] text-text-secondary">
              <input
                type="checkbox"
                checked={saveAsPolicy}
                onChange={(e) => setSaveAsPolicy(e.target.checked)}
                className="accent-accent"
              />
              {t('query.promoteToPolicy')}
            </label>
            {saveAsPolicy && (
              <select
                value={saveSeverity}
                onChange={(e) => setSaveSeverity(e.target.value as PolicySeverity)}
                className="mt-2 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              >
                {POLICY_SEVERITIES.map((s) => (
                  <option key={s} value={s}>{t(`query.severity.${s}`)}</option>
                ))}
              </select>
            )}
            <p className="mt-1.5 text-[11px] text-text-muted">{t('query.policyHint')}</p>
            <Button
              variant="secondary"
              size="sm"
              className="mt-2 w-full"
              disabled={!saveName.trim() || !dsl.trim()}
              onClick={() => void save()}
            >
              <BookmarkPlus size={14} className="mr-1.5" />
              {t('query.save')}
            </Button>
          </section>

          <section className="rounded-lg border border-border bg-bg-secondary">
            <h2 className="border-b border-border px-3 py-2 text-sm font-semibold text-text-primary">
              {t('query.savedTitle')}
            </h2>
            {saved === null ? (
              <p className="px-3 py-4 text-[12px] text-text-muted">{t('query.savedUnavailable')}</p>
            ) : saved.length === 0 ? (
              <p className="px-3 py-4 text-[12px] text-text-muted">{t('query.savedEmpty')}</p>
            ) : (
              <ul className="divide-y divide-border">
                {saved.map((row) => (
                  <li key={row.id} className="px-3 py-2">
                    <div className="flex items-start gap-2">
                      <button
                        onClick={() => { setDsl(row.dsl); setError(null); }}
                        className="min-w-0 flex-1 text-left"
                      >
                        <span className="block truncate text-[13px] text-text-primary hover:text-accent">
                          {row.name}
                        </span>
                        <span className="block truncate font-mono text-[10px] text-text-muted">
                          {row.dsl}
                        </span>
                      </button>
                      <button
                        onClick={() => void remove(row)}
                        title={t('query.delete')}
                        className="shrink-0 rounded p-1 text-text-muted hover:bg-bg-hover hover:text-status-ssl-expired"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5">
                      <button
                        onClick={() => void togglePolicy(row)}
                        className={cn(
                          'rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
                          row.isPolicy
                            ? 'border-accent/50 bg-accent/10 text-accent'
                            : 'border-border bg-bg-tertiary text-text-muted',
                        )}
                      >
                        {row.isPolicy ? t('query.isPolicy') : t('query.notPolicy')}
                      </button>
                      {row.isPolicy && (
                        <span className="font-mono text-[10px] text-text-muted">
                          {t(`query.severity.${row.severity}`)}
                          {row.lastRunAt
                            ? ` · ${t('query.lastRun', {
                                when: dateFmt.format(new Date(row.lastRunAt)),
                                count: row.lastMatchCount ?? 0,
                              })}`
                            : ` · ${t('query.neverRun')}`}
                        </span>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </aside>
      </div>
    </div>
  );
}

function ResultPanel({
  result,
  expanded,
  onToggleRow,
  dateFmt,
}: {
  result: QueryResult;
  expanded: Set<number>;
  onToggleRow: (deviceId: number) => void;
  dateFmt: Intl.DateTimeFormat;
}) {
  const { t } = useTranslation();

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-bg-secondary px-3 py-2">
        <span className="font-display text-lg font-semibold tabular-nums text-text-primary">
          {result.devicesExamined > 0
            ? t('query.matchedOf', { matched: result.rows.length, total: result.devicesExamined })
            : t('query.matchedUnknownTotal', { matched: result.rows.length })}
        </span>
        <span className="font-mono text-[11px] text-text-muted">
          {t('query.elapsed', { ms: result.elapsedMs })}
        </span>
        {result.devicesWithoutSnapshot > 0 && (
          <span
            className="rounded border border-status-ssl-warning/50 bg-status-ssl-warning/10 px-1.5 py-0.5 text-[11px] text-status-ssl-warning"
            title={t('query.noSnapshotHint')}
          >
            {t('query.noSnapshot', { count: result.devicesWithoutSnapshot })}
          </span>
        )}
        {result.truncated && (
          <span className="rounded border border-status-ssl-expired/60 bg-status-ssl-expired/15 px-1.5 py-0.5 text-[11px] text-status-ssl-expired">
            {t('query.truncated')}
          </span>
        )}
      </div>

      {result.notice && (
        <p className="rounded-md border border-border bg-bg-tertiary px-3 py-2 text-[12px] text-text-muted">
          {result.notice}
        </p>
      )}

      {result.rows.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-12 text-center">
          <p className="text-sm text-text-muted">{t('query.noMatch')}</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">{t('query.noMatchHint')}</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full min-w-[48rem] text-left text-[13px]">
            <thead className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
              <tr>
                <th className="w-8 px-2 py-2" />
                <th className="px-3 py-2 font-medium">{t('query.columns.device')}</th>
                <th className="px-3 py-2 font-medium">{t('query.columns.model')}</th>
                {result.columns.map((c) => (
                  <th key={c.key} className="px-3 py-2 font-mono font-medium" title={c.path}>
                    {c.key}
                  </th>
                ))}
                <th className="px-3 py-2 font-medium">{t('query.columns.snapshot')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {result.rows.map((row) => (
                <ResultRow
                  key={row.deviceId}
                  row={row}
                  columns={result.columns.map((c) => c.key)}
                  open={expanded.has(row.deviceId)}
                  onToggle={() => onToggleRow(row.deviceId)}
                  dateFmt={dateFmt}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ResultRow({
  row,
  columns,
  open,
  onToggle,
  dateFmt,
}: {
  row: QueryRow;
  columns: string[];
  open: boolean;
  onToggle: () => void;
  dateFmt: Intl.DateTimeFormat;
}) {
  const { t } = useTranslation();
  const snapshotAt = row.snapshotAt ? new Date(row.snapshotAt) : null;

  return (
    <>
      <tr className="hover:bg-bg-hover">
        <td className="px-2 py-2">
          <button onClick={onToggle} className="rounded p-0.5 text-text-muted hover:text-text-primary">
            {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          </button>
        </td>
        <td className="px-3 py-2">
          <Link to={`/devices/${row.deviceId}`} className="text-text-primary hover:text-accent">
            {anonHostname(row.deviceName ?? `#${row.deviceId}`)}
          </Link>
          <span className="block text-[11px] text-text-muted">{row.siteName ?? '—'}</span>
        </td>
        <td className="px-3 py-2 font-mono text-[11px] text-text-muted">
          {row.brand}
          {row.model ? ` ${row.model}` : ''}
          {row.osVersion ? ` · ${row.osVersion}` : ''}
        </td>
        {columns.map((key) => (
          <td key={key} className="px-3 py-2 font-mono text-[12px] text-text-secondary">
            {renderCell(row.cells[key])}
          </td>
        ))}
        <td className="px-3 py-2 font-mono text-[11px] text-text-muted">
          {snapshotAt && !Number.isNaN(snapshotAt.getTime()) ? dateFmt.format(snapshotAt) : '—'}
        </td>
      </tr>

      {open && (
        <tr>
          <td colSpan={columns.length + 4} className="bg-bg-primary/40 px-3 py-3">
            {row.matches.length === 0 ? (
              <p className="text-[12px] text-text-muted">{t('query.noMatchDetail')}</p>
            ) : (
              <ul className="space-y-2">
                {row.matches.map((match, i) => {
                  // §8.2 — every expanded value is scanned before it is drawn.
                  const hits = scanValueForSecrets(match.value, 3);
                  return (
                    <li key={`${match.semKey}-${i}`} className="rounded-md border border-border bg-bg-secondary p-2">
                      <p className="flex flex-wrap items-center gap-2 text-[11px]">
                        <span className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-accent">
                          {match.resource}
                        </span>
                        <span className="font-mono text-text-muted">{match.semKey}</span>
                      </p>
                      {hits.length > 0 ? (
                        <p className="mt-1 inline-flex items-center gap-1.5 rounded border border-status-ssl-expired/60 bg-status-ssl-expired/15 px-2 py-1 text-[11px] text-status-ssl-expired">
                          <ShieldAlert size={12} />
                          {t('query.secretRedacted', { keys: hits.join(', ') })}
                        </p>
                      ) : (
                        <pre className="mt-1 max-h-56 overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] text-text-secondary">
                          {JSON.stringify(match.value, null, 2)}
                        </pre>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

function renderCell(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (Array.isArray(value)) return value.map((v) => String(v)).join(', ');
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
