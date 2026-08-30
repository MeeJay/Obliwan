import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Search,
  ShieldAlert,
  X,
} from 'lucide-react';
import {
  NCM_RESOURCE_KINDS,
  RESOURCE_KIND_TO_COLLECTION,
  type CoverageState,
  type NcmDocumentStored,
  type NcmResourceKind,
} from '@obliwan/shared';
import { cn } from '@/utils/cn';
import { coverageList } from '@/utils/ncmCompare';
import { scanValueForSecrets } from '@/utils/secretScan';

/**
 * The NCM tree (spec §4.2, `components/config/NcmTree`).
 *
 * ── WHAT THIS SCREEN IS FOR ─────────────────────────────────────────────────
 * It renders the pivot document, not the router's text. That distinction is the
 * whole product decision D1: the truth ObliWAN reasons about is the NCM, and an
 * operator who never sees it has no way to tell a real change from an export
 * artefact. So every section carries its COVERAGE badge — `partial`,
 * `unsupported` and `failed` are shown as loudly as the records themselves,
 * because a section that reads "0 records" while coverage is `failed` means
 * "we could not look", not "there is nothing there", and confusing the two is
 * how somebody ends up approving a plan that deletes a firewall.
 *
 * `unmodeled[]` gets a section of its own for the same reason (§7): the
 * boundary of what we model is a number the operator is entitled to see, and a
 * section flagged `forwardingRelevant` is what makes the Management-Path Guard
 * refuse to conclude later.
 *
 * ── SECRETS ─────────────────────────────────────────────────────────────────
 * Every value about to be painted goes through `scanValueForSecrets` first.
 * `SecretFingerprint` (`{algo, fp, unavailable}`) is the SUPPORTED carrier and
 * is rendered as such; anything else that looks like key material is replaced
 * by a warning chip and counted in the banner. See §8.2 / R10.
 */

type Rec = Record<string, unknown>;

export interface NcmTreeProps {
  document: NcmDocumentStored | null;
  /** semKeys to highlight — the result of an N/N-1 comparison, for instance.
   *  The tree does not compute them and does not know what they mean. */
  highlighted?: ReadonlySet<string>;
  /** Sections open on first render. Defaults to none: a 200-rule firewall
   *  expanded by default is the same wall of text the NCM exists to replace. */
  defaultOpen?: readonly NcmResourceKind[];
  className?: string;
}

const COVERAGE_TONE: Record<CoverageState, string> = {
  complete: 'text-status-up border-status-up/40 bg-status-up/10',
  partial: 'text-status-ssl-warning border-status-ssl-warning/40 bg-status-ssl-warning/10',
  failed: 'text-status-ssl-expired border-status-ssl-expired/40 bg-status-ssl-expired/10',
  unsupported: 'text-text-muted border-border bg-bg-tertiary',
};

/** Fields that are metadata about the COLLECTION rather than configuration.
 *  Rendered in a dimmer row so they cannot be mistaken for config. */
const META_FIELDS = new Set(['semKey', 'kind', 'keyQuality', 'managedBy', 'managedSlug', 'via']);

function text(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'string') return v === '' ? '""' : v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (Array.isArray(v)) return v.length === 0 ? '[]' : v.map(text).join(', ');
  try { return JSON.stringify(v); } catch { return String(v); }
}

function isFingerprint(v: unknown): v is { algo: string; fp: string | null; unavailable: boolean } {
  return !!v && typeof v === 'object' && 'algo' in v && 'fp' in v && 'unavailable' in v;
}

/** One line that says what the record IS, without opening it. Deliberately
 *  per-kind: a generic `JSON.stringify` here would be unreadable, and an
 *  unreadable list is a list nobody scans. */
function summarize(kind: NcmResourceKind, r: Rec): string {
  switch (kind) {
    case 'interface': {
      const addrs = Array.isArray(r.addresses)
        ? (r.addresses as Rec[]).map((a) => String(a.cidr ?? '')).filter(Boolean)
        : [];
      return [String(r.type ?? ''), addrs.join(' ')].filter(Boolean).join(' · ');
    }
    case 'vlan':
      return [
        r.parent ? String(r.parent) : '',
        `id ${String(r.vlanId ?? '?')}`,
        Array.isArray(r.taggedPorts) && r.taggedPorts.length > 0
          ? `tagged ${(r.taggedPorts as string[]).join(',')}` : '',
      ].filter(Boolean).join(' · ');
    case 'route':
      return `${String(r.dst ?? '')} → ${r.gateway ? String(r.gateway) : 'blackhole'}`;
    case 'firewallRule':
      return `${String(r.chain ?? '')} · ${String(r.action ?? '')}`;
    case 'natRule':
      return `${String(r.chain ?? '')} · ${String(r.action ?? '')}`;
    case 'dhcpScope':
      return `${String(r.subnet ?? '')} · ${String(r.onInterface ?? '')}`;
    case 'ipsecPeer':
      return String(r.remote ?? r.name ?? '');
    case 'localUser':
      return [String(r.username ?? ''), r.group ? String(r.group) : ''].filter(Boolean).join(' · ');
    case 'service':
      return [
        String(r.service ?? ''),
        r.enabled === false ? 'disabled' : 'enabled',
        r.port ? `:${String(r.port)}` : '',
      ].filter(Boolean).join(' ');
    case 'qosRule':
      return [String(r.queueClass ?? ''), r.name ? String(r.name) : ''].filter(Boolean).join(' · ');
    default:
      return '';
  }
}

export function NcmTree({ document, highlighted, defaultOpen = [], className }: NcmTreeProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState<Set<string>>(new Set<string>(defaultOpen));
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState('');

  const coverage = useMemo(() => coverageList(document), [document]);

  const sections = useMemo(() => {
    const resources = (document as unknown as Rec | null)?.resources as Rec | undefined;
    const needle = search.trim().toLowerCase();
    return NCM_RESOURCE_KINDS.map((kind) => {
      const arr = resources?.[RESOURCE_KIND_TO_COLLECTION[kind]];
      const rows: Rec[] = Array.isArray(arr) ? (arr as Rec[]) : [];
      const filtered = needle
        ? rows.filter((r) =>
            `${String(r.semKey ?? '')} ${summarize(kind, r)} ${String(r.comment ?? '')}`
              .toLowerCase()
              .includes(needle))
        : rows;
      return {
        kind,
        rows: filtered,
        total: rows.length,
        coverage: coverage.find((c) => c.kind === kind)!,
      };
    });
  }, [document, coverage, search]);

  const unmodeled = useMemo(() => {
    const list = (document as unknown as Rec | null)?.unmodeled;
    return Array.isArray(list) ? (list as Rec[]) : [];
  }, [document]);

  const extensions = useMemo(() => {
    const ext = (document as unknown as Rec | null)?.extensions;
    return ext && typeof ext === 'object' ? (ext as Rec) : {};
  }, [document]);

  const secretPaths = useMemo(
    () => (document ? scanValueForSecrets(document, 8) : []),
    [document],
  );

  if (!document) {
    return (
      <div className={cn('rounded-lg border border-border bg-bg-secondary py-12 text-center', className)}>
        <p className="text-sm text-text-muted">{t('config.tree.noDocument')}</p>
      </div>
    );
  }

  const toggleSection = (key: string) => {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const toggleRow = (key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  return (
    <div className={cn('rounded-lg border border-border bg-bg-secondary', className)}>
      {secretPaths.length > 0 && (
        <div className="flex items-start gap-2 border-b border-status-ssl-expired/40 bg-status-ssl-expired/5 px-3 py-2 text-[12px] text-status-ssl-expired">
          <ShieldAlert size={14} className="mt-0.5 shrink-0" />
          <span>{t('config.tree.secretDetected', { fields: secretPaths.join(', ') })}</span>
        </div>
      )}

      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <div className="relative">
          <Search
            size={13}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted"
          />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('config.tree.searchPlaceholder')}
            className="w-64 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>
        {search && (
          <button
            onClick={() => setSearch('')}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            <X size={12} />
            {t('devices.filters.clear')}
          </button>
        )}
        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('config.tree.recordTotal', {
            count: sections.reduce((a, s) => a + s.total, 0),
          })}
        </span>
      </div>

      <div className="divide-y divide-border">
        {sections.map((section) => {
          const isOpen = open.has(section.kind);
          const cov = section.coverage;
          return (
            <div key={section.kind}>
              <button
                onClick={() => toggleSection(section.kind)}
                className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-bg-hover"
              >
                {isOpen ? <ChevronDown size={14} className="text-text-muted" />
                        : <ChevronRight size={14} className="text-text-muted" />}
                <span className="text-[13px] font-medium text-text-primary">
                  {t(`ncm.kind.${section.kind}`)}
                </span>
                <span className="font-mono text-[11px] text-text-muted">
                  {search ? `${section.rows.length}/${section.total}` : section.total}
                </span>
                <span
                  className={cn(
                    'ml-auto rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
                    COVERAGE_TONE[cov.state],
                  )}
                  title={cov.reason ?? undefined}
                >
                  {t(`ncm.coverage.${cov.state}`)}
                </span>
              </button>

              {isOpen && (
                <div className="border-t border-border/60 bg-bg-primary/30">
                  {cov.state !== 'complete' && (
                    <p className="px-9 py-2 text-[12px] text-text-muted">
                      {t(`ncm.coverageHint.${cov.state}`)}
                      {cov.reason ? ` — ${cov.reason}` : ''}
                    </p>
                  )}
                  {section.rows.length === 0 ? (
                    <p className="px-9 py-3 text-[12px] text-text-muted">
                      {cov.state === 'complete'
                        ? t('config.tree.sectionEmpty')
                        : t('config.tree.sectionUnknown')}
                    </p>
                  ) : (
                    section.rows.map((row) => {
                      const key = String(row.semKey ?? '');
                      const rowKey = `${section.kind}/${key}`;
                      const isExpanded = expanded.has(rowKey);
                      return (
                        <div key={rowKey} className="border-t border-border/40 first:border-t-0">
                          <button
                            onClick={() => toggleRow(rowKey)}
                            className={cn(
                              'flex w-full items-center gap-2 px-9 py-1.5 text-left hover:bg-bg-hover',
                              highlighted?.has(key) && 'bg-accent/10',
                            )}
                          >
                            {isExpanded ? <ChevronDown size={12} className="shrink-0 text-text-muted" />
                                        : <ChevronRight size={12} className="shrink-0 text-text-muted" />}
                            <span className="truncate font-mono text-[11px] text-text-secondary">{key}</span>
                            <span className="truncate text-[12px] text-text-muted">
                              {summarize(section.kind, row)}
                            </span>
                            <span className="ml-auto flex shrink-0 items-center gap-1">
                              {row.disabled === true && (
                                <Chip tone="muted">{t('config.tree.disabled')}</Chip>
                              )}
                              {row.managedBy === 'obliwan' && (
                                <Chip tone="accent">obliwan:{String(row.managedSlug ?? '')}</Chip>
                              )}
                              {row.managedBy === 'foreign' && (
                                <Chip tone="warn">{t('ncm.managedBy.foreign')}</Chip>
                              )}
                              {row.keyQuality === 'weak' && (
                                <Chip tone="warn">{t('ncm.keyQuality.weak')}</Chip>
                              )}
                            </span>
                          </button>
                          {isExpanded && <FieldTable record={row} />}
                        </div>
                      );
                    })
                  )}
                </div>
              )}
            </div>
          );
        })}

        {/* ── unmodeled: the honest boundary (§7) ── */}
        <div>
          <button
            onClick={() => toggleSection('__unmodeled')}
            className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-bg-hover"
          >
            {open.has('__unmodeled') ? <ChevronDown size={14} className="text-text-muted" />
                                     : <ChevronRight size={14} className="text-text-muted" />}
            <span className="text-[13px] font-medium text-text-primary">
              {t('config.tree.unmodeled')}
            </span>
            <span className="font-mono text-[11px] text-text-muted">{unmodeled.length}</span>
            {unmodeled.some((u) => u.forwardingRelevant === true) && (
              <span className="ml-auto inline-flex items-center gap-1 rounded border border-status-ssl-warning/40 bg-status-ssl-warning/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-status-ssl-warning">
                <AlertTriangle size={10} />
                {t('config.tree.forwardingRelevant')}
              </span>
            )}
          </button>
          {open.has('__unmodeled') && (
            <div className="border-t border-border/60 bg-bg-primary/30">
              <p className="px-9 py-2 text-[12px] text-text-muted">{t('config.tree.unmodeledHint')}</p>
              {unmodeled.length === 0 ? (
                <p className="px-9 pb-3 text-[12px] text-text-muted">{t('config.tree.unmodeledNone')}</p>
              ) : (
                unmodeled.map((u, i) => (
                  <div key={`${String(u.section)}-${i}`} className="flex items-center gap-2 px-9 py-1.5">
                    <span className="font-mono text-[11px] text-text-secondary">{String(u.section ?? '')}</span>
                    <span className="text-[12px] text-text-muted">
                      {t('config.tree.lineCount', { count: Number(u.lineCount ?? 0) })}
                    </span>
                    {u.forwardingRelevant === true && (
                      <Chip tone="warn">{t('config.tree.forwardingRelevant')}</Chip>
                    )}
                  </div>
                ))
              )}
            </div>
          )}
        </div>

        {/* ── extensions: outside the hash, outside the diff, shown anyway ── */}
        {Object.keys(extensions).length > 0 && (
          <div>
            <button
              onClick={() => toggleSection('__extensions')}
              className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-bg-hover"
            >
              {open.has('__extensions') ? <ChevronDown size={14} className="text-text-muted" />
                                        : <ChevronRight size={14} className="text-text-muted" />}
              <span className="text-[13px] font-medium text-text-primary">
                {t('config.tree.extensions')}
              </span>
              <span className="font-mono text-[11px] text-text-muted">
                {Object.keys(extensions).length}
              </span>
            </button>
            {open.has('__extensions') && (
              <div className="border-t border-border/60 bg-bg-primary/30">
                <p className="px-9 py-2 text-[12px] text-text-muted">
                  {t('config.tree.extensionsHint')}
                </p>
                <FieldTable record={extensions} />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── pieces ──────────────────────────────────────────────────────────────────

function Chip({ children, tone }: { children: React.ReactNode; tone: 'muted' | 'warn' | 'accent' }) {
  const tones = {
    muted: 'border-border bg-bg-tertiary text-text-muted',
    warn: 'border-status-ssl-warning/40 bg-status-ssl-warning/10 text-status-ssl-warning',
    accent: 'border-accent/40 bg-accent/10 text-accent',
  };
  return (
    <span className={cn('rounded border px-1.5 py-0.5 font-mono text-[10px]', tones[tone])}>
      {children}
    </span>
  );
}

function FieldTable({ record }: { record: Rec }) {
  const { t } = useTranslation();
  const bad = useMemo(() => new Set(scanValueForSecrets(record, 8)), [record]);
  const entries = Object.entries(record).sort(([a], [b]) => {
    const am = META_FIELDS.has(a) ? 1 : 0;
    const bm = META_FIELDS.has(b) ? 1 : 0;
    return am - bm || a.localeCompare(b);
  });
  return (
    <dl className="grid grid-cols-[10rem_1fr] gap-x-3 gap-y-1 border-t border-border/40 bg-bg-secondary px-9 py-2 text-[12px]">
      {entries.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className={cn('font-mono', META_FIELDS.has(k) ? 'text-text-muted/70' : 'text-text-muted')}>
            {k}
          </dt>
          <dd className="break-all font-mono text-text-primary">
            {bad.has(k) ? (
              <span className="inline-flex items-center gap-1 rounded bg-status-ssl-expired/15 px-1.5 py-0.5 text-[11px] text-status-ssl-expired">
                <ShieldAlert size={10} />
                {t('config.tree.valueWithheld')}
              </span>
            ) : isFingerprint(v) ? (
              <span className="text-text-secondary">
                {v.unavailable
                  ? t('config.tree.secretUnavailable')
                  : `${v.algo}:${v.fp ?? '—'}`}
              </span>
            ) : (
              text(v)
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}
