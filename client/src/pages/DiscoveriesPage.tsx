import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Building2,
  EyeOff,
  Link2,
  MapPin,
  Radar,
  RotateCw,
  ShieldAlert,
  X,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  DEVICE_BRANDS,
  DEVICE_FAMILIES,
  DEVICE_ROLES,
  FAMILY_BRAND,
  type DeviceBrand,
  type DeviceFamily,
  type DeviceRole,
  type DiscoveryState,
} from '@obliwan/shared';
import { discoveriesApi } from '@/api/discoveries.api';
import { useDeviceStore } from '@/store/deviceStore';
import { useSiteStore } from '@/store/siteStore';
import { useTenantStore } from '@/store/tenantStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { cn } from '@/utils/cn';
import type { Discovery } from '@/types/fleet';
import toast from 'react-hot-toast';

const STATE_TABS: DiscoveryState[] = ['pending', 'bound', 'ignored'];

const selectClass =
  'w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-50';

/**
 * The CHR quarantine queue (spec §4.2, risk R4).
 *
 * Every visual decision on this page exists to stop one specific accident:
 * binding customer A's PPP session to customer B's site, after which the
 * template engine cheerfully pushes A's configuration onto B's router. The
 * queue is therefore not a list with a one-click "accept" button — the bind
 * dialog forces the operator to pick a tenant explicitly, to read the raw
 * evidence the concentrator reported, to tick an attestation, and to retype
 * the PPP username. None of that is decorative.
 */
export function DiscoveriesPage() {
  const { t } = useTranslation();
  const [state, setState] = useState<DiscoveryState>('pending');
  const [rows, setRows] = useState<Discovery[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [binding, setBinding] = useState<Discovery | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      setRows(await discoveriesApi.list({ state }));
    } catch (err) {
      const message =
        (err as { response?: { data?: { error?: string } } }).response?.data?.error ??
        (err as Error).message;
      setLoadError(message ?? 'unknown error');
    } finally {
      setLoading(false);
    }
  }, [state]);

  useEffect(() => { void load(); }, [load]);

  const handleIgnore = async (row: Discovery) => {
    if (!confirm(t('discoveries.confirmIgnore', { username: row.pppUsername }))) return;
    try {
      await discoveriesApi.ignore(row.id);
      toast.success(t('discoveries.ignored'));
      void load();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('discoveries.ignoreFailed'));
    }
  };

  return (
    <div className="p-6">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
            <Radar size={22} className="text-accent" />
            {t('nav.discoveries')}
          </h1>
          <p className="mt-1 text-sm text-text-muted">{t('discoveries.subtitle')}</p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => void load()}>
          <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
          {t('devices.refresh')}
        </Button>
      </div>

      {/* The standing warning. It is not dismissible on purpose. */}
      <div className="mb-5 flex items-start gap-3 rounded-lg border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-4">
        <ShieldAlert size={18} className="mt-0.5 shrink-0 text-status-ssl-warning" />
        <div>
          <h2 className="text-sm font-semibold text-status-ssl-warning">{t('discoveries.warningTitle')}</h2>
          <p className="mt-1 text-xs text-text-secondary">{t('discoveries.warningBody')}</p>
        </div>
      </div>

      {/* State tabs */}
      <div className="mb-4 flex gap-1 rounded-lg border border-border bg-bg-secondary p-1">
        {STATE_TABS.map((s) => (
          <button
            key={s}
            onClick={() => setState(s)}
            className={cn(
              'flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors',
              state === s ? 'bg-accent text-white' : 'text-text-muted hover:text-text-primary',
            )}
          >
            {t(`discoveries.state.${s}`)}
          </button>
        ))}
      </div>

      {loadError ? (
        <div className="rounded-lg border border-status-down/40 bg-status-down/5 p-4 text-sm text-status-down">
          {t('discoveries.loadFailed')} — <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : loading ? (
        <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
      ) : rows.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Radar size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t(`discoveries.empty.${state}`)}</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead>
              <tr className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
                <th className="px-3 py-2 font-medium">{t('discoveries.columns.pppUsername')}</th>
                <th className="px-3 py-2 font-medium">{t('discoveries.columns.concentrator')}</th>
                <th className="px-3 py-2 font-medium">{t('discoveries.columns.addresses')}</th>
                <th className="px-3 py-2 font-medium">{t('discoveries.columns.profile')}</th>
                <th className="px-3 py-2 font-medium">{t('discoveries.columns.seen')}</th>
                <th className="px-3 py-2 font-medium">{t('discoveries.columns.review')}</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map((row) => (
                <tr key={row.id} className="transition-colors hover:bg-bg-hover">
                  <td className="px-3 py-2">
                    <span className="font-mono text-[13px] font-medium text-text-primary">{row.pppUsername}</span>
                    {row.pppComment && (
                      <div className="text-[11px] text-text-muted">{row.pppComment}</div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-text-secondary">
                    {row.concentratorName ?? `#${row.concentratorId}`}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-text-muted">
                    <div>{row.remoteAddress ?? '—'}</div>
                    <div>{row.callerIp ?? '—'}</div>
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-text-muted">{row.profile ?? '—'}</td>
                  <td className="px-3 py-2 text-[11px] text-text-muted">
                    <div>{new Date(row.firstSeenAt).toLocaleString()}</div>
                    <div>{new Date(row.lastSeenAt).toLocaleString()}</div>
                  </td>
                  <td className="px-3 py-2 text-[11px] text-text-muted">
                    {row.state === 'pending' ? (
                      <span className="inline-flex items-center gap-1 rounded-full border border-status-pending/30 bg-status-pending/10 px-2 py-0.5 text-status-pending">
                        {t('discoveries.state.pending')}
                      </span>
                    ) : (
                      <>
                        <div>{row.reviewedByName ?? (row.reviewedBy !== null ? `#${row.reviewedBy}` : '—')}</div>
                        <div>{row.reviewedAt ? new Date(row.reviewedAt).toLocaleString() : '—'}</div>
                      </>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {row.state === 'pending' && (
                      <div className="flex justify-end gap-1.5">
                        <Button size="sm" onClick={() => setBinding(row)}>
                          <Link2 size={13} className="mr-1.5" />
                          {t('discoveries.review')}
                        </Button>
                        <Button size="sm" variant="secondary" onClick={() => void handleIgnore(row)}>
                          <EyeOff size={13} className="mr-1.5" />
                          {t('discoveries.ignore')}
                        </Button>
                      </div>
                    )}
                    {row.state === 'bound' && (
                      <span className="text-[11px] text-text-muted">
                        {row.boundDeviceName ?? `#${row.boundDeviceId}`}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {binding && (
        <BindDialog
          discovery={binding}
          onClose={() => setBinding(null)}
          onBound={() => { setBinding(null); void load(); }}
        />
      )}
    </div>
  );
}

// ── Bind dialog ─────────────────────────────────────────────────────────────

function BindDialog({
  discovery,
  onClose,
  onBound,
}: {
  discovery: Discovery;
  onClose: () => void;
  onBound: () => void;
}) {
  const { t } = useTranslation();
  const { tenants, fetchTenants, currentTenantId } = useTenantStore();
  const { sites, fetchSites } = useSiteStore();
  const { devices, fetchDevices } = useDeviceStore();

  // The bind lands in the SESSION tenant — the server resolves it from
  // `requireTenant` and never from this body. Offering a free choice here
  // would be a control that does nothing, which is worse than no control: the
  // operator would believe they had filed the router with customer B while the
  // server filed it with customer A. So the field states the workspace and is
  // read-only; switching customer is a workspace switch, deliberately.
  const [tenantId] = useState<string>(currentTenantId !== null ? String(currentTenantId) : '');
  const [siteId, setSiteId] = useState<string>('');
  const [mode, setMode] = useState<'existing' | 'new'>('new');
  const [deviceId, setDeviceId] = useState<string>('');
  const [newName, setNewName] = useState(discovery.pppUsername);
  const [brand, setBrand] = useState<DeviceBrand>('mikrotik');
  const [family, setFamily] = useState<DeviceFamily>('mikrotik_routeros7');
  const [role, setRole] = useState<DeviceRole>('cpe');
  const [attested, setAttested] = useState(false);
  const [typed, setTyped] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void fetchTenants();
    void fetchSites();
    void fetchDevices();
  }, [fetchTenants, fetchSites, fetchDevices]);

  const familiesForBrand = (b: DeviceBrand) => DEVICE_FAMILIES.filter((f) => FAMILY_BRAND[f] === b);

  // Sites and devices are narrowed by the CHOSEN tenant, never by the operator's
  // ambient workspace: the whole point of the dialog is that the target is
  // stated, not inherited.
  const tenantSites = useMemo(
    () => (tenantId ? sites.filter((s) => s.tenantId === Number(tenantId)) : []),
    [sites, tenantId],
  );
  const candidateDevices = useMemo(
    () =>
      devices.filter(
        (d) =>
          (!tenantId || d.tenantId === Number(tenantId)) &&
          (!siteId || d.siteId === Number(siteId)) &&
          // Never offer a device that already answers to another PPP identity.
          (d.pppUsername === null || d.pppUsername === discovery.pppUsername),
      ),
    [devices, tenantId, siteId, discovery.pppUsername],
  );

  const usernameMatches = typed.trim() === discovery.pppUsername;
  const targetChosen = mode === 'existing' ? deviceId !== '' : newName.trim().length > 0;
  const canSubmit =
    tenantId !== '' && siteId !== '' && targetChosen && attested && usernameMatches && !saving;

  const submit = async (e: { preventDefault: () => void }) => {
    e.preventDefault();
    if (!canSubmit) return;
    setSaving(true);
    try {
      // Exactly one of the two, which is what the server's validator refines
      // on. `brand` is not sent: it is derived from `family` server-side, and a
      // pair that disagrees would resolve every later driver lookup to the
      // wrong dialect. `typed` / `attested` never leave the browser — they gate
      // `canSubmit` above and were never an authorisation.
      await discoveriesApi.bind(
        discovery.id,
        mode === 'existing'
          ? { deviceId: Number(deviceId) }
          : {
              device: {
                name: newName.trim(),
                family,
                role,
                siteId: Number(siteId),
              },
            },
      );
      toast.success(t('discoveries.bound'));
      onBound();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('discoveries.bindFailed'));
    } finally {
      setSaving(false);
    }
  };

  const rawEntries = Object.entries(discovery.raw ?? {});

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50" onClick={onClose} />
      <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-2xl flex-col border-l border-border bg-bg-primary shadow-xl">
        <div className="flex shrink-0 items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <ShieldAlert size={16} className="text-status-ssl-warning" />
            <div>
              <h2 className="text-sm font-semibold text-text-primary">{t('discoveries.bindTitle')}</h2>
              <p className="font-mono text-[11px] text-text-muted">{discovery.pppUsername}</p>
            </div>
          </div>
          <button onClick={onClose} className="rounded p-1 text-text-muted hover:text-text-primary">
            <X size={16} />
          </button>
        </div>

        <form onSubmit={submit} className="flex-1 space-y-4 overflow-y-auto p-4">
          {/* Consequence banner */}
          <div className="flex items-start gap-2 rounded-lg border border-status-down/40 bg-status-down/5 p-3">
            <AlertTriangle size={16} className="mt-0.5 shrink-0 text-status-down" />
            <p className="text-xs text-text-secondary">{t('discoveries.bindConsequence')}</p>
          </div>

          {/* Evidence — raw, unjudged, exactly what the CHR reported */}
          <section className="rounded-lg border border-border bg-bg-secondary p-3">
            <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
              {t('discoveries.evidence')}
            </h3>
            <dl className="grid grid-cols-2 gap-3 text-[12px]">
              <div>
                <dt className="text-text-muted">{t('discoveries.columns.concentrator')}</dt>
                <dd className="text-text-primary">{discovery.concentratorName ?? `#${discovery.concentratorId}`}</dd>
              </div>
              <div>
                <dt className="text-text-muted">{t('discoveries.columns.profile')}</dt>
                <dd className="font-mono text-text-primary">{discovery.profile ?? '—'}</dd>
              </div>
              <div>
                <dt className="text-text-muted">{t('discoveries.fields.remoteAddress')}</dt>
                <dd className="font-mono text-text-primary">{discovery.remoteAddress ?? '—'}</dd>
              </div>
              <div>
                <dt className="text-text-muted">{t('discoveries.fields.callerIp')}</dt>
                <dd className="font-mono text-text-primary">{discovery.callerIp ?? '—'}</dd>
              </div>
              <div className="col-span-2">
                <dt className="text-text-muted">{t('discoveries.fields.comment')}</dt>
                <dd className="text-text-primary">{discovery.pppComment ?? '—'}</dd>
              </div>
            </dl>
            {rawEntries.length > 0 && (
              <details className="mt-2">
                <summary className="cursor-pointer text-[11px] text-text-muted hover:text-text-secondary">
                  {t('discoveries.rawPayload')}
                </summary>
                <pre className="mt-1 max-h-40 overflow-auto rounded bg-bg-tertiary p-2 font-mono text-[10px] text-text-secondary">
                  {JSON.stringify(discovery.raw, null, 2)}
                </pre>
              </details>
            )}
            <p className="mt-2 text-[11px] italic text-text-muted">{t('discoveries.evidenceHint')}</p>
          </section>

          {/* 1 — tenant */}
          <div className="space-y-1">
            <label className="flex items-center gap-1.5 text-sm font-medium text-text-secondary">
              <Building2 size={13} />
              {t('discoveries.fields.tenant')}
            </label>
            <select className={selectClass} value={tenantId} disabled required>
              <option value="">{t('discoveries.selectTenant')}</option>
              {tenants.map((tenant) => (
                <option key={tenant.id} value={tenant.id}>{tenant.name}</option>
              ))}
            </select>
            <p className="text-[11px] text-text-muted">{t('discoveries.tenantHint')}</p>
          </div>

          {/* 2 — site */}
          <div className="space-y-1">
            <label className="flex items-center gap-1.5 text-sm font-medium text-text-secondary">
              <MapPin size={13} />
              {t('discoveries.fields.site')}
            </label>
            <select
              className={selectClass}
              value={siteId}
              onChange={(e) => { setSiteId(e.target.value); setDeviceId(''); }}
              disabled={!tenantId}
              required
            >
              <option value="">{tenantId ? t('discoveries.selectSite') : t('discoveries.selectTenantFirst')}</option>
              {tenantSites.map((s) => (
                <option key={s.id} value={s.id}>{s.name} ({s.code})</option>
              ))}
            </select>
            {tenantId !== '' && tenantSites.length === 0 && (
              <p className="text-[11px] text-status-ssl-warning">{t('discoveries.noSiteForTenant')}</p>
            )}
          </div>

          {/* 3 — device */}
          <div className="space-y-2">
            <span className="block text-sm font-medium text-text-secondary">{t('discoveries.fields.device')}</span>
            <div className="flex gap-1 rounded-lg border border-border bg-bg-secondary p-1">
              <button
                type="button"
                onClick={() => setMode('new')}
                className={cn(
                  'flex-1 rounded-md px-3 py-1.5 text-[13px] transition-colors',
                  mode === 'new' ? 'bg-accent text-white' : 'text-text-muted hover:text-text-primary',
                )}
              >
                {t('discoveries.createDevice')}
              </button>
              <button
                type="button"
                onClick={() => setMode('existing')}
                className={cn(
                  'flex-1 rounded-md px-3 py-1.5 text-[13px] transition-colors',
                  mode === 'existing' ? 'bg-accent text-white' : 'text-text-muted hover:text-text-primary',
                )}
              >
                {t('discoveries.attachDevice')}
              </button>
            </div>

            {mode === 'existing' ? (
              <>
                <select
                  className={selectClass}
                  value={deviceId}
                  onChange={(e) => setDeviceId(e.target.value)}
                  disabled={!siteId}
                >
                  <option value="">{siteId ? t('discoveries.selectDevice') : t('discoveries.selectSiteFirst')}</option>
                  {candidateDevices.map((d) => (
                    <option key={d.id} value={d.id}>{d.name}</option>
                  ))}
                </select>
                {siteId !== '' && candidateDevices.length === 0 && (
                  <p className="text-[11px] text-status-ssl-warning">{t('discoveries.noCandidateDevice')}</p>
                )}
              </>
            ) : (
              <div className="grid grid-cols-2 gap-3">
                <Input
                  label={t('devices.fields.name')}
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="col-span-2"
                />
                <div className="space-y-1">
                  <label className="block text-sm font-medium text-text-secondary">{t('devices.fields.brand')}</label>
                  <select
                    className={selectClass}
                    value={brand}
                    onChange={(e) => {
                      const b = e.target.value as DeviceBrand;
                      setBrand(b);
                      setFamily(familiesForBrand(b)[0]);
                    }}
                  >
                    {DEVICE_BRANDS.map((b) => <option key={b} value={b}>{t(`fleet.brand.${b}`)}</option>)}
                  </select>
                </div>
                <div className="space-y-1">
                  <label className="block text-sm font-medium text-text-secondary">{t('devices.fields.family')}</label>
                  <select
                    className={selectClass}
                    value={family}
                    onChange={(e) => setFamily(e.target.value as DeviceFamily)}
                  >
                    {familiesForBrand(brand).map((f) => (
                      <option key={f} value={f}>{t(`fleet.family.${f}`)}</option>
                    ))}
                  </select>
                </div>
                <div className="space-y-1 col-span-2">
                  <label className="block text-sm font-medium text-text-secondary">{t('devices.fields.role')}</label>
                  <select
                    className={selectClass}
                    value={role}
                    onChange={(e) => setRole(e.target.value as DeviceRole)}
                  >
                    {DEVICE_ROLES.map((r) => <option key={r} value={r}>{t(`fleet.role.${r}`)}</option>)}
                  </select>
                </div>
              </div>
            )}
          </div>

          {/* 4 — attestation + type-to-confirm */}
          <section className="space-y-3 rounded-lg border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3">
            <label className="flex items-start gap-2 text-xs text-text-secondary">
              <input
                type="checkbox"
                checked={attested}
                onChange={(e) => setAttested(e.target.checked)}
                className="mt-0.5 h-4 w-4 shrink-0 rounded border-border bg-bg-tertiary accent-accent"
              />
              {t('discoveries.attestation')}
            </label>

            <div className="space-y-1">
              <label className="block text-xs font-medium text-text-secondary">
                {t('discoveries.typeToConfirm', { username: discovery.pppUsername })}
              </label>
              <input
                type="text"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                className={cn(
                  'w-full rounded-md border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary focus:outline-none focus:ring-2',
                  typed.length === 0
                    ? 'border-border focus:ring-accent'
                    : usernameMatches
                      ? 'border-status-up/50 focus:ring-status-up'
                      : 'border-status-down/50 focus:ring-status-down',
                )}
              />
              {typed.length > 0 && !usernameMatches && (
                <p className="text-[11px] text-status-down">{t('discoveries.typeMismatch')}</p>
              )}
            </div>
          </section>
        </form>

        <div className="flex shrink-0 items-center justify-end gap-2 border-t border-border px-4 py-3">
          <Button variant="secondary" size="sm" onClick={onClose}>{t('common.cancel')}</Button>
          <Button size="sm" disabled={!canSubmit} loading={saving} onClick={(e) => void submit(e)}>
            <Link2 size={14} className="mr-1.5" />
            {t('discoveries.confirmBind')}
          </Button>
        </div>
      </div>
    </>
  );
}
