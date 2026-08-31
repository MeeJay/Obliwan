import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { Plus, Router, Radio, RotateCw, Search, X, Eye } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  DEVICE_BRANDS,
  DEVICE_FAMILIES,
  DEVICE_ROLES,
  DEVICE_STATUSES,
  FAMILY_BRAND,
  CAPABILITIES,
  type DeviceBrand,
  type DeviceFamily,
  type DeviceRole,
} from '@obliwan/shared';
import { devicesApi } from '@/api/devices.api';
import { useDeviceStore } from '@/store/deviceStore';
import { useSiteStore } from '@/store/siteStore';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { PresenceDot } from '@/components/fleet/PresenceDot';
import { VerdictBadge } from '@/components/fleet/VerdictBadge';
import { cn } from '@/utils/cn';
import { deviceStatusStyle } from '@/utils/verdict';
import { anonHostname } from '@/utils/anonymize';
import toast from 'react-hot-toast';

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

interface CreateForm {
  name: string;
  brand: DeviceBrand;
  family: DeviceFamily;
  role: DeviceRole;
  siteId: string;
  pppUsername: string;
  tunnelIp: string;
  model: string;
  serial: string;
  /**
   * Reachability. Filled in, the SERVER dials the box, reads its identity and
   * keeps the credential in the vault. Left empty, this is a plain row that
   * nobody will ever dial.
   *
   * One form, two verbs, and the fork is the presence of a credential — which
   * is also the capability boundary on the server (`CREDENTIAL_MANAGE`). An
   * operator adding their own router should not have to know which of two
   * screens is the right one.
   */
  host: string;
  port: string;
  username: string;
  password: string;
  useTls: boolean;
}

const emptyCreateForm: CreateForm = {
  name: '',
  brand: 'mikrotik',
  family: 'mikrotik_routeros7',
  role: 'cpe',
  siteId: '',
  pppUsername: '',
  tunnelIp: '',
  model: '',
  serial: '',
  host: '',
  port: '',
  username: '',
  password: '',
  useTls: false,
};

/**
 * Fleet table (spec §4.2).
 *
 * Filtering happens client-side on purpose: the sidebar tree and this page
 * share one `deviceStore`, and a server-side filtered fetch would silently
 * empty the tree every time an operator typed in the search box. At the scale
 * this product targets (a few hundred devices) the full list is one request.
 */
export function DevicesPage() {
  const { t } = useTranslation();
  const { devices, isLoading, loadError, fetchDevices, filters, setFilters, resetFilters, presence } =
    useDeviceStore();
  const { sites, fetchSites } = useSiteStore();
  const { hasCapability, getDevicePermission } = useAuthStore();

  const canWriteFleet = hasCapability(CAPABILITIES.DEVICE_WRITE);

  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<CreateForm>(emptyCreateForm);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void fetchDevices();
    void fetchSites();
  }, [fetchDevices, fetchSites]);

  // Models are whatever the fleet actually reports — never a hard-coded list.
  const models = useMemo(() => {
    const set = new Set<string>();
    devices.forEach((d) => { if (d.model) set.add(d.model); });
    return [...set].sort();
  }, [devices]);

  const filtered = useMemo(() => {
    const needle = filters.search.trim().toLowerCase();
    return devices
      .filter((d) => {
        if (filters.brand && d.brand !== filters.brand) return false;
        if (filters.model && d.model !== filters.model) return false;
        if (filters.status && d.status !== filters.status) return false;
        if (filters.role && d.role !== filters.role) return false;
        if (filters.siteId !== null && d.siteId !== filters.siteId) return false;
        if (!needle) return true;
        return [d.name, d.model, d.serial, d.pppUsername, d.tunnelIp, d.systemIdentity]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(needle));
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [devices, filters]);

  const siteName = (siteId: number | null) =>
    siteId === null ? null : sites.find((s) => s.id === siteId)?.name ?? `#${siteId}`;

  const familiesForBrand = (brand: DeviceBrand) =>
    DEVICE_FAMILIES.filter((f) => FAMILY_BRAND[f] === brand);

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      // A credential turns "record a row" into "go and look". The server dials,
      // reads the identity off the hardware and vaults the secret; the device
      // still lands `pending`, because a row an operator typed is a claim about
      // a box and a human confirms it afterwards (D5 / R4).
      const willProbe = Boolean(form.host && form.username && form.password);
      if (willProbe) {
        const r = await devicesApi.enrollProbe({
          name: form.name,
          family: form.family,
          host: form.host,
          port: form.port ? Number(form.port) : undefined,
          username: form.username,
          password: form.password,
          useTls: form.useTls,
          siteId: form.siteId ? Number(form.siteId) : null,
        });
        // Said out loud rather than left to be discovered on the first push:
        // without a serial or a system identity, `assertTargetBinding` refuses
        // every write to this device, forever.
        if (r.identityRead) toast.success(t('devices.enrolledIdentityRead'));
        else toast.error(t('devices.enrolledNoIdentity'));
        setShowCreate(false);
        setForm(emptyCreateForm);
        void fetchDevices();
        return;
      }

      await devicesApi.create({
        name: form.name,
        brand: form.brand,
        family: form.family,
        role: form.role,
        siteId: form.siteId ? Number(form.siteId) : null,
        pppUsername: form.pppUsername || null,
        tunnelIp: form.tunnelIp || null,
        model: form.model || null,
        serial: form.serial || null,
      });
      toast.success(t('devices.created'));
      setShowCreate(false);
      setForm(emptyCreateForm);
      void fetchDevices();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('devices.failedCreate'));
    } finally {
      setSaving(false);
    }
  };

  const activeFilterCount =
    (filters.brand ? 1 : 0) +
    (filters.model ? 1 : 0) +
    (filters.status ? 1 : 0) +
    (filters.role ? 1 : 0) +
    (filters.siteId !== null ? 1 : 0) +
    (filters.search ? 1 : 0);

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">{t('nav.devices')}</h1>
          <p className="mt-1 text-sm text-text-muted">
            {t('devices.subtitle', { count: devices.length })}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => void fetchDevices()}>
            <RotateCw size={14} className={cn('mr-1.5', isLoading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
          {canWriteFleet && (
            <Button size="sm" onClick={() => setShowCreate((v) => !v)}>
              <Plus size={14} className="mr-1.5" />
              {t('devices.newDevice')}
            </Button>
          )}
        </div>
      </div>

      {/* Create form */}
      {showCreate && canWriteFleet && (
        <form
          onSubmit={handleCreate}
          className="mb-5 rounded-lg border border-border bg-bg-secondary p-4"
        >
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-text-secondary">
            {t('devices.newDevice')}
          </h2>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <Input
              label={t('devices.fields.name')}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('devices.fields.brand')}
              </label>
              <select
                className={cn(selectClass, 'w-full py-2')}
                value={form.brand}
                onChange={(e) => {
                  const brand = e.target.value as DeviceBrand;
                  setForm({ ...form, brand, family: familiesForBrand(brand)[0] });
                }}
              >
                {DEVICE_BRANDS.map((b) => (
                  <option key={b} value={b}>{t(`fleet.brand.${b}`)}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('devices.fields.family')}
              </label>
              <select
                className={cn(selectClass, 'w-full py-2')}
                value={form.family}
                onChange={(e) => setForm({ ...form, family: e.target.value as DeviceFamily })}
              >
                {familiesForBrand(form.brand).map((f) => (
                  <option key={f} value={f}>{t(`fleet.family.${f}`)}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('devices.fields.role')}
              </label>
              <select
                className={cn(selectClass, 'w-full py-2')}
                value={form.role}
                onChange={(e) => setForm({ ...form, role: e.target.value as DeviceRole })}
              >
                {DEVICE_ROLES.map((r) => (
                  <option key={r} value={r}>{t(`fleet.role.${r}`)}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('devices.fields.site')}
              </label>
              <select
                className={cn(selectClass, 'w-full py-2')}
                value={form.siteId}
                onChange={(e) => setForm({ ...form, siteId: e.target.value })}
              >
                <option value="">{t('devices.noSite')}</option>
                {sites.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </div>
            <Input
              label={t('devices.fields.pppUsername')}
              value={form.pppUsername}
              onChange={(e) => setForm({ ...form, pppUsername: e.target.value })}
              placeholder={t('devices.fields.pppUsernamePlaceholder')}
            />
            <Input
              label={t('devices.fields.model')}
              value={form.model}
              onChange={(e) => setForm({ ...form, model: e.target.value })}
            />
            <Input
              label={t('devices.fields.serial')}
              value={form.serial}
              onChange={(e) => setForm({ ...form, serial: e.target.value })}
            />
            <Input
              label={t('devices.fields.tunnelIp')}
              value={form.tunnelIp}
              onChange={(e) => setForm({ ...form, tunnelIp: e.target.value })}
              placeholder="10.10.0.42"
            />
          </div>

          {/* Reachability — optional, and the fork between the two verbs.
              Filled in, ObliWAN dials the box now and vaults the credential.
              Left empty, this stays a plain row nobody will dial. */}
          <div className="mt-4 border-t border-border pt-4">
            <h3 className="mb-1 text-sm font-semibold uppercase tracking-wide text-text-secondary">
              {t('devices.reachTitle')}
            </h3>
            <p className="mb-3 text-xs text-text-muted">{t('devices.reachHint')}</p>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
              <Input
                label={t('devices.fields.host')}
                value={form.host}
                onChange={(e) => setForm({ ...form, host: e.target.value })}
                placeholder="192.168.88.1"
              />
              <Input
                label={t('devices.fields.port')}
                value={form.port}
                onChange={(e) => setForm({ ...form, port: e.target.value })}
                placeholder="8728"
              />
              <Input
                label={t('devices.fields.username')}
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                placeholder="obliwan-svc"
                autoComplete="off"
              />
              <Input
                label={t('devices.fields.password')}
                type="password"
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                autoComplete="new-password"
              />
              <label className="flex items-end gap-2 pb-2 text-sm text-text-secondary">
                <input
                  type="checkbox"
                  checked={form.useTls}
                  onChange={(e) => setForm({ ...form, useTls: e.target.checked })}
                />
                {t('devices.fields.useTls')}
              </label>
            </div>
          </div>

          <p className="mt-3 text-xs text-text-muted">{t('devices.createHint')}</p>
          <div className="mt-3 flex gap-2">
            <Button type="submit" size="sm" loading={saving}>{t('common.create')}</Button>
            <Button type="button" size="sm" variant="secondary" onClick={() => setShowCreate(false)}>
              {t('common.cancel')}
            </Button>
          </div>
        </form>
      )}

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            value={filters.search}
            onChange={(e) => setFilters({ search: e.target.value })}
            placeholder={t('devices.searchPlaceholder')}
            className="w-64 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>

        <select className={selectClass} value={filters.brand} onChange={(e) => setFilters({ brand: e.target.value })}>
          <option value="">{t('devices.filters.allBrands')}</option>
          {DEVICE_BRANDS.map((b) => <option key={b} value={b}>{t(`fleet.brand.${b}`)}</option>)}
        </select>

        <select className={selectClass} value={filters.model} onChange={(e) => setFilters({ model: e.target.value })}>
          <option value="">{t('devices.filters.allModels')}</option>
          {models.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>

        <select className={selectClass} value={filters.status} onChange={(e) => setFilters({ status: e.target.value })}>
          <option value="">{t('devices.filters.allStatuses')}</option>
          {DEVICE_STATUSES.map((s) => <option key={s} value={s}>{t(`fleet.status.${s}`)}</option>)}
        </select>

        <select className={selectClass} value={filters.role} onChange={(e) => setFilters({ role: e.target.value })}>
          <option value="">{t('devices.filters.allRoles')}</option>
          {DEVICE_ROLES.map((r) => <option key={r} value={r}>{t(`fleet.role.${r}`)}</option>)}
        </select>

        <select
          className={selectClass}
          value={filters.siteId ?? ''}
          onChange={(e) => setFilters({ siteId: e.target.value ? Number(e.target.value) : null })}
        >
          <option value="">{t('devices.filters.allSites')}</option>
          {sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>

        {activeFilterCount > 0 && (
          <button
            onClick={resetFilters}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            <X size={12} />
            {t('devices.filters.clear')}
          </button>
        )}

        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('devices.showing', { shown: filtered.length, total: devices.length })}
        </span>
      </div>

      {/* Table */}
      {loadError ? (
        <div className="rounded-lg border border-status-down/40 bg-status-down/5 p-4 text-sm text-status-down">
          {t('devices.loadFailed')} — <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : isLoading && devices.length === 0 ? (
        <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
      ) : filtered.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Router size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">
            {devices.length === 0 ? t('devices.empty') : t('devices.noMatch')}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead>
              <tr className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
                <th className="px-3 py-2 font-medium">{t('devices.columns.presence')}</th>
                <th className="px-3 py-2 font-medium">{t('devices.columns.name')}</th>
                <th className="px-3 py-2 font-medium">{t('devices.columns.brand')}</th>
                <th className="px-3 py-2 font-medium">{t('devices.columns.model')}</th>
                <th className="px-3 py-2 font-medium">{t('devices.columns.site')}</th>
                <th className="px-3 py-2 font-medium">{t('devices.columns.status')}</th>
                <th className="px-3 py-2 font-medium">{t('devices.columns.verdict')}</th>
                <th className="px-3 py-2 font-medium">{t('devices.columns.lastSeen')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((device) => {
                const live = presence[device.id] ?? device.presence ?? null;
                const perm = getDevicePermission(device.id, device.groupId);
                return (
                  <tr key={device.id} className="group transition-colors hover:bg-bg-hover">
                    <td className="px-3 py-2">
                      <PresenceDot presence={live} size={9} />
                    </td>
                    <td className="px-3 py-2">
                      <Link
                        to={`/devices/${device.id}`}
                        className="flex items-center gap-2 font-medium text-text-primary hover:text-accent"
                      >
                        {device.role === 'concentrator'
                          ? <Radio size={13} className="shrink-0 text-accent" />
                          : <Router size={13} className="shrink-0 text-text-muted" />}
                        {anonHostname(device.name)}
                      </Link>
                      {device.pppUsername && (
                        <span className="font-mono text-[10px] text-text-muted">{device.pppUsername}</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-text-secondary">
                      {t(`fleet.brand.${device.brand}`)}
                      <div className="text-[10px] text-text-muted">{t(`fleet.family.${device.family}`)}</div>
                    </td>
                    <td className="px-3 py-2 text-text-secondary">{device.model ?? '—'}</td>
                    <td className="px-3 py-2 text-text-secondary">
                      {device.siteId !== null ? (
                        <Link to={`/sites/${device.siteId}`} className="hover:text-accent">
                          {siteName(device.siteId)}
                        </Link>
                      ) : (
                        <span className="italic text-text-muted">{t('fleet.unassignedSite')}</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <span className={cn(
                        'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium',
                        deviceStatusStyle(device.status),
                      )}>
                        {t(`fleet.status.${device.status}`)}
                      </span>
                      {perm === 'ro' && (
                        <span
                          className="ml-1.5 inline-flex items-center gap-0.5 text-[10px] text-text-muted"
                          title={t('devices.readOnlyHint')}
                        >
                          <Eye size={9} />{t('users.teams.roLabel')}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <VerdictBadge verdict={live?.verdict ?? null} />
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-text-muted">
                      {device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString() : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

