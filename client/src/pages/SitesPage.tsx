import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { MapPin, Plus, RotateCw, Search } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { CAPABILITIES } from '@obliwan/shared';
import { sitesApi } from '@/api/sites.api';
import { useSiteStore } from '@/store/siteStore';
import { useDeviceStore } from '@/store/deviceStore';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { cn } from '@/utils/cn';
import { verdictStyle } from '@/utils/verdict';
import { anonHostname } from '@/utils/anonymize';
import { formatMaintenanceWindow } from '@/utils/maintenance';
import toast from 'react-hot-toast';

interface SiteForm {
  code: string;
  name: string;
  address: string;
  contact: string;
  timezone: string;
}

const emptyForm: SiteForm = {
  code: '',
  name: '',
  address: '',
  contact: '',
  timezone: 'Europe/Paris',
};

export function SitesPage() {
  const { t, i18n } = useTranslation();
  const { sites, isLoading, loadError, fetchSites } = useSiteStore();
  const { devices, fetchDevices, siteRollup } = useDeviceStore();
  const { hasCapability } = useAuthStore();

  const canWrite = hasCapability(CAPABILITIES.DEVICE_WRITE);

  const [search, setSearch] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<SiteForm>(emptyForm);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void fetchSites();
    void fetchDevices();
  }, [fetchSites, fetchDevices]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return [...sites]
      .filter((s) =>
        !needle ||
        [s.name, s.code, s.address, s.contact]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(needle)),
      )
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [sites, search]);

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await sitesApi.create({
        code: form.code,
        name: form.name,
        address: form.address || null,
        contact: form.contact || null,
        timezone: form.timezone || undefined,
      });
      toast.success(t('sites.created'));
      setForm(emptyForm);
      setShowForm(false);
      void fetchSites();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('sites.failedCreate'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">{t('nav.sites')}</h1>
          <p className="mt-1 text-sm text-text-muted">{t('sites.subtitle', { count: sites.length })}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => { void fetchSites(); void fetchDevices(); }}>
            <RotateCw size={14} className={cn('mr-1.5', isLoading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
          {canWrite && (
            <Button size="sm" onClick={() => setShowForm((v) => !v)}>
              <Plus size={14} className="mr-1.5" />
              {t('sites.newSite')}
            </Button>
          )}
        </div>
      </div>

      {showForm && canWrite && (
        <form onSubmit={handleCreate} className="mb-5 rounded-lg border border-border bg-bg-secondary p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-text-secondary">
            {t('sites.newSite')}
          </h2>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <Input
              label={t('sites.fields.code')}
              value={form.code}
              onChange={(e) => setForm({ ...form, code: e.target.value })}
              placeholder="SIEGE"
              required
            />
            <Input
              label={t('sites.fields.name')}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
            <Input
              label={t('sites.fields.timezone')}
              value={form.timezone}
              onChange={(e) => setForm({ ...form, timezone: e.target.value })}
            />
            <Input
              label={t('sites.fields.address')}
              value={form.address}
              onChange={(e) => setForm({ ...form, address: e.target.value })}
              className="md:col-span-2"
            />
            <Input
              label={t('sites.fields.contact')}
              value={form.contact}
              onChange={(e) => setForm({ ...form, contact: e.target.value })}
            />
          </div>
          <p className="mt-3 text-xs text-text-muted">{t('sites.codeHint')}</p>
          <div className="mt-3 flex gap-2">
            <Button type="submit" size="sm" loading={saving}>{t('common.create')}</Button>
            <Button type="button" size="sm" variant="secondary" onClick={() => setShowForm(false)}>
              {t('common.cancel')}
            </Button>
          </div>
        </form>
      )}

      <div className="mb-4 flex items-center gap-2">
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('sites.searchPlaceholder')}
            className="w-64 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>
        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('devices.showing', { shown: filtered.length, total: sites.length })}
        </span>
      </div>

      {loadError ? (
        <div className="rounded-lg border border-status-down/40 bg-status-down/5 p-4 text-sm text-status-down">
          {t('sites.loadFailed')} — <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : isLoading && sites.length === 0 ? (
        <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
      ) : filtered.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <MapPin size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">
            {sites.length === 0 ? t('sites.empty') : t('sites.noMatch')}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full min-w-[820px] text-left text-sm">
            <thead>
              <tr className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
                <th className="px-3 py-2 font-medium">{t('sites.columns.code')}</th>
                <th className="px-3 py-2 font-medium">{t('sites.columns.name')}</th>
                <th className="px-3 py-2 font-medium">{t('sites.columns.presence')}</th>
                <th className="px-3 py-2 font-medium">{t('sites.columns.devices')}</th>
                <th className="px-3 py-2 font-medium">{t('sites.columns.maintenance')}</th>
                <th className="px-3 py-2 font-medium">{t('sites.columns.timezone')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((site) => {
                const rollup = siteRollup(site.id);
                const style = verdictStyle(rollup.worstVerdict);
                const known = rollup.total - rollup.unknown;
                return (
                  <tr key={site.id} className="transition-colors hover:bg-bg-hover">
                    <td className="px-3 py-2 font-mono text-[12px] text-text-secondary">{site.code}</td>
                    <td className="px-3 py-2">
                      <Link
                        to={`/sites/${site.id}`}
                        className="flex items-center gap-2 font-medium text-text-primary hover:text-accent"
                      >
                        <MapPin size={13} className="shrink-0 text-text-muted" />
                        {anonHostname(site.name)}
                      </Link>
                      {site.address && <div className="text-[11px] text-text-muted">{site.address}</div>}
                    </td>
                    <td className="px-3 py-2">
                      {rollup.total === 0 ? (
                        <span className="text-xs italic text-text-muted">{t('sites.noDevice')}</span>
                      ) : (
                        <span className="inline-flex items-center gap-2">
                          <span
                            className={cn(
                              'inline-block h-2 w-2 shrink-0 rounded-full',
                              known === 0 ? 'border-2 border-text-muted/60 bg-transparent' : style.dot,
                            )}
                          />
                          <span className="font-mono text-[12px] text-text-secondary">
                            {rollup.up}/{rollup.total}
                          </span>
                          {rollup.unknown > 0 && (
                            <span className="text-[10px] italic text-text-muted">
                              {t('sites.unknownCount', { count: rollup.unknown })}
                            </span>
                          )}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-[12px] text-text-secondary">
                      {site.deviceCount ?? devices.filter((d) => d.siteId === site.id).length}
                    </td>
                    <td className="px-3 py-2 text-[12px] text-text-secondary">
                      {formatMaintenanceWindow(site.maintenanceWindow, i18n.language)
                        ?? <span className="italic text-text-muted">{t('sites.noMaintenanceWindow')}</span>}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-text-muted">{site.timezone}</td>
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
