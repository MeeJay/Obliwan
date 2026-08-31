import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Layers, Plus, RotateCw, Search, Lock, FileText, CheckCircle2 } from 'lucide-react';
import { CAPABILITIES, DEVICE_BRANDS, type DeviceBrand } from '@obliwan/shared';
import { templatesApi, type Template, type TemplateRevision } from '@/api/templates.api';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';

/**
 * Templates and their revisions (M5).
 *
 * ┌─ THE TWO REFUSALS THIS SCREEN MUST MAKE VISIBLE ─────────────────────────┐
 * │ 1. A PUBLISHED REVISION IS FROZEN. Publishing is offered once and then    │
 * │    the button is gone — not disabled with a tooltip, gone. A plan pins    │
 * │    itself to a revision, and a pin that can be edited afterwards is not   │
 * │    a pin: the plan an operator approved in March would silently mean      │
 * │    something else in June.                                                │
 * │ 2. LIBRARY TEMPLATES ARE READ-ONLY. They belong to no tenant (`isLibrary`)│
 * │    and are shared by every one of them. The screen shows the padlock      │
 * │    rather than letting a save fail server-side, because a form that       │
 * │    accepts input it cannot save is a form that wastes somebody's work.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * There is no delete. The server has no `DELETE /:id` either:
 * `config_renders.revision_id` is ON DELETE RESTRICT, because a template whose
 * revisions produced renders that produced plans is the answer to "why is this
 * line on this router". Archiving is a status change.
 */
export function TemplatesPage() {
  const { t } = useTranslation();
  const { hasCapability } = useAuthStore();
  const canWrite = hasCapability(CAPABILITIES.TEMPLATE_WRITE);

  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Template | null>(null);
  const [revisions, setRevisions] = useState<TemplateRevision[] | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({ name: '', description: '', brand: '' as '' | DeviceBrand });

  const load = async () => {
    setLoading(true);
    try {
      setTemplates(await templatesApi.list({ includeLibrary: true }));
    } catch {
      toast.error(t('templates.loadFailed', { defaultValue: 'Could not load templates' }));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  useEffect(() => {
    if (!selected) { setRevisions(null); return; }
    let alive = true;
    templatesApi.revisions(selected.id)
      .then((r) => { if (alive) setRevisions(r); })
      .catch(() => { if (alive) setRevisions([]); });
    return () => { alive = false; };
  }, [selected]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return templates;
    return templates.filter((x) =>
      x.name.toLowerCase().includes(q) || (x.description ?? '').toLowerCase().includes(q));
  }, [templates, search]);

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const created = await templatesApi.create({
        name: form.name,
        description: form.description || null,
        brand: form.brand || null,
      });
      toast.success(t('templates.created', { defaultValue: 'Template created' }));
      setShowCreate(false);
      setForm({ name: '', description: '', brand: '' });
      setTemplates((prev) => [...prev, created].sort((a, b) => a.name.localeCompare(b.name)));
    } catch (err) {
      const m = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(m ?? t('templates.createFailed', { defaultValue: 'Could not create the template' }));
    } finally {
      setSaving(false);
    }
  };

  const handlePublish = async (rev: TemplateRevision) => {
    // Asked in plain words, because it cannot be undone and the consequence is
    // not obvious from a button labelled "publish".
    const ok = window.confirm(t('templates.publishConfirm', {
      defaultValue:
        'Publishing revision {{n}} freezes it for good. Plans will pin themselves to it and it '
        + 'can never be edited again — a change means a new revision. Continue?',
      n: rev.revision,
    }));
    if (!ok) return;
    try {
      const updated = await templatesApi.publish(rev.id);
      setRevisions((prev) => (prev ?? []).map((r) => (r.id === updated.id ? updated : r)));
      toast.success(t('templates.published', { defaultValue: 'Revision published and frozen' }));
    } catch (err) {
      const m = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(m ?? t('templates.publishFailed', { defaultValue: 'Could not publish' }));
    }
  };

  if (loading) return <div className="p-6"><LoadingSpinner /></div>;

  return (
    <div className="p-6">
      <div className="mb-5 flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <Layers size={22} /> {t('nav.templates')}
        </h1>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="secondary" onClick={() => void load()}>
            <RotateCw size={14} className="mr-1.5" />{t('common.refresh', { defaultValue: 'Refresh' })}
          </Button>
          {canWrite && (
            <Button size="sm" onClick={() => setShowCreate((v) => !v)}>
              <Plus size={14} className="mr-1.5" />{t('templates.new', { defaultValue: 'New template' })}
            </Button>
          )}
        </div>
      </div>

      {showCreate && canWrite && (
        <form onSubmit={handleCreate} className="mb-5 rounded-lg border border-border bg-bg-secondary p-4">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <Input
              label={t('templates.fields.name', { defaultValue: 'Name' })}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
            <Input
              label={t('templates.fields.description', { defaultValue: 'Description' })}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('templates.fields.brand', { defaultValue: 'Brand' })}
              </label>
              <select
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary"
                value={form.brand}
                onChange={(e) => setForm({ ...form, brand: e.target.value as '' | DeviceBrand })}
              >
                <option value="">{t('templates.anyBrand', { defaultValue: 'Any brand' })}</option>
                {DEVICE_BRANDS.map((b) => <option key={b} value={b}>{t(`fleet.brand.${b}`)}</option>)}
              </select>
            </div>
          </div>
          <div className="mt-3 flex gap-2">
            <Button type="submit" size="sm" loading={saving}>{t('common.create')}</Button>
            <Button type="button" size="sm" variant="secondary" onClick={() => setShowCreate(false)}>
              {t('common.cancel')}
            </Button>
          </div>
        </form>
      )}

      <div className="mb-4 flex items-center gap-2">
        <Search size={16} className="text-text-muted" />
        <input
          className="w-full max-w-sm rounded-md border border-border bg-bg-tertiary px-3 py-1.5 text-sm text-text-primary"
          placeholder={t('templates.search', { defaultValue: 'Search templates…' })}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-border bg-bg-secondary">
          {filtered.length === 0 ? (
            <div className="px-6 py-12 text-center text-sm text-text-secondary">
              {t('templates.empty', { defaultValue: 'No template yet.' })}
            </div>
          ) : (
            <ul className="divide-y divide-border">
              {filtered.map((tpl) => (
                <li key={tpl.id}>
                  <button
                    type="button"
                    onClick={() => setSelected(tpl)}
                    className={`flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-bg-tertiary ${
                      selected?.id === tpl.id ? 'bg-bg-tertiary' : ''
                    }`}
                  >
                    <FileText size={16} className="shrink-0 text-text-muted" />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm text-text-primary">{tpl.name}</span>
                      <span className="block truncate text-xs text-text-muted">
                        {tpl.description ?? '—'}
                      </span>
                    </span>
                    {tpl.isLibrary && (
                      <Lock
                        size={14}
                        className="shrink-0 text-text-muted"
                        aria-label={t('templates.libraryReadOnly', { defaultValue: 'Shipped library — read-only' })}
                      />
                    )}
                    <span className="shrink-0 font-mono text-[10px] uppercase text-text-muted">
                      {tpl.status}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="rounded-lg border border-border bg-bg-secondary p-4">
          {!selected ? (
            <p className="py-10 text-center text-sm text-text-secondary">
              {t('templates.pickOne', { defaultValue: 'Select a template to see its revisions.' })}
            </p>
          ) : (
            <>
              <div className="mb-3">
                <h2 className="text-sm font-semibold text-text-primary">{selected.name}</h2>
                {selected.isLibrary && (
                  <p className="mt-1 text-xs text-text-muted">
                    {t('templates.libraryNote', {
                      defaultValue:
                        'Shipped library: shared by every tenant and read-only. Duplicate it to change anything.',
                    })}
                  </p>
                )}
              </div>

              {revisions === null ? (
                <LoadingSpinner />
              ) : revisions.length === 0 ? (
                <p className="py-6 text-center text-sm text-text-secondary">
                  {t('templates.noRevision', { defaultValue: 'No revision yet.' })}
                </p>
              ) : (
                <ul className="divide-y divide-border">
                  {revisions.map((rev) => {
                    const published = rev.status === 'published';
                    return (
                      <li key={rev.id} className="flex items-center gap-3 py-2.5">
                        <span className="font-mono text-xs text-text-muted">#{rev.revision}</span>
                        <span className="min-w-0 flex-1">
                          <span className="block text-sm text-text-primary">
                            {published
                              ? t('templates.frozen', { defaultValue: 'Published — frozen' })
                              : t('templates.draft', { defaultValue: 'Draft' })}
                          </span>
                          <span className="block font-mono text-[10px] text-text-muted">
                            {rev.bodySha256?.slice(0, 12)}
                          </span>
                        </span>
                        {published ? (
                          <CheckCircle2 size={16} className="shrink-0 text-text-muted" />
                        ) : canWrite && !selected.isLibrary ? (
                          <Button size="sm" variant="secondary" onClick={() => void handlePublish(rev)}>
                            {t('templates.publish', { defaultValue: 'Publish' })}
                          </Button>
                        ) : null}
                      </li>
                    );
                  })}
                </ul>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
