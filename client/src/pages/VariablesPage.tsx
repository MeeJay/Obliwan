import { useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Braces, KeyRound, RotateCw, Trash2 } from 'lucide-react';
import { CAPABILITIES } from '@obliwan/shared';
import { variablesApi, type VariableScope } from '@/api/variables.api';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';

/**
 * Inherited variables (M5).
 *
 * ┌─ A SECRET IS SHOWN AS EXISTING, NEVER AS A VALUE ────────────────────────┐
 * │ The API returns `isSecret` and no value — not a masked one, none. So this │
 * │ screen renders a key icon and the word "secret", and offers to REPLACE    │
 * │ it. There is no reveal button because there is nothing to reveal: §8.2    │
 * │ keeps a rendered secret in memory only, on the vault → device path.       │
 * │                                                                          │
 * │ A `••••` placeholder would be worse than this. It implies the value is    │
 * │ one click away and invites somebody to build that click.                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The scope selector shows what is set AT a level, not the folded result: an
 * operator editing variables needs to know which level they are writing to,
 * because a value set closer to the device silently wins over this one. The
 * folded view belongs on the device page, where the question is "what will
 * this box get".
 */
export function VariablesPage() {
  const { t } = useTranslation();
  const { hasCapability } = useAuthStore();
  const canWrite = hasCapability(CAPABILITIES.TEMPLATE_WRITE);

  const [scope, setScope] = useState<VariableScope>('tenant');
  const [entries, setEntries] = useState<Array<{ key: string; value: unknown; isSecret: boolean }>>([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ key: '', value: '', isSecret: false });
  const [saving, setSaving] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const raw = await variablesApi.atScope(scope);
      // The resolver owns the shape; normalise defensively rather than assume.
      const list = Array.isArray((raw as { variables?: unknown }).variables)
        ? ((raw as { variables: Array<{ key: string; value?: unknown; isSecret?: boolean }> }).variables)
            .map((v) => ({ key: v.key, value: v.value, isSecret: Boolean(v.isSecret) }))
        : Object.entries(raw as Record<string, unknown>)
            .filter(([k]) => k !== 'variables')
            .map(([k, v]) => ({ key: k, value: v, isSecret: v === null || v === undefined }));
      setEntries(list.sort((a, b) => a.key.localeCompare(b.key)));
    } catch {
      toast.error(t('variables.loadFailed', { defaultValue: 'Could not load variables' }));
      setEntries([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, [scope]);

  const handleSet = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await variablesApi.setAtScope(scope, undefined, {
        key: form.key,
        value: form.isSecret ? form.value : tryJson(form.value),
        isSecret: form.isSecret,
      });
      toast.success(t('variables.saved', { defaultValue: 'Variable saved' }));
      setForm({ key: '', value: '', isSecret: false });
      void load();
    } catch (err) {
      const m = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(m ?? t('variables.saveFailed', { defaultValue: 'Could not save' }));
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async (key: string) => {
    if (!window.confirm(t('variables.removeConfirm', {
      defaultValue: 'Remove "{{key}}" at this scope? Any value inherited from a wider scope takes over.',
      key,
    }))) return;
    try {
      await variablesApi.removeAtScope(scope, undefined, key);
      void load();
    } catch {
      toast.error(t('variables.removeFailed', { defaultValue: 'Could not remove' }));
    }
  };

  return (
    <div className="p-6">
      <div className="mb-5 flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <Braces size={22} /> {t('nav.variables')}
        </h1>
        <div className="flex items-center gap-2">
          <select
            className="rounded-md border border-border bg-bg-tertiary px-3 py-1.5 text-sm text-text-primary"
            value={scope}
            onChange={(e) => setScope(e.target.value as VariableScope)}
          >
            <option value="tenant">{t('variables.scope.tenant', { defaultValue: 'Tenant' })}</option>
            <option value="global">{t('variables.scope.global', { defaultValue: 'Global' })}</option>
          </select>
          <Button size="sm" variant="secondary" onClick={() => void load()}>
            <RotateCw size={14} className="mr-1.5" />{t('common.refresh', { defaultValue: 'Refresh' })}
          </Button>
        </div>
      </div>

      <p className="mb-4 text-xs text-text-muted">
        {t('variables.scopeHint', {
          defaultValue:
            'These are the values set AT this level. Resolution runs global → tenant → group chain → '
            + 'device, and a value set closer to the device wins over this one.',
        })}
      </p>

      {canWrite && (
        <form onSubmit={handleSet} className="mb-5 rounded-lg border border-border bg-bg-secondary p-4">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <Input
              label={t('variables.fields.key', { defaultValue: 'Key' })}
              value={form.key}
              onChange={(e) => setForm({ ...form, key: e.target.value })}
              placeholder="wan.mtu"
              required
            />
            <Input
              label={t('variables.fields.value', { defaultValue: 'Value' })}
              value={form.value}
              onChange={(e) => setForm({ ...form, value: e.target.value })}
              type={form.isSecret ? 'password' : 'text'}
              autoComplete="off"
            />
            <label className="flex items-end gap-2 pb-2 text-sm text-text-secondary">
              <input
                type="checkbox"
                checked={form.isSecret}
                onChange={(e) => setForm({ ...form, isSecret: e.target.checked })}
              />
              {t('variables.fields.isSecret', { defaultValue: 'Secret (never readable again)' })}
            </label>
          </div>
          <div className="mt-3">
            <Button type="submit" size="sm" loading={saving}>{t('common.save', { defaultValue: 'Save' })}</Button>
          </div>
        </form>
      )}

      {loading ? <LoadingSpinner /> : (
        <div className="rounded-lg border border-border bg-bg-secondary">
          {entries.length === 0 ? (
            <div className="px-6 py-12 text-center text-sm text-text-secondary">
              {t('variables.empty', { defaultValue: 'No variable set at this level.' })}
            </div>
          ) : (
            <table className="w-full text-sm">
              <tbody className="divide-y divide-border">
                {entries.map((v) => (
                  <tr key={v.key}>
                    <td className="px-4 py-2.5 font-mono text-text-primary">{v.key}</td>
                    <td className="px-4 py-2.5 text-text-secondary">
                      {v.isSecret ? (
                        <span className="inline-flex items-center gap-1.5 text-text-muted">
                          <KeyRound size={13} />
                          {t('variables.secretSet', { defaultValue: 'secret — set, never readable' })}
                        </span>
                      ) : (
                        <span className="font-mono">{JSON.stringify(v.value)}</span>
                      )}
                    </td>
                    <td className="w-10 px-4 py-2.5 text-right">
                      {canWrite && (
                        <button
                          type="button"
                          onClick={() => void handleRemove(v.key)}
                          className="text-text-muted hover:text-text-primary"
                          title={t('common.delete', { defaultValue: 'Delete' })}
                        >
                          <Trash2 size={14} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

/** A variable is typed JSON on the server. Plain text stays plain text. */
function tryJson(raw: string): unknown {
  const s = raw.trim();
  if (s === '') return '';
  if (/^(true|false|null|-?\d+(\.\d+)?|\[.*\]|\{.*\})$/s.test(s)) {
    try { return JSON.parse(s); } catch { return raw; }
  }
  return raw;
}
