import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { KeyRound, Plus, Trash2, RotateCw } from 'lucide-react';
import toast from 'react-hot-toast';
import { snmpApi, type SnmpCredential, type SnmpCredentialInput } from '@/api/snmp.api';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { cn } from '@/utils/cn';

/**
 * SNMP credentials — the one gesture that turns supervision on for a fleet.
 *
 * ┌─ WHY THIS SCREEN DID NOT EXIST, AND WHY THAT MATTERED ───────────────────┐
 * │ The server has had full CRUD on `snmp_credentials` since M3. The client   │
 * │ never had a page, so the only way to create one was curl — and the        │
 * │ "Automatic SNMP target credential" setting was a sentence pointing at a   │
 * │ screen that was not there. A feature reachable only by its API is a       │
 * │ feature the product does not have.                                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── THE SECRET GOES ONE WAY ─────────────────────────────────────────────────
 * A community string is typed here, sent once, and encrypted into the vault.
 * It never comes back: the list shows `hasCommunity: true` and no field capable
 * of carrying the value. There is deliberately no "reveal" and no "edit the
 * community" — you replace a credential, you do not read one back (section
 * 8.2). The form says so, because an operator who expects to find it later will
 * otherwise write it down somewhere worse.
 *
 * ── AND WHY DELETING CAN FAIL ───────────────────────────────────────────────
 * The server refuses with 409 while any target still uses it. That is not an
 * obstacle to route around: deleting it anyway would take every device polled
 * with it out of supervision, silently, and a fleet that stopped being watched
 * looks exactly like a fleet with nothing wrong.
 */

const EMPTY: SnmpCredentialInput = { name: '', version: 'v2c', community: '' };

export function SnmpCredentialsCard() {
  const { t } = useTranslation();
  const [rows, setRows] = useState<SnmpCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<SnmpCredentialInput>(EMPTY);
  const [saving, setSaving] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      setRows(await snmpApi.listCredentials());
    } catch {
      setRows([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  const submit = async () => {
    setSaving(true);
    try {
      await snmpApi.createCredential(form);
      toast.success(t('snmpCred.created'));
      setForm(EMPTY);
      setShowForm(false);
      await load();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('snmpCred.createFailed'));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (c: SnmpCredential) => {
    if (!confirm(t('snmpCred.confirmDelete', { name: c.name }))) return;
    try {
      await snmpApi.deleteCredential(c.id);
      toast.success(t('snmpCred.deleted'));
      await load();
    } catch (err) {
      // The 409 message names the reason — targets still use it. Forwarded
      // verbatim rather than flattened to "delete failed".
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('snmpCred.deleteFailed'));
    }
  };

  const isV3 = form.version === 'v3';

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-text-primary">
            <KeyRound size={15} /> {t('snmpCred.title')}
          </h3>
          <p className="mt-0.5 text-xs text-text-muted">{t('snmpCred.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="secondary" onClick={() => void load()}>
            <RotateCw size={13} className={cn(loading && 'animate-spin')} />
          </Button>
          <Button size="sm" onClick={() => setShowForm((v) => !v)}>
            <Plus size={13} className="mr-1.5" />{t('snmpCred.add')}
          </Button>
        </div>
      </div>

      {showForm && (
        <div className="mb-4 rounded-md border border-border bg-bg-tertiary p-3">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <Input
              label={t('snmpCred.name')}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder={t('snmpCred.namePlaceholder')}
            />
            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('snmpCred.version')}
              </label>
              <select
                className="w-full rounded-md border border-border bg-bg-secondary px-2 py-2 text-sm text-text-primary"
                value={form.version}
                onChange={(e) => setForm({
                  ...EMPTY,
                  name: form.name,
                  version: e.target.value as SnmpCredentialInput['version'],
                })}
              >
                <option value="v2c">v2c</option>
                <option value="v1">v1</option>
                <option value="v3">v3 (USM)</option>
              </select>
            </div>

            {!isV3 ? (
              <Input
                label={t('snmpCred.community')}
                type="password"
                value={form.community ?? ''}
                onChange={(e) => setForm({ ...form, community: e.target.value })}
              />
            ) : (
              <Input
                label={t('snmpCred.username')}
                value={form.username ?? ''}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
              />
            )}

            {isV3 && (
              <>
                <div className="space-y-1">
                  <label className="block text-sm font-medium text-text-secondary">
                    {t('snmpCred.securityLevel')}
                  </label>
                  <select
                    className="w-full rounded-md border border-border bg-bg-secondary px-2 py-2 text-sm text-text-primary"
                    value={form.securityLevel ?? 'authPriv'}
                    onChange={(e) => setForm({ ...form, securityLevel: e.target.value })}
                  >
                    <option value="authPriv">authPriv</option>
                    <option value="authNoPriv">authNoPriv</option>
                    <option value="noAuthNoPriv">noAuthNoPriv</option>
                  </select>
                </div>
                <div className="space-y-1">
                  <label className="block text-sm font-medium text-text-secondary">
                    {t('snmpCred.authProtocol')}
                  </label>
                  <select
                    className="w-full rounded-md border border-border bg-bg-secondary px-2 py-2 text-sm text-text-primary"
                    value={form.authProtocol ?? 'sha256'}
                    onChange={(e) => setForm({ ...form, authProtocol: e.target.value })}
                  >
                    <option value="sha256">SHA-256</option>
                    <option value="sha512">SHA-512</option>
                    <option value="sha1">SHA-1</option>
                    <option value="md5">MD5</option>
                  </select>
                </div>
                <Input
                  label={t('snmpCred.authKey')}
                  type="password"
                  value={form.authKey ?? ''}
                  onChange={(e) => setForm({ ...form, authKey: e.target.value })}
                />
                <div className="space-y-1">
                  <label className="block text-sm font-medium text-text-secondary">
                    {t('snmpCred.privProtocol')}
                  </label>
                  <select
                    className="w-full rounded-md border border-border bg-bg-secondary px-2 py-2 text-sm text-text-primary"
                    value={form.privProtocol ?? 'aes128'}
                    onChange={(e) => setForm({ ...form, privProtocol: e.target.value })}
                  >
                    <option value="aes128">AES-128</option>
                    <option value="aes256">AES-256</option>
                    <option value="des">DES</option>
                  </select>
                </div>
                <Input
                  label={t('snmpCred.privKey')}
                  type="password"
                  value={form.privKey ?? ''}
                  onChange={(e) => setForm({ ...form, privKey: e.target.value })}
                />
              </>
            )}
          </div>

          <p className="mt-3 text-xs text-text-muted">{t('snmpCred.oneWayHint')}</p>

          <div className="mt-3 flex gap-2">
            <Button size="sm" onClick={() => void submit()} disabled={saving || !form.name}>
              {t('snmpCred.create')}
            </Button>
            <Button size="sm" variant="secondary" onClick={() => { setShowForm(false); setForm(EMPTY); }}>
              {t('common.cancel', { defaultValue: 'Cancel' })}
            </Button>
          </div>
        </div>
      )}

      {loading ? <LoadingSpinner /> : rows.length === 0 ? (
        <p className="py-6 text-center text-sm text-text-muted">{t('snmpCred.empty')}</p>
      ) : (
        <ul className="divide-y divide-border">
          {rows.map((c) => (
            <li key={c.id} className="flex items-center gap-3 py-2">
              <span className="font-mono text-xs text-text-muted">#{c.id}</span>
              <span className="text-sm text-text-primary">{c.name}</span>
              <span className="rounded-full border border-border px-2 py-0.5 text-[10px] text-text-secondary">
                {c.version}
              </span>
              {c.username && (
                <span className="font-mono text-[11px] text-text-muted">{c.username}</span>
              )}
              {/* Booleans, never values. There is nothing here to reveal. */}
              {c.hasCommunity && (
                <span className="text-[11px] text-text-muted">{t('snmpCred.hasCommunity')}</span>
              )}
              {c.hasAuthKey && (
                <span className="text-[11px] text-text-muted">{t('snmpCred.hasAuthKey')}</span>
              )}
              <button
                type="button"
                onClick={() => void remove(c)}
                className="ml-auto text-text-muted hover:text-status-down"
                title={t('snmpCred.delete')}
              >
                <Trash2 size={14} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
