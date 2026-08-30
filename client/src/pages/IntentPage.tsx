import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import {
  BookmarkPlus,
  Cpu,
  Hammer,
  Plus,
  ShieldAlert,
  Trash2,
  Unplug,
  X,
} from 'lucide-react';
import type { DeviceBrand } from '@obliwan/shared';
import { CAPABILITIES, DEVICE_BRANDS } from '@obliwan/shared';
import { intentApi, type CapabilityMatrixRow, type SavedIntent } from '@/api/intent.api';
import { errorMessageOf } from '@/api/change.api';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { CompileResultCard } from '@/components/intent/CompileResultCard';
import { cn } from '@/utils/cn';
import type { IntentCompileResult, SiteIntent, WanMode } from '@/types/intent';
import { BRAND_LABELS, CAPABILITY_FLAG_LABEL_KEYS, WAN_MODES, emptyIntent } from '@/types/intent';

/**
 * `IntentPage` — the Intent Compiler screen (M11, killer K4).
 *
 * ┌─ WHAT THIS SCREEN IS FOR ────────────────────────────────────────────────┐
 * │ Compose a SITE INTENT once, see which of the four brands can carry it,   │
 * │ and — when one cannot — read the capability that is missing and the      │
 * │ brand it is missing on. That last sentence is the product: it is the     │
 * │ vendor knowledge leaving the senior's head, which is the whole business  │
 * │ case of K4 (§1.2).                                                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── THIS SCREEN TOUCHES NO EQUIPMENT ────────────────────────────────────────
 * §5/M11 puts `capabilityCheck` BEFORE any network access, and D3 says nothing
 * writes to a device outside `change_jobs`. So there is no apply button here
 * and there will not be one: the page ends at a compiled artefact and a link to
 * `/plan`, where the plan, the Management-Path Guard verdict and the blast
 * radius are visible together. Compiling is free and reversible; applying is
 * neither, and the two gestures do not belong on the same screen.
 *
 * ── §8.2 ────────────────────────────────────────────────────────────────────
 * The PPPoE form field is a vault credential PICKER, not a password box. The
 * intent document that travels to the compiler carries an id; the secret is
 * resolved at apply time, on the server, inside a change job. There is no code
 * path on this page along which a password could be typed, stored in an intent,
 * or rendered into an artefact preview.
 */

export function IntentPage() {
  const { t } = useTranslation();
  const { hasCapability, isAdmin } = useAuthStore();
  const canCompose = isAdmin() || hasCapability(CAPABILITIES.TEMPLATE_WRITE);

  const [intent, setIntent] = useState<SiteIntent>(() => emptyIntent());
  const [brands, setBrands] = useState<DeviceBrand[]>([...DEVICE_BRANDS]);
  const [result, setResult] = useState<IntentCompileResult | null>(null);
  const [compiling, setCompiling] = useState(false);
  const [unavailable, setUnavailable] = useState(false);

  const [matrix, setMatrix] = useState<CapabilityMatrixRow[] | null>(null);
  const [saved, setSaved] = useState<SavedIntent[] | null>(null);
  const [saveName, setSaveName] = useState('');

  useEffect(() => {
    void (async () => {
      try { setMatrix(await intentApi.capabilities()); } catch { setMatrix(null); }
      try { setSaved(await intentApi.listSaved()); } catch { setSaved(null); }
    })();
  }, []);

  const patch = useCallback(<K extends keyof SiteIntent>(key: K, value: SiteIntent[K]) => {
    setIntent((prev) => ({ ...prev, [key]: value }));
  }, []);

  const compile = useCallback(async () => {
    setCompiling(true);
    try {
      const res = await intentApi.compile(intent, brands);
      if (res === null) { setUnavailable(true); setResult(null); }
      else { setUnavailable(false); setResult(res); }
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('intent.compileFailed'));
      setResult(null);
    } finally {
      setCompiling(false);
    }
  }, [intent, brands, t]);

  const save = useCallback(async () => {
    if (!saveName.trim()) return;
    try {
      const row = await intentApi.save(saveName.trim(), intent);
      if (row === null) { toast.error(t('intent.saveEndpointAbsent')); return; }
      setSaveName('');
      setSaved(await intentApi.listSaved());
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('intent.saveFailed'));
    }
  }, [saveName, intent, t]);

  const ready = intent.name.trim().length > 0 && intent.lanCidr.trim().length > 0;

  if (!canCompose) {
    return (
      <div className="p-6">
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <ShieldAlert size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('intent.forbidden')}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="mb-5">
        <h1 className="font-display text-2xl font-semibold text-text-primary">{t('nav.intent')}</h1>
        <p className="mt-1 text-sm text-text-muted">{t('intent.subtitle')}</p>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
        {/* ── the intent ── */}
        <div className="min-w-0 space-y-3">
          <IntentForm intent={intent} onPatch={patch} />

          <section className="rounded-lg border border-border bg-bg-secondary p-3">
            <h2 className="mb-2 text-sm font-semibold text-text-primary">{t('intent.targets')}</h2>
            <div className="flex flex-wrap gap-2">
              {DEVICE_BRANDS.map((brand) => {
                const on = brands.includes(brand);
                return (
                  <button
                    key={brand}
                    onClick={() => setBrands((prev) =>
                      prev.includes(brand) ? prev.filter((b) => b !== brand) : [...prev, brand])}
                    className={cn(
                      'rounded-md border px-2.5 py-1 text-[12px] transition-colors',
                      on
                        ? 'border-accent/50 bg-accent/10 text-accent'
                        : 'border-border bg-bg-tertiary text-text-muted hover:text-text-primary',
                    )}
                  >
                    {BRAND_LABELS[brand]}
                  </button>
                );
              })}
            </div>
            <p className="mt-2 text-[11px] text-text-muted">{t('intent.targetsHint')}</p>

            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button
                variant="primary"
                size="sm"
                loading={compiling}
                disabled={!ready || brands.length === 0}
                onClick={() => void compile()}
              >
                <Hammer size={14} className="mr-1.5" />
                {t('intent.compile')}
              </Button>
              <span className="text-[11px] text-text-muted">{t('intent.compileHint')}</span>
            </div>
          </section>

          <section className="rounded-lg border border-border bg-bg-secondary p-3">
            <h2 className="mb-2 text-sm font-semibold text-text-primary">{t('intent.savedTitle')}</h2>
            <div className="flex gap-2">
              <input
                type="text"
                value={saveName}
                onChange={(e) => setSaveName(e.target.value)}
                placeholder={t('intent.savePlaceholder')}
                className="min-w-0 flex-1 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
              />
              <Button variant="secondary" size="sm" disabled={!saveName.trim()} onClick={() => void save()}>
                <BookmarkPlus size={14} className="mr-1.5" />
                {t('common.save')}
              </Button>
            </div>
            {saved === null ? (
              <p className="mt-2 text-[12px] text-text-muted">{t('intent.savedUnavailable')}</p>
            ) : saved.length === 0 ? (
              <p className="mt-2 text-[12px] text-text-muted">{t('intent.savedEmpty')}</p>
            ) : (
              <ul className="mt-2 divide-y divide-border">
                {saved.map((row) => (
                  <li key={row.id} className="flex items-center gap-2 py-1.5">
                    <button
                      onClick={() => setIntent({ ...emptyIntent(), ...row.intent })}
                      className="min-w-0 flex-1 truncate text-left text-[13px] text-text-primary hover:text-accent"
                    >
                      {row.name}
                    </button>
                    <button
                      onClick={async () => {
                        if (!(await intentApi.remove(row.id))) {
                          toast.error(t('intent.saveEndpointAbsent'));
                          return;
                        }
                        setSaved(await intentApi.listSaved());
                      }}
                      className="shrink-0 rounded p-1 text-text-muted hover:bg-bg-hover hover:text-status-ssl-expired"
                    >
                      <Trash2 size={12} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        {/* ── the answer ── */}
        <div className="min-w-0 space-y-3">
          {unavailable ? (
            <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
              <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
              <p className="text-sm text-text-muted">{t('intent.endpointUnavailable')}</p>
              <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
                {t('intent.endpointUnavailableHint')}
              </p>
            </div>
          ) : compiling && !result ? (
            <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
          ) : result ? (
            <>
              <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-bg-secondary px-3 py-2">
                <span className="font-display text-lg font-semibold text-text-primary">
                  {t('intent.compilesOn', {
                    ok: result.results.filter((r) => r.status === 'ok').length,
                    total: result.results.length,
                  })}
                </span>
                {result.compilerVersion && (
                  <span className="font-mono text-[11px] text-text-muted">
                    {t('intent.compilerVersion', { version: result.compilerVersion })}
                  </span>
                )}
              </div>
              {result.results.map((r) => <CompileResultCard key={r.brand} result={r} />)}
              <p className="rounded-md border border-border bg-bg-tertiary px-3 py-2 text-[12px] text-text-muted">
                {t('intent.applyElsewhere')}{' '}
                <Link to="/plan" className="text-accent hover:underline">{t('nav.changes')}</Link>
              </p>
            </>
          ) : (
            <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
              <Cpu size={28} className="mx-auto mb-2 text-text-muted" />
              <p className="text-sm text-text-muted">{t('intent.noResultYet')}</p>
              <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">{t('intent.noResultHint')}</p>
            </div>
          )}

          <CapabilityMatrix rows={matrix} />
        </div>
      </div>
    </div>
  );
}

// ── The form ────────────────────────────────────────────────────────────────

function IntentForm({
  intent,
  onPatch,
}: {
  intent: SiteIntent;
  onPatch: <K extends keyof SiteIntent>(key: K, value: SiteIntent[K]) => void;
}) {
  const { t } = useTranslation();

  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-3">
      <h2 className="mb-2 text-sm font-semibold text-text-primary">{t('intent.formTitle')}</h2>

      <div className="grid gap-2 sm:grid-cols-2">
        <Text
          label={t('intent.field.name')}
          value={intent.name}
          onChange={(v) => onPatch('name', v)}
        />
        <Text
          label={t('intent.field.lanCidr')}
          value={intent.lanCidr}
          placeholder="10.42.0.0/24"
          mono
          onChange={(v) => onPatch('lanCidr', v)}
        />
      </div>

      {/* ── WAN ── */}
      <h3 className="mt-3 text-[11px] uppercase tracking-wider text-text-muted">{t('intent.section.wan')}</h3>
      <div className="mt-1 grid gap-2 sm:grid-cols-2">
        <label className="block">
          <span className="block text-[12px] text-text-secondary">{t('intent.field.wanMode')}</span>
          <select
            value={intent.wan.mode}
            onChange={(e) => onPatch('wan', { ...intent.wan, mode: e.target.value as WanMode })}
            className="mt-1 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
          >
            {WAN_MODES.map((m) => (
              <option key={m} value={m}>{t(`intent.wanMode.${m}`)}</option>
            ))}
          </select>
        </label>
        {intent.wan.mode === 'static' && (
          <>
            <Text
              label={t('intent.field.wanAddress')}
              value={intent.wan.address}
              mono
              onChange={(v) => onPatch('wan', { ...intent.wan, address: v })}
            />
            <Text
              label={t('intent.field.wanGateway')}
              value={intent.wan.gateway}
              mono
              onChange={(v) => onPatch('wan', { ...intent.wan, gateway: v })}
            />
          </>
        )}
        {intent.wan.mode === 'pppoe' && (
          <div>
            <span className="block text-[12px] text-text-secondary">{t('intent.field.wanCredential')}</span>
            <input
              type="number"
              value={intent.wan.credentialId ?? ''}
              onChange={(e) => onPatch('wan', {
                ...intent.wan,
                credentialId: e.target.value === '' ? null : Number(e.target.value),
              })}
              placeholder={t('intent.field.credentialIdPlaceholder')}
              className="mt-1 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 font-mono text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            />
            {/* §8.2, said out loud where the temptation is. */}
            <p className="mt-1 text-[11px] text-text-muted">{t('intent.field.credentialHint')}</p>
          </div>
        )}
      </div>
      <Toggle
        label={t('intent.field.wanFailover')}
        checked={intent.wan.failover}
        onChange={(v) => onPatch('wan', { ...intent.wan, failover: v })}
      />

      {/* ── VLANs ── */}
      <h3 className="mt-3 text-[11px] uppercase tracking-wider text-text-muted">{t('intent.section.vlans')}</h3>
      <ul className="mt-1 space-y-1">
        {intent.vlans.map((vlan, i) => (
          <li key={i} className="flex flex-wrap items-center gap-1.5">
            <input
              type="number"
              value={vlan.id}
              onChange={(e) => {
                const next = [...intent.vlans];
                next[i] = { ...vlan, id: Number(e.target.value) };
                onPatch('vlans', next);
              }}
              className="w-20 rounded-md border border-border bg-bg-tertiary px-2 py-1 font-mono text-[12px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            />
            <input
              type="text"
              value={vlan.name}
              placeholder={t('intent.field.vlanName')}
              onChange={(e) => {
                const next = [...intent.vlans];
                next[i] = { ...vlan, name: e.target.value };
                onPatch('vlans', next);
              }}
              className="min-w-0 flex-1 rounded-md border border-border bg-bg-tertiary px-2 py-1 text-[12px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            />
            <input
              type="text"
              value={vlan.cidr}
              placeholder="10.42.10.0/24"
              onChange={(e) => {
                const next = [...intent.vlans];
                next[i] = { ...vlan, cidr: e.target.value };
                onPatch('vlans', next);
              }}
              className="w-40 rounded-md border border-border bg-bg-tertiary px-2 py-1 font-mono text-[12px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            />
            <button
              onClick={() => onPatch('vlans', intent.vlans.filter((_, j) => j !== i))}
              className="rounded p-1 text-text-muted hover:bg-bg-hover hover:text-status-ssl-expired"
            >
              <X size={12} />
            </button>
          </li>
        ))}
      </ul>
      <button
        onClick={() => onPatch('vlans', [...intent.vlans, { id: 10, name: '', cidr: '', internet: true }])}
        className="mt-1 inline-flex items-center gap-1 rounded-md border border-border bg-bg-tertiary px-2 py-1 text-[12px] text-text-secondary hover:text-text-primary"
      >
        <Plus size={12} />
        {t('intent.addVlan')}
      </button>

      {/* ── Firewall + VPN ── */}
      <h3 className="mt-3 text-[11px] uppercase tracking-wider text-text-muted">{t('intent.section.security')}</h3>
      <div className="mt-1 space-y-1">
        <Toggle
          label={t('intent.field.dropWanInput')}
          checked={intent.firewall.defaultWanInput === 'drop'}
          onChange={(v) => onPatch('firewall', {
            ...intent.firewall,
            defaultWanInput: v ? 'drop' : 'accept',
          })}
        />
        <Toggle
          label={t('intent.field.mgmtTunnelOnly')}
          checked={intent.firewall.mgmtFromTunnelOnly}
          onChange={(v) => onPatch('firewall', { ...intent.firewall, mgmtFromTunnelOnly: v })}
        />
        <Toggle
          label={t('intent.field.l2tp')}
          checked={intent.vpn.l2tpToConcentrator}
          onChange={(v) => onPatch('vpn', { ...intent.vpn, l2tpToConcentrator: v })}
        />
        <Toggle
          label={t('intent.field.ipsec')}
          checked={intent.vpn.ipsec}
          onChange={(v) => onPatch('vpn', { ...intent.vpn, ipsec: v })}
        />
        <Toggle
          label={t('intent.field.siteToSite')}
          checked={intent.vpn.siteToSite}
          onChange={(v) => onPatch('vpn', { ...intent.vpn, siteToSite: v })}
        />
        <Toggle
          label={t('intent.field.dhcp')}
          checked={intent.dhcp.enabled}
          onChange={(v) => onPatch('dhcp', { ...intent.dhcp, enabled: v })}
        />
      </div>
    </section>
  );
}

function Text({
  label,
  value,
  onChange,
  placeholder,
  mono,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mono?: boolean;
}) {
  return (
    <label className="block">
      <span className="block text-[12px] text-text-secondary">{label}</span>
      <input
        type="text"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className={cn(
          'mt-1 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent',
          mono && 'font-mono',
        )}
      />
    </label>
  );
}

function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="mt-1.5 flex items-center gap-2 text-[12px] text-text-secondary">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="accent-accent"
      />
      {label}
    </label>
  );
}

// ── The capability matrix ───────────────────────────────────────────────────

/**
 * What each family declares it can do, BEFORE any intent is written.
 *
 * This exists so the refusal message is not the first time a technician learns
 * that DrayTek cannot schedule a task at its own next boot. The flags shown are
 * the ones an intent actually depends on; the full `DeviceCapabilities` matrix
 * is a driver-author document, not an operator one.
 */
const MATRIX_FLAGS = [
  'canPushConfig',
  'canScheduleOnDevice',
  'requiresExplicitCommit',
  'requiresRebootToApply',
  'supportsStructuredDiff',
  'canUpgradeFirmware',
] as const;

function CapabilityMatrix({ rows }: { rows: CapabilityMatrixRow[] | null }) {
  const { t } = useTranslation();

  return (
    <section className="rounded-lg border border-border bg-bg-secondary">
      <h2 className="border-b border-border px-3 py-2 text-sm font-semibold text-text-primary">
        {t('intent.matrixTitle')}
      </h2>
      {rows === null ? (
        <p className="px-3 py-4 text-[12px] text-text-muted">{t('intent.matrixUnavailable')}</p>
      ) : rows.length === 0 ? (
        <p className="px-3 py-4 text-[12px] text-text-muted">{t('intent.matrixEmpty')}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[40rem] text-left text-[12px]">
            <thead className="border-b border-border text-[10px] uppercase tracking-wider text-text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">{t('intent.matrixFamily')}</th>
                {MATRIX_FLAGS.map((flag) => (
                  <th key={flag} className="px-2 py-2 font-medium" title={flag}>
                    {t(CAPABILITY_FLAG_LABEL_KEYS[flag])}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map((row) => (
                <tr key={row.family} className="hover:bg-bg-hover">
                  <td className="px-3 py-2">
                    <span className="text-text-primary">{BRAND_LABELS[row.brand]}</span>
                    <span className="block font-mono text-[10px] text-text-muted">{row.family}</span>
                  </td>
                  {MATRIX_FLAGS.map((flag) => (
                    <td key={flag} className="px-2 py-2 text-center">
                      <span className={row.flags[flag] ? 'text-status-up' : 'text-text-muted'}>
                        {row.flags[flag] ? '✓' : '—'}
                      </span>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="border-t border-border px-3 py-2 text-[11px] text-text-muted">
        {t('intent.matrixHint')}
      </p>
    </section>
  );
}
