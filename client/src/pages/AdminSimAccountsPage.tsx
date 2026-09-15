import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  KeyRound,
  Pencil,
  Plus,
  RefreshCw,
  ShieldAlert,
  Trash2,
  Wifi,
} from 'lucide-react';
import toast from 'react-hot-toast';
import {
  SIM_AUTH_MODES,
  SIM_PLATFORMS,
  type SimAccount,
  type SimAuthMode,
  type SimPlatform,
  type SimPlatformInfo,
} from '@obliwan/shared';
import { simApi, errorMessageOf, type SimCapUsage, type SimSyncRun } from '@/api/sim.api';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { EmptyState, When } from '@/components/mobile/SimBits';
import { cn } from '@/utils/cn';

const selectClass =
  'w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

/**
 * ObliWAN F9 — partner accounts. PLATFORM ADMINISTRATION.
 *
 * ┌─ SEVERAL ACCOUNTS ON THE SAME PARTNER IS THE NORMAL CASE ─────────────────┐
 * │ CFAST is held through two separate accounts, and a partner reseller can   │
 * │ easily have more. The schema allows it: `sim_accounts` is unique on       │
 * │ `(platform, lower(name))`, so the only requirement is a distinct NAME per │
 * │ account on a platform — and every SIM line carries its `account_id`, so   │
 * │ two accounts' inventories never merge.                                    │
 * │                                                                          │
 * │ The uniqueness is on the name and not on the credential ON PURPOSE: two   │
 * │ rows silently pointing at the same partner login is two operators each    │
 * │ believing they configured "the" account, and two sweeps doubling the      │
 * │ partner's rate-limit spend.                                               │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT THIS SCREEN NEVER SHOWS ────────────────────────────────────────────┐
 * │ A stored credential. The API returns `hasCredential: boolean` and there   │
 * │ is no reveal endpoint — a partner API token has no use that would justify │
 * │ one. A credential can only be REPLACED, never read back.                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export function AdminSimAccountsPage() {
  const { t } = useTranslation();
  const [accounts, setAccounts] = useState<SimAccount[]>([]);
  const [platforms, setPlatforms] = useState<SimPlatformInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [credentialFor, setCredentialFor] = useState<SimAccount | null>(null);
  const [editing, setEditing] = useState<SimAccount | null>(null);
  const [runsFor, setRunsFor] = useState<{ account: SimAccount; runs: SimSyncRun[] } | null>(null);
  const [busy, setBusy] = useState<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [a, p] = await Promise.all([simApi.accounts(), simApi.platforms()]);
      setAccounts(a);
      setPlatforms(p);
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const test = async (a: SimAccount) => {
    setBusy(a.id);
    try {
      const result = await simApi.testAccount(a.id);
      if (result.ok) {
        // The count is the point, not the tick: a token can authenticate and
        // still see zero lines (wrong partner id, missing role), and "connected"
        // over an empty fleet is the most expensive kind of green.
        toast.success(t('mobile.accounts.testOk', { count: result.lineCount ?? 0 }));
      } else {
        toast.error(result.error ?? t('mobile.accounts.testFailed'));
      }
      await load();
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setBusy(null);
    }
  };

  const sync = async (a: SimAccount) => {
    setBusy(a.id);
    try {
      await simApi.syncAccount(a.id);
      toast.success(t('mobile.accounts.syncDone'));
      await load();
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setBusy(null);
    }
  };

  const remove = async (a: SimAccount) => {
    if (!window.confirm(t('mobile.accounts.confirmDelete', { name: a.name }))) return;
    try {
      await simApi.deleteAccount(a.id);
      toast.success(t('mobile.accounts.deleted'));
      await load();
    } catch (err) {
      toast.error(errorMessageOf(err));
    }
  };

  const openRuns = async (a: SimAccount) => {
    try {
      setRunsFor({ account: a, runs: await simApi.runs(a.id) });
    } catch (err) {
      toast.error(errorMessageOf(err));
    }
  };

  return (
    <div className="p-6">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">
            {t('mobile.accounts.title')}
          </h1>
          <p className="mt-1 text-sm text-text-secondary">{t('mobile.accounts.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={() => setCreating(true)}>
            <Plus size={14} className="mr-1.5" />
            {t('mobile.accounts.add')}
          </Button>
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RefreshCw size={14} className="mr-1.5" />
            {t('common.refresh')}
          </Button>
        </div>
      </div>

      {loading ? (
        <div className="flex h-48 items-center justify-center">
          <LoadingSpinner />
        </div>
      ) : accounts.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary">
          <EmptyState message={t('mobile.accounts.empty')} />
        </div>
      ) : (
        <div className="space-y-3">
          {accounts.map((a) => {
            const info = platforms.find((p) => p.platform === a.platform);
            const expiringSoon =
              a.tokenExpiresAt !== null &&
              new Date(a.tokenExpiresAt).getTime() - Date.now() < 7 * 86_400_000;
            return (
              <div
                key={a.id}
                className={cn(
                  'rounded-lg border bg-bg-secondary p-4',
                  a.status === 'auth_failed' ? 'border-status-down/50' : 'border-border',
                )}
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold text-text-primary">{a.name}</span>
                      <span className="rounded-full border border-border bg-bg-tertiary px-2 py-0.5 text-[11px] text-text-secondary">
                        {info?.label ?? a.platform}
                      </span>
                      <StatusChip status={a.status} />
                      {!a.hasCredential ? (
                        <span className="rounded-full border border-status-ssl-warning/30 bg-status-ssl-warning/10 px-2 py-0.5 text-[11px] text-status-ssl-warning">
                          {t('mobile.accounts.noCredential')}
                        </span>
                      ) : null}
                    </div>
                    <p className="mt-1 text-xs text-text-muted">
                      {/* `?? '—'` and NOT `?? 0`: an account that has never
                          been swept has an UNKNOWN line count, and "0 line(s)
                          on the last sweep" reads as an empty partner account
                          rather than as one nobody has polled yet. */}
                      {t('mobile.accounts.meta', {
                        mode: t(`mobile.authMode.${a.authMode}`),
                        partner: a.partnerRef ?? '—',
                        lines: a.lastSyncLineCount ?? '—',
                      })}
                    </p>
                    <p className="mt-0.5 text-xs text-text-muted">
                      {t('mobile.accounts.lastSync')} <When iso={a.lastSyncAt} />
                    </p>
                    {a.lastSyncError ? (
                      <p className="mt-1 max-w-2xl break-words text-xs text-status-down">
                        {a.lastSyncError}
                      </p>
                    ) : null}
                    {expiringSoon ? (
                      // The warning that exists because the alternative is a
                      // fleet that silently stops being watched.
                      <p className="mt-1 text-xs text-status-ssl-warning">
                        {t('mobile.accounts.tokenExpiring')} <When iso={a.tokenExpiresAt} />
                      </p>
                    ) : null}
                    {info && !info.readImplemented ? (
                      <p className="mt-2 flex items-start gap-1.5 text-xs text-text-secondary">
                        <ShieldAlert size={13} className="mt-0.5 shrink-0 text-text-muted" />
                        {info.note}
                      </p>
                    ) : null}
                  </div>

                  <CapEditor account={a} onSaved={() => void load()} />

                  <div className="flex shrink-0 flex-wrap items-center gap-1">
                    <Button variant="secondary" size="sm" onClick={() => setEditing(a)}>
                      <Pencil size={13} className="mr-1" />
                      {t('mobile.accounts.edit')}
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => setCredentialFor(a)}
                    >
                      <KeyRound size={13} className="mr-1" />
                      {t('mobile.accounts.credential')}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      loading={busy === a.id}
                      disabled={!a.hasCredential}
                      onClick={() => void test(a)}
                    >
                      <Wifi size={13} className="mr-1" />
                      {t('mobile.accounts.test')}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      loading={busy === a.id}
                      disabled={!a.hasCredential || !info?.readImplemented}
                      onClick={() => void sync(a)}
                    >
                      <RefreshCw size={13} className="mr-1" />
                      {t('mobile.accounts.sync')}
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => void openRuns(a)}>
                      {t('mobile.accounts.journal')}
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => void remove(a)}>
                      <Trash2 size={13} className="text-status-down" />
                    </Button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {creating ? (
        <CreateDialog
          platforms={platforms}
          onClose={() => setCreating(false)}
          onDone={async () => {
            setCreating(false);
            await load();
          }}
        />
      ) : null}

      {editing ? (
        <EditDialog
          account={editing}
          onClose={() => setEditing(null)}
          onDone={async () => {
            setEditing(null);
            await load();
          }}
        />
      ) : null}

      {credentialFor ? (
        <CredentialDialog
          account={credentialFor}
          onClose={() => setCredentialFor(null)}
          onDone={async () => {
            setCredentialFor(null);
            await load();
          }}
        />
      ) : null}

      {runsFor ? (
        <RunsDialog data={runsFor} onClose={() => setRunsFor(null)} />
      ) : null}
    </div>
  );
}

/**
 * Editing an account after it exists.
 *
 * ┌─ EVERYTHING HERE WAS WRITE-ONCE, AND THE ONLY ESCAPE WAS DESTRUCTIVE ────┐
 * │ The create form pre-fills a skip list with "SFR" and a base URL, and the │
 * │ partner id is usually learned from the first token rather than typed.    │
 * │ None of those could be corrected afterwards: the API served PATCH, no    │
 * │ screen called it, and the only way to change a typo in a name or to stop │
 * │ skipping an operator was to DELETE the account — which cascades every    │
 * │ SIM line, every balance and every assignment with it.                     │
 * │                                                                         │
 * │ `platform` stays absent on purpose: changing it would leave a credential │
 * │ minted for one partner pointed at another's connector, and every line    │
 * │ already collected attributed to the wrong one. The server omits it from  │
 * │ the patch schema for the same reason.                                     │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
function EditDialog({
  account,
  onClose,
  onDone,
}: {
  account: SimAccount;
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState(account.name);
  const [baseUrl, setBaseUrl] = useState(account.baseUrl ?? '');
  const [partnerRef, setPartnerRef] = useState(account.partnerRef ?? '');
  const [skipOperators, setSkipOperators] = useState(account.skipOperators.join(', '));
  const [authMode, setAuthMode] = useState<SimAuthMode>(account.authMode);
  const [saving, setSaving] = useState(false);

  const modeChanged = authMode !== account.authMode;

  const submit = async () => {
    setSaving(true);
    try {
      await simApi.updateAccount(account.id, {
        name: name.trim(),
        baseUrl: baseUrl.trim() === '' ? null : baseUrl.trim(),
        partnerRef: partnerRef.trim() === '' ? null : partnerRef.trim(),
        skipOperators: skipOperators
          .split(',')
          .map((x) => x.trim())
          .filter((x) => x !== ''),
        ...(modeChanged ? { authMode } : {}),
      });
      toast.success(t('mobile.accounts.saved'));
      await onDone();
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={t('mobile.accounts.editTitle', { name: account.name })} onClose={onClose}>
      <div className="space-y-3 p-4">
        <label className="block">
          <span className="mb-1 block text-xs text-text-secondary">
            {t('mobile.accounts.name')}
          </span>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="block">
          <span className="mb-1 block text-xs text-text-secondary">
            {t('mobile.accounts.partnerRef')}
          </span>
          <Input value={partnerRef} onChange={(e) => setPartnerRef(e.target.value)} />
        </label>
        <label className="block">
          <span className="mb-1 block text-xs text-text-secondary">
            {t('mobile.accounts.baseUrl')}
          </span>
          <Input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={t('mobile.accounts.baseUrlPlaceholder')}
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-xs text-text-secondary">
            {t('mobile.accounts.skipOperators')}
          </span>
          <Input value={skipOperators} onChange={(e) => setSkipOperators(e.target.value)} />
          <span className="mt-1 block text-[11px] text-text-muted">
            {t('mobile.accounts.skipOperatorsHint')}
          </span>
        </label>
        <label className="block">
          <span className="mb-1 block text-xs text-text-secondary">
            {t('mobile.accounts.authMode')}
          </span>
          <select
            className={selectClass}
            value={authMode}
            onChange={(e) => setAuthMode(e.target.value as SimAuthMode)}
          >
            {SIM_AUTH_MODES.map((m) => (
              <option key={m} value={m}>
                {t(`mobile.authMode.${m}`)}
              </option>
            ))}
          </select>
          {/* The server clears the stored credential and disables the account
              when the mode changes — a token replayed as a password is not a
              state worth keeping. Said here so the consequence is visible
              BEFORE the save, not discovered after it. */}
          {modeChanged ? (
            <span className="mt-1 block text-[11px] text-status-ssl-warning">
              {t('mobile.accounts.authModeChangeWarning')}
            </span>
          ) : null}
        </label>
        <p className="text-[11px] text-text-muted">{t('mobile.accounts.platformFixed')}</p>
      </div>
      <footer className="flex justify-end gap-2 border-t border-border px-4 py-3">
        <Button variant="ghost" size="sm" onClick={onClose}>
          {t('common.cancel')}
        </Button>
        <Button size="sm" loading={saving} disabled={name.trim() === ''} onClick={() => void submit()}>
          {t('common.save')}
        </Button>
      </footer>
    </Modal>
  );
}

/**
 * The two monthly ceilings, on the screen.
 *
 * ┌─ THEY EXISTED IN THE SCHEMA AND NOWHERE ELSE ────────────────────────────┐
 * │ Migration 032 decision 9 says the caps are on the account "from the      │
 * │ first migration, before anything can spend", because a ceiling added     │
 * │ after the automation is a ceiling that was absent on the day it was      │
 * │ first needed. They were settable through the API and visible on no       │
 * │ screen — so in practice nobody would ever have set one, and the day an   │
 * │ execution adapter landed `assertExecutionAllowed` would have refused     │
 * │ every purchase with a message about a field the operator had never seen. │
 * │                                                                         │
 * │ Blank means NOT CONFIGURED, which the server treats as REFUSE, not as    │
 * │ unlimited — the hint under the fields says exactly that.                 │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
function CapEditor({ account, onSaved }: { account: SimAccount; onSaved: () => void }) {
  const { t } = useTranslation();
  // The month's spend against the ceilings. Migration 032 decision 9 says the
  // proposal screen SHOWS usage against the caps rather than letting them gate
  // a proposal — this is that reading, and it is what gives
  // `GET /sim/accounts/:id/caps` a caller.
  const [usage, setUsage] = useState<SimCapUsage | null>(null);
  const [count, setCount] = useState(
    account.monthlyRechargeCap === null ? '' : String(account.monthlyRechargeCap),
  );
  const [cost, setCost] = useState(
    account.monthlyCostCapCents === null ? '' : (account.monthlyCostCapCents / 100).toFixed(2),
  );
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    simApi
      .caps(account.id)
      .then(setUsage)
      .catch(() => setUsage(null));
  }, [account.id]);

  const save = async () => {
    const parsedCost = cost.trim() === '' ? null : Number(cost.trim().replace(',', '.'));
    if (parsedCost !== null && (!Number.isFinite(parsedCost) || parsedCost < 0)) {
      toast.error(t('mobile.accounts.capCostUnreadable'));
      return;
    }
    setSaving(true);
    try {
      await simApi.updateAccount(account.id, {
        monthlyRechargeCap: count.trim() === '' ? null : Number(count.trim()),
        monthlyCostCapCents: parsedCost === null ? null : Math.round(parsedCost * 100),
      });
      toast.success(t('mobile.accounts.capsSaved'));
      onSaved();
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="mt-3 flex flex-wrap items-end gap-2 border-t border-border pt-3">
      <label className="block">
        <span className="mb-1 block text-[11px] text-text-secondary">
          {t('mobile.accounts.capCount')}
        </span>
        <Input
          value={count}
          inputMode="numeric"
          className="w-28"
          placeholder={t('mobile.accounts.capUnset')}
          onChange={(e) => setCount(e.target.value)}
        />
      </label>
      <label className="block">
        <span className="mb-1 block text-[11px] text-text-secondary">
          {t('mobile.accounts.capCost')}
        </span>
        <Input
          value={cost}
          inputMode="decimal"
          className="w-32"
          placeholder={t('mobile.accounts.capUnset')}
          onChange={(e) => setCost(e.target.value)}
        />
      </label>
      <Button variant="secondary" size="sm" loading={saving} onClick={() => void save()}>
        {t('common.save')}
      </Button>
      {usage ? (
        <p className="w-full text-[11px] text-text-secondary">
          {t('mobile.accounts.capUsage', {
            count: usage.rechargesThisMonth,
            cost: (usage.costThisMonthCents / 100).toFixed(2),
          })}
          {usage.unpricedThisMonth > 0 ? (
            // An unpriced month cannot be checked against a cost ceiling at all,
            // and `assertExecutionAllowed` refuses rather than treating the
            // unknown as zero. The screen says so where the ceiling is set.
            <span className="text-status-ssl-warning">
              {' '}
              {t('mobile.accounts.capUnpriced', { count: usage.unpricedThisMonth })}
            </span>
          ) : null}
        </p>
      ) : null}
      <p className="w-full text-[11px] text-text-muted">{t('mobile.accounts.capHint')}</p>
    </div>
  );
}

function StatusChip({ status }: { status: SimAccount['status'] }) {
  const { t } = useTranslation();
  const cls = {
    active: 'border-status-up/30 bg-status-up/15 text-status-up',
    disabled: 'border-border bg-text-muted/10 text-text-secondary',
    auth_failed: 'border-status-down/30 bg-status-down/15 text-status-down',
  }[status];
  return (
    <span className={cn('rounded-full border px-2 py-0.5 text-[11px]', cls)}>
      {t(`mobile.accountStatus.${status}`)}
    </span>
  );
}

function CreateDialog({
  platforms,
  onClose,
  onDone,
}: {
  platforms: SimPlatformInfo[];
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const [platform, setPlatform] = useState<SimPlatform>(SIM_PLATFORMS[0]);
  const [name, setName] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [partnerRef, setPartnerRef] = useState('');
  const [authMode, setAuthMode] = useState<SimAuthMode>('token');
  const [skipOperators, setSkipOperators] = useState('SFR');
  const [saving, setSaving] = useState(false);

  const info = platforms.find((p) => p.platform === platform);

  const submit = async () => {
    setSaving(true);
    try {
      await simApi.createAccount({
        platform,
        name: name.trim(),
        baseUrl: baseUrl.trim() === '' ? null : baseUrl.trim(),
        partnerRef: partnerRef.trim() === '' ? null : partnerRef.trim(),
        authMode,
        skipOperators: skipOperators
          .split(',')
          .map((s) => s.trim())
          .filter((s) => s !== ''),
      });
      toast.success(t('mobile.accounts.created'));
      await onDone();
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={t('mobile.accounts.add')} onClose={onClose}>
      <div className="space-y-3 p-4">
        <label className="block">
          <span className="mb-1 block text-xs text-text-secondary">
            {t('mobile.accounts.platform')}
          </span>
          <select
            className={selectClass}
            value={platform}
            onChange={(e) => setPlatform(e.target.value as SimPlatform)}
          >
            {platforms.map((p) => (
              <option key={p.platform} value={p.platform}>
                {p.label}
              </option>
            ))}
          </select>
          {info ? <span className="mt-1 block text-[11px] text-text-muted">{info.note}</span> : null}
        </label>

        <label className="block">
          <span className="mb-1 block text-xs text-text-secondary">
            {t('mobile.accounts.name')}
          </span>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t('mobile.accounts.namePlaceholder')}
          />
          {/* Several accounts per platform is normal — see the page header. */}
          <span className="mt-1 block text-[11px] text-text-muted">
            {t('mobile.accounts.nameHint')}
          </span>
        </label>

        <label className="block">
          <span className="mb-1 block text-xs text-text-secondary">
            {t('mobile.accounts.authMode')}
          </span>
          <select
            className={selectClass}
            value={authMode}
            onChange={(e) => setAuthMode(e.target.value as SimAuthMode)}
          >
            {SIM_AUTH_MODES.map((m) => (
              <option key={m} value={m}>
                {t(`mobile.authMode.${m}`)}
              </option>
            ))}
          </select>
          <span className="mt-1 block text-[11px] text-text-muted">
            {t(`mobile.accounts.authHint.${authMode}`)}
          </span>
        </label>

        <label className="block">
          <span className="mb-1 block text-xs text-text-secondary">
            {t('mobile.accounts.partnerRef')}
          </span>
          <Input value={partnerRef} onChange={(e) => setPartnerRef(e.target.value)} />
          <span className="mt-1 block text-[11px] text-text-muted">
            {t('mobile.accounts.partnerRefHint')}
          </span>
        </label>

        <label className="block">
          <span className="mb-1 block text-xs text-text-secondary">
            {t('mobile.accounts.baseUrl')}
          </span>
          <Input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={t('mobile.accounts.baseUrlPlaceholder')}
          />
        </label>

        <label className="block">
          <span className="mb-1 block text-xs text-text-secondary">
            {t('mobile.accounts.skipOperators')}
          </span>
          <Input value={skipOperators} onChange={(e) => setSkipOperators(e.target.value)} />
          <span className="mt-1 block text-[11px] text-text-muted">
            {t('mobile.accounts.skipOperatorsHint')}
          </span>
        </label>
      </div>
      <footer className="flex justify-end gap-2 border-t border-border px-4 py-3">
        <Button variant="ghost" size="sm" onClick={onClose}>
          {t('common.cancel')}
        </Button>
        <Button size="sm" loading={saving} disabled={name.trim() === ''} onClick={() => void submit()}>
          {t('common.create')}
        </Button>
      </footer>
    </Modal>
  );
}

/**
 * Supplies a credential. NEVER displays one.
 *
 * The one-time-code tab exists because an unattended sweep cannot answer an OTP
 * challenge: an operator completes it here once, and what is stored is the
 * resulting long-lived token.
 */
function CredentialDialog({
  account,
  onClose,
  onDone,
}: {
  account: SimAccount;
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const [mode, setMode] = useState<'credential' | 'otp'>('credential');
  const [token, setToken] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    setSaving(true);
    try {
      if (mode === 'otp') {
        await simApi.authenticateWithCode(account.id, { username, password, code });
      } else if (account.authMode === 'token') {
        await simApi.setCredential(account.id, { authMode: 'token', token: token.trim() });
      } else {
        await simApi.setCredential(account.id, { authMode: 'password', username, password });
      }
      toast.success(t('mobile.accounts.credentialSaved'));
      await onDone();
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={t('mobile.accounts.credentialTitle', { name: account.name })} onClose={onClose}>
      <div className="space-y-3 p-4">
        <div className="flex rounded-md border border-border">
          {(['credential', 'otp'] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={cn(
                'flex-1 px-3 py-1.5 text-[13px] first:rounded-l-md last:rounded-r-md',
                mode === m
                  ? 'bg-bg-tertiary text-text-primary'
                  : 'text-text-secondary hover:text-text-primary',
              )}
            >
              {t(`mobile.accounts.credTab.${m}`)}
            </button>
          ))}
        </div>

        {mode === 'otp' ? (
          <>
            <p className="text-[11px] text-text-muted">{t('mobile.accounts.otpHint')}</p>
            <Input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={t('mobile.accounts.username')}
            />
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t('mobile.accounts.password')}
            />
            <Input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder={t('mobile.accounts.code')}
            />
          </>
        ) : account.authMode === 'token' ? (
          <>
            <p className="text-[11px] text-text-muted">{t('mobile.accounts.tokenHint')}</p>
            <textarea
              className="h-28 w-full rounded-md border border-border bg-bg-tertiary p-2 font-mono text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="eyJhbGciOi..."
            />
          </>
        ) : (
          <>
            <p className="text-[11px] text-text-muted">{t('mobile.accounts.passwordHint')}</p>
            <Input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={t('mobile.accounts.username')}
            />
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t('mobile.accounts.password')}
            />
          </>
        )}

        <p className="text-[11px] text-text-muted">{t('mobile.accounts.neverShown')}</p>
      </div>
      <footer className="flex justify-end gap-2 border-t border-border px-4 py-3">
        <Button variant="ghost" size="sm" onClick={onClose}>
          {t('common.cancel')}
        </Button>
        <Button size="sm" loading={saving} onClick={() => void submit()}>
          {t('common.save')}
        </Button>
      </footer>
    </Modal>
  );
}

/** The sweep journal: why a balance is stale. */
function RunsDialog({
  data,
  onClose,
}: {
  data: { account: SimAccount; runs: SimSyncRun[] };
  onClose: () => void;
}) {
  const { t } = useTranslation();
  return (
    <Modal title={t('mobile.accounts.journalTitle', { name: data.account.name })} onClose={onClose}>
      <div className="max-h-96 overflow-y-auto">
        {data.runs.length === 0 ? (
          <EmptyState message={t('mobile.accounts.noRuns')} />
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 border-b border-border bg-bg-secondary text-left text-text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">{t('mobile.accounts.runStarted')}</th>
                <th className="px-3 py-2 font-medium">{t('mobile.accounts.runOutcome')}</th>
                <th className="px-3 py-2 text-right font-medium">{t('mobile.accounts.runLines')}</th>
                <th className="px-3 py-2 text-right font-medium">
                  {t('mobile.accounts.runFailed')}
                </th>
                <th className="px-3 py-2 text-right font-medium">
                  {t('mobile.accounts.runProposals')}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {data.runs.map((r) => (
                <tr key={r.id}>
                  <td className="px-3 py-1.5">
                    <When iso={r.startedAt} />
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        r.outcome === 'ok'
                          ? 'text-status-up'
                          : r.outcome === 'partial'
                            ? 'text-status-ssl-warning'
                            : 'text-status-down',
                      )}
                    >
                      {r.outcome ?? t('mobile.accounts.runRunning')}
                    </span>
                    {r.error ? (
                      <span className="mt-0.5 block max-w-md break-words text-text-muted">
                        {r.error}
                      </span>
                    ) : null}
                  </td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{r.linesSeen}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{r.linesFailed}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{r.proposalsCreated}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <footer className="flex justify-end border-t border-border px-4 py-3">
        <Button variant="secondary" size="sm" onClick={onClose}>
          {t('common.close')}
        </Button>
      </footer>
    </Modal>
  );
}

function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-lg rounded-lg border border-border bg-bg-secondary shadow-xl">
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 className="text-sm font-semibold text-text-primary">{title}</h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary">
            ×
          </button>
        </header>
        {children}
      </div>
    </div>
  );
}
