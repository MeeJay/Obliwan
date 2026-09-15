import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Check, Info, Receipt, RefreshCw, ShoppingCart, X } from 'lucide-react';
import toast from 'react-hot-toast';
import { CAPABILITIES, type SimRecharge } from '@obliwan/shared';
import { simApi, errorMessageOf } from '@/api/sim.api';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import {
  DataAmount,
  EmptyState,
  Money,
  RechargeStatusBadge,
  When,
} from '@/components/mobile/SimBits';

/**
 * ObliWAN F9 — the top-up queue.
 *
 * ┌─ TWO ACTS, AND THE SCREEN MUST NOT BLUR THEM ─────────────────────────────┐
 * │ APPROVE authorises the spend. It does NOT buy anything: ObliWAN has no    │
 * │ partner endpoint to buy with (`SIM_RECHARGE_ADAPTERS` is empty on         │
 * │ purpose), so an approved top-up is one somebody must still purchase on    │
 * │ the partner's portal.                                                     │
 * │                                                                          │
 * │ RECORD is the second act: "I bought it, here is what it cost". That is    │
 * │ the row the re-invoicing report reads.                                    │
 * │                                                                          │
 * │ A single "approve" button that silently did both would produce a billing  │
 * │ report full of purchases nobody made. The banner at the top of this page  │
 * │ says so in words, because a colour and a label are not enough for a       │
 * │ screen that moves money.                                                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export function MobileRechargesPage() {
  const { t } = useTranslation();
  const hasCapability = useAuthStore((s) => s.hasCapability);
  const canDecide = hasCapability(CAPABILITIES.SIM_RECHARGE);

  const [rows, setRows] = useState<SimRecharge[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<'open' | 'all'>('open');
  const [recordFor, setRecordFor] = useState<SimRecharge | null>(null);
  // The SAME dialog, for the second act: filling in a cost that was left blank
  // when the top-up was recorded because the partner invoice had not arrived.
  // Without this the cost could be entered exactly once, and an unpriced month
  // blocked `assertExecutionAllowed` with no way to unblock it.
  const [priceFor, setPriceFor] = useState<SimRecharge | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(
        await simApi.recharges({
          status: tab === 'open' ? 'proposed,approved,failed' : undefined,
          limit: 500,
        }),
      );
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setLoading(false);
    }
  }, [tab]);

  useEffect(() => {
    void load();
  }, [load]);

  const decide = async (r: SimRecharge, action: 'approve' | 'reject') => {
    try {
      await (action === 'approve' ? simApi.approve(r.id) : simApi.reject(r.id));
      // Explicit keys rather than an interpolated one: `${action}d` produces
      // `rejectd`, which i18next resolves to the key name itself and ships as a
      // visible typo in eighteen languages.
      toast.success(
        t(action === 'approve' ? 'mobile.recharges.approved' : 'mobile.recharges.rejected'),
      );
      await load();
    } catch (err) {
      toast.error(errorMessageOf(err));
    }
  };

  return (
    <div className="p-6">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">
            {t('mobile.recharges.title')}
          </h1>
          <p className="mt-1 text-sm text-text-secondary">{t('mobile.recharges.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-md border border-border">
            {(['open', 'all'] as const).map((v) => (
              <button
                key={v}
                onClick={() => setTab(v)}
                className={
                  tab === v
                    ? 'bg-bg-tertiary px-3 py-1.5 text-[13px] text-text-primary first:rounded-l-md last:rounded-r-md'
                    : 'px-3 py-1.5 text-[13px] text-text-secondary hover:text-text-primary first:rounded-l-md last:rounded-r-md'
                }
              >
                {t(`mobile.recharges.tab.${v}`)}
              </button>
            ))}
          </div>
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RefreshCw size={14} className="mr-1.5" />
            {t('common.refresh')}
          </Button>
        </div>
      </div>

      {/* The sentence that keeps "approved" from being read as "bought". */}
      <div className="mb-4 flex items-start gap-2 rounded-lg border border-accent/30 bg-accent/5 p-3 text-xs text-text-secondary">
        <Info size={14} className="mt-0.5 shrink-0 text-accent" />
        <p>{t('mobile.recharges.manualBanner')}</p>
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-bg-secondary">
        {loading ? (
          <div className="flex h-48 items-center justify-center">
            <LoadingSpinner />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState message={t('mobile.recharges.empty')} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs text-text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.msisdn')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.site')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.zone')}</th>
                  <th className="px-4 py-2 text-right font-medium">
                    {t('mobile.recharges.atProposal')}
                  </th>
                  <th className="px-4 py-2 font-medium">{t('mobile.recharges.proposed')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.recharges.status')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.report.cost')}</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((r) => (
                  <tr key={r.id} className="hover:bg-bg-hover">
                    <td className="px-4 py-2">
                      {r.simId === null ? (
                        <span className="font-mono text-text-secondary">{r.msisdn}</span>
                      ) : (
                        <Link
                          to={`/mobile/lines/${r.simId}`}
                          className="font-mono text-text-primary hover:text-accent"
                        >
                          {r.msisdn}
                        </Link>
                      )}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">
                      {r.siteName ?? <span className="text-text-muted">—</span>}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">{r.zone}</td>
                    <td className="px-4 py-2 text-right">
                      <DataAmount mb={r.restMbAtProposal} />
                      <span className="block text-[11px] text-text-muted">
                        {t('mobile.recharges.triggerLabel', {
                          trigger: t(`mobile.trigger.${r.trigger}`),
                        })}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs">
                      <When iso={r.proposedAt} />
                      <span className="block text-text-muted">
                        {r.proposedByName ?? t('mobile.recharges.bySystem')}
                      </span>
                    </td>
                    <td className="px-4 py-2">
                      <RechargeStatusBadge status={r.status} />
                    </td>
                    <td className="px-4 py-2 text-right">
                      <Money cents={r.costCents} currency={r.currency} />
                    </td>
                    <td className="px-4 py-2">
                      {canDecide ? (
                        <div className="flex items-center justify-end gap-1">
                          {r.status === 'proposed' ? (
                            <>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => void decide(r, 'approve')}
                              >
                                <Check size={14} className="mr-1 text-status-up" />
                                {t('mobile.recharges.approve')}
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => void decide(r, 'reject')}
                              >
                                <X size={14} className="mr-1 text-text-muted" />
                                {t('mobile.recharges.reject')}
                              </Button>
                            </>
                          ) : null}
                          {r.status === 'approved' || r.status === 'failed' ? (
                            <Button variant="secondary" size="sm" onClick={() => setRecordFor(r)}>
                              <ShoppingCart size={14} className="mr-1" />
                              {t('mobile.recharges.record')}
                            </Button>
                          ) : null}
                          {(r.status === 'recorded' || r.status === 'executed') &&
                          r.costCents === null ? (
                            <Button variant="ghost" size="sm" onClick={() => setPriceFor(r)}>
                              <Receipt size={14} className="mr-1" />
                              {t('mobile.recharges.price')}
                            </Button>
                          ) : null}
                        </div>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {recordFor ? (
        <RecordDialog
          recharge={recordFor}
          mode="record"
          onClose={() => setRecordFor(null)}
          onDone={async () => {
            setRecordFor(null);
            await load();
          }}
        />
      ) : null}

      {priceFor ? (
        <RecordDialog
          recharge={priceFor}
          mode="price"
          onClose={() => setPriceFor(null)}
          onDone={async () => {
            setPriceFor(null);
            await load();
          }}
        />
      ) : null}
    </div>
  );
}

/**
 * "I bought it on the portal — here is what it cost."
 *
 * The cost is OPTIONAL, and the dialog says so: the partner's invoice usually
 * arrives after the top-up. Forcing a number here would get zeros typed in, and
 * a zero is indistinguishable from a free top-up on the report. Left blank, the
 * row is counted as unpriced and the report says how many there are.
 */
function RecordDialog({
  recharge,
  mode,
  onClose,
  onDone,
}: {
  recharge: SimRecharge;
  /** `record` marks the purchase; `price` fills in an invoice that arrived
   *  later. Same fields, same validation, different verb — and `price` moves
   *  no state, so a billable row stays exactly as billable as it was. */
  mode: 'record' | 'price';
  onClose: () => void;
  onDone: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const [cost, setCost] = useState('');
  const [currency, setCurrency] = useState('EUR');
  const [reference, setReference] = useState('');
  const [planMb, setPlanMb] = useState(recharge.planMb === null ? '' : String(recharge.planMb));
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    // ┌─ A COST THE PARSER CANNOT READ IS NOT "NO COST" ────────────────────┐
    // │ `Number('12,35 €')` is NaN, and `Math.round(NaN * 100)` is NaN,     │
    // │ which JSON-serialises to `null`. The first draft therefore recorded │
    // │ a top-up the operator HAD priced as unpriced, with a success toast  │
    // │ — money quietly dropped from the re-invoicing report by a stray     │
    // │ character. Refused here, with the field named.                       │
    // └────────────────────────────────────────────────────────────────────┘
    const typed = cost.trim();
    const parsedCost = typed === '' ? null : Number(typed.replace(',', '.'));
    if (parsedCost !== null && (!Number.isFinite(parsedCost) || parsedCost < 0)) {
      toast.error(t('mobile.recharges.costUnreadable'));
      return;
    }
    if (parsedCost !== null && currency.trim().length !== 3) {
      toast.error(t('mobile.recharges.currencyRequired'));
      return;
    }

    // THE SAME HOLE, ON THE OTHER FIELD. Number("5 Go") is NaN, which
    // serialises to null and WIPES the proposal frozen plan_mb — the volume the
    // sweep recorded — while reporting success. The cost field was fixed and
    // this one was left, which is how a fix round produces a defect that reads
    // as a deliberate choice.
    const typedVolume = planMb.trim();
    const parsedVolume = typedVolume === '' ? null : Number(typedVolume.replace(',', '.'));
    if (parsedVolume !== null && (!Number.isInteger(parsedVolume) || parsedVolume < 1)) {
      toast.error(t('mobile.recharges.volumeUnreadable'));
      return;
    }

    setSaving(true);
    try {
      const call = mode === 'record' ? simApi.record : simApi.price;
      await call(recharge.id, {
        // Cents, from a value typed in whole currency units. `Math.round` and
        // not a bare multiplication: 12.35 * 100 is 1234.9999999999998, and a
        // truncated cent on every line is a report that never reconciles.
        costCents: parsedCost === null ? null : Math.round(parsedCost * 100),
        // A cost with no currency is refused by the schema AND by the database
        // (migration 032, decision 8), so the two travel together or neither.
        currency: parsedCost === null ? null : currency.trim().toUpperCase(),
        billingReference: reference.trim() === '' ? null : reference.trim(),
        planMb: parsedVolume,
      });
      toast.success(t(mode === 'record' ? 'mobile.recharges.recorded' : 'mobile.recharges.priced'));
      await onDone();
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded-lg border border-border bg-bg-secondary shadow-xl">
        <header className="border-b border-border px-4 py-3">
          <h2 className="text-sm font-semibold text-text-primary">
            {t(mode === 'record' ? 'mobile.recharges.recordTitle' : 'mobile.recharges.priceTitle')}
          </h2>
          <p className="mt-0.5 font-mono text-xs text-text-muted">
            {recharge.msisdn} · {recharge.zone}
          </p>
        </header>
        <div className="space-y-3 p-4">
          <label className="block">
            <span className="mb-1 block text-xs text-text-secondary">
              {t('mobile.recharges.volume')}
            </span>
            <Input value={planMb} inputMode="numeric" onChange={(e) => setPlanMb(e.target.value)} />
          </label>
          <div className="grid grid-cols-3 gap-2">
            <label className="col-span-2 block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.recharges.cost')}
              </span>
              <Input
                value={cost}
                inputMode="decimal"
                placeholder={t('mobile.recharges.costOptional')}
                onChange={(e) => setCost(e.target.value)}
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.report.currency')}
              </span>
              <Input
                value={currency}
                maxLength={3}
                onChange={(e) => setCurrency(e.target.value)}
              />
            </label>
          </div>
          <label className="block">
            <span className="mb-1 block text-xs text-text-secondary">
              {t('mobile.recharges.reference')}
            </span>
            <Input value={reference} onChange={(e) => setReference(e.target.value)} />
          </label>
          <p className="text-[11px] text-text-muted">{t('mobile.recharges.costHint')}</p>
        </div>
        <footer className="flex justify-end gap-2 border-t border-border px-4 py-3">
          <Button variant="ghost" size="sm" onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <Button size="sm" loading={saving} onClick={() => void submit()}>
            {t(mode === 'record' ? 'mobile.recharges.record' : 'mobile.recharges.price')}
          </Button>
        </footer>
      </div>
    </div>
  );
}
