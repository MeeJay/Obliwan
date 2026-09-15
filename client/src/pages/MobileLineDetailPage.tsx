import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ArrowLeft, Info, RefreshCw, Save, Wallet } from 'lucide-react';
import toast from 'react-hot-toast';
import {
  CAPABILITIES,
  MB_PER_GB,
  formatData,
  isMasterTenant,
  type SimRecharge,
} from '@obliwan/shared';
import { simApi, errorMessageOf, type SimLineListItem } from '@/api/sim.api';
import { sitesApi } from '@/api/sites.api';
import { useDeviceStore } from '@/store/deviceStore';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import {
  DataAmount,
  EmptyState,
  Panel,
  RechargeStatusBadge,
  VerdictBadge,
  When,
} from '@/components/mobile/SimBits';
import type { Site } from '@/types/fleet';

const selectClass =
  'w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

/**
 * ObliWAN F9 — one SIM line.
 *
 * ┌─ THE THRESHOLD FIELD IS IN MEGABYTES, AND THE SCREEN SAYS SO ─────────────┐
 * │ The same reason `ThresholdsPage` prints its unit next to every box: an    │
 * │ operator who types "1" meaning one gigabyte into a field that means       │
 * │ megabytes has just armed an alert at 1 Mo, which fires the day the line   │
 * │ is already dead. The field shows the equivalent in Go live, underneath.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE AUTO TOGGLE DOES NOT BUY ANYTHING ───────────────────────────────────┐
 * │ It decides whether this line may PRODUCE a proposal. The proposal is then │
 * │ approved by somebody holding SIM_RECHARGE, and the top-up itself is       │
 * │ bought on the partner's portal — ObliWAN has no endpoint to buy with. The │
 * │ note under the toggle says exactly that, because a switch labelled        │
 * │ "automatic top-up" that quietly means "automatic proposal" is a switch    │
 * │ somebody will believe.                                                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export function MobileLineDetailPage() {
  const { t } = useTranslation();
  const { id } = useParams<{ id: string }>();
  const lineId = Number(id);
  const hasCapability = useAuthStore((s) => s.hasCapability);
  const canManage = hasCapability(CAPABILITIES.SIM_MANAGE);

  const devices = useDeviceStore((s) => s.devices);
  const fetchDevices = useDeviceStore((s) => s.fetchDevices);

  // ┌─ THE WORKSPACE PICKER IS WHAT MAKES F9 DO ANYTHING AT ALL ─────────────┐
  // │ A line arrives from the partner in the POOL (`tenant_id IS NULL`), and │
  // │ a pooled line raises no alert, produces no proposal and appears on no  │
  // │ re-invoicing report — every one of those paths requires a tenant. The  │
  // │ first draft of this page offered a site and a router picker and NO     │
  // │ workspace picker, and `updateLine` refuses a tenant change from a      │
  // │ non-master caller, so on a fresh install nothing could ever leave the  │
  // │ pool: the detection, approval and billing halves of the feature were   │
  // │ unreachable through the product.                                       │
  // │                                                                        │
  // │ Shown only in the master workspace, because that is the only scope the │
  // │ server accepts a re-assignment from — a picker that always 403s is     │
  // │ worse than none.                                                       │
  // └────────────────────────────────────────────────────────────────────────┘
  const tenants = useTenantStore((s) => s.tenants);
  const fetchTenants = useTenantStore((s) => s.fetchTenants);
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const isPlatformAdmin = useAuthStore((s) => s.isAdmin)();
  const canAssignWorkspace = isPlatformAdmin && isMasterTenant(currentTenantId);

  const [line, setLine] = useState<SimLineListItem | null>(null);
  const [sites, setSites] = useState<Site[]>([]);
  const [history, setHistory] = useState<
    Array<{ zone: string; restMb: number | null; usedMb: number | null; observedAt: string }>
  >([]);
  const [recharges, setRecharges] = useState<SimRecharge[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Draft state for the editable fields.
  const [siteId, setSiteId] = useState<string>('');
  const [deviceId, setDeviceId] = useState<string>('');
  const [label, setLabel] = useState('');
  const [iccid, setIccid] = useState('');
  const [tenantId, setTenantId] = useState<string>('');
  const [thresholdMb, setThresholdMb] = useState('');
  const [planMb, setPlanMb] = useState('');
  const [auto, setAuto] = useState(false);

  const load = useCallback(async () => {
    if (!Number.isInteger(lineId) || lineId <= 0) return;
    setLoading(true);
    try {
      const [l, h, r] = await Promise.all([
        simApi.line(lineId),
        simApi.lineHistory(lineId, 90),
        simApi.recharges({ simId: lineId, limit: 50 }),
      ]);
      setLine(l);
      setHistory(h);
      setRecharges(r);
      setTenantId(l.tenantId === null ? '' : String(l.tenantId));
      setSiteId(l.siteId === null ? '' : String(l.siteId));
      setDeviceId(l.deviceId === null ? '' : String(l.deviceId));
      setLabel(l.label ?? '');
      setIccid(l.iccid ?? '');
      setThresholdMb(l.lowThresholdMb === null ? '' : String(l.lowThresholdMb));
      setPlanMb(l.rechargePlanMb === null ? '' : String(l.rechargePlanMb));
      setAuto(l.autoRechargeEnabled);
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setLoading(false);
    }
  }, [lineId]);

  useEffect(() => {
    void load();
    void fetchDevices();
    if (canAssignWorkspace) void fetchTenants();
    sitesApi
      .list()
      .then(setSites)
      .catch(() => setSites([]));
  }, [load, fetchDevices, fetchTenants, canAssignWorkspace]);

  const save = async () => {
    if (!line) return;
    setSaving(true);
    try {
      const nextTenant = tenantId === '' ? null : Number(tenantId);

      // A move cannot carry the old workspace's site and router. The pickers
      // are populated from the SESSION's workspace, so on a move their ids
      // belong to the wrong tenant: sending them made the server refuse with
      // "that site does not exist in this workspace" and discard the entire
      // save. The workspace picker, added so that assignment was possible at
      // all, could therefore never move a line that was already assigned.
      // A move sends null for both; the site and router are then set from the
      // destination workspace, where the pickers list the right inventory.
      const updated = await simApi.updateLine(line.id, {
        // Only sent when this session may actually change it, and only when it
        // differs — so an ordinary edit by a tenant admin never carries a
        // `tenantId` the server would refuse.
        ...(movingWorkspace ? { tenantId: nextTenant } : {}),
        siteId:
          movingWorkspace || nextTenant === null ? null : siteId === '' ? null : Number(siteId),
        deviceId:
          movingWorkspace || nextTenant === null
            ? null
            : deviceId === ''
              ? null
              : Number(deviceId),
        label: label.trim() === '' ? null : label.trim(),
        iccid: iccid.trim() === '' ? null : iccid.trim(),
        // An empty box means "use the global default", which is `null` — not 0.
        // Sending 0 would arm an alert at zero remaining, i.e. never.
        lowThresholdMb: thresholdMb.trim() === '' ? null : Number(thresholdMb),
        rechargePlanMb: planMb.trim() === '' ? null : Number(planMb),
        autoRechargeEnabled: auto,
      });
      setLine(updated);
      toast.success(t('mobile.detail.saved'));
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setSaving(false);
    }
  };

  const propose = async (zone: string) => {
    if (!line) return;
    try {
      await simApi.propose({
        simId: line.id,
        zone,
        planMb: planMb.trim() === '' ? null : Number(planMb),
      });
      toast.success(t('mobile.detail.proposed'));
      setRecharges(await simApi.recharges({ simId: line.id, limit: 50 }));
    } catch (err) {
      toast.error(errorMessageOf(err));
    }
  };

  if (loading && !line) {
    return (
      <div className="flex h-64 items-center justify-center">
        <LoadingSpinner />
      </div>
    );
  }
  if (!line) {
    return <div className="p-6 text-sm text-text-secondary">{t('mobile.detail.notFound')}</div>;
  }

  // True while the form proposes a DIFFERENT workspace from the stored one. The
  // site and router pickers list the session's own inventory, so they cannot
  // describe the destination — they stay disabled until the move is saved.
  const movingWorkspace =
    canAssignWorkspace && (tenantId === '' ? null : Number(tenantId)) !== line.tenantId;

  const gbHint =
    thresholdMb.trim() === '' || Number.isNaN(Number(thresholdMb))
      ? null
      : (Number(thresholdMb) / MB_PER_GB).toFixed(2);

  return (
    <div className="p-6">
      <Link
        to="/mobile/lines"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary"
      >
        <ArrowLeft size={14} />
        {t('mobile.detail.back')}
      </Link>

      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-mono text-2xl font-semibold text-text-primary">{line.msisdn}</h1>
          <p className="mt-1 text-sm text-text-secondary">
            {line.accountName} · {line.operator ?? t('mobile.noOperator')} ·{' '}
            {line.tenantId === null ? t('mobile.lines.pool') : (line.siteName ?? t('mobile.noSite'))}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <VerdictBadge verdict={line.verdict} stale={line.stale} />
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RefreshCw size={14} className="mr-1.5" />
            {t('common.refresh')}
          </Button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* ── Zones ───────────────────────────────────────────────────────── */}
        <Panel className="lg:col-span-2" title={t('mobile.detail.zones')}>
          {line.zones.length === 0 ? (
            <EmptyState message={t('mobile.detail.noZones')} />
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs text-text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.zone')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.detail.plan')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.detail.used')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.lines.remaining')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.detail.lowSince')}</th>
                  {/* A zone the partner stopped returning keeps its last row
                      forever: `applyBalances` only upserts the zones present in
                      the response. Without this column a four-hour-old reading
                      and a four-month-old one look identical, and a zone that
                      silently vanished from the feed reads as healthy. */}
                  <th className="px-4 py-2 font-medium">{t('mobile.detail.observedAt')}</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {line.zones.map((z) => (
                  <tr key={z.zone}>
                    <td className="px-4 py-2 text-text-primary">{z.zone}</td>
                    <td className="px-4 py-2 text-right">
                      <DataAmount mb={z.rechargeMb} />
                    </td>
                    <td className="px-4 py-2 text-right">
                      <DataAmount mb={z.usedMb} />
                    </td>
                    <td className="px-4 py-2 text-right">
                      <DataAmount mb={z.restMb} />
                    </td>
                    <td className="px-4 py-2 text-xs">
                      <When iso={z.lowSince} />
                    </td>
                    <td className="px-4 py-2 text-xs">
                      <When iso={z.observedAt} />
                    </td>
                    <td className="px-4 py-2 text-right">
                      {canManage ? (
                        <Button variant="ghost" size="sm" onClick={() => void propose(z.zone)}>
                          <Wallet size={13} className="mr-1" />
                          {t('mobile.detail.propose')}
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="border-t border-border px-4 py-2 text-[11px] text-text-muted">
            {t('mobile.detail.thresholdApplied', { value: formatData(line.thresholdMb) })}
          </p>
        </Panel>

        {/* ── Assignment and policy ───────────────────────────────────────── */}
        <Panel title={t('mobile.detail.policy')}>
          <div className="space-y-3 p-4">
            {canAssignWorkspace ? (
              <label className="block">
                <span className="mb-1 block text-xs text-text-secondary">
                  {t('mobile.detail.workspace')}
                </span>
                <select
                  className={selectClass}
                  value={tenantId}
                  disabled={!canManage}
                  onChange={(e) => setTenantId(e.target.value)}
                >
                  <option value="">{t('mobile.detail.unassignedPool')}</option>
                  {tenants.map((tn) => (
                    <option key={tn.id} value={tn.id}>
                      {tn.name}
                    </option>
                  ))}
                </select>
                <span className="mt-1 block text-[11px] text-text-muted">
                  {t('mobile.detail.workspaceHint')}
                </span>
              </label>
            ) : null}

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.lines.site')}
              </span>
              <select
                className={selectClass}
                value={siteId}
                disabled={!canManage || tenantId === '' || movingWorkspace}
                onChange={(e) => setSiteId(e.target.value)}
              >
                <option value="">{t('mobile.detail.none')}</option>
                {sites.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.detail.router')}
              </span>
              <select
                className={selectClass}
                value={deviceId}
                disabled={!canManage || tenantId === '' || movingWorkspace}
                onChange={(e) => setDeviceId(e.target.value)}
              >
                <option value="">{t('mobile.detail.none')}</option>
                {devices.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name}
                  </option>
                ))}
              </select>
              <span className="mt-1 block text-[11px] text-text-muted">
                {t('mobile.detail.routerHint')}
              </span>
            </label>

            {tenantId === '' ? (
              <p className="rounded-md border border-accent/30 bg-accent/5 px-3 py-2 text-[11px] text-text-secondary">
                {canAssignWorkspace
                  ? t('mobile.detail.poolHintAdmin')
                  : t('mobile.detail.poolHint')}
              </p>
            ) : movingWorkspace ? (
              <p className="rounded-md border border-status-ssl-warning/30 bg-status-ssl-warning/5 px-3 py-2 text-[11px] text-text-secondary">
                {t('mobile.detail.movingHint')}
              </p>
            ) : null}

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.detail.label')}
              </span>
              <Input value={label} disabled={!canManage} onChange={(e) => setLabel(e.target.value)} />
            </label>

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.detail.iccid')}
              </span>
              <Input
                value={iccid}
                disabled={!canManage}
                placeholder={t('mobile.detail.iccidPlaceholder')}
                onChange={(e) => setIccid(e.target.value)}
              />
              <span className="mt-1 block text-[11px] text-text-muted">
                {t('mobile.detail.iccidHint')}
              </span>
            </label>

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.detail.threshold')}
              </span>
              <Input
                value={thresholdMb}
                disabled={!canManage}
                inputMode="numeric"
                placeholder={t('mobile.detail.thresholdPlaceholder', {
                  value: formatData(line.thresholdMb),
                })}
                onChange={(e) => setThresholdMb(e.target.value)}
              />
              {/* The unit, next to the box — see the header. */}
              <span className="mt-1 block text-[11px] text-text-muted">
                {gbHint === null
                  ? t('mobile.detail.thresholdUnit')
                  : t('mobile.detail.thresholdEquals', { gb: gbHint })}
              </span>
            </label>

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.detail.planMb')}
              </span>
              <Input
                value={planMb}
                disabled={!canManage}
                inputMode="numeric"
                onChange={(e) => setPlanMb(e.target.value)}
              />
            </label>

            <label className="flex items-start gap-2">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={auto}
                disabled={!canManage}
                onChange={(e) => setAuto(e.target.checked)}
              />
              <span className="text-xs">
                <span className="block text-text-primary">{t('mobile.detail.auto')}</span>
                <span className="mt-0.5 block text-text-muted">{t('mobile.detail.autoHint')}</span>
              </span>
            </label>

            {canManage ? (
              <Button className="w-full" loading={saving} onClick={() => void save()}>
                <Save size={14} className="mr-1.5" />
                {t('common.save')}
              </Button>
            ) : null}
          </div>
        </Panel>
      </div>

      {/* ── Top-ups on this line ──────────────────────────────────────────── */}
      <Panel className="mt-6" title={t('mobile.detail.rechargeHistory')}>
        {recharges.length === 0 ? (
          <EmptyState message={t('mobile.detail.noRecharges')} />
        ) : (
          <table className="w-full text-sm">
            <thead className="border-b border-border text-left text-xs text-text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">{t('mobile.recharges.proposed')}</th>
                <th className="px-4 py-2 font-medium">{t('mobile.lines.zone')}</th>
                <th className="px-4 py-2 text-right font-medium">{t('mobile.recharges.atProposal')}</th>
                <th className="px-4 py-2 font-medium">{t('mobile.recharges.status')}</th>
                <th className="px-4 py-2 font-medium">{t('mobile.recharges.decidedBy')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {recharges.map((r) => (
                <tr key={r.id}>
                  <td className="px-4 py-2 text-xs">
                    <When iso={r.proposedAt} />
                  </td>
                  <td className="px-4 py-2 text-text-secondary">{r.zone}</td>
                  <td className="px-4 py-2 text-right">
                    <DataAmount mb={r.restMbAtProposal} />
                  </td>
                  <td className="px-4 py-2">
                    <RechargeStatusBadge status={r.status} />
                  </td>
                  <td className="px-4 py-2 text-xs text-text-secondary">
                    {r.decidedByName ?? <span className="text-text-muted">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {/* ── Consumption history ───────────────────────────────────────────── */}
      <Panel className="mt-6" title={t('mobile.detail.history')}>
        {history.length === 0 ? (
          <EmptyState message={t('mobile.detail.noHistory')} />
        ) : (
          <div className="max-h-80 overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 border-b border-border bg-bg-secondary text-left text-xs text-text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">{t('mobile.detail.observedAt')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.zone')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.detail.used')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.lines.remaining')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {history.map((h, i) => (
                  <tr key={`${h.observedAt}-${h.zone}-${i}`}>
                    <td className="px-4 py-1.5 text-xs">
                      <When iso={h.observedAt} />
                    </td>
                    <td className="px-4 py-1.5 text-text-secondary">{h.zone}</td>
                    <td className="px-4 py-1.5 text-right">
                      <DataAmount mb={h.usedMb} />
                    </td>
                    <td className="px-4 py-1.5 text-right">
                      <DataAmount mb={h.restMb} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="flex items-start gap-2 border-t border-border px-4 py-2 text-[11px] text-text-muted">
          <Info size={12} className="mt-0.5 shrink-0" />
          {t('mobile.detail.historyHint')}
        </p>
      </Panel>
    </div>
  );
}
