import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Activity,
  Archive,
  FileCode,
  GitCompareArrows,
  Lock,
  PlayCircle,
  Plug,
  Radio,
  RadioTower,
  Router,
  ScrollText,
  Settings as SettingsIcon,
  ShieldAlert,
  Trash2,
  KeyRound,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  CAPABILITIES,
  TRANSPORT_KINDS,
  DEVICE_STATUSES,
  type TransportKind,
  type DeviceStatus,
} from '@obliwan/shared';
import { devicesApi } from '@/api/devices.api';
import { useDeviceStore } from '@/store/deviceStore';
import { useSiteStore } from '@/store/siteStore';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { VerdictBadge } from '@/components/fleet/VerdictBadge';
import { PresenceDot } from '@/components/fleet/PresenceDot';
import { cn } from '@/utils/cn';
import { connStateStyle, deviceStatusStyle, TRANSPORT_DEFAULT_PORT } from '@/utils/verdict';
import { anonHostname } from '@/utils/anonymize';
import { DeviceInterfacesTab } from '@/components/telemetry/DeviceInterfacesTab';
import { DeviceConfigTab } from '@/components/config/DeviceConfigTab';
import { DeviceDriftTab } from '@/components/config/DeviceDriftTab';
import { DeviceChangesTab } from '@/components/change/DeviceChangesTab';
import { DeviceAcsTab } from '@/components/acs/DeviceAcsTab';
import type { DeviceDetail, DeviceTransport, TransportTestResult } from '@/types/fleet';
import toast from 'react-hot-toast';

// ── Tabs ────────────────────────────────────────────────────────────────────
//
// Spec §4.2 lists nine tabs. M2 gave two of them content; M3 unlocked a third,
// Interfaces; M4 unlocks Configuration and Dérive. The remaining four are
// rendered DISABLED with the milestone that unlocks them — never as a tab that
// opens on an empty pane, which reads as a broken page rather than as an
// unfinished one.
//
// `backups` keeps its M4 marker on purpose: the backup screen is M4 SERVER
// work and is not part of this milestone's client scope, and a tab that opens
// on nothing would be a regression on the rule above.

type TabId =
  | 'overview' | 'interfaces' | 'config' | 'drift'
  | 'changes' | 'backups' | 'acs' | 'logs' | 'settings';

interface TabDef {
  id: TabId;
  labelKey: string;
  icon: React.ReactNode;
  /** Absent = the tab works today. */
  milestone?: string;
}

const TABS: TabDef[] = [
  { id: 'overview',   labelKey: 'devices.tabs.overview',   icon: <Router size={14} /> },
  { id: 'interfaces', labelKey: 'devices.tabs.interfaces', icon: <Activity size={14} /> },
  { id: 'config',     labelKey: 'devices.tabs.config',     icon: <FileCode size={14} /> },
  { id: 'drift',      labelKey: 'devices.tabs.drift',      icon: <GitCompareArrows size={14} /> },
  { id: 'changes',    labelKey: 'devices.tabs.changes',    icon: <PlayCircle size={14} /> },
  { id: 'backups',    labelKey: 'devices.tabs.backups',    icon: <Archive size={14} />,          milestone: 'M4' },
  // M10 unlocks TR-069. The tab is enabled for EVERY brand on purpose: on a
  // MikroTik or a SonicWall its content is the sentence "this platform ships no
  // CWMP client, use <transport> instead" (D2), and that sentence is exactly
  // what the operator came looking for. A tab greyed out on three quarters of
  // the fleet would leave him to guess it.
  { id: 'acs',        labelKey: 'devices.tabs.acs',        icon: <RadioTower size={14} /> },
  { id: 'logs',       labelKey: 'devices.tabs.logs',       icon: <ScrollText size={14} />,       milestone: 'M8' },
  { id: 'settings',   labelKey: 'devices.tabs.settings',   icon: <SettingsIcon size={14} /> },
];

// ── Small presentational helpers ────────────────────────────────────────────

function Field({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wider text-text-muted">{label}</dt>
      <dd className={cn('mt-0.5 text-sm text-text-primary', mono && 'font-mono text-[13px]')}>
        {value === null || value === undefined || value === '' ? (
          <span className="text-text-muted">—</span>
        ) : (
          value
        )}
      </dd>
    </div>
  );
}

/** Shown in place of a tab the session may not read. R10 keeps CONFIG_READ
 *  distinct from DEVICE_READ, so this is a normal state, not an error. */
function CapabilityNotice() {
  const { t } = useTranslation();
  return (
    <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
      <ShieldAlert size={26} className="mx-auto mb-2 text-text-muted" />
      <p className="text-sm text-text-muted">{t('config.noCapability')}</p>
    </div>
  );
}

function Card({ title, children, className }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={cn('rounded-lg border border-border bg-bg-secondary p-4', className)}>
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-text-secondary">{title}</h2>
      {children}
    </section>
  );
}

// ── Page ────────────────────────────────────────────────────────────────────

export function DeviceDetailPage() {
  const { id } = useParams<{ id: string }>();
  const deviceId = Number(id);
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { canWriteDevice, getDevicePermission, hasCapability, isAdmin } = useAuthStore();
  const { sites, fetchSites } = useSiteStore();
  const livePresence = useDeviceStore((s) => s.presence[deviceId]);
  const removeFromStore = useDeviceStore((s) => s.removeDevice);

  const [tab, setTab] = useState<TabId>('overview');
  const [device, setDevice] = useState<DeviceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  /** `null` = the server does not expose the channel list yet. */
  const [transports, setTransports] = useState<DeviceTransport[] | null>(null);
  const [transportsUnavailable, setTransportsUnavailable] = useState(false);
  const [testResults, setTestResults] = useState<TransportTestResult[] | null>(null);
  const [testing, setTesting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const detail = await devicesApi.getById(deviceId);
      setDevice(detail);
      if (detail.transports) {
        setTransports(detail.transports);
      } else {
        const list = await devicesApi.transports(deviceId);
        setTransports(list);
        setTransportsUnavailable(list === null);
      }
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (status === 404) setNotFound(true);
      else toast.error(t('devices.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [deviceId, t]);

  useEffect(() => {
    if (!Number.isFinite(deviceId)) { setNotFound(true); setLoading(false); return; }
    void load();
    void fetchSites();
  }, [deviceId, load, fetchSites]);

  const presence = livePresence ?? device?.presence ?? null;
  const canWrite = device ? canWriteDevice(device.id, device.groupId) : false;
  const permission = device ? getDevicePermission(device.id, device.groupId) : null;

  const health = useMemo(() => device?.health ?? [], [device]);
  const canReadConfig = isAdmin() || hasCapability(CAPABILITIES.CONFIG_READ);
  // R10's argument applied once more: seeing a router and being allowed to
  // watch (or start) a write against it are two different privileges.
  const canSeeChanges = isAdmin() || hasCapability(CAPABILITIES.CHANGE_APPLY);

  if (loading && !device) {
    return <div className="flex h-full items-center justify-center"><LoadingSpinner size="lg" /></div>;
  }

  if (notFound || !device) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4">
        <p className="text-text-muted">{t('devices.notFound')}</p>
        <Link to="/devices"><Button variant="secondary">{t('devices.backToFleet')}</Button></Link>
      </div>
    );
  }

  const siteName = device.siteId !== null
    ? sites.find((s) => s.id === device.siteId)?.name ?? `#${device.siteId}`
    : null;

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResults(null);
    try {
      const results = await devicesApi.testConnection(device.id);
      setTestResults(results);
      if (results.length === 0) toast(t('devices.testNoResult'));
      else if (results.every((r) => r.ok)) toast.success(t('devices.testAllOk'));
      else toast.error(t('devices.testSomeFailed'));
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('devices.testFailed'));
    } finally {
      setTesting(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm(t('devices.confirmDelete', { name: device.name }))) return;
    try {
      await devicesApi.remove(device.id);
      removeFromStore(device.id);
      toast.success(t('devices.deleted'));
      navigate('/devices');
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('devices.failedDelete'));
    }
  };

  return (
    <div className="p-6">
      <Link to="/devices" className="mb-4 inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary">
        <ArrowLeft size={14} />
        {t('devices.backToFleet')}
      </Link>

      {/* Header */}
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/10">
            {device.role === 'concentrator'
              ? <Radio size={24} className="text-accent" />
              : <Router size={24} className="text-accent" />}
          </div>
          <div>
            <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
              <PresenceDot presence={presence} size={10} />
              {anonHostname(device.name)}
            </h1>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <span className={cn(
                'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium',
                deviceStatusStyle(device.status),
              )}>
                {t(`fleet.status.${device.status}`)}
              </span>
              <span className="rounded-full border border-border bg-bg-tertiary px-2 py-0.5 text-[10px] text-text-muted">
                {t(`fleet.role.${device.role}`)}
              </span>
              <VerdictBadge verdict={presence?.verdict ?? null} />
              {permission === 'ro' && (
                <span className="rounded-full border border-border bg-bg-tertiary px-2 py-0.5 text-[10px] text-text-muted">
                  {t('devices.readOnlyBadge')}
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={handleTestConnection} loading={testing}>
            <Plug size={14} className="mr-1.5" />
            {t('devices.testConnection')}
          </Button>
          {canWrite && (
            <Button variant="danger" size="sm" onClick={handleDelete}>
              <Trash2 size={14} className="mr-1.5" />
              {t('common.delete')}
            </Button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-5 flex flex-wrap gap-1 border-b border-border">
        {TABS.map((def) => {
          if (def.milestone) {
            return (
              <div
                key={def.id}
                aria-disabled="true"
                title={t('devices.tabLocked', { milestone: def.milestone })}
                className="flex cursor-not-allowed select-none items-center gap-1.5 border-b-2 border-transparent px-3 py-2 text-[13px] text-text-muted opacity-40"
              >
                {def.icon}
                {t(def.labelKey)}
                <Lock size={10} />
                <span className="font-mono text-[10px] tracking-wider">{def.milestone}</span>
              </div>
            );
          }
          return (
            <button
              key={def.id}
              onClick={() => setTab(def.id)}
              className={cn(
                'flex items-center gap-1.5 border-b-2 px-3 py-2 text-[13px] transition-colors',
                tab === def.id
                  ? 'border-accent text-text-primary'
                  : 'border-transparent text-text-secondary hover:text-text-primary',
              )}
            >
              {def.icon}
              {t(def.labelKey)}
            </button>
          );
        })}
      </div>

      {/* Test-connection results */}
      {testResults && (
        <div className="mb-5 rounded-lg border border-border bg-bg-secondary p-4">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">
            {t('devices.testResults')}
          </h2>
          {testResults.length === 0 ? (
            <p className="text-sm text-text-muted">{t('devices.testNoResult')}</p>
          ) : (
            <ul className="space-y-1.5">
              {testResults.map((r, i) => (
                <li key={`${r.transport}-${i}`} className="flex items-center gap-2 text-sm">
                  <span className={cn(
                    'inline-flex w-24 justify-center rounded-full border px-2 py-0.5 text-[10px] font-medium',
                    r.ok
                      ? 'border-status-up/30 bg-status-up/10 text-status-up'
                      : 'border-status-down/40 bg-status-down/10 text-status-down',
                  )}>
                    {t(`fleet.transport.${r.transport}`)}
                  </span>
                  <span className={r.ok ? 'text-status-up' : 'text-status-down'}>
                    {r.ok ? t('devices.testOk') : t('devices.testKo')}
                  </span>
                  {r.rttMs != null && <span className="font-mono text-xs text-text-muted">{r.rttMs} ms</span>}
                  {r.error && <span className="font-mono text-xs text-text-muted">{r.error}</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* ── Overview ── */}
      {tab === 'overview' && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card title={t('devices.sections.identity')}>
            <dl className="grid grid-cols-2 gap-4">
              <Field label={t('devices.fields.brand')} value={t(`fleet.brand.${device.brand}`)} />
              <Field label={t('devices.fields.family')} value={t(`fleet.family.${device.family}`)} />
              <Field label={t('devices.fields.model')} value={device.model} />
              <Field label={t('devices.fields.serial')} value={device.serial} mono />
              <Field label={t('devices.fields.osVersion')} value={device.osVersion} mono />
              <Field label={t('devices.fields.systemIdentity')} value={device.systemIdentity} mono />
              <Field label={t('devices.fields.pppUsername')} value={device.pppUsername} mono />
              <Field label={t('devices.fields.uuid')} value={device.uuid} mono />
            </dl>
            <p className="mt-3 text-xs text-text-muted">{t('devices.identityHint')}</p>
          </Card>

          <Card title={t('devices.sections.placement')}>
            <dl className="grid grid-cols-2 gap-4">
              <Field
                label={t('devices.fields.site')}
                value={device.siteId !== null
                  ? <Link to={`/sites/${device.siteId}`} className="text-accent hover:underline">{siteName}</Link>
                  : <span className="italic text-text-muted">{t('fleet.unassignedSite')}</span>}
              />
              <Field
                label={t('devices.fields.group')}
                value={device.groupId !== null
                  ? <Link to={`/group/${device.groupId}`} className="text-accent hover:underline">
                      {device.groupName ?? `#${device.groupId}`}
                    </Link>
                  : null}
              />
              <Field
                label={t('devices.fields.concentrator')}
                value={device.concentratorId !== null
                  ? <Link to={`/devices/${device.concentratorId}`} className="text-accent hover:underline">
                      {device.concentratorName ?? `#${device.concentratorId}`}
                    </Link>
                  : <span className="italic text-text-muted">{t('devices.noConcentrator')}</span>}
              />
              <Field label={t('devices.fields.managed')} value={device.isManaged ? t('fleet.yes') : t('fleet.no')} />
              <Field label={t('devices.fields.firstSeen')} value={device.firstSeenAt ? new Date(device.firstSeenAt).toLocaleString() : null} />
              <Field label={t('devices.fields.lastSeen')} value={device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString() : null} />
            </dl>
          </Card>

          <Card title={t('devices.sections.reachability')}>
            <div className="mb-3">
              <VerdictBadge verdict={presence?.verdict ?? null} withHint />
            </div>
            <dl className="grid grid-cols-2 gap-4">
              <Field
                label={t('devices.fields.pppState')}
                value={presence == null || presence.up === null
                  ? <span className="italic text-text-muted">{t('fleet.presenceUnknown')}</span>
                  : presence.up
                    ? <span className="text-status-up">{t('fleet.presenceUp')}</span>
                    : <span className="text-status-down">{t('fleet.presenceDown')}</span>}
              />
              <Field label={t('fleet.lastChange')} value={presence?.at ? new Date(presence.at).toLocaleString() : null} />
              <Field label={t('devices.fields.tunnelIp')} value={presence?.tunnelIp ?? device.tunnelIp} mono />
              <Field label={t('devices.fields.wanPublicIp')} value={presence?.callerIp ?? device.wanPublicIp} mono />
              <Field label={t('devices.fields.sourceIpHint')} value={device.sourceIpHint} mono />
            </dl>
            <p className="mt-3 text-xs text-text-muted">{t('devices.addressingHint')}</p>
          </Card>

          <Card title={t('devices.sections.transportHealth')}>
            {health.length === 0 ? (
              <p className="text-sm text-text-muted">{t('devices.noHealth')}</p>
            ) : (
              <ul className="space-y-2">
                {health.map((h) => (
                  <li key={h.transport} className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="w-24 font-mono text-[12px] text-text-secondary">
                      {t(`fleet.transport.${h.transport}`)}
                    </span>
                    <span className={cn(
                      'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium',
                      connStateStyle(h.connState),
                    )}>
                      {t(`fleet.connState.${h.connState}`)}
                    </span>
                    <span className="text-[11px] text-text-muted">
                      {t(`fleet.circuit.${h.circuitState}`)}
                    </span>
                    {h.lastRttMs != null && (
                      <span className="font-mono text-[11px] text-text-muted">{h.lastRttMs} ms</span>
                    )}
                    {h.lastError && (
                      <span className="font-mono text-[11px] text-text-muted">{h.lastError}</span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {device.notes && (
            <Card title={t('devices.fields.notes')} className="lg:col-span-2">
              <p className="whitespace-pre-wrap text-sm text-text-secondary">{device.notes}</p>
            </Card>
          )}
        </div>
      )}

      {/* ── Interfaces (M3) ── */}
      {tab === 'interfaces' && <DeviceInterfacesTab deviceId={device.id} />}

      {/* ── Configuration + Dérive (M4) ──
          Both are behind CONFIG_READ, which R10 keeps distinct from
          DEVICE_READ: a user who may see that this router exists is not
          thereby allowed to read its configuration. The tab is hidden rather
          than shown-and-empty, because an empty pane reads as "this device has
          no configuration", which is a statement we would be inventing. */}
      {tab === 'config' && (
        canReadConfig
          ? <DeviceConfigTab deviceId={device.id} deviceName={device.name} />
          : <CapabilityNotice />
      )}

      {tab === 'drift' && (
        canReadConfig ? <DeviceDriftTab deviceId={device.id} /> : <CapabilityNotice />
      )}

      {/* M6 — Changements. Behind CHANGE_APPLY rather than DEVICE_READ: this
          tab is where a change is started from, and the queue is the only path
          along which this product writes to an equipment (decision D3). The
          tab shows the §8.3 safety net BEFORE it shows the link to the
          planner. */}
      {tab === 'changes' && (
        canSeeChanges
          ? <DeviceChangesTab deviceId={device.id} deviceName={device.name} />
          : <CapabilityNotice />
      )}

      {/* ── TR-069 (M10) ──
          No capability gate at the tab: the coverage answer ("MikroTik ships no
          CWMP client") is architectural, not privileged, and `DeviceAcsTab`
          checks ACS_ADMIN itself before it fetches anything. */}
      {tab === 'acs' && (
        <DeviceAcsTab deviceId={device.id} brand={device.brand} family={device.family} />
      )}

      {/* ── Settings ── */}
      {tab === 'settings' && (
        <SettingsTab
          device={device}
          canWrite={canWrite}
          transports={transports}
          transportsUnavailable={transportsUnavailable}
          onChanged={load}
        />
      )}
    </div>
  );
}

// ── Settings tab ────────────────────────────────────────────────────────────

interface SettingsTabProps {
  device: DeviceDetail;
  canWrite: boolean;
  transports: DeviceTransport[] | null;
  transportsUnavailable: boolean;
  onChanged: () => Promise<void>;
}

interface TransportForm {
  transport: TransportKind;
  host: string;
  port: string;
  username: string;
  secret: string;
  useTls: boolean;
}

function SettingsTab({ device, canWrite, transports, transportsUnavailable, onChanged }: SettingsTabProps) {
  const { t } = useTranslation();
  const { sites } = useSiteStore();

  const [name, setName] = useState(device.name);
  const [status, setStatus] = useState<DeviceStatus>(device.status);
  const [siteId, setSiteId] = useState<string>(device.siteId === null ? '' : String(device.siteId));
  const [isManaged, setIsManaged] = useState(device.isManaged);
  const [notes, setNotes] = useState(device.notes ?? '');
  const [saving, setSaving] = useState(false);

  const [showTransportForm, setShowTransportForm] = useState(false);
  const [tf, setTf] = useState<TransportForm>({
    transport: 'ssh', host: '', port: '', username: '', secret: '', useTls: false,
  });
  const [addingTransport, setAddingTransport] = useState(false);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await devicesApi.update(device.id, {
        name,
        status,
        siteId: siteId ? Number(siteId) : null,
        isManaged,
        notes: notes || null,
      });
      toast.success(t('devices.updated'));
      await onChanged();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('devices.failedUpdate'));
    } finally {
      setSaving(false);
    }
  };

  const addTransport = async (e: FormEvent) => {
    e.preventDefault();
    setAddingTransport(true);
    try {
      await devicesApi.upsertTransport(device.id, {
        transport: tf.transport,
        host: tf.host || null,
        port: tf.port ? Number(tf.port) : null,
        username: tf.username || null,
        secret: tf.secret || null,
        useTls: tf.useTls,
      });
      toast.success(t('devices.transportAdded'));
      // Wipe the secret from component state the moment it leaves the browser.
      setTf({ transport: 'ssh', host: '', port: '', username: '', secret: '', useTls: false });
      setShowTransportForm(false);
      await onChanged();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('devices.transportFailed'));
    } finally {
      setAddingTransport(false);
    }
  };

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card title={t('devices.sections.general')}>
        {!canWrite && (
          <p className="mb-3 rounded-md border border-border bg-bg-tertiary px-3 py-2 text-xs text-text-muted">
            {t('devices.readOnlyHint')}
          </p>
        )}
        <form onSubmit={save} className="space-y-3">
          <Input
            label={t('devices.fields.name')}
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={!canWrite}
            required
          />
          <div className="space-y-1">
            <label className="block text-sm font-medium text-text-secondary">{t('devices.fields.status')}</label>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as DeviceStatus)}
              disabled={!canWrite}
              className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-50"
            >
              {DEVICE_STATUSES.map((s) => (
                <option key={s} value={s}>{t(`fleet.status.${s}`)}</option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-text-secondary">{t('devices.fields.site')}</label>
            <select
              value={siteId}
              onChange={(e) => setSiteId(e.target.value)}
              disabled={!canWrite}
              className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-50"
            >
              <option value="">{t('devices.noSite')}</option>
              {sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </div>
          <label className="flex items-center gap-2 text-sm text-text-primary">
            <input
              type="checkbox"
              checked={isManaged}
              disabled={!canWrite}
              onChange={(e) => setIsManaged(e.target.checked)}
              className="h-4 w-4 rounded border-border bg-bg-tertiary accent-accent"
            />
            {t('devices.fields.managed')}
          </label>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-text-secondary">{t('devices.fields.notes')}</label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              disabled={!canWrite}
              rows={3}
              className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-50"
            />
          </div>
          {canWrite && (
            <Button type="submit" size="sm" loading={saving}>{t('common.save')}</Button>
          )}
        </form>
      </Card>

      <Card title={t('devices.sections.transports')}>
        <div className="mb-3 flex items-start gap-2 rounded-md border border-accent/20 bg-accent/5 p-3">
          <KeyRound size={14} className="mt-0.5 shrink-0 text-accent" />
          <p className="text-xs text-text-secondary">{t('devices.vaultHint')}</p>
        </div>

        {transportsUnavailable ? (
          <p className="rounded-md border border-dashed border-border px-3 py-4 text-center text-xs text-text-muted">
            {t('devices.transportsUnavailable')}
          </p>
        ) : !transports || transports.length === 0 ? (
          <p className="rounded-md border border-dashed border-border px-3 py-4 text-center text-xs text-text-muted">
            {t('devices.noTransport')}
          </p>
        ) : (
          <ul className="divide-y divide-border rounded-md border border-border">
            {transports.map((tr) => (
              <li key={tr.id} className="px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[12px] text-text-primary">
                    {t(`fleet.transport.${tr.transport}`)}
                  </span>
                  <span className={cn(
                    'rounded-full border px-1.5 py-0.5 text-[10px]',
                    tr.enabled
                      ? 'border-status-up/30 bg-status-up/10 text-status-up'
                      : 'border-border bg-bg-tertiary text-text-muted',
                  )}>
                    {tr.enabled ? t('fleet.enabled') : t('fleet.disabled')}
                  </span>
                  <span className="font-mono text-[11px] text-text-muted">
                    {tr.host ?? '—'}{tr.port ? `:${tr.port}` : ''}
                  </span>
                  {tr.username && (
                    <span className="font-mono text-[11px] text-text-muted">{tr.username}</span>
                  )}
                  <span className="ml-auto flex items-center gap-1.5">
                    {tr.hasSecret && (
                      <span
                        className="inline-flex items-center gap-0.5 rounded-full border border-border bg-bg-tertiary px-1.5 py-0.5 text-[10px] text-text-muted"
                        title={t('devices.secretStoredHint')}
                      >
                        <KeyRound size={9} />
                        {t('devices.secretStored', { version: tr.keyVersion })}
                      </span>
                    )}
                    {tr.useTls && (
                      <span className="rounded-full border border-border bg-bg-tertiary px-1.5 py-0.5 text-[10px] text-text-muted">
                        TLS
                      </span>
                    )}
                  </span>
                </div>
                {tr.tlsFingerprintSha256 && (
                  <div className="mt-1 break-all font-mono text-[10px] text-text-muted">
                    {t('devices.pinnedFingerprint')}: {tr.tlsFingerprintSha256}
                  </div>
                )}
                {tr.lastError && (
                  <div className="mt-1 font-mono text-[10px] text-status-down">{tr.lastError}</div>
                )}
              </li>
            ))}
          </ul>
        )}

        {canWrite && (
          <div className="mt-3">
            {!showTransportForm ? (
              <Button size="sm" variant="secondary" onClick={() => setShowTransportForm(true)}>
                <Plug size={14} className="mr-1.5" />
                {t('devices.addTransport')}
              </Button>
            ) : (
              <form onSubmit={addTransport} className="space-y-3 rounded-md border border-border p-3">
                <div className="space-y-1">
                  <label className="block text-sm font-medium text-text-secondary">
                    {t('devices.fields.transport')}
                  </label>
                  <select
                    value={tf.transport}
                    onChange={(e) => {
                      const transport = e.target.value as TransportKind;
                      const port = TRANSPORT_DEFAULT_PORT[transport];
                      setTf({ ...tf, transport, port: port === null ? '' : String(port) });
                    }}
                    className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent"
                  >
                    {TRANSPORT_KINDS.map((k) => (
                      <option key={k} value={k}>{t(`fleet.transport.${k}`)}</option>
                    ))}
                  </select>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <Input
                    label={t('devices.fields.host')}
                    value={tf.host}
                    onChange={(e) => setTf({ ...tf, host: e.target.value })}
                    placeholder={device.tunnelIp ?? ''}
                  />
                  <Input
                    label={t('devices.fields.port')}
                    value={tf.port}
                    onChange={(e) => setTf({ ...tf, port: e.target.value })}
                  />
                  <Input
                    label={t('devices.fields.username')}
                    value={tf.username}
                    onChange={(e) => setTf({ ...tf, username: e.target.value })}
                    autoComplete="off"
                  />
                  <Input
                    label={t('devices.fields.secret')}
                    type="password"
                    value={tf.secret}
                    onChange={(e) => setTf({ ...tf, secret: e.target.value })}
                    autoComplete="new-password"
                  />
                </div>
                <label className="flex items-center gap-2 text-sm text-text-primary">
                  <input
                    type="checkbox"
                    checked={tf.useTls}
                    onChange={(e) => setTf({ ...tf, useTls: e.target.checked })}
                    className="h-4 w-4 rounded border-border bg-bg-tertiary accent-accent"
                  />
                  {t('devices.fields.useTls')}
                </label>
                {tf.transport === 'routeros_api' && !tf.useTls && (
                  <p className="flex items-start gap-1.5 text-xs text-status-ssl-warning">
                    <ShieldAlert size={12} className="mt-0.5 shrink-0" />
                    {t('devices.plaintextApiWarning')}
                  </p>
                )}
                <div className="flex gap-2">
                  <Button type="submit" size="sm" loading={addingTransport}>{t('common.save')}</Button>
                  <Button type="button" size="sm" variant="secondary" onClick={() => setShowTransportForm(false)}>
                    {t('common.cancel')}
                  </Button>
                </div>
              </form>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
