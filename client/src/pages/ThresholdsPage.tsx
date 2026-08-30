import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  ArrowLeft,
  BellRing,
  Info,
  Pencil,
  Plus,
  RotateCw,
  Timer,
  Trash2,
  Unplug,
  Waves,
} from 'lucide-react';
import {
  CAPABILITIES,
  THRESHOLD_COMPARATORS,
  THRESHOLD_METRICS,
  THRESHOLD_SCOPES,
  THRESHOLD_SEVERITIES,
  alertClearValue,
  type ThresholdComparator,
  type ThresholdMetric,
  type ThresholdScope,
  type ThresholdSeverity,
} from '@obliwan/shared';
import toast from 'react-hot-toast';
import { thresholdsApi } from '@/api/thresholds.api';
import { interfacesApi } from '@/api/interfaces.api';
import { useDeviceStore } from '@/store/deviceStore';
import { useGroupStore } from '@/store/groupStore';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { cn } from '@/utils/cn';
import { formatBps, formatDuration } from '@/utils/series';
import type { NetInterface, Threshold, ThresholdInput } from '@/types/telemetry';

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

// ── Metric metadata ─────────────────────────────────────────────────────────
//
// The unit is not decoration: `dev_temp_dc` is stored in TENTHS of a degree and
// `dev_rtt_us` in microseconds. An operator who types "45" meaning 45 °C into a
// field that means deci-degrees has just armed a threshold at 4.5 °C, which
// will never fire. The unit must be on screen, next to the box.

type MetricUnit = 'bps' | 'pct' | 'count' | 'dc' | 'us' | 'enum';

const METRIC_UNIT: Record<ThresholdMetric, MetricUnit> = {
  if_in_bps: 'bps',
  if_out_bps: 'bps',
  if_in_util_pct: 'pct',
  if_out_util_pct: 'pct',
  if_in_errs: 'count',
  if_out_errs: 'count',
  if_in_discards: 'count',
  if_out_discards: 'count',
  if_oper_status: 'enum',
  dev_cpu_pct: 'pct',
  dev_mem_pct: 'pct',
  dev_temp_dc: 'dc',
  dev_rtt_us: 'us',
  dev_reachable: 'enum',
};

const UNIT_KEY: Record<MetricUnit, string> = {
  bps: 'thresholds.units.bps',
  pct: 'thresholds.units.pct',
  count: 'thresholds.units.count',
  dc: 'thresholds.units.dc',
  us: 'thresholds.units.us',
  enum: 'thresholds.units.enum',
};

/** `dev_*` metrics never apply to an interface, and vice versa. */
function metricEntity(metric: ThresholdMetric): 'interface' | 'device' {
  return metric.startsWith('dev_') ? 'device' : 'interface';
}

/** `unitLabel` arrives already translated: this helper is called from render
 *  paths that each hold their own `t`, and threading the i18n function through
 *  a formatter is how a formatter ends up depending on React. */
function formatMetricValue(metric: ThresholdMetric, value: number, unitLabel: string): string {
  switch (METRIC_UNIT[metric]) {
    case 'bps':
      return formatBps(value, 1);
    case 'pct':
      return `${value} %`;
    case 'dc':
      return `${(value / 10).toFixed(1)} °C`;
    case 'us':
      return `${(value / 1000).toFixed(1)} ms`;
    default:
      return METRIC_UNIT[metric] === 'enum' ? String(value) : `${value} ${unitLabel}`;
  }
}

const SEVERITY_STYLE: Record<ThresholdSeverity, string> = {
  info: 'bg-status-pending/10 border-status-pending/30 text-status-pending',
  warning: 'bg-status-ssl-warning/10 border-status-ssl-warning/30 text-status-ssl-warning',
  critical: 'bg-status-ssl-expired/10 border-status-ssl-expired/40 text-status-ssl-expired',
};

/** Common dwell times, offered as chips so the field is not a blank box. */
const FOR_PRESETS = [60, 300, 900, 3600];

const emptyForm: ThresholdInput = {
  name: '',
  enabled: true,
  scope: 'tenant',
  deviceId: null,
  groupId: null,
  ifId: null,
  metric: 'if_in_util_pct',
  comparator: 'gt',
  value: 80,
  // NO DEFAULT IS INHERITED FROM THE DATABASE — `for_seconds` and
  // `hysteresis_pct` are NOT NULL with no DEFAULT on purpose, so an omitted
  // value is a hard INSERT failure rather than a silent one. These two numbers
  // are the form's own opinionated starting point, shown and editable, never a
  // hidden fallback.
  forSeconds: 300,
  hysteresisPct: 10,
  severity: 'warning',
  channelId: null,
};

/**
 * Threshold administration (spec §5/M3 — "seuils `for` + hystérésis →
 * notifications").
 *
 * This screen exists as much to EXPLAIN two fields as to edit them.
 * `forSeconds` and `hysteresisPct` are the only two mechanisms that stop an
 * alert from re-notifying in a loop, and an operator who does not understand
 * them sets them to 0 and then blames the product for the pager storm. So both
 * carry an inline explanation, and the form prints the resulting fire/clear
 * sentence in plain language as the numbers change.
 */
export function ThresholdsPage() {
  const { t } = useTranslation();
  const { devices, fetchDevices } = useDeviceStore();
  const { getGroupList, fetchGroups } = useGroupStore();
  const { hasCapability, isAdmin } = useAuthStore();

  const canWrite = isAdmin() || hasCapability(CAPABILITIES.SNMP_ADMIN);

  const [rows, setRows] = useState<Threshold[]>([]);
  const [interfaces, setInterfaces] = useState<NetInterface[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form, setForm] = useState<ThresholdInput>(emptyForm);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const list = await thresholdsApi.list();
      if (list === null) {
        setUnavailable(true);
        setRows([]);
      } else {
        setUnavailable(false);
        setRows(list);
      }
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      setLoadError(message ?? t('thresholds.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void load();
    void fetchDevices();
    void fetchGroups();
    void interfacesApi
      .list()
      .then((list) => setInterfaces(list ?? []))
      .catch(() => setInterfaces([]));
  }, [load, fetchDevices, fetchGroups]);

  const groups = useMemo(() => getGroupList(), [getGroupList]);

  // ── Derived explanation ───────────────────────────────────────────────────

  const clearValue = alertClearValue(form.value, form.comparator, form.hysteresisPct);
  const comparatorSymbol = { gt: '>', gte: '≥', lt: '<', lte: '≤' }[form.comparator];
  const clearSymbol = form.comparator === 'gt' || form.comparator === 'gte' ? '<' : '>';

  const validationError = useMemo(() => {
    if (!form.name.trim()) return t('thresholds.errors.nameRequired');
    // These two mirror the database CHECKs exactly. Catching them here is not
    // a substitute for the constraint — it is a better error message for the
    // same rule.
    if (!(form.forSeconds > 0)) return t('thresholds.errors.forPositive');
    if (form.forSeconds > 86_400) return t('thresholds.errors.forMax');
    if (form.hysteresisPct < 0 || form.hysteresisPct > 50) return t('thresholds.errors.hysteresisRange');
    if (form.scope === 'device' && form.deviceId === null) return t('thresholds.errors.deviceRequired');
    if (form.scope === 'group' && form.groupId === null) return t('thresholds.errors.groupRequired');
    if (form.scope === 'interface' && form.ifId === null) return t('thresholds.errors.interfaceRequired');
    return null;
  }, [form, t]);

  // ── Actions ───────────────────────────────────────────────────────────────

  const openCreate = () => {
    setEditingId(null);
    setForm(emptyForm);
    setShowForm(true);
  };

  const openEdit = (row: Threshold) => {
    setEditingId(row.id);
    setForm({
      name: row.name,
      enabled: row.enabled,
      scope: row.scope,
      deviceId: row.deviceId,
      groupId: row.groupId,
      ifId: row.ifId,
      metric: row.metric,
      comparator: row.comparator,
      value: row.value,
      forSeconds: row.forSeconds,
      hysteresisPct: row.hysteresisPct,
      severity: row.severity,
      channelId: row.channelId,
    });
    setShowForm(true);
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (validationError) {
      toast.error(validationError);
      return;
    }
    setSaving(true);
    try {
      // Scope hygiene: a rule scoped to a device must not carry a stale
      // `ifId` from a previous edit, or the server has to guess which one
      // wins. The client sends exactly one target, or none.
      const payload: ThresholdInput = {
        ...form,
        deviceId: form.scope === 'device' ? form.deviceId : null,
        groupId: form.scope === 'group' ? form.groupId : null,
        ifId: form.scope === 'interface' ? form.ifId : null,
      };
      if (editingId === null) {
        await thresholdsApi.create(payload);
        toast.success(t('thresholds.created'));
      } else {
        await thresholdsApi.update(editingId, payload);
        toast.success(t('thresholds.updated'));
      }
      setShowForm(false);
      setEditingId(null);
      setForm(emptyForm);
      void load();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('thresholds.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (row: Threshold) => {
    if (!confirm(t('thresholds.confirmDelete', { name: row.name }))) return;
    try {
      await thresholdsApi.remove(row.id);
      toast.success(t('thresholds.deleted'));
      void load();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('thresholds.deleteFailed'));
    }
  };

  const scopeLabel = (row: Threshold): string => {
    switch (row.scope) {
      case 'device':
        return row.deviceName ?? `#${row.deviceId}`;
      case 'group':
        return row.groupName ?? `#${row.groupId}`;
      case 'interface':
        return row.ifName ?? `#${row.ifId}`;
      default:
        return t(`thresholds.scope.${row.scope}`);
    }
  };

  const entityKind = metricEntity(form.metric);
  const unit = METRIC_UNIT[form.metric];

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <Link
            to="/interfaces"
            className="mb-1 inline-flex items-center gap-1 text-[12px] text-text-muted hover:text-text-primary"
          >
            <ArrowLeft size={12} />
            {t('nav.interfaces')}
          </Link>
          <h1 className="text-2xl font-semibold text-text-primary">{t('thresholds.title')}</h1>
          <p className="mt-1 text-sm text-text-muted">{t('thresholds.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
          {canWrite && !unavailable && (
            <Button size="sm" onClick={openCreate}>
              <Plus size={14} className="mr-1.5" />
              {t('thresholds.newThreshold')}
            </Button>
          )}
        </div>
      </div>

      {/* The lesson, stated once at the top of the screen. */}
      <div className="mb-5 rounded-lg border border-accent/25 bg-accent/5 p-4">
        <h2 className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-primary">
          <Info size={14} className="text-accent" />
          {t('thresholds.explainer.title')}
        </h2>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div>
            <div className="mb-1 flex items-center gap-1.5 text-[12px] font-semibold text-text-primary">
              <Timer size={12} className="text-accent" />
              {t('thresholds.fields.forSeconds')}
            </div>
            <p className="text-[12px] leading-relaxed text-text-secondary">
              {t('thresholds.explainer.for')}
            </p>
          </div>
          <div>
            <div className="mb-1 flex items-center gap-1.5 text-[12px] font-semibold text-text-primary">
              <Waves size={12} className="text-accent" />
              {t('thresholds.fields.hysteresis')}
            </div>
            <p className="text-[12px] leading-relaxed text-text-secondary">
              {t('thresholds.explainer.hysteresis')}
            </p>
          </div>
        </div>
        <p className="mt-3 border-t border-accent/20 pt-2 text-[11px] text-text-muted">
          {t('thresholds.explainer.mandatory')}
        </p>
      </div>

      {/* Form */}
      {showForm && canWrite && (
        <form onSubmit={handleSubmit} className="mb-5 rounded-lg border border-border bg-bg-secondary p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-text-secondary">
            {editingId === null ? t('thresholds.newThreshold') : t('thresholds.editThreshold')}
          </h2>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <Input
              label={t('thresholds.fields.name')}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />

            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('thresholds.fields.scope')}
              </label>
              <select
                className={cn(selectClass, 'w-full py-2')}
                value={form.scope}
                onChange={(e) =>
                  setForm({
                    ...form,
                    scope: e.target.value as ThresholdScope,
                    deviceId: null,
                    groupId: null,
                    ifId: null,
                  })
                }
              >
                {THRESHOLD_SCOPES.map((s) => (
                  <option key={s} value={s}>{t(`thresholds.scope.${s}`)}</option>
                ))}
              </select>
            </div>

            {/* Scope target */}
            {form.scope === 'device' && (
              <div className="space-y-1">
                <label className="block text-sm font-medium text-text-secondary">
                  {t('thresholds.fields.device')}
                </label>
                <select
                  className={cn(selectClass, 'w-full py-2')}
                  value={form.deviceId ?? ''}
                  onChange={(e) =>
                    setForm({ ...form, deviceId: e.target.value ? Number(e.target.value) : null })
                  }
                >
                  <option value="">{t('thresholds.fields.selectDevice')}</option>
                  {devices.map((d) => (
                    <option key={d.id} value={d.id}>{d.name}</option>
                  ))}
                </select>
              </div>
            )}
            {form.scope === 'group' && (
              <div className="space-y-1">
                <label className="block text-sm font-medium text-text-secondary">
                  {t('thresholds.fields.group')}
                </label>
                <select
                  className={cn(selectClass, 'w-full py-2')}
                  value={form.groupId ?? ''}
                  onChange={(e) =>
                    setForm({ ...form, groupId: e.target.value ? Number(e.target.value) : null })
                  }
                >
                  <option value="">{t('thresholds.fields.selectGroup')}</option>
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>{g.name}</option>
                  ))}
                </select>
              </div>
            )}
            {form.scope === 'interface' && (
              <div className="space-y-1">
                <label className="block text-sm font-medium text-text-secondary">
                  {t('thresholds.fields.interface')}
                </label>
                <select
                  className={cn(selectClass, 'w-full py-2')}
                  value={form.ifId ?? ''}
                  onChange={(e) =>
                    setForm({ ...form, ifId: e.target.value ? Number(e.target.value) : null })
                  }
                >
                  <option value="">{t('thresholds.fields.selectInterface')}</option>
                  {interfaces.map((i) => (
                    <option key={i.id} value={i.id}>
                      {(i.deviceName ?? `#${i.deviceId}`) + ' · ' + i.ifName}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('thresholds.fields.metric')}
              </label>
              <select
                className={cn(selectClass, 'w-full py-2')}
                value={form.metric}
                onChange={(e) => setForm({ ...form, metric: e.target.value as ThresholdMetric })}
              >
                {THRESHOLD_METRICS.map((m) => (
                  <option key={m} value={m}>{t(`thresholds.metric.${m}`)}</option>
                ))}
              </select>
              <p className="text-[11px] text-text-muted">
                {t(
                  entityKind === 'device'
                    ? 'thresholds.metricAppliesDevice'
                    : 'thresholds.metricAppliesInterface',
                )}
              </p>
            </div>

            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('thresholds.fields.comparator')}
              </label>
              <select
                className={cn(selectClass, 'w-full py-2')}
                value={form.comparator}
                onChange={(e) =>
                  setForm({ ...form, comparator: e.target.value as ThresholdComparator })
                }
              >
                {THRESHOLD_COMPARATORS.map((c) => (
                  <option key={c} value={c}>{t(`thresholds.comparator.${c}`)}</option>
                ))}
              </select>
            </div>

            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('thresholds.fields.value')}{' '}
                <span className="font-normal text-text-muted">({t(UNIT_KEY[unit])})</span>
              </label>
              <input
                type="number"
                step="any"
                className={cn(selectClass, 'w-full py-2')}
                value={form.value}
                onChange={(e) => setForm({ ...form, value: Number(e.target.value) })}
                required
              />
            </div>

            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('thresholds.fields.severity')}
              </label>
              <select
                className={cn(selectClass, 'w-full py-2')}
                value={form.severity}
                onChange={(e) =>
                  setForm({ ...form, severity: e.target.value as ThresholdSeverity })
                }
              >
                {THRESHOLD_SEVERITIES.map((s) => (
                  <option key={s} value={s}>{t(`thresholds.severity.${s}`)}</option>
                ))}
              </select>
            </div>
          </div>

          {/* The two anti-storm fields, given their own block. */}
          <div className="mt-4 grid grid-cols-1 gap-4 rounded-md border border-border bg-bg-tertiary/40 p-3 md:grid-cols-2">
            <div className="space-y-1">
              <label className="flex items-center gap-1.5 text-sm font-medium text-text-secondary">
                <Timer size={13} className="text-accent" />
                {t('thresholds.fields.forSeconds')}
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={1}
                  max={86400}
                  className={cn(selectClass, 'w-32 py-2')}
                  value={form.forSeconds}
                  onChange={(e) => setForm({ ...form, forSeconds: Number(e.target.value) })}
                  required
                />
                <span className="font-mono text-[12px] text-text-muted">
                  {formatDuration(form.forSeconds)}
                </span>
              </div>
              <div className="flex flex-wrap gap-1 pt-1">
                {FOR_PRESETS.map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setForm({ ...form, forSeconds: p })}
                    className={cn(
                      'rounded border px-1.5 py-0.5 font-mono text-[10px] transition-colors',
                      form.forSeconds === p
                        ? 'border-accent bg-accent/10 text-accent'
                        : 'border-border bg-bg-tertiary text-text-muted hover:text-text-primary',
                    )}
                  >
                    {formatDuration(p)}
                  </button>
                ))}
              </div>
              <p className="pt-1 text-[11px] leading-relaxed text-text-muted">
                {t('thresholds.hints.forSeconds')}
              </p>
            </div>

            <div className="space-y-1">
              <label className="flex items-center gap-1.5 text-sm font-medium text-text-secondary">
                <Waves size={13} className="text-accent" />
                {t('thresholds.fields.hysteresis')}
              </label>
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min={0}
                  max={50}
                  step={1}
                  value={form.hysteresisPct}
                  onChange={(e) => setForm({ ...form, hysteresisPct: Number(e.target.value) })}
                  className="h-1.5 flex-1 accent-accent"
                />
                <span className="w-12 shrink-0 text-right font-mono text-[12px] text-text-primary">
                  {form.hysteresisPct} %
                </span>
              </div>
              {form.hysteresisPct === 0 && (
                <p className="pt-1 text-[11px] leading-relaxed text-status-ssl-warning">
                  {t('thresholds.hints.hysteresisZero')}
                </p>
              )}
              <p className="pt-1 text-[11px] leading-relaxed text-text-muted">
                {t('thresholds.hints.hysteresis')}
              </p>
            </div>

            {/* The sentence. This is the part an operator actually reads. */}
            <div className="md:col-span-2 rounded-md border border-border bg-bg-secondary p-3">
              <div className="mb-1 text-[11px] uppercase tracking-wider text-text-muted">
                {t('thresholds.preview.title')}
              </div>
              <p className="text-[13px] leading-relaxed text-text-primary">
                {t('thresholds.preview.fires', {
                  comparator: comparatorSymbol,
                  value: formatMetricValue(form.metric, form.value, t(UNIT_KEY[unit])),
                  duration: formatDuration(form.forSeconds),
                })}
              </p>
              <p className="mt-1 text-[13px] leading-relaxed text-text-primary">
                {form.hysteresisPct === 0
                  ? t('thresholds.preview.clearsNoHysteresis', {
                      comparator: clearSymbol,
                      value: formatMetricValue(form.metric, form.value, t(UNIT_KEY[unit])),
                    })
                  : t('thresholds.preview.clears', {
                      comparator: clearSymbol,
                      value: formatMetricValue(form.metric, clearValue, t(UNIT_KEY[unit])),
                      pct: form.hysteresisPct,
                    })}
              </p>
            </div>
          </div>

          <label className="mt-3 flex items-center gap-2 text-sm text-text-primary">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
              className="h-4 w-4 rounded border-border bg-bg-tertiary accent-accent"
            />
            {t('thresholds.fields.enabled')}
          </label>

          {validationError && (
            <p className="mt-2 text-xs text-status-ssl-expired">{validationError}</p>
          )}

          <div className="mt-3 flex gap-2">
            <Button type="submit" size="sm" loading={saving}>
              {editingId === null ? t('common.create') : t('common.save')}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="secondary"
              onClick={() => {
                setShowForm(false);
                setEditingId(null);
              }}
            >
              {t('common.cancel')}
            </Button>
          </div>
        </form>
      )}

      {/* List */}
      {unavailable ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('thresholds.endpointUnavailable')}</p>
        </div>
      ) : loadError ? (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
          {t('thresholds.loadFailed')} — <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : loading && rows.length === 0 ? (
        <div className="flex justify-center py-16">
          <LoadingSpinner size="lg" />
        </div>
      ) : rows.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <BellRing size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('thresholds.empty')}</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full min-w-[960px] text-left text-sm">
            <thead>
              <tr className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
                <th className="px-3 py-2 font-medium">{t('thresholds.columns.name')}</th>
                <th className="px-3 py-2 font-medium">{t('thresholds.columns.scope')}</th>
                <th className="px-3 py-2 font-medium">{t('thresholds.columns.condition')}</th>
                <th className="px-3 py-2 font-medium">{t('thresholds.columns.for')}</th>
                <th className="px-3 py-2 font-medium">{t('thresholds.columns.hysteresis')}</th>
                <th className="px-3 py-2 font-medium">{t('thresholds.columns.severity')}</th>
                <th className="px-3 py-2 font-medium">{t('thresholds.columns.state')}</th>
                {canWrite && <th className="px-3 py-2 font-medium" />}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map((row) => (
                <tr key={row.id} className={cn('transition-colors hover:bg-bg-hover', !row.enabled && 'opacity-50')}>
                  <td className="px-3 py-2 font-medium text-text-primary">{row.name}</td>
                  <td className="px-3 py-2 text-text-secondary">
                    {t(`thresholds.scope.${row.scope}`)}
                    <div className="text-[10px] text-text-muted">{scopeLabel(row)}</div>
                  </td>
                  <td className="px-3 py-2 font-mono text-[12px] text-text-secondary">
                    {t(`thresholds.metric.${row.metric}`)}{' '}
                    {{ gt: '>', gte: '≥', lt: '<', lte: '≤' }[row.comparator]}{' '}
                    {formatMetricValue(row.metric, row.value, t(UNIT_KEY[METRIC_UNIT[row.metric]]))}
                  </td>
                  <td className="px-3 py-2 font-mono text-[12px] text-text-secondary">
                    {formatDuration(row.forSeconds)}
                  </td>
                  <td className="px-3 py-2 font-mono text-[12px] text-text-secondary">
                    {row.hysteresisPct} %
                    <div className="text-[10px] text-text-muted">
                      {t('thresholds.clearsAt', {
                        value: formatMetricValue(
                          row.metric,
                          alertClearValue(row.value, row.comparator, row.hysteresisPct),
                          t(UNIT_KEY[METRIC_UNIT[row.metric]]),
                        ),
                      })}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={cn(
                        'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium',
                        SEVERITY_STYLE[row.severity],
                      )}
                    >
                      {t(`thresholds.severity.${row.severity}`)}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px]">
                    {row.firingCount ? (
                      <span className="text-status-ssl-expired">
                        {t('thresholds.firingCount', { count: row.firingCount })}
                      </span>
                    ) : row.pendingCount ? (
                      // `pending` is shown, never folded into "ok": it is the
                      // only way to see that the dwell timer is running.
                      <span className="text-status-ssl-warning">
                        {t('thresholds.pendingCount', { count: row.pendingCount })}
                      </span>
                    ) : (
                      <span className="text-text-muted">{t('thresholds.stateOk')}</span>
                    )}
                  </td>
                  {canWrite && (
                    <td className="px-3 py-2">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => openEdit(row)}
                          className="rounded p-1.5 text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
                          title={t('common.edit')}
                        >
                          <Pencil size={13} />
                        </button>
                        <button
                          onClick={() => void handleDelete(row)}
                          className="rounded p-1.5 text-text-muted transition-colors hover:bg-bg-hover hover:text-status-ssl-expired"
                          title={t('common.delete')}
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
