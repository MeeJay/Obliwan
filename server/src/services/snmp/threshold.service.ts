/**
 * Thresholds: `ok -> pending -> firing`, with a dwell timer and hysteresis.
 *
 * ┌─ THE TWO MECHANISMS, AND WHY BOTH ARE MANDATORY ──────────────────────────┐
 * │ `for_seconds` stops ONE 30-second spike from paging a human at 03:00.     │
 * │ `hysteresis_pct` stops a value parked ON the boundary from firing,        │
 * │ clearing, firing and clearing again every single cycle, for ever.         │
 * │                                                                          │
 * │ Both are NOT NULL WITH NO DEFAULT in the schema. That is deliberate: an   │
 * │ omitted value is a hard INSERT failure, not a silently inherited one.     │
 * │ A default of 0 on either would look like it worked and would produce the  │
 * │ alert storm the columns exist to prevent.                                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * THE THREE STATES ARE THREE, NOT TWO. `pending` is not cosmetic: folding it
 * into `ok` makes the dwell timer unobservable, so "why did this not fire?"
 * becomes unanswerable and every future report of a missed alert is
 * unfalsifiable.
 *
 * A HOLE NEVER CLEARS AN ALERT. When a metric is not measurable this cycle
 * (the sample was discarded -- a reboot, a wrap, an ifIndex remap) the
 * threshold is NOT evaluated at all. Reading "no data" as "not breached" would
 * resolve a real outage on the strength of the fact that we lost sight of it,
 * which is the single most dangerous confusion in this file.
 */

import type {
  AlertEntityKind,
  DeviceSampleRow,
  IfSampleRow,
  ThresholdComparator,
  ThresholdMetric,
  ThresholdScope,
  ThresholdSeverity,
  ThresholdState,
} from '@obliwan/shared';
import { alertClearValue, ifOperStatusName, IF_OPER_STATUS, SENTINEL } from '@obliwan/shared';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { notificationService } from '../notification.service';
import { getPlugin } from '../../notifications/registry';
import { config } from '../../config';
import type { SnmpInterfaceRow } from './targets';

/**
 * Knex types `RawBinding` as a homogeneous scalar or array, which cannot
 * express "an array of arrays, some of which contain nulls" -- exactly the
 * shape every `unnest()` insert in this codebase needs. The cast is confined
 * to this one helper rather than sprinkled at each call site, so there is one
 * place to look if the driver's contract ever changes.
 */
function bindings(values: unknown[]): readonly Knex.RawBinding[] {
  return values as readonly Knex.RawBinding[];
}


// ============================================================================
// Rows
// ============================================================================

export interface ThresholdRow {
  id: number;
  uuid: string;
  tenant_id: number;
  name: string;
  enabled: boolean;
  scope: ThresholdScope;
  device_id: number | null;
  group_id: number | null;
  if_id: number | null;
  metric: ThresholdMetric;
  comparator: ThresholdComparator;
  value: string;
  for_seconds: number;
  hysteresis_pct: string;
  severity: ThresholdSeverity;
  channel_id: number | null;
}

interface AlertStateRow {
  threshold_id: number;
  entity_kind: AlertEntityKind;
  entity_id: number;
  device_id: number;
  state: ThresholdState;
  since: Date;
  breach_started_at: Date | null;
  last_eval_at: Date;
  last_value: string | null;
  notified_at: Date | null;
  notification_count: number;
}

export interface EvaluationInput {
  deviceId: number;
  tenantId: number;
  groupId: number | null;
  deviceName: string;
  at: Date;
  interfaces: SnmpInterfaceRow[];
  /** ONLY the samples that were actually written. A discarded interface is
   *  absent, and absence means "not evaluated" -- see the file header. */
  samples: IfSampleRow[];
  deviceSample: DeviceSampleRow;
}

// ============================================================================
// Metric extraction
// ============================================================================

const INTERFACE_METRICS = new Set<ThresholdMetric>([
  'if_in_bps',
  'if_out_bps',
  'if_in_util_pct',
  'if_out_util_pct',
  'if_in_errs',
  'if_out_errs',
  'if_in_discards',
  'if_out_discards',
  'if_oper_status',
]);

/**
 * The metric's value for one interface sample, or `null` when it cannot be
 * computed.
 *
 * The utilisation metrics return `null` when the line speed is unknown: on a
 * PPP link or a tunnel `ifHighSpeed` is 0, and "0 % of an unknown capacity"
 * would read as a perfectly healthy link that can never alert.
 */
function interfaceMetric(
  metric: ThresholdMetric,
  sample: IfSampleRow,
  iface: SnmpInterfaceRow,
): number | null {
  const speed = Number(iface.speed_bps ?? 0);
  switch (metric) {
    case 'if_in_bps':
      return Number(sample.inBps);
    case 'if_out_bps':
      return Number(sample.outBps);
    case 'if_in_util_pct':
      return speed > 0 ? (Number(sample.inBps) * 100) / speed : null;
    case 'if_out_util_pct':
      return speed > 0 ? (Number(sample.outBps) * 100) / speed : null;
    case 'if_in_errs':
      return sample.inErrs;
    case 'if_out_errs':
      return sample.outErrs;
    case 'if_in_discards':
      return sample.inDiscards;
    case 'if_out_discards':
      return sample.outDiscards;
    case 'if_oper_status':
      return sample.operStatus;
    default:
      return null;
  }
}

function deviceMetric(metric: ThresholdMetric, sample: DeviceSampleRow): number | null {
  switch (metric) {
    case 'dev_cpu_pct':
      // A sentinel is NOT a value. Comparing -1 against "cpu > 80" is
      // harmless; comparing it against "cpu < 5" would fire on every device
      // that does not expose a CPU gauge at all.
      return sample.cpuPct === SENTINEL.NOT_AVAILABLE ? null : sample.cpuPct;
    case 'dev_mem_pct': {
      const used = Number(sample.memUsedBytes);
      const total = Number(sample.memTotalBytes);
      if (used === SENTINEL.NOT_AVAILABLE || total === SENTINEL.NOT_AVAILABLE || total <= 0) {
        return null;
      }
      return (used * 100) / total;
    }
    case 'dev_temp_dc':
      return sample.tempDc === SENTINEL.TEMP_NOT_AVAILABLE ? null : sample.tempDc;
    case 'dev_rtt_us':
      return sample.rttUs === SENTINEL.NOT_AVAILABLE ? null : sample.rttUs;
    case 'dev_reachable':
      return sample.reachable ? 1 : 0;
    default:
      return null;
  }
}

function compare(value: number, bound: number, comparator: ThresholdComparator): boolean {
  switch (comparator) {
    case 'gt':
      return value > bound;
    case 'gte':
      return value >= bound;
    case 'lt':
      return value < bound;
    case 'lte':
      return value <= bound;
    default:
      return false;
  }
}

// ============================================================================
// Which thresholds apply to this device
// ============================================================================

/**
 * Group scope walks the CLOSURE, not `devices.group_id`.
 *
 * A threshold set on "France" must cover a device filed under
 * "France / South / Toulouse". Matching only the direct group would make every
 * threshold above the leaf silently inert -- and an alert rule that exists,
 * looks configured and never fires is worse than no rule at all.
 */
export async function thresholdsForDevice(
  tenantId: number,
  deviceId: number,
  ifIds: number[],
): Promise<ThresholdRow[]> {
  return db<ThresholdRow>('snmp_thresholds')
    .where('snmp_thresholds.enabled', true)
    .where('snmp_thresholds.tenant_id', tenantId)
    .where((qb) => {
      qb.whereIn('snmp_thresholds.scope', ['global', 'tenant'])
        .orWhere((q) => q.where('snmp_thresholds.scope', 'device').where('snmp_thresholds.device_id', deviceId))
        .orWhere((q) =>
          q.where('snmp_thresholds.scope', 'group').whereIn(
            'snmp_thresholds.group_id',
            db('group_closure')
              .select('ancestor_id')
              .whereIn(
                'descendant_id',
                db('devices').select('group_id').where('id', deviceId).whereNotNull('group_id'),
              ),
          ),
        );
      if (ifIds.length > 0) {
        qb.orWhere((q) =>
          q.where('snmp_thresholds.scope', 'interface').whereIn('snmp_thresholds.if_id', ifIds),
        );
      }
    });
}

// ============================================================================
// The state machine
// ============================================================================

interface Transition {
  thresholdId: number;
  entityKind: AlertEntityKind;
  entityId: number;
  from: ThresholdState;
  to: ThresholdState;
  value: number;
  entityLabel: string;
}

/**
 * Evaluate every applicable threshold against what this cycle measured.
 *
 * Returns the transitions, so a caller (and a test) can assert on them without
 * reading the database back.
 */
export async function evaluateDevice(input: EvaluationInput): Promise<Transition[]> {
  const byIfId = new Map(input.interfaces.map((i) => [i.id, i]));
  const ifIds = input.interfaces.map((i) => i.id);
  const thresholds = await thresholdsForDevice(input.tenantId, input.deviceId, ifIds);
  if (thresholds.length === 0) return [];

  const existing = await db<AlertStateRow>('snmp_alert_state').whereIn(
    'threshold_id',
    thresholds.map((t) => t.id),
  );
  const stateKey = (t: number, k: AlertEntityKind, e: number): string => `${t}|${k}|${e}`;
  const states = new Map(existing.map((s) => [stateKey(s.threshold_id, s.entity_kind, s.entity_id), s]));

  const transitions: Transition[] = [];
  const upserts: AlertStateRow[] = [];

  const evaluateOne = (
    threshold: ThresholdRow,
    entityKind: AlertEntityKind,
    entityId: number,
    entityLabel: string,
    value: number,
  ): void => {
    const key = stateKey(threshold.id, entityKind, entityId);
    const previous = states.get(key);
    const from: ThresholdState = previous?.state ?? 'ok';
    const bound = Number(threshold.value);
    const hysteresis = Number(threshold.hysteresis_pct);

    // While FIRING the bar to stay breached moves INTO the band: a `gt` rule
    // clears only below `value * (1 - h)`. Applying the shift in the wrong
    // direction makes an alert impossible to clear, which looks exactly like a
    // stuck alert and is diagnosed as one for weeks.
    const effectiveBound =
      from === 'firing' ? alertClearValue(bound, threshold.comparator, hysteresis) : bound;
    const breached = compare(value, effectiveBound, threshold.comparator);

    let to: ThresholdState = from;
    let breachStartedAt = previous?.breach_started_at ?? null;
    let since = previous?.since ?? input.at;

    if (breached) {
      if (from === 'ok') {
        to = 'pending';
        breachStartedAt = input.at;
        since = input.at;
      } else if (from === 'pending') {
        const heldMs = input.at.getTime() - (breachStartedAt ?? input.at).getTime();
        if (heldMs >= threshold.for_seconds * 1000) {
          to = 'firing';
          since = input.at;
        }
      }
      // `firing` stays firing. It is NOT re-notified: `notification_count`
      // increments only on the ok/pending -> firing edge.
    } else if (from !== 'ok') {
      to = 'ok';
      breachStartedAt = null;
      since = input.at;
    }

    upserts.push({
      threshold_id: threshold.id,
      entity_kind: entityKind,
      entity_id: entityId,
      device_id: input.deviceId,
      state: to,
      since,
      // The CHECK on the table is `state = 'ok' OR breach_started_at IS NOT
      // NULL`: a non-ok row without a breach start is refused by the database.
      breach_started_at: to === 'ok' ? null : (breachStartedAt ?? input.at),
      last_eval_at: input.at,
      last_value: String(value),
      notified_at: previous?.notified_at ?? null,
      notification_count: previous?.notification_count ?? 0,
    });

    if (to !== from) {
      transitions.push({
        thresholdId: threshold.id,
        entityKind,
        entityId,
        from,
        to,
        value,
        entityLabel,
      });
    }
  };

  for (const threshold of thresholds) {
    if (INTERFACE_METRICS.has(threshold.metric)) {
      for (const sample of input.samples) {
        const iface = byIfId.get(sample.ifId);
        if (!iface) continue;
        // An interface-scoped threshold only looks at its own interface.
        if (threshold.scope === 'interface' && threshold.if_id !== sample.ifId) continue;
        const value = interfaceMetric(threshold.metric, sample, iface);
        if (value === null) continue;
        evaluateOne(threshold, 'interface', sample.ifId, `${input.deviceName} / ${iface.if_name}`, value);
      }
    } else {
      if (threshold.scope === 'interface') continue;
      const value = deviceMetric(threshold.metric, input.deviceSample);
      if (value === null) continue;
      evaluateOne(threshold, 'device', input.deviceId, input.deviceName, value);
    }
  }

  if (upserts.length > 0) await persistStates(upserts);

  for (const transition of transitions) {
    if (transition.to === 'firing' || (transition.from === 'firing' && transition.to === 'ok')) {
      const threshold = thresholds.find((t) => t.id === transition.thresholdId);
      if (threshold) await notify(threshold, transition, input);
    }
  }

  return transitions;
}

async function persistStates(rows: AlertStateRow[]): Promise<void> {
  await db.raw(
    `INSERT INTO snmp_alert_state
       (threshold_id, entity_kind, entity_id, device_id, state, since,
        breach_started_at, last_eval_at, last_value, notified_at, notification_count)
     SELECT * FROM unnest(
       ?::int[], ?::text[], ?::int[], ?::int[], ?::text[], ?::timestamptz[],
       ?::timestamptz[], ?::timestamptz[], ?::numeric[], ?::timestamptz[], ?::int[])
     ON CONFLICT (threshold_id, entity_kind, entity_id) DO UPDATE SET
       state             = EXCLUDED.state,
       since             = EXCLUDED.since,
       breach_started_at = EXCLUDED.breach_started_at,
       last_eval_at      = EXCLUDED.last_eval_at,
       last_value        = EXCLUDED.last_value,
       device_id         = EXCLUDED.device_id`,
    bindings([
      rows.map((r) => r.threshold_id),
      rows.map((r) => r.entity_kind),
      rows.map((r) => r.entity_id),
      rows.map((r) => r.device_id),
      rows.map((r) => r.state),
      rows.map((r) => r.since.toISOString()),
      rows.map((r) => (r.breach_started_at ? r.breach_started_at.toISOString() : null)),
      rows.map((r) => r.last_eval_at.toISOString()),
      rows.map((r) => r.last_value),
      rows.map((r) => (r.notified_at ? r.notified_at.toISOString() : null)),
      rows.map((r) => r.notification_count),
    ]),
  );
}

// ============================================================================
// Notification
// ============================================================================

/**
 * One notification per EDGE, never per cycle.
 *
 * `notification_count` is bumped and `notified_at` stamped only here, on the
 * `-> firing` and `firing -> ok` edges. A firing alert that stays firing sends
 * nothing: re-notifying every 30 s is how an alerting system trains its
 * audience to filter it out, and after that a real outage is invisible.
 */
async function notify(
  threshold: ThresholdRow,
  transition: Transition,
  input: EvaluationInput,
): Promise<void> {
  const firing = transition.to === 'firing';
  const readable =
    threshold.metric === 'if_oper_status'
      ? ifOperStatusName(transition.value)
      : formatValue(transition.value);

  const payload = {
    entityName: transition.entityLabel,
    oldStatus: transition.from,
    newStatus: transition.to,
    timestamp: input.at.toISOString(),
    appName: config.appName,
    message: firing
      ? `${threshold.name}: ${threshold.metric} ${threshold.comparator} ${threshold.value} ` +
        `(observed ${readable}) held for ${threshold.for_seconds}s [${threshold.severity}]`
      : `${threshold.name}: cleared (observed ${readable})`,
  };

  try {
    if (threshold.channel_id !== null) {
      await sendToChannel(threshold.channel_id, threshold.tenant_id, payload);
    } else {
      // No explicit channel: the device's own global/group/device binding
      // chain decides, tenant-scoped throughout.
      await notificationService.sendForDevice(
        threshold.tenant_id,
        input.deviceId,
        input.groupId,
        payload,
      );
    }
    await db('snmp_alert_state')
      .where({
        threshold_id: transition.thresholdId,
        entity_kind: transition.entityKind,
        entity_id: transition.entityId,
      })
      .update({
        notified_at: input.at,
        notification_count: db.raw('notification_count + 1'),
      });
  } catch (err) {
    logger.error(
      { err, thresholdId: threshold.id, entityId: transition.entityId },
      'Threshold notification failed (the state transition is recorded)',
    );
  }
}

/**
 * Send to ONE channel, honouring the tenant visibility rule.
 *
 * `_channelRowById` applies "own tenant, or explicitly shared to it" -- the
 * same rule as the list endpoint. A threshold cannot be pointed at another
 * customer's Discord webhook by writing its id into `channel_id`.
 */
async function sendToChannel(
  channelId: number,
  tenantId: number,
  payload: Parameters<typeof notificationService.sendForDevice>[3],
): Promise<void> {
  const row = await notificationService._channelRowById(channelId, tenantId);
  if (!row || !row.is_enabled) {
    logger.warn({ channelId, tenantId }, 'Threshold channel not usable by this tenant — skipped');
    return;
  }
  const plugin = getPlugin(row.type);
  if (!plugin) {
    logger.warn({ channelId, type: row.type }, 'No notification plugin for this channel type');
    return;
  }
  const channel = {
    id: row.id,
    name: row.name,
    type: row.type,
    config: typeof row.config === 'string' ? JSON.parse(row.config) : row.config,
    isEnabled: row.is_enabled,
    createdBy: row.created_by,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
  const resolved = await notificationService.resolveChannelConfig(channel, row.tenant_id);
  await plugin.send(resolved, payload);
}

function formatValue(value: number): string {
  if (!Number.isFinite(value)) return String(value);
  return Math.abs(value) >= 1000 ? Math.round(value).toLocaleString('en-US') : value.toFixed(2);
}

// ============================================================================
// Startup sweep
// ============================================================================

/**
 * What to do with alert state that nobody has re-evaluated for a long time --
 * the case after a restart or a three-day outage (study section 2.7). This is
 * the reason `snmp_alert_state` carries `INDEX(state, last_eval_at)`.
 *
 * ARBITRAGE, STATED SO IT IS NOT SILENTLY REVERSED:
 *
 *   `pending` -> `ok`, silently. A dwell timer that stopped being fed proves
 *   nothing. Keeping it would let a threshold fire minutes after the poller
 *   came back, on the strength of a breach that started before the outage.
 *
 *   `firing` STAYS `firing`, and is only logged. It is tempting to clear it,
 *   and it would be wrong: we do not know that the condition ended, we only
 *   know we stopped looking. Inventing a resolution from an absence of data is
 *   the same error as reading a hole as a zero. The next real evaluation
 *   clears it through the normal hysteresis path, within one poll interval.
 */
export async function sweepStaleAlerts(maxAgeSec: number): Promise<{ cleared: number; stale: number }> {
  const cutoff = new Date(Date.now() - maxAgeSec * 1000);

  const cleared = await db('snmp_alert_state')
    .where('state', 'pending')
    .where('last_eval_at', '<', cutoff)
    .update({ state: 'ok', breach_started_at: null, since: new Date() });

  const stale = await db('snmp_alert_state')
    .where('state', 'firing')
    .where('last_eval_at', '<', cutoff)
    .count<{ count: string }[]>('* as count');
  const staleCount = Number(stale[0]?.count ?? 0);

  if (cleared > 0 || staleCount > 0) {
    logger.info(
      { clearedPending: cleared, staleFiring: staleCount, olderThanSec: maxAgeSec },
      'Alert state sweep: stale pending timers reset; firing alerts kept (we stopped looking, ' +
        'we did not observe a resolution)',
    );
  }
  return { cleared, stale: staleCount };
}

// ============================================================================
// CRUD, used by the controller
// ============================================================================

export interface ThresholdInput {
  name: string;
  enabled?: boolean;
  scope: ThresholdScope;
  deviceId?: number | null;
  groupId?: number | null;
  ifId?: number | null;
  metric: ThresholdMetric;
  comparator: ThresholdComparator;
  value: number;
  forSeconds: number;
  hysteresisPct: number;
  severity: ThresholdSeverity;
  channelId?: number | null;
}

export async function listThresholds(tenantId: number): Promise<ThresholdRow[]> {
  return db<ThresholdRow>('snmp_thresholds').where({ tenant_id: tenantId }).orderBy('name');
}

export async function getThreshold(tenantId: number, id: number): Promise<ThresholdRow | null> {
  const row = await db<ThresholdRow>('snmp_thresholds').where({ id, tenant_id: tenantId }).first();
  return row ?? null;
}

function toColumns(input: ThresholdInput, tenantId: number): Record<string, unknown> {
  return {
    tenant_id: tenantId,
    name: input.name,
    enabled: input.enabled ?? true,
    scope: input.scope,
    device_id: input.scope === 'device' ? (input.deviceId ?? null) : null,
    group_id: input.scope === 'group' ? (input.groupId ?? null) : null,
    if_id: input.scope === 'interface' ? (input.ifId ?? null) : null,
    metric: input.metric,
    comparator: input.comparator,
    value: input.value,
    for_seconds: input.forSeconds,
    hysteresis_pct: input.hysteresisPct,
    severity: input.severity,
    channel_id: input.channelId ?? null,
  };
}

export async function createThreshold(tenantId: number, input: ThresholdInput): Promise<ThresholdRow> {
  const [row] = await db<ThresholdRow>('snmp_thresholds')
    .insert(toColumns(input, tenantId))
    .returning('*');
  return row;
}

export async function updateThreshold(
  tenantId: number,
  id: number,
  input: ThresholdInput,
): Promise<ThresholdRow | null> {
  const [row] = await db('snmp_thresholds')
    .where({ id, tenant_id: tenantId })
    .update({ ...toColumns(input, tenantId), updated_at: new Date() })
    .returning('*');
  return (row as ThresholdRow) ?? null;
}

export async function deleteThreshold(tenantId: number, id: number): Promise<boolean> {
  const count = await db('snmp_thresholds').where({ id, tenant_id: tenantId }).del();
  return count > 0;
}

/** Current alert state, tenant-scoped through the threshold. */
export async function listAlertStates(
  tenantId: number,
  filters: { deviceId?: number; state?: ThresholdState } = {},
): Promise<Array<AlertStateRow & { threshold_name: string; severity: ThresholdSeverity; metric: ThresholdMetric }>> {
  const q = db('snmp_alert_state')
    .join('snmp_thresholds', 'snmp_thresholds.id', 'snmp_alert_state.threshold_id')
    .where('snmp_thresholds.tenant_id', tenantId)
    .select(
      'snmp_alert_state.*',
      'snmp_thresholds.name as threshold_name',
      'snmp_thresholds.severity',
      'snmp_thresholds.metric',
    )
    .orderBy('snmp_alert_state.since', 'desc');
  if (filters.deviceId) q.where('snmp_alert_state.device_id', filters.deviceId);
  if (filters.state) q.where('snmp_alert_state.state', filters.state);
  return q;
}

/** Exported for the bench: `if_oper_status` is compared numerically. */
export const OPER_STATUS_UP = IF_OPER_STATUS.up;
