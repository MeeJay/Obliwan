/**
 * Wire-shape reconciliation for the M3 telemetry routes.
 *
 * The server services for M3 (`server/src/services/snmp/*.service.ts`) were
 * written in parallel with these screens, and their READ paths hand back raw
 * knex rows: `snake_case` keys, and PostgreSQL `numeric` columns arriving as
 * STRINGS (`value`, `hysteresis_pct`, and every `numeric(20,0)` counter). The
 * WRITE paths already take camelCase.
 *
 * Rather than guess which shape the controller layer will settle on — it does
 * not exist yet — every reader below accepts BOTH and coerces. Three concrete
 * failures this prevents:
 *
 *  - `value: "80"` as a string sorts and compares as text: "9" > "80", and the
 *    hysteresis arithmetic silently concatenates instead of subtracting.
 *  - `speed_bps: 0` is the IF-MIB "unknown" sentinel, NOT zero capacity
 *    (`shared/src/telemetry.ts`, `PollState.lineSpeedBps`). Rendered literally
 *    it prints "0 bit/s" and turns every utilisation into a divide-by-zero or,
 *    worse, a confident 0 %.
 *  - a `state` column typed `string` server-side has to be narrowed before it
 *    can drive a union-typed render path.
 *
 * When the lead consolidates and the controller settles on one shape, this
 * file shrinks to nothing — but until then it is what keeps the pages working
 * against either.
 */

import { IF_OPER_STATUS, type IfOperStatusCode, type InterfaceState } from '@obliwan/shared';
import type {
  AlertStateRow,
  IfSeriesPoint,
  IfSeriesResponse,
  NetInterface,
  SeriesGranularity,
  Threshold,
} from '@/types/telemetry';

type Raw = Record<string, unknown>;

/** camelCase key, or its snake_case twin, whichever the server sent. */
function pick(row: Raw, camel: string): unknown {
  if (camel in row) return row[camel];
  const snake = camel.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
  return row[snake];
}

/** PostgreSQL `numeric` arrives as a string. `null`/`undefined`/'' stay null. */
export function num(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? n : null;
}

function numOr(v: unknown, fallback: number): number {
  return num(v) ?? fallback;
}

function str(v: unknown): string | null {
  return v === null || v === undefined ? null : String(v);
}

function bool(v: unknown, fallback = false): boolean {
  if (v === null || v === undefined) return fallback;
  if (typeof v === 'boolean') return v;
  return v === 'true' || v === 't' || v === 1 || v === '1';
}

/**
 * IF-MIB line speed. **0 means UNKNOWN, not zero.**
 *
 * This single mapping is what stops the saturation column from claiming that a
 * PPP link or a tunnel — where `ifHighSpeed` is genuinely 0 — is running at
 * 0 % of capacity, i.e. perfectly idle, i.e. nothing to look at.
 */
export function normalizeSpeed(v: unknown): number | null {
  const n = num(v);
  return n === null || n <= 0 ? null : n;
}

/**
 * IF-MIB ifOperStatus, narrowed to 1..7.
 *
 * Anything outside that range is a decode bug on the agent's side, and it
 * resolves to `unknown` (4) — NEVER to `up` (1). A garbled status must not be
 * able to paint a dead port green.
 */
function operCode(v: unknown): IfOperStatusCode | null {
  const n = num(v);
  if (n === null) return null;
  return (n >= 1 && n <= 7 ? n : IF_OPER_STATUS.unknown) as IfOperStatusCode;
}

// ── Interfaces ──────────────────────────────────────────────────────────────

export function normalizeInterface(raw: Raw): NetInterface {
  const state = str(pick(raw, 'state'));
  const sample = (pick(raw, 'lastSample') ?? null) as Raw | null;

  return {
    id: numOr(pick(raw, 'id'), 0),
    deviceId: numOr(pick(raw, 'deviceId'), 0),
    deviceName: str(pick(raw, 'deviceName')),
    siteId: num(pick(raw, 'siteId')),
    siteName: str(pick(raw, 'siteName')),
    ifName: str(pick(raw, 'ifName')) ?? '',
    ifAlias: str(pick(raw, 'ifAlias')),
    ifDescr: str(pick(raw, 'ifDescr')),
    ifIndex: num(pick(raw, 'ifIndex')),
    // Anything the server invents narrows to `vanished` only on an exact
    // match; an unrecognised lifecycle must not silently read as live.
    state: (state === 'vanished' ? 'vanished' : 'active') as InterfaceState,
    vanishedAt: str(pick(raw, 'vanishedAt')),
    adminStatus: num(pick(raw, 'adminStatus')),
    operStatus: operCode(pick(raw, 'operStatus')),
    speedBps: normalizeSpeed(pick(raw, 'speedBps')),
    counterBits: numOr(pick(raw, 'counterBits'), 64) === 32 ? 32 : 64,
    counterUnreliable: bool(pick(raw, 'counterUnreliable')),
    needsRediscovery: bool(pick(raw, 'needsRediscovery')),
    effectivePollSec: numOr(pick(raw, 'effectivePollSec'), 30),
    ifType: num(pick(raw, 'ifType')),
    monitored: bool(pick(raw, 'monitored'), true),
    lastSeenAt: str(pick(raw, 'lastSeenAt')),
    lastDiscard: str(pick(raw, 'lastDiscard')),
    consecutiveDiscards: num(pick(raw, 'consecutiveDiscards')) ?? 0,
    lastSample: sample
      ? {
          ts: str(pick(sample, 'ts')) ?? '',
          inBps: numOr(pick(sample, 'inBps'), 0),
          outBps: numOr(pick(sample, 'outBps'), 0),
          inPps: numOr(pick(sample, 'inPps'), 0),
          outPps: numOr(pick(sample, 'outPps'), 0),
          inErrs: numOr(pick(sample, 'inErrs'), 0),
          outErrs: numOr(pick(sample, 'outErrs'), 0),
          inDiscards: numOr(pick(sample, 'inDiscards'), 0),
          outDiscards: numOr(pick(sample, 'outDiscards'), 0),
          elapsedMs: numOr(pick(sample, 'elapsedMs'), 0),
          operStatus: operCode(pick(sample, 'operStatus')) ?? IF_OPER_STATUS.unknown,
        }
      : null,
  };
}

// ── Series ──────────────────────────────────────────────────────────────────

const RESOLUTIONS: SeriesGranularity[] = ['raw', '1m', '5m', '1h'];

function normalizePoint(raw: Raw): IfSeriesPoint {
  return {
    ts: str(pick(raw, 'ts')) ?? str(pick(raw, 'bucket')) ?? '',
    // `num()` returning null for an absent value is exactly right here: the
    // hole must stay a hole all the way to the chart.
    inBps: num(pick(raw, 'inBps')),
    outBps: num(pick(raw, 'outBps')),
    inMaxBps: num(pick(raw, 'inMaxBps')),
    outMaxBps: num(pick(raw, 'outMaxBps')),
    inPps: num(pick(raw, 'inPps')),
    outPps: num(pick(raw, 'outPps')),
    inErrs: num(pick(raw, 'inErrs')),
    outErrs: num(pick(raw, 'outErrs')),
    inDiscards: num(pick(raw, 'inDiscards')),
    outDiscards: num(pick(raw, 'outDiscards')),
    operStatus: num(pick(raw, 'operStatus')),
    sampleCount: num(pick(raw, 'sampleCount')) ?? undefined,
    expectedCount: num(pick(raw, 'expectedCount')) ?? undefined,
  };
}

export function normalizeSeries(raw: Raw, fallbackBucketSec: number): IfSeriesResponse {
  // The server calls it `resolution`; an earlier draft of this client called
  // it `granularity`. Accept both, so neither side has to land first.
  const resRaw = str(pick(raw, 'resolution')) ?? str(pick(raw, 'granularity'));
  const resolution = (RESOLUTIONS as string[]).includes(resRaw ?? '')
    ? (resRaw as SeriesGranularity)
    : 'raw';
  const points = Array.isArray(pick(raw, 'points'))
    ? (pick(raw, 'points') as Raw[]).map(normalizePoint)
    : [];

  return {
    ifId: numOr(pick(raw, 'ifId'), 0),
    resolution,
    bucketSec: numOr(pick(raw, 'bucketSec'), fallbackBucketSec),
    from: str(pick(raw, 'from')) ?? '',
    to: str(pick(raw, 'to')) ?? '',
    points,
    gaps: num(pick(raw, 'gaps')) ?? 0,
    counterUnreliable: bool(pick(raw, 'counterUnreliable')),
    speedBps: normalizeSpeed(pick(raw, 'speedBps')),
  };
}

// ── Thresholds ──────────────────────────────────────────────────────────────

export function normalizeThreshold(raw: Raw): Threshold {
  return {
    id: numOr(pick(raw, 'id'), 0),
    uuid: str(pick(raw, 'uuid')) ?? '',
    tenantId: numOr(pick(raw, 'tenantId'), 0),
    name: str(pick(raw, 'name')) ?? '',
    enabled: bool(pick(raw, 'enabled'), true),
    scope: (str(pick(raw, 'scope')) ?? 'tenant') as Threshold['scope'],
    deviceId: num(pick(raw, 'deviceId')),
    deviceName: str(pick(raw, 'deviceName')),
    groupId: num(pick(raw, 'groupId')),
    groupName: str(pick(raw, 'groupName')),
    ifId: num(pick(raw, 'ifId')),
    ifName: str(pick(raw, 'ifName')),
    metric: (str(pick(raw, 'metric')) ?? 'if_in_util_pct') as Threshold['metric'],
    comparator: (str(pick(raw, 'comparator')) ?? 'gt') as Threshold['comparator'],
    // `numeric` -> string on the wire. Left as a string it would break every
    // comparison and turn the hysteresis arithmetic into concatenation.
    value: numOr(pick(raw, 'value'), 0),
    forSeconds: numOr(pick(raw, 'forSeconds'), 0),
    hysteresisPct: numOr(pick(raw, 'hysteresisPct'), 0),
    severity: (str(pick(raw, 'severity')) ?? 'warning') as Threshold['severity'],
    channelId: num(pick(raw, 'channelId')),
    firingCount: num(pick(raw, 'firingCount')) ?? undefined,
    pendingCount: num(pick(raw, 'pendingCount')) ?? undefined,
  };
}

export function normalizeAlertState(raw: Raw): AlertStateRow {
  return {
    thresholdId: numOr(pick(raw, 'thresholdId'), 0),
    thresholdName: str(pick(raw, 'thresholdName')),
    entityKind: (str(pick(raw, 'entityKind')) ?? 'interface') as AlertStateRow['entityKind'],
    entityId: numOr(pick(raw, 'entityId'), 0),
    entityLabel: str(pick(raw, 'entityLabel')),
    deviceId: numOr(pick(raw, 'deviceId'), 0),
    deviceName: str(pick(raw, 'deviceName')),
    state: (str(pick(raw, 'state')) ?? 'ok') as AlertStateRow['state'],
    since: str(pick(raw, 'since')) ?? '',
    breachStartedAt: str(pick(raw, 'breachStartedAt')),
    lastEvalAt: str(pick(raw, 'lastEvalAt')) ?? '',
    lastValue: num(pick(raw, 'lastValue')),
    notifiedAt: str(pick(raw, 'notifiedAt')),
    notificationCount: num(pick(raw, 'notificationCount')) ?? 0,
  };
}
