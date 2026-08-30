import apiClient from './client';
import type { ApiResponse, DeviceBrand, DeviceFamily } from '@obliwan/shared';
import { DEVICE_BRANDS, DEVICE_FAMILIES } from '@obliwan/shared';
import { isRouteAbsent, errorMessageOf } from './change.api';
import type {
  CwmpCpe,
  CwmpDataModel,
  CwmpFile,
  CwmpParameter,
  CwmpReachability,
  CwmpRpcDirection,
  CwmpRpcEntry,
  CwmpRpcLogView,
  CwmpTask,
  CwmpTaskCommand,
  CwmpTaskState,
  EnqueueTaskRequest,
} from '@/types/acs';
import {
  CWMP_DATA_MODELS,
  CWMP_REACHABILITIES,
  CWMP_RPC_DIRECTIONS,
  CWMP_TASK_COMMANDS,
  CWMP_TASK_STATES,
  isSecretParameterPath,
} from '@/types/acs';

/**
 * ACS / TR-069 (M10, feature C10).
 *
 * ── THE ROUTE PREFIX — CHECKED, NOT ASSUMED ─────────────────────────────────
 * `server/src/routes/index.ts` was READ while writing this file. It mounts
 * NOTHING under `/acs`: the M10 server work is not in this milestone's client
 * scope. So the EXACT paths this module calls are written down here, in the
 * shape the existing tenant-scoped routers use (`/sites`, `/devices`, `/snmp`,
 * `/config`, `/drift`, `/plan`, `/changes`, `/rollouts`, `/logs`, `/query`),
 * and every one of them degrades to a stated absence rather than to a blank
 * screen. In M3 the client forgot the `/snmp` prefix and in M4 the paths
 * diverged; the lead re-stitched both times.
 *
 *   GET    /api/acs/cpe?search&family&reachability&limit  -> CwmpCpe[]
 *   GET    /api/acs/cpe/:deviceId                          -> CwmpCpe
 *   GET    /api/acs/cpe/:deviceId/parameters?prefix&search&limit -> CwmpParameter[]
 *   GET    /api/acs/cpe/:deviceId/tasks?limit              -> CwmpTask[]
 *   POST   /api/acs/tasks                                  -> EnqueueTaskRequest -> CwmpTask
 *   POST   /api/acs/tasks/:id/cancel                       -> CwmpTask
 *   POST   /api/acs/cpe/:deviceId/connection-request       -> ConnectionRequestOutcome
 *   GET    /api/acs/cpe/:deviceId/rpc-log?limit            -> CwmpRpcLogView
 *   GET    /api/acs/firmware                               -> CwmpFile[]
 *   DELETE /api/acs/firmware/:id
 *
 * `POST /api/acs/tasks` and not `POST /api/acs/cpe/:id/tasks`: an SPV body
 * carries values that must not be reconstructible from an access log, and the
 * flatter route keeps the device id in the body with them rather than in a URL
 * every proxy on the path writes down.
 *
 * ── §8.2 IS THE WHOLE POINT OF THE NORMALISERS BELOW ────────────────────────
 * The last audit found the L2TP passwords of an entire fleet in a jsonb column
 * served to the UI. The TR-069 data model is the richest possible source of
 * exactly that mistake: `...WANPPPConnection.1.Password` is a first-class leaf
 * of the standard. So `parameterOf()` REDACTS on the way in — before the value
 * ever reaches a component — whenever the path looks like a secret, whatever
 * the server chose to send. Over-redaction shows up as a visible chip the
 * operator can report; under-redaction shows up in a screenshot in a ticket.
 *
 * The same rule kills the value echo in `taskOf()`: an enqueued
 * SetParameterValues is summarised by its PATHS and never by its values.
 */

type Raw = Record<string, unknown>;

function pick(row: Raw, camel: string): unknown {
  if (camel in row) return row[camel];
  const snake = camel.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
  return row[snake];
}

function n(v: unknown, fallback: number): number {
  if (v === null || v === undefined || v === '') return fallback;
  const x = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(x) ? x : fallback;
}

function nOrNull(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const x = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(x) ? x : null;
}

function s(v: unknown): string | null {
  return v === null || v === undefined || v === '' ? null : String(v);
}

function bool(v: unknown, fallback = false): boolean {
  if (v === null || v === undefined) return fallback;
  if (typeof v === 'boolean') return v;
  return v === 'true' || v === 't' || v === 1 || v === '1';
}

/** Tri-state: `null` really means "not stated", never "false". */
function boolOrNull(v: unknown): boolean | null {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v === 'boolean') return v;
  if (v === 'true' || v === 't' || v === 1 || v === '1') return true;
  if (v === 'false' || v === 'f' || v === 0 || v === '0') return false;
  return null;
}

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  if (payload && typeof payload === 'object') {
    const p = payload as Raw;
    const items = p.items ?? p.rows ?? p.cpe ?? p.cpes ?? p.devices ?? p.tasks
      ?? p.parameters ?? p.entries ?? p.files ?? p.firmware;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

function strList(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => String(x)).filter((x) => x.length > 0);
  if (typeof v === 'string' && v.length > 0) return v.split(',').map((x) => x.trim()).filter(Boolean);
  if (v && typeof v === 'object') return Object.keys(v as Raw);
  return [];
}

function brandOf(v: unknown): DeviceBrand | null {
  const raw = s(v);
  return raw && (DEVICE_BRANDS as readonly string[]).includes(raw) ? (raw as DeviceBrand) : null;
}

function familyOf(v: unknown): DeviceFamily | null {
  const raw = s(v);
  return raw && (DEVICE_FAMILIES as readonly string[]).includes(raw) ? (raw as DeviceFamily) : null;
}

function familyList(v: unknown): DeviceFamily[] {
  return strList(v).filter((x): x is DeviceFamily => (DEVICE_FAMILIES as readonly string[]).includes(x));
}

// ── Normalisers ─────────────────────────────────────────────────────────────

/**
 * An unrecognised reachability degrades to `unknown`, never to `online`.
 * "We do not know whether this CPE is talking to us" is a fact an operator can
 * act on; a green dot he cannot trust is worse than no dot.
 */
function reachabilityOf(v: unknown): CwmpReachability {
  const raw = (s(v) ?? '').toLowerCase();
  return (CWMP_REACHABILITIES as readonly string[]).includes(raw)
    ? (raw as CwmpReachability)
    : 'unknown';
}

function dataModelOf(v: unknown): CwmpDataModel | null {
  const raw = (s(v) ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
  return (CWMP_DATA_MODELS as readonly string[]).includes(raw) ? (raw as CwmpDataModel) : null;
}

export function normalizeCpe(raw: Raw): CwmpCpe {
  return {
    deviceId: n(pick(raw, 'deviceId') ?? pick(raw, 'id'), 0),
    deviceName: s(pick(raw, 'deviceName') ?? pick(raw, 'name')),
    siteId: nOrNull(pick(raw, 'siteId')),
    siteName: s(pick(raw, 'siteName')),
    brand: brandOf(pick(raw, 'brand')),
    family: familyOf(pick(raw, 'family')),
    model: s(pick(raw, 'model')),
    cwmpId: String(pick(raw, 'cwmpId') ?? pick(raw, 'cwmp_id') ?? ''),
    dataModel: dataModelOf(pick(raw, 'dataModel')),
    rootPrefix: s(pick(raw, 'rootPrefix')),
    cwmpVersion: s(pick(raw, 'cwmpVersion')),
    softwareVersion: s(pick(raw, 'softwareVersion') ?? pick(raw, 'osVersion')),
    periodicInformInterval: nOrNull(pick(raw, 'periodicInformInterval')),
    lastInformAt: s(pick(raw, 'lastInformAt')),
    lastInformEvent: s(pick(raw, 'lastInformEvent')),
    reachability: reachabilityOf(pick(raw, 'reachability')),
    // A Connection Request URL that is present but empty is NOT a usable one.
    hasConnectionRequest:
      bool(pick(raw, 'hasConnectionRequest'))
      || (s(pick(raw, 'connectionRequestUrl')) !== null),
    connectionRequestOk: boolOrNull(pick(raw, 'connectionRequestOk')),
    lastConnectionRequestAt: s(pick(raw, 'lastConnectionRequestAt')),
    queuedTasks: n(pick(raw, 'queuedTasks'), 0),
    parameterCount: n(pick(raw, 'parameterCount'), 0),
    vendorQuirks: strList(pick(raw, 'vendorQuirks')),
  };
}

/**
 * §8.2 enforcement point. A parameter whose PATH looks like a secret is
 * redacted here, on the way in, whether or not the server flagged it — the
 * component layer never sees the string at all.
 */
export function normalizeParameter(raw: Raw): CwmpParameter {
  const path = String(pick(raw, 'path') ?? pick(raw, 'name') ?? '');
  const serverRedacted = bool(pick(raw, 'redacted'));
  const secretPath = isSecretParameterPath(path);
  const rawValue = pick(raw, 'value');
  return {
    path,
    value: serverRedacted || secretPath ? null : s(rawValue),
    valueType: s(pick(raw, 'valueType') ?? pick(raw, 'type')),
    writable: bool(pick(raw, 'writable')),
    notification: nOrNull(pick(raw, 'notification')),
    redacted: serverRedacted || secretPath,
    updatedAt: s(pick(raw, 'updatedAt')),
  };
}

function taskCommandOf(v: unknown): CwmpTaskCommand {
  const raw = s(v) ?? '';
  const hit = CWMP_TASK_COMMANDS.find((c) => c.toLowerCase() === raw.toLowerCase());
  // An unknown RPC name is shown verbatim rather than mapped onto a known one:
  // rendering an unrecognised command as `Reboot` would be catastrophic.
  return hit ?? (raw as CwmpTaskCommand);
}

/**
 * An unknown task state degrades to `queued` — the state that claims the LEAST.
 * Reading an unrecognised value as `done` would tell an operator a firmware
 * push landed when nobody knows whether it did.
 */
function taskStateOf(v: unknown): CwmpTaskState {
  const raw = (s(v) ?? '').toLowerCase();
  return (CWMP_TASK_STATES as readonly string[]).includes(raw) ? (raw as CwmpTaskState) : 'queued';
}

export function normalizeTask(raw: Raw): CwmpTask {
  // The summary must describe the payload without reproducing it. If the
  // server sent a `values` map anyway, we derive the summary from its KEYS.
  const explicit = s(pick(raw, 'summary'));
  const paths = strList(pick(raw, 'paths'));
  const values = pick(raw, 'values');
  const derived = paths.length > 0
    ? paths.join(', ')
    : values && typeof values === 'object'
      ? Object.keys(values as Raw).join(', ')
      : null;
  return {
    id: n(pick(raw, 'id'), 0),
    deviceId: n(pick(raw, 'deviceId'), 0),
    deviceName: s(pick(raw, 'deviceName')),
    command: taskCommandOf(pick(raw, 'command') ?? pick(raw, 'rpc')),
    commandKey: String(pick(raw, 'commandKey') ?? pick(raw, 'command_key') ?? ''),
    state: taskStateOf(pick(raw, 'state') ?? pick(raw, 'status')),
    attempts: n(pick(raw, 'attempts'), 0),
    summary: explicit ?? derived,
    faultCode: s(pick(raw, 'faultCode')),
    faultString: s(pick(raw, 'faultString')),
    createdAt: String(pick(raw, 'createdAt') ?? ''),
    sentAt: s(pick(raw, 'sentAt')),
    completedAt: s(pick(raw, 'completedAt')),
    expiresAt: s(pick(raw, 'expiresAt')),
    createdByName: s(pick(raw, 'createdByName')),
  };
}

function directionOf(v: unknown): CwmpRpcDirection {
  const raw = (s(v) ?? '').toLowerCase();
  if ((CWMP_RPC_DIRECTIONS as readonly string[]).includes(raw)) return raw as CwmpRpcDirection;
  // `inbound` / `outbound` / `in` / `out` all appear in CWMP tooling.
  if (raw.startsWith('in') || raw === 'cpe' || raw === 'request') return 'cpe_to_acs';
  return 'acs_to_cpe';
}

export function normalizeRpcEntry(raw: Raw): CwmpRpcEntry {
  return {
    id: String(pick(raw, 'id') ?? `${pick(raw, 'at')}-${pick(raw, 'rpc')}`),
    deviceId: n(pick(raw, 'deviceId'), 0),
    sessionId: s(pick(raw, 'sessionId')),
    at: String(pick(raw, 'at') ?? pick(raw, 'createdAt') ?? ''),
    direction: directionOf(pick(raw, 'direction')),
    rpc: String(pick(raw, 'rpc') ?? pick(raw, 'method') ?? '—'),
    httpStatus: nOrNull(pick(raw, 'httpStatus')),
    faultCode: s(pick(raw, 'faultCode')),
    bodyExcerpt: s(pick(raw, 'bodyExcerpt') ?? pick(raw, 'body')),
  };
}

export function normalizeFile(raw: Raw): CwmpFile {
  return {
    id: n(pick(raw, 'id'), 0),
    name: String(pick(raw, 'name') ?? pick(raw, 'filename') ?? ''),
    fileType: String(pick(raw, 'fileType') ?? '1 Firmware Upgrade Image'),
    version: s(pick(raw, 'version')),
    sizeBytes: nOrNull(pick(raw, 'sizeBytes') ?? pick(raw, 'size')),
    sha256: s(pick(raw, 'sha256')),
    families: familyList(pick(raw, 'families')),
    uploadedAt: String(pick(raw, 'uploadedAt') ?? pick(raw, 'createdAt') ?? ''),
    uploadedByName: s(pick(raw, 'uploadedByName')),
  };
}

/** Outcome of a Connection Request attempt — see the header of `types/acs.ts`
 *  for why this is never presented as "refreshed". */
export interface ConnectionRequestOutcome {
  /** The ACS reached the CPE's CR endpoint and it answered 200. */
  delivered: boolean;
  /** Why it did not, in the server's words. Redacted, shown verbatim. */
  reason: string | null;
  /** Always true when the request could not be delivered: the task stays in
   *  the queue and will run at the next Inform. */
  queued: boolean;
}

function outcomeOf(payload: unknown): ConnectionRequestOutcome {
  const row = (payload ?? {}) as Raw;
  const delivered = bool(pick(row, 'delivered'));
  return {
    delivered,
    reason: s(pick(row, 'reason') ?? pick(row, 'error')),
    // Fail-safe default: if the server did not say, assume the work is still
    // pending rather than telling the operator it was dropped.
    queued: boolOrNull(pick(row, 'queued')) ?? true,
  };
}

// ── The client ──────────────────────────────────────────────────────────────

export const acsApi = {
  /** `null` = this build does not serve the ACS API. Not "no CPE". */
  async listCpe(params: {
    search?: string;
    family?: DeviceFamily | '';
    reachability?: CwmpReachability | '';
    limit?: number;
  } = {}): Promise<CwmpCpe[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/acs/cpe', {
        params: {
          search: params.search || undefined,
          family: params.family || undefined,
          reachability: params.reachability || undefined,
          limit: params.limit ?? 200,
        },
      });
      return asRows(res.data.data).map(normalizeCpe);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async getCpe(deviceId: number): Promise<CwmpCpe | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/acs/cpe/${deviceId}`);
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      return normalizeCpe(payload as Raw);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async listParameters(
    deviceId: number,
    opts: { prefix?: string; search?: string; limit?: number } = {},
  ): Promise<CwmpParameter[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/acs/cpe/${deviceId}/parameters`, {
        params: {
          prefix: opts.prefix || undefined,
          search: opts.search || undefined,
          limit: opts.limit ?? 2000,
        },
      });
      return asRows(res.data.data).map(normalizeParameter);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async listTasks(deviceId: number, limit = 100): Promise<CwmpTask[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/acs/cpe/${deviceId}/tasks`, {
        params: { limit },
      });
      return asRows(res.data.data).map(normalizeTask);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * Enqueue an RPC. It does NOT run now — it runs when the CPE next opens a
   * session. Every caller of this is responsible for saying so on screen.
   */
  async enqueue(req: EnqueueTaskRequest): Promise<CwmpTask | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>('/acs/tasks', req);
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      return normalizeTask(payload as Raw);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async cancelTask(id: number): Promise<boolean> {
    try {
      await apiClient.post<ApiResponse<unknown>>(`/acs/tasks/${id}/cancel`, {});
      return true;
    } catch (err) {
      if (isRouteAbsent(err)) return false;
      throw err;
    }
  },

  /**
   * Ask the ACS to poke the CPE's Connection Request URL.
   *
   * The return value is the honest one: `delivered` says whether the poke
   * actually landed. It is never rendered as "refreshed" — the CPE still has to
   * open a session and run the queue, and behind a carrier NAT the poke simply
   * does not arrive. `null` = no ACS API in this build.
   */
  async connectionRequest(deviceId: number): Promise<ConnectionRequestOutcome | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>(
        `/acs/cpe/${deviceId}/connection-request`, {},
      );
      return outcomeOf(res.data.data);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      // A refused or failed poke is an ANSWER, not an outage: the task is still
      // queued and the next Inform will pick it up.
      return { delivered: false, reason: errorMessageOf(err), queued: true };
    }
  },

  /**
   * The RPC log. `enabled:false` is a first-class answer — §3.6 disables
   * capture by default, and an empty list means two opposite things depending
   * on that flag.
   */
  async rpcLog(deviceId: number, limit = 200): Promise<CwmpRpcLogView | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/acs/cpe/${deviceId}/rpc-log`, {
        params: { limit },
      });
      const payload = res.data.data;
      const row = (payload ?? {}) as Raw;
      return {
        // Absent flag = capture is OFF. §3.6 says disabled by default, and
        // guessing "on" would make an empty log look like a dead CPE.
        enabled: bool(pick(row, 'enabled'), false),
        retentionDays: nOrNull(pick(row, 'retentionDays')),
        entries: asRows(pick(row, 'entries') ?? payload).map(normalizeRpcEntry),
      };
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async listFirmware(): Promise<CwmpFile[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/acs/firmware');
      return asRows(res.data.data).map(normalizeFile);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async removeFirmware(id: number): Promise<boolean> {
    try {
      await apiClient.delete<ApiResponse<unknown>>(`/acs/firmware/${id}`);
      return true;
    } catch (err) {
      if (isRouteAbsent(err)) return false;
      throw err;
    }
  },

};
