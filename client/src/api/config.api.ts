import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';
import type {
  ConfigSnapshotDetail,
  ConfigSnapshotSummary,
  SnapshotRawText,
} from '@/types/config';

/**
 * Configuration snapshots (M4).
 *
 * ── THE ROUTE PREFIX, AND WHY IT IS WRITTEN DOWN HERE ───────────────────────
 * In M3 the client assumed the SNMP routes were mounted at the root and the
 * lead had to re-sew eight paths once the real mount turned out to be `/snmp`.
 * So this time the prefix was CHECKED rather than assumed: at the time of
 * writing `server/src/routes/index.ts` mounts `auth`, `sites`, `devices`,
 * `discoveries` and `snmp`, and carries NO config or drift router at all —
 * both server agents are writing them in parallel with this file.
 *
 * The paths below therefore follow the shape M3 established for a
 * tenant-scoped domain router (`tenantRouter.use('/snmp', snmpRoutes)` →
 * `/api/snmp/devices/:id/interfaces`), applied to `/config`:
 *
 *   GET  /api/config/snapshots?deviceId&siteId&limit
 *   GET  /api/config/devices/:deviceId/snapshots?limit
 *   GET  /api/config/snapshots/:id
 *   GET  /api/config/snapshots/:id/raw
 *
 * If the server agents mount them elsewhere, this file is the ONE place to
 * change, and the exact strings are repeated in the milestone report.
 *
 * ── ON THE `null` RETURNS ───────────────────────────────────────────────────
 * Convention inherited from M2/M3 and kept deliberately: `null` means "this
 * deployment does not serve the endpoint", which every screen renders as an
 * explicit "not available yet" panel. An empty array is a DIFFERENT answer —
 * "we asked, and this device has no snapshot" — and the two must never draw the
 * same way. A fleet that has never been collected and a build with no collector
 * look identical otherwise, and the operator has no way to tell which.
 *
 * A 404 is folded into `null` only on the COLLECTION routes. On
 * `/snapshots/:id` a 404 means "no such snapshot in your tenant", which is a
 * real answer the caller must see, and it is left to throw.
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
  return v === null || v === undefined ? null : String(v);
}

function bool(v: unknown, fallback = false): boolean {
  if (v === null || v === undefined) return fallback;
  if (typeof v === 'boolean') return v;
  return v === 'true' || v === 't' || v === 1 || v === '1';
}

function statusOf(err: unknown): number | undefined {
  return (err as { response?: { status?: number } }).response?.status;
}

/** Collection routes only — see the note above. */
function isRouteAbsent(err: unknown): boolean {
  const st = statusOf(err);
  return st === 404 || st === 501;
}

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  // Some list endpoints in this codebase answer `{ data: { items: [...] } }`.
  if (payload && typeof payload === 'object') {
    const items = (payload as Raw).items ?? (payload as Raw).rows ?? (payload as Raw).snapshots;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

/**
 * `order_analysis` and `source` are CHECK-constrained text server-side. A
 * string coming off knex is `string`, so it has to be narrowed before it can
 * drive a union-typed render path — and narrowed to the CLOSED value when it is
 * unrecognised, never to the optimistic one. An unknown order-analysis state
 * degrades to `'partial'` rather than `'full'`: claiming a complete order
 * analysis we did not verify is exactly the failure §4.3 guards against.
 */
function orderAnalysisOf(v: unknown): ConfigSnapshotSummary['orderAnalysis'] {
  return v === 'full' || v === 'partial' || v === 'skipped' ? v : 'partial';
}

const SOURCES: readonly string[] = [
  'routeros_api', 'ssh', 'rest', 'cwmp', 'pre_change', 'import',
];
function sourceOf(v: unknown): ConfigSnapshotSummary['source'] {
  const str = String(v ?? '');
  return (SOURCES.includes(str) ? str : 'import') as ConfigSnapshotSummary['source'];
}

export function normalizeSnapshot(raw: Raw): ConfigSnapshotSummary {
  return {
    id: n(pick(raw, 'id'), 0),
    uuid: String(pick(raw, 'uuid') ?? ''),
    deviceId: n(pick(raw, 'deviceId'), 0),
    deviceName: s(pick(raw, 'deviceName')),
    siteId: nOrNull(pick(raw, 'siteId')),
    siteName: s(pick(raw, 'siteName')),
    source: sourceOf(pick(raw, 'source')),
    ncmHash: String(pick(raw, 'ncmHash') ?? ''),
    ncmVersion: n(pick(raw, 'ncmVersion'), 1),
    semKeyGeneration: n(pick(raw, 'semKeyGeneration'), 1),
    normalizationEpoch: String(pick(raw, 'normalizationEpoch') ?? ''),
    orderAnalysis: orderAnalysisOf(pick(raw, 'orderAnalysis')),
    osVersion: s(pick(raw, 'osVersion')),
    model: s(pick(raw, 'model')),
    unmodeledForwardingCount: n(pick(raw, 'unmodeledForwardingCount'), 0),
    rawBytes: nOrNull(pick(raw, 'rawBytes')),
    rawSha256: s(pick(raw, 'rawSha256')),
    capturedAt: String(pick(raw, 'capturedAt') ?? ''),
    lastSeenAt: String(pick(raw, 'lastSeenAt') ?? pick(raw, 'capturedAt') ?? ''),
    seenCount: n(pick(raw, 'seenCount'), 1),
  };
}

function normalizeSnapshotDetail(raw: Raw): ConfigSnapshotDetail {
  const doc = pick(raw, 'ncm');
  return {
    ...normalizeSnapshot(raw),
    // NOT re-parsed through the Zod schema here. `NcmDocumentStored` is
    // `.passthrough()` precisely so a document written by a NEWER server
    // survives a read; running `.parse()` in the browser would add ~18 kB of
    // schema work to every snapshot open in exchange for rejecting documents
    // the renderer is already written to tolerate. The tree renders what it
    // recognises and shows the rest under `extensions`.
    ncm: doc && typeof doc === 'object'
      ? (doc as ConfigSnapshotDetail['ncm'])
      : null,
  };
}

export interface SnapshotListParams {
  deviceId?: number;
  siteId?: number;
  limit?: number;
}

function clean(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

export const configApi = {
  /** Fleet-wide snapshot list. `null` = endpoint not served by this build. */
  async listSnapshots(params: SnapshotListParams = {}): Promise<ConfigSnapshotSummary[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/config/snapshots', {
        params: clean(params as Record<string, unknown>),
      });
      return asRows(res.data.data).map(normalizeSnapshot);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** The snapshots of ONE device, newest first. `null` = route absent. */
  async forDevice(deviceId: number, limit = 50): Promise<ConfigSnapshotSummary[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(
        `/config/devices/${deviceId}/snapshots`,
        { params: { limit } },
      );
      return asRows(res.data.data).map(normalizeSnapshot);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * One snapshot WITH its NCM document.
   *
   * A 404 is NOT swallowed here: it means the snapshot does not exist in this
   * tenant, which the caller is entitled to see as an error rather than as an
   * unimplemented build.
   */
  async getSnapshot(id: number): Promise<ConfigSnapshotDetail | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/config/snapshots/${id}`);
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      return normalizeSnapshotDetail(payload as Raw);
    } catch (err) {
      if (statusOf(err) === 501) return null;
      throw err;
    }
  },

  /**
   * The REDACTED `/export` text behind `raw_gz`.
   *
   * `raw_gz` is nullable in migration 007, so "this snapshot has no archived
   * text" is a legitimate answer and comes back as `{ text: '' }`-shaped data
   * rather than an error. A 404 on this sub-route is folded into `null`
   * because a build may serve snapshots without serving the archive.
   */
  async getRaw(id: number): Promise<SnapshotRawText | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/config/snapshots/${id}/raw`);
      const payload = res.data.data;
      if (payload === null || payload === undefined) return null;
      if (typeof payload === 'string') {
        return { snapshotId: id, text: payload, sha256: null, redacted: true };
      }
      if (typeof payload !== 'object') return null;
      const row = payload as Raw;
      const text = pick(row, 'text') ?? pick(row, 'raw') ?? pick(row, 'content');
      return {
        snapshotId: id,
        text: typeof text === 'string' ? text : '',
        sha256: s(pick(row, 'sha256') ?? pick(row, 'rawSha256')),
        // Absent flag = assume redacted, because R10 makes it a server
        // guarantee — but the client scans the text either way and says so if
        // the scan trips.
        redacted: bool(pick(row, 'redacted'), true),
      };
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },
};
