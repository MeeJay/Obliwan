/**
 * ObliWAN — M8 HTTP surface: the unified journal, login events, K6 attribution
 * and the K7 verdict.
 *
 * ┌─ EVERY DEVICE-SCOPED HANDLER RESOLVES THE DEVICE THROUGH THE TENANT ─────┐
 * │ `syslog_messages`, `snmp_traps`, `device_login_events`,                   │
 * │ `drift_attributions` and `reachability_verdicts` carry NO tenant column.  │
 * │ The join on `devices` is the whole of the isolation, and a cross-tenant   │
 * │ id must read as 404 and not as 403 — a 403 confirms the row exists.       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ AND ONE ENDPOINT IS NOT TENANT-SCOPED, ON PURPOSE ──────────────────────┐
 * │ `GET /logs/unattributed` lists senders we could not tie to any device,    │
 * │ which means we cannot tie them to any tenant either. It is therefore      │
 * │ ADMIN-ONLY (`AUDIT_READ`, which no built-in permission set grants) and it │
 * │ returns no message bodies — only the address that is talking and the name │
 * │ it claims. That is what fixes the inventory gap; the text would only leak │
 * │ one customer's logs to another.                                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import {
  listLogs,
  unattributedSources,
  ingestHealth,
} from '../services/logs/logs.service';
import { listLoginEvents } from '../services/logs/loginEvents.service';
import { pullDeviceLog } from '../services/logs/routerosLog.service';
import {
  LOG_SOURCES,
  LOGIN_EVENT_KINDS,
  ATTRIBUTION_VERDICTS,
} from '../services/logs/contract';
import {
  attributeRun,
  getAttributionForRun,
  listAttributions,
} from '../services/drift/attribution.service';
import {
  assessDevice,
  enableExternalProbe,
  latestVerdict,
  probeDevice,
} from '../services/fleet/reachability.service';

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    const flat = result.error.flatten();
    const fields = Object.entries(flat.fieldErrors)
      .map(([f, m]) => `${f}: ${((m as string[] | undefined) ?? []).join(', ')}`)
      .concat(flat.formErrors)
      .filter((s) => s.length > 0)
      .join('; ');
    throw new AppError(400, fields ? `Validation failed — ${fields}` : 'Validation failed');
  }
  return result.data;
}

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

function parseBigId(raw: string, what = 'id'): string {
  if (!/^[0-9]{1,19}$/.test(raw)) throw new AppError(400, `Invalid ${what}`);
  return raw;
}

/** The single door onto a device from this controller. A device of another
 *  tenant is indistinguishable from a device that does not exist. */
async function requireDevice(tenantId: number, deviceId: number): Promise<{ id: number }> {
  const device = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{ id: number } | undefined>('id');
  if (!device) throw new AppError(404, 'Device not found');
  return device;
}

const logsQuery = z.object({
  deviceId: z.coerce.number().int().positive().optional(),
  maxSeverity: z.coerce.number().int().min(0).max(7).optional(),
  // Repeated `?source=syslog&source=trap` or a single comma-separated value.
  source: z.union([z.string(), z.array(z.string())]).optional(),
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  search: z.string().min(1).max(200).optional(),
  limit: z.coerce.number().int().min(1).max(500).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

const loginsQuery = z.object({
  deviceId: z.coerce.number().int().positive().optional(),
  account: z.string().min(1).max(128).optional(),
  event: z.enum(LOGIN_EVENT_KINDS).optional(),
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  limit: z.coerce.number().int().min(1).max(1000).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

const attributionsQuery = z.object({
  deviceId: z.coerce.number().int().positive().optional(),
  verdict: z.enum(ATTRIBUTION_VERDICTS).optional(),
  openOnly: z.enum(['true', 'false']).optional(),
  limit: z.coerce.number().int().min(1).max(500).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

const probeBody = z.object({
  targetIp: z.string().min(3).max(45).nullable().optional(),
  port: z.number().int().min(1).max(65535).optional(),
  intervalSec: z.number().int().min(10).max(86400).optional(),
});

const unattributedQuery = z.object({
  hours: z.coerce.number().int().min(1).max(168).optional(),
});

export const logsController = {
  /** GET /api/logs */
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(logsQuery, req.query);
      const raw = q.source === undefined ? [] : Array.isArray(q.source) ? q.source : [q.source];
      const requested = raw.flatMap((s) => s.split(','));
      const invalid = requested.filter((s) => !LOG_SOURCES.includes(s as never));
      if (invalid.length > 0) throw new AppError(400, `Unknown log source: ${invalid.join(', ')}`);

      if (q.deviceId) await requireDevice(req.tenantId, q.deviceId);

      res.json({
        success: true,
        data: await listLogs(req.tenantId, {
          deviceId: q.deviceId,
          maxSeverity: q.maxSeverity,
          sources: requested.length > 0 ? (requested as never) : undefined,
          from: q.from,
          to: q.to,
          search: q.search,
          limit: q.limit,
          offset: q.offset,
        }),
      });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/logs/health — ingestion counters and the queue gauge. */
  async health(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: ingestHealth() });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/logs/unattributed — ADMIN ONLY, and no message bodies. */
  async unattributed(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(unattributedQuery, req.query);
      res.json({ success: true, data: await unattributedSources(q.hours ?? 24) });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/logs/logins */
  async logins(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(loginsQuery, req.query);
      if (q.deviceId) await requireDevice(req.tenantId, q.deviceId);
      res.json({ success: true, data: await listLoginEvents(req.tenantId, q) });
    } catch (err) {
      next(err);
    }
  },

  /** POST /api/logs/devices/:deviceId/pull — read `/log` off this box now. */
  async pull(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await requireDevice(req.tenantId, deviceId);
      res.json({ success: true, data: await pullDeviceLog(deviceId) });
    } catch (err) {
      next(err);
    }
  },

  // ── K6 ───────────────────────────────────────────────────────────────────

  /** GET /api/logs/attributions */
  async attributions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(attributionsQuery, req.query);
      if (q.deviceId) await requireDevice(req.tenantId, q.deviceId);
      res.json({
        success: true,
        data: await listAttributions(req.tenantId, {
          deviceId: q.deviceId,
          verdict: q.verdict,
          openOnly: q.openOnly === 'true',
          limit: q.limit,
          offset: q.offset,
        }),
      });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/logs/attributions/runs/:runId */
  async attributionForRun(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const runId = parseBigId(req.params.runId, 'run id');
      const row = await getAttributionForRun(req.tenantId, runId);
      if (!row) throw new AppError(404, 'No attribution for this drift run');
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/logs/attributions/runs/:runId — recompute.
   *
   * Behind DRIFT_MANAGE and not DRIFT_READ: recomputing can CHANGE a verdict
   * that has already been read and acted on — an `unattributed` becoming an
   * `attributed` puts a name on a change after the fact. That is a decision,
   * and it must belong to someone entitled to make it.
   */
  async reattribute(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const runId = parseBigId(req.params.runId, 'run id');
      // Scope first: `attributeRun` is not tenant-aware by design (it is called
      // from a sweep that has no tenant), so the check has to happen here.
      const run = await db('drift_runs as dr')
        .join('devices as d', 'd.id', 'dr.device_id')
        .where('dr.id', runId)
        .andWhere('d.tenant_id', req.tenantId)
        .first<{ id: string } | undefined>('dr.id');
      if (!run) throw new AppError(404, 'Drift run not found');

      const result = await attributeRun(runId, { force: true });
      if (!result) {
        throw new AppError(
          409,
          'This run reports no drift, so there is no change to attribute',
        );
      }
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },

  // ── K7 ───────────────────────────────────────────────────────────────────

  /** GET /api/logs/reachability/devices/:deviceId — the last stored verdict. */
  async verdict(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await requireDevice(req.tenantId, deviceId);
      const row = await latestVerdict(deviceId);
      if (!row) throw new AppError(404, 'This device has never been assessed');
      res.json({ success: true, data: { deviceId, ...row } });
    } catch (err) {
      next(err);
    }
  },

  /** POST /api/logs/reachability/devices/:deviceId/assess — evaluate now. */
  async assess(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await requireDevice(req.tenantId, deviceId);
      res.json({ success: true, data: await assessDevice(deviceId) });
    } catch (err) {
      next(err);
    }
  },

  /**
   * PUT /api/logs/reachability/devices/:deviceId/external-probe
   *
   * DEVICE_WRITE, because enabling this makes the platform open TCP connections
   * to a customer's public address on a schedule. That is an outbound action
   * against somebody else's network and an operator's decision to take — not a
   * side effect of adding a device to the inventory.
   */
  async setExternalProbe(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await requireDevice(req.tenantId, deviceId);
      const body = parse(probeBody, req.body ?? {});
      await enableExternalProbe(deviceId, body);
      // Probe once immediately: an operator who just enabled this wants to know
      // whether it works, and a baseline that only appears two minutes later
      // looks like a broken feature.
      res.json({ success: true, data: await probeDevice(deviceId) });
    } catch (err) {
      next(err);
    }
  },
};
