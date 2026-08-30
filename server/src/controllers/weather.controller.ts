/**
 * ObliWAN F5 — Operator Weather, HTTP layer.
 *
 * Everything is scoped through `req.tenantId`. `wan_path_events`,
 * `device_wan_path`, `operator_incidents` and `operator_incident_members` all
 * carry `tenant_id NOT NULL` (migration 021) and every service call takes it as
 * its first argument: there is no "current tenant" read from a session inside
 * the service layer, and no query in this milestone can return a row without
 * one. `ip_asn_ranges` is the one table with no tenant column, and it is public
 * routing data — see migration 021, decision 3.
 *
 * A ROW BELONGING TO ANOTHER CUSTOMER IS A 404, NEVER A 403. A 403 confirms
 * that the id exists, which on a bigserial is an enumeration oracle over
 * another MSP customer's incident history.
 *
 * ┌─ WHY THE CAPABILITIES SPLIT THE WAY THEY DO ──────────────────────────────┐
 * │ DEVICE_READ      read the weather, the incidents and the path history.    │
 * │                  This is fleet state — which site is on LTE, which        │
 * │                  carrier is having a bad afternoon — and it carries no    │
 * │                  configuration and no secret. Same class as presence.     │
 * │ DEVICE_WRITE     the on-demand probe and the on-demand sweep. The probe   │
 * │                  makes this server OPEN A SESSION to a customer's router  │
 * │                  with a vault credential; the sweep OPENS AND CLOSES      │
 * │                  incidents. Neither is a read of our database, and        │
 * │                  neither belongs behind a read capability.                │
 * │ SETTINGS_MANAGE  the quorum policy, AND NOTHING ELSE. It decides whether  │
 * │                  an MSP telephones a carrier, and it is a tenant-local    │
 * │                  decision: a customer's quorum belongs to that customer's │
 * │                  admin.                                                   │
 * │ requireRole      WRITING THE ASN TABLE. This block used to list the ASN   │
 * │   ('admin')      import under SETTINGS_MANAGE while calling it a          │
 * │                  cross-tenant act that "cannot sit behind a tenant-scoped │
 * │                  fleet capability" — and SETTINGS_MANAGE is exactly that, │
 * │                  since `TENANT_ROLE_CAPABILITIES.admin` grants it to the   │
 * │                  admin of ANY tenant. `ip_asn_ranges` has no `tenant_id`,  │
 * │                  so one customer's admin rewrote every other customer's   │
 * │                  attribution. The guard is now the PLATFORM role, read    │
 * │                  from `users.role`; see `routes/weather.routes.ts`.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS (§8.2): nothing on this surface can return one. The widest object it
 * serves is a device's egress path — addresses, an interface name, an ASN.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import {
  ASN_RANGE_SOURCES, OPERATOR_INCIDENT_STATUSES, WeatherPolicyError,
  type DeviceWanPath, type IpScope, type WanPathKind, type WeatherSource,
} from '@obliwan/shared/dist/weather';
import { AppError } from '../middleware/errorHandler';
import { db } from '../db';
import {
  attributeAddress, getAsnTableStatus, getIncident, getTenantPolicy, getWeatherReport,
  importAsnDataset,
  listIncidents, listPathEvents, observeEgressPath, runWeatherScan, setTenantPolicy,
  clearingThresholdFor, resumeThresholdFor,
} from '../services/weather';

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

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

/** A policy that violates the open/close asymmetry is a 400 with the reason
 *  spelled out, not a 500 and not a silent fallback to the default. */
function asPolicyError(err: unknown): never {
  if (err instanceof WeatherPolicyError) throw new AppError(400, err.message);
  throw err;
}

const incidentQuery = z
  .object({
    status: z.enum(OPERATOR_INCIDENT_STATUSES).optional(),
    limit: z.coerce.number().int().min(1).max(500).optional(),
  })
  .strict();

const eventQuery = z
  .object({
    sinceMinutes: z.coerce.number().int().min(1).max(20_160).optional(),
    deviceId: z.coerce.number().int().positive().optional(),
    asn: z.coerce.number().int().positive().max(4294967295).optional(),
    limit: z.coerce.number().int().min(1).max(1000).optional(),
  })
  .strict();

const policyBody = z
  .object({
    windowMinutes: z.number().int(),
    minSites: z.number().int(),
    minFraction: z.number(),
    clearRatio: z.number(),
    holdDownMinutes: z.number().int(),
    fleetWideAsnCount: z.number().int(),
    fleetWideFraction: z.number(),
    enabled: z.boolean().optional(),
  })
  .strict();

const importBody = z
  .object({
    /** The dataset itself: one range per line. See `parseAsnRangeLine`. */
    dataset: z.string().min(1).max(64 * 1024 * 1024),
    label: z.string().min(1).max(255),
    source: z.enum(ASN_RANGE_SOURCES).optional(),
  })
  .strict();

const scanBody = z
  .object({
    lookbackMinutes: z.number().int().min(1).max(10_080).optional(),
    skipIngest: z.boolean().optional(),
  })
  .strict();

const probeBody = z
  .object({
    /** Skip the RouterOS dial and use only the generic SNMP signal. */
    offlineOnly: z.boolean().optional(),
  })
  .strict();

interface PathRow {
  device_id: number;
  site_id: number | null;
  name: string;
  path_kind: WanPathKind;
  egress_interface: string | null;
  effective_public_ip: string | null;
  observed_public_ip: string | null;
  ip_scope: IpScope;
  asn: string | null;
  as_org: string | null;
  country: string | null;
  region: string | null;
  source: WeatherSource;
  observed_at: Date;
}

function toPathView(row: PathRow): DeviceWanPath {
  return {
    deviceId: row.device_id,
    siteId: row.site_id,
    deviceName: row.name,
    pathKind: row.path_kind,
    egressInterface: row.egress_interface,
    publicIp: row.effective_public_ip,
    // The generated column resolves to the observation whenever there is one,
    // so "did the concentrator see this?" is exactly this comparison.
    publicIpObserved: row.observed_public_ip !== null,
    ipScope: row.ip_scope,
    asn: row.asn === null ? null : Number(row.asn),
    asOrg: row.as_org,
    country: row.country,
    region: row.region,
    source: row.source,
    observedAt: new Date(row.observed_at).toISOString(),
  };
}

/**
 * The device egress table. Joined to `devices` on BOTH id and tenant so the
 * pair is proven by the query rather than trusted from the row — the same
 * discipline every other cross-table read in this codebase follows.
 */
async function loadPaths(tenantId: number, deviceId?: number): Promise<DeviceWanPath[]> {
  let q = db('device_wan_path as p')
    .join('devices as d', function joinDevice(this: any) {
      this.on('d.id', '=', 'p.device_id').andOn('d.tenant_id', '=', 'p.tenant_id');
    })
    .where('p.tenant_id', tenantId)
    .orderBy('p.observed_at', 'desc');
  if (deviceId) q = q.andWhere('p.device_id', deviceId);

  const rows = await q.select<PathRow[]>(
    'p.device_id', 'd.site_id', 'd.name', 'p.path_kind', 'p.egress_interface',
    'p.effective_public_ip', 'p.observed_public_ip', 'p.ip_scope', 'p.asn',
    'p.as_org', 'p.country', 'p.region', 'p.source', 'p.observed_at',
  );
  return rows.map(toPathView);
}

export const weatherController = {
  /** GET /api/weather — the map, including the ASNs that did NOT reach quorum. */
  async report(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const report = await getWeatherReport(req.tenantId);
      res.json({
        success: true,
        data: {
          ...report,
          clearingThreshold: clearingThresholdFor(report.policy),
          resumeThreshold: resumeThresholdFor(report.policy),
        },
      });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/weather/incidents */
  async incidents(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(incidentQuery, req.query ?? {});
      res.json({ success: true, data: await listIncidents(req.tenantId, q) });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/weather/incidents/:id — with its members and the frozen policy. */
  async incident(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const detail = await getIncident(req.tenantId, parseId(req.params.id, 'incident id'));
      if (!detail) throw new AppError(404, 'Incident not found');
      res.json({ success: true, data: detail });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/weather/events — the raw path transitions behind the verdicts. */
  async events(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(eventQuery, req.query ?? {});
      res.json({ success: true, data: await listPathEvents(req.tenantId, q) });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/weather/paths — who is on LTE right now, fleet-wide. */
  async paths(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await loadPaths(req.tenantId) });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/weather/devices/:deviceId/path */
  async devicePath(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const [row] = await loadPaths(req.tenantId, deviceId);
      if (!row) throw new AppError(404, 'No egress path recorded for this device');
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/weather/devices/:deviceId/probe — resolve the ACTIVE egress path
   * from the box, through the capability matrix (R11), and persist it.
   */
  async probe(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(probeBody, req.body ?? {});
      const deviceId = parseId(req.params.deviceId, 'device id');
      const outcome = await observeEgressPath(req.tenantId, deviceId, {
        offlineOnly: body.offlineOnly,
      });
      const [row] = await loadPaths(req.tenantId, deviceId);
      res.json({ success: true, data: { ...outcome, path: row ?? null } });
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('Device ')) {
        next(new AppError(404, 'Device not found'));
        return;
      }
      next(err);
    }
  },

  /**
   * POST /api/weather/scan — one sweep for this tenant, on demand.
   *
   * Idempotent: the ingestion is keyed on the PPP session, membership on
   * (incident, device), and the opening races on a partial unique index. An
   * operator hammering this button cannot manufacture a second incident.
   */
  async scan(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(scanBody, req.body ?? {});
      const outcome = await runWeatherScan(req.tenantId, body);
      res.json({
        success: true,
        data: {
          enabled: outcome.enabled,
          ingested: outcome.ingested,
          opened: outcome.opened,
          clearing: outcome.clearing,
          closed: outcome.closed,
          resumed: outcome.resumed,
          fleetWide: outcome.evaluation.fleetWide,
          fleetWideReason: outcome.evaluation.fleetWideReason,
          asns: outcome.evaluation.asns,
        },
      });
    } catch (err) {
      if (err instanceof WeatherPolicyError) {
        next(new AppError(400, err.message));
        return;
      }
      next(err);
    }
  },

  /** GET /api/weather/policy */
  async policy(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const loaded = await getTenantPolicy(req.tenantId);
      res.json({
        success: true,
        data: {
          ...loaded,
          clearingThreshold: clearingThresholdFor(loaded.policy),
          resumeThreshold: resumeThresholdFor(loaded.policy),
        },
      });
    } catch (err) {
      if (err instanceof WeatherPolicyError) {
        next(new AppError(400, err.message));
        return;
      }
      next(err);
    }
  },

  /** PUT /api/weather/policy — the quorum. Refused if it is not asymmetric. */
  async setPolicy(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // `enabled` is passed THROUGH, undefined and all. It used to be
      // `enabled ?? true`, which re-enabled a tenant that had deliberately
      // switched operator correlation off as soon as anything wrote a quorum
      // without sending the key. Absent now means "do not touch it"; see
      // `setTenantPolicy`.
      const { enabled, ...policy } = parse(policyBody, req.body ?? {});
      const saved = await setTenantPolicy(req.tenantId, policy, enabled).catch(asPolicyError);
      res.json({
        success: true,
        data: {
          ...saved,
          clearingThreshold: clearingThresholdFor(saved.policy),
          resumeThreshold: resumeThresholdFor(saved.policy),
        },
      });
    } catch (err) {
      if (err instanceof WeatherPolicyError) {
        next(new AppError(400, err.message));
        return;
      }
      next(err);
    }
  },

  /** GET /api/weather/asn-table — how old the offline attribution data is. */
  async asnTable(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await getAsnTableStatus() });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/weather/asn-table — load the offline enrichment table.
   *
   * GLOBAL DATA. This is not a tenant's ASN table, it is the ASN table, and the
   * capability in front of it says so. The label is stored verbatim and shown
   * in the UI: a caller that puts a signed URL in it has published it.
   */
  async importAsnTable(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(importBody, req.body ?? {});
      const outcome = await importAsnDataset(body.dataset, {
        label: body.label,
        source: body.source,
        userId: req.session?.userId ?? null,
      });
      res.json({ success: true, data: outcome });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/weather/classify?ip=… — what our offline enrichment makes of one
   * address. The debugging endpoint for "why is this site unattributed", which
   * is otherwise a question with no answer but a shrug.
   */
  async classify(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const ip = typeof req.query.ip === 'string' ? req.query.ip : '';
      if (!ip) throw new AppError(400, 'Query parameter `ip` is required');
      if (ip.length > 64) throw new AppError(400, 'Not an address');
      const attribution = await attributeAddress(ip);
      res.json({
        success: true,
        data: {
          ip,
          scope: attribution.scope,
          attributable: attribution.scope === 'public',
          reason: attribution.reason,
          asn: attribution.asn,
        },
      });
    } catch (err) {
      next(err);
    }
  },
};

