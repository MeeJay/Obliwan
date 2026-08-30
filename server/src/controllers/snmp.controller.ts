/**
 * SNMP / telemetry — HTTP layer.
 *
 * Three rules, all of them already load-bearing elsewhere in this codebase and
 * restated here because this is the surface where they are tested:
 *
 *  1. THE TENANT IS ALWAYS `req.tenantId`, from the session, never anything the
 *     client sent. Every service call in this file takes it as its first
 *     argument, and every one of them filters on it.
 *
 *  2. A CROSS-TENANT ID IS A 404, NOT A 403. "That interface exists but is not
 *     yours" is itself a disclosure about another customer's inventory.
 *
 *  3. NO SECRET LEAVES. `snmp_credentials` is exposed through
 *     `SnmpCredentialSummary`, which carries `hasCommunity: boolean` and has no
 *     field capable of holding a community string or a USM key. There is no
 *     "masked" variant, because a masked secret is a secret that has already
 *     travelled.
 *
 * Validation is done with zod INSIDE the handlers rather than through a
 * `validators/*.schema.ts` + `validate()` middleware pair, which is this
 * codebase's usual shape. That is a deliberate scope decision, not a
 * preference: `server/src/validators/` belongs to another workstream in this
 * milestone. Moving these schemas into their own file later is a cut and
 * paste, and the `validate(schema)` middleware will accept them unchanged.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import {
  SNMP_VERSIONS,
  SNMP_SECURITY_LEVELS,
  SNMP_AUTH_PROTOCOLS,
  SNMP_PRIV_PROTOCOLS,
  THRESHOLD_SCOPES,
  THRESHOLD_METRICS,
  THRESHOLD_COMPARATORS,
  THRESHOLD_SEVERITIES,
  THRESHOLD_STATES,
} from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import * as credentials from '../services/snmp/credential.service';
import * as series from '../services/snmp/series.service';
import * as thresholds from '../services/snmp/threshold.service';
import { schedulerStats } from '../services/snmp/scheduler';
import { writerStats } from '../services/snmp/writer';
import { trapStats } from '../services/snmp/trapReceiver';
import { syslogStats } from '../services/snmp/syslogReceiver';

// ============================================================================
// Helpers
// ============================================================================

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    // `AppError` carries a message and nothing else, so the field errors are
    // folded into it. Losing them entirely would leave the operator with
    // "Validation failed" and a form of fourteen fields.
    const flat = result.error.flatten();
    const fields = Object.entries(flat.fieldErrors)
      .map(([field, messages]) => `${field}: ${((messages as string[] | undefined) ?? []).join(', ')}`)
      .concat(flat.formErrors)
      .filter((s) => s.length > 0)
      .join('; ');
    throw new AppError(400, fields ? `Validation failed — ${fields}` : 'Validation failed');
  }
  return result.data;
}

/** Postgres codes we translate rather than leak as a 500. */
function isUniqueViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505';
}
function isForeignKeyViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === '23503';
}
/** A CHECK violation here is almost always a shape rule the database enforces
 *  and the API restates (credential shape, threshold scope shape). Surfacing it
 *  as a 400 tells the operator to fix the payload; a 500 tells them to open a
 *  ticket. */
function isCheckViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === '23514';
}

/**
 * A time window. Defaults to the last six hours -- the "what happened just
 * now" case -- and is capped at two years, which is the 1 h tier's retention:
 * a wider window can only return emptiness, and an empty answer to a
 * ten-year request reads as "this interface carried no traffic".
 */
const windowSchema = z.object({
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
  granularity: z.enum(['raw', '1m', '5m', '1h']).optional(),
});

function parseWindow(query: unknown): {
  from: Date;
  to: Date;
  granularity?: series.SeriesResolution;
} {
  const q = parse(windowSchema, query);
  const to = q.to ? new Date(q.to) : new Date();
  const from = q.from ? new Date(q.from) : new Date(to.getTime() - 6 * 3600 * 1000);
  if (from.getTime() >= to.getTime()) {
    throw new AppError(400, '`from` must be strictly before `to`');
  }
  if (to.getTime() - from.getTime() > 730 * 86400 * 1000) {
    throw new AppError(400, 'Window longer than the 730-day retention of the hourly tier');
  }
  return { from, to, granularity: q.granularity };
}

// ============================================================================
// Schemas
// ============================================================================

const credentialSchema = z
  .object({
    name: z.string().min(1).max(128),
    version: z.enum(SNMP_VERSIONS),
    community: z.string().min(1).max(255).optional(),
    username: z.string().min(1).max(128).nullable().optional(),
    securityLevel: z.enum(SNMP_SECURITY_LEVELS).nullable().optional(),
    authProtocol: z.enum(SNMP_AUTH_PROTOCOLS).nullable().optional(),
    authKey: z.string().min(8).max(255).optional(),
    privProtocol: z.enum(SNMP_PRIV_PROTOCOLS).nullable().optional(),
    privKey: z.string().min(8).max(255).optional(),
    context: z.string().max(128).nullable().optional(),
  })
  .superRefine((value, ctx) => {
    // The same shape rule as `snmp_credentials_shape_chk`. Stated twice on
    // purpose: the database GUARANTEES it, this makes the message readable.
    if (value.version === 'v3') {
      if (!value.username) {
        ctx.addIssue({ code: 'custom', path: ['username'], message: 'required for v3' });
      }
      if (!value.securityLevel) {
        ctx.addIssue({ code: 'custom', path: ['securityLevel'], message: 'required for v3' });
      }
      if (value.securityLevel === 'authPriv' && !value.privProtocol) {
        ctx.addIssue({ code: 'custom', path: ['privProtocol'], message: 'required for authPriv' });
      }
      if (value.securityLevel !== 'noAuthNoPriv' && !value.authProtocol) {
        ctx.addIssue({ code: 'custom', path: ['authProtocol'], message: 'required for auth levels' });
      }
    } else if (value.username) {
      ctx.addIssue({ code: 'custom', path: ['username'], message: 'v1/v2c take a community, not a user' });
    }
  });

const targetSchema = z.object({
  credentialId: z.number().int().positive().nullable().optional(),
  host: z.string().max(255).nullable().optional(),
  port: z.number().int().min(1).max(65535).optional(),
  enabled: z.boolean().optional(),
  pollIntervalSec: z.number().int().min(5).max(86400).nullable().optional(),
  timeoutMs: z.number().int().min(100).max(60000).optional(),
  retries: z.number().int().min(0).max(5).optional(),
  maxRepetitions: z.number().int().min(1).max(100).optional(),
  supportsHcCounters: z.boolean().optional(),
});

/**
 * `forSeconds` and `hysteresisPct` are REQUIRED, with no default -- exactly
 * like the columns. Giving them a default here would reintroduce, at the API,
 * the silent 0 that the schema refuses: an alert with no dwell timer and no
 * hysteresis fires on the first spike and then flaps for ever.
 */
const thresholdSchema = z
  .object({
    name: z.string().min(1).max(128),
    enabled: z.boolean().optional(),
    scope: z.enum(THRESHOLD_SCOPES),
    deviceId: z.number().int().positive().nullable().optional(),
    groupId: z.number().int().positive().nullable().optional(),
    ifId: z.number().int().positive().nullable().optional(),
    metric: z.enum(THRESHOLD_METRICS),
    comparator: z.enum(THRESHOLD_COMPARATORS),
    value: z.number().finite(),
    forSeconds: z.number().int().min(1).max(86400),
    hysteresisPct: z.number().min(0).max(50),
    severity: z.enum(THRESHOLD_SEVERITIES),
    channelId: z.number().int().positive().nullable().optional(),
  })
  .superRefine((value, ctx) => {
    const need = (field: 'deviceId' | 'groupId' | 'ifId'): void => {
      if (value[field] == null) {
        ctx.addIssue({ code: 'custom', path: [field], message: `required for scope "${value.scope}"` });
      }
    };
    if (value.scope === 'device') need('deviceId');
    if (value.scope === 'group') need('groupId');
    if (value.scope === 'interface') need('ifId');
  });

// ============================================================================
// Controller
// ============================================================================

export const snmpController = {
  // -- Credentials (CREDENTIAL_MANAGE) ------------------------------------

  async listCredentials(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await credentials.listCredentials(req.tenantId) });
    } catch (err) {
      next(err);
    }
  },

  async getCredential(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await credentials.getCredential(req.tenantId, parseId(req.params.id));
      if (!row) throw new AppError(404, 'Credential not found');
      const usage = await credentials.credentialUsage(req.tenantId, row.id);
      res.json({ success: true, data: { ...row, targetCount: usage } });
    } catch (err) {
      next(err);
    }
  },

  async createCredential(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(credentialSchema, req.body);
      const row = await credentials.createCredential(req.tenantId, input);
      res.status(201).json({ success: true, data: row });
    } catch (err) {
      if (isUniqueViolation(err)) {
        next(new AppError(409, 'A credential with this name already exists in this tenant'));
        return;
      }
      if (isCheckViolation(err)) {
        next(new AppError(400, 'Credential shape refused by the database (version / key combination)'));
        return;
      }
      next(err);
    }
  },

  async updateCredential(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(credentialSchema, req.body);
      const row = await credentials.updateCredential(req.tenantId, parseId(req.params.id), input);
      if (!row) throw new AppError(404, 'Credential not found');
      res.json({ success: true, data: row });
    } catch (err) {
      if (isUniqueViolation(err)) {
        next(new AppError(409, 'A credential with this name already exists in this tenant'));
        return;
      }
      if (isCheckViolation(err)) {
        next(new AppError(400, 'Credential shape refused by the database (version / key combination)'));
        return;
      }
      next(err);
    }
  },

  async deleteCredential(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deleted = await credentials.deleteCredential(req.tenantId, parseId(req.params.id));
      if (!deleted) throw new AppError(404, 'Credential not found');
      res.json({ success: true });
    } catch (err) {
      if (isForeignKeyViolation(err)) {
        // ON DELETE RESTRICT from snmp_targets. Deleting it anyway would take
        // every device using it out of supervision, silently.
        next(new AppError(409, 'This credential is still used by one or more SNMP targets'));
        return;
      }
      next(err);
    }
  },

  // -- Targets ------------------------------------------------------------

  async getTarget(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await credentials.getTargetSummary(req.tenantId, parseId(req.params.deviceId));
      if (!row) throw new AppError(404, 'No SNMP target for this device');
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  async putTarget(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(targetSchema, req.body);
      const row = await credentials.upsertTarget(req.tenantId, parseId(req.params.deviceId), input);
      // Null covers both "no such device in this tenant" and "no such
      // credential in this tenant": the same 404, no existence oracle.
      if (!row) throw new AppError(404, 'Device or credential not found');
      res.json({ success: true, data: row });
    } catch (err) {
      if (isCheckViolation(err)) {
        next(new AppError(400, 'Target values refused by the database (port / interval / timeout range)'));
        return;
      }
      next(err);
    }
  },

  async deleteTarget(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deleted = await credentials.deleteTarget(req.tenantId, parseId(req.params.deviceId));
      if (!deleted) throw new AppError(404, 'No SNMP target for this device');
      res.json({ success: true });
    } catch (err) {
      next(err);
    }
  },

  // -- Interfaces and series ----------------------------------------------

  /**
   * GET /api/snmp/interfaces — every interface of the tenant, with its last
   * measurement, device and site. Feeds the fleet view, which sorts by
   * saturation and cannot do that from the per-device endpoint without one
   * round-trip per device.
   */
  async listFleetInterfaces(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const rows = await series.listFleetInterfaces(req.tenantId!, {
        includeVanished: req.query.includeVanished === 'true',
        deviceId: req.query.deviceId ? parseId(req.query.deviceId as string) : undefined,
      });
      res.json({ success: true, data: rows });
    } catch (err) {
      next(err);
    }
  },

  async listInterfaces(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const includeVanished = req.query.includeVanished === 'true';
      const rows = await series.listInterfaces(req.tenantId, parseId(req.params.deviceId), {
        includeVanished,
      });
      res.json({ success: true, data: rows });
    } catch (err) {
      next(err);
    }
  },

  async interfaceSeries(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { from, to, granularity } = parseWindow(req.query);
      const data = await series.getInterfaceSeries(
        req.tenantId,
        parseId(req.params.ifId, 'interface id'),
        from,
        to,
        granularity,
      );
      if (!data) throw new AppError(404, 'Interface not found');
      res.json({ success: true, data });
    } catch (err) {
      next(err);
    }
  },

  async deviceSeries(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { from, to, granularity } = parseWindow(req.query);
      const data = await series.getDeviceSeries(
        req.tenantId,
        parseId(req.params.deviceId),
        from,
        to,
        granularity,
      );
      if (!data) throw new AppError(404, 'Device not found');
      res.json({ success: true, data });
    } catch (err) {
      next(err);
    }
  },

  async billingP95(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { from, to } = parseWindow(req.query);
      const data = await series.billingP95(
        req.tenantId,
        parseId(req.params.ifId, 'interface id'),
        from,
        to,
      );
      if (!data) throw new AppError(404, 'Interface not found');
      // Named so nobody labels it "p95" without the qualifier: it is the 95th
      // percentile OF 5-MINUTE AVERAGES, the carrier billing convention, and
      // it is mathematically lower than a p95 of instantaneous rates.
      res.json({ success: true, data: { ...data, basis: '5-minute averages' } });
    } catch (err) {
      next(err);
    }
  },

  // -- Thresholds ---------------------------------------------------------

  async listThresholds(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await thresholds.listThresholds(req.tenantId) });
    } catch (err) {
      next(err);
    }
  },

  async getThreshold(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await thresholds.getThreshold(req.tenantId, parseId(req.params.id));
      if (!row) throw new AppError(404, 'Threshold not found');
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  async createThreshold(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(thresholdSchema, req.body);
      const row = await thresholds.createThreshold(req.tenantId, input);
      res.status(201).json({ success: true, data: row });
    } catch (err) {
      if (isUniqueViolation(err)) {
        next(new AppError(409, 'A threshold with this name already exists in this tenant'));
        return;
      }
      if (isForeignKeyViolation(err)) {
        next(new AppError(400, 'The referenced device, group, interface or channel does not exist'));
        return;
      }
      if (isCheckViolation(err)) {
        next(new AppError(400, 'Threshold refused by the database (scope shape, dwell time or hysteresis range)'));
        return;
      }
      next(err);
    }
  },

  async updateThreshold(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(thresholdSchema, req.body);
      const row = await thresholds.updateThreshold(req.tenantId, parseId(req.params.id), input);
      if (!row) throw new AppError(404, 'Threshold not found');
      res.json({ success: true, data: row });
    } catch (err) {
      if (isUniqueViolation(err)) {
        next(new AppError(409, 'A threshold with this name already exists in this tenant'));
        return;
      }
      if (isCheckViolation(err)) {
        next(new AppError(400, 'Threshold refused by the database (scope shape, dwell time or hysteresis range)'));
        return;
      }
      next(err);
    }
  },

  async deleteThreshold(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deleted = await thresholds.deleteThreshold(req.tenantId, parseId(req.params.id));
      if (!deleted) throw new AppError(404, 'Threshold not found');
      res.json({ success: true });
    } catch (err) {
      next(err);
    }
  },

  async listAlerts(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const query = parse(
        z.object({
          deviceId: z.coerce.number().int().positive().optional(),
          state: z.enum(THRESHOLD_STATES).optional(),
        }),
        req.query,
      );
      res.json({ success: true, data: await thresholds.listAlertStates(req.tenantId, query) });
    } catch (err) {
      next(err);
    }
  },

  // -- Runtime status -----------------------------------------------------

  /**
   * The collection's own health.
   *
   * It is exposed as an endpoint rather than left to the logs because a
   * missing series and a broken collector look IDENTICAL on a chart: both are
   * a flat absence. `abandonedBatches` and `layer3Recoveries` in particular
   * should both be zero, and a non-zero value is an incident even while every
   * graph still looks fine.
   */
  async status(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({
        success: true,
        data: {
          scheduler: schedulerStats(),
          writer: writerStats(),
          traps: trapStats(),
          syslog: syslogStats(),
        },
      });
    } catch (err) {
      next(err);
    }
  },
};
