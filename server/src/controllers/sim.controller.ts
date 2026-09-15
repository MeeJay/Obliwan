/**
 * ObliWAN F9 — mobile data lines, HTTP layer.
 *
 * ┌─ TWO SCOPES ON ONE PREFIX, AND THE SPLIT IS THE SECURITY DESIGN ──────────┐
 * │                                                                          │
 * │ /sim/accounts/*   PLATFORM. `requireRole('admin')` on the route, upstream │
 * │                   of every branch here. These rows hold a partner         │
 * │                   CREDENTIAL and have no `tenant_id` (migration 032,      │
 * │                   decision 2), so one write changes what every tenant is  │
 * │                   shown. SETTINGS_MANAGE would NOT do: it is granted to   │
 * │                   the admin of any tenant through                         │
 * │                   `TENANT_ROLE_CAPABILITIES`, which is exactly the bug F5 │
 * │                   shipped on `ip_asn_ranges`. Worse here — a tenant admin │
 * │                   could repoint `base_url` at a host they control and     │
 * │                   harvest the credential on the next sweep.               │
 * │                                                                          │
 * │ everything else   TENANT. Every read goes through `scope()` below, which  │
 * │                   builds `{ tenantId, masterView }` from what             │
 * │                   `requireTenant` established against a real              │
 * │                   `user_tenants` row — never from                         │
 * │                   `req.session.currentTenantId` (AUDIT-SEC #2).           │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT THIS SURFACE MUST NEVER RETURN ─────────────────────────────────────┐
 * │ A partner credential, in any shape. `toAccount()` has an explicit         │
 * │ projection that excludes `credential_blob`, and there is deliberately NO  │
 * │ reveal endpoint: SECRET_READ exists for device credentials an engineer    │
 * │ must sometimes type into a console, and a partner API token has no such   │
 * │ use. `POST /accounts/:id/otp` ACCEPTS a password and a code and returns   │
 * │ neither — it stores the resulting token and answers with the account.     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * D3: no route here writes to an equipment. The one route that reaches outside
 * this installation at all is the sweep, which talks to a partner's web API.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import {
  SIM_PLATFORM_CATALOG,
  SIM_RECHARGE_STATUSES,
  simAccountInputSchema,
  simCredentialInputSchema,
  simLineUpdateSchema,
  simManualRechargeSchema,
  simRechargeCompletionSchema,
  simRechargeDecisionSchema,
  type SimRechargeStatus,
} from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import { db } from '../db';
import {
  SimAccountError,
  createAccount,
  deleteAccount,
  getAccount,
  listAccounts,
  setCredential,
  testConnection,
  updateAccount,
  type SimAccountRow,
} from '../services/sim/account.service';
import {
  fleetSummary,
  getLine,
  getLineHistory,
  listLines,
  updateLine,
  type SimScope,
} from '../services/sim/line.service';
import {
  approve,
  capUsage,
  execute,
  getRecharge,
  listRecharges,
  priceRecharge,
  proposeManual,
  recordCompletion,
  reject,
} from '../services/sim/recharge.service';
import { rechargeReport, reportToCsv } from '../services/sim/report.service';
import { syncAccount } from '../services/sim/sync.service';
import { SimConnectorError } from '../services/sim/types';
import { phenixAuthenticateWithCode } from '../services/sim/phenix.connector';

// ============================================================================
// Helpers
// ============================================================================

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

function parse<S extends z.ZodTypeAny>(schema: S, value: unknown): z.infer<S> {
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

/**
 * The tenant scope for every non-account route.
 *
 * `masterView` comes from `requireTenant`, which set it only after a real
 * membership lookup AND a platform-admin check. Recomputing it here from the
 * session would reintroduce the god-view defect the middleware closes.
 */
function scope(req: Request): SimScope {
  return { tenantId: req.tenantId, masterView: req.masterView };
}

/**
 * The acting user, for the audit ledger and the decision columns.
 *
 * `express-session` types every `SessionData` field as optional, and every
 * route here is behind `requireAuth`, so the fields ARE set. The guard is not
 * ceremony: a top-up decision attributed to user `undefined` is an unsigned
 * approval in a money trail, and failing loudly beats writing one.
 */
function actor(req: Request): { id: number; name: string } {
  const id = req.session.userId;
  if (typeof id !== 'number') throw new AppError(401, 'Not authenticated');
  return { id, name: req.session.username ?? String(id) };
}

/**
 * Service errors carry their own HTTP status; everything else stays what it is
 * and becomes a 500.
 *
 * Translated here rather than thrown as `AppError` from the service layer, so
 * the services stay callable from the sweep — which has no request, no response
 * and no use for an HTTP status.
 */
/** Partner-side failure codes → the HTTP status an operator should see. */
const CONNECTOR_STATUS: Record<string, number> = {
  // The operator typed a wrong password or a wrong one-time code. Their input,
  // their fix — a 400, not the 500 the first draft produced by falling through.
  AUTH_FAILED: 400,
  NOT_IMPLEMENTED: 501,
  CONFIG_ERROR: 400,
  // The partner answered badly or not at all. Nothing here is wrong; 502 says
  // "upstream", which is what an operator needs to know before retrying.
  PARTNER_ERROR: 502,
  UNREADABLE: 502,
};

function toHttp(err: unknown): unknown {
  if (err instanceof SimAccountError) return new AppError(err.status, err.message);
  if (err instanceof SimConnectorError) {
    // The message was scrubbed of credential literals in the error's own
    // constructor (§8.2), so it is safe to hand to the client.
    return new AppError(CONNECTOR_STATUS[err.code] ?? 502, err.message);
  }
  return err;
}

// ============================================================================
// Platform: accounts
// ============================================================================

export const simController = {
  /** The coverage matrix, as data. The UI renders it rather than hard-coding
   *  which partners are readable — see `shared/src/sim.ts`, decision 3. */
  listPlatforms(_req: Request, res: Response): void {
    res.json({ success: true, data: SIM_PLATFORM_CATALOG });
  },

  async listAccounts(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await listAccounts() });
    } catch (err) {
      next(err);
    }
  },

  async createAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(simAccountInputSchema, req.body);
      res.status(201).json({ success: true, data: await createAccount(input) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async updateAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      // `platform` is omitted from the patch schema: changing it would leave a
      // credential minted for one partner pointed at another's connector, and
      // every line already collected attributed to the wrong platform.
      const input = parse(simAccountInputSchema.partial().omit({ platform: true }), req.body);
      res.json({ success: true, data: await updateAccount(id, input) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async deleteAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      await deleteAccount(parseId(req.params.id, 'account id'));
      res.json({ success: true });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async setCredential(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      const cred = parse(simCredentialInputSchema, req.body);
      // A token knows its own partner id and expiry; both are re-derived inside
      // `setCredential` so what is stored matches what was supplied rather than
      // what was typed into the form.
      res.json({ success: true, data: await setCredential(id, cred) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /**
   * The one-time-code flow, which is interactive BY DEFINITION.
   *
   * A sweep has no human and therefore cannot answer a code challenge. This
   * route exists so an operator can complete that challenge once and leave a
   * long-lived token behind; the password and the code are used here and stored
   * nowhere (§8.2).
   */
  async authenticateWithCode(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      const input = parse(
        z.object({
          username: z.string().trim().min(1).max(190),
          password: z.string().min(1).max(512),
          code: z.string().trim().min(4).max(12),
        }),
        req.body,
      );
      const account = await getAccount(id);
      if (!account) throw new AppError(404, 'Account not found');
      if (account.platform !== 'phenix') {
        throw new AppError(400, 'One-time-code sign-in is only implemented for Phenix Partner.');
      }
      const row = await db<SimAccountRow>('sim_accounts').where({ id }).first();
      const result = await phenixAuthenticateWithCode(
        row?.base_url ?? null,
        input.username,
        input.password,
        input.code,
      );
      if (account.authMode !== 'token') {
        await updateAccount(id, { authMode: 'token' });
      }
      const saved = await setCredential(
        id,
        { authMode: 'token', token: result.token },
        { partnerRef: result.partnerRef, expiresAt: result.expiresAt },
      );
      res.json({ success: true, data: saved });
      // A wrong code throws a SimConnectorError, which `toHttp` now maps to a
      // 400 — it used to fall through as "Internal server error", telling an
      // operator who mistyped six digits that the product had broken.
    } catch (err) {
      next(toHttp(err));
    }
  },

  async testAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      res.json({ success: true, data: await testConnection(id) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /**
   * Runs a sweep now.
   *
   * Platform-guarded like the rest of `/accounts`, because a sweep spends a
   * partner's rate limit on an API that publishes none — a button any tenant
   * admin could press is a button that gets the whole installation throttled.
   */
  async syncAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      const row = await db<SimAccountRow>('sim_accounts').where({ id }).first();
      if (!row) throw new AppError(404, 'Account not found');
      res.json({ success: true, data: await syncAccount(row) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /** The sweep journal: why a balance is stale. */
  async listRuns(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      const rows = await db('sim_sync_runs')
        .where({ account_id: id })
        .orderBy('started_at', 'desc')
        .limit(50);
      res.json({ success: true, data: rows });
    } catch (err) {
      next(err);
    }
  },

  async accountCaps(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await capUsage(parseId(req.params.id, 'account id')) });
    } catch (err) {
      next(err);
    }
  },

  // ==========================================================================
  // Tenant: lines
  // ==========================================================================

  async summary(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await fleetSummary(scope(req)) });
    } catch (err) {
      next(err);
    }
  },

  async listLines(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(
        z.object({
          accountId: z.coerce.number().int().positive().optional(),
          assignment: z.enum(['assigned', 'pool']).optional(),
          verdict: z.enum(['ok', 'low', 'unknown']).optional(),
          search: z.string().trim().max(120).optional(),
          limit: z.coerce.number().int().min(1).max(5000).optional(),
        }),
        req.query,
      );
      res.json({ success: true, data: await listLines(scope(req), q) });
    } catch (err) {
      next(err);
    }
  },

  async getLine(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const line = await getLine(scope(req), parseId(req.params.id, 'line id'));
      // 404, never 403: a 403 confirms the id exists, which on a serial primary
      // key is an enumeration oracle over another customer's SIM inventory.
      if (!line) throw new AppError(404, 'Line not found');
      res.json({ success: true, data: line });
    } catch (err) {
      next(err);
    }
  },

  async getLineHistory(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'line id');
      const { days } = parse(
        z.object({ days: z.coerce.number().int().min(1).max(730).optional() }),
        req.query,
      );
      res.json({ success: true, data: await getLineHistory(scope(req), id, days ?? 90) });
    } catch (err) {
      next(err);
    }
  },

  async updateLine(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'line id');
      const patch = parse(simLineUpdateSchema, req.body);
      res.json({ success: true, data: await updateLine(scope(req), id, patch) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  // ==========================================================================
  // Tenant: top-ups
  // ==========================================================================

  async listRecharges(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(
        z.object({
          status: z
            .string()
            .optional()
            .transform((s) => (s ? s.split(',').map((v) => v.trim()) : undefined))
            .pipe(z.array(z.enum(SIM_RECHARGE_STATUSES)).optional()),
          simId: z.coerce.number().int().positive().optional(),
          limit: z.coerce.number().int().min(1).max(2000).optional(),
        }),
        req.query,
      );
      const data = await listRecharges(scope(req), {
        status: q.status as SimRechargeStatus[] | undefined,
        simId: q.simId,
        limit: q.limit,
      });
      res.json({ success: true, data });
    } catch (err) {
      next(err);
    }
  },

  async getRechargeById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await getRecharge(scope(req), parseId(req.params.id, 'top-up id'));
      if (!row) throw new AppError(404, 'Top-up not found');
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  async proposeRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(simManualRechargeSchema, req.body);
      const data = await proposeManual(scope(req), input, actor(req));
      res.status(201).json({ success: true, data });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async approveRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'top-up id');
      const { note } = parse(simRechargeDecisionSchema, req.body ?? {});
      res.json({ success: true, data: await approve(scope(req), id, actor(req), note ?? null) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async rejectRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'top-up id');
      const { note } = parse(simRechargeDecisionSchema, req.body ?? {});
      res.json({ success: true, data: await reject(scope(req), id, actor(req), note ?? null) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /** Records a top-up bought on the partner's portal. The normal terminal
   *  state today, and never refused by a cap — see `recharge.service`. */
  async recordRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'top-up id');
      const input = parse(simRechargeCompletionSchema, req.body ?? {});
      res.json({ success: true, data: await recordCompletion(scope(req), id, actor(req), input) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /**
   * Fills in the cost of a top-up that was already recorded.
   *
   * Not a state change: the row stays exactly as billable as it was. It exists
   * because the partner's invoice usually arrives after the purchase, and
   * without it `assertExecutionAllowed`'s own error message — "record their
   * cost first" — named an operation the product did not have.
   */
  async priceRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'top-up id');
      const input = parse(simRechargeCompletionSchema, req.body ?? {});
      res.json({ success: true, data: await priceRecharge(scope(req), id, actor(req), input) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /**
   * Asks ObliWAN to buy it. Answers 501 for every platform today.
   *
   * The route exists so the refusal is a documented, testable answer with a
   * reason an operator can read, rather than a missing endpoint that a future
   * client discovers as a 404.
   */
  async executeRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'top-up id');
      res.json({ success: true, data: await execute(scope(req), id, actor(req)) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  // ==========================================================================
  // Tenant: re-invoicing report
  // ==========================================================================

  async report(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { from, to } = parseWindow(req);
      res.json({ success: true, data: await rechargeReport(scope(req), from, to) });
    } catch (err) {
      next(err);
    }
  },

  async reportCsv(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { from, to } = parseWindow(req);
      const report = await rechargeReport(scope(req), from, to);
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="sim-recharges-${from.toISOString().slice(0, 10)}.csv"`,
      );
      // A BOM, so Excel opens a UTF-8 CSV with accented site names intact
      // instead of as mojibake somebody then "fixes" by hand in an invoice.
      res.send('﻿' + reportToCsv(report));
    } catch (err) {
      next(err);
    }
  },
};

/**
 * The reporting window.
 *
 * Defaults to the current calendar month, which is the period somebody
 * re-invoices. Both bounds are required to be real dates; an unparseable one is
 * a 400 rather than silently becoming "the epoch", which would export every
 * top-up ever made under a heading that says one month.
 */
function parseWindow(req: Request): { from: Date; to: Date } {
  const q = parse(
    z.object({
      from: z.string().datetime({ offset: true }).optional(),
      to: z.string().datetime({ offset: true }).optional(),
    }),
    req.query,
  );
  const now = new Date();
  const from = q.from
    ? new Date(q.from)
    : new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const to = q.to ? new Date(q.to) : now;
  // `z.string().datetime({offset:true})` accepts an offset Postgres cannot
  // parse into a real instant (`+99:00`), which `new Date()` turns into an
  // Invalid Date — and a query built on one is a 500, not the 400 the comment
  // above promised. Checked rather than assumed.
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
    throw new AppError(400, 'The reporting period is not a pair of valid instants');
  }
  if (from > to) throw new AppError(400, 'The start of the period is after its end');
  return { from, to };
}
