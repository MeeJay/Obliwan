/**
 * Config snapshots / NCM — HTTP layer.
 *
 * The three rules of `snmp.controller.ts` apply verbatim, and the third one is
 * sharper here:
 *
 *  1. THE TENANT IS ALWAYS `req.tenantId`, from the session. Every service call
 *     takes it as its first argument and every one of them joins `devices` on
 *     it, because `config_snapshots` and the ten `ncm_*` tables have no tenant
 *     column of their own.
 *
 *  2. A CROSS-TENANT ID IS A 404, NOT A 403.
 *
 *  3. WHAT THIS ENDPOINT SERVES IS A CONFIGURATION. `CONFIG_READ` is
 *     deliberately distinct from `DEVICE_READ` (risk R10): seeing that a device
 *     exists is a different question from seeing what it carries. `raw_gz` is
 *     the REDACTED export — `show-sensitive=no` is hard-wired in
 *     `collect.service.ts` and a non-empty secret prop aborts the collection
 *     outright — which is why it is served under `CONFIG_READ` and not
 *     `SECRET_READ`.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { NcmVersionAheadError } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import * as snapshots from '../services/config/snapshot.service';
import { collectAndStore, hasNormalizer, NoNormalizerError, SensitiveMaterialError } from '../services/config/collect.service';
import { reindexSnapshot } from '../services/config/ncmIndex.service';

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

/** Snapshot ids are bigint: they arrive as strings and must stay strings, or a
 *  fleet past 2^53 snapshots starts serving the wrong row. */
function parseBigId(raw: string, what = 'id'): string {
  if (!/^[0-9]{1,19}$/.test(raw)) throw new AppError(400, `Invalid ${what}`);
  return raw;
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

const listQuery = z.object({
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

const compareQuery = z.object({
  from: z.string().regex(/^[0-9]{1,19}$/).optional(),
  to: z.string().regex(/^[0-9]{1,19}$/).optional(),
  scope: z.enum(['managed_only', 'full']).optional(),
  fuzzy: z.enum(['true', 'false']).optional(),
});

export const configController = {
  /** GET /api/config/devices/:deviceId/snapshots */
  async listSnapshots(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(listQuery, req.query);
      // Serves both `/config/devices/:deviceId/snapshots` and the fleet-wide
      // `/config/snapshots`. `deviceId` may also arrive as a query parameter on
      // the latter; absent everywhere, the caller gets the whole tenant.
      const rawDeviceId = req.params.deviceId ?? (req.query.deviceId as string | undefined);
      const deviceId = rawDeviceId === undefined ? undefined : parseId(rawDeviceId, 'device id');
      const rows = await snapshots.listSnapshots(req.tenantId, deviceId, q);
      res.json({ success: true, data: rows });
    } catch (err) {
      next(err);
    }
  },

  /** GET /api/config/snapshots/:id — metadata only, no document. */
  async getSnapshot(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await snapshots.getSnapshot(req.tenantId, parseBigId(req.params.id, 'snapshot id'));
      if (!row) throw new AppError(404, 'Snapshot not found');
      res.json({ success: true, data: row });
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/config/snapshots/:id/ncm — the NCM tree the UI renders.
   *
   * Grouped by resource kind and then by ORDER GROUP (chain), because a
   * firewall rendered as one flat 200-line list has positions that mean
   * nothing across chains.
   */
  async getNcmTree(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tree = await snapshots.getNcmTree(
        req.tenantId,
        parseBigId(req.params.id, 'snapshot id'),
      );
      if (!tree) throw new AppError(404, 'Snapshot not found');
      res.json({ success: true, data: tree });
    } catch (err) {
      if (err instanceof NcmVersionAheadError) {
        // A row written by a newer server during a rollback. Refusing is the
        // only honest answer: a partially-understood document rendered as if
        // complete is worse than an error.
        next(new AppError(409, err.message));
        return;
      }
      next(err);
    }
  },

  /** GET /api/config/snapshots/:id/export — the redacted raw export, as text. */
  async exportSnapshot(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const raw = await snapshots.getSnapshotRaw(
        req.tenantId,
        parseBigId(req.params.id, 'snapshot id'),
      );
      if (!raw) throw new AppError(404, 'Snapshot not found, or it carries no raw archive');
      res.type('text/plain; charset=utf-8');
      res.setHeader('X-Obliwan-Raw-Sha256', raw.sha256 ?? '');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${raw.deviceName.replace(/[^\w.-]/g, '_')}-${raw.capturedAt}.rsc"`,
      );
      res.send(raw.text);
    } catch (err) {
      next(err);
    }
  },

  /**
   * GET /api/config/devices/:deviceId/compare — N against N-1 by default.
   *
   * `scope` defaults to `managed_only` in the engine, and the response carries
   * `outOfScopeCount` so the operator can see what that default hid.
   */
  async compare(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(compareQuery, req.query);
      const result = await snapshots.compareSnapshots(
        req.tenantId,
        parseId(req.params.deviceId, 'device id'),
        {
          fromId: q.from,
          toId: q.to,
          scope: q.scope,
          fuzzy: q.fuzzy === undefined ? undefined : q.fuzzy === 'true',
        },
      );
      if (!result) {
        throw new AppError(404, 'Not enough snapshots for this device to compare');
      }
      res.json({ success: true, data: result });
    } catch (err) {
      if (err instanceof NcmVersionAheadError) {
        next(new AppError(409, err.message));
        return;
      }
      next(err);
    }
  },

  /**
   * POST /api/config/devices/:deviceId/collect — read the box now.
   *
   * A READ of the equipment, never a write: it runs `/export terse
   * show-sensitive=no` and stores the result. It still opens a connection, so
   * it sits behind `CONFIG_WRITE` rather than `CONFIG_READ` — an operator
   * entitled to look at stored configuration is not thereby entitled to make
   * the platform dial a customer's router.
   */
  async collect(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!hasNormalizer()) {
        throw new AppError(
          503,
          'No NCM normaliser is registered on this build; collection is refused rather than ' +
            'storing an empty document',
        );
      }
      const result = await collectAndStore(
        parseId(req.params.deviceId, 'device id'),
        req.tenantId,
        { source: 'ssh' },
      );
      res.json({ success: true, data: result });
    } catch (err) {
      if (err instanceof NoNormalizerError) {
        next(new AppError(503, err.message));
        return;
      }
      if (err instanceof SensitiveMaterialError) {
        // R10. The message names the PROP and never the value.
        next(new AppError(422, err.message));
        return;
      }
      next(err);
    }
  },

  /** POST /api/config/snapshots/:id/reindex — rebuild the flattened cache. */
  async reindex(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'snapshot id');
      // Ownership is checked through the tenant-scoped read BEFORE the rebuild,
      // which itself is a raw id lookup.
      const owned = await snapshots.getSnapshot(req.tenantId, id);
      if (!owned) throw new AppError(404, 'Snapshot not found');
      const result = await reindexSnapshot(id);
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },
};
