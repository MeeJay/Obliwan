/**
 * Compliance attestations (F2) — HTTP layer.
 *
 * ┌─ PREVIEW AND ISSUE ARE TWO ROUTES ON ONE CODE PATH ───────────────────────┐
 * │ `POST /preview` builds the document and returns it. `POST /issue` builds  │
 * │ the SAME document, freezes it, and records the issuance in `audit_log`.   │
 * │                                                                           │
 * │ An operator has to be able to look at what would be attested before       │
 * │ putting a permanent, ledger-recorded statement into the world — and a     │
 * │ preview computed by a different function from the issued document would   │
 * │ be a preview of something else. `issue()` calls `build()`.                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Behind AUDIT_READ, whose catalogue entry is "read the append-only audit log
 * and the command audit" — which is exactly what an attestation is an assembly
 * of. It is NOT behind CONFIG_READ: the document carries hashes of
 * configurations and never their content (§8.2 / R10), so it does not disclose
 * what CONFIG_READ exists to protect.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { ATTESTATION_METHOD } from '../services/attestation/contract';
import { AppError } from '../middleware/errorHandler';
import * as attestation from '../services/attestation/attestation.service';
import * as auditLog from '../services/attestation/auditLog.service';
import { DEFAULT_MAX_GAP_DAYS } from '../services/attestation/evidence';

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

const isoDate = z.string().refine((v) => !Number.isNaN(new Date(v).getTime()), {
  message: 'must be an ISO-8601 date',
});

const buildBody = z
  .object({
    deviceId: z.number().int().positive(),
    from: isoDate,
    to: isoDate,
    /**
     * How long a stretch of unobserved time is tolerated before `continuous`
     * is downgraded to `continuous_with_gaps`.
     *
     * Exposed because the acceptable answer depends on the collection cadence
     * the customer pays for, and because a threshold nobody can see is a
     * threshold nobody can argue with — which is exactly why it is now a
     * member of the HASHED `chainHeader` and is printed in `claim`.
     *
     * FREE ON `/preview`, CAPPED AT `DEFAULT_MAX_GAP_DAYS` ON `/issue`
     * (enforced in `attestation.service.issue()`, which every caller goes
     * through). Looking at what a 90-day tolerance would say is a fair
     * question; publishing a permanent document whose author picked the
     * threshold that made his own fleet look continuous is not.
     */
    maxGapDays: z.number().int().min(0).max(365).optional(),
  })
  .refine((b) => new Date(b.to).getTime() > new Date(b.from).getTime(), {
    message: 'to must be after from',
  });

const uuidParam = z.string().uuid();

function mapError(err: unknown): unknown {
  if (err instanceof attestation.AttestationError) return new AppError(err.status, err.message);
  return err;
}

function actorOf(req: Request): { issuedByUsername: string; issuedByUserId: number | null } {
  return {
    issuedByUsername: req.session?.username ?? 'unknown',
    issuedByUserId: req.session?.userId ?? null,
  };
}

export const attestationController = {
  /** POST /api/attestation/preview — build, return, persist nothing. */
  async preview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const b = parse(buildBody, req.body ?? {});
      const doc = await attestation.build(req.tenantId, {
        deviceId: b.deviceId,
        from: new Date(b.from),
        to: new Date(b.to),
        maxGapDays: b.maxGapDays,
        ...actorOf(req),
      });
      res.json({ success: true, data: doc });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** POST /api/attestation/issue — freeze it and record the issuance. */
  async issue(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const b = parse(buildBody, req.body ?? {});
      const out = await attestation.issue(req.tenantId, {
        deviceId: b.deviceId,
        from: new Date(b.from),
        to: new Date(b.to),
        maxGapDays: b.maxGapDays,
        ...actorOf(req),
      });
      res.status(201).json({ success: true, data: out });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** GET /api/attestation — what has been issued. Metadata only. */
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(
        z.object({
          deviceId: z.coerce.number().int().positive().optional(),
          limit: z.coerce.number().int().min(1).max(500).optional(),
          offset: z.coerce.number().int().min(0).optional(),
        }),
        req.query,
      );
      res.json({ success: true, data: await attestation.listAttestations(req.tenantId, q) });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * GET /api/attestation/:uuid — the frozen document.
   *
   * Returned from `attestations.document` and never rebuilt from live data.
   * The digest is defined over a CANONICAL serialisation (sorted keys, no
   * whitespace), so it survives the `jsonb` round-trip that reorders the keys —
   * a reader verifies the CONTENT, and no transport has to preserve byte order.
   */
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const uuid = parse(uuidParam, req.params.uuid);
      const hit = await attestation.getAttestation(req.tenantId, uuid);
      if (!hit) throw new AppError(404, 'Attestation not found');
      res.json({ success: true, data: hit.document });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * POST /api/attestation/:uuid/verify — recompute every hash in the stored
   * document, and check it against the ledger row written at issuance.
   *
   * Convenience, not proof. The proof is that a reader can do this themselves
   * from `verification` inside the document, without us.
   */
  async verify(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const uuid = parse(uuidParam, req.params.uuid);
      const report = await attestation.verifyStored(req.tenantId, uuid);
      if (!report) throw new AppError(404, 'Attestation not found');
      res.json({ success: true, data: report });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * POST /api/attestation/:uuid/compare — rebuild the same window from live
   * data and compare the evidence roots.
   *
   * `evidenceRoot` excludes `issuedAt`, so an identical root means the
   * underlying evidence has not moved since issuance. A different one is not an
   * accusation: a snapshot confirmed once more since then legitimately changes
   * it. It is the question a reader wants answered, stated precisely.
   */
  async compare(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const uuid = parse(uuidParam, req.params.uuid);
      const out = await attestation.compareToLive(
        req.tenantId,
        uuid,
        req.session?.username ?? 'unknown',
      );
      if (!out) {
        throw new AppError(
          404,
          'Attestation not found, or its device has been deleted and the window cannot be '
            + 'rebuilt. The frozen document remains readable and verifiable.',
        );
      }
      res.json({ success: true, data: out });
    } catch (err) {
      next(mapError(err));
    }
  },

  /**
   * GET /api/attestation/ledger — the tenant's append-only chain.
   *
   * Its own route because C11 lists `audit_log` as a product surface in its own
   * right, not only as a section of an attestation.
   */
  async ledger(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(
        z.object({
          action: z.string().max(64).optional(),
          entityType: z.string().max(48).optional(),
          entityId: z.string().max(64).optional(),
          from: isoDate.optional(),
          to: isoDate.optional(),
          limit: z.coerce.number().int().min(1).max(500).optional(),
          offset: z.coerce.number().int().min(0).optional(),
        }),
        req.query,
      );
      const rows = await auditLog.listAudit(req.tenantId, {
        action: q.action,
        entityType: q.entityType,
        entityId: q.entityId,
        from: q.from ? new Date(q.from) : undefined,
        to: q.to ? new Date(q.to) : undefined,
        limit: q.limit,
        offset: q.offset,
      });
      res.json({ success: true, data: rows });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** GET /api/attestation/method — the verification procedure on its own, so a
   *  reader can fetch the spec without holding a document. */
  method(_req: Request, res: Response): void {
    res.json({
      success: true,
      data: { method: ATTESTATION_METHOD, defaultMaxGapDays: DEFAULT_MAX_GAP_DAYS },
    });
  },
};
