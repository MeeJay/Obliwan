/**
 * The Intent Compiler (K4) — HTTP layer.
 *
 * ┌─ WHY A CAPABILITY REFUSAL IS A 422 AND NOT A 500 ─────────────────────────┐
 * │ "This site cannot be built on that box, because that brand cannot do X"   │
 * │ is not a failure of the server. It is the ANSWER — the one that lets a    │
 * │ technician who only knows MikroTik decide, before ordering hardware and   │
 * │ before driving anywhere, that a Vigor will not do. It comes back with the │
 * │ full list of gaps, each naming the capability, the brand and the line of  │
 * │ the intent that asked for it. A 500 with "compilation failed" would send  │
 * │ the reader straight back to asking the senior engineer, which is the      │
 * │ thing this milestone exists to stop.                                      │
 * │                                                                          │
 * │ `POST /:id/compile` goes further and answers 200 with a row per target:   │
 * │ a request for four brands where three are refused must show the fourth,   │
 * │ not hide it behind the first refusal.                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING HERE TOUCHES AN EQUIPMENT ───────────────────────────────────────┐
 * │ Compiling reads `devices` and `device_capabilities` and writes two        │
 * │ tables. It opens no transport, decrypts no credential and dials nothing.  │
 * │ Applying a compiled artefact is M6's job, inside a `change_jobs` row      │
 * │ (D3), and no route below can reach it.                                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ §8.2 ────────────────────────────────────────────────────────────────────┐
 * │ Every artefact this controller returns is the redacted one; the compiler  │
 * │ has no way to produce another, because the intent has no field a secret   │
 * │ can be typed into. That is why the artefact is readable behind            │
 * │ CONFIG_READ rather than behind SECRET_READ.                               │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { DEVICE_FAMILIES } from '@obliwan/shared';
import { SiteIntentDocument } from '@obliwan/shared/dist/intent';
import { AppError } from '../middleware/errorHandler';
import { brandCoverage, capabilityCheckMany } from '../services/intent/capabilityCheck';
import { renderableFamilies } from '../services/intent/brandProfiles';
import * as store from '../services/intent/intentStore.service';

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

/**
 * A validation failure on an intent has to say WHICH field, because the intent
 * is a document a human writes: "Validation failed" on a 40-field site design
 * is indistinguishable from a broken server.
 */
function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (result.success) return result.data;
  const issues = result.error.issues
    .slice(0, 12)
    .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
    .join('; ');
  throw new AppError(400, `Invalid intent — ${issues}`);
}

const intentBody = z
  .object({
    siteId: z.number().int().positive().nullable().optional(),
    intent: SiteIntentDocument,
    isPublished: z.boolean().optional(),
  })
  .strict();

const checkBody = z
  .object({
    intent: SiteIntentDocument,
    families: z.array(z.enum(DEVICE_FAMILIES)).min(1).max(DEVICE_FAMILIES.length).optional(),
  })
  .strict();

const compileBody = z
  .object({
    deviceIds: z.array(z.number().int().positive()).max(200).optional(),
    families: z.array(z.enum(DEVICE_FAMILIES)).max(DEVICE_FAMILIES.length).optional(),
  })
  .strict();

export const intentController = {
  /**
   * GET /api/intent/capabilities
   *
   * The whole brand matrix: what each family can express, what our driver
   * declares, and where no renderer exists. Risk R2 says the coverage per brand
   * must be VISIBLE rather than implied, or the product re-creates the
   * "TR-069 covers everything" expectation it exists to correct.
   */
  capabilities(_req: Request, res: Response, next: NextFunction): void {
    try {
      res.json({ renderable: renderableFamilies(), brands: brandCoverage() });
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/intent/check
   *
   * The cheapest useful thing in the milestone: an intent that is not stored
   * yet, checked against every family, with no device, no session and no
   * network. This is the editor's live "which of my brands could take this
   * site" panel.
   */
  check(req: Request, res: Response, next: NextFunction): void {
    try {
      const { intent, families } = parse(checkBody, req.body);
      const verdicts = capabilityCheckMany(intent, families ?? DEVICE_FAMILIES);
      res.json({
        ok: verdicts.every((v) => v.ok),
        verdicts,
      });
    } catch (err) {
      next(err);
    }
  },

  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await store.listIntents(req.tenantId));
    } catch (err) {
      next(err);
    }
  },

  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await store.getIntent(req.tenantId, parseId(req.params.id)));
    } catch (err) {
      next(err);
    }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { intent, siteId } = parse(intentBody, req.body);
      const row = await store.createIntent(req.tenantId, req.session?.userId ?? null, {
        siteId: siteId ?? null,
        body: intent,
      });
      res.status(201).json(row);
    } catch (err) {
      next(err);
    }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { intent, siteId, isPublished } = parse(intentBody, req.body);
      res.json(
        await store.updateIntent(req.tenantId, parseId(req.params.id), {
          // Passed THROUGH, `undefined` included. `?? null` here is what made
          // `updateIntent`'s three-state `siteId` unreachable: a PATCH that
          // never mentioned a site arrived as an explicit "unfile it" and the
          // intent lost its site with no error. See `IntentUpdateInput`.
          siteId,
          body: intent,
          isPublished,
        }),
      );
    } catch (err) {
      next(err);
    }
  },

  async remove(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      await store.deleteIntent(req.tenantId, parseId(req.params.id));
      res.status(204).end();
    } catch (err) {
      next(err);
    }
  },

  /**
   * POST /api/intent/:id/compile
   *
   * 200 with one row per target, refusals included. The status code describes
   * whether the SERVER did its job, not whether every brand can build the site.
   */
  async compile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(compileBody, req.body ?? {});
      const { intent, results } = await store.compileAndStore(
        req.tenantId,
        req.session?.userId ?? null,
        parseId(req.params.id),
        body,
      );
      res.json({
        intent: { id: intent.id, slug: intent.slug, revision: intent.revision },
        compiled: results.filter((r) => r.ok).length,
        refused: results.filter((r) => !r.ok).length,
        results,
      });
    } catch (err) {
      next(err);
    }
  },

  async compilations(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await store.listCompilations(req.tenantId, parseId(req.params.id)));
    } catch (err) {
      next(err);
    }
  },

  /** The artefact and the desired NCM — the two large columns, fetched only
   *  when somebody actually opens one compilation. */
  async compilation(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const intentId = parseId(req.params.id);
      const compilationId = req.params.compilationId;
      if (!/^\d+$/.test(compilationId)) throw new AppError(400, 'Invalid compilation id');
      res.json(await store.getCompilation(req.tenantId, intentId, compilationId));
    } catch (err) {
      next(err);
    }
  },

  async gaps(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await store.listGaps(req.tenantId, parseId(req.params.id)));
    } catch (err) {
      next(err);
    }
  },
};
