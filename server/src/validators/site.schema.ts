import { z } from 'zod';

/**
 * Sites — validation.
 *
 * `code` is the operator-facing short key (unique per tenant, see migration
 * 002). It is constrained to a slug so that it can safely appear in a bundle
 * filename, a template variable and a URL without escaping rules diverging
 * between the three.
 */

const timeOfDay = z
  .string()
  .regex(/^([01]\d|2[0-3]):[0-5]\d$/, 'expected HH:MM');

/** The window that will gate every push from M6. Kept deliberately small and
 *  explicit rather than an opaque blob: the change scheduler has to be able to
 *  reason about it without a parser of its own. */
export const maintenanceWindowSchema = z
  .object({
    // 0 = Sunday, matching JS `Date.getDay()`.
    days: z.array(z.number().int().min(0).max(6)).min(1).max(7),
    start: timeOfDay,
    end: timeOfDay,
    tz: z.string().min(1).max(64).optional(),
  })
  .strict();

export const createSiteSchema = z.object({
  code: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/, 'letters, digits, dot, dash and underscore only'),
  name: z.string().min(1).max(255),
  address: z.string().max(2000).nullable().optional(),
  contact: z.string().max(500).nullable().optional(),
  timezone: z.string().min(1).max(64).optional(),
  maintenanceWindow: maintenanceWindowSchema.nullable().optional(),
});

export const updateSiteSchema = createSiteSchema.partial();

export const listSitesQuerySchema = z.object({
  search: z.string().max(255).optional(),
});

export type CreateSiteInput = z.infer<typeof createSiteSchema>;
export type UpdateSiteInput = z.infer<typeof updateSiteSchema>;
