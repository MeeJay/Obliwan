import { z } from 'zod';
import {
  DEVICE_FAMILIES,
  DEVICE_ROLES,
  DEVICE_STATUSES,
  TRANSPORT_KINDS,
} from '@obliwan/shared';

/**
 * Devices and transports — validation.
 *
 * Two things this file refuses on purpose:
 *
 *  - `brand`. It is derived from `family` server-side (FAMILY_BRAND). Accepting
 *    both invites a request where they disagree, and every driver lookup after
 *    that resolves to the wrong dialect.
 *
 *  - a secret inside `params`. `params` is transport-specific knobs and is
 *    stored in clear jsonb; credentials go in `secret` / `privateKey`, which are
 *    encrypted before they touch a column. The check below is a guard rail, not
 *    a security boundary — but it catches the honest mistake, which is the one
 *    that actually happens.
 */

const familyEnum = z.enum(DEVICE_FAMILIES as unknown as [string, ...string[]]);
const roleEnum = z.enum(DEVICE_ROLES as unknown as [string, ...string[]]);
const statusEnum = z.enum(DEVICE_STATUSES as unknown as [string, ...string[]]);
const transportEnum = z.enum(TRANSPORT_KINDS as unknown as [string, ...string[]]);

/** Loose on purpose: Postgres `inet` is the real validator, and it is stricter
 *  and more correct than any regex written here would be. This only rejects the
 *  obviously-not-an-address so the error arrives as a 400, not a 500. */
const ipish = z
  .string()
  .min(2)
  .max(64)
  .regex(/^[0-9a-fA-F.:]+$/, 'expected an IPv4 or IPv6 address');

const SECRET_KEY_HINT = /(pass|secret|psk|token|key|community|credential)/i;

const paramsSchema = z
  .record(z.unknown())
  .refine(
    (params) =>
      !Object.entries(params).some(
        ([k, v]) => SECRET_KEY_HINT.test(k) && typeof v === 'string' && v.length > 0,
      ),
    {
      message:
        'params must not carry a credential — use `secret` / `privateKey`, which are encrypted (section 8.2)',
    },
  );

export const createDeviceSchema = z.object({
  name: z.string().min(1).max(255),
  family: familyEnum,
  role: roleEnum.optional(),
  siteId: z.number().int().positive().nullable().optional(),
  groupId: z.number().int().positive().nullable().optional(),
  model: z.string().max(128).nullable().optional(),
  serial: z.string().max(128).nullable().optional(),
  osVersion: z.string().max(64).nullable().optional(),
  concentratorId: z.number().int().positive().nullable().optional(),
  pppUsername: z.string().min(1).max(128).nullable().optional(),
  systemIdentity: z.string().max(128).nullable().optional(),
  tunnelIp: ipish.nullable().optional(),
  wanPublicIp: ipish.nullable().optional(),
  sourceIpHint: ipish.nullable().optional(),
  status: statusEnum.optional(),
  isManaged: z.boolean().optional(),
  notes: z.string().max(4000).nullable().optional(),
});

export const updateDeviceSchema = createDeviceSchema.partial();

/**
 * Declaring the concentrator. It is a device like any other, but the fleet has
 * exactly one job for it, so it gets its own shape: a CHR with no reachable
 * RouterOS API is useless, and asking for the credential in the same call is
 * what makes "declare the CHR" a single operator gesture.
 */
export const createConcentratorSchema = z.object({
  name: z.string().min(1).max(255),
  family: familyEnum.default('mikrotik_routeros7'),
  host: z.string().min(1).max(255),
  port: z.number().int().min(1).max(65535).optional(),
  username: z.string().min(1).max(128),
  password: z.string().min(1).max(512),
  useTls: z.boolean().optional(),
  tlsFingerprintSha256: z
    .string()
    .regex(/^[0-9a-fA-F:]{64,95}$/, 'expected a SHA-256 hex fingerprint')
    .nullable()
    .optional(),
  siteId: z.number().int().positive().nullable().optional(),
  systemIdentity: z.string().max(128).nullable().optional(),
  notes: z.string().max(4000).nullable().optional(),
});

export const upsertTransportSchema = z.object({
  enabled: z.boolean().optional(),
  priority: z.number().int().min(0).max(1000).optional(),
  host: z.string().max(255).nullable().optional(),
  port: z.number().int().min(1).max(65535).nullable().optional(),
  username: z.string().max(128).nullable().optional(),
  /** Plaintext in; ciphertext stored. Omit to keep the stored one, send `null`
   *  to delete it. It is never echoed back by any response shape. */
  secret: z.string().max(4096).nullable().optional(),
  privateKey: z.string().max(16384).nullable().optional(),
  useTls: z.boolean().optional(),
  tlsFingerprintSha256: z
    .string()
    .regex(/^[0-9a-fA-F:]{64,95}$/)
    .nullable()
    .optional(),
  params: paramsSchema.optional(),
});

export const transportParamSchema = z.object({
  transport: transportEnum,
});

export const listDevicesQuerySchema = z.object({
  siteId: z.coerce.number().int().positive().optional(),
  role: roleEnum.optional(),
  status: statusEnum.optional(),
  brand: z.string().max(32).optional(),
  family: familyEnum.optional(),
  concentratorId: z.coerce.number().int().positive().optional(),
  search: z.string().max(255).optional(),
  limit: z.coerce.number().int().min(1).max(500).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

// ── Discoveries ─────────────────────────────────────────────────────────────

export const listDiscoveriesQuerySchema = z.object({
  state: z.enum(['pending', 'bound', 'ignored']).optional(),
  concentratorId: z.coerce.number().int().positive().optional(),
  search: z.string().max(255).optional(),
  limit: z.coerce.number().int().min(1).max(500).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

export const scanDiscoveriesSchema = z.object({
  concentratorId: z.number().int().positive(),
});

/**
 * Binding a quarantined PPP username.
 *
 * Either to an existing device, or to one created on the spot. Both paths are
 * an explicit human gesture — there is deliberately no "bind everything"
 * variant, because the whole value of the quarantine is that somebody looked
 * (risk R4).
 */
export const bindDiscoverySchema = z
  .object({
    deviceId: z.number().int().positive().optional(),
    device: createDeviceSchema
      .omit({ pppUsername: true, concentratorId: true })
      .optional(),
  })
  .refine((v) => (v.deviceId === undefined) !== (v.device === undefined), {
    message: 'provide either deviceId (bind to an existing device) or device (create one)',
  });

export const setDiscoveryStateSchema = z.object({
  state: z.enum(['pending', 'ignored']),
});

export type CreateDeviceInput = z.infer<typeof createDeviceSchema>;
export type UpdateDeviceInput = z.infer<typeof updateDeviceSchema>;
export type CreateConcentratorInput = z.infer<typeof createConcentratorSchema>;
export type UpsertTransportInput = z.infer<typeof upsertTransportSchema>;
export type BindDiscoveryInput = z.infer<typeof bindDiscoverySchema>;

/**
 * Single-device enrolment FROM THE UI (M15, second path).
 *
 * ┌─ WHY IT IS NOT THE BENCH PAYLOAD WITH A FLAG ────────────────────────────┐
 * │ The two flows look alike and their secret policy is OPPOSITE. On a bench, │
 * │ the factory password never leaves the preparer's workstation and no       │
 * │ credential is transmitted. Here the operator types the credential ObliWAN │
 * │ will keep, and it goes STRAIGHT TO THE VAULT.                             │
 * │                                                                          │
 * │ One route with a boolean would make that difference a runtime branch      │
 * │ instead of a capability boundary — and `CREDENTIAL_MANAGE` is exactly the │
 * │ line that must separate them.                                            │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export const enrollDeviceSchema = z.object({
  name: z.string().min(1).max(255),
  family: familyEnum,
  transport: z.enum(['routeros_api', 'ssh', 'rest', 'snmp']).optional(),
  host: z.string().min(1).max(255),
  port: z.number().int().min(1).max(65535).optional(),
  username: z.string().min(1).max(128),
  password: z.string().min(1).max(512),
  useTls: z.boolean().optional(),
  siteId: z.number().int().positive().nullable().optional(),
  notes: z.string().max(4000).nullable().optional(),
});
export type EnrollDeviceInput = z.infer<typeof enrollDeviceSchema>;
