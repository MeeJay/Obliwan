/**
 * ObliWAN — per-tenant ACS settings, and the routing of a CPE to a tenant.
 *
 * ┌─ THE TENANT IS IN THE URL, AND THERE IS NOWHERE ELSE TO PUT IT ───────────┐
 * │ A CPE has no session, no cookie of ours before the first Inform, and no   │
 * │ header saying who it belongs to. All it has is the ACS URL it was         │
 * │ provisioned with — burned into the box by whoever installed it. So the    │
 * │ listener routes on `POST /<tenant_slug>` and this service is the lookup.  │
 * │                                                                          │
 * │ CONSEQUENCE, and it is why `tenant_slug` is UNIQUE and effectively        │
 * │ immutable: changing a slug orphans every CPE in that tenant until each    │
 * │ one is re-provisioned by hand, on site. The API refuses the rename rather │
 * │ than performing it (see `acs.controller.ts`).                             │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * The cache exists because this lookup runs on EVERY POST of every session of
 * every CPE — 300 boxes at a 300 s interval is one lookup a second, and each
 * one would otherwise be a round trip to Postgres to fetch a row that changes
 * about twice a year. 30 s of staleness is the price, and it is bounded: an
 * operator who flips `allow_auto_enroll` waits half a minute.
 */

import { db } from '../../db';
import { logger } from '../../utils/logger';

export interface AcsSettings {
  id: number;
  tenantId: number;
  tenantSlug: string;
  digestRealm: string;
  trustedCidrs: string[];
  allowAutoEnroll: boolean;
  rpcLogEnabled: boolean;
  defaultPeriodicInformInterval: number;
}

interface SettingsRow {
  id: number;
  tenant_id: number;
  tenant_slug: string;
  digest_realm: string;
  trusted_cidrs: string[] | null;
  allow_auto_enroll: boolean;
  rpc_log_enabled: boolean;
  default_periodic_inform_interval: number;
}

const CACHE_TTL_MS = 30_000;
const cache = new Map<string, { at: number; value: AcsSettings | null }>();

function toSettings(row: SettingsRow): AcsSettings {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    tenantSlug: row.tenant_slug,
    digestRealm: row.digest_realm,
    trustedCidrs: row.trusted_cidrs ?? [],
    allowAutoEnroll: row.allow_auto_enroll,
    rpcLogEnabled: row.rpc_log_enabled,
    defaultPeriodicInformInterval: row.default_periodic_inform_interval,
  };
}

/** Drop the cache. Called by the controller after any write. */
export function invalidateAcsSettings(): void {
  cache.clear();
}

/**
 * The tenant a CPE calling `/<slug>` belongs to.
 *
 * Returns null for an unknown slug, and the listener answers 404. It does NOT
 * fall back to a default tenant: a fallback here would mean that a typo in one
 * CPE's provisioning silently files it under somebody else's customer, which is
 * risk R4 wearing a TR-069 hat.
 */
export async function settingsForSlug(slug: string): Promise<AcsSettings | null> {
  const key = slug.toLowerCase();
  const hit = cache.get(key);
  const now = Date.now();
  if (hit && now - hit.at < CACHE_TTL_MS) return hit.value;

  const row = (await db('cwmp_acs_settings')
    .where({ tenant_slug: key })
    .first()) as SettingsRow | undefined;

  const value = row ? toSettings(row) : null;
  cache.set(key, { at: now, value });
  return value;
}

export async function settingsForTenant(tenantId: number): Promise<AcsSettings | null> {
  const row = (await db('cwmp_acs_settings')
    .where({ tenant_id: tenantId })
    .first()) as SettingsRow | undefined;
  return row ? toSettings(row) : null;
}

/**
 * Create the ACS settings row for a tenant, or return the existing one.
 *
 * The slug defaults to the tenant's own slug when it has one — an operator
 * should not have to invent a second name for the same customer — and falls
 * back to `t<id>`, which is ugly, unique and never empty.
 */
export async function ensureSettingsForTenant(tenantId: number): Promise<AcsSettings> {
  const existing = await settingsForTenant(tenantId);
  if (existing) return existing;

  const tenant = (await db('tenants').where({ id: tenantId }).first('slug', 'name')) as
    | { slug?: string | null; name?: string | null }
    | undefined;

  const candidate = slugify(tenant?.slug || tenant?.name || '') || `t${tenantId}`;
  const slug = await uniqueSlug(candidate);

  const [row] = (await db('cwmp_acs_settings')
    .insert({ tenant_id: tenantId, tenant_slug: slug })
    .returning('*')) as SettingsRow[];

  invalidateAcsSettings();
  logger.info({ tenantId, slug }, 'ACS: settings row created for tenant');
  return toSettings(row);
}

export async function updateSettings(
  tenantId: number,
  patch: Partial<{
    digestRealm: string;
    trustedCidrs: string[];
    allowAutoEnroll: boolean;
    rpcLogEnabled: boolean;
    defaultPeriodicInformInterval: number;
  }>,
): Promise<AcsSettings> {
  const update: Record<string, unknown> = { updated_at: db.fn.now() };
  if (patch.digestRealm !== undefined) update.digest_realm = patch.digestRealm;
  if (patch.trustedCidrs !== undefined) update.trusted_cidrs = patch.trustedCidrs;
  if (patch.allowAutoEnroll !== undefined) update.allow_auto_enroll = patch.allowAutoEnroll;
  if (patch.rpcLogEnabled !== undefined) update.rpc_log_enabled = patch.rpcLogEnabled;
  if (patch.defaultPeriodicInformInterval !== undefined) {
    update.default_periodic_inform_interval = patch.defaultPeriodicInformInterval;
  }

  await db('cwmp_acs_settings').where({ tenant_id: tenantId }).update(update);
  invalidateAcsSettings();

  const after = await settingsForTenant(tenantId);
  if (!after) throw new Error(`ACS settings for tenant ${tenantId} disappeared mid-update`);
  return after;
}

// ============================================================================
// Source address filtering
// ============================================================================

/**
 * Is `ip` inside one of `cidrs`?
 *
 * An EMPTY list means "no restriction", and that is the shipped default on
 * purpose: a CPE behind carrier NAT has a public address that changes with the
 * line, sometimes daily. A default-deny here would look like security and would
 * in practice be a fleet that stops reporting after the first PPPoE
 * renegotiation — so the real gate is the Digest credential, and this is the
 * optional second one for deployments where the CPEs sit behind a known range.
 *
 * Implemented on the raw bytes rather than with `ip-address` because it must
 * accept an IPv4-mapped IPv6 address (`::ffff:81.250.14.7`), which is what
 * Node hands you on a dual-stack listener and what makes every "why does my
 * CIDR not match" bug in this class.
 */
export function ipMatchesCidrs(ip: string, cidrs: readonly string[]): boolean {
  if (cidrs.length === 0) return true;
  const addr = normaliseIp(ip);
  if (!addr) return false;
  return cidrs.some((cidr) => ipInCidr(addr, cidr));
}

function normaliseIp(ip: string): string | null {
  if (!ip) return null;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return mapped ? mapped[1] : ip;
}

function ipInCidr(ip: string, cidr: string): boolean {
  const [network, bitsRaw] = cidr.split('/');
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;

  const a = ipv4ToInt(ip);
  const b = ipv4ToInt(network);
  if (a === null || b === null) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : ~((1 << (32 - bits)) - 1) >>> 0;
  return (a & mask) >>> 0 === (b & mask) >>> 0;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out = ((out << 8) | n) >>> 0;
  }
  return out;
}

// ============================================================================
// Slugs
// ============================================================================

export function slugify(input: string): string {
  return input
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}

async function uniqueSlug(base: string): Promise<string> {
  let candidate = base;
  for (let i = 2; i < 100; i++) {
    const clash = await db('cwmp_acs_settings').where({ tenant_slug: candidate }).first('id');
    if (!clash) return candidate;
    candidate = `${base.slice(0, 60)}-${i}`;
  }
  throw new Error(`could not derive a free ACS slug from "${base}"`);
}
