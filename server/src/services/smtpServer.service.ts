import { db } from '../db';
import nodemailer from 'nodemailer';
import { logger } from '../utils/logger';
import type { SmtpServer } from '@obliwan/shared';

interface SmtpServerRow {
  id: number;
  name: string;
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  from_address: string;
  tenant_id: number | null;
  created_at: Date;
  updated_at: Date;
}

function rowToServer(row: SmtpServerRow): SmtpServer {
  return {
    id: row.id,
    name: row.name,
    host: row.host,
    port: row.port,
    secure: row.secure,
    username: row.username,
    fromAddress: row.from_address,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

/**
 * SMTP relays are of two kinds, and the difference is a security boundary.
 *
 *  - `tenant_id = <id>`  : a CUSTOMER's private relay. Its operator sees every
 *    envelope that goes through it.
 *  - `tenant_id IS NULL` : a PLATFORM relay, owned by the operator of the
 *    ObliWAN instance. This is the only kind that may legitimately carry
 *    instance-wide mail — login OTPs and password-reset links, whose recipients
 *    are users of EVERY tenant.
 *
 * VERIF-SECFIX-AUTRES #5 — the second kind had become unreachable: the create
 * route sits under `tenantRouter` and always wrote `req.tenantId`, so the
 * `whereNull('tenant_id')` branch of `list()` was dead code and `app_config`'s
 * `otp_smtp_server_id` — a single value for the whole instance — could only
 * ever point at one customer's private relay. Acme's postmaster would then read
 * Globex's OTP codes and reset links in his MTA log, and deleting the Acme
 * tenant (ON DELETE CASCADE) would silently stop authentication mail for
 * everybody.
 *
 * The rule enforced below: a lookup with NO tenant means "instance-wide use",
 * and only a platform relay answers it. A lookup WITH a tenant accepts that
 * tenant's own relay or a platform relay, never another tenant's.
 */
export const smtpServerService = {
  /**
   * Relays usable from `tenantId`: its own plus the platform ones.
   * `undefined` means the platform scope alone.
   */
  async list(tenantId?: number): Promise<SmtpServer[]> {
    const query = db<SmtpServerRow>('smtp_servers').orderBy('name');
    if (tenantId !== undefined) {
      // The platform relays are included on purpose: they are the ones the
      // instance operator expects to see and pick, and before this change no
      // route could display them at all.
      query.where(function () {
        this.where('tenant_id', tenantId).orWhereNull('tenant_id');
      });
    } else {
      query.whereNull('tenant_id');
    }
    const rows = await query;
    return rows.map(rowToServer);
  },

  /**
   * Raw row by id, with NO tenant filter.
   *
   * Reserved for the admin CRUD routes, which are `requireRole('admin')` and
   * address relays by id across the whole instance. Never use it to decide
   * whether a relay may be USED on behalf of a tenant — that is `getById`.
   */
  async _rowById(id: number): Promise<SmtpServerRow | null> {
    const row = await db<SmtpServerRow>('smtp_servers').where({ id }).first();
    return row || null;
  },

  /**
   * A relay `tenantId` is allowed to use.
   *
   * `tenantId === undefined` is the INSTANCE scope (OTP, password reset): only
   * a platform relay qualifies. This is what stops `otp_smtp_server_id` from
   * designating a customer's private server.
   */
  async getById(id: number, tenantId?: number): Promise<SmtpServerRow | null> {
    const query = db<SmtpServerRow>('smtp_servers').where({ id });
    if (tenantId === undefined) {
      query.whereNull('tenant_id');
    } else {
      query.where(function () {
        this.where('tenant_id', tenantId).orWhereNull('tenant_id');
      });
    }
    const row = await query.first();
    if (!row) {
      // Say WHY rather than let the caller report a bare "not configured": the
      // most likely cause is an instance-wide setting still pointing at a relay
      // that belongs to a customer, and that diagnosis is not guessable from
      // the outside.
      const anywhere = await this._rowById(id);
      if (anywhere) {
        logger.warn(
          `SMTP relay #${id} ("${anywhere.name}") belongs to tenant ${anywhere.tenant_id} and was ` +
            (tenantId === undefined
              ? 'refused for instance-wide mail (OTP / password reset): that mail reaches users of every tenant, ' +
                'so it must go through a PLATFORM relay (smtp_servers.tenant_id IS NULL).'
              : `refused for tenant ${tenantId}.`),
        );
      }
      return null;
    }
    return row;
  },

  /** True when `tenantId` may reference this relay (own relay or platform relay). */
  async isUsableBy(id: number, tenantId: number): Promise<boolean> {
    return (await this.getById(id, tenantId)) !== null;
  },

  /*
   * VERDICT-CONSOLIDATION §3.3.2 — `isPlatformRelay(id)` used to live here and
   * `grep -rn isPlatformRelay server/src` returned nothing but its own
   * declaration. It had been written for `appConfigController.set`, so that
   * `otp_smtp_server_id` could not be pointed at a customer's private relay at
   * the moment it is typed. That controller never called it.
   *
   * A dead guard is worse than an absent one: the next reader greps the name,
   * finds a function whose body states the rule, and concludes the rule is
   * enforced. It is the exact shape this pass closed under #10
   * (`assertVaultUsable` without a caller), reopened one file to the left, and
   * it is why the SMTP half of the audit looked finished while the instance
   * mail was in fact dying at send time.
   *
   * It is DELETED rather than wired, because wiring it means editing
   * `appConfig.controller.ts`, which is not this agent's file. Nothing is lost:
   * the rule itself is enforced — `getById(id)` with no tenant already refuses
   * anything but a platform relay, and that is the call every instance-mail
   * path makes (`getTransportConfig(id)` with no tenant, from the OTP and
   * password-reset senders). What is missing is only the EARLY refusal.
   *
   * To restore it, in `appConfigController.set`:
   *
   *     if (key === 'otp_smtp_server_id' && String(value) !== '') {
   *       const relay = await smtpServerService.getById(Number(value));
   *       if (!relay) throw new AppError(400,
   *         'otp_smtp_server_id must designate a PLATFORM relay ' +
   *         '(smtp_servers.tenant_id IS NULL): OTP and password-reset mail ' +
   *         'reaches users of every tenant.');
   *     }
   */

  async create(data: {
    name: string;
    host: string;
    port: number;
    secure: boolean;
    username: string;
    password: string;
    fromAddress: string;
    tenantId?: number;
    /**
     * Create a PLATFORM relay (`tenant_id NULL`) instead of a tenant one.
     * Wins over `tenantId`, which every caller under `tenantRouter` fills in
     * unconditionally — that is precisely why the platform kind had become
     * impossible to create.
     */
    isPlatform?: boolean;
  }): Promise<SmtpServer> {
    const [row] = await db<SmtpServerRow>('smtp_servers')
      .insert({
        name: data.name,
        host: data.host,
        port: data.port,
        secure: data.secure,
        username: data.username,
        password: data.password,
        from_address: data.fromAddress,
        tenant_id: data.isPlatform === true ? null : (data.tenantId ?? null),
      })
      .returning('*');
    return rowToServer(row);
  },

  /**
   * Resolve a relay the caller is allowed to MUTATE.
   *
   * Deliberately stricter than `getById`, which answers "may this tenant SEND
   * through it" and therefore also accepts the platform relay. Being allowed to
   * send through the instance relay must not imply being allowed to repoint it:
   * that relay carries the OTP and password-reset mail of every tenant.
   */
  async _resolveForMutation(
    id: number,
    tenantId: number | undefined,
    isPlatformAdmin: boolean,
  ): Promise<SmtpServerRow | null> {
    const row = await this._rowById(id);
    if (!row) return null;
    if (row.tenant_id === null) return isPlatformAdmin ? row : null;
    if (isPlatformAdmin && tenantId === undefined) return row;
    return row.tenant_id === tenantId ? row : null;
  },

  async update(id: number, data: Partial<{
    name: string;
    host: string;
    port: number;
    secure: boolean;
    username: string;
    password: string;
    fromAddress: string;
  }>, scope?: { tenantId: number | undefined; isPlatformAdmin: boolean }): Promise<SmtpServer | null> {
    if (scope && !(await this._resolveForMutation(id, scope.tenantId, scope.isPlatformAdmin))) return null;
    const update: Record<string, unknown> = { updated_at: new Date() };
    if (data.name !== undefined) update.name = data.name;
    if (data.host !== undefined) update.host = data.host;
    if (data.port !== undefined) update.port = data.port;
    if (data.secure !== undefined) update.secure = data.secure;
    if (data.username !== undefined) update.username = data.username;
    if (data.password !== undefined) update.password = data.password;
    if (data.fromAddress !== undefined) update.from_address = data.fromAddress;

    const [row] = await db<SmtpServerRow>('smtp_servers').where({ id }).update(update).returning('*');
    return row ? rowToServer(row) : null;
  },

  async delete(id: number, scope?: { tenantId: number | undefined; isPlatformAdmin: boolean }): Promise<boolean> {
    if (scope && !(await this._resolveForMutation(id, scope.tenantId, scope.isPlatformAdmin))) return false;
    const count = await db('smtp_servers').where({ id }).del();
    return count > 0;
  },

  async test(id: number, scope?: { tenantId: number | undefined; isPlatformAdmin: boolean }): Promise<void> {
    const row = scope
      ? await this._resolveForMutation(id, scope.tenantId, scope.isPlatformAdmin)
      : await this._rowById(id);
    if (!row) throw new Error('SMTP server not found');

    const transport = nodemailer.createTransport({
      host: row.host,
      port: row.port,
      secure: row.secure,
      auth: { user: row.username, pass: row.password },
    });

    await transport.verify();
  },

  /**
   * Build a nodemailer transport config from a server row.
   *
   * `tenantId` omitted = instance scope (password reset, OTP): a customer's
   * relay is refused with `null`, which the callers already surface as
   * "SMTP server not configured".
   */
  async getTransportConfig(
    id: number,
    tenantId?: number,
  ): Promise<{ host: string; port: number; secure: boolean; username: string; password: string; fromAddress: string } | null> {
    const row = await this.getById(id, tenantId);
    if (!row) return null;
    return {
      host: row.host,
      port: row.port,
      secure: row.secure,
      username: row.username,
      password: row.password,
      fromAddress: row.from_address,
    };
  },
};
