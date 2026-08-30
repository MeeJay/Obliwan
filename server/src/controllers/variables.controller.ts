// ============================================================================
// ObliWAN — template variables : HTTP layer
// ============================================================================
//
// The three rules of `templates.controller.ts` apply verbatim, and one of them
// is sharper here:
//
//  1. THE TENANT IS ALWAYS `req.tenantId`. `config_variables.tenant_id` is NOT
//     NULL — there is no cross-tenant variable library and there must never be
//     one, because a variable is a customer's addressing plan.
//
//  2. A CROSS-TENANT ID IS A 404. `variableResolver` already answers
//     "Device #7 does not exist in tenant #2" for a device it cannot see; this
//     file turns that into a 404 rather than a 500.
//
//  3. READING A VARIABLE IS NOT READING ITS VALUE. A secret variable comes back
//     as `__OBLIWAN_SECRET_<KEY>__` with a keyed fingerprint, at EVERY level of
//     this API, with no query parameter, header or admin flag that changes it
//     (§8.2). The plaintext exists in memory only, on the vault -> equipment
//     path, and M5 has no such path. If you are looking for the endpoint that
//     reveals a secret: it does not exist, which is why it cannot be
//     mis-permissioned.
//
// RBAC: reading resolved variables is `TEMPLATE_READ`; writing one is
// `TEMPLATE_WRITE`. A variable is an input to a rendered template, so whoever
// can set one can change what the server will push — the same class of act as
// authoring the template, and the same capability.

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { AppError } from '../middleware/errorHandler';
import { db } from '../db';
import {
  setVariableSchema, setVariablesBulkSchema, VARIABLE_SCOPES,
} from '../validators/template.schema';
import {
  variableResolver, VariableResolutionError, VarSchemaError,
  type JsonValue, type VariableScope, type VarSchema,
} from '../services/template/variableResolver.service';

// ============================================================================
// Params
// ============================================================================

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

/**
 * `scope` + optional `scopeId` from the path, with migration 008's own rule
 * applied: `global` and `tenant` carry NO scope id (their identity is the
 * tenant), `group` and `device` require one.
 *
 * Enforced HERE and not only in the service, because a `device` row that
 * reached the table with a NULL `scope_id` would land in the UNSCOPED partial
 * unique index and behave, silently, like a global variable for the whole
 * fleet. The database CHECK refuses it too — three layers, one rule.
 */
function parseScope(req: Request): { scope: VariableScope; scopeId: number | null } {
  const raw = req.params.scope;
  if (!(VARIABLE_SCOPES as readonly string[]).includes(raw)) {
    throw new AppError(400, `Invalid scope "${raw}". Expected one of ${VARIABLE_SCOPES.join(', ')}.`);
  }
  const scope = raw as VariableScope;
  const needsId = scope === 'group' || scope === 'device';
  const hasId = req.params.scopeId !== undefined && req.params.scopeId !== '';

  if (needsId && !hasId) throw new AppError(400, `Scope "${scope}" requires a scope id in the path.`);
  if (!needsId && hasId) {
    throw new AppError(
      400,
      `Scope "${scope}" must not carry a scope id — it is identified by the tenant.`,
    );
  }
  return { scope, scopeId: hasId ? parseId(req.params.scopeId, 'scope id') : null };
}

/**
 * A `group` or `device` scope id must belong to THIS tenant before anything is
 * written against it.
 *
 * `config_variables.scope_id` is polymorphic and therefore carries no foreign
 * key (the same trade-off `settings` and `notification_bindings` make). Nothing
 * in the schema stops `PUT /variables/device/999` from writing a row keyed on
 * another customer's device id — the read path would never surface it, but the
 * row would sit in this tenant's table forever and would become live the day
 * an id was reused. This check is the only thing that prevents it.
 */
async function assertScopeTargetOwned(
  tenantId: number,
  scope: VariableScope,
  scopeId: number | null,
): Promise<void> {
  if (scopeId === null) return;
  const table = scope === 'group' ? 'device_groups' : 'devices';
  const row = await db(table).where({ id: scopeId, tenant_id: tenantId }).first('id');
  if (!row) throw new AppError(404, `No ${scope} ${scopeId} in this tenant.`);
}

function mapError(err: unknown): unknown {
  if (err instanceof AppError) return err;
  if (err instanceof VarSchemaError) return new AppError(400, err.message);
  if (err instanceof VariableResolutionError) {
    const e = new AppError(422, err.message) as AppError & { details?: unknown };
    e.details = { missing: err.missing, typeErrors: err.typeErrors, chain: err.chain };
    return e;
  }
  if (err instanceof Error && /does not exist in tenant/.test(err.message)) {
    // The resolver's own cross-tenant refusal. Rule 2: it is a 404.
    return new AppError(404, err.message.replace(/ in tenant #\d+/, ''));
  }
  if (err instanceof Error && /^(Illegal context key|Scope |A secret|Variable )/.test(err.message)) {
    return new AppError(400, err.message);
  }
  return err;
}

const varSchemaQuery = z.object({
  /** The revision whose `var_schema` types the answer. Optional: without it the
   *  values come back untyped and nothing is reported as missing, which is the
   *  right behaviour for the "what is set here" screen. */
  revisionId: z.string().regex(/^[0-9]{1,19}$/).optional(),
});

/** Load a revision's `var_schema`, tenant-scoped (library revisions included,
 *  since a tenant may render a library template). */
async function schemaOfRevision(tenantId: number, revisionId: string): Promise<VarSchema | null> {
  const row = (await db('template_revisions')
    .where('id', revisionId)
    .whereRaw('(tenant_id = ? OR tenant_id IS NULL)', [tenantId])
    .first('var_schema')) as { var_schema: unknown } | undefined;
  if (!row) throw new AppError(404, `Template revision ${revisionId} not found`);
  return (row.var_schema ?? null) as VarSchema | null;
}

// ============================================================================
// Controller
// ============================================================================

export const variablesController = {
  /**
   * The resolved view for one device: every variable that applies, with WHERE
   * each value came from.
   *
   * This is what backs `InheritanceBadge`. `source`, `sourceId`, `sourceName`
   * and `sourceDepth` are the whole point — a value with no visible origin is a
   * value an operator cannot correct, and "why is this VLAN 300 on this site"
   * is the single most common support question a template system generates.
   *
   * Non-throwing: `missing`, `typeErrors` and `rejected` come back as lists so
   * the form can mark the offending fields instead of showing one red banner.
   */
  async forDevice(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const q = parse(varSchemaQuery, req.query);
      const schema = q.revisionId ? await schemaOfRevision(req.tenantId, q.revisionId) : null;
      const report = await variableResolver.resolveForDevice(req.tenantId, deviceId, schema);
      res.json({ success: true, data: report });
    } catch (err) { next(mapError(err)); }
  },

  /** Inherited values and this group's own overrides, kept apart so the UI can
   *  show what a group ADDS rather than a flattened list. */
  async forGroup(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const groupId = parseId(req.params.groupId, 'group id');
      await assertScopeTargetOwned(req.tenantId, 'group', groupId);
      const q = parse(varSchemaQuery, req.query);
      const schema = q.revisionId ? await schemaOfRevision(req.tenantId, q.revisionId) : null;
      const data = await variableResolver.resolveForGroup(req.tenantId, groupId, schema);
      res.json({ success: true, data });
    } catch (err) { next(mapError(err)); }
  },

  async forTenant(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(varSchemaQuery, req.query);
      const schema = q.revisionId ? await schemaOfRevision(req.tenantId, q.revisionId) : null;
      const data = await variableResolver.resolveForTenant(req.tenantId, schema);
      res.json({ success: true, data });
    } catch (err) { next(mapError(err)); }
  },

  /** Everything set AT one level, with no inheritance. The editing view. */
  async listAtScope(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { scope, scopeId } = parseScope(req);
      await assertScopeTargetOwned(req.tenantId, scope, scopeId);
      const data = await variableResolver.getByScope(req.tenantId, scope, scopeId);
      res.json({ success: true, data });
    } catch (err) { next(mapError(err)); }
  },

  /** Write ONE variable. A secret is encrypted on the way in and never comes
   *  back. */
  async setAtScope(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { scope, scopeId } = parseScope(req);
      await assertScopeTargetOwned(req.tenantId, scope, scopeId);
      const input = parse(setVariableSchema, req.body);
      await variableResolver.set(
        // `variableValue` in the validator infers as `unknown` (a recursive
        // `z.lazy` cannot infer a closed union), and the resolver's `JsonValue`
        // is the same shape stated nominally. The cast is the ONLY place the
        // two meet, and it is safe precisely because the parse above already
        // proved the value is JSON — depth-capped, no functions, no cycles.
        req.tenantId, scope, scopeId, input.key, input.value as JsonValue, input.isSecret,
        { updatedBy: req.session.userId ?? null },
      );
      res.json({
        success: true,
        message: input.isSecret
          ? `Secret variable "${input.key}" stored in the vault.`
          : `Variable "${input.key}" saved.`,
      });
    } catch (err) { next(mapError(err)); }
  },

  /** Validate EVERYTHING first, then write the lot in one transaction: a
   *  half-applied variables form leaves an operator with no way to tell which
   *  half took. The service owns that guarantee; this handler only shapes it. */
  async setBulkAtScope(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { scope, scopeId } = parseScope(req);
      await assertScopeTargetOwned(req.tenantId, scope, scopeId);
      const input = parse(setVariablesBulkSchema, req.body);
      await variableResolver.setBulk(
        req.tenantId, scope, scopeId,
        input.entries.map((e) => ({
          key: e.key,
          // Same boundary cast as `setAtScope` above, same justification.
          value: e.value as JsonValue,
          isSecret: e.isSecret,
          meta: { updatedBy: req.session.userId ?? null },
        })),
      );
      res.json({ success: true, message: `${input.entries.length} variable(s) saved.` });
    } catch (err) { next(mapError(err)); }
  },

  /**
   * Remove one variable at one level.
   *
   * The key travels in the query string, not in the path: a variable key is
   * `^[a-z][a-zA-Z0-9_]{0,119}$` and would be unambiguous as a path segment,
   * but `/variables/global/:key` and `/variables/group/:scopeId` have the same
   * arity, and a route table where `DELETE /variables/global/vlan` and
   * `DELETE /variables/group/12` are told apart by whether the last segment
   * looks numeric is a route table one rename away from deleting the wrong row.
   */
  async removeAtScope(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { scope, scopeId } = parseScope(req);
      await assertScopeTargetOwned(req.tenantId, scope, scopeId);
      const key = typeof req.query.key === 'string' ? req.query.key : '';
      if (!key) throw new AppError(400, 'The `key` query parameter is required.');
      const removed = await variableResolver.remove(req.tenantId, scope, scopeId, key);
      if (!removed) throw new AppError(404, `Variable "${key}" is not set at this level.`);
      res.json({ success: true, message: `Variable "${key}" removed.` });
    } catch (err) { next(mapError(err)); }
  },
};
