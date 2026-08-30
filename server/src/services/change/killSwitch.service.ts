// ============================================================================
// ObliWAN — the kill switch (M6, decision D3 / §8.3)
// ============================================================================
//
// The gesture somebody makes at 03:00 with one hand on the phone.
//
// ┌─ THE THREE PROPERTIES, AND ALL THREE ARE LOAD-BEARING ────────────────────┐
// │                                                                           │
// │ 1. IT IS READ JUST BEFORE THE WRITE, NOT ONLY AT ENQUEUE TIME.            │
// │    A switch that is only consulted when a job is created stops nothing:   │
// │    the whole point of the gesture is that it is made WHILE jobs are       │
// │    already running. `assertWritable()` is called by `apply.service` at    │
// │    every phase boundary and, most importantly, immediately before the     │
// │    bytes leave for the device. Between that check and the write there is  │
// │    one function call and no I/O.                                          │
// │                                                                           │
// │ 2. IT FAILS CLOSED, INCLUDING WHEN THE DATABASE IS THE THING THAT BROKE.  │
// │    `kill_switch_blocks()` (migration 009) already returns `true` when the │
// │    global row is MISSING. This module adds the other half: if the QUERY   │
// │    itself throws — pool exhausted, connection dropped, Postgres gone —    │
// │    the answer is `blocked: true`. "We could not ask whether we are        │
// │    allowed to write" is not permission to write. A kill switch that fails │
// │    open is not a kill switch.                                             │
// │                                                                           │
// │ 3. ENGAGING IS EASIER THAN RELEASING.                                     │
// │    Engaging needs no reason (a reason field that blocks the panic gesture │
// │    is a reason field that gets bypassed — migration 009 says so and the   │
// │    column is nullable for exactly that). Releasing is the act that lets   │
// │    the fleet be written to again, and the route behind it is the stricter │
// │    of the two capabilities.                                               │
// └───────────────────────────────────────────────────────────────────────────┘
//
// SCOPES. Global blocks every tenant; a tenant row blocks one. There is no
// per-device scope, on purpose: the kill switch is the blunt instrument, and a
// blunt instrument with a target selector is not blunt.

import type { Knex } from 'knex';
import {
  SOCKET_EVENTS,
  type KillSwitchDecision,
  type KillSwitchScope,
  type KillSwitchState,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { emitToTenant } from '../fleet/fleetEvents';

// ============================================================================
// Errors
// ============================================================================

/**
 * Thrown by `assertWritable()`. Carries the operator sentence so the refusal
 * that lands on the job row is the one the person who engaged the switch wrote.
 */
export class KillSwitchEngagedError extends Error {
  readonly scope: KillSwitchScope | null;
  readonly killSwitchReason: string | null;

  constructor(decision: KillSwitchDecision) {
    super(
      decision.by === null
        ? 'Refused: the write kill-switch could not be read, so no write is permitted (fail-closed).'
        : `Refused: the ${decision.by} write kill-switch is ENGAGED.` +
          (decision.reason ? ` Reason: ${decision.reason}` : ''),
    );
    this.name = 'KillSwitchEngagedError';
    this.scope = decision.by;
    this.killSwitchReason = decision.reason;
  }
}

// ============================================================================
// Rows
// ============================================================================

interface KillSwitchRow {
  id: number;
  scope: KillSwitchScope;
  tenant_id: number | null;
  engaged: boolean;
  reason: string | null;
  engaged_by: number | null;
  engaged_at: Date | null;
  released_by: number | null;
  released_at: Date | null;
  updated_at: Date;
}

function toState(row: KillSwitchRow): KillSwitchState {
  return {
    scope: row.scope,
    tenantId: row.tenant_id,
    engaged: row.engaged,
    reason: row.reason,
    engagedBy: row.engaged_by,
    engagedAt: row.engaged_at ? new Date(row.engaged_at).toISOString() : null,
    releasedBy: row.released_by,
    releasedAt: row.released_at ? new Date(row.released_at).toISOString() : null,
  };
}

// ============================================================================
// The read — property 1 and property 2
// ============================================================================

/**
 * May this tenant be written to right now?
 *
 * ONE round trip, and it reads the two rows rather than calling
 * `kill_switch_blocks()`, for one reason: the SQL function answers a boolean
 * and a refused job has to be able to TELL the operator which switch stopped it
 * and why. The fail-closed semantics of the function are reproduced here
 * exactly — a missing global row blocks — and are covered by the same test.
 *
 * ANY failure of the query itself yields `blocked: true`, `scope: null`. That
 * is the difference between "we asked and the answer was no" and "we could not
 * ask", and both must stop the write; only the message differs.
 */
export async function readKillSwitch(
  tenantId: number,
  q: Knex | Knex.Transaction = db,
): Promise<KillSwitchDecision> {
  try {
    const rows = (await q('kill_switch')
      .where(function scopeFilter(this: Knex.QueryBuilder) {
        void this.where('scope', 'global').orWhere({ scope: 'tenant', tenant_id: tenantId });
      })
      .select('*')) as KillSwitchRow[];

    const global = rows.find((r) => r.scope === 'global') ?? null;
    const tenant = rows.find((r) => r.scope === 'tenant') ?? null;

    // Fail-closed, mirroring `kill_switch_blocks()`: a missing global row is a
    // row somebody removed, and the answer to "should I write to a customer's
    // router" while the safety row is missing is no.
    if (!global) {
      logger.error(
        { tenantId },
        'Kill switch: the GLOBAL row is missing — refusing every write (fail-closed)',
      );
      return {
        blocked: true,
        by: 'global',
        reason:
          'The global kill-switch row is missing from the database. ' +
          'Writes are refused until it is restored (fail-closed).',
      };
    }

    if (global.engaged) return { blocked: true, by: 'global', reason: global.reason };
    if (tenant?.engaged) return { blocked: true, by: 'tenant', reason: tenant.reason };
    return { blocked: false, by: null, reason: null };
  } catch (err) {
    logger.error({ err, tenantId }, 'Kill switch: read FAILED — refusing every write (fail-closed)');
    return {
      blocked: true,
      by: null,
      reason:
        'The write kill-switch could not be read (database error). ' +
        'No write is permitted while its state is unknown.',
    };
  }
}

/**
 * THE call every write path makes, and it must be made again immediately before
 * the bytes go out — not once at the top of the job.
 */
export async function assertWritable(
  tenantId: number,
  q: Knex | Knex.Transaction = db,
): Promise<void> {
  const decision = await readKillSwitch(tenantId, q);
  if (decision.blocked) throw new KillSwitchEngagedError(decision);
}

/**
 * The same question answered through the database function rather than through
 * the rows. Kept as a separate, exported call so the SQL predicate that other
 * services (and any future `WHERE NOT kill_switch_blocks(tenant_id)`) rely on
 * is exercised by the same tests as the row read above. Fail-closed on error,
 * like its sibling.
 */
export async function killSwitchBlocks(
  tenantId: number,
  q: Knex | Knex.Transaction = db,
): Promise<boolean> {
  try {
    const result = (await q.raw('SELECT kill_switch_blocks(?) AS blocked', [tenantId])) as {
      rows: Array<{ blocked: boolean }>;
    };
    // A function that answered nothing is a function that did not answer.
    return result.rows[0]?.blocked !== false;
  } catch (err) {
    logger.error({ err, tenantId }, 'kill_switch_blocks() failed — treating as ENGAGED');
    return true;
  }
}

// ============================================================================
// The state, for the UI
// ============================================================================

export interface KillSwitchView {
  /** The effective answer for this tenant, global first. */
  decision: KillSwitchDecision;
  global: KillSwitchState | null;
  tenant: KillSwitchState | null;
}

export async function getKillSwitchView(tenantId: number): Promise<KillSwitchView> {
  const rows = (await db('kill_switch')
    .where(function scopeFilter(this: Knex.QueryBuilder) {
      void this.where('scope', 'global').orWhere({ scope: 'tenant', tenant_id: tenantId });
    })
    .select('*')) as KillSwitchRow[];

  const global = rows.find((r) => r.scope === 'global') ?? null;
  const tenant = rows.find((r) => r.scope === 'tenant') ?? null;

  return {
    decision: await readKillSwitch(tenantId),
    global: global ? toState(global) : null,
    tenant: tenant ? toState(tenant) : null,
  };
}

// ============================================================================
// The gestures
// ============================================================================

export interface SwitchInput {
  scope: KillSwitchScope;
  /** Ignored on the global scope; required on the tenant scope. */
  tenantId: number | null;
  reason?: string | null;
  userId: number | null;
}

/**
 * STOP. Every write to every equipment in scope is refused from the moment this
 * commits — including the write a job that is already `applying` is about to
 * make, because `apply.service` re-reads the switch at every phase boundary.
 *
 * What it does NOT do, and must not: it does not abort in-flight jobs, kill
 * sockets or tear down connections. A job stopped mid-apply by a rug pull is a
 * half-configured router; a job that finds the switch engaged at its next
 * checkpoint fails cleanly and lets its dead-man run. The switch prevents the
 * NEXT write, which is the only thing it can do without becoming the hazard.
 */
export async function engageKillSwitch(input: SwitchInput): Promise<KillSwitchState> {
  const row = await upsertSwitch(input, true);
  logger.warn(
    { scope: input.scope, tenantId: input.tenantId, userId: input.userId, reason: input.reason },
    'KILL SWITCH ENGAGED — no further write will be attempted on any equipment in scope',
  );
  broadcast(row);
  return toState(row);
}

/** Let the fleet be written to again. The stricter of the two gestures. */
export async function releaseKillSwitch(input: SwitchInput): Promise<KillSwitchState> {
  const row = await upsertSwitch(input, false);
  logger.warn(
    { scope: input.scope, tenantId: input.tenantId, userId: input.userId },
    'Kill switch RELEASED — writes are permitted again in scope',
  );
  broadcast(row);
  return toState(row);
}

async function upsertSwitch(input: SwitchInput, engaged: boolean): Promise<KillSwitchRow> {
  if (input.scope === 'tenant' && !input.tenantId) {
    throw new Error('A tenant kill switch needs a tenant');
  }

  const now = db.fn.now();
  const patch: Record<string, unknown> = {
    engaged,
    reason: input.reason ?? null,
    updated_at: now,
  };
  if (engaged) {
    patch.engaged_by = input.userId;
    patch.engaged_at = now;
    // `engaged_at` is what the CHECK constraint wants; the release columns are
    // cleared so "engaged since" is never read off a stale release.
    patch.released_by = null;
    patch.released_at = null;
  } else {
    patch.released_by = input.userId;
    patch.released_at = now;
    // `kill_switch_engaged_chk` only demands engaged_at when engaged; keeping
    // it lets the UI say "was engaged from X to Y".
  }

  const where =
    input.scope === 'global'
      ? { scope: 'global' as const }
      : { scope: 'tenant' as const, tenant_id: input.tenantId as number };

  const updated = (await db('kill_switch').where(where).update(patch).returning('*')) as
    KillSwitchRow[];
  if (updated.length > 0) return updated[0];

  // Only reachable for a tenant scope: the global row is seeded by migration
  // 009 and protected against deletion by a trigger.
  const inserted = (await db('kill_switch')
    .insert({
      scope: input.scope,
      tenant_id: input.scope === 'global' ? null : input.tenantId,
      ...patch,
    })
    .returning('*')) as KillSwitchRow[];
  return inserted[0];
}

/**
 * `wan:killSwitch:changed`. A global engage is broadcast to EVERY tenant room
 * that has a live listener rather than to one: every client must drop its apply
 * buttons on this one, whatever page it is on and whatever tenant it is
 * positioned on.
 */
function broadcast(row: KillSwitchRow): void {
  const payload = toState(row);
  if (row.scope === 'tenant' && row.tenant_id !== null) {
    emitToTenant(row.tenant_id, SOCKET_EVENTS.KILL_SWITCH_CHANGED, payload);
    return;
  }
  void db('tenants')
    .select('id')
    .then((rows: Array<{ id: number }>) => {
      for (const t of rows) emitToTenant(t.id, SOCKET_EVENTS.KILL_SWITCH_CHANGED, payload);
    })
    .catch((err) => logger.warn({ err }, 'Kill switch: could not broadcast the global change'));
}

export const killSwitchService = {
  readKillSwitch,
  assertWritable,
  killSwitchBlocks,
  getKillSwitchView,
  engageKillSwitch,
  releaseKillSwitch,
};
