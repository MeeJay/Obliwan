/**
 * F3 — property 2: an intervention nobody closes expires BY ITSELF, and says so.
 *
 * Why this is a module of its own, and not a function inside
 * `intervention.service.ts` where it started:
 *
 * `driftLink.sweepInterventionLinks()` is the function a scheduler arms, and it
 * is therefore the one place where "expire what nobody closed" can run without
 * a human opening a screen. But `intervention.service.ts` already imports
 * `driftLink.ts` (closing a window claims its own diff), so calling back into
 * the service from the linker would close a cycle — and a cycle whose
 * resolution order decides whether a function is defined at call time is
 * exactly the bug `window.ts` was split out to avoid.
 *
 * So the rule moves DOWN instead: both the lifecycle service and the linker
 * depend on this file, and neither depends on the other for it. There is still
 * ONE implementation of the expiry, which is the property that matters —
 * `intervention.service.ts` re-exports it so no caller has to know it moved.
 *
 * `logEvent` lives here for the same reason: the expiry has to append its own
 * lifecycle fact, and a second copy of the insert would be a second place where
 * `intervention_events.detail` could be filled with something the CHECK of
 * migration 020 refuses.
 */

import type { Knex } from 'knex';
import type { InterventionEvent } from '@obliwan/shared/dist/intervention';
import { db } from '../../db';
import { logger } from '../../utils/logger';

/**
 * Append one lifecycle fact.
 *
 * `detail` carries numbers and ids only. The CHECK on the column refuses a
 * credential-shaped key independently of what this function believes it is
 * writing — two independent refusals, §8.2.
 */
export async function logEvent(
  q: Knex | Knex.Transaction,
  tenantId: number,
  interventionId: string,
  event: InterventionEvent,
  actorUserId: number | null,
  detail: Record<string, unknown> = {},
): Promise<void> {
  await q('intervention_events').insert({
    tenant_id: tenantId,
    intervention_id: interventionId,
    event,
    actor_user_id: actorUserId,
    detail: JSON.stringify(detail),
  });
}

export interface ExpiryOutcome {
  expired: number;
  /** Ids, so a caller can tell an operator WHICH windows ran out. */
  ids: string[];
}

/**
 * Close, by force, every window whose declared deadline has passed.
 *
 * Called by `openIntervention` (where it is what makes a new window on the same
 * device possible at all), by `listInterventions` and `getIntervention` (so an
 * operator never reads a stale `open`), by the sweep endpoint — and, since the
 * audit that found this, by `sweepInterventionLinks`, which is the only one of
 * those a scheduler ever calls. Every other caller is an HTTP path: without the
 * last one the answer to "does a window nobody closes really expire?" was "only
 * if a human opens the screen".
 *
 * Idempotent by construction — the UPDATE's own predicate is the lock.
 *
 * `tenantId` is optional so a future scheduler can expire the whole instance in
 * one statement. Every HTTP path passes it. Omitting it widens a WRITE and
 * never a READ — the statement can only move a window of any tenant from
 * `open` to `expired` at its own declared deadline, which is the correct
 * outcome for all of them, and it returns no row content to a caller.
 */
export async function expireOverdue(
  tenantId?: number,
  now: Date = new Date(),
  deviceId?: number,
): Promise<ExpiryOutcome> {
  const q = db('interventions')
    .where('status', 'open')
    .andWhere('expires_at', '<', now);
  if (tenantId !== undefined) void q.andWhere('tenant_id', tenantId);
  if (deviceId !== undefined) void q.andWhere('device_id', deviceId);

  const rows = (await q
    // `expired_at` is the JOURNAL of this sweep — the instant somebody (or
    // something) noticed. It is deliberately NOT the end of the window:
    // `effectiveEnd()` reads `expires_at` for an expired row, so a sweep that
    // runs late records how late it was without moving the attribution
    // boundary the operator was shown in `/interventions/params`.
    .update({ status: 'expired', expired_at: now, updated_at: now })
    .returning(['id', 'tenant_id', 'device_id', 'operator', 'opened_at', 'expires_at'])) as Array<{
    id: string;
    tenant_id: number;
    device_id: number;
    operator: string;
    opened_at: Date;
    expires_at: Date;
  }>;

  for (const row of rows) {
    const unattendedSeconds = Math.max(
      0,
      Math.round((now.getTime() - row.expires_at.getTime()) / 1000),
    );
    await logEvent(db, Number(row.tenant_id), String(row.id), 'expired', null, {
      unattendedSeconds,
      declaredSeconds: Math.round(
        (row.expires_at.getTime() - row.opened_at.getTime()) / 1000,
      ),
    });
    // Said out loud, not merely stored. An intervention nobody closed means
    // nobody looked at the diff either, so the work is still unmodelled.
    logger.warn(
      {
        interventionId: String(row.id),
        tenantId: Number(row.tenant_id),
        deviceId: Number(row.device_id),
        unattendedSeconds,
      },
      'Intervention window expired without being closed — the diff was never reviewed, ' +
        'and drift on this device is attributable again from now on',
    );
  }

  return { expired: rows.length, ids: rows.map((r) => String(r.id)) };
}
