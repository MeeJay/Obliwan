/**
 * ObliWAN — the per-CPE task queue.
 *
 * ┌─ WHY A QUEUE AND NOT A REQUEST ───────────────────────────────────────────┐
 * │ Every other transport in this product is SYNCHRONOUS: the arbiter dials   │
 * │ the box and waits. TR-069 is the opposite — the CPE dials US, once every  │
 * │ few minutes, and the ACS has a few seconds of floor time before the box   │
 * │ hangs up for another interval. An operator's "read the WAN address" is    │
 * │ therefore never an action, it is an INTENT that will be executed later,   │
 * │ and modelling it as anything else produces an API that appears to hang.   │
 * │                                                                          │
 * │ `expires_at` is the second half of that: a CPE offline for a week must    │
 * │ not be handed a week of stale intent the second it reconnects. Intent     │
 * │ that outlives its usefulness is worse than intent that was never          │
 * │ recorded, because it executes.                                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ D3 — NOTHING WRITES TO AN EQUIPMENT OUTSIDE `change_jobs` ───────────────┐
 * │ `set_parameter_values`, `download` and `reboot` MODIFY a customer's       │
 * │ router. Decision D3 says that is the exclusive privilege of the change    │
 * │ queue, and it applies here in full: `enqueueTask()` refuses a mutating    │
 * │ kind unless the caller passes the `change_jobs` row that authorises it.   │
 * │ The ACS API therefore exposes reads directly and mutations only through   │
 * │ a change job — the same door as a RouterOS push, with the same guard,     │
 * │ the same approval and the same audit trail.                               │
 * │                                                                          │
 * │ `get_parameter_values` is exempt because it is a READ, exactly as         │
 * │ `POST /config/devices/:id/collect` is a read on the MikroTik side.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import crypto from 'crypto';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import {
  CWMP_TASK_TERMINAL,
  isRetryableFault,
  summarisePayload,
  type CwmpFault,
  type CwmpTask,
  type CwmpTaskKind,
  type CwmpTaskPayload,
  type CwmpTaskState,
} from './contract';

/** Kinds that change the state of somebody else's hardware (D3). */
const MUTATING_KINDS: ReadonlySet<CwmpTaskKind> = new Set<CwmpTaskKind>([
  'set_parameter_values',
  'download',
  'reboot',
]);

/**
 * ┌─ THE ONE NARROW EXCEPTION TO D3, AND ITS JUSTIFICATION ───────────────────┐
 * │ These two leaves configure the ACS's OWN management channel: how often    │
 * │ the CPE calls home. They change nothing about the service the box         │
 * │ delivers — no interface, no route, no firewall rule, no credential of     │
 * │ the customer's — and they cannot lock anybody out of anything.            │
 * │                                                                          │
 * │ They are exempted because the alternative makes the product dishonest.    │
 * │ ObliWAN has NO Connection Request (arbitrage: STUN/XMPP bindings expire   │
 * │ in 30-120 s), so lowering the inform interval is the ONLY way to make a   │
 * │ CPE call back sooner — and that is what the UI promises in                │
 * │ `CWMP_NO_CONNECTION_REQUEST_EXPLANATION`. Routing it through a change     │
 * │ job with a frozen plan, a management-path guard and an approval, in       │
 * │ order to say "please call home in a minute", would mean nobody ever uses  │
 * │ it and the UI's honest sentence quietly becomes a lie.                    │
 * │                                                                          │
 * │ MATCHED ON THE FULL SUFFIX, NOT ON A LEAF NAME. `…PeriodicInformInterval` │
 * │ under `ManagementServer` is plumbing; a vendor-specific leaf that happens │
 * │ to end the same way somewhere else in the tree is not.                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const ACS_PLUMBING_SUFFIXES: readonly string[] = [
  'ManagementServer.PeriodicInformInterval',
  'ManagementServer.PeriodicInformEnable',
];

export function isAcsPlumbingPath(path: string): boolean {
  return ACS_PLUMBING_SUFFIXES.some((suffix) => path.endsWith(suffix));
}

export class TaskRefusedError extends Error {
  constructor(message: string, readonly code: 'requires_change_job' | 'not_enrolled') {
    super(message);
    this.name = 'TaskRefusedError';
  }
}

interface TaskRow {
  id: number;
  device_id: number;
  kind: CwmpTaskKind;
  command_key: string;
  state: CwmpTaskState;
  attempts: number;
  max_attempts: number;
  payload: CwmpTaskPayload;
  fault: CwmpFault | null;
  created_by: number | null;
  expires_at: Date;
  sent_at: Date | null;
  completed_at: Date | null;
  created_at: Date;
}

function toTask(row: TaskRow): CwmpTask {
  return {
    id: row.id,
    deviceId: row.device_id,
    kind: row.kind,
    commandKey: row.command_key,
    state: row.state,
    attempts: row.attempts,
    maxAttempts: row.max_attempts,
    payload: row.payload,
    fault: row.fault,
    createdBy: row.created_by,
    expiresAt: row.expires_at.toISOString(),
    sentAt: row.sent_at ? row.sent_at.toISOString() : null,
    completedAt: row.completed_at ? row.completed_at.toISOString() : null,
    createdAt: row.created_at.toISOString(),
  };
}

/**
 * A CommandKey.
 *
 * It has to be unique across the whole table (migration 015, decision 4) AND
 * survive a round trip through firmware that may truncate it — TR-069 caps it
 * at 32 characters and several vendors enforce that silently. 24 hex characters
 * plus a 4-character prefix is 28, inside every limit, and 96 bits of entropy.
 */
export function newCommandKey(prefix = 'obw'): string {
  return `${prefix}-${crypto.randomBytes(12).toString('hex')}`;
}

export interface EnqueueOptions {
  createdBy?: number | null;
  ttlSeconds?: number;
  maxAttempts?: number;
  commandKey?: string;
  /**
   * The `change_jobs.id` that authorises a mutating task (D3). Reads do not
   * need one; a mutation without one is REFUSED, not logged and allowed.
   */
  changeJobId?: number | null;
  /**
   * Claim the `ACS_PLUMBING_SUFFIXES` exception above. The claim is VERIFIED,
   * not trusted: a payload touching anything outside the whitelist is refused
   * exactly as if the flag had not been passed.
   */
  acsPlumbing?: boolean;
}

export async function enqueueTask(
  deviceId: number,
  payload: CwmpTaskPayload,
  opts: EnqueueOptions = {},
): Promise<CwmpTask> {
  const enrolled = (await db('cwmp_devices').where({ device_id: deviceId }).first('device_id')) as
    | { device_id: number }
    | undefined;
  if (!enrolled) {
    throw new TaskRefusedError(
      `device ${deviceId} is not enrolled in the ACS — enrol it first`,
      'not_enrolled',
    );
  }

  if (MUTATING_KINDS.has(payload.kind) && !opts.changeJobId) {
    const plumbing =
      opts.acsPlumbing === true &&
      payload.kind === 'set_parameter_values' &&
      payload.ops.every((op) => isAcsPlumbingPath(op.path));

    if (!plumbing) {
      throw new TaskRefusedError(
        `${payload.kind} modifies the equipment and must go through a change job ` +
          '(decision D3: nothing writes to an equipment outside change_jobs)',
        'requires_change_job',
      );
    }
  }

  const ttl = opts.ttlSeconds ?? 24 * 3600;
  const [row] = (await db('cwmp_tasks')
    .insert({
      device_id: deviceId,
      kind: payload.kind,
      command_key: opts.commandKey ?? newCommandKey(),
      state: 'queued',
      max_attempts: opts.maxAttempts ?? 3,
      payload: JSON.stringify(payload),
      created_by: opts.createdBy ?? null,
      expires_at: new Date(Date.now() + ttl * 1000),
    })
    .returning('*')) as TaskRow[];

  logger.info(
    { deviceId, taskId: row.id, kind: payload.kind, summary: summarisePayload(payload) },
    'ACS: task queued',
  );
  return toTask(row);
}

/**
 * Claim the next task for a CPE that is on the line right now.
 *
 * `FOR UPDATE SKIP LOCKED` because two replicas may be serving two POSTs of
 * the same CPE at the same instant (a retransmit, a NAT rebinding), and handing
 * the same RPC to both would make the CPE answer twice with the same
 * `cwmp:ID` — after which nothing can be correlated to anything.
 *
 * Expiry is checked HERE and not only in the sweeper: the sweeper runs every
 * minute, and a task that expired thirty seconds ago must not go out just
 * because the CPE happened to call in first.
 */
export async function claimNextTask(deviceId: number): Promise<CwmpTask | null> {
  return db.transaction(async (trx) => {
    const row = (await trx('cwmp_tasks')
      .where({ device_id: deviceId, state: 'queued' })
      .andWhere('expires_at', '>', trx.fn.now())
      .orderBy('id')
      .forUpdate()
      .skipLocked()
      .first()) as TaskRow | undefined;

    if (!row) return null;

    const [updated] = (await trx('cwmp_tasks')
      .where({ id: row.id })
      .update({
        state: 'sent',
        attempts: row.attempts + 1,
        sent_at: trx.fn.now(),
        updated_at: trx.fn.now(),
      })
      .returning('*')) as TaskRow[];

    return toTask(updated);
  });
}

/** The CPE answered without a fault. */
export async function completeTask(taskId: number): Promise<void> {
  await db('cwmp_tasks')
    .where({ id: taskId })
    .whereNotIn('state', [...CWMP_TASK_TERMINAL])
    .update({ state: 'done', completed_at: db.fn.now(), updated_at: db.fn.now() });
}

/**
 * The CPE answered a fault.
 *
 * ┌─ ONLY READS AUTO-RETRY, AND THE ASYMMETRY IS THE POINT ───────────────────┐
 * │ A retryable fault on a `get_parameter_values` goes BACK to `queued` and    │
 * │ the CPE gets it again next session; `9004 Resources Exceeded` on a CPE     │
 * │ that was busy is exactly the case that is worth another attempt.           │
 * │                                                                          │
 * │ A MUTATION IS NEVER RETRIED AUTOMATICALLY. `download`, `reboot` and        │
 * │ `set_parameter_values` were authorised by ONE change job against ONE       │
 * │ frozen plan (D3); silently doing them again five minutes later is a        │
 * │ second write nobody approved. Concretely, this is the difference between   │
 * │ "the firmware push failed, a human decides" and "the ACS re-pushed a       │
 * │ firmware image to a CPE that had just failed to take it" — which is also   │
 * │ how a Download comes back around with a CommandKey that already has a      │
 * │ transfer row and dies on a unique violation.                               │
 * │                                                                          │
 * │ `9005 Invalid parameter name` is terminal for everything, mutation or not: │
 * │ retrying it forever burns the box's session budget every five minutes for  │
 * │ a path that will never exist.                                              │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function failTask(taskId: number, fault: CwmpFault): Promise<CwmpTaskState> {
  const row = (await db('cwmp_tasks').where({ id: taskId }).first()) as TaskRow | undefined;
  if (!row) return 'failed';

  const canRetry =
    !MUTATING_KINDS.has(row.kind) &&
    isRetryableFault(fault.code) &&
    row.attempts < row.max_attempts;
  const state: CwmpTaskState = canRetry ? 'queued' : 'failed';

  await db('cwmp_tasks')
    .where({ id: taskId })
    .update({
      state,
      fault: JSON.stringify(fault),
      completed_at: canRetry ? null : db.fn.now(),
      updated_at: db.fn.now(),
    });

  logger.warn(
    { taskId, deviceId: row.device_id, code: fault.code, attempts: row.attempts, state },
    'ACS: task faulted',
  );
  return state;
}

/**
 * Return an in-flight task to the queue.
 *
 * Called when a session dies mid-RPC — the line dropped, the CPE rebooted, the
 * server was redeployed. Without it the task sits in `sent` forever and the
 * operator sees a request that never completes and never fails, which is the
 * single most expensive state a queue can have.
 */
export async function requeueSentTask(taskId: number, reason: string): Promise<void> {
  const row = (await db('cwmp_tasks').where({ id: taskId, state: 'sent' }).first()) as
    | TaskRow
    | undefined;
  if (!row) return;

  if (row.attempts >= row.max_attempts) {
    await db('cwmp_tasks')
      .where({ id: taskId })
      .update({
        state: 'failed',
        fault: JSON.stringify({
          faultCode: 'Server',
          code: '9002',
          faultString: `abandoned after ${row.attempts} attempts: ${reason}`,
        }),
        completed_at: db.fn.now(),
        updated_at: db.fn.now(),
      });
    return;
  }
  await db('cwmp_tasks')
    .where({ id: taskId })
    .update({ state: 'queued', sent_at: null, updated_at: db.fn.now() });
}

export async function cancelTask(taskId: number, deviceId: number): Promise<boolean> {
  const affected = await db('cwmp_tasks')
    .where({ id: taskId, device_id: deviceId })
    .whereIn('state', ['queued', 'sent'])
    .update({ state: 'cancelled', completed_at: db.fn.now(), updated_at: db.fn.now() });
  return affected > 0;
}

/** The sweeper. Runs on the leader; see `services/cwmp/index.ts`. */
export async function expireStaleTasks(): Promise<number> {
  return db('cwmp_tasks')
    .where({ state: 'queued' })
    .andWhere('expires_at', '<=', db.fn.now())
    .update({ state: 'expired', completed_at: db.fn.now(), updated_at: db.fn.now() });
}

export async function listTasks(
  deviceId: number,
  opts: { states?: CwmpTaskState[]; limit?: number } = {},
): Promise<CwmpTask[]> {
  const q = db('cwmp_tasks').where({ device_id: deviceId });
  if (opts.states?.length) q.whereIn('state', opts.states);
  const rows = (await q.orderBy('id', 'desc').limit(opts.limit ?? 100)) as TaskRow[];
  return rows.map(toTask);
}

export async function getTask(taskId: number): Promise<CwmpTask | null> {
  const row = (await db('cwmp_tasks').where({ id: taskId }).first()) as TaskRow | undefined;
  return row ? toTask(row) : null;
}

export async function getTaskByCommandKey(commandKey: string): Promise<CwmpTask | null> {
  const row = (await db('cwmp_tasks').where({ command_key: commandKey }).first()) as
    | TaskRow
    | undefined;
  return row ? toTask(row) : null;
}

export async function countPending(deviceIds: readonly number[]): Promise<Map<number, number>> {
  if (deviceIds.length === 0) return new Map();
  const rows = (await db('cwmp_tasks')
    .whereIn('device_id', deviceIds as number[])
    .whereIn('state', ['queued', 'sent'])
    .groupBy('device_id')
    .select('device_id')
    .count<{ device_id: number; count: string }[]>('* as count')) as Array<{
    device_id: number;
    count: string;
  }>;
  return new Map(rows.map((r) => [r.device_id, Number(r.count)]));
}
