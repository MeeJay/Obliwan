/**
 * ObliWAN — CWMP session continuity. The cookie, and nothing but the cookie.
 *
 * ┌─ A CWMP SESSION IS A DOZEN HTTP REQUESTS THAT MUST BE ONE CONVERSATION ───┐
 * │ The CPE POSTs an Inform, then an empty body, then a response, then        │
 * │ another empty body… and the ACS has to know that request #7 belongs to    │
 * │ the same conversation as request #1, because that is where the task it    │
 * │ dispatched at #5 is waiting for its answer.                               │
 * │                                                                          │
 * │ TR-069 says to use an HTTP cookie. THAT IS THE ONLY KEY THIS FILE HAS,    │
 * │ and the cookie is 24 bytes of `crypto.randomBytes` — a bearer token.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE SOURCE ADDRESS IS NOT AN IDENTITY, AND THE FALLBACK THAT USED IT IS ─┐
 * │ GONE.                                                                     │
 * │                                                                          │
 * │ There used to be `findSessionByAddressOnly(ip, tenant)`: on a POST with   │
 * │ no cookie and no body it returned the most recent open session of that    │
 * │ address, on the theory that a wrong match only ever reaches another CPE   │
 * │ of the same customer. Two things made that catastrophic rather than       │
 * │ merely imprecise:                                                         │
 * │                                                                          │
 * │  1. THE CALLER IS UNAUTHENTICATED. One empty POST from anybody at that    │
 * │     address adopted a live session and was handed the next queued RPC —   │
 * │     including a `SetParameterValues` whose value the serialiser had just  │
 * │     decrypted from the vault. The CPE IS the customer's NAT, so "that     │
 * │     address" means every host on the customer's LAN.                      │
 * │  2. UNDER A6 EVERY SESSION SHARES ONE ADDRESS. The shipped                │
 * │     `docker-compose.yml` publishes 7547 through the bridge, so the peer   │
 * │     is 172.18.0.1 for the entire fleet. "The most recent open session of  │
 * │     this address" then means "the last CPE of this tenant to inform,      │
 * │     whichever one that was".                                              │
 * │                                                                          │
 * │ A CPE that eats cookies therefore gets no RPC in that session; it must    │
 * │ re-Inform, which is cheap (MaxEnvelopes=1 already makes the session       │
 * │ ping-pong) and which is the only exchange that carries an identity AND a  │
 * │ Digest credential. The `noCookie` quirk is still recorded — on the        │
 * │ Inform, where the box has proved who it is — so an operator can see it.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE COOKIE IS SCOPED TO THE TENANT OF THE URL ───────────────────────────┐
 * │ `cwmp_sessions` carries no `tenant_id` (migration 015, decision 1), so    │
 * │ the JOIN on `devices` IS the isolation — exactly as it is in              │
 * │ `resolveCpe()`. Without it, tenant A's CPE could post its own legitimate  │
 * │ cookie to `/tenant-b` and the machine would mix the two origins: A's      │
 * │ device id with B's tenant id, which wrote A's paths into B's             │
 * │ `cwmp_param_map`. A slug is not a secret; it defaults to the customer's   │
 * │ own name.                                                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY THE SESSION IS A ROW AND NOT A MAP ──────────────────────────────────┐
 * │ Three reasons, in order of how expensive each one is to discover late:    │
 * │  1. A redeploy in the middle of a 300-CPE inform window would lose every  │
 * │     in-flight task, and each would be retried from scratch.               │
 * │  2. `OBLIWAN_ROLE=web` may run several replicas (A5) and a CPE's second   │
 * │     POST can land on another one.                                         │
 * │  3. "Which CPEs are talking to us right now" is a question an operator    │
 * │     asks during an incident, and an in-memory Map cannot answer it.       │
 * │                                                                          │
 * │ Full session AFFINITY across replicas is explicitly out of scope for v1   │
 * │ (arbitrage A5 (c)). What this gives is session VISIBILITY and crash       │
 * │ recovery, which is what the milestone needs.                              │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import crypto from 'crypto';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { requeueSentTask } from './task.service';

export const SESSION_COOKIE = 'ACSsession';

export interface CwmpSession {
  id: number;
  deviceId: number | null;
  sessionToken: string;
  cwmpId: string | null;
  sourceIp: string | null;
  state: 'open' | 'closed' | 'abandoned';
  rpcCount: number;
  authenticated: boolean;
  pendingRpcId: string | null;
  pendingTaskId: number | null;
  startedAt: Date;
  lastSeenAt: Date;
}

interface SessionRow {
  id: number;
  device_id: number | null;
  session_token: string;
  cwmp_id: string | null;
  source_ip: string | null;
  state: 'open' | 'closed' | 'abandoned';
  rpc_count: number;
  authenticated: boolean;
  pending_rpc_id: string | null;
  pending_task_id: number | null;
  started_at: Date;
  last_seen_at: Date;
}

function toSession(row: SessionRow): CwmpSession {
  return {
    id: row.id,
    deviceId: row.device_id,
    sessionToken: row.session_token,
    cwmpId: row.cwmp_id,
    sourceIp: row.source_ip,
    state: row.state,
    rpcCount: row.rpc_count,
    authenticated: row.authenticated,
    pendingRpcId: row.pending_rpc_id,
    pendingTaskId: row.pending_task_id,
    startedAt: row.started_at,
    lastSeenAt: row.last_seen_at,
  };
}

export function newSessionToken(): string {
  return crypto.randomBytes(24).toString('base64url');
}

/**
 * Start a session. Closes any session the same box already had open.
 *
 * The close is not tidiness: a CPE whose line dropped mid-session comes back
 * with a NEW Inform, and its previous session still holds a task in `sent`. If
 * that session were left open the fallback index would reject the new one, and
 * the CPE would be locked out of the ACS by its own previous attempt.
 */
export async function openSession(args: {
  deviceId: number | null;
  cwmpId: string | null;
  sourceIp: string;
  authenticated: boolean;
}): Promise<CwmpSession> {
  if (args.cwmpId) {
    const stale = (await db('cwmp_sessions')
      .where({ cwmp_id: args.cwmpId, state: 'open' })
      .select('id', 'pending_task_id')) as Array<{ id: number; pending_task_id: number | null }>;
    for (const s of stale) {
      await closeSession(s.id, 'abandoned', 'superseded by a new Inform');
    }
  }

  const [row] = (await db('cwmp_sessions')
    .insert({
      device_id: args.deviceId,
      session_token: newSessionToken(),
      cwmp_id: args.cwmpId,
      source_ip: args.sourceIp,
      authenticated: args.authenticated,
      state: 'open',
    })
    .returning('*')) as SessionRow[];

  return toSession(row);
}

/**
 * A session that has PROVED which device it is.
 *
 * The two narrowings are what the branches of the session machine were each
 * forgetting on their own: `authenticated` is true AND `deviceId` is a number.
 * Making it a distinct type means a branch cannot reach `dispatchNextTask`,
 * `completeTask` or `ingestParameterValues` without having produced one — the
 * compiler asks the question that three of the four branches forgot to.
 */
export interface AuthenticatedCwmpSession extends CwmpSession {
  deviceId: number;
  authenticated: true;
}

/**
 * The verdict on an incoming POST's cookie. Three cases, and the caller has to
 * name the one it is handling — there is deliberately no `CwmpSession | null`
 * to forget to test.
 */
export type SessionMatch =
  | { kind: 'none' }
  | { kind: 'unauthenticated'; session: CwmpSession }
  | { kind: 'authenticated'; session: AuthenticatedCwmpSession };

/**
 * Does this CPE already have a session open that it never continued?
 *
 * The signal behind the `noCookie` quirk. A cookie-honouring CPE ends its
 * session on the ACS's 204, which CLOSES the row; so a box that is informing
 * again while its previous session is still open, and that echoed no
 * `ACSsession` with this Inform, dropped the cookie. Asked BEFORE
 * `openSession`, which abandons those rows.
 *
 * It is only ever consulted on an Inform that has already passed Digest, so it
 * is an observation about a box we have identified — not an identification.
 */
export async function hasOpenSessionFor(cwmpId: string): Promise<boolean> {
  const row = (await db('cwmp_sessions')
    .where({ cwmp_id: cwmpId, state: 'open' })
    .first('id')) as { id: number } | undefined;
  return row !== undefined;
}

/**
 * Find the session an incoming POST belongs to, and say whether it may act.
 *
 * COOKIE ONLY, AND TENANT-SCOPED. See the two boxes in the file header: the
 * address-keyed fallback is gone, and the JOIN on `devices` is what stops a
 * cookie minted under one customer's slug from being spent under another's.
 */
export async function matchSession(args: {
  cookieToken: string | null;
  tenantId: number;
}): Promise<SessionMatch> {
  if (!args.cookieToken) return { kind: 'none' };

  const row = (await db('cwmp_sessions as s')
    .join('devices as d', 'd.id', 's.device_id')
    .where('s.session_token', args.cookieToken)
    .andWhere('s.state', 'open')
    .andWhere('d.tenant_id', args.tenantId)
    .first('s.*')) as SessionRow | undefined;

  if (!row) return { kind: 'none' };

  const session = toSession(row);
  if (!session.authenticated || session.deviceId === null) {
    return { kind: 'unauthenticated', session };
  }
  return { kind: 'authenticated', session: session as AuthenticatedCwmpSession };
}

export async function touchSession(
  sessionId: number,
  patch: {
    pendingRpcId?: string | null;
    pendingTaskId?: number | null;
    incrementRpc?: boolean;
    deviceId?: number;
    authenticated?: boolean;
  } = {},
): Promise<void> {
  const update: Record<string, unknown> = { last_seen_at: db.fn.now() };
  if (patch.pendingRpcId !== undefined) update.pending_rpc_id = patch.pendingRpcId;
  if (patch.pendingTaskId !== undefined) update.pending_task_id = patch.pendingTaskId;
  if (patch.deviceId !== undefined) update.device_id = patch.deviceId;
  if (patch.authenticated !== undefined) update.authenticated = patch.authenticated;
  if (patch.incrementRpc) update.rpc_count = db.raw('rpc_count + 1');
  await db('cwmp_sessions').where({ id: sessionId }).update(update);
}

/**
 * End a session, returning any in-flight task to the queue.
 *
 * The requeue is the important half. A session that ends with a task in `sent`
 * and nothing done about it leaves that task stuck forever — see
 * `requeueSentTask`, which is where the attempt budget is spent.
 */
export async function closeSession(
  sessionId: number,
  state: 'closed' | 'abandoned',
  reason?: string,
): Promise<void> {
  const row = (await db('cwmp_sessions').where({ id: sessionId }).first('pending_task_id')) as
    | { pending_task_id: number | null }
    | undefined;

  if (row?.pending_task_id && state === 'abandoned') {
    await requeueSentTask(row.pending_task_id, reason ?? 'session abandoned');
  }

  await db('cwmp_sessions')
    .where({ id: sessionId })
    .update({ state, ended_at: db.fn.now(), pending_task_id: null, pending_rpc_id: null });
}

/**
 * Reap sessions that stopped talking.
 *
 * CPEs disappear mid-session constantly: the DSL line renegotiates, the box
 * reboots, the customer unplugs it. Every one of those leaves an open row and,
 * worse, a task pinned in `sent`. This is what unpins them, and it is the only
 * reason a task ever leaves `sent` without the CPE answering.
 */
export async function reapIdleSessions(idleSeconds: number): Promise<number> {
  const rows = (await db('cwmp_sessions')
    .where({ state: 'open' })
    .andWhere('last_seen_at', '<', db.raw(`now() - (? || ' seconds')::interval`, [idleSeconds]))
    .select('id')) as Array<{ id: number }>;

  for (const row of rows) {
    await closeSession(row.id, 'abandoned', `idle for more than ${idleSeconds}s`);
  }
  if (rows.length > 0) {
    logger.info({ count: rows.length, idleSeconds }, 'ACS: reaped idle CWMP sessions');
  }
  return rows.length;
}

/**
 * CPEs that knocked and were refused.
 *
 * The `discoveries` table of the ACS: an unknown `cwmp_id` never creates a
 * device (that is risk R4), but it IS recorded, so an operator can see the four
 * boxes an installer plugged in this morning instead of discovering them when a
 * customer calls.
 */
export async function listUnknownCallers(
  limit = 50,
): Promise<Array<{ cwmpId: string; sourceIp: string | null; lastSeenAt: string; attempts: number }>> {
  const rows = (await db('cwmp_sessions')
    .whereNull('device_id')
    .whereNotNull('cwmp_id')
    .groupBy('cwmp_id', 'source_ip')
    .select('cwmp_id', 'source_ip')
    .max('last_seen_at as last_seen_at')
    .count<{ count: string }[]>('* as count')
    .orderBy('last_seen_at', 'desc')
    .limit(limit)) as Array<{
    cwmp_id: string;
    source_ip: string | null;
    last_seen_at: Date;
    count: string;
  }>;

  return rows.map((r) => ({
    cwmpId: r.cwmp_id,
    sourceIp: r.source_ip,
    lastSeenAt: new Date(r.last_seen_at).toISOString(),
    attempts: Number(r.count),
  }));
}
