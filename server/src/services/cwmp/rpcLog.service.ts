/**
 * ObliWAN — the CWMP envelope log. Off by default, redacted always.
 *
 * ┌─ RISK R7 IS THE WHOLE DESIGN OF THIS FILE ────────────────────────────────┐
 * │ A CWMP session is a dozen envelopes and a full parameter read is hundreds │
 * │ of kilobytes. 300 CPEs at a 300 s interval with logging on is ~10 rows/s  │
 * │ and, at a conservative 4 KB average, ~3 GB a day. The architecture        │
 * │ document names `cwmp_rpc_log` explicitly as the table that explodes.      │
 * │                                                                          │
 * │ So: DISABLED by default, enabled per TENANT and narrowed per DEVICE,      │
 * │ partitioned by day, dropped after seven — never DELETEd (migration 006's  │
 * │ numbers: DROP returns the space, DELETE returns dead tuples and destroys  │
 * │ the physical correlation BRIN depends on).                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ EVERY BODY IS REDACTED BEFORE IT IS WRITTEN (§8.2) ──────────────────────┐
 * │ A CWMP envelope carries the customer's PPPoE password in cleartext XML.   │
 * │ An operator turning debug logging on to diagnose one CPE must not thereby │
 * │ write that customer's credentials into a table — logging is the classic   │
 * │ way a secret escapes a system that was otherwise careful with it, and     │
 * │ the redaction therefore happens HERE, on the write path, and not at       │
 * │ display time where a `SELECT` bypasses it.                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { db } from '../../db';
import { logger } from '../../utils/logger';
import { decrypt } from '../secretVault.service';
import { isSecretParameterPath, type CwmpFault, type CwmpTask } from './contract';

export const REDACTED_XML = '***REDACTED***';

export interface RpcLogEntry {
  deviceId: number | null;
  sessionId: number | null;
  direction: 'cpe_to_acs' | 'acs_to_cpe';
  method: string | null;
  cwmpId: string | null;
  httpStatus: number | null;
  body: string;
  /**
   * Extra literals to remove from the body, on top of what `redactEnvelope`
   * can see for itself.
   *
   * The caller sometimes knows a secret the XML does not label as one: a CPE
   * fault that echoes a rejected value carries no `<Name>` and no `<Value>`,
   * so only the code that RESOLVED that value can name it. Used by the fault
   * branch of the session machine.
   */
  scrub?: readonly string[];
}

/**
 * Strip every value whose `<Name>` is a credential path.
 *
 * Works on the raw XML rather than on a parsed tree, deliberately: this runs on
 * bodies the parser may have REJECTED — a malformed envelope is exactly what an
 * operator turns logging on to look at — and a redactor that needed a
 * successful parse would fail open on the one case that matters.
 *
 * Four passes:
 *  1. `<Name>secret.path</Name><Value…>x</Value>` -> value replaced.
 *  2. `<Password>x</Password>` and friends, which appear OUTSIDE a
 *     ParameterValueStruct (the `Download` RPC has its own Password field).
 *  3. THE FAULT. A CPE that refuses a write answers `9007` and several DrayTek
 *     and Zyxel trains REPEAT THE REJECTED VALUE in the fault. The struct is
 *     `<ParameterName>…</ParameterName><FaultCode>…</FaultCode>
 *     <FaultString>…</FaultString>` — there is no `<Value>` anywhere in it, so
 *     pass 1, which needs `<Name>` and `<Value>` to be ADJACENT, never looked
 *     at it. That is how a vault plaintext reached `cwmp_tasks.fault` and the
 *     rpc log while every parameter-tree assertion still passed.
 *  4. Any `<FaultString>` that NAMES a credential path goes whole: the value a
 *     firmware echoes next to the path it refused is the value we just
 *     decrypted, and losing the diagnostic text of a fault on a password leaf
 *     is a trade this file makes without hesitating.
 */
export function redactEnvelope(xml: string): string {
  let out = xml.replace(
    /(<Name>([^<]*)<\/Name>\s*<Value([^>]*)>)([\s\S]*?)(<\/Value>)/g,
    (whole, prefix: string, name: string, _attrs: string, _value: string, suffix: string) =>
      isSecretParameterPath(name.trim()) ? `${prefix}${REDACTED_XML}${suffix}` : whole,
  );

  out = out.replace(
    /<(Password|Passphrase|PreSharedKey|KeyPassphrase|PrivateKey)>([\s\S]*?)<\/\1>/gi,
    (_whole, tag: string, value: string) =>
      value.trim().length === 0 ? `<${tag}></${tag}>` : `<${tag}>${REDACTED_XML}</${tag}>`,
  );

  // Pass 3 — the SetParameterValuesFault struct, matched on the adjacency the
  // fault actually has. Bounded at 400 characters so it cannot reach across
  // into an unrelated struct further down the envelope.
  out = out.replace(
    /(<ParameterName>([^<]*)<\/ParameterName>[\s\S]{0,400}?<FaultString>)([\s\S]*?)(<\/FaultString>)/g,
    (whole, prefix: string, name: string, _value: string, suffix: string) =>
      isSecretParameterPath(name.trim()) ? `${prefix}${REDACTED_XML}${suffix}` : whole,
  );

  // Pass 4 — a fault string that mentions a credential path at all.
  out = out.replace(
    /(<FaultString>)([\s\S]*?)(<\/FaultString>)/gi,
    (whole, open: string, text: string, close: string) =>
      mentionsSecretPath(text) ? `${open}${REDACTED_XML}${close}` : whole,
  );

  // An `Authorization:` line pasted into a body by a debug proxy, and the
  // download token. Neither is a §8.2 secret; both are credentials in practice.
  out = out.replace(/(Authorization:\s*)(\S+)/gi, `$1${REDACTED_XML}`);

  return out;
}

/**
 * Does this free text name a parameter path whose leaf is a credential?
 *
 * Free text, because a fault string is prose: `Invalid value for
 * InternetGatewayDevice.…WANPPPConnection.1.Password: "hunter2"`. Every dotted
 * token is offered to the same classifier the parameter tree uses, so the two
 * can never disagree about what counts as a secret.
 */
export function mentionsSecretPath(text: string): boolean {
  for (const match of text.matchAll(/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_{}\[\]-]+)+/g)) {
    if (isSecretParameterPath(match[0])) return true;
  }
  return false;
}

/**
 * The plaintexts `serialiseTask` resolved out of the vault for this task.
 *
 * Re-derived rather than remembered: the fault arrives in a LATER HTTP request
 * than the one that put the value on the wire, possibly on another replica
 * (A5), so there is nothing in memory to remember it with. The task row names
 * the `secretRef`, the vault answers it, and the plaintext lives for the length
 * of one string comparison — the same bargain `serialiseTask` makes.
 */
export function taskSecretPlaintexts(task: CwmpTask | null): string[] {
  if (!task || task.payload.kind !== 'set_parameter_values') return [];
  const out: string[] = [];
  for (const op of task.payload.ops) {
    if (op.secretRef === undefined) continue;
    try {
      const plain = decrypt(op.secretRef);
      if (plain.length > 0) out.push(plain);
    } catch {
      // An unreadable ref is R8's problem, not this function's. Nothing to
      // scrub means nothing is claimed to have been scrubbed.
    }
  }
  return out;
}

/**
 * Redact a fault BEFORE it is stored on the task row.
 *
 * `failTask` writes this verbatim into `cwmp_tasks.fault`, a column with no
 * retention (unlike `cwmp_rpc_log`, dropped at seven days) that
 * `GET /api/acs/devices/:id/tasks` returns to the UI. Two independent rules:
 *
 *  - EXACT MATCH. Any substring equal to a value the serialiser resolved from
 *    the vault for THIS task, in plaintext or XML-escaped, is replaced. This
 *    does not care what the firmware wrote around it.
 *  - THE PATH. A fault naming a credential path — whether from
 *    `parameters[].path` or from the prose of the fault string — loses its
 *    text entirely, because that is where a value gets echoed.
 */
export function redactFault(fault: CwmpFault, task: CwmpTask | null): CwmpFault {
  const plaintexts = taskSecretPlaintexts(task);
  const secretPaths =
    task?.payload.kind === 'set_parameter_values'
      ? task.payload.ops.map((op) => op.path).filter((path) => isSecretParameterPath(path))
      : [];

  const clean = (text: string): string => {
    let out = text;
    for (const plain of plaintexts) {
      out = replaceLiteral(out, plain, REDACTED_XML);
      out = replaceLiteral(out, escapeXml(plain), REDACTED_XML);
    }
    if (secretPaths.some((path) => out.includes(path)) || mentionsSecretPath(out)) {
      return REDACTED_XML;
    }
    return out;
  };

  return {
    ...fault,
    faultString: clean(fault.faultString ?? ''),
    ...(fault.parameters
      ? {
          parameters: fault.parameters.map((p) => ({
            ...p,
            faultString: isSecretParameterPath(p.path)
              ? REDACTED_XML
              : clean(p.faultString ?? ''),
          })),
        }
      : {}),
  };
}

function replaceLiteral(haystack: string, needle: string, replacement: string): string {
  if (needle.length === 0) return haystack;
  return haystack.split(needle).join(replacement);
}

function escapeXml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

interface Gate {
  at: number;
  enabled: boolean;
}

/**
 * Two-level gate: the tenant switch AND the device switch.
 *
 * Cached for 30 s for the same reason `acsSettings` is: this is consulted on
 * every envelope of every session, and it is a boolean that changes when an
 * operator clicks something.
 */
const GATE_TTL_MS = 30_000;
const gateCache = new Map<number, Gate>();

export function invalidateRpcLogGate(): void {
  gateCache.clear();
}

export async function loggingEnabledFor(deviceId: number | null): Promise<boolean> {
  if (deviceId === null) return false;
  const hit = gateCache.get(deviceId);
  const now = Date.now();
  if (hit && now - hit.at < GATE_TTL_MS) return hit.enabled;

  const row = (await db('cwmp_devices as c')
    .join('devices as d', 'd.id', 'c.device_id')
    .leftJoin('cwmp_acs_settings as s', 's.tenant_id', 'd.tenant_id')
    .where('c.device_id', deviceId)
    .first('c.rpc_log_enabled as device_flag', 's.rpc_log_enabled as tenant_flag')) as
    | { device_flag: boolean; tenant_flag: boolean | null }
    | undefined;

  // BOTH must be on. The tenant switch is the budget decision ("this customer
  // may generate log volume"); the device switch is the diagnostic one
  // ("this box is misbehaving"). Either alone would be a way to log the whole
  // fleet by accident.
  const enabled = !!row && row.device_flag === true && row.tenant_flag === true;
  gateCache.set(deviceId, { at: now, enabled });
  return enabled;
}

/**
 * Write one envelope, if logging is on for this device.
 *
 * NEVER throws and never awaits on the critical path in a way that can delay a
 * CPE response: a logging failure must not break a session. A missing partition
 * (SQLSTATE 23514) is repaired once and the row is retried once — the same
 * three-layer shape as the SNMP writer, minus the layer that would abandon a
 * poll cycle, because losing one log line matters less than one sample.
 */
export async function logRpc(entry: RpcLogEntry): Promise<void> {
  try {
    if (!(await loggingEnabledFor(entry.deviceId))) return;

    let body = redactEnvelope(entry.body);
    for (const literal of entry.scrub ?? []) {
      if (literal.length > 0) body = body.split(literal).join(REDACTED_XML);
    }
    const row = {
      ts: new Date(),
      device_id: entry.deviceId,
      session_id: entry.sessionId,
      direction: entry.direction,
      method: entry.method,
      cwmp_id: entry.cwmpId ? entry.cwmpId.slice(0, 64) : null,
      http_status: entry.httpStatus,
      body,
      byte_count: Buffer.byteLength(entry.body, 'utf8'),
    };

    try {
      await db('cwmp_rpc_log').insert(row);
    } catch (err) {
      if (!isMissingPartition(err)) throw err;
      await db.raw("SELECT ensure_series_partition('cwmp_rpc_log'::regclass, 'day', now())");
      await db('cwmp_rpc_log').insert(row);
    }
  } catch (err) {
    logger.warn({ err, deviceId: entry.deviceId }, 'ACS: rpc log write failed (session continues)');
  }
}

function isMissingPartition(err: unknown): boolean {
  const code = (err as { code?: string } | null)?.code;
  return code === '23514';
}

export interface RpcLogQuery {
  deviceId: number;
  limit?: number;
  since?: Date;
}

export async function readRpcLog(q: RpcLogQuery): Promise<
  Array<{
    ts: string;
    direction: string;
    method: string | null;
    cwmpId: string | null;
    httpStatus: number | null;
    byteCount: number;
    body: string | null;
  }>
> {
  const query = db('cwmp_rpc_log').where({ device_id: q.deviceId });
  if (q.since) query.andWhere('ts', '>=', q.since);
  const rows = (await query.orderBy('ts', 'desc').limit(Math.min(q.limit ?? 100, 1000))) as Array<{
    ts: Date;
    direction: string;
    method: string | null;
    cwmp_id: string | null;
    http_status: number | null;
    byte_count: number;
    body: string | null;
  }>;

  return rows.map((r) => ({
    ts: r.ts.toISOString(),
    direction: r.direction,
    method: r.method,
    cwmpId: r.cwmp_id,
    httpStatus: r.http_status,
    byteCount: r.byte_count,
    body: r.body,
  }));
}
