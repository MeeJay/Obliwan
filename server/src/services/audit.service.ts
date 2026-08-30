// ============================================================================
// ObliWAN — `command_audit`: every command sent to an equipment (§8.2 / R10)
// ============================================================================
//
// ┌─ THE RULE THIS FILE ENFORCES, AND IT IS NOT A BEST EFFORT ────────────────┐
// │ IF THE AUDIT WRITE FAILS, THE DEVICE WRITE DOES NOT HAPPEN.               │
// │                                                                           │
// │ That is why `auditedCommand()` INSERTS BEFORE it calls the function that  │
// │ dials the box, and lets the insert error propagate untouched. An          │
// │ untraceable gesture on a customer's network is not an acceptable          │
// │ degradation mode — it is the one thing that makes an incident review      │
// │ impossible, and an incident review that cannot say what we sent is a      │
// │ review that ends in "it must have been ObliWAN".                          │
// │                                                                           │
// │ The order is therefore: INSERT the intent -> send -> INSERT the result.   │
// │ Never: send -> INSERT. Never: try/catch around the INSERT.                │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ── WHY TWO ROWS PER COMMAND, AND WHY THAT IS NOT A DESIGN CHOICE I LIKED ───
//
// `command_audit` carries a `success boolean NULL` column documented as "NULL
// while in flight", which implies the row is filled in afterwards. It also
// carries `command_audit_append_only`, a BEFORE UPDATE trigger that raises on
// EVERY update, unconditionally. The two cannot both be honoured by a single
// row: there is no legal statement that turns `success = NULL` into
// `success = true`.
//
// Migration 009 is another agent's file and is not mine to change, so this
// module resolves the contradiction in the only direction that keeps the
// guarantee above: the ATTEMPT row is written first (that is the one whose
// failure cancels the operation), and the RESULT is appended as a second,
// separate row carrying `args_redacted.auditPhase = 'result'` and the id of the
// attempt it answers. `listCommandAudit()` folds the pair back into one line so
// the incident screen shows one command with one outcome.
//
// The alternative — write one row AFTER the command, with its outcome — is
// exactly the design that loses the audit trail for the command that killed the
// box, because the process that would have written it is the process that is
// now talking to a router which stopped answering.
//
// ── SECRETS (§8.2 / R10) ───────────────────────────────────────────────────
//
// `command_audit.command` reaches the audit screen, the export bundle and every
// log shipper downstream. A password that lands here has been published. Two
// independent layers, because either one alone has a hole:
//
//  1. VALUE-BASED. The caller passes the secret literals it just decrypted from
//     the vault (`secretsOf(transport)` in `drivers/types.ts`), and they are
//     replaced wherever they appear. Exact, but only covers secrets we hold.
//  2. PATTERN-BASED. `password=…`, `secret="…"`, `psk=…`, `community=…` and
//     friends are masked by shape. Covers the secret the device generated, the
//     one a template inlined, and the one nobody told this module about.
//
// Neither is a proof. Postgres cannot detect a secret, and a driver that
// invents a new spelling of "key" defeats layer 2 in silence. The real defence
// is that the driver redacts at the source; this module is the second wall.

import type { Knex } from 'knex';
import { db } from '../db';
import { logger } from '../utils/logger';

// ============================================================================
// Redaction
// ============================================================================

export const REDACTED = '***';

/**
 * Argument / parameter names whose VALUE is a secret.
 *
 * Deliberately generous — a false positive costs one masked value on an audit
 * screen, a false negative publishes a customer's PSK. `key` catches
 * `private-key`, `apiKey`, `authKey` and `wireguard-key`; it also catches
 * `key-size` and `keepalive`, and masking those is a price worth paying.
 */
const SECRET_NAME = new RegExp(
  [
    'pass(word|wd|phrase)?',
    'secret',
    'psk',
    'pre-?shared',
    'key',
    'token',
    'credential',
    'community',
    'auth',
    'priv',
    'wpa',
    'shared-?key',
    'seed',
    'salt',
    'signature',
  ].join('|'),
  'i',
);

/** True when a parameter NAME means its value must never be stored. */
export function isSecretName(name: string): boolean {
  return SECRET_NAME.test(name);
}

/**
 * `name=value`, `name="value"`, `name='value'` — the RouterOS / CLI shape.
 * Captured in three groups so the name and the quoting survive the mask and the
 * line stays readable: `/ppp/secret/set password=***` still tells an operator
 * exactly what was done.
 */
const ASSIGNMENT = /\b([A-Za-z][\w.-]*)\s*=\s*("([^"]*)"|'([^']*)'|[^\s;,)]+)/g;

/** A bare word that could be a parameter NAME: no `=`, no path separator. */
const BARE_NAME = /^[A-Za-z][\w.-]*$/;

/**
 * `set password value`, `snmp-server community value` — the space-separated
 * shape used by the DrayTek / SonicWall / Zyxel CLIs, where there is no `=` to
 * anchor on.
 *
 * Written as a TOKEN WALK rather than as a regex, and that is not a style
 * preference: a `/(\w+)\s+(\S+)/g` pass consumes the value it just looked at,
 * so in `snmp-server community s3cret` it matches (`snmp-server`, `community`),
 * decides `snmp-server` is not a secret, and never gets to look at `community`
 * at all. The secret survives. A walk looks at every token.
 *
 * A token carrying an `=` is skipped: the assignment pass has already dealt
 * with it, and re-testing `password=***` here would make the NEXT token — a
 * perfectly ordinary `name=site-001` — look like the secret's value.
 */
function redactSpaced(text: string): string {
  const parts = text.split(/(\s+)/);
  for (let i = 0; i < parts.length; i++) {
    const token = parts[i];
    if (!token || /^\s+$/.test(token)) continue;
    if (!BARE_NAME.test(token) || !isSecretName(token)) continue;
    for (let j = i + 1; j < parts.length; j++) {
      if (/^\s+$/.test(parts[j])) continue;
      parts[j] = REDACTED;
      break;
    }
  }
  return parts.join('');
}

/**
 * Mask a command line.
 *
 * `secrets` are literal values (from the vault) replaced wherever they occur,
 * INCLUDING when they appear with no attribute name in front of them — which is
 * exactly how a `.rsc` body or an `/import` payload leaks one.
 */
export function redactCommand(
  command: string,
  secrets: ReadonlyArray<string | null | undefined> = [],
): string {
  let out = command;

  // Layer 1 — value based. Short strings are skipped: replacing every "1234"
  // in a config because a PIN happens to be 1234 destroys the line's meaning.
  for (const secret of secrets) {
    if (!secret || secret.length < 4) continue;
    out = out.split(secret).join(REDACTED);
  }

  // Layer 2 — shape based.
  out = out.replace(ASSIGNMENT, (whole, name: string) =>
    isSecretName(name) ? `${name}=${REDACTED}` : whole,
  );
  out = redactSpaced(out);

  return out;
}

/**
 * Mask a structured argument bag, recursively.
 *
 * A secret-named key is masked WHATEVER its value's type: `{ password: { a: 1 } }`
 * becomes `'***'`, not `{ a: 1 }`. Descending into a masked subtree is how a
 * nested credential object survives redaction.
 */
export function redactArgs(
  args: unknown,
  secrets: ReadonlyArray<string | null | undefined> = [],
  depth = 0,
): unknown {
  if (depth > 8) return REDACTED;
  if (args === null || args === undefined) return args;

  if (typeof args === 'string') return redactCommand(args, secrets);
  if (typeof args === 'number' || typeof args === 'boolean') return args;
  if (Array.isArray(args)) return args.map((v) => redactArgs(v, secrets, depth + 1));

  if (typeof args === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(args as Record<string, unknown>)) {
      out[k] = isSecretName(k) ? REDACTED : redactArgs(v, secrets, depth + 1);
    }
    return out;
  }
  return REDACTED;
}

function redactObject(
  args: Record<string, unknown> | undefined,
  secrets: ReadonlyArray<string | null | undefined>,
): Record<string, unknown> {
  const out = redactArgs(args ?? {}, secrets);
  return out !== null && typeof out === 'object' && !Array.isArray(out)
    ? (out as Record<string, unknown>)
    : {};
}

// ============================================================================
// The append
// ============================================================================

/** `command_audit.transport`. Mirrors `TRANSPORT_KINDS` in migration 009. */
export type AuditTransport = 'routeros_api' | 'ssh' | 'rest' | 'cwmp' | 'snmp';

export interface CommandIntent {
  tenantId: number;
  /** Denormalised identity: an audit row must still read after the device is
   *  gone (migration 009, decision 5 — no foreign keys on this table). */
  deviceId: number | null;
  deviceUuid?: string | null;
  deviceName?: string | null;
  userId?: number | null;
  username?: string | null;
  jobId?: number | null;
  stepId?: number | null;
  transport: AuditTransport;
  /** The command as it will be SENT. Redacted here, before it is stored. */
  command: string;
  args?: Record<string, unknown>;
  /** True for anything that modifies the box. Drives the "every write that
   *  night" index, so a read mislabelled as a write is noise and a write
   *  mislabelled as a read is a hole. */
  isWrite: boolean;
  /** Where WE dialled from, on a multi-homed server. Not the device's address. */
  sourceIp?: string | null;
  /** Ties one operator gesture to the N commands it produced across M devices. */
  correlationId?: string | null;
  /** Vault literals to mask on top of the pattern pass. */
  secrets?: ReadonlyArray<string | null | undefined>;
}

export interface CommandResult {
  success: boolean;
  error?: string | null;
  durationMs?: number | null;
  /** Device output worth keeping, redacted before it is stored. */
  detail?: Record<string, unknown>;
}

/**
 * Append the INTENT row. Throws on failure, and the throw is the feature.
 *
 * Returns the row id, which the result row points back at.
 */
export async function recordCommandIntent(
  intent: CommandIntent,
  q: Knex | Knex.Transaction = db,
): Promise<number> {
  const secrets = intent.secrets ?? [];
  const rows = (await q('command_audit')
    .insert({
      tenant_id: intent.tenantId,
      device_id: intent.deviceId,
      device_uuid: intent.deviceUuid ?? null,
      device_name: intent.deviceName ?? null,
      user_id: intent.userId ?? null,
      username: intent.username ?? null,
      job_id: intent.jobId ?? null,
      step_id: intent.stepId ?? null,
      transport: intent.transport,
      command: redactCommand(intent.command, secrets),
      args_redacted: JSON.stringify({
        auditPhase: 'attempt',
        ...redactObject(intent.args, secrets),
      }),
      is_write: intent.isWrite,
      // NULL: the answer has not come. Collapsing that into `false` would hide
      // a timeout as a refusal, and those are two different incidents.
      success: null,
      source_ip: intent.sourceIp ?? null,
      correlation_id: intent.correlationId ?? null,
    })
    .returning('id')) as Array<{ id: string | number }>;

  return Number(rows[0].id);
}

/**
 * Append the RESULT row for a previously recorded intent.
 *
 * `is_write` is copied from the intent so a write still counts once in the
 * `command_audit_writes_idx` read — `listCommandAudit()` and every query in
 * this module exclude `auditPhase = 'result'` from the primary listing.
 *
 * NEVER THROWS. The device write has already happened by the time this runs;
 * losing the outcome row must not turn a successful change into a failed job,
 * and the attempt row (which is the one that proves the gesture was made) is
 * already committed. It logs loudly instead.
 */
export async function recordCommandResult(
  attemptId: number,
  intent: CommandIntent,
  result: CommandResult,
  q: Knex | Knex.Transaction = db,
): Promise<void> {
  const secrets = intent.secrets ?? [];
  try {
    await q('command_audit').insert({
      tenant_id: intent.tenantId,
      device_id: intent.deviceId,
      device_uuid: intent.deviceUuid ?? null,
      device_name: intent.deviceName ?? null,
      user_id: intent.userId ?? null,
      username: intent.username ?? null,
      job_id: intent.jobId ?? null,
      step_id: intent.stepId ?? null,
      transport: intent.transport,
      command: redactCommand(intent.command, secrets),
      args_redacted: JSON.stringify({
        auditPhase: 'result',
        attemptId,
        ...redactObject(result.detail, secrets),
      }),
      is_write: intent.isWrite,
      success: result.success,
      error_redacted: result.error ? redactCommand(result.error, secrets) : null,
      duration_ms: result.durationMs ?? null,
      source_ip: intent.sourceIp ?? null,
      correlation_id: intent.correlationId ?? null,
    });
  } catch (err) {
    logger.error(
      { err, attemptId, jobId: intent.jobId, deviceId: intent.deviceId },
      'command_audit: the RESULT row could not be appended. The attempt row stands; ' +
        'this command will read as "no answer recorded".',
    );
  }
}

/**
 * THE wrapper. Nothing in `services/change/` talks to a device except through
 * this function.
 *
 *   const out = await auditedCommand(intent, () => driver.send(...));
 *
 * If the intent insert throws, `send` is never called — that is the guarantee
 * of this file, and it is the reason the `await` on line 1 has no try/catch
 * around it.
 */
export async function auditedCommand<T>(
  intent: CommandIntent,
  send: (auditId: number) => Promise<T>,
  q: Knex | Knex.Transaction = db,
): Promise<T> {
  // 1. THE TRACE, FIRST. No try/catch: a failure here must reach the caller and
  //    cancel the operation.
  const auditId = await recordCommandIntent(intent, q);

  const startedAt = Date.now();
  try {
    const value = await send(auditId);
    await recordCommandResult(
      auditId,
      intent,
      { success: true, durationMs: Date.now() - startedAt },
      q,
    );
    return value;
  } catch (err) {
    await recordCommandResult(
      auditId,
      intent,
      {
        success: false,
        error: err instanceof Error ? err.message : String(err),
        durationMs: Date.now() - startedAt,
      },
      q,
    );
    throw err;
  }
}

// ============================================================================
// Reads
// ============================================================================

export interface CommandAuditRow {
  id: number;
  tenantId: number;
  deviceId: number | null;
  deviceName: string | null;
  userId: number | null;
  username: string | null;
  jobId: number | null;
  stepId: number | null;
  transport: AuditTransport;
  /** Already masked. There is no unmasked version anywhere. */
  command: string;
  args: Record<string, unknown>;
  isWrite: boolean;
  /** `null` = the command was sent and no outcome was ever recorded. That is a
   *  finding in itself, not a missing field. */
  success: boolean | null;
  errorRedacted: string | null;
  durationMs: number | null;
  correlationId: string | null;
  executedAt: string;
}

export interface AuditQuery {
  deviceId?: number;
  jobId?: number;
  correlationId?: string;
  /** Writes only — the query an incident starts with. */
  writesOnly?: boolean;
  limit?: number;
  offset?: number;
}

interface RawAuditRow {
  id: string | number;
  tenant_id: number;
  device_id: number | null;
  device_name: string | null;
  user_id: number | null;
  username: string | null;
  job_id: string | number | null;
  step_id: string | number | null;
  transport: AuditTransport;
  command: string;
  args_redacted: Record<string, unknown> | string;
  is_write: boolean;
  success: boolean | null;
  error_redacted: string | null;
  duration_ms: number | null;
  correlation_id: string | null;
  executed_at: Date;
}

function parseArgs(value: Record<string, unknown> | string): Record<string, unknown> {
  if (typeof value !== 'string') return value ?? {};
  try {
    return JSON.parse(value) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/**
 * The incident read: one line per command, attempt and result folded together.
 *
 * Tenant-scoped on `tenant_id` — `command_audit` carries no foreign key to
 * `tenants` (decision 5), so this WHERE clause is the ONLY thing standing
 * between one customer and another customer's command history.
 */
export async function listCommandAudit(
  tenantId: number,
  query: AuditQuery = {},
): Promise<{ rows: CommandAuditRow[]; total: number }> {
  const limit = Math.min(Math.max(query.limit ?? 100, 1), 500);
  const offset = Math.max(query.offset ?? 0, 0);

  const base = () => {
    const q = db('command_audit').where('tenant_id', tenantId);
    // Result rows are folded onto their attempt below; they must not be listed
    // as commands of their own or every write would appear twice.
    void q.whereRaw("COALESCE(args_redacted->>'auditPhase', 'attempt') <> 'result'");
    if (query.deviceId) void q.where('device_id', query.deviceId);
    if (query.jobId) void q.where('job_id', query.jobId);
    if (query.correlationId) void q.where('correlation_id', query.correlationId);
    if (query.writesOnly) void q.where('is_write', true);
    return q;
  };

  const [{ count }] = (await base().count({ count: '*' })) as Array<{ count: string }>;
  const attempts = (await base()
    .orderBy('executed_at', 'desc')
    .orderBy('id', 'desc')
    .limit(limit)
    .offset(offset)
    .select('*')) as RawAuditRow[];

  // One extra query, never one per row.
  const ids = attempts.map((r) => Number(r.id));
  const results =
    ids.length === 0
      ? []
      : ((await db('command_audit')
          .where('tenant_id', tenantId)
          .whereRaw("args_redacted->>'auditPhase' = 'result'")
          .whereRaw(
            "(args_redacted->>'attemptId')::bigint = ANY(?)",
            [db.raw('ARRAY[' + ids.map(() => '?').join(',') + ']::bigint[]', ids)],
          )
          .select('*')) as RawAuditRow[]);

  const byAttempt = new Map<number, RawAuditRow>();
  for (const r of results) {
    const args = parseArgs(r.args_redacted);
    const attemptId = Number(args.attemptId);
    if (Number.isFinite(attemptId)) byAttempt.set(attemptId, r);
  }

  const rows = attempts.map((a) => {
    const id = Number(a.id);
    const outcome = byAttempt.get(id);
    const args = parseArgs(a.args_redacted);
    delete args.auditPhase;
    return {
      id,
      tenantId: a.tenant_id,
      deviceId: a.device_id,
      deviceName: a.device_name,
      userId: a.user_id,
      username: a.username,
      jobId: a.job_id === null ? null : Number(a.job_id),
      stepId: a.step_id === null ? null : Number(a.step_id),
      transport: a.transport,
      command: a.command,
      args,
      isWrite: a.is_write,
      success: outcome ? outcome.success : a.success,
      errorRedacted: outcome ? outcome.error_redacted : a.error_redacted,
      durationMs: outcome ? outcome.duration_ms : a.duration_ms,
      correlationId: a.correlation_id,
      executedAt: new Date(a.executed_at).toISOString(),
    } satisfies CommandAuditRow;
  });

  return { rows, total: Number(count) };
}

export const auditService = {
  redactCommand,
  redactArgs,
  isSecretName,
  recordCommandIntent,
  recordCommandResult,
  auditedCommand,
  listCommandAudit,
};
