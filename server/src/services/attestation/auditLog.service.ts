// ============================================================================
// ObliWAN — `audit_log`: the append-only, hash-chained ledger (§3.7, C11)
// ============================================================================
//
// ┌─ WHAT THIS MODULE DOES NOT DO, AND WHY THAT MATTERS ──────────────────────┐
// │ IT DOES NOT COMPUTE THE HASH.                                             │
// │                                                                           │
// │ `seq`, `prev_hash` and `hash` are assigned by the `audit_log_chain`       │
// │ trigger of migration 019, inside the database, under a per-tenant         │
// │ advisory lock. This module inserts the FACTS and reads back what Postgres │
// │ decided.                                                                  │
// │                                                                           │
// │ That split is the entire point of the ledger. A chain computed by the     │
// │ same process that later exports it proves nothing to the reader: the      │
// │ export is self-consistent because one program produced both halves. With  │
// │ the digest produced by the database and re-checked in JavaScript by       │
// │ `verifyAttestation()` — or by a stranger's script, from the published     │
// │ method — agreement between the two is evidence rather than a tautology.   │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ── SECRETS (§8.2 / R10) ───────────────────────────────────────────────────
//
// `before` and `after` reach the audit screen, the attestation document and
// whatever an MSP forwards to its client's insurer. `redactEvidence()` below
// masks by parameter NAME using the same vocabulary as `audit.service.ts`, and
// it is the SECOND wall: the caller is expected to hand over field values that
// were never secret in the first place. Nothing in this milestone writes a
// credential — exceptions carry operator prose and attestations carry hashes —
// so the mask exists for the caller that does not exist yet.

import type { Knex } from 'knex';
import { db } from '../../db';
import { isSecretName, REDACTED } from '../audit.service';

export const AUDIT_ACTOR_TYPES = ['user', 'system', 'automation', 'api'] as const;
export type AuditActorType = (typeof AUDIT_ACTOR_TYPES)[number];

export interface AuditEntryInput {
  tenantId: number;
  actorType: AuditActorType;
  /** The user id, the worker identity, the API key id — whatever names the
   *  actor in ITS OWN namespace. Text, not an FK: the ledger outlives the row. */
  actorId?: string | number | null;
  actorName?: string | null;
  /** `<domain>.<verb>`, e.g. `drift_exception.created`. Vocabulary is open on
   *  purpose: a closed enum would mean every new audited act needs a migration,
   *  which is how audit coverage stops growing. */
  action: string;
  entityType?: string | null;
  entityId?: string | number | null;
  before?: Record<string, unknown> | null;
  after?: Record<string, unknown> | null;
  correlationId?: string | null;
}

export interface AuditEntry {
  id: string;
  tenantId: number;
  seq: string;
  actorType: string;
  actorId: string | null;
  actorName: string | null;
  action: string;
  entityType: string | null;
  entityId: string | null;
  correlationId: string | null;
  occurredAt: string;
  prevHash: string | null;
  hash: string;
}

/** Depth past which we stop walking a payload. An audited object is a handful
 *  of scalars; anything deeper is a document that does not belong in a ledger. */
const MAX_DEPTH = 6;

/**
 * Masks by parameter NAME, recursively, and truncates long strings.
 *
 * Deliberately generous: masking `keySize` costs one dull line on an audit
 * screen, publishing a PSK costs a customer. Same trade `audit.service.ts`
 * already made, and the same predicate — `isSecretName` — so the two walls
 * cannot disagree about what a secret is called.
 */
export function redactEvidence(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return null;
  if (depth >= MAX_DEPTH) return '[depth]';
  if (typeof value === 'string') return value.length > 2000 ? `${value.slice(0, 2000)}…` : value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.slice(0, 200).map((v) => redactEvidence(v, depth + 1));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSecretName(k) ? REDACTED : redactEvidence(v, depth + 1);
    }
    return out;
  }
  return String(value);
}

/**
 * Appends one entry and returns what the database chained it as.
 *
 * The error is NOT swallowed. `audit.service.ts` states the rule for
 * `command_audit` — if the audit write fails, the operation does not happen —
 * and the same holds here: the callers in this milestone (creating an
 * exception, issuing an attestation) run the insert INSIDE their transaction,
 * so a failed ledger write rolls the act back rather than leaving an
 * unrecorded one.
 */
export async function appendAudit(
  input: AuditEntryInput,
  trx?: Knex.Transaction,
): Promise<AuditEntry> {
  const q = trx ?? db;
  const [row] = await q('audit_log')
    .insert({
      tenant_id: input.tenantId,
      actor_type: input.actorType,
      actor_id: input.actorId === null || input.actorId === undefined
        ? null
        : String(input.actorId),
      actor_name: input.actorName ?? null,
      action: input.action,
      entity_type: input.entityType ?? null,
      entity_id: input.entityId === null || input.entityId === undefined
        ? null
        : String(input.entityId),
      before: input.before ? JSON.stringify(redactEvidence(input.before)) : null,
      after: input.after ? JSON.stringify(redactEvidence(input.after)) : null,
      correlation_id: input.correlationId ?? null,
    })
    // `seq`, `prev_hash` and `hash` come back from the trigger. Reading them in
    // the RETURNING clause rather than with a second SELECT is not an
    // optimisation: a follow-up SELECT could observe a row another transaction
    // appended in between and report the wrong link.
    .returning<AuditRow[]>([
      'id', 'tenant_id', 'seq', 'actor_type', 'actor_id', 'actor_name', 'action',
      'entity_type', 'entity_id', 'correlation_id', 'occurred_at', 'prev_hash', 'hash',
    ]);
  return toEntry(row);
}

interface AuditRow {
  id: string;
  tenant_id: number;
  seq: string;
  actor_type: string;
  actor_id: string | null;
  actor_name: string | null;
  action: string;
  entity_type: string | null;
  entity_id: string | null;
  correlation_id: string | null;
  occurred_at: Date;
  prev_hash: string | null;
  hash: string;
}

function toEntry(r: AuditRow): AuditEntry {
  return {
    id: String(r.id),
    tenantId: r.tenant_id,
    seq: String(r.seq),
    actorType: r.actor_type,
    actorId: r.actor_id,
    actorName: r.actor_name,
    action: r.action,
    entityType: r.entity_type,
    entityId: r.entity_id,
    correlationId: r.correlation_id,
    occurredAt: new Date(r.occurred_at).toISOString(),
    prevHash: r.prev_hash,
    hash: r.hash,
  };
}

/**
 * The columns the chain is hashed over, rendered EXACTLY as the trigger
 * rendered them.
 *
 * `occurred_at` goes through the same `to_char` the plpgsql uses rather than
 * through `Date.toISOString()`. It would almost always agree — and "almost" is
 * the word that turns a verifier into a source of false alarms. The jsonb
 * columns are cast with `::text` for the same reason: `JSON.stringify` of a
 * parsed jsonb re-orders nothing but re-spaces everything.
 */
const CHAIN_COLUMNS = db.raw(`
  id,
  seq,
  to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS occurred_at_iso,
  actor_type, actor_id, actor_name, action, entity_type, entity_id,
  correlation_id::text AS correlation_id,
  "before"::text AS before_json,
  "after"::text  AS after_json,
  prev_hash, hash
`);

export interface ChainRow {
  id: string;
  seq: string;
  occurredAt: string;
  actorType: string;
  actorId: string | null;
  actorName: string | null;
  action: string;
  entityType: string | null;
  entityId: string | null;
  correlationId: string | null;
  beforeJson: string | null;
  afterJson: string | null;
  prevHash: string | null;
  hash: string;
}

interface RawChainRow {
  id: string;
  seq: string;
  occurred_at_iso: string;
  actor_type: string;
  actor_id: string | null;
  actor_name: string | null;
  action: string;
  entity_type: string | null;
  entity_id: string | null;
  correlation_id: string | null;
  before_json: string | null;
  after_json: string | null;
  prev_hash: string | null;
  hash: string;
}

function toChainRow(r: RawChainRow): ChainRow {
  return {
    id: String(r.id),
    seq: String(r.seq),
    occurredAt: r.occurred_at_iso,
    actorType: r.actor_type,
    actorId: r.actor_id,
    actorName: r.actor_name,
    action: r.action,
    entityType: r.entity_type,
    entityId: r.entity_id,
    correlationId: r.correlation_id,
    beforeJson: r.before_json,
    afterJson: r.after_json,
    prevHash: r.prev_hash,
    hash: r.hash,
  };
}

/** Longest ledger slice an attestation may embed. */
export const MAX_CHAIN_SLICE = 5000;

/** Thrown rather than truncating. See `chainSlice`. */
export class ChainTooLongError extends Error {
  constructor(public readonly rows: number, public readonly limit: number) {
    super(
      `This window covers ${rows} ledger rows (limit ${limit}). Narrow it: a TRUNCATED chain `
        + 'would still verify and would still be an incomplete answer, which is the worst of '
        + 'both.',
    );
    this.name = 'ChainTooLongError';
  }
}

/**
 * A CONTIGUOUS slice of one tenant's chain, by sequence number.
 *
 * By `seq` and not by `occurred_at`, and the difference is load-bearing: a
 * time-filtered slice has holes wherever a row falls outside the window, and a
 * chain with holes fails its own verification for a reason that has nothing to
 * do with tampering. The caller translates the window it wants into a seq range
 * with `chainRangeForWindow()` and then takes everything in between.
 *
 * ┌─ IT REFUSES RATHER THAN TRUNCATES, AND THAT IS THE WHOLE POINT ───────────┐
 * │ A `LIMIT` here would return the first N rows of the range. That prefix is │
 * │ CONTIGUOUS, so it passes every verification a reader can run — while the  │
 * │ document around it says the slice covers the window. A silently short     │
 * │ answer that looks correct under verification is worse than an error: it   │
 * │ is the one failure mode a hash chain cannot warn anybody about.           │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function chainSlice(
  tenantId: number,
  fromSeq: string,
  toSeq: string,
  limit = MAX_CHAIN_SLICE,
): Promise<ChainRow[]> {
  const span = BigInt(toSeq) - BigInt(fromSeq) + 1n;
  if (span > BigInt(limit)) throw new ChainTooLongError(Number(span), limit);

  const rows = await db('audit_log')
    .where({ tenant_id: tenantId })
    .andWhere('seq', '>=', fromSeq)
    .andWhere('seq', '<=', toSeq)
    .orderBy('seq', 'asc')
    .select<RawChainRow[]>(CHAIN_COLUMNS);
  return rows.map(toChainRow);
}

/**
 * The `[fromSeq, toSeq]` range covering a time window, or null when the tenant
 * wrote nothing in it.
 *
 * Both bounds come from ONE indexed query per side on
 * `audit_log_tenant_time_idx`.
 */
export async function chainRangeForWindow(
  tenantId: number,
  from: Date,
  to: Date,
): Promise<{ fromSeq: string; toSeq: string } | null> {
  const first = await db('audit_log')
    .where({ tenant_id: tenantId })
    .andWhere('occurred_at', '>=', from)
    .andWhere('occurred_at', '<=', to)
    .orderBy('seq', 'asc')
    .first<{ seq: string } | undefined>('seq');
  if (!first) return null;
  const last = await db('audit_log')
    .where({ tenant_id: tenantId })
    .andWhere('occurred_at', '>=', from)
    .andWhere('occurred_at', '<=', to)
    .orderBy('seq', 'desc')
    .first<{ seq: string } | undefined>('seq');
  return { fromSeq: String(first.seq), toSeq: String(last!.seq) };
}

export interface ListAuditFilter {
  action?: string;
  entityType?: string;
  entityId?: string;
  from?: Date;
  to?: Date;
  limit?: number;
  offset?: number;
}

/** The audit screen's read. tenant_id leads, always. */
export async function listAudit(
  tenantId: number,
  filter: ListAuditFilter = {},
): Promise<AuditEntry[]> {
  const q = db('audit_log').where({ tenant_id: tenantId });
  if (filter.action) void q.andWhere('action', filter.action);
  if (filter.entityType) void q.andWhere('entity_type', filter.entityType);
  if (filter.entityId) void q.andWhere('entity_id', filter.entityId);
  if (filter.from) void q.andWhere('occurred_at', '>=', filter.from);
  if (filter.to) void q.andWhere('occurred_at', '<=', filter.to);
  const rows = await q
    .orderBy('seq', 'desc')
    .limit(Math.min(filter.limit ?? 100, 500))
    .offset(filter.offset ?? 0)
    .select<AuditRow[]>([
      'id', 'tenant_id', 'seq', 'actor_type', 'actor_id', 'actor_name', 'action',
      'entity_type', 'entity_id', 'correlation_id', 'occurred_at', 'prev_hash', 'hash',
    ]);
  return rows.map(toEntry);
}
