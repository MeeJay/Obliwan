// ============================================================================
// @obliwan/shared — Evidence: drift exceptions (F1) and compliance
// attestations (F2). ARCHITECTURE.md §10.
// ============================================================================
//
// ┌─ WHAT THIS FILE IS FOR, IN ONE SENTENCE EACH ─────────────────────────────┐
// │ F1  A drift finding may only be silenced by a JUSTIFIED, DATED, AUTHORED  │
// │     exception that EXPIRES. "Ignored" without those four is how a fleet   │
// │     hides its drift forever, and that is the failure this feature exists  │
// │     to make impossible.                                                   │
// │ F2  An attestation is a document that a THIRD PARTY can re-verify without │
// │     trusting ObliWAN. Everything below serves that one property.          │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ── WHY THE HASHING LIVES IN `shared/` AND NOT ON THE SERVER ────────────────
//
// The attestation's whole value is that its chain can be recomputed by somebody
// who does not run our server. That means the algorithm has to be WRITTEN DOWN,
// not merely implemented — and the place a client, a script and a reviewer can
// all read it is here. `ATTESTATION_METHOD` below is emitted VERBATIM inside
// every attestation, so the document explains how to check itself.
//
// The encoding is deliberately boring: length-prefixed UTF-8 fields, SHA-256,
// lowercase hex. It is ~15 lines to reimplement in any language, which is the
// design target — a verification procedure nobody can implement is a
// verification procedure that will never be run.

import { sha256Hex, canonicalJson } from './ncm/hash';

// ============================================================================
// F1 — Drift exceptions
// ============================================================================

/**
 * Minimum length of a justification, in characters after trimming.
 *
 * 24 is not a magic number, it is the shortest sentence that can carry a REASON
 * rather than an acknowledgement. "ok", "known", "as agreed", "see ticket" all
 * fall under it; "NAT rule kept for the legacy ERP at site 12" clears it. The
 * same value is compiled into the CHECK constraint of migration 019 — the
 * database is the enforcement, this constant only lets the UI say so first.
 */
export const MIN_JUSTIFICATION_LENGTH = 24;

/** Longest justification the API accepts. A justification is a paragraph, not
 *  an attachment; past this the operator wants a ticket link. */
export const MAX_JUSTIFICATION_LENGTH = 4000;

/**
 * Longest review horizon an exception may be granted, in days.
 *
 * An exception with a ten-year review date is a permanent suppression wearing a
 * review date as a disguise, which is precisely the outcome F1 exists to
 * prevent. 366 days is the outer bound of "we will look at this again", and it
 * is enforced by CHECK, not by the form.
 */
export const MAX_REVIEW_HORIZON_DAYS = 366;

/**
 * The two stored statuses, and only the first one can hide anything.
 *
 * `active`  and review_due_at in the future -> the finding is suppressed.
 * `active`  and review_due_at in the past   -> EXPIRED. The finding is BACK.
 * `revoked` -> someone withdrew it. The finding is back, immediately.
 *
 * Note that `expired` is NOT a stored status: it is `status = 'active' AND
 * review_due_at <= now()`. Storing it would mean a row whose truth depends on a
 * sweeper having run, and a sweeper that is late would make an expired
 * exception keep suppressing — the exact "hide the drift forever" hole. The
 * derived form cannot be late.
 */
export const EXCEPTION_STATUSES = ['active', 'revoked'] as const;
export type ExceptionStatus = (typeof EXCEPTION_STATUSES)[number];

/** What an exception looks like to a reader, statuses folded into one word. */
export const EXCEPTION_STATES = ['active', 'expiring', 'expired', 'revoked'] as const;
export type ExceptionState = (typeof EXCEPTION_STATES)[number];

/** Days before `reviewDueAt` at which an exception starts reporting `expiring`.
 *  Purely a reporting nuance — nothing behaves differently. */
export const EXCEPTION_EXPIRING_SOON_DAYS = 14;

/** Every act that can be recorded against an exception. Append-only history. */
export const EXCEPTION_DECISIONS = ['created', 'renewed', 'revoked'] as const;
export type ExceptionDecision = (typeof EXCEPTION_DECISIONS)[number];

export interface DriftExceptionReview {
  id: string;
  exceptionId: string;
  decision: ExceptionDecision;
  justification: string;
  /** NULL once the user row is deleted; `reviewedByUsername` survives it. */
  reviewedByUserId: number | null;
  reviewedByUsername: string;
  reviewedAt: string;
  previousReviewDueAt: string | null;
  newReviewDueAt: string | null;
}

export interface DriftException {
  id: string;
  uuid: string;
  tenantId: number;
  deviceId: number;
  deviceName?: string;
  /** The semantic key of the resource this exception forgives. Matched against
   *  BOTH `drift_findings.sem_key` and `.legacy_sem_key`, so a
   *  `semKeyGeneration` bump (§8.4) does not silently resurrect every
   *  suppressed finding in the fleet on the day the rules change. */
  semKey: string;
  resource: string;
  /**
   * `'<kind>/<semKey>/<field>'` to forgive ONE field, or null to forgive the
   * whole resource. Nullable, therefore every uniqueness index over it is
   * PARTIAL: `NULLS DISTINCT` is the Postgres default and would happily let a
   * device accumulate an unbounded pile of "whole resource" exceptions.
   */
  path: string | null;
  justification: string;
  status: ExceptionStatus;
  /** Derived, never stored — see EXCEPTION_STATUSES. */
  state: ExceptionState;
  /** True exactly when `state` is `expired` or `revoked`: the findings under
   *  this exception are visible on the drift screen again. */
  visibleAgain: boolean;
  reviewDueAt: string;
  createdByUserId: number | null;
  createdByUsername: string;
  createdAt: string;
  revokedAt: string | null;
  revokedByUsername: string | null;
  renewalCount: number;
  lastRenewedAt: string | null;
  /** The finding that prompted the exception, kept as provenance. It belongs to
   *  ONE drift run and will be superseded by later runs; the exception itself is
   *  keyed on `semKey`, which is what makes it survive them. */
  originFindingId: string | null;
  /** The severity that was accepted on the day the exception was granted. An
   *  exception written against a `low` that has since become `critical` is a
   *  decision nobody actually made. */
  severityAtCreation: string | null;
  /** Findings currently suppressed by this exception. */
  suppressedFindings: number;
  reviews?: DriftExceptionReview[];
}

/** Derives the reader-facing state. Pure: same inputs, same answer, on both
 *  sides of the wire. `now` is a parameter so a test can be a test. */
export function exceptionState(
  input: { status: ExceptionStatus; reviewDueAt: string | Date },
  now: Date = new Date(),
): ExceptionState {
  if (input.status === 'revoked') return 'revoked';
  const due = input.reviewDueAt instanceof Date ? input.reviewDueAt : new Date(input.reviewDueAt);
  if (due.getTime() <= now.getTime()) return 'expired';
  const soon = EXCEPTION_EXPIRING_SOON_DAYS * 86_400_000;
  return due.getTime() - now.getTime() <= soon ? 'expiring' : 'active';
}

/** True when the exception is NOT suppressing anything any more. */
export function exceptionIsVisibleAgain(state: ExceptionState): boolean {
  return state === 'expired' || state === 'revoked';
}

/**
 * The application-side mirror of the CHECK constraint, and it is a MIRROR, not
 * the enforcement: migration 019 refuses the row regardless of what this
 * function returns. It exists so the API can answer 400 with a sentence instead
 * of letting a 23514 reach the error handler as a 500.
 */
/**
 * Every character PostgreSQL's `[[:space:]]` class strips, plus the invisible
 * ones it does not: no-break space, the U+2000 block, zero-width space, joiners,
 * the Braille blank and the BOM. `String.prototype.trim()` leaves several of
 * them, so thirty zero-width spaces used to satisfy a 24-character minimum here
 * while the database CHECK refused the row.
 */
const INVISIBLE = /[\s  ᠎ -‏  ⁠⠀　﻿]/g;

/**
 * The client-side mirror of the database CHECK, and it must stay the STRICTER of
 * the two readings rather than the friendlier one: a guard that says "fine" and
 * is then refused by Postgres teaches an operator that the error is a glitch to
 * retry, not a rule to respect.
 */
export function justificationProblem(raw: unknown): string | null {
  if (typeof raw !== 'string') return 'A justification is required.';
  const substance = raw.normalize('NFKC').replace(INVISIBLE, '');
  // A justification made only of punctuation is not a justification.
  if (!/[\p{L}\p{N}]/u.test(substance)) {
    return 'A justification must contain words — say WHY this drift is accepted.';
  }
  const trimmed = substance;
  if (trimmed.length < MIN_JUSTIFICATION_LENGTH) {
    return `A justification of at least ${MIN_JUSTIFICATION_LENGTH} characters is required — `
      + 'say WHY this drift is accepted, not that it is.';
  }
  if (trimmed.length > MAX_JUSTIFICATION_LENGTH) {
    return `A justification may not exceed ${MAX_JUSTIFICATION_LENGTH} characters.`;
  }
  return null;
}

/** Same shape for the review date. */
export function reviewDateProblem(raw: unknown, now: Date = new Date()): string | null {
  if (typeof raw !== 'string' || raw.length === 0) return 'A review date is required.';
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return 'The review date is not a valid date.';
  if (d.getTime() <= now.getTime()) return 'The review date must be in the future.';
  const max = now.getTime() + MAX_REVIEW_HORIZON_DAYS * 86_400_000;
  if (d.getTime() > max) {
    return `The review date may not be more than ${MAX_REVIEW_HORIZON_DAYS} days out — `
      + 'an exception nobody ever revisits is a permanent suppression.';
  }
  return null;
}

// ============================================================================
// F2 — The attestation
// ============================================================================

/**
 * The verdict, and the two middle values are the honest ones.
 *
 * `continuous`            one configuration held for the whole window, and we
 *                         observed it often enough to say so.
 * `continuous_with_gaps`  one configuration, but there are stretches during
 *                         which NOBODY LOOKED. The claim is weaker and the
 *                         document says exactly where.
 * `changed`               the configuration changed inside the window. Not a
 *                         failure — the periods and the changes are the answer.
 * `insufficient_evidence` no snapshot covers the window. Refusing to attest is
 *                         a feature; an attestation that always says yes is
 *                         worth nothing to the party who asked for it.
 */
export const ATTESTATION_VERDICTS = [
  'continuous',
  'continuous_with_gaps',
  'changed',
  'insufficient_evidence',
] as const;
export type AttestationVerdict = (typeof ATTESTATION_VERDICTS)[number];

/**
 * The version of the RULES a verdict was drawn by, and it lives in the HASHED
 * header for the same reason `maxGapDays` does.
 *
 * `verdict` and `statement` are not evidence rows: they are a CONCLUSION about
 * the rows. Until v2 nothing about how that conclusion was reached entered
 * `evidenceRoot`, so two documents with an identical root could carry opposite
 * claims — one `continuous`, one `continuous_with_gaps` — and every hash in
 * both of them would recompute. A reader handed the flattering one had no way
 * to notice.
 *
 * v1  gaps only; the tolerance was an argument of `build()` and appeared
 *     nowhere in the emitted JSON.
 * v2  the tolerance is a hashed header member, and a period vouched for by
 *     fewer than MIN_INDEPENDENT_SOURCES_FOR_CONTINUOUS distinct source ROWS
 *     may not be called `continuous`.
 */
export const ATTESTATION_JUDGE_VERSION = 'obliwan.attestation.judge/v2';

/**
 * How many DISTINCT source rows a period needs before the word `continuous`
 * may be used about it.
 *
 * `config_snapshots` carries two dates, `captured_at` and `last_seen_at`. Both
 * are real observations, and both come from ONE row. A period built out of
 * nothing else is a claim resting on a single record, and describing it as
 * "confirmed by 2 independent dated observations" is false in the one word
 * that matters. `confirmations` counts DATES; this counts SOURCES.
 */
export const MIN_INDEPENDENT_SOURCES_FOR_CONTINUOUS = 2;

/** Kinds of evidence entry. The chain covers them all, in one order. */
export const EVIDENCE_KINDS = [
  'snapshot',
  'observation',
  'change_job',
  'apply_outcome',
  'command',
  'exception',
] as const;
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number];

/**
 * One evidence row, and the shape is the whole trick.
 *
 * `fields` is an ORDERED array of `[name, value | null]`. The hash is computed
 * over THAT array and nothing else, which means a verifier needs no knowledge
 * of our schema whatsoever: it walks the array it was handed, encodes each
 * entry by the published rule, and checks the digest. Adding a column to
 * `config_snapshots` next year does not break last year's verifier.
 *
 * The alternative — a typed object per kind, hashed by a schema both sides must
 * agree on — is the design where the verifier has to be upgraded in lockstep
 * with the producer, which in practice means the verifier is never run again.
 */
export interface EvidenceEntry {
  seq: number;
  kind: EvidenceKind;
  fields: [string, string | null][];
  /** sha256 of the row preimage. See ATTESTATION_METHOD. */
  rowHash: string;
  /** sha256 linking this row to the previous one. The last one is the root. */
  chainHash: string;
}

export interface AttestationPeriod {
  ncmHash: string;
  /** sha256 of the RAW redacted export, when we still hold the archive. This is
   *  the ONE hash a customer can verify against their own copy of the config
   *  with `sha256sum` and no ObliWAN code at all. */
  rawSha256: string | null;
  /** Start of the period as evidence supports it. */
  from: string;
  to: string;
  /** True when `from` is the moment the configuration was FIRST captured rather
   *  than merely the earliest point inside the requested window. */
  fromExact: boolean;
  toExact: boolean;
  /** Dated observations that the device carried this exact hash. A single
   *  `config_snapshots` row contributes TWO of them (`captured_at` and
   *  `last_seen_at`), which is why this number on its own never justifies the
   *  word `continuous` — see `independentSources`. */
  confirmations: number;
  /** How many DISTINCT source ROWS those observations came from. Two dates off
   *  one snapshot row are one source, not two. */
  independentSources: number;
  /** Stretches inside the period during which nothing observed the device. */
  gaps: { from: string; to: string; seconds: number }[];
  snapshotId: string;
}

export interface AttestationChange {
  jobId: string;
  jobUuid: string;
  kind: string;
  status: string;
  outcome: string | null;
  baseStateHash: string;
  safetyLevel: string;
  guardVerdict: string | null;
  wasOverridden: boolean;
  requestedByUsername: string | null;
  approvedByUsername: string | null;
  startedAt: string | null;
  finishedAt: string | null;
}

/**
 * The published verification procedure. This object is embedded VERBATIM in
 * every attestation, so the document carries its own specification.
 */
export const ATTESTATION_METHOD = {
  spec: 'obliwan.attestation/v1',
  hash: 'SHA-256, output as 64 lowercase hex characters',
  fieldEncoding:
    'enc(v) = "-1:" when v is null, otherwise decimal-UTF8-byte-length + ":" + v. '
    + 'Length-prefixing is what makes the concatenation unambiguous: without it, '
    + 'two adjacent fields could be re-split and produce the same preimage.',
  rowHash:
    'rowHash = SHA256("obliwan.evidence.row.v1" + enc(kind) + '
    + 'for each [name, value] of fields in order: enc(name) + enc(value))',
  chain:
    'chainHash[0] = SHA256("obliwan.evidence.chain.v1" + enc(headerCanonicalJson) + enc(rowHash[0])); '
    + 'chainHash[i] = SHA256("obliwan.evidence.chain.v1" + enc(chainHash[i-1]) + enc(rowHash[i])). '
    + 'evidenceRoot = chainHash of the LAST entry, or SHA256("obliwan.evidence.chain.v1" + '
    + 'enc(headerCanonicalJson)) when there is no entry at all.',
  header:
    'headerCanonicalJson is the `chainHeader` member of this document, serialised as '
    + 'JSON with object keys sorted ascending by UTF-16 code unit, no whitespace, and no '
    + 'undefined members. It deliberately EXCLUDES issuedAt, so re-issuing an attestation '
    + 'over the same window must reproduce the same evidenceRoot. A different root for the '
    + 'same window means the underlying evidence changed. The header also carries every '
    + 'PARAMETER the verdict was drawn under — `maxGapDays`, the tolerated stretch of '
    + 'unobserved time, and `judgeVersion`, the rulebook that produced `claim`. Both are '
    + 'therefore inside evidenceRoot: two documents over the same window drawn under '
    + 'different tolerances CANNOT share a root. A chainHeader lacking either member is '
    + 'not a v2 document and must be rejected.',
  documentDigest:
    'SHA256(canonicalJson(this document with the `documentDigest` member removed)). '
    + 'Identifies this exact issued document, including its issuedAt.',
  timestamps: 'ISO-8601, UTC, milliseconds — exactly JavaScript Date.toISOString().',
  auditLog:
    'The `auditChain` section carries the tenant-scoped append-only ledger rows whose '
    + 'occurredAt falls in the window. Verify it independently: seq must be contiguous, '
    + 'prevHash of row n must equal hash of row n-1, and hash must equal '
    + 'SHA256("obliwan.audit.v1" + enc(prevHash) + enc(tenantId) + enc(seq) + enc(occurredAt) + '
    + 'enc(actorType) + enc(actorId) + enc(actorName) + enc(action) + enc(entityType) + '
    + 'enc(entityId) + enc(correlationId) + enc(beforeJson) + enc(afterJson)), where the two '
    + 'json members are the jsonb columns rendered by Postgres `::text` and NULL columns are '
    + 'encoded as null. The hashes are computed by the DATABASE on insert, not by the '
    + 'application. occurredAt is rendered by Postgres as '
    + "to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"').",
  limits: [
    'This document is NOT cryptographically signed. It proves INTERNAL CONSISTENCY of the '
    + 'evidence set it carries and detects any later edit to that set — it does not prove '
    + 'that ObliWAN did not compute a different set from the start.',
    "ncmHash is computed over ObliWAN's normalised model of the configuration, so verifying "
    + 'it requires ObliWAN\'s canonicaliser. rawSha256 does NOT: it is the SHA-256 of the raw '
    + 'redacted device export, and anyone holding that file can check it with sha256sum.',
    'The evidence set is bounded by what was collected. A period reported with gaps is a '
    + 'period during which nothing looked at the device, and the document says so rather '
    + 'than interpolating.',
    'No secret material is present by construction: this document carries hashes, timestamps '
    + 'and identifiers, never a configuration body and never a command line.',
    'The verdict is a CONCLUSION, not evidence. Read chainHeader.maxGapDays before reading '
    + 'claim.verdict: `continuous` means "no unobserved stretch longer than that tolerance", '
    + 'and a large tolerance is a weak claim wearing a strong word. Both the tolerance and '
    + 'the rulebook version are inside the hashed header precisely so that this cannot be '
    + 'tuned invisibly.',
    'periods[].confirmations counts DATES; periods[].independentSources counts the distinct '
    + 'source ROWS behind them. One config_snapshots row supplies two dates (captured_at and '
    + 'last_seen_at) and is ONE source. A period with fewer than two independent sources is '
    + 'never reported as `continuous`, however long the tolerance.',
  ],
} as const;

/**
 * The chain header — hashed, and deliberately free of `issuedAt`.
 *
 * ┌─ EVERY KNOB THAT CAN MOVE THE VERDICT BELONGS IN HERE ────────────────────┐
 * │ The header is the SEED of the evidence chain, so anything named in it is  │
 * │ covered by `evidenceRoot`. Anything not named in it is a parameter the    │
 * │ reader cannot see and the chain cannot detect.                            │
 * │                                                                           │
 * │ `maxGapDays` used to be exactly that — an argument passed to `build()`,   │
 * │ absent from the emitted JSON and absent from the root. Asking for a       │
 * │ 365-day tolerance over a 365-day window turned a period nothing had       │
 * │ looked at for a year into the word `continuous`, and the root came out    │
 * │ byte-identical to the honest document's. It is a header member now, and   │
 * │ so is `judgeVersion`.                                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export interface AttestationChainHeader {
  spec: string;
  /** `ATTESTATION_JUDGE_VERSION` — which rulebook produced `claim`. */
  judgeVersion: string;
  tenantId: number;
  deviceUuid: string;
  deviceName: string;
  brand: string;
  model: string | null;
  serial: string | null;
  windowFrom: string;
  windowTo: string;
  /**
   * The declared tolerance, in days: a stretch during which nothing observed
   * the device is a GAP once it exceeds this. Hashed, printed in `claim`, and
   * CAPPED at issuance — see `DEFAULT_MAX_GAP_DAYS` on the server.
   */
  maxGapDays: number;
}

export interface AuditChainRow {
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

export interface AttestationDocument {
  spec: 'obliwan.attestation/v1';
  /** Populated once the attestation is persisted; absent on a dry preview. */
  attestationUuid?: string;
  issuedAt: string;
  issuedByUsername: string;
  generator: string;

  chainHeader: AttestationChainHeader;

  claim: {
    verdict: AttestationVerdict;
    /** One English sentence stating exactly what is being attested. */
    statement: string;
    windowFrom: string;
    windowTo: string;
    /** Set only when the verdict is `continuous` or `continuous_with_gaps`. */
    ncmHash: string | null;
    /** The tolerance the verdict was drawn under, repeated out of the hashed
     *  header so a reader who only reads `claim` still sees it. */
    maxGapDays: number;
    /** Distinct source rows behind the attested period; 0 when no single
     *  period is being claimed. */
    independentSources: number;
    /** `ATTESTATION_JUDGE_VERSION`, repeated out of the header. */
    judgeVersion: string;
  };

  periods: AttestationPeriod[];
  changes: AttestationChange[];
  /** Counters rather than rows: a command line is not needed to establish that
   *  N writes happened, and not carrying them removes an entire class of
   *  secret-leak risk from a document meant to be forwarded to third parties. */
  commandSummary: {
    total: number;
    writes: number;
    failed: number;
    inFlight: number;
    firstAt: string | null;
    lastAt: string | null;
  };
  applyOutcomes: { outcome: string; count: number }[];
  /** Exceptions (F1) in force over the window — an insurer asking "was this box
   *  compliant" deserves to see what was deliberately forgiven. */
  acceptedDrift: {
    exceptionUuid: string;
    semKey: string;
    resource: string;
    path: string | null;
    justification: string;
    severityAtCreation: string | null;
    createdByUsername: string;
    createdAt: string;
    reviewDueAt: string;
    state: ExceptionState;
  }[];

  evidence: EvidenceEntry[];
  auditChain: AuditChainRow[];

  evidenceRoot: string;
  entryCount: number;
  verification: typeof ATTESTATION_METHOD;
  /** sha256 of this document with this member removed. */
  documentDigest: string;
}

// ============================================================================
// The hashing primitives — small on purpose. Reimplement, do not import.
// ============================================================================

const ROW_DOMAIN = 'obliwan.evidence.row.v1';
const CHAIN_DOMAIN = 'obliwan.evidence.chain.v1';
export const AUDIT_DOMAIN = 'obliwan.audit.v1';

/** UTF-8 byte length. `TextEncoder` is already the dependency `ncm/hash` took. */
function byteLen(s: string): number {
  return new TextEncoder().encode(s).length;
}

/**
 * `enc(null) = "-1:"`, `enc(v) = byteLength(v) + ":" + v`.
 *
 * The length prefix is not decoration. Without it `["ab","c"]` and `["a","bc"]`
 * concatenate to the same string, and two different evidence rows would collide
 * — which is the entire attack a chain is supposed to prevent.
 */
export function encodeField(v: string | null): string {
  return v === null ? '-1:' : `${byteLen(v)}:${v}`;
}

export function evidenceRowHash(kind: string, fields: [string, string | null][]): string {
  let s = ROW_DOMAIN + encodeField(kind);
  for (const [name, value] of fields) s += encodeField(name) + encodeField(value);
  return sha256Hex(s);
}

/** Seeds the chain from the header, so the evidence cannot be lifted wholesale
 *  from one device's attestation and pasted into another's. */
export function evidenceChainSeed(header: AttestationChainHeader): string {
  return CHAIN_DOMAIN + encodeField(canonicalJson(header as unknown as Record<string, unknown>));
}

export function evidenceChainStep(
  prev: string | null,
  rowHash: string,
  header?: AttestationChainHeader,
): string {
  if (prev === null) {
    if (!header) throw new Error('evidenceChainStep: the first link needs the header');
    return sha256Hex(evidenceChainSeed(header) + encodeField(rowHash));
  }
  return sha256Hex(CHAIN_DOMAIN + encodeField(prev) + encodeField(rowHash));
}

/** The root of an empty evidence set — an attestation over a window in which
 *  nothing at all was recorded is still a document, and still hashes. */
export function emptyEvidenceRoot(header: AttestationChainHeader): string {
  return sha256Hex(evidenceChainSeed(header));
}

/** Preimage of one `audit_log` row. Mirrors the plpgsql of migration 019 —
 *  the DATABASE is the producer, this is only how a reader re-checks it. */
export function auditRowPreimage(
  tenantId: number,
  r: Omit<AuditChainRow, 'id' | 'hash'>,
): string {
  return AUDIT_DOMAIN
    + encodeField(r.prevHash)
    + encodeField(String(tenantId))
    + encodeField(r.seq)
    + encodeField(r.occurredAt)
    + encodeField(r.actorType)
    + encodeField(r.actorId)
    + encodeField(r.actorName)
    + encodeField(r.action)
    + encodeField(r.entityType)
    + encodeField(r.entityId)
    + encodeField(r.correlationId)
    + encodeField(r.beforeJson)
    + encodeField(r.afterJson);
}

export interface ChainProblem {
  seq: number;
  field: 'rowHash' | 'chainHash' | 'evidenceRoot' | 'documentDigest' | 'auditChain';
  expected: string;
  found: string;
}

/**
 * Recomputes every hash in an attestation and reports what does not match.
 *
 * Shipped so the CLIENT can verify a document it was handed rather than
 * displaying "verified" because the server said so. It is NOT the independent
 * verifier the attestation's value rests on — an independent verifier is one
 * written from `ATTESTATION_METHOD` by somebody who does not run this code, and
 * the whole point of publishing the method is that writing one is easy.
 */
export function verifyAttestation(doc: AttestationDocument): ChainProblem[] {
  const problems: ChainProblem[] = [];
  let prev: string | null = null;

  doc.evidence.forEach((e, i) => {
    const rh = evidenceRowHash(e.kind, e.fields);
    if (rh !== e.rowHash) {
      problems.push({ seq: e.seq, field: 'rowHash', expected: rh, found: e.rowHash });
    }
    const ch = evidenceChainStep(i === 0 ? null : prev, rh, doc.chainHeader);
    if (ch !== e.chainHash) {
      problems.push({ seq: e.seq, field: 'chainHash', expected: ch, found: e.chainHash });
    }
    prev = e.chainHash;
  });

  const root = doc.evidence.length === 0
    ? emptyEvidenceRoot(doc.chainHeader)
    : doc.evidence[doc.evidence.length - 1].chainHash;
  if (root !== doc.evidenceRoot) {
    problems.push({ seq: -1, field: 'evidenceRoot', expected: root, found: doc.evidenceRoot });
  }

  const { documentDigest: _drop, ...rest } = doc;
  const digest = sha256Hex(canonicalJson(rest as unknown as Record<string, unknown>));
  if (digest !== doc.documentDigest) {
    problems.push({ seq: -1, field: 'documentDigest', expected: digest, found: doc.documentDigest });
  }

  // The audit ledger is chained by the DATABASE, so verifying it here is a
  // genuinely independent check of a value this process did not compute.
  let prevAudit: string | null = null;
  let prevSeq: bigint | null = null;
  doc.auditChain.forEach((r, i) => {
    const h = sha256Hex(auditRowPreimage(doc.chainHeader.tenantId, r));
    if (h !== r.hash) {
      problems.push({ seq: i, field: 'auditChain', expected: h, found: r.hash });
    }
    if (prevAudit !== null && r.prevHash !== prevAudit) {
      problems.push({
        seq: i,
        field: 'auditChain',
        expected: prevAudit,
        found: r.prevHash ?? 'null',
      });
    }
    const seq = BigInt(r.seq);
    if (prevSeq !== null && seq !== prevSeq + 1n) {
      problems.push({ seq: i, field: 'auditChain', expected: String(prevSeq + 1n), found: r.seq });
    }
    prevAudit = r.hash;
    prevSeq = seq;
  });

  return problems;
}

/** Convenience for a UI that wants a value by name out of `fields`. */
export function evidenceField(entry: EvidenceEntry, name: string): string | null {
  const hit = entry.fields.find(([n]) => n === name);
  return hit ? hit[1] : null;
}
