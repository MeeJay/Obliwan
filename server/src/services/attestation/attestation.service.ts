// ============================================================================
// ObliWAN — F2: the compliance attestation (ARCHITECTURE §10)
// ============================================================================
//
// ┌─ THE PROPERTY THAT MATTERS IS "VERIFIABLE", NOT "OFFICIAL-LOOKING" ───────┐
// │ An attestation a reader has to take on our word is worth nothing in front │
// │ of an insurer. The document produced here carries:                        │
// │                                                                           │
// │   1. every evidence row, as an ORDERED list of named fields;              │
// │   2. the SHA-256 of each row and the chain that links them;               │
// │   3. `rawSha256` — the digest of the raw device export, which a customer  │
// │      holding their own copy checks with `sha256sum` and no ObliWAN code;  │
// │   4. a slice of the `audit_log` chain, whose hashes were computed by      │
// │      POSTGRES and not by this process;                                    │
// │   5. `verification`, the algorithm itself, in prose, inside the document. │
// │                                                                           │
// │ Anyone can reimplement (1)-(4) from (5) in about fifteen lines. That is   │
// │ the design target: a verification procedure nobody can implement is a     │
// │ verification procedure that will never be run.                            │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ── WHAT IT DELIBERATELY DOES NOT DO ───────────────────────────────────────
//
// It does not sign. There is no PKI in this product, and a "signature" that is
// an HMAC with a key living in the same database as the data it signs proves
// nothing to a third party — it would be a stronger-looking claim with the same
// strength, which is the worst possible outcome for a compliance document. The
// gap is stated in `ATTESTATION_METHOD.limits`, inside every document.
//
// ── SECRETS (§8.2 / R10) ───────────────────────────────────────────────────
//
// The document carries hashes, timestamps, identifiers, counters and operator
// prose. It never carries `config_snapshots.ncm`, never `change_plans.ops`,
// never `command_audit.command`. That is not a filter applied at the end — it
// is which columns `evidence.ts` selects.

import { randomUUID } from 'node:crypto';
// `canonicalJson` and `sha256Hex` come from the NCM contract, which the barrel
// already exports: the document digest is deliberately the SAME serialiser and
// the SAME hash the snapshots are keyed by, so a reader learns one rule.
import { canonicalJson, sha256Hex } from '@obliwan/shared';
import {
  ATTESTATION_JUDGE_VERSION,
  ATTESTATION_METHOD,
  PUBLISHED_METHOD,
  AttestationChainHeader,
  AttestationChange,
  AttestationDocument,
  AttestationPeriod,
  AttestationVerdict,
  ChainProblem,
  EvidenceEntry,
  EvidenceKind,
  MIN_INDEPENDENT_SOURCES_FOR_CONTINUOUS,
  emptyEvidenceRoot,
  evidenceChainStep,
  evidenceRowHash,
  verifyAttestation,
} from './contract';
import { db } from '../../db';
import { exceptionsInForce } from '../drift/exception.service';
import {
  ChainTooLongError,
  appendAudit,
  chainRangeForWindow,
  chainSlice,
} from './auditLog.service';
import {
  DEFAULT_MAX_GAP_DAYS,
  DerivedPeriod,
  MAX_EVIDENCE_ENTRIES,
  derivePeriods,
  loadApplyOutcomes,
  loadChangeJobs,
  loadCommandSummary,
  loadObservations,
  loadSnapshots,
  loadSubject,
} from './evidence';

export class AttestationError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'AttestationError';
  }
}

export const GENERATOR = 'obliwan/attestation-1.0';

export interface BuildOptions {
  deviceId: number;
  from: Date;
  to: Date;
  /**
   * Tolerated stretch of unobserved time. Free on `/preview`, CAPPED on
   * `/issue` — see `issue()`. Whatever it ends up being, it is written into
   * the hashed `chainHeader` and printed in `claim`, so it can no longer be a
   * knob only the caller knows about.
   */
  maxGapDays?: number;
  /** Who is asking. Recorded in the document and in the ledger. */
  issuedByUsername: string;
  issuedByUserId: number | null;
}

/**
 * The tolerance actually used, from whatever the caller asked for.
 *
 * Negative and non-finite values would produce a `maxGapSeconds` that makes
 * every instant a gap (or none of them); both are refused rather than clamped
 * silently into a claim.
 */
function resolveMaxGapDays(raw: number | undefined): number {
  if (raw === undefined) return DEFAULT_MAX_GAP_DAYS;
  if (!Number.isFinite(raw) || raw < 0) {
    throw new AttestationError(400, 'maxGapDays must be a non-negative number of days.');
  }
  return raw;
}

// ============================================================================
// Building
// ============================================================================

const ISO = (d: Date): string => d.toISOString();
const N = (v: number | null | undefined): string | null =>
  v === null || v === undefined ? null : String(v);

/**
 * Assembles the document. Reads only; nothing is written and nothing is
 * persisted — `issue()` below is what commits one.
 *
 * Splitting build from issue is not tidiness: an operator must be able to LOOK
 * at what would be attested before putting a permanent, frozen, ledger-recorded
 * statement into the world. A preview that goes through a different code path
 * from the issued document would be a preview of something else.
 */
export async function build(tenantId: number, opts: BuildOptions): Promise<AttestationDocument> {
  if (opts.to.getTime() <= opts.from.getTime()) {
    throw new AttestationError(400, 'The window must end after it starts.');
  }
  const subject = await loadSubject(tenantId, opts.deviceId);
  if (!subject) throw new AttestationError(404, 'Device not found');

  const maxGapDays = resolveMaxGapDays(opts.maxGapDays);
  const maxGapSeconds = maxGapDays * 86_400;

  const snapshots = await loadSnapshots(opts.deviceId, opts.from, opts.to);
  const observations = await loadObservations(tenantId, opts.deviceId, snapshots);
  const periods = derivePeriods(observations, snapshots, { from: opts.from, to: opts.to }, maxGapSeconds);
  const jobs = await loadChangeJobs(tenantId, opts.deviceId, opts.from, opts.to);
  const outcomes = await loadApplyOutcomes(tenantId, opts.deviceId, opts.from, opts.to);
  const commands = await loadCommandSummary(tenantId, opts.deviceId, opts.from, opts.to);
  const exceptions = await exceptionsInForce(tenantId, opts.deviceId, opts.from, opts.to);

  // ── The header, and `maxGapDays` is IN IT ────────────────────────────────
  //
  // The header seeds the evidence chain, so every member of it is covered by
  // `evidenceRoot`. That is the whole reason the tolerance and the judge
  // version live here rather than in `BuildOptions` alone: a document built at
  // 365 days and a document built at 7 over the same window are now two
  // different roots, and the flattering one can no longer be passed off as the
  // honest one's twin.
  const header: AttestationChainHeader = {
    spec: ATTESTATION_METHOD.spec,
    judgeVersion: ATTESTATION_JUDGE_VERSION,
    tenantId,
    deviceUuid: subject.uuid,
    deviceName: subject.name,
    brand: subject.brand,
    model: subject.model,
    serial: subject.serial,
    windowFrom: ISO(opts.from),
    windowTo: ISO(opts.to),
    maxGapDays,
  };

  // ── The evidence rows, in a FIXED order ─────────────────────────────────
  //
  // The chain is order-sensitive, so the sequence has to be a function of the
  // data and never of a query planner's mood. Every source below is loaded with
  // an explicit ORDER BY, and the sections are concatenated in a constant order.
  const rows: { kind: EvidenceKind; fields: [string, string | null][] }[] = [];

  for (const s of snapshots) {
    rows.push({
      kind: 'snapshot',
      fields: [
        ['snapshotId', s.id],
        ['deviceUuid', subject.uuid],
        ['ncmHash', s.ncmHash],
        // THE hash a third party can check against their own copy of the
        // export with no ObliWAN code at all.
        ['rawSha256', s.rawSha256],
        ['rawBytes', N(s.rawBytes)],
        ['source', s.source],
        ['capturedAt', ISO(s.capturedAt)],
        ['lastSeenAt', ISO(s.lastSeenAt)],
        ['seenCount', String(s.seenCount)],
        ['ncmVersion', String(s.ncmVersion)],
        ['semKeyGeneration', String(s.semKeyGeneration)],
        ['normalizationEpoch', s.normalizationEpoch],
        ['orderAnalysis', s.orderAnalysis],
        ['osVersion', s.osVersion],
        ['unmodeledForwardingCount', String(s.unmodeledForwardingCount)],
      ],
    });
  }

  for (const o of observations) {
    rows.push({
      kind: 'observation',
      fields: [
        ['at', ISO(o.at)],
        ['ncmHash', o.ncmHash],
        ['source', o.source],
        ['refTable', o.refTable],
        ['refId', o.refId],
      ],
    });
  }

  for (const j of jobs) {
    rows.push({
      kind: 'change_job',
      fields: [
        ['jobId', j.id],
        ['jobUuid', j.uuid],
        ['kind', j.kind],
        ['status', j.status],
        ['outcome', j.outcome],
        ['baseStateHash', j.baseStateHash],
        ['safetyLevel', j.safetyLevel],
        ['guardVerdict', j.guardVerdict],
        ['overridden', j.overriddenAt === null ? 'false' : 'true'],
        ['requestedBy', j.requestedBy],
        ['approvedBy', j.approvedBy],
        ['createdAt', ISO(j.createdAt)],
        ['startedAt', j.startedAt === null ? null : ISO(j.startedAt)],
        ['finishedAt', j.finishedAt === null ? null : ISO(j.finishedAt)],
      ],
    });
  }

  for (const o of outcomes) {
    rows.push({
      kind: 'apply_outcome',
      fields: [
        ['outcome', o.outcome],
        ['count', String(o.count)],
        ['firstAt', ISO(o.firstAt)],
        ['lastAt', ISO(o.lastAt)],
      ],
    });
  }

  // One row, counters only — see `loadCommandSummary`. It is inside the chain
  // so that "no write happened on this box that night" is itself covered by the
  // digest rather than being a number the reader has to trust.
  rows.push({
    kind: 'command',
    fields: [
      ['total', String(commands.total)],
      ['writes', String(commands.writes)],
      ['failed', String(commands.failed)],
      ['inFlight', String(commands.inFlight)],
      ['firstAt', commands.firstAt === null ? null : ISO(commands.firstAt)],
      ['lastAt', commands.lastAt === null ? null : ISO(commands.lastAt)],
    ],
  });

  for (const e of exceptions) {
    rows.push({
      kind: 'exception',
      fields: [
        ['exceptionUuid', e.uuid],
        ['semKey', e.semKey],
        ['resource', e.resource],
        ['path', e.path],
        ['severityAtCreation', e.severityAtCreation],
        ['justification', e.justification],
        ['createdBy', e.createdByUsername],
        ['createdAt', e.createdAt],
        ['reviewDueAt', e.reviewDueAt],
        ['status', e.status],
        ['revokedAt', e.revokedAt],
        ['renewalCount', String(e.renewalCount)],
      ],
    });
  }

  if (rows.length > MAX_EVIDENCE_ENTRIES) {
    throw new AttestationError(
      413,
      `This window covers ${rows.length} evidence rows (limit ${MAX_EVIDENCE_ENTRIES}). `
        + 'Narrow the window — an attestation is a document, not a data export.',
    );
  }

  const evidence: EvidenceEntry[] = [];
  let prev: string | null = null;
  rows.forEach((r, i) => {
    const rowHash = evidenceRowHash(r.kind, r.fields);
    const chainHash = evidenceChainStep(i === 0 ? null : prev, rowHash, header);
    evidence.push({ seq: i, kind: r.kind, fields: r.fields, rowHash, chainHash });
    prev = chainHash;
  });

  const evidenceRoot = evidence.length === 0
    ? emptyEvidenceRoot(header)
    : evidence[evidence.length - 1].chainHash;

  const claim = judge(periods, { from: opts.from, to: opts.to }, maxGapDays);

  const doc: Omit<AttestationDocument, 'documentDigest'> = {
    spec: 'obliwan.attestation/v1',
    issuedAt: ISO(new Date()),
    issuedByUsername: opts.issuedByUsername,
    generator: GENERATOR,
    chainHeader: header,
    claim,
    periods: periods.map((p): AttestationPeriod => ({
      ncmHash: p.ncmHash,
      rawSha256: snapshots.find((s) => s.ncmHash === p.ncmHash)?.rawSha256 ?? null,
      from: ISO(p.from),
      to: ISO(p.to),
      fromExact: p.fromExact,
      toExact: p.toExact,
      confirmations: p.confirmations,
      independentSources: p.independentSources,
      gaps: p.gaps.map((g) => ({ from: ISO(g.from), to: ISO(g.to), seconds: g.seconds })),
      snapshotId: p.snapshotId,
    })),
    changes: jobs.map((j): AttestationChange => ({
      jobId: j.id,
      jobUuid: j.uuid,
      kind: j.kind,
      status: j.status,
      outcome: j.outcome,
      baseStateHash: j.baseStateHash,
      safetyLevel: j.safetyLevel,
      guardVerdict: j.guardVerdict,
      wasOverridden: j.overriddenAt !== null,
      requestedByUsername: j.requestedBy,
      approvedByUsername: j.approvedBy,
      startedAt: j.startedAt === null ? null : ISO(j.startedAt),
      finishedAt: j.finishedAt === null ? null : ISO(j.finishedAt),
    })),
    commandSummary: {
      total: commands.total,
      writes: commands.writes,
      failed: commands.failed,
      inFlight: commands.inFlight,
      firstAt: commands.firstAt === null ? null : ISO(commands.firstAt),
      lastAt: commands.lastAt === null ? null : ISO(commands.lastAt),
    },
    applyOutcomes: outcomes.map((o) => ({ outcome: o.outcome, count: o.count })),
    acceptedDrift: exceptions.map((e) => ({
      exceptionUuid: e.uuid,
      semKey: e.semKey,
      resource: e.resource,
      path: e.path,
      justification: e.justification,
      severityAtCreation: e.severityAtCreation,
      createdByUsername: e.createdByUsername,
      createdAt: e.createdAt,
      reviewDueAt: e.reviewDueAt,
      state: e.state,
    })),
    evidence,
    auditChain: await loadAuditChain(tenantId, opts.from, opts.to),
    evidenceRoot,
    entryCount: evidence.length,
    // `PUBLISHED_METHOD` and not `ATTESTATION_METHOD`: the shared constant's
    // `auditLog` sentence describes a slice filtered by time, and
    // `loadAuditChain` below produces a CONTIGUOUS one by `seq` — which is the
    // right choice and the wrong description. See the box on
    // `PUBLISHED_METHOD`: a document whose published method contradicts the
    // document's own contents is the one defect a hash chain cannot warn
    // anybody about, because both halves recompute perfectly.
    verification: PUBLISHED_METHOD,
  };

  const documentDigest = sha256Hex(canonicalJson(doc as unknown as Record<string, unknown>));
  return { ...doc, documentDigest };
}

/**
 * A CONTIGUOUS slice of the tenant's ledger, translated from the time window
 * into a sequence range first.
 *
 * Filtering the chain by timestamp would produce holes wherever a row falls
 * outside the window, and a chain with holes fails its own verification for a
 * reason that has nothing to do with tampering — a verifier that cries wolf on
 * a correct document is worse than no verifier.
 */
async function loadAuditChain(
  tenantId: number,
  from: Date,
  to: Date,
): Promise<AttestationDocument['auditChain']> {
  const range = await chainRangeForWindow(tenantId, from, to);
  if (!range) return [];
  try {
    return await chainSlice(tenantId, range.fromSeq, range.toSeq);
  } catch (err) {
    // Surfaced as a 413 with the same sentence as an oversized evidence set: a
    // truncated chain would pass verification and still be an incomplete
    // answer, so the caller is told to narrow the window instead.
    if (err instanceof ChainTooLongError) throw new AttestationError(413, err.message);
    throw err;
  }
}

/**
 * The verdict, and every branch of it is a refusal to overstate.
 *
 * A single period that COVERS the whole window is the only shape that supports
 * a continuity claim. One that merely intersects it leaves the rest of the
 * window unobserved, and "we have a snapshot from somewhere in there" is not
 * the same statement as "it was in this configuration throughout" — so it comes
 * out as `insufficient_evidence` rather than as a hedged yes.
 *
 * ┌─ TWO WAYS `continuous` USED TO BE PURCHASED, AND HOW BOTH ARE SHUT ───────┐
 * │ 1. BUY THE TOLERANCE. `maxGapDays` was a caller argument that appeared    │
 * │    nowhere in the document. Passing 365 over a 365-day window emptied     │
 * │    the gap list and printed "continuously", with an evidenceRoot          │
 * │    IDENTICAL to the honest 7-day document's. The tolerance is now a       │
 * │    hashed `chainHeader` member AND it is printed in the sentence below,   │
 * │    so a reader is told exactly how weak the claim is and the chain        │
 * │    covers the number.                                                     │
 * │                                                                           │
 * │ 2. COUNT ONE ROW TWICE. `confirmations` counts DATES, and a single        │
 * │    `config_snapshots` row supplies two of them — `captured_at` and        │
 * │    `last_seen_at`. "Confirmed by 2 independent dated observations" over   │
 * │    one record is the false word in an otherwise true sentence.            │
 * │    `independentSources` counts SOURCE ROWS, and under                     │
 * │    MIN_INDEPENDENT_SOURCES_FOR_CONTINUOUS the verdict is downgraded and   │
 * │    the sentence says so in capitals.                                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
function judge(
  periods: readonly DerivedPeriod[],
  window: { from: Date; to: Date },
  maxGapDays: number,
): AttestationDocument['claim'] {
  const base = {
    windowFrom: ISO(window.from),
    windowTo: ISO(window.to),
    maxGapDays,
    judgeVersion: ATTESTATION_JUDGE_VERSION,
  };
  const tolerance = `the declared tolerance of ${maxGapDays} day(s) without an observation`;

  const covering = periods.find(
    (p) => p.from.getTime() <= window.from.getTime() && p.to.getTime() >= window.to.getTime(),
  );

  if (covering && periods.length === 1) {
    const gapSeconds = covering.gaps.reduce((a, g) => a + g.seconds, 0);
    const thin = covering.independentSources < MIN_INDEPENDENT_SOURCES_FOR_CONTINUOUS;
    const verdict: AttestationVerdict = covering.gaps.length > 0 || thin
      ? 'continuous_with_gaps'
      : 'continuous';

    const witnesses = `${covering.confirmations} dated observation(s) drawn from `
      + `${covering.independentSources} independent source row(s)`;

    let statement: string;
    if (covering.gaps.length > 0) {
      statement = `The device was observed in configuration ${covering.ncmHash} at `
        + `${witnesses}, spanning ${base.windowFrom} to ${base.windowTo}, with `
        + `${covering.gaps.length} unobserved stretch(es) totalling `
        + `${Math.round(gapSeconds / 3600)} hours during which nothing looked at it, `
        + `measured against ${tolerance}. `
        + 'No differing configuration was ever observed inside the window.';
      if (thin) {
        statement += ' CONTINUITY IS NOT ESTABLISHED: those observations come from fewer than '
          + `${MIN_INDEPENDENT_SOURCES_FOR_CONTINUOUS} independent records.`;
      }
    } else if (thin) {
      // No gap AT THIS TOLERANCE, but only one record vouches for the period.
      // This is precisely the shape a 365-day tolerance manufactures out of a
      // single `config_snapshots` row, and it must not read as continuity.
      statement = `The device was observed in configuration ${covering.ncmHash} at `
        + `${witnesses}, spanning ${base.windowFrom} to ${base.windowTo}. No unobserved `
        + `stretch exceeds ${tolerance}, BUT CONTINUITY IS NOT ESTABLISHED: fewer than `
        + `${MIN_INDEPENDENT_SOURCES_FOR_CONTINUOUS} independent records vouch for this `
        + 'period, and two dates read off one record are one witness, not two.';
    } else {
      statement = `The device was in configuration ${covering.ncmHash} continuously from `
        + `${base.windowFrom} to ${base.windowTo}, confirmed by ${witnesses}, with no `
        + `unobserved stretch longer than ${tolerance}.`;
    }

    return {
      ...base,
      verdict,
      ncmHash: covering.ncmHash,
      independentSources: covering.independentSources,
      statement,
    };
  }

  if (periods.length === 0) {
    return {
      ...base,
      verdict: 'insufficient_evidence',
      ncmHash: null,
      independentSources: 0,
      statement: 'No configuration of this device was observed inside the window. '
        + 'Nothing is attested.',
    };
  }

  if (periods.length === 1) {
    const p = periods[0];
    return {
      ...base,
      verdict: 'insufficient_evidence',
      ncmHash: null,
      independentSources: p.independentSources,
      statement: `The only configuration observed inside the window (${p.ncmHash}) was seen `
        + `between ${ISO(p.from)} and ${ISO(p.to)}, which does not cover the requested window. `
        + 'The remainder of the window is unobserved and nothing is attested about it.',
    };
  }

  return {
    ...base,
    verdict: 'changed',
    ncmHash: null,
    independentSources: 0,
    statement: `The device carried ${periods.length} distinct configurations inside the window. `
      + 'The periods, the change jobs and the evidence chain below establish which, and when.',
  };
}

// ============================================================================
// Issuing
// ============================================================================

export interface IssuedAttestation {
  uuid: string;
  document: AttestationDocument;
}

/**
 * Freezes the document, records the issuance in the ledger, and returns it.
 *
 * ┌─ WHY THE UUID IS MINTED IN NODE AND NOT BY `gen_random_uuid()` ───────────┐
 * │ The document carries its own uuid, and `attestations` is frozen against   │
 * │ UPDATE by trigger — so there is no "insert, read the uuid back, patch the │
 * │ document" path, by design. The row must therefore be written ONCE, with   │
 * │ its final bytes, which means the identity has to exist before the INSERT. │
 * │ `randomUUID()` is a v4 from the same CSPRNG `gen_random_uuid()` uses; the │
 * │ column keeps its default for every other writer.                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * One transaction, and the ledger insert is inside it: an attestation that
 * exists without a ledger entry is a document nobody can date, and the ledger
 * entry is what makes a LATER re-issue over the same window comparable — same
 * `evidenceRoot` means the evidence did not move, a different one means it did.
 */
export async function issue(
  tenantId: number,
  opts: BuildOptions,
): Promise<IssuedAttestation> {
  // ── THE TOLERANCE IS CAPPED AT ISSUANCE, NOT AT PREVIEW ──────────────────
  //
  // `/preview` may be asked any tolerance: looking at what a 90-day tolerance
  // would say is a legitimate question and the answer is thrown away. An
  // ISSUED attestation is a permanent, ledger-recorded, forwardable document,
  // and letting its author pick the threshold that makes his own fleet look
  // continuous is letting him write the verdict. Past DEFAULT_MAX_GAP_DAYS the
  // request is refused rather than silently clamped: an operator who asked for
  // 365 and received a document saying 7 would not read the difference, and
  // the number is now inside `evidenceRoot`, so a quiet substitution would be
  // a document that does not answer the question that was asked.
  //
  // Enforced HERE and not only in the controller, so that every future caller
  // of `issue()` — a scheduler, an export, a script — inherits the cap.
  if (opts.maxGapDays !== undefined && opts.maxGapDays > DEFAULT_MAX_GAP_DAYS) {
    throw new AttestationError(
      400,
      `An issued attestation may not declare a tolerance above ${DEFAULT_MAX_GAP_DAYS} day(s); `
        + `${opts.maxGapDays} was requested. A wider tolerance turns unobserved time into the `
        + 'word "continuous". Use POST /api/attestation/preview to see what a wider one would '
        + 'say — a preview is not a document.',
    );
  }
  const built = await build(tenantId, opts);
  const subject = await loadSubject(tenantId, opts.deviceId);
  if (!subject) throw new AttestationError(404, 'Device not found');

  const uuid = randomUUID();
  const { documentDigest: _discard, ...body } = built;
  const withUuid = { ...body, attestationUuid: uuid };
  const finalDoc: AttestationDocument = {
    ...withUuid,
    documentDigest: sha256Hex(canonicalJson(withUuid as unknown as Record<string, unknown>)),
  };

  return db.transaction(async (trx) => {
    // The ledger FIRST: if the chain refuses the entry, no attestation is
    // issued. Same ordering rule as `audit.service.ts` — the record of an act
    // is written before the act, never after it.
    const ledger = await appendAudit(
      {
        tenantId,
        actorType: opts.issuedByUserId === null ? 'system' : 'user',
        actorId: opts.issuedByUserId,
        actorName: opts.issuedByUsername,
        action: 'attestation.issued',
        entityType: 'attestation',
        entityId: uuid,
        after: {
          deviceUuid: subject.uuid,
          deviceName: subject.name,
          windowFrom: ISO(opts.from),
          windowTo: ISO(opts.to),
          verdict: finalDoc.claim.verdict,
          ncmHash: finalDoc.claim.ncmHash,
          evidenceRoot: finalDoc.evidenceRoot,
          documentDigest: finalDoc.documentDigest,
          entryCount: finalDoc.entryCount,
        },
      },
      trx,
    );

    await trx('attestations').insert({
      uuid,
      tenant_id: tenantId,
      device_id: subject.id,
      device_uuid: subject.uuid,
      device_name: subject.name,
      window_from: opts.from,
      window_to: opts.to,
      verdict: finalDoc.claim.verdict,
      claimed_ncm_hash: finalDoc.claim.ncmHash,
      evidence_root: finalDoc.evidenceRoot,
      document_digest: finalDoc.documentDigest,
      entry_count: finalDoc.entryCount,
      document: JSON.stringify(finalDoc),
      issued_by_user_id: opts.issuedByUserId,
      issued_by_username: opts.issuedByUsername,
      audit_log_id: ledger.id,
      audit_log_seq: ledger.seq,
    });

    return { uuid, document: finalDoc };
  });
}

// ============================================================================
// Reading back
// ============================================================================

export interface StoredAttestation {
  id: string;
  uuid: string;
  deviceId: number | null;
  deviceUuid: string;
  deviceName: string;
  windowFrom: string;
  windowTo: string;
  verdict: AttestationVerdict;
  claimedNcmHash: string | null;
  evidenceRoot: string;
  documentDigest: string;
  entryCount: number;
  issuedByUsername: string;
  issuedAt: string;
  auditLogSeq: string | null;
}

interface StoredRow {
  id: string;
  uuid: string;
  device_id: number | null;
  device_uuid: string;
  device_name: string;
  window_from: Date;
  window_to: Date;
  verdict: AttestationVerdict;
  claimed_ncm_hash: string | null;
  evidence_root: string;
  document_digest: string;
  entry_count: number;
  issued_by_username: string;
  issued_at: Date;
  audit_log_seq: string | null;
}

const STORED_COLUMNS = [
  'id', 'uuid', 'device_id', 'device_uuid', 'device_name', 'window_from', 'window_to',
  'verdict', 'claimed_ncm_hash', 'evidence_root', 'document_digest', 'entry_count',
  'issued_by_username', 'issued_at', 'audit_log_seq',
];

function toStored(r: StoredRow): StoredAttestation {
  return {
    id: String(r.id),
    uuid: r.uuid,
    deviceId: r.device_id,
    deviceUuid: r.device_uuid,
    deviceName: r.device_name,
    windowFrom: new Date(r.window_from).toISOString(),
    windowTo: new Date(r.window_to).toISOString(),
    verdict: r.verdict,
    claimedNcmHash: r.claimed_ncm_hash,
    evidenceRoot: r.evidence_root,
    documentDigest: r.document_digest,
    entryCount: Number(r.entry_count),
    issuedByUsername: r.issued_by_username,
    issuedAt: new Date(r.issued_at).toISOString(),
    auditLogSeq: r.audit_log_seq === null ? null : String(r.audit_log_seq),
  };
}

export async function listAttestations(
  tenantId: number,
  filter: { deviceId?: number; limit?: number; offset?: number } = {},
): Promise<StoredAttestation[]> {
  const q = db('attestations').where({ tenant_id: tenantId });
  if (filter.deviceId !== undefined) void q.andWhere('device_id', filter.deviceId);
  const rows = await q
    .orderBy('issued_at', 'desc')
    .limit(Math.min(filter.limit ?? 100, 500))
    .offset(filter.offset ?? 0)
    .select<StoredRow[]>(STORED_COLUMNS);
  return rows.map(toStored);
}

export async function getAttestation(
  tenantId: number,
  uuid: string,
): Promise<{ meta: StoredAttestation; document: AttestationDocument } | null> {
  const row = await db('attestations')
    .where({ tenant_id: tenantId, uuid })
    .first<(StoredRow & { document: AttestationDocument }) | undefined>([
      ...STORED_COLUMNS,
      'document',
    ]);
  if (!row) return null;
  return { meta: toStored(row), document: row.document };
}

export interface VerificationReport {
  uuid: string;
  /** True when every hash in the stored document recomputes. */
  documentIntact: boolean;
  problems: ChainProblem[];
  /** The ledger row recorded at issuance, re-read and re-chained NOW. Its
   *  presence and its hash are what tie the frozen document to a position in a
   *  chain this process did not compute. */
  ledgerSeq: string | null;
  ledgerHashMatches: boolean | null;
}

/**
 * Re-verifies a STORED attestation.
 *
 * Deliberately re-runs the same pure verifier the client would run, over the
 * frozen bytes rather than over freshly-queried data: the question is "is the
 * document we issued still the document we issued", and answering it by
 * rebuilding from today's tables would answer a different one.
 */
export async function verifyStored(
  tenantId: number,
  uuid: string,
): Promise<VerificationReport | null> {
  const hit = await getAttestation(tenantId, uuid);
  if (!hit) return null;
  const problems = verifyAttestation(hit.document);

  let ledgerHashMatches: boolean | null = null;
  let ledgerSeq: string | null = null;
  const ledger = await db('audit_log')
    .where({ tenant_id: tenantId, entity_type: 'attestation', entity_id: uuid })
    .andWhere('action', 'attestation.issued')
    .orderBy('seq', 'asc')
    .first<{ seq: string; after: { documentDigest?: string } | null } | undefined>('seq', 'after');
  if (ledger) {
    ledgerSeq = String(ledger.seq);
    // The ledger recorded the digest at issuance. If the frozen document still
    // hashes to it, the two independent stores agree.
    ledgerHashMatches = ledger.after?.documentDigest === hit.document.documentDigest;
  }

  return {
    uuid,
    documentIntact: problems.length === 0,
    problems,
    ledgerSeq,
    ledgerHashMatches,
  };
}

/** Re-issue comparison: does the SAME window still produce the SAME evidence
 *  root? A different one is not an alarm — it means the underlying evidence
 *  moved, which is exactly the question a reader wants answered. */
export async function compareToLive(
  tenantId: number,
  uuid: string,
  issuedByUsername: string,
): Promise<{ storedRoot: string; liveRoot: string; identical: boolean } | null> {
  const hit = await getAttestation(tenantId, uuid);
  if (!hit || hit.meta.deviceId === null) return null;
  // The rebuild uses the tolerance the STORED document declares, not today's
  // default. `maxGapDays` is a hashed header member, so rebuilding at a
  // different one would change the root for a reason that has nothing to do
  // with the evidence — the comparison must vary in ONE thing, the data.
  const live = await build(tenantId, {
    deviceId: hit.meta.deviceId,
    from: new Date(hit.meta.windowFrom),
    to: new Date(hit.meta.windowTo),
    maxGapDays: hit.document.chainHeader?.maxGapDays,
    issuedByUsername,
    issuedByUserId: null,
  });
  return {
    storedRoot: hit.meta.evidenceRoot,
    liveRoot: live.evidenceRoot,
    identical: hit.meta.evidenceRoot === live.evidenceRoot,
  };
}
