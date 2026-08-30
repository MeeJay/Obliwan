// ============================================================================
// ObliWAN — the evidence contract, re-exported for the server
// ============================================================================
//
// ┌─ WHY THIS FILE EXISTS, AND WHEN IT SHOULD DISAPPEAR ──────────────────────┐
// │ `shared/src/evidence.ts` is the F1/F2 contract. `shared/src/index.ts` is  │
// │ the barrel, and it is the LEAD's file — the milestone that owns this      │
// │ feature does not add lines to it.                                         │
// │                                                                           │
// │ Until the barrel carries `export * from './evidence';`, the package's     │
// │ public entry point does not surface these types, so the server reaches    │
// │ the module by its subpath. That is a ONE-LINE-DEEP dependency, and it is  │
// │ confined to this file precisely so that removing it is one deletion:      │
// │                                                                           │
// │   1. add `export * from './evidence';` to `shared/src/index.ts`;          │
// │   2. point the four importers below at `@obliwan/shared`;                 │
// │   3. delete this file.                                                    │
// │                                                                           │
// │ The alternative — every consumer spelling the subpath out — is the shape  │
// │ where step 2 is a grep across the server instead of a rename.             │
// └───────────────────────────────────────────────────────────────────────────┘

import { ATTESTATION_METHOD, MIN_JUSTIFICATION_LENGTH } from '@obliwan/shared/dist/evidence';

export * from '@obliwan/shared/dist/evidence';

// ============================================================================
// What the server adds on top of the shared contract
// ============================================================================
//
// Additions, never a fork. Two of them exist because a wall built in `shared`
// turned out to have a hole; the third because one sentence the document
// publishes about itself did not describe what the code produces.

/**
 * Every character that occupies no ink: Unicode whitespace, the no-break
 * spaces, the zero-width family, the bidi marks, the word joiner, the byte
 * order mark — and U+2800 BRAILLE PATTERN BLANK, which is whitespace to no
 * library at all and renders as nothing.
 *
 * Written as escapes on purpose. A source file that CONTAINS the characters it
 * is trying to catch is a file nobody can review.
 *
 * ┌─ WHY THE DATABASE'S `btrim` WAS NOT ENOUGH ───────────────────────────────┐
 * │ `length(btrim(justification)) >= 24` reads as "24 characters that are not │
 * │ blank". `btrim` removes U+0020 and nothing else, so 24 NO-BREAK SPACES    │
 * │ satisfied it. The application mirror used `String.trim()`, which removes  │
 * │ more — but not U+200B ZERO WIDTH SPACE — so the two guards had a hole in  │
 * │ COMMON: `justificationProblem` returned null for thirty zero-width        │
 * │ spaces, the CHECK accepted the row, and the exceptions screen rendered an │
 * │ empty justification for a suppression that hides a critical for 300 days. │
 * │                                                                           │
 * │ Migration 023 replaces the CHECK with this same character set spelled out │
 * │ in SQL. This is the mirror, and a mirror must not be looser than the      │
 * │ glass.                                                                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const INVISIBLE_CLASS =
  '\\s\\u00a0\\u1680\\u180e\\u2000-\\u200f\\u202f\\u205f\\u2060\\u2800\\u3000\\ufeff';
const INVISIBLE = new RegExp(`[${INVISIBLE_CLASS}]`, 'gu');
const INVISIBLE_EDGES = new RegExp(`^[${INVISIBLE_CLASS}]+|[${INVISIBLE_CLASS}]+$`, 'gu');

/** The justification with every invisible character removed — what the CHECK
 *  measures, and what "is there anything here at all" must be asked of. */
export function justificationSubstance(raw: string): string {
  return raw.normalize('NFKC').replace(INVISIBLE, '');
}

/**
 * The form that is STORED: NFKC-normalised, stripped of leading and trailing
 * invisibles.
 *
 * Only the EDGES are touched. The interior is the operator's own prose, and a
 * record that rewrites the prose it is keeping is not a record. The point is
 * that the stored value is the one the CHECK measured — not that it is tidy.
 */
export function tidyJustification(raw: string): string {
  return raw.normalize('NFKC').replace(INVISIBLE_EDGES, '');
}

/**
 * The full application-side guard: `justificationProblem` from the shared
 * contract, plus the two things it cannot see.
 *
 * A mirror of migration 023's CHECK and not the enforcement — the database
 * refuses the row regardless. It exists so the API answers a sentence instead
 * of a 23514, and it has to stay at least as strict as the constraint.
 */
export function justificationProblemStrict(raw: unknown): string | null {
  if (typeof raw !== 'string') return 'A justification is required.';
  const substance = justificationSubstance(raw);
  if (substance.length < MIN_JUSTIFICATION_LENGTH) {
    return `A justification of at least ${MIN_JUSTIFICATION_LENGTH} characters is required — `
      + 'say WHY this drift is accepted, not that it is. Spaces, no-break spaces and '
      + 'zero-width characters are not characters.';
  }
  if (!/[\p{L}\p{N}]/u.test(substance)) {
    return 'A justification must contain words — punctuation alone says nothing that can be '
      + 'read a year from now.';
  }
  return null;
}

/**
 * True when two justifications say the same thing, once the invisible
 * characters and the case are out of the way.
 *
 * A renewal is a NEW decision. Re-posting the string `GET /api/exceptions/:id`
 * has just returned records a second identical assertion and proves only that
 * somebody clicked — which is precisely the evidence a review history exists to
 * carry.
 */
export function sameJustification(a: string, b: string): boolean {
  return justificationSubstance(a).toLowerCase() === justificationSubstance(b).toLowerCase();
}

/**
 * `ATTESTATION_METHOD` with the one sentence that was not true corrected.
 *
 * ┌─ A DOCUMENT MAY NOT CONTRADICT ITSELF IN FRONT OF A THIRD PARTY ──────────┐
 * │ The shared constant told the reader that `auditChain` carries "the ledger │
 * │ rows whose occurredAt falls in the window". `loadAuditChain` does not do  │
 * │ that, and MUST not: it takes the CONTIGUOUS slice [fromSeq..toSeq]        │
 * │ covering the window, because a time-filtered chain has a hole wherever a  │
 * │ row falls outside it, and a hole makes every later row unverifiable.      │
 * │                                                                           │
 * │ The slice is a SUPERSET of the window, never a subset: its bounds are the │
 * │ lowest and highest `seq` of exactly the rows the window contains. So the  │
 * │ defect was inclusion, not omission — but a stranger checking the          │
 * │ published assertion would report a discrepancy on a perfectly correct     │
 * │ document, and on an attestation a document that contradicts its own       │
 * │ method is worse than one that says less.                                  │
 * │                                                                           │
 * │ Corrected here and not in `shared/src/evidence.ts`, which is another      │
 * │ perimeter's file. The cast is what spreading a `const`-asserted object    │
 * │ costs: the shape is identical, one string differs.                        │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export const PUBLISHED_METHOD = {
  ...ATTESTATION_METHOD,
  auditLog:
    'The `auditChain` section carries a CONTIGUOUS slice of the tenant-scoped append-only '
    + 'ledger, by sequence number: the range [fromSeq..toSeq] whose bounds are the lowest and '
    + 'the highest `seq` among the rows whose occurredAt falls in the window. Those two bounds '
    + 'are the `seq` of the first and of the last row printed here. The slice is therefore a '
    + 'SUPERSET of the window — rows appended in between by other activity are present — and '
    + 'that is deliberate: a chain filtered by time has a hole wherever a row falls outside '
    + 'it, and a hole makes every later row unverifiable. `seq`, assigned at INSERT under a '
    + 'per-tenant lock, is the authoritative order; occurredAt is a wall-clock reading and two '
    + 'rows may carry timestamps in the opposite order to their seq. '
    + 'Verify the slice independently: seq must be contiguous, '
    + 'prevHash of row n must equal hash of row n-1, and hash must equal '
    + 'SHA256("obliwan.audit.v1" + enc(prevHash) + enc(tenantId) + enc(seq) + enc(occurredAt) + '
    + 'enc(actorType) + enc(actorId) + enc(actorName) + enc(action) + enc(entityType) + '
    + 'enc(entityId) + enc(correlationId) + enc(beforeJson) + enc(afterJson)), where the two '
    + 'json members are the jsonb columns rendered by Postgres `::text` and NULL columns are '
    + 'encoded as null. The hashes are computed by the DATABASE on insert, not by the '
    + 'application. occurredAt is rendered by Postgres as '
    + "to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"').",
} as unknown as typeof ATTESTATION_METHOD;
