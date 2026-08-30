#!/usr/bin/env node
/* eslint-disable */
// ============================================================================
// ObliWAN attestation — INDEPENDENT VERIFIER
// ============================================================================
//
//   node independent-verifier.cjs <attestation.json>
//
//   exit 0 = every hash recomputes.   exit 1 = something does not.
//
// ┌─ THIS FILE SHARES NO CODE WITH THE THING IT CHECKS ───────────────────────┐
// │ It imports `node:crypto` and NOTHING ELSE. No `@obliwan/shared`, no       │
// │ `sha256Hex`, no `canonicalJson`, no types, no build step. It is written   │
// │ from the `verification` section that every attestation carries inside     │
// │ itself, and it is the demonstration that that section is sufficient:      │
// │ eighty lines, one standard-library import, no ObliWAN.                    │
// │                                                                           │
// │ If this script and the server ever disagree, the DOCUMENT is what both    │
// │ are talking about — and the document is what a third party holds. That is │
// │ the whole point: an attestation that could only be verified by the        │
// │ software that produced it is a claim, not evidence.                       │
// │                                                                           │
// │ Hand it to a customer. Hand it to their insurer. It has no dependencies   │
// │ and it runs on any Node.                                                  │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ── WHAT IT PROVES, AND WHAT IT DOES NOT ───────────────────────────────────
//
// PROVES  the evidence set inside this document has not been edited, reordered,
//         extended or truncated since the document was written, and the ledger
//         rows it quotes are internally consistent with the hashes Postgres
//         computed for them.
//
// DOES NOT PROVE  that ObliWAN assembled an honest set in the first place.
//         Nothing short of a signature over the document by a key ObliWAN does
//         not hold — or a timestamp lodged with a third party — can establish
//         that, and the document says so in `verification.limits`.
//
// The one check anybody can run WITHOUT ObliWAN and WITHOUT this script:
// every `snapshot` row carries `rawSha256`, the SHA-256 of the raw device
// export. If you kept your own copy of that export, `sha256sum` it and compare.

const crypto = require('node:crypto');
const fs = require('node:fs');

function sha256(s) {
  return crypto.createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');
}

// verification.fieldEncoding:
//   enc(v) = "-1:" when v is null, otherwise UTF8-byte-length + ":" + v
function enc(v) {
  if (v === null || v === undefined) return '-1:';
  const s = String(v);
  return Buffer.byteLength(s, 'utf8') + ':' + s;
}

// verification.header: "JSON with object keys sorted ascending by UTF-16 code
// unit, no whitespace, and no undefined members."
function canonical(v) {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('non-finite number');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (typeof v === 'object') {
    const keys = Object.keys(v).sort();
    const parts = [];
    for (const k of keys) {
      if (v[k] === undefined) continue;
      parts.push(JSON.stringify(k) + ':' + canonical(v[k]));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error('unsupported type ' + typeof v);
}

const ROW = 'obliwan.evidence.row.v1';
const CHAIN = 'obliwan.evidence.chain.v1';
const AUDIT = 'obliwan.audit.v1';

function main() {
  const file = process.argv[2];
  if (!file) {
    console.error('usage: node independent-verifier.cjs <attestation.json>');
    process.exit(2);
  }
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  const problems = [];

  // ── 1. the document identifies itself ──────────────────────────────────
  if (doc.spec !== 'obliwan.attestation/v1') {
    problems.push('unknown spec: ' + doc.spec);
  }

  // ── 1b. THE HEADER MUST DECLARE THE PARAMETERS THE VERDICT WAS DRAWN UNDER
  //
  // verification.header: "The header also carries every PARAMETER the verdict
  // was drawn under — maxGapDays ... and judgeVersion ... A chainHeader lacking
  // either member is not a v2 document and must be rejected."
  //
  // This is not pedantry about a field. A document whose tolerance is not in
  // the hashed header is a document whose author chose, invisibly, how much
  // unobserved time the word "continuous" is allowed to cover — and two such
  // documents saying opposite things share one evidenceRoot. Refusing them is
  // the check.
  const hdr = doc.chainHeader || {};
  if (typeof hdr.maxGapDays !== 'number') {
    problems.push('chainHeader.maxGapDays is missing or not a number — the tolerance the '
      + 'verdict was drawn under is not covered by evidenceRoot, so `continuous` in this '
      + 'document means nothing checkable');
  }
  if (typeof hdr.judgeVersion !== 'string' || hdr.judgeVersion.length === 0) {
    problems.push('chainHeader.judgeVersion is missing — the rulebook that produced '
      + 'claim.verdict is not covered by evidenceRoot');
  }
  // Cross-check the copy printed in `claim` against the hashed original. Only
  // the header is inside the root; a mismatch means the human-readable half of
  // the document disagrees with the half the chain protects.
  if (doc.claim && typeof hdr.maxGapDays === 'number'
      && doc.claim.maxGapDays !== hdr.maxGapDays) {
    problems.push('claim.maxGapDays (' + doc.claim.maxGapDays + ') disagrees with the hashed '
      + 'chainHeader.maxGapDays (' + hdr.maxGapDays + ')');
  }

  // ── 2. every evidence row hashes to its rowHash ────────────────────────
  // verification.rowHash:
  //   SHA256(ROW + enc(kind) + for each [name,value]: enc(name)+enc(value))
  const seed = CHAIN + enc(canonical(doc.chainHeader));
  let prev = null;

  (doc.evidence || []).forEach((e, i) => {
    let pre = ROW + enc(e.kind);
    for (const [name, value] of e.fields) pre += enc(name) + enc(value);
    const rowHash = sha256(pre);
    if (rowHash !== e.rowHash) {
      problems.push(`evidence[${i}] (${e.kind}): rowHash mismatch — expected ${rowHash}, `
        + `document says ${e.rowHash}`);
    }
    // verification.chain
    const chainHash = i === 0
      ? sha256(seed + enc(rowHash))
      : sha256(CHAIN + enc(prev) + enc(rowHash));
    if (chainHash !== e.chainHash) {
      problems.push(`evidence[${i}] (${e.kind}): chainHash mismatch — expected ${chainHash}, `
        + `document says ${e.chainHash}`);
    }
    if (e.seq !== i) {
      problems.push(`evidence[${i}]: seq is ${e.seq}, expected ${i} — a row was inserted, `
        + 'removed or reordered');
    }
    prev = e.chainHash;
  });

  // ── 3. the root ────────────────────────────────────────────────────────
  const root = (doc.evidence || []).length === 0
    ? sha256(seed)
    : doc.evidence[doc.evidence.length - 1].chainHash;
  if (root !== doc.evidenceRoot) {
    problems.push(`evidenceRoot mismatch — expected ${root}, document says ${doc.evidenceRoot}`);
  }
  if ((doc.evidence || []).length !== doc.entryCount) {
    problems.push(`entryCount says ${doc.entryCount}, the document carries `
      + `${(doc.evidence || []).length} rows`);
  }

  // ── 4. the document digest ─────────────────────────────────────────────
  // verification.documentDigest: SHA256(canonicalJson(document minus documentDigest))
  const copy = Object.assign({}, doc);
  delete copy.documentDigest;
  const digest = sha256(canonical(copy));
  if (digest !== doc.documentDigest) {
    problems.push(`documentDigest mismatch — expected ${digest}, `
      + `document says ${doc.documentDigest}`);
  }

  // ── 5. the audit ledger, chained by Postgres ───────────────────────────
  // verification.auditLog
  const tenantId = doc.chainHeader && doc.chainHeader.tenantId;
  let prevHash = null;
  let prevSeq = null;
  (doc.auditChain || []).forEach((r, i) => {
    const pre = AUDIT
      + enc(r.prevHash)
      + enc(String(tenantId))
      + enc(r.seq)
      + enc(r.occurredAt)
      + enc(r.actorType)
      + enc(r.actorId)
      + enc(r.actorName)
      + enc(r.action)
      + enc(r.entityType)
      + enc(r.entityId)
      + enc(r.correlationId)
      + enc(r.beforeJson)
      + enc(r.afterJson);
    const h = sha256(pre);
    if (h !== r.hash) {
      problems.push(`auditChain[${i}] (seq ${r.seq}, ${r.action}): hash mismatch — `
        + `expected ${h}, ledger says ${r.hash}`);
    }
    if (prevHash !== null && r.prevHash !== prevHash) {
      problems.push(`auditChain[${i}] (seq ${r.seq}): prevHash does not point at the previous `
        + 'row — the chain is broken or a row was removed');
    }
    if (prevSeq !== null && BigInt(r.seq) !== prevSeq + 1n) {
      problems.push(`auditChain[${i}]: seq jumps from ${prevSeq} to ${r.seq} — the slice is `
        + 'not contiguous');
    }
    prevHash = r.hash;
    prevSeq = BigInt(r.seq);
  });

  // ── report ─────────────────────────────────────────────────────────────
  const h = doc.chainHeader || {};
  console.log(`subject   ${h.deviceName} (${h.deviceUuid})`);
  console.log(`window    ${h.windowFrom} .. ${h.windowTo}`);
  // Printed next to the verdict on purpose: "continuous" is only as strong as
  // the tolerance it was measured against, and a reader must not have to go
  // looking for that number.
  console.log(`tolerance ${h.maxGapDays} day(s) unobserved  [judge ${h.judgeVersion}]`);
  console.log(`verdict   ${doc.claim && doc.claim.verdict}`);
  console.log(`evidence  ${(doc.evidence || []).length} rows, ledger `
    + `${(doc.auditChain || []).length} rows`);
  console.log(`root      ${doc.evidenceRoot}`);

  if (problems.length === 0) {
    console.log('\nVERIFIED — every hash recomputes from the published method.');
    console.log('NOTE: this establishes that the evidence set has not been altered since');
    console.log('      issuance. It is NOT a signature: see verification.limits.');
    process.exit(0);
  }
  console.log(`\nFAILED — ${problems.length} problem(s):`);
  for (const p of problems) console.log('  - ' + p);
  process.exit(1);
}

main();
