// ============================================================================
// @obliwan/shared/ncm — THE contract
// ============================================================================
//
// Barrel. No logic, no side effects.
//
// This folder is the pivot format of the whole product: the drift engine (K2 /
// K6), Fleet Query (K5), the Intent Compiler (K4), fleet take-over (K8) and the
// planner (C7) all speak it. It holds SCHEMAS and PURE FUNCTIONS only — no
// database access, no I/O — because the client needs it to render a diff and
// because the testability of these functions is the point of milestone M4.
//
// Reading order for someone new:
//   primitives.ts  — the tagged-string selector atoms and the normalisers
//   resources.ts   — the ten modelled resource kinds
//   model.ts       — the document envelope, `coverage`, `unmodeled`
//   keys.ts        — semantic keys, `matchHash`, the `obliwan:` marker
//   canonical.ts   — canonical serialisation and `ncmHash`
//   intersect.ts   — may-intersect and order signatures
//   diff.ts        — the shape of a finding
//   plan.ts        — the shape of a plan
//   upgrade.ts     — reading an older document forward
//   normalization.ts — the rule vocabulary shared with migration 007

export * from './hash';
export * from './primitives';
export * from './resources';
export * from './model';
export * from './keys';
export * from './canonical';
export * from './intersect';
export * from './diff';
export * from './plan';
export * from './upgrade';
export * from './normalization';
