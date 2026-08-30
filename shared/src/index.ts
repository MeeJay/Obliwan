// @obliwan/shared — the contract between server and client.
// Keep this file a pure re-export barrel: no logic, no side effects.

export * from './types';
export * from './capabilities';
export * from './tenants';
export * from './settings';
export * from './socketEvents';
export * from './device';
export * from './telemetry';

// The safe-write contract (M6) — decision D3. Kept next to `device` on
// purpose: it consumes `SafetyLevel` from there and never redefines it.
export * from './change';

// The NCM contract (M4) — decision D1. A sub-barrel: `src/ncm/index.ts` is the
// single place that knows that folder's layout.
export * from './ncm';

// Waved rollouts (M7 — K3). Carries the subtree interlock helpers of §8.5, so
// the composition refusal is expressed once and shared by server and client
// rather than reimplemented on each side.
export * from './rollout';

// Logs, drift attribution and the reachability verdict (M8 — K6 + K7).
export * from './logs';

// Fleet Query (M9 — K5): the DSL types and the field catalogue derived from the
// NCM Zod schemas, never hand-maintained.
export * from './query';

// TR-069 / CWMP (M10). Carries ACS_BRAND_COVERAGE as DATA rather than as prose:
// RouterOS and SonicOS have no CWMP client and never will (risk R2), and a
// screen that lets an operator believe otherwise is the failure mode here.
export * from './cwmp';

// Intent Compiler (M11 — K4): one site intent, four dialects, and a compilation
// that FAILS before any network access when the hardware cannot do it.
export * from './intent';

// Fleet takeover / Golden Site (M12 — K8).
export * from './baseline';

// Drift exceptions with a mandatory justification and a review date, plus the
// verifiable compliance attestation (F1 + F2, §10). "Expired" is DERIVED, never
// stored: an exception whose review date has passed makes its drift visible
// again, so this cannot become a way to hide drift forever.
export * from './evidence';

// Intervention mode and the change → telemetry aftermath (F3 + F4, §10).
export * from './intervention';

// Operator weather (F5, §10). A single site switching to LTE is a flap; twelve
// sites on the same ASN within ten minutes is an operator incident — the whole
// feature is the quorum, not the event.
export * from './weather';

// Hardware replacement detection (F6). `assertTargetBinding` already checked
// identity BEFORE each write; this watches it CHANGE over time — a serial that
// moves is a box that was swapped, and the product used to collect that on every
// connection and throw it away.
export * from './identity';

// Computed availability (F7). Its value is that K7 can tell "the site was down"
// from "WE lost the tunnel": a management-plane outage is never billed against a
// customer's SLA, and the report says how much time was excluded and why.
export * from './sla';

// End-of-life inventory (F8). "End of support unknown" is an honest answer;
// "supported" for a model absent from the catalogue is not.
export * from './lifecycle';
