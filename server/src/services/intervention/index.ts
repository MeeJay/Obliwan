/**
 * F3 — the intervention mode. One import surface for the three modules:
 * `intervention.service.ts` owns the lifecycle (declare, close, expire),
 * `driftLink.ts` owns the one thing the lifecycle exists for — drift observed
 * during a declared window stops reading as an anomaly nobody owns — and
 * `window.ts` holds the single definition of when a window really ended, which
 * both of the others need and neither may own.
 *
 * The split is not cosmetic: the linker calls K6's `attributeRun()` and must
 * never be the place a window is opened or expired, and the lifecycle must
 * never be the place an attribution verdict is decided.
 */
export * from './intervention.service';
export * from './driftLink';
export * from './window';
