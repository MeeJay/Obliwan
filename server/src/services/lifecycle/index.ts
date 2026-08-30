/**
 * ObliWAN F8 — End-of-Life Inventory runtime.
 *
 * ┌─ THERE IS NO RUNTIME. THAT IS DELIBERATE, AND IT IS THE HONEST HEADER ────┐
 * │ This barrel has no timer, no leader election and no background sweep, and │
 * │ it must not grow one by accident.                                         │
 * │                                                                          │
 * │ F5 needs a sweep because it OPENS INCIDENTS: a state transition nobody    │
 * │ asked for has to be detected while it is happening. F8 computes a verdict │
 * │ from two facts that were already collected (`devices.model`,              │
 * │ `devices.os_version`, from M2) and a catalogue a human edits. Nothing     │
 * │ about it is time-critical: a model that went end-of-support this morning  │
 * │ is exactly as end-of-support when the screen is next opened, and the      │
 * │ answer is recomputed from the server's clock every single read (migration │
 * │ 027, decision 7 — nothing is derived into a column).                      │
 * │                                                                          │
 * │ A periodic job here would buy nothing and would cost the one thing this   │
 * │ feature cannot afford: a cached verdict that is wrong the morning after   │
 * │ it was computed, and wrong SILENTLY, because the row still looks fresh.   │
 * │                                                                          │
 * │ `server/src/index.ts` therefore starts NOTHING for F8. If that ever       │
 * │ changes — a nightly digest, a notification when a model crosses its       │
 * │ boundary — THIS BLOCK CHANGES IN THE SAME COMMIT. Three unmounted routers │
 * │ and one "not on a timer" header that was on a timer have already gone     │
 * │ unnoticed on this project.                                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ MOUNTING: NOT DONE, AND NOT SILENTLY ────────────────────────────────────┐
 * │ `server/src/routes/index.ts` is OUTSIDE this milestone's perimeter, so    │
 * │ `lifecycle.routes.ts` is written, complete and guarded — and NOT MOUNTED. │
 * │ Nothing in F8 is reachable over HTTP until somebody adds, next to the F5  │
 * │ block:                                                                    │
 * │                                                                          │
 * │   import lifecycleRoutes from './lifecycle.routes';                       │
 * │   tenantRouter.use('/lifecycle', lifecycleRoutes);                        │
 * │                                                                          │
 * │ Saying this out loud is the point. A header that claims a surface is live │
 * │ when it is not tells the next reviewer to skip the request-level test.    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * D3: F8 writes to no equipment and reads from no equipment. It is a report
 * over ObliWAN's own Postgres.
 */

export * from './catalog.service';
export * from './inventory.service';
