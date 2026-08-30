/**
 * F3 — the one definition of "when did this window really end".
 *
 * It lives in a module of its own, and that is not tidiness: the lifecycle
 * service needs it to render a summary and the drift linker needs it to compute
 * an overlap. Exporting it from either one would make the two import each other
 * in a cycle, and a cycle whose resolution order decides whether a function is
 * defined at call time is the kind of bug that only shows up under a different
 * bundler.
 *
 * A SECOND copy of this rule would be worse than the cycle. "Ends at
 * `expires_at` unless it was closed / expired / cancelled earlier" is the
 * definition attribution is decided on; two implementations of it would
 * disagree the first time either is improved, and the disagreement would be
 * invisible — one screen saying a drift belongs to a window and another saying
 * it does not.
 */

export interface WindowBoundsRow {
  status: string;
  expires_at: Date;
  closed_at: Date | null;
  expired_at: Date | null;
  cancelled_at: Date | null;
}

/**
 * An OPEN window ends at its DECLARED deadline and not at "now": a drift run
 * evaluated in the middle of a live window must be attributable to it, and a
 * window that ended at the current instant would attribute nothing that has not
 * already been detected. A terminal window ends when it really ended.
 *
 * ┌─ AN EXPIRED WINDOW ENDS AT `expires_at`, NEVER AT `expired_at` ───────────┐
 * │ `expired_at` is not an end: it is the instant the expiry sweep NOTICED,   │
 * │ written by `expireOverdue`'s own `update({ expired_at: now })`, and the   │
 * │ CHECK `interventions_terminal_chk` only requires it to be at or after the │
 * │ deadline — there is no ceiling on how late it may be. Reading it here     │
 * │ made the attribution boundary depend on the punctuality of a sweep: a     │
 * │ TWO-HOUR window that nobody swept for three days was recorded as covering │
 * │ seventy-one hours of change, at 100 %.                                    │
 * │                                                                           │
 * │ It also contradicted three things the product says out loud — the         │
 * │ `rules.expiry` text served by `GET /interventions/params` ("from that     │
 * │ instant drift on the device is attributable again"), the comment on       │
 * │ `liveInterventionFor`, and the expiry message itself.                     │
 * │                                                                           │
 * │ `expired_at` keeps its job: it is the JOURNAL of the sweep, and           │
 * │ `unattendedSeconds` — how long the window sat open past its deadline —    │
 * │ is computed from exactly that difference.                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * A window CLOSED or CANCELLED after its deadline is clamped for the same
 * reason: a human clicking "close" an hour late did not extend the window he
 * declared, and `interventions_terminal_chk` does not forbid the late click.
 */
export function effectiveEnd(row: WindowBoundsRow): Date {
  const declared = row.expires_at;
  const earlier = (d: Date): Date => (d < declared ? d : declared);
  if (row.status === 'closed' && row.closed_at) return earlier(row.closed_at);
  if (row.status === 'expired') return declared;
  if (row.status === 'cancelled' && row.cancelled_at) return earlier(row.cancelled_at);
  return declared;
}
