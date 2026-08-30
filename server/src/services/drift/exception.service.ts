// ============================================================================
// ObliWAN — F1: the justification of an accepted drift (ARCHITECTURE §10)
// ============================================================================
//
// ┌─ THE ONE SENTENCE THIS FILE EXISTS FOR ───────────────────────────────────┐
// │ A drift finding may be silenced only by a JUSTIFIED, DATED, AUTHORED      │
// │ exception, and when its review date passes THE FINDING COMES BACK.        │
// │                                                                           │
// │ Without the last clause the feature is worse than nothing: it would be a  │
// │ supported, audited, well-documented way to hide drift forever.            │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ── WHY THE SUPPRESSION IS MATERIALISED INTO `drift_findings.ignored` ───────
//
// The drift screen, the fleet roll-up and `drift_runs.max_severity` all read
// `drift_findings.ignored`. This module never asks them to learn about
// exceptions: it WRITES the boolean they already read, and `sweep()` is what
// keeps that boolean honest.
//
//   apply   an active exception marks its matching findings ignored, including
//           the ones a drift run created ten minutes ago — but only up to the
//           SEVERITY that was accepted, see below.
//   revive  an EXPIRED or REVOKED exception un-marks them, so the finding
//           reappears on the existing drift screen with no code there knowing
//           this feature exists. So does a finding that has become GRAVER than
//           the decision that forgave it.
//
// ── AN EXCEPTION FORGIVES A SEVERITY, NOT A NAME ───────────────────────────
//
// `severity_at_creation` records what the operator actually accepted, and both
// halves of the sweep compare against it. A sem_key is built from a rule's
// MATCH criteria and not from its action, so the same key survives the rule
// changing what it does: a NAT rule forgiven at `low` for a cosmetic comment
// and later rewritten to redirect traffic elsewhere emits a `critical` under
// that same key. Nothing but this comparison stands between that `critical`
// and three hundred days of silence.
//
// `expired` is derived (`review_due_at <= now()`), never stored — see decision
// 2 of migration 019. The sweep therefore cannot make an expiry happen late in
// the sense that matters: what it can be late about is the SCREEN, which is why
// it also runs at the head of every read in this module and not only on a
// timer. A finding hidden by an exception that expired four minutes ago is a
// four-minute-old screen; a finding hidden by a status column nobody flipped is
// a permanent lie.
//
// ── WHY THE KEY IS `sem_key` AND NOT A FINDING ID ──────────────────────────
//
// Every drift run creates NEW finding rows. An exception pinned to a finding id
// would be dead by the next run, and an operator would re-justify the same NAT
// rule every morning until he stopped reading the screen — which is the exact
// behaviour F1 was written against. `origin_finding_id` is provenance only.
//
// The match also accepts `legacy_sem_key` (§8.4): a `semKeyGeneration` bump
// must not resurrect every suppressed finding in the fleet on the morning the
// keying rules change.

import type { Knex } from 'knex';
// `findingPath` is the ONE function that knows the `<kind>/<semKey>[/<field>]`
// format. Importing it — rather than splitting the string on '/' — is what
// stops a sem_key that legitimately contains a slash (`route.v1:main:0.0.0.0/0:
// 10.255.0.1`) from being mistaken for a field-scoped path.
import { type DiffKind, findingPath } from '@obliwan/shared';
import {
  DriftException,
  DriftExceptionReview,
  ExceptionDecision,
  ExceptionStatus,
  exceptionIsVisibleAgain,
  exceptionState,
  sameJustification,
  tidyJustification,
} from '../attestation/contract';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { appendAudit } from '../attestation/auditLog.service';

// ============================================================================
// Rows
// ============================================================================

interface ExceptionRow {
  id: string;
  uuid: string;
  tenant_id: number;
  device_id: number;
  device_name?: string;
  sem_key: string;
  resource: string;
  path: string | null;
  justification: string;
  status: ExceptionStatus;
  review_due_at: Date;
  created_by_user_id: number | null;
  created_by_username: string;
  created_at: Date;
  revoked_at: Date | null;
  revoked_by_username: string | null;
  renewal_count: number;
  last_renewed_at: Date | null;
  origin_finding_id: string | null;
  severity_at_creation: string | null;
  suppressed_findings?: string | number;
}

const EXCEPTION_COLUMNS = [
  'e.id', 'e.uuid', 'e.tenant_id', 'e.device_id', 'e.sem_key', 'e.resource', 'e.path',
  'e.justification', 'e.status', 'e.review_due_at', 'e.created_by_user_id',
  'e.created_by_username', 'e.created_at', 'e.revoked_at', 'e.revoked_by_username',
  'e.renewal_count', 'e.last_renewed_at', 'e.origin_finding_id', 'e.severity_at_creation',
];

function toException(r: ExceptionRow, now = new Date()): DriftException {
  const state = exceptionState(
    { status: r.status, reviewDueAt: r.review_due_at },
    now,
  );
  return {
    id: String(r.id),
    uuid: r.uuid,
    tenantId: r.tenant_id,
    deviceId: r.device_id,
    deviceName: r.device_name,
    semKey: r.sem_key,
    resource: r.resource,
    path: r.path,
    justification: r.justification,
    status: r.status,
    state,
    visibleAgain: exceptionIsVisibleAgain(state),
    reviewDueAt: new Date(r.review_due_at).toISOString(),
    createdByUserId: r.created_by_user_id,
    createdByUsername: r.created_by_username,
    createdAt: new Date(r.created_at).toISOString(),
    revokedAt: r.revoked_at === null ? null : new Date(r.revoked_at).toISOString(),
    revokedByUsername: r.revoked_by_username,
    renewalCount: r.renewal_count,
    lastRenewedAt: r.last_renewed_at === null ? null : new Date(r.last_renewed_at).toISOString(),
    originFindingId: r.origin_finding_id === null ? null : String(r.origin_finding_id),
    severityAtCreation: r.severity_at_creation,
    suppressedFindings: Number(r.suppressed_findings ?? 0),
  };
}

interface ReviewRow {
  id: string;
  exception_id: string;
  decision: ExceptionDecision;
  justification: string;
  reviewed_by_user_id: number | null;
  reviewed_by_username: string;
  reviewed_at: Date;
  previous_review_due_at: Date | null;
  new_review_due_at: Date | null;
}

function toReview(r: ReviewRow): DriftExceptionReview {
  return {
    id: String(r.id),
    exceptionId: String(r.exception_id),
    decision: r.decision,
    justification: r.justification,
    reviewedByUserId: r.reviewed_by_user_id,
    reviewedByUsername: r.reviewed_by_username,
    reviewedAt: new Date(r.reviewed_at).toISOString(),
    previousReviewDueAt: r.previous_review_due_at === null
      ? null : new Date(r.previous_review_due_at).toISOString(),
    newReviewDueAt: r.new_review_due_at === null
      ? null : new Date(r.new_review_due_at).toISOString(),
  };
}

/** The actor, as every mutating call needs it. `username` is stored as a
 *  snapshot because "who accepted this" must survive the account. */
export interface Actor {
  userId: number | null;
  username: string;
}

export class ExceptionError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'ExceptionError';
  }
}

// ============================================================================
// The sweep — apply what is active, give back what expired
// ============================================================================

/**
 * Recomputes `ignored_count`, `max_severity` and `status` for the runs whose
 * findings just changed visibility.
 *
 * This duplicates ~12 lines of `drift.service.setFindingIgnored`, and it is a
 * deliberate duplication rather than an extraction: `drift.service.ts` is not
 * this milestone's file to rewrite. Both must stay in step — a run whose
 * `max_severity` is stale keeps a device green while a critical is visible on
 * the findings list, which is the failure mode the drift screen cannot detect
 * on its own. Expressed as ONE set-based statement so it stays correct for
 * 30 000 runs as easily as for one.
 */
async function recomputeRuns(trx: Knex.Transaction, runIds: readonly string[]): Promise<void> {
  if (runIds.length === 0) return;
  await trx.raw(
    `
    UPDATE drift_runs dr SET
      ignored_count = s.ignored_count,
      max_severity  = s.max_severity,
      status        = CASE WHEN dr.status IN ('error','unreachable') THEN dr.status
                           WHEN s.visible_count > 0 THEN 'drifted' ELSE 'in_sync' END
    FROM (
      SELECT run_id,
             count(*) FILTER (WHERE ignored)     AS ignored_count,
             count(*) FILTER (WHERE NOT ignored) AS visible_count,
             (ARRAY_REMOVE(ARRAY_AGG(CASE WHEN NOT ignored THEN severity END ORDER BY
                CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
                              WHEN 'low' THEN 1 ELSE 0 END DESC), NULL))[1] AS max_severity
        FROM drift_findings
       WHERE run_id = ANY(?)
       GROUP BY run_id
    ) s
    WHERE s.run_id = dr.id
    `,
    // `= ANY(?)` with an array binding rather than `whereIn`: a sweep that
    // touched five thousand runs would otherwise build a five-thousand-term IN
    // list, and knex's binding types do not accept a readonly array.
    [[...runIds]],
  );
}

export interface SweepOptions {
  /** Narrow the pass to one exception — what creating, renewing or revoking
   *  one uses so the write costs a targeted update rather than a fleet pass. */
  onlyExceptionId?: string;
  /**
   * Narrow the pass to one customer.
   *
   * `POST /api/exceptions/sweep` is mounted on the TENANT router and used to
   * call `sweep()` with no argument: a DRIFT_MANAGE user of tenant A issued an
   * on-demand write over the `drift_findings` and `drift_runs` of every tenant
   * in the installation. Nothing leaked — the pass only moves booleans to the
   * value the exceptions already imply — but a per-request unbounded write on
   * two of the largest tables in the schema is not a tenant-scoped operation.
   * The UNSCOPED form is the leader's timer, which is where a fleet-wide pass
   * belongs.
   */
  tenantId?: number;
}

export interface SweepResult {
  /** Findings newly hidden by an active exception. */
  applied: number;
  /** Findings handed back because their exception expired, was revoked, or was
   *  outgrown — a finding graver than `severity_at_creation` is a decision
   *  nobody made and comes back on the screen. */
  revived: number;
  /**
   * Findings that lost one of their two reasons and stayed hidden because the
   * other still holds — an expiring exception over a finding a normalization
   * rule silences independently, or a dead rule over a finding an active
   * exception covers. Reported separately from `revived` on purpose: an
   * operator watching these counters needs to know that N of his expiries did
   * NOT put anything back on the screen, or he will spend the morning looking
   * for drift that something else is eating.
   */
  detached: number;
  /** Exceptions currently past their review date. */
  expired: number;
}

/**
 * The whole visibility contract, in one transaction.
 *
 * Idempotent by construction: both statements are `UPDATE ... WHERE` over the
 * rows that are in the WRONG state, so a sweep on a settled database touches
 * nothing and a sweep interrupted halfway is repaired by the next one.
 *
 * Optionally narrowed to one exception (`onlyExceptionId`) so creating,
 * renewing or revoking one costs a targeted update rather than a fleet-wide
 * pass, and optionally to one customer (`tenantId`) so a tenant-scoped route
 * cannot ask for a write across the whole installation. The unnarrowed form is
 * the leader's timer.
 */
/**
 * The severity ladder, as one SQL expression over a column.
 *
 * Duplicated from `SEVERITY_RANK` in `shared/src/ncm/diff.ts` and from
 * `recomputeRuns` above for the same reason those two already duplicate each
 * other: a CASE inside an `UPDATE ... FROM` cannot import TypeScript, and the
 * alternative — a Postgres function — is a schema object this milestone would
 * have to create in a migration that other perimeters are also editing.
 *
 * NULL is the FLOOR, not the ceiling. `severity_at_creation` is nullable
 * (migration 019), and the only honest reading of "no severity was recorded
 * when this was accepted" is "nothing above `info` was accepted". The opposite
 * default — treat NULL as `critical` — would make every legacy row a blanket
 * pardon, which is the failure this guard exists to end.
 */
const SEVERITY_RANK_SQL = (col: string): string =>
  `CASE ${col} WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 `
  + `WHEN 'low' THEN 1 ELSE 0 END`;

/**
 * The predicate that says "this normalization rule is, RIGHT NOW, a live
 * layer-4 suppression for this device".
 *
 * It is the SQL twin of `drift.service.loadLayer4Rules` — same tenant-or-
 * library test, same `enabled`, same `layer = 4`, same four scopes — and the
 * two must not disagree, or the sweep would hand back findings the engine is
 * still suppressing (or keep hiding findings it is not).
 *
 * `dr` is the finding's run and `d` its device; both must be in scope at the
 * call site.
 */
const RULE_STILL_SUPPRESSES = `
  EXISTS (
    SELECT 1 FROM normalization_rules nr
     WHERE nr.id = df.ignored_by_rule
       AND nr.enabled = true
       AND nr.layer = 4
       AND nr.kind = 'suppress_finding'
       AND (nr.tenant_id = d.tenant_id OR nr.tenant_id IS NULL)
       AND (
            nr.scope IN ('global', 'brand')
         OR (nr.scope = 'device' AND nr.scope_id = dr.device_id)
         OR (nr.scope = 'group'  AND d.group_id IS NOT NULL AND nr.scope_id = d.group_id)
       )
  )
`;

export async function sweep(opts: SweepOptions = {}): Promise<SweepResult> {
  return db.transaction(async (trx) => {
    const only = opts.onlyExceptionId ?? null;
    const tenant = opts.tenantId ?? null;

    // ── REVIVE ────────────────────────────────────────────────────────────
    // An exception that is revoked, or whose review date has passed, stops
    // hiding anything AT ONCE. `now()` is the database's, not the process's:
    // two web replicas with drifting clocks must not disagree about whether a
    // customer's drift is visible.
    //
    // ┌─ THE THIRD REASON A FINDING COMES BACK: IT GOT WORSE ─────────────────┐
    // │ `severity_at_creation` records what was ACCEPTED. Until this clause   │
    // │ existed it was written, displayed, printed into the attestation — and │
    // │ never compared to anything, which is a rule stated in the contract    │
    // │ (`shared/src/evidence.ts`: "an exception written against a `low` that │
    // │ has since become `critical` is a decision nobody actually made") and  │
    // │ enforced nowhere.                                                     │
    // │                                                                       │
    // │ The APPLY clause below refuses to hide a finding graver than the      │
    // │ decision. This clause hands back the ones that are ALREADY hidden and │
    // │ have since been re-emitted at a higher severity — without it, a       │
    // │ finding suppressed while it was `low` would stay suppressed after the │
    // │ same sem_key came back `critical`, and the sweep would be enforcing   │
    // │ the rule only for rows it had not touched yet.                        │
    // └───────────────────────────────────────────────────────────────────────┘
    const revived = await trx.raw<{ rows: { id: string; run_id: string }[] }>(
      `
      UPDATE drift_findings df
         SET ignored = false, ignored_by_exception = NULL
        FROM drift_exceptions e
       WHERE df.ignored_by_exception = e.id
         AND df.ignored_by_rule IS NULL
         AND (
              e.status = 'revoked'
           OR e.review_due_at <= now()
           OR ${SEVERITY_RANK_SQL('df.severity')} > ${SEVERITY_RANK_SQL('e.severity_at_creation')}
         )
         AND (?::bigint IS NULL OR e.id = ?::bigint)
         AND (?::int IS NULL OR e.tenant_id = ?::int)
      RETURNING df.id, df.run_id
      `,
      [only, only, tenant, tenant],
    );

    // A finding that ALSO matches a normalization rule keeps its suppression
    // and simply loses the exception: the rule is an independent reason, and
    // dropping it here would make an expiring exception un-hide something the
    // customer's own rule silences.
    const detached = await trx.raw<{ rows: { id: string; run_id: string }[] }>(
      `
      UPDATE drift_findings df
         SET ignored_by_exception = NULL
        FROM drift_exceptions e
       WHERE df.ignored_by_exception = e.id
         AND df.ignored_by_rule IS NOT NULL
         AND (
              e.status = 'revoked'
           OR e.review_due_at <= now()
           OR ${SEVERITY_RANK_SQL('df.severity')} > ${SEVERITY_RANK_SQL('e.severity_at_creation')}
         )
         AND (?::bigint IS NULL OR e.id = ?::bigint)
         AND (?::int IS NULL OR e.tenant_id = ?::int)
      RETURNING df.id, df.run_id
      `,
      [only, only, tenant, tenant],
    );

    // ── REVIVE, THE OTHER HALF: THE RULE STOPPED APPLYING ─────────────────
    //
    // ┌─ A FINDING HIDDEN BY A RULE CAME BACK FROM NOWHERE, EVER ─────────────┐
    // │ Both clauses above key on `ignored_by_exception`. A finding hidden by │
    // │ `ignored_by_rule` — whether the engine wrote it during a run or a     │
    // │ caller wrote it through `PATCH /findings/:id/ignore` — had NO path    │
    // │ back to the screen at all. Disable the suppression rule, narrow its   │
    // │ scope, move the device out of the group it was scoped to: the         │
    // │ findings it silenced last month stay silenced forever, and the device │
    // │ stays green.                                                          │
    // │                                                                       │
    // │ That is the same sentence F1 exists to abolish, reached by the other  │
    // │ door: "a finding marked ignored disappears, and three months later    │
    // │ nobody knows why". `RULE_STILL_SUPPRESSES` is the engine's own rule    │
    // │ set expressed in SQL, so "the rule no longer applies" is decided by   │
    // │ the same predicate the run would decide it by.                        │
    // │                                                                       │
    // │ Nothing here re-evaluates whether the rule MATCHES this finding —     │
    // │ that needs the regex and lives in the engine. This clause answers the │
    // │ cheaper and more urgent question: does the named rule still exist, is │
    // │ it still enabled, is it still a layer-4 suppression, and is it still  │
    // │ this customer's and this device's?                                    │
    // └───────────────────────────────────────────────────────────────────────┘
    // Skipped when the pass is narrowed to ONE exception. The rule clauses have
    // nothing to do with that exception, and running them anyway would turn
    // every grant, renewal and revocation — which exist precisely so the write
    // costs a targeted update — into a scan of every finding in the
    // installation. The timer and the read paths run the unnarrowed form.
    const NOTHING = { rows: [] as { id: string; run_id: string }[] };
    const ruleRevived = only !== null ? NOTHING : await trx.raw<typeof NOTHING>(
      `
      UPDATE drift_findings df
         SET ignored = false, ignored_by_rule = NULL
        FROM drift_runs dr, devices d
       WHERE dr.id = df.run_id
         AND d.id = dr.device_id
         AND df.ignored = true
         AND df.ignored_by_rule IS NOT NULL
         AND df.ignored_by_exception IS NULL
         AND NOT ${RULE_STILL_SUPPRESSES}
         AND (?::int IS NULL OR d.tenant_id = ?::int)
      RETURNING df.id, df.run_id
      `,
      [tenant, tenant],
    );

    // Same dead rule, but an exception is holding the suppression up on its
    // own. The finding stays hidden and simply loses the stale reason —
    // symmetric with `detached` above, and counted with it.
    const ruleDetached = only !== null ? NOTHING : await trx.raw<typeof NOTHING>(
      `
      UPDATE drift_findings df
         SET ignored_by_rule = NULL
        FROM drift_runs dr, devices d
       WHERE dr.id = df.run_id
         AND d.id = dr.device_id
         AND df.ignored_by_rule IS NOT NULL
         AND (df.ignored = false OR df.ignored_by_exception IS NOT NULL)
         AND NOT ${RULE_STILL_SUPPRESSES}
         AND (?::int IS NULL OR d.tenant_id = ?::int)
      RETURNING df.id, df.run_id
      `,
      [tenant, tenant],
    );

    // ── APPLY ─────────────────────────────────────────────────────────────
    // Every finding of the exception's device whose semantic key it forgives,
    // that is not already suppressed for another reason. Scoped by
    // `drift_runs.device_id` — `drift_findings` has no tenant column, and
    // `drift_exceptions.device_id` is guaranteed to be the exception tenant's
    // by the `drift_exceptions_same_tenant` trigger, so the device is the
    // isolation boundary here.
    //
    // ┌─ AN EXCEPTION FORGIVES A SEVERITY, NOT A NAME ────────────────────────┐
    // │ `orderedRuleKey` is built from a rule's MATCH CRITERIA, not from its  │
    // │ action, so one sem_key survives the rule changing what it does. A NAT │
    // │ rule that drifted on a cosmetic comment (`low`, forgiven for 300      │
    // │ days) and then started redirecting traffic to a third-party host      │
    // │ (`critical`) is the SAME sem_key — and without the rank comparison    │
    // │ below the second finding inherits the first one's pardon, sets        │
    // │ `max_severity` back to NULL, and the equipment stays green for the    │
    // │ rest of the horizon.                                                  │
    // │                                                                       │
    // │ `<=`, so an exception granted on a `critical` still forgives the      │
    // │ `low` the same resource produces next week: a decision covers what it │
    // │ accepted and everything milder, never anything worse.                 │
    // └───────────────────────────────────────────────────────────────────────┘
    const applied = await trx.raw<{ rows: { id: string; run_id: string }[] }>(
      `
      UPDATE drift_findings df
         SET ignored = true, ignored_by_exception = e.id
        FROM drift_exceptions e, drift_runs dr
       WHERE dr.id = df.run_id
         AND dr.device_id = e.device_id
         AND e.status = 'active'
         AND e.review_due_at > now()
         AND (df.sem_key = e.sem_key OR df.legacy_sem_key = e.sem_key)
         AND (e.path IS NULL OR df.path = e.path)
         AND ${SEVERITY_RANK_SQL('df.severity')} <= ${SEVERITY_RANK_SQL('e.severity_at_creation')}
         AND df.ignored = false
         AND df.ignored_by_exception IS NULL
         AND (?::bigint IS NULL OR e.id = ?::bigint)
         AND (?::int IS NULL OR e.tenant_id = ?::int)
      RETURNING df.id, df.run_id
      `,
      [only, only, tenant, tenant],
    );

    const runIds = new Set<string>();
    for (const r of revived.rows) runIds.add(String(r.run_id));
    for (const r of ruleRevived.rows) runIds.add(String(r.run_id));
    for (const r of applied.rows) runIds.add(String(r.run_id));
    // The two `detached` statements did not change `ignored`, so they cannot
    // change a roll-up.
    await recomputeRuns(trx, [...runIds]);

    const expired = await trx('drift_exceptions')
      .where({ status: 'active' })
      .andWhere('review_due_at', '<=', trx.fn.now())
      .modify((q) => {
        if (only) void q.andWhere('id', only);
        if (tenant !== null) void q.andWhere('tenant_id', tenant);
      })
      .count<{ count: string }[]>('id as count');

    return {
      applied: applied.rows.length,
      revived: revived.rows.length + ruleRevived.rows.length,
      detached: detached.rows.length + ruleDetached.rows.length,
      expired: Number(expired[0]?.count ?? 0),
    };
  });
}

// ============================================================================
// Reads
// ============================================================================

function scoped(tenantId: number) {
  // `drift_exceptions` carries `tenant_id` AND the device does too; the trigger
  // keeps them equal on write. Filtering on the exception's own column is the
  // indexed path (`drift_exceptions_tenant_device_idx`).
  return db('drift_exceptions as e')
    .join('devices as d', 'd.id', 'e.device_id')
    .where('e.tenant_id', tenantId);
}

export interface ListExceptionsFilter {
  deviceId?: number;
  /** `active` | `expiring` | `expired` | `revoked`. Derived, so it is
   *  translated into a predicate here rather than compared to a column. */
  state?: 'active' | 'expiring' | 'expired' | 'revoked';
  /** Exceptions whose review date falls within N days — the review queue. */
  dueWithinDays?: number;
  semKey?: string;
  limit?: number;
  offset?: number;
}

export async function listExceptions(
  tenantId: number,
  filter: ListExceptionsFilter = {},
): Promise<DriftException[]> {
  // A read of this list is the moment an operator decides whether drift is
  // hidden, so it must not be able to show a stale answer. See the header.
  await sweepQuietly();

  const q = scoped(tenantId);
  if (filter.deviceId !== undefined) void q.andWhere('e.device_id', filter.deviceId);
  if (filter.semKey) void q.andWhere('e.sem_key', filter.semKey);
  if (filter.state === 'revoked') void q.andWhere('e.status', 'revoked');
  if (filter.state === 'expired') {
    void q.andWhere('e.status', 'active').andWhere('e.review_due_at', '<=', db.fn.now());
  }
  if (filter.state === 'active' || filter.state === 'expiring') {
    void q.andWhere('e.status', 'active').andWhere('e.review_due_at', '>', db.fn.now());
  }
  if (filter.dueWithinDays !== undefined) {
    void q
      .andWhere('e.status', 'active')
      .andWhereRaw("e.review_due_at <= now() + (? || ' days')::interval", [
        String(filter.dueWithinDays),
      ]);
  }

  const rows = await q
    .orderBy('e.review_due_at', 'asc')
    .limit(Math.min(filter.limit ?? 200, 1000))
    .offset(filter.offset ?? 0)
    .select<ExceptionRow[]>([
      ...EXCEPTION_COLUMNS,
      'd.name as device_name',
      db.raw(
        '(SELECT count(*) FROM drift_findings df WHERE df.ignored_by_exception = e.id) '
          + 'AS suppressed_findings',
      ),
    ]);

  const now = new Date();
  const out = rows.map((r) => toException(r, now));
  // `expiring` is a slice of `active` and cannot be expressed as a SQL
  // predicate without duplicating the threshold in two places. Filtered here,
  // against the same pure function the client uses.
  if (filter.state === 'expiring') return out.filter((e) => e.state === 'expiring');
  if (filter.state === 'active') return out.filter((e) => e.state === 'active');
  return out;
}

export async function getException(
  tenantId: number,
  id: string,
): Promise<DriftException | null> {
  await sweepQuietly();
  const row = await scoped(tenantId)
    .andWhere('e.id', id)
    .first<ExceptionRow | undefined>([
      ...EXCEPTION_COLUMNS,
      'd.name as device_name',
      db.raw(
        '(SELECT count(*) FROM drift_findings df WHERE df.ignored_by_exception = e.id) '
          + 'AS suppressed_findings',
      ),
    ]);
  if (!row) return null;
  const reviews = await db('drift_exception_reviews')
    .where({ exception_id: id, tenant_id: tenantId })
    .orderBy('reviewed_at', 'asc')
    .select<ReviewRow[]>('*');
  return { ...toException(row), reviews: reviews.map(toReview) };
}

// ============================================================================
// Writes
// ============================================================================

export interface CreateExceptionInput {
  /** Either a finding to derive the target from… */
  findingId?: string;
  /** …or the target spelled out. One of the two is required. */
  deviceId?: number;
  semKey?: string;
  resource?: string;
  path?: string | null;
  justification: string;
  reviewDueAt: string;
}

/**
 * Grants an exception, then applies it.
 *
 * The insert, the review row, the ledger entry and the suppression all live in
 * ONE transaction. A granted exception whose ledger entry failed would be a
 * suppression nobody can attribute — the exact object F1 exists to abolish.
 */
export async function createException(
  tenantId: number,
  actor: Actor,
  input: CreateExceptionInput,
): Promise<DriftException> {
  let deviceId = input.deviceId ?? null;
  let semKey = input.semKey ?? null;
  let resource = input.resource ?? null;
  let path: string | null = input.path ?? null;
  let severity: string | null = null;
  let originFindingId: string | null = null;

  if (input.findingId) {
    // Scoped finding -> run -> device -> tenant. A finding id from another
    // customer is a 404 and never a 403: "that finding exists but is not yours"
    // is itself a disclosure about another customer's inventory.
    const f = await db('drift_findings as df')
      .join('drift_runs as dr', 'dr.id', 'df.run_id')
      .join('devices as d', 'd.id', 'dr.device_id')
      .where('d.tenant_id', tenantId)
      .andWhere('df.id', input.findingId)
      .first<{
        id: string; device_id: number; sem_key: string; resource: string;
        kind: DiffKind; path: string; severity: string;
      } | undefined>(
        'df.id', 'dr.device_id', 'df.sem_key', 'df.resource', 'df.kind', 'df.path',
        'df.severity',
      );
    if (!f) throw new ExceptionError(404, 'Finding not found');
    originFindingId = String(f.id);
    deviceId = f.device_id;
    semKey = f.sem_key;
    resource = f.resource;
    severity = f.severity;
    // ── IS THIS FINDING ABOUT ONE FIELD, OR ABOUT THE WHOLE RESOURCE? ──────
    //
    // Ask `findingPath`, which is the ONE function that knows the format, and
    // never `split('/')`.
    //
    // The old test was `f.path.split('/').length > 2`, which does not mean
    // "the path names a field": it means "the string contains two slashes".
    // `routeKey` produces `route.v1:main:0.0.0.0/0:10.255.0.1` (keys.ts), so
    // EVERY route — and every interface, DHCP scope, `other:<rawName>` service
    // or local user whose name contains a slash — made a three-segment path and
    // got pinned. Pinned to `changed/route.v1:…`, at that: the APPLY clause
    // requires `df.path = e.path`, so the morning the same route reappeared as
    // `missing` or `moved` the exception stopped matching and the operator
    // re-justified the same route again. That is precisely the every-morning
    // re-justification F1 exists to abolish.
    //
    // A finding is field-scoped exactly when its path is NOT the canonical
    // whole-resource path for its own kind and key. Today the engine never
    // emits a field-scoped one (`semanticDiff.ts` calls `findingPath` with two
    // arguments at all three sites; the per-field detail lives in
    // `field_diffs`), so in practice this resolves to "the whole resource" —
    // which is the truth, and no longer a promise the data cannot keep. If the
    // engine ever starts emitting `<kind>/<semKey>/<field>`, this comparison
    // recognises it with no further change here.
    const fieldScoped = f.path !== findingPath(f.kind, f.sem_key);
    path = input.path !== undefined ? input.path : (fieldScoped ? f.path : null);
  }

  if (deviceId === null || semKey === null || resource === null) {
    throw new ExceptionError(400, 'Either findingId, or deviceId + semKey + resource, is required');
  }

  const device = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{ id: number; name: string } | undefined>('id', 'name');
  if (!device) throw new ExceptionError(404, 'Device not found');

  // ── THE SEVERITY BEING ACCEPTED, ON THE `deviceId + semKey` PATH ─────────
  //
  // `severity_at_creation` is now LOAD-BEARING: `sweep()` refuses to hide a
  // finding graver than it. On the `findingId` path it comes off the finding.
  // On this one there is no finding in the request, so it is read from the
  // gravest thing the same key is CURRENTLY producing on that device — which
  // is the same question the operator is answering, asked of the data instead
  // of the form.
  //
  // Nothing matching means NULL, which forgives nothing above `info`. That is
  // the deliberate outcome, not a gap: an exception written before any drift
  // exists is a pardon signed for a decision nobody has seen, and it must not
  // be the thing that hides tomorrow's `critical`. The operator grants it
  // again against the real finding, in one click, with the severity in front
  // of him.
  if (severity === null) {
    const worst = await db('drift_findings as df')
      .join('drift_runs as dr', 'dr.id', 'df.run_id')
      .join('devices as d', 'd.id', 'dr.device_id')
      .where('d.tenant_id', tenantId)
      .andWhere('dr.device_id', deviceId)
      .andWhere((qb) => {
        void qb.where('df.sem_key', semKey).orWhere('df.legacy_sem_key', semKey);
      })
      .modify((qb) => { if (path !== null) void qb.andWhere('df.path', path); })
      .orderByRaw(
        "CASE df.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
          + "WHEN 'low' THEN 1 ELSE 0 END DESC",
      )
      .first<{ severity: string } | undefined>('df.severity');
    severity = worst?.severity ?? null;
  }

  const created = await db.transaction(async (trx) => {
    let row: ExceptionRow;
    try {
      const [inserted] = await trx('drift_exceptions')
        .insert({
          tenant_id: tenantId,
          device_id: deviceId,
          sem_key: semKey,
          resource,
          path,
          // Trimmed here so the stored value is the one the CHECK measured.
          // Storing the untrimmed form would let `length(btrim(...)) >= 24`
          // pass on a value the UI then renders with 300 leading spaces.
          justification: tidyJustification(input.justification),
          status: 'active',
          review_due_at: new Date(input.reviewDueAt),
          created_by_user_id: actor.userId,
          created_by_username: actor.username,
          origin_finding_id: originFindingId,
          severity_at_creation: severity,
        })
        .returning<ExceptionRow[]>('*');
      row = inserted;
    } catch (err) {
      throw translate(err);
    }

    await trx('drift_exception_reviews').insert({
      exception_id: row.id,
      tenant_id: tenantId,
      decision: 'created' satisfies ExceptionDecision,
      justification: tidyJustification(input.justification),
      reviewed_by_user_id: actor.userId,
      reviewed_by_username: actor.username,
      previous_review_due_at: null,
      new_review_due_at: row.review_due_at,
    });

    // In the transaction on purpose: if the ledger refuses the entry, the
    // exception does not exist. Same rule `audit.service.ts` states for
    // `command_audit` — an untraceable act is not an acceptable degradation.
    await appendAudit(
      {
        tenantId,
        actorType: actor.userId === null ? 'system' : 'user',
        actorId: actor.userId,
        actorName: actor.username,
        action: 'drift_exception.created',
        entityType: 'drift_exception',
        entityId: row.uuid,
        after: {
          deviceId,
          deviceName: device.name,
          semKey,
          resource,
          path,
          justification: tidyJustification(input.justification),
          reviewDueAt: new Date(row.review_due_at).toISOString(),
          severityAtCreation: severity,
          originFindingId,
        },
      },
      trx,
    );

    return row;
  });

  await sweep({ onlyExceptionId: String(created.id), tenantId });
  const full = await getException(tenantId, String(created.id));
  // The row was just written inside a committed transaction and scoped reads
  // use the same tenant, so this cannot legitimately be null.
  if (!full) throw new ExceptionError(500, 'Exception vanished after creation');
  return full;
}

export interface RenewExceptionInput {
  justification: string;
  reviewDueAt: string;
}

/**
 * Reconduction. A renewal is a NEW decision and carries its OWN justification —
 * "still needed a year later" is a different assertion from the original one,
 * and collapsing them into one mutable column erases the only evidence that
 * anybody ever looked again.
 *
 * An EXPIRED exception can be renewed: that is the normal path through the
 * review queue. A REVOKED one cannot — withdrawing was a decision, and undoing
 * it is granting a new exception.
 */
export async function renewException(
  tenantId: number,
  id: string,
  actor: Actor,
  input: RenewExceptionInput,
): Promise<DriftException> {
  await db.transaction(async (trx) => {
    // FOR UPDATE: two operators renewing the same exception at once would
    // otherwise both read `renewal_count = 3`, both write 4, and the history
    // would show one renewal for two decisions.
    const row = await trx('drift_exceptions')
      .where({ id, tenant_id: tenantId })
      .forUpdate()
      .first<ExceptionRow | undefined>('*');
    if (!row) throw new ExceptionError(404, 'Exception not found');
    if (row.status === 'revoked') {
      throw new ExceptionError(
        409,
        'This exception was revoked. Withdrawing was a decision — grant a new exception '
          + 'rather than undoing it.',
      );
    }
    const next = new Date(input.reviewDueAt);
    if (next.getTime() <= new Date(row.review_due_at).getTime()) {
      throw new ExceptionError(400, 'A renewal must push the review date forward.');
    }

    // ┌─ THE SAME SENTENCE TWICE IS ONE DECISION, NOT TWO ────────────────────┐
    // │ `GET /api/exceptions/:id` returns the justification in clear. Posting │
    // │ it back to `/renew` byte for byte used to be accepted, and the review │
    // │ history then held N identical entries: a record that somebody         │
    // │ clicked, dressed as a record that somebody looked. The whole reason   │
    // │ the review row carries its OWN justification column instead of        │
    // │ pointing at the exception's is that "still needed a year later" is a  │
    // │ DIFFERENT assertion from the original one.                            │
    // │                                                                       │
    // │ Compared on `justificationSubstance` and case-folded, so padding the  │
    // │ old text with a no-break space or re-capitalising it does not buy a   │
    // │ renewal either.                                                       │
    // └───────────────────────────────────────────────────────────────────────┘
    if (sameJustification(input.justification, row.justification)) {
      throw new ExceptionError(
        409,
        'A renewal is a new decision and needs its own justification. This one repeats the '
          + 'previous text word for word — say what has been re-examined and why the drift is '
          + 'still acceptable, or revoke the exception.',
      );
    }

    try {
      await trx('drift_exceptions')
        .where({ id })
        .update({
          review_due_at: next,
          justification: tidyJustification(input.justification),
          renewal_count: row.renewal_count + 1,
          last_renewed_at: trx.fn.now(),
          updated_at: trx.fn.now(),
        });
    } catch (err) {
      throw translate(err);
    }

    await trx('drift_exception_reviews').insert({
      exception_id: id,
      tenant_id: tenantId,
      decision: 'renewed' satisfies ExceptionDecision,
      justification: tidyJustification(input.justification),
      reviewed_by_user_id: actor.userId,
      reviewed_by_username: actor.username,
      previous_review_due_at: row.review_due_at,
      new_review_due_at: next,
    });

    await appendAudit(
      {
        tenantId,
        actorType: actor.userId === null ? 'system' : 'user',
        actorId: actor.userId,
        actorName: actor.username,
        action: 'drift_exception.renewed',
        entityType: 'drift_exception',
        entityId: row.uuid,
        before: {
          reviewDueAt: new Date(row.review_due_at).toISOString(),
          justification: row.justification,
          renewalCount: row.renewal_count,
        },
        after: {
          reviewDueAt: next.toISOString(),
          justification: tidyJustification(input.justification),
          renewalCount: row.renewal_count + 1,
        },
      },
      trx,
    );
  });

  // Re-applies the suppression to findings that came back while it was expired.
  await sweep({ onlyExceptionId: id, tenantId });
  const full = await getException(tenantId, id);
  if (!full) throw new ExceptionError(404, 'Exception not found');
  return full;
}

/** Withdrawal. The findings come back immediately. */
export async function revokeException(
  tenantId: number,
  id: string,
  actor: Actor,
  reason: string,
): Promise<DriftException> {
  await db.transaction(async (trx) => {
    const row = await trx('drift_exceptions')
      .where({ id, tenant_id: tenantId })
      .forUpdate()
      .first<ExceptionRow | undefined>('*');
    if (!row) throw new ExceptionError(404, 'Exception not found');
    if (row.status === 'revoked') throw new ExceptionError(409, 'Already revoked');

    await trx('drift_exceptions')
      .where({ id })
      .update({
        status: 'revoked',
        revoked_at: trx.fn.now(),
        revoked_by_user_id: actor.userId,
        revoked_by_username: actor.username,
        updated_at: trx.fn.now(),
      });

    try {
      await trx('drift_exception_reviews').insert({
        exception_id: id,
        tenant_id: tenantId,
        decision: 'revoked' satisfies ExceptionDecision,
        justification: tidyJustification(reason),
        reviewed_by_user_id: actor.userId,
        reviewed_by_username: actor.username,
        previous_review_due_at: row.review_due_at,
        new_review_due_at: null,
      });
    } catch (err) {
      throw translate(err);
    }

    await appendAudit(
      {
        tenantId,
        actorType: actor.userId === null ? 'system' : 'user',
        actorId: actor.userId,
        actorName: actor.username,
        action: 'drift_exception.revoked',
        entityType: 'drift_exception',
        entityId: row.uuid,
        before: { status: row.status, justification: row.justification },
        after: { status: 'revoked', reason: tidyJustification(reason) },
      },
      trx,
    );
  });

  await sweep({ onlyExceptionId: id, tenantId });
  const full = await getException(tenantId, id);
  if (!full) throw new ExceptionError(404, 'Exception not found');
  return full;
}

/**
 * The two CHECK constraints of migration 019, turned into sentences.
 *
 * The database is the enforcement — these codes are what a caller that bypassed
 * the Zod schema produces, and answering 400 with a reason beats letting a
 * 23514 surface as a 500 with a constraint name in it.
 */
function translate(err: unknown): unknown {
  const e = err as { code?: string; constraint?: string };
  if (e?.code === '23514' && e.constraint?.includes('justified')) {
    return new ExceptionError(
      400,
      'A justification of at least 24 characters is required — say WHY this drift is '
        + 'accepted, not that it is.',
    );
  }
  if (e?.code === '23514' && e.constraint?.includes('horizon')) {
    return new ExceptionError(
      400,
      'The review date must be in the future and within one year — an exception nobody '
        + 'ever revisits is a permanent suppression.',
    );
  }
  if (e?.code === '23505' && e.constraint?.startsWith('drift_exceptions_active')) {
    return new ExceptionError(
      409,
      'An active exception already covers this resource on this device. Renew or revoke it.',
    );
  }
  return err;
}

// ============================================================================
// The sweeper duty
// ============================================================================

/** Debounce for the read-path sweep. A list read is not a maintenance window;
 *  once every few seconds is enough to keep a screen honest and it stops a
 *  refresh loop from turning into a write loop. */
const READ_SWEEP_MIN_INTERVAL_MS = 5_000;
let lastReadSweep = 0;
let readSweepInFlight: Promise<unknown> | null = null;

/**
 * The sweep as a read path calls it: debounced, deduplicated, and never fatal.
 *
 * A sweep failure must not turn a list into a 500 — the list is still readable
 * and the timer will retry. It IS logged at error level, because a sweep that
 * has been failing for a week means expired exceptions are still hiding drift.
 */
async function sweepQuietly(): Promise<void> {
  const now = Date.now();
  if (readSweepInFlight) {
    await readSweepInFlight.catch(() => undefined);
    return;
  }
  if (now - lastReadSweep < READ_SWEEP_MIN_INTERVAL_MS) return;
  lastReadSweep = now;
  readSweepInFlight = sweep()
    .then((r) => {
      if (r.applied || r.revived) {
        logger.info({ ...r, trigger: 'read' }, 'Drift exception sweep');
      }
    })
    .catch((err) => logger.error({ err }, 'Drift exception sweep failed on a read path'))
    .finally(() => {
      readSweepInFlight = null;
    });
  await readSweepInFlight;
}

/** How often the background duty re-checks the whole installation. */
export const SWEEP_INTERVAL_MS = 60_000;

let sweepTimer: NodeJS.Timeout | null = null;

/**
 * Arms the periodic sweep. Called from `startEvidenceRuntime()`, which is wired
 * to leadership — see `services/attestation/runtime.ts`.
 *
 * The timer is what makes an expiry reach the DRIFT screen (which knows nothing
 * about exceptions) without anybody opening the exceptions page first.
 */
export function startExceptionSweeper(): void {
  if (sweepTimer) return;
  let running = false;
  sweepTimer = setInterval(() => {
    if (running) return;
    running = true;
    void sweep()
      .then((r) => {
        if (r.applied || r.revived) {
          logger.info({ ...r, trigger: 'timer' }, 'Drift exception sweep');
        }
      })
      .catch((err) => logger.error({ err }, 'Drift exception sweep failed'))
      .finally(() => { running = false; });
  }, SWEEP_INTERVAL_MS);
  sweepTimer.unref();
}

export function stopExceptionSweeper(): void {
  if (sweepTimer) clearInterval(sweepTimer);
  sweepTimer = null;
}

// ============================================================================
// For the attestation (F2)
// ============================================================================

/** A stretch of time during which an exception was actually hiding something. */
interface Cover {
  from: Date;
  to: Date;
}

/**
 * The stretches during which an exception was in force, rebuilt from
 * `drift_exception_reviews`.
 *
 * ┌─ AN EXCEPTION IS NOT ONE INTERVAL ────────────────────────────────────────┐
 * │ Created in January until February, forgotten, renewed in June until       │
 * │ December: it hid nothing from February to June. `review_due_at` holds     │
 * │ only the LAST of those dates, so a predicate written against it reports   │
 * │ the exception as in force over a March window in which it was expired and │
 * │ the drift was on the screen for anyone to see.                            │
 * │                                                                           │
 * │ `drift_exception_reviews` is append-only and carries                      │
 * │ `previous_review_due_at` / `new_review_due_at` per decision, which is     │
 * │ exactly the history needed to rebuild the real intervals.                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * A row with no review history at all (written before 019, or by hand) falls
 * back to the single interval its own columns describe — the old behaviour,
 * and the only honest answer when the history does not exist.
 */
function coverIntervals(r: ExceptionRow, reviews: readonly ReviewRow[]): Cover[] {
  const created = new Date(r.created_at);
  const ordered = [...reviews].sort(
    (a, b) => new Date(a.reviewed_at).getTime() - new Date(b.reviewed_at).getTime()
      || Number(a.id) - Number(b.id),
  );

  const first = ordered.find((v) => v.decision === 'created');
  let start = created;
  let end = first?.new_review_due_at
    ? new Date(first.new_review_due_at)
    : new Date(r.review_due_at);

  const out: Cover[] = [];
  for (const rev of ordered) {
    if (rev.decision === 'created') continue;
    const at = new Date(rev.reviewed_at);
    if (rev.decision === 'revoked') {
      // Withdrawal ends the current stretch on the spot, and there is no next
      // one: `renewException` refuses to revive a revoked exception.
      if (at.getTime() < end.getTime()) end = at;
      out.push({ from: start, to: end });
      return out;
    }
    if (rev.decision === 'renewed' && rev.new_review_due_at) {
      const extended = new Date(rev.new_review_due_at);
      if (at.getTime() <= end.getTime()) {
        // Renewed before it lapsed: one continuous stretch, pushed further out.
        if (extended.getTime() > end.getTime()) end = extended;
      } else {
        // Renewed AFTER it lapsed. The gap in between is a period during which
        // the drift was visible, and it must not be papered over.
        out.push({ from: start, to: end });
        start = at;
        end = extended;
      }
    }
  }
  // A revocation with no review row behind it (only reachable by hand) still
  // ends the last stretch.
  if (r.revoked_at !== null) {
    const revoked = new Date(r.revoked_at);
    if (revoked.getTime() < end.getTime()) end = revoked;
  }
  out.push({ from: start, to: end });
  return out;
}

/** The exception as it stood at one instant, rebuilt from its history. */
function asOf(r: ExceptionRow, at: Date, reviews: readonly ReviewRow[]): ExceptionRow {
  const past = reviews
    .filter((v) => new Date(v.reviewed_at).getTime() <= at.getTime())
    .sort(
      (a, b) => new Date(a.reviewed_at).getTime() - new Date(b.reviewed_at).getTime()
        || Number(a.id) - Number(b.id),
    );
  if (past.length === 0) return r;

  const renewals = past.filter((v) => v.decision === 'renewed');
  const revoked = past.find((v) => v.decision === 'revoked');
  const reversed = [...past].reverse();
  const lastDated = reversed.find((v) => v.new_review_due_at !== null);
  // The last GRANT or RENEWAL, never a revocation: a revocation row carries the
  // reason for withdrawing, which is a different sentence from the reason the
  // drift was accepted, and printing one where the other belongs would be a
  // misquote in a document addressed to a third party.
  const lastGrant = reversed.find((v) => v.decision === 'created' || v.decision === 'renewed');

  return {
    ...r,
    status: revoked ? 'revoked' : 'active',
    review_due_at: lastDated?.new_review_due_at
      ? new Date(lastDated.new_review_due_at)
      : r.review_due_at,
    // The wording that was in force then, not the one a later renewal replaced
    // it with.
    justification: lastGrant?.justification ?? r.justification,
    revoked_at: revoked ? new Date(revoked.reviewed_at) : null,
    revoked_by_username: revoked ? revoked.reviewed_by_username : null,
    renewal_count: renewals.length,
    last_renewed_at: renewals.length === 0
      ? null
      : new Date(renewals[renewals.length - 1].reviewed_at),
  };
}

/**
 * Exceptions that were in force over a window, for one device, DESCRIBED AS
 * THEY STOOD IN THAT WINDOW.
 *
 * ┌─ THE READER IS AN INSURER, NOT AN OPERATOR ───────────────────────────────┐
 * │ `acceptedDrift[].state` used to be `toException(r)` with no `now` — the   │
 * │ state at the moment the document was BUILT. An exception revoked          │
 * │ yesterday therefore printed `revoked` inside an attestation covering a    │
 * │ window during which it was actively hiding a critical, and one created in │
 * │ January, lapsed in February and renewed in June printed `active` on a     │
 * │ March-to-April window it did not cover at all.                            │
 * │                                                                           │
 * │ Both halves are fixed here: membership is decided by real coverage        │
 * │ intervals rebuilt from the review history, and every field is reported as │
 * │ of the CLOSE OF THE WINDOW — status, review date, renewal count, and the  │
 * │ justification that was in force then rather than the one a later renewal  │
 * │ replaced it with. The document then says what was true of the period it   │
 * │ attests, which is the only thing it is allowed to say.                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function exceptionsInForce(
  tenantId: number,
  deviceId: number,
  from: Date,
  to: Date,
): Promise<DriftException[]> {
  const rows = await db('drift_exceptions as e')
    .where('e.tenant_id', tenantId)
    .andWhere('e.device_id', deviceId)
    // Nothing created after the window closed can have covered any of it. The
    // other bound is decided per row, below, from the history.
    .andWhere('e.created_at', '<=', to)
    .orderBy('e.created_at', 'asc')
    .select<ExceptionRow[]>(EXCEPTION_COLUMNS);
  if (rows.length === 0) return [];

  // tenant_id leads on the history read too: `drift_exception_reviews` carries
  // its own tenant column and an id list is not an authorisation.
  const history = await db('drift_exception_reviews')
    .where('tenant_id', tenantId)
    .whereIn('exception_id', rows.map((r) => String(r.id)))
    .select<ReviewRow[]>('*');
  const byException = new Map<string, ReviewRow[]>();
  for (const h of history) {
    const key = String(h.exception_id);
    const bucket = byException.get(key);
    if (bucket) bucket.push(h);
    else byException.set(key, [h]);
  }

  const out: DriftException[] = [];
  for (const r of rows) {
    const reviews = byException.get(String(r.id)) ?? [];
    const covers = coverIntervals(r, reviews);
    const overlaps = covers.some(
      (c) => c.from.getTime() <= to.getTime() && c.to.getTime() >= from.getTime(),
    );
    if (!overlaps) continue;
    // `to` as the clock: `state` is then the state at the close of the attested
    // window, which is what the field name means to a reader of the document.
    out.push(toException(asOf(r, to, reviews), to));
  }
  return out;
}
