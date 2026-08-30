// ============================================================================
// ObliWAN — F2: assembling the evidence set for one device and one window
// ============================================================================
//
// This file answers ONE question and refuses to answer more than it can:
//
//   "Was equipment D in configuration C from T1 to T2?"
//
// ┌─ THE TRAP THIS FILE IS BUILT AROUND ──────────────────────────────────────┐
// │ `config_snapshots` DEDUPLICATES. `UNIQUE(device_id, ncm_hash)` means a    │
// │ device that goes A -> B -> A does not produce three rows: it produces     │
// │ two, and the A row's `last_seen_at` is bumped to the second visit while   │
// │ its `captured_at` stays in January.                                       │
// │                                                                           │
// │ Reading "A held from captured_at to last_seen_at" off that row is         │
// │ therefore WRONG, and wrong in the direction that manufactures a           │
// │ compliance claim out of a period during which the box was running B. An   │
// │ attestation that makes that mistake is worse than no attestation: it is   │
// │ a false statement with a hash chain under it.                             │
// │                                                                           │
// │ So this module does not read intervals off rows. It collects DATED        │
// │ OBSERVATIONS — every moment at which some independent part of the         │
// │ platform recorded which hash the device was carrying — sorts them, and    │
// │ derives the periods from the sequence. An interleaved B collapses the A   │
// │ claim automatically, because the observation is right there in the        │
// │ middle of it.                                                             │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ── THE FOUR OBSERVATION SOURCES, AND WHY EACH ONE COUNTS ──────────────────
//
//  captured    `config_snapshots.captured_at` — the first collection that saw
//              this exact document.
//  confirmed   `config_snapshots.last_seen_at` — the most recent collection
//              that saw it. Between the two, `seen_count` further collections
//              agreed, but the deduplication did not keep their timestamps;
//              the count is carried as evidence, the dates are not invented.
//  drift_run   `drift_runs.started_at` with the run's own `snapshot_id`. A
//              drift evaluation is an independent, dated statement about which
//              document the device was on.
//  change_job  `change_jobs.started_at` with `base_state_hash`. The strongest
//              of the four: the executor RE-CHECKS that hash against the live
//              device before it is allowed to write, so the job starting is
//              proof the device carried that configuration at that instant.
//
// ── WHAT A GAP IS, AND WHY IT IS PRINTED RATHER THAN SMOOTHED ──────────────
//
// Two observations of the same hash six months apart do not establish six
// months of continuity — they establish two instants. The stretch in between is
// a period during which NOBODY LOOKED, and the honest document says so. An
// insurer who is told "continuous" over a window that contains a four-month
// hole has been given a number, not evidence.

import { db } from '../../db';

/** Beyond this, an attestation is a data export and not a document. The caller
 *  is told to narrow the window rather than handed a 40 MB JSON. */
export const MAX_EVIDENCE_ENTRIES = 5000;

/** Default stretch of unobserved time that downgrades `continuous` to
 *  `continuous_with_gaps`. Seven days: the collection cadence of a healthy
 *  fleet is daily, so a week of silence is a fact about our coverage that the
 *  reader is entitled to. */
export const DEFAULT_MAX_GAP_DAYS = 7;

export interface DeviceSubject {
  id: number;
  uuid: string;
  name: string;
  brand: string;
  model: string | null;
  serial: string | null;
  tenantId: number;
}

export interface SnapshotRow {
  id: string;
  ncmHash: string;
  rawSha256: string | null;
  rawBytes: number | null;
  ncmVersion: number;
  semKeyGeneration: number;
  normalizationEpoch: string;
  orderAnalysis: string;
  osVersion: string | null;
  source: string;
  capturedAt: Date;
  lastSeenAt: Date;
  seenCount: number;
  unmodeledForwardingCount: number;
}

export type ObservationSource = 'captured' | 'confirmed' | 'drift_run' | 'change_job';

export interface Observation {
  at: Date;
  ncmHash: string;
  source: ObservationSource;
  /** The row that carries the observation, so a reader can go and look at it. */
  refTable: string;
  refId: string;
}

export interface ChangeJobRow {
  id: string;
  uuid: string;
  kind: string;
  status: string;
  outcome: string | null;
  baseStateHash: string;
  safetyLevel: string;
  guardVerdict: string | null;
  overriddenAt: Date | null;
  requestedBy: string | null;
  approvedBy: string | null;
  startedAt: Date | null;
  finishedAt: Date | null;
  createdAt: Date;
}

export interface ApplyOutcomeRow {
  outcome: string;
  count: number;
  firstAt: Date;
  lastAt: Date;
}

export interface CommandSummaryRow {
  total: number;
  writes: number;
  failed: number;
  inFlight: number;
  firstAt: Date | null;
  lastAt: Date | null;
}

/**
 * The subject, scoped by tenant. A device id from another customer is `null`,
 * which the controller turns into a 404 — "that device exists but is not yours"
 * is itself a disclosure about another customer's inventory.
 */
export async function loadSubject(
  tenantId: number,
  deviceId: number,
): Promise<DeviceSubject | null> {
  const row = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{
      id: number; uuid: string; name: string; brand: string;
      model: string | null; serial: string | null; tenant_id: number;
    } | undefined>('id', 'uuid', 'name', 'brand', 'model', 'serial', 'tenant_id');
  if (!row) return null;
  return {
    id: row.id,
    uuid: row.uuid,
    name: row.name,
    brand: row.brand,
    model: row.model,
    serial: row.serial,
    tenantId: row.tenant_id,
  };
}

/**
 * Every snapshot whose observed lifetime touches the window, plus the one
 * immediately before it.
 *
 * The "one before" is not padding: without it, a device that was collected in
 * January and not again until April has NO snapshot intersecting a February
 * window, and the attestation would report `insufficient_evidence` for a period
 * whose configuration we do in fact have a bounded claim about. Including it
 * lets the gap analysis do its job — the claim comes out as
 * `continuous_with_gaps` with the hole printed, which is the true answer.
 */
export async function loadSnapshots(
  deviceId: number,
  from: Date,
  to: Date,
): Promise<SnapshotRow[]> {
  const rows = await db('config_snapshots')
    .where({ device_id: deviceId })
    .andWhere((qb) => {
      void qb
        .where((inner) => {
          void inner.where('captured_at', '<=', to).andWhere('last_seen_at', '>=', from);
        })
        // The most recent snapshot that had already been confirmed before the
        // window opened.
        .orWhereIn('id', db('config_snapshots')
          .where({ device_id: deviceId })
          .andWhere('last_seen_at', '<', from)
          .orderBy('last_seen_at', 'desc')
          .limit(1)
          .select('id'));
    })
    .orderBy([{ column: 'captured_at', order: 'asc' }, { column: 'id', order: 'asc' }])
    .select<{
      id: string; ncm_hash: string; raw_sha256: string | null; raw_bytes: number | null;
      ncm_version: number; sem_key_generation: number; normalization_epoch: string;
      order_analysis: string; os_version: string | null; source: string;
      captured_at: Date; last_seen_at: Date; seen_count: number;
      unmodeled_forwarding_count: number;
    }[]>(
      'id', 'ncm_hash', 'raw_sha256', 'raw_bytes', 'ncm_version', 'sem_key_generation',
      'normalization_epoch', 'order_analysis', 'os_version', 'source',
      'captured_at', 'last_seen_at', 'seen_count', 'unmodeled_forwarding_count',
    );

  return rows.map((r) => ({
    id: String(r.id),
    ncmHash: r.ncm_hash,
    rawSha256: r.raw_sha256,
    rawBytes: r.raw_bytes === null ? null : Number(r.raw_bytes),
    ncmVersion: Number(r.ncm_version),
    semKeyGeneration: Number(r.sem_key_generation),
    normalizationEpoch: r.normalization_epoch,
    orderAnalysis: r.order_analysis,
    osVersion: r.os_version,
    source: r.source,
    capturedAt: new Date(r.captured_at),
    lastSeenAt: new Date(r.last_seen_at),
    seenCount: Number(r.seen_count),
    unmodeledForwardingCount: Number(r.unmodeled_forwarding_count),
  }));
}

/**
 * Every dated statement about which configuration the device was carrying.
 *
 * Deduplicated on `(at, ncmHash, source)` and sorted deterministically — the
 * evidence chain is order-sensitive by design, so two runs over the same data
 * must produce the same sequence or the root would be meaningless.
 */
export async function loadObservations(
  tenantId: number,
  deviceId: number,
  snapshots: readonly SnapshotRow[],
): Promise<Observation[]> {
  const out: Observation[] = [];
  const byId = new Map<string, SnapshotRow>();

  for (const s of snapshots) {
    byId.set(s.id, s);
    out.push({
      at: s.capturedAt,
      ncmHash: s.ncmHash,
      source: 'captured',
      refTable: 'config_snapshots',
      refId: s.id,
    });
    // A snapshot seen once has `captured_at = last_seen_at`; emitting both
    // would be one observation counted twice and would inflate `confirmations`.
    if (s.lastSeenAt.getTime() !== s.capturedAt.getTime()) {
      out.push({
        at: s.lastSeenAt,
        ncmHash: s.ncmHash,
        source: 'confirmed',
        refTable: 'config_snapshots',
        refId: s.id,
      });
    }
  }

  if (byId.size > 0) {
    const ids = [...byId.keys()];
    // `drift_runs` has no tenant column: scoped by JOIN on devices, and the
    // device itself was already resolved under the tenant.
    const runs = await db('drift_runs as dr')
      .join('devices as d', 'd.id', 'dr.device_id')
      .where('d.tenant_id', tenantId)
      .andWhere('dr.device_id', deviceId)
      .whereIn('dr.snapshot_id', ids)
      .select<{ id: string; snapshot_id: string; started_at: Date }[]>(
        'dr.id', 'dr.snapshot_id', 'dr.started_at',
      );
    for (const r of runs) {
      const s = byId.get(String(r.snapshot_id));
      if (!s) continue;
      out.push({
        at: new Date(r.started_at),
        ncmHash: s.ncmHash,
        source: 'drift_run',
        refTable: 'drift_runs',
        refId: String(r.id),
      });
    }
  }

  // The strongest source: a job that reached `started_at` had its
  // `base_state_hash` re-checked against the LIVE device (migration 009 —
  // "the executor refuses to apply it if the device has moved since").
  const jobs = await db('change_jobs')
    .where({ tenant_id: tenantId, device_id: deviceId })
    .whereNotNull('started_at')
    .select<{ id: string; base_state_hash: string; started_at: Date }[]>(
      'id', 'base_state_hash', 'started_at',
    );
  for (const j of jobs) {
    out.push({
      at: new Date(j.started_at),
      ncmHash: j.base_state_hash,
      source: 'change_job',
      refTable: 'change_jobs',
      refId: String(j.id),
    });
  }

  const seen = new Set<string>();
  const deduped: Observation[] = [];
  for (const o of out) {
    const key = `${o.at.getTime()}|${o.ncmHash}|${o.source}|${o.refId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(o);
  }
  deduped.sort(
    (a, b) =>
      a.at.getTime() - b.at.getTime()
      || (a.source < b.source ? -1 : a.source > b.source ? 1 : 0)
      || (a.refId < b.refId ? -1 : a.refId > b.refId ? 1 : 0),
  );
  return deduped;
}

/** Changes attempted on the device inside the window. `change_jobs` carries its
 *  own `tenant_id`, and the read filters on BOTH it and the device — a job row
 *  whose two columns disagreed would be a bug, not a reason to widen. */
export async function loadChangeJobs(
  tenantId: number,
  deviceId: number,
  from: Date,
  to: Date,
): Promise<ChangeJobRow[]> {
  const rows = await db('change_jobs as cj')
    .join('devices as d', 'd.id', 'cj.device_id')
    .leftJoin('users as ru', 'ru.id', 'cj.requested_by')
    .leftJoin('users as au', 'au.id', 'cj.approved_by')
    .where('d.tenant_id', tenantId)
    .andWhere('cj.tenant_id', tenantId)
    .andWhere('cj.device_id', deviceId)
    .andWhere((qb) => {
      void qb
        .whereBetween('cj.created_at', [from, to])
        .orWhereBetween('cj.started_at', [from, to])
        .orWhereBetween('cj.finished_at', [from, to]);
    })
    .orderBy('cj.id', 'asc')
    .select<{
      id: string; uuid: string; kind: string; status: string; outcome: string | null;
      base_state_hash: string; safety_level: string; guard_verdict: string | null;
      overridden_at: Date | null; requested_by_username: string | null;
      approved_by_username: string | null; started_at: Date | null;
      finished_at: Date | null; created_at: Date;
    }[]>(
      'cj.id', 'cj.uuid', 'cj.kind', 'cj.status', 'cj.outcome', 'cj.base_state_hash',
      'cj.safety_level', 'cj.guard_verdict', 'cj.overridden_at', 'cj.started_at',
      'cj.finished_at', 'cj.created_at',
      'ru.username as requested_by_username',
      'au.username as approved_by_username',
    );

  return rows.map((r) => ({
    id: String(r.id),
    uuid: r.uuid,
    kind: r.kind,
    status: r.status,
    outcome: r.outcome,
    baseStateHash: r.base_state_hash,
    safetyLevel: r.safety_level,
    guardVerdict: r.guard_verdict,
    overriddenAt: r.overridden_at === null ? null : new Date(r.overridden_at),
    requestedBy: r.requested_by_username,
    approvedBy: r.approved_by_username,
    startedAt: r.started_at === null ? null : new Date(r.started_at),
    finishedAt: r.finished_at === null ? null : new Date(r.finished_at),
    createdAt: new Date(r.created_at),
  }));
}

/**
 * `apply_outcomes` has NO foreign keys (migration 009, decision 5) — the corpus
 * outlives the client. That makes the tenant column the only isolation on the
 * table itself, so this read ALSO joins `devices` and filters on its tenant.
 * Either column alone would be one bug away from a cross-customer read.
 */
export async function loadApplyOutcomes(
  tenantId: number,
  deviceId: number,
  from: Date,
  to: Date,
): Promise<ApplyOutcomeRow[]> {
  const rows = await db('apply_outcomes as ao')
    .join('devices as d', 'd.id', 'ao.device_id')
    .where('d.tenant_id', tenantId)
    .andWhere('ao.tenant_id', tenantId)
    .andWhere('ao.device_id', deviceId)
    .andWhereBetween('ao.observed_at', [from, to])
    .groupBy('ao.outcome')
    .orderBy('ao.outcome', 'asc')
    .select<{ outcome: string; count: string; first_at: Date; last_at: Date }[]>(
      'ao.outcome',
      db.raw('count(*) as count'),
      db.raw('min(ao.observed_at) as first_at'),
      db.raw('max(ao.observed_at) as last_at'),
    );
  return rows.map((r) => ({
    outcome: r.outcome,
    count: Number(r.count),
    firstAt: new Date(r.first_at),
    lastAt: new Date(r.last_at),
  }));
}

/**
 * COUNTERS, not rows, and that is a §8.2 decision rather than a size one.
 *
 * `command_audit.command` is redacted at two independent layers, but it is
 * still the column closest to a secret in the whole schema. An attestation is
 * a document designed to be forwarded to a third party, so the command TEXT
 * does not go in it — "seventeen writes, all attached to two change jobs, none
 * failed" is what establishes the claim, and it carries no leak surface at all.
 */
export async function loadCommandSummary(
  tenantId: number,
  deviceId: number,
  from: Date,
  to: Date,
): Promise<CommandSummaryRow> {
  const row = await db('command_audit as ca')
    .join('devices as d', 'd.id', 'ca.device_id')
    .where('d.tenant_id', tenantId)
    .andWhere('ca.tenant_id', tenantId)
    .andWhere('ca.device_id', deviceId)
    .andWhereBetween('ca.executed_at', [from, to])
    .first<{
      total: string; writes: string; failed: string; in_flight: string;
      first_at: Date | null; last_at: Date | null;
    }>(
      db.raw('count(*) as total'),
      db.raw('count(*) FILTER (WHERE ca.is_write) as writes'),
      db.raw('count(*) FILTER (WHERE ca.success = false) as failed'),
      db.raw('count(*) FILTER (WHERE ca.success IS NULL) as in_flight'),
      db.raw('min(ca.executed_at) as first_at'),
      db.raw('max(ca.executed_at) as last_at'),
    );
  return {
    total: Number(row?.total ?? 0),
    writes: Number(row?.writes ?? 0),
    failed: Number(row?.failed ?? 0),
    inFlight: Number(row?.in_flight ?? 0),
    firstAt: row?.first_at ? new Date(row.first_at) : null,
    lastAt: row?.last_at ? new Date(row.last_at) : null,
  };
}

// ============================================================================
// The timeline
// ============================================================================

export interface DerivedPeriod {
  ncmHash: string;
  snapshotId: string;
  from: Date;
  to: Date;
  fromExact: boolean;
  toExact: boolean;
  /** How many dated observations fell in the run. */
  confirmations: number;
  /**
   * How many DISTINCT source rows those observations came from.
   *
   * `loadObservations` emits `captured` and `confirmed` for the SAME
   * `config_snapshots` row, so a device seen twice a year apart produces
   * `confirmations = 2` off ONE record. Counting `(refTable, refId)` pairs is
   * what separates "two dates" from "two witnesses", and the verdict needs the
   * second: an attestation that says "confirmed by 2 independent dated
   * observations" about one row is false in the only word an insurer reads.
   */
  independentSources: number;
  gaps: { from: Date; to: Date; seconds: number }[];
}

/**
 * Folds the observation sequence into periods.
 *
 * A run of consecutive observations carrying the same hash is one period,
 * bounded by its first and last observation and by NOTHING ELSE. The interval
 * before the first and after the last is unknown, and `fromExact` / `toExact`
 * say which of the two ends is anchored to a real collection event
 * (`captured_at` / `last_seen_at`) rather than merely to the oldest or newest
 * thing we happen to hold.
 *
 * Gaps are computed on the CLIPPED period — a four-month hole that lies
 * entirely before the requested window is not a weakness of the claim being
 * made, and reporting it would train readers to ignore the gap list.
 */
export function derivePeriods(
  observations: readonly Observation[],
  snapshots: readonly SnapshotRow[],
  window: { from: Date; to: Date },
  maxGapSeconds: number,
): DerivedPeriod[] {
  if (observations.length === 0) return [];

  const snapByHash = new Map<string, SnapshotRow>();
  for (const s of snapshots) if (!snapByHash.has(s.ncmHash)) snapByHash.set(s.ncmHash, s);

  const periods: DerivedPeriod[] = [];
  let run: Observation[] = [observations[0]];

  const flush = (): void => {
    const hash = run[0].ncmHash;
    const first = run[0];
    const last = run[run.length - 1];
    const snap = snapByHash.get(hash);

    const clipFrom = new Date(Math.max(first.at.getTime(), window.from.getTime()));
    const clipTo = new Date(Math.min(last.at.getTime(), window.to.getTime()));
    const gaps: { from: Date; to: Date; seconds: number }[] = [];
    if (clipTo.getTime() > clipFrom.getTime()) {
      // Only the observations inside the clipped span can vouch for it; the
      // two just outside it bound the ends, which is why the walk starts from
      // the full run and clips each step rather than filtering first.
      let prev: Date | null = null;
      for (const o of run) {
        const t = new Date(
          Math.min(Math.max(o.at.getTime(), clipFrom.getTime()), clipTo.getTime()),
        );
        if (prev !== null) {
          // ROUNDED TO A WHOLE SECOND, and not for readability. The document is
          // stored as `jsonb` and its digest is taken over a CANONICAL
          // serialisation, so any value that could round-trip through Postgres
          // numeric and back into a JavaScript float differently from how it
          // went in would break the digest of a document nobody touched. Whole
          // seconds have no such edge; a gap is measured in days anyway.
          const seconds = Math.round((t.getTime() - prev.getTime()) / 1000);
          if (seconds > maxGapSeconds) gaps.push({ from: prev, to: t, seconds });
        }
        prev = t;
      }
    }

    const sources = new Set<string>();
    for (const o of run) sources.add(`${o.refTable}#${o.refId}`);

    periods.push({
      ncmHash: hash,
      snapshotId: snap ? snap.id : '',
      from: first.at,
      to: last.at,
      // "We know when this configuration first appeared" — the run opens on the
      // snapshot's own `captured_at` rather than on an observation we happen to
      // have inherited from an earlier period's tail.
      fromExact: first.source === 'captured',
      toExact: last.source === 'confirmed' || last.source === 'captured',
      confirmations: run.length,
      independentSources: sources.size,
      gaps,
    });
  };

  for (let i = 1; i < observations.length; i++) {
    if (observations[i].ncmHash === run[run.length - 1].ncmHash) {
      run.push(observations[i]);
    } else {
      flush();
      run = [observations[i]];
    }
  }
  flush();

  // Periods that lie entirely outside the window are context we loaded to bound
  // the ends; they are not part of the claim and would only pad the document.
  return periods.filter(
    (p) => p.to.getTime() >= window.from.getTime() && p.from.getTime() <= window.to.getTime(),
  );
}
