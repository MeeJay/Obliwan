/**
 * ObliWAN F5 — turning PPP session history into WAN path events.
 *
 * ┌─ THE SIGNAL THAT ALREADY EXISTED AND WAS THROWN AWAY ─────────────────────┐
 * │ `applySessionUp()` computes `publicPathChanged` — "this session came back │
 * │ from a different public address than the one we had" — passes it to the   │
 * │ verdict engine, and nothing has ever aggregated it. That is a SILENT WAN  │
 * │ FAILOVER, detected since M2, reported to nobody.                          │
 * │                                                                          │
 * │ F5 does not modify `pppPresence.service.ts` to hook into it. It derives   │
 * │ the same transitions from `ppp_sessions`, which is the PERSISTED form of  │
 * │ that signal, by comparing each session's `caller_ip` with the one         │
 * │ immediately before it on the same device. Three reasons this             │
 * │ is better than a callback and not merely more polite:                     │
 * │                                                                          │
 * │ 1. IT IS RETROACTIVE. A correlation that only sees events fired since the │
 * │    process started is blind for ten minutes after every deploy — which,   │
 * │    given that deploys and incidents both happen on bad afternoons, is     │
 * │    exactly when it would be blind.                                        │
 * │ 2. IT IS IDEMPOTENT. Keyed on (tenant_id, device_id, session_id), so a    │
 * │    re-scan of the same window produces the same rows. An event stream     │
 * │    replayed after a leader handover would double every vote and hand a    │
 * │    quorum of five to three sites counted twice.                           │
 * │ 3. IT SURVIVES A MISSED `listen`. The 60 s reconciliation sweep writes    │
 * │    the session row even when the streaming event was dropped; a callback  │
 * │    on the event would not have fired at all.                              │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * TENANT SCOPING. `ppp_sessions` has no tenant column, so every read here joins
 * `devices` and filters `d.tenant_id`. The predecessor lookup is correlated on
 * `device_id` alone and needs no tenant predicate of its own — a session of a
 * device belongs, by construction, to that device's tenant — but it must never
 * be widened to match on anything else: a lookup keyed on `ppp_username` or on
 * `caller_ip` would compute a device's "previous address" from another
 * customer's rows, and the derived event would then be attributed to, and
 * counted for, the wrong fleet.
 */

import {
  siteKeyOf, type WanEventDirection, type WanPathKind,
} from '@obliwan/shared/dist/weather';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { attributeAddress } from './asn.service';

/**
 * How far back the session scan looks for NEW SESSIONS TO CLASSIFY.
 *
 * ┌─ IT BOUNDS THE SCAN, NOT THE COMPARISON ──────────────────────────────────┐
 * │ This is the only thing this number does, and the distinction is the whole │
 * │ correctness of the ingestion.                                             │
 * │                                                                          │
 * │ It used to bound a `LAG(...) OVER (PARTITION BY device_id)` — the filter  │
 * │ sat INSIDE the CTE, so it removed rows before the window function ran and │
 * │ the "previous address" was the previous address WITHIN THE LOOKBACK. A    │
 * │ transition was therefore only ever detected when BOTH sessions had        │
 * │ started inside it. A healthy fixed line holds one PPP session for days:   │
 * │ twelve sites up for twenty-six hours failing over five minutes ago got a  │
 * │ NULL predecessor, were filtered out by `prev_ip IS NOT NULL`, and the     │
 * │ sweep reported `{ scanned: 0, inserted: 0 }`. The feature was inert on    │
 * │ precisely the fleet it exists for, and only a fixture that aged the       │
 * │ previous session to `minutesAgo + 120` ever made it look alive.           │
 * │                                                                          │
 * │ The predecessor is now fetched per candidate session by a LATERAL         │
 * │ sub-select with no time bound at all, riding the (device_id, started_at)  │
 * │ index of migration 002 — it reads exactly one row and reaches back as far │
 * │ as it has to.                                                             │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export const DEFAULT_LOOKBACK_MINUTES = 180;

interface TransitionRow {
  session_id: string;
  device_id: number;
  tenant_id: number;
  site_id: number | null;
  caller_ip: string | null;
  prev_ip: string | null;
  started_at: Date;
}

export interface IngestOutcome {
  scanned: number;
  inserted: number;
  skippedUnattributable: number;
}

/**
 * Derive and persist path transitions for one tenant.
 *
 * A transition is a session that came up from a DIFFERENT public address than
 * the previous session of the same device. Direction:
 *
 *   lateral  same ASN on both sides — a DHCP renumber at the same carrier.
 *            Recorded and never counted: a carrier's nightly lease rotation
 *            would otherwise be a nightly fleet-wide incident.
 *   back     the device returned to the ASN of its immediately preceding
 *            `away`. Informational; recovery itself is decided from CURRENT
 *            state by the correlator, not from this label.
 *   away     everything else. The only direction that can feed a quorum.
 */
export async function ingestPathEvents(
  tenantId: number,
  opts: { lookbackMinutes?: number; now?: Date } = {},
): Promise<IngestOutcome> {
  const lookback = opts.lookbackMinutes ?? DEFAULT_LOOKBACK_MINUTES;

  const { rows } = (await db.raw(
    `
    SELECT ps.id          AS session_id,
           ps.device_id   AS device_id,
           d.tenant_id    AS tenant_id,
           d.site_id      AS site_id,
           ps.caller_ip   AS caller_ip,
           ps.started_at  AS started_at,
           prev.caller_ip AS prev_ip
      FROM ppp_sessions ps
      JOIN devices d ON d.id = ps.device_id
      -- THE PREDECESSOR, UNBOUNDED IN TIME AND BOUNDED TO ONE ROW.
      -- Index (device_id, started_at) from migration 002; the ORDER BY walks
      -- it backwards and LIMIT 1 stops at the first row. (started_at, id) is
      -- compared as a PAIR so two sessions stamped the same second still have
      -- a total order -- id is a bigserial, and it is the only tiebreak that
      -- agrees with the ORDER BY of the outer query.
      LEFT JOIN LATERAL (
        SELECT p.caller_ip
          FROM ppp_sessions p
         WHERE p.device_id = ps.device_id
           AND (p.started_at, p.id) < (ps.started_at, ps.id)
         ORDER BY p.started_at DESC, p.id DESC
         LIMIT 1
      ) prev ON TRUE
     WHERE d.tenant_id = ?
       AND ps.device_id IS NOT NULL
       AND ps.started_at >= now() - (? * INTERVAL '1 minute')
       AND prev.caller_ip IS NOT NULL
       AND ps.caller_ip IS NOT NULL
       AND host(ps.caller_ip) <> host(prev.caller_ip)
     ORDER BY ps.device_id, ps.started_at, ps.id
    `,
    [tenantId, lookback],
  )) as { rows: TransitionRow[] };

  let inserted = 0;
  let skipped = 0;
  /**
   * Per device, the ASN the device is currently AWAY FROM, or null when it is
   * not away from anything.
   *
   * SEEDED FROM `wan_path_events`, NOT FROM THIS PASS. See `lastAwayAsnOf`.
   */
  const awayFrom = new Map<number, number | null>();

  for (const row of rows) {
    const from = await attributeAddress(row.prev_ip);
    const to = await attributeAddress(row.caller_ip);

    const fromAsn = from.asn?.asn ?? null;
    const toAsn = to.asn?.asn ?? null;

    // First time this pass touches this device: recover its away-state from the
    // history, as of the instant BEFORE this transition.
    if (!awayFrom.has(row.device_id)) {
      awayFrom.set(
        row.device_id,
        await lastAwayAsnOf(row.tenant_id, row.device_id, row.started_at),
      );
    }

    let direction: WanEventDirection;
    if (fromAsn !== null && toAsn !== null && fromAsn === toAsn) {
      direction = 'lateral';
    } else if (toAsn !== null && awayFrom.get(row.device_id) === toAsn) {
      direction = 'back';
      awayFrom.set(row.device_id, null);
    } else {
      direction = 'away';
      awayFrom.set(row.device_id, fromAsn);
    }

    // An `away` we cannot attribute is not a candidate for anything — no ASN,
    // no quorum key. It is still recorded, because "this site moved and we
    // could not say where from" is a real observation and the alternative is a
    // silent gap in the history an operator is reading during an outage.
    if (direction === 'away' && fromAsn === null) skipped++;

    const paths = await pathKindsFor(row.device_id, direction);

    const result = await db.raw(
      `
      INSERT INTO wan_path_events
        (tenant_id, device_id, site_id, session_id, at, direction,
         from_ip, to_ip, from_asn, to_asn, from_as_org, to_as_org,
         from_path_kind, to_path_kind, source)
      VALUES (?, ?, ?, ?, ?, ?, ?::inet, ?::inet, ?, ?, ?, ?, ?, ?, 'ppp_caller_id')
      ON CONFLICT (tenant_id, device_id, session_id) WHERE session_id IS NOT NULL
        DO NOTHING
      RETURNING id
      `,
      [
        row.tenant_id,
        row.device_id,
        row.site_id,
        row.session_id,
        row.started_at,
        direction,
        row.prev_ip,
        row.caller_ip,
        fromAsn,
        toAsn,
        from.asn?.asOrg ?? null,
        to.asn?.asOrg ?? null,
        paths.from,
        paths.to,
      ],
    );
    if ((result.rows as unknown[]).length > 0) inserted++;
  }

  if (inserted > 0) {
    logger.info(
      { tenantId, scanned: rows.length, inserted, skippedUnattributable: skipped },
      'F5 ingested WAN path transitions from PPP session history',
    );
  }
  return { scanned: rows.length, inserted, skippedUnattributable: skipped };
}

/**
 * The ASN this device is away FROM as of `before`, or null if it is not away.
 *
 * ┌─ WHY THIS IS A DATABASE READ AND NOT A VARIABLE ──────────────────────────┐
 * │ `back` and `away` differ by exactly one fact — "did this device leave the │
 * │ ASN it is now returning to?" — and that fact lives in `wan_path_events`,  │
 * │ which is append-only and indexed (device_id, at DESC) for this read.      │
 * │                                                                          │
 * │ It used to live in a Map rebuilt from each pass's own result set. The     │
 * │ moment the originating `away` fell out of the scan — i.e. any outage      │
 * │ lasting longer than one lookback, which is most of them — the return leg  │
 * │ found an empty Map and was classified `away` WITH THE MOBILE CARRIER AS   │
 * │ `from_asn`. `from_asn` is the correlation key (migration 021, decision    │
 * │ 1), so twelve sites coming home from an LTE failover opened one incident  │
 * │ against the carrier that had just rescued them, at full confidence, at    │
 * │ the exact minute service was restored. The one incident a real outage     │
 * │ produced named the wrong operator and fired on recovery.                  │
 * │                                                                          │
 * │ `at < before` is strict, so re-scanning a window never re-reads the event │
 * │ being classified and a replay yields the same label — the idempotence     │
 * │ that used to be a property of "rebuilt from scratch every pass" is now a  │
 * │ property of the predicate.                                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
async function lastAwayAsnOf(
  tenantId: number,
  deviceId: number,
  before: Date,
): Promise<number | null> {
  const row = await db('wan_path_events')
    .where({ tenant_id: tenantId, device_id: deviceId })
    .whereIn('direction', ['away', 'back'])
    .andWhere('at', '<', before)
    .orderBy([{ column: 'at', order: 'desc' }, { column: 'id', order: 'desc' }])
    .first<{ direction: WanEventDirection; from_asn: string | null } | undefined>(
      'direction', 'from_asn',
    );

  // A `back` is the state being CLEARED: the device came home, it is away from
  // nothing. Only an `away` leaves a debt, and only an attributable one.
  if (!row || row.direction !== 'away' || row.from_asn === null) return null;
  return Number(row.from_asn);
}

/**
 * Best-effort path kinds for an event.
 *
 * `device_wan_path.path_kind` is CURRENT state, so it can only ever describe
 * the `to` side of the most recent transition — and it does so only when the
 * observation is fresh enough to be about this event rather than the one
 * before. Anything else stays `unknown`, which is a third value meaning "not
 * measured" and never a synonym for `wan_port`. Guessing "it must have been on
 * its WAN port before" is how a feature reports a failover that never happened.
 */
async function pathKindsFor(
  deviceId: number,
  direction: WanEventDirection,
): Promise<{ from: WanPathKind; to: WanPathKind }> {
  const row = await db('device_wan_path')
    .where({ device_id: deviceId })
    .first<{ path_kind: WanPathKind } | undefined>('path_kind');
  const current = row?.path_kind ?? 'unknown';
  return direction === 'away' ? { from: 'unknown', to: current } : { from: current, to: 'unknown' };
}

// ============================================================================
// Read model for the device timeline
// ============================================================================

export interface WanPathEventView {
  id: number;
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  siteKey: number;
  at: string;
  direction: WanEventDirection;
  fromIp: string | null;
  toIp: string | null;
  fromAsn: number | null;
  toAsn: number | null;
  fromAsOrg: string | null;
  toAsOrg: string | null;
  fromPathKind: WanPathKind;
  toPathKind: WanPathKind;
}

/** Recent transitions for a tenant, newest first. Scoped by `tenant_id` on the
 *  event AND by the join to `devices` — the events table carries the column,
 *  and the join is what proves the device still belongs to that tenant. */
export async function listPathEvents(
  tenantId: number,
  opts: { sinceMinutes?: number; deviceId?: number; asn?: number; limit?: number } = {},
): Promise<WanPathEventView[]> {
  const limit = Math.min(Math.max(opts.limit ?? 200, 1), 1000);
  let q = db('wan_path_events as e')
    .join('devices as d', function joinDevice(this: any) {
      this.on('d.id', '=', 'e.device_id').andOn('d.tenant_id', '=', 'e.tenant_id');
    })
    .where('e.tenant_id', tenantId)
    .orderBy('e.at', 'desc')
    .limit(limit);

  if (opts.sinceMinutes) {
    q = q.andWhereRaw("e.at >= now() - (? * INTERVAL '1 minute')", [opts.sinceMinutes]);
  }
  if (opts.deviceId) q = q.andWhere('e.device_id', opts.deviceId);
  if (opts.asn) {
    q = q.andWhere(function asnFilter(this: any) {
      this.where('e.from_asn', opts.asn).orWhere('e.to_asn', opts.asn);
    });
  }

  const rows = await q.select<
    Array<{
      id: string;
      device_id: number;
      name: string;
      site_id: number | null;
      at: Date;
      direction: WanEventDirection;
      from_ip: string | null;
      to_ip: string | null;
      from_asn: string | null;
      to_asn: string | null;
      from_as_org: string | null;
      to_as_org: string | null;
      from_path_kind: WanPathKind;
      to_path_kind: WanPathKind;
    }>
  >(
    'e.id', 'e.device_id', 'd.name', 'e.site_id', 'e.at', 'e.direction',
    'e.from_ip', 'e.to_ip', 'e.from_asn', 'e.to_asn', 'e.from_as_org', 'e.to_as_org',
    'e.from_path_kind', 'e.to_path_kind',
  );

  return rows.map((r) => ({
    id: Number(r.id),
    deviceId: r.device_id,
    deviceName: r.name,
    siteId: r.site_id,
    siteKey: siteKeyOf(r.site_id, r.device_id),
    at: new Date(r.at).toISOString(),
    direction: r.direction,
    fromIp: r.from_ip,
    toIp: r.to_ip,
    fromAsn: r.from_asn === null ? null : Number(r.from_asn),
    toAsn: r.to_asn === null ? null : Number(r.to_asn),
    fromAsOrg: r.from_as_org,
    toAsOrg: r.to_as_org,
    fromPathKind: r.from_path_kind,
    toPathKind: r.to_path_kind,
  }));
}
