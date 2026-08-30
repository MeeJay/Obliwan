/**
 * ObliWAN F5 — the correlator. THE feature.
 *
 * ┌─ WHAT THIS FILE REFUSES TO DO ────────────────────────────────────────────┐
 * │ Conclude "operator incident" from one site. Ever. Under any tuning.       │
 * │                                                                          │
 * │ The decision itself is not taken here — it is taken by                    │
 * │ `evaluateOperatorWeather()` in `shared/src/weather.ts`, which is pure,    │
 * │ has no clock and no database, and can be read in one screen. This file    │
 * │ does three things and nothing else: it ASSEMBLES the evidence (with       │
 * │ `tenant_id` on every read), it APPLIES the decisions, and it emits.       │
 * │                                                                          │
 * │ Three independent layers stand between a flap and a phone call to a       │
 * │ carrier, and they are deliberately of different kinds:                    │
 * │   1. the quorum, in pure arithmetic somebody can unit-test;               │
 * │   2. the fleet-wide guard, which vetoes when the shape says the fault is  │
 * │      ours;                                                                │
 * │   3. `operator_incidents_live_uniq`, a partial unique index, which makes  │
 * │      "twelve alerts for one outage" unrepresentable even if 1 and 2 were  │
 * │      both wrong.                                                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ RECOVERY IS DECIDED FROM STATE, NOT FROM EVENTS ─────────────────────────┐
 * │ A member has recovered when the device is CURRENTLY back on the           │
 * │ incident's ASN — `device_wan_path.asn = incident.asn` — not when a `back` │
 * │ event happened to be recorded. Positive evidence only, the same doctrine  │
 * │ as K7's `SITE_DOWN`: a device we can no longer attribute (session down,   │
 * │ private address, table gap) is NOT recovered, it is unknown, and unknown  │
 * │ keeps the incident open. The failure mode of the opposite choice is an    │
 * │ incident that closes because the whole region went dark.                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * TENANT SCOPING: every statement below carries `tenant_id`, including the ones
 * over `wan_path_events` (which has the column) and the ones over
 * `device_wan_path` (which has it too, and is additionally joined to `devices`
 * so the pair is proven rather than trusted).
 */

import {
  DEFAULT_WEATHER_POLICY, WEATHER_SOCKET_EVENTS, clearThreshold,
  evaluateOperatorWeather, normalizeWeatherPolicy, resumeThreshold,
  type AsnCandidate, type OpenIncidentState, type OperatorIncidentDetail,
  type OperatorIncidentStatus, type OperatorIncidentSummary, type WanPathKind,
  type WeatherEvaluation, type WeatherPolicy, type WeatherReport,
} from '@obliwan/shared/dist/weather';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { emitToTenant } from '../fleet/fleetEvents';
import { ingestPathEvents } from './ingest.service';
import { refreshObservedPaths } from './egressPath.service';

// ============================================================================
// 1. The policy
// ============================================================================

interface SettingsRow {
  window_minutes: number;
  min_sites: number;
  min_fraction: string;
  clear_ratio: string;
  hold_down_minutes: number;
  fleet_wide_asn_count: number;
  fleet_wide_fraction: string;
  enabled: boolean;
}

export interface TenantWeatherPolicy {
  policy: WeatherPolicy;
  enabled: boolean;
}

/**
 * Load a tenant's policy, or the default.
 *
 * `normalizeWeatherPolicy` is on the way OUT of the database as well as on the
 * way in. A row edited by hand in psql, or written by a future migration
 * default, must not be able to put an invalid quorum into the correlator — and
 * an invalid one THROWS rather than silently reverting to the default, because
 * "your tuned quorum was ignored" is a failure nobody notices until the alert
 * that should have fired did not.
 */
export async function getTenantPolicy(tenantId: number): Promise<TenantWeatherPolicy> {
  const row = await db('weather_settings')
    .where({ tenant_id: tenantId })
    .first<SettingsRow | undefined>();
  if (!row) return { policy: { ...DEFAULT_WEATHER_POLICY }, enabled: true };

  return {
    enabled: row.enabled,
    policy: normalizeWeatherPolicy({
      windowMinutes: row.window_minutes,
      minSites: row.min_sites,
      minFraction: Number(row.min_fraction),
      clearRatio: Number(row.clear_ratio),
      holdDownMinutes: row.hold_down_minutes,
      fleetWideAsnCount: row.fleet_wide_asn_count,
      fleetWideFraction: Number(row.fleet_wide_fraction),
    }),
  };
}

/**
 * Store a tenant's policy. Validated by the same function the correlator uses
 * — and then again by `weather_settings_hold_down_chk` in the database.
 *
 * ┌─ `enabled` IS TRI-STATE, AND OMITTING IT CHANGES NOTHING ──────────────────┐
 * │ It used to default to `true`. A tenant who had deliberately switched      │
 * │ operator correlation OFF got it switched back ON by the next write that   │
 * │ only meant to move the quorum — an API client, a script or a UI build     │
 * │ that does not send the key. That is a permissive default: MISSING         │
 * │ INFORMATION WIDENED THE PERIMETER, which is the one shape of default this │
 * │ project refuses everywhere else.                                          │
 * │                                                                          │
 * │ `undefined` now means "leave it as it is": the stored value wins, and     │
 * │ `true` is used only for a tenant that has no row yet (which is also what  │
 * │ `getTenantPolicy` reports for one). Turning the feature on or off is an   │
 * │ explicit act in both directions.                                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function setTenantPolicy(
  tenantId: number,
  input: unknown,
  enabled?: boolean,
): Promise<TenantWeatherPolicy> {
  const policy = normalizeWeatherPolicy(input);
  // The COLUMN, not `getTenantPolicy`: that function re-validates the stored
  // quorum and THROWS on a row that violates the asymmetry, so routing this
  // read through it would make a bad stored policy impossible to repair
  // through the very endpoint that exists to repair it.
  //
  // Read outside a transaction on purpose: `enabled` is not part of the
  // quorum, so a concurrent toggle losing to a concurrent quorum edit is
  // last-writer-wins on one boolean, not a torn policy. Locking a settings row
  // to protect a checkbox would cost more than it buys.
  let effectiveEnabled = enabled;
  if (effectiveEnabled === undefined) {
    const current = await db('weather_settings')
      .where({ tenant_id: tenantId })
      .first<{ enabled: boolean } | undefined>('enabled');
    // No row yet = the feature has never been switched off for this tenant,
    // which is exactly what `getTenantPolicy` reports for one.
    effectiveEnabled = current?.enabled ?? true;
  }
  await db('weather_settings')
    .insert({
      tenant_id: tenantId,
      window_minutes: policy.windowMinutes,
      min_sites: policy.minSites,
      min_fraction: policy.minFraction,
      clear_ratio: policy.clearRatio,
      hold_down_minutes: policy.holdDownMinutes,
      fleet_wide_asn_count: policy.fleetWideAsnCount,
      fleet_wide_fraction: policy.fleetWideFraction,
      enabled: effectiveEnabled,
      updated_at: db.fn.now(),
    })
    .onConflict('tenant_id')
    .merge([
      'window_minutes', 'min_sites', 'min_fraction', 'clear_ratio',
      'hold_down_minutes', 'fleet_wide_asn_count', 'fleet_wide_fraction',
      'enabled', 'updated_at',
    ]);
  return { policy, enabled: effectiveEnabled };
}

// ============================================================================
// 2. Assembling the evidence
// ============================================================================

/**
 * THE LINE A ROW BELONGS TO, IN SQL. The exact mirror of `lineKeyOf()`.
 *
 * Two implementations of one rule is a liability, so they are kept adjacent and
 * the harness asserts they agree. The rule: the site if there is one, otherwise
 * the PUBLIC ADDRESS the device egresses from, otherwise the device itself.
 * `host()` normalises `185.10.1.1/32` and `185.10.1.1` to the same text, which
 * is what `lineKeyOf` does with its `split('/')`.
 *
 * WHY THE ADDRESS AND NOT THE DEVICE: `devices.site_id` is nullable and nothing
 * populates it, so `COALESCE(site_id, -device_id)` — what every count in this
 * file used to say — gave five routers behind one DSL line five votes, and one
 * bounce of that line satisfied a quorum of five at fraction 1.00. See
 * migration 022 and `lineKeyOf`.
 */
const LINE_KEY_SQL = (t: string): string =>
  `CASE WHEN ${t}.site_id IS NOT NULL THEN 'site:' || ${t}.site_id ` +
  `WHEN ${t}.from_ip IS NOT NULL THEN 'line:' || host(${t}.from_ip) ` +
  `ELSE 'dev:' || ${t}.device_id END`;

/** Same rule over a CURRENT-state row, whose address column is the generated
 *  `effective_public_ip` rather than an event's `from_ip`. */
const CURRENT_LINE_KEY_SQL =
  `CASE WHEN d.site_id IS NOT NULL THEN 'site:' || d.site_id ` +
  `WHEN dwp.effective_public_ip IS NOT NULL THEN 'line:' || host(dwp.effective_public_ip) ` +
  `ELSE 'dev:' || d.id END`;

/**
 * A MEMBER's line key: the one RESOLVED AND STORED when it joined.
 *
 * The COALESCE is for rows written before migration 022, which have no
 * `line_key`; they keep counting exactly as they did — one vote per device —
 * rather than being back-filled with a guess about which line a device was on
 * during an incident that has already closed.
 */
const MEMBER_LINE_KEY_SQL =
  `COALESCE(m.line_key, ` +
  `CASE WHEN m.site_id IS NOT NULL THEN 'site:' || m.site_id ` +
  `ELSE 'dev:' || m.device_id END)`;

/**
 * Sites that left each ASN inside the correlation window.
 *
 * `direction = 'away'` only — a `lateral` is one carrier renumbering its own
 * customer and must never be a vote. LINES, not devices (decision 2 of the
 * shared contract, as amended by the audit): see `LINE_KEY_SQL`.
 */
async function loadCandidates(
  tenantId: number,
  windowMinutes: number,
  nominalHorizonDays: number,
): Promise<AsnCandidate[]> {
  const { rows: affected } = (await db.raw(
    `
    SELECT e.from_asn                                   AS asn,
           MIN(e.from_as_org)                           AS as_org,
           ARRAY_AGG(DISTINCT ${LINE_KEY_SQL('e')})     AS site_keys,
           COUNT(DISTINCT ${LINE_KEY_SQL('e')})
             FILTER (WHERE e.to_path_kind = 'lte')      AS on_lte
      FROM wan_path_events e
     WHERE e.tenant_id = ?
       AND e.direction = 'away'
       AND e.from_asn IS NOT NULL
       AND e.at >= now() - (? * INTERVAL '1 minute')
     GROUP BY e.from_asn
    `,
    [tenantId, windowMinutes],
  )) as { rows: Array<{ asn: string; as_org: string | null; site_keys: string[]; on_lte: string }> };

  if (affected.length === 0) return [];

  // THE DENOMINATOR, and it is not "who is on this ASN right now".
  //
  // After a failover the site is on the MOBILE carrier's ASN, so counting
  // current attributions would shrink the denominator exactly as the numerator
  // grows and hand the relative quorum a free pass. The right denominator is
  // "sites whose NOMINAL carrier is this ASN": the ones still on it, plus the
  // ones that have left it at some point in the recent past.
  const { rows: fleet } = (await db.raw(
    `
    SELECT asn, COUNT(DISTINCT site_key) AS sites FROM (
      SELECT dwp.asn AS asn, ${CURRENT_LINE_KEY_SQL} AS site_key
        FROM device_wan_path dwp
        JOIN devices d ON d.id = dwp.device_id AND d.tenant_id = dwp.tenant_id
       WHERE dwp.tenant_id = ? AND dwp.asn IS NOT NULL
      UNION
      SELECT e.from_asn, ${LINE_KEY_SQL('e')}
        FROM wan_path_events e
       WHERE e.tenant_id = ?
         AND e.from_asn IS NOT NULL
         AND e.at >= now() - (? * INTERVAL '1 day')
    ) t
    GROUP BY asn
    `,
    [tenantId, tenantId, nominalHorizonDays],
  )) as { rows: Array<{ asn: string; sites: string }> };

  const fleetByAsn = new Map<number, number>(
    fleet.map((r) => [Number(r.asn), Number(r.sites)]),
  );

  return affected.map((r) => ({
    asn: Number(r.asn),
    asOrg: r.as_org,
    affectedSiteKeys: r.site_keys ?? [],
    fleetSiteCount: fleetByAsn.get(Number(r.asn)) ?? (r.site_keys ?? []).length,
    onLteCount: Number(r.on_lte),
  }));
}

export interface SiteCoverage {
  deviceCount: number;
  unsitedDeviceCount: number;
  unsitedGroupedByLineCount: number;
  unsitedUngroupedDeviceCount: number;
  unsitedBehindConcentratorCount: number;
}

/**
 * HOW MUCH OF THIS TENANT'S QUORUM RESTS ON A FALLBACK, in one query.
 *
 * ┌─ WHY A BREAKDOWN AND NOT A COUNT ─────────────────────────────────────────┐
 * │ This used to return one number — "devices with no site_id" — and that     │
 * │ number could not be acted on. It had no denominator, so it did not say    │
 * │ whether the fleet was mostly unsited or barely; and it merged the case    │
 * │ where the fallback WORKS (grouped by egress address: five routers behind  │
 * │ one line are one vote, which is what `lineKeyOf` is for) with the case    │
 * │ where it DOES NOT (no address either: `dev:<id>`, one vote per device —   │
 * │ the exact collapse migration 022 was written to stop). Those two          │
 * │ populations need opposite reactions, so they are counted separately.      │
 * │                                                                          │
 * │ The predicate for "grouped by line" is `effective_public_ip IS NOT NULL`, │
 * │ character for character the branch `CURRENT_LINE_KEY_SQL` takes. A        │
 * │ coverage number that described something other than what the key actually │
 * │ does would be a second implementation of the rule, quietly disagreeing.   │
 * │                                                                          │
 * │ Concentrators are excluded from every count: they are infrastructure,     │
 * │ they carry the tunnels rather than sit behind them, and they never vote.  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Tenant scope is on `devices` AND repeated on the join to `device_wan_path`
 * (which has its own `tenant_id`), so neither side can widen the other.
 */
async function loadSiteCoverage(tenantId: number): Promise<SiteCoverage> {
  const { rows } = (await db.raw(
    `
    SELECT COUNT(*)                                                   AS devices,
           COUNT(*) FILTER (WHERE d.site_id IS NULL)                  AS unsited,
           COUNT(*) FILTER (WHERE d.site_id IS NULL
                              AND dwp.effective_public_ip IS NOT NULL) AS grouped,
           COUNT(*) FILTER (WHERE d.site_id IS NULL
                              AND dwp.effective_public_ip IS NULL)     AS ungrouped,
           COUNT(*) FILTER (WHERE d.site_id IS NULL
                              AND d.concentrator_id IS NOT NULL)       AS behind_chr
      FROM devices d
      LEFT JOIN device_wan_path dwp
        ON dwp.device_id = d.id AND dwp.tenant_id = d.tenant_id
     WHERE d.tenant_id = ? AND d.role <> 'concentrator'
    `,
    [tenantId],
  )) as {
    rows: Array<{
      devices: string; unsited: string; grouped: string;
      ungrouped: string; behind_chr: string;
    }>;
  };
  const r = rows[0];
  return {
    deviceCount: Number(r?.devices ?? 0),
    unsitedDeviceCount: Number(r?.unsited ?? 0),
    unsitedGroupedByLineCount: Number(r?.grouped ?? 0),
    unsitedUngroupedDeviceCount: Number(r?.ungrouped ?? 0),
    unsitedBehindConcentratorCount: Number(r?.behind_chr ?? 0),
  };
}

/** Distinct sites for which we hold an attributable public address. The
 *  denominator of the fleet-wide guard. */
async function loadAttributedSiteCount(tenantId: number): Promise<number> {
  const { rows } = (await db.raw(
    `
    SELECT COUNT(DISTINCT ${CURRENT_LINE_KEY_SQL}) AS sites
      FROM device_wan_path dwp
      JOIN devices d ON d.id = dwp.device_id AND d.tenant_id = dwp.tenant_id
     WHERE dwp.tenant_id = ? AND dwp.asn IS NOT NULL
    `,
    [tenantId],
  )) as { rows: Array<{ sites: string }> };
  return Number(rows[0]?.sites ?? 0);
}

/**
 * Retire the members that are demonstrably back, then read what is left.
 *
 * The UPDATE is the state-based recovery of the header: a member is retired
 * only when its device's CURRENT attributed ASN is the incident's own. Nothing
 * un-retires a member inside this function — a relapse is a NEW `away` event,
 * which re-joins it through `joinMembers`.
 */
async function refreshMembership(tenantId: number): Promise<void> {
  await db.raw(
    `
    UPDATE operator_incident_members m
       SET recovered_at = now()
      FROM operator_incidents i, device_wan_path dwp
     WHERE m.tenant_id = ?
       AND i.id = m.incident_id
       AND i.tenant_id = m.tenant_id
       AND i.status <> 'closed'
       AND dwp.device_id = m.device_id
       AND dwp.tenant_id = m.tenant_id
       AND m.recovered_at IS NULL
       AND dwp.asn IS NOT NULL
       AND dwp.asn = i.asn
    `,
    [tenantId],
  );
}

/**
 * Re-join every live incident's ASN to the devices that have a FRESH `away`
 * event for it.
 *
 * WHY THIS IS A STEP OF ITS OWN, RUN BEFORE THE EVALUATION.
 *
 * Membership is STATE, and the evaluation reads it. An earlier shape of this
 * file only added members as a side effect of the `open` and `grow` actions,
 * which produced a hole with teeth: a site that recovered and then failed over
 * again while its incident was already open produced neither action — `open` is
 * suppressed because the incident is live, `grow` only fires when the count
 * exceeds the previous peak — so the relapse was never recorded, the incident
 * kept clearing on a recovery that had stopped being true, and it closed in the
 * middle of the outage.
 *
 * Bringing the membership up to date FIRST means the evaluation always reasons
 * about the fleet as it is now, and the actions are consequences rather than
 * the mechanism.
 */
async function syncLiveMembers(tenantId: number, windowMinutes: number): Promise<void> {
  const live = await db('operator_incidents')
    .where({ tenant_id: tenantId })
    .whereNot('status', 'closed')
    .select<Array<{ id: string; asn: string }>>('id', 'asn');

  for (const incident of live) {
    const seeds = await seedsForAsn(tenantId, Number(incident.asn), windowMinutes);
    await joinMembers(tenantId, Number(incident.id), seeds);
  }
}

async function loadOpenIncidents(tenantId: number): Promise<OpenIncidentState[]> {
  const { rows } = (await db.raw(
    `
    SELECT i.id, i.asn, i.status, i.clearing_since, i.peak_site_count,
           COALESCE(
             ARRAY_AGG(DISTINCT ${MEMBER_LINE_KEY_SQL})
               FILTER (WHERE m.recovered_at IS NULL),
             '{}'::text[]
           ) AS still
      FROM operator_incidents i
      LEFT JOIN operator_incident_members m
        ON m.incident_id = i.id AND m.tenant_id = i.tenant_id
     WHERE i.tenant_id = ? AND i.status <> 'closed'
     GROUP BY i.id
    `,
    [tenantId],
  )) as {
    rows: Array<{
      id: string;
      asn: string;
      status: 'open' | 'clearing';
      clearing_since: Date | null;
      peak_site_count: number;
      still: string[];
    }>;
  };

  return rows.map((r) => ({
    incidentId: Number(r.id),
    asn: Number(r.asn),
    status: r.status,
    clearingSince: r.clearing_since ? new Date(r.clearing_since).toISOString() : null,
    stillAffectedSiteKeys: r.still ?? [],
    peakSiteCount: r.peak_site_count,
  }));
}

// ============================================================================
// 3. Applying the decisions
// ============================================================================

interface MemberSeed {
  deviceId: number;
  siteId: number | null;
  /** Resolved from the event that seeded it, and STORED on the member row —
   *  a vote must not change identity because a device was re-addressed while
   *  the incident it belongs to was still open. */
  lineKey: string;
  eventId: number;
  fromPathKind: WanPathKind;
  toPathKind: WanPathKind;
}

/**
 * The devices that produced an `away` from this ASN inside the window, one row
 * per device, carrying its MOST RECENT such event.
 *
 * Most recent, not earliest, and it is not a detail: this row is compared with
 * `operator_incident_members.event_id` to decide whether a member that had
 * recovered has just relapsed. Handing back the earliest event would compare a
 * member against evidence it was already joined on, so a relapse inside the
 * correlation window would look identical to the same failover seen twice — and
 * the incident would go on clearing through an outage that had resumed.
 */
async function seedsForAsn(
  tenantId: number,
  asn: number,
  windowMinutes: number,
): Promise<MemberSeed[]> {
  const { rows } = (await db.raw(
    `
    SELECT DISTINCT ON (e.device_id)
           e.device_id, e.site_id, e.id AS event_id, e.from_path_kind, e.to_path_kind,
           ${LINE_KEY_SQL('e')} AS line_key
      FROM wan_path_events e
     WHERE e.tenant_id = ?
       AND e.from_asn = ?
       AND e.direction = 'away'
       AND e.at >= now() - (? * INTERVAL '1 minute')
     ORDER BY e.device_id, e.at DESC, e.id DESC
    `,
    [tenantId, asn, windowMinutes],
  )) as {
    rows: Array<{
      device_id: number;
      site_id: number | null;
      event_id: string;
      line_key: string;
      from_path_kind: WanPathKind;
      to_path_kind: WanPathKind;
    }>;
  };

  return rows.map((r) => ({
    deviceId: r.device_id,
    siteId: r.site_id,
    lineKey: r.line_key,
    eventId: Number(r.event_id),
    fromPathKind: r.from_path_kind,
    toPathKind: r.to_path_kind,
  }));
}

/**
 * Add members, or refresh the ones already in.
 *
 * ONE ROW PER DEVICE PER INCIDENT — the unique index says so, and it has to,
 * because the row count IS the site count that decides whether the incident is
 * still live. Inserting a second row for a device seen twice would keep an
 * incident open on the strength of one site counted repeatedly.
 *
 * THE RELAPSE RULE. `recovered_at` is cleared only when the incoming evidence
 * is STRICTLY NEWER than the evidence already stored. Both mistakes are real:
 *   - never clearing it means a site that failed over, recovered and failed
 *     over again is counted as recovered while it is down;
 *   - always clearing it means a member can never retire, because the sweep
 *     re-presents the same `away` event for as long as it sits in the window,
 *     and the incident never closes.
 */
async function joinMembers(
  tenantId: number,
  incidentId: number,
  seeds: readonly MemberSeed[],
): Promise<void> {
  for (const seed of seeds) {
    await db.raw(
      `
      INSERT INTO operator_incident_members
        (tenant_id, incident_id, device_id, site_id, line_key, event_id,
         from_path_kind, to_path_kind, joined_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, now())
      ON CONFLICT (tenant_id, incident_id, device_id) DO UPDATE
         SET to_path_kind = EXCLUDED.to_path_kind,
             -- The line is refreshed with the evidence, never cleared: a later
             -- event that cannot name a line must not silently promote the
             -- device back to a vote of its own.
             line_key = COALESCE(EXCLUDED.line_key, operator_incident_members.line_key),
             recovered_at = CASE
               WHEN EXCLUDED.event_id IS NOT NULL
                AND EXCLUDED.event_id > COALESCE(operator_incident_members.event_id, 0)
                 THEN NULL
               ELSE operator_incident_members.recovered_at
             END,
             event_id = GREATEST(
               COALESCE(operator_incident_members.event_id, 0),
               COALESCE(EXCLUDED.event_id, 0)
             )
      `,
      [
        tenantId,
        incidentId,
        seed.deviceId,
        seed.siteId,
        seed.lineKey,
        seed.eventId,
        seed.fromPathKind,
        seed.toPathKind,
      ],
    );
  }
}

/** Recompute the two counters from the members. Never incremented by hand:
 *  a counter maintained by arithmetic on the side is a counter that drifts. */
async function refreshCounters(tenantId: number, incidentId: number): Promise<number> {
  const { rows } = (await db.raw(
    `
    UPDATE operator_incidents i
       SET current_site_count = c.live,
           peak_site_count    = GREATEST(i.peak_site_count, c.total),
           updated_at         = now()
      FROM (
        SELECT COUNT(DISTINCT ${MEMBER_LINE_KEY_SQL})
                 FILTER (WHERE m.recovered_at IS NULL) AS live,
               COUNT(DISTINCT ${MEMBER_LINE_KEY_SQL}) AS total
          FROM operator_incident_members m
         WHERE m.tenant_id = ? AND m.incident_id = ?
      ) c
     WHERE i.id = ? AND i.tenant_id = ?
     RETURNING i.current_site_count
    `,
    [tenantId, incidentId, incidentId, tenantId],
  )) as { rows: Array<{ current_site_count: number }> };
  return rows[0]?.current_site_count ?? 0;
}

export interface ScanOutcome {
  tenantId: number;
  enabled: boolean;
  policy: WeatherPolicy;
  ingested: number;
  evaluation: WeatherEvaluation;
  opened: number[];
  closed: number[];
  clearing: number[];
  resumed: number[];
}

/** How far back "nominal carrier" membership is remembered for the denominator. */
export const NOMINAL_HORIZON_DAYS = 7;

/**
 * ONE SWEEP. Ingest, refresh, evaluate, apply, emit.
 *
 * Idempotent end to end: the ingestion is keyed on the session, the membership
 * is keyed on (incident, device), the counters are recomputed rather than
 * incremented, and opening races on a partial unique index. Running it twice in
 * a row changes nothing — which is what makes it safe to expose on a route AND
 * to run on a timer.
 */
export async function runWeatherScan(
  tenantId: number,
  opts: { skipIngest?: boolean; lookbackMinutes?: number } = {},
): Promise<ScanOutcome> {
  const { policy, enabled } = await getTenantPolicy(tenantId);

  let ingested = 0;
  if (!opts.skipIngest) {
    // The order matters: attributions first, so a transition detected in the
    // same sweep is evaluated against a fresh `device_wan_path`, and the
    // membership refresh below can see a device that is already back.
    await refreshObservedPaths(tenantId);
    const outcome = await ingestPathEvents(tenantId, { lookbackMinutes: opts.lookbackMinutes });
    ingested = outcome.inserted;
  }

  // Membership first, evaluation second. Retire what is demonstrably back, then
  // re-join what has just left again — see `syncLiveMembers` for the bug this
  // ordering exists to close.
  await refreshMembership(tenantId);
  await syncLiveMembers(tenantId, policy.windowMinutes);

  const [candidates, attributedSiteCount, openIncidents] = await Promise.all([
    loadCandidates(tenantId, policy.windowMinutes, NOMINAL_HORIZON_DAYS),
    loadAttributedSiteCount(tenantId),
    loadOpenIncidents(tenantId),
  ]);

  const evaluation = evaluateOperatorWeather({
    now: new Date().toISOString(),
    policy,
    attributedSiteCount,
    candidates,
    openIncidents,
  });

  const opened: number[] = [];
  const closed: number[] = [];
  const clearing: number[] = [];
  const resumed: number[] = [];

  for (const action of evaluation.actions) {
    switch (action.kind) {
      case 'open': {
        if (!enabled) {
          logger.info(
            { tenantId, asn: action.asn, reason: action.reason },
            'F5 quorum reached but operator weather is disabled for this tenant; no incident opened',
          );
          break;
        }
        const seeds = await seedsForAsn(tenantId, action.asn, policy.windowMinutes);
        // ON CONFLICT on the LIVE partial unique index. Two schedulers racing
        // (a timer and an operator hitting the route) produce one incident, and
        // the loser gets zero rows back and simply joins the members below.
        const { rows } = (await db.raw(
          `
          INSERT INTO operator_incidents
            (tenant_id, asn, as_org, status, opened_at, current_site_count,
             peak_site_count, fleet_site_count, policy, open_reason)
          VALUES (?, ?, ?, 'open', now(), 0, 0, ?, ?::jsonb, ?)
          ON CONFLICT (tenant_id, asn) WHERE status <> 'closed' DO NOTHING
          RETURNING id
          `,
          [
            tenantId,
            action.asn,
            action.asOrg,
            action.fleetSiteCount,
            JSON.stringify(policy),
            action.reason.slice(0, 160),
          ],
        )) as { rows: Array<{ id: string }> };

        let incidentId: number;
        if (rows[0]) {
          incidentId = Number(rows[0].id);
        } else {
          // The insert lost a race on the live partial unique index. The winner
          // is the incident; join it rather than inventing a second one.
          const existing = await db('operator_incidents')
            .where({ tenant_id: tenantId, asn: action.asn })
            .whereNot('status', 'closed')
            .first<{ id: string } | undefined>('id');
          if (!existing) break;
          incidentId = Number(existing.id);
        }

        await joinMembers(tenantId, incidentId, seeds);
        const live = await refreshCounters(tenantId, incidentId);
        if (rows[0]) {
          opened.push(incidentId);
          logger.warn(
            {
              tenantId, incidentId, asn: action.asn, asOrg: action.asOrg,
              sites: action.siteKeys.length, fleetSiteCount: action.fleetSiteCount,
              reason: action.reason,
            },
            'OPERATOR INCIDENT opened — a quorum of sites left the same ASN inside the window',
          );
          emitToTenant(tenantId, WEATHER_SOCKET_EVENTS.OPERATOR_INCIDENT_OPENED, {
            incidentId, asn: action.asn, asOrg: action.asOrg,
            siteCount: live, fleetSiteCount: action.fleetSiteCount, reason: action.reason,
          });
        }
        break;
      }

      case 'grow': {
        // The members are already in — `syncLiveMembers` put them there before
        // the evaluation ran. This action only publishes the fact.
        const live = await refreshCounters(tenantId, action.incidentId);
        emitToTenant(tenantId, WEATHER_SOCKET_EVENTS.OPERATOR_INCIDENT_GREW, {
          incidentId: action.incidentId, asn: action.asn, siteCount: live,
        });
        break;
      }

      case 'start_clearing': {
        // THE ROW COUNT IS THE GATE. The notification and the log line are
        // announcements of a STATE TRANSITION, so they fire only when a
        // transition actually occurred — `open` -> `clearing`, once. An UPDATE
        // that matches nothing means the incident was already clearing, and
        // saying so again is the second of the six notifications decision 5 of
        // the shared contract exists to prevent.
        const transitioned = await db('operator_incidents')
          .where({ id: action.incidentId, tenant_id: tenantId })
          .andWhere('status', 'open')
          .update({ status: 'clearing', clearing_since: db.fn.now(), updated_at: db.fn.now() });
        if (transitioned === 0) break;

        clearing.push(action.incidentId);
        logger.info(
          { tenantId, incidentId: action.incidentId, asn: action.asn, reason: action.reason },
          'Operator incident is recovering; the hold-down has started — it is NOT closed yet',
        );
        emitToTenant(tenantId, WEATHER_SOCKET_EVENTS.OPERATOR_INCIDENT_CLEARING, {
          incidentId: action.incidentId, asn: action.asn,
          remaining: action.remaining, holdDownMinutes: policy.holdDownMinutes,
        });
        break;
      }

      case 'extend_hold_down': {
        // Recovery stopped holding without reaching the re-opening quorum. The
        // status does not move and nothing is emitted; only the clock restarts,
        // because closing means "recovery held for holdDownMinutes" and it did
        // not. Letting the old timestamp stand would close the incident on the
        // strength of a hold-down that was interrupted.
        await db('operator_incidents')
          .where({ id: action.incidentId, tenant_id: tenantId })
          .andWhere('status', 'clearing')
          .update({ clearing_since: db.fn.now(), updated_at: db.fn.now() });
        break;
      }

      case 'resume': {
        // The relapse resets `clearing_since` to NULL: an incident that came
        // back has not been recovering for the last twenty minutes, and letting
        // the old timestamp stand would close it early on the next sweep.
        await db('operator_incidents')
          .where({ id: action.incidentId, tenant_id: tenantId })
          .andWhere('status', 'clearing')
          .update({ status: 'open', clearing_since: null, updated_at: db.fn.now() });
        resumed.push(action.incidentId);
        break;
      }

      case 'close': {
        await db('operator_incidents')
          .where({ id: action.incidentId, tenant_id: tenantId })
          .andWhere('status', 'clearing')
          .update({
            status: 'closed',
            closed_at: db.fn.now(),
            clearing_since: null,
            close_reason: action.reason.slice(0, 160),
            updated_at: db.fn.now(),
          });
        closed.push(action.incidentId);
        logger.info(
          { tenantId, incidentId: action.incidentId, asn: action.asn, reason: action.reason },
          'Operator incident closed after a sustained hold-down',
        );
        emitToTenant(tenantId, WEATHER_SOCKET_EVENTS.OPERATOR_INCIDENT_CLOSED, {
          incidentId: action.incidentId, asn: action.asn, reason: action.reason,
        });
        break;
      }
    }
  }

  // Counters for every live incident, including the ones no action touched:
  // members retire through `refreshMembership` without producing an action, and
  // a stale `current_site_count` is what the clearing decision reads next time.
  for (const incident of openIncidents) {
    if (!opened.includes(incident.incidentId)) {
      await refreshCounters(tenantId, incident.incidentId);
    }
  }

  return { tenantId, enabled, policy, ingested, evaluation, opened, closed, clearing, resumed };
}

// ============================================================================
// 4. Read models
// ============================================================================

interface IncidentRow {
  id: string;
  asn: string;
  as_org: string | null;
  status: OperatorIncidentStatus;
  opened_at: Date;
  clearing_since: Date | null;
  closed_at: Date | null;
  current_site_count: number;
  peak_site_count: number;
  fleet_site_count: number;
  open_reason: string | null;
  close_reason: string | null;
  policy?: unknown;
}

function toSummary(row: IncidentRow): OperatorIncidentSummary {
  return {
    id: Number(row.id),
    asn: Number(row.asn),
    asOrg: row.as_org,
    status: row.status,
    openedAt: new Date(row.opened_at).toISOString(),
    clearingSince: row.clearing_since ? new Date(row.clearing_since).toISOString() : null,
    closedAt: row.closed_at ? new Date(row.closed_at).toISOString() : null,
    currentSiteCount: row.current_site_count,
    peakSiteCount: row.peak_site_count,
    fleetSiteCount: row.fleet_site_count,
    openReason: row.open_reason,
    closeReason: row.close_reason,
  };
}

export async function listIncidents(
  tenantId: number,
  opts: { status?: OperatorIncidentStatus; limit?: number } = {},
): Promise<OperatorIncidentSummary[]> {
  let q = db('operator_incidents')
    .where({ tenant_id: tenantId })
    .orderBy('opened_at', 'desc')
    .limit(Math.min(Math.max(opts.limit ?? 100, 1), 500));
  if (opts.status) q = q.andWhere('status', opts.status);
  const rows = await q.select<IncidentRow[]>('*');
  return rows.map(toSummary);
}

/** One incident with its members. A row of another tenant simply is not found —
 *  the caller gets the same answer as for an id that never existed. */
export async function getIncident(
  tenantId: number,
  incidentId: number,
): Promise<OperatorIncidentDetail | null> {
  const row = await db('operator_incidents')
    .where({ id: incidentId, tenant_id: tenantId })
    .first<IncidentRow | undefined>('*');
  if (!row) return null;

  const members = await db('operator_incident_members as m')
    .join('devices as d', function joinDevice(this: any) {
      this.on('d.id', '=', 'm.device_id').andOn('d.tenant_id', '=', 'm.tenant_id');
    })
    .leftJoin('sites as s', 's.id', 'm.site_id')
    .where('m.tenant_id', tenantId)
    .andWhere('m.incident_id', incidentId)
    .orderBy('m.joined_at', 'asc')
    .select<
      Array<{
        device_id: number;
        site_id: number | null;
        name: string;
        site_name: string | null;
        joined_at: Date;
        recovered_at: Date | null;
        from_path_kind: WanPathKind;
        to_path_kind: WanPathKind;
      }>
    >(
      'm.device_id', 'm.site_id', 'd.name', 's.name as site_name',
      'm.joined_at', 'm.recovered_at', 'm.from_path_kind', 'm.to_path_kind',
    );

  return {
    ...toSummary(row),
    // Frozen at open time. Re-validated on the way out: a hand-edited jsonb
    // must not reach the UI as a policy the product claims to have applied.
    policy: normalizeWeatherPolicy(row.policy ?? null),
    members: members.map((m) => ({
      deviceId: m.device_id,
      siteId: m.site_id,
      deviceName: m.name,
      siteName: m.site_name,
      joinedAt: new Date(m.joined_at).toISOString(),
      recoveredAt: m.recovered_at ? new Date(m.recovered_at).toISOString() : null,
      fromPathKind: m.from_path_kind,
      toPathKind: m.to_path_kind,
    })),
  };
}

/**
 * The weather map: what every carrier looks like right now, INCLUDING the ones
 * that did not reach quorum.
 *
 * Showing the near-misses is not a nicety. An operator who only ever sees
 * incidents has no way to tell "nothing is happening" from "three sites moved
 * and the quorum is five", and the second is the number that decides whether
 * the quorum is tuned right.
 */
export async function getWeatherReport(tenantId: number): Promise<WeatherReport> {
  const { policy } = await getTenantPolicy(tenantId);
  const [candidates, attributedSiteCount, openIncidents, incidents, coverage] =
    await Promise.all([
      loadCandidates(tenantId, policy.windowMinutes, NOMINAL_HORIZON_DAYS),
      loadAttributedSiteCount(tenantId),
      loadOpenIncidents(tenantId),
      listIncidents(tenantId, { limit: 50 }),
      loadSiteCoverage(tenantId),
    ]);

  const evaluation = evaluateOperatorWeather({
    now: new Date().toISOString(),
    policy,
    attributedSiteCount,
    candidates,
    openIncidents,
  });

  return {
    generatedAt: new Date().toISOString(),
    policy,
    fleetWide: evaluation.fleetWide,
    fleetWideReason: evaluation.fleetWideReason,
    attributedSiteCount,
    // Spread, so the contract and the query cannot drift apart one field at a
    // time: adding a coverage number in one place makes the other fail to
    // compile instead of silently serving a zero.
    ...coverage,
    asns: evaluation.asns,
    incidents,
  };
}

/** Exposed so the API can show the threshold next to the count: a number of
 *  affected sites means nothing without the number it has to fall below. */
export function clearingThresholdFor(policy: WeatherPolicy): number {
  return clearThreshold(policy);
}

/** The OTHER edge, and it has to travel with the first one. Showing only the
 *  clearing threshold now under-describes the rule: an incident falls into
 *  `clearing` below `clearingThresholdFor` and comes back out only at or above
 *  this, and an operator reading one number without the other would predict
 *  the wrong behaviour on every count between them. See `resumeThreshold`. */
export function resumeThresholdFor(policy: WeatherPolicy): number {
  return resumeThreshold(policy);
}
