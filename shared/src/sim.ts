// ============================================================================
// @obliwan/shared — mobile data lines (SIM fleet) contract
// ============================================================================
//
// ObliWAN manages routers. A growing share of those routers reach the internet
// through a SIM — as a primary uplink on a site with no copper, or as the LTE
// backup that F5 / `uplink.service` already reports on. The line behind that
// SIM is bought from a mobile partner, it carries a data allowance, and when
// the allowance runs out the site goes dark in a way no amount of router
// supervision can see coming.
//
// This file is the vocabulary shared by the server and the client for that
// fleet of lines. It holds NO transport, no credential and no SQL.
//
// ┌─ FIVE DECISIONS ENCODED HERE, NOT DOCUMENTED ELSEWHERE ───────────────────┐
// │                                                                          │
// │ 1. EVERY DATA QUANTITY IS AN INTEGER NUMBER OF MEGABYTES.                 │
// │    The partner portals speak in "Go" as a decimal string. Floats are how  │
// │    a threshold comparison becomes non-deterministic: 0.1 + 0.2 is not     │
// │    0.3, and a line sitting exactly on its threshold would then flip       │
// │    between "low" and "ok" depending on which zone was summed first. The   │
// │    conversion factor (1 Go = 1024 Mo, `MB_PER_GB`) is a DISPLAY           │
// │    convention and nothing else: the remaining amount and the threshold    │
// │    are stored in the same unit, so the comparison that decides whether    │
// │    money gets spent is exact whatever the factor is.                      │
// │                                                                          │
// │ 2. AN ABSENT VALUE IS `null`, AND `null` IS NEVER `0`.                    │
// │    THIS IS THE MOST IMPORTANT LINE IN THE FILE. The prototype this        │
// │    feature comes from read the partner API with                           │
// │    `(float) ($row['restValueGo'] ?? 0)` — so a renamed field, a partial   │
// │    response or a line the API does not know about became "0 Go left",     │
// │    which is precisely the input that triggers a recharge. A missing       │
// │    reading must produce `unknown`, and `unknown` must never spend money.  │
// │    `evaluateBalance` is the one place that rule is written, and it is     │
// │    pure so that it can be tested without a partner account.               │
// │                                                                          │
// │ 3. A PLATFORM DECLARES WHAT IT CAN DO, AS DATA.                           │
// │    `SIM_PLATFORM_CATALOG` says, per partner, whether reading is           │
// │    implemented and whether recharging is implemented — the same shape as  │
// │    `ACS_BRAND_COVERAGE`, for the same reason. A screen that lets an       │
// │    operator believe ObliWAN is watching a line it cannot read is the      │
// │    failure mode of this feature, and prose in a README does not prevent   │
// │    it. The UI reads this array.                                           │
// │                                                                          │
// │ 4. A RECHARGE IS A STATE MACHINE WITH AN EXPLICIT TRANSITION TABLE.       │
// │    Recharging spends real money and cannot be undone. `executed` (an      │
// │    adapter called the partner API) and `recorded` (a human did it on the  │
// │    portal and said so) are DELIBERATELY DISTINCT terminal states, because │
// │    a billing report that cannot tell them apart cannot be audited.        │
// │                                                                          │
// │ 5. ONE PROPOSAL PER LOW EPISODE, ENFORCED BY A KEY.                       │
// │    A line that is below its threshold is below it on every poll. Without  │
// │    an episode key, a four-hourly sweep proposes six recharges a day for   │
// │    the same line, and an automated future would BUY six. The key is       │
// │    `sim:zone:low_since` — it changes only when the line climbs back above │
// │    the threshold and falls again, which is the definition of a new        │
// │    episode. See `rechargeIdempotencyKey`.                                 │
// └───────────────────────────────────────────────────────────────────────────┘

import { z } from 'zod';

// ============================================================================
// Units
// ============================================================================

/**
 * Megabytes per gigabyte, for DISPLAY and for parsing partner payloads.
 *
 * 1024 rather than 1000 is a convention, not a claim about what the carrier
 * bills. It is stated once, applied on both sides of every comparison, and
 * therefore cancels: a line with `restMb <= thresholdMb` is low under either
 * factor, as long as nobody converts one side and not the other. Do not
 * "fix" this to 1000 without converting every stored threshold in the same
 * migration — that would silently move every operator's alert point by 2.4%.
 */
export const MB_PER_GB = 1024;

/**
 * Partner "Go" (may arrive as a string) → integer MB. Absent stays absent.
 *
 * ┌─ THE TRIM IS THE WHOLE FUNCTION ────────────────────────────────────────┐
 * │ `Number(' ')` is `0`, not `NaN` — every JavaScript WhiteSpace string     │
 * │ coerces to zero. The first draft tested `gb === ''` and therefore turned │
 * │ a padded or blanked partner field into "0 Go remaining", which           │
 * │ `evaluateBalance` reads as `low`. Because a field's spelling is uniform  │
 * │ across one partner response, that fires on EVERY line of the account at  │
 * │ once: the exact fleet-wide false emergency decision 2 exists to prevent, │
 * │ reintroduced by three missing characters.                                │
 * │                                                                         │
 * │ `f9-rules.verify.ts` asserts ' ', '\t' and '\n' alongside '' for this    │
 * │ reason. A real `0` from the partner still survives as `0`: a line the    │
 * │ partner says is empty really is empty, and that is not the same fact.    │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
export function gbToMb(gb: number | string | null | undefined): number | null {
  if (gb === null || gb === undefined) return null;
  if (typeof gb !== 'number') {
    const trimmed = String(gb).trim();
    if (trimmed === '') return null;
    const n = Number(trimmed.replace(',', '.'));
    return Number.isFinite(n) && n >= 0 ? Math.round(n * MB_PER_GB) : null;
  }
  return Number.isFinite(gb) && gb >= 0 ? Math.round(gb * MB_PER_GB) : null;
}

/** Integer MB → Go, for display only. Absent stays absent. */
export function mbToGb(mb: number | null | undefined): number | null {
  if (mb === null || mb === undefined) return null;
  return mb / MB_PER_GB;
}

/** "12.4 Go" / "820 Mo" / "—" for an absent reading. Never renders 0 for null. */
export function formatData(mb: number | null | undefined): string {
  if (mb === null || mb === undefined) return '—';
  if (mb < MB_PER_GB) return `${Math.round(mb)} Mo`;
  return `${(mb / MB_PER_GB).toFixed(mb < 10 * MB_PER_GB ? 2 : 1)} Go`;
}

// ============================================================================
// Platforms
// ============================================================================

export const SIM_PLATFORMS = ['phenix', 'cfast'] as const;
export type SimPlatform = (typeof SIM_PLATFORMS)[number];

/**
 * How a platform's data reaches ObliWAN.
 *
 * `pull`  we poll the partner's API on a timer. Phenix, and — on CFAST's own
 *         published documentation — CFAST too.
 * `push`  the partner calls us. CFAST's portal does ship "Connexions
 *         partenaires → Webhooks", and this file once read that menu as the
 *         shape to expect there. It was wrong, and the correction is worth
 *         keeping written down: CFAST publishes its event catalogue, and that
 *         catalogue carries entity CRUD, order status and billing events — no
 *         consumption, quota or threshold event of any kind. A webhook there
 *         can say a line was re-provisioned; it can never say a line is low on
 *         data, which is the only thing F9 needs. The kind stays in the
 *         vocabulary because it is a real integration shape. No connector
 *         declares it today.
 * `file`  an operator uploads an export from the portal. Declared by no
 *         connector and served by no importer. It is named because a partner
 *         with no usable API is the case it would exist for — not because
 *         anything implements it.
 */
export type SimIngestionKind = 'pull' | 'push' | 'file';

export interface SimPlatformInfo {
  platform: SimPlatform;
  label: string;
  ingestion: readonly SimIngestionKind[];
  /** Can ObliWAN READ this partner's inventory and balances today? */
  readImplemented: boolean;
  /**
   * Can ObliWAN EXECUTE a recharge on this partner today?
   *
   * `false` everywhere as of this writing, and that is not an oversight — see
   * `SIM_RECHARGE_ADAPTERS` on the server. No partner endpoint for buying a
   * top-up has been confirmed against a real account, and a product that
   * claims it can spend money and then cannot is worse than one that says it
   * proposes and lets a human buy.
   */
  rechargeImplemented: boolean;
  /** Shown verbatim in the UI next to the platform. Say what is missing. */
  note: string;
}

export const SIM_PLATFORM_CATALOG: readonly SimPlatformInfo[] = [
  {
    platform: 'phenix',
    label: 'Phenix Partner',
    // `file` is NOT listed, and that is the honest state: no importer exists.
    // Declaring an ingestion kind the product cannot perform is the same lie
    // this catalogue exists to prevent, one level down — see the note on
    // `SimIngestionKind`.
    ingestion: ['pull'],
    readImplemented: true,
    rechargeImplemented: false,
    note:
      'Inventory and per-zone balances are read from the partner API. No top-up ' +
      'endpoint is known, so a recharge is proposed here and bought on the portal.',
  },
  {
    platform: 'cfast',
    label: 'CFAST',
    // `pull`, corrected from `push` against CFAST's own public developer
    // portal, which documents an OAuth2 REST API and an event catalogue with
    // no consumption event in it.
    //
    // Stating the partner's real shape does NOT arm the sweep: `isPollable` on
    // the server requires `readImplemented` as well, and it is false below. The
    // two fields answer different questions — what the partner offers, and
    // what ObliWAN has built — and conflating them is what made the first
    // draft encode a guess as a capability.
    ingestion: ['pull'],
    readImplemented: false,
    rechargeImplemented: false,
    // Rendered verbatim in the UI, so it must not offer an escape hatch the
    // product does not have: there is no importer for any partner.
    note:
      'Not implemented. CFAST documents a polled REST API publicly, but no ' +
      'endpoint returning the data REMAINING on a line has been found there, ' +
      'and no account has been read. An account can be created and hold ' +
      'assignments; nothing reads balances for it yet.',
  },
];

const PLATFORM_BY_KEY = new Map<string, SimPlatformInfo>(
  SIM_PLATFORM_CATALOG.map((p) => [p.platform, p]),
);

export function isSimPlatform(value: unknown): value is SimPlatform {
  return typeof value === 'string' && PLATFORM_BY_KEY.has(value);
}

export function simPlatformInfo(platform: SimPlatform): SimPlatformInfo {
  const info = PLATFORM_BY_KEY.get(platform);
  // A platform in the CHECK constraint but not in the catalogue would render as
  // a blank row with no capability flags, which is exactly the silent lie
  // decision 3 exists to prevent. Fail where it can be seen.
  if (!info) throw new Error(`SIM_PLATFORM_CATALOG is missing the platform: ${platform}`);
  return info;
}

// ============================================================================
// Accounts
// ============================================================================

/**
 * How the connector authenticates, and why the distinction is load-bearing.
 *
 * `password`  username + password, exchanged for a token on every sweep. Works
 *             ONLY for a partner account that does not enforce a one-time code.
 * `token`     a bearer token supplied by an operator, stored in the vault and
 *             replayed. This is the ONLY mode that survives an account with OTP
 *             enabled: the partner's `authenticateWithCodeConfirmation` needs a
 *             code from a human, and an unattended sweep has no human. The
 *             token carries an expiry, ObliWAN reads it and warns BEFORE it
 *             dies, because the failure mode otherwise is a fleet that silently
 *             stops being watched at the exact moment an allowance runs out.
 */
export const SIM_AUTH_MODES = ['password', 'token'] as const;
export type SimAuthMode = (typeof SIM_AUTH_MODES)[number];

export const SIM_ACCOUNT_STATUSES = ['active', 'disabled', 'auth_failed'] as const;
export type SimAccountStatus = (typeof SIM_ACCOUNT_STATUSES)[number];

export interface SimAccount {
  id: number;
  platform: SimPlatform;
  name: string;
  baseUrl: string | null;
  /** Phenix `partenaireId`. Decoded from the JWT when the token carries it. */
  partnerRef: string | null;
  authMode: SimAuthMode;
  /**
   * Whether a credential is stored — NEVER the credential.
   * §8.2: no endpoint on this feature returns vault material in clear.
   */
  hasCredential: boolean;
  tokenExpiresAt: string | null;
  status: SimAccountStatus;
  /** Operators whose lines this account must not poll. Phenix SFR lines use a
   *  different consumption path and answer nothing useful on the normal one —
   *  the prototype skipped them and so does this. */
  skipOperators: string[];
  /** Hard ceilings for the day an execution adapter exists. Null = no ceiling
   *  configured, which `assertRechargeAllowed` treats as REFUSE, not as
   *  unlimited. */
  monthlyRechargeCap: number | null;
  monthlyCostCapCents: number | null;
  lastSyncAt: string | null;
  lastSyncError: string | null;
  lastSyncLineCount: number | null;
  createdAt: string;
  updatedAt: string;
}

// ============================================================================
// Lines
// ============================================================================

export const SIM_LINE_STATUSES = ['active', 'suspended', 'unknown'] as const;
export type SimLineStatus = (typeof SIM_LINE_STATUSES)[number];

export interface SimLine {
  id: number;
  accountId: number;
  platform: SimPlatform;
  accountName: string;
  /** Null = in the unassigned pool. A line nobody has claimed yet is a real
   *  state and is shown as such, never hidden and never attributed by guess. */
  tenantId: number | null;
  msisdn: string;
  /**
   * The SIM serial. NULLABLE, and empty today on Phenix: the partner API
   * returns `msisdn`, `operateur` and `codeClient` and no ICCID at all.
   *
   * This column is the seam for correlating a line with the router that holds
   * it once the fleet is enrolled in the ACS — TR-069 exposes the SIM serial on
   * a cellular CPE. Until something fills it, correlation is done by hand
   * through `deviceId`, and an empty ICCID is reported as unknown rather than
   * matched against another empty one.
   */
  iccid: string | null;
  operator: string | null;
  clientCode: string | null;
  label: string | null;
  siteId: number | null;
  siteName: string | null;
  /** The router this line feeds, when known. Set by hand today. */
  deviceId: number | null;
  deviceName: string | null;
  status: SimLineStatus;
  /** Per-line override of the global low-data threshold, in MB. */
  lowThresholdMb: number | null;
  /** Opt-in, per line. Off by default: nothing proposes to spend money on a
   *  line nobody has said should be topped up automatically. */
  autoRechargeEnabled: boolean;
  /** Size of the top-up to propose, in MB. Null = "operator decides". */
  rechargePlanMb: number | null;
  firstSeenAt: string;
  lastSeenAt: string;
  zones: SimZoneBalance[];
}

// ============================================================================
// Balances
// ============================================================================

export interface SimZoneBalance {
  /** Partner zone label ("France", "Europe"...). Never empty; an unlabelled
   *  zone is stored as `UNKNOWN_ZONE` so a row is never keyed on ''. */
  zone: string;
  rechargeMb: number | null;
  usedMb: number | null;
  restMb: number | null;
  observedAt: string;
  /** When this zone first went below its threshold and stayed there. Null when
   *  it is not low. This IS the episode marker (decision 5). */
  lowSince: string | null;
}

export const UNKNOWN_ZONE = 'unknown';

/**
 * The stored form of a partner's zone label.
 *
 * ┌─ WHY THIS EXISTS RATHER THAN A BARE `.trim()` ──────────────────────────┐
 * │ `sim_balances` is keyed on `(sim_id, zone)` and each row carries its own │
 * │ `low_since`. If the partner returns "Europe" on one sweep and "Europe "  │
 * │ or "europe" on the next, that is TWO rows for one real zone, each with   │
 * │ its own episode — and therefore two idempotency keys and two proposals   │
 * │ for a single shortage, which is the outcome decision 5 exists to         │
 * │ prevent. The idempotency key already lowercases, but by then the damage  │
 * │ (two balance rows, two episodes) is done.                                │
 * │                                                                         │
 * │ So the label is canonicalised ONCE, here, on the way in: trimmed, inner  │
 * │ whitespace collapsed. Case is preserved — it is the partner's display    │
 * │ label and an operator reads it — and the case-insensitive uniqueness is  │
 * │ enforced by a functional index in migration 032.                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
export function canonicalZone(raw: string | null | undefined): string {
  const z = (raw ?? '').replace(/\s+/g, ' ').trim();
  return z === '' ? UNKNOWN_ZONE : z;
}

/**
 * The verdict vocabulary. `unknown` is a first-class answer, not an error.
 *
 * There is no fourth value on purpose: "probably low" would be a value whose
 * only possible consumer is a recharge, and a recharge on a probability is a
 * bill on a probability.
 */
export type BalanceVerdict = 'ok' | 'low' | 'unknown';

/**
 * The single place the low-data rule is written.
 *
 * Pure, total, and takes the threshold as an argument rather than reading a
 * setting — a rule that reads its own configuration cannot be tested, and this
 * project has already shipped one caller-driven parameter that flipped a
 * verdict (§11.1, motif 5).
 *
 * `restMb === null` → `unknown`. Never `low`. See decision 2.
 */
export function evaluateBalance(restMb: number | null, thresholdMb: number): BalanceVerdict {
  if (restMb === null || !Number.isFinite(restMb)) return 'unknown';
  return restMb <= thresholdMb ? 'low' : 'ok';
}

/**
 * How old a reading may be and still count as an answer.
 *
 * ┌─ `unknown` WAS A PARSE-TIME PROPERTY ONLY, AND THAT WAS THE HOLE ────────┐
 * │ Decision 2 was enforced at exactly one moment — when the connector reads │
 * │ a field. Once a value reached `sim_balances.rest_mb` it was immortal:    │
 * │ `applyBalances` only upserts the zones present in THIS response, so a    │
 * │ zone the partner stopped returning, a line whose operator was added to   │
 * │ the skip list, and an account whose token died all kept their last good  │
 * │ reading forever. `observed_at` was stored, typed and carried all the way │
 * │ to the client — and consulted by NO decision anywhere.                    │
 * │                                                                         │
 * │ So a fleet nobody had read for six weeks rendered `ok`, and              │
 * │ `fleetSummary.okLines` counted it — while the dashboard header claimed   │
 * │ "a dead token, a renamed field and a rate limit all look like nothing to │
 * │ report on a dashboard that folds unknown into ok". A dead token did not  │
 * │ produce `unknown`. It produced yesterday's good news, indefinitely.      │
 * │                                                                         │
 * │ A reading older than the horizon is treated exactly like a reading the   │
 * │ partner never gave: excluded from the comparison, and `unknown` if that  │
 * │ is all there is. Which means it also never proposes a top-up.            │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * The horizon is passed in rather than read from a clock or a setting, for the
 * same reason `evaluateBalance` takes its threshold: a rule that reads its own
 * configuration cannot be tested. Callers derive it from the sweep interval —
 * see `stalenessHorizonMs`.
 */
export interface ReadingFreshness {
  /** The instant to judge against. */
  now: number;
  /** Older than this and the reading stops being an answer. */
  maxAgeMs: number;
}

/**
 * The horizon for a given sweep interval.
 *
 * THREE missed sweeps, not one: a single missed pass is ordinary — a partner
 * blip, a restart, a leadership handover — and a horizon that tight would flip
 * a healthy fleet to `unknown` every time anything hiccuped, which is its own
 * kind of lie. Three consecutive misses is a partner that has stopped
 * answering.
 */
export function stalenessHorizonMs(syncIntervalMinutes: number): number {
  return Math.max(1, syncIntervalMinutes) * 60_000 * 3;
}

/** Is this reading too old to be treated as an answer? */
export function isReadingStale(observedAt: string, freshness: ReadingFreshness): boolean {
  const t = Date.parse(observedAt);
  // An unparseable instant is not evidence of freshness.
  if (!Number.isFinite(t)) return true;
  return freshness.now - t > freshness.maxAgeMs;
}

/**
 * The zone that decides a line's fate: the one with the least data left.
 *
 * Zones with no reading are EXCLUDED from the comparison rather than treated as
 * zero — otherwise one unreadable zone would drag every line to "low" and, in
 * an automated future, top up the whole fleet. A line whose every zone is
 * unreadable returns `null`, which its caller must report as `unknown`.
 *
 * A zone whose reading is STALE is excluded on the same footing: see
 * `ReadingFreshness`. Omitting `freshness` keeps the old age-blind behaviour
 * and is meant only for callers that have already filtered.
 */
export function worstZone(
  zones: readonly SimZoneBalance[],
  freshness?: ReadingFreshness,
): SimZoneBalance | null {
  let worst: SimZoneBalance | null = null;
  let worstRest = Number.POSITIVE_INFINITY;
  for (const z of zones) {
    if (z.restMb === null) continue;
    if (freshness && isReadingStale(z.observedAt, freshness)) continue;
    if (z.restMb < worstRest) {
      worst = z;
      worstRest = z.restMb;
    }
  }
  return worst;
}

/** A line's overall verdict, from its zones and its effective threshold. */
export function lineVerdict(
  zones: readonly SimZoneBalance[],
  thresholdMb: number,
  freshness?: ReadingFreshness,
): { verdict: BalanceVerdict; zone: SimZoneBalance | null; stale: boolean } {
  const zone = worstZone(zones, freshness);
  if (!zone) {
    // Distinguish "we never read it" from "we read it, but too long ago": both
    // are `unknown`, and only the second has an operator action attached.
    const stale =
      !!freshness &&
      zones.length > 0 &&
      zones.some((z) => z.restMb !== null && isReadingStale(z.observedAt, freshness));
    return { verdict: 'unknown', zone: null, stale };
  }
  return { verdict: evaluateBalance(zone.restMb, thresholdMb), zone, stale: false };
}

/** The threshold that applies to a line: its override, else the global default. */
export function effectiveThresholdMb(
  lineOverrideMb: number | null | undefined,
  globalDefaultMb: number,
): number {
  return lineOverrideMb === null || lineOverrideMb === undefined
    ? globalDefaultMb
    : lineOverrideMb;
}

// ============================================================================
// Recharges — the money path
// ============================================================================

export const SIM_RECHARGE_STATUSES = [
  'proposed',
  'approved',
  'executed',
  'recorded',
  'rejected',
  'failed',
  'expired',
] as const;
export type SimRechargeStatus = (typeof SIM_RECHARGE_STATUSES)[number];

/**
 * Legal transitions. Anything absent from this table is refused by
 * `assertRechargeTransition`, and the DB carries the same vocabulary as a CHECK
 * (§11.1, motif 7: a service-layer enum is not what runs when somebody updates
 * a row from psql).
 *
 * `executed` vs `recorded` — BOTH terminal, BOTH billable, DELIBERATELY NOT THE
 * SAME VALUE:
 *   executed  an adapter called the partner's API and it returned success.
 *   recorded  a human bought the top-up on the partner's portal and logged it.
 * Today every billable row is `recorded`, because no adapter exists. When one
 * lands, the report must still be able to answer "which of these did the
 * machine buy" — collapsing the two would destroy that answer permanently.
 */
export const SIM_RECHARGE_TRANSITIONS: Readonly<
  Record<SimRechargeStatus, readonly SimRechargeStatus[]>
> = {
  proposed: ['approved', 'rejected', 'expired'],
  // An approval authorises the spend; it does not perform it.
  approved: ['executed', 'recorded', 'failed'],
  // A failed execution may still turn out to have been done by hand.
  failed: ['recorded'],
  executed: [],
  recorded: [],
  rejected: [],
  expired: [],
};

export function canRechargeTransition(
  from: SimRechargeStatus,
  to: SimRechargeStatus,
): boolean {
  return SIM_RECHARGE_TRANSITIONS[from].includes(to);
}

/** Terminal = no further transition is legal. */
export function isRechargeTerminal(status: SimRechargeStatus): boolean {
  return SIM_RECHARGE_TRANSITIONS[status].length === 0;
}

/**
 * The statuses in which a top-up was actually BOUGHT.
 *
 * Exported as a constant because three SQL sites (the report, the monthly
 * summary, the cap usage) each need this list in a `whereIn`, and three
 * hand-written `['executed','recorded']` literals are three copies of a rule
 * that decides what gets invoiced. `isRechargeBillable` is the same rule for a
 * single value; both read from here so they cannot disagree.
 */
export const SIM_BILLABLE_STATUSES: readonly SimRechargeStatus[] = ['executed', 'recorded'];

/**
 * Does this row belong on the re-invoicing report?
 *
 * Only states where a top-up was actually bought. A `proposed` or `approved`
 * row has cost nobody anything yet and must never appear as a charge — the
 * whole point of the report is that an operator can hand it to accounting.
 */
export function isRechargeBillable(status: SimRechargeStatus): boolean {
  return SIM_BILLABLE_STATUSES.includes(status);
}

export const SIM_RECHARGE_TRIGGERS = ['threshold', 'manual'] as const;
export type SimRechargeTrigger = (typeof SIM_RECHARGE_TRIGGERS)[number];

export interface SimRecharge {
  id: number;
  /** Null once the line is gone. The identifying fields below are denormalised
   *  precisely so a billing record survives the deletion of its line — the same
   *  reasoning as `notification_log.channel_name`. */
  simId: number | null;
  accountId: number | null;
  platform: SimPlatform;
  tenantId: number | null;
  tenantName: string | null;
  msisdn: string;
  operator: string | null;
  siteId: number | null;
  /** Frozen at proposal time. The report groups on this, so a site rename must
   *  not rewrite last quarter's invoice lines. */
  siteName: string | null;
  deviceName: string | null;
  status: SimRechargeStatus;
  trigger: SimRechargeTrigger;
  zone: string;
  /** The evidence the proposal was based on. Frozen. */
  restMbAtProposal: number | null;
  /** The rule that fired, frozen. A later change to the global threshold must
   *  not rewrite why this proposal exists. */
  thresholdMbAtProposal: number;
  planMb: number | null;
  costCents: number | null;
  currency: string | null;
  billingReference: string | null;
  idempotencyKey: string;
  proposedAt: string;
  proposedBy: number | null;
  proposedByName: string | null;
  decidedAt: string | null;
  decidedBy: number | null;
  decidedByName: string | null;
  decisionNote: string | null;
  completedAt: string | null;
  completedBy: number | null;
  failureReason: string | null;
}

/**
 * One proposal per low episode.
 *
 * `lowSince` is the timestamp the zone crossed below its threshold and has
 * stayed below ever since; it is cleared the moment the line climbs back above.
 * So the key is stable for as long as one episode lasts and different for the
 * next one — which is exactly "do not propose twice for the same overshoot, do
 * propose again after a real recharge and a real depletion".
 *
 * The zone is normalised because 'Europe' and 'europe ' are the same zone and
 * two keys would be two proposals — and, one day, two purchases.
 */
export function rechargeIdempotencyKey(
  simId: number,
  zone: string,
  lowSince: string,
): string {
  const z = zone.trim().toLowerCase() || UNKNOWN_ZONE;
  return `${simId}:${z}:${lowSince}`;
}

// ============================================================================
// Re-invoicing report
// ============================================================================

export interface SimRechargeReportRow {
  siteId: number | null;
  siteName: string | null;
  tenantId: number | null;
  tenantName: string | null;
  /** Null once the line has been deleted. The row still bills. */
  simId: number | null;
  msisdn: string;
  platform: SimPlatform;
  operator: string | null;
  rechargeCount: number;
  totalMb: number | null;
  totalCostCents: number | null;
  currency: string | null;
  firstRechargeAt: string;
  lastRechargeAt: string;
  /** How many billable rows carry no cost. Surfaced rather than summed as zero:
   *  a report that quietly bills 0 for an unpriced top-up under-invoices
   *  without saying so. */
  unpricedCount: number;
  /**
   * How many billable rows carry no VOLUME.
   *
   * The same rule as `unpricedCount`, applied to the other partial sum. A
   * top-up recorded with the volume box left empty contributes nothing to
   * `totalMb`, so without this the screen shows "2.0 Go topped up" for a line
   * that consumed roughly twice that — and `suggestsPlanChange` compares the
   * understated figure against the allowance and fails to flag a plan that IS
   * undersized. The report's second reason for existing dies quietly.
   */
  unknownVolumeCount: number;

  // ── The two fields that turn a journal into a decision ──────────────────
  /**
   * The line's CURRENT subscribed allowance, summed across its zones.
   *
   * NOT a historical value, and the screen says so: it is read from today's
   * `sim_balances.recharge_mb`, because no partner tells us what the plan was
   * last March. That is enough for the question actually being asked — "is
   * this line's plan the right size TODAY" — and pretending it is a
   * point-in-time figure would be inventing one.
   *
   * `null` when the partner reports no plan size for any zone.
   */
  basePlanMb: number | null;
  /**
   * How many DISTINCT CALENDAR MONTHS of the window carried at least one
   * top-up.
   *
   * This is the recurrence signal, and it is the number worth acting on. A
   * site that ran out once had a bad month; a site that ran out in five months
   * out of six is on the wrong plan, and topping it up is more expensive per
   * megabyte than the allowance it should have been sold. ObliWAN does not
   * renegotiate anything — it makes the case visible.
   */
  monthsWithRecharge: number;
}

/**
 * Is this line's top-up pattern a plan problem rather than an incident?
 *
 * Pure, and deliberately conservative: TWO months is not a pattern — a holiday
 * period and a one-off migration produce two — and a rule that flags everything
 * gets ignored like any other over-eager alert.
 *
 * ┌─ BOTH BRANCHES ARE WINDOW-INDEPENDENT, AND THAT IS NOT INCIDENTAL ───────┐
 * │ The screen offers a 1 / 3 / 6 / 12-month window. A rule comparing a       │
 * │ WINDOW-CUMULATIVE top-up total against a SINGLE-MONTH allowance would    │
 * │ flag more lines the longer the window, so the "plans to review" count     │
 * │ would track the dropdown rather than the fleet — and twelve months of     │
 * │ small top-ups adding up to one month's plan is not an undersized plan.    │
 * │                                                                          │
 * │ So the volume branch is expressed PER MONTH IN WHICH A TOP-UP HAPPENED:   │
 * │ a line that, in an average such month, bought as much data as its whole   │
 * │ allowance is a line running on roughly half the plan it needs. That       │
 * │ statement means the same thing at any window length.                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Returns `false` whenever the allowance is unknown and the recurrence is low:
 * an unknown plan must never be presented as a finding.
 */
export function suggestsPlanChange(row: SimRechargeReportRow): boolean {
  if (row.monthsWithRecharge >= 3) return true;
  if (
    row.basePlanMb !== null &&
    row.basePlanMb > 0 &&
    row.totalMb !== null &&
    row.monthsWithRecharge > 0
  ) {
    return row.totalMb / row.monthsWithRecharge >= row.basePlanMb;
  }
  return false;
}

export interface SimRechargeReport {
  from: string;
  to: string;
  rows: SimRechargeReportRow[];
  totalRecharges: number;
  totalCostCents: number | null;
  unpricedCount: number;
  unknownVolumeCount: number;
  /** Distinct currencies present. More than one means the totals above are not
   *  a sum an accountant can use, and the UI must say so instead of adding
   *  euros to pounds. */
  currencies: string[];
}

// ============================================================================
// Dashboard projections
// ============================================================================

export interface SimFleetSummary {
  totalLines: number;
  assignedLines: number;
  unassignedLines: number;
  /** Counted by verdict. `unknown` is reported, never folded into `ok` — a
   *  fleet where half the lines cannot be read must not look healthy. */
  okLines: number;
  lowLines: number;
  unknownLines: number;
  /**
   * How many of `unknownLines` are unknown because their readings went STALE,
   * rather than because they were never read. A non-zero value here means the
   * sweep has stopped for those lines — a different problem, with a different
   * fix, from a line the partner has never reported a balance for.
   */
  staleLines: number;
  pendingProposals: number;
  /** Accounts that cannot authenticate right now. A non-zero value here is why
   *  `unknownLines` is non-zero, and the dashboard shows them together. */
  failedAccounts: number;
  staleAccounts: number;
  rechargesThisMonth: number;
  /**
   * `null` when nothing was priced this month OR when more than one currency
   * appears. Summing across currencies is arithmetic on incompatible units —
   * the same rule `SimRechargeReport` applies (report rule 4) — and a dashboard
   * tile that prints one number for two currencies is worse than the report,
   * because nobody scrolls to a footnote on a tile.
   */
  costThisMonthCents: number | null;
  /** Distinct currencies among this month's billable top-ups. The tile prints
   *  the single one, or refuses a total when there are several. */
  currencies: string[];
  /** Billable top-ups this month with no cost recorded yet. Counted, never
   *  added as zero. */
  unpricedThisMonth: number;
}

// ============================================================================
// Validation schemas (API boundary)
// ============================================================================

const msisdnSchema = z
  .string()
  .trim()
  .min(6)
  .max(20)
  // Digits, optional leading +. Anything else is not a number a partner can be
  // asked about, and it is also the shape that ends up in a URL query
  // (§11.1, motif 6: a value sent onward unescaped).
  .regex(/^\+?[0-9]{6,19}$/, 'MSISDN must be digits, optionally prefixed with +');

export { msisdnSchema as simMsisdnSchema };

export const simAccountInputSchema = z.object({
  platform: z.enum(SIM_PLATFORMS),
  name: z.string().trim().min(1).max(120),
  baseUrl: z.string().trim().url().max(255).nullable().optional(),
  partnerRef: z.string().trim().max(64).nullable().optional(),
  authMode: z.enum(SIM_AUTH_MODES),
  skipOperators: z.array(z.string().trim().min(1).max(60)).max(32).optional(),
  monthlyRechargeCap: z.number().int().min(0).max(100_000).nullable().optional(),
  monthlyCostCapCents: z.number().int().min(0).max(100_000_000).nullable().optional(),
});
export type SimAccountInput = z.infer<typeof simAccountInputSchema>;

export const simCredentialInputSchema = z.discriminatedUnion('authMode', [
  z.object({
    authMode: z.literal('password'),
    username: z.string().trim().min(1).max(190),
    password: z.string().min(1).max(512),
  }),
  z.object({
    authMode: z.literal('token'),
    token: z.string().trim().min(20).max(8192),
  }),
]);
export type SimCredentialInput = z.infer<typeof simCredentialInputSchema>;

export const simLineUpdateSchema = z.object({
  tenantId: z.number().int().positive().nullable().optional(),
  siteId: z.number().int().positive().nullable().optional(),
  deviceId: z.number().int().positive().nullable().optional(),
  iccid: z
    .string()
    .trim()
    .regex(/^[0-9]{18,22}$/, 'ICCID must be 18 to 22 digits')
    .nullable()
    .optional(),
  label: z.string().trim().max(190).nullable().optional(),
  lowThresholdMb: z.number().int().min(0).max(10_000_000).nullable().optional(),
  autoRechargeEnabled: z.boolean().optional(),
  rechargePlanMb: z.number().int().min(1).max(10_000_000).nullable().optional(),
});
export type SimLineUpdate = z.infer<typeof simLineUpdateSchema>;

export const simManualRechargeSchema = z.object({
  simId: z.number().int().positive(),
  zone: z.string().trim().min(1).max(80),
  planMb: z.number().int().min(1).max(10_000_000).nullable().optional(),
  note: z.string().trim().max(2000).nullable().optional(),
});
export type SimManualRechargeInput = z.infer<typeof simManualRechargeSchema>;

export const simRechargeDecisionSchema = z.object({
  note: z.string().trim().max(2000).nullable().optional(),
});

export const simRechargeCompletionSchema = z
  .object({
    costCents: z.number().int().min(0).max(100_000_000).nullable().optional(),
    currency: z
      .string()
      .trim()
      .length(3)
      .regex(/^[A-Za-z]{3}$/, 'Currency must be a 3-letter ISO 4217 code')
      .nullable()
      .optional(),
    billingReference: z.string().trim().max(190).nullable().optional(),
    planMb: z.number().int().min(1).max(10_000_000).nullable().optional(),
    note: z.string().trim().max(2000).nullable().optional(),
  })
  // ┌─ THE PAIRING IS CHECKED HERE, NOT ONLY BY THE DATABASE ────────────────┐
  // │ `sim_recharges_currency_chk` (migration 032, decision 8) already makes │
  // │ a cost with no currency unstorable — but a constraint violation        │
  // │ surfaces to the API as an unhandled 500 with a Postgres constraint     │
  // │ name in it, which tells an operator nothing and looks like an outage.  │
  // │ Refusing at the boundary turns it into a 400 that says what to fix,    │
  // │ and the CHECK stays as the guarantee for everything that does not      │
  // │ come through this schema.                                              │
  // └───────────────────────────────────────────────────────────────────────┘
  .refine(
    (v) => v.costCents === null || v.costCents === undefined || !!v.currency,
    { message: 'A cost needs a currency', path: ['currency'] },
  );
export type SimRechargeCompletionInput = z.infer<typeof simRechargeCompletionSchema>;
