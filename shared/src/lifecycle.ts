// ============================================================================
// @obliwan/shared — F8, End-of-Life Inventory
// ============================================================================
//
// ONE SENTENCE: this file turns "what is this MSP still running" into a
// renewal list a salesperson can put in front of a customer, and it refuses to
// say "supported" about anything it cannot cite a vendor date for.
//
// ┌─ THE SENTENCE THIS FILE EXISTS TO MAKE UNSAYABLE ─────────────────────────┐
// │ "THIS BOX IS FINE" — SAID BY A PROGRAM THAT HAS NEVER HEARD OF THE BOX.   │
// │                                                                          │
// │ Every other feature in this product avoids a cost. This one produces      │
// │ REVENUE: it is the list an MSP takes to a renewal conversation. That      │
// │ inverts the usual failure economics. A drift alarm that is wrong wastes   │
// │ an engineer's afternoon. A LIFECYCLE VERDICT THAT IS WRONG IS SAID OUT    │
// │ LOUD TO A PAYING CUSTOMER, by a salesperson who cannot check it, and the  │
// │ customer's own vendor contact contradicts it the same week.               │
// │                                                                          │
// │ There are exactly two ways to be wrong, and they are NOT symmetric:       │
// │                                                                          │
// │   FALSE "OBSOLETE"  — embarrassing, once. The customer's vendor rep says  │
// │                       "no, that model is supported until 2029". The MSP   │
// │                       looks like it is inventing reasons to sell.         │
// │   FALSE "SUPPORTED" — the customer keeps a firewall that stopped getting  │
// │                       security fixes two years ago BECAUSE OUR SCREEN     │
// │                       SAID IT WAS FINE. That is the one that ends in a    │
// │                       breach report with our product name in it.          │
// │                                                                          │
// │ So the third answer is a first-class citizen here. "END OF SUPPORT        │
// │ UNKNOWN" is an honest, useful, SHIPPABLE verdict — it means "go ask the   │
// │ vendor" and it is the correct output for a catalogue that has never heard │
// │ of this model. `supported` is NOT the default, is NOT what an empty       │
// │ catalogue produces, and cannot be reached without a cited FUTURE date.    │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ SEVEN DECISIONS THAT MUST SURVIVE EVERY LATER REFACTOR ──────────────────┐
// │                                                                           │
// │ 1. `supported` REQUIRES A CITED DATE IN THE FUTURE. Not "the catalogue    │
// │    has a row", not "the version is recent", not "no bad news". A cited    │
// │    boundary that has not yet passed, or nothing. `deriveModelStatus` and  │
// │    `deriveFirmwareStatus` each have exactly ONE branch that can return    │
// │    `supported`, and both are guarded by a non-null future date. Every     │
// │    other path in both functions funnels into `unknown` or worse. If you   │
// │    are adding a branch to either function, that is the invariant you are  │
// │    about to break.                                                        │
// │                                                                           │
// │ 2. A CATALOGUE ENTRY WITHOUT A SOURCE IS NOT DATA, IT IS A RUMOUR.        │
// │    `source` is a required non-empty string in the Zod schema AND a CHECK  │
// │    in migration 027, and it rides in the API response next to every       │
// │    verdict. A salesperson who tells a customer their hardware is obsolete │
// │    must be able to name the vendor page that says so, IN THE SAME SCREEN. │
// │    `verifiedAt` is required for the same reason: a citation from 2019 is  │
// │    a different quality of evidence from one checked last month, and the   │
// │    reader has to be able to tell which one they are holding.              │
// │                                                                           │
// │ 3. `declaredStatus` CAN ONLY MAKE A VERDICT WORSE, NEVER BETTER.          │
// │    Vendors regularly declare a product dead without publishing a date     │
// │    (DrayTek's end-of-life list, SonicWall's retired generations). Losing  │
// │    that fact because there is no date to compare would be absurd, so the  │
// │    catalogue can carry a bare declaration. Its vocabulary deliberately    │
// │    EXCLUDES `supported` and `unknown` — see LIFECYCLE_DECLARED_STATUSES — │
// │    and `worstStatus` combines it with the date-derived verdict by taking  │
// │    the MORE severe of the two. There is no representable catalogue row    │
// │    that upgrades a device to `supported`.                                 │
// │                                                                           │
// │ 4. `unknown` OUTRANKS `supported` IN THE SEVERITY ORDER, ON PURPOSE.      │
// │    LIFECYCLE_SEVERITY puts `supported` at 0 and `unknown` at 1. A device  │
// │    nobody has any information about needs a human to look at it; a device │
// │    with a cited support date until 2031 does not. Sorting the renewal     │
// │    list by severity therefore floats the research pile above the boxes we │
// │    can actually vouch for, which is the correct work queue.               │
// │                                                                           │
// │ 5. `asOf` IS A PARAMETER OF THESE PURE FUNCTIONS AND NEVER OF THE HTTP    │
// │    API. Every function here takes the date to reason at, because a rule   │
// │    that reads a clock cannot be tested. But the API MUST NOT expose it:   │
// │    `asOf=2000-01-01` would turn the whole fleet `supported`, and          │
// │    `asOf=2099-01-01` would turn it all `end_of_life`. The server passes   │
// │    its own clock, full stop. (This project has already shipped one        │
// │    caller-driven parameter that flipped a verdict; there is not going to  │
// │    be a second.)                                                          │
// │                                                                           │
// │ 6. THE VERSION PARSER IS STRICT AT THE FRONT AND LENIENT AT THE BACK.     │
// │    `os_version` in this fleet holds `7.14.3`, `6.49.10`, `4.4.5.1`,       │
// │    `V5.30(ABUV.0)C0` and `6.5.4.8-89n`. `parseVersion` accepts an         │
// │    optional leading `v`, then REQUIRES a digit, then reads the dotted     │
// │    numeric run and STOPS at the first thing that is not one. Anything     │
// │    that does not begin with a number returns `null`, and `null` means     │
// │    `unknown`, never `supported`. A parser that guessed here would compare │
// │    a build tag against a release number and call a 2016 firmware current. │
// │                                                                           │
// │ 7. MATCHING IS LONGEST-SPECIFIC-WINS, AND IT IS DETERMINISTIC.            │
// │    Models: an `exact` entry beats every `prefix` entry, and among         │
// │    prefixes the longest pattern wins. Branches: a family-specific entry   │
// │    beats a family-wide one, and among those the branch with the most      │
// │    components wins (`6.49` beats `6`). Ties break on the lowest id so the │
// │    same fleet and the same catalogue always produce the same list — a     │
// │    renewal quote that changes between two page loads is not a quote.      │
// └───────────────────────────────────────────────────────────────────────────┘
//
// SECRETS (§8.2): there is no secret anywhere near this file. Its inputs are a
// brand, a family, a model string and a firmware version; its catalogue is
// published vendor lifecycle information. Nothing here reads a credential,
// and nothing here is ever sent to an equipment — F8 is READ-ONLY against
// ObliWAN's own database (decision D3 is not even engaged).
//
// EVERY FUNCTION BELOW IS PURE. No clock, no I/O, no database. The rule that
// decides what an MSP tells a customer has to be readable in one sitting and
// testable without a fleet.

import { z } from 'zod';
import { DEVICE_BRANDS, DEVICE_FAMILIES, type DeviceBrand, type DeviceFamily } from './device';

// ============================================================================
// 1. Vocabularies
//
// Text + CHECK in the database, exactly like every other vocabulary in this
// schema since migration 002. The comment after each list gives the LONGEST
// value in characters; migration 027 sizes its columns from these and rounds
// up, because a CHECK wider than its column is a constraint that can only ever
// be discovered as "value too long for type" at 2 a.m.
// ============================================================================

/**
 * What we can say about a MODEL, from a vendor citation.
 *
 *   unknown         we have no dated boundary for this hardware. Either the
 *                   catalogue has never heard of it, or the entry exists and
 *                   the vendor publishes no date. THIS IS A REAL ANSWER, it is
 *                   what an empty catalogue produces, and it means "ask the
 *                   vendor" — it does NOT mean "probably fine".
 *   supported       a cited boundary exists AND has not passed yet. The only
 *                   verdict in this file that claims something reassuring, and
 *                   the only one that cannot be reached without a date.
 *   end_of_sale     no longer sold. Still receiving software support. For an
 *                   MSP this is the EARLIEST actionable signal: the customer
 *                   can no longer buy a spare, so the spare has to be planned.
 *   end_of_support  past the last software/security update. No fix is coming
 *                   for the next advisory. This is the one that has to be said
 *                   out loud to the customer.
 *   end_of_life     past the final support boundary — retired, no RMA.
 *
 * Longest value: 'end_of_support' — 14 characters.
 */
export const LIFECYCLE_STATUSES = [
  'unknown',
  'supported',
  'end_of_sale',
  'end_of_support',
  'end_of_life',
] as const;
export type LifecycleStatus = (typeof LIFECYCLE_STATUSES)[number];

/**
 * What we can say about the FIRMWARE a box is running.
 *
 *   unknown      no version recorded, an unparseable version, or no catalogue
 *                branch covering it. Same rule as above: never `supported`.
 *   supported    the branch has a cited end-of-support date in the future AND
 *                the running release is at or above the branch's minimum.
 *   outdated     the branch is alive but this box is BELOW the lowest release
 *                the vendor still fixes. A firmware upgrade closes it — this
 *                is a maintenance ticket, not a sale.
 *   unsupported  the branch's end-of-support date has passed, or the vendor
 *                has declared the branch dead. No fix is coming. On hardware
 *                that cannot run a newer branch, this IS the sale.
 *
 * Longest value: 'unsupported' — 11 characters.
 */
export const FIRMWARE_STATUSES = ['unknown', 'supported', 'outdated', 'unsupported'] as const;
export type FirmwareStatus = (typeof FIRMWARE_STATUSES)[number];

/**
 * How a catalogue row is matched against `devices.model`.
 *
 *   exact   the normalised model key must be identical.
 *   prefix  the normalised model key must START WITH the pattern. This is what
 *           covers `RB2011UiAS-RM` and `RB2011iL-IN` with one row `RB2011`.
 *
 * A prefix entry is a loaded weapon: `TZ3` would swallow TZ300 and TZ370, two
 * generations with different fates. `exact` beats `prefix` in the match order
 * (decision 7) precisely so a specific row can always overrule a broad one.
 *
 * Longest value: 'prefix' — 6 characters.
 */
export const LIFECYCLE_MATCH_MODES = ['exact', 'prefix'] as const;
export type LifecycleMatchMode = (typeof LIFECYCLE_MATCH_MODES)[number];

/**
 * Where a catalogue row came from. Same three values as `ip_asn_ranges.source`
 * in migration 021, and for the same reason: a row seeded by us, a row loaded
 * from a dataset and a row typed by an operator carry different weight, and
 * the screen has to be able to say which.
 *
 * Longest value: 'builtin' — 7 characters.
 */
export const LIFECYCLE_SOURCE_KINDS = ['builtin', 'import', 'manual'] as const;
export type LifecycleSourceKind = (typeof LIFECYCLE_SOURCE_KINDS)[number];

/**
 * A vendor declaration WITHOUT A DATE. Decision 3.
 *
 * Note what is absent: `supported` and `unknown`. There is no way to write a
 * catalogue row that declares something fine — a vendor saying "still
 * supported" without a date tells you nothing you can act on, and encoding it
 * would create exactly the false-`supported` path this file is built to
 * prevent. Only bad news travels undated.
 *
 * Longest value: 'end_of_support' — 14 characters.
 */
export const LIFECYCLE_DECLARED_STATUSES = ['end_of_sale', 'end_of_support', 'end_of_life'] as const;
export type LifecycleDeclaredStatus = (typeof LIFECYCLE_DECLARED_STATUSES)[number];

/**
 * Which half of the catalogue an import touched.
 * Longest value: 'firmware' — 8 characters.
 */
export const LIFECYCLE_IMPORT_KINDS = ['model', 'firmware'] as const;
export type LifecycleImportKind = (typeof LIFECYCLE_IMPORT_KINDS)[number];

/**
 * What the MSP should DO about this device. This is the column the renewal
 * list sorts on, and it is derived — never stored.
 *
 *   urgent   no security fix is available for this box today.
 *   plan     the clock is running: end of sale passed, or a patch exists that
 *            this box is behind.
 *   watch    supported, with a cited boundary inside RENEWAL_WATCH_DAYS. This
 *            is the PIPELINE — the quote you write before the customer asks.
 *   unknown  we cannot vouch for it either way. Research, then re-run.
 *   none     cited as supported, with the boundary comfortably far away.
 *
 * Longest value: 'unknown' — 7 characters. (Derived; never a column.)
 */
export const RENEWAL_PRIORITIES = ['none', 'unknown', 'watch', 'plan', 'urgent'] as const;
export type RenewalPriority = (typeof RENEWAL_PRIORITIES)[number];

// ============================================================================
// 2. Orders
// ============================================================================

/**
 * Severity order. Decision 4: `unknown` (1) is ABOVE `supported` (0).
 *
 * Used by `worstStatus` to combine a date-derived verdict with an undated
 * vendor declaration, and by the inventory sort to put the work at the top.
 */
export const LIFECYCLE_SEVERITY: Readonly<Record<LifecycleStatus, number>> = Object.freeze({
  supported: 0,
  unknown: 1,
  end_of_sale: 2,
  end_of_support: 3,
  end_of_life: 4,
});

/** Same idea on the firmware axis. `unknown` above `supported`, same reason. */
export const FIRMWARE_SEVERITY: Readonly<Record<FirmwareStatus, number>> = Object.freeze({
  supported: 0,
  unknown: 1,
  outdated: 2,
  unsupported: 3,
});

export const RENEWAL_PRIORITY_RANK: Readonly<Record<RenewalPriority, number>> = Object.freeze({
  none: 0,
  unknown: 1,
  watch: 2,
  plan: 3,
  urgent: 4,
});

/**
 * How far ahead a cited boundary has to be before it stops being a sales
 * opportunity and becomes background.
 *
 * A SERVER-SIDE CONSTANT AND NOT AN API PARAMETER (decision 5). It changes
 * which devices land in `watch`, i.e. it changes a verdict, so a caller does
 * not get to set it. The HTTP surface has a `horizonDays` FILTER that selects
 * rows out of an already-computed list; that one changes nothing.
 */
export const RENEWAL_WATCH_DAYS = 365;

/** Return the more severe of two lifecycle statuses. Decision 3 and 4. */
export function worstStatus(a: LifecycleStatus, b: LifecycleStatus): LifecycleStatus {
  return LIFECYCLE_SEVERITY[a] >= LIFECYCLE_SEVERITY[b] ? a : b;
}

// ============================================================================
// 3. Reason codes
//
// Machine-readable, because the client renders in eighteen locales and a
// translated sentence generated on the server would be untranslatable. Each
// verdict also carries an English `detail` for the audit trail and for the
// operator who reads the raw JSON at 2 a.m.
// ============================================================================

export const MODEL_REASONS = [
  /** `devices.model` is NULL or blank — nothing to look up. */
  'no_model_recorded',
  /** The catalogue has never heard of this brand + model. */
  'no_catalog_entry',
  /** An entry exists, and no date and no declaration in it. */
  'no_dates_published',
  'past_end_of_sale',
  'past_end_of_software_support',
  'past_end_of_support',
  /** Undated vendor declaration. Decision 3. */
  'vendor_declared',
  /** The only reason that yields `supported`. Decision 1. */
  'boundary_in_future',
] as const;
export type ModelReason = (typeof MODEL_REASONS)[number];

export const FIRMWARE_REASONS = [
  /** `devices.os_version` is NULL or blank. */
  'no_version_recorded',
  /** Present, but it does not start with a number. Decision 6. */
  'version_unparseable',
  /** No catalogue branch covers this version. */
  'no_branch_entry',
  /** A branch matched and carries neither a date nor a declaration. */
  'no_end_of_support_published',
  'past_branch_end_of_support',
  'below_min_supported_version',
  'vendor_declared',
  /** The only reason that yields `supported`. Decision 1. */
  'branch_end_in_future',
] as const;
export type FirmwareReason = (typeof FIRMWARE_REASONS)[number];

// ============================================================================
// 4. The catalogue, as TypeScript
// ============================================================================

/** A citation, carried next to every verdict so it can be read out loud. */
export interface LifecycleCitation {
  entryId: number;
  sourceKind: LifecycleSourceKind;
  /** Free text naming the vendor page or document. Never empty (decision 2). */
  source: string;
  sourceUrl: string | null;
  /** `YYYY-MM-DD`. When a human last checked this row against its source. */
  verifiedAt: string;
  /** How old that check is, at the date the assessment was run. */
  verifiedDaysAgo: number;
  note: string | null;
}

export interface ModelCatalogEntry {
  id: number;
  brand: DeviceBrand;
  /** Normalised key: `^[A-Z0-9]+$`. See `normalizeModelKey`. */
  modelPattern: string;
  matchMode: LifecycleMatchMode;
  /** What a human calls it, e.g. `MikroTik RB2011 series`. Display only. */
  modelLabel: string;
  /** `YYYY-MM-DD` or null. Last day the vendor sold it. */
  endOfSale: string | null;
  /** `YYYY-MM-DD` or null. Last day it received firmware / security fixes. */
  endOfSoftwareSupport: string | null;
  /** `YYYY-MM-DD` or null. Final boundary — no support of any kind after it. */
  endOfSupport: string | null;
  declaredStatus: LifecycleDeclaredStatus | null;
  /** What to sell instead. The revenue field; null when we will not guess. */
  replacement: string | null;
  sourceKind: LifecycleSourceKind;
  source: string;
  sourceUrl: string | null;
  verifiedAt: string;
  note: string | null;
}

export interface FirmwareCatalogEntry {
  id: number;
  brand: DeviceBrand;
  /**
   * Nullable ON PURPOSE: some vendors version firmware per product line and
   * some per whole catalogue. A null family means "any family of this brand",
   * and a family-specific row beats it (decision 7).
   *
   * NULLABLE + part of the uniqueness key means migration 027 must use PARTIAL
   * unique indexes; `NULLS DISTINCT` would let the family-wide row repeat.
   */
  family: DeviceFamily | null;
  /** Dotted numeric prefix: `6`, `6.49`, `7`, `4.4`. `^\d+(\.\d+)*$`. */
  branch: string;
  branchLabel: string;
  /** Lowest release in this branch the vendor still fixes. `^\d+(\.\d+)*$`. */
  minSupportedVersion: string | null;
  /** `YYYY-MM-DD` or null. When the branch stopped receiving fixes. */
  endOfSupport: string | null;
  declaredStatus: LifecycleDeclaredStatus | null;
  sourceKind: LifecycleSourceKind;
  source: string;
  sourceUrl: string | null;
  verifiedAt: string;
  note: string | null;
}

/** Both halves, as the services load them. Small enough to hold in memory:
 *  the whole point of matching in TypeScript rather than in SQL is that the
 *  rule stays pure and testable without a database. */
export interface LifecycleCatalog {
  models: ModelCatalogEntry[];
  firmware: FirmwareCatalogEntry[];
}

// ============================================================================
// 5. Dates
//
// ISO `YYYY-MM-DD` throughout, compared as STRINGS. That is not laziness: for
// zero-padded ISO dates lexicographic order IS chronological order, it has no
// timezone, and it cannot drift by a day because the server is in Paris and
// the customer is in Nouméa. A lifecycle boundary is a calendar fact, not an
// instant.
// ============================================================================

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** True for a well-formed, real calendar date in `YYYY-MM-DD`. */
export function isIsoDate(value: unknown): value is string {
  if (typeof value !== 'string' || !ISO_DATE_RE.test(value)) return false;
  const t = Date.parse(`${value}T00:00:00Z`);
  if (Number.isNaN(t)) return false;
  // Rejects 2025-02-30, which `Date.parse` would happily roll into March.
  return new Date(t).toISOString().slice(0, 10) === value;
}

/**
 * `Date` -> `YYYY-MM-DD`, ON THE LOCAL CALENDAR. The one place the two
 * representations meet, and the ONLY conversion in F8 — the server's "today"
 * and a `date` column read back out of Postgres both come through here.
 *
 * Local components, NOT `toISOString()`. `pg` hands back a `date` column as a
 * `Date` at LOCAL midnight; rendering that through UTC slips it a day backwards
 * anywhere west of Greenwich. Two conversions that disagree by a day give a
 * boundary that has "passed" for one comparison and not for the other, and the
 * verdict flickers at midnight — for a screen an MSP quotes from, that is the
 * quietest possible kind of wrong.
 */
export function toIsoDate(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/**
 * Whole days from `from` to `to`. Negative when `to` is in the past.
 * Both must be ISO dates; anything else is a programming error and returns 0
 * rather than NaN, because a NaN would silently poison every comparison
 * downstream of it.
 */
export function daysBetween(from: string, to: string): number {
  if (!isIsoDate(from) || !isIsoDate(to)) return 0;
  const a = Date.parse(`${from}T00:00:00Z`);
  const b = Date.parse(`${to}T00:00:00Z`);
  return Math.round((b - a) / 86_400_000);
}

/** True when `date` is a real ISO date at or before `asOf` — i.e. it HAS passed. */
export function hasPassed(date: string | null, asOf: string): boolean {
  return date !== null && isIsoDate(date) && date <= asOf;
}

// ============================================================================
// 6. Normalisation and version arithmetic
// ============================================================================

/**
 * `devices.model` -> a matching key, or null when there is nothing to match.
 *
 * Uppercase, then keep ONLY `A-Z0-9`. Everything a vendor puts between the
 * meaningful characters is noise that differs between the label on the box,
 * the string SNMP returns and the string an operator typed:
 *
 *   'RB2011UiAS-RM'     -> 'RB2011UIASRM'
 *   'rb 2011 UiAS RM'   -> 'RB2011UIASRM'
 *   'USG FLEX 100'      -> 'USGFLEX100'
 *   'Vigor2927 Lac'     -> 'VIGOR2927LAC'
 *   'TZ370'             -> 'TZ370'
 *
 * The catalogue stores its patterns ALREADY normalised (migration 027 has a
 * CHECK for it), so the two sides of every comparison went through the same
 * function — the classic failure here is normalising one side only.
 */
export function normalizeModelKey(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const key = raw.toUpperCase().replace(/[^A-Z0-9]/g, '');
  return key.length > 0 ? key : null;
}

/**
 * A firmware version string -> its leading dotted numeric run, or null.
 *
 * Decision 6: strict at the front, lenient at the back. An optional leading
 * `v`/`V` is skipped; after that a DIGIT is required; then digits and dots are
 * consumed and everything from the first other character is dropped.
 *
 *   '7.14.3'            -> [7, 14, 3]      MikroTik RouterOS 7
 *   '6.49.10'           -> [6, 49, 10]     MikroTik RouterOS 6 long-term
 *   '7.14.3 (stable)'   -> [7, 14, 3]      channel suffix dropped
 *   '4.4.5.1'           -> [4, 4, 5, 1]    DrayTek Vigor
 *   'V5.30(ABUV.0)C0'   -> [5, 30]         Zyxel: stops at '('
 *   '6.5.4.8-89n'       -> [6, 5, 4, 8]    SonicOS: stops at '-'
 *   'RouterOS 7.1'      -> null            does not START with a number
 *   ''                  -> null
 *
 * `RouterOS 7.1` returning null is deliberate. Scanning for a number ANYWHERE
 * in the string is how you end up parsing `2011` out of `RB2011` and comparing
 * a hardware model against a firmware branch. A version string that does not
 * begin with a version is not a version we are willing to reason about, and
 * `unknown` is the honest output.
 *
 * At most 6 components: past that it is a build identifier, not a release.
 */
export function parseVersion(raw: string | null | undefined): number[] | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim().replace(/^[vV](?=\d)/, '');
  const m = /^(\d+(?:\.\d+)*)/.exec(trimmed);
  if (!m) return null;
  const parts = m[1].split('.').slice(0, 6).map((p) => Number.parseInt(p, 10));
  // `parseInt` on `\d+` cannot produce NaN, but a 30-digit component would
  // produce Infinity-ish garbage; refuse rather than compare it.
  if (parts.some((n) => !Number.isSafeInteger(n))) return null;
  return parts;
}

/**
 * Component-wise comparison, missing components read as 0.
 * `7.14` === `7.14.0`, and `6.49.10` > `6.49.2` (numeric, not lexicographic —
 * the bug that makes 6.49.10 look older than 6.49.2 is exactly why this is not
 * a string compare).
 */
export function compareVersions(a: number[], b: number[]): number {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Is `version` inside `branch`? True when the branch's components are an exact
 * prefix of the version's.
 *
 *   [6, 49, 10] in '6'     -> true
 *   [6, 49, 10] in '6.49'  -> true
 *   [6, 48, 6]  in '6.49'  -> false
 *   [7, 14, 3]  in '6'     -> false
 *
 * A malformed branch matches nothing (rather than everything), which keeps a
 * bad catalogue row from swallowing the fleet.
 */
export function versionInBranch(version: number[], branch: string): boolean {
  const b = parseVersion(branch);
  if (b === null || b.length === 0) return false;
  if (b.length > version.length) return false;
  return b.every((component, i) => component === version[i]);
}

// ============================================================================
// 7. Matching
//
// Decision 7: most specific wins, ties break on the lowest id. Both functions
// are total — they return null rather than throwing, because "the catalogue
// does not cover this" is a normal, expected, shippable outcome.
// ============================================================================

/** Pick the catalogue row that describes this device's hardware, or null. */
export function matchModelEntry(
  brand: DeviceBrand,
  model: string | null | undefined,
  entries: readonly ModelCatalogEntry[],
): ModelCatalogEntry | null {
  const key = normalizeModelKey(model);
  if (key === null) return null;

  let best: ModelCatalogEntry | null = null;
  for (const e of entries) {
    if (e.brand !== brand) continue;
    const hit = e.matchMode === 'exact' ? e.modelPattern === key : key.startsWith(e.modelPattern);
    if (!hit) continue;
    if (best === null || modelEntryBeats(e, best)) best = e;
  }
  return best;
}

/** `a` is a better match than `b`: exact first, then the longer pattern, then
 *  the lower id. Total and antisymmetric so the result cannot depend on the
 *  order the rows came out of Postgres. */
function modelEntryBeats(a: ModelCatalogEntry, b: ModelCatalogEntry): boolean {
  if (a.matchMode !== b.matchMode) return a.matchMode === 'exact';
  if (a.modelPattern.length !== b.modelPattern.length) {
    return a.modelPattern.length > b.modelPattern.length;
  }
  return a.id < b.id;
}

/** Pick the catalogue row that describes this device's firmware branch. */
export function matchFirmwareEntry(
  brand: DeviceBrand,
  family: DeviceFamily,
  version: number[] | null,
  entries: readonly FirmwareCatalogEntry[],
): FirmwareCatalogEntry | null {
  if (version === null) return null;

  let best: FirmwareCatalogEntry | null = null;
  for (const e of entries) {
    if (e.brand !== brand) continue;
    if (e.family !== null && e.family !== family) continue;
    if (!versionInBranch(version, e.branch)) continue;
    if (best === null || firmwareEntryBeats(e, best)) best = e;
  }
  return best;
}

/** Family-specific beats family-wide; then the branch with more components;
 *  then the lower id. */
function firmwareEntryBeats(a: FirmwareCatalogEntry, b: FirmwareCatalogEntry): boolean {
  const aFam = a.family !== null;
  const bFam = b.family !== null;
  if (aFam !== bFam) return aFam;
  const aDepth = (parseVersion(a.branch) ?? []).length;
  const bDepth = (parseVersion(b.branch) ?? []).length;
  if (aDepth !== bDepth) return aDepth > bDepth;
  return a.id < b.id;
}

// ============================================================================
// 8. The verdicts
//
// DECISION 1 LIVES HERE. Each function has exactly ONE `return 'supported'`
// and it is guarded by a cited date that has not passed. Everything else
// funnels to `unknown` or worse.
// ============================================================================

export interface ModelVerdict {
  status: LifecycleStatus;
  reason: ModelReason;
  /** English, for logs and for the raw-JSON reader. The client translates from
   *  `reason`; this string is never the thing a locale renders. */
  detail: string;
  citation: LifecycleCitation | null;
  endOfSale: string | null;
  endOfSoftwareSupport: string | null;
  endOfSupport: string | null;
  replacement: string | null;
  /** Days until the NEXT boundary that has not passed yet; null when there is
   *  none. Negative is impossible by construction — a passed boundary changes
   *  the status instead. This is what drives `watch`. */
  daysUntilNextBoundary: number | null;
}

function citationOf(
  e: { id: number; sourceKind: LifecycleSourceKind; source: string; sourceUrl: string | null;
       verifiedAt: string; note: string | null },
  asOf: string,
): LifecycleCitation {
  return {
    entryId: e.id,
    sourceKind: e.sourceKind,
    source: e.source,
    sourceUrl: e.sourceUrl,
    verifiedAt: e.verifiedAt,
    verifiedDaysAgo: daysBetween(e.verifiedAt, asOf),
    note: e.note,
  };
}

/**
 * The hardware verdict.
 *
 * `entry === null` covers BOTH "no model on the device" and "no catalogue row",
 * which the caller distinguishes by passing `hasModel`. Both are `unknown`,
 * and neither is ever `supported`.
 */
export function deriveModelStatus(
  entry: ModelCatalogEntry | null,
  hasModel: boolean,
  asOf: string,
): ModelVerdict {
  const empty = {
    citation: null,
    endOfSale: null,
    endOfSoftwareSupport: null,
    endOfSupport: null,
    replacement: null,
    daysUntilNextBoundary: null,
  };

  if (!hasModel) {
    return {
      status: 'unknown',
      reason: 'no_model_recorded',
      detail: 'No model recorded on this device — nothing to look up.',
      ...empty,
    };
  }
  if (entry === null) {
    return {
      status: 'unknown',
      reason: 'no_catalog_entry',
      detail: 'The lifecycle catalogue has no entry for this brand and model.',
      ...empty,
    };
  }

  const cite = citationOf(entry, asOf);
  const dates = {
    endOfSale: entry.endOfSale,
    endOfSoftwareSupport: entry.endOfSoftwareSupport,
    endOfSupport: entry.endOfSupport,
    replacement: entry.replacement,
  };

  // Next boundary still ahead of us, most imminent first. Used for `watch`.
  const future = [entry.endOfSale, entry.endOfSoftwareSupport, entry.endOfSupport]
    .filter((d): d is string => d !== null && isIsoDate(d) && d > asOf)
    .sort();
  const daysUntilNextBoundary = future.length > 0 ? daysBetween(asOf, future[0]) : null;

  // --- dated verdict, worst boundary first ---------------------------------
  let dated: { status: LifecycleStatus; reason: ModelReason; detail: string } | null = null;
  if (hasPassed(entry.endOfSupport, asOf)) {
    dated = {
      status: 'end_of_life',
      reason: 'past_end_of_support',
      detail: `Vendor end of support was ${entry.endOfSupport}.`,
    };
  } else if (hasPassed(entry.endOfSoftwareSupport, asOf)) {
    dated = {
      status: 'end_of_support',
      reason: 'past_end_of_software_support',
      detail: `Vendor end of software/security support was ${entry.endOfSoftwareSupport}.`,
    };
  } else if (hasPassed(entry.endOfSale, asOf)) {
    dated = {
      status: 'end_of_sale',
      reason: 'past_end_of_sale',
      detail: `Vendor end of sale was ${entry.endOfSale}.`,
    };
  }

  // --- undated declaration (decision 3) ------------------------------------
  const declared = entry.declaredStatus;

  if (dated === null && declared === null) {
    // An entry exists but says nothing datable. THE ONE PLACE `supported` CAN
    // BE RETURNED, and only when a real boundary is on the calendar ahead.
    if (daysUntilNextBoundary !== null) {
      return {
        status: 'supported',
        reason: 'boundary_in_future',
        detail: `Supported: the next published boundary is ${future[0]}.`,
        citation: cite,
        ...dates,
        daysUntilNextBoundary,
      };
    }
    return {
      status: 'unknown',
      reason: 'no_dates_published',
      detail: 'The vendor publishes no end-of-life date for this model.',
      citation: cite,
      ...dates,
      daysUntilNextBoundary: null,
    };
  }

  // At least one of the two says something bad. Take the WORSE.
  const datedStatus: LifecycleStatus = dated?.status ?? 'unknown';
  const declaredStatus: LifecycleStatus = declared ?? 'unknown';
  const status = worstStatus(datedStatus, declaredStatus);
  const useDeclared = dated === null || LIFECYCLE_SEVERITY[declaredStatus] > LIFECYCLE_SEVERITY[datedStatus];

  return {
    status,
    reason: useDeclared ? 'vendor_declared' : (dated as { reason: ModelReason }).reason,
    detail: useDeclared
      ? `The vendor has declared this model ${declared}; no effective date was published.`
      : (dated as { detail: string }).detail,
    citation: cite,
    ...dates,
    daysUntilNextBoundary,
  };
}

export interface FirmwareVerdict {
  status: FirmwareStatus;
  reason: FirmwareReason;
  detail: string;
  citation: LifecycleCitation | null;
  /** The branch that matched, e.g. `6.49`. Null when nothing matched. */
  branch: string | null;
  branchLabel: string | null;
  minSupportedVersion: string | null;
  endOfSupport: string | null;
  /** What `parseVersion` made of `devices.os_version`, echoed so a wrong
   *  verdict can be blamed on the parse rather than on the catalogue. */
  parsedVersion: number[] | null;
  daysUntilEndOfSupport: number | null;
}

/**
 * The firmware verdict.
 *
 * Order matters: an END-OF-SUPPORT BRANCH BEATS A VERSION CHECK. A box running
 * the very last release of a dead branch is not "current", it is unsupported —
 * there is no patch to install and the answer is new hardware or a major
 * upgrade, which is a completely different conversation from "run the updater".
 */
export function deriveFirmwareStatus(
  entry: FirmwareCatalogEntry | null,
  rawVersion: string | null | undefined,
  asOf: string,
): FirmwareVerdict {
  const parsed = parseVersion(rawVersion);
  const empty = {
    citation: null,
    branch: null,
    branchLabel: null,
    minSupportedVersion: null,
    endOfSupport: null,
    parsedVersion: parsed,
    daysUntilEndOfSupport: null,
  };

  if (typeof rawVersion !== 'string' || rawVersion.trim() === '') {
    return {
      status: 'unknown',
      reason: 'no_version_recorded',
      detail: 'No firmware version recorded on this device.',
      ...empty,
    };
  }
  if (parsed === null) {
    return {
      status: 'unknown',
      reason: 'version_unparseable',
      detail: `Firmware version ${JSON.stringify(rawVersion)} does not start with a number; refusing to guess.`,
      ...empty,
    };
  }
  if (entry === null) {
    return {
      status: 'unknown',
      reason: 'no_branch_entry',
      detail: 'The lifecycle catalogue has no branch covering this firmware version.',
      ...empty,
    };
  }

  const cite = citationOf(entry, asOf);
  const common = {
    citation: cite,
    branch: entry.branch,
    branchLabel: entry.branchLabel,
    minSupportedVersion: entry.minSupportedVersion,
    endOfSupport: entry.endOfSupport,
    parsedVersion: parsed,
  };
  const eosAhead =
    entry.endOfSupport !== null && isIsoDate(entry.endOfSupport) && entry.endOfSupport > asOf
      ? daysBetween(asOf, entry.endOfSupport)
      : null;

  // 1. The branch is dead, by date.
  if (hasPassed(entry.endOfSupport, asOf)) {
    return {
      status: 'unsupported',
      reason: 'past_branch_end_of_support',
      detail: `${entry.branchLabel} stopped receiving fixes on ${entry.endOfSupport}.`,
      ...common,
      daysUntilEndOfSupport: null,
    };
  }

  // 2. The branch is dead, by undated vendor declaration (decision 3).
  if (entry.declaredStatus !== null) {
    return {
      status: 'unsupported',
      reason: 'vendor_declared',
      detail: `The vendor has declared ${entry.branchLabel} ${entry.declaredStatus}; no effective date was published.`,
      ...common,
      daysUntilEndOfSupport: eosAhead,
    };
  }

  // 3. The branch lives, but this box is behind its floor.
  const floor = parseVersion(entry.minSupportedVersion);
  if (floor !== null && compareVersions(parsed, floor) < 0) {
    return {
      status: 'outdated',
      reason: 'below_min_supported_version',
      detail: `Running below ${entry.minSupportedVersion}, the lowest release still fixed in ${entry.branchLabel}.`,
      ...common,
      daysUntilEndOfSupport: eosAhead,
    };
  }

  // 4. THE ONE PLACE `supported` CAN BE RETURNED. Decision 1: a cited date,
  //    ahead of us. No date means unknown, however new the firmware looks.
  if (eosAhead !== null) {
    return {
      status: 'supported',
      reason: 'branch_end_in_future',
      detail: `${entry.branchLabel} is supported until ${entry.endOfSupport}.`,
      ...common,
      daysUntilEndOfSupport: eosAhead,
    };
  }

  return {
    status: 'unknown',
    reason: 'no_end_of_support_published',
    detail: `The vendor publishes no end-of-support date for ${entry.branchLabel}.`,
    ...common,
    daysUntilEndOfSupport: null,
  };
}

// ============================================================================
// 9. Per-device assessment and the renewal priority
// ============================================================================

export interface LifecycleDeviceInput {
  deviceId: number;
  name: string;
  siteId: number | null;
  siteName: string | null;
  brand: DeviceBrand;
  family: DeviceFamily;
  model: string | null;
  osVersion: string | null;
}

export interface LifecycleAssessment {
  device: LifecycleDeviceInput;
  hardware: ModelVerdict;
  firmware: FirmwareVerdict;
  priority: RenewalPriority;
  /** Sort key. Not persisted, not part of the contract's meaning — just the
   *  deterministic order the renewal list comes out in. */
  rank: number;
}

/**
 * What to do about this box.
 *
 * The mapping is deliberately blunt, because the person reading it is holding
 * a phone and not a spreadsheet:
 *
 *   urgent   the hardware is past software support (or fully dead), OR the
 *            firmware branch is unsupported. Either way: NO SECURITY FIX IS
 *            AVAILABLE. This is the sale, and it is also the liability.
 *   plan     end of sale has passed (no more spares), or a patch exists that
 *            this box is behind. The clock is running but nothing is on fire.
 *   watch    cited as supported, boundary inside RENEWAL_WATCH_DAYS. Pipeline.
 *   unknown  at least one axis has no citation. Research, do not quote.
 *   none     cited as supported on both axes, with room to spare.
 */
export function renewalPriorityOf(hardware: ModelVerdict, firmware: FirmwareVerdict): RenewalPriority {
  if (hardware.status === 'end_of_life' || hardware.status === 'end_of_support') return 'urgent';
  if (firmware.status === 'unsupported') return 'urgent';
  if (hardware.status === 'end_of_sale') return 'plan';
  if (firmware.status === 'outdated') return 'plan';
  if (hardware.status === 'unknown' || firmware.status === 'unknown') return 'unknown';
  // Both axes are `supported` from here — the only remaining question is how
  // soon the cited boundary lands.
  const soonest = [hardware.daysUntilNextBoundary, firmware.daysUntilEndOfSupport]
    .filter((d): d is number => d !== null);
  if (soonest.length > 0 && Math.min(...soonest) <= RENEWAL_WATCH_DAYS) return 'watch';
  return 'none';
}

/** One device, both axes, the priority and the sort rank. Pure. */
export function assessDevice(
  device: LifecycleDeviceInput,
  catalog: LifecycleCatalog,
  asOf: string,
): LifecycleAssessment {
  const modelEntry = matchModelEntry(device.brand, device.model, catalog.models);
  const hardware = deriveModelStatus(
    modelEntry,
    normalizeModelKey(device.model) !== null,
    asOf,
  );
  const firmwareEntry = matchFirmwareEntry(
    device.brand,
    device.family,
    parseVersion(device.osVersion),
    catalog.firmware,
  );
  const firmware = deriveFirmwareStatus(firmwareEntry, device.osVersion, asOf);
  const priority = renewalPriorityOf(hardware, firmware);

  // Priority dominates; then the worse hardware status; then the worse
  // firmware status. Deterministic, and the caller breaks the final tie on
  // deviceId so two identical boxes never swap places between page loads.
  const rank =
    RENEWAL_PRIORITY_RANK[priority] * 100 +
    LIFECYCLE_SEVERITY[hardware.status] * 10 +
    FIRMWARE_SEVERITY[firmware.status];

  return { device, hardware, firmware, priority, rank };
}

/** The order the renewal list is served in: worst first, then by name, then by
 *  id. `localeCompare` is deliberately NOT used — a locale-dependent sort makes
 *  the same fleet come out in two orders on two servers. */
export function compareAssessments(a: LifecycleAssessment, b: LifecycleAssessment): number {
  if (a.rank !== b.rank) return b.rank - a.rank;
  if (a.device.name !== b.device.name) return a.device.name < b.device.name ? -1 : 1;
  return a.device.deviceId - b.device.deviceId;
}

// ============================================================================
// 10. Aggregates
// ============================================================================

export interface LifecycleSummary {
  asOf: string;
  devicesTotal: number;
  byHardwareStatus: Record<LifecycleStatus, number>;
  byFirmwareStatus: Record<FirmwareStatus, number>;
  byPriority: Record<RenewalPriority, number>;
  /**
   * HOW MUCH OF THE FLEET THE CATALOGUE ACTUALLY COVERS.
   *
   * This is not a vanity metric, it is the honesty gauge for the whole screen.
   * A renewal list built from a catalogue that covers 4% of the fleet is a
   * renewal list with a 96% blind spot, and the MSP has to see that number
   * BEFORE it decides the fleet is healthy. Without it, an empty catalogue and
   * a fleet with nothing wrong produce the same green page.
   *
   * READ THE NAME PRECISELY: `cited`, not `dated`. A device counts as covered
   * when a catalogue row MATCHED it and that row names a source — including a
   * row whose honest content is "the vendor publishes no end-of-life date for
   * this model". That row still yields `unknown`, and it should: what it buys
   * is that nobody researches the same model a second time.
   */
  coverage: {
    hardwareCited: number;
    firmwareCited: number;
    hardwareCitedPct: number;
    firmwareCitedPct: number;
  };
  /** Devices whose hardware OR firmware has no citation at all. */
  needsResearch: number;
}

function zeroed<K extends string>(keys: readonly K[]): Record<K, number> {
  const out = {} as Record<K, number>;
  for (const k of keys) out[k] = 0;
  return out;
}

export function summarizeLifecycle(
  assessments: readonly LifecycleAssessment[],
  asOf: string,
): LifecycleSummary {
  const byHardwareStatus = zeroed(LIFECYCLE_STATUSES);
  const byFirmwareStatus = zeroed(FIRMWARE_STATUSES);
  const byPriority = zeroed(RENEWAL_PRIORITIES);
  let hardwareCited = 0;
  let firmwareCited = 0;
  let needsResearch = 0;

  for (const a of assessments) {
    byHardwareStatus[a.hardware.status] += 1;
    byFirmwareStatus[a.firmware.status] += 1;
    byPriority[a.priority] += 1;
    if (a.hardware.citation !== null) hardwareCited += 1;
    if (a.firmware.citation !== null) firmwareCited += 1;
    if (a.hardware.citation === null || a.firmware.citation === null) needsResearch += 1;
  }

  const total = assessments.length;
  const pct = (n: number): number => (total === 0 ? 0 : Math.round((n / total) * 1000) / 10);

  return {
    asOf,
    devicesTotal: total,
    byHardwareStatus,
    byFirmwareStatus,
    byPriority,
    coverage: {
      hardwareCited,
      firmwareCited,
      hardwareCitedPct: pct(hardwareCited),
      firmwareCitedPct: pct(firmwareCited),
    },
    needsResearch,
  };
}

/**
 * The RESEARCH LIST: every distinct (brand, model) in this fleet the catalogue
 * has never heard of, with how many devices are behind it.
 *
 * This is the other half of honesty. Saying "unknown" to the salesperson is
 * correct but not actionable; saying "these eleven model strings account for
 * 340 of your devices, look them up in this order" is what turns the unknown
 * pile into a catalogue. Sorted by device count, descending.
 */
export interface CatalogGap {
  brand: DeviceBrand;
  /** The raw string as it appears on the devices, for the person googling it. */
  model: string | null;
  modelKey: string | null;
  families: DeviceFamily[];
  deviceCount: number;
}

export function catalogGaps(assessments: readonly LifecycleAssessment[]): CatalogGap[] {
  const byKey = new Map<string, CatalogGap>();
  for (const a of assessments) {
    if (a.hardware.citation !== null) continue;
    const modelKey = normalizeModelKey(a.device.model);
    const key = `${a.device.brand} ${modelKey ?? ''}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.deviceCount += 1;
      if (!existing.families.includes(a.device.family)) existing.families.push(a.device.family);
    } else {
      byKey.set(key, {
        brand: a.device.brand,
        model: a.device.model,
        modelKey,
        families: [a.device.family],
        deviceCount: 1,
      });
    }
  }
  return [...byKey.values()].sort((x, y) => {
    if (x.deviceCount !== y.deviceCount) return y.deviceCount - x.deviceCount;
    if (x.brand !== y.brand) return x.brand < y.brand ? -1 : 1;
    return (x.modelKey ?? '') < (y.modelKey ?? '') ? -1 : 1;
  });
}

// ============================================================================
// 11. Validation of catalogue writes
//
// Two independent refusals, exactly like `weather.ts` and the CHECKs of
// migration 021: the Zod schema below, and the constraints in migration 027.
// The service-layer one is not what runs when somebody edits a row from psql
// during a renewal campaign.
// ============================================================================

/** Thrown by `validateModelEntry` / `validateFirmwareEntry`. The controller
 *  turns it into a 400 with the reason spelled out — never a 500 and never a
 *  silent drop of the offending row. */
export class LifecycleCatalogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LifecycleCatalogError';
  }
}

const isoDate = z.string().refine(isIsoDate, { message: 'expected a YYYY-MM-DD calendar date' });
const dottedVersion = z
  .string()
  .regex(/^\d+(\.\d+)*$/, 'expected a dotted numeric version such as 6.49 or 7.14.3')
  .max(48);

/**
 * `source` is REQUIRED AND NON-EMPTY (decision 2). `.trim().min(1)` and not
 * `.min(1)`: a source of three spaces satisfies a length check and cites
 * nothing.
 */
const sourceField = z.string().trim().min(1, 'a catalogue entry without a source is a rumour').max(160);

export const modelCatalogEntrySchema = z
  .object({
    brand: z.enum(DEVICE_BRANDS),
    /** Callers send the human string; the service normalises it. Accepting an
     *  already-normalised key is fine — the function is idempotent. */
    model: z.string().trim().min(1).max(128),
    matchMode: z.enum(LIFECYCLE_MATCH_MODES).optional(),
    modelLabel: z.string().trim().min(1).max(160),
    endOfSale: isoDate.nullable().optional(),
    endOfSoftwareSupport: isoDate.nullable().optional(),
    endOfSupport: isoDate.nullable().optional(),
    declaredStatus: z.enum(LIFECYCLE_DECLARED_STATUSES).nullable().optional(),
    replacement: z.string().trim().min(1).max(160).nullable().optional(),
    source: sourceField,
    sourceUrl: z.string().trim().max(512).nullable().optional(),
    verifiedAt: isoDate,
    note: z.string().max(2000).nullable().optional(),
  })
  .strict();
export type ModelCatalogEntryInput = z.infer<typeof modelCatalogEntrySchema>;

export const firmwareCatalogEntrySchema = z
  .object({
    brand: z.enum(DEVICE_BRANDS),
    family: z.enum(DEVICE_FAMILIES).nullable().optional(),
    branch: dottedVersion.max(32),
    branchLabel: z.string().trim().min(1).max(160),
    minSupportedVersion: dottedVersion.nullable().optional(),
    endOfSupport: isoDate.nullable().optional(),
    declaredStatus: z.enum(LIFECYCLE_DECLARED_STATUSES).nullable().optional(),
    source: sourceField,
    sourceUrl: z.string().trim().max(512).nullable().optional(),
    verifiedAt: isoDate,
    note: z.string().max(2000).nullable().optional(),
  })
  .strict();
export type FirmwareCatalogEntryInput = z.infer<typeof firmwareCatalogEntrySchema>;

/**
 * The rules Zod cannot express, and every one of them is a rule about not
 * publishing nonsense to a customer.
 *
 * Mirrored by CHECK constraints in migration 027 — two independent refusals.
 */
export function validateModelEntry(input: ModelCatalogEntryInput): void {
  const { endOfSale: sale, endOfSoftwareSupport: soft, endOfSupport: hard } = input;

  // Chronology. A model whose support ends before it stops being sold is a
  // transposition in the import file, and it would produce a device that is
  // simultaneously `end_of_support` and on sale.
  if (sale && soft && sale > soft) {
    throw new LifecycleCatalogError(
      `endOfSale (${sale}) is after endOfSoftwareSupport (${soft}) — the vendor cannot stop fixing it before it stops selling it`,
    );
  }
  if (soft && hard && soft > hard) {
    throw new LifecycleCatalogError(
      `endOfSoftwareSupport (${soft}) is after endOfSupport (${hard})`,
    );
  }
  if (sale && hard && sale > hard) {
    throw new LifecycleCatalogError(`endOfSale (${sale}) is after endOfSupport (${hard})`);
  }

  // An entry with no date and no declaration is ALLOWED, and it is one of the
  // most useful rows in the table: it is the difference between "we have never
  // looked at this model" and "we looked, and the vendor publishes nothing".
  // It yields `unknown` either way — but the second one comes with a citation,
  // so nobody researches it twice.
  //
  // What it must NOT be is a blank row that silently counts towards coverage.
  // So the price of an undated entry is that a human has to write down what
  // they found: `note` becomes mandatory.
  if (!sale && !soft && !hard && !input.declaredStatus) {
    if (!input.note || input.note.trim() === '') {
      throw new LifecycleCatalogError(
        'a model entry with no date and no declaredStatus must carry a note saying what the vendor actually publishes — otherwise it is a blank row that inflates catalogue coverage',
      );
    }
  }

  if (normalizeModelKey(input.model) === null) {
    throw new LifecycleCatalogError(
      `model ${JSON.stringify(input.model)} normalises to nothing — it contains no letters or digits`,
    );
  }
}

export function validateFirmwareEntry(input: FirmwareCatalogEntryInput): void {
  const branch = parseVersion(input.branch);
  if (branch === null || branch.length === 0) {
    throw new LifecycleCatalogError(`branch ${JSON.stringify(input.branch)} is not a dotted version`);
  }
  const floor = parseVersion(input.minSupportedVersion ?? null);
  if (input.minSupportedVersion !== null && input.minSupportedVersion !== undefined) {
    if (floor === null) {
      throw new LifecycleCatalogError(
        `minSupportedVersion ${JSON.stringify(input.minSupportedVersion)} is not a dotted version`,
      );
    }
    // The floor has to be INSIDE the branch it is the floor of. `branch: '6'`
    // with `minSupportedVersion: '7.14'` marks every RouterOS 6 box outdated
    // and tells the operator to install a release that does not exist in that
    // tree — a fleet-wide false alarm from one transposed field.
    if (!versionInBranch(floor, input.branch)) {
      throw new LifecycleCatalogError(
        `minSupportedVersion ${input.minSupportedVersion} is not inside branch ${input.branch}`,
      );
    }
  }
  // Same rule as `validateModelEntry`: a branch entry that carries no date, no
  // declaration and no floor can only ever produce `unknown` — which is fine
  // and honest, PROVIDED a human wrote down what they found when they looked.
  if (!input.endOfSupport && !input.declaredStatus && !input.minSupportedVersion) {
    if (!input.note || input.note.trim() === '') {
      throw new LifecycleCatalogError(
        'a firmware entry with no endOfSupport, no declaredStatus and no minSupportedVersion must carry a note saying what the vendor actually publishes',
      );
    }
  }
}
