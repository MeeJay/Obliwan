/**
 * ObliWAN F5 — ASN / region enrichment, OFFLINE.
 *
 * ┌─ THE CHOICE THIS FILE MAKES, AND WHY (§10/F5, point 3) ───────────────────┐
 * │ Attribution is a LONGEST-PREFIX MATCH AGAINST A LOCAL TABLE. There is no  │
 * │ network call in this file. There is no third-party API key, no WHOIS      │
 * │ client, no RDAP fetch, and no per-device HTTP request.                    │
 * │                                                                          │
 * │ Three reasons, in order of how much they would have hurt:                 │
 * │                                                                          │
 * │ 1. IT WOULD FAIL EXACTLY WHEN IT MATTERS. The moment this feature has a   │
 * │    job to do is the moment a carrier is broken. That is also the moment   │
 * │    an outbound lookup times out — so the one screen an operator opens     │
 * │    during an outage would be the one screen that spins.                   │
 * │ 2. THREE HUNDRED SITES x EVERY FLAP = A RATE-LIMIT BAN, and then a        │
 * │    permanently empty ASN column that nobody notices until a quorum        │
 * │    silently stops being reachable.                                        │
 * │ 3. IT PUBLISHES THE CUSTOMER'S TOPOLOGY. "Which public addresses does     │
 * │    this MSP's fleet sit on" is exactly the map an attacker wants, and     │
 * │    handing it to a free API one query at a time is handing it over.       │
 * │                                                                          │
 * │ THE COST, STATED HONESTLY: the table has to be loaded and refreshed by    │
 * │ the operator. `weather_asn_imports` records when, from what and how many  │
 * │ rows, and the API surfaces it, so "why is this site unattributed" has an  │
 * │ answer that is not a shrug. An empty table degrades cleanly: no ASN, no   │
 * │ candidate, no quorum, no incident — never a wrong one.                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * INPUT FORMATS. Two, because the two things an operator actually has are a
 * public IP-to-ASN dump (the `start end asn country org` TSV that iptoasn.com,
 * a RIB dump or an internal export all produce) and a hand-written list of
 * CIDRs for the carriers they care about. `parseAsnRangeLine` accepts both and
 * `rangeToCidrs` turns a start/end pair into the minimal set of CIDR blocks —
 * pure, exact, and it is what makes the TSV form usable at all.
 *
 * SECRETS (§8.2): nothing here touches a credential. `weather_asn_imports.label`
 * is operator-supplied and reaches the UI, so it is length-clamped and stored
 * verbatim; a caller that puts a URL with a token in it has published it
 * themselves, and the controller says so.
 */

import { LRUCache } from 'lru-cache';
import {
  ASN_RANGE_SOURCES, classifyIpScope, isAttributableAddress,
  type AsnRangeSource, type IpScope,
} from '@obliwan/shared/dist/weather';
import { parseIp, type ParsedIp } from '@obliwan/shared/dist/ncm/primitives';
import { db } from '../../db';
import { logger } from '../../utils/logger';

export interface AsnAttribution {
  asn: number;
  asOrg: string | null;
  country: string | null;
  region: string | null;
  /** The prefix that matched, e.g. `185.12.64.0/22`. Shown in the UI: an
   *  operator arguing with a carrier needs to see WHICH block we matched. */
  prefix: string;
}

export interface AddressAttribution {
  scope: IpScope;
  /** Null whenever `scope !== 'public'` OR the table has no covering prefix.
   *  Those two are different situations and `reason` distinguishes them. */
  asn: AsnAttribution | null;
  reason: 'attributed' | 'not_public' | 'no_covering_prefix' | 'no_address';
}

// ============================================================================
// 1. Range arithmetic — pure, exact, offline
// ============================================================================

function ipToBig(parsed: ParsedIp): bigint {
  let acc = 0n;
  for (const byte of parsed.bytes) acc = (acc << 8n) | BigInt(byte);
  return acc;
}

function bigToIp(value: bigint, version: 4 | 6): string {
  if (version === 4) {
    return [24n, 16n, 8n, 0n].map((s) => Number((value >> s) & 0xffn)).join('.');
  }
  const groups: string[] = [];
  for (let i = 7n; i >= 0n; i--) {
    groups.push((((value >> (i * 16n)) & 0xffffn) as bigint).toString(16));
  }
  return groups.join(':');
}

function lowestSetBit(value: bigint, width: number): number {
  if (value === 0n) return width;
  let n = 0;
  let v = value;
  while ((v & 1n) === 0n) {
    v >>= 1n;
    n++;
  }
  return n;
}

function bitLength(value: bigint): number {
  let n = 0;
  let v = value;
  while (v > 0n) {
    v >>= 1n;
    n++;
  }
  return n;
}

/**
 * Decompose an inclusive address range into the MINIMAL set of CIDR blocks.
 *
 * The greedy standard algorithm: at each step take the largest block that is
 * both aligned on the current start and no larger than what is left. Exact —
 * no block ever extends past `end`, which is the failure mode that would
 * attribute a neighbouring carrier's addresses to this one.
 *
 * Returns `[]` for a malformed or inverted range rather than throwing: an
 * import file with one bad line must load the other 900 000.
 */
export function rangeToCidrs(startRaw: string, endRaw: string, limit = 4096): string[] {
  const start = parseIp(startRaw.trim());
  const end = parseIp(endRaw.trim());
  if (!start || !end || start.version !== end.version) return [];

  const width = start.version === 4 ? 32 : 128;
  let cur = ipToBig(start);
  const last = ipToBig(end);
  if (cur > last) return [];

  const out: string[] = [];
  while (cur <= last && out.length < limit) {
    // Largest block aligned here…
    const aligned = lowestSetBit(cur, width);
    // …and no bigger than the remaining span.
    const remaining = last - cur + 1n;
    const spanBits = Math.min(aligned, bitLength(remaining) - 1);
    const size = 1n << BigInt(spanBits);
    out.push(`${bigToIp(cur, start.version)}/${width - spanBits}`);
    cur += size;
  }
  return out;
}

// ============================================================================
// 2. Import parsing
// ============================================================================

export interface ParsedAsnRange {
  prefix: string;
  asn: number;
  asOrg: string | null;
  country: string | null;
  region: string | null;
}

const MAX_ASN = 4294967295;

/**
 * Parse ONE line of an ASN dataset. Two accepted shapes, tab- or
 * whitespace-separated:
 *
 *   `1.0.0.0  1.0.0.255  13335  US  CLOUDFLARENET`   (start / end / asn / cc / org)
 *   `185.12.64.0/22  2200  FR  RENATER  FR-IDF`      (cidr / asn / cc / org / region)
 *
 * Lines starting with `#` and blank lines yield `[]`. A line that does not
 * parse yields `[]` too and is counted as rejected — never guessed at.
 */
export function parseAsnRangeLine(line: string): ParsedAsnRange[] {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return [];
  const f = trimmed.split(/[\t,;]|\s{1,}/).filter((s) => s.length > 0);
  if (f.length < 2) return [];

  const cidrForm = f[0].includes('/');
  const asnRaw = cidrForm ? f[1] : f[2];
  const asn = Number.parseInt((asnRaw ?? '').replace(/^AS/i, ''), 10);
  if (!Number.isInteger(asn) || asn <= 0 || asn > MAX_ASN) return [];

  const country = normaliseCountry(cidrForm ? f[2] : f[3]);
  const asOrg = clamp(cidrForm ? f.slice(3, 4).join(' ') : f.slice(4).join(' '), 128);
  const region = clamp(cidrForm ? f.slice(4).join(' ') : null, 64);

  const prefixes = cidrForm ? [f[0]] : rangeToCidrs(f[0], f[1]);
  return prefixes.map((prefix) => ({ prefix, asn, asOrg, country, region }));
}

function clamp(value: string | null | undefined, max: number): string | null {
  if (!value) return null;
  const s = value.trim();
  return s.length === 0 ? null : s.slice(0, max);
}

function normaliseCountry(value: string | null | undefined): string | null {
  if (!value) return null;
  const s = value.trim().toUpperCase();
  return /^[A-Z]{2}$/.test(s) ? s : null;
}

// ============================================================================
// 3. Loading
// ============================================================================

export interface ImportOutcome {
  importId: number;
  loaded: number;
  rejected: number;
  label: string;
}

/**
 * Load ranges into `ip_asn_ranges`.
 *
 * LAST WRITER WINS, EXPLICITLY. `ON CONFLICT (prefix) DO UPDATE` — two datasets
 * disagreeing about the origin of a prefix must not produce two rows, because
 * longest-prefix match would then be a coin flip and the same site would be
 * attributed to two carriers on two consecutive scans.
 *
 * The whole load is ONE transaction with the journal row: a half-loaded table
 * that claims to be a complete import is worse than no import.
 */
export async function importAsnRanges(
  ranges: readonly ParsedAsnRange[],
  opts: { label: string; source?: AsnRangeSource; userId?: number | null; rejected?: number },
): Promise<ImportOutcome> {
  const source: AsnRangeSource = opts.source ?? 'import';
  if (!ASN_RANGE_SOURCES.includes(source)) {
    throw new Error(`Unknown ASN range source "${source}"`);
  }
  const label = opts.label.trim().slice(0, 255) || 'unlabelled';

  const outcome = await db.transaction(async (trx) => {
    let loaded = 0;
    const BATCH = 1000;
    for (let i = 0; i < ranges.length; i += BATCH) {
      const chunk = ranges.slice(i, i + BATCH).map((r) => ({
        prefix: trx.raw('?::cidr', [r.prefix]),
        asn: r.asn,
        as_org: r.asOrg,
        country: r.country,
        region: r.region,
        source,
        updated_at: trx.fn.now(),
      }));
      if (chunk.length === 0) continue;
      await trx('ip_asn_ranges')
        .insert(chunk)
        .onConflict('prefix')
        .merge(['asn', 'as_org', 'country', 'region', 'source', 'updated_at']);
      loaded += chunk.length;
    }

    const [row] = await trx('weather_asn_imports')
      .insert({
        source,
        label,
        rows_loaded: loaded,
        rows_rejected: opts.rejected ?? 0,
        imported_by: opts.userId ?? null,
      })
      .returning<Array<{ id: string | number }>>('id');

    return { importId: Number(row.id), loaded, rejected: opts.rejected ?? 0, label };
  });

  // The whole point of the cache is that the table does not change often. When
  // it does, everything cached before is a stale attribution.
  clearAsnCache();
  logger.info(outcome, 'ASN ranges imported (offline enrichment table refreshed)');
  return outcome;
}

/** Parse a whole dataset and load it. Returns the rejected count honestly. */
export async function importAsnDataset(
  text: string,
  opts: { label: string; source?: AsnRangeSource; userId?: number | null },
): Promise<ImportOutcome> {
  const ranges: ParsedAsnRange[] = [];
  let rejected = 0;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const parsed = parseAsnRangeLine(line);
    if (parsed.length === 0) rejected++;
    else ranges.push(...parsed);
  }
  return importAsnRanges(ranges, { ...opts, rejected });
}

// ============================================================================
// 4. Lookup
// ============================================================================

/**
 * Cache. Negative results are cached too, and that is the important half: a
 * fleet on prefixes the table does not cover would otherwise re-scan the whole
 * GiST index for every device on every sweep, forever, to learn nothing.
 */
const cache = new LRUCache<string, AddressAttribution>({ max: 20_000, ttl: 6 * 3_600_000 });

export function clearAsnCache(): void {
  cache.clear();
}

const NO_ADDRESS: AddressAttribution = { scope: 'invalid', asn: null, reason: 'no_address' };

/**
 * Attribute one address, offline.
 *
 * `isAttributableAddress` is the gate and it runs FIRST: a `caller-id` of
 * 10.8.0.14 means the session arrived over a private transit and says nothing
 * about any carrier. Attributing it would file every MPLS customer under one
 * fictional operator and produce a permanent, confident, invented incident.
 */
export async function attributeAddress(
  raw: string | null | undefined,
): Promise<AddressAttribution> {
  if (!raw) return NO_ADDRESS;
  const key = raw.trim();
  const hit = cache.get(key);
  if (hit) return hit;

  const scope = classifyIpScope(key);
  if (!isAttributableAddress(key)) {
    const result: AddressAttribution = { scope, asn: null, reason: 'not_public' };
    cache.set(key, result);
    return result;
  }

  // Longest-prefix match. `>>=` is index-backed by the GiST opclass of
  // migration 021; `ORDER BY masklen DESC` picks the most specific announcement
  // when a /24 sits inside an aggregate /16.
  const row = await db('ip_asn_ranges')
    .whereRaw('prefix >>= ?::inet', [key.split('/')[0]])
    .orderByRaw('masklen(prefix) DESC')
    .first<
      | { prefix: string; asn: string | number; as_org: string | null; country: string | null; region: string | null }
      | undefined
    >('prefix', 'asn', 'as_org', 'country', 'region');

  const result: AddressAttribution = row
    ? {
        scope,
        reason: 'attributed',
        asn: {
          asn: Number(row.asn),
          asOrg: row.as_org,
          country: row.country,
          region: row.region,
          prefix: row.prefix,
        },
      }
    : { scope, asn: null, reason: 'no_covering_prefix' };

  cache.set(key, result);
  return result;
}

export interface AsnTableStatus {
  ranges: number;
  lastImport: {
    id: number;
    label: string;
    source: AsnRangeSource;
    rowsLoaded: number;
    rowsRejected: number;
    importedAt: string;
  } | null;
}

/**
 * "How old is this attribution?" — the question decision 4 of migration 021
 * promised an answer to. Global, like the table: it carries no customer datum.
 */
export async function getAsnTableStatus(): Promise<AsnTableStatus> {
  const [{ count }] = await db('ip_asn_ranges').count<Array<{ count: string }>>('* as count');
  const last = await db('weather_asn_imports')
    .orderBy('imported_at', 'desc')
    .first<
      | {
          id: string | number;
          label: string;
          source: AsnRangeSource;
          rows_loaded: number;
          rows_rejected: number;
          imported_at: Date;
        }
      | undefined
    >('id', 'label', 'source', 'rows_loaded', 'rows_rejected', 'imported_at');

  return {
    ranges: Number(count),
    lastImport: last
      ? {
          id: Number(last.id),
          label: last.label,
          source: last.source,
          rowsLoaded: last.rows_loaded,
          rowsRejected: last.rows_rejected,
          importedAt: new Date(last.imported_at).toISOString(),
        }
      : null,
  };
}
