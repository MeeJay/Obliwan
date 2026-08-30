// ============================================================================
// @obliwan/shared — NCM primitives
// ============================================================================
//
// Implements §2.1 and §3.3 of `docs/M4-NCM-contrat.md`.
//
// Every selector value in the NCM is a TAGGED STRING, never a nested object.
// Rationale (decision, not style): `config_snapshots.ncm` carries a GIN
// `jsonb_path_ops` index, and containment (`@>`) over arrays of SCALARS is the
// only pattern that index accelerates. Fleet Query (K5) is built on exactly
// that operator, so the shape of a selector is a performance decision.
//
//   'any'                      the selector is absent / matches everything
//   'cidr:10.0.0.0/24'         canonical CIDR, host bits zeroed, v6 lowercased
//   'ip:203.0.113.7'           single address (never emitted as /32)
//   'range:10.0.0.1-10.0.0.9'  inclusive range
//   'ref:WAN'                  unresolved named object (address list, zone
//                              object, service group) — NEVER silently expanded
//   'iface:ether1'             interface by device-local name
//   'ifaceList:WAN'            RouterOS interface list / brand equivalent
//   'mac:aa:bb:cc:dd:ee:ff'    lowercase, colon-separated
//   'fqdn:vpn.example.net'     lowercased DNS name

import { z } from 'zod';

export const SELECTOR_ATOM_TAGS = [
  'any', 'cidr', 'ip', 'range', 'ref', 'iface', 'ifaceList', 'mac', 'fqdn',
] as const;
export type SelectorAtomTag = (typeof SELECTOR_ATOM_TAGS)[number];

export const SelectorAtom = z
  .string()
  .min(3)
  .max(200)
  .regex(
    /^(any|(cidr|ip|range|ref|iface|ifaceList|mac|fqdn):[^\s]+)$/,
    'selector atom must be "any" or "<tag>:<value>"',
  );
export type SelectorAtom = z.infer<typeof SelectorAtom>;

/**
 * A selector is a SORTED, DEDUPLICATED array of atoms.
 * `['any']` and `[]` are collapsed to `['any']` by the normalizer — the two must
 * never coexist, because RouterOS `/export` omits a default `src-address` while
 * the API returns it, and that single asymmetry is enough to make every rule of
 * the fleet look changed when the collection transport switches. That is the
 * documented number-one source of false drift (§3.3 rule 1).
 */
export const Selector = z.array(SelectorAtom).min(1);
export type Selector = z.infer<typeof Selector>;

/** The canonical "matches everything" selector. */
export const ANY_SELECTOR: Selector = ['any'];

/** Merged, sorted, non-overlapping inclusive port intervals. `null` = any. */
export const PortSet = z
  .array(z.tuple([z.number().int().min(0).max(65535), z.number().int().min(0).max(65535)]))
  .nullable();
export type PortSet = z.infer<typeof PortSet>;

/**
 * Lowercase protocol name; numeric protocols are mapped through a fixed table,
 * unknown numbers stay as `proto-<n>`. `null` = any.
 */
export const Protocol = z.string().regex(/^([a-z0-9]+|proto-\d{1,3})$/).nullable();
export type Protocol = z.infer<typeof Protocol>;

/** §3.3 rule 5. Fixed, never extended at runtime: a moving table would change
 *  every `matchHash` that contains a numeric protocol. */
export const PROTOCOL_NUMBERS: Readonly<Record<number, string>> = {
  1: 'icmp', 2: 'igmp', 6: 'tcp', 17: 'udp', 41: 'ipv6', 47: 'gre',
  50: 'esp', 51: 'ah', 58: 'icmpv6', 89: 'ospf', 103: 'pim', 112: 'vrrp',
  132: 'sctp', 137: 'mpls-in-ip',
};

/** Canonical L3/L4 zone vocabulary. Brands with no zone model (MikroTik) emit
 *  `null`; brands that have one (DrayTek / Zyxel / SonicWall) map their zone
 *  name here so a cross-brand `matchHash` is comparable. */
export const Zone = z.string().min(1).max(64).nullable();
export type Zone = z.infer<typeof Zone>;

/**
 * A secret NEVER enters the NCM (risk R10, §8.2 of ARCHITECTURE.md). What
 * enters is a keyed fingerprint, so "the PSK changed" is detectable without the
 * platform ever writing the PSK to a diffable store.
 *
 *   value = base64url( HMAC-SHA256( tenantFingerprintKey, purpose || rawSecret ) )[0..22]
 *
 * The key is per-tenant and derived from OBLIWAN_ENCRYPTION_KEY: two tenants
 * with the same weak PSK must not be linkable through the snapshot store.
 * (Open arbitration Q5 — per-tenant is what the contract encodes today.)
 *
 * The derivation itself lives on the SERVER: it needs the tenant key, which the
 * client must never hold. `shared` only owns the SHAPE.
 */
export const SecretFingerprint = z.object({
  algo: z.literal('hmac-sha256/v1'),
  /** null when the brand cannot report the secret at all (show-sensitive=no). */
  fp: z.string().length(22).nullable(),
  /** true when the value was unavailable, so `fp: null` means "unknown", NOT
   *  "empty password". The diff must never read the two as equal. */
  unavailable: z.boolean(),
}).strict();
export type SecretFingerprint = z.infer<typeof SecretFingerprint>;

/** The value a parser emits when `/export show-sensitive=no` hid the secret —
 *  which, per R10, is ALWAYS the case for MikroTik. */
export const UNAVAILABLE_SECRET: SecretFingerprint = {
  algo: 'hmac-sha256/v1',
  fp: null,
  unavailable: true,
};

// ============================================================================
// Address arithmetic — the substrate of `cidr:` atoms and of `mayIntersect`
// ============================================================================
//
// No dependency. `ip-address` is a server-side package and this module has to
// run in the browser too (the diff view resolves overlaps to explain a `moved`).

export interface ParsedIp {
  version: 4 | 6;
  /** 4 or 16 bytes, network order. */
  bytes: Uint8Array;
}

export interface ParsedCidr extends ParsedIp {
  /** 0..32 for v4, 0..128 for v6. */
  prefix: number;
}

const V4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Parses a bare IPv4 or IPv6 literal. Returns null on anything malformed —
 *  the caller decides whether that is a `ref:` or an error. */
export function parseIp(input: string): ParsedIp | null {
  const s = input.trim();
  if (!s) return null;

  const m4 = V4_RE.exec(s);
  if (m4) {
    const b = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      const part = m4[i + 1];
      // Reject '01' style: RouterOS never emits it, and accepting it would let
      // two spellings of one address produce two different atoms.
      if (part.length > 1 && part[0] === '0') return null;
      const n = Number(part);
      if (n > 255) return null;
      b[i] = n;
    }
    return { version: 4, bytes: b };
  }

  return parseIpv6(s);
}

function parseIpv6(input: string): ParsedIp | null {
  let s = input.toLowerCase();
  // Zone index (fe80::1%ether1) is device-local state, not an address.
  const pct = s.indexOf('%');
  if (pct >= 0) s = s.slice(0, pct);
  if (!/^[0-9a-f:.]*$/.test(s) || s.length === 0) return null;

  // An embedded IPv4 tail (::ffff:192.0.2.1) is expanded to two hextets first.
  const lastColon = s.lastIndexOf(':');
  if (s.includes('.')) {
    const tail = s.slice(lastColon + 1);
    const v4 = V4_RE.exec(tail);
    if (!v4) return null;
    const b = parseIp(tail);
    if (!b || b.version !== 4) return null;
    const hi = ((b.bytes[0] << 8) | b.bytes[1]).toString(16);
    const lo = ((b.bytes[2] << 8) | b.bytes[3]).toString(16);
    s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const dbl = s.indexOf('::');
  if (dbl !== s.lastIndexOf('::')) return null;

  let headParts: string[];
  let tailParts: string[];
  if (dbl >= 0) {
    const head = s.slice(0, dbl);
    const tail = s.slice(dbl + 2);
    headParts = head ? head.split(':') : [];
    tailParts = tail ? tail.split(':') : [];
  } else {
    headParts = s.split(':');
    tailParts = [];
  }
  if (headParts.some((p) => p === '') || tailParts.some((p) => p === '')) return null;
  const total = headParts.length + tailParts.length;
  if (dbl < 0 ? total !== 8 : total > 7) return null;

  const groups: number[] = [];
  const push = (p: string): boolean => {
    if (p.length > 4 || !/^[0-9a-f]+$/.test(p)) return false;
    groups.push(parseInt(p, 16));
    return true;
  };
  for (const p of headParts) if (!push(p)) return null;
  if (dbl >= 0) for (let i = total; i < 8; i++) groups.push(0);
  for (const p of tailParts) if (!push(p)) return null;
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (groups[i] >>> 8) & 0xff;
    bytes[i * 2 + 1] = groups[i] & 0xff;
  }
  return { version: 6, bytes };
}

/** RFC 5952 output for v6 (lowercase, longest run of zeroes compressed once),
 *  dotted quad for v4. */
export function formatIp(ip: ParsedIp): string {
  if (ip.version === 4) return Array.from(ip.bytes).join('.');

  const g: number[] = [];
  for (let i = 0; i < 8; i++) g.push((ip.bytes[i * 2] << 8) | ip.bytes[i * 2 + 1]);

  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] === 0) {
      if (curStart < 0) curStart = i;
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  // RFC 5952: a single zero group is NOT compressed.
  if (bestLen < 2) return g.map((x) => x.toString(16)).join(':');

  const head = g.slice(0, bestStart).map((x) => x.toString(16)).join(':');
  const tail = g.slice(bestStart + bestLen).map((x) => x.toString(16)).join(':');
  return `${head}::${tail}`;
}

/** Parses `addr/prefix` or a bare address (implicit host prefix). */
export function parseCidr(input: string): ParsedCidr | null {
  const s = input.trim();
  const slash = s.lastIndexOf('/');
  const addrPart = slash >= 0 ? s.slice(0, slash) : s;
  const ip = parseIp(addrPart);
  if (!ip) return null;
  const width = ip.version === 4 ? 32 : 128;
  if (slash < 0) return { ...ip, prefix: width };
  const raw = s.slice(slash + 1);
  if (!/^\d{1,3}$/.test(raw)) return null;
  const prefix = Number(raw);
  if (prefix > width) return null;
  return { ...ip, prefix };
}

function maskBytes(bytes: Uint8Array, prefix: number): Uint8Array {
  const out = new Uint8Array(bytes.length);
  out.set(bytes);
  for (let i = 0; i < out.length; i++) {
    const bitsBefore = i * 8;
    if (prefix >= bitsBefore + 8) continue;
    if (prefix <= bitsBefore) { out[i] = 0; continue; }
    const keep = prefix - bitsBefore;
    out[i] &= (0xff << (8 - keep)) & 0xff;
  }
  return out;
}

/**
 * §3.3 rule 2 — canonical CIDR: host bits zeroed, IPv6 compressed and
 * lowercased. Returns null when the input is not an address at all.
 *
 * `preserveHost` is for interface addresses, where `10.0.0.1/24` means "this
 * box is .1 in that /24" and zeroing the host bits would destroy the config.
 */
export function canonicalizeCidr(input: string, preserveHost = false): string | null {
  const c = parseCidr(input);
  if (!c) return null;
  const bytes = preserveHost ? c.bytes : maskBytes(c.bytes, c.prefix);
  return `${formatIp({ version: c.version, bytes })}/${c.prefix}`;
}

/**
 * §3.3 rule 2 — an address-shaped value becomes a selector atom:
 *   `0.0.0.0/0` and `::/0` collapse to `any`
 *   a host prefix (/32, /128) becomes `ip:<addr>` and NEVER `cidr:<addr>/32`
 *   anything unparsable becomes `ref:<value>` — a named object we refuse to
 *   expand silently (§3.3 rule 8)
 */
export function addressAtom(input: string): SelectorAtom {
  const raw = input.trim();
  const c = parseCidr(raw);
  if (!c) return `ref:${raw}`;
  const width = c.version === 4 ? 32 : 128;
  if (c.prefix === 0) return 'any';
  const bytes = c.prefix === width ? c.bytes : maskBytes(c.bytes, c.prefix);
  const addr = formatIp({ version: c.version, bytes });
  return c.prefix === width ? `ip:${addr}` : `cidr:${addr}/${c.prefix}`;
}

/** `range:a-b` with both bounds canonicalised. Falls back to `ref:` when either
 *  side is not an address. */
export function rangeAtom(from: string, to: string): SelectorAtom {
  const a = parseIp(from.trim());
  const b = parseIp(to.trim());
  if (!a || !b || a.version !== b.version) return `ref:${from.trim()}-${to.trim()}`;
  return `range:${formatIp(a)}-${formatIp(b)}`;
}

/** Lowercased, colon-separated. Accepts `-` and `.` separators on input. */
export function macAtom(input: string): SelectorAtom {
  const hex = input.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (hex.length !== 12) return `ref:${input.trim()}`;
  return `mac:${(hex.match(/.{2}/g) as string[]).join(':')}`;
}

// ============================================================================
// Selector and port-set normalisation (§3.3)
// ============================================================================

/**
 * Sort, deduplicate, and collapse to `['any']`. An EMPTY input yields
 * `['any']`: an absent selector means "matches everything", and the whole
 * anti-noise budget of §5.4 depends on that equivalence being applied here and
 * nowhere else.
 *
 * `any` is absorbing: `['any','cidr:10.0.0.0/8']` collapses to `['any']`,
 * because a selector that already matches everything is not narrowed by also
 * listing a subset.
 */
export function normalizeSelector(atoms: readonly string[]): Selector {
  if (atoms.length === 0) return ANY_SELECTOR;
  const set = new Set<string>();
  for (const a of atoms) {
    const t = a.trim();
    if (!t) continue;
    if (t === 'any') return ANY_SELECTOR;
    set.add(t);
  }
  if (set.size === 0) return ANY_SELECTOR;
  return Array.from(set).sort();
}

/**
 * §3.3 rule 3 — merge and sort inclusive port intervals. Adjacent intervals are
 * merged (`[80,80]` + `[81,81]` -> `[80,81]`) so that two spellings of one port
 * range cannot produce two `matchHash` values.
 *
 * Returns `null` for an empty input, which is the encoding of "any port".
 */
export function normalizePortSet(
  intervals: readonly (readonly [number, number])[] | null | undefined,
): PortSet {
  if (!intervals || intervals.length === 0) return null;
  const norm = intervals
    .map(([a, b]) => (a <= b ? [a, b] : [b, a]) as [number, number])
    .filter(([a, b]) => Number.isInteger(a) && Number.isInteger(b) && a >= 0 && b <= 65535)
    .sort((x, y) => (x[0] - y[0]) || (x[1] - y[1]));
  if (norm.length === 0) return null;

  const out: [number, number][] = [norm[0]];
  for (let i = 1; i < norm.length; i++) {
    const last = out[out.length - 1];
    const cur = norm[i];
    if (cur[0] <= last[1] + 1) last[1] = Math.max(last[1], cur[1]);
    else out.push(cur);
  }
  // The full range is "any", and must be encoded the same way an absent port
  // selector is — same reason as `['any']` for selectors.
  if (out.length === 1 && out[0][0] === 0 && out[0][1] === 65535) return null;
  return out;
}

/** Parses a brand port expression (`80,443,8000-8010`) into a normalised set.
 *  Named services that do not resolve to numbers make the whole expression
 *  unparsable, and the caller must fall back to a `ref:` in `unmodeledMatch`. */
export function parsePortExpression(expr: string): PortSet | 'unparsable' {
  const parts = expr.split(',').map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0) return null;
  const acc: [number, number][] = [];
  for (const p of parts) {
    const dash = p.indexOf('-');
    if (dash > 0) {
      const a = Number(p.slice(0, dash));
      const b = Number(p.slice(dash + 1));
      if (!Number.isInteger(a) || !Number.isInteger(b)) return 'unparsable';
      acc.push([a, b]);
    } else {
      const n = Number(p);
      if (!Number.isInteger(n)) return 'unparsable';
      acc.push([n, n]);
    }
  }
  return normalizePortSet(acc);
}

/** §3.3 rule 5 — numeric protocol to canonical name, unknown numbers preserved
 *  as `proto-<n>` so the information is never lost. */
export function normalizeProtocol(input: string | number | null | undefined): Protocol {
  if (input === null || input === undefined || input === '') return null;
  const s = String(input).trim().toLowerCase();
  if (s === 'any' || s === 'all') return null;
  if (/^\d{1,3}$/.test(s)) {
    const n = Number(s);
    return PROTOCOL_NUMBERS[n] ?? `proto-${n}`;
  }
  return s.replace(/[^a-z0-9]/g, '');
}

/** §3.3 rule 4 — a set-valued match token list, lowercased, deduplicated,
 *  sorted. `connection-state=related,established` and
 *  `connection-state=established,related` must hash identically. */
export function normalizeTokenSet(input: readonly string[] | string | null | undefined): string[] {
  if (input === null || input === undefined) return [];
  const raw = typeof input === 'string' ? input.split(',') : input;
  const set = new Set<string>();
  for (const t of raw) {
    const v = t.trim().toLowerCase();
    if (v) set.add(v);
  }
  return Array.from(set).sort();
}

/** §3.3 rule 6 — RouterOS `yes/no`, REST `true/false`, SNMP `1/2`. Returns
 *  `null` on anything else so a parser cannot invent `false` from noise. */
export function normalizeBoolean(input: unknown): boolean | null {
  if (typeof input === 'boolean') return input;
  if (typeof input === 'number') return input === 1 ? true : input === 0 ? false : null;
  if (typeof input !== 'string') return null;
  const s = input.trim().toLowerCase();
  if (s === 'yes' || s === 'true' || s === '1' || s === 'on' || s === 'enabled') return true;
  if (s === 'no' || s === 'false' || s === '0' || s === 'off' || s === 'disabled') return false;
  return null;
}
