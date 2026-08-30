// ============================================================================
// @obliwan/shared — NCM hashing primitives
// ============================================================================
//
// WHY A HAND-ROLLED SHA-256 AND NOT `node:crypto`.
//
// `shared/` is imported by the CLIENT bundle. Section 1.1 of
// `docs/M4-NCM-contrat.md` is explicit that `buildSemKey`, `canonicalize` and
// `mayIntersect` must be pure, dependency-free and runnable on BOTH sides —
// the client renders the diff and has to be able to re-derive a key to line a
// finding up with a resource. Importing `node:crypto` here would either break
// the Vite build or drag a crypto polyfill into the browser bundle; using
// `crypto.subtle` would make every hashing call asynchronous, which would turn
// `canonicalize()` and `computeMatchHash()` into promises and infect the whole
// parser. Neither trade is acceptable for ~90 lines of well-understood code.
//
// Cost, stated honestly: this runs at roughly 20-40 MB/s instead of the
// ~400 MB/s of the native implementation. A RouterOS `/export` normalises to a
// document well under 1 MB, so one `ncmHash` costs single-digit milliseconds
// and one `matchHash` costs microseconds. If a profile ever shows this as hot,
// the fix is to inject a hasher through `setSha256Impl` (below) from the server
// — NOT to make the shared contract depend on Node.

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const HEX = '0123456789abcdef';

function utf8Bytes(s: string): Uint8Array {
  // TextEncoder is present in Node >= 11 and in every browser we target.
  return new TextEncoder().encode(s);
}

function sha256Bytes(msg: Uint8Array): Uint8Array {
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  const bitLen = msg.length * 8;
  // Padded length: message + 0x80 + zeros + 8-byte big-endian bit length.
  const padded = new Uint8Array(((msg.length + 9 + 63) >> 6) << 6);
  padded.set(msg);
  padded[msg.length] = 0x80;
  // The length is a 64-bit big-endian value. JS numbers are exact to 2^53 and a
  // config document is nowhere near 2^50 bytes, so the high word comes from a
  // float division rather than BigInt (which would cost more than it buys).
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, hi, false);
  dv.setUint32(padded.length - 4, lo, false);

  const w = new Uint32Array(64);

  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15];
      const y = w[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h[0], b = h[1], c = h[2], d = h[3];
    let e = h[4], f = h[5], g = h[6], hh = h[7];

    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;

      hh = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }

    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = (h[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (h[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (h[i] >>> 8) & 0xff;
    out[i * 4 + 3] = h[i] & 0xff;
  }
  return out;
}

export type Sha256Impl = (input: string) => string;

let sha256Override: Sha256Impl | null = null;

/**
 * Escape hatch for the server: swap in `node:crypto` if a profile ever proves
 * the portable implementation is hot. It MUST produce lowercase hex of the
 * SHA-256 of the UTF-8 bytes of the input — anything else silently reshuffles
 * every `sem_key` in the database, which is a `semKeyGeneration` bump in
 * disguise (§8.4). Exposed for benchmarking, not for behaviour changes.
 */
export function setSha256Impl(impl: Sha256Impl | null): void {
  sha256Override = impl;
}

/** Lowercase hex SHA-256 of the UTF-8 encoding of `input`. 64 characters. */
export function sha256Hex(input: string): string {
  if (sha256Override) return sha256Override(input);
  const digest = sha256Bytes(utf8Bytes(input));
  let out = '';
  for (let i = 0; i < digest.length; i++) {
    out += HEX[digest[i] >>> 4] + HEX[digest[i] & 0x0f];
  }
  return out;
}

/** The 16-hex-char truncation used by `matchHash` and `payloadHash`. */
export function sha256Short(input: string): string {
  return sha256Hex(input).slice(0, 16);
}

/**
 * Deterministic JSON: object keys sorted by UTF-16 code unit, no whitespace,
 * `undefined` members dropped exactly as `JSON.stringify` drops them (so
 * `{a: undefined}` and `{}` hash identically instead of diverging).
 *
 * ARRAY ORDER IS PRESERVED. Sorting the arrays of the unordered resource kinds
 * is the caller's job (`canonicalize` in canonical.ts), because only the caller
 * knows which arrays carry meaning in their order — see ORDERED_RESOURCE_KINDS.
 *
 * Numbers: non-finite values are rejected rather than serialised as `null`,
 * because a silent NaN inside a hashed document is a stability bug that no unit
 * test would ever see (risk N-R3).
 */
export function canonicalJson(value: unknown): string {
  return enc(value);
}

function enc(v: unknown): string {
  if (v === null || v === undefined) return 'null';
  const t = typeof v;
  if (t === 'string') return JSON.stringify(v);
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(v as number)) {
      throw new Error(`canonicalJson: non-finite number (${String(v)})`);
    }
    // `-0` and `0` must serialise identically; JSON.stringify already does that.
    return JSON.stringify(v);
  }
  if (t === 'bigint') throw new Error('canonicalJson: bigint is not representable');
  if (Array.isArray(v)) return `[${v.map(enc).join(',')}]`;
  if (t === 'object') {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).sort();
    const parts: string[] = [];
    for (const k of keys) {
      if (o[k] === undefined) continue;
      parts.push(`${JSON.stringify(k)}:${enc(o[k])}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new Error(`canonicalJson: unsupported type ${t}`);
}
