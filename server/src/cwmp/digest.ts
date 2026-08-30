/**
 * ObliWAN — HTTP Digest for the CWMP listener, done by hand.
 *
 * ┌─ WHY BY HAND, AND WHY HA1 RATHER THAN A PASSWORD ─────────────────────────┐
 * │ The ACS never needs the CPE's password. Digest is defined over            │
 * │ HA1 = MD5(username:realm:password), so storing HA1 is enough to verify a  │
 * │ response and means the plaintext exists for exactly as long as it takes   │
 * │ to enrol the device — after which it is shown once to the operator and    │
 * │ forgotten. That is §8.2 applied to the one credential the ACS owns.       │
 * │                                                                           │
 * │ HA1 is nonetheless PASSWORD-EQUIVALENT for this realm: whoever has it can │
 * │ authenticate. It is therefore stored ENCRYPTED (`acs_auth_ha1_enc`,       │
 * │ migration 015 decision 7), not as a bare hash the way an .htdigest would. │
 * │                                                                           │
 * │ MD5 is not a choice. TR-069 CPEs implement RFC 2617 MD5 Digest and        │
 * │ nothing else; offering SHA-256 gets you a CPE that ignores the challenge  │
 * │ and retries the same unauthenticated request until its retry budget runs  │
 * │ out. The mitigation is that the credential protects an inbound listener   │
 * │ whose worst case is a forged Inform, and that forged Informs cannot       │
 * │ enrol a device (`allow_auto_enroll` defaults to false, migration 015).    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE NONCE IS STATELESS, ON PURPOSE ──────────────────────────────────────┐
 * │ `OBLIWAN_ROLE=web` may run several replicas (A5) and a CPE's retry can    │
 * │ land on a different one than the challenge did. A nonce held in a Map     │
 * │ would then be unknown, the ACS would challenge again, and a CPE with a    │
 * │ retry budget of three would give up — intermittently, under load, which   │
 * │ is the worst possible failure to diagnose.                                │
 * │                                                                           │
 * │ So the nonce CARRIES its own proof: `<expiry>:<HMAC(expiry:ip)>`. Any     │
 * │ replica can verify it, nothing has to be shared, and an expired one is    │
 * │ rejected by arithmetic rather than by eviction.                           │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ …WHICH IS WHY THE REPLAY BOUND HAD TO BE WRITTEN DOWN SOMEWHERE ─────────┐
 * │ This header used to end with "replay within the window is bounded by the  │
 * │ `nc` counter recorded on the session row". There was no such counter, no  │
 * │ such column, and no comparison: `verifyDigest` read `creds.nc` only to    │
 * │ feed it to the hash. The listener is plain HTTP by design (§6.2 — the     │
 * │ fleet was provisioned with `http://` ACS URLs), so anyone on the path     │
 * │ could capture one `Authorization: Digest …` header and re-POST it for the │
 * │ next 300 seconds to open an authenticated session. A guard that exists    │
 * │ only in a comment is worse than an absent one, because the next reader    │
 * │ greps it, finds the sentence, and stops looking.                          │
 * │                                                                          │
 * │ It exists now, and it is NOT on the session row: the Inform IS the        │
 * │ authentication exchange and the session row is created AFTER it, so a     │
 * │ replay simply opens a second session and a per-session counter never sees │
 * │ it. The record lives on `cwmp_devices.auth_nonce_seen` (migration 023),   │
 * │ the one row both the original and the replay resolve to, and the rule is  │
 * │ `claimDigestNonce` in `device.service.ts`: a `(nonce, nc)` pair is        │
 * │ accepted at most once. `NONCE_TTL_MS` bounds the set — an entry is        │
 * │ dropped as soon as its own nonce has expired, because from that moment    │
 * │ `nonceIsValid` refuses it anyway.                                         │
 * │                                                                          │
 * │ A CPE that ignores `qop` sends no `nc` at all (RFC 2069 shape). Those are │
 * │ read as `nc = 0`, which makes the header exactly single-use: an honest    │
 * │ box that retries after a lost response gets `stale=true` and one extra    │
 * │ round trip, the same cost as an aged-out nonce, and no CPE prompt.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import crypto from 'crypto';
import { config } from '../config';

/** How long a nonce stays valid. Long enough for a CPE on a slow line to
 *  retry, short enough that a captured Authorization header is worthless by
 *  the time it is replayed from somewhere else. */
const NONCE_TTL_MS = 5 * 60_000;

/**
 * Key for the nonce HMAC.
 *
 * Derived from `SESSION_SECRET` and NOT from `OBLIWAN_ENCRYPTION_KEY`. That is
 * the opposite of the rule everywhere else in this codebase, and it is
 * deliberate: risk R8 says a credential must not depend on a rotatable secret
 * because rotating it makes stored ciphertext unreadable. Nothing is STORED
 * here. Rotating `SESSION_SECRET` invalidates in-flight nonces, every CPE gets
 * one extra 401, and the fleet reauthenticates. The vault key, by contrast, is
 * the one thing that must never be spent on something disposable.
 */
function nonceKey(): Buffer {
  return crypto.createHash('sha256').update(`${config.sessionSecret}:cwmp-nonce`).digest();
}

export function makeNonce(clientIp: string, now: number = Date.now()): string {
  const expiry = now + NONCE_TTL_MS;
  const mac = crypto
    .createHmac('sha256', nonceKey())
    .update(`${expiry}:${clientIp}`)
    .digest('base64url')
    .slice(0, 32);
  return `${expiry}.${mac}`;
}

/**
 * The instant a nonce stops being accepted, read back out of the nonce itself.
 *
 * `null` when the string is not shaped like one of ours. Used by
 * `claimDigestNonce` to know when a replay record may be forgotten: past that
 * instant `nonceIsValid` refuses the nonce on arithmetic alone, so keeping the
 * record would only grow a column.
 */
export function nonceExpiry(nonce: string): number | null {
  const dot = nonce.indexOf('.');
  if (dot <= 0) return null;
  const expiry = Number(nonce.slice(0, dot));
  return Number.isFinite(expiry) ? expiry : null;
}

/**
 * The `nc` a CPE sent, as a number.
 *
 * RFC 2617 writes it as EIGHT hex digits and increments it per request made
 * with the same nonce. Absent (a CPE that ignored our `qop="auth"` and answered
 * in the RFC 2069 shape) reads as 0 — see the replay block in the header: it
 * makes that CPE's header single-use rather than unbounded.
 *
 * Anything unparseable also reads as 0. It cannot be used to slip past the
 * bound: `claimDigestNonce` refuses a `(nonce, nc)` pair it has already seen,
 * and a garbage `nc` collapses onto the same 0 every time.
 */
export function digestNc(nc: string | undefined): number {
  if (!nc) return 0;
  const n = Number.parseInt(nc.trim(), 16);
  return Number.isSafeInteger(n) && n >= 0 ? n : 0;
}

export function nonceIsValid(nonce: string, clientIp: string, now: number = Date.now()): boolean {
  const dot = nonce.indexOf('.');
  if (dot <= 0) return false;
  const expiry = Number(nonce.slice(0, dot));
  if (!Number.isFinite(expiry) || expiry < now) return false;
  const expected = crypto
    .createHmac('sha256', nonceKey())
    .update(`${expiry}:${clientIp}`)
    .digest('base64url')
    .slice(0, 32);
  const given = nonce.slice(dot + 1);
  // Constant-time: the nonce is not a secret, but a timing oracle on it would
  // let an attacker forge one, and the comparison costs nothing.
  return (
    given.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected))
  );
}

// ============================================================================
// Challenge
// ============================================================================

export function buildChallenge(realm: string, clientIp: string): string {
  return (
    `Digest realm="${escapeHeader(realm)}", ` +
    `qop="auth", ` +
    `nonce="${makeNonce(clientIp)}", ` +
    `opaque="${crypto.randomBytes(8).toString('hex')}", ` +
    `algorithm=MD5`
  );
}

// ============================================================================
// Verification
// ============================================================================

export interface DigestCredentials {
  scheme: 'digest' | 'basic' | 'unknown';
  username: string;
  realm?: string;
  nonce?: string;
  uri?: string;
  qop?: string;
  nc?: string;
  cnonce?: string;
  response?: string;
  /** Basic only — the plaintext password the CPE sent. */
  password?: string;
}

/**
 * Parse an `Authorization` header.
 *
 * Returns `scheme: 'basic'` rather than throwing when a CPE sends Basic. That
 * is the `basicAuthOnly` quirk, and the ACS answers it with a clear refusal
 * (recorded on the device) instead of a fourth 401 that would make the operator
 * believe the credential is wrong.
 */
export function parseAuthorization(header: string | undefined): DigestCredentials | null {
  if (!header) return null;
  const schemeMatch = /^\s*(\w+)\s+/.exec(header);
  if (!schemeMatch) return null;
  const scheme = schemeMatch[1].toLowerCase();
  const rest = header.slice(schemeMatch[0].length);

  if (scheme === 'basic') {
    let decoded = '';
    try {
      decoded = Buffer.from(rest.trim(), 'base64').toString('utf8');
    } catch {
      return null;
    }
    const sep = decoded.indexOf(':');
    return {
      scheme: 'basic',
      username: sep === -1 ? decoded : decoded.slice(0, sep),
      password: sep === -1 ? '' : decoded.slice(sep + 1),
    };
  }

  if (scheme !== 'digest') return { scheme: 'unknown', username: '' };

  const parts: Record<string, string> = {};
  for (const m of rest.matchAll(/(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))/g)) {
    parts[m[1].toLowerCase()] = m[2] ?? m[3];
  }
  return {
    scheme: 'digest',
    username: parts.username ?? '',
    realm: parts.realm,
    nonce: parts.nonce,
    uri: parts.uri,
    qop: parts.qop,
    nc: parts.nc,
    cnonce: parts.cnonce,
    response: parts.response,
  };
}

/** HA1 = MD5(username:realm:password). Produced ONCE, at enrolment. */
export function computeHa1(username: string, realm: string, password: string): string {
  return md5(`${username}:${realm}:${password}`);
}

export interface VerifyResult {
  ok: boolean;
  /** Why not, for the log and for the operator. Never echoes the credential. */
  reason?: 'no_credentials' | 'wrong_scheme' | 'stale_nonce' | 'bad_response' | 'uri_mismatch';
  /** True when the nonce simply aged out: the CPE is honest, it just needs a
   *  fresh challenge. RFC 2617 calls this `stale=true` and a CPE that gets it
   *  retries silently instead of prompting. */
  stale?: boolean;
}

/**
 * Verify a Digest response against a stored HA1.
 *
 * The `uri` check matters more here than in a browser context: the ACS routes
 * on `POST /<tenant_slug>`, so a response computed for another tenant's path
 * must not validate against this one. Without it, a CPE legitimately enrolled
 * in tenant A could replay its own header at tenant B's endpoint.
 */
export function verifyDigest(
  creds: DigestCredentials,
  ha1: string,
  method: string,
  requestUri: string,
  clientIp: string,
): VerifyResult {
  if (creds.scheme === 'basic') return { ok: false, reason: 'wrong_scheme' };
  if (creds.scheme !== 'digest' || !creds.response || !creds.nonce) {
    return { ok: false, reason: 'no_credentials' };
  }
  if (!nonceIsValid(creds.nonce, clientIp)) {
    return { ok: false, reason: 'stale_nonce', stale: true };
  }
  // A CPE may or may not include the query string; compare the path only.
  const givenPath = (creds.uri ?? '').split('?')[0];
  if (givenPath && givenPath !== requestUri.split('?')[0]) {
    return { ok: false, reason: 'uri_mismatch' };
  }

  const ha2 = md5(`${method}:${creds.uri ?? requestUri}`);
  const expected = creds.qop
    ? md5(`${ha1}:${creds.nonce}:${creds.nc ?? ''}:${creds.cnonce ?? ''}:${creds.qop}:${ha2}`)
    : md5(`${ha1}:${creds.nonce}:${ha2}`);

  const a = Buffer.from(creds.response.toLowerCase());
  const b = Buffer.from(expected.toLowerCase());
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'bad_response' };
  }
  return { ok: true };
}

/**
 * A password for a freshly enrolled CPE.
 *
 * Alphanumeric only, and that is not laziness. TR-069 credentials are typed
 * into vendor web UIs, echoed through menu CLIs and pasted into provisioning
 * spreadsheets; a password containing `&`, `<` or a quote gets mangled by at
 * least one of those on the way, and the failure surfaces days later as "the
 * CPE never authenticates". 32 characters of base32 alphabet is 160 bits.
 */
export function generateCpePassword(): string {
  const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(32);
  let out = '';
  for (let i = 0; i < 32; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

function md5(input: string): string {
  return crypto.createHash('md5').update(input).digest('hex');
}

function escapeHeader(value: string): string {
  return value.replace(/["\\\r\n]/g, '');
}
