// ObliWAN client — the "do not paint that" guard (spec §8.2, risk R10).
//
// The contract is unambiguous: `/export show-sensitive=no` is hard-wired, the
// service account is stripped of the `sensitive` policy, the NCM stores
// `SecretFingerprint` objects instead of values, and the snapshot, the diff,
// the plan and the audit trail only ever see the redacted version. Redaction is
// therefore a SERVER guarantee, and this file does not pretend otherwise.
//
// It exists because the client is nonetheless the last place a leak can be
// caught before it reaches a screen, a screenshot or a support ticket — and
// because a guarantee nobody verifies is a guarantee that silently stops
// holding the day a parser gains a new field. §8.2 lists two doors that are
// still open by construction: `NcmDocument.extensions` (unversioned brand data)
// and the `raw_gz` archive of a future brand whose export has no
// `show-sensitive` equivalent at all.
//
// ── THE RULE THIS FILE OBEYS ────────────────────────────────────────────────
// On a hit we do NOT render the value, not even partially, not even masked
// character by character — a masked secret still leaks its length and its
// shape. We render a warning chip, we count it, and the screen tells the
// operator to report it. Silently masking would hide a server bug; refusing to
// draw the whole page would make an unrelated false positive destroy the
// operator's only view of his configuration. The chosen middle is: draw
// everything else, replace the suspect fragment, shout about it.
//
// FALSE POSITIVES ARE EXPECTED AND ARE THE CHEAP SIDE. A base64 certificate
// fingerprint tripping the entropy rule costs one line the operator has to
// open the raw export to read. A missed pre-shared key costs the customer's
// VPN. The thresholds below are therefore deliberately jumpy, and every rule
// says in one word what it is looking for so a hit is diagnosable.

export type SecretHitRule =
  | 'assignment'      // `password=hunter2`, `secret: xyz` — a named secret field
  | 'privateKey'      // PEM / OpenSSH private key block
  | 'entropy';        // a long high-entropy token in a value position

export interface SecretHit {
  rule: SecretHitRule;
  /** 0-based index of the offending line within the scanned text. */
  line: number;
  /** The KEY only, never the value: `password`, `pre-shared-key`. Safe to show
   *  and the only thing the operator needs in order to report the leak. */
  label: string;
}

/**
 * Key names that make whatever follows them a secret. Kept to names that are
 * unambiguous in a network configuration: `key` alone is not here, because
 * `key-type`, `keepalive` and `sshkey-fingerprint` would all trip it.
 */
const SECRET_KEYS = [
  'password', 'passwd', 'pwd', 'passphrase',
  'secret', 'psk', 'pre-shared-key', 'preshared-key', 'presharedkey',
  'private-key', 'privatekey', 'wpa-pre-shared-key', 'wpa2-pre-shared-key',
  'community', 'authentication-password', 'encryption-password',
  'auth-password', 'enc-password', 'radius-secret', 'shared-secret',
  'api-key', 'apikey', 'token', 'bearer', 'credential', 'credentials',
];

/**
 * `password=` / `password: ` / `password "…"` followed by something that is not
 * already a redaction. RouterOS writes `password=""` when the value was
 * stripped, and every brand has its own placeholder, so the negative list
 * matters as much as the positive one: flagging the redaction itself would make
 * the warning permanent and therefore ignored.
 */
const REDACTED_VALUES = new Set([
  '', '""', "''", '*', '**', '***', '****', '*****', '********',
  '<hidden>', '<redacted>', '[redacted]', '[hidden]', 'redacted', 'hidden',
  'x', 'xx', 'xxx', 'xxxx', 'null', 'none', 'unset', '-',
]);

const ASSIGNMENT_RE = new RegExp(
  `(?:^|[\\s;,{("'])(${SECRET_KEYS.join('|')})\\s*[=:]\\s*("[^"]*"|'[^']*'|\\S+)`,
  'i',
);

const PEM_RE = /-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----/;

/** Shannon entropy in bits per character. */
function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * A long, high-entropy, non-hex token. Hex is excluded on purpose: every hash
 * in this product (`ncmHash`, `matchHash`, `raw_sha256`, an SSH fingerprint) is
 * hex, they are all designed to be shown, and they would otherwise dominate the
 * hit list until nobody reads it.
 */
function looksLikeHighEntropyToken(token: string): boolean {
  if (token.length < 24) return false;
  if (/^[0-9a-fA-F:]+$/.test(token)) return false;          // hashes, MACs
  if (/^[0-9.:/]+$/.test(token)) return false;              // addresses
  if (!/^[A-Za-z0-9+/=_\-.]+$/.test(token)) return false;   // not token-shaped
  if (!/[0-9]/.test(token) || !/[A-Za-z]/.test(token)) return false;
  return entropy(token) >= 3.9;
}

function isRedacted(value: string): boolean {
  const v = value.trim().replace(/^["']|["']$/g, '').toLowerCase();
  if (REDACTED_VALUES.has(v)) return true;
  return /^[*x•]+$/.test(v);
}

/**
 * Scans a block of text. Returns at most `limit` hits — the caller renders a
 * banner, not a report, and scanning a 3000-line export must stay a few
 * milliseconds so it can run on every render of a snapshot.
 */
export function scanTextForSecrets(text: string, limit = 20): SecretHit[] {
  const hits: SecretHit[] = [];
  if (!text) return hits;
  const lines = text.split('\n');
  for (let i = 0; i < lines.length && hits.length < limit; i++) {
    const line = lines[i];
    if (line.length > 4096) continue;   // a base64 blob line: not config text
    if (PEM_RE.test(line)) {
      hits.push({ rule: 'privateKey', line: i, label: 'private-key' });
      continue;
    }
    const m = ASSIGNMENT_RE.exec(line);
    if (m && !isRedacted(m[2])) {
      hits.push({ rule: 'assignment', line: i, label: m[1].toLowerCase() });
      continue;
    }
    for (const token of line.split(/[\s=,;"']+/)) {
      if (looksLikeHighEntropyToken(token)) {
        hits.push({ rule: 'entropy', line: i, label: 'high-entropy value' });
        break;
      }
    }
  }
  return hits;
}

/**
 * Scans a JSON-ish value tree (an NCM resource, a finding's `intentValue`).
 * Returns the dotted paths of the properties that must not be painted.
 *
 * `SecretFingerprint` objects are the SUPPORTED way to carry a secret's
 * identity and are skipped by name: `{ algo, fp, unavailable }` is designed to
 * be shown, and `fp` is a truncated HMAC that trips the entropy rule every
 * single time.
 */
export function scanValueForSecrets(value: unknown, limit = 20): string[] {
  const bad: string[] = [];
  const walk = (node: unknown, path: string, depth: number): void => {
    if (bad.length >= limit || depth > 8) return;
    if (typeof node === 'string') {
      if (PEM_RE.test(node) || looksLikeHighEntropyToken(node)) bad.push(path);
      return;
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length && bad.length < limit; i++) {
        walk(node[i], `${path}[${i}]`, depth + 1);
      }
      return;
    }
    if (node && typeof node === 'object') {
      const obj = node as Record<string, unknown>;
      // The designed carrier, not a leak.
      if ('algo' in obj && 'fp' in obj && 'unavailable' in obj) return;
      for (const [k, v] of Object.entries(obj)) {
        if (bad.length >= limit) break;
        // A field NAMED like a secret is suspect whatever its value shape,
        // because the model has no such field: its presence is the bug.
        if (SECRET_KEYS.includes(k.toLowerCase()) && typeof v === 'string' && !isRedacted(v)) {
          bad.push(path ? `${path}.${k}` : k);
          continue;
        }
        walk(v, path ? `${path}.${k}` : k, depth + 1);
      }
    }
  };
  walk(value, '', 0);
  return bad;
}
