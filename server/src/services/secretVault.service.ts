import crypto from 'crypto';
import { config } from '../config';
import { db } from '../db';
import { logger } from '../utils/logger';

/**
 * secretVault.service.ts — the credential vault (arbitrage A3, risk R8).
 *
 * AES-256-GCM, a dedicated `OBLIWAN_ENCRYPTION_KEY`, a random IV per secret,
 * an authentication tag, and a versioned storage format that carries the key
 * generation inside the blob itself.
 *
 * ┌─ WHY THIS FILE EXISTS AND `utils/crypto.ts` IS NOT USED ──────────────────┐
 * │ `utils/crypto.ts` is inherited from Obliguard and derives its key from    │
 * │ SESSION_SECRET. Rotating a session secret is a routine operation; doing   │
 * │ it there would make every device credential in the fleet undecryptable    │
 * │ with no error at startup. That is risk R8, and it is why the vault has    │
 * │ its own key and its own `key_version` column. NEVER call utils/crypto     │
 * │ from a vault code path.                                                   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Storage format (single line, ASCII, greppable, self-describing):
 *
 *     v1:<key_version>:<iv b64>:<tag b64>:<ciphertext b64>
 *
 * The version prefix is the format version; `key_version` is the generation of
 * OBLIWAN_ENCRYPTION_KEY that produced the ciphertext. They move independently,
 * which is the whole point: a key rotation must not require a format change.
 *
 * NON-NEGOTIABLE, section 8.2 — no plaintext secret is ever logged, returned in
 * an error message, or persisted anywhere but `device_transports.secret_enc` /
 * `private_key_enc`. Not truncated, not "just the first 4 chars", not in debug.
 * A decryption error names the `key_version` that failed and says nothing else.
 */

const FORMAT_VERSION = 'v1';
const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12; // GCM standard; 96-bit IVs are the only ones NIST blesses
const TAG_BYTES = 16;
const KEY_BYTES = 32;

/** A vault error carries WHICH key generation failed, and nothing about the
 *  content. Callers may surface `message` to an operator verbatim. */
export class VaultError extends Error {
  constructor(
    message: string,
    readonly keyVersion?: number,
  ) {
    super(message);
    this.name = 'VaultError';
  }
}

/** Parsed blob header — never contains plaintext. */
export interface SecretBlobInfo {
  formatVersion: string;
  keyVersion: number;
}

// ============================================================================
// Key material
// ============================================================================

/**
 * Additional key generations, for the window during which a rotation is in
 * flight and rows carrying the old version still exist.
 *
 *   OBLIWAN_ENCRYPTION_KEY          -> current generation
 *   OBLIWAN_ENCRYPTION_KEY_VERSION  -> its number (default 1)
 *   OBLIWAN_ENCRYPTION_KEY_<n>      -> retired generation n, decrypt-only
 *
 * Retired keys are decrypt-only by construction: `encrypt()` never consults
 * this map, it always uses the current generation.
 */
function readLegacyKeys(): Map<number, Buffer> {
  const out = new Map<number, Buffer>();
  for (const [name, value] of Object.entries(process.env)) {
    const m = /^OBLIWAN_ENCRYPTION_KEY_(\d+)$/.exec(name);
    if (!m || !value) continue;
    const version = Number(m[1]);
    const raw = value.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
      // Deliberately does not echo the value.
      throw new VaultError(
        `OBLIWAN_ENCRYPTION_KEY_${version} is set but is not 64 hex characters.`,
        version,
      );
    }
    out.set(version, Buffer.from(raw, 'hex'));
  }
  return out;
}

let cachedCurrentKey: Buffer | null = null;
let cachedLegacyKeys: Map<number, Buffer> | null = null;

/** The generation new secrets are written with. */
export function currentKeyVersion(): number {
  const raw = (process.env.OBLIWAN_ENCRYPTION_KEY_VERSION || '1').trim();
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) {
    throw new VaultError(
      `OBLIWAN_ENCRYPTION_KEY_VERSION must be an integer >= 1 (got "${raw}").`,
    );
  }
  return n;
}

function currentKey(): Buffer {
  if (cachedCurrentKey) return cachedCurrentKey;
  if (!config.encryptionKey) {
    throw new VaultError(
      'OBLIWAN_ENCRYPTION_KEY is not set. Device credentials cannot be read or ' +
        'written. Generate one with: openssl rand -hex 32',
    );
  }
  if (!config.encryptionKeyValid) {
    throw new VaultError(
      'OBLIWAN_ENCRYPTION_KEY is set but is not 64 hex characters (32 bytes). ' +
        'Generate a valid one with: openssl rand -hex 32',
    );
  }
  cachedCurrentKey = Buffer.from(config.encryptionKey, 'hex');
  return cachedCurrentKey;
}

function keyForVersion(version: number): Buffer {
  if (version === currentKeyVersion()) return currentKey();
  if (!cachedLegacyKeys) cachedLegacyKeys = readLegacyKeys();
  const key = cachedLegacyKeys.get(version);
  if (!key) {
    throw new VaultError(
      `No encryption key available for key_version ${version}. Provide it as ` +
        `OBLIWAN_ENCRYPTION_KEY_${version} (64 hex chars) to decrypt rows still ` +
        'on that generation.',
      version,
    );
  }
  return key;
}

/** Test seam / rotation hook: forget the memoised key material. Call after
 *  changing the environment. */
export function resetKeyCache(): void {
  cachedCurrentKey = null;
  cachedLegacyKeys = null;
}

// ============================================================================
// Encrypt / decrypt
// ============================================================================

function assertKeyBuffer(key: Buffer, label: string): void {
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) {
    throw new VaultError(`${label} must be exactly ${KEY_BYTES} bytes (256 bits).`);
  }
}

function encryptWith(plaintext: string, key: Buffer, keyVersion: number): string {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    FORMAT_VERSION,
    String(keyVersion),
    iv.toString('base64'),
    tag.toString('base64'),
    ct.toString('base64'),
  ].join(':');
}

/**
 * Encrypt a secret with the CURRENT key generation.
 * The returned string is what goes into `secret_enc` / `private_key_enc`, and
 * the caller must also write `key_version = currentKeyVersion()` on the row.
 */
export function encrypt(plaintext: string): string {
  if (typeof plaintext !== 'string') {
    throw new VaultError('encrypt() expects a string.');
  }
  return encryptWith(plaintext, currentKey(), currentKeyVersion());
}

/** Split a blob without touching the ciphertext. Throws on a malformed blob. */
function parse(blob: string): {
  keyVersion: number;
  iv: Buffer;
  tag: Buffer;
  ct: Buffer;
} {
  if (typeof blob !== 'string' || blob.length === 0) {
    throw new VaultError('Encrypted blob is empty or not a string.');
  }
  const parts = blob.split(':');
  if (parts.length !== 5) {
    throw new VaultError(
      `Malformed encrypted blob: expected 5 colon-separated fields, got ${parts.length}.`,
    );
  }
  const [format, versionStr, ivB64, tagB64, ctB64] = parts;
  if (format !== FORMAT_VERSION) {
    throw new VaultError(`Unsupported vault blob format "${format}" (expected ${FORMAT_VERSION}).`);
  }
  const keyVersion = Number(versionStr);
  if (!Number.isInteger(keyVersion) || keyVersion < 1) {
    throw new VaultError(`Malformed encrypted blob: invalid key_version "${versionStr}".`);
  }
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const ct = Buffer.from(ctB64, 'base64');
  if (iv.length !== IV_BYTES) {
    throw new VaultError(
      `Malformed encrypted blob: IV is ${iv.length} bytes, expected ${IV_BYTES}.`,
      keyVersion,
    );
  }
  if (tag.length !== TAG_BYTES) {
    throw new VaultError(
      `Malformed encrypted blob: auth tag is ${tag.length} bytes, expected ${TAG_BYTES}.`,
      keyVersion,
    );
  }
  return { keyVersion, iv, tag, ct };
}

/** Read a blob's header (format + key generation) without decrypting it.
 *  Safe to log — it contains no key material and no plaintext. */
export function inspect(blob: string): SecretBlobInfo {
  const { keyVersion } = parse(blob);
  return { formatVersion: FORMAT_VERSION, keyVersion };
}

function decryptWith(blob: string, key: Buffer): string {
  const { keyVersion, iv, tag, ct } = parse(blob);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch {
    // The node error ("Unsupported state or unable to authenticate data") is
    // swallowed on purpose: it is identical for a wrong key and for a tampered
    // ciphertext, and repeating it tells an operator nothing. Naming the key
    // generation is the ONLY useful, non-leaking piece of information here.
    throw new VaultError(
      `Failed to decrypt secret encrypted with key_version ${keyVersion}: ` +
        'authentication failed (wrong key, or the stored value was altered).',
      keyVersion,
    );
  }
}

/**
 * Decrypt a blob, selecting the key from the `key_version` the blob carries.
 * The returned plaintext is IN-MEMORY ONLY (section 8.2): it may travel to the
 * device, and nowhere else. Never log it, never put it in a PlanOp, never
 * cache it on disk.
 */
export function decrypt(blob: string): string {
  const { keyVersion } = parse(blob);
  return decryptWith(blob, keyForVersion(keyVersion));
}

/**
 * Re-encrypt an existing blob under a new key generation. The plaintext exists
 * for the duration of this call and is never named in a log line.
 *
 * `newKey` is 64 hex chars or a 32-byte Buffer — passed explicitly rather than
 * read from the environment so a rotation tool can hold the new key without it
 * having to be the process-wide current one yet.
 */
export function reencrypt(blob: string, newKey: string | Buffer, newKeyVersion: number): string {
  if (!Number.isInteger(newKeyVersion) || newKeyVersion < 1) {
    throw new VaultError(`reencrypt(): newKeyVersion must be an integer >= 1.`);
  }
  let key: Buffer;
  if (typeof newKey === 'string') {
    const raw = newKey.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
      throw new VaultError('reencrypt(): newKey must be 64 hex characters (32 bytes).');
    }
    key = Buffer.from(raw, 'hex');
  } else {
    key = newKey;
  }
  assertKeyBuffer(key, 'reencrypt(): newKey');

  const plaintext = decrypt(blob);
  try {
    return encryptWith(plaintext, key, newKeyVersion);
  } finally {
    // Nothing to zero on a JS string; the note is here so nobody "improves"
    // this function by holding the plaintext in a longer-lived variable.
  }
}

// ============================================================================
// Startup guard
// ============================================================================

/**
 * Refuse to run without a usable key IF the database already holds secrets.
 *
 * An instance with an empty vault and no key is a legitimate fresh install and
 * boots with a warning. An instance that HAS ciphertext and no key (or a
 * malformed one) is the R8 failure mode: it would run, look healthy, and fail
 * one device at a time. It must die at startup instead.
 *
 * Returns the non-fatal warnings so the caller logs them through pino.
 * Called from index.ts AFTER migrations, BEFORE the arbiter starts.
 */
export async function assertVaultUsable(): Promise<string[]> {
  const warnings: string[] = [];

  const row = await db('device_transports')
    .whereNotNull('secret_enc')
    .orWhereNotNull('private_key_enc')
    .count<{ count: string }[]>('* as count')
    .first();
  const storedSecrets = Number(row?.count ?? 0);

  if (storedSecrets === 0) {
    if (!config.encryptionKey) {
      warnings.push(
        'OBLIWAN_ENCRYPTION_KEY is not set. The credential vault is empty, so ' +
          'startup continues, but no device credential can be stored until it ' +
          'is. Generate one with: openssl rand -hex 32',
      );
    } else if (!config.encryptionKeyValid) {
      warnings.push(
        'OBLIWAN_ENCRYPTION_KEY is set but is not 64 hex characters (32 bytes). ' +
          'The vault is empty so startup continues, but the first credential ' +
          'write will fail. Generate a valid one with: openssl rand -hex 32',
      );
    }
    return warnings;
  }

  // From here on there IS ciphertext in the database. No key means no fleet.
  if (!config.encryptionKey) {
    throw new VaultError(
      `Refusing to start: ${storedSecrets} stored device credential(s) exist but ` +
        'OBLIWAN_ENCRYPTION_KEY is not set. Starting without it would fail one ' +
        'device at a time instead of failing here. Restore the key and retry.',
    );
  }
  if (!config.encryptionKeyValid) {
    throw new VaultError(
      `Refusing to start: ${storedSecrets} stored device credential(s) exist and ` +
        'OBLIWAN_ENCRYPTION_KEY is not 64 hex characters (32 bytes). Restore the ' +
        'correct key and retry.',
    );
  }

  // A key that is present and well-formed can still be the WRONG key. Prove it
  // decrypts by trying exactly one row per key_version present in the table.
  const versions = await db('device_transports')
    .whereNotNull('secret_enc')
    .distinct<{ key_version: number }[]>('key_version');

  for (const { key_version } of versions) {
    const sample = await db('device_transports')
      .where({ key_version })
      .whereNotNull('secret_enc')
      .select<{ secret_enc: string }[]>('secret_enc')
      .first();
    if (!sample?.secret_enc) continue;
    try {
      decrypt(sample.secret_enc);
    } catch (err) {
      const message = err instanceof VaultError ? err.message : 'unknown vault error';
      throw new VaultError(
        `Refusing to start: the configured encryption key cannot decrypt stored ` +
          `credentials at key_version ${key_version}. ${message}`,
        key_version,
      );
    }
  }

  logger.info(
    { storedSecrets, keyVersions: versions.map((v) => v.key_version) },
    'Credential vault verified',
  );
  return warnings;
}
