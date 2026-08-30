import bcrypt from 'bcrypt';
import crypto from 'crypto';

const SALT_ROUNDS = 12;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function generateToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

// ── AES-256-GCM symmetric encryption ───────────────────────────────────────
//
// WARNING — this key is DERIVED FROM SESSION_SECRET. That is exactly risk R8:
// rotating the session secret would silently render every ciphertext
// unreadable, with no error at startup. It is left here only because NOTHING
// currently calls encryptSecret()/decryptSecret() — the M1 schema stores no
// secret at all.
//
// The device-credential vault (M2, migration 002) MUST NOT use these helpers.
// It gets its own module keyed on config.encryptionKey (OBLIWAN_ENCRYPTION_KEY,
// already read and validated in config.ts) with a key_version column, per
// arbitrage A3.

function deriveKey(): Buffer {
  const { config } = require('../config') as { config: { sessionSecret: string } };
  return crypto.createHash('sha256').update(config.sessionSecret).digest();
}

/** Encrypt plaintext with AES-256-GCM. Returns "iv:tag:ciphertext" (hex). */
export function encryptSecret(plaintext: string): string {
  const key = deriveKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
}

/** Decrypt a string produced by encryptSecret. */
export function decryptSecret(encrypted: string): string {
  const key = deriveKey();
  const [ivHex, tagHex, encHex] = encrypted.split(':');
  if (!ivHex || !tagHex || !encHex) throw new Error('Invalid encrypted format');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const enc = Buffer.from(encHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf-8');
}
