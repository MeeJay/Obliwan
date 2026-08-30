import crypto from 'crypto';
import * as OTPAuth from 'otpauth';
import QRCode from 'qrcode';
import nodemailer from 'nodemailer';
import { db } from '../db';
import { smtpServerService } from './smtpServer.service';
import { config } from '../config';
import { logger } from '../utils/logger';

const TOTP_PERIOD = 30;

/**
 * VERIF-SECFIX R6 — the window was 2, i.e. ±2 periods = ±60 s, which keeps
 * FIVE six-digit codes valid at any instant and divides the brute-force space
 * by five (1 in 200 000 per guess instead of 1 in 10^6). RFC 6238 §5.2 asks for
 * "at most one time step" of tolerance; 1 (±30 s) covers real client clock
 * drift on a machine with any NTP at all, and every authenticator app on the
 * market resyncs its own clock.
 */
const TOTP_WINDOW = 1;

/**
 * Anti-replay for consumed TOTP counters (VERIF-SECFIX R6, scenario b), now
 * DURABLE — the follow-up the previous pass reported and could not write.
 *
 * A TOTP code stays valid for a whole period plus the window — up to 90 s with
 * the settings above. Nothing recorded that a code had already been spent, so a
 * code seen once (shoulder-surfing, a screen share, a phishing proxy relaying
 * the login form) could be replayed inside that span.
 *
 * The first fix was a `Map` in process memory, and its own comment named the
 * limit: it survives neither a restart nor a second replica. That reserve is not
 * academic here — `config.ts` implements arbitrage A5
 * (`OBLIWAN_ROLE=web|worker|all`) and states that several `web` replicas may run
 * side by side. A per-process Map therefore CONTRADICTS the deployment shape the
 * project has already chosen: the guard silently disappears on every deploy,
 * every crash-restart, and for every request that a load balancer happens to
 * send to the other replica.
 *
 * The high-water mark now lives in `users.totp_last_counter` (migration 004) and
 * is moved forward by the same statement that validates it, so PostgreSQL — not
 * application memory — arbitrates the race between two submissions of the same
 * code, wherever they land.
 */

export const twoFactorService = {
  // ── TOTP ──────────────────────────────────────────────────────────────────

  generateTotpSecret(username: string): { secret: string; uri: string } {
    const secret = new OTPAuth.Secret({ size: 20 });
    const totp = new OTPAuth.TOTP({
      issuer: config.appName,
      label: username,
      algorithm: 'SHA1',
      digits: 6,
      period: TOTP_PERIOD,
      secret,
    });
    return {
      secret: secret.base32,
      uri: totp.toString(),
    };
  },

  async generateTotpQr(uri: string): Promise<string> {
    return QRCode.toDataURL(uri);
  },

  /**
   * Validates a TOTP code and returns the ABSOLUTE counter it matched
   * (`floor(now/period) + delta`), or null. Callers that authenticate with the
   * code must feed that counter to `consumeTotpCounter` so it cannot be
   * replayed; `verifyTotp` below is the boolean form, for the enrolment path
   * where the secret is not yet a credential.
   */
  validateTotp(secret: string, code: string): number | null {
    try {
      const totp = new OTPAuth.TOTP({
        issuer: config.appName,
        algorithm: 'SHA1',
        digits: 6,
        period: TOTP_PERIOD,
        secret: OTPAuth.Secret.fromBase32(secret.trim()),
      });
      const delta = totp.validate({ token: code.trim(), window: TOTP_WINDOW });
      if (delta === null) return null;
      return Math.floor(Date.now() / 1000 / TOTP_PERIOD) + delta;
    } catch (err) {
      logger.warn({ err }, 'TOTP verification threw an exception (secret may be malformed)');
      return null;
    }
  },

  verifyTotp(secret: string, code: string): boolean {
    return this.validateTotp(secret, code) !== null;
  },

  /**
   * Burns a TOTP counter for a user. Returns false when the counter has already
   * been used (or is older than the last one used), which is a replay.
   *
   * The whole decision is ONE statement. Reading `totp_last_counter` and then
   * writing it would put a read-modify-write between two submissions of the same
   * code — precisely the race this guard exists to lose safely — and would be
   * worthless across replicas. The `WHERE` clause carries the rule, and
   * `rowCount` is the verdict: PostgreSQL serialises the two concurrent UPDATEs
   * on the row, the second one re-evaluates the predicate against the value the
   * first committed, matches nothing, and returns 0.
   *
   * `totp_last_counter IS NULL` is the never-used state, which is also what a
   * freshly enrolled or rotated secret leaves behind.
   */
  async consumeTotpCounter(userId: number, counter: number): Promise<boolean> {
    const updated = await db('users')
      .where({ id: userId })
      .where((qb) => {
        qb.whereNull('totp_last_counter').orWhere('totp_last_counter', '<', counter);
      })
      .update({ totp_last_counter: counter });
    return updated > 0;
  },

  /**
   * Clears the high-water mark after a TOTP secret is rotated or removed.
   *
   * It MUST be reset, not left behind: a new secret produces codes for the same
   * absolute counters (the counter is `floor(now/30)`, a property of the clock,
   * not of the secret), so a stale mark would refuse every code of the new
   * secret until real time caught up with it.
   */
  async forgetTotpCounters(userId?: number): Promise<void> {
    const q = db('users').update({ totp_last_counter: null });
    if (userId !== undefined) q.where({ id: userId });
    await q;
  },

  // ── Email OTP ──────────────────────────────────────────────────────────────

  /**
   * AUDIT-SEC #8 (MAJEUR) — this was `Math.floor(100000 + Math.random()*900000)`.
   * `Math.random()` is V8's xorshift128+: not a CSPRNG, produced in
   * pre-computed batches, and with an internal state reconstructible from a
   * handful of consecutive outputs. It was generating the SECOND FACTOR of
   * authentication, while `crypto.randomInt` was one import away.
   *
   * The `padStart` matters: without it, `randomInt(0, 1e6)` would emit codes
   * shorter than six digits and quietly shrink the space.
   */
  generateEmailOtp(): string {
    return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  },

  async sendEmailOtp(smtpServerId: number, toEmail: string, code: string): Promise<void> {
    const server = await smtpServerService.getById(smtpServerId);
    if (!server) throw new Error('SMTP server not configured for OTP');

    const transport = nodemailer.createTransport({
      host: server.host,
      port: server.port,
      secure: server.secure,
      auth: { user: server.username, pass: server.password },
    });

    await transport.sendMail({
      from: server.from_address,
      to: toEmail,
      subject: `${config.appName} — Your login code`,
      text: `Your login verification code is: ${code}\n\nThis code expires in 10 minutes.`,
      html: `
        <h2>${config.appName} — Login verification</h2>
        <p>Your verification code is:</p>
        <h1 style="letter-spacing:8px;font-family:monospace">${code}</h1>
        <p style="color:#888;font-size:12px">This code expires in 10 minutes. If you did not request this, ignore this email.</p>
      `,
    });

    logger.info(`Email OTP sent to ${toEmail}`);
  },
};
