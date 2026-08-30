/**
 * ObliWAN — M6 / K1. The mandatory pre-change backup (risk R1).
 *
 * R1 says a push can cut the tunnel we administer through and turn a mistake
 * into a van. Two things stand between that mistake and the van: the on-box
 * dead-man (`safeApply.service.ts`) and THIS FILE, because the dead-man has
 * nothing to restore if the backup was never taken — or, worse, if it was
 * "taken" and is 43 bytes of nothing.
 *
 * So a backup here is not "we ran /system/backup/save and it said !done". It is
 * a chain in which every link is checked:
 *
 *   save  -> the file appears AND its size stops growing   (waitForDeviceFile)
 *   pull  -> a single-use token, a bounded body, a digest  (transfer.service)
 *   prove -> re-read from OUR disk, re-hash, compare, floor on the size
 *   erase -> delete on the device and RE-READ to prove absence
 *   record-> one row in `device_backups`, with the digest and the firmware
 *
 * Any link that fails fails the backup, and a failed preflight backup fails the
 * job before anything is written. That is not a policy this service enforces by
 * being careful: migration 009's `change_jobs_preflight_backup_chk` makes a
 * write job at `arming` or beyond IMPOSSIBLE to represent without a backup id.
 *
 * TWO KINDS, ON PURPOSE (§3.5, shared/change.ts):
 *   binary  `/system/backup/save` — what the dead-man restores. Complete
 *           (users, certificates), but only onto a compatible RouterOS.
 *   rsc     `/export terse show-sensitive=no` — what a human reads at 3 a.m.
 *           before deciding what he is restoring. Portable, diffable, and the
 *           thing we compare against to PROVE a rollback actually happened.
 *
 * R10 IS HARD-CODED HERE. `show-sensitive=no` is not a parameter, not a
 * default, not a config key: it is a literal in `buildExportWords()` and there
 * is an assertion refusing any caller-supplied `show-sensitive`. A `.rsc` with
 * PSKs in it becomes a snapshot, a diff, a UI panel and a log line, and there
 * is no taking it back.
 *
 * THIS FILE ALSO OWNS THE DEVICE SESSION, and that is deliberate rather than
 * accidental: it is the lowest layer above the transport that needs both the
 * database (to resolve a device and to write `command_audit`) and a fresh
 * socket. `rollback.service.ts` and `safeApply.service.ts` import it from here
 * so there is exactly one place where a command goes to an equipment and
 * exactly one place where that fact is recorded.
 */

import crypto from 'crypto';
import fsp from 'fs/promises';
import path from 'path';
import {
  FAMILY_BRAND,
  type BackupKind,
  type BackupRetentionClass,
  type BackupTrigger,
  type DeviceFamily,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { decrypt, encrypt } from '../secretVault.service';
import {
  createRouterOsConnection,
  redactWords,
  RouterOsTrapError,
  type RouterOsConnection,
} from '../transport/routeros';
import { compareIdentity, readRouterOsIdentity } from '../fleet/deviceBinding.service';
import { auditedCommand } from '../audit.service';
import {
  deviceFileInfo,
  hashFile,
  removeDeviceFile,
  redactTransferUrl,
  TRANSFER_TOKEN_IN_TEXT,
  TransferError,
  TransferReceiver,
  uploadFileFromDevice,
  verifyArtefact,
  waitForDeviceFile,
} from './transfer.service';

// ============================================================================
// Errors
// ============================================================================

export type ChangeErrorKind =
  | 'DEVICE_UNKNOWN'
  | 'NO_TRANSPORT'
  | 'NO_CREDENTIAL'
  | 'CONNECT_FAILED'
  | 'IDENTITY_MISMATCH'
  | 'BRAND_UNSUPPORTED'
  | 'BACKUP_FAILED'
  | 'BACKUP_UNVERIFIED'
  | 'ONDEVICE_CLEANUP_FAILED'
  | 'SECRET_LEAK_REFUSED'
  /** A command was refused because its audit trace could not be guaranteed. */
  | 'AUDIT_REQUIRED';

export class ChangeError extends Error {
  readonly kind: ChangeErrorKind;
  readonly detail: Record<string, unknown>;
  constructor(kind: ChangeErrorKind, message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.name = 'ChangeError';
    this.kind = kind;
    this.detail = detail;
  }
}

// ============================================================================
// Redaction for the audit trail — §8.2, stricter than the transport's
// ============================================================================

/**
 * Attribute values that are a CONFIG BODY rather than a scalar. The transport's
 * `redactWords()` masks `=password=`, which is necessary and nowhere near
 * sufficient: the whole point of `safeApply` is that it ships the rendered
 * configuration inside `=source=` of a `/system/script/add`. That value is the
 * complete config WITH the secrets the vault injected. It must never reach
 * `command_audit`, `change_job_steps` or a log line.
 */
const BODY_ATTRIBUTES = new Set(['source', 'on-event', 'contents', 'value', 'comment']);

/**
 * Build the audit-safe rendering of a sentence.
 *
 * Three passes, each closing a different hole:
 *  1. the transport's own secret-attribute masking (`=password=` etc.);
 *  2. body attributes collapsed to a byte count — you learn that a 4 812-byte
 *     script was sent, never what was in it;
 *  3. literal scrubbing of any secret value the caller declares, which catches
 *     a secret that arrived through an attribute nobody thought to name.
 */
export function redactForAudit(
  words: readonly string[],
  secretValues: readonly string[] = [],
): string {
  const masked = redactWords(words).map((w) => {
    if (!w.startsWith('=')) return w;
    const rest = w.slice(1);
    const i = rest.indexOf('=');
    if (i === -1) return w;
    const key = rest.slice(0, i);
    const value = rest.slice(i + 1);
    if (BODY_ATTRIBUTES.has(key) && value.length > 0) {
      return `=${key}=<${Buffer.byteLength(value, 'utf8')} bytes, redacted>`;
    }
    return w;
  });
  let line = masked.join(' ');
  // A single-use transfer token is a bearer credential for the seconds it is
  // alive, and it travels inside `=url=`, which no secret-attribute list would
  // ever flag. The first run of the M6 recipe caught it sitting in
  // `command_audit`; this pass is what closes it.
  line = line.replace(TRANSFER_TOKEN_IN_TEXT, '/_obliwan/transfer/***');
  for (const secret of secretValues) {
    if (secret && secret.length >= 4) line = line.split(secret).join('***');
  }
  return line;
}

/**
 * Refuse to persist a string that still contains a known secret.
 *
 * This exists because §8.2 is a property of the SYSTEM, not a habit of the
 * author: the redacted rendering is produced in one place and then checked
 * against the secrets we know we injected. If the check fires, we throw rather
 * than write — a job that stops is a meeting, a PSK in `command_audit` is a
 * disclosure that cannot be undone.
 */
export function assertNoSecrets(text: string, secretValues: readonly string[]): void {
  for (const secret of secretValues) {
    if (secret && secret.length >= 4 && text.includes(secret)) {
      throw new ChangeError(
        'SECRET_LEAK_REFUSED',
        'refusing to persist a value that still contains a secret (§8.2)',
        { length: text.length },
      );
    }
  }
}

// ============================================================================
// The device target and the fresh session
// ============================================================================

export interface DeviceTarget {
  id: number;
  tenantId: number;
  uuid: string;
  name: string;
  brand: string;
  family: DeviceFamily;
  model: string | null;
  osVersion: string | null;
  siteId: number | null;
  status: string;
  isManaged: boolean;
  tunnelIp: string | null;
  /** The device immediately upstream ON THE MANAGEMENT PATH (migration 030).
   *  Null = the topology was never declared, which is not the same as "there
   *  is none": every consumer takes the closed branch on null. */
  upstreamDeviceId: number | null;
  pppUsername: string | null;
  systemIdentity: string | null;
  serial: string | null;
  concentratorId: number | null;
  /** Where to dial TODAY. Never an identity (R4). */
  host: string | null;
  port: number | null;
  useTls: boolean;
  username: string | null;
  fingerprint: string | null;
  /** Ciphertext. Decrypted only inside `openDeviceSession`, never stored. */
  secretEnc: string | null;
  transportEnabled: boolean;
}

export async function loadDeviceTarget(deviceId: number): Promise<DeviceTarget> {
  const row = await db('devices as d')
    .leftJoin('device_transports as t', function joinApi(this: any) {
      this.on('t.device_id', '=', 'd.id').andOn('t.transport', '=', db.raw('?', ['routeros_api']));
    })
    .where('d.id', deviceId)
    .first<any>(
      'd.id',
      'd.tenant_id',
      'd.uuid',
      'd.name',
      'd.brand',
      'd.family',
      'd.model',
      'd.os_version',
      'd.site_id',
      'd.status',
      'd.is_managed',
      'd.tunnel_ip',
      'd.upstream_device_id',
      'd.ppp_username',
      'd.system_identity',
      'd.serial',
      'd.concentrator_id',
      't.host',
      't.port',
      't.use_tls',
      't.username',
      't.secret_enc',
      't.tls_fingerprint_sha256',
      't.enabled',
    );
  if (!row) throw new ChangeError('DEVICE_UNKNOWN', `Device ${deviceId} does not exist`);
  return {
    id: row.id,
    tenantId: row.tenant_id,
    uuid: row.uuid,
    name: row.name,
    brand: row.brand,
    family: row.family,
    model: row.model ?? null,
    osVersion: row.os_version ?? null,
    siteId: row.site_id ?? null,
    status: row.status,
    isManaged: row.is_managed === true,
    tunnelIp: row.tunnel_ip ?? null,
    upstreamDeviceId: row.upstream_device_id ?? null,
    pppUsername: row.ppp_username ?? null,
    systemIdentity: row.system_identity ?? null,
    serial: row.serial ?? null,
    concentratorId: row.concentrator_id ?? null,
    host: row.host ?? null,
    port: row.port ?? null,
    useTls: row.use_tls === true,
    username: row.username ?? null,
    fingerprint: row.tls_fingerprint_sha256 ?? null,
    secretEnc: row.secret_enc ?? null,
    transportEnabled: row.enabled === true,
  };
}

/** Test seam. The only thing the self-test replaces is the socket factory. */
export type DialFn = (
  target: DeviceTarget,
  opts: { connectTimeoutMs: number; requestTimeoutMs: number; label: string },
) => Promise<RouterOsConnection>;

export interface SessionOptions {
  /** Free-form, goes into the log line and the connection label. */
  purpose: string;
  jobId?: number | null;
  stepId?: number | null;
  userId?: number | null;
  username?: string | null;
  correlationId?: string | null;
  connectTimeoutMs?: number;
  requestTimeoutMs?: number;
  /** R4 — verify the identity ON THIS SOCKET before handing it over. Default
   *  true, and there is no production reason to pass false. */
  assertIdentity?: boolean;
  dial?: DialFn;
  /** Secrets whose literal value must never appear in the audit trail. */
  secretValues?: readonly string[];
}

export interface RunOptions {
  isWrite: boolean;
  timeoutMs?: number;
  /** Extra secrets for this command only (a one-shot backup password). */
  secretValues?: readonly string[];
  /** Do not write a `command_audit` row. Reserved for the polling reads that
   *  would otherwise write one row per 250 ms.
   *
   *  NEVER legal together with `isWrite: true` — `run()` throws on that pair.
   *  The exit door exists for `/file/print` loops, not for gestures that change
   *  a customer's box. */
  skipAudit?: boolean;
}

/**
 * ONE authenticated socket, opened for one purpose, whose identity was proven
 * on the socket itself.
 *
 * `assertTargetBinding()` (M2, R4) opens its OWN fresh connection and closes
 * it. That proves the identity of the box that answered THAT socket. Between
 * that socket and the one we then write on, a PPP pool has all the time it
 * needs to move the lease. So this class re-runs the identity comparison on the
 * connection it is about to hand out, using the same exported primitives —
 * `readRouterOsIdentity()` + `compareIdentity()` — so there is one comparison
 * rule in the codebase and it is M2's.
 */
export class DeviceSession {
  readonly conn: RouterOsConnection;
  readonly target: DeviceTarget;
  readonly openedAt = Date.now();
  private readonly opts: SessionOptions;
  private readonly secrets: string[];
  private closed = false;

  constructor(conn: RouterOsConnection, target: DeviceTarget, opts: SessionOptions) {
    this.conn = conn;
    this.target = target;
    this.opts = opts;
    this.secrets = [...(opts.secretValues ?? [])];
  }

  /** Add a secret that must be scrubbed from every later audit line. */
  protect(secret: string): void {
    if (secret) this.secrets.push(secret);
  }

  /**
   * Send one sentence and record it — IN THAT ORDER, WHICH IS THE REVERSE OF
   * WHAT THE SENTENCE SAYS.
   *
   * The intent row goes in FIRST, through `auditedCommand()`, and its INSERT is
   * not wrapped in a try/catch: if `command_audit` cannot be appended, this
   * method throws and `conn.query` is never reached. No trace, no bytes. That
   * is §8.2 / R10 and it is the reason this file exists at the layer it does —
   * it is the single place where a command leaves for an equipment, so it is
   * the single place where that rule can be made true rather than described.
   *
   * The RESULT row is appended afterwards and `recordCommandResult()` never
   * throws: once the box has been written to, losing the outcome row must not
   * turn a good change into a failed job. The attempt row — the one that proves
   * the gesture was made — is already committed.
   *
   * A `!trap` is an ANSWER (the menu refused); a socket death is not, and the
   * two are different incidents. The result row cannot carry NULL, so the
   * distinction is carried in the error text instead: a non-trap failure is
   * prefixed `no answer: `.
   */
  async run(words: string[], options: RunOptions): Promise<Record<string, string>[]> {
    const secrets = [...this.secrets, ...(options.secretValues ?? [])];
    const line = redactForAudit(words, secrets);
    assertNoSecrets(line, secrets);

    if (options.skipAudit) {
      // The only exit door, and it may never cover a write.
      if (options.isWrite) {
        throw new ChangeError(
          'AUDIT_REQUIRED',
          'skipAudit is not available for a write (§8.2 / R10)',
          { deviceId: this.target.id, purpose: this.opts.purpose },
        );
      }
      return this.conn.query(words, { timeoutMs: options.timeoutMs });
    }

    return auditedCommand(
      {
        tenantId: this.target.tenantId,
        deviceId: this.target.id,
        deviceUuid: this.target.uuid,
        deviceName: this.target.name,
        userId: this.opts.userId ?? null,
        username: this.opts.username ?? null,
        jobId: this.opts.jobId ?? null,
        stepId: this.opts.stepId ?? null,
        transport: 'routeros_api',
        command: line,
        args: { purpose: this.opts.purpose },
        isWrite: options.isWrite,
        correlationId: this.opts.correlationId ?? null,
        secrets,
      },
      async () => {
        try {
          return await this.conn.query(words, { timeoutMs: options.timeoutMs });
        } catch (err) {
          // The device's OWN answer can echo back a single-use transfer token
          // or a literal we injected. `auditedCommand` stores `err.message`, so
          // it is redacted here, in place, before it can reach `command_audit`,
          // `change_job_steps` or a log line. Nothing in this tree branches on
          // the text of a device error.
          if (err instanceof Error) {
            const prefix = err instanceof RouterOsTrapError ? '' : 'no answer: ';
            err.message = prefix + redactForAudit([err.message], secrets);
          }
          throw err;
        }
      },
    );
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.conn.close();
  }
}

const defaultDial: DialFn = async (target, opts) => {
  if (!target.host && !target.tunnelIp) {
    throw new ChangeError('NO_TRANSPORT', 'no address to dial', { deviceId: target.id });
  }
  if (!target.username || !target.secretEnc) {
    throw new ChangeError('NO_CREDENTIAL', 'no credential in the vault', { deviceId: target.id });
  }
  return createRouterOsConnection({
    host: (target.host ?? target.tunnelIp) as string,
    port: target.port ?? undefined,
    tls: target.useTls,
    username: target.username,
    password: decrypt(target.secretEnc),
    expectedFingerprint: target.fingerprint,
    connectTimeoutMs: opts.connectTimeoutMs,
    requestTimeoutMs: opts.requestTimeoutMs,
    label: opts.label,
  });
};

/**
 * Open a NEW socket to a device and prove, on that socket, that it is the right
 * device.
 *
 * There is no pooled variant and there will not be one. §5/M6 asks for a fresh
 * socket after the change specifically because an ALREADY-OPEN socket survives
 * a rule that blocks NEW connections: reusing it would report "everything is
 * fine" from inside a box nobody else can reach any more.
 */
export async function openDeviceSession(
  deviceId: number,
  options: SessionOptions,
): Promise<DeviceSession> {
  const target = await loadDeviceTarget(deviceId);
  if (target.status === 'disabled') {
    throw new ChangeError('NO_TRANSPORT', "device status is 'disabled'; no transport may be opened");
  }
  const brand = FAMILY_BRAND[target.family];
  if (brand !== 'mikrotik') {
    throw new ChangeError(
      'BRAND_UNSUPPORTED',
      `there is no RouterOS API session for family '${target.family}' — ` +
        'see the per-brand write paths in safeApply.service.ts',
      { family: target.family, brand },
    );
  }
  if (!target.transportEnabled) {
    throw new ChangeError('NO_TRANSPORT', 'routeros_api transport is absent or disabled');
  }

  const dial = options.dial ?? defaultDial;
  let conn: RouterOsConnection;
  try {
    conn = await dial(target, {
      connectTimeoutMs: options.connectTimeoutMs ?? 10_000,
      requestTimeoutMs: options.requestTimeoutMs ?? 30_000,
      label: `${options.purpose}:${target.name}`,
    });
  } catch (err) {
    if (err instanceof ChangeError) throw err;
    throw new ChangeError(
      'CONNECT_FAILED',
      `fresh connection to ${target.host ?? target.tunnelIp} failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
      { deviceId },
    );
  }

  if (options.assertIdentity !== false) {
    try {
      const observed = await readRouterOsIdentity(conn);
      const comparison = compareIdentity(
        {
          ppp_username: target.pppUsername,
          system_identity: target.systemIdentity,
          serial: target.serial,
        },
        observed,
      );
      if (!comparison.ok) {
        conn.close();
        throw new ChangeError(
          'IDENTITY_MISMATCH',
          `R4: ${comparison.reason} (device ${deviceId}, dialled ${target.host ?? target.tunnelIp})`,
          { deviceId, checks: comparison.checks },
        );
      }
    } catch (err) {
      conn.close();
      if (err instanceof ChangeError) throw err;
      throw new ChangeError(
        'IDENTITY_MISMATCH',
        `R4: identity could not be read on the fresh socket: ${
          err instanceof Error ? err.message : String(err)
        }`,
        { deviceId },
      );
    }
  }

  return new DeviceSession(conn, target, options);
}

// ============================================================================
// Storage layout and retention
// ============================================================================

export function backupRoot(): string {
  const configured = (process.env.OBLIWAN_BACKUP_ROOT ?? '').trim();
  return configured.length > 0 ? configured : path.join(process.cwd(), 'data', 'backups');
}

/**
 * Retention in days per class. `legal_hold` is `null` — a hold that expires is
 * not a hold, and migration 009 enforces that with a CHECK.
 *
 * Configurable through `app_config` key `backup_retention_days`, a JSON object.
 * The defaults are deliberately unambitious: a preflight backup is interesting
 * for as long as somebody might want to undo the change it protected.
 */
export const DEFAULT_RETENTION_DAYS: Readonly<Record<BackupRetentionClass, number | null>> = {
  short: 7,
  standard: 90,
  long: 365,
  legal_hold: null,
};

export async function retentionDays(): Promise<Record<BackupRetentionClass, number | null>> {
  const row = await db('app_config').where({ key: 'backup_retention_days' }).first('value');
  const result = { ...DEFAULT_RETENTION_DAYS } as Record<BackupRetentionClass, number | null>;
  if (!row?.value) return result;
  try {
    const parsed = JSON.parse(row.value) as Record<string, unknown>;
    for (const key of Object.keys(result) as BackupRetentionClass[]) {
      const v = parsed[key];
      if (key === 'legal_hold') continue; // never expires, whatever the config says
      if (typeof v === 'number' && Number.isFinite(v) && v > 0) result[key] = Math.floor(v);
    }
  } catch {
    logger.warn('backup_retention_days is not valid JSON; using defaults');
  }
  return result;
}

// ============================================================================
// The RouterOS commands, built in one place
// ============================================================================

/** File extension RouterOS gives each kind. */
const EXTENSION: Record<BackupKind, string> = { binary: '.backup', rsc: '.rsc' };

/** A backup below this is not a backup. Both floors are deliberately low
 *  enough for a bare CHR and high enough to catch a zero-length file. */
export const MIN_BACKUP_BYTES: Record<BackupKind, number> = { binary: 1024, rsc: 128 };

export function backupBaseName(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
}

/**
 * R10, LITERALLY. `show-sensitive=no` is a constant in this function.
 *
 * There is no options object, no default, no override, and the assertion below
 * exists so that a future refactor that adds one fails loudly instead of
 * quietly exporting PSKs into every snapshot, diff and audit screen in the
 * product. `terse` is there too: the one-line-per-item form is what the NCM
 * parser and the diff read.
 */
export function buildExportWords(fileBaseName: string): string[] {
  const words = ['/export', '=terse=', '=show-sensitive=no', `=file=${fileBaseName}`];
  const sensitive = words.filter((w) => w.startsWith('=show-sensitive='));
  if (sensitive.length !== 1 || sensitive[0] !== '=show-sensitive=no') {
    throw new ChangeError('SECRET_LEAK_REFUSED', 'R10: /export must carry show-sensitive=no');
  }
  return words;
}

export function buildBackupSaveWords(fileBaseName: string, password: string): string[] {
  // The password is what makes the blob useless to whoever finds it in transit.
  // It is generated per backup, stored ENCRYPTED in `device_backups`, and never
  // written next to the blob.
  return ['/system/backup/save', `=name=${fileBaseName}`, `=password=${password}`];
}

// ============================================================================
// Taking a backup
// ============================================================================

export interface TakeBackupOptions {
  deviceId: number;
  trigger: BackupTrigger;
  /** Default: both. A preflight backup takes both where the driver can. */
  kinds?: BackupKind[];
  jobId?: number | null;
  retentionClass?: BackupRetentionClass;
  createdBy?: number | null;
  correlationId?: string | null;
  /** Reuse a session the caller already opened and proved. When absent, one is
   *  opened (and closed) here. */
  session?: DeviceSession;
  dial?: DialFn;
  /** The address the ROUTER must dial to reach our receiver. In production this
   *  is the tunnel-side address of the ObliWAN host. */
  callbackHost?: string;
  receiver?: TransferReceiver;
  maxBytes?: number;
  saveTimeoutMs?: number;
  transferTimeoutMs?: number;
  filePollMs?: number;
  /**
   * THE ONE EXCEPTION TO "ERASE IT FROM THE DEVICE", AND IT IS NOT A LOOPHOLE.
   *
   * The on-box dead-man restores with `/system/backup/load name=<file>`. It has
   * to run when the tunnel is down, ObliWAN is unreachable and nobody is
   * watching — so the blob it loads MUST be on the router. A dead-man that
   * fetches its own backup over the network is not a dead-man; it is a rollback
   * that needs the very link the change just cut.
   *
   * So the binary preflight backup is kept on the device for the length of the
   * change window and ONLY that: `safeApply` deletes it at disarm, and
   * `rollback.service.cleanupDeadmanArtefacts()` deletes it after a fire. A job
   * cannot reach `succeeded` while it is still there. The `.rsc` is never kept
   * — nothing restores from it, so leaving it would be pure exposure.
   */
  keepOnDeviceKinds?: BackupKind[];
  /** Force the on-device file name (the dead-man references it by name). */
  fileBaseName?: Partial<Record<BackupKind, string>>;
}

export interface BackupArtefact {
  id: number;
  kind: BackupKind;
  storagePath: string;
  absolutePath: string;
  sizeBytes: number;
  sha256: string;
  osVersion: string | null;
  /** True only when the file was PROVEN gone from the device. */
  onDeviceRemoved: boolean;
  /** Non-null when the blob was deliberately LEFT on the device for the
   *  dead-man to load. Whoever holds this name owes a deletion. */
  onDeviceFileName: string | null;
  removalAttempts: number;
  transferMs: number;
  deviceReportedBytes: number;
}

export interface BackupSet {
  deviceId: number;
  jobId: number | null;
  artefacts: BackupArtefact[];
  /** The binary one, which is what the dead-man restores. */
  binary: BackupArtefact | null;
  rsc: BackupArtefact | null;
  totalMs: number;
}

/**
 * Take one backup of one kind, pull it off, prove it, erase it, record it.
 *
 * The order is the contract. In particular the on-device deletion happens
 * BEFORE the row is written, and a deletion we could not verify aborts the
 * whole thing: we would rather have no backup and a loud failure than a backup
 * whose original is still sitting on the customer's router.
 */
export async function takeBackupOfKind(
  session: DeviceSession,
  kind: BackupKind,
  options: TakeBackupOptions,
  receiver: TransferReceiver,
): Promise<BackupArtefact> {
  const target = session.target;
  const base = options.fileBaseName?.[kind] ?? backupBaseName(`obliwan-${options.jobId ?? 'man'}-${kind}`);
  const fileName = `${base}${EXTENSION[kind]}`;
  const keepOnDevice = (options.keepOnDeviceKinds ?? []).includes(kind);
  const maxBytes = options.maxBytes ?? 128 * 1024 * 1024;
  const password = kind === 'binary' ? crypto.randomBytes(24).toString('base64url') : null;
  if (password) session.protect(password);

  // --- 1. ask the device to produce it -------------------------------------
  if (kind === 'binary') {
    await session.run(buildBackupSaveWords(base, password as string), {
      isWrite: true,
      timeoutMs: options.saveTimeoutMs ?? 120_000,
      secretValues: [password as string],
    });
  } else {
    await session.run(buildExportWords(base), {
      isWrite: false,
      timeoutMs: options.saveTimeoutMs ?? 120_000,
    });
  }

  // --- 2. wait for it to actually exist and stop growing --------------------
  const onDevice = await waitForDeviceFile(session.conn, fileName, {
    timeoutMs: options.saveTimeoutMs ?? 120_000,
    pollMs: options.filePollMs ?? 250,
  });

  // --- 3. pull it off, with a token that dies on first use ------------------
  const expectation = receiver.expect({
    purpose: `backup:${target.id}:${kind}`,
    maxBytes,
    timeoutMs: options.transferTimeoutMs ?? 5 * 60_000,
    callbackHost: options.callbackHost,
  });
  let received;
  try {
    const fetchOutcome = await session.run(
      ['/tool/fetch', '=upload=yes', `=src-path=${fileName}`, `=url=${expectation.url}`],
      { isWrite: false, timeoutMs: options.transferTimeoutMs ?? 5 * 60_000 },
    ).then(
      (rows) => ({ ok: true, rows }),
      (err) => ({ ok: false, err }),
    );
    if (!fetchOutcome.ok) {
      expectation.cancel('the device refused or failed the /tool/fetch upload');
    }
    received = await expectation.received;
  } catch (err) {
    expectation.cancel('transfer failed');
    // Leave nothing behind even on the failure path: the file exists on the
    // customer's router right now and the reason we failed is irrelevant to
    // that fact.
    await removeDeviceFile(session.conn, fileName).catch(() => undefined);
    throw err instanceof TransferError
      ? new ChangeError('BACKUP_FAILED', `${kind} backup transfer failed: ${err.message}`, err.detail)
      : err;
  }

  // --- 4. prove it ---------------------------------------------------------
  let verified;
  try {
    verified = await verifyArtefact(received, {
      minBytes: MIN_BACKUP_BYTES[kind],
      deviceReportedBytes: onDevice.sizeBytes,
    });
  } catch (err) {
    await fsp.rm(received.path, { force: true }).catch(() => undefined);
    await removeDeviceFile(session.conn, fileName).catch(() => undefined);
    throw new ChangeError(
      'BACKUP_UNVERIFIED',
      `${kind} backup failed verification: ${err instanceof Error ? err.message : String(err)}`,
      err instanceof TransferError ? err.detail : {},
    );
  }

  // --- 5. move it into place ----------------------------------------------
  const relative = path
    .join(String(target.tenantId), String(target.id), `${base}${EXTENSION[kind]}`)
    .replace(/\\/g, '/');
  const absolute = path.join(backupRoot(), relative);
  await fsp.mkdir(path.dirname(absolute), { recursive: true });
  await fsp.rename(verified.path, absolute).catch(async () => {
    // rename fails across devices; fall back to a copy + unlink.
    await fsp.copyFile(verified.path, absolute);
    await fsp.rm(verified.path, { force: true });
  });
  const settled = await hashFile(absolute);
  if (settled.sha256 !== verified.sha256 || settled.bytes !== verified.bytes) {
    await fsp.rm(absolute, { force: true }).catch(() => undefined);
    throw new ChangeError('BACKUP_UNVERIFIED', 'the backup changed between spool and storage', {
      spooled: verified.sha256,
      stored: settled.sha256,
    });
  }

  // --- 6. ERASE IT FROM THE DEVICE, and prove that too ---------------------
  // ...unless this is the blob the on-box dead-man has to load. See the long
  // note on `keepOnDeviceKinds`: the deletion is deferred, never cancelled.
  let removal = { verified: true, attempts: 0, lastError: null as string | null };
  if (!keepOnDevice) {
    removal = await removeDeviceFile(session.conn, fileName, { attempts: 3 });
    if (!removal.verified) {
      await fsp.rm(absolute, { force: true }).catch(() => undefined);
      throw new ChangeError(
        'ONDEVICE_CLEANUP_FAILED',
        `the ${kind} backup could not be proven deleted from ${target.name} ` +
          `(${removal.attempts} attempts): ${removal.lastError ?? 'unknown'} — ` +
          'refusing to leave a copy of the customer configuration on the equipment',
        { fileName, attempts: removal.attempts },
      );
    }
  }

  // --- 7. record it --------------------------------------------------------
  const classes = await retentionDays();
  const retention = options.retentionClass ?? 'standard';
  const days = classes[retention];
  const [row] = await db('device_backups')
    .insert({
      tenant_id: target.tenantId,
      device_id: target.id,
      kind,
      trigger_kind: options.trigger,
      storage_path: relative,
      size_bytes: settled.bytes,
      sha256: settled.sha256,
      encryption_password_enc: password ? encrypt(password) : null,
      retention_class: retention,
      expires_at: days === null ? null : new Date(Date.now() + days * 86_400_000),
      status: 'available',
      taken_before_job_id: options.jobId ?? null,
      os_version: target.osVersion,
      verified_at: new Date(),
      created_by: options.createdBy ?? null,
    })
    .returning('id');

  const id = typeof row === 'object' ? Number((row as any).id) : Number(row);
  logger.info(
    {
      deviceId: target.id,
      backupId: id,
      kind,
      bytes: settled.bytes,
      transferMs: received.durationMs,
      onDeviceRemoved: !keepOnDevice,
      keptOnDeviceAs: keepOnDevice ? fileName : null,
    },
    keepOnDevice
      ? 'backup taken and verified; the blob is LEFT on the equipment for the dead-man and owes a deletion'
      : 'backup taken, verified and erased from the equipment',
  );
  return {
    id,
    kind,
    storagePath: relative,
    absolutePath: absolute,
    sizeBytes: settled.bytes,
    sha256: settled.sha256,
    osVersion: target.osVersion,
    onDeviceRemoved: !keepOnDevice,
    onDeviceFileName: keepOnDevice ? fileName : null,
    removalAttempts: removal.attempts,
    transferMs: received.durationMs,
    deviceReportedBytes: onDevice.sizeBytes,
  };
}

/**
 * The public entry point: take the pre-change backup.
 *
 * Both kinds by default, and the BINARY one is mandatory for a preflight: it is
 * the artefact the on-box dead-man restores. A `.rsc`-only preflight would give
 * an operator something to read and the dead-man nothing to load.
 */
export async function takeDeviceBackup(options: TakeBackupOptions): Promise<BackupSet> {
  const started = Date.now();
  const kinds = options.kinds ?? ['binary', 'rsc'];
  const ownSession = !options.session;
  const session =
    options.session ??
    (await openDeviceSession(options.deviceId, {
      purpose: 'backup',
      jobId: options.jobId ?? null,
      userId: options.createdBy ?? null,
      correlationId: options.correlationId ?? null,
      dial: options.dial,
    }));
  const ownReceiver = !options.receiver;
  const receiver = options.receiver ?? new TransferReceiver();
  if (ownReceiver) await receiver.start();

  try {
    if (options.trigger === 'preflight' && !kinds.includes('binary')) {
      throw new ChangeError(
        'BACKUP_FAILED',
        'a preflight backup must include the binary kind — it is what the dead-man restores',
      );
    }
    const artefacts: BackupArtefact[] = [];
    for (const kind of kinds) {
      artefacts.push(await takeBackupOfKind(session, kind, options, receiver));
    }
    return {
      deviceId: options.deviceId,
      jobId: options.jobId ?? null,
      artefacts,
      binary: artefacts.find((a) => a.kind === 'binary') ?? null,
      rsc: artefacts.find((a) => a.kind === 'rsc') ?? null,
      totalMs: Date.now() - started,
    };
  } finally {
    if (ownReceiver) await receiver.stop();
    if (ownSession) session.close();
  }
}

// ============================================================================
// Reading a backup back
// ============================================================================

export interface StoredBackupRow {
  id: number;
  tenantId: number;
  deviceId: number;
  kind: BackupKind;
  storagePath: string;
  sizeBytes: number;
  sha256: string;
  status: string;
  osVersion: string | null;
  takenAt: string;
  encryptionPasswordEnc: string | null;
}

export async function getBackup(id: number): Promise<StoredBackupRow | null> {
  const row = await db('device_backups').where({ id }).first<any>();
  if (!row) return null;
  return {
    id: row.id,
    tenantId: row.tenant_id,
    deviceId: row.device_id,
    kind: row.kind,
    storagePath: row.storage_path,
    sizeBytes: Number(row.size_bytes),
    sha256: row.sha256,
    status: row.status,
    osVersion: row.os_version ?? null,
    takenAt: row.taken_at,
    encryptionPasswordEnc: row.encryption_password_enc ?? null,
  };
}

/** The blob's password, decrypted. In memory, for the length of one restore. */
export function backupPassword(row: StoredBackupRow): string | null {
  return row.encryptionPasswordEnc ? decrypt(row.encryptionPasswordEnc) : null;
}

/**
 * Prove a stored backup is still what it claims to be.
 *
 * "A backup nobody verified is a backup nobody has." A row whose blob has gone
 * missing becomes `missing` — a distinct state from `purged`, so a lost backup
 * is an incident and an expired one is routine.
 */
export async function verifyStoredBackup(
  id: number,
): Promise<{ ok: boolean; reason: string; sha256?: string }> {
  const row = await getBackup(id);
  if (!row) return { ok: false, reason: 'no such backup' };
  const absolute = path.join(backupRoot(), row.storagePath);
  try {
    const { sha256, bytes } = await hashFile(absolute);
    if (sha256 !== row.sha256 || bytes !== row.sizeBytes) {
      await db('device_backups').where({ id }).update({ status: 'failed', updated_at: db.fn.now() });
      return { ok: false, reason: 'digest or size does not match the recorded value', sha256 };
    }
    await db('device_backups')
      .where({ id })
      .update({ verified_at: new Date(), status: 'available', updated_at: db.fn.now() });
    return { ok: true, reason: 'digest and size match', sha256 };
  } catch {
    await db('device_backups').where({ id }).update({ status: 'missing', updated_at: db.fn.now() });
    return { ok: false, reason: 'the blob is not on disk' };
  }
}

/**
 * Read a `.rsc` backup back as text, for the diff that PROVES a rollback.
 *
 * Comment lines are stripped before the caller hashes: a RouterOS export starts
 * with `# 2026-08-29 14:02:11 by RouterOS 7.14.3`, so two exports of an
 * identical configuration never hash the same. Comparing the canonical forms is
 * the difference between "we think it restored" and "the configuration on the
 * box is byte-identical to the one we backed up".
 */
export function canonicaliseRsc(text: string): string {
  return text
    .split(/\r?\n/)
    .map((l) => l.trimEnd())
    .filter((l) => l.length > 0 && !l.startsWith('#'))
    .join('\n');
}

export function canonicalRscHash(text: string): string {
  return crypto.createHash('sha256').update(canonicaliseRsc(text), 'utf8').digest('hex');
}

export async function readRscBackup(id: number): Promise<string> {
  const row = await getBackup(id);
  if (!row) throw new ChangeError('BACKUP_FAILED', `no such backup ${id}`);
  if (row.kind !== 'rsc') throw new ChangeError('BACKUP_FAILED', `backup ${id} is not an .rsc`);
  return fsp.readFile(path.join(backupRoot(), row.storagePath), 'utf8');
}

// ============================================================================
// Retention sweep
// ============================================================================

export interface PurgeReport {
  examined: number;
  purged: number;
  missing: number;
  errors: string[];
}

/**
 * Delete expired blobs and mark their rows `purged`.
 *
 * Rows are never deleted: the fact that a backup EXISTED on a given night is
 * part of the change record, and the row is small. `legal_hold` has no
 * `expires_at` and therefore cannot be selected here at all.
 */
export async function purgeExpiredBackups(now = new Date()): Promise<PurgeReport> {
  const rows = await db('device_backups')
    .where('status', 'available')
    .whereNotNull('expires_at')
    .andWhere('expires_at', '<=', now)
    .select<any[]>('id', 'storage_path');
  const report: PurgeReport = { examined: rows.length, purged: 0, missing: 0, errors: [] };
  for (const row of rows) {
    const absolute = path.join(backupRoot(), row.storage_path);
    try {
      await fsp.rm(absolute, { force: true });
      await db('device_backups')
        .where({ id: row.id })
        .update({ status: 'purged', updated_at: db.fn.now() });
      report.purged++;
    } catch (err) {
      report.missing++;
      report.errors.push(`${row.id}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return report;
}

// ============================================================================
// The other three brands (A2)
// ============================================================================

/**
 * DrayTek / Zyxel / SonicWall.
 *
 * There is no backup path here, and pretending otherwise would be the exact
 * failure §8.3 warns about: a backup that does not exist is discovered at the
 * moment somebody needs to restore. The three brands' configuration export runs
 * over SSH/HTTPS and belongs to their drivers (M10/M11); until those exist,
 * this refuses by name.
 *
 * The consequence is stated where it matters — `resolveSafetyNet()` in
 * `safeApply.service.ts` cannot return `armed` for these families, because
 * `armed` means "the box restores itself from a backup" and there is no backup.
 */
export async function takeBackupNonMikrotik(family: DeviceFamily): Promise<never> {
  throw new ChangeError(
    'BRAND_UNSUPPORTED',
    `no backup path for family '${family}' (${FAMILY_BRAND[family] ?? 'unknown brand'}). ` +
      'DrayTek/Zyxel/SonicWall configuration export lands with their drivers at M10/M11. ' +
      'Until then a write job on these families cannot claim safety level "armed".',
    { family },
  );
}

/** True when this family has a backup path AND therefore a restorable net. */
export function familyHasBackupPath(family: DeviceFamily): boolean {
  return FAMILY_BRAND[family] === 'mikrotik';
}

/** Present a device file listing, for the operator screen that answers
 *  "did we leave anything on this router?". */
export async function listObliwanFilesOnDevice(
  session: DeviceSession,
): Promise<Array<{ name: string; sizeBytes: number }>> {
  const rows = await session.run(['/file/print'], { isWrite: false, skipAudit: true });
  return rows
    .filter((r) => (r.name ?? '').startsWith('obliwan-'))
    .map((r) => ({ name: r.name, sizeBytes: Number(r.size ?? 0) || 0 }));
}

/** Exported for the self-test: probe one file without an audit row. */
export async function peekDeviceFile(session: DeviceSession, name: string) {
  return deviceFileInfo(session.conn, name);
}

/**
 * Collect the deferred deletion owed by `keepOnDeviceKinds`.
 *
 * Called at disarm and after a dead-man fire. Returns the removal result rather
 * than throwing, because the caller has to decide: at disarm a failure is a
 * loud incident; after a rollback it is a follow-up task on a device that is,
 * at least, back up.
 */
export async function removeBackupFromDevice(
  session: DeviceSession,
  fileName: string,
): Promise<{ verified: boolean; attempts: number; lastError: string | null }> {
  const removal = await removeDeviceFile(session.conn, fileName, { attempts: 4, backoffMs: 400 });
  if (removal.verified) {
    logger.info(
      { deviceId: session.target.id, fileName },
      'dead-man backup erased from the equipment',
    );
  } else {
    logger.error(
      { deviceId: session.target.id, fileName, lastError: removal.lastError },
      'dead-man backup still present on the equipment — a copy of the customer config remains',
    );
  }
  return { verified: removal.verified, attempts: removal.attempts, lastError: removal.lastError };
}
