/**
 * ObliWAN — Download, the file it points at, and the TransferComplete that
 * closes the loop.
 *
 * ┌─ THE THREE-PARTY DANCE, AND WHY IT NEEDS ITS OWN TABLE ───────────────────┐
 * │  1. ACS -> CPE : `Download(CommandKey, URL, FileType)`. The CPE answers   │
 * │     `Status = 1`, meaning "accepted, I will do it later". The TASK is now │
 * │     done; the TRANSFER has not started.                                   │
 * │  2. CPE -> file server : a plain HTTP GET of the URL, from the customer's │
 * │     line, with no session and no credential of ours.                      │
 * │  3. CPE -> ACS : `TransferComplete(CommandKey, FaultStruct)`, in a        │
 * │     LATER SESSION — minutes for a config file, hours or days for a        │
 * │     firmware image across a reboot on a bad line.                         │
 * │                                                                          │
 * │ Step 3 is why `CommandKey` is UNIQUE across the whole table (migration    │
 * │ 015, decision 4): the session that brings the TransferComplete may be the │
 * │ first one after a factory reset, on a different address, with a different │
 * │ cookie. The CommandKey is the ONLY thread through it.                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY THE URL CARRIES A TOKEN AND NOT A PASSWORD (§8.2, R9) ───────────────┐
 * │ TR-069 `Download` has `Username` and `Password` fields and we send them   │
 * │ EMPTY. A CPE behind carrier NAT fetching over plain HTTP would otherwise  │
 * │ put a REUSABLE credential in clear on a transit network once per firmware │
 * │ push. A single-use, expiring, unguessable token scoped to one device and  │
 * │ one file leaks nothing that outlives the transfer.                         │
 * │                                                                          │
 * │ The token is treated as a secret in LOGS (never printed) even though it   │
 * │ is not one in the §8.2 sense: it grants read of a firmware image, not of  │
 * │ a credential. Logging it would still let anyone with the log fetch the    │
 * │ image, and "the log is not sensitive" is how logs become sensitive.       │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import crypto from 'crypto';
import { db } from '../../db';
import { config } from '../../config';
import { logger } from '../../utils/logger';
import { completeTask, failTask, getTaskByCommandKey } from './task.service';
import type { CwmpFileType } from './contract';

export interface TransferRecord {
  id: number;
  deviceId: number;
  fileId: number | null;
  commandKey: string;
  taskId: number | null;
  urlToken: string;
  state: 'pending' | 'fetched' | 'completed' | 'failed' | 'expired';
  httpFetchedAt: string | null;
  fetchCount: number;
  startTime: string | null;
  completeTime: string | null;
  faultCode: string | null;
  faultString: string | null;
  createdAt: string;
}

export interface CwmpFileRecord {
  id: number;
  tenantId: number | null;
  name: string;
  fileType: CwmpFileType;
  storagePath: string;
  sha256: string;
  sizeBytes: number;
  brand: string | null;
  modelPattern: string | null;
  version: string | null;
}

interface FileRow {
  id: number;
  tenant_id: number | null;
  name: string;
  file_type: CwmpFileType;
  storage_path: string;
  sha256: string;
  size_bytes: string | number;
  brand: string | null;
  model_pattern: string | null;
  version: string | null;
}

function toFile(row: FileRow): CwmpFileRecord {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    name: row.name,
    fileType: row.file_type,
    storagePath: row.storage_path,
    sha256: row.sha256,
    sizeBytes: Number(row.size_bytes),
    brand: row.brand,
    modelPattern: row.model_pattern,
    version: row.version,
  };
}

export class TransferRefusedError extends Error {
  constructor(message: string, readonly code: 'no_file' | 'model_mismatch') {
    super(message);
    this.name = 'TransferRefusedError';
  }
}

/** A file, visible to a tenant: its own, or the shipped library. */
export async function getFile(fileId: number, tenantId: number): Promise<CwmpFileRecord | null> {
  const row = (await db('cwmp_files')
    .where({ id: fileId })
    .andWhere((q) => q.whereNull('tenant_id').orWhere('tenant_id', tenantId))
    .first()) as FileRow | undefined;
  return row ? toFile(row) : null;
}

export async function listFiles(tenantId: number): Promise<CwmpFileRecord[]> {
  const rows = (await db('cwmp_files')
    .where((q) => q.whereNull('tenant_id').orWhere('tenant_id', tenantId))
    .orderBy('name')) as FileRow[];
  return rows.map(toFile);
}

/**
 * Refuse a firmware image that was not built for this box.
 *
 * A firmware pushed to the wrong model bricks a customer's router, and the
 * recovery is a van. This is the one check in the ACS that is worth failing
 * closed on incomplete information: a file with no declared brand/model is
 * ACCEPTED (it may be a vendor config file, which is model-agnostic), but a
 * file that DOES declare one and disagrees with the device is refused.
 */
export function assertFileFitsDevice(
  file: CwmpFileRecord,
  device: { brand: string; model: string | null },
): void {
  if (file.brand && file.brand !== device.brand) {
    throw new TransferRefusedError(
      `"${file.name}" is a ${file.brand} image and this device is a ${device.brand}`,
      'model_mismatch',
    );
  }
  if (file.modelPattern) {
    if (!device.model) {
      throw new TransferRefusedError(
        `"${file.name}" targets model ${file.modelPattern} and this device's model is unknown`,
        'model_mismatch',
      );
    }
    const rx = new RegExp(
      '^' +
        file.modelPattern
          .split('*')
          .map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
          .join('.*') +
        '$',
      'i',
    );
    if (!rx.test(device.model)) {
      throw new TransferRefusedError(
        `"${file.name}" targets model ${file.modelPattern} and this device is a ${device.model}`,
        'model_mismatch',
      );
    }
  }
}

/** 32 bytes of base64url: unguessable, and short enough for a Vigor URL field. */
export function newUrlToken(): string {
  return crypto.randomBytes(32).toString('base64url');
}

export async function createTransfer(args: {
  deviceId: number;
  fileId: number;
  taskId: number;
  commandKey: string;
}): Promise<TransferRecord> {
  const [row] = (await db('cwmp_transfers')
    .insert({
      device_id: args.deviceId,
      file_id: args.fileId,
      task_id: args.taskId,
      command_key: args.commandKey,
      url_token: newUrlToken(),
      token_expires_at: new Date(Date.now() + config.cwmp.downloadTokenTtlSeconds * 1000),
      state: 'pending',
    })
    .returning('*')) as Array<Record<string, unknown>>;
  return toTransfer(row);
}

/**
 * The file server's authorisation check, in one query.
 *
 * Everything is verified together: the token exists, it has not expired, the
 * transfer is still open, and the file still exists. Splitting it would create
 * a window in which an expired token still resolves to a path.
 */
export async function resolveToken(token: string): Promise<{
  transfer: TransferRecord;
  file: CwmpFileRecord;
} | null> {
  const row = (await db('cwmp_transfers as t')
    .join('cwmp_files as f', 'f.id', 't.file_id')
    .where('t.url_token', token)
    .whereIn('t.state', ['pending', 'fetched'])
    .andWhere('t.token_expires_at', '>', db.fn.now())
    .first('t.*', 'f.id as f_id', 'f.tenant_id as f_tenant_id', 'f.name as f_name',
      'f.file_type as f_file_type', 'f.storage_path as f_storage_path',
      'f.sha256 as f_sha256', 'f.size_bytes as f_size_bytes', 'f.brand as f_brand',
      'f.model_pattern as f_model_pattern', 'f.version as f_version')) as
    | Record<string, unknown>
    | undefined;

  if (!row) return null;
  return {
    transfer: toTransfer(row),
    file: toFile({
      id: row.f_id as number,
      tenant_id: row.f_tenant_id as number | null,
      name: row.f_name as string,
      file_type: row.f_file_type as CwmpFileType,
      storage_path: row.f_storage_path as string,
      sha256: row.f_sha256 as string,
      size_bytes: row.f_size_bytes as string,
      brand: row.f_brand as string | null,
      model_pattern: row.f_model_pattern as string | null,
      version: row.f_version as string | null,
    }),
  };
}

/**
 * Record that the CPE actually fetched the file.
 *
 * `fetch_count` is incremented rather than the state being flipped once,
 * because a CPE on a flaky line retries the GET — sometimes a dozen times — and
 * a token that became invalid on the first byte would turn a slow download into
 * a permanent failure. The token stays valid until it expires; what is
 * single-use is the TRANSFER, not the GET.
 */
export async function markFetched(transferId: number): Promise<void> {
  await db('cwmp_transfers')
    .where({ id: transferId })
    .update({
      state: 'fetched',
      http_fetched_at: db.fn.now(),
      fetch_count: db.raw('fetch_count + 1'),
      updated_at: db.fn.now(),
    });
}

/**
 * Close a transfer from a `TransferComplete`, and close its task with it.
 *
 * FaultCode `0` is success. Anything else is the CPE telling us why the image
 * did not take, and it is the single most useful diagnostic the ACS ever
 * receives — `9010 Download failure` on twenty CPEs at once is a file server
 * problem, on one CPE it is that line.
 */
export async function completeTransfer(args: {
  commandKey: string;
  faultCode: string;
  faultString: string;
  startTime: string | null;
  completeTime: string | null;
}): Promise<{ matched: boolean; deviceId: number | null }> {
  const row = (await db('cwmp_transfers').where({ command_key: args.commandKey }).first()) as
    | Record<string, unknown>
    | undefined;

  const succeeded = args.faultCode === '0' || args.faultCode === '';

  if (!row) {
    // An UNMATCHED TransferComplete is not an error to swallow. It means either
    // a transfer this ACS never asked for (another ACS managed this CPE before
    // us — which the drift attribution calls `foreign_acs`) or a lost row. Log
    // it loudly; do not invent a transfer to hang it on.
    logger.warn(
      { commandKey: args.commandKey, faultCode: args.faultCode },
      'ACS: TransferComplete for an unknown CommandKey (foreign ACS, or a lost transfer)',
    );
    return { matched: false, deviceId: null };
  }

  await db('cwmp_transfers')
    .where({ id: row.id as number })
    .update({
      state: succeeded ? 'completed' : 'failed',
      fault_code: args.faultCode || null,
      fault_string: args.faultString || null,
      start_time: args.startTime ? new Date(args.startTime) : null,
      complete_time: args.completeTime ? new Date(args.completeTime) : null,
      updated_at: db.fn.now(),
    });

  // The task was already `done` when the CPE accepted the Download RPC. If the
  // transfer then FAILED, the task has to be corrected — otherwise the history
  // says the firmware push succeeded and the box says otherwise.
  const task = await getTaskByCommandKey(args.commandKey);
  if (task) {
    if (succeeded) {
      await completeTask(task.id);
    } else {
      await failTask(task.id, {
        faultCode: 'Client',
        code: args.faultCode || '9017',
        faultString: args.faultString || 'transfer failed on the CPE',
      });
    }
  }

  return { matched: true, deviceId: (row.device_id as number) ?? null };
}

/** Transfers whose token aged out before the CPE ever fetched. */
export async function expireStaleTransfers(): Promise<number> {
  return db('cwmp_transfers')
    .whereIn('state', ['pending'])
    .andWhere('token_expires_at', '<=', db.fn.now())
    .update({ state: 'expired', updated_at: db.fn.now() });
}

export async function listTransfers(deviceId: number, limit = 50): Promise<TransferRecord[]> {
  const rows = (await db('cwmp_transfers')
    .where({ device_id: deviceId })
    .orderBy('id', 'desc')
    .limit(limit)) as Array<Record<string, unknown>>;
  return rows.map(toTransfer);
}

function toTransfer(row: Record<string, unknown>): TransferRecord {
  return {
    id: row.id as number,
    deviceId: row.device_id as number,
    fileId: (row.file_id as number | null) ?? null,
    commandKey: row.command_key as string,
    taskId: (row.task_id as number | null) ?? null,
    urlToken: row.url_token as string,
    state: row.state as TransferRecord['state'],
    httpFetchedAt: row.http_fetched_at ? new Date(row.http_fetched_at as string).toISOString() : null,
    fetchCount: Number(row.fetch_count ?? 0),
    startTime: row.start_time ? new Date(row.start_time as string).toISOString() : null,
    completeTime: row.complete_time ? new Date(row.complete_time as string).toISOString() : null,
    faultCode: (row.fault_code as string | null) ?? null,
    faultString: (row.fault_string as string | null) ?? null,
    createdAt: new Date(row.created_at as string).toISOString(),
  };
}
