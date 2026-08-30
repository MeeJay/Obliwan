/**
 * ObliWAN — the parameter tree, and the §8.2 gate every value passes through.
 *
 * ┌─ THE ONE RULE ────────────────────────────────────────────────────────────┐
 * │ A TR-069 parameter tree contains the customer's PPPoE/L2TP password, the  │
 * │ Wi-Fi passphrase, the pre-shared key and every local login. `upsert()` is │
 * │ the ONLY writer of `cwmp_parameters`, and it drops the value of every     │
 * │ path `isSecretParameterPath()` recognises BEFORE the row reaches the      │
 * │ database. The database then refuses the row anyway                        │
 * │ (`cwmp_parameters_secret_null_chk`), which is the belt to this brace.     │
 * │                                                                          │
 * │ The last audit found the L2TP passwords of an entire fleet in a jsonb     │
 * │ column that was being served to the UI. Two independent mechanisms is     │
 * │ the correct number for a mistake that has already been made once.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY THE PATH IS KEPT WHEN THE VALUE IS NOT ──────────────────────────────┐
 * │ Deleting the row entirely would be worse than keeping it. The path is     │
 * │ what tells the operator the parameter EXISTS and is writable, which is    │
 * │ what makes "push the PPPoE password from the vault" possible at all       │
 * │ (§8.2: the platform is the vault and it renders complete configurations). │
 * │ The row with a NULL value and `is_secret = true` is the honest record:    │
 * │ "this exists, we can write it, we do not keep what is in it".            │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { db } from '../../db';
import { isSecretParameterPath, type CwmpParameter, type CwmpValueType } from './contract';

export interface IncomingParameter {
  path: string;
  value: string;
  valueType: CwmpValueType;
  writable?: boolean;
}

export interface UpsertResult {
  written: number;
  /** How many arrived carrying a credential whose value was dropped. Surfaced
   *  so an operator can SEE that suppression is happening rather than take it
   *  on trust. */
  secretsSuppressed: number;
}

/**
 * Write a batch of parameters.
 *
 * One statement per batch of 500 rather than one per parameter: a full TR-181
 * subtree read is 400-1200 leaves and a per-row round trip would make the
 * session outlive the CPE's own timeout.
 */
export async function upsertParameters(
  deviceId: number,
  params: readonly IncomingParameter[],
): Promise<UpsertResult> {
  if (params.length === 0) return { written: 0, secretsSuppressed: 0 };

  let secretsSuppressed = 0;
  const rows = params.map((p) => {
    const secret = isSecretParameterPath(p.path);
    if (secret) secretsSuppressed++;
    return {
      device_id: deviceId,
      path: p.path.slice(0, 512),
      // THE GATE. Nothing downstream has to remember to do this.
      value: secret ? null : p.value,
      value_type: p.valueType,
      writable: p.writable ?? false,
      is_secret: secret,
      updated_at: db.fn.now(),
    };
  });

  // Deduplicate within the batch: a CPE that repeats a path in one
  // ParameterList makes `ON CONFLICT` fail with "cannot affect row a second
  // time", which would abort the whole session over a cosmetic vendor bug.
  const byPath = new Map<string, (typeof rows)[number]>();
  for (const row of rows) byPath.set(row.path, row);
  const unique = [...byPath.values()];

  let written = 0;
  for (let i = 0; i < unique.length; i += 500) {
    const chunk = unique.slice(i, i + 500);
    await db('cwmp_parameters')
      .insert(chunk)
      .onConflict(['device_id', 'path'])
      .merge(['value', 'value_type', 'writable', 'is_secret', 'updated_at']);
    written += chunk.length;
  }

  return { written, secretsSuppressed };
}

export interface ListOptions {
  prefix?: string;
  limit?: number;
  offset?: number;
}

/**
 * Read the tree, or a subtree.
 *
 * `prefix` uses `LIKE 'x%'`, which is what `cwmp_parameters_prefix_idx`
 * (`varchar_pattern_ops`) exists for. The `%` and `_` in the caller's prefix
 * are escaped: a path containing an underscore is completely ordinary in
 * TR-181 and would otherwise silently widen the match.
 */
export async function listParameters(
  deviceId: number,
  opts: ListOptions = {},
): Promise<{ parameters: CwmpParameter[]; total: number }> {
  const base = db('cwmp_parameters').where({ device_id: deviceId });
  if (opts.prefix) {
    base.andWhere('path', 'like', `${escapeLike(opts.prefix)}%`);
  }

  const countRow = (await base.clone().count<{ count: string }[]>('* as count'))[0];
  const rows = (await base
    .clone()
    .orderBy('path')
    .limit(Math.min(opts.limit ?? 500, 5000))
    .offset(opts.offset ?? 0)) as Array<{
    path: string;
    value: string | null;
    value_type: CwmpValueType;
    writable: boolean;
    notification: number;
    is_secret: boolean;
    updated_at: Date;
  }>;

  return {
    total: Number(countRow?.count ?? 0),
    parameters: rows.map((r) => ({
      path: r.path,
      // Already NULL in the column for a secret. Re-asserted here so that a
      // future migration that loosens the CHECK cannot leak through the API.
      value: r.is_secret ? null : r.value,
      valueType: r.value_type,
      writable: r.writable,
      notification: (r.notification === 1 || r.notification === 2 ? r.notification : 0) as 0 | 1 | 2,
      isSecret: r.is_secret,
      updatedAt: r.updated_at.toISOString(),
    })),
  };
}

/** Every path we know for a device — the input to `expandInstanceTemplate`. */
export async function knownPaths(deviceId: number): Promise<string[]> {
  const rows = (await db('cwmp_parameters')
    .where({ device_id: deviceId })
    .select('path')) as Array<{ path: string }>;
  return rows.map((r) => r.path);
}

/** Raw values for a set of paths. Secrets come back NULL, by construction. */
export async function valuesFor(
  deviceId: number,
  paths: readonly string[],
): Promise<Map<string, string | null>> {
  if (paths.length === 0) return new Map();
  const rows = (await db('cwmp_parameters')
    .where({ device_id: deviceId })
    .whereIn('path', paths as string[])
    .select('path', 'value', 'is_secret')) as Array<{
    path: string;
    value: string | null;
    is_secret: boolean;
  }>;
  return new Map(rows.map((r) => [r.path, r.is_secret ? null : r.value]));
}

function escapeLike(input: string): string {
  return input.replace(/[\\%_]/g, (c) => `\\${c}`);
}
