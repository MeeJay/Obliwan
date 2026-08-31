import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { requireCapability } from '../middleware/rbac';
import { db } from '../db';

/**
 * Pre-change backups — READ ONLY, and deliberately not everything.
 *
 * ┌─ WHAT THIS ROUTE REFUSES TO EXPOSE, AND WHY ─────────────────────────────┐
 * │ `device_backups` carries two columns this API will never return:          │
 * │                                                                          │
 * │   `encryption_password_enc`  the key to the archive. §8.2: a secret       │
 * │                              exists in memory on the vault → device path  │
 * │                              and nowhere else. It is not selected here —  │
 * │                              not redacted, ABSENT, so no future refactor  │
 * │                              can leak it by widening a `select('*')`.     │
 * │   `storage_path`             a server-side filesystem path. Publishing it │
 * │                              buys an operator nothing and hands a reader  │
 * │                              the layout of the backup store.              │
 * │                                                                          │
 * │ There is also NO DOWNLOAD ENDPOINT. A backup is a device's complete       │
 * │ configuration; streaming it into a browser turns a controlled artefact    │
 * │ into a file in a Downloads folder, on a laptop, forever. Restoring is     │
 * │ what a backup is for, and restoring goes through `change_jobs` like every │
 * │ other write (D3). If a human ever needs the bytes, that is a deliberate   │
 * │ server-side operation with a name, not a link on a list.                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `CONFIG_READ` and not `DEVICE_READ`: knowing a device exists and reading its
 * configuration history are different privileges, and §Capabilities keeps them
 * apart precisely so config can be withheld.
 */
const router = Router();

router.get('/', requireCapability(CAPABILITIES.CONFIG_READ), async (req, res, next) => {
  try {
    const deviceId = req.query.deviceId ? Number(req.query.deviceId) : null;
    const limit = Math.min(Number(req.query.limit ?? 200), 500);

    let q = db('device_backups as b')
      .leftJoin('devices as d', 'd.id', 'b.device_id')
      .where('b.tenant_id', req.tenantId);
    if (deviceId) q = q.where('b.device_id', deviceId);

    const rows = await q
      .orderBy('b.created_at', 'desc')
      .limit(limit)
      .select(
        'b.id', 'b.device_id', 'b.kind', 'b.trigger_kind', 'b.size_bytes',
        'b.retention_class', 'b.expires_at', 'b.status', 'b.taken_before_job_id',
        'b.os_version', 'b.created_at',
        'd.name as device_name',
      );

    res.json({
      success: true,
      data: rows.map((r: Record<string, unknown>) => ({
        id: Number(r.id),
        deviceId: r.device_id === null ? null : Number(r.device_id),
        deviceName: (r.device_name as string | null) ?? null,
        kind: r.kind,
        triggerKind: r.trigger_kind,
        sizeBytes: Number(r.size_bytes ?? 0),
        retentionClass: r.retention_class,
        expiresAt: r.expires_at,
        status: r.status,
        takenBeforeJobId: r.taken_before_job_id === null ? null : Number(r.taken_before_job_id),
        osVersion: r.os_version,
        createdAt: r.created_at,
      })),
    });
  } catch (err) {
    next(err);
  }
});

export default router;
