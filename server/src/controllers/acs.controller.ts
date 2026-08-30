/**
 * ObliWAN — the ACS admin API (M10). HTTP layer only.
 *
 * ┌─ TENANT SCOPING, AND WHY EVERY LOOKUP GOES THROUGH `devices` ─────────────┐
 * │ Not one CWMP table carries a `tenant_id` (migration 015, decision 1). The │
 * │ join to `devices` IS the isolation, on every single read, and there is no │
 * │ shortcut: `assertDeviceInTenant()` runs before anything touches a         │
 * │ `cwmp_*` table with a device id from the URL. A device id belonging to    │
 * │ another customer is a 404 and never a 403 — a 403 confirms the row.       │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT THIS API WILL NOT DO ───────────────────────────────────────────────┐
 * │ 1. It will not push a firmware image or a parameter write on its own.     │
 * │    `set_parameter_values`, `download` and `reboot` are refused by         │
 * │    `enqueueTask` unless a `change_jobs` row authorises them (D3). The     │
 * │    endpoints exist and return 409 with the reason, which is more useful   │
 * │    than not existing: it tells the caller WHERE the door is.              │
 * │ 2. It will not draw a Refresh button. `POST …/refresh` answers a          │
 * │    `CwmpRefreshOutcome` whose `supported` is `false` and whose            │
 * │    `explanation` says why, and it lowers the inform interval instead.     │
 * │ 3. It will not return a secret. Parameter values on credential paths are  │
 * │    NULL in the column and NULL in the response (§8.2), and the HA1 of a   │
 * │    CPE is never serialised at all.                                        │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { AppError } from '../middleware/errorHandler';
import { db } from '../db';
import { config } from '../config';
import { logger } from '../utils/logger';
import * as acs from '../services/cwmp';
import { acsReadiness } from '../cwmp';
import {
  ACS_BRAND_COVERAGE,
  CWMP_ROOT_PREFIX,
  CWMP_SENSITIVE_NOTE,
  acsCoversFamily,
  acsSettingsSchema,
  classifyReachability,
  downloadSchema,
  getParameterValuesSchema,
  paramMapUpsertSchema,
  setParameterValuesSchema,
  summarisePayload,
  type AcsDeviceDetail,
  type AcsDeviceSummary,
  type CwmpDataModel,
  type CwmpQuirks,
} from '../services/cwmp/contract';

// ============================================================================
// Helpers
// ============================================================================

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    const flat = result.error.flatten();
    const fields = Object.entries(flat.fieldErrors)
      .map(([f, m]) => `${f}: ${((m as string[] | undefined) ?? []).join(', ')}`)
      .concat(flat.formErrors)
      .filter((s) => s.length > 0)
      .join('; ');
    throw new AppError(400, fields ? `Validation failed — ${fields}` : 'Validation failed');
  }
  return result.data;
}

interface DeviceRow {
  id: number;
  name: string;
  brand: string;
  family: string;
  model: string | null;
}

/**
 * THE ISOLATION. Every handler that takes a device id from the URL calls this
 * FIRST, and nothing below it re-checks — which is only safe because there is
 * exactly one way in.
 */
async function assertDeviceInTenant(req: Request, deviceId: number): Promise<DeviceRow> {
  const row = (await db('devices')
    .where({ id: deviceId, tenant_id: req.tenantId })
    .first('id', 'name', 'brand', 'family', 'model')) as DeviceRow | undefined;
  if (!row) throw new AppError(404, 'Device not found');
  return row;
}

type CwmpRow = acs.CwmpDeviceRow;

async function loadCpe(deviceId: number): Promise<CwmpRow> {
  const row = (await db('cwmp_devices').where({ device_id: deviceId }).first()) as
    | CwmpRow
    | undefined;
  if (!row) {
    throw new AppError(
      404,
      'This device is not enrolled in the ACS. Enrol it first (POST /api/acs/devices/:id/enrol).',
    );
  }
  return row;
}

function toSummary(device: DeviceRow, cwmp: CwmpRow, counts: { params: number; tasks: number }): AcsDeviceSummary {
  return {
    deviceId: device.id,
    deviceName: device.name,
    brand: device.brand,
    family: device.family,
    cwmpId: cwmp.cwmp_id,
    dataModel: cwmp.data_model,
    cwmpVersion: cwmp.cwmp_version,
    rootPrefix: cwmp.root_prefix,
    reachability: classifyReachability(cwmp.last_inform_at, cwmp.periodic_inform_interval),
    lastInformAt: cwmp.last_inform_at ? new Date(cwmp.last_inform_at).toISOString() : null,
    lastInformEvents: cwmp.last_inform_events ?? [],
    periodicInformInterval: cwmp.periodic_inform_interval,
    parameterCount: counts.params,
    pendingTasks: counts.tasks,
    // Always false, carried per device so the client never hardcodes it.
    connectionRequestSupported: false,
  };
}

// ============================================================================
// Controller
// ============================================================================

export const acsController = {
  /**
   * The coverage panel (risk R2). Deliberately the first endpoint in this file:
   * it is the answer to the question every operator asks first, and it is
   * readable by anyone who may see the ACS at all.
   */
  async coverage(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await acs.coverageReport(req.tenantId) });
    } catch (err) {
      next(err);
    }
  },

  /** Boot-time readiness, on demand: "why is nothing arriving on 7547". */
  async status(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const settings = await acs.settingsForTenant(req.tenantId);
      res.json({
        success: true,
        data: {
          listenerPort: config.cwmp.port,
          tlsPort: config.cwmp.tlsCertPath ? config.cwmp.tlsPort : null,
          enabled: config.cwmp.enabled,
          acsUrl: settings
            ? `${config.cwmp.publicBaseUrl.replace(/\/+$/, '')}/${settings.tenantSlug}`
            : null,
          settings,
          warnings: await acsReadiness(),
          unknownCallers: await acs.listUnknownCallers(),
          connectionRequestSupported: false,
          brands: ACS_BRAND_COVERAGE,
        },
      });
    } catch (err) {
      next(err);
    }
  },

  // ── Settings ─────────────────────────────────────────────────────────────

  async getSettings(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await acs.ensureSettingsForTenant(req.tenantId) });
    } catch (err) {
      next(err);
    }
  },

  /**
   * Update the ACS settings.
   *
   * `tenantSlug` is deliberately NOT patchable. It is burned into every CPE in
   * the field, and renaming it orphans all of them until each is re-provisioned
   * on site. A schema that silently accepted it would make that a one-click
   * mistake.
   */
  async updateSettings(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(acsSettingsSchema.partial(), req.body);
      await acs.ensureSettingsForTenant(req.tenantId);
      const after = await acs.updateSettings(req.tenantId, input);
      acs.invalidateRpcLogGate();
      // NOTE ON AUDIT: `audit_log` (ARCHITECTURE §3.7 — append-only, chained by
      // hash) has no writer in this tree yet; `audit.service.ts` implements
      // `command_audit` only, which is for commands SENT TO A DEVICE and would
      // be the wrong table for a settings change. Rather than invent a second
      // audit trail from this milestone, the act is logged through pino and
      // this comment names the gap for whoever lands `audit_log`.
      logger.info(
        { tenantId: req.tenantId, userId: req.session.userId, change: input },
        'ACS: settings updated',
      );
      res.json({ success: true, data: after });
    } catch (err) {
      next(err);
    }
  },

  // ── Devices ──────────────────────────────────────────────────────────────

  async listDevices(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const rows = (await db('cwmp_devices as c')
        .join('devices as d', 'd.id', 'c.device_id')
        .where('d.tenant_id', req.tenantId)
        .orderBy('c.last_inform_at', 'desc')
        .select('c.*', 'd.name as d_name', 'd.brand as d_brand', 'd.family as d_family',
          'd.model as d_model')) as Array<CwmpRow & Record<string, unknown>>;

      const ids = rows.map((r) => r.device_id);
      const pending = await acs.countPending(ids);
      const paramCounts = await parameterCounts(ids);

      res.json({
        success: true,
        data: rows.map((r) =>
          toSummary(
            {
              id: r.device_id,
              name: String(r.d_name),
              brand: String(r.d_brand),
              family: String(r.d_family),
              model: (r.d_model as string | null) ?? null,
            },
            r,
            { params: paramCounts.get(r.device_id) ?? 0, tasks: pending.get(r.device_id) ?? 0 },
          ),
        ),
      });
    } catch (err) {
      next(err);
    }
  },

  async getDevice(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const device = await assertDeviceInTenant(req, deviceId);
      const cwmp = await loadCpe(deviceId);

      const paths = await acs.knownPaths(deviceId);
      const values = await acs.valuesFor(deviceId, paths);
      const canonical = await acs.canonicalValues(
        {
          tenantId: req.tenantId,
          dataModel: cwmp.data_model,
          brand: device.brand,
          model: device.model,
          firmware: cwmp.software_version,
        },
        paths,
        values,
      );

      // WHAT THIS CPE'S CANONICAL MODEL IS MISSING, and it is not a footnote.
      // On TR-181 the WAN and LAN addresses are structurally identical paths
      // that differ only by instance number, so learn mode refuses to guess
      // which is which — and the operator has to be TOLD that, next to the
      // device, or the field is simply blank forever with no explanation.
      const unmapped = await acs.unmappedKeys({
        tenantId: req.tenantId,
        dataModel: cwmp.data_model,
        brand: device.brand,
        model: device.model,
        firmware: cwmp.software_version,
      });

      const pending = await acs.countPending([deviceId]);
      const detail: AcsDeviceDetail = {
        ...toSummary(device, cwmp, { params: paths.length, tasks: pending.get(deviceId) ?? 0 }),
        manufacturer: cwmp.manufacturer,
        oui: cwmp.oui,
        productClass: cwmp.product_class,
        serialNumber: cwmp.serial_number,
        hardwareVersion: cwmp.hardware_version,
        softwareVersion: cwmp.software_version,
        vendorQuirks: (cwmp.vendor_quirks ?? {}) as CwmpQuirks,
        canonical,
      };

      res.json({
        success: true,
        data: detail,
        meta: {
          // The URL an operator has to type into the CPE. Surfaced next to the
          // device rather than only in settings: it is what the installer needs.
          connectionRequestUrl: cwmp.connection_request_url,
          connectionRequestNote:
            'Announced by the CPE and shown for diagnostics only. ObliWAN never dials it.',
          sensitiveNote: CWMP_SENSITIVE_NOTE,
          unmappedCanonicalKeys: unmapped,
          unmappedNote:
            unmapped.length === 0
              ? undefined
              : 'These canonical fields have no parameter mapping for this model. Learn mode ' +
                'refuses to guess when two candidate paths are structurally identical (on ' +
                'TR-181 the WAN and LAN addresses differ only by instance number). Map them ' +
                'once under Parameter map and they resolve from then on.',
        },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * Enrol a device, or rotate its credential.
   *
   * The password is in the response ONCE and is stored nowhere: only HA1 is
   * kept, and encrypted (§8.2, migration 015 decision 7). A caller that loses
   * it rotates rather than recovers, which is the correct shape.
   */
  async enrol(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const device = await assertDeviceInTenant(req, deviceId);

      if (!acsCoversFamily(device.family)) {
        // 409 and not 400: the request is well-formed, the WORLD refuses it.
        throw new AppError(
          409,
          `The ACS does not cover ${device.family}: this hardware has no TR-069 client and ` +
            'never will (risk R2). Manage it over its own transport.',
        );
      }

      const settings = await acs.ensureSettingsForTenant(req.tenantId);
      const result = await acs.enrolDevice(
        deviceId,
        req.tenantId,
        settings.digestRealm,
        config.cwmp.publicBaseUrl || `http://<this-server>:${config.cwmp.port}`,
        settings.tenantSlug,
      );

      // The username is not a secret; the password is, and it is absent from
      // this line on purpose. A log is a place secrets go to be discovered.
      logger.info(
        {
          tenantId: req.tenantId,
          deviceId,
          userId: req.session.userId,
          username: result.username,
        },
        'ACS: device enrolled / credential rotated',
      );

      res.json({
        success: true,
        data: result,
        meta: {
          warning:
            'This password is shown once and is not stored. Provision it into the CPE now; ' +
            'if it is lost, rotate rather than recover.',
        },
      });
    } catch (err) {
      if (err instanceof acs.AcsEnrolmentError) {
        next(new AppError(err.code === 'no_device' ? 404 : 409, err.message));
        return;
      }
      next(err);
    }
  },

  // ── Parameters ───────────────────────────────────────────────────────────

  async listParameters(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await assertDeviceInTenant(req, deviceId);
      await loadCpe(deviceId);

      const prefix = typeof req.query.prefix === 'string' ? req.query.prefix : undefined;
      const limit = Number.parseInt(String(req.query.limit ?? '500'), 10);
      const offset = Number.parseInt(String(req.query.offset ?? '0'), 10);

      const result = await acs.listParameters(deviceId, {
        prefix,
        limit: Number.isFinite(limit) ? limit : 500,
        offset: Number.isFinite(offset) ? offset : 0,
      });

      res.json({
        success: true,
        data: result.parameters,
        meta: { total: result.total, sensitiveNote: CWMP_SENSITIVE_NOTE },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * The CPE's configuration, as a document.
   *
   * A DrayTek `.cfg` is a vendor-encrypted binary keyed to the model and a
   * Zyxel CPE has no config export at all, so for these two families the
   * CONFIGURATION IS THE PARAMETER TREE (decision D1). This is the equivalent
   * of "show me this router's config" on the MikroTik side, and it is what the
   * NCM collector will consume when the config workstream wires it in.
   *
   * Sorted and stable so an unchanged CPE hashes identically twice —
   * `config_snapshots` deduplicates on `ncm_hash`, and an unstable ordering
   * would make every collection a new row.
   */
  async configDocument(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await assertDeviceInTenant(req, deviceId);
      await loadCpe(deviceId);

      const document = await acs.cwmpConfigDocument(deviceId);
      if (document === null) {
        throw new AppError(
          404,
          'This CPE has never reported any parameters. Queue a discovery read and wait for ' +
            'its next inform.',
        );
      }
      res.json({
        success: true,
        data: { document, lines: document.split('\n').length },
        // Credential paths are present with an explicit marker instead of the
        // value: a diff has to be able to see that the parameter exists (§8.2).
        meta: { sensitiveNote: CWMP_SENSITIVE_NOTE },
      });
    } catch (err) {
      next(err);
    }
  },

  /** Queue a read. A read needs no change job — same rule as `/config/collect`. */
  async queueRead(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await assertDeviceInTenant(req, deviceId);
      const input = parse(getParameterValuesSchema, req.body);

      const task = await acs.enqueueTask(
        deviceId,
        { kind: 'get_parameter_values', paths: input.paths },
        { createdBy: req.session.userId ?? null },
      );
      res.status(202).json({ success: true, data: task, meta: whenWillItRun() });
    } catch (err) {
      next(mapTaskError(err));
    }
  },

  /**
   * Queue a full-tree read.
   *
   * ONE RPC on the root partial path, not a walk: `GetParameterValues` on a
   * name ending in `.` returns the whole subtree (arbitrage A1 — no
   * GetParameterNames). This is also what feeds learn mode.
   */
  async queueDiscovery(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await assertDeviceInTenant(req, deviceId);
      const cwmp = await loadCpe(deviceId);

      const task = await acs.enqueueTask(
        deviceId,
        {
          kind: 'get_parameter_values',
          paths: [CWMP_ROOT_PREFIX[cwmp.data_model as CwmpDataModel]],
        },
        { createdBy: req.session.userId ?? null, ttlSeconds: 3600 },
      );
      res.status(202).json({ success: true, data: task, meta: whenWillItRun() });
    } catch (err) {
      next(mapTaskError(err));
    }
  },

  /**
   * Queue a write. REFUSED without a change job (D3) — and the refusal is the
   * point of the endpoint existing at all.
   */
  async queueWrite(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await assertDeviceInTenant(req, deviceId);
      const input = parse(setParameterValuesSchema, req.body);
      const changeJobId = await requireChangeJob(req, deviceId);

      const task = await acs.enqueueTask(
        deviceId,
        {
          kind: 'set_parameter_values',
          // `valueType` has a Zod default, which the schema's INPUT type still
          // marks optional. Re-asserting it here is not ceremony: a
          // `SetParameterValues` with a missing `xsi:type` is rejected by the
          // CPE for the WHOLE envelope, not just that leaf.
          ops: input.ops.map((op) => ({ ...op, valueType: op.valueType ?? 'xsd:string' })),
          parameterKey: input.parameterKey,
        },
        { createdBy: req.session.userId ?? null, changeJobId },
      );
      res.status(202).json({ success: true, data: task, meta: whenWillItRun() });
    } catch (err) {
      next(mapTaskError(err));
    }
  },

  async queueDownload(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const device = await assertDeviceInTenant(req, deviceId);
      const input = parse(downloadSchema, req.body);
      const changeJobId = await requireChangeJob(req, deviceId);

      const file = await acs.getFile(input.fileId, req.tenantId);
      if (!file) throw new AppError(404, 'File not found');
      // A firmware pushed to the wrong model bricks a router and the recovery
      // is a van. Checked before the task exists, not at dispatch time.
      acs.assertFileFitsDevice(file, device);

      const task = await acs.enqueueTask(
        deviceId,
        {
          kind: 'download',
          fileType: file.fileType,
          fileId: file.id,
          fileSize: file.sizeBytes,
          targetFileName: input.targetFileName,
        },
        { createdBy: req.session.userId ?? null, changeJobId, ttlSeconds: 7 * 24 * 3600 },
      );
      res.status(202).json({ success: true, data: task, meta: whenWillItRun() });
    } catch (err) {
      if (err instanceof acs.TransferRefusedError) {
        next(new AppError(409, err.message));
        return;
      }
      next(mapTaskError(err));
    }
  },

  async queueReboot(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await assertDeviceInTenant(req, deviceId);
      const changeJobId = await requireChangeJob(req, deviceId);

      const task = await acs.enqueueTask(
        deviceId,
        { kind: 'reboot' },
        { createdBy: req.session.userId ?? null, changeJobId },
      );
      res.status(202).json({ success: true, data: task, meta: whenWillItRun() });
    } catch (err) {
      next(mapTaskError(err));
    }
  },

  /** The honest "refresh". See `refresh.service.ts`. */
  async refresh(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await assertDeviceInTenant(req, deviceId);
      const outcome = await acs.requestRefresh(deviceId, req.session.userId ?? null);
      res.status(202).json({ success: true, data: outcome });
    } catch (err) {
      next(mapTaskError(err));
    }
  },

  // ── Tasks and transfers ──────────────────────────────────────────────────

  async listTasks(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await assertDeviceInTenant(req, deviceId);
      const tasks = await acs.listTasks(deviceId, { limit: 200 });
      res.json({
        success: true,
        // `payloadSummary` and NOT the payload: a set_parameter_values on a
        // credential path renders as "(from vault)" and never as a value.
        data: tasks.map((t) => ({
          id: t.id,
          deviceId: t.deviceId,
          kind: t.kind,
          commandKey: t.commandKey,
          state: t.state,
          attempts: t.attempts,
          maxAttempts: t.maxAttempts,
          // REDACTED AGAIN ON THE WAY OUT. `handleCpeFault` already redacts
          // before `failTask` stores it, so this is the belt for rows written
          // before that existed — and it is why the header of this file can
          // keep saying that no secret leaves through here.
          fault: t.fault ? acs.redactFault(t.fault, t) : null,
          createdAt: t.createdAt,
          sentAt: t.sentAt,
          completedAt: t.completedAt,
          expiresAt: t.expiresAt,
          payloadSummary: summarisePayload(t.payload),
        })),
      });
    } catch (err) {
      next(err);
    }
  },

  async cancelTask(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const taskId = parseId(req.params.taskId, 'task id');
      await assertDeviceInTenant(req, deviceId);
      const ok = await acs.cancelTask(taskId, deviceId);
      if (!ok) throw new AppError(404, 'Task not found, or already finished');
      res.json({ success: true });
    } catch (err) {
      next(err);
    }
  },

  async listTransfers(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await assertDeviceInTenant(req, deviceId);
      const transfers = await acs.listTransfers(deviceId);
      // `urlToken` is stripped: it is the authorisation for the file fetch and
      // it does not belong in an API response any more than in a log.
      res.json({
        success: true,
        data: transfers.map(({ urlToken: _omitted, ...rest }) => rest),
      });
    } catch (err) {
      next(err);
    }
  },

  async listFiles(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await acs.listFiles(req.tenantId) });
    } catch (err) {
      next(err);
    }
  },

  // ── Parameter map ────────────────────────────────────────────────────────

  async listMappings(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const learnedOnly = req.query.learned === 'true';
      res.json({
        success: true,
        data: await acs.listMappings(req.tenantId, { learnedOnly }),
      });
    } catch (err) {
      next(err);
    }
  },

  async upsertMapping(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(paramMapUpsertSchema, req.body);
      const mapping = await acs.upsertMapping(req.tenantId, input);
      logger.info(
        { tenantId: req.tenantId, userId: req.session.userId, mappingId: mapping.id },
        'ACS: parameter mapping upserted',
      );
      res.json({ success: true, data: mapping });
    } catch (err) {
      next(err);
    }
  },

  async deleteMapping(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'mapping id');
      const ok = await acs.deleteMapping(req.tenantId, id);
      if (!ok) {
        throw new AppError(
          404,
          'Mapping not found. Shipped library mappings (no tenant) cannot be deleted — ' +
            'override them with a tenant mapping of lower priority instead.',
        );
      }
      res.json({ success: true });
    } catch (err) {
      next(err);
    }
  },

  // ── RPC log ──────────────────────────────────────────────────────────────

  /**
   * The envelope log of one device.
   *
   * Behind `ACS_ADMIN` like everything else here, and worth saying why it is
   * not behind something weaker: the bodies are redacted (§8.2) but they still
   * describe a customer's network in complete detail.
   */
  async rpcLog(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await assertDeviceInTenant(req, deviceId);
      const enabled = await acs.loggingEnabledFor(deviceId);
      const entries = await acs.readRpcLog({ deviceId, limit: 200 });
      res.json({
        success: true,
        data: entries,
        meta: {
          enabled,
          note: enabled
            ? 'Bodies are redacted before they are stored. Retention is 7 days.'
            : 'RPC logging is OFF for this device. It must be enabled on BOTH the tenant ' +
              '(ACS settings) and the device — it is the table that explodes (risk R7).',
        },
      });
    } catch (err) {
      next(err);
    }
  },

  async setRpcLog(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      await assertDeviceInTenant(req, deviceId);
      const { enabled } = parse(z.object({ enabled: z.boolean() }), req.body);
      await db('cwmp_devices')
        .where({ device_id: deviceId })
        .update({ rpc_log_enabled: enabled, updated_at: db.fn.now() });
      acs.invalidateRpcLogGate();
      res.json({ success: true, data: { enabled } });
    } catch (err) {
      next(err);
    }
  },
};

// ============================================================================
// Local helpers
// ============================================================================

async function parameterCounts(deviceIds: readonly number[]): Promise<Map<number, number>> {
  if (deviceIds.length === 0) return new Map();
  const rows = (await db('cwmp_parameters')
    .whereIn('device_id', deviceIds as number[])
    .groupBy('device_id')
    .select('device_id')
    .count<{ device_id: number; count: string }[]>('* as count')) as Array<{
    device_id: number;
    count: string;
  }>;
  return new Map(rows.map((r) => [r.device_id, Number(r.count)]));
}

/**
 * Find the change job that authorises a mutation on this device (D3).
 *
 * `?changeJobId=` names it explicitly. Without one the request is refused with
 * a message that says where the door is — a 409 an operator can act on rather
 * than a 403 they have to guess at.
 */
async function requireChangeJob(req: Request, deviceId: number): Promise<number> {
  const raw = req.body?.changeJobId ?? req.query.changeJobId;
  const id = Number.parseInt(String(raw ?? ''), 10);
  if (!Number.isInteger(id) || id <= 0) {
    throw new AppError(
      409,
      'Writing to a CPE goes through a change job (decision D3: nothing writes to an ' +
        'equipment outside change_jobs). Create the job first and pass its id as changeJobId.',
    );
  }

  const job = (await db('change_jobs as j')
    .join('devices as d', 'd.id', 'j.device_id')
    .where('j.id', id)
    .andWhere('d.tenant_id', req.tenantId)
    .first('j.id', 'j.device_id', 'j.status')) as
    | { id: number; device_id: number; status: string }
    | undefined;

  if (!job) throw new AppError(404, 'Change job not found');
  if (job.device_id !== deviceId) {
    throw new AppError(409, 'That change job targets a different device');
  }
  // The non-terminal statuses of `change_jobs` (migration 009). A finished job
  // must not be able to authorise a fresh RPC days later: the plan it was
  // frozen against is long gone, which is the whole point of `base_state_hash`.
  const LIVE_STATUSES = [
    'queued',
    'claimed',
    'backing_up',
    'arming',
    'applying',
    'verifying',
    'soaking',
    'disarming',
  ];
  if (!LIVE_STATUSES.includes(job.status)) {
    throw new AppError(409, `Change job ${id} is ${job.status} and cannot authorise a new RPC`);
  }
  return job.id;
}

function mapTaskError(err: unknown): unknown {
  if (err instanceof acs.TaskRefusedError) {
    return new AppError(err.code === 'not_enrolled' ? 404 : 409, err.message);
  }
  return err;
}

/**
 * The sentence every 202 carries.
 *
 * A queued CWMP task is NOT a completed action, and an API that returned 200
 * with a task id would be inviting the client to draw a spinner. Saying when it
 * will run — and that the ACS cannot make it sooner — is the same honesty as
 * the refusal to draw a Refresh button.
 */
function whenWillItRun(): Record<string, unknown> {
  return {
    queued: true,
    connectionRequestSupported: false,
    note:
      'The task is queued. It runs the next time the CPE contacts the ACS on its own ' +
      'inform interval — ObliWAN cannot make a CPE call in on demand.',
  };
}
