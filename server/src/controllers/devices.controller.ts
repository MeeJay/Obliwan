import type { EnrollDeviceInput } from '../validators/device.schema';
import type { Request, Response, NextFunction } from 'express';
import { FAMILY_BRAND, type DeviceFamily, type TransportKind } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import * as deviceService from '../services/fleet/device.service';
import { toDeviceDetailDto, toDeviceDto } from '../services/fleet/dto';
import {
  assertTargetBinding,
  BindingAssertionError,
} from '../services/fleet/deviceBinding.service';
import { pppPresence } from '../services/fleet/pppPresence.service';
import { assessDevice } from '../services/fleet/reachability.service';
import type {
  CreateConcentratorInput,
  CreateDeviceInput,
  UpdateDeviceInput,
  UpsertTransportInput,
} from '../validators/device.schema';

/**
 * Devices — HTTP layer.
 *
 * The response shapes come from `device.service.ts`, which is the only module
 * allowed to serialise a transport. Nothing in this file selects from
 * `device_transports` directly; that is how "no secret ever leaves through the
 * API" stays true after the fifth person edits this controller.
 *
 * Every device row is mapped by `services/fleet/dto.ts` before it reaches
 * `res.json()`. The columns are `snake_case`, the API contract is `camelCase`,
 * and the conversion happens at this edge and nowhere else. Transports keep
 * their own serialiser, `toPublicTransport()`, which is what guarantees
 * `hasSecret` / `hasPrivateKey` in place of `secret_enc` / `private_key_enc` —
 * encrypted or not, the blob never crosses this boundary (section 8.2).
 */

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

function pgCode(err: unknown): string | undefined {
  return typeof err === 'object' && err !== null ? (err as { code?: string }).code : undefined;
}

/** Turn the constraints of migration 002 into operator-readable answers. */
function translateDbError(err: unknown): AppError | null {
  const code = pgCode(err);
  const detail =
    typeof err === 'object' && err !== null ? String((err as { detail?: string }).detail ?? '') : '';

  if (code === '23505') {
    if (detail.includes('ppp_username')) {
      return new AppError(409, 'This PPP username is already bound to another device');
    }
    if (detail.includes('brand') && detail.includes('serial')) {
      return new AppError(409, 'A device with this brand and serial already exists');
    }
    return new AppError(409, 'A device with these unique attributes already exists');
  }
  if (code === '23503') {
    // FK RESTRICT — the concentrator still has children (this is on purpose:
    // deleting it would orphan the presence source of truth for a whole fleet).
    return new AppError(
      409,
      'This device is still referenced by other devices (a concentrator with attached CPEs cannot be deleted)',
    );
  }
  return null;
}

const DEFAULT_ENROL_TRANSPORT: Readonly<Record<string, TransportKind>> = {
  mikrotik_routeros6: 'routeros_api',
  mikrotik_routeros7: 'routeros_api',
  draytek_vigor: 'ssh',
  zyxel_standalone: 'ssh',
  zyxel_nebula: 'rest',
  zyxel_cpe: 'ssh',
  sonicwall_sonicos: 'rest',
};

export const devicesController = {
  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = req.query as Record<string, unknown>;
      const result = await deviceService.listDevices(req.tenantId, {
        siteId: q.siteId as number | undefined,
        role: q.role as string | undefined,
        status: q.status as string | undefined,
        brand: q.brand as string | undefined,
        family: q.family as string | undefined,
        concentratorId: q.concentratorId as number | undefined,
        search: q.search as string | undefined,
        limit: q.limit as number | undefined,
        offset: q.offset as number | undefined,
      });
      res.json({
        success: true,
        data: result.items.map(toDeviceDto),
        meta: { total: result.total },
      });
    } catch (err) {
      next(err);
    }
  },

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const device = await deviceService.getDeviceDetail(req.tenantId, parseId(req.params.id));
      if (!device) throw new AppError(404, 'Device not found');
      res.json({ success: true, data: toDeviceDetailDto(device) });
    } catch (err) {
      next(err);
    }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as CreateDeviceInput;
      const device = await deviceService.createDevice(req.tenantId, {
        ...body,
        family: body.family as DeviceFamily,
        role: body.role as 'cpe' | 'concentrator' | undefined,
        status: body.status as CreateDeviceInput['status'],
      } as deviceService.CreateDeviceData);
      res.status(201).json({ success: true, data: toDeviceDto(device) });
    } catch (err) {
      const translated = translateDbError(err);
      if (translated) return next(translated);
      if (err instanceof Error && err.message.includes('does not exist in this tenant')) {
        return next(new AppError(400, err.message));
      }
      next(err);
    }
  },

  /**
   * Declare the concentrator — the first gesture of an ObliWAN install.
   *
   * Creates the `devices` row (role `chr`) and its `routeros_api` transport in
   * one transaction-shaped call, then immediately tests the credential. A CHR
   * that was declared but never verified is worse than no CHR: discovery would
   * silently return nothing and read as "an empty fleet".
   */
  async createConcentrator(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as CreateConcentratorInput;
      const family = body.family as DeviceFamily;
      if (FAMILY_BRAND[family] !== 'mikrotik') {
        throw new AppError(400, 'The concentrator must be a MikroTik: only RouterOS serves /ppp/active');
      }

      const device = await deviceService.createDevice(req.tenantId, {
        name: body.name,
        family,
        role: 'concentrator',
        siteId: body.siteId ?? null,
        systemIdentity: body.systemIdentity ?? null,
        notes: body.notes ?? null,
        // A concentrator is active as soon as it answers; it is not a discovered
        // CPE waiting for a human to place it.
        status: 'active',
      });

      await deviceService.upsertTransport(req.tenantId, device.id, 'routeros_api', {
        enabled: true,
        priority: 10,
        host: body.host,
        port: body.port ?? null,
        username: body.username,
        secret: body.password,
        useTls: body.useTls ?? false,
        tlsFingerprintSha256: body.tlsFingerprintSha256 ?? null,
      });

      const test = await deviceService.testTransport(req.tenantId, device.id, 'routeros_api');
      if (test.ok && test.identity?.systemIdentity) {
        await deviceService.updateDevice(req.tenantId, device.id, {
          systemIdentity: test.identity.systemIdentity,
          serial: test.identity.serial ?? undefined,
        });
      }

      const detail = await deviceService.getDeviceDetail(req.tenantId, device.id);
      res.status(201).json({
        success: true,
        data: {
          device: detail ? toDeviceDetailDto(detail) : null,
          connection: test,
        },
      });
    } catch (err) {
      const translated = translateDbError(err);
      if (translated) return next(translated);
      next(err);
    }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const device = await deviceService.updateDevice(
        req.tenantId,
        parseId(req.params.id),
        req.body as UpdateDeviceInput as deviceService.UpdateDeviceData,
      );
      if (!device) throw new AppError(404, 'Device not found');
      res.json({ success: true, data: toDeviceDto(device) });
    } catch (err) {
      const translated = translateDbError(err);
      if (translated) return next(translated);
      if (err instanceof Error && /does not exist in this tenant|its own concentrator|not a concentrator/.test(err.message)) {
        return next(new AppError(400, err.message));
      }
      next(err);
    }
  },

  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const children = await deviceService.concentratorChildCount(req.tenantId, id);
      if (children > 0) {
        throw new AppError(
          409,
          `This concentrator still has ${children} device(s) attached. ` +
            'Re-attach or delete them first — deleting it would leave them with no presence source.',
        );
      }
      const ok = await deviceService.deleteDevice(req.tenantId, id);
      if (!ok) throw new AppError(404, 'Device not found');
      res.json({ success: true, message: 'Device deleted' });
    } catch (err) {
      const translated = translateDbError(err);
      if (translated) return next(translated);
      next(err);
    }
  },

  // ── Transports ────────────────────────────────────────────────────────────

  async listTransports(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = await deviceService.listTransports(req.tenantId, parseId(req.params.id));
      res.json({ success: true, data });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      next(err);
    }
  },

  async upsertTransport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = await deviceService.upsertTransport(
        req.tenantId,
        parseId(req.params.id),
        req.params.transport as TransportKind,
        req.body as UpsertTransportInput,
      );
      res.json({ success: true, data });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      if (err instanceof Error && err.message.startsWith('Unknown transport')) {
        return next(new AppError(400, err.message));
      }
      next(err);
    }
  },

  async deleteTransport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const ok = await deviceService.deleteTransport(
        req.tenantId,
        parseId(req.params.id),
        req.params.transport as TransportKind,
      );
      if (!ok) throw new AppError(404, 'Transport not found');
      res.json({ success: true, message: 'Transport deleted' });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      next(err);
    }
  },

  async testTransport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const result = await deviceService.testTransport(
        req.tenantId,
        parseId(req.params.id),
        req.params.transport as TransportKind,
      );
      // A failed test is a legitimate answer, not an HTTP error: the operator
      // asked a question and got one.
      res.json({ success: true, data: result });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      next(err);
    }
  },

  /**
   * "Test this device" — every enabled channel, once.
   *
   * The channel-level `POST /:id/transports/:transport/test` answers "does
   * THIS credential work". This one answers "can we reach this box at all",
   * which is the question the detail page's button actually asks and the one
   * the client has always called. Both are kept: they are different questions
   * and a device with four channels deserves both answers.
   *
   * The payload is `{ deviceId, results: [...] }` — a named envelope, because
   * a bare array leaves no room for the device-level context this will grow
   * (the arbiter's refusal reasons, in M3).
   */
  async testConnection(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const results = await deviceService.testAllTransports(req.tenantId, id);
      res.json({
        success: true,
        data: {
          deviceId: id,
          results: results.map((r) => ({
            transport: r.transport,
            ok: r.ok,
            rttMs: r.latencyMs,
            dialled: r.dialled,
            // Already redacted by the transport layer; never a credential.
            error: r.error,
          })),
        },
      });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      next(err);
    }
  },

  // ── Identity, presence, history ───────────────────────────────────────────

  /**
   * Re-prove the device's identity on a FRESH connection (D5 / R4).
   *
   * Exposed as an explicit operator action so the assertion can be exercised
   * before M6 gives it teeth. A failure is a 409, not a 500: the box answered,
   * it is simply not the box we recorded.
   */
  async assertBinding(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const device = await deviceService.getDevice(req.tenantId, id);
      if (!device) throw new AppError(404, 'Device not found');

      const assertion = await assertTargetBinding(id, { throwOnFailure: false });
      if (!assertion.ok) {
        res.status(409).json({ success: false, error: assertion.reason, data: assertion });
        return;
      }
      res.json({ success: true, data: assertion });
    } catch (err) {
      if (err instanceof BindingAssertionError) {
        res.status(409).json({
          success: false,
          error: err.assertion.reason,
          data: err.assertion,
        });
        return;
      }
      next(err);
    }
  },

  async sessions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const data = await deviceService.deviceSessions(req.tenantId, parseId(req.params.id));
      res.json({ success: true, data });
    } catch (err) {
      if (err instanceof Error && err.message.includes('does not exist')) {
        return next(new AppError(404, 'Device not found'));
      }
      next(err);
    }
  },

  async reachability(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const device = await deviceService.getDevice(req.tenantId, id);
      if (!device) throw new AppError(404, 'Device not found');
      const [history, current] = await Promise.all([
        deviceService.deviceVerdicts(req.tenantId, id),
        assessDevice(id),
      ]);
      res.json({ success: true, data: { current, history } });
    } catch (err) {
      next(err);
    }
  },

  /** Force a full `/ppp/active` sweep on a concentrator, now. */
  async reconcile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id);
      const device = await deviceService.getDevice(req.tenantId, id);
      if (!device) throw new AppError(404, 'Device not found');
      if (device.role !== 'concentrator') throw new AppError(400, 'This device is not a concentrator');
      const result = await pppPresence.reconcileNow(id);
      res.json({ success: true, data: result });
    } catch (err) {
      next(err);
    }
  },

  /** Which concentrators this process is streaming from, if it is the leader. */
  async presenceStatus(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const ids = await deviceService.concentratorIdsForTenant(req.tenantId);
      res.json({
        success: true,
        data: {
          running: pppPresence.isRunning,
          watched: pppPresence.watched.filter((id) => ids.includes(id)),
          concentrators: ids,
        },
      });
    } catch (err) {
      next(err);
    }
  },

  /**
   * Bench enrolment (M15) — a router configured on a workbench announces itself.
   *
   * ┌─ IT LANDS IN QUARANTINE, AND THE TENANT IS A SUGGESTION ───────────────┐
   * │ `status: 'pending'` and `is_managed: false`, whatever the payload says  │
   * │ — the bench tool does not even send them. This is the same quarantine   │
   * │ CHR discovery uses and for the same reason (D5 / R4): the preparer      │
   * │ picked a customer from a dropdown, on a workbench, on their fortieth    │
   * │ box of the day. Get it wrong and customer A's variables render onto     │
   * │ customer B's router. So `proposedTenantId` is recorded as a NOTE and    │
   * │ binds nothing; a human confirms it in the UI with the identity the box  │
   * │ actually reported in front of them.                                     │
   * │                                                                        │
   * │ Nothing dials a device this endpoint creates. It has no credential —    │
   * │ the factory password never left the preparer's workstation, and the     │
   * │ account the tool created goes to the vault through the normal path.     │
   * └────────────────────────────────────────────────────────────────────────┘
   *
   * The identity is REQUIRED to carry a serial or a system identity. Without
   * one, no later connection could be matched to this row, `assertTargetBinding`
   * would refuse it forever, and the fleet would hold a device it can see and
   * never touch — worse than one it never knew about. The bench tool refuses
   * first; this refuses again, because a client-side check is a convenience and
   * not a boundary.
   */
  /**
   * Single-device enrolment FROM THE UI (M15, second path).
   *
   * ┌─ THE SAME QUARANTINE, THE OPPOSITE SECRET POLICY ──────────────────────┐
   * │ Like the bench path, the device lands `pending` and unmanaged: a row an │
   * │ operator typed is a CLAIM about a box, and a claim is confirmed on a    │
   * │ fresh connection before anything is pushed (D5 / R4).                   │
   * │                                                                        │
   * │ Unlike the bench path, a credential IS transmitted — this is the one    │
   * │ ObliWAN will keep — so it goes straight to the vault and this route     │
   * │ demands `CREDENTIAL_MANAGE`. That capability is the whole difference    │
   * │ between the two, which is why they are two routes and not one route     │
   * │ with a flag.                                                           │
   * └────────────────────────────────────────────────────────────────────────┘
   *
   * The probe runs AFTER the transport is stored, because `testTransport`
   * reads the vault rather than taking a password as an argument — the same
   * path a real operation will use. Probing with the value from the request
   * body would prove that THIS password works, not that the stored one does,
   * and those two differ the day an encryption key is wrong.
   *
   * A probe that reads no identity does NOT delete the row. The operator can
   * see it, fix the credential and retry; and `pending` + unmanaged already
   * means nothing will dial it. Silently discarding what somebody typed is a
   * worse failure than leaving a row they can correct.
   */
  async enrollFromUi(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as EnrollDeviceInput;
      const family = body.family as DeviceFamily;
      const transport = (body.transport ?? DEFAULT_ENROL_TRANSPORT[family] ?? 'ssh') as TransportKind;

      const device = await deviceService.createDevice(req.tenantId, {
        name: body.name,
        family,
        role: 'cpe',
        siteId: body.siteId ?? null,
        systemIdentity: null,
        notes: body.notes ?? null,
        // Not negotiable by the payload. A human binds it afterwards.
        status: 'pending',
      });

      await deviceService.upsertTransport(req.tenantId, device.id, transport, {
        enabled: true,
        priority: 10,
        host: body.host,
        port: body.port ?? null,
        username: body.username,
        secret: body.password,
        useTls: body.useTls ?? transport === 'rest',
        tlsFingerprintSha256: null,
      });

      const test = await deviceService.testTransport(req.tenantId, device.id, transport);
      if (test.ok && (test.identity?.systemIdentity || test.identity?.serial)) {
        await deviceService.updateDevice(req.tenantId, device.id, {
          systemIdentity: test.identity.systemIdentity ?? undefined,
          serial: test.identity.serial ?? undefined,
        });
      }

      const detail = await deviceService.getDeviceDetail(req.tenantId, device.id);
      res.status(201).json({
        success: true,
        data: {
          device: detail ? toDeviceDetailDto(detail) : null,
          connection: test,
          // Said out loud rather than left for the operator to discover on the
          // first push: without one of the two identity attributes,
          // `assertTargetBinding` refuses every write to this device.
          identityRead: Boolean(test.identity?.systemIdentity || test.identity?.serial),
        },
      });
    } catch (err) {
      next(err);
    }
  },

  async enroll(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as {
        identity: {
          family: string; brand?: string | null; model?: string | null;
          osVersion?: string | null; serial?: string | null; systemIdentity?: string | null;
        };
        proposedTenantId?: number | null;
        note?: string | null;
        preparedBy?: string | null;
        preparedAt?: string | null;
      };
      const id = body?.identity;
      if (!id?.family) throw new AppError(400, 'identity.family is required');
      if (!id.serial && !id.systemIdentity) {
        throw new AppError(
          400,
          'The device reported neither a serial number nor a system identity. It cannot be ' +
            'recognised on a later connection (D5), so it is not enrolled.',
        );
      }

      const family = id.family as DeviceFamily;
      if (!FAMILY_BRAND[family]) throw new AppError(400, `unknown family '${id.family}'`);

      const provenance = [
        'Enrolled from a preparation bench (M15).',
        body.preparedBy ? `Workstation: ${body.preparedBy}.` : null,
        body.preparedAt ? `At: ${body.preparedAt}.` : null,
        // Recorded as text on purpose: a suggestion that lived in a foreign key
        // would be one migration away from becoming a binding.
        body.proposedTenantId ? `Tenant PROPOSED by the preparer: #${body.proposedTenantId} (not applied).` : null,
        body.note ? `Note: ${body.note}` : null,
      ].filter(Boolean).join(' ');

      const device = await deviceService.createDevice(req.tenantId, {
        name: id.systemIdentity || id.serial || `bench-${Date.now()}`,
        family,
        role: 'cpe',
        siteId: null,
        systemIdentity: id.systemIdentity ?? null,
        notes: provenance,
        // The quarantine. Not negotiable by the payload.
        status: 'pending',
      });

      res.status(201).json({
        success: true,
        data: { deviceId: device.id, status: 'pending' },
      });
    } catch (err) {
      next(err);
    }
  },
};
