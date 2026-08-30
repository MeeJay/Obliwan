/**
 * ObliWAN — the bench provisioning core (M15).
 *
 * ┌─ WHAT THIS IS FOR ───────────────────────────────────────────────────────┐
 * │ An order preparer has a brand-new router on a workbench, on their own     │
 * │ LAN, with its factory password. ObliWAN cannot reach it: there is no      │
 * │ tunnel yet, and there will not be one until the box is configured. So     │
 * │ something local has to do the first configuration — and that something is │
 * │ the only place in the product allowed to write local accounts.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY IT IS TYPESCRIPT AND NOT GO, UNLIKE THE OTHER OBLI* AGENTS ─────────┐
 * │ Obliview and Obliance ship Go agents because they do OS-level work:       │
 * │ hardware UUIDs, PawnIO, airgap. This tool does VENDOR PROTOCOL work —     │
 * │ RouterOS binary API, SSH dialects, SonicOS REST — every line of which is  │
 * │ already written, reviewed and harnessed in `services/drivers` and         │
 * │ `services/transport`.                                                    │
 * │                                                                          │
 * │ Rewriting it in Go would create a SECOND renderer for the same devices.   │
 * │ The day the two disagree by one space, every freshly prepared router      │
 * │ arrives with drift on its first collection — risk R3, on exactly the      │
 * │ population just installed, found weeks later. One implementation, shared  │
 * │ with the server, versioned with it.                                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE TWO REFUSALS THAT MAKE THIS SAFE ───────────────────────────────────┐
 * │ 1. IT PROPOSES A TENANT, IT NEVER ASSIGNS ONE. The preparer picks a       │
 * │    customer from a list on a workbench, at 4pm, on their fortieth box.    │
 * │    That is exactly the human step D5/R4 exists to distrust: get it wrong  │
 * │    and customer A's variables render onto customer B's router. So the     │
 * │    device lands `pending` and unmanaged — the same quarantine CHR         │
 * │    discovery uses — and a human binds it afterwards, in the UI, with the  │
 * │    identity the box actually reported in front of them.                   │
 * │                                                                          │
 * │ 2. THE FACTORY PASSWORD NEVER LEAVES THIS PROCESS. It is typed by the     │
 * │    preparer, used to open one session, and dropped. It is not sent to     │
 * │    ObliWAN, not stored, and not in the enrolment payload. The credential  │
 * │    ObliWAN will later use is the one this tool CREATES, and that one goes │
 * │    to the vault through the normal path, never through here.              │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

import type { DeviceFamily, TransportKind } from '@obliwan/shared';
import { getDriver } from '../services/drivers/registry';
import type { DriverContext, ResolvedTransport } from '../services/drivers/types';

/** What the preparer types, and nothing more. */
export interface BenchTarget {
  /** Address on the WORKBENCH lan. Never recorded as identity (D5). */
  host: string;
  port?: number;
  family: DeviceFamily;
  /** Factory account. Used once, never transmitted, never stored. */
  username: string;
  password: string;
  /** Which transport to speak. Defaults per family. */
  transport?: TransportKind;
}

/** What the tool learned from the box itself. */
export interface BenchIdentity {
  family: DeviceFamily;
  brand: string | null;
  model: string | null;
  osVersion: string | null;
  /** Read off the hardware. This is what makes the far side recognise the box
   *  rather than create a second row for it (D5). */
  serial: string | null;
  systemIdentity: string | null;
}

/** The payload posted to `/api/devices/enroll`. Deliberately small, and
 *  deliberately WITHOUT a status, a tenant binding or any secret. */
export interface EnrolmentRequest {
  identity: BenchIdentity;
  /** A SUGGESTION. The server records it as such and binds nothing. */
  proposedTenantId: number | null;
  /** Free label the preparer typed — a site code, an order number. */
  note: string | null;
  /** Which workstation did this, from the suite's machine-identity pattern. */
  preparedBy: string | null;
  preparedAt: string;
}

const DEFAULT_TRANSPORT: Readonly<Record<string, TransportKind>> = {
  mikrotik_routeros6: 'routeros_api',
  mikrotik_routeros7: 'routeros_api',
  draytek_vigor: 'ssh',
  zyxel_standalone: 'ssh',
  zyxel_nebula: 'rest',
  zyxel_cpe: 'ssh',
  sonicwall_sonicos: 'rest',
};

/**
 * Build the one-shot driver context. No database, no vault, no arbiter — this
 * process has none of them and must not grow them: a bench tool that needs a
 * connection string is a bench tool that cannot leave the office.
 */
function benchContext(target: BenchTarget): DriverContext {
  const transport = target.transport ?? DEFAULT_TRANSPORT[target.family] ?? 'ssh';
  const resolved: ResolvedTransport = {
    transport,
    enabled: true,
    priority: 0,
    host: target.host,
    port: target.port ?? null,
    useTls: transport === 'rest',
    tlsFingerprintSha256: null,
    params: {},
    credentials: { username: target.username, password: target.password },
  };
  return {
    // There is no device row yet — that is the point of enrolling. The drivers
    // use these only for logging and correlation.
    deviceId: 0,
    tenantId: 0,
    family: target.family,
    transports: [resolved],
    timeoutMs: 20_000,
  };
}

/**
 * Step 1 — ask the box what it is.
 *
 * Runs BEFORE anything is written. A preparer who selected the wrong family in
 * the dropdown finds out here, from the hardware, instead of after a failed
 * push into a CLI that does not speak the dialect they chose.
 */
export async function readBenchIdentity(target: BenchTarget): Promise<BenchIdentity> {
  const driver = getDriver(target.family);
  const inv = await driver.getInventory(benchContext(target));
  return {
    family: target.family,
    brand: inv.brand ?? null,
    model: inv.model ?? null,
    osVersion: inv.osVersion ?? null,
    serial: inv.serial ?? null,
    systemIdentity: inv.systemIdentity ?? null,
  };
}

/**
 * Step 2 — turn what the box reported into an enrolment.
 *
 * PURE, so the refusal below is testable without a router and without a server.
 * The refusal matters more than the mapping: a box that reports neither a
 * serial nor a system identity cannot be recognised later, and enrolling it
 * would create a row that no future connection can be matched against.
 * `assertTargetBinding` would then refuse it forever, which is a device the
 * platform can see and never touch — worse than one it never knew about.
 */
export function buildEnrolment(
  identity: BenchIdentity,
  opts: { proposedTenantId?: number | null; note?: string | null; preparedBy?: string | null; now: string },
): EnrolmentRequest {
  if (!identity.serial && !identity.systemIdentity) {
    throw new Error(
      'The device reported neither a serial number nor a system identity. ObliWAN would have no ' +
        'way to recognise it on a later connection (D5), so it is not enrolled. Check the ' +
        'credentials and the selected family, then read the identity again.',
    );
  }
  return {
    identity,
    proposedTenantId: opts.proposedTenantId ?? null,
    note: opts.note ?? null,
    preparedBy: opts.preparedBy ?? null,
    preparedAt: opts.now,
  };
}

/**
 * Step 3 — hand it to the platform.
 *
 * The enrolment token is a bench credential, scoped to enrolment and nothing
 * else. It is NOT an operator session: a workstation on a preparation bench is
 * a shared machine, and a token found on it must not be able to read the
 * fleet's configuration or push to it.
 */
export async function submitEnrolment(
  baseUrl: string,
  token: string,
  body: EnrolmentRequest,
): Promise<{ deviceId: number; status: string }> {
  const res = await fetch(`${baseUrl.replace(/\/+$/, '')}/api/devices/enroll`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-obliwan-enrolment': token },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`enrolment refused (${res.status}): ${(await res.text()).slice(0, 300)}`);
  }
  return (await res.json()) as { deviceId: number; status: string };
}
