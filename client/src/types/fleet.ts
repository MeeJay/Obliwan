// ObliWAN client — inventory DTOs (M2).
//
// These are the shapes the client expects on the wire for the fleet routes.
// They deliberately live in the client and NOT in @obliwan/shared: `shared/`
// is owned by another agent this milestone, and inventing entities there
// behind its back would create a merge conflict on a contract file. When the
// lead consolidates, these interfaces should move to `shared/src/inventory.ts`
// verbatim and be re-exported from here.
//
// Section 8.2 is load-bearing in every shape below: NO secret ever crosses
// this boundary. A transport exposes `hasSecret` / `hasPrivateKey` booleans,
// never the material itself, and `lastError` is the redacted message.

import type {
  DeviceBrand,
  DeviceFamily,
  DeviceRole,
  DeviceStatus,
  TransportKind,
  DiscoveryState,
  CircuitState,
  ReachabilityVerdict,
} from '@obliwan/shared';

// ── Sites ───────────────────────────────────────────────────────────────────

/** Opaque to the client in M2 — the change scheduler owns the semantics (C8).
 *  We render it, we never interpret it beyond display. */
export interface MaintenanceWindow {
  /** 0 = Sunday … 6 = Saturday, as stored by the scheduler. */
  days?: number[];
  /** 'HH:MM' local to `tz`. */
  start?: string;
  end?: string;
  tz?: string;
}

export interface Site {
  id: number;
  uuid: string;
  tenantId: number;
  code: string;
  name: string;
  address: string | null;
  contact: string | null;
  timezone: string;
  maintenanceWindow: MaintenanceWindow | null;
  createdAt: string;
  updatedAt: string;
  /** Server-side rollup when the list endpoint provides it. */
  deviceCount?: number;
}

export interface SiteInput {
  code: string;
  name: string;
  address?: string | null;
  contact?: string | null;
  timezone?: string;
  maintenanceWindow?: MaintenanceWindow | null;
}

// ── Presence & reachability ─────────────────────────────────────────────────

/**
 * The client-side view of "is this box on the tunnel right now".
 *
 * `up: null` is a THIRD value: nothing has been observed yet. Folding it into
 * `false` is exactly how a green fleet turns red on a page load, so the UI
 * renders it as "unknown", never as "down".
 */
export interface DevicePresence {
  up: boolean | null;
  /** `null` = no K7 verdict has ever been recorded for this device. Rendered
   *  as UNREACHABLE ("we cannot see"), never as an outage. */
  verdict: ReachabilityVerdict | null;
  at: string | null;
  tunnelIp?: string | null;
  callerIp?: string | null;
}

// ── Devices ─────────────────────────────────────────────────────────────────

export interface Device {
  id: number;
  uuid: string;
  tenantId: number;
  siteId: number | null;
  siteName?: string | null;
  groupId: number | null;
  groupName?: string | null;
  name: string;
  brand: DeviceBrand;
  family: DeviceFamily;
  model: string | null;
  serial: string | null;
  osVersion: string | null;
  role: DeviceRole;
  concentratorId: number | null;
  concentratorName?: string | null;
  pppUsername: string | null;
  systemIdentity: string | null;
  tunnelIp: string | null;
  wanPublicIp: string | null;
  sourceIpHint: string | null;
  status: DeviceStatus;
  isManaged: boolean;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
  /** Present when the list endpoint joins the last verdict. */
  presence?: DevicePresence | null;
}

export interface DeviceInput {
  name: string;
  brand: DeviceBrand;
  family: DeviceFamily;
  role: DeviceRole;
  siteId?: number | null;
  groupId?: number | null;
  model?: string | null;
  serial?: string | null;
  osVersion?: string | null;
  concentratorId?: number | null;
  pppUsername?: string | null;
  systemIdentity?: string | null;
  tunnelIp?: string | null;
  wanPublicIp?: string | null;
  sourceIpHint?: string | null;
  status?: DeviceStatus;
  isManaged?: boolean;
  notes?: string | null;
}

/** One channel. Ciphertext stays server-side; only its presence is reported. */
export interface DeviceTransport {
  id: number;
  deviceId: number;
  transport: TransportKind;
  enabled: boolean;
  priority: number;
  host: string | null;
  port: number | null;
  username: string | null;
  /** Section 8.2 — the vault holds the material, the UI only learns it exists. */
  hasSecret: boolean;
  hasPrivateKey: boolean;
  keyVersion: number;
  useTls: boolean;
  tlsFingerprintSha256: string | null;
  params: Record<string, unknown>;
  lastOkAt: string | null;
  /** Already redacted server-side. */
  lastError: string | null;
}

export interface DeviceTransportInput {
  transport: TransportKind;
  enabled?: boolean;
  priority?: number;
  host?: string | null;
  port?: number | null;
  username?: string | null;
  /** Write-only. Sent once, never read back. */
  secret?: string | null;
  privateKey?: string | null;
  useTls?: boolean;
  params?: Record<string, unknown>;
}

export type ConnState = 'ok' | 'degraded' | 'down' | 'unknown';

export interface DeviceHealth {
  deviceId: number;
  transport: TransportKind;
  connState: ConnState;
  circuitState: CircuitState;
  consecutiveFailures: number;
  backoffMs: number;
  nextRetryAt: string | null;
  lastRttMs: number | null;
  lastOkAt: string | null;
  lastFailureAt: string | null;
  lastError: string | null;
  enabled: boolean;
}

/** `GET /api/devices/:id`. Every joined block is optional: the server agent
 *  may ship them incrementally, and a missing block must degrade to an honest
 *  "not available", never to a crash or to invented data. */
export interface DeviceDetail extends Device {
  transports?: DeviceTransport[];
  health?: DeviceHealth[];
}

export interface TransportTestResult {
  transport: TransportKind;
  ok: boolean;
  rttMs?: number | null;
  /** Redacted message. */
  error?: string | null;
}

export interface TestConnectionResponse {
  deviceId: number;
  results: TransportTestResult[];
}

// ── PPP presence history ────────────────────────────────────────────────────

export interface PppSession {
  id: number;
  concentratorId: number;
  deviceId: number | null;
  deviceName?: string | null;
  pppUsername: string;
  tunnelIp: string | null;
  callerIp: string | null;
  startedAt: string;
  /** null = still open. */
  endedAt: string | null;
  durationSeconds: number | null;
  disconnectReason: string | null;
}

// ── Discovery quarantine ────────────────────────────────────────────────────

export interface Discovery {
  id: number;
  uuid: string;
  concentratorId: number;
  concentratorName?: string | null;
  pppUsername: string;
  remoteAddress: string | null;
  callerIp: string | null;
  profile: string | null;
  pppComment: string | null;
  raw: Record<string, unknown>;
  state: DiscoveryState;
  boundDeviceId: number | null;
  boundDeviceName?: string | null;
  reviewedBy: number | null;
  reviewedByName?: string | null;
  reviewedAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
}

/**
 * Binding a discovery is a security act (risk R4): it decides whose router
 * receives whose configuration.
 *
 * RECONCILED WITH THE SERVER. This used to carry `tenantId`,
 * `confirmPppUsername` and `confirmedIdentity`, none of which the server reads:
 *
 *  - the TENANT is the session's, resolved by `requireTenant`. A tenant sent in
 *    a body is a tenant the caller chose, and the whole point of the M1 work
 *    was that nothing tenant-scoped is ever taken from a request body. The bind
 *    dialog therefore states the workspace tenant instead of offering a choice
 *    the server would ignore — an ignored control is worse than no control,
 *    because the operator believes it did something.
 *  - `confirmPppUsername` / `confirmedIdentity` stay CLIENT-SIDE guard rails.
 *    They gate the submit button; they were never an authorisation, and
 *    shipping them made them look like one.
 *
 * `brand` is absent by design: the server derives it from `family`
 * (`FAMILY_BRAND`), and accepting both invites a request where the two
 * disagree and every driver lookup afterwards resolves to the wrong dialect.
 */
export interface DiscoveryBindInput {
  /** Attach to an existing device… */
  deviceId?: number;
  /** …or create one. Exactly one of the two — the server refuses both/neither. */
  device?: {
    name: string;
    family: DeviceFamily;
    role: DeviceRole;
    siteId?: number | null;
    groupId?: number | null;
  };
}

/** `pending` puts the row back in the review queue; `ignored` files it as "not
 *  ours". There is no `bound` here: binding is a different, heavier gesture. */
export interface DiscoveryStateInput {
  state: 'pending' | 'ignored';
}
