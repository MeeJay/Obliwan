// ObliWAN — the multi-brand device contract.
//
// This file is the ONE place where "what a box is" and "what a box can do" is
// declared. Everything downstream (UI, scheduler, planner, template engine,
// drivers) reads these types. Nothing outside `server/src/services/drivers/`
// is ever allowed to branch on `brand` — it branches on capabilities.
//
// Decision D2: `DeviceDriver` is the abstraction; TR-069/CWMP is one transport
// among five, not the architecture.

// ============================================================================
// Identity
// ============================================================================

/** The four brands in the fleet. Adding a fifth must not touch anything but
 *  the driver folder and this union. */
export const DEVICE_BRANDS = ['mikrotik', 'draytek', 'zyxel', 'sonicwall'] as const;
export type DeviceBrand = (typeof DEVICE_BRANDS)[number];

/**
 * Sub-family within a brand. The family — not the brand — decides which
 * transport a driver reaches for and which command dialect it speaks.
 *
 * RouterOS 6 and RouterOS 7 are two SEPARATE families on purpose (risk R11):
 * `/system/health` returns a record on v6 and rows on v7, wireless moved from
 * `/interface/wireless` to `/interface/wifi`, and menu paths diverge. Treating
 * them as one family means every collector carries a version `if`, which is
 * exactly the hard-coded-path failure R11 exists to prevent.
 *
 * SonicOS 6.5 vs 7.x is deliberately NOT a family split: the difference there
 * is "REST API present or not", which is an observed capability probed at
 * connection time (`device_capabilities.observed_overrides`), not a different
 * command dialect. `devices.os_version` carries the detail.
 */
export const DEVICE_FAMILIES = [
  'mikrotik_routeros6', // RouterOS 6.x — RB / hEX / CCR still on the long-term tree
  'mikrotik_routeros7', // RouterOS 7.x — the CHR and current hardware
  'draytek_vigor',      // Vigor 2865 / 2927 / 2962 / 3910 — CLI + CWMP, opaque .cfg
  'zyxel_nebula',       // Nebula-managed (NSG / USG FLEX / ATP / switches / APs)
  'zyxel_standalone',   // USG FLEX / ATP / VPN series in standalone mode
  'zyxel_cpe',          // VMG / DX / EX xDSL & GPON CPE — TR-069 only
  'sonicwall_sonicos',  // TZ / NSa / NSv — SonicOS 6.5 and 7.x, see note above
] as const;
export type DeviceFamily = (typeof DEVICE_FAMILIES)[number];

/** Which brand a family belongs to. Single source of truth — never re-derive
 *  this from a string prefix at a call site. */
export const FAMILY_BRAND: Readonly<Record<DeviceFamily, DeviceBrand>> = {
  mikrotik_routeros6: 'mikrotik',
  mikrotik_routeros7: 'mikrotik',
  draytek_vigor: 'draytek',
  zyxel_nebula: 'zyxel',
  zyxel_standalone: 'zyxel',
  zyxel_cpe: 'zyxel',
  sonicwall_sonicos: 'sonicwall',
};

/**
 * How ObliWAN reaches the box. Exactly five — this union is mirrored by the
 * CHECK constraint on `device_transports.transport` (migration 002), so adding
 * a value here is a migration, not a one-line edit.
 *
 * Telnet is intentionally absent: it would carry fleet credentials in clear
 * over transit networks (risk R9).
 */
export const TRANSPORT_KINDS = ['routeros_api', 'ssh', 'rest', 'cwmp', 'snmp'] as const;
export type TransportKind = (typeof TRANSPORT_KINDS)[number];

/** `cpe` = a managed site device. `chr` = the central concentrator that
 *  terminates the L2TP tunnels and is the source of truth for presence (D4). */
export const DEVICE_ROLES = ['cpe', 'concentrator'] as const;
export type DeviceRole = (typeof DEVICE_ROLES)[number];

/**
 * `pending`     — discovered, not yet bound to a tenant. Quarantine (risk R4).
 * `active`      — managed; plans may target it.
 * `quarantined` — identity assertion failed, or an operator pulled it out of
 *                 the fleet. Readable, never writable.
 * `disabled`    — kept for history; no transport is ever opened.
 */
export const DEVICE_STATUSES = ['pending', 'active', 'quarantined', 'disabled'] as const;
export type DeviceStatus = (typeof DEVICE_STATUSES)[number];

/** Discovery quarantine states (table `discoveries`). */
export const DISCOVERY_STATES = ['pending', 'bound', 'ignored'] as const;
export type DiscoveryState = (typeof DISCOVERY_STATES)[number];

/** Persisted circuit-breaker state (table `device_health`). Survives restart. */
export const CIRCUIT_STATES = ['closed', 'open', 'half_open'] as const;
export type CircuitState = (typeof CIRCUIT_STATES)[number];

// ============================================================================
// Capabilities — declarative, and the safe default is "cannot"
// ============================================================================

/** Config export shape. Decides whether the drift engine can produce a
 *  structured diff or only an opaque fingerprint. */
export const CONFIG_FORMATS = ['text_cli', 'json', 'binary_opaque', 'cwmp_params'] as const;
export type ConfigFormat = (typeof CONFIG_FORMATS)[number];

/** Finest granularity at which a driver can push a change. */
export const APPLY_GRANULARITIES = ['full_replace', 'section', 'line', 'parameter'] as const;
export type ApplyGranularity = (typeof APPLY_GRANULARITIES)[number];

/**
 * What a device is known to be able to do.
 *
 * Rule: a driver spreads `NO_CAPABILITIES` and then turns on ONLY what it has
 * actually implemented and verified. A flag left at `false` means "we do not
 * know how to do this", never "the hardware cannot". The safe default is to
 * refuse, so a missing driver method surfaces as a refusal rather than as a
 * half-executed change on a production router.
 */
export interface DeviceCapabilities {
  // --- Transports the driver can actually open -----------------------------
  supportsRouterosApi: boolean;
  supportsSsh: boolean;
  supportsRest: boolean;
  supportsCwmp: boolean;
  supportsSnmp: boolean;
  /** Order the driver really attempts at runtime; first entry wins. */
  transportPriority: TransportKind[];

  // --- Read paths ----------------------------------------------------------
  canExportConfig: boolean;
  canReadInterfaces: boolean;
  canReadRoutes: boolean;
  canReadVlans: boolean;
  canReadFirewall: boolean;
  canReadDhcpLeases: boolean;
  canReadTunnels: boolean;
  canReadLogs: boolean;
  /** Concentrator only: can serve `/ppp/active` and `/ppp/secret`. */
  canReadPppSessions: boolean;
  /** Concentrator only: can stream `/ppp/active/listen` (push, not poll). */
  canStreamPppEvents: boolean;

  // --- Write paths (M6 — every driver ships these false until then) --------
  canPushConfig: boolean;
  canBackup: boolean;
  canRestore: boolean;
  canReboot: boolean;
  canUpgradeFirmware: boolean;
  canRunScript: boolean;
  /** Device can schedule a task that runs at its own next boot — the on-box
   *  dead-man of K1 (`/system/scheduler start-time=startup`). */
  canScheduleOnDevice: boolean;

  // --- Change semantics ----------------------------------------------------
  configFormat: ConfigFormat;
  applyGranularity: ApplyGranularity;
  /** Structured/deterministic export → a line-level drift diff is meaningful. */
  supportsStructuredDiff: boolean;
  /** Changes land in a staging area; the driver MUST commit or discard. */
  requiresExplicitCommit: boolean;
  /** Config only takes effect after a reload/reboot (DrayTek .cfg restore). */
  requiresRebootToApply: boolean;

  // --- Operational limits, read by the arbiter and the rate limiter --------
  /** Max concurrent sessions the box tolerates. Cloud APIs = shared quota. */
  maxConcurrentSessions: number;
  /** Floor between two polls. Nebula REST is quota-limited. */
  minPollIntervalMs: number;
  /** Honest, user-visible gaps. Shown in the UI "limitations" panel. */
  notes: string[];
}

/**
 * Every flag false. Drivers do `{ ...NO_CAPABILITIES, canReadInterfaces: true }`.
 *
 * Frozen on purpose: a driver that mutated the shared object instead of
 * spreading it would silently grant its capabilities to every other family.
 */
export const NO_CAPABILITIES: Readonly<DeviceCapabilities> = Object.freeze({
  supportsRouterosApi: false,
  supportsSsh: false,
  supportsRest: false,
  supportsCwmp: false,
  supportsSnmp: false,
  transportPriority: [] as TransportKind[],

  canExportConfig: false,
  canReadInterfaces: false,
  canReadRoutes: false,
  canReadVlans: false,
  canReadFirewall: false,
  canReadDhcpLeases: false,
  canReadTunnels: false,
  canReadLogs: false,
  canReadPppSessions: false,
  canStreamPppEvents: false,

  canPushConfig: false,
  canBackup: false,
  canRestore: false,
  canReboot: false,
  canUpgradeFirmware: false,
  canRunScript: false,
  canScheduleOnDevice: false,

  configFormat: 'binary_opaque',
  applyGranularity: 'full_replace',
  supportsStructuredDiff: false,
  requiresExplicitCommit: false,
  requiresRebootToApply: false,

  maxConcurrentSessions: 1,
  minPollIntervalMs: 60_000,
  notes: [] as string[],
});

/** The boolean flag names only — for the UI matrix and for the
 *  `device_capabilities.observed_overrides` jsonb blob. */
export type DeviceCapabilityFlag = {
  [K in keyof DeviceCapabilities]: DeviceCapabilities[K] extends boolean ? K : never;
}[keyof DeviceCapabilities];

/** Per-unit deltas measured at probe time, layered over the family defaults.
 *  Stored in `device_capabilities.observed_overrides`. */
export type ObservedCapabilityOverrides = Partial<Record<DeviceCapabilityFlag, boolean>>;

// ============================================================================
// Safety level — section 8.3. The type lands now, the enforcement in M6.
// ============================================================================

/**
 * How much of a net exists under a change, per device.
 *
 * `armed`         — dead-man ON the device itself. It repairs itself even if
 *                   the ObliWAN server dies. MikroTik only.
 * `armed_by_peer` — the dead-man is carried by a co-located MikroTik on the
 *                   same site, reached through a tunnel the change does not
 *                   touch. One brand repairs another.
 * `degraded`      — detection without recovery. We will know the CPE stopped
 *                   informing; we will not be able to fix it remotely. An
 *                   explicit operator confirmation is required before apply.
 *
 * The level is computed per device and shown on the blast-radius screen BEFORE
 * launch, never after. A wave rollout (K3) treats `degraded` devices last.
 */
export const SAFETY_LEVELS = ['armed', 'armed_by_peer', 'degraded'] as const;
export type SafetyLevel = (typeof SAFETY_LEVELS)[number];

/** Sort key for rollout waves: safest first, `degraded` last. */
export const SAFETY_LEVEL_RANK: Readonly<Record<SafetyLevel, number>> = {
  armed: 0,
  armed_by_peer: 1,
  degraded: 2,
};
