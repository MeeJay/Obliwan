// ObliWAN client — Intent Compiler DTOs (M11, killer K4).
//
// ── WHAT K4 ACTUALLY SELLS ──────────────────────────────────────────────────
// §1.2/K4: "un technicien qui ne connaît que MikroTik déploie un DrayTek, et la
// connaissance constructeur quitte la tête du senior pour entrer dans le
// produit." The compiler is only half of that. The other half is the FAILURE
// message: when a site intent does not compile for a brand, the screen has to
// say WHICH capability is missing and ON WHICH brand — because that sentence
// IS the vendor knowledge being transferred. "Compilation failed" transfers
// nothing and sends the technician back to the senior.
//
// So `CapabilityGap` below carries three things and none of them is optional
// in practice: the brand/family it is about, the `DeviceCapabilityFlag` that
// is false, and a human sentence. When the server sends only the flag, the
// client still renders a named capability, because
// `CAPABILITY_FLAG_LABEL_KEYS` maps every flag of the `DeviceCapabilities`
// contract onto an i18n key. That map is derived from the contract in
// `@obliwan/shared/device`, so a new flag is a compile error here rather than a
// blank line on screen.
//
// ── WHY THE COMPILE IS PRE-NETWORK ──────────────────────────────────────────
// §5/M11: `capabilityCheck` fails the compilation BEFORE any network access.
// This screen therefore never touches a device and never enqueues anything: it
// ends at "this compiles for these brands", and the apply path stays where D3
// put it — `change_jobs`, reached from `/plan`.

import type { DeviceBrand, DeviceCapabilityFlag, DeviceFamily } from '@obliwan/shared';

// ── The intent itself ───────────────────────────────────────────────────────

/**
 * A site intent, in the vocabulary an operator uses rather than a vendor's.
 *
 * Deliberately small and flat. The full intent grammar is a server contract
 * (`intent/compiler`, §5/M11) and inventing a rich one here would be inventing
 * a language the compiler does not speak. What the client owns is the FORM:
 * the fields below are the ones every one of the four brands has an opinion
 * about, which is precisely what makes them the interesting compile targets.
 */
export interface SiteIntent {
  name: string;
  /** e.g. `10.42.0.0/24`. */
  lanCidr: string;
  vlans: IntentVlan[];
  wan: IntentWan;
  dhcp: IntentDhcp;
  firewall: IntentFirewall;
  vpn: IntentVpn;
  /** Free-form note carried into the generated artefacts' header comment. */
  notes: string;
}

export interface IntentVlan {
  id: number;
  name: string;
  cidr: string;
  /** VLAN may reach the internet. `false` = isolated segment. */
  internet: boolean;
}

export const WAN_MODES = ['dhcp', 'static', 'pppoe'] as const;
export type WanMode = (typeof WAN_MODES)[number];

export interface IntentWan {
  mode: WanMode;
  /** `static` only. */
  address: string;
  gateway: string;
  /** `pppoe` only. The PASSWORD IS NOT HERE — §8.2. An intent references a
   *  vault credential by id; the secret never travels through this form, is
   *  never stored in the intent document, and never appears in an artefact
   *  preview. `null` = the operator has not picked one yet. */
  credentialId: number | null;
  /** Second uplink present. Drives the failover capability check. */
  failover: boolean;
}

export interface IntentDhcp {
  enabled: boolean;
  poolStart: string;
  poolEnd: string;
  dns: string[];
}

export interface IntentFirewall {
  /** Default action for traffic arriving on the WAN input chain. */
  defaultWanInput: 'drop' | 'accept';
  /** Management reachable from the tunnel only — the K2 assumption. */
  mgmtFromTunnelOnly: boolean;
  /** Ports opened from the WAN, as `tcp/443` strings. */
  wanOpenPorts: string[];
}

export interface IntentVpn {
  /** The L2TP client back to the concentrator (D4). */
  l2tpToConcentrator: boolean;
  /** IPsec transport under it. */
  ipsec: boolean;
  /** A site-to-site tunnel to another managed site. */
  siteToSite: boolean;
}

export function emptyIntent(): SiteIntent {
  return {
    name: '',
    lanCidr: '',
    vlans: [],
    wan: { mode: 'dhcp', address: '', gateway: '', credentialId: null, failover: false },
    dhcp: { enabled: true, poolStart: '', poolEnd: '', dns: [] },
    firewall: { defaultWanInput: 'drop', mgmtFromTunnelOnly: true, wanOpenPorts: [] },
    vpn: { l2tpToConcentrator: true, ipsec: true, siteToSite: false },
    notes: '',
  };
}

// ── Compilation result ──────────────────────────────────────────────────────

export const COMPILE_STATUSES = ['ok', 'partial', 'unsupported', 'error'] as const;
export type CompileStatus = (typeof COMPILE_STATUSES)[number];

/**
 * One reason a brand cannot carry this intent.
 *
 * `capability` is a `DeviceCapabilityFlag` — the SAME vocabulary the drivers
 * declare in `@obliwan/shared/device`. That is what makes the message
 * actionable: "draytek_vigor cannot do `canScheduleOnDevice`" points at a row
 * of the capability matrix a reader can go and check, whereas "not supported"
 * points at nothing.
 */
export interface CapabilityGap {
  brand: DeviceBrand;
  family: DeviceFamily | null;
  /** `null` when the compiler refused for a reason that is not a capability
   *  flag (an unroutable address plan, a VLAN id out of the model's range). */
  capability: DeviceCapabilityFlag | null;
  /** The part of the intent that needed it: `vpn.ipsec`, `wan.failover`. */
  intentPath: string;
  /** Server sentence. When absent, the renderer composes one from
   *  `capability` + `brand` — the message must never degrade to nothing. */
  detail: string | null;
  /** Model this was decided for, when the gap is per-model rather than
   *  per-family (a TZ270 has no second WAN, an NSa 2700 does). */
  model: string | null;
}

/** A rendered artefact, per brand. Never applied from this screen (D3). */
export interface CompiledArtifact {
  brand: DeviceBrand;
  family: DeviceFamily | null;
  /** `routeros_script`, `sonicos_rest`, `vigor_cli`, `cwmp_spv`. */
  format: string;
  /** The rendered body. Scanned for secrets before it is painted (§8.2): the
   *  compiler resolves vault references at APPLY time, not here, so anything
   *  secret-shaped in this string is a bug worth shouting about. */
  body: string;
  /** Number of NCM operations this artefact represents. */
  opCount: number;
}

export interface BrandCompileResult {
  brand: DeviceBrand;
  family: DeviceFamily | null;
  status: CompileStatus;
  gaps: CapabilityGap[];
  artifact: CompiledArtifact | null;
  /** How many devices of this brand are in the fleet — the blast radius of
   *  "this intent compiles for DrayTek". */
  deviceCount: number;
  /** Server note about what it did NOT check. */
  notice: string | null;
}

export interface IntentCompileResult {
  intentName: string;
  results: BrandCompileResult[];
  /** Server-side compiler version, so a golden-file mismatch in CI can be
   *  correlated with what the operator saw. */
  compilerVersion: string | null;
  compiledAt: string;
}

// ── Capability labels ───────────────────────────────────────────────────────

/**
 * Every boolean flag of `DeviceCapabilities`, mapped to its i18n key.
 *
 * `Record<DeviceCapabilityFlag, string>` and not `Partial<>`: when a driver
 * author adds a capability to the shared contract, this file stops compiling
 * until the label exists. That is the mechanism that keeps K4's failure
 * messages complete — a gap whose capability has no label renders as a raw
 * identifier, which is exactly the "compilation failed" non-message K4 is
 * supposed to replace.
 */
export const CAPABILITY_FLAG_LABEL_KEYS: Record<DeviceCapabilityFlag, string> = {
  supportsRouterosApi: 'intent.cap.supportsRouterosApi',
  supportsSsh: 'intent.cap.supportsSsh',
  supportsRest: 'intent.cap.supportsRest',
  supportsCwmp: 'intent.cap.supportsCwmp',
  supportsSnmp: 'intent.cap.supportsSnmp',

  canExportConfig: 'intent.cap.canExportConfig',
  canReadInterfaces: 'intent.cap.canReadInterfaces',
  canReadRoutes: 'intent.cap.canReadRoutes',
  canReadVlans: 'intent.cap.canReadVlans',
  canReadFirewall: 'intent.cap.canReadFirewall',
  canReadDhcpLeases: 'intent.cap.canReadDhcpLeases',
  canReadTunnels: 'intent.cap.canReadTunnels',
  canReadLogs: 'intent.cap.canReadLogs',
  canReadPppSessions: 'intent.cap.canReadPppSessions',
  canStreamPppEvents: 'intent.cap.canStreamPppEvents',

  canPushConfig: 'intent.cap.canPushConfig',
  canBackup: 'intent.cap.canBackup',
  canRestore: 'intent.cap.canRestore',
  canReboot: 'intent.cap.canReboot',
  canUpgradeFirmware: 'intent.cap.canUpgradeFirmware',
  canRunScript: 'intent.cap.canRunScript',
  canScheduleOnDevice: 'intent.cap.canScheduleOnDevice',

  supportsStructuredDiff: 'intent.cap.supportsStructuredDiff',
  requiresExplicitCommit: 'intent.cap.requiresExplicitCommit',
  requiresRebootToApply: 'intent.cap.requiresRebootToApply',
};

/** Brand display names. Not translated — they are trademarks, and a French UI
 *  saying "Point d'accès Mikrotik" for `mikrotik` helps nobody. */
export const BRAND_LABELS: Readonly<Record<DeviceBrand, string>> = {
  mikrotik: 'MikroTik',
  draytek: 'DrayTek',
  zyxel: 'Zyxel',
  sonicwall: 'SonicWall',
};
