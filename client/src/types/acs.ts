// ObliWAN client — TR-069 / CWMP DTOs (M10, feature C10).
//
// ── WHAT THIS FILE REFUSES TO PRETEND ───────────────────────────────────────
// Decision D2 and §5/M10 are explicit: the ACS covers **DrayTek and Zyxel CPE
// only**. RouterOS has no TR-069 client at all and neither does SonicOS. That
// is not a gap to be quietly filled in later — it is the shape of the product,
// and `CWMP_BRAND_COVERAGE` below is the client-side statement of it. An ACS
// screen that lists four brands and shows two of them permanently "offline"
// teaches the operator that ObliWAN is broken; one that says "this brand has no
// CWMP client, use the RouterOS API path" teaches him the architecture.
//
// ── §8.2 — THE CWMP DATA MODEL IS FULL OF PASSWORDS ─────────────────────────
// This is not a hypothetical. TR-098 has
// `InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.Password`
// and TR-181 has `Device.PPP.Interface.{i}.Password`; a Vigor also carries
// `...X_00507F_*.PreSharedKey` and the WLAN `KeyPassphrase`. Those are exactly
// the L2TP passwords the last audit found served to the UI out of a jsonb
// column. So:
//
//   * `CwmpParameter.value` is `string | null`, and `null` here means
//     WITHHELD, not empty — `redacted: true` says which it is.
//   * `isSecretParameterPath()` below is the client's own second opinion. It
//     is NOT the protection (the server must never serve the value); it is the
//     thing that makes a server regression visible instead of silent.
//   * `cr_password_enc` and `acs_auth_ha1` have no representation in this file
//     at all. The only thing the client learns about a Connection Request
//     credential is the BOOLEAN `hasConnectionRequest`.
//
// ── THE OTHER HONESTY RULE: "REFRESH NOW" DOES NOT EXIST ────────────────────
// CWMP is CPE-initiated. The ACS speaks only when the CPE opens a session, and
// a Connection Request is a best-effort UDP/HTTP poke at an address that is
// very often behind a NAT the ACS cannot traverse. A button labelled "Refresh
// now" that enqueues a task and returns is a lie with a spinner on it. The
// vocabulary below therefore separates:
//   - `nextInformExpectedAt`  — when the CPE is due to call in on its own,
//   - `hasConnectionRequest`  — whether a poke can even be attempted,
//   - `connectionRequestOk`   — whether the LAST poke actually worked.
// The screen composes a sentence from the three and never promises immediacy.

import type { DeviceBrand, DeviceFamily } from '@obliwan/shared';

// ── Brand coverage (D2) ─────────────────────────────────────────────────────

export type CwmpCoverageLevel =
  /** The brand ships a CWMP client and ObliWAN drives it. */
  | 'supported'
  /** Some models of the brand do, some do not (Zyxel: CPE yes, USG/ATP no). */
  | 'partial'
  /** No TR-069 client exists on this platform. Never an error, never a bug. */
  | 'absent';

export interface CwmpBrandCoverage {
  brand: DeviceBrand;
  level: CwmpCoverageLevel;
  /** Families that actually speak CWMP. Empty for `absent`. */
  families: DeviceFamily[];
  /** i18n key carrying the one-sentence explanation. */
  reasonKey: string;
  /** Transport the operator should use instead, when CWMP is absent. */
  insteadKey: string | null;
}

/**
 * The coverage matrix, stated once.
 *
 * It is a CONSTANT and not a server fetch on purpose: it is a consequence of
 * decision D2 — of which client software exists on which vendor's firmware —
 * and not of the state of a particular installation. A server round trip would
 * turn an architectural fact into something that can be empty while loading,
 * and the one thing this panel must never do is fail to say "MikroTik has no
 * CWMP client" because a fetch was in flight.
 */
export const CWMP_BRAND_COVERAGE: readonly CwmpBrandCoverage[] = [
  {
    brand: 'draytek',
    level: 'supported',
    families: ['draytek_vigor'],
    reasonKey: 'acs.coverage.draytek',
    insteadKey: null,
  },
  {
    brand: 'zyxel',
    level: 'partial',
    families: ['zyxel_cpe'],
    reasonKey: 'acs.coverage.zyxel',
    insteadKey: 'acs.coverage.zyxelInstead',
  },
  {
    brand: 'mikrotik',
    level: 'absent',
    families: [],
    reasonKey: 'acs.coverage.mikrotik',
    insteadKey: 'acs.coverage.mikrotikInstead',
  },
  {
    brand: 'sonicwall',
    level: 'absent',
    families: [],
    reasonKey: 'acs.coverage.sonicwall',
    insteadKey: 'acs.coverage.sonicwallInstead',
  },
];

/** Families that can ever appear on this screen. Anything else is a device the
 *  ACS will never hear from, and listing it would be the lie D2 warns about. */
export const CWMP_CAPABLE_FAMILIES: readonly DeviceFamily[] = ['draytek_vigor', 'zyxel_cpe'];

export function coverageOfBrand(brand: DeviceBrand | null): CwmpBrandCoverage | null {
  if (!brand) return null;
  return CWMP_BRAND_COVERAGE.find((c) => c.brand === brand) ?? null;
}

// ── Vocabulary ──────────────────────────────────────────────────────────────

export const CWMP_DATA_MODELS = ['tr098', 'tr181'] as const;
export type CwmpDataModel = (typeof CWMP_DATA_MODELS)[number];

/**
 * How the ACS currently sees a CPE.
 *
 * `never_informed` is a value of its own and is never folded into `offline`:
 * a CPE that was provisioned but has not yet been pointed at the ACS URL and a
 * CPE that has gone dark are two different jobs for two different people.
 * `unknown` is what an unrecognised server value degrades to — never `online`.
 */
export const CWMP_REACHABILITIES = ['online', 'idle', 'overdue', 'never_informed', 'unknown'] as const;
export type CwmpReachability = (typeof CWMP_REACHABILITIES)[number];

/** RPCs this UI can enqueue. Mirrors §5/M10: GPV/SPV/Download/Reboot, plus the
 *  object lifecycle a TR-069 parameter tree needs to be editable at all. */
export const CWMP_TASK_COMMANDS = [
  'GetParameterValues',
  'GetParameterNames',
  'SetParameterValues',
  'Download',
  'Reboot',
  'AddObject',
  'DeleteObject',
] as const;
export type CwmpTaskCommand = (typeof CWMP_TASK_COMMANDS)[number];

/**
 * `expired` exists because `cwmp_tasks.expires_at` does. A task that sat in the
 * queue past its deadline did NOT fail on the device — nothing was ever sent —
 * and showing it as `failed` would send a technician to look at a router that
 * never heard from us.
 */
export const CWMP_TASK_STATES = ['queued', 'sent', 'done', 'failed', 'expired', 'cancelled'] as const;
export type CwmpTaskState = (typeof CWMP_TASK_STATES)[number];

export const CWMP_RPC_DIRECTIONS = ['acs_to_cpe', 'cpe_to_acs'] as const;
export type CwmpRpcDirection = (typeof CWMP_RPC_DIRECTIONS)[number];

// ── The CPE ─────────────────────────────────────────────────────────────────

export interface CwmpCpe {
  deviceId: number;
  deviceName: string | null;
  siteId: number | null;
  siteName: string | null;
  brand: DeviceBrand | null;
  family: DeviceFamily | null;
  model: string | null;
  /** `OUI-ProductClass-Serial`. The CWMP identity, distinct from D5's fleet
   *  identity — the two are correlated server-side, never merged here. */
  cwmpId: string;
  dataModel: CwmpDataModel | null;
  /** `InternetGatewayDevice.` or `Device.`. Shown because a wrong root prefix
   *  is the single most common reason a parameter path "does not exist". */
  rootPrefix: string | null;
  cwmpVersion: string | null;
  softwareVersion: string | null;
  /** Seconds between two scheduled Informs, as the CPE reports it. */
  periodicInformInterval: number | null;
  lastInformAt: string | null;
  /** The EventCode of the last Inform (`2 PERIODIC`, `1 BOOT`, `4 VALUE CHANGE`…). */
  lastInformEvent: string | null;
  reachability: CwmpReachability;
  /**
   * A Connection Request URL is on file. Deliberately a boolean: the URL
   * embeds a host and port that are useful, but `cr_password_enc` is next to it
   * in the same record and the safest client contract is one that cannot carry
   * either (§8.2).
   */
  hasConnectionRequest: boolean;
  /** Outcome of the LAST Connection Request attempt. `null` = never attempted,
   *  which is not the same as "it does not work". */
  connectionRequestOk: boolean | null;
  lastConnectionRequestAt: string | null;
  queuedTasks: number;
  parameterCount: number;
  /** Quirk keys from `cwmp_devices.vendor_quirks`, e.g. `no_cookie`,
   *  `single_element_array`, `bad_xsi_type`. Shown, never interpreted. */
  vendorQuirks: string[];
}

/**
 * Where the next contact will realistically come from.
 *
 * Computed here rather than server-side so the countdown ticks without a poll,
 * and so the "we do not know" branch is impossible to skip: a CPE that has
 * never informed has NO next-inform time, and the caller has to render that.
 */
export function nextInformExpectedAt(cpe: CwmpCpe): Date | null {
  if (!cpe.lastInformAt || !cpe.periodicInformInterval || cpe.periodicInformInterval <= 0) {
    return null;
  }
  const last = new Date(cpe.lastInformAt).getTime();
  if (Number.isNaN(last)) return null;
  return new Date(last + cpe.periodicInformInterval * 1000);
}

// ── Parameters ──────────────────────────────────────────────────────────────

export interface CwmpParameter {
  path: string;
  /** `null` + `redacted:false` = the CPE reported an empty value.
   *  `null` + `redacted:true`  = the value exists and is deliberately withheld. */
  value: string | null;
  valueType: string | null;
  writable: boolean;
  /** TR-069 notification attribute: 0 off, 1 passive, 2 active. */
  notification: number | null;
  redacted: boolean;
  updatedAt: string | null;
}

/**
 * Parameter leaves whose value must never be painted, whatever the server sent.
 *
 * Matched on the LAST segment of the path (and on a couple of two-segment
 * tails), case-insensitively, so it works across TR-098, TR-181 and the
 * `X_<OUI>_` vendor extensions where the interesting leaks actually live.
 */
const SECRET_PARAM_TAILS = [
  'password', 'passphrase', 'keypassphrase', 'presharedkey', 'preshared_key',
  'psk', 'secret', 'sharedsecret', 'wepkey', 'privatekey', 'connectionrequestpassword',
  'username_password', 'radiussecret', 'authpassword', 'privacypassword',
  'x_password', 'pppoepassword', 'adminpassword', 'userpassword',
];

/**
 * The client's second opinion on §8.2, for CWMP paths specifically.
 *
 * This is NOT the protection. The protection is that `cwmp_parameters.value`
 * for these paths never leaves the server. This function exists so that the day
 * a learn-mode import or a new vendor quirk widens the server's idea of a safe
 * parameter, the screen shows a redaction chip instead of a customer's PPPoE
 * password — a visible over-redaction rather than an invisible leak.
 */
export function isSecretParameterPath(path: string): boolean {
  const lower = path.toLowerCase();
  const tail = lower.split('.').pop() ?? '';
  if (SECRET_PARAM_TAILS.includes(tail)) return true;
  // `...WLANConfiguration.1.PreSharedKey.1.KeyPassphrase` — the tail is right
  // but so is a two-level check for models that suffix an index.
  return SECRET_PARAM_TAILS.some((k) => tail.startsWith(k) || lower.endsWith(`.${k}`));
}

/** A node of the aggregated parameter tree the screen renders. */
export interface ParamNode {
  /** Last path segment. */
  name: string;
  /** Full dotted path down to and including this node. */
  path: string;
  children: ParamNode[];
  /** Present on leaves only. */
  leaf: CwmpParameter | null;
  /** Number of leaves at or under this node — the branch label's counter. */
  leafCount: number;
}

/**
 * Fold a flat `cwmp_parameters` page into a tree.
 *
 * Kept a pure function next to the DTOs rather than inside the component so it
 * is trivially testable and so the tree cannot accidentally acquire a fetch.
 */
export function buildParamTree(rows: CwmpParameter[]): ParamNode[] {
  const root: ParamNode = { name: '', path: '', children: [], leaf: null, leafCount: 0 };
  const index = new Map<string, ParamNode>([['', root]]);

  for (const row of rows) {
    const segments = row.path.split('.').filter((s) => s.length > 0);
    let current = root;
    let prefix = '';
    for (let i = 0; i < segments.length; i++) {
      prefix = prefix ? `${prefix}.${segments[i]}` : segments[i];
      let node = index.get(prefix);
      if (!node) {
        node = { name: segments[i], path: prefix, children: [], leaf: null, leafCount: 0 };
        index.set(prefix, node);
        current.children.push(node);
      }
      current = node;
    }
    current.leaf = row;
    // Walk back up incrementing the counters.
    let walk = '';
    for (const segment of segments) {
      walk = walk ? `${walk}.${segment}` : segment;
      const node = index.get(walk);
      if (node) node.leafCount += 1;
    }
    root.leafCount += 1;
  }

  const sort = (nodes: ParamNode[]): ParamNode[] => {
    nodes.sort((a, b) => {
      // Instance numbers sort numerically: `.10.` after `.9.`, not before it.
      const na = Number(a.name);
      const nb = Number(b.name);
      if (Number.isInteger(na) && Number.isInteger(nb)) return na - nb;
      return a.name.localeCompare(b.name);
    });
    for (const node of nodes) sort(node.children);
    return nodes;
  };
  return sort(root.children);
}

// ── Tasks ───────────────────────────────────────────────────────────────────

export interface CwmpTask {
  id: number;
  deviceId: number;
  deviceName: string | null;
  command: CwmpTaskCommand;
  /** `cwmp_tasks.command_key UNIQUE` — the correlation handle a
   *  `TransferComplete` comes back with. Shown because it is the only way to
   *  tie a firmware push to its outcome by eye. */
  commandKey: string;
  state: CwmpTaskState;
  attempts: number;
  /** Human summary of the payload: the parameter paths, the firmware name.
   *  NEVER the values — an SPV that sets a PPP password would otherwise print
   *  it here (§8.2). */
  summary: string | null;
  faultCode: string | null;
  faultString: string | null;
  createdAt: string;
  sentAt: string | null;
  completedAt: string | null;
  expiresAt: string | null;
  createdByName: string | null;
}

export interface EnqueueTaskRequest {
  deviceId: number;
  command: CwmpTaskCommand;
  /** GPV / GPN / SPV / AddObject / DeleteObject. */
  paths?: string[];
  /** SPV only. Sent, never echoed back into a list or a log. */
  values?: Record<string, string>;
  /** Download only. */
  fileId?: number;
}

// ── RPC log ─────────────────────────────────────────────────────────────────

export interface CwmpRpcEntry {
  id: string;
  deviceId: number;
  sessionId: string | null;
  at: string;
  direction: CwmpRpcDirection;
  rpc: string;
  /** HTTP status of the exchange, when the transport recorded one. */
  httpStatus: number | null;
  faultCode: string | null;
  /** Redacted SOAP excerpt. Painted through `secretScan` regardless: the
   *  envelope of an SPV literally contains the values that were set. */
  bodyExcerpt: string | null;
}

/**
 * `cwmp_rpc_log` is **disabled by default** (§3.6) with a 7-day retention.
 * The screen must say which of the two it is looking at: an empty log because
 * capture is off is a setting, an empty log because nothing happened is a
 * symptom, and they need opposite actions.
 */
export interface CwmpRpcLogView {
  enabled: boolean;
  retentionDays: number | null;
  entries: CwmpRpcEntry[];
}

// ── Firmware ────────────────────────────────────────────────────────────────

export interface CwmpFile {
  id: number;
  name: string;
  /** TR-069 FileType, e.g. `1 Firmware Upgrade Image`. */
  fileType: string;
  version: string | null;
  sizeBytes: number | null;
  sha256: string | null;
  /** Families this image is declared for. An image with an empty list is
   *  offered for NO device: pushing a Vigor image to a Zyxel is a brick, and
   *  "the operator will be careful" is not a safety mechanism. */
  families: DeviceFamily[];
  uploadedAt: string;
  uploadedByName: string | null;
}

