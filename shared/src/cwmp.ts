/**
 * @obliwan/shared — the TR-069 / CWMP contract (M10, feature C10, arbitrage A1).
 *
 * ┌─ WHAT THIS FILE IS FOR ───────────────────────────────────────────────────┐
 * │ One vocabulary for the ACS, shared by the CWMP listener (port 7547), the  │
 * │ admin API (`/api/acs`), the DrayTek and Zyxel drivers, and the client.    │
 * │ Nothing here talks XML: the wire format is `server/src/cwmp/xml.ts` and   │
 * │ it is the ONLY module allowed to know what a SOAP envelope looks like.    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE FOUR SENTENCES THIS CONTRACT EXISTS TO KEEP TRUE ────────────────────┐
 * │                                                                           │
 * │ 1. TWO PARAMETER TREES, ONE INTERNAL MODEL (§5 M10).                      │
 * │    TR-098 roots at `InternetGatewayDevice.` and TR-181 at `Device.`. The  │
 * │    same fact — "the WAN got address 81.x.y.z" — lives at two completely   │
 * │    different paths. `CanonicalKey` is the single name the rest of the     │
 * │    product uses; `cwmp_param_map` is the translation table, per data      │
 * │    model / brand / model / firmware. NOTHING outside the map may hardcode │
 * │    a vendor path.                                                         │
 * │                                                                           │
 * │ 2. THE ACS COVERS TWO BRANDS OUT OF FOUR, AND SAYS SO (risk R2).          │
 * │    RouterOS has no CWMP client. SonicOS has no CWMP client. That is a     │
 * │    property of the hardware, not a milestone we have not reached yet, and │
 * │    `ACS_BRAND_COVERAGE` below is what the UI renders instead of implying  │
 * │    universal coverage. It is exported as DATA precisely so the coverage   │
 * │    panel cannot drift from the truth.                                     │
 * │                                                                           │
 * │ 3. THERE IS NO "REFRESH NOW" BUTTON, AND THE UI MUST NOT DRAW ONE.        │
 * │    Connection Request is out of scope (arbitrage: STUN/XMPP have mediocre │
 * │    success rates and NAT bindings expire in 30-120 s). The real fallback  │
 * │    is to LOWER `PeriodicInformInterval` and wait. `CwmpRefreshOutcome`    │
 * │    exists so that answer is a typed, honest value — "the CPE will call    │
 * │    back within N seconds" — instead of a spinner that lies.               │
 * │                                                                           │
 * │ 4. THE PARAMETER TREE IS FULL OF PASSWORDS (§8.2).                        │
 * │    `InternetGatewayDevice.…WANPPPConnection.1.Password` is the L2TP/PPPoE │
 * │    password of the customer's line; `…WLANConfiguration.1.KeyPassphrase`  │
 * │    is their Wi-Fi key; `…Users.User.{i}.Password` is a login. The last    │
 * │    audit found exactly this class of secret sitting in a jsonb column     │
 * │    served to the UI. `isSecretParameterPath()` is the classifier, it is   │
 * │    applied AT INGESTION (the value is never written), and it is exported  │
 * │    from the shared package so the server and the client agree on which    │
 * │    rows are blanks rather than empty strings.                             │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { z } from 'zod';

// ============================================================================
// 1. Data models — TR-098 and TR-181
// ============================================================================

/** The two parameter trees in the field. There is no third one worth having. */
export const CWMP_DATA_MODELS = ['tr098', 'tr181'] as const;
export type CwmpDataModel = (typeof CWMP_DATA_MODELS)[number];

/**
 * The root prefix each model hangs off, INCLUDING the trailing dot.
 *
 * The trailing dot is not cosmetic: in CWMP a name that ends with `.` is a
 * PARTIAL PATH and `GetParameterValues` on it returns the whole subtree, which
 * is how learn mode discovers a tree without `GetParameterNames`. Dropping the
 * dot turns a subtree read into a request for one non-existent leaf and earns
 * fault 9005.
 */
export const CWMP_ROOT_PREFIX: Readonly<Record<CwmpDataModel, string>> = Object.freeze({
  tr098: 'InternetGatewayDevice.',
  tr181: 'Device.',
});

/** Recognise a model from any parameter path. Returns null when it is neither. */
export function dataModelOfPath(path: string): CwmpDataModel | null {
  if (path.startsWith(CWMP_ROOT_PREFIX.tr098)) return 'tr098';
  if (path.startsWith(CWMP_ROOT_PREFIX.tr181)) return 'tr181';
  return null;
}

/**
 * Both roots appear in an Inform's ParameterList and BOTH may be present on a
 * dual-stack CPE. When they are, TR-181 wins: it is the newer model, it is the
 * one the vendor keeps current, and picking arbitrarily would make a device
 * flip data models between two Informs and invalidate its whole param map.
 */
export function chooseDataModel(paths: readonly string[]): CwmpDataModel | null {
  let sawTr098 = false;
  for (const p of paths) {
    const m = dataModelOfPath(p);
    if (m === 'tr181') return 'tr181';
    if (m === 'tr098') sawTr098 = true;
  }
  return sawTr098 ? 'tr098' : null;
}

// ============================================================================
// 2. RPCs — the deliberately short list of arbitrage A1
// ============================================================================

/**
 * A BOOTSTRAP means the CPE has no memory of us: its parameter cache, its
 * `PeriodicInformInterval` and anything we ever set are gone. Anything we
 * believed about the box has to be re-established rather than trusted.
 *
 * Matched on the numeric prefix rather than the whole string. Inform event
 * codes (TR-069 Annex A.3.2.1) are `0 BOOTSTRAP`, `1 BOOT`, `2 PERIODIC`,
 * `4 VALUE CHANGE`, `6 CONNECTION REQUEST`, `7 TRANSFER COMPLETE`,
 * `M Reboot`, `M Download` — space included, exactly as they appear on the
 * wire. Firmware varies the CASE and occasionally the spacing of the word, and
 * a comparison against the full literal fails on a device that writes
 * `0 Bootstrap`. The number is the part the specification pins down.
 */
export function informIsBootstrap(events: readonly string[]): boolean {
  return events.some((e) => e.trim().toUpperCase().startsWith('0 '));
}

// ============================================================================
// 3. Parameter values
// ============================================================================

/**
 * The xsd types CWMP actually uses. `base64` is in the list because
 * `SetParameterValues` on a certificate blob uses it and a CPE that sees an
 * unknown type answers fault 9003 for the whole envelope, not just that leaf.
 */
export const CWMP_VALUE_TYPES = [
  'xsd:string',
  'xsd:int',
  'xsd:unsignedInt',
  'xsd:long',
  'xsd:unsignedLong',
  'xsd:boolean',
  'xsd:dateTime',
  'xsd:base64',
] as const;
export type CwmpValueType = (typeof CWMP_VALUE_TYPES)[number];

/**
 * Normalise whatever `xsi:type` the CPE wrote.
 *
 * QUIRK, AND IT IS THE COMMON ONE: plenty of firmware sends `string` without
 * the `xsd:` prefix, `boolean` capitalised, `unsignedint` lowercased, or a
 * namespace prefix of its own invention (`xs:string`, `SOAP-ENC:string`). A
 * parser that trusts the literal ends up with a `value_type` column full of
 * junk, and the first `SetParameterValues` built from it is rejected wholesale
 * by the CPE. Anything unrecognised degrades to `xsd:string`, which every CPE
 * accepts — never to null, which would make the column unusable.
 */
export function normaliseValueType(raw: string | null | undefined): CwmpValueType {
  if (!raw) return 'xsd:string';
  const bare = raw.includes(':') ? raw.slice(raw.lastIndexOf(':') + 1) : raw;
  switch (bare.trim().toLowerCase()) {
    case 'int':
    case 'integer':
      return 'xsd:int';
    case 'unsignedint':
      return 'xsd:unsignedInt';
    case 'long':
      return 'xsd:long';
    case 'unsignedlong':
      return 'xsd:unsignedLong';
    case 'boolean':
    case 'bool':
      return 'xsd:boolean';
    case 'datetime':
      return 'xsd:dateTime';
    case 'base64':
    case 'base64binary':
      return 'xsd:base64';
    default:
      return 'xsd:string';
  }
}

/** One leaf of the parameter tree, as ObliWAN stores it. */
export interface CwmpParameter {
  path: string;
  /** NULL when `isSecret` — the value is deliberately never read into memory
   *  beyond the parse, and never written. See §8.2 and rule 4 at the top. */
  value: string | null;
  valueType: CwmpValueType;
  writable: boolean;
  /** `0` off, `1` passive, `2` active — TR-069 SetParameterAttributes. */
  notification: 0 | 1 | 2;
  isSecret: boolean;
  updatedAt: string;
}

// ============================================================================
// 4. Secret parameter paths — §8.2, applied at ingestion
// ============================================================================

/**
 * Leaf names whose VALUE is a credential, whatever the tree above them.
 *
 * Matched on the LAST path segment, case-insensitively, because the prefix is
 * exactly the part that differs between TR-098 and TR-181 and between vendors.
 * `WANPPPConnection.1.Password` (TR-098) and `PPP.Interface.1.Password`
 * (TR-181) are the same secret.
 *
 * DELIBERATELY BROAD. A false positive costs one parameter shown as "(secret,
 * not stored)" in the UI; a false negative puts the L2TP password of an entire
 * customer base in a jsonb column, which is the finding this list exists to
 * make impossible to reproduce.
 */
const SECRET_LEAF_EXACT: ReadonlySet<string> = new Set([
  'password',
  'passphrase',
  'keypassphrase',
  'presharedkey',
  'psk',
  'wepkey',
  'secret',
  'sharedsecret',
  'privatekey',
  'connectionrequestpassword',
  'stunpassword',
]);

/** Substrings that make a leaf a secret regardless of the exact spelling. */
const SECRET_LEAF_CONTAINS: readonly string[] = [
  'password',
  'passphrase',
  'presharedkey',
  'privatekey',
  'secretkey',
  'authkey',
  'privkey',
  'wepkey',
];

export const CWMP_SENSITIVE_NOTE =
  'Values of credential parameters are never read into a stored column, never ' +
  'diffed, never exported and never returned by the API (§8.2). The PATH is ' +
  'kept so the parameter is visible and writable; the value is not.';

/**
 * True when the value at `path` is a credential and must not be stored.
 *
 * Note the deliberate asymmetry with `SetParameterValues`: ObliWAN may WRITE a
 * secret to one of these paths (that is the whole point of §8.2 — the platform
 * is the vault and it renders complete configurations), it just never READS one
 * back into a column. Writing is a memory-only path from the vault to the CPE.
 */
export function isSecretParameterPath(path: string): boolean {
  const lastDot = path.lastIndexOf('.');
  const leaf = (lastDot === -1 ? path : path.slice(lastDot + 1)).toLowerCase();
  if (SECRET_LEAF_EXACT.has(leaf)) return true;
  return SECRET_LEAF_CONTAINS.some((needle) => leaf.includes(needle));
}

// ============================================================================
// 5. Canonical keys — the one name the rest of the product uses
// ============================================================================

/**
 * The canonical model. Small on purpose: every key here has to be mapped by
 * hand for two data models and validated against firmware we do not own, and a
 * key nobody consumes is a maintenance cost with no reader (the "dead guard"
 * this codebase has already paid for three times).
 *
 * `{i}` marks an instance number in the vendor path —
 * `…WANConnectionDevice.{i}.WANPPPConnection.{i}.ExternalIPAddress`. The map
 * stores the template; the resolver expands it against the paths the CPE
 * actually reported.
 */
export const CWMP_CANONICAL_KEYS = [
  // identity
  'device.manufacturer',
  'device.model',
  'device.serial',
  'device.hardware_version',
  'device.software_version',
  'device.uptime_seconds',
  // management
  'mgmt.periodic_inform_enable',
  'mgmt.periodic_inform_interval',
  'mgmt.connection_request_url',
  'mgmt.parameter_key',
  // wan
  'wan.external_ip',
  'wan.connection_status',
  'wan.connection_type',
  'wan.mac_address',
  'wan.uptime_seconds',
  // lan
  'lan.ip_address',
  'lan.subnet_mask',
  'lan.dhcp_enable',
  'lan.dhcp_min_address',
  'lan.dhcp_max_address',
  // wifi
  'wifi.ssid',
  'wifi.enable',
  'wifi.channel',
  'wifi.security_mode',
  // hosts
  'hosts.total',
] as const;
export type CanonicalKey = (typeof CWMP_CANONICAL_KEYS)[number];

/** One row of `cwmp_param_map`, as the services and the API exchange it. */
export interface CwmpParamMapping {
  id: number;
  canonicalKey: CanonicalKey;
  dataModel: CwmpDataModel;
  /** NULL = applies to every brand. Same convention as `templates.tenant_id`:
   *  NULL is the shipped library, a value is a narrowing override. */
  brand: string | null;
  modelPattern: string | null;
  firmwarePattern: string | null;
  paramPath: string;
  /** Lower wins when several rows match — the narrowing above is expressed as
   *  a number so the resolution order is data, not a chain of ifs. */
  priority: number;
  /** true when this row was LEARNED from a live CPE rather than shipped. */
  learned: boolean;
}

/**
 * Expand a `{i}` template against the paths a CPE actually reported.
 *
 * Returns every concrete path that matches, in tree order. An empty array means
 * "this CPE does not expose that key", which is a legitimate answer and must
 * never be turned into an empty string by the caller.
 */
export function expandInstanceTemplate(
  template: string,
  knownPaths: readonly string[],
): string[] {
  if (!template.includes('{i}')) {
    return knownPaths.includes(template) ? [template] : [];
  }
  const rx = new RegExp(
    '^' +
      template
        .split('{i}')
        .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
        .join('(\\d+)') +
      '$',
  );
  return knownPaths.filter((p) => rx.test(p)).sort(comparePathsByInstance);
}

/** Order `…1.…` before `…2.…` before `…10.…` — numeric, not lexicographic. */
export function comparePathsByInstance(a: string, b: string): number {
  const na = a.split('.');
  const nb = b.split('.');
  for (let i = 0; i < Math.max(na.length, nb.length); i++) {
    const sa = na[i] ?? '';
    const sb = nb[i] ?? '';
    if (sa === sb) continue;
    const ia = Number(sa);
    const ib = Number(sb);
    if (Number.isInteger(ia) && Number.isInteger(ib)) return ia - ib;
    return sa < sb ? -1 : 1;
  }
  return 0;
}

// ============================================================================
// 6. The task queue — one file per CPE
// ============================================================================

export const CWMP_TASK_KINDS = [
  'get_parameter_values',
  'set_parameter_values',
  'download',
  'reboot',
] as const;
export type CwmpTaskKind = (typeof CWMP_TASK_KINDS)[number];

/**
 * `queued`    waiting for the CPE to call in.
 * `sent`      the RPC is on the wire; the CPE has not answered yet.
 * `done`      the CPE answered without a fault.
 * `failed`    the CPE answered a fault, or the attempt budget ran out.
 * `expired`   `expires_at` passed before the CPE ever called in. A CPE that is
 *             offline for a week must not be handed a week of stale intent the
 *             second it reconnects.
 * `cancelled` an operator withdrew it.
 */
export const CWMP_TASK_STATES = [
  'queued',
  'sent',
  'done',
  'failed',
  'expired',
  'cancelled',
] as const;
export type CwmpTaskState = (typeof CWMP_TASK_STATES)[number];

export const CWMP_TASK_TERMINAL: ReadonlySet<CwmpTaskState> = new Set<CwmpTaskState>([
  'done',
  'failed',
  'expired',
  'cancelled',
]);

/** Download file types (TR-069 Annex D). Firmware and config, nothing else. */
export const CWMP_FILE_TYPES = [
  '1 Firmware Upgrade Image',
  '3 Vendor Configuration File',
] as const;
export type CwmpFileType = (typeof CWMP_FILE_TYPES)[number];

/**
 * A single parameter write.
 *
 * `value` is a LITERAL. `secretRef` names a vault entry instead, and the two
 * are mutually exclusive: that is how §8.2 survives a queue table. The literal
 * of a secret parameter is never persisted; the reference is resolved in memory
 * at the moment the envelope is serialised, on the vault -> CPE path only.
 */
export interface CwmpSetOp {
  path: string;
  valueType: CwmpValueType;
  value?: string;
  secretRef?: string;
}

export type CwmpTaskPayload =
  | { kind: 'get_parameter_values'; paths: string[] }
  | { kind: 'set_parameter_values'; ops: CwmpSetOp[]; parameterKey?: string }
  | {
      kind: 'download';
      fileType: CwmpFileType;
      fileId: number;
      /** Bytes, as announced to the CPE. 0 = unknown, which is legal. */
      fileSize: number;
      targetFileName?: string;
    }
  | { kind: 'reboot' };

export interface CwmpTask {
  id: number;
  deviceId: number;
  kind: CwmpTaskKind;
  /** The correlation handle. UNIQUE across the whole table: `TransferComplete`
   *  arrives in a LATER session than the `Download` that caused it, sometimes
   *  days later, and `CommandKey` is the only thing tying the two together. */
  commandKey: string;
  state: CwmpTaskState;
  attempts: number;
  maxAttempts: number;
  payload: CwmpTaskPayload;
  fault: CwmpFault | null;
  createdBy: number | null;
  expiresAt: string;
  sentAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

// ============================================================================
// 7. Faults
// ============================================================================

export interface CwmpFault {
  /** SOAP faultcode, e.g. `Client`. */
  faultCode: string;
  /** CWMP fault code, e.g. `9001`. */
  code: string;
  faultString: string;
  /** Per-parameter faults of a partially rejected SetParameterValues. */
  parameters?: Array<{ path: string; code: string; faultString: string }>;
}

/** The fault codes the ACS has to reason about, not the whole annex. */
export const CWMP_FAULT = Object.freeze({
  METHOD_NOT_SUPPORTED: '9000',
  REQUEST_DENIED: '9001',
  INTERNAL_ERROR: '9002',
  INVALID_ARGUMENTS: '9003',
  RESOURCES_EXCEEDED: '9004',
  INVALID_PARAMETER_NAME: '9005',
  INVALID_PARAMETER_TYPE: '9006',
  INVALID_PARAMETER_VALUE: '9007',
  NON_WRITABLE_PARAMETER: '9008',
  DOWNLOAD_FAILURE: '9010',
  TRANSFER_FAILURE: '9017',
});

/**
 * Is retrying this fault worth an attempt?
 *
 * `9004 Resources Exceeded` is the one that matters in practice: a CPE that
 * cannot allocate for a 400-path GetParameterValues right now will manage a
 * smaller one, or the same one after a reboot. `9005 Invalid Parameter Name`
 * never becomes valid by repetition — retrying it just burns the CPE's session
 * budget every five minutes, forever.
 */
export function isRetryableFault(code: string): boolean {
  return (
    code === CWMP_FAULT.INTERNAL_ERROR ||
    code === CWMP_FAULT.RESOURCES_EXCEEDED ||
    code === CWMP_FAULT.DOWNLOAD_FAILURE ||
    code === CWMP_FAULT.TRANSFER_FAILURE
  );
}

// ============================================================================
// 8. Reachability, and the refusal to draw a Refresh button (rule 3)
// ============================================================================

export const CWMP_REACHABILITY = ['never_seen', 'online', 'stale', 'lost'] as const;
export type CwmpReachability = (typeof CWMP_REACHABILITY)[number];

/**
 * Classify a CPE from its last Inform alone.
 *
 * Deliberately NOT a ping and not a Connection Request: the only evidence an
 * ACS has that a CPE exists is that it called in. `stale` means "it is late but
 * within the grace we allow for a jittery line"; `lost` means "it has missed
 * enough Informs that something is wrong". Two names rather than one because
 * the K7 verdict consumes `cwmp_recent` and a boolean would flap.
 */
export function classifyReachability(
  lastInformAt: Date | string | null,
  periodicInformInterval: number,
  now: Date = new Date(),
): CwmpReachability {
  if (!lastInformAt) return 'never_seen';
  const last = typeof lastInformAt === 'string' ? new Date(lastInformAt) : lastInformAt;
  const age = (now.getTime() - last.getTime()) / 1000;
  const interval = periodicInformInterval > 0 ? periodicInformInterval : 300;
  if (age <= interval * 1.5) return 'online';
  if (age <= interval * 4) return 'stale';
  return 'lost';
}

/**
 * The answer to "refresh this CPE now", and the reason this type exists.
 *
 * `supported` is ALWAYS false in v1 and that is a product decision, not a bug:
 * Connection Request needs a reachable `ConnectionRequestURL`, which behind
 * carrier NAT means STUN or XMPP, whose NAT bindings expire in 30-120 s and
 * whose real-world success rate does not justify the machinery. What the ACS
 * can honestly do is SHORTEN the interval and tell the operator when the box
 * will next call in. The UI renders `etaSeconds`, not a spinner.
 */
export interface CwmpRefreshOutcome {
  supported: false;
  /** What actually happened. */
  action: 'periodic_interval_lowered' | 'already_pending' | 'device_never_seen';
  /** Seconds until the CPE is expected to call in, best estimate. Null when
   *  the CPE has never been seen and no estimate is honest. */
  etaSeconds: number | null;
  /** The interval now queued for the CPE, in seconds. */
  requestedInterval: number;
  /** Verbatim sentence for the UI. Written here so every surface says the same
   *  thing and nobody invents a cheerier one. */
  explanation: string;
}

export const CWMP_NO_CONNECTION_REQUEST_EXPLANATION =
  'ObliWAN does not push to a CPE on demand. TR-069 Connection Request needs a ' +
  'reachable ConnectionRequestURL, which behind carrier NAT means STUN or XMPP ' +
  'bindings that expire in 30-120 seconds. Instead the inform interval has been ' +
  'lowered for this CPE: it will contact the ACS on its own, and the queued tasks ' +
  'run then.';

// ============================================================================
// 9. Brand coverage — risk R2, as data the UI renders
// ============================================================================

export interface AcsBrandCoverage {
  brand: string;
  /** Does the hardware have a CWMP client at all? */
  hasCwmpClient: boolean;
  /** Does ObliWAN's ACS manage it? */
  managedByAcs: boolean;
  families: string[];
  /** One sentence, shown verbatim in the coverage panel. */
  note: string;
}

/**
 * THE ANSWER TO "WHY IS MY MIKROTIK NOT IN THE ACS".
 *
 * Exported as data and rendered as a table so the expectation is corrected in
 * the product, at the moment the question is asked, instead of in a document
 * nobody reads. Decision D2 and risk R2 in four rows.
 */
export const ACS_BRAND_COVERAGE: readonly AcsBrandCoverage[] = Object.freeze([
  {
    brand: 'draytek',
    hasCwmpClient: true,
    managedByAcs: true,
    families: ['draytek_vigor'],
    note:
      'Vigor firmware ships a TR-069 client and it is the best management channel ' +
      'this brand has: the .cfg backup is an opaque vendor blob, so the structured ' +
      'configuration model comes from the CWMP parameter tree.',
  },
  {
    brand: 'zyxel',
    hasCwmpClient: true,
    managedByAcs: true,
    families: ['zyxel_cpe'],
    note:
      'VMG / DX / EX xDSL and GPON gateways are carrier-provisioned and in practice ' +
      'TR-069 only. USG FLEX / ATP (zyxel_standalone, zyxel_nebula) are firewalls ' +
      'with no CWMP client — they are managed over SSH and the Nebula API.',
  },
  {
    brand: 'mikrotik',
    hasCwmpClient: false,
    managedByAcs: false,
    families: [],
    note:
      'RouterOS has no TR-069 client, in any version. MikroTik devices are managed ' +
      'over the RouterOS API and SSH, and they will never appear in the ACS.',
  },
  {
    brand: 'sonicwall',
    hasCwmpClient: false,
    managedByAcs: false,
    families: [],
    note:
      'SonicOS has no TR-069 client. SonicWall appliances are managed over the ' +
      'SonicOS REST API and will never appear in the ACS.',
  },
]);

/** Families the ACS can enrol. Anything else is refused at the door, loudly. */
export const ACS_MANAGED_FAMILIES: readonly string[] = Object.freeze(
  ACS_BRAND_COVERAGE.filter((c) => c.managedByAcs).flatMap((c) => c.families),
);

export function acsCoversFamily(family: string | null | undefined): boolean {
  return !!family && ACS_MANAGED_FAMILIES.includes(family);
}

// ============================================================================
// 10. Identity — `OUI-ProductClass-Serial`
// ============================================================================

/**
 * The CWMP device identifier, built exactly as TR-069 specifies it.
 *
 * `ProductClass` is OPTIONAL on the wire and a surprising number of CPEs omit
 * it. The two-field form `OUI-Serial` is then the legal identifier, and a
 * builder that blindly joined three fields would produce `00507F--1234`, a
 * distinct string from the one the same box sends after a firmware upgrade that
 * starts populating ProductClass. Devices would silently double.
 */
export interface CwmpDeviceIdParts {
  manufacturer?: string | null;
  oui: string;
  productClass?: string | null;
  serialNumber: string;
}

export function buildCwmpId(parts: CwmpDeviceIdParts): string {
  const oui = (parts.oui || '').trim().toUpperCase();
  const serial = (parts.serialNumber || '').trim();
  const pc = (parts.productClass || '').trim();
  if (!oui || !serial) {
    throw new Error('buildCwmpId: OUI and SerialNumber are both required');
  }
  return pc ? `${oui}-${pc}-${serial}` : `${oui}-${serial}`;
}

/** The longest `cwmp_id` the schema accepts. OUI(6) + class(64) + serial(64)
 *  plus two separators = 136; 192 leaves room and keeps the index small. */
export const CWMP_ID_MAX_LENGTH = 192;

// ============================================================================
// 11. API DTOs
// ============================================================================

/**
 * What this particular CPE got wrong, recorded as it is observed.
 *
 * These are not settings. Every one of them was written by the parser after a
 * real envelope forced it to cope, which makes this record the field report the
 * next person needs — and the reason a brand-new quirk shows up as data instead
 * of as a mysterious parse failure.
 */
export interface CwmpQuirks {
  /** The CPE never returned the `ACSsession` cookie we set. Session continuity
   *  falls back to `(cwmp_id, source IP)`. */
  noCookie?: boolean;
  /** `xsi:type` absent or unparseable on at least one value. */
  badXsiType?: boolean;
  /** Sent a SOAP envelope with no `cwmp:ID` header. */
  noCwmpId?: boolean;
  /** Uses `InternetGatewayDevice.` and `Device.` in the same tree. */
  mixedDataModel?: boolean;
  /** `soap-enc:arrayType` count disagreed with the number of children. */
  arrayCountMismatch?: boolean;
  /** Refused Digest and only offered Basic. */
  basicAuthOnly?: boolean;
}

export interface AcsDeviceSummary {
  deviceId: number;
  deviceName: string;
  brand: string;
  family: string;
  cwmpId: string;
  dataModel: CwmpDataModel;
  cwmpVersion: string | null;
  rootPrefix: string;
  reachability: CwmpReachability;
  lastInformAt: string | null;
  lastInformEvents: string[];
  periodicInformInterval: number;
  parameterCount: number;
  pendingTasks: number;
  /** Always false in v1 — see `CwmpRefreshOutcome`. Carried per device so the
   *  client never has to hardcode the capability. */
  connectionRequestSupported: false;
}

export interface AcsDeviceDetail extends AcsDeviceSummary {
  manufacturer: string | null;
  oui: string | null;
  productClass: string | null;
  serialNumber: string | null;
  hardwareVersion: string | null;
  softwareVersion: string | null;
  /** Quirks OBSERVED on this unit, not configured for it. */
  vendorQuirks: CwmpQuirks;
  canonical: Partial<Record<CanonicalKey, string | null>>;
}

export interface AcsTaskSummary {
  id: number;
  deviceId: number;
  kind: CwmpTaskKind;
  commandKey: string;
  state: CwmpTaskState;
  attempts: number;
  maxAttempts: number;
  fault: CwmpFault | null;
  createdAt: string;
  sentAt: string | null;
  completedAt: string | null;
  expiresAt: string;
  /** Redacted view of the payload — a `set_parameter_values` op on a secret
   *  path shows the path and `"(from vault)"`, never a value. */
  payloadSummary: string;
}

/** What the coverage panel renders (risk R2). */
export interface AcsCoverageReport {
  brands: readonly AcsBrandCoverage[];
  /** Devices in the fleet per brand, and how many of them the ACS has seen. */
  fleet: Array<{
    brand: string;
    devices: number;
    cwmpEnrolled: number;
    informedLast24h: number;
  }>;
  connectionRequestSupported: false;
  connectionRequestExplanation: string;
}

// ============================================================================
// 12. Zod schemas for the admin API
// ============================================================================

const pathSchema = z
  .string()
  .min(1)
  .max(512)
  // A CWMP parameter name is dot-separated alphanumerics plus instance numbers.
  // Anything else is either an injection attempt or a bug, and both deserve a
  // 400 rather than a trip to the CPE.
  .regex(/^[A-Za-z0-9_.:{}-]+$/, 'not a CWMP parameter path');

export const getParameterValuesSchema = z.object({
  /** A name ending in `.` is a partial path and pulls the whole subtree. */
  paths: z.array(pathSchema).min(1).max(256),
});

export const setParameterValuesSchema = z.object({
  ops: z
    .array(
      z
        .object({
          path: pathSchema,
          valueType: z.enum(CWMP_VALUE_TYPES).default('xsd:string'),
          value: z.string().max(4096).optional(),
          secretRef: z.string().max(256).optional(),
        })
        .refine((op) => (op.value === undefined) !== (op.secretRef === undefined), {
          message: 'exactly one of `value` or `secretRef` must be set',
        }),
    )
    .min(1)
    .max(64),
  parameterKey: z.string().max(32).optional(),
});

export const downloadSchema = z.object({
  fileId: z.number().int().positive(),
  targetFileName: z.string().max(256).optional(),
});

export const paramMapUpsertSchema = z.object({
  canonicalKey: z.enum(CWMP_CANONICAL_KEYS),
  dataModel: z.enum(CWMP_DATA_MODELS),
  brand: z.string().max(32).nullable().optional(),
  modelPattern: z.string().max(128).nullable().optional(),
  firmwarePattern: z.string().max(128).nullable().optional(),
  paramPath: pathSchema,
  priority: z.number().int().min(0).max(1000).default(100),
});

export const acsSettingsSchema = z.object({
  digestRealm: z.string().min(1).max(128),
  trustedCidrs: z.array(z.string().max(64)).max(64),
  allowAutoEnroll: z.boolean(),
  /** Off by default (risk R7): this table is the one that explodes. */
  rpcLogEnabled: z.boolean(),
  defaultPeriodicInformInterval: z.number().int().min(30).max(86_400),
});

export type GetParameterValuesInput = z.infer<typeof getParameterValuesSchema>;
export type SetParameterValuesInput = z.infer<typeof setParameterValuesSchema>;
export type DownloadInput = z.infer<typeof downloadSchema>;
export type ParamMapUpsertInput = z.infer<typeof paramMapUpsertSchema>;
export type AcsSettingsInput = z.infer<typeof acsSettingsSchema>;

// ============================================================================
// 13. Redaction helper for the API and the logs
// ============================================================================

/** One-line summary of a task payload, with every secret already gone. */
export function summarisePayload(payload: CwmpTaskPayload): string {
  switch (payload.kind) {
    case 'get_parameter_values':
      return payload.paths.length === 1
        ? `GetParameterValues ${payload.paths[0]}`
        : `GetParameterValues (${payload.paths.length} paths)`;
    case 'set_parameter_values':
      return (
        'SetParameterValues ' +
        payload.ops
          .map((op) =>
            op.secretRef || isSecretParameterPath(op.path)
              ? `${op.path}=(from vault)`
              : `${op.path}=${truncate(op.value ?? '', 48)}`,
          )
          .join(', ')
      );
    case 'download':
      return `Download ${payload.fileType} (file #${payload.fileId})`;
    case 'reboot':
      return 'Reboot';
  }
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}
